//! Short-lived requester-scoped bucket keys. Only wrapped keys enter object metadata.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use locallycloud_core::integration::kms::{
    KmsAuthorizeCachedKeyRequest, KmsDataKeyAction, KmsDecryptRequest, KmsGenerateDataKeyRequest,
    SensitiveBytes,
};
use sha2::{Digest, Sha256};

use crate::{
    error::S3Error,
    ops::{kms_call, kms_error, Ctx},
};

#[derive(Clone)]
pub(crate) struct BucketKey {
    pub plain: Arc<SensitiveBytes>,
    pub wrapped: Vec<u8>,
    pub key_arn: String,
    expires: Instant,
}

#[derive(Default)]
pub(crate) struct BucketKeyCache(Mutex<BTreeMap<String, BucketKey>>);

impl BucketKeyCache {
    fn get(&self, key: &str) -> Result<Option<BucketKey>, S3Error> {
        Ok(self
            .0
            .lock()
            .map_err(|_| S3Error::InternalError)?
            .get(key)
            .filter(|entry| entry.expires > Instant::now())
            .cloned())
    }
    fn insert(&self, key: String, entry: BucketKey) -> Result<(), S3Error> {
        let mut cache = self.0.lock().map_err(|_| S3Error::InternalError)?;
        cache.retain(|_, entry| entry.expires > Instant::now());
        if cache.len() >= 256 && !cache.contains_key(&key) {
            let oldest = cache
                .iter()
                .min_by_key(|(_, v)| v.expires)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                cache.remove(&oldest);
            }
        }
        cache.insert(key, entry);
        Ok(())
    }
}

fn cache_key(ctx: &Ctx<'_>, bucket: &str, key: &str, wrapped: Option<&[u8]>) -> String {
    let requester = (
        ctx.account,
        ctx.storage_account,
        ctx.region,
        ctx.identity
            .as_ref()
            .and_then(|identity| identity.access_key_id.as_deref()),
        format!("{:?}", ctx.delegated_identity),
        bucket,
        key,
        wrapped,
    );
    // The hash includes session identity/scoping and the exact wrapped bucket key.
    format!("{:x}", Sha256::digest(format!("{requester:?}").as_bytes()))
}

async fn validate_cached(
    ctx: &Ctx<'_>,
    entry: &BucketKey,
    context: &BTreeMap<String, String>,
    action: KmsDataKeyAction,
) -> Result<(), S3Error> {
    let call = kms_call(ctx, action.as_str(), &entry.key_arn, context)?;
    ctx.dispatcher
        .as_deref()
        .ok_or(S3Error::InternalError)?
        .kms_authorize_cached_key_bounded(
            KmsAuthorizeCachedKeyRequest {
                call,
                key_id: entry.key_arn.clone(),
                ciphertext: SensitiveBytes::new(entry.wrapped.clone()),
                encryption_context: context.clone(),
                action,
            },
            Duration::from_secs(3),
        )
        .await
        .map_err(kms_error)
}

pub(crate) async fn for_write(
    ctx: &Ctx<'_>,
    bucket: &str,
    key: &str,
    context: &BTreeMap<String, String>,
) -> Result<BucketKey, S3Error> {
    let cache_key = cache_key(ctx, bucket, key, None);
    if let Some(entry) = ctx.store.bucket_keys.get(&cache_key)? {
        validate_cached(ctx, &entry, context, KmsDataKeyAction::Generate).await?;
        return Ok(entry);
    }
    let call = kms_call(ctx, "kms:GenerateDataKey", key, context)?;
    let output = ctx
        .dispatcher
        .as_deref()
        .ok_or(S3Error::InternalError)?
        .kms_generate_data_key_bounded(
            KmsGenerateDataKeyRequest {
                call,
                key_id: key.into(),
                number_of_bytes: 32,
                encryption_context: context.clone(),
            },
            Duration::from_secs(3),
        )
        .await
        .map_err(kms_error)?;
    let entry = BucketKey {
        plain: Arc::new(output.plaintext),
        wrapped: output.ciphertext.into_vec(),
        key_arn: output.key_id,
        expires: Instant::now() + Duration::from_secs(300),
    };
    ctx.store.bucket_keys.insert(cache_key, entry.clone())?;
    Ok(entry)
}

pub(crate) async fn for_read(
    ctx: &Ctx<'_>,
    bucket: &str,
    key: &str,
    wrapped: &[u8],
    context: &BTreeMap<String, String>,
) -> Result<Arc<SensitiveBytes>, S3Error> {
    let cache_key = cache_key(ctx, bucket, key, Some(wrapped));
    if let Some(entry) = ctx.store.bucket_keys.get(&cache_key)? {
        validate_cached(ctx, &entry, context, KmsDataKeyAction::Decrypt).await?;
        return Ok(entry.plain);
    }
    let call = kms_call(ctx, "kms:Decrypt", key, context)?;
    let output = ctx
        .dispatcher
        .as_deref()
        .ok_or(S3Error::InternalError)?
        .kms_decrypt_bounded(
            KmsDecryptRequest {
                call,
                key_id: Some(key.into()),
                ciphertext: SensitiveBytes::new(wrapped.to_vec()),
                encryption_context: context.clone(),
            },
            Duration::from_secs(3),
        )
        .await
        .map_err(kms_error)?;
    let plain = Arc::new(output.plaintext);
    ctx.store.bucket_keys.insert(
        cache_key,
        BucketKey {
            plain: plain.clone(),
            wrapped: wrapped.to_vec(),
            key_arn: output.key_id,
            expires: Instant::now() + Duration::from_secs(300),
        },
    )?;
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_core::integration::kms::{
        KmsDecryptOutput, KmsEncryptOutput, KmsEncryptRequest, KmsGenerateDataKeyOutput,
        KmsInternalApi, KmsInternalError, KmsValidateKeyOutput, KmsValidateKeyRequest,
    };
    use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct CountingKms {
        generate: AtomicUsize,
        decrypt: AtomicUsize,
        authorize: AtomicUsize,
        denied: AtomicBool,
    }
    impl CountingKms {
        fn allowed(&self, context: &BTreeMap<String, String>) -> Result<(), KmsInternalError> {
            assert_eq!(
                context.get("aws:s3:arn").map(String::as_str),
                Some("arn:aws:s3:::bucket")
            );
            if self.denied.load(Ordering::Acquire) {
                Err(KmsInternalError::AccessDenied)
            } else {
                Ok(())
            }
        }
    }
    impl locallycloud_core::integration::authorization::AuthorizationEvaluator for CountingKms {
        fn authorize(
            &self,
            _: locallycloud_core::integration::authorization::AuthorizationRequest,
        ) -> Result<(), locallycloud_core::integration::authorization::AuthorizationError> {
            Ok(())
        }
        fn resolve_caller_arn(
            &self,
            identity: &locallycloud_core::integration::RequestIdentity,
        ) -> Result<Option<String>, locallycloud_core::integration::authorization::AuthorizationError>
        {
            Ok(identity
                .access_key_id
                .as_ref()
                .map(|key| format!("arn:aws:iam::{}:user/{key}", identity.account_id)))
        }
        fn identity_policy_allows(
            &self,
            _: locallycloud_core::integration::authorization::AuthorizationRequest,
        ) -> bool {
            true
        }
        fn identity_policy_denies(
            &self,
            _: locallycloud_core::integration::authorization::AuthorizationRequest,
        ) -> bool {
            false
        }
    }
    impl KmsInternalApi for CountingKms {
        fn encrypt(&self, _: KmsEncryptRequest) -> Result<KmsEncryptOutput, KmsInternalError> {
            Err(KmsInternalError::Unavailable)
        }
        fn generate_data_key(
            &self,
            request: KmsGenerateDataKeyRequest,
        ) -> Result<KmsGenerateDataKeyOutput, KmsInternalError> {
            self.allowed(&request.encryption_context)?;
            let ordinal = self.generate.fetch_add(1, Ordering::AcqRel) + 1;
            Ok(KmsGenerateDataKeyOutput {
                plaintext: SensitiveBytes::new(vec![ordinal as u8; 32]),
                ciphertext: SensitiveBytes::new(vec![ordinal as u8]),
                key_id: request.key_id,
            })
        }
        fn decrypt(
            &self,
            request: KmsDecryptRequest,
        ) -> Result<KmsDecryptOutput, KmsInternalError> {
            self.allowed(&request.encryption_context)?;
            self.decrypt.fetch_add(1, Ordering::AcqRel);
            Ok(KmsDecryptOutput {
                plaintext: SensitiveBytes::new(vec![request.ciphertext.as_slice()[0]; 32]),
                key_id: request.key_id.unwrap(),
            })
        }
        fn validate_key(
            &self,
            request: KmsValidateKeyRequest,
        ) -> Result<KmsValidateKeyOutput, KmsInternalError> {
            Ok(KmsValidateKeyOutput {
                key_arn: request.key_id,
            })
        }
        fn authorize_cached_key(
            &self,
            request: KmsAuthorizeCachedKeyRequest,
        ) -> Result<(), KmsInternalError> {
            self.authorize.fetch_add(1, Ordering::AcqRel);
            self.allowed(&request.encryption_context)
        }
    }
    #[async_trait::async_trait]
    impl locallycloud_core::handler::NativeHandler for CountingKms {
        async fn handle(
            &self,
            _: locallycloud_core::handler::ServiceRequest,
        ) -> axum::response::Response {
            http::Response::new(axum::body::Body::empty())
        }
    }

    #[tokio::test]
    async fn cached_bucket_keys_reduce_crypto_calls_without_sharing_requesters_or_hiding_denial() {
        let registry = ServiceRegistry::with_known_services();
        let kms = Arc::new(CountingKms::default());
        registry.register_native_with_kms_api(
            ServiceName::new("kms"),
            ServiceMetadata::new(AwsProtocol::Json11, Some("TrentService")),
            kms.clone(),
            kms.clone(),
        );
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            kms.clone(),
            kms.clone(),
        );
        let dispatcher = Arc::new(
            locallycloud_core::integration::InternalDispatcher::new_shared(
                &registry,
                locallycloud_core::proxy::ProxyConfig {
                    backend_url: "http://127.0.0.1:1".into(),
                    upstream_timeout: Duration::from_secs(1),
                },
                locallycloud_core::proxy::LegacyHealth::new(false),
                "us-east-1".into(),
                "000000000000".into(),
            ),
        );
        let store = crate::store::AccountStore::default();
        let mut ctx = Ctx {
            store: &store,
            account: "000000000000",
            storage_account: "000000000000",
            copy_source_account: None,
            region: "us-east-1",
            request_id: "request",
            dispatcher: Some(dispatcher),
            identity: Some(locallycloud_core::integration::RequestIdentity {
                account_id: "000000000000".into(),
                access_key_id: Some("first".into()),
                arn: None,
            }),
            delegated_identity: None,
            strict_external: false,
        };
        let context = BTreeMap::from([("aws:s3:arn".into(), "arn:aws:s3:::bucket".into())]);
        let first = for_write(&ctx, "bucket", "key", &context).await.unwrap();
        let second = for_write(&ctx, "bucket", "key", &context).await.unwrap();
        assert_eq!(first.wrapped, second.wrapped);
        assert_eq!(kms.generate.load(Ordering::Acquire), 1);
        let opened = for_read(&ctx, "bucket", "key", &first.wrapped, &context)
            .await
            .unwrap();
        assert_eq!(opened.as_slice(), first.plain.as_slice());
        for_read(&ctx, "bucket", "key", &first.wrapped, &context)
            .await
            .unwrap();
        assert_eq!(kms.decrypt.load(Ordering::Acquire), 1);
        assert_eq!(kms.authorize.load(Ordering::Acquire), 2);
        ctx.identity.as_mut().unwrap().access_key_id = Some("second".into());
        for_write(&ctx, "bucket", "key", &context).await.unwrap();
        assert_eq!(kms.generate.load(Ordering::Acquire), 2);
        ctx.delegated_identity = Some(
            locallycloud_core::integration::identity::CallerIdentity::AssumedRole {
                role_arn: "arn:aws:iam::000000000000:role/worker".into(),
                session_name: "scoped-session".into(),
            },
        );
        for_write(&ctx, "bucket", "key", &context).await.unwrap();
        assert_eq!(kms.generate.load(Ordering::Acquire), 3);
        kms.denied.store(true, Ordering::Release);
        assert!(matches!(
            for_write(&ctx, "bucket", "key", &context).await,
            Err(S3Error::AccessDenied)
        ));
        ctx.delegated_identity = None;
        ctx.identity.as_mut().unwrap().access_key_id = Some("first".into());
        assert!(matches!(
            for_read(&ctx, "bucket", "key", &first.wrapped, &context).await,
            Err(S3Error::AccessDenied)
        ));
        assert_eq!(kms.generate.load(Ordering::Acquire), 3);
        assert_eq!(kms.decrypt.load(Ordering::Acquire), 1);
    }

    #[test]
    fn data_keys_are_unique_and_bound_to_the_bucket_and_object() {
        let key = SensitiveBytes::new(vec![7; 32]);
        let (first, wrapped) =
            crate::encryption::wrap_bucket_key(&key, vec![9; 64], "bucket", "one").unwrap();
        let (second, _) =
            crate::encryption::wrap_bucket_key(&key, vec![9; 64], "bucket", "one").unwrap();
        assert_ne!(first.as_slice(), second.as_slice());
        let envelope = || serde_json::from_slice(&wrapped).unwrap();
        assert_eq!(
            crate::encryption::unwrap_bucket_key(&key, envelope(), "bucket", "one")
                .unwrap()
                .as_slice(),
            first.as_slice()
        );
        assert!(crate::encryption::unwrap_bucket_key(&key, envelope(), "other", "one").is_err());
        assert!(crate::encryption::unwrap_bucket_key(&key, envelope(), "bucket", "other").is_err());
        let mut tampered: crate::encryption::BucketEnvelope = envelope();
        tampered.object_key[13] ^= 1;
        assert!(crate::encryption::unwrap_bucket_key(&key, tampered, "bucket", "one").is_err());
    }
    #[test]
    fn cache_is_bounded_and_expired_keys_are_not_returned() {
        let cache = BucketKeyCache::default();
        let entry = BucketKey {
            plain: Arc::new(SensitiveBytes::new(vec![7; 32])),
            wrapped: vec![9; 64],
            key_arn: "key".into(),
            expires: Instant::now() + Duration::from_secs(300),
        };
        for index in 0..300 {
            cache.insert(index.to_string(), entry.clone()).unwrap();
        }
        assert_eq!(cache.0.lock().unwrap().len(), 256);
        let mut expired = entry;
        expired.expires = Instant::now() - Duration::from_secs(1);
        cache.insert("expired".into(), expired).unwrap();
        assert!(cache.get("expired").unwrap().is_none());
    }
}
