use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use locallycloud_state::StateDb;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::AuthorizationRequest;
use locallycloud_core::integration::kms::{
    KmsCallContext, KmsDecryptRequest, KmsEncryptRequest, KmsKeySelector, KmsServiceKey,
    SensitiveBytes as KmsSensitiveBytes,
};
use locallycloud_core::integration::lambda::{
    LambdaCallContext, LambdaInternalError, LambdaInvokeRequest, SensitivePayload,
};
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{AwsProtocol, ServiceRegistry};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::error::SecretsError;
use crate::model::{
    serialize_binary, serialize_string, PlainValue, RotationOccurrence, RotationState,
    RotationStep, Scope, SecretRecord, SecretVersion, SensitiveBytes, ValueKind, VersionOperation,
};
use crate::protocol::{
    self, CreateSecretRequest, DeleteSecretRequest, GetSecretValueRequest,
    ListSecretVersionIdsRequest, ListSecretsRequest, PutResourcePolicyRequest,
    PutSecretValueRequest, RotateSecretRequest, SecretIdRequest, Tag, TagResourceRequest,
    UntagResourceRequest, UpdateSecretRequest, UpdateSecretVersionStageRequest,
};
use crate::store::SecretStore;

const DEFAULT_MAX_RESULTS: usize = 100;
const MAX_SECRET_BYTES: usize = 65_536;
#[cfg(not(test))]
const KMS_WAIT_LIMIT: Duration = Duration::from_secs(2);
#[cfg(test)]
const KMS_WAIT_LIMIT: Duration = Duration::from_millis(100);

pub(crate) struct SecretsManagerHandler {
    registry: Weak<ServiceRegistry>,
    store: Arc<SecretStore>,
    persistence_failed: AtomicBool,
}

impl SecretsManagerHandler {
    pub(crate) fn new(registry: Weak<ServiceRegistry>) -> Self {
        Self {
            registry,
            store: Arc::new(SecretStore::new()),
            persistence_failed: AtomicBool::new(false),
        }
    }

    pub(crate) fn with_state(
        registry: Weak<ServiceRegistry>,
        state: Arc<StateDb>,
    ) -> Result<Self, SecretsError> {
        Ok(Self {
            registry,
            store: Arc::new(SecretStore::with_state(state)?),
            persistence_failed: AtomicBool::new(false),
        })
    }

    async fn persist(&self) -> Result<(), SecretsError> {
        let store = self.store.clone();
        let saved = tokio::task::spawn_blocking(move || store.save()).await;
        if !matches!(saved, Ok(Ok(()))) {
            self.persistence_failed.store(true, Ordering::Release);
            return Err(SecretsError::Internal);
        }
        Ok(())
    }

    async fn process(&self, request: &ServiceRequest) -> Result<Vec<u8>, SecretsError> {
        if request.method != http::Method::POST
            || request.uri.path() != "/"
            || request.uri.query().is_some()
        {
            return Err(SecretsError::UnknownOperation);
        }
        protocol::validate_content_type(&request.headers)?;
        if request.body.len() > protocol::MAX_REQUEST_BODY {
            return Err(SecretsError::InvalidParameter);
        }
        let operation = protocol::operation(&request.headers)?;
        let scope = Scope::new(&request.account_id, &request.region);
        match operation {
            "CreateSecret" => {
                self.create_secret(decode(&request.body)?, &scope, request)
                    .await
            }
            "PutSecretValue" => {
                self.put_secret_value(decode(&request.body)?, &scope, request)
                    .await
            }
            "GetSecretValue" => {
                self.get_secret_value(decode(&request.body)?, &scope, request)
                    .await
            }
            "UpdateSecret" => {
                self.update_secret(decode(&request.body)?, &scope, request)
                    .await
            }
            "UpdateSecretVersionStage" => {
                self.update_secret_version_stage(decode(&request.body)?, &scope, request)
            }
            "ListSecretVersionIds" => {
                self.list_secret_version_ids(decode(&request.body)?, &scope, request)
            }
            "DeleteSecret" => self.delete_secret(decode(&request.body)?, &scope, request),
            "RestoreSecret" => self.restore_secret(decode(&request.body)?, &scope, request),
            "DescribeSecret" => self.describe_secret(decode(&request.body)?, &scope, request),
            "ListSecrets" => self.list_secrets(decode(&request.body)?, &scope, request),
            "TagResource" => self.tag_resource(decode(&request.body)?, &scope, request),
            "UntagResource" => self.untag_resource(decode(&request.body)?, &scope, request),
            "GetResourcePolicy" => {
                self.get_resource_policy(decode(&request.body)?, &scope, request)
            }
            "PutResourcePolicy" => {
                self.put_resource_policy(decode(&request.body)?, &scope, request)
            }
            "DeleteResourcePolicy" => {
                self.delete_resource_policy(decode(&request.body)?, &scope, request)
            }
            "RotateSecret" => {
                self.rotate_secret(decode(&request.body)?, &scope, request)
                    .await
            }
            "CancelRotateSecret" => {
                self.cancel_rotate_secret(decode(&request.body)?, &scope, request)
            }
            _ => Err(SecretsError::UnknownOperation),
        }
    }

    fn resolve_and_authorize(
        &self,
        scope: &Scope,
        secret_id: &str,
        request: &ServiceRequest,
        operation: &str,
    ) -> Result<Arc<Mutex<Option<SecretRecord>>>, SecretsError> {
        let slot = self.store.resolve(scope, secret_id)?;
        let arn = lock(&slot)?
            .as_ref()
            .map(|record| record.arn.clone())
            .ok_or(SecretsError::ResourceNotFound)?;
        self.authorize(request, operation, &arn)?;
        Ok(slot)
    }

    fn authorize(
        &self,
        request: &ServiceRequest,
        operation: &str,
        resource: &str,
    ) -> Result<(), SecretsError> {
        let dispatcher = self.dispatcher()?;
        let authorization = request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        let mut context = BTreeMap::new();
        context.insert(
            "aws:RequestedRegion".to_owned(),
            vec![request.region.clone()],
        );
        context.insert(
            "aws:ResourceAccount".to_owned(),
            vec![request.account_id.clone()],
        );
        dispatcher
            .authorize(AuthorizationRequest {
                request_identity: RequestIdentity {
                    account_id: request.account_id.clone(),
                    access_key_id: authorization
                        .and_then(RequestIdentity::access_key_from_authorization),
                    arn: None,
                },
                delegated_identity: None,
                source_service: "secretsmanager".to_owned(),
                action: format!("secretsmanager:{operation}"),
                resource: resource.to_owned(),
                context,
            })
            .map_err(SecretsError::from_authorization)
    }

    #[allow(clippy::too_many_arguments)]
    async fn encrypt_version(
        &self,
        request: &ServiceRequest,
        scope: &Scope,
        arn: &str,
        version_id: &str,
        value: PlainValue,
        kms_key_id: Option<&str>,
        operation: VersionOperation,
        stages: BTreeSet<String>,
        created_date: f64,
    ) -> Result<SecretVersion, SecretsError> {
        validate_value(&value)?;
        let PlainValue {
            kind,
            bytes,
            digest,
        } = value;
        let output = self
            .dispatcher()?
            .kms_encrypt_bounded(
                KmsEncryptRequest {
                    call: kms_call(request, scope),
                    key: kms_key_id.map_or(
                        KmsKeySelector::ServiceDefault(KmsServiceKey::SecretsManager),
                        |key| KmsKeySelector::Explicit(key.to_owned()),
                    ),
                    plaintext: KmsSensitiveBytes::new(bytes.into_vec()),
                    encryption_context: encryption_context(arn, version_id),
                },
                KMS_WAIT_LIMIT,
            )
            .await
            .map_err(SecretsError::from_encrypt)?;
        Ok(SecretVersion {
            id: version_id.to_owned(),
            ciphertext: SensitiveBytes::new(output.ciphertext.into_vec()),
            kind,
            digest,
            operation,
            requested_stages: stages,
            stages: BTreeSet::new(),
            created_date,
            key_arn: output.key_id,
        })
    }

    async fn decrypt_value(
        &self,
        request: &ServiceRequest,
        scope: &Scope,
        arn: &str,
        version_id: &str,
        key_arn: &str,
        ciphertext: SensitiveBytes,
    ) -> Result<SensitiveBytes, SecretsError> {
        let output = self
            .dispatcher()?
            .kms_decrypt_bounded(
                KmsDecryptRequest {
                    call: kms_call(request, scope),
                    key_id: Some(key_arn.to_owned()),
                    ciphertext: KmsSensitiveBytes::new(ciphertext.into_vec()),
                    encryption_context: encryption_context(arn, version_id),
                },
                KMS_WAIT_LIMIT,
            )
            .await
            .map_err(SecretsError::from_decrypt)?;
        Ok(SensitiveBytes::new(output.plaintext.into_vec()))
    }

    fn dispatcher(
        &self,
    ) -> Result<Arc<locallycloud_core::integration::InternalDispatcher>, SecretsError> {
        self.registry
            .upgrade()
            .and_then(|registry| registry.internal_dispatcher())
            .ok_or(SecretsError::Internal)
    }
}

#[async_trait]
impl NativeHandler for SecretsManagerHandler {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        self.store.resource_regions(account)
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let result = if self.persistence_failed.load(Ordering::Acquire) {
            Err(SecretsError::Internal)
        } else {
            let write = protocol::operation(&request.headers).is_ok_and(|op| {
                matches!(
                    op,
                    "CreateSecret"
                        | "PutSecretValue"
                        | "UpdateSecret"
                        | "UpdateSecretVersionStage"
                        | "DeleteSecret"
                        | "RestoreSecret"
                        | "TagResource"
                        | "UntagResource"
                        | "PutResourcePolicy"
                        | "DeleteResourcePolicy"
                        | "RotateSecret"
                        | "CancelRotateSecret"
                )
            });
            let result = self.process(&request).await;
            if write && result.is_ok() && self.persist().await.is_err() {
                self.persistence_failed.store(true, Ordering::Release);
                Err(SecretsError::Internal)
            } else {
                result
            }
        };
        match result {
            Ok(body) => Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, protocol::CONTENT_TYPE)
                .header("x-amzn-RequestId", &request.request_id)
                .body(Body::from(body))
                .expect("Secrets Manager JSON response is valid"),
            Err(error) => AwsError::from(error)
                .with_request_id(request.request_id)
                .render(AwsProtocol::Json11)
                .into_response(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct GetSecretValueOutput {
    #[serde(rename = "ARN")]
    arn: String,
    name: String,
    version_id: String,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_string"
    )]
    secret_string: Option<SensitiveBytes>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_binary"
    )]
    secret_binary: Option<SensitiveBytes>,
    version_stages: BTreeSet<String>,
    created_date: f64,
}

fn serialize_optional_string<S>(
    value: &Option<SensitiveBytes>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(value) => serialize_string(value, serializer),
        None => serializer.serialize_none(),
    }
}

fn serialize_optional_binary<S>(
    value: &Option<SensitiveBytes>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(value) => serialize_binary(value, serializer),
        None => serializer.serialize_none(),
    }
}

mod helpers;
mod mutations;
mod reads;
mod rotation;
use helpers::*;

#[cfg(test)]
mod kms_boundary_tests {
    use super::*;
    use axum::body::Bytes;
    use locallycloud_core::integration::authorization::{
        AuthorizationError, AuthorizationEvaluator, AuthorizationRequest,
    };
    use locallycloud_core::integration::kms::{
        KmsDecryptOutput, KmsEncryptOutput, KmsGenerateDataKeyOutput, KmsGenerateDataKeyRequest,
        KmsInternalApi, KmsInternalError, KmsValidateKeyOutput, KmsValidateKeyRequest,
    };
    use locallycloud_core::integration::InternalDispatcher;
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
    use locallycloud_core::registry::{ServiceMetadata, ServiceName};
    use std::sync::atomic::{AtomicU8, Ordering};

    struct EmptyHandler;

    #[async_trait]
    impl NativeHandler for EmptyHandler {
        async fn handle(&self, _: ServiceRequest) -> Response {
            Response::new(Body::empty())
        }
    }

    struct PermitAll;

    impl AuthorizationEvaluator for PermitAll {
        fn authorize(&self, _: AuthorizationRequest) -> Result<(), AuthorizationError> {
            Ok(())
        }
    }

    // 0 = healthy, 1 = unavailable, 2 = completes only after caller timeout.
    #[derive(Default)]
    struct FaultKms {
        encrypt_mode: AtomicU8,
        decrypt_mode: AtomicU8,
    }

    impl FaultKms {
        fn fail(mode: u8) -> Result<(), KmsInternalError> {
            match mode {
                1 => Err(KmsInternalError::Unavailable),
                2 => {
                    std::thread::sleep(Duration::from_millis(250));
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }

    impl KmsInternalApi for FaultKms {
        fn encrypt(
            &self,
            request: KmsEncryptRequest,
        ) -> Result<KmsEncryptOutput, KmsInternalError> {
            Self::fail(self.encrypt_mode.load(Ordering::SeqCst))?;
            Ok(KmsEncryptOutput {
                ciphertext: KmsSensitiveBytes::new(
                    request
                        .plaintext
                        .as_slice()
                        .iter()
                        .map(|b| b ^ 0xaa)
                        .collect(),
                ),
                key_id: "arn:aws:kms:us-east-1:000000000000:key/test".into(),
            })
        }

        fn decrypt(
            &self,
            request: KmsDecryptRequest,
        ) -> Result<KmsDecryptOutput, KmsInternalError> {
            Self::fail(self.decrypt_mode.load(Ordering::SeqCst))?;
            Ok(KmsDecryptOutput {
                plaintext: KmsSensitiveBytes::new(
                    request
                        .ciphertext
                        .as_slice()
                        .iter()
                        .map(|b| b ^ 0xaa)
                        .collect(),
                ),
                key_id: "arn:aws:kms:us-east-1:000000000000:key/test".into(),
            })
        }

        fn generate_data_key(
            &self,
            _: KmsGenerateDataKeyRequest,
        ) -> Result<KmsGenerateDataKeyOutput, KmsInternalError> {
            Err(KmsInternalError::Unavailable)
        }

        fn validate_key(
            &self,
            _: KmsValidateKeyRequest,
        ) -> Result<KmsValidateKeyOutput, KmsInternalError> {
            Err(KmsInternalError::Unavailable)
        }
    }

    fn request(operation: &str, body: serde_json::Value) -> ServiceRequest {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "content-type",
            "application/x-amz-json-1.1".parse().unwrap(),
        );
        headers.insert(
            "x-amz-target",
            format!("secretsmanager.{operation}").parse().unwrap(),
        );
        ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(body.to_string()),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "test-request".into(),
        }
    }

    fn setup() -> (SecretsManagerHandler, Arc<FaultKms>, Arc<ServiceRegistry>) {
        let registry = ServiceRegistry::with_known_services();
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Json11, None),
            Arc::new(EmptyHandler),
            Arc::new(PermitAll),
        );
        let kms = Arc::new(FaultKms::default());
        registry.register_native_with_kms_api(
            ServiceName::new("kms"),
            ServiceMetadata::new(AwsProtocol::Json11, None),
            Arc::new(EmptyHandler),
            kms.clone(),
        );
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        )));
        (
            SecretsManagerHandler::new(Arc::downgrade(&registry)),
            kms,
            registry,
        )
    }

    async fn http_call(
        address: std::net::SocketAddr,
        operation: &str,
        value: serde_json::Value,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let body = value.to_string();
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let wire = format!(
            "POST / HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/x-amz-json-1.1\r\nX-Amz-Target: secretsmanager.{operation}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(wire.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    #[tokio::test]
    async fn persisted_secret_survives_handler_restart_with_metadata_and_ciphertext() {
        let (_, _, registry) = setup();
        let path = std::env::temp_dir()
            .join(format!("locallycloud-sm-{}", uuid::Uuid::new_v4()))
            .join("state.sqlite3");
        let state = Arc::new(locallycloud_state::StateDb::open(path.clone()).unwrap());
        let handler =
            SecretsManagerHandler::with_state(Arc::downgrade(&registry), state.clone()).unwrap();
        let created = handler.handle(request("CreateSecret", json!({"Name":"durable","SecretString":"secret-canary","Tags":[{"Key":"team","Value":"data"}]}))).await;
        assert_eq!(created.status(), http::StatusCode::OK);
        let policy = handler.handle(request("PutResourcePolicy", json!({"SecretId":"durable","ResourcePolicy":"{\"Version\":\"2012-10-17\",\"Statement\":[]}"}))).await;
        assert_eq!(policy.status(), http::StatusCode::OK);
        drop(handler);
        let restarted =
            SecretsManagerHandler::with_state(Arc::downgrade(&registry), state).unwrap();
        let value = restarted
            .handle(request("GetSecretValue", json!({"SecretId":"durable"})))
            .await;
        assert_eq!(value.status(), http::StatusCode::OK);
        let body = axum::body::to_bytes(value.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["SecretString"],
            "secret-canary"
        );
        let slot = restarted
            .store
            .resolve(&Scope::new("000000000000", "us-east-1"), "durable")
            .unwrap();
        let guard = lock(&slot).unwrap();
        let record = guard.as_ref().unwrap();
        assert_eq!(record.tags.get("team").map(String::as_str), Some("data"));
        assert!(record.resource_policy.is_some());
        drop(guard);
        drop(restarted);
        drop(path);
    }

    #[tokio::test]
    async fn sqlite_failure_never_acknowledges_secret_write() {
        let (_, _, registry) = setup();
        let path = std::env::temp_dir()
            .join(format!("locallycloud-sm-{}", uuid::Uuid::new_v4()))
            .join("state.sqlite3");
        let state = Arc::new(locallycloud_state::StateDb::open(path).unwrap());
        let handler =
            SecretsManagerHandler::with_state(Arc::downgrade(&registry), state.clone()).unwrap();
        state
            .connection()
            .unwrap()
            .execute("DROP TABLE sm_secrets", [])
            .unwrap();
        let created = handler
            .handle(request(
                "CreateSecret",
                json!({"Name":"lost","SecretString":"secret-canary"}),
            ))
            .await;
        assert_eq!(created.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
        let read = handler
            .handle(request("GetSecretValue", json!({"SecretId":"lost"})))
            .await;
        assert_eq!(read.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn http_endpoint_fails_closed_for_unavailable_and_timed_out_kms() {
        use axum::routing::post;
        let (handler, kms, _registry) = setup();
        let handler = Arc::new(handler);
        let endpoint_handler = handler.clone();
        let app = axum::Router::new().route(
            "/",
            post(move |headers: http::HeaderMap, body: Bytes| {
                let endpoint_handler = endpoint_handler.clone();
                async move {
                    endpoint_handler
                        .handle(ServiceRequest {
                            method: http::Method::POST,
                            uri: "/".parse().unwrap(),
                            headers,
                            body,
                            region: "us-east-1".into(),
                            account_id: "000000000000".into(),
                            request_id: "http-test".into(),
                        })
                        .await
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let scope = Scope::new("000000000000", "us-east-1");

        for mode in [1, 2] {
            kms.encrypt_mode.store(mode, Ordering::SeqCst);
            let name = format!("http-failed-create-{mode}");
            let response = http_call(
                address,
                "CreateSecret",
                json!({
                    "Name": name, "SecretString": "http-create-canary"
                }),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 400"), "{response}");
            assert!(response.contains("EncryptionFailure"), "{response}");
            assert!(!response.contains("http-create-canary"), "{response}");
            assert!(lock(&handler.store.slot_for_name(&scope, &name))
                .unwrap()
                .is_none());
        }
        kms.encrypt_mode.store(0, Ordering::SeqCst);
        let response = http_call(
            address,
            "CreateSecret",
            json!({
                "Name": "http-existing", "SecretString": "http-original-canary"
            }),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let slot = handler.store.slot_for_name(&scope, "http-existing");
        let before = {
            let guard = lock(&slot).unwrap();
            let record = guard.as_ref().unwrap();
            (record.stage_index.clone(), record.versions.len())
        };
        for mode in [1, 2] {
            kms.encrypt_mode.store(mode, Ordering::SeqCst);
            let response = http_call(
                address,
                "PutSecretValue",
                json!({
                    "SecretId": "http-existing", "SecretString": "http-put-canary"
                }),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 400"), "{response}");
            assert!(response.contains("EncryptionFailure"), "{response}");
            assert!(!response.contains("http-put-canary"), "{response}");
            kms.decrypt_mode.store(mode, Ordering::SeqCst);
            let response = http_call(
                address,
                "GetSecretValue",
                json!({
                    "SecretId": "http-existing"
                }),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 400"), "{response}");
            assert!(response.contains("DecryptionFailure"), "{response}");
            assert!(!response.contains("http-original-canary"), "{response}");
            kms.decrypt_mode.store(0, Ordering::SeqCst);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let guard = lock(&slot).unwrap();
        let record = guard.as_ref().unwrap();
        assert_eq!(record.stage_index, before.0);
        assert_eq!(record.versions.len(), before.1);
        server.abort();
    }

    #[tokio::test]
    async fn kms_unavailable_and_late_result_do_not_publish_versions_or_plaintext() {
        let (handler, kms, _registry) = setup();
        let scope = Scope::new("000000000000", "us-east-1");
        for mode in [1, 2] {
            kms.encrypt_mode.store(mode, Ordering::SeqCst);
            let name = format!("failed-create-{mode}");
            let result = handler
                .process(&request(
                    "CreateSecret",
                    json!({
                        "Name": name, "SecretString": "canary-create"
                    }),
                ))
                .await;
            assert!(matches!(result, Err(SecretsError::EncryptionFailure)));
            if mode == 2 {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            assert!(lock(&handler.store.slot_for_name(&scope, &name))
                .unwrap()
                .is_none());
        }

        kms.encrypt_mode.store(0, Ordering::SeqCst);
        handler
            .process(&request(
                "CreateSecret",
                json!({
                    "Name": "existing", "SecretString": "canary-original"
                }),
            ))
            .await
            .unwrap();
        let slot = handler.store.slot_for_name(&scope, "existing");
        let before = {
            let guard = lock(&slot).unwrap();
            let record = guard.as_ref().unwrap();
            (record.stage_index.clone(), record.versions.len())
        };
        for mode in [1, 2] {
            kms.encrypt_mode.store(mode, Ordering::SeqCst);
            let result = handler
                .process(&request(
                    "PutSecretValue",
                    json!({
                        "SecretId": "existing", "SecretString": "canary-put"
                    }),
                ))
                .await;
            assert!(matches!(result, Err(SecretsError::EncryptionFailure)));
            let result = handler
                .process(&request(
                    "UpdateSecret",
                    json!({
                        "SecretId": "existing", "SecretString": "canary-update"
                    }),
                ))
                .await;
            assert!(matches!(result, Err(SecretsError::EncryptionFailure)));
            if mode == 2 {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            let guard = lock(&slot).unwrap();
            let record = guard.as_ref().unwrap();
            assert_eq!(record.stage_index, before.0);
            assert_eq!(record.versions.len(), before.1);
        }

        kms.decrypt_mode.store(1, Ordering::SeqCst);
        let result = handler
            .process(&request(
                "GetSecretValue",
                json!({
                    "SecretId": "existing"
                }),
            ))
            .await;
        assert!(matches!(result, Err(SecretsError::DecryptionFailure)));
        kms.decrypt_mode.store(2, Ordering::SeqCst);
        let result = handler
            .process(&request(
                "GetSecretValue",
                json!({
                    "SecretId": "existing"
                }),
            ))
            .await;
        assert!(matches!(result, Err(SecretsError::DecryptionFailure)));
        let response = handler
            .handle(request("GetSecretValue", json!({"SecretId": "existing"})))
            .await;
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
        let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response_text = String::from_utf8(response_body.to_vec()).unwrap();
        assert!(response_text.contains("DecryptionFailure"));
        assert!(!response_text.contains("canary-original"));
        kms.decrypt_mode.store(0, Ordering::SeqCst);
        let result = handler
            .process(&request(
                "GetSecretValue",
                json!({
                    "SecretId": "existing"
                }),
            ))
            .await
            .unwrap();
        assert!(String::from_utf8(result)
            .unwrap()
            .contains("canary-original"));
    }
}
