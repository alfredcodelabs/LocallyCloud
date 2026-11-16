//! Typed, protocol-neutral KMS operations for native service integrations.

use std::collections::BTreeMap;
use std::fmt;

/// Contract version understood by the registry and internal callers.
pub const KMS_INTERNAL_API_VERSION: u16 = 7;

#[derive(Clone, Copy)]
pub enum KmsDataKeyAction {
    Generate,
    Decrypt,
}

impl KmsDataKeyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generate => "kms:GenerateDataKey",
            Self::Decrypt => "kms:Decrypt",
        }
    }
}

/// Revalidate a cached service key without generating or decrypting key material again.
pub struct KmsAuthorizeCachedKeyRequest {
    pub call: KmsCallContext,
    pub key_id: String,
    pub ciphertext: SensitiveBytes,
    pub encryption_context: BTreeMap<String, String>,
    pub action: KmsDataKeyAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsCallContext {
    pub source_service: String,
    pub account_id: String,
    pub region: String,
    pub request_id: String,
    pub caller_arn: Option<String>,
    /// True only when the stored IAM identity policy explicitly permits this operation.
    pub iam_policy_allowed: bool,
    /// Explicit IAM deny or an unresolved/boundary-limited identity; cannot be overridden by key policy.
    pub iam_policy_denied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmsServiceKey {
    SecretsManager,
    Ssm,
    S3,
    DynamoDb,
}

impl KmsServiceKey {
    pub fn service_name(self) -> &'static str {
        match self {
            Self::SecretsManager => "secretsmanager",
            Self::Ssm => "ssm",
            Self::S3 => "s3",
            Self::DynamoDb => "dynamodb",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmsKeySelector {
    Explicit(String),
    ServiceDefault(KmsServiceKey),
}

pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveBytes")
            .field("length", &self.0.len())
            .field("value", &"[redacted]")
            .finish()
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub struct KmsEncryptRequest {
    pub call: KmsCallContext,
    pub key: KmsKeySelector,
    pub plaintext: SensitiveBytes,
    pub encryption_context: BTreeMap<String, String>,
}

impl fmt::Debug for KmsEncryptRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KmsEncryptRequest")
            .field("call", &self.call)
            .field("key", &self.key)
            .field("plaintext", &self.plaintext)
            .field("encryption_context_entries", &self.encryption_context.len())
            .finish()
    }
}

pub struct KmsEncryptOutput {
    pub ciphertext: SensitiveBytes,
    pub key_id: String,
}

/// A fresh symmetric data key and its KMS-encrypted copy.
pub struct KmsGenerateDataKeyRequest {
    pub call: KmsCallContext,
    pub key_id: String,
    pub number_of_bytes: usize,
    pub encryption_context: BTreeMap<String, String>,
}

pub struct KmsGenerateDataKeyOutput {
    pub plaintext: SensitiveBytes,
    pub ciphertext: SensitiveBytes,
    pub key_id: String,
}

pub struct KmsDecryptRequest {
    pub call: KmsCallContext,
    pub key_id: Option<String>,
    pub ciphertext: SensitiveBytes,
    pub encryption_context: BTreeMap<String, String>,
}

impl fmt::Debug for KmsDecryptRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KmsDecryptRequest")
            .field("call", &self.call)
            .field("key_id", &self.key_id)
            .field("ciphertext", &self.ciphertext)
            .field("encryption_context_entries", &self.encryption_context.len())
            .finish()
    }
}

pub struct KmsDecryptOutput {
    pub plaintext: SensitiveBytes,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsValidateKeyRequest {
    pub call: KmsCallContext,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsValidateKeyOutput {
    pub key_arn: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KmsInternalError {
    #[error("KMS internal capability is unavailable")]
    Unavailable,
    #[error("KMS rejected the internal request")]
    InvalidRequest,
    #[error("KMS key was not found")]
    NotFound,
    #[error("KMS key is disabled")]
    Disabled,
    #[error("KMS key is not usable")]
    InvalidState,
    #[error("KMS rejected the ciphertext")]
    InvalidCiphertext,
    #[error("KMS denied the internal request")]
    AccessDenied,
    #[error("KMS internal operation failed")]
    Internal,
}

pub trait KmsInternalApi: Send + Sync {
    /// Current resource aliases for a canonical key ARN, without key material or authorization recursion.
    /// An absent/planned key has no aliases. Unavailable metadata must fail authorization closed.
    fn resource_aliases(&self, _key_arn: &str) -> Result<Vec<String>, KmsInternalError> {
        Err(KmsInternalError::Unavailable)
    }
    fn authorize_cached_key(
        &self,
        _request: KmsAuthorizeCachedKeyRequest,
    ) -> Result<(), KmsInternalError> {
        Err(KmsInternalError::Unavailable)
    }
    fn version(&self) -> u16 {
        KMS_INTERNAL_API_VERSION
    }

    fn encrypt(&self, request: KmsEncryptRequest) -> Result<KmsEncryptOutput, KmsInternalError>;

    fn generate_data_key(
        &self,
        request: KmsGenerateDataKeyRequest,
    ) -> Result<KmsGenerateDataKeyOutput, KmsInternalError>;

    fn decrypt(&self, request: KmsDecryptRequest) -> Result<KmsDecryptOutput, KmsInternalError>;

    fn validate_key(
        &self,
        request: KmsValidateKeyRequest,
    ) -> Result<KmsValidateKeyOutput, KmsInternalError>;
}

impl super::InternalDispatcher {
    /// Resolve the concrete key and preserve the authenticated caller for a native KMS hop.
    /// Identity permission is evidence for key-policy delegation, never a substitute for it.
    pub async fn kms_call_context(
        &self,
        request: &crate::handler::ServiceRequest,
        service: &str,
        action: &str,
        key_id: &str,
        encryption: &BTreeMap<String, String>,
        wait_limit: std::time::Duration,
    ) -> Result<(KmsCallContext, String), KmsInternalError> {
        if !matches!(
            action,
            "kms:Encrypt" | "kms:Decrypt" | "kms:GenerateDataKey"
        ) {
            return Err(KmsInternalError::InvalidRequest);
        }
        let identity = super::RequestIdentity {
            account_id: request.account_id.clone(),
            access_key_id: request
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(super::RequestIdentity::access_key_from_authorization),
            arn: None,
        };
        let delegated_identity = super::identity::trusted_role(request);
        let service_principal = request
            .headers
            .get("x-locallycloud-verified-internal-scope")
            .filter(|value| *value == "1")
            .and_then(|_| request.headers.get(super::identity::PRINCIPAL_HEADER))
            .and_then(|value| value.to_str().ok())
            .filter(|principal| {
                principal
                    .strip_suffix(".amazonaws.com")
                    .is_some_and(|service| {
                        !service.is_empty()
                            && service
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    })
            });
        let caller_arn = match &delegated_identity {
            Some(super::identity::CallerIdentity::AssumedRole { role_arn, .. }) => {
                Some(role_arn.clone())
            }
            _ if service_principal.is_some() => service_principal.map(str::to_owned),
            _ => self
                .resolve_caller_arn(&identity)
                .map_err(|_| KmsInternalError::AccessDenied)?,
        };
        let mut call = KmsCallContext {
            source_service: service.into(),
            account_id: request.account_id.clone(),
            region: request.region.clone(),
            request_id: request.request_id.clone(),
            caller_arn,
            iam_policy_allowed: false,
            iam_policy_denied: false,
        };
        let resolved = self
            .kms_validate_key_bounded(
                KmsValidateKeyRequest {
                    call: call.clone(),
                    key_id: key_id.into(),
                },
                wait_limit,
            )
            .await?;
        let mut context = BTreeMap::from([
            (
                "kms:viaservice".into(),
                vec![format!("{service}.{}.amazonaws.com", request.region)],
            ),
            ("kms:calleraccount".into(), vec![request.account_id.clone()]),
            ("aws:requestedregion".into(), vec![request.region.clone()]),
            (
                "kms:encryptioncontextkeys".into(),
                encryption.keys().cloned().collect(),
            ),
        ]);
        for (key, value) in encryption {
            context
                .entry(format!(
                    "kms:encryptioncontext:{}",
                    key.to_ascii_lowercase()
                ))
                .or_insert_with(Vec::new)
                .push(value.clone());
        }
        if let Some(arn) = &call.caller_arn {
            context.insert("aws:principalarn".into(), vec![arn.clone()]);
            context.insert(
                "aws:principalaccount".into(),
                vec![request.account_id.clone()],
            );
        }
        let authorization = super::authorization::AuthorizationRequest {
            request_identity: identity,
            delegated_identity,
            source_service: service.into(),
            action: action.into(),
            resource: resolved.key_arn.clone(),
            context,
        };
        // AWS service principals have no identity policy. Their key-policy grant is still
        // checked by KMS; only Core-attested internal calls can take this path.
        if service_principal.is_none() {
            call.iam_policy_denied = (call.caller_arn.is_some() || self.strict_sigv4_required())
                && self.identity_policy_denies(authorization.clone());
            call.iam_policy_allowed = self.identity_policy_allows(authorization);
        }
        Ok((call, resolved.key_arn))
    }
}
