//! Typed, protocol-neutral KMS operations for native service integrations.

use std::collections::BTreeMap;
use std::fmt;

/// Contract version understood by the registry and internal callers.
pub const KMS_INTERNAL_API_VERSION: u16 = 5;

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
}

impl KmsServiceKey {
    pub fn service_name(self) -> &'static str {
        match self {
            Self::SecretsManager => "secretsmanager",
            Self::Ssm => "ssm",
            Self::S3 => "s3",
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
