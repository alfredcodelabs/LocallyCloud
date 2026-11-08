//! Table-scoped KMS data keys for encrypted storage. This does not enable public SSE support.
pub mod catalog;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use locallycloud_core::integration::kms::{
    KmsCallContext, KmsDecryptRequest, KmsGenerateDataKeyRequest, KmsInternalError, KmsServiceKey,
    SensitiveBytes,
};
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_state::StateCipher;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DdbError;

const KMS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_ENVELOPE: usize = 64 * 1024;
const MAX_WRAPPED_KEY: usize = 16 * 1024;

/// Physical identity is independent of the reusable AWS table name.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "StoredScope")]
pub struct TableKeyScope {
    account: String,
    region: String,
    table: String,
    storage_id: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredScope {
    account: String,
    region: String,
    table: String,
    storage_id: Uuid,
}

impl TryFrom<StoredScope> for TableKeyScope {
    type Error = DdbError;

    fn try_from(scope: StoredScope) -> Result<Self, Self::Error> {
        Self::new(
            &scope.account,
            &scope.region,
            &scope.table,
            scope.storage_id,
        )
    }
}

impl TableKeyScope {
    pub fn new(
        account: &str,
        region: &str,
        table: &str,
        storage_id: Uuid,
    ) -> Result<Self, DdbError> {
        crate::streams::validate_scope_values(account, region)?;
        crate::store::validate_table_name(table)?;
        if storage_id.is_nil() {
            return Err(DdbError::Validation(
                "A physical table identity is required".into(),
            ));
        }
        Ok(Self {
            account: account.into(),
            region: region.into(),
            table: table.into(),
            storage_id,
        })
    }

    pub fn storage_id(&self) -> Uuid {
        self.storage_id
    }

    pub fn table_name(&self) -> &str {
        &self.table
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    fn context(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("aws:dynamodb:tableName".into(), self.table.clone()),
            ("aws:dynamodb:subscriberId".into(), self.account.clone()),
        ])
    }

    fn validate_call(&self, call: &KmsCallContext) -> Result<(), KmsInternalError> {
        if call.source_service != KmsServiceKey::DynamoDb.service_name()
            || call.account_id != self.account
            || call.region != self.region
            || call.request_id.is_empty()
        {
            return Err(KmsInternalError::InvalidRequest);
        }
        Ok(())
    }

    fn validate_key_arn(&self, arn: &str) -> Result<(), KmsInternalError> {
        let prefix = format!("arn:aws:kms:{}:{}:key/", self.region, self.account);
        let id = arn
            .strip_prefix(&prefix)
            .ok_or(KmsInternalError::InvalidCiphertext)?;
        if id.is_empty()
            || id.len() > 256
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(KmsInternalError::InvalidCiphertext);
        }
        Ok(())
    }
}

/// Only authenticated metadata containing the KMS-wrapped key is durable.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableKeyEnvelope {
    version: u8,
    sealed: Vec<u8>,
}

impl fmt::Debug for TableKeyEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TableKeyEnvelope")
            .field("version", &self.version)
            .field("sealed_bytes", &self.sealed.len())
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WrappedKey {
    key_arn: String,
    ciphertext: Vec<u8>,
}

/// Plaintext exists only long enough to initialize the encrypted table worker.
#[derive(Debug)]
pub struct TableKeyMaterial {
    pub plaintext: SensitiveBytes,
    pub envelope: TableKeyEnvelope,
    pub key_arn: String,
}

pub struct TableKeys {
    dispatcher: Arc<InternalDispatcher>,
    metadata_cipher: Arc<StateCipher>,
}

impl TableKeys {
    pub fn new(dispatcher: Arc<InternalDispatcher>, metadata_cipher: Arc<StateCipher>) -> Self {
        Self {
            dispatcher,
            metadata_cipher,
        }
    }

    pub async fn generate(
        &self,
        scope: &TableKeyScope,
        call: KmsCallContext,
        key_id: Option<&str>,
    ) -> Result<TableKeyMaterial, KmsInternalError> {
        scope.validate_call(&call)?;
        let key_id = match key_id {
            Some(id) if !id.is_empty() && id.len() <= 2048 => id.to_owned(),
            Some(_) => return Err(KmsInternalError::InvalidRequest),
            None => format!("alias/aws/{}", KmsServiceKey::DynamoDb.service_name()),
        };
        let generated = self
            .dispatcher
            .kms_generate_data_key_bounded(
                KmsGenerateDataKeyRequest {
                    call,
                    key_id,
                    number_of_bytes: 32,
                    encryption_context: scope.context(),
                },
                KMS_TIMEOUT,
            )
            .await?;
        scope.validate_key_arn(&generated.key_id)?;
        if generated.plaintext.as_slice().len() != 32
            || generated.ciphertext.as_slice().is_empty()
            || generated.ciphertext.as_slice().len() > MAX_WRAPPED_KEY
        {
            return Err(KmsInternalError::InvalidCiphertext);
        }
        let key_arn = generated.key_id;
        let wrapped = WrappedKey {
            key_arn: key_arn.clone(),
            ciphertext: generated.ciphertext.as_slice().to_vec(),
        };
        let encoded = serde_json::to_vec(&wrapped).map_err(|_| KmsInternalError::Internal)?;
        let id = scope.storage_id.to_string();
        let sealed = self
            .metadata_cipher
            .seal(
                &[
                    "dynamodb-table-key-v1",
                    &scope.account,
                    &scope.region,
                    &scope.table,
                    &id,
                ],
                &encoded,
            )
            .map_err(|_| KmsInternalError::Internal)?;
        if sealed.len() > MAX_ENVELOPE {
            return Err(KmsInternalError::Internal);
        }
        Ok(TableKeyMaterial {
            plaintext: generated.plaintext,
            envelope: TableKeyEnvelope { version: 1, sealed },
            key_arn,
        })
    }

    pub async fn open(
        &self,
        scope: &TableKeyScope,
        call: KmsCallContext,
        envelope: &TableKeyEnvelope,
    ) -> Result<SensitiveBytes, KmsInternalError> {
        scope.validate_call(&call)?;
        let wrapped = self.wrapped_key(scope, envelope)?;
        let opened = self
            .dispatcher
            .kms_decrypt_bounded(
                KmsDecryptRequest {
                    call,
                    key_id: Some(wrapped.key_arn.clone()),
                    ciphertext: SensitiveBytes::new(wrapped.ciphertext),
                    encryption_context: scope.context(),
                },
                KMS_TIMEOUT,
            )
            .await?;
        if opened.key_id != wrapped.key_arn || opened.plaintext.as_slice().len() != 32 {
            return Err(KmsInternalError::InvalidCiphertext);
        }
        Ok(opened.plaintext)
    }
    fn wrapped_key(
        &self,
        scope: &TableKeyScope,
        envelope: &TableKeyEnvelope,
    ) -> Result<WrappedKey, KmsInternalError> {
        if envelope.version != 1 || envelope.sealed.len() > MAX_ENVELOPE {
            return Err(KmsInternalError::InvalidCiphertext);
        }
        let id = scope.storage_id.to_string();
        let decoded = self
            .metadata_cipher
            .open(
                &[
                    "dynamodb-table-key-v1",
                    &scope.account,
                    &scope.region,
                    &scope.table,
                    &id,
                ],
                &envelope.sealed,
            )
            .map_err(|_| KmsInternalError::InvalidCiphertext)?;
        let wrapped: WrappedKey =
            serde_json::from_slice(&decoded).map_err(|_| KmsInternalError::InvalidCiphertext)?;
        scope.validate_key_arn(&wrapped.key_arn)?;
        if wrapped.ciphertext.is_empty() || wrapped.ciphertext.len() > MAX_WRAPPED_KEY {
            return Err(KmsInternalError::InvalidCiphertext);
        }
        Ok(wrapped)
    }
}
