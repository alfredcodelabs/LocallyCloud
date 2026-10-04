use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::policy::KeyPolicy;

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct Scope {
    pub(crate) account_id: String,
    pub(crate) region: String,
}

impl Scope {
    pub(crate) fn new(account_id: &str, region: &str) -> Self {
        Self {
            account_id: account_id.to_owned(),
            region: region.to_owned(),
        }
    }

    pub(crate) fn key_arn(&self, key_id: &str) -> String {
        format!(
            "arn:aws:kms:{}:{}:key/{key_id}",
            self.region, self.account_id
        )
    }

    pub(crate) fn alias_arn(&self, alias_name: &str) -> String {
        format!(
            "arn:aws:kms:{}:{}:{alias_name}",
            self.region, self.account_id
        )
    }
}

#[derive(Clone)]
pub(crate) struct SecretMaterial([u8; 32]);

impl SecretMaterial {
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone)]
pub(crate) enum KeyState {
    Enabled,
    Disabled,
    PendingDeletion {
        deletion_date: f64,
        pending_window_days: u32,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyManager {
    Customer,
    Aws,
}

impl KeyManager {
    fn as_str(self) -> &'static str {
        match self {
            Self::Customer => "CUSTOMER",
            Self::Aws => "AWS",
        }
    }
}

#[derive(Clone)]
pub(crate) struct KeyRecord {
    pub(crate) key_id: String,
    pub(crate) description: String,
    pub(crate) creation_date: f64,
    pub(crate) state: KeyState,
    pub(crate) manager: KeyManager,
    pub(crate) owner_service: Option<String>,
    pub(crate) policy: KeyPolicy,
    pub(crate) explicit_policy: bool,
    pub(crate) material_version: u32,
    pub(crate) material: SecretMaterial,
}

impl KeyRecord {
    pub(crate) fn is_enabled(&self) -> bool {
        matches!(self.state, KeyState::Enabled)
    }

    pub(crate) fn metadata(&self, scope: &Scope) -> Value {
        let (key_state, deletion_date) = match self.state {
            KeyState::Enabled => ("Enabled", None),
            KeyState::Disabled => ("Disabled", None),
            KeyState::PendingDeletion { deletion_date, .. } => {
                ("PendingDeletion", Some(deletion_date))
            }
        };
        let mut metadata = json!({
            "AWSAccountId": scope.account_id,
            "KeyId": self.key_id,
            "Arn": scope.key_arn(&self.key_id),
            "CreationDate": self.creation_date,
            "Enabled": self.is_enabled(),
            "Description": self.description,
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": key_state,
            "Origin": "AWS_KMS",
            "KeyManager": self.manager.as_str(),
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "KeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
            "MultiRegion": false
        });
        if let Some(deletion_date) = deletion_date {
            metadata["DeletionDate"] = json!(deletion_date);
        }
        metadata
    }

    pub(crate) fn pending_window_days(&self) -> Option<u32> {
        match self.state {
            KeyState::PendingDeletion {
                pending_window_days,
                ..
            } => Some(pending_window_days),
            KeyState::Enabled | KeyState::Disabled => None,
        }
    }
}

pub(crate) struct KeyListEntry {
    pub(crate) key_id: String,
    pub(crate) key_arn: String,
}

#[derive(Clone)]
pub(crate) struct AliasRecord {
    pub(crate) alias_name: String,
    pub(crate) target_key_id: String,
    pub(crate) creation_date: f64,
    pub(crate) last_updated_date: f64,
}
