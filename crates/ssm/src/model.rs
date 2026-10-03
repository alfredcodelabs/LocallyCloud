use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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

    pub(crate) fn parameter_arn(&self, name: &str) -> String {
        let name = name.strip_prefix('/').unwrap_or(name);
        format!(
            "arn:aws:ssm:{}:{}:parameter/{name}",
            self.region, self.account_id
        )
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SecretString(String);

impl SecretString {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) enum ParameterValue {
    Plain(SecretString),
    Encrypted {
        ciphertext: Vec<u8>,
        key_arn: String,
        key_id: String,
    },
}

impl ParameterValue {
    pub(crate) fn parameter_type(&self) -> &'static str {
        match self {
            Self::Plain(_) => "String",
            Self::Encrypted { .. } => "SecureString",
        }
    }

    pub(crate) fn key_id(&self) -> Option<&str> {
        match self {
            Self::Plain(_) => None,
            Self::Encrypted { key_id, .. } => Some(key_id),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ParameterRecord {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) value: ParameterValue,
    pub(crate) version: u64,
    pub(crate) last_modified_date: f64,
    pub(crate) tags: std::collections::BTreeMap<String, String>,
}

pub(crate) enum ParameterValueSnapshot {
    Plain(String),
    Encrypted {
        ciphertext: Vec<u8>,
        key_arn: String,
    },
}

pub(crate) struct ParameterSnapshot {
    pub(crate) name: String,
    pub(crate) value: ParameterValueSnapshot,
    pub(crate) version: u64,
    pub(crate) last_modified_date: f64,
}

pub(crate) struct ParameterMetadataSnapshot {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) parameter_type: &'static str,
    pub(crate) key_id: Option<String>,
    pub(crate) version: u64,
    pub(crate) last_modified_date: f64,
}
