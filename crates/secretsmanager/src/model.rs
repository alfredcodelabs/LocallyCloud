use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
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

    pub(crate) fn secret_arn(&self, name: &str, suffix: &str) -> String {
        format!(
            "arn:aws:secretsmanager:{}:{}:secret:{name}-{suffix}",
            self.region, self.account_id
        )
    }

    pub(crate) fn arn_prefix(&self) -> String {
        format!(
            "arn:aws:secretsmanager:{}:{}:secret:",
            self.region, self.account_id
        )
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct SensitiveString(String);

impl SensitiveString {
    pub(crate) fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0).into_bytes()
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct SensitiveBinary(Vec<u8>);

impl SensitiveBinary {
    pub(crate) fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl<'de> Deserialize<'de> for SensitiveBinary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        STANDARD.decode(encoded).map(Self).map_err(D::Error::custom)
    }
}

impl Drop for SensitiveBinary {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SensitiveDigest([u8; 32]);

impl SensitiveDigest {
    pub(crate) fn for_value(kind: ValueKind, value: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update([kind.marker()]);
        hasher.update(value);
        Self(hasher.finalize().into())
    }
}

impl PartialEq for SensitiveDigest {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Drop for SensitiveDigest {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum ValueKind {
    String,
    Binary,
}

impl ValueKind {
    fn marker(self) -> u8 {
        match self {
            Self::String => 0,
            Self::Binary => 1,
        }
    }
}

pub(crate) struct PlainValue {
    pub(crate) kind: ValueKind,
    pub(crate) bytes: SensitiveBytes,
    pub(crate) digest: SensitiveDigest,
}

impl PlainValue {
    pub(crate) fn new(kind: ValueKind, bytes: Vec<u8>) -> Self {
        let digest = SensitiveDigest::for_value(kind, &bytes);
        Self {
            kind,
            bytes: SensitiveBytes::new(bytes),
            digest,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum VersionOperation {
    Create,
    Put,
    Update,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SecretVersion {
    pub(crate) id: String,
    pub(crate) ciphertext: SensitiveBytes,
    pub(crate) kind: ValueKind,
    pub(crate) digest: SensitiveDigest,
    pub(crate) operation: VersionOperation,
    pub(crate) requested_stages: BTreeSet<String>,
    pub(crate) stages: BTreeSet<String>,
    pub(crate) created_date: f64,
    pub(crate) key_arn: String,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum RotationStep {
    Create,
    Set,
    Test,
    Finish,
    Complete,
}

impl RotationStep {
    pub(crate) fn event_name(self) -> Option<&'static str> {
        match self {
            Self::Create => Some("createSecret"),
            Self::Set => Some("setSecret"),
            Self::Test => Some("testSecret"),
            Self::Finish => Some("finishSecret"),
            Self::Complete => None,
        }
    }

    pub(crate) fn next(self) -> Self {
        match self {
            Self::Create => Self::Set,
            Self::Set => Self::Test,
            Self::Test => Self::Finish,
            Self::Finish | Self::Complete => Self::Complete,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RotationOccurrence {
    pub(crate) version_id: String,
    pub(crate) step: RotationStep,
    pub(crate) in_flight: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RotationState {
    pub(crate) enabled: bool,
    pub(crate) lambda_arn: String,
    pub(crate) occurrence: Option<RotationOccurrence>,
    pub(crate) last_rotated_date: Option<f64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SecretRecord {
    pub(crate) arn: String,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) kms_key_id: Option<String>,
    pub(crate) created_date: f64,
    pub(crate) last_changed_date: f64,
    pub(crate) deleted_date: Option<f64>,
    pub(crate) tags: BTreeMap<String, String>,
    pub(crate) resource_policy: Option<String>,
    pub(crate) rotation: Option<RotationState>,
    pub(crate) versions: BTreeMap<String, SecretVersion>,
    pub(crate) stage_index: BTreeMap<String, String>,
}

pub(crate) fn serialize_binary<S>(bytes: &SensitiveBytes, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&STANDARD.encode(bytes.as_slice()))
}

pub(crate) fn serialize_string<S>(bytes: &SensitiveBytes, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let value = std::str::from_utf8(bytes.as_slice()).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(value)
}
