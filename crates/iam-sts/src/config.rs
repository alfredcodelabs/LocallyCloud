//! Validated IAM startup configuration; credentials retain their separate secret inputs.
use std::ffi::OsString;

use serde::Deserialize;

use crate::enforcement::EnforcementMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IamConfig {
    pub enforcement: EnforcementMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("IAM enforcement must be either strict or permissive (valid UTF-8)")]
pub struct IamConfigError;

impl IamConfig {
    pub fn from_env() -> Result<Self, IamConfigError> {
        Self::from_lookup(|key| std::env::var_os(key))
    }

    /// Native settings take precedence over compatibility aliases, even when invalid.
    pub fn from_lookup(get: impl Fn(&str) -> Option<OsString>) -> Result<Self, IamConfigError> {
        for key in ["LOCALLYCLOUD_IAM_ENFORCEMENT", "LOCALSTACK_IAM_ENFORCEMENT"] {
            if let Some(value) = get(key) {
                return Ok(Self {
                    enforcement: value.to_str().ok_or(IamConfigError)?.parse()?,
                });
            }
        }
        Ok(Self::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn absence_defaults_but_unknown_empty_and_non_utf8_fail() {
        assert_eq!(
            IamConfig::from_lookup(|_| None).unwrap(),
            IamConfig::default()
        );
        for value in [
            OsString::from("strcit"),
            OsString::new(),
            OsString::from("STRICT"),
            OsString::from_vec(vec![0xff]),
        ] {
            assert!(IamConfig::from_lookup(|_| Some(value.clone())).is_err());
        }
        assert_eq!(
            serde_json::from_str::<IamConfig>("{}").unwrap(),
            IamConfig::default()
        );
        assert!(serde_json::from_str::<IamConfig>(r#"{"enforcement":"strcit"}"#).is_err());
        assert!(serde_json::from_str::<IamConfig>(r#"{"enforcement":"strict","typo":1}"#).is_err());
        assert_eq!(
            serde_json::from_str::<IamConfig>(r#"{"enforcement":"strict"}"#)
                .unwrap()
                .enforcement,
            EnforcementMode::Strict
        );
    }

    #[test]
    fn native_setting_precedes_alias_without_invalid_fallback() {
        let get = |key: &str| {
            Some(OsString::from(if key.starts_with("LOCALLYCLOUD_") {
                "strict"
            } else {
                "permissive"
            }))
        };
        assert_eq!(
            IamConfig::from_lookup(get).unwrap().enforcement,
            EnforcementMode::Strict
        );
        assert_eq!(
            IamConfig::from_lookup(
                |key| (key.starts_with("LOCALSTACK_")).then(|| OsString::from("strict"))
            )
            .unwrap()
            .enforcement,
            EnforcementMode::Strict
        );
        assert!(IamConfig::from_lookup(|key| Some(OsString::from(
            if key.starts_with("LOCALLYCLOUD_") {
                ""
            } else {
                "strict"
            }
        )))
        .is_err());
    }
}
