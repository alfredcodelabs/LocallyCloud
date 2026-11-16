//! Validated IAM startup configuration; credentials retain their separate secret inputs.
use std::ffi::OsString;

use serde::Deserialize;

use crate::enforcement::EnforcementMode;
use crate::store::AccountRoot;

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

/// Explicit startup credential for a strict-mode IAM administrator.
/// Durable registration preserves an existing credential and its revocation state.
pub struct BootstrapCredentials {
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BootstrapError {
    #[error(transparent)]
    Configuration(#[from] crate::config::IamConfigError),
    #[error("strict IAM requires both bootstrap access key ID and secret access key")]
    MissingCredentials,
    #[error("invalid bootstrap access key ID or secret access key")]
    InvalidCredentials,
    #[error("root provisioning requires a valid LocallyCloud root credential pair and account")]
    InvalidRootCredentials,
    #[error("root access key conflicts with an existing IAM credential")]
    RootCredentialCollision,
    #[error("IAM credential inputs do not match the configured account or enforcement mode")]
    MismatchedStartupInputs,
}

impl BootstrapCredentials {
    /// Read only explicit LocallyCloud settings. Never include credential values in errors.
    pub fn from_env(strict: bool) -> Result<Option<Self>, BootstrapError> {
        Self::from_lookup(strict, &|name| std::env::var(name).ok())
    }

    pub(crate) fn from_lookup(
        strict: bool,
        get: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, BootstrapError> {
        let id = get("LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID");
        let secret = get("LOCALLYCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY");
        match (id, secret) {
            (None, None) if !strict => Ok(None),
            (Some(access_key_id), Some(secret_access_key)) => {
                let valid_id = access_key_id.len() == 20
                    && access_key_id.starts_with("AKIA")
                    && access_key_id
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
                let valid_secret = secret_access_key.len() == 40
                    && secret_access_key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
                if !valid_id || !valid_secret {
                    return Err(BootstrapError::InvalidCredentials);
                }
                Ok(Some(Self {
                    access_key_id,
                    secret_access_key,
                }))
            }
            _ => Err(BootstrapError::MissingCredentials),
        }
    }
}

pub(crate) fn root_from_lookup(
    account: &str,
    get: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<AccountRoot>, BootstrapError> {
    let credentials = BootstrapCredentials::from_lookup(false, &|name| {
        get(match name {
            "LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID" => "LOCALLYCLOUD_ROOT_ACCESS_KEY_ID",
            "LOCALLYCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY" => "LOCALLYCLOUD_ROOT_SECRET_ACCESS_KEY",
            _ => return None,
        })
    })
    .map_err(|_| BootstrapError::InvalidRootCredentials)?;
    let Some(credentials) = credentials else {
        return Ok(None);
    };
    if account.len() != 12 || !account.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BootstrapError::InvalidRootCredentials);
    }
    Ok(Some(AccountRoot {
        account: account.into(),
        access_key_id: credentials.access_key_id,
        secret_access_key: credentials.secret_access_key,
    }))
}
pub(crate) fn validate_root_collision(
    root: Option<&AccountRoot>,
    bootstrap: Option<&BootstrapCredentials>,
) -> Result<(), BootstrapError> {
    if root
        .zip(bootstrap)
        .is_some_and(|(root, bootstrap)| root.access_key_id == bootstrap.access_key_id)
    {
        return Err(BootstrapError::RootCredentialCollision);
    }
    Ok(())
}

/// Secret startup inputs. Deliberately neither Debug nor serializable.
/// Keep these outside the JSON configuration document.
pub struct IamCredentials {
    account: String,
    enforcement: EnforcementMode,
    pub(crate) bootstrap: Option<BootstrapCredentials>,
    pub(crate) root: Option<AccountRoot>,
}

impl IamCredentials {
    pub fn from_lookup(
        account: &str,
        config: IamConfig,
        get: impl Fn(&str) -> Option<OsString>,
    ) -> Result<Self, BootstrapError> {
        let read = |name, error| {
            get(name)
                .map(|value| value.into_string().map_err(|_| error))
                .transpose()
        };
        let bootstrap_id = read(
            "LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID",
            BootstrapError::InvalidCredentials,
        )?;
        let bootstrap_secret = read(
            "LOCALLYCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY",
            BootstrapError::InvalidCredentials,
        )?;
        let root_id = read(
            "LOCALLYCLOUD_ROOT_ACCESS_KEY_ID",
            BootstrapError::InvalidRootCredentials,
        )?;
        let root_secret = read(
            "LOCALLYCLOUD_ROOT_SECRET_ACCESS_KEY",
            BootstrapError::InvalidRootCredentials,
        )?;
        let bootstrap = BootstrapCredentials::from_lookup(
            config.enforcement == EnforcementMode::Strict,
            &|name| match name {
                "LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID" => bootstrap_id.clone(),
                "LOCALLYCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY" => bootstrap_secret.clone(),
                _ => None,
            },
        )?;
        let root = root_from_lookup(account, &|name| match name {
            "LOCALLYCLOUD_ROOT_ACCESS_KEY_ID" => root_id.clone(),
            "LOCALLYCLOUD_ROOT_SECRET_ACCESS_KEY" => root_secret.clone(),
            _ => None,
        })?;
        validate_root_collision(root.as_ref(), bootstrap.as_ref())?;
        Ok(Self {
            account: account.into(),
            enforcement: config.enforcement,
            bootstrap,
            root,
        })
    }

    /// The bootstrap signing identity for offline operations; never returns its secret.
    pub fn bootstrap_access_key_id(&self) -> Option<&str> {
        self.bootstrap
            .as_ref()
            .map(|credentials| credentials.access_key_id.as_str())
    }

    pub(crate) fn validate(&self, account: &str, config: IamConfig) -> Result<(), BootstrapError> {
        if self.account != account || self.enforcement != config.enforcement {
            return Err(BootstrapError::MismatchedStartupInputs);
        }
        Ok(())
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

    #[test]
    fn secret_inputs_resolve_once_and_bind_the_registration_context() {
        use std::cell::RefCell;
        let calls = RefCell::new(Vec::new());
        let strict = IamConfig {
            enforcement: EnforcementMode::Strict,
        };
        let inputs = IamCredentials::from_lookup("123456789012", strict, |name| {
            calls.borrow_mut().push(name.to_owned());
            match name {
                "LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID" => Some("AKIAABCDEFGHIJKLMNOP".into()),
                "LOCALLYCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY" => Some("a".repeat(40).into()),
                "LOCALLYCLOUD_ROOT_ACCESS_KEY_ID" => Some("AKIARRRRRRRRRRRRRRRR".into()),
                "LOCALLYCLOUD_ROOT_SECRET_ACCESS_KEY" => Some("r".repeat(40).into()),
                _ => panic!("unexpected input lookup"),
            }
        })
        .unwrap();
        assert_eq!(calls.borrow().len(), 4);
        assert_eq!(
            inputs.bootstrap_access_key_id(),
            Some("AKIAABCDEFGHIJKLMNOP")
        );
        assert_eq!(
            inputs.bootstrap.as_ref().unwrap().access_key_id,
            "AKIAABCDEFGHIJKLMNOP"
        );
        assert_eq!(inputs.root.as_ref().unwrap().account, "123456789012");
        assert!(inputs.validate("123456789012", strict).is_ok());
        assert!(matches!(
            inputs.validate("000000000000", strict),
            Err(BootstrapError::MismatchedStartupInputs)
        ));
        assert!(matches!(
            inputs.validate("123456789012", IamConfig::default()),
            Err(BootstrapError::MismatchedStartupInputs)
        ));
    }

    #[test]
    fn secret_inputs_reject_partial_non_utf8_and_colliding_credentials_without_disclosure() {
        let permissive = IamConfig::default();
        let empty = IamCredentials::from_lookup("123456789012", permissive, |_| None).unwrap();
        assert!(empty.bootstrap.is_none() && empty.root.is_none());
        let strict = IamConfig {
            enforcement: EnforcementMode::Strict,
        };
        assert!(matches!(
            IamCredentials::from_lookup("123456789012", strict, |_| None),
            Err(BootstrapError::MissingCredentials)
        ));
        for name in [
            "LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID",
            "LOCALLYCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY",
            "LOCALLYCLOUD_ROOT_ACCESS_KEY_ID",
            "LOCALLYCLOUD_ROOT_SECRET_ACCESS_KEY",
        ] {
            for value in [
                OsString::from_vec(vec![0xff]),
                OsString::from("private-input"),
            ] {
                let result = IamCredentials::from_lookup("123456789012", permissive, |key| {
                    (key == name).then(|| value.clone())
                });
                let error = match result {
                    Err(error) => error,
                    Ok(_) => panic!("invalid secret input was accepted"),
                };
                assert!(!error.to_string().contains("private-input"));
            }
        }
        let collision = IamCredentials::from_lookup("123456789012", strict, |name| {
            if name.ends_with("ACCESS_KEY_ID") {
                Some("AKIAABCDEFGHIJKLMNOP".into())
            } else {
                Some("a".repeat(40).into())
            }
        });
        assert!(matches!(
            collision,
            Err(BootstrapError::RootCredentialCollision)
        ));
    }
}
