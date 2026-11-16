//! Operational DynamoDB settings resolved once before service registration.
use std::ffi::OsString;
use std::time::Duration;

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DynamoDbEngineChoice {
    #[default]
    Native,
    ExtendDb,
}

impl DynamoDbEngineChoice {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::ExtendDb => "extenddb",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DynamoDbConfig {
    pub engine: DynamoDbEngineChoice,
    pub simulate_write_limits: bool,
    pub kms_timeout_secs: u64,
}

impl Default for DynamoDbConfig {
    fn default() -> Self {
        Self {
            engine: DynamoDbEngineChoice::Native,
            simulate_write_limits: false,
            kms_timeout_secs: 3,
        }
    }
}

impl DynamoDbConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=300).contains(&self.kms_timeout_secs) {
            return Err("dynamodb.kms_timeout_secs must be between 1 and 300".into());
        }
        if self.simulate_write_limits && self.engine != DynamoDbEngineChoice::Native {
            return Err("dynamodb.simulate_write_limits requires the native engine".into());
        }
        Ok(())
    }

    pub fn resolve_with(mut self, get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        if let Some(value) = get("LOCALLYCLOUD_DYNAMODB_ENGINE") {
            self.engine = match value.to_str() {
                Some("native") => DynamoDbEngineChoice::Native,
                Some("extenddb") => DynamoDbEngineChoice::ExtendDb,
                _ => return Err("LOCALLYCLOUD_DYNAMODB_ENGINE must be native or extenddb".into()),
            };
        }
        if let Some(value) = get("LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS") {
            self.simulate_write_limits =
                match value.to_str() {
                    Some("1" | "true") => true,
                    Some("0" | "false") => false,
                    _ => return Err(
                        "LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS must be 1, 0, true or false"
                            .into(),
                    ),
                };
        }
        if let Some(value) = get("LOCALLYCLOUD_DYNAMODB_KMS_TIMEOUT_SECS") {
            self.kms_timeout_secs = value
                .to_str()
                .and_then(|value| value.parse().ok())
                .ok_or("LOCALLYCLOUD_DYNAMODB_KMS_TIMEOUT_SECS must be an integer")?;
        }
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn kms_timeout(&self) -> Duration {
        Duration::from_secs(self.kms_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn defaults_file_and_environment_are_resolved_explicitly() {
        let defaults: DynamoDbConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaults.engine, DynamoDbEngineChoice::Native);
        assert!(!defaults.simulate_write_limits);
        assert_eq!(defaults.kms_timeout_secs, 3);
        let configured: DynamoDbConfig = serde_json::from_str(
            r#"{"engine":"native","simulate_write_limits":true,"kms_timeout_secs":7}"#,
        )
        .unwrap();
        let resolved = configured
            .resolve_with(&|name| match name {
                "LOCALLYCLOUD_DYNAMODB_ENGINE" => Some("extenddb".into()),
                "LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS" => Some("0".into()),
                "LOCALLYCLOUD_DYNAMODB_KMS_TIMEOUT_SECS" => Some("9".into()),
                _ => None,
            })
            .unwrap();
        assert_eq!(resolved.engine.as_str(), "extenddb");
        assert!(!resolved.simulate_write_limits);
        assert_eq!(resolved.kms_timeout_secs, 9);
        for value in ["1", "true"] {
            assert!(
                defaults
                    .resolve_with(
                        &|name| (name == "LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS")
                            .then(|| value.into())
                    )
                    .unwrap()
                    .simulate_write_limits
            );
        }
    }

    #[test]
    fn null_unknown_wrong_types_and_invalid_environment_fail_without_echo() {
        for document in [
            r#"{"engine":null}"#,
            r#"{"engine":"other"}"#,
            r#"{"simulate_write_limits":null}"#,
            r#"{"simulate_write_limits":"true"}"#,
            r#"{"kms_timeout_secs":null}"#,
            r#"{"typo":true}"#,
        ] {
            assert!(serde_json::from_str::<DynamoDbConfig>(document).is_err());
        }
        for (name, value) in [
            ("LOCALLYCLOUD_DYNAMODB_ENGINE", ""),
            ("LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS", "yes"),
            ("LOCALLYCLOUD_DYNAMODB_KMS_TIMEOUT_SECS", "0"),
            ("LOCALLYCLOUD_DYNAMODB_KMS_TIMEOUT_SECS", "301"),
        ] {
            assert!(DynamoDbConfig::default()
                .resolve_with(&|key| (name == key).then(|| value.into()))
                .is_err());
        }
        for name in [
            "LOCALLYCLOUD_DYNAMODB_ENGINE",
            "LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS",
            "LOCALLYCLOUD_DYNAMODB_KMS_TIMEOUT_SECS",
        ] {
            assert!(DynamoDbConfig::default()
                .resolve_with(&|key| (name == key).then(|| OsString::from_vec(vec![0xff])))
                .is_err());
        }
        assert!(DynamoDbConfig {
            engine: DynamoDbEngineChoice::ExtendDb,
            simulate_write_limits: true,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
}
