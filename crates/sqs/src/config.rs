//! SQS endpoint presentation is resolved once and injected as QueueUrlStyle.
use std::ffi::OsString;

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SqsEndpointStrategy {
    #[default]
    Path,
    Aws,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SqsConfig {
    pub endpoint_strategy: SqsEndpointStrategy,
}

impl SqsConfig {
    pub fn resolve_with(mut self, get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        if let Some(value) = get("LOCALLYCLOUD_SQS_ENDPOINT_STRATEGY") {
            self.endpoint_strategy = match value.to_str().map(str::to_ascii_lowercase).as_deref() {
                Some("path") => SqsEndpointStrategy::Path,
                Some("aws") => SqsEndpointStrategy::Aws,
                _ => return Err("LOCALLYCLOUD_SQS_ENDPOINT_STRATEGY must be path or aws".into()),
            };
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn file_default_and_environment_precedence_preserve_native_strategy() {
        let defaults: SqsConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaults.endpoint_strategy, SqsEndpointStrategy::Path);
        let file: SqsConfig = serde_json::from_str(r#"{"endpoint_strategy":"aws"}"#).unwrap();
        assert_eq!(
            file.resolve_with(&|_| None).unwrap().endpoint_strategy,
            SqsEndpointStrategy::Aws
        );
        assert_eq!(
            file.resolve_with(&|_| Some("PATH".into()))
                .unwrap()
                .endpoint_strategy,
            SqsEndpointStrategy::Path
        );
        assert_eq!(
            defaults
                .resolve_with(&|_| Some("AWS".into()))
                .unwrap()
                .endpoint_strategy,
            SqsEndpointStrategy::Aws
        );
    }

    #[test]
    fn invalid_values_do_not_fall_back_or_echo_inputs() {
        for json in [
            r#"{"endpoint_strategy":null}"#,
            r#"{"endpoint_strategy":"other"}"#,
            r#"{"typo":true}"#,
        ] {
            assert!(serde_json::from_str::<SqsConfig>(json).is_err());
        }
        for value in [
            OsString::new(),
            OsString::from("private-value"),
            OsString::from_vec(vec![0xff]),
        ] {
            let error = SqsConfig::default()
                .resolve_with(&|_| Some(value.clone()))
                .unwrap_err();
            assert!(!error.contains("private-value"));
        }
    }
}
