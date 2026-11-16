//! Local notification buffers and retry polling, not AWS resource quotas.
use std::ffi::OsString;

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct S3Config {
    pub notification_queue_capacity: usize,
    pub notification_retry_interval_ms: u64,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            notification_queue_capacity: 1024,
            notification_retry_interval_ms: 1000,
        }
    }
}

impl S3Config {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=16_384).contains(&self.notification_queue_capacity) {
            return Err("s3.notification_queue_capacity must be between 1 and 16384".into());
        }
        if !(100..=60_000).contains(&self.notification_retry_interval_ms) {
            return Err("s3.notification_retry_interval_ms must be between 100 and 60000".into());
        }
        Ok(())
    }

    pub fn resolve_with(mut self, get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        if let Some(value) = get("LOCALLYCLOUD_S3_NOTIFICATION_QUEUE_CAPACITY") {
            self.notification_queue_capacity = value
                .to_str()
                .and_then(|value| value.parse().ok())
                .ok_or("LOCALLYCLOUD_S3_NOTIFICATION_QUEUE_CAPACITY must be a valid integer")?;
        }
        if let Some(value) = get("LOCALLYCLOUD_S3_NOTIFICATION_RETRY_INTERVAL_MS") {
            self.notification_retry_interval_ms = value
                .to_str()
                .and_then(|value| value.parse().ok())
                .ok_or("LOCALLYCLOUD_S3_NOTIFICATION_RETRY_INTERVAL_MS must be a valid integer")?;
        }
        self.validate()?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn partial_file_configuration_inherits_defaults_and_environment_overrides_independently() {
        let file: S3Config = serde_json::from_str(r#"{"notification_queue_capacity":2}"#).unwrap();
        assert_eq!(file.notification_retry_interval_ms, 1000);
        let resolved = file
            .resolve_with(&|key| {
                (key == "LOCALLYCLOUD_S3_NOTIFICATION_RETRY_INTERVAL_MS").then(|| "2000".into())
            })
            .unwrap();
        assert_eq!(resolved.notification_queue_capacity, 2);
        assert_eq!(resolved.notification_retry_interval_ms, 2000);
        assert_eq!(
            file.resolve_with(&|_| None)
                .unwrap()
                .notification_queue_capacity,
            2
        );
    }

    #[test]
    fn invalid_document_ranges_and_environment_values_fail_without_disclosing_inputs() {
        for json in [
            r#"{"notification_queue_capacity":null}"#,
            r#"{"notification_retry_interval_ms":null}"#,
            r#"{"typo":1}"#,
        ] {
            assert!(serde_json::from_str::<S3Config>(json).is_err());
        }
        for capacity in [0, 16_385, usize::MAX] {
            assert!(S3Config {
                notification_queue_capacity: capacity,
                ..Default::default()
            }
            .validate()
            .is_err());
        }
        for interval in [0, 99, 60_001, u64::MAX] {
            assert!(S3Config {
                notification_retry_interval_ms: interval,
                ..Default::default()
            }
            .validate()
            .is_err());
        }
        for key in [
            "LOCALLYCLOUD_S3_NOTIFICATION_QUEUE_CAPACITY",
            "LOCALLYCLOUD_S3_NOTIFICATION_RETRY_INTERVAL_MS",
        ] {
            for value in [
                OsString::new(),
                OsString::from("private-invalid-value"),
                OsString::from_vec(vec![0xff]),
            ] {
                let error = S3Config::default()
                    .resolve_with(&|name| (name == key).then(|| value.clone()))
                    .unwrap_err();
                assert!(!error.contains("private-invalid-value"));
            }
        }
    }
}
