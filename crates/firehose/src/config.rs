//! Local operational settings. AWS quotas and defensive payload limits remain fixed.
use serde::Deserialize;
use std::ffi::OsString;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirehoseConfig {
    pub source_poll_interval_ms: u64,
    pub s3_dispatch_timeout_secs: u64,
    pub max_retry_delay_secs: u64,
}

impl Default for FirehoseConfig {
    fn default() -> Self {
        Self {
            source_poll_interval_ms: 1000,
            s3_dispatch_timeout_secs: 10,
            max_retry_delay_secs: 30,
        }
    }
}

impl FirehoseConfig {
    pub fn validate(&self) -> Result<(), String> {
        for (name, value, maximum) in [
            (
                "source_poll_interval_ms",
                self.source_poll_interval_ms,
                60000,
            ),
            (
                "s3_dispatch_timeout_secs",
                self.s3_dispatch_timeout_secs,
                300,
            ),
            ("max_retry_delay_secs", self.max_retry_delay_secs, 3600),
        ] {
            if !(1..=maximum).contains(&value) {
                return Err(format!("firehose.{name} must be between 1 and {maximum}"));
            }
        }
        Ok(())
    }
    pub fn resolve_with(mut self, get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        for (name, target) in [
            (
                "LOCALLYCLOUD_FIREHOSE_SOURCE_POLL_INTERVAL_MS",
                &mut self.source_poll_interval_ms,
            ),
            (
                "LOCALLYCLOUD_FIREHOSE_S3_DISPATCH_TIMEOUT_SECS",
                &mut self.s3_dispatch_timeout_secs,
            ),
            (
                "LOCALLYCLOUD_FIREHOSE_MAX_RETRY_DELAY_SECS",
                &mut self.max_retry_delay_secs,
            ),
        ] {
            if let Some(value) = get(name) {
                *target = value
                    .to_str()
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| format!("{name} must be an integer"))?;
            }
        }
        self.validate()?;
        Ok(self)
    }
}
