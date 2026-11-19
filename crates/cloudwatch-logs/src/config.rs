//! Local operational settings. AWS quotas and defensive payload limits remain fixed.
use serde::Deserialize;
use std::ffi::OsString;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogsConfig {
    pub delivery_retry_interval_ms: u64,
    pub retention_reclaim_delay_ms: u64,
}

impl Default for LogsConfig {
    fn default() -> Self {
        Self {
            delivery_retry_interval_ms: 5000,
            retention_reclaim_delay_ms: 100,
        }
    }
}

impl LogsConfig {
    pub fn validate(&self) -> Result<(), String> {
        for (name, value, maximum) in [
            (
                "delivery_retry_interval_ms",
                self.delivery_retry_interval_ms,
                60000,
            ),
            (
                "retention_reclaim_delay_ms",
                self.retention_reclaim_delay_ms,
                60000,
            ),
        ] {
            if !(1..=maximum).contains(&value) {
                return Err(format!("logs.{name} must be between 1 and {maximum}"));
            }
        }
        Ok(())
    }
    pub fn resolve_with(mut self, get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        for (name, target) in [
            (
                "LOCALLYCLOUD_LOGS_DELIVERY_RETRY_INTERVAL_MS",
                &mut self.delivery_retry_interval_ms,
            ),
            (
                "LOCALLYCLOUD_LOGS_RETENTION_RECLAIM_DELAY_MS",
                &mut self.retention_reclaim_delay_ms,
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
