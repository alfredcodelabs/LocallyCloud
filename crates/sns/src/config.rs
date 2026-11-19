//! Local operational settings. AWS quotas and defensive payload limits remain fixed.
use serde::Deserialize;
use std::ffi::OsString;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SnsConfig {
    pub http_local_origins: Vec<String>,
    pub http_client_cache_capacity: usize,
    pub http_timeout_secs: u64,
    pub outbox_retry_initial_secs: u64,
    pub outbox_retry_max_secs: u64,
}

impl Default for SnsConfig {
    fn default() -> Self {
        Self {
            http_local_origins: Vec::new(),
            http_client_cache_capacity: 16,
            http_timeout_secs: 5,
            outbox_retry_initial_secs: 1,
            outbox_retry_max_secs: 30,
        }
    }
}

impl SnsConfig {
    pub fn validate(&self) -> Result<(), String> {
        locallycloud_core::egress::validate_local_origins(&self.http_local_origins)
            .map_err(|error| format!("sns.http_local_origins: {error}"))?;
        if !(1..=256).contains(&self.http_client_cache_capacity) {
            return Err("sns.http_client_cache_capacity must be between 1 and 256".into());
        }

        for (name, value, maximum) in [
            ("http_timeout_secs", self.http_timeout_secs, 300),
            (
                "outbox_retry_initial_secs",
                self.outbox_retry_initial_secs,
                300,
            ),
            ("outbox_retry_max_secs", self.outbox_retry_max_secs, 3600),
        ] {
            if !(1..=maximum).contains(&value) {
                return Err(format!("sns.{name} must be between 1 and {maximum}"));
            }
        }
        if self.outbox_retry_initial_secs > self.outbox_retry_max_secs {
            return Err(
                "sns.outbox_retry_initial_secs must not exceed outbox_retry_max_secs".into(),
            );
        }
        Ok(())
    }
    pub fn resolve_with(mut self, get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        for (name, target) in [
            (
                "LOCALLYCLOUD_SNS_HTTP_TIMEOUT_SECS",
                &mut self.http_timeout_secs,
            ),
            (
                "LOCALLYCLOUD_SNS_OUTBOX_RETRY_INITIAL_SECS",
                &mut self.outbox_retry_initial_secs,
            ),
            (
                "LOCALLYCLOUD_SNS_OUTBOX_RETRY_MAX_SECS",
                &mut self.outbox_retry_max_secs,
            ),
        ] {
            if let Some(value) = get(name) {
                *target = value
                    .to_str()
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| format!("{name} must be an integer"))?;
            }
        }
        if let Some(value) = get("LOCALLYCLOUD_SNS_HTTP_LOCAL_ORIGINS") {
            self.http_local_origins = value
                .to_str()
                .and_then(|value| serde_json::from_str(value).ok())
                .ok_or("LOCALLYCLOUD_SNS_HTTP_LOCAL_ORIGINS must be a JSON array of origins")?;
        }
        if let Some(value) = get("LOCALLYCLOUD_SNS_HTTP_CLIENT_CACHE_CAPACITY") {
            self.http_client_cache_capacity =
                value
                    .to_str()
                    .and_then(|value| value.parse().ok())
                    .ok_or("LOCALLYCLOUD_SNS_HTTP_CLIENT_CACHE_CAPACITY must be an integer")?;
        }
        self.validate()?;
        Ok(self)
    }
}
