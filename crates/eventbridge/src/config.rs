//! Local delivery and HTTP budgets; AWS target retry policies remain domain data.
use std::ffi::OsString;
use std::time::Duration;

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EventBridgeConfig {
    pub retry_time_scale: f64,
    pub pending_retry_poll_interval_ms: u64,
    pub http_connect_timeout_secs: u64,
    pub http_request_timeout_secs: u64,
    pub http_response_body_limit_bytes: usize,
}

impl Default for EventBridgeConfig {
    fn default() -> Self {
        Self {
            retry_time_scale: 1.0,
            pending_retry_poll_interval_ms: 25,
            http_connect_timeout_secs: 5,
            http_request_timeout_secs: 30,
            http_response_body_limit_bytes: 10 * 1024 * 1024,
        }
    }
}

impl EventBridgeConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.retry_time_scale.is_finite() || !(0.000001..=1.0).contains(&self.retry_time_scale)
        {
            return Err(
                "eventbridge.retry_time_scale must be finite and between 0.000001 and 1".into(),
            );
        }
        if !(1..=10 * 1024 * 1024).contains(&self.http_response_body_limit_bytes) {
            return Err(
                "eventbridge.http_response_body_limit_bytes must be between 1 and 10485760".into(),
            );
        }
        for (name, value, maximum) in [
            (
                "pending_retry_poll_interval_ms",
                self.pending_retry_poll_interval_ms,
                10_000,
            ),
            (
                "http_connect_timeout_secs",
                self.http_connect_timeout_secs,
                300,
            ),
            (
                "http_request_timeout_secs",
                self.http_request_timeout_secs,
                300,
            ),
        ] {
            if !(1..=maximum).contains(&value) {
                return Err(format!(
                    "eventbridge.{name} must be between 1 and {maximum}"
                ));
            }
        }
        Ok(())
    }

    pub fn resolve_with(mut self, get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        if let Some(value) = get("LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE") {
            self.retry_time_scale = value.to_str().and_then(|value| value.parse().ok()).ok_or(
                "LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE must be a finite number from 0.000001 to 1",
            )?;
        }
        for (name, target) in [
            (
                "LOCALLYCLOUD_EVENTBRIDGE_PENDING_RETRY_POLL_INTERVAL_MS",
                &mut self.pending_retry_poll_interval_ms,
            ),
            (
                "LOCALLYCLOUD_EVENTBRIDGE_HTTP_CONNECT_TIMEOUT_SECS",
                &mut self.http_connect_timeout_secs,
            ),
            (
                "LOCALLYCLOUD_EVENTBRIDGE_HTTP_REQUEST_TIMEOUT_SECS",
                &mut self.http_request_timeout_secs,
            ),
        ] {
            if let Some(value) = get(name) {
                *target = value
                    .to_str()
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| format!("{name} must be an integer"))?;
            }
        }
        if let Some(value) = get("LOCALLYCLOUD_EVENTBRIDGE_HTTP_RESPONSE_BODY_LIMIT_BYTES") {
            self.http_response_body_limit_bytes =
                value.to_str().and_then(|value| value.parse().ok()).ok_or(
                    "LOCALLYCLOUD_EVENTBRIDGE_HTTP_RESPONSE_BODY_LIMIT_BYTES must be an integer",
                )?;
        }
        self.validate()?;
        Ok(self)
    }

    pub fn retry_second(&self) -> Duration {
        Duration::from_secs_f64(self.retry_time_scale)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn retry_scale_and_operational_budgets_resolve_without_live_environment() {
        let defaults = EventBridgeConfig::default();
        assert_eq!(defaults.retry_second(), Duration::from_secs(1));
        let file: EventBridgeConfig =
            serde_json::from_str(r#"{"retry_time_scale":0.5,"http_request_timeout_secs":20}"#)
                .unwrap();
        let resolved = file
            .resolve_with(&|name| {
                (name == "LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE").then(|| "0.001".into())
            })
            .unwrap();
        assert_eq!(resolved.retry_second(), Duration::from_millis(1));
        assert_eq!(resolved.http_request_timeout_secs, 20);
        assert_eq!(resolved.pending_retry_poll_interval_ms, 25);
        for value in ["", "0", "-1", "NaN", "inf", "1.1", "0.0000001", "oops"] {
            assert!(defaults
                .resolve_with(
                    &|name| (name == "LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE").then(|| value.into())
                )
                .is_err());
        }
        assert!(defaults
            .resolve_with(&|name| (name == "LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE")
                .then(|| OsString::from_vec(vec![0xff])))
            .is_err());
        assert_eq!(defaults.http_response_body_limit_bytes, 10 * 1024 * 1024);
        assert_eq!(
            defaults
                .resolve_with(&|name| (name
                    == "LOCALLYCLOUD_EVENTBRIDGE_HTTP_RESPONSE_BODY_LIMIT_BYTES")
                    .then(|| "17".into()))
                .unwrap()
                .http_response_body_limit_bytes,
            17
        );
        for limit in [0, 10 * 1024 * 1024 + 1] {
            assert!(EventBridgeConfig {
                http_response_body_limit_bytes: limit,
                ..defaults
            }
            .validate()
            .is_err());
        }
        for document in [
            r#"{"retry_time_scale":null}"#,
            r#"{"http_request_timeout_secs":null}"#,
            r#"{"http_response_body_limit_bytes":null}"#,
            r#"{"unknown":1}"#,
        ] {
            assert!(serde_json::from_str::<EventBridgeConfig>(document).is_err());
        }
        for (name, value) in [
            (
                "LOCALLYCLOUD_EVENTBRIDGE_PENDING_RETRY_POLL_INTERVAL_MS",
                "0",
            ),
            (
                "LOCALLYCLOUD_EVENTBRIDGE_PENDING_RETRY_POLL_INTERVAL_MS",
                "10001",
            ),
            ("LOCALLYCLOUD_EVENTBRIDGE_HTTP_CONNECT_TIMEOUT_SECS", "301"),
            ("LOCALLYCLOUD_EVENTBRIDGE_HTTP_REQUEST_TIMEOUT_SECS", "0"),
        ] {
            assert!(defaults
                .resolve_with(&|key| (key == name).then(|| value.into()))
                .is_err());
        }
    }
}
