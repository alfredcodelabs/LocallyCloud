//! Instance-local record budget and optional AWS write-rate simulation.
use serde::Deserialize;
use std::ffi::OsString;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KinesisConfig {
    pub max_buffered_bytes: usize,
    pub simulate_write_limits: bool,
}
impl Default for KinesisConfig {
    fn default() -> Self {
        Self {
            max_buffered_bytes: 64 * 1024 * 1024,
            simulate_write_limits: false,
        }
    }
}
impl KinesisConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=1024 * 1024 * 1024).contains(&self.max_buffered_bytes) {
            return Err("kinesis.max_buffered_bytes must be between 1 and 1073741824".into());
        }
        Ok(())
    }
    pub fn resolve_with(mut self, get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        if let Some(value) = get("LOCALLYCLOUD_KINESIS_MAX_BUFFERED_BYTES") {
            self.max_buffered_bytes = value
                .to_str()
                .and_then(|value| value.parse().ok())
                .ok_or("LOCALLYCLOUD_KINESIS_MAX_BUFFERED_BYTES must be an integer")?;
        }
        if let Some(value) = get("LOCALLYCLOUD_KINESIS_SIMULATE_WRITE_LIMITS") {
            self.simulate_write_limits =
                match value.to_str().map(str::to_ascii_lowercase).as_deref() {
                    Some("1" | "true") => true,
                    Some("0" | "false") => false,
                    _ => return Err(
                        "LOCALLYCLOUD_KINESIS_SIMULATE_WRITE_LIMITS must be true, false, 1 or 0"
                            .into(),
                    ),
                };
        }
        self.validate()?;
        Ok(self)
    }
}
