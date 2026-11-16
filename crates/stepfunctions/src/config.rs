//! Local polling and cleanup budgets; ASL timeouts and AWS quotas stay in the domain.
use std::ffi::OsString;

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StepFunctionsConfig {
    pub execution_poll_interval_ms: u64,
    pub athena_poll_interval_ms: u64,
    pub athena_cancel_timeout_secs: u64,
}

impl Default for StepFunctionsConfig {
    fn default() -> Self {
        Self {
            execution_poll_interval_ms: 10,
            athena_poll_interval_ms: 50,
            athena_cancel_timeout_secs: 5,
        }
    }
}

impl StepFunctionsConfig {
    pub fn validate(&self) -> Result<(), String> {
        for (name, value, maximum) in [
            (
                "execution_poll_interval_ms",
                self.execution_poll_interval_ms,
                10_000,
            ),
            (
                "athena_poll_interval_ms",
                self.athena_poll_interval_ms,
                10_000,
            ),
            (
                "athena_cancel_timeout_secs",
                self.athena_cancel_timeout_secs,
                300,
            ),
        ] {
            if !(1..=maximum).contains(&value) {
                return Err(format!(
                    "stepfunctions.{name} must be between 1 and {maximum}"
                ));
            }
        }
        Ok(())
    }

    pub fn resolve_with(mut self, get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        for (name, target) in [
            (
                "LOCALLYCLOUD_STEPFUNCTIONS_EXECUTION_POLL_INTERVAL_MS",
                &mut self.execution_poll_interval_ms,
            ),
            (
                "LOCALLYCLOUD_STEPFUNCTIONS_ATHENA_POLL_INTERVAL_MS",
                &mut self.athena_poll_interval_ms,
            ),
            (
                "LOCALLYCLOUD_STEPFUNCTIONS_ATHENA_CANCEL_TIMEOUT_SECS",
                &mut self.athena_cancel_timeout_secs,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn resolves_partial_file_and_environment_without_changing_aws_limits() {
        let file: StepFunctionsConfig =
            serde_json::from_str(r#"{"execution_poll_interval_ms":20}"#).unwrap();
        assert_eq!(file.athena_poll_interval_ms, 50);
        let resolved = file
            .resolve_with(&|name| {
                (name == "LOCALLYCLOUD_STEPFUNCTIONS_ATHENA_POLL_INTERVAL_MS").then(|| "75".into())
            })
            .unwrap();
        assert_eq!(
            (
                resolved.execution_poll_interval_ms,
                resolved.athena_poll_interval_ms,
                resolved.athena_cancel_timeout_secs
            ),
            (20, 75, 5)
        );
        assert_eq!(crate::store::MAX_HISTORY_EVENTS, 25_000);
        for value in [
            OsString::from("0"),
            OsString::from("10001"),
            OsString::from(""),
            OsString::from("1.5"),
            OsString::from_vec(vec![0xff]),
        ] {
            assert!(file
                .resolve_with(&|name| (name
                    == "LOCALLYCLOUD_STEPFUNCTIONS_EXECUTION_POLL_INTERVAL_MS")
                    .then(|| value.clone()))
                .is_err());
        }
        for document in [r#"{"execution_poll_interval_ms":null}"#, r#"{"unknown":1}"#] {
            assert!(serde_json::from_str::<StepFunctionsConfig>(document).is_err());
        }
    }
}
