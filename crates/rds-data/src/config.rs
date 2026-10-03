use std::path::PathBuf;
use std::time::Duration;

use crate::StartupError;

/// Identity admission policy. Only local namespacing is currently supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMode {
    LocalIdentity,
    SecretsValidation,
}

/// Finite local safety limits. These are implementation limits, not AWS quotas.
#[derive(Debug, Clone)]
pub struct RdsDataLimits {
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub formatted_records_bytes: usize,
    pub max_parameters: usize,
    pub max_batch_sets: usize,
    pub max_rows: usize,
    pub max_transactions: usize,
    pub max_field_bytes: usize,
    pub max_blocking_operations: usize,
}

impl Default for RdsDataLimits {
    fn default() -> Self {
        Self {
            request_bytes: 4 * 1024 * 1024,
            response_bytes: 1024 * 1024,
            formatted_records_bytes: 10 * 1024 * 1024,
            max_parameters: 1_000,
            max_batch_sets: 1_000,
            max_rows: 100_000,
            max_transactions: 16,
            max_field_bytes: 1024 * 1024,
            max_blocking_operations: 16,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RdsDataConfig {
    pub state_root: PathBuf,
    pub identity_mode: IdentityMode,
    pub limits: RdsDataLimits,
    pub busy_timeout: Duration,
    pub transaction_idle_timeout: Duration,
    pub transaction_absolute_timeout: Duration,
}

impl Default for RdsDataConfig {
    fn default() -> Self {
        Self {
            state_root: locallycloud_state::StateDb::data_dir()
                .map(|root| root.join("rds-data"))
                .unwrap_or_default(),
            identity_mode: IdentityMode::LocalIdentity,
            limits: RdsDataLimits::default(),
            busy_timeout: Duration::from_secs(5),
            transaction_idle_timeout: Duration::from_secs(3 * 60),
            transaction_absolute_timeout: Duration::from_secs(24 * 60 * 60),
        }
    }
}

impl RdsDataConfig {
    pub(crate) fn validate(&self) -> Result<(), StartupError> {
        if !self.state_root.is_absolute() {
            return Err(StartupError::InvalidConfig(
                "state_root must be absolute".into(),
            ));
        }
        if self.identity_mode != IdentityMode::LocalIdentity {
            return Err(StartupError::InvalidConfig(
                "SecretsValidation mode is unavailable because Core has no approved capability"
                    .into(),
            ));
        }
        let limits = &self.limits;
        if limits.request_bytes != 4 * 1024 * 1024
            || limits.response_bytes != 1024 * 1024
            || limits.formatted_records_bytes != 10 * 1024 * 1024
        {
            return Err(StartupError::InvalidConfig(
                "AWS-facing request and response limits are fixed".into(),
            ));
        }
        if [
            limits.max_parameters,
            limits.max_batch_sets,
            limits.max_rows,
            limits.max_transactions,
            limits.max_field_bytes,
            limits.max_blocking_operations,
        ]
        .contains(&0)
            || limits.max_parameters > 10_000
            || limits.max_batch_sets > 10_000
            || limits.max_rows > 1_000_000
            || limits.max_transactions > limits.max_blocking_operations
            || limits.max_field_bytes > 10 * 1024 * 1024
            || limits.max_blocking_operations > 256
            || self.busy_timeout.is_zero()
            || self.busy_timeout > Duration::from_secs(60)
            || self.transaction_idle_timeout.is_zero()
            || self.transaction_absolute_timeout.is_zero()
            || self.transaction_idle_timeout >= self.transaction_absolute_timeout
        {
            return Err(StartupError::InvalidConfig(
                "all local safety limits must be finite and non-zero".into(),
            ));
        }
        Ok(())
    }
}
