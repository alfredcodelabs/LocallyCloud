//! Subscription `DeliveryPolicy`: the single parser for its retry settings.

use std::time::Duration;

use serde_json::{Map, Value};

use crate::error::SnsError;
use crate::model::Subscription;

/// AWS default retries of the healthy retry policy.
const DEFAULT_NUM_RETRIES: u32 = 3;
const MAX_NUM_RETRIES: u64 = 100;
const MAX_DELAY_TARGET_SECS: u64 = 3600;

/// Effective retry settings of one subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetryPolicy {
    pub num_retries: u32,
    pub min_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            num_retries: DEFAULT_NUM_RETRIES,
            min_delay: Duration::ZERO,
        }
    }
}

impl RetryPolicy {
    /// Parse a client-supplied subscription `DeliveryPolicy`.
    pub(crate) fn parse(raw: &str) -> Result<Self, SnsError> {
        let policy: Value =
            serde_json::from_str(raw).map_err(|_| invalid("DeliveryPolicy is not valid JSON"))?;
        let root = policy
            .as_object()
            .ok_or_else(|| invalid("DeliveryPolicy must be a JSON object"))?;
        if root.keys().any(|key| key != "healthyRetryPolicy") {
            return Err(invalid("DeliveryPolicy contains unsupported fields"));
        }
        let healthy = root
            .get("healthyRetryPolicy")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("DeliveryPolicy requires healthyRetryPolicy"))?;
        if healthy
            .keys()
            .any(|key| key != "numRetries" && key != "minDelayTarget")
        {
            return Err(invalid("DeliveryPolicy contains unsupported retry fields"));
        }
        let num_retries = integer(healthy, "numRetries", MAX_NUM_RETRIES)?
            .map_or(DEFAULT_NUM_RETRIES, |value| value as u32);
        let min_delay = integer(healthy, "minDelayTarget", MAX_DELAY_TARGET_SECS)?
            .map_or(Duration::ZERO, Duration::from_secs);
        Ok(Self {
            num_retries,
            min_delay,
        })
    }

    /// The subscription's stored policy (validated when it was set), or the AWS default.
    pub(crate) fn of(subscription: &Subscription) -> Self {
        subscription
            .attributes
            .get("DeliveryPolicy")
            .and_then(|raw| Self::parse(raw).ok())
            .unwrap_or_default()
    }

    /// Topic `EffectiveDeliveryPolicy` when the topic sets none.
    pub(crate) fn default_effective_topic_policy() -> String {
        format!(
            "{{\"http\":{{\"defaultHealthyRetryPolicy\":{{\"numRetries\":{DEFAULT_NUM_RETRIES}}}}}}}"
        )
    }
}

fn integer(policy: &Map<String, Value>, field: &str, max: u64) -> Result<Option<u64>, SnsError> {
    let Some(value) = policy.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .filter(|value| *value <= max)
        .map(Some)
        .ok_or_else(|| invalid("DeliveryPolicy retry values are out of range"))
}

fn invalid(message: &str) -> SnsError {
    SnsError::InvalidParameter(message.into())
}
