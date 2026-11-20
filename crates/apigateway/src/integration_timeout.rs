//! AWS integration timeout bounds (`timeoutInMillis`) per API protocol.

use serde_json::Value;

use crate::error::ApiGwError;

/// Bounds and default of `timeoutInMillis` for one API protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IntegrationTimeout {
    min: u64,
    max: u64,
    default: u64,
}

/// REST APIs: 50 ms to 29 s, default 29 s.
pub(crate) const REST: IntegrationTimeout = IntegrationTimeout {
    min: 50,
    max: 29_000,
    default: 29_000,
};

/// HTTP APIs: 50 ms to 30 s, default 30 s.
pub(crate) const HTTP: IntegrationTimeout = IntegrationTimeout {
    min: 50,
    max: 30_000,
    default: 30_000,
};

/// WebSocket APIs: 50 ms to 29 s, default 29 s.
pub(crate) const WEBSOCKET: IntegrationTimeout = IntegrationTimeout {
    min: 50,
    max: 29_000,
    default: 29_000,
};

/// Time budget for a Lambda authorizer invocation.
pub(crate) const LAMBDA_AUTHORIZER_MS: u64 = 29_000;

impl IntegrationTimeout {
    /// Bounds for an API Gateway v2 `protocolType` (`HTTP` or `WEBSOCKET`).
    pub(crate) fn for_v2_protocol(protocol: &str) -> Self {
        if protocol == "WEBSOCKET" {
            WEBSOCKET
        } else {
            HTTP
        }
    }

    /// Validate a client-supplied `timeoutInMillis`.
    pub(crate) fn validate(self, value: &Value) -> Result<u64, ApiGwError> {
        let timeout = value
            .as_u64()
            .ok_or_else(|| ApiGwError::BadRequest("timeoutInMillis must be an integer".into()))?;
        if !(self.min..=self.max).contains(&timeout) {
            return Err(ApiGwError::BadRequest(format!(
                "timeoutInMillis must be between {} and {}",
                self.min, self.max
            )));
        }
        Ok(timeout)
    }

    /// The stored integration's timeout, or this protocol's default.
    pub(crate) fn of(self, integration: &Value) -> u64 {
        integration
            .get("timeoutInMillis")
            .and_then(Value::as_u64)
            .unwrap_or(self.default)
    }
}
