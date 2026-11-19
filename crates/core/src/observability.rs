//! Structured observability.
//!
//! Formats tracing for interactive consoles or JSON consumers and emits per-request
//! routing-decision records correlated by request id. Never logs SigV4 signatures, secret
//! keys or security tokens. See Requirement 19.

use crate::router::RoutingDecision;
mod logging;
pub use logging::{init_tracing, LogColor, LogFormat, LoggingConfig};

/// Record a failure once at its owning boundary, using only approved diagnostic fields.
/// Callers supply a static/typed cause code, never a raw source error or client payload.
pub fn log_service_error(
    service: &str,
    operation: Option<&str>,
    request_id: &str,
    cause_code: &str,
    status: u16,
) {
    if status >= 500 {
        tracing::error!(
            service,
            operation,
            request_id,
            cause_code,
            status,
            "service request failed"
        );
    } else {
        log_service_rejection(service, operation, request_id, cause_code, status);
    }
}

/// An expected service rejection can retain a protocol-required 5xx without becoming an ERROR.
/// Classification belongs to the service's typed failure, not to a message-string heuristic.
pub fn log_service_rejection(
    service: &str,
    operation: Option<&str>,
    request_id: &str,
    cause_code: &str,
    status: u16,
) {
    tracing::debug!(
        service,
        operation,
        request_id,
        cause_code,
        status,
        "service request rejected"
    );
}

/// A unique identifier assigned to each inbound request, used to correlate log records
/// with the response.
pub fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Emit a structured record for a routing decision (Req 19.1–19.3, 19.6). Only the
/// resolved service, the resolution source, and the disposition are logged — never any
/// signature, secret key, or security token (Req 19.7).
pub fn log_routing_decision(decision: &RoutingDecision, request_id: &str) {
    tracing::info!(
        request_id,
        service = decision.service_name.as_str(),
        resolution_source = ?decision.resolution_source,
        disposition = ?decision.disposition,
        "routing decision"
    );
}
