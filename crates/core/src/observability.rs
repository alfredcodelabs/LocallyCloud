//! Structured observability.
//!
//! Initializes tracing (JSON primary, plain-text fallback) and emits per-request
//! routing-decision records correlated by request id. Never logs SigV4 signatures, secret
//! keys or security tokens. See Requirement 19.

use crate::router::RoutingDecision;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the global tracing subscriber. Tries JSON output first and falls back to
/// plain text rather than terminating startup if JSON initialization fails (Req 19.5).
/// Idempotent: a second call is a no-op once a global subscriber exists.
pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json_ok = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json())
        .try_init()
        .is_ok();
    if !json_ok {
        // Either a subscriber is already set, or JSON could not initialize. A plain-text
        // attempt covers the latter and is harmless for the former.
        let _ = fmt().try_init();
    }
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
