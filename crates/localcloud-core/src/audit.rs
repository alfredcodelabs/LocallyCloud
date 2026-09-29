//! Bounded, cycle-free completed-dispatch observation.
//!
//! The boundary deliberately contains no request or response bodies.

use std::time::SystemTime;

use crate::registry::{AwsProtocol, Disposition};

#[derive(Debug, Clone)]
pub struct DispatchOutcome {
    pub dispatch_id: String,
    pub request_id: String,
    pub account_id: String,
    pub region: String,
    pub service: String,
    pub operation: String,
    pub protocol: AwsProtocol,
    pub disposition: Disposition,
    pub started_at: SystemTime,
    pub completed_at: SystemTime,
    pub http_status: u16,
    /// AWS-modeled error type, obtained only from a response header and bounded by Core.
    pub error_code: Option<String>,
}

/// Called after the handler/proxy has produced its response. Implementations must be bounded
/// and must never depend on the originating response body or block for I/O.
pub trait CompletionObserver: Send + Sync {
    fn observe(&self, outcome: DispatchOutcome);
}
