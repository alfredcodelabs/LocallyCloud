//! Health and readiness.
//!
//! Tracks localcloud's own readiness, reported independently of the legacy backend, and
//! shapes the health response. The HTTP routes (`/_localcloud/health` and the
//! `/_localstack/health` compatibility alias) are wired in [`crate::server`].
//! See Requirements 4 and 12.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Shared readiness flag. Cloneable; all clones observe the same state.
#[derive(Clone, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    pub fn new() -> Self {
        Readiness(Arc::new(AtomicBool::new(false)))
    }

    /// Mark localcloud ready once the registry and runtime selector are initialized.
    pub fn mark_ready(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// The (status, json-body) pair for the health endpoint given the current readiness.
pub fn health_response(ready: bool) -> (u16, &'static str) {
    if ready {
        (200, r#"{"status":"running"}"#)
    } else {
        (503, r#"{"status":"starting"}"#)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_starts_not_ready_and_can_be_marked() {
        let r = Readiness::new();
        assert!(!r.is_ready());
        r.mark_ready();
        assert!(r.is_ready());
    }

    #[test]
    fn readiness_clones_share_state() {
        let r = Readiness::new();
        let r2 = r.clone();
        r.mark_ready();
        assert!(r2.is_ready());
    }

    #[test]
    fn health_response_reflects_readiness() {
        assert_eq!(health_response(false).0, 503);
        assert_eq!(health_response(true).0, 200);
        assert!(health_response(true).1.contains("running"));
        assert!(health_response(false).1.contains("starting"));
    }
}
