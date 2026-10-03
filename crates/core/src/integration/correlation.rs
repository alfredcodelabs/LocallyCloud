//! Correlation context for a cross-service flow.
//!
//! A `flow_id` is stable across every hop of a flow; each hop gets a fresh `span_id`. Each
//! hop emits a structured record (flow_id, source, target, pattern, disposition) so a flow is
//! traceable end-to-end, including where it crosses the Native/Proxied boundary. Signatures,
//! secrets, and tokens are never logged. See Requirement 7.

use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationContext {
    /// Stable id propagated across all hops of a flow.
    pub flow_id: String,
    /// Per-hop span id.
    pub span_id: String,
}

impl CorrelationContext {
    /// Start a new flow.
    pub fn root() -> Self {
        CorrelationContext {
            flow_id: Uuid::new_v4().to_string(),
            span_id: Uuid::new_v4().to_string(),
        }
    }

    /// Derive the next hop: same `flow_id`, a fresh `span_id`.
    pub fn child(&self) -> Self {
        CorrelationContext {
            flow_id: self.flow_id.clone(),
            span_id: Uuid::new_v4().to_string(),
        }
    }

    /// Emit the structured per-hop record. `disposition` is `Native`/`ProxiedToLegacy`; the
    /// record never carries secrets or tokens.
    pub fn log_hop(&self, source: &str, target: &str, pattern: &str, disposition: &str) {
        tracing::info!(
            flow_id = %self.flow_id,
            span_id = %self.span_id,
            source,
            target,
            pattern,
            disposition,
            "cross-service hop"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_has_distinct_flow_and_span() {
        let root = CorrelationContext::root();
        assert!(!root.flow_id.is_empty());
        assert!(!root.span_id.is_empty());
        assert_ne!(root.flow_id, root.span_id);
    }

    #[test]
    fn child_shares_flow_but_new_span() {
        let root = CorrelationContext::root();
        let child = root.child();
        assert_eq!(root.flow_id, child.flow_id);
        assert_ne!(root.span_id, child.span_id);
    }

    #[test]
    fn distinct_roots_have_distinct_flows() {
        assert_ne!(
            CorrelationContext::root().flow_id,
            CorrelationContext::root().flow_id
        );
    }
}
