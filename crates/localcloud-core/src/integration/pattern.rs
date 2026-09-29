//! Integration-pattern registry.
//!
//! Service specs declare a supported wiring (e.g. `s3->lambda`, `sns->sqs`) by registering an
//! [`IntegrationPattern`] WITHOUT modifying the dispatcher. Each pattern carries an
//! `EnvelopeBuilder` that produces the exact AWS record shape the target expects (`aws:s3`,
//! `aws:sns`, `aws:sqs`, …). This module is the contract and storage; the concrete builders
//! live in the owning service crates. See Requirement 5.

use bytes::Bytes;
use dashmap::DashMap;

use crate::registry::ServiceName;

/// A stable identifier for a wiring, e.g. `IntegrationPatternId("sns->sqs")`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntegrationPatternId(pub &'static str);

/// How a pattern delivers to its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    /// Request/response (e.g. Step Functions optimized `lambda:invoke`).
    Synchronous,
    /// Enqueue + background execute (e.g. Lambda async invoke).
    Asynchronous,
    /// Fan-out event delivery (e.g. S3 event, SNS→SQS).
    Notification,
}

/// The source event handed to an [`EnvelopeBuilder`].
#[derive(Debug, Clone)]
pub struct SourceEvent {
    pub source: ServiceName,
    pub payload: Bytes,
}

/// Builds the AWS-shaped target event from the source event.
pub type EnvelopeBuilder = fn(&SourceEvent) -> Bytes;

/// A declared cross-service wiring.
#[derive(Clone)]
pub struct IntegrationPattern {
    pub id: IntegrationPatternId,
    pub source_service: ServiceName,
    pub target_service: ServiceName,
    pub delivery_mode: DeliveryMode,
    pub envelope: EnvelopeBuilder,
}

/// Concurrent registry of integration patterns.
#[derive(Default)]
pub struct IntegrationPatternRegistry {
    patterns: DashMap<IntegrationPatternId, IntegrationPattern>,
}

impl IntegrationPatternRegistry {
    pub fn new() -> Self {
        IntegrationPatternRegistry {
            patterns: DashMap::new(),
        }
    }

    /// Register (or replace) a pattern. No dispatcher change is required.
    pub fn register(&self, pattern: IntegrationPattern) {
        self.patterns.insert(pattern.id, pattern);
    }

    pub fn get(&self, id: IntegrationPatternId) -> Option<IntegrationPattern> {
        self.patterns.get(&id).map(|p| p.clone())
    }

    /// Build the target envelope for a registered pattern, if present.
    pub fn build_envelope(&self, id: IntegrationPatternId, event: &SourceEvent) -> Option<Bytes> {
        self.get(id).map(|p| (p.envelope)(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sns_to_sqs_envelope(event: &SourceEvent) -> Bytes {
        // Stand-in builder for the test; real builders live in the service crates.
        Bytes::from(format!(
            "{{\"Records\":[{{\"body\":{:?}}}]}}",
            String::from_utf8_lossy(&event.payload)
        ))
    }

    fn pattern() -> IntegrationPattern {
        IntegrationPattern {
            id: IntegrationPatternId("sns->sqs"),
            source_service: ServiceName::new("sns"),
            target_service: ServiceName::new("sqs"),
            delivery_mode: DeliveryMode::Notification,
            envelope: sns_to_sqs_envelope,
        }
    }

    #[test]
    fn register_then_get() {
        let reg = IntegrationPatternRegistry::new();
        reg.register(pattern());
        let got = reg.get(IntegrationPatternId("sns->sqs")).unwrap();
        assert_eq!(got.source_service, ServiceName::new("sns"));
        assert_eq!(got.target_service, ServiceName::new("sqs"));
        assert!(matches!(got.delivery_mode, DeliveryMode::Notification));
    }

    #[test]
    fn get_unknown_is_none() {
        let reg = IntegrationPatternRegistry::new();
        assert!(reg.get(IntegrationPatternId("nope")).is_none());
    }

    #[test]
    fn build_envelope_runs_the_builder() {
        let reg = IntegrationPatternRegistry::new();
        reg.register(pattern());
        let event = SourceEvent {
            source: ServiceName::new("sns"),
            payload: Bytes::from("hello"),
        };
        let out = reg
            .build_envelope(IntegrationPatternId("sns->sqs"), &event)
            .unwrap();
        assert!(String::from_utf8_lossy(&out).contains("hello"));
    }
}
