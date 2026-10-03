//! Cross-service delivery engine.
//!
//! Owns the *mechanics* of delivering a [`CrossServiceCall`] through the single
//! [`InternalDispatcher`] path; the *policy* values (retries, DLQ/destinations) are supplied
//! by the owning service spec so behaviour matches AWS for that service. Synchronous delivery
//! returns the protocol-correct response to the source; asynchronous delivery retries
//! retriable failures and, on exhaustion or a terminal failure, surfaces a classified
//! [`DeliveryError`] (never silently dropping the event). See Requirement 6.

use std::sync::Arc;
use std::time::Duration;

use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, Method, Uri};

use super::correlation::CorrelationContext;
use super::identity::{CallerIdentity, IdentityPropagator};
use super::pattern::IntegrationPatternId;
use super::InternalDispatcher;
use crate::registry::ServiceName;

/// A call originating from one emulated service to another (or from a Guest SDK).
pub struct CrossServiceCall {
    pub source_service: ServiceName,
    pub account_id: String,
    pub region: String,
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub identity: CallerIdentity,
    pub correlation: CorrelationContext,
    pub pattern: Option<IntegrationPatternId>,
}

impl CrossServiceCall {
    fn pattern_label(&self) -> &str {
        self.pattern.map(|p| p.0).unwrap_or("direct")
    }
}

/// Whether a failure may be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    Retriable,
    Terminal,
}

/// Where exhausted/failed async events are routed (resolved + delivered by the owning service).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureTarget {
    DeadLetterQueue(String),
    Destination(String),
}

/// Retry/failure policy supplied by the owning service spec (Lambda, SQS, …).
#[derive(Debug, Clone)]
pub struct AsyncDeliveryPolicy {
    pub max_attempts: u32,
    pub on_failure: Option<FailureTarget>,
}

/// A classified async-delivery failure after retries are exhausted or a terminal error occurs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("async delivery failed ({class:?}) after {attempts} attempt(s), last status {last_status}")]
pub struct DeliveryError {
    pub class: FailureClass,
    pub last_status: u16,
    pub attempts: u32,
    /// `true` when the owning service has a failure target (DLQ/destination) to route to.
    pub routed_to_failure: bool,
}

pub struct DeliveryEngine {
    dispatcher: Arc<InternalDispatcher>,
}

impl DeliveryEngine {
    pub fn new(dispatcher: Arc<InternalDispatcher>) -> Self {
        DeliveryEngine { dispatcher }
    }

    /// Classify an HTTP status: throttling (429) and server errors (5xx) are retriable;
    /// everything else is terminal.
    pub fn classify(status: u16) -> FailureClass {
        if status == 429 || (500..600).contains(&status) {
            FailureClass::Retriable
        } else {
            FailureClass::Terminal
        }
    }

    /// Synchronous delivery: dispatch once and return the target's response unaltered for the
    /// source to interpret.
    pub async fn deliver_sync(&self, call: CrossServiceCall) -> Response {
        call.correlation.log_hop(
            call.source_service.as_str(),
            "resolved-by-router",
            call.pattern_label(),
            "sync",
        );
        self.dispatch_once(&call).await
    }

    /// Asynchronous delivery: retry retriable failures up to `max_attempts`; return `Ok` on
    /// the first 2xx; on a terminal failure stop immediately; on exhaustion surface a
    /// `Retriable` `DeliveryError`. The owning service routes the event to `on_failure`.
    pub async fn deliver_async(
        &self,
        call: CrossServiceCall,
        policy: &AsyncDeliveryPolicy,
    ) -> Result<(), DeliveryError> {
        self.deliver_async_checked(call, policy, || true).await
    }

    /// Re-evaluate an execution permission before every attempt, including retries.
    pub async fn deliver_async_checked(
        &self,
        call: CrossServiceCall,
        policy: &AsyncDeliveryPolicy,
        allowed: impl Fn() -> bool,
    ) -> Result<(), DeliveryError> {
        let attempts = policy.max_attempts.max(1);
        let mut last_status = 0u16;
        for attempt in 1..=attempts {
            if !allowed() {
                return Err(self.fail(&call, FailureClass::Terminal, 403, attempt, policy));
            }
            let response = self.dispatch_once(&call).await;
            last_status = response.status().as_u16();
            if (200..300).contains(&last_status) {
                return Ok(());
            }
            match Self::classify(last_status) {
                FailureClass::Terminal => {
                    return Err(self.fail(
                        &call,
                        FailureClass::Terminal,
                        last_status,
                        attempt,
                        policy,
                    ));
                }
                FailureClass::Retriable => {
                    if attempt < attempts {
                        let shift = attempt.saturating_sub(1).min(5);
                        let delay_ms = 25_u64.saturating_mul(1_u64 << shift);
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                }
            }
        }
        Err(self.fail(
            &call,
            FailureClass::Retriable,
            last_status,
            attempts,
            policy,
        ))
    }

    fn fail(
        &self,
        call: &CrossServiceCall,
        class: FailureClass,
        last_status: u16,
        attempts: u32,
        policy: &AsyncDeliveryPolicy,
    ) -> DeliveryError {
        let routed_to_failure = policy.on_failure.is_some();
        tracing::warn!(
            flow_id = %call.correlation.flow_id,
            source = call.source_service.as_str(),
            pattern = call.pattern_label(),
            ?class,
            last_status,
            attempts,
            routed_to_failure,
            "async cross-service delivery failed"
        );
        DeliveryError {
            class,
            last_status,
            attempts,
            routed_to_failure,
        }
    }

    async fn dispatch_once(&self, call: &CrossServiceCall) -> Response {
        let mut headers = call.headers.clone();
        IdentityPropagator::attach(&mut headers, &call.identity);
        self.dispatcher
            .dispatch_scoped(
                &call.method,
                &call.uri,
                &headers,
                call.body.clone(),
                &call.correlation.flow_id,
                &call.account_id,
                &call.region,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::{NativeHandler, ServiceRequest};
    use crate::proxy::{LegacyHealth, ProxyConfig};
    use crate::registry::{AwsProtocol, ServiceMetadata, ServiceRegistry};
    use axum::body::Body;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    /// A native handler that returns the given status for the first `fail_times` calls, then 200.
    struct FlakyHandler {
        calls: AtomicU32,
        fail_times: u32,
        fail_status: u16,
    }

    #[async_trait::async_trait]
    impl NativeHandler for FlakyHandler {
        async fn handle(&self, _request: ServiceRequest) -> Response {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            let status = if n < self.fail_times {
                self.fail_status
            } else {
                200
            };
            Response::builder()
                .status(status)
                .body(Body::from("x"))
                .unwrap()
        }
    }

    fn engine_with(handler: Arc<dyn NativeHandler>) -> DeliveryEngine {
        let registry = ServiceRegistry::with_known_services();
        registry.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            handler,
        );
        let dispatcher = Arc::new(InternalDispatcher::new(
            registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(true),
            "us-east-1".into(),
            "000000000000".into(),
        ));
        DeliveryEngine::new(dispatcher)
    }

    fn call() -> CrossServiceCall {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=test/20240101/us-east-1/lambda/aws4_request"
                .parse()
                .unwrap(),
        );
        CrossServiceCall {
            source_service: ServiceName::new("states"),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
            method: Method::POST,
            uri: "/2015-03-31/functions/f/invocations".parse().unwrap(),
            headers,
            body: Bytes::from("{}"),
            identity: CallerIdentity::Default,
            correlation: CorrelationContext::root(),
            pattern: Some(IntegrationPatternId("states->lambda")),
        }
    }

    fn policy(max: u32) -> AsyncDeliveryPolicy {
        AsyncDeliveryPolicy {
            max_attempts: max,
            on_failure: Some(FailureTarget::DeadLetterQueue("arn:dlq".into())),
        }
    }

    #[tokio::test]
    async fn checked_retry_stops_after_role_revocation() {
        let handler = Arc::new(FlakyHandler {
            calls: AtomicU32::new(0),
            fail_times: 2,
            fail_status: 503,
        });
        let engine = engine_with(handler.clone());
        let checks = AtomicU32::new(0);
        let error = engine
            .deliver_async_checked(call(), &policy(3), || {
                checks.fetch_add(1, Ordering::SeqCst) == 0
            })
            .await
            .unwrap_err();
        assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        assert_eq!(error.class, FailureClass::Terminal);
        assert_eq!(error.last_status, 403);
    }

    #[test]
    fn classify_status() {
        assert_eq!(DeliveryEngine::classify(429), FailureClass::Retriable);
        assert_eq!(DeliveryEngine::classify(503), FailureClass::Retriable);
        assert_eq!(DeliveryEngine::classify(400), FailureClass::Terminal);
        assert_eq!(DeliveryEngine::classify(404), FailureClass::Terminal);
    }

    #[tokio::test]
    async fn async_retries_then_succeeds() {
        let engine = engine_with(Arc::new(FlakyHandler {
            calls: AtomicU32::new(0),
            fail_times: 2,
            fail_status: 503,
        }));
        assert!(engine.deliver_async(call(), &policy(3)).await.is_ok());
    }

    #[tokio::test]
    async fn async_terminal_failure_does_not_retry() {
        let handler = Arc::new(FlakyHandler {
            calls: AtomicU32::new(0),
            fail_times: u32::MAX,
            fail_status: 400,
        });
        let engine = engine_with(handler.clone());
        let err = engine.deliver_async(call(), &policy(5)).await.unwrap_err();
        assert_eq!(err.class, FailureClass::Terminal);
        assert_eq!(
            err.attempts, 1,
            "terminal failure stops after the first attempt"
        );
        assert!(err.routed_to_failure);
    }

    #[tokio::test]
    async fn async_exhausts_retriable_failures() {
        let engine = engine_with(Arc::new(FlakyHandler {
            calls: AtomicU32::new(0),
            fail_times: u32::MAX,
            fail_status: 503,
        }));
        let err = engine.deliver_async(call(), &policy(3)).await.unwrap_err();
        assert_eq!(err.class, FailureClass::Retriable);
        assert_eq!(err.attempts, 3);
    }

    #[tokio::test]
    async fn sync_returns_target_response() {
        let engine = engine_with(Arc::new(FlakyHandler {
            calls: AtomicU32::new(0),
            fail_times: 0,
            fail_status: 500,
        }));
        let resp = engine.deliver_sync(call()).await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn concurrent_deliveries_keep_independent_correlation() {
        let engine = Arc::new(engine_with(Arc::new(FlakyHandler {
            calls: AtomicU32::new(0),
            fail_times: 0,
            fail_status: 500,
        })));
        let mut handles = Vec::new();
        for _ in 0..50u32 {
            let engine = engine.clone();
            handles.push(tokio::spawn(async move {
                // Each call carries its own freshly-rooted correlation + identity.
                let c = call();
                let flow = c.correlation.flow_id.clone();
                let ok = engine.deliver_async(c, &policy(2)).await.is_ok();
                (flow, ok)
            }));
        }
        let mut flows = std::collections::HashSet::new();
        for h in handles {
            let (flow, ok) = h.await.unwrap();
            assert!(ok, "each concurrent delivery succeeds independently");
            assert!(flows.insert(flow), "each delivery has a distinct flow_id");
        }
        assert_eq!(flows.len(), 50);
    }
}
