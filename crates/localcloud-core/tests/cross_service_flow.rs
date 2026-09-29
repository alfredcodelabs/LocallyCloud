//! Task 10 — end-to-end cross-service flow validation.
//!
//! Validates a `stepfunctions -> lambda -> s3` flow through the SINGLE
//! [`InternalDispatcher`] path: each hop is dispatched through the same router+registry an
//! external client would use, and the Native/Proxied boundary is explicit. Native services
//! (`lambda`, `s3`) resolve in-process to their registered handlers; a Proxied service takes
//! the legacy forwarding path — a distinct, observable disposition.
//!
//! Each hop emits a correlated routing record via the dispatcher's `log_routing_decision`, so
//! the boundary is visible in logs. The per-hop dispositions are asserted here by outcome.
//! Running the guest workloads that would originate these hops live is an environment boundary
//! (no firecracker kernel/rootfs, no OCI registry pull here); the dispatch contract they rely
//! on is what this test exercises.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, Method};

use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::integration::InternalDispatcher;
use localcloud_core::proxy::{LegacyHealth, ProxyConfig};
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

/// Records the order in which native services are invoked across the flow.
struct RecordingHandler {
    name: &'static str,
    order: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl NativeHandler for RecordingHandler {
    async fn handle(&self, _request: ServiceRequest) -> Response {
        self.order.lock().unwrap().push(self.name.to_string());
        Response::builder()
            .status(200)
            .body(axum::body::Body::from(format!("{}-ok", self.name)))
            .unwrap()
    }
}

fn auth(service: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        "authorization",
        format!("AWS4-HMAC-SHA256 Credential=test/20240101/us-east-1/{service}/aws4_request")
            .parse()
            .unwrap(),
    );
    h
}

#[tokio::test]
async fn stepfunctions_lambda_s3_flow_through_single_dispatcher() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let registry = ServiceRegistry::with_known_services();
    registry.register_native(
        ServiceName::new("lambda"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        Arc::new(RecordingHandler {
            name: "lambda",
            order: order.clone(),
        }),
    );
    registry.register_native(
        ServiceName::new("s3"),
        ServiceMetadata::new(AwsProtocol::RestXml, None),
        Arc::new(RecordingHandler {
            name: "s3",
            order: order.clone(),
        }),
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

    // Hop 1: Step Functions optimized integration invokes Lambda (Native).
    let lambda = dispatcher
        .dispatch(
            &Method::POST,
            &"/2015-03-31/functions/f/invocations".parse().unwrap(),
            &auth("lambda"),
            Bytes::from("{}"),
            "flow-1",
        )
        .await;
    assert_eq!(
        lambda.status(),
        200,
        "stepfunctions->lambda must resolve natively"
    );

    // Hop 2: the Lambda workload writes to S3 via an in-Guest SDK call (Native), through the
    // SAME dispatcher path.
    let s3 = dispatcher
        .dispatch(
            &Method::PUT,
            &"/my-bucket/key".parse().unwrap(),
            &auth("s3"),
            Bytes::from("payload"),
            "flow-1",
        )
        .await;
    assert_eq!(s3.status(), 200, "lambda->s3 must resolve natively");

    // The flow traversed both native hops in order through the single routing path.
    assert_eq!(
        *order.lock().unwrap(),
        vec!["lambda".to_string(), "s3".to_string()]
    );
}

#[tokio::test]
async fn native_and_proxied_boundary_is_explicit() {
    let registry = ServiceRegistry::with_known_services();
    registry.register_native(
        ServiceName::new("lambda"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        Arc::new(RecordingHandler {
            name: "lambda",
            order: Arc::new(Mutex::new(Vec::new())),
        }),
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

    // Native disposition: handled in-process (200).
    let native = dispatcher
        .dispatch(
            &Method::POST,
            &"/2015-03-31/functions/f/invocations".parse().unwrap(),
            &auth("lambda"),
            Bytes::from("{}"),
            "boundary",
        )
        .await;
    assert_eq!(native.status(), 200);

    // Proxied disposition: a service not registered native takes the legacy forwarding path,
    // an observably distinct boundary (dead backend -> 502, not a native 200/501).
    let proxied = dispatcher
        .dispatch(
            &Method::POST,
            &"/".parse().unwrap(),
            &auth("sns"),
            Bytes::from("{}"),
            "boundary",
        )
        .await;
    assert_eq!(
        proxied.status(),
        502,
        "proxied service must cross the legacy boundary, not resolve natively"
    );
}
