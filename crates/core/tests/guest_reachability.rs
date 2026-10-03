//! Task 9 — in-Guest reachability validation.
//!
//! Validates the endpoint-injection mechanism end-to-end over real HTTP: a locallycloud
//! dispatch endpoint is served on a real TCP socket, a [`GuestEndpointInjector`] is built from
//! that listen address (exactly as it is for a started Guest), and a request issued with the
//! injected endpoint + credentials — as an in-Guest AWS SDK would — reaches locallycloud and
//! resolves to the expected routing decision.
//!
//! The injected environment is identical for both compute runtimes (Firecracker and youki),
//! so this validates the shared contract for both. Booting a live microVM/container to run a
//! real SDK inside it is an environment boundary (no firecracker kernel/rootfs, no static
//! guest SDK artifact here), so the in-Guest hop is exercised over the same loopback HTTP path
//! the Guest uses (youki shares the host netns; Firecracker reaches the host over its tap).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::response::Response;
use axum::routing::any;
use axum::Router;

use locallycloud_core::endpoint::EndpointResolver;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::guest::{GuestCredentials, GuestEndpointInjector};
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

/// A native handler that identifies which service handled the request.
struct NamedHandler(&'static str);

#[async_trait::async_trait]
impl NativeHandler for NamedHandler {
    async fn handle(&self, _request: ServiceRequest) -> Response {
        Response::builder()
            .status(200)
            .body(axum::body::Body::from(format!("{}-native", self.0)))
            .unwrap()
    }
}

/// Serve a locallycloud dispatch endpoint on a real TCP socket; return its address.
async fn serve_locallycloud() -> std::net::SocketAddr {
    let registry = ServiceRegistry::with_known_services();
    registry.register_native(
        ServiceName::new("lambda"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        Arc::new(NamedHandler("lambda")),
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

    let app = Router::new().fallback(any(forward)).with_state(dispatcher);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Hand an inbound HTTP request to the single dispatch path, as the locallycloud server does.
async fn forward(State(dispatcher): State<Arc<InternalDispatcher>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    dispatcher
        .dispatch(
            &parts.method,
            &parts.uri,
            &parts.headers,
            bytes,
            "guest-req",
        )
        .await
}

#[tokio::test]
async fn injected_endpoint_reaches_locallycloud_and_routes_correctly() {
    let addr = serve_locallycloud().await;

    // Build the injector exactly as it is built for a started Guest.
    let resolver = EndpointResolver::resolve(None, addr);
    let injector =
        GuestEndpointInjector::new(&resolver, "us-east-1", GuestCredentials::development());

    // The endpoint is reachable from the host (Req 4.4 diagnostic path).
    assert!(
        injector
            .check_reachable(Duration::from_secs(2))
            .await
            .is_reachable(),
        "injected endpoint must be reachable"
    );

    // Issue a call as an in-Guest AWS SDK would: injected endpoint + injected credentials.
    let env = injector.env_vars();
    let endpoint = &env["AWS_ENDPOINT_URL"];
    let access_key = &env["AWS_ACCESS_KEY_ID"];
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{endpoint}/2015-03-31/functions/f/invocations"))
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential={access_key}/20240101/us-east-1/lambda/aws4_request"
            ),
        )
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "in-Guest SDK call must reach locallycloud"
    );
    assert_eq!(
        resp.text().await.unwrap(),
        "lambda-native",
        "injected endpoint must resolve to the expected native routing decision"
    );
}

#[tokio::test]
async fn unreachable_endpoint_yields_a_diagnostic() {
    // A port with nothing listening: the injector reports an actionable diagnostic rather
    // than letting a later in-Guest SDK call fail opaquely.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let resolver = EndpointResolver::resolve(None, addr);
    let injector =
        GuestEndpointInjector::new(&resolver, "us-east-1", GuestCredentials::development());
    assert!(!injector
        .check_reachable(Duration::from_secs(1))
        .await
        .is_reachable());
}
