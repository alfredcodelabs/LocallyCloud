//! Native service handler contract.
//!
//! A service crate implements [`NativeHandler`] and registers it via
//! [`ServiceRegistry::register_native`](crate::registry::ServiceRegistry::register_native).
//! The [`InternalDispatcher`](crate::integration::InternalDispatcher) invokes it for
//! requests whose disposition is `Native`, so adding a service does not change the router.

use async_trait::async_trait;
use axum::extract::ws::WebSocketUpgrade;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};

/// A decomposed in-process request handed to a native service handler.
#[derive(Debug, Clone)]
pub struct ServiceRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
    /// AWS region resolved for this request (from the credential scope or the default).
    pub region: String,
    /// AWS account id resolved for this request.
    pub account_id: String,
    /// Correlation id for logging.
    pub request_id: String,
}

/// A natively-implemented AWS service.
#[async_trait]
pub trait NativeHandler: Send + Sync {
    async fn handle(&self, request: ServiceRequest) -> Response;

    /// Resolve a public invocation from stored resources in the configured account.
    /// This selects routing only; the handler still enforces invocation authorization.
    async fn public_invoke_region(
        &self,
        _account: &str,
        _host: &str,
        _path: &str,
    ) -> Option<String> {
        None
    }

    /// Regions containing existing resources owned by this account. Global services and
    /// handlers without regional control-plane resources contribute no regions.
    /// Read-created scopes, defaults, deletion tombstones and telemetry are excluded.
    async fn resource_regions(&self, _account: &str) -> Result<Vec<String>, &'static str> {
        Ok(Vec::new())
    }

    /// Whether this account owns any global control-plane resources.
    async fn has_global_resources(&self, _account: &str) -> Result<bool, &'static str> {
        Ok(false)
    }

    async fn handle_websocket(
        &self,
        _request: ServiceRequest,
        _upgrade: WebSocketUpgrade,
    ) -> Response {
        StatusCode::UPGRADE_REQUIRED.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct DefaultWebSocketHandler;

    #[async_trait]
    impl NativeHandler for DefaultWebSocketHandler {
        async fn handle(&self, _request: ServiceRequest) -> Response {
            Response::new(Body::empty())
        }
    }

    async fn websocket_handler(upgrade: WebSocketUpgrade) -> Response {
        DefaultWebSocketHandler
            .handle_websocket(
                ServiceRequest {
                    method: Method::GET,
                    uri: "/".parse().unwrap(),
                    headers: HeaderMap::new(),
                    body: Bytes::new(),
                    region: "us-east-1".to_string(),
                    account_id: "000000000000".to_string(),
                    request_id: "rid".to_string(),
                },
                upgrade,
            )
            .await
    }

    #[tokio::test]
    async fn default_websocket_handler_returns_upgrade_required() {
        let app = Router::new().route("/", get(websocket_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET / HTTP/1.1\r\nHost: {address}\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        let mut response = [0; 256];
        let bytes_read = stream.read(&mut response).await.unwrap();
        let response = std::str::from_utf8(&response[..bytes_read]).unwrap();
        assert!(response.starts_with("HTTP/1.1 426 Upgrade Required\r\n"));

        server.abort();
    }
}
