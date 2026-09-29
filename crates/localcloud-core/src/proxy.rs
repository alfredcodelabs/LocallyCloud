//! SigV4-preserving reverse proxy to an optional external backend.
//!
//! Forwards unsupported-service requests, preserving the signed material: the method, path,
//! query string, and every header (including `Authorization` and the original `Host`) are
//! sent unchanged, and the response is relayed byte-for-byte. The TCP connection target is
//! the configured backend authority, kept separate from the forwarded `Host` header value
//! by using a low-level HTTP/1 connection. See Requirements 9, 10 and 11.

use std::time::Duration;

use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, Method, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Legacy backend base URL, e.g. `http://localhost:4567`.
    pub backend_url: String,
    /// Upstream timeout applied to both connect and request phases.
    pub upstream_timeout: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("legacy backend unreachable: {0}")]
    ConnectionFailed(String),
    #[error("upstream timed out after {0:?}")]
    Timeout(Duration),
}

impl ProxyError {
    /// AWS error code for this failure.
    pub fn code(&self) -> &'static str {
        match self {
            ProxyError::ConnectionFailed(_) => "BadGateway",
            ProxyError::Timeout(_) => "GatewayTimeout",
        }
    }

    /// HTTP status: 502 for connection failure, 504 for timeout (Req 11.1, 11.2).
    pub fn http_status(&self) -> u16 {
        match self {
            ProxyError::ConnectionFailed(_) => 502,
            ProxyError::Timeout(_) => 504,
        }
    }
}

/// Shared liveness state of the legacy backend. Cloneable; all clones observe the same
/// state. Starts optimistic (healthy) so the first request is attempted rather than
/// fast-failed before any probe has run. See Requirement 12.
#[derive(Clone)]
pub struct LegacyHealth {
    healthy: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl LegacyHealth {
    pub fn new(initial: bool) -> Self {
        LegacyHealth {
            healthy: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(initial)),
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Set the liveness state, logging only on a transition (Req 12.2).
    pub fn set(&self, healthy: bool) {
        let prev = self
            .healthy
            .swap(healthy, std::sync::atomic::Ordering::SeqCst);
        if prev != healthy {
            if healthy {
                tracing::info!("legacy backend became healthy");
            } else {
                tracing::warn!("legacy backend became unhealthy");
            }
        }
    }

    /// Spawn a background task that probes the legacy backend by TCP-connecting to its
    /// authority on each interval, updating the shared state (Req 12.1, 12.2).
    pub fn spawn_checker(
        self,
        backend_url: String,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let addr = match connect_addr(&backend_url) {
                Some(a) => a,
                None => {
                    tracing::error!(
                        backend_url,
                        "cannot parse legacy backend url; health checks disabled"
                    );
                    return;
                }
            };
            loop {
                tokio::time::sleep(interval).await;
                let ok = matches!(
                    timeout(interval, TcpStream::connect(&addr)).await,
                    Ok(Ok(_))
                );
                self.set(ok);
            }
        })
    }
}

/// Parse `host:port` from a backend base URL like `http://localhost:4567`.
fn connect_addr(backend_url: &str) -> Option<String> {
    let uri: Uri = backend_url.parse().ok()?;
    let host = uri.host()?;
    let port = uri.port_u16().unwrap_or(80);
    Some(format!("{host}:{port}"))
}

/// Forward a request to the legacy backend and relay the response.
pub async fn forward_to_legacy(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
    config: &ProxyConfig,
) -> Result<Response, ProxyError> {
    let addr = connect_addr(&config.backend_url)
        .ok_or_else(|| ProxyError::ConnectionFailed("invalid backend url".to_string()))?;

    // Connect to the backend authority (Req 10.5: connection target separate from Host).
    let stream = match timeout(config.upstream_timeout, TcpStream::connect(&addr)).await {
        Err(_) => return Err(ProxyError::Timeout(config.upstream_timeout)),
        Ok(Err(e)) => return Err(ProxyError::ConnectionFailed(e.to_string())),
        Ok(Ok(s)) => s,
    };

    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| ProxyError::ConnectionFailed(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Build the outbound request in origin form (path?query), copying every header
    // verbatim so the signed material — including the original Host — is preserved.
    let path_and_query = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let mut builder = http::Request::builder()
        .method(method.clone())
        .uri(path_and_query);
    if let Some(out_headers) = builder.headers_mut() {
        *out_headers = headers.clone();
    }
    let request = builder
        .body(Full::new(body))
        .map_err(|e| ProxyError::ConnectionFailed(e.to_string()))?;

    let upstream = match timeout(config.upstream_timeout, sender.send_request(request)).await {
        Err(_) => return Err(ProxyError::Timeout(config.upstream_timeout)),
        Ok(Err(e)) => return Err(ProxyError::ConnectionFailed(e.to_string())),
        Ok(Ok(r)) => r,
    };

    // Relay the response status, headers, and body byte-for-byte (Req 9.7).
    let status = upstream.status();
    let resp_headers = upstream.headers().clone();
    let collected = upstream
        .into_body()
        .collect()
        .await
        .map_err(|e| ProxyError::ConnectionFailed(e.to_string()))?
        .to_bytes();

    let mut out = Response::builder().status(status);
    if let Some(h) = out.headers_mut() {
        *h = resp_headers;
    }
    out.body(Body::from(collected))
        .map_err(|e| ProxyError::ConnectionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Request;
    use axum::routing::any;
    use axum::Router;

    /// Spin a fake "legacy backend" that echoes the method, the received `Host` header, and
    /// the request body. Returns its base URL.
    async fn spawn_echo_backend() -> String {
        let app = Router::new().fallback(any(|req: Request| async move {
            let (parts, body) = req.into_parts();
            let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
            let host = parts
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            Response::builder()
                .status(200)
                .header("x-echo-method", parts.method.as_str())
                .header("x-echo-host", host)
                .body(Body::from(bytes))
                .unwrap()
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn forwards_method_body_and_preserves_host() {
        let backend = spawn_echo_backend().await;
        let cfg = ProxyConfig {
            backend_url: backend,
            upstream_timeout: Duration::from_secs(5),
        };

        let mut headers = HeaderMap::new();
        headers.insert("host", "my-bucket.s3.amazonaws.com".parse().unwrap());
        headers.insert(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=x".parse().unwrap(),
        );

        let resp = forward_to_legacy(
            &Method::PUT,
            &"/bucket/key?versionId=1".parse().unwrap(),
            &headers,
            Bytes::from_static(b"payload-bytes"),
            &cfg,
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-echo-method").unwrap(), "PUT");
        // The client-signed Host is forwarded unchanged, not rewritten to the backend.
        assert_eq!(
            resp.headers().get("x-echo-host").unwrap(),
            "my-bucket.s3.amazonaws.com"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"payload-bytes");
    }

    #[tokio::test]
    async fn connection_failure_maps_to_502() {
        // Port 1 is not listening.
        let cfg = ProxyConfig {
            backend_url: "http://127.0.0.1:1".to_string(),
            upstream_timeout: Duration::from_secs(2),
        };
        let err = forward_to_legacy(
            &Method::GET,
            &"/".parse().unwrap(),
            &HeaderMap::new(),
            Bytes::new(),
            &cfg,
        )
        .await
        .unwrap_err();
        assert_eq!(err.http_status(), 502);
    }
}
