use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use http::{HeaderName, HeaderValue, Method};
use locallycloud_core::egress::{EgressClient, EgressError, EgressSettings};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    #[error("invalid EventBridge HTTP request")]
    InvalidRequest,
    #[error("EventBridge HTTP transport failed")]
    Transport,
    #[error("EventBridge HTTP response exceeded the local body budget")]
    ResponseTooLarge,
    #[error("EventBridge HTTP destination is not permitted")]
    DestinationDenied,
}

impl From<()> for HttpError {
    fn from(_: ()) -> Self {
        Self::Transport
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpRequest {
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: String::new(),
        }
    }

    pub fn header(&mut self, name: &str, value: &str) -> Result<(), HttpError> {
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| HttpError::InvalidRequest)?;
        let value = HeaderValue::from_str(value).map_err(|_| HttpError::InvalidRequest)?;
        self.headers.push((
            name.as_str().to_string(),
            value
                .to_str()
                .map_err(|_| HttpError::InvalidRequest)?
                .to_string(),
        ));
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// Signed delta-seconds from `Retry-After`. HTTP-date values are not interpreted.
    pub retry_after: Option<i64>,
}

fn retry_after(response: &reqwest::Response) -> Option<i64> {
    response
        .headers()
        .get(http::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError>;

    async fn send_for_status(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let response = self.send(request).await?;
        Ok(HttpResponse {
            body: Vec::new(),
            ..response
        })
    }
}

pub struct ReqwestHttpClient {
    response_body_limit: usize,
    client: EgressClient,
}

impl Default for ReqwestHttpClient {
    fn default() -> Self {
        Self::with_config(&crate::EventBridgeConfig::default(), &[])
            .expect("default EventBridge HTTP policy is valid")
    }
}

impl ReqwestHttpClient {
    /// `listeners` are LocallyCloud's own addresses, which destinations can never reach.
    /// Per-origin connections are still opened only on first delivery.
    pub(crate) fn with_config(
        config: &crate::EventBridgeConfig,
        listeners: &[SocketAddr],
    ) -> Result<Self, String> {
        Self::with_roots(config, listeners, Vec::new())
    }

    fn with_roots(
        config: &crate::EventBridgeConfig,
        listeners: &[SocketAddr],
        root_certificates: Vec<reqwest::Certificate>,
    ) -> Result<Self, String> {
        let client = EgressClient::new(
            EgressSettings {
                local_origins: config.http_local_origins.clone(),
                client_capacity: config.http_client_cache_capacity,
                connect_timeout: Some(Duration::from_secs(config.http_connect_timeout_secs)),
                request_timeout: Some(Duration::from_secs(config.http_request_timeout_secs)),
                root_certificates,
                ..Default::default()
            },
            listeners,
        )
        .map_err(|error| format!("eventbridge.http_local_origins: {error}"))?;
        Ok(Self {
            response_body_limit: config.http_response_body_limit_bytes,
            client,
        })
    }

    async fn send_request(&self, request: HttpRequest) -> Result<reqwest::Response, HttpError> {
        let HttpRequest {
            method,
            url,
            headers,
            body,
        } = request;
        if !url.starts_with("https://") {
            return Err(HttpError::InvalidRequest);
        }
        let mut outbound = self
            .client
            .request(method, &url)
            .map_err(destination_failure)?;
        for (name, value) in headers {
            outbound = outbound.header(name.as_str(), value.as_str());
        }
        if !body.is_empty() {
            outbound = outbound.body(body);
        }
        outbound
            .send()
            .await
            .map_err(|error| destination_failure(EgressError::from_request(&error)))
    }
}

// The URL can carry query parameters from the connection, so only the cause is logged.
fn destination_failure(error: EgressError) -> HttpError {
    match error {
        EgressError::InvalidUrl | EgressError::InvalidOrigin(_) => HttpError::InvalidRequest,
        EgressError::DestinationDenied | EgressError::HostProbe | EgressError::DnsAnswers => {
            tracing::warn!(
                service = "events",
                operation = "InvokeApiDestination",
                cause_code = "destination_denied",
                "API destination address is not permitted; allow it with eventbridge.http_local_origins"
            );
            HttpError::DestinationDenied
        }
        EgressError::DnsResolution
        | EgressError::CacheUnavailable
        | EgressError::ClientInitialization
        | EgressError::TlsConfiguration
        | EgressError::Connection
        | EgressError::Timeout => HttpError::Transport,
    }
}

// Keep the old exported name for crate-internal test constructors outside this audited file set.
pub use ReqwestHttpClient as CurlHttpClient;

#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let response = self.send_request(request).await?;
        let status = response.status().as_u16();
        let retry_after = retry_after(&response);
        let body = read_response_body(response, self.response_body_limit).await?;
        Ok(HttpResponse {
            status,
            body,
            retry_after,
        })
    }

    async fn send_for_status(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let response = self.send_request(request).await?;
        Ok(HttpResponse {
            status: response.status().as_u16(),
            body: Vec::new(),
            retry_after: retry_after(&response),
        })
    }
}

async fn read_response_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, HttpError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(HttpError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| HttpError::Transport)? {
        body.len()
            .checked_add(chunk.len())
            .filter(|length| *length <= limit)
            .ok_or(HttpError::ResponseTooLarge)?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(crate) fn form_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_non_https_without_external_process() {
        let request = HttpRequest::new(Method::GET, "http://example.invalid");
        assert_eq!(
            ReqwestHttpClient::default().send(request).await,
            Err(HttpError::InvalidRequest)
        );
    }

    #[tokio::test]
    async fn configured_client_bounds_owned_tls_response_bodies_and_request_time() {
        use axum::{extract::Path, routing::get, Router};
        use std::sync::Arc;
        struct OwnedServer(tokio::task::JoinHandle<()>);
        impl Drop for OwnedServer {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let identity = Arc::new(
            locallycloud_core::tls::GuestCallbackTls::new()
                .await
                .unwrap(),
        );
        let status_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = status_requests.clone();
        let server = OwnedServer(identity.clone().spawn(
            listener,
            Router::new().route(
                "/{kind}",
                get(move |Path(kind): Path<String>| {
                    let observed = observed.clone();
                    async move {
                        if kind == "oversize" {
                            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                        if kind == "stall" {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                        let payload = vec![b'x'; if kind == "exact" { 16 } else { 17 }];
                        let body = axum::body::Body::from(payload);
                        let body = if kind == "chunked" {
                            axum::body::Body::from_stream(body.into_data_stream())
                        } else {
                            body
                        };
                        http::Response::builder()
                            .status(202)
                            .header("retry-after", "-3")
                            .body(body)
                            .unwrap()
                    }
                }),
            ),
            false,
        ));
        let config = crate::EventBridgeConfig {
            http_request_timeout_secs: 1,
            http_response_body_limit_bytes: 16,
            http_local_origins: vec![origin.clone()],
            ..Default::default()
        };
        config.validate().unwrap();
        let client = ReqwestHttpClient::with_roots(
            &config,
            &[],
            vec![reqwest::Certificate::from_pem(identity.ca_pem().as_bytes()).unwrap()],
        )
        .unwrap();
        let exact = client
            .send(HttpRequest::new(Method::GET, format!("{origin}/exact")))
            .await
            .unwrap();
        assert_eq!((exact.status, exact.body.len()), (202, 16));
        assert_eq!(exact.retry_after, Some(-3));
        assert_eq!(
            client
                .send(HttpRequest::new(Method::GET, format!("{origin}/oversize")))
                .await,
            Err(HttpError::ResponseTooLarge)
        );
        let status_only = client
            .send_for_status(HttpRequest::new(Method::GET, format!("{origin}/oversize")))
            .await
            .unwrap();
        assert_eq!((status_only.status, status_only.body.len()), (202, 0));
        assert_eq!(status_only.retry_after, Some(-3));
        assert_eq!(status_requests.load(std::sync::atomic::Ordering::SeqCst), 2);

        let chunked = client
            .client
            .request(Method::GET, &format!("{origin}/chunked"))
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(chunked.content_length(), None);
        assert_eq!(
            read_response_body(chunked, 16).await,
            Err(HttpError::ResponseTooLarge)
        );
        let stalled = tokio::time::timeout(
            Duration::from_secs(2),
            client.send(HttpRequest::new(Method::GET, format!("{origin}/stall"))),
        )
        .await
        .unwrap();
        assert_eq!(stalled, Err(HttpError::Transport));
        drop(server);
    }

    #[tokio::test]
    async fn outbound_client_preserves_redirect_status_without_forwarding_credentials() {
        use axum::{extract::Request, routing::any, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let sink = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sink_url = format!("http://{}", sink.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let sink_hits = hits.clone();
        let sink_task = tokio::spawn(async move {
            axum::serve(
                sink,
                Router::new().fallback(any(move || {
                    let hits = sink_hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        "ok"
                    }
                })),
            )
            .await
            .unwrap();
        });
        let source = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source_url = format!("http://{}", source.local_addr().unwrap());
        let client = ReqwestHttpClient::with_config(
            &crate::EventBridgeConfig {
                http_request_timeout_secs: 2,
                http_local_origins: vec![source_url.clone(), sink_url.clone()],
                ..Default::default()
            },
            &[],
        )
        .unwrap()
        .client;
        let location = sink_url.clone();
        let source_task = tokio::spawn(async move {
            axum::serve(
                source,
                Router::new().fallback(any(move |request: Request| {
                    let location = location.clone();
                    async move {
                        let status = request
                            .uri()
                            .path()
                            .trim_start_matches('/')
                            .parse::<u16>()
                            .unwrap();
                        http::Response::builder()
                            .status(status)
                            .header("location", location)
                            .body(axum::body::Body::from("ok"))
                            .unwrap()
                    }
                })),
            )
            .await
            .unwrap();
        });
        for status in [301, 302, 303, 307, 308] {
            let response = client
                .request(Method::POST, &format!("{source_url}/{status}"))
                .unwrap()
                .header("x-api-key", "fictional-key")
                .body("client_secret=fictional-secret")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status);
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            client
                .request(Method::POST, &format!("{source_url}/200"))
                .unwrap()
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            client
                .request(Method::POST, &sink_url)
                .unwrap()
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        source_task.abort();
        sink_task.abort();
        let _ = source_task.await;
        let _ = sink_task.await;
    }

    #[tokio::test]
    async fn local_and_metadata_destinations_are_denied_without_contacting_them() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let observed = accepted.clone();
        let server = tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                observed.fetch_add(1, Ordering::SeqCst);
            }
        });
        let client = ReqwestHttpClient::default();
        for url in [
            format!("https://{address}/hook"),
            format!("https://localhost:{}/hook", address.port()),
            "https://169.254.169.254/latest/meta-data".to_string(),
            "https://[fd00:ec2::254]/".to_string(),
        ] {
            assert_eq!(
                client
                    .send(HttpRequest::new(Method::POST, url.clone()))
                    .await,
                Err(HttpError::DestinationDenied),
                "{url}"
            );
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
        let local = crate::EventBridgeConfig {
            http_local_origins: vec![format!("https://{address}")],
            http_request_timeout_secs: 2,
            ..Default::default()
        };
        assert!(ReqwestHttpClient::with_config(&local, &[address]).is_err());
        let allowed = ReqwestHttpClient::with_config(&local, &[]).unwrap();
        // The plain TCP listener cannot complete TLS, but the connection is permitted.
        assert_eq!(
            allowed
                .send(HttpRequest::new(
                    Method::POST,
                    format!("https://{address}/")
                ))
                .await,
            Err(HttpError::Transport)
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[test]
    fn form_encoding_uses_percent_encoding_for_spaces_and_plus() {
        assert_eq!(form_encode("a b+c"), "a%20b%2Bc");
    }
}
