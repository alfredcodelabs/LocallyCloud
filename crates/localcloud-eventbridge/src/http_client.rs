use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use http::{HeaderName, HeaderValue, Method};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpError;

impl From<()> for HttpError {
    fn from(_: ()) -> Self {
        Self
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
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| HttpError)?;
        let value = HeaderValue::from_str(value).map_err(|_| HttpError)?;
        self.headers.push((
            name.as_str().to_string(),
            value.to_str().map_err(|_| HttpError)?.to_string(),
        ));
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError>;
}

#[derive(Default)]
pub struct ReqwestHttpClient;

// Keep the old exported name for crate-internal test constructors outside this audited file set.
pub use ReqwestHttpClient as CurlHttpClient;

fn client() -> Result<&'static reqwest::Client, HttpError> {
    static CLIENT: OnceLock<Result<reqwest::Client, HttpError>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|_| HttpError)
        })
        .as_ref()
        .map_err(|_| HttpError)
}

#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let HttpRequest {
            method,
            url,
            headers,
            body,
        } = request;
        if !url.starts_with("https://") {
            return Err(HttpError);
        }
        let mut outbound = client()?.request(method, url);
        for (name, value) in headers {
            outbound = outbound.header(name.as_str(), value.as_str());
        }
        if !body.is_empty() {
            outbound = outbound.body(body);
        }
        let response = outbound.send().await.map_err(|_| HttpError)?;
        let status = response.status().as_u16();
        let body = response.bytes().await.map_err(|_| HttpError)?.to_vec();
        Ok(HttpResponse { status, body })
    }
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
        assert_eq!(ReqwestHttpClient.send(request).await, Err(HttpError));
    }

    #[test]
    fn form_encoding_uses_percent_encoding_for_spaces_and_plus() {
        assert_eq!(form_encode("a b+c"), "a%20b%2Bc");
    }
}
