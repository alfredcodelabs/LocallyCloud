//! Budgeted AWS reads through the injected [`AwsReader`], and reply classification.

use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use locallycloud_core::views::architecture::{AwsRead, AwsReader, ReadError, TopologyError};
use serde_json::Value;

/// Upper bound of nested JSON values accepted from AWS replies and documents.
pub(crate) const JSON_DEPTH: usize = 32;
/// Upper bound of JSON values accepted from one AWS reply or document.
pub(crate) const JSON_VALUES: usize = 50_000;

/// The outcome of a read the topology can continue after.
pub(crate) enum Reply {
    Body(Bytes),
    /// The resource no longer exists (drift or deletion).
    Missing,
    /// Any other AWS error; its code is kept to classify validation errors.
    Failed {
        code: Option<String>,
    },
}

/// Counts every read against a fixed budget.
pub(crate) struct Reads<'a> {
    reader: &'a dyn AwsReader,
    used: AtomicUsize,
    limit: usize,
}

impl<'a> Reads<'a> {
    pub(crate) fn new(reader: &'a dyn AwsReader, limit: usize) -> Self {
        Self {
            reader,
            used: AtomicUsize::new(0),
            limit,
        }
    }

    pub(crate) async fn send(&self, read: AwsRead) -> Result<Reply, TopologyError> {
        if self.used.fetch_add(1, Ordering::Relaxed) >= self.limit {
            return Err(TopologyError::Unprocessable(format!(
                "Topology needs more than {} AWS reads",
                self.limit
            )));
        }
        let service = read.service;
        let reply = self.reader.read(read).await.map_err(|error| match error {
            ReadError::NotRead => TopologyError::AccessDenied(format!(
                "The architecture view may not perform this {service} operation"
            )),
            ReadError::TooLarge(limit) => {
                TopologyError::Unprocessable(format!("A {service} response exceeds {limit} bytes"))
            }
        })?;
        if (200..300).contains(&reply.status) {
            return Ok(Reply::Body(reply.body));
        }
        let code = error_code(&reply.body);
        match classify(reply.status, code.as_deref()) {
            Failure::Denied => Err(TopologyError::AccessDenied(format!(
                "Not authorized to read {service} configuration for this topology"
            ))),
            Failure::Missing => Ok(Reply::Missing),
            Failure::Other => Ok(Reply::Failed { code }),
        }
    }
}

enum Failure {
    Denied,
    Missing,
    Other,
}

const DENIED_CODES: &[&str] = &[
    "AccessDenied",
    "AccessDeniedException",
    "AuthorizationError",
    "UnauthorizedOperation",
    "MissingAuthenticationToken",
    "InvalidClientTokenId",
    "UnrecognizedClientException",
    "SignatureDoesNotMatch",
    "ExpiredToken",
];

fn classify(status: u16, code: Option<&str>) -> Failure {
    let code = code.unwrap_or_default();
    if status == 401 || status == 403 || DENIED_CODES.contains(&code) {
        return Failure::Denied;
    }
    let missing = code.ends_with("NotFoundException")
        || code.ends_with("NotFound")
        || code.ends_with("DoesNotExist")
        || code.starts_with("NoSuch");
    if status == 404 || missing {
        return Failure::Missing;
    }
    Failure::Other
}

/// AWS error code from a JSON (`__type`, `code`) or XML (`<Code>`) error body.
fn error_code(body: &[u8]) -> Option<String> {
    if body.len() > 64 * 1024 {
        return None;
    }
    if let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(body) {
        let raw = ["__type", "code", "Code"]
            .iter()
            .find_map(|key| map.get(*key).and_then(Value::as_str))?;
        let code = raw.rsplit_once('#').map_or(raw, |(_, code)| code);
        return Some(code.split(':').next().unwrap_or(code).to_owned());
    }
    let text = std::str::from_utf8(body).ok()?;
    let (_, rest) = text.split_once("<Code>")?;
    let (code, _) = rest.split_once("</Code>")?;
    Some(code.trim().to_owned())
}

/// A Query-protocol read (`Action` form body).
pub(crate) fn query(
    service: &'static str,
    action: &str,
    version: &str,
    params: &[(&str, &str)],
) -> AwsRead {
    let mut body = format!("Action={}&Version={}", encode(action), encode(version));
    for (key, value) in params {
        body.push('&');
        body.push_str(&encode(key));
        body.push('=');
        body.push_str(&encode(value));
    }
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/x-www-form-urlencoded; charset=utf-8"),
    );
    AwsRead {
        service,
        method: http::Method::POST,
        uri: http::Uri::from_static("/"),
        headers,
        body: Bytes::from(body),
    }
}

/// A JSON-RPC read addressed by `X-Amz-Target`.
pub(crate) fn json_rpc(
    service: &'static str,
    target: &'static str,
    content_type: &'static str,
    body: &Value,
) -> AwsRead {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-target", http::HeaderValue::from_static(target));
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(content_type),
    );
    AwsRead {
        service,
        method: http::Method::POST,
        uri: http::Uri::from_static("/"),
        headers,
        body: Bytes::from(body.to_string()),
    }
}

/// A REST read. `path` must already be built from [`encode`]d segments.
pub(crate) fn rest_get(service: &'static str, path: &str) -> Result<AwsRead, TopologyError> {
    let uri = path
        .parse::<http::Uri>()
        .map_err(|_| TopologyError::Unprocessable(format!("Invalid {service} read path")))?;
    Ok(AwsRead {
        service,
        method: http::Method::GET,
        uri,
        headers: http::HeaderMap::new(),
        body: Bytes::new(),
    })
}

/// Percent-encodes everything except RFC 3986 unreserved characters.
pub(crate) fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Parses a JSON reply within the structure bounds; anything else is unusable.
pub(crate) fn json(body: &[u8], what: &str) -> Result<Value, TopologyError> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .filter(bounded)
        .ok_or_else(|| {
            TopologyError::Unprocessable(format!("{what} returned an unusable response"))
        })
}

/// Iterative depth and size check, so no client-supplied structure is recursed unbounded.
pub(crate) fn bounded(value: &Value) -> bool {
    let mut pending = vec![(value, 0usize)];
    let mut count = 0usize;
    while let Some((value, depth)) = pending.pop() {
        count += 1;
        if count > JSON_VALUES || depth > JSON_DEPTH {
            return false;
        }
        match value {
            Value::Array(items) => pending.extend(items.iter().map(|v| (v, depth + 1))),
            Value::Object(map) => pending.extend(map.values().map(|v| (v, depth + 1))),
            _ => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_error_codes_from_every_protocol() {
        assert_eq!(
            error_code(br#"{"__type":"com.amazon#ResourceNotFoundException","message":"x"}"#)
                .as_deref(),
            Some("ResourceNotFoundException")
        );
        assert_eq!(
            error_code(
                b"<ErrorResponse><Error><Code>ValidationError</Code></Error></ErrorResponse>"
            )
            .as_deref(),
            Some("ValidationError")
        );
        assert!(matches!(
            classify(400, Some("NoSuchBucket")),
            Failure::Missing
        ));
        assert!(matches!(
            classify(400, Some("AccessDenied")),
            Failure::Denied
        ));
        assert!(matches!(classify(500, None), Failure::Other));
    }

    #[test]
    fn encodes_reserved_characters() {
        assert_eq!(encode("a b/c&d=é"), "a%20b%2Fc%26d%3D%C3%A9");
    }

    #[test]
    fn rejects_deep_or_large_json() {
        let mut deep = serde_json::json!(1);
        for _ in 0..40 {
            deep = serde_json::json!({ "n": deep });
        }
        assert!(!bounded(&deep));
        let wide = Value::Array(vec![Value::Null; JSON_VALUES + 1]);
        assert!(!bounded(&wide));
        assert!(bounded(&serde_json::json!({"a": [1, 2, {"b": 3}]})));
    }
}
