//! AWS error-shape mapping framework.
//!
//! Serializes an internal error into the protocol-correct AWS wire shape so strict SDK
//! error deserialization succeeds: XML for REST-XML/Query, `__type` JSON for JSON 1.0/1.1,
//! and a `message` body plus `x-amzn-errortype` header for REST-JSON. See Requirement 18.

use crate::registry::AwsProtocol;

pub(crate) fn cloudwatch_cbor_request(uri: &http::Uri, headers: &http::HeaderMap) -> bool {
    uri.path()
        .starts_with("/service/GraniteServiceVersion20100801/operation/")
        && headers
            .get("content-type")
            .is_some_and(|value| value == "application/cbor")
        && headers
            .get("smithy-protocol")
            .is_some_and(|value| value == "rpc-v2-cbor")
}

/// Preserve early routing/signature errors for current CloudWatch SDK clients.
pub(crate) async fn cloudwatch_cbor_error(
    response: axum::response::Response,
) -> axum::response::Response {
    if response.status().is_success()
        || response
            .headers()
            .get("content-type")
            .is_some_and(|value| value == "application/cbor")
    {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .unwrap_or_default();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    let code = value
        .get("__type")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            parts
                .headers
                .get("x-amzn-errortype")
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or("InternalServiceError")
        .to_owned();
    let message = value
        .get("message")
        .or_else(|| value.get("Message"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("AWS request failed");
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(
        &serde_json::json!({"__type":code,"message":message}),
        &mut bytes,
    )
    .expect("CBOR error to Vec cannot fail");
    parts.headers.remove(http::header::CONTENT_LENGTH);
    parts.headers.insert(
        "content-type",
        http::HeaderValue::from_static("application/cbor"),
    );
    parts.headers.insert(
        "smithy-protocol",
        http::HeaderValue::from_static("rpc-v2-cbor"),
    );
    if let Ok(value) = code.parse() {
        parts.headers.insert("x-amzn-errortype", value);
    }
    axum::response::Response::from_parts(parts, axum::body::Body::from(bytes))
}

/// AWS error metadata, independent of protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsError {
    /// AWS error code, e.g. `ResourceNotFoundException`.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// HTTP status real AWS returns for this error.
    pub http_status: u16,
    /// Request id correlated to the response.
    pub request_id: String,
    /// `Sender` (client fault) vs `Receiver` (server fault); only used by the XML shape.
    pub sender_fault: bool,
    /// REST-JSON body key for the message. AWS varies by service: API Gateway uses
    /// `message`, Lambda uses `Message`. Defaults to `message`.
    pub rest_json_message_key: &'static str,
    /// XML namespace for the Query `<ErrorResponse>` element (service+version specific,
    /// e.g. `https://iam.amazonaws.com/doc/2010-05-08/`). `None` omits the attribute.
    pub xml_namespace: Option<&'static str>,
}

/// A protocol-rendered error response, framework-agnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedError {
    pub status: u16,
    pub content_type: &'static str,
    /// Extra response headers (name, value), e.g. `x-amzn-RequestId` or `x-amzn-errortype`.
    pub headers: Vec<(&'static str, String)>,
    pub body: String,
}

impl RenderedError {
    /// Build an Axum response from the rendered error.
    pub fn into_response(self) -> axum::response::Response {
        let mut builder = http::Response::builder()
            .status(self.status)
            .header("content-type", self.content_type);
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        builder
            .body(axum::body::Body::from(self.body))
            .expect("rendered AWS error is always a valid response")
    }
}

impl AwsError {
    pub fn new(code: impl Into<String>, message: impl Into<String>, http_status: u16) -> Self {
        AwsError {
            code: code.into(),
            message: message.into(),
            http_status,
            request_id: String::new(),
            sender_fault: true,
            rest_json_message_key: "message",
            xml_namespace: None,
        }
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = request_id.into();
        self
    }

    /// Override the REST-JSON message body key (e.g. `Message` for Lambda).
    pub fn with_rest_json_message_key(mut self, key: &'static str) -> Self {
        self.rest_json_message_key = key;
        self
    }

    /// Set the Query `<ErrorResponse>` XML namespace (service+version specific).
    pub fn with_xml_namespace(mut self, namespace: &'static str) -> Self {
        self.xml_namespace = Some(namespace);
        self
    }

    /// Render the error in the wire shape for `protocol`.
    pub fn render(&self, protocol: AwsProtocol) -> RenderedError {
        match protocol {
            AwsProtocol::RestXml | AwsProtocol::Query => self.to_xml(),
            AwsProtocol::Json10 => self.to_json_rpc("application/x-amz-json-1.0"),
            AwsProtocol::Json11 => self.to_json_rpc("application/x-amz-json-1.1"),
            AwsProtocol::RestJson => self.to_rest_json(),
        }
    }

    fn to_xml(&self) -> RenderedError {
        let fault = if self.sender_fault {
            "Sender"
        } else {
            "Receiver"
        };
        let open_tag = match self.xml_namespace {
            Some(ns) => format!("<ErrorResponse xmlns=\"{ns}\">"),
            None => "<ErrorResponse>".to_string(),
        };
        let body = format!(
            "{}\n  <Error>\n    <Type>{}</Type>\n    <Code>{}</Code>\n    <Message>{}</Message>\n  </Error>\n  <RequestId>{}</RequestId>\n</ErrorResponse>",
            open_tag,
            fault,
            xml_escape(&self.code),
            xml_escape(&self.message),
            xml_escape(&self.request_id),
        );
        RenderedError {
            status: self.http_status,
            content_type: "application/xml",
            headers: vec![("x-amzn-RequestId", self.request_id.clone())],
            body,
        }
    }

    fn to_json_rpc(&self, content_type: &'static str) -> RenderedError {
        let body = format!(
            "{{\"__type\":{},\"message\":{}}}",
            json_string(&self.code),
            json_string(&self.message),
        );
        RenderedError {
            status: self.http_status,
            content_type,
            headers: vec![("x-amzn-RequestId", self.request_id.clone())],
            body,
        }
    }

    fn to_rest_json(&self) -> RenderedError {
        let body = format!(
            "{{{}:{}}}",
            json_string(self.rest_json_message_key),
            json_string(&self.message),
        );
        RenderedError {
            status: self.http_status,
            content_type: "application/json",
            headers: vec![
                ("x-amzn-errortype", self.code.clone()),
                ("x-amzn-RequestId", self.request_id.clone()),
            ],
            body,
        }
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Serialize a string as a JSON string literal (quotes + minimal escaping).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AwsError {
        AwsError::new(
            "ResourceNotFoundException",
            "The resource was not found",
            404,
        )
        .with_request_id("req-123")
    }

    #[test]
    fn query_and_rest_xml_render_xml() {
        for proto in [AwsProtocol::Query, AwsProtocol::RestXml] {
            let r = sample().render(proto);
            assert_eq!(r.content_type, "application/xml");
            assert_eq!(r.status, 404);
            assert!(r.body.contains("<Code>ResourceNotFoundException</Code>"));
            assert!(r.body.contains("<Type>Sender</Type>"));
            assert!(r.body.contains("<RequestId>req-123</RequestId>"));
        }
    }

    #[test]
    fn json_rpc_uses_type_member_and_versioned_content_type() {
        let r10 = sample().render(AwsProtocol::Json10);
        assert_eq!(r10.content_type, "application/x-amz-json-1.0");
        assert!(r10
            .body
            .contains("\"__type\":\"ResourceNotFoundException\""));
        assert!(r10
            .body
            .contains("\"message\":\"The resource was not found\""));

        let r11 = sample().render(AwsProtocol::Json11);
        assert_eq!(r11.content_type, "application/x-amz-json-1.1");
        assert!(r11
            .body
            .contains("\"__type\":\"ResourceNotFoundException\""));
    }

    #[test]
    fn rest_json_uses_errortype_header() {
        let r = sample().render(AwsProtocol::RestJson);
        assert_eq!(r.content_type, "application/json");
        assert!(r
            .body
            .contains("\"message\":\"The resource was not found\""));
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| *k == "x-amzn-errortype" && v == "ResourceNotFoundException"));
    }

    #[test]
    fn rest_json_message_key_is_overridable() {
        let r = sample()
            .with_rest_json_message_key("Message")
            .render(AwsProtocol::RestJson);
        assert!(r
            .body
            .contains("\"Message\":\"The resource was not found\""));
        assert!(!r.body.contains("\"message\""));
    }

    #[test]
    fn xml_namespace_is_emitted_when_set() {
        let r = sample()
            .with_xml_namespace("https://iam.amazonaws.com/doc/2010-05-08/")
            .render(AwsProtocol::Query);
        assert!(r
            .body
            .starts_with("<ErrorResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">"));
        let none = sample().render(AwsProtocol::Query);
        assert!(none.body.starts_with("<ErrorResponse>"));
    }

    #[test]
    fn receiver_fault_renders_in_xml_type() {
        let mut e = sample();
        e.sender_fault = false;
        let r = e.render(AwsProtocol::Query);
        assert!(r.body.contains("<Type>Receiver</Type>"));
    }

    #[test]
    fn message_special_characters_are_escaped() {
        let e = AwsError::new("BadRequest", "bad <value> & \"quote\"", 400);
        let xml = e.render(AwsProtocol::RestXml);
        assert!(xml.body.contains("bad &lt;value&gt; &amp; \"quote\""));
        let json = e.render(AwsProtocol::Json10);
        assert!(json.body.contains("bad <value> & \\\"quote\\\""));
    }

    #[test]
    fn status_is_carried_through() {
        let e = AwsError::new("TooManyRequestsException", "slow down", 429);
        assert_eq!(e.render(AwsProtocol::RestJson).status, 429);
    }
}
