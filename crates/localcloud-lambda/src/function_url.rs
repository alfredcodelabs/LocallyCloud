//! Function URL request/response translation.
//!
//! A Function URL invocation maps an HTTP request to the API Gateway **payload format 2.0**
//! proxy event, invokes the function synchronously, and maps the structured
//! `Proxy_Response_V2` back to an HTTP response (Requirement 14.7). A non-structured return
//! is wrapped as `200 application/json`; a malformed response surfaces as `502`.

use base64::Engine as _;
use serde_json::{json, Map, Value};

/// The HTTP request received on a Function URL.
pub struct UrlRequest {
    pub method: String,
    pub raw_path: String,
    pub raw_query: String,
    /// Headers as received (name, value); multi-value headers appear multiple times.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub url_id: String,
    pub region: String,
    pub account: String,
    pub request_id: String,
}

/// The HTTP response produced from a function's structured return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlHttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Build the API Gateway v2 (2.0) proxy event for a Function URL request.
pub fn build_v2_event(req: &UrlRequest) -> Value {
    // Cookies come out of the `Cookie` header into a dedicated array; other headers are
    // comma-joined by name (lowercased), per the 2.0 contract.
    let mut cookies: Vec<String> = Vec::new();
    let mut header_map: Map<String, Value> = Map::new();
    for (name, value) in &req.headers {
        let lower = name.to_ascii_lowercase();
        if lower == "cookie" {
            cookies.extend(value.split("; ").map(str::to_string));
            continue;
        }
        match header_map.get_mut(&lower) {
            Some(Value::String(existing)) => {
                *existing = format!("{existing},{value}");
            }
            _ => {
                header_map.insert(lower, Value::String(value.clone()));
            }
        }
    }

    let query_params = parse_query(&req.raw_query);
    let (body, is_base64) = encode_body(&req.body);
    let domain = format!("{}.lambda-url.{}.on.aws", req.url_id, req.region);

    let mut event = json!({
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": req.raw_path,
        "rawQueryString": req.raw_query,
        "headers": Value::Object(header_map),
        "requestContext": {
            "accountId": req.account,
            "apiId": req.url_id,
            "domainName": domain,
            "domainPrefix": req.url_id,
            "http": {
                "method": req.method,
                "path": req.raw_path,
                "protocol": "HTTP/1.1",
                "sourceIp": "127.0.0.1",
                "userAgent": header_value(&req.headers, "user-agent").unwrap_or_default(),
            },
            "requestId": req.request_id,
            "routeKey": "$default",
            "stage": "$default",
        },
        "isBase64Encoded": is_base64,
    });
    if !cookies.is_empty() {
        event["cookies"] = json!(cookies);
    }
    if !query_params.is_empty() {
        event["queryStringParameters"] = Value::Object(query_params);
    }
    if let Some(b) = body {
        event["body"] = json!(b);
    }
    event
}

/// Interpret a function's response payload as a `Proxy_Response_V2`, or wrap a non-structured
/// return as `200 application/json`.
pub fn interpret_v2_response(payload: &[u8]) -> UrlHttpResponse {
    let parsed: Option<Value> = serde_json::from_slice(payload).ok();
    match &parsed {
        Some(Value::Object(obj)) if obj.contains_key("statusCode") => structured(obj),
        _ => UrlHttpResponse {
            // Non-structured return: the whole payload becomes a 200 JSON body.
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: payload.to_vec(),
        },
    }
}

fn structured(obj: &Map<String, Value>) -> UrlHttpResponse {
    let status = obj.get("statusCode").and_then(Value::as_u64).unwrap_or(200) as u16;
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(map) = obj.get("headers").and_then(Value::as_object) {
        for (k, v) in map {
            if let Some(s) = scalar(v) {
                headers.push((k.clone(), s));
            }
        }
    }
    if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        headers.push(("content-type".into(), "application/json".into()));
    }
    if let Some(cookies) = obj.get("cookies").and_then(Value::as_array) {
        for c in cookies.iter().filter_map(Value::as_str) {
            headers.push(("set-cookie".into(), c.to_string()));
        }
    }
    let is_base64 = obj
        .get("isBase64Encoded")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let body = match obj.get("body").and_then(Value::as_str) {
        Some(s) if is_base64 => b64().decode(s).unwrap_or_default(),
        Some(s) => s.as_bytes().to_vec(),
        None => Vec::new(),
    };
    UrlHttpResponse {
        status,
        headers,
        body,
    }
}

/// The HTTP response for a function-error outcome on a Function URL (AWS returns 502).
pub fn error_response() -> UrlHttpResponse {
    UrlHttpResponse {
        status: 502,
        headers: vec![("content-type".into(), "application/json".into())],
        body: b"{\"message\":\"Internal Server Error\"}".to_vec(),
    }
}

fn encode_body(body: &[u8]) -> (Option<String>, bool) {
    if body.is_empty() {
        return (None, false);
    }
    match std::str::from_utf8(body) {
        Ok(s) => (Some(s.to_string()), false),
        Err(_) => (Some(b64().encode(body)), true),
    }
}

fn parse_query(raw: &str) -> Map<String, Value> {
    let mut out: Map<String, Value> = Map::new();
    for pair in raw.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        // Repeated keys are comma-joined, matching API Gateway v2.
        match out.get_mut(k) {
            Some(Value::String(existing)) => *existing = format!("{existing},{v}"),
            _ => {
                out.insert(k.to_string(), Value::String(v.to_string()));
            }
        }
    }
    out
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> UrlRequest {
        UrlRequest {
            method: "POST".into(),
            raw_path: "/items".into(),
            raw_query: "a=1&b=2".into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Cookie".into(), "s=1; t=2".into()),
                ("User-Agent".into(), "curl".into()),
            ],
            body: b"{\"x\":1}".to_vec(),
            url_id: "abc123".into(),
            region: "us-east-1".into(),
            account: "000000000000".into(),
            request_id: "rid".into(),
        }
    }

    #[test]
    fn builds_v2_event() {
        let e = build_v2_event(&req());
        assert_eq!(e["version"], "2.0");
        assert_eq!(e["routeKey"], "$default");
        assert_eq!(e["rawPath"], "/items");
        assert_eq!(e["rawQueryString"], "a=1&b=2");
        assert_eq!(e["requestContext"]["http"]["method"], "POST");
        assert_eq!(
            e["requestContext"]["domainName"],
            "abc123.lambda-url.us-east-1.on.aws"
        );
        assert_eq!(e["headers"]["content-type"], "application/json");
        // Cookie header is split into the cookies array, not the headers map.
        assert!(e["headers"].get("cookie").is_none());
        assert_eq!(e["cookies"][0], "s=1");
        assert_eq!(e["cookies"][1], "t=2");
        assert_eq!(e["queryStringParameters"]["a"], "1");
        assert_eq!(e["body"], "{\"x\":1}");
        assert_eq!(e["isBase64Encoded"], false);
    }

    #[test]
    fn binary_body_is_base64() {
        let mut r = req();
        r.body = vec![0xff, 0xfe];
        let e = build_v2_event(&r);
        assert_eq!(e["isBase64Encoded"], true);
        assert_eq!(e["body"], b64().encode([0xff, 0xfe]));
    }

    #[test]
    fn interprets_structured_response() {
        let payload =
            br#"{"statusCode":201,"headers":{"x-custom":"v"},"cookies":["a=1"],"body":"created"}"#;
        let r = interpret_v2_response(payload);
        assert_eq!(r.status, 201);
        assert!(r.headers.iter().any(|(k, v)| k == "x-custom" && v == "v"));
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "set-cookie" && v == "a=1"));
        assert_eq!(r.body, b"created");
    }

    #[test]
    fn interprets_base64_body() {
        let encoded = b64().encode([1u8, 2, 3]);
        let payload = format!(r#"{{"statusCode":200,"isBase64Encoded":true,"body":"{encoded}"}}"#);
        let r = interpret_v2_response(payload.as_bytes());
        assert_eq!(r.body, vec![1, 2, 3]);
    }

    #[test]
    fn wraps_non_structured_return() {
        let payload = br#"{"result":42}"#;
        let r = interpret_v2_response(payload);
        assert_eq!(r.status, 200);
        assert_eq!(r.body, payload);
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "application/json"));
    }
}
