//! AWS_PROXY payload construction and Lambda response interpretation for HTTP APIs, faithful
//! to the documented `2.0` and `1.0` payload formats. These are pure functions so they are
//! unit-tested directly; the execute path wires them to the real Lambda `Invoke` dispatch.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{json, Map, Value};
use time::OffsetDateTime;

/// Everything the payload builders need from the incoming invoke request.
pub struct EventInput<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub stage: &'a str,
    pub raw_path: &'a str,
    pub resource_path: &'a str,
    pub raw_query: &'a str,
    pub route_key: &'a str,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
    pub account: &'a str,
    pub api_id: &'a str,
    pub request_id: &'a str,
    /// `(claims, scopes)` from a JWT authorizer, when the route is JWT-protected.
    pub jwt: Option<(Value, Vec<String>)>,
}

/// A normalised proxy response ready to render as an HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Encode the request body as `(body_string, is_base64)` — UTF-8 verbatim, else base64.
fn encode_body(body: &[u8]) -> (String, bool) {
    match std::str::from_utf8(body) {
        Ok(s) => (s.to_string(), false),
        Err(_) => (BASE64.encode(body), true),
    }
}

fn header_maps(headers: &HeaderMap) -> (Map<String, Value>, Map<String, Value>) {
    let mut single = Map::new();
    let mut multi = Map::new();
    for name in headers.keys() {
        let key = name.as_str().to_ascii_lowercase();
        let values: Vec<Value> = headers
            .get_all(name)
            .iter()
            .map(|value| Value::String(String::from_utf8_lossy(value.as_bytes()).into_owned()))
            .collect();
        if let Some(last) = values.last() {
            single.insert(key.clone(), last.clone());
            multi.insert(key, Value::Array(values));
        }
    }
    (single, multi)
}

fn joined_headers(headers: &HeaderMap) -> Map<String, Value> {
    let (_, multi) = header_maps(headers);
    multi
        .into_iter()
        .filter(|(name, _)| name != "cookie")
        .map(|(name, values)| {
            let joined = values
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",");
            (name, Value::String(joined))
        })
        .collect()
}

pub(crate) fn percent_decode(value: &str) -> String {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                    decoded.push((high << 4) | low);
                    index += 3;
                } else {
                    decoded.push(b'%');
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn query_maps(raw_query: &str) -> (Map<String, Value>, Map<String, Value>) {
    let mut single = Map::new();
    let mut multi: Map<String, Value> = Map::new();
    for pair in raw_query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key);
        let value = percent_decode(value);
        if key.is_empty() {
            continue;
        }
        single.insert(key.clone(), Value::String(value.clone()));
        multi
            .entry(key)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .expect("query multi-value entry is an array")
            .push(Value::String(value));
    }
    (single, multi)
}

fn joined_query(raw_query: &str) -> Map<String, Value> {
    let (_, multi) = query_maps(raw_query);
    multi
        .into_iter()
        .map(|(key, values)| {
            let joined = values
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",");
            (key, Value::String(joined))
        })
        .collect()
}

fn cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn path_parameters(input: &EventInput<'_>) -> Value {
    let route_path = input
        .route_key
        .split_once(' ')
        .map(|(_, path)| path)
        .filter(|path| path.contains('{'))
        .unwrap_or(input.resource_path);
    let stage_root = format!("/{}", input.stage);
    let stage_prefix = format!("{stage_root}/");
    let actual_path = if input.stage == "$default" {
        input.raw_path
    } else if input.raw_path == stage_root {
        "/"
    } else {
        input
            .raw_path
            .strip_prefix(&stage_prefix)
            .unwrap_or(input.raw_path)
    };
    let template: Vec<&str> = route_path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let actual: Vec<&str> = actual_path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let mut params = Map::new();
    for (actual_index, part) in template.into_iter().enumerate() {
        if let Some(name) = part
            .strip_prefix('{')
            .and_then(|part| part.strip_suffix("+}"))
        {
            let remainder = actual.get(actual_index..).unwrap_or_default().join("/");
            params.insert(name.to_string(), Value::String(remainder));
            break;
        }
        if let Some(name) = part
            .strip_prefix('{')
            .and_then(|part| part.strip_suffix('}'))
        {
            if let Some(value) = actual.get(actual_index) {
                params.insert(name.to_string(), Value::String((*value).to_string()));
            }
        }
    }
    if params.is_empty() {
        Value::Null
    } else {
        Value::Object(params)
    }
}

fn authorizer_context(jwt: &Option<(Value, Vec<String>)>) -> Option<Value> {
    jwt.as_ref()
        .map(|(claims, scopes)| json!({ "jwt": { "claims": claims, "scopes": scopes } }))
}

fn request_time() -> (String, i128) {
    let now = OffsetDateTime::now_utc();
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][now.month() as usize - 1];
    let formatted = format!(
        "{:02}/{}/{:04}:{:02}:{:02}:{:02} +0000",
        now.day(),
        month,
        now.year(),
        now.hour(),
        now.minute(),
        now.second()
    );
    (formatted, now.unix_timestamp_nanos() / 1_000_000)
}

/// Build the proxy event for the integration's payload format (`2.0` default, or `1.0`).
pub fn build_event(format: &str, input: &EventInput) -> Value {
    if format == "1.0" {
        build_v1(input)
    } else {
        build_v2(input)
    }
}

fn build_v2(input: &EventInput) -> Value {
    let (body, is_b64) = encode_body(input.body);
    let query = joined_query(input.raw_query);
    let (time, time_epoch) = request_time();
    let mut request_context = json!({
        "accountId": input.account,
        "apiId": input.api_id,
        "domainName": input.host,
        "http": {
            "method": input.method,
            "path": input.raw_path,
            "protocol": "HTTP/1.1",
            "sourceIp": source_ip(input.headers),
            "userAgent": header_str(input.headers, "user-agent"),
        },
        "requestId": input.request_id,
        "routeKey": input.route_key,
        "stage": input.stage,
        "time": time,
        "timeEpoch": time_epoch,
    });
    if let Some(authorizer) = authorizer_context(&input.jwt) {
        request_context["authorizer"] = authorizer;
    }
    let mut event = json!({
        "version": "2.0",
        "routeKey": input.route_key,
        "rawPath": input.raw_path,
        "rawQueryString": input.raw_query,
        "cookies": cookies(input.headers),
        "headers": joined_headers(input.headers),
        "pathParameters": path_parameters(input),
        "requestContext": request_context,
        "body": if input.body.is_empty() { Value::Null } else { Value::String(body) },
        "isBase64Encoded": is_b64,
    });
    if !query.is_empty() {
        event["queryStringParameters"] = Value::Object(query);
    }
    event
}

fn build_v1(input: &EventInput) -> Value {
    let (body, is_b64) = encode_body(input.body);
    let (single_headers, multi_headers) = header_maps(input.headers);
    let (single_query, multi_query) = query_maps(input.raw_query);
    let (_, request_time_epoch) = request_time();
    let mut request_context = json!({
        "accountId": input.account,
        "apiId": input.api_id,
        "resourceId": input.resource_path,
        "resourcePath": input.resource_path,
        "httpMethod": input.method,
        "path": input.raw_path,
        "protocol": "HTTP/1.1",
        "stage": input.stage,
        "requestId": input.request_id,
        "requestTimeEpoch": request_time_epoch,
        "identity": {
            "sourceIp": source_ip(input.headers),
        },
    });
    if let Some(authorizer) = authorizer_context(&input.jwt) {
        request_context["authorizer"] = authorizer;
    }
    json!({
        "version": "1.0",
        "resource": input.resource_path,
        "path": input.raw_path,
        "httpMethod": input.method,
        "headers": object_or_null(single_headers),
        "multiValueHeaders": object_or_null(multi_headers),
        "queryStringParameters": object_or_null(single_query),
        "multiValueQueryStringParameters": object_or_null(multi_query),
        "pathParameters": path_parameters(input),
        "stageVariables": Value::Null,
        "requestContext": request_context,
        "body": if input.body.is_empty() { Value::Null } else { Value::String(body) },
        "isBase64Encoded": is_b64,
    })
}

fn object_or_null(map: Map<String, Value>) -> Value {
    if map.is_empty() {
        Value::Null
    } else {
        Value::Object(map)
    }
}

fn header_str(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn source_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Interpret a Lambda function result as an HTTP API response.
///
/// A valid structured response is honoured even when Lambda reports `Function_Error`. Otherwise,
/// invalid JSON, malformed structured fields, invalid base64, or an unstructured 1.0 response
/// become an AWS-shaped 502. Payload 2.0 auto-wraps valid non-structured JSON as a 200 response.
pub fn interpret_response(format: &str, function_error: bool, output: &[u8]) -> ProxyResponse {
    let parsed: Value = match serde_json::from_slice(output) {
        Ok(value) => value,
        Err(_) => return error_response(502),
    };
    let structured = parsed.get("statusCode").is_some()
        || parsed.get("headers").is_some()
        || parsed.get("multiValueHeaders").is_some()
        || parsed.get("cookies").is_some()
        || parsed.get("body").is_some()
        || parsed.get("isBase64Encoded").is_some();
    if structured {
        return structured_response(format, &parsed).unwrap_or_else(|| error_response(502));
    }
    if function_error || format == "1.0" {
        return error_response(502);
    }
    ProxyResponse {
        status: 200,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: parsed.to_string().into_bytes(),
    }
}

fn structured_response(format: &str, value: &Value) -> Option<ProxyResponse> {
    let object = value.as_object()?;
    let status = match object.get("statusCode") {
        Some(value) => value.as_u64()?,
        None => 200,
    };
    if !(100..=599).contains(&status) {
        return None;
    }

    let mut headers = Vec::new();
    if let Some(value) = object.get("headers") {
        for (name, value) in value.as_object()? {
            push_header(&mut headers, name, value.as_str()?)?;
        }
    }
    if format == "1.0" {
        if let Some(value) = object.get("multiValueHeaders") {
            for (name, values) in value.as_object()? {
                for value in values.as_array()? {
                    push_header(&mut headers, name, value.as_str()?)?;
                }
            }
        }
    }
    if let Some(value) = object.get("cookies") {
        if format == "1.0" {
            return None;
        }
        for cookie in value.as_array()? {
            push_header(&mut headers, "set-cookie", cookie.as_str()?)?;
        }
    }

    let raw_body = match object.get("body") {
        Some(Value::String(body)) => body.as_str(),
        Some(_) => return None,
        None => "",
    };
    let is_base64 = match object.get("isBase64Encoded") {
        Some(value) => value.as_bool()?,
        None => false,
    };
    let body = if is_base64 {
        BASE64.decode(raw_body).ok()?
    } else {
        raw_body.as_bytes().to_vec()
    };
    Some(ProxyResponse {
        status: status as u16,
        headers,
        body,
    })
}

fn push_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) -> Option<()> {
    HeaderName::from_bytes(name.as_bytes()).ok()?;
    HeaderValue::from_str(value).ok()?;
    headers.push((name.to_string(), value.to_string()));
    Some(())
}

fn error_response(status: u16) -> ProxyResponse {
    ProxyResponse {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: json!({ "message": "Internal server error" })
            .to_string()
            .into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn input<'a>(
        h: &'a HeaderMap,
        body: &'a [u8],
        jwt: Option<(Value, Vec<String>)>,
    ) -> EventInput<'a> {
        EventInput {
            method: "GET",
            host: "abc.execute-api.us-east-1.amazonaws.com",
            stage: "prod",
            raw_path: "/prod/items",
            resource_path: "/items",
            raw_query: "a=1&b=2",
            route_key: "GET /items",
            headers: h,
            body,
            account: "000000000000",
            api_id: "abc",
            request_id: "rid",
            jwt,
        }
    }

    #[test]
    fn v2_event_shape_and_authorizer() {
        let h = headers(&[("user-agent", "curl/8"), ("cookie", "a=1; b=2")]);
        let claims = json!({ "sub": "u1" });
        let ev = build_event(
            "2.0",
            &input(&h, b"hi", Some((claims.clone(), vec!["read".into()]))),
        );
        assert_eq!(ev["version"], "2.0");
        assert_eq!(ev["routeKey"], "GET /items");
        assert_eq!(ev["rawQueryString"], "a=1&b=2");
        assert_eq!(ev["queryStringParameters"]["a"], "1");
        assert_eq!(ev["cookies"], json!(["a=1", "b=2"]));
        assert_eq!(ev["requestContext"]["http"]["method"], "GET");
        assert_eq!(ev["requestContext"]["authorizer"]["jwt"]["claims"], claims);
        assert_eq!(ev["body"], "hi");
        assert_eq!(ev["isBase64Encoded"], false);
    }

    #[test]
    fn v1_event_shape() {
        let h = headers(&[]);
        let ev = build_event("1.0", &input(&h, b"x", None));
        assert_eq!(ev["version"], "1.0");
        assert_eq!(ev["resource"], "/items");
        assert_eq!(ev["httpMethod"], "GET");
        assert!(ev["requestContext"].get("authorizer").is_none());
    }

    #[test]
    fn binary_body_is_base64() {
        let h = headers(&[]);
        let ev = build_event("2.0", &input(&h, &[0xff, 0xfe], None));
        assert_eq!(ev["isBase64Encoded"], true);
        assert_eq!(ev["body"], BASE64.encode([0xff, 0xfe]));
    }

    #[test]
    fn v1_event_has_last_and_all_values_and_complete_context() {
        let h = headers(&[
            ("x-test", "first"),
            ("x-test", "last"),
            ("x-forwarded-for", "192.0.2.1, 10.0.0.1"),
        ]);
        let mut request = input(&h, b"", None);
        request.raw_path = "/prod/items/42/a/b";
        request.resource_path = "/items/{id}/{proxy+}";
        request.route_key = "GET /items/{id}/{proxy+}";
        request.raw_query = "tag=one&tag=two&empty=";
        let event = build_event("1.0", &request);

        assert_eq!(event["headers"]["x-test"], "last");
        assert_eq!(
            event["multiValueHeaders"]["x-test"],
            json!(["first", "last"])
        );
        assert_eq!(event["queryStringParameters"]["tag"], "two");
        assert_eq!(
            event["multiValueQueryStringParameters"]["tag"],
            json!(["one", "two"])
        );
        assert_eq!(
            event["pathParameters"],
            json!({ "id": "42", "proxy": "a/b" })
        );
        assert!(event["stageVariables"].is_null());
        assert!(event["body"].is_null());
        assert_eq!(event["isBase64Encoded"], false);
        assert_eq!(
            event["requestContext"]["resourcePath"],
            request.resource_path
        );
        assert_eq!(event["requestContext"]["path"], request.raw_path);
        assert_eq!(event["requestContext"]["protocol"], "HTTP/1.1");
        assert_eq!(event["requestContext"]["identity"]["sourceIp"], "192.0.2.1");
        assert!(event["requestContext"]["requestTimeEpoch"]
            .as_i64()
            .is_some());
    }

    #[test]
    fn v2_joins_values_removes_cookie_and_omits_empty_query() {
        let h = headers(&[
            ("x-test", "first"),
            ("x-test", "last"),
            ("cookie", "a=1; b=2"),
            ("cookie", "c=3"),
        ]);
        let mut request = input(&h, b"", None);
        request.raw_query = "";
        let event = build_event("2.0", &request);

        assert_eq!(event["headers"]["x-test"], "first,last");
        assert!(event["headers"].get("cookie").is_none());
        assert_eq!(event["cookies"], json!(["a=1", "b=2", "c=3"]));
        assert!(event.get("queryStringParameters").is_none());
        assert_eq!(event["rawQueryString"], "");
        assert!(event["body"].is_null());
        assert!(event["requestContext"]["time"].as_str().is_some());
        assert!(event["requestContext"]["timeEpoch"].as_i64().is_some());
    }

    #[test]
    fn v2_joins_repeated_query_values_and_binds_path_parameters() {
        let h = headers(&[]);
        let mut request = input(&h, b"x", None);
        request.raw_path = "/prod/items/42";
        request.resource_path = "/items/{id}";
        request.route_key = "GET /items/{id}";
        request.raw_query = "tag=one&tag=two";
        let event = build_event("2.0", &request);

        assert_eq!(event["queryStringParameters"]["tag"], "one,two");
        assert_eq!(event["pathParameters"], json!({ "id": "42" }));
    }

    #[test]
    fn structured_2_0_response() {
        let out = json!({ "statusCode": 201, "headers": { "x-a": "b" }, "cookies": ["c=1"], "body": "ok" });
        let r = interpret_response("2.0", false, out.to_string().as_bytes());
        assert_eq!(r.status, 201);
        assert!(r.headers.contains(&("x-a".to_string(), "b".to_string())));
        assert!(r
            .headers
            .contains(&("set-cookie".to_string(), "c=1".to_string())));
        assert_eq!(r.body, b"ok");
    }

    #[test]
    fn unstructured_2_0_is_wrapped_200() {
        let r = interpret_response("2.0", false, br#"{"hello":"world"}"#);
        assert_eq!(r.status, 200);
        assert_eq!(r.body, br#"{"hello":"world"}"#);
    }

    #[test]
    fn unstructured_1_0_is_502() {
        let r = interpret_response("1.0", false, br#"{"hello":"world"}"#);
        assert_eq!(r.status, 502);
    }

    #[test]
    fn function_error_without_valid_proxy_response_is_502() {
        let r = interpret_response("2.0", true, b"{}");
        assert_eq!(r.status, 502);
        assert_eq!(r.body, br#"{"message":"Internal server error"}"#);
    }

    #[test]
    fn function_error_with_valid_proxy_response_is_honoured() {
        let out = json!({ "statusCode": 418, "body": "handled" });
        let r = interpret_response("1.0", true, out.to_string().as_bytes());
        assert_eq!(r.status, 418);
        assert_eq!(r.body, b"handled");
    }

    #[test]
    fn v1_response_combines_single_and_multi_value_headers() {
        let out = json!({
            "statusCode": 200,
            "headers": { "x-one": "single" },
            "multiValueHeaders": { "x-many": ["first", "second"] },
            "body": "ok"
        });
        let response = interpret_response("1.0", false, out.to_string().as_bytes());
        assert_eq!(response.status, 200);
        assert!(response
            .headers
            .contains(&("x-one".into(), "single".into())));
        assert!(response
            .headers
            .contains(&("x-many".into(), "first".into())));
        assert!(response
            .headers
            .contains(&("x-many".into(), "second".into())));
    }

    #[test]
    fn malformed_structured_responses_are_502() {
        for output in [
            json!({ "statusCode": "200", "body": "ok" }),
            json!({ "statusCode": 700, "body": "ok" }),
            json!({ "statusCode": 200, "headers": { "x-test": 1 } }),
            json!({ "statusCode": 200, "body": {}, "isBase64Encoded": false }),
            json!({ "statusCode": 200, "body": "%%%", "isBase64Encoded": true }),
            json!({ "statusCode": 200, "cookies": [1] }),
        ] {
            assert_eq!(
                interpret_response("2.0", false, output.to_string().as_bytes()).status,
                502,
                "output should be malformed: {output}"
            );
        }
    }

    #[test]
    fn invalid_json_is_502() {
        let r = interpret_response("2.0", false, b"not json");
        assert_eq!(r.status, 502);
    }

    #[test]
    fn base64_response_body_is_decoded() {
        let out =
            json!({ "statusCode": 200, "body": BASE64.encode([1, 2, 3]), "isBase64Encoded": true });
        let r = interpret_response("2.0", false, out.to_string().as_bytes());
        assert_eq!(r.body, vec![1, 2, 3]);
    }
}
