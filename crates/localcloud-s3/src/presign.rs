//! SigV4 query and browser POST validation for S3.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};
use localcloud_core::handler::ServiceRequest;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::error::S3Error;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const MAX_EXPIRES: i64 = 604_800;

pub struct PostUpload {
    pub key: String,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub status: u16,
}

#[derive(Debug)]
struct Scope {
    access_key: String,
    date: String,
    region: String,
    service: String,
    terminal: String,
}

#[derive(Debug)]
struct Part {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    body: Bytes,
}

pub fn is_presigned_url(req: &ServiceRequest) -> bool {
    raw_query_pairs(req.uri.query().unwrap_or_default())
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(b"X-Amz-Signature"))
}
pub fn validate_url(req: &ServiceRequest) -> Result<(), S3Error> {
    let pairs = raw_query_pairs(req.uri.query().unwrap_or_default());
    let required = |name: &str| -> Result<String, S3Error> {
        query_value(&pairs, name)
            .ok_or(S3Error::AccessDenied)
            .and_then(|value| String::from_utf8(value).map_err(|_| S3Error::AccessDenied))
    };
    if required("X-Amz-Algorithm")? != ALGORITHM {
        return Err(S3Error::AccessDenied);
    }
    let credential = required("X-Amz-Credential")?;
    let scope = parse_scope(&credential)?;
    if scope.service != "s3" || scope.terminal != "aws4_request" {
        return Err(S3Error::AccessDenied);
    }
    let date = required("X-Amz-Date")?;
    if !date.starts_with(&scope.date) {
        return Err(S3Error::AccessDenied);
    }
    let expires = required("X-Amz-Expires")?
        .parse::<i64>()
        .map_err(|_| S3Error::AuthorizationQueryParametersError)?;
    if !(1..=MAX_EXPIRES).contains(&expires) {
        return Err(S3Error::AuthorizationQueryParametersError);
    }
    let signed_at = parse_amz_date(&date)?;
    let now = OffsetDateTime::now_utc();
    if now > signed_at + time::Duration::seconds(expires) {
        return Err(S3Error::AccessDenied);
    }
    if signed_at - now > time::Duration::minutes(15) {
        return Err(S3Error::AccessDenied);
    }

    let signed_headers = required("X-Amz-SignedHeaders")?;
    let canonical_headers = canonical_headers(&req.headers, &signed_headers)?;
    let canonical_query = canonical_query(&pairs);
    let payload_hash = req
        .headers
        .get("x-amz-content-sha256")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("UNSIGNED-PAYLOAD");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method.as_str(),
        canonical_uri(req.uri.path()),
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash
    );
    let credential_scope = format!(
        "{}/{}/{}/{}",
        scope.date, scope.region, scope.service, scope.terminal
    );
    let string_to_sign = format!(
        "{ALGORITHM}\n{date}\n{credential_scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let secret = resolve_secret(&scope.access_key).ok_or(S3Error::AccessDenied)?;
    let expected = hex(&hmac_sha256(
        &signing_key(&secret, &scope.date, &scope.region, &scope.service),
        string_to_sign.as_bytes(),
    ));
    let supplied = required("X-Amz-Signature")?;
    if !constant_time_eq(expected.as_bytes(), supplied.as_bytes()) {
        return Err(S3Error::AccessDenied);
    }
    Ok(())
}

pub fn parse_post(req: &ServiceRequest, bucket: &str) -> Result<PostUpload, S3Error> {
    let content_type = req
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .ok_or(S3Error::AccessDenied)?;
    let boundary = multipart_boundary(content_type).ok_or(S3Error::AccessDenied)?;
    let parts = parse_multipart(&req.body, &boundary)?;
    validate_post(parts, bucket)
}
fn validate_post(parts: Vec<Part>, bucket: &str) -> Result<PostUpload, S3Error> {
    let mut fields = BTreeMap::new();
    let mut file = None;
    for part in parts {
        if part.name.eq_ignore_ascii_case("file") {
            if file.replace(part).is_some() {
                return Err(S3Error::AccessDenied);
            }
        } else {
            let value = String::from_utf8(part.body.to_vec()).map_err(|_| S3Error::AccessDenied)?;
            if fields.insert(part.name, value).is_some() {
                return Err(S3Error::AccessDenied);
            }
        }
    }
    let file = file.ok_or(S3Error::AccessDenied)?;
    let policy_b64 = field(&fields, "policy").ok_or(S3Error::AccessDenied)?;
    let policy_bytes = base64::engine::general_purpose::STANDARD
        .decode(policy_b64)
        .map_err(|_| S3Error::AccessDenied)?;
    let policy: Value = serde_json::from_slice(&policy_bytes).map_err(|_| S3Error::AccessDenied)?;
    let expiration = policy
        .get("expiration")
        .and_then(Value::as_str)
        .ok_or(S3Error::AccessDenied)?;
    let expiration =
        OffsetDateTime::parse(expiration, &Rfc3339).map_err(|_| S3Error::AccessDenied)?;
    if OffsetDateTime::now_utc() > expiration {
        return Err(S3Error::AccessDenied);
    }

    let algorithm = field(&fields, "x-amz-algorithm").ok_or(S3Error::AccessDenied)?;
    if algorithm != ALGORITHM {
        return Err(S3Error::AccessDenied);
    }
    let credential = field(&fields, "x-amz-credential").ok_or(S3Error::AccessDenied)?;
    let scope = parse_scope(credential)?;
    if scope.service != "s3" || scope.terminal != "aws4_request" {
        return Err(S3Error::AccessDenied);
    }
    let date = field(&fields, "x-amz-date").ok_or(S3Error::AccessDenied)?;
    if !date.starts_with(&scope.date) {
        return Err(S3Error::AccessDenied);
    }
    let secret = resolve_secret(&scope.access_key).ok_or(S3Error::AccessDenied)?;
    let expected = hex(&hmac_sha256(
        &signing_key(&secret, &scope.date, &scope.region, &scope.service),
        policy_b64.as_bytes(),
    ));
    let supplied = field(&fields, "x-amz-signature").ok_or(S3Error::AccessDenied)?;
    if !constant_time_eq(expected.as_bytes(), supplied.as_bytes()) {
        return Err(S3Error::AccessDenied);
    }

    let conditions = policy
        .get("conditions")
        .and_then(Value::as_array)
        .ok_or(S3Error::AccessDenied)?;
    for condition in conditions {
        validate_condition(condition, &fields, bucket, file.body.len())?;
    }

    let filename = file
        .filename
        .as_deref()
        .unwrap_or_default()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default();
    let key = field(&fields, "key")
        .ok_or(S3Error::AccessDenied)?
        .replace("${filename}", filename);
    let mut headers = HeaderMap::new();
    let object_content_type = field(&fields, "content-type")
        .map(str::to_string)
        .or(file.content_type)
        .unwrap_or_else(|| "binary/octet-stream".to_string());
    headers.insert(
        "content-type",
        HeaderValue::from_str(&object_content_type).map_err(|_| S3Error::AccessDenied)?,
    );
    copy_form_headers(&fields, &mut headers)?;
    let status = field(&fields, "success_action_status")
        .unwrap_or("204")
        .parse::<u16>()
        .map_err(|_| S3Error::AccessDenied)?;
    if !matches!(status, 200 | 201 | 204) {
        return Err(S3Error::AccessDenied);
    }
    Ok(PostUpload {
        key,
        headers,
        body: file.body,
        status,
    })
}
fn validate_condition(
    condition: &Value,
    fields: &BTreeMap<String, String>,
    bucket: &str,
    content_length: usize,
) -> Result<(), S3Error> {
    if let Some(object) = condition.as_object() {
        for (name, expected) in object {
            let expected = expected.as_str().ok_or(S3Error::AccessDenied)?;
            let actual = if name.eq_ignore_ascii_case("bucket") {
                Some(bucket)
            } else {
                field(fields, name)
            };
            if actual != Some(expected) {
                return Err(S3Error::AccessDenied);
            }
        }
        return Ok(());
    }
    let values = condition.as_array().ok_or(S3Error::AccessDenied)?;
    let operation = values
        .first()
        .and_then(Value::as_str)
        .ok_or(S3Error::AccessDenied)?;
    if operation.eq_ignore_ascii_case("content-length-range") {
        let min = values
            .get(1)
            .and_then(Value::as_u64)
            .ok_or(S3Error::AccessDenied)?;
        let max = values
            .get(2)
            .and_then(Value::as_u64)
            .ok_or(S3Error::AccessDenied)?;
        let length = u64::try_from(content_length).map_err(|_| S3Error::AccessDenied)?;
        return if (min..=max).contains(&length) {
            Ok(())
        } else {
            Err(S3Error::AccessDenied)
        };
    }
    let variable = values
        .get(1)
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix('$'))
        .ok_or(S3Error::AccessDenied)?;
    let expected = values
        .get(2)
        .and_then(Value::as_str)
        .ok_or(S3Error::AccessDenied)?;
    let actual = field(fields, variable).unwrap_or_default();
    let valid = match operation.to_ascii_lowercase().as_str() {
        "eq" => actual == expected,
        "starts-with" => actual.starts_with(expected),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(S3Error::AccessDenied)
    }
}

fn copy_form_headers(
    fields: &BTreeMap<String, String>,
    headers: &mut HeaderMap,
) -> Result<(), S3Error> {
    for (name, value) in fields {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("x-amz-meta-") || lower == "x-amz-tagging" {
            let name =
                HeaderName::from_bytes(lower.as_bytes()).map_err(|_| S3Error::AccessDenied)?;
            let value = HeaderValue::from_str(value).map_err(|_| S3Error::AccessDenied)?;
            headers.insert(name, value);
        }
    }
    Ok(())
}

fn field<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn multipart_boundary(content_type: &str) -> Option<Vec<u8>> {
    if !content_type
        .split(';')
        .next()?
        .trim()
        .eq_ignore_ascii_case("multipart/form-data")
    {
        return None;
    }
    content_type
        .split(';')
        .skip(1)
        .find_map(|parameter| {
            let (name, value) = parameter.trim().split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("boundary")
                .then(|| value.trim().trim_matches('"').as_bytes().to_vec())
        })
        .filter(|boundary| !boundary.is_empty() && boundary.len() <= 70)
}
fn parse_multipart(body: &[u8], boundary: &[u8]) -> Result<Vec<Part>, S3Error> {
    let mut delimiter = b"--".to_vec();
    delimiter.extend_from_slice(boundary);
    if !body.starts_with(&delimiter) {
        return Err(S3Error::AccessDenied);
    }
    let mut cursor = delimiter.len();
    let mut parts = Vec::new();
    loop {
        if body.get(cursor..cursor + 2) == Some(b"--") {
            cursor += 2;
            if body
                .get(cursor..)
                .is_some_and(|tail| tail.is_empty() || tail == b"\r\n")
            {
                return Ok(parts);
            }
            return Err(S3Error::AccessDenied);
        }
        if body.get(cursor..cursor + 2) != Some(b"\r\n") {
            return Err(S3Error::AccessDenied);
        }
        cursor += 2;
        let headers_end = find_bytes(body, b"\r\n\r\n", cursor).ok_or(S3Error::AccessDenied)?;
        let headers = parse_part_headers(&body[cursor..headers_end])?;
        let data_start = headers_end + 4;
        let mut marker = b"\r\n".to_vec();
        marker.extend_from_slice(&delimiter);
        let data_end = find_bytes(body, &marker, data_start).ok_or(S3Error::AccessDenied)?;
        let disposition = headers
            .get("content-disposition")
            .ok_or(S3Error::AccessDenied)?;
        let (name, filename) = parse_disposition(disposition)?;
        parts.push(Part {
            name,
            filename,
            content_type: headers.get("content-type").cloned(),
            body: Bytes::copy_from_slice(&body[data_start..data_end]),
        });
        cursor = data_end + marker.len();
    }
}

fn parse_part_headers(bytes: &[u8]) -> Result<BTreeMap<String, String>, S3Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| S3Error::AccessDenied)?;
    let mut headers = BTreeMap::new();
    for line in text.split("\r\n") {
        let (name, value) = line.split_once(':').ok_or(S3Error::AccessDenied)?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || headers.insert(name, value.trim().to_string()).is_some() {
            return Err(S3Error::AccessDenied);
        }
    }
    Ok(headers)
}

fn parse_disposition(value: &str) -> Result<(String, Option<String>), S3Error> {
    let mut segments = value.split(';');
    if !segments
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("form-data"))
    {
        return Err(S3Error::AccessDenied);
    }
    let mut name = None;
    let mut filename = None;
    for segment in segments {
        let (key, value) = segment
            .trim()
            .split_once('=')
            .ok_or(S3Error::AccessDenied)?;
        let value = value
            .trim()
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .ok_or(S3Error::AccessDenied)?;
        if key.eq_ignore_ascii_case("name") {
            name = Some(value.to_string());
        } else if key.eq_ignore_ascii_case("filename") {
            filename = Some(value.to_string());
        }
    }
    Ok((name.ok_or(S3Error::AccessDenied)?, filename))
}

fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| start + position)
}
fn raw_query_pairs(query: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (
                percent_decode(name.as_bytes()),
                percent_decode(value.as_bytes()),
            )
        })
        .collect()
}

fn query_value(pairs: &[(Vec<u8>, Vec<u8>)], name: &str) -> Option<Vec<u8>> {
    let mut values = pairs
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, value)| value.clone());
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn canonical_query(pairs: &[(Vec<u8>, Vec<u8>)]) -> String {
    let mut encoded: Vec<(String, String)> = pairs
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case(b"X-Amz-Signature"))
        .map(|(name, value)| (uri_encode(name, false), uri_encode(value, false)))
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn canonical_uri(path: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    uri_encode(&percent_decode(path.as_bytes()), true)
}

fn canonical_headers(headers: &HeaderMap, signed: &str) -> Result<String, S3Error> {
    let names: Vec<&str> = signed.split(';').collect();
    if names.is_empty()
        || names.iter().any(|name| {
            name.is_empty()
                || *name != name.to_ascii_lowercase()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        })
        || names.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(S3Error::AccessDenied);
    }
    let mut canonical = String::new();
    for name in names {
        let values = headers.get_all(name);
        let mut found = false;
        let mut joined = String::new();
        for value in values {
            let value = value.to_str().map_err(|_| S3Error::AccessDenied)?;
            if found {
                joined.push(',');
            }
            joined.push_str(&collapse_whitespace(value));
            found = true;
        }
        if !found {
            return Err(S3Error::AccessDenied);
        }
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(&joined);
        canonical.push('\n');
    }
    Ok(canonical)
}

fn collapse_whitespace(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

fn percent_decode(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'%' && index + 2 < value.len() {
            if let (Some(high), Some(low)) =
                (hex_digit(value[index + 1]), hex_digit(value[index + 2]))
            {
                output.push(high << 4 | low);
                index += 3;
                continue;
            }
        }
        output.push(value[index]);
        index += 1;
    }
    output
}
pub(crate) fn uri_encode(value: &[u8], preserve_slash: bool) -> String {
    let mut output = String::with_capacity(value.len());
    for &byte in value {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || preserve_slash && byte == b'/'
        {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn parse_scope(credential: &str) -> Result<Scope, S3Error> {
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5
        || parts[0].is_empty()
        || parts[1].len() != 8
        || !parts[1].bytes().all(|byte| byte.is_ascii_digit())
        || parts[2].is_empty()
    {
        return Err(S3Error::AccessDenied);
    }
    Ok(Scope {
        access_key: parts[0].to_string(),
        date: parts[1].to_string(),
        region: parts[2].to_string(),
        service: parts[3].to_string(),
        terminal: parts[4].to_string(),
    })
}

fn parse_amz_date(value: &str) -> Result<OffsetDateTime, S3Error> {
    let format =
        time::format_description::parse_borrowed::<2>("[year][month][day]T[hour][minute][second]Z")
            .map_err(|_| S3Error::AccessDenied)?;
    PrimitiveDateTime::parse(value, &format)
        .map(PrimitiveDateTime::assume_utc)
        .map_err(|_| S3Error::AccessDenied)
}

fn resolve_secret(access_key: &str) -> Option<String> {
    if let Ok(secret) = env::var("LOCALCLOUD_S3_SECRET_ACCESS_KEY") {
        let configured_key = env::var("LOCALCLOUD_S3_ACCESS_KEY_ID").ok();
        if configured_key
            .as_deref()
            .is_none_or(|key| key == access_key)
        {
            return Some(secret);
        }
    }
    if env::var("AWS_ACCESS_KEY_ID").ok().as_deref() == Some(access_key) {
        if let Ok(secret) = env::var("AWS_SECRET_ACCESS_KEY") {
            return Some(secret);
        }
    }
    if let Some(secret) = profile_secret(access_key) {
        return Some(secret);
    }
    matches!(access_key, "test" | "localcloud").then(|| "test".to_string())
}

fn profile_secret(access_key: &str) -> Option<String> {
    let profile = env::var("AWS_PROFILE").unwrap_or_else(|_| "default".to_string());
    let path = env::var_os("AWS_SHARED_CREDENTIALS_FILE")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".aws/credentials")))?;
    let contents = fs::read_to_string(path).ok()?;
    let mut active = false;
    let mut key = None;
    let mut secret = None;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            if active {
                break;
            }
            active = line[1..line.len() - 1].trim() == profile;
            continue;
        }
        if !active || line.starts_with(['#', ';']) || line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        match name.trim() {
            "aws_access_key_id" => key = Some(value.trim().to_string()),
            "aws_secret_access_key" => secret = Some(value.trim().to_string()),
            _ => {}
        }
    }
    (key.as_deref() == Some(access_key))
        .then_some(secret)
        .flatten()
}
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, service.as_bytes());
    hmac_sha256(&service_key, b"aws4_request")
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0_u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK];
    let mut outer_pad = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Method, Uri};

    fn request(method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> ServiceRequest {
        ServiceRequest {
            method,
            uri,
            headers,
            body,
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "req-presign".to_string(),
        }
    }

    #[test]
    fn hmac_matches_rfc_4231_vector() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn canonical_query_sorts_and_excludes_signature() {
        let pairs = raw_query_pairs("z=a%20b&X-Amz-Signature=deadbeef&a=%2F");
        assert_eq!(canonical_query(&pairs), "a=%2F&z=a%20b");
    }
    fn signed_uri(path: &str, expires: i64) -> Uri {
        let format = time::format_description::parse_borrowed::<2>(
            "[year][month][day]T[hour][minute][second]Z",
        )
        .unwrap();
        let date = OffsetDateTime::now_utc().format(&format).unwrap();
        let short_date = &date[..8];
        let credential = format!("test/{short_date}/us-east-1/s3/aws4_request");
        let query = format!(
            "X-Amz-Algorithm={ALGORITHM}&X-Amz-Credential={}&X-Amz-Date={date}&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host",
            uri_encode(credential.as_bytes(), false)
        );
        let pairs = raw_query_pairs(&query);
        let canonical = format!(
            "GET\n{}\n{}\nhost:localhost:4599\n\nhost\nUNSIGNED-PAYLOAD",
            canonical_uri(path),
            canonical_query(&pairs)
        );
        let scope = format!("{short_date}/us-east-1/s3/aws4_request");
        let string_to_sign = format!(
            "{ALGORITHM}\n{date}\n{scope}\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let signature = hex(&hmac_sha256(
            &signing_key("test", short_date, "us-east-1", "s3"),
            string_to_sign.as_bytes(),
        ));
        format!("{path}?{query}&X-Amz-Signature={signature}")
            .parse()
            .unwrap()
    }

    #[test]
    fn presigned_url_round_trip_and_tamper() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:4599"));
        let valid = request(
            Method::GET,
            signed_uri("/bucket/key", 60),
            headers.clone(),
            Bytes::new(),
        );
        assert!(validate_url(&valid).is_ok());

        let tampered = request(
            Method::GET,
            signed_uri("/bucket/other", 60),
            headers,
            Bytes::new(),
        );
        let original_signature = query_value(
            &raw_query_pairs(valid.uri.query().unwrap()),
            "X-Amz-Signature",
        )
        .unwrap();
        let mut uri = tampered.uri.to_string();
        let range = uri.rfind('=').unwrap() + 1..;
        uri.replace_range(range, std::str::from_utf8(&original_signature).unwrap());
        let tampered = request(
            Method::GET,
            uri.parse().unwrap(),
            tampered.headers,
            Bytes::new(),
        );
        assert!(matches!(
            validate_url(&tampered),
            Err(S3Error::AccessDenied)
        ));
    }

    #[test]
    fn presigned_post_validates_policy_and_filename() {
        let now = OffsetDateTime::now_utc();
        let date_format = time::format_description::parse_borrowed::<2>(
            "[year][month][day]T[hour][minute][second]Z",
        )
        .unwrap();
        let date = now.format(&date_format).unwrap();
        let expiration = (now + time::Duration::minutes(5)).format(&Rfc3339).unwrap();
        let credential = format!("test/{}/us-east-1/s3/aws4_request", &date[..8]);
        let policy = serde_json::json!({
            "expiration": expiration,
            "conditions": [
                {"bucket": "bucket"},
                ["starts-with", "$key", "uploads/"],
                ["eq", "$Content-Type", "text/plain"],
                ["content-length-range", 1, 10]
            ]
        });
        let policy = base64::engine::general_purpose::STANDARD.encode(policy.to_string());
        let signature = hex(&hmac_sha256(
            &signing_key("test", &date[..8], "us-east-1", "s3"),
            policy.as_bytes(),
        ));
        let boundary = "lc-boundary";
        let mut body = Vec::new();
        for (name, value) in [
            ("key", "uploads/${filename}"),
            ("policy", policy.as_str()),
            ("x-amz-algorithm", ALGORITHM),
            ("x-amz-credential", credential.as_str()),
            ("x-amz-date", date.as_str()),
            ("x-amz-signature", signature.as_str()),
            ("Content-Type", "text/plain"),
        ] {
            body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes());
        }
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--{boundary}--\r\n").as_bytes());
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:4599"));
        headers.insert(
            "content-type",
            HeaderValue::from_str(&format!("multipart/form-data; boundary={boundary}")).unwrap(),
        );
        let upload = parse_post(
            &request(
                Method::POST,
                "/bucket".parse().unwrap(),
                headers,
                Bytes::from(body),
            ),
            "bucket",
        )
        .unwrap();
        assert_eq!(upload.key, "uploads/note.txt");
        assert_eq!(upload.body, "hello");
        assert_eq!(upload.headers.get("content-type").unwrap(), "text/plain");
    }
}
