//! S3 wire conversion for Step Functions SDK tasks; storage stays in S3.

use http::{HeaderMap, HeaderValue, Uri};
use quick_xml::{events::Event, Reader};
use serde_json::{json, Map, Value};

use crate::error::AslError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum S3Action {
    ListObjectsV2,
    PutObject,
    GetObject,
    HeadObject,
    CopyObject,
}

impl S3Action {
    pub(crate) fn parse(action: &str) -> Result<Self, AslError> {
        match action {
            "listObjectsV2" => Ok(Self::ListObjectsV2),
            "putObject" => Ok(Self::PutObject),
            "getObject" => Ok(Self::GetObject),
            "headObject" => Ok(Self::HeadObject),
            "copyObject" => Ok(Self::CopyObject),
            _ => Err(AslError::runtime(format!("unsupported S3 action {action}"))),
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::ListObjectsV2 => "listObjectsV2",
            Self::PutObject => "putObject",
            Self::GetObject => "getObject",
            Self::HeadObject => "headObject",
            Self::CopyObject => "copyObject",
        }
    }
}

pub(crate) fn encode(value: &str, keep_slashes: bool) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (keep_slashes && byte == b'/')
        {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}

fn decode(value: &str) -> Result<String, AslError> {
    let bytes = value.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes
                .get(index + 1..index + 3)
                .ok_or_else(|| invalid("Invalid CopySource encoding"))?;
            let hex =
                std::str::from_utf8(hex).map_err(|_| invalid("Invalid CopySource encoding"))?;
            result.push(
                u8::from_str_radix(hex, 16).map_err(|_| invalid("Invalid CopySource encoding"))?,
            );
            index += 3;
        } else {
            result.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(result).map_err(|_| invalid("Invalid CopySource encoding"))
}

fn invalid(message: &str) -> AslError {
    AslError::new("S3.InvalidArgument", message)
}

pub(crate) fn string<'a>(payload: &'a Value, field: &str) -> Result<&'a str, AslError> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid(&format!("S3 integration requires {field}")))
}

pub(crate) fn copy_source(payload: &Value) -> Result<(String, String, bool), AslError> {
    let source = string(payload, "CopySource")?;
    if source.starts_with("arn:") {
        return Err(invalid(
            "Local CopyObject integration does not support access-point CopySource",
        ));
    }
    let (path, query) = source.split_once('?').unwrap_or((source, ""));
    let path = decode(path)?;
    let (bucket, key) = path
        .trim_start_matches('/')
        .split_once('/')
        .filter(|(bucket, key)| !bucket.is_empty() && !key.is_empty())
        .ok_or_else(|| invalid("CopySource must name a bucket and key"))?;
    let versioned = query.split('&').any(|part| part.starts_with("versionId="));
    Ok((bucket.into(), key.into(), versioned))
}

pub(crate) fn list_uri(payload: &Value, bucket: &str) -> Result<Uri, AslError> {
    let mut uri = format!("/{}?list-type=2", encode(bucket, false));
    for (field, query) in [
        ("Prefix", "prefix"),
        ("Delimiter", "delimiter"),
        ("ContinuationToken", "continuation-token"),
        ("StartAfter", "start-after"),
        ("EncodingType", "encoding-type"),
        ("MaxKeys", "max-keys"),
        ("FetchOwner", "fetch-owner"),
    ] {
        if let Some(value) = payload.get(field) {
            let text = match field {
                "MaxKeys" => value.as_u64().map(|n| n.to_string()),
                "FetchOwner" => value.as_bool().map(|b| b.to_string()),
                _ => value.as_str().map(String::from),
            }
            .ok_or_else(|| invalid(&format!("Invalid {field} type")))?;
            uri.push_str(&format!("&{query}={}", encode(&text, false)));
        }
    }
    uri.parse().map_err(|_| invalid("Invalid S3 list request"))
}

pub(crate) fn add_headers(headers: &mut HeaderMap, payload: &Value) -> Result<(), AslError> {
    for (field, header) in [
        ("ContentMD5", "content-md5"),
        ("ContentType", "content-type"),
        ("IfMatch", "if-match"),
        ("IfNoneMatch", "if-none-match"),
        ("CopySource", "x-amz-copy-source"),
        ("CopySourceIfMatch", "x-amz-copy-source-if-match"),
        ("CopySourceIfNoneMatch", "x-amz-copy-source-if-none-match"),
        (
            "CopySourceIfModifiedSince",
            "x-amz-copy-source-if-modified-since",
        ),
        (
            "CopySourceIfUnmodifiedSince",
            "x-amz-copy-source-if-unmodified-since",
        ),
        ("MetadataDirective", "x-amz-metadata-directive"),
        ("TaggingDirective", "x-amz-tagging-directive"),
        ("Tagging", "x-amz-tagging"),
        ("ServerSideEncryption", "x-amz-server-side-encryption"),
        ("SSEKMSKeyId", "x-amz-server-side-encryption-aws-kms-key-id"),
    ] {
        if let Some(value) = payload.get(field) {
            let text = if matches!(
                field,
                "CopySourceIfModifiedSince" | "CopySourceIfUnmodifiedSince"
            ) {
                http_date(value)?
            } else {
                value
                    .as_str()
                    .ok_or_else(|| invalid(&format!("Invalid {field} type")))?
                    .into()
            };
            headers.insert(
                http::header::HeaderName::from_static(header),
                HeaderValue::from_str(&text)
                    .map_err(|_| invalid(&format!("Invalid {field} header")))?,
            );
        }
    }
    if let Some(metadata) = payload.get("Metadata") {
        let metadata = metadata
            .as_object()
            .ok_or_else(|| invalid("Metadata must be an object"))?;
        for (key, value) in metadata {
            let name = format!("x-amz-meta-{key}")
                .parse::<http::header::HeaderName>()
                .map_err(|_| invalid("Invalid Metadata key"))?;
            let value = value
                .as_str()
                .ok_or_else(|| invalid("Metadata values must be strings"))?;
            headers.insert(
                name,
                HeaderValue::from_str(value).map_err(|_| invalid("Invalid Metadata value"))?,
            );
        }
    }
    Ok(())
}

fn http_date(value: &Value) -> Result<String, AslError> {
    use time::{
        format_description::well_known::{Rfc2822, Rfc3339},
        OffsetDateTime, PrimitiveDateTime, UtcOffset,
    };
    let format = time::format_description::parse_borrowed::<2>(
        "[weekday repr:short], [day padding:zero] [month repr:short] [year] [hour]:[minute]:[second] GMT",
    ).map_err(|_| invalid("Invalid timestamp format"))?;
    let date = match value {
        Value::String(text) => OffsetDateTime::parse(text, &Rfc3339)
            .or_else(|_| OffsetDateTime::parse(text, &Rfc2822))
            .or_else(|_| PrimitiveDateTime::parse(text, &format).map(PrimitiveDateTime::assume_utc))
            .map_err(|_| invalid("Invalid copy source timestamp"))?,
        Value::Number(number) => {
            let seconds = number
                .as_f64()
                .filter(|n| n.is_finite())
                .ok_or_else(|| invalid("Invalid copy source timestamp"))?;
            OffsetDateTime::from_unix_timestamp_nanos((seconds * 1_000_000_000.0) as i128)
                .map_err(|_| invalid("Invalid copy source timestamp"))?
        }
        _ => return Err(invalid("Invalid copy source timestamp type")),
    };
    date.to_offset(UtcOffset::UTC)
        .format(&format)
        .map_err(|_| invalid("Invalid copy source timestamp"))
}

pub(crate) fn validate_fields(action: S3Action, payload: &Value) -> Result<(), AslError> {
    let fields: &[&str] = match action {
        S3Action::ListObjectsV2 => &[
            "Bucket",
            "Prefix",
            "Delimiter",
            "ContinuationToken",
            "StartAfter",
            "EncodingType",
            "MaxKeys",
            "FetchOwner",
        ],
        S3Action::CopyObject => &[
            "Bucket",
            "Key",
            "CopySource",
            "CopySourceIfMatch",
            "CopySourceIfNoneMatch",
            "CopySourceIfModifiedSince",
            "CopySourceIfUnmodifiedSince",
            "IfMatch",
            "IfNoneMatch",
            "MetadataDirective",
            "TaggingDirective",
            "Tagging",
            "Metadata",
            "ContentType",
            "ServerSideEncryption",
            "SSEKMSKeyId",
        ],
        S3Action::PutObject | S3Action::GetObject | S3Action::HeadObject => return Ok(()),
    };
    if let Some(field) = payload.as_object().and_then(|object| {
        object
            .keys()
            .find(|field| !fields.contains(&field.as_str()))
    }) {
        return Err(AslError::new(
            "S3.InvalidRequest",
            format!(
                "Local {} integration does not support {field}",
                action.wire_name()
            ),
        ));
    }
    Ok(())
}

#[derive(Default)]
struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

fn xml(body: &[u8]) -> Result<Node, AslError> {
    let mut reader = Reader::from_reader(body);
    let mut stack = vec![Node::default()];
    loop {
        let event = reader
            .read_event()
            .map_err(|_| AslError::task_failed("Malformed S3 XML response"))?;
        match event {
            Event::Start(start) => {
                if stack.len() > 32 {
                    return Err(AslError::task_failed(
                        "S3 XML response nesting exceeds local limit",
                    ));
                }
                stack.push(Node {
                    name: start.local_name().as_ref().to_owned(),
                    ..Node::default()
                });
            }
            Event::Empty(start) => stack.last_mut().unwrap().children.push(Node {
                name: start.local_name().as_ref().to_owned(),
                ..Node::default()
            }),
            Event::Text(text) => stack.last_mut().unwrap().text.push_str(text.as_ref()),
            Event::CData(text) => stack.last_mut().unwrap().text.push_str(text.as_ref()),
            Event::GeneralRef(reference) => {
                let reference = reference.as_ref();
                let escaped = format!("&{reference};");
                let text = quick_xml::escape::unescape(&escaped)
                    .map_err(|_| AslError::task_failed("Invalid S3 XML entity"))?;
                stack.last_mut().unwrap().text.push_str(&text);
            }
            Event::End(_) => {
                if stack.len() < 2 {
                    return Err(AslError::task_failed("Malformed S3 XML response"));
                }
                let node = stack.pop().unwrap();
                stack.last_mut().unwrap().children.push(node);
            }
            Event::Eof => break,
            Event::DocType(_) => {
                return Err(AslError::task_failed("Unsupported S3 XML document type"))
            }
            _ => {}
        }
    }
    if stack.len() != 1 || stack[0].children.len() != 1 || !stack[0].text.trim().is_empty() {
        return Err(AslError::task_failed("Malformed S3 XML response"));
    }
    Ok(stack.pop().unwrap().children.remove(0))
}

fn sdk_value(node: &Node) -> Result<Value, AslError> {
    if node.children.is_empty() {
        return match node.name.as_str() {
            "KeyCount" | "MaxKeys" | "Size" => node
                .text
                .parse::<u64>()
                .map(|v| json!(v))
                .map_err(|_| AslError::task_failed("Invalid S3 XML number")),
            "IsTruncated" => node
                .text
                .parse::<bool>()
                .map(|v| json!(v))
                .map_err(|_| AslError::task_failed("Invalid S3 XML boolean")),
            _ => Ok(json!(node.text)),
        };
    }
    let mut result = Map::new();
    for child in &node.children {
        let value = sdk_value(child)?;
        match child.name.as_str() {
            "Contents" | "CommonPrefixes" | "ChecksumAlgorithm" => {
                result
                    .entry(child.name.clone())
                    .or_insert_with(|| json!([]))
                    .as_array_mut()
                    .unwrap()
                    .push(value);
            }
            _ => {
                result.insert(child.name.clone(), value);
            }
        }
    }
    Ok(Value::Object(result))
}

fn embedded_error(root: &Node) -> Option<AslError> {
    if root.name != "Error" {
        return None;
    }
    let field = |name: &str| {
        root.children
            .iter()
            .find(|node| node.name == name)
            .map(|node| node.text.as_str())
    };
    Some(AslError::new(
        format!("S3.{}", field("Code").unwrap_or("S3Error")),
        field("Message").unwrap_or("S3 request failed"),
    ))
}

pub(crate) fn response(action: S3Action, body: &[u8]) -> Result<Value, AslError> {
    let root = xml(body)?;
    if let Some(error) = embedded_error(&root) {
        return Err(error);
    }
    let (expected, wrap_copy) = match action {
        S3Action::ListObjectsV2 => ("ListBucketResult", false),
        S3Action::CopyObject => ("CopyObjectResult", true),
        S3Action::PutObject | S3Action::GetObject | S3Action::HeadObject => {
            return Err(AslError::runtime("Unsupported S3 XML action"))
        }
    };
    if root.name != expected {
        return Err(AslError::task_failed("Unexpected S3 XML response root"));
    }
    let value = sdk_value(&root)?;
    if wrap_copy {
        Ok(json!({"CopyObjectResult":value}))
    } else {
        Ok(value)
    }
}

pub(crate) fn error(body: &[u8], fallback: &str) -> AslError {
    xml(body)
        .ok()
        .and_then(|root| embedded_error(&root))
        .unwrap_or_else(|| AslError::new("S3.S3Error", fallback))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_actions_fail_at_the_dispatch_boundary() {
        for action in ["deleteObject", "ListObjectsV2", "", "error"] {
            let error = S3Action::parse(action).unwrap_err();
            assert_eq!(error.error, "States.Runtime");
            assert_eq!(error.cause, format!("unsupported S3 action {action}"));
        }
        for action in [
            "listObjectsV2",
            "putObject",
            "getObject",
            "headObject",
            "copyObject",
        ] {
            assert_eq!(S3Action::parse(action).unwrap().wire_name(), action);
        }
        assert_eq!(
            error(
                b"<Error><Code>AccessDenied</Code><Message>denied</Message></Error>",
                "fallback"
            )
            .error,
            "S3.AccessDenied"
        );
    }

    #[test]
    fn list_members_have_sdk_types_and_xml_entities() {
        let value = response(S3Action::ListObjectsV2, br#"<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>cache</Name><Prefix></Prefix><KeyCount>2</KeyCount><MaxKeys>2</MaxKeys><IsTruncated>true</IsTruncated><Contents><Key>a&amp;&lt;&#43;</Key><Size>3</Size><ChecksumAlgorithm>SHA256</ChecksumAlgorithm></Contents><CommonPrefixes><Prefix>dir/</Prefix></CommonPrefixes><NextContinuationToken>x&amp;y</NextContinuationToken></ListBucketResult>"#).unwrap();
        assert_eq!(value["Contents"][0]["Key"], "a&<+");
        assert_eq!(value["Contents"][0]["Size"], 3);
        assert_eq!(value["Contents"][0]["ChecksumAlgorithm"], json!(["SHA256"]));
        assert_eq!(value["CommonPrefixes"], json!([{"Prefix":"dir/"}]));
        assert_eq!(value["IsTruncated"], true);
        assert_eq!(value["NextContinuationToken"], "x&y");
    }

    #[test]
    fn copy_embedded_error_is_not_success() {
        let error = response(
            S3Action::CopyObject,
            b"<Error><Code>PreconditionFailed</Code><Message>a&amp;b</Message></Error>",
        )
        .unwrap_err();
        assert_eq!(error.error, "S3.PreconditionFailed");
        assert_eq!(error.cause, "a&b");
        assert!(response(S3Action::ListObjectsV2, b"<ListBucketResult>").is_err());
    }

    #[test]
    fn requests_encode_query_and_decode_source_without_plus_substitution() {
        let uri = list_uri(
            &json!({"Prefix":"a/b &+%","ContinuationToken":"x/y+%","MaxKeys":2}),
            "cache",
        )
        .unwrap();
        assert_eq!(
            uri.to_string(),
            "/cache?list-type=2&prefix=a%2Fb%20%26%2B%25&continuation-token=x%2Fy%2B%25&max-keys=2"
        );
        assert_eq!(
            copy_source(&json!({"CopySource":"/cache/a%20b+%25?versionId=old"})).unwrap(),
            ("cache".into(), "a b+%".into(), true)
        );
    }

    #[test]
    fn copy_timestamps_are_serialized_as_http_dates_and_invalid_values_fail() {
        let mut headers = HeaderMap::new();
        add_headers(&mut headers, &json!({"CopySourceIfModifiedSince":"2026-10-06T01:00:00+01:00", "CopySourceIfUnmodifiedSince":0})).unwrap();
        assert_eq!(
            headers["x-amz-copy-source-if-modified-since"],
            "Tue, 06 Oct 2026 00:00:00 GMT"
        );
        assert_eq!(
            headers["x-amz-copy-source-if-unmodified-since"],
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );
        assert!(add_headers(
            &mut headers,
            &json!({"CopySourceIfModifiedSince":"tomorrow"})
        )
        .is_err());
    }
}
