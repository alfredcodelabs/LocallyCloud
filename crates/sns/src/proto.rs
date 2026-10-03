//! Dual-protocol request handling: protocol detection and a unified `Input` accessor over
//! Query (form-urlencoded with indexed members) and AWS JSON request bodies.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::SnsError;
use crate::model::{AttributeValue, MessageAttribute};

use base64::Engine;

/// The wire protocol of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Query,
    Json,
}

impl Protocol {
    /// Map to the Core protocol used by the error mapper.
    pub fn aws(self) -> locallycloud_core::registry::AwsProtocol {
        match self {
            Protocol::Query => locallycloud_core::registry::AwsProtocol::Query,
            Protocol::Json => locallycloud_core::registry::AwsProtocol::Json10,
        }
    }
}

/// A parsed request body in either protocol.
pub enum Input {
    Json(Value),
    Query(BTreeMap<String, String>),
}

impl Input {
    /// Parse `X-Amz-Target` (JSON) or the form body's `Action` (Query) into `(protocol, op)`.
    pub fn classify(x_amz_target: Option<&str>, body: &[u8]) -> (Protocol, Option<String>, Input) {
        if let Some(target) = x_amz_target {
            let op = target.rsplit('.').next().map(str::to_string);
            let value: Value =
                serde_json::from_slice(body).unwrap_or(Value::Object(Default::default()));
            (Protocol::Json, op, Input::Json(value))
        } else {
            let map = parse_form(body);
            let op = map.get("Action").cloned();
            (Protocol::Query, op, Input::Query(map))
        }
    }

    /// A scalar string parameter.
    pub fn get(&self, key: &str) -> Option<String> {
        match self {
            Input::Json(v) => v.get(key).and_then(|x| match x {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                Value::Bool(b) => Some(b.to_string()),
                _ => None,
            }),
            Input::Query(m) => m.get(key).cloned(),
        }
        .filter(|s| !s.is_empty())
    }

    pub fn require(&self, key: &str) -> Result<String, SnsError> {
        self.get(key)
            .ok_or_else(|| SnsError::InvalidParameter(format!("{key} is required")))
    }

    /// An attribute map: Query `Attributes.entry.<n>.key/value`, JSON `Attributes` object.
    pub fn attributes(&self, field: &str) -> BTreeMap<String, String> {
        match self {
            Input::Json(v) => v
                .get(field)
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, val)| value_to_string(val).map(|s| (k.clone(), s)))
                        .collect()
                })
                .unwrap_or_default(),
            Input::Query(m) => {
                let mut out = BTreeMap::new();
                let mut n = 1;
                loop {
                    let kk = format!("{field}.entry.{n}.key");
                    match m.get(&kk) {
                        Some(k) => {
                            let v = m
                                .get(&format!("{field}.entry.{n}.value"))
                                .cloned()
                                .unwrap_or_default();
                            out.insert(k.clone(), v);
                            n += 1;
                        }
                        None => break,
                    }
                }
                out
            }
        }
    }

    /// Tags: Query `Tags.member.<n>.Key/Value`, JSON `Tags` array of `{Key, Value}`.
    pub fn tags(&self) -> Vec<(String, String)> {
        match self {
            Input::Json(v) => v
                .get("Tags")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|t| {
                            Some((
                                t.get("Key")?.as_str()?.to_string(),
                                t.get("Value")?.as_str()?.to_string(),
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            Input::Query(m) => {
                let mut out = Vec::new();
                let mut n = 1;
                while let Some(k) = m.get(&format!("Tags.member.{n}.Key")) {
                    let v = m
                        .get(&format!("Tags.member.{n}.Value"))
                        .cloned()
                        .unwrap_or_default();
                    out.push((k.clone(), v));
                    n += 1;
                }
                out
            }
        }
    }

    /// Tag keys: Query `TagKeys.member.<n>`, JSON `TagKeys` array.
    pub fn tag_keys(&self) -> Vec<String> {
        match self {
            Input::Json(v) => v
                .get("TagKeys")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            Input::Query(m) => indexed_list(m, "TagKeys.member"),
        }
    }

    /// Message attributes in either protocol.
    pub fn message_attributes(&self) -> Result<BTreeMap<String, MessageAttribute>, SnsError> {
        let mut out = BTreeMap::new();
        match self {
            Input::Json(v) => {
                if let Some(obj) = v.get("MessageAttributes").and_then(Value::as_object) {
                    for (name, spec) in obj {
                        out.insert(
                            name.clone(),
                            parse_attr(
                                spec.get("DataType").and_then(Value::as_str),
                                spec.get("StringValue").and_then(Value::as_str),
                                spec.get("BinaryValue").and_then(Value::as_str),
                                name,
                            )?,
                        );
                    }
                }
            }
            Input::Query(m) => {
                let mut n = 1;
                while let Some(name) = m.get(&format!("MessageAttributes.entry.{n}.Name")) {
                    let name = name.clone();
                    let p = format!("MessageAttributes.entry.{n}.Value");
                    out.insert(
                        name.clone(),
                        parse_attr(
                            m.get(&format!("{p}.DataType")).map(String::as_str),
                            m.get(&format!("{p}.StringValue")).map(String::as_str),
                            m.get(&format!("{p}.BinaryValue")).map(String::as_str),
                            &name,
                        )?,
                    );
                    n += 1;
                }
            }
        }
        Ok(out)
    }

    /// Extract batch entries as sub-inputs (`PublishBatchRequestEntries`).
    pub fn batch_entries(&self, list_field: &str) -> Vec<Input> {
        match self {
            Input::Json(v) => v
                .get(list_field)
                .and_then(Value::as_array)
                .map(|a| a.iter().cloned().map(Input::Json).collect())
                .unwrap_or_default(),
            Input::Query(m) => {
                let mut out = Vec::new();
                let mut n = 1;
                loop {
                    let prefix = format!("{list_field}.member.{n}.");
                    let sub: BTreeMap<String, String> = m
                        .iter()
                        .filter_map(|(k, v)| {
                            k.strip_prefix(&prefix).map(|s| (s.to_string(), v.clone()))
                        })
                        .collect();
                    if sub.is_empty() {
                        break;
                    }
                    out.push(Input::Query(sub));
                    n += 1;
                }
                out
            }
        }
    }
}

fn parse_attr(
    data_type: Option<&str>,
    string_value: Option<&str>,
    binary_value: Option<&str>,
    name: &str,
) -> Result<MessageAttribute, SnsError> {
    if name.is_empty()
        || name.len() > 256
        || name.starts_with('.')
        || name.ends_with('.')
        || name.contains("..")
        || name.to_ascii_lowercase().starts_with("aws.")
        || name.to_ascii_lowercase().starts_with("amazon.")
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(SnsError::InvalidParameter(format!(
            "invalid message attribute name {name}"
        )));
    }
    let data_type = data_type
        .ok_or_else(|| SnsError::InvalidParameter(format!("attribute {name} missing DataType")))?
        .to_string();
    let base_type = data_type.split('.').next().unwrap_or_default();
    let value = match base_type {
        "String" => match (string_value, binary_value) {
            (Some(value), None) => AttributeValue::String(value.to_string()),
            _ => {
                return Err(SnsError::InvalidParameter(format!(
                    "attribute {name} requires only StringValue"
                )))
            }
        },
        "Number" => match (string_value, binary_value) {
            (Some(value), None) if value.parse::<f64>().is_ok_and(f64::is_finite) => {
                AttributeValue::String(value.to_string())
            }
            _ => {
                return Err(SnsError::InvalidParameter(format!(
                    "attribute {name} requires a finite numeric StringValue"
                )))
            }
        },
        "Binary" => match (string_value, binary_value) {
            (None, Some(value)) => AttributeValue::Binary(
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(|_| {
                        SnsError::InvalidParameter(format!(
                            "attribute {name} BinaryValue is not base64"
                        ))
                    })?,
            ),
            _ => {
                return Err(SnsError::InvalidParameter(format!(
                    "attribute {name} requires only BinaryValue"
                )))
            }
        },
        _ => {
            return Err(SnsError::InvalidParameter(format!(
                "attribute {name} has unsupported DataType {data_type}"
            )))
        }
    };
    Ok(MessageAttribute { data_type, value })
}

fn value_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn indexed_list(m: &BTreeMap<String, String>, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut n = 1;
    while let Some(v) = m.get(&format!("{prefix}.{n}")) {
        out.push(v.clone());
        n += 1;
    }
    out
}

/// Parse a form-urlencoded body into a parameter map.
fn parse_form(body: &[u8]) -> BTreeMap<String, String> {
    let text = String::from_utf8_lossy(body);
    let mut map = BTreeMap::new();
    for pair in text.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (form_decode(k), form_decode(v)),
            None => (form_decode(pair), String::new()),
        };
        map.insert(k, v);
    }
    map
}

fn form_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_query_vs_json() {
        let (p, op, _) = Input::classify(None, b"Action=CreateTopic&Name=t");
        assert_eq!(p, Protocol::Query);
        assert_eq!(op.as_deref(), Some("CreateTopic"));

        let (p, op, _) = Input::classify(
            Some("AmazonSimpleNotificationService.CreateTopic"),
            br#"{"Name":"t"}"#,
        );
        assert_eq!(p, Protocol::Json);
        assert_eq!(op.as_deref(), Some("CreateTopic"));
    }

    #[test]
    fn query_attributes_and_tags() {
        let (_, _, input) = Input::classify(
            None,
            b"Action=CreateTopic&Attributes.entry.1.key=FifoTopic&Attributes.entry.1.value=true&Tags.member.1.Key=env&Tags.member.1.Value=prod",
        );
        assert_eq!(
            input.attributes("Attributes").get("FifoTopic"),
            Some(&"true".to_string())
        );
        assert_eq!(input.tags(), vec![("env".to_string(), "prod".to_string())]);
    }

    #[test]
    fn json_message_attributes() {
        let (_, _, input) = Input::classify(
            Some("AmazonSimpleNotificationService.Publish"),
            br#"{"Message":"m","MessageAttributes":{"k":{"DataType":"String","StringValue":"v"}}}"#,
        );
        let attrs = input.message_attributes().unwrap();
        assert_eq!(attrs.get("k").unwrap().data_type, "String");
    }

    #[test]
    fn query_batch_entries() {
        let (_, _, input) = Input::classify(
            None,
            b"Action=PublishBatch&PublishBatchRequestEntries.member.1.Id=a&PublishBatchRequestEntries.member.1.Message=hi&PublishBatchRequestEntries.member.2.Id=b&PublishBatchRequestEntries.member.2.Message=yo",
        );
        let entries = input.batch_entries("PublishBatchRequestEntries");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].get("Id"), Some("a".to_string()));
        assert_eq!(entries[1].get("Message"), Some("yo".to_string()));
    }
}
