//! Dual-protocol support for SQS: classify a request as modern AWS JSON 1.0
//! (`X-Amz-Target`) or legacy Query/XML (`Action` form field), and serialize success
//! responses in the request's protocol.
//!
//! The operation layer (`ops.rs`) is protocol-agnostic: it always consumes and produces a
//! JSON [`Value`]. This module bridges the legacy Query protocol to that shape on the way in
//! (translating SQS indexed members such as `Attribute.<n>.Name`/`.Value`,
//! `MessageAttribute.<n>.*`, and `*BatchRequestEntry.<n>.*` into the JSON request shape the
//! ops expect) and back out (rendering the JSON response as the Query `<{Op}Response>` XML
//! envelope). JSON requests pass through unchanged.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

/// SQS Query XML namespace (API version 2012-11-05).
const XMLNS: &str = "http://queue.amazonaws.com/doc/2012-11-05/";

/// The wire protocol of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Query,
    Json,
}

impl Protocol {
    /// Map to the Core protocol used by the error mapper.
    pub fn aws(self) -> localcloud_core::registry::AwsProtocol {
        match self {
            Protocol::Query => localcloud_core::registry::AwsProtocol::Query,
            Protocol::Json => localcloud_core::registry::AwsProtocol::Json10,
        }
    }
}

/// Classify a request into `(protocol, operation, request-body-as-Value)`.
///
/// JSON requests parse the body directly. Query requests parse the form body and translate
/// SQS indexed members into the same JSON request shape the ops consume.
pub fn classify(x_amz_target: Option<&str>, body: &[u8]) -> (Protocol, Option<String>, Value) {
    if let Some(target) = x_amz_target {
        let op = target.rsplit('.').next().map(str::to_string);
        let value: Value = if body.is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_slice(body).unwrap_or(Value::Object(Map::new()))
        };
        (Protocol::Json, op, value)
    } else {
        let map = parse_form(body);
        let op = map.get("Action").cloned();
        (Protocol::Query, op, query_to_value(&map))
    }
}

// ============================ Query request → JSON Value =======================

/// Translate a flat Query parameter map into the JSON request shape the ops expect.
fn query_to_value(map: &BTreeMap<String, String>) -> Value {
    let mut obj = Map::new();

    // Scalars: every key without a '.' (except the protocol meta-fields).
    for (k, v) in map {
        if !k.contains('.') && k != "Action" && k != "Version" {
            obj.insert(k.clone(), Value::String(v.clone()));
        }
    }

    // Attribute.<n>.Name / .Value  → Attributes object (Create/SetQueueAttributes).
    let attrs = idx_name_value(map, "Attribute", "Name", "Value");
    if !attrs.is_empty() {
        obj.insert("Attributes".into(), Value::Object(attrs));
    }

    // Tag.<n>.Key / .Value  → Tags object (TagQueue).
    let tags = idx_name_value(map, "Tag", "Key", "Value");
    if !tags.is_empty() {
        obj.insert("Tags".into(), Value::Object(tags));
    }

    // AttributeName.<n> (+ MessageSystemAttributeName.<n>)  → AttributeNames array.
    let mut attr_names = idx_list(map, "AttributeName");
    attr_names.extend(idx_list(map, "MessageSystemAttributeName"));
    if !attr_names.is_empty() {
        obj.insert("AttributeNames".into(), to_array(attr_names));
    }

    // MessageAttributeName.<n>  → MessageAttributeNames array.
    let msg_attr_names = idx_list(map, "MessageAttributeName");
    if !msg_attr_names.is_empty() {
        obj.insert("MessageAttributeNames".into(), to_array(msg_attr_names));
    }

    // TagKey.<n>  → TagKeys array (UntagQueue).
    let tag_keys = idx_list(map, "TagKey");
    if !tag_keys.is_empty() {
        obj.insert("TagKeys".into(), to_array(tag_keys));
    }

    // AddPermission: AWSAccountId.<n> → AWSAccountIds, ActionName.<n> → Actions.
    let accounts = idx_list(map, "AWSAccountId");
    if !accounts.is_empty() {
        obj.insert("AWSAccountIds".into(), to_array(accounts));
    }
    let actions = idx_list(map, "ActionName");
    if !actions.is_empty() {
        obj.insert("Actions".into(), to_array(actions));
    }

    // MessageAttribute.<n>.Name / .Value.*  → MessageAttributes object.
    let message_attributes = idx_message_attributes(map, "MessageAttribute");
    if !message_attributes.is_empty() {
        obj.insert(
            "MessageAttributes".into(),
            Value::Object(message_attributes),
        );
    }

    // MessageSystemAttribute.<n>.Name / .Value.*  → MessageSystemAttributes object.
    let system_attributes = idx_message_attributes(map, "MessageSystemAttribute");
    if !system_attributes.is_empty() {
        obj.insert(
            "MessageSystemAttributes".into(),
            Value::Object(system_attributes),
        );
    }

    // Batch entries (exactly one family present per request) → Entries array.
    for prefix in [
        "SendMessageBatchRequestEntry",
        "DeleteMessageBatchRequestEntry",
        "ChangeMessageVisibilityBatchRequestEntry",
    ] {
        let entries = idx_entries(map, prefix);
        if !entries.is_empty() {
            obj.insert("Entries".into(), Value::Array(entries));
            break;
        }
    }

    Value::Object(obj)
}

/// Collect `prefix.<n>` scalars (1-based, contiguous) into a list.
fn idx_list(map: &BTreeMap<String, String>, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut n = 1;
    while let Some(v) = map.get(&format!("{prefix}.{n}")) {
        out.push(v.clone());
        n += 1;
    }
    out
}

/// Collect `prefix.<n>.<name_key>`/`prefix.<n>.<value_key>` pairs into a `{name: value}` map.
fn idx_name_value(
    map: &BTreeMap<String, String>,
    prefix: &str,
    name_key: &str,
    value_key: &str,
) -> Map<String, Value> {
    let mut out = Map::new();
    let mut n = 1;
    while let Some(name) = map.get(&format!("{prefix}.{n}.{name_key}")) {
        let value = map
            .get(&format!("{prefix}.{n}.{value_key}"))
            .cloned()
            .unwrap_or_default();
        out.insert(name.clone(), Value::String(value));
        n += 1;
    }
    out
}

/// Collect `prefix.<n>.Name` + `prefix.<n>.Value.{DataType,StringValue,BinaryValue}` into the
/// JSON message-attribute shape `{name: {DataType, StringValue?, BinaryValue?}}`.
fn idx_message_attributes(map: &BTreeMap<String, String>, prefix: &str) -> Map<String, Value> {
    let mut out = Map::new();
    let mut n = 1;
    while let Some(name) = map.get(&format!("{prefix}.{n}.Name")) {
        let value_prefix = format!("{prefix}.{n}.Value");
        let mut spec = Map::new();
        if let Some(dt) = map.get(&format!("{value_prefix}.DataType")) {
            spec.insert("DataType".into(), json!(dt));
        }
        if let Some(sv) = map.get(&format!("{value_prefix}.StringValue")) {
            spec.insert("StringValue".into(), json!(sv));
        }
        if let Some(bv) = map.get(&format!("{value_prefix}.BinaryValue")) {
            spec.insert("BinaryValue".into(), json!(bv));
        }
        out.insert(name.clone(), Value::Object(spec));
        n += 1;
    }
    out
}

/// Collect `prefix.<n>.*` sub-parameters into per-entry objects, recursing so nested members
/// (e.g. an entry's own `MessageAttribute.<m>.*`) are translated too.
fn idx_entries(map: &BTreeMap<String, String>, prefix: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut n = 1;
    loop {
        let entry_prefix = format!("{prefix}.{n}.");
        let sub: BTreeMap<String, String> = map
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix(&entry_prefix)
                    .map(|s| (s.to_string(), v.clone()))
            })
            .collect();
        if sub.is_empty() {
            break;
        }
        out.push(query_to_value(&sub));
        n += 1;
    }
    out
}

fn to_array(items: Vec<String>) -> Value {
    Value::Array(items.into_iter().map(Value::String).collect())
}

// ============================ JSON Value → Query XML ===========================

/// Render the JSON response `value` as the Query `<{op}Response>` XML envelope.
pub fn to_query_xml(op: &str, value: &Value, request_id: &str) -> String {
    let inner = result_inner(op, value);
    let result = if inner.is_empty() {
        String::new()
    } else {
        format!("<{op}Result>{inner}</{op}Result>")
    };
    format!(
        "<{op}Response xmlns=\"{XMLNS}\">{result}<ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata></{op}Response>",
        xml_escape(request_id),
    )
}

/// Build the inner XML of the `<{op}Result>` element from the JSON response body.
fn result_inner(op: &str, v: &Value) -> String {
    match op {
        "ListQueues" => format!(
            "{}{}",
            repeated_el(v.get("QueueUrls"), "QueueUrl"),
            v.get("NextToken")
                .and_then(Value::as_str)
                .map(|token| text_el("NextToken", token))
                .unwrap_or_default(),
        ),
        "ListDeadLetterSourceQueues" => format!(
            "{}{}",
            repeated_el(v.get("queueUrls"), "QueueUrl"),
            v.get("NextToken")
                .and_then(Value::as_str)
                .map(|token| text_el("NextToken", token))
                .unwrap_or_default(),
        ),
        "GetQueueAttributes" => attributes_xml(v.get("Attributes")),
        "ListQueueTags" => tags_xml(v.get("Tags")),
        "ReceiveMessage" => messages_xml(v.get("Messages")),
        "SendMessageBatch" => batch_xml(v, "SendMessageBatchResultEntry"),
        "DeleteMessageBatch" => batch_xml(v, "DeleteMessageBatchResultEntry"),
        "ChangeMessageVisibilityBatch" => batch_xml(v, "ChangeMessageVisibilityBatchResultEntry"),
        "ListMessageMoveTasks" => move_tasks_xml(v.get("Results")),
        // Scalar-only results: CreateQueue, GetQueueUrl, SendMessage, StartMessageMoveTask,
        // CancelMessageMoveTask, and the empty `{}` results.
        _ => scalar_fields_xml(v),
    }
}

/// Emit each scalar field of an object as `<Key>value</Key>` (skipping non-scalars).
fn scalar_fields_xml(v: &Value) -> String {
    v.as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, val)| scalar_str(val).map(|s| text_el(k, &s)))
                .collect()
        })
        .unwrap_or_default()
}

/// Emit a JSON array of strings as repeated flat `<el>value</el>` elements.
fn repeated_el(v: Option<&Value>, el: &str) -> String {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(|s| text_el(el, s))
                .collect()
        })
        .unwrap_or_default()
}

/// `{name: value}` → repeated `<Attribute><Name/><Value/></Attribute>`.
fn attributes_xml(v: Option<&Value>) -> String {
    v.and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, val)| {
                    format!(
                        "<Attribute>{}{}</Attribute>",
                        text_el("Name", k),
                        text_el("Value", &scalar_str(val).unwrap_or_default()),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `{key: value}` → repeated `<Tag><Key/><Value/></Tag>`.
fn tags_xml(v: Option<&Value>) -> String {
    v.and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, val)| {
                    format!(
                        "<Tag>{}{}</Tag>",
                        text_el("Key", k),
                        text_el("Value", &scalar_str(val).unwrap_or_default()),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Array of message objects → repeated `<Message>` elements.
fn messages_xml(v: Option<&Value>) -> String {
    v.and_then(Value::as_array)
        .map(|a| a.iter().map(message_xml).collect())
        .unwrap_or_default()
}

fn message_xml(m: &Value) -> String {
    let mut s = String::from("<Message>");
    for key in ["MessageId", "ReceiptHandle", "MD5OfBody", "Body"] {
        if let Some(val) = m.get(key).and_then(Value::as_str) {
            s.push_str(&text_el(key, val));
        }
    }
    if let Some(attrs) = m.get("Attributes").and_then(Value::as_object) {
        for (k, val) in attrs {
            s.push_str(&format!(
                "<Attribute>{}{}</Attribute>",
                text_el("Name", k),
                text_el("Value", &scalar_str(val).unwrap_or_default()),
            ));
        }
    }
    if let Some(md5) = m.get("MD5OfMessageAttributes").and_then(Value::as_str) {
        s.push_str(&text_el("MD5OfMessageAttributes", md5));
    }
    if let Some(ma) = m.get("MessageAttributes").and_then(Value::as_object) {
        for (name, spec) in ma {
            let mut value_inner = String::new();
            if let Some(dt) = spec.get("DataType").and_then(Value::as_str) {
                value_inner.push_str(&text_el("DataType", dt));
            }
            if let Some(sv) = spec.get("StringValue").and_then(Value::as_str) {
                value_inner.push_str(&text_el("StringValue", sv));
            }
            if let Some(bv) = spec.get("BinaryValue").and_then(Value::as_str) {
                value_inner.push_str(&text_el("BinaryValue", bv));
            }
            s.push_str(&format!(
                "<MessageAttribute>{}<Value>{value_inner}</Value></MessageAttribute>",
                text_el("Name", name),
            ));
        }
    }
    s.push_str("</Message>");
    s
}

/// `{Successful, Failed}` → repeated `<{ok_entry}>` + `<BatchResultErrorEntry>` elements.
fn batch_xml(v: &Value, ok_entry: &str) -> String {
    let mut s = String::new();
    if let Some(ok) = v.get("Successful").and_then(Value::as_array) {
        for e in ok {
            s.push_str(&format!(
                "<{ok_entry}>{}</{ok_entry}>",
                scalar_fields_xml(e)
            ));
        }
    }
    if let Some(failed) = v.get("Failed").and_then(Value::as_array) {
        for e in failed {
            s.push_str(&format!(
                "<BatchResultErrorEntry>{}</BatchResultErrorEntry>",
                scalar_fields_xml(e),
            ));
        }
    }
    s
}

/// Array of move-task objects → repeated `<ListMessageMoveTasksResultEntry>` elements.
fn move_tasks_xml(v: Option<&Value>) -> String {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|t| {
                    format!(
                        "<ListMessageMoveTasksResultEntry>{}</ListMessageMoveTasksResultEntry>",
                        scalar_fields_xml(t),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn scalar_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

// ============================ form + xml helpers ===============================

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

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn text_el(name: &str, text: &str) -> String {
    format!("<{name}>{}</{name}>", xml_escape(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_query_vs_json() {
        let (p, op, _) = classify(None, b"Action=ListQueues&Version=2012-11-05");
        assert_eq!(p, Protocol::Query);
        assert_eq!(op.as_deref(), Some("ListQueues"));

        let (p, op, _) = classify(
            Some("AmazonSQS.SendMessage"),
            br#"{"QueueUrl":"u","MessageBody":"b"}"#,
        );
        assert_eq!(p, Protocol::Json);
        assert_eq!(op.as_deref(), Some("SendMessage"));
    }

    #[test]
    fn query_scalars_and_attributes() {
        let (_, _, v) = classify(
            None,
            b"Action=CreateQueue&QueueName=q&Attribute.1.Name=FifoQueue&Attribute.1.Value=true&Attribute.2.Name=DelaySeconds&Attribute.2.Value=5",
        );
        assert_eq!(v["QueueName"], "q");
        assert_eq!(v["Attributes"]["FifoQueue"], "true");
        assert_eq!(v["Attributes"]["DelaySeconds"], "5");
    }

    #[test]
    fn query_attribute_names_and_message_attributes() {
        let (_, _, v) = classify(
            None,
            b"Action=ReceiveMessage&QueueUrl=u&AttributeName.1=All&MessageAttributeName.1=x&MaxNumberOfMessages=5",
        );
        assert_eq!(v["AttributeNames"][0], "All");
        assert_eq!(v["MessageAttributeNames"][0], "x");
        assert_eq!(v["MaxNumberOfMessages"], "5");
    }

    #[test]
    fn query_send_message_attributes() {
        let (_, _, v) = classify(
            None,
            b"Action=SendMessage&QueueUrl=u&MessageBody=b&MessageAttribute.1.Name=k&MessageAttribute.1.Value.DataType=String&MessageAttribute.1.Value.StringValue=v",
        );
        assert_eq!(v["MessageAttributes"]["k"]["DataType"], "String");
        assert_eq!(v["MessageAttributes"]["k"]["StringValue"], "v");
    }

    #[test]
    fn query_tags_and_tag_keys() {
        let (_, _, v) = classify(
            None,
            b"Action=TagQueue&QueueUrl=u&Tag.1.Key=env&Tag.1.Value=prod",
        );
        assert_eq!(v["Tags"]["env"], "prod");
        let (_, _, v2) = classify(
            None,
            b"Action=UntagQueue&QueueUrl=u&TagKey.1=env&TagKey.2=team",
        );
        assert_eq!(v2["TagKeys"][0], "env");
        assert_eq!(v2["TagKeys"][1], "team");
    }

    #[test]
    fn query_batch_entries_with_nested_attributes() {
        let (_, _, v) = classify(
            None,
            b"Action=SendMessageBatch&QueueUrl=u&SendMessageBatchRequestEntry.1.Id=a&SendMessageBatchRequestEntry.1.MessageBody=one&SendMessageBatchRequestEntry.1.MessageAttribute.1.Name=k&SendMessageBatchRequestEntry.1.MessageAttribute.1.Value.DataType=String&SendMessageBatchRequestEntry.1.MessageAttribute.1.Value.StringValue=v&SendMessageBatchRequestEntry.2.Id=b&SendMessageBatchRequestEntry.2.MessageBody=two",
        );
        let entries = v["Entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["Id"], "a");
        assert_eq!(entries[0]["MessageBody"], "one");
        assert_eq!(entries[0]["MessageAttributes"]["k"]["StringValue"], "v");
        assert_eq!(entries[1]["Id"], "b");
    }

    #[test]
    fn add_permission_lists() {
        let (_, _, v) = classify(
            None,
            b"Action=AddPermission&QueueUrl=u&Label=l&AWSAccountId.1=111&ActionName.1=SendMessage&ActionName.2=ReceiveMessage",
        );
        assert_eq!(v["AWSAccountIds"][0], "111");
        assert_eq!(v["Actions"][0], "SendMessage");
        assert_eq!(v["Actions"][1], "ReceiveMessage");
    }

    #[test]
    fn renders_scalar_result_envelope() {
        let xml = to_query_xml(
            "CreateQueue",
            &json!({ "QueueUrl": "https://sqs.us-east-1.amazonaws.com/0/q" }),
            "rid",
        );
        assert!(xml.starts_with(
            "<CreateQueueResponse xmlns=\"http://queue.amazonaws.com/doc/2012-11-05/\">"
        ));
        assert!(xml.contains("<CreateQueueResult><QueueUrl>https://sqs.us-east-1.amazonaws.com/0/q</QueueUrl></CreateQueueResult>"));
        assert!(xml.contains("<RequestId>rid</RequestId>"));
    }

    #[test]
    fn renders_empty_result_without_result_element() {
        let xml = to_query_xml("DeleteQueue", &json!({}), "rid");
        assert!(!xml.contains("<DeleteQueueResult>"));
        assert!(xml.contains("<ResponseMetadata><RequestId>rid</RequestId></ResponseMetadata>"));
    }

    #[test]
    fn renders_list_queues_flat() {
        let xml = to_query_xml("ListQueues", &json!({ "QueueUrls": ["a", "b"] }), "rid");
        assert!(xml.contains(
            "<ListQueuesResult><QueueUrl>a</QueueUrl><QueueUrl>b</QueueUrl></ListQueuesResult>"
        ));
    }

    #[test]
    fn renders_get_queue_attributes() {
        let xml = to_query_xml(
            "GetQueueAttributes",
            &json!({ "Attributes": { "VisibilityTimeout": "30" } }),
            "rid",
        );
        assert!(
            xml.contains("<Attribute><Name>VisibilityTimeout</Name><Value>30</Value></Attribute>")
        );
    }

    #[test]
    fn renders_receive_message_with_attributes() {
        let xml = to_query_xml(
            "ReceiveMessage",
            &json!({ "Messages": [{
                "MessageId": "id1",
                "ReceiptHandle": "rh",
                "MD5OfBody": "md5",
                "Body": "hello",
                "Attributes": { "SenderId": "acct" },
                "MD5OfMessageAttributes": "amd5",
                "MessageAttributes": { "k": { "DataType": "String", "StringValue": "v" } }
            }] }),
            "rid",
        );
        assert!(xml.contains("<Message><MessageId>id1</MessageId><ReceiptHandle>rh</ReceiptHandle><MD5OfBody>md5</MD5OfBody><Body>hello</Body>"));
        assert!(xml.contains("<Attribute><Name>SenderId</Name><Value>acct</Value></Attribute>"));
        assert!(xml.contains("<MessageAttribute><Name>k</Name><Value><DataType>String</DataType><StringValue>v</StringValue></Value></MessageAttribute>"));
    }

    #[test]
    fn renders_send_message_batch() {
        let xml = to_query_xml(
            "SendMessageBatch",
            &json!({
                "Successful": [{ "Id": "a", "MessageId": "m1", "MD5OfMessageBody": "md5" }],
                "Failed": [{ "Id": "b", "Code": "X", "Message": "boom", "SenderFault": true }]
            }),
            "rid",
        );
        assert!(xml.contains("<SendMessageBatchResultEntry>"));
        assert!(xml.contains("<Id>a</Id>"));
        assert!(xml.contains("<BatchResultErrorEntry>"));
        assert!(xml.contains("<SenderFault>true</SenderFault>"));
    }

    #[test]
    fn renders_list_queue_tags() {
        let xml = to_query_xml(
            "ListQueueTags",
            &json!({ "Tags": { "env": "prod" } }),
            "rid",
        );
        assert!(xml.contains("<Tag><Key>env</Key><Value>prod</Value></Tag>"));
    }
}
