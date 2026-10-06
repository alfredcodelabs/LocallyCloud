//! S3 bucket notification configuration, matching, event shapes, and delivery requests.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::S3Error;
use crate::xml::text_el;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationConfiguration {
    pub queues: Vec<TargetConfiguration>,
    pub topics: Vec<TargetConfiguration>,
    pub lambdas: Vec<TargetConfiguration>,
    pub event_bridge: bool,
}

impl NotificationConfiguration {
    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
            && self.topics.is_empty()
            && self.lambdas.is_empty()
            && !self.event_bridge
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetConfiguration {
    pub id: String,
    pub arn: String,
    pub events: Vec<EventType>,
    pub filter_rules: Vec<FilterRule>,
    xml_kind: XmlTargetKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum XmlTargetKind {
    Queue,
    Topic,
    CloudFunction,
    LambdaFunction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterRule {
    pub name: FilterRuleName,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterRuleName {
    Prefix,
    Suffix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    ObjectCreatedAny,
    ObjectCreatedPut,
    ObjectCreatedPost,
    ObjectCreatedCopy,
    ObjectCreatedCompleteMultipartUpload,
    ObjectRemovedAny,
    ObjectRemovedDelete,
    ObjectRemovedDeleteMarkerCreated,
}

impl EventType {
    fn parse(value: &str) -> Result<Self, S3Error> {
        match value {
            "s3:ObjectCreated:*" => Ok(Self::ObjectCreatedAny),
            "s3:ObjectCreated:Put" => Ok(Self::ObjectCreatedPut),
            "s3:ObjectCreated:Post" => Ok(Self::ObjectCreatedPost),
            "s3:ObjectCreated:Copy" => Ok(Self::ObjectCreatedCopy),
            "s3:ObjectCreated:CompleteMultipartUpload" => {
                Ok(Self::ObjectCreatedCompleteMultipartUpload)
            }
            "s3:ObjectRemoved:*" => Ok(Self::ObjectRemovedAny),
            "s3:ObjectRemoved:Delete" => Ok(Self::ObjectRemovedDelete),
            "s3:ObjectRemoved:DeleteMarkerCreated" => Ok(Self::ObjectRemovedDeleteMarkerCreated),
            _ => Err(invalid("unsupported notification event")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::ObjectCreatedAny => "s3:ObjectCreated:*",
            Self::ObjectCreatedPut => "s3:ObjectCreated:Put",
            Self::ObjectCreatedPost => "s3:ObjectCreated:Post",
            Self::ObjectCreatedCopy => "s3:ObjectCreated:Copy",
            Self::ObjectCreatedCompleteMultipartUpload => {
                "s3:ObjectCreated:CompleteMultipartUpload"
            }
            Self::ObjectRemovedAny => "s3:ObjectRemoved:*",
            Self::ObjectRemovedDelete => "s3:ObjectRemoved:Delete",
            Self::ObjectRemovedDeleteMarkerCreated => "s3:ObjectRemoved:DeleteMarkerCreated",
        }
    }

    fn matches(self, actual: Self) -> bool {
        self == actual
            || matches!(
                (self, actual),
                (
                    Self::ObjectCreatedAny,
                    Self::ObjectCreatedPut
                        | Self::ObjectCreatedPost
                        | Self::ObjectCreatedCopy
                        | Self::ObjectCreatedCompleteMultipartUpload
                ) | (
                    Self::ObjectRemovedAny,
                    Self::ObjectRemovedDelete | Self::ObjectRemovedDeleteMarkerCreated
                )
            )
    }

    pub fn event_name(self) -> &'static str {
        self.as_str().strip_prefix("s3:").unwrap_or(self.as_str())
    }

    fn detail_type(self) -> &'static str {
        match self {
            Self::ObjectCreatedAny
            | Self::ObjectCreatedPut
            | Self::ObjectCreatedPost
            | Self::ObjectCreatedCopy
            | Self::ObjectCreatedCompleteMultipartUpload => "Object Created",
            Self::ObjectRemovedAny
            | Self::ObjectRemovedDelete
            | Self::ObjectRemovedDeleteMarkerCreated => "Object Deleted",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObjectEvent {
    pub bucket: String,
    pub key: String,
    pub event_type: EventType,
    pub reason: &'static str,
    pub time: OffsetDateTime,
    pub size: Option<usize>,
    pub etag: Option<String>,
    pub version_id: Option<String>,
    pub sequencer: String,
    pub configuration: NotificationConfiguration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryTarget {
    Lambda,
    Queue,
    Topic,
    EventBridge,
}

pub struct DeliveryRequest {
    pub target: DeliveryTarget,
    pub arn: Option<String>,
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Debug)]
struct XmlNode {
    name: String,
    text: String,
    children: Vec<XmlNode>,
}

fn invalid(message: &str) -> S3Error {
    S3Error::InvalidArgument(message.to_string())
}

fn parse_tree(body: &[u8]) -> Result<XmlNode, S3Error> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut root = None;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) => stack.push(XmlNode {
                name: element.local_name().as_ref().to_owned(),
                text: String::new(),
                children: Vec::new(),
            }),
            Ok(Event::Empty(element)) => {
                let node = XmlNode {
                    name: element.local_name().as_ref().to_owned(),
                    text: String::new(),
                    children: Vec::new(),
                };
                attach_node(node, &mut stack, &mut root)?;
            }
            Ok(Event::Text(text)) => {
                let value = quick_xml::escape::unescape(text.as_ref())
                    .map_err(|_| S3Error::MalformedXML)?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&value);
                } else if !value.trim().is_empty() {
                    return Err(S3Error::MalformedXML);
                }
            }
            Ok(Event::End(element)) => {
                let node = stack.pop().ok_or(S3Error::MalformedXML)?;
                if node.name != element.local_name().as_ref() {
                    return Err(S3Error::MalformedXML);
                }
                attach_node(node, &mut stack, &mut root)?;
            }
            Ok(Event::Decl(_)) => {}
            Ok(Event::Eof) => break,
            Ok(_) => return Err(S3Error::MalformedXML),
            Err(_) => return Err(S3Error::MalformedXML),
        }
        buffer.clear();
    }
    if !stack.is_empty() {
        return Err(S3Error::MalformedXML);
    }
    root.ok_or(S3Error::MalformedXML)
}

fn attach_node(
    node: XmlNode,
    stack: &mut [XmlNode],
    root: &mut Option<XmlNode>,
) -> Result<(), S3Error> {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else if root.replace(node).is_some() {
        return Err(S3Error::MalformedXML);
    }
    Ok(())
}
pub fn parse_configuration(body: &[u8]) -> Result<NotificationConfiguration, S3Error> {
    let root = parse_tree(body)?;
    if root.name != "NotificationConfiguration" || !root.text.is_empty() {
        return Err(S3Error::MalformedXML);
    }
    let mut configuration = NotificationConfiguration::default();
    for (index, child) in root.children.iter().enumerate() {
        match child.name.as_str() {
            "QueueConfiguration" => {
                configuration
                    .queues
                    .push(parse_target(child, XmlTargetKind::Queue, index)?)
            }
            "TopicConfiguration" => {
                configuration
                    .topics
                    .push(parse_target(child, XmlTargetKind::Topic, index)?)
            }
            "CloudFunctionConfiguration" => configuration.lambdas.push(parse_target(
                child,
                XmlTargetKind::CloudFunction,
                index,
            )?),
            "LambdaFunctionConfiguration" => configuration.lambdas.push(parse_target(
                child,
                XmlTargetKind::LambdaFunction,
                index,
            )?),
            "EventBridgeConfiguration" => {
                if configuration.event_bridge
                    || !child.children.is_empty()
                    || !child.text.is_empty()
                {
                    return Err(invalid("invalid EventBridgeConfiguration"));
                }
                configuration.event_bridge = true;
            }
            _ => return Err(invalid("unsupported notification configuration")),
        }
    }
    Ok(configuration)
}

fn parse_target(
    node: &XmlNode,
    kind: XmlTargetKind,
    index: usize,
) -> Result<TargetConfiguration, S3Error> {
    if !node.text.is_empty() {
        return Err(invalid("invalid notification configuration"));
    }
    let mut id = None;
    let mut arn = None;
    let mut events = Vec::new();
    let mut filter_rules = Vec::new();
    for child in &node.children {
        match child.name.as_str() {
            "Id" if id.is_none() => id = Some(leaf_text(child)?),
            name if is_target_field(kind, name) && arn.is_none() => arn = Some(leaf_text(child)?),
            "Event" => events.push(EventType::parse(&leaf_text(child)?)?),
            "Filter" if filter_rules.is_empty() => filter_rules = parse_filter(child)?,
            _ => return Err(invalid("invalid notification configuration field")),
        }
    }
    let arn = arn
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("notification target is required"))?;
    if events.is_empty() {
        return Err(invalid("at least one notification event is required"));
    }
    let expected_service = match kind {
        XmlTargetKind::Queue => "sqs",
        XmlTargetKind::Topic => "sns",
        XmlTargetKind::CloudFunction | XmlTargetKind::LambdaFunction => "lambda",
    };
    if !valid_target_arn(&arn, expected_service) {
        return Err(invalid("notification target ARN is invalid"));
    }
    let id = id
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("locallycloud-{}-{index}", kind.id_component()));
    Ok(TargetConfiguration {
        id,
        arn,
        events,
        filter_rules,
        xml_kind: kind,
    })
}

impl XmlTargetKind {
    fn id_component(self) -> &'static str {
        match self {
            Self::Queue => "queue",
            Self::Topic => "topic",
            Self::CloudFunction | Self::LambdaFunction => "lambda",
        }
    }
}

fn valid_target_arn(arn: &str, service: &str) -> bool {
    let parts = arn.split(':').collect::<Vec<_>>();
    if parts.first() != Some(&"arn")
        || parts.get(2) != Some(&service)
        || parts.get(3).is_none_or(|value| value.is_empty())
        || parts.get(4).is_none_or(|value| value.is_empty())
    {
        return false;
    }
    match service {
        "lambda" => {
            parts.len() >= 7
                && parts[5] == "function"
                && !parts[6].is_empty()
                && parts.iter().skip(7).all(|part| !part.is_empty())
        }
        "sqs" | "sns" => parts.len() == 6 && !parts[5].is_empty(),
        _ => false,
    }
}

fn is_target_field(kind: XmlTargetKind, name: &str) -> bool {
    match kind {
        XmlTargetKind::Queue => name == "Queue",
        XmlTargetKind::Topic => name == "Topic",
        XmlTargetKind::CloudFunction => name == "CloudFunction",
        XmlTargetKind::LambdaFunction => {
            matches!(
                name,
                "LambdaFunctionArn" | "LambdaFunction" | "CloudFunction"
            )
        }
    }
}

fn leaf_text(node: &XmlNode) -> Result<String, S3Error> {
    if !node.children.is_empty() {
        return Err(invalid("notification field must contain text only"));
    }
    Ok(node.text.clone())
}

fn parse_filter(node: &XmlNode) -> Result<Vec<FilterRule>, S3Error> {
    if !node.text.is_empty() || node.children.len() != 1 || node.children[0].name != "S3Key" {
        return Err(invalid("Filter must contain exactly one S3Key"));
    }
    let s3_key = &node.children[0];
    if !s3_key.text.is_empty() {
        return Err(invalid("invalid S3Key filter"));
    }
    let mut rules = Vec::new();
    for child in &s3_key.children {
        if child.name != "FilterRule" || !child.text.is_empty() {
            return Err(invalid("invalid S3Key filter rule"));
        }
        let mut name = None;
        let mut value = None;
        for field in &child.children {
            match field.name.as_str() {
                "Name" if name.is_none() => {
                    name = Some(match leaf_text(field)?.as_str() {
                        "prefix" => FilterRuleName::Prefix,
                        "suffix" => FilterRuleName::Suffix,
                        _ => return Err(invalid("filter rule name must be prefix or suffix")),
                    });
                }
                "Value" if value.is_none() => value = Some(leaf_text(field)?),
                _ => return Err(invalid("invalid filter rule field")),
            }
        }
        let name = name.ok_or_else(|| invalid("filter rule Name is required"))?;
        let value = value.ok_or_else(|| invalid("filter rule Value is required"))?;
        if rules.iter().any(|rule: &FilterRule| rule.name == name) {
            return Err(invalid("duplicate filter rule name"));
        }
        rules.push(FilterRule { name, value });
    }
    if rules.is_empty() {
        return Err(invalid("S3Key requires at least one FilterRule"));
    }
    Ok(rules)
}

pub fn configuration_xml(configuration: &NotificationConfiguration) -> String {
    let mut xml = String::new();
    for target in &configuration.queues {
        xml.push_str(&target_xml(target));
    }
    for target in &configuration.topics {
        xml.push_str(&target_xml(target));
    }
    for target in &configuration.lambdas {
        xml.push_str(&target_xml(target));
    }
    if configuration.event_bridge {
        xml.push_str("<EventBridgeConfiguration/>");
    }
    xml
}

fn target_xml(target: &TargetConfiguration) -> String {
    let (config_name, arn_name) = match target.xml_kind {
        XmlTargetKind::Queue => ("QueueConfiguration", "Queue"),
        XmlTargetKind::Topic => ("TopicConfiguration", "Topic"),
        XmlTargetKind::CloudFunction => ("CloudFunctionConfiguration", "CloudFunction"),
        XmlTargetKind::LambdaFunction => ("LambdaFunctionConfiguration", "LambdaFunctionArn"),
    };
    let mut xml = format!(
        "<{config_name}>{}{}",
        text_el("Id", &target.id),
        text_el(arn_name, &target.arn)
    );
    for event in &target.events {
        xml.push_str(&text_el("Event", event.as_str()));
    }
    if !target.filter_rules.is_empty() {
        xml.push_str("<Filter><S3Key>");
        for rule in &target.filter_rules {
            let name = match rule.name {
                FilterRuleName::Prefix => "prefix",
                FilterRuleName::Suffix => "suffix",
            };
            xml.push_str(&format!(
                "<FilterRule>{}{}</FilterRule>",
                text_el("Name", name),
                text_el("Value", &rule.value)
            ));
        }
        xml.push_str("</S3Key></Filter>");
    }
    xml.push_str(&format!("</{config_name}>"));
    xml
}
fn target_matches(target: &TargetConfiguration, event: &ObjectEvent) -> bool {
    target
        .events
        .iter()
        .any(|configured| configured.matches(event.event_type))
        && target.filter_rules.iter().all(|rule| match rule.name {
            FilterRuleName::Prefix => event.key.starts_with(&rule.value),
            FilterRuleName::Suffix => event.key.ends_with(&rule.value),
        })
}

pub fn delivery_requests(
    event: &ObjectEvent,
    account: &str,
    caller_account: &str,
    region: &str,
    request_id: &str,
    source_ip: &str,
) -> Vec<DeliveryRequest> {
    let mut requests = Vec::new();
    for target in &event.configuration.lambdas {
        if target_matches(target, event) {
            let payload = record_payload(
                event,
                target,
                account,
                caller_account,
                region,
                request_id,
                source_ip,
            );
            if let Some(request) = lambda_request(&target.arn, payload) {
                requests.push(request);
            }
        }
    }
    for target in &event.configuration.queues {
        if target_matches(target, event) {
            let payload = record_payload(
                event,
                target,
                account,
                caller_account,
                region,
                request_id,
                source_ip,
            );
            if let Some(request) = queue_request(&target.arn, payload) {
                requests.push(request);
            }
        }
    }
    for target in &event.configuration.topics {
        if target_matches(target, event) {
            let payload = record_payload(
                event,
                target,
                account,
                caller_account,
                region,
                request_id,
                source_ip,
            );
            requests.push(topic_request(&target.arn, payload));
        }
    }
    if event.configuration.event_bridge {
        requests.push(event_bridge_request(
            event,
            caller_account,
            request_id,
            source_ip,
        ));
    }
    requests
}

pub fn coalesce_event_bridge(requests: Vec<DeliveryRequest>) -> Vec<DeliveryRequest> {
    let mut other = Vec::new();
    let mut entries = Vec::new();
    for request in requests {
        if request.target != DeliveryTarget::EventBridge {
            other.push(request);
            continue;
        }
        if let Ok(mut body) = serde_json::from_slice::<Value>(&request.body) {
            if let Some(values) = body
                .get_mut("Entries")
                .and_then(Value::as_array_mut)
                .map(std::mem::take)
            {
                entries.extend(values);
            }
        }
    }
    for chunk in entries.chunks(10) {
        other.push(json_request(
            DeliveryTarget::EventBridge,
            "AWSEvents.PutEvents",
            "application/x-amz-json-1.1",
            json!({"Entries": chunk}),
        ));
    }
    other
}

fn record_payload(
    event: &ObjectEvent,
    target: &TargetConfiguration,
    account: &str,
    caller_account: &str,
    region: &str,
    request_id: &str,
    source_ip: &str,
) -> String {
    let mut object = Map::new();
    object.insert("key".into(), json!(event_key(&event.key)));
    if let Some(size) = event.size {
        object.insert("size".into(), json!(size));
    }
    if let Some(etag) = &event.etag {
        object.insert("eTag".into(), json!(etag.trim_matches('"')));
    }
    if let Some(version_id) = &event.version_id {
        object.insert("versionId".into(), json!(version_id));
    }
    object.insert("sequencer".into(), json!(event.sequencer));
    json!({
        "Records": [{
            "eventVersion": "2.1",
            "eventSource": "aws:s3",
            "awsRegion": region,
            "eventTime": event.time.format(&Rfc3339).unwrap_or_default(),
            "eventName": event.event_type.event_name(),
            "userIdentity": {"principalId": caller_account},
            "requestParameters": {"sourceIPAddress": source_ip},
            "responseElements": {"x-amz-request-id": request_id},
            "s3": {
                "s3SchemaVersion": "1.0",
                "configurationId": target.id,
                "bucket": {
                    "name": event.bucket,
                    "ownerIdentity": {"principalId": account},
                    "arn": format!("arn:aws:s3:::{}", event.bucket)
                },
                "object": Value::Object(object)
            }
        }]
    })
    .to_string()
}

fn event_bridge_request(
    event: &ObjectEvent,
    account: &str,
    request_id: &str,
    source_ip: &str,
) -> DeliveryRequest {
    let mut object = Map::new();
    object.insert("key".into(), json!(&event.key));
    object.insert("sequencer".into(), json!(event.sequencer));
    if let Some(size) = event.size {
        object.insert("size".into(), json!(size));
    }
    if let Some(etag) = &event.etag {
        object.insert("etag".into(), json!(etag.trim_matches('"')));
    }
    if let Some(version_id) = &event.version_id {
        object.insert("version-id".into(), json!(version_id));
    }
    let mut detail = json!({
        "version": "0",
        "bucket": {"name": event.bucket},
        "object": Value::Object(object),
        "request-id": request_id,
        "requester": account,
        "source-ip-address": source_ip,
        "reason": event.reason,
    });
    if event.event_type.detail_type() == "Object Deleted" {
        detail["deletion-type"] = json!(if event.event_type
            == EventType::ObjectRemovedDeleteMarkerCreated
        {
            "Delete Marker Created"
        } else {
            "Permanently Deleted"
        });
    }
    let body = json!({
        "Entries": [{
            "Source": "aws.s3",
            "DetailType": event.event_type.detail_type(),
            "Detail": detail.to_string(),
            "Resources": [format!("arn:aws:s3:::{}", event.bucket)]
        }]
    });
    json_request(
        DeliveryTarget::EventBridge,
        "AWSEvents.PutEvents",
        "application/x-amz-json-1.1",
        body,
    )
}

fn lambda_request(arn: &str, payload: String) -> Option<DeliveryRequest> {
    let resource = arn.splitn(7, ':').nth(6)?;
    let name = resource.strip_prefix("function:").unwrap_or(resource);
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-invocation-type", HeaderValue::from_static("Event"));
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    Some(DeliveryRequest {
        target: DeliveryTarget::Lambda,
        arn: Some(arn.to_string()),
        method: Method::POST,
        uri: format!("/2015-03-31/functions/{name}/invocations")
            .parse()
            .ok()?,
        headers,
        body: Bytes::from(payload),
    })
}

fn queue_request(arn: &str, payload: String) -> Option<DeliveryRequest> {
    let parts = arn.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return None;
    }
    let body = json!({
        "QueueUrl": format!("https://sqs.{}.amazonaws.com/{}/{}", parts[3], parts[4], parts[5]),
        "MessageBody": payload
    });
    let mut request = json_request(
        DeliveryTarget::Queue,
        "AmazonSQS.SendMessage",
        "application/x-amz-json-1.0",
        body,
    );
    request.arn = Some(arn.to_string());
    Some(request)
}

fn topic_request(arn: &str, payload: String) -> DeliveryRequest {
    let body = format!(
        "Action=Publish&TopicArn={}&Message={}",
        form_encode(arn),
        form_encode(&payload)
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    DeliveryRequest {
        target: DeliveryTarget::Topic,
        arn: Some(arn.to_string()),
        method: Method::POST,
        uri: "/".parse().expect("SNS URI is valid"),
        headers,
        body: Bytes::from(body),
    }
}

fn json_request(
    target: DeliveryTarget,
    operation: &'static str,
    content_type: &'static str,
    body: Value,
) -> DeliveryRequest {
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-target", HeaderValue::from_static(operation));
    headers.insert("content-type", HeaderValue::from_static(content_type));
    DeliveryRequest {
        target,
        arn: None,
        method: Method::POST,
        uri: "/".parse().expect("JSON service URI is valid"),
        headers,
        body: Bytes::from(body.to_string()),
    }
}

fn event_key(key: &str) -> String {
    let mut encoded = String::with_capacity(key.len());
    for byte in key.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn form_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_targets() -> NotificationConfiguration {
        parse_configuration(concat!(
            "<NotificationConfiguration>",
            "<QueueConfiguration><Id>queue-id</Id><Queue>arn:aws:sqs:eu-west-1:123456789012:q</Queue><Event>s3:ObjectCreated:*</Event><Filter><S3Key><FilterRule><Name>prefix</Name><Value>in/</Value></FilterRule><FilterRule><Name>suffix</Name><Value>.txt</Value></FilterRule></S3Key></Filter></QueueConfiguration>",
            "<TopicConfiguration><Id>topic-id</Id><Topic>arn:aws:sns:eu-west-1:123456789012:t</Topic><Event>s3:ObjectCreated:Put</Event></TopicConfiguration>",
            "<CloudFunctionConfiguration><Id>lambda-id</Id><CloudFunction>arn:aws:lambda:eu-west-1:123456789012:function:fn</CloudFunction><Event>s3:ObjectCreated:Put</Event></CloudFunctionConfiguration>",
            "<EventBridgeConfiguration/>",
            "</NotificationConfiguration>"
        ).as_bytes()).unwrap()
    }

    fn event(configuration: NotificationConfiguration, key: &str) -> ObjectEvent {
        ObjectEvent {
            bucket: "bucket".into(),
            key: key.into(),
            event_type: EventType::ObjectCreatedPut,
            reason: "PutObject",
            time: OffsetDateTime::UNIX_EPOCH,
            size: Some(4),
            etag: Some("\"etag\"".into()),
            version_id: Some("v1".into()),
            sequencer: "0001".into(),
            configuration,
        }
    }

    #[test]
    fn configuration_round_trips_ids_aliases_and_filters() {
        let configuration = all_targets();
        assert_eq!(configuration.queues[0].id, "queue-id");
        assert_eq!(configuration.queues[0].filter_rules.len(), 2);
        let xml = configuration_xml(&configuration);
        assert!(xml.contains("<CloudFunctionConfiguration>"));
        assert!(xml.contains("<Id>lambda-id</Id>"));
        assert!(xml.contains("<EventBridgeConfiguration/>"));

        let alias = parse_configuration(b"<NotificationConfiguration><LambdaFunctionConfiguration><LambdaFunctionArn>arn:aws:lambda:us-east-1:1:function:f</LambdaFunctionArn><Event>s3:ObjectRemoved:*</Event></LambdaFunctionConfiguration></NotificationConfiguration>").unwrap();
        assert!(configuration_xml(&alias).contains("<LambdaFunctionConfiguration>"));
        assert_eq!(alias.lambdas[0].id, "locallycloud-lambda-0");
    }

    #[test]
    fn validation_is_strict_and_empty_clears() {
        assert!(parse_configuration(b"<NotificationConfiguration/>")
            .unwrap()
            .is_empty());
        for invalid_xml in [
            "<NotificationConfiguration><QueueConfiguration><Queue>arn:aws:sqs:r:a:q</Queue></QueueConfiguration></NotificationConfiguration>",
            "<NotificationConfiguration><TopicConfiguration><Topic>arn:aws:sns:r:a:t</Topic><Event>s3:ObjectRestore:Completed</Event></TopicConfiguration></NotificationConfiguration>",
            "<NotificationConfiguration><QueueConfiguration><Queue>arn:aws:sqs:r:a:q</Queue><Event>s3:ObjectCreated:*</Event><Filter><S3Key><FilterRule><Name>contains</Name><Value>x</Value></FilterRule></S3Key></Filter></QueueConfiguration></NotificationConfiguration>",
        ] {
            assert!(matches!(
                parse_configuration(invalid_xml.as_bytes()),
                Err(S3Error::InvalidArgument(_))
            ));
        }
    }

    #[test]
    fn filters_require_prefix_and_suffix_and_shapes_cover_every_target() {
        let configuration = all_targets();
        let requests = delivery_requests(
            &event(configuration.clone(), "in/a b.txt"),
            "123456789012",
            "111111111111",
            "eu-west-1",
            "rid",
            "127.0.0.1",
        );
        assert_eq!(requests.len(), 4);
        assert!(requests
            .iter()
            .any(|request| request.target == DeliveryTarget::Lambda));
        assert!(requests
            .iter()
            .any(|request| request.target == DeliveryTarget::Queue));
        assert!(requests
            .iter()
            .any(|request| request.target == DeliveryTarget::Topic));
        assert!(requests
            .iter()
            .any(|request| request.target == DeliveryTarget::EventBridge));

        let lambda = requests
            .iter()
            .find(|request| request.target == DeliveryTarget::Lambda)
            .unwrap();
        let body: Value = serde_json::from_slice(&lambda.body).unwrap();
        let record = &body["Records"][0];
        assert_eq!(record["userIdentity"]["principalId"], "111111111111");
        assert_eq!(
            record["s3"]["bucket"]["ownerIdentity"]["principalId"],
            "123456789012"
        );
        assert_eq!(record["eventVersion"], "2.1");
        assert_eq!(record["eventSource"], "aws:s3");
        assert_eq!(record["awsRegion"], "eu-west-1");
        assert_eq!(record["s3"]["configurationId"], "lambda-id");
        assert_eq!(record["s3"]["object"]["key"], "in%2Fa+b.txt");
        assert_eq!(record["s3"]["object"]["versionId"], "v1");

        let filtered = delivery_requests(
            &event(configuration, "out/a.txt"),
            "123456789012",
            "111111111111",
            "eu-west-1",
            "rid",
            "127.0.0.1",
        );
        assert_eq!(filtered.len(), 3);
        assert!(!filtered
            .iter()
            .any(|request| request.target == DeliveryTarget::Queue));
    }
}
