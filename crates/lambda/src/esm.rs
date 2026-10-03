//! Event source mappings (ESM): lifecycle store + the poll→batch→invoke contract.
//!
//! The control plane creates/updates/deletes mappings for SQS, DynamoDB Streams, and Kinesis
//! sources. SQS mappings are backed by a production poller; stream-source polling remains a
//! control-plane-only surface until those services expose equivalent source adapters.

use std::collections::HashSet;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::to_bytes;
use bytes::Bytes;
use dashmap::DashMap;
use http::{HeaderMap, HeaderValue, Method, Uri};
use locallycloud_core::integration::identity::{CallerIdentity, IdentityPropagator};
use locallycloud_core::registry::ServiceRegistry;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::error::LambdaError;

/// The kind of event source, resolved from its ARN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    Sqs,
    DynamoDbStreams,
    Kinesis,
}

impl SourceType {
    /// Resolve from an event-source ARN (`arn:aws:<service>:...`).
    pub fn from_arn(arn: &str) -> Option<SourceType> {
        let service = arn.split(':').nth(2)?;
        match service {
            "sqs" => Some(SourceType::Sqs),
            "dynamodb"
                if arn.split(':').nth(5).is_some_and(|resource| {
                    resource.starts_with("table/") && resource.contains("/stream/")
                }) =>
            {
                Some(SourceType::DynamoDbStreams)
            }
            "kinesis"
                if arn
                    .split(':')
                    .nth(5)
                    .is_some_and(|resource| resource.starts_with("stream/")) =>
            {
                Some(SourceType::Kinesis)
            }
            _ => None,
        }
    }

    fn event_source(self) -> &'static str {
        match self {
            SourceType::Sqs => "aws:sqs",
            SourceType::DynamoDbStreams => "aws:dynamodb",
            SourceType::Kinesis => "aws:kinesis",
        }
    }
}

/// An event source mapping.
#[derive(Debug, Clone)]
pub struct EventSourceMapping {
    pub uuid: String,
    pub function_arn: String,
    pub event_source_arn: String,
    pub enabled: bool,
    pub batch_size: u32,
    pub maximum_batching_window_in_seconds: u32,
    pub function_response_types: Vec<String>,
    pub state: String,
    pub last_modified: f64,
    pub starting_position: Option<String>,
}

impl EventSourceMapping {
    pub fn to_json(&self) -> Value {
        let mut function_arn_parts = self.function_arn.split(':');
        let region = function_arn_parts.nth(3).unwrap_or_default();
        let account = function_arn_parts.next().unwrap_or_default();
        let mut v = json!({
            "UUID": self.uuid,
            "EventSourceMappingArn": format!(
                "arn:aws:lambda:{region}:{account}:event-source-mapping:{}",
                self.uuid
            ),
            "FunctionArn": self.function_arn,
            "EventSourceArn": self.event_source_arn,
            "BatchSize": self.batch_size,
            "MaximumBatchingWindowInSeconds": self.maximum_batching_window_in_seconds,
            "FunctionResponseTypes": self.function_response_types,
            "State": self.state,
            "StateTransitionReason": "USER_INITIATED",
            "LastModified": self.last_modified,
        });
        if let Some(pos) = &self.starting_position {
            v["StartingPosition"] = json!(pos);
        }
        v
    }

    pub fn reports_batch_item_failures(&self) -> bool {
        self.function_response_types
            .iter()
            .any(|value| value == "ReportBatchItemFailures")
    }
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// ESM store keyed by UUID.
#[derive(Default)]
pub struct EsmStore {
    mappings: DashMap<String, EventSourceMapping>,
}

impl EsmStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, esm: EventSourceMapping) {
        self.mappings.insert(esm.uuid.clone(), esm);
    }

    pub fn get(&self, uuid: &str) -> Option<EventSourceMapping> {
        self.mappings.get(uuid).map(|e| e.clone())
    }

    pub fn remove(&self, uuid: &str) -> Option<EventSourceMapping> {
        self.mappings.remove(uuid).map(|(_, v)| v)
    }

    pub fn update<F: FnOnce(&mut EventSourceMapping)>(
        &self,
        uuid: &str,
        f: F,
    ) -> Option<EventSourceMapping> {
        let mut e = self.mappings.get_mut(uuid)?;
        f(&mut e);
        e.last_modified = now();
        Some(e.clone())
    }

    /// All mappings, optionally filtered by function ARN and/or event-source ARN.
    pub fn list(
        &self,
        function_arn: Option<&str>,
        source_arn: Option<&str>,
    ) -> Vec<EventSourceMapping> {
        let mut out: Vec<EventSourceMapping> = self
            .mappings
            .iter()
            .filter(|e| function_arn.map(|f| e.function_arn == f).unwrap_or(true))
            .filter(|e| source_arn.map(|s| e.event_source_arn == s).unwrap_or(true))
            .map(|e| e.clone())
            .collect();
        out.sort_by(|a, b| a.uuid.cmp(&b.uuid));
        out
    }
}

fn response_types(input: &Value) -> Result<Vec<String>, LambdaError> {
    let Some(values) = input.get("FunctionResponseTypes") else {
        return Ok(Vec::new());
    };
    let values = values.as_array().ok_or_else(|| {
        LambdaError::InvalidParameterValue("FunctionResponseTypes must be an array".into())
    })?;
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let value = value.as_str().ok_or_else(|| {
            LambdaError::InvalidParameterValue(
                "FunctionResponseTypes entries must be strings".into(),
            )
        })?;
        if value != "ReportBatchItemFailures" || result.iter().any(|item| item == value) {
            return Err(LambdaError::InvalidParameterValue(format!(
                "unsupported FunctionResponseType: {value}"
            )));
        }
        result.push(value.to_string());
    }
    Ok(result)
}

pub fn validate_batch_size(_source_type: SourceType, batch_size: u64) -> Result<u32, LambdaError> {
    let max = 10_000;
    if !(1..=max).contains(&batch_size) {
        return Err(LambdaError::InvalidParameterValue(format!(
            "BatchSize for this event source must be between 1 and {max}"
        )));
    }
    Ok(batch_size as u32)
}

pub fn validate_batch_configuration(
    source_type: SourceType,
    source_arn: &str,
    batch_size: u32,
    window: u32,
) -> Result<(), LambdaError> {
    if source_type == SourceType::Sqs && source_arn.ends_with(".fifo") && batch_size > 10 {
        return Err(LambdaError::InvalidParameterValue(
            "BatchSize for an SQS FIFO queue must be between 1 and 10".into(),
        ));
    }
    if batch_size > 10 && window == 0 {
        return Err(LambdaError::InvalidParameterValue(
            "MaximumBatchingWindowInSeconds must be at least 1 when BatchSize exceeds 10".into(),
        ));
    }
    Ok(())
}

pub fn parse_batching_window(input: &Value, default: u32) -> Result<u32, LambdaError> {
    let Some(value) = input.get("MaximumBatchingWindowInSeconds") else {
        return Ok(default);
    };
    let Some(window) = value.as_u64().filter(|window| *window <= 300) else {
        return Err(LambdaError::InvalidParameterValue(
            "MaximumBatchingWindowInSeconds must be between 0 and 300".into(),
        ));
    };
    Ok(window as u32)
}

/// Create a mapping from the request. Validates the source ARN type, function/source region
/// match, source-specific batch size, and applies AWS defaults.
pub fn create_mapping(
    region: &str,
    function_arn: &str,
    input: &Value,
) -> Result<EventSourceMapping, LambdaError> {
    let source_arn = input
        .get("EventSourceArn")
        .and_then(Value::as_str)
        .ok_or_else(|| LambdaError::InvalidParameterValue("EventSourceArn is required".into()))?;
    let source_type = SourceType::from_arn(source_arn).ok_or_else(|| {
        LambdaError::InvalidParameterValue(format!("unsupported event source: {source_arn}"))
    })?;
    let source_region = source_arn.split(':').nth(3).unwrap_or("");
    if source_region != region {
        return Err(LambdaError::InvalidParameterValue(format!(
            "event source region {source_region} does not match {region}"
        )));
    }
    let default_batch_size = if source_type == SourceType::Sqs {
        10
    } else {
        100
    };
    let requested_batch_size = match input.get("BatchSize") {
        Some(value) => value.as_u64().ok_or_else(|| {
            LambdaError::InvalidParameterValue("BatchSize must be an integer".into())
        })?,
        None => default_batch_size,
    };
    let batch_size = validate_batch_size(source_type, requested_batch_size)?;
    let maximum_batching_window_in_seconds = parse_batching_window(input, 0)?;
    validate_batch_configuration(
        source_type,
        source_arn,
        batch_size,
        maximum_batching_window_in_seconds,
    )?;
    let enabled = input
        .get("Enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let starting_position = input
        .get("StartingPosition")
        .and_then(Value::as_str)
        .map(str::to_string);
    if matches!(
        source_type,
        SourceType::DynamoDbStreams | SourceType::Kinesis
    ) && starting_position.is_none()
    {
        return Err(LambdaError::InvalidParameterValue(
            "StartingPosition is required for stream sources".into(),
        ));
    }
    Ok(EventSourceMapping {
        uuid: Uuid::new_v4().to_string(),
        function_arn: function_arn.to_string(),
        event_source_arn: source_arn.to_string(),
        enabled,
        batch_size,
        maximum_batching_window_in_seconds,
        function_response_types: response_types(input)?,
        state: if enabled {
            "Enabled".into()
        } else {
            "Disabled".into()
        },
        last_modified: now(),
        starting_position,
    })
}

pub fn update_response_types(input: &Value) -> Result<Option<Vec<String>>, LambdaError> {
    input
        .get("FunctionResponseTypes")
        .map(|_| response_types(input))
        .transpose()
}

// ============================ poller ==========================================

/// A source record keeps the public failure identifier separate from its opaque ack token.
#[derive(Debug, Clone)]
pub struct SourceRecord {
    pub item_identifier: String,
    pub ack_token: String,
    pub body: Value,
}

#[async_trait]
pub trait BatchSource: Send + Sync {
    async fn poll(&self, max: u32, window: Duration) -> Result<Vec<SourceRecord>, String>;
    async fn ack(&self, tokens: &[String]) -> Result<(), String>;
}

pub fn build_batch_event(
    source_type: SourceType,
    source_arn: &str,
    records: &[SourceRecord],
) -> Value {
    let items: Vec<Value> = records
        .iter()
        .map(|record| {
            let mut item = record.body.clone();
            if let Some(object) = item.as_object_mut() {
                object
                    .entry("eventSource")
                    .or_insert_with(|| json!(source_type.event_source()));
                object
                    .entry("eventSourceARN")
                    .or_insert_with(|| json!(source_arn));
            }
            item
        })
        .collect();
    json!({ "Records": items })
}

fn failed_item_ids(response: &[u8], known: &HashSet<String>) -> Result<HashSet<String>, String> {
    if response.is_empty() {
        return Ok(HashSet::new());
    }
    let parsed: Value = serde_json::from_slice(response)
        .map_err(|_| "Lambda returned an invalid partial batch response".to_string())?;
    if parsed.is_null() {
        return Ok(HashSet::new());
    }
    let object = parsed
        .as_object()
        .ok_or_else(|| "Lambda partial batch response must be an object".to_string())?;
    let Some(failures) = object.get("batchItemFailures") else {
        return Ok(HashSet::new());
    };
    let failures = failures
        .as_array()
        .ok_or_else(|| "batchItemFailures must be an array".to_string())?;
    let mut failed = HashSet::new();
    for failure in failures {
        let identifier = failure
            .get("itemIdentifier")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "batchItemFailures entries require itemIdentifier".to_string())?;
        if !known.contains(identifier) {
            return Err(format!(
                "batchItemFailures references unknown itemIdentifier {identifier}"
            ));
        }
        failed.insert(identifier.to_string());
    }
    Ok(failed)
}

/// Run one poll cycle. A hard invocation failure or malformed partial response leaves the entire
/// batch unacknowledged so SQS visibility/redrive semantics remain authoritative.
pub async fn poll_once<F, Fut>(
    mapping: &EventSourceMapping,
    source: &Arc<dyn BatchSource>,
    run: F,
) -> Result<bool, String>
where
    F: FnOnce(Value) -> Fut,
    Fut: std::future::Future<Output = Option<Vec<u8>>>,
{
    if !mapping.enabled {
        return Ok(false);
    }
    let source_type = SourceType::from_arn(&mapping.event_source_arn)
        .ok_or_else(|| "unsupported event source".to_string())?;
    let records = source
        .poll(
            mapping.batch_size,
            Duration::from_secs(mapping.maximum_batching_window_in_seconds.into()),
        )
        .await?;
    if records.is_empty() {
        return Ok(false);
    }
    let event = build_batch_event(source_type, &mapping.event_source_arn, &records);
    let Some(response) = run(event).await else {
        return Ok(true);
    };

    let failed = if mapping.reports_batch_item_failures() {
        let known = records
            .iter()
            .map(|record| record.item_identifier.clone())
            .collect();
        failed_item_ids(&response, &known)?
    } else {
        HashSet::new()
    };
    let succeeded: Vec<String> = records
        .iter()
        .filter(|record| !failed.contains(&record.item_identifier))
        .map(|record| record.ack_token.clone())
        .collect();
    if !succeeded.is_empty() {
        source.ack(&succeeded).await?;
    }
    Ok(true)
}

/// SQS adapter that talks through locallycloud's scoped in-process dispatcher.
pub struct SqsBatchSource {
    registry: Weak<ServiceRegistry>,
    queue_url: String,
    source_arn: String,
    account: String,
    region: String,
}

impl SqsBatchSource {
    pub fn new(
        registry: Weak<ServiceRegistry>,
        source_arn: &str,
        account: &str,
        region: &str,
    ) -> Result<Self, String> {
        let parts: Vec<&str> = source_arn.split(':').collect();
        if parts.len() != 6
            || parts[2] != "sqs"
            || parts[3] != region
            || parts[4] != account
            || parts[5].is_empty()
        {
            return Err("invalid or cross-scope SQS event source ARN".into());
        }
        Ok(Self {
            registry,
            queue_url: format!("https://sqs.{region}.amazonaws.com/{account}/{}", parts[5]),
            source_arn: source_arn.to_string(),
            account: account.to_string(),
            region: region.to_string(),
        })
    }

    async fn dispatch(&self, target: &str, body: Value) -> Result<Value, String> {
        let registry = self
            .registry
            .upgrade()
            .ok_or_else(|| "service registry is unavailable".to_string())?;
        let dispatcher = registry
            .internal_dispatcher()
            .ok_or_else(|| "internal dispatcher is unavailable".to_string())?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(target).map_err(|error| error.to_string())?,
        );
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-amz-json-1.0"),
        );
        let uri: Uri = "/"
            .parse()
            .map_err(|error: http::uri::InvalidUri| error.to_string())?;
        IdentityPropagator::attach(
            &mut headers,
            &CallerIdentity::ServicePrincipal {
                service: "lambda".into(),
            },
        );
        let response = dispatcher
            .dispatch_scoped(
                &Method::POST,
                &uri,
                &headers,
                Bytes::from(body.to_string()),
                &Uuid::new_v4().to_string(),
                &self.account,
                &self.region,
            )
            .await;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|error| error.to_string())?;
        if !status.is_success() {
            return Err(format!(
                "{target} failed with {status}: {}",
                String::from_utf8_lossy(&bytes)
            ));
        }
        if bytes.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())
        }
    }
}

fn lambda_message_attributes(value: Option<&Value>) -> Value {
    let mut output = Map::new();
    for (name, attribute) in value.and_then(Value::as_object).into_iter().flatten() {
        let mut normalized = Map::new();
        for (wire, event) in [
            ("StringValue", "stringValue"),
            ("BinaryValue", "binaryValue"),
            ("StringListValues", "stringListValues"),
            ("BinaryListValues", "binaryListValues"),
            ("DataType", "dataType"),
        ] {
            if let Some(value) = attribute.get(wire) {
                normalized.insert(event.to_string(), value.clone());
            }
        }
        output.insert(name.clone(), Value::Object(normalized));
    }
    Value::Object(output)
}

#[async_trait]
impl BatchSource for SqsBatchSource {
    async fn poll(&self, max: u32, window: Duration) -> Result<Vec<SourceRecord>, String> {
        let window = if self.source_arn.ends_with(".fifo") {
            Duration::ZERO
        } else {
            window
        };
        let mut records = Vec::new();
        let mut deadline = Instant::now();
        loop {
            let response = self
                .dispatch(
                    "AmazonSQS.ReceiveMessage",
                    json!({
                        "QueueUrl": self.queue_url,
                        "MaxNumberOfMessages": (max as usize - records.len()).min(10),
                        "WaitTimeSeconds": 1,
                        "MessageSystemAttributeNames": ["All"],
                        "MessageAttributeNames": ["All"]
                    }),
                )
                .await;
            let response = match response {
                Ok(response) => response,
                Err(error) if records.is_empty() => return Err(error),
                Err(_) => break,
            };
            if records.is_empty() {
                deadline = Instant::now() + window;
            }
            let received: Vec<SourceRecord> = response
            .get("Messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|message| {
                let message_id = message
                    .get("MessageId")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "SQS message is missing MessageId".to_string())?;
                let receipt = message
                    .get("ReceiptHandle")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "SQS message is missing ReceiptHandle".to_string())?;
                Ok::<SourceRecord, String>(SourceRecord {
                    item_identifier: message_id.to_string(),
                    ack_token: receipt.to_string(),
                    body: json!({
                        "messageId": message_id,
                        "receiptHandle": receipt,
                        "body": message.get("Body").and_then(Value::as_str).unwrap_or_default(),
                        "attributes": message.get("Attributes").cloned().unwrap_or_else(|| json!({})),
                        "messageAttributes": lambda_message_attributes(message.get("MessageAttributes")),
                        "md5OfBody": message.get("MD5OfBody").and_then(Value::as_str).unwrap_or_default(),
                        "eventSource": "aws:sqs",
                        "eventSourceARN": self.source_arn,
                        "awsRegion": self.region,
                    }),
                })
            })
            .collect::<Result<_, _>>()?;
            if received.is_empty() {
                if records.is_empty() || Instant::now() >= deadline {
                    break;
                }
                continue;
            }
            records.extend(received);
            if records.len() >= max as usize || window.is_zero() || Instant::now() >= deadline {
                break;
            }
        }
        Ok(records)
    }

    async fn ack(&self, tokens: &[String]) -> Result<(), String> {
        for chunk in tokens.chunks(10) {
            let entries: Vec<Value> = chunk
                .iter()
                .enumerate()
                .map(|(index, token)| json!({"Id": index.to_string(), "ReceiptHandle": token}))
                .collect();
            let response = self
                .dispatch(
                    "AmazonSQS.DeleteMessageBatch",
                    json!({"QueueUrl": self.queue_url, "Entries": entries}),
                )
                .await?;
            let failures = response
                .get("Failed")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if !failures.is_empty() {
                return Err(format!(
                    "SQS batch delete failed: {}",
                    Value::Array(failures.to_vec())
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn source_type_from_arn() {
        assert_eq!(
            SourceType::from_arn("arn:aws:sqs:us-east-1:0:q"),
            Some(SourceType::Sqs)
        );
        assert_eq!(
            SourceType::from_arn("arn:aws:dynamodb:us-east-1:0:table/t/stream/1"),
            Some(SourceType::DynamoDbStreams)
        );
        assert_eq!(SourceType::from_arn("arn:aws:s3:::b"), None);
    }

    #[test]
    fn create_validates_and_defaults() {
        let input = json!({ "EventSourceArn": "arn:aws:sqs:us-east-1:0:q" });
        let esm =
            create_mapping("us-east-1", "arn:aws:lambda:us-east-1:0:function:f", &input).unwrap();
        assert_eq!(esm.batch_size, 10);
        assert!(esm.enabled);
        assert_eq!(esm.state, "Enabled");
        assert!(esm.function_response_types.is_empty());

        let bad = json!({ "EventSourceArn": "arn:aws:sqs:eu-west-1:0:q" });
        assert!(create_mapping("us-east-1", "arn", &bad).is_err());
        let oversized = json!({ "EventSourceArn": "arn:aws:sqs:us-east-1:0:q", "BatchSize": 11 });
        assert!(create_mapping("us-east-1", "arn", &oversized).is_err());
        let stream = json!({ "EventSourceArn": "arn:aws:kinesis:us-east-1:0:stream/s" });
        assert!(create_mapping("us-east-1", "arn", &stream).is_err());
    }

    #[test]
    fn sqs_large_batch_requires_window_and_standard_queue() {
        let arn = "arn:aws:sqs:us-east-1:0:q";
        let function = "arn:aws:lambda:us-east-1:0:function:f";
        let large = json!({
            "EventSourceArn": arn,
            "BatchSize": 15,
            "MaximumBatchingWindowInSeconds": 1,
        });
        let mapping = create_mapping("us-east-1", function, &large).unwrap();
        assert_eq!(mapping.batch_size, 15);
        assert_eq!(mapping.maximum_batching_window_in_seconds, 1);
        assert_eq!(mapping.to_json()["MaximumBatchingWindowInSeconds"], 1);

        let no_window = json!({"EventSourceArn": arn, "BatchSize": 15});
        assert!(create_mapping("us-east-1", function, &no_window).is_err());
        let fifo = json!({
            "EventSourceArn": "arn:aws:sqs:us-east-1:0:q.fifo",
            "BatchSize": 15,
            "MaximumBatchingWindowInSeconds": 1,
        });
        assert!(create_mapping("us-east-1", function, &fifo).is_err());
        assert!(parse_batching_window(&json!({"MaximumBatchingWindowInSeconds": 301}), 0).is_err());
    }

    struct MemSource {
        available: Mutex<Vec<SourceRecord>>,
        acked: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl BatchSource for MemSource {
        async fn poll(&self, max: u32, _window: Duration) -> Result<Vec<SourceRecord>, String> {
            let mut available = self.available.lock().unwrap();
            let count = (max as usize).min(available.len());
            Ok(available.drain(..count).collect())
        }

        async fn ack(&self, tokens: &[String]) -> Result<(), String> {
            self.acked.lock().unwrap().extend_from_slice(tokens);
            Ok(())
        }
    }

    fn mapping(response_types: Vec<String>) -> EventSourceMapping {
        EventSourceMapping {
            uuid: "u".into(),
            function_arn: "arn".into(),
            event_source_arn: "arn:aws:sqs:us-east-1:0:q".into(),
            enabled: true,
            batch_size: 10,
            maximum_batching_window_in_seconds: 0,
            function_response_types: response_types,
            state: "Enabled".into(),
            last_modified: 0.0,
            starting_position: None,
        }
    }

    #[tokio::test]
    async fn poll_once_acks_only_succeeded_records() {
        let mem = Arc::new(MemSource {
            available: Mutex::new(vec![
                SourceRecord {
                    item_identifier: "a".into(),
                    ack_token: "receipt-a".into(),
                    body: json!({"messageId":"a"}),
                },
                SourceRecord {
                    item_identifier: "b".into(),
                    ack_token: "receipt-b".into(),
                    body: json!({"messageId":"b"}),
                },
            ]),
            acked: Mutex::new(Vec::new()),
        });
        let source: Arc<dyn BatchSource> = mem.clone();
        poll_once(
            &mapping(vec!["ReportBatchItemFailures".into()]),
            &source,
            |event| async move {
                assert_eq!(event["Records"].as_array().unwrap().len(), 2);
                assert_eq!(event["Records"][0]["eventSource"], "aws:sqs");
                Some(br#"{"batchItemFailures":[{"itemIdentifier":"b"}]}"#.to_vec())
            },
        )
        .await
        .unwrap();
        assert_eq!(*mem.acked.lock().unwrap(), vec!["receipt-a".to_string()]);
    }
}
