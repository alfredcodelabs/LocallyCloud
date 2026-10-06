//! Event source mappings (ESM): lifecycle store + the poll→batch→invoke contract.
//!
//! The control plane creates/updates/deletes mappings for SQS, DynamoDB Streams, and Kinesis
//! sources. SQS and Kinesis have source adapters; DynamoDB Streams remains control plane only.

mod kinesis;
mod persistence;
pub use kinesis::KinesisBatchSource;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::model::FunctionStore;
use async_trait::async_trait;
use axum::body::to_bytes;
use bytes::Bytes;
use dashmap::DashMap;
use http::{HeaderMap, HeaderValue, Method, Uri};
use locallycloud_core::integration::authorization::ServiceRoleAuthorizationRequest;
use locallycloud_core::integration::identity::{CallerIdentity, IdentityPropagator};
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSourceMapping {
    pub uuid: String,
    pub function_arn: String,
    pub event_source_arn: String,
    pub enabled: bool,
    pub batch_size: u32,
    pub maximum_batching_window_in_seconds: u32,
    pub function_response_types: Vec<String>,
    #[serde(default)]
    pub maximum_concurrency: Option<u32>,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    pub state: String,
    pub last_modified: f64,
    pub starting_position: Option<String>,
    #[serde(default)]
    pub starting_timestamp: f64,
    #[serde(default)]
    pub last_processing_result: Option<String>,
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
            "StateTransitionReason": self.last_processing_result.as_deref().unwrap_or("USER_INITIATED"),
            "LastModified": self.last_modified,
        });
        if let Some(maximum) = self.maximum_concurrency {
            v["ScalingConfig"] = json!({"MaximumConcurrency": maximum});
        }
        if let Some(result) = &self.last_processing_result {
            v["LastProcessingResult"] = json!(result);
        }
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
    persistence: std::sync::Mutex<Option<persistence::Persistence>>,
    checkpoints: DashMap<(String, String), (f64, Option<String>)>,
}

impl EsmStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, esm: EventSourceMapping) -> Result<(), LambdaError> {
        self.save(&esm)?;
        self.mappings.insert(esm.uuid.clone(), esm);
        Ok(())
    }

    /// Startup-only injection, before accepting requests or starting pollers.
    pub fn attach_state(&self, state: Arc<locallycloud_state::StateDb>) -> Result<(), LambdaError> {
        let persistence = persistence::Persistence::open(state)?;
        for mut mapping in persistence.load()? {
            if mapping.enabled {
                mapping.state = "Disabled".into();
                mapping.last_processing_result = Some("FunctionUnavailable".into());
            }
            self.mappings.insert(mapping.uuid.clone(), mapping);
        }
        for (key, checkpoint) in persistence.checkpoints()? {
            self.checkpoints.insert(key, checkpoint);
        }
        *self.persistence.lock().map_err(|_| state_error())? = Some(persistence);
        Ok(())
    }

    fn save(&self, mapping: &EventSourceMapping) -> Result<(), LambdaError> {
        if let Some(state) = self.persistence.lock().map_err(|_| state_error())?.as_ref() {
            state.save(mapping)?;
        }
        Ok(())
    }

    fn prepare_shard(
        &self,
        uuid: &str,
        shard: &str,
        generation: f64,
    ) -> Result<Option<String>, String> {
        let key = (uuid.to_string(), shard.to_string());
        if let Some(existing) = self.checkpoints.get(&key) {
            if existing.0 != generation {
                return Err("Kinesis source stream was replaced".into());
            }
            return Ok(existing.1.clone());
        }
        self.save_checkpoint(uuid, shard, generation, None)?;
        Ok(None)
    }

    fn save_checkpoint(
        &self,
        uuid: &str,
        shard: &str,
        generation: f64,
        sequence: Option<String>,
    ) -> Result<(), String> {
        if let Some(state) = self
            .persistence
            .lock()
            .map_err(|_| "ESM state lock failed")?
            .as_ref()
        {
            state
                .save_checkpoint(uuid, shard, generation, sequence.as_deref())
                .map_err(|e| e.to_string())?;
        }
        self.checkpoints
            .insert((uuid.into(), shard.into()), (generation, sequence));
        Ok(())
    }

    pub fn get(&self, uuid: &str) -> Option<EventSourceMapping> {
        self.mappings.get(uuid).map(|e| e.clone())
    }

    pub fn remove(&self, uuid: &str) -> Result<Option<EventSourceMapping>, LambdaError> {
        // Tag/update writers already hold this entry before saving; deletion must use
        // the same order so an overlapping writer cannot recreate a deleted row.
        let entry = self.mappings.entry(uuid.into());
        if let Some(state) = self.persistence.lock().map_err(|_| state_error())?.as_ref() {
            state.remove(uuid)?;
        }
        self.checkpoints.retain(|(id, _), _| id != uuid);
        Ok(match entry {
            dashmap::mapref::entry::Entry::Occupied(entry) => Some(entry.remove()),
            dashmap::mapref::entry::Entry::Vacant(_) => None,
        })
    }

    pub fn update<F: FnOnce(&mut EventSourceMapping)>(
        &self,
        uuid: &str,
        f: F,
    ) -> Result<Option<EventSourceMapping>, LambdaError> {
        let Some(mut e) = self.mappings.get_mut(uuid) else {
            return Ok(None);
        };
        let mut next = e.clone();
        f(&mut next);
        next.last_modified = now();
        self.save(&next)?;
        *e = next.clone();
        Ok(Some(next))
    }

    pub fn tag(&self, uuid: &str, tags: BTreeMap<String, String>) -> Result<(), LambdaError> {
        let mut mapping = self.mappings.get_mut(uuid).ok_or_else(|| {
            LambdaError::ResourceNotFound(format!("Event source mapping not found: {uuid}"))
        })?;
        let mut next = mapping.clone();
        next.tags.extend(tags);
        if next.tags.len() > 50 {
            return Err(LambdaError::InvalidParameterValue(
                "Maximum 50 tags allowed".into(),
            ));
        }
        self.save(&next)?;
        *mapping = next;
        Ok(())
    }

    pub fn set_processing_result(&self, uuid: &str, result: String) -> Result<(), LambdaError> {
        let Some(mut mapping) = self.mappings.get_mut(uuid) else {
            return Ok(());
        };
        if mapping.last_processing_result.as_deref() == Some(&result) {
            return Ok(());
        }
        let mut next = mapping.clone();
        next.last_processing_result = Some(result);
        self.save(&next)?;
        *mapping = next;
        Ok(())
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
    if source_type == SourceType::Sqs && batch_size > 10 && window == 0 {
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
        maximum_concurrency: parse_scaling_config(input, source_type)?.flatten(),
        tags: parse_tags(input.get("Tags"))?,
        state: if enabled {
            "Enabled".into()
        } else {
            "Disabled".into()
        },
        last_modified: now(),
        starting_position,
        starting_timestamp: now(),
        last_processing_result: None,
    })
}

pub fn parse_tags(value: Option<&Value>) -> Result<BTreeMap<String, String>, LambdaError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let tags = value
        .as_object()
        .ok_or_else(|| LambdaError::InvalidParameterValue("Tags must be a string map".into()))?;
    if tags.len() > 50 {
        return Err(LambdaError::InvalidParameterValue(
            "Maximum 50 tags allowed".into(),
        ));
    }
    tags.iter()
        .map(|(key, value)| {
            let value = value.as_str().ok_or_else(|| {
                LambdaError::InvalidParameterValue("Tag values must be strings".into())
            })?;
            if key.is_empty()
                || key.chars().count() > 128
                || value.chars().count() > 256
                || key.to_ascii_lowercase().starts_with("aws:")
            {
                return Err(LambdaError::InvalidParameterValue(
                    "Invalid tag key or value".into(),
                ));
            }
            Ok((key.clone(), value.to_string()))
        })
        .collect()
}

/// Outer Option distinguishes omitted updates from an explicit empty configuration.
pub fn parse_scaling_config(
    input: &Value,
    source: SourceType,
) -> Result<Option<Option<u32>>, LambdaError> {
    let Some(config) = input.get("ScalingConfig") else {
        return Ok(None);
    };
    let invalid = || {
        LambdaError::InvalidParameterValue(
            "ScalingConfig requires an SQS source and MaximumConcurrency between 2 and 1000".into(),
        )
    };
    if source != SourceType::Sqs {
        return Err(invalid());
    }
    let object = config.as_object().ok_or_else(invalid)?;
    if object.keys().any(|key| key != "MaximumConcurrency") {
        return Err(invalid());
    }
    let maximum = object
        .get("MaximumConcurrency")
        .map(|value| {
            value
                .as_u64()
                .filter(|value| (2..=1000).contains(value))
                .map(|value| value as u32)
                .ok_or_else(invalid)
        })
        .transpose()?;
    Ok(Some(maximum))
}

/// Cancellation drains aborted children before a replacement may admit new work.
pub async fn run_workers<F, Fut>(count: u32, mut cancel: tokio::sync::oneshot::Receiver<()>, run: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    if !matches!(
        cancel.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ) {
        return;
    }
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..count {
        workers.spawn(run());
    }
    loop {
        tokio::select! {
            biased;
            _ = &mut cancel => { workers.abort_all(); break; },
            next = workers.join_next() => if next.is_none() { break; },
        }
    }
    while workers.join_next().await.is_some() {}
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
        return Err("Lambda invocation failed".into());
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
    let mut blocked = false;
    let succeeded: Vec<String> = records
        .iter()
        .filter(|record| {
            let failed = failed.contains(&record.item_identifier);
            if source_type == SourceType::Kinesis {
                blocked |= failed;
                !blocked
            } else {
                !failed
            }
        })
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
    functions: Arc<FunctionStore>,
    function_name: String,
    queue_url: String,
    source_arn: String,
    account: String,
    region: String,
}

impl SqsBatchSource {
    pub fn new(
        registry: Weak<ServiceRegistry>,
        functions: Arc<FunctionStore>,
        function_arn: &str,
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
        let function_name = function_arn
            .split(":function:")
            .nth(1)
            .and_then(|name| name.split(':').next())
            .filter(|name| !name.is_empty())
            .ok_or("invalid function ARN")?
            .to_string();
        Ok(Self {
            registry,
            functions,
            function_name,
            queue_url: format!("https://sqs.{region}.amazonaws.com/{account}/{}", parts[5]),
            source_arn: source_arn.to_string(),
            account: account.to_string(),
            region: region.to_string(),
        })
    }

    pub async fn validate(&self) -> Result<(), String> {
        self.dispatch(
            "AmazonSQS.GetQueueAttributes",
            json!({
                "QueueUrl": self.queue_url, "AttributeNames": ["QueueArn"]
            }),
        )
        .await?;
        Ok(())
    }

    async fn dispatch(&self, target: &str, body: Value) -> Result<Value, String> {
        let registry = self
            .registry
            .upgrade()
            .ok_or("service registry is unavailable")?;
        let role = self
            .functions
            .execution_role(&self.account, &self.region, &self.function_name)
            .ok_or("FunctionUnavailable")?;
        let operation = target.rsplit('.').next().ok_or("invalid SQS operation")?;
        let action = match operation {
            "DeleteMessageBatch" => "DeleteMessage",
            operation => operation,
        };
        registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .ok_or("IAM is unavailable")?
            .authorize_service_role_execution(ServiceRoleAuthorizationRequest {
                source_arn: None,
                caller: RequestIdentity {
                    account_id: self.account.clone(),
                    access_key_id: None,
                    arn: None,
                },
                role_arn: role.clone(),
                service_principal: "lambda.amazonaws.com".into(),
                action: format!("sqs:{action}"),
                resource: self.source_arn.clone(),
            })
            .map_err(|_| "SQS execution role is not authorized")?;
        dispatch_source_as(
            &self.registry,
            &self.account,
            &self.region,
            target,
            body,
            CallerIdentity::AssumedRole {
                role_arn: role,
                session_name: "lambda-esm".into(),
            },
        )
        .await
    }
}

async fn dispatch_source(
    registry: &Weak<ServiceRegistry>,
    account: &str,
    region: &str,
    target: &str,
    body: Value,
) -> Result<Value, String> {
    dispatch_source_as(
        registry,
        account,
        region,
        target,
        body,
        CallerIdentity::ServicePrincipal {
            service: "lambda".into(),
        },
    )
    .await
}

async fn dispatch_source_as(
    registry: &Weak<ServiceRegistry>,
    account: &str,
    region: &str,
    target: &str,
    body: Value,
    identity: CallerIdentity,
) -> Result<Value, String> {
    let registry = registry
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
        HeaderValue::from_static(if target.starts_with("Kinesis_") {
            "application/x-amz-json-1.1"
        } else {
            "application/x-amz-json-1.0"
        }),
    );
    let uri: Uri = "/"
        .parse()
        .map_err(|error: http::uri::InvalidUri| error.to_string())?;
    IdentityPropagator::attach(&mut headers, &identity);
    let response = dispatcher
        .dispatch_scoped(
            &Method::POST,
            &uri,
            &headers,
            Bytes::from(body.to_string()),
            &Uuid::new_v4().to_string(),
            account,
            region,
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

fn state_error() -> LambdaError {
    LambdaError::InternalError("Lambda event source state is unavailable".into())
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
            maximum_concurrency: None,
            tags: BTreeMap::new(),
            state: "Enabled".into(),
            last_modified: 0.0,
            starting_position: None,
            starting_timestamp: now(),
            last_processing_result: None,
        }
    }

    #[test]
    fn scaling_config_validates_clears_and_survives_state_reload() {
        let source = SourceType::Sqs;
        assert_eq!(parse_scaling_config(&json!({}), source).unwrap(), None);
        assert_eq!(
            parse_scaling_config(&json!({"ScalingConfig": {}}), source).unwrap(),
            Some(None)
        );
        for value in [json!(1), json!(1001), json!(2.5), json!("2"), Value::Null] {
            assert!(parse_scaling_config(
                &json!({"ScalingConfig": {"MaximumConcurrency": value}}),
                source
            )
            .is_err());
        }
        for config in [json!(null), json!([]), json!({"Other": 2})] {
            assert!(parse_scaling_config(&json!({"ScalingConfig": config}), source).is_err());
        }
        assert!(parse_scaling_config(&json!({"ScalingConfig": {}}), SourceType::Kinesis).is_err());
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("lambda-scaling-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("state.sqlite");
        let state = Arc::new(locallycloud_state::StateDb::open(path.clone()).unwrap());
        let store = EsmStore::new();
        store.attach_state(state.clone()).unwrap();
        let mut mapping = mapping(vec![]);
        mapping.maximum_concurrency = Some(2);
        store.insert(mapping.clone()).unwrap();
        assert_eq!(
            store.list(None, None)[0].to_json()["ScalingConfig"]["MaximumConcurrency"],
            2
        );
        let restored = EsmStore::new();
        restored.attach_state(state.clone()).unwrap();
        assert_eq!(
            restored.get(&mapping.uuid).unwrap().maximum_concurrency,
            Some(2)
        );
        restored
            .update(&mapping.uuid, |item| item.maximum_concurrency = None)
            .unwrap();
        let cleared = EsmStore::new();
        cleared.attach_state(state.clone()).unwrap();
        assert!(cleared
            .get(&mapping.uuid)
            .unwrap()
            .to_json()
            .get("ScalingConfig")
            .is_none());
        drop((store, restored, cleared, state));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_tag_delete_cannot_restore_deleted_mapping_and_failure_preserves_it() {
        let root = std::env::temp_dir().join(format!("lambda-esm-delete-race-{}", Uuid::new_v4()));
        let state = Arc::new(locallycloud_state::StateDb::open(root.join("state.sqlite")).unwrap());
        let store = Arc::new(EsmStore::new());
        store.attach_state(state.clone()).unwrap();
        for number in 0..64 {
            let mut item = mapping(vec![]);
            item.uuid = format!("race-{number}");
            let uuid = item.uuid.clone();
            store.insert(item).unwrap();
            let barrier = Arc::new(std::sync::Barrier::new(3));
            std::thread::scope(|threads| {
                let tag_store = store.clone();
                let tag_uuid = uuid.clone();
                let tag_barrier = barrier.clone();
                threads.spawn(move || {
                    tag_barrier.wait();
                    match tag_store.tag(
                        &tag_uuid,
                        BTreeMap::from([("team".into(), "orders".into())]),
                    ) {
                        Ok(()) | Err(LambdaError::ResourceNotFound(_)) => {}
                        Err(error) => panic!("{error}"),
                    }
                });
                let delete_store = store.clone();
                let delete_uuid = uuid.clone();
                let delete_barrier = barrier.clone();
                threads.spawn(move || {
                    delete_barrier.wait();
                    delete_store.remove(&delete_uuid).unwrap();
                });
                barrier.wait();
            });
            assert!(store.get(&uuid).is_none());
        }
        let reopened = EsmStore::new();
        reopened.attach_state(state.clone()).unwrap();
        assert!(reopened.list(None, None).is_empty());
        let mut item = mapping(vec![]);
        item.uuid = "rollback".into();
        store.insert(item).unwrap();
        state.connection().unwrap().execute_batch("CREATE TRIGGER reject_esm_delete BEFORE DELETE ON lambda_event_source_mappings BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(store.remove("rollback").is_err());
        assert!(store.get("rollback").is_some());
        let reopened = EsmStore::new();
        reopened.attach_state(state.clone()).unwrap();
        assert!(reopened.get("rollback").is_some());
        drop((store, reopened, state));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn concurrent_workers_bound_real_invocations_and_cancel_without_ack() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let mem = Arc::new(MemSource {
            available: Mutex::new(
                (0..8)
                    .map(|id| SourceRecord {
                        item_identifier: id.to_string(),
                        ack_token: id.to_string(),
                        body: json!({"messageId": id.to_string()}),
                    })
                    .collect(),
            ),
            acked: Mutex::new(vec![]),
        });
        let mut mapping = mapping(vec![]);
        mapping.batch_size = 1;
        mapping.maximum_concurrency = Some(2);
        let (cancel, cancelled) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn({
            let (active, peak, started, release, mem) = (
                active.clone(),
                peak.clone(),
                started.clone(),
                release.clone(),
                mem.clone(),
            );
            async move {
                run_workers(mapping.maximum_concurrency.unwrap(), cancelled, || {
                    let (mapping, active, peak, started, release) = (
                        mapping.clone(),
                        active.clone(),
                        peak.clone(),
                        started.clone(),
                        release.clone(),
                    );
                    let source: Arc<dyn BatchSource> = mem.clone();
                    async move {
                        loop {
                            if !poll_once(&mapping, &source, |_| {
                                let (active, peak, started, release) = (
                                    active.clone(),
                                    peak.clone(),
                                    started.clone(),
                                    release.clone(),
                                );
                                async move {
                                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                                    let _guard = Active(active);
                                    peak.fetch_max(current, Ordering::SeqCst);
                                    started.add_permits(1);
                                    release.notified().await;
                                    Some(vec![])
                                }
                            })
                            .await
                            .unwrap()
                            {
                                break;
                            }
                        }
                    }
                })
                .await;
            }
        });
        let permits = tokio::time::timeout(Duration::from_secs(2), started.acquire_many(2))
            .await
            .unwrap()
            .unwrap();
        permits.forget();
        assert_eq!(active.load(Ordering::SeqCst), 2);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        release.notify_waiters();
        let permits = tokio::time::timeout(Duration::from_secs(2), started.acquire_many(2))
            .await
            .unwrap()
            .unwrap();
        permits.forget();
        assert_eq!(mem.acked.lock().unwrap().len(), 2);
        cancel.send(()).unwrap();
        // The same handoff used by reconcile_esm: replacement admission waits for drain.
        let replacement = tokio::spawn({
            let active = active.clone();
            async move {
                worker.await.unwrap();
                assert_eq!(active.load(Ordering::SeqCst), 0);
                let (cancel, cancelled) = tokio::sync::oneshot::channel();
                cancel.send(()).unwrap();
                // An update followed immediately by delete must not admit any work.
                run_workers(2, cancelled, || async {
                    panic!("cancelled replacement admitted work")
                })
                .await;
            }
        });
        tokio::time::timeout(Duration::from_secs(2), replacement)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mem.acked.lock().unwrap().len(), 2);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
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
        let records = mem.available.lock().unwrap().clone();
        let failed = poll_once(&mapping(vec![]), &source, |_| async { None }).await;
        assert_eq!(failed.unwrap_err(), "Lambda invocation failed");
        assert!(mem.acked.lock().unwrap().is_empty());
        // Simulate the same unacknowledged batch becoming visible on its next poll.
        *mem.available.lock().unwrap() = records;
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
