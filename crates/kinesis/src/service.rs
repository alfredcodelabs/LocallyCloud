mod control;
mod persistence;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use http::HeaderMap;
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::AwsProtocol;
use locallycloud_state::{StateDb, StateError};
use md5::{Digest, Md5};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use uuid::Uuid;

use crate::TARGET_PREFIX;

const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const MAX_REQUEST_BODY: usize = 2 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_RECORDS: usize = 10_000;
const MAX_GET_RECORD_BYTES: usize = 10 * 1024 * 1024;
#[cfg(test)]
const RETENTION_SECONDS: f64 = 24.0 * 60.0 * 60.0;
const DEFAULT_MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024;
#[cfg(test)]
const SHARD_ID: &str = "shardId-000000000000";
const MAX_SHARDS: i64 = 128;
const ITERATOR_LIFETIME_SECONDS: i64 = 300;
const MAX_ITERATOR_BYTES: usize = 16 * 1024;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Eq, Hash, PartialEq)]
struct Scope {
    account_id: String,
    region: String,
}

impl Scope {
    fn new(request: &ServiceRequest) -> Self {
        Self {
            account_id: request.account_id.clone(),
            region: request.region.clone(),
        }
    }

    fn stream_arn(&self, name: &str) -> String {
        format!(
            "arn:aws:kinesis:{}:{}:stream/{name}",
            self.region, self.account_id
        )
    }
}

#[derive(Eq, Hash, PartialEq)]
struct StreamKey {
    scope: Scope,
    name: String,
}

impl StreamKey {
    fn new(scope: &Scope, name: &str) -> Self {
        Self {
            scope: scope.clone(),
            name: name.to_owned(),
        }
    }
}

struct Stream {
    generation: String,
    created_at: f64,
    next_sequence: u64,
    shards: Vec<Shard>,
    retention_hours: i64,
    tags: BTreeMap<String, String>,
}

#[derive(Default)]
struct Shard {
    first_position: usize,
    records: VecDeque<Record>,
}

struct Record {
    sequence_number: String,
    data: Vec<u8>,
    partition_key: String,
    arrival_time: f64,
}

#[derive(Serialize, Deserialize)]
struct IteratorPayload {
    version: u8,
    account_id: String,
    region: String,
    stream_name: String,
    generation: String,
    shard_id: String,
    position: usize,
    expires_at: i64,
}

#[derive(Default)]
struct Store {
    streams: HashMap<StreamKey, Stream>,
    buffered_bytes: usize,
}

impl Store {
    fn trim_expired(&mut self, now: f64) {
        for stream in self.streams.values_mut() {
            let retention_seconds = stream.retention_hours as f64 * 3600.0;
            for shard in &mut stream.shards {
                let mut trimmed = false;
                while shard
                    .records
                    .front()
                    .is_some_and(|record| record.arrival_time <= now - retention_seconds)
                {
                    let record = shard.records.pop_front().expect("nonempty front");
                    self.buffered_bytes -= record_charge(&record.data, &record.partition_key);
                    shard.first_position += 1;
                    trimmed = true;
                }
                if trimmed {
                    shard.records.shrink_to_fit();
                }
            }
        }
    }
}

fn record_charge(data: &[u8], partition_key: &str) -> usize {
    data.len() + partition_key.len() + std::mem::size_of::<Record>()
}

#[derive(Clone)]
pub(crate) struct KinesisHandler {
    store: Arc<Mutex<Store>>,
    max_buffered_bytes: usize,
    iterator_secret: [u8; 32],
    persistence: Option<Arc<persistence::Persistence>>,
}

impl KinesisHandler {
    pub(crate) fn new() -> Self {
        Self::from_store(Store::default(), None, None)
    }

    pub(crate) fn with_state(state: Arc<StateDb>) -> Result<Self, StateError> {
        let (persistence, store, secret) = persistence::Persistence::open(state)?;
        Ok(Self::from_store(
            store,
            Some(Arc::new(persistence)),
            Some(secret),
        ))
    }

    fn from_store(
        store: Store,
        persistence: Option<Arc<persistence::Persistence>>,
        secret: Option<[u8; 32]>,
    ) -> Self {
        let iterator_secret = secret.unwrap_or_else(|| {
            let mut value = [0_u8; 32];
            value[..16].copy_from_slice(Uuid::new_v4().as_bytes());
            value[16..].copy_from_slice(Uuid::new_v4().as_bytes());
            value
        });
        Self {
            store: Arc::new(Mutex::new(store)),
            max_buffered_bytes: std::env::var("LOCALLYCLOUD_KINESIS_MAX_BUFFERED_BYTES")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|limit| *limit > 0)
                .unwrap_or(DEFAULT_MAX_BUFFERED_BYTES),
            iterator_secret,
            persistence,
        }
    }

    fn process(&self, request: &ServiceRequest) -> Result<Success, KinesisError> {
        if request.method != http::Method::POST
            || request.uri.path() != "/"
            || request.uri.query().is_some()
        {
            return Err(KinesisError::UnknownOperation);
        }
        validate_content_type(&request.headers)?;
        if request.body.len() > MAX_REQUEST_BODY {
            return Err(KinesisError::Validation(
                "The request body exceeds the supported limit".into(),
            ));
        }
        let operation = operation(&request.headers)?;
        let scope = Scope::new(request);
        match operation {
            "ListStreams"
            | "DescribeStreamSummary"
            | "DescribeLimits"
            | "IncreaseStreamRetentionPeriod"
            | "DecreaseStreamRetentionPeriod"
            | "ListTagsForStream"
            | "AddTagsToStream"
            | "RemoveTagsFromStream"
            | "ListTagsForResource"
            | "TagResource"
            | "UntagResource" => self.control(operation, &request.body, &scope),
            "CreateStream" => self.create_stream(decode(&request.body)?, &scope),
            "DescribeStream" => self.describe_stream(decode(&request.body)?, &scope),
            "ListShards" => self.list_shards(decode(&request.body)?, &scope),
            "PutRecord" => self.put_record(decode(&request.body)?, &scope),
            "GetShardIterator" => self.get_shard_iterator(decode(&request.body)?, &scope),
            "GetRecords" => self.get_records(decode(&request.body)?, &scope),
            "DeleteStream" => self.delete_stream(decode(&request.body)?, &scope),
            _ => Err(KinesisError::UnknownOperation),
        }
    }

    fn create_stream(
        &self,
        request: CreateStreamRequest,
        scope: &Scope,
    ) -> Result<Success, KinesisError> {
        validate_stream_name(&request.stream_name)?;
        if !(1..=MAX_SHARDS).contains(&request.shard_count) {
            return Err(KinesisError::InvalidArgument(format!(
                "ShardCount must be between 1 and {MAX_SHARDS} for this local backend"
            )));
        }
        if request
            .stream_mode_details
            .as_ref()
            .is_some_and(|m| m.stream_mode != "PROVISIONED")
        {
            return Err(KinesisError::InvalidArgument(
                "Only PROVISIONED streams are supported".into(),
            ));
        }
        if request
            .max_record_size_in_ki_b
            .is_some_and(|size| size != 1024)
        {
            return Err(KinesisError::InvalidArgument(
                "The maximum record size supported is 1024 KiB".into(),
            ));
        }
        control::validate_tags(&request.tags)?;
        let key = StreamKey::new(scope, &request.stream_name);
        let mut store = self.lock_store()?;
        if store.streams.contains_key(&key) {
            return Err(KinesisError::ResourceInUse(format!(
                "Stream {} already exists.",
                request.stream_name
            )));
        }
        let open_shards: usize = store
            .streams
            .iter()
            .filter(|(key, _)| key.scope == *scope)
            .map(|(_, stream)| stream.shards.len())
            .sum();
        if open_shards + request.shard_count as usize > MAX_SHARDS as usize {
            return Err(KinesisError::LimitExceeded(
                "The local account shard limit has been reached".into(),
            ));
        }
        let stream = Stream {
            generation: Uuid::new_v4().to_string(),
            created_at: now_epoch()?,
            next_sequence: 1,
            shards: (0..request.shard_count).map(|_| Shard::default()).collect(),
            retention_hours: 24,
            tags: request.tags,
        };
        if let Some(persistence) = &self.persistence {
            persistence
                .create(&key, &stream)
                .map_err(|_| KinesisError::Internal)?;
        }
        store.streams.insert(key, stream);
        Ok(Success::Empty)
    }

    fn describe_stream(
        &self,
        mut request: StreamNameRequest,
        scope: &Scope,
    ) -> Result<Success, KinesisError> {
        request.stream_name =
            control::resolve_name(&request.stream_name, request.stream_arn.as_deref(), scope)?;
        let store = self.lock_store()?;
        let stream = store
            .streams
            .get(&StreamKey::new(scope, &request.stream_name))
            .ok_or_else(|| stream_not_found(&request.stream_name))?;
        Ok(Success::Json(json!({
            "StreamDescription": {
                "StreamName": request.stream_name,
                "StreamARN": scope.stream_arn(&request.stream_name),
                "StreamStatus": "ACTIVE",
                "Shards": (0..stream.shards.len()).map(|index| shard_value(index, stream.shards.len())).collect::<Vec<_>>(),
                "HasMoreShards": false,
                "RetentionPeriodHours": stream.retention_hours,
                "StreamModeDetails": {"StreamMode": "PROVISIONED"},
                "EncryptionType": "NONE",
                "StreamCreationTimestamp": stream.created_at,
                "EnhancedMonitoring": [{ "ShardLevelMetrics": [] }]
            }
        })))
    }

    fn list_shards(
        &self,
        mut request: StreamNameRequest,
        scope: &Scope,
    ) -> Result<Success, KinesisError> {
        request.stream_name =
            control::resolve_name(&request.stream_name, request.stream_arn.as_deref(), scope)?;
        let store = self.lock_store()?;
        let stream = store
            .streams
            .get(&StreamKey::new(scope, &request.stream_name))
            .ok_or_else(|| stream_not_found(&request.stream_name))?;
        Ok(Success::Json(json!({ "Shards": (0..stream.shards.len())
            .map(|index| shard_value(index, stream.shards.len())).collect::<Vec<_>>() })))
    }

    fn put_record(
        &self,
        request: PutRecordRequest,
        scope: &Scope,
    ) -> Result<Success, KinesisError> {
        validate_stream_name(&request.stream_name)?;
        validate_partition_key(&request.partition_key)?;
        let data = STANDARD.decode(request.data.as_bytes()).map_err(|_| {
            KinesisError::Serialization("Data must be valid base64-encoded bytes".into())
        })?;
        if data.len() > MAX_RECORD_BYTES {
            return Err(KinesisError::InvalidArgument(
                "The record exceeds the supported 1 MiB limit".into(),
            ));
        }
        let hash = match request.explicit_hash_key.as_deref() {
            Some(value) => parse_hash_key(value)?,
            None => u128::from_be_bytes(Md5::digest(request.partition_key.as_bytes()).into()),
        };
        let arrival_time = now_epoch()?;
        let mut store = self.lock_store()?;
        if !store
            .streams
            .contains_key(&StreamKey::new(scope, &request.stream_name))
        {
            return Err(stream_not_found(&request.stream_name));
        }
        store.trim_expired(arrival_time);
        let charge = record_charge(&data, &request.partition_key);
        if store.buffered_bytes.saturating_add(charge) > self.max_buffered_bytes {
            return Err(KinesisError::Capacity(
                "LocallyCloud in-memory Kinesis record capacity is full".into(),
            ));
        }
        let stream = store
            .streams
            .get_mut(&StreamKey::new(scope, &request.stream_name))
            .ok_or_else(|| stream_not_found(&request.stream_name))?;
        let shard_index = (0..stream.shards.len())
            .find(|index| {
                let (start, end) = hash_range(*index, stream.shards.len());
                hash >= start && hash <= end
            })
            .ok_or(KinesisError::Internal)?;
        let sequence_number = stream.next_sequence.to_string();
        let next_sequence = stream
            .next_sequence
            .checked_add(1)
            .ok_or(KinesisError::Internal)?;
        let record = Record {
            sequence_number: sequence_number.clone(),
            data,
            partition_key: request.partition_key,
            arrival_time,
        };
        if let Some(persistence) = &self.persistence {
            persistence
                .append(
                    &StreamKey::new(scope, &request.stream_name),
                    stream,
                    shard_index,
                    &record,
                )
                .map_err(|_| KinesisError::Internal)?;
        }
        stream.next_sequence = next_sequence;
        stream.shards[shard_index].records.push_back(record);
        store.buffered_bytes += charge;
        Ok(Success::Json(json!({
            "ShardId": shard_id(shard_index),
            "SequenceNumber": sequence_number
        })))
    }

    fn get_shard_iterator(
        &self,
        request: GetShardIteratorRequest,
        scope: &Scope,
    ) -> Result<Success, KinesisError> {
        validate_stream_name(&request.stream_name)?;
        if !matches!(
            request.shard_iterator_type.as_str(),
            "TRIM_HORIZON"
                | "LATEST"
                | "AT_TIMESTAMP"
                | "AT_SEQUENCE_NUMBER"
                | "AFTER_SEQUENCE_NUMBER"
        ) {
            return Err(KinesisError::Validation(
                "Unsupported ShardIteratorType".into(),
            ));
        }
        let mut store = self.lock_store()?;
        store.trim_expired(now_epoch()?);
        let stream = store
            .streams
            .get(&StreamKey::new(scope, &request.stream_name))
            .ok_or_else(|| stream_not_found(&request.stream_name))?;
        let shard = shard_index(&request.shard_id)
            .and_then(|index| stream.shards.get(index))
            .ok_or_else(|| shard_not_found(&request.stream_name))?;
        let token = self.encode_iterator(IteratorPayload {
            version: 1,
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            stream_name: request.stream_name,
            generation: stream.generation.clone(),
            shard_id: request.shard_id,
            position: match request.shard_iterator_type.as_str() {
                "TRIM_HORIZON" => shard.first_position,
                "LATEST" => shard.first_position + shard.records.len(),
                "AT_TIMESTAMP" => {
                    let timestamp = request
                        .timestamp
                        .filter(|value| value.is_finite() && *value >= 0.0)
                        .ok_or_else(|| {
                            KinesisError::InvalidArgument("Timestamp is required".into())
                        })?;
                    shard.first_position
                        + shard
                            .records
                            .iter()
                            .position(|record| record.arrival_time >= timestamp)
                            .unwrap_or(shard.records.len())
                }
                "AT_SEQUENCE_NUMBER" | "AFTER_SEQUENCE_NUMBER" => {
                    let sequence =
                        request.starting_sequence_number.as_deref().ok_or_else(|| {
                            KinesisError::InvalidArgument(
                                "StartingSequenceNumber is required".into(),
                            )
                        })?;
                    shard
                        .records
                        .iter()
                        .position(|record| record.sequence_number == sequence)
                        .map(|position| {
                            shard.first_position
                                + position
                                + usize::from(
                                    request.shard_iterator_type == "AFTER_SEQUENCE_NUMBER",
                                )
                        })
                        .ok_or_else(|| {
                            KinesisError::InvalidArgument(
                                "StartingSequenceNumber was not found".into(),
                            )
                        })?
                }
                _ => {
                    return Err(KinesisError::Validation(
                        "Unsupported ShardIteratorType".into(),
                    ))
                }
            },
            expires_at: now_epoch_seconds()?.saturating_add(ITERATOR_LIFETIME_SECONDS),
        })?;
        Ok(Success::Json(json!({ "ShardIterator": token })))
    }

    fn get_records(
        &self,
        request: GetRecordsRequest,
        scope: &Scope,
    ) -> Result<Success, KinesisError> {
        let limit = request.limit.unwrap_or(MAX_RECORDS as i64);
        if !(1..=MAX_RECORDS as i64).contains(&limit) {
            return Err(KinesisError::InvalidArgument(
                "Limit must be between 1 and 10000".into(),
            ));
        }
        let payload = self.decode_iterator(&request.shard_iterator)?;
        if payload.account_id != scope.account_id || payload.region != scope.region {
            return Err(invalid_iterator());
        }
        if payload.expires_at <= now_epoch_seconds()? {
            return Err(KinesisError::ExpiredIterator(
                "The shard iterator has expired".into(),
            ));
        }
        if payload.version != 1 {
            return Err(invalid_iterator());
        }
        let mut store = self.lock_store()?;
        store.trim_expired(now_epoch()?);
        let stream = store
            .streams
            .get(&StreamKey::new(scope, &payload.stream_name))
            .ok_or_else(|| shard_not_found(&payload.stream_name))?;
        if stream.generation != payload.generation {
            return Err(shard_not_found(&payload.stream_name));
        }
        let shard = shard_index(&payload.shard_id)
            .and_then(|index| stream.shards.get(index))
            .ok_or_else(invalid_iterator)?;
        if payload.position < shard.first_position {
            return Err(KinesisError::ExpiredIterator(
                "The iterator points to trimmed records".into(),
            ));
        }
        let tail = shard.first_position + shard.records.len();
        if payload.position > tail {
            return Err(invalid_iterator());
        }
        let mut page_bytes = 0;
        let records = shard
            .records
            .iter()
            .skip(payload.position - shard.first_position)
            .take(limit as usize)
            .take_while(|record| {
                let fits = page_bytes + record.data.len() <= MAX_GET_RECORD_BYTES;
                if fits {
                    page_bytes += record.data.len();
                }
                fits
            })
            .map(|record| {
                json!({
                    "SequenceNumber": record.sequence_number,
                    "ApproximateArrivalTimestamp": record.arrival_time,
                    "Data": STANDARD.encode(&record.data),
                    "PartitionKey": record.partition_key
                })
            })
            .collect::<Vec<_>>();
        let end = payload.position + records.len();
        let next_iterator = self.encode_iterator(IteratorPayload {
            version: 1,
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            stream_name: payload.stream_name,
            generation: payload.generation,
            shard_id: payload.shard_id,
            position: end,
            expires_at: now_epoch_seconds()?.saturating_add(ITERATOR_LIFETIME_SECONDS),
        })?;
        Ok(Success::Json(json!({
            "Records": records,
            "NextShardIterator": next_iterator,
            "MillisBehindLatest": 0
        })))
    }

    fn delete_stream(
        &self,
        mut request: StreamNameRequest,
        scope: &Scope,
    ) -> Result<Success, KinesisError> {
        request.stream_name =
            control::resolve_name(&request.stream_name, request.stream_arn.as_deref(), scope)?;
        let mut store = self.lock_store()?;
        let key = StreamKey::new(scope, &request.stream_name);
        if !store.streams.contains_key(&key) {
            return Err(stream_not_found(&request.stream_name));
        }
        if let Some(persistence) = &self.persistence {
            persistence
                .delete(&key)
                .map_err(|_| KinesisError::Internal)?;
        }
        let removed = store
            .streams
            .remove(&key)
            .ok_or_else(|| stream_not_found(&request.stream_name))?;
        store.buffered_bytes -= removed
            .shards
            .iter()
            .flat_map(|shard| &shard.records)
            .map(|record| record_charge(&record.data, &record.partition_key))
            .sum::<usize>();
        Ok(Success::Empty)
    }

    fn encode_iterator(&self, payload: IteratorPayload) -> Result<String, KinesisError> {
        self.encode_token(&payload)
    }

    fn encode_token<T: Serialize>(&self, payload: &T) -> Result<String, KinesisError> {
        let payload = serde_json::to_vec(&payload).map_err(|_| KinesisError::Internal)?;
        let mut mac = HmacSha256::new_from_slice(&self.iterator_secret)
            .map_err(|_| KinesisError::Internal)?;
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn decode_iterator(&self, token: &str) -> Result<IteratorPayload, KinesisError> {
        self.decode_token(token)
    }

    fn decode_token<T: DeserializeOwned>(&self, token: &str) -> Result<T, KinesisError> {
        if token.is_empty() || token.len() > MAX_ITERATOR_BYTES {
            return Err(invalid_iterator());
        }
        let (payload, signature) = token.split_once('.').ok_or_else(invalid_iterator)?;
        if signature.contains('.') {
            return Err(invalid_iterator());
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| invalid_iterator())?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| invalid_iterator())?;
        let mut mac = HmacSha256::new_from_slice(&self.iterator_secret)
            .map_err(|_| KinesisError::Internal)?;
        mac.update(&payload);
        mac.verify_slice(&signature)
            .map_err(|_| invalid_iterator())?;
        serde_json::from_slice(&payload).map_err(|_| invalid_iterator())
    }

    fn lock_store(&self) -> Result<MutexGuard<'_, Store>, KinesisError> {
        self.store.lock().map_err(|_| KinesisError::Internal)
    }
}

#[async_trait]
impl NativeHandler for KinesisHandler {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        Ok(self
            .store
            .lock()
            .map_err(|_| "Kinesis inventory unavailable")?
            .streams
            .keys()
            .filter(|k| k.scope.account_id == account)
            .map(|k| k.scope.region.clone())
            .collect())
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let request_id = request.request_id.clone();
        let handler = self.clone();
        let outcome = tokio::task::spawn_blocking(move || handler.process(&request)).await;
        match outcome.unwrap_or(Err(KinesisError::Internal)) {
            Ok(success) => {
                let body = match success {
                    Success::Empty => Body::empty(),
                    Success::Json(value) => Body::from(value.to_string()),
                };
                Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
                    .header("x-amzn-RequestId", &request_id)
                    .body(body)
                    .expect("Kinesis JSON response is valid")
            }
            Err(error) => AwsError::from(error)
                .with_request_id(request_id)
                .render(AwsProtocol::Json11)
                .into_response(),
        }
    }
}

enum Success {
    Empty,
    Json(Value),
}

#[derive(Debug)]
enum KinesisError {
    Serialization(String),
    Validation(String),
    UnknownOperation,
    ResourceInUse(String),
    ResourceNotFound(String),
    InvalidArgument(String),
    ExpiredIterator(String),
    ExpiredNextToken,
    LimitExceeded(String),
    Capacity(String),
    Internal,
}

impl From<KinesisError> for AwsError {
    fn from(error: KinesisError) -> Self {
        let (code, message, status) = match error {
            KinesisError::Serialization(message) => ("SerializationException", message, 400),
            KinesisError::Validation(message) => ("ValidationException", message, 400),
            KinesisError::UnknownOperation => (
                "UnknownOperationException",
                "The requested Kinesis operation is not supported".into(),
                400,
            ),
            KinesisError::ResourceInUse(message) => ("ResourceInUseException", message, 400),
            KinesisError::ResourceNotFound(message) => ("ResourceNotFoundException", message, 400),
            KinesisError::InvalidArgument(message) => ("InvalidArgumentException", message, 400),
            KinesisError::ExpiredIterator(message) => ("ExpiredIteratorException", message, 400),
            KinesisError::LimitExceeded(message) => ("LimitExceededException", message, 400),
            KinesisError::ExpiredNextToken => (
                "ExpiredNextTokenException",
                "The pagination token has expired".into(),
                400,
            ),
            KinesisError::Capacity(message) => {
                ("ProvisionedThroughputExceededException", message, 400)
            }
            KinesisError::Internal => (
                "InternalFailureException",
                "The request could not be completed".into(),
                500,
            ),
        };
        AwsError::new(code, message, status)
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct CreateStreamRequest {
    stream_name: String,
    shard_count: i64,
    #[serde(default)]
    tags: BTreeMap<String, String>,
    stream_mode_details: Option<control::StreamModeDetails>,
    #[serde(rename = "MaxRecordSizeInKiB")]
    max_record_size_in_ki_b: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct StreamNameRequest {
    #[serde(default)]
    stream_name: String,
    #[serde(rename = "StreamARN")]
    stream_arn: Option<String>,
    #[serde(default, rename = "EnforceConsumerDeletion")]
    _enforce_consumer_deletion: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct PutRecordRequest {
    stream_name: String,
    data: String,
    partition_key: String,
    explicit_hash_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct GetShardIteratorRequest {
    stream_name: String,
    shard_id: String,
    shard_iterator_type: String,
    starting_sequence_number: Option<String>,
    timestamp: Option<f64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct GetRecordsRequest {
    shard_iterator: String,
    limit: Option<i64>,
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), KinesisError> {
    let media_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .ok_or_else(|| KinesisError::Validation("Content-Type is required".into()))?;
    if media_type.eq_ignore_ascii_case(CONTENT_TYPE) {
        Ok(())
    } else {
        Err(KinesisError::Validation(
            "Content-Type must be application/x-amz-json-1.1".into(),
        ))
    }
}

fn operation(headers: &HeaderMap) -> Result<&str, KinesisError> {
    headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .and_then(|target| target.strip_prefix(TARGET_PREFIX))
        .and_then(|suffix| suffix.strip_prefix('.'))
        .filter(|operation| !operation.is_empty() && !operation.contains('.'))
        .ok_or(KinesisError::UnknownOperation)
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, KinesisError> {
    serde_json::from_slice(body)
        .map_err(|_| KinesisError::Serialization("The request could not be deserialized".into()))
}

fn validate_stream_name(name: &str) -> Result<(), KinesisError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(KinesisError::Validation(
            "StreamName must contain 1-128 alphanumeric, underscore, hyphen, or period characters"
                .into(),
        ));
    }
    Ok(())
}

fn validate_partition_key(value: &str) -> Result<(), KinesisError> {
    if value.is_empty() || value.chars().count() > 256 {
        return Err(KinesisError::InvalidArgument(
            "PartitionKey must contain 1-256 characters".into(),
        ));
    }
    Ok(())
}

fn shard_id(index: usize) -> String {
    format!("shardId-{index:012}")
}

fn shard_index(value: &str) -> Option<usize> {
    let index = value.strip_prefix("shardId-")?.parse().ok()?;
    (shard_id(index) == value).then_some(index)
}

fn parse_hash_key(value: &str) -> Result<u128, KinesisError> {
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(KinesisError::InvalidArgument(
            "Invalid ExplicitHashKey".into(),
        ));
    }
    value.parse().map_err(|_| {
        KinesisError::InvalidArgument("ExplicitHashKey exceeds the 128-bit hash range".into())
    })
}

fn hash_range(index: usize, count: usize) -> (u128, u128) {
    let count = count as u128;
    let boundary = |i: usize| {
        let i = i as u128;
        (u128::MAX / count) * i + ((u128::MAX % count + 1) * i) / count
    };
    (
        boundary(index),
        if index + 1 == count as usize {
            u128::MAX
        } else {
            boundary(index + 1) - 1
        },
    )
}

fn shard_value(index: usize, count: usize) -> Value {
    let (start, end) = hash_range(index, count);
    json!({
        "ShardId": shard_id(index),
        "HashKeyRange": {"StartingHashKey": start.to_string(), "EndingHashKey": end.to_string()},
        "SequenceNumberRange": {"StartingSequenceNumber": "1"}
    })
}

fn stream_not_found(name: &str) -> KinesisError {
    KinesisError::ResourceNotFound(format!("Stream {name} not found."))
}

fn shard_not_found(stream_name: &str) -> KinesisError {
    KinesisError::ResourceNotFound(format!("Shard in stream {stream_name} does not exist"))
}

fn invalid_iterator() -> KinesisError {
    KinesisError::InvalidArgument("Invalid ShardIterator.".into())
}

fn now_epoch() -> Result<f64, KinesisError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .map_err(|_| KinesisError::Internal)
}

fn now_epoch_seconds() -> Result<i64, KinesisError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .map_err(|_| KinesisError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn scope() -> Scope {
        Scope {
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        }
    }

    pub(super) fn create(handler: &KinesisHandler) {
        handler
            .create_stream(
                CreateStreamRequest {
                    stream_name: "events".into(),
                    shard_count: 1,
                    ..Default::default()
                },
                &scope(),
            )
            .unwrap_or_else(|_| panic!("create stream"));
    }

    pub(super) fn put(handler: &KinesisHandler, data: &[u8]) -> Result<Success, KinesisError> {
        handler.put_record(
            PutRecordRequest {
                stream_name: "events".into(),
                data: STANDARD.encode(data),
                partition_key: "p".into(),
                explicit_hash_key: None,
            },
            &scope(),
        )
    }

    fn iterator(handler: &KinesisHandler) -> String {
        let Success::Json(value) = handler
            .get_shard_iterator(
                GetShardIteratorRequest {
                    stream_name: "events".into(),
                    shard_id: SHARD_ID.into(),
                    shard_iterator_type: "TRIM_HORIZON".into(),
                    starting_sequence_number: None,
                    timestamp: None,
                },
                &scope(),
            )
            .unwrap_or_else(|_| panic!("iterator"))
        else {
            panic!("iterator response");
        };
        value["ShardIterator"].as_str().unwrap().to_owned()
    }

    #[test]
    fn accepted_records_survive_handler_restart() {
        let root = std::env::temp_dir().join(format!("kinesis-restart-{}", Uuid::new_v4()));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).expect("state"));
        {
            let handler = KinesisHandler::with_state(state.clone()).expect("handler");
            create(&handler);
            assert!(put(&handler, b"durable").is_ok());
            let old_iterator = iterator(&handler);
            std::fs::write(root.join("iterator"), old_iterator).expect("iterator token");
        }
        let handler = KinesisHandler::with_state(state).expect("reopened handler");
        let old_iterator = std::fs::read_to_string(root.join("iterator")).expect("iterator token");
        assert!(handler
            .get_records(
                GetRecordsRequest {
                    shard_iterator: old_iterator,
                    limit: Some(10),
                },
                &scope()
            )
            .is_ok());
        let Success::Json(page) = handler
            .get_records(
                GetRecordsRequest {
                    shard_iterator: iterator(&handler),
                    limit: Some(10),
                },
                &scope(),
            )
            .expect("replayed records")
        else {
            panic!("records response");
        };
        assert_eq!(page["Records"][0]["Data"], STANDARD.encode(b"durable"));
        assert_eq!(page["Records"][0]["SequenceNumber"], "1");
        assert!(put(&handler, b"next").is_ok());
        assert_eq!(
            handler.lock_store().unwrap().streams[&StreamKey::new(&scope(), "events")]
                .next_sequence,
            3
        );
        drop(handler);
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn aggregate_capacity_rejects_before_sequence_and_releases_on_delete() {
        let mut handler = KinesisHandler::new();
        handler.max_buffered_bytes = record_charge(b"A", "p");
        create(&handler);
        assert!(put(&handler, b"A").is_ok());
        assert!(matches!(
            put(&handler, b"B"),
            Err(KinesisError::Capacity(_))
        ));
        {
            let store = handler.lock_store().unwrap();
            let stream = store
                .streams
                .get(&StreamKey::new(&scope(), "events"))
                .unwrap();
            assert_eq!(stream.next_sequence, 2);
            assert_eq!(stream.shards[0].records.len(), 1);
            assert_eq!(store.buffered_bytes, handler.max_buffered_bytes);
        }
        handler
            .delete_stream(
                StreamNameRequest {
                    stream_name: "events".into(),
                    _enforce_consumer_deletion: None,
                    stream_arn: None,
                },
                &scope(),
            )
            .unwrap_or_else(|_| panic!("delete stream"));
        assert_eq!(handler.lock_store().unwrap().buffered_bytes, 0);
    }

    #[test]
    fn get_records_caps_page_bytes_and_keeps_next_cursor() {
        let handler = KinesisHandler::new();
        create(&handler);
        let data = vec![b'X'; MAX_RECORD_BYTES];
        for _ in 0..11 {
            assert!(put(&handler, &data).is_ok());
        }
        let Success::Json(first) = handler
            .get_records(
                GetRecordsRequest {
                    shard_iterator: iterator(&handler),
                    limit: Some(100),
                },
                &scope(),
            )
            .unwrap_or_else(|_| panic!("first page"))
        else {
            panic!("page response");
        };
        assert_eq!(first["Records"].as_array().unwrap().len(), 10);
        let next = first["NextShardIterator"].as_str().unwrap().to_owned();
        let Success::Json(second) = handler
            .get_records(
                GetRecordsRequest {
                    shard_iterator: next,
                    limit: Some(100),
                },
                &scope(),
            )
            .unwrap_or_else(|_| panic!("second page"))
        else {
            panic!("page response");
        };
        assert_eq!(second["Records"].as_array().unwrap().len(), 1);
        assert_eq!(second["Records"][0]["SequenceNumber"], "11");
    }

    #[test]
    fn expired_records_are_trimmed_without_reusing_old_cursor_positions() {
        let handler = KinesisHandler::new();
        create(&handler);
        assert!(put(&handler, b"A").is_ok());
        assert!(put(&handler, b"B").is_ok());
        let stale = iterator(&handler);
        {
            let mut store = handler.lock_store().unwrap();
            let stream = store
                .streams
                .get_mut(&StreamKey::new(&scope(), "events"))
                .unwrap();
            stream.shards[0].records.front_mut().unwrap().arrival_time =
                now_epoch().unwrap() - RETENTION_SECONDS - 1.0;
        }
        let current = iterator(&handler);
        assert!(matches!(
            handler.get_records(
                GetRecordsRequest {
                    shard_iterator: stale,
                    limit: Some(10)
                },
                &scope()
            ),
            Err(KinesisError::ExpiredIterator(_))
        ));
        let Success::Json(page) = handler
            .get_records(
                GetRecordsRequest {
                    shard_iterator: current,
                    limit: Some(10),
                },
                &scope(),
            )
            .unwrap_or_else(|_| panic!("get records"))
        else {
            panic!("records response");
        };
        assert_eq!(page["Records"].as_array().unwrap().len(), 1);
        assert_eq!(page["Records"][0]["Data"], STANDARD.encode(b"B"));
        assert_eq!(
            handler.lock_store().unwrap().buffered_bytes,
            record_charge(b"B", "p")
        );
    }
    #[test]
    fn multishard_hash_routing_iterators_and_restart_preserve_isolation() {
        let root = std::env::temp_dir().join(format!("kinesis-multishard-{}", Uuid::new_v4()));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let handler = KinesisHandler::with_state(state.clone()).unwrap();
        handler
            .create_stream(
                CreateStreamRequest {
                    stream_name: "events".into(),
                    shard_count: 3,
                    ..Default::default()
                },
                &scope(),
            )
            .unwrap();
        let expected = [
            ("a", None, 0),
            ("middle", Some(hash_range(1, 3).0.to_string()), 1),
            ("z", None, 2),
            ("zero", Some("0".into()), 0),
            ("last", Some(u128::MAX.to_string()), 2),
        ];
        for (key, hash, index) in &expected {
            let Success::Json(result) = handler
                .put_record(
                    PutRecordRequest {
                        stream_name: "events".into(),
                        partition_key: (*key).into(),
                        data: STANDARD.encode(key.as_bytes()),
                        explicit_hash_key: hash.clone(),
                    },
                    &scope(),
                )
                .unwrap()
            else {
                panic!("put");
            };
            assert_eq!(result["ShardId"], shard_id(*index));
        }
        let Success::Json(description) = handler
            .describe_stream(
                StreamNameRequest {
                    stream_name: "events".into(),
                    _enforce_consumer_deletion: None,
                    stream_arn: None,
                },
                &scope(),
            )
            .unwrap()
        else {
            panic!("describe");
        };
        assert_eq!(
            description["StreamDescription"]["Shards"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        let mut iterators = Vec::new();
        for index in 0..3 {
            let Success::Json(result) = handler
                .get_shard_iterator(
                    GetShardIteratorRequest {
                        stream_name: "events".into(),
                        shard_id: shard_id(index),
                        shard_iterator_type: "TRIM_HORIZON".into(),
                        starting_sequence_number: None,
                        timestamp: None,
                    },
                    &scope(),
                )
                .unwrap()
            else {
                panic!("iterator");
            };
            iterators.push(result["ShardIterator"].as_str().unwrap().to_string());
        }
        let before = handler.lock_store().unwrap().streams[&StreamKey::new(&scope(), "events")]
            .next_sequence;
        for invalid in ["-1", "01", "340282366920938463463374607431768211456"] {
            assert!(handler
                .put_record(
                    PutRecordRequest {
                        stream_name: "events".into(),
                        partition_key: "p".into(),
                        data: STANDARD.encode(b"invalid"),
                        explicit_hash_key: Some(invalid.into())
                    },
                    &scope()
                )
                .is_err());
        }
        assert_eq!(
            handler.lock_store().unwrap().streams[&StreamKey::new(&scope(), "events")]
                .next_sequence,
            before
        );
        drop(handler);
        let handler = KinesisHandler::with_state(state).unwrap();
        for (index, token) in iterators.into_iter().enumerate() {
            let Success::Json(page) = handler
                .get_records(
                    GetRecordsRequest {
                        shard_iterator: token,
                        limit: Some(10),
                    },
                    &scope(),
                )
                .unwrap()
            else {
                panic!("records");
            };
            let actual: Vec<_> = page["Records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|record| record["PartitionKey"].as_str().unwrap())
                .collect();
            let want: Vec<_> = expected
                .iter()
                .filter(|(_, _, shard)| *shard == index)
                .map(|(key, _, _)| *key)
                .collect();
            assert_eq!(actual, want);
        }
        drop(handler);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn single_shard_sqlite_migration_preserves_positions_and_next_sequence() {
        let root = std::env::temp_dir().join(format!("kinesis-migration-{}", Uuid::new_v4()));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        {
            let db = state.connection().unwrap();
            db.execute_batch("CREATE TABLE kinesis_streams (account TEXT, region TEXT, name TEXT, generation TEXT, created_at REAL, next_sequence INTEGER, first_position INTEGER, PRIMARY KEY(account,region,name)); CREATE TABLE kinesis_records (account TEXT, region TEXT, name TEXT, position INTEGER, sequence TEXT, data BLOB, partition_key TEXT, arrival_time REAL, PRIMARY KEY(account,region,name,position));").unwrap();
            db.execute("INSERT INTO kinesis_streams VALUES ('000000000000','us-east-1','events','legacy',?1,16,7)", [now_epoch().unwrap()]).unwrap();
            db.execute("INSERT INTO kinesis_records VALUES ('000000000000','us-east-1','events',7,'15',?1,'p',?2)", rusqlite::params![b"legacy".as_slice(), now_epoch().unwrap()]).unwrap();
        }
        let handler = KinesisHandler::with_state(state.clone()).unwrap();
        let Success::Json(page) = handler
            .get_records(
                GetRecordsRequest {
                    shard_iterator: iterator(&handler),
                    limit: Some(10),
                },
                &scope(),
            )
            .unwrap()
        else {
            panic!("records");
        };
        assert_eq!(page["Records"][0]["SequenceNumber"], "15");
        assert_eq!(page["Records"][0]["Data"], STANDARD.encode(b"legacy"));
        let Success::Json(put) = put(&handler, b"new").unwrap() else {
            panic!("put");
        };
        assert_eq!(put["SequenceNumber"], "16");
        drop(handler);
        let handler = KinesisHandler::with_state(state).unwrap();
        let Success::Json(page) = handler
            .get_records(
                GetRecordsRequest {
                    shard_iterator: iterator(&handler),
                    limit: Some(10),
                },
                &scope(),
            )
            .unwrap()
        else {
            panic!("records");
        };
        assert_eq!(page["Records"].as_array().unwrap().len(), 2);
        drop(handler);
        std::fs::remove_dir_all(root).unwrap();
    }
}
