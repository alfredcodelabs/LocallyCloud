use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::{
    AuthorizationRequest, ServiceRoleAuthorizationRequest,
};
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{AwsProtocol, ServiceName, ServiceRegistry};
use locallycloud_state::StateDb;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::iceberg;
use crate::TARGET_PREFIX;

mod persistence;

const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const MAX_REQUEST_BODY: usize = 2 * 1024 * 1024;
const MAX_BATCH_REQUEST_BODY: usize = 6 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 1_000 * 1024;
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_BATCH_RECORDS: usize = 500;
const MAX_BUFFERED_RECORDS: usize = 1_000;
const MAX_BUFFERED_BYTES: usize = 10 * 1024 * 1024;
const LOCAL_COALESCE_DELAY: Duration = Duration::from_secs(2);
const COALESCE_SIZE_BYTES: usize = 1024 * 1024;
const MAX_DELIVERY_ATTEMPTS: u8 = 6;
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
const S3_DISPATCH_TIMEOUT: Duration = Duration::from_secs(10);
const SOURCE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const DESTINATION_ID: &str = "destinationId-000000000001";

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
            "arn:aws:firehose:{}:{}:deliverystream/{name}",
            self.region, self.account_id
        )
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
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

#[derive(Clone, Serialize, Deserialize)]
struct DestinationConfig {
    role_arn: String,
    s3_role_arn: String,
    bucket_arn: String,
    bucket: String,
    prefix: String,
    iceberg: Option<iceberg::Target>,
}

#[derive(Clone, Serialize, Deserialize)]
struct KinesisSource {
    arn: String,
    name: String,
    role_arn: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fetched: Option<String>,
    #[serde(default)]
    checkpoints: BTreeMap<String, String>,
    #[serde(default)]
    fetched_shards: BTreeMap<String, String>,
    #[serde(default)]
    next_shard: usize,
    ready: bool,
    failure: Option<String>,
    creation_timestamp: Option<f64>,
    stopped: bool,
}

#[derive(Clone)]
struct DeliveryStream {
    source: Option<KinesisSource>,
    generation: Uuid,
    created_at: f64,
    destination: DestinationConfig,
    role_caller: Option<RequestIdentity>,
    pending: VecDeque<Vec<u8>>,
    retained: VecDeque<Vec<u8>>,
    retry_token: Option<Uuid>,
    in_flight: Option<InFlight>,
    delivery_attempts: u8,
    retry_at: Option<Instant>,
    terminal_failure: bool,
}

#[derive(Clone)]
struct InFlight {
    token: Uuid,
    records: usize,
    bytes: usize,
}

struct Batch {
    key: StreamKey,
    generation: Uuid,
    token: Uuid,
    destination: DestinationConfig,
    role_caller: Option<RequestIdentity>,
    records: Vec<Vec<u8>>,
}

struct Inner {
    registry: Weak<ServiceRegistry>,
    streams: Mutex<HashMap<StreamKey, DeliveryStream>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    notify: Notify,
    shutting_down: AtomicBool,
    state: Option<Arc<StateDb>>,
}

pub(crate) struct FirehoseHandler {
    inner: Arc<Inner>,
}

pub struct FirehoseHandle {
    inner: Arc<Inner>,
}

impl FirehoseHandler {
    pub(crate) fn new(registry: Weak<ServiceRegistry>) -> (Self, FirehoseHandle) {
        let inner = Arc::new(Inner {
            registry,
            streams: Mutex::new(HashMap::new()),
            worker: Mutex::new(None),
            notify: Notify::new(),
            shutting_down: AtomicBool::new(false),
            state: None,
        });
        (
            Self {
                inner: Arc::clone(&inner),
            },
            FirehoseHandle { inner },
        )
    }

    pub(crate) fn with_state(
        registry: Weak<ServiceRegistry>,
        state: Arc<StateDb>,
    ) -> Result<(Self, FirehoseHandle), persistence::PersistError> {
        let streams = persistence::load(&state)?;
        let inner = Arc::new(Inner {
            registry,
            streams: Mutex::new(streams),
            worker: Mutex::new(None),
            notify: Notify::new(),
            shutting_down: AtomicBool::new(false),
            state: Some(state),
        });
        Ok((
            Self {
                inner: inner.clone(),
            },
            FirehoseHandle { inner },
        ))
    }

    async fn process(&self, request: &ServiceRequest) -> Result<Success, FirehoseError> {
        if request.method != Method::POST
            || request.uri.path() != "/"
            || request.uri.query().is_some()
        {
            return Err(FirehoseError::UnknownOperation);
        }
        validate_content_type(&request.headers)?;
        let operation = operation(&request.headers)?;
        let request_limit = if operation == "PutRecordBatch" {
            MAX_BATCH_REQUEST_BODY
        } else {
            MAX_REQUEST_BODY
        };
        if request.body.len() > request_limit {
            return Err(FirehoseError::InvalidArgument(
                "The request body exceeds the supported limit".into(),
            ));
        }
        let scope = Scope::new(request);
        if matches!(
            operation,
            "CreateDeliveryStream"
                | "ListDeliveryStreams"
                | "DescribeDeliveryStream"
                | "PutRecord"
                | "PutRecordBatch"
                | "DeleteDeliveryStream"
                | "LocallyCloudRetryDeliveryStream"
        ) {
            self.authorize_public_operation(request, &scope, operation)?;
        }
        match operation {
            "CreateDeliveryStream" => {
                self.create_delivery_stream(decode(&request.body)?, &scope, request)
                    .await
            }
            "ListDeliveryStreams" => self.list_delivery_streams(decode(&request.body)?, &scope),
            "DescribeDeliveryStream" => {
                self.describe_delivery_stream(decode(&request.body)?, &scope)
            }
            "PutRecord" => self.put_record(decode(&request.body)?, &scope),
            "PutRecordBatch" => self.put_record_batch(decode(&request.body)?, &scope),
            "DeleteDeliveryStream" => self.delete_delivery_stream(decode(&request.body)?, &scope),
            "LocallyCloudRetryDeliveryStream" => {
                self.retry_delivery_stream(decode(&request.body)?, &scope)
            }
            _ => Err(FirehoseError::UnknownOperation),
        }
    }

    fn list_delivery_streams(
        &self,
        request: ListDeliveryStreamsRequest,
        scope: &Scope,
    ) -> Result<Success, FirehoseError> {
        let limit = request.limit.unwrap_or(10);
        if !(1..=10_000).contains(&limit) {
            return Err(FirehoseError::InvalidArgument(
                "Limit must be between 1 and 10000".into(),
            ));
        }
        if let Some(start) = &request.exclusive_start_delivery_stream_name {
            validate_stream_name(start)?;
        }
        if request.delivery_stream_type.as_deref().is_some_and(|kind| {
            !matches!(
                kind,
                "DirectPut" | "KinesisStreamAsSource" | "MSKAsSource" | "DatabaseAsSource"
            )
        }) {
            return Err(FirehoseError::InvalidArgument(
                "Invalid DeliveryStreamType".into(),
            ));
        }
        let mut names: Vec<_> = self
            .inner
            .lock_streams()?
            .iter()
            .filter(|(key, stream)| {
                key.scope == *scope
                    && request
                        .exclusive_start_delivery_stream_name
                        .as_ref()
                        .is_none_or(|start| key.name > *start)
                    && request.delivery_stream_type.as_deref().is_none_or(|kind| {
                        kind == if stream.source.is_some() {
                            "KinesisStreamAsSource"
                        } else {
                            "DirectPut"
                        }
                    })
            })
            .map(|(key, _)| key.name.clone())
            .collect();
        names.sort_unstable();
        let has_more = names.len() > limit as usize;
        names.truncate(limit as usize);
        Ok(Success::Json(
            json!({"DeliveryStreamNames": names, "HasMoreDeliveryStreams": has_more}),
        ))
    }

    async fn create_delivery_stream(
        &self,
        request: CreateDeliveryStreamRequest,
        scope: &Scope,
        service_request: &ServiceRequest,
    ) -> Result<Success, FirehoseError> {
        validate_stream_name(&request.delivery_stream_name)?;
        let source = match (
            request
                .delivery_stream_type
                .as_deref()
                .unwrap_or("DirectPut"),
            request.kinesis_stream_source_configuration,
        ) {
            ("DirectPut", None) => None,
            ("KinesisStreamAsSource", Some(config)) => {
                let expected = format!(
                    "arn:aws:kinesis:{}:{}:stream/",
                    scope.region, scope.account_id
                );
                let name = config
                    .kinesis_stream_arn
                    .strip_prefix(&expected)
                    .filter(|name| !name.is_empty() && !name.contains('/'))
                    .ok_or_else(|| {
                        unsupported("KinesisStreamARN must identify a same-scope stream")
                    })?;
                validate_role_arn(&config.role_arn, &scope.account_id)?;
                let registry = self
                    .inner
                    .registry
                    .upgrade()
                    .ok_or_else(|| unsupported("Kinesis is unavailable"))?;
                if registry
                    .native_handler(&ServiceName::new("kinesis"))
                    .is_none()
                    || registry.internal_dispatcher().is_none()
                {
                    return Err(unsupported("Kinesis is unavailable"));
                }
                Some(KinesisSource {
                    arn: config.kinesis_stream_arn.clone(),
                    name: name.to_owned(),
                    role_arn: config.role_arn,
                    checkpoint: None,
                    fetched: None,
                    checkpoints: BTreeMap::new(),
                    fetched_shards: BTreeMap::new(),
                    next_shard: 0,
                    ready: false,
                    failure: None,
                    creation_timestamp: None,
                    stopped: false,
                })
            }
            _ => {
                return Err(unsupported(
                    "DeliveryStreamType/source configuration is unsupported",
                ))
            }
        };
        let destination = match (
            request.extended_s3_destination_configuration,
            request.iceberg_destination_configuration,
        ) {
            (Some(config), None) => DestinationConfig::extended_s3(config, scope)?,
            (None, Some(config)) => validate_iceberg_configuration(config, scope)?,
            _ => {
                return Err(FirehoseError::InvalidArgument(
                    "Exactly one destination configuration is required".into(),
                ));
            }
        };

        if destination.iceberg.is_some() {
            if source.is_some() {
                return Err(unsupported(
                    "Iceberg destination currently requires DirectPut",
                ));
            }
            let registry = self
                .inner
                .registry
                .upgrade()
                .ok_or_else(|| unsupported("Glue and S3 are unavailable"))?;
            if registry.native_handler(&ServiceName::new("glue")).is_none()
                || registry.native_handler(&ServiceName::new("s3")).is_none()
                || registry.internal_dispatcher().is_none()
            {
                return Err(unsupported("Glue and S3 are unavailable"));
            }
        }
        let role_caller =
            self.authorize_service_roles(service_request, scope, source.as_ref(), &destination)?;
        if let Some(target) = &destination.iceberg {
            let registry = self.inner.registry.upgrade().ok_or_else(|| {
                FirehoseError::ServiceUnavailable("Glue and S3 are unavailable".into())
            })?;
            let dispatcher = registry.internal_dispatcher().ok_or_else(|| {
                FirehoseError::ServiceUnavailable("Glue and S3 are unavailable".into())
            })?;
            iceberg::preflight(
                iceberg::Context {
                    dispatcher: &dispatcher,
                    account: &scope.account_id,
                    region: &scope.region,
                    bucket: &target.bucket,
                },
                target,
            )
            .await
            .map_err(|error| match error {
                iceberg::Error::Unsupported => FirehoseError::InvalidArgument(
                    "Iceberg table metadata is unsupported or unavailable".into(),
                ),
                iceberg::Error::Transient => FirehoseError::ServiceUnavailable(
                    "Iceberg table metadata could not be read".into(),
                ),
            })?;
        }
        let key = StreamKey::new(scope, &request.delivery_stream_name);
        let mut streams = self.inner.lock_streams()?;
        if streams.contains_key(&key) {
            return Err(FirehoseError::ResourceInUse(format!(
                "Firehose {} under accountId {} already exists",
                request.delivery_stream_name, scope.account_id
            )));
        }
        let stream = DeliveryStream {
            source,
            generation: Uuid::new_v4(),
            created_at: now_epoch()?,
            destination,
            role_caller,
            pending: VecDeque::new(),
            retained: VecDeque::new(),
            retry_token: None,
            in_flight: None,
            delivery_attempts: 0,
            retry_at: None,
            terminal_failure: false,
        };
        self.inner.persist_create(&key, &stream)?;
        streams.insert(key, stream);
        if request.delivery_stream_type.as_deref() == Some("KinesisStreamAsSource") {
            self.inner.ensure_worker()?;
            self.inner.notify.notify_one();
        }
        Ok(Success::Json(json!({
            "DeliveryStreamARN": scope.stream_arn(&request.delivery_stream_name)
        })))
    }

    fn authorize_public_operation(
        &self,
        request: &ServiceRequest,
        scope: &Scope,
        operation: &str,
    ) -> Result<(), FirehoseError> {
        let Some(registry) = self.inner.registry.upgrade() else {
            return Ok(());
        };
        let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
            return Ok(());
        };
        if !evaluator.strict_sigv4_required() {
            return Ok(());
        }
        if request
            .headers
            .get("x-locallycloud-verified-external-sigv4")
            != Some(&HeaderValue::from_static("1"))
        {
            return Err(FirehoseError::AccessDenied);
        }
        let access_key_id = request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(RequestIdentity::access_key_from_authorization)
            .ok_or(FirehoseError::AccessDenied)?;
        let body: Value = serde_json::from_slice(&request.body)
            .map_err(|error| FirehoseError::Serialization(error.to_string()))?;
        let resource = if operation == "ListDeliveryStreams" {
            "*".to_owned()
        } else {
            let name = body
                .get("DeliveryStreamName")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    FirehoseError::InvalidArgument("DeliveryStreamName is required".into())
                })?;
            validate_stream_name(name)?;
            scope.stream_arn(name)
        };
        evaluator
            .authorize(AuthorizationRequest {
                request_identity: RequestIdentity {
                    account_id: scope.account_id.clone(),
                    access_key_id: Some(access_key_id),
                    arn: None,
                },
                delegated_identity: None,
                source_service: "firehose".into(),
                action: format!(
                    "firehose:{}",
                    if operation == "LocallyCloudRetryDeliveryStream" {
                        "UpdateDestination"
                    } else {
                        operation
                    }
                ),
                resource,
                context: Default::default(),
            })
            .map_err(|_| FirehoseError::AccessDenied)
    }

    fn authorize_service_roles(
        &self,
        request: &ServiceRequest,
        scope: &Scope,
        source: Option<&KinesisSource>,
        destination: &DestinationConfig,
    ) -> Result<Option<RequestIdentity>, FirehoseError> {
        let Some(registry) = self.inner.registry.upgrade() else {
            return Ok(None);
        };
        let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
            return Ok(None);
        };
        if !evaluator.strict_sigv4_required() {
            return Ok(None);
        }
        if request
            .headers
            .get("x-locallycloud-verified-external-sigv4")
            != Some(&HeaderValue::from_static("1"))
        {
            return Err(FirehoseError::AccessDenied);
        }
        let access_key_id = request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(RequestIdentity::access_key_from_authorization)
            .ok_or(FirehoseError::AccessDenied)?;
        let caller = RequestIdentity {
            account_id: scope.account_id.clone(),
            access_key_id: Some(access_key_id),
            arn: None,
        };
        authorize_roles(&registry, scope, &caller, source, destination, true)?;
        Ok(Some(caller))
    }

    fn describe_delivery_stream(
        &self,
        request: StreamNameRequest,
        scope: &Scope,
    ) -> Result<Success, FirehoseError> {
        validate_stream_name(&request.delivery_stream_name)?;
        let streams = self.inner.lock_streams()?;
        let stream = streams
            .get(&StreamKey::new(scope, &request.delivery_stream_name))
            .ok_or_else(|| stream_not_found(scope))?;
        let mut description = json!({
            "DeliveryStreamDescription": {
                "DeliveryStreamName": request.delivery_stream_name,
                "DeliveryStreamARN": scope.stream_arn(&request.delivery_stream_name),
                "DeliveryStreamStatus": "ACTIVE",
                "DeliveryStreamType": "DirectPut",
                "VersionId": "1",
                "CreateTimestamp": stream.created_at,
                "Destinations": [{
                    "DestinationId": DESTINATION_ID,
                    "ExtendedS3DestinationDescription": {
                        "RoleARN": stream.destination.role_arn,
                        "BucketARN": stream.destination.bucket_arn,
                        "Prefix": stream.destination.prefix,
                        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {"NoEncryptionConfig": "NoEncryption"},
                        "CloudWatchLoggingOptions": {"Enabled": false},
                        "S3BackupMode": "Disabled"
                    }
                }],
                "HasMoreDestinations": false
            }
        });
        if let Some(target) = &stream.destination.iceberg {
            description["DeliveryStreamDescription"]["Destinations"][0] = json!({
                "DestinationId": DESTINATION_ID,
                "IcebergDestinationDescription": {
                    "CatalogConfiguration": {"CatalogARN": format!("arn:aws:glue:{}:{}:catalog", scope.region, scope.account_id)},
                    "RoleARN": stream.destination.role_arn,
                    "S3DestinationDescription": {
                        "RoleARN": stream.destination.s3_role_arn,
                        "BucketARN": stream.destination.bucket_arn,
                        "Prefix": stream.destination.prefix,
                    },
                    "DestinationTableConfigurationList": [{
                        "DestinationDatabaseName": target.database,
                        "DestinationTableName": target.table,
                    }],
                },
            });
        }
        if let Some(source) = &stream.source {
            description["DeliveryStreamDescription"]["DeliveryStreamType"] =
                json!("KinesisStreamAsSource");
            description["DeliveryStreamDescription"]["DeliveryStreamStatus"] =
                json!(if source.stopped {
                    "CREATING_FAILED"
                } else if source.ready {
                    "ACTIVE"
                } else {
                    "CREATING"
                });
            description["DeliveryStreamDescription"]["Source"] = json!({
                "KinesisStreamSourceDescription": {"KinesisStreamARN": source.arn, "RoleARN": source.role_arn}
            });
            if let Some(failure) = &source.failure {
                description["DeliveryStreamDescription"]["LocallyCloudSourceFailure"] =
                    json!(failure);
            }
        }
        if stream.terminal_failure {
            description["DeliveryStreamDescription"]["LocallyCloudDeliveryFailure"] = json!({
                "State": "RETRY_EXHAUSTED",
                "Attempts": stream.delivery_attempts,
                "RetainedRecordCount": stream.retained.len(),
                "PendingRecordCount": stream.pending.len(),
                "Durable": self.inner.state.is_some()
            });
        }
        Ok(Success::Json(description))
    }

    fn put_record(
        &self,
        request: PutRecordRequest,
        scope: &Scope,
    ) -> Result<Success, FirehoseError> {
        validate_stream_name(&request.delivery_stream_name)?;
        let data = base64::engine::general_purpose::STANDARD
            .decode(request.record.data)
            .map_err(|_| {
                FirehoseError::InvalidArgument("Record.Data is not valid Base64".into())
            })?;
        if data.len() > MAX_RECORD_BYTES {
            return Err(FirehoseError::InvalidArgument(format!(
                "Record.Data must decode to 0-{MAX_RECORD_BYTES} bytes"
            )));
        }
        let key = StreamKey::new(scope, &request.delivery_stream_name);
        let mut streams = self.inner.lock_streams()?;
        let stream = streams
            .get_mut(&key)
            .ok_or_else(|| stream_not_found(scope))?;
        if stream.source.is_some() {
            return Err(unsupported(
                "PutRecord is unavailable for KinesisStreamAsSource",
            ));
        }
        if stream.terminal_failure {
            return Err(delivery_exhausted(stream));
        }
        self.inner.authorize_stream_runtime(scope, stream)?;
        if stream.destination.iceberg.is_some() && !iceberg::valid_record(&data) {
            return Err(FirehoseError::InvalidArgument(
                "Iceberg Record.Data must contain a flat JSON object; destination schema validation applies during delivery".into(),
            ));
        }
        let (buffered_records, buffered_bytes) = buffered_usage(stream);
        if buffered_records >= MAX_BUFFERED_RECORDS
            || buffered_bytes.saturating_add(data.len()) > MAX_BUFFERED_BYTES
        {
            return Err(FirehoseError::ServiceUnavailable(
                "The local delivery queue is full".into(),
            ));
        }
        self.inner.ensure_worker()?;
        self.inner
            .persist_append(&key, stream, std::slice::from_ref(&data))?;
        stream.pending.push_back(data);
        drop(streams);
        self.inner.notify.notify_one();
        Ok(Success::Json(json!({
            "RecordId": Uuid::new_v4().to_string(),
            "Encrypted": false
        })))
    }

    fn put_record_batch(
        &self,
        request: PutRecordBatchRequest,
        scope: &Scope,
    ) -> Result<Success, FirehoseError> {
        validate_stream_name(&request.delivery_stream_name)?;
        if request.records.is_empty() || request.records.len() > MAX_BATCH_RECORDS {
            return Err(FirehoseError::InvalidArgument(
                "Records must contain 1-500 entries".into(),
            ));
        }
        let mut total_bytes = 0usize;
        let mut records = Vec::with_capacity(request.records.len());
        for record in request.records {
            let data = base64::engine::general_purpose::STANDARD
                .decode(record.data)
                .map_err(|_| {
                    FirehoseError::InvalidArgument("Record.Data is not valid Base64".into())
                })?;
            if data.len() > MAX_RECORD_BYTES {
                return Err(FirehoseError::InvalidArgument(format!(
                    "Record.Data must decode to 0-{MAX_RECORD_BYTES} bytes"
                )));
            }
            total_bytes += data.len();
            if total_bytes > MAX_BATCH_BYTES {
                return Err(FirehoseError::InvalidArgument(
                    "Records exceed the 4 MiB batch limit".into(),
                ));
            }
            records.push(data);
        }

        let key = StreamKey::new(scope, &request.delivery_stream_name);
        let mut streams = self.inner.lock_streams()?;
        let stream = streams
            .get_mut(&key)
            .ok_or_else(|| stream_not_found(scope))?;
        if stream.source.is_some() {
            return Err(unsupported(
                "PutRecordBatch is unavailable for KinesisStreamAsSource",
            ));
        }
        if stream.terminal_failure {
            return Err(delivery_exhausted(stream));
        }
        self.inner.authorize_stream_runtime(scope, stream)?;
        self.inner.ensure_worker()?;
        let (mut buffered_records, mut buffered_bytes) = buffered_usage(stream);
        let mut failed = 0usize;
        let mut accepted = false;
        let mut responses = Vec::with_capacity(records.len());
        let mut accepted_data = Vec::new();
        for data in records {
            if stream.destination.iceberg.is_some() && !iceberg::valid_record(&data) {
                failed += 1;
                responses.push(json!({
                    "ErrorCode": "InvalidArgumentException",
                    "ErrorMessage": "Iceberg Record.Data must contain a flat JSON object; destination schema validation applies during delivery"
                }));
                continue;
            }
            if buffered_records >= MAX_BUFFERED_RECORDS
                || buffered_bytes.saturating_add(data.len()) > MAX_BUFFERED_BYTES
            {
                failed += 1;
                responses.push(json!({
                    "ErrorCode": "ServiceUnavailableException",
                    "ErrorMessage": "The local delivery queue is full"
                }));
                continue;
            }
            buffered_records += 1;
            buffered_bytes += data.len();
            responses.push(json!({ "RecordId": Uuid::new_v4().to_string() }));
            accepted_data.push(data);
            accepted = true;
        }
        self.inner.persist_append(&key, stream, &accepted_data)?;
        stream.pending.extend(accepted_data);
        drop(streams);
        if accepted {
            self.inner.notify.notify_one();
        }
        Ok(Success::Json(json!({
            "Encrypted": false,
            "FailedPutCount": failed,
            "RequestResponses": responses
        })))
    }

    fn delete_delivery_stream(
        &self,
        request: DeleteDeliveryStreamRequest,
        scope: &Scope,
    ) -> Result<Success, FirehoseError> {
        validate_stream_name(&request.delivery_stream_name)?;
        let force = request.allow_force_delete.unwrap_or(false);
        let key = StreamKey::new(scope, &request.delivery_stream_name);
        let mut streams = self.inner.lock_streams()?;
        let stream = streams.get(&key).ok_or_else(|| stream_not_found(scope))?;
        if force {
            if !stream.terminal_failure || stream.in_flight.is_some() {
                return Err(unsupported(
                    "AllowForceDelete requires exhausted delivery retries",
                ));
            }
            let (discarded_records, discarded_bytes) = buffered_usage(stream);
            tracing::warn!(
                stream = %request.delivery_stream_name,
                discarded_records,
                discarded_bytes,
                "Force-deleted terminal Firehose stream and discarded in-memory records"
            );
            self.inner.persist_delete(&key)?;
            streams.remove(&key);
            return Ok(Success::Json(json!({})));
        }
        if !stream.pending.is_empty() || !stream.retained.is_empty() || stream.in_flight.is_some() {
            return Err(FirehoseError::ResourceInUse(
                "The delivery stream still has undelivered records".into(),
            ));
        }
        self.inner.persist_delete(&key)?;
        streams.remove(&key);
        Ok(Success::Json(json!({})))
    }

    fn retry_delivery_stream(
        &self,
        request: StreamNameRequest,
        scope: &Scope,
    ) -> Result<Success, FirehoseError> {
        validate_stream_name(&request.delivery_stream_name)?;
        let key = StreamKey::new(scope, &request.delivery_stream_name);
        let mut streams = self.inner.lock_streams()?;
        let stream = streams
            .get_mut(&key)
            .ok_or_else(|| stream_not_found(scope))?;
        if !stream.terminal_failure || stream.in_flight.is_some() || stream.retained.is_empty() {
            return Err(FirehoseError::ResourceInUse(
                "The delivery stream has no exhausted batch to retry".into(),
            ));
        }
        self.inner.ensure_worker()?;
        let mut updated = stream.clone();
        updated.terminal_failure = false;
        updated.delivery_attempts = 0;
        updated.retry_at = None;
        // Keep retry_token and retained bytes: Iceberg checks the same token after a lost ACK.
        self.inner.persist_create(&key, &updated)?;
        *stream = updated;
        drop(streams);
        self.inner.notify.notify_one();
        Ok(Success::Json(json!({})))
    }
}

fn authorize_roles(
    registry: &ServiceRegistry,
    scope: &Scope,
    caller: &RequestIdentity,
    source: Option<&KinesisSource>,
    destination: &DestinationConfig,
    assignment: bool,
) -> Result<(), FirehoseError> {
    let evaluator = registry
        .authorization_evaluator(&ServiceName::new("iam"))
        .ok_or(FirehoseError::AccessDenied)?;
    let authorize = |role_arn: &str, action: &str, resource: &str| {
        let request = ServiceRoleAuthorizationRequest {
            source_arn: None,
            caller: caller.clone(),
            role_arn: role_arn.to_owned(),
            service_principal: "firehose.amazonaws.com".into(),
            action: action.into(),
            resource: resource.into(),
        };
        if assignment {
            evaluator.authorize_service_role(request)
        } else {
            evaluator.authorize_service_role_execution(request)
        }
        .map_err(|_| FirehoseError::AccessDenied)
    };
    if let Some(source) = source {
        for action in [
            "kinesis:DescribeStream",
            "kinesis:ListShards",
            "kinesis:GetShardIterator",
            "kinesis:GetRecords",
        ] {
            authorize(&source.role_arn, action, &source.arn)?;
        }
    }
    let objects = format!("{}/*", destination.bucket_arn);
    authorize(&destination.s3_role_arn, "s3:PutObject", &objects)?;
    if let Some(target) = &destination.iceberg {
        let table = format!(
            "arn:aws:glue:{}:{}:table/{}/{}",
            scope.region, scope.account_id, target.database, target.table
        );
        for action in ["glue:GetTable", "glue:UpdateTable"] {
            authorize(&destination.role_arn, action, &table)?;
        }
        authorize(&destination.s3_role_arn, "s3:GetObject", &objects)?;
    }
    Ok(())
}

impl FirehoseHandle {
    pub(crate) fn resume(&self) -> Result<(), persistence::PersistError> {
        let needs_worker = self
            .inner
            .lock_streams()
            .map_err(|_| std::io::Error::other("Firehose stream lock is poisoned"))?
            .values()
            .any(|stream| {
                !stream.terminal_failure
                    && (!stream.pending.is_empty()
                        || !stream.retained.is_empty()
                        || stream.source.as_ref().is_some_and(|source| !source.stopped))
            });
        if needs_worker {
            self.inner
                .ensure_worker()
                .map_err(|_| std::io::Error::other("Firehose worker could not start"))?;
            self.inner.notify.notify_one();
        }
        Ok(())
    }

    pub async fn shutdown(self) {
        self.inner.shutting_down.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
        let worker = self
            .inner
            .worker
            .lock()
            .ok()
            .and_then(|mut worker| worker.take());
        if let Some(worker) = worker {
            if let Err(error) = worker.await {
                tracing::warn!(%error, "Firehose delivery worker terminated unexpectedly");
            }
        }
    }
}

impl Inner {
    fn authorize_stream_runtime(
        &self,
        scope: &Scope,
        stream: &DeliveryStream,
    ) -> Result<(), FirehoseError> {
        let Some(caller) = &stream.role_caller else {
            return Ok(());
        };
        let registry = self.registry.upgrade().ok_or(FirehoseError::AccessDenied)?;
        authorize_roles(
            &registry,
            scope,
            caller,
            stream.source.as_ref(),
            &stream.destination,
            false,
        )
        .map_err(|_| {
            FirehoseError::ServiceUnavailable("Firehose role authorization is denied".into())
        })
    }

    fn lock_streams(
        &self,
    ) -> Result<MutexGuard<'_, HashMap<StreamKey, DeliveryStream>>, FirehoseError> {
        self.streams.lock().map_err(|_| FirehoseError::Internal)
    }

    fn ensure_worker(self: &Arc<Self>) -> Result<(), FirehoseError> {
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(FirehoseError::ServiceUnavailable(
                "Firehose is shutting down".into(),
            ));
        }
        let mut worker = self.worker.lock().map_err(|_| FirehoseError::Internal)?;
        if worker.as_ref().is_none_or(JoinHandle::is_finished) {
            let inner = Arc::clone(self);
            *worker = Some(tokio::spawn(async move {
                inner.worker_loop().await;
            }));
        }
        Ok(())
    }

    async fn worker_loop(self: Arc<Self>) {
        loop {
            match self.next_retry_delay() {
                Some(delay) => {
                    tokio::select! {
                        _ = self.notify.notified() => {},
                        _ = tokio::time::sleep(delay) => {},
                    }
                }
                None => self.notify.notified().await,
            }
            if self.shutting_down.load(Ordering::Acquire) {
                return;
            }
            self.poll_sources().await;
            self.coalesce().await;
            loop {
                if self.shutting_down.load(Ordering::Acquire) {
                    return;
                }
                let batches = self.take_batches();
                if batches.is_empty() {
                    break;
                }
                for batch in batches {
                    if let Some(caller) = &batch.role_caller {
                        let authorized = self.registry.upgrade().is_some_and(|registry| {
                            authorize_roles(
                                &registry,
                                &batch.key.scope,
                                caller,
                                None,
                                &batch.destination,
                                false,
                            )
                            .is_ok()
                        });
                        if !authorized {
                            self.defer_unauthorized_batch(batch);
                            continue;
                        }
                    }
                    let delivered = self.deliver_batch(&batch).await;
                    self.complete_batch(batch, delivered);
                }
            }
        }
    }

    async fn coalesce(&self) {
        let deadline = Instant::now() + LOCAL_COALESCE_DELAY;
        while !self.shutting_down.load(Ordering::Acquire) && !self.batch_ready() {
            tokio::select! {
                _ = self.notify.notified() => {},
                _ = tokio::time::sleep_until(deadline.into()) => break,
            }
        }
    }

    fn batch_ready(&self) -> bool {
        self.streams.lock().is_ok_and(|streams| {
            streams.values().any(|stream| {
                if stream.terminal_failure || stream.in_flight.is_some() {
                    return false;
                }
                if !stream.retained.is_empty() {
                    return stream.retry_at.is_none_or(|due| due <= Instant::now());
                }
                !stream.pending.is_empty()
                    && (stream.source.is_some()
                        || stream.pending.len() >= MAX_BUFFERED_RECORDS
                        || stream.pending.iter().map(Vec::len).sum::<usize>()
                            >= COALESCE_SIZE_BYTES)
            })
        })
    }

    fn next_retry_delay(&self) -> Option<Duration> {
        let streams = self.streams.lock().ok()?;
        let retry = streams
            .values()
            .filter(|stream| {
                !stream.terminal_failure
                    && (!stream.retained.is_empty() || !stream.pending.is_empty())
            })
            .filter_map(|stream| stream.retry_at)
            .map(|due| due.saturating_duration_since(Instant::now()))
            .min();
        if streams.values().any(|stream| {
            stream.source.as_ref().is_some_and(|source| !source.stopped) && !stream.terminal_failure
        }) {
            Some(
                retry
                    .unwrap_or(SOURCE_POLL_INTERVAL)
                    .min(SOURCE_POLL_INTERVAL),
            )
        } else {
            retry
        }
    }

    async fn poll_sources(&self) {
        let candidates = match self.lock_streams() {
            Ok(streams) => streams
                .iter()
                .filter(|(_, stream)| {
                    stream.source.is_some()
                        && !stream.terminal_failure
                        && stream.pending.is_empty()
                        && stream.retained.is_empty()
                        && stream.in_flight.is_none()
                        && !stream.source.as_ref().is_some_and(|source| source.stopped)
                })
                .map(|(key, stream)| {
                    (
                        key.clone(),
                        stream.generation,
                        stream
                            .source
                            .as_ref()
                            .expect("filtered source")
                            .name
                            .clone(),
                        stream
                            .source
                            .as_ref()
                            .expect("filtered source")
                            .checkpoints
                            .clone(),
                        stream
                            .source
                            .as_ref()
                            .expect("filtered source")
                            .creation_timestamp,
                        stream.source.as_ref().expect("filtered source").clone(),
                        stream.destination.clone(),
                        stream.role_caller.clone(),
                    )
                })
                .collect::<Vec<_>>(),
            Err(_) => return,
        };
        for (
            key,
            generation,
            name,
            checkpoint,
            creation_timestamp,
            source,
            destination,
            role_caller,
        ) in candidates
        {
            let authorized = role_caller.as_ref().is_none_or(|caller| {
                self.registry.upgrade().is_some_and(|registry| {
                    authorize_roles(
                        &registry,
                        &key.scope,
                        caller,
                        Some(&source),
                        &destination,
                        false,
                    )
                    .is_ok()
                })
            });
            let result = if authorized {
                self.fetch_source_record(
                    &key,
                    &name,
                    &checkpoint,
                    creation_timestamp,
                    source.next_shard,
                )
                .await
            } else {
                Err("SOURCE_ACCESS_DENIED")
            };
            let Ok((observed_creation, records, next_shard)) = result else {
                let reason = result.err().unwrap_or("SOURCE_UNAVAILABLE");
                if let Ok(mut streams) = self.lock_streams() {
                    if let Some(stream) = streams
                        .get_mut(&key)
                        .filter(|stream| stream.generation == generation)
                    {
                        if let Some(source) = stream.source.as_mut() {
                            source.failure = Some(reason.to_string());
                            source.stopped = reason == "SOURCE_REPLACED";
                        }
                    }
                }
                tracing::warn!(stream = %key.name, reason, "Firehose Kinesis source poll failed");
                continue;
            };
            let Ok(mut streams) = self.lock_streams() else {
                return;
            };
            let Some(stream) = streams.get_mut(&key) else {
                continue;
            };
            if stream.generation != generation
                || stream.terminal_failure
                || !stream.pending.is_empty()
                || !stream.retained.is_empty()
                || stream.in_flight.is_some()
            {
                continue;
            }
            let previous = stream.clone();
            let Some(source) = stream.source.as_mut() else {
                continue;
            };
            source.ready = true;
            source.creation_timestamp = Some(observed_creation);
            if records
                .iter()
                .any(|(_, _, data)| data.len() > MAX_RECORD_BYTES)
                || records.iter().map(|(_, _, data)| data.len()).sum::<usize>() > MAX_BUFFERED_BYTES
            {
                source.failure = Some("SOURCE_BATCH_TOO_LARGE".to_string());
                tracing::warn!(stream = %key.name, "Firehose Kinesis source page exceeds supported limit");
                continue;
            }
            source.failure = None;
            for (shard, sequence, _) in &records {
                source
                    .fetched_shards
                    .insert(shard.clone(), sequence.clone());
            }
            source.next_shard = next_shard;
            let data = records
                .into_iter()
                .map(|(_, _, data)| data)
                .collect::<Vec<_>>();
            if let Err(error) = self.persist_append(&key, stream, &data) {
                *stream = previous;
                tracing::error!(stream = %key.name, ?error, "Firehose source records could not be committed");
                continue;
            }
            stream.pending.extend(data);
        }
    }

    async fn fetch_source_record(
        &self,
        key: &StreamKey,
        name: &str,
        checkpoints: &BTreeMap<String, String>,
        creation_timestamp: Option<f64>,
        next_shard: usize,
    ) -> Result<(f64, Vec<(String, String, Vec<u8>)>, usize), &'static str> {
        let description = self
            .call_kinesis(key, "DescribeStream", json!({"StreamName": name}))
            .await
            .map_err(|_| "SOURCE_UNAVAILABLE")?;
        let observed_creation = description["StreamDescription"]["StreamCreationTimestamp"]
            .as_f64()
            .ok_or("SOURCE_UNAVAILABLE")?;
        if creation_timestamp.is_some_and(|expected| expected != observed_creation) {
            return Err("SOURCE_REPLACED");
        }
        let shards = self
            .call_kinesis(key, "ListShards", json!({"StreamName": name}))
            .await
            .map_err(|_| "SOURCE_UNAVAILABLE")?;
        let shards = shards["Shards"]
            .as_array()
            .filter(|shards| !shards.is_empty())
            .ok_or("SOURCE_UNAVAILABLE")?;
        let mut records = Vec::new();
        let mut bytes = 0;
        let mut cursor = next_shard % shards.len();
        for offset in 0..shards.len() {
            let index = (next_shard + offset) % shards.len();
            let shard = shards[index]["ShardId"]
                .as_str()
                .ok_or("SOURCE_UNAVAILABLE")?;
            let mut request =
                json!({"StreamName":name,"ShardId":shard,"ShardIteratorType":"TRIM_HORIZON"});
            if let Some(sequence) = checkpoints.get(shard) {
                request["ShardIteratorType"] = json!("AFTER_SEQUENCE_NUMBER");
                request["StartingSequenceNumber"] = json!(sequence);
            }
            let iterator = self
                .call_kinesis(key, "GetShardIterator", request)
                .await
                .map_err(|_| "SOURCE_UNAVAILABLE")?;
            let iterator = iterator["ShardIterator"]
                .as_str()
                .ok_or("SOURCE_UNAVAILABLE")?;
            let page = self.call_kinesis(key, "GetRecords", json!({"ShardIterator":iterator,"Limit":(MAX_BUFFERED_RECORDS / shards.len()).max(1)})).await.map_err(|_| "SOURCE_UNAVAILABLE")?;
            let mut full = false;
            for record in page["Records"].as_array().ok_or("SOURCE_UNAVAILABLE")? {
                let sequence = record["SequenceNumber"]
                    .as_str()
                    .ok_or("SOURCE_UNAVAILABLE")?;
                let data = record["Data"].as_str().ok_or("SOURCE_UNAVAILABLE")?;
                let data = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|_| "SOURCE_UNAVAILABLE")?;
                if bytes + data.len() > MAX_BUFFERED_BYTES || records.len() >= MAX_BUFFERED_RECORDS
                {
                    full = true;
                    break;
                }
                bytes += data.len();
                records.push((shard.to_string(), sequence.to_string(), data));
            }
            cursor = (index + 1) % shards.len();
            if full || bytes >= MAX_BUFFERED_BYTES || records.len() >= MAX_BUFFERED_RECORDS {
                break;
            }
        }
        let current = self
            .call_kinesis(key, "DescribeStream", json!({"StreamName":name}))
            .await
            .map_err(|_| "SOURCE_UNAVAILABLE")?;
        if current["StreamDescription"]["StreamCreationTimestamp"].as_f64()
            != Some(observed_creation)
        {
            return Err("SOURCE_REPLACED");
        }
        Ok((observed_creation, records, cursor))
    }

    async fn call_kinesis(
        &self,
        key: &StreamKey,
        operation: &str,
        body: Value,
    ) -> Result<Value, ()> {
        let registry = self.registry.upgrade().ok_or(())?;
        let dispatcher = registry.internal_dispatcher().ok_or(())?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static(CONTENT_TYPE),
        );
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("Kinesis_20131202.{operation}")).map_err(|_| ())?,
        );
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential=local/19700101/{}/kinesis/aws4_request",
            key.scope.region
        );
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&authorization).map_err(|_| ())?,
        );
        let uri: Uri = "/".parse().map_err(|_| ())?;
        let response = tokio::time::timeout(
            S3_DISPATCH_TIMEOUT,
            dispatcher.dispatch_scoped(
                &Method::POST,
                &uri,
                &headers,
                Bytes::from(body.to_string()),
                &Uuid::new_v4().to_string(),
                &key.scope.account_id,
                &key.scope.region,
            ),
        )
        .await
        .map_err(|_| ())?;
        if !response.status().is_success() {
            return Err(());
        }
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .map_err(|_| ())?;
        serde_json::from_slice(&body).map_err(|_| ())
    }

    fn take_batches(&self) -> Vec<Batch> {
        let Ok(mut streams) = self.streams.lock() else {
            tracing::error!("Firehose stream store lock is poisoned");
            return Vec::new();
        };
        streams
            .iter_mut()
            .filter_map(|(key, stream)| {
                if stream.in_flight.is_some() || stream.terminal_failure
                    || stream.retry_at.is_some_and(|due| due > Instant::now())
                {
                    return None;
                }
                let queue = if !stream.retained.is_empty() {
                    if stream.retry_at.is_some_and(|due| due > Instant::now()) {
                        return None;
                    }
                    "retained"
                } else if !stream.pending.is_empty() {
                    "pending"
                } else {
                    return None;
                };
                let count = if queue == "retained" { stream.retained.len() } else { stream.pending.len() };
                let token = stream.retry_token.unwrap_or_else(Uuid::new_v4);
                if let Err(error) = self.persist_take(key, queue, count, token) {
                    stream.retry_at = Some(Instant::now() + SOURCE_POLL_INTERVAL);
                    tracing::error!(stream = %key.name, ?error, "Firehose batch could not be journaled");
                    return None;
                }
                stream.retry_token = None;
                stream.retry_at = None;
                let records = if queue == "retained" {
                    stream.retained.drain(..).collect::<Vec<_>>()
                } else {
                    stream.pending.drain(..).collect::<Vec<_>>()
                };
                stream.in_flight = Some(InFlight {
                    token,
                    records: records.len(),
                    bytes: records.iter().map(Vec::len).sum(),
                });
                Some(Batch {
                    key: key.clone(),
                    generation: stream.generation,
                    token,
                    destination: stream.destination.clone(),
                    role_caller: stream.role_caller.clone(),
                    records,
                })
            })
            .collect()
    }

    fn defer_unauthorized_batch(&self, batch: Batch) {
        let Ok(mut streams) = self.streams.lock() else {
            return;
        };
        let Some(stream) = streams.get_mut(&batch.key) else {
            return;
        };
        if stream.generation != batch.generation
            || stream.in_flight.as_ref().map(|flight| flight.token) != Some(batch.token)
        {
            return;
        }
        let mut updated = stream.clone();
        updated.in_flight = None;
        updated.retry_token = Some(batch.token);
        updated.retained.extend(batch.records.iter().cloned());
        updated.retry_at = Some(Instant::now() + SOURCE_POLL_INTERVAL);
        if let Err(error) = self.persist_complete(
            &batch.key,
            &updated,
            batch.token,
            batch.records.len(),
            false,
        ) {
            stream.in_flight = None;
            stream.retry_token = Some(batch.token);
            stream.retained.extend(batch.records);
            stream.retry_at = Some(Instant::now() + SOURCE_POLL_INTERVAL);
            tracing::error!(stream = %batch.key.name, ?error, "Firehose denied batch could not be retained");
            self.notify.notify_one();
            return;
        }
        *stream = updated;
        tracing::warn!(stream = %batch.key.name, "Firehose delivery role authorization denied; batch retained");
    }

    async fn deliver_batch(&self, batch: &Batch) -> bool {
        let Some(registry) = self.registry.upgrade() else {
            tracing::warn!(stream = %batch.key.name, "Firehose registry is unavailable");
            return false;
        };
        let Some(dispatcher) = registry.internal_dispatcher() else {
            tracing::warn!(stream = %batch.key.name, "Firehose internal dispatcher is unavailable");
            return false;
        };
        if let Some(target) = &batch.destination.iceberg {
            return iceberg::append(
                iceberg::Context {
                    dispatcher: &dispatcher,
                    account: &batch.key.scope.account_id,
                    region: &batch.key.scope.region,
                    bucket: &target.bucket,
                },
                target,
                batch.token,
                &batch.records,
            )
            .await
            .is_ok();
        }
        let key = object_key(&batch.destination.prefix, &batch.key.name, batch.token);
        let uri: Uri = match format!(
            "/{}/{}",
            percent_encode(&batch.destination.bucket, false),
            percent_encode(&key, true)
        )
        .parse()
        {
            Ok(uri) => uri,
            Err(error) => {
                tracing::warn!(stream = %batch.key.name, %error, "Firehose S3 URI is invalid");
                return false;
            }
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static(
                "AWS4-HMAC-SHA256 Credential=locallycloud/19700101/us-east-1/s3/aws4_request",
            ),
        );
        let body = Bytes::from(
            batch
                .records
                .iter()
                .flat_map(|record| record.iter().copied())
                .collect::<Vec<_>>(),
        );
        let request_id = Uuid::new_v4().to_string();
        let response = tokio::time::timeout(
            S3_DISPATCH_TIMEOUT,
            dispatcher.dispatch_scoped(
                &Method::PUT,
                &uri,
                &headers,
                body,
                &request_id,
                &batch.key.scope.account_id,
                &batch.key.scope.region,
            ),
        )
        .await;
        let Ok(response) = response else {
            tracing::warn!(stream = %batch.key.name, "Firehose S3 PutObject timed out");
            return false;
        };
        let has_etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.is_empty());
        if !response.status().is_success() || !has_etag {
            tracing::warn!(
                stream = %batch.key.name,
                status = %response.status(),
                has_etag,
                "Firehose S3 PutObject was not acknowledged"
            );
            return false;
        }
        true
    }

    fn complete_batch(&self, batch: Batch, delivered: bool) {
        let Ok(mut streams) = self.streams.lock() else {
            tracing::error!("Firehose stream store lock is poisoned after delivery");
            return;
        };
        let Some(stream) = streams.get_mut(&batch.key) else {
            return;
        };
        if stream.generation != batch.generation
            || stream.in_flight.as_ref().map(|value| value.token) != Some(batch.token)
        {
            return;
        }
        let mut updated = stream.clone();
        updated.in_flight = None;
        if delivered {
            if let Some(source) = updated.source.as_mut() {
                if let Some(sequence) = source.fetched.take() {
                    source
                        .checkpoints
                        .insert("shardId-000000000000".into(), sequence);
                }
                source.checkpoints.append(&mut source.fetched_shards);
            }
            updated.delivery_attempts = 0;
            updated.retry_at = None;
        } else {
            updated.retry_token = Some(batch.token);
            updated.retained.extend(batch.records.iter().cloned());
            updated.delivery_attempts = updated.delivery_attempts.saturating_add(1);
            if updated.delivery_attempts >= MAX_DELIVERY_ATTEMPTS {
                updated.terminal_failure = true;
                updated.retry_at = None;
                tracing::error!(
                    stream = %batch.key.name,
                    attempts = updated.delivery_attempts,
                    retained_records = updated.retained.len(),
                    "Firehose delivery exhausted; records retained in the local queue"
                );
            } else {
                let seconds = 1_u64 << (updated.delivery_attempts - 1);
                updated.retry_at =
                    Some(Instant::now() + Duration::from_secs(seconds).min(MAX_RETRY_DELAY));
            }
        }
        if let Err(error) = self.persist_complete(
            &batch.key,
            &updated,
            batch.token,
            batch.records.len(),
            delivered,
        ) {
            // SQLite still owns the in-flight rows. Keep the bytes and token in memory too;
            // persist_take reconciles the rows once SQLite becomes available again.
            stream.in_flight = None;
            stream.retry_token = Some(batch.token);
            stream.retained.extend(batch.records);
            stream.retry_at = Some(Instant::now() + SOURCE_POLL_INTERVAL);
            tracing::error!(stream = %batch.key.name, ?error, "Firehose delivery checkpoint could not be committed");
            self.notify.notify_one();
            return;
        }
        *stream = updated;
    }
}

#[async_trait]
impl NativeHandler for FirehoseHandler {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        Ok(self
            .inner
            .streams
            .lock()
            .map_err(|_| "Firehose inventory unavailable")?
            .keys()
            .filter(|k| k.scope.account_id == account)
            .map(|k| k.scope.region.clone())
            .collect())
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        match self.process(&request).await {
            Ok(success) => Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
                .header("x-amzn-RequestId", &request.request_id)
                .body(Body::from(success.into_value().to_string()))
                .expect("Firehose JSON response is valid"),
            Err(error) => AwsError::from(error)
                .with_request_id(request.request_id)
                .render(AwsProtocol::Json11)
                .into_response(),
        }
    }
}

enum Success {
    Json(Value),
}

impl Success {
    fn into_value(self) -> Value {
        match self {
            Self::Json(value) => value,
        }
    }
}

#[derive(Debug)]
enum FirehoseError {
    Serialization(String),
    InvalidArgument(String),
    UnknownOperation,
    ResourceInUse(String),
    ResourceNotFound(String),
    AccessDenied,
    ServiceUnavailable(String),
    Internal,
}

impl From<FirehoseError> for AwsError {
    fn from(error: FirehoseError) -> Self {
        let (code, message, status) = match error {
            FirehoseError::Serialization(message) => ("SerializationException", message, 400),
            FirehoseError::InvalidArgument(message) => ("InvalidArgumentException", message, 400),
            FirehoseError::UnknownOperation => (
                "UnknownOperationException",
                "The requested Firehose operation is not supported by this milestone".into(),
                400,
            ),
            FirehoseError::ResourceInUse(message) => ("ResourceInUseException", message, 400),
            FirehoseError::ResourceNotFound(message) => ("ResourceNotFoundException", message, 400),
            FirehoseError::AccessDenied => ("AccessDeniedException", "Access denied".into(), 403),
            FirehoseError::ServiceUnavailable(message) => {
                ("ServiceUnavailableException", message, 503)
            }
            FirehoseError::Internal => (
                "InternalFailureException",
                "The request could not be completed".into(),
                500,
            ),
        };
        AwsError::new(code, message, status)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct ListDeliveryStreamsRequest {
    limit: Option<i64>,
    delivery_stream_type: Option<String>,
    exclusive_start_delivery_stream_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct CreateDeliveryStreamRequest {
    delivery_stream_name: String,
    delivery_stream_type: Option<String>,
    extended_s3_destination_configuration: Option<ExtendedS3DestinationConfiguration>,
    iceberg_destination_configuration: Option<IcebergDestinationConfiguration>,
    kinesis_stream_source_configuration: Option<KinesisStreamSourceConfiguration>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct KinesisStreamSourceConfiguration {
    #[serde(rename = "KinesisStreamARN")]
    kinesis_stream_arn: String,
    #[serde(rename = "RoleARN")]
    role_arn: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct IcebergDestinationConfiguration {
    catalog_configuration: CatalogConfiguration,
    #[serde(rename = "RoleARN")]
    role_arn: String,
    #[serde(rename = "S3Configuration")]
    s3_configuration: IcebergS3Configuration,
    #[serde(default)]
    append_only: bool,
    destination_table_configuration_list: Vec<DestinationTableConfiguration>,
    #[serde(default)]
    buffering_hints: Option<BufferingHints>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct CatalogConfiguration {
    #[serde(rename = "CatalogARN")]
    catalog_arn: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct IcebergS3Configuration {
    #[serde(rename = "RoleARN")]
    role_arn: String,
    #[serde(rename = "BucketARN")]
    bucket_arn: String,
    #[serde(default)]
    prefix: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct DestinationTableConfiguration {
    destination_database_name: String,
    destination_table_name: String,
    #[serde(default)]
    unique_keys: Vec<String>,
    #[serde(default)]
    s3_error_output_prefix: Option<String>,
    #[serde(default)]
    partition_spec: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct ExtendedS3DestinationConfiguration {
    #[serde(rename = "RoleARN")]
    role_arn: String,
    #[serde(rename = "BucketARN")]
    bucket_arn: String,
    prefix: Option<String>,
    buffering_hints: Option<BufferingHints>,
    compression_format: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct BufferingHints {
    #[serde(rename = "SizeInMBs")]
    size_in_m_bs: Option<i64>,
    interval_in_seconds: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct StreamNameRequest {
    delivery_stream_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct PutRecordRequest {
    delivery_stream_name: String,
    record: RecordInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct PutRecordBatchRequest {
    delivery_stream_name: String,
    records: Vec<RecordInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct RecordInput {
    data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct DeleteDeliveryStreamRequest {
    delivery_stream_name: String,
    allow_force_delete: Option<bool>,
}

impl DestinationConfig {
    fn extended_s3(
        config: ExtendedS3DestinationConfiguration,
        scope: &Scope,
    ) -> Result<Self, FirehoseError> {
        let hints = config.buffering_hints.as_ref();
        let size = hints.and_then(|hints| hints.size_in_m_bs);
        let interval = hints.and_then(|hints| hints.interval_in_seconds);
        if size.is_some() != interval.is_some() {
            return Err(FirehoseError::InvalidArgument(
                "BufferingHints requires both SizeInMBs and IntervalInSeconds".into(),
            ));
        }
        if size.unwrap_or(5) != 1 || interval.unwrap_or(300) != 60 {
            return Err(unsupported(
                "BufferingHints defaults to AWS SizeInMBs=5 and IntervalInSeconds=300; locally only explicit SizeInMBs=1 and IntervalInSeconds=60 is supported",
            ));
        }
        if config
            .compression_format
            .as_deref()
            .unwrap_or("UNCOMPRESSED")
            != "UNCOMPRESSED"
        {
            return Err(unsupported("CompressionFormat must be UNCOMPRESSED"));
        }
        let prefix = config.prefix.unwrap_or_default();
        if prefix.is_empty() {
            return Err(unsupported("The automatic AWS UTC time Prefix is not supported; provide an explicit nonempty Prefix"));
        }
        let bucket = validate_bucket_arn(&config.bucket_arn)?;
        validate_role_arn(&config.role_arn, &scope.account_id)?;
        if prefix.len() > 512 {
            return Err(FirehoseError::InvalidArgument(
                "Prefix must contain 1-512 bytes".into(),
            ));
        }
        Ok(Self {
            s3_role_arn: config.role_arn.clone(),
            role_arn: config.role_arn,
            bucket_arn: config.bucket_arn,
            bucket,
            prefix,
            iceberg: None,
        })
    }
}

fn validate_iceberg_configuration(
    config: IcebergDestinationConfiguration,
    scope: &Scope,
) -> Result<DestinationConfig, FirehoseError> {
    if !config.append_only {
        return Err(unsupported("AppendOnly must be true for Iceberg delivery"));
    }
    if let Some(hints) = &config.buffering_hints {
        if hints.size_in_m_bs != Some(1) || hints.interval_in_seconds != Some(60) {
            return Err(unsupported(
                "Iceberg BufferingHints must be SizeInMBs=1 and IntervalInSeconds=60",
            ));
        }
    }
    if config.destination_table_configuration_list.len() != 1 {
        return Err(unsupported(
            "Exactly one DestinationTableConfiguration is required",
        ));
    }
    let table = config
        .destination_table_configuration_list
        .into_iter()
        .next()
        .expect("single table validated");
    validate_iceberg_name(&table.destination_database_name, "DestinationDatabaseName")?;
    validate_iceberg_name(&table.destination_table_name, "DestinationTableName")?;
    if !table.unique_keys.is_empty()
        || table.s3_error_output_prefix.is_some()
        || table.partition_spec.is_some()
    {
        return Err(unsupported(
            "Iceberg update keys, partition spec, and table error output are not supported",
        ));
    }
    let expected_catalog_arn =
        format!("arn:aws:glue:{}:{}:catalog", scope.region, scope.account_id);
    if config.catalog_configuration.catalog_arn != expected_catalog_arn {
        return Err(unsupported(
            "CatalogARN must identify the same-account, same-region Glue catalog",
        ));
    }
    validate_role_arn(&config.role_arn, &scope.account_id)?;
    validate_role_arn(&config.s3_configuration.role_arn, &scope.account_id)?;
    let bucket = validate_bucket_arn(&config.s3_configuration.bucket_arn)?;
    if config.s3_configuration.prefix.len() > 512 {
        return Err(FirehoseError::InvalidArgument(
            "S3Configuration.Prefix exceeds 512 bytes".into(),
        ));
    }
    Ok(DestinationConfig {
        role_arn: config.role_arn,
        s3_role_arn: config.s3_configuration.role_arn,
        bucket_arn: config.s3_configuration.bucket_arn,
        bucket: bucket.clone(),
        prefix: config.s3_configuration.prefix,
        iceberg: Some(iceberg::Target {
            database: table.destination_database_name,
            table: table.destination_table_name,
            bucket,
        }),
    })
}

fn validate_iceberg_name(value: &str, field: &str) -> Result<(), FirehoseError> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
    {
        return Err(FirehoseError::InvalidArgument(format!(
            "{field} must contain 1-255 alphanumeric, period, or underscore characters"
        )));
    }
    Ok(())
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), FirehoseError> {
    let media_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .ok_or_else(|| FirehoseError::InvalidArgument("Content-Type is required".into()))?;
    if media_type.eq_ignore_ascii_case(CONTENT_TYPE) {
        Ok(())
    } else {
        Err(FirehoseError::InvalidArgument(
            "Content-Type must be application/x-amz-json-1.1".into(),
        ))
    }
}

fn operation(headers: &HeaderMap) -> Result<&str, FirehoseError> {
    headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .and_then(|target| target.strip_prefix(TARGET_PREFIX))
        .and_then(|suffix| suffix.strip_prefix('.'))
        .filter(|operation| !operation.is_empty() && !operation.contains('.'))
        .ok_or(FirehoseError::UnknownOperation)
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, FirehoseError> {
    serde_json::from_slice(body)
        .map_err(|_| FirehoseError::Serialization("The request could not be deserialized".into()))
}

fn validate_stream_name(name: &str) -> Result<(), FirehoseError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(FirehoseError::InvalidArgument(
            "DeliveryStreamName must contain 1-64 alphanumeric, underscore, hyphen, or period characters"
                .into(),
        ));
    }
    Ok(())
}

fn validate_bucket_arn(arn: &str) -> Result<String, FirehoseError> {
    let bucket = arn
        .strip_prefix("arn:aws:s3:::")
        .filter(|bucket| !bucket.is_empty() && !bucket.contains('/'))
        .ok_or_else(|| FirehoseError::InvalidArgument("BucketARN is invalid".into()))?;
    Ok(bucket.to_owned())
}

fn validate_role_arn(arn: &str, account_id: &str) -> Result<(), FirehoseError> {
    let prefix = format!("arn:aws:iam::{account_id}:role/");
    if arn
        .strip_prefix(&prefix)
        .is_some_and(|role| !role.is_empty())
    {
        Ok(())
    } else {
        Err(FirehoseError::InvalidArgument(
            "RoleARN must reference a role in the request account".into(),
        ))
    }
}

fn now_epoch() -> Result<f64, FirehoseError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .map_err(|_| FirehoseError::Internal)
}

fn buffered_usage(stream: &DeliveryStream) -> (usize, usize) {
    let in_flight_records = stream.in_flight.as_ref().map_or(0, |value| value.records);
    let in_flight_bytes = stream.in_flight.as_ref().map_or(0, |value| value.bytes);
    let records = stream.pending.len() + stream.retained.len() + in_flight_records;
    let bytes = stream.pending.iter().map(Vec::len).sum::<usize>()
        + stream.retained.iter().map(Vec::len).sum::<usize>()
        + in_flight_bytes;
    (records, bytes)
}

fn object_key(prefix: &str, stream_name: &str, token: Uuid) -> String {
    format!("{prefix}{stream_name}/{token}")
}

fn percent_encode(value: &str, preserve_slash: bool) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (preserve_slash && byte == b'/')
        {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn stream_not_found(scope: &Scope) -> FirehoseError {
    FirehoseError::ResourceNotFound(format!(
        "Firehose not found under account {}.",
        scope.account_id
    ))
}

fn delivery_exhausted(stream: &DeliveryStream) -> FirehoseError {
    FirehoseError::ServiceUnavailable(format!(
        "Delivery failed after {} attempts; {} records remain in memory and this stream no longer accepts records",
        stream.delivery_attempts,
        stream.retained.len() + stream.pending.len()
    ))
}

fn unsupported(message: &str) -> FirehoseError {
    FirehoseError::InvalidArgument(format!(
        "{message}; unsupported local Firehose configuration"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation: &str, body: Value) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static(CONTENT_TYPE),
        );
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("{TARGET_PREFIX}.{operation}")).unwrap(),
        );
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(body.to_string()),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "request-1".into(),
        }
    }

    fn iceberg_configuration(table_name: &str) -> Value {
        json!({
            "DeliveryStreamName": "lake-events",
            "DeliveryStreamType": "DirectPut",
            "IcebergDestinationConfiguration": {
                "CatalogConfiguration": {
                    "CatalogARN": "arn:aws:glue:us-east-1:000000000000:catalog"
                },
                "RoleARN": "arn:aws:iam::000000000000:role/firehose",
                "S3Configuration": {
                    "BucketARN": "arn:aws:s3:::lake-errors",
                    "RoleARN": "arn:aws:iam::000000000000:role/firehose"
                },
                "AppendOnly": true,
                "DestinationTableConfigurationList": [{
                    "DestinationDatabaseName": "lake",
                    "DestinationTableName": table_name
                }]
            }
        })
    }

    #[tokio::test]
    async fn restart_replays_inflight_batch_and_commits_checkpoint() {
        let root = std::env::temp_dir().join(format!(
            "locallycloud-firehose-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let scope = Scope {
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let key = StreamKey::new(&scope, "events");
        let (handler, handle) = FirehoseHandler::with_state(Weak::new(), state.clone()).unwrap();
        let stream = DeliveryStream {
            source: Some(KinesisSource {
                arn: "arn:aws:kinesis:us-east-1:000000000000:stream/source".into(),
                name: "source".into(),
                role_arn: String::new(),
                checkpoint: Some("12".into()),
                fetched: Some("13".into()),
                checkpoints: BTreeMap::new(),
                fetched_shards: BTreeMap::new(),
                next_shard: 0,
                ready: true,
                failure: None,
                creation_timestamp: Some(1.0),
                stopped: false,
            }),
            generation: Uuid::new_v4(),
            created_at: 1.0,
            destination: DestinationConfig {
                role_arn: String::new(),
                s3_role_arn: String::new(),
                bucket_arn: String::new(),
                bucket: "output".into(),
                prefix: "events/".into(),
                iceberg: None,
            },
            role_caller: None,
            pending: VecDeque::new(),
            retained: VecDeque::new(),
            retry_token: None,
            in_flight: None,
            delivery_attempts: 0,
            retry_at: None,
            terminal_failure: false,
        };
        handler.inner.persist_create(&key, &stream).unwrap();
        handler
            .inner
            .persist_append(&key, &stream, &[b"record".to_vec()])
            .unwrap();
        handler
            .inner
            .lock_streams()
            .unwrap()
            .insert(key.clone(), stream);
        handler
            .inner
            .lock_streams()
            .unwrap()
            .get_mut(&key)
            .unwrap()
            .pending
            .push_back(b"record".to_vec());
        let first = handler.inner.take_batches().pop().unwrap();
        assert_eq!(first.records, [b"record".to_vec()]);
        let token = first.token;
        {
            let mut streams = handler.inner.lock_streams().unwrap();
            let stream = streams.get_mut(&key).unwrap();
            stream.in_flight = None;
            stream.retry_token = Some(token);
            stream.retained.extend(first.records.iter().cloned());
        }
        let reclaimed = handler.inner.take_batches().pop().unwrap();
        assert_eq!(reclaimed.token, token);
        assert_eq!(reclaimed.records, first.records);
        drop(reclaimed);
        drop(first);
        drop(handler);
        drop(handle);

        let (handler, handle) = FirehoseHandler::with_state(Weak::new(), state.clone()).unwrap();
        let replay = handler.inner.take_batches().pop().unwrap();
        assert_eq!(replay.token, token);
        assert_eq!(replay.records, [b"record".to_vec()]);
        assert_eq!(
            object_key("events/", "events", replay.token),
            object_key("events/", "events", token)
        );
        handler.inner.complete_batch(replay, true);
        drop(handler);
        drop(handle);

        let (handler, handle) = FirehoseHandler::with_state(Weak::new(), state).unwrap();
        let streams = handler.inner.lock_streams().unwrap();
        let restored = streams.get(&key).unwrap();
        assert!(restored.pending.is_empty() && restored.retained.is_empty());
        assert_eq!(
            restored
                .source
                .as_ref()
                .unwrap()
                .checkpoints
                .get("shardId-000000000000")
                .map(String::as_str),
            Some("13")
        );
        drop(streams);
        drop(handler);
        drop(handle);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn iceberg_rejects_before_create_when_dependencies_unavailable() {
        let (handler, _) = FirehoseHandler::new(Weak::new());
        let result = handler
            .process(&request(
                "CreateDeliveryStream",
                iceberg_configuration("events"),
            ))
            .await;
        assert!(
            matches!(result, Err(FirehoseError::InvalidArgument(message)) if message.contains("unavailable"))
        );
        assert!(handler.inner.lock_streams().unwrap().is_empty());
    }

    #[tokio::test]
    async fn iceberg_rejects_bad_table_name_before_activation() {
        let (handler, _) = FirehoseHandler::new(Weak::new());
        let result = handler
            .process(&request(
                "CreateDeliveryStream",
                iceberg_configuration("events;DROP"),
            ))
            .await;
        assert!(matches!(
            result,
            Err(FirehoseError::InvalidArgument(message))
                if message.contains("DestinationTableName")
        ));
        assert!(handler.inner.lock_streams().unwrap().is_empty());
    }

    #[tokio::test]
    async fn iceberg_public_handler_rejects_without_dependencies() {
        let (handler, _) = FirehoseHandler::new(Weak::new());
        let response = handler
            .handle(request(
                "CreateDeliveryStream",
                iceberg_configuration("events"),
            ))
            .await;
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert!(body["__type"]
            .as_str()
            .unwrap()
            .contains("InvalidArgumentException"));
        assert!(handler.inner.lock_streams().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_batch_retries_before_new_records_and_exhaustion_is_visible() {
        let (handler, _) = FirehoseHandler::new(Weak::new());
        let scope = Scope {
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let key = StreamKey::new(&scope, "events");
        handler.inner.lock_streams().unwrap().insert(
            key.clone(),
            DeliveryStream {
                source: None,
                generation: Uuid::new_v4(),
                created_at: 0.0,
                role_caller: None,
                destination: DestinationConfig {
                    role_arn: String::new(),
                    s3_role_arn: String::new(),
                    bucket_arn: String::new(),
                    bucket: "events".into(),
                    prefix: String::new(),
                    iceberg: None,
                },
                pending: VecDeque::from([b"first".to_vec()]),
                retained: VecDeque::new(),
                retry_token: None,
                in_flight: None,
                delivery_attempts: 0,
                retry_at: None,
                terminal_failure: false,
            },
        );
        let first = handler.inner.take_batches().pop().unwrap();
        handler.inner.complete_batch(first, false);
        {
            let mut streams = handler.inner.lock_streams().unwrap();
            let stream = streams.get_mut(&key).unwrap();
            stream.pending.push_back(b"second".to_vec());
        }
        assert!(handler.inner.take_batches().is_empty());
        for attempt in 1..MAX_DELIVERY_ATTEMPTS {
            {
                let mut streams = handler.inner.lock_streams().unwrap();
                streams.get_mut(&key).unwrap().retry_at = Some(Instant::now());
            }
            let retry = handler.inner.take_batches().pop().unwrap();
            assert_eq!(retry.records, [b"first".to_vec()]);
            handler.inner.complete_batch(retry, false);
            if attempt + 1 == MAX_DELIVERY_ATTEMPTS {
                break;
            }
        }
        assert!(handler.inner.take_batches().is_empty());
        let description = handler
            .process(&request(
                "DescribeDeliveryStream",
                json!({"DeliveryStreamName":"events"}),
            ))
            .await
            .unwrap()
            .into_value();
        let failure = &description["DeliveryStreamDescription"]["LocallyCloudDeliveryFailure"];
        assert_eq!(failure["State"], "RETRY_EXHAUSTED");
        assert_eq!(failure["Attempts"], MAX_DELIVERY_ATTEMPTS);
        assert_eq!(failure["RetainedRecordCount"], 1);
        assert_eq!(failure["PendingRecordCount"], 1);
        assert_eq!(failure["Durable"], false);
        assert!(matches!(
            handler
                .process(&request(
                    "PutRecord",
                    json!({"DeliveryStreamName":"events","Record":{"Data":"eA=="}}),
                ))
                .await,
            Err(FirehoseError::ServiceUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn terminal_stream_requires_force_delete_and_returns_standard_shape() {
        let (handler, _) = FirehoseHandler::new(Weak::new());
        let scope = Scope {
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let key = StreamKey::new(&scope, "events");
        handler.inner.lock_streams().unwrap().insert(
            key.clone(),
            DeliveryStream {
                source: None,
                generation: Uuid::new_v4(),
                created_at: 0.0,
                role_caller: None,
                destination: DestinationConfig {
                    role_arn: String::new(),
                    s3_role_arn: String::new(),
                    bucket_arn: String::new(),
                    bucket: "events".into(),
                    prefix: String::new(),
                    iceberg: None,
                },
                pending: VecDeque::from([b"later".to_vec()]),
                retained: VecDeque::from([b"failed".to_vec()]),
                retry_token: None,
                in_flight: None,
                delivery_attempts: MAX_DELIVERY_ATTEMPTS,
                retry_at: None,
                terminal_failure: true,
            },
        );
        assert!(matches!(
            handler
                .process(&request(
                    "DeleteDeliveryStream",
                    json!({"DeliveryStreamName":"events"}),
                ))
                .await,
            Err(FirehoseError::ResourceInUse(_))
        ));
        assert!(handler.inner.lock_streams().unwrap().contains_key(&key));
        let deleted = handler
            .process(&request(
                "DeleteDeliveryStream",
                json!({"DeliveryStreamName":"events","AllowForceDelete":true}),
            ))
            .await
            .unwrap()
            .into_value();
        assert_eq!(deleted, json!({}));
        assert!(!handler.inner.lock_streams().unwrap().contains_key(&key));
    }

    #[test]
    fn successful_retry_unblocks_later_batch_in_order() {
        let (handler, _) = FirehoseHandler::new(Weak::new());
        let scope = Scope {
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let key = StreamKey::new(&scope, "events");
        handler.inner.lock_streams().unwrap().insert(
            key.clone(),
            DeliveryStream {
                source: None,
                generation: Uuid::new_v4(),
                created_at: 0.0,
                role_caller: None,
                destination: DestinationConfig {
                    role_arn: String::new(),
                    s3_role_arn: String::new(),
                    bucket_arn: String::new(),
                    bucket: "events".into(),
                    prefix: String::new(),
                    iceberg: None,
                },
                pending: VecDeque::from([b"first".to_vec()]),
                retained: VecDeque::new(),
                retry_token: None,
                in_flight: None,
                delivery_attempts: 0,
                retry_at: None,
                terminal_failure: false,
            },
        );
        let first = handler.inner.take_batches().pop().unwrap();
        handler.inner.complete_batch(first, false);
        {
            let mut streams = handler.inner.lock_streams().unwrap();
            let stream = streams.get_mut(&key).unwrap();
            stream.pending.push_back(b"second".to_vec());
            stream.retry_at = Some(Instant::now());
        }
        let retry = handler.inner.take_batches().pop().unwrap();
        assert_eq!(retry.records, [b"first".to_vec()]);
        handler.inner.complete_batch(retry, true);
        let next = handler.inner.take_batches().pop().unwrap();
        assert_eq!(next.records, [b"second".to_vec()]);
    }

    #[tokio::test]
    async fn extended_s3_stream_remains_describable() {
        let (handler, _) = FirehoseHandler::new(Weak::new());
        let create = json!({
            "DeliveryStreamName": "s3-events",
            "DeliveryStreamType": "DirectPut",
            "ExtendedS3DestinationConfiguration": {
                "RoleARN": "arn:aws:iam::000000000000:role/firehose",
                "BucketARN": "arn:aws:s3:::events",
                "Prefix": "delivery/",
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                "CompressionFormat": "UNCOMPRESSED"
            }
        });
        let mut create = create;
        create.as_object_mut().unwrap().remove("DeliveryStreamType");
        // AWS optional omissions must not fail deserialization or silently acquire
        // the local fast-buffer settings instead of AWS's 5 MiB / 300 s defaults.
        for hints in [
            None,
            Some(json!({})),
            Some(json!({"SizeInMBs": 5, "IntervalInSeconds": 300})),
        ] {
            let mut omitted = create.clone();
            let destination = omitted["ExtendedS3DestinationConfiguration"]
                .as_object_mut()
                .unwrap();
            destination.remove("CompressionFormat");
            destination.remove("Prefix");
            match hints {
                Some(hints) => {
                    destination.insert("BufferingHints".into(), hints);
                }
                None => {
                    destination.remove("BufferingHints");
                }
            }
            assert!(
                matches!(handler.process(&request("CreateDeliveryStream", omitted)).await,
                Err(FirehoseError::InvalidArgument(message)) if message.contains("defaults to AWS") && message.contains("unsupported"))
            );
        }
        for field in ["SizeInMBs", "IntervalInSeconds"] {
            let mut partial = create.clone();
            partial["ExtendedS3DestinationConfiguration"]["BufferingHints"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                matches!(handler.process(&request("CreateDeliveryStream", partial)).await,
                Err(FirehoseError::InvalidArgument(message)) if message.contains("requires both"))
            );
        }
        for prefix in [None, Some(json!(""))] {
            let mut omitted = create.clone();
            let destination = omitted["ExtendedS3DestinationConfiguration"]
                .as_object_mut()
                .unwrap();
            match prefix {
                Some(prefix) => {
                    destination.insert("Prefix".into(), prefix);
                }
                None => {
                    destination.remove("Prefix");
                }
            }
            assert!(
                matches!(handler.process(&request("CreateDeliveryStream", omitted)).await,
                Err(FirehoseError::InvalidArgument(message)) if message.contains("automatic AWS UTC time Prefix"))
            );
        }
        assert_eq!(
            handler
                .process(&request("ListDeliveryStreams", json!({})))
                .await
                .unwrap()
                .into_value(),
            json!({"DeliveryStreamNames": [], "HasMoreDeliveryStreams": false})
        );
        assert!(handler.inner.lock_streams().unwrap().is_empty());
        create["ExtendedS3DestinationConfiguration"]
            .as_object_mut()
            .unwrap()
            .remove("CompressionFormat");
        assert!(handler
            .process(&request("CreateDeliveryStream", create))
            .await
            .is_ok());
        let description = handler
            .process(&request(
                "DescribeDeliveryStream",
                json!({"DeliveryStreamName": "s3-events"}),
            ))
            .await
            .unwrap_or_else(|_| panic!("S3 stream should be present"))
            .into_value();
        assert_eq!(
            description["DeliveryStreamDescription"]["Destinations"][0]
                ["ExtendedS3DestinationDescription"]["BucketARN"],
            "arn:aws:s3:::events"
        );
        assert!(description["DeliveryStreamDescription"]["Destinations"][0]
            .get("IcebergDestinationDescription")
            .is_none());
        for (name, account, region) in [
            ("z-events", "000000000000", "us-east-1"),
            ("a-events", "000000000000", "us-east-1"),
            ("other-account", "111111111111", "us-east-1"),
            ("other-region", "000000000000", "eu-west-1"),
        ] {
            let mut create = request(
                "CreateDeliveryStream",
                json!({"DeliveryStreamName":name,"ExtendedS3DestinationConfiguration":{
                "RoleARN":format!("arn:aws:iam::{account}:role/firehose"),"BucketARN":"arn:aws:s3:::events","Prefix":"delivery/","BufferingHints":{"SizeInMBs":1,"IntervalInSeconds":60}}}),
            );
            create.account_id = account.into();
            create.region = region.into();
            handler.process(&create).await.unwrap();
        }
        assert_eq!(
            handler
                .process(&request("ListDeliveryStreams", json!({"Limit":2})))
                .await
                .unwrap()
                .into_value(),
            json!({"DeliveryStreamNames":["a-events","s3-events"],"HasMoreDeliveryStreams":true})
        );
        assert_eq!(handler.process(&request("ListDeliveryStreams", json!({"Limit":2,"ExclusiveStartDeliveryStreamName":"s3-events","DeliveryStreamType":"DirectPut"}))).await.unwrap().into_value(),
            json!({"DeliveryStreamNames":["z-events"],"HasMoreDeliveryStreams":false}));
        assert_eq!(
            handler
                .process(&request(
                    "ListDeliveryStreams",
                    json!({"DeliveryStreamType":"KinesisStreamAsSource"})
                ))
                .await
                .unwrap()
                .into_value(),
            json!({"DeliveryStreamNames":[],"HasMoreDeliveryStreams":false})
        );
        for body in [
            json!({"Limit":0}),
            json!({"Limit":10001}),
            json!({"Limit":-1}),
            json!({"ExclusiveStartDeliveryStreamName":"bad name"}),
            json!({"DeliveryStreamType":"wrong"}),
        ] {
            assert!(matches!(
                handler.process(&request("ListDeliveryStreams", body)).await,
                Err(FirehoseError::InvalidArgument(_))
            ));
        }
    }
}
