//! Scoped, in-memory X-Ray trace ingestion and retrieval.
//!
//! PutTraceSegments, PutTelemetryRecords, BatchGetTraces and a bounded
//! GetTraceSummaries subset are native. BatchGetTraces returns one document per segment, with
//! independently sent subsegments merged into their parents. Other X-Ray operations
//! fail explicitly until their contracts and state are implemented.
//! Daemon (UDP) documents from Lambda `Active` environments arrive as
//! scoped internal `PutTraceSegments` calls. Traces are kept for X-Ray's 30-day retention;
//! a scope at its segment cap evicts the traces stored first.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use http::Method;
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use serde_json::{json, Value};

const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
const MAX_BATCH_DOCUMENTS: usize = 50;
const MAX_REQUEST_BYTES: usize = MAX_BATCH_DOCUMENTS * (MAX_DOCUMENT_BYTES + 64);
const MAX_SCOPE_SEGMENTS: usize = 10_000;
const MAX_TRACE_SEGMENTS: usize = 500;
const MAX_TELEMETRY_BUCKETS_PER_SCOPE: usize = 1440;
const MAX_SUMMARY_RESULTS: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Scope {
    account_id: String,
    region: String,
}

#[derive(Debug, Clone)]
struct Segment {
    /// Shared so reads can copy a trace out of the store lock cheaply.
    document: Arc<str>,
    start: f64,
    end: Option<f64>,
    in_progress: bool,
    name: String,
    is_root: bool,
    /// `"type": "subsegment"`: an independent subsegment, not a segment of its own.
    is_subsegment: bool,
    /// `parent_id` of an independent subsegment.
    parent_id: Option<String>,
    has_error: bool,
    has_fault: bool,
    has_throttle: bool,
}

#[derive(Default, Clone)]
struct TelemetryAggregate {
    records: u64,
    received: u64,
    rejected: u64,
    sent: u64,
    spillover: u64,
}

type Trace = BTreeMap<String, Segment>;

/// X-Ray keeps trace data for 30 days (not adjustable).
const RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

struct StoredTrace {
    segments: Trace,
    /// Position in [`TraceStore::order`].
    sequence: u64,
    /// When the first segment of the trace was stored (Unix seconds).
    received: u64,
}

/// The traces of one scope. Traces are ordered by when their first segment was stored, not by
/// client-supplied times, so retention and eviction cannot be steered by document contents.
#[derive(Default)]
struct TraceStore {
    traces: BTreeMap<String, StoredTrace>,
    /// Insertion sequence → trace id, oldest first.
    order: BTreeMap<u64, String>,
    next_sequence: u64,
    segment_count: usize,
}

impl TraceStore {
    /// The trace's segments, if it is still retained at `now`.
    fn get(&self, trace_id: &str, now: u64) -> Option<&Trace> {
        self.traces
            .get(trace_id)
            .filter(|trace| now < trace.received.saturating_add(RETENTION_SECONDS))
            .map(|trace| &trace.segments)
    }

    fn retained(&self, now: u64) -> impl Iterator<Item = (&String, &Trace)> {
        self.traces
            .iter()
            .filter(move |(_, trace)| now < trace.received.saturating_add(RETENTION_SECONDS))
            .map(|(id, trace)| (id, &trace.segments))
    }

    fn remove(&mut self, trace_id: &str) {
        if let Some(trace) = self.traces.remove(trace_id) {
            self.order.remove(&trace.sequence);
            self.segment_count -= trace.segments.len();
        }
    }

    /// Drop traces whose first segment is older than the retention period.
    fn expire(&mut self, now: u64) {
        while let Some((_, oldest)) = self.order.first_key_value() {
            let expired = self
                .traces
                .get(oldest)
                .is_none_or(|trace| now >= trace.received.saturating_add(RETENTION_SECONDS));
            if !expired {
                break;
            }
            let oldest = oldest.clone();
            self.remove(&oldest);
        }
    }

    /// Evict the oldest traces other than `keep` until one more segment fits in the scope.
    fn make_room(&mut self, keep: &str) {
        while self.segment_count >= MAX_SCOPE_SEGMENTS {
            let Some(oldest) = self.order.values().find(|id| id.as_str() != keep).cloned() else {
                return;
            };
            self.remove(&oldest);
        }
    }

    fn insert(&mut self, trace_id: String, id: String, segment: Segment, now: u64) {
        if !self.traces.contains_key(&trace_id) {
            let sequence = self.next_sequence;
            self.next_sequence += 1;
            self.order.insert(sequence, trace_id.clone());
            self.traces.insert(
                trace_id.clone(),
                StoredTrace {
                    segments: Trace::new(),
                    sequence,
                    received: now,
                },
            );
        }
        if let Some(trace) = self.traces.get_mut(&trace_id) {
            if trace.segments.insert(id, segment).is_none() {
                self.segment_count += 1;
            }
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[derive(Default)]
pub struct XrayHandler {
    scopes: Mutex<BTreeMap<Scope, TraceStore>>,
    telemetry: Mutex<BTreeMap<Scope, BTreeMap<i64, TelemetryAggregate>>>,
}

impl XrayHandler {
    pub fn new() -> Self {
        Self::default()
    }

    fn process(&self, request: &ServiceRequest) -> Result<Value, ApiError> {
        if request.method != Method::POST {
            return Err(ApiError::UnknownOperation);
        }
        match request.uri.path() {
            "/TraceSegments" => self.put_trace_segments(request),
            "/Traces" => self.batch_get_traces(request),
            "/TelemetryRecords" => self.put_telemetry_records(request),
            "/TraceSummaries" => self.get_trace_summaries(request),
            _ => Err(ApiError::UnknownOperation),
        }
    }

    fn put_trace_segments(&self, request: &ServiceRequest) -> Result<Value, ApiError> {
        let body = request_json(request)?;
        let documents = body
            .get("TraceSegmentDocuments")
            .and_then(Value::as_array)
            .ok_or(ApiError::InvalidRequest)?;
        if documents.is_empty() || documents.len() > MAX_BATCH_DOCUMENTS {
            return Err(ApiError::InvalidRequest);
        }
        let documents = documents
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .ok_or(ApiError::InvalidRequest)?;
        let rejected = self.ingest_documents(&request.account_id, &request.region, &documents)?;
        Ok(json!({"UnprocessedTraceSegments": rejected}))
    }

    /// Store segment documents in one account and Region scope, returning the
    /// `UnprocessedTraceSegments` entries. Shared by `PutTraceSegments` callers and the
    /// per-environment Lambda daemon endpoints, which reach it through internal dispatch.
    fn ingest_documents(
        &self,
        account_id: &str,
        region: &str,
        documents: &[&str],
    ) -> Result<Vec<Value>, ApiError> {
        self.ingest_documents_at(account_id, region, documents, unix_now())
    }

    /// [`ingest_documents`](Self::ingest_documents) at `now` (Unix seconds). Expired traces
    /// are dropped first; a full scope evicts its oldest traces, while a full trace rejects.
    fn ingest_documents_at(
        &self,
        account_id: &str,
        region: &str,
        documents: &[&str],
        now: u64,
    ) -> Result<Vec<Value>, ApiError> {
        let scope = Scope {
            account_id: account_id.to_owned(),
            region: region.to_owned(),
        };
        let mut scopes = self.scopes.lock().map_err(|_| ApiError::InternalFailure)?;
        let traces = scopes.entry(scope).or_default();
        traces.expire(now);
        let mut rejected = Vec::new();
        for &raw in documents {
            let segment = match parse_segment(raw) {
                Ok(segment) => segment,
                Err(failure) => {
                    rejected.push(failure);
                    continue;
                }
            };
            let trace_id = segment.trace_id;
            let id = segment.id;
            let existing = traces.get(&trace_id, now).and_then(|trace| trace.get(&id));
            if let Some(existing) = existing {
                if !existing.in_progress
                    && (segment.value.in_progress || *existing.document != *raw)
                {
                    rejected.push(rejection(
                        Some(&id),
                        "InvalidSegment",
                        "Final segment already exists",
                    ));
                    continue;
                }
                if existing.in_progress && segment.value.start != existing.start {
                    rejected.push(rejection(
                        Some(&id),
                        "InvalidSegment",
                        "Segment start_time changed",
                    ));
                    continue;
                }
            } else {
                let trace_size = traces.get(&trace_id, now).map_or(0, BTreeMap::len);
                if trace_size >= MAX_TRACE_SEGMENTS {
                    rejected.push(rejection(
                        Some(&id),
                        "SegmentRejected",
                        "Trace capacity exceeded",
                    ));
                    continue;
                }
                traces.make_room(&trace_id);
            }
            traces.insert(trace_id, id, segment.value, now);
        }
        Ok(rejected)
    }

    fn put_telemetry_records(&self, request: &ServiceRequest) -> Result<Value, ApiError> {
        let body = request_json(request)?;
        let object = body.as_object().ok_or(ApiError::InvalidRequest)?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "TelemetryRecords" | "EC2InstanceId" | "Hostname" | "ResourceARN"
            )
        }) {
            return Err(ApiError::InvalidRequest);
        }
        for (key, limit) in [
            ("EC2InstanceId", 20),
            ("Hostname", 255),
            ("ResourceARN", 500),
        ] {
            if let Some(value) = object.get(key) {
                if value.as_str().is_none_or(|text| text.len() > limit) {
                    return Err(ApiError::InvalidRequest);
                }
            }
        }
        let records = object
            .get("TelemetryRecords")
            .and_then(Value::as_array)
            .ok_or(ApiError::InvalidRequest)?;
        if records.is_empty() {
            return Err(ApiError::InvalidRequest);
        }
        let mut staged: BTreeMap<i64, TelemetryAggregate> = BTreeMap::new();
        for record in records {
            let record = record.as_object().ok_or(ApiError::InvalidRequest)?;
            if record.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "Timestamp"
                        | "BackendConnectionErrors"
                        | "SegmentsReceivedCount"
                        | "SegmentsRejectedCount"
                        | "SegmentsSentCount"
                        | "SegmentsSpilloverCount"
                )
            }) {
                return Err(ApiError::InvalidRequest);
            }
            let timestamp = record
                .get("Timestamp")
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite() && *value >= 0.0 && *value <= i64::MAX as f64)
                .ok_or(ApiError::InvalidRequest)?;
            let bucket = (timestamp as i64) / 60;
            let aggregate = staged.entry(bucket).or_default();
            aggregate.records = aggregate.records.saturating_add(1);
            aggregate.received = aggregate
                .received
                .saturating_add(telemetry_count(record, "SegmentsReceivedCount")?);
            aggregate.rejected = aggregate
                .rejected
                .saturating_add(telemetry_count(record, "SegmentsRejectedCount")?);
            aggregate.sent = aggregate
                .sent
                .saturating_add(telemetry_count(record, "SegmentsSentCount")?);
            aggregate.spillover = aggregate
                .spillover
                .saturating_add(telemetry_count(record, "SegmentsSpilloverCount")?);
            if let Some(errors) = record.get("BackendConnectionErrors") {
                let errors = errors.as_object().ok_or(ApiError::InvalidRequest)?;
                if errors.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "ConnectionRefusedCount"
                            | "HTTPCode4XXCount"
                            | "HTTPCode5XXCount"
                            | "OtherCount"
                            | "TimeoutCount"
                            | "UnknownHostCount"
                    )
                }) {
                    return Err(ApiError::InvalidRequest);
                }
                for key in errors.keys() {
                    telemetry_count(errors, key)?;
                }
            }
        }
        let scope = Scope {
            account_id: request.account_id.clone(),
            region: request.region.clone(),
        };
        let mut all = self
            .telemetry
            .lock()
            .map_err(|_| ApiError::InternalFailure)?;
        let buckets = all.entry(scope).or_default();
        for (minute, value) in staged {
            let aggregate = buckets.entry(minute).or_default();
            aggregate.records = aggregate.records.saturating_add(value.records);
            aggregate.received = aggregate.received.saturating_add(value.received);
            aggregate.rejected = aggregate.rejected.saturating_add(value.rejected);
            aggregate.sent = aggregate.sent.saturating_add(value.sent);
            aggregate.spillover = aggregate.spillover.saturating_add(value.spillover);
        }
        while buckets.len() > MAX_TELEMETRY_BUCKETS_PER_SCOPE {
            buckets.pop_first();
        }
        Ok(json!({}))
    }

    fn get_trace_summaries(&self, request: &ServiceRequest) -> Result<Value, ApiError> {
        let body = request_json(request)?;
        let object = body.as_object().ok_or(ApiError::InvalidRequest)?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "StartTime"
                    | "EndTime"
                    | "FilterExpression"
                    | "TimeRangeType"
                    | "NextToken"
                    | "Sampling"
                    | "SamplingStrategy"
            )
        }) {
            return Err(ApiError::InvalidRequest);
        }
        if object.contains_key("NextToken")
            || object.contains_key("SamplingStrategy")
            || object.get("Sampling") == Some(&Value::Bool(true))
            || object
                .get("TimeRangeType")
                .is_some_and(|v| v.as_str() != Some("TraceId"))
        {
            return Err(ApiError::InvalidRequest);
        }
        if object.get("Sampling").is_some_and(|v| !v.is_boolean()) {
            return Err(ApiError::InvalidRequest);
        }
        let start = object
            .get("StartTime")
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite() && *v >= 0.0)
            .ok_or(ApiError::InvalidRequest)?;
        let end = object
            .get("EndTime")
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite() && *v > start)
            .ok_or(ApiError::InvalidRequest)?;
        let service_filter = match object.get("FilterExpression") {
            None => None,
            Some(Value::String(filter)) => Some(parse_service_filter(filter)?),
            _ => return Err(ApiError::InvalidRequest),
        };
        let scope = Scope {
            account_id: request.account_id.clone(),
            region: request.region.clone(),
        };
        let all = self.scopes.lock().map_err(|_| ApiError::InternalFailure)?;
        let mut matches = Vec::new();
        let mut processed = 0u64;
        if let Some(traces) = all.get(&scope) {
            for (id, segments) in traces.retained(unix_now()) {
                let trace_time = trace_id_time(id).ok_or(ApiError::InternalFailure)? as f64;
                if trace_time < start || trace_time >= end {
                    continue;
                }
                processed = processed.saturating_add(1);
                if service_filter.as_ref().is_some_and(|name| {
                    !segments
                        .values()
                        .any(|s| !s.is_subsegment && &s.name == name)
                }) {
                    continue;
                }
                let first = segments
                    .values()
                    .map(|s| s.start)
                    .fold(f64::INFINITY, f64::min);
                let last = segments
                    .values()
                    .filter_map(|s| s.end)
                    .fold(f64::NEG_INFINITY, f64::max);
                let root = segments.values().find(|s| s.is_root);
                let service_names: BTreeSet<&str> = segments
                    .values()
                    .filter(|s| !s.is_subsegment)
                    .map(|s| s.name.as_str())
                    .collect();
                let mut summary = json!({
                    "Id": id, "StartTime": first,
                    "IsPartial": segments.values().any(|s| s.in_progress),
                    "HasError": root.is_some_and(|s| s.has_error),
                    "HasFault": root.is_some_and(|s| s.has_fault),
                    "HasThrottle": segments.values().any(|s| s.has_throttle),
                    "ServiceIds": service_names.into_iter().map(|name| json!({"Name": name, "AccountId": scope.account_id})).collect::<Vec<_>>()
                });
                if last.is_finite() {
                    summary["Duration"] = json!((last - first).max(0.0));
                }
                if let Some(root) = root {
                    summary["EntryPoint"] =
                        json!({"Name": root.name, "AccountId": scope.account_id});
                    if let Some(done) = root.end {
                        summary["ResponseTime"] = json!((done - root.start).max(0.0));
                    }
                }
                matches.push((trace_time as u64, id.clone(), summary));
            }
        }
        if matches.len() > MAX_SUMMARY_RESULTS {
            return Err(ApiError::InvalidRequest);
        }
        matches.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        Ok(json!({
            "TracesProcessedCount": processed,
            "TraceSummaries": matches.into_iter().map(|(_, _, summary)| summary).collect::<Vec<_>>()
        }))
    }

    fn batch_get_traces(&self, request: &ServiceRequest) -> Result<Value, ApiError> {
        let body = request_json(request)?;
        if body.get("NextToken").is_some() {
            return Err(ApiError::InvalidRequest);
        }
        let ids = body
            .get("TraceIds")
            .and_then(Value::as_array)
            .ok_or(ApiError::InvalidRequest)?;
        if ids.is_empty() || ids.len() > 5 || ids.iter().any(|id| !id.is_string()) {
            return Err(ApiError::InvalidRequest);
        }
        for id in ids {
            let id = id.as_str().expect("preflight checked string");
            if !valid_trace_id(id) {
                return Err(ApiError::InvalidRequest);
            }
        }
        let scope = Scope {
            account_id: request.account_id.clone(),
            region: request.region.clone(),
        };
        // Copy the requested traces (documents are shared) and parse them after the store lock
        // is released, so assembly does not block ingestion.
        let mut selected = Vec::new();
        {
            let scopes = self.scopes.lock().map_err(|_| ApiError::InternalFailure)?;
            let mut seen = BTreeSet::new();
            if let Some(traces) = scopes.get(&scope) {
                let now = unix_now();
                for id in ids {
                    let id = id.as_str().expect("preflight checked string");
                    if !seen.insert(id) {
                        continue;
                    }
                    if let Some(segments) = traces.get(id, now) {
                        selected.push((id, segments.clone()));
                    }
                }
            }
        }
        let mut found = Vec::new();
        for (id, segments) in selected {
            let minimum = segments
                .values()
                .map(|segment| segment.start)
                .fold(f64::INFINITY, f64::min);
            let maximum = segments
                .values()
                .filter_map(|segment| segment.end)
                .fold(f64::NEG_INFINITY, f64::max);
            let mut trace = json!({
                "Id": id,
                "Segments": assemble_trace(&segments)
            });
            if maximum.is_finite() {
                trace["Duration"] = json!((maximum - minimum).max(0.0));
            }
            found.push(trace);
        }
        Ok(json!({"Traces": found, "UnprocessedTraceIds": []}))
    }
}

#[async_trait]
impl NativeHandler for XrayHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        match self.process(&request) {
            Ok(value) => Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/json")
                .header("x-amzn-RequestId", &request.request_id)
                .body(if request.uri.path() == "/TelemetryRecords" {
                    Body::empty()
                } else {
                    Body::from(value.to_string())
                })
                .expect("valid X-Ray response"),
            Err(error) => AwsError::new(error.code(), error.message(), error.status())
                .with_request_id(&request.request_id)
                .render(AwsProtocol::RestJson)
                .into_response(),
        }
    }
}

pub fn register(registry: &Arc<ServiceRegistry>) {
    registry.register_native(
        ServiceName::new("xray"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        Arc::new(XrayHandler::new()),
    );
}

#[derive(Debug)]
enum ApiError {
    InvalidRequest,
    RequestTooLarge,
    UnknownOperation,
    InternalFailure,
}

impl ApiError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "InvalidRequestException",
            Self::RequestTooLarge => "RequestEntityTooLargeException",
            Self::UnknownOperation => "UnknownOperationException",
            Self::InternalFailure => "InternalFailure",
        }
    }

    fn message(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "Invalid X-Ray request",
            Self::RequestTooLarge => "X-Ray request is too large",
            Self::UnknownOperation => "X-Ray operation is not implemented",
            Self::InternalFailure => "X-Ray store is unavailable",
        }
    }

    fn status(&self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::RequestTooLarge => 413,
            Self::UnknownOperation => 404,
            Self::InternalFailure => 500,
        }
    }
}

fn request_json(request: &ServiceRequest) -> Result<Value, ApiError> {
    if request.body.len() > MAX_REQUEST_BYTES {
        return Err(ApiError::RequestTooLarge);
    }
    let value: Value =
        serde_json::from_slice(&request.body).map_err(|_| ApiError::InvalidRequest)?;
    if !value.is_object() {
        return Err(ApiError::InvalidRequest);
    }
    Ok(value)
}

struct ParsedSegment {
    trace_id: String,
    id: String,
    value: Segment,
}

fn parse_segment(raw: &str) -> Result<ParsedSegment, Value> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|_| rejection(None, "InvalidSegment", "Segment is not valid JSON"))?;
    let id = value.get("id").and_then(Value::as_str);
    let id = id.filter(|id| valid_segment_id(id)).ok_or_else(|| {
        rejection(
            id,
            "InvalidSegment",
            "Segment id must be 16 hexadecimal digits",
        )
    })?;
    let trace_id = value.get("trace_id").and_then(Value::as_str);
    let trace_id = trace_id
        .filter(|id| valid_trace_id(id))
        .ok_or_else(|| rejection(Some(id), "InvalidTraceId", "Invalid trace_id"))?;
    let name = value.get("name").and_then(Value::as_str);
    if !name.is_some_and(|name| !name.is_empty() && name.len() <= 200) {
        return Err(rejection(
            Some(id),
            "InvalidSegment",
            "Invalid segment name",
        ));
    }
    let start = value.get("start_time").and_then(Value::as_f64);
    let start = start
        .filter(|time| time.is_finite() && *time >= 0.0)
        .ok_or_else(|| rejection(Some(id), "InvalidSegment", "Invalid start_time"))?;
    if value.get("end_time").is_some() && !value["end_time"].is_number() {
        return Err(rejection(Some(id), "InvalidSegment", "Invalid end_time"));
    }
    let end = value.get("end_time").and_then(Value::as_f64);
    let in_progress = value.get("in_progress") == Some(&Value::Bool(true));
    if value.get("in_progress").is_some() && !value["in_progress"].is_boolean() {
        return Err(rejection(Some(id), "InvalidSegment", "Invalid in_progress"));
    }
    if end.is_some_and(|time| !time.is_finite() || time < start)
        || (end.is_none() && !in_progress)
        || (end.is_some() && in_progress)
    {
        return Err(rejection(
            Some(id),
            "InvalidSegment",
            "Invalid segment end_time",
        ));
    }
    if raw.len() > MAX_DOCUMENT_BYTES {
        return Err(rejection(
            Some(id),
            "SegmentTooLarge",
            "Segment exceeds 64 kB",
        ));
    }
    let is_subsegment = value.get("type").and_then(Value::as_str) == Some("subsegment");
    Ok(ParsedSegment {
        trace_id: trace_id.to_owned(),
        id: id.to_owned(),
        value: Segment {
            document: Arc::from(raw),
            start,
            end,
            in_progress,
            name: name.expect("preflight checked name").to_owned(),
            is_root: value.get("parent_id").is_none() && !is_subsegment,
            is_subsegment,
            parent_id: is_subsegment
                .then(|| value.get("parent_id").and_then(Value::as_str))
                .flatten()
                .map(str::to_owned),
            has_error: value.get("error") == Some(&Value::Bool(true)),
            has_fault: value.get("fault") == Some(&Value::Bool(true)),
            has_throttle: value.get("throttle") == Some(&Value::Bool(true)),
        },
    })
}

/// Deepest subsegment nesting, counting the document's root, that merging may produce. A merge
/// that would nest a subsegment (or anything embedded in it) deeper returns that subsegment as a
/// document of its own, so assembled documents stay within SDK JSON nesting limits.
const MAX_ASSEMBLY_DEPTH: usize = 32;
/// Nesting depth searched for embedded subsegments inside one stored document.
const MAX_EMBEDDED_DEPTH: usize = 32;
/// Fields that only route an independent subsegment; embedded subsegments do not carry them.
const ROUTING_FIELDS: [&str; 3] = ["type", "trace_id", "parent_id"];

/// The `Segments` of a `BatchGetTraces` trace: one document per segment, with every
/// independent subsegment merged into the `subsegments` of its parent segment or subsegment.
/// Subsegments whose parent is not in the trace (or that form a cycle) are returned as their
/// own documents. Documents and merged subsegments are ordered by `start_time`, then id.
fn assemble_trace(trace: &Trace) -> Vec<Value> {
    let by_start = |a: &&str, b: &&str| {
        trace[*a]
            .start
            .total_cmp(&trace[*b].start)
            .then_with(|| a.cmp(b))
    };
    let mut order: Vec<&str> = trace.keys().map(String::as_str).collect();
    order.sort_by(by_start);
    let mut parsed = BTreeMap::new();
    let mut embedded_owner: BTreeMap<String, &str> = BTreeMap::new();
    for &id in &order {
        if let Ok(value) = serde_json::from_str::<Value>(&trace[id].document) {
            collect_embedded_ids(&value, id, MAX_EMBEDDED_DEPTH, &mut embedded_owner);
            parsed.insert(id, value);
        }
    }
    let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut roots = Vec::new();
    for &id in &order {
        let segment = &trace[id];
        let owner = segment
            .parent_id
            .as_deref()
            .filter(|_| segment.is_subsegment && parsed.contains_key(id))
            .and_then(|parent| match trace.get_key_value(parent) {
                Some((parent, _)) => Some(parent.as_str()),
                None => embedded_owner.get(parent).copied(),
            })
            .filter(|owner| *owner != id && parsed.contains_key(owner));
        match owner {
            Some(owner) => children.entry(owner).or_default().push(id),
            None => roots.push(id),
        }
    }
    let mut assembly = Assembly {
        trace,
        parsed,
        children,
        visited: BTreeSet::new(),
        deferred: Vec::new(),
        documents: Vec::new(),
    };
    for id in roots {
        assembly.emit(id);
    }
    // Subsegments past the depth bound, then cycle members that no root reached.
    while let Some(id) = assembly.deferred.pop() {
        assembly.emit(id);
    }
    for &id in &order {
        assembly.emit(id);
    }
    let mut documents = assembly.documents;
    documents.sort_by(|(a, _), (b, _)| by_start(a, b));
    documents
        .into_iter()
        .map(|(id, document)| json!({"Id": id, "Document": document}))
        .collect()
}

struct Assembly<'a> {
    trace: &'a Trace,
    parsed: BTreeMap<&'a str, Value>,
    children: BTreeMap<&'a str, Vec<&'a str>>,
    visited: BTreeSet<&'a str>,
    deferred: Vec<&'a str>,
    documents: Vec<(&'a str, String)>,
}

impl<'a> Assembly<'a> {
    /// Return `id` as a document of its own, unless it was already placed.
    fn emit(&mut self, id: &'a str) {
        if self.visited.contains(id) {
            return;
        }
        let document = match self.build(id, 0) {
            Some((value, true)) => value.to_string(),
            _ => self.trace[id].document.to_string(),
        };
        self.documents.push((id, document));
    }

    /// `id` with its independent subsegments merged, and whether anything was merged.
    fn build(&mut self, id: &'a str, depth: usize) -> Option<(Value, bool)> {
        self.visited.insert(id);
        let mut value = self.parsed.remove(id)?;
        let mut merged = false;
        let children = self.children.get(id).cloned().unwrap_or_default();
        for child in children {
            if self.visited.contains(child) {
                continue;
            }
            let parent = self.trace[child].parent_id.as_deref().unwrap_or_default();
            let target = if parent == id {
                Some((&mut value, 0))
            } else {
                find_embedded_mut(&mut value, parent, MAX_EMBEDDED_DEPTH)
            };
            // The parent's `subsegments` is not an array: keep the child as a document.
            let target = target.filter(|(node, _)| {
                node.as_object().is_some_and(|node| {
                    node.get("subsegments")
                        .is_none_or(|subsegments| subsegments.is_array())
                })
            });
            let Some((target, embedded)) = target else {
                self.deferred.push(child);
                continue;
            };
            // One budget for the whole document: `value` sits at `depth`, the child one level
            // below its target, and the child's own embedded subsegments below that.
            let level = depth + embedded + 1;
            let height = self
                .parsed
                .get(child)
                .map_or(0, |child| subsegment_height(child, MAX_ASSEMBLY_DEPTH));
            if level + height >= MAX_ASSEMBLY_DEPTH {
                self.deferred.push(child);
                continue;
            }
            let Some((mut child_value, _)) = self.build(child, level) else {
                continue;
            };
            let Some(subsegments) = target
                .as_object_mut()
                .map(|node| node.entry("subsegments").or_insert_with(|| json!([])))
                .and_then(Value::as_array_mut)
            else {
                self.documents.push((child, child_value.to_string()));
                continue;
            };
            if let Some(fields) = child_value.as_object_mut() {
                for field in ROUTING_FIELDS {
                    fields.remove(field);
                }
            }
            subsegments.push(child_value);
            subsegments.sort_by(|a, b| {
                embedded_start(a)
                    .total_cmp(&embedded_start(b))
                    .then_with(|| embedded_id(a).cmp(embedded_id(b)))
            });
            merged = true;
        }
        Some((value, merged))
    }
}

fn embedded_start(value: &Value) -> f64 {
    value
        .get("start_time")
        .and_then(Value::as_f64)
        .unwrap_or(f64::INFINITY)
}

fn embedded_id(value: &Value) -> &str {
    value.get("id").and_then(Value::as_str).unwrap_or_default()
}

/// Record the ids of the subsegments embedded in `node`, owned by stored document `owner`.
fn collect_embedded_ids<'a>(
    node: &Value,
    owner: &'a str,
    depth: usize,
    ids: &mut BTreeMap<String, &'a str>,
) {
    if depth == 0 {
        return;
    }
    let Some(subsegments) = node.get("subsegments").and_then(Value::as_array) else {
        return;
    };
    for subsegment in subsegments {
        if let Some(id) = subsegment.get("id").and_then(Value::as_str) {
            ids.entry(id.to_owned()).or_insert(owner);
        }
        collect_embedded_ids(subsegment, owner, depth - 1, ids);
    }
}

/// The subsegment `id` embedded in `node`, with its nesting level below `node` (1 for a direct
/// subsegment).
fn find_embedded_mut<'v>(
    node: &'v mut Value,
    id: &str,
    depth: usize,
) -> Option<(&'v mut Value, usize)> {
    if depth == 0 {
        return None;
    }
    let subsegments = node.get_mut("subsegments")?.as_array_mut()?;
    for subsegment in subsegments {
        if subsegment.get("id").and_then(Value::as_str) == Some(id) {
            return Some((subsegment, 1));
        }
        if let Some((found, level)) = find_embedded_mut(subsegment, id, depth - 1) {
            return Some((found, level + 1));
        }
    }
    None
}

/// Levels of subsegments nested below `node`, capped at `limit`.
fn subsegment_height(node: &Value, limit: usize) -> usize {
    if limit == 0 {
        return 0;
    }
    node.get("subsegments")
        .and_then(Value::as_array)
        .and_then(|subsegments| {
            subsegments
                .iter()
                .map(|subsegment| 1 + subsegment_height(subsegment, limit - 1))
                .max()
        })
        .unwrap_or(0)
}

fn telemetry_count(record: &serde_json::Map<String, Value>, key: &str) -> Result<u64, ApiError> {
    match record.get(key) {
        None => Ok(0),
        Some(value) => value
            .as_u64()
            .filter(|n| *n <= i32::MAX as u64)
            .ok_or(ApiError::InvalidRequest),
    }
}

fn parse_service_filter(filter: &str) -> Result<String, ApiError> {
    let name = filter
        .strip_prefix("service(\"")
        .and_then(|value| value.strip_suffix("\")"))
        .ok_or(ApiError::InvalidRequest)?;
    if name.is_empty() || name.len() > 200 || name.contains(['\"', '\\']) {
        return Err(ApiError::InvalidRequest);
    }
    Ok(name.to_owned())
}

fn trace_id_time(id: &str) -> Option<u32> {
    u32::from_str_radix(id.split('-').nth(1)?, 16).ok()
}

fn rejection(id: Option<&str>, code: &str, message: &str) -> Value {
    let mut value = json!({"ErrorCode": code, "Message": message});
    if let Some(id) = id {
        value["Id"] = json!(id);
    }
    value
}

fn valid_segment_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_trace_id(id: &str) -> bool {
    let mut parts = id.split('-');
    matches!((parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("1"), Some(time), Some(unique), None)
            if time.len() == 8 && unique.len() == 24
                && time.bytes().chain(unique.bytes()).all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, StatusCode, Uri};

    const TRACE: &str = "1-65a00000-0123456789abcdef01234567";

    fn request(path: &str, account: &str, region: &str, body: Value) -> ServiceRequest {
        ServiceRequest {
            method: Method::POST,
            uri: path.parse::<Uri>().unwrap(),
            headers: HeaderMap::new(),
            body: body.to_string().into(),
            region: region.into(),
            account_id: account.into(),
            request_id: "test-request".into(),
        }
    }

    async fn call(handler: &XrayHandler, request: ServiceRequest) -> (StatusCode, Value) {
        let response = handler.handle(request).await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        )
    }

    fn segment(id: &str, trace_id: &str, in_progress: bool) -> String {
        let mut value =
            json!({"id": id, "trace_id": trace_id, "name": "worker", "start_time": 1.0});
        if in_progress {
            value["in_progress"] = json!(true);
        } else {
            value["end_time"] = json!(3.0);
        }
        value.to_string()
    }

    #[tokio::test]
    async fn partial_ingestion_and_scoped_latest_revision() {
        let handler = XrayHandler::new();
        let id = "1234567890abcdef";
        let initial = segment(id, TRACE, true);
        let final_doc = segment(id, TRACE, false);
        let (status, body) = call(
            &handler,
            request(
                "/TraceSegments",
                "a",
                "us-east-1",
                json!({"TraceSegmentDocuments": [initial, "invalid json", final_doc.clone()]}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["UnprocessedTraceSegments"].as_array().unwrap().len(),
            1
        );
        let (_, body) = call(
            &handler,
            request(
                "/Traces",
                "a",
                "us-east-1",
                json!({"TraceIds": [TRACE, TRACE]}),
            ),
        )
        .await;
        assert_eq!(body["Traces"].as_array().unwrap().len(), 1);
        assert_eq!(body["Traces"][0]["Segments"][0]["Document"], final_doc);
        assert_eq!(body["Traces"][0]["Duration"], 2.0);
        for (account, region) in [("b", "us-east-1"), ("a", "us-west-2")] {
            let (_, body) = call(
                &handler,
                request("/Traces", account, region, json!({"TraceIds": [TRACE]})),
            )
            .await;
            assert_eq!(body["Traces"], json!([]));
        }
        let (_, body) = call(
            &handler,
            request(
                "/TraceSegments",
                "a",
                "us-east-1",
                json!({"TraceSegmentDocuments": [segment(id, TRACE, true)]}),
            ),
        )
        .await;
        assert_eq!(
            body["UnprocessedTraceSegments"].as_array().unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn telemetry_is_atomic_scoped_and_never_creates_a_trace() {
        let handler = XrayHandler::new();
        let good = json!({"Timestamp": 100.0, "SegmentsReceivedCount": 2,
            "BackendConnectionErrors": {"TimeoutCount": 1}});
        let (status, body) = call(
            &handler,
            request(
                "/TelemetryRecords",
                "a",
                "us-east-1",
                json!({"TelemetryRecords": [good.clone()]}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, Value::Null);
        let scope = Scope {
            account_id: "a".into(),
            region: "us-east-1".into(),
        };
        assert_eq!(handler.telemetry.lock().unwrap()[&scope][&1].received, 2);
        let (status, _) = call(
            &handler,
            request(
                "/TelemetryRecords",
                "a",
                "us-east-1",
                json!({"TelemetryRecords": [good, {"Timestamp": 101.0, "SegmentsSentCount": -1}]}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(handler.telemetry.lock().unwrap()[&scope][&1].records, 1);
        let (_, traces) = call(
            &handler,
            request("/Traces", "a", "us-east-1", json!({"TraceIds": [TRACE]})),
        )
        .await;
        assert_eq!(traces["Traces"], json!([]));
        assert!(handler
            .telemetry
            .lock()
            .unwrap()
            .get(&Scope {
                account_id: "b".into(),
                region: "us-east-1".into()
            })
            .is_none());
    }

    #[tokio::test]
    async fn summaries_use_trace_id_interval_and_verified_service_filter() {
        let handler = XrayHandler::new();
        let segment = segment("1234567890abcdef", TRACE, false);
        let (_, _) = call(
            &handler,
            request(
                "/TraceSegments",
                "a",
                "us-east-1",
                json!({"TraceSegmentDocuments": [segment]}),
            ),
        )
        .await;
        let trace_time = trace_id_time(TRACE).unwrap() as f64;
        let query = json!({"StartTime": trace_time, "EndTime": trace_time + 1.0,
            "FilterExpression": "service(\"worker\")"});
        let (_, result) = call(
            &handler,
            request("/TraceSummaries", "a", "us-east-1", query.clone()),
        )
        .await;
        assert_eq!(result["TracesProcessedCount"], 1);
        assert_eq!(result["TraceSummaries"][0]["Id"], TRACE);
        assert_eq!(result["TraceSummaries"][0]["Duration"], 2.0);
        assert_eq!(result["TraceSummaries"][0]["ResponseTime"], 2.0);
        assert_eq!(result["TraceSummaries"][0]["IsPartial"], false);
        let (_, west) = call(
            &handler,
            request("/TraceSummaries", "a", "us-west-2", query.clone()),
        )
        .await;
        assert_eq!(west["TraceSummaries"], json!([]));
        let (_, other) = call(
            &handler,
            request(
                "/TraceSummaries",
                "a",
                "us-east-1",
                json!({"StartTime": trace_time + 1.0, "EndTime": trace_time + 2.0}),
            ),
        )
        .await;
        assert_eq!(other["TraceSummaries"], json!([]));
        let (status, _) = call(
            &handler,
            request(
                "/TraceSummaries",
                "a",
                "us-east-1",
                json!({"StartTime": trace_time, "EndTime": trace_time + 1.0, "Sampling": true}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalid_requests_and_unsupported_routes_do_not_mutate() {
        let handler = XrayHandler::new();
        let (status, _) = call(
            &handler,
            request(
                "/TraceSegments",
                "a",
                "us-east-1",
                json!({"TraceSegmentDocuments": ["not json", 23]}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, body) = call(
            &handler,
            request(
                "/TraceSummaries",
                "a",
                "us-east-1",
                json!({"StartTime": 1.0, "EndTime": 5.0, "FilterExpression": "unsupported()"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["message"], "Invalid X-Ray request");
        let (_, body) = call(
            &handler,
            request("/Traces", "a", "us-east-1", json!({"TraceIds": [TRACE]})),
        )
        .await;
        assert_eq!(body["Traces"], json!([]));
    }

    async fn stored_trace_ids(handler: &XrayHandler, ids: &[&str]) -> Vec<String> {
        let (_, body) = call(
            handler,
            request("/Traces", "a", "us-east-1", json!({"TraceIds": ids})),
        )
        .await;
        body["Traces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|trace| trace["Id"].as_str().unwrap().to_owned())
            .collect()
    }

    #[tokio::test]
    async fn full_scope_evicts_oldest_trace_and_full_trace_rejects() {
        let handler = XrayHandler::new();
        let now = unix_now();
        let trace_id = |n: usize| format!("1-65a00000-{n:024x}");
        let traces_needed = MAX_SCOPE_SEGMENTS / MAX_TRACE_SEGMENTS;
        for trace in 0..traces_needed {
            let documents: Vec<String> = (0..MAX_TRACE_SEGMENTS)
                .map(|n| segment(&format!("{n:016x}"), &trace_id(trace), false))
                .collect();
            let documents: Vec<&str> = documents.iter().map(String::as_str).collect();
            let rejected = handler
                .ingest_documents_at("a", "us-east-1", &documents, now)
                .unwrap();
            assert!(rejected.is_empty(), "{rejected:?}");
        }
        // A full trace still rejects its next segment.
        let rejected = handler
            .ingest_documents_at(
                "a",
                "us-east-1",
                &[&segment("ffffffffffffffff", &trace_id(1), false)],
                now,
            )
            .unwrap();
        assert_eq!(rejected[0]["Message"], "Trace capacity exceeded");
        // A full scope evicts the trace stored first and keeps the new one.
        let newest = trace_id(traces_needed);
        let rejected = handler
            .ingest_documents_at(
                "a",
                "us-east-1",
                &[&segment("1234567890abcdef", &newest, false)],
                now,
            )
            .unwrap();
        assert!(rejected.is_empty(), "{rejected:?}");
        let (oldest, second) = (trace_id(0), trace_id(1));
        assert_eq!(
            stored_trace_ids(&handler, &[&oldest, &second, &newest]).await,
            vec![second.clone(), newest.clone()]
        );
        let scope = Scope {
            account_id: "a".into(),
            region: "us-east-1".into(),
        };
        let stored = handler.scopes.lock().unwrap()[&scope].segment_count;
        assert_eq!(stored, MAX_SCOPE_SEGMENTS - MAX_TRACE_SEGMENTS + 1);
        let trace_time = trace_id_time(&oldest).unwrap() as f64;
        let (_, summaries) = call(
            &handler,
            request(
                "/TraceSummaries",
                "a",
                "us-east-1",
                json!({"StartTime": trace_time, "EndTime": trace_time + 1.0}),
            ),
        )
        .await;
        let ids: Vec<&Value> = summaries["TraceSummaries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|summary| &summary["Id"])
            .collect();
        assert!(!ids.contains(&&json!(oldest)));
        assert!(ids.contains(&&json!(newest)));
    }

    #[tokio::test]
    async fn traces_expire_thirty_days_after_they_were_stored() {
        let handler = XrayHandler::new();
        let now = unix_now();
        let old = "1-65a00000-000000000000000000000001";
        handler
            .ingest_documents_at(
                "a",
                "us-east-1",
                &[&segment("1234567890abcdef", old, false)],
                now - RETENTION_SECONDS,
            )
            .unwrap();
        handler
            .ingest_documents_at(
                "a",
                "us-east-1",
                &[&segment("1234567890abcdef", TRACE, false)],
                now - RETENTION_SECONDS + 60,
            )
            .unwrap();
        // Queries hide expired traces; the next ingestion drops them.
        assert_eq!(stored_trace_ids(&handler, &[old, TRACE]).await, vec![TRACE]);
        handler
            .ingest_documents_at(
                "a",
                "us-east-1",
                &[&segment("abcdef1234567890", TRACE, false)],
                now,
            )
            .unwrap();
        let scope = Scope {
            account_id: "a".into(),
            region: "us-east-1".into(),
        };
        let scopes = handler.scopes.lock().unwrap();
        assert!(!scopes[&scope].traces.contains_key(old));
        assert_eq!(scopes[&scope].segment_count, 2);
    }

    /// The documents a Lambda `Active` environment produces: the function segment emitted by
    /// Lambda and an SDK subsegment sent on its own through the daemon endpoint, whose parent
    /// is the facade id (the `Parent` of the trace header).
    #[tokio::test]
    async fn lambda_function_segment_and_daemon_subsegment_form_one_trace() {
        let handler = XrayHandler::new();
        let function = json!({"name": "orders", "id": "1111111111111111", "trace_id": TRACE,
            "start_time": 10.0, "end_time": 10.5, "origin": "AWS::Lambda::Function",
            "resource_arn": "arn:aws:lambda:us-east-1:000000000000:function:orders",
            "fault": true})
        .to_string();
        let subsegment = json!({"name": "## handler", "id": "2222222222222222",
            "trace_id": TRACE, "parent_id": "1111111111111111", "type": "subsegment",
            "start_time": 10.1, "end_time": 10.4})
        .to_string();
        for document in [&subsegment, &function] {
            let rejected = handler
                .ingest_documents("000000000000", "us-east-1", &[document])
                .unwrap();
            assert!(rejected.is_empty(), "{rejected:?}");
        }
        let (_, body) = call(
            &handler,
            request(
                "/Traces",
                "000000000000",
                "us-east-1",
                json!({"TraceIds": [TRACE]}),
            ),
        )
        .await;
        let segments = body["Traces"][0]["Segments"].as_array().unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0]["Id"], "1111111111111111");
        let document: Value =
            serde_json::from_str(segments[0]["Document"].as_str().unwrap()).unwrap();
        assert_eq!(document["origin"], "AWS::Lambda::Function");
        assert_eq!(
            document["subsegments"],
            json!([{"name": "## handler", "id": "2222222222222222",
                "start_time": 10.1, "end_time": 10.4}])
        );
        assert_eq!(body["Traces"][0]["Duration"], 0.5);
        let trace_time = trace_id_time(TRACE).unwrap() as f64;
        let (_, summaries) = call(
            &handler,
            request(
                "/TraceSummaries",
                "000000000000",
                "us-east-1",
                json!({"StartTime": trace_time, "EndTime": trace_time + 1.0,
                    "FilterExpression": "service(\"orders\")"}),
            ),
        )
        .await;
        let summary = &summaries["TraceSummaries"][0];
        assert_eq!(summary["EntryPoint"]["Name"], "orders");
        assert_eq!(summary["HasFault"], true);
        assert_eq!(summary["ResponseTime"], 0.5);
        assert_eq!(
            summary["ServiceIds"],
            json!([{"Name": "orders", "AccountId": "000000000000"}])
        );
        let (_, other) = call(
            &handler,
            request(
                "/Traces",
                "111111111111",
                "us-east-1",
                json!({"TraceIds": [TRACE]}),
            ),
        )
        .await;
        assert_eq!(other["Traces"], json!([]));
    }

    fn subsegment(id: &str, parent: &str, start: f64) -> Value {
        json!({"name": format!("sub-{id}"), "id": id, "trace_id": TRACE, "parent_id": parent,
            "type": "subsegment", "start_time": start, "end_time": start + 0.1})
    }

    fn ingest(handler: &XrayHandler, documents: &[Value]) {
        let documents: Vec<String> = documents.iter().map(Value::to_string).collect();
        let documents: Vec<&str> = documents.iter().map(String::as_str).collect();
        let rejected = handler
            .ingest_documents("a", "us-east-1", &documents)
            .unwrap();
        assert!(rejected.is_empty(), "{rejected:?}");
    }

    /// `(Id, parsed Document)` of every returned segment document.
    async fn trace_documents(handler: &XrayHandler) -> Vec<(String, Value)> {
        let (_, body) = call(
            handler,
            request("/Traces", "a", "us-east-1", json!({"TraceIds": [TRACE]})),
        )
        .await;
        body["Traces"][0]["Segments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|segment| {
                (
                    segment["Id"].as_str().unwrap().to_owned(),
                    serde_json::from_str(segment["Document"].as_str().unwrap()).unwrap(),
                )
            })
            .collect()
    }

    fn subsegment_ids(node: &Value) -> Vec<&str> {
        node["subsegments"]
            .as_array()
            .map(|items| items.iter().map(|s| s["id"].as_str().unwrap()).collect())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn nested_independent_subsegments_merge_into_their_parents() {
        let handler = XrayHandler::new();
        let root = json!({"name": "api", "id": "aaaaaaaaaaaaaaaa", "trace_id": TRACE,
            "start_time": 1.0, "end_time": 2.0,
            "subsegments": [{"id": "eeeeeeeeeeeeeeee", "name": "embedded",
                "start_time": 1.5, "end_time": 1.6}]});
        ingest(
            &handler,
            &[
                subsegment("cccccccccccccccc", "bbbbbbbbbbbbbbbb", 1.3),
                subsegment("dddddddddddddddd", "aaaaaaaaaaaaaaaa", 1.1),
                subsegment("bbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaa", 1.2),
                subsegment("ffffffffffffffff", "eeeeeeeeeeeeeeee", 1.55),
                root,
            ],
        );
        let documents = trace_documents(&handler).await;
        assert_eq!(documents.len(), 1);
        let (id, document) = &documents[0];
        assert_eq!(id, "aaaaaaaaaaaaaaaa");
        assert_eq!(
            subsegment_ids(document),
            ["dddddddddddddddd", "bbbbbbbbbbbbbbbb", "eeeeeeeeeeeeeeee"]
        );
        let nested = &document["subsegments"][1];
        assert_eq!(subsegment_ids(nested), ["cccccccccccccccc"]);
        assert_eq!(nested["name"], "sub-bbbbbbbbbbbbbbbb");
        for field in ROUTING_FIELDS {
            assert!(nested.get(field).is_none());
            assert!(nested["subsegments"][0].get(field).is_none());
        }
        assert_eq!(
            subsegment_ids(&document["subsegments"][2]),
            ["ffffffffffffffff"]
        );
    }

    #[tokio::test]
    async fn subsegments_without_a_stored_parent_are_returned_as_documents() {
        let handler = XrayHandler::new();
        let orphan = subsegment("bbbbbbbbbbbbbbbb", "9999999999999999", 1.2);
        let child = subsegment("cccccccccccccccc", "bbbbbbbbbbbbbbbb", 1.3);
        let first = subsegment("dddddddddddddddd", "eeeeeeeeeeeeeeee", 1.0);
        let second = subsegment("eeeeeeeeeeeeeeee", "dddddddddddddddd", 1.1);
        ingest(&handler, &[orphan.clone(), child, first, second]);
        let documents = trace_documents(&handler).await;
        let ids: Vec<&str> = documents.iter().map(|(id, _)| id.as_str()).collect();
        // The orphan keeps its own child; the two-subsegment cycle comes back once.
        assert_eq!(ids, ["dddddddddddddddd", "bbbbbbbbbbbbbbbb"]);
        assert_eq!(subsegment_ids(&documents[0].1), ["eeeeeeeeeeeeeeee"]);
        assert_eq!(documents[1].1["parent_id"], orphan["parent_id"]);
        assert_eq!(documents[1].1["type"], "subsegment");
        assert_eq!(subsegment_ids(&documents[1].1), ["cccccccccccccccc"]);
    }

    #[tokio::test]
    async fn subsegment_chains_past_the_depth_bound_split_into_documents() {
        let handler = XrayHandler::new();
        let id = |n: usize| format!("{n:016x}");
        let mut documents = vec![json!({"name": "api", "id": id(0), "trace_id": TRACE,
            "start_time": 1.0, "end_time": 2.0})];
        for n in 1..=MAX_ASSEMBLY_DEPTH + 5 {
            documents.push(subsegment(&id(n), &id(n - 1), 1.0 + n as f64 / 100.0));
        }
        ingest(&handler, &documents);
        let returned = trace_documents(&handler).await;
        assert_eq!(returned.len(), 2);
        assert_eq!(returned[0].0, id(0));
        assert_eq!(returned[1].0, id(MAX_ASSEMBLY_DEPTH));
    }

    /// Levels of nested documents, counting `node` itself.
    fn nesting(node: &Value) -> usize {
        1 + node["subsegments"]
            .as_array()
            .map_or(0, |items| items.iter().map(nesting).max().unwrap_or(0))
    }

    fn collect_ids<'v>(node: &'v Value, ids: &mut Vec<&'v str>) {
        ids.push(node["id"].as_str().unwrap());
        for item in node["subsegments"].as_array().into_iter().flatten() {
            collect_ids(item, ids);
        }
    }

    #[tokio::test]
    async fn embedded_parents_share_the_assembly_depth_budget() {
        let handler = XrayHandler::new();
        let embedded_levels = MAX_ASSEMBLY_DEPTH - 2;
        let id = |n: usize, level: usize| format!("{n:08x}{level:08x}");
        // Every stored subsegment embeds a chain just under the budget, and the next stored
        // subsegment attaches to the deepest embedded entry of the previous one.
        let with_chain = |mut document: Value, n: usize| {
            let mut chain = Value::Null;
            for level in (1..=embedded_levels).rev() {
                let mut node = json!({"id": id(n, level), "name": "embedded",
                    "start_time": 1.0, "end_time": 1.1});
                if !chain.is_null() {
                    node["subsegments"] = json!([chain]);
                }
                chain = node;
            }
            document["subsegments"] = json!([chain]);
            document
        };
        let mut documents = vec![with_chain(
            json!({"name": "api", "id": id(0, 0), "trace_id": TRACE,
                "start_time": 1.0, "end_time": 2.0}),
            0,
        )];
        let stored = 40;
        for n in 1..stored {
            let parent = id(n - 1, embedded_levels);
            let start = 1.0 + n as f64 / 100.0;
            documents.push(with_chain(subsegment(&id(n, 0), &parent, start), n));
        }
        ingest(&handler, &documents);
        let returned = trace_documents(&handler).await;
        let mut ids = Vec::new();
        for (_, document) in &returned {
            assert!(
                nesting(document) <= MAX_ASSEMBLY_DEPTH,
                "{}",
                nesting(document)
            );
            collect_ids(document, &mut ids);
        }
        ids.sort_unstable();
        let mut expected: Vec<String> = (0..stored)
            .flat_map(|n| (0..=embedded_levels).map(move |level| id(n, level)))
            .collect();
        expected.sort_unstable();
        assert_eq!(ids, expected);
        // Without one shared budget every link of the chain would merge into the root.
        assert_eq!(returned.len(), stored);
    }

    #[tokio::test]
    async fn final_subsegment_replaces_its_in_progress_revision_in_the_parent() {
        let handler = XrayHandler::new();
        let root = json!({"name": "api", "id": "aaaaaaaaaaaaaaaa", "trace_id": TRACE,
            "start_time": 1.0, "in_progress": true});
        let mut pending = subsegment("bbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaa", 1.2);
        pending.as_object_mut().unwrap().remove("end_time");
        pending["in_progress"] = json!(true);
        ingest(&handler, &[root, pending]);
        let documents = trace_documents(&handler).await;
        assert_eq!(documents.len(), 1);
        assert_eq!(documents[0].1["in_progress"], true);
        assert_eq!(documents[0].1["subsegments"][0]["in_progress"], true);
        let done = subsegment("bbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaa", 1.2);
        ingest(&handler, &[done]);
        let documents = trace_documents(&handler).await;
        let merged = &documents[0].1["subsegments"];
        assert_eq!(merged.as_array().unwrap().len(), 1);
        assert!(merged[0].get("in_progress").is_none());
        assert_eq!(merged[0]["end_time"], 1.2 + 0.1);
    }
}
