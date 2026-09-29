//! Scoped, in-memory X-Ray trace ingestion and retrieval.
//!
//! PutTraceSegments, PutTelemetryRecords, BatchGetTraces and a bounded
//! GetTraceSummaries subset are native. Other X-Ray operations
//! fail explicitly until their contracts and state are implemented.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use http::Method;
use localcloud_core::error_mapping::AwsError;
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
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
    document: String,
    start: f64,
    end: Option<f64>,
    in_progress: bool,
    name: String,
    is_root: bool,
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
type TraceStore = BTreeMap<String, Trace>;

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
        if documents.iter().any(|document| !document.is_string()) {
            return Err(ApiError::InvalidRequest);
        }

        let scope = Scope {
            account_id: request.account_id.clone(),
            region: request.region.clone(),
        };
        let mut scopes = self.scopes.lock().map_err(|_| ApiError::InternalFailure)?;
        let traces = scopes.entry(scope).or_default();
        let mut rejected = Vec::new();
        for document in documents {
            let raw = document.as_str().expect("preflight checked string");
            let segment = match parse_segment(raw) {
                Ok(segment) => segment,
                Err(failure) => {
                    rejected.push(failure);
                    continue;
                }
            };
            let trace_id = segment.trace_id;
            let id = segment.id;
            let existing = traces.get(&trace_id).and_then(|trace| trace.get(&id));
            if let Some(existing) = existing {
                if !existing.in_progress && (segment.value.in_progress || existing.document != raw)
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
                let trace_size = traces.get(&trace_id).map_or(0, BTreeMap::len);
                let total: usize = traces.values().map(BTreeMap::len).sum();
                if trace_size >= MAX_TRACE_SEGMENTS || total >= MAX_SCOPE_SEGMENTS {
                    rejected.push(rejection(
                        Some(&id),
                        "SegmentRejected",
                        "Trace capacity exceeded",
                    ));
                    continue;
                }
            }
            traces
                .entry(trace_id)
                .or_default()
                .insert(id, segment.value);
        }
        Ok(json!({"UnprocessedTraceSegments": rejected}))
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
                if !value.as_str().is_some_and(|text| text.len() <= limit) {
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
            for (id, segments) in traces {
                let trace_time = trace_id_time(id).ok_or(ApiError::InternalFailure)? as f64;
                if trace_time < start || trace_time >= end {
                    continue;
                }
                processed = processed.saturating_add(1);
                if service_filter
                    .as_ref()
                    .is_some_and(|name| !segments.values().any(|s| &s.name == name))
                {
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
                let service_names: BTreeSet<&str> =
                    segments.values().map(|s| s.name.as_str()).collect();
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
        let scopes = self.scopes.lock().map_err(|_| ApiError::InternalFailure)?;
        let mut found = Vec::new();
        let mut seen = BTreeSet::new();
        if let Some(traces) = scopes.get(&scope) {
            for id in ids {
                let id = id.as_str().expect("preflight checked string");
                if !seen.insert(id) {
                    continue;
                }
                if let Some(segments) = traces.get(id) {
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
                        "Segments": segments.iter().map(|(id, segment)| json!({"Id": id, "Document": segment.document})).collect::<Vec<_>>()
                    });
                    if maximum.is_finite() {
                        trace["Duration"] = json!((maximum - minimum).max(0.0));
                    }
                    found.push(trace);
                }
            }
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
    Ok(ParsedSegment {
        trace_id: trace_id.to_owned(),
        id: id.to_owned(),
        value: Segment {
            document: raw.to_owned(),
            start,
            end,
            in_progress,
            name: name.expect("preflight checked name").to_owned(),
            is_root: value.get("parent_id").is_none(),
            has_error: value.get("error") == Some(&Value::Bool(true)),
            has_fault: value.get("fault") == Some(&Value::Bool(true)),
            has_throttle: value.get("throttle") == Some(&Value::Bool(true)),
        },
    })
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
}
