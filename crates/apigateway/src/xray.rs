//! X-Ray active tracing for REST API stages (`tracingEnabled`).
//!
//! A traced stage continues the caller's trace (a valid `Root` in `X-Amzn-Trace-Id`) or starts
//! one, honors the caller's `Sampled=1`/`Sampled=0`, and otherwise applies X-Ray's default
//! rule: a reservoir of 1 request per second plus 5% of the remaining requests. A sampled
//! request records an `AWS::ApiGateway::Stage` segment named `<api-name>/<stage>`, with one
//! embedded `Lambda` subsegment per Lambda call; each call gets
//! `Root=<root>;Parent=<subsegment id>;Sampled=1`, so the `AWS::Lambda` segment becomes the
//! subsegment's child. Unsampled requests forward `Root=<root>;Sampled=0`. The segment is
//! stored through X-Ray `PutTraceSegments` (internal dispatch) in the API's account and Region.
//! HTTP APIs do not support X-Ray tracing and only forward the client header.

use std::collections::HashSet;
use std::sync::{Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use locallycloud_core::registry::ServiceRegistry;
use serde_json::{json, Value};
use uuid::Uuid;

/// The default sampling rule's fixed rate beyond the reservoir.
const FIXED_RATE: f64 = 0.05;
/// X-Ray rejects segment names longer than 200 characters.
const MAX_NAME_CHARS: usize = 200;

/// X-Ray's `Default` sampling rule (1 request per second, then 5%), per account and Region.
pub struct Sampler {
    /// The current second and the scopes whose reservoir slot it already used.
    reservoir: Mutex<(u64, HashSet<String>)>,
    /// Uniform draw in `[0, 1)`; injectable so tests are deterministic.
    draw: Box<dyn Fn() -> f64 + Send + Sync>,
}

impl Default for Sampler {
    fn default() -> Self {
        Self::with_draw(|| {
            let bytes = random_bytes::<4>();
            f64::from(u32::from_be_bytes(bytes)) / (f64::from(u32::MAX) + 1.0)
        })
    }
}

impl Sampler {
    pub fn with_draw(draw: impl Fn() -> f64 + Send + Sync + 'static) -> Self {
        Self {
            reservoir: Mutex::new((0, HashSet::new())),
            draw: Box::new(draw),
        }
    }

    fn sample(&self, scope: &str) -> bool {
        self.sample_at(scope, unix_seconds())
    }

    fn sample_at(&self, scope: &str, second: u64) -> bool {
        let reserved = {
            let mut reservoir = self
                .reservoir
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if reservoir.0 != second {
                *reservoir = (second, HashSet::new());
            }
            reservoir.1.insert(scope.to_owned())
        };
        reserved || (self.draw)() < FIXED_RATE
    }
}

/// The stage a traced request runs on.
pub(crate) struct TracedStage {
    pub api_id: String,
    pub api_name: String,
    pub stage: String,
}

/// The trace context of one request on a stage with `tracingEnabled`.
pub(crate) struct StageTrace {
    root: String,
    sampled: bool,
    /// The stage segment's id (meaningful only when sampled).
    id: String,
    caller_parent: Option<String>,
    /// Sampled by the stage's rule rather than by the caller's decision.
    by_rule: bool,
    start: SystemTime,
    subsegments: Mutex<Vec<Value>>,
}

/// How one Lambda call of a traced request ended.
pub(crate) enum CallOutcome {
    Status(u16),
    TimedOut,
}

impl StageTrace {
    /// Continue the caller's trace or start one, deciding `Sampled` for this request.
    /// `scope` keys the reservoir (the API's account and Region).
    pub(crate) fn begin(incoming: Option<&HeaderValue>, sampler: &Sampler, scope: &str) -> Self {
        let incoming = incoming.and_then(|value| value.to_str().ok());
        let root = incoming.and_then(valid_root);
        let decision = root.and(incoming).and_then(incoming_decision);
        let caller_parent = root.and(incoming).and_then(valid_parent).map(str::to_owned);
        let (sampled, by_rule) = match decision {
            Some(decision) => (decision, false),
            None => (sampler.sample(scope), true),
        };
        Self {
            root: root.map(str::to_owned).unwrap_or_else(new_root),
            sampled,
            id: hex(&random_bytes::<8>()),
            caller_parent,
            by_rule,
            start: SystemTime::now(),
            subsegments: Mutex::new(Vec::new()),
        }
    }

    /// The header for one downstream Lambda call and, when sampled, the id of the subsegment
    /// that records the call (the `Parent` the callee sees).
    pub(crate) fn downstream(&self) -> (HeaderValue, Option<String>) {
        let subsegment = self.sampled.then(|| hex(&random_bytes::<8>()));
        let header = match &subsegment {
            Some(parent) => format!("Root={};Parent={parent};Sampled=1", self.root),
            None => format!("Root={};Sampled=0", self.root),
        };
        // Generated from hex digits and fixed text only.
        let header =
            HeaderValue::from_str(&header).unwrap_or_else(|_| HeaderValue::from_static(""));
        (header, subsegment)
    }

    /// Record the `Lambda` subsegment of a call started at `start` with `downstream`'s id.
    pub(crate) fn record_lambda(
        &self,
        id: String,
        start: SystemTime,
        function: &str,
        region: &str,
        outcome: CallOutcome,
    ) {
        let name = function_name(function);
        let mut subsegment = json!({
            "id": id,
            "name": "Lambda",
            "start_time": epoch_seconds(start),
            "end_time": epoch_seconds(SystemTime::now()),
            "namespace": "aws",
            "http": {"request": {
                "url": format!(
                    "https://lambda.{region}.amazonaws.com/2015-03-31/functions/{function}/invocations"
                ),
                "method": "POST",
            }},
            "aws": {
                "function_name": name,
                "region": region,
                "operation": "Invoke",
                "resource_names": [name],
            },
        });
        match outcome {
            CallOutcome::Status(status) => {
                subsegment["http"]["response"] = json!({ "status": status });
                apply_status_flags(&mut subsegment, status);
            }
            CallOutcome::TimedOut => {
                subsegment["fault"] = json!(true);
            }
        }
        self.subsegments
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(subsegment);
    }

    /// The stage segment of a sampled request that ended with `status`.
    pub(crate) fn segment(
        &self,
        stage: &TracedStage,
        account: &str,
        region: &str,
        request_id: &str,
        request: (&Method, &str),
        status: u16,
    ) -> Option<Value> {
        if !self.sampled {
            return None;
        }
        let (method, url) = request;
        let name: String = format!("{}/{}", stage.api_name, stage.stage)
            .chars()
            .take(MAX_NAME_CHARS)
            .collect();
        let subsegments = std::mem::take(
            &mut *self
                .subsegments
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let mut segment = json!({
            "id": self.id,
            "name": name,
            "trace_id": self.root,
            "start_time": epoch_seconds(self.start),
            "end_time": epoch_seconds(SystemTime::now()),
            "origin": "AWS::ApiGateway::Stage",
            "resource_arn": format!(
                "arn:aws:apigateway:{region}::/restapis/{}/stages/{}",
                stage.api_id, stage.stage
            ),
            "http": {
                "request": {"url": url, "method": method.as_str()},
                "response": {"status": status},
            },
            "aws": {"api_gateway": {
                "account_id": account,
                "rest_api_id": stage.api_id,
                "stage": stage.stage,
                "request_id": request_id,
            }},
            "annotations": {"aws:api_id": stage.api_id, "aws:api_stage": stage.stage},
        });
        if self.by_rule {
            segment["aws"]["xray"] = json!({ "sampling_rule_name": "Default" });
        }
        if let Some(parent) = &self.caller_parent {
            segment["parent_id"] = json!(parent);
        }
        if !subsegments.is_empty() {
            segment["subsegments"] = Value::Array(subsegments);
        }
        apply_status_flags(&mut segment, status);
        Some(segment)
    }
}

/// `error` for 4xx (plus `throttle` for 429) and `fault` for 5xx.
fn apply_status_flags(document: &mut Value, status: u16) {
    match status {
        429 => {
            document["error"] = json!(true);
            document["throttle"] = json!(true);
        }
        400..=499 => document["error"] = json!(true),
        500..=599 => document["fault"] = json!(true),
        _ => {}
    }
}

/// The function name of an integration's function (a name, a partial or a full ARN, possibly
/// qualified).
fn function_name(function: &str) -> &str {
    let tail = function
        .rsplit_once(":function:")
        .map_or(function, |(_, tail)| tail);
    tail.split(':').next().unwrap_or(tail)
}

/// Store `documents` through X-Ray `PutTraceSegments` in the API's scope, in the background.
/// Delivery is best effort: failures are logged at debug level and dropped.
pub(crate) fn put_trace_segments(
    registry: &Weak<ServiceRegistry>,
    account: &str,
    region: &str,
    documents: Vec<String>,
) {
    let Some(dispatcher) = registry
        .upgrade()
        .and_then(|registry| registry.internal_dispatcher())
    else {
        tracing::debug!("X-Ray segments dropped: internal dispatcher unavailable");
        return;
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // The credential scope only routes the call; the trusted scope is the API's.
    let Ok(authorization) = HeaderValue::from_str(&format!(
        "AWS4-HMAC-SHA256 Credential=local/19700101/{region}/xray/aws4_request"
    )) else {
        return;
    };
    headers.insert(http::header::AUTHORIZATION, authorization);
    let count = documents.len();
    let body = json!({ "TraceSegmentDocuments": documents }).to_string();
    let account = account.to_owned();
    let region = region.to_owned();
    tokio::spawn(async move {
        let response = dispatcher
            .dispatch_scoped(
                &Method::POST,
                &Uri::from_static("/TraceSegments"),
                &headers,
                Bytes::from(body),
                &Uuid::new_v4().to_string(),
                &account,
                &region,
            )
            .await;
        let status = response.status();
        let unprocessed = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|body| body["UnprocessedTraceSegments"].as_array().map(Vec::len))
            .unwrap_or(0);
        if !status.is_success() || unprocessed > 0 {
            tracing::debug!(%status, count, unprocessed, "X-Ray segments not fully stored");
        }
    });
}

fn field<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(name)?.strip_prefix('='))
}

/// A well-formed `Root=1-xxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx` value.
fn valid_root(header: &str) -> Option<&str> {
    let root = field(header, "Root")?;
    let mut parts = root.split('-');
    let well_formed = parts.next() == Some("1")
        && parts.next().is_some_and(|epoch| is_hex(epoch, 8))
        && parts.next().is_some_and(|id| is_hex(id, 24))
        && parts.next().is_none();
    well_formed.then_some(root)
}

fn valid_parent(header: &str) -> Option<&str> {
    field(header, "Parent").filter(|parent| is_hex(parent, 16))
}

/// `Sampled=1` or `Sampled=0`; `Sampled=?` and other values defer the decision.
fn incoming_decision(header: &str) -> Option<bool> {
    match field(header, "Sampled")? {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

fn epoch_seconds(at: SystemTime) -> f64 {
    at.duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs_f64())
        .unwrap_or_default()
}

fn new_root() -> String {
    format!(
        "1-{:08x}-{}",
        unix_seconds() as u32,
        hex(&random_bytes::<12>())
    )
}

/// Random bytes drawn from v4 UUIDs, skipping their fixed version and variant bytes.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    let mut filled = 0;
    while filled < N {
        let uuid = Uuid::new_v4();
        for (index, byte) in uuid.as_bytes().iter().enumerate() {
            if index == 6 || index == 8 {
                continue;
            }
            if filled == N {
                break;
            }
            out[filled] = *byte;
            filled += 1;
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "1-5759e988-bd862e3fe1be46a994272793";

    fn stage() -> TracedStage {
        TracedStage {
            api_id: "a1b2c3d4e5".into(),
            api_name: "testxray".into(),
            stage: "dev".into(),
        }
    }

    fn begin(header: Option<&str>, sampler: &Sampler) -> StageTrace {
        let header = header.map(|value| HeaderValue::from_str(value).unwrap());
        StageTrace::begin(header.as_ref(), sampler, "000000000000/us-east-1")
    }

    #[test]
    fn caller_decision_wins_and_root_is_kept() {
        let never = || Sampler::with_draw(|| 0.99);
        let sampler = never();
        // Exhaust the reservoir so only the caller's decision can sample.
        assert!(sampler.sample("000000000000/us-east-1"));
        for (decision, expected) in [("1", true), ("0", false), ("?", false)] {
            let trace = begin(
                Some(&format!(
                    "Root={ROOT};Parent=53995c3f42cd8ad8;Sampled={decision}"
                )),
                &sampler,
            );
            assert_eq!(trace.sampled, expected, "Sampled={decision}");
            assert_eq!(trace.root, ROOT);
            assert_eq!(trace.caller_parent.as_deref(), Some("53995c3f42cd8ad8"));
            assert_eq!(trace.by_rule, decision == "?");
        }
        // A decision without a valid Root starts a new trace sampled by the rule.
        let trace = begin(Some("Root=1-bad;Sampled=1"), &never());
        assert_ne!(trace.root, "1-bad");
        assert!(valid_root(&format!("Root={}", trace.root)).is_some());
        assert!(trace.sampled && trace.by_rule && trace.caller_parent.is_none());
    }

    #[test]
    fn default_rule_is_one_per_second_per_scope_plus_five_percent() {
        let sampler = Sampler::with_draw(|| 0.99);
        assert!(sampler.sample_at("a", 100));
        assert!(!sampler.sample_at("a", 100));
        assert!(sampler.sample_at("b", 100));
        assert!(sampler.sample_at("a", 101));
        let draws = std::sync::atomic::AtomicUsize::new(0);
        let fixed = Sampler::with_draw(move || {
            let n = draws.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n.is_multiple_of(20) {
                0.01
            } else {
                0.5
            }
        });
        assert!(fixed.sample_at("a", 7));
        assert_eq!((0..100).filter(|_| fixed.sample_at("a", 7)).count(), 5);
        let default = Sampler::default();
        assert!((0..1000).all(|_| (0.0..1.0).contains(&(default.draw)())));
    }

    #[test]
    fn downstream_header_parents_on_the_call_subsegment() {
        let trace = begin(Some(&format!("Root={ROOT};Sampled=1")), &Sampler::default());
        let (header, subsegment) = trace.downstream();
        let subsegment = subsegment.unwrap();
        assert!(is_hex(&subsegment, 16) && subsegment != trace.id);
        assert_eq!(
            header.to_str().unwrap(),
            format!("Root={ROOT};Parent={subsegment};Sampled=1")
        );
        let unsampled = begin(Some(&format!("Root={ROOT};Sampled=0")), &Sampler::default());
        let (header, subsegment) = unsampled.downstream();
        assert!(subsegment.is_none());
        assert_eq!(header.to_str().unwrap(), format!("Root={ROOT};Sampled=0"));
        assert!(unsampled
            .segment(&stage(), "1", "us-east-1", "r", (&Method::GET, "u"), 200)
            .is_none());
    }

    #[test]
    fn stage_segment_matches_the_documented_shape() {
        let trace = begin(
            Some(&format!("Root={ROOT};Parent=53995c3f42cd8ad8;Sampled=1")),
            &Sampler::default(),
        );
        let (_, id) = trace.downstream();
        let id = id.unwrap();
        trace.record_lambda(
            id.clone(),
            SystemTime::now(),
            "arn:aws:lambda:us-east-1:123412341234:function:xray123",
            "us-east-1",
            CallOutcome::Status(200),
        );
        let segment = trace
            .segment(
                &stage(),
                "123412341234",
                "us-east-1",
                "req-1",
                (&Method::GET, "http://h/dev?x=1"),
                502,
            )
            .unwrap();
        assert_eq!(segment["name"], "testxray/dev");
        assert_eq!(segment["origin"], "AWS::ApiGateway::Stage");
        assert_eq!(segment["trace_id"], ROOT);
        assert_eq!(segment["parent_id"], "53995c3f42cd8ad8");
        assert_eq!(
            segment["resource_arn"],
            "arn:aws:apigateway:us-east-1::/restapis/a1b2c3d4e5/stages/dev"
        );
        assert_eq!(segment["http"]["request"]["method"], "GET");
        assert_eq!(segment["http"]["request"]["url"], "http://h/dev?x=1");
        assert_eq!(segment["http"]["response"]["status"], 502);
        assert_eq!(segment["fault"], true);
        assert!(segment.get("error").is_none());
        assert_eq!(segment["aws"]["api_gateway"]["rest_api_id"], "a1b2c3d4e5");
        assert_eq!(segment["aws"]["api_gateway"]["account_id"], "123412341234");
        assert_eq!(segment["aws"]["api_gateway"]["request_id"], "req-1");
        // Sampled by the caller, not by the stage's rule.
        assert!(segment["aws"].get("xray").is_none());
        assert_eq!(segment["annotations"]["aws:api_stage"], "dev");
        let lambda = &segment["subsegments"][0];
        assert_eq!(lambda["id"], id.as_str());
        assert_eq!(lambda["name"], "Lambda");
        assert_eq!(lambda["namespace"], "aws");
        assert_eq!(lambda["aws"]["function_name"], "xray123");
        assert_eq!(lambda["aws"]["operation"], "Invoke");
        assert_eq!(lambda["http"]["response"]["status"], 200);
        assert!(lambda.get("fault").is_none());
        assert!(lambda["end_time"].as_f64() <= segment["end_time"].as_f64());
        assert!(segment["start_time"].as_f64() <= lambda["start_time"].as_f64());

        for (status, flags) in [
            (200, vec![]),
            (403, vec!["error"]),
            (429, vec!["error", "throttle"]),
            (504, vec!["fault"]),
        ] {
            let trace = begin(None, &Sampler::default());
            let segment = trace
                .segment(&stage(), "1", "us-east-1", "r", (&Method::GET, "u"), status)
                .unwrap();
            for flag in ["error", "throttle", "fault"] {
                assert_eq!(
                    segment.get(flag).is_some(),
                    flags.contains(&flag),
                    "{status}"
                );
            }
            assert_eq!(segment["aws"]["xray"]["sampling_rule_name"], "Default");
            assert!(segment.get("parent_id").is_none());
            assert!(segment.get("subsegments").is_none());
        }
        let long = TracedStage {
            api_name: "n".repeat(300),
            ..stage()
        };
        let trace = begin(None, &Sampler::default());
        let segment = trace
            .segment(&long, "1", "us-east-1", "r", (&Method::GET, "u"), 200)
            .unwrap();
        assert_eq!(
            segment["name"].as_str().unwrap().chars().count(),
            MAX_NAME_CHARS
        );
    }

    #[test]
    fn function_names_come_from_names_and_arns() {
        for (function, name) in [
            ("f", "f"),
            ("f:live", "f"),
            ("arn:aws:lambda:us-east-1:123412341234:function:f", "f"),
            ("arn:aws:lambda:us-east-1:123412341234:function:f:3", "f"),
            ("123412341234:function:f", "f"),
        ] {
            assert_eq!(function_name(function), name);
        }
    }

    #[test]
    fn failed_calls_are_faults() {
        let trace = begin(None, &Sampler::default());
        for outcome in [CallOutcome::TimedOut, CallOutcome::Status(500)] {
            let (_, id) = trace.downstream();
            trace.record_lambda(id.unwrap(), SystemTime::now(), "f", "us-east-1", outcome);
        }
        let segment = trace
            .segment(&stage(), "1", "us-east-1", "r", (&Method::GET, "u"), 504)
            .unwrap();
        let subsegments = segment["subsegments"].as_array().unwrap();
        assert_eq!(subsegments.len(), 2);
        assert!(subsegments
            .iter()
            .all(|subsegment| subsegment["fault"] == true));
        assert!(subsegments[0]["http"].get("response").is_none());
        assert_eq!(subsegments[1]["http"]["response"]["status"], 500);
    }
}
