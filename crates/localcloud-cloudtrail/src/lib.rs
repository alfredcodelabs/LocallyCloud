//! Bounded, regional CloudTrail management event history.
//!
//! This first native slice implements LookupEvents. Trail lifecycle and delivery are explicitly
//! rejected until receivers and the full AWS contracts are available.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use localcloud_core::audit::{CompletionObserver, DispatchOutcome};
use localcloud_core::error_mapping::AwsError;
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::registry::AwsProtocol;
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

const MAX_BODY: usize = 32 * 1024;
const MAX_HISTORY_PER_SCOPE: usize = 10_000;
const MAX_TOKENS: usize = 256;
const HISTORY_AGE: Duration = Duration::from_secs(90 * 24 * 60 * 60);
const TOKEN_AGE: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
struct AuditEvent {
    id: String,
    request_id: String,
    time: SystemTime,
    account: String,
    region: String,
    name: String,
    source: String,
    error_code: Option<String>,
}

struct Page {
    scope: (String, String),
    query: String,
    events: Vec<AuditEvent>,
    offset: usize,
    expires: SystemTime,
}

#[derive(Default)]
struct State {
    history: HashMap<(String, String), VecDeque<AuditEvent>>,
    pages: HashMap<String, Page>,
}

/// The same object is installed as NativeHandler and Core CompletionObserver.
/// It never holds the ServiceRegistry, so registry ownership is acyclic.
#[derive(Default)]
pub struct CloudTrailService {
    state: Mutex<State>,
}

impl CloudTrailService {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn lookup(&self, request: &ServiceRequest, body: &Map<String, Value>) -> Result<Value, Error> {
        const FIELDS: &[&str] = &[
            "StartTime",
            "EndTime",
            "LookupAttributes",
            "MaxResults",
            "NextToken",
            "EventCategory",
        ];
        if body.keys().any(|key| !FIELDS.contains(&key.as_str())) {
            return Err(Error::new(
                "InvalidLookupAttributesException",
                "Unsupported lookup field",
            ));
        }
        if body.contains_key("EventCategory") {
            return Err(Error::new(
                "UnsupportedOperationException",
                "Insights event history is unavailable",
            ));
        }
        let max = match body.get("MaxResults") {
            None => 50,
            Some(value) => value
                .as_u64()
                .filter(|count| (1..=50).contains(count))
                .ok_or_else(|| {
                    Error::new(
                        "InvalidMaxResultsException",
                        "MaxResults must be between 1 and 50",
                    )
                })? as usize,
        };
        let start = parse_time(body.get("StartTime"))?;
        let end = parse_time(body.get("EndTime"))?;
        if start.zip(end).is_some_and(|(start, end)| start > end) {
            return Err(Error::new(
                "InvalidTimeRangeException",
                "StartTime exceeds EndTime",
            ));
        }
        let attribute = match body.get("LookupAttributes") {
            None => None,
            Some(Value::Array(items)) if items.len() == 1 => {
                let item = items[0].as_object().ok_or_else(invalid_attribute)?;
                if item.len() != 2 {
                    return Err(invalid_attribute());
                }
                let key = item
                    .get("AttributeKey")
                    .and_then(Value::as_str)
                    .ok_or_else(invalid_attribute)?;
                let value = item
                    .get("AttributeValue")
                    .and_then(Value::as_str)
                    .ok_or_else(invalid_attribute)?;
                if value.is_empty() || value.len() > 2000 {
                    return Err(invalid_attribute());
                }
                match key {
                    "EventName" | "EventSource" | "EventId" | "ReadOnly" => {
                        if key == "ReadOnly" && value != "true" && value != "false" {
                            return Err(invalid_attribute());
                        }
                        Some((key.to_string(), value.to_string()))
                    }
                    _ => {
                        return Err(Error::new(
                            "UnsupportedOperationException",
                            "Lookup attribute is unavailable",
                        ))
                    }
                }
            }
            _ => return Err(invalid_attribute()),
        };
        let mut canonical = body.clone();
        canonical.remove("NextToken");
        let query = serde_json::to_string(&canonical).map_err(|_| invalid_attribute())?;
        let scope = (request.account_id.clone(), request.region.clone());
        let now = SystemTime::now();
        let mut state = self.state.lock().map_err(|_| Error::internal())?;
        state.pages.retain(|_, page| page.expires > now);
        let (events, offset) = if let Some(token) = body.get("NextToken") {
            let token = token
                .as_str()
                .filter(|token| token.len() <= 128)
                .ok_or_else(invalid_token)?;
            let page = state.pages.get(token).ok_or_else(invalid_token)?;
            if page.scope != scope || page.query != query {
                return Err(invalid_token());
            }
            (page.events.clone(), page.offset)
        } else {
            let cutoff = now.checked_sub(HISTORY_AGE).unwrap_or(UNIX_EPOCH);
            let mut events: Vec<_> = state
                .history
                .get(&scope)
                .into_iter()
                .flatten()
                .filter(|event| event.time >= cutoff)
                .filter(|event| start.is_none_or(|time| epoch(event.time) >= time))
                .filter(|event| end.is_none_or(|time| epoch(event.time) <= time))
                .filter(|event| match attribute.as_ref() {
                    None => true,
                    Some((key, value)) => match key.as_str() {
                        "EventName" => &event.name == value,
                        "EventSource" => &event.source == value,
                        "EventId" => &event.id == value,
                        "ReadOnly" => value == "false",
                        _ => false,
                    },
                })
                .cloned()
                .collect();
            events.sort_by(|a, b| b.time.cmp(&a.time).then_with(|| b.id.cmp(&a.id)));
            (events, 0)
        };
        let end_index = offset.saturating_add(max).min(events.len());
        let rendered: Vec<Value> = events[offset..end_index].iter().map(render_event).collect();
        let mut result = json!({"Events": rendered});
        if end_index < events.len() {
            if state.pages.len() >= MAX_TOKENS {
                return Err(Error::internal());
            }
            let token = Uuid::new_v4().to_string();
            state.pages.insert(
                token.clone(),
                Page {
                    scope,
                    query,
                    events,
                    offset: end_index,
                    expires: now + TOKEN_AGE,
                },
            );
            result["NextToken"] = Value::String(token);
        }
        Ok(result)
    }
}

impl CompletionObserver for CloudTrailService {
    fn observe(&self, outcome: DispatchOutcome) {
        let Some((source, name)) = management_operation(&outcome) else {
            return;
        };
        if outcome.account_id.len() > 64 || outcome.region.len() > 64 {
            return;
        }
        let event = AuditEvent {
            id: outcome.dispatch_id,
            request_id: outcome.request_id,
            time: outcome.completed_at,
            account: outcome.account_id.clone(),
            region: outcome.region.clone(),
            name: name.to_string(),
            source: source.to_string(),
            error_code: outcome.error_code,
        };
        // A poisoned or contended observer must never alter the originating response.
        if let Ok(mut state) = self.state.lock() {
            let events = state
                .history
                .entry((outcome.account_id, outcome.region))
                .or_default();
            events.push_back(event);
            while events.len() > MAX_HISTORY_PER_SCOPE {
                events.pop_front();
            }
        }
    }
}

#[async_trait]
impl NativeHandler for CloudTrailService {
    async fn handle(&self, request: ServiceRequest) -> Response {
        if request.method != http::Method::POST {
            return Error::new("UnsupportedOperationException", "CloudTrail requires POST")
                .render(&request.request_id);
        }
        let target = request
            .headers
            .get("x-amz-target")
            .and_then(|value| value.to_str().ok());
        if target != Some("com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents") {
            return Error::new(
                "UnsupportedOperationException",
                "CloudTrail operation is unavailable",
            )
            .render(&request.request_id);
        }
        if request.body.len() > MAX_BODY {
            return Error::new(
                "InvalidLookupAttributesException",
                "Request exceeds supported size",
            )
            .render(&request.request_id);
        }
        let body = match serde_json::from_slice::<Value>(&request.body) {
            Ok(Value::Object(body)) => body,
            _ => {
                return Error::new("InvalidLookupAttributesException", "Invalid request body")
                    .render(&request.request_id)
            }
        };
        match self.lookup(&request, &body) {
            Ok(value) => Response::builder()
                .status(200)
                .header("content-type", "application/x-amz-json-1.1")
                .header("x-amzn-RequestId", request.request_id.as_str())
                .body(Body::from(value.to_string()))
                .expect("static response"),
            Err(error) => error.render(&request.request_id),
        }
    }
}

fn parse_time(value: Option<&Value>) -> Result<Option<f64>, Error> {
    match value {
        None => Ok(None),
        Some(Value::Number(number)) => number
            .as_f64()
            .filter(|value| value.is_finite() && *value >= 0.0)
            .map(Some)
            .ok_or_else(|| Error::new("InvalidTimeRangeException", "Invalid timestamp")),
        _ => Err(Error::new("InvalidTimeRangeException", "Invalid timestamp")),
    }
}

fn epoch(time: SystemTime) -> f64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

fn management_operation(outcome: &DispatchOutcome) -> Option<(&'static str, &'static str)> {
    match (outcome.service.as_str(), outcome.operation.as_str()) {
        ("sqs", "CreateQueue") => Some(("sqs.amazonaws.com", "CreateQueue")),
        ("sqs", "DeleteQueue") => Some(("sqs.amazonaws.com", "DeleteQueue")),
        ("sqs", "SetQueueAttributes") => Some(("sqs.amazonaws.com", "SetQueueAttributes")),
        ("sqs", "AddPermission") => Some(("sqs.amazonaws.com", "AddPermission")),
        ("sqs", "RemovePermission") => Some(("sqs.amazonaws.com", "RemovePermission")),
        _ => None,
    }
}

fn render_event(event: &AuditEvent) -> Value {
    let date = OffsetDateTime::from(event.time)
        .format(&Rfc3339)
        .unwrap_or_default();
    let mut detail = json!({
        "eventVersion": "1.11",
        "userIdentity": { "type": "AWSAccount", "accountId": event.account },
        "eventTime": date,
        "eventSource": event.source,
        "eventName": event.name,
        "awsRegion": event.region,
        "requestParameters": Value::Null,
        "responseElements": Value::Null,
        "requestID": event.request_id,
        "eventID": event.id,
        "eventType": "AwsApiCall",
        "recipientAccountId": event.account,
        "readOnly": false,
        "eventCategory": "Management",
    });
    if let Some(code) = &event.error_code {
        detail["errorCode"] = Value::String(code.clone());
    }
    json!({
        "EventId": event.id,
        "EventName": event.name,
        "EventSource": event.source,
        "EventTime": epoch(event.time),
        "ReadOnly": "false",
        "Resources": [],
        "CloudTrailEvent": detail.to_string(),
    })
}

#[derive(Debug)]
struct Error {
    code: &'static str,
    message: &'static str,
}
impl Error {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
    fn internal() -> Self {
        Self::new(
            "CloudTrailServiceException",
            "CloudTrail history is unavailable",
        )
    }
    fn render(self, request_id: &str) -> Response {
        let status = if self.code == "CloudTrailServiceException" {
            500
        } else {
            400
        };
        AwsError::new(self.code, self.message, status)
            .with_request_id(request_id)
            .render(AwsProtocol::Json11)
            .into_response()
    }
}
fn invalid_attribute() -> Error {
    Error::new(
        "InvalidLookupAttributesException",
        "Invalid lookup attribute",
    )
}
fn invalid_token() -> Error {
    Error::new("InvalidNextTokenException", "Invalid pagination token")
}

#[cfg(test)]
mod tests {
    use super::*;
    use localcloud_core::registry::Disposition;

    fn outcome(account: &str, region: &str, name: &str, code: Option<&str>) -> DispatchOutcome {
        DispatchOutcome {
            dispatch_id: Uuid::new_v4().to_string(),
            request_id: "request-id".into(),
            account_id: account.into(),
            region: region.into(),
            service: "sqs".into(),
            operation: name.into(),
            protocol: AwsProtocol::Json10,
            disposition: Disposition::Native,
            started_at: SystemTime::now(),
            completed_at: SystemTime::now(),
            http_status: if code.is_some() { 400 } else { 200 },
            error_code: code.map(str::to_string),
        }
    }

    fn request(account: &str, region: &str) -> ServiceRequest {
        ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: http::HeaderMap::new(),
            body: axum::body::Bytes::new(),
            region: region.into(),
            account_id: account.into(),
            request_id: "lookup-id".into(),
        }
    }

    #[test]
    fn scoped_history_and_redaction() {
        let service = CloudTrailService::new();
        service.observe(outcome("111111111111", "us-east-1", "CreateQueue", None));
        service.observe(outcome(
            "111111111111",
            "us-east-1",
            "DeleteQueue",
            Some("AccessDenied"),
        ));
        service.observe(outcome("222222222222", "us-east-1", "CreateQueue", None));
        service.observe(outcome("111111111111", "eu-west-1", "CreateQueue", None));
        service.observe(outcome("111111111111", "us-east-1", "SendMessage", None));
        let result = service
            .lookup(&request("111111111111", "us-east-1"), &Map::new())
            .unwrap();
        let events = result["Events"].as_array().unwrap();
        assert_eq!(events.len(), 2);
        let error = events
            .iter()
            .find(|event| event["EventName"] == "DeleteQueue")
            .unwrap();
        let detail: Value =
            serde_json::from_str(error["CloudTrailEvent"].as_str().unwrap()).unwrap();
        assert_eq!(detail["errorCode"], "AccessDenied");
        assert_eq!(detail["recipientAccountId"], "111111111111");
        assert!(detail.get("requestParameters").unwrap().is_null());
        assert!(detail.get("responseElements").unwrap().is_null());
        assert!(detail.to_string().len() < 2048);
    }

    #[test]
    fn filter_time_and_token_scope() {
        let service = CloudTrailService::new();
        for _ in 0..3 {
            service.observe(outcome("111111111111", "us-east-1", "CreateQueue", None));
        }
        let mut query = Map::new();
        query.insert("MaxResults".into(), json!(1));
        query.insert(
            "LookupAttributes".into(),
            json!([{"AttributeKey":"EventName","AttributeValue":"CreateQueue"}]),
        );
        let req = request("111111111111", "us-east-1");
        let first = service.lookup(&req, &query).unwrap();
        assert_eq!(first["Events"].as_array().unwrap().len(), 1);
        let token = first["NextToken"].as_str().unwrap();
        query.insert("NextToken".into(), json!(token));
        let second = service.lookup(&req, &query).unwrap();
        assert_ne!(
            first["Events"][0]["EventId"],
            second["Events"][0]["EventId"]
        );
        assert!(matches!(
            service.lookup(&request("222222222222", "us-east-1"), &query),
            Err(Error {
                code: "InvalidNextTokenException",
                ..
            })
        ));
        query.insert("MaxResults".into(), json!(2));
        assert!(matches!(
            service.lookup(&req, &query),
            Err(Error {
                code: "InvalidNextTokenException",
                ..
            })
        ));
    }

    #[test]
    fn invalid_lookup_does_not_mutate_history() {
        let service = CloudTrailService::new();
        service.observe(outcome("111111111111", "us-east-1", "CreateQueue", None));
        let request = request("111111111111", "us-east-1");
        for body in [
            json!({"MaxResults": 51}),
            json!({"StartTime": 100, "EndTime": 1}),
            json!({"LookupAttributes": [{"AttributeKey": "Username", "AttributeValue": "a"}]}),
            json!({"NextToken":"not-a-token"}),
        ] {
            assert!(service.lookup(&request, body.as_object().unwrap()).is_err());
        }
        assert_eq!(
            service.lookup(&request, &Map::new()).unwrap()["Events"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn observer_accepts_only_explicit_management_operations() {
        let service = CloudTrailService::new();
        service.observe(outcome("111111111111", "us-east-1", "SendMessage", None));
        service.observe(outcome("111111111111", "us-east-1", "ReceiveMessage", None));
        assert!(service
            .lookup(&request("111111111111", "us-east-1"), &Map::new())
            .unwrap()["Events"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}
