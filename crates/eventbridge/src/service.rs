use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use http::Method;
use serde_json::{Map, Value};

use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

use crate::error::{EventsError, PipesError, SchedulerError};
use crate::events::{EventsService, RequestContext};
use crate::http_client::{CurlHttpClient, HttpClient};
use crate::pipes::PipesService;
use crate::schedule::{Clock, SystemClock};
use crate::scheduler::SchedulerService;
use crate::store::EbStore;
use locallycloud_state::StateDb;

#[path = "classic_authorization.rs"]
mod classic_authorization;
#[path = "rest_authorization.rs"]
mod rest_authorization;

struct Services {
    registry: Weak<ServiceRegistry>,
    events: EventsService,
    scheduler: SchedulerService,
    pipes: PipesService,
}

impl Services {
    fn new(registry: Weak<ServiceRegistry>, clock: Arc<dyn Clock>) -> Self {
        Self::with_store(registry, clock, Arc::new(EbStore::new()))
    }

    fn with_store(
        registry: Weak<ServiceRegistry>,
        clock: Arc<dyn Clock>,
        store: Arc<EbStore>,
    ) -> Self {
        let http: Arc<dyn HttpClient> = Arc::new(CurlHttpClient);
        Self {
            registry: registry.clone(),
            events: EventsService::new(
                store.clone(),
                registry.clone(),
                clock.clone(),
                http.clone(),
            ),
            scheduler: SchedulerService::new(store.clone(), registry.clone(), clock),
            pipes: PipesService::new(store, registry, http),
        }
    }
}

struct EventsHandler(Arc<Services>);
struct SchedulerHandler(Arc<Services>);
struct PipesHandler(Arc<Services>);

#[async_trait]
impl NativeHandler for EventsHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let target = match request
            .headers
            .get("x-amz-target")
            .and_then(|value| value.to_str().ok())
        {
            Some(target) if target.starts_with("AWSEvents.") => target,
            _ => {
                return EventsError::UnknownOperation("missing or invalid X-Amz-Target".into())
                    .into_response(&request.request_id)
            }
        };
        let operation = target.rsplit('.').next().unwrap_or_default();
        let body = match parse_body(&request) {
            Ok(body) => body,
            Err(message) => {
                return EventsError::Validation(message).into_response(&request.request_id)
            }
        };
        if let Err(error) =
            classic_authorization::check(&self.0.registry, &request, operation, &body)
        {
            return error.into_response(&request.request_id);
        }
        // Complete the state commit even if the client disconnects mid-request.
        let services = self.0.clone();
        let operation = operation.to_string();
        let account = request.account_id.clone();
        let region = request.region.clone();
        let request_id = request.request_id.clone();
        let result = tokio::spawn(async move {
            let context = RequestContext {
                account: &account,
                region: &region,
                request_id: &request_id,
            };
            services.events.dispatch(&operation, &context, &body).await
        })
        .await;
        match result {
            Ok(Ok(value)) => json_response(value, "application/x-amz-json-1.1"),
            Ok(Err(error)) => error.into_response(&request.request_id),
            Err(_) => EventsError::Internal("EventBridge operation failed".into())
                .into_response(&request.request_id),
        }
    }
}

#[async_trait]
impl NativeHandler for SchedulerHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let (operation, path_value) = match scheduler_route(&request.method, request.uri.path()) {
            Some(route) => route,
            None => {
                return SchedulerError::ResourceNotFound("route not found".into())
                    .into_response(&request.request_id)
            }
        };
        let mut body = match parse_body(&request) {
            Ok(body) => body,
            Err(message) => {
                return SchedulerError::Validation(message).into_response(&request.request_id)
            }
        };
        merge_query(&mut body, request.uri.query());
        if rest_authorization::check(
            &self.0.registry,
            &request,
            "scheduler",
            operation,
            path_value.as_deref(),
            &body,
        )
        .is_err()
        {
            return SchedulerError::AccessDenied(
                "User is not authorized to perform this Scheduler operation".into(),
            )
            .into_response(&request.request_id);
        }
        // A disconnected client must not cancel an in-flight SQLite commit.
        let services = self.0.clone();
        let account = request.account_id.clone();
        let region = request.region.clone();
        let result = tokio::spawn(async move {
            services
                .scheduler
                .dispatch(operation, path_value.as_deref(), &account, &region, &body)
                .await
        })
        .await;
        match result {
            Ok(Ok(value)) => json_response(value, "application/json"),
            Ok(Err(error)) => error.into_response(&request.request_id),
            Err(_) => SchedulerError::Internal("Scheduler operation failed".into())
                .into_response(&request.request_id),
        }
    }
}

#[async_trait]
impl NativeHandler for PipesHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let (operation, path_value) = match pipes_route(&request.method, request.uri.path()) {
            Some(route) => route,
            None => {
                return PipesError::NotFound("route not found".into())
                    .into_response(&request.request_id)
            }
        };
        let mut body = match parse_body(&request) {
            Ok(body) => body,
            Err(message) => {
                return PipesError::Validation(message).into_response(&request.request_id)
            }
        };
        merge_query(&mut body, request.uri.query());
        if rest_authorization::check(
            &self.0.registry,
            &request,
            "pipes",
            operation,
            path_value.as_deref(),
            &body,
        )
        .is_err()
        {
            return PipesError::AccessDenied(
                "User is not authorized to perform this Pipes operation".into(),
            )
            .into_response(&request.request_id);
        }
        match self
            .0
            .pipes
            .dispatch(
                operation,
                path_value.as_deref(),
                &request.account_id,
                &request.region,
                &body,
            )
            .await
        {
            Ok(value) => json_response(value, "application/json"),
            Err(error) => error.into_response(&request.request_id),
        }
    }
}

fn parse_body(request: &ServiceRequest) -> Result<Value, String> {
    if request.body.is_empty() {
        Ok(Value::Object(Map::new()))
    } else {
        let body: Value = serde_json::from_slice(&request.body)
            .map_err(|error| format!("invalid JSON body: {error}"))?;
        if body.is_object() {
            Ok(body)
        } else {
            Err("request body must be a JSON object".into())
        }
    }
}
fn json_response(value: Value, content_type: &str) -> Response {
    http::Response::builder()
        .status(200)
        .header("content-type", content_type)
        .body(Body::from(value.to_string()))
        .expect("valid response")
}
fn scheduler_route(method: &Method, path: &str) -> Option<(&'static str, Option<String>)> {
    if path == "/schedules" && method == Method::GET {
        return Some(("ListSchedules", None));
    }
    if let Some(name) = path.strip_prefix("/schedules/") {
        let operation = match *method {
            Method::POST => "CreateSchedule",
            Method::GET => "GetSchedule",
            Method::PUT => "UpdateSchedule",
            Method::DELETE => "DeleteSchedule",
            _ => return None,
        };
        return Some((operation, Some(percent_decode_path(name))));
    }
    if path == "/schedule-groups" && method == Method::GET {
        return Some(("ListScheduleGroups", None));
    }
    if let Some(name) = path.strip_prefix("/schedule-groups/") {
        let operation = match *method {
            Method::POST => "CreateScheduleGroup",
            Method::GET => "GetScheduleGroup",
            Method::DELETE => "DeleteScheduleGroup",
            _ => return None,
        };
        return Some((operation, Some(percent_decode_path(name))));
    }
    if let Some(arn) = path.strip_prefix("/tags/") {
        let operation = match *method {
            Method::POST => "TagResource",
            Method::DELETE => "UntagResource",
            Method::GET => "ListTagsForResource",
            _ => return None,
        };
        return Some((operation, Some(percent_decode_path(arn))));
    }
    None
}

fn pipes_route(method: &Method, path: &str) -> Option<(&'static str, Option<String>)> {
    if path == "/v1/pipes" && method == Method::GET {
        return Some(("ListPipes", None));
    }
    if let Some(rest) = path.strip_prefix("/v1/pipes/") {
        if let Some(name) = rest.strip_suffix("/start") {
            return (method == Method::POST)
                .then(|| ("StartPipe", Some(percent_decode_path(name))));
        }
        if let Some(name) = rest.strip_suffix("/stop") {
            return (method == Method::POST).then(|| ("StopPipe", Some(percent_decode_path(name))));
        }
        let operation = match *method {
            Method::POST => "CreatePipe",
            Method::GET => "DescribePipe",
            Method::PUT => "UpdatePipe",
            Method::DELETE => "DeletePipe",
            _ => return None,
        };
        return Some((operation, Some(percent_decode_path(rest))));
    }
    if let Some(arn) = path.strip_prefix("/tags/") {
        let operation = match *method {
            Method::POST => "TagResource",
            Method::DELETE => "UntagResource",
            Method::GET => "ListTagsForResource",
            _ => return None,
        };
        return Some((operation, Some(percent_decode_path(arn))));
    }
    None
}

fn merge_query(body: &mut Value, query: Option<&str>) {
    let Some(map) = body.as_object_mut() else {
        return;
    };
    for pair in query
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode_query(key);
        let Some(member) = query_member_name(&key) else {
            continue;
        };
        let value = Value::String(percent_decode_query(value));
        if key == "tagKeys" {
            match map
                .entry(member)
                .or_insert_with(|| Value::Array(Vec::new()))
            {
                Value::Array(values) => values.push(value),
                existing => {
                    let first = std::mem::replace(existing, Value::Null);
                    *existing = Value::Array(vec![first, value]);
                }
            }
            continue;
        }
        match map.get_mut(&member) {
            None => {
                map.insert(member, value);
            }
            Some(Value::Array(values)) => values.push(value),
            Some(existing) => {
                let first = std::mem::replace(existing, Value::Null);
                *existing = Value::Array(vec![first, value]);
            }
        }
    }
}

fn query_member_name(key: &str) -> Option<String> {
    let mut chars = key.chars();
    let first = chars.next()?;
    if !first.is_ascii_lowercase() {
        return None;
    }
    Some(first.to_ascii_uppercase().to_string() + chars.as_str())
}

fn percent_decode_path(value: &str) -> String {
    percent_decode(value, false)
}

fn percent_decode_query(value: &str) -> String {
    percent_decode(value, true)
}

fn percent_decode(value: &str, plus_as_space: bool) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                output.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        output.push(if plus_as_space && bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod query_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn query_uses_lower_camel_names_and_merges_repeated_values() {
        let mut body = json!({});
        merge_query(
            &mut body,
            Some("nextToken=a+b&maxResults=10&tagKeys=one&tagKeys=two&NextToken=ignored"),
        );
        assert_eq!(body["NextToken"], "a b");
        assert_eq!(body["MaxResults"], "10");
        assert_eq!(body["TagKeys"], json!(["one", "two"]));
    }

    #[test]
    fn path_decoding_preserves_plus_while_decoding_percent_escapes() {
        let (_, name) = scheduler_route(&Method::GET, "/schedules/a+b%2Bc").unwrap();
        assert_eq!(name.as_deref(), Some("a+b+c"));
    }
}

pub fn register(registry: &Arc<ServiceRegistry>) {
    register_with_clock(registry, Arc::new(SystemClock));
}
pub fn register_with_clock(registry: &Arc<ServiceRegistry>, clock: Arc<dyn Clock>) {
    if registry.internal_dispatcher().is_none() {
        let dispatcher = Arc::new(InternalDispatcher::new_shared(
            registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        ));
        registry.set_internal_dispatcher(dispatcher);
    }
    let services = Arc::new(Services::new(Arc::downgrade(registry), clock));
    registry.register_native(
        ServiceName::new("events"),
        ServiceMetadata::new(AwsProtocol::Json11, Some("AWSEvents")),
        Arc::new(EventsHandler(services.clone())),
    );
    registry.register_native(
        ServiceName::new("scheduler"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        Arc::new(SchedulerHandler(services.clone())),
    );
    registry.register_native(
        ServiceName::new("pipes"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        Arc::new(PipesHandler(services)),
    );
}
pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    state: Arc<StateDb>,
) -> Result<(), String> {
    if registry.internal_dispatcher().is_none() {
        let dispatcher = Arc::new(InternalDispatcher::new_shared(
            registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        ));
        registry.set_internal_dispatcher(dispatcher);
    }
    let store = Arc::new(EbStore::with_state(state)?);
    let services = Arc::new(Services::with_store(
        Arc::downgrade(registry),
        Arc::new(SystemClock),
        store,
    ));
    services.pipes.restore()?;
    registry.register_native(
        ServiceName::new("events"),
        ServiceMetadata::new(AwsProtocol::Json11, Some("AWSEvents")),
        Arc::new(EventsHandler(services.clone())),
    );
    registry.register_native(
        ServiceName::new("scheduler"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        Arc::new(SchedulerHandler(services.clone())),
    );
    registry.register_native(
        ServiceName::new("pipes"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        Arc::new(PipesHandler(services.clone())),
    );
    tokio::spawn(async move {
        services.events.resume_scheduled_rules().await;
        services.events.resume_replays().await;
        services.scheduler.resume_schedules().await;
        services.pipes.resume_workers().await;
        let notify = services.events.store.pending_notify();
        let mut delay = Duration::from_secs(1);
        loop {
            if services.events.resume_pending().await {
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(Duration::from_secs(60));
            } else {
                delay = Duration::from_secs(1);
                notify.notified().await;
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue};
    use locallycloud_core::registry::Disposition;
    use serde_json::json;
    fn request(method: Method, path: &str, body: Value) -> ServiceRequest {
        ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from(body.to_string()),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "r".into(),
        }
    }
    async fn body(response: Response) -> (u16, Value) {
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    fn json_request(prefix: &str, operation: &str, payload: Value) -> ServiceRequest {
        let mut request = request(Method::POST, "/", payload);
        request.headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("{prefix}.{operation}")).unwrap(),
        );
        request
    }
    async fn events(handler: &Arc<dyn NativeHandler>, operation: &str, payload: Value) -> Value {
        let (status, value) = body(
            handler
                .handle(json_request("AWSEvents", operation, payload))
                .await,
        )
        .await;
        assert_eq!(status, 200, "{operation}: {value}");
        value
    }
    #[test]
    fn registers_all_three_native() {
        let registry = ServiceRegistry::with_known_services();
        register(&registry);
        for service in ["events", "scheduler", "pipes"] {
            assert_eq!(
                registry.disposition(&ServiceName::new(service)),
                Disposition::Native
            );
        }
    }
    #[tokio::test]
    async fn scheduler_and_pipes_rest_routes_round_trip() {
        let registry = ServiceRegistry::with_known_services();
        register(&registry);
        let scheduler = registry
            .native_handler(&ServiceName::new("scheduler"))
            .unwrap();
        let response = scheduler
            .handle(request(Method::POST, "/schedule-groups/team", json!({})))
            .await;
        assert_eq!(body(response).await.0, 200);
        let pipes = registry.native_handler(&ServiceName::new("pipes")).unwrap();
        let response=pipes.handle(request(Method::POST,"/v1/pipes/p",json!({"Source":"arn:aws:sqs:us-east-1:000000000000:q","Target":"arn:aws:sqs:us-east-1:000000000000:o","RoleArn":"arn:aws:iam::000000000000:role/r","DesiredState":"STOPPED"}))).await;
        let (status, value) = body(response).await;
        assert_eq!(status, 200, "{value}");
        assert_eq!(value["CurrentState"], "CREATING");
        let arn = value["Arn"].as_str().unwrap();
        let (_, tagged) = body(
            pipes
                .handle(request(
                    Method::POST,
                    &format!("/tags/{arn}"),
                    json!({"tags":{"wire":"lowercase"}}),
                ))
                .await,
        )
        .await;
        assert_eq!(tagged, json!({}));
        let (_, tags) = body(
            pipes
                .handle(request(Method::GET, &format!("/tags/{arn}"), json!({})))
                .await,
        )
        .await;
        assert_eq!(tags["tags"]["wire"], "lowercase");
        tokio::time::sleep(Duration::from_millis(10)).await;
        let response = pipes
            .handle(request(Method::GET, "/v1/pipes/p", json!({})))
            .await;
        let (_, value) = body(response).await;
        assert_eq!(value["CurrentState"], "STOPPED");
        let (_, started) = body(
            pipes
                .handle(request(Method::POST, "/v1/pipes/p/start", json!({})))
                .await,
        )
        .await;
        assert_eq!(started["CurrentState"], "STARTING");
        let (_, stopping) = body(
            pipes
                .handle(request(Method::POST, "/v1/pipes/p/stop", json!({})))
                .await,
        )
        .await;
        assert_eq!(stopping["CurrentState"], "STOPPING");
        tokio::time::sleep(Duration::from_millis(10)).await;
        let (_, stopped) = body(
            pipes
                .handle(request(Method::GET, "/v1/pipes/p", json!({})))
                .await,
        )
        .await;
        assert_eq!(stopped["DesiredState"], "STOPPED");
        assert_eq!(stopped["CurrentState"], "STOPPED");
    }
    #[tokio::test]
    async fn matching_event_reaches_real_sqs_through_internal_dispatcher() {
        let registry = ServiceRegistry::with_known_services();
        locallycloud_sqs::register(&registry);
        register(&registry);
        let eventbridge = registry
            .native_handler(&ServiceName::new("events"))
            .unwrap();
        let sqs = registry.native_handler(&ServiceName::new("sqs")).unwrap();
        let create = sqs
            .handle(json_request(
                "AmazonSQS",
                "CreateQueue",
                json!({"QueueName":"eventbridge-compat"}),
            ))
            .await;
        assert_eq!(create.status(), 200);
        events(
            &eventbridge,
            "PutRule",
            json!({"Name":"orders","EventPattern":"{\"source\":[\"app.orders\"]}"}),
        )
        .await;
        events(
            &eventbridge,
            "PutTargets",
            json!({"Rule":"orders","Targets":[{"Id":"queue","Arn":"arn:aws:sqs:us-east-1:000000000000:eventbridge-compat"}]}),
        )
        .await;
        events(
            &eventbridge,
            "PutEvents",
            json!({"Entries":[{"Source":"app.orders","DetailType":"Created","Detail":"{\"id\":7}"}]}),
        )
        .await;
        let (_, received) = body(
            sqs.handle(json_request(
                "AmazonSQS",
                "ReceiveMessage",
                json!({"QueueUrl":"https://sqs.us-east-1.amazonaws.com/000000000000/eventbridge-compat"}),
            ))
            .await,
        )
        .await;
        let envelope: Value =
            serde_json::from_str(received["Messages"][0]["Body"].as_str().unwrap()).unwrap();
        assert_eq!(envelope["source"], "app.orders");
        assert_eq!(envelope["detail"]["id"], 7);
    }

    #[tokio::test]
    async fn configured_s3_put_object_routes_through_real_eventbridge() {
        let registry = ServiceRegistry::with_known_services();
        locallycloud_sqs::register(&registry);
        register(&registry);
        locallycloud_s3::register(&registry);
        let eventbridge = registry
            .native_handler(&ServiceName::new("events"))
            .unwrap();
        let sqs = registry.native_handler(&ServiceName::new("sqs")).unwrap();
        let s3 = registry.native_handler(&ServiceName::new("s3")).unwrap();

        let create = sqs
            .handle(json_request(
                "AmazonSQS",
                "CreateQueue",
                json!({"QueueName":"s3-events"}),
            ))
            .await;
        assert_eq!(create.status(), 200);
        events(
            &eventbridge,
            "PutRule",
            json!({"Name":"s3","EventPattern":"{\"source\":[\"aws.s3\"]}"}),
        )
        .await;
        events(
            &eventbridge,
            "PutTargets",
            json!({"Rule":"s3","Targets":[{"Id":"queue","Arn":"arn:aws:sqs:us-east-1:000000000000:s3-events"}]}),
        )
        .await;

        let s3_request = |method: Method, path: &str, body: &str| {
            let mut request = request(method, path, Value::Null);
            request.body = Bytes::from(body.to_string());
            request
                .headers
                .insert("host", HeaderValue::from_static("localhost:4566"));
            request
        };
        assert_eq!(
            s3.handle(s3_request(Method::PUT, "/bucket", ""))
                .await
                .status(),
            200
        );
        let notification =
            "<NotificationConfiguration><EventBridgeConfiguration/></NotificationConfiguration>";
        assert_eq!(
            s3.handle(s3_request(
                Method::PUT,
                "/bucket?notification",
                notification,
            ))
            .await
            .status(),
            200
        );
        assert_eq!(
            s3.handle(s3_request(Method::PUT, "/bucket/key.txt", "payload"))
                .await
                .status(),
            200
        );

        let received = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let (_, received) = body(
                    sqs.handle(json_request(
                        "AmazonSQS",
                        "ReceiveMessage",
                        json!({"QueueUrl":"https://sqs.us-east-1.amazonaws.com/000000000000/s3-events"}),
                    ))
                    .await,
                )
                .await;
                if received["Messages"].as_array().is_some_and(|messages| !messages.is_empty()) {
                    break received;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("S3 notification did not reach SQS");
        let envelope: Value =
            serde_json::from_str(received["Messages"][0]["Body"].as_str().unwrap()).unwrap();
        assert_eq!(envelope["source"], "aws.s3");
        assert_eq!(envelope["detail-type"], "Object Created");
        assert_eq!(envelope["detail"]["bucket"]["name"], "bucket");
        assert_eq!(envelope["detail"]["object"]["key"], "key.txt");
    }

    #[tokio::test]
    async fn events_requires_json11_target() {
        let registry = ServiceRegistry::with_known_services();
        register(&registry);
        let events = registry
            .native_handler(&ServiceName::new("events"))
            .unwrap();
        let mut request = request(Method::POST, "/", json!({}));
        request
            .headers
            .insert("x-amz-target", HeaderValue::from_static("Wrong.ListRules"));
        let (response_status, value) = body(events.handle(request).await).await;
        assert_eq!(response_status, 400);
        assert_eq!(value["__type"], "UnknownOperationException");
    }
}
