use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{
    AwsProtocol, Disposition, ServiceMetadata, ServiceName, ServiceRegistry,
};
use proptest::prelude::*;
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

use crate::pattern;
use crate::schedule;
use crate::transform::{self, Context, InputMode};

const ACCOUNT: &str = "000000000000";
const REGION: &str = "us-east-1";

fn request(method: Method, path: &str, body: Value) -> ServiceRequest {
    ServiceRequest {
        method,
        uri: path.parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::from(body.to_string()),
        region: REGION.into(),
        account_id: ACCOUNT.into(),
        request_id: "property".into(),
    }
}

fn json_request(prefix: &str, operation: &str, body: Value) -> ServiceRequest {
    let mut request = request(Method::POST, "/", body);
    request.headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("{prefix}.{operation}")).unwrap(),
    );
    request
}
fn event_request(operation: &str, body: Value) -> ServiceRequest {
    json_request("AWSEvents", operation, body)
}

fn sqs_request(operation: &str, body: Value) -> ServiceRequest {
    json_request("AmazonSQS", operation, body)
}

async fn response_parts(response: Response) -> (u16, HeaderMap, Value) {
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, headers, body)
}

async fn call_ok(handler: &Arc<dyn NativeHandler>, request: ServiceRequest) -> Value {
    let (status, _, body) = response_parts(handler.handle(request).await).await;
    assert!((200..300).contains(&status), "status={status}, body={body}");
    body
}

fn tags_array(tags: &BTreeMap<String, String>) -> Value {
    Value::Array(
        tags.iter()
            .map(|(key, value)| json!({"Key":key,"Value":value}))
            .collect(),
    )
}

fn listed_tags(value: &Value) -> BTreeMap<String, String> {
    value["Tags"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|tag| {
            Some((
                tag.get("Key")?.as_str()?.to_string(),
                tag.get("Value")?.as_str()?.to_string(),
            ))
        })
        .collect()
}

fn json_response(status: u16, value: Value) -> Response {
    http::Response::builder()
        .status(status)
        .body(Body::from(value.to_string()))
        .unwrap()
}

fn generated_error_response(service: &str, index: usize) -> (&'static str, u16, Response) {
    match service {
        "events" => {
            use crate::error::EventsError;
            let error = match index % 8 {
                0 => EventsError::ResourceNotFound("generated".into()),
                1 => EventsError::ResourceAlreadyExists("generated".into()),
                2 => EventsError::InvalidEventPattern("generated".into()),
                3 => EventsError::Validation("generated".into()),
                4 => EventsError::ConcurrentModification("generated".into()),
                5 => EventsError::LimitExceeded("generated".into()),
                6 => EventsError::UnknownOperation("generated".into()),
                _ => EventsError::Internal("generated".into()),
            };
            (
                error.code(),
                error.http_status(),
                error.into_response("property"),
            )
        }
        "scheduler" => {
            use crate::error::SchedulerError;
            let error = match index % 6 {
                0 => SchedulerError::ResourceNotFound("generated".into()),
                1 => SchedulerError::Conflict("generated".into()),
                2 => SchedulerError::Validation("generated".into()),
                3 => SchedulerError::ServiceQuotaExceeded("generated".into()),
                4 => SchedulerError::Throttling("generated".into()),
                _ => SchedulerError::Internal("generated".into()),
            };
            (
                error.code(),
                error.http_status(),
                error.into_response("property"),
            )
        }
        _ => {
            use crate::error::PipesError;
            let error = match index % 6 {
                0 => PipesError::NotFound("generated".into()),
                1 => PipesError::Conflict("generated".into()),
                2 => PipesError::Validation("generated".into()),
                3 => PipesError::ServiceQuotaExceeded("generated".into()),
                4 => PipesError::Throttling("generated".into()),
                _ => PipesError::Internal("generated".into()),
            };
            (
                error.code(),
                error.http_status(),
                error.into_response("property"),
            )
        }
    }
}
struct SqsPipeRecorder {
    message: Mutex<Option<Value>>,
    calls: Mutex<Vec<String>>,
}

impl SqsPipeRecorder {
    fn new(message: Value) -> Self {
        Self {
            message: Mutex::new(Some(message)),
            calls: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl NativeHandler for SqsPipeRecorder {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let target = request
            .headers
            .get("x-amz-target")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let operation = target.rsplit('.').next().unwrap_or_default().to_string();
        self.calls.lock().unwrap().push(operation.clone());
        match operation.as_str() {
            "ReceiveMessage" => {
                let message = self.message.lock().unwrap().take();
                json_response(
                    200,
                    message.map_or_else(
                        || json!({}),
                        |body| {
                            json!({"Messages":[{
                                "Body":body.to_string(),
                                "MessageId":"message-1",
                                "ReceiptHandle":"receipt-1"
                            }]})
                        },
                    ),
                )
            }
            "DeleteMessage" => json_response(200, json!({})),
            _ => json_response(400, json!({"message":"unexpected SQS operation"})),
        }
    }
}

struct LambdaRecorder {
    enriched: Value,
    calls: Mutex<Vec<(String, Value)>>,
}

#[async_trait::async_trait]
impl NativeHandler for LambdaRecorder {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let mode = request
            .headers
            .get("x-amz-invocation-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = serde_json::from_slice(&request.body).unwrap();
        self.calls.lock().unwrap().push((mode.clone(), body));
        if mode == "RequestResponse" {
            json_response(200, self.enriched.clone())
        } else {
            json_response(202, json!({}))
        }
    }
}

struct RecordingClock {
    now: Mutex<OffsetDateTime>,
    sleeps: Mutex<Vec<OffsetDateTime>>,
}

impl RecordingClock {
    fn new(now: OffsetDateTime) -> Self {
        Self {
            now: Mutex::new(now),
            sleeps: Mutex::new(Vec::new()),
        }
    }
}

impl schedule::Clock for RecordingClock {
    fn now(&self) -> OffsetDateTime {
        *self.now.lock().unwrap()
    }

    fn sleep_until<'a>(
        &'a self,
        due: OffsetDateTime,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.sleeps.lock().unwrap().push(due);
            *self.now.lock().unwrap() = due;
            tokio::task::yield_now().await;
        })
    }
}

async fn queue_message_count(sqs: &Arc<dyn NativeHandler>, queue: &str) -> usize {
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    let received = call_ok(
        sqs,
        sqs_request(
            "ReceiveMessage",
            json!({
                "QueueUrl":format!("https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/{queue}"),
                "MaxNumberOfMessages":10
            }),
        ),
    )
    .await;
    received["Messages"].as_array().map_or(0, Vec::len)
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    // Property 1: Native Dispatch, No Proxy.
    // Property 2: Protocol Consistency.
    // Property 3: Error Deserialization.
    #[test]
    fn properties_1_2_3_native_dispatch_and_protocol_errors(
        service_index in 0usize..3,
        error_index in 0usize..24,
        missing in "[a-z]{1,12}",
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        runtime.block_on(async move {
            let registry = ServiceRegistry::with_known_services();
            crate::register(&registry);
            let service = ["events", "scheduler", "pipes"][service_index];
            let name = ServiceName::new(service);
            prop_assert_eq!(registry.disposition(&name), Disposition::Native);
            let handler = registry.native_handler(&name).unwrap();
            let response = match service {
                "events" => handler.handle(event_request(&missing, json!({}))).await,
                "scheduler" => handler.handle(request(Method::GET, &format!("/missing/{missing}"), json!({}))).await,
                _ => handler.handle(request(Method::GET, &format!("/missing/{missing}"), json!({}))).await,
            };
            let (status, headers, body) = response_parts(response).await;
            prop_assert!(status >= 400);
            prop_assert!(body.is_object());
            if service == "events" {
                prop_assert_eq!(headers["content-type"].to_str().unwrap(), "application/x-amz-json-1.1");
                prop_assert!(body["__type"].as_str().is_some());
                prop_assert!(body.get("message").is_some());
                prop_assert!(headers.get("x-amzn-errortype").is_none());
            } else {
                prop_assert_eq!(headers["content-type"].to_str().unwrap(), "application/json");
                prop_assert!(headers.get("x-amzn-errortype").is_some());
                prop_assert!(body["message"].as_str().is_some());
                prop_assert!(body.get("__type").is_none());
            }

            let (code, expected_status, generated) =
                generated_error_response(service, error_index);
            let (status, headers, body) = response_parts(generated).await;
            prop_assert_eq!(status, expected_status);
            prop_assert!(body["message"].as_str().is_some());
            if service == "events" {
                prop_assert_eq!(body["__type"].as_str(), Some(code));
                prop_assert_eq!(headers["content-type"].to_str().unwrap(), "application/x-amz-json-1.1");
                prop_assert!(headers.get("x-amzn-errortype").is_none());
            } else {
                prop_assert_eq!(headers["x-amzn-errortype"].to_str().unwrap(), code);
                prop_assert_eq!(headers["content-type"].to_str().unwrap(), "application/json");
                prop_assert!(body.get("__type").is_none());
            }
            Ok(())
        })?;
    }
    // Property 5: Pattern Correctness.
    // Property 6: Pattern Determinism.
    // Property 7: Operator Composition.
    // Property 10: Transformer Determinism.
    #[test]
    fn properties_5_6_7_10_pattern_and_transform_are_compositional(
        wanted in "[a-z]{1,8}",
        alternate in "[a-z]{1,8}",
        actual in "[a-z]{1,8}",
        expected_presence in any::<bool>(),
        actual_presence in any::<bool>(),
        labels_match in any::<bool>(),
        low in -100i64..100,
        width in 0i64..100,
        number in -150i64..250,
        transformed in "[A-Za-z0-9 ]{0,24}",
    ) {
        let high = low + width;
        let compiled = pattern::compile(&json!({
            "source":[wanted.clone(), alternate.clone()],
            "detail":{
                "number":[{"numeric":[">=",low,"<=",high]}],
                "optional":[{"exists":expected_presence}],
                "labels":[wanted.clone(), alternate.clone()]
            }
        })).unwrap();
        let label = if labels_match {
            wanted.clone()
        } else {
            "not-present".into()
        };
        let mut detail = json!({"number":number,"labels":[label]});
        if actual_presence {
            detail["optional"] = json!("present");
        }
        let event = json!({"source":actual,"detail":detail});
        let expected = (event["source"] == wanted || event["source"] == alternate)
            && (low..=high).contains(&number)
            && expected_presence == actual_presence
            && labels_match;
        let first = pattern::matches(&compiled, &event);
        prop_assert_eq!(first, expected);
        prop_assert_eq!(pattern::matches(&compiled, &event), first);

        let or_pattern = pattern::compile(&json!({"$or":[
            {"source":[wanted]}, {"source":[alternate]}
        ]})).unwrap();
        prop_assert_eq!(
            pattern::matches(&or_pattern, &event),
            event["source"] == wanted || event["source"] == alternate,
        );

        let transform_event = json!({"detail":{"value":transformed}});
        let mode = InputMode::Transformer {
            paths: BTreeMap::from([("value".into(), "$.detail.value".into())]),
            template: "<value>|<undefined>".into(),
        };
        let context = Context {
            rule_arn:"arn", rule_name:"rule", event_json:"{}", ingestion_time:"time"
        };
        let output = transform::apply(&mode, &transform_event, &context);
        prop_assert_eq!(transform::apply(&mode, &transform_event, &context), output.clone());
        prop_assert!(output.ends_with('|'));
    }
    // Property 4: Detail Preservation.
    // Property 8: Test-Dispatch Parity.
    // Property 9: Fanout Correctness.
    // Property 11: Single Transformation.
    // Property 12: Target-Set Consistency.
    // Property 14: EventBridge Tag Round-Trip.
    #[test]
    fn properties_4_8_9_11_12_14_events_handlers(
        source in "[a-z]{1,10}",
        matches_dispatch in any::<bool>(),
        detail in prop::collection::btree_map("[a-z]{1,6}", any::<i32>(), 0..8),
        target_flags in prop::collection::btree_map("t[0-9]{1,2}", any::<bool>(), 1..8),
        supplied_tags in prop::collection::btree_map("k[a-z]{1,5}", "[A-Za-z0-9]{0,8}", 0..8),
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        runtime.block_on(async move {
            let registry = ServiceRegistry::with_known_services();
            locallycloud_sqs::register(&registry);
            crate::register(&registry);
            let events = registry.native_handler(&ServiceName::new("events")).unwrap();
            let sqs = registry.native_handler(&ServiceName::new("sqs")).unwrap();
            for queue in ["enabled", "constant", "disabled", "nonmatching"] {
                let create = sqs
                    .handle(sqs_request("CreateQueue", json!({"QueueName":queue})))
                    .await;
                prop_assert!(create.status().is_success());
            }
            let pattern_text = json!({"source":[source.clone()]}).to_string();
            for (name, state, pattern, queue) in [
                ("enabled", "ENABLED", pattern_text.clone(), "enabled"),
                ("disabled", "DISABLED", pattern_text.clone(), "disabled"),
                ("nonmatching", "ENABLED", json!({"source":["never.matches"]}).to_string(), "nonmatching"),
            ] {
                call_ok(&events, event_request("PutRule", json!({
                    "Name":name,"State":state,"EventPattern":pattern
                }))).await;
                call_ok(&events, event_request("PutTargets", json!({
                    "Rule":name,"Targets":[{"Id":"queue","Arn":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:{queue}")}]
                }))).await;
            }
            let constant_payload = json!({"constant":source}).to_string();
            call_ok(&events, event_request("PutTargets", json!({
                "Rule":"enabled","Targets":[{
                    "Id":"constant","Arn":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:constant"),
                    "Input":constant_payload
                }]
            }))).await;
            let emitted_source = if matches_dispatch {
                source.clone()
            } else {
                format!("x{source}")
            };
            let canonical = json!({
                "source":emitted_source,
                "detail-type":"Generated",
                "detail":detail
            });
            let tested = call_ok(&events, event_request("TestEventPattern", json!({
                "EventPattern":pattern_text,"Event":canonical.to_string()
            }))).await;
            prop_assert_eq!(tested["Result"].as_bool(), Some(matches_dispatch));
            let put = call_ok(&events, event_request("PutEvents", json!({"Entries":[{
                "Source":emitted_source,"DetailType":"Generated","Detail":json!(detail).to_string()
            }]}))).await;
            prop_assert_eq!(put["FailedEntryCount"].as_u64(), Some(0));
            for (queue, should_receive) in [
                ("enabled", matches_dispatch),
                ("constant", matches_dispatch),
                ("disabled", false),
                ("nonmatching", false),
            ] {
                let received = call_ok(&sqs, sqs_request("ReceiveMessage", json!({
                    "QueueUrl":format!("https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/{queue}"),
                    "MaxNumberOfMessages":10
                }))).await;
                let messages = received["Messages"].as_array().map_or(0, Vec::len);
                prop_assert_eq!(messages, usize::from(should_receive));
                if should_receive {
                    let payload: Value = serde_json::from_str(
                        received["Messages"][0]["Body"].as_str().unwrap()
                    ).unwrap();
                    if queue == "enabled" {
                        prop_assert_eq!(&payload["detail"], &json!(detail));
                    } else {
                        prop_assert_eq!(payload, json!({"constant":source}));
                    }
                }
            }

            let bad = events.handle(event_request("PutTargets", json!({
                "Rule":"enabled","Targets":[{
                    "Id":"bad","Arn":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:enabled"),
                    "Input":"{}","InputPath":"$.detail"
                }]
            }))).await;
            let (status, _, error) = response_parts(bad).await;
            prop_assert_eq!(status, 400);
            prop_assert_eq!(error["__type"].as_str(), Some("ValidationException"));

            let targets: Vec<_> = target_flags.keys().map(|id| json!({
                "Id":id,"Arn":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:{id}")
            })).collect();
            call_ok(&events, event_request("PutTargets", json!({
                "Rule":"enabled","Targets":targets
            }))).await;
            let removed: Vec<_> = target_flags.iter()
                .filter(|(_, remove)| **remove)
                .map(|(id, _)| Value::String(id.clone())).collect();
            call_ok(&events, event_request("RemoveTargets", json!({
                "Rule":"enabled","Ids":removed
            }))).await;
            let listed = call_ok(&events, event_request("ListTargetsByRule", json!({
                "Rule":"enabled"
            }))).await;
            let listed_ids: BTreeSet<_> = listed["Targets"].as_array().unwrap().iter()
                .filter_map(|target| target["Id"].as_str()).collect();
            let expected_ids: BTreeSet<_> = target_flags.iter()
                .filter(|(_, remove)| !**remove).map(|(id, _)| id.as_str())
                .chain(["queue", "constant"]).collect();
            prop_assert_eq!(listed_ids, expected_ids);
            let bus = call_ok(&events, event_request("CreateEventBus", json!({
                "Name":"tagged-bus"
            }))).await;
            let resources = [
                bus["EventBusArn"].as_str().unwrap().to_string(),
                format!("arn:aws:events:{REGION}:{ACCOUNT}:rule/enabled"),
            ];
            for arn in resources {
                call_ok(&events, event_request("TagResource", json!({
                    "ResourceARN":arn,"Tags":tags_array(&supplied_tags)
                }))).await;
                let listed = call_ok(&events, event_request("ListTagsForResource", json!({
                    "ResourceARN":arn
                }))).await;
                let actual = listed_tags(&listed);
                for (key, value) in &supplied_tags {
                    prop_assert_eq!(actual.get(key), Some(value));
                }
            }
            Ok(())
        })?;
    }

    // Property 13: Replay Range.
    #[test]
    fn property_13_replay_range_is_inclusive(
        offsets in prop::collection::btree_set(-20i64..=20, 0..9),
        bound_a in -20i64..=20,
        bound_b in -20i64..=20,
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        runtime.block_on(async move {
            let registry = ServiceRegistry::with_known_services();
            locallycloud_sqs::register(&registry);
            crate::register(&registry);
            let events = registry.native_handler(&ServiceName::new("events")).unwrap();
            let sqs = registry.native_handler(&ServiceName::new("sqs")).unwrap();
            call_ok(&sqs, sqs_request("CreateQueue", json!({"QueueName":"replayed"}))).await;
            let bus_arn = format!("arn:aws:events:{REGION}:{ACCOUNT}:event-bus/default");
            let archive = call_ok(&events, event_request("CreateArchive", json!({
                "ArchiveName":"generated","EventSourceArn":bus_arn,"RetentionDays":0
            }))).await;
            let base = 1_700_000_000i64;
            for offset in &offsets {
                call_ok(&events, event_request("PutEvents", json!({"Entries":[{
                    "Source":"replay.source","DetailType":"Generated",
                    "Detail":json!({"offset":offset}).to_string(),"Time":base + offset
                }]}))).await;
            }
            call_ok(&events, event_request("PutRule", json!({
                "Name":"replay-rule","EventPattern":"{\"source\":[\"replay.source\"]}"
            }))).await;
            call_ok(&events, event_request("PutTargets", json!({
                "Rule":"replay-rule","Targets":[{"Id":"q","Arn":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:replayed")}]
            }))).await;
            let low = bound_a.min(bound_b);
            let high = bound_a.max(bound_b);
            call_ok(&events, event_request("StartReplay", json!({
                "ReplayName":"range","EventSourceArn":archive["ArchiveArn"],
                "EventStartTime":base + low,"EventEndTime":base + high,
                "Destination":{"Arn":bus_arn}
            }))).await;
            for _ in 0..100 {
                let replay = call_ok(&events, event_request("DescribeReplay", json!({
                    "ReplayName":"range"
                }))).await;
                if replay["State"] == "COMPLETED" { break; }
                tokio::task::yield_now().await;
            }
            let received = call_ok(&sqs, sqs_request("ReceiveMessage", json!({
                "QueueUrl":format!("https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/replayed"),
                "MaxNumberOfMessages":10
            }))).await;
            let actual: BTreeSet<i64> = received["Messages"].as_array().into_iter().flatten()
                .filter_map(|message| message["Body"].as_str())
                .map(|body| serde_json::from_str::<Value>(body).unwrap()["detail"]["offset"].as_i64().unwrap())
                .collect();
            let expected: BTreeSet<i64> = offsets.iter().copied()
                .filter(|offset| (low..=high).contains(offset)).collect();
            prop_assert_eq!(actual, expected);
            Ok(())
        })?;
    }

    // Property 15: Group Cascade Delete.
    // Property 20: Scheduler Tag Round-Trip.
    #[test]
    fn properties_15_20_scheduler_group_lifecycle_and_tags(
        suffix in "[a-z0-9]{1,10}",
        supplied_tags in prop::collection::btree_map("k[a-z]{1,5}", "[A-Za-z0-9]{0,8}", 0..8),
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        runtime.block_on(async move {
            let registry = ServiceRegistry::with_known_services();
            crate::register(&registry);
            let scheduler = registry.native_handler(&ServiceName::new("scheduler")).unwrap();
            let group = format!("g{suffix}");
            let schedule_name = format!("s{suffix}");
            let created = call_ok(&scheduler, request(Method::POST,
                &format!("/schedule-groups/{group}"), json!({}))).await;
            let arn = created["ScheduleGroupArn"].as_str().unwrap();
            call_ok(&scheduler, request(Method::POST, &format!("/tags/{arn}"), json!({
                "Tags":tags_array(&supplied_tags)
            }))).await;
            let listed = call_ok(&scheduler, request(Method::GET,
                &format!("/tags/{arn}"), json!({}))).await;
            let actual = listed_tags(&listed);
            for (key, value) in &supplied_tags {
                prop_assert_eq!(actual.get(key), Some(value));
            }
            let created_schedule = call_ok(&scheduler, request(Method::POST,
                &format!("/schedules/{schedule_name}"), json!({
                    "GroupName":group,"ScheduleExpression":"rate(1 minute)",
                    "FlexibleTimeWindow":{"Mode":"OFF"},"State":"DISABLED",
                    "Target":{"Arn":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:unused"),
                              "RoleArn":format!("arn:aws:iam::{ACCOUNT}:role/scheduler")}
                }))).await;
            let schedule_arn = created_schedule["ScheduleArn"].as_str().unwrap();
            call_ok(&scheduler, request(Method::POST, &format!("/tags/{schedule_arn}"), json!({
                "Tags":tags_array(&supplied_tags)
            }))).await;
            let schedule_tags = call_ok(&scheduler, request(Method::GET,
                &format!("/tags/{schedule_arn}"), json!({}))).await;
            let actual = listed_tags(&schedule_tags);
            for (key, value) in &supplied_tags {
                prop_assert_eq!(actual.get(key), Some(value));
            }
            call_ok(&scheduler, request(Method::DELETE,
                &format!("/schedule-groups/{group}"), json!({}))).await;
            let groups = call_ok(&scheduler, request(Method::GET,
                "/schedule-groups", json!({}))).await;
            prop_assert!(!groups["ScheduleGroups"].as_array().unwrap().iter()
                .any(|value| value["Name"] == group));
            let schedules = call_ok(&scheduler, request(Method::GET,
                "/schedules", json!({"GroupName":group}))).await;
            prop_assert!(schedules["Schedules"].as_array().unwrap().is_empty());
            Ok(())
        })?;
    }

    // Property 16: One-Time Firing.
    // Property 17: Recurring Bound.
    // Property 18: Flexible-Window Bound.
    // Property 19: Timezone Correctness.
    #[test]
    fn properties_16_17_18_19_scheduler_dispatch_and_timezones(
        day in 1u8..=28,
        hour in 0u8..24,
        minute in 0u8..60,
        interval_minutes in 2i64..120,
        occurrences in 1usize..6,
        maximum_window in 1u64..=1440,
        flexible in any::<bool>(),
        name in "[A-Za-z0-9_.-]{1,32}",
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        runtime.block_on(async move {
            let expression = format!("at(2025-01-{day:02}T{hour:02}:{minute:02}:00)");
            let scheduled = time::Date::from_calendar_date(2025, time::Month::January, day).unwrap()
                .with_hms(hour, minute, 0).unwrap()
                .assume_offset(time::UtcOffset::from_hms(-5, 0, 0).unwrap())
                .to_offset(time::UtcOffset::UTC);
            let window = if flexible {
                json!({"Mode":"FLEXIBLE","MaximumWindowInMinutes":maximum_window})
            } else {
                json!({"Mode":"OFF"})
            };
            let expected_fire = if flexible {
                crate::scheduler::flexible_fire_time(&name, scheduled, maximum_window)
            } else {
                scheduled
            };

            let registry = ServiceRegistry::with_known_services();
            locallycloud_sqs::register(&registry);
            let clock = Arc::new(RecordingClock::new(scheduled));
            crate::register_with_clock(&registry, clock.clone());
            let scheduler = registry.native_handler(&ServiceName::new("scheduler")).unwrap();
            let sqs = registry.native_handler(&ServiceName::new("sqs")).unwrap();
            call_ok(&sqs, sqs_request("CreateQueue", json!({"QueueName":"one-time"}))).await;
            call_ok(&scheduler, request(Method::POST, &format!("/schedules/{name}"), json!({
                "ScheduleExpression":expression,
                "ScheduleExpressionTimezone":"America/New_York",
                "FlexibleTimeWindow":window,
                "Target":{
                    "Arn":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:one-time"),
                    "RoleArn":format!("arn:aws:iam::{ACCOUNT}:role/scheduler")
                }
            }))).await;
            prop_assert_eq!(queue_message_count(&sqs, "one-time").await, 1);
            let sleeps = clock.sleeps.lock().unwrap().clone();
            prop_assert_eq!(sleeps.as_slice(), &[expected_fire]);
            prop_assert!(expected_fire >= scheduled);
            prop_assert!(expected_fire <= scheduled + Duration::minutes(maximum_window as i64));

            let anchor = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
            let end = anchor + Duration::minutes(interval_minutes * (occurrences - 1) as i64);
            let registry = ServiceRegistry::with_known_services();
            locallycloud_sqs::register(&registry);
            let clock = Arc::new(RecordingClock::new(anchor));
            crate::register_with_clock(&registry, clock.clone());
            let scheduler = registry.native_handler(&ServiceName::new("scheduler")).unwrap();
            let sqs = registry.native_handler(&ServiceName::new("sqs")).unwrap();
            call_ok(&sqs, sqs_request("CreateQueue", json!({"QueueName":"recurring"}))).await;
            call_ok(&scheduler, request(Method::POST, "/schedules/recurring", json!({
                "ScheduleExpression":format!("rate({interval_minutes} minutes)"),
                "StartDate":anchor.unix_timestamp(),
                "EndDate":end.unix_timestamp(),
                "FlexibleTimeWindow":{"Mode":"OFF"},
                "Target":{
                    "Arn":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:recurring"),
                    "RoleArn":format!("arn:aws:iam::{ACCOUNT}:role/scheduler")
                }
            }))).await;
            prop_assert_eq!(queue_message_count(&sqs, "recurring").await, occurrences);
            let sleeps = clock.sleeps.lock().unwrap().clone();
            prop_assert_eq!(sleeps.len(), occurrences);
            for (index, actual) in sleeps.iter().enumerate() {
                let expected = anchor + Duration::minutes(interval_minutes * index as i64);
                prop_assert_eq!(*actual, expected);
                prop_assert!(*actual >= anchor && *actual <= end);
            }
            Ok(())
        })?;
    }

    // Property 21: Pipe State Domain.
    // Property 22: Start-Stop Convergence.
    // Property 26: Pipes Tag Round-Trip.
    #[test]
    fn properties_21_22_26_pipe_lifecycle_state_and_tags(
        suffix in "[a-z0-9]{1,10}",
        supplied_tags in prop::collection::btree_map("k[a-z]{1,5}", "[A-Za-z0-9]{0,8}", 0..8),
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        runtime.block_on(async move {
            let registry = ServiceRegistry::with_known_services();
            crate::register(&registry);
            let pipes = registry.native_handler(&ServiceName::new("pipes")).unwrap();
            let name = format!("p{suffix}");
            let created = call_ok(&pipes, request(Method::POST, &format!("/v1/pipes/{name}"), json!({
                "Source":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:source"),
                "Target":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:target"),
                "RoleArn":format!("arn:aws:iam::{ACCOUNT}:role/pipe"),"DesiredState":"STOPPED"
            }))).await;
            let domain = ["RUNNING","STOPPED","CREATING","UPDATING","DELETING","STARTING","STOPPING"];
            prop_assert!(domain.contains(&created["CurrentState"].as_str().unwrap()));
            let arn = created["Arn"].as_str().unwrap();
            call_ok(&pipes, request(Method::POST, &format!("/tags/{arn}"), json!({
                "tags":supplied_tags
            }))).await;
            let listed = call_ok(&pipes, request(Method::GET, &format!("/tags/{arn}"), json!({}))).await;
            for (key, value) in &supplied_tags {
                prop_assert_eq!(listed["tags"].get(key).and_then(Value::as_str), Some(value.as_str()));
            }
            let started = call_ok(&pipes, request(Method::POST,
                &format!("/v1/pipes/{name}/start"), json!({}))).await;
            prop_assert_eq!(started["DesiredState"].as_str(), Some("RUNNING"));
            prop_assert!(domain.contains(&started["CurrentState"].as_str().unwrap()));
            let stopping = call_ok(&pipes, request(Method::POST,
                &format!("/v1/pipes/{name}/stop"), json!({}))).await;
            prop_assert_eq!(stopping["DesiredState"].as_str(), Some("STOPPED"));
            for _ in 0..100 {
                let described = call_ok(&pipes, request(Method::GET,
                    &format!("/v1/pipes/{name}"), json!({}))).await;
                prop_assert!(domain.contains(&described["CurrentState"].as_str().unwrap()));
                if described["CurrentState"] == "STOPPED" {
                    prop_assert_eq!(described["DesiredState"].as_str(), Some("STOPPED"));
                    return Ok(());
                }
                tokio::task::yield_now().await;
            }
            prop_assert!(false, "pipe did not converge to STOPPED");
            Ok(())
        })?;
    }

    // Property 23: Filter-Then-Forward.
    // Property 24: Pipeline Ordering.
    // Property 25: Enrichment Replaces Payload.
    #[test]
    fn properties_23_24_25_real_pipe_pipeline(
        expected_kind in "[a-z]{1,10}",
        matches_filter in any::<bool>(),
        enriched_value in "[A-Za-z0-9]{1,12}",
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        runtime.block_on(async move {
            let actual_kind = if matches_filter { expected_kind.clone() } else { format!("x{expected_kind}") };
            let registry = ServiceRegistry::with_known_services();
            let sqs = Arc::new(SqsPipeRecorder::new(json!({"kind":actual_kind})));
            let enriched = json!({"enriched":enriched_value});
            let lambda = Arc::new(LambdaRecorder { enriched: enriched.clone(), calls: Mutex::new(Vec::new()) });
            registry.register_native(
                ServiceName::new("sqs"),
                ServiceMetadata::new(AwsProtocol::Json10, Some("AmazonSQS")),
                sqs.clone(),
            );
            registry.register_native(
                ServiceName::new("lambda"),
                ServiceMetadata::new(AwsProtocol::RestJson, None),
                lambda.clone(),
            );
            crate::register(&registry);
            let pipes = registry.native_handler(&ServiceName::new("pipes")).unwrap();
            let filter = json!({"body":{"kind":[expected_kind]}}).to_string();
            call_ok(&pipes, request(Method::POST, "/v1/pipes/pipeline", json!({
                "Source":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:source"),
                "SourceParameters":{"FilterCriteria":{"Filters":[{"Pattern":filter}]}},
                "Enrichment":format!("arn:aws:lambda:{REGION}:{ACCOUNT}:function:enrich"),
                "Target":format!("arn:aws:lambda:{REGION}:{ACCOUNT}:function:target"),
                "RoleArn":format!("arn:aws:iam::{ACCOUNT}:role/pipe")
            }))).await;
            for _ in 0..100 {
                if sqs.calls.lock().unwrap().iter().any(|call| call == "DeleteMessage") { break; }
                tokio::time::sleep(StdDuration::from_millis(1)).await;
            }
            prop_assert!(sqs.calls.lock().unwrap().iter().any(|call| call == "DeleteMessage"));
            {
                let calls = lambda.calls.lock().unwrap();
                if matches_filter {
                    prop_assert_eq!(calls.len(), 2);
                    prop_assert_eq!(calls[0].0.as_str(), "RequestResponse");
                    prop_assert_eq!(calls[1].0.as_str(), "Event");
                    prop_assert_eq!(&calls[1].1, &enriched);
                } else {
                    prop_assert!(calls.is_empty());
                }
            }
            call_ok(&pipes, request(Method::POST, "/v1/pipes/pipeline/stop", json!({}))).await;
            Ok(())
        })?;
    }
}
#[tokio::test]
async fn compatibility_json11_and_rest_json_routes_headers_success_and_errors() {
    let registry = ServiceRegistry::with_known_services();
    crate::register(&registry);

    let events = registry
        .native_handler(&ServiceName::new("events"))
        .unwrap();
    let success = events.handle(event_request("ListRules", json!({}))).await;
    assert_eq!(success.status(), 200);
    assert_eq!(
        success.headers()["content-type"],
        "application/x-amz-json-1.1"
    );
    assert!(response_parts(success).await.2["Rules"].is_array());
    let error = events.handle(event_request("PutRule", json!({}))).await;
    let (status, headers, body) = response_parts(error).await;
    assert_eq!(status, 400);
    assert_eq!(headers["content-type"], "application/x-amz-json-1.1");
    assert_eq!(body["__type"], "ValidationException");
    assert!(body["message"].is_string());
    let no_trigger = events
        .handle(event_request("PutRule", json!({"Name":"no-trigger"})))
        .await;
    let (status, _, body) = response_parts(no_trigger).await;
    assert_eq!(status, 400);
    assert_eq!(body["__type"], "ValidationException");

    let scheduler = registry
        .native_handler(&ServiceName::new("scheduler"))
        .unwrap();
    let created = scheduler
        .handle(request(Method::POST, "/schedule-groups/compat", json!({})))
        .await;
    assert_eq!(created.status(), 200);
    assert_eq!(created.headers()["content-type"], "application/json");
    let group = call_ok(
        &scheduler,
        request(Method::GET, "/schedule-groups/compat", json!({})),
    )
    .await;
    assert_eq!(group["Name"], "compat");
    let missing = scheduler
        .handle(request(Method::GET, "/schedule-groups/missing", json!({})))
        .await;
    let (status, headers, body) = response_parts(missing).await;
    assert_eq!(status, 404);
    assert_eq!(headers["x-amzn-errortype"], "ResourceNotFoundException");
    assert!(body["message"].is_string());

    let pipes = registry.native_handler(&ServiceName::new("pipes")).unwrap();
    let created = call_ok(
        &pipes,
        request(
            Method::POST,
            "/v1/pipes/compat",
            json!({
                "Source":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:source"),
                "Target":format!("arn:aws:sqs:{REGION}:{ACCOUNT}:target"),
                "RoleArn":format!("arn:aws:iam::{ACCOUNT}:role/pipe"),
                "DesiredState":"STOPPED"
            }),
        ),
    )
    .await;
    assert_eq!(created["Name"], "compat");
    let described = call_ok(&pipes, request(Method::GET, "/v1/pipes/compat", json!({}))).await;
    assert_eq!(described["DesiredState"], "STOPPED");
    let missing = pipes
        .handle(request(Method::GET, "/v1/pipes/missing", json!({})))
        .await;
    let (status, headers, body) = response_parts(missing).await;
    assert_eq!(status, 404);
    assert_eq!(headers["x-amzn-errortype"], "NotFoundException");
    assert!(body["message"].is_string());
}
