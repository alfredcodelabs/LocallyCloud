//! PutLogEvents with embedded metric format lines delivers metrics to the Monitoring sink.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::response::Response;
use http::{HeaderMap, HeaderValue, Method};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::metrics::{
    EmitOutcome, MetricObservation, MetricOrigin, MetricSink, MetricUnit,
};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use serde_json::{json, Value};

#[derive(Default)]
struct RecordingSink {
    observations: Mutex<Vec<MetricObservation>>,
}

impl MetricSink for RecordingSink {
    fn try_emit(&self, observations: Vec<MetricObservation>) -> EmitOutcome {
        self.observations.lock().unwrap().extend(observations);
        EmitOutcome::Accepted
    }
}

struct StubMonitoring;

#[async_trait]
impl NativeHandler for StubMonitoring {
    async fn handle(&self, _request: ServiceRequest) -> Response {
        Response::new(Body::empty())
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn setup() -> (Arc<ServiceRegistry>, Arc<RecordingSink>) {
    let registry = ServiceRegistry::with_known_services();
    let sink = Arc::new(RecordingSink::default());
    registry.register_native_with_metric_sink(
        ServiceName::new("monitoring"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        Arc::new(StubMonitoring),
        sink.clone(),
    );
    locallycloud_cloudwatch_logs::register(&registry).unwrap();
    (registry, sink)
}

async fn call(registry: &ServiceRegistry, operation: &str, body: Value) -> (u16, Value) {
    let handler = registry
        .lookup(&ServiceName::new("logs"))
        .and_then(|entry| entry.handler)
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-amz-json-1.1"),
    );
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("Logs_20140328.{operation}")).unwrap(),
    );
    let response = handler
        .handle(ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: body.to_string().into(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "emf-test".into(),
        })
        .await;
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn wait_for(sink: &RecordingSink, count: usize) -> Vec<MetricObservation> {
    for _ in 0..200 {
        let observations = sink.observations.lock().unwrap().clone();
        if observations.len() >= count {
            return observations;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    sink.observations.lock().unwrap().clone()
}

fn powertools_line(timestamp_ms: i64) -> String {
    json!({
        "_aws": {
            "Timestamp": timestamp_ms,
            "CloudWatchMetrics": [{
                "Namespace": "ServerlessAirline",
                "Dimensions": [["service"]],
                "Metrics": [{ "Name": "SuccessfulBooking", "Unit": "Count" }]
            }]
        },
        "service": "booking",
        "SuccessfulBooking": [1.0, 2.0]
    })
    .to_string()
}

#[tokio::test]
async fn put_log_events_with_emf_publishes_metrics_and_keeps_every_event() {
    let (registry, sink) = setup();
    let group = json!({ "logGroupName": "/app/booking" });
    assert_eq!(call(&registry, "CreateLogGroup", group).await.0, 200);
    let stream = json!({ "logGroupName": "/app/booking", "logStreamName": "s" });
    assert_eq!(call(&registry, "CreateLogStream", stream).await.0, 200);

    let now = now_ms();
    let invalid_emf = json!({
        "_aws": { "Timestamp": now, "CloudWatchMetrics": [{
            "Namespace": "ServerlessAirline", "Dimensions": [["service"]],
            "Metrics": [{ "Name": "Missing" }]
        }]},
        "service": "booking"
    })
    .to_string();
    let messages = [
        "plain text line".to_owned(),
        powertools_line(now),
        invalid_emf,
    ];
    let events: Vec<_> = messages
        .iter()
        .map(|message| json!({ "timestamp": now, "message": message }))
        .collect();
    let (status, body) = call(
        &registry,
        "PutLogEvents",
        json!({ "logGroupName": "/app/booking", "logStreamName": "s", "logEvents": events }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("rejectedLogEventsInfo").is_none(), "{body}");

    let observations = wait_for(&sink, 2).await;
    assert_eq!(observations.len(), 2, "{observations:?}");
    for (observation, value) in observations.iter().zip([1.0, 2.0]) {
        assert_eq!(observation.account_id, "000000000000");
        assert_eq!(observation.region, "us-east-1");
        assert_eq!(observation.namespace, "ServerlessAirline");
        assert_eq!(observation.metric_name, "SuccessfulBooking");
        assert_eq!(
            observation.dimensions.get("service").map(String::as_str),
            Some("booking")
        );
        assert_eq!(observation.dimensions.len(), 1);
        assert_eq!(observation.value, value);
        assert_eq!(observation.unit, Some(MetricUnit::Count));
        assert_eq!(observation.storage_resolution, 60);
        assert_eq!(observation.timestamp_ms, now);
        assert_eq!(observation.origin, MetricOrigin::CloudWatchLogs);
    }

    let (status, stored) = call(
        &registry,
        "GetLogEvents",
        json!({ "logGroupName": "/app/booking", "logStreamName": "s", "startFromHead": true }),
    )
    .await;
    assert_eq!(status, 200, "{stored}");
    let stored: Vec<_> = stored["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["message"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(stored, messages);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(sink.observations.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn emf_ingest_succeeds_without_monitoring_and_later_puts_are_delivered_once() {
    let registry = ServiceRegistry::with_known_services();
    locallycloud_cloudwatch_logs::register(&registry).unwrap();
    let group = json!({ "logGroupName": "late" });
    assert_eq!(call(&registry, "CreateLogGroup", group).await.0, 200);
    let stream = json!({ "logGroupName": "late", "logStreamName": "s" });
    assert_eq!(call(&registry, "CreateLogStream", stream).await.0, 200);
    let now = now_ms();
    let put = |message: String| {
        json!({
            "logGroupName": "late",
            "logStreamName": "s",
            "logEvents": [{ "timestamp": now, "message": message }]
        })
    };
    let (status, body) = call(&registry, "PutLogEvents", put(powertools_line(now))).await;
    assert_eq!(status, 200, "{body}");
    // Let the lazily spawned worker observe the missing receiver; like metric-filter effects,
    // EMF effects rejected by an unavailable receiver are not redelivered later.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let sink = Arc::new(RecordingSink::default());
    registry.register_native_with_metric_sink(
        ServiceName::new("monitoring"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        Arc::new(StubMonitoring),
        sink.clone(),
    );
    let (status, body) = call(&registry, "PutLogEvents", put(powertools_line(now))).await;
    assert_eq!(status, 200, "{body}");
    let observations = wait_for(&sink, 2).await;
    assert_eq!(observations.len(), 2, "{observations:?}");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(sink.observations.lock().unwrap().len(), 2);
}
