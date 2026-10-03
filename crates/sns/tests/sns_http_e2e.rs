//! End-to-end SNS→HTTP(S) tests against a **real local HTTP server** (no mocks): subscription
//! confirmation flow, notification delivery, and dead-letter routing of a failed delivery to a
//! real SQS queue. Drives the registered SNS handler through the Core registry.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use serde_json::{json, Value};

use axum::Router;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};

/// Recorded inbound deliveries: (x-amz-sns-message-type, body).
type Recorder = Arc<Mutex<Vec<(String, String)>>>;

/// Spawn a real HTTP server that records every POST and replies with `status`.
async fn spawn_endpoint(status: u16) -> (String, Recorder) {
    let rec: Recorder = Arc::new(Mutex::new(Vec::new()));
    let captured = rec.clone();
    let app = Router::new().fallback(move |headers: HeaderMap, body: String| {
        let captured = captured.clone();
        async move {
            let mt = headers
                .get("x-amz-sns-message-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            captured.lock().unwrap().push((mt, body));
            axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::OK)
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/"), rec)
}

async fn spawn_blocked_notification_endpoint() -> (
    String,
    Recorder,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
) {
    let rec: Recorder = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let captured = rec.clone();
    let endpoint_started = started.clone();
    let endpoint_release = release.clone();
    let app = Router::new().fallback(move |headers: HeaderMap, body: String| {
        let captured = captured.clone();
        let started = endpoint_started.clone();
        let release = endpoint_release.clone();
        async move {
            let kind = headers
                .get("x-amz-sns-message-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_string();
            captured.lock().unwrap().push((kind.clone(), body));
            if kind == "Notification" {
                started.notify_one();
                release.notified().await;
            }
            axum::http::StatusCode::OK
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/"), rec, started, release)
}

fn registry() -> Arc<ServiceRegistry> {
    let reg = ServiceRegistry::with_known_services();
    locallycloud_sqs::register(&reg);
    locallycloud_sns::register(&reg);
    reg
}

fn handler(reg: &Arc<ServiceRegistry>, service: &str) -> Arc<dyn NativeHandler> {
    reg.native_handler(&ServiceName::new(service)).unwrap()
}

async fn call(h: &Arc<dyn NativeHandler>, target_prefix: &str, op: &str, body: Value) -> Value {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("{target_prefix}.{op}")).unwrap(),
    );
    let req = ServiceRequest {
        method: Method::POST,
        uri: "/".parse().unwrap(),
        headers,
        body: Bytes::from(body.to_string()),
        region: "us-east-1".to_string(),
        account_id: "000000000000".to_string(),
        request_id: "rid".to_string(),
    };
    let resp = h.handle(req).await;
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }
}

async fn sns(h: &Arc<dyn NativeHandler>, op: &str, body: Value) -> Value {
    call(h, "AmazonSimpleNotificationService", op, body).await
}
async fn sqs(h: &Arc<dyn NativeHandler>, op: &str, body: Value) -> Value {
    call(h, "AmazonSQS", op, body).await
}

/// Poll the recorder until a message of `kind` arrives (or time out).
async fn wait_for(rec: &Recorder, kind: &str) -> Option<String> {
    for _ in 0..50 {
        if let Some((_, body)) = rec.lock().unwrap().iter().find(|(mt, _)| mt == kind) {
            return Some(body.clone());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    None
}

#[tokio::test]
async fn http_subscription_confirmation_then_notification() {
    let (endpoint, rec) = spawn_endpoint(200).await;
    let reg = registry();
    let sns_h = handler(&reg, "sns");

    let topic = sns(&sns_h, "CreateTopic", json!({ "Name": "t" })).await["TopicArn"]
        .as_str()
        .unwrap()
        .to_string();
    sns(&sns_h, "Subscribe", json!({
        "TopicArn": topic, "Protocol": "http", "Endpoint": endpoint, "ReturnSubscriptionArn": "true"
    })).await;

    // A SubscriptionConfirmation is POSTed to the endpoint; confirm via its Token.
    let confirm_body = wait_for(&rec, "SubscriptionConfirmation")
        .await
        .expect("confirmation delivered");
    let confirm: Value = serde_json::from_str(&confirm_body).unwrap();
    assert_eq!(confirm["Type"], "SubscriptionConfirmation");
    let token = confirm["Token"].as_str().unwrap().to_string();
    assert!(confirm["SubscribeURL"]
        .as_str()
        .unwrap()
        .contains("ConfirmSubscription"));

    sns(
        &sns_h,
        "ConfirmSubscription",
        json!({ "TopicArn": topic, "Token": token }),
    )
    .await;

    // Now a publish is delivered as a Notification.
    sns(
        &sns_h,
        "Publish",
        json!({ "TopicArn": topic, "Message": "hello-http" }),
    )
    .await;
    let note_body = wait_for(&rec, "Notification")
        .await
        .expect("notification delivered");
    let note: Value = serde_json::from_str(&note_body).unwrap();
    assert_eq!(note["Type"], "Notification");
    assert_eq!(note["Message"], "hello-http");
}

#[tokio::test]
async fn failed_http_delivery_is_dead_lettered_to_sqs() {
    // The subscriber endpoint always fails (HTTP 500).
    let (endpoint, rec) = spawn_endpoint(500).await;
    let reg = registry();
    let sns_h = handler(&reg, "sns");
    let sqs_h = handler(&reg, "sqs");

    // A real DLQ queue.
    let qurl = sqs(&sqs_h, "CreateQueue", json!({ "QueueName": "sns-dlq" })).await["QueueUrl"]
        .as_str()
        .unwrap()
        .to_string();
    let dlq_arn = "arn:aws:sqs:us-east-1:000000000000:sns-dlq";

    let topic = sns(&sns_h, "CreateTopic", json!({ "Name": "t2" })).await["TopicArn"]
        .as_str()
        .unwrap()
        .to_string();
    sns(&sns_h, "Subscribe", json!({
        "TopicArn": topic, "Protocol": "http", "Endpoint": endpoint, "ReturnSubscriptionArn": "true",
        "Attributes": {
            "DeliveryPolicy": json!({ "healthyRetryPolicy": { "numRetries": 2, "minDelayTarget": 0 } }).to_string(),
            "RedrivePolicy": json!({ "deadLetterTargetArn": dlq_arn }).to_string()
        }
    })).await;

    // Confirm via the token from the (failing-but-recorded) confirmation POST.
    let confirm_body = wait_for(&rec, "SubscriptionConfirmation")
        .await
        .expect("confirmation recorded");
    let token = serde_json::from_str::<Value>(&confirm_body).unwrap()["Token"]
        .as_str()
        .unwrap()
        .to_string();
    sns(
        &sns_h,
        "ConfirmSubscription",
        json!({ "TopicArn": topic, "Token": token }),
    )
    .await;

    // Publish: HTTP delivery fails (500) → routed to the DLQ queue.
    sns(
        &sns_h,
        "Publish",
        json!({ "TopicArn": topic, "Message": "dead-letter-me" }),
    )
    .await;

    // The failed notification lands in the DLQ.
    let mut got = String::new();
    for _ in 0..50 {
        let recv = sqs(&sqs_h, "ReceiveMessage", json!({ "QueueUrl": qurl })).await;
        if let Some(body) = recv["Messages"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|m| m["Body"].as_str())
        {
            got = body.to_string();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        got.contains("dead-letter-me"),
        "DLQ should carry the failed notification, got: {got}"
    );
    let notification_attempts = rec
        .lock()
        .unwrap()
        .iter()
        .filter(|(kind, _)| kind == "Notification")
        .count();
    assert_eq!(notification_attempts, 3, "initial attempt plus two retries");
}

#[tokio::test]
async fn blocked_http_subscription_does_not_delay_sqs_or_publish() {
    let (endpoint, rec, started, release) = spawn_blocked_notification_endpoint().await;
    let reg = registry();
    let sns_h = handler(&reg, "sns");
    let sqs_h = handler(&reg, "sqs");

    let queue = sqs(
        &sqs_h,
        "CreateQueue",
        json!({ "QueueName": "sns-independent-fanout" }),
    )
    .await;
    let queue_url = queue["QueueUrl"].as_str().unwrap().to_string();
    let queue_arn = "arn:aws:sqs:us-east-1:000000000000:sns-independent-fanout";
    let topic = sns(&sns_h, "CreateTopic", json!({ "Name": "independent" })).await["TopicArn"]
        .as_str()
        .unwrap()
        .to_string();

    sns(
        &sns_h,
        "Subscribe",
        json!({
            "TopicArn": topic,
            "Protocol": "http",
            "Endpoint": endpoint,
            "ReturnSubscriptionArn": "true"
        }),
    )
    .await;
    let confirmation = wait_for(&rec, "SubscriptionConfirmation")
        .await
        .expect("confirmation delivered");
    let token = serde_json::from_str::<Value>(&confirmation).unwrap()["Token"]
        .as_str()
        .unwrap()
        .to_string();
    sns(
        &sns_h,
        "ConfirmSubscription",
        json!({ "TopicArn": topic, "Token": token }),
    )
    .await;
    sns(
        &sns_h,
        "Subscribe",
        json!({ "TopicArn": topic, "Protocol": "sqs", "Endpoint": queue_arn }),
    )
    .await;

    tokio::time::timeout(
        std::time::Duration::from_millis(200),
        sns(
            &sns_h,
            "Publish",
            json!({ "TopicArn": topic, "Message": "independent-delivery" }),
        ),
    )
    .await
    .expect("Publish must not wait for a blocked HTTP subscriber");
    tokio::time::timeout(std::time::Duration::from_secs(1), started.notified())
        .await
        .expect("HTTP notification started and remains blocked");

    let mut delivered = false;
    for _ in 0..50 {
        let received = sqs(&sqs_h, "ReceiveMessage", json!({ "QueueUrl": queue_url })).await;
        if received["Messages"]
            .as_array()
            .is_some_and(|messages| !messages.is_empty())
        {
            delivered = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    release.notify_waiters();
    assert!(
        delivered,
        "SQS delivery must complete while HTTP remains blocked"
    );
}
