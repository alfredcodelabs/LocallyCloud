//! Returned queue URLs point at this locallycloud instance and every queue URL form keeps
//! working. Requests go through the Core `InternalDispatcher` (router + native handler), the
//! same path the server uses, with the headers an AWS SDK sends after taking the QueueUrl
//! host as its endpoint (`Host` = endpoint host, path `/<account>/<queue>`).
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use serde_json::{json, Value};

use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::ServiceRegistry;
use locallycloud_sqs::QueueUrlStyle;
use locallycloud_state::StateDb;

const ENDPOINT: &str = "http://127.0.0.1:4566";
const HOST: &str = "127.0.0.1:4566";
const REGION: &str = "eu-west-1";

struct TempState(PathBuf);

impl TempState {
    fn new() -> Self {
        TempState(std::env::temp_dir().join(format!(
            "locallycloud-sqs-queue-urls-{}",
            uuid::Uuid::new_v4()
        )))
    }

    fn open(&self) -> Arc<StateDb> {
        Arc::new(StateDb::open(self.0.join("state.sqlite3")).unwrap())
    }
}

impl Drop for TempState {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dispatcher(
    state: Arc<StateDb>,
    style: Option<QueueUrlStyle>,
) -> (Arc<ServiceRegistry>, InternalDispatcher) {
    let registry = ServiceRegistry::with_known_services();
    match style {
        Some(style) => {
            locallycloud_sqs::register_with_state_and_queue_urls(&registry, state, style).unwrap()
        }
        None => locallycloud_sqs::register_with_state(&registry, state).unwrap(),
    }
    let dispatcher = InternalDispatcher::new_shared(
        &registry,
        ProxyConfig {
            backend_url: "http://127.0.0.1:1".into(),
            upstream_timeout: Duration::from_secs(2),
        },
        LegacyHealth::new(false),
        "us-east-1".into(),
        "000000000000".into(),
    );
    (registry, dispatcher)
}

fn signed_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static(HOST));
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential=test/20250101/{REGION}/sqs/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature=abc123"
        ))
        .unwrap(),
    );
    headers
}

async fn send(
    dispatcher: &InternalDispatcher,
    path: &str,
    headers: HeaderMap,
    body: String,
) -> (u16, String) {
    let uri: Uri = path.parse().unwrap();
    let response = dispatcher
        .dispatch(&Method::POST, &uri, &headers, Bytes::from(body), "rid")
        .await;
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn json_call(
    dispatcher: &InternalDispatcher,
    path: &str,
    op: &str,
    body: Value,
) -> (u16, Value) {
    let mut headers = signed_headers();
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("AmazonSQS.{op}")).unwrap(),
    );
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/x-amz-json-1.0"),
    );
    let (status, text) = send(dispatcher, path, headers, body.to_string()).await;
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

async fn query_call(dispatcher: &InternalDispatcher, path: &str, form: &str) -> (u16, String) {
    let mut headers = signed_headers();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    send(dispatcher, path, headers, form.to_string()).await
}

fn form_encode(value: &str) -> String {
    value.replace(':', "%3A").replace('/', "%2F")
}

fn url_path(url: &str) -> &str {
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    &without_scheme[without_scheme.find('/').unwrap()..]
}

#[tokio::test]
async fn json_queue_urls_are_local_and_every_form_is_accepted() {
    let temp = TempState::new();
    let (_registry, d) = dispatcher(temp.open(), Some(QueueUrlStyle::Endpoint(ENDPOINT.into())));
    let local = format!("{ENDPOINT}/000000000000/orders");

    let (status, created) = json_call(&d, "/", "CreateQueue", json!({"QueueName": "orders"})).await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["QueueUrl"], local);
    let (_, url) = json_call(&d, "/", "GetQueueUrl", json!({"QueueName": "orders"})).await;
    assert_eq!(url["QueueUrl"], local);
    let (_, owned) = json_call(
        &d,
        "/",
        "GetQueueUrl",
        json!({"QueueName": "orders", "QueueOwnerAWSAccountId": "000000000000"}),
    )
    .await;
    assert_eq!(owned["QueueUrl"], local);
    let (_, listed) = json_call(&d, "/", "ListQueues", json!({})).await;
    assert_eq!(listed["QueueUrls"], json!([local]));

    // SDK v3 / botocore send to the QueueUrl origin; also accept the path, the legacy AWS
    // URL, and a bare path, all resolved in the signing region.
    for (path, queue_url) in [
        (url_path(&local), local.as_str()),
        ("/", local.as_str()),
        (
            "/",
            "https://sqs.eu-west-1.amazonaws.com/000000000000/orders",
        ),
        (
            "/",
            "https://eu-west-1.queue.amazonaws.com/000000000000/orders",
        ),
        ("/", "/000000000000/orders"),
    ] {
        let (status, sent) = json_call(
            &d,
            path,
            "SendMessage",
            json!({"QueueUrl": queue_url, "MessageBody": queue_url}),
        )
        .await;
        assert_eq!(status, 200, "{queue_url}: {sent}");
    }
    let (_, received) = json_call(
        &d,
        url_path(&local),
        "ReceiveMessage",
        json!({"QueueUrl": local, "MaxNumberOfMessages": 10}),
    )
    .await;
    assert_eq!(received["Messages"].as_array().unwrap().len(), 5);

    // The queue ARN is unchanged by the URL shape.
    let (_, attributes) = json_call(
        &d,
        "/",
        "GetQueueAttributes",
        json!({"QueueUrl": local, "AttributeNames": ["QueueArn"]}),
    )
    .await;
    assert_eq!(
        attributes["Attributes"]["QueueArn"],
        "arn:aws:sqs:eu-west-1:000000000000:orders"
    );

    let (_, dlq) = json_call(&d, "/", "CreateQueue", json!({"QueueName": "orders-dlq"})).await;
    let (status, _) = json_call(
        &d,
        "/",
        "SetQueueAttributes",
        json!({"QueueUrl": local, "Attributes": {"RedrivePolicy": json!({
            "deadLetterTargetArn": "arn:aws:sqs:eu-west-1:000000000000:orders-dlq",
            "maxReceiveCount": "3"
        }).to_string()}}),
    )
    .await;
    assert_eq!(status, 200);
    let (_, sources) = json_call(
        &d,
        "/",
        "ListDeadLetterSourceQueues",
        json!({"QueueUrl": dlq["QueueUrl"]}),
    )
    .await;
    assert_eq!(sources["queueUrls"], json!([local]));
}

#[tokio::test]
async fn query_queue_urls_are_local_and_every_form_is_accepted() {
    let temp = TempState::new();
    let (_registry, d) = dispatcher(temp.open(), Some(QueueUrlStyle::Endpoint(ENDPOINT.into())));
    let local = format!("{ENDPOINT}/000000000000/legacy");

    let (status, created) = query_call(&d, "/", "Action=CreateQueue&QueueName=legacy").await;
    assert_eq!(status, 200, "{created}");
    assert!(created.contains(&format!("<QueueUrl>{local}</QueueUrl>")));
    let (_, url) = query_call(&d, "/", "Action=GetQueueUrl&QueueName=legacy").await;
    assert!(url.contains(&format!("<QueueUrl>{local}</QueueUrl>")));
    let (_, listed) = query_call(&d, "/", "Action=ListQueues").await;
    assert!(listed.contains(&format!("<QueueUrl>{local}</QueueUrl>")));

    for (path, queue_url) in [
        (url_path(&local), Some(local.as_str())),
        (url_path(&local), None),
        (
            "/",
            Some("https://sqs.eu-west-1.amazonaws.com/000000000000/legacy"),
        ),
        ("/", Some("/000000000000/legacy")),
    ] {
        let parameter = queue_url
            .map(|url| format!("&QueueUrl={}", form_encode(url)))
            .unwrap_or_default();
        let (status, sent) = query_call(
            &d,
            path,
            &format!("Action=SendMessage&Version=2012-11-05{parameter}&MessageBody=hello"),
        )
        .await;
        assert_eq!(status, 200, "{path} {queue_url:?}: {sent}");
    }
    let (_, received) = query_call(
        &d,
        url_path(&local),
        "Action=ReceiveMessage&MaxNumberOfMessages=10",
    )
    .await;
    assert_eq!(received.matches("<Message>").count(), 4, "{received}");
}

#[tokio::test]
async fn persisted_queues_keep_working_with_local_urls() {
    let temp = TempState::new();
    let aws_url = "https://sqs.eu-west-1.amazonaws.com/000000000000/kept";
    {
        let (_registry, d) = dispatcher(temp.open(), Some(QueueUrlStyle::Aws));
        let (_, created) = json_call(&d, "/", "CreateQueue", json!({"QueueName": "kept"})).await;
        assert_eq!(created["QueueUrl"], aws_url);
        let (status, _) = json_call(
            &d,
            "/",
            "SendMessage",
            json!({"QueueUrl": aws_url, "MessageBody": "before restart"}),
        )
        .await;
        assert_eq!(status, 200);
    }

    let (_registry, d) = dispatcher(temp.open(), Some(QueueUrlStyle::Endpoint(ENDPOINT.into())));
    let local = format!("{ENDPOINT}/000000000000/kept");
    let (_, url) = json_call(&d, "/", "GetQueueUrl", json!({"QueueName": "kept"})).await;
    assert_eq!(url["QueueUrl"], local);
    let (_, received) = json_call(
        &d,
        "/",
        "ReceiveMessage",
        json!({"QueueUrl": aws_url, "VisibilityTimeout": 0}),
    )
    .await;
    assert_eq!(received["Messages"][0]["Body"], "before restart");
    let (_, received) = json_call(
        &d,
        url_path(&local),
        "ReceiveMessage",
        json!({"QueueUrl": local}),
    )
    .await;
    assert_eq!(received["Messages"][0]["Body"], "before restart");
}

#[tokio::test]
async fn library_registration_keeps_aws_urls() {
    let temp = TempState::new();
    let (_registry, d) = dispatcher(temp.open(), None);
    let (_, created) = json_call(&d, "/", "CreateQueue", json!({"QueueName": "compat"})).await;
    assert_eq!(
        created["QueueUrl"],
        "https://sqs.eu-west-1.amazonaws.com/000000000000/compat"
    );
}
