//! Property-based tests for SQS (design Properties 1–12).
//!
//! These drive the real in-process service handler (no mocks) over both wire protocols and
//! exercise the pure URL/ARN and MD5 engines. Each property is checked across many generated
//! inputs with `proptest`.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use proptest::prelude::*;
use serde_json::{json, Value};

use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_sqs::error::SqsError;
use localcloud_sqs::md5::body_md5;
use localcloud_sqs::model::QueueArn;
use localcloud_sqs::service::SqsHandler;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}

/// A JSON-protocol request.
fn json_req(op: &str, body: Value) -> ServiceRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("AmazonSQS.{op}")).unwrap(),
    );
    ServiceRequest {
        method: Method::POST,
        uri: "/".parse().unwrap(),
        headers,
        body: Bytes::from(body.to_string()),
        region: "us-east-1".into(),
        account_id: "000000000000".into(),
        request_id: "rid".into(),
    }
}

/// A Query-protocol request from a raw form body.
fn query_req(form: &str) -> ServiceRequest {
    ServiceRequest {
        method: Method::POST,
        uri: "/".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::from(form.to_string()),
        region: "us-east-1".into(),
        account_id: "000000000000".into(),
        request_id: "rid".into(),
    }
}

async fn call_json(h: &SqsHandler, op: &str, body: Value) -> (u16, Value) {
    let resp = h.handle(json_req(op, body)).await;
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn call_query(h: &SqsHandler, form: &str) -> (u16, String) {
    let resp = h.handle(query_req(form)).await;
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn create(h: &SqsHandler, name: &str) -> String {
    let (s, v) = call_json(h, "CreateQueue", json!({ "QueueName": name })).await;
    assert_eq!(s, 200);
    v["QueueUrl"].as_str().unwrap().to_string()
}

// Identifier-like segments to keep URLs/forms well-formed.
fn ident() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_-]{1,40}"
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, .. ProptestConfig::default() })]

    /// Property 3: queue URL ↔ ARN round-trips for any valid region/account/name.
    #[test]
    fn url_arn_round_trip(region in ident(), account in "[0-9]{12}", name in ident()) {
        let arn = QueueArn::new(&region, &account, &name);
        let parsed = QueueArn::from_url(&arn.to_url()).unwrap();
        prop_assert_eq!(parsed, arn);
    }

    /// Property 5: `MD5OfMessageBody` is deterministic, 32 lowercase-hex chars.
    #[test]
    fn md5_is_stable_hex(body in ".{0,256}") {
        let a = body_md5(&body);
        let b = body_md5(&body);
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(a.len(), 32);
        prop_assert!(a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// Property 2: every error renders a JSON `__type` and a Query `<Code>` with the same
    /// HTTP status across protocols.
    #[test]
    fn error_renders_in_both_protocols(idx in 0usize..6) {
        let errors = [
            SqsError::QueueDoesNotExist,
            SqsError::QueueNameExists,
            SqsError::ReceiptHandleIsInvalid,
            SqsError::EmptyBatchRequest,
            SqsError::TooManyEntriesInBatchRequest,
            SqsError::BatchEntryIdsNotDistinct,
        ];
        let e = &errors[idx];
        let j = e.render_json("rid");
        let q = e.render_query("rid");
        let json_needle = format!("com.amazonaws.sqs#{}", e.code());
        let xml_needle = format!("<Code>{}</Code>", e.query_code());
        prop_assert!(j.body.contains(&json_needle));
        prop_assert!(q.body.contains(&xml_needle));
        prop_assert_eq!(j.status, q.status);
    }

    /// Property 1: the same body sent over JSON and Query yields the same body MD5.
    #[test]
    fn protocol_consistency_md5(body in "[a-zA-Z0-9 ]{1,80}") {
        let h = SqsHandler::new();
        rt().block_on(async {
            let url = create(&h, "pc").await;
            let (sj, vj) = call_json(&h, "SendMessage", json!({ "QueueUrl": url, "MessageBody": body })).await;
            prop_assert_eq!(sj, 200);
            let (sq, xml) = call_query(&h, &format!("Action=SendMessage&QueueUrl={url}&MessageBody={body}")).await;
            prop_assert_eq!(sq, 200);
            let expected = body_md5(&body);
            prop_assert_eq!(vj["MD5OfMessageBody"].as_str().unwrap(), expected.as_str());
            let xml_needle = format!("<MD5OfMessageBody>{expected}</MD5OfMessageBody>");
            prop_assert!(xml.contains(&xml_needle));
            Ok(())
        }).unwrap();
    }

    /// Property 4: re-creating a queue with the same name is idempotent (same URL).
    #[test]
    fn idempotent_create(name in ident()) {
        let h = SqsHandler::new();
        rt().block_on(async {
            let (_, a) = call_json(&h, "CreateQueue", json!({ "QueueName": name })).await;
            let (_, b) = call_json(&h, "CreateQueue", json!({ "QueueName": name })).await;
            prop_assert_eq!(a["QueueUrl"].as_str(), b["QueueUrl"].as_str());
            let (_, l) = call_json(&h, "ListQueues", json!({})).await;
            prop_assert_eq!(l["QueueUrls"].as_array().unwrap().len(), 1);
            Ok(())
        }).unwrap();
    }

    /// Property 6: a body at `MaximumMessageSize` is accepted; one byte over is rejected.
    #[test]
    fn size_boundary(limit in 1024usize..2048) {
        let h = SqsHandler::new();
        rt().block_on(async {
            let (_, cv) = call_json(&h, "CreateQueue", json!({
                "QueueName": "sz",
                "Attributes": { "MaximumMessageSize": limit.to_string() }
            })).await;
            let url = cv["QueueUrl"].as_str().unwrap().to_string();
            let at_limit = "a".repeat(limit);
            let over = "a".repeat(limit + 1);
            let (s_ok, _) = call_json(&h, "SendMessage", json!({ "QueueUrl": url, "MessageBody": at_limit })).await;
            prop_assert_eq!(s_ok, 200);
            let (s_over, _) = call_json(&h, "SendMessage", json!({ "QueueUrl": url, "MessageBody": over })).await;
            prop_assert_eq!(s_over, 400);
            Ok(())
        }).unwrap();
    }

    /// Property 8: batch completeness — Successful ∪ Failed covers exactly the input ids.
    #[test]
    fn batch_completeness(n in 1usize..=10) {
        let h = SqsHandler::new();
        rt().block_on(async {
            let url = create(&h, "batch").await;
            let entries: Vec<Value> = (0..n)
                .map(|i| json!({ "Id": format!("id{i}"), "MessageBody": format!("m{i}") }))
                .collect();
            let (s, v) = call_json(&h, "SendMessageBatch", json!({ "QueueUrl": url, "Entries": entries })).await;
            prop_assert_eq!(s, 200);
            let ok = v["Successful"].as_array().unwrap().len();
            let failed = v["Failed"].as_array().unwrap().len();
            prop_assert_eq!(ok + failed, n);
            Ok(())
        }).unwrap();
    }

    /// Property 9: FIFO messages in a group are received in send order.
    #[test]
    fn fifo_ordering(bodies in proptest::collection::vec("[a-z]{1,8}", 2..6)) {
        let h = SqsHandler::new();
        rt().block_on(async {
            let (_, cv) = call_json(&h, "CreateQueue", json!({
                "QueueName": "ord.fifo", "Attributes": { "FifoQueue": "true" }
            })).await;
            let url = cv["QueueUrl"].as_str().unwrap().to_string();
            for (i, b) in bodies.iter().enumerate() {
                call_json(&h, "SendMessage", json!({
                    "QueueUrl": url, "MessageBody": b,
                    "MessageGroupId": "g", "MessageDeduplicationId": format!("d{i}")
                })).await;
            }
            let (_, r) = call_json(&h, "ReceiveMessage", json!({ "QueueUrl": url, "MaxNumberOfMessages": 10 })).await;
            let got: Vec<String> = r["Messages"].as_array().unwrap().iter()
                .map(|m| m["Body"].as_str().unwrap().to_string()).collect();
            prop_assert_eq!(got, bodies);
            Ok(())
        }).unwrap();
    }

    /// Property 10: identical dedup id within the window stores exactly one message.
    #[test]
    fn fifo_exactly_once(body in "[a-z]{1,16}", copies in 2usize..6) {
        let h = SqsHandler::new();
        rt().block_on(async {
            let (_, cv) = call_json(&h, "CreateQueue", json!({
                "QueueName": "once.fifo",
                "Attributes": { "FifoQueue": "true", "ContentBasedDeduplication": "true" }
            })).await;
            let url = cv["QueueUrl"].as_str().unwrap().to_string();
            let mut first_id = None;
            for _ in 0..copies {
                let (_, v) = call_json(&h, "SendMessage", json!({
                    "QueueUrl": url, "MessageBody": body, "MessageGroupId": "g"
                })).await;
                let id = v["MessageId"].as_str().unwrap().to_string();
                match &first_id {
                    None => first_id = Some(id),
                    Some(f) => prop_assert_eq!(&id, f),
                }
            }
            let (_, r) = call_json(&h, "ReceiveMessage", json!({ "QueueUrl": url, "MaxNumberOfMessages": 10 })).await;
            prop_assert_eq!(r["Messages"].as_array().unwrap().len(), 1);
            Ok(())
        }).unwrap();
    }

    /// Property 12: queues with the same name in different scopes are independent.
    #[test]
    fn region_account_scoping(name in ident()) {
        let h = SqsHandler::new();
        rt().block_on(async {
            // Same name, two accounts (encoded via QueueOwnerAWSAccountId resolution on the URL).
            let url1 = create(&h, &name).await;
            // A queue URL for a different account that does not exist must not resolve.
            let other = format!("https://sqs.us-east-1.amazonaws.com/999999999999/{name}");
            let (s, v) = call_json(&h, "GetQueueAttributes", json!({ "QueueUrl": other })).await;
            prop_assert_eq!(s, 400);
            prop_assert!(v["__type"].as_str().unwrap().contains("QueueDoesNotExist"));
            // The real one still resolves.
            let (s2, _) = call_json(&h, "GetQueueAttributes", json!({ "QueueUrl": url1 })).await;
            prop_assert_eq!(s2, 200);
            Ok(())
        }).unwrap();
    }
}

/// Property 7 & 11 use timing/visibility and are deterministic with a fixed visibility of 0,
/// so they live as focused async tests rather than randomized properties.
#[tokio::test]
async fn visibility_redelivery_increments_receive_count() {
    let h = SqsHandler::new();
    let url = create(&h, "vis").await;
    call_json(
        &h,
        "SendMessage",
        json!({ "QueueUrl": url, "MessageBody": "x" }),
    )
    .await;
    let (_, r1) = call_json(
        &h,
        "ReceiveMessage",
        json!({ "QueueUrl": url, "AttributeNames": ["All"] }),
    )
    .await;
    let handle = r1["Messages"][0]["ReceiptHandle"]
        .as_str()
        .unwrap()
        .to_string();
    // Invisible immediately after receive.
    let (_, empty) = call_json(&h, "ReceiveMessage", json!({ "QueueUrl": url })).await;
    assert!(empty.get("Messages").is_none());
    // Reset visibility → redelivered with an incremented receive count.
    call_json(
        &h,
        "ChangeMessageVisibility",
        json!({ "QueueUrl": url, "ReceiptHandle": handle, "VisibilityTimeout": 0 }),
    )
    .await;
    let (_, r2) = call_json(
        &h,
        "ReceiveMessage",
        json!({ "QueueUrl": url, "AttributeNames": ["All"] }),
    )
    .await;
    assert_eq!(
        r2["Messages"][0]["Attributes"]["ApproximateReceiveCount"],
        "2"
    );
}

#[tokio::test]
async fn redrive_threshold_moves_after_max_receive() {
    let h = SqsHandler::new();
    let dlq_url = create(&h, "dlq").await;
    let redrive = json!({ "deadLetterTargetArn": "arn:aws:sqs:us-east-1:000000000000:dlq", "maxReceiveCount": 2 }).to_string();
    let (_, cv) = call_json(
        &h,
        "CreateQueue",
        json!({
            "QueueName": "src", "Attributes": { "RedrivePolicy": redrive }
        }),
    )
    .await;
    let url = cv["QueueUrl"].as_str().unwrap().to_string();
    call_json(
        &h,
        "SendMessage",
        json!({ "QueueUrl": url, "MessageBody": "poison" }),
    )
    .await;

    // Receive twice (count → 2, the threshold), resetting visibility each time.
    for _ in 0..2 {
        let (_, r) = call_json(&h, "ReceiveMessage", json!({ "QueueUrl": url })).await;
        let handle = r["Messages"][0]["ReceiptHandle"]
            .as_str()
            .unwrap()
            .to_string();
        call_json(
            &h,
            "ChangeMessageVisibility",
            json!({ "QueueUrl": url, "ReceiptHandle": handle, "VisibilityTimeout": 0 }),
        )
        .await;
    }
    // The next receive triggers the move; the source is now empty.
    let (_, r3) = call_json(&h, "ReceiveMessage", json!({ "QueueUrl": url })).await;
    assert!(r3.get("Messages").is_none());
    // The message now lives in the DLQ.
    let (_, d) = call_json(&h, "ReceiveMessage", json!({ "QueueUrl": dlq_url })).await;
    assert_eq!(d["Messages"][0]["Body"], "poison");
}
