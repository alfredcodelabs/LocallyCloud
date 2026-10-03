//! End-to-end tests over both wire protocols, plus the Lambda event-source-mapping (ESM)
//! queue-side consumption contract (design Task 12 / 14).
//!
//! These drive the real in-process `SqsHandler` (no mocks). The JSON path mirrors what the
//! AWS CLI / SDK v3 send (`X-Amz-Target`); the Query path mirrors signed legacy SDK traffic
//! (`Action` form body). Cross-service inbound delivery (S3/SNS/EventBridge → SQS) is
//! validated in the integration layer; SNS→SQS was validated live with the AWS CLI.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use serde_json::{json, Value};

use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_sqs::service::SqsHandler;

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

async fn json_call(h: &SqsHandler, op: &str, body: Value) -> (u16, Value) {
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

async fn query_call(h: &SqsHandler, form: &str) -> (u16, String) {
    let resp = h.handle(query_req(form)).await;
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn json_full_lifecycle() {
    let h = SqsHandler::new();
    let (_, c) = json_call(&h, "CreateQueue", json!({ "QueueName": "lc" })).await;
    let url = c["QueueUrl"].as_str().unwrap().to_string();

    let (s, _) = json_call(
        &h,
        "SendMessage",
        json!({ "QueueUrl": url, "MessageBody": "m1" }),
    )
    .await;
    assert_eq!(s, 200);
    let (_, r) = json_call(&h, "ReceiveMessage", json!({ "QueueUrl": url })).await;
    let handle = r["Messages"][0]["ReceiptHandle"]
        .as_str()
        .unwrap()
        .to_string();
    let (sd, _) = json_call(
        &h,
        "DeleteMessage",
        json!({ "QueueUrl": url, "ReceiptHandle": handle }),
    )
    .await;
    assert_eq!(sd, 200);
    // Tag round-trip.
    json_call(
        &h,
        "TagQueue",
        json!({ "QueueUrl": url, "Tags": { "team": "core" } }),
    )
    .await;
    let (_, t) = json_call(&h, "ListQueueTags", json!({ "QueueUrl": url })).await;
    assert_eq!(t["Tags"]["team"], "core");
}

#[tokio::test]
async fn query_full_lifecycle() {
    let h = SqsHandler::new();
    let (sc, create) = query_call(&h, "Action=CreateQueue&QueueName=qlc").await;
    assert_eq!(sc, 200);
    assert!(create
        .contains("<QueueUrl>https://sqs.us-east-1.amazonaws.com/000000000000/qlc</QueueUrl>"));
    let url = "https://sqs.us-east-1.amazonaws.com/000000000000/qlc";

    let (ss, send) = query_call(
        &h,
        &format!("Action=SendMessage&QueueUrl={url}&MessageBody=hello"),
    )
    .await;
    assert_eq!(ss, 200);
    assert!(send.contains("<MD5OfMessageBody>5d41402abc4b2a76b9719d911017c592</MD5OfMessageBody>"));

    let (sr, recv) = query_call(
        &h,
        &format!("Action=ReceiveMessage&QueueUrl={url}&AttributeName.1=All"),
    )
    .await;
    assert_eq!(sr, 200);
    assert!(recv.contains("<Body>hello</Body>"));
    assert!(
        recv.contains("<Attribute><Name>SenderId</Name><Value>000000000000</Value></Attribute>")
    );

    // Batch send via Query, then assert both entries succeed in the XML.
    let (sb, batch) = query_call(
        &h,
        &format!("Action=SendMessageBatch&QueueUrl={url}&SendMessageBatchRequestEntry.1.Id=a&SendMessageBatchRequestEntry.1.MessageBody=one&SendMessageBatchRequestEntry.2.Id=b&SendMessageBatchRequestEntry.2.MessageBody=two"),
    )
    .await;
    assert_eq!(sb, 200);
    assert_eq!(batch.matches("<SendMessageBatchResultEntry>").count(), 2);

    // Tags via Query.
    query_call(
        &h,
        &format!("Action=TagQueue&QueueUrl={url}&Tag.1.Key=env&Tag.1.Value=prod"),
    )
    .await;
    let (_, tags) = query_call(&h, &format!("Action=ListQueueTags&QueueUrl={url}")).await;
    assert!(tags.contains("<Tag><Key>env</Key><Value>prod</Value></Tag>"));
}

#[tokio::test]
async fn query_message_attributes_round_trip() {
    let h = SqsHandler::new();
    query_call(&h, "Action=CreateQueue&QueueName=qattr").await;
    let url = "https://sqs.us-east-1.amazonaws.com/000000000000/qattr";
    let (s, _) = query_call(
        &h,
        &format!("Action=SendMessage&QueueUrl={url}&MessageBody=b&MessageAttribute.1.Name=color&MessageAttribute.1.Value.DataType=String&MessageAttribute.1.Value.StringValue=blue"),
    )
    .await;
    assert_eq!(s, 200);
    let (_, recv) = query_call(
        &h,
        &format!("Action=ReceiveMessage&QueueUrl={url}&MessageAttributeName.1=All"),
    )
    .await;
    assert!(recv.contains("<MessageAttribute><Name>color</Name><Value><DataType>String</DataType><StringValue>blue</StringValue></Value></MessageAttribute>"));
}

/// The Lambda ESM queue-side consumption contract (Task 12): a poller reads up to the batch
/// size, deletes the messages it successfully processed, and leaves the rest to be
/// redelivered after the visibility timeout; messages that exceed `maxReceiveCount` move to
/// the DLQ exactly once.
#[tokio::test]
async fn esm_consumption_contract() {
    let h = SqsHandler::new();
    let (_, dlq) = json_call(&h, "CreateQueue", json!({ "QueueName": "esm-dlq" })).await;
    let dlq_url = dlq["QueueUrl"].as_str().unwrap().to_string();
    let redrive =
        json!({ "deadLetterTargetArn": "arn:aws:sqs:us-east-1:000000000000:esm-dlq", "maxReceiveCount": 1 }).to_string();
    let (_, src) = json_call(
        &h,
        "CreateQueue",
        json!({
            "QueueName": "esm-src", "Attributes": { "RedrivePolicy": redrive }
        }),
    )
    .await;
    let url = src["QueueUrl"].as_str().unwrap().to_string();

    // Produce a batch of 5 messages.
    let entries: Vec<Value> = (0..5)
        .map(|i| json!({ "Id": format!("e{i}"), "MessageBody": format!("body-{i}") }))
        .collect();
    json_call(
        &h,
        "SendMessageBatch",
        json!({ "QueueUrl": url, "Entries": entries }),
    )
    .await;

    // Poll with batch size 3 (≤ MaxNumberOfMessages contract).
    let (_, batch1) = json_call(
        &h,
        "ReceiveMessage",
        json!({ "QueueUrl": url, "MaxNumberOfMessages": 3 }),
    )
    .await;
    let received = batch1["Messages"].as_array().unwrap();
    assert!(received.len() <= 3 && !received.is_empty());

    // Process (delete) all but one; the undeleted one stays in flight (visibility on failure).
    let to_delete: Vec<Value> = received
        .iter()
        .skip(1)
        .map(|m| json!({ "Id": m["MessageId"], "ReceiptHandle": m["ReceiptHandle"] }))
        .collect();
    let undeleted_handle = received[0]["ReceiptHandle"].as_str().unwrap().to_string();
    let (sd, del) = json_call(
        &h,
        "DeleteMessageBatch",
        json!({ "QueueUrl": url, "Entries": to_delete }),
    )
    .await;
    assert_eq!(sd, 200);
    assert_eq!(
        del["Successful"].as_array().unwrap().len(),
        received.len() - 1
    );

    // Reset visibility on the undeleted message → redelivered; its receive count reaches the
    // redrive threshold, so the following poll moves it to the DLQ.
    json_call(
        &h,
        "ChangeMessageVisibility",
        json!({ "QueueUrl": url, "ReceiptHandle": undeleted_handle, "VisibilityTimeout": 0 }),
    )
    .await;
    // Drain remaining visible messages until the poison message is moved to the DLQ.
    for _ in 0..6 {
        let (_, poll) = json_call(
            &h,
            "ReceiveMessage",
            json!({ "QueueUrl": url, "MaxNumberOfMessages": 10, "VisibilityTimeout": 0 }),
        )
        .await;
        if poll.get("Messages").is_none() {
            break;
        }
    }
    // The poison message now lives in the DLQ.
    let (_, dlq_recv) = json_call(
        &h,
        "ReceiveMessage",
        json!({ "QueueUrl": dlq_url, "MaxNumberOfMessages": 10 }),
    )
    .await;
    let dlq_bodies: Vec<String> = dlq_recv["Messages"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|m| m["Body"].as_str().unwrap().to_string())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        dlq_bodies.contains(&"body-0".to_string()),
        "undeleted message should redrive to the DLQ"
    );
}

#[tokio::test]
async fn cross_protocol_visibility_is_shared() {
    // A message sent over JSON is receivable over Query (same store, one queue).
    let h = SqsHandler::new();
    json_call(&h, "CreateQueue", json!({ "QueueName": "xp" })).await;
    let url = "https://sqs.us-east-1.amazonaws.com/000000000000/xp";
    json_call(
        &h,
        "SendMessage",
        json!({ "QueueUrl": url, "MessageBody": "cross" }),
    )
    .await;
    let (_, recv) = query_call(&h, &format!("Action=ReceiveMessage&QueueUrl={url}")).await;
    assert!(recv.contains("<Body>cross</Body>"));
}

#[tokio::test]
async fn invalid_attribute_update_is_atomic() {
    let h = SqsHandler::new();
    let url = json_call(&h, "CreateQueue", json!({ "QueueName": "atomic-attrs" }))
        .await
        .1["QueueUrl"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _) = json_call(
        &h,
        "SetQueueAttributes",
        json!({ "QueueUrl": url, "Attributes": {
            "DelaySeconds": "10", "UnknownAttribute": "x"
        }}),
    )
    .await;
    assert_eq!(status, 400);
    let (_, attributes) = json_call(
        &h,
        "GetQueueAttributes",
        json!({ "QueueUrl": url, "AttributeNames": ["DelaySeconds"] }),
    )
    .await;
    assert_eq!(attributes["Attributes"]["DelaySeconds"], "0");
}

#[tokio::test]
async fn list_queues_uses_validated_stable_tokens() {
    let h = SqsHandler::new();
    for name in ["page-a", "page-b", "page-c"] {
        json_call(&h, "CreateQueue", json!({ "QueueName": name })).await;
    }
    let (_, first) = json_call(&h, "ListQueues", json!({ "MaxResults": 2 })).await;
    assert_eq!(first["QueueUrls"].as_array().unwrap().len(), 2);
    let token = first["NextToken"].as_str().unwrap();
    let (_, second) = json_call(
        &h,
        "ListQueues",
        json!({ "MaxResults": 2, "NextToken": token }),
    )
    .await;
    assert_eq!(second["QueueUrls"].as_array().unwrap().len(), 1);
    assert!(second.get("NextToken").is_none());
    let (status, _) = json_call(
        &h,
        "ListQueues",
        json!({ "MaxResults": 2, "NextToken": "invalid" }),
    )
    .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn fifo_duplicate_returns_original_sequence_number() {
    let h = SqsHandler::new();
    let (_, created) = json_call(
        &h,
        "CreateQueue",
        json!({ "QueueName": "sequence.fifo", "Attributes": { "FifoQueue": "true" } }),
    )
    .await;
    let url = created["QueueUrl"].as_str().unwrap();
    let (_, first) = json_call(
        &h,
        "SendMessage",
        json!({ "QueueUrl": url, "MessageBody": "one", "MessageGroupId": "g", "MessageDeduplicationId": "d1" }),
    )
    .await;
    json_call(
        &h,
        "SendMessage",
        json!({ "QueueUrl": url, "MessageBody": "two", "MessageGroupId": "g", "MessageDeduplicationId": "d2" }),
    )
    .await;
    let (_, duplicate) = json_call(
        &h,
        "SendMessage",
        json!({ "QueueUrl": url, "MessageBody": "one", "MessageGroupId": "g", "MessageDeduplicationId": "d1" }),
    )
    .await;
    assert_eq!(duplicate["MessageId"], first["MessageId"]);
    assert_eq!(duplicate["SequenceNumber"], first["SequenceNumber"]);
}

#[tokio::test]
async fn fifo_receive_attempt_replays_the_same_delivery() {
    let h = SqsHandler::new();
    let (_, created) = json_call(
        &h,
        "CreateQueue",
        json!({ "QueueName": "receive-attempt.fifo", "Attributes": { "FifoQueue": "true" } }),
    )
    .await;
    let url = created["QueueUrl"].as_str().unwrap();
    json_call(
        &h,
        "SendMessage",
        json!({ "QueueUrl": url, "MessageBody": "body", "MessageGroupId": "g", "MessageDeduplicationId": "d" }),
    )
    .await;
    let request = json!({ "QueueUrl": url, "ReceiveRequestAttemptId": "attempt-1" });
    let (_, first) = json_call(&h, "ReceiveMessage", request.clone()).await;
    let (_, second) = json_call(&h, "ReceiveMessage", request).await;
    assert_eq!(first["Messages"], second["Messages"]);
}

#[tokio::test]
async fn missing_dlq_never_removes_the_source_message() {
    let h = SqsHandler::new();
    let (_, dlq) = json_call(&h, "CreateQueue", json!({ "QueueName": "gone-dlq" })).await;
    let dlq_url = dlq["QueueUrl"].as_str().unwrap().to_string();
    let redrive = json!({
        "deadLetterTargetArn": "arn:aws:sqs:us-east-1:000000000000:gone-dlq",
        "maxReceiveCount": 1
    })
    .to_string();
    let (_, source) = json_call(
        &h,
        "CreateQueue",
        json!({ "QueueName": "gone-source", "Attributes": { "RedrivePolicy": redrive } }),
    )
    .await;
    let source_url = source["QueueUrl"].as_str().unwrap().to_string();
    json_call(
        &h,
        "SendMessage",
        json!({ "QueueUrl": source_url, "MessageBody": "preserve" }),
    )
    .await;
    let (_, received) = json_call(&h, "ReceiveMessage", json!({ "QueueUrl": source_url })).await;
    json_call(
        &h,
        "ChangeMessageVisibility",
        json!({ "QueueUrl": source_url, "ReceiptHandle": received["Messages"][0]["ReceiptHandle"], "VisibilityTimeout": 0 }),
    )
    .await;
    json_call(&h, "DeleteQueue", json!({ "QueueUrl": dlq_url })).await;
    let (status, _) = json_call(&h, "ReceiveMessage", json!({ "QueueUrl": source_url })).await;
    assert_eq!(status, 400);
    let (_, attributes) = json_call(
        &h,
        "GetQueueAttributes",
        json!({ "QueueUrl": source_url, "AttributeNames": ["ApproximateNumberOfMessages"] }),
    )
    .await;
    assert_eq!(attributes["Attributes"]["ApproximateNumberOfMessages"], "1");
}

#[tokio::test]
async fn deny_all_redrive_policy_preserves_source_message() {
    let h = SqsHandler::new();
    let (_, dlq) = json_call(&h, "CreateQueue", json!({ "QueueName": "deny-dlq" })).await;
    let dlq_url = dlq["QueueUrl"].as_str().unwrap().to_string();
    let redrive = json!({
        "deadLetterTargetArn": "arn:aws:sqs:us-east-1:000000000000:deny-dlq",
        "maxReceiveCount": 1
    })
    .to_string();
    let (_, source) = json_call(
        &h,
        "CreateQueue",
        json!({ "QueueName": "deny-source", "Attributes": { "RedrivePolicy": redrive } }),
    )
    .await;
    let source_url = source["QueueUrl"].as_str().unwrap().to_string();
    let deny = json!({ "redrivePermission": "denyAll" }).to_string();
    json_call(
        &h,
        "SetQueueAttributes",
        json!({ "QueueUrl": dlq_url, "Attributes": { "RedriveAllowPolicy": deny } }),
    )
    .await;
    json_call(
        &h,
        "SendMessage",
        json!({ "QueueUrl": source_url, "MessageBody": "preserve" }),
    )
    .await;
    let (_, received) = json_call(&h, "ReceiveMessage", json!({ "QueueUrl": source_url })).await;
    json_call(
        &h,
        "ChangeMessageVisibility",
        json!({ "QueueUrl": source_url, "ReceiptHandle": received["Messages"][0]["ReceiptHandle"], "VisibilityTimeout": 0 }),
    )
    .await;
    let (status, _) = json_call(&h, "ReceiveMessage", json!({ "QueueUrl": source_url })).await;
    assert_eq!(status, 400);
    let (_, attributes) = json_call(
        &h,
        "GetQueueAttributes",
        json!({ "QueueUrl": source_url, "AttributeNames": ["ApproximateNumberOfMessages"] }),
    )
    .await;
    assert_eq!(attributes["Attributes"]["ApproximateNumberOfMessages"], "1");
}

#[tokio::test]
async fn message_move_task_is_running_and_cancellable() {
    let h = SqsHandler::new();
    let (_, dlq) = json_call(&h, "CreateQueue", json!({ "QueueName": "move-dlq" })).await;
    let dlq_url = dlq["QueueUrl"].as_str().unwrap().to_string();
    let redrive = json!({
        "deadLetterTargetArn": "arn:aws:sqs:us-east-1:000000000000:move-dlq",
        "maxReceiveCount": 2
    })
    .to_string();
    json_call(
        &h,
        "CreateQueue",
        json!({ "QueueName": "move-source", "Attributes": { "RedrivePolicy": redrive } }),
    )
    .await;
    for body in ["one", "two", "three"] {
        json_call(
            &h,
            "SendMessage",
            json!({ "QueueUrl": dlq_url, "MessageBody": body }),
        )
        .await;
    }
    let source_arn = "arn:aws:sqs:us-east-1:000000000000:move-dlq";
    let (_, started) = json_call(
        &h,
        "StartMessageMoveTask",
        json!({ "SourceArn": source_arn, "MaxNumberOfMessagesPerSecond": 1 }),
    )
    .await;
    let handle = started["TaskHandle"].as_str().unwrap();
    let (_, cancelled) =
        json_call(&h, "CancelMessageMoveTask", json!({ "TaskHandle": handle })).await;
    assert!(cancelled["ApproximateNumberOfMessagesMoved"].is_number());
    let (_, listed) = json_call(
        &h,
        "ListMessageMoveTasks",
        json!({ "SourceArn": source_arn, "MaxResults": 10 }),
    )
    .await;
    assert_eq!(listed["Results"][0]["Status"], "CANCELLED");
    assert_eq!(listed["Results"][0]["MaxNumberOfMessagesPerSecond"], 1);
    assert_eq!(listed["Results"][0]["ApproximateNumberOfMessagesToMove"], 3);
    let (status, _) = json_call(&h, "CancelMessageMoveTask", json!({ "TaskHandle": handle })).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn receive_rejects_out_of_range_values() {
    let h = SqsHandler::new();
    let url = json_call(&h, "CreateQueue", json!({ "QueueName": "receive-bounds" }))
        .await
        .1["QueueUrl"]
        .as_str()
        .unwrap()
        .to_string();
    for body in [
        json!({ "QueueUrl": url, "MaxNumberOfMessages": 11 }),
        json!({ "QueueUrl": url, "WaitTimeSeconds": 21 }),
        json!({ "QueueUrl": url, "VisibilityTimeout": 43_201 }),
    ] {
        assert_eq!(json_call(&h, "ReceiveMessage", body).await.0, 400);
    }
}

#[tokio::test]
async fn long_poll_wakes_when_a_delayed_message_becomes_visible() {
    let h = SqsHandler::new();
    let (_, created) = json_call(
        &h,
        "CreateQueue",
        json!({ "QueueName": "delayed-wakeup", "Attributes": { "DelaySeconds": "1" } }),
    )
    .await;
    let url = created["QueueUrl"].as_str().unwrap();
    json_call(
        &h,
        "SendMessage",
        json!({ "QueueUrl": url, "MessageBody": "delayed" }),
    )
    .await;
    let started = std::time::Instant::now();
    let (_, received) = json_call(
        &h,
        "ReceiveMessage",
        json!({ "QueueUrl": url, "WaitTimeSeconds": 2 }),
    )
    .await;
    assert_eq!(received["Messages"][0]["Body"], "delayed");
    assert!(started.elapsed() < std::time::Duration::from_millis(1_800));
}

#[tokio::test]
async fn repeated_purge_is_rejected_during_the_guard_window() {
    let h = SqsHandler::new();
    let url = json_call(&h, "CreateQueue", json!({ "QueueName": "purge-window" }))
        .await
        .1["QueueUrl"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        json_call(&h, "PurgeQueue", json!({ "QueueUrl": url }))
            .await
            .0,
        200
    );
    let (status, error) = json_call(&h, "PurgeQueue", json!({ "QueueUrl": url })).await;
    assert_eq!(status, 400);
    assert!(error["__type"]
        .as_str()
        .unwrap()
        .contains("PurgeQueueInProgress"));
}

#[tokio::test]
async fn malformed_policy_is_rejected_without_replacing_the_previous_policy() {
    let h = SqsHandler::new();
    let url = json_call(&h, "CreateQueue", json!({ "QueueName": "policy-atomic" }))
        .await
        .1["QueueUrl"]
        .as_str()
        .unwrap()
        .to_string();
    let valid = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": ["sqs:SendMessage", "sqs:SetQueueAttributes", "sqs:GetQueueAttributes"],
            "Resource": "arn:aws:sqs:us-east-1:000000000000:policy-atomic"
        }]
    })
    .to_string();
    assert_eq!(
        json_call(
            &h,
            "SetQueueAttributes",
            json!({ "QueueUrl": url, "Attributes": { "Policy": valid } }),
        )
        .await
        .0,
        200
    );
    let malformed = json!({ "Statement": [{ "Action": "sqs:*", "Resource": "*" }] }).to_string();
    assert_eq!(
        json_call(
            &h,
            "SetQueueAttributes",
            json!({ "QueueUrl": url, "Attributes": { "Policy": malformed } }),
        )
        .await
        .0,
        400
    );
    let (_, attributes) = json_call(
        &h,
        "GetQueueAttributes",
        json!({ "QueueUrl": url, "AttributeNames": ["Policy"] }),
    )
    .await;
    assert_eq!(attributes["Attributes"]["Policy"], valid);
}
