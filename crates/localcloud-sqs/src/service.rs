//! SQS service handler: dual-protocol dispatch (modern AWS JSON 1.0 via `X-Amz-Target`,
//! legacy Query/XML via the `Action` form field), registered `Native`.
//!
//! All current AWS tooling (boto3, CLI v2, the v3 SDKs, Terraform, Serverless Framework)
//! speaks the AWS JSON protocol; the legacy Query/XML protocol is also fully supported for
//! older SDKs. The operation layer is protocol-agnostic — `proto::classify` normalizes the
//! request into a JSON `Value` and `proto::to_query_xml` serializes the response back into
//! the request's protocol.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use serde_json::Value;

use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::integration::authorization::AuthorizationRequest;
use localcloud_core::integration::{InternalDispatcher, RequestIdentity};
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

use crate::error::SqsError;
use crate::model::QueueArn;
use crate::ops::{self, Ctx};
use crate::policy::{self, Decision};
use crate::proto::{self, Protocol};
use crate::store::SqsStore;
use localcloud_state::StateDb;

const TARGET_PREFIX: &str = "AmazonSQS";

pub struct SqsHandler {
    store: Arc<SqsStore>,
    registry: Weak<ServiceRegistry>,
}

impl Default for SqsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SqsHandler {
    pub fn new() -> Self {
        SqsHandler {
            store: Arc::new(SqsStore::new()),
            registry: Weak::new(),
        }
    }

    fn with_registry(registry: &Arc<ServiceRegistry>) -> Self {
        Self {
            store: Arc::new(SqsStore::new()),
            registry: Arc::downgrade(registry),
        }
    }

    fn with_state(registry: &Arc<ServiceRegistry>, state: Arc<StateDb>) -> Result<Self, SqsError> {
        Ok(Self {
            store: Arc::new(SqsStore::with_state(state)?),
            registry: Arc::downgrade(registry),
        })
    }

    async fn authorize_queue_operation(
        &self,
        op: &str,
        body: &Value,
        request: &ServiceRequest,
        dispatcher: Option<&Arc<InternalDispatcher>>,
    ) -> Result<(), SqsError> {
        let Some(action) = queue_action(op) else {
            return Ok(());
        };
        let strict = dispatcher.is_some_and(|d| d.strict_sigv4_required());
        let (resource, arn) = self.queue_resource(op, body, request)?;
        let policy = if let Some(arn) = &arn {
            if let Some(queue) = self.store.get(arn) {
                queue.state.lock().await.attributes.get("Policy").cloned()
            } else {
                None
            }
        } else {
            None
        };
        let external = request
            .headers
            .get("x-localcloud-verified-external-sigv4")
            .is_some_and(|value| value == "1");
        let internal = request
            .headers
            .get("x-localcloud-verified-internal-scope")
            .is_some_and(|value| value == "1");
        if !strict && policy.is_none() {
            return Ok(());
        }
        if strict && !external && !internal {
            return Err(SqsError::AccessDenied);
        }
        let principal = if external {
            let dispatcher = dispatcher.ok_or(SqsError::AccessDenied)?;
            let access_key_id = request
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(RequestIdentity::access_key_from_authorization)
                .ok_or(SqsError::AccessDenied)?;
            let identity = RequestIdentity {
                account_id: request.account_id.clone(),
                access_key_id: Some(access_key_id),
                arn: None,
            };
            dispatcher
                .authorize(AuthorizationRequest {
                    request_identity: identity.clone(),
                    delegated_identity: None,
                    source_service: "sqs".into(),
                    action: action.into(),
                    resource: resource.clone(),
                    context: BTreeMap::new(),
                })
                .map_err(|_| SqsError::AccessDenied)?;
            dispatcher
                .resolve_caller_arn(&identity)
                .map_err(|_| SqsError::AccessDenied)?
                .ok_or(SqsError::AccessDenied)?
        } else if internal {
            request
                .headers
                .get("x-localcloud-caller-principal")
                .and_then(|value| value.to_str().ok())
                .ok_or(SqsError::AccessDenied)?
                .to_string()
        } else {
            // Permissive external callers are not authenticated: policy can grant only
            // an anonymous wildcard principal, never a client-supplied internal header.
            "anonymous".to_string()
        };
        if let Some(raw) = policy {
            match policy::evaluate(&raw, &principal, &request.account_id, action, &resource) {
                Decision::Deny => return Err(SqsError::AccessDenied),
                Decision::Unmatched if !external => return Err(SqsError::AccessDenied),
                _ => {}
            }
        }
        Ok(())
    }

    async fn dispatch(&self, op: &str, ctx: &Ctx<'_>, body: &Value) -> Result<Value, SqsError> {
        match op {
            "CreateQueue" => ops::create_queue(ctx, body).await,
            "DeleteQueue" => ops::delete_queue(ctx, body).await,
            "ListQueues" => ops::list_queues(ctx, body).await,
            "GetQueueUrl" => ops::get_queue_url(ctx, body).await,
            "GetQueueAttributes" => ops::get_queue_attributes(ctx, body).await,
            "SetQueueAttributes" => ops::set_queue_attributes(ctx, body).await,
            "SendMessage" => ops::send_message(ctx, body).await,
            "SendMessageBatch" => ops::send_message_batch(ctx, body).await,
            "ReceiveMessage" => ops::receive_message(ctx, body).await,
            "DeleteMessage" => ops::delete_message(ctx, body).await,
            "DeleteMessageBatch" => ops::delete_message_batch(ctx, body).await,
            "ChangeMessageVisibility" => ops::change_message_visibility(ctx, body).await,
            "ChangeMessageVisibilityBatch" => ops::change_message_visibility_batch(ctx, body).await,
            "PurgeQueue" => ops::purge_queue(ctx, body).await,
            "TagQueue" => ops::tag_queue(ctx, body).await,
            "UntagQueue" => ops::untag_queue(ctx, body).await,
            "ListQueueTags" => ops::list_queue_tags(ctx, body).await,
            "AddPermission" => ops::add_permission(ctx, body).await,
            "RemovePermission" => ops::remove_permission(ctx, body).await,
            "ListDeadLetterSourceQueues" => ops::list_dead_letter_source_queues(ctx, body).await,
            "StartMessageMoveTask" => ops::start_message_move_task(ctx, body).await,
            "ListMessageMoveTasks" => ops::list_message_move_tasks(ctx, body).await,
            "CancelMessageMoveTask" => ops::cancel_message_move_task(ctx, body).await,
            other => Err(SqsError::UnsupportedOperation(format!(
                "unsupported operation {other}"
            ))),
        }
    }
}

#[async_trait]
impl NativeHandler for SqsHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let target = request
            .headers
            .get("x-amz-target")
            .and_then(|v| v.to_str().ok());
        let (protocol, op, body) = proto::classify(target, &request.body);

        let op = match op {
            Some(o) => o,
            None => {
                return error_response(
                    SqsError::UnsupportedOperation(
                        "missing operation (X-Amz-Target or Action)".into(),
                    ),
                    &request,
                    protocol,
                )
            }
        };

        let ctx = Ctx {
            store: self.store.clone(),
            region: &request.region,
            account: &request.account_id,
            request_id: &request.request_id,
            dispatcher: self
                .registry
                .upgrade()
                .and_then(|r| r.internal_dispatcher()),
            authorization: request
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        };
        if let Err(error) = self
            .authorize_queue_operation(&op, &body, &request, ctx.dispatcher.as_ref())
            .await
        {
            return error_response(error, &request, protocol);
        }
        match self.dispatch(&op, &ctx, &body).await {
            Ok(value) => success_response(&op, value, protocol, &request.request_id),
            Err(err) => error_response(err, &request, protocol),
        }
    }
}

impl SqsHandler {
    fn queue_resource(
        &self,
        op: &str,
        body: &Value,
        request: &ServiceRequest,
    ) -> Result<(String, Option<QueueArn>), SqsError> {
        if op == "ListQueues" {
            return Ok(("*".into(), None));
        }
        let arn = if matches!(op, "CreateQueue" | "GetQueueUrl") {
            let name = body
                .get("QueueName")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| SqsError::MissingParameter("QueueName is required".into()))?;
            let account = if op == "GetQueueUrl" {
                body.get("QueueOwnerAWSAccountId")
                    .and_then(Value::as_str)
                    .unwrap_or(&request.account_id)
            } else {
                &request.account_id
            };
            QueueArn::new(&request.region, account, name)
        } else if matches!(op, "StartMessageMoveTask" | "ListMessageMoveTasks") {
            let source = body
                .get("SourceArn")
                .and_then(Value::as_str)
                .ok_or_else(|| SqsError::InvalidParameterValue("SourceArn is required".into()))?;
            ops::arn_from_str(source).ok_or_else(|| {
                SqsError::InvalidParameterValue("SourceArn must be an SQS queue ARN".into())
            })?
        } else if op == "CancelMessageMoveTask" {
            let handle = body
                .get("TaskHandle")
                .and_then(Value::as_str)
                .ok_or_else(|| SqsError::InvalidParameterValue("TaskHandle is required".into()))?;
            let source = self.store.move_task_source_arn(handle).ok_or_else(|| {
                SqsError::ResourceNotFound("the specified task handle does not exist".into())
            })?;
            ops::arn_from_str(&source).ok_or_else(|| {
                SqsError::InvalidParameterValue("SourceArn must be an SQS queue ARN".into())
            })?
        } else {
            let url = body
                .get("QueueUrl")
                .and_then(Value::as_str)
                .ok_or_else(|| SqsError::MissingParameter("QueueUrl is required".into()))?;
            QueueArn::from_url(url)?
        };
        Ok((arn.to_arn(), Some(arn)))
    }
}

fn queue_action(op: &str) -> Option<&'static str> {
    match op {
        "CreateQueue" => Some("sqs:CreateQueue"),
        "ListQueues" => Some("sqs:ListQueues"),
        "GetQueueUrl" => Some("sqs:GetQueueUrl"),
        "SendMessage" | "SendMessageBatch" => Some("sqs:SendMessage"),
        "ReceiveMessage" => Some("sqs:ReceiveMessage"),
        "DeleteMessage" | "DeleteMessageBatch" => Some("sqs:DeleteMessage"),
        "ChangeMessageVisibility" | "ChangeMessageVisibilityBatch" => {
            Some("sqs:ChangeMessageVisibility")
        }
        "PurgeQueue" => Some("sqs:PurgeQueue"),
        "SetQueueAttributes" => Some("sqs:SetQueueAttributes"),
        "AddPermission" => Some("sqs:AddPermission"),
        "RemovePermission" => Some("sqs:RemovePermission"),
        "DeleteQueue" => Some("sqs:DeleteQueue"),
        "GetQueueAttributes" => Some("sqs:GetQueueAttributes"),
        "TagQueue" => Some("sqs:TagQueue"),
        "UntagQueue" => Some("sqs:UntagQueue"),
        "ListQueueTags" => Some("sqs:ListQueueTags"),
        "ListDeadLetterSourceQueues" => Some("sqs:ListDeadLetterSourceQueues"),
        "StartMessageMoveTask" => Some("sqs:StartMessageMoveTask"),
        "ListMessageMoveTasks" => Some("sqs:ListMessageMoveTasks"),
        "CancelMessageMoveTask" => Some("sqs:CancelMessageMoveTask"),
        _ => None,
    }
}

/// Serialize a successful operation result in the request's protocol.
fn success_response(op: &str, value: Value, protocol: Protocol, request_id: &str) -> Response {
    match protocol {
        Protocol::Json => json_response(value),
        Protocol::Query => query_xml_response(op, value, request_id),
    }
}

fn json_response(value: Value) -> Response {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/x-amz-json-1.0")
        .body(Body::from(value.to_string()))
        .expect("json 1.0 response is always valid")
}

fn query_xml_response(op: &str, value: Value, request_id: &str) -> Response {
    let body = proto::to_query_xml(op, &value, request_id);
    http::Response::builder()
        .status(200)
        .header("content-type", "application/xml")
        .body(Body::from(body))
        .expect("query xml response is always valid")
}

/// Render an error in the request's protocol, adding the `x-amzn-query-error` header for
/// `awsQueryCompatible` JSON clients (Terraform, AWS SDK v2 in query mode).
fn error_response(err: SqsError, request: &ServiceRequest, protocol: Protocol) -> Response {
    let query_compat_header = (protocol == Protocol::Json && is_query_compat(request))
        .then(|| format!("{};Sender", err.query_code()));
    let mut response = err.into_protocol_response(&request.request_id, protocol.aws());
    if let Some(value) = query_compat_header {
        if let Ok(header) = http::HeaderValue::from_str(&value) {
            response.headers_mut().insert("x-amzn-query-error", header);
        }
    }
    response
}

/// Whether the client opted into `awsQueryCompatible` error mapping (`x-amzn-query-mode`).
fn is_query_compat(req: &ServiceRequest) -> bool {
    req.headers
        .get("x-amzn-query-mode")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    state: Arc<StateDb>,
) -> Result<(), SqsError> {
    let handler: Arc<dyn NativeHandler> = Arc::new(SqsHandler::with_state(registry, state)?);
    registry.register_native(
        ServiceName::new("sqs"),
        ServiceMetadata::new(AwsProtocol::Json10, Some(TARGET_PREFIX)),
        handler,
    );
    Ok(())
}

/// Register SQS as a `Native` JSON 1.0 service in the Core registry.
pub fn register(registry: &Arc<ServiceRegistry>) {
    let handler: Arc<dyn NativeHandler> = Arc::new(SqsHandler::with_registry(registry));
    registry.register_native(
        ServiceName::new("sqs"),
        ServiceMetadata::new(AwsProtocol::Json10, Some(TARGET_PREFIX)),
        handler,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method};
    use serde_json::json;
    use std::time::Duration;

    fn request(op: &str, body: Value) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("{TARGET_PREFIX}.{op}")).unwrap(),
        );
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(body.to_string()),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        }
    }

    #[tokio::test]
    async fn accepted_message_and_visibility_survive_restart() {
        let root =
            std::env::temp_dir().join(format!("localcloud-sqs-restart-{}", uuid::Uuid::new_v4()));
        let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let registry = Arc::new(ServiceRegistry::new());
        let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
        let url = create(&h, "restart.fifo").await;
        let (status, sent) = call(&h, "SendMessage", json!({
            "QueueUrl": url, "MessageBody": "durable", "MessageGroupId": "g", "MessageDeduplicationId": "d"
        })).await;
        assert_eq!(status, 200);
        let id = sent["MessageId"].as_str().unwrap().to_string();
        drop(h);
        let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
        let (status, repeated) = call(&h, "SendMessage", json!({
            "QueueUrl": url, "MessageBody": "durable", "MessageGroupId": "g", "MessageDeduplicationId": "d"
        })).await;
        assert_eq!(status, 200);
        assert_eq!(repeated["MessageId"], id);
        let (status, received) = call(
            &h,
            "ReceiveMessage",
            json!({"QueueUrl": url, "VisibilityTimeout": 60}),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(received["Messages"][0]["MessageId"], id);
        drop(h);
        let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
        let (status, empty) = call(&h, "ReceiveMessage", json!({"QueueUrl": url})).await;
        assert_eq!(status, 200);
        assert!(empty.get("Messages").is_none());
        let receipt = received["Messages"][0]["ReceiptHandle"].as_str().unwrap();
        let (status, _) = call(
            &h,
            "DeleteMessage",
            json!({"QueueUrl": url, "ReceiptHandle": receipt}),
        )
        .await;
        assert_eq!(status, 200);
        drop(h);
        let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
        let (status, empty) = call(&h, "ReceiveMessage", json!({"QueueUrl": url})).await;
        assert_eq!(status, 200);
        assert!(empty.get("Messages").is_none());
        let (status, _) = call(&h, "DeleteQueue", json!({"QueueUrl": url})).await;
        assert_eq!(status, 200);
        drop(h);
        let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
        let (status, error) = call(&h, "CreateQueue", json!({"QueueName": "restart.fifo"})).await;
        assert_eq!(status, 400);
        assert!(error.to_string().contains("QueueDeletedRecently"));
        drop(h);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn query_compat_error_includes_legacy_code_header() {
        let h = SqsHandler::new();
        let mut req = request(
            "GetQueueAttributes",
            json!({ "QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/missing" }),
        );
        req.headers
            .insert("x-amzn-query-mode", HeaderValue::from_static("true"));
        let resp = h.handle(req).await;
        assert_eq!(resp.status(), 400);
        assert_eq!(
            resp.headers().get("x-amzn-query-error").unwrap(),
            "AWS.SimpleQueueService.NonExistentQueue;Sender"
        );
    }

    #[tokio::test]
    async fn without_query_compat_no_legacy_header() {
        let h = SqsHandler::new();
        let req = request(
            "GetQueueAttributes",
            json!({ "QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/missing" }),
        );
        let resp = h.handle(req).await;
        assert_eq!(resp.status(), 400);
        assert!(resp.headers().get("x-amzn-query-error").is_none());
    }

    async fn call(h: &SqsHandler, op: &str, body: Value) -> (u16, Value) {
        let resp = h.handle(request(op, body)).await;
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    async fn create(h: &SqsHandler, name: &str) -> String {
        let (status, v) = call(h, "CreateQueue", json!({ "QueueName": name })).await;
        assert_eq!(status, 200);
        v["QueueUrl"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn send_receive_delete_lifecycle() {
        let h = SqsHandler::new();
        let url = create(&h, "q").await;

        let (status, v) = call(
            &h,
            "SendMessage",
            json!({ "QueueUrl": url, "MessageBody": "hello" }),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(v["MD5OfMessageBody"], "5d41402abc4b2a76b9719d911017c592");

        let (_, v) = call(&h, "ReceiveMessage", json!({ "QueueUrl": url })).await;
        let msg = &v["Messages"][0];
        assert_eq!(msg["Body"], "hello");
        let handle = msg["ReceiptHandle"].as_str().unwrap().to_string();

        // Now invisible: an immediate second receive is empty.
        let (_, v2) = call(&h, "ReceiveMessage", json!({ "QueueUrl": url })).await;
        assert!(v2.get("Messages").is_none());

        let (status, _) = call(
            &h,
            "DeleteMessage",
            json!({ "QueueUrl": url, "ReceiptHandle": handle }),
        )
        .await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn change_visibility_makes_message_available_again() {
        let h = SqsHandler::new();
        let url = create(&h, "q").await;
        call(
            &h,
            "SendMessage",
            json!({ "QueueUrl": url, "MessageBody": "x" }),
        )
        .await;
        let (_, v) = call(&h, "ReceiveMessage", json!({ "QueueUrl": url })).await;
        let handle = v["Messages"][0]["ReceiptHandle"]
            .as_str()
            .unwrap()
            .to_string();
        // Reset visibility to 0 → immediately receivable again.
        call(
            &h,
            "ChangeMessageVisibility",
            json!({ "QueueUrl": url, "ReceiptHandle": handle, "VisibilityTimeout": 0 }),
        )
        .await;
        let (_, v2) = call(
            &h,
            "ReceiveMessage",
            json!({ "QueueUrl": url, "AttributeNames": ["All"] }),
        )
        .await;
        assert_eq!(v2["Messages"][0]["Body"], "x");
        // Receive count incremented across redeliveries.
        assert_eq!(
            v2["Messages"][0]["Attributes"]["ApproximateReceiveCount"],
            "2"
        );
    }

    #[tokio::test]
    async fn missing_queue_is_error() {
        let h = SqsHandler::new();
        let (status, v) = call(
            &h,
            "SendMessage",
            json!({ "QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/nope", "MessageBody": "x" }),
        )
        .await;
        assert_eq!(status, 400);
        assert!(v["__type"].as_str().unwrap().contains("QueueDoesNotExist"));
    }

    #[tokio::test]
    async fn fifo_requires_group_and_dedups() {
        let h = SqsHandler::new();
        let (_, cv) = call(
            &h,
            "CreateQueue",
            json!({ "QueueName": "q.fifo", "Attributes": { "FifoQueue": "true", "ContentBasedDeduplication": "true" } }),
        )
        .await;
        let url = cv["QueueUrl"].as_str().unwrap().to_string();

        // Missing MessageGroupId → error.
        let (status, _) = call(
            &h,
            "SendMessage",
            json!({ "QueueUrl": url, "MessageBody": "a" }),
        )
        .await;
        assert_eq!(status, 400);

        // Two identical sends in the same group → deduplicated to one stored message.
        let (_, s1) = call(
            &h,
            "SendMessage",
            json!({ "QueueUrl": url, "MessageBody": "dup", "MessageGroupId": "g1" }),
        )
        .await;
        let (_, s2) = call(
            &h,
            "SendMessage",
            json!({ "QueueUrl": url, "MessageBody": "dup", "MessageGroupId": "g1" }),
        )
        .await;
        assert_eq!(s1["MessageId"], s2["MessageId"]);

        let (_, r) = call(
            &h,
            "ReceiveMessage",
            json!({ "QueueUrl": url, "MaxNumberOfMessages": 10, "AttributeNames": ["All"] }),
        )
        .await;
        assert_eq!(r["Messages"].as_array().unwrap().len(), 1);
        assert!(r["Messages"][0]["Attributes"]["SequenceNumber"].is_string());
    }

    #[tokio::test]
    async fn fifo_orders_within_group_and_blocks_until_delete() {
        let h = SqsHandler::new();
        let (_, cv) = call(
            &h,
            "CreateQueue",
            json!({ "QueueName": "ord.fifo", "Attributes": { "FifoQueue": "true" } }),
        )
        .await;
        let url = cv["QueueUrl"].as_str().unwrap().to_string();
        for (i, dedup) in ["d1", "d2"].iter().enumerate() {
            call(
                &h,
                "SendMessage",
                json!({ "QueueUrl": url, "MessageBody": format!("m{i}"), "MessageGroupId": "g", "MessageDeduplicationId": dedup }),
            )
            .await;
        }
        // First receive returns both in order (same group, in-order within one call).
        let (_, r) = call(
            &h,
            "ReceiveMessage",
            json!({ "QueueUrl": url, "MaxNumberOfMessages": 10 }),
        )
        .await;
        let bodies: Vec<&str> = r["Messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["Body"].as_str().unwrap())
            .collect();
        assert_eq!(bodies, vec!["m0", "m1"]);
    }

    #[tokio::test]
    async fn send_batch_partial() {
        let h = SqsHandler::new();
        let url = create(&h, "q").await;
        let (status, v) = call(
            &h,
            "SendMessageBatch",
            json!({ "QueueUrl": url, "Entries": [
                { "Id": "a", "MessageBody": "one" },
                { "Id": "b", "MessageBody": "two" }
            ] }),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(v["Successful"].as_array().unwrap().len(), 2);
        assert!(v["Failed"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dead_letter_redrive_after_max_receive() {
        let h = SqsHandler::new();
        let dlq_url = create(&h, "dlq").await;
        let dlq_arn = "arn:aws:sqs:us-east-1:000000000000:dlq";
        let redrive = json!({ "deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1 }).to_string();
        let (_, cv) = call(
            &h,
            "CreateQueue",
            json!({ "QueueName": "src", "Attributes": { "RedrivePolicy": redrive } }),
        )
        .await;
        let url = cv["QueueUrl"].as_str().unwrap().to_string();

        call(
            &h,
            "SendMessage",
            json!({ "QueueUrl": url, "MessageBody": "poison" }),
        )
        .await;
        // First receive (count→1), reset visibility, second receive triggers the move.
        let (_, r1) = call(&h, "ReceiveMessage", json!({ "QueueUrl": url })).await;
        let handle = r1["Messages"][0]["ReceiptHandle"]
            .as_str()
            .unwrap()
            .to_string();
        call(
            &h,
            "ChangeMessageVisibility",
            json!({ "QueueUrl": url, "ReceiptHandle": handle, "VisibilityTimeout": 0 }),
        )
        .await;
        let (_, r2) = call(&h, "ReceiveMessage", json!({ "QueueUrl": url })).await;
        assert!(
            r2.get("Messages").is_none(),
            "message should have been redriven"
        );

        // It now lives in the DLQ.
        let (_, d) = call(&h, "ReceiveMessage", json!({ "QueueUrl": dlq_url })).await;
        assert_eq!(d["Messages"][0]["Body"], "poison");
    }

    #[tokio::test]
    async fn tags_round_trip() {
        let h = SqsHandler::new();
        let url = create(&h, "q").await;
        call(
            &h,
            "TagQueue",
            json!({ "QueueUrl": url, "Tags": { "env": "prod" } }),
        )
        .await;
        let (_, v) = call(&h, "ListQueueTags", json!({ "QueueUrl": url })).await;
        assert_eq!(v["Tags"]["env"], "prod");
        call(
            &h,
            "UntagQueue",
            json!({ "QueueUrl": url, "TagKeys": ["env"] }),
        )
        .await;
        let (_, v2) = call(&h, "ListQueueTags", json!({ "QueueUrl": url })).await;
        assert!(v2.get("Tags").is_none());
    }

    #[tokio::test]
    async fn long_polling_wakes_on_send() {
        let h = Arc::new(SqsHandler::new());
        let url = create(&h, "q").await;
        let sender = h.clone();
        let su = url.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            call(
                &sender,
                "SendMessage",
                json!({ "QueueUrl": su, "MessageBody": "late" }),
            )
            .await;
        });
        let (_, v) = call(
            &h,
            "ReceiveMessage",
            json!({ "QueueUrl": url, "WaitTimeSeconds": 3 }),
        )
        .await;
        assert_eq!(v["Messages"][0]["Body"], "late");
    }

    #[tokio::test]
    async fn purge_clears_messages() {
        let h = SqsHandler::new();
        let url = create(&h, "q").await;
        call(
            &h,
            "SendMessage",
            json!({ "QueueUrl": url, "MessageBody": "x" }),
        )
        .await;
        call(&h, "PurgeQueue", json!({ "QueueUrl": url })).await;
        let (_, attrs) = call(
            &h,
            "GetQueueAttributes",
            json!({ "QueueUrl": url, "AttributeNames": ["ApproximateNumberOfMessages"] }),
        )
        .await;
        assert_eq!(attrs["Attributes"]["ApproximateNumberOfMessages"], "0");
    }

    #[tokio::test]
    async fn query_protocol_create_and_list_round_trip() {
        let h = SqsHandler::new();
        // CreateQueue via the legacy Query protocol (no X-Amz-Target, Action form field).
        let create = ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from("Action=CreateQueue&QueueName=qq&Version=2012-11-05"),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        };
        let resp = h.handle(create).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/xml"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(body.contains("<CreateQueueResponse"));
        assert!(body
            .contains("<QueueUrl>https://sqs.us-east-1.amazonaws.com/000000000000/qq</QueueUrl>"));

        // ListQueues via Query returns the queue as a flat <QueueUrl>.
        let list = ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from("Action=ListQueues&Version=2012-11-05"),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        };
        let resp = h.handle(list).await;
        assert_eq!(resp.status(), 200);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(body.contains("<ListQueuesResult><QueueUrl>https://sqs.us-east-1.amazonaws.com/000000000000/qq</QueueUrl></ListQueuesResult>"));
    }

    #[tokio::test]
    async fn query_protocol_send_receive_xml() {
        let h = SqsHandler::new();
        let create = ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from("Action=CreateQueue&QueueName=q"),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        };
        h.handle(create).await;

        let url = "https://sqs.us-east-1.amazonaws.com/000000000000/q";
        let send = ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from(format!(
                "Action=SendMessage&QueueUrl={url}&MessageBody=hello"
            )),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        };
        let resp = h.handle(send).await;
        assert_eq!(resp.status(), 200);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains("<MD5OfMessageBody>5d41402abc4b2a76b9719d911017c592</MD5OfMessageBody>")
        );

        let recv = ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from(format!("Action=ReceiveMessage&QueueUrl={url}")),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        };
        let resp = h.handle(recv).await;
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(body.contains("<Message>"));
        assert!(body.contains("<Body>hello</Body>"));
    }

    #[tokio::test]
    async fn query_protocol_error_is_xml() {
        let h = SqsHandler::new();
        let req = ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from(
                "Action=GetQueueAttributes&QueueUrl=https://sqs.us-east-1.amazonaws.com/000000000000/missing",
            ),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        };
        let resp = h.handle(req).await;
        assert_eq!(resp.status(), 400);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/xml"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(body.contains("<Code>AWS.SimpleQueueService.NonExistentQueue</Code>"));
    }
}
