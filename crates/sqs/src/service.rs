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

use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::AuthorizationRequest;
use locallycloud_core::integration::{InternalDispatcher, RequestIdentity};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

use crate::error::SqsError;
use crate::metrics::SqsMetrics;
use crate::model::QueueArn;
use crate::ops::{self, Ctx};
use crate::policy::{self, Decision};
use crate::proto::{self, Protocol};
use crate::store::SqsStore;
use locallycloud_state::StateDb;

const TARGET_PREFIX: &str = "AmazonSQS";

pub struct SqsHandler {
    store: Arc<SqsStore>,
    registry: Weak<ServiceRegistry>,
    metrics: SqsMetrics,
}

impl Default for SqsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SqsHandler {
    pub fn new() -> Self {
        Self::from_parts(Arc::new(SqsStore::new()), Weak::new())
    }

    fn with_registry(registry: &Arc<ServiceRegistry>) -> Self {
        Self::from_parts(Arc::new(SqsStore::new()), Arc::downgrade(registry))
    }

    fn with_state(registry: &Arc<ServiceRegistry>, state: Arc<StateDb>) -> Result<Self, SqsError> {
        Ok(Self::from_parts(
            Arc::new(SqsStore::with_state(state)?),
            Arc::downgrade(registry),
        ))
    }

    #[cfg(test)]
    fn with_metrics_period(registry: &Arc<ServiceRegistry>, period: std::time::Duration) -> Self {
        let store = Arc::new(SqsStore::new());
        let metrics = SqsMetrics::with_period(store.clone(), Arc::downgrade(registry), period);
        Self {
            store,
            registry: Arc::downgrade(registry),
            metrics,
        }
    }

    fn from_parts(store: Arc<SqsStore>, registry: Weak<ServiceRegistry>) -> Self {
        let metrics = SqsMetrics::new(store.clone(), registry.clone());
        Self {
            store,
            registry,
            metrics,
        }
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
            .get("x-locallycloud-verified-external-sigv4")
            .is_some_and(|value| value == "1");
        let internal = request
            .headers
            .get("x-locallycloud-verified-internal-scope")
            .is_some_and(|value| value == "1");
        if !strict && policy.is_none() {
            return Ok(());
        }
        if strict && !external && !internal {
            return Err(SqsError::AccessDenied);
        }
        let authenticated_operator = if internal && !external && dispatcher.is_some() {
            let dispatcher = dispatcher.ok_or(SqsError::AccessDenied)?;
            let principal = request
                .headers
                .get(locallycloud_core::integration::identity::PRINCIPAL_HEADER)
                .and_then(|v| v.to_str().ok())
                .ok_or(SqsError::AccessDenied)?;
            let identity = RequestIdentity {
                account_id: request.account_id.clone(),
                access_key_id: request
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(RequestIdentity::access_key_from_authorization),
                arn: None,
            };
            match dispatcher.resolve_caller_arn(&identity) {
                Ok(Some(resolved)) if resolved == principal => true,
                Ok(Some(_)) => return Err(SqsError::AccessDenied),
                _ if !strict
                    || locallycloud_core::integration::identity::trusted_role(request)
                        .is_some()
                    || principal.ends_with(".amazonaws.com") =>
                {
                    false
                }
                _ => return Err(SqsError::AccessDenied),
            }
        } else {
            false
        };
        let principal = if external || authenticated_operator {
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
                .get("x-locallycloud-caller-principal")
                .and_then(|value| value.to_str().ok())
                .ok_or(SqsError::AccessDenied)?
                .to_string()
        } else {
            // Permissive external callers are not authenticated: policy can grant only
            // an anonymous wildcard principal, never a client-supplied internal header.
            "anonymous".to_string()
        };
        let same_account_iam = arn.as_ref().is_some_and(|queue| {
            if external || internal {
                principal.starts_with(&format!("arn:aws:iam::{}:", queue.account))
                    || principal.starts_with(&format!("arn:aws:sts::{}:", queue.account))
            } else {
                // Permissive mode models an ordinary SigV4 caller in Core's resolved
                // account. This is not signature verification or service attestation.
                !strict
                    && queue.account == request.account_id
                    && request
                        .headers
                        .get(http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .filter(|value| value.starts_with("AWS4-HMAC-SHA256 "))
                        .and_then(RequestIdentity::access_key_from_authorization)
                        .is_some()
            }
        });
        if let Some(raw) = policy {
            // Core removes these headers at external ingress and creates the internal
            // attestation only for trusted in-process scoped dispatch.
            let source = if internal
                && !external
                && matches!(
                    principal.as_str(),
                    "sns.amazonaws.com" | "events.amazonaws.com"
                ) {
                let arn = request
                    .headers
                    .get("x-locallycloud-source-arn")
                    .and_then(|value| value.to_str().ok());
                let account = request
                    .headers
                    .get("x-locallycloud-source-account")
                    .and_then(|value| value.to_str().ok());
                let valid = arn.zip(account).is_some_and(|(arn, source_account)| {
                    let components = arn.splitn(6, ':').collect::<Vec<_>>();
                    components.len() == 6
                        && components[0] == "arn"
                        && match principal.as_str() {
                            "sns.amazonaws.com" => {
                                components[2] == "sns" && !components[5].is_empty()
                            }
                            "events.amazonaws.com" => {
                                components[2] == "events"
                                    && components[5]
                                        .strip_prefix("rule/")
                                        .is_some_and(|name| !name.is_empty())
                            }
                            _ => false,
                        }
                        && components[3] == request.region
                        && components[4] == source_account
                        && source_account == request.account_id
                        && !components[5].is_empty()
                });
                if valid {
                    policy::SourceContext { arn, account }
                } else {
                    policy::SourceContext::default()
                }
            } else {
                policy::SourceContext::default()
            };
            match policy::evaluate(
                &raw,
                &principal,
                &request.account_id,
                action,
                &resource,
                source,
            ) {
                Decision::Deny => return Err(SqsError::AccessDenied),
                Decision::Unmatched if !same_account_iam => return Err(SqsError::AccessDenied),
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
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        Ok(self
            .store
            .all()
            .into_iter()
            .filter(|q| q.arn.account == account)
            .map(|q| q.arn.region.clone())
            .collect())
    }

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
            metrics: self.metrics.recorder(),
        };
        if let Err(error) = self
            .authorize_queue_operation(&op, &body, &request, ctx.dispatcher.as_ref())
            .await
        {
            return error_response(error, &request, protocol);
        }
        match self.dispatch(&op, &ctx, &body).await {
            Ok(value) => {
                if !matches!(op.as_str(), "ListQueues" | "DeleteQueue") {
                    ctx.metrics.touch();
                }
                success_response(&op, value, protocol, &request.request_id)
            }
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
        let arn = match op {
            "ListQueues" => return Ok(("*".into(), None)),
            "CreateQueue" | "GetQueueUrl" => {
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
            }
            "StartMessageMoveTask" | "ListMessageMoveTasks" => {
                let source = body
                    .get("SourceArn")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        SqsError::InvalidParameterValue("SourceArn is required".into())
                    })?;
                ops::arn_from_str(source).ok_or_else(|| {
                    SqsError::InvalidParameterValue("SourceArn must be an SQS queue ARN".into())
                })?
            }
            "CancelMessageMoveTask" => {
                let handle = body
                    .get("TaskHandle")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        SqsError::InvalidParameterValue("TaskHandle is required".into())
                    })?;
                let source = self.store.move_task_source_arn(handle).ok_or_else(|| {
                    SqsError::ResourceNotFound("the specified task handle does not exist".into())
                })?;
                ops::arn_from_str(&source).ok_or_else(|| {
                    SqsError::InvalidParameterValue("SourceArn must be an SQS queue ARN".into())
                })?
            }
            _ => {
                let url = body
                    .get("QueueUrl")
                    .and_then(Value::as_str)
                    .ok_or_else(|| SqsError::MissingParameter("QueueUrl is required".into()))?;
                QueueArn::from_url(url)?
            }
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
    async fn source_policy_requires_core_internal_sns_context() {
        let h = SqsHandler::new();
        let policy = json!({"Statement":{"Effect":"Allow", "Principal":{"Service":"sns.amazonaws.com"}, "Action":"sqs:SendMessage", "Resource":"arn:aws:sqs:us-east-1:000000000000:source-guard", "Condition":{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:us-east-1:000000000000:orders"}, "StringEquals":{"aws:SourceAccount":"000000000000"}}}}).to_string();
        let (status, created) = call(
            &h,
            "CreateQueue",
            json!({"QueueName":"source-guard", "Attributes":{"Policy":policy}}),
        )
        .await;
        assert_eq!(status, 200);
        let body = json!({"QueueUrl":created["QueueUrl"], "MessageBody":"order"});
        let mut req = request("SendMessage", body.clone());
        for (key, value) in [
            ("x-locallycloud-caller-principal", "sns.amazonaws.com"),
            (
                "x-locallycloud-source-arn",
                "arn:aws:sns:us-east-1:000000000000:orders",
            ),
            ("x-locallycloud-source-account", "000000000000"),
        ] {
            req.headers.insert(key, value.parse().unwrap());
        }
        // Unverified caller-provided service/source headers cannot grant access.
        assert!(h
            .authorize_queue_operation("SendMessage", &body, &req, None)
            .await
            .is_err());
        req.headers.insert(
            "x-locallycloud-verified-internal-scope",
            "1".parse().unwrap(),
        );
        assert!(h
            .authorize_queue_operation("SendMessage", &body, &req, None)
            .await
            .is_ok());
        for (key, value) in [
            (
                "x-locallycloud-source-arn",
                "arn:aws:sns:us-west-2:000000000000:orders",
            ),
            (
                "x-locallycloud-source-arn",
                "arn:aws:sns:us-east-1:111111111111:orders",
            ),
            ("x-locallycloud-source-account", "111111111111"),
            ("x-locallycloud-caller-principal", "s3.amazonaws.com"),
            ("x-locallycloud-verified-external-sigv4", "1"),
        ] {
            let mut invalid = req.clone();
            invalid.headers.insert(key, value.parse().unwrap());
            assert!(
                h.authorize_queue_operation("SendMessage", &body, &invalid, None)
                    .await
                    .is_err(),
                "{key}: {value}"
            );
        }
        req.headers.remove("x-locallycloud-source-account");
        assert!(h
            .authorize_queue_operation("SendMessage", &body, &req, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn eventbridge_source_policy_requires_attested_same_scope_rule() {
        let h = SqsHandler::new();
        let source = "arn:aws:events:us-east-1:000000000000:rule/orders/ledger";
        let policy = json!({"Statement":{"Effect":"Allow", "Principal":{"Service":"events.amazonaws.com"}, "Action":"sqs:SendMessage", "Resource":"arn:aws:sqs:us-east-1:000000000000:events-source", "Condition":{"ArnEquals":{"aws:SourceArn":source}, "StringEquals":{"aws:SourceAccount":"000000000000"}}}}).to_string();
        let (status, created) = call(
            &h,
            "CreateQueue",
            json!({"QueueName":"events-source", "Attributes":{"Policy":policy}}),
        )
        .await;
        assert_eq!(status, 200);
        let body = json!({"QueueUrl":created["QueueUrl"], "MessageBody":"ledger"});
        let mut req = request("SendMessage", body.clone());
        for (key, value) in [
            ("x-locallycloud-caller-principal", "events.amazonaws.com"),
            ("x-locallycloud-source-arn", source),
            ("x-locallycloud-source-account", "000000000000"),
        ] {
            req.headers.insert(key, value.parse().unwrap());
        }
        assert!(h
            .authorize_queue_operation("SendMessage", &body, &req, None)
            .await
            .is_err());
        req.headers.insert(
            "x-locallycloud-verified-internal-scope",
            "1".parse().unwrap(),
        );
        assert!(h
            .authorize_queue_operation("SendMessage", &body, &req, None)
            .await
            .is_ok());
        for invalid in [
            "arn:aws:events:us-west-2:000000000000:rule/orders/ledger",
            "arn:aws:events:us-east-1:111111111111:rule/orders/ledger",
            "arn:aws:events:us-east-1:000000000000:event-bus/orders",
            "arn:aws:events:us-east-1:000000000000:rule/",
        ] {
            let mut forged = req.clone();
            forged
                .headers
                .insert("x-locallycloud-source-arn", invalid.parse().unwrap());
            assert!(h
                .authorize_queue_operation("SendMessage", &body, &forged, None)
                .await
                .is_err());
        }
        req.headers.remove("x-locallycloud-source-account");
        assert!(h
            .authorize_queue_operation("SendMessage", &body, &req, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn service_policy_preserves_owner_access_but_deny_and_cross_account_win() {
        let h = SqsHandler::new();
        let resource = "arn:aws:sqs:us-east-1:000000000000:owner-policy";
        let policy = json!({"Statement":{"Effect":"Allow", "Principal":{"Service":"sns.amazonaws.com"}, "Action":"sqs:SendMessage", "Resource":resource}}).to_string();
        let (status, created) = call(
            &h,
            "CreateQueue",
            json!({"QueueName":"owner-policy", "Attributes":{"Policy":policy}}),
        )
        .await;
        assert_eq!(status, 200);
        let body = json!({"QueueUrl":created["QueueUrl"], "AttributeNames":["Policy"]});
        let mut req = request("GetQueueAttributes", body.clone());
        assert!(h
            .authorize_queue_operation("GetQueueAttributes", &body, &req, None)
            .await
            .is_err());
        req.headers.insert(http::header::AUTHORIZATION, "AWS4-HMAC-SHA256 Credential=test/20261006/us-east-1/sqs/aws4_request, SignedHeaders=host, Signature=test".parse().unwrap());
        assert!(h
            .authorize_queue_operation("GetQueueAttributes", &body, &req, None)
            .await
            .is_ok());
        let mut other = req.clone();
        other.account_id = "111111111111".into();
        assert!(h
            .authorize_queue_operation("GetQueueAttributes", &body, &other, None)
            .await
            .is_err());
        req.headers.remove(http::header::AUTHORIZATION);
        req.headers.insert(
            "x-locallycloud-verified-internal-scope",
            "1".parse().unwrap(),
        );
        req.headers.insert(
            "x-locallycloud-caller-principal",
            "arn:aws:iam::000000000000:role/worker".parse().unwrap(),
        );
        assert!(h
            .authorize_queue_operation("GetQueueAttributes", &body, &req, None)
            .await
            .is_ok());
        let mut other = req.clone();
        other.headers.insert(
            "x-locallycloud-caller-principal",
            "arn:aws:iam::111111111111:role/worker".parse().unwrap(),
        );
        assert!(h
            .authorize_queue_operation("GetQueueAttributes", &body, &other, None)
            .await
            .is_err());
        let deny = json!({"Statement":{"Effect":"Deny", "Principal":"*", "Action":"sqs:GetQueueAttributes", "Resource":resource}}).to_string();
        let arn = QueueArn::new("us-east-1", "000000000000", "owner-policy");
        h.store
            .get(&arn)
            .unwrap()
            .state
            .lock()
            .await
            .attributes
            .insert("Policy".into(), deny);
        assert!(h
            .authorize_queue_operation("GetQueueAttributes", &body, &req, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn legacy_queue_size_limit_survives_restart() {
        let root =
            std::env::temp_dir().join(format!("locallycloud-sqs-size-{}", uuid::Uuid::new_v4()));
        let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let registry = Arc::new(ServiceRegistry::new());
        let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
        let (status, created) = call(
            &h,
            "CreateQueue",
            json!({"QueueName": "legacy-limit", "Attributes": {"MaximumMessageSize": "262144"}}),
        )
        .await;
        assert_eq!(status, 200);
        let url = created["QueueUrl"].as_str().unwrap().to_string();
        drop(h);
        let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
        let (_, attrs) = call(
            &h,
            "GetQueueAttributes",
            json!({"QueueUrl": url, "AttributeNames": ["MaximumMessageSize"]}),
        )
        .await;
        assert_eq!(attrs["Attributes"]["MaximumMessageSize"], "262144");
        for (bytes, expected) in [(262_144, 200), (262_145, 400)] {
            let (status, _) = call(
                &h,
                "SendMessage",
                json!({"QueueUrl": url, "MessageBody": "a".repeat(bytes)}),
            )
            .await;
            assert_eq!(status, expected);
        }
        drop(h);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn accepted_message_and_visibility_survive_restart() {
        let root =
            std::env::temp_dir().join(format!("locallycloud-sqs-restart-{}", uuid::Uuid::new_v4()));
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
    async fn disk_backlog_above_64_mib_preserves_restart_attempts_and_atomic_redrive() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("sqs-disk-backlog-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let registry = Arc::new(ServiceRegistry::new());
        let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
        let url = create(&h, "backlog.fifo").await;
        let dlq_url = create(&h, "backlog-dlq.fifo").await;
        let arn = crate::model::QueueArn::new("us-east-1", "000000000000", "backlog.fifo");
        let dlq_arn = "arn:aws:sqs:us-east-1:000000000000:backlog-dlq.fifo";
        let filler = "x".repeat(1_048_570);
        for index in 0..65 {
            let body = format!("{index:06}{filler}");
            let (status, _) = call(&h, "SendMessage", json!({"QueueUrl":url,"MessageBody":body,"MessageGroupId":format!("g-{index}"),"MessageDeduplicationId":format!("d-{index}")})).await;
            assert_eq!(status, 200);
        }
        let q = h.store.get(&arn).unwrap();
        {
            let state = q.state.lock().await;
            assert_eq!(state.messages.len(), 65);
            assert!(state
                .messages
                .iter()
                .all(|message| message.body_on_disk && message.body.capacity() == 0));
        }
        drop(q);
        drop(h);
        let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
        let q = h.store.get(&arn).unwrap();
        assert!(q
            .state
            .lock()
            .await
            .messages
            .iter()
            .all(|message| message.body_on_disk && message.body.capacity() == 0));
        // A failed durable receive cannot publish a receipt or lose its offloaded payload.
        db.connection().unwrap().execute_batch("CREATE TRIGGER sqs_receive_failure BEFORE UPDATE ON sqs_messages BEGIN SELECT RAISE(FAIL,'injected receive failure'); END;").unwrap();
        let (status, _) = call(&h, "ReceiveMessage", json!({"QueueUrl":url})).await;
        assert_eq!(status, 500);
        assert!(q
            .state
            .lock()
            .await
            .messages
            .iter()
            .all(|message| message.receipt_handle.is_none() && message.receive_count == 0));
        db.connection()
            .unwrap()
            .execute_batch("DROP TRIGGER sqs_receive_failure;")
            .unwrap();
        let (status, received) = call(
            &h,
            "ReceiveMessage",
            json!({"QueueUrl":url,"ReceiveRequestAttemptId":"first","VisibilityTimeout":0}),
        )
        .await;
        assert_eq!(status, 200);
        let expected = format!("000000{filler}");
        assert_eq!(received["Messages"][0]["Body"].as_str().unwrap(), expected);
        let receipt = received["Messages"][0]["ReceiptHandle"].as_str().unwrap();
        assert_eq!(
            call(
                &h,
                "DeleteMessage",
                json!({"QueueUrl":url,"ReceiptHandle":receipt})
            )
            .await
            .0,
            200
        );
        drop(q);
        drop(h);
        let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
        let (status, replayed) = call(
            &h,
            "ReceiveMessage",
            json!({"QueueUrl":url,"ReceiveRequestAttemptId":"first"}),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(replayed["Messages"][0]["Body"].as_str().unwrap(), expected);
        let policy = json!({"deadLetterTargetArn":dlq_arn,"maxReceiveCount":1}).to_string();
        assert_eq!(
            call(
                &h,
                "SetQueueAttributes",
                json!({"QueueUrl":url,"Attributes":{"RedrivePolicy":policy}})
            )
            .await
            .0,
            200
        );
        // Receive the next record once; the following receive attempts automatic redrive.
        let (status, poison) = call(
            &h,
            "ReceiveMessage",
            json!({"QueueUrl":url,"VisibilityTimeout":0}),
        )
        .await;
        assert_eq!(status, 200);
        let poison_id = poison["Messages"][0]["MessageId"]
            .as_str()
            .unwrap()
            .to_string();
        let poison_body = poison["Messages"][0]["Body"].as_str().unwrap().to_string();
        db.connection().unwrap().execute_batch(&format!("CREATE TRIGGER sqs_dlq_failure BEFORE INSERT ON sqs_messages WHEN NEW.arn='{dlq_arn}' BEGIN SELECT RAISE(FAIL,'injected DLQ failure'); END;")).unwrap();
        assert_eq!(
            call(&h, "ReceiveMessage", json!({"QueueUrl":url})).await.0,
            500
        );
        let q = h.store.get(&arn).unwrap();
        assert!(q
            .state
            .lock()
            .await
            .messages
            .iter()
            .any(|message| message.id == poison_id && message.body_on_disk));
        db.connection()
            .unwrap()
            .execute_batch("DROP TRIGGER sqs_dlq_failure;")
            .unwrap();
        assert_eq!(
            call(&h, "ReceiveMessage", json!({"QueueUrl":url})).await.0,
            200
        );
        let expired_id = q.state.lock().await.messages.back().unwrap().id.clone();
        drop(q);
        drop(h);
        // Legacy durable rows may already be expired at startup; the retention bound must
        // derive from all restored timestamps, including messages moved out of send order.
        db.connection().unwrap().execute("UPDATE sqs_messages SET payload=json_set(payload,'$.sent_timestamp_ms',0) WHERE arn=?1 AND id=?2", rusqlite::params![arn.to_arn(), expired_id]).unwrap();
        let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
        assert_eq!(
            call(&h, "GetQueueAttributes", json!({"QueueUrl":url}))
                .await
                .0,
            200
        );
        assert!(!h
            .store
            .get(&arn)
            .unwrap()
            .state
            .lock()
            .await
            .messages
            .iter()
            .any(|message| message.id == expired_id));
        let remaining: i64 = db
            .connection()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sqs_messages WHERE arn=?1 AND id=?2",
                rusqlite::params![arn.to_arn(), expired_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
        let (status, moved) = call(&h, "ReceiveMessage", json!({"QueueUrl":dlq_url})).await;
        assert_eq!(status, 200);
        assert_eq!(moved["Messages"][0]["MessageId"], poison_id);
        assert_eq!(moved["Messages"][0]["Body"].as_str().unwrap(), poison_body);
        assert_eq!(
            call(&h, "DeleteQueue", json!({"QueueUrl":url})).await.0,
            200
        );
        assert_eq!(
            call(&h, "DeleteQueue", json!({"QueueUrl":dlq_url})).await.0,
            200
        );
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

    mod vended_metrics {
        use super::*;
        use locallycloud_core::integration::metrics::{
            EmitOutcome, MetricObservation, MetricSink, MetricUnit,
        };
        use std::sync::Mutex;

        struct RecordingSink {
            outcome: EmitOutcome,
            observations: Mutex<Vec<MetricObservation>>,
        }

        impl MetricSink for RecordingSink {
            fn try_emit(&self, observations: Vec<MetricObservation>) -> EmitOutcome {
                self.observations.lock().unwrap().extend(observations);
                self.outcome
            }
        }

        struct NoopHandler;

        #[async_trait]
        impl NativeHandler for NoopHandler {
            async fn handle(&self, _request: ServiceRequest) -> Response {
                Response::new(Body::empty())
            }
        }

        fn registry_with_sink(outcome: EmitOutcome) -> (Arc<ServiceRegistry>, Arc<RecordingSink>) {
            let registry = Arc::new(ServiceRegistry::new());
            let sink = Arc::new(RecordingSink {
                outcome,
                observations: Mutex::new(Vec::new()),
            });
            registry.register_native_with_metric_sink(
                ServiceName::new("monitoring"),
                ServiceMetadata::new(AwsProtocol::Query, None),
                Arc::new(NoopHandler),
                sink.clone(),
            );
            (registry, sink)
        }

        fn points(sink: &RecordingSink, queue: &str, name: &str) -> Vec<MetricObservation> {
            sink.observations
                .lock()
                .unwrap()
                .iter()
                .filter(|o| o.metric_name == name && o.dimensions["QueueName"] == queue)
                .cloned()
                .collect()
        }

        fn sum(sink: &RecordingSink, queue: &str, name: &str) -> f64 {
            points(sink, queue, name).iter().map(|o| o.value).sum()
        }

        #[tokio::test]
        async fn queue_age_poison_redrive_restart_and_legacy_retention() {
            let root = std::env::temp_dir().join(format!("sqs-age-{}", uuid::Uuid::new_v4()));
            let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
            let (registry, sink) = registry_with_sink(EmitOutcome::Accepted);
            let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
            let mut queues = Vec::new();
            for fifo in [false, true] {
                let suffix = if fifo { ".fifo" } else { "" };
                let source = format!("age-source{suffix}");
                let dlq = format!("age-dlq{suffix}");
                let dlq_url = create(&h, &dlq).await;
                let dlq_arn = format!("arn:aws:sqs:us-east-1:000000000000:{dlq}");
                let (status, created) = call(&h, "CreateQueue", json!({"QueueName":source,"Attributes":{
                    "RedrivePolicy":json!({"deadLetterTargetArn":dlq_arn,"maxReceiveCount":4}).to_string()
                }})).await;
                assert_eq!(status, 200);
                let url = created["QueueUrl"].as_str().unwrap().to_string();
                let mut send = json!({"QueueUrl":url,"MessageBody":"old poison"});
                if fifo {
                    send["MessageGroupId"] = json!("group");
                    send["MessageDeduplicationId"] = json!("dedup");
                }
                assert_eq!(call(&h, "SendMessage", send).await.0, 200);
                queues.push((fifo, source, dlq, url, dlq_url));
            }
            drop(h);
            let old = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64)
                - 180_000;
            // Legacy metadata has no queue-arrival field; hydration must preserve its age.
            db.connection().unwrap().execute(
                "UPDATE sqs_messages SET payload=json_remove(json_set(payload,'$.sent_timestamp_ms',?1),'$.queue_arrival_ms')", [old]
            ).unwrap();
            let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
            h.metrics.recorder().tick().await;
            for (_, source, _, _, _) in &queues {
                assert!(
                    points(&sink, source, "ApproximateAgeOfOldestMessage")
                        .last()
                        .unwrap()
                        .value
                        >= 180.0
                );
            }
            for (fifo, source, dlq, url, _) in &queues {
                for _ in 0..3 {
                    let (status, received) = call(
                        &h,
                        "ReceiveMessage",
                        json!({"QueueUrl":url,"VisibilityTimeout":0}),
                    )
                    .await;
                    assert_eq!(status, 200);
                    assert_eq!(received["Messages"].as_array().unwrap().len(), 1);
                }
                h.metrics.recorder().tick().await;
                let age = points(&sink, source, "ApproximateAgeOfOldestMessage")
                    .last()
                    .unwrap()
                    .value;
                if *fifo {
                    assert!(age >= 180.0);
                } else {
                    assert_eq!(age, 0.0);
                }
                // The configured threshold is still four, independently of age exclusion.
                assert_eq!(
                    call(
                        &h,
                        "ReceiveMessage",
                        json!({"QueueUrl":url,"VisibilityTimeout":0})
                    )
                    .await
                    .1["Messages"]
                        .as_array()
                        .unwrap()
                        .len(),
                    1
                );
                let (status, moved) = call(
                    &h,
                    "ReceiveMessage",
                    json!({"QueueUrl":url,"VisibilityTimeout":0}),
                )
                .await;
                assert_eq!(status, 200);
                assert!(moved.get("Messages").is_none());
                let queue = h
                    .store
                    .get(&QueueArn::new("us-east-1", "000000000000", dlq))
                    .unwrap();
                let state = queue.state.lock().await;
                let message = &state.messages[0];
                assert!(message.queue_arrival_ms.unwrap() > old + 170_000);
                assert_eq!(
                    message.sent_timestamp_ms,
                    if *fifo {
                        message.queue_arrival_ms.unwrap()
                    } else {
                        old
                    }
                );
                drop(state);
                h.metrics.recorder().tick().await;
                assert!(
                    points(&sink, dlq, "ApproximateAgeOfOldestMessage")
                        .last()
                        .unwrap()
                        .value
                        < 10.0
                );
            }
            drop(h);
            let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
            for (fifo, _, dlq, _, dlq_url) in &queues {
                let queue = h
                    .store
                    .get(&QueueArn::new("us-east-1", "000000000000", dlq))
                    .unwrap();
                let state = queue.state.lock().await;
                let message = &state.messages[0];
                assert!(message.queue_arrival_ms.unwrap() > old + 170_000);
                assert_eq!(
                    message.sent_timestamp_ms,
                    if *fifo {
                        message.queue_arrival_ms.unwrap()
                    } else {
                        old
                    }
                );
                drop(state);
                let (status, received) = call(
                    &h,
                    "ReceiveMessage",
                    json!({"QueueUrl":dlq_url,"MessageSystemAttributeNames":["SentTimestamp"]}),
                )
                .await;
                assert_eq!(status, 200);
                let timestamp = received["Messages"][0]["Attributes"]["SentTimestamp"]
                    .as_str()
                    .unwrap()
                    .parse::<i64>()
                    .unwrap();
                if *fifo {
                    assert!(timestamp > old + 170_000);
                } else {
                    assert_eq!(timestamp, old);
                }
            }
            h.metrics.recorder().tick().await;
            for (_, _, dlq, _, _) in &queues {
                assert!(
                    points(&sink, dlq, "ApproximateAgeOfOldestMessage")
                        .last()
                        .unwrap()
                        .value
                        < 10.0
                );
            }
            drop(h);
            drop(db);
            std::fs::remove_dir_all(root).unwrap();
        }

        #[tokio::test]
        async fn fifo_deduplicated_sends_are_not_counted_as_sent() {
            let (registry, sink) = registry_with_sink(EmitOutcome::Accepted);
            let h = SqsHandler::with_metrics_period(&registry, Duration::from_secs(3600));
            let (status, created) = call(
                &h,
                "CreateQueue",
                json!({ "QueueName": "dedup.fifo", "Attributes": { "FifoQueue": "true" } }),
            )
            .await;
            assert_eq!(status, 200);
            let url = created["QueueUrl"].as_str().unwrap().to_string();
            for _ in 0..2 {
                let (status, _) = call(
                    &h,
                    "SendMessage",
                    json!({ "QueueUrl": url, "MessageBody": "same", "MessageGroupId": "g",
                            "MessageDeduplicationId": "d1" }),
                )
                .await;
                assert_eq!(status, 200);
            }
            h.metrics.recorder().tick().await;
            assert_eq!(sum(&sink, "dedup.fifo", "NumberOfMessagesSent"), 1.0);
            assert_eq!(points(&sink, "dedup.fifo", "SentMessageSize").len(), 1);
        }

        #[tokio::test]
        async fn operation_counters_are_aggregated_and_emitted() {
            let (registry, sink) = registry_with_sink(EmitOutcome::Accepted);
            let h = SqsHandler::with_metrics_period(&registry, Duration::from_secs(3600));
            let url = create(&h, "metered").await;
            for body in ["hello", "abc"] {
                let (status, _) = call(
                    &h,
                    "SendMessage",
                    json!({ "QueueUrl": url, "MessageBody": body }),
                )
                .await;
                assert_eq!(status, 200);
            }
            let (status, batch) = call(
                &h,
                "SendMessageBatch",
                json!({ "QueueUrl": url, "Entries": [
                    { "Id": "a", "MessageBody": "four" },
                    { "Id": "b", "MessageBody": "x", "DelaySeconds": 5000 },
                    { "Id": "c", "MessageBody": "sz", "MessageAttributes": {
                        "k": { "DataType": "String", "StringValue": "vv" } } }
                ] }),
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(batch["Failed"].as_array().unwrap().len(), 1);
            let (_, received) = call(
                &h,
                "ReceiveMessage",
                json!({ "QueueUrl": url, "MaxNumberOfMessages": 10 }),
            )
            .await;
            let handles: Vec<String> = received["Messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["ReceiptHandle"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(handles.len(), 4);
            let (_, empty) = call(&h, "ReceiveMessage", json!({ "QueueUrl": url })).await;
            assert!(empty.get("Messages").is_none());
            let (status, _) = call(
                &h,
                "DeleteMessage",
                json!({ "QueueUrl": url, "ReceiptHandle": handles[0] }),
            )
            .await;
            assert_eq!(status, 200);
            let (_, deleted) = call(
                &h,
                "DeleteMessageBatch",
                json!({ "QueueUrl": url, "Entries": [
                    { "Id": "a", "ReceiptHandle": handles[1] },
                    { "Id": "b", "ReceiptHandle": "garbage" }
                ] }),
            )
            .await;
            assert_eq!(deleted["Successful"].as_array().unwrap().len(), 1);
            assert!(
                sink.observations.lock().unwrap().is_empty(),
                "counters are buffered until the sampler flushes"
            );

            h.metrics.recorder().tick().await;

            assert_eq!(sum(&sink, "metered", "NumberOfMessagesSent"), 4.0);
            assert_eq!(sum(&sink, "metered", "NumberOfMessagesReceived"), 4.0);
            assert_eq!(sum(&sink, "metered", "NumberOfEmptyReceives"), 1.0);
            assert_eq!(sum(&sink, "metered", "NumberOfMessagesDeleted"), 2.0);
            let mut sizes: Vec<f64> = points(&sink, "metered", "SentMessageSize")
                .iter()
                .map(|o| o.value)
                .collect();
            sizes.sort_by(f64::total_cmp);
            // "sz" + attribute name "k" + data type "String" + value "vv".
            assert_eq!(sizes, vec![3.0, 4.0, 5.0, 11.0]);
            let observations = sink.observations.lock().unwrap().clone();
            assert!(observations.iter().all(|o| o.namespace == "AWS/SQS"
                && o.account_id == "000000000000"
                && o.region == "us-east-1"
                && o.dimensions.len() == 1
                && o.storage_resolution == 60));
            let sent = observations
                .iter()
                .find(|o| o.metric_name == "NumberOfMessagesSent")
                .unwrap();
            assert_eq!(sent.unit, Some(MetricUnit::Count));
            assert_eq!(sent.timestamp_ms % 60_000, 0);
            assert!(observations
                .iter()
                .filter(|o| o.metric_name == "SentMessageSize")
                .all(|o| o.unit == Some(MetricUnit::Bytes)));

            sink.observations.lock().unwrap().clear();
            h.metrics.recorder().tick().await;
            assert_eq!(sum(&sink, "metered", "NumberOfMessagesSent"), 0.0);
        }

        #[tokio::test]
        async fn gauges_sample_queue_depth_and_age() {
            let (registry, sink) = registry_with_sink(EmitOutcome::Accepted);
            let h = SqsHandler::with_metrics_period(&registry, Duration::from_secs(3600));
            let url = create(&h, "depth").await;
            let idle = create(&h, "idle").await;
            for (body, delay) in [("in-flight", 0), ("visible", 0), ("delayed", 600)] {
                call(
                    &h,
                    "SendMessage",
                    json!({ "QueueUrl": url, "MessageBody": body, "DelaySeconds": delay }),
                )
                .await;
            }
            call(&h, "ReceiveMessage", json!({ "QueueUrl": url })).await;
            assert!(!idle.is_empty());
            sink.observations.lock().unwrap().clear();

            h.metrics.recorder().tick().await;

            let gauge = |queue: &str, name: &str| {
                let samples = points(&sink, queue, name);
                assert_eq!(samples.len(), 1, "{queue} {name}");
                samples[0].clone()
            };
            assert_eq!(
                gauge("depth", "ApproximateNumberOfMessagesVisible").value,
                1.0
            );
            assert_eq!(
                gauge("depth", "ApproximateNumberOfMessagesNotVisible").value,
                1.0
            );
            assert_eq!(
                gauge("depth", "ApproximateNumberOfMessagesDelayed").value,
                1.0
            );
            let age = gauge("depth", "ApproximateAgeOfOldestMessage");
            assert_eq!(age.unit, Some(MetricUnit::Seconds));
            assert!((0.0..5.0).contains(&age.value));
            for name in [
                "ApproximateNumberOfMessagesVisible",
                "ApproximateNumberOfMessagesNotVisible",
                "ApproximateNumberOfMessagesDelayed",
                "ApproximateAgeOfOldestMessage",
            ] {
                assert_eq!(gauge("idle", name).value, 0.0);
            }
        }

        #[tokio::test]
        async fn sampler_starts_lazily_and_stops_without_queues() {
            let (registry, sink) = registry_with_sink(EmitOutcome::Accepted);
            let h = SqsHandler::with_metrics_period(&registry, Duration::from_millis(50));
            let recorder = h.metrics.recorder();
            assert!(!recorder.sampler_running());
            call(&h, "ListQueues", json!({})).await;
            assert!(!recorder.sampler_running());

            let url = create(&h, "lazy").await;
            assert!(recorder.sampler_running());
            call(
                &h,
                "SendMessage",
                json!({ "QueueUrl": url, "MessageBody": "tick" }),
            )
            .await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(sum(&sink, "lazy", "NumberOfMessagesSent"), 1.0);
            assert!(!points(&sink, "lazy", "ApproximateNumberOfMessagesVisible").is_empty());

            call(&h, "DeleteQueue", json!({ "QueueUrl": url })).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(!recorder.sampler_running());
        }

        #[tokio::test]
        async fn no_sampler_or_buffer_without_monitoring() {
            let registry = Arc::new(ServiceRegistry::new());
            let h = SqsHandler::with_metrics_period(&registry, Duration::from_millis(50));
            let url = create(&h, "unmetered").await;
            let (status, _) = call(
                &h,
                "SendMessage",
                json!({ "QueueUrl": url, "MessageBody": "x" }),
            )
            .await;
            assert_eq!(status, 200);
            assert!(!h.metrics.recorder().sampler_running());
            // Monitoring appearing later receives gauges only: nothing was buffered.
            let sink = Arc::new(RecordingSink {
                outcome: EmitOutcome::Accepted,
                observations: Mutex::new(Vec::new()),
            });
            registry.register_native_with_metric_sink(
                ServiceName::new("monitoring"),
                ServiceMetadata::new(AwsProtocol::Query, None),
                Arc::new(NoopHandler),
                sink.clone(),
            );
            assert_eq!(h.metrics.recorder().tick().await, 4);
            assert!(points(&sink, "unmetered", "NumberOfMessagesSent").is_empty());
        }

        #[tokio::test]
        async fn rejected_emission_never_fails_the_api_call() {
            let (registry, sink) = registry_with_sink(EmitOutcome::Full);
            let h = SqsHandler::with_metrics_period(&registry, Duration::from_millis(20));
            let url = create(&h, "full").await;
            for _ in 0..3 {
                let (status, _) = call(
                    &h,
                    "SendMessage",
                    json!({ "QueueUrl": url, "MessageBody": "x" }),
                )
                .await;
                assert_eq!(status, 200);
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
            let (status, _) = call(&h, "ReceiveMessage", json!({ "QueueUrl": url })).await;
            assert_eq!(status, 200);
            assert!(!sink.observations.lock().unwrap().is_empty());
        }
    }
}
