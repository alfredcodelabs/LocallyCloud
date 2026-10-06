use axum::body::to_bytes;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use locallycloud_core::integration::authorization::ServiceRoleAuthorizationRequest;
use locallycloud_core::integration::correlation::CorrelationContext;
use locallycloud_core::integration::delivery::{
    AsyncDeliveryPolicy, CrossServiceCall, DeliveryEngine,
};
use locallycloud_core::integration::identity::CallerIdentity;
use locallycloud_core::integration::logs::{
    LogScope, ProducerContext, ProducerGroupSpec, ProducerLogEvent, ProducerStreamSpec, SinkError,
};
use locallycloud_core::integration::pattern::IntegrationPatternId;
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::model::{RetryPolicy, Target};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryFailure;

#[derive(Debug, Clone)]
pub struct DeliveryRequest {
    pub source_service: &'static str,
    pub source_arn: Option<String>,
    pub arn: String,
    pub payload: String,
    pub role_arn: Option<String>,
    pub sqs_parameters: Option<Value>,
    pub target_parameters: Option<Value>,
    pub retry: RetryPolicy,
    pub dead_letter_arn: Option<String>,
    pub scheduled_at: Option<OffsetDateTime>,
}

impl From<(&Target, String)> for DeliveryRequest {
    fn from((target, payload): (&Target, String)) -> Self {
        Self {
            source_service: "events",
            source_arn: None,
            arn: target.arn.clone(),
            payload,
            role_arn: target.role_arn.clone(),
            sqs_parameters: target.sqs_parameters.clone(),
            target_parameters: Some(target.extra.clone()),
            retry: target.retry.clone(),
            dead_letter_arn: target.dead_letter_arn.clone(),
            scheduled_at: None,
        }
    }
}

pub(crate) fn authorize_role_execution(
    registry: &ServiceRegistry,
    role_arn: Option<&str>,
    source_service: &str,
    source_arn: Option<&str>,
    action: &str,
    resource: &str,
    account: &str,
) -> bool {
    let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
        return true;
    };
    if !evaluator.strict_sigv4_required() {
        return true;
    }
    let Some(role_arn) = role_arn else {
        return source_service == "events"
            && matches!(
                action,
                "lambda:InvokeFunction" | "sqs:SendMessage" | "sns:Publish"
            );
    };
    evaluator
        .authorize_service_role_execution(ServiceRoleAuthorizationRequest {
            source_arn: source_arn.map(str::to_string),
            caller: RequestIdentity {
                account_id: account.into(),
                access_key_id: None,
                arn: None,
            },
            role_arn: role_arn.into(),
            service_principal: format!("{source_service}.amazonaws.com"),
            action: action.into(),
            resource: resource.into(),
        })
        .is_ok()
}

fn authorize_target(
    registry: &ServiceRegistry,
    request: &DeliveryRequest,
    mode: InvocationMode,
    account: &str,
) -> bool {
    let action = match (arn_service(&request.arn), mode) {
        (Some("lambda"), _) => "lambda:InvokeFunction",
        (Some("sqs"), _) => "sqs:SendMessage",
        (Some("states"), InvocationMode::AsyncTarget) => "states:StartExecution",
        (Some("states"), InvocationMode::SyncEnrichment) => "states:StartSyncExecution",
        (Some("sns"), _) => "sns:Publish",
        (Some("kinesis"), _) => "kinesis:PutRecord",
        (Some("firehose"), _) => "firehose:PutRecord",
        (Some("logs"), _) => "logs:PutLogEvents",
        (Some("events"), _) => "events:PutEvents",
        _ => return false,
    };
    authorize_role_execution(
        registry,
        request.role_arn.as_deref(),
        request.source_service,
        request.source_arn.as_deref(),
        action,
        &request.arn,
        account,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InvocationMode {
    AsyncTarget,
    SyncEnrichment,
}

pub(crate) fn log_group_name(arn: &str, region: &str, account: &str) -> Option<String> {
    let mut parts = arn.splitn(6, ':');
    if parts.next()? != "arn" || parts.next()?.is_empty() || parts.next()? != "logs" {
        return None;
    }
    if parts.next()? != region || parts.next()? != account {
        return None;
    }
    let resource = parts.next()?.strip_prefix("log-group:")?;
    let name = resource.strip_suffix(":*").unwrap_or(resource);
    (!name.is_empty() && !name.contains(":log-stream:")).then(|| name.to_string())
}

pub(crate) async fn deliver_logs(
    registry: &ServiceRegistry,
    request: &DeliveryRequest,
    region: &str,
    account: &str,
    rule_name: &str,
    correlation: CorrelationContext,
) -> Result<(), ()> {
    if request.role_arn.is_some()
        && !authorize_target(registry, request, InvocationMode::AsyncTarget, account)
    {
        return Err(());
    }
    let group_name = log_group_name(&request.arn, region, account).ok_or(())?;
    let scope = LogScope::new(account, region);
    let identity = request.role_arn.as_ref().map_or(
        CallerIdentity::ServicePrincipal {
            service: request.source_service.into(),
        },
        |role| CallerIdentity::AssumedRole {
            role_arn: role.clone(),
            session_name: "eventbridge".into(),
        },
    );
    let context = ProducerContext {
        source_service: request.source_service.into(),
        identity,
        correlation,
        loop_depth: 0,
    };
    let attempts = request.retry.maximum_attempts.saturating_add(1);
    let mut delivered = false;
    if !event_expired(request, OffsetDateTime::now_utc()) {
        for attempt in 0..attempts {
            let result = async {
                if !authorize_target(registry, request, InvocationMode::AsyncTarget, account) {
                    return Err(SinkError::Rejected("execution role denied".into()));
                }
                let sink = registry
                    .log_sink(&ServiceName::new("logs"))
                    .ok_or(SinkError::Unavailable)?;
                let group = sink
                    .resolve_group(
                        scope.clone(),
                        ProducerGroupSpec {
                            name: group_name.clone(),
                        },
                        context.clone(),
                    )
                    .await?;
                let stream = sink
                    .ensure_stream(
                        scope.clone(),
                        group,
                        ProducerStreamSpec {
                            name: format!("events/{rule_name}"),
                        },
                        context.clone(),
                    )
                    .await?;
                let outcome = sink
                    .append(
                        scope.clone(),
                        stream,
                        vec![ProducerLogEvent {
                            timestamp_ms: (OffsetDateTime::now_utc().unix_timestamp_nanos()
                                / 1_000_000) as i64,
                            message: request.payload.clone(),
                        }],
                        context.clone(),
                    )
                    .await?;
                if outcome.stored_events != 1 {
                    return Err(SinkError::Rejected("partial producer commit".into()));
                }
                Ok::<(), SinkError>(())
            }
            .await;
            match result {
                Ok(()) => {
                    delivered = true;
                    break;
                }
                Err(error) if retriable_sink_error(&error) && attempt + 1 < attempts => {
                    let delay = 25u64.saturating_mul(1u64 << attempt.min(5));
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
                Err(_) => break,
            }
        }
    }
    if delivered {
        return Ok(());
    }
    if let Some(dlq) = &request.dead_letter_arn {
        let dlq_request = DeliveryRequest {
            source_service: request.source_service,
            source_arn: request.source_arn.clone(),
            arn: dlq.clone(),
            payload: request.payload.clone(),
            role_arn: request.role_arn.clone(),
            sqs_parameters: None,
            target_parameters: None,
            retry: RetryPolicy {
                maximum_attempts: 0,
                maximum_age_seconds: None,
            },
            dead_letter_arn: None,
            scheduled_at: None,
        };
        let _ = deliver(registry, &dlq_request, region, account).await;
    }
    Err(())
}

fn retriable_sink_error(error: &SinkError) -> bool {
    matches!(
        error,
        SinkError::Unavailable | SinkError::Backpressure | SinkError::Internal(_)
    )
}

pub async fn deliver(
    registry: &ServiceRegistry,
    request: &DeliveryRequest,
    region: &str,
    account: &str,
) -> Result<(), DeliveryFailure> {
    if request.source_service == "pipes"
        && matches!(arn_service(&request.arn), Some("states" | "lambda"))
        && request
            .target_parameters
            .as_ref()
            .and_then(|parameters| crate::pipes::find_string(parameters, "InvocationType"))
            .unwrap_or("REQUEST_RESPONSE")
            == "REQUEST_RESPONSE"
    {
        return deliver_sync(registry, request, region, account)
            .await
            .map(|_| ());
    }
    let dispatcher = registry.internal_dispatcher().ok_or(DeliveryFailure)?;
    let engine = DeliveryEngine::new(dispatcher);
    let result = if event_expired(request, OffsetDateTime::now_utc()) {
        Err(())
    } else {
        match target_call(request, region, account, InvocationMode::AsyncTarget) {
            Ok(call) => {
                let policy = delivery_policy(request);
                let delivery = engine.deliver_async_checked(call, &policy, || {
                    authorize_target(registry, request, InvocationMode::AsyncTarget, account)
                });
                if let (Some(scheduled_at), Some(maximum_age)) =
                    (request.scheduled_at, request.retry.maximum_age_seconds)
                {
                    let deadline = scheduled_at
                        + time::Duration::seconds(maximum_age.min(i64::MAX as u64) as i64);
                    let remaining = (deadline - OffsetDateTime::now_utc())
                        .try_into()
                        .unwrap_or(std::time::Duration::ZERO);
                    tokio::time::timeout(remaining, delivery)
                        .await
                        .map_err(|_| ())
                        .and_then(|result| result.map_err(|_| ()))
                } else {
                    delivery.await.map_err(|_| ())
                }
            }
            Err(()) => Err(()),
        }
    };
    if result.is_ok() {
        return Ok(());
    }

    // DeliveryEngine only reports the failure; EventBridge owns one explicit DLQ attempt.
    if let Some(dlq) = &request.dead_letter_arn {
        let dlq_request = DeliveryRequest {
            source_service: request.source_service,
            source_arn: request.source_arn.clone(),
            arn: dlq.clone(),
            payload: request.payload.clone(),
            role_arn: request.role_arn.clone(),
            sqs_parameters: None,
            target_parameters: None,
            retry: RetryPolicy {
                maximum_attempts: 0,
                maximum_age_seconds: None,
            },
            dead_letter_arn: None,
            scheduled_at: None,
        };
        let call = target_call(&dlq_request, region, account, InvocationMode::AsyncTarget)
            .map_err(|_| DeliveryFailure)?;
        if engine
            .deliver_async_checked(
                call,
                &AsyncDeliveryPolicy {
                    max_attempts: 1,
                    on_failure: None,
                },
                || authorize_target(registry, &dlq_request, InvocationMode::AsyncTarget, account),
            )
            .await
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(DeliveryFailure)
}

fn delivery_policy(request: &DeliveryRequest) -> AsyncDeliveryPolicy {
    AsyncDeliveryPolicy {
        max_attempts: request.retry.maximum_attempts.saturating_add(1),
        on_failure: None,
    }
}

pub async fn deliver_sync(
    registry: &ServiceRegistry,
    request: &DeliveryRequest,
    region: &str,
    account: &str,
) -> Result<Value, DeliveryFailure> {
    let dispatcher = registry.internal_dispatcher().ok_or(DeliveryFailure)?;
    if !authorize_target(registry, request, InvocationMode::SyncEnrichment, account) {
        return Err(DeliveryFailure);
    }
    let response = DeliveryEngine::new(dispatcher)
        .deliver_sync(
            target_call(request, region, account, InvocationMode::SyncEnrichment)
                .map_err(|_| DeliveryFailure)?,
        )
        .await;
    if !response.status().is_success() || response.headers().contains_key("x-amz-function-error") {
        return Err(DeliveryFailure);
    }
    let bytes = to_bytes(response.into_body(), 6 * 1024 * 1024)
        .await
        .map_err(|_| DeliveryFailure)?;
    sync_output(request, &bytes).map_err(|_| DeliveryFailure)
}

fn sync_output(request: &DeliveryRequest, bytes: &[u8]) -> Result<Value, ()> {
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    let value =
        serde_json::from_slice(bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(bytes)));
    if arn_service(&request.arn) != Some("states") {
        return Ok(value);
    }
    if value.get("status").and_then(Value::as_str) != Some("SUCCEEDED") {
        return Err(());
    }
    let Some(output) = value.get("output").and_then(Value::as_str) else {
        return Ok(Value::Null);
    };
    Ok(serde_json::from_str(output).unwrap_or_else(|_| json!(output)))
}

fn event_expired(request: &DeliveryRequest, now: OffsetDateTime) -> bool {
    let Some(maximum_age) = request.retry.maximum_age_seconds else {
        return false;
    };
    let timestamp = request.scheduled_at.or_else(|| {
        serde_json::from_str::<Value>(&request.payload)
            .ok()
            .and_then(|value| {
                value
                    .get("time")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .and_then(|value| OffsetDateTime::parse(&value, &Rfc3339).ok())
    });
    let Some(timestamp) = timestamp else {
        return false;
    };
    let maximum_age = maximum_age.min(i64::MAX as u64) as i64;
    (now - timestamp).whole_seconds() > maximum_age
}

fn arn_service(arn: &str) -> Option<&str> {
    arn.split(':').nth(2)
}

fn target_call(
    request: &DeliveryRequest,
    region: &str,
    account: &str,
    mode: InvocationMode,
) -> Result<CrossServiceCall, ()> {
    let parts: Vec<&str> = request.arn.split(':').collect();
    let service = *parts.get(2).ok_or(())?;
    let resource = parts.get(5..).ok_or(())?.join(":");
    let (method, uri, mut headers, body, target_service) = match service {
        "lambda" => {
            let name = resource.strip_prefix("function:").unwrap_or(&resource);
            let mut headers = HeaderMap::new();
            let invocation_type = match mode {
                InvocationMode::AsyncTarget => HeaderValue::from_static("Event"),
                InvocationMode::SyncEnrichment => HeaderValue::from_static("RequestResponse"),
            };
            headers.insert("x-amz-invocation-type", invocation_type);
            (
                Method::POST,
                uri(&format!("/2015-03-31/functions/{name}/invocations"))?,
                headers,
                Bytes::from(request.payload.clone()),
                "lambda",
            )
        }
        "sqs" => {
            let name = resource.rsplit(':').next().unwrap_or(&resource);
            let queue_region = parts.get(3).copied().unwrap_or(region);
            let queue_account = parts.get(4).copied().unwrap_or(account);
            let mut value = json!({
                "QueueUrl": format!("https://sqs.{queue_region}.amazonaws.com/{queue_account}/{name}"),
                "MessageBody": request.payload,
            });
            if let Some(group) = request
                .sqs_parameters
                .as_ref()
                .and_then(|v| v.get("MessageGroupId"))
            {
                value["MessageGroupId"] = group.clone();
            }
            json_call(
                "AmazonSQS.SendMessage",
                value,
                "application/x-amz-json-1.0",
                "sqs",
            )?
        }
        "sns" => {
            let body = format!(
                "Action=Publish&TopicArn={}&Message={}",
                percent(&request.arn),
                percent(&request.payload)
            );
            let mut headers = HeaderMap::new();
            headers.insert(
                "content-type",
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            (Method::POST, uri("/")?, headers, Bytes::from(body), "sns")
        }
        "states" => json_call(
            match mode {
                InvocationMode::AsyncTarget => "AWSStepFunctions.StartExecution",
                InvocationMode::SyncEnrichment => "AWSStepFunctions.StartSyncExecution",
            },
            json!({"stateMachineArn": request.arn, "input": request.payload}),
            "application/x-amz-json-1.0",
            "states",
        )?,
        "kinesis" => {
            let partition_key =
                kinesis_partition_key(request).unwrap_or_else(|| "locallycloud".into());
            let stream = resource.strip_prefix("stream/").unwrap_or(&resource);
            json_call(
                "Kinesis_20131202.PutRecord",
                json!({"StreamName": stream, "Data": base64(request.payload.as_bytes()), "PartitionKey": partition_key}),
                "application/x-amz-json-1.1",
                "kinesis",
            )?
        }
        "firehose" => {
            let stream = resource
                .strip_prefix("deliverystream/")
                .unwrap_or(&resource);
            json_call(
                "Firehose_20150804.PutRecord",
                json!({"DeliveryStreamName": stream, "Record": {"Data": base64(request.payload.as_bytes())}}),
                "application/x-amz-json-1.1",
                "firehose",
            )?
        }
        "logs" => {
            let group = resource
                .strip_prefix("log-group:")
                .unwrap_or(&resource)
                .split(":log-stream:")
                .next()
                .unwrap_or(&resource);
            json_call(
                "Logs_20140328.PutLogEvents",
                json!({"logGroupName": group, "logStreamName": "eventbridge", "logEvents": [{"timestamp": OffsetDateTime::now_utc().unix_timestamp() * 1000, "message": request.payload}]}),
                "application/x-amz-json-1.1",
                "logs",
            )?
        }
        "events" => {
            let bus = resource.strip_prefix("event-bus/").ok_or(())?;
            json_call(
                "AWSEvents.PutEvents",
                json!({"Entries": [event_bus_entry(request, bus)?]}),
                "application/x-amz-json-1.1",
                "events",
            )?
        }
        _ => return Err(()),
    };
    if request.source_service == "events" && target_service == "sqs" {
        if let Some(source_arn) = request.source_arn.as_deref() {
            headers.insert(
                "x-locallycloud-source-arn",
                HeaderValue::from_str(source_arn).map_err(|_| ())?,
            );
            headers.insert(
                "x-locallycloud-source-account",
                HeaderValue::from_str(account).map_err(|_| ())?,
            );
        }
    }
    headers.insert("authorization", authorization(region, target_service)?);
    let identity = request.role_arn.as_ref().map_or(
        CallerIdentity::ServicePrincipal {
            service: request.source_service.into(),
        },
        |role| CallerIdentity::AssumedRole {
            role_arn: role.clone(),
            session_name: "eventbridge".into(),
        },
    );
    let pattern = match request.source_service {
        "scheduler" => "scheduler->target",
        "pipes" => "pipes->target",
        _ => "eventbridge->target",
    };
    Ok(CrossServiceCall {
        source_service: ServiceName::new(request.source_service),
        account_id: account.to_string(),
        region: region.to_string(),
        method,
        uri,
        headers,
        body,
        identity,
        correlation: CorrelationContext::root(),
        pattern: Some(IntegrationPatternId(pattern)),
    })
}

fn event_bus_entry(request: &DeliveryRequest, bus: &str) -> Result<Value, ()> {
    let envelope: Value = serde_json::from_str(&request.payload).map_err(|_| ())?;
    let source = envelope.get("source").and_then(Value::as_str).ok_or(())?;
    let detail_type = envelope
        .get("detail-type")
        .and_then(Value::as_str)
        .ok_or(())?;
    let detail = envelope.get("detail").ok_or(())?.to_string();
    let resources = envelope
        .get("resources")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let time = envelope.get("time").cloned().ok_or(())?;
    Ok(json!({
        "Source": source,
        "DetailType": detail_type,
        "Detail": detail,
        "Resources": resources,
        "Time": time,
        "EventBusName": bus,
    }))
}

fn kinesis_partition_key(request: &DeliveryRequest) -> Option<String> {
    let parameters = request.target_parameters.as_ref()?;
    if let Some(key) = nested_string(parameters, "KinesisStreamParameters", "PartitionKey") {
        return Some(key.to_string());
    }
    let path = nested_string(parameters, "KinesisParameters", "PartitionKeyPath")?;
    let payload: Value = serde_json::from_str(&request.payload).ok()?;
    match crate::transform::extract(&payload, path) {
        Value::String(value) => Some(value),
        Value::Null => None,
        value => Some(value.to_string()),
    }
}

fn base64(value: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.chunks(3) {
        let encoded = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(char::from(TABLE[((encoded >> 18) & 63) as usize]));
        output.push(char::from(TABLE[((encoded >> 12) & 63) as usize]));
        output.push(if chunk.len() > 1 {
            char::from(TABLE[((encoded >> 6) & 63) as usize])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(TABLE[(encoded & 63) as usize])
        } else {
            '='
        });
    }
    output
}

fn nested_string<'a>(value: &'a Value, container: &str, key: &str) -> Option<&'a str> {
    value
        .get(container)
        .unwrap_or(value)
        .get(key)
        .and_then(Value::as_str)
}

fn json_call(
    target: &str,
    body: Value,
    content_type: &'static str,
    service: &'static str,
) -> Result<(Method, Uri, HeaderMap, Bytes, &'static str), ()> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(target).map_err(|_| ())?,
    );
    headers.insert("content-type", HeaderValue::from_static(content_type));
    Ok((
        Method::POST,
        uri("/")?,
        headers,
        Bytes::from(body.to_string()),
        service,
    ))
}

fn authorization(region: &str, service: &str) -> Result<HeaderValue, ()> {
    HeaderValue::from_str(&format!(
        "AWS4-HMAC-SHA256 Credential=locallycloud/19700101/{region}/{service}/aws4_request"
    ))
    .map_err(|_| ())
}

fn uri(value: &str) -> Result<Uri, ()> {
    value.parse().map_err(|_| ())
}

fn percent(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(arn: &str, payload: Value) -> DeliveryRequest {
        DeliveryRequest {
            source_service: "events",
            source_arn: None,
            arn: arn.into(),
            payload: payload.to_string(),
            role_arn: None,
            sqs_parameters: None,
            target_parameters: None,
            retry: RetryPolicy {
                maximum_attempts: 2,
                maximum_age_seconds: None,
            },
            dead_letter_arn: Some("arn:aws:sqs:us-east-1:000000000000:dlq".into()),
            scheduled_at: None,
        }
    }

    #[test]
    fn sqs_rule_delivery_carries_trusted_source_context() {
        let mut req = request(
            "arn:aws:sqs:us-east-1:000000000000:ingestion",
            json!({"ledgerId":"one"}),
        );
        let source = "arn:aws:events:us-east-1:000000000000:rule/orders/ledger";
        req.source_arn = Some(source.into());
        let call = target_call(
            &req,
            "us-east-1",
            "000000000000",
            InvocationMode::AsyncTarget,
        )
        .unwrap();
        assert_eq!(call.headers["x-locallycloud-source-arn"], source);
        assert_eq!(
            call.headers["x-locallycloud-source-account"],
            "000000000000"
        );
        req.source_service = "pipes";
        let call = target_call(
            &req,
            "us-east-1",
            "000000000000",
            InvocationMode::AsyncTarget,
        )
        .unwrap();
        assert!(!call.headers.contains_key("x-locallycloud-source-arn"));
    }

    struct StrictIam;

    impl locallycloud_core::integration::authorization::AuthorizationEvaluator for StrictIam {
        fn strict_sigv4_required(&self) -> bool {
            true
        }

        fn authorize(
            &self,
            _request: locallycloud_core::integration::authorization::AuthorizationRequest,
        ) -> Result<(), locallycloud_core::integration::authorization::AuthorizationError> {
            Ok(())
        }
    }

    struct NoopHandler;

    #[async_trait::async_trait]
    impl locallycloud_core::handler::NativeHandler for NoopHandler {
        async fn handle(
            &self,
            _request: locallycloud_core::handler::ServiceRequest,
        ) -> axum::response::Response {
            axum::response::Response::new(axum::body::Body::empty())
        }
    }

    #[test]
    fn strict_mode_rejects_roleless_classic_targets_without_resource_policy_path() {
        use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};

        let registry = ServiceRegistry::with_known_services();
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            std::sync::Arc::new(NoopHandler),
            std::sync::Arc::new(StrictIam),
        );
        for arn in [
            "arn:aws:lambda:us-east-1:000000000000:function:f",
            "arn:aws:sqs:us-east-1:000000000000:q",
            "arn:aws:sns:us-east-1:000000000000:t",
        ] {
            assert!(authorize_target(
                &registry,
                &request(arn, json!({})),
                InvocationMode::AsyncTarget,
                "000000000000",
            ));
        }
        for arn in [
            "arn:aws:states:us-east-1:000000000000:stateMachine:s",
            "arn:aws:kinesis:us-east-1:000000000000:stream/k",
            "arn:aws:firehose:us-east-1:000000000000:deliverystream/f",
            "arn:aws:events:us-east-1:000000000000:event-bus/b",
            "arn:aws:logs:us-east-1:000000000000:log-group:g",
        ] {
            assert!(!authorize_target(
                &registry,
                &request(arn, json!({})),
                InvocationMode::AsyncTarget,
                "000000000000",
            ));
        }
        let mut scheduler = request("arn:aws:sqs:us-east-1:000000000000:q", json!({}));
        scheduler.source_service = "scheduler";
        assert!(!authorize_target(
            &registry,
            &scheduler,
            InvocationMode::AsyncTarget,
            "000000000000",
        ));
    }

    #[test]
    fn invocation_mode_selects_lambda_and_step_functions_operations() {
        let lambda = request(
            "arn:aws:lambda:us-east-1:000000000000:function:f",
            json!({}),
        );
        let async_call = target_call(
            &lambda,
            "us-east-1",
            "000000000000",
            InvocationMode::AsyncTarget,
        )
        .unwrap();
        assert_eq!(async_call.headers["x-amz-invocation-type"], "Event");
        let sync_call = target_call(
            &lambda,
            "us-east-1",
            "000000000000",
            InvocationMode::SyncEnrichment,
        )
        .unwrap();
        assert_eq!(
            sync_call.headers["x-amz-invocation-type"],
            "RequestResponse"
        );

        let states = request(
            "arn:aws:states:us-east-1:000000000000:stateMachine:s",
            json!({}),
        );
        let async_call = target_call(
            &states,
            "us-east-1",
            "000000000000",
            InvocationMode::AsyncTarget,
        )
        .unwrap();
        assert_eq!(
            async_call.headers["x-amz-target"],
            "AWSStepFunctions.StartExecution"
        );
        let sync_call = target_call(
            &states,
            "us-east-1",
            "000000000000",
            InvocationMode::SyncEnrichment,
        )
        .unwrap();
        assert_eq!(
            sync_call.headers["x-amz-target"],
            "AWSStepFunctions.StartSyncExecution"
        );
    }

    #[test]
    fn step_functions_enrichment_returns_parsed_output() {
        let states = request(
            "arn:aws:states:us-east-1:000000000000:stateMachine:s",
            json!({}),
        );
        let response = br#"{"status":"SUCCEEDED","output":"{\"answer\":42}"}"#;
        assert_eq!(
            sync_output(&states, response).unwrap(),
            json!({"answer": 42})
        );
    }

    #[test]
    fn event_bus_target_preserves_canonical_event_fields() {
        let envelope = json!({
            "source": "app.orders",
            "detail-type": "Created",
            "detail": {"id": 7},
            "resources": ["arn:one"],
            "time": "2024-01-02T03:04:05Z",
            "id": "ignored"
        });
        let request = request(
            "arn:aws:events:us-east-1:000000000000:event-bus/downstream",
            envelope,
        );
        let call = target_call(
            &request,
            "us-east-1",
            "000000000000",
            InvocationMode::AsyncTarget,
        )
        .unwrap();
        let body: Value = serde_json::from_slice(&call.body).unwrap();
        let entry = &body["Entries"][0];
        assert_eq!(entry["Source"], "app.orders");
        assert_eq!(entry["DetailType"], "Created");
        assert_eq!(
            serde_json::from_str::<Value>(entry["Detail"].as_str().unwrap()).unwrap(),
            json!({"id": 7})
        );
        assert_eq!(entry["Resources"], json!(["arn:one"]));
        assert_eq!(entry["Time"], "2024-01-02T03:04:05Z");
    }

    #[test]
    fn stream_targets_use_partition_path_and_base64_blob_shapes() {
        let mut kinesis = request(
            "arn:aws:kinesis:us-east-1:000000000000:stream/orders",
            json!({"detail":{"tenant":"acme"}}),
        );
        kinesis.target_parameters = Some(json!({
            "KinesisParameters":{"PartitionKeyPath":"$.detail.tenant"}
        }));
        let call = target_call(
            &kinesis,
            "us-east-1",
            "000000000000",
            InvocationMode::AsyncTarget,
        )
        .unwrap();
        let body: Value = serde_json::from_slice(&call.body).unwrap();
        assert_eq!(body["StreamName"], "orders");
        assert_eq!(body["PartitionKey"], "acme");
        assert_eq!(body["Data"], base64(kinesis.payload.as_bytes()));

        let firehose = request(
            "arn:aws:firehose:us-east-1:000000000000:deliverystream/audit",
            json!({"ok":true}),
        );
        let call = target_call(
            &firehose,
            "us-east-1",
            "000000000000",
            InvocationMode::AsyncTarget,
        )
        .unwrap();
        let body: Value = serde_json::from_slice(&call.body).unwrap();
        assert_eq!(body["DeliveryStreamName"], "audit");
        assert_eq!(body["Record"]["Data"], base64(firehose.payload.as_bytes()));
    }

    #[test]
    fn scheduler_age_uses_due_time_not_user_input() {
        let mut request = request(
            "arn:aws:sqs:us-east-1:000000000000:q",
            json!({"time":"2000-01-01T00:00:00Z"}),
        );
        request.source_service = "scheduler";
        request.retry.maximum_age_seconds = Some(60);
        let due = OffsetDateTime::parse("2026-09-27T00:00:00Z", &Rfc3339).unwrap();
        request.scheduled_at = Some(due);
        assert!(!event_expired(&request, due + time::Duration::seconds(1)));
        assert!(event_expired(&request, due + time::Duration::seconds(61)));
    }

    #[test]
    fn maximum_event_age_is_enforced_for_canonical_envelopes() {
        let mut request = request(
            "arn:aws:sqs:us-east-1:000000000000:q",
            json!({"time": "2024-01-02T03:04:05Z"}),
        );
        request.retry.maximum_age_seconds = Some(60);
        let now = OffsetDateTime::parse("2024-01-02T03:05:06Z", &Rfc3339).unwrap();
        assert!(event_expired(&request, now));
        assert!(delivery_policy(&request).on_failure.is_none());
    }
}
