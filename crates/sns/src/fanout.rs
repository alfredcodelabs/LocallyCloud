//! Fanout delivery to confirmed, filter-matching subscriptions.
//!
//! SNS→SQS delivery is performed in-process by dispatching a real `SendMessage` to the SQS
//! native handler through the Core registry (the integration path). SNS→Lambda is delivered
//! as an async invoke when the Lambda data plane is available; a per-subscription failure
//! never fails the publish.

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};

use crate::envelope::Notification;
use crate::filter;
use crate::model::{MessageAttribute, Subscription};

/// An owned message that can be delivered from background tasks.
#[derive(Clone, Serialize, Deserialize)]
pub struct Delivery {
    pub message_id: String,
    pub topic_arn: String,
    pub message: String,
    pub structure: Option<serde_json::Map<String, Value>>,
    pub subject: Option<String>,
    pub timestamp: String,
    pub attributes: BTreeMap<String, MessageAttribute>,
    pub group_id: Option<String>,
    pub dedup_id: Option<String>,
    pub region: String,
    pub account: String,
    pub request_id: String,
}

impl Delivery {
    /// Resolve the message body for a protocol: the protocol-specific key of a JSON message
    /// structure, else `default`, else the plain message.
    fn resolve(&self, protocol: &str) -> &str {
        self.structure
            .as_ref()
            .and_then(|m| m.get(protocol).or_else(|| m.get("default")))
            .and_then(Value::as_str)
            .unwrap_or(&self.message)
    }
}

/// One accepted publication and the subscription snapshot selected for it.
#[derive(Clone, Serialize, Deserialize)]
pub struct FanoutJob {
    #[serde(skip)]
    pub outbox_id: Option<i64>,
    pub subscriptions: Vec<Subscription>,
    pub delivery: Delivery,
}

#[derive(Clone, Copy)]
pub enum DeliveryFailure {
    Subscription,
    Task,
    HttpRejected(u16),
    Egress(locallycloud_core::egress::EgressError),
}
impl DeliveryFailure {
    fn diagnostic(self) -> (&'static str, u16) {
        match self {
            Self::Subscription => ("subscription_not_acknowledged", 400),
            Self::Task => ("delivery_task_failed", 500),
            Self::HttpRejected(status) => ("http_subscriber_rejected", status),
            Self::Egress(error) => {
                use locallycloud_core::egress::EgressError;
                match error {
                    EgressError::InvalidUrl
                    | EgressError::InvalidOrigin(_)
                    | EgressError::DestinationDenied
                    | EgressError::DnsAnswers => ("http_destination_denied", 400),
                    EgressError::Timeout => ("http_subscriber_timeout", 504),
                    EgressError::DnsResolution => ("http_dns_resolution_failed", 503),
                    EgressError::HostProbe => ("http_host_probe_failed", 503),
                    EgressError::CacheUnavailable | EgressError::ClientInitialization => {
                        ("http_client_unavailable", 500)
                    }
                    EgressError::TlsConfiguration => ("http_tls_configuration_failed", 500),
                    EgressError::Connection => ("http_subscriber_connection_failed", 503),
                }
            }
        }
    }
}

/// Deliver to every confirmed subscription whose filter policy matches. Each subscription owns
/// its task, so a slow endpoint cannot delay another target. The caller may await this function to
/// serialize FIFO publications, or detach it for standard topics.
pub async fn deliver_accepted(
    registry: Arc<ServiceRegistry>,
    http: Arc<locallycloud_core::egress::EgressClient>,
    store: Arc<crate::store::SnsStore>,
    job: FanoutJob,
) {
    let id = job.outbox_id;
    let mut backoff = std::time::Duration::from_secs(store.config.outbox_retry_initial_secs);
    loop {
        let outcome = fan_out(registry.clone(), http.clone(), job.clone()).await;
        let (cause, status) = match outcome {
            Ok(()) => {
                let owned = store.clone();
                match tokio::task::spawn_blocking(move || owned.complete_job(id)).await {
                    Ok(Ok(())) => return,
                    _ => ("outbox_acknowledgement_failed", 500),
                }
            }
            Err(failure) => failure.diagnostic(),
        };
        locallycloud_core::observability::log_service_error(
            "sns",
            Some("Fanout"),
            &job.delivery.request_id,
            cause,
            status,
        );
        if id.is_none() {
            return;
        }
        // A deleted topic cascades its outbox rows; stop retrying that publication.
        let owned = store.clone();
        if matches!(
            tokio::task::spawn_blocking(move || owned.job_exists(id)).await,
            Ok(Ok(false))
        ) {
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(
            store.config.outbox_retry_max_secs,
        ));
    }
}

pub async fn fan_out(
    registry: Arc<ServiceRegistry>,
    http: Arc<locallycloud_core::egress::EgressClient>,
    job: FanoutJob,
) -> Result<(), DeliveryFailure> {
    let delivery = Arc::new(job.delivery);
    let mut tasks = tokio::task::JoinSet::new();
    for sub in job.subscriptions {
        if !sub.confirmed || !filter_matches(&sub, &delivery) {
            continue;
        }
        let registry = registry.clone();
        let http = http.clone();
        let delivery = delivery.clone();
        tasks.spawn(async move { deliver_subscription(&registry, &http, &sub, &delivery).await });
    }
    let mut failure = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(cause)) => {
                if failure.is_none_or(|previous: DeliveryFailure| {
                    previous.diagnostic().1 < 500 && cause.diagnostic().1 >= 500
                }) {
                    failure = Some(cause);
                }
            }
            Err(_) => {
                failure = Some(DeliveryFailure::Task);
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

async fn deliver_subscription(
    registry: &ServiceRegistry,
    http: &Arc<locallycloud_core::egress::EgressClient>,
    sub: &Subscription,
    d: &Delivery,
) -> Result<(), DeliveryFailure> {
    let (retries, delay) = delivery_policy(sub);
    let mut failure = DeliveryFailure::Subscription;
    for attempt in 0..=retries {
        let delivered = match sub.protocol.as_str() {
            "sqs" => {
                if deliver_to_sqs(registry, sub, d).await {
                    Ok(())
                } else {
                    Err(DeliveryFailure::Subscription)
                }
            }
            "lambda" => {
                if deliver_to_lambda(registry, sub, d).await {
                    Ok(())
                } else {
                    Err(DeliveryFailure::Subscription)
                }
            }
            "http" | "https" => deliver_to_http(http, sub, d).await,
            _ => Err(DeliveryFailure::Subscription),
        };
        match delivered {
            Ok(()) => return Ok(()),
            Err(cause) => failure = cause,
        }
        if attempt < retries && !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
    if handle_failed_delivery(registry, sub, d).await {
        Ok(())
    } else {
        Err(failure)
    }
}

fn delivery_policy(sub: &Subscription) -> (u32, std::time::Duration) {
    let Some(policy) = sub
        .attributes
        .get("DeliveryPolicy")
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
    else {
        return (3, std::time::Duration::ZERO);
    };
    let healthy = policy.get("healthyRetryPolicy").unwrap_or(&policy);
    let retries = healthy
        .get("numRetries")
        .and_then(Value::as_u64)
        .unwrap_or(3) as u32;
    let delay = healthy
        .get("minDelayTarget")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    (retries, std::time::Duration::from_secs(delay))
}

/// On delivery failure, route the notification to the subscription's dead-letter queue when a
/// `RedrivePolicy` is set. Return false when neither target accepted the notification.
async fn handle_failed_delivery(
    registry: &ServiceRegistry,
    sub: &Subscription,
    d: &Delivery,
) -> bool {
    let dlq_arn = sub
        .attributes
        .get("RedrivePolicy")
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .and_then(|p| {
            p.get("deadLetterTargetArn")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    match dlq_arn {
        Some(arn) => {
            let notification = Notification {
                message_id: &d.message_id,
                topic_arn: &d.topic_arn,
                subscription_arn: &sub.arn,
                message: &d.message,
                subject: d.subject.as_deref(),
                timestamp: &d.timestamp,
                attributes: &d.attributes,
            };
            let sent = send_to_sqs_arn(registry, &arn, &notification.envelope_string(), d).await;
            sent
        }
        None => false,
    }
}

fn filter_matches(sub: &Subscription, d: &Delivery) -> bool {
    let Some(raw) = sub.attributes.get("FilterPolicy") else {
        return true;
    };
    let Ok(policy) = filter::validate(raw) else {
        return false;
    };
    let scope = sub
        .attributes
        .get("FilterPolicyScope")
        .map(String::as_str)
        .unwrap_or("MessageAttributes");
    if scope == "MessageBody" {
        filter::matches_body(&policy, &d.message)
    } else {
        filter::matches_attributes(&policy, &d.attributes)
    }
}

async fn dispatch(registry: &ServiceRegistry, service: &str, request: ServiceRequest) -> bool {
    match registry.native_handler(&ServiceName::new(service)) {
        Some(handler) => {
            let resp = handler.handle(request).await;
            resp.status().is_success()
        }
        None => false,
    }
}

async fn dispatch_sqs_delivery(
    registry: &ServiceRegistry,
    mut request: ServiceRequest,
    delivery: &Delivery,
) -> bool {
    let Some(dispatcher) = registry.internal_dispatcher() else {
        return false;
    };
    let Ok(source_arn) = HeaderValue::from_str(&delivery.topic_arn) else {
        return false;
    };
    let Ok(source_account) = HeaderValue::from_str(&delivery.account) else {
        return false;
    };
    request
        .headers
        .insert("x-locallycloud-source-arn", source_arn);
    request
        .headers
        .insert("x-locallycloud-source-account", source_account);
    let call = locallycloud_core::integration::delivery::CrossServiceCall {
        source_service: ServiceName::new("sns"),
        account_id: request.account_id,
        region: request.region,
        method: request.method,
        uri: request.uri,
        headers: request.headers,
        body: request.body,
        identity: locallycloud_core::integration::identity::CallerIdentity::ServicePrincipal {
            service: "sns".into(),
        },
        correlation: locallycloud_core::integration::correlation::CorrelationContext::root(),
        pattern: None,
    };
    locallycloud_core::integration::delivery::DeliveryEngine::new(dispatcher)
        .deliver_sync(call)
        .await
        .status()
        .is_success()
}

pub async fn sqs_target_exists(
    registry: &ServiceRegistry,
    queue_arn: &str,
    region: &str,
    account: &str,
    request_id: &str,
) -> bool {
    let parts: Vec<&str> = queue_arn.split(':').collect();
    if parts.len() != 6
        || parts[0] != "arn"
        || parts[2] != "sqs"
        || parts[3] != region
        || parts[4] != account
        || parts[5].is_empty()
    {
        return false;
    }
    let queue_url = format!(
        "https://sqs.{}.amazonaws.com/{}/{}",
        parts[3], parts[4], parts[5]
    );
    dispatch(
        registry,
        "sqs",
        json_request(
            "AmazonSQS.GetQueueAttributes",
            json!({"QueueUrl": queue_url, "AttributeNames": ["QueueArn"]}),
            region,
            account,
            request_id,
        ),
    )
    .await
}

async fn deliver_to_sqs(registry: &ServiceRegistry, sub: &Subscription, d: &Delivery) -> bool {
    // The endpoint is the queue ARN: arn:aws:sqs:<region>:<account>:<name>.
    let parts: Vec<&str> = sub.endpoint.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    let (region, account, name) = (parts[3], parts[4], parts[5]);
    let queue_url = format!("https://sqs.{region}.amazonaws.com/{account}/{name}");
    let message = d.resolve("sqs");

    let mut payload = json!({ "QueueUrl": queue_url });
    let obj = payload.as_object_mut().unwrap();
    if sub.raw_delivery() {
        obj.insert("MessageBody".into(), json!(message));
        if !d.attributes.is_empty() {
            obj.insert("MessageAttributes".into(), sqs_attributes(&d.attributes));
        }
    } else {
        let notification = Notification {
            message_id: &d.message_id,
            topic_arn: &d.topic_arn,
            subscription_arn: &sub.arn,
            message,
            subject: d.subject.as_deref(),
            timestamp: &d.timestamp,
            attributes: &d.attributes,
        };
        obj.insert("MessageBody".into(), json!(notification.envelope_string()));
    }
    if name.ends_with(".fifo") {
        if let Some(g) = d.group_id.as_deref() {
            obj.insert("MessageGroupId".into(), json!(g));
        }
        if let Some(dd) = d.dedup_id.as_deref() {
            obj.insert("MessageDeduplicationId".into(), json!(dd));
        }
    }

    let request = json_request(
        "AmazonSQS.SendMessage",
        payload,
        &d.region,
        &d.account,
        &d.request_id,
    );
    dispatch_sqs_delivery(registry, request, d).await
}

/// Send a plain body to an SQS queue identified by ARN (used for dead-letter delivery).
async fn send_to_sqs_arn(
    registry: &ServiceRegistry,
    queue_arn: &str,
    body: &str,
    d: &Delivery,
) -> bool {
    let parts: Vec<&str> = queue_arn.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    let (region, account, name) = (parts[3], parts[4], parts[5]);
    let queue_url = format!("https://sqs.{region}.amazonaws.com/{account}/{name}");
    let payload = json!({ "QueueUrl": queue_url, "MessageBody": body });
    let request = json_request(
        "AmazonSQS.SendMessage",
        payload,
        &d.region,
        &d.account,
        &d.request_id,
    );
    dispatch_sqs_delivery(registry, request, d).await
}

/// POST the notification (non-raw envelope, or bare body for raw delivery) to an http/https
/// subscriber with the AWS-documented SNS headers. A non-2xx or unreachable endpoint is a
/// failed delivery (routed to the DLQ by the caller) but never fails `Publish`.
async fn deliver_to_http(
    http: &Arc<locallycloud_core::egress::EgressClient>,
    sub: &Subscription,
    d: &Delivery,
) -> Result<(), DeliveryFailure> {
    let raw = sub.raw_delivery();
    let body = if raw {
        d.resolve(&sub.protocol).to_string()
    } else {
        let notification = Notification {
            message_id: &d.message_id,
            topic_arn: &d.topic_arn,
            subscription_arn: &sub.arn,
            message: d.resolve(&sub.protocol),
            subject: d.subject.as_deref(),
            timestamp: &d.timestamp,
            attributes: &d.attributes,
        };
        notification.envelope_string()
    };
    let mut builder = http
        .request(Method::POST, &sub.endpoint)
        .map_err(DeliveryFailure::Egress)?
        .header("x-amz-sns-message-type", "Notification")
        .header("x-amz-sns-message-id", &d.message_id)
        .header("x-amz-sns-topic-arn", &d.topic_arn)
        .header("x-amz-sns-subscription-arn", sub.arn.as_str())
        .header("content-type", "text/plain; charset=UTF-8")
        .body(body);
    if raw {
        builder = builder.header("x-amz-sns-rawdelivery", "true");
    }
    match builder.send().await {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => Err(DeliveryFailure::HttpRejected(response.status().as_u16())),
        Err(error) => Err(DeliveryFailure::Egress(
            locallycloud_core::egress::EgressError::from_request(&error),
        )),
    }
}

async fn deliver_to_lambda(registry: &ServiceRegistry, sub: &Subscription, d: &Delivery) -> bool {
    // Endpoint is the function ARN: arn:aws:lambda:<region>:<account>:function:<name>.
    let parts: Vec<&str> = sub.endpoint.split(':').collect();
    if parts.len() < 7 {
        return false;
    }
    let name = parts[6];
    let message = d.resolve("lambda");
    let notification = Notification {
        message_id: &d.message_id,
        topic_arn: &d.topic_arn,
        subscription_arn: &sub.arn,
        message,
        subject: d.subject.as_deref(),
        timestamp: &d.timestamp,
        attributes: &d.attributes,
    };
    let event = notification.lambda_event(&sub.arn);
    // Async (event) invocation; the path mirrors the Lambda data-plane invoke endpoint.
    let mut headers = base_headers(&d.region, &d.account, &d.request_id);
    headers.insert("x-amz-invocation-type", HeaderValue::from_static("Event"));
    let request = ServiceRequest {
        method: Method::POST,
        uri: format!("/2015-03-31/functions/{name}/invocations")
            .parse()
            .unwrap_or_else(|_| "/".parse().unwrap()),
        headers,
        body: Bytes::from(event.to_string()),
        region: d.region.to_string(),
        account_id: d.account.to_string(),
        request_id: d.request_id.to_string(),
    };
    dispatch(registry, "lambda", request).await
}

/// Convert SNS message attributes to the SQS `MessageAttributes` request shape.
fn sqs_attributes(attrs: &BTreeMap<String, MessageAttribute>) -> Value {
    // The SQS and SNS JSON attribute shapes are identical ({DataType, StringValue/BinaryValue}).
    use crate::model::AttributeValue;
    let mut map = serde_json::Map::new();
    for (name, attr) in attrs {
        let mut spec = serde_json::Map::new();
        spec.insert("DataType".into(), json!(attr.data_type));
        match &attr.value {
            AttributeValue::String(s) => {
                spec.insert("StringValue".into(), json!(s));
            }
            AttributeValue::Binary(b) => {
                use base64::Engine;
                spec.insert(
                    "BinaryValue".into(),
                    json!(base64::engine::general_purpose::STANDARD.encode(b)),
                );
            }
        }
        map.insert(name.clone(), Value::Object(spec));
    }
    Value::Object(map)
}

fn base_headers(_region: &str, _account: &str, _request_id: &str) -> HeaderMap {
    HeaderMap::new()
}

/// POST a `SubscriptionConfirmation` message to an http/https endpoint so the subscriber can
/// confirm via the `SubscribeURL`. Best-effort: a failure never fails `Subscribe`.
pub async fn send_confirmation(
    http: &Arc<locallycloud_core::egress::EgressClient>,
    base: &str,
    endpoint: &str,
    topic_arn: &str,
    token: &str,
    request_id: &str,
) {
    let subscribe_url =
        format!("{base}/?Action=ConfirmSubscription&TopicArn={topic_arn}&Token={token}");
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let msg = crate::envelope::confirmation_message(
        request_id,
        topic_arn,
        token,
        &subscribe_url,
        &timestamp,
    );
    let request = match http.request(Method::POST, endpoint) {
        Ok(request) => request,
        Err(error) => {
            let (cause, status) = DeliveryFailure::Egress(error).diagnostic();
            locallycloud_core::observability::log_service_error(
                "sns",
                Some("Subscribe"),
                request_id,
                cause,
                status,
            );
            return;
        }
    };
    let response = request
        .header("x-amz-sns-message-type", "SubscriptionConfirmation")
        .header("x-amz-sns-topic-arn", topic_arn)
        .header("content-type", "text/plain; charset=UTF-8")
        .body(msg.to_string())
        .send()
        .await;
    let failure = match response {
        Ok(response) if response.status().is_success() => None,
        Ok(response) => Some(("confirmation_not_acknowledged", response.status().as_u16())),
        Err(error) => Some(
            DeliveryFailure::Egress(locallycloud_core::egress::EgressError::from_request(&error))
                .diagnostic(),
        ),
    };
    if let Some((cause, status)) = failure {
        locallycloud_core::observability::log_service_error(
            "sns",
            Some("Subscribe"),
            request_id,
            cause,
            status,
        );
    }
}

fn json_request(
    target: &str,
    body: Value,
    region: &str,
    account: &str,
    request_id: &str,
) -> ServiceRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(target).expect("static target is valid"),
    );
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/x-amz-json-1.0"),
    );
    ServiceRequest {
        method: Method::POST,
        uri: "/".parse().expect("root uri is valid"),
        headers,
        body: Bytes::from(body.to_string()),
        region: region.to_string(),
        account_id: account.to_string(),
        request_id: request_id.to_string(),
    }
}
