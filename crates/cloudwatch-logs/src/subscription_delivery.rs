use std::io::Write;
use std::sync::{Arc, Mutex, Weak};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use flate2::write::GzEncoder;
use flate2::Compression;
use http::{HeaderMap, HeaderValue, Method, Uri};
use locallycloud_core::integration::correlation::CorrelationContext;
use locallycloud_core::integration::delivery::{
    AsyncDeliveryPolicy, CrossServiceCall, DeliveryEngine,
};
use locallycloud_core::integration::identity::CallerIdentity;
use locallycloud_core::integration::pattern::IntegrationPatternId;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::error::LogsError;
use crate::model::{PendingSubscriptionDelivery, ScopeKey, StoredEvent};
use crate::store::LogsStore;

const DELIVERY_BATCH_SIZE: usize = 100;
const MAX_ASYNC_PAYLOAD_BYTES: usize = 256 * 1024;

pub struct SubscriptionDeliveryWorker {
    store: Arc<LogsStore>,
    registry: Weak<ServiceRegistry>,
    notify: Arc<Notify>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl SubscriptionDeliveryWorker {
    pub fn new(store: Arc<LogsStore>, registry: Weak<ServiceRegistry>) -> Self {
        Self {
            store,
            registry,
            notify: Arc::new(Notify::new()),
            handle: Mutex::new(None),
        }
    }

    pub fn wake(&self) {
        let Ok(mut handle) = self.handle.lock() else {
            return;
        };
        if handle.as_ref().is_none_or(JoinHandle::is_finished) {
            let store = self.store.clone();
            let registry = self.registry.clone();
            let notify = self.notify.clone();
            *handle = Some(tokio::spawn(async move {
                run(store, registry, notify).await;
            }));
        }
        self.notify.notify_one();
    }
}

impl Drop for SubscriptionDeliveryWorker {
    fn drop(&mut self) {
        self.notify.notify_waiters();
        if let Ok(handle) = self.handle.get_mut() {
            if let Some(handle) = handle.take() {
                handle.abort();
            }
        }
    }
}

async fn run(store: Arc<LogsStore>, registry: Weak<ServiceRegistry>, notify: Arc<Notify>) {
    loop {
        tokio::select! { _=notify.notified()=>{}, _=tokio::time::sleep(std::time::Duration::from_secs(5))=>{} }
        loop {
            let deliveries = match store.pending_subscription_deliveries(DELIVERY_BATCH_SIZE) {
                Ok(deliveries) if !deliveries.is_empty() => deliveries,
                _ => break,
            };
            let mut failed = false;
            for delivery in deliveries {
                let delivered = deliver(&registry, &delivery).await;
                let owned = store.clone();
                let finished = tokio::task::spawn_blocking(move || {
                    owned.finish_subscription_delivery(delivery.id, delivered)
                })
                .await;
                if !matches!(finished, Ok(Ok(()))) {
                    return;
                }
                failed |= !delivered;
            }
            if failed {
                break;
            }
        }
    }
}

async fn deliver(registry: &Weak<ServiceRegistry>, delivery: &PendingSubscriptionDelivery) -> bool {
    let Some(registry) = registry.upgrade() else {
        return false;
    };
    let Some(dispatcher) = registry.internal_dispatcher() else {
        return false;
    };
    let payloads = match split_payloads(delivery) {
        Ok(payloads) => payloads,
        Err(_) => return false,
    };
    let engine = DeliveryEngine::new(dispatcher);
    let policy = AsyncDeliveryPolicy {
        max_attempts: 3,
        on_failure: None,
    };
    for payload in payloads {
        let call = match lambda_call(
            &delivery.group_key.scope,
            &delivery.group_key.name,
            &delivery.function_name,
            payload,
            "Event",
        ) {
            Ok(call) => call,
            Err(_) => return false,
        };
        if engine.deliver_async(call, &policy).await.is_err() {
            return false;
        }
    }
    true
}

fn split_payloads(delivery: &PendingSubscriptionDelivery) -> Result<Vec<Vec<u8>>, LogsError> {
    let mut payloads = Vec::new();
    let mut start = 0;
    while start < delivery.events.len() {
        let mut low = start + 1;
        let mut high = delivery.events.len();
        let mut accepted = None;
        while low <= high {
            let middle = low + (high - low) / 2;
            let payload = encode_payload(delivery, &delivery.events[start..middle])?;
            if payload.len() <= MAX_ASYNC_PAYLOAD_BYTES {
                accepted = Some((middle, payload));
                low = middle + 1;
            } else {
                high = middle.saturating_sub(1);
            }
        }
        let Some((end, payload)) = accepted else {
            return Err(LogsError::InvalidParameter(
                "a subscription event exceeds the Lambda async payload limit".into(),
            ));
        };
        payloads.push(payload);
        start = end;
    }
    Ok(payloads)
}

fn encode_payload(
    delivery: &PendingSubscriptionDelivery,
    events: &[StoredEvent],
) -> Result<Vec<u8>, LogsError> {
    let envelope = SubscriptionEnvelope {
        owner: &delivery.group_key.scope.account_id,
        log_group: &delivery.group_key.name,
        log_stream: &delivery.log_stream_name,
        subscription_filters: [&delivery.filter_name],
        message_type: "DATA_MESSAGE",
        log_events: events
            .iter()
            .map(|event| SubscriptionLogEvent {
                id: &event.id,
                timestamp: event.timestamp_ms,
                message: &event.message,
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|_| LogsError::ServiceUnavailable("subscription serialization failed".into()))?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&bytes)
        .map_err(|_| LogsError::ServiceUnavailable("subscription gzip failed".into()))?;
    let compressed = encoder
        .finish()
        .map_err(|_| LogsError::ServiceUnavailable("subscription gzip failed".into()))?;
    serde_json::to_vec(&json!({ "awslogs": { "data": STANDARD.encode(compressed) } }))
        .map_err(|_| LogsError::ServiceUnavailable("subscription serialization failed".into()))
}

pub(crate) fn lambda_call(
    scope: &ScopeKey,
    log_group: &str,
    function_name: &str,
    payload: Vec<u8>,
    invocation_type: &'static str,
) -> Result<CrossServiceCall, LogsError> {
    let uri: Uri = format!("/2015-03-31/functions/{function_name}/invocations")
        .parse()
        .map_err(|_| LogsError::ServiceUnavailable("invalid Lambda invocation path".into()))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-invocation-type",
        HeaderValue::from_static(invocation_type),
    );
    headers.insert(
        "x-locallycloud-source-arn",
        HeaderValue::from_str(&format!(
            "arn:aws:logs:{}:{}:log-group:{log_group}",
            scope.region, scope.account_id,
        ))
        .map_err(|_| LogsError::ServiceUnavailable("invalid subscription source ARN".into()))?,
    );
    headers.insert(
        "x-locallycloud-source-account",
        HeaderValue::from_str(&scope.account_id).map_err(|_| {
            LogsError::ServiceUnavailable("invalid subscription source account".into())
        })?,
    );
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential=locallycloud/19700101/{}/lambda/aws4_request",
            scope.region
        ))
        .map_err(|_| LogsError::ServiceUnavailable("invalid Lambda authorization".into()))?,
    );
    Ok(CrossServiceCall {
        source_service: ServiceName::new("logs"),
        account_id: scope.account_id.clone(),
        region: scope.region.clone(),
        method: Method::POST,
        uri,
        headers,
        body: payload.into(),
        identity: CallerIdentity::ServicePrincipal {
            service: "logs".into(),
        },
        correlation: CorrelationContext::root(),
        pattern: Some(IntegrationPatternId("logs->lambda")),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionEnvelope<'a> {
    owner: &'a str,
    log_group: &'a str,
    log_stream: &'a str,
    subscription_filters: [&'a str; 1],
    message_type: &'static str,
    log_events: Vec<SubscriptionLogEvent<'a>>,
}

#[derive(Serialize)]
struct SubscriptionLogEvent<'a> {
    id: &'a str,
    timestamp: i64,
    message: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use locallycloud_core::handler::{NativeHandler, ServiceRequest};
    use locallycloud_core::integration::identity::PRINCIPAL_HEADER;
    use locallycloud_core::integration::InternalDispatcher;
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
    use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};

    #[tokio::test]
    async fn subscription_calls_attest_the_actual_log_group_and_service_principal() {
        struct Destination;
        #[async_trait]
        impl NativeHandler for Destination {
            async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
                assert_eq!(request.account_id, "000000000000");
                assert_eq!(request.region, "us-east-2");
                assert_eq!(
                    request.headers["x-locallycloud-verified-internal-scope"],
                    "1"
                );
                assert_eq!(request.headers[PRINCIPAL_HEADER], "logs.amazonaws.com");
                assert_eq!(
                    request.headers["x-locallycloud-source-account"],
                    "000000000000"
                );
                assert_eq!(
                    request.headers["x-locallycloud-source-arn"],
                    "arn:aws:logs:us-east-2:000000000000:log-group:accounting/custom-logs"
                );
                let status = if request.headers["x-amz-invocation-type"] == "DryRun" {
                    204
                } else {
                    202
                };
                http::Response::builder()
                    .status(status)
                    .body(axum::body::Body::empty())
                    .unwrap()
            }
        }
        let registry = Arc::new(ServiceRegistry::new());
        registry.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            Arc::new(Destination),
        );
        let dispatcher = Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: std::time::Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            "us-east-2".into(),
            "000000000000".into(),
        ));
        let scope = ScopeKey {
            account_id: "000000000000".into(),
            region: "us-east-2".into(),
        };
        let engine = DeliveryEngine::new(dispatcher);
        for (invocation, expected) in [("DryRun", 204), ("Event", 202)] {
            let response = engine
                .deliver_sync(
                    lambda_call(
                        &scope,
                        "accounting/custom-logs",
                        "worker",
                        b"{}".to_vec(),
                        invocation,
                    )
                    .unwrap(),
                )
                .await;
            assert_eq!(response.status(), expected);
        }
    }
}
