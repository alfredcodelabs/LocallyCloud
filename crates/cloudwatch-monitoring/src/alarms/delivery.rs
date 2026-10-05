use super::*;

pub(crate) fn start_worker(
    registry: &Arc<ServiceRegistry>,
    domain: Arc<MonitoringDomain>,
    alarms: Arc<Alarms>,
) -> tokio::task::JoinHandle<()> {
    let registry = Arc::downgrade(registry);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            if !alarms.active() {
                alarms.wake.notified().await;
                tick.reset();
            }
            tick.tick().await;
            let Some(registry) = registry.upgrade() else {
                break;
            };
            let a = alarms.clone();
            let d = domain.clone();
            let evaluated = tokio::task::spawn_blocking(move || {
                // A full backlog may defer a transition; existing deliveries must still drain.
                let _ = a.evaluate(&d, now_ms());
                a.pending()
            })
            .await;
            let Ok(Ok(pending)) = evaluated else {
                continue;
            };
            let Some(dispatcher) = registry.internal_dispatcher() else {
                continue;
            };
            let engine = locallycloud_core::integration::delivery::DeliveryEngine::new(dispatcher);
            for action in pending {
                let mut headers = http::HeaderMap::new();
                headers.insert(
                    "content-type",
                    "application/x-www-form-urlencoded".parse().unwrap(),
                );
                let body = format!(
                    "Action=Publish&TopicArn={}&Message={}",
                    encode_form(&action.target),
                    encode_form(&action.message)
                );
                let call = locallycloud_core::integration::delivery::CrossServiceCall {
                    source_service: ServiceName::new("monitoring"),
                    account_id: action.scope.account_id.clone(),
                    region: action.scope.region.clone(),
                    method: http::Method::POST,
                    uri: "/".parse().unwrap(),
                    headers,
                    body: body.into(),
                    identity:
                        locallycloud_core::integration::identity::CallerIdentity::ServicePrincipal {
                            service: "cloudwatch".into(),
                        },
                    correlation:
                        locallycloud_core::integration::correlation::CorrelationContext::root(),
                    pattern: None,
                };
                let response = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    engine.deliver_sync(call),
                )
                .await;
                if let Ok(response) = response {
                    let status = response.status();
                    // Invalid/deleted targets and denied actions are terminal and audited;
                    // throttling, timeout and server failures remain durable retries.
                    let permanent = match status.as_u16() {
                        401 | 403 | 404 => true,
                        400 => {
                            // SNS may report throttling with HTTP 400. Only confirmed client
                            // errors are terminal; an unknown response remains retryable.
                            axum::body::to_bytes(response.into_body(), 65536)
                                .await
                                .ok()
                                .is_some_and(|body| {
                                    let text = String::from_utf8_lossy(&body);
                                    [
                                        "InvalidParameter",
                                        "InvalidParameterValue",
                                        "NotFound",
                                        "AuthorizationError",
                                        "AccessDenied",
                                    ]
                                    .iter()
                                    .any(|code| text.contains(&format!("<Code>{code}</Code>")))
                                })
                        }
                        _ => false,
                    };
                    if status.is_success() || permanent {
                        let a = alarms.clone();
                        let id = action.id;
                        let failure = (!status.is_success())
                            .then(|| format!("SNS Publish returned HTTP {}", status.as_u16()));
                        let _ = tokio::task::spawn_blocking(move || {
                            a.finish_action(id, failure.as_deref())
                        })
                        .await;
                    }
                }
            }
        }
    })
}
fn encode_form(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
