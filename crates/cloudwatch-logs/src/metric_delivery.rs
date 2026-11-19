use std::sync::{Arc, Mutex, Weak};

use locallycloud_core::integration::metrics::{EmitOutcome, MetricObservation, MetricSink};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::store::LogsStore;

const DELIVERY_BATCH_SIZE: usize = 500;

pub struct MetricDeliveryWorker {
    retry_interval: std::time::Duration,
    store: Arc<LogsStore>,
    registry: Weak<ServiceRegistry>,
    notify: Arc<Notify>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl MetricDeliveryWorker {
    #[cfg(test)]
    pub fn new(store: Arc<LogsStore>, registry: Weak<ServiceRegistry>) -> Self {
        Self::with_retry_interval(
            store,
            registry,
            std::time::Duration::from_millis(
                crate::LogsConfig::default().delivery_retry_interval_ms,
            ),
        )
    }
    pub fn with_retry_interval(
        store: Arc<LogsStore>,
        registry: Weak<ServiceRegistry>,
        retry_interval: std::time::Duration,
    ) -> Self {
        Self {
            retry_interval,
            store,
            registry,
            notify: Arc::new(Notify::new()),
            handle: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn started(&self) -> bool {
        self.handle.lock().unwrap().is_some()
    }

    pub fn wake(&self) {
        let Ok(mut handle) = self.handle.lock() else {
            return;
        };
        if handle.as_ref().is_none_or(JoinHandle::is_finished) {
            let store = self.store.clone();
            let registry = self.registry.clone();
            let notify = self.notify.clone();
            let retry_interval = self.retry_interval;
            *handle = Some(tokio::spawn(async move {
                run(store, registry, notify, retry_interval).await;
            }));
        }
        self.notify.notify_one();
    }
}

impl Drop for MetricDeliveryWorker {
    fn drop(&mut self) {
        self.notify.notify_waiters();
        if let Ok(handle) = self.handle.get_mut() {
            if let Some(handle) = handle.take() {
                handle.abort();
            }
        }
    }
}

async fn emit(
    sink: &dyn MetricSink,
    observations: Vec<MetricObservation>,
    durable: bool,
) -> EmitOutcome {
    if durable {
        sink.emit_durable(observations).await
    } else {
        sink.try_emit(observations)
    }
}

/// Settle effects in the store: delivered (or permanently refused) effects are removed, the
/// rest are marked failed for retry. Returns false when the store could not be updated.
async fn finish(store: &Arc<LogsStore>, ids: Vec<u64>, settled: bool) -> bool {
    if ids.is_empty() {
        return true;
    }
    let owned = store.clone();
    matches!(
        tokio::task::spawn_blocking(move || owned.finish_metric_effects(&ids, settled)).await,
        Ok(Ok(()))
    )
}

async fn run(
    store: Arc<LogsStore>,
    registry: Weak<ServiceRegistry>,
    notify: Arc<Notify>,
    retry_interval: std::time::Duration,
) {
    let mut retry_pending = false;
    loop {
        if retry_pending {
            tokio::select! { _=notify.notified()=>{}, _=tokio::time::sleep(retry_interval)=>{} }
        } else {
            notify.notified().await;
        }
        retry_pending = false;
        loop {
            let effects = match store.pending_metric_effects(DELIVERY_BATCH_SIZE) {
                Ok(effects) if !effects.is_empty() => effects,
                Ok(_) => break,
                Err(_) => {
                    locallycloud_core::observability::log_service_error(
                        "logs",
                        Some("MetricDelivery"),
                        "background",
                        "metric_queue_read_failed",
                        500,
                    );
                    retry_pending = true;
                    break;
                }
            };
            let ids: Vec<_> = effects.iter().map(|effect| effect.id).collect();
            let durable = store.persistence().is_some();
            let observations: Vec<MetricObservation> = effects
                .into_iter()
                .map(|effect| {
                    let mut observation = effect.observation;
                    if durable {
                        observation.correlation_id = format!("logs-effect:{}", effect.id);
                    }
                    observation
                })
                .collect();
            let sink = registry
                .upgrade()
                .and_then(|registry| registry.metric_sink(&ServiceName::new("monitoring")));
            let Some(sink) = sink else {
                if !finish(&store, ids, false).await {
                    locallycloud_core::observability::log_service_error(
                        "logs",
                        Some("MetricDelivery"),
                        "background",
                        "metric_checkpoint_failed",
                        500,
                    );
                } else {
                    locallycloud_core::observability::log_service_error(
                        "logs",
                        Some("MetricDelivery"),
                        "background",
                        "metric_sink_unavailable",
                        503,
                    );
                }
                retry_pending = true;
                break;
            };
            let outcome = emit(sink.as_ref(), observations.clone(), durable).await;
            let (settled, retry) = match outcome {
                EmitOutcome::Accepted => (ids, Vec::new()),
                // A permanently refused batch must not wedge the queue: deliver its effects
                // one by one and discard only those Monitoring can never accept.
                EmitOutcome::Dropped => {
                    let mut settled = Vec::new();
                    let mut retry = Vec::new();
                    for (id, observation) in ids.into_iter().zip(observations) {
                        match emit(sink.as_ref(), vec![observation], durable).await {
                            EmitOutcome::Accepted | EmitOutcome::Dropped => settled.push(id),
                            _ => retry.push(id),
                        }
                    }
                    (settled, retry)
                }
                _ => (Vec::new(), ids),
            };
            let settled_ok = finish(&store, settled, true).await;
            let retry_empty = retry.is_empty();
            let retry_ok = finish(&store, retry, false).await;
            if !settled_ok || !retry_ok || !retry_empty {
                let (cause, status) = if !settled_ok || !retry_ok {
                    ("metric_checkpoint_failed", 500)
                } else {
                    ("metric_delivery_pending", 503)
                };
                locallycloud_core::observability::log_service_error(
                    "logs",
                    Some("MetricDelivery"),
                    "background",
                    cause,
                    status,
                );
                retry_pending = true;
                break;
            }
        }
    }
}
