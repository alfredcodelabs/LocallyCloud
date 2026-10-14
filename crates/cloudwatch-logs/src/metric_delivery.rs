use std::sync::{Arc, Mutex, Weak};

use locallycloud_core::integration::metrics::{EmitOutcome, MetricObservation, MetricSink};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::store::LogsStore;

const DELIVERY_BATCH_SIZE: usize = 500;

pub struct MetricDeliveryWorker {
    store: Arc<LogsStore>,
    registry: Weak<ServiceRegistry>,
    notify: Arc<Notify>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl MetricDeliveryWorker {
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

async fn run(store: Arc<LogsStore>, registry: Weak<ServiceRegistry>, notify: Arc<Notify>) {
    loop {
        tokio::select! { _=notify.notified()=>{}, _=tokio::time::sleep(std::time::Duration::from_secs(5))=>{} }
        loop {
            let effects = match store.pending_metric_effects(DELIVERY_BATCH_SIZE) {
                Ok(effects) if !effects.is_empty() => effects,
                _ => break,
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
                let _ = finish(&store, ids, false).await;
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
                break;
            }
        }
    }
}
