use std::sync::{Arc, Mutex, Weak};

use locallycloud_core::integration::metrics::EmitOutcome;
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
            let observations = effects
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
            let outcome = match sink {
                Some(sink) if durable => sink.emit_durable(observations).await,
                Some(sink) => sink.try_emit(observations),
                None => EmitOutcome::Unavailable,
            };
            let delivered = outcome == EmitOutcome::Accepted;
            let owned = store.clone();
            let finished =
                tokio::task::spawn_blocking(move || owned.finish_metric_effects(&ids, delivered))
                    .await;
            if !matches!(finished, Ok(Ok(()))) || !delivered {
                break;
            }
        }
    }
}
