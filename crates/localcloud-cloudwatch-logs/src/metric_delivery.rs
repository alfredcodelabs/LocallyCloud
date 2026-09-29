use std::sync::{Arc, Mutex, Weak};

use localcloud_core::integration::metrics::EmitOutcome;
use localcloud_core::registry::{ServiceName, ServiceRegistry};
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
        notify.notified().await;
        loop {
            let effects = match store.pending_metric_effects(DELIVERY_BATCH_SIZE) {
                Ok(effects) if !effects.is_empty() => effects,
                _ => break,
            };
            let ids: Vec<_> = effects.iter().map(|effect| effect.id).collect();
            let observations = effects
                .into_iter()
                .map(|effect| effect.observation)
                .collect();
            let outcome = registry
                .upgrade()
                .and_then(|registry| registry.metric_sink(&ServiceName::new("monitoring")))
                .map_or(EmitOutcome::Unavailable, |sink| sink.try_emit(observations));
            let delivered = outcome == EmitOutcome::Accepted;
            if store.finish_metric_effects(&ids, delivered).is_err() || !delivered {
                break;
            }
        }
    }
}
