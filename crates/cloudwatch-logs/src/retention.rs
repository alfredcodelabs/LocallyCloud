use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::clock::Clock;
use crate::store::LogsStore;

pub struct RetentionWorker {
    store: Arc<LogsStore>,
    delay: Duration,
    clock: Arc<dyn Clock>,
    notify: Arc<Notify>,
    shutdown: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl RetentionWorker {
    pub fn with_delay(store: Arc<LogsStore>, clock: Arc<dyn Clock>, delay: Duration) -> Self {
        Self {
            delay,
            store,
            clock,
            notify: Arc::new(Notify::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
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
            let clock = self.clock.clone();
            let notify = self.notify.clone();
            let shutdown = self.shutdown.clone();
            let delay = self.delay;
            *handle = Some(tokio::spawn(async move {
                run(store, clock, notify, shutdown, delay).await;
            }));
        }
        self.notify.notify_one();
    }
}

impl Drop for RetentionWorker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.notify.notify_waiters();
        if let Ok(handle) = self.handle.get_mut() {
            if let Some(handle) = handle.take() {
                handle.abort();
            }
        }
    }
}

async fn run(
    store: Arc<LogsStore>,
    clock: Arc<dyn Clock>,
    notify: Arc<Notify>,
    shutdown: Arc<AtomicBool>,
    delay: Duration,
) {
    loop {
        notify.notified().await;
        if shutdown.load(Ordering::Acquire) {
            return;
        }
        tokio::time::sleep(delay).await;

        loop {
            if shutdown.load(Ordering::Acquire) {
                return;
            }
            let now_ms = clock.now_ms();
            let owned = store.clone();
            let next_expiration_ms =
                match tokio::task::spawn_blocking(move || owned.purge_expired(now_ms)).await {
                    Ok(Ok(next)) => next,
                    _ => {
                        locallycloud_core::observability::log_service_error(
                            "logs",
                            Some("Retention"),
                            "background",
                            "retention_persistence_failed",
                            500,
                        );
                        break;
                    }
                };
            let Some(deadline_ms) = next_expiration_ms else {
                break;
            };
            let wait_ms = deadline_ms.saturating_sub(now_ms).max(1) as u64;
            tokio::select! {
                _ = notify.notified() => {
                    tokio::time::sleep(delay).await;
                }
                _ = tokio::time::sleep(Duration::from_millis(wait_ms)) => {}
            }
        }
    }
}
