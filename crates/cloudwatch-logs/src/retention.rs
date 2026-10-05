use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::clock::Clock;
use crate::store::LogsStore;

const RECLAIM_DELAY: Duration = Duration::from_millis(100);

pub struct RetentionWorker {
    store: Arc<LogsStore>,
    clock: Arc<dyn Clock>,
    notify: Arc<Notify>,
    shutdown: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl RetentionWorker {
    pub fn new(store: Arc<LogsStore>, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            clock,
            notify: Arc::new(Notify::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            handle: Mutex::new(None),
        }
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
            *handle = Some(tokio::spawn(async move {
                run(store, clock, notify, shutdown).await;
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
) {
    loop {
        notify.notified().await;
        if shutdown.load(Ordering::Acquire) {
            return;
        }
        tokio::time::sleep(RECLAIM_DELAY).await;

        loop {
            if shutdown.load(Ordering::Acquire) {
                return;
            }
            let now_ms = clock.now_ms();
            let owned = store.clone();
            let next_expiration_ms =
                match tokio::task::spawn_blocking(move || owned.purge_expired(now_ms)).await {
                    Ok(Ok(next)) => next,
                    _ => break,
                };
            let Some(deadline_ms) = next_expiration_ms else {
                break;
            };
            let wait_ms = deadline_ms.saturating_sub(now_ms).max(1) as u64;
            tokio::select! {
                _ = notify.notified() => {
                    tokio::time::sleep(RECLAIM_DELAY).await;
                }
                _ = tokio::time::sleep(Duration::from_millis(wait_ms)) => {}
            }
        }
    }
}
