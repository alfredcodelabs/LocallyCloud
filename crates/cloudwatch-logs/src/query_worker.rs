use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::clock::Clock;
use crate::insights::execute_query;
use crate::store::LogsStore;

pub struct QueryWorker {
    store: Arc<LogsStore>,
    clock: Arc<dyn Clock>,
    notify: Arc<Notify>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl QueryWorker {
    pub fn new(store: Arc<LogsStore>, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            clock,
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
            let clock = self.clock.clone();
            let notify = self.notify.clone();
            *handle = Some(tokio::spawn(async move {
                run(store, clock, notify).await;
            }));
        }
        self.notify.notify_one();
    }
}

impl Drop for QueryWorker {
    fn drop(&mut self) {
        self.notify.notify_waiters();
        if let Ok(handle) = self.handle.get_mut() {
            if let Some(handle) = handle.take() {
                handle.abort();
            }
        }
    }
}

async fn run(store: Arc<LogsStore>, clock: Arc<dyn Clock>, notify: Arc<Notify>) {
    loop {
        notify.notified().await;
        // Keep Scheduled observable and give StopQuery a deterministic cancellation window.
        tokio::time::sleep(Duration::from_millis(5)).await;
        loop {
            let owned = store.clone();
            let query =
                match tokio::task::spawn_blocking(move || owned.claim_scheduled_query()).await {
                    Ok(Ok(Some(query))) => query,
                    Ok(Ok(None)) => break,
                    _ => return,
                };
            match execute_query(&store, &query).await {
                Some((rows, statistics)) => {
                    let owned = store.clone();
                    let scope = query.scope.clone();
                    let id = query.id.clone();
                    let now = clock.now_ms();
                    if !matches!(
                        tokio::task::spawn_blocking(
                            move || owned.complete_query(&scope, &id, rows, statistics, now)
                        )
                        .await,
                        Ok(Ok(_))
                    ) {
                        return;
                    }
                }
                None => {
                    let owned = store.clone();
                    let scope = query.scope.clone();
                    let id = query.id.clone();
                    let now = clock.now_ms();
                    if !matches!(
                        tokio::task::spawn_blocking(move || owned.fail_query(&scope, &id, now))
                            .await,
                        Ok(Ok(()))
                    ) {
                        return;
                    }
                }
            }
        }
    }
}
