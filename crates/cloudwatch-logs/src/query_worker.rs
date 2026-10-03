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
            let query = match store.claim_scheduled_query() {
                Ok(Some(query)) => query,
                Ok(None) => break,
                Err(_) => return,
            };
            match execute_query(&store, &query).await {
                Some((rows, statistics)) => {
                    if store
                        .complete_query(&query.scope, &query.id, rows, statistics, clock.now_ms())
                        .is_err()
                    {
                        return;
                    }
                }
                None => {
                    if store
                        .query_is_running(&query.scope, &query.id)
                        .unwrap_or(false)
                        && store
                            .fail_query(&query.scope, &query.id, clock.now_ms())
                            .is_err()
                    {
                        return;
                    }
                }
            }
        }
    }
}
