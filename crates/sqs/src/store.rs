//! Region/account-scoped SQS store with per-queue guarded state and long-poll wakeups.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::AtomicI64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use time::OffsetDateTime;
use tokio::sync::{Mutex, Notify, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

use crate::error::SqsError;
use crate::model::{Message, QueueArn};
use crate::persistence::SqsPersistence;
use locallycloud_state::StateDb;

/// Default queue attribute values (seconds / bytes).
pub const DEFAULT_VISIBILITY_TIMEOUT: i64 = 30;
pub const DEFAULT_DELAY_SECONDS: i64 = 0;
pub const DEFAULT_MAX_MESSAGE_SIZE: i64 = 1_048_576;
pub const DEFAULT_RETENTION_PERIOD: i64 = 345_600;
pub const DEFAULT_WAIT_TIME_SECONDS: i64 = 0;
pub const MAX_RECEIVE_WAIT_SECONDS: i64 = 20;
/// Window after deletion during which re-create with the same name is rejected.
pub const DELETED_RECENTLY_SECS: u64 = 60;
/// FIFO deduplication window.
pub const DEDUP_WINDOW: Duration = Duration::from_secs(300);

pub struct DedupEntry {
    pub at: Instant,
    pub message_id: String,
    pub sequence: u128,
}

/// FIFO deduplication keys still inside [`DEDUP_WINDOW`]. `order` keeps keys sorted by
/// insertion instant, so expiry pops from the front instead of scanning every key.
#[derive(Default)]
pub struct DedupWindow {
    entries: BTreeMap<String, DedupEntry>,
    order: VecDeque<(Instant, String)>,
}

impl DedupWindow {
    pub fn prune(&mut self, now: Instant) {
        while self
            .order
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) >= DEDUP_WINDOW)
        {
            let Some((at, key)) = self.order.pop_front() else {
                break;
            };
            if self.entries.get(&key).is_some_and(|entry| entry.at == at) {
                self.entries.remove(&key);
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<&DedupEntry> {
        self.entries.get(key)
    }

    /// Restored keys may arrive in any order; sends always append at the back.
    pub fn insert(&mut self, key: String, entry: DedupEntry) {
        let position = self.order.partition_point(|(at, _)| *at <= entry.at);
        self.order.insert(position, (entry.at, key.clone()));
        self.entries.insert(key, entry);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

pub struct ReceiveAttempt {
    pub expires_at: Instant,
    pub messages: Vec<Message>,
}

/// Mutable queue state behind the per-queue lock.
pub struct QueueState {
    pub attributes: BTreeMap<String, String>,
    pub tags: BTreeMap<String, String>,
    pub messages: VecDeque<Message>,
    /// Lower bound used to avoid repeated full retention scans on fresh backlog.
    pub oldest_sent_timestamp_ms: Option<i64>,
    pub dedup: DedupWindow,
    pub receive_attempts: BTreeMap<String, ReceiveAttempt>,
    pub sequence: u128,
    pub last_purge: Option<Instant>,
    pub created: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}

impl QueueState {
    fn new(attributes: BTreeMap<String, String>, tags: BTreeMap<String, String>) -> Self {
        let now = OffsetDateTime::now_utc();
        QueueState {
            attributes,
            tags,
            messages: VecDeque::new(),
            oldest_sent_timestamp_ms: None,
            dedup: DedupWindow::default(),
            receive_attempts: BTreeMap::new(),
            sequence: 0,
            last_purge: None,
            created: now,
            last_modified: now,
        }
    }

    pub fn push_message(&mut self, message: Message) {
        self.oldest_sent_timestamp_ms = Some(
            self.oldest_sent_timestamp_ms
                .map_or(message.sent_timestamp_ms, |oldest| {
                    oldest.min(message.sent_timestamp_ms)
                }),
        );
        self.messages.push_back(message);
    }

    /// Integer attribute with a default.
    pub fn int_attr(&self, name: &str, default: i64) -> i64 {
        self.attributes
            .get(name)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    pub fn visibility_timeout(&self) -> i64 {
        self.int_attr("VisibilityTimeout", DEFAULT_VISIBILITY_TIMEOUT)
    }
    pub fn delay_seconds(&self) -> i64 {
        self.int_attr("DelaySeconds", DEFAULT_DELAY_SECONDS)
    }
    pub fn max_message_size(&self) -> i64 {
        self.int_attr("MaximumMessageSize", DEFAULT_MAX_MESSAGE_SIZE)
    }
    pub fn retention_period(&self) -> i64 {
        self.int_attr("MessageRetentionPeriod", DEFAULT_RETENTION_PERIOD)
    }
    pub fn wait_time_seconds(&self) -> i64 {
        self.int_attr("ReceiveMessageWaitTimeSeconds", DEFAULT_WAIT_TIME_SECONDS)
    }
    pub fn content_based_dedup(&self) -> bool {
        self.attributes
            .get("ContentBasedDeduplication")
            .map(|v| v == "true")
            .unwrap_or(false)
    }
    pub fn touch(&mut self) {
        self.last_modified = OffsetDateTime::now_utc();
    }
}

/// A queue with its guarded state and a long-poll wakeup notifier.
pub struct GuardedQueue {
    pub arn: QueueArn,
    pub fifo: bool,
    pub state: Mutex<QueueState>,
    pub notify: Notify,
    /// Wall-clock ms of the last API access or observed message presence; drives the
    /// CloudWatch inactivity cutoff for vended gauges.
    pub last_activity_ms: AtomicI64,
}

type Key = (String, String, String);

fn key(arn: &QueueArn) -> Key {
    (arn.account.clone(), arn.region.clone(), arn.name.clone())
}

/// A dead-letter message-move task.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MoveTask {
    pub handle: String,
    pub source_arn: String,
    pub destination_arn: Option<String>,
    pub status: String,
    pub messages_moved: u64,
    pub messages_to_move: u64,
    pub max_messages_per_second: u64,
    pub started_ms: i64,
}

/// Result of an atomic create attempt.
pub enum InsertResult {
    Inserted(Arc<GuardedQueue>),
    Existing(Arc<GuardedQueue>),
}

enum MoveTaskUpdate {
    Moved,
    Finish(String),
    Cancel,
}

/// Region/account-scoped queue store.
#[derive(Default)]
pub struct SqsStore {
    queues: DashMap<Key, Arc<GuardedQueue>>,
    recently_deleted: DashMap<Key, Instant>,
    move_tasks: DashMap<String, MoveTask>,
    lifecycle: Arc<RwLock<()>>,
    move_task_gate: Arc<Mutex<()>>,
    persistence: Option<SqsPersistence>,
}

impl SqsStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_state(db: Arc<StateDb>) -> Result<Self, SqsError> {
        let persistence = SqsPersistence::open(db)?;
        let mut store = Self::default();
        persistence.load(&store)?;
        for task in persistence.load_tasks()? {
            store.move_tasks.insert(task.handle.clone(), task);
        }
        store.persistence = Some(persistence);
        Ok(store)
    }

    pub fn persistence(&self) -> Option<&SqsPersistence> {
        self.persistence.as_ref()
    }

    pub async fn lifecycle_read(&self) -> OwnedRwLockReadGuard<()> {
        self.lifecycle.clone().read_owned().await
    }

    pub async fn lifecycle_write(&self) -> OwnedRwLockWriteGuard<()> {
        self.lifecycle.clone().write_owned().await
    }

    /// Atomically create a queue without ever replacing an existing queue or its state.
    pub fn insert_if_absent(
        &self,
        arn: QueueArn,
        fifo: bool,
        attributes: BTreeMap<String, String>,
        tags: BTreeMap<String, String>,
    ) -> InsertResult {
        self.insert_state_if_absent(arn, fifo, QueueState::new(attributes, tags))
    }

    /// The caller owns lifecycle-write admission. Persist the detached queue before
    /// making it visible to readers that do not take that admission lock.
    pub(crate) fn create_if_absent(
        &self,
        arn: QueueArn,
        fifo: bool,
        attributes: BTreeMap<String, String>,
        tags: BTreeMap<String, String>,
    ) -> Result<InsertResult, SqsError> {
        if let Some(existing) = self.get(&arn) {
            return Ok(InsertResult::Existing(existing));
        }
        let state = QueueState::new(attributes, tags);
        if let Some(db) = self.persistence() {
            db.create_queue(&arn, &state)?;
        }
        Ok(self.insert_state_if_absent(arn, fifo, state))
    }

    fn insert_state_if_absent(&self, arn: QueueArn, fifo: bool, state: QueueState) -> InsertResult {
        let q = Arc::new(GuardedQueue {
            arn: arn.clone(),
            fifo,
            state: Mutex::new(state),
            notify: Notify::new(),
            last_activity_ms: AtomicI64::new(crate::metrics::now_ms()),
        });
        match self.queues.entry(key(&arn)) {
            Entry::Vacant(entry) => {
                entry.insert(q.clone());
                InsertResult::Inserted(q)
            }
            Entry::Occupied(entry) => InsertResult::Existing(entry.get().clone()),
        }
    }

    pub fn get(&self, arn: &QueueArn) -> Option<Arc<GuardedQueue>> {
        self.queues.get(&key(arn)).map(|e| e.clone())
    }

    pub fn exists(&self, arn: &QueueArn) -> bool {
        self.queues.contains_key(&key(arn))
    }

    pub fn restore_deleted(&self, arn: QueueArn, deleted_at: Instant) {
        self.recently_deleted.insert(key(&arn), deleted_at);
    }

    pub fn remove(&self, arn: &QueueArn) -> Option<Arc<GuardedQueue>> {
        let removed = self.queues.remove(&key(arn)).map(|(_, v)| v);
        if removed.is_some() {
            self.recently_deleted.insert(key(arn), Instant::now());
        }
        removed
    }

    /// Whether the name was deleted within the `QueueDeletedRecently` window.
    pub fn deleted_recently(&self, arn: &QueueArn) -> bool {
        if let Some(at) = self.recently_deleted.get(&key(arn)) {
            at.elapsed().as_secs() < DELETED_RECENTLY_SECS
        } else {
            false
        }
    }

    /// Queue names (URLs built by the caller) in a scope, optionally prefix-filtered.
    pub fn list(
        &self,
        account: &str,
        region: &str,
        prefix: Option<&str>,
    ) -> Vec<Arc<GuardedQueue>> {
        let mut out: Vec<Arc<GuardedQueue>> = self
            .queues
            .iter()
            .filter(|e| e.key().0 == account && e.key().1 == region)
            .filter(|e| prefix.map(|p| e.key().2.starts_with(p)).unwrap_or(true))
            .map(|e| e.value().clone())
            .collect();
        out.sort_by(|a, b| a.arn.name.cmp(&b.arn.name));
        out
    }

    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    /// Every queue across accounts and regions.
    pub fn all(&self) -> Vec<Arc<GuardedQueue>> {
        self.queues.iter().map(|e| e.value().clone()).collect()
    }

    pub(crate) async fn move_task_write(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.move_task_gate.clone().lock_owned().await
    }

    pub fn insert_move_task(&self, task: MoveTask) -> Result<(), SqsError> {
        if let Some(db) = self.persistence() {
            db.save_task(&task)?;
        }
        self.move_tasks.insert(task.handle.clone(), task);
        Ok(())
    }

    pub fn has_running_move_task(&self, source_arn: &str) -> bool {
        self.move_tasks
            .iter()
            .any(|entry| entry.source_arn == source_arn && entry.status == "RUNNING")
    }

    pub fn move_task_source_arn(&self, handle: &str) -> Option<String> {
        self.move_tasks
            .get(handle)
            .map(|task| task.source_arn.clone())
    }

    pub fn move_task_status(&self, handle: &str) -> Option<String> {
        self.move_tasks.get(handle).map(|task| task.status.clone())
    }

    pub async fn record_message_moved(self: &Arc<Self>, handle: &str) -> Result<bool, SqsError> {
        Ok(self
            .update_move_task(handle, MoveTaskUpdate::Moved)
            .await?
            .is_some_and(|task| task.status == "RUNNING"))
    }

    pub async fn finish_move_task(
        self: &Arc<Self>,
        handle: &str,
        status: &str,
    ) -> Result<(), SqsError> {
        self.update_move_task(handle, MoveTaskUpdate::Finish(status.into()))
            .await
            .map(drop)
    }

    async fn update_move_task(
        self: &Arc<Self>,
        handle: &str,
        update: MoveTaskUpdate,
    ) -> Result<Option<MoveTask>, SqsError> {
        let gate = self.move_task_write().await;
        let store = self.clone();
        let handle = handle.to_owned();
        tokio::task::spawn_blocking(move || {
            let _gate = gate;
            let Some(mut task) = store
                .move_tasks
                .get(&handle)
                .map(|entry| entry.value().clone())
            else {
                return Ok(None);
            };
            match (update, task.status.as_str()) {
                (MoveTaskUpdate::Moved, _) => task.messages_moved += 1,
                (MoveTaskUpdate::Finish(status), "RUNNING") => task.status = status,
                (MoveTaskUpdate::Cancel, "RUNNING") => task.status = "CANCELLED".into(),
                (MoveTaskUpdate::Finish(_) | MoveTaskUpdate::Cancel, _) => return Ok(None),
            }
            if let Some(db) = store.persistence() {
                db.save_task(&task)?;
            }
            store.move_tasks.insert(handle, task.clone());
            Ok(Some(task))
        })
        .await
        .map_err(|_| SqsError::StorageUnavailable)?
    }

    pub fn list_move_tasks(&self, source_arn: &str) -> Vec<MoveTask> {
        let mut tasks: Vec<MoveTask> = self
            .move_tasks
            .iter()
            .filter(|e| e.value().source_arn == source_arn)
            .map(|e| e.value().clone())
            .collect();
        tasks.sort_by_key(|t| std::cmp::Reverse(t.started_ms));
        tasks
    }

    /// Cancel a running task. Missing or terminal tasks are rejected.
    pub async fn cancel_move_task(self: &Arc<Self>, handle: &str) -> Result<Option<u64>, SqsError> {
        Ok(self
            .update_move_task(handle, MoveTaskUpdate::Cancel)
            .await?
            .map(|task| task.messages_moved))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(at: Instant, id: &str) -> DedupEntry {
        DedupEntry {
            at,
            message_id: id.to_owned(),
            sequence: 1,
        }
    }

    #[test]
    fn dedup_window_expires_oldest_keys_first_and_keeps_reinserted_keys() {
        let now = Instant::now();
        let old = now - DEDUP_WINDOW - Duration::from_secs(1);
        let mut window = DedupWindow::default();
        // Restored keys arrive unordered; the window keeps them by instant.
        window.insert("fresh".into(), entry(now - Duration::from_secs(10), "m2"));
        window.insert("stale".into(), entry(old, "m1"));
        window.insert("again".into(), entry(old, "m0"));
        window.prune(now);
        assert!(window.get("stale").is_none() && window.get("again").is_none());
        assert_eq!(
            window.get("fresh").map(|e| e.message_id.as_str()),
            Some("m2")
        );
        assert_eq!(window.entries.len(), 1);

        // A key sent again after expiry is not dropped by its older queue position.
        let mut window = DedupWindow::default();
        window.insert("k".into(), entry(old, "first"));
        window.insert("k".into(), entry(now, "second"));
        window.prune(now);
        assert_eq!(
            window.get("k").map(|e| e.message_id.as_str()),
            Some("second")
        );
        window.clear();
        assert!(window.entries.is_empty() && window.order.is_empty());
    }

    fn arn(name: &str) -> QueueArn {
        QueueArn::new("us-east-1", "000000000000", name)
    }

    #[test]
    fn insert_get_remove() {
        let store = SqsStore::new();
        assert!(matches!(
            store.insert_if_absent(arn("q"), false, BTreeMap::new(), BTreeMap::new()),
            InsertResult::Inserted(_)
        ));
        assert!(matches!(
            store.insert_if_absent(arn("q"), false, BTreeMap::new(), BTreeMap::new()),
            InsertResult::Existing(_)
        ));
        assert!(store.exists(&arn("q")));
        assert!(store.remove(&arn("q")).is_some());
        assert!(!store.exists(&arn("q")));
        assert!(store.deleted_recently(&arn("q")));
    }

    #[test]
    fn list_prefix_filter() {
        let store = SqsStore::new();
        store.insert_if_absent(arn("orders"), false, BTreeMap::new(), BTreeMap::new());
        store.insert_if_absent(arn("events"), false, BTreeMap::new(), BTreeMap::new());
        assert_eq!(
            store.list("000000000000", "us-east-1", Some("ord")).len(),
            1
        );
        assert_eq!(store.list("000000000000", "us-east-1", None).len(), 2);
    }

    #[test]
    fn concurrent_insert_never_replaces_queue_state() {
        let store = Arc::new(SqsStore::new());
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let store = store.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    match store.insert_if_absent(
                        arn("shared"),
                        false,
                        BTreeMap::new(),
                        BTreeMap::new(),
                    ) {
                        InsertResult::Inserted(queue) | InsertResult::Existing(queue) => queue,
                    }
                })
            })
            .collect();
        let queues: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let stored = store.get(&arn("shared")).unwrap();
        assert!(queues.iter().all(|queue| Arc::ptr_eq(queue, &stored)));
    }
}
