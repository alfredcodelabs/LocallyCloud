//! Region/account-scoped SQS store with per-queue guarded state and long-poll wakeups.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

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
    /// dedup id → (inserted instant, original message id, original sequence number).
    pub dedup: BTreeMap<String, (Instant, String, u128)>,
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
            dedup: BTreeMap::new(),
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

/// Region/account-scoped queue store.
#[derive(Default)]
pub struct SqsStore {
    queues: DashMap<Key, Arc<GuardedQueue>>,
    recently_deleted: DashMap<Key, Instant>,
    move_tasks: DashMap<String, MoveTask>,
    lifecycle: Arc<RwLock<()>>,
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
        let q = Arc::new(GuardedQueue {
            arn: arn.clone(),
            fifo,
            state: Mutex::new(QueueState::new(attributes, tags)),
            notify: Notify::new(),
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

    pub fn forget_uncommitted(&self, arn: &QueueArn) {
        self.queues.remove(&key(arn));
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

    pub fn record_message_moved(&self, handle: &str) -> Result<bool, SqsError> {
        let Some(mut task) = self.move_tasks.get_mut(handle) else {
            return Ok(false);
        };
        let mut updated = task.clone();
        updated.messages_moved += 1;
        if let Some(db) = self.persistence() {
            db.save_task(&updated)?;
        }
        *task = updated;
        Ok(task.status == "RUNNING")
    }

    pub fn finish_move_task(&self, handle: &str, status: &str) -> Result<(), SqsError> {
        if let Some(mut task) = self.move_tasks.get_mut(handle) {
            if task.status == "RUNNING" {
                let mut updated = task.clone();
                updated.status = status.to_string();
                if let Some(db) = self.persistence() {
                    db.save_task(&updated)?;
                }
                *task = updated;
            }
        }
        Ok(())
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
    pub fn cancel_move_task(&self, handle: &str) -> Result<Option<u64>, SqsError> {
        let Some(mut task) = self.move_tasks.get_mut(handle) else {
            return Ok(None);
        };
        if task.status != "RUNNING" {
            return Ok(None);
        }
        let mut updated = task.clone();
        updated.status = "CANCELLED".to_string();
        if let Some(db) = self.persistence() {
            db.save_task(&updated)?;
        }
        *task = updated;
        Ok(Some(task.messages_moved))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
