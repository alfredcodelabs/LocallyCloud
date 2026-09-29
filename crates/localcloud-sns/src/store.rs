//! Region/account-scoped SNS store. Subscriptions live within their topic.

use localcloud_state::StateDb;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use tokio::sync::{Mutex, RwLock};

use crate::fanout::FanoutJob;
use crate::model::{Subscription, TopicArn};

/// FIFO deduplication window.
pub const DEDUP_WINDOW_SECS: u64 = 300;

/// A replayable FIFO publish accepted within the deduplication window.
#[derive(Clone)]
pub struct DedupRecord {
    pub inserted_at: Instant,
    pub message_id: String,
    pub sequence_number: String,
}

/// Result of atomically inserting a topic.
pub enum InsertResult {
    Inserted(Arc<RwLock<TopicState>>),
    Existing(Arc<RwLock<TopicState>>),
}

/// Live topic state behind a per-topic lock.
pub struct TopicState {
    pub arn: TopicArn,
    pub identity: String,
    pub fifo: bool,
    pub attributes: BTreeMap<String, String>,
    pub tags: BTreeMap<String, String>,
    pub subscriptions: Vec<Subscription>,
    /// FIFO dedup window: effective dedup id → original accepted result.
    pub dedup: BTreeMap<String, DedupRecord>,
    pub sequence: u128,
    /// Serial FIFO delivery worker. Channel send order matches acceptance under this topic lock.
    pub fifo_delivery: Option<tokio::sync::mpsc::UnboundedSender<FanoutJob>>,
}

impl TopicState {
    pub fn content_based_dedup(&self) -> bool {
        self.attributes
            .get("ContentBasedDeduplication")
            .map(|v| v == "true")
            .unwrap_or(false)
    }
}

type Key = (String, String, String);

#[derive(Default)]
pub struct SnsStore {
    topics: DashMap<Key, Arc<RwLock<TopicState>>>,
    state: Option<Arc<StateDb>>,
    pub operation_gate: Mutex<()>,
    uncommitted: AtomicBool,
}

fn key(arn: &TopicArn) -> Key {
    (arn.account.clone(), arn.region.clone(), arn.name.clone())
}

impl SnsStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn new_persistent(state: Arc<StateDb>) -> Self {
        Self {
            state: Some(state),
            ..Self::default()
        }
    }

    pub(crate) fn state(&self) -> Option<&StateDb> {
        self.state.as_deref()
    }

    pub(crate) fn insert_loaded(&self, topic: TopicState) {
        self.topics
            .insert(key(&topic.arn), Arc::new(RwLock::new(topic)));
    }

    pub(crate) fn all_topics(&self) -> Vec<Arc<RwLock<TopicState>>> {
        self.topics
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn mark_uncommitted(&self) {
        if self.state.is_some() {
            self.uncommitted.store(true, Ordering::Release);
        }
    }

    pub fn has_uncommitted(&self) -> bool {
        self.uncommitted.load(Ordering::Acquire)
    }
    pub fn clear_uncommitted(&self) {
        self.uncommitted.store(false, Ordering::Release);
    }

    /// Atomically insert a topic without replacing an existing topic or its state.
    pub fn insert(
        &self,
        arn: TopicArn,
        fifo: bool,
        attributes: BTreeMap<String, String>,
        tags: BTreeMap<String, String>,
    ) -> InsertResult {
        let state = Arc::new(RwLock::new(TopicState {
            arn: arn.clone(),
            identity: uuid::Uuid::new_v4().to_string(),
            fifo,
            attributes,
            tags,
            subscriptions: Vec::new(),
            dedup: BTreeMap::new(),
            sequence: 0,
            fifo_delivery: None,
        }));
        match self.topics.entry(key(&arn)) {
            Entry::Occupied(entry) => InsertResult::Existing(entry.get().clone()),
            Entry::Vacant(entry) => {
                entry.insert(state.clone());
                InsertResult::Inserted(state)
            }
        }
    }

    pub fn get(&self, arn: &TopicArn) -> Option<Arc<RwLock<TopicState>>> {
        self.topics.get(&key(arn)).map(|e| e.clone())
    }

    pub fn exists(&self, arn: &TopicArn) -> bool {
        self.topics.contains_key(&key(arn))
    }

    pub fn remove(&self, arn: &TopicArn) -> Option<Arc<RwLock<TopicState>>> {
        self.topics.remove(&key(arn)).map(|(_, v)| v)
    }

    /// Topic handles in a scope, sorted by name.
    pub fn list(&self, account: &str, region: &str) -> Vec<Arc<RwLock<TopicState>>> {
        let mut out: Vec<Arc<RwLock<TopicState>>> = self
            .topics
            .iter()
            .filter(|e| e.key().0 == account && e.key().1 == region)
            .map(|e| e.value().clone())
            .collect();
        out.sort_by(|a, b| {
            let an = a.try_read().map(|s| s.arn.name.clone()).unwrap_or_default();
            let bn = b.try_read().map(|s| s.arn.name.clone()).unwrap_or_default();
            an.cmp(&bn)
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_remove() {
        let store = SnsStore::new();
        let arn = TopicArn::new("us-east-1", "0", "t");
        store.insert(arn.clone(), false, BTreeMap::new(), BTreeMap::new());
        assert!(store.exists(&arn));
        assert!(store.remove(&arn).is_some());
        assert!(!store.exists(&arn));
    }

    #[tokio::test]
    async fn scoped_by_account() {
        let store = SnsStore::new();
        store.insert(
            TopicArn::new("us-east-1", "a", "t"),
            false,
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert!(store.get(&TopicArn::new("us-east-1", "a", "t")).is_some());
        assert!(store.get(&TopicArn::new("us-east-1", "b", "t")).is_none());
    }
}
