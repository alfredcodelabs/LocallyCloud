//! SNS topic metadata and accepted publication outbox in the shared SQLite state file.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use locallycloud_state::StateDb;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::error::SnsError;
use crate::fanout::FanoutJob;
use crate::model::{Subscription, TopicArn};
use crate::store::{DedupRecord, SnsStore, TopicState, DEDUP_WINDOW_SECS};

pub type PersistError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Serialize, Deserialize)]
struct SavedDedup {
    message_id: String,
    sequence_number: String,
    accepted_unix: i64,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SavedTopic {
    arn: TopicArn,
    identity: String,
    fifo: bool,
    attributes: BTreeMap<String, String>,
    tags: BTreeMap<String, String>,
    subscriptions: Vec<Subscription>,
    dedup: BTreeMap<String, SavedDedup>,
    sequence: u128,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

impl SavedTopic {
    pub(crate) fn from_state(topic: &TopicState) -> Self {
        let now = now_unix();
        Self {
            arn: topic.arn.clone(),
            identity: topic.identity.clone(),
            fifo: topic.fifo,
            attributes: topic.attributes.clone(),
            tags: topic.tags.clone(),
            subscriptions: topic.subscriptions.clone(),
            sequence: topic.sequence,
            dedup: topic
                .dedup
                .iter()
                .map(|(key, record)| {
                    (
                        key.clone(),
                        SavedDedup {
                            message_id: record.message_id.clone(),
                            sequence_number: record.sequence_number.clone(),
                            accepted_unix: now - record.inserted_at.elapsed().as_secs() as i64,
                        },
                    )
                })
                .collect(),
        }
    }

    fn into_state(self) -> TopicState {
        let now = now_unix();
        TopicState {
            arn: self.arn,
            identity: self.identity,
            fifo: self.fifo,
            attributes: self.attributes,
            tags: self.tags,
            subscriptions: self.subscriptions,
            dedup: self
                .dedup
                .into_iter()
                .filter_map(|(key, record)| {
                    let age = (now - record.accepted_unix).max(0) as u64;
                    (age < DEDUP_WINDOW_SECS).then(|| {
                        (
                            key,
                            DedupRecord {
                                inserted_at: Instant::now() - Duration::from_secs(age),
                                message_id: record.message_id,
                                sequence_number: record.sequence_number,
                            },
                        )
                    })
                })
                .collect(),
            sequence: self.sequence,
            fifo_delivery: None,
        }
    }
}

fn schema(connection: &rusqlite::Connection) -> Result<(), PersistError> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS sns_topics (
        account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL, metadata TEXT NOT NULL,
        PRIMARY KEY(account,region,name)
    );
    CREATE TABLE IF NOT EXISTS sns_outbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL, job TEXT NOT NULL,
        FOREIGN KEY(account,region,name) REFERENCES sns_topics(account,region,name) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS sns_outbox_topic_idx ON sns_outbox(account,region,name,id);")?;
    Ok(())
}

fn save_topic(connection: &rusqlite::Connection, topic: &SavedTopic) -> Result<(), PersistError> {
    let arn = &topic.arn;
    let previous: Option<String> = connection
        .query_row(
            "SELECT metadata FROM sns_topics WHERE account=?1 AND region=?2 AND name=?3",
            params![arn.account, arn.region, arn.name],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(previous) = previous {
        let previous: SavedTopic = serde_json::from_str(&previous)?;
        if previous.identity != topic.identity {
            connection.execute(
                "DELETE FROM sns_topics WHERE account=?1 AND region=?2 AND name=?3",
                params![arn.account, arn.region, arn.name],
            )?;
        }
    }
    let metadata = serde_json::to_string(topic)?;
    connection.execute(
        "INSERT INTO sns_topics(account,region,name,metadata) VALUES(?1,?2,?3,?4)
        ON CONFLICT(account,region,name) DO UPDATE SET metadata=excluded.metadata",
        params![arn.account, arn.region, arn.name, metadata],
    )?;
    Ok(())
}

impl SnsStore {
    pub fn with_state(state: Arc<StateDb>) -> Result<Self, PersistError> {
        let connection = state.connection()?;
        schema(&connection)?;
        let store = Self::new_persistent(state);
        let mut query = connection.prepare("SELECT metadata FROM sns_topics")?;
        let rows = query.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            let saved: SavedTopic = serde_json::from_str(&row?)?;
            let topic = saved.into_state();
            store.insert_loaded(topic);
        }
        Ok(store)
    }

    pub async fn persist_metadata(self: &Arc<Self>) -> Result<(), SnsError> {
        let Some(state) = self.state() else {
            return Ok(());
        };
        let state = state.clone();
        let serial = self.metadata_gate.clone().lock_owned().await;
        let store = self.clone();
        let mut changes = Vec::new();
        for arn in self.pending_metadata() {
            let saved = match self.get(&arn) {
                Some(topic) => Some(SavedTopic::from_state(&*topic.read().await)),
                None => None,
            };
            changes.push((arn, saved));
        }
        tokio::task::spawn_blocking(move || -> Result<(), SnsError> {
            let _serial = serial;
            let mut connection = state.connection().map_err(|_| SnsError::InternalError)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| SnsError::InternalError)?;
            for (arn, saved) in changes {
                match saved {
                    Some(topic) => {
                        save_topic(&transaction, &topic).map_err(|_| SnsError::InternalError)?
                    }
                    None => {
                        transaction
                            .execute(
                                "DELETE FROM sns_topics WHERE account=?1 AND region=?2 AND name=?3",
                                params![arn.account, arn.region, arn.name],
                            )
                            .map_err(|_| SnsError::InternalError)?;
                    }
                }
            }
            transaction.commit().map_err(|_| SnsError::InternalError)?;
            store.clear_uncommitted();
            Ok(())
        })
        .await
        .map_err(|_| SnsError::InternalError)??;
        Ok(())
    }

    /// Commit FIFO sequence/dedup and one publication before Publish returns an ACK.
    pub(crate) async fn accept_job(
        self: &Arc<Self>,
        topic: SavedTopic,
        job: FanoutJob,
    ) -> Result<Option<i64>, SnsError> {
        let Some(state) = self.state() else {
            return Ok(None);
        };
        let state = state.clone();
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = state.connection().map_err(|_| SnsError::InternalError)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| SnsError::InternalError)?;
            save_topic(&transaction, &topic).map_err(|_| SnsError::InternalError)?;
            let encoded = serde_json::to_string(&job).map_err(|_| SnsError::InternalError)?;
            transaction
                .execute(
                    "INSERT INTO sns_outbox(account,region,name,job) VALUES(?1,?2,?3,?4)",
                    params![topic.arn.account, topic.arn.region, topic.arn.name, encoded],
                )
                .map_err(|_| SnsError::InternalError)?;
            let id = transaction.last_insert_rowid();
            transaction.commit().map_err(|_| SnsError::InternalError)?;
            store.clear_topic_uncommitted(&topic.arn);
            Ok(Some(id))
        })
        .await
        .map_err(|_| SnsError::InternalError)?
    }

    pub fn pending_jobs(&self) -> Result<Vec<FanoutJob>, PersistError> {
        let Some(state) = self.state() else {
            return Ok(Vec::new());
        };
        let connection = state.connection()?;
        let mut query = connection.prepare("SELECT id,job FROM sns_outbox ORDER BY id")?;
        let rows = query.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (id, encoded) = row?;
            let mut job: FanoutJob = serde_json::from_str(&encoded)?;
            job.outbox_id = Some(id);
            Ok(job)
        })
        .collect()
    }

    pub fn job_exists(&self, id: Option<i64>) -> Result<bool, SnsError> {
        let (Some(state), Some(id)) = (self.state(), id) else {
            return Ok(false);
        };
        let connection = state.connection().map_err(|_| SnsError::InternalError)?;
        connection
            .query_row("SELECT 1 FROM sns_outbox WHERE id=?1", params![id], |_| {
                Ok(())
            })
            .optional()
            .map(|value| value.is_some())
            .map_err(|_| SnsError::InternalError)
    }

    pub fn complete_job(&self, id: Option<i64>) -> Result<(), SnsError> {
        let (Some(state), Some(id)) = (self.state(), id) else {
            return Ok(());
        };
        state
            .connection()
            .map_err(|_| SnsError::InternalError)?
            .execute("DELETE FROM sns_outbox WHERE id=?1", params![id])
            .map_err(|_| SnsError::InternalError)?;
        Ok(())
    }
}

#[cfg(test)]
mod delta_tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_request_keeps_commit_serialized_until_sqlite_finishes() {
        let path = std::env::temp_dir()
            .join(format!("sns-cancel-{}", uuid::Uuid::new_v4()))
            .join("state.sqlite3");
        let state = Arc::new(StateDb::open(path).unwrap());
        let store = Arc::new(SnsStore::with_state(state.clone()).unwrap());
        let arn = TopicArn::new("us-east-1", "000000000000", "edited");
        store.insert(arn.clone(), false, BTreeMap::new(), BTreeMap::new());
        let blocker = state.connection().unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let saving = store.clone();
        let request = tokio::spawn(async move { saving.persist_metadata().await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.metadata_gate.try_lock().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert!(
            store.metadata_gate.try_lock().is_err(),
            "cancelled request must leave ownership with its SQLite worker"
        );
        blocker.execute_batch("ROLLBACK").unwrap();
        let serial = tokio::time::timeout(Duration::from_secs(2), store.metadata_gate.lock())
            .await
            .unwrap();
        assert!(!store.has_uncommitted());
        drop(serial);
        store
            .get(&arn)
            .unwrap()
            .write()
            .await
            .tags
            .insert("revision".into(), "newest".into());
        store.mark_uncommitted(&arn);
        store.persist_metadata().await.unwrap();
        let restored = SnsStore::with_state(state).unwrap();
        assert_eq!(
            restored.get(&arn).unwrap().read().await.tags["revision"],
            "newest"
        );
    }

    #[tokio::test]
    async fn metadata_writes_only_dirty_topics_and_retries_failed_commits() {
        let path = std::env::temp_dir()
            .join(format!("sns-delta-{}", uuid::Uuid::new_v4()))
            .join("state.sqlite3");
        let state = Arc::new(StateDb::open(path).unwrap());
        let store = Arc::new(SnsStore::with_state(state.clone()).unwrap());
        let edited = TopicArn::new("us-east-1", "000000000000", "edited");
        let unrelated = TopicArn::new("us-east-1", "000000000000", "unrelated");
        for arn in [&edited, &unrelated] {
            store.insert(arn.clone(), false, BTreeMap::new(), BTreeMap::new());
        }
        store.persist_metadata().await.unwrap();
        state.connection().unwrap().execute_batch("CREATE TRIGGER protect_topic_update BEFORE UPDATE ON sns_topics WHEN OLD.name='unrelated' BEGIN SELECT RAISE(ABORT,'unrelated update'); END;
            CREATE TRIGGER protect_topic_delete BEFORE DELETE ON sns_topics WHEN OLD.name='unrelated' BEGIN SELECT RAISE(ABORT,'unrelated delete'); END;
            CREATE TRIGGER fail_write BEFORE UPDATE ON sns_topics WHEN OLD.name='edited' BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
        store
            .get(&edited)
            .unwrap()
            .write()
            .await
            .tags
            .insert("team".into(), "data".into());
        store.mark_uncommitted(&edited);
        assert!(store.persist_metadata().await.is_err());
        assert!(store.has_uncommitted());
        state
            .connection()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_write;")
            .unwrap();
        store.persist_metadata().await.unwrap();
        assert!(!store.has_uncommitted());
        let restored = SnsStore::with_state(state.clone()).unwrap();
        assert_eq!(
            restored.get(&edited).unwrap().read().await.tags["team"],
            "data"
        );
        store.remove(&edited);
        store.persist_metadata().await.unwrap();
        let restored = SnsStore::with_state(state).unwrap();
        assert!(restored.get(&edited).is_none());
        assert!(restored.get(&unrelated).is_some());
    }
}
