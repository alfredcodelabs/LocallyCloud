//! SNS topic metadata and accepted publication outbox in the shared SQLite state file.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use locallycloud_state::StateDb;
use rusqlite::{params, OptionalExtension};
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
struct SavedTopic {
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
    fn from_state(topic: &TopicState) -> Self {
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

    pub async fn persist_metadata(&self) -> Result<(), SnsError> {
        let Some(state) = self.state() else {
            return Ok(());
        };
        let mut topics = Vec::new();
        let mut present = std::collections::BTreeSet::new();
        for topic in self.all_topics() {
            let topic = topic.read().await;
            present.insert((
                topic.arn.account.clone(),
                topic.arn.region.clone(),
                topic.arn.name.clone(),
            ));
            topics.push(SavedTopic::from_state(&topic));
        }
        let mut connection = state.connection().map_err(|_| SnsError::InternalError)?;
        let transaction = connection
            .transaction()
            .map_err(|_| SnsError::InternalError)?;
        for topic in &topics {
            save_topic(&transaction, topic).map_err(|_| SnsError::InternalError)?;
        }
        {
            let mut query = transaction
                .prepare("SELECT account,region,name FROM sns_topics")
                .map_err(|_| SnsError::InternalError)?;
            let rows = query
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|_| SnsError::InternalError)?;
            for row in rows {
                let key = row.map_err(|_| SnsError::InternalError)?;
                if !present.contains(&key) {
                    transaction
                        .execute(
                            "DELETE FROM sns_topics WHERE account=?1 AND region=?2 AND name=?3",
                            params![key.0, key.1, key.2],
                        )
                        .map_err(|_| SnsError::InternalError)?;
                }
            }
        }
        transaction.commit().map_err(|_| SnsError::InternalError)?;
        self.clear_uncommitted();
        Ok(())
    }

    /// Commit FIFO sequence/dedup and one publication before Publish returns an ACK.
    pub fn accept_job(&self, topic: &TopicState, job: &FanoutJob) -> Result<Option<i64>, SnsError> {
        let Some(state) = self.state() else {
            return Ok(None);
        };
        let mut connection = state.connection().map_err(|_| SnsError::InternalError)?;
        let transaction = connection
            .transaction()
            .map_err(|_| SnsError::InternalError)?;
        save_topic(&transaction, &SavedTopic::from_state(topic))
            .map_err(|_| SnsError::InternalError)?;
        let encoded = serde_json::to_string(job).map_err(|_| SnsError::InternalError)?;
        transaction
            .execute(
                "INSERT INTO sns_outbox(account,region,name,job) VALUES(?1,?2,?3,?4)",
                params![topic.arn.account, topic.arn.region, topic.arn.name, encoded],
            )
            .map_err(|_| SnsError::InternalError)?;
        let id = transaction.last_insert_rowid();
        transaction.commit().map_err(|_| SnsError::InternalError)?;
        self.clear_uncommitted();
        Ok(Some(id))
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
