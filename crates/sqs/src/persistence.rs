//! Durable SQS rows. A committed message or receipt is the acknowledgement boundary.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use locallycloud_state::StateDb;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::SqsError;
use crate::model::{EncryptedBody, Message, MessageAttribute, QueueArn};
use crate::store::{GuardedQueue, MoveTask, QueueState, ReceiveAttempt, SqsStore};

fn storage_error(error: impl std::fmt::Display) -> SqsError {
    tracing::error!(%error, "SQS persistent state failure");
    SqsError::StorageUnavailable
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn deadline_ms(deadline: Instant) -> i64 {
    let now = Instant::now();
    if deadline >= now {
        now_ms().saturating_add(deadline.duration_since(now).as_millis() as i64)
    } else {
        now_ms().saturating_sub(now.duration_since(deadline).as_millis() as i64)
    }
}

fn instant(deadline_ms: i64) -> Instant {
    let now = Instant::now();
    let current_ms = now_ms();
    if deadline_ms >= current_ms {
        now + Duration::from_millis((deadline_ms - current_ms) as u64)
    } else {
        now - Duration::from_millis((current_ms - deadline_ms) as u64)
    }
}

#[derive(Serialize, Deserialize)]
struct StoredQueue {
    attributes: BTreeMap<String, String>,
    tags: BTreeMap<String, String>,
    sequence: u128,
    last_purge_ms: Option<i64>,
    created_ms: i64,
    last_modified_ms: i64,
}

impl From<&QueueState> for StoredQueue {
    fn from(s: &QueueState) -> Self {
        Self {
            attributes: s.attributes.clone(),
            tags: s.tags.clone(),
            sequence: s.sequence,
            last_purge_ms: s.last_purge.map(deadline_ms),
            created_ms: (s.created.unix_timestamp_nanos() / 1_000_000) as i64,
            last_modified_ms: (s.last_modified.unix_timestamp_nanos() / 1_000_000) as i64,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredMessage {
    id: String,
    body: String,
    encrypted_body: Option<EncryptedBody>,
    md5_body: String,
    attributes: BTreeMap<String, MessageAttribute>,
    md5_attributes: Option<String>,
    system_attributes: BTreeMap<String, String>,
    group_id: Option<String>,
    dedup_id: Option<String>,
    sequence_number: Option<u128>,
    sent_timestamp_ms: i64,
    receive_count: u32,
    first_receive_ms: Option<i64>,
    visible_at_ms: i64,
    receipt_handle: Option<String>,
}

impl From<&Message> for StoredMessage {
    fn from(m: &Message) -> Self {
        Self {
            id: m.id.clone(),
            body: m.body.clone(),
            encrypted_body: m.encrypted_body.clone(),
            md5_body: m.md5_body.clone(),
            attributes: m.attributes.clone(),
            md5_attributes: m.md5_attributes.clone(),
            system_attributes: m.system_attributes.clone(),
            group_id: m.group_id.clone(),
            dedup_id: m.dedup_id.clone(),
            sequence_number: m.sequence_number,
            sent_timestamp_ms: m.sent_timestamp_ms,
            receive_count: m.receive_count,
            first_receive_ms: m.first_receive_ms,
            visible_at_ms: deadline_ms(m.visible_at),
            receipt_handle: m.receipt_handle.clone(),
        }
    }
}

impl From<StoredMessage> for Message {
    fn from(m: StoredMessage) -> Self {
        Self {
            id: m.id,
            body: m.body,
            encrypted_body: m.encrypted_body,
            md5_body: m.md5_body,
            attributes: m.attributes,
            md5_attributes: m.md5_attributes,
            system_attributes: m.system_attributes,
            group_id: m.group_id,
            dedup_id: m.dedup_id,
            sequence_number: m.sequence_number,
            sent_timestamp_ms: m.sent_timestamp_ms,
            receive_count: m.receive_count,
            first_receive_ms: m.first_receive_ms,
            visible_at: instant(m.visible_at_ms),
            receipt_handle: m.receipt_handle,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredAttempt {
    expires_ms: i64,
    messages: Vec<StoredMessage>,
}

pub struct SqsPersistence {
    connection: Mutex<rusqlite::Connection>,
}

impl SqsPersistence {
    pub fn open(db: Arc<StateDb>) -> Result<Self, SqsError> {
        let connection = db.connection().map_err(storage_error)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sqs_queues (arn TEXT PRIMARY KEY, state TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS sqs_deleted (arn TEXT PRIMARY KEY, deleted_ms INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS sqs_move_tasks (handle TEXT PRIMARY KEY, payload TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS sqs_messages (
                 arn TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL,
                 PRIMARY KEY (arn, id),
                 FOREIGN KEY (arn) REFERENCES sqs_queues(arn) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS sqs_dedup (
                 arn TEXT NOT NULL, dedup_key TEXT NOT NULL, expires_ms INTEGER NOT NULL,
                 message_id TEXT NOT NULL, sequence TEXT NOT NULL,
                 PRIMARY KEY (arn, dedup_key),
                 FOREIGN KEY (arn) REFERENCES sqs_queues(arn) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS sqs_receive_attempts (
                 arn TEXT NOT NULL, attempt_id TEXT NOT NULL, payload TEXT NOT NULL,
                 PRIMARY KEY (arn, attempt_id),
                 FOREIGN KEY (arn) REFERENCES sqs_queues(arn) ON DELETE CASCADE
             );",
            )
            .map_err(storage_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn load(&self, store: &SqsStore) -> Result<(), SqsError> {
        let connection = self.connection.lock().map_err(storage_error)?;
        let mut statement = connection
            .prepare("SELECT arn,state FROM sqs_queues")
            .map_err(storage_error)?;
        let queues = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage_error)?;
        let mut deleted = connection
            .prepare("SELECT arn,deleted_ms FROM sqs_deleted WHERE deleted_ms>?1")
            .map_err(storage_error)?;
        let deleted_rows = deleted
            .query_map([now_ms() - 60_000], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(storage_error)?;
        for deleted in deleted_rows {
            let (arn, deleted_ms) = deleted.map_err(storage_error)?;
            if let Some(arn) = crate::ops::arn_from_str(&arn) {
                store.restore_deleted(arn, instant(deleted_ms));
            }
        }
        for queue in queues {
            let (arn, json) = queue.map_err(storage_error)?;
            let arn = crate::ops::arn_from_str(&arn)
                .ok_or_else(|| storage_error("invalid stored SQS ARN"))?;
            let saved: StoredQueue = serde_json::from_str(&json).map_err(storage_error)?;
            let fifo = arn.name.ends_with(".fifo");
            let queue =
                match store.insert_if_absent(arn.clone(), fifo, saved.attributes, saved.tags) {
                    crate::store::InsertResult::Inserted(q) => q,
                    crate::store::InsertResult::Existing(_) => {
                        return Err(storage_error("duplicate stored SQS queue"))
                    }
                };
            let mut state = queue.state.try_lock().map_err(storage_error)?;
            state.sequence = saved.sequence;
            state.last_purge = saved.last_purge_ms.map(instant);
            state.created =
                OffsetDateTime::from_unix_timestamp_nanos(saved.created_ms as i128 * 1_000_000)
                    .map_err(storage_error)?;
            state.last_modified = OffsetDateTime::from_unix_timestamp_nanos(
                saved.last_modified_ms as i128 * 1_000_000,
            )
            .map_err(storage_error)?;
            let key = arn.to_arn();
            let mut statement = connection
                .prepare("SELECT payload FROM sqs_messages WHERE arn=?1 ORDER BY rowid")
                .map_err(storage_error)?;
            let messages = statement
                .query_map([&key], |row| row.get::<_, String>(0))
                .map_err(storage_error)?;
            for payload in messages {
                let saved: StoredMessage = serde_json::from_str(&payload.map_err(storage_error)?)
                    .map_err(storage_error)?;
                state.messages.push(saved.into());
            }
            let mut statement = connection
                .prepare(
                    "SELECT dedup_key,expires_ms,message_id,sequence FROM sqs_dedup WHERE arn=?1",
                )
                .map_err(storage_error)?;
            let dedup = statement
                .query_map([&key], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(storage_error)?;
            for value in dedup {
                let (dedup_key, expires_ms, id, sequence) = value.map_err(storage_error)?;
                if expires_ms > now_ms() {
                    let sequence = sequence.parse().map_err(storage_error)?;
                    state.dedup.insert(
                        dedup_key,
                        (instant(expires_ms) - Duration::from_secs(300), id, sequence),
                    );
                }
            }
            let mut statement = connection
                .prepare("SELECT attempt_id,payload FROM sqs_receive_attempts WHERE arn=?1")
                .map_err(storage_error)?;
            let attempts = statement
                .query_map([&key], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(storage_error)?;
            for value in attempts {
                let (id, payload) = value.map_err(storage_error)?;
                let saved: StoredAttempt = serde_json::from_str(&payload).map_err(storage_error)?;
                if saved.expires_ms > now_ms() {
                    state.receive_attempts.insert(
                        id,
                        ReceiveAttempt {
                            expires_at: instant(saved.expires_ms),
                            messages: saved.messages.into_iter().map(Into::into).collect(),
                        },
                    );
                }
            }
        }
        Ok(())
    }

    pub fn load_tasks(&self) -> Result<Vec<MoveTask>, SqsError> {
        let connection = self.connection.lock().map_err(storage_error)?;
        let mut tasks: Vec<MoveTask> = {
            let mut statement = connection
                .prepare("SELECT payload FROM sqs_move_tasks")
                .map_err(storage_error)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(storage_error)?;
            let mut tasks = Vec::new();
            for row in rows {
                tasks.push(
                    serde_json::from_str(&row.map_err(storage_error)?).map_err(storage_error)?,
                );
            }
            tasks
        };
        for task in &mut tasks {
            if task.status == "RUNNING" {
                task.status = "FAILED".to_string();
                self.save_task_locked(&connection, task)?;
            }
        }
        Ok(tasks)
    }

    fn save_task_locked(
        &self,
        connection: &rusqlite::Connection,
        task: &MoveTask,
    ) -> Result<(), SqsError> {
        let payload = serde_json::to_string(task).map_err(storage_error)?;
        connection.execute("INSERT INTO sqs_move_tasks(handle,payload) VALUES (?1,?2) ON CONFLICT(handle) DO UPDATE SET payload=excluded.payload", params![task.handle,payload]).map_err(storage_error)?;
        Ok(())
    }

    pub fn save_task(&self, task: &MoveTask) -> Result<(), SqsError> {
        let connection = self.connection.lock().map_err(storage_error)?;
        self.save_task_locked(&connection, task)
    }

    pub fn create_queue(&self, arn: &QueueArn, state: &QueueState) -> Result<(), SqsError> {
        let mut connection = self.connection.lock().map_err(storage_error)?;
        let transaction = connection.transaction().map_err(storage_error)?;
        let json = serde_json::to_string(&StoredQueue::from(state)).map_err(storage_error)?;
        transaction
            .execute(
                "INSERT INTO sqs_queues(arn,state) VALUES (?1,?2)",
                params![arn.to_arn(), json],
            )
            .map_err(storage_error)?;
        transaction
            .execute("DELETE FROM sqs_deleted WHERE arn=?1", [arn.to_arn()])
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn save_queue(&self, queue: &GuardedQueue, state: &QueueState) -> Result<(), SqsError> {
        let connection = self.connection.lock().map_err(storage_error)?;
        let json = serde_json::to_string(&StoredQueue::from(state)).map_err(storage_error)?;
        let updated = connection
            .execute(
                "UPDATE sqs_queues SET state=?2 WHERE arn=?1",
                params![queue.arn.to_arn(), json],
            )
            .map_err(storage_error)?;
        if updated != 1 {
            return Err(storage_error(
                "SQS queue disappeared during metadata update",
            ));
        }
        Ok(())
    }

    pub fn delete_queue(&self, arn: &QueueArn) -> Result<(), SqsError> {
        let mut connection = self.connection.lock().map_err(storage_error)?;
        let transaction = connection.transaction().map_err(storage_error)?;
        let deleted = transaction
            .execute("DELETE FROM sqs_queues WHERE arn=?1", [arn.to_arn()])
            .map_err(storage_error)?;
        if deleted != 1 {
            return Err(storage_error("SQS queue disappeared during deletion"));
        }
        transaction.execute("INSERT INTO sqs_deleted(arn,deleted_ms) VALUES (?1,?2) ON CONFLICT(arn) DO UPDATE SET deleted_ms=excluded.deleted_ms", params![arn.to_arn(),now_ms()]).map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn save_message(
        &self,
        queue: &GuardedQueue,
        state: &QueueState,
        message: &Message,
        dedup: Option<(&str, &str, u128)>,
    ) -> Result<(), SqsError> {
        let mut connection = self.connection.lock().map_err(storage_error)?;
        let transaction = connection.transaction().map_err(storage_error)?;
        let json = serde_json::to_string(&StoredMessage::from(message)).map_err(storage_error)?;
        transaction.execute("INSERT INTO sqs_messages(arn,id,payload) VALUES (?1,?2,?3) ON CONFLICT(arn,id) DO UPDATE SET payload=excluded.payload", params![queue.arn.to_arn(), message.id, json]).map_err(storage_error)?;
        if let Some((key, id, number)) = dedup {
            transaction
                .execute(
                    "DELETE FROM sqs_dedup WHERE arn=?1 AND expires_ms<=?2",
                    params![queue.arn.to_arn(), now_ms()],
                )
                .map_err(storage_error)?;
            transaction.execute("INSERT INTO sqs_dedup(arn,dedup_key,expires_ms,message_id,sequence) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(arn,dedup_key) DO UPDATE SET expires_ms=excluded.expires_ms,message_id=excluded.message_id,sequence=excluded.sequence", params![queue.arn.to_arn(),key,now_ms()+300_000,id,number.to_string()]).map_err(storage_error)?;
        }
        if message.sequence_number.is_some() {
            let json = serde_json::to_string(&StoredQueue::from(state)).map_err(storage_error)?;
            transaction
                .execute(
                    "UPDATE sqs_queues SET state=?2 WHERE arn=?1",
                    params![queue.arn.to_arn(), json],
                )
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn update_messages(
        &self,
        queue: &GuardedQueue,
        messages: &[Message],
        attempt: Option<(&str, &ReceiveAttempt)>,
    ) -> Result<(), SqsError> {
        let mut connection = self.connection.lock().map_err(storage_error)?;
        let transaction = connection.transaction().map_err(storage_error)?;
        for message in messages {
            let json =
                serde_json::to_string(&StoredMessage::from(message)).map_err(storage_error)?;
            let updated = transaction
                .execute(
                    "UPDATE sqs_messages SET payload=?3 WHERE arn=?1 AND id=?2",
                    params![queue.arn.to_arn(), message.id, json],
                )
                .map_err(storage_error)?;
            if updated != 1 {
                return Err(storage_error("SQS message disappeared during update"));
            }
        }
        if let Some((id, attempt)) = attempt {
            let payload = serde_json::to_string(&StoredAttempt {
                expires_ms: deadline_ms(attempt.expires_at),
                messages: attempt.messages.iter().map(StoredMessage::from).collect(),
            })
            .map_err(storage_error)?;
            transaction.execute("INSERT INTO sqs_receive_attempts(arn,attempt_id,payload) VALUES (?1,?2,?3) ON CONFLICT(arn,attempt_id) DO UPDATE SET payload=excluded.payload", params![queue.arn.to_arn(),id,payload]).map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn delete_attempts(&self, queue: &GuardedQueue, ids: &[&str]) -> Result<(), SqsError> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut connection = self.connection.lock().map_err(storage_error)?;
        let transaction = connection.transaction().map_err(storage_error)?;
        for id in ids {
            transaction
                .execute(
                    "DELETE FROM sqs_receive_attempts WHERE arn=?1 AND attempt_id=?2",
                    params![queue.arn.to_arn(), id],
                )
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn restore_receive(
        &self,
        queue: &GuardedQueue,
        messages: &[Message],
        attempt_id: Option<&str>,
    ) -> Result<(), SqsError> {
        let mut connection = self.connection.lock().map_err(storage_error)?;
        let transaction = connection.transaction().map_err(storage_error)?;
        for message in messages {
            let json =
                serde_json::to_string(&StoredMessage::from(message)).map_err(storage_error)?;
            let updated = transaction
                .execute(
                    "UPDATE sqs_messages SET payload=?3 WHERE arn=?1 AND id=?2",
                    params![queue.arn.to_arn(), message.id, json],
                )
                .map_err(storage_error)?;
            if updated != 1 {
                return Err(storage_error("SQS message disappeared during update"));
            }
        }
        if let Some(id) = attempt_id {
            transaction
                .execute(
                    "DELETE FROM sqs_receive_attempts WHERE arn=?1 AND attempt_id=?2",
                    params![queue.arn.to_arn(), id],
                )
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn delete_messages(&self, queue: &GuardedQueue, ids: &[&str]) -> Result<(), SqsError> {
        let mut connection = self.connection.lock().map_err(storage_error)?;
        let transaction = connection.transaction().map_err(storage_error)?;
        for id in ids {
            transaction
                .execute(
                    "DELETE FROM sqs_messages WHERE arn=?1 AND id=?2",
                    params![queue.arn.to_arn(), id],
                )
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn purge(&self, queue: &GuardedQueue, state: &QueueState) -> Result<(), SqsError> {
        let mut connection = self.connection.lock().map_err(storage_error)?;
        let transaction = connection.transaction().map_err(storage_error)?;
        let arn = queue.arn.to_arn();
        transaction
            .execute("DELETE FROM sqs_messages WHERE arn=?1", [&arn])
            .map_err(storage_error)?;
        transaction
            .execute("DELETE FROM sqs_dedup WHERE arn=?1", [&arn])
            .map_err(storage_error)?;
        transaction
            .execute("DELETE FROM sqs_receive_attempts WHERE arn=?1", [&arn])
            .map_err(storage_error)?;
        let json = serde_json::to_string(&StoredQueue::from(state)).map_err(storage_error)?;
        transaction
            .execute(
                "UPDATE sqs_queues SET state=?2 WHERE arn=?1",
                params![arn, json],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn move_messages(
        &self,
        source: &GuardedQueue,
        destination: &GuardedQueue,
        messages: &[Message],
    ) -> Result<(), SqsError> {
        let mut connection = self.connection.lock().map_err(storage_error)?;
        let transaction = connection.transaction().map_err(storage_error)?;
        for message in messages {
            let json =
                serde_json::to_string(&StoredMessage::from(message)).map_err(storage_error)?;
            let deleted = transaction
                .execute(
                    "DELETE FROM sqs_messages WHERE arn=?1 AND id=?2",
                    params![source.arn.to_arn(), message.id],
                )
                .map_err(storage_error)?;
            if deleted != 1 {
                return Err(storage_error("SQS message disappeared during move"));
            }
            transaction
                .execute(
                    "INSERT INTO sqs_messages(arn,id,payload) VALUES (?1,?2,?3)",
                    params![destination.arn.to_arn(), message.id, json],
                )
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;
        Ok(())
    }
}
