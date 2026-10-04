//! Durable Firehose queue and delivery journal. The streams mutex is held by every caller.

use super::*;
use rusqlite::{params, Connection};

pub(super) type PersistError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Serialize, Deserialize)]
struct SavedIdentity {
    account_id: String,
    access_key_id: Option<String>,
    arn: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SavedStream {
    source: Option<KinesisSource>,
    generation: String,
    created_at: f64,
    destination: DestinationConfig,
    role_caller: Option<SavedIdentity>,
    retry_token: Option<String>,
    delivery_attempts: u8,
    terminal_failure: bool,
}

impl SavedStream {
    fn from_stream(stream: &DeliveryStream) -> Self {
        Self {
            source: stream.source.clone(),
            generation: stream.generation.to_string(),
            created_at: stream.created_at,
            destination: stream.destination.clone(),
            role_caller: stream.role_caller.as_ref().map(|caller| SavedIdentity {
                account_id: caller.account_id.clone(),
                access_key_id: caller.access_key_id.clone(),
                arn: caller.arn.clone(),
            }),
            retry_token: stream.retry_token.map(|token| token.to_string()),
            delivery_attempts: stream.delivery_attempts,
            terminal_failure: stream.terminal_failure,
        }
    }

    fn into_stream(self) -> Result<DeliveryStream, PersistError> {
        Ok(DeliveryStream {
            source: self.source.map(|mut source| {
                if let Some(sequence) = source.checkpoint.take() {
                    source
                        .checkpoints
                        .entry("shardId-000000000000".into())
                        .or_insert(sequence);
                }
                if let Some(sequence) = source.fetched.take() {
                    source
                        .fetched_shards
                        .entry("shardId-000000000000".into())
                        .or_insert(sequence);
                }
                source
            }),
            generation: Uuid::parse_str(&self.generation)?,
            created_at: self.created_at,
            destination: self.destination,
            role_caller: self.role_caller.map(|caller| RequestIdentity {
                account_id: caller.account_id,
                access_key_id: caller.access_key_id,
                arn: caller.arn,
            }),
            pending: VecDeque::new(),
            retained: VecDeque::new(),
            retry_token: self
                .retry_token
                .map(|token| Uuid::parse_str(&token))
                .transpose()?,
            in_flight: None,
            delivery_attempts: self.delivery_attempts,
            retry_at: None,
            terminal_failure: self.terminal_failure,
        })
    }
}

fn schema(connection: &Connection) -> Result<(), PersistError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS firehose_streams (
            account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
            config TEXT NOT NULL,
            PRIMARY KEY(account, region, name)
        );
        CREATE TABLE IF NOT EXISTS firehose_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending','retained','inflight')),
            token TEXT, payload BLOB NOT NULL,
            FOREIGN KEY(account, region, name)
                REFERENCES firehose_streams(account, region, name) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS firehose_queue_idx
            ON firehose_records(account, region, name, state, id);",
    )?;
    Ok(())
}

pub(super) fn load(state: &StateDb) -> Result<HashMap<StreamKey, DeliveryStream>, PersistError> {
    let connection = state.connection()?;
    schema(&connection)?;
    let mut streams = HashMap::new();
    {
        let mut query =
            connection.prepare("SELECT account,region,name,config FROM firehose_streams")?;
        let rows = query.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (account_id, region, name, config) = row?;
            let saved: SavedStream = serde_json::from_str(&config)?;
            streams.insert(
                StreamKey {
                    scope: Scope { account_id, region },
                    name,
                },
                saved.into_stream()?,
            );
        }
    }
    {
        let mut query = connection.prepare(
            "SELECT account,region,name,state,token,payload FROM firehose_records ORDER BY id",
        )?;
        let rows = query.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        for row in rows {
            let (account_id, region, name, record_state, token, payload) = row?;
            let key = StreamKey {
                scope: Scope { account_id, region },
                name,
            };
            let Some(stream) = streams.get_mut(&key) else {
                continue;
            };
            match record_state.as_str() {
                "pending" => stream.pending.push_back(payload),
                "retained" => stream.retained.push_back(payload),
                "inflight" => {
                    stream.retained.push_back(payload);
                    if let Some(token) = token {
                        stream.retry_token = Some(Uuid::parse_str(&token)?);
                    }
                }
                _ => unreachable!("SQLite CHECK restricts states"),
            }
        }
    }
    // A process may stop after claiming a batch and before observing its destination ACK.
    // Requeue those rows with their original token so the same object key is retried.
    connection.execute(
        "UPDATE firehose_records SET state='retained' WHERE state='inflight'",
        [],
    )?;
    Ok(streams)
}

fn save_config(
    connection: &Connection,
    key: &StreamKey,
    stream: &DeliveryStream,
) -> Result<(), PersistError> {
    let config = serde_json::to_string(&SavedStream::from_stream(stream))?;
    connection.execute(
        "INSERT INTO firehose_streams(account,region,name,config) VALUES(?1,?2,?3,?4)
         ON CONFLICT(account,region,name) DO UPDATE SET config=excluded.config",
        params![key.scope.account_id, key.scope.region, key.name, config],
    )?;
    Ok(())
}

impl Inner {
    pub(super) fn persist_create(
        &self,
        key: &StreamKey,
        stream: &DeliveryStream,
    ) -> Result<(), FirehoseError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        let connection = state.connection().map_err(|_| FirehoseError::Internal)?;
        save_config(&connection, key, stream).map_err(|_| FirehoseError::Internal)
    }

    pub(super) fn persist_delete(&self, key: &StreamKey) -> Result<(), FirehoseError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        let connection = state.connection().map_err(|_| FirehoseError::Internal)?;
        connection
            .execute(
                "DELETE FROM firehose_streams WHERE account=?1 AND region=?2 AND name=?3",
                params![key.scope.account_id, key.scope.region, key.name],
            )
            .map_err(|_| FirehoseError::Internal)?;
        Ok(())
    }

    /// Records and source fetched position enter SQLite in one commit before an ACK or poll advance.
    pub(super) fn persist_append(
        &self,
        key: &StreamKey,
        stream: &DeliveryStream,
        records: &[Vec<u8>],
    ) -> Result<(), FirehoseError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        let mut connection = state.connection().map_err(|_| FirehoseError::Internal)?;
        let tx = connection
            .transaction()
            .map_err(|_| FirehoseError::Internal)?;
        save_config(&tx, key, stream).map_err(|_| FirehoseError::Internal)?;
        for data in records {
            tx.execute("INSERT INTO firehose_records(account,region,name,state,payload) VALUES(?1,?2,?3,'pending',?4)",
                params![key.scope.account_id,key.scope.region,key.name,data]).map_err(|_| FirehoseError::Internal)?;
        }
        tx.commit().map_err(|_| FirehoseError::Internal)
    }

    pub(super) fn persist_take(
        &self,
        key: &StreamKey,
        queue: &str,
        count: usize,
        token: Uuid,
    ) -> Result<(), FirehoseError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        let mut connection = state.connection().map_err(|_| FirehoseError::Internal)?;
        let tx = connection
            .transaction()
            .map_err(|_| FirehoseError::Internal)?;
        if queue == "retained" {
            tx.execute(
                "UPDATE firehose_records SET state='retained' WHERE account=?1 AND region=?2 AND name=?3 AND state='inflight' AND token=?4",
                params![key.scope.account_id,key.scope.region,key.name,token.to_string()],
            ).map_err(|_| FirehoseError::Internal)?;
        }
        let changed = tx.execute(
            "UPDATE firehose_records SET state='inflight',token=?1 WHERE id IN (
                SELECT id FROM firehose_records WHERE account=?2 AND region=?3 AND name=?4 AND state=?5
                ORDER BY id LIMIT ?6)",
            params![token.to_string(),key.scope.account_id,key.scope.region,key.name,queue,count as i64],
        ).map_err(|_| FirehoseError::Internal)?;
        if changed != count {
            return Err(FirehoseError::Internal);
        }
        tx.commit().map_err(|_| FirehoseError::Internal)
    }

    /// A downstream ACK and Kinesis checkpoint commit atomically with removal of delivered rows.
    pub(super) fn persist_complete(
        &self,
        key: &StreamKey,
        stream: &DeliveryStream,
        token: Uuid,
        count: usize,
        delivered: bool,
    ) -> Result<(), FirehoseError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        let mut connection = state.connection().map_err(|_| FirehoseError::Internal)?;
        let tx = connection
            .transaction()
            .map_err(|_| FirehoseError::Internal)?;
        let changed = if delivered {
            tx.execute("DELETE FROM firehose_records WHERE account=?1 AND region=?2 AND name=?3 AND state='inflight' AND token=?4",
                params![key.scope.account_id,key.scope.region,key.name,token.to_string()])
        } else {
            tx.execute("UPDATE firehose_records SET state='retained' WHERE account=?1 AND region=?2 AND name=?3 AND state='inflight' AND token=?4",
                params![key.scope.account_id,key.scope.region,key.name,token.to_string()])
        }.map_err(|_| FirehoseError::Internal)?;
        if changed != count {
            return Err(FirehoseError::Internal);
        }
        save_config(&tx, key, stream).map_err(|_| FirehoseError::Internal)?;
        tx.commit().map_err(|_| FirehoseError::Internal)
    }
}
