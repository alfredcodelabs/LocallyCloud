use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use locallycloud_state::{StateDb, StateError};
use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

use super::{record_charge, Record, Scope, Shard, Store, Stream, StreamKey};

pub(super) struct Persistence {
    state: Arc<StateDb>,
}

impl Persistence {
    pub(super) fn open(state: Arc<StateDb>) -> Result<(Self, Store, [u8; 32]), StateError> {
        let mut connection = state.connection()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS kinesis_settings (key TEXT PRIMARY KEY, value BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS kinesis_streams (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                generation TEXT NOT NULL, created_at REAL NOT NULL,
                next_sequence INTEGER NOT NULL, first_position INTEGER NOT NULL,
                PRIMARY KEY (account, region, name)
            );
            CREATE TABLE IF NOT EXISTS kinesis_shards (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                shard INTEGER NOT NULL, first_position INTEGER NOT NULL,
                PRIMARY KEY (account, region, name, shard),
                FOREIGN KEY (account, region, name) REFERENCES kinesis_streams(account, region, name) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS kinesis_shard_records (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                shard INTEGER NOT NULL, position INTEGER NOT NULL, sequence TEXT NOT NULL,
                data BLOB NOT NULL, partition_key TEXT NOT NULL, arrival_time REAL NOT NULL,
                PRIMARY KEY (account, region, name, shard, position),
                FOREIGN KEY (account, region, name, shard) REFERENCES kinesis_shards(account, region, name, shard) ON DELETE CASCADE
            );",
        )?;
        let format: Option<Vec<u8>> = connection
            .query_row(
                "SELECT value FROM kinesis_settings WHERE key='storage_format'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if format.is_none() {
            let old_records: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='kinesis_records')", [], |row| row.get(0),
            )?;
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "INSERT INTO kinesis_shards SELECT account, region, name, 0, first_position FROM kinesis_streams;",
            )?;
            if old_records {
                transaction.execute_batch(
                    "INSERT INTO kinesis_shard_records SELECT account, region, name, 0, position, sequence, data, partition_key, arrival_time FROM kinesis_records;
                    DROP TABLE kinesis_records;",
                )?;
            }
            transaction.execute(
                "INSERT INTO kinesis_settings VALUES ('storage_format', ?1)",
                [b"2".as_slice()],
            )?;
            transaction.commit()?;
        } else if format.as_deref() != Some(b"2") {
            return Err(rusqlite::Error::InvalidQuery.into());
        }
        let columns: Vec<String> = connection
            .prepare("PRAGMA table_info(kinesis_streams)")?
            .query_map([], |row| row.get(1))?
            .collect::<Result<_, _>>()?;
        let transaction = connection.transaction()?;
        if !columns.iter().any(|c| c == "retention_hours") {
            transaction.execute_batch("ALTER TABLE kinesis_streams ADD COLUMN retention_hours INTEGER NOT NULL DEFAULT 24;")?;
        }
        if !columns.iter().any(|c| c == "tags") {
            transaction.execute_batch(
                "ALTER TABLE kinesis_streams ADD COLUMN tags TEXT NOT NULL DEFAULT '{}';",
            )?;
        }
        transaction.commit()?;
        let mut generated_secret = [0_u8; 32];
        generated_secret[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        generated_secret[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        connection.execute(
            "INSERT OR IGNORE INTO kinesis_settings(key,value) VALUES ('iterator_secret',?1)",
            [&generated_secret[..]],
        )?;
        let secret: Vec<u8> = connection.query_row(
            "SELECT value FROM kinesis_settings WHERE key='iterator_secret'",
            [],
            |row| row.get(0),
        )?;
        let secret: [u8; 32] = secret
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut streams = HashMap::new();
        let mut statement = connection.prepare(
            "SELECT account, region, name, generation, created_at, next_sequence, retention_hours, tags FROM kinesis_streams",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                stream_key(row)?,
                Stream {
                    generation: row.get(3)?,
                    created_at: row.get(4)?,
                    next_sequence: row.get::<_, i64>(5)? as u64,
                    shards: Vec::new(),
                    retention_hours: row.get(6)?,
                    tags: serde_json::from_str(&row.get::<_, String>(7)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                },
            ))
        })?;
        for row in rows {
            let (key, stream) = row?;
            streams.insert(key, stream);
        }
        let mut statement = connection.prepare("SELECT account, region, name, shard, first_position FROM kinesis_shards ORDER BY account, region, name, shard")?;
        let rows = statement.query_map([], |row| {
            Ok((
                stream_key(row)?,
                row.get::<_, u32>(3)? as usize,
                usize::try_from(row.get::<_, i64>(4)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
            ))
        })?;
        for row in rows {
            let (key, index, first_position) = row?;
            let stream = streams.get_mut(&key).ok_or(rusqlite::Error::InvalidQuery)?;
            if index != stream.shards.len() {
                return Err(rusqlite::Error::InvalidQuery.into());
            }
            stream.shards.push(Shard {
                first_position,
                records: VecDeque::new(),
            });
        }
        let mut statement = connection.prepare(
            "SELECT account, region, name, shard, position, sequence, data, partition_key, arrival_time FROM kinesis_shard_records ORDER BY account, region, name, shard, position",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                stream_key(row)?,
                row.get::<_, u32>(3)? as usize,
                Record {
                    sequence_number: row.get(5)?,
                    data: row.get(6)?,
                    partition_key: row.get(7)?,
                    arrival_time: row.get(8)?,
                },
            ))
        })?;
        let mut store = Store {
            streams,
            buffered_bytes: 0,
        };
        for row in rows {
            let (key, index, record) = row?;
            let shard = store
                .streams
                .get_mut(&key)
                .and_then(|stream| stream.shards.get_mut(index))
                .ok_or(rusqlite::Error::InvalidQuery)?;
            store.buffered_bytes += record_charge(&record.data, &record.partition_key);
            shard.records.push_back(record);
        }
        store.trim_expired(super::now_epoch().unwrap_or(0.0));
        Ok((Self { state }, store, secret))
    }

    pub(super) fn create(&self, key: &StreamKey, stream: &Stream) -> Result<(), StateError> {
        let mut connection = self.state.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO kinesis_streams (account,region,name,generation,created_at,next_sequence,first_position,retention_hours,tags) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8)",
            params![
                key.scope.account_id,
                key.scope.region,
                key.name,
                stream.generation,
                stream.created_at,
                stream.next_sequence as i64,
                stream.retention_hours,
                serde_json::to_string(&stream.tags).map_err(|_| rusqlite::Error::InvalidQuery)?
            ],
        )?;
        for (index, shard) in stream.shards.iter().enumerate() {
            transaction.execute(
                "INSERT INTO kinesis_shards VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    key.scope.account_id,
                    key.scope.region,
                    key.name,
                    index as i64,
                    shard.first_position as i64
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn append(
        &self,
        key: &StreamKey,
        stream: &Stream,
        index: usize,
        record: &Record,
    ) -> Result<(), StateError> {
        let shard = &stream.shards[index];
        let mut connection = self.state.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO kinesis_shard_records VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                key.scope.account_id,
                key.scope.region,
                key.name,
                index as i64,
                (shard.first_position + shard.records.len()) as i64,
                record.sequence_number,
                record.data,
                record.partition_key,
                record.arrival_time
            ],
        )?;
        transaction.execute("UPDATE kinesis_streams SET next_sequence=?4 WHERE account=?1 AND region=?2 AND name=?3", params![key.scope.account_id, key.scope.region, key.name, stream.next_sequence as i64 + 1])?;
        transaction.execute("UPDATE kinesis_shards SET first_position=?5 WHERE account=?1 AND region=?2 AND name=?3 AND shard=?4", params![key.scope.account_id, key.scope.region, key.name, index as i64, shard.first_position as i64])?;
        transaction.execute("DELETE FROM kinesis_shard_records WHERE account=?1 AND region=?2 AND name=?3 AND shard=?4 AND position<?5 AND arrival_time<=?6", params![key.scope.account_id, key.scope.region, key.name, index as i64, shard.first_position as i64, record.arrival_time - stream.retention_hours as f64 * 3600.0])?;
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn configure(
        &self,
        key: &StreamKey,
        retention: i64,
        tags: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), StateError> {
        self.state.connection()?.execute("UPDATE kinesis_streams SET retention_hours=?4, tags=?5 WHERE account=?1 AND region=?2 AND name=?3",
            params![key.scope.account_id,key.scope.region,key.name,retention,
            serde_json::to_string(tags).map_err(|_| rusqlite::Error::InvalidQuery)?])?;
        Ok(())
    }

    pub(super) fn delete(&self, key: &StreamKey) -> Result<(), StateError> {
        self.state.connection()?.execute(
            "DELETE FROM kinesis_streams WHERE account=?1 AND region=?2 AND name=?3",
            params![key.scope.account_id, key.scope.region, key.name],
        )?;
        Ok(())
    }
}

fn stream_key(row: &rusqlite::Row<'_>) -> rusqlite::Result<StreamKey> {
    Ok(StreamKey {
        scope: Scope {
            account_id: row.get(0)?,
            region: row.get(1)?,
        },
        name: row.get(2)?,
    })
}
