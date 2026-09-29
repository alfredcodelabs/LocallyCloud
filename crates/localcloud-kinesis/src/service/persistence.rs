use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use localcloud_state::{StateDb, StateError};
use rusqlite::params;
use uuid::Uuid;

use super::{record_charge, Record, Scope, Store, Stream, StreamKey, RETENTION_SECONDS};

pub(super) struct Persistence {
    state: Arc<StateDb>,
}

impl Persistence {
    pub(super) fn open(state: Arc<StateDb>) -> Result<(Self, Store, [u8; 32]), StateError> {
        let connection = state.connection()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS kinesis_settings (
                key TEXT PRIMARY KEY, value BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS kinesis_streams (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                generation TEXT NOT NULL, created_at REAL NOT NULL,
                next_sequence INTEGER NOT NULL, first_position INTEGER NOT NULL,
                PRIMARY KEY (account, region, name)
            );
            CREATE TABLE IF NOT EXISTS kinesis_records (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                position INTEGER NOT NULL, sequence TEXT NOT NULL,
                data BLOB NOT NULL, partition_key TEXT NOT NULL, arrival_time REAL NOT NULL,
                PRIMARY KEY (account, region, name, position),
                FOREIGN KEY (account, region, name)
                    REFERENCES kinesis_streams(account, region, name) ON DELETE CASCADE
            );",
        )?;
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
            "SELECT account, region, name, generation, created_at, next_sequence, first_position
             FROM kinesis_streams",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                StreamKey {
                    scope: Scope {
                        account_id: row.get(0)?,
                        region: row.get(1)?,
                    },
                    name: row.get(2)?,
                },
                Stream {
                    generation: row.get(3)?,
                    created_at: row.get(4)?,
                    next_sequence: row.get::<_, i64>(5)? as u64,
                    first_position: row.get::<_, i64>(6)? as usize,
                    records: VecDeque::new(),
                },
            ))
        })?;
        for row in rows {
            let (key, stream) = row?;
            streams.insert(key, stream);
        }
        let mut statement = connection.prepare(
            "SELECT account, region, name, position, sequence, data, partition_key, arrival_time
             FROM kinesis_records ORDER BY account, region, name, position",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                StreamKey {
                    scope: Scope {
                        account_id: row.get(0)?,
                        region: row.get(1)?,
                    },
                    name: row.get(2)?,
                },
                Record {
                    sequence_number: row.get(4)?,
                    data: row.get(5)?,
                    partition_key: row.get(6)?,
                    arrival_time: row.get(7)?,
                },
            ))
        })?;
        let mut store = Store {
            streams,
            buffered_bytes: 0,
        };
        for row in rows {
            let (key, record) = row?;
            if let Some(stream) = store.streams.get_mut(&key) {
                store.buffered_bytes += record_charge(&record.data, &record.partition_key);
                stream.records.push_back(record);
            }
        }
        store.trim_expired(super::now_epoch().unwrap_or(0.0));
        Ok((Self { state }, store, secret))
    }

    pub(super) fn create(&self, key: &StreamKey, stream: &Stream) -> Result<(), StateError> {
        self.state.connection()?.execute(
            "INSERT INTO kinesis_streams VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                key.scope.account_id,
                key.scope.region,
                key.name,
                stream.generation,
                stream.created_at,
                stream.next_sequence as i64,
                stream.first_position as i64
            ],
        )?;
        Ok(())
    }

    pub(super) fn append(
        &self,
        key: &StreamKey,
        stream: &Stream,
        record: &Record,
    ) -> Result<(), StateError> {
        let mut connection = self.state.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO kinesis_records VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                key.scope.account_id,
                key.scope.region,
                key.name,
                (stream.first_position + stream.records.len()) as i64,
                record.sequence_number,
                record.data,
                record.partition_key,
                record.arrival_time
            ],
        )?;
        transaction.execute(
            "UPDATE kinesis_streams SET next_sequence = ?4, first_position = ?5
             WHERE account = ?1 AND region = ?2 AND name = ?3",
            params![
                key.scope.account_id,
                key.scope.region,
                key.name,
                stream.next_sequence as i64 + 1,
                stream.first_position as i64
            ],
        )?;
        transaction.execute(
            "DELETE FROM kinesis_records WHERE account = ?1 AND region = ?2 AND name = ?3
             AND position < ?4 AND arrival_time <= ?5",
            params![
                key.scope.account_id,
                key.scope.region,
                key.name,
                stream.first_position as i64,
                record.arrival_time - RETENTION_SECONDS
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn delete(&self, key: &StreamKey) -> Result<(), StateError> {
        self.state.connection()?.execute(
            "DELETE FROM kinesis_streams WHERE account = ?1 AND region = ?2 AND name = ?3",
            params![key.scope.account_id, key.scope.region, key.name],
        )?;
        Ok(())
    }
}
