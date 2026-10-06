use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use locallycloud_state::{StateDb, StateError};
use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

use super::{Record, Scope, Shard, Store, Stream, StreamKey, MAX_GET_RECORD_BYTES};

pub(super) struct Persistence {
    pub(super) state: Arc<StateDb>,
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
        connection.execute_batch("CREATE INDEX IF NOT EXISTS kinesis_record_sequence ON kinesis_shard_records(account,region,name,shard,sequence);
            CREATE INDEX IF NOT EXISTS kinesis_record_timestamp ON kinesis_shard_records(account,region,name,shard,arrival_time,position);")?;
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
                next_position: first_position,
                records: VecDeque::new(),
                ..Default::default()
            });
        }
        let mut statement = connection.prepare("SELECT account,region,name,shard,MIN(position),MAX(position),COUNT(*) FROM kinesis_shard_records GROUP BY account,region,name,shard")?;
        let rows = statement.query_map([], |row| {
            Ok((
                stream_key(row)?,
                position(row, 3)?,
                position(row, 4)?,
                position(row, 5)?,
                position(row, 6)?,
            ))
        })?;
        for row in rows {
            let (key, index, first, last, count) = row?;
            let shard = streams
                .get_mut(&key)
                .and_then(|stream| stream.shards.get_mut(index))
                .ok_or(rusqlite::Error::InvalidQuery)?;
            if first != shard.first_position
                || last.checked_sub(first).and_then(|n| n.checked_add(1)) != Some(count)
            {
                return Err(rusqlite::Error::InvalidQuery.into());
            }
            shard.next_position = last.checked_add(1).ok_or(rusqlite::Error::InvalidQuery)?;
        }
        let mut store = Store {
            streams,
            buffered_bytes: 0,
        };
        let persistence = Self { state };
        for (key, stream) in &mut store.streams {
            persistence.trim(key, stream, super::now_epoch().unwrap_or(0.0))?;
        }
        Ok((persistence, store, secret))
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
        self.append_many(key, stream, &[(index, record)], stream.next_sequence + 1)
    }

    pub(super) fn append_many(
        &self,
        key: &StreamKey,
        stream: &Stream,
        records: &[(usize, &Record)],
        next: u64,
    ) -> Result<(), StateError> {
        if records.is_empty() {
            return Ok(());
        }
        let mut connection = self.state.connection()?;
        let transaction = connection.transaction()?;
        let mut offsets = vec![0usize; stream.shards.len()];
        for (index, record) in records {
            let shard = &stream.shards[*index];
            transaction.execute(
                "INSERT INTO kinesis_shard_records VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    key.scope.account_id,
                    key.scope.region,
                    key.name,
                    *index as i64,
                    (shard.next_position + offsets[*index]) as i64,
                    record.sequence_number,
                    record.data,
                    record.partition_key,
                    record.arrival_time
                ],
            )?;
            offsets[*index] += 1;
            transaction.execute("UPDATE kinesis_shards SET first_position=?5 WHERE account=?1 AND region=?2 AND name=?3 AND shard=?4",params![key.scope.account_id,key.scope.region,key.name,*index as i64,shard.first_position as i64])?;
        }
        transaction.execute("UPDATE kinesis_streams SET next_sequence=?4 WHERE account=?1 AND region=?2 AND name=?3",params![key.scope.account_id,key.scope.region,key.name,next as i64])?;
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn trim(
        &self,
        key: &StreamKey,
        stream: &mut Stream,
        now: f64,
    ) -> Result<(), StateError> {
        let mut connection = self.state.connection()?;
        let transaction = connection.transaction()?;
        let mut firsts = Vec::with_capacity(stream.shards.len());
        let cutoff = now - stream.retention_hours as f64 * 3600.0;
        for (index, shard) in stream.shards.iter().enumerate() {
            let mut first = shard.first_position;
            {
                let mut statement = transaction.prepare("SELECT position,arrival_time FROM kinesis_shard_records WHERE account=?1 AND region=?2 AND name=?3 AND shard=?4 AND position>=?5 ORDER BY position")?;
                let mut rows = statement.query(params![
                    key.scope.account_id,
                    key.scope.region,
                    key.name,
                    index as i64,
                    first as i64
                ])?;
                while let Some(row) = rows.next()? {
                    if row.get::<_, f64>(1)? > cutoff {
                        break;
                    }
                    first = position(row, 0)? + 1;
                }
            }
            if first != shard.first_position {
                transaction.execute("DELETE FROM kinesis_shard_records WHERE account=?1 AND region=?2 AND name=?3 AND shard=?4 AND position<?5", params![key.scope.account_id,key.scope.region,key.name,index as i64,first as i64])?;
                transaction.execute("UPDATE kinesis_shards SET first_position=?5 WHERE account=?1 AND region=?2 AND name=?3 AND shard=?4",params![key.scope.account_id,key.scope.region,key.name,index as i64,first as i64])?;
            }
            firsts.push(first);
        }
        transaction.commit()?;
        for (shard, first) in stream.shards.iter_mut().zip(firsts) {
            shard.first_position = first;
        }
        Ok(())
    }

    pub(super) fn page(
        &self,
        key: &StreamKey,
        index: usize,
        position: usize,
        limit: usize,
    ) -> Result<Vec<Record>, StateError> {
        let connection = self.state.connection()?;
        let mut statement = connection.prepare("SELECT sequence,data,partition_key,arrival_time FROM kinesis_shard_records WHERE account=?1 AND region=?2 AND name=?3 AND shard=?4 AND position>=?5 ORDER BY position LIMIT ?6")?;
        let mut rows = statement.query(params![
            key.scope.account_id,
            key.scope.region,
            key.name,
            index as i64,
            position as i64,
            limit as i64
        ])?;
        let mut records = Vec::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let data: Vec<u8> = row.get(1)?;
            if bytes + data.len() > MAX_GET_RECORD_BYTES {
                break;
            }
            bytes += data.len();
            records.push(Record {
                sequence_number: row.get(0)?,
                data,
                partition_key: row.get(2)?,
                arrival_time: row.get(3)?,
            });
        }
        Ok(records)
    }

    pub(super) fn sequence_position(
        &self,
        key: &StreamKey,
        index: usize,
        sequence: &str,
    ) -> Result<Option<usize>, StateError> {
        Ok(self.state.connection()?.query_row("SELECT position FROM kinesis_shard_records WHERE account=?1 AND region=?2 AND name=?3 AND shard=?4 AND sequence=?5",params![key.scope.account_id,key.scope.region,key.name,index as i64,sequence], |row| position(row,0)).optional()?)
    }

    pub(super) fn timestamp_position(
        &self,
        key: &StreamKey,
        index: usize,
        timestamp: f64,
    ) -> Result<Option<usize>, StateError> {
        Ok(self.state.connection()?.query_row("SELECT MIN(position) FROM kinesis_shard_records WHERE account=?1 AND region=?2 AND name=?3 AND shard=?4 AND arrival_time>=?5",params![key.scope.account_id,key.scope.region,key.name,index as i64,timestamp], |row| row.get::<_,Option<i64>>(0)?.map(|value| usize::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)).transpose())?)
    }

    pub(super) fn latest_arrival(
        &self,
        key: &StreamKey,
        index: usize,
    ) -> Result<Option<f64>, StateError> {
        Ok(self.state.connection()?.query_row("SELECT arrival_time FROM kinesis_shard_records WHERE account=?1 AND region=?2 AND name=?3 AND shard=?4 ORDER BY position DESC LIMIT 1",params![key.scope.account_id,key.scope.region,key.name,index as i64], |row| row.get(0)).optional()?)
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

fn position(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<usize> {
    usize::try_from(row.get::<_, i64>(index)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
