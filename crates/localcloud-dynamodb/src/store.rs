//! Region/account-scoped table store and table definition model.
//!
//! Items are held in a `BTreeMap` keyed by a type-aware primary key so range queries on the
//! sort key follow AWS sort order. Secondary-index views are derived on read by re-keying
//! base items, which is functionally faithful without maintaining separate entry maps.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use localcloud_state::StateDb;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex, RwLock};

use crate::error::DdbError;
use crate::value::{number_cmp, AttributeValue, Item};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Hash,
    Range,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySchemaElement {
    pub name: String,
    pub key_type: KeyType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeDefinition {
    pub name: String,
    pub attr_type: String, // "S" | "N" | "B"
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectionType {
    All,
    KeysOnly,
    Include,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Projection {
    pub projection_type: ProjectionType,
    pub non_key_attributes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecondaryIndex {
    pub name: String,
    pub key_schema: Vec<KeySchemaElement>,
    pub projection: Projection,
    /// `true` for a GSI, `false` for an LSI.
    pub global: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSpecification {
    pub enabled: bool,
    pub view_type: String, // NEW_IMAGE | OLD_IMAGE | NEW_AND_OLD_IMAGES | KEYS_ONLY
}

/// A single change record captured on a table's stream (Requirement 28).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamRecord {
    pub event_id: String,
    pub event_name: String, // INSERT | MODIFY | REMOVE
    pub keys: Item,
    pub old_image: Option<Item>,
    pub new_image: Option<Item>,
    pub sequence_number: String,
    pub size_bytes: usize,
    pub creation_unix: f64,
    pub view_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableDefinition {
    pub name: String,
    pub arn: String,
    pub key_schema: Vec<KeySchemaElement>,
    pub attribute_definitions: Vec<AttributeDefinition>,
    pub indexes: Vec<SecondaryIndex>,
    pub billing_mode: String, // PROVISIONED | PAY_PER_REQUEST
    pub read_capacity: u64,
    pub write_capacity: u64,
    pub stream_spec: Option<StreamSpecification>,
    pub creation_date: String,
    pub status: String,        // ACTIVE
    pub replicas: Vec<String>, // MREC regions, including this region
}

impl TableDefinition {
    pub fn hash_key(&self) -> &str {
        &self
            .key_schema
            .iter()
            .find(|k| k.key_type == KeyType::Hash)
            .unwrap()
            .name
    }

    pub fn range_key(&self) -> Option<&str> {
        self.key_schema
            .iter()
            .find(|k| k.key_type == KeyType::Range)
            .map(|k| k.name.as_str())
    }

    pub fn index(&self, name: &str) -> Option<&SecondaryIndex> {
        self.indexes.iter().find(|i| i.name == name)
    }
}

/// A type-aware key scalar with AWS sort semantics (numbers numeric, strings/bytes ordered).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyScalar {
    S(String),
    N(String),
    B(Vec<u8>),
}

impl KeyScalar {
    pub fn from_value(value: &AttributeValue) -> Option<KeyScalar> {
        match value {
            AttributeValue::S(s) => Some(KeyScalar::S(s.clone())),
            AttributeValue::N(n) => Some(KeyScalar::N(n.clone())),
            AttributeValue::B(b) => Some(KeyScalar::B(b.clone())),
            _ => None,
        }
    }

    fn rank(&self) -> u8 {
        match self {
            KeyScalar::N(_) => 0,
            KeyScalar::S(_) => 1,
            KeyScalar::B(_) => 2,
        }
    }
}

impl Ord for KeyScalar {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (KeyScalar::N(a), KeyScalar::N(b)) => number_cmp(a, b),
            (KeyScalar::S(a), KeyScalar::S(b)) => a.cmp(b),
            (KeyScalar::B(a), KeyScalar::B(b)) => a.cmp(b),
            _ => self.rank().cmp(&other.rank()),
        }
    }
}

impl PartialOrd for KeyScalar {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Stored primary key: partition plus optional sort, ordered for range scans.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StoredKey {
    pub partition: KeyScalar,
    pub sort: Option<KeyScalar>,
}

/// A Kinesis streaming destination associated with a table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KinesisDestination {
    pub stream_arn: String,
    pub status: String,
}

/// A table export-to-S3 job (Requirement 34). Export content is not materialized; the job
/// metadata and status are tracked (documented fidelity gap).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportJob {
    pub export_arn: String,
    pub status: String,
    pub start_time: f64,
    pub s3_bucket: Option<String>,
}

/// Live table state behind a per-table lock.
pub struct TableData {
    pub def: TableDefinition,
    persist_id: String,
    pub items: BTreeMap<StoredKey, Item>,
    pub tags: BTreeMap<String, String>,
    pub ttl_attribute: Option<String>,
    pub pitr_enabled: bool,
    /// Ordered change records when a stream is enabled (oldest first).
    pub stream_records: Vec<StreamRecord>,
    /// Monotonic stream sequence counter.
    pub stream_seq: u64,
    /// Kinesis streaming destinations associated with the table.
    pub kinesis_destinations: Vec<KinesisDestination>,
    /// Change records awaiting delivery through the Core InternalDispatcher.
    pub kinesis_pending: Vec<(String, StreamRecord)>,
    /// Export jobs created for the table.
    pub exports: Vec<ExportJob>,
    pub replica_versions: BTreeMap<StoredKey, (u128, String)>,
    pub replica_pending: Vec<(StoredKey, Option<Item>, (u128, String))>,
    pub dirty_keys: std::collections::BTreeSet<StoredKey>,
    stream_persisted: usize,
}

impl TableData {
    /// Create table state with empty items/streams.
    pub fn new(
        def: TableDefinition,
        tags: BTreeMap<String, String>,
        ttl_attribute: Option<String>,
        pitr_enabled: bool,
    ) -> Self {
        TableData {
            def,
            persist_id: uuid::Uuid::new_v4().to_string(),
            items: BTreeMap::new(),
            tags,
            ttl_attribute,
            pitr_enabled,
            stream_records: Vec::new(),
            stream_seq: 0,
            kinesis_destinations: Vec::new(),
            kinesis_pending: Vec::new(),
            exports: Vec::new(),
            replica_versions: BTreeMap::new(),
            replica_pending: Vec::new(),
            dirty_keys: std::collections::BTreeSet::new(),
            stream_persisted: 0,
        }
    }

    /// Whether a stream is currently enabled on this table.
    pub fn stream_enabled(&self) -> bool {
        self.def
            .stream_spec
            .as_ref()
            .map(|s| s.enabled)
            .unwrap_or(false)
    }

    /// The stream ARN for this table when a stream is enabled.
    pub fn stream_arn(&self) -> Option<String> {
        self.def
            .stream_spec
            .as_ref()
            .filter(|s| s.enabled)
            .map(|_| format!("{}/stream/{}", self.def.arn, self.def.creation_date))
    }

    /// Project the key attributes of an item per the table key schema.
    fn key_image(&self, item: &Item) -> Item {
        let mut keys = Item::new();
        let hk = self.def.hash_key();
        if let Some(v) = item.get(hk) {
            keys.insert(hk.to_string(), v.clone());
        }
        if let Some(rk) = self.def.range_key() {
            if let Some(v) = item.get(rk) {
                keys.insert(rk.to_string(), v.clone());
            }
        }
        keys
    }

    /// Record a committed item change for DynamoDB Streams and every active Kinesis
    /// destination. Kinesis always receives both images; the table stream honors its view type.
    pub fn emit_stream(&mut self, old: Option<&Item>, new: Option<&Item>) {
        self.emit_change(old, new, true);
    }

    pub fn emit_replica_stream(&mut self, old: Option<&Item>, new: Option<&Item>) {
        self.emit_change(old, new, false);
    }

    /// A delete of an absent key still needs a tombstone for concurrent MREC writes.
    pub fn record_replica_change(&mut self, key: StoredKey, item: Option<Item>) {
        self.dirty_keys.insert(key.clone());
        if self.def.replicas.is_empty() {
            return;
        }
        let region = self
            .def
            .arn
            .split(':')
            .nth(3)
            .unwrap_or_default()
            .to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|time| time.as_nanos())
            .unwrap_or_default();
        let previous = self.replica_versions.get(&key).map(|v| v.0).unwrap_or(0);
        let version = (now.max(previous + 1), region);
        self.replica_versions.insert(key.clone(), version.clone());
        self.replica_pending.push((key, item, version));
    }

    fn emit_change(&mut self, old: Option<&Item>, new: Option<&Item>, local: bool) {
        if local {
            if let Some(item) = new.or(old) {
                if let Ok(key) = self.key_of(item) {
                    self.dirty_keys.insert(key.clone());
                    self.record_replica_change(key, new.cloned());
                }
            }
        }
        if !self.stream_enabled() && self.kinesis_destinations.is_empty() {
            return;
        }
        let event_name = match (old, new) {
            (None, Some(_)) => "INSERT",
            (Some(_), Some(_)) => "MODIFY",
            (Some(_), None) => "REMOVE",
            (None, None) => return,
        };
        self.stream_seq += 1;
        let record = StreamRecord {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_name: event_name.to_string(),
            keys: self.key_image(new.or(old).unwrap()),
            old_image: old.cloned(),
            new_image: new.cloned(),
            sequence_number: format!("{:025}", self.stream_seq),
            size_bytes: new.or(old).map(crate::value::item_size).unwrap_or(0),
            creation_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0),
            view_type: "NEW_AND_OLD_IMAGES".to_string(),
        };

        if self.stream_enabled() {
            let view = self.def.stream_spec.as_ref().unwrap().view_type.clone();
            let mut stream_record = record.clone();
            stream_record.view_type = view.clone();
            match view.as_str() {
                "KEYS_ONLY" => {
                    stream_record.old_image = None;
                    stream_record.new_image = None;
                }
                "NEW_IMAGE" => stream_record.old_image = None,
                "OLD_IMAGE" => stream_record.new_image = None,
                _ => {}
            }
            self.stream_records.push(stream_record);
        }

        for destination in self
            .kinesis_destinations
            .iter()
            .filter(|destination| destination.status == "ACTIVE")
        {
            self.kinesis_pending
                .push((destination.stream_arn.clone(), record.clone()));
        }
    }

    /// Extract the storage key for `item` per the table key schema; error if a key attribute
    /// is missing or has the wrong scalar type.
    pub fn key_of(&self, item: &Item) -> Result<StoredKey, DdbError> {
        let partition = self.scalar_key(item, self.def.hash_key())?;
        let sort = match self.def.range_key() {
            Some(rk) => Some(self.scalar_key(item, rk)?),
            None => None,
        };
        Ok(StoredKey { partition, sort })
    }

    fn scalar_key(&self, item: &Item, name: &str) -> Result<KeyScalar, DdbError> {
        let value = item
            .get(name)
            .ok_or_else(|| DdbError::Validation(format!("missing key attribute {name}")))?;
        KeyScalar::from_value(value).ok_or_else(|| {
            DdbError::Validation(format!("key attribute {name} must be a scalar S/N/B"))
        })
    }
}

type ScopedKey = (String, String, String);
type TxnTokenKey = (String, String, String);

#[derive(Clone)]
pub struct TxnOutcome {
    pub fingerprint: String,
    pub result: Result<Value, DdbError>,
    pub created_at: Instant,
}

/// Region/account-scoped table store.
#[derive(Default)]
pub struct TableStore {
    tables: DashMap<ScopedKey, Arc<RwLock<TableData>>>,
    txn_tokens: DashMap<TxnTokenKey, Arc<Mutex<Option<TxnOutcome>>>>,
    pub replica_topology: Mutex<()>,
    pub operation_gate: Mutex<()>,
    uncommitted: AtomicBool,
    state: Option<Arc<StateDb>>,
}

impl TableStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_state(state: Arc<StateDb>) -> Result<Self, DdbError> {
        let connection = state.connection().map_err(persist_error)?;
        connection
            .execute_batch(
                "
            CREATE TABLE IF NOT EXISTS dynamodb_tables (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                metadata TEXT NOT NULL,
                PRIMARY KEY(account, region, name)
            );
            CREATE TABLE IF NOT EXISTS dynamodb_txn_tokens (
                account TEXT NOT NULL, region TEXT NOT NULL, token TEXT NOT NULL,
                fingerprint TEXT NOT NULL, created_unix INTEGER NOT NULL, result TEXT NOT NULL,
                PRIMARY KEY(account, region, token)
            );
            CREATE TABLE IF NOT EXISTS dynamodb_stream_records (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                sequence INTEGER NOT NULL, record TEXT NOT NULL,
                PRIMARY KEY(account, region, name, sequence),
                FOREIGN KEY(account, region, name)
                    REFERENCES dynamodb_tables(account, region, name) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS dynamodb_replica_versions (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                item_key TEXT NOT NULL, version TEXT NOT NULL,
                PRIMARY KEY(account, region, name, item_key),
                FOREIGN KEY(account, region, name)
                    REFERENCES dynamodb_tables(account, region, name) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS dynamodb_items (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                item_key TEXT NOT NULL, item TEXT NOT NULL,
                PRIMARY KEY(account, region, name, item_key),
                FOREIGN KEY(account, region, name)
                    REFERENCES dynamodb_tables(account, region, name) ON DELETE CASCADE
            );
        ",
            )
            .map_err(persist_error)?;
        let store = Self {
            state: Some(state),
            ..Self::default()
        };
        {
            let mut query = connection
                .prepare("SELECT account, region, name, metadata FROM dynamodb_tables")
                .map_err(persist_error)?;
            let rows = query
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(persist_error)?;
            for row in rows {
                let (account, region, name, metadata) = row.map_err(persist_error)?;
                let saved: PersistedTable =
                    serde_json::from_str(&metadata).map_err(persist_error)?;
                store.tables.insert(
                    (account, region, name),
                    Arc::new(RwLock::new(saved.into_data())),
                );
            }
        }
        let mut query = connection
            .prepare("SELECT account, region, name, item_key, item FROM dynamodb_items")
            .map_err(persist_error)?;
        let rows = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(persist_error)?;
        for row in rows {
            let (account, region, name, key, item) = row.map_err(persist_error)?;
            let key: StoredKey = serde_json::from_str(&key).map_err(persist_error)?;
            let item: Item = serde_json::from_str(&item).map_err(persist_error)?;
            if let Some(table) = store.get(&account, &region, &name) {
                table
                    .try_write()
                    .expect("newly loaded table has no readers")
                    .items
                    .insert(key, item);
            }
        }
        {
            let mut query = connection.prepare("SELECT account,region,name,record FROM dynamodb_stream_records ORDER BY account,region,name,sequence")
                .map_err(persist_error)?;
            let rows = query
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(persist_error)?;
            for row in rows {
                let (account, region, name, record) = row.map_err(persist_error)?;
                let record = serde_json::from_str(&record).map_err(persist_error)?;
                if let Some(table) = store.get(&account, &region, &name) {
                    let mut guard = table
                        .try_write()
                        .expect("newly loaded table has no readers");
                    guard.stream_records.push(record);
                    guard.stream_persisted += 1;
                }
            }
        }
        {
            let mut query = connection
                .prepare(
                    "SELECT account,region,name,item_key,version FROM dynamodb_replica_versions",
                )
                .map_err(persist_error)?;
            let rows = query
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(persist_error)?;
            for row in rows {
                let (account, region, name, key, version) = row.map_err(persist_error)?;
                let key = serde_json::from_str(&key).map_err(persist_error)?;
                let version = serde_json::from_str(&version).map_err(persist_error)?;
                if let Some(table) = store.get(&account, &region, &name) {
                    table
                        .try_write()
                        .expect("newly loaded table has no readers")
                        .replica_versions
                        .insert(key, version);
                }
            }
        }
        {
            let now = unix_secs();
            let mut query = connection.prepare("SELECT account,region,token,fingerprint,created_unix,result FROM dynamodb_txn_tokens WHERE created_unix>?1")
                .map_err(persist_error)?;
            let rows = query
                .query_map(params![now - 600], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })
                .map_err(persist_error)?;
            for row in rows {
                let (account, region, token, fingerprint, created_unix, result) =
                    row.map_err(persist_error)?;
                let age = (now - created_unix).max(0) as u64;
                let result = serde_json::from_str(&result).map_err(persist_error)?;
                store.txn_tokens.insert(
                    (account, region, token),
                    Arc::new(Mutex::new(Some(TxnOutcome {
                        fingerprint,
                        result: Ok(result),
                        created_at: Instant::now() - Duration::from_secs(age),
                    }))),
                );
            }
        }
        Ok(store)
    }

    /// A cancelled or failed request must commit its in-memory changes before another read.
    pub fn mark_uncommitted(&self) {
        if self.state.is_some() {
            self.uncommitted.store(true, AtomicOrdering::Release);
        }
    }

    pub fn has_uncommitted(&self) -> bool {
        self.uncommitted.load(AtomicOrdering::Acquire)
    }

    pub fn clear_uncommitted(&self) {
        self.uncommitted.store(false, AtomicOrdering::Release);
    }

    pub async fn has_dirty_items(&self) -> bool {
        for (_, _, table) in self.all_tables() {
            if !table.read().await.dirty_keys.is_empty() {
                return true;
            }
        }
        false
    }

    /// Commit changed items and metadata before the service acknowledges a write.
    pub async fn persist(&self) -> Result<(), DdbError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        let entries = self.all_tables();
        let mut locked = Vec::with_capacity(entries.len());
        for (account, region, table) in &entries {
            locked.push((account, region, table.write().await));
        }
        let mut connection = state.connection().map_err(persist_error)?;
        let transaction = connection.transaction().map_err(persist_error)?;
        let mut present = std::collections::BTreeSet::new();
        for (account, region, table) in &locked {
            let name = &table.def.name;
            present.insert(((*account).clone(), (*region).clone(), name.clone()));
            let old_metadata: Option<String> = transaction
                .query_row(
                    "SELECT metadata FROM dynamodb_tables WHERE account=?1 AND region=?2 AND name=?3",
                    params![account, region, name],
                    |row| row.get(0),
                )
                .optional()
                .map_err(persist_error)?;
            if let Some(old_metadata) = old_metadata {
                let old: PersistedTable =
                    serde_json::from_str(&old_metadata).map_err(persist_error)?;
                if old.identity() != table.persist_id {
                    // A newly created table must not inherit rows from an older table with its name.
                    transaction.execute(
                        "DELETE FROM dynamodb_tables WHERE account=?1 AND region=?2 AND name=?3",
                        params![account, region, name],
                    ).map_err(persist_error)?;
                }
            }
            let metadata =
                serde_json::to_string(&PersistedTable::from_data(table)).map_err(persist_error)?;
            transaction
                .execute(
                    "INSERT INTO dynamodb_tables(account,region,name,metadata) VALUES(?1,?2,?3,?4)
                ON CONFLICT(account,region,name) DO UPDATE SET metadata=excluded.metadata",
                    params![account, region, name, metadata],
                )
                .map_err(persist_error)?;
            for record in table.stream_records.iter().skip(table.stream_persisted) {
                let sequence: i64 = record.sequence_number.parse().map_err(persist_error)?;
                let encoded = serde_json::to_string(record).map_err(persist_error)?;
                transaction.execute("INSERT INTO dynamodb_stream_records(account,region,name,sequence,record) VALUES(?1,?2,?3,?4,?5)",
                    params![account,region,name,sequence,encoded]).map_err(persist_error)?;
            }
            for key in &table.dirty_keys {
                let encoded_key = serde_json::to_string(key).map_err(persist_error)?;
                if let Some(version) = table.replica_versions.get(key) {
                    let encoded_version = serde_json::to_string(version).map_err(persist_error)?;
                    transaction.execute("INSERT INTO dynamodb_replica_versions(account,region,name,item_key,version) VALUES(?1,?2,?3,?4,?5)
                        ON CONFLICT(account,region,name,item_key) DO UPDATE SET version=excluded.version",
                        params![account,region,name,encoded_key,encoded_version]).map_err(persist_error)?;
                }
                if let Some(item) = table.items.get(key) {
                    let encoded_item = serde_json::to_string(item).map_err(persist_error)?;
                    transaction.execute("INSERT INTO dynamodb_items(account,region,name,item_key,item) VALUES(?1,?2,?3,?4,?5)
                        ON CONFLICT(account,region,name,item_key) DO UPDATE SET item=excluded.item",
                        params![account, region, name, encoded_key, encoded_item]).map_err(persist_error)?;
                } else {
                    transaction.execute("DELETE FROM dynamodb_items WHERE account=?1 AND region=?2 AND name=?3 AND item_key=?4",
                        params![account, region, name, encoded_key]).map_err(persist_error)?;
                }
            }
        }
        {
            let mut query = transaction
                .prepare("SELECT account,region,name FROM dynamodb_tables")
                .map_err(persist_error)?;
            let rows = query
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(persist_error)?;
            for row in rows {
                let key = row.map_err(persist_error)?;
                if !present.contains(&key) {
                    transaction.execute("DELETE FROM dynamodb_tables WHERE account=?1 AND region=?2 AND name=?3",
                        params![key.0,key.1,key.2]).map_err(persist_error)?;
                }
            }
        }
        let now = unix_secs();
        transaction
            .execute(
                "DELETE FROM dynamodb_txn_tokens WHERE created_unix<=?1",
                params![now - 600],
            )
            .map_err(persist_error)?;
        for entry in &self.txn_tokens {
            let Some(outcome) = entry.value().try_lock().ok() else {
                continue;
            };
            let Some(outcome) = outcome.as_ref() else {
                continue;
            };
            let Ok(result) = &outcome.result else {
                continue;
            };
            let created_unix = now - outcome.created_at.elapsed().as_secs() as i64;
            let encoded_result = serde_json::to_string(result).map_err(persist_error)?;
            transaction.execute("INSERT INTO dynamodb_txn_tokens(account,region,token,fingerprint,created_unix,result) VALUES(?1,?2,?3,?4,?5,?6)
                ON CONFLICT(account,region,token) DO UPDATE SET fingerprint=excluded.fingerprint,created_unix=excluded.created_unix,result=excluded.result",
                params![entry.key().0,entry.key().1,entry.key().2,outcome.fingerprint,created_unix,encoded_result])
                .map_err(persist_error)?;
        }
        transaction.commit().map_err(persist_error)?;
        self.clear_uncommitted();
        for (_, _, mut table) in locked {
            table.dirty_keys.clear();
            table.stream_persisted = table.stream_records.len();
        }
        Ok(())
    }

    fn key(account: &str, region: &str, name: &str) -> ScopedKey {
        (account.to_string(), region.to_string(), name.to_string())
    }

    /// Atomically create a table; `ResourceInUseException` if the name already exists.
    pub fn create(&self, account: &str, region: &str, data: TableData) -> Result<(), DdbError> {
        let key = Self::key(account, region, &data.def.name);
        use dashmap::mapref::entry::Entry;
        match self.tables.entry(key) {
            Entry::Occupied(_) => Err(DdbError::ResourceInUse(format!(
                "Table already exists: {}",
                data.def.name
            ))),
            Entry::Vacant(slot) => {
                slot.insert(Arc::new(RwLock::new(data)));
                Ok(())
            }
        }
    }

    pub fn get(&self, account: &str, region: &str, name: &str) -> Option<Arc<RwLock<TableData>>> {
        self.tables
            .get(&Self::key(account, region, name))
            .map(|e| e.clone())
    }

    pub fn remove(
        &self,
        account: &str,
        region: &str,
        name: &str,
    ) -> Option<Arc<RwLock<TableData>>> {
        self.tables
            .remove(&Self::key(account, region, name))
            .map(|(_, v)| v)
    }

    /// Snapshot every table with its scope. Arcs keep entries alive only for the current sweep.
    pub fn all_tables(&self) -> Vec<(String, String, Arc<RwLock<TableData>>)> {
        self.tables
            .iter()
            .map(|entry| {
                (
                    entry.key().0.clone(),
                    entry.key().1.clone(),
                    entry.value().clone(),
                )
            })
            .collect()
    }

    /// Serialize all uses of one idempotency token and retain its original outcome.
    pub fn txn_slot(
        &self,
        account: &str,
        region: &str,
        token: &str,
    ) -> Arc<Mutex<Option<TxnOutcome>>> {
        self.txn_tokens
            .entry((account.to_string(), region.to_string(), token.to_string()))
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone()
    }

    pub fn purge_expired_txn_tokens(&self) {
        let expired: Vec<TxnTokenKey> = self
            .txn_tokens
            .iter()
            .filter_map(|entry| {
                let outcome = entry.value().try_lock().ok()?;
                outcome
                    .as_ref()
                    .filter(|outcome| outcome.created_at.elapsed() >= Duration::from_secs(600))
                    .map(|_| entry.key().clone())
            })
            .collect();
        for key in expired {
            self.txn_tokens.remove(&key);
        }
    }

    /// Sorted table names in a scope.
    pub fn list_names(&self, account: &str, region: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .tables
            .iter()
            .filter(|e| e.key().0 == account && e.key().1 == region)
            .map(|e| e.key().2.clone())
            .collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_def(name: &str) -> TableDefinition {
        TableDefinition {
            name: name.to_string(),
            arn: format!("arn:aws:dynamodb:us-east-1:0:table/{name}"),
            key_schema: vec![KeySchemaElement {
                name: "pk".into(),
                key_type: KeyType::Hash,
            }],
            attribute_definitions: vec![AttributeDefinition {
                name: "pk".into(),
                attr_type: "S".into(),
            }],
            indexes: vec![],
            billing_mode: "PAY_PER_REQUEST".into(),
            read_capacity: 0,
            write_capacity: 0,
            stream_spec: None,
            creation_date: "now".into(),
            status: "ACTIVE".into(),
            replicas: vec![],
        }
    }

    fn data(def: TableDefinition) -> TableData {
        TableData::new(def, BTreeMap::new(), None, false)
    }

    #[test]
    fn create_is_exclusive() {
        let store = TableStore::new();
        assert!(store
            .create("0", "us-east-1", data(simple_def("t")))
            .is_ok());
        assert!(matches!(
            store.create("0", "us-east-1", data(simple_def("t"))),
            Err(DdbError::ResourceInUse(_))
        ));
    }

    #[test]
    fn scoped_by_account_and_region() {
        let store = TableStore::new();
        store
            .create("0", "us-east-1", data(simple_def("t")))
            .unwrap();
        assert!(store.get("0", "us-east-1", "t").is_some());
        assert!(store.get("0", "eu-west-1", "t").is_none());
        assert!(store.get("1", "us-east-1", "t").is_none());
    }

    #[tokio::test]
    async fn accepted_item_and_replica_backlog_survive_restart() {
        let root = std::env::temp_dir().join(format!(
            "localcloud-ddb-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let mut def = simple_def("events");
        def.replicas = vec!["us-east-1".into(), "eu-west-1".into()];
        def.stream_spec = Some(StreamSpecification {
            enabled: true,
            view_type: "NEW_AND_OLD_IMAGES".into(),
        });
        let store = TableStore::with_state(state.clone()).unwrap();
        store.create("0", "us-east-1", data(def)).unwrap();
        let table = store.get("0", "us-east-1", "events").unwrap();
        let mut item = Item::new();
        item.insert("pk".into(), AttributeValue::S("one".into()));
        item.insert("payload".into(), AttributeValue::S("durable".into()));
        let key = {
            let mut guard = table.write().await;
            let key = guard.key_of(&item).unwrap();
            guard.emit_stream(None, Some(&item));
            guard.items.insert(key.clone(), item.clone());
            key
        };
        store.persist().await.unwrap();
        drop(store);

        let store = TableStore::with_state(state.clone()).unwrap();
        let table = store.get("0", "us-east-1", "events").unwrap();
        {
            let guard = table.read().await;
            assert_eq!(guard.items.get(&key), Some(&item));
            assert_eq!(guard.stream_records.len(), 1);
            assert_eq!(guard.replica_pending.len(), 1);
        }
        {
            let mut guard = table.write().await;
            guard.emit_stream(Some(&item), None);
            guard.items.remove(&key);
        }
        store.persist().await.unwrap();
        drop(store);
        let reopened = TableStore::with_state(state).unwrap();
        let table = reopened.get("0", "us-east-1", "events").unwrap();
        assert!(!table.read().await.items.contains_key(&key));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn recreating_same_table_name_clears_prior_rows() {
        let root = std::env::temp_dir().join(format!(
            "localcloud-ddb-recreate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let store = TableStore::with_state(state.clone()).unwrap();
        store
            .create("0", "us-east-1", data(simple_def("t")))
            .unwrap();
        let table = store.get("0", "us-east-1", "t").unwrap();
        let mut item = Item::new();
        item.insert("pk".into(), AttributeValue::S("old".into()));
        {
            let mut guard = table.write().await;
            let key = guard.key_of(&item).unwrap();
            guard.emit_stream(None, Some(&item));
            guard.items.insert(key, item);
        }
        store.persist().await.unwrap();
        // One commit sees the replacement incarnation directly, without persisting removal first.
        store.remove("0", "us-east-1", "t");
        store
            .create("0", "us-east-1", data(simple_def("t")))
            .unwrap();
        store.persist().await.unwrap();
        drop(store);
        let reopened = TableStore::with_state(state).unwrap();
        assert!(reopened
            .get("0", "us-east-1", "t")
            .unwrap()
            .read()
            .await
            .items
            .is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn numeric_key_orders_numerically() {
        let mut items: BTreeMap<StoredKey, ()> = BTreeMap::new();
        for n in ["10", "9", "100", "1"] {
            items.insert(
                StoredKey {
                    partition: KeyScalar::N(n.into()),
                    sort: None,
                },
                (),
            );
        }
        let order: Vec<_> = items
            .keys()
            .map(|k| match &k.partition {
                KeyScalar::N(n) => n.clone(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(order, vec!["1", "9", "10", "100"]);
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedTable {
    def: TableDefinition,
    #[serde(default)]
    persist_id: String,
    tags: BTreeMap<String, String>,
    ttl_attribute: Option<String>,
    pitr_enabled: bool,
    stream_seq: u64,
    kinesis_destinations: Vec<KinesisDestination>,
    kinesis_pending: Vec<(String, StreamRecord)>,
    exports: Vec<ExportJob>,
    replica_pending: Vec<(StoredKey, Option<Item>, (u128, String))>,
}

impl PersistedTable {
    fn identity(&self) -> String {
        if self.persist_id.is_empty() {
            format!("legacy:{}", self.def.creation_date)
        } else {
            self.persist_id.clone()
        }
    }

    fn from_data(data: &TableData) -> Self {
        Self {
            def: data.def.clone(),
            persist_id: data.persist_id.clone(),
            tags: data.tags.clone(),
            ttl_attribute: data.ttl_attribute.clone(),
            pitr_enabled: data.pitr_enabled,
            stream_seq: data.stream_seq,
            kinesis_destinations: data.kinesis_destinations.clone(),
            kinesis_pending: data.kinesis_pending.clone(),
            exports: data.exports.clone(),
            replica_pending: data.replica_pending.clone(),
        }
    }

    fn into_data(self) -> TableData {
        let persist_id = self.identity();
        TableData {
            def: self.def,
            persist_id,
            items: BTreeMap::new(),
            tags: self.tags,
            ttl_attribute: self.ttl_attribute,
            pitr_enabled: self.pitr_enabled,
            stream_records: Vec::new(),
            stream_seq: self.stream_seq,
            kinesis_destinations: self.kinesis_destinations,
            kinesis_pending: self.kinesis_pending,
            exports: self.exports,
            replica_versions: BTreeMap::new(),
            replica_pending: self.replica_pending,
            dirty_keys: Default::default(),
            stream_persisted: 0,
        }
    }
}

fn persist_error(error: impl std::fmt::Display) -> DdbError {
    DdbError::Internal(format!("DynamoDB persistence failed: {error}"))
}

fn unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}
