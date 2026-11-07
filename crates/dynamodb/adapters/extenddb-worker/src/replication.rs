//! Transaction-local MREC capture. Public Streams keep their own images and retention.
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use extenddb_core::types::{AttributeValue, Item, TableKeyInfo};
use extenddb_storage::error::StorageError;
use extenddb_storage::{StreamCapture, TableEngine};
use extenddb_storage_sqlite::mutation_hook::{Mutation, MutationDecision, MutationHook};
use extenddb_storage_sqlite::SqliteEngine;
use serde::{Deserialize, Serialize};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};

const MAX_PAGE: usize = 32;
const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PENDING_BYTES: i64 = 64 * 1024 * 1024;
const MAX_PENDING_CHANGES: i64 = 10_000;

type Result<T> = std::result::Result<T, StorageError>;
type CaptureFuture<'a> = Pin<Box<dyn Future<Output = Result<MutationDecision>> + Send + 'a>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub table_name: String,
    pub global_id: String,
    pub regions: Vec<String>,
    pub snapshot_frontier: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub account_id: String,
    pub global_id: String,
    pub table_name: String,
    pub key: Item,
    pub item: Option<Item>,
    pub clock: i64,
    pub origin: String,
    pub source_region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub seq: i64,
    pub target: String,
    pub change: Change,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub changes: Vec<Change>,
    pub next_rowid: i64,
    pub done: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Incoming {
    account_id: String,
    global_id: String,
    table_name: String,
    clock: i64,
    origin: String,
    source_region: String,
}

pub struct Replication {
    pool: SqlitePool,
    account_id: String,
    region: String,
}

fn storage(_: sqlx::Error) -> StorageError {
    StorageError::Transient("replication storage unavailable".into())
}
fn invalid(message: &str) -> StorageError {
    StorageError::Validation(message.into())
}
fn valid_region(region: &str) -> bool {
    (3..=64).contains(&region.len())
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn key_of(info: &TableKeyInfo, item: &Item) -> Result<Item> {
    info.key_schema
        .iter()
        .map(|part| {
            let value = item
                .get(&part.attribute_name)
                .ok_or_else(|| invalid("replica key is incomplete"))?;
            let value = match value {
                AttributeValue::S(_) | AttributeValue::B(_) => value.clone(),
                AttributeValue::N(number) => AttributeValue::N(
                    extenddb_core::validation::number::validate_and_normalize_number(number)
                        .map_err(|_| invalid("invalid replica numeric key"))?,
                ),
                _ => return Err(invalid("invalid replica key type")),
            };
            Ok((part.attribute_name.clone(), value))
        })
        .collect()
}
fn key_json(info: &TableKeyInfo, item: &Item) -> Result<String> {
    serde_json::to_string(&key_of(info, item)?).map_err(|_| invalid("invalid replica key"))
}
fn base_table(table_id: &str) -> Result<String> {
    if table_id.len() != 36 || !table_id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(invalid("invalid replica table identifier"));
    }
    Ok(format!("\"_ddb_{table_id}\""))
}
fn page_limit(limit: usize) -> Result<i64> {
    if !(1..=MAX_PAGE).contains(&limit) {
        return Err(invalid("replication page limit must be 1..32"));
    }
    Ok(limit as i64)
}

impl Replication {
    pub async fn dispatch(
        &self,
        engine: &SqliteEngine,
        operation: &str,
        mut body: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let text = |field: &str| {
            body.get(field)
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 256)
                .ok_or_else(|| invalid("missing or invalid replication control field"))
        };
        let limit = match body.get("Limit") {
            None => MAX_PAGE,
            Some(value) => value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| invalid("invalid replication page limit"))?,
        };
        let output = match operation {
            "__locallycloud_global_configure" => {
                let regions: Vec<String> = serde_json::from_value(
                    body.get("Regions")
                        .cloned()
                        .ok_or_else(|| invalid("Regions is required"))?,
                )
                .map_err(|_| invalid("invalid replica regions"))?;
                serde_json::to_value(
                    self.configure(text("TableName")?, text("GlobalId")?, regions)
                        .await?,
                )
            }
            "__locallycloud_global_configurations" => {
                let after = body
                    .get("After")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                serde_json::to_value(self.configurations(after, limit).await?)
            }
            "__locallycloud_global_pending" => match body.get("Target") {
                None => {
                    if body.get("AfterSeq").is_some() {
                        return Err(invalid("AfterSeq requires a target lane"));
                    }
                    serde_json::to_value(self.pending(limit).await?)
                }
                Some(target) => {
                    let target = target
                        .as_str()
                        .ok_or_else(|| invalid("invalid replication target"))?;
                    let after = match body.get("AfterSeq") {
                        None => 0,
                        Some(value) => value
                            .as_i64()
                            .ok_or_else(|| invalid("invalid replication cursor"))?,
                    };
                    let deliveries = if after == 0 {
                        self.pending_for_target(target, limit).await?
                    } else {
                        self.pending_for_target_after(target, after, limit).await?
                    };
                    serde_json::to_value(deliveries)
                }
            },
            "__locallycloud_global_ack" => {
                let seq = body
                    .get("Seq")
                    .and_then(serde_json::Value::as_i64)
                    .filter(|seq| *seq > 0)
                    .ok_or_else(|| invalid("invalid replication sequence"))?;
                let target = text("Target")?;
                if !valid_region(target) {
                    return Err(invalid("invalid replication target"));
                }
                self.acknowledge(seq, target).await?;
                Ok(serde_json::json!({}))
            }
            "__locallycloud_global_apply" => {
                let change: Change = serde_json::from_value(
                    body.get_mut("Change")
                        .map(serde_json::Value::take)
                        .ok_or_else(|| invalid("Change is required"))?,
                )
                .map_err(|_| invalid("invalid replication change"))?;
                self.apply(engine, change).await?;
                Ok(serde_json::json!({}))
            }
            "__locallycloud_global_snapshot" => {
                let cursor = match body.get("AfterRowId") {
                    None => 0,
                    Some(value) => value
                        .as_i64()
                        .ok_or_else(|| invalid("invalid snapshot cursor"))?,
                };
                serde_json::to_value(self.snapshot(text("TableName")?, cursor, limit).await?)
            }
            "__locallycloud_global_reserve" => {
                self.reserve(text("TableName")?, text("GlobalId")?).await?;
                Ok(serde_json::json!({}))
            }
            "__locallycloud_global_activate" => {
                self.activate(text("TableName")?, text("GlobalId")?).await?;
                Ok(serde_json::json!({}))
            }
            "__locallycloud_global_freeze" => {
                self.freeze(text("TableName")?, text("GlobalId")?).await?;
                Ok(serde_json::json!({}))
            }
            "__locallycloud_global_detach" => {
                self.detach(text("TableName")?).await?;
                Ok(serde_json::json!({}))
            }
            _ => return Err(invalid("unknown replication control operation")),
        };
        output.map_err(|_| invalid("could not encode replication control response"))
    }

    pub async fn open(database: &str, account_id: &str, region: &str) -> Result<Arc<Self>> {
        if account_id.len() != 12
            || !account_id.bytes().all(|b| b.is_ascii_digit())
            || !valid_region(region)
        {
            return Err(invalid("invalid replication scope"));
        }
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(database)
            .create_if_missing(false)
            .foreign_keys(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(5));
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(storage)?;
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS lc_replication_topology (
            table_name TEXT PRIMARY KEY, global_id TEXT NOT NULL UNIQUE,
            table_id TEXT NOT NULL, regions TEXT NOT NULL, snapshot_frontier INTEGER NOT NULL,
            frozen INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS lc_replication_retired(table_id TEXT PRIMARY KEY,global_id TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS lc_replication_reservations(table_name TEXT PRIMARY KEY,global_id TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS lc_replication_clock (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), clock INTEGER NOT NULL,
            pending_bytes INTEGER NOT NULL CHECK(pending_bytes>=0), pending_count INTEGER NOT NULL CHECK(pending_count>=0));
            INSERT OR IGNORE INTO lc_replication_clock VALUES(1,0,0,0);
            CREATE TABLE IF NOT EXISTS lc_replication_versions (
            global_id TEXT NOT NULL, table_id TEXT NOT NULL, item_key TEXT NOT NULL, clock INTEGER NOT NULL,
            origin TEXT NOT NULL, PRIMARY KEY(global_id,table_id,item_key));
            CREATE TABLE IF NOT EXISTS lc_replication_changes (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, global_id TEXT NOT NULL,
            payload TEXT NOT NULL, payload_bytes INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS lc_replication_deliveries (
            change_seq INTEGER NOT NULL REFERENCES lc_replication_changes(seq) ON DELETE CASCADE,
            target TEXT NOT NULL, PRIMARY KEY(change_seq,target));
            CREATE INDEX IF NOT EXISTS lc_replication_target_lane ON lc_replication_deliveries(target,change_seq);")
            .execute(&pool).await.map_err(storage)?;
        for (table, required) in [
            ("lc_replication_versions", "table_id"),
            ("lc_replication_topology", "frozen"),
        ] {
            let columns: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info(?)")
                .bind(table)
                .fetch_all(&pool)
                .await
                .map_err(storage)?;
            if !columns.iter().any(|column| column == required) {
                return Err(StorageError::Unsupported(
                    "replication metadata requires an explicit migration".into(),
                ));
            }
        }
        Ok(Arc::new(Self {
            pool,
            account_id: account_id.into(),
            region: region.into(),
        }))
    }

    pub async fn configure(
        &self,
        table_name: &str,
        global_id: &str,
        mut regions: Vec<String>,
    ) -> Result<Configuration> {
        if global_id.is_empty()
            || global_id.len() > 128
            || !global_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(invalid("invalid global table generation"));
        }
        let unique: BTreeSet<_> = regions.iter().collect();
        if !(1..=64).contains(&regions.len())
            || unique.len() != regions.len()
            || !regions.iter().all(|region| valid_region(region))
            || !regions.iter().any(|region| region == &self.region)
        {
            return Err(invalid("invalid replica membership"));
        }
        regions.sort();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage)?;
        let table_id: String =
            sqlx::query_scalar("SELECT table_id FROM tables WHERE account_id=? AND table_name=?")
                .bind(&self.account_id)
                .bind(table_name)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?
                .ok_or_else(|| StorageError::TableNotFound(table_name.into()))?;
        let retired: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM lc_replication_retired WHERE table_id=?)",
        )
        .bind(&table_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
        if retired {
            return Err(StorageError::IndexesInUse("replica is retiring".into()));
        }
        let old: Option<(String, String, String)> = sqlx::query_as(
            "SELECT global_id,regions,table_id FROM lc_replication_topology WHERE table_name=?",
        )
        .bind(table_name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
        let old_regions: Vec<String> = match old {
            Some((id, text, existing_table_id))
                if id == global_id && existing_table_id == table_id =>
            {
                serde_json::from_str(&text)
                    .map_err(|_| invalid("invalid replica membership state"))?
            }
            Some(_) => return Err(invalid("global table generation cannot change")),
            None => Vec::new(),
        };
        for removed in old_regions
            .iter()
            .filter(|region| !regions.contains(region))
        {
            let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM lc_replication_deliveries d JOIN lc_replication_changes c ON c.seq=d.change_seq WHERE c.global_id=? AND d.target=?)")
                .bind(global_id).bind(removed).fetch_one(&mut *tx).await.map_err(storage)?;
            if pending {
                return Err(StorageError::IndexesInUse(
                    "replica has pending writes; retry after replication".into(),
                ));
            }
        }
        for added in regions
            .iter()
            .filter(|region| *region != &self.region && !old_regions.contains(region))
        {
            sqlx::query("INSERT OR IGNORE INTO lc_replication_deliveries(change_seq,target) SELECT seq,? FROM lc_replication_changes WHERE global_id=?")
                .bind(added).bind(global_id).execute(&mut *tx).await.map_err(storage)?;
        }
        let frontier: i64 = sqlx::query_scalar(&format!(
            "SELECT COALESCE(MAX(rowid),0) FROM {}",
            base_table(&table_id)?
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
        let membership =
            serde_json::to_string(&regions).map_err(|_| invalid("invalid membership"))?;
        sqlx::query("INSERT INTO lc_replication_topology(table_name,global_id,table_id,regions,snapshot_frontier) VALUES(?,?,?,?,?) ON CONFLICT(table_name) DO UPDATE SET regions=excluded.regions,snapshot_frontier=excluded.snapshot_frontier")
            .bind(table_name).bind(global_id).bind(&table_id).bind(membership).bind(frontier)
            .execute(&mut *tx).await.map_err(storage)?;
        tx.commit().await.map_err(storage)?;
        Ok(Configuration {
            table_name: table_name.into(),
            global_id: global_id.into(),
            regions,
            snapshot_frontier: frontier,
        })
    }

    pub async fn configurations(&self, after: &str, limit: usize) -> Result<Vec<Configuration>> {
        let rows = sqlx::query("SELECT table_name,global_id,regions,snapshot_frontier FROM lc_replication_topology WHERE table_name>? ORDER BY table_name LIMIT ?")
            .bind(after).bind(page_limit(limit)?).fetch_all(&self.pool).await.map_err(storage)?;
        rows.into_iter()
            .map(|row| {
                Ok(Configuration {
                    table_name: row.try_get(0).map_err(storage)?,
                    global_id: row.try_get(1).map_err(storage)?,
                    regions: serde_json::from_str(row.try_get::<&str, _>(2).map_err(storage)?)
                        .map_err(|_| invalid("invalid membership state"))?,
                    snapshot_frontier: row.try_get(3).map_err(storage)?,
                })
            })
            .collect()
    }

    pub async fn reserve(&self, table_name: &str, global_id: &str) -> Result<()> {
        extenddb_core::validation::validate_table_name(
            table_name,
            &extenddb_core::limits::LimitsConfig::default(),
        )
        .map_err(|_| invalid("invalid replica table name"))?;
        if global_id.is_empty()
            || global_id.len() > 128
            || !global_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(invalid("invalid global table generation"));
        }
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage)?;
        let reserved: Option<String> = sqlx::query_scalar(
            "SELECT global_id FROM lc_replication_reservations WHERE table_name=?",
        )
        .bind(table_name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
        match reserved {
            Some(id) if id == global_id => return Ok(()),
            Some(_) => {
                return Err(StorageError::IndexesInUse(
                    "replica name is reserved by another operation".into(),
                ))
            }
            None => {}
        }
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM tables WHERE account_id=? AND table_name=?)",
        )
        .bind(&self.account_id)
        .bind(table_name)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
        if exists {
            return Err(StorageError::TableAlreadyExists(table_name.into()));
        }
        sqlx::query("INSERT INTO lc_replication_reservations(table_name,global_id) VALUES(?,?)")
            .bind(table_name)
            .bind(global_id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        tx.commit().await.map_err(storage)
    }

    pub async fn activate(&self, table_name: &str, global_id: &str) -> Result<()> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage)?;
        let configured:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM lc_replication_topology t JOIN tables d ON d.table_id=t.table_id WHERE d.account_id=? AND t.table_name=? AND t.global_id=? AND t.frozen=0)")
            .bind(&self.account_id).bind(table_name).bind(global_id).fetch_one(&mut *tx).await.map_err(storage)?;
        if !configured {
            return Err(invalid("replica is not configured for activation"));
        }
        let reservation: Option<String> = sqlx::query_scalar(
            "SELECT global_id FROM lc_replication_reservations WHERE table_name=?",
        )
        .bind(table_name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
        if reservation.is_some_and(|id| id != global_id) {
            return Err(invalid("replica reservation belongs to another operation"));
        }
        sqlx::query("DELETE FROM lc_replication_reservations WHERE table_name=? AND global_id=?")
            .bind(table_name)
            .bind(global_id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        tx.commit().await.map_err(storage)
    }

    pub async fn freeze(&self, table_name: &str, global_id: &str) -> Result<()> {
        let result = sqlx::query(
            "UPDATE lc_replication_topology SET frozen=1 WHERE table_name=? AND global_id=?",
        )
        .bind(table_name)
        .bind(global_id)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::TableNotFound(table_name.into()));
        }
        Ok(())
    }

    pub async fn detach(&self, table_name: &str) -> Result<()> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage)?;
        let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM lc_replication_changes c JOIN lc_replication_topology t ON t.global_id=c.global_id WHERE t.table_name=?)")
            .bind(table_name).fetch_one(&mut *tx).await.map_err(storage)?;
        if pending {
            return Err(StorageError::IndexesInUse(
                "replica has pending writes; retry after replication".into(),
            ));
        }
        sqlx::query("INSERT OR IGNORE INTO lc_replication_retired(table_id,global_id) SELECT table_id,global_id FROM lc_replication_topology WHERE table_name=? AND frozen=1")
            .bind(table_name).execute(&mut *tx).await.map_err(storage)?;
        sqlx::query("DELETE FROM lc_replication_topology WHERE table_name=?")
            .bind(table_name)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        tx.commit().await.map_err(storage)
    }

    pub async fn pending(&self, limit: usize) -> Result<Vec<Delivery>> {
        self.pending_page(None, 0, limit).await
    }

    pub async fn pending_for_target(&self, target: &str, limit: usize) -> Result<Vec<Delivery>> {
        self.pending_for_target_after(target, 0, limit).await
    }

    pub async fn pending_for_target_after(
        &self,
        target: &str,
        after: i64,
        limit: usize,
    ) -> Result<Vec<Delivery>> {
        if !valid_region(target) || after < 0 {
            return Err(invalid("invalid replication target or cursor"));
        }
        self.pending_page(Some(target), after, limit).await
    }

    async fn pending_page(
        &self,
        target: Option<&str>,
        after: i64,
        limit: usize,
    ) -> Result<Vec<Delivery>> {
        page_limit(limit)?;
        let mut bytes = 0;
        let mut deliveries = Vec::new();
        let mut cursor = (after, String::new());
        for _ in 0..limit {
            let row=match target {
                Some(target)=>sqlx::query("SELECT c.seq,d.target,c.payload FROM lc_replication_deliveries d JOIN lc_replication_changes c ON c.seq=d.change_seq WHERE d.target=? AND c.seq>? ORDER BY c.seq LIMIT 1")
                    .bind(target).bind(cursor.0).fetch_optional(&self.pool).await.map_err(storage)?,
                None=>sqlx::query("SELECT c.seq,d.target,c.payload FROM lc_replication_changes c JOIN lc_replication_deliveries d ON c.seq=d.change_seq WHERE c.seq>? OR (c.seq=? AND d.target>?) ORDER BY c.seq,d.target LIMIT 1")
                    .bind(cursor.0).bind(cursor.0).bind(&cursor.1).fetch_optional(&self.pool).await.map_err(storage)?,
            };
            let Some(row) = row else {
                break;
            };
            let payload: &str = row.try_get(2).map_err(storage)?;
            if !deliveries.is_empty() && bytes + payload.len() > MAX_PAGE_BYTES {
                break;
            }
            bytes += payload.len();
            let seq = row.try_get(0).map_err(storage)?;
            let target: String = row.try_get(1).map_err(storage)?;
            cursor = (seq, target.clone());
            deliveries.push(Delivery {
                seq,
                target,
                change: serde_json::from_str(payload)
                    .map_err(|_| invalid("invalid replication payload"))?,
            });
        }
        Ok(deliveries)
    }

    pub async fn acknowledge(&self, seq: i64, target: &str) -> Result<()> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage)?;
        sqlx::query("DELETE FROM lc_replication_deliveries WHERE change_seq=? AND target=?")
            .bind(seq)
            .bind(target)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        let done: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS(SELECT 1 FROM lc_replication_deliveries WHERE change_seq=?)",
        )
        .bind(seq)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
        if done {
            let bytes: Option<i64> = sqlx::query_scalar(
                "DELETE FROM lc_replication_changes WHERE seq=? RETURNING payload_bytes",
            )
            .bind(seq)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?;
            if let Some(bytes) = bytes {
                sqlx::query("UPDATE lc_replication_clock SET pending_bytes=pending_bytes-?,pending_count=pending_count-1 WHERE singleton=1").bind(bytes).execute(&mut *tx).await.map_err(storage)?;
            }
        }
        tx.commit().await.map_err(storage)
    }

    pub async fn apply(&self, engine: &SqliteEngine, change: Change) -> Result<()> {
        if change.account_id != self.account_id || change.clock < 0 || !valid_region(&change.origin)
        {
            return Err(invalid("invalid replica change scope"));
        }
        let info = engine
            .table_key_info(&self.account_id, &change.table_name)
            .await?;
        let key = key_of(&info, &change.key)?;
        if key.len() != change.key.len() {
            return Err(invalid("replica change has non-key attributes in its key"));
        }
        if let Some(item) = &change.item {
            if key_json(&info, item)? != key_json(&info, &key)? {
                return Err(invalid("replica image key differs from its change key"));
            }
            extenddb_core::validation::validate_item_size(item, 409_600)
                .map_err(|_| invalid("replica image exceeds item size"))?;
        }
        let capture = info
            .stream_specification
            .as_ref()
            .filter(|s| s.stream_enabled)
            .and_then(|s| s.stream_view_type)
            .map(|view_type| StreamCapture {
                view_type,
                user_identity: None,
                region: Arc::from(self.region.as_str()),
            });
        let context = serde_json::to_value(Incoming {
            account_id: change.account_id,
            global_id: change.global_id,
            table_name: change.table_name,
            clock: change.clock,
            origin: change.origin,
            source_region: change.source_region,
        })
        .map_err(|_| invalid("invalid replica context"))?;
        engine
            .apply_replica_change(&info, &key, change.item, &context, capture.as_ref())
            .await
    }

    pub async fn snapshot(
        &self,
        table_name: &str,
        after_rowid: i64,
        limit: usize,
    ) -> Result<Snapshot> {
        if after_rowid < 0 {
            return Err(invalid("invalid snapshot cursor"));
        }
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage)?;
        let row=sqlx::query("SELECT t.global_id,t.table_id,t.snapshot_frontier,d.key_schema FROM lc_replication_topology t JOIN tables d ON d.table_id=t.table_id AND d.account_id=? WHERE t.table_name=?")
            .bind(&self.account_id).bind(table_name).fetch_optional(&mut *tx).await.map_err(storage)?.ok_or_else(||StorageError::TableNotFound(table_name.into()))?;
        let global_id: String = row.try_get(0).map_err(storage)?;
        let table_id: String = row.try_get(1).map_err(storage)?;
        let frontier: i64 = row.try_get(2).map_err(storage)?;
        let schema: Vec<extenddb_core::types::KeySchemaElement> =
            serde_json::from_str(row.try_get::<&str, _>(3).map_err(storage)?)
                .map_err(|_| invalid("invalid key schema"))?;
        page_limit(limit)?;
        let mut next = after_rowid;
        let mut changes = Vec::new();
        let mut bytes = 0;
        for _ in 0..limit {
            let row = sqlx::query(&format!(
                "SELECT rowid,item_data FROM {} WHERE rowid>? AND rowid<=? ORDER BY rowid LIMIT 1",
                base_table(&table_id)?
            ))
            .bind(next)
            .bind(frontier)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?;
            let Some(row) = row else {
                break;
            };
            let json: &str = row.try_get(1).map_err(storage)?;
            if !changes.is_empty() && bytes + json.len() > MAX_PAGE_BYTES {
                break;
            }
            let item: Item =
                serde_json::from_str(json).map_err(|_| invalid("invalid stored replica item"))?;
            let key: Item = schema
                .iter()
                .map(|part| {
                    item.get(&part.attribute_name)
                        .cloned()
                        .map(|value| (part.attribute_name.clone(), value))
                        .ok_or_else(|| invalid("stored replica key missing"))
                })
                .collect::<Result<_>>()?;
            let item_key =
                serde_json::to_string(&key).map_err(|_| invalid("invalid stored replica key"))?;
            sqlx::query("INSERT OR IGNORE INTO lc_replication_versions(global_id,table_id,item_key,clock,origin) VALUES(?,?,?,0,?)").bind(&global_id).bind(&table_id).bind(&item_key).bind(&self.region).execute(&mut *tx).await.map_err(storage)?;
            let (clock, origin): (i64, String) = sqlx::query_as(
                "SELECT clock,origin FROM lc_replication_versions WHERE global_id=? AND table_id=? AND item_key=?",
            )
            .bind(&global_id)
            .bind(&table_id)
            .bind(&item_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
            changes.push(Change {
                account_id: self.account_id.clone(),
                global_id: global_id.clone(),
                table_name: table_name.into(),
                key,
                item: Some(item),
                clock,
                origin,
                source_region: self.region.clone(),
            });
            bytes += json.len();
            next = row.try_get(0).map_err(storage)?;
        }
        let more: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {} WHERE rowid>? AND rowid<=?)",
            base_table(&table_id)?
        ))
        .bind(next)
        .bind(frontier)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
        tx.commit().await.map_err(storage)?;
        Ok(Snapshot {
            changes,
            next_rowid: next,
            done: !more,
        })
    }
}

impl MutationHook for Replication {
    fn capture<'a, 'c>(
        &'a self,
        tx: &'a mut Transaction<'c, Sqlite>,
        mutation: Mutation<'a>,
    ) -> CaptureFuture<'a> {
        Box::pin(async move {
            if mutation.key_info.account_id != self.account_id {
                return Err(invalid("replication account mismatch"));
            }
            if mutation.context.is_none() {
                let reserved: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM lc_replication_reservations WHERE table_name=?)",
                )
                .bind(&mutation.key_info.table_name)
                .fetch_one(&mut **tx)
                .await
                .map_err(storage)?;
                if reserved {
                    return Err(StorageError::IndexesInUse(
                        "replica is being created".into(),
                    ));
                }
            }
            let topology:Option<(String,String,bool)>=sqlx::query_as("SELECT global_id,regions,frozen FROM lc_replication_topology WHERE table_name=? AND table_id=?")
                .bind(&mutation.key_info.table_name).bind(&mutation.key_info.table_id).fetch_optional(&mut **tx).await.map_err(storage)?;
            if mutation.context.is_none() {
                let retired: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM lc_replication_retired WHERE table_id=?)",
                )
                .bind(&mutation.key_info.table_id)
                .fetch_one(&mut **tx)
                .await
                .map_err(storage)?;
                if retired {
                    return Err(StorageError::IndexesInUse("replica is retiring".into()));
                }
            }
            let Some((global_id, membership, frozen)) = topology else {
                if mutation.context.is_some() {
                    return Err(invalid("replica is not configured"));
                }
                return Ok(MutationDecision::Apply);
            };
            if frozen && mutation.context.is_none() {
                return Err(StorageError::IndexesInUse("replica is retiring".into()));
            }
            let regions: Vec<String> = serde_json::from_str(&membership)
                .map_err(|_| invalid("invalid replica membership state"))?;
            let key = key_of(mutation.key_info, mutation.key)?;
            let item_key =
                serde_json::to_string(&key).map_err(|_| invalid("invalid replica key"))?;
            let old: Option<(i64, String)> = sqlx::query_as(
                "SELECT clock,origin FROM lc_replication_versions WHERE global_id=? AND table_id=? AND item_key=?",
            )
            .bind(&global_id)
            .bind(&mutation.key_info.table_id)
            .bind(&item_key)
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage)?;
            let current: i64 =
                sqlx::query_scalar("SELECT clock FROM lc_replication_clock WHERE singleton=1")
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(storage)?;
            let (clock, origin, local) = match mutation.context {
                Some(context) => {
                    let incoming: Incoming = serde_json::from_value(context.clone())
                        .map_err(|_| invalid("invalid incoming replication metadata"))?;
                    if incoming.account_id != self.account_id
                        || incoming.global_id != global_id
                        || incoming.table_name != mutation.key_info.table_name
                        || incoming.clock < 0
                        || !valid_region(&incoming.origin)
                        || !regions.contains(&incoming.source_region)
                    {
                        return Err(invalid("incoming replica scope or membership mismatch"));
                    }
                    if old.as_ref().is_some_and(|version| {
                        version >= &(incoming.clock, incoming.origin.clone())
                    }) {
                        return Ok(MutationDecision::Skip);
                    }
                    (incoming.clock, incoming.origin, false)
                }
                None => {
                    let now: i64 = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| invalid("system clock precedes epoch"))?
                        .as_micros()
                        .try_into()
                        .map_err(|_| invalid("replication clock out of range"))?;
                    (
                        now.max(
                            current
                                .checked_add(1)
                                .ok_or_else(|| invalid("replication clock exhausted"))?,
                        ),
                        self.region.clone(),
                        true,
                    )
                }
            };
            sqlx::query("UPDATE lc_replication_clock SET clock=MAX(clock,?) WHERE singleton=1")
                .bind(clock)
                .execute(&mut **tx)
                .await
                .map_err(storage)?;
            sqlx::query("INSERT INTO lc_replication_versions(global_id,table_id,item_key,clock,origin) VALUES(?,?,?,?,?) ON CONFLICT(global_id,table_id,item_key) DO UPDATE SET clock=excluded.clock,origin=excluded.origin")
                .bind(&global_id).bind(&mutation.key_info.table_id).bind(&item_key).bind(clock).bind(&origin).execute(&mut **tx).await.map_err(storage)?;
            if local && regions.len() > 1 {
                let change = Change {
                    account_id: self.account_id.clone(),
                    global_id: global_id.clone(),
                    table_name: mutation.key_info.table_name.clone(),
                    key,
                    item: mutation.new.cloned(),
                    clock,
                    origin,
                    source_region: self.region.clone(),
                };
                let payload = serde_json::to_string(&change)
                    .map_err(|_| invalid("invalid replication payload"))?;
                let accepted=sqlx::query("UPDATE lc_replication_clock SET pending_bytes=pending_bytes+?,pending_count=pending_count+1 WHERE singleton=1 AND pending_bytes+?<=? AND pending_count<?")
                    .bind(payload.len()as i64).bind(payload.len()as i64).bind(MAX_PENDING_BYTES).bind(MAX_PENDING_CHANGES).execute(&mut **tx).await.map_err(storage)?;
                if accepted.rows_affected() != 1 {
                    return Err(StorageError::Transient(
                        "replication backlog capacity reached; retry after replication".into(),
                    ));
                }
                let seq=sqlx::query("INSERT INTO lc_replication_changes(global_id,payload,payload_bytes) VALUES(?,?,?)").bind(global_id).bind(&payload).bind(payload.len()as i64).execute(&mut **tx).await.map_err(storage)?.last_insert_rowid();
                for region in regions.iter().filter(|region| *region != &self.region) {
                    sqlx::query(
                        "INSERT INTO lc_replication_deliveries(change_seq,target) VALUES(?,?)",
                    )
                    .bind(seq)
                    .bind(region)
                    .execute(&mut **tx)
                    .await
                    .map_err(storage)?;
                }
            }
            Ok(MutationDecision::Apply)
        })
    }
}

#[cfg(test)]
mod pitr_tests {
    use super::*;
    use extenddb_core::expression::ExpressionMaps;
    use extenddb_core::types::CreateTableInput;
    use extenddb_storage::bootstrapper::Bootstrapper;
    use extenddb_storage::management_store::ManagementStore;
    use extenddb_storage::DataEngine;
    use extenddb_storage_sqlite::{SqliteBootstrapper, SqliteCatalogStore};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};

    const ACCOUNT: &str = "000000000000";
    const TABLE: &str = "replicated-history";
    const GLOBAL: &str = "replicated-history-generation";
    const A: &str = "us-east-1";
    const B: &str = "us-east-2";
    const DAY_US: i64 = 86_400_000_000;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "worker-mrec-pitr-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn open(path: &Path, region: &str) -> (SqliteEngine, Arc<Replication>) {
        let path = path.to_str().unwrap();
        let bootstrap = SqliteBootstrapper::new(path);
        if !bootstrap.is_catalog_initialized().await.unwrap() {
            bootstrap.run_catalog_migrations().await.unwrap();
            bootstrap.bootstrap_encryption_key().await.unwrap();
            bootstrap.bootstrap_default_account().await.unwrap();
        }
        let engine = SqliteEngine::new(path, 1, region, 409_600).await.unwrap();
        let replication = Replication::open(path, ACCOUNT, region).await.unwrap();
        engine.install_mutation_hook(replication.clone()).unwrap();
        // Bootstrap chooses its default account; production also ensures the explicit worker scope.
        let catalog = SqliteCatalogStore::new(replication.pool.clone());
        if catalog.get_account_detail(ACCOUNT).await.unwrap().is_none() {
            catalog.create_account(ACCOUNT, ACCOUNT).await.unwrap();
        }
        sqlx::query(
            "INSERT OR REPLACE INTO settings(key,value) VALUES('control_plane_delay_seconds','0')",
        )
        .execute(&replication.pool)
        .await
        .unwrap();
        (engine, replication)
    }

    async fn table(engine: &SqliteEngine) -> TableKeyInfo {
        let input: CreateTableInput = serde_json::from_value(serde_json::json!({
            "TableName":TABLE,"BillingMode":"PAY_PER_REQUEST",
            "KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],
            "AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}]
        }))
        .unwrap();
        engine.create_table(ACCOUNT, input).await.unwrap();
        engine.table_key_info(ACCOUNT, TABLE).await.unwrap()
    }

    fn item(value: &str) -> Item {
        serde_json::from_value(serde_json::json!({"pk":{"S":"key"},"payload":{"S":value}})).unwrap()
    }
    fn key() -> Item {
        serde_json::from_value(serde_json::json!({"pk":{"S":"key"}})).unwrap()
    }
    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros()
            .try_into()
            .unwrap()
    }
    async fn history(replication: &Replication) -> (i64, i64) {
        sqlx::query_as("SELECT COUNT(*),COALESCE(MAX(at_us),0) FROM lc_pitr_versions WHERE table_id=(SELECT table_id FROM tables WHERE account_id=? AND table_name=?)")
            .bind(ACCOUNT).bind(TABLE).fetch_one(&replication.pool).await.unwrap()
    }
    async fn version(replication: &Replication, info: &TableKeyInfo) -> i64 {
        sqlx::query_scalar("SELECT clock FROM lc_replication_versions WHERE global_id=? AND table_id=? AND item_key=?")
            .bind(GLOBAL).bind(&info.table_id).bind(key_json(info,&key()).unwrap())
            .fetch_one(&replication.pool).await.unwrap()
    }
    async fn pending(replication: &Replication) -> Delivery {
        let mut changes = replication.pending_for_target(B, 10).await.unwrap();
        assert_eq!(changes.len(), 1);
        changes.remove(0)
    }
    async fn put(engine: &SqliteEngine, info: &TableKeyInfo, value: &str) {
        engine
            .put_item(
                info,
                item(value),
                false,
                None,
                &ExpressionMaps::default(),
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn remote_commit_history_is_atomic_replay_safe_and_survives_reopen() {
        // This is the worker suite's only database test and owns its normal one-time VFS setup.
        crate::cipher::install(zeroize::Zeroizing::new([73; 32])).unwrap();
        let directory = tokio::task::spawn_blocking(Directory::new).await.unwrap();
        let a_path = directory.0.join("a.sqlite3");
        let b_path = directory.0.join("b.sqlite3");
        let (a, source) = open(&a_path, A).await;
        let (b, receiver) = open(&b_path, B).await;
        let a_info = table(&a).await;
        let b_info = table(&b).await;
        let source_window = a
            .pitr_configure(ACCOUNT, TABLE, true, Some(35))
            .await
            .unwrap();
        source
            .configure(TABLE, GLOBAL, vec![A.into(), B.into()])
            .await
            .unwrap();
        receiver
            .configure(TABLE, GLOBAL, vec![A.into(), B.into()])
            .await
            .unwrap();
        assert_eq!(
            b.pitr_describe(ACCOUNT, TABLE).await.unwrap()["ContinuousBackupsDescription"]
                ["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"],
            "DISABLED"
        );
        b.pitr_configure(ACCOUNT, TABLE, true, Some(1))
            .await
            .unwrap();
        assert_eq!(
            a.pitr_describe(ACCOUNT, TABLE).await.unwrap()["ContinuousBackupsDescription"]
                ["PointInTimeRecoveryDescription"]["EarliestRestorableDateTime"],
            source_window["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]
                ["EarliestRestorableDateTime"]
        );
        assert_eq!(
            b.pitr_describe(ACCOUNT, TABLE).await.unwrap()["ContinuousBackupsDescription"]
                ["PointInTimeRecoveryDescription"]["RecoveryPeriodInDays"],
            1
        );

        // MREC's ordering clock may lead wall time; PITR must use the actual local commit time.
        sqlx::query("UPDATE lc_replication_clock SET clock=? WHERE singleton=1")
            .bind(now() + DAY_US)
            .execute(&source.pool)
            .await
            .unwrap();
        put(&a, &a_info, "v1").await;
        let first = pending(&source).await;
        let before = now();
        receiver.apply(&b, first.change.clone()).await.unwrap();
        let after = now();
        let first_history = history(&receiver).await;
        assert_eq!(first_history.0, 1);
        assert!((before..=after).contains(&first_history.1));
        assert!(first_history.1 < first.change.clock);
        assert_eq!(version(&receiver, &b_info).await, first.change.clock);
        assert_eq!(b.get_item(&b_info, &key()).await.unwrap(), Some(item("v1")));
        source.acknowledge(first.seq, B).await.unwrap();
        receiver.apply(&b, first.change.clone()).await.unwrap();
        assert_eq!(history(&receiver).await, first_history);

        put(&a, &a_info, "v2").await;
        let second = pending(&source).await;
        sqlx::query("UPDATE lc_pitr_clock SET last_us=? WHERE singleton=1")
            .bind(now() + DAY_US)
            .execute(&receiver.pool)
            .await
            .unwrap();
        assert!(receiver.apply(&b, second.change.clone()).await.is_err());
        assert_eq!(b.get_item(&b_info, &key()).await.unwrap(), Some(item("v1")));
        assert_eq!(version(&receiver, &b_info).await, first.change.clock);
        assert_eq!(history(&receiver).await, first_history);
        assert_eq!(
            pending(&source).await.seq,
            second.seq,
            "failed receiver commit must not acknowledge source outbox"
        );
        sqlx::query("UPDATE lc_pitr_clock SET last_us=? WHERE singleton=1")
            .bind(first_history.1)
            .execute(&receiver.pool)
            .await
            .unwrap();
        receiver.pool.close().await;
        drop(b);
        drop(receiver);
        let (b, receiver) = open(&b_path, B).await;
        assert_eq!(history(&receiver).await, first_history);
        assert_eq!(
            b.pitr_describe(ACCOUNT, TABLE).await.unwrap()["ContinuousBackupsDescription"]
                ["PointInTimeRecoveryDescription"]["RecoveryPeriodInDays"],
            1
        );
        receiver.apply(&b, second.change.clone()).await.unwrap();
        source.acknowledge(second.seq, B).await.unwrap();
        assert_eq!(b.get_item(&b_info, &key()).await.unwrap(), Some(item("v2")));
        let second_history = history(&receiver).await;
        assert_eq!(second_history.0, 2);
        receiver.apply(&b, first.change.clone()).await.unwrap();
        assert_eq!(
            history(&receiver).await,
            second_history,
            "stale LWW delivery cannot append history"
        );

        put(&a, &a_info, "v2").await;
        let unchanged = pending(&source).await;
        receiver.apply(&b, unchanged.change.clone()).await.unwrap();
        source.acknowledge(unchanged.seq, B).await.unwrap();
        assert_eq!(version(&receiver, &b_info).await, unchanged.change.clock);
        assert_eq!(
            history(&receiver).await,
            second_history,
            "higher-version identical image is a PITR no-op"
        );

        a.delete_item(
            &a_info,
            &key(),
            false,
            None,
            &ExpressionMaps::default(),
            None,
        )
        .await
        .unwrap();
        let deleted = pending(&source).await;
        receiver.apply(&b, deleted.change.clone()).await.unwrap();
        source.acknowledge(deleted.seq, B).await.unwrap();
        assert_eq!(b.get_item(&b_info, &key()).await.unwrap(), None);
        assert_eq!(history(&receiver).await.0, 3);
        receiver.apply(&b, first.change).await.unwrap();
        assert_eq!(b.get_item(&b_info, &key()).await.unwrap(), None);
        assert_eq!(history(&receiver).await.0, 3);

        #[allow(clippy::cast_precision_loss)]
        let at = first_history.1 as f64 / 1_000_000.0;
        b.pitr_restore(ACCOUNT, TABLE, "regional-restored", Some(at))
            .await
            .unwrap();
        let restored = b
            .table_key_info(ACCOUNT, "regional-restored")
            .await
            .unwrap();
        assert_eq!(
            b.get_item(&restored, &key()).await.unwrap(),
            Some(item("v1"))
        );
        assert_eq!(
            b.pitr_describe(ACCOUNT, "regional-restored").await.unwrap()
                ["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]
                ["PointInTimeRecoveryStatus"],
            "DISABLED"
        );
        let global: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM lc_replication_topology WHERE table_name='regional-restored')").fetch_one(&receiver.pool).await.unwrap();
        assert!(!global);
        assert!(source.pending_for_target(B, 10).await.unwrap().is_empty());
        receiver.pool.close().await;
        source.pool.close().await;
        drop(b);
        drop(a);
    }
}
