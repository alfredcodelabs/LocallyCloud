//! Incremental S3 metadata and notification outbox transactions in the shared SQLite state.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use locallycloud_state::StateDb;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};

use super::service::{StoredDelivery, MAX_PENDING_NOTIFICATIONS};
use crate::store::{
    AccountStore, BucketState, MultipartUpload, PublicAccessBlock, StoredObject, StoredPart,
    StoredVersion,
};
use base64::{engine::general_purpose::STANDARD, Engine};

pub(crate) struct StateRow {
    pub account: String,
    pub bucket: String,
    pub kind: String,
    pub key: String,
    pub subkey: String,
    pub payload: Option<Vec<u8>>,
}

#[derive(Clone)]
pub(super) struct S3Persistence {
    state: Arc<StateDb>,
    pub(super) blobs: PathBuf,
}

fn sql(error: rusqlite::Error) -> String {
    error.to_string()
}

fn file_references(value: &Value, paths: &mut BTreeSet<PathBuf>) {
    match value {
        Value::Object(map) => {
            if let Some(path) = map.get("File").and_then(Value::as_str) {
                paths.insert(PathBuf::from(path));
            }
            for value in map.values() {
                file_references(value, paths);
            }
        }
        Value::Array(items) => {
            for value in items {
                file_references(value, paths);
            }
        }
        _ => {}
    }
}

fn encoded(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| error.to_string())
}

fn snapshot_rows(payload: &[u8]) -> Result<(Vec<StateRow>, u64), String> {
    let snapshot: Value = serde_json::from_slice(payload).map_err(|error| error.to_string())?;
    let mut rows = Vec::new();
    let buckets = snapshot["buckets"]
        .as_array()
        .ok_or("invalid S3 snapshot buckets")?;
    for entry in buckets {
        let account = entry[0].as_str().ok_or("invalid S3 snapshot account")?;
        let bucket = entry[1].as_str().ok_or("invalid S3 snapshot bucket")?;
        let mut metadata = entry[2]
            .as_object()
            .ok_or("invalid S3 bucket metadata")?
            .clone();
        for kind in ["objects", "versions", "uploads"] {
            let entries = metadata.remove(kind).unwrap_or_else(|| json!({}));
            for (key, value) in entries
                .as_object()
                .ok_or("invalid S3 snapshot collection")?
            {
                let mut value = value.clone();
                if kind == "uploads" {
                    let parts = value
                        .as_object_mut()
                        .ok_or("invalid S3 upload")?
                        .remove("parts")
                        .unwrap_or_else(|| json!({}));
                    for (number, part) in parts.as_object().ok_or("invalid S3 upload parts")? {
                        rows.push(StateRow {
                            account: account.into(),
                            bucket: bucket.into(),
                            kind: "part".into(),
                            key: key.clone(),
                            subkey: number.clone(),
                            payload: Some(encoded(part)?),
                        });
                    }
                }
                rows.push(StateRow {
                    account: account.into(),
                    bucket: bucket.into(),
                    kind: match kind {
                        "objects" => "object",
                        "versions" => "versions",
                        _ => "upload",
                    }
                    .into(),
                    key: key.clone(),
                    subkey: String::new(),
                    payload: Some(encoded(&value)?),
                });
            }
        }
        rows.push(StateRow {
            account: account.into(),
            bucket: bucket.into(),
            kind: "bucket".into(),
            key: String::new(),
            subkey: String::new(),
            payload: Some(encoded(&Value::Object(metadata))?),
        });
    }
    for entry in snapshot["account_public_access_blocks"]
        .as_array()
        .ok_or("invalid S3 account configuration")?
    {
        let account = entry[0]
            .as_str()
            .ok_or("invalid S3 account configuration")?;
        rows.push(StateRow {
            account: account.into(),
            bucket: String::new(),
            kind: "account".into(),
            key: account.into(),
            subkey: String::new(),
            payload: Some(encoded(&entry[1])?),
        });
    }
    Ok((
        rows,
        snapshot["next_id"]
            .as_u64()
            .ok_or("invalid S3 snapshot next id")?,
    ))
}

fn compact_inline_bytes(value: &mut Value) -> Result<(), String> {
    match value {
        Value::Object(fields) => {
            if let Some(Value::Array(bytes)) = fields.get("Inline") {
                let bytes = bytes
                    .iter()
                    .map(|byte| {
                        byte.as_u64()
                            .and_then(|byte| u8::try_from(byte).ok())
                            .ok_or("invalid S3 inline byte")
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                fields.insert("Inline".into(), Value::String(STANDARD.encode(bytes)));
            }
            for value in fields.values_mut() {
                compact_inline_bytes(value)?;
            }
        }
        Value::Array(items) => {
            for value in items {
                compact_inline_bytes(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn canonical_null_version(
    transaction: &Transaction<'_>,
    account: &str,
    bucket: &str,
    key: &str,
    value: &Value,
) -> Result<bool, String> {
    let Some(chain) = value
        .as_array()
        .filter(|chain| chain.len() == 1 && chain[0]["id"] == "null")
    else {
        return Ok(false);
    };
    let metadata: Option<Vec<u8>> = transaction.query_row("SELECT payload FROM s3_entries WHERE account=?1 AND bucket=?2 AND kind='bucket' AND key=''", params![account,bucket], |row| row.get(0)).optional().map_err(sql)?;
    let Some(metadata) = metadata else {
        return Err("S3 version has no bucket".into());
    };
    let metadata: Value = serde_json::from_slice(&metadata).map_err(|error| error.to_string())?;
    if metadata["versioning"] != "NeverEnabled" {
        return Ok(false);
    }
    let object: Option<Vec<u8>> = transaction.query_row("SELECT payload FROM s3_entries WHERE account=?1 AND bucket=?2 AND kind='object' AND key=?3", params![account,bucket,key], |row| row.get(0)).optional().map_err(sql)?;
    let Some(object) = object else {
        return Ok(false);
    };
    let object: Value = serde_json::from_slice(&object).map_err(|error| error.to_string())?;
    Ok(chain[0]["value"]["Object"] == object
        && chain[0]["last_modified"] == object["last_modified"])
}

impl S3Persistence {
    pub(super) fn new(state: Arc<StateDb>) -> Result<Self, String> {
        let blobs = state.path().with_extension("s3-blobs");
        let new_blobs = !blobs.exists();
        std::fs::create_dir_all(&blobs).map_err(|error| error.to_string())?;
        if new_blobs {
            std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let metadata = std::fs::symlink_metadata(&blobs).map_err(|error| error.to_string())?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("S3 blob directory must be private and not a symlink".into());
        }
        let mut connection = state.connection().map_err(|error| error.to_string())?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        transaction.execute_batch("CREATE TABLE IF NOT EXISTS s3_state (id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS s3_notification_outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, payload BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS s3_metadata (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, next_id TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS s3_entries (account TEXT NOT NULL, bucket TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL, subkey TEXT NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(account,bucket,kind,key,subkey)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS s3_blob_refs (account TEXT NOT NULL, bucket TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL, subkey TEXT NOT NULL, path TEXT NOT NULL, PRIMARY KEY(account,bucket,kind,key,subkey,path)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS s3_blob_refs_path ON s3_blob_refs(path);").map_err(sql)?;
        let version: Option<i64> = transaction
            .query_row("SELECT version FROM s3_metadata WHERE id=1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(sql)?;
        match version {
            Some(2 | 3) => {}
            Some(_) => return Err("unsupported S3 persistent metadata version".into()),
            None => {
                let legacy: Option<Vec<u8>> = transaction
                    .query_row("SELECT payload FROM s3_state WHERE id=1", [], |row| {
                        row.get(0)
                    })
                    .optional()
                    .map_err(sql)?;
                let (rows, next_id) = match legacy {
                    Some(payload) => snapshot_rows(&payload)?,
                    None => (Vec::new(), 1),
                };
                for row in &rows {
                    Self::apply_row(&transaction, row, &mut BTreeSet::new())?;
                }
                transaction
                    .execute(
                        "INSERT INTO s3_metadata(id,version,next_id) VALUES(1,2,?1)",
                        [next_id.to_string()],
                    )
                    .map_err(sql)?;
                // Old binaries must fail loading, rather than overwrite newer incremental state.
                transaction.execute("INSERT INTO s3_state(id,payload) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", [b"{\"s3_incremental_schema\":2}".as_slice()]).map_err(sql)?;
            }
        }
        if version != Some(3) {
            // Rewrite one bounded row at a time, keeping migration and blob references atomic.
            let mut statement = transaction.prepare("SELECT account,bucket,kind,key,subkey,payload FROM s3_entries ORDER BY account,bucket,kind,key,subkey").map_err(sql)?;
            let mut rows = statement.query([]).map_err(sql)?;
            while let Some(row) = rows.next().map_err(sql)? {
                let account: String = row.get(0).map_err(sql)?;
                let bucket: String = row.get(1).map_err(sql)?;
                let kind: String = row.get(2).map_err(sql)?;
                let key: String = row.get(3).map_err(sql)?;
                let subkey: String = row.get(4).map_err(sql)?;
                let payload: Vec<u8> = row.get(5).map_err(sql)?;
                let mut value: Value =
                    serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
                compact_inline_bytes(&mut value)?;
                let payload = encoded(&value)?;
                transaction.execute("UPDATE s3_entries SET payload=?6 WHERE account=?1 AND bucket=?2 AND kind=?3 AND key=?4 AND subkey=?5", params![account,bucket,kind,key,subkey,payload]).map_err(sql)?;
                if kind == "versions"
                    && canonical_null_version(&transaction, &account, &bucket, &key, &value)?
                {
                    transaction.execute("DELETE FROM s3_entries WHERE account=?1 AND bucket=?2 AND kind='versions' AND key=?3", params![account,bucket,key]).map_err(sql)?;
                    transaction.execute("DELETE FROM s3_blob_refs WHERE account=?1 AND bucket=?2 AND kind='versions' AND key=?3", params![account,bucket,key]).map_err(sql)?;
                }
            }
            drop(rows);
            drop(statement);
            transaction
                .execute("UPDATE s3_metadata SET version=3 WHERE id=1", [])
                .map_err(sql)?;
            transaction
                .execute(
                    "UPDATE s3_state SET payload=?1 WHERE id=1",
                    [b"{\"s3_incremental_schema\":3}".as_slice()],
                )
                .map_err(sql)?;
        }
        transaction.commit().map_err(sql)?;
        Ok(Self { state, blobs })
    }

    pub(super) fn restore(&self, store: &AccountStore) -> Result<(), String> {
        let connection = self.state.connection().map_err(|error| error.to_string())?;
        let mut buckets: BTreeMap<(String, String), BucketState> = BTreeMap::new();
        let mut blocks: Vec<(String, PublicAccessBlock)> = Vec::new();
        // Bucket/upload metadata precede their children; no aggregate JSON tree or body copies.
        let mut statement = connection.prepare("SELECT account,bucket,kind,key,subkey,payload FROM s3_entries ORDER BY CASE kind WHEN 'bucket' THEN 0 WHEN 'upload' THEN 1 ELSE 2 END,account,bucket,kind,key,subkey").map_err(sql)?;
        let mut rows = statement.query([]).map_err(sql)?;
        while let Some(row) = rows.next().map_err(sql)? {
            let account: String = row.get(0).map_err(sql)?;
            let name: String = row.get(1).map_err(sql)?;
            let kind: String = row.get(2).map_err(sql)?;
            let key: String = row.get(3).map_err(sql)?;
            let subkey: String = row.get(4).map_err(sql)?;
            let payload: Vec<u8> = row.get(5).map_err(sql)?;
            let decode = |error: serde_json::Error| error.to_string();
            match kind.as_str() {
                "bucket" => {
                    let bucket: BucketState = serde_json::from_slice(&payload).map_err(decode)?;
                    if bucket.name != name || buckets.keys().any(|(_, existing)| existing == &name)
                    {
                        return Err("invalid or duplicated S3 bucket identity".into());
                    }
                    buckets.insert((account, name), bucket);
                }
                "account" => {
                    blocks.push((account, serde_json::from_slice(&payload).map_err(decode)?))
                }
                _ => {
                    let bucket = buckets
                        .get_mut(&(account, name))
                        .ok_or("S3 metadata entity has no bucket")?;
                    match kind.as_str() {
                        "object" => {
                            let object: StoredObject =
                                serde_json::from_slice(&payload).map_err(decode)?;
                            bucket.objects.insert(key, object);
                        }
                        "versions" => {
                            let versions: Vec<StoredVersion> =
                                serde_json::from_slice(&payload).map_err(decode)?;
                            bucket.versions.insert(key, versions);
                        }
                        "upload" => {
                            let upload: MultipartUpload =
                                serde_json::from_slice(&payload).map_err(decode)?;
                            if upload.id != key {
                                return Err("invalid S3 upload identity".into());
                            }
                            bucket.uploads.insert(key, upload);
                        }
                        "part" => {
                            let number: u16 =
                                subkey.parse().map_err(|_| "invalid S3 part number")?;
                            let part: StoredPart =
                                serde_json::from_slice(&payload).map_err(decode)?;
                            bucket
                                .uploads
                                .untracked_mut(&key)
                                .ok_or("S3 part has no multipart upload")?
                                .parts
                                .insert(number, part);
                        }
                        _ => return Err("invalid S3 metadata entity kind".into()),
                    }
                }
            }
        }
        let next: String = connection
            .query_row("SELECT next_id FROM s3_metadata WHERE id=1", [], |row| {
                row.get(0)
            })
            .map_err(sql)?;
        let next_id = next.parse::<u64>().map_err(|error| error.to_string())?;
        store.restore_entries(buckets, blocks, next_id);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn load(&self) -> Result<Option<Vec<u8>>, String> {
        let connection = self.state.connection().map_err(|error| error.to_string())?;
        let mut statement = connection.prepare("SELECT account,bucket,kind,key,subkey,payload FROM s3_entries ORDER BY account,bucket,kind,key,subkey").map_err(sql)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })
            .map_err(sql)?;
        let mut entries = Vec::new();
        for row in rows {
            let (account, bucket, kind, key, subkey, payload) = row.map_err(sql)?;
            let value: Value =
                serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
            entries.push((account, bucket, kind, key, subkey, value));
        }
        let mut buckets: BTreeMap<(String, String), Value> = BTreeMap::new();
        let mut blocks = Vec::new();
        for (account, bucket, kind, _, _, value) in &entries {
            if kind == "bucket" {
                let mut metadata = value
                    .as_object()
                    .ok_or("invalid S3 bucket metadata")?
                    .clone();
                for name in ["objects", "versions", "uploads"] {
                    metadata.insert(name.into(), json!({}));
                }
                buckets.insert((account.clone(), bucket.clone()), Value::Object(metadata));
            } else if kind == "account" {
                blocks.push(json!([account, value]));
            }
        }
        for (account, bucket, kind, key, _, value) in &entries {
            let collection = match kind.as_str() {
                "object" => "objects",
                "versions" => "versions",
                "upload" => "uploads",
                "bucket" | "account" | "part" => continue,
                _ => return Err("invalid S3 metadata entity kind".into()),
            };
            let metadata = buckets
                .get_mut(&(account.clone(), bucket.clone()))
                .ok_or("S3 metadata entity has no bucket")?;
            let mut value = value.clone();
            if kind == "upload" {
                value
                    .as_object_mut()
                    .ok_or("invalid S3 upload metadata")?
                    .insert("parts".into(), json!({}));
            }
            metadata[collection]
                .as_object_mut()
                .ok_or("invalid S3 metadata collection")?
                .insert(key.clone(), value);
        }
        for (account, bucket, kind, key, subkey, value) in &entries {
            if kind != "part" {
                continue;
            }
            let metadata = buckets
                .get_mut(&(account.clone(), bucket.clone()))
                .ok_or("S3 upload part has no bucket")?;
            metadata["uploads"][key]["parts"]
                .as_object_mut()
                .ok_or("S3 part has no multipart upload")?
                .insert(subkey.clone(), value.clone());
        }
        let next: String = connection
            .query_row("SELECT next_id FROM s3_metadata WHERE id=1", [], |row| {
                row.get(0)
            })
            .map_err(sql)?;
        let next_id = next.parse::<u64>().map_err(|error| error.to_string())?;
        let buckets: Vec<_> = buckets
            .into_iter()
            .map(|((account, bucket), metadata)| json!([account, bucket, metadata]))
            .collect();
        encoded(&json!({"buckets":buckets,"account_public_access_blocks":blocks,"next_id":next_id}))
            .map(Some)
    }

    fn apply_row(
        transaction: &Transaction<'_>,
        row: &StateRow,
        candidates: &mut BTreeSet<PathBuf>,
    ) -> Result<(), String> {
        let (filter, args): (&str, Vec<&str>) = if row.payload.is_none() && row.kind == "bucket" {
            ("account=?1 AND bucket=?2", vec![&row.account, &row.bucket])
        } else if row.payload.is_none() && row.kind == "upload" {
            (
                "account=?1 AND bucket=?2 AND kind IN ('upload','part') AND key=?3",
                vec![&row.account, &row.bucket, &row.key],
            )
        } else {
            (
                "account=?1 AND bucket=?2 AND kind=?3 AND key=?4 AND subkey=?5",
                vec![&row.account, &row.bucket, &row.kind, &row.key, &row.subkey],
            )
        };
        let mut statement = transaction
            .prepare(&format!("SELECT path FROM s3_blob_refs WHERE {filter}"))
            .map_err(sql)?;
        for path in statement
            .query_map(rusqlite::params_from_iter(args.iter()), |row| {
                row.get::<_, String>(0)
            })
            .map_err(sql)?
        {
            candidates.insert(PathBuf::from(path.map_err(sql)?));
        }
        drop(statement);
        transaction
            .execute(
                &format!("DELETE FROM s3_blob_refs WHERE {filter}"),
                rusqlite::params_from_iter(args.iter()),
            )
            .map_err(sql)?;
        if let Some(payload) = &row.payload {
            let value: Value =
                serde_json::from_slice(payload).map_err(|error| error.to_string())?;
            let mut paths = BTreeSet::new();
            file_references(&value, &mut paths);
            transaction.execute("INSERT INTO s3_entries(account,bucket,kind,key,subkey,payload) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(account,bucket,kind,key,subkey) DO UPDATE SET payload=excluded.payload", params![row.account,row.bucket,row.kind,row.key,row.subkey,payload]).map_err(sql)?;
            for path in paths {
                let path = path.to_str().ok_or("invalid S3 blob reference path")?;
                transaction.execute("INSERT INTO s3_blob_refs(account,bucket,kind,key,subkey,path) VALUES(?1,?2,?3,?4,?5,?6)", params![row.account,row.bucket,row.kind,row.key,row.subkey,path]).map_err(sql)?;
            }
        } else {
            transaction
                .execute(
                    &format!("DELETE FROM s3_entries WHERE {filter}"),
                    rusqlite::params_from_iter(args.iter()),
                )
                .map_err(sql)?;
        }
        Ok(())
    }

    fn append_notifications(
        transaction: &Transaction<'_>,
        notifications: &[StoredDelivery],
    ) -> Result<(), String> {
        if notifications.is_empty() {
            return Ok(());
        }
        let pending: i64 = transaction
            .query_row("SELECT count(*) FROM s3_notification_outbox", [], |row| {
                row.get(0)
            })
            .map_err(sql)?;
        if pending.saturating_add(notifications.len() as i64) > MAX_PENDING_NOTIFICATIONS {
            return Err("S3 notification outbox is full".into());
        }
        for notification in notifications {
            let payload = serde_json::to_vec(notification).map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO s3_notification_outbox(payload) VALUES(?1)",
                    [payload],
                )
                .map_err(sql)?;
        }
        Ok(())
    }

    pub(super) fn save_delta(
        &self,
        rows: &[StateRow],
        notifications: &[StoredDelivery],
        next_id: u64,
    ) -> Result<(), String> {
        let mut connection = self.state.connection().map_err(|error| error.to_string())?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let mut candidates = BTreeSet::new();
        for row in rows {
            Self::apply_row(&transaction, row, &mut candidates)?;
        }
        transaction
            .execute(
                "UPDATE s3_metadata SET next_id=?1 WHERE id=1",
                [next_id.to_string()],
            )
            .map_err(sql)?;
        Self::append_notifications(&transaction, notifications)?;
        transaction.commit().map_err(sql)?;
        if let Err(error) = self.remove_candidates(&candidates) {
            tracing::warn!(%error,"S3 obsolete blob cleanup deferred until startup");
        }
        Ok(())
    }

    // Compatibility path for explicit administrative full snapshots; normal writes use save_delta.
    #[cfg(test)]
    pub(super) fn save(
        &self,
        payload: &[u8],
        notifications: &[StoredDelivery],
    ) -> Result<(), String> {
        let (rows, next_id) = snapshot_rows(payload)?;
        let mut connection = self.state.connection().map_err(|error| error.to_string())?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let mut candidates = BTreeSet::new();
        {
            let mut statement = transaction
                .prepare("SELECT DISTINCT path FROM s3_blob_refs")
                .map_err(sql)?;
            for path in statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(sql)?
            {
                candidates.insert(PathBuf::from(path.map_err(sql)?));
            }
        }
        transaction
            .execute("DELETE FROM s3_blob_refs", [])
            .map_err(sql)?;
        transaction
            .execute("DELETE FROM s3_entries", [])
            .map_err(sql)?;
        for row in &rows {
            Self::apply_row(&transaction, row, &mut candidates)?;
        }
        transaction
            .execute(
                "UPDATE s3_metadata SET next_id=?1 WHERE id=1",
                [next_id.to_string()],
            )
            .map_err(sql)?;
        Self::append_notifications(&transaction, notifications)?;
        transaction.commit().map_err(sql)?;
        if let Err(error) = self.remove_candidates(&candidates) {
            tracing::warn!(%error,"S3 obsolete blob cleanup deferred until startup");
        }
        Ok(())
    }

    fn remove_candidates(&self, candidates: &BTreeSet<PathBuf>) -> Result<(), String> {
        if candidates.is_empty() {
            return Ok(());
        }
        let mut connection = self.state.connection().map_err(|error| error.to_string())?;
        // Hold the SQLite writer lock while checking references and unlinking, so an added
        // reference cannot race between the last-reference check and file removal.
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        for path in candidates {
            if path.parent() != Some(self.blobs.as_path()) {
                return Err("S3 blob reference escapes private blob directory".into());
            }
            let referenced: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM s3_blob_refs WHERE path=?1)",
                    [path.to_str().ok_or("invalid S3 blob path")?],
                    |row| row.get(0),
                )
                .map_err(sql)?;
            if !referenced {
                match std::fs::remove_file(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
        transaction.commit().map_err(sql)
    }

    pub(super) fn remove_orphan_blobs(&self) -> Result<(), String> {
        let candidates = std::fs::read_dir(&self.blobs)
            .map_err(|error| error.to_string())?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        self.remove_candidates(&candidates)
    }
    pub(super) fn has_capacity(&self, required: i64) -> Result<bool, String> {
        if required <= 0 {
            return Ok(true);
        }
        let pending: i64 = self
            .state
            .connection()
            .map_err(|error| error.to_string())?
            .query_row("SELECT count(*) FROM s3_notification_outbox", [], |row| {
                row.get(0)
            })
            .map_err(|error| error.to_string())?;
        Ok(pending.saturating_add(required) <= MAX_PENDING_NOTIFICATIONS)
    }

    pub(super) fn has_pending(&self) -> Result<bool, String> {
        let exists: i64 = self
            .state
            .connection()
            .map_err(|error| error.to_string())?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM s3_notification_outbox)",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        Ok(exists != 0)
    }

    pub(super) fn max_outbox_id(&self) -> Result<i64, String> {
        self.state
            .connection()
            .map_err(|error| error.to_string())?
            .query_row(
                "SELECT coalesce(max(id), 0) FROM s3_notification_outbox",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())
    }

    pub(super) fn load_outbox(
        &self,
        after: i64,
        through: i64,
    ) -> Result<Vec<(i64, StoredDelivery)>, String> {
        let connection = self.state.connection().map_err(|error| error.to_string())?;
        let mut statement = connection
            .prepare(
                "SELECT id,payload FROM s3_notification_outbox WHERE id>?1 AND id<=?2 ORDER BY id LIMIT 64",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![after, through], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|error| error.to_string())?;
        let mut pending = Vec::new();
        for row in rows {
            let (id, payload) = row.map_err(|error| error.to_string())?;
            pending.push((
                id,
                serde_json::from_slice(&payload).map_err(|error| error.to_string())?,
            ));
        }
        Ok(pending)
    }

    pub(super) fn delete_outbox(&self, id: i64) -> Result<(), String> {
        self.state
            .connection()
            .map_err(|error| error.to_string())?
            .execute("DELETE FROM s3_notification_outbox WHERE id=?1", [id])
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (PathBuf, Arc<StateDb>) {
        let root = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        (root, db)
    }

    fn row(kind: &str, key: &str, payload: Option<Value>) -> StateRow {
        StateRow {
            account: "000000000000".into(),
            bucket: "bucket".into(),
            kind: kind.into(),
            key: key.into(),
            subkey: String::new(),
            payload: payload.map(|value| encoded(&value).unwrap()),
        }
    }

    #[test]
    fn incremental_rows_preserve_shared_blobs_and_cascade_upload_and_bucket() {
        let (root, db) = fixture();
        let persistence = S3Persistence::new(db.clone()).unwrap();
        let shared = persistence.blobs.join("shared");
        std::fs::write(&shared, b"shared ciphertext").unwrap();
        let held_reader = std::fs::File::open(&shared).unwrap();
        persistence
            .save_delta(
                &[
                    row("bucket", "", Some(json!({"region":"us-east-1"}))),
                    row("object", "original", Some(json!({"body":{"File":shared}}))),
                    row("object", "copy", Some(json!({"body":{"File":shared}}))),
                    row("upload", "u", Some(json!({"key":"multipart"}))),
                    StateRow {
                        subkey: "1".into(),
                        ..row("part", "u", Some(json!({"body":{"File":shared}})))
                    },
                ],
                &[],
                7,
            )
            .unwrap();
        persistence
            .save_delta(&[row("object", "original", None)], &[], 8)
            .unwrap();
        assert!(shared.exists());
        let loaded: Value = serde_json::from_slice(&persistence.load().unwrap().unwrap()).unwrap();
        assert!(loaded["buckets"][0][2]["objects"].get("original").is_none());
        assert!(loaded["buckets"][0][2]["objects"].get("copy").is_some());
        assert!(loaded["buckets"][0][2]["uploads"]["u"]["parts"]
            .get("1")
            .is_some());
        persistence
            .save_delta(&[row("upload", "u", None)], &[], 9)
            .unwrap();
        assert!(shared.exists());
        let loaded: Value = serde_json::from_slice(&persistence.load().unwrap().unwrap()).unwrap();
        assert!(loaded["buckets"][0][2]["uploads"]
            .as_object()
            .unwrap()
            .is_empty());
        persistence
            .save_delta(&[row("bucket", "", None)], &[], 10)
            .unwrap();
        assert!(!shared.exists());
        assert_eq!(held_reader.metadata().unwrap().len(), 17);
        let loaded: Value = serde_json::from_slice(&persistence.load().unwrap().unwrap()).unwrap();
        assert_eq!(loaded["next_id"], 10);
        assert!(loaded["buckets"].as_array().unwrap().is_empty());
        drop(held_reader);
        drop(persistence);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_migration_is_atomic_and_normalizes_multipart_parts() {
        let (root, db) = fixture();
        let mut snapshot = json!({"buckets":[["000000000000","bucket",{
            "region":"us-west-2", "objects":{"k":{"body":{"Inline":[1,2]}}},
            "versions":{"k":[{"version_id":"v"}]},
            "uploads":{"u":{"key":"k", "parts":{"1":{"etag":"e"}}}}
        }]],"account_public_access_blocks":[["000000000000",{"block_public_acls":true}]],"next_id":42});
        let conn = db.connection().unwrap();
        conn.execute_batch("CREATE TABLE s3_state(id INTEGER PRIMARY KEY,payload BLOB NOT NULL); CREATE TABLE s3_notification_outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,payload BLOB NOT NULL)").unwrap();
        conn.execute(
            "INSERT INTO s3_state VALUES(1,?1)",
            [encoded(&snapshot).unwrap()],
        )
        .unwrap();
        let persistence = S3Persistence::new(db.clone()).unwrap();
        compact_inline_bytes(&mut snapshot).unwrap();
        let loaded: Value = serde_json::from_slice(&persistence.load().unwrap().unwrap()).unwrap();
        assert_eq!(loaded, snapshot);
        let legacy: Vec<u8> = conn
            .query_row("SELECT payload FROM s3_state", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&legacy).unwrap()["s3_incremental_schema"],
            3
        );
        let entries: i64 = conn
            .query_row("SELECT count(*) FROM s3_entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(entries, 6);
        drop(persistence);
        let reopened = S3Persistence::new(db.clone()).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&reopened.load().unwrap().unwrap()).unwrap(),
            snapshot
        );
        drop(reopened);
        drop(conn);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();

        let (root, db) = fixture();
        let conn = db.connection().unwrap();
        conn.execute_batch("CREATE TABLE s3_state(id INTEGER PRIMARY KEY,payload BLOB NOT NULL)")
            .unwrap();
        let invalid = b"{\"buckets\":[],\"next_id\":42}";
        conn.execute("INSERT INTO s3_state VALUES(1,?1)", [invalid.as_slice()])
            .unwrap();
        assert!(S3Persistence::new(db.clone()).is_err());
        let unchanged: Vec<u8> = conn
            .query_row("SELECT payload FROM s3_state", [], |row| row.get(0))
            .unwrap();
        assert_eq!(unchanged, invalid);
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='s3_metadata'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
        drop(conn);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn outbox_failure_rolls_back_metadata_counter_and_blob_references() {
        let (root, db) = fixture();
        let persistence = S3Persistence::new(db.clone()).unwrap();
        persistence
            .save_delta(
                &[row("bucket", "", Some(json!({"region":"us-east-1"})))],
                &[],
                1,
            )
            .unwrap();
        let conn = db.connection().unwrap();
        conn.execute_batch("CREATE TRIGGER reject_s3_outbox BEFORE INSERT ON s3_notification_outbox BEGIN SELECT RAISE(ABORT,'injected outbox failure'); END").unwrap();
        let notification:StoredDelivery = serde_json::from_value(json!({"request_id":"r","account_id":"000000000000","region":"us-east-1","target":"Queue","arn":null,"method":"POST","uri":"/","headers":[],"body":[]})).unwrap();
        let blob = persistence.blobs.join("uncommitted");
        std::fs::write(&blob, b"uncommitted").unwrap();
        assert!(persistence
            .save_delta(
                &[row("object", "k", Some(json!({"body":{"File":blob}})))],
                &[notification],
                2
            )
            .is_err());
        assert!(blob.exists());
        let loaded: Value = serde_json::from_slice(&persistence.load().unwrap().unwrap()).unwrap();
        assert_eq!(loaded["next_id"], 1);
        assert!(loaded["buckets"][0][2]["objects"]
            .as_object()
            .unwrap()
            .is_empty());
        assert!(!persistence.has_pending().unwrap());
        let refs: i64 = conn
            .query_row("SELECT count(*) FROM s3_blob_refs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(refs, 0);
        drop(conn);
        drop(persistence);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }
}
