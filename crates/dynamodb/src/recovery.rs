//! Durable PITR checkpoints and incremental item versions. History stays on disk.
use base64::Engine;
use locallycloud_state::StateCipher;
use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde_json::{json, Value};

use crate::error::DdbError;
use crate::store::{StoredKey, TableData};
use crate::value::Item;

pub(crate) const SEALED: &str = "dynamodb-sealed-v1:";

pub(crate) fn encode(
    cipher: Option<&StateCipher>,
    encrypted: bool,
    context: &[&str],
    value: &str,
) -> Result<String, DdbError> {
    if !encrypted {
        return Ok(value.into());
    }
    let cipher = cipher.ok_or_else(|| {
        DdbError::Validation(
            "DynamoDB SSE requires persistent state and LOCALLYCLOUD_KMS_MASTER_KEY".into(),
        )
    })?;
    let sealed = cipher.seal(context, value.as_bytes()).map_err(error)?;
    Ok(format!(
        "{SEALED}{}",
        base64::engine::general_purpose::STANDARD.encode(sealed)
    ))
}

pub(crate) fn decode(
    cipher: Option<&StateCipher>,
    context: &[&str],
    value: &str,
) -> Result<String, DdbError> {
    let Some(encoded) = value.strip_prefix(SEALED) else {
        return Ok(value.into());
    };
    let cipher = cipher.ok_or_else(|| {
        DdbError::Internal(
            "Encrypted DynamoDB state requires the original LOCALLYCLOUD_KMS_MASTER_KEY".into(),
        )
    })?;
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(error)?;
    let opened = cipher.open(context, &sealed).map_err(error)?;
    String::from_utf8(opened.to_vec()).map_err(error)
}

pub(crate) fn encode_item(
    cipher: Option<&StateCipher>,
    encrypted: bool,
    scope: &[&str; 3],
    key: &str,
    item: &Item,
) -> Result<String, DdbError> {
    encode(
        cipher,
        encrypted,
        &["dynamodb-item", scope[0], scope[1], scope[2], key],
        &serde_json::to_string(item).map_err(error)?,
    )
}

pub(crate) fn decode_item(
    cipher: Option<&StateCipher>,
    scope: &[&str; 3],
    key: &str,
    item: &str,
) -> Result<Item, DdbError> {
    serde_json::from_str(&decode(
        cipher,
        &["dynamodb-item", scope[0], scope[1], scope[2], key],
        item,
    )?)
    .map_err(error)
}

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS dynamodb_recovery (
 account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
 enabled INTEGER NOT NULL, started REAL NOT NULL, latest REAL NOT NULL, days INTEGER NOT NULL,
 PRIMARY KEY(account,region,name),
 FOREIGN KEY(account,region,name) REFERENCES dynamodb_tables(account,region,name) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS dynamodb_recovery_items (
 account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
 item_key TEXT NOT NULL, at REAL NOT NULL, item TEXT,
 PRIMARY KEY(account,region,name,item_key,at),
 FOREIGN KEY(account,region,name) REFERENCES dynamodb_recovery(account,region,name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS dynamodb_recovery_age ON dynamodb_recovery_items(at);";

/// Bound cleanup per commit, including histories of idle/deleted keys.
pub(crate) fn prune(tx: &Transaction<'_>) -> Result<(), DdbError> {
    let at = now();
    tx.execute("DELETE FROM dynamodb_recovery_items WHERE rowid IN (
        SELECT old.rowid FROM dynamodb_recovery_items AS old JOIN dynamodb_recovery AS window USING(account,region,name)
        WHERE old.at < ?1-86400 AND old.at < ?1-window.days*86400 AND EXISTS (
          SELECT 1 FROM dynamodb_recovery_items AS newer WHERE newer.account=old.account AND newer.region=old.region AND newer.name=old.name AND newer.item_key=old.item_key AND newer.at>old.at AND newer.at<=?1-window.days*86400)
        LIMIT 128)",params![at]).map_err(error)?;
    Ok(())
}

pub(crate) fn error(error: impl std::fmt::Display) -> DdbError {
    DdbError::Internal(format!("DynamoDB recovery persistence failed: {error}"))
}

pub(crate) fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs_f64())
        .unwrap_or_default()
}

#[derive(Clone, Copy)]
pub(crate) struct Window {
    enabled: bool,
    started: f64,
    latest: f64,
    days: u32,
}

fn window(
    db: &Connection,
    account: &str,
    region: &str,
    name: &str,
) -> Result<Option<Window>, DdbError> {
    db.query_row("SELECT enabled,started,latest,days FROM dynamodb_recovery WHERE account=?1 AND region=?2 AND name=?3",
        params![account,region,name], |row| Ok(Window {enabled:row.get(0)?,started:row.get(1)?,latest:row.get(2)?,days:row.get(3)?}))
        .optional().map_err(error)
}

fn bounds(window: Window) -> (f64, f64) {
    let latest = if window.enabled {
        now().max(window.latest)
    } else {
        window.latest
    };
    (
        window.started.max(now() - f64::from(window.days) * 86400.0),
        latest,
    )
}

pub(crate) fn describe(
    db: &Connection,
    account: &str,
    region: &str,
    name: &str,
) -> Result<Value, DdbError> {
    let mut description = json!({"PointInTimeRecoveryStatus":"DISABLED"});
    if let Some(window) = window(db, account, region, name)?.filter(|window| window.enabled) {
        let (earliest, latest) = bounds(window);
        description = json!({"PointInTimeRecoveryStatus":"ENABLED","RecoveryPeriodInDays":window.days,
            "EarliestRestorableDateTime":earliest,"LatestRestorableDateTime":latest});
    }
    Ok(
        json!({"ContinuousBackupsDescription":{"ContinuousBackupsStatus":"ENABLED","PointInTimeRecoveryDescription":description}}),
    )
}

pub(crate) fn configure(
    db: &mut Connection,
    account: &str,
    region: &str,
    name: &str,
    enabled: bool,
    days: Option<u32>,
) -> Result<Value, DdbError> {
    let tx = db.transaction().map_err(error)?;
    let old = window(&tx, account, region, name)?;
    let days = days.or(old.map(|window| window.days)).unwrap_or(35);
    let at = now();
    if enabled && !old.is_some_and(|window| window.enabled) {
        tx.execute(
            "DELETE FROM dynamodb_recovery WHERE account=?1 AND region=?2 AND name=?3",
            params![account, region, name],
        )
        .map_err(error)?;
        tx.execute(
            "INSERT INTO dynamodb_recovery VALUES(?1,?2,?3,1,?4,?4,?5)",
            params![account, region, name, at, days],
        )
        .map_err(error)?;
        tx.execute("INSERT INTO dynamodb_recovery_items SELECT account,region,name,item_key,?4,item FROM dynamodb_items WHERE account=?1 AND region=?2 AND name=?3",params![account,region,name,at]).map_err(error)?;
    } else {
        let cutoff =
            at - f64::from(days.min(old.map(|window| window.days).unwrap_or(days))) * 86400.0;
        tx.execute("UPDATE dynamodb_recovery SET enabled=?4,latest=?5,days=?6,started=MAX(started,?7) WHERE account=?1 AND region=?2 AND name=?3",params![account,region,name,enabled,at,days,cutoff]).map_err(error)?;
    }
    tx.commit().map_err(error)?;
    describe(db, account, region, name)
}

/// Run in the same transaction as the acknowledged item changes.
pub(crate) fn record(
    tx: &Transaction<'_>,
    account: &str,
    region: &str,
    table: &TableData,
    cipher: Option<&StateCipher>,
) -> Result<(), DdbError> {
    if table.dirty_keys.is_empty() {
        return Ok(());
    }
    let name = &table.def.name;
    let Some(window) = window(tx, account, region, name)?.filter(|window| window.enabled) else {
        return Ok(());
    };
    let at = now().max(window.latest + 0.000001);
    for key in &table.dirty_keys {
        let key_text = serde_json::to_string(key).map_err(error)?;
        let item = table
            .items
            .get(key)
            .map(|item| {
                encode_item(
                    cipher,
                    table.def.sse_type.is_some(),
                    &[account, region, name],
                    &key_text,
                    item,
                )
            })
            .transpose()
            .map_err(error)?;
        tx.execute(
            "INSERT INTO dynamodb_recovery_items VALUES(?1,?2,?3,?4,?5,?6)",
            params![account, region, name, key_text, at, item],
        )
        .map_err(error)?;
    }
    tx.execute(
        "UPDATE dynamodb_recovery SET latest=?4,started=MAX(started,?5) WHERE account=?1 AND region=?2 AND name=?3",
        params![account, region, name, at, at - f64::from(window.days) * 86400.0],
    )
    .map_err(error)?;
    Ok(())
}

pub(crate) fn restore(
    db: &Connection,
    account: &str,
    region: &str,
    name: &str,
    requested: Option<f64>,
    cipher: Option<&StateCipher>,
) -> Result<BTreeMap<StoredKey, Item>, DdbError> {
    let window = window(db, account, region, name)?.ok_or_else(|| {
        DdbError::RecoveryUnavailable("Point-in-time recovery is not enabled for this table".into())
    })?;
    let (earliest, latest) = bounds(window);
    let at = requested.unwrap_or(latest);
    if !at.is_finite() || at < earliest || at > latest {
        return Err(DdbError::InvalidRestoreTime(
            "RestoreDateTime is outside the restorable interval".into(),
        ));
    }
    let mut query = db.prepare("SELECT item_key,item FROM dynamodb_recovery_items AS current WHERE account=?1 AND region=?2 AND name=?3 AND at<=?4 AND item IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM dynamodb_recovery_items AS newer WHERE newer.account=current.account AND newer.region=current.region AND newer.name=current.name AND newer.item_key=current.item_key AND newer.at>current.at AND newer.at<=?4)").map_err(error)?;
    let mut rows = query
        .query(params![account, region, name, at])
        .map_err(error)?;
    let mut items = BTreeMap::new();
    while let Some(row) = rows.next().map_err(error)? {
        let key: String = row.get(0).map_err(error)?;
        let item: String = row.get(1).map_err(error)?;
        items.insert(
            serde_json::from_str(&key).map_err(error)?,
            decode_item(cipher, &[account, region, name], &key, &item)?,
        );
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retention_keeps_the_baseline_and_never_expands_a_pruned_window() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE dynamodb_tables(account TEXT,region TEXT,name TEXT,metadata TEXT,PRIMARY KEY(account,region,name));").unwrap();
        db.execute_batch(SCHEMA).unwrap();
        db.execute(
            "INSERT INTO dynamodb_tables VALUES('a','r','table','{}')",
            [],
        )
        .unwrap();
        let at = now();
        db.execute(
            "INSERT INTO dynamodb_recovery VALUES('a','r','table',1,?1,?2,1)",
            params![at - 4.0 * 86400.0, at],
        )
        .unwrap();
        for (age, value) in [(3.0, "old"), (2.0, "baseline"), (0.5, "current")] {
            db.execute(
                "INSERT INTO dynamodb_recovery_items VALUES('a','r','table','key',?1,?2)",
                params![at - age * 86400.0, value],
            )
            .unwrap();
        }
        let tx = db.transaction().unwrap();
        prune(&tx).unwrap();
        tx.commit().unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM dynamodb_recovery_items", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 2);
        configure(&mut db, "a", "r", "table", true, Some(35)).unwrap();
        let window = window(&db, "a", "r", "table").unwrap().unwrap();
        assert!(window.started >= at - 86400.0);
    }
}
