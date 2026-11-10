//! Validate native PITR history before any migration inspection callback runs.
use std::collections::BTreeSet;

use locallycloud_state::StateCipher;
use rusqlite::{params, Connection};

use super::{invalid, MAX_RECORD};
use crate::error::DdbError;
use crate::store::StoredKey;

pub(super) fn validate(
    connection: &Connection,
    cipher: &StateCipher,
    schema: &BTreeSet<String>,
) -> Result<u64, DdbError> {
    let has_windows = schema.contains("dynamodb_recovery");
    let has_versions = schema.contains("dynamodb_recovery_items");
    if has_versions {
        let query = if has_windows {
            "SELECT EXISTS(SELECT 1 FROM dynamodb_recovery_items v WHERE NOT EXISTS(SELECT 1 FROM dynamodb_recovery w WHERE w.account=v.account AND w.region=v.region AND w.name=v.name))"
        } else {
            "SELECT EXISTS(SELECT 1 FROM dynamodb_recovery_items)"
        };
        if connection
            .query_row(query, [], |row| row.get::<_, bool>(0))
            .map_err(|_| invalid())?
        {
            return Err(invalid());
        }
    }
    if !has_windows {
        return Ok(0);
    }
    // Length limits apply in SQLite, before materializing source-controlled fields.
    let mut windows = connection.prepare(
        "SELECT substr(w.account,1,13),substr(w.region,1,65),substr(w.name,1,256),w.enabled,w.started,w.latest,w.days,CASE WHEN length(CAST(t.metadata AS BLOB))<=?1 THEN t.metadata END FROM dynamodb_recovery w JOIN dynamodb_tables t USING(account,region,name) ORDER BY w.account,w.region,w.name",
    ).map_err(|_| invalid())?;
    let mut windows = windows.query([MAX_RECORD]).map_err(|_| invalid())?;
    let mut encrypted = 0u64;
    while let Some(row) = windows.next().map_err(|_| invalid())? {
        let account: String = row.get(0).map_err(|_| invalid())?;
        let region: String = row.get(1).map_err(|_| invalid())?;
        let name: String = row.get(2).map_err(|_| invalid())?;
        let enabled: i64 = row.get(3).map_err(|_| invalid())?;
        let started: f64 = row.get(4).map_err(|_| invalid())?;
        let latest: f64 = row.get(5).map_err(|_| invalid())?;
        let days: i64 = row.get(6).map_err(|_| invalid())?;
        let encoded: String = row.get(7).map_err(|_| invalid())?;
        let (data, _) = crate::store::migration_table(cipher, &account, &region, &name, &encoded)?;
        if !matches!(enabled, 0 | 1)
            || (enabled == 1) != data.pitr_enabled
            || !started.is_finite()
            || !latest.is_finite()
            || started < 0.0
            || latest < started
            || !(1..=35).contains(&days)
        {
            return Err(invalid());
        }
        if !has_versions {
            continue;
        }
        let mut versions = connection.prepare(
            "SELECT CASE WHEN length(CAST(item_key AS BLOB))<=?4 THEN item_key END,at,item IS NULL,CASE WHEN length(CAST(item AS BLOB))<=?4 THEN item END FROM dynamodb_recovery_items WHERE account=?1 AND region=?2 AND name=?3 ORDER BY item_key,at",
        ).map_err(|_| invalid())?;
        let mut versions = versions
            .query(params![account, region, name, MAX_RECORD])
            .map_err(|_| invalid())?;
        while let Some(row) = versions.next().map_err(|_| invalid())? {
            let key: String = row.get(0).map_err(|_| invalid())?;
            let at: f64 = row.get(1).map_err(|_| invalid())?;
            let tombstone: bool = row.get(2).map_err(|_| invalid())?;
            let encoded: Option<String> = row.get(3).map_err(|_| invalid())?;
            let saved: StoredKey = serde_json::from_str(&key).map_err(|_| invalid())?;
            // Retention keeps the last baseline before started; it must not be discarded.
            if !at.is_finite()
                || at < 0.0
                || at > latest
                || saved.sort.is_some() != data.def.range_key().is_some()
            {
                return Err(invalid());
            }
            match (tombstone, encoded) {
                (true, None) => {}
                (false, Some(encoded)) => {
                    let item = crate::recovery::decode_item(
                        Some(cipher),
                        &[&account, &region, &name],
                        &key,
                        &encoded,
                    )
                    .map_err(|_| invalid())?;
                    if data.key_of(&item).map_err(|_| invalid())? != saved {
                        return Err(invalid());
                    }
                    if encoded.starts_with(crate::recovery::SEALED) {
                        encrypted = encrypted.checked_add(1).ok_or_else(invalid)?;
                    }
                }
                _ => return Err(invalid()),
            }
        }
    }
    Ok(encrypted)
}
