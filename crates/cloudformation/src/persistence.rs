//! Incremental encrypted ownership records; external provisioning is not crash-atomic.
use std::sync::Mutex;

use locallycloud_state::{StateCipher, StateDb};
use rusqlite::{params, Connection};
use serde::Serialize;

use crate::error::CfnError;

pub(crate) struct Persistence {
    connection: Mutex<Connection>,
    cipher: StateCipher,
}

pub(crate) const RETENTION_SECONDS: i64 = 90 * 24 * 60 * 60;
pub(crate) fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

impl Persistence {
    pub(crate) fn new(db: &StateDb, cipher: StateCipher) -> Result<Self, CfnError> {
        let connection = db.connection().map_err(|_| CfnError::Internal)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS cfn_metadata_v1 (
                kind TEXT NOT NULL CHECK(kind IN ('stack','change','deleted')),
                scope_key TEXT NOT NULL, payload BLOB NOT NULL,
                deleted_at INTEGER, PRIMARY KEY(kind,scope_key)
            );",
            )
            .map_err(|_| CfnError::Internal)?;
        Ok(Self {
            connection: Mutex::new(connection),
            cipher,
        })
    }

    pub(crate) fn load(
        &self,
        mut restore: impl FnMut(&str, String, Option<i64>, &[u8]) -> Result<(), CfnError>,
    ) -> Result<(), CfnError> {
        let connection = self.connection.lock().map_err(|_| CfnError::Internal)?;
        let mut statement = connection
            .prepare("SELECT kind,scope_key,deleted_at,payload FROM cfn_metadata_v1")
            .map_err(|_| CfnError::Internal)?;
        let mut rows = statement.query([]).map_err(|_| CfnError::Internal)?;
        while let Some(row) = rows.next().map_err(|_| CfnError::Internal)? {
            let kind: String = row.get(0).map_err(|_| CfnError::Internal)?;
            let key: String = row.get(1).map_err(|_| CfnError::Internal)?;
            let deleted_at: Option<i64> = row.get(2).map_err(|_| CfnError::Internal)?;
            let payload: Vec<u8> = row.get(3).map_err(|_| CfnError::Internal)?;
            let plaintext = self
                .cipher
                .open(&["cloudformation", &kind, &key], &payload)
                .map_err(|_| CfnError::Internal)?;
            restore(&kind, key, deleted_at, &plaintext)?;
        }
        drop(rows);
        drop(statement);
        connection
            .execute(
                "DELETE FROM cfn_metadata_v1 WHERE kind='deleted' AND deleted_at <= ?1",
                [now() - RETENTION_SECONDS],
            )
            .map_err(|_| CfnError::Internal)?;
        Ok(())
    }

    pub(crate) fn put<T: Serialize>(
        &self,
        kind: &str,
        key: &str,
        record: &T,
    ) -> Result<(), CfnError> {
        let payload = self.encode(kind, key, record)?;
        self.connection.lock().map_err(|_| CfnError::Internal)?.execute(
            "INSERT INTO cfn_metadata_v1(kind,scope_key,payload) VALUES(?1,?2,?3) ON CONFLICT(kind,scope_key) DO UPDATE SET payload=excluded.payload", params![kind,key,payload],
        ).map_err(|_| CfnError::Internal)?;
        Ok(())
    }

    fn encode<T: Serialize>(&self, kind: &str, key: &str, record: &T) -> Result<Vec<u8>, CfnError> {
        let plaintext = serde_json::to_vec(record).map_err(|_| CfnError::Internal)?;
        self.cipher
            .seal(&["cloudformation", kind, key], &plaintext)
            .map_err(|_| CfnError::Internal)
    }

    pub(crate) fn admit(
        &self,
        key: &str,
        stack: &crate::model::Stack,
        change: Option<(&str, &crate::store::ChangeSet)>,
    ) -> Result<(), CfnError> {
        let payload = self.encode("stack", key, stack)?;
        let claim = change
            .map(|(key, change)| Ok::<_, CfnError>((key, self.encode("change", key, change)?)))
            .transpose()?;
        let mut connection = self.connection.lock().map_err(|_| CfnError::Internal)?;
        let tx = connection.transaction().map_err(|_| CfnError::Internal)?;
        tx.execute("INSERT INTO cfn_metadata_v1(kind,scope_key,payload) VALUES('stack',?1,?2) ON CONFLICT(kind,scope_key) DO UPDATE SET payload=excluded.payload", params![key,payload]).map_err(|_| CfnError::Internal)?;
        if let Some((key, payload)) = claim {
            let changed = tx
                .execute(
                    "UPDATE cfn_metadata_v1 SET payload=?2 WHERE kind='change' AND scope_key=?1",
                    params![key, payload],
                )
                .map_err(|_| CfnError::Internal)?;
            if changed != 1 {
                return Err(CfnError::Internal);
            }
        }
        tx.commit().map_err(|_| CfnError::Internal)
    }

    pub(crate) fn remove_change(&self, key: &str) -> Result<(), CfnError> {
        self.connection
            .lock()
            .map_err(|_| CfnError::Internal)?
            .execute(
                "DELETE FROM cfn_metadata_v1 WHERE kind='change' AND scope_key=?1",
                [key],
            )
            .map_err(|_| CfnError::Internal)?;
        Ok(())
    }

    pub(crate) fn archive(
        &self,
        active_key: &str,
        archive_key: &str,
        stack: &crate::model::Stack,
        deleted_at: i64,
        changes: &[String],
    ) -> Result<(), CfnError> {
        let payload = self.encode("deleted", archive_key, &(deleted_at, stack))?;
        let mut connection = self.connection.lock().map_err(|_| CfnError::Internal)?;
        let tx = connection.transaction().map_err(|_| CfnError::Internal)?;
        tx.execute(
            "DELETE FROM cfn_metadata_v1 WHERE kind='stack' AND scope_key=?1",
            [active_key],
        )
        .map_err(|_| CfnError::Internal)?;
        for key in changes {
            tx.execute(
                "DELETE FROM cfn_metadata_v1 WHERE kind='change' AND scope_key=?1",
                [key],
            )
            .map_err(|_| CfnError::Internal)?;
        }
        tx.execute(
            "DELETE FROM cfn_metadata_v1 WHERE kind='deleted' AND deleted_at<=?1",
            [now() - RETENTION_SECONDS],
        )
        .map_err(|_| CfnError::Internal)?;
        tx.execute("INSERT INTO cfn_metadata_v1(kind,scope_key,payload,deleted_at) VALUES('deleted',?1,?2,?3) ON CONFLICT(kind,scope_key) DO UPDATE SET payload=excluded.payload, deleted_at=excluded.deleted_at", params![archive_key,payload,deleted_at]).map_err(|_| CfnError::Internal)?;
        tx.commit().map_err(|_| CfnError::Internal)
    }
}
