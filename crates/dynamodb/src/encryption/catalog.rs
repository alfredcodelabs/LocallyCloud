//! Durable table-file identities and key envelopes; this does not enable public SSE.
use std::sync::Arc;

use locallycloud_state::StateDb;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use super::{TableKeyEnvelope, TableKeyScope, TableKeys};
use crate::error::DdbError;

const MAX_RECORD: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilePhase {
    Creating,
    Active,
    Deleting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileMetadata {
    scope: TableKeyScope,
    envelope: TableKeyEnvelope,
    phase: FilePhase,
    revision: i64,
}

#[derive(Debug, Clone)]
pub struct TableFileRecord(FileMetadata);

impl TableFileRecord {
    pub fn scope(&self) -> &TableKeyScope {
        &self.0.scope
    }

    pub fn envelope(&self) -> &TableKeyEnvelope {
        &self.0.envelope
    }

    pub fn phase(&self) -> FilePhase {
        self.0.phase
    }

    /// File names never contain AWS names or client-provided path segments.
    pub fn file_name(&self) -> String {
        format!("{}.sqlite3", self.0.scope.storage_id())
    }
}

#[derive(Clone)]
pub struct TableCatalog {
    state: Arc<StateDb>,
    keys: Arc<TableKeys>,
}

fn unavailable() -> DdbError {
    DdbError::Internal("Encrypted table catalog is unavailable or failed authentication".into())
}

fn conflict() -> DdbError {
    DdbError::ResourceInUse("Table storage changed; reload its current identity".into())
}

impl TableCatalog {
    pub async fn new(state: Arc<StateDb>, keys: Arc<TableKeys>) -> Result<Self, DdbError> {
        let db = state.clone();
        tokio::task::spawn_blocking(move || {
            db.connection()
                .map_err(|_| unavailable())?
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS lc_dynamodb_table_files (
                    account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                    storage_id TEXT NOT NULL UNIQUE, revision INTEGER NOT NULL CHECK(revision > 0),
                    metadata BLOB NOT NULL, PRIMARY KEY(account,region,name))",
                )
                .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| unavailable())??;
        Ok(Self { state, keys })
    }

    /// Persist before starting a worker. A duplicate name never replaces an existing file.
    pub async fn reserve(
        &self,
        scope: TableKeyScope,
        envelope: TableKeyEnvelope,
    ) -> Result<TableFileRecord, DdbError> {
        Self::validate_scope(scope.account(), scope.region(), scope.table_name())?;
        self.keys
            .wrapped_key(&scope, &envelope)
            .map_err(|_| unavailable())?;
        let record = FileMetadata {
            scope,
            envelope,
            phase: FilePhase::Creating,
            revision: 1,
        };
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let sealed = this.encode(&record)?;
            let db = this.state.connection().map_err(|_| unavailable())?;
            let n = db.execute(
                "INSERT INTO lc_dynamodb_table_files(account,region,name,storage_id,revision,metadata)
                 VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT DO NOTHING",
                (record.scope.account(),record.scope.region(),record.scope.table_name(),record.scope.storage_id().to_string(),record.revision,sealed),
            ).map_err(|_| unavailable())?;
            if n != 1 { return Err(conflict()); }
            Ok(TableFileRecord(record))
        }).await.map_err(|_| unavailable())?
    }

    pub async fn load(
        &self,
        account: &str,
        region: &str,
        name: &str,
    ) -> Result<Option<TableFileRecord>, DdbError> {
        Self::validate_scope(account, region, name)?;
        let this = self.clone();
        let (account, region, name) = (account.to_owned(), region.to_owned(), name.to_owned());
        tokio::task::spawn_blocking(move || {
            let db = this.state.connection().map_err(|_| unavailable())?;
            let row: Option<(String, i64, Vec<u8>)> = db
                .query_row(
                    "SELECT CASE WHEN length(storage_id)=36 THEN storage_id ELSE NULL END,revision,
                 CASE WHEN length(metadata)<=?4 THEN metadata ELSE NULL END
                 FROM lc_dynamodb_table_files WHERE account=?1 AND region=?2 AND name=?3",
                    (
                        &account,
                        &region,
                        &name,
                        i64::try_from(MAX_RECORD + 1024).map_err(|_| unavailable())?,
                    ),
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|_| unavailable())?;
            row.map(|(id, revision, sealed)| {
                this.decode(&account, &region, &name, &id, revision, &sealed)
            })
            .transpose()
        })
        .await
        .map_err(|_| unavailable())?
    }

    pub async fn transition(
        &self,
        previous: &TableFileRecord,
        phase: FilePhase,
    ) -> Result<TableFileRecord, DdbError> {
        match (previous.phase(), phase) {
            (FilePhase::Creating, FilePhase::Active | FilePhase::Deleting)
            | (FilePhase::Active, FilePhase::Deleting) => {}
            _ => {
                return Err(DdbError::Validation(
                    "Invalid table storage transition".into(),
                ))
            }
        }
        let this = self.clone();
        let mut record = previous.0.clone();
        let revision = record.revision;
        record.revision = revision.checked_add(1).ok_or_else(unavailable)?;
        record.phase = phase;
        tokio::task::spawn_blocking(move || {
            let sealed = this.encode(&record)?;
            let n = this
                .state
                .connection()
                .map_err(|_| unavailable())?
                .execute(
                    "UPDATE lc_dynamodb_table_files SET metadata=?1,revision=?2
                 WHERE account=?3 AND region=?4 AND name=?5 AND storage_id=?6 AND revision=?7",
                    (
                        sealed,
                        record.revision,
                        record.scope.account(),
                        record.scope.region(),
                        record.scope.table_name(),
                        record.scope.storage_id().to_string(),
                        revision,
                    ),
                )
                .map_err(|_| unavailable())?;
            if n != 1 {
                return Err(conflict());
            }
            Ok(TableFileRecord(record))
        })
        .await
        .map_err(|_| unavailable())?
    }

    /// Call only after the worker has stopped and its database/WAL files are removed.
    pub async fn forget_deleted(&self, record: &TableFileRecord) -> Result<(), DdbError> {
        if record.phase() != FilePhase::Deleting {
            return Err(DdbError::Validation("Table storage is not deleting".into()));
        }
        let this = self.clone();
        let record = record.0.clone();
        tokio::task::spawn_blocking(move || {
            let n = this
                .state
                .connection()
                .map_err(|_| unavailable())?
                .execute(
                    "DELETE FROM lc_dynamodb_table_files
                 WHERE account=?1 AND region=?2 AND name=?3 AND storage_id=?4 AND revision=?5",
                    (
                        record.scope.account(),
                        record.scope.region(),
                        record.scope.table_name(),
                        record.scope.storage_id().to_string(),
                        record.revision,
                    ),
                )
                .map_err(|_| unavailable())?;
            if n != 1 {
                return Err(conflict());
            }
            Ok(())
        })
        .await
        .map_err(|_| unavailable())?
    }

    fn validate_scope(account: &str, region: &str, name: &str) -> Result<(), DdbError> {
        crate::streams::validate_scope_values(account, region)?;
        crate::store::validate_table_name(name)
    }

    fn encode(&self, record: &FileMetadata) -> Result<Vec<u8>, DdbError> {
        let bytes = serde_json::to_vec(record).map_err(|_| unavailable())?;
        if bytes.len() > MAX_RECORD {
            return Err(unavailable());
        }
        self.keys
            .metadata_cipher
            .seal(
                &[
                    "dynamodb-table-file-v1",
                    record.scope.account(),
                    record.scope.region(),
                    record.scope.table_name(),
                    &record.scope.storage_id().to_string(),
                    &record.revision.to_string(),
                ],
                &bytes,
            )
            .map_err(|_| unavailable())
    }

    fn decode(
        &self,
        account: &str,
        region: &str,
        name: &str,
        id: &str,
        revision: i64,
        sealed: &[u8],
    ) -> Result<TableFileRecord, DdbError> {
        if sealed.len() > MAX_RECORD + 1024 || revision <= 0 {
            return Err(unavailable());
        }
        let bytes = self
            .keys
            .metadata_cipher
            .open(
                &[
                    "dynamodb-table-file-v1",
                    account,
                    region,
                    name,
                    id,
                    &revision.to_string(),
                ],
                sealed,
            )
            .map_err(|_| unavailable())?;
        let record: FileMetadata = serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
        if record.scope.account() != account
            || record.scope.region() != region
            || record.scope.table_name() != name
            || record.scope.storage_id().to_string() != id
            || record.scope.storage_id().is_nil()
            || record.revision != revision
        {
            return Err(unavailable());
        }
        self.keys
            .wrapped_key(&record.scope, &record.envelope)
            .map_err(|_| unavailable())?;
        Ok(TableFileRecord(record))
    }
}
