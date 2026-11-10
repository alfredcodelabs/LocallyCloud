//! Durable table-file identities and key envelopes; this does not enable public SSE.
use std::sync::Arc;

use locallycloud_state::StateDb;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use super::{TableKeyEnvelope, TableKeyScope, TableKeys};
use crate::error::DdbError;

// Envelope allowance plus bounded normalized schema and provider description.
const MAX_CREATE_INTENT: usize = 1024 * 1024;
const MAX_RECORD: usize = 128 * 1024 + 2 * MAX_CREATE_INTENT;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilePhase {
    Creating,
    Active,
    Updating,
    Deleting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileMetadata {
    scope: TableKeyScope,
    envelope: TableKeyEnvelope,
    phase: FilePhase,
    revision: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    create_intent: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_update: Option<serde_json::Value>,
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

    pub fn revision(&self) -> i64 {
        self.0.revision
    }

    pub fn phase(&self) -> FilePhase {
        self.0.phase
    }

    /// Complete normalized CreateTable parameters, absent for legacy reservations.
    pub fn create_intent(&self) -> Option<&serde_json::Value> {
        self.0.create_intent.as_ref()
    }

    /// Last validated ACTIVE description returned by the provider.
    pub fn description(&self) -> Option<&serde_json::Value> {
        self.0.description.as_ref()
    }

    /// Authorized update parameters persisted before the provider mutation.
    pub fn pending_update(&self) -> Option<&serde_json::Value> {
        self.0.pending_update.as_ref()
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
        self.reserve_inner(scope, envelope, None).await
    }

    /// Persist complete normalized CreateTable parameters before provider mutation.
    /// The provider validates the schema. Never pass a request or credentials.
    pub async fn reserve_with_intent(
        &self,
        scope: TableKeyScope,
        envelope: TableKeyEnvelope,
        intent: serde_json::Value,
    ) -> Result<TableFileRecord, DdbError> {
        Self::validate_intent(&scope, &intent)?;
        self.reserve_inner(scope, envelope, Some(intent)).await
    }

    async fn reserve_inner(
        &self,
        scope: TableKeyScope,
        envelope: TableKeyEnvelope,
        create_intent: Option<serde_json::Value>,
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
            create_intent,
            description: None,
            pending_update: None,
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

    pub async fn has_scope(&self, account: &str, region: &str) -> Result<bool, DdbError> {
        crate::streams::validate_scope_values(account, region)?;
        let (account, region) = (account.to_owned(), region.to_owned());
        let state = self.state.clone();
        tokio::task::spawn_blocking(move || {
            state.connection().map_err(|_|unavailable())?.query_row(
                "SELECT EXISTS(SELECT 1 FROM lc_dynamodb_table_files WHERE account=?1 AND region=?2)",
                (&account,&region),|row|row.get(0),
            ).map_err(|_|unavailable())
        }).await.map_err(|_|unavailable())?
    }

    /// Bounded recovery inventory, ordered by account, region and table name.
    /// Continue after the last record until a page is empty. Pages are not a snapshot.
    /// A serialized-byte budget may return fewer rows than the requested limit.
    pub async fn page(
        &self,
        after: Option<&TableFileRecord>,
        limit: usize,
    ) -> Result<Vec<TableFileRecord>, DdbError> {
        if !(1..=100).contains(&limit) {
            return Err(DdbError::Validation(
                "Catalog page size must be between 1 and 100".into(),
            ));
        }
        let after_is_none = after.is_none();
        let cursor = match after {
            Some(record) => {
                let scope = record.scope();
                Self::validate_scope(scope.account(), scope.region(), scope.table_name())?;
                (
                    scope.account().to_owned(),
                    scope.region().to_owned(),
                    scope.table_name().to_owned(),
                )
            }
            None => (String::new(), String::new(), String::new()),
        };
        self.read_page(cursor, after_is_none, limit, false).await
    }

    /// Bounded inventory within one account and region, ordered by table name.
    pub async fn page_scope(
        &self,
        account: &str,
        region: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<TableFileRecord>, DdbError> {
        crate::streams::validate_scope_values(account, region)?;
        if let Some(name) = after {
            crate::store::validate_table_name(name)?;
        }
        if !(1..=100).contains(&limit) {
            return Err(DdbError::Validation(
                "Catalog page size must be between 1 and 100".into(),
            ));
        }
        self.read_page(
            (
                account.to_owned(),
                region.to_owned(),
                after.unwrap_or_default().to_owned(),
            ),
            after.is_none(),
            limit,
            true,
        )
        .await
    }

    async fn read_page(
        &self,
        cursor: (String, String, String),
        initial: bool,
        limit: usize,
        scoped: bool,
    ) -> Result<Vec<TableFileRecord>, DdbError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let db = this.state.connection().map_err(|_| unavailable())?;
            let comparison = if initial { ">=" } else { ">" };
            let filter = if scoped {
                format!("account=?1 AND region=?2 AND name{comparison}?3")
            } else {
                format!("(account,region,name){comparison}(?1,?2,?3)")
            };
            let sql = format!(
                "SELECT
                 CASE WHEN length(CAST(account AS BLOB))=12 THEN account ELSE NULL END,
                 CASE WHEN length(CAST(region AS BLOB)) BETWEEN 3 AND 64 THEN region ELSE NULL END,
                 CASE WHEN length(CAST(name AS BLOB)) BETWEEN 3 AND 255 THEN name ELSE NULL END,
                 CASE WHEN length(CAST(storage_id AS BLOB))=36 THEN storage_id ELSE NULL END,
                 revision, CASE WHEN length(metadata)<=?4 THEN metadata ELSE NULL END,
                 length(metadata)
                 FROM lc_dynamodb_table_files WHERE {filter}
                 ORDER BY account,region,name LIMIT ?5"
            );
            let mut statement = db.prepare(&sql).map_err(|_| unavailable())?;
            let mut rows = statement
                .query((
                    &cursor.0,
                    &cursor.1,
                    &cursor.2,
                    i64::try_from(MAX_RECORD + 1024).map_err(|_| unavailable())?,
                    i64::try_from(limit).map_err(|_| unavailable())?,
                ))
                .map_err(|_| unavailable())?;
            let mut records = Vec::with_capacity(limit);
            let mut page_bytes = 0usize;
            while let Some(row) = rows.next().map_err(|_| unavailable())? {
                let account: String = row.get(0).map_err(|_| unavailable())?;
                let region: String = row.get(1).map_err(|_| unavailable())?;
                let name: String = row.get(2).map_err(|_| unavailable())?;
                let id: String = row.get(3).map_err(|_| unavailable())?;
                let revision: i64 = row.get(4).map_err(|_| unavailable())?;
                let sealed_len: i64 = row.get(6).map_err(|_| unavailable())?;
                let sealed_len = usize::try_from(sealed_len).map_err(|_| unavailable())?;
                if !records.is_empty() && sealed_len > MAX_RECORD + 1024 - page_bytes {
                    break;
                }
                let sealed: Vec<u8> = row.get(5).map_err(|_| unavailable())?;
                page_bytes += sealed.len();
                records.push(this.decode(&account, &region, &name, &id, revision, &sealed)?);
            }
            Ok(records)
        })
        .await
        .map_err(|_| unavailable())?
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
        let mut record = previous.0.clone();
        record.phase = phase;
        self.save(previous, record).await
    }

    /// Persist the actual ACTIVE provider description when creation completes.
    pub async fn activate(
        &self,
        previous: &TableFileRecord,
        description: serde_json::Value,
    ) -> Result<TableFileRecord, DdbError> {
        if previous.phase() != FilePhase::Creating {
            return Err(DdbError::Validation("Table storage is not creating".into()));
        }
        Self::validate_description(previous.scope(), &description)?;
        let mut record = previous.0.clone();
        record.phase = FilePhase::Active;
        record.description = Some(description);
        self.save(previous, record).await
    }

    /// Refresh an ACTIVE description without changing its immutable storage identity.
    pub async fn refresh_description(
        &self,
        previous: &TableFileRecord,
        description: serde_json::Value,
    ) -> Result<TableFileRecord, DdbError> {
        if previous.phase() != FilePhase::Active {
            return Err(DdbError::Validation("Table storage is not active".into()));
        }
        Self::validate_description(previous.scope(), &description)?;
        let mut record = previous.0.clone();
        record.description = Some(description);
        self.save(previous, record).await
    }

    /// Fence deletion before changing the provider's deletion protection.
    pub async fn begin_update(
        &self,
        previous: &TableFileRecord,
        intent: serde_json::Value,
    ) -> Result<TableFileRecord, DdbError> {
        if previous.phase() != FilePhase::Active {
            return Err(DdbError::Validation("Table storage is not active".into()));
        }
        Self::validate_update(previous.scope(), &intent)?;
        let mut record = previous.0.clone();
        record.phase = FilePhase::Updating;
        record.pending_update = Some(intent);
        self.save(previous, record).await
    }

    /// Clear the fence only after observing the intended provider state.
    pub async fn complete_update(
        &self,
        previous: &TableFileRecord,
        description: serde_json::Value,
    ) -> Result<TableFileRecord, DdbError> {
        if previous.phase() != FilePhase::Updating {
            return Err(DdbError::Validation("Table storage is not updating".into()));
        }
        Self::validate_description(previous.scope(), &description)?;
        let intent = previous.pending_update().ok_or_else(unavailable)?;
        Self::validate_update(previous.scope(), intent)?;
        if description.get("DeletionProtectionEnabled") != intent.get("DeletionProtectionEnabled") {
            return Err(DdbError::Validation(
                "Provider table update has not completed".into(),
            ));
        }
        let mut record = previous.0.clone();
        record.phase = FilePhase::Active;
        record.description = Some(description);
        record.pending_update = None;
        self.save(previous, record).await
    }

    async fn save(
        &self,
        previous: &TableFileRecord,
        mut record: FileMetadata,
    ) -> Result<TableFileRecord, DdbError> {
        let this = self.clone();
        let revision = previous.revision();
        record.revision = revision.checked_add(1).ok_or_else(unavailable)?;
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

    fn validate_intent(scope: &TableKeyScope, intent: &serde_json::Value) -> Result<(), DdbError> {
        const MEMBERS: &[&str] = &[
            "AttributeDefinitions",
            "BillingMode",
            "DeletionProtectionEnabled",
            "GlobalSecondaryIndexes",
            "GlobalTableSettingsReplicationMode",
            "GlobalTableSourceArn",
            "KeySchema",
            "LocalSecondaryIndexes",
            "OnDemandThroughput",
            "ProvisionedThroughput",
            "ResourcePolicy",
            "StreamSpecification",
            "TableClass",
            "TableName",
            "Tags",
            "VectorIndexes",
            "WarmThroughput",
        ];
        let object = intent.as_object().ok_or_else(|| {
            DdbError::Validation("CreateTable intent must be normalized parameters".into())
        })?;
        if object
            .keys()
            .any(|member| !MEMBERS.contains(&member.as_str()))
        {
            return Err(DdbError::Validation(
                "CreateTable intent contains unsupported parameters".into(),
            ));
        }
        if intent.get("TableName").and_then(serde_json::Value::as_str) != Some(scope.table_name()) {
            return Err(DdbError::Validation(
                "CreateTable intent must match the table storage scope".into(),
            ));
        }
        Self::validate_value(intent)
    }

    fn validate_update(scope: &TableKeyScope, intent: &serde_json::Value) -> Result<(), DdbError> {
        if intent.as_object().is_none_or(|object| object.len() != 2)
            || intent.get("TableName").and_then(serde_json::Value::as_str)
                != Some(scope.table_name())
            || intent
                .get("DeletionProtectionEnabled")
                .and_then(serde_json::Value::as_bool)
                .is_none()
        {
            return Err(DdbError::Validation(
                "Table update intent must contain only its scoped name and deletion protection"
                    .into(),
            ));
        }
        Ok(())
    }

    fn validate_description(
        scope: &TableKeyScope,
        description: &serde_json::Value,
    ) -> Result<(), DdbError> {
        let arn = format!(
            "arn:aws:dynamodb:{}:{}:table/{}",
            scope.region(),
            scope.account(),
            scope.table_name()
        );
        if description
            .get("TableName")
            .and_then(serde_json::Value::as_str)
            != Some(scope.table_name())
            || description
                .get("TableArn")
                .and_then(serde_json::Value::as_str)
                != Some(arn.as_str())
            || description
                .get("TableStatus")
                .and_then(serde_json::Value::as_str)
                != Some("ACTIVE")
        {
            return Err(DdbError::Validation(
                "ACTIVE table description must match the table storage scope".into(),
            ));
        }
        Self::validate_value(description)
    }

    fn validate_value(value: &serde_json::Value) -> Result<(), DdbError> {
        fn bounded_depth(value: &serde_json::Value, depth: usize) -> bool {
            if depth > 32 {
                return false;
            }
            match value {
                serde_json::Value::Array(values) => {
                    values.iter().all(|value| bounded_depth(value, depth + 1))
                }
                serde_json::Value::Object(values) => {
                    values.values().all(|value| bounded_depth(value, depth + 1))
                }
                _ => true,
            }
        }
        struct SizeLimit(usize);
        impl std::io::Write for SizeLimit {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if bytes.len() > MAX_CREATE_INTENT - self.0 {
                    return Err(std::io::Error::other("Catalog value exceeds size limit"));
                }
                self.0 += bytes.len();
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        if !bounded_depth(value, 0) || serde_json::to_writer(SizeLimit(0), value).is_err() {
            return Err(DdbError::Validation(
                "Catalog value exceeds size or nesting limits".into(),
            ));
        }
        Ok(())
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
        if let Some(intent) = &record.create_intent {
            Self::validate_intent(&record.scope, intent).map_err(|_| unavailable())?;
        }
        if let Some(description) = &record.description {
            Self::validate_description(&record.scope, description).map_err(|_| unavailable())?;
        }
        match (record.phase, &record.pending_update) {
            (FilePhase::Updating, Some(intent)) => {
                Self::validate_update(&record.scope, intent).map_err(|_| unavailable())?;
            }
            (FilePhase::Updating, None) | (_, Some(_)) => return Err(unavailable()),
            (_, None) => {}
        }
        self.keys
            .wrapped_key(&record.scope, &record.envelope)
            .map_err(|_| unavailable())?;
        Ok(TableFileRecord(record))
    }
}
