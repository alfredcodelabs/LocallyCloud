//! Bounded, read-only native-engine inspection. This does not import or switch engines.
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use locallycloud_state::StateCipher;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;

use crate::error::DdbError;
use crate::store::{StoredKey, StreamRecord, TableData};

#[path = "migration_export.rs"]
mod export;
pub use export::{
    export_native, export_native_recovery, export_native_recovery_with_policy,
    export_native_with_policy, MigrationPolicy, NativeRecord,
};

const MAX_RECORD: i64 = 8 * 1024 * 1024;
const KNOWN_TABLES: &[&str] = &[
    "dynamodb_tables",
    "dynamodb_items",
    "dynamodb_stream_records",
    "dynamodb_replica_versions",
    "dynamodb_recovery",
    "dynamodb_recovery_items",
    "dynamodb_txn_tokens",
    "locallycloud_service_engines",
];

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockingFeature {
    ServerSideEncryption,
    StreamIdentityAndHistory,
    PointInTimeRecovery,
    GlobalReplication,
    KinesisDestinations,
    ExportMetadata,
    UnknownMetadata,
    TableNotActive,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TableInspection {
    pub account: String,
    pub region: String,
    pub table: String,
    pub item_count: u64,
    pub stream_records: u64,
    pub recovery_versions: u64,
    pub replication_versions: u64,
    pub tag_count: usize,
    pub ttl_configured: bool,
    pub sse_type: Option<String>,
    pub proposed_normalization: Option<&'static str>,
    pub secondary_indexes: usize,
    pub blocking_features: Vec<BlockingFeature>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectionSummary {
    pub source_engine: &'static str,
    pub table_count: u64,
    pub item_count: u64,
    pub source_key_authenticated: bool,
    pub encrypted_records_authenticated: u64,
    pub active_transaction_tokens: u64,
    pub unrecognized_storage_tables: Vec<String>,
    pub apply_ready: bool,
}

#[derive(Clone, Copy)]
enum RecordKind {
    Metadata,
    Item,
    Stream,
    RecoveryItem,
}

impl RecordKind {
    const ALL: [Self; 4] = [Self::Metadata, Self::Item, Self::Stream, Self::RecoveryItem];

    fn table(self) -> &'static str {
        match self {
            Self::Metadata => "dynamodb_tables",
            Self::Item => "dynamodb_items",
            Self::Stream => "dynamodb_stream_records",
            Self::RecoveryItem => "dynamodb_recovery_items",
        }
    }

    fn query(self) -> &'static str {
        match self {
            Self::Metadata => "SELECT substr(account,1,13),substr(region,1,65),substr(name,1,256),'',CASE WHEN length(CAST(metadata AS BLOB))<=?1 THEN metadata END FROM dynamodb_tables",
            Self::Item => "SELECT substr(account,1,13),substr(region,1,65),substr(name,1,256),CASE WHEN length(CAST(item_key AS BLOB))<=?1 THEN item_key END,CASE WHEN length(CAST(item AS BLOB))<=?1 THEN item END FROM dynamodb_items",
            Self::Stream => "SELECT substr(account,1,13),substr(region,1,65),substr(name,1,256),CAST(sequence AS TEXT),CASE WHEN length(CAST(record AS BLOB))<=?1 THEN record END FROM dynamodb_stream_records",
            Self::RecoveryItem => "SELECT substr(account,1,13),substr(region,1,65),substr(name,1,256),CASE WHEN length(CAST(item_key AS BLOB))<=?1 THEN item_key END,CASE WHEN length(CAST(item AS BLOB))<=?1 THEN item END FROM dynamodb_recovery_items WHERE item IS NOT NULL",
        }
    }
}

fn invalid() -> DdbError {
    DdbError::Internal(
        "Native DynamoDB state is invalid, exceeds inspection limits, or cannot be authenticated"
            .into(),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SourceBinding {
    Native,
    CommittedExtendDb,
}

fn source_schema_with_binding(
    connection: &Connection,
    binding: SourceBinding,
) -> Result<(BTreeSet<String>, bool), DdbError> {
    let mut query = connection.prepare("SELECT substr(name,1,65) FROM sqlite_master WHERE type='table' AND (name GLOB 'dynamodb_*' OR name='locallycloud_service_engines') LIMIT 129").map_err(|_| invalid())?;
    let mut schema = BTreeSet::new();
    for name in query
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| invalid())?
    {
        let name = name.map_err(|_| invalid())?;
        if name.len() > 64 || schema.len() >= 128 {
            return Err(invalid());
        }
        schema.insert(name);
    }
    let mut native_bound = false;
    if schema.contains("locallycloud_service_engines") {
        let engine: Option<String> = connection
            .query_row(
                "SELECT engine FROM locallycloud_service_engines WHERE service='dynamodb'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| invalid())?;
        match engine.as_deref() {
            None => {}
            Some("native") if binding == SourceBinding::Native => {
                native_bound = true;
            }
            Some("extenddb") if binding == SourceBinding::CommittedExtendDb => {
                native_bound = true;
            }
            Some("extenddb") => return Err(DdbError::Validation(
                "This state already selects ExtendDB; native migration inspection does not apply"
                    .into(),
            )),
            Some(_) => return Err(invalid()),
        }
    }
    if binding == SourceBinding::CommittedExtendDb && !native_bound {
        return Err(DdbError::Validation(
            "Committed migration recovery requires an ExtendDB engine binding".into(),
        ));
    }
    Ok((schema, native_bound))
}

fn check_orphans(connection: &Connection, schema: &BTreeSet<String>) -> Result<(), DdbError> {
    for table in [
        "dynamodb_items",
        "dynamodb_stream_records",
        "dynamodb_recovery_items",
        "dynamodb_recovery",
        "dynamodb_replica_versions",
    ] {
        if !schema.contains(table) {
            continue;
        }
        let condition = if schema.contains("dynamodb_tables") {
            " WHERE NOT EXISTS(SELECT 1 FROM dynamodb_tables AS parent WHERE parent.account=records.account AND parent.region=records.region AND parent.name=records.name)"
        } else {
            ""
        };
        let query = format!("SELECT EXISTS(SELECT 1 FROM {table} AS records{condition})");
        if connection
            .query_row(&query, [], |row| row.get::<_, bool>(0))
            .map_err(|_| invalid())?
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn authenticate(
    connection: &Connection,
    cipher: &StateCipher,
    schema: &BTreeSet<String>,
) -> Result<u64, DdbError> {
    let mut encrypted = 0u64;
    for kind in RecordKind::ALL {
        if !schema.contains(kind.table()) {
            continue;
        }
        let mut query = connection.prepare(kind.query()).map_err(|_| invalid())?;
        let mut rows = query.query([MAX_RECORD]).map_err(|_| invalid())?;
        while let Some(row) = rows.next().map_err(|_| invalid())? {
            let account: String = row.get(0).map_err(|_| invalid())?;
            let region: String = row.get(1).map_err(|_| invalid())?;
            let name: String = row.get(2).map_err(|_| invalid())?;
            crate::streams::validate_scope_values(&account, &region).map_err(|_| invalid())?;
            crate::store::validate_table_name(&name).map_err(|_| invalid())?;
            let key: String = row.get(3).map_err(|_| invalid())?;
            let encoded: String = row.get(4).map_err(|_| invalid())?;
            if encoded.starts_with(crate::recovery::SEALED) {
                encrypted = encrypted.checked_add(1).ok_or_else(invalid)?;
            }
            match kind {
                RecordKind::Metadata => {
                    crate::store::migration_table(cipher, &account, &region, &name, &encoded)?;
                }
                RecordKind::Item | RecordKind::RecoveryItem => {
                    let _: StoredKey = serde_json::from_str(&key).map_err(|_| invalid())?;
                    crate::recovery::decode_item(
                        Some(cipher),
                        &[&account, &region, &name],
                        &key,
                        &encoded,
                    )
                    .map_err(|_| invalid())?;
                }
                RecordKind::Stream => {
                    let plaintext = crate::recovery::decode(
                        Some(cipher),
                        &["dynamodb-stream", &account, &region, &name, &key],
                        &encoded,
                    )
                    .map_err(|_| invalid())?;
                    let _: StreamRecord =
                        serde_json::from_str(&plaintext).map_err(|_| invalid())?;
                }
            }
        }
    }
    Ok(encrypted)
}

fn scoped_count(
    connection: &Connection,
    schema: &BTreeSet<String>,
    table: &'static str,
    scope: [&str; 3],
) -> Result<u64, DdbError> {
    if !schema.contains(table) {
        return Ok(0);
    }
    // Identifiers come only from this module's fixed schema names, never from a client.
    let count = connection
        .query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE account=?1 AND region=?2 AND name=?3"),
            scope,
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| invalid())?;
    u64::try_from(count).map_err(|_| invalid())
}

fn validate_items(
    connection: &Connection,
    cipher: &StateCipher,
    schema: &BTreeSet<String>,
    scope: [&str; 3],
    data: &TableData,
) -> Result<u64, DdbError> {
    if !schema.contains("dynamodb_items") {
        return Ok(0);
    }
    let mut query=connection.prepare("SELECT CASE WHEN length(CAST(item_key AS BLOB))<=?4 THEN item_key END,CASE WHEN length(CAST(item AS BLOB))<=?4 THEN item END FROM dynamodb_items WHERE account=?1 AND region=?2 AND name=?3 ORDER BY item_key").map_err(|_|invalid())?;
    let mut rows = query
        .query(params![scope[0], scope[1], scope[2], MAX_RECORD])
        .map_err(|_| invalid())?;
    let mut count = 0u64;
    while let Some(row) = rows.next().map_err(|_| invalid())? {
        let key: String = row.get(0).map_err(|_| invalid())?;
        let encoded: String = row.get(1).map_err(|_| invalid())?;
        let saved: StoredKey = serde_json::from_str(&key).map_err(|_| invalid())?;
        let item = crate::recovery::decode_item(Some(cipher), &scope, &key, &encoded)
            .map_err(|_| invalid())?;
        if data.key_of(&item).map_err(|_| invalid())? != saved {
            return Err(invalid());
        }
        count = count.checked_add(1).ok_or_else(invalid)?;
    }
    Ok(count)
}

/// Inspect a consistent snapshot without loading the complete native store or changing it.
/// Every encrypted native record is authenticated before the first callback is invoked.
pub fn inspect_native(
    path: &Path,
    cipher: &StateCipher,
    visit: impl FnMut(TableInspection) -> Result<(), DdbError>,
) -> Result<InspectionSummary, DdbError> {
    let connection = open_snapshot(path)?;
    inspect_snapshot(&connection, cipher, visit)
}

fn open_snapshot(path: &Path) -> Result<Connection, DdbError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| {
        DdbError::Validation("Native source database must already exist and be readable".into())
    })?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| invalid())?;
    connection
        .execute_batch("BEGIN DEFERRED")
        .map_err(|_| invalid())?;
    Ok(connection)
}

/// Read the administrative engine marker without creating or initializing source state.
/// This is not key authentication; callers must authenticate an export before mutation.
pub fn engine_binding(path: &Path) -> Result<Option<String>, DdbError> {
    let connection = open_snapshot(path)?;
    let present = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='locallycloud_service_engines')",
        [], |row| row.get::<_, bool>(0),
    ).map_err(|_| invalid())?;
    if !present {
        return Ok(None);
    }
    connection.query_row(
        "SELECT CASE WHEN length(CAST(engine AS BLOB))<=64 THEN engine END FROM locallycloud_service_engines WHERE service='dynamodb'",
        [], |row| row.get::<_, String>(0),
    ).optional().map_err(|_| invalid())
}

fn inspect_snapshot(
    connection: &Connection,
    cipher: &StateCipher,
    visit: impl FnMut(TableInspection) -> Result<(), DdbError>,
) -> Result<InspectionSummary, DdbError> {
    inspect_snapshot_with_binding(connection, cipher, SourceBinding::Native, visit)
}

fn inspect_snapshot_with_binding(
    connection: &Connection,
    cipher: &StateCipher,
    binding: SourceBinding,
    mut visit: impl FnMut(TableInspection) -> Result<(), DdbError>,
) -> Result<InspectionSummary, DdbError> {
    let (schema, native_bound) = source_schema_with_binding(connection, binding)?;
    check_orphans(connection, &schema)?;
    let encrypted = authenticate(connection, cipher, &schema)?;
    let mut summary = InspectionSummary {
        source_engine: if binding == SourceBinding::CommittedExtendDb {
            "extenddb"
        } else if native_bound || schema.contains("dynamodb_tables") {
            "native"
        } else {
            "unbound"
        },
        table_count: 0,
        item_count: 0,
        source_key_authenticated: encrypted > 0,
        encrypted_records_authenticated: encrypted,
        active_transaction_tokens: 0,
        unrecognized_storage_tables: schema
            .iter()
            .filter(|name| !KNOWN_TABLES.contains(&name.as_str()))
            .cloned()
            .collect(),
        apply_ready: false,
    };
    if schema.contains("dynamodb_txn_tokens") {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_secs();
        let now = i64::try_from(now).map_err(|_| invalid())?;
        let count = connection
            .query_row(
                "SELECT COUNT(*) FROM dynamodb_txn_tokens WHERE created_unix>?1",
                [now.saturating_sub(600)],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| invalid())?;
        summary.active_transaction_tokens = u64::try_from(count).map_err(|_| invalid())?;
    }
    if !schema.contains("dynamodb_tables") {
        return Ok(summary);
    }
    let mut query=connection.prepare("SELECT substr(account,1,13),substr(region,1,65),substr(name,1,256),CASE WHEN length(CAST(metadata AS BLOB))<=?1 THEN metadata END FROM dynamodb_tables ORDER BY account,region,name").map_err(|_|invalid())?;
    let mut rows = query.query([MAX_RECORD]).map_err(|_| invalid())?;
    while let Some(row) = rows.next().map_err(|_| invalid())? {
        let account: String = row.get(0).map_err(|_| invalid())?;
        let region: String = row.get(1).map_err(|_| invalid())?;
        let name: String = row.get(2).map_err(|_| invalid())?;
        let encoded: String = row.get(3).map_err(|_| invalid())?;
        let (data, unknown) =
            crate::store::migration_table(cipher, &account, &region, &name, &encoded)?;
        let scope = [account.as_str(), region.as_str(), name.as_str()];
        let item_count = validate_items(connection, cipher, &schema, scope, &data)?;
        let stream_records = scoped_count(connection, &schema, "dynamodb_stream_records", scope)?;
        let recovery_versions =
            scoped_count(connection, &schema, "dynamodb_recovery_items", scope)?;
        let replication_versions =
            scoped_count(connection, &schema, "dynamodb_replica_versions", scope)?;
        let recovery_windows = scoped_count(connection, &schema, "dynamodb_recovery", scope)?;
        let mut blocking_features = Vec::new();
        for (present, feature) in [
            (
                data.def.sse_type.is_some(),
                BlockingFeature::ServerSideEncryption,
            ),
            (
                data.def.stream_spec.as_ref().is_some_and(|v| v.enabled)
                    || data.stream_seq > 0
                    || stream_records > 0,
                BlockingFeature::StreamIdentityAndHistory,
            ),
            (
                data.pitr_enabled || recovery_versions > 0 || recovery_windows > 0,
                BlockingFeature::PointInTimeRecovery,
            ),
            (
                !data.def.replicas.is_empty()
                    || !data.replica_pending.is_empty()
                    || replication_versions > 0,
                BlockingFeature::GlobalReplication,
            ),
            (
                !data.kinesis_destinations.is_empty() || !data.kinesis_pending.is_empty(),
                BlockingFeature::KinesisDestinations,
            ),
            (!data.exports.is_empty(), BlockingFeature::ExportMetadata),
            (unknown, BlockingFeature::UnknownMetadata),
            (data.def.status != "ACTIVE", BlockingFeature::TableNotActive),
        ] {
            if present {
                blocking_features.push(feature);
            }
        }
        summary.table_count = summary.table_count.checked_add(1).ok_or_else(invalid)?;
        summary.item_count = summary
            .item_count
            .checked_add(item_count)
            .ok_or_else(invalid)?;
        visit(TableInspection {
            account,
            region,
            table: name,
            item_count,
            stream_records,
            recovery_versions,
            replication_versions,
            tag_count: data.tags.len(),
            ttl_configured: data.ttl_attribute.is_some(),
            proposed_normalization: (data.def.sse_type.as_deref() == Some("AES256")).then_some(
                "Explicit opt-in replaces legacy AES256 SSE metadata with the default-owned descriptor; SQLCipher encrypts destination storage; KMS is not migrated"),
            sse_type: data.def.sse_type.clone(),
            secondary_indexes: data.def.indexes.len(),
            blocking_features,
        })?;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{KeyScalar, StoredKey, TableStore};
    use crate::value::{AttributeValue, Item};
    use locallycloud_state::StateDb;
    use serde_json::{json, Value};
    use std::sync::Arc;

    const ACCOUNT: &str = "000000000000";
    const REGION: &str = "us-east-1";

    struct Fixture {
        root: std::path::PathBuf,
        state: StateDb,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("ddb-native-inspection-{}", uuid::Uuid::new_v4()));
            let state = StateDb::open(root.join("state.db")).unwrap();
            TableStore::with_state_and_cipher(
                Arc::new(state.clone()),
                Some(Arc::new(StateCipher::with_key(&[7; 32]))),
            )
            .unwrap();
            Self { root, state }
        }
        fn table(&self, name: &str, encrypted: bool, customize: impl FnOnce(&mut Value)) {
            let mut metadata = json!({"def":{"sse_type":if encrypted {Some("AES256")} else {None},
                "name":name,"arn":format!("arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{name}"),
                "key_schema":[{"name":"pk","key_type":"Hash"}],"attribute_definitions":[{"name":"pk","attr_type":"S"}],
                "indexes":[],"billing_mode":"PAY_PER_REQUEST","read_capacity":0,"write_capacity":0,
                "warm_throughput":null,"stream_spec":null,"creation_date":"1","status":"ACTIVE","replicas":[]},
                "persist_id":"fixture","tags":{},"ttl_attribute":null,"pitr_enabled":false,"stream_seq":0,
                "kinesis_destinations":[],"kinesis_pending":[],"exports":[],"replica_pending":[]});
            customize(&mut metadata);
            let cipher = StateCipher::with_key(&[7; 32]);
            let metadata = crate::recovery::encode(
                Some(&cipher),
                encrypted,
                &["dynamodb-metadata", ACCOUNT, REGION, name],
                &metadata.to_string(),
            )
            .unwrap();
            self.state
                .connection()
                .unwrap()
                .execute(
                    "INSERT INTO dynamodb_tables VALUES(?1,?2,?3,?4)",
                    params![ACCOUNT, REGION, name, metadata],
                )
                .unwrap();
            self.item(name, "row", encrypted, &cipher);
        }
        fn item(&self, name: &str, key: &str, encrypted: bool, cipher: &StateCipher) {
            let key_text = serde_json::to_string(&StoredKey {
                partition: KeyScalar::S(key.into()),
                sort: None,
            })
            .unwrap();
            let item: Item = [
                ("pk".into(), AttributeValue::S(key.into())),
                (
                    "payload".into(),
                    AttributeValue::S("must-not-appear-in-report".into()),
                ),
            ]
            .into_iter()
            .collect();
            let encoded = crate::recovery::encode_item(
                Some(cipher),
                encrypted,
                &[ACCOUNT, REGION, name],
                &key_text,
                &item,
            )
            .unwrap();
            self.state
                .connection()
                .unwrap()
                .execute(
                    "INSERT INTO dynamodb_items VALUES(?1,?2,?3,?4,?5)",
                    params![ACCOUNT, REGION, name, key_text, encoded],
                )
                .unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn inspection_is_read_only_and_reports_no_items_or_key_material() {
        let fixture = Fixture::new();
        fixture.table("orders", false, |_| {});
        let before = std::fs::read(fixture.state.path()).unwrap();
        let mut tables = Vec::new();
        let summary = inspect_native(
            fixture.state.path(),
            &StateCipher::with_key(&[7; 32]),
            |table| {
                tables.push(table);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(summary.table_count, 1);
        assert_eq!(summary.item_count, 1);
        assert!(!summary.source_key_authenticated);
        assert!(!summary.apply_ready);
        assert!(tables[0].blocking_features.is_empty());
        assert!(!serde_json::to_string(&tables)
            .unwrap()
            .contains("must-not-appear-in-report"));
        assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
    }

    #[test]
    fn wrong_key_authenticates_all_envelopes_before_any_output() {
        let fixture = Fixture::new();
        fixture.table("aaa-plain", false, |_| {});
        fixture.table("zzz-encrypted", true, |_| {});
        let mut emitted = 0;
        assert!(inspect_native(
            fixture.state.path(),
            &StateCipher::with_key(&[8; 32]),
            |_| {
                emitted += 1;
                Ok(())
            }
        )
        .is_err());
        assert_eq!(emitted, 0);
        let summary = inspect_native(
            fixture.state.path(),
            &StateCipher::with_key(&[7; 32]),
            |_| Ok(()),
        )
        .unwrap();
        assert!(summary.source_key_authenticated);
        assert_eq!(summary.encrypted_records_authenticated, 2);
    }

    #[test]
    fn encrypted_items_with_plain_metadata_also_fail_before_output() {
        let fixture = Fixture::new();
        fixture.table("orders", false, |_| {});
        fixture.item(
            "orders",
            "sealed-row",
            true,
            &StateCipher::with_key(&[8; 32]),
        );
        let mut emitted = 0;
        assert!(inspect_native(
            fixture.state.path(),
            &StateCipher::with_key(&[7; 32]),
            |_| {
                emitted += 1;
                Ok(())
            }
        )
        .is_err());
        assert_eq!(emitted, 0);
    }

    #[test]
    fn advanced_features_and_live_tokens_are_reported_without_cutover() {
        let fixture = Fixture::new();
        fixture.table("orders",true,|metadata|{
            metadata["def"]["stream_spec"]=json!({"enabled":true,"view_type":"KEYS_ONLY"});
            metadata["def"]["replicas"]=json!([REGION,"us-east-2"]);
            metadata["pitr_enabled"]=json!(true);
            metadata["ttl_attribute"]=json!("expires");
            metadata["kinesis_destinations"]=json!([{"stream_arn":"arn:aws:kinesis:us-east-1:000000000000:stream/events","status":"ACTIVE"}]);
            metadata["exports"]=json!([{"export_arn":"export","status":"COMPLETED","start_time":1.0,"s3_bucket":null}]);
            metadata["future_field"]=json!({"doNotDrop":true});
        });
        let connection = fixture.state.connection().unwrap();
        connection
            .execute_batch("CREATE TABLE dynamodb_future_data(value TEXT)")
            .unwrap();
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        connection
            .execute(
                "INSERT INTO dynamodb_txn_tokens VALUES(?1,?2,'token','fingerprint',?3,'{}')",
                params![ACCOUNT, REGION, now],
            )
            .unwrap();
        let mut tables = Vec::new();
        let summary = inspect_native(
            fixture.state.path(),
            &StateCipher::with_key(&[7; 32]),
            |table| {
                tables.push(table);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(summary.active_transaction_tokens, 1);
        assert_eq!(
            summary.unrecognized_storage_tables,
            vec!["dynamodb_future_data"]
        );
        assert_eq!(tables[0].blocking_features.len(), 7);
        assert!(tables[0].ttl_configured);
        assert!(!summary.apply_ready);
    }

    #[test]
    fn missing_source_and_oversized_records_never_report_success() {
        let path =
            std::env::temp_dir().join(format!("ddb-inspection-missing-{}", uuid::Uuid::new_v4()));
        assert!(inspect_native(&path, &StateCipher::with_key(&[7; 32]), |_| Ok(())).is_err());
        assert!(!path.exists());
        let fixture = Fixture::new();
        fixture.table("orders", false, |_| {});
        fixture
            .state
            .connection()
            .unwrap()
            .execute(
                "UPDATE dynamodb_tables SET metadata=zeroblob(?1)",
                [MAX_RECORD + 1],
            )
            .unwrap();
        let mut emitted = 0;
        assert!(inspect_native(
            fixture.state.path(),
            &StateCipher::with_key(&[7; 32]),
            |_| {
                emitted += 1;
                Ok(())
            }
        )
        .is_err());
        assert_eq!(emitted, 0);
    }

    #[test]
    fn orphaned_rows_and_other_engine_bindings_are_refused() {
        let fixture = Fixture::new();
        fixture.table("orders", false, |_| {});
        let connection = fixture.state.connection().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        connection
            .execute("DELETE FROM dynamodb_tables", [])
            .unwrap();
        assert!(inspect_native(
            fixture.state.path(),
            &StateCipher::with_key(&[7; 32]),
            |_| Ok(())
        )
        .is_err());
        connection
            .execute("DELETE FROM dynamodb_items", [])
            .unwrap();
        connection.execute_batch("CREATE TABLE locallycloud_service_engines(service TEXT PRIMARY KEY,engine TEXT); INSERT INTO locallycloud_service_engines VALUES('dynamodb','extenddb');").unwrap();
        assert!(inspect_native(
            fixture.state.path(),
            &StateCipher::with_key(&[7; 32]),
            |_| Ok(())
        )
        .is_err());
    }
    #[test]
    fn all_table_counts_share_one_snapshot_even_if_a_writer_commits_during_reporting() {
        let fixture = Fixture::new();
        fixture.table("aaa-first", false, |_| {});
        fixture.table("zzz-second", false, |_| {});
        let mut counts = Vec::new();
        let summary = inspect_native(
            fixture.state.path(),
            &StateCipher::with_key(&[7; 32]),
            |table| {
                if table.table == "aaa-first" {
                    fixture.item(
                        "zzz-second",
                        "late-row",
                        false,
                        &StateCipher::with_key(&[7; 32]),
                    );
                }
                counts.push(table.item_count);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(counts, vec![1, 1]);
        assert_eq!(summary.item_count, 2);
        let count: i64 = fixture
            .state
            .connection()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM dynamodb_items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 3);
    }
    #[test]
    fn engine_marker_is_reported_even_before_native_schema_initialization() {
        let root =
            std::env::temp_dir().join(format!("ddb-inspection-marker-{}", uuid::Uuid::new_v4()));
        let fixture = Fixture {
            state: StateDb::open(root.join("state.db")).unwrap(),
            root,
        };
        fixture.state.connection().unwrap().execute_batch("CREATE TABLE locallycloud_service_engines(service TEXT PRIMARY KEY,engine TEXT); INSERT INTO locallycloud_service_engines VALUES('dynamodb','native');").unwrap();
        let summary = inspect_native(
            fixture.state.path(),
            &StateCipher::with_key(&[7; 32]),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(summary.source_engine, "native");
        assert_eq!(summary.table_count, 0);
        assert!(!summary.source_key_authenticated);
        assert!(!summary.apply_ready);
    }

    #[test]
    fn export_preserves_wire_types_keys_schema_tags_and_source_bytes() {
        let fixture = Fixture::new();
        fixture.table("orders", false, |metadata| {
            metadata["tags"] = json!({"owner":"synthetic"});
            metadata["def"]["billing_mode"] = json!("PROVISIONED");
            metadata["def"]["read_capacity"] = json!(3);
            metadata["def"]["write_capacity"] = json!(4);
            metadata["def"]["warm_throughput"] = json!({"read":12000,"write":4000});
            metadata["def"]["indexes"] = json!([{"name":"by-pk","key_schema":[{"name":"pk","key_type":"Hash"}],
                "projection":{"projection_type":"Include","non_key_attributes":["payload"]},"global":true,
                "read_capacity":5,"write_capacity":6,"warm_throughput":null}]);
        });
        let wire = json!({"pk":{"S":"row"},"payload":{"M":{"nested":{"L":[{"BOOL":true},{"NULL":true},{"B":"AAH/"},{"N":"123.45"}]}}},
            "strings":{"SS":["a","b"]},"numbers":{"NS":["1","2"]},"bytes":{"BS":["AA==","AQ=="]}});
        let item = crate::value::item_from_json(&wire).unwrap();
        let encoded = serde_json::to_string(&item).unwrap();
        fixture
            .state
            .connection()
            .unwrap()
            .execute("UPDATE dynamodb_items SET item=?1", [encoded])
            .unwrap();
        let before = std::fs::read(fixture.state.path()).unwrap();
        let mut records = Vec::new();
        let summary = export_native(
            fixture.state.path(),
            &StateCipher::with_key(&[7; 32]),
            |record| {
                records.push(record);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(summary.item_count, 1);
        assert_eq!(records.len(), 2);
        let NativeRecord::Table {
            account,
            region,
            table,
            create,
            tags,
            ttl_attribute,
            normalized_legacy_aes256,
            item_count,
        } = &records[0]
        else {
            panic!("table must precede item")
        };
        assert_eq!(
            (account.as_str(), region.as_str(), table.as_str()),
            (ACCOUNT, REGION, "orders")
        );
        assert_eq!(*item_count, 1);
        assert_eq!(*ttl_attribute, None);
        assert!(!*normalized_legacy_aes256);
        assert_eq!(*tags, json!([{"Key":"owner","Value":"synthetic"}]));
        assert_eq!(
            create["ProvisionedThroughput"],
            json!({"ReadCapacityUnits":3,"WriteCapacityUnits":4})
        );
        assert_eq!(
            create["GlobalSecondaryIndexes"][0]["ProvisionedThroughput"],
            json!({"ReadCapacityUnits":5,"WriteCapacityUnits":6})
        );
        assert_eq!(
            create["GlobalSecondaryIndexes"][0]["Projection"],
            json!({"ProjectionType":"INCLUDE","NonKeyAttributes":["payload"]})
        );
        let NativeRecord::Item {
            item: actual, key, ..
        } = &records[1]
        else {
            panic!("item expected")
        };
        assert_eq!(actual, &wire);
        assert_eq!(*key, json!({"pk":{"S":"row"}}));
        assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
    }

    #[test]
    fn export_rejects_late_unsupported_metadata_before_first_record() {
        for feature in [
            "invalid-ttl",
            "unsupported-ttl",
            "warm",
            "nested",
            "sse",
            "unknown-table",
            "transaction",
        ] {
            let fixture = Fixture::new();
            fixture.table("aaa-plain", false, |_| {});
            fixture.table("zzz-blocked", feature == "sse", |metadata| match feature {
                "invalid-ttl" => metadata["ttl_attribute"] = json!(""),
                "unsupported-ttl" => metadata["ttl_attribute"] = json!("expires:mañana"),
                "warm" => metadata["def"]["warm_throughput"] = json!({"read":24000,"write":4000}),
                "nested" => metadata["def"]["key_schema"][0]["future_semantics"] = json!(true),
                _ => {}
            });
            match feature {
                "unknown-table" => {
                    fixture
                        .state
                        .connection()
                        .unwrap()
                        .execute_batch("CREATE TABLE dynamodb_future(data TEXT)")
                        .unwrap();
                }
                "transaction" => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    fixture.state.connection().unwrap().execute("INSERT INTO dynamodb_txn_tokens(account,region,token,fingerprint,created_unix,result) VALUES(?1,?2,'token','fingerprint',?3,'{}')",params![ACCOUNT,REGION,now]).unwrap();
                }
                _ => {}
            }
            let mut calls = 0;
            assert!(
                export_native(
                    fixture.state.path(),
                    &StateCipher::with_key(&[7; 32]),
                    |_| {
                        calls += 1;
                        Ok(())
                    }
                )
                .is_err(),
                "{feature}"
            );
            assert_eq!(calls, 0, "{feature}");
        }
    }

    #[test]
    fn export_uses_one_snapshot_even_if_source_changes_after_first_record() {
        let fixture = Fixture::new();
        fixture.table("orders", false, |_| {});
        let cipher = StateCipher::with_key(&[7; 32]);
        let mut emitted = 0;
        let summary = export_native(fixture.state.path(), &cipher, |record| {
            match record {
                NativeRecord::Table { item_count, .. } => {
                    assert_eq!(item_count, 1);
                    fixture.item("orders", "later", false, &cipher);
                }
                NativeRecord::Item { .. } => emitted += 1,
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.item_count, 1);
        assert_eq!(emitted, 1);
        assert_eq!(
            fixture
                .state
                .connection()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM dynamodb_items", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn export_callback_failure_stops_without_source_mutation() {
        let fixture = Fixture::new();
        fixture.table("orders", false, |_| {});
        let before = std::fs::read(fixture.state.path()).unwrap();
        let mut calls = 0;
        let error = export_native(
            fixture.state.path(),
            &StateCipher::with_key(&[7; 32]),
            |_| {
                calls += 1;
                Err(DdbError::Internal("destination unavailable".into()))
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("destination unavailable"));
        assert_eq!(calls, 1);
        assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
    }

    #[test]
    fn export_authenticates_all_source_envelopes_before_any_callback() {
        let fixture = Fixture::new();
        fixture.table("aaa-plain", false, |_| {});
        fixture.table("zzz-encrypted", true, |_| {});
        let mut calls = 0;
        assert!(export_native(
            fixture.state.path(),
            &StateCipher::with_key(&[8; 32]),
            |_| {
                calls += 1;
                Ok(())
            }
        )
        .is_err());
        assert_eq!(calls, 0);
    }

    #[test]
    fn committed_recovery_requires_extenddb_binding_and_keeps_normal_export_closed() {
        let fixture = Fixture::new();
        fixture.table("orders", true, |metadata| {
            metadata["def"]["sse_type"] = Value::Null
        });
        let cipher = StateCipher::with_key(&[7; 32]);
        let mut calls = 0;
        assert!(export_native_recovery(fixture.state.path(), &cipher, |_| {
            calls += 1;
            Ok(())
        })
        .is_err());
        fixture.state.connection().unwrap().execute_batch("CREATE TABLE locallycloud_service_engines(service TEXT PRIMARY KEY,engine TEXT); INSERT INTO locallycloud_service_engines VALUES('dynamodb','native');").unwrap();
        assert!(export_native_recovery(fixture.state.path(), &cipher, |_| {
            calls += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(calls, 0);
        fixture
            .state
            .connection()
            .unwrap()
            .execute(
                "UPDATE locallycloud_service_engines SET engine='extenddb'",
                [],
            )
            .unwrap();
        assert!(export_native(fixture.state.path(), &cipher, |_| {
            calls += 1;
            Ok(())
        })
        .is_err());
        assert!(inspect_native(fixture.state.path(), &cipher, |_| Ok(())).is_err());
        assert!(export_native_recovery(
            fixture.state.path(),
            &StateCipher::with_key(&[8; 32]),
            |_| {
                calls += 1;
                Ok(())
            }
        )
        .is_err());
        assert_eq!(calls, 0);
        let before = std::fs::read(fixture.state.path()).unwrap();
        let summary = export_native_recovery(fixture.state.path(), &cipher, |_| {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.source_engine, "extenddb");
        assert_eq!(summary.table_count, 1);
        assert!(summary.source_key_authenticated);
        assert_eq!(calls, 2);
        assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
    }

    #[test]
    fn engine_binding_is_read_only_bounded_and_does_not_create_missing_source() {
        let fixture = Fixture::new();
        let before = std::fs::read(fixture.state.path()).unwrap();
        assert_eq!(engine_binding(fixture.state.path()).unwrap(), None);
        assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
        let missing = fixture.root.join("missing.db");
        assert!(engine_binding(&missing).is_err());
        assert!(!missing.exists());
        fixture.state.connection().unwrap().execute_batch("CREATE TABLE locallycloud_service_engines(service TEXT PRIMARY KEY,engine TEXT); INSERT INTO locallycloud_service_engines VALUES('dynamodb','native');").unwrap();
        for name in ["native", "extenddb", "future"] {
            fixture
                .state
                .connection()
                .unwrap()
                .execute("UPDATE locallycloud_service_engines SET engine=?1", [name])
                .unwrap();
            let before = std::fs::read(fixture.state.path()).unwrap();
            assert_eq!(
                engine_binding(fixture.state.path()).unwrap().as_deref(),
                Some(name)
            );
            assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
        }
        fixture
            .state
            .connection()
            .unwrap()
            .execute(
                "UPDATE locallycloud_service_engines SET engine=?1",
                ["x".repeat(65)],
            )
            .unwrap();
        assert!(engine_binding(fixture.state.path()).is_err());
    }

    #[test]
    fn export_preserves_enabled_and_disabled_ttl_without_reaping_expired_items() {
        for enabled in [false, true] {
            let fixture = Fixture::new();
            fixture.table("orders", false, |metadata| {
                if enabled {
                    metadata["ttl_attribute"] = json!("expires");
                }
            });
            let item = crate::value::item_from_json(&json!({"pk":{"S":"row"},"expires":{"N":"1"}}))
                .unwrap();
            fixture
                .state
                .connection()
                .unwrap()
                .execute(
                    "UPDATE dynamodb_items SET item=?1",
                    [serde_json::to_string(&item).unwrap()],
                )
                .unwrap();
            let before = std::fs::read(fixture.state.path()).unwrap();
            let mut metadata_seen = false;
            let mut expired_seen = false;
            let summary = export_native(
                fixture.state.path(),
                &StateCipher::with_key(&[7; 32]),
                |record| {
                    match record {
                        NativeRecord::Table { ttl_attribute, .. } => {
                            assert_eq!(
                                ttl_attribute.as_deref(),
                                if enabled { Some("expires") } else { None }
                            );
                            metadata_seen = true;
                        }
                        NativeRecord::Item { item, .. } => {
                            assert_eq!(item["expires"], json!({"N":"1"}));
                            expired_seen = true;
                        }
                    }
                    Ok(())
                },
            )
            .unwrap();
            assert!(metadata_seen && expired_seen);
            assert_eq!(summary.item_count, 1);
            assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
        }
    }

    #[test]
    fn legacy_aes256_requires_opt_in_and_reports_metadata_normalization_without_source_changes() {
        let fixture = Fixture::new();
        fixture.table("aaa-plain", false, |_| {});
        fixture.table("zzz-legacy", true, |_| {});
        let cipher = StateCipher::with_key(&[7; 32]);
        let before = std::fs::read(fixture.state.path()).unwrap();
        let mut calls = 0;
        assert!(export_native(fixture.state.path(), &cipher, |_| {
            calls += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(calls, 0);
        assert!(export_native_with_policy(
            fixture.state.path(),
            &StateCipher::with_key(&[8; 32]),
            MigrationPolicy::NormalizeLegacyAes256,
            |_| {
                calls += 1;
                Ok(())
            }
        )
        .is_err());
        assert_eq!(calls, 0);
        let mut normalized = 0;
        let mut items = 0;
        let summary = export_native_with_policy(
            fixture.state.path(),
            &cipher,
            MigrationPolicy::NormalizeLegacyAes256,
            |record| {
                match record {
                    NativeRecord::Table {
                        table,
                        create,
                        normalized_legacy_aes256,
                        ..
                    } => {
                        assert_eq!(normalized_legacy_aes256, table == "zzz-legacy");
                        if normalized_legacy_aes256 {
                            normalized += 1;
                        }
                        assert!(create.get("SSESpecification").is_none());
                    }
                    NativeRecord::Item { .. } => items += 1,
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(normalized, 1);
        assert_eq!(items, 2);
        assert!(summary.source_key_authenticated);
        let mut found = false;
        inspect_native(fixture.state.path(), &cipher, |table| {
            if table.table == "zzz-legacy" {
                assert_eq!(table.sse_type.as_deref(), Some("AES256"));
                assert!(table
                    .proposed_normalization
                    .unwrap()
                    .contains("Explicit opt-in"));
                assert!(table
                    .blocking_features
                    .iter()
                    .any(|feature| matches!(feature, BlockingFeature::ServerSideEncryption)));
                found = true;
            }
            Ok(())
        })
        .unwrap();
        assert!(found);
        assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
    }

    #[test]
    fn normalization_never_accepts_kms_unknown_types_or_other_unsupported_features() {
        for kind in ["KMS", "FUTURE", "AES256-with-pitr"] {
            let fixture = Fixture::new();
            fixture.table("aaa-plain", false, |_| {});
            fixture.table("zzz-blocked", true, |metadata| match kind {
                "AES256-with-pitr" => metadata["pitr_enabled"] = json!(true),
                _ => metadata["def"]["sse_type"] = json!(kind),
            });
            let cipher = StateCipher::with_key(&[7; 32]);
            let before = std::fs::read(fixture.state.path()).unwrap();
            let mut calls = 0;
            assert!(
                export_native_with_policy(
                    fixture.state.path(),
                    &cipher,
                    MigrationPolicy::NormalizeLegacyAes256,
                    |_| {
                        calls += 1;
                        Ok(())
                    }
                )
                .is_err(),
                "{kind}"
            );
            assert_eq!(calls, 0, "{kind}");
            assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
        }
    }

    #[test]
    fn committed_legacy_aes256_recovery_also_requires_explicit_normalization() {
        let fixture = Fixture::new();
        fixture.table("orders", true, |_| {});
        fixture.state.connection().unwrap().execute_batch("CREATE TABLE locallycloud_service_engines(service TEXT PRIMARY KEY,engine TEXT); INSERT INTO locallycloud_service_engines VALUES('dynamodb','extenddb');").unwrap();
        let before = std::fs::read(fixture.state.path()).unwrap();
        let cipher = StateCipher::with_key(&[7; 32]);
        let mut calls = 0;
        assert!(export_native_recovery(fixture.state.path(), &cipher, |_| {
            calls += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(calls, 0);
        export_native_recovery_with_policy(
            fixture.state.path(),
            &cipher,
            MigrationPolicy::NormalizeLegacyAes256,
            |_| {
                calls += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
    }
}
