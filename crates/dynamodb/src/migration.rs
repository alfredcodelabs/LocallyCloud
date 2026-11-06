//! Bounded, read-only native-engine inspection. This does not import or switch engines.
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use locallycloud_state::StateCipher;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;

use crate::error::DdbError;
use crate::store::{StoredKey, StreamRecord, TableData};

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
    pub secondary_indexes: usize,
    pub blocking_features: Vec<BlockingFeature>,
}

#[derive(Serialize)]
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

fn source_schema(connection: &Connection) -> Result<(BTreeSet<String>, bool), DdbError> {
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
            Some("native") => {
                native_bound = true;
            }
            Some("extenddb") => return Err(DdbError::Validation(
                "This state already selects ExtendDB; native migration inspection does not apply"
                    .into(),
            )),
            Some(_) => return Err(invalid()),
        }
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
    mut visit: impl FnMut(TableInspection) -> Result<(), DdbError>,
) -> Result<InspectionSummary, DdbError> {
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
    let (schema, native_bound) = source_schema(&connection)?;
    check_orphans(&connection, &schema)?;
    let encrypted = authenticate(&connection, cipher, &schema)?;
    let mut summary = InspectionSummary {
        source_engine: if native_bound || schema.contains("dynamodb_tables") {
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
        let item_count = validate_items(&connection, cipher, &schema, scope, &data)?;
        let stream_records = scoped_count(&connection, &schema, "dynamodb_stream_records", scope)?;
        let recovery_versions =
            scoped_count(&connection, &schema, "dynamodb_recovery_items", scope)?;
        let replication_versions =
            scoped_count(&connection, &schema, "dynamodb_replica_versions", scope)?;
        let recovery_windows = scoped_count(&connection, &schema, "dynamodb_recovery", scope)?;
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
}
