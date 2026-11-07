//! Streaming export for an offline importer; no source mutation or engine selection.
use std::path::Path;

use locallycloud_state::StateCipher;
use rusqlite::params;
use serde_json::{json, Value};

use super::{
    inspect_snapshot_with_binding, invalid, open_snapshot, scoped_count,
    source_schema_with_binding, BlockingFeature, InspectionSummary, SourceBinding, MAX_RECORD,
};
use crate::error::DdbError;
use crate::store::{KeySchemaElement, KeyType, ProjectionType, TableData, WarmThroughput};
use crate::value::{item_from_json, item_size, item_to_json, Item, MAX_ITEM_SIZE};

/// Metadata preservation is the default; normalization always requires explicit consent.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum MigrationPolicy {
    #[default]
    Preserve,
    NormalizeLegacyAes256,
}

impl MigrationPolicy {
    fn normalizes(self, sse_type: Option<&str>) -> bool {
        self == Self::NormalizeLegacyAes256 && sse_type == Some("AES256")
    }
}

/// Each table precedes its items; values and primary keys use DynamoDB JSON wire types.
#[derive(Debug)]
pub enum NativeRecord {
    Table {
        account: String,
        region: String,
        table: String,
        create: Value,
        /// AWS tag array containing `Key` and `Value` fields.
        tags: Value,
        /// TTL configuration; the offline importer must suspend expiration until cutover.
        ttl_attribute: Option<String>,
        /// Legacy SSE metadata is deliberately replaced by the default-owned descriptor.
        normalized_legacy_aes256: bool,
        item_count: u64,
    },
    Item {
        account: String,
        region: String,
        table: String,
        item: Value,
        key: Value,
    },
}

fn unsupported(feature: &str) -> DdbError {
    DdbError::Validation(format!(
        "Native DynamoDB migration cannot preserve {feature}; source remains unchanged"
    ))
}

fn fields(value: &Value, names: &[&str]) -> Result<(), DdbError> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.keys().any(|key| !names.contains(&key.as_str())) {
        return Err(unsupported("unknown nested metadata"));
    }
    Ok(())
}

// Serde ignores unknown struct fields; check nested definitions before serializing a new schema.
fn nested_metadata(encoded: &str, cipher: &StateCipher, scope: [&str; 3]) -> Result<(), DdbError> {
    let plaintext = crate::recovery::decode(
        Some(cipher),
        &["dynamodb-metadata", scope[0], scope[1], scope[2]],
        encoded,
    )?;
    let metadata: Value = serde_json::from_str(&plaintext).map_err(|_| invalid())?;
    let definition = metadata.get("def").ok_or_else(invalid)?;
    for field in ["key_schema", "attribute_definitions"] {
        let allowed: &[&str] = match field {
            "key_schema" => &["name", "key_type"],
            _ => &["name", "attr_type"],
        };
        for entry in definition
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(invalid)?
        {
            fields(entry, allowed)?;
        }
    }
    for index in definition
        .get("indexes")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?
    {
        fields(
            index,
            &[
                "name",
                "key_schema",
                "projection",
                "global",
                "read_capacity",
                "write_capacity",
                "warm_throughput",
            ],
        )?;
        for key in index
            .get("key_schema")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?
        {
            fields(key, &["name", "key_type"])?;
        }
        fields(
            index.get("projection").ok_or_else(invalid)?,
            &["projection_type", "non_key_attributes"],
        )?;
        if let Some(warm) = index.get("warm_throughput").filter(|v| !v.is_null()) {
            fields(warm, &["read", "write"])?;
        }
    }
    if let Some(warm) = definition.get("warm_throughput").filter(|v| !v.is_null()) {
        fields(warm, &["read", "write"])?;
    }
    if let Some(stream) = definition.get("stream_spec").filter(|v| !v.is_null()) {
        fields(stream, &["enabled", "view_type"])?;
    }
    Ok(())
}

fn default_warm(warm: Option<WarmThroughput>, read: u64, write: u64) -> Result<(), DdbError> {
    let baseline = WarmThroughput::baseline(read, write);
    if warm.is_some_and(|warm| warm.read != baseline.read || warm.write != baseline.write) {
        return Err(unsupported("custom warm throughput"));
    }
    Ok(())
}

fn keys(schema: &[KeySchemaElement]) -> Value {
    Value::Array(schema.iter().map(|key| json!({"AttributeName":key.name,"KeyType":match key.key_type {KeyType::Hash=>"HASH",KeyType::Range=>"RANGE"}})).collect())
}

fn throughput(read: u64, write: u64) -> Result<Value, DdbError> {
    if read == 0 || write == 0 {
        return Err(invalid());
    }
    Ok(json!({"ReadCapacityUnits":read,"WriteCapacityUnits":write}))
}

fn create_table(data: &TableData) -> Result<Value, DdbError> {
    let def = &data.def;
    if data.ttl_attribute.as_ref().is_some_and(|attribute| {
        attribute.is_empty() || attribute.len() > 255 || attribute.contains('\0')
    }) {
        return Err(unsupported("invalid TTL attribute metadata"));
    }
    if data.ttl_attribute.as_ref().is_some_and(|attribute| {
        !attribute
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    }) {
        return Err(unsupported(
            "TTL attribute names not supported by the optional engine",
        ));
    }
    let provisioned = match def.billing_mode.as_str() {
        "PROVISIONED" => true,
        "PAY_PER_REQUEST" if def.read_capacity == 0 && def.write_capacity == 0 => false,
        _ => return Err(unsupported("billing or capacity metadata")),
    };
    default_warm(def.warm_throughput, def.read_capacity, def.write_capacity)?;
    let mut create = json!({"TableName":def.name,"KeySchema":keys(&def.key_schema),
        "AttributeDefinitions":def.attribute_definitions.iter().map(|attr|json!({"AttributeName":attr.name,"AttributeType":attr.attr_type})).collect::<Vec<_>>(),
        "BillingMode":def.billing_mode});
    if provisioned {
        create["ProvisionedThroughput"] = throughput(def.read_capacity, def.write_capacity)?;
    }
    for global in [false, true] {
        let mut indexes = Vec::new();
        for index in def.indexes.iter().filter(|index| index.global == global) {
            default_warm(
                index.warm_throughput,
                index.read_capacity,
                index.write_capacity,
            )?;
            let projection_type = match index.projection.projection_type {
                ProjectionType::All => "ALL",
                ProjectionType::KeysOnly => "KEYS_ONLY",
                ProjectionType::Include => "INCLUDE",
            };
            let mut projection = json!({"ProjectionType":projection_type});
            if !index.projection.non_key_attributes.is_empty() {
                if projection_type != "INCLUDE" {
                    return Err(invalid());
                }
                projection["NonKeyAttributes"] = json!(index.projection.non_key_attributes);
            }
            let mut output = json!({"IndexName":index.name,"KeySchema":keys(&index.key_schema),"Projection":projection});
            if global && provisioned {
                output["ProvisionedThroughput"] =
                    throughput(index.read_capacity, index.write_capacity)?;
            } else if index.read_capacity != 0 || index.write_capacity != 0 {
                return Err(unsupported("secondary index capacity metadata"));
            }
            indexes.push(output);
        }
        if !indexes.is_empty() {
            create[if global {
                "GlobalSecondaryIndexes"
            } else {
                "LocalSecondaryIndexes"
            }] = Value::Array(indexes);
        }
    }
    if let Some(stream) = &def.stream_spec {
        create["StreamSpecification"] =
            json!({"StreamEnabled":stream.enabled,"StreamViewType":stream.view_type});
    }
    Ok(create)
}

fn wire_item(item: &Item, data: &TableData) -> Result<(Value, Value), DdbError> {
    if item_size(item) > MAX_ITEM_SIZE {
        return Err(invalid());
    }
    let wire = item_to_json(item);
    if item_from_json(&wire).map_err(|_| invalid())? != *item {
        return Err(invalid());
    }
    let mut key = serde_json::Map::new();
    for field in &data.def.key_schema {
        key.insert(
            field.name.clone(),
            item.get(&field.name).ok_or_else(invalid)?.to_json(),
        );
    }
    Ok((wire, Value::Object(key)))
}

/// Authenticate and validate the complete snapshot before yielding anything. The caller
/// must hold the source runtime lock and retain a failed destination as uncommitted.
/// Memory is bounded by one metadata record and one item, independent of source size.
pub fn export_native(
    path: &Path,
    cipher: &StateCipher,
    visit: impl FnMut(NativeRecord) -> Result<(), DdbError>,
) -> Result<InspectionSummary, DdbError> {
    export_native_with_policy(path, cipher, MigrationPolicy::Preserve, visit)
}

pub fn export_native_with_policy(
    path: &Path,
    cipher: &StateCipher,
    policy: MigrationPolicy,
    visit: impl FnMut(NativeRecord) -> Result<(), DdbError>,
) -> Result<InspectionSummary, DdbError> {
    export_with_binding(path, cipher, SourceBinding::Native, policy, visit)
}

/// Re-read the preserved native source solely for an already-committed cutover recovery.
/// The caller must validate its durable verified/published intent before calling this,
/// then authenticate and compare the final worker before marking that intent complete.
/// Unlike normal export, this requires the source engine marker to be exactly ExtendDB.
pub fn export_native_recovery(
    path: &Path,
    cipher: &StateCipher,
    visit: impl FnMut(NativeRecord) -> Result<(), DdbError>,
) -> Result<InspectionSummary, DdbError> {
    export_native_recovery_with_policy(path, cipher, MigrationPolicy::Preserve, visit)
}

pub fn export_native_recovery_with_policy(
    path: &Path,
    cipher: &StateCipher,
    policy: MigrationPolicy,
    visit: impl FnMut(NativeRecord) -> Result<(), DdbError>,
) -> Result<InspectionSummary, DdbError> {
    export_with_binding(
        path,
        cipher,
        SourceBinding::CommittedExtendDb,
        policy,
        visit,
    )
}

fn export_with_binding(
    path: &Path,
    cipher: &StateCipher,
    binding: SourceBinding,
    policy: MigrationPolicy,
    mut visit: impl FnMut(NativeRecord) -> Result<(), DdbError>,
) -> Result<InspectionSummary, DdbError> {
    let connection = open_snapshot(path)?;
    let summary = inspect_snapshot_with_binding(&connection, cipher, binding, |table| {
        if table.blocking_features.iter().any(|feature| {
            !matches!(feature, BlockingFeature::ServerSideEncryption)
                || !policy.normalizes(table.sse_type.as_deref())
        }) {
            return Err(unsupported(
                "the table features reported by migrate-dynamodb --dry-run",
            ));
        }
        Ok(())
    })?;
    if !summary.unrecognized_storage_tables.is_empty() {
        return Err(unsupported("unrecognized native storage tables"));
    }
    if summary.active_transaction_tokens > 0 {
        return Err(unsupported("unexpired transaction idempotency tokens"));
    }
    let (schema, _) = source_schema_with_binding(&connection, binding)?;
    if !schema.contains("dynamodb_tables") {
        return Ok(summary);
    }
    // Preflight all schemas and wire values before callbacks; reuse the same SQLite snapshot.
    for emit in [false, true] {
        let mut query=connection.prepare("SELECT account,region,name,CASE WHEN length(CAST(metadata AS BLOB))<=?1 THEN metadata END FROM dynamodb_tables ORDER BY account,region,name").map_err(|_|invalid())?;
        let mut rows = query.query([MAX_RECORD]).map_err(|_| invalid())?;
        while let Some(row) = rows.next().map_err(|_| invalid())? {
            let account: String = row.get(0).map_err(|_| invalid())?;
            let region: String = row.get(1).map_err(|_| invalid())?;
            let table: String = row.get(2).map_err(|_| invalid())?;
            let encoded: String = row.get(3).map_err(|_| invalid())?;
            let scope = [account.as_str(), region.as_str(), table.as_str()];
            nested_metadata(&encoded, cipher, scope)?;
            let (data, _) =
                crate::store::migration_table(cipher, &account, &region, &table, &encoded)?;
            let create = create_table(&data)?;
            if emit {
                let count = scoped_count(&connection, &schema, "dynamodb_items", scope)?;
                visit(NativeRecord::Table {
                    account: account.clone(),
                    region: region.clone(),
                    table: table.clone(),
                    create,
                    tags: Value::Array(
                        data.tags
                            .iter()
                            .map(|(key, value)| json!({"Key":key,"Value":value}))
                            .collect(),
                    ),
                    ttl_attribute: data.ttl_attribute.clone(),
                    normalized_legacy_aes256: policy.normalizes(data.def.sse_type.as_deref()),
                    item_count: count,
                })?;
            }
            if !schema.contains("dynamodb_items") {
                continue;
            }
            let mut items=connection.prepare("SELECT CASE WHEN length(CAST(item_key AS BLOB))<=?4 THEN item_key END,CASE WHEN length(CAST(item AS BLOB))<=?4 THEN item END FROM dynamodb_items WHERE account=?1 AND region=?2 AND name=?3 ORDER BY item_key").map_err(|_|invalid())?;
            let mut items = items
                .query(params![account, region, table, MAX_RECORD])
                .map_err(|_| invalid())?;
            while let Some(row) = items.next().map_err(|_| invalid())? {
                let key: String = row.get(0).map_err(|_| invalid())?;
                let encoded: String = row.get(1).map_err(|_| invalid())?;
                let item = crate::recovery::decode_item(Some(cipher), &scope, &key, &encoded)?;
                let (item, key) = wire_item(&item, &data)?;
                if emit {
                    visit(NativeRecord::Item {
                        account: account.clone(),
                        region: region.clone(),
                        table: table.clone(),
                        item,
                        key,
                    })?;
                }
            }
        }
    }
    Ok(summary)
}
