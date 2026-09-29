//! DynamoDB operation handlers. Each takes the parsed JSON 1.0 request body and returns the
//! JSON 1.0 response body (or a `DdbError`). Table state is accessed through per-table locks.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use serde_json::{json, Map, Value};
use tokio::sync::RwLock;

use localcloud_core::registry::ServiceRegistry;

use crate::error::{CancellationReason, DdbError};
use crate::expression::{ConditionExpression, ProjectionExpression, UpdateExpression};
use crate::store::{
    AttributeDefinition, KeySchemaElement, KeyType, KinesisDestination, Projection, ProjectionType,
    SecondaryIndex, StoredKey, StreamSpecification, TableData, TableDefinition, TableStore,
};
use crate::value::{
    item_from_json, item_size, item_to_json, number_cmp, AttributeValue, Item, MAX_ITEM_SIZE,
};

/// Request context: resolved region and account for the call.
pub struct Ctx<'a> {
    pub store: &'a TableStore,
    pub region: &'a str,
    pub account: &'a str,
}

// ============================ Request helpers ==================================

fn req_str<'a>(req: &'a Value, field: &str) -> Result<&'a str, DdbError> {
    req.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| DdbError::Validation(format!("{field} is required")))
}

fn parse_names(req: &Value) -> HashMap<String, String> {
    req.get("ExpressionAttributeNames")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_values(req: &Value) -> Result<HashMap<String, AttributeValue>, DdbError> {
    let mut out = HashMap::new();
    if let Some(obj) = req
        .get("ExpressionAttributeValues")
        .and_then(Value::as_object)
    {
        for (k, v) in obj {
            out.insert(k.clone(), AttributeValue::from_json(v)?);
        }
    }
    Ok(out)
}

fn now_epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

async fn get_table(ctx: &Ctx<'_>, name: &str) -> Result<Arc<RwLock<TableData>>, DdbError> {
    ctx.store.get(ctx.account, ctx.region, name).ok_or_else(|| {
        DdbError::ResourceNotFound(format!(
            "Requested resource not found: Table: {name} not found"
        ))
    })
}

/// Parse a `Key` request object into the key attributes of an item.
fn parse_key(req: &Value) -> Result<Item, DdbError> {
    let key = req
        .get("Key")
        .ok_or_else(|| DdbError::Validation("Key is required".into()))?;
    item_from_json(key)
}

// ============================ Table lifecycle ==================================

fn parse_key_schema(value: &Value) -> Result<Vec<KeySchemaElement>, DdbError> {
    let arr = value
        .as_array()
        .ok_or_else(|| DdbError::Validation("KeySchema must be an array".into()))?;
    let mut out = Vec::new();
    for e in arr {
        let name = req_str(e, "AttributeName")?.to_string();
        let key_type = match req_str(e, "KeyType")? {
            "HASH" => KeyType::Hash,
            "RANGE" => KeyType::Range,
            other => return Err(DdbError::Validation(format!("invalid KeyType {other}"))),
        };
        out.push(KeySchemaElement { name, key_type });
    }
    if out.iter().filter(|k| k.key_type == KeyType::Hash).count() != 1 {
        return Err(DdbError::Validation(
            "exactly one HASH key is required".into(),
        ));
    }
    if out.iter().filter(|k| k.key_type == KeyType::Range).count() > 1 {
        return Err(DdbError::Validation(
            "at most one RANGE key is allowed".into(),
        ));
    }
    Ok(out)
}

fn parse_projection(value: &Value) -> Result<Projection, DdbError> {
    let projection_type = match req_str(value, "ProjectionType")? {
        "ALL" => ProjectionType::All,
        "KEYS_ONLY" => ProjectionType::KeysOnly,
        "INCLUDE" => ProjectionType::Include,
        other => {
            return Err(DdbError::Validation(format!(
                "invalid ProjectionType {other}"
            )))
        }
    };
    let non_key_attributes = value
        .get("NonKeyAttributes")
        .and_then(Value::as_array)
        .map(|attributes| {
            attributes
                .iter()
                .map(|attribute| {
                    attribute.as_str().map(str::to_string).ok_or_else(|| {
                        DdbError::Validation("NonKeyAttributes must contain strings".into())
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    if projection_type == ProjectionType::Include && non_key_attributes.is_empty() {
        return Err(DdbError::Validation(
            "NonKeyAttributes is required for INCLUDE projection".into(),
        ));
    }
    if projection_type != ProjectionType::Include && !non_key_attributes.is_empty() {
        return Err(DdbError::Validation(
            "NonKeyAttributes is only valid for INCLUDE projection".into(),
        ));
    }
    Ok(Projection {
        projection_type,
        non_key_attributes,
    })
}

fn parse_indexes(req: &Value, field: &str, global: bool) -> Result<Vec<SecondaryIndex>, DdbError> {
    let mut out = Vec::new();
    if let Some(arr) = req.get(field).and_then(Value::as_array) {
        for idx in arr {
            let name = req_str(idx, "IndexName")?.to_string();
            let key_schema = parse_key_schema(
                idx.get("KeySchema")
                    .ok_or_else(|| DdbError::Validation("index KeySchema required".into()))?,
            )?;
            let projection = parse_projection(
                idx.get("Projection")
                    .ok_or_else(|| DdbError::Validation("index Projection required".into()))?,
            )?;
            out.push(SecondaryIndex {
                name,
                key_schema,
                projection,
                global,
            });
        }
    }
    Ok(out)
}

pub async fn create_table(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?.to_string();
    let key_schema = parse_key_schema(
        req.get("KeySchema")
            .ok_or_else(|| DdbError::Validation("KeySchema is required".into()))?,
    )?;
    let attr_defs_value = req
        .get("AttributeDefinitions")
        .and_then(Value::as_array)
        .ok_or_else(|| DdbError::Validation("AttributeDefinitions is required".into()))?;
    let mut attribute_definitions = Vec::new();
    let mut definition_names = std::collections::HashSet::new();
    for definition in attr_defs_value {
        let name = req_str(definition, "AttributeName")?.to_string();
        let attr_type = req_str(definition, "AttributeType")?.to_string();
        if !matches!(attr_type.as_str(), "S" | "N" | "B") {
            return Err(DdbError::Validation(format!(
                "invalid AttributeType {attr_type}"
            )));
        }
        if !definition_names.insert(name.clone()) {
            return Err(DdbError::Validation(format!(
                "duplicate AttributeDefinition for {name}"
            )));
        }
        attribute_definitions.push(AttributeDefinition { name, attr_type });
    }

    let indexes = {
        let mut gsis = parse_indexes(req, "GlobalSecondaryIndexes", true)?;
        gsis.extend(parse_indexes(req, "LocalSecondaryIndexes", false)?);
        gsis
    };
    let mut used_attributes: std::collections::HashSet<String> =
        key_schema.iter().map(|key| key.name.clone()).collect();
    let mut index_names = std::collections::HashSet::new();
    let table_hash = key_schema
        .iter()
        .find(|key| key.key_type == KeyType::Hash)
        .unwrap()
        .name
        .as_str();
    let table_has_range = key_schema.iter().any(|key| key.key_type == KeyType::Range);
    for index in &indexes {
        if !index_names.insert(index.name.as_str()) {
            return Err(DdbError::Validation(format!(
                "duplicate index name {}",
                index.name
            )));
        }
        for key in &index.key_schema {
            used_attributes.insert(key.name.clone());
        }
        if !index.global {
            let index_hash = index
                .key_schema
                .iter()
                .find(|key| key.key_type == KeyType::Hash)
                .unwrap();
            let index_has_range = index
                .key_schema
                .iter()
                .any(|key| key.key_type == KeyType::Range);
            if !table_has_range || index_hash.name != table_hash || !index_has_range {
                return Err(DdbError::Validation(
                    "LocalSecondaryIndex must share the table HASH key and define a RANGE key"
                        .into(),
                ));
            }
        }
    }
    for attribute in &used_attributes {
        if !definition_names.contains(attribute) {
            return Err(DdbError::Validation(format!(
                "key attribute {attribute} has no AttributeDefinition"
            )));
        }
    }
    for definition in &definition_names {
        if !used_attributes.contains(definition) {
            return Err(DdbError::Validation(format!(
                "AttributeDefinition {definition} is not used in any key schema"
            )));
        }
    }

    let billing_mode = req
        .get("BillingMode")
        .and_then(Value::as_str)
        .unwrap_or("PROVISIONED");
    if !matches!(billing_mode, "PROVISIONED" | "PAY_PER_REQUEST") {
        return Err(DdbError::Validation(format!(
            "invalid BillingMode {billing_mode}"
        )));
    }
    let (read_capacity, write_capacity) = match req.get("ProvisionedThroughput") {
        Some(pt) => (
            pt.get("ReadCapacityUnits")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            pt.get("WriteCapacityUnits")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        ),
        None => (0, 0),
    };
    if billing_mode == "PAY_PER_REQUEST" && req.get("ProvisionedThroughput").is_some() {
        return Err(DdbError::Validation(
            "ProvisionedThroughput cannot be specified with PAY_PER_REQUEST billing".into(),
        ));
    }
    if billing_mode == "PROVISIONED" && (read_capacity == 0 || write_capacity == 0) {
        return Err(DdbError::Validation(
            "ProvisionedThroughput is required for PROVISIONED billing".into(),
        ));
    }
    if let Some(gsis) = req.get("GlobalSecondaryIndexes").and_then(Value::as_array) {
        for gsi in gsis {
            let throughput = gsi.get("ProvisionedThroughput");
            if billing_mode == "PAY_PER_REQUEST" && throughput.is_some() {
                return Err(DdbError::Validation(
                    "GSI ProvisionedThroughput cannot be specified with PAY_PER_REQUEST billing"
                        .into(),
                ));
            }
            if billing_mode == "PROVISIONED" {
                let (read, write) = throughput_pair(throughput);
                if read == 0 || write == 0 {
                    return Err(DdbError::Validation(
                        "ProvisionedThroughput is required for every GSI in PROVISIONED billing"
                            .into(),
                    ));
                }
            }
        }
    }
    let stream_spec = req
        .get("StreamSpecification")
        .map(parse_stream_spec)
        .transpose()?;
    let def = TableDefinition {
        name: name.clone(),
        arn: format!(
            "arn:aws:dynamodb:{}:{}:table/{name}",
            ctx.region, ctx.account
        ),
        key_schema,
        attribute_definitions,
        indexes,
        billing_mode: billing_mode.to_string(),
        read_capacity,
        write_capacity,
        stream_spec,
        creation_date: now_epoch_secs().to_string(),
        status: "ACTIVE".to_string(),
        replicas: Vec::new(),
    };
    let tags = req
        .get("Tags")
        .and_then(Value::as_array)
        .map(|a| parse_tag_list(a))
        .unwrap_or_default();
    let data = TableData::new(def.clone(), tags, None, false);
    ctx.store.create(ctx.account, ctx.region, data)?;
    Ok(json!({ "TableDescription": describe(&def, 0) }))
}

fn parse_stream_spec(value: &Value) -> Result<StreamSpecification, DdbError> {
    let enabled = value
        .get("StreamEnabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| DdbError::Validation("StreamEnabled is required".into()))?;
    let view_type = value.get("StreamViewType").and_then(Value::as_str);
    if enabled
        && !matches!(
            view_type,
            Some("KEYS_ONLY" | "NEW_IMAGE" | "OLD_IMAGE" | "NEW_AND_OLD_IMAGES")
        )
    {
        return Err(DdbError::Validation(
            "a valid StreamViewType is required when StreamEnabled is true".into(),
        ));
    }
    if !enabled && view_type.is_some() {
        return Err(DdbError::Validation(
            "StreamViewType cannot be specified when StreamEnabled is false".into(),
        ));
    }
    Ok(StreamSpecification {
        enabled,
        view_type: view_type.unwrap_or("NEW_AND_OLD_IMAGES").to_string(),
    })
}

fn parse_tag_list(arr: &[Value]) -> std::collections::BTreeMap<String, String> {
    arr.iter()
        .filter_map(|t| {
            let k = t.get("Key").and_then(Value::as_str)?;
            let v = t.get("Value").and_then(Value::as_str)?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// Build the table description JSON.
fn describe(def: &TableDefinition, item_count: usize) -> Value {
    let key_schema: Vec<Value> = def
        .key_schema
        .iter()
        .map(|k| {
            json!({
                "AttributeName": k.name,
                "KeyType": match k.key_type { KeyType::Hash => "HASH", KeyType::Range => "RANGE" }
            })
        })
        .collect();
    let attr_defs: Vec<Value> = def
        .attribute_definitions
        .iter()
        .map(|a| json!({ "AttributeName": a.name, "AttributeType": a.attr_type }))
        .collect();
    let mut out = json!({
        "TableName": def.name,
        "TableArn": def.arn,
        "TableId": def.arn,
        "TableStatus": def.status,
        "KeySchema": key_schema,
        "AttributeDefinitions": attr_defs,
        "CreationDateTime": def.creation_date.parse::<f64>().unwrap_or(0.0),
        "ItemCount": item_count,
        "TableSizeBytes": 0,
        "BillingModeSummary": { "BillingMode": def.billing_mode },
        "ProvisionedThroughput": {
            "ReadCapacityUnits": def.read_capacity,
            "WriteCapacityUnits": def.write_capacity,
            "NumberOfDecreasesToday": 0
        }
    });
    if let Some(stream) = &def.stream_spec {
        if stream.enabled {
            let stream_arn = format!("{}/stream/{}", def.arn, def.creation_date);
            out["LatestStreamArn"] = json!(stream_arn);
            out["LatestStreamLabel"] = json!(def.creation_date);
            out["StreamSpecification"] =
                json!({ "StreamEnabled": true, "StreamViewType": stream.view_type });
        }
    }
    let gsis: Vec<Value> = def
        .indexes
        .iter()
        .filter(|i| i.global)
        .map(describe_index)
        .collect();
    let lsis: Vec<Value> = def
        .indexes
        .iter()
        .filter(|i| !i.global)
        .map(describe_index)
        .collect();
    if !gsis.is_empty() {
        out["GlobalSecondaryIndexes"] = json!(gsis);
    }
    if !lsis.is_empty() {
        out["LocalSecondaryIndexes"] = json!(lsis);
    }
    if !def.replicas.is_empty() {
        out["GlobalTableVersion"] = json!("2019.11.21");
        out["Replicas"] = json!(def
            .replicas
            .iter()
            .map(|region| { json!({ "RegionName": region, "ReplicaStatus": "ACTIVE" }) })
            .collect::<Vec<_>>());
    }
    out
}

fn describe_index(idx: &SecondaryIndex) -> Value {
    let key_schema: Vec<Value> = idx
        .key_schema
        .iter()
        .map(|k| {
            json!({
                "AttributeName": k.name,
                "KeyType": match k.key_type { KeyType::Hash => "HASH", KeyType::Range => "RANGE" }
            })
        })
        .collect();
    let projection_type = match idx.projection.projection_type {
        ProjectionType::All => "ALL",
        ProjectionType::KeysOnly => "KEYS_ONLY",
        ProjectionType::Include => "INCLUDE",
    };
    json!({
        "IndexName": idx.name,
        "KeySchema": key_schema,
        "Projection": {
            "ProjectionType": projection_type,
            "NonKeyAttributes": idx.projection.non_key_attributes,
        },
        "IndexStatus": "ACTIVE",
        "ItemCount": 0,
        "ProvisionedThroughput": { "ReadCapacityUnits": 0, "WriteCapacityUnits": 0 }
    })
}

pub async fn describe_table(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let table = get_table(ctx, name).await?;
    let guard = table.read().await;
    Ok(json!({ "Table": describe(&guard.def, guard.items.len()) }))
}

/// Resolve the short table name from a table ARN (`arn:...:table/<name>`).
fn name_from_arn(arn: &str) -> Result<&str, DdbError> {
    arn.rsplit("table/")
        .next()
        .filter(|s| !s.is_empty() && *s != arn)
        .ok_or_else(|| DdbError::Validation(format!("invalid ResourceArn: {arn}")))
}

pub async fn describe_time_to_live(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let table = get_table(ctx, name).await?;
    let guard = table.read().await;
    let description = match &guard.ttl_attribute {
        Some(attr) => json!({ "TimeToLiveStatus": "ENABLED", "AttributeName": attr }),
        None => json!({ "TimeToLiveStatus": "DISABLED" }),
    };
    Ok(json!({ "TimeToLiveDescription": description }))
}

pub async fn update_time_to_live(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let spec = req
        .get("TimeToLiveSpecification")
        .ok_or_else(|| DdbError::Validation("TimeToLiveSpecification is required".into()))?;
    let enabled = spec
        .get("Enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            DdbError::Validation("TimeToLiveSpecification.Enabled is required".into())
        })?;
    let attribute = spec.get("AttributeName").and_then(Value::as_str);
    if enabled && attribute.is_none() {
        return Err(DdbError::Validation(
            "AttributeName is required when Enabled is true".into(),
        ));
    }
    let table = get_table(ctx, name).await?;
    let mut guard = table.write().await;
    guard.ttl_attribute = match (enabled, &guard.ttl_attribute) {
        (true, Some(existing)) if existing != attribute.unwrap() => {
            return Err(DdbError::Validation(
                "TimeToLive is already enabled with a different attribute name".into(),
            ))
        }
        (true, _) => Some(attribute.unwrap().to_string()),
        (false, _) => None,
    };
    Ok(json!({
        "TimeToLiveSpecification": {
            "Enabled": enabled,
            "AttributeName": attribute.unwrap_or_default(),
        }
    }))
}

fn continuous_backups_json(pitr_enabled: bool) -> Value {
    json!({
        "ContinuousBackupsDescription": {
            "ContinuousBackupsStatus": "DISABLED",
            "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": if pitr_enabled { "ENABLED" } else { "DISABLED" }
            }
        }
    })
}

pub async fn describe_continuous_backups(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let table = get_table(ctx, name).await?;
    let guard = table.read().await;
    Ok(continuous_backups_json(guard.pitr_enabled))
}

pub async fn update_continuous_backups(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let enabled = req
        .get("PointInTimeRecoverySpecification")
        .and_then(|s| s.get("PointInTimeRecoveryEnabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let table = get_table(ctx, name).await?;
    if enabled {
        return Err(DdbError::Validation(
            "Point-in-time recovery is unavailable until backups can be restored".into(),
        ));
    }
    let mut guard = table.write().await;
    guard.pitr_enabled = false;
    Ok(continuous_backups_json(false))
}

pub async fn list_tags_of_resource(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let arn = req_str(req, "ResourceArn")?;
    let table = get_table(ctx, name_from_arn(arn)?).await?;
    let guard = table.read().await;
    let tags: Vec<Value> = guard
        .tags
        .iter()
        .map(|(k, v)| json!({ "Key": k, "Value": v }))
        .collect();
    Ok(json!({ "Tags": tags }))
}

pub async fn tag_resource(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let arn = req_str(req, "ResourceArn")?;
    let table = get_table(ctx, name_from_arn(arn)?).await?;
    let mut guard = table.write().await;
    if let Some(arr) = req.get("Tags").and_then(Value::as_array) {
        for (k, v) in parse_tag_list(arr) {
            guard.tags.insert(k, v);
        }
    }
    Ok(json!({}))
}

pub async fn untag_resource(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let arn = req_str(req, "ResourceArn")?;
    let table = get_table(ctx, name_from_arn(arn)?).await?;
    let mut guard = table.write().await;
    if let Some(keys) = req.get("TagKeys").and_then(Value::as_array) {
        for key in keys.iter().filter_map(Value::as_str) {
            guard.tags.remove(key);
        }
    }
    Ok(json!({}))
}

pub async fn update_table(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let table = get_table(ctx, name).await?;
    if req.get("ReplicaUpdates").is_some() {
        return update_replicas(ctx, req, &table).await;
    }
    let mut guard = table.write().await;
    if !guard.def.replicas.is_empty() {
        return Err(DdbError::Validation(
            "Schema and billing updates on MREC tables are not supported".into(),
        ));
    }

    let mut updated = guard.def.clone();

    // Merge any new attribute definitions (needed for new GSI key attributes).
    if let Some(arr) = req.get("AttributeDefinitions").and_then(Value::as_array) {
        for a in arr {
            let new_def = AttributeDefinition {
                name: req_str(a, "AttributeName")?.to_string(),
                attr_type: req_str(a, "AttributeType")?.to_string(),
            };
            match updated
                .attribute_definitions
                .iter_mut()
                .find(|d| d.name == new_def.name)
            {
                Some(existing) => existing.attr_type = new_def.attr_type,
                None => updated.attribute_definitions.push(new_def),
            }
        }
    }

    // Billing-mode switch with throughput coherence.
    if let Some(mode) = req.get("BillingMode").and_then(Value::as_str) {
        match mode {
            "PAY_PER_REQUEST" => {
                updated.billing_mode = mode.to_string();
                updated.read_capacity = 0;
                updated.write_capacity = 0;
            }
            "PROVISIONED" => {
                let pt = req.get("ProvisionedThroughput");
                let (r, w) = throughput_pair(pt);
                if r == 0 || w == 0 {
                    return Err(DdbError::Validation(
                        "ProvisionedThroughput is required when switching to PROVISIONED billing"
                            .into(),
                    ));
                }
                updated.billing_mode = mode.to_string();
                updated.read_capacity = r;
                updated.write_capacity = w;
            }
            other => return Err(DdbError::Validation(format!("invalid BillingMode {other}"))),
        }
    } else if let Some(pt) = req.get("ProvisionedThroughput") {
        // Throughput update without a billing-mode change.
        let (r, w) = throughput_pair(Some(pt));
        if r == 0 || w == 0 {
            return Err(DdbError::Validation(
                "ProvisionedThroughput requires positive read and write capacity".into(),
            ));
        }
        updated.read_capacity = r;
        updated.write_capacity = w;
    }

    // Stream enable/disable.
    if let Some(spec) = req.get("StreamSpecification") {
        let parsed = parse_stream_spec(spec)?;
        updated.stream_spec = parsed.enabled.then_some(parsed);
    }

    // GSI create/update/delete.
    if let Some(updates) = req
        .get("GlobalSecondaryIndexUpdates")
        .and_then(Value::as_array)
    {
        for update in updates {
            apply_gsi_update(&mut updated, update)?;
        }
    }

    guard.def = updated;
    let count = guard.items.len();
    Ok(json!({ "TableDescription": describe(&guard.def, count) }))
}

/// MREC topology updates are serialized; ordinary writes remain available during bootstrap.
async fn update_replicas(
    ctx: &Ctx<'_>,
    req: &Value,
    table: &Arc<RwLock<TableData>>,
) -> Result<Value, DdbError> {
    let updates = req
        .get("ReplicaUpdates")
        .and_then(Value::as_array)
        .ok_or_else(|| DdbError::Validation("ReplicaUpdates must be an array".into()))?;
    if updates.len() != 1
        || req.as_object().is_some_and(|obj| {
            obj.keys()
                .any(|key| key != "TableName" && key != "ReplicaUpdates")
        })
    {
        return Err(DdbError::Validation(
            "Use one ReplicaUpdates operation per UpdateTable request".into(),
        ));
    }
    let update = &updates[0];
    let (create, target) = if let Some(create) = update.get("Create") {
        (true, req_str(create, "RegionName")?)
    } else if let Some(delete) = update.get("Delete") {
        (false, req_str(delete, "RegionName")?)
    } else {
        return Err(DdbError::Validation(
            "ReplicaUpdates supports Create or Delete".into(),
        ));
    };
    if target.is_empty() || target == ctx.region {
        return Err(DdbError::Validation(
            "Replica RegionName must differ from the request region".into(),
        ));
    }
    let name = req_str(req, "TableName")?;
    let _topology = ctx.store.replica_topology.lock().await;
    if !ctx
        .store
        .get(ctx.account, ctx.region, name)
        .is_some_and(|current| Arc::ptr_eq(&current, table))
    {
        return Err(DdbError::ResourceNotFound(format!(
            "Table not found: {name}"
        )));
    }
    let mut source = table.write().await;
    let name = source.def.name.clone();
    if create {
        if source.def.replicas.iter().any(|region| region == target) {
            return Err(DdbError::ResourceInUse(format!(
                "Replica already exists in {target}"
            )));
        }
        let mut regions = source.def.replicas.clone();
        if regions.is_empty() {
            regions.push(ctx.region.to_string());
        }
        regions.push(target.to_string());
        regions.sort();
        let mut def = source.def.clone();
        def.arn = format!("arn:aws:dynamodb:{target}:{}:table/{name}", ctx.account);
        def.replicas = regions.clone();
        def.stream_spec = Some(StreamSpecification {
            enabled: true,
            view_type: "NEW_AND_OLD_IMAGES".into(),
        });
        let mut replica = TableData::new(
            def,
            source.tags.clone(),
            source.ttl_attribute.clone(),
            source.pitr_enabled,
        );
        replica.items = source.items.clone();
        replica.dirty_keys.extend(replica.items.keys().cloned());
        replica.replica_versions = source.replica_versions.clone();
        replica
            .dirty_keys
            .extend(replica.replica_versions.keys().cloned());
        // Existing items precede all future writes. Tombstones are copied as well.
        ctx.store.create(ctx.account, target, replica)?;
        source.def.replicas = regions.clone();
        source.def.stream_spec = Some(StreamSpecification {
            enabled: true,
            view_type: "NEW_AND_OLD_IMAGES".into(),
        });
        for region in regions
            .iter()
            .filter(|region| region.as_str() != ctx.region && region.as_str() != target)
        {
            if let Some(peer) = ctx.store.get(ctx.account, region, &name) {
                peer.write().await.def.replicas = regions.clone();
            }
        }
    } else {
        if !source.def.replicas.iter().any(|region| region == target) {
            return Err(DdbError::ResourceNotFound(format!(
                "Replica not found in {target}"
            )));
        }
        let regions: Vec<_> = source
            .def
            .replicas
            .iter()
            .filter(|region| region.as_str() != target)
            .cloned()
            .collect();
        let replica = ctx
            .store
            .get(ctx.account, target, &name)
            .ok_or_else(|| DdbError::ResourceNotFound(format!("Replica not found in {target}")))?;
        let replica_guard = replica.write().await;
        if !replica_guard.replica_pending.is_empty() {
            return Err(DdbError::ResourceInUse(format!(
                "Replica in {target} has pending writes; retry after replication"
            )));
        }
        ctx.store.remove(ctx.account, target, &name);
        drop(replica_guard);
        source.def.replicas = if regions.len() == 1 {
            Vec::new()
        } else {
            regions.clone()
        };
        for region in regions
            .iter()
            .filter(|region| region.as_str() != ctx.region)
        {
            if let Some(peer) = ctx.store.get(ctx.account, region, &name) {
                peer.write().await.def.replicas = source.def.replicas.clone();
            }
        }
    }
    Ok(json!({ "TableDescription": describe(&source.def, source.items.len()) }))
}

/// Read `(read, write)` capacity from a `ProvisionedThroughput` object (0 when absent).
fn throughput_pair(pt: Option<&Value>) -> (u64, u64) {
    match pt {
        Some(pt) => (
            pt.get("ReadCapacityUnits")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            pt.get("WriteCapacityUnits")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        ),
        None => (0, 0),
    }
}

/// Apply a single `GlobalSecondaryIndexUpdates` entry (Create/Update/Delete) to the table.
fn apply_gsi_update(def: &mut TableDefinition, update: &Value) -> Result<(), DdbError> {
    if let Some(create) = update.get("Create") {
        let index_name = req_str(create, "IndexName")?.to_string();
        if def.index(&index_name).is_some() {
            return Err(DdbError::Validation(format!(
                "index {index_name} already exists on table {}",
                def.name
            )));
        }
        let key_schema = parse_key_schema(
            create
                .get("KeySchema")
                .ok_or_else(|| DdbError::Validation("index KeySchema required".into()))?,
        )?;
        // Every GSI key attribute must have an AttributeDefinition.
        let defined: std::collections::HashSet<&str> = def
            .attribute_definitions
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        for k in &key_schema {
            if !defined.contains(k.name.as_str()) {
                return Err(DdbError::Validation(format!(
                    "GSI key attribute {} has no AttributeDefinition",
                    k.name
                )));
            }
        }
        let projection = parse_projection(
            create
                .get("Projection")
                .ok_or_else(|| DdbError::Validation("index Projection required".into()))?,
        )?;
        def.indexes.push(SecondaryIndex {
            name: index_name,
            key_schema,
            projection,
            global: true,
        });
    } else if let Some(upd) = update.get("Update") {
        let index_name = req_str(upd, "IndexName")?;
        if def.index(index_name).is_none() {
            return Err(DdbError::ResourceNotFound(format!(
                "index {index_name} does not exist"
            )));
        }
        // Only throughput is mutable on a GSI; capacities are not surfaced, so this is a no-op
        // beyond existence validation.
    } else if let Some(del) = update.get("Delete") {
        let index_name = req_str(del, "IndexName")?;
        if def.index(index_name).is_none() {
            return Err(DdbError::ResourceNotFound(format!(
                "index {index_name} does not exist"
            )));
        }
        def.indexes.retain(|i| i.name != index_name);
    } else {
        return Err(DdbError::Validation(
            "GlobalSecondaryIndexUpdates entry must have Create, Update, or Delete".into(),
        ));
    }
    Ok(())
}

pub async fn delete_table(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let _topology = ctx.store.replica_topology.lock().await;
    let existing = get_table(ctx, name).await?;
    if !existing.read().await.def.replicas.is_empty() {
        return Err(DdbError::ResourceInUse(
            "Remove replicas with UpdateTable before deleting a global table".into(),
        ));
    }
    let table = ctx
        .store
        .remove(ctx.account, ctx.region, name)
        .ok_or_else(|| DdbError::ResourceNotFound(format!("Table not found: {name}")))?;
    let guard = table.read().await;
    Ok(json!({ "TableDescription": describe(&guard.def, guard.items.len()) }))
}

pub async fn list_tables(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let mut names = ctx.store.list_names(ctx.account, ctx.region);
    if let Some(start) = req.get("ExclusiveStartTableName").and_then(Value::as_str) {
        names.retain(|n| n.as_str() > start);
    }
    let limit = req.get("Limit").and_then(Value::as_u64).unwrap_or(100) as usize;
    let truncated = names.len() > limit;
    names.truncate(limit);
    let mut out = json!({ "TableNames": names });
    if truncated {
        if let Some(last) = names.last() {
            out["LastEvaluatedTableName"] = json!(last);
        }
    }
    Ok(out)
}

// ============================ Item operations ==================================

/// Evaluate an optional `ConditionExpression` against the current (possibly empty) item.
fn check_condition(req: &Value, current: &Item) -> Result<(), DdbError> {
    if let Some(expr) = req.get("ConditionExpression").and_then(Value::as_str) {
        let names = parse_names(req);
        let values = parse_values(req)?;
        let cond = ConditionExpression::parse(expr, &names, &values)?;
        if !cond.matches(current) {
            return Err(DdbError::ConditionalCheckFailed(
                "The conditional request failed".into(),
            ));
        }
    }
    Ok(())
}

/// Evaluate the gating condition for a write: modern `ConditionExpression` or the legacy
/// `Expected`/`ConditionalOperator` pair (mutually exclusive).
fn evaluate_conditions(req: &Value, current: &Item) -> Result<(), DdbError> {
    let has_expr = req
        .get("ConditionExpression")
        .and_then(Value::as_str)
        .is_some();
    let has_expected = req
        .get("Expected")
        .and_then(Value::as_object)
        .map(|m| !m.is_empty())
        .unwrap_or(false);
    if has_expr && has_expected {
        return Err(DdbError::Validation(
            "Cannot use both ConditionExpression and the legacy Expected parameter".into(),
        ));
    }
    if has_expected {
        return evaluate_expected(req, current);
    }
    check_condition(req, current)
}

/// Evaluate the legacy `Expected` map under `ConditionalOperator` (`AND` default / `OR`).
fn evaluate_expected(req: &Value, current: &Item) -> Result<(), DdbError> {
    let expected = req.get("Expected").and_then(Value::as_object).unwrap();
    let or = req
        .get("ConditionalOperator")
        .and_then(Value::as_str)
        .map(|c| c.eq_ignore_ascii_case("OR"))
        .unwrap_or(false);
    let mut any = false;
    let mut all = true;
    for (attr, spec) in expected {
        let ok = evaluate_expected_one(attr, spec, current)?;
        any |= ok;
        all &= ok;
    }
    let pass = if or { any } else { all };
    if pass {
        Ok(())
    } else {
        Err(DdbError::ConditionalCheckFailed(
            "The conditional request failed".into(),
        ))
    }
}

/// Evaluate one `Expected` entry (operator form or legacy `Value`/`Exists` form).
fn evaluate_expected_one(attr: &str, spec: &Value, current: &Item) -> Result<bool, DdbError> {
    let present = current.get(attr);
    if let Some(op) = spec.get("ComparisonOperator").and_then(Value::as_str) {
        let list: Vec<AttributeValue> =
            match spec.get("AttributeValueList").and_then(Value::as_array) {
                Some(arr) => arr
                    .iter()
                    .map(AttributeValue::from_json)
                    .collect::<Result<_, _>>()?,
                None => Vec::new(),
            };
        return Ok(eval_comparison(op, present, &list));
    }
    let exists = spec.get("Exists").and_then(Value::as_bool);
    match spec.get("Value") {
        Some(v) => {
            if exists == Some(false) {
                return Err(DdbError::Validation(
                    "Exists=false cannot be combined with Value".into(),
                ));
            }
            let want = AttributeValue::from_json(v)?;
            Ok(present == Some(&want))
        }
        None => match exists {
            Some(false) => Ok(present.is_none()),
            Some(true) => Err(DdbError::Validation("Exists=true requires a Value".into())),
            None => Err(DdbError::Validation(
                "Expected entry requires Value or Exists".into(),
            )),
        },
    }
}

/// Evaluate a legacy `ComparisonOperator` against the present attribute and operand list.
fn eval_comparison(op: &str, present: Option<&AttributeValue>, list: &[AttributeValue]) -> bool {
    let first = list.first();
    match op {
        "NULL" => present.is_none(),
        "NOT_NULL" => present.is_some(),
        "EQ" => matches!((present, first), (Some(a), Some(b)) if a == b),
        "NE" => match (present, first) {
            (Some(a), Some(b)) => a != b,
            _ => true,
        },
        "LE" => cmp_scalar(present, first)
            .map(|o| o.is_le())
            .unwrap_or(false),
        "LT" => cmp_scalar(present, first)
            .map(|o| o.is_lt())
            .unwrap_or(false),
        "GE" => cmp_scalar(present, first)
            .map(|o| o.is_ge())
            .unwrap_or(false),
        "GT" => cmp_scalar(present, first)
            .map(|o| o.is_gt())
            .unwrap_or(false),
        "BEGINS_WITH" => begins_with(present, first),
        "CONTAINS" => contains(present, first),
        "NOT_CONTAINS" => present.is_some() && !contains(present, first),
        "IN" => present
            .map(|a| list.iter().any(|b| a == b))
            .unwrap_or(false),
        "BETWEEN" => match (present, list.first(), list.get(1)) {
            (Some(a), Some(lo), Some(hi)) => {
                cmp_av(a, lo).map(|o| o.is_ge()).unwrap_or(false)
                    && cmp_av(a, hi).map(|o| o.is_le()).unwrap_or(false)
            }
            _ => false,
        },
        _ => false,
    }
}

/// Compare two scalar attribute values of the same type (N numerically, S/B lexically).
fn cmp_av(a: &AttributeValue, b: &AttributeValue) -> Option<std::cmp::Ordering> {
    match (a, b) {
        (AttributeValue::N(x), AttributeValue::N(y)) => Some(number_cmp(x, y)),
        (AttributeValue::S(x), AttributeValue::S(y)) => Some(x.cmp(y)),
        (AttributeValue::B(x), AttributeValue::B(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

fn cmp_scalar(
    present: Option<&AttributeValue>,
    other: Option<&AttributeValue>,
) -> Option<std::cmp::Ordering> {
    match (present, other) {
        (Some(a), Some(b)) => cmp_av(a, b),
        _ => None,
    }
}

fn begins_with(present: Option<&AttributeValue>, prefix: Option<&AttributeValue>) -> bool {
    match (present, prefix) {
        (Some(AttributeValue::S(s)), Some(AttributeValue::S(p))) => s.starts_with(p.as_str()),
        (Some(AttributeValue::B(b)), Some(AttributeValue::B(p))) => b.starts_with(p.as_slice()),
        _ => false,
    }
}

fn contains(present: Option<&AttributeValue>, target: Option<&AttributeValue>) -> bool {
    let (Some(p), Some(t)) = (present, target) else {
        return false;
    };
    match p {
        AttributeValue::S(s) => matches!(t, AttributeValue::S(sub) if s.contains(sub.as_str())),
        AttributeValue::Ss(set) => matches!(t, AttributeValue::S(m) if set.contains(m)),
        AttributeValue::Ns(set) => matches!(t, AttributeValue::N(m) if set.contains(m)),
        AttributeValue::Bs(set) => matches!(t, AttributeValue::B(m) if set.contains(m)),
        AttributeValue::L(list) => list.contains(t),
        _ => false,
    }
}

fn maybe_project(req: &Value, item: &Item) -> Result<Item, DdbError> {
    if let Some(expr) = req.get("ProjectionExpression").and_then(Value::as_str) {
        let names = parse_names(req);
        let proj = ProjectionExpression::parse(expr, &names)?;
        Ok(proj.project(item))
    } else {
        Ok(item.clone())
    }
}

fn return_values(req: &Value) -> &str {
    req.get("ReturnValues")
        .and_then(Value::as_str)
        .unwrap_or("NONE")
}

pub async fn put_item(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let item_value = req
        .get("Item")
        .ok_or_else(|| DdbError::Validation("Item is required".into()))?;
    let item = item_from_json(item_value)?;
    if item_size(&item) > MAX_ITEM_SIZE {
        return Err(DdbError::Validation(
            "Item size has exceeded the maximum allowed size".into(),
        ));
    }
    let table = get_table(ctx, name).await?;
    let mut guard = table.write().await;
    let key = guard.key_of(&item)?;
    let existing = guard.items.get(&key).cloned();
    evaluate_conditions(req, existing.as_ref().unwrap_or(&Item::new()))?;
    guard.emit_stream(existing.as_ref(), Some(&item));
    guard.items.insert(key, item);
    let mut out = Map::new();
    if return_values(req) == "ALL_OLD" {
        if let Some(old) = existing {
            out.insert("Attributes".into(), item_to_json(&old));
        }
    }
    Ok(Value::Object(out))
}

pub async fn get_item(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let key_item = parse_key(req)?;
    let table = get_table(ctx, name).await?;
    let mut guard = table.write().await;
    reap_expired(&mut guard, now_epoch_secs());
    let key = guard.key_of(&key_item)?;
    match guard.items.get(&key) {
        Some(item) => Ok(json!({ "Item": item_to_json(&maybe_project(req, item)?) })),
        None => Ok(json!({})),
    }
}

/// Delete items whose numeric TTL attribute is at or before `now_secs`, emitting REMOVE
/// stream records for each committed expiry.
fn reap_expired(data: &mut TableData, now_secs: f64) {
    let Some(attr) = data.ttl_attribute.clone() else {
        return;
    };
    let expired: Vec<StoredKey> = data
        .items
        .iter()
        .filter(|(_, item)| match item.get(&attr) {
            Some(AttributeValue::N(n)) => n.parse::<f64>().map(|t| t <= now_secs).unwrap_or(false),
            _ => false,
        })
        .map(|(k, _)| k.clone())
        .collect();
    for key in expired {
        if let Some(item) = data.items.remove(&key) {
            data.emit_stream(Some(&item), None);
        }
    }
}

/// Periodic TTL sweep across every account/region scope. The handler owns the timer; this
/// function owns only one deterministic pass and therefore remains directly testable.
pub async fn sweep_expired(store: &TableStore) {
    let now = now_epoch_secs();
    for (_, _, table) in store.all_tables() {
        let mut guard = table.write().await;
        reap_expired(&mut guard, now);
    }
}

/// Periodic maintenance pass: reap TTL and forward queued Kinesis records through the same
/// Core dispatcher used by external requests. Failed/unavailable deliveries remain queued.
pub async fn run_maintenance(store: &TableStore, registry: &Weak<ServiceRegistry>) {
    let _gate = store.operation_gate.lock().await;
    if store.has_uncommitted() {
        if let Err(error) = store.persist().await {
            tracing::error!(%error, "DynamoDB prior write could not be committed");
            return;
        }
    }
    store.mark_uncommitted();
    store.purge_expired_txn_tokens();
    sweep_expired(store).await;
    let mut changed = replicate_pending(store).await;
    for (_, region, table) in store.all_tables() {
        let pending = {
            let mut guard = table.write().await;
            std::mem::take(&mut guard.kinesis_pending)
        };
        changed |= !pending.is_empty();
        for (stream_arn, record) in pending {
            if !deliver_kinesis(registry, &region, &stream_arn, &record).await {
                table
                    .write()
                    .await
                    .kinesis_pending
                    .push((stream_arn, record));
            }
        }
    }
    if !changed {
        for (_, _, table) in store.all_tables() {
            if !table.read().await.dirty_keys.is_empty() {
                changed = true;
                break;
            }
        }
    }
    if changed {
        if let Err(error) = store.persist().await {
            tracing::error!(%error, "DynamoDB maintenance persistence failed");
        }
    } else {
        store.clear_uncommitted();
    }
}

/// A single delayed pass provides eventual propagation. Replicated writes emit streams but
/// never enqueue another replica change, so there is no feedback loop.
pub async fn replicate_pending(store: &TableStore) -> bool {
    let mut changed = false;
    // ponytail: one topology lock serializes bootstrap and fan-out; shard it if
    // multi-table replication throughput becomes a bottleneck.
    let _topology = store.replica_topology.lock().await;
    for (account, source_region, table) in store.all_tables() {
        let (name, targets, pending) = {
            let mut guard = table.write().await;
            (
                guard.def.name.clone(),
                guard.def.replicas.clone(),
                std::mem::take(&mut guard.replica_pending),
            )
        };
        changed |= !pending.is_empty();
        for (key, item, version) in pending {
            for region in targets.iter().filter(|region| *region != &source_region) {
                let Some(replica) = store.get(&account, region, &name) else {
                    continue;
                };
                let mut dest = replica.write().await;
                if !dest
                    .def
                    .replicas
                    .iter()
                    .any(|member| member == &source_region)
                    || dest
                        .replica_versions
                        .get(&key)
                        .is_some_and(|old| old >= &version)
                {
                    continue;
                }
                let old = dest.items.get(&key).cloned();
                dest.emit_replica_stream(old.as_ref(), item.as_ref());
                if let Some(item) = &item {
                    dest.items.insert(key.clone(), item.clone());
                } else {
                    dest.items.remove(&key);
                }
                dest.replica_versions.insert(key.clone(), version.clone());
                dest.dirty_keys.insert(key.clone());
            }
        }
    }
    changed
}

async fn deliver_kinesis(
    registry: &Weak<ServiceRegistry>,
    region: &str,
    stream_arn: &str,
    record: &crate::store::StreamRecord,
) -> bool {
    let Some(dispatcher) = registry
        .upgrade()
        .and_then(|registry| registry.internal_dispatcher())
    else {
        return false;
    };
    let Some(stream_name) = stream_arn
        .split(":stream/")
        .nth(1)
        .filter(|name| !name.is_empty())
    else {
        return false;
    };
    let data = base64::engine::general_purpose::STANDARD
        .encode(crate::streams::record_json(region, record).to_string());
    let body = json!({
        "StreamName": stream_name,
        "Data": data,
        "PartitionKey": record.event_id,
    })
    .to_string();
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/x-amz-json-1.1"),
    );
    headers.insert(
        "x-amz-target",
        HeaderValue::from_static("Kinesis_20131202.PutRecord"),
    );
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential=local/19700101/{region}/kinesis/aws4_request, SignedHeaders=host;x-amz-date, Signature=0"
    );
    let Ok(authorization) = HeaderValue::from_str(&authorization) else {
        return false;
    };
    headers.insert("authorization", authorization);
    let uri: Uri = "/".parse().expect("static URI");
    dispatcher
        .dispatch(
            &Method::POST,
            &uri,
            &headers,
            Bytes::from(body),
            &record.event_id,
        )
        .await
        .status()
        .is_success()
}

pub async fn delete_item(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let key_item = parse_key(req)?;
    let table = get_table(ctx, name).await?;
    let mut guard = table.write().await;
    let key = guard.key_of(&key_item)?;
    let existing = guard.items.get(&key).cloned();
    evaluate_conditions(req, existing.as_ref().unwrap_or(&Item::new()))?;
    if existing.is_some() {
        guard.emit_stream(existing.as_ref(), None);
    } else {
        guard.record_replica_change(key.clone(), None);
    }
    guard.items.remove(&key);
    let mut out = Map::new();
    if return_values(req) == "ALL_OLD" {
        if let Some(old) = existing {
            out.insert("Attributes".into(), item_to_json(&old));
        }
    }
    Ok(Value::Object(out))
}

pub async fn update_item(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let key_item = parse_key(req)?;
    let table = get_table(ctx, name).await?;
    let mut guard = table.write().await;
    let key = guard.key_of(&key_item)?;
    let existing = guard.items.get(&key).cloned();
    evaluate_conditions(req, existing.as_ref().unwrap_or(&Item::new()))?;

    // Start from the existing item, or from the key when creating.
    let mut item = existing.clone().unwrap_or_else(|| key_item.clone());
    if let Some(expr) = req.get("UpdateExpression").and_then(Value::as_str) {
        let names = parse_names(req);
        let values = parse_values(req)?;
        let update = UpdateExpression::parse(expr, &names, &values)?;
        update.apply(&mut item)?;
    }
    if guard.key_of(&item)? != key {
        return Err(DdbError::Validation(
            "UpdateExpression cannot change a primary key".into(),
        ));
    }
    if item_size(&item) > MAX_ITEM_SIZE {
        return Err(DdbError::Validation(
            "Item size has exceeded the maximum allowed size".into(),
        ));
    }
    guard.emit_stream(existing.as_ref(), Some(&item));
    guard.items.insert(key, item.clone());

    let mut out = Map::new();
    match return_values(req) {
        "ALL_OLD" | "UPDATED_OLD" => {
            if let Some(old) = existing {
                out.insert("Attributes".into(), item_to_json(&old));
            }
        }
        "ALL_NEW" | "UPDATED_NEW" => {
            out.insert("Attributes".into(), item_to_json(&item));
        }
        _ => {}
    }
    Ok(Value::Object(out))
}

// ============================ Query and Scan ===================================

/// Build a `Key` JSON object holding the given attribute names from an item.
fn key_json(item: &Item, attr_names: &[String]) -> Value {
    let mut map = Map::new();
    for name in attr_names {
        if let Some(v) = item.get(name) {
            map.insert(name.clone(), v.to_json());
        }
    }
    Value::Object(map)
}

/// Compute the storage key for an item under an arbitrary (table or index) key schema.
fn stored_key_for(item: &Item, hash: &str, range: Option<&str>) -> Option<StoredKey> {
    let partition = crate::store::KeyScalar::from_value(item.get(hash)?)?;
    let sort = match range {
        Some(rk) => Some(crate::store::KeyScalar::from_value(item.get(rk)?)?),
        None => None,
    };
    Some(StoredKey { partition, sort })
}

pub async fn query(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let table = get_table(ctx, name).await?;
    let mut guard = table.write().await;
    reap_expired(&mut guard, now_epoch_secs());

    // Resolve the key schema for the base table or the requested index.
    let (hash, range, index_name, allowed) = match req.get("IndexName").and_then(Value::as_str) {
        Some(idx_name) => {
            let idx = guard
                .def
                .index(idx_name)
                .ok_or_else(|| DdbError::Validation(format!("index {idx_name} does not exist")))?;
            let h = idx
                .key_schema
                .iter()
                .find(|k| k.key_type == KeyType::Hash)
                .unwrap()
                .name
                .clone();
            let r = idx
                .key_schema
                .iter()
                .find(|k| k.key_type == KeyType::Range)
                .map(|k| k.name.clone());
            (
                h,
                r,
                Some(idx_name.to_string()),
                index_allowed_set(&guard.def, idx),
            )
        }
        None => (
            guard.def.hash_key().to_string(),
            guard.def.range_key().map(str::to_string),
            None,
            None,
        ),
    };
    if index_name.is_some() && req.get("ConsistentRead").and_then(Value::as_bool) == Some(true) {
        // GSIs only support eventually consistent reads.
        if guard
            .def
            .index(index_name.as_deref().unwrap())
            .map(|i| i.global)
            .unwrap_or(false)
        {
            return Err(DdbError::Validation(
                "Consistent reads are not supported on global secondary indexes".into(),
            ));
        }
    }

    let key_expr = req_str(req, "KeyConditionExpression")?;
    let names = parse_names(req);
    let values = parse_values(req)?;
    let key_cond = ConditionExpression::parse(key_expr, &names, &values)?;

    // Candidate items with the index/table keys present, matching the key condition, sorted.
    let mut candidates: Vec<(StoredKey, Item)> = guard
        .items
        .values()
        .filter(|item| key_cond.matches(item))
        .filter_map(|item| stored_key_for(item, &hash, range.as_deref()).map(|k| (k, item.clone())))
        .collect();
    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    let forward = req
        .get("ScanIndexForward")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !forward {
        candidates.reverse();
    }

    paginate_and_respond(
        req,
        &guard.def,
        candidates,
        &hash,
        range.as_deref(),
        allowed,
    )
}

pub async fn scan(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let table = get_table(ctx, name).await?;
    let mut guard = table.write().await;
    reap_expired(&mut guard, now_epoch_secs());

    let (hash, range, allowed) = match req.get("IndexName").and_then(Value::as_str) {
        Some(idx_name) => {
            let idx = guard
                .def
                .index(idx_name)
                .ok_or_else(|| DdbError::Validation(format!("index {idx_name} does not exist")))?;
            let h = idx
                .key_schema
                .iter()
                .find(|k| k.key_type == KeyType::Hash)
                .unwrap()
                .name
                .clone();
            let r = idx
                .key_schema
                .iter()
                .find(|k| k.key_type == KeyType::Range)
                .map(|k| k.name.clone());
            (h, r, index_allowed_set(&guard.def, idx))
        }
        None => (
            guard.def.hash_key().to_string(),
            guard.def.range_key().map(str::to_string),
            None,
        ),
    };

    let total_segments = req.get("TotalSegments").and_then(Value::as_u64);
    let segment = req.get("Segment").and_then(Value::as_u64);
    if total_segments.is_some() != segment.is_some() {
        return Err(DdbError::Validation(
            "Segment and TotalSegments must be used together".into(),
        ));
    }

    let mut candidates: Vec<(StoredKey, Item)> = guard
        .items
        .values()
        .filter_map(|item| stored_key_for(item, &hash, range.as_deref()).map(|k| (k, item.clone())))
        .collect();
    candidates.sort_by(|a, b| a.0.cmp(&b.0));

    // Parallel scan partitioning: each item handled by exactly one segment.
    if let (Some(total), Some(seg)) = (total_segments, segment) {
        if total == 0 || seg >= total {
            return Err(DdbError::Validation("invalid Segment/TotalSegments".into()));
        }
        candidates = candidates
            .into_iter()
            .enumerate()
            .filter(|(i, _)| (*i as u64) % total == seg)
            .map(|(_, kv)| kv)
            .collect();
    }

    paginate_and_respond(
        req,
        &guard.def,
        candidates,
        &hash,
        range.as_deref(),
        allowed,
    )
}

/// The set of attribute names retained by a secondary index's projection, or `None` when the
/// projection is `ALL`. Always includes the table and index key attributes.
fn index_allowed_set(
    def: &TableDefinition,
    idx: &SecondaryIndex,
) -> Option<std::collections::HashSet<String>> {
    if idx.projection.projection_type == ProjectionType::All {
        return None;
    }
    let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
    set.insert(def.hash_key().to_string());
    if let Some(r) = def.range_key() {
        set.insert(r.to_string());
    }
    for k in &idx.key_schema {
        set.insert(k.name.clone());
    }
    if idx.projection.projection_type == ProjectionType::Include {
        for a in &idx.projection.non_key_attributes {
            set.insert(a.clone());
        }
    }
    Some(set)
}

/// Restrict an item to the given set of attribute names.
fn filter_item(item: &Item, allowed: &std::collections::HashSet<String>) -> Item {
    item.iter()
        .filter(|(k, _)| allowed.contains(k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Apply ExclusiveStartKey, Limit, FilterExpression, Select, and projection; build the
/// Query/Scan response.
fn paginate_and_respond(
    req: &Value,
    def: &TableDefinition,
    mut candidates: Vec<(StoredKey, Item)>,
    hash: &str,
    range: Option<&str>,
    allowed: Option<std::collections::HashSet<String>>,
) -> Result<Value, DdbError> {
    // ExclusiveStartKey: resume after the matching key.
    if let Some(start_value) = req.get("ExclusiveStartKey") {
        let start_item = item_from_json(start_value)?;
        if let Some(start_key) = stored_key_for(&start_item, hash, range) {
            if let Some(pos) = candidates.iter().position(|(k, _)| *k == start_key) {
                candidates.drain(..=pos);
            }
        }
    }

    let limit = match req.get("Limit").and_then(Value::as_u64) {
        Some(0) => return Err(DdbError::Validation("Limit must be at least 1".into())),
        Some(l) => Some(l as usize),
        None => None,
    };
    let mut last_evaluated: Option<Item> = None;
    if let Some(limit) = limit {
        if candidates.len() > limit {
            last_evaluated = Some(candidates[limit - 1].1.clone());
            candidates.truncate(limit);
        }
    }
    let scanned_count = candidates.len();

    // FilterExpression after the read set.
    let filtered: Vec<Item> = match req.get("FilterExpression").and_then(Value::as_str) {
        Some(expr) => {
            let names = parse_names(req);
            let values = parse_values(req)?;
            let filter = ConditionExpression::parse(expr, &names, &values)?;
            candidates
                .into_iter()
                .map(|(_, i)| i)
                .filter(|i| filter.matches(i))
                .collect()
        }
        None => candidates.into_iter().map(|(_, i)| i).collect(),
    };

    let select = req.get("Select").and_then(Value::as_str).unwrap_or("");
    let count_only = select == "COUNT";

    let mut out = Map::new();
    out.insert("Count".into(), json!(filtered.len()));
    out.insert("ScannedCount".into(), json!(scanned_count));
    if !count_only {
        let mut items = Vec::with_capacity(filtered.len());
        for item in &filtered {
            // Restrict to the index projection (if querying a secondary index), then apply any
            // explicit ProjectionExpression.
            let base = match &allowed {
                Some(set) => filter_item(item, set),
                None => item.clone(),
            };
            items.push(item_to_json(&maybe_project(req, &base)?));
        }
        out.insert("Items".into(), Value::Array(items));
    }
    if let Some(last) = last_evaluated {
        // Include the table key attributes plus the index keys used for ordering.
        let mut attr_names: Vec<String> = def.key_schema.iter().map(|k| k.name.clone()).collect();
        attr_names.push(hash.to_string());
        if let Some(r) = range {
            attr_names.push(r.to_string());
        }
        attr_names.sort();
        attr_names.dedup();
        out.insert("LastEvaluatedKey".into(), key_json(&last, &attr_names));
    }
    Ok(Value::Object(out))
}

// ============================ Batch operations =================================

pub async fn batch_write_item(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let request_items = req
        .get("RequestItems")
        .and_then(Value::as_object)
        .ok_or_else(|| DdbError::Validation("RequestItems is required".into()))?;
    let total: usize = request_items
        .values()
        .filter_map(|v| v.as_array().map(|a| a.len()))
        .sum();
    if total > 25 {
        return Err(DdbError::Validation(
            "Too many items requested (max 25)".into(),
        ));
    }
    for (table_name, ops) in request_items {
        let ops = ops
            .as_array()
            .ok_or_else(|| DdbError::Validation("RequestItems entry must be an array".into()))?;
        let table = get_table(ctx, table_name).await?;
        let mut guard = table.write().await;
        let mut seen: Vec<StoredKey> = Vec::new();
        for op in ops {
            if let Some(put) = op.get("PutRequest") {
                let item = item_from_json(
                    put.get("Item")
                        .ok_or_else(|| DdbError::Validation("PutRequest.Item required".into()))?,
                )?;
                let key = guard.key_of(&item)?;
                if seen.contains(&key) {
                    return Err(DdbError::Validation(
                        "Provided list of item keys contains duplicates".into(),
                    ));
                }
                seen.push(key.clone());
                let existing = guard.items.get(&key).cloned();
                guard.emit_stream(existing.as_ref(), Some(&item));
                guard.items.insert(key, item);
            } else if let Some(del) = op.get("DeleteRequest") {
                let key_item =
                    item_from_json(del.get("Key").ok_or_else(|| {
                        DdbError::Validation("DeleteRequest.Key required".into())
                    })?)?;
                let key = guard.key_of(&key_item)?;
                if seen.contains(&key) {
                    return Err(DdbError::Validation(
                        "Provided list of item keys contains duplicates".into(),
                    ));
                }
                seen.push(key.clone());
                let existing = guard.items.get(&key).cloned();
                if existing.is_some() {
                    guard.emit_stream(existing.as_ref(), None);
                } else {
                    guard.record_replica_change(key.clone(), None);
                }
                guard.items.remove(&key);
            }
        }
    }
    Ok(json!({ "UnprocessedItems": {} }))
}

pub async fn batch_get_item(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let request_items = req
        .get("RequestItems")
        .and_then(Value::as_object)
        .ok_or_else(|| DdbError::Validation("RequestItems is required".into()))?;
    let total: usize = request_items
        .values()
        .filter_map(|v| v.get("Keys").and_then(Value::as_array).map(|a| a.len()))
        .sum();
    if total > 100 {
        return Err(DdbError::Validation(
            "Too many keys requested (max 100)".into(),
        ));
    }
    let mut responses = Map::new();
    for (table_name, spec) in request_items {
        let keys = spec
            .get("Keys")
            .and_then(Value::as_array)
            .ok_or_else(|| DdbError::Validation("Keys is required".into()))?;
        let table = get_table(ctx, table_name).await?;
        let guard = table.read().await;
        let mut items = Vec::new();
        for key_value in keys {
            let key_item = item_from_json(key_value)?;
            let key = guard.key_of(&key_item)?;
            if let Some(item) = guard.items.get(&key) {
                items.push(item_to_json(&maybe_project(spec, item)?));
            }
        }
        responses.insert(table_name.clone(), Value::Array(items));
    }
    Ok(json!({ "Responses": responses, "UnprocessedKeys": {} }))
}

// ============================ Transactions =====================================

/// Return the single transaction verb and payload, rejecting empty or multi-verb actions.
fn transaction_action(action: &Value) -> Result<(&str, &Value), DdbError> {
    let object = action
        .as_object()
        .ok_or_else(|| DdbError::Validation("invalid transaction action".into()))?;
    if object.len() != 1 {
        return Err(DdbError::Validation(
            "each transaction action must contain exactly one operation".into(),
        ));
    }
    let (verb, inner) = object.iter().next().unwrap();
    if !inner.is_object() {
        return Err(DdbError::Validation(
            "transaction operation must be an object".into(),
        ));
    }
    Ok((verb, inner))
}

/// Collect the unique table names referenced by transaction actions, sorted (lock order).
fn transact_table_names(actions: &[Value]) -> Result<Vec<String>, DdbError> {
    let mut names = Vec::new();
    for action in actions {
        let (_, inner) = transaction_action(action)?;
        let table = req_str(inner, "TableName")?.to_string();
        if !names.contains(&table) {
            names.push(table);
        }
    }
    names.sort();
    Ok(names)
}

enum StagedWrite {
    Put {
        table: String,
        key: StoredKey,
        old: Option<Item>,
        new: Item,
    },
    Delete {
        table: String,
        key: StoredKey,
        old: Option<Item>,
    },
    Check,
}

pub async fn transact_write_items(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let token = match req.get("ClientRequestToken") {
        Some(Value::String(token)) if !token.is_empty() && token.len() <= 36 => {
            Some(token.as_str())
        }
        Some(_) => {
            return Err(DdbError::Validation(
                "ClientRequestToken must be a non-empty string of at most 36 characters".into(),
            ))
        }
        None => None,
    };

    if let Some(token) = token {
        let mut canonical = req.clone();
        canonical
            .as_object_mut()
            .unwrap()
            .remove("ClientRequestToken");
        let fingerprint = canonical.to_string();
        let slot = ctx.store.txn_slot(ctx.account, ctx.region, token);
        let mut outcome = slot.lock().await;
        if let Some(previous) = outcome.as_ref() {
            if previous.created_at.elapsed() < std::time::Duration::from_secs(600) {
                if previous.fingerprint != fingerprint {
                    return Err(DdbError::IdempotentParameterMismatch(
                        "A request with this ClientRequestToken has different parameters".into(),
                    ));
                }
                return previous.result.clone();
            }
            *outcome = None;
        }
        let result = transact_write_items_once(ctx, req).await;
        *outcome = Some(crate::store::TxnOutcome {
            fingerprint,
            result: result.clone(),
            created_at: std::time::Instant::now(),
        });
        return result;
    }

    transact_write_items_once(ctx, req).await
}

async fn transact_write_items_once(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let actions = req
        .get("TransactItems")
        .and_then(Value::as_array)
        .ok_or_else(|| DdbError::Validation("TransactItems is required".into()))?;
    if actions.is_empty() || actions.len() > 100 {
        return Err(DdbError::Validation(
            "TransactItems must have 1..=100 actions".into(),
        ));
    }

    // Lock every involved table in name order to avoid deadlock and to hide partial commits.
    let names = transact_table_names(actions)?;
    let mut guards = std::collections::BTreeMap::new();
    for name in &names {
        let table = get_table(ctx, name).await?;
        guards.insert(name.clone(), table.write_owned().await);
    }

    let mut seen: Vec<(String, StoredKey)> = Vec::new();
    let mut reasons = Vec::with_capacity(actions.len());
    let mut staged = Vec::with_capacity(actions.len());
    let mut any_failed = false;

    // Materialize every resulting item before mutating any table. The commit loop below is
    // intentionally infallible, preserving all-or-nothing behavior even for late update errors.
    for action in actions {
        let (verb, inner) = transaction_action(action)?;
        let table_name = req_str(inner, "TableName")?;
        let guard = guards.get(table_name).unwrap();
        let (key, old, stage) = match verb {
            "Put" => {
                let item = item_from_json(
                    inner
                        .get("Item")
                        .ok_or_else(|| DdbError::Validation("Put.Item required".into()))?,
                )?;
                if item_size(&item) > MAX_ITEM_SIZE {
                    return Err(DdbError::Validation(
                        "Item size has exceeded the maximum allowed size".into(),
                    ));
                }
                let key = guard.key_of(&item)?;
                let old = guard.items.get(&key).cloned();
                let stage = StagedWrite::Put {
                    table: table_name.to_string(),
                    key: key.clone(),
                    old: old.clone(),
                    new: item,
                };
                (key, old, stage)
            }
            "Update" => {
                let key_item = parse_key(inner)?;
                let key = guard.key_of(&key_item)?;
                let old = guard.items.get(&key).cloned();
                let mut item = old.clone().unwrap_or_else(|| key_item.clone());
                if let Some(expr) = inner.get("UpdateExpression").and_then(Value::as_str) {
                    let names = parse_names(inner);
                    let values = parse_values(inner)?;
                    UpdateExpression::parse(expr, &names, &values)?.apply(&mut item)?;
                }
                if guard.key_of(&item)? != key {
                    return Err(DdbError::Validation(
                        "The document path provided in the update expression is invalid for update"
                            .into(),
                    ));
                }
                if item_size(&item) > MAX_ITEM_SIZE {
                    return Err(DdbError::Validation(
                        "Item size has exceeded the maximum allowed size".into(),
                    ));
                }
                let stage = StagedWrite::Put {
                    table: table_name.to_string(),
                    key: key.clone(),
                    old: old.clone(),
                    new: item,
                };
                (key, old, stage)
            }
            "Delete" | "ConditionCheck" => {
                let key_item = parse_key(inner)?;
                let key = guard.key_of(&key_item)?;
                let old = guard.items.get(&key).cloned();
                let stage = if verb == "Delete" {
                    StagedWrite::Delete {
                        table: table_name.to_string(),
                        key: key.clone(),
                        old: old.clone(),
                    }
                } else {
                    StagedWrite::Check
                };
                (key, old, stage)
            }
            other => {
                return Err(DdbError::Validation(format!(
                    "unknown transaction verb {other}"
                )))
            }
        };

        if seen
            .iter()
            .any(|(table, existing_key)| table == table_name && *existing_key == key)
        {
            return Err(DdbError::Validation(
                "Transaction request cannot include multiple operations on one item".into(),
            ));
        }
        seen.push((table_name.to_string(), key));

        match check_condition(inner, old.as_ref().unwrap_or(&Item::new())) {
            Ok(()) => reasons.push(CancellationReason::none()),
            Err(DdbError::ConditionalCheckFailed(_)) => {
                any_failed = true;
                reasons.push(CancellationReason::new(
                    "ConditionalCheckFailed",
                    Some("The conditional request failed".into()),
                ));
            }
            Err(error) => return Err(error),
        }
        staged.push(stage);
    }

    if any_failed {
        return Err(DdbError::TransactionCanceled(reasons));
    }

    for write in staged {
        match write {
            StagedWrite::Put {
                table,
                key,
                old,
                new,
            } => {
                let guard = guards.get_mut(&table).unwrap();
                guard.emit_stream(old.as_ref(), Some(&new));
                guard.items.insert(key, new);
            }
            StagedWrite::Delete { table, key, old } => {
                let guard = guards.get_mut(&table).unwrap();
                if old.is_some() {
                    guard.emit_stream(old.as_ref(), None);
                } else {
                    guard.record_replica_change(key.clone(), None);
                }
                guard.items.remove(&key);
            }
            StagedWrite::Check => {}
        }
    }
    Ok(json!({}))
}

pub async fn transact_get_items(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let actions = req
        .get("TransactItems")
        .and_then(Value::as_array)
        .ok_or_else(|| DdbError::Validation("TransactItems is required".into()))?;
    if actions.is_empty() || actions.len() > 100 {
        return Err(DdbError::Validation(
            "TransactItems must have 1..=100 actions".into(),
        ));
    }
    let mut responses = Vec::with_capacity(actions.len());
    for action in actions {
        let get = action
            .get("Get")
            .ok_or_else(|| DdbError::Validation("transaction action must be Get".into()))?;
        let table_name = req_str(get, "TableName")?;
        let table = get_table(ctx, table_name).await?;
        let guard = table.read().await;
        let key_item = parse_key(get)?;
        let key = guard.key_of(&key_item)?;
        match guard.items.get(&key) {
            Some(item) => {
                responses.push(json!({ "Item": item_to_json(&maybe_project(get, item)?) }))
            }
            None => responses.push(json!({})),
        }
    }
    Ok(json!({ "Responses": responses }))
}

// ============================ Kinesis streaming destination ====================

pub async fn enable_kinesis_streaming_destination(
    ctx: &Ctx<'_>,
    req: &Value,
) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let stream_arn = req_str(req, "StreamArn")?.to_string();
    let table = get_table(ctx, name).await?;
    let mut guard = table.write().await;
    if let Some(dest) = guard
        .kinesis_destinations
        .iter_mut()
        .find(|d| d.stream_arn == stream_arn)
    {
        dest.status = "ACTIVE".to_string();
    } else {
        guard.kinesis_destinations.push(KinesisDestination {
            stream_arn: stream_arn.clone(),
            status: "ACTIVE".to_string(),
        });
    }
    Ok(json!({ "TableName": name, "StreamArn": stream_arn, "DestinationStatus": "ACTIVE" }))
}

pub async fn disable_kinesis_streaming_destination(
    ctx: &Ctx<'_>,
    req: &Value,
) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let stream_arn = req_str(req, "StreamArn")?.to_string();
    let table = get_table(ctx, name).await?;
    let mut guard = table.write().await;
    guard
        .kinesis_destinations
        .retain(|d| d.stream_arn != stream_arn);
    guard
        .kinesis_pending
        .retain(|(pending_arn, _)| pending_arn != &stream_arn);
    Ok(json!({ "TableName": name, "StreamArn": stream_arn, "DestinationStatus": "DISABLED" }))
}

pub async fn describe_kinesis_streaming_destination(
    ctx: &Ctx<'_>,
    req: &Value,
) -> Result<Value, DdbError> {
    let name = req_str(req, "TableName")?;
    let table = get_table(ctx, name).await?;
    let guard = table.read().await;
    let destinations: Vec<Value> = guard
        .kinesis_destinations
        .iter()
        .map(|d| json!({ "StreamArn": d.stream_arn, "DestinationStatus": d.status }))
        .collect();
    Ok(json!({ "TableName": name, "KinesisDataStreamDestinations": destinations }))
}

// ============================ Export to point in time ==========================

pub async fn export_table_to_point_in_time(
    _ctx: &Ctx<'_>,
    _req: &Value,
) -> Result<Value, DdbError> {
    Err(DdbError::Validation(
        "ExportTableToPointInTime is unavailable until an S3 export can be materialized".into(),
    ))
}

fn export_description(
    export_arn: &str,
    table_arn: &str,
    status: &str,
    start_time: f64,
    s3_bucket: Option<&str>,
) -> Value {
    let mut out = json!({
        "ExportArn": export_arn,
        "ExportStatus": status,
        "TableArn": table_arn,
        "StartTime": start_time,
        "ExportFormat": "DYNAMODB_JSON",
    });
    if let Some(bucket) = s3_bucket {
        out["S3Bucket"] = json!(bucket);
    }
    out
}

pub async fn describe_export(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let export_arn = req_str(req, "ExportArn")?;
    let table_name = export_arn
        .split("table/")
        .nth(1)
        .and_then(|s| s.split("/export/").next())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DdbError::ExportNotFound(format!("Export not found: {export_arn}")))?;
    let table = ctx
        .store
        .get(ctx.account, ctx.region, table_name)
        .ok_or_else(|| DdbError::ExportNotFound(format!("Export not found: {export_arn}")))?;
    let guard = table.read().await;
    let job = guard
        .exports
        .iter()
        .find(|e| e.export_arn == export_arn)
        .ok_or_else(|| DdbError::ExportNotFound(format!("Export not found: {export_arn}")))?;
    Ok(json!({
        "ExportDescription": export_description(
            &job.export_arn,
            &guard.def.arn,
            &job.status,
            job.start_time,
            job.s3_bucket.as_deref(),
        )
    }))
}

pub async fn list_exports(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    // Optional TableArn filter; otherwise all exports in scope.
    let table_filter = req
        .get("TableArn")
        .and_then(Value::as_str)
        .map(name_from_arn)
        .transpose()?;
    let mut summaries = Vec::new();
    let names = match table_filter {
        Some(n) => vec![n.to_string()],
        None => ctx.store.list_names(ctx.account, ctx.region),
    };
    for name in names {
        if let Some(table) = ctx.store.get(ctx.account, ctx.region, &name) {
            let guard = table.read().await;
            for job in &guard.exports {
                summaries.push(json!({ "ExportArn": job.export_arn, "ExportStatus": job.status }));
            }
        }
    }
    Ok(json!({ "ExportSummaries": summaries }))
}

#[cfg(test)]
mod global_table_tests {
    use super::*;

    #[tokio::test]
    async fn deleting_replica_waits_for_its_local_writes() {
        let store = TableStore::new();
        let east = Ctx {
            store: &store,
            account: "123456789012",
            region: "us-east-1",
        };
        let west = Ctx {
            store: &store,
            account: "123456789012",
            region: "us-west-2",
        };
        create_table(
            &east,
            &json!({
                "TableName":"pending-delete", "KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],
                "AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],
                "BillingMode":"PAY_PER_REQUEST"
            }),
        )
        .await
        .unwrap();
        update_table(&east, &json!({"TableName":"pending-delete","ReplicaUpdates":[{"Create":{"RegionName":"us-west-2"}}]})).await.unwrap();
        put_item(
            &west,
            &json!({"TableName":"pending-delete","Item":{"pk":{"S":"important"}}}),
        )
        .await
        .unwrap();
        let delete = json!({"TableName":"pending-delete","ReplicaUpdates":[{"Delete":{"RegionName":"us-west-2"}}]});
        assert!(matches!(
            update_table(&east, &delete).await,
            Err(DdbError::ResourceInUse(_))
        ));
        assert!(store
            .get(east.account, west.region, "pending-delete")
            .is_some());
        replicate_pending(&store).await;
        update_table(&east, &delete).await.unwrap();
        assert!(store
            .get(east.account, west.region, "pending-delete")
            .is_none());
        assert!(get_item(
            &east,
            &json!({"TableName":"pending-delete","Key":{"pk":{"S":"important"}}})
        )
        .await
        .unwrap()
        .get("Item")
        .is_some());
    }

    #[tokio::test]
    async fn topology_change_cannot_overtake_drained_replication() {
        let store = Arc::new(TableStore::new());
        let east = Ctx {
            store: &store,
            account: "123456789012",
            region: "us-east-1",
        };
        let west = Ctx {
            store: &store,
            account: "123456789012",
            region: "us-west-2",
        };
        create_table(
            &east,
            &json!({
                "TableName":"race", "KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],
                "AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],
                "BillingMode":"PAY_PER_REQUEST"
            }),
        )
        .await
        .unwrap();
        update_table(
            &east,
            &json!({"TableName":"race","ReplicaUpdates":[{"Create":{"RegionName":"us-west-2"}}]}),
        )
        .await
        .unwrap();
        put_item(
            &west,
            &json!({"TableName":"race","Item":{"pk":{"S":"pending"}}}),
        )
        .await
        .unwrap();
        let topology = store.replica_topology.lock().await;
        let replica_store = store.clone();
        let sweep = tokio::spawn(async move { replicate_pending(&replica_store).await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !sweep.is_finished(),
            "replication must wait for topology changes"
        );
        assert_eq!(
            store
                .get(west.account, west.region, "race")
                .unwrap()
                .read()
                .await
                .replica_pending
                .len(),
            1
        );
        drop(topology);
        sweep.await.unwrap();
        update_table(
            &east,
            &json!({"TableName":"race","ReplicaUpdates":[{"Create":{"RegionName":"eu-west-1"}}]}),
        )
        .await
        .unwrap();
        let eu = Ctx {
            store: &store,
            account: east.account,
            region: "eu-west-1",
        };
        assert!(get_item(
            &eu,
            &json!({"TableName":"race","Key":{"pk":{"S":"pending"}}})
        )
        .await
        .unwrap()
        .get("Item")
        .is_some());
    }

    #[tokio::test]
    async fn mrec_bootstrap_bidirectional_writes_and_delete() {
        let store = TableStore::new();
        let east = Ctx {
            store: &store,
            account: "123456789012",
            region: "us-east-1",
        };
        let west = Ctx {
            store: &store,
            account: "123456789012",
            region: "us-west-2",
        };
        create_table(
            &east,
            &json!({
                "TableName": "events", "KeySchema": [{"AttributeName":"pk","KeyType":"HASH"}],
                "AttributeDefinitions": [{"AttributeName":"pk","AttributeType":"S"}],
                "BillingMode": "PAY_PER_REQUEST"
            }),
        )
        .await
        .unwrap();
        put_item(
            &east,
            &json!({"TableName":"events","Item":{"pk":{"S":"one"},"v":{"S":"before"}}}),
        )
        .await
        .unwrap();
        let updated = update_table(
            &east,
            &json!({"TableName":"events","ReplicaUpdates":[{"Create":{"RegionName":"us-west-2"}}]}),
        )
        .await
        .unwrap();
        assert_eq!(
            updated["TableDescription"]["GlobalTableVersion"],
            "2019.11.21"
        );
        assert_eq!(
            updated["TableDescription"]["Replicas"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(get_item(
            &west,
            &json!({"TableName":"events","Key":{"pk":{"S":"one"}}})
        )
        .await
        .unwrap()
        .get("Item")
        .is_some());

        put_item(
            &west,
            &json!({"TableName":"events","Item":{"pk":{"S":"two"},"v":{"S":"west"}}}),
        )
        .await
        .unwrap();
        assert!(get_item(
            &east,
            &json!({"TableName":"events","Key":{"pk":{"S":"two"}}})
        )
        .await
        .unwrap()
        .get("Item")
        .is_none());
        replicate_pending(&store).await;
        assert_eq!(
            get_item(
                &east,
                &json!({"TableName":"events","Key":{"pk":{"S":"two"}}})
            )
            .await
            .unwrap()["Item"]["v"]["S"],
            "west"
        );

        delete_item(
            &east,
            &json!({"TableName":"events","Key":{"pk":{"S":"one"}}}),
        )
        .await
        .unwrap();
        replicate_pending(&store).await;
        assert!(get_item(
            &west,
            &json!({"TableName":"events","Key":{"pk":{"S":"one"}}})
        )
        .await
        .unwrap()
        .get("Item")
        .is_none());
        assert!(get_item(
            &west,
            &json!({"TableName":"events","Key":{"pk":{"S":"two"}}})
        )
        .await
        .unwrap()
        .get("Item")
        .is_some());
        update_table(
            &east,
            &json!({"TableName":"events","ReplicaUpdates":[{"Delete":{"RegionName":"us-west-2"}}]}),
        )
        .await
        .unwrap();
        assert!(store.get(east.account, west.region, "events").is_none());
    }
}
