//! Adapt optional backup fields while the official engine owns snapshots and restores.
use extenddb_core::error::DynamoDbError;
use extenddb_engine::OperationContext;
use extenddb_storage::error::StorageError;
use extenddb_storage_sqlite::SqliteEngine;
use serde_json::{json, Value};

type Result<T> = std::result::Result<T, DynamoDbError>;

fn validation(message: &str) -> DynamoDbError {
    DynamoDbError::ValidationException(message.into())
}

fn storage(error: StorageError) -> DynamoDbError {
    match error {
        StorageError::Validation(message) if message.starts_with("Backup not found:") => {
            DynamoDbError::BackupNotFoundException("Backup does not exist or has expired".into())
        }
        StorageError::Validation(message) | StorageError::Unsupported(message) => {
            validation(&message)
        }
        StorageError::TableNotFound(message) => DynamoDbError::ResourceNotFoundException(message),
        _ => DynamoDbError::InternalServerError("backup metadata operation failed".into()),
    }
}

fn require_public_backup(kind: &str) -> Result<()> {
    match kind {
        "USER" | "SYSTEM" => Ok(()),
        _ => Err(DynamoDbError::BackupNotFoundException(
            "Backup does not exist".into(),
        )),
    }
}

fn name(value: &str) -> Result<()> {
    if !(3..=255).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(validation("invalid table or backup name"));
    }
    Ok(())
}

fn table(value: &str, account: &str, region: &str) -> Result<String> {
    let prefix = format!("arn:aws:dynamodb:{}:{}:table/", region, account);
    let value = if value.starts_with("arn:") {
        value
            .strip_prefix(&prefix)
            .ok_or_else(|| validation("table ARN must match account and region"))?
    } else {
        value
    };
    name(value)?;
    Ok(value.into())
}

fn backup_arn(value: &str, account: &str, region: &str) -> Result<()> {
    let prefix = format!("arn:aws:dynamodb:{}:{}:table/", region, account);
    let resource = value
        .strip_prefix(&prefix)
        .ok_or_else(|| validation("backup ARN must match account and region"))?;
    let (table, id) = resource
        .split_once("/backup/")
        .ok_or_else(|| validation("invalid backup ARN"))?;
    name(table)?;
    if value.len() > 1024
        || id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(validation("invalid backup ARN"));
    }
    Ok(())
}

fn required<'a>(body: &'a Value, key: &str) -> Result<&'a str> {
    body.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| validation(&format!("{key} is required")))
}

#[derive(Debug, PartialEq)]
enum BackupFilter {
    User,
    System,
    All,
    External,
}

impl BackupFilter {
    fn storage_kind(&self) -> Option<&'static str> {
        match self {
            Self::User => Some("USER"),
            Self::System => Some("SYSTEM"),
            Self::All => None,
            Self::External => Some("AWS_BACKUP"),
        }
    }
}

#[derive(Debug, PartialEq)]
struct Listing {
    table: Option<String>,
    start: String,
    lower: Option<f64>,
    upper: Option<f64>,
    limit: u32,
    backup_type: BackupFilter,
}

fn listing(body: &Value, account: &str, region: &str) -> Result<Listing> {
    let table = body
        .get("TableName")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| validation("invalid TableName"))
                .and_then(|v| table(v, account, region))
        })
        .transpose()?;
    let limit = match body.get("Limit") {
        None => 100,
        Some(value) => value
            .as_u64()
            .filter(|v| (1..=100).contains(v))
            .ok_or_else(|| validation("Limit must be an integer between 1 and 100"))?
            as u32,
    };
    let start = body
        .get("ExclusiveStartBackupArn")
        .map(|v| {
            v.as_str()
                .ok_or_else(|| validation("invalid ExclusiveStartBackupArn"))
        })
        .transpose()?
        .unwrap_or("");
    if body.get("ExclusiveStartBackupArn").is_some() {
        backup_arn(start, account, region)?;
    }
    let timestamp = |field: &str| -> Result<Option<f64>> {
        body.get(field)
            .map(|v| {
                v.as_f64()
                    .filter(|v| v.is_finite())
                    .ok_or_else(|| validation("invalid backup time range"))
            })
            .transpose()
    };
    let lower = timestamp("TimeRangeLowerBound")?;
    let upper = timestamp("TimeRangeUpperBound")?;
    if matches!((lower, upper), (Some(lower),Some(upper)) if lower>upper) {
        return Err(validation("invalid backup time range"));
    }
    let backup_type = match body.get("BackupType") {
        None => BackupFilter::User,
        Some(Value::String(value)) => match value.as_str() {
            "USER" => BackupFilter::User,
            "SYSTEM" => BackupFilter::System,
            "ALL" => BackupFilter::All,
            "AWS_BACKUP" => BackupFilter::External,
            _ => return Err(validation("invalid BackupType")),
        },
        _ => return Err(validation("invalid BackupType")),
    };
    Ok(Listing {
        table,
        start: start.into(),
        lower,
        upper,
        limit,
        backup_type,
    })
}

fn project(source: &Value, fields: &[&str]) -> Value {
    let mut result = json!({});
    for field in fields {
        if let Some(value) = source.get(*field) {
            result[*field] = value.clone();
        }
    }
    result
}

fn decorate(output: &mut Value, snapshot: &Value) {
    let Some(description) = output.get_mut("BackupDescription") else {
        return;
    };
    let Some(details) = description.get_mut("SourceTableDetails") else {
        return;
    };
    if let Some(created) = snapshot.get("CreationDateTime") {
        details["TableCreationDateTime"] = created.clone();
    }
    if let Some(throughput) = snapshot.get("ProvisionedThroughput") {
        details["ProvisionedThroughput"] =
            project(throughput, &["ReadCapacityUnits", "WriteCapacityUnits"]);
    }
    if let Some(throughput) = snapshot.get("OnDemandThroughput") {
        details["OnDemandThroughput"] = throughput.clone();
    }
    let mut features = json!({});
    for field in [
        "GlobalSecondaryIndexes",
        "LocalSecondaryIndexes",
        "VectorIndexes",
    ] {
        if let Some(indexes) = snapshot.get(field).and_then(Value::as_array) {
            let items = indexes
                .iter()
                .map(|index| {
                    let mut item = project(
                        index,
                        &[
                            "IndexName",
                            "KeySchema",
                            "Projection",
                            "OnDemandThroughput",
                            "VectorAttribute",
                            "Dimensions",
                            "DistanceFunction",
                            "SearchSchema",
                        ],
                    );
                    if let Some(throughput) = index.get("ProvisionedThroughput") {
                        item["ProvisionedThroughput"] =
                            project(throughput, &["ReadCapacityUnits", "WriteCapacityUnits"]);
                    }
                    item
                })
                .collect::<Vec<_>>();
            features[field] = json!(items);
        }
    }
    for (source, target) in [
        ("StreamSpecification", "StreamDescription"),
        ("TimeToLiveDescription", "TimeToLiveDescription"),
        ("SSEDescription", "SSEDescription"),
    ] {
        if let Some(value) = snapshot.get(source) {
            features[target] = value.clone();
        }
    }
    description["SourceTableFeatureDetails"] = features;
}

pub async fn dispatch(
    operation: &str,
    mut body: Value,
    context: &OperationContext,
    sqlite: &SqliteEngine,
) -> Result<Value> {
    match operation {
        "ListBackups" => {
            let request = listing(&body, &context.account_id, &context.region)?;
            if request.backup_type == BackupFilter::External {
                return Ok(json!({"BackupSummaries":[]}));
            }
            let mut records = sqlite
                .list_backup_page_typed(
                    &context.account_id,
                    request.table.as_deref(),
                    &request.start,
                    request.lower,
                    request.upper,
                    request.limit + 1,
                    request.backup_type.storage_kind(),
                )
                .await
                .map_err(storage)?;
            let more = records.len() > request.limit as usize;
            records.truncate(request.limit as usize);
            let cursor = records.last().map(|v| v.backup_arn.clone());
            let mut summaries = Vec::with_capacity(records.len());
            for record in records {
                let expiry = if record.backup_type == "SYSTEM" {
                    sqlite
                        .backup_expiry(&context.account_id, &record.backup_arn)
                        .await
                        .map_err(storage)?
                } else {
                    None
                };
                let mut value = serde_json::to_value(record).map_err(|_| {
                    DynamoDbError::InternalServerError("Cannot serialize backup summary".into())
                })?;
                if let Some(expiry) = expiry {
                    value["BackupExpiryDateTime"] = json!(expiry);
                }
                summaries.push(value);
            }
            let mut output = json!({"BackupSummaries":summaries});
            if more {
                output["LastEvaluatedBackupArn"] = json!(cursor);
            }
            return Ok(output);
        }
        "CreateBackup" => {
            let table = table(
                required(&body, "TableName")?,
                &context.account_id,
                &context.region,
            )?;
            name(required(&body, "BackupName")?)?;
            body["TableName"] = json!(table);
        }
        "RestoreTableFromBackup" => {
            name(required(&body, "TargetTableName")?)?;
            if body.as_object().is_none_or(|fields| {
                fields.keys().any(|key| {
                    !matches!(key.as_str(), "BackupArn" | "TargetTableName" | "TableName")
                })
            }) {
                return Err(validation("backup restore overrides are not yet supported"));
            }
            backup_arn(
                required(&body, "BackupArn")?,
                &context.account_id,
                &context.region,
            )?;
        }
        "DescribeBackup" | "DeleteBackup" => backup_arn(
            required(&body, "BackupArn")?,
            &context.account_id,
            &context.region,
        )?,
        _ => return Err(validation("invalid backup operation")),
    }
    let identity = if matches!(
        operation,
        "DescribeBackup" | "DeleteBackup" | "RestoreTableFromBackup"
    ) {
        let arn = required(&body, "BackupArn")?;
        let kind = sqlite
            .backup_kind(&context.account_id, arn)
            .await
            .map_err(storage)?;
        require_public_backup(&kind)?;
        let expiry = sqlite
            .backup_expiry(&context.account_id, arn)
            .await
            .map_err(storage)?;
        Some((kind, expiry))
    } else {
        None
    };
    let snapshot = if matches!(operation, "DescribeBackup" | "DeleteBackup") {
        sqlite
            .backup_snapshot(&context.account_id, required(&body, "BackupArn")?)
            .await
            .map_err(storage)?
    } else {
        None
    };
    let mut output = extenddb_engine::dispatch(operation, body, context, "localhost")
        .await?
        .body;
    if let Some(snapshot) = snapshot {
        decorate(&mut output, &snapshot);
    }
    if let Some((kind, expiry)) =
        identity.filter(|_| matches!(operation, "DescribeBackup" | "DeleteBackup"))
    {
        let details = output
            .pointer_mut("/BackupDescription/BackupDetails")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                DynamoDbError::InternalServerError(
                    "Backup description is missing its details".into(),
                )
            })?;
        details.insert("BackupType".into(), json!(kind));
        if let Some(expiry) = expiry {
            details.insert("BackupExpiryDateTime".into(), json!(expiry));
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_descriptions_include_real_source_schema_not_current_source_state() {
        let mut output =
            json!({"BackupDescription":{"SourceTableDetails":{"TableCreationDateTime":99}}});
        decorate(
            &mut output,
            &json!({"CreationDateTime":1,"ProvisionedThroughput":{"ReadCapacityUnits":7,"WriteCapacityUnits":11,"LastIncreaseDateTime":2},"GlobalSecondaryIndexes":[{"IndexName":"by-value","KeySchema":[],"Projection":{"ProjectionType":"ALL"},"IndexStatus":"ACTIVE","ProvisionedThroughput":{"ReadCapacityUnits":3,"WriteCapacityUnits":4}}],"TimeToLiveDescription":{"TimeToLiveStatus":"ENABLED","AttributeName":"expires"},"StreamSpecification":{"StreamEnabled":true,"StreamViewType":"KEYS_ONLY"}}),
        );
        let details = &output["BackupDescription"];
        assert_eq!(details["SourceTableDetails"]["TableCreationDateTime"], 1);
        assert_eq!(
            details["SourceTableDetails"]["ProvisionedThroughput"],
            json!({"ReadCapacityUnits":7,"WriteCapacityUnits":11})
        );
        let features = &details["SourceTableFeatureDetails"];
        assert_eq!(
            features["GlobalSecondaryIndexes"][0]["ProvisionedThroughput"]["ReadCapacityUnits"],
            3
        );
        assert!(features["GlobalSecondaryIndexes"][0]
            .get("IndexStatus")
            .is_none());
        assert_eq!(features["StreamDescription"]["StreamViewType"], "KEYS_ONLY");
        assert_eq!(
            features["TimeToLiveDescription"]["AttributeName"],
            "expires"
        );
    }

    #[test]
    fn list_bounds_filters_and_cursor_scope_are_validated_before_storage() {
        let account = "000000000000";
        let region = "us-east-1";
        let parse = |body: &Value| listing(body, account, region);
        assert_eq!(parse(&json!({})).unwrap().limit, 100);
        assert_eq!(
            parse(&json!({"Limit":1,"BackupType":"SYSTEM"}))
                .unwrap()
                .backup_type,
            BackupFilter::System
        );
        assert_eq!(
            parse(&json!({"BackupType":"ALL"})).unwrap().backup_type,
            BackupFilter::All
        );
        assert_eq!(parse(&json!({})).unwrap().backup_type, BackupFilter::User);
        for body in [
            json!({"Limit":0}),
            json!({"Limit":101}),
            json!({"Limit":1.5}),
            json!({"TableName":"../escape"}),
            json!({"TimeRangeLowerBound":2,"TimeRangeUpperBound":1}),
            json!({"BackupType":"other"}),
            json!({"ExclusiveStartBackupArn":"arn:aws:dynamodb:us-east-2:000000000000:table/orders/backup/123-abc"}),
        ] {
            assert!(parse(&body).is_err());
        }
        let request=parse(&json!({"Limit":2,"TableName":"arn:aws:dynamodb:us-east-1:000000000000:table/orders","TimeRangeLowerBound":1,"TimeRangeUpperBound":2})).unwrap();
        assert_eq!(request.table.as_deref(), Some("orders"));
        assert_eq!(request.lower, Some(1.0));
        assert_eq!(request.upper, Some(2.0));
    }

    #[test]
    fn absent_or_expired_backup_metadata_uses_canonical_backup_not_found_error() {
        assert!(matches!(
            storage(StorageError::Validation(
                "Backup not found: private arn".into()
            )),
            DynamoDbError::BackupNotFoundException(_)
        ));
    }

    #[test]
    fn public_backup_operations_never_admit_internal_snapshot_arns() {
        assert!(require_public_backup("USER").is_ok());
        assert!(require_public_backup("SYSTEM").is_ok());
        for kind in ["INTERNAL", "FUTURE", ""] {
            assert!(matches!(
                require_public_backup(kind),
                Err(DynamoDbError::BackupNotFoundException(_))
            ));
        }
    }
}
