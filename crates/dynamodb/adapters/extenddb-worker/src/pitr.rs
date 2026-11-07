//! Validate the AWS boundary; the SQLite extension owns PITR history and restore transactions.
use extenddb_core::error::DynamoDbError;
use extenddb_engine::OperationContext;
use extenddb_storage::error::StorageError;
use extenddb_storage_sqlite::SqliteEngine;
use serde_json::Value;

type Result<T> = std::result::Result<T, DynamoDbError>;

fn invalid(message: &str) -> DynamoDbError {
    DynamoDbError::ValidationException(message.into())
}

fn storage(error: StorageError) -> DynamoDbError {
    match error {
        StorageError::Validation(message) if message.starts_with("PITR_UNAVAILABLE:") => {
            DynamoDbError::PointInTimeRecoveryUnavailableException(
                "Point in time recovery is unavailable for the source table".into(),
            )
        }
        StorageError::Validation(message) if message.starts_with("PITR_INVALID_TIME:") => {
            DynamoDbError::InvalidRestoreTimeException(
                "Restore time is outside the available recovery window".into(),
            )
        }
        StorageError::Validation(message) | StorageError::Unsupported(message) => invalid(&message),
        StorageError::TableNotFound(_) => {
            DynamoDbError::TableNotFoundException("Source table does not exist".into())
        }
        StorageError::TableAlreadyExists(_) => {
            DynamoDbError::TableAlreadyExistsException("Target table already exists".into())
        }
        StorageError::TableNotActive(_) | StorageError::IndexesInUse(_) => {
            DynamoDbError::TableInUseException("Source table or index is not ACTIVE".into())
        }
        _ => DynamoDbError::InternalServerError("PITR storage operation failed".into()),
    }
}

fn name(value: &str) -> Result<String> {
    if !(3..=255).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(invalid("Invalid table name"));
    }
    Ok(value.into())
}

fn table(value: &str, account: &str, region: &str) -> Result<String> {
    let table = if value.starts_with("arn:") {
        value
            .strip_prefix(&format!("arn:aws:dynamodb:{region}:{account}:table/"))
            .ok_or_else(|| invalid("Source table ARN must match account and region"))?
    } else {
        value
    };
    name(table)
}

fn string<'a>(body: &'a Value, field: &str) -> Result<&'a str> {
    body.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("{field} is required")))
}

#[derive(Debug, PartialEq)]
enum Request {
    Describe(String),
    Configure {
        table: String,
        enabled: bool,
        days: Option<u32>,
    },
    Restore {
        source: String,
        target: String,
        at: Option<f64>,
    },
}

fn parse(operation: &str, body: &Value, account: &str, region: &str) -> Result<Request> {
    let allowed = match operation {
        "DescribeContinuousBackups" => &["TableName"][..],
        "UpdateContinuousBackups" => &["TableName", "PointInTimeRecoverySpecification"][..],
        "RestoreTableToPointInTime" => &[
            "SourceTableName",
            "SourceTableArn",
            "TargetTableName",
            "RestoreDateTime",
            "UseLatestRestorableTime",
            "TableName",
        ][..],
        _ => return Err(invalid("Unknown PITR operation")),
    };
    if body.as_object().is_none_or(|fields| {
        fields
            .keys()
            .any(|field| !allowed.contains(&field.as_str()))
    }) {
        return Err(invalid(
            "PITR overrides or unknown fields are not supported",
        ));
    }
    match operation {
        "DescribeContinuousBackups" => Ok(Request::Describe(table(
            string(body, "TableName")?,
            account,
            region,
        )?)),
        "UpdateContinuousBackups" => {
            let table = table(string(body, "TableName")?, account, region)?;
            let spec = body
                .get("PointInTimeRecoverySpecification")
                .and_then(Value::as_object)
                .ok_or_else(|| invalid("PointInTimeRecoverySpecification is required"))?;
            if spec.keys().any(|field| {
                !matches!(
                    field.as_str(),
                    "PointInTimeRecoveryEnabled" | "RecoveryPeriodInDays"
                )
            }) {
                return Err(invalid("Unknown PITR setting"));
            }
            let enabled = spec
                .get("PointInTimeRecoveryEnabled")
                .and_then(Value::as_bool)
                .ok_or_else(|| invalid("PointInTimeRecoveryEnabled must be a boolean"))?;
            let days = spec
                .get("RecoveryPeriodInDays")
                .map(|days| {
                    days.as_u64()
                        .filter(|days| (1..=35).contains(days))
                        .map(|days| days as u32)
                        .ok_or_else(|| {
                            invalid("RecoveryPeriodInDays must be an integer from 1 to 35")
                        })
                })
                .transpose()?;
            Ok(Request::Configure {
                table,
                enabled,
                days,
            })
        }
        "RestoreTableToPointInTime" => {
            let source = match (body.get("SourceTableName"), body.get("SourceTableArn")) {
                (Some(source), None) => source
                    .as_str()
                    .ok_or_else(|| invalid("SourceTableName must be a string"))?,
                (None, Some(source)) => source
                    .as_str()
                    .filter(|source| source.starts_with("arn:"))
                    .ok_or_else(|| invalid("SourceTableArn must be a table ARN"))?,
                _ => return Err(invalid("Specify exactly one source table name or ARN")),
            };
            let source = table(source, account, region)?;
            let target = name(string(body, "TargetTableName")?)?;
            if body
                .get("TableName")
                .is_some_and(|alias| alias.as_str() != Some(target.as_str()))
            {
                return Err(invalid(
                    "Internal target alias does not match TargetTableName",
                ));
            }
            let latest = body
                .get("UseLatestRestorableTime")
                .map(|value| {
                    value
                        .as_bool()
                        .ok_or_else(|| invalid("UseLatestRestorableTime must be a boolean"))
                })
                .transpose()?
                .unwrap_or(false);
            let at = body
                .get("RestoreDateTime")
                .map(|value| {
                    value
                        .as_f64()
                        .filter(|value| value.is_finite())
                        .ok_or_else(|| invalid("RestoreDateTime must be a finite number"))
                })
                .transpose()?;
            if latest == at.is_some() {
                return Err(invalid(
                    "Specify a restore time or UseLatestRestorableTime=true",
                ));
            }
            Ok(Request::Restore { source, target, at })
        }
        _ => Err(invalid("Unknown PITR operation")),
    }
}

pub async fn dispatch(
    operation: &str,
    body: Value,
    context: &OperationContext,
    sqlite: &SqliteEngine,
) -> Result<Value> {
    match parse(operation, &body, &context.account_id, &context.region)? {
        Request::Describe(table) => sqlite
            .pitr_describe(&context.account_id, &table)
            .await
            .map_err(storage),
        Request::Configure {
            table,
            enabled,
            days,
        } => sqlite
            .pitr_configure(&context.account_id, &table, enabled, days)
            .await
            .map_err(storage),
        Request::Restore { source, target, at } => sqlite
            .pitr_restore(&context.account_id, &source, &target, at)
            .await
            .map_err(storage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const ACCOUNT: &str = "000000000000";
    const REGION: &str = "us-east-1";

    #[test]
    fn restore_parses_scoped_arn_and_exact_real_time_selection() {
        assert_eq!(parse("RestoreTableToPointInTime",&json!({"SourceTableArn":format!("arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/source"),"TargetTableName":"target","RestoreDateTime":123.5}),ACCOUNT,REGION).unwrap(),Request::Restore{source:"source".into(),target:"target".into(),at:Some(123.5)});
        for invalid in [
            json!({"SourceTableName":"source","TargetTableName":"target"}),
            json!({"SourceTableName":"source","TargetTableName":"target","UseLatestRestorableTime":true,"RestoreDateTime":1}),
            json!({"SourceTableName":"source","TargetTableName":"target","RestoreDateTime":"1"}),
            json!({"SourceTableArn":"arn:aws:dynamodb:us-west-2:000000000000:table/source","TargetTableName":"target","UseLatestRestorableTime":true}),
            json!({"SourceTableName":"source","SourceTableArn":"anything","TargetTableName":"target","UseLatestRestorableTime":true}),
            json!({"SourceTableName":"source","TargetTableName":"target","UseLatestRestorableTime":true,"SSESpecificationOverride":{}}),
        ] {
            assert!(parse("RestoreTableToPointInTime", &invalid, ACCOUNT, REGION).is_err());
        }
    }

    #[test]
    fn recovery_period_and_specification_are_strictly_validated() {
        for days in [json!(0), json!(36), json!(1.5), json!("7")] {
            assert!(parse("UpdateContinuousBackups",&json!({"TableName":"source","PointInTimeRecoverySpecification":{"PointInTimeRecoveryEnabled":true,"RecoveryPeriodInDays":days}}),ACCOUNT,REGION).is_err());
        }
        assert_eq!(parse("UpdateContinuousBackups",&json!({"TableName":"source","PointInTimeRecoverySpecification":{"PointInTimeRecoveryEnabled":true,"RecoveryPeriodInDays":7}}),ACCOUNT,REGION).unwrap(),Request::Configure{table:"source".into(),enabled:true,days:Some(7)});
        assert!(matches!(
            storage(StorageError::Validation("PITR_UNAVAILABLE:disabled".into())),
            DynamoDbError::PointInTimeRecoveryUnavailableException(_)
        ));
        assert!(matches!(
            storage(StorageError::Validation("PITR_INVALID_TIME:outside".into())),
            DynamoDbError::InvalidRestoreTimeException(_)
        ));
    }

    #[test]
    fn restore_collision_and_inactive_source_use_the_documented_pitr_error_types() {
        assert!(matches!(
            storage(StorageError::TableAlreadyExists("target".into())),
            DynamoDbError::TableAlreadyExistsException(_)
        ));
        assert!(matches!(
            storage(StorageError::TableNotActive("source".into())),
            DynamoDbError::TableInUseException(_)
        ));
    }
}
