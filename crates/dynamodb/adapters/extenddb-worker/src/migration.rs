//! Private offline-only history commands; unavailable to ordinary runtime workers.
use extenddb_core::error::DynamoDbError;
use extenddb_core::types::Item;
use extenddb_engine::OperationContext;
use extenddb_storage::error::StorageError;
use extenddb_storage_sqlite::SqliteEngine;
use serde::Deserialize;
use serde_json::Value;

use crate::WorkerMode;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Begin {
    table_name: String,
    enabled: bool,
    started: f64,
    latest: f64,
    days: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Put {
    table_name: String,
    key: Item,
    at: f64,
    item: Option<Item>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Get {
    table_name: String,
    key: Item,
    at: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Describe {
    table_name: String,
}

fn invalid() -> DynamoDbError {
    DynamoDbError::ValidationException("Invalid offline history command".into())
}

fn parse<T: serde::de::DeserializeOwned>(body: Value) -> Result<T, DynamoDbError> {
    let name = body
        .get("TableName")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if !(3..=255).contains(&name.len())
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(invalid());
    }
    serde_json::from_value(body).map_err(|_| invalid())
}

pub async fn dispatch(
    operation: &str,
    body: Value,
    mode: WorkerMode,
    context: &OperationContext,
    sqlite: &SqliteEngine,
) -> Result<Value, DynamoDbError> {
    if mode != WorkerMode::Migration {
        return Err(invalid());
    }
    let account = &context.account_id;
    let result = match operation {
        "__locallycloud_migration_history_begin" => {
            let value: Begin = parse(body)?;
            sqlite
                .native_history_begin(
                    account,
                    &value.table_name,
                    value.enabled,
                    value.started,
                    value.latest,
                    value.days,
                )
                .await
        }
        "__locallycloud_migration_history_put" => {
            if body.get("Item").is_none() {
                return Err(invalid());
            }
            let value: Put = parse(body)?;
            sqlite
                .native_history_put(
                    account,
                    &value.table_name,
                    value.at,
                    &value.key,
                    value.item.as_ref(),
                )
                .await
        }
        "__locallycloud_migration_history_get" => {
            let value: Get = parse(body)?;
            sqlite
                .native_history_get(account, &value.table_name, value.at, &value.key)
                .await
        }
        "__locallycloud_migration_history_describe" => {
            let value: Describe = parse(body)?;
            sqlite
                .native_history_describe(account, &value.table_name)
                .await
        }
        _ => return Err(invalid()),
    };
    result.map_err(|error| match error {
        StorageError::Validation(_) | StorageError::Unsupported(_) => invalid(),
        StorageError::TableNotFound(_) => DynamoDbError::ResourceNotFoundException(
            "Native history record or table does not exist".into(),
        ),
        StorageError::TableNotActive(_) | StorageError::IndexesInUse(_) => {
            DynamoDbError::ResourceInUseException("Native history target is not available".into())
        }
        _ => DynamoDbError::InternalServerError("Offline history storage operation failed".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn history_fields_are_strict_and_timestamps_roundtrip_exactly() {
        let at = f64::from_bits(1_793_000_000.0f64.to_bits() + 1);
        let bytes =
            serde_json::to_vec(&json!({"TableName":"orders","At":at,"Key":{"pk":{"S":"key"}}}))
                .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap();
        let parsed: Get = parse(body).unwrap();
        assert_eq!(parsed.at.to_bits(), at.to_bits());
        for invalid in [
            json!({"TableName":"../orders","At":at,"Key":{}}),
            json!({"TableName":"orders","At":at,"Key":{},"Extra":true}),
            json!({"TableName":"orders","At":"not-a-time","Key":{}}),
        ] {
            assert!(parse::<Get>(invalid).is_err());
        }
    }
}
