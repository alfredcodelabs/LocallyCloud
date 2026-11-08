//! A table file has one physical key and cannot be reused for another table or generation.
use extenddb_core::error::DynamoDbError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TableFile {
    pub table_name: String,
    pub storage_id: String,
}

impl TableFile {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(3..=255).contains(&self.table_name.len())
            || !self
                .table_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            return Err("invalid physical table name");
        }
        let id =
            Uuid::parse_str(&self.storage_id).map_err(|_| "invalid physical table identity")?;
        if id.is_nil() || id.to_string() != self.storage_id {
            return Err("invalid physical table identity");
        }
        Ok(())
    }

    pub fn scope(&self, account: &str, region: &str) -> Result<String, serde_json::Error> {
        serde_json::to_string(&(
            "table-file-v1",
            account,
            region,
            &self.table_name,
            &self.storage_id,
        ))
    }

    pub fn authorize(
        &self,
        operation: &str,
        body: &Value,
        account: &str,
        region: &str,
    ) -> Result<(), DynamoDbError> {
        let invalid = || {
            DynamoDbError::ValidationException(
                "Request does not belong to this encrypted table file".into(),
            )
        };
        let arn = format!(
            "arn:aws:dynamodb:{region}:{account}:table/{}",
            self.table_name
        );
        let name = |value: &Value| -> Result<(), DynamoDbError> {
            match value.as_str() {
                Some(value) if value == self.table_name || value == arn => Ok(()),
                _ => Err(invalid()),
            }
        };
        let resource = |value: &Value| -> Result<(), DynamoDbError> {
            match value.as_str() {
                Some(value) if value == arn || value.starts_with(&format!("{arn}/")) => Ok(()),
                _ => Err(invalid()),
            }
        };
        if matches!(
            operation,
            "RestoreTableFromBackup" | "RestoreTableToPointInTime"
        ) || body.get("ReplicaUpdates").is_some()
            || body.get("SSESpecification").is_some()
        {
            return Err(DynamoDbError::ValidationException(
                "This operation requires the table storage coordinator".into(),
            ));
        }
        for field in [
            "TableName",
            "SourceTableName",
            "SourceTableArn",
            "TargetTableName",
        ] {
            if let Some(value) = body.get(field) {
                name(value)?;
            }
        }
        for field in ["ResourceArn", "StreamArn", "BackupArn"] {
            if let Some(value) = body.get(field) {
                resource(value)?;
            }
        }
        if let Some(items) = body.get("RequestItems").and_then(Value::as_object) {
            if items.len() > 100 {
                return Err(invalid());
            }
            for table in items.keys() {
                name(&Value::String(table.clone()))?;
            }
        }
        if let Some(items) = body.get("TransactItems").and_then(Value::as_array) {
            if items.len() > 100 {
                return Err(invalid());
            }
            for item in items {
                for action in ["Put", "Update", "Delete", "ConditionCheck", "Get"] {
                    if let Some(table) = item.get(action).and_then(|action| action.get("TableName"))
                    {
                        name(table)?;
                    }
                }
            }
        }
        if let Some(table) = body
            .get("Change")
            .and_then(|change| change.get("table_name"))
        {
            name(table)?;
        }
        if body.get("ShardIterator").is_some() {
            let resolved = crate::streams::resolve(body)?;
            resource(resolved.get("StreamArn").ok_or_else(invalid)?)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn one_file_cannot_accept_another_tables_data_or_a_cross_file_transaction() {
        let file = TableFile {
            table_name: "orders".into(),
            storage_id: "0a459173-a2cb-45f0-a1dd-5112fb17d4f7".into(),
        };
        file.validate().unwrap();
        let check = |op, body| file.authorize(op, &body, "000000000000", "us-east-1");
        assert!(check("PutItem", json!({"TableName":"orders"})).is_ok());
        assert!(check("PutItem", json!({"TableName":"payments"})).is_err());
        assert!(check(
            "BatchGetItem",
            json!({"RequestItems":{"orders":{},"payments":{}}})
        )
        .is_err());
        assert!(check("TransactWriteItems",json!({"TransactItems":[{"Put":{"TableName":"orders"}},{"Delete":{"TableName":"payments"}}]})).is_err());
        assert!(check(
            "DescribeStream",
            json!({"StreamArn":"arn:aws:dynamodb:us-east-2:000000000000:table/orders/stream/label"})
        )
        .is_err());
        assert!(check(
            "DescribeBackup",
            json!({"BackupArn":"arn:aws:dynamodb:us-east-1:000000000000:table/payments/backup/id"})
        )
        .is_err());
        assert!(check(
            "RestoreTableFromBackup",
            json!({"TargetTableName":"orders"})
        )
        .is_err());
    }
}
