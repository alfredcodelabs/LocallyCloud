//! `dynamodb:LeadingKeys`: the partition key values a request names. The Service
//! Authorization Reference lists the key for item reads and writes, Query, the batch and
//! transaction actions and PartiQL. Scan names no partition key, so AWS supplies none.

use async_trait::async_trait;
use base64::Engine;
use locallycloud_core::handler::ServiceRequest;
use serde_json::Value;

use crate::error::DdbError;
use crate::store::{KeyType, TableStore};
use crate::value::AttributeValue;

pub(crate) const CONTEXT_KEY: &str = "dynamodb:leadingkeys";
const SCHEMA_MISMATCH: &str = "The provided key element does not match the schema";

/// Partition key attribute of a table, or of the index a Query reads.
#[async_trait]
pub(crate) trait PartitionKeys: Send + Sync {
    async fn partition_key(
        &self,
        request: &ServiceRequest,
        table: &str,
        index: Option<&str>,
    ) -> Result<String, DdbError>;
}

#[async_trait]
impl PartitionKeys for TableStore {
    async fn partition_key(
        &self,
        request: &ServiceRequest,
        table: &str,
        index: Option<&str>,
    ) -> Result<String, DdbError> {
        let stored = self
            .get(&request.account_id, &request.region, table)
            .ok_or_else(|| {
                DdbError::ResourceNotFound(format!(
                    "Requested resource not found: Table: {table} not found"
                ))
            })?;
        let guard = stored.read().await;
        let Some(name) = index else {
            return Ok(guard.def.hash_key().to_string());
        };
        guard
            .def
            .index(name)
            .and_then(|index| {
                index
                    .key_schema
                    .iter()
                    .find(|k| k.key_type == KeyType::Hash)
            })
            .map(|key| key.name.clone())
            .ok_or_else(|| DdbError::Validation(format!("index {name} does not exist")))
    }
}

/// Where an operation names its partition key values.
enum Source {
    /// The request itself carries `Key` or `Item`.
    Single,
    Query,
    BatchGet,
    BatchWrite,
    Transact,
    PartiQl,
}

fn source(op: &str) -> Option<Source> {
    match op {
        "GetItem" | "PutItem" | "UpdateItem" | "DeleteItem" => Some(Source::Single),
        "Query" => Some(Source::Query),
        "BatchGetItem" => Some(Source::BatchGet),
        "BatchWriteItem" => Some(Source::BatchWrite),
        "TransactGetItems" | "TransactWriteItems" => Some(Source::Transact),
        "ExecuteStatement" | "ExecuteTransaction" | "BatchExecuteStatement" => {
            Some(Source::PartiQl)
        }
        _ => None,
    }
}

/// Leading keys for one `(action, table)` authorization target; empty when AWS supplies
/// none. An error means AWS would supply the key but this request does not determine it.
pub(crate) async fn values(
    keys: &dyn PartitionKeys,
    request: &ServiceRequest,
    op: &str,
    body: &Value,
    action: &str,
    table: &str,
) -> Result<Vec<String>, DdbError> {
    let Some(source) = source(op) else {
        return Ok(Vec::new());
    };
    let index = match source {
        Source::Query => body.get("IndexName").and_then(Value::as_str),
        _ => None,
    };
    let partition = keys.partition_key(request, table, index).await?;
    let values = match source {
        Source::Query => vec![crate::ops::query_partition_value(body, &partition)?],
        Source::PartiQl => crate::partiql::leading_key_values(op, body, action, table, &partition)?,
        Source::Single => vec![key_value(body, &partition)?],
        Source::BatchGet => field(body, "RequestItems")?
            .get(table)
            .and_then(|entry| entry.get("Keys"))
            .and_then(Value::as_array)
            .ok_or_else(|| DdbError::Validation("Keys is required".into()))?
            .iter()
            .map(|key| attribute(key, &partition))
            .collect::<Result<_, _>>()?,
        Source::BatchWrite => field(body, "RequestItems")?
            .get(table)
            .and_then(Value::as_array)
            .ok_or_else(|| DdbError::Validation("RequestItems is required".into()))?
            .iter()
            .map(|write| {
                let request = write
                    .get("PutRequest")
                    .or_else(|| write.get("DeleteRequest"))
                    .ok_or_else(|| DdbError::Validation("invalid write request".into()))?;
                key_value(request, &partition)
            })
            .collect::<Result<_, _>>()?,
        Source::Transact => {
            let mut values = Vec::new();
            for item in field(body, "TransactItems")?
                .as_array()
                .ok_or_else(|| DdbError::Validation("TransactItems is required".into()))?
            {
                let (inner, item_action) = crate::service::transact_entry(op, item)?;
                if item_action == action
                    && inner.get("TableName").and_then(Value::as_str) == Some(table)
                {
                    values.push(key_value(inner, &partition)?);
                }
            }
            values
        }
    };
    values.iter().map(key_text).collect()
}

fn field<'a>(body: &'a Value, name: &str) -> Result<&'a Value, DdbError> {
    body.get(name)
        .ok_or_else(|| DdbError::Validation(format!("{name} is required")))
}

/// The partition value of a request's `Key` (reads, updates, deletes) or `Item` (puts).
fn key_value(request: &Value, partition: &str) -> Result<AttributeValue, DdbError> {
    let key = request
        .get("Key")
        .or_else(|| request.get("Item"))
        .ok_or_else(|| DdbError::Validation("Key is required".into()))?;
    attribute(key, partition)
}

fn attribute(key: &Value, partition: &str) -> Result<AttributeValue, DdbError> {
    AttributeValue::from_json(
        key.get(partition)
            .ok_or_else(|| DdbError::Validation(SCHEMA_MISMATCH.into()))?,
    )
}

fn key_text(value: &AttributeValue) -> Result<String, DdbError> {
    match value {
        AttributeValue::S(text) | AttributeValue::N(text) => Ok(text.clone()),
        AttributeValue::B(bytes) => Ok(base64::engine::general_purpose::STANDARD.encode(bytes)),
        _ => Err(DdbError::Validation(SCHEMA_MISMATCH.into())),
    }
}
