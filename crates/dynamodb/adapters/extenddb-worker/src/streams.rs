//! Resolve private engine tokens with the upstream parser before IAM authorization.
use std::time::{SystemTime, UNIX_EPOCH};

use extenddb_core::error::DynamoDbError;
use extenddb_engine::{
    classify_shard_iterator, decode_shard_iterator, ShardIteratorClass,
    SHARD_ITERATOR_EXPIRED_MESSAGE,
};
use serde_json::{json, Map, Value};

const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_WIRE_BYTES: usize = 32 * 1024 * 1024 - 4096;

/// Use upstream one-record reads until the AWS response budget is reached.
/// A rejected next record leaves the preceding iterator intact for the next call.
pub async fn get_records(
    body: Value,
    context: &extenddb_engine::OperationContext,
) -> Result<Value, DynamoDbError> {
    let limit = match body.get("Limit") {
        None => 1000,
        Some(value) => value.as_u64().filter(|limit| *limit > 0).ok_or_else(|| {
            DynamoDbError::ValidationException("Limit must be a positive integer".into())
        })?,
    };
    if limit > 1000 {
        return Err(DynamoDbError::LimitExceededException(
            "GetRecords cannot return more than 1000 records".into(),
        ));
    }
    let metadata = resolve(&body)?;
    let scope = format!(
        "arn:aws:dynamodb:{}:{}:table/",
        context.region, context.account_id
    );
    if !metadata
        .get("StreamArn")
        .and_then(Value::as_str)
        .is_some_and(|arn| arn.starts_with(&scope))
    {
        return Err(DynamoDbError::ValidationException(
            "Stream ARN must match the request account and region".into(),
        ));
    }
    let mut next = body
        .get("ShardIterator")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut records = Vec::new();
    let mut logical_bytes = 0;
    let mut wire_bytes = 0;
    for _ in 0..limit {
        let Some(iterator) = next.as_ref() else {
            break;
        };
        let mut page = extenddb_engine::handle_get_records(
            json!({"ShardIterator":iterator,"Limit":1}),
            context,
        )
        .await?;
        let following = match page.get("NextShardIterator") {
            None | Some(Value::Null) => None,
            Some(Value::String(token)) if !token.is_empty() && token.len() <= 2048 => {
                Some(token.clone())
            }
            _ => return Err(invalid_page()),
        };
        let page_records = page
            .get_mut("Records")
            .and_then(Value::as_array_mut)
            .ok_or_else(invalid_page)?;
        match page_records.len() {
            0 => {
                next = following;
                break;
            }
            1 => {
                let record = page_records.pop().ok_or_else(invalid_page)?;
                if !push_record(&mut records, record, &mut logical_bytes, &mut wire_bytes)? {
                    break;
                }
                next = following;
            }
            _ => return Err(invalid_page()),
        }
    }
    let mut output = Map::new();
    output.insert("Records".into(), Value::Array(records));
    output.insert(
        "NextShardIterator".into(),
        next.map(Value::String).unwrap_or(Value::Null),
    );
    Ok(Value::Object(output))
}

fn invalid_page() -> DynamoDbError {
    DynamoDbError::InternalServerError("Invalid upstream stream page".into())
}

fn push_record(
    records: &mut Vec<Value>,
    record: Value,
    logical_bytes: &mut u64,
    wire_bytes: &mut usize,
) -> Result<bool, DynamoDbError> {
    let wire = record.to_string().len();
    let logical = record
        .get("dynamodb")
        .and_then(|record| record.get("SizeBytes"))
        .and_then(Value::as_u64)
        .filter(|bytes| *bytes > 0)
        .unwrap_or(wire as u64);
    if logical_bytes.saturating_add(logical) > MAX_RECORD_BYTES
        || wire_bytes.saturating_add(wire) > MAX_WIRE_BYTES
    {
        if records.is_empty() {
            return Err(DynamoDbError::InternalServerError(
                "Stream record exceeds the GetRecords response limit".into(),
            ));
        }
        return Ok(false);
    }
    *logical_bytes += logical;
    *wire_bytes += wire;
    records.push(record);
    Ok(true)
}

pub fn resolve(body: &Value) -> Result<Value, DynamoDbError> {
    let token = body
        .get("ShardIterator")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty() && token.len() <= 2048)
        .ok_or_else(|| DynamoDbError::ValidationException("Invalid ShardIterator".into()))?;
    match classify_shard_iterator(token) {
        ShardIteratorClass::Stream(arn) => {
            let decoded = decode_shard_iterator(token).ok_or_else(|| {
                DynamoDbError::ValidationException("Invalid ShardIterator".into())
            })?;
            let created = decoded.created_at.ok_or_else(|| {
                DynamoDbError::ValidationException("Invalid ShardIterator".into())
            })?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| DynamoDbError::InternalServerError("System clock unavailable".into()))?
                .as_secs();
            if now.saturating_sub(created) > 900 {
                return Err(DynamoDbError::ExpiredIteratorException(
                    SHARD_ITERATOR_EXPIRED_MESSAGE.into(),
                ));
            }
            Ok(json!({"StreamArn":arn,"Sequence":decoded.sequence}))
        }
        ShardIteratorClass::Expired => Err(DynamoDbError::ExpiredIteratorException(
            SHARD_ITERATOR_EXPIRED_MESSAGE.into(),
        )),
        ShardIteratorClass::Invalid => Err(DynamoDbError::ValidationException(
            "Invalid ShardIterator".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use extenddb_engine::encode_shard_iterator;

    #[test]
    fn upstream_iterator_resource_and_expiration_are_preserved() {
        let arn =
            "arn:aws:dynamodb:us-east-1:000000000000:table/orders/stream/2026-11-06T01:02:03.000";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = encode_shard_iterator("shard-1", "AFTER_SEQUENCE_NUMBER", "42", now, arn);
        assert_eq!(
            resolve(&json!({"ShardIterator":token})).unwrap(),
            json!({"StreamArn":arn,"Sequence":"42"})
        );
        let expired =
            encode_shard_iterator("shard-1", "AFTER_SEQUENCE_NUMBER", "42", now - 901, arn);
        assert!(matches!(
            resolve(&json!({"ShardIterator":expired})),
            Err(DynamoDbError::ExpiredIteratorException(_))
        ));
        for token in ["invalid".into(), "x".repeat(2049)] {
            assert!(matches!(
                resolve(&json!({"ShardIterator":token})),
                Err(DynamoDbError::ValidationException(_))
            ));
        }
    }

    #[test]
    fn bounded_records_preserve_an_unconsumed_record_when_the_page_is_full() {
        let mut records = Vec::new();
        let (mut logical, mut wire) = (0, 0);
        let record = json!({"dynamodb":{"SizeBytes":400_000}});
        assert!(push_record(&mut records, record.clone(), &mut logical, &mut wire).unwrap());
        assert!(push_record(&mut records, record.clone(), &mut logical, &mut wire).unwrap());
        let before = (records.len(), logical, wire);
        assert!(!push_record(&mut records, record, &mut logical, &mut wire).unwrap());
        assert_eq!((records.len(), logical, wire), before);
        assert!(push_record(
            &mut Vec::new(),
            json!({"dynamodb":{"SizeBytes":MAX_RECORD_BYTES+1}}),
            &mut 0,
            &mut 0
        )
        .is_err());
    }

    #[test]
    fn missing_or_zero_size_uses_the_bounded_wire_size() {
        for size in [Value::Null, json!(0)] {
            let mut records = Vec::new();
            let (mut logical, mut wire) = (0, 0);
            let record = json!({"dynamodb":{"SizeBytes":size,"NewImage":{"value":{"S":"x".repeat(600*1024)}}}});
            assert!(push_record(&mut records, record.clone(), &mut logical, &mut wire).unwrap());
            assert!(!push_record(&mut records, record, &mut logical, &mut wire).unwrap());
            assert_eq!(records.len(), 1);
            assert_eq!(logical, wire as u64);
        }
    }
}
