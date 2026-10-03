//! DynamoDB Streams data API (`DynamoDBStreams_20120810.*`).
//!
//! Streams share the DynamoDB signing name (`dynamodb`), so requests route to the same
//! native service; these operations are dispatched alongside the control/data plane and read
//! the change records captured on each table (see `TableData::emit_stream`). A stream is
//! modeled as a single open shard whose records are addressed by a positional shard iterator.

use base64::Engine;
use serde_json::{json, Map, Value};

use crate::error::DdbError;
use crate::ops::Ctx;
use crate::store::{KeyType, StreamRecord, TableData};
use crate::value::item_to_json;

/// The single shard id exposed per stream.
const SHARD_ID: &str = "shardId-00000000000000000000-00000000";

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn req_str<'a>(req: &'a Value, field: &str) -> Result<&'a str, DdbError> {
    req.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| DdbError::Validation(format!("{field} is required")))
}

/// Resolve the table name encoded in a stream ARN
/// (`arn:aws:dynamodb:<region>:<account>:table/<name>/stream/<label>`).
fn table_name_from_stream_arn(arn: &str) -> Result<&str, DdbError> {
    let after = arn
        .split("table/")
        .nth(1)
        .ok_or_else(|| DdbError::Validation(format!("invalid stream ARN: {arn}")))?;
    after
        .split("/stream/")
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DdbError::Validation(format!("invalid stream ARN: {arn}")))
}

async fn resolve_stream_table(
    ctx: &Ctx<'_>,
    stream_arn: &str,
) -> Result<std::sync::Arc<tokio::sync::RwLock<TableData>>, DdbError> {
    let name = table_name_from_stream_arn(stream_arn)?;
    let table = ctx
        .store
        .get(ctx.account, ctx.region, name)
        .ok_or_else(|| DdbError::ResourceNotFound(format!("Stream not found: {stream_arn}")))?;
    // The ARN must match the table's current stream ARN.
    {
        let guard = table.read().await;
        if guard.stream_arn().as_deref() != Some(stream_arn) {
            return Err(DdbError::ResourceNotFound(format!(
                "Stream not found: {stream_arn}"
            )));
        }
    }
    Ok(table)
}

pub async fn list_streams(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let filter = req.get("TableName").and_then(Value::as_str);
    let mut streams = Vec::new();
    for name in ctx.store.list_names(ctx.account, ctx.region) {
        if let Some(f) = filter {
            if f != name {
                continue;
            }
        }
        if let Some(table) = ctx.store.get(ctx.account, ctx.region, &name) {
            let guard = table.read().await;
            if let Some(arn) = guard.stream_arn() {
                streams.push(json!({
                    "StreamArn": arn,
                    "TableName": name,
                    "StreamLabel": guard.def.creation_date,
                }));
            }
        }
    }
    Ok(json!({ "Streams": streams }))
}

pub async fn describe_stream(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let stream_arn = req_str(req, "StreamArn")?;
    let table = resolve_stream_table(ctx, stream_arn).await?;
    let guard = table.read().await;
    let view_type = guard.def.stream_spec.as_ref().unwrap().view_type.clone();
    let key_schema: Vec<Value> = guard
        .def
        .key_schema
        .iter()
        .map(|k| {
            json!({
                "AttributeName": k.name,
                "KeyType": match k.key_type { KeyType::Hash => "HASH", KeyType::Range => "RANGE" }
            })
        })
        .collect();
    let starting = guard
        .stream_records
        .first()
        .map(|r| r.sequence_number.clone())
        .unwrap_or_else(|| format!("{:025}", 0));
    Ok(json!({
        "StreamDescription": {
            "StreamArn": stream_arn,
            "StreamLabel": guard.def.creation_date,
            "StreamStatus": "ENABLED",
            "StreamViewType": view_type,
            "CreationRequestDateTime": guard.def.creation_date.parse::<f64>().unwrap_or(0.0),
            "TableName": guard.def.name,
            "KeySchema": key_schema,
            "Shards": [{
                "ShardId": SHARD_ID,
                "SequenceNumberRange": { "StartingSequenceNumber": starting }
            }]
        }
    }))
}

pub async fn get_shard_iterator(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let stream_arn = req_str(req, "StreamArn")?;
    let shard_id = req_str(req, "ShardId")?;
    if shard_id != SHARD_ID {
        return Err(DdbError::ResourceNotFound(format!(
            "Shard not found: {shard_id}"
        )));
    }
    let iterator_type = req_str(req, "ShardIteratorType")?;
    let table = resolve_stream_table(ctx, stream_arn).await?;
    let guard = table.read().await;

    let position = match iterator_type {
        "TRIM_HORIZON" => 0usize,
        "LATEST" => guard.stream_records.len(),
        "AT_SEQUENCE_NUMBER" | "AFTER_SEQUENCE_NUMBER" => {
            let seq = req_str(req, "SequenceNumber")?;
            let idx = guard
                .stream_records
                .iter()
                .position(|r| r.sequence_number == seq)
                .ok_or_else(|| DdbError::Validation(format!("sequence number not found: {seq}")))?;
            if iterator_type == "AFTER_SEQUENCE_NUMBER" {
                idx + 1
            } else {
                idx
            }
        }
        other => {
            return Err(DdbError::Validation(format!(
                "invalid ShardIteratorType: {other}"
            )))
        }
    };
    Ok(json!({ "ShardIterator": encode_iterator(stream_arn, position) }))
}

pub async fn get_records(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let iterator = req_str(req, "ShardIterator")?;
    let (stream_arn, position) = decode_iterator(iterator)?;
    let limit = req
        .get("Limit")
        .and_then(Value::as_u64)
        .unwrap_or(1000)
        .max(1) as usize;
    let table = resolve_stream_table(ctx, &stream_arn).await?;
    let guard = table.read().await;

    let end = (position + limit).min(guard.stream_records.len());
    let slice = if position <= guard.stream_records.len() {
        &guard.stream_records[position..end]
    } else {
        &[]
    };
    let records: Vec<Value> = slice.iter().map(|r| record_json(ctx.region, r)).collect();
    let next_position = position + records.len();
    Ok(json!({
        "Records": records,
        // The shard stays open, so a next iterator is always returned.
        "NextShardIterator": encode_iterator(&stream_arn, next_position),
    }))
}

pub(crate) fn record_json(region: &str, r: &StreamRecord) -> Value {
    let mut dynamodb = Map::new();
    dynamodb.insert("ApproximateCreationDateTime".into(), json!(r.creation_unix));
    dynamodb.insert("Keys".into(), item_to_json(&r.keys));
    if let Some(old) = &r.old_image {
        dynamodb.insert("OldImage".into(), item_to_json(old));
    }
    if let Some(new) = &r.new_image {
        dynamodb.insert("NewImage".into(), item_to_json(new));
    }
    dynamodb.insert("SequenceNumber".into(), json!(r.sequence_number));
    dynamodb.insert("SizeBytes".into(), json!(r.size_bytes));
    dynamodb.insert("StreamViewType".into(), json!(r.view_type));
    json!({
        "awsRegion": region,
        "eventID": r.event_id,
        "eventName": r.event_name,
        "eventSource": "aws:dynamodb",
        "eventVersion": "1.1",
        "dynamodb": Value::Object(dynamodb),
    })
}

fn encode_iterator(stream_arn: &str, position: usize) -> String {
    b64().encode(format!("{stream_arn}|{position}"))
}

fn decode_iterator(iterator: &str) -> Result<(String, usize), DdbError> {
    let decoded = b64()
        .decode(iterator)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or_else(|| DdbError::Validation("invalid shard iterator".into()))?;
    let (arn, pos) = decoded
        .rsplit_once('|')
        .ok_or_else(|| DdbError::Validation("invalid shard iterator".into()))?;
    let position = pos
        .parse::<usize>()
        .map_err(|_| DdbError::Validation("invalid shard iterator".into()))?;
    Ok((arn.to_string(), position))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterator_round_trip() {
        let arn = "arn:aws:dynamodb:us-east-1:0:table/t/stream/123";
        let it = encode_iterator(arn, 7);
        let (got_arn, pos) = decode_iterator(&it).unwrap();
        assert_eq!(got_arn, arn);
        assert_eq!(pos, 7);
    }

    #[test]
    fn table_name_parsed_from_stream_arn() {
        let arn = "arn:aws:dynamodb:us-east-1:000000000000:table/orders/stream/2024";
        assert_eq!(table_name_from_stream_arn(arn).unwrap(), "orders");
    }
}
