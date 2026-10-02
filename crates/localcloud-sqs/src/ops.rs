//! SQS operations. Each takes the parsed JSON request body and returns the JSON response
//! body (or an `SqsError`). Visibility, FIFO ordering/dedup, long polling, and dead-letter
//! redrive are all enforced here.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, RandomizedNonceKey, UnboundKey, AES_256_GCM};
use base64::Engine;
use localcloud_core::integration::authorization::AuthorizationRequest;
use localcloud_core::integration::kms::{
    KmsCallContext, KmsDecryptRequest, KmsGenerateDataKeyRequest, KmsInternalError,
    KmsValidateKeyRequest, SensitiveBytes,
};
use localcloud_core::integration::{InternalDispatcher, RequestIdentity};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::error::SqsError;
use crate::md5::{attributes_md5, body_md5};
use crate::metrics::{message_counts, MetricsRecorder};
use crate::model::{AttributeValue, EncryptedBody, Message, MessageAttribute, QueueArn};
use crate::store::{
    GuardedQueue, InsertResult, QueueState, ReceiveAttempt, SqsStore, DEFAULT_DELAY_SECONDS,
    DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_RETENTION_PERIOD, DEFAULT_VISIBILITY_TIMEOUT,
    DEFAULT_WAIT_TIME_SECONDS, MAX_RECEIVE_WAIT_SECONDS,
};

/// FIFO deduplication window.
const DEDUP_WINDOW: Duration = Duration::from_secs(300);
/// Maximum batch entries per request.
const MAX_BATCH: usize = 10;
const MAX_BATCH_PAYLOAD: usize = 262_144;
const MAX_TAGS: usize = 50;
const RECEIVE_ATTEMPT_WINDOW: Duration = Duration::from_secs(300);

pub struct Ctx<'a> {
    pub store: Arc<SqsStore>,
    pub region: &'a str,
    pub account: &'a str,
    pub request_id: &'a str,
    pub dispatcher: Option<Arc<InternalDispatcher>>,
    pub authorization: Option<String>,
    pub metrics: Arc<MetricsRecorder>,
}

// ============================ request helpers ==================================

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn req_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, SqsError> {
    str_field(v, key).ok_or_else(|| SqsError::MissingParameter(format!("{key} is required")))
}

fn optional_i64(v: &Value, key: &str) -> Result<Option<i64>, SqsError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_i64()
            .map(Some)
            .ok_or_else(|| SqsError::InvalidParameterValue(format!("{key} must be an integer"))),
        Some(Value::String(s)) => s
            .parse::<i64>()
            .map(Some)
            .map_err(|_| SqsError::InvalidParameterValue(format!("{key} must be an integer"))),
        Some(_) => Err(SqsError::InvalidParameterValue(format!(
            "{key} must be an integer"
        ))),
    }
}

fn bounded_i64(v: &Value, key: &str, default: i64, min: i64, max: i64) -> Result<i64, SqsError> {
    let value = optional_i64(v, key)?.unwrap_or(default);
    if !(min..=max).contains(&value) {
        return Err(SqsError::InvalidParameterValue(format!(
            "{key} must be between {min} and {max}"
        )));
    }
    Ok(value)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Resolve the queue named by the request's `QueueUrl`; `QueueDoesNotExist` when absent.
fn resolve_queue(ctx: &Ctx<'_>, v: &Value) -> Result<Arc<GuardedQueue>, SqsError> {
    let url = req_str(v, "QueueUrl")?;
    let arn = QueueArn::from_url(url)?;
    ctx.store.get(&arn).ok_or(SqsError::QueueDoesNotExist)
}

/// Parse `Attributes` (a `{name: value}` object) into a string map without dropping
/// malformed entries.
fn parse_attributes(v: &Value) -> Result<BTreeMap<String, String>, SqsError> {
    let Some(value) = v.get("Attributes") else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| SqsError::InvalidAttributeValue("Attributes must be an object".into()))?;
    object
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|value| (name.clone(), value.to_string()))
                .ok_or_else(|| {
                    SqsError::InvalidAttributeValue(format!(
                        "attribute {name} must have a string value"
                    ))
                })
        })
        .collect()
}

fn parse_tags(v: &Value) -> Result<BTreeMap<String, String>, SqsError> {
    let Some(value) = v.get("tags").or_else(|| v.get("Tags")) else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| SqsError::InvalidParameterValue("Tags must be an object".into()))?;
    if object.len() > MAX_TAGS {
        return Err(SqsError::InvalidParameterValue(format!(
            "a queue can have at most {MAX_TAGS} tags"
        )));
    }
    object
        .iter()
        .map(|(key, value)| {
            if key.is_empty()
                || key.len() > 128
                || key.to_ascii_lowercase().starts_with("aws:")
                || !key
                    .chars()
                    .all(|c| c.is_alphanumeric() || " _.:/=+-@".contains(c))
            {
                return Err(SqsError::InvalidParameterValue(format!(
                    "invalid tag key {key}"
                )));
            }
            let value = value.as_str().ok_or_else(|| {
                SqsError::InvalidParameterValue(format!("tag {key} must be a string"))
            })?;
            if value.len() > 256 {
                return Err(SqsError::InvalidParameterValue(format!(
                    "tag {key} value exceeds 256 characters"
                )));
            }
            Ok((key.clone(), value.to_string()))
        })
        .collect()
}

fn valid_queue_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name
            .strip_suffix(".fifo")
            .unwrap_or(name)
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn valid_batch_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Parse `MessageAttributes` into typed attributes.
fn parse_message_attributes(v: &Value) -> Result<BTreeMap<String, MessageAttribute>, SqsError> {
    let mut out = BTreeMap::new();
    let Some(obj) = v.get("MessageAttributes").and_then(Value::as_object) else {
        return Ok(out);
    };
    for (name, spec) in obj {
        let data_type = spec
            .get("DataType")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SqsError::InvalidParameterValue(format!("attribute {name} missing DataType"))
            })?
            .to_string();
        let value = if let Some(s) = spec.get("StringValue").and_then(Value::as_str) {
            AttributeValue::String(s.to_string())
        } else if let Some(b) = spec.get("BinaryValue").and_then(Value::as_str) {
            let bytes = b64().decode(b).map_err(|_| {
                SqsError::InvalidParameterValue(format!(
                    "attribute {name} BinaryValue is not base64"
                ))
            })?;
            AttributeValue::Binary(bytes)
        } else {
            return Err(SqsError::InvalidParameterValue(format!(
                "attribute {name} has no StringValue or BinaryValue"
            )));
        };
        out.insert(name.clone(), MessageAttribute { data_type, value });
    }
    Ok(out)
}

/// Serialize message attributes to the JSON response shape.
fn message_attributes_json(attrs: &BTreeMap<String, MessageAttribute>) -> Value {
    let mut map = Map::new();
    for (name, attr) in attrs {
        let mut spec = Map::new();
        spec.insert("DataType".into(), json!(attr.data_type));
        match &attr.value {
            AttributeValue::String(s) => {
                spec.insert("StringValue".into(), json!(s));
            }
            AttributeValue::Binary(b) => {
                spec.insert("BinaryValue".into(), json!(b64().encode(b)));
            }
        }
        map.insert(name.clone(), Value::Object(spec));
    }
    Value::Object(map)
}

fn default_attributes(fifo: bool) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::from([
        (
            "VisibilityTimeout".to_string(),
            DEFAULT_VISIBILITY_TIMEOUT.to_string(),
        ),
        (
            "MessageRetentionPeriod".to_string(),
            DEFAULT_RETENTION_PERIOD.to_string(),
        ),
        (
            "MaximumMessageSize".to_string(),
            DEFAULT_MAX_MESSAGE_SIZE.to_string(),
        ),
        (
            "DelaySeconds".to_string(),
            DEFAULT_DELAY_SECONDS.to_string(),
        ),
        (
            "ReceiveMessageWaitTimeSeconds".to_string(),
            DEFAULT_WAIT_TIME_SECONDS.to_string(),
        ),
    ]);
    if fifo {
        attributes.insert("FifoQueue".into(), "true".into());
        attributes.insert("ContentBasedDeduplication".into(), "false".into());
    }
    attributes
}

fn parse_bool_attribute(name: &str, value: &str) -> Result<(), SqsError> {
    if matches!(value, "true" | "false") {
        Ok(())
    } else {
        Err(SqsError::InvalidAttributeValue(format!(
            "{name} must be true or false"
        )))
    }
}

fn parse_bounded_attribute(name: &str, value: &str, min: i64, max: i64) -> Result<(), SqsError> {
    let parsed = value
        .parse::<i64>()
        .map_err(|_| SqsError::InvalidAttributeValue(format!("{name} must be an integer")))?;
    if !(min..=max).contains(&parsed) {
        return Err(SqsError::InvalidAttributeValue(format!(
            "{name} must be between {min} and {max}"
        )));
    }
    Ok(())
}

fn nonempty_string_or_array(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(values)) => {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
        }
        _ => false,
    }
}

fn validate_policy_document(raw: &str) -> Result<(), SqsError> {
    let document: Value = serde_json::from_str(raw)
        .map_err(|_| SqsError::InvalidAttributeValue("Policy must be valid JSON".into()))?;
    let object = document
        .as_object()
        .ok_or_else(|| SqsError::InvalidAttributeValue("Policy must be a JSON object".into()))?;
    if object
        .get("Version")
        .is_some_and(|value| !value.is_string())
    {
        return Err(SqsError::InvalidAttributeValue(
            "Policy.Version must be a string".into(),
        ));
    }
    let statements: Vec<&Value> = match object.get("Statement") {
        Some(Value::Object(_)) => vec![&object["Statement"]],
        Some(Value::Array(values)) if !values.is_empty() => values.iter().collect(),
        _ => {
            return Err(SqsError::InvalidAttributeValue(
                "Policy.Statement must be a non-empty object or array".into(),
            ))
        }
    };
    for statement in statements {
        let statement = statement.as_object().ok_or_else(|| {
            SqsError::InvalidAttributeValue("Policy statements must be objects".into())
        })?;
        if !matches!(
            statement.get("Effect").and_then(Value::as_str),
            Some("Allow" | "Deny")
        ) {
            return Err(SqsError::InvalidAttributeValue(
                "Policy statement Effect must be Allow or Deny".into(),
            ));
        }
        if nonempty_string_or_array(statement.get("Action"))
            == nonempty_string_or_array(statement.get("NotAction"))
        {
            return Err(SqsError::InvalidAttributeValue(
                "Policy statement must contain exactly one of Action or NotAction".into(),
            ));
        }
        if nonempty_string_or_array(statement.get("Resource"))
            == nonempty_string_or_array(statement.get("NotResource"))
        {
            return Err(SqsError::InvalidAttributeValue(
                "Policy statement must contain exactly one of Resource or NotResource".into(),
            ));
        }
        if statement
            .get("Condition")
            .is_some_and(|value| !value.is_object())
        {
            return Err(SqsError::InvalidAttributeValue(
                "Policy statement Condition must be an object".into(),
            ));
        }
    }
    Ok(())
}

fn parse_redrive_policy_raw(raw: &str) -> Result<(QueueArn, u32), SqsError> {
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|_| SqsError::InvalidAttributeValue("RedrivePolicy must be valid JSON".into()))?;
    let object = parsed.as_object().ok_or_else(|| {
        SqsError::InvalidAttributeValue("RedrivePolicy must be a JSON object".into())
    })?;
    let arn = object
        .get("deadLetterTargetArn")
        .and_then(Value::as_str)
        .and_then(arn_from_str)
        .ok_or_else(|| {
            SqsError::InvalidAttributeValue(
                "RedrivePolicy.deadLetterTargetArn must be an SQS ARN".into(),
            )
        })?;
    let max = object
        .get("maxReceiveCount")
        .and_then(|value| match value {
            Value::String(value) => value.parse::<u32>().ok(),
            Value::Number(value) => value.as_u64().and_then(|v| u32::try_from(v).ok()),
            _ => None,
        })
        .filter(|value| *value >= 1 && *value <= 1_000)
        .ok_or_else(|| {
            SqsError::InvalidAttributeValue(
                "RedrivePolicy.maxReceiveCount must be between 1 and 1000".into(),
            )
        })?;
    Ok((arn, max))
}

fn parse_redrive_allow_policy(raw: &str) -> Result<(String, Vec<QueueArn>), SqsError> {
    let parsed: Value = serde_json::from_str(raw).map_err(|_| {
        SqsError::InvalidAttributeValue("RedriveAllowPolicy must be valid JSON".into())
    })?;
    let object = parsed.as_object().ok_or_else(|| {
        SqsError::InvalidAttributeValue("RedriveAllowPolicy must be a JSON object".into())
    })?;
    let permission = object
        .get("redrivePermission")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "allowAll" | "denyAll" | "byQueue"))
        .ok_or_else(|| {
            SqsError::InvalidAttributeValue(
                "RedriveAllowPolicy.redrivePermission is invalid".into(),
            )
        })?
        .to_string();
    let sources = match object.get("sourceQueueArns") {
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value.as_str().and_then(arn_from_str).ok_or_else(|| {
                    SqsError::InvalidAttributeValue(
                        "RedriveAllowPolicy contains an invalid source queue ARN".into(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(SqsError::InvalidAttributeValue(
                "RedriveAllowPolicy.sourceQueueArns must be an array".into(),
            ))
        }
        None => Vec::new(),
    };
    if permission == "byQueue" && (sources.is_empty() || sources.len() > 10) {
        return Err(SqsError::InvalidAttributeValue(
            "byQueue requires between 1 and 10 sourceQueueArns".into(),
        ));
    }
    if permission != "byQueue" && !sources.is_empty() {
        return Err(SqsError::InvalidAttributeValue(
            "sourceQueueArns is only valid with byQueue".into(),
        ));
    }
    Ok((permission, sources))
}

fn redrive_allowed(source: &QueueArn, dlq_state: &QueueState) -> Result<bool, SqsError> {
    let Some(raw) = dlq_state.attributes.get("RedriveAllowPolicy") else {
        return Ok(true);
    };
    let (permission, sources) = parse_redrive_allow_policy(raw)?;
    Ok(match permission.as_str() {
        "allowAll" => true,
        "denyAll" => false,
        "byQueue" => sources.iter().any(|arn| arn == source),
        _ => false,
    })
}

fn validate_attributes(
    ctx: &Ctx<'_>,
    queue_arn: &QueueArn,
    fifo: bool,
    attributes: &BTreeMap<String, String>,
    creating: bool,
) -> Result<(), SqsError> {
    for (name, value) in attributes {
        if value.is_empty() && !creating {
            continue;
        }
        match name.as_str() {
            "VisibilityTimeout" => parse_bounded_attribute(name, value, 0, 43_200)?,
            "MessageRetentionPeriod" => parse_bounded_attribute(name, value, 60, 1_209_600)?,
            "MaximumMessageSize" => parse_bounded_attribute(name, value, 1_024, 262_144)?,
            "DelaySeconds" => parse_bounded_attribute(name, value, 0, 900)?,
            "ReceiveMessageWaitTimeSeconds" => {
                parse_bounded_attribute(name, value, 0, MAX_RECEIVE_WAIT_SECONDS)?
            }
            "KmsDataKeyReusePeriodSeconds" => parse_bounded_attribute(name, value, 60, 86_400)?,
            "FifoQueue" if creating => {
                parse_bool_attribute(name, value)?;
                if (value == "true") != fifo {
                    return Err(SqsError::InvalidAttributeValue(
                        "FifoQueue must match the .fifo queue-name suffix".into(),
                    ));
                }
            }
            "FifoQueue" => {
                return Err(SqsError::InvalidAttributeName(
                    "FifoQueue cannot be changed after creation".into(),
                ))
            }
            "ContentBasedDeduplication" | "SqsManagedSseEnabled" => {
                parse_bool_attribute(name, value)?;
                if name == "ContentBasedDeduplication" && !fifo {
                    return Err(SqsError::InvalidAttributeValue(
                        "ContentBasedDeduplication is only valid for FIFO queues".into(),
                    ));
                }
            }
            "FifoThroughputLimit" => {
                if !fifo || !matches!(value.as_str(), "perQueue" | "perMessageGroupId") {
                    return Err(SqsError::InvalidAttributeValue(
                        "FifoThroughputLimit is invalid for this queue".into(),
                    ));
                }
            }
            "DeduplicationScope" => {
                if !fifo || !matches!(value.as_str(), "queue" | "messageGroup") {
                    return Err(SqsError::InvalidAttributeValue(
                        "DeduplicationScope is invalid for this queue".into(),
                    ));
                }
            }
            "Policy" => validate_policy_document(value)?,
            "RedrivePolicy" => {
                let (target, _) = parse_redrive_policy_raw(value)?;
                if target == *queue_arn
                    || target.account != queue_arn.account
                    || target.region != queue_arn.region
                {
                    return Err(SqsError::InvalidAttributeValue(
                        "dead-letter queue must be a different queue in the same region and account"
                            .into(),
                    ));
                }
                let dlq = ctx.store.get(&target).ok_or_else(|| {
                    SqsError::InvalidAttributeValue("dead-letter queue does not exist".into())
                })?;
                if dlq.fifo != fifo {
                    return Err(SqsError::InvalidAttributeValue(
                        "source queue and dead-letter queue must have the same type".into(),
                    ));
                }
            }
            "RedriveAllowPolicy" => {
                let (_, sources) = parse_redrive_allow_policy(value)?;
                if sources.iter().any(|source| {
                    source.account != queue_arn.account || source.region != queue_arn.region
                }) {
                    return Err(SqsError::InvalidAttributeValue(
                        "source queues must be in the same region and account".into(),
                    ));
                }
            }
            "KmsMasterKeyId" if !value.is_empty() => {}
            name if is_read_only(name) => {
                return Err(SqsError::InvalidAttributeName(format!(
                    "attribute {name} is read-only"
                )))
            }
            _ => {
                return Err(SqsError::InvalidAttributeName(format!(
                    "unknown queue attribute {name}"
                )))
            }
        }
    }
    Ok(())
}

async fn ensure_redrive_allowed(
    ctx: &Ctx<'_>,
    source: &QueueArn,
    attributes: &BTreeMap<String, String>,
) -> Result<(), SqsError> {
    let Some(raw) = attributes
        .get("RedrivePolicy")
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let (target, _) = parse_redrive_policy_raw(raw)?;
    let dlq = ctx.store.get(&target).ok_or_else(|| {
        SqsError::InvalidAttributeValue("dead-letter queue does not exist".into())
    })?;
    let state = dlq.state.lock().await;
    if !redrive_allowed(source, &state)? {
        return Err(SqsError::InvalidAttributeValue(
            "dead-letter queue redrive policy does not allow this source queue".into(),
        ));
    }
    Ok(())
}

// ============================ queue lifecycle ==================================

pub async fn create_queue(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let name = req_str(v, "QueueName")?;
    if !valid_queue_name(name) {
        return Err(SqsError::InvalidParameterValue(
            "QueueName must be 1-80 alphanumeric, hyphen, or underscore characters".into(),
        ));
    }
    let attributes = parse_attributes(v)?;
    let tags = parse_tags(v)?;

    let declared_fifo = match attributes.get("FifoQueue") {
        Some(value) => {
            parse_bool_attribute("FifoQueue", value)?;
            value == "true"
        }
        None => false,
    };
    let name_is_fifo = name.ends_with(".fifo");
    if declared_fifo != name_is_fifo && attributes.contains_key("FifoQueue") {
        return Err(SqsError::InvalidParameterValue(
            "FifoQueue must match the .fifo queue-name suffix".into(),
        ));
    }
    let fifo = name_is_fifo;
    let arn = QueueArn::new(ctx.region, ctx.account, name);

    let _lifecycle = ctx.store.lifecycle_write().await;
    if ctx.store.deleted_recently(&arn) {
        return Err(SqsError::QueueDeletedRecently);
    }
    validate_attributes(ctx, &arn, fifo, &attributes, true)?;
    ensure_redrive_allowed(ctx, &arn, &attributes).await?;

    let mut stored = default_attributes(fifo);
    stored.extend(attributes);
    match ctx
        .store
        .insert_if_absent(arn.clone(), fifo, stored.clone(), tags)
    {
        InsertResult::Inserted(queue) => {
            if let Some(db) = ctx.store.persistence() {
                let state = queue.state.lock().await;
                if let Err(error) = db.create_queue(&arn, &state) {
                    ctx.store.forget_uncommitted(&arn);
                    return Err(error);
                }
            }
            Ok(json!({ "QueueUrl": arn.to_url() }))
        }
        InsertResult::Existing(existing) => {
            let state = existing.state.lock().await;
            if state.attributes == stored {
                Ok(json!({ "QueueUrl": arn.to_url() }))
            } else {
                Err(SqsError::QueueNameExists)
            }
        }
    }
}

/// Read-only (computed) attributes that cannot be set by the client.
fn is_read_only(name: &str) -> bool {
    matches!(
        name,
        "ApproximateNumberOfMessages"
            | "ApproximateNumberOfMessagesNotVisible"
            | "ApproximateNumberOfMessagesDelayed"
            | "CreatedTimestamp"
            | "LastModifiedTimestamp"
            | "QueueArn"
    )
}

pub async fn delete_queue(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let _lifecycle = ctx.store.lifecycle_write().await;
    let q = resolve_queue(ctx, v)?;
    if let Some(db) = ctx.store.persistence() {
        db.delete_queue(&q.arn)?;
    }
    ctx.store.remove(&q.arn);
    q.notify.notify_waiters();
    Ok(json!({}))
}

fn page_token(operation: &str, ctx: &Ctx<'_>, filter: &str, last_name: &str) -> String {
    b64().encode(
        json!([operation, ctx.account, ctx.region, filter, last_name])
            .to_string()
            .as_bytes(),
    )
}

fn page_after(
    operation: &str,
    ctx: &Ctx<'_>,
    filter: &str,
    token: Option<&str>,
) -> Result<Option<String>, SqsError> {
    let Some(token) = token else {
        return Ok(None);
    };
    let decoded = b64()
        .decode(token)
        .map_err(|_| SqsError::InvalidParameterValue("NextToken is invalid".into()))?;
    let fields: Vec<String> = serde_json::from_slice(&decoded)
        .map_err(|_| SqsError::InvalidParameterValue("NextToken is invalid".into()))?;
    if fields.len() != 5
        || fields[0] != operation
        || fields[1] != ctx.account
        || fields[2] != ctx.region
        || fields[3] != filter
        || fields[4].is_empty()
    {
        return Err(SqsError::InvalidParameterValue(
            "NextToken does not match this request".into(),
        ));
    }
    Ok(Some(fields[4].clone()))
}

pub async fn list_queues(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let prefix = str_field(v, "QueueNamePrefix").unwrap_or("");
    let max = bounded_i64(v, "MaxResults", 1_000, 1, 1_000)? as usize;
    let after = page_after("ListQueues", ctx, prefix, str_field(v, "NextToken"))?;
    let queues: Vec<_> = ctx
        .store
        .list(
            ctx.account,
            ctx.region,
            (!prefix.is_empty()).then_some(prefix),
        )
        .into_iter()
        .filter(|queue| {
            after
                .as_ref()
                .map(|name| queue.arn.name > *name)
                .unwrap_or(true)
        })
        .collect();
    let page: Vec<_> = queues.iter().take(max).collect();
    let mut response = Map::new();
    if !page.is_empty() {
        response.insert(
            "QueueUrls".into(),
            Value::Array(page.iter().map(|queue| json!(queue.arn.to_url())).collect()),
        );
    }
    if queues.len() > page.len() {
        response.insert(
            "NextToken".into(),
            json!(page_token(
                "ListQueues",
                ctx,
                prefix,
                &page.last().expect("non-empty page").arn.name,
            )),
        );
    }
    Ok(Value::Object(response))
}

pub async fn get_queue_url(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let name = req_str(v, "QueueName")?;
    let account = str_field(v, "QueueOwnerAWSAccountId").unwrap_or(ctx.account);
    let arn = QueueArn::new(ctx.region, account, name);
    if !ctx.store.exists(&arn) {
        return Err(SqsError::QueueDoesNotExist);
    }
    Ok(json!({ "QueueUrl": arn.to_url() }))
}

fn expire_messages(
    ctx: &Ctx<'_>,
    q: &GuardedQueue,
    state: &mut QueueState,
) -> Result<(), SqsError> {
    let cutoff_ms = now_ms().saturating_sub(state.retention_period().saturating_mul(1_000));
    let expired: Vec<&str> = state
        .messages
        .iter()
        .filter(|message| message.sent_timestamp_ms <= cutoff_ms)
        .map(|message| message.id.as_str())
        .collect();
    let now = Instant::now();
    let attempts: Vec<&str> = state
        .receive_attempts
        .iter()
        .filter(|(_, attempt)| attempt.expires_at <= now)
        .map(|(id, _)| id.as_str())
        .collect();
    if let Some(db) = ctx.store.persistence() {
        if !expired.is_empty() {
            db.delete_messages(q, &expired)?;
        }
        if !attempts.is_empty() {
            db.delete_attempts(q, &attempts)?;
        }
    }
    state
        .messages
        .retain(|message| message.sent_timestamp_ms > cutoff_ms);
    state
        .receive_attempts
        .retain(|_, attempt| attempt.expires_at > now);
    Ok(())
}

/// Build the full attribute map (stored + computed) for a queue.
fn computed_attributes(q: &GuardedQueue, state: &QueueState) -> BTreeMap<String, String> {
    let (visible, not_visible, delayed) = message_counts(state, Instant::now());
    let mut attrs = state.attributes.clone();
    attrs.insert("QueueArn".into(), q.arn.to_arn());
    attrs.insert("ApproximateNumberOfMessages".into(), visible.to_string());
    attrs.insert(
        "ApproximateNumberOfMessagesNotVisible".into(),
        not_visible.to_string(),
    );
    attrs.insert(
        "ApproximateNumberOfMessagesDelayed".into(),
        delayed.to_string(),
    );
    attrs.insert(
        "CreatedTimestamp".into(),
        state.created.unix_timestamp().to_string(),
    );
    attrs.insert(
        "LastModifiedTimestamp".into(),
        state.last_modified.unix_timestamp().to_string(),
    );
    // Defaults surfaced when not explicitly set.
    attrs
        .entry("VisibilityTimeout".into())
        .or_insert_with(|| state.visibility_timeout().to_string());
    attrs
        .entry("DelaySeconds".into())
        .or_insert_with(|| state.delay_seconds().to_string());
    attrs
        .entry("MaximumMessageSize".into())
        .or_insert_with(|| state.max_message_size().to_string());
    attrs
        .entry("MessageRetentionPeriod".into())
        .or_insert_with(|| state.retention_period().to_string());
    attrs
        .entry("ReceiveMessageWaitTimeSeconds".into())
        .or_insert_with(|| state.wait_time_seconds().to_string());
    attrs
}

pub async fn get_queue_attributes(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let mut state = q.state.lock().await;
    expire_messages(ctx, &q, &mut state)?;
    let requested: Vec<String> = v
        .get("AttributeNames")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| vec!["All".to_string()]);
    let all = computed_attributes(&q, &state);
    let selected: Map<String, Value> = if requested.iter().any(|n| n == "All") {
        all.into_iter().map(|(k, v)| (k, json!(v))).collect()
    } else {
        all.into_iter()
            .filter(|(k, _)| requested.contains(k))
            .map(|(k, v)| (k, json!(v)))
            .collect()
    };
    Ok(json!({ "Attributes": selected }))
}

pub async fn set_queue_attributes(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let updates = parse_attributes(v)?;
    if updates.is_empty() {
        return Err(SqsError::MissingParameter("Attributes is required".into()));
    }
    let _lifecycle = ctx.store.lifecycle_read().await;
    let q = resolve_queue(ctx, v)?;
    validate_attributes(ctx, &q.arn, q.fifo, &updates, false)?;
    ensure_redrive_allowed(ctx, &q.arn, &updates).await?;

    let mut state = q.state.lock().await;
    let original = state.attributes.clone();
    let last_modified = state.last_modified;
    for (name, value) in updates {
        if value.is_empty() {
            state.attributes.remove(&name);
        } else {
            state.attributes.insert(name, value);
        }
    }
    state.touch();
    if let Some(db) = ctx.store.persistence() {
        if let Err(error) = db.save_queue(&q, &state) {
            state.attributes = original;
            state.last_modified = last_modified;
            return Err(error);
        }
    }
    Ok(json!({}))
}

// ============================ send =============================================

struct SendInput {
    body: String,
    attributes: BTreeMap<String, MessageAttribute>,
    system_attributes: BTreeMap<String, String>,
    delay_seconds: Option<i64>,
    group_id: Option<String>,
    dedup_id: Option<String>,
}

struct SendResult {
    id: String,
    sequence_number: Option<u128>,
    md5_body: String,
    md5_attributes: Option<String>,
    /// Body plus message attribute bytes, reported as `SentMessageSize`.
    size: usize,
    /// False when FIFO deduplication returned an earlier message instead of adding one.
    added: bool,
}

/// Parse a single send request (or a batch entry) into a `SendInput`.
fn parse_send_input(v: &Value) -> Result<SendInput, SqsError> {
    let body = req_str(v, "MessageBody")?.to_string();
    let attributes = parse_message_attributes(v)?;
    let mut system_attributes = BTreeMap::new();
    if let Some(value) = v.get("MessageSystemAttributes") {
        let object = value.as_object().ok_or_else(|| {
            SqsError::InvalidParameterValue("MessageSystemAttributes must be an object".into())
        })?;
        for (name, spec) in object {
            if name != "AWSTraceHeader" {
                return Err(SqsError::InvalidParameterValue(format!(
                    "unsupported message system attribute {name}"
                )));
            }
            let value = spec
                .get("StringValue")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SqsError::InvalidParameterValue("AWSTraceHeader requires a StringValue".into())
                })?;
            system_attributes.insert(name.clone(), value.to_string());
        }
    }
    let delay_seconds = optional_i64(v, "DelaySeconds")?;
    if delay_seconds.is_some_and(|delay| !(0..=900).contains(&delay)) {
        return Err(SqsError::InvalidParameterValue(
            "DelaySeconds must be between 0 and 900".into(),
        ));
    }
    Ok(SendInput {
        body,
        attributes,
        system_attributes,
        delay_seconds,
        group_id: str_field(v, "MessageGroupId").map(String::from),
        dedup_id: str_field(v, "MessageDeduplicationId").map(String::from),
    })
}

fn attribute_size(attrs: &BTreeMap<String, MessageAttribute>) -> usize {
    attrs
        .iter()
        .map(|(name, a)| {
            name.len()
                + a.data_type.len()
                + match &a.value {
                    AttributeValue::String(s) => s.len(),
                    AttributeValue::Binary(b) => b.len(),
                }
        })
        .sum()
}

/// Validate FIFO/standard parameters and enqueue a message. Returns the result, recomputing
/// MD5s from the current request even when a FIFO duplicate is suppressed.
fn enqueue(
    q: &GuardedQueue,
    db: Option<&crate::persistence::SqsPersistence>,
    state: &mut QueueState,
    input: SendInput,
    encrypted_body: Option<EncryptedBody>,
) -> Result<SendResult, SqsError> {
    // Size validation against the queue maximum.
    let total = input.body.len() + attribute_size(&input.attributes);
    if total as i64 > state.max_message_size() {
        return Err(SqsError::InvalidParameterValue(format!(
            "message length {total} exceeds the queue maximum {}",
            state.max_message_size()
        )));
    }
    if input.body.is_empty() {
        return Err(SqsError::MissingParameter("MessageBody is required".into()));
    }

    let md5_body = body_md5(&input.body);
    let md5_attributes = attributes_md5(&input.attributes);

    // FIFO vs standard parameter enforcement.
    let (group_id, effective_dedup) = if q.fifo {
        if input.delay_seconds.is_some() {
            return Err(SqsError::InvalidParameterValue(
                "DelaySeconds is not valid for FIFO message sends; configure it on the queue"
                    .into(),
            ));
        }
        let group = input.group_id.clone().ok_or_else(|| {
            SqsError::MissingParameter("MessageGroupId is required for FIFO queues".into())
        })?;
        if group.len() > 128 {
            return Err(SqsError::InvalidParameterValue(
                "MessageGroupId cannot exceed 128 characters".into(),
            ));
        }
        let dedup = match &input.dedup_id {
            Some(d) if d.len() <= 128 => d.clone(),
            Some(_) => {
                return Err(SqsError::InvalidParameterValue(
                    "MessageDeduplicationId cannot exceed 128 characters".into(),
                ))
            }
            None if state.content_based_dedup() => md5_body.clone(),
            None => return Err(SqsError::InvalidParameterValue(
                "MessageDeduplicationId is required unless ContentBasedDeduplication is enabled"
                    .into(),
            )),
        };
        (Some(group), Some(dedup))
    } else {
        if input.group_id.is_some() || input.dedup_id.is_some() {
            return Err(SqsError::InvalidParameterValue(
                "MessageGroupId/MessageDeduplicationId are only valid for FIFO queues".into(),
            ));
        }
        (None, None)
    };

    // FIFO deduplication window: a duplicate returns the original id and sequence number.
    let dedup_key = effective_dedup.as_ref().map(|dedup| {
        if state
            .attributes
            .get("DeduplicationScope")
            .map(String::as_str)
            == Some("messageGroup")
        {
            format!("{}\0{dedup}", group_id.as_deref().unwrap_or_default())
        } else {
            dedup.clone()
        }
    });
    if let Some(dedup) = &dedup_key {
        let now = Instant::now();
        state
            .dedup
            .retain(|_, (at, _, _)| now.duration_since(*at) < DEDUP_WINDOW);
        if let Some((_, original_id, original_sequence)) = state.dedup.get(dedup) {
            return Ok(SendResult {
                id: original_id.clone(),
                sequence_number: Some(*original_sequence),
                md5_body,
                md5_attributes,
                size: total,
                added: false,
            });
        }
    }

    let id = Uuid::new_v4().to_string();
    let sequence_number = if q.fifo {
        state.sequence += 1;
        Some(state.sequence)
    } else {
        None
    };
    let delay = if q.fifo {
        state.delay_seconds()
    } else {
        input.delay_seconds.unwrap_or_else(|| state.delay_seconds())
    };
    let message = Message {
        id: id.clone(),
        body: if encrypted_body.is_some() {
            String::new()
        } else {
            input.body
        },
        encrypted_body,
        md5_body: md5_body.clone(),
        attributes: input.attributes,
        md5_attributes: md5_attributes.clone(),
        system_attributes: input.system_attributes,
        group_id,
        dedup_id: effective_dedup.clone(),
        sequence_number,
        sent_timestamp_ms: now_ms(),
        receive_count: 0,
        first_receive_ms: None,
        visible_at: Instant::now() + Duration::from_secs(delay as u64),
        receipt_handle: None,
    };
    if let Some(db) = db {
        let dedup = dedup_key.as_ref().map(|key| {
            (
                key.as_str(),
                id.as_str(),
                sequence_number.expect("FIFO sequence"),
            )
        });
        if let Err(error) = db.save_message(q, state, &message, dedup) {
            if sequence_number.is_some() {
                state.sequence -= 1;
            }
            return Err(error);
        }
    }
    if let Some(dedup) = dedup_key {
        state.dedup.insert(
            dedup,
            (
                Instant::now(),
                id.clone(),
                sequence_number.expect("FIFO messages have sequence numbers"),
            ),
        );
    }
    state.messages.push(message);
    Ok(SendResult {
        id,
        sequence_number,
        md5_body,
        md5_attributes,
        size: total,
        added: true,
    })
}

fn send_result_json(r: &SendResult) -> Value {
    let mut obj = Map::new();
    obj.insert("MessageId".into(), json!(r.id));
    obj.insert("MD5OfMessageBody".into(), json!(r.md5_body));
    if let Some(md5) = &r.md5_attributes {
        obj.insert("MD5OfMessageAttributes".into(), json!(md5));
    }
    if let Some(seq) = r.sequence_number {
        obj.insert("SequenceNumber".into(), json!(seq.to_string()));
    }
    Value::Object(obj)
}

fn queue_key_id(state: &QueueState) -> Option<String> {
    state
        .attributes
        .get("KmsMasterKeyId")
        .cloned()
        .filter(|key| !key.is_empty())
}

const KMS_WAIT_LIMIT: Duration = Duration::from_secs(2);

fn request_identity(ctx: &Ctx<'_>) -> RequestIdentity {
    RequestIdentity {
        account_id: ctx.account.into(),
        access_key_id: ctx
            .authorization
            .as_deref()
            .and_then(RequestIdentity::access_key_from_authorization),
        arn: None,
    }
}

fn kms_call(ctx: &Ctx<'_>) -> KmsCallContext {
    let caller_arn = ctx
        .dispatcher
        .as_ref()
        .and_then(|dispatcher| dispatcher.resolve_caller_arn(&request_identity(ctx)).ok())
        .flatten();
    KmsCallContext {
        source_service: "sqs".into(),
        account_id: ctx.account.into(),
        region: ctx.region.into(),
        request_id: ctx.request_id.into(),
        caller_arn,
        iam_policy_allowed: false,
    }
}

fn kms_context(arn: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("aws:sqs:queuearn".into(), arn.into())])
}

fn authorize_kms(ctx: &Ctx<'_>, action: &str, resource: &str) -> Result<bool, SqsError> {
    let dispatcher = ctx.dispatcher.as_ref().ok_or(SqsError::KmsAccessDenied)?;
    let request = AuthorizationRequest {
        request_identity: request_identity(ctx),
        delegated_identity: None,
        source_service: "sqs".into(),
        action: action.into(),
        resource: resource.into(),
        context: BTreeMap::new(),
    };
    dispatcher
        .authorize(request.clone())
        .map_err(|_| SqsError::KmsAccessDenied)?;
    Ok(dispatcher.identity_policy_allows(request))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MoveKmsFailure {
    Retryable,
    Terminal,
}

fn move_kms_failure(error: KmsInternalError) -> MoveKmsFailure {
    match error {
        KmsInternalError::Unavailable | KmsInternalError::Internal => MoveKmsFailure::Retryable,
        KmsInternalError::InvalidRequest
        | KmsInternalError::NotFound
        | KmsInternalError::InvalidState
        | KmsInternalError::InvalidCiphertext
        | KmsInternalError::AccessDenied => MoveKmsFailure::Terminal,
    }
}

fn public_kms_failure(_: MoveKmsFailure) -> SqsError {
    SqsError::KmsAccessDenied
}

fn authorize_move_destination_key(ctx: &Ctx<'_>, key_id: &str) -> Result<(), MoveKmsFailure> {
    let dispatcher = ctx.dispatcher.as_ref().ok_or(MoveKmsFailure::Terminal)?;
    let resolved = dispatcher
        .kms_validate_key(KmsValidateKeyRequest {
            call: kms_call(ctx),
            key_id: key_id.into(),
        })
        .map_err(move_kms_failure)?;
    authorize_kms(ctx, "kms:GenerateDataKey", &resolved.key_arn)
        .map_err(|_| MoveKmsFailure::Terminal)?;
    authorize_kms(ctx, "kms:Decrypt", &resolved.key_arn)
        .map(|_| ())
        .map_err(|_| MoveKmsFailure::Terminal)
}

async fn encrypt_body(
    ctx: &Ctx<'_>,
    arn: &str,
    key_id: &str,
    body: &str,
) -> Result<EncryptedBody, SqsError> {
    encrypt_body_classified(ctx, arn, key_id, body)
        .await
        .map_err(public_kms_failure)
}

async fn encrypt_body_classified(
    ctx: &Ctx<'_>,
    arn: &str,
    key_id: &str,
    body: &str,
) -> Result<EncryptedBody, MoveKmsFailure> {
    let dispatcher = ctx.dispatcher.as_ref().ok_or(MoveKmsFailure::Terminal)?;
    let resolved = dispatcher
        .kms_validate_key(KmsValidateKeyRequest {
            call: kms_call(ctx),
            key_id: key_id.into(),
        })
        .map_err(move_kms_failure)?;
    let iam_policy_allowed = authorize_kms(ctx, "kms:GenerateDataKey", &resolved.key_arn)
        .map_err(|_| MoveKmsFailure::Terminal)?;
    let data_key = dispatcher
        .kms_generate_data_key_bounded(
            KmsGenerateDataKeyRequest {
                call: KmsCallContext {
                    iam_policy_allowed,
                    ..kms_call(ctx)
                },
                key_id: key_id.into(),
                number_of_bytes: 32,
                encryption_context: kms_context(arn),
            },
            KMS_WAIT_LIMIT,
        )
        .await
        .map_err(move_kms_failure)?;
    let key = RandomizedNonceKey::new(&AES_256_GCM, data_key.plaintext.as_slice())
        .map_err(|_| MoveKmsFailure::Terminal)?;
    let mut ciphertext = body.as_bytes().to_vec();
    let nonce = key
        .seal_in_place_append_tag(Aad::from(arn.as_bytes()), &mut ciphertext)
        .map_err(|_| MoveKmsFailure::Terminal)?;
    let mut nonce_bytes = [0_u8; 12];
    nonce_bytes.copy_from_slice(nonce.as_ref());
    Ok(EncryptedBody {
        encryption_context_arn: arn.to_string(),
        ciphertext,
        encrypted_data_key: data_key.ciphertext.into_vec(),
        nonce: nonce_bytes,
        key_id: data_key.key_id,
    })
}

async fn decrypt_body(ctx: &Ctx<'_>, encrypted: &EncryptedBody) -> Result<String, SqsError> {
    decrypt_body_classified(ctx, encrypted)
        .await
        .map_err(public_kms_failure)
}

async fn decrypt_body_classified(
    ctx: &Ctx<'_>,
    encrypted: &EncryptedBody,
) -> Result<String, MoveKmsFailure> {
    let arn = &encrypted.encryption_context_arn;
    let dispatcher = ctx.dispatcher.as_ref().ok_or(MoveKmsFailure::Terminal)?;
    let iam_policy_allowed = authorize_kms(ctx, "kms:Decrypt", &encrypted.key_id)
        .map_err(|_| MoveKmsFailure::Terminal)?;
    let data_key = dispatcher
        .kms_decrypt_bounded(
            KmsDecryptRequest {
                call: KmsCallContext {
                    iam_policy_allowed,
                    ..kms_call(ctx)
                },
                key_id: Some(encrypted.key_id.clone()),
                ciphertext: SensitiveBytes::new(encrypted.encrypted_data_key.clone()),
                encryption_context: kms_context(arn),
            },
            KMS_WAIT_LIMIT,
        )
        .await
        .map_err(move_kms_failure)?;
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, data_key.plaintext.as_slice())
            .map_err(|_| MoveKmsFailure::Terminal)?,
    );
    let nonce =
        Nonce::try_assume_unique_for_key(&encrypted.nonce).map_err(|_| MoveKmsFailure::Terminal)?;
    let mut plaintext = encrypted.ciphertext.clone();
    let opened = key
        .open_in_place(nonce, Aad::from(arn.as_bytes()), &mut plaintext)
        .map_err(|_| MoveKmsFailure::Terminal)?;
    String::from_utf8(opened.to_vec()).map_err(|_| MoveKmsFailure::Terminal)
}

async fn messages_json(
    ctx: &Ctx<'_>,
    _arn: &str,
    selected: &[Message],
    want_attr: &(dyn Fn(&str) -> bool + Sync),
    want_msg_attr: &(dyn Fn(&str) -> bool + Sync),
) -> Result<Vec<Value>, SqsError> {
    let mut output = Vec::with_capacity(selected.len());
    for message in selected {
        let body = match &message.encrypted_body {
            Some(encrypted) => Some(decrypt_body(ctx, encrypted).await?),
            None => None,
        };
        output.push(message_json(
            message,
            body.as_deref(),
            ctx.account,
            want_attr,
            want_msg_attr,
        ));
    }
    Ok(output)
}

pub async fn send_message(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let input = parse_send_input(v)?;
    let key_id = {
        q.state
            .lock()
            .await
            .attributes
            .get("KmsMasterKeyId")
            .cloned()
            .filter(|key| !key.is_empty())
    };
    let encrypted = match key_id.as_deref() {
        Some(key) => Some(encrypt_body(ctx, &q.arn.to_arn(), key, &input.body).await?),
        None => None,
    };
    let mut state = q.state.lock().await;
    if state
        .attributes
        .get("KmsMasterKeyId")
        .filter(|key| !key.is_empty())
        != key_id.as_ref()
    {
        return Err(SqsError::KmsAccessDenied);
    }
    let result = enqueue(&q, ctx.store.persistence(), &mut state, input, encrypted)?;
    drop(state);
    q.notify.notify_one();
    if result.added {
        ctx.metrics.record_sent(&q.arn, result.size);
    }
    Ok(send_result_json(&result))
}

pub async fn send_message_batch(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let entries = v
        .get("Entries")
        .and_then(Value::as_array)
        .ok_or(SqsError::EmptyBatchRequest)?;
    if entries.is_empty() {
        return Err(SqsError::EmptyBatchRequest);
    }
    if entries.len() > MAX_BATCH {
        return Err(SqsError::TooManyEntriesInBatchRequest);
    }
    // Entry ids must be valid and distinct; aggregate payload is validated before mutation.
    let mut seen = Vec::new();
    let mut payload_size = 0usize;
    for entry in entries {
        let id = req_str(entry, "Id")
            .map_err(|_| SqsError::InvalidBatchEntryId("entry missing Id".into()))?;
        if !valid_batch_id(id) {
            return Err(SqsError::InvalidBatchEntryId(format!(
                "invalid batch entry Id {id}"
            )));
        }
        if seen.contains(&id) {
            return Err(SqsError::BatchEntryIdsNotDistinct);
        }
        seen.push(id);
        if let Ok(input) = parse_send_input(entry) {
            payload_size = payload_size
                .saturating_add(input.body.len())
                .saturating_add(attribute_size(&input.attributes));
        }
    }
    if payload_size > MAX_BATCH_PAYLOAD {
        return Err(SqsError::BatchRequestTooLong);
    }

    // Prepare every encryptable entry before acquiring the queue lock. A KMS failure
    // rejects the whole request without publishing any entry; validation errors remain
    // per-entry results as required by the batch API.
    let key_id = q
        .state
        .lock()
        .await
        .attributes
        .get("KmsMasterKeyId")
        .cloned()
        .filter(|key| !key.is_empty());
    let mut prepared = Vec::with_capacity(entries.len());
    for entry in entries {
        let input = parse_send_input(entry);
        let item = match input {
            Ok(input) => {
                let encrypted = match key_id.as_deref() {
                    Some(key) => Some(encrypt_body(ctx, &q.arn.to_arn(), key, &input.body).await?),
                    None => None,
                };
                Ok((input, encrypted))
            }
            Err(error) => Err(error),
        };
        prepared.push(item);
    }

    let mut successful = Vec::new();
    let mut failed = Vec::new();
    let mut state = q.state.lock().await;
    if state
        .attributes
        .get("KmsMasterKeyId")
        .filter(|key| !key.is_empty())
        != key_id.as_ref()
    {
        return Err(SqsError::KmsAccessDenied);
    }
    for (entry, item) in entries.iter().zip(prepared) {
        let id = entry
            .get("Id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        match item.and_then(|(input, encrypted)| {
            enqueue(&q, ctx.store.persistence(), &mut state, input, encrypted)
        }) {
            Ok(result) => {
                if result.added {
                    ctx.metrics.record_sent(&q.arn, result.size);
                }
                let mut success = send_result_json(&result);
                success
                    .as_object_mut()
                    .unwrap()
                    .insert("Id".into(), json!(id));
                successful.push(success);
            }
            Err(error) => failed.push(json!({
                "Id": id, "Code": error.code(), "Message": error.to_string(), "SenderFault": error.http_status() < 500,
            })),
        }
    }
    drop(state);
    q.notify.notify_waiters();
    Ok(json!({ "Successful": successful, "Failed": failed }))
}

// ============================ receive ==========================================

/// Move messages whose receive count has reached the redrive threshold to the DLQ before a
/// receive. The destination and its allow policy are resolved before source mutation.
async fn redrive_expired(ctx: &Ctx<'_>, q: &Arc<GuardedQueue>) -> Result<(), SqsError> {
    let _lifecycle = ctx.store.lifecycle_read().await;
    let (dlq_arn, max_receive) = {
        let state = q.state.lock().await;
        match parse_redrive_policy(&state)? {
            Some(policy) => policy,
            None => return Ok(()),
        }
    };
    let now = Instant::now();
    {
        let state = q.state.lock().await;
        if !state
            .messages
            .iter()
            .any(|message| message.is_visible(now) && message.receive_count >= max_receive)
        {
            return Ok(());
        }
    }
    let dlq = ctx.store.get(&dlq_arn).ok_or_else(|| {
        SqsError::InvalidAttributeValue("dead-letter queue does not exist".into())
    })?;
    {
        let dlq_state = dlq.state.lock().await;
        if !redrive_allowed(&q.arn, &dlq_state)? {
            return Err(SqsError::InvalidAttributeValue(
                "dead-letter queue no longer allows this source queue".into(),
            ));
        }
    }

    if q.arn == dlq.arn {
        return Err(SqsError::InvalidAttributeValue(
            "a queue cannot be its own dead-letter queue".into(),
        ));
    }
    // Hold both queue locks from validation through transfer. Queue ARN order prevents
    // deadlocks when two queues have opposing redrive policies.
    let (mut state, mut dlq_state) = if q.arn.to_arn() < dlq.arn.to_arn() {
        (q.state.lock().await, dlq.state.lock().await)
    } else {
        let destination = dlq.state.lock().await;
        (q.state.lock().await, destination)
    };
    if !redrive_allowed(&q.arn, &dlq_state)? {
        return Err(SqsError::InvalidAttributeValue(
            "dead-letter queue no longer allows this source queue".into(),
        ));
    }
    expire_messages(ctx, q, &mut state)?;
    let now = Instant::now();
    let transfer: Vec<Message> = state
        .messages
        .iter()
        .filter(|message| message.is_visible(now) && message.receive_count >= max_receive)
        .map(|message| {
            let mut message = message.clone();
            message.receive_count = 0;
            message.first_receive_ms = None;
            message.receipt_handle = None;
            message.visible_at = Instant::now();
            message
        })
        .collect();
    if let Some(db) = ctx.store.persistence() {
        db.move_messages(q, &dlq, &transfer)?;
    }
    let mut index = 0;
    let mut moved = false;
    while index < state.messages.len() {
        let message = &state.messages[index];
        if message.is_visible(now) && message.receive_count >= max_receive {
            let mut message = state.messages.remove(index);
            message.receive_count = 0;
            message.first_receive_ms = None;
            message.receipt_handle = None;
            message.visible_at = Instant::now();
            dlq_state.messages.push(message);
            moved = true;
        } else {
            index += 1;
        }
    }
    drop(state);
    drop(dlq_state);
    if moved {
        dlq.notify.notify_waiters();
    }
    Ok(())
}

/// Parse the stored `RedrivePolicy`; malformed stored state fails closed.
fn parse_redrive_policy(state: &QueueState) -> Result<Option<(QueueArn, u32)>, SqsError> {
    state
        .attributes
        .get("RedrivePolicy")
        .map(|raw| parse_redrive_policy_raw(raw).map(Some))
        .unwrap_or(Ok(None))
}

/// Parse an SQS ARN `arn:aws:sqs:<region>:<account>:<name>`.
pub(crate) fn arn_from_str(arn: &str) -> Option<QueueArn> {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() == 6 && parts[2] == "sqs" {
        Some(QueueArn::new(parts[3], parts[4], parts[5]))
    } else {
        None
    }
}

/// Select and lock up to `max` visible messages, honoring FIFO group ordering.
fn select_messages(
    state: &mut QueueState,
    fifo: bool,
    max: usize,
    visibility: i64,
) -> Vec<Message> {
    let now = Instant::now();
    let blocked_groups: Vec<String> = if fifo {
        state
            .messages
            .iter()
            .filter(|m| m.is_in_flight(now))
            .filter_map(|m| m.group_id.clone())
            .collect()
    } else {
        Vec::new()
    };

    let mut take_indices = Vec::new();
    for (i, m) in state.messages.iter().enumerate() {
        if take_indices.len() >= max {
            break;
        }
        if !m.is_visible(now) {
            continue;
        }
        if fifo {
            if let Some(g) = &m.group_id {
                if blocked_groups.contains(g) {
                    continue;
                }
            }
        }
        take_indices.push(i);
    }

    let mut taken = Vec::with_capacity(take_indices.len());
    for i in take_indices {
        let m = &mut state.messages[i];
        m.receive_count += 1;
        if m.first_receive_ms.is_none() {
            m.first_receive_ms = Some(now_ms());
        }
        m.visible_at = now + Duration::from_secs(visibility.max(0) as u64);
        let handle = format!("{}:{}", m.id, Uuid::new_v4());
        m.receipt_handle = Some(handle);
        taken.push(m.clone());
    }
    taken
}

fn message_json(
    m: &Message,
    plaintext_body: Option<&str>,
    account: &str,
    want_attr: &dyn Fn(&str) -> bool,
    want_msg_attr: &dyn Fn(&str) -> bool,
) -> Value {
    let mut obj = Map::new();
    obj.insert("MessageId".into(), json!(m.id));
    obj.insert(
        "ReceiptHandle".into(),
        json!(m.receipt_handle.clone().unwrap_or_default()),
    );
    obj.insert("MD5OfBody".into(), json!(m.md5_body));
    obj.insert("Body".into(), json!(plaintext_body.unwrap_or(&m.body)));
    if let Some(md5) = &m.md5_attributes {
        obj.insert("MD5OfMessageAttributes".into(), json!(md5));
    }

    // System attributes.
    let mut sys: Vec<(String, String)> = vec![
        ("SenderId".into(), account.to_string()),
        ("SentTimestamp".into(), m.sent_timestamp_ms.to_string()),
        (
            "ApproximateReceiveCount".into(),
            m.receive_count.to_string(),
        ),
    ];
    if let Some(first) = m.first_receive_ms {
        sys.push(("ApproximateFirstReceiveTimestamp".into(), first.to_string()));
    }
    if let Some(g) = &m.group_id {
        sys.push(("MessageGroupId".into(), g.clone()));
    }
    if let Some(d) = &m.dedup_id {
        sys.push(("MessageDeduplicationId".into(), d.clone()));
    }
    if let Some(seq) = m.sequence_number {
        sys.push(("SequenceNumber".into(), seq.to_string()));
    }
    for (k, val) in &m.system_attributes {
        sys.push((k.clone(), val.clone()));
    }
    let selected_sys: Map<String, Value> = sys
        .into_iter()
        .filter(|(k, _)| want_attr(k))
        .map(|(k, v)| (k, json!(v)))
        .collect();
    if !selected_sys.is_empty() {
        obj.insert("Attributes".into(), Value::Object(selected_sys));
    }

    // Message attributes.
    let selected_attrs: BTreeMap<String, MessageAttribute> = m
        .attributes
        .iter()
        .filter(|(name, _)| want_msg_attr(name))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if !selected_attrs.is_empty() {
        obj.insert(
            "MessageAttributes".into(),
            message_attributes_json(&selected_attrs),
        );
    }
    Value::Object(obj)
}

/// Build a name-matcher from a requested list (supports `All`/`.*`).
fn matcher(requested: Vec<String>) -> impl Fn(&str) -> bool {
    let all = requested.iter().any(|n| n == "All" || n == ".*");
    move |name: &str| all || requested.iter().any(|n| n == name)
}

fn string_list(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn restore_selection(state: &mut QueueState, selected: &[Message]) {
    for message in selected {
        if let Some(stored) = state.messages.iter_mut().find(|stored| {
            stored.id == message.id && stored.receipt_handle == message.receipt_handle
        }) {
            stored.receipt_handle = None;
            stored.visible_at = Instant::now();
            stored.receive_count = stored.receive_count.saturating_sub(1);
            if stored.receive_count == 0 {
                stored.first_receive_ms = None;
            }
        }
    }
}

pub async fn receive_message(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let key_id = q
        .state
        .lock()
        .await
        .attributes
        .get("KmsMasterKeyId")
        .cloned()
        .filter(|key| !key.is_empty());
    if let Some(key_id) = key_id {
        let dispatcher = ctx.dispatcher.as_ref().ok_or(SqsError::KmsAccessDenied)?;
        let resolved = dispatcher
            .kms_validate_key(KmsValidateKeyRequest {
                call: kms_call(ctx),
                key_id,
            })
            .map_err(|_| SqsError::KmsAccessDenied)?;
        authorize_kms(ctx, "kms:Decrypt", &resolved.key_arn)?;
    }
    let max = bounded_i64(v, "MaxNumberOfMessages", 1, 1, 10)? as usize;
    let vis_override = optional_i64(v, "VisibilityTimeout")?;
    if vis_override.is_some_and(|visibility| !(0..=43_200).contains(&visibility)) {
        return Err(SqsError::InvalidParameterValue(
            "VisibilityTimeout must be between 0 and 43200".into(),
        ));
    }
    let attempt_id = str_field(v, "ReceiveRequestAttemptId").map(String::from);
    if attempt_id.is_some() && !q.fifo {
        return Err(SqsError::InvalidParameterValue(
            "ReceiveRequestAttemptId is only valid for FIFO queues".into(),
        ));
    }
    if attempt_id.as_ref().is_some_and(|id| id.len() > 128) {
        return Err(SqsError::InvalidParameterValue(
            "ReceiveRequestAttemptId cannot exceed 128 characters".into(),
        ));
    }

    // Attribute selection: MessageSystemAttributeNames (preferred) or legacy AttributeNames.
    let mut attr_names = string_list(v, "MessageSystemAttributeNames");
    attr_names.extend(string_list(v, "AttributeNames"));
    let want_attr = matcher(attr_names);
    let want_msg_attr = matcher(string_list(v, "MessageAttributeNames"));

    let wait_secs = {
        let mut state = q.state.lock().await;
        expire_messages(ctx, &q, &mut state)?;
        let wait = optional_i64(v, "WaitTimeSeconds")?.unwrap_or_else(|| state.wait_time_seconds());
        if !(0..=MAX_RECEIVE_WAIT_SECONDS).contains(&wait) {
            return Err(SqsError::InvalidParameterValue(format!(
                "WaitTimeSeconds must be between 0 and {MAX_RECEIVE_WAIT_SECONDS}"
            )));
        }
        if let Some(id) = &attempt_id {
            if let Some(attempt) = state.receive_attempts.get(id) {
                let selected = attempt.messages.clone();
                drop(state);
                let messages =
                    messages_json(ctx, &q.arn.to_arn(), &selected, &want_attr, &want_msg_attr)
                        .await?;
                ctx.metrics.record_received(&q.arn, messages.len());
                return Ok(json!({ "Messages": messages }));
            }
        }
        wait
    };

    let start = Instant::now();
    loop {
        redrive_expired(ctx, &q).await?;
        let (selected, next_visibility) = {
            let mut state = q.state.lock().await;
            expire_messages(ctx, &q, &mut state)?;
            let visibility = vis_override.unwrap_or_else(|| state.visibility_timeout());
            let selected = select_messages(&mut state, q.fifo, max, visibility);
            if !selected.is_empty() {
                if let Some(id) = &attempt_id {
                    state.receive_attempts.insert(
                        id.clone(),
                        ReceiveAttempt {
                            expires_at: Instant::now() + RECEIVE_ATTEMPT_WINDOW,
                            messages: selected.clone(),
                        },
                    );
                }
            }
            if !selected.is_empty() {
                if let Some(db) = ctx.store.persistence() {
                    let attempt = attempt_id.as_ref().and_then(|id| {
                        state
                            .receive_attempts
                            .get(id)
                            .map(|entry| (id.as_str(), entry))
                    });
                    if let Err(error) = db.update_messages(&q, &selected, attempt) {
                        restore_selection(&mut state, &selected);
                        if let Some(id) = &attempt_id {
                            state.receive_attempts.remove(id);
                        }
                        return Err(error);
                    }
                }
            }
            let now = Instant::now();
            let next_visibility = state
                .messages
                .iter()
                .filter_map(|message| message.visible_at.checked_duration_since(now))
                .min();
            (selected, next_visibility)
        };
        if !selected.is_empty() {
            match messages_json(ctx, &q.arn.to_arn(), &selected, &want_attr, &want_msg_attr).await {
                Ok(messages) => {
                    ctx.metrics.record_received(&q.arn, messages.len());
                    return Ok(json!({ "Messages": messages }));
                }
                Err(error) => {
                    let mut state = q.state.lock().await;
                    restore_selection(&mut state, &selected);
                    if let Some(db) = ctx.store.persistence() {
                        let restored: Vec<_> = state
                            .messages
                            .iter()
                            .filter(|m| selected.iter().any(|s| s.id == m.id))
                            .cloned()
                            .collect();
                        db.restore_receive(&q, &restored, attempt_id.as_deref())?;
                    }
                    if let Some(id) = &attempt_id {
                        state.receive_attempts.remove(id);
                    }
                    return Err(error);
                }
            }
        }
        let elapsed = start.elapsed().as_secs() as i64;
        if elapsed >= wait_secs {
            ctx.metrics.record_received(&q.arn, 0);
            return Ok(json!({}));
        }
        let remaining = Duration::from_secs((wait_secs - elapsed) as u64);
        let sleep_for = next_visibility.map_or(remaining, |next| next.min(remaining));
        tokio::select! {
            _ = q.notify.notified() => {}
            _ = tokio::time::sleep(sleep_for) => {}
        }
    }
}

// ============================ delete / visibility / purge ======================

/// Extract the message id encoded in a receipt handle (`<id>:<token>`).
fn message_id_from_handle(handle: &str) -> Result<&str, SqsError> {
    handle
        .split_once(':')
        .map(|(id, _)| id)
        .filter(|id| !id.is_empty())
        .ok_or(SqsError::ReceiptHandleIsInvalid)
}

/// Delete a message by its receipt handle (idempotent). Only removes when the handle is the
/// message's current in-flight handle, so a stale handle never deletes a redelivered message.
fn delete_by_handle(
    q: &GuardedQueue,
    db: Option<&crate::persistence::SqsPersistence>,
    state: &mut QueueState,
    handle: &str,
) -> Result<(), SqsError> {
    let id = message_id_from_handle(handle)?;
    if let Some(pos) = state
        .messages
        .iter()
        .position(|m| m.id == id && m.receipt_handle.as_deref() == Some(handle))
    {
        let id = state.messages[pos].id.as_str();
        if let Some(db) = db {
            db.delete_messages(q, &[id])?;
        }
        state.messages.remove(pos);
    }
    Ok(())
}

pub async fn delete_message(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let handle = req_str(v, "ReceiptHandle")?;
    let mut state = q.state.lock().await;
    delete_by_handle(&q, ctx.store.persistence(), &mut state, handle)?;
    drop(state);
    ctx.metrics.record_deleted(&q.arn, 1);
    Ok(json!({}))
}

pub async fn delete_message_batch(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let entries = batch_entries(v)?;
    let mut state = q.state.lock().await;
    let mut successful = Vec::new();
    let mut failed = Vec::new();
    for e in &entries {
        let id = e
            .get("Id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        match e.get("ReceiptHandle").and_then(Value::as_str) {
            Some(handle) => match delete_by_handle(&q, ctx.store.persistence(), &mut state, handle)
            {
                Ok(()) => successful.push(json!({ "Id": id })),
                Err(err) => failed.push(batch_error(&id, &err)),
            },
            None => failed.push(batch_error(&id, &SqsError::ReceiptHandleIsInvalid)),
        }
    }
    drop(state);
    ctx.metrics.record_deleted(&q.arn, successful.len());
    Ok(json!({ "Successful": successful, "Failed": failed }))
}

/// Adjust a message's visibility deadline by its receipt handle.
fn change_visibility(
    q: &GuardedQueue,
    db: Option<&crate::persistence::SqsPersistence>,
    state: &mut QueueState,
    handle: &str,
    timeout: i64,
) -> Result<(), SqsError> {
    let id = message_id_from_handle(handle)?;
    let now = Instant::now();
    let m = state
        .messages
        .iter_mut()
        .find(|m| m.id == id && m.receipt_handle.as_deref() == Some(handle))
        .ok_or(SqsError::MessageNotInflight)?;
    let original = m.clone();
    m.visible_at = now + Duration::from_secs(timeout.max(0) as u64);
    if timeout <= 0 {
        m.receipt_handle = None;
    }
    if let Some(db) = db {
        if let Err(error) = db.update_messages(q, std::slice::from_ref(m), None) {
            *m = original;
            return Err(error);
        }
    }
    Ok(())
}

pub async fn change_message_visibility(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let handle = req_str(v, "ReceiptHandle")?;
    let timeout = optional_i64(v, "VisibilityTimeout")?
        .ok_or_else(|| SqsError::MissingParameter("VisibilityTimeout is required".into()))?;
    if !(0..=43_200).contains(&timeout) {
        return Err(SqsError::InvalidParameterValue(
            "VisibilityTimeout must be between 0 and 43200".into(),
        ));
    }
    let mut state = q.state.lock().await;
    change_visibility(&q, ctx.store.persistence(), &mut state, handle, timeout)?;
    drop(state);
    if timeout <= 0 {
        q.notify.notify_waiters();
    }
    Ok(json!({}))
}

pub async fn change_message_visibility_batch(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let entries = batch_entries(v)?;
    let mut state = q.state.lock().await;
    let mut successful = Vec::new();
    let mut failed = Vec::new();
    for e in &entries {
        let id = e
            .get("Id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let handle = e.get("ReceiptHandle").and_then(Value::as_str).unwrap_or("");
        let result = optional_i64(e, "VisibilityTimeout").and_then(|timeout| {
            let timeout = timeout.ok_or_else(|| {
                SqsError::MissingParameter("VisibilityTimeout is required".into())
            })?;
            if !(0..=43_200).contains(&timeout) {
                return Err(SqsError::InvalidParameterValue(
                    "VisibilityTimeout must be between 0 and 43200".into(),
                ));
            }
            change_visibility(&q, ctx.store.persistence(), &mut state, handle, timeout)
        });
        match result {
            Ok(()) => successful.push(json!({ "Id": id })),
            Err(err) => failed.push(batch_error(&id, &err)),
        }
    }
    Ok(json!({ "Successful": successful, "Failed": failed }))
}

pub async fn purge_queue(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let mut state = q.state.lock().await;
    if state
        .last_purge
        .is_some_and(|last_purge| last_purge.elapsed() < Duration::from_secs(60))
    {
        return Err(SqsError::PurgeQueueInProgress);
    }
    let previous_purge = state.last_purge;
    state.last_purge = Some(Instant::now());
    if let Some(db) = ctx.store.persistence() {
        if let Err(error) = db.purge(&q, &state) {
            state.last_purge = previous_purge;
            return Err(error);
        }
    }
    state.messages.clear();
    state.dedup.clear();
    state.receive_attempts.clear();
    Ok(json!({}))
}

/// Validate and return batch entries (1..=10, ids present and distinct).
fn batch_entries(v: &Value) -> Result<Vec<Value>, SqsError> {
    let entries = v
        .get("Entries")
        .and_then(Value::as_array)
        .ok_or(SqsError::EmptyBatchRequest)?;
    if entries.is_empty() {
        return Err(SqsError::EmptyBatchRequest);
    }
    if entries.len() > MAX_BATCH {
        return Err(SqsError::TooManyEntriesInBatchRequest);
    }
    let mut seen = Vec::new();
    for e in entries {
        let id = e
            .get("Id")
            .and_then(Value::as_str)
            .ok_or_else(|| SqsError::InvalidBatchEntryId("entry missing Id".into()))?;
        if !valid_batch_id(id) {
            return Err(SqsError::InvalidBatchEntryId(format!(
                "invalid batch entry Id {id}"
            )));
        }
        if seen.contains(&id) {
            return Err(SqsError::BatchEntryIdsNotDistinct);
        }
        seen.push(id);
    }
    Ok(entries.clone())
}

fn batch_error(id: &str, err: &SqsError) -> Value {
    json!({ "Id": id, "Code": err.code(), "Message": err.to_string(), "SenderFault": err.http_status() < 500 })
}

// ============================ tags / permissions ===============================

pub async fn tag_queue(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let tags = parse_tags(v)?;
    if tags.is_empty() {
        return Err(SqsError::MissingParameter("Tags is required".into()));
    }
    let mut state = q.state.lock().await;
    let original = state.tags.clone();
    let last_modified = state.last_modified;
    let new_keys = tags
        .keys()
        .filter(|key| !state.tags.contains_key(*key))
        .count();
    if state.tags.len() + new_keys > MAX_TAGS {
        return Err(SqsError::InvalidParameterValue(format!(
            "a queue can have at most {MAX_TAGS} tags"
        )));
    }
    state.tags.extend(tags);
    state.touch();
    if let Some(db) = ctx.store.persistence() {
        if let Err(error) = db.save_queue(&q, &state) {
            state.tags = original;
            state.last_modified = last_modified;
            return Err(error);
        }
    }
    Ok(json!({}))
}

pub async fn untag_queue(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let keys = string_list(v, "TagKeys");
    if keys.is_empty() {
        return Err(SqsError::MissingParameter("TagKeys is required".into()));
    }
    if keys.len() > MAX_TAGS
        || keys.iter().any(|key| {
            key.is_empty()
                || key.len() > 128
                || key.to_ascii_lowercase().starts_with("aws:")
                || !key
                    .chars()
                    .all(|c| c.is_alphanumeric() || " _.:/=+-@".contains(c))
        })
    {
        return Err(SqsError::InvalidParameterValue(
            "TagKeys contains an invalid tag key".into(),
        ));
    }
    let mut state = q.state.lock().await;
    let original = state.tags.clone();
    let last_modified = state.last_modified;
    state.tags.retain(|k, _| !keys.contains(k));
    state.touch();
    if let Some(db) = ctx.store.persistence() {
        if let Err(error) = db.save_queue(&q, &state) {
            state.tags = original;
            state.last_modified = last_modified;
            return Err(error);
        }
    }
    Ok(json!({}))
}

pub async fn list_queue_tags(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let state = q.state.lock().await;
    if state.tags.is_empty() {
        return Ok(json!({}));
    }
    let tags: Map<String, Value> = state
        .tags
        .iter()
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect();
    Ok(json!({ "Tags": tags }))
}

pub async fn add_permission(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let label = str_field(v, "Label")
        .ok_or_else(|| SqsError::InvalidParameterValue("Label is required".into()))?
        .to_string();
    let accounts = string_list(v, "AWSAccountIds");
    let actions = string_list(v, "Actions");
    if !valid_batch_id(&label) {
        return Err(SqsError::InvalidParameterValue(
            "Label must be 1-80 alphanumeric, hyphen, or underscore characters".into(),
        ));
    }
    if accounts.is_empty() {
        return Err(SqsError::MissingParameter(
            "AWSAccountId is required".into(),
        ));
    }
    if accounts.len() > 7 {
        return Err(SqsError::InvalidParameterValue(
            "AWSAccountIds cannot contain more than 7 accounts".into(),
        ));
    }
    if accounts
        .iter()
        .any(|account| account.len() != 12 || !account.chars().all(|c| c.is_ascii_digit()))
    {
        return Err(SqsError::InvalidParameterValue(
            "AWSAccountIds contains an invalid account id".into(),
        ));
    }
    const ALLOWED_ACTIONS: [&str; 7] = [
        "*",
        "SendMessage",
        "ReceiveMessage",
        "DeleteMessage",
        "ChangeMessageVisibility",
        "GetQueueAttributes",
        "GetQueueUrl",
    ];
    if actions.is_empty() {
        return Err(SqsError::MissingParameter("ActionName is required".into()));
    }
    if actions.len() > 7
        || actions
            .iter()
            .any(|action| !ALLOWED_ACTIONS.contains(&action.as_str()))
    {
        return Err(SqsError::InvalidParameterValue(
            "Actions contains an unsupported SQS action".into(),
        ));
    }
    let mut state = q.state.lock().await;
    let original = state.attributes.clone();
    let last_modified = state.last_modified;
    let mut policy = state
        .attributes
        .get("Policy")
        .and_then(|p| serde_json::from_str::<Value>(p).ok())
        .unwrap_or_else(|| json!({ "Version": "2012-10-17", "Id": format!("{}/SQSDefaultPolicy", q.arn.to_arn()), "Statement": [] }));
    if policy.get("Statement").is_some_and(Value::is_object) {
        let statement = policy
            .get_mut("Statement")
            .map(Value::take)
            .expect("Statement was present");
        policy["Statement"] = Value::Array(vec![statement]);
    }
    let statements = policy
        .get_mut("Statement")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| SqsError::InvalidAttributeValue("malformed Policy".into()))?;
    if statements
        .iter()
        .any(|s| s.get("Sid").and_then(Value::as_str) == Some(label.as_str()))
    {
        return Err(SqsError::InvalidParameterValue(format!(
            "permission {label} already exists"
        )));
    }
    let principals: Vec<Value> = accounts
        .iter()
        .map(|a| json!(format!("arn:aws:iam::{a}:root")))
        .collect();
    statements.push(json!({
        "Sid": label,
        "Effect": "Allow",
        "Principal": { "AWS": principals },
        "Action": actions.iter().map(|a| json!(format!("SQS:{a}"))).collect::<Vec<_>>(),
        "Resource": q.arn.to_arn(),
    }));
    state.attributes.insert("Policy".into(), policy.to_string());
    state.touch();
    if let Some(db) = ctx.store.persistence() {
        if let Err(error) = db.save_queue(&q, &state) {
            state.attributes = original;
            state.last_modified = last_modified;
            return Err(error);
        }
    }
    Ok(json!({}))
}

pub async fn remove_permission(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let label = str_field(v, "Label")
        .ok_or_else(|| SqsError::InvalidParameterValue("Label is required".into()))?;
    let mut state = q.state.lock().await;
    let original = state.attributes.clone();
    let last_modified = state.last_modified;
    let raw =
        state.attributes.get("Policy").cloned().ok_or_else(|| {
            SqsError::InvalidParameterValue(format!("permission {label} not found"))
        })?;
    let mut policy = serde_json::from_str::<Value>(&raw)
        .map_err(|_| SqsError::InvalidAttributeValue("malformed stored Policy".into()))?;
    if policy.get("Statement").is_some_and(Value::is_object) {
        let statement = policy
            .get_mut("Statement")
            .map(Value::take)
            .expect("Statement was present");
        policy["Statement"] = Value::Array(vec![statement]);
    }
    let statements = policy
        .get_mut("Statement")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| SqsError::InvalidAttributeValue("malformed stored Policy".into()))?;
    let previous_len = statements.len();
    statements.retain(|statement| statement.get("Sid").and_then(Value::as_str) != Some(label));
    if statements.len() == previous_len {
        return Err(SqsError::InvalidParameterValue(format!(
            "permission {label} not found"
        )));
    }
    if statements.is_empty() {
        state.attributes.remove("Policy");
    } else {
        state.attributes.insert("Policy".into(), policy.to_string());
    }
    state.touch();
    if let Some(db) = ctx.store.persistence() {
        if let Err(error) = db.save_queue(&q, &state) {
            state.attributes = original;
            state.last_modified = last_modified;
            return Err(error);
        }
    }
    Ok(json!({}))
}

// ============================ redrive / move tasks =============================

pub async fn list_dead_letter_source_queues(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let q = resolve_queue(ctx, v)?;
    let max = bounded_i64(v, "MaxResults", 1_000, 1, 1_000)? as usize;
    let target_arn = q.arn.to_arn();
    let after = page_after(
        "ListDeadLetterSourceQueues",
        ctx,
        &target_arn,
        str_field(v, "NextToken"),
    )?;
    let mut sources = Vec::new();
    for candidate in ctx.store.list(ctx.account, ctx.region, None) {
        if after
            .as_ref()
            .is_some_and(|last_name| candidate.arn.name <= *last_name)
        {
            continue;
        }
        let state = candidate.state.lock().await;
        if parse_redrive_policy(&state)?.is_some_and(|(dlq, _)| dlq.to_arn() == target_arn) {
            sources.push(candidate.clone());
        }
    }
    let page: Vec<_> = sources.iter().take(max).collect();
    let mut response = Map::new();
    response.insert(
        "queueUrls".into(),
        Value::Array(page.iter().map(|queue| json!(queue.arn.to_url())).collect()),
    );
    if sources.len() > page.len() {
        response.insert(
            "NextToken".into(),
            json!(page_token(
                "ListDeadLetterSourceQueues",
                ctx,
                &target_arn,
                &page.last().expect("non-empty page").arn.name,
            )),
        );
    }
    Ok(Value::Object(response))
}

enum MoveOneResult {
    Blocked,
    Retryable,
    Moved,
    Waiting,
    Empty,
}

async fn move_one_message(
    ctx: &Ctx<'_>,
    source: &GuardedQueue,
    destination: &GuardedQueue,
) -> MoveOneResult {
    // KMS calls must happen outside both queue locks. If the selected message or
    // either queue key changes during preparation, retry on the next worker tick.
    let (snapshot, source_key) = {
        let state = source.state.lock().await;
        let now = Instant::now();
        let Some(message) = state
            .messages
            .iter()
            .find(|message| message.is_visible(now))
        else {
            return if state.messages.is_empty() {
                MoveOneResult::Empty
            } else {
                MoveOneResult::Waiting
            };
        };
        (message.clone(), queue_key_id(&state))
    };
    let destination_key = {
        let state = destination.state.lock().await;
        queue_key_id(&state)
    };
    let plaintext = match &snapshot.encrypted_body {
        Some(encrypted) => match decrypt_body_classified(ctx, encrypted).await {
            Ok(body) => body,
            Err(MoveKmsFailure::Retryable) => return MoveOneResult::Retryable,
            Err(MoveKmsFailure::Terminal) => return MoveOneResult::Blocked,
        },
        None => snapshot.body.clone(),
    };
    let encrypted = match destination_key.as_deref() {
        Some(key) => {
            match authorize_move_destination_key(ctx, key) {
                Ok(()) => {}
                Err(MoveKmsFailure::Retryable) => return MoveOneResult::Retryable,
                Err(MoveKmsFailure::Terminal) => return MoveOneResult::Blocked,
            }
            match encrypt_body_classified(ctx, &destination.arn.to_arn(), key, &plaintext).await {
                Ok(encrypted) => match decrypt_body_classified(ctx, &encrypted).await {
                    Ok(_) => Some(encrypted),
                    Err(MoveKmsFailure::Retryable) => return MoveOneResult::Retryable,
                    Err(MoveKmsFailure::Terminal) => return MoveOneResult::Blocked,
                },
                Err(MoveKmsFailure::Retryable) => return MoveOneResult::Retryable,
                Err(MoveKmsFailure::Terminal) => return MoveOneResult::Blocked,
            }
        }
        None => None,
    };

    let (mut source_state, mut destination_state) =
        if source.arn.to_arn() < destination.arn.to_arn() {
            (source.state.lock().await, destination.state.lock().await)
        } else {
            let destination_state = destination.state.lock().await;
            (source.state.lock().await, destination_state)
        };
    if queue_key_id(&source_state) != source_key
        || queue_key_id(&destination_state) != destination_key
    {
        return MoveOneResult::Waiting;
    }
    if expire_messages(ctx, source, &mut source_state).is_err() {
        return MoveOneResult::Retryable;
    }
    let Some(index) = source_state.messages.iter().position(|message| {
        message.id == snapshot.id
            && message.receipt_handle == snapshot.receipt_handle
            && message.receive_count == snapshot.receive_count
            && message.is_visible(Instant::now())
    }) else {
        return MoveOneResult::Waiting;
    };
    let mut message = source_state.messages[index].clone();
    message.body = if encrypted.is_some() {
        String::new()
    } else {
        plaintext
    };
    message.encrypted_body = encrypted;
    message.receipt_handle = None;
    message.receive_count = 0;
    message.first_receive_ms = None;
    message.visible_at = Instant::now();
    if let Some(db) = ctx.store.persistence() {
        if db
            .move_messages(source, destination, std::slice::from_ref(&message))
            .is_err()
        {
            return MoveOneResult::Retryable;
        }
    }
    source_state.messages.remove(index);
    destination_state.messages.push(message);
    drop(source_state);
    drop(destination_state);
    destination.notify.notify_waiters();
    MoveOneResult::Moved
}

pub async fn start_message_move_task(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let source_arn = str_field(v, "SourceArn")
        .ok_or_else(|| SqsError::InvalidParameterValue("SourceArn is required".into()))?
        .to_string();
    let source_key = arn_from_str(&source_arn).ok_or_else(|| {
        SqsError::InvalidParameterValue("SourceArn must be an SQS queue ARN".into())
    })?;
    if source_key.region != ctx.region || source_key.account != ctx.account {
        return Err(SqsError::InvalidParameterValue(
            "SourceArn must be in the request region and account".into(),
        ));
    }
    let rate = bounded_i64(v, "MaxNumberOfMessagesPerSecond", 500, 1, 500)? as u64;
    let lifecycle = ctx.store.lifecycle_read().await;
    let source = ctx.store.get(&source_key).ok_or_else(|| {
        SqsError::ResourceNotFound(format!("source queue {source_arn} does not exist"))
    })?;
    if ctx.store.has_running_move_task(&source_arn) {
        return Err(SqsError::InvalidParameterValue(
            "a message move task is already running for this source".into(),
        ));
    }

    // Resolve all source queues that currently target this DLQ. An explicit destination
    // must still be one of these sources; arbitrary queue-to-queue draining is rejected.
    let mut sources = Vec::new();
    for candidate in ctx.store.list(ctx.account, ctx.region, None) {
        let state = candidate.state.lock().await;
        if parse_redrive_policy(&state)?.is_some_and(|(dlq, _)| dlq.to_arn() == source_arn) {
            sources.push(candidate.clone());
        }
    }
    let destination = match str_field(v, "DestinationArn") {
        Some(value) => {
            let requested = arn_from_str(value).ok_or_else(|| {
                SqsError::InvalidParameterValue("DestinationArn must be an SQS queue ARN".into())
            })?;
            if !ctx.store.exists(&requested) {
                return Err(SqsError::ResourceNotFound(format!(
                    "destination queue {value} does not exist"
                )));
            }
            sources
                .iter()
                .find(|candidate| candidate.arn == requested)
                .cloned()
                .ok_or_else(|| {
                    SqsError::InvalidParameterValue(
                        "DestinationArn must be a source queue for this dead-letter queue".into(),
                    )
                })?
        }
        None if sources.len() == 1 => sources.remove(0),
        None => {
            return Err(SqsError::InvalidParameterValue(
                "DestinationArn is required when the source has zero or multiple source queues"
                    .into(),
            ))
        }
    };

    if source.arn == destination.arn {
        return Err(SqsError::InvalidParameterValue(
            "source and destination queues must differ".into(),
        ));
    }
    // Destination encryption requires both permissions before a task is created.
    // The worker repeats this check because key policy or queue settings can change.
    let destination_key = {
        let state = destination.state.lock().await;
        queue_key_id(&state)
    };
    if let Some(key) = destination_key.as_deref() {
        authorize_move_destination_key(ctx, key).map_err(public_kms_failure)?;
        // IAM authorization alone cannot establish that the key policy permits
        // SQS. Probe the actual KMS calls before publishing a task handle.
        let probe = encrypt_body(ctx, &destination.arn.to_arn(), key, "").await?;
        decrypt_body(ctx, &probe).await?;
    }
    let messages_to_move = {
        let mut state = source.state.lock().await;
        expire_messages(ctx, &source, &mut state)?;
        state.messages.len() as u64
    };
    let handle = b64().encode(format!("{source_arn}:{}", Uuid::new_v4()));
    ctx.store.insert_move_task(crate::store::MoveTask {
        handle: handle.clone(),
        source_arn,
        destination_arn: Some(destination.arn.to_arn()),
        status: "RUNNING".to_string(),
        messages_moved: 0,
        messages_to_move,
        max_messages_per_second: rate,
        started_ms: now_ms(),
    })?;

    let store = ctx.store.clone();
    let task_handle = handle.clone();
    let region = ctx.region.to_string();
    let account = ctx.account.to_string();
    let request_id = ctx.request_id.to_string();
    let dispatcher = ctx.dispatcher.clone();
    let authorization = ctx.authorization.clone();
    let metrics = ctx.metrics.clone();
    tokio::spawn(async move {
        let _lifecycle = lifecycle;
        let worker_ctx = Ctx {
            store: store.clone(),
            region: &region,
            account: &account,
            request_id: &request_id,
            dispatcher,
            authorization,
            metrics,
        };
        let interval = Duration::from_secs_f64(1.0 / rate as f64);
        let mut retry_delay = Duration::from_millis(100);
        loop {
            if store.move_task_status(&task_handle).as_deref() != Some("RUNNING") {
                return;
            }
            match move_one_message(&worker_ctx, &source, &destination).await {
                MoveOneResult::Moved => {
                    retry_delay = Duration::from_millis(100);
                    if !matches!(store.record_message_moved(&task_handle), Ok(true)) {
                        return;
                    }
                    tokio::time::sleep(interval).await;
                }
                MoveOneResult::Retryable => {
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = retry_delay.saturating_mul(2).min(Duration::from_secs(2));
                }
                MoveOneResult::Blocked => {
                    let _ = store.finish_move_task(&task_handle, "FAILED");
                    return;
                }
                MoveOneResult::Waiting => {
                    tokio::time::sleep(interval.max(Duration::from_millis(100))).await;
                }
                MoveOneResult::Empty => {
                    let _ = store.finish_move_task(&task_handle, "COMPLETED");
                    return;
                }
            }
        }
    });
    Ok(json!({ "TaskHandle": handle }))
}

pub async fn list_message_move_tasks(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let source_arn = req_str(v, "SourceArn")?;
    let source = arn_from_str(source_arn).ok_or_else(|| {
        SqsError::InvalidParameterValue("SourceArn must be an SQS queue ARN".into())
    })?;
    if !ctx.store.exists(&source) {
        return Err(SqsError::ResourceNotFound(format!(
            "source queue {source_arn} does not exist"
        )));
    }
    let max = bounded_i64(v, "MaxResults", 1, 1, 10)? as usize;
    let results: Vec<Value> = ctx
        .store
        .list_move_tasks(source_arn)
        .into_iter()
        .take(max)
        .map(|t| {
            let mut obj = json!({
                "TaskHandle": t.handle,
                "Status": t.status,
                "SourceArn": t.source_arn,
                "ApproximateNumberOfMessagesMoved": t.messages_moved,
                "ApproximateNumberOfMessagesToMove": t.messages_to_move,
                "MaxNumberOfMessagesPerSecond": t.max_messages_per_second,
                "StartedTimestamp": t.started_ms,
            });
            if let Some(dest) = t.destination_arn {
                obj.as_object_mut()
                    .unwrap()
                    .insert("DestinationArn".into(), json!(dest));
            }
            obj
        })
        .collect();
    Ok(json!({ "Results": results }))
}

pub async fn cancel_message_move_task(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SqsError> {
    let handle = req_str(v, "TaskHandle")?;
    match ctx.store.move_task_status(handle).as_deref() {
        None => {
            return Err(SqsError::ResourceNotFound(
                "the specified task handle does not exist".into(),
            ))
        }
        Some("RUNNING") => {}
        Some(_) => {
            return Err(SqsError::InvalidParameterValue(
                "the specified task is not running".into(),
            ))
        }
    }
    let moved = ctx.store.cancel_move_task(handle)?.ok_or_else(|| {
        SqsError::InvalidParameterValue("the specified task is no longer running".into())
    })?;
    Ok(json!({ "ApproximateNumberOfMessagesMoved": moved }))
}
