//! SNS operations. Each returns a [`Reply`] (serialized per protocol by the service) or an
//! [`SnsError`]. Publish performs real fanout through the Core registry.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use uuid::Uuid;

use locallycloud_core::registry::ServiceRegistry;

use crate::digest::sha256_hex;
use crate::error::SnsError;
use crate::fanout::{sqs_target_exists, Delivery, FanoutJob};
use crate::filter;
use crate::model::{Subscription, TopicArn};
use crate::proto::Input;
use crate::reply::{BatchErr, BatchOk, Reply, SubView};
use crate::store::{DedupRecord, InsertResult, SnsStore, TopicState, DEDUP_WINDOW_SECS};

/// Maximum SNS message size in bytes.
const MAX_MESSAGE_SIZE: usize = 262_144;
/// Pagination page size.
const PAGE_SIZE: usize = 100;

const TOPIC_ATTRIBUTES: &[&str] = &[
    "DisplayName",
    "Policy",
    "DeliveryPolicy",
    "FifoTopic",
    "ContentBasedDeduplication",
    "FifoThroughputScope",
    "KmsMasterKeyId",
    "TracingConfig",
    "SignatureVersion",
    "ApplicationSuccessFeedbackRoleArn",
    "ApplicationSuccessFeedbackSampleRate",
    "ApplicationFailureFeedbackRoleArn",
    "FirehoseSuccessFeedbackRoleArn",
    "FirehoseSuccessFeedbackSampleRate",
    "FirehoseFailureFeedbackRoleArn",
    "HTTPSuccessFeedbackRoleArn",
    "HTTPSuccessFeedbackSampleRate",
    "HTTPFailureFeedbackRoleArn",
    "LambdaSuccessFeedbackRoleArn",
    "LambdaSuccessFeedbackSampleRate",
    "LambdaFailureFeedbackRoleArn",
    "SQSSuccessFeedbackRoleArn",
    "SQSSuccessFeedbackSampleRate",
    "SQSFailureFeedbackRoleArn",
];
const SUBSCRIPTION_ATTRIBUTES: &[&str] = &[
    "RawMessageDelivery",
    "FilterPolicy",
    "FilterPolicyScope",
    "RedrivePolicy",
    "DeliveryPolicy",
];

fn validate_topic_name(name: &str) -> Result<(), SnsError> {
    let base = name.strip_suffix(".fifo").unwrap_or(name);
    if name.len() > 256
        || base.is_empty()
        || !base
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(SnsError::InvalidParameter(
            "topic name must be 1-256 characters containing only letters, numbers, hyphens, and underscores (plus .fifo suffix)".into(),
        ));
    }
    Ok(())
}

fn parse_bool(name: &str, value: &str) -> Result<(), SnsError> {
    if value != "true" && value != "false" {
        return Err(SnsError::InvalidParameter(format!(
            "{name} must be true or false"
        )));
    }
    Ok(())
}

fn validate_tags(tags: &[(String, String)]) -> Result<(), SnsError> {
    if tags.len() > 50 {
        return Err(SnsError::InvalidParameter(
            "a topic may have at most 50 tags".into(),
        ));
    }
    let mut keys = std::collections::BTreeSet::new();
    for (key, value) in tags {
        if key.is_empty() || key.len() > 128 || value.len() > 256 || !keys.insert(key) {
            return Err(SnsError::InvalidParameter(
                "invalid or duplicate tag".into(),
            ));
        }
    }
    Ok(())
}

fn validate_topic_attributes(attributes: &BTreeMap<String, String>) -> Result<(), SnsError> {
    for (name, value) in attributes {
        if !TOPIC_ATTRIBUTES.contains(&name.as_str()) {
            return Err(SnsError::InvalidParameter(format!(
                "unknown topic attribute {name}"
            )));
        }
        if matches!(name.as_str(), "DeliveryPolicy" | "Policy")
            && !serde_json::from_str::<serde_json::Value>(value)
                .map(|v| v.is_object())
                .unwrap_or(false)
        {
            return Err(SnsError::InvalidParameter(format!(
                "{name} must be a JSON object"
            )));
        }
        if name.ends_with("SuccessFeedbackSampleRate")
            && value
                .parse::<u8>()
                .ok()
                .filter(|rate| *rate <= 100)
                .is_none()
        {
            return Err(SnsError::InvalidParameter(format!(
                "{name} must be an integer from 0 to 100"
            )));
        }
        match name.as_str() {
            "FifoTopic" | "ContentBasedDeduplication" => parse_bool(name, value)?,
            _ => {}
        }
    }
    Ok(())
}

fn validate_delivery_policy(value: &str) -> Result<(), SnsError> {
    let policy: serde_json::Value = serde_json::from_str(value)
        .map_err(|_| SnsError::InvalidParameter("DeliveryPolicy is not valid JSON".into()))?;
    let root = policy
        .as_object()
        .ok_or_else(|| SnsError::InvalidParameter("DeliveryPolicy must be a JSON object".into()))?;
    if root.keys().any(|key| key != "healthyRetryPolicy") {
        return Err(SnsError::InvalidParameter(
            "DeliveryPolicy contains unsupported fields".into(),
        ));
    }
    let healthy = root
        .get("healthyRetryPolicy")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            SnsError::InvalidParameter("DeliveryPolicy requires healthyRetryPolicy".into())
        })?;
    if healthy
        .keys()
        .any(|key| key != "numRetries" && key != "minDelayTarget")
    {
        return Err(SnsError::InvalidParameter(
            "DeliveryPolicy contains unsupported retry fields".into(),
        ));
    }
    let retries = healthy
        .get("numRetries")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(3);
    let delay = healthy
        .get("minDelayTarget")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if retries > 100 || delay > 3600 {
        return Err(SnsError::InvalidParameter(
            "DeliveryPolicy retry values are out of range".into(),
        ));
    }
    Ok(())
}

fn redrive_target(value: &str) -> Result<String, SnsError> {
    let policy: serde_json::Value = serde_json::from_str(value)
        .map_err(|_| SnsError::InvalidParameter("RedrivePolicy is not valid JSON".into()))?;
    let object = policy
        .as_object()
        .ok_or_else(|| SnsError::InvalidParameter("RedrivePolicy must be a JSON object".into()))?;
    if object.len() != 1 {
        return Err(SnsError::InvalidParameter(
            "RedrivePolicy only supports deadLetterTargetArn".into(),
        ));
    }
    object
        .get("deadLetterTargetArn")
        .and_then(serde_json::Value::as_str)
        .filter(|arn| !arn.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            SnsError::InvalidParameter("RedrivePolicy requires deadLetterTargetArn".into())
        })
}

fn validate_subscription_attributes(
    protocol: &str,
    attributes: &BTreeMap<String, String>,
) -> Result<(), SnsError> {
    for (name, value) in attributes {
        if !SUBSCRIPTION_ATTRIBUTES.contains(&name.as_str()) {
            return Err(SnsError::InvalidParameter(format!(
                "unknown subscription attribute {name}"
            )));
        }
        match name.as_str() {
            "RawMessageDelivery" => {
                parse_bool(name, value)?;
                if value == "true" && !matches!(protocol, "sqs" | "http" | "https") {
                    return Err(SnsError::InvalidParameter(
                        "RawMessageDelivery is not supported for this protocol".into(),
                    ));
                }
            }
            "FilterPolicy" => {
                filter::validate(value)?;
            }
            "FilterPolicyScope" => {
                if value != "MessageAttributes" && value != "MessageBody" {
                    return Err(SnsError::InvalidParameter(
                        "FilterPolicyScope must be MessageAttributes or MessageBody".into(),
                    ));
                }
            }
            "RedrivePolicy" => {
                redrive_target(value)?;
            }
            "DeliveryPolicy" => {
                if !matches!(protocol, "http" | "https") {
                    return Err(SnsError::InvalidParameter(
                        "DeliveryPolicy is only supported for http/https subscriptions".into(),
                    ));
                }
                validate_delivery_policy(value)?;
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}

fn validate_endpoint(protocol: &str, endpoint: &str) -> Result<(), SnsError> {
    if endpoint.is_empty() {
        return Err(SnsError::InvalidParameter("Endpoint is required".into()));
    }
    let valid = match protocol {
        "sqs" => {
            let parts: Vec<&str> = endpoint.split(':').collect();
            parts.len() == 6 && parts[0] == "arn" && parts[2] == "sqs" && !parts[5].is_empty()
        }
        "lambda" => {
            let parts: Vec<&str> = endpoint.split(':').collect();
            parts.len() >= 7
                && parts[0] == "arn"
                && parts[2] == "lambda"
                && parts[5] == "function"
                && !parts[6].is_empty()
        }
        "http" | "https" => reqwest::Url::parse(endpoint)
            .map(|url| url.scheme() == protocol && url.host_str().is_some())
            .unwrap_or(false),
        _ => false,
    };
    if !valid {
        return Err(SnsError::InvalidParameter(format!(
            "Endpoint is invalid for protocol {protocol}"
        )));
    }
    Ok(())
}

pub struct Ctx<'a> {
    pub store: &'a Arc<SnsStore>,
    pub region: &'a str,
    pub account: &'a str,
    pub request_id: &'a str,
}

fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

fn resolve_topic(ctx: &Ctx<'_>, input: &Input) -> Result<Arc<RwLock<TopicState>>, SnsError> {
    let arn_str = input
        .get("TopicArn")
        .or_else(|| input.get("TargetArn"))
        .ok_or_else(|| SnsError::InvalidParameter("TopicArn is required".into()))?;
    let arn = TopicArn::parse(&arn_str)
        .ok_or_else(|| SnsError::InvalidParameter(format!("malformed ARN {arn_str}")))?;
    ctx.store
        .get(&arn)
        .ok_or_else(|| SnsError::NotFound("Topic does not exist".into()))
}

// ============================ topic lifecycle ==================================

pub async fn create_topic(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let name = input.require("Name")?;
    validate_topic_name(&name)?;
    let attributes = input.attributes("Attributes");
    validate_topic_attributes(&attributes)?;
    let tags = input.tags();
    validate_tags(&tags)?;
    let declared_fifo = attributes
        .get("FifoTopic")
        .map(|v| v == "true")
        .unwrap_or(false);
    let name_is_fifo = name.ends_with(".fifo");
    if declared_fifo && !name_is_fifo {
        return Err(SnsError::InvalidParameter(
            "FIFO topic names must end with .fifo".into(),
        ));
    }
    if !name_is_fifo && attributes.contains_key("ContentBasedDeduplication") {
        return Err(SnsError::InvalidParameter(
            "ContentBasedDeduplication is only valid for FIFO topics".into(),
        ));
    }
    let fifo = name_is_fifo || declared_fifo;
    let arn = TopicArn::new(ctx.region, ctx.account, &name);
    let mut stored = attributes;
    if fifo {
        stored
            .entry("FifoTopic".into())
            .or_insert_with(|| "true".into());
        stored
            .entry("ContentBasedDeduplication".into())
            .or_insert_with(|| "false".into());
    }
    let tags: BTreeMap<String, String> = tags.into_iter().collect();
    match ctx
        .store
        .insert(arn.clone(), fifo, stored.clone(), tags.clone())
    {
        InsertResult::Inserted(_) => Ok(Reply::Field("TopicArn", arn.to_arn())),
        InsertResult::Existing(existing) => {
            let state = existing.read().await;
            if state.fifo != fifo || state.attributes != stored || state.tags != tags {
                return Err(SnsError::InvalidParameter(format!(
                    "topic {name} already exists with different attributes or tags"
                )));
            }
            Ok(Reply::Field("TopicArn", arn.to_arn()))
        }
    }
}

pub async fn delete_topic(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let arn_str = input.require("TopicArn")?;
    if let Some(arn) = TopicArn::parse(&arn_str) {
        ctx.store.remove(&arn);
    }
    // Idempotent: deleting a missing topic is success.
    Ok(Reply::Empty)
}

pub async fn list_topics(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let all: Vec<String> = {
        let mut arns = Vec::new();
        for t in ctx.store.list(ctx.account, ctx.region) {
            arns.push(t.read().await.arn.to_arn());
        }
        arns
    };
    let scope = format!("topics:{}:{}", ctx.account, ctx.region);
    let (page, next) = paginate(&all, input.get("NextToken").as_deref(), &scope)?;
    Ok(Reply::Topics { arns: page, next })
}

pub async fn get_topic_attributes(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let topic = resolve_topic(ctx, input)?;
    let state = topic.read().await;
    let mut attrs = state.attributes.clone();
    let confirmed = state.subscriptions.iter().filter(|s| s.confirmed).count();
    let pending = state.subscriptions.iter().filter(|s| !s.confirmed).count();
    attrs.insert("TopicArn".into(), state.arn.to_arn());
    attrs.insert("Owner".into(), ctx.account.to_string());
    attrs.insert("SubscriptionsConfirmed".into(), confirmed.to_string());
    attrs.insert("SubscriptionsPending".into(), pending.to_string());
    attrs.insert("SubscriptionsDeleted".into(), "0".into());
    attrs
        .entry("EffectiveDeliveryPolicy".into())
        .or_insert_with(|| "{\"http\":{\"defaultHealthyRetryPolicy\":{\"numRetries\":3}}}".into());
    attrs
        .entry("Policy".into())
        .or_insert_with(|| default_policy(&state.arn, ctx.account));
    Ok(Reply::Attributes(attrs))
}

fn default_policy(arn: &TopicArn, account: &str) -> String {
    serde_json::json!({
        "Version": "2008-10-17",
        "Id": "__default_policy_ID",
        "Statement": [{
            "Sid": "__default_statement_ID",
            "Effect": "Allow",
            "Principal": { "AWS": "*" },
            "Action": ["SNS:Publish", "SNS:Subscribe"],
            "Resource": arn.to_arn(),
            "Condition": { "StringEquals": { "AWS:SourceOwner": account } }
        }]
    })
    .to_string()
}

pub async fn set_topic_attributes(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let topic = resolve_topic(ctx, input)?;
    let name = input.require("AttributeName")?;
    let value = input.get("AttributeValue").unwrap_or_default();
    if !TOPIC_ATTRIBUTES.contains(&name.as_str()) || name == "FifoTopic" {
        return Err(SnsError::InvalidParameter(format!(
            "topic attribute {name} is not settable"
        )));
    }
    if !value.is_empty() {
        validate_topic_attributes(&BTreeMap::from([(name.clone(), value.clone())]))?;
    }
    let mut state = topic.write().await;
    if name == "ContentBasedDeduplication" && !state.fifo {
        return Err(SnsError::InvalidParameter(
            "ContentBasedDeduplication is only valid for FIFO topics".into(),
        ));
    }
    if value.is_empty() {
        state.attributes.remove(&name);
    } else {
        state.attributes.insert(name, value);
    }
    Ok(Reply::Empty)
}

// ============================ subscriptions ====================================

const PENDING_PROTOCOLS: &[&str] = &["http", "https"];
const SUBSCRIBABLE: &[&str] = &["http", "https", "sqs", "lambda"];

pub async fn subscribe(
    ctx: &Ctx<'_>,
    registry: &ServiceRegistry,
    http: &reqwest::Client,
    input: &Input,
) -> Result<Reply, SnsError> {
    let topic = resolve_topic(ctx, input)?;
    let protocol = input.require("Protocol")?.to_ascii_lowercase();
    if !SUBSCRIBABLE.contains(&protocol.as_str()) {
        return Err(SnsError::UnsupportedOperation(format!(
            "protocol {protocol} has no local delivery backend"
        )));
    }
    let endpoint = input.require("Endpoint")?;
    validate_endpoint(&protocol, &endpoint)?;
    let provided = input.attributes("Attributes");
    validate_subscription_attributes(&protocol, &provided)?;
    let return_real = input
        .get("ReturnSubscriptionArn")
        .map(|v| v == "true")
        .unwrap_or(false);

    if protocol == "sqs" {
        // Subscribe validates the endpoint ARN; queue delivery permissions do not grant
        // SNS GetQueueAttributes and cannot establish whether the queue exists.
        let parts: Vec<_> = endpoint.split(':').collect();
        if parts[3] != ctx.region || parts[4] != ctx.account {
            return Err(SnsError::InvalidParameter(
                "SQS subscription endpoints currently require the same region and account".into(),
            ));
        }
    }
    if let Some(redrive) = provided.get("RedrivePolicy") {
        let target = redrive_target(redrive)?;
        if !sqs_target_exists(registry, &target, ctx.region, ctx.account, ctx.request_id).await {
            return Err(SnsError::InvalidParameter(
                "RedrivePolicy target must be an existing SQS queue in the same region and account"
                    .into(),
            ));
        }
    }

    let mut state = topic.write().await;
    if state.fifo {
        if protocol != "sqs" {
            return Err(SnsError::InvalidParameter(
                "FIFO topics only support the sqs protocol".into(),
            ));
        }
        if !endpoint.ends_with(".fifo") {
            return Err(SnsError::InvalidParameter(
                "FIFO topics require an SQS FIFO queue endpoint".into(),
            ));
        }
    }

    // Duplicate (same protocol + endpoint) returns the existing subscription.
    if let Some(existing) = state
        .subscriptions
        .iter()
        .find(|s| s.protocol == protocol && s.endpoint == endpoint)
    {
        return Ok(Reply::Field(
            "SubscriptionArn",
            existing.reported_arn(return_real),
        ));
    }

    let confirmed = !PENDING_PROTOCOLS.contains(&protocol.as_str());
    let pending_token = if confirmed {
        None
    } else {
        Some(Uuid::new_v4().simple().to_string())
    };
    let arn = format!("{}:{}", state.arn.to_arn(), Uuid::new_v4());

    let sub = Subscription {
        arn: arn.clone(),
        topic_arn: state.arn.to_arn(),
        protocol: protocol.clone(),
        endpoint: endpoint.clone(),
        owner: ctx.account.to_string(),
        confirmed,
        pending_token: pending_token.clone(),
        attributes: provided,
    };
    let reported = sub.reported_arn(return_real);
    let topic_arn = state.arn.to_arn();
    state.subscriptions.push(sub);
    drop(state);

    // An http/https subscription is pending until confirmed: POST the confirmation message so
    // the subscriber can confirm via the SubscribeURL (best-effort; never fails Subscribe).
    if (protocol == "http" || protocol == "https") && !endpoint.is_empty() {
        if let Some(token) = pending_token {
            crate::fanout::send_confirmation(http, &endpoint, &topic_arn, &token, ctx.request_id)
                .await;
        }
    }
    Ok(Reply::Field("SubscriptionArn", reported))
}

pub async fn confirm_subscription(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let topic = resolve_topic(ctx, input)?;
    let token = input.require("Token")?;
    let mut state = topic.write().await;
    let sub = state
        .subscriptions
        .iter_mut()
        .find(|s| s.pending_token.as_deref() == Some(token.as_str()))
        .ok_or_else(|| SnsError::AuthorizationError("invalid confirmation token".into()))?;
    sub.confirmed = true;
    sub.pending_token = None;
    Ok(Reply::Field("SubscriptionArn", sub.arn.clone()))
}

pub async fn unsubscribe(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let sub_arn = input.require("SubscriptionArn")?;
    let topic = topic_of_subscription(ctx, &sub_arn)?;
    let mut state = topic.write().await;
    let before = state.subscriptions.len();
    state.subscriptions.retain(|s| s.arn != sub_arn);
    if state.subscriptions.len() == before {
        return Err(SnsError::NotFound("Subscription does not exist".into()));
    }
    Ok(Reply::Empty)
}

fn topic_of_subscription(
    ctx: &Ctx<'_>,
    sub_arn: &str,
) -> Result<Arc<RwLock<TopicState>>, SnsError> {
    let (topic_arn, _) = sub_arn
        .rsplit_once(':')
        .ok_or_else(|| SnsError::InvalidParameter("malformed subscription ARN".into()))?;
    let arn = TopicArn::parse(topic_arn)
        .ok_or_else(|| SnsError::InvalidParameter("malformed subscription ARN".into()))?;
    ctx.store
        .get(&arn)
        .ok_or_else(|| SnsError::NotFound("Subscription does not exist".into()))
}

fn sub_view(s: &Subscription) -> SubView {
    SubView {
        arn: if s.confirmed {
            s.arn.clone()
        } else {
            "PendingConfirmation".to_string()
        },
        owner: s.owner.clone(),
        protocol: s.protocol.clone(),
        endpoint: s.endpoint.clone(),
        topic_arn: s.topic_arn.clone(),
    }
}

pub async fn list_subscriptions(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let mut all = Vec::new();
    for t in ctx.store.list(ctx.account, ctx.region) {
        for s in &t.read().await.subscriptions {
            all.push(sub_view(s));
        }
    }
    let scope = format!("subscriptions:{}:{}", ctx.account, ctx.region);
    let (page, next) = paginate(&all, input.get("NextToken").as_deref(), &scope)?;
    Ok(Reply::Subscriptions { subs: page, next })
}

pub async fn list_subscriptions_by_topic(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let topic = resolve_topic(ctx, input)?;
    let subs: Vec<SubView> = topic
        .read()
        .await
        .subscriptions
        .iter()
        .map(sub_view)
        .collect();
    let scope = format!(
        "topic-subscriptions:{}:{}",
        ctx.account,
        input.require("TopicArn")?
    );
    let (page, next) = paginate(&subs, input.get("NextToken").as_deref(), &scope)?;
    Ok(Reply::Subscriptions { subs: page, next })
}

pub async fn get_subscription_attributes(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let sub_arn = input.require("SubscriptionArn")?;
    let topic = topic_of_subscription(ctx, &sub_arn)?;
    let state = topic.read().await;
    let sub = state
        .subscriptions
        .iter()
        .find(|s| s.arn == sub_arn)
        .ok_or_else(|| SnsError::NotFound("Subscription does not exist".into()))?;
    let mut attrs = sub.attributes.clone();
    attrs.insert("SubscriptionArn".into(), sub.arn.clone());
    attrs.insert("TopicArn".into(), sub.topic_arn.clone());
    attrs.insert("Protocol".into(), sub.protocol.clone());
    attrs.insert("Endpoint".into(), sub.endpoint.clone());
    attrs.insert("Owner".into(), sub.owner.clone());
    attrs.insert(
        "ConfirmationWasAuthenticated".into(),
        sub.confirmed.to_string(),
    );
    attrs
        .entry("RawMessageDelivery".into())
        .or_insert_with(|| "false".into());
    attrs
        .entry("FilterPolicyScope".into())
        .or_insert_with(|| "MessageAttributes".into());
    attrs.insert("PendingConfirmation".into(), (!sub.confirmed).to_string());
    Ok(Reply::Attributes(attrs))
}

pub async fn set_subscription_attributes(
    ctx: &Ctx<'_>,
    registry: &ServiceRegistry,
    input: &Input,
) -> Result<Reply, SnsError> {
    let sub_arn = input.require("SubscriptionArn")?;
    let name = input.require("AttributeName")?;
    let value = input.get("AttributeValue").unwrap_or_default();
    if !SUBSCRIPTION_ATTRIBUTES.contains(&name.as_str()) {
        return Err(SnsError::InvalidParameter(format!(
            "unknown subscription attribute {name}"
        )));
    }
    let topic = topic_of_subscription(ctx, &sub_arn)?;
    let (protocol, mut attributes) = {
        let state = topic.read().await;
        let sub = state
            .subscriptions
            .iter()
            .find(|s| s.arn == sub_arn)
            .ok_or_else(|| SnsError::NotFound("Subscription does not exist".into()))?;
        (sub.protocol.clone(), sub.attributes.clone())
    };
    if value.is_empty() {
        attributes.remove(&name);
    } else {
        attributes.insert(name.clone(), value.clone());
    }
    validate_subscription_attributes(&protocol, &attributes)?;
    if name == "RedrivePolicy" && !value.is_empty() {
        let target = redrive_target(&value)?;
        if !sqs_target_exists(registry, &target, ctx.region, ctx.account, ctx.request_id).await {
            return Err(SnsError::InvalidParameter(
                "RedrivePolicy target must be an existing SQS queue in the same region and account"
                    .into(),
            ));
        }
    }
    let mut state = topic.write().await;
    let sub = state
        .subscriptions
        .iter_mut()
        .find(|s| s.arn == sub_arn)
        .ok_or_else(|| SnsError::NotFound("Subscription does not exist".into()))?;
    sub.attributes = attributes;
    Ok(Reply::Empty)
}

// ============================ tagging ==========================================

pub async fn tag_resource(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let topic = resolve_topic_by_field(ctx, input, "ResourceArn")?;
    let tags = input.tags();
    validate_tags(&tags)?;
    let mut state = topic.write().await;
    let resulting = state.tags.len()
        + tags
            .iter()
            .filter(|(key, _)| !state.tags.contains_key(key))
            .count();
    if resulting > 50 {
        return Err(SnsError::InvalidParameter(
            "a topic may have at most 50 tags".into(),
        ));
    }
    for (k, v) in tags {
        state.tags.insert(k, v);
    }
    Ok(Reply::Empty)
}

pub async fn untag_resource(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let topic = resolve_topic_by_field(ctx, input, "ResourceArn")?;
    let keys = input.tag_keys();
    let mut state = topic.write().await;
    state.tags.retain(|k, _| !keys.contains(k));
    Ok(Reply::Empty)
}

pub async fn list_tags_for_resource(ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
    let topic = resolve_topic_by_field(ctx, input, "ResourceArn")?;
    let tags: Vec<(String, String)> = topic
        .read()
        .await
        .tags
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Ok(Reply::Tags(tags))
}

fn resolve_topic_by_field(
    ctx: &Ctx<'_>,
    input: &Input,
    field: &str,
) -> Result<Arc<RwLock<TopicState>>, SnsError> {
    let arn_str = input.require(field)?;
    let arn = TopicArn::parse(&arn_str)
        .ok_or_else(|| SnsError::InvalidParameter(format!("malformed ARN {arn_str}")))?;
    ctx.store
        .get(&arn)
        .ok_or_else(|| SnsError::NotFound("Resource does not exist".into()))
}

/// Opaque, scope-bound pagination over a stable sorted snapshot.
fn paginate<T: Clone>(
    items: &[T],
    token: Option<&str>,
    scope: &str,
) -> Result<(Vec<T>, Option<String>), SnsError> {
    let start = match token {
        None => 0,
        Some(token) => {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .ok_or_else(|| SnsError::InvalidParameter("invalid NextToken".into()))?;
            let (token_scope, offset) = decoded
                .rsplit_once('|')
                .ok_or_else(|| SnsError::InvalidParameter("invalid NextToken".into()))?;
            if token_scope != scope {
                return Err(SnsError::InvalidParameter(
                    "NextToken does not belong to this listing".into(),
                ));
            }
            offset
                .parse::<usize>()
                .ok()
                .filter(|offset| *offset <= items.len())
                .ok_or_else(|| SnsError::InvalidParameter("invalid NextToken".into()))?
        }
    };
    let end = (start + PAGE_SIZE).min(items.len());
    let page = items.get(start..end).map(<[T]>::to_vec).unwrap_or_default();
    let next = if end < items.len() {
        Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{scope}|{end}")))
    } else {
        None
    };
    Ok((page, next))
}

// ============================ publish ==========================================

/// Validate, apply FIFO dedup/sequencing, snapshot subscriptions, and fan out one message.
/// Returns `(message_id, sequence_number)`.
async fn do_publish(
    ctx: &Ctx<'_>,
    registry: &Arc<ServiceRegistry>,
    http: &reqwest::Client,
    topic: &Arc<RwLock<TopicState>>,
    input: &Input,
) -> Result<(String, Option<String>), SnsError> {
    let message = input.require("Message")?;
    if message.is_empty() {
        return Err(SnsError::InvalidParameter(
            "Message must not be empty".into(),
        ));
    }
    let subject = input.get("Subject");
    let attributes = input.message_attributes()?;

    // Size validation (body + subject + attributes).
    let mut size = message.len() + subject.as_ref().map(String::len).unwrap_or(0);
    for (name, a) in &attributes {
        size += name.len() + a.data_type.len();
        size += match &a.value {
            crate::model::AttributeValue::String(s) => s.len(),
            crate::model::AttributeValue::Binary(b) => b.len(),
        };
    }
    if size > MAX_MESSAGE_SIZE {
        return Err(SnsError::InvalidParameter(format!(
            "message size {size} exceeds the maximum {MAX_MESSAGE_SIZE}"
        )));
    }

    // Message structure (`json` requires a `default` member).
    let structure = match input.get("MessageStructure").as_deref() {
        Some("json") => {
            let parsed: serde_json::Value = serde_json::from_str(&message).map_err(|_| {
                SnsError::InvalidParameter(
                    "Message must be valid JSON for MessageStructure=json".into(),
                )
            })?;
            let obj = parsed.as_object().ok_or_else(|| {
                SnsError::InvalidParameter("Message must be a JSON object".into())
            })?;
            if !obj.contains_key("default") {
                return Err(SnsError::InvalidParameter(
                    "JSON message requires a 'default' key".into(),
                ));
            }
            Some(obj.clone())
        }
        Some(other) => {
            return Err(SnsError::InvalidParameter(format!(
                "invalid MessageStructure {other}"
            )))
        }
        None => None,
    };

    let group_id = input.get("MessageGroupId");
    let mut dedup_id = input.get("MessageDeduplicationId");
    let message_id = Uuid::new_v4().to_string();
    let timestamp = now_iso();

    let mut state = topic.write().await;
    if state.fifo {
        let Some(group_id_value) = group_id.as_deref() else {
            return Err(SnsError::InvalidParameter(
                "MessageGroupId is required for FIFO topics".into(),
            ));
        };
        let effective = match &dedup_id {
            Some(value) if !value.is_empty() => value.clone(),
            Some(_) => {
                return Err(SnsError::InvalidParameter(
                    "MessageDeduplicationId must not be empty".into(),
                ))
            }
            None if state.content_based_dedup() => sha256_hex(&message),
            None => return Err(SnsError::InvalidParameter(
                "MessageDeduplicationId is required unless ContentBasedDeduplication is enabled"
                    .into(),
            )),
        };
        dedup_id = Some(effective.clone());
        let now = Instant::now();
        state.dedup.retain(|_, record| {
            now.duration_since(record.inserted_at).as_secs() < DEDUP_WINDOW_SECS
        });
        if let Some(original) = state.dedup.get(&effective) {
            return Ok((
                original.message_id.clone(),
                Some(original.sequence_number.clone()),
            ));
        }
        let previous_sequence = state.sequence;
        let previous_dedup = state.dedup.clone();
        state.sequence += 1;
        let sequence_number = state.sequence.to_string();
        state.dedup.insert(
            effective,
            DedupRecord {
                inserted_at: now,
                message_id: message_id.clone(),
                sequence_number: sequence_number.clone(),
            },
        );
        let mut job = FanoutJob {
            outbox_id: None,
            subscriptions: state.subscriptions.clone(),
            delivery: Delivery {
                message_id: message_id.clone(),
                topic_arn: state.arn.to_arn(),
                message: message.clone(),
                structure,
                subject,
                timestamp,
                attributes,
                group_id: Some(group_id_value.to_string()),
                dedup_id,
                region: ctx.region.to_string(),
                account: ctx.account.to_string(),
                request_id: ctx.request_id.to_string(),
            },
        };
        match ctx.store.accept_job(&state, &job) {
            Ok(id) => job.outbox_id = id,
            Err(error) => {
                state.sequence = previous_sequence;
                state.dedup = previous_dedup;
                return Err(error);
            }
        }
        if state.fifo_delivery.is_none() {
            let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
            let worker_registry = registry.clone();
            let worker_http = http.clone();
            let worker_store = ctx.store.clone();
            std::mem::drop(tokio::spawn(async move {
                while let Some(job) = receiver.recv().await {
                    crate::fanout::deliver_accepted(
                        worker_registry.clone(),
                        worker_http.clone(),
                        worker_store.clone(),
                        job,
                    )
                    .await;
                }
            }));
            state.fifo_delivery = Some(sender);
        }
        let sent = state
            .fifo_delivery
            .as_ref()
            .is_some_and(|sender| sender.send(job).is_ok());
        if !sent {
            return Err(SnsError::InternalError);
        }
        return Ok((message_id, Some(sequence_number)));
    }

    if group_id.is_some() || dedup_id.is_some() {
        return Err(SnsError::InvalidParameter(
            "MessageGroupId/MessageDeduplicationId are only valid for FIFO topics".into(),
        ));
    }
    let mut job = FanoutJob {
        outbox_id: None,
        subscriptions: state.subscriptions.clone(),
        delivery: Delivery {
            message_id: message_id.clone(),
            topic_arn: state.arn.to_arn(),
            message,
            structure,
            subject,
            timestamp,
            attributes,
            group_id: None,
            dedup_id: None,
            region: ctx.region.to_string(),
            account: ctx.account.to_string(),
            request_id: ctx.request_id.to_string(),
        },
    };
    job.outbox_id = ctx.store.accept_job(&state, &job)?;
    drop(state);
    std::mem::drop(tokio::spawn(crate::fanout::deliver_accepted(
        registry.clone(),
        http.clone(),
        ctx.store.clone(),
        job,
    )));
    Ok((message_id, None))
}

pub async fn publish(
    ctx: &Ctx<'_>,
    registry: &Arc<ServiceRegistry>,
    http: &reqwest::Client,
    input: &Input,
) -> Result<Reply, SnsError> {
    // Direct SMS has no data plane in locallycloud and must not report a false success.
    if input.get("TopicArn").is_none() && input.get("TargetArn").is_none() {
        if input.get("PhoneNumber").is_some() {
            return Err(SnsError::UnsupportedOperation(
                "direct SMS publish is not supported because no SMS delivery backend is available"
                    .into(),
            ));
        }
        return Err(SnsError::InvalidParameter(
            "TopicArn or TargetArn is required".into(),
        ));
    }
    let topic = resolve_topic(ctx, input)?;
    let (message_id, sequence_number) = do_publish(ctx, registry, http, &topic, input).await?;
    Ok(Reply::Publish {
        message_id,
        sequence_number,
    })
}

pub async fn publish_batch(
    ctx: &Ctx<'_>,
    registry: &Arc<ServiceRegistry>,
    http: &reqwest::Client,
    input: &Input,
) -> Result<Reply, SnsError> {
    let topic = resolve_topic(ctx, input)?;
    let entries = input.batch_entries("PublishBatchRequestEntries");
    if entries.is_empty() {
        return Err(SnsError::EmptyBatchRequest);
    }
    if entries.len() > 10 {
        return Err(SnsError::TooManyEntriesInBatchRequest);
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut aggregate_size = 0usize;
    for entry in &entries {
        let id = entry
            .get("Id")
            .ok_or_else(|| SnsError::InvalidParameter("entry missing Id".into()))?;
        if id.len() > 80
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(SnsError::InvalidParameter(format!(
                "invalid batch entry Id {id}"
            )));
        }
        if !ids.insert(id) {
            return Err(SnsError::BatchEntryIdsNotDistinct);
        }
        aggregate_size += entry.get("Message").map_or(0, |value| value.len());
        aggregate_size += entry.get("Subject").map_or(0, |value| value.len());
    }
    if aggregate_size > MAX_MESSAGE_SIZE {
        return Err(SnsError::BatchRequestTooLong);
    }

    let mut successful = Vec::new();
    let mut failed = Vec::new();
    for e in &entries {
        let id = e.get("Id").unwrap_or_default();
        match do_publish(ctx, registry, http, &topic, e).await {
            Ok((message_id, sequence_number)) => successful.push(BatchOk {
                id,
                message_id,
                sequence_number,
            }),
            Err(err) => failed.push(BatchErr {
                id,
                code: err.code().to_string(),
                message: err.to_string(),
            }),
        }
    }
    Ok(Reply::PublishBatch { successful, failed })
}
