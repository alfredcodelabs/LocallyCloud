use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};

use http::Method;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use uuid::Uuid;

use locallycloud_core::integration::correlation::CorrelationContext;
use locallycloud_core::integration::identity::CallerIdentity;
use locallycloud_core::integration::logs::{
    LogScope, ProducerContext, ProducerGroupSpec, SinkError,
};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};

use crate::arn::EbArn;
use crate::delivery::{self, DeliveryRequest};
use crate::error::EventsError;
use crate::http_client::{form_encode, HttpClient, HttpError, HttpRequest};
use crate::model::{
    ApiDestination, Archive, ArchivedEvent, Connection, EventBus, Replay, RetryPolicy, Rule, Target,
};
use crate::pattern;
use crate::schedule::{self, Clock};
use crate::schemas;
use crate::store::{EbStore, PendingFanout};
use crate::transform::{self, Context, InputMode};

#[derive(Clone)]
pub struct RequestContext<'a> {
    pub account: &'a str,
    pub region: &'a str,
    pub request_id: &'a str,
}

pub struct EventsService {
    pub store: Arc<EbStore>,
    registry: Weak<ServiceRegistry>,
    clock: Arc<dyn Clock>,
    http: Arc<dyn HttpClient>,
    workers: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    active_fanouts: Arc<Mutex<HashSet<String>>>,
    control_plane_gate: tokio::sync::RwLock<()>,
}

struct ActiveFanout {
    id: String,
    active: Arc<Mutex<HashSet<String>>>,
}

impl Drop for ActiveFanout {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(&self.id);
        }
    }
}

impl EventsService {
    pub fn new(
        store: Arc<EbStore>,
        registry: Weak<ServiceRegistry>,
        clock: Arc<dyn Clock>,
        http: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            store,
            registry,
            clock,
            http,
            workers: Arc::new(Mutex::new(HashMap::new())),
            active_fanouts: Arc::new(Mutex::new(HashSet::new())),
            control_plane_gate: tokio::sync::RwLock::new(()),
        }
    }

    pub async fn dispatch(
        &self,
        operation: &str,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let mutation = durable_bus_mutation(operation);
        let _write = if mutation {
            Some(self.control_plane_gate.write().await)
        } else {
            None
        };
        let _read = if !mutation {
            Some(self.control_plane_gate.read().await)
        } else {
            None
        };
        self.reap_finished_workers();
        if !self.store.healthy() {
            return Err(EventsError::Internal(
                "durable EventBridge state is unavailable".into(),
            ));
        }
        let result = match operation {
            "CreateEventBus" => self.create_event_bus(ctx, body).await,
            "DeleteEventBus" => self.delete_event_bus(ctx, body).await,
            "DescribeEventBus" => self.describe_event_bus(ctx, body).await,
            "UpdateEventBus" => self.update_event_bus(ctx, body).await,
            "ListEventBuses" => self.list_event_buses(ctx, body).await,
            "PutPermission" => self.put_permission(ctx, body).await,
            "RemovePermission" => self.remove_permission(ctx, body).await,
            "PutRule" => self.put_rule(ctx, body).await,
            "DeleteRule" => self.delete_rule(ctx, body).await,
            "DescribeRule" => self.describe_rule(ctx, body).await,
            "ListRules" => self.list_rules(ctx, body).await,
            "ListRuleNamesByTarget" => self.list_rule_names_by_target(ctx, body).await,
            "EnableRule" => self.set_rule_state(ctx, body, "ENABLED").await,
            "DisableRule" => self.set_rule_state(ctx, body, "DISABLED").await,
            "PutTargets" => self.put_targets(ctx, body).await,
            "RemoveTargets" => self.remove_targets(ctx, body).await,
            "ListTargetsByRule" => self.list_targets(ctx, body).await,
            "PutEvents" => self.put_events(ctx, body, false).await,
            "PutPartnerEvents" => self.put_events(ctx, body, true).await,
            "TestEventPattern" => test_event_pattern(body),
            "TagResource" => self.tag_resource(ctx, body).await,
            "UntagResource" => self.untag_resource(ctx, body).await,
            "ListTagsForResource" => self.list_tags(ctx, body).await,
            "CreateArchive" => self.create_archive(ctx, body).await,
            "DescribeArchive" => self.describe_archive(ctx, body).await,
            "UpdateArchive" => self.update_archive(ctx, body).await,
            "DeleteArchive" => self.delete_archive(ctx, body).await,
            "ListArchives" => self.list_archives(ctx, body).await,
            "StartReplay" => self.start_replay(ctx, body).await,
            "DescribeReplay" => self.describe_replay(ctx, body).await,
            "CancelReplay" => self.cancel_replay(ctx, body).await,
            "ListReplays" => self.list_replays(ctx, body).await,
            "CreateConnection" => self.create_connection(ctx, body).await,
            "UpdateConnection" => self.update_connection(ctx, body).await,
            "ListConnections" => self.list_connections(ctx, body).await,
            "DescribeConnection" => self.describe_connection(ctx, body).await,
            "DeleteConnection" => self.delete_connection(ctx, body).await,
            "CreateApiDestination" => self.create_api_destination(ctx, body).await,
            "UpdateApiDestination" => self.update_api_destination(ctx, body).await,
            "ListApiDestinations" => self.list_api_destinations(ctx, body).await,
            "DescribeApiDestination" => self.describe_api_destination(ctx, body).await,
            "DeleteApiDestination" => self.delete_api_destination(ctx, body).await,
            other => Err(EventsError::UnknownOperation(format!(
                "unsupported operation {other}"
            ))),
        }?;
        if mutation {
            self.store
                .persist_buses_at(ctx.account, ctx.region, self.clock.now())
                .await
                .map_err(EventsError::Internal)?;
        }
        self.reconcile_worker(operation, ctx, body).await;
        self.reap_finished_workers();
        Ok(result)
    }
}

fn durable_bus_mutation(operation: &str) -> bool {
    matches!(
        operation,
        "CreateEventBus"
            | "DeleteEventBus"
            | "UpdateEventBus"
            | "PutPermission"
            | "RemovePermission"
            | "PutRule"
            | "DeleteRule"
            | "EnableRule"
            | "DisableRule"
            | "PutTargets"
            | "RemoveTargets"
            | "TagResource"
            | "UntagResource"
            | "CreateConnection"
            | "UpdateConnection"
            | "DeleteConnection"
            | "CreateApiDestination"
            | "UpdateApiDestination"
            | "DeleteApiDestination"
            | "CreateArchive"
            | "UpdateArchive"
            | "DeleteArchive"
            | "StartReplay"
            | "CancelReplay"
    )
}

impl Drop for EventsService {
    fn drop(&mut self) {
        if let Ok(mut workers) = self.workers.lock() {
            for (_, worker) in workers.drain() {
                worker.abort();
            }
        }
    }
}

fn required<'a>(body: &'a Value, key: &str) -> Result<&'a str, EventsError> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| EventsError::Validation(format!("{key} is required")))
}

fn optional(body: &Value, key: &str) -> Option<String> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn event_bus_name_or_arn(value: &str) -> &str {
    value
        .split_once(":event-bus/")
        .map(|(_, name)| name)
        .unwrap_or(value)
}

fn bus_name(body: &Value) -> String {
    optional(body, "EventBusName")
        .map(|value| event_bus_name_or_arn(&value).to_string())
        .unwrap_or_else(|| "default".into())
}

fn tags(body: &Value) -> BTreeMap<String, String> {
    body.get("Tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tag| {
            Some((
                tag.get("Key")?.as_str()?.to_string(),
                tag.get("Value")?.as_str()?.to_string(),
            ))
        })
        .collect()
}

fn retention_days(body: &Value) -> Result<Option<i64>, EventsError> {
    let Some(value) = body.get("RetentionDays") else {
        return Ok(None);
    };
    let days = value
        .as_i64()
        .ok_or_else(|| EventsError::Validation("RetentionDays must be an integer".into()))?;
    if days < 0 {
        return Err(EventsError::Validation(
            "RetentionDays must be greater than or equal to 0".into(),
        ));
    }
    Ok(Some(days))
}

fn prune_archive(archive: &mut Archive, now: OffsetDateTime) {
    if archive.retention_days == 0 {
        return;
    }
    let retention = time::Duration::seconds(archive.retention_days.saturating_mul(86_400));
    let Some(cutoff) = now.checked_sub(retention) else {
        return;
    };
    archive.events.retain(|event| event.time >= cutoff);
}

fn paginated_response(
    body: &Value,
    result_key: &str,
    values: Vec<Value>,
    limit_key: &str,
) -> Result<Value, EventsError> {
    let start = match body.get("NextToken") {
        None => 0,
        Some(Value::String(token)) if !token.is_empty() => token
            .parse::<usize>()
            .map_err(|_| EventsError::Validation("NextToken is invalid".into()))?,
        _ => return Err(EventsError::Validation("NextToken is invalid".into())),
    };
    let limit = match body.get(limit_key) {
        None => 100,
        Some(value) => {
            let value = value
                .as_u64()
                .filter(|value| (1..=100).contains(value))
                .ok_or_else(|| {
                    EventsError::Validation(format!("{limit_key} must be between 1 and 100"))
                })?;
            value as usize
        }
    };
    let total = values.len();
    if start > total {
        return Err(EventsError::Validation("NextToken is invalid".into()));
    }
    let end = start.saturating_add(limit).min(total);
    let page = values.into_iter().skip(start).take(end - start).collect();
    let mut response = serde_json::Map::new();
    response.insert(result_key.into(), Value::Array(page));
    if end < total {
        response.insert("NextToken".into(), Value::String(end.to_string()));
    }
    Ok(Value::Object(response))
}
impl EventsService {
    async fn create_event_bus(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let requested = required(body, "Name")?;
        let name = requested.to_string();
        let source = optional(body, "EventSourceName");
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        if state.buses.contains_key(&name) {
            return Err(EventsError::ResourceAlreadyExists(format!(
                "Event bus {name} already exists"
            )));
        }
        let arn = EbArn::EventBus {
            region: ctx.region.into(),
            account: ctx.account.into(),
            name: name.clone(),
        }
        .to_string();
        state.buses.insert(
            name.clone(),
            EventBus {
                name,
                arn: arn.clone(),
                description: optional(body, "Description"),
                event_source_name: source,
                policy: None,
                kms_key_identifier: optional(body, "KmsKeyIdentifier"),
                dead_letter_config: body.get("DeadLetterConfig").cloned(),
                log_config: body.get("LogConfig").cloned(),
                rules: BTreeMap::new(),
                tags: tags(body),
            },
        );
        Ok(json!({"EventBusArn": arn}))
    }

    async fn delete_event_bus(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = event_bus_name_or_arn(required(body, "Name")?);
        if name == "default" {
            return Err(EventsError::Validation(
                "the default event bus cannot be deleted".into(),
            ));
        }
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let bus = state.buses.get(name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Event bus {name} does not exist"))
        })?;
        let arn = bus.arn.clone();
        if state
            .archives
            .values()
            .any(|archive| archive.source_arn == arn)
            || state.replays.values().any(|replay| {
                replay.state == "RUNNING"
                    && replay.destination.get("Arn").and_then(Value::as_str) == Some(arn.as_str())
            })
        {
            return Err(EventsError::ConcurrentModification(
                "delete dependent archives and finish replays before deleting the event bus".into(),
            ));
        }
        state.buses.remove(name);
        drop(state);
        self.abort_prefix(&format!("{}:{}:{name}:", ctx.account, ctx.region));
        Ok(json!({}))
    }

    async fn describe_event_bus(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = optional(body, "Name").unwrap_or_else(|| "default".into());
        let name = event_bus_name_or_arn(&name);
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let bus = state.buses.get(name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Event bus {name} does not exist"))
        })?;
        let mut out = json!({"Name": bus.name, "Arn": bus.arn});
        insert_opt(
            &mut out,
            "Description",
            bus.description.clone().map(Value::String),
        );
        insert_opt(
            &mut out,
            "Policy",
            bus.policy.as_ref().map(Value::to_string).map(Value::String),
        );
        insert_opt(
            &mut out,
            "KmsKeyIdentifier",
            bus.kms_key_identifier.clone().map(Value::String),
        );
        insert_opt(&mut out, "DeadLetterConfig", bus.dead_letter_config.clone());
        insert_opt(&mut out, "LogConfig", bus.log_config.clone());
        Ok(out)
    }

    async fn update_event_bus(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = optional(body, "Name").unwrap_or_else(|| "default".into());
        let name = event_bus_name_or_arn(&name);
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let bus = state.buses.get_mut(name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Event bus {name} does not exist"))
        })?;
        if body.get("Description").is_some() {
            bus.description = optional(body, "Description");
        }
        if body.get("KmsKeyIdentifier").is_some() {
            bus.kms_key_identifier = optional(body, "KmsKeyIdentifier");
        }
        if body.get("DeadLetterConfig").is_some() {
            bus.dead_letter_config = body
                .get("DeadLetterConfig")
                .filter(|value| !value.is_null())
                .cloned();
        }
        if body.get("LogConfig").is_some() {
            bus.log_config = body
                .get("LogConfig")
                .filter(|value| !value.is_null())
                .cloned();
        }
        Ok(json!({"Arn": bus.arn, "Name": bus.name}))
    }

    async fn list_event_buses(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let prefix = optional(body, "NamePrefix").unwrap_or_default();
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let buses: Vec<_> = state
            .buses
            .values()
            .filter(|bus| bus.name.starts_with(&prefix))
            .map(|bus| json!({"Name":bus.name,"Arn":bus.arn,"Description":bus.description}))
            .collect();
        paginated_response(body, "EventBuses", buses, "Limit")
    }

    async fn put_permission(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = bus_name(body);
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let bus = state.buses.get_mut(&name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Event bus {name} does not exist"))
        })?;
        if let Some(raw) = optional(body, "Policy") {
            bus.policy = Some(
                serde_json::from_str(&raw)
                    .map_err(|_| EventsError::Validation("Policy must be valid JSON".into()))?,
            );
            return Ok(json!({}));
        }
        let sid = required(body, "StatementId")?;
        let action = required(body, "Action")?;
        let principal = required(body, "Principal")?;
        let policy = bus
            .policy
            .get_or_insert_with(|| json!({"Version":"2012-10-17","Statement":[]}));
        let statements = policy
            .get_mut("Statement")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| EventsError::Validation("stored policy is invalid".into()))?;
        statements.retain(|statement| statement.get("Sid").and_then(Value::as_str) != Some(sid));
        statements.push(json!({"Sid":sid,"Effect":"Allow","Principal":{"AWS":principal},"Action":action,"Resource":bus.arn}));
        Ok(json!({}))
    }

    async fn remove_permission(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = bus_name(body);
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let bus = state.buses.get_mut(&name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Event bus {name} does not exist"))
        })?;
        if body
            .get("RemoveAllPermissions")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            bus.policy = None;
            return Ok(json!({}));
        }
        let sid = required(body, "StatementId")?;
        let statements = bus
            .policy
            .as_mut()
            .and_then(|p| p.get_mut("Statement"))
            .and_then(Value::as_array_mut)
            .ok_or_else(|| {
                EventsError::ResourceNotFound(format!("Statement {sid} does not exist"))
            })?;
        let before = statements.len();
        statements.retain(|statement| statement.get("Sid").and_then(Value::as_str) != Some(sid));
        if statements.len() == before {
            return Err(EventsError::ResourceNotFound(format!(
                "Statement {sid} does not exist"
            )));
        }
        if statements.is_empty() {
            bus.policy = None;
        }
        Ok(json!({}))
    }
}

fn insert_opt(out: &mut Value, key: &str, value: Option<Value>) {
    if let (Some(map), Some(value)) = (out.as_object_mut(), value) {
        map.insert(key.into(), value);
    }
}
impl EventsService {
    async fn put_rule(&self, ctx: &RequestContext<'_>, body: &Value) -> Result<Value, EventsError> {
        let name = required(body, "Name")?.to_string();
        let bus_name = bus_name(body);
        let event_pattern = optional(body, "EventPattern")
            .map(|raw| {
                let parsed: Value = serde_json::from_str(&raw).map_err(|_| {
                    EventsError::InvalidEventPattern("EventPattern is not valid JSON".into())
                })?;
                pattern::compile(&parsed)
            })
            .transpose()?;
        let expression = optional(body, "ScheduleExpression");
        if event_pattern.is_none() && expression.is_none() {
            return Err(EventsError::Validation(
                "EventPattern or ScheduleExpression is required".into(),
            ));
        }
        if expression.is_some() && bus_name != "default" {
            return Err(EventsError::Validation(
                "scheduled rules are supported only on the default event bus".into(),
            ));
        }
        if let Some(expression) = &expression {
            schedule::parse(expression, false).map_err(EventsError::Validation)?;
        }
        let state_name = optional(body, "State").unwrap_or_else(|| "ENABLED".into());
        if !matches!(
            state_name.as_str(),
            "ENABLED" | "DISABLED" | "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
        ) {
            return Err(EventsError::Validation("invalid rule State".into()));
        }
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let bus = state.buses.get_mut(&bus_name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Event bus {bus_name} does not exist"))
        })?;
        let arn = EbArn::Rule {
            region: ctx.region.into(),
            account: ctx.account.into(),
            bus: bus_name,
            name: name.clone(),
        }
        .to_string();
        let existing = bus.rules.get(&name);
        let targets = existing
            .map(|rule| rule.targets.clone())
            .unwrap_or_default();
        let existing_tags = existing.map(|rule| rule.tags.clone()).unwrap_or_default();
        let generation = existing
            .map(|rule| rule.generation + 1)
            .unwrap_or_else(|| Uuid::new_v4().as_u128() as u64);
        bus.rules.insert(
            name.clone(),
            Rule {
                name,
                arn: arn.clone(),
                state: state_name,
                event_pattern,
                schedule_expression: expression,
                description: optional(body, "Description"),
                role_arn: optional(body, "RoleArn"),
                targets,
                tags: if existing_tags.is_empty() {
                    tags(body)
                } else {
                    existing_tags
                },
                generation,
            },
        );
        Ok(json!({"RuleArn": arn}))
    }

    async fn describe_rule(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Name")?;
        let bus_name = bus_name(body);
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let rule = state
            .buses
            .get(&bus_name)
            .and_then(|bus| bus.rules.get(name))
            .ok_or_else(|| EventsError::ResourceNotFound(format!("Rule {name} does not exist")))?;
        Ok(rule_json(rule, Some(&bus_name)))
    }

    async fn list_rules(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let bus_name = bus_name(body);
        let prefix = optional(body, "NamePrefix").unwrap_or_default();
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let bus = state.buses.get(&bus_name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Event bus {bus_name} does not exist"))
        })?;
        let rules: Vec<_> = bus
            .rules
            .values()
            .filter(|rule| rule.name.starts_with(&prefix))
            .map(|rule| rule_json(rule, None))
            .collect();
        paginated_response(body, "Rules", rules, "Limit")
    }

    async fn list_rule_names_by_target(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let arn = required(body, "TargetArn")?;
        let bus_filter = optional(body, "EventBusName");
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let mut names: Vec<_> = state
            .buses
            .iter()
            .filter(|(name, _)| bus_filter.as_ref().is_none_or(|filter| filter == *name))
            .flat_map(|(_, bus)| bus.rules.values())
            .filter(|rule| rule.targets.iter().any(|target| target.arn == arn))
            .map(|rule| Value::String(rule.name.clone()))
            .collect();
        names.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
        paginated_response(body, "RuleNames", names, "Limit")
    }

    async fn set_rule_state(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
        new_state: &str,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Name")?;
        let bus_name = bus_name(body);
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let rule = state
            .buses
            .get_mut(&bus_name)
            .and_then(|bus| bus.rules.get_mut(name))
            .ok_or_else(|| EventsError::ResourceNotFound(format!("Rule {name} does not exist")))?;
        rule.state = new_state.into();
        rule.generation += 1;
        Ok(json!({}))
    }

    async fn delete_rule(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Name")?;
        let bus_name = bus_name(body);
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let bus = state.buses.get_mut(&bus_name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Event bus {bus_name} does not exist"))
        })?;
        let rule = bus
            .rules
            .get(name)
            .ok_or_else(|| EventsError::ResourceNotFound(format!("Rule {name} does not exist")))?;
        if !rule.targets.is_empty() && !body.get("Force").and_then(Value::as_bool).unwrap_or(false)
        {
            return Err(EventsError::Validation(
                "Rule can't be deleted since it has targets".into(),
            ));
        }
        bus.rules.remove(name);
        Ok(json!({}))
    }

    async fn put_targets(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Rule")?;
        let entries = body
            .get("Targets")
            .and_then(Value::as_array)
            .ok_or_else(|| EventsError::Validation("Targets is required".into()))?;
        let parsed: Result<Vec<_>, _> = entries.iter().map(parse_target).collect();
        let parsed = parsed?;
        let bus_name = bus_name(body);
        let scope = self.store.scope(ctx.account, ctx.region).await;
        {
            let state = scope.read().await;
            if !state
                .buses
                .get(&bus_name)
                .is_some_and(|bus| bus.rules.contains_key(name))
            {
                return Err(EventsError::ResourceNotFound(format!(
                    "Rule {name} does not exist"
                )));
            }
        }

        let registry = self.registry.upgrade();
        let mut accepted = Vec::with_capacity(parsed.len());
        let mut failed = Vec::new();
        for target in parsed {
            if target.arn.split(':').nth(2) == Some("logs") {
                let Some(group_name) =
                    delivery::log_group_name(&target.arn, ctx.region, ctx.account)
                else {
                    failed.push(json!({
                        "TargetId": target.id,
                        "ErrorCode": "ValidationException",
                        "ErrorMessage": "CloudWatch Logs target ARN must identify a same-scope log group"
                    }));
                    continue;
                };
                let identity = target.role_arn.as_ref().map_or(
                    CallerIdentity::ServicePrincipal {
                        service: "events".into(),
                    },
                    |role| CallerIdentity::AssumedRole {
                        role_arn: role.clone(),
                        session_name: "eventbridge".into(),
                    },
                );
                let context = ProducerContext {
                    source_service: "events".into(),
                    identity,
                    correlation: CorrelationContext {
                        flow_id: ctx.request_id.to_string(),
                        span_id: Uuid::new_v4().to_string(),
                    },
                    loop_depth: 0,
                };
                let result = match registry.as_ref() {
                    Some(registry) => match registry.log_sink(&ServiceName::new("logs")) {
                        Some(sink) => {
                            sink.resolve_group(
                                LogScope::new(ctx.account, ctx.region),
                                ProducerGroupSpec { name: group_name },
                                context,
                            )
                            .await
                        }
                        None => Err(SinkError::Unavailable),
                    },
                    None => Err(SinkError::Unavailable),
                };
                if let Err(error) = result {
                    let code = if matches!(error, SinkError::NotFound(_)) {
                        "ResourceNotFoundException"
                    } else {
                        "ValidationException"
                    };
                    failed.push(json!({
                        "TargetId": target.id,
                        "ErrorCode": code,
                        "ErrorMessage": error.to_string()
                    }));
                    continue;
                }
            }
            accepted.push(target);
        }

        let mut state = scope.write().await;
        let rule = state
            .buses
            .get_mut(&bus_name)
            .and_then(|bus| bus.rules.get_mut(name))
            .ok_or_else(|| EventsError::ResourceNotFound(format!("Rule {name} does not exist")))?;
        for target in accepted {
            if let Some(position) = rule
                .targets
                .iter()
                .position(|current| current.id == target.id)
            {
                rule.targets[position] = target;
            } else {
                rule.targets.push(target);
            }
        }
        Ok(json!({"FailedEntryCount":failed.len(),"FailedEntries":failed}))
    }

    async fn remove_targets(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Rule")?;
        let ids: Vec<&str> = body
            .get("Ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let bus_name = bus_name(body);
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let rule = state
            .buses
            .get_mut(&bus_name)
            .and_then(|bus| bus.rules.get_mut(name))
            .ok_or_else(|| EventsError::ResourceNotFound(format!("Rule {name} does not exist")))?;
        let existing: Vec<String> = rule
            .targets
            .iter()
            .map(|target| target.id.clone())
            .collect();
        rule.targets
            .retain(|target| !ids.contains(&target.id.as_str()));
        let failed: Vec<_> = ids.into_iter().filter(|id| !existing.iter().any(|existing| existing == id)).map(|id| json!({"TargetId":id,"ErrorCode":"ResourceNotFoundException","ErrorMessage":"Target does not exist"})).collect();
        Ok(json!({"FailedEntryCount":failed.len(),"FailedEntries":failed}))
    }

    async fn list_targets(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Rule")?;
        let bus_name = bus_name(body);
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let rule = state
            .buses
            .get(&bus_name)
            .and_then(|bus| bus.rules.get(name))
            .ok_or_else(|| EventsError::ResourceNotFound(format!("Rule {name} does not exist")))?;
        let mut targets: Vec<_> = rule.targets.iter().collect();
        targets.sort_by(|left, right| left.id.cmp(&right.id));
        let targets = targets.into_iter().map(target_json).collect();
        paginated_response(body, "Targets", targets, "Limit")
    }
}
fn rule_json(rule: &Rule, bus: Option<&str>) -> Value {
    let mut value = json!({"Name":rule.name,"Arn":rule.arn,"State":rule.state});
    insert_opt(
        &mut value,
        "EventBusName",
        bus.map(|v| Value::String(v.into())),
    );
    insert_opt(
        &mut value,
        "EventPattern",
        rule.event_pattern
            .as_ref()
            .map(Value::to_string)
            .map(Value::String),
    );
    insert_opt(
        &mut value,
        "ScheduleExpression",
        rule.schedule_expression.clone().map(Value::String),
    );
    insert_opt(
        &mut value,
        "Description",
        rule.description.clone().map(Value::String),
    );
    insert_opt(
        &mut value,
        "RoleArn",
        rule.role_arn.clone().map(Value::String),
    );
    value
}

fn parse_target(value: &Value) -> Result<Target, EventsError> {
    let id = required(value, "Id")?.to_string();
    let arn = required(value, "Arn")?.to_string();
    let input = optional(value, "Input");
    let input_path = optional(value, "InputPath");
    let input_transformer = value
        .get("InputTransformer")
        .map(|input| {
            let paths = input
                .get("InputPathsMap")
                .map_or(Ok(BTreeMap::new()), |raw| {
                    let map = raw.as_object().ok_or_else(|| {
                        EventsError::Validation(
                            "InputTransformer.InputPathsMap must be an object".into(),
                        )
                    })?;
                    if map.len() > 100 {
                        return Err(EventsError::Validation(
                            "InputTransformer.InputPathsMap exceeds 100 entries".into(),
                        ));
                    }
                    map.iter()
                        .map(|(key, value)| {
                            let path = value.as_str().ok_or_else(|| {
                                EventsError::Validation(
                                    "InputPathsMap values must be JSON paths".into(),
                                )
                            })?;
                            if key.is_empty()
                                || key.len() > 256
                                || !key.bytes().all(|ch| {
                                    ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-'
                                })
                                || key.to_ascii_uppercase().starts_with("AWS.")
                                || path.len() > 256
                                || !path.starts_with("$.")
                            {
                                return Err(EventsError::Validation(
                                    "invalid InputPathsMap entry".into(),
                                ));
                            }
                            Ok((key.clone(), path.to_string()))
                        })
                        .collect()
                })?;
            let template = input
                .get("InputTemplate")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    EventsError::Validation("InputTransformer.InputTemplate is required".into())
                })?
                .to_string();
            if template.is_empty() || template.len() > 8192 {
                return Err(EventsError::Validation(
                    "InputTemplate must contain 1 to 8192 characters".into(),
                ));
            }
            Ok::<_, EventsError>((paths, template))
        })
        .transpose()?;
    if [
        input.is_some(),
        input_path.is_some(),
        input_transformer.is_some(),
    ]
    .into_iter()
    .filter(|set| *set)
    .count()
        > 1
    {
        return Err(EventsError::Validation(format!(
            "target {id} specifies more than one input mode"
        )));
    }
    let retry_value = value.get("RetryPolicy").unwrap_or(&Value::Null);
    let maximum_attempts = retry_value
        .get("MaximumRetryAttempts")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(u64::from(u32::MAX)) as u32;
    Ok(Target {
        id,
        arn,
        role_arn: optional(value, "RoleArn"),
        input,
        input_path,
        input_transformer,
        sqs_parameters: value.get("SqsParameters").cloned(),
        retry: RetryPolicy {
            maximum_attempts,
            maximum_age_seconds: retry_value
                .get("MaximumEventAgeInSeconds")
                .and_then(Value::as_u64),
        },
        dead_letter_arn: value
            .get("DeadLetterConfig")
            .and_then(|dlq| dlq.get("Arn"))
            .and_then(Value::as_str)
            .map(str::to_string),
        extra: value.clone(),
    })
}

fn target_json(target: &Target) -> Value {
    let mut value = json!({"Id":target.id,"Arn":target.arn});
    insert_opt(
        &mut value,
        "RoleArn",
        target.role_arn.clone().map(Value::String),
    );
    insert_opt(&mut value, "Input", target.input.clone().map(Value::String));
    insert_opt(
        &mut value,
        "InputPath",
        target.input_path.clone().map(Value::String),
    );
    if let Some((paths, template)) = &target.input_transformer {
        value["InputTransformer"] = json!({"InputPathsMap":paths,"InputTemplate":template});
    }
    insert_opt(&mut value, "SqsParameters", target.sqs_parameters.clone());
    if let Some(arn) = &target.dead_letter_arn {
        value["DeadLetterConfig"] = json!({"Arn":arn});
    }
    if let Some(retry_policy) = target.extra.get("RetryPolicy") {
        value["RetryPolicy"] = retry_policy.clone();
    }
    value
}

fn test_event_pattern(body: &Value) -> Result<Value, EventsError> {
    let pattern_raw = required(body, "EventPattern")?;
    let event_raw = required(body, "Event")?;
    let pattern_value: Value = serde_json::from_str(pattern_raw)
        .map_err(|_| EventsError::InvalidEventPattern("EventPattern is not valid JSON".into()))?;
    let compiled = pattern::compile(&pattern_value)?;
    let event: Value = serde_json::from_str(event_raw)
        .map_err(|_| EventsError::InvalidEventPattern("Event is not valid JSON".into()))?;
    if !event.is_object() {
        return Err(EventsError::InvalidEventPattern(
            "Event must be a JSON object".into(),
        ));
    }
    Ok(json!({"Result":pattern::matches(&compiled, &event)}))
}
impl EventsService {
    async fn put_events(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
        partner: bool,
    ) -> Result<Value, EventsError> {
        let entries = body
            .get("Entries")
            .and_then(Value::as_array)
            .ok_or_else(|| EventsError::Validation("Entries is required".into()))?;
        let mut output = Vec::with_capacity(entries.len());
        let mut failed = 0usize;
        for entry in entries {
            match self.process_entry(ctx, entry, partner).await {
                Ok(id) => output.push(json!({"EventId":id})),
                Err(error) => {
                    failed += 1;
                    output.push(json!({"ErrorCode":error.code(),"ErrorMessage":error.to_string()}));
                }
            }
        }
        Ok(json!({"FailedEntryCount":failed,"Entries":output}))
    }

    async fn process_entry(
        &self,
        ctx: &RequestContext<'_>,
        entry: &Value,
        partner: bool,
    ) -> Result<String, EventsError> {
        let source = required(entry, "Source")?;
        let detail_type = required(entry, "DetailType")?;
        let detail = optional(entry, "Detail").unwrap_or_else(|| "{}".into());
        let detail: Value = serde_json::from_str(&detail)
            .map_err(|_| EventsError::Validation("Detail must be valid JSON".into()))?;
        if !detail.is_object() {
            return Err(EventsError::Validation(
                "Detail must be a JSON object".into(),
            ));
        }
        let id = Uuid::new_v4().to_string();
        let timestamp = match entry.get("Time") {
            Some(value) => event_time(Some(value))?,
            None => self.clock.now(),
        };
        let resources: Vec<String> = entry
            .get("Resources")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        let event = json!({
            "version":"0","id":id,"detail-type":detail_type,"source":source,
            "account":ctx.account,"time":timestamp.format(&Rfc3339).unwrap_or_default(),
            "region":ctx.region,"resources":resources,"detail":detail,
        });
        let selected_bus = if partner {
            let source = source.strip_prefix("aws.partner/").unwrap_or(source);
            format!("aws.partner/{source}")
        } else {
            optional(entry, "EventBusName")
                .map(|value| event_bus_name_or_arn(&value).to_string())
                .unwrap_or_else(|| "default".into())
        };
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let (rules, archived) = {
            let mut state = scope.write().await;
            let Some(bus) = state.buses.get(&selected_bus) else {
                return Ok(id);
            };
            let bus_arn = bus.arn.clone();
            let rules: Vec<Rule> = bus.rules.values().cloned().collect();
            let now = self.clock.now();
            let mut archived = Vec::new();
            for archive in state
                .archives
                .values_mut()
                .filter(|archive| archive.source_arn == bus_arn)
            {
                prune_archive(archive, now);
                if archive
                    .event_pattern
                    .as_ref()
                    .is_none_or(|pattern| pattern::matches(pattern, &event))
                {
                    archived.push((
                        archive.name.clone(),
                        ArchivedEvent {
                            event: event.clone(),
                            time: timestamp,
                        },
                    ));
                }
            }
            (rules, archived)
        };
        let active = self
            .claim_fanout(&id)
            .ok_or_else(|| EventsError::Internal("fanout already active".into()))?;
        self.store
            .accept_event(
                PendingFanout {
                    id: id.clone(),
                    account: ctx.account.to_string(),
                    region: ctx.region.to_string(),
                    event: event.clone(),
                    rules: rules.clone(),
                },
                archived.clone(),
            )
            .await
            .map_err(EventsError::Internal)?;
        if self.store.state_db().is_none() {
            let mut state = scope.write().await;
            for (name, item) in archived {
                if let Some(archive) = state.archives.get_mut(&name) {
                    archive.events.push(item);
                }
            }
        }
        if let Some(state) = self.store.state_db() {
            let account = ctx.account.to_string();
            let region = ctx.region.to_string();
            let bus = selected_bus.clone();
            let original = event.clone();
            match tokio::task::spawn_blocking(move || {
                schemas::discovery::on_event(&state, &account, &region, &bus, &original)
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(%error, "EventBridge schema discovery failed"),
                Err(error) => tracing::warn!(%error, "EventBridge schema discovery task failed"),
            }
        }
        if self.fanout(ctx, &rules, &event, None).await {
            self.store
                .complete_fanout(&id)
                .await
                .map_err(EventsError::Internal)?;
        } else {
            drop(active);
            self.store.notify_pending();
        }
        Ok(id)
    }

    fn claim_fanout(&self, id: &str) -> Option<ActiveFanout> {
        let mut active = self.active_fanouts.lock().ok()?;
        if !active.insert(id.to_string()) {
            return None;
        }
        Some(ActiveFanout {
            id: id.to_string(),
            active: self.active_fanouts.clone(),
        })
    }

    pub async fn resume_pending(&self) -> bool {
        let pending = match self.store.pending_fanouts().await {
            Ok(pending) => pending,
            Err(error) => {
                tracing::error!(%error, "failed to load pending EventBridge fanout");
                return true;
            }
        };
        let mut failed = false;
        for work in pending {
            let Some(_active) = self.claim_fanout(&work.id) else {
                continue;
            };
            let ctx = RequestContext {
                account: &work.account,
                region: &work.region,
                request_id: &work.id,
            };
            if self.fanout(&ctx, &work.rules, &work.event, None).await {
                if let Err(error) = self.store.complete_fanout(&work.id).await {
                    tracing::error!(%error, "failed to complete EventBridge fanout");
                    failed = true;
                }
            } else {
                failed = true;
            }
        }
        failed
    }

    pub async fn resume_scheduled_rules(&self) {
        for (account, region) in self.store.bus_scope_keys() {
            let scope = self.store.scope(&account, &region).await;
            let rules = {
                let state = scope.read().await;
                state
                    .buses
                    .values()
                    .flat_map(|bus| {
                        bus.rules.values().map(|rule| {
                            (
                                bus.name.clone(),
                                rule.name.clone(),
                                rule.arn.clone(),
                                rule.enabled() && rule.schedule_expression.is_some(),
                            )
                        })
                    })
                    .collect::<Vec<_>>()
            };
            for (bus, name, arn, enabled) in rules {
                if !enabled
                    && self
                        .store
                        .pending_firings("rule", &arn)
                        .is_ok_and(|rows| rows.is_empty())
                {
                    continue;
                }
                let ctx = RequestContext {
                    account: &account,
                    region: &region,
                    request_id: "restart",
                };
                self.reconcile_worker("PutRule", &ctx, &json!({"Name": name, "EventBusName": bus}))
                    .await;
            }
        }
    }

    async fn fanout(
        &self,
        ctx: &RequestContext<'_>,
        rules: &[Rule],
        event: &Value,
        selected_rule_arns: Option<&[String]>,
    ) -> bool {
        let Some(registry) = self.registry.upgrade() else {
            return false;
        };
        fanout_rules(
            FanoutContext {
                registry: &registry,
                store: &self.store,
                http: self.http.as_ref(),
                region: ctx.region,
                account: ctx.account,
                correlation: CorrelationContext {
                    flow_id: ctx.request_id.to_string(),
                    span_id: Uuid::new_v4().to_string(),
                },
            },
            rules,
            event,
            selected_rule_arns,
        )
        .await
    }
}

struct FanoutContext<'a> {
    registry: &'a ServiceRegistry,
    store: &'a EbStore,
    http: &'a dyn HttpClient,
    region: &'a str,
    account: &'a str,
    correlation: CorrelationContext,
}

async fn fanout_rules(
    context: FanoutContext<'_>,
    rules: &[Rule],
    event: &Value,
    selected_rule_arns: Option<&[String]>,
) -> bool {
    let mut delivered = true;
    let event_json = event.to_string();
    let ingestion = event
        .get("time")
        .and_then(Value::as_str)
        .unwrap_or_default();
    for rule in rules {
        if !rule.enabled() || selected_rule_arns.is_some_and(|arns| !arns.contains(&rule.arn)) {
            continue;
        }
        let Some(pattern_value) = &rule.event_pattern else {
            continue;
        };
        if !pattern::matches(pattern_value, event) {
            continue;
        }
        for target in &rule.targets {
            let mut effective_target = target.clone();
            if effective_target.role_arn.is_none() {
                effective_target.role_arn = rule.role_arn.clone();
            }
            let mode = target_mode(target);
            let transform_context = Context {
                rule_arn: &rule.arn,
                rule_name: &rule.name,
                event_json: &event_json,
                ingestion_time: ingestion,
            };
            let payload = transform::apply(&mode, event, &transform_context);
            delivered &= deliver_event_target(
                FanoutContext {
                    registry: context.registry,
                    store: context.store,
                    http: context.http,
                    region: context.region,
                    account: context.account,
                    correlation: context.correlation.child(),
                },
                &effective_target,
                payload,
                &rule.arn,
                &rule.name,
            )
            .await;
        }
    }
    delivered
}

fn target_mode(target: &Target) -> InputMode {
    if let Some(input) = &target.input {
        InputMode::Constant(input.clone())
    } else if let Some(path) = &target.input_path {
        InputMode::Path(path.clone())
    } else if let Some((paths, template)) = &target.input_transformer {
        InputMode::Transformer {
            paths: paths.clone(),
            template: template.clone(),
        }
    } else {
        InputMode::None
    }
}

fn event_time(value: Option<&Value>) -> Result<OffsetDateTime, EventsError> {
    match value {
        None => Ok(OffsetDateTime::now_utc()),
        Some(Value::Number(number)) => OffsetDateTime::from_unix_timestamp(
            number
                .as_i64()
                .or_else(|| number.as_f64().map(|value| value as i64))
                .ok_or_else(|| EventsError::Validation("Time is invalid".into()))?,
        )
        .map_err(|_| EventsError::Validation("Time is invalid".into())),
        Some(Value::String(value)) => OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|_| EventsError::Validation("Time is invalid".into())),
        _ => Err(EventsError::Validation("Time is invalid".into())),
    }
}
impl EventsService {
    async fn create_archive(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "ArchiveName")?.to_string();
        let source_arn = required(body, "EventSourceArn")?.to_string();
        let event_pattern = optional(body, "EventPattern")
            .map(|raw| {
                let parsed: Value = serde_json::from_str(&raw).map_err(|_| {
                    EventsError::InvalidEventPattern("EventPattern is not valid JSON".into())
                })?;
                pattern::compile(&parsed)
            })
            .transpose()?;
        let retention_days = retention_days(body)?.unwrap_or(0);
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        if !state.buses.values().any(|bus| bus.arn == source_arn) {
            return Err(EventsError::ResourceNotFound(
                "source event bus does not exist".into(),
            ));
        }
        if state.archives.contains_key(&name) {
            return Err(EventsError::ResourceAlreadyExists(format!(
                "Archive {name} already exists"
            )));
        }
        let arn = EbArn::Archive {
            region: ctx.region.into(),
            account: ctx.account.into(),
            name: name.clone(),
        }
        .to_string();
        state.archives.insert(
            name.clone(),
            Archive {
                name: name.clone(),
                arn: arn.clone(),
                source_arn,
                description: optional(body, "Description"),
                event_pattern,
                retention_days,
                tags: tags(body),
                events: Vec::new(),
            },
        );
        drop(state);
        self.store
            .persist_archive(ctx.account, ctx.region, &name)
            .await
            .map_err(EventsError::Internal)?;
        Ok(json!({"ArchiveArn":arn,"State":"ENABLED"}))
    }

    async fn describe_archive(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "ArchiveName")?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let archive = state.archives.get_mut(name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Archive {name} does not exist"))
        })?;
        let now = self.clock.now();
        prune_archive(archive, now);
        let mut value = archive_json(archive);
        drop(state);
        if self.store.state_db().is_some() {
            value["EventCount"] = json!(self
                .store
                .archive_count(ctx.account, ctx.region, name, now)
                .await
                .map_err(EventsError::Internal)?);
        }
        Ok(value)
    }

    async fn update_archive(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "ArchiveName")?;
        let compiled = optional(body, "EventPattern")
            .map(|raw| {
                serde_json::from_str::<Value>(&raw)
                    .map_err(|_| {
                        EventsError::InvalidEventPattern("EventPattern is not valid JSON".into())
                    })
                    .and_then(|value| pattern::compile(&value))
            })
            .transpose()?;
        let retention_days = retention_days(body)?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let archive = state.archives.get_mut(name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Archive {name} does not exist"))
        })?;
        if body.get("Description").is_some() {
            archive.description = optional(body, "Description");
        }
        if body.get("EventPattern").is_some() {
            archive.event_pattern = compiled;
        }
        if let Some(days) = retention_days {
            archive.retention_days = days;
        }
        prune_archive(archive, self.clock.now());
        let arn = archive.arn.clone();
        drop(state);
        self.store
            .persist_archive(ctx.account, ctx.region, name)
            .await
            .map_err(EventsError::Internal)?;
        Ok(json!({"ArchiveArn":arn,"State":"ENABLED"}))
    }

    async fn delete_archive(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "ArchiveName")?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        if scope.write().await.archives.remove(name).is_none() {
            return Err(EventsError::ResourceNotFound(format!(
                "Archive {name} does not exist"
            )));
        }
        self.store
            .delete_persisted_archive(ctx.account, ctx.region, name)
            .await
            .map_err(EventsError::Internal)?;
        Ok(json!({}))
    }

    async fn list_archives(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let prefix = optional(body, "NamePrefix").unwrap_or_default();
        let source = optional(body, "EventSourceArn");
        let requested_state = optional(body, "State");
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let now = self.clock.now();
        for archive in state.archives.values_mut() {
            prune_archive(archive, now);
        }
        let selected: Vec<Archive> = state
            .archives
            .values()
            .filter(|archive| {
                archive.name.starts_with(&prefix)
                    && source
                        .as_ref()
                        .is_none_or(|value| value == &archive.source_arn)
                    && requested_state
                        .as_ref()
                        .is_none_or(|value| value == "ENABLED")
            })
            .cloned()
            .collect();
        drop(state);
        let mut archives = Vec::with_capacity(selected.len());
        for archive in selected {
            let mut value = archive_json(&archive);
            if self.store.state_db().is_some() {
                value["EventCount"] = json!(self
                    .store
                    .archive_count(ctx.account, ctx.region, &archive.name, now,)
                    .await
                    .map_err(EventsError::Internal)?);
            }
            archives.push(value);
        }
        paginated_response(body, "Archives", archives, "Limit")
    }

    async fn start_replay(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "ReplayName")?.to_string();
        let source_arn = required(body, "EventSourceArn")?.to_string();
        let start =
            event_time(Some(body.get("EventStartTime").ok_or_else(|| {
                EventsError::Validation("EventStartTime is required".into())
            })?))?;
        let end =
            event_time(Some(body.get("EventEndTime").ok_or_else(|| {
                EventsError::Validation("EventEndTime is required".into())
            })?))?;
        if start > end {
            return Err(EventsError::Validation(
                "EventStartTime must not be after EventEndTime".into(),
            ));
        }
        let destination = body
            .get("Destination")
            .cloned()
            .ok_or_else(|| EventsError::Validation("Destination is required".into()))?;
        let destination_arn = destination
            .get("Arn")
            .and_then(Value::as_str)
            .ok_or_else(|| EventsError::Validation("Destination.Arn is required".into()))?;
        let destination_bus = match EbArn::parse(destination_arn)? {
            EbArn::EventBus {
                region,
                account,
                name,
            } if region == ctx.region && account == ctx.account => name,
            _ => {
                return Err(EventsError::ResourceNotFound(
                    "destination event bus does not exist".into(),
                ))
            }
        };
        let durable = self.store.state_db().is_some();
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let (events, replay) = {
            let mut state = scope.write().await;
            if state.replays.contains_key(&name) {
                return Err(EventsError::ResourceAlreadyExists(format!(
                    "Replay {name} already exists"
                )));
            }
            if !state.buses.contains_key(&destination_bus) {
                return Err(EventsError::ResourceNotFound(
                    "destination event bus does not exist".into(),
                ));
            }
            let archive = state
                .archives
                .values_mut()
                .find(|archive| archive.arn == source_arn)
                .ok_or_else(|| EventsError::ResourceNotFound("Archive does not exist".into()))?;
            if archive.source_arn != destination_arn {
                return Err(EventsError::Validation(
                    "Replay destination must be the archive source bus".into(),
                ));
            }
            prune_archive(archive, self.clock.now());
            let events: Vec<_> = if durable {
                Vec::new()
            } else {
                archive
                    .events
                    .iter()
                    .filter(|event| event.time >= start && event.time <= end)
                    .map(|archived| {
                        let mut event = archived.event.clone();
                        event["replay-name"] = json!(name);
                        event
                    })
                    .collect()
            };
            let arn = format!(
                "arn:aws:events:{}:{}:replay/{}",
                ctx.region, ctx.account, name
            );
            let replay = Replay {
                name: name.clone(),
                arn,
                source_arn: source_arn.clone(),
                destination: destination.clone(),
                start,
                end,
                state: "RUNNING".into(),
            };
            state.replays.insert(name.clone(), replay.clone());
            (events, replay)
        };
        let (events, total) = if durable {
            let total = self
                .store
                .snapshot_replay(ctx.account, ctx.region, &replay)
                .await
                .map_err(|error| EventsError::Internal(format!("snapshot replay: {error}")))?;
            (None, total)
        } else {
            let total = events.len();
            (Some(events), total)
        };
        self.spawn_replay_worker(
            ctx.account.to_string(),
            ctx.region.to_string(),
            replay.clone(),
            events,
            0,
            total,
        );
        Ok(json!({"ReplayArn":replay.arn,"ReplayStartTime":self.clock.now().unix_timestamp()}))
    }

    fn spawn_replay_worker(
        &self,
        account: String,
        region: String,
        replay: Replay,
        events: Option<Vec<Value>>,
        cursor: usize,
        total: usize,
    ) {
        let key = replay_worker_key(&account, &region, &replay.name);
        self.abort_worker(&key);
        let registry = self.registry.clone();
        let store = self.store.clone();
        let http = self.http.clone();
        let workers = self.workers.clone();
        let completion_key = key.clone();
        let (registered_tx, registered_rx) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            let _ = registered_rx.await;
            let destination = replay
                .destination
                .get("Arn")
                .and_then(Value::as_str)
                .map(event_bus_name_or_arn)
                .unwrap_or_default()
                .to_string();
            let selected: Option<Vec<String>> = replay
                .destination
                .get("FilterArns")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                });
            for index in cursor..total {
                let event = if let Some(events) = &events {
                    events.get(index).cloned()
                } else {
                    match store
                        .load_replay_item(&account, &region, &replay.name, index)
                        .await
                    {
                        Ok(item) => item,
                        Err(error) => {
                            tracing::error!(%error, "failed to load EventBridge replay item");
                            return;
                        }
                    }
                };
                let Some(event) = event else {
                    tracing::error!(index, "EventBridge replay snapshot is incomplete");
                    return;
                };
                loop {
                    let scope = store.scope(&account, &region).await;
                    let rules = {
                        let state = scope.read().await;
                        if !state
                            .replays
                            .get(&replay.name)
                            .is_some_and(|item| item.state == "RUNNING")
                        {
                            return;
                        }
                        state
                            .buses
                            .get(&destination)
                            .map(|bus| bus.rules.values().cloned().collect::<Vec<_>>())
                    };
                    let delivered =
                        if let (Some(rules), Some(registry)) = (rules, registry.upgrade()) {
                            fanout_rules(
                                FanoutContext {
                                    registry: &registry,
                                    store: &store,
                                    http: http.as_ref(),
                                    region: &region,
                                    account: &account,
                                    correlation: CorrelationContext::root(),
                                },
                                &rules,
                                &event,
                                selected.as_deref(),
                            )
                            .await
                        } else {
                            false
                        };
                    if delivered {
                        match store
                            .advance_replay(&account, &region, &replay.name, "RUNNING", index + 1)
                            .await
                        {
                            Ok(true) => break,
                            Ok(false) => return,
                            Err(error) => {
                                tracing::error!(%error, "failed to persist EventBridge replay progress");
                                return;
                            }
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
            match store
                .advance_replay(&account, &region, &replay.name, "COMPLETED", total)
                .await
            {
                Ok(true) => {
                    let scope = store.scope(&account, &region).await;
                    let mut guard = scope.write().await;
                    if let Some(item) = guard.replays.get_mut(&replay.name) {
                        if item.state == "RUNNING" {
                            item.state = "COMPLETED".into();
                        }
                    }
                }
                Ok(false) => {}
                Err(error) => tracing::error!(%error, "failed to complete EventBridge replay"),
            }
            if let Ok(mut workers) = workers.lock() {
                workers.remove(&completion_key);
            }
        });
        if let Ok(mut workers) = self.workers.lock() {
            workers.insert(key, worker);
        }
        let _ = registered_tx.send(());
    }

    pub async fn resume_replays(&self) {
        match self.store.pending_replays().await {
            Ok(pending) => {
                for (account, region, replay, cursor, total) in pending {
                    self.spawn_replay_worker(account, region, replay, None, cursor, total);
                }
            }
            Err(error) => tracing::error!(%error, "failed to load EventBridge replays"),
        }
    }

    async fn describe_replay(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "ReplayName")?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let replay = state.replays.get(name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Replay {name} does not exist"))
        })?;
        Ok(replay_json(replay))
    }

    async fn cancel_replay(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "ReplayName")?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let arn = {
            let mut state = scope.write().await;
            let replay = state.replays.get_mut(name).ok_or_else(|| {
                EventsError::ResourceNotFound(format!("Replay {name} does not exist"))
            })?;
            if replay.state != "RUNNING" {
                return Err(EventsError::Validation(format!(
                    "Replay {name} is not running"
                )));
            }
            replay.arn.clone()
        };
        let cancelled = self
            .store
            .set_replay_state(ctx.account, ctx.region, name, "CANCELLED")
            .await
            .map_err(EventsError::Internal)?;
        if !cancelled {
            return Err(EventsError::Validation(format!(
                "Replay {name} is not running"
            )));
        }
        if let Some(replay) = scope.write().await.replays.get_mut(name) {
            replay.state = "CANCELLED".into();
        }
        self.abort_worker(&replay_worker_key(ctx.account, ctx.region, name));
        Ok(json!({"ReplayArn":arn,"State":"CANCELLED"}))
    }

    async fn list_replays(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let prefix = optional(body, "NamePrefix").unwrap_or_default();
        let source = optional(body, "EventSourceArn");
        let requested_state = optional(body, "State");
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let replays: Vec<_> = state
            .replays
            .values()
            .filter(|replay| {
                replay.name.starts_with(&prefix)
                    && source
                        .as_ref()
                        .is_none_or(|value| value == &replay.source_arn)
                    && requested_state
                        .as_ref()
                        .is_none_or(|value| value == &replay.state)
            })
            .map(replay_json)
            .collect();
        paginated_response(body, "Replays", replays, "Limit")
    }
}

fn archive_json(archive: &Archive) -> Value {
    json!({"ArchiveName":archive.name,"ArchiveArn":archive.arn,"EventSourceArn":archive.source_arn,"Description":archive.description,"EventPattern":archive.event_pattern.as_ref().map(Value::to_string),"RetentionDays":archive.retention_days,"State":"ENABLED","EventCount":archive.events.len()})
}

fn replay_json(replay: &Replay) -> Value {
    json!({"ReplayName":replay.name,"ReplayArn":replay.arn,"State":replay.state,"EventSourceArn":replay.source_arn,"Destination":replay.destination,"EventStartTime":replay.start.unix_timestamp(),"EventEndTime":replay.end.unix_timestamp()})
}
impl EventsService {
    async fn tag_resource(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let arn = body
            .get("ResourceARN")
            .or_else(|| body.get("ResourceArn"))
            .and_then(Value::as_str)
            .ok_or_else(|| EventsError::Validation("ResourceARN is required".into()))?;
        self.mutate_tags(ctx, arn, |current| current.extend(tags(body)))
            .await?;
        Ok(json!({}))
    }

    async fn untag_resource(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let arn = body
            .get("ResourceARN")
            .or_else(|| body.get("ResourceArn"))
            .and_then(Value::as_str)
            .ok_or_else(|| EventsError::Validation("ResourceARN is required".into()))?;
        let keys: Vec<String> = body
            .get("TagKeys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        self.mutate_tags(ctx, arn, |current| {
            current.retain(|key, _| !keys.contains(key))
        })
        .await?;
        Ok(json!({}))
    }

    async fn list_tags(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let arn = body
            .get("ResourceARN")
            .or_else(|| body.get("ResourceArn"))
            .and_then(Value::as_str)
            .ok_or_else(|| EventsError::Validation("ResourceARN is required".into()))?;
        let parsed = EbArn::parse(arn)?;
        if parsed.account() != ctx.account || parsed.region() != ctx.region {
            return Err(EventsError::ResourceNotFound(format!(
                "resource {arn} does not exist"
            )));
        }
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let values = match parsed {
            EbArn::EventBus { name, .. } => state.buses.get(&name).map(|resource| &resource.tags),
            EbArn::Rule { bus, name, .. } => state
                .buses
                .get(&bus)
                .and_then(|resource| resource.rules.get(&name))
                .map(|resource| &resource.tags),
            EbArn::Archive { name, .. } => state.archives.get(&name).map(|resource| &resource.tags),
            EbArn::Connection { name, .. } => {
                state.connections.get(&name).map(|resource| &resource.tags)
            }
            EbArn::ApiDestination { name, .. } => state
                .api_destinations
                .get(&name)
                .map(|resource| &resource.tags),
            _ => None,
        }
        .ok_or_else(|| EventsError::ResourceNotFound(format!("resource {arn} does not exist")))?;
        Ok(
            json!({"Tags":values.iter().map(|(key,value)| json!({"Key":key,"Value":value})).collect::<Vec<_>>() }),
        )
    }

    async fn mutate_tags(
        &self,
        ctx: &RequestContext<'_>,
        arn: &str,
        mutation: impl FnOnce(&mut BTreeMap<String, String>),
    ) -> Result<(), EventsError> {
        let parsed = EbArn::parse(arn)?;
        if parsed.account() != ctx.account || parsed.region() != ctx.region {
            return Err(EventsError::ResourceNotFound(format!(
                "resource {arn} does not exist"
            )));
        }
        let archive_name = match &parsed {
            EbArn::Archive { name, .. } => Some(name.clone()),
            _ => None,
        };
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let target = match parsed {
            EbArn::EventBus { name, .. } => state
                .buses
                .get_mut(&name)
                .map(|resource| &mut resource.tags),
            EbArn::Rule { bus, name, .. } => state
                .buses
                .get_mut(&bus)
                .and_then(|resource| resource.rules.get_mut(&name))
                .map(|resource| &mut resource.tags),
            EbArn::Archive { name, .. } => state
                .archives
                .get_mut(&name)
                .map(|resource| &mut resource.tags),
            EbArn::Connection { name, .. } => state
                .connections
                .get_mut(&name)
                .map(|resource| &mut resource.tags),
            EbArn::ApiDestination { name, .. } => state
                .api_destinations
                .get_mut(&name)
                .map(|resource| &mut resource.tags),
            _ => None,
        }
        .ok_or_else(|| EventsError::ResourceNotFound(format!("resource {arn} does not exist")))?;
        mutation(target);
        drop(state);
        if let Some(name) = archive_name {
            self.store
                .persist_archive(ctx.account, ctx.region, &name)
                .await
                .map_err(EventsError::Internal)?;
        }
        Ok(())
    }

    async fn create_connection(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Name")?.to_string();
        let auth_type = required(body, "AuthorizationType")?.to_string();
        let parameters = body
            .get("AuthParameters")
            .cloned()
            .ok_or_else(|| EventsError::Validation("AuthParameters is required".into()))?;
        validate_connection_auth(&auth_type, &parameters)?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        if state.connections.contains_key(&name) {
            return Err(EventsError::ResourceAlreadyExists(format!(
                "Connection {name} already exists"
            )));
        }
        let arn = EbArn::Connection {
            region: ctx.region.into(),
            account: ctx.account.into(),
            name: name.clone(),
        }
        .to_string();
        state.connections.insert(
            name.clone(),
            Connection {
                name,
                arn: arn.clone(),
                auth_type: auth_type.clone(),
                auth_parameters: parameters,
                tags: tags(body),
            },
        );
        Ok(
            json!({"ConnectionArn":arn,"ConnectionState":"AUTHORIZED","AuthorizationType":auth_type}),
        )
    }

    async fn describe_connection(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Name")?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let connection = state.connections.get(name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Connection {name} does not exist"))
        })?;
        Ok(
            json!({"Name":connection.name,"ConnectionArn":connection.arn,"AuthorizationType":connection.auth_type,"ConnectionState":"AUTHORIZED"}),
        )
    }

    async fn delete_connection(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Name")?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        if scope.write().await.connections.remove(name).is_none() {
            return Err(EventsError::ResourceNotFound(format!(
                "Connection {name} does not exist"
            )));
        }
        Ok(
            json!({"ConnectionArn":format!("arn:aws:events:{}:{}:connection/{name}",ctx.region,ctx.account),"ConnectionState":"DELETING"}),
        )
    }
    async fn create_api_destination(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Name")?.to_string();
        let connection_arn = required(body, "ConnectionArn")?.to_string();
        let endpoint = required(body, "InvocationEndpoint")?.to_string();
        if !endpoint.starts_with("https://") {
            return Err(EventsError::Validation(
                "InvocationEndpoint must use HTTPS".into(),
            ));
        }
        let method = required(body, "HttpMethod")?.to_string();
        validate_api_method(&method)?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        if !state
            .connections
            .values()
            .any(|connection| connection.arn == connection_arn)
        {
            return Err(EventsError::ResourceNotFound(
                "Connection does not exist".into(),
            ));
        }
        if state.api_destinations.contains_key(&name) {
            return Err(EventsError::ResourceAlreadyExists(format!(
                "API destination {name} already exists"
            )));
        }
        let arn = EbArn::ApiDestination {
            region: ctx.region.into(),
            account: ctx.account.into(),
            name: name.clone(),
        }
        .to_string();
        state.api_destinations.insert(
            name.clone(),
            ApiDestination {
                name,
                arn: arn.clone(),
                connection_arn: connection_arn.clone(),
                endpoint: endpoint.clone(),
                method: method.clone(),
                rate_limit: body
                    .get("InvocationRateLimitPerSecond")
                    .and_then(Value::as_i64),
                tags: tags(body),
            },
        );
        Ok(
            json!({"ApiDestinationArn":arn,"ApiDestinationState":"ACTIVE","ConnectionArn":connection_arn,"InvocationEndpoint":endpoint,"HttpMethod":method}),
        )
    }

    async fn describe_api_destination(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Name")?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let destination = state.api_destinations.get(name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("API destination {name} does not exist"))
        })?;
        Ok(
            json!({"Name":destination.name,"ApiDestinationArn":destination.arn,"ApiDestinationState":"ACTIVE","ConnectionArn":destination.connection_arn,"InvocationEndpoint":destination.endpoint,"HttpMethod":destination.method,"InvocationRateLimitPerSecond":destination.rate_limit}),
        )
    }

    async fn delete_api_destination(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Name")?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let removed = scope
            .write()
            .await
            .api_destinations
            .remove(name)
            .ok_or_else(|| {
                EventsError::ResourceNotFound(format!("API destination {name} does not exist"))
            })?;
        Ok(json!({"ApiDestinationArn":removed.arn,"ApiDestinationState":"INACTIVE"}))
    }
}
impl EventsService {
    async fn update_connection(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Name")?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        let connection = state.connections.get_mut(name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("Connection {name} does not exist"))
        })?;
        let auth_type =
            optional(body, "AuthorizationType").unwrap_or_else(|| connection.auth_type.clone());
        let auth_parameters = body
            .get("AuthParameters")
            .cloned()
            .unwrap_or_else(|| connection.auth_parameters.clone());
        validate_connection_auth(&auth_type, &auth_parameters)?;
        connection.auth_type = auth_type;
        connection.auth_parameters = auth_parameters;
        Ok(
            json!({"ConnectionArn":connection.arn,"ConnectionState":"AUTHORIZED","AuthorizationType":connection.auth_type}),
        )
    }

    async fn list_connections(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let prefix = optional(body, "NamePrefix").unwrap_or_default();
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let connections: Vec<_> = state
            .connections
            .values()
            .filter(|connection| connection.name.starts_with(&prefix))
            .map(|connection| json!({"Name":connection.name,"ConnectionArn":connection.arn,"ConnectionState":"AUTHORIZED","AuthorizationType":connection.auth_type}))
            .collect();
        paginated_response(body, "Connections", connections, "Limit")
    }

    async fn update_api_destination(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let name = required(body, "Name")?;
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let mut state = scope.write().await;
        if let Some(connection_arn) = optional(body, "ConnectionArn") {
            if !state
                .connections
                .values()
                .any(|connection| connection.arn == connection_arn)
            {
                return Err(EventsError::ResourceNotFound(
                    "Connection does not exist".into(),
                ));
            }
        }
        let destination = state.api_destinations.get_mut(name).ok_or_else(|| {
            EventsError::ResourceNotFound(format!("API destination {name} does not exist"))
        })?;
        if let Some(value) = optional(body, "ConnectionArn") {
            destination.connection_arn = value;
        }
        if let Some(value) = optional(body, "InvocationEndpoint") {
            if !value.starts_with("https://") {
                return Err(EventsError::Validation(
                    "InvocationEndpoint must use HTTPS".into(),
                ));
            }
            destination.endpoint = value;
        }
        if let Some(value) = optional(body, "HttpMethod") {
            validate_api_method(&value)?;
            destination.method = value;
        }
        if let Some(value) = body
            .get("InvocationRateLimitPerSecond")
            .and_then(Value::as_i64)
        {
            destination.rate_limit = Some(value);
        }
        Ok(json!({"ApiDestinationArn":destination.arn,"ApiDestinationState":"ACTIVE"}))
    }

    async fn list_api_destinations(
        &self,
        ctx: &RequestContext<'_>,
        body: &Value,
    ) -> Result<Value, EventsError> {
        let prefix = optional(body, "NamePrefix").unwrap_or_default();
        let connection = optional(body, "ConnectionArn");
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let state = scope.read().await;
        let destinations: Vec<_> = state.api_destinations.values()
            .filter(|destination| destination.name.starts_with(&prefix) && connection.as_ref().is_none_or(|arn| arn == &destination.connection_arn))
            .map(|destination| json!({"Name":destination.name,"ApiDestinationArn":destination.arn,"ApiDestinationState":"ACTIVE","ConnectionArn":destination.connection_arn,"InvocationEndpoint":destination.endpoint,"HttpMethod":destination.method,"InvocationRateLimitPerSecond":destination.rate_limit}))
            .collect();
        paginated_response(body, "ApiDestinations", destinations, "Limit")
    }
}

impl EventsService {
    async fn reconcile_worker(&self, operation: &str, ctx: &RequestContext<'_>, body: &Value) {
        if !matches!(
            operation,
            "PutRule" | "EnableRule" | "DisableRule" | "DeleteRule"
        ) {
            return;
        }
        let Some(name) = body.get("Name").and_then(Value::as_str) else {
            return;
        };
        let bus = bus_name(body);
        let key = format!("{}:{}:{bus}:{name}", ctx.account, ctx.region);
        if let Ok(mut workers) = self.workers.lock() {
            if let Some(worker) = workers.remove(&key) {
                worker.abort();
            }
        }
        if operation == "DeleteRule" {
            return;
        }
        let scope = self.store.scope(ctx.account, ctx.region).await;
        let rule = {
            scope
                .read()
                .await
                .buses
                .get(&bus)
                .and_then(|bus| bus.rules.get(name))
                .cloned()
        };
        let Some(rule) = rule else {
            return;
        };
        let has_pending = self
            .store
            .pending_firings("rule", &rule.arn)
            .is_ok_and(|rows| !rows.is_empty());
        if !(rule.enabled() && rule.schedule_expression.is_some()) && !has_pending {
            return;
        }
        let expression = rule
            .schedule_expression
            .as_deref()
            .and_then(|value| schedule::parse(value, false).ok());
        let registry = self.registry.clone();
        let store = self.store.clone();
        let clock = self.clock.clone();
        let http = self.http.clone();
        let account = ctx.account.to_string();
        let region = ctx.region.to_string();
        let name = name.to_string();
        let generation = rule.generation;
        let worker = tokio::spawn(async move {
            let now = clock.now();
            let (saved_cursor, saved_anchor) = match store.firing_cursor(
                "rule",
                &rule.arn,
                generation,
                now.unix_timestamp_nanos() as i64,
                now.unix_timestamp_nanos() as i64,
            ) {
                Ok(value) => value,
                Err(error) => {
                    tracing::error!(%error, "scheduled Rule cursor unavailable");
                    return;
                }
            };
            let mut cursor =
                OffsetDateTime::from_unix_timestamp_nanos(saved_cursor as i128).unwrap_or(now);
            let anchor =
                OffsetDateTime::from_unix_timestamp_nanos(saved_anchor as i128).unwrap_or(now);
            loop {
                if !deliver_pending_rule(&store, &registry, http.as_ref(), &account, &region, &rule)
                    .await
                {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                if !rule.enabled() {
                    break;
                }
                let Some(expression) = expression.as_ref() else {
                    break;
                };
                let Some(due) = schedule::next_after_anchored(expression, cursor, "UTC", anchor)
                    .ok()
                    .flatten()
                else {
                    break;
                };
                schedule::sleep_until(clock.as_ref(), due).await;
                let scope = store.scope(&account, &region).await;
                let guard = scope.read().await;
                let current = guard
                    .buses
                    .get("default")
                    .and_then(|bus| bus.rules.get(&name))
                    .filter(|current| current.enabled() && current.generation == generation)
                    .cloned();
                let Some(current) = current else {
                    break;
                };
                let event = json!({"version":"0","id":Uuid::new_v4().to_string(),
                    "detail-type":"Scheduled Event","source":"aws.events","account":account,
                    "time":due.format(&Rfc3339).unwrap_or_default(),"region":region,"resources":[],"detail":{}});
                let payload = json!({"rule":current,"event":event});
                if let Err(error) = store.enqueue_firing(
                    "rule",
                    &rule.arn,
                    generation,
                    due.unix_timestamp_nanos() as i64,
                    &payload,
                ) {
                    tracing::error!(%error, "scheduled Rule firing journal unavailable");
                    break;
                }
                drop(guard);
                if store.state_db().is_none() {
                    if let Some(registry) = registry.upgrade() {
                        let _ = deliver_rule_targets(
                            &registry,
                            &store,
                            http.as_ref(),
                            &current,
                            &event,
                            &region,
                            &account,
                        )
                        .await;
                    }
                }
                cursor = due;
            }
        });
        if let Ok(mut workers) = self.workers.lock() {
            workers.insert(key, worker);
        }
    }

    fn reap_finished_workers(&self) {
        if let Ok(mut workers) = self.workers.lock() {
            workers.retain(|_, worker| !worker.is_finished());
        }
    }

    fn abort_worker(&self, key: &str) {
        if let Ok(mut workers) = self.workers.lock() {
            if let Some(worker) = workers.remove(key) {
                worker.abort();
            }
        }
    }

    fn abort_prefix(&self, prefix: &str) {
        if let Ok(mut workers) = self.workers.lock() {
            let keys: Vec<_> = workers
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect();
            for key in keys {
                if let Some(worker) = workers.remove(&key) {
                    worker.abort();
                }
            }
        }
    }
}

fn replay_worker_key(account: &str, region: &str, name: &str) -> String {
    format!("replay:{account}:{region}:{name}")
}

async fn deliver_pending_rule(
    store: &EbStore,
    registry: &Weak<ServiceRegistry>,
    http: &dyn HttpClient,
    account: &str,
    region: &str,
    rule: &Rule,
) -> bool {
    let pending = match store.pending_firings("rule", &rule.arn) {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(%error, "scheduled Rule pending firings unavailable");
            return false;
        }
    };
    for (due_ns, payload) in pending {
        let Some((snapshot, event)) = payload
            .get("rule")
            .and_then(|value| serde_json::from_value::<Rule>(value.clone()).ok())
            .zip(payload.get("event").cloned())
        else {
            tracing::error!("scheduled Rule firing snapshot is invalid");
            return false;
        };
        match store.firing_ready(
            "rule",
            &rule.arn,
            due_ns,
            OffsetDateTime::now_utc().unix_timestamp_nanos() as i64,
        ) {
            Ok(true) => {}
            Ok(false) => return false,
            Err(error) => {
                tracing::error!(%error, "scheduled Rule retry metadata unavailable");
                return false;
            }
        }
        let Some(registry) = registry.upgrade() else {
            let _ = store.defer_firing(
                "rule",
                &rule.arn,
                due_ns,
                OffsetDateTime::now_utc().unix_timestamp_nanos() as i64,
            );
            return false;
        };
        if !deliver_rule_targets(&registry, store, http, &snapshot, &event, region, account).await {
            let max_age = snapshot
                .targets
                .iter()
                .map(|target| target.retry.maximum_age_seconds.unwrap_or(86_400))
                .max()
                .unwrap_or(86_400);
            let outer_limit = snapshot
                .targets
                .iter()
                .map(|target| {
                    if target
                        .extra
                        .get("RetryPolicy")
                        .and_then(|value| value.get("MaximumRetryAttempts"))
                        .is_some()
                    {
                        1
                    } else {
                        185
                    }
                })
                .max()
                .unwrap_or(185);
            let now_ns = OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
            let attempts = store
                .firing_attempts("rule", &rule.arn, due_ns)
                .unwrap_or(0);
            let exhausted = attempts + 1 >= outer_limit
                || now_ns.saturating_sub(due_ns) >= (max_age as i64).saturating_mul(1_000_000_000);
            let result = if exhausted {
                store.terminal_firing("rule", &rule.arn, due_ns, "retry policy exhausted")
            } else {
                store.defer_firing("rule", &rule.arn, due_ns, now_ns)
            };
            if let Err(error) = result {
                tracing::error!(%error, "scheduled Rule retry metadata unavailable");
            }
            return false;
        }
        if let Err(error) = store.complete_firing("rule", &rule.arn, due_ns) {
            tracing::error!(%error, "scheduled Rule firing completion unavailable");
            return false;
        }
    }
    true
}

async fn deliver_rule_targets(
    registry: &ServiceRegistry,
    store: &EbStore,
    http: &dyn HttpClient,
    rule: &Rule,
    event: &Value,
    region: &str,
    account: &str,
) -> bool {
    let event_json = event.to_string();
    let ingestion = event
        .get("time")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let correlation = CorrelationContext::root();
    let mut all_delivered = true;
    for target in &rule.targets {
        let mut effective_target = target.clone();
        if effective_target.role_arn.is_none() {
            effective_target.role_arn = rule.role_arn.clone();
        }
        let context = Context {
            rule_arn: &rule.arn,
            rule_name: &rule.name,
            event_json: &event_json,
            ingestion_time: ingestion,
        };
        let payload = transform::apply(&target_mode(target), event, &context);
        all_delivered &= deliver_event_target(
            FanoutContext {
                registry,
                store,
                http,
                region,
                account,
                correlation: correlation.child(),
            },
            &effective_target,
            payload,
            &rule.arn,
            &rule.name,
        )
        .await;
    }
    all_delivered
}

async fn deliver_event_target(
    context: FanoutContext<'_>,
    target: &Target,
    payload: String,
    rule_arn: &str,
    rule_name: &str,
) -> bool {
    let FanoutContext {
        registry,
        store,
        http,
        region,
        account,
        correlation,
    } = context;
    if target.arn.split(':').nth(2) == Some("logs") {
        let mut request = DeliveryRequest::from((target, payload));
        request.source_arn = Some(rule_arn.into());
        return delivery::deliver_logs(registry, &request, region, account, rule_name, correlation)
            .await
            .is_ok();
    }
    if let Ok(EbArn::ApiDestination {
        name,
        region: arn_region,
        account: arn_account,
    }) = EbArn::parse(&target.arn)
    {
        if !delivery::authorize_role_execution(
            registry,
            target.role_arn.as_deref(),
            "events",
            Some(rule_arn),
            "events:InvokeApiDestination",
            &target.arn,
            account,
        ) {
            return false;
        }
        let scope = store.scope(account, region).await;
        let configuration = if arn_region == region && arn_account == account {
            let state = scope.read().await;
            state.api_destinations.get(&name).and_then(|destination| {
                state
                    .connections
                    .values()
                    .find(|connection| connection.arn == destination.connection_arn)
                    .map(|connection| (destination.clone(), connection.clone()))
            })
        } else {
            None
        };
        let mut delivered = false;
        if let Some((destination, connection)) = configuration {
            for attempt in 0..=target.retry.maximum_attempts {
                match invoke_api_destination(http, &destination, &connection, &payload).await {
                    ApiDelivery::Success(_) => {
                        delivered = true;
                        break;
                    }
                    ApiDelivery::TerminalFailure => break,
                    ApiDelivery::RetriableFailure if attempt < target.retry.maximum_attempts => {
                        let delay_ms = 25_u64.saturating_mul(1_u64 << attempt.min(5));
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    }
                    ApiDelivery::RetriableFailure => break,
                }
            }
        }
        if !delivered {
            if let Some(dlq) = &target.dead_letter_arn {
                let request = DeliveryRequest {
                    source_service: "events",
                    source_arn: Some(rule_arn.into()),
                    arn: dlq.clone(),
                    payload,
                    role_arn: target.role_arn.clone(),
                    sqs_parameters: None,
                    target_parameters: None,
                    retry: RetryPolicy {
                        maximum_attempts: 0,
                        maximum_age_seconds: None,
                    },
                    dead_letter_arn: None,
                    scheduled_at: None,
                };
                return delivery::deliver(registry, &request, region, account)
                    .await
                    .is_ok();
            }
        }
        return delivered;
    }
    let mut request = DeliveryRequest::from((target, payload));
    request.source_arn = Some(rule_arn.into());
    delivery::deliver(registry, &request, region, account)
        .await
        .is_ok()
}

fn validate_connection_auth(auth_type: &str, parameters: &Value) -> Result<(), EventsError> {
    let required_string = |value: &Value, key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| EventsError::Validation(format!("AuthParameters.{key} is required")))
    };
    match auth_type {
        "API_KEY" => {
            let values = parameters.get("ApiKeyAuthParameters").unwrap_or(parameters);
            required_string(values, "ApiKeyName")?;
            required_string(values, "ApiKeyValue")?;
        }
        "BASIC" => {
            let values = parameters.get("BasicAuthParameters").unwrap_or(parameters);
            required_string(values, "Username")?;
            required_string(values, "Password")?;
        }
        "OAUTH_CLIENT_CREDENTIALS" => {
            let values = parameters.get("OAuthParameters").unwrap_or(parameters);
            let endpoint = required_string(values, "AuthorizationEndpoint")?;
            if !endpoint.starts_with("https://") {
                return Err(EventsError::Validation(
                    "OAuth AuthorizationEndpoint must use HTTPS".into(),
                ));
            }
            let clients = values.get("ClientParameters").ok_or_else(|| {
                EventsError::Validation("OAuth ClientParameters is required".into())
            })?;
            required_string(clients, "ClientID")?;
            required_string(clients, "ClientSecret")?;
            validate_api_method(
                values
                    .get("HttpMethod")
                    .and_then(Value::as_str)
                    .unwrap_or("POST"),
            )?;
        }
        _ => {
            return Err(EventsError::Validation(
                "AuthorizationType must be API_KEY, BASIC, or OAUTH_CLIENT_CREDENTIALS".into(),
            ))
        }
    }
    Ok(())
}

fn validate_api_method(method: &str) -> Result<(), EventsError> {
    let parsed = Method::from_bytes(method.as_bytes())
        .map_err(|_| EventsError::Validation("invalid HttpMethod".into()))?;
    if matches!(
        parsed,
        Method::GET
            | Method::POST
            | Method::PUT
            | Method::PATCH
            | Method::DELETE
            | Method::HEAD
            | Method::OPTIONS
    ) {
        Ok(())
    } else {
        Err(EventsError::Validation("invalid HttpMethod".into()))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ApiDelivery {
    Success(Value),
    RetriableFailure,
    TerminalFailure,
}

pub(crate) async fn invoke_api_destination(
    http: &dyn HttpClient,
    destination: &ApiDestination,
    connection: &Connection,
    payload: &str,
) -> ApiDelivery {
    let Ok(method) = Method::from_bytes(destination.method.as_bytes()) else {
        return ApiDelivery::TerminalFailure;
    };
    let mut request = HttpRequest::new(method, destination.endpoint.clone());
    if apply_http_parameters(
        &mut request,
        connection.auth_parameters.get("InvocationHttpParameters"),
    )
    .is_err()
    {
        return ApiDelivery::TerminalFailure;
    }
    let auth_result = match connection.auth_type.as_str() {
        "API_KEY" => {
            let values = connection
                .auth_parameters
                .get("ApiKeyAuthParameters")
                .unwrap_or(&connection.auth_parameters);
            match (
                values.get("ApiKeyName").and_then(Value::as_str),
                values.get("ApiKeyValue").and_then(Value::as_str),
            ) {
                (Some(name), Some(value)) => request.header(name, value),
                _ => Err(HttpError),
            }
        }
        "BASIC" => {
            let values = connection
                .auth_parameters
                .get("BasicAuthParameters")
                .unwrap_or(&connection.auth_parameters);
            match (
                values.get("Username").and_then(Value::as_str),
                values.get("Password").and_then(Value::as_str),
            ) {
                (Some(username), Some(password)) => request.header(
                    "authorization",
                    &format!("Basic {}", base64(&format!("{username}:{password}"))),
                ),
                _ => Err(HttpError),
            }
        }
        "OAUTH_CLIENT_CREDENTIALS" => match oauth_token(http, &connection.auth_parameters).await {
            Some(token) => request.header("authorization", &format!("Bearer {token}")),
            None => return ApiDelivery::RetriableFailure,
        },
        _ => return ApiDelivery::TerminalFailure,
    };
    if auth_result.is_err() {
        return ApiDelivery::TerminalFailure;
    }
    request.body = payload.to_string();
    match http.send(request).await {
        Ok(response) if (200..300).contains(&response.status) => {
            let value = if response.body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&response.body).unwrap_or_else(|_| {
                    Value::String(String::from_utf8_lossy(&response.body).into_owned())
                })
            };
            ApiDelivery::Success(value)
        }
        Ok(response) if response.status == 429 || response.status >= 500 => {
            ApiDelivery::RetriableFailure
        }
        Ok(_) => ApiDelivery::TerminalFailure,
        Err(_) => ApiDelivery::RetriableFailure,
    }
}

fn apply_http_parameters(
    request: &mut HttpRequest,
    parameters: Option<&Value>,
) -> Result<(), HttpError> {
    let Some(parameters) = parameters else {
        return Ok(());
    };
    if let Some(headers) = parameters.get("HeaderParameters").and_then(Value::as_array) {
        for header in headers {
            if let (Some(key), Some(value)) = (
                header.get("Key").and_then(Value::as_str),
                header.get("Value").and_then(Value::as_str),
            ) {
                request.header(key, value)?;
            }
        }
    }
    if let Some(query) = parameters
        .get("QueryStringParameters")
        .and_then(Value::as_array)
    {
        append_query(
            &mut request.url,
            query.iter().filter_map(|parameter| {
                Some((
                    parameter.get("Key")?.as_str()?,
                    parameter.get("Value")?.as_str()?,
                ))
            }),
        );
    }
    Ok(())
}

async fn oauth_token(http: &dyn HttpClient, parameters: &Value) -> Option<String> {
    let oauth = parameters.get("OAuthParameters").unwrap_or(parameters);
    let endpoint = oauth.get("AuthorizationEndpoint")?.as_str()?;
    if !endpoint.starts_with("https://") {
        return None;
    }
    let clients = oauth.get("ClientParameters")?;
    let client_id = clients.get("ClientID")?.as_str()?;
    let client_secret = clients.get("ClientSecret")?.as_str()?;
    let method = Method::from_bytes(
        oauth
            .get("HttpMethod")
            .and_then(Value::as_str)
            .unwrap_or("POST")
            .as_bytes(),
    )
    .ok()?;
    let http_parameters = oauth.get("OAuthHttpParameters");
    let mut request = HttpRequest::new(method.clone(), endpoint);
    apply_http_parameters(&mut request, http_parameters).ok()?;
    let mut form = vec![
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];
    if let Some(body_parameters) = http_parameters
        .and_then(|value| value.get("BodyParameters"))
        .and_then(Value::as_array)
    {
        form.extend(body_parameters.iter().filter_map(|parameter| {
            Some((
                parameter.get("Key")?.as_str()?,
                parameter.get("Value")?.as_str()?,
            ))
        }));
    }
    if method == Method::GET {
        append_query(&mut request.url, form);
    } else {
        request.body = form_body(form);
        request
            .header("content-type", "application/x-www-form-urlencoded")
            .ok()?;
    }
    let response = http.send(request).await.ok()?;
    if !(200..300).contains(&response.status) {
        return None;
    }
    serde_json::from_slice::<Value>(&response.body)
        .ok()?
        .get("access_token")?
        .as_str()
        .map(str::to_string)
}

fn append_query<'a>(url: &mut String, values: impl IntoIterator<Item = (&'a str, &'a str)>) {
    for (key, value) in values {
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str(&form_encode(key));
        url.push('=');
        url.push_str(&form_encode(value));
    }
}

fn form_body<'a>(values: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    values
        .into_iter()
        .map(|(key, value)| format!("{}={}", form_encode(key), form_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn base64(value: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(char::from(TABLE[((value >> 18) & 63) as usize]));
        output.push(char::from(TABLE[((value >> 12) & 63) as usize]));
        output.push(if chunk.len() > 1 {
            char::from(TABLE[((value >> 6) & 63) as usize])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(TABLE[(value & 63) as usize])
        } else {
            '='
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_validation_preserves_nested_json() {
        let raw: Value = serde_json::from_str("{\"nested\":{\"n\":1},\"a\":[true,null]}").unwrap();
        assert!(raw.is_object());
        assert_eq!(raw["nested"]["n"], 1);
    }

    #[test]
    fn oauth_connection_parameters_are_validated_without_external_processes() {
        let valid = json!({
            "OAuthParameters": {
                "AuthorizationEndpoint": "https://auth.example/token",
                "HttpMethod": "POST",
                "ClientParameters": {"ClientID":"client","ClientSecret":"secret"}
            }
        });
        assert!(validate_connection_auth("OAUTH_CLIENT_CREDENTIALS", &valid).is_ok());
        assert!(validate_connection_auth(
            "OAUTH_CLIENT_CREDENTIALS",
            &json!({"OAuthParameters":{"AuthorizationEndpoint":"https://auth.example/token"}})
        )
        .is_err());
        assert!(validate_api_method("TRACE").is_err());
    }

    #[tokio::test]
    async fn injectable_http_client_records_api_key_basic_and_oauth() {
        use std::collections::VecDeque;

        use crate::http_client::HttpResponse;

        struct Recorder {
            requests: Mutex<Vec<HttpRequest>>,
            responses: Mutex<VecDeque<HttpResponse>>,
        }

        #[async_trait::async_trait]
        impl HttpClient for Recorder {
            async fn send(
                &self,
                request: HttpRequest,
            ) -> Result<HttpResponse, crate::http_client::HttpError> {
                self.requests.lock().unwrap().push(request);
                self.responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or(crate::http_client::HttpError)
            }
        }

        let http = Recorder {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::from([
                HttpResponse {
                    status: 200,
                    body: br#"{"access_token":"test-token"}"#.to_vec(),
                },
                HttpResponse {
                    status: 200,
                    body: br#"{"auth":"oauth"}"#.to_vec(),
                },
                HttpResponse {
                    status: 200,
                    body: br#"{"auth":"api-key"}"#.to_vec(),
                },
                HttpResponse {
                    status: 200,
                    body: br#"{"auth":"basic"}"#.to_vec(),
                },
            ])),
        };
        let destination = ApiDestination {
            name: "api".into(),
            arn: "arn:aws:events:r:a:api-destination/api".into(),
            connection_arn: "arn:aws:events:r:a:connection/c".into(),
            endpoint: "https://api.example/invoke".into(),
            method: "POST".into(),
            rate_limit: None,
            tags: BTreeMap::new(),
        };
        let oauth = Connection {
            name: "oauth".into(),
            arn: destination.connection_arn.clone(),
            auth_type: "OAUTH_CLIENT_CREDENTIALS".into(),
            auth_parameters: json!({
                "OAuthParameters": {
                    "AuthorizationEndpoint": "https://auth.example/token",
                    "HttpMethod": "POST",
                    "ClientParameters": {"ClientID":"client","ClientSecret":"secret"}
                }
            }),
            tags: BTreeMap::new(),
        };
        assert_eq!(
            invoke_api_destination(&http, &destination, &oauth, "{\"ok\":true}").await,
            ApiDelivery::Success(json!({"auth":"oauth"}))
        );
        let api_key = Connection {
            name: "key".into(),
            arn: destination.connection_arn.clone(),
            auth_type: "API_KEY".into(),
            auth_parameters: json!({"ApiKeyAuthParameters":{"ApiKeyName":"x-api-key","ApiKeyValue":"key-secret"}}),
            tags: BTreeMap::new(),
        };
        assert!(matches!(
            invoke_api_destination(&http, &destination, &api_key, "{}").await,
            ApiDelivery::Success(_)
        ));
        let basic = Connection {
            name: "basic".into(),
            arn: destination.connection_arn.clone(),
            auth_type: "BASIC".into(),
            auth_parameters: json!({"BasicAuthParameters":{"Username":"user","Password":"pass"}}),
            tags: BTreeMap::new(),
        };
        assert!(matches!(
            invoke_api_destination(&http, &destination, &basic, "{}").await,
            ApiDelivery::Success(_)
        ));

        let requests = http.requests.lock().unwrap();
        assert!(requests[0].body.contains("client_secret=secret"));
        assert_eq!(
            requests[1]
                .headers
                .iter()
                .find(|(name, _)| name == "authorization")
                .map(|(_, value)| value.as_str()),
            Some("Bearer test-token")
        );
        assert!(requests[2]
            .headers
            .contains(&("x-api-key".into(), "key-secret".into())));
        assert!(requests[3]
            .headers
            .contains(&("authorization".into(), "Basic dXNlcjpwYXNz".into())));
    }

    #[test]
    fn target_rejects_multiple_input_modes() {
        assert!(parse_target(
            &json!({"Id":"x","Arn":"arn:aws:sqs:r:a:q","Input":"{}","InputPath":"$.detail"})
        )
        .is_err());
    }

    #[test]
    fn target_rejects_invalid_input_transformer_map() {
        let base = "arn:aws:sqs:us-east-1:000000000000:q";
        for transformer in [
            json!({"InputTemplate":"<x>","InputPathsMap":{"x":42}}),
            json!({"InputTemplate":"<x>","InputPathsMap":{"x":"not-a-path"}}),
            json!({"InputTemplate":"<x>","InputPathsMap":{"bad.key":"$.detail.x"}}),
            json!({"InputTemplate":"","InputPathsMap":{}}),
        ] {
            assert!(
                parse_target(&json!({"Id":"x","Arn":base,"InputTransformer":transformer})).is_err()
            );
        }
    }

    #[test]
    fn pagination_is_deterministic_and_validated() {
        let values = vec![json!("a"), json!("b"), json!("c")];
        let first =
            paginated_response(&json!({"Limit":2}), "Items", values.clone(), "Limit").unwrap();
        assert_eq!(first["Items"], json!(["a", "b"]));
        assert_eq!(first["NextToken"], "2");

        let second = paginated_response(
            &json!({"Limit":2,"NextToken":first["NextToken"]}),
            "Items",
            values,
            "Limit",
        )
        .unwrap();
        assert_eq!(second["Items"], json!(["c"]));
        assert!(second.get("NextToken").is_none());
        assert!(paginated_response(&json!({"Limit":0}), "Items", vec![], "Limit").is_err());
        assert!(paginated_response(
            &json!({"NextToken":"not-a-token"}),
            "Items",
            vec![],
            "Limit"
        )
        .is_err());
    }

    #[test]
    fn retention_is_validated_and_prunes_at_the_boundary() {
        assert!(retention_days(&json!({"RetentionDays":-1})).is_err());
        assert!(retention_days(&json!({"RetentionDays":"1"})).is_err());
        assert_eq!(
            retention_days(&json!({"RetentionDays":0})).unwrap(),
            Some(0)
        );

        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let mut archive = Archive {
            name: "archive".into(),
            arn: "arn:aws:events:r:a:archive/archive".into(),
            source_arn: "arn:aws:events:r:a:event-bus/default".into(),
            description: None,
            event_pattern: None,
            retention_days: 1,
            tags: BTreeMap::new(),
            events: vec![
                ArchivedEvent {
                    event: json!({"id":"expired"}),
                    time: now - time::Duration::days(1) - time::Duration::seconds(1),
                },
                ArchivedEvent {
                    event: json!({"id":"boundary"}),
                    time: now - time::Duration::days(1),
                },
            ],
        };
        prune_archive(&mut archive, now);
        assert_eq!(archive.events.len(), 1);
        assert_eq!(archive.events[0].event["id"], "boundary");
    }

    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    fn test_service(now: OffsetDateTime) -> EventsService {
        EventsService::new(
            Arc::new(EbStore::new()),
            Weak::new(),
            Arc::new(FixedClock(now)),
            Arc::new(crate::http_client::CurlHttpClient),
        )
    }

    #[tokio::test]
    async fn archive_reads_updates_and_replay_prune_expired_events() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let service = test_service(now);
        let ctx = RequestContext {
            account: "a",
            region: "r",
            request_id: "request",
        };
        let scope = service.store.scope(ctx.account, ctx.region).await;
        let bus_arn = scope.read().await.buses["default"].arn.clone();
        {
            let mut state = scope.write().await;
            for name in ["describe", "list", "update", "replay"] {
                state.archives.insert(
                    name.into(),
                    Archive {
                        name: name.into(),
                        arn: format!("arn:aws:events:r:a:archive/{name}"),
                        source_arn: bus_arn.clone(),
                        description: None,
                        event_pattern: None,
                        retention_days: 1,
                        tags: BTreeMap::new(),
                        events: vec![ArchivedEvent {
                            event: json!({"version":"0","id":name,"time":(now - time::Duration::days(2)).format(&Rfc3339).unwrap()}),
                            time: now - time::Duration::days(2),
                        }],
                    },
                );
            }
        }

        let described = service
            .describe_archive(&ctx, &json!({"ArchiveName":"describe"}))
            .await
            .unwrap();
        assert_eq!(described["EventCount"], 0);
        service.list_archives(&ctx, &json!({})).await.unwrap();
        service
            .update_archive(&ctx, &json!({"ArchiveName":"update","RetentionDays":1}))
            .await
            .unwrap();
        service
            .start_replay(
                &ctx,
                &json!({
                    "ReplayName":"replay-run",
                    "EventSourceArn":"arn:aws:events:r:a:archive/replay",
                    "EventStartTime":now.unix_timestamp() - 300_000,
                    "EventEndTime":now.unix_timestamp(),
                    "Destination":{"Arn":bus_arn}
                }),
            )
            .await
            .unwrap();
        tokio::task::yield_now().await;

        let state = scope.read().await;
        assert!(state
            .archives
            .values()
            .all(|archive| archive.events.is_empty()));
        assert_eq!(state.replays["replay-run"].state, "COMPLETED");
        drop(state);
        for _ in 0..10 {
            if service.workers.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(service.workers.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn completed_replay_cannot_be_cancelled_and_handles_are_reaped() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let service = test_service(now);
        let ctx = RequestContext {
            account: "a",
            region: "r",
            request_id: "request",
        };
        let scope = service.store.scope(ctx.account, ctx.region).await;
        scope.write().await.replays.insert(
            "completed".into(),
            Replay {
                name: "completed".into(),
                arn: "arn:aws:events:r:a:replay/completed".into(),
                source_arn: "arn:aws:events:r:a:archive/source".into(),
                destination: json!({}),
                start: now,
                end: now,
                state: "COMPLETED".into(),
            },
        );
        assert!(matches!(
            service
                .cancel_replay(&ctx, &json!({"ReplayName":"completed"}))
                .await,
            Err(EventsError::Validation(_))
        ));

        service
            .workers
            .lock()
            .unwrap()
            .insert("finished".into(), tokio::spawn(async {}));
        tokio::task::yield_now().await;
        service.reap_finished_workers();
        assert!(service.workers.lock().unwrap().is_empty());
    }

    #[test]
    fn untransformed_bus_target_keeps_the_canonical_envelope_payload() {
        let target = parse_target(&json!({
            "Id":"bus",
            "Arn":"arn:aws:events:r:a:event-bus/destination"
        }))
        .unwrap();
        let event = json!({
            "version":"0","id":"event","detail-type":"type","source":"source",
            "account":"a","time":"2024-01-01T00:00:00Z","region":"r",
            "resources":[],"detail":{"nested":true}
        });
        let event_json = event.to_string();
        let context = Context {
            rule_arn: "arn:aws:events:r:a:rule/rule",
            rule_name: "rule",
            event_json: &event_json,
            ingestion_time: "2024-01-01T00:00:00Z",
        };
        let payload = transform::apply(&target_mode(&target), &event, &context);
        assert_eq!(serde_json::from_str::<Value>(&payload).unwrap(), event);
    }
}
