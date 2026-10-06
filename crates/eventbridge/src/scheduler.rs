use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, Weak};

use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use uuid::Uuid;

use locallycloud_core::registry::ServiceRegistry;

use crate::arn::EbArn;
use crate::delivery::{self, DeliveryRequest};
use crate::error::SchedulerError;
use crate::model::{RetryPolicy, Schedule, ScheduleGroup};
use crate::schedule::{self, Clock, ScheduleExpr};
use crate::store::EbStore;

pub struct SchedulerService {
    pub store: Arc<EbStore>,
    registry: Weak<ServiceRegistry>,
    clock: Arc<dyn Clock>,
    workers: Mutex<HashMap<String, JoinHandle<()>>>,
}

impl SchedulerService {
    pub fn new(
        store: Arc<EbStore>,
        registry: Weak<ServiceRegistry>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            registry,
            clock,
            workers: Mutex::new(HashMap::new()),
        }
    }

    pub async fn dispatch(
        &self,
        operation: &str,
        name: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, SchedulerError> {
        let mutation = matches!(
            operation,
            "CreateSchedule"
                | "UpdateSchedule"
                | "DeleteSchedule"
                | "CreateScheduleGroup"
                | "DeleteScheduleGroup"
                | "TagResource"
                | "UntagResource"
        );
        let _write = if mutation {
            Some(self.store.scheduler_gate.write().await)
        } else {
            None
        };
        let _read = if !mutation {
            Some(self.store.scheduler_gate.read().await)
        } else {
            None
        };
        if !self.store.healthy() {
            return Err(SchedulerError::Internal(
                "durable Scheduler state is unavailable".into(),
            ));
        }
        self.reap_finished_workers();
        let result = match operation {
            "CreateSchedule" => self.create_schedule(name, account, region, body).await,
            "GetSchedule" => self.get_schedule(name, account, region, body).await,
            "UpdateSchedule" => self.update_schedule(name, account, region, body).await,
            "DeleteSchedule" => self.delete_schedule(name, account, region, body).await,
            "ListSchedules" => self.list_schedules(account, region, body).await,
            "CreateScheduleGroup" => self.create_group(name, account, region, body).await,
            "GetScheduleGroup" => self.get_group(name, account, region).await,
            "DeleteScheduleGroup" => self.delete_group(name, account, region).await,
            "ListScheduleGroups" => self.list_groups(account, region, body).await,
            "TagResource" => self.tag_resource(name, account, region, body).await,
            "UntagResource" => self.untag_resource(name, account, region, body).await,
            "ListTagsForResource" => self.list_tags(name, account, region).await,
            _ => Err(SchedulerError::ResourceNotFound("route not found".into())),
        }?;
        if mutation {
            self.store
                .persist_scheduler(account, region, self.clock.now())
                .await
                .map_err(SchedulerError::Internal)?;
            if matches!(operation, "CreateSchedule" | "UpdateSchedule") {
                let schedule_name = name.ok_or_else(|| {
                    SchedulerError::Validation("schedule name is required".into())
                })?;
                let scope = self.store.scope(account, region).await;
                let schedule = scope
                    .read()
                    .await
                    .schedules
                    .get(&(group(body), schedule_name.into()))
                    .cloned();
                if let Some(schedule) = schedule {
                    self.reconcile(account, region, &schedule).await;
                }
            }
        }
        Ok(result)
    }
}

impl Drop for SchedulerService {
    fn drop(&mut self) {
        if let Ok(mut workers) = self.workers.lock() {
            for (_, worker) in workers.drain() {
                worker.abort();
            }
        }
    }
}

fn name<'a>(name: Option<&'a str>, resource: &str) -> Result<&'a str, SchedulerError> {
    name.filter(|value| !value.is_empty())
        .ok_or_else(|| SchedulerError::Validation(format!("{resource} name is required")))
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn group(body: &Value) -> String {
    body.get("GroupName")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("default")
        .to_string()
}

fn parse_time(value: Option<&Value>) -> Result<Option<OffsetDateTime>, SchedulerError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => OffsetDateTime::from_unix_timestamp(
            number
                .as_i64()
                .or_else(|| number.as_f64().map(|value| value as i64))
                .ok_or_else(|| SchedulerError::Validation("invalid timestamp".into()))?,
        )
        .map(Some)
        .map_err(|_| SchedulerError::Validation("invalid timestamp".into())),
        Some(Value::String(value)) => OffsetDateTime::parse(value, &Rfc3339)
            .map(Some)
            .map_err(|_| SchedulerError::Validation("invalid timestamp".into())),
        _ => Err(SchedulerError::Validation("invalid timestamp".into())),
    }
}

fn validate_date_range(
    start: Option<OffsetDateTime>,
    end: Option<OffsetDateTime>,
) -> Result<(), SchedulerError> {
    if start.zip(end).is_some_and(|(start, end)| start > end) {
        return Err(SchedulerError::Validation(
            "StartDate must not be after EndDate".into(),
        ));
    }
    Ok(())
}

fn paginate(body: &Value, key: &str, values: Vec<Value>) -> Result<Value, SchedulerError> {
    let start = match body.get("NextToken") {
        None => 0,
        Some(Value::String(token)) => token
            .parse::<usize>()
            .map_err(|_| SchedulerError::Validation("NextToken is invalid".into()))?,
        _ => return Err(SchedulerError::Validation("NextToken is invalid".into())),
    };
    let limit = match body.get("MaxResults") {
        None => 100,
        Some(value) => value
            .as_u64()
            .filter(|value| (1..=100).contains(value))
            .ok_or_else(|| {
                SchedulerError::Validation("MaxResults must be between 1 and 100".into())
            })? as usize,
    };
    let total = values.len();
    if start > total {
        return Err(SchedulerError::Validation("NextToken is invalid".into()));
    }
    let end = start.saturating_add(limit).min(total);
    let page = values.into_iter().skip(start).take(end - start).collect();
    let mut response = serde_json::Map::new();
    response.insert(key.into(), Value::Array(page));
    if end < total {
        response.insert("NextToken".into(), Value::String(end.to_string()));
    }
    Ok(Value::Object(response))
}

fn flexible_window(value: Option<&Value>) -> Result<Value, SchedulerError> {
    let value =
        value.ok_or_else(|| SchedulerError::Validation("FlexibleTimeWindow is required".into()))?;
    let mode = value
        .get("Mode")
        .and_then(Value::as_str)
        .ok_or_else(|| SchedulerError::Validation("FlexibleTimeWindow.Mode is required".into()))?;
    let maximum = value.get("MaximumWindowInMinutes").and_then(Value::as_u64);
    match (mode, maximum) {
        ("OFF", None) => Ok(json!({"Mode":"OFF"})),
        ("FLEXIBLE", Some(minutes @ 1..=1440)) => {
            Ok(json!({"Mode":"FLEXIBLE","MaximumWindowInMinutes":minutes}))
        }
        _ => Err(SchedulerError::Validation(
            "invalid FlexibleTimeWindow".into(),
        )),
    }
}

fn validate_target(value: Option<&Value>) -> Result<Value, SchedulerError> {
    let value = value.ok_or_else(|| SchedulerError::Validation("Target is required".into()))?;
    if value
        .get("Arn")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(SchedulerError::Validation("Target.Arn is required".into()));
    }
    if value
        .get("RoleArn")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(SchedulerError::Validation(
            "Target.RoleArn is required".into(),
        ));
    }
    if let Some(retry) = value.get("RetryPolicy") {
        let retry = retry.as_object().ok_or_else(|| {
            SchedulerError::Validation("Target.RetryPolicy must be an object".into())
        })?;
        if retry
            .get("MaximumRetryAttempts")
            .is_some_and(|attempts| !attempts.as_u64().is_some_and(|attempts| attempts <= 185))
        {
            return Err(SchedulerError::Validation(
                "Target.RetryPolicy.MaximumRetryAttempts must be between 0 and 185".into(),
            ));
        }
        if retry
            .get("MaximumEventAgeInSeconds")
            .is_some_and(|age| !age.as_u64().is_some_and(|age| (60..=86400).contains(&age)))
        {
            return Err(SchedulerError::Validation(
                "Target.RetryPolicy.MaximumEventAgeInSeconds must be between 60 and 86400".into(),
            ));
        }
    }
    Ok(value.clone())
}
fn schedule_description(body: &Value) -> Result<Option<String>, SchedulerError> {
    body.get("Description")
        .map(|value| {
            value
                .as_str()
                .filter(|value| value.chars().count() <= 512)
                .map(str::to_owned)
                .ok_or_else(|| {
                    SchedulerError::Validation(
                        "Description must be a string of at most 512 characters".into(),
                    )
                })
        })
        .transpose()
}

impl SchedulerService {
    async fn create_schedule(
        &self,
        path_name: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, SchedulerError> {
        let schedule_name = name(path_name, "schedule")?;
        if !valid_name(schedule_name) {
            return Err(SchedulerError::Validation("invalid schedule name".into()));
        }
        let group_name = group(body);
        let description = schedule_description(body)?;
        let expression = body
            .get("ScheduleExpression")
            .and_then(Value::as_str)
            .ok_or_else(|| SchedulerError::Validation("ScheduleExpression is required".into()))?
            .to_string();
        schedule::parse(&expression, true).map_err(SchedulerError::Validation)?;
        let timezone = body
            .get("ScheduleExpressionTimezone")
            .and_then(Value::as_str)
            .unwrap_or("UTC")
            .to_string();
        schedule::timezone_offset(&timezone, self.clock.now())
            .map_err(SchedulerError::Validation)?;
        let window = flexible_window(body.get("FlexibleTimeWindow"))?;
        let target = validate_target(body.get("Target"))?;
        let state_name = body
            .get("State")
            .and_then(Value::as_str)
            .unwrap_or("ENABLED");
        if !matches!(state_name, "ENABLED" | "DISABLED") {
            return Err(SchedulerError::Validation("invalid State".into()));
        }
        let action = body
            .get("ActionAfterCompletion")
            .and_then(Value::as_str)
            .unwrap_or("NONE");
        if !matches!(action, "NONE" | "DELETE") {
            return Err(SchedulerError::Validation(
                "invalid ActionAfterCompletion".into(),
            ));
        }
        let start_date = parse_time(body.get("StartDate"))?;
        let end_date = parse_time(body.get("EndDate"))?;
        validate_date_range(start_date, end_date)?;
        let scope = self.store.scope(account, region).await;
        let mut state = scope.write().await;
        if !state.schedule_groups.contains_key(&group_name) {
            return Err(SchedulerError::ResourceNotFound(format!(
                "Schedule group {group_name} does not exist"
            )));
        }
        let key = (group_name.clone(), schedule_name.to_string());
        if state.schedules.contains_key(&key) {
            return Err(SchedulerError::Conflict(format!(
                "Schedule {schedule_name} already exists"
            )));
        }
        let arn = EbArn::Schedule {
            region: region.into(),
            account: account.into(),
            group: group_name.clone(),
            name: schedule_name.into(),
        }
        .to_string();
        let schedule = Schedule {
            name: schedule_name.into(),
            description,
            arn: arn.clone(),
            group: group_name,
            expression,
            timezone,
            flexible_window: window,
            start_date,
            end_date,
            state: state_name.into(),
            action_after_completion: action.into(),
            kms_key_arn: body
                .get("KmsKeyArn")
                .and_then(Value::as_str)
                .map(str::to_string),
            target,
            tags: parse_scheduler_tags(body),
            generation: Uuid::new_v4().as_u128() as u64,
        };
        state.schedules.insert(key, schedule.clone());
        drop(state);
        Ok(json!({"ScheduleArn":arn}))
    }

    async fn get_schedule(
        &self,
        path_name: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, SchedulerError> {
        let schedule_name = name(path_name, "schedule")?;
        let group_name = group(body);
        let scope = self.store.scope(account, region).await;
        let state = scope.read().await;
        let schedule = state
            .schedules
            .get(&(group_name, schedule_name.into()))
            .ok_or_else(|| {
                SchedulerError::ResourceNotFound(format!("Schedule {schedule_name} does not exist"))
            })?;
        Ok(schedule_json(schedule))
    }

    async fn update_schedule(
        &self,
        path_name: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, SchedulerError> {
        let schedule_name = name(path_name, "schedule")?;
        let group_name = group(body);
        let description = schedule_description(body)?;
        let expression = body
            .get("ScheduleExpression")
            .and_then(Value::as_str)
            .ok_or_else(|| SchedulerError::Validation("ScheduleExpression is required".into()))?
            .to_string();
        schedule::parse(&expression, true).map_err(SchedulerError::Validation)?;
        let timezone = body
            .get("ScheduleExpressionTimezone")
            .and_then(Value::as_str)
            .unwrap_or("UTC")
            .to_string();
        schedule::timezone_offset(&timezone, self.clock.now())
            .map_err(SchedulerError::Validation)?;
        let window = flexible_window(body.get("FlexibleTimeWindow"))?;
        let target = validate_target(body.get("Target"))?;
        let updated_state = body
            .get("State")
            .and_then(Value::as_str)
            .unwrap_or("ENABLED");
        if !matches!(updated_state, "ENABLED" | "DISABLED") {
            return Err(SchedulerError::Validation("invalid State".into()));
        }
        let action = body
            .get("ActionAfterCompletion")
            .and_then(Value::as_str)
            .unwrap_or("NONE");
        if !matches!(action, "NONE" | "DELETE") {
            return Err(SchedulerError::Validation(
                "invalid ActionAfterCompletion".into(),
            ));
        }
        let start_date = parse_time(body.get("StartDate"))?;
        let end_date = parse_time(body.get("EndDate"))?;
        validate_date_range(start_date, end_date)?;
        let scope = self.store.scope(account, region).await;
        let mut state = scope.write().await;
        let schedule = state
            .schedules
            .get_mut(&(group_name, schedule_name.into()))
            .ok_or_else(|| {
                SchedulerError::ResourceNotFound(format!("Schedule {schedule_name} does not exist"))
            })?;
        schedule.description = description;
        schedule.expression = expression;
        schedule.timezone = timezone;
        schedule.flexible_window = window;
        schedule.start_date = start_date;
        schedule.end_date = end_date;
        schedule.state = updated_state.into();
        schedule.action_after_completion = action.into();
        schedule.kms_key_arn = body
            .get("KmsKeyArn")
            .and_then(Value::as_str)
            .map(str::to_string);
        schedule.target = target;
        schedule.generation += 1;
        let arn = schedule.arn.clone();
        drop(state);
        Ok(json!({"ScheduleArn":arn}))
    }

    async fn delete_schedule(
        &self,
        path_name: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, SchedulerError> {
        let schedule_name = name(path_name, "schedule")?;
        let group_name = group(body);
        let scope = self.store.scope(account, region).await;
        if scope
            .write()
            .await
            .schedules
            .remove(&(group_name.clone(), schedule_name.into()))
            .is_none()
        {
            return Err(SchedulerError::ResourceNotFound(format!(
                "Schedule {schedule_name} does not exist"
            )));
        }
        self.abort(&worker_key(account, region, &group_name, schedule_name));
        Ok(json!({}))
    }

    async fn list_schedules(
        &self,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, SchedulerError> {
        let group_filter = body.get("GroupName").and_then(Value::as_str);
        let prefix = body.get("NamePrefix").and_then(Value::as_str).unwrap_or("");
        let scope = self.store.scope(account, region).await;
        let state = scope.read().await;
        let schedules: Vec<_> = state
            .schedules
            .values()
            .filter(|schedule| {
                group_filter.is_none_or(|group| group == schedule.group)
                    && schedule.name.starts_with(prefix)
            })
            .map(schedule_summary)
            .collect();
        paginate(body, "Schedules", schedules)
    }
}
impl SchedulerService {
    async fn create_group(
        &self,
        path_name: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, SchedulerError> {
        let group_name = name(path_name, "schedule group")?;
        if !valid_name(group_name) {
            return Err(SchedulerError::Validation(
                "invalid schedule group name".into(),
            ));
        }
        let scope = self.store.scope(account, region).await;
        let mut state = scope.write().await;
        if state.schedule_groups.contains_key(group_name) {
            return Err(SchedulerError::Conflict(format!(
                "Schedule group {group_name} already exists"
            )));
        }
        let arn = EbArn::ScheduleGroup {
            region: region.into(),
            account: account.into(),
            name: group_name.into(),
        }
        .to_string();
        let now = self.clock.now();
        state.schedule_groups.insert(
            group_name.into(),
            ScheduleGroup {
                name: group_name.into(),
                arn: arn.clone(),
                created_at: now,
                modified_at: now,
                tags: parse_scheduler_tags(body),
            },
        );
        Ok(json!({"ScheduleGroupArn":arn}))
    }

    async fn get_group(
        &self,
        path_name: Option<&str>,
        account: &str,
        region: &str,
    ) -> Result<Value, SchedulerError> {
        let group_name = name(path_name, "schedule group")?;
        let scope = self.store.scope(account, region).await;
        let state = scope.read().await;
        let group = state.schedule_groups.get(group_name).ok_or_else(|| {
            SchedulerError::ResourceNotFound(format!("Schedule group {group_name} does not exist"))
        })?;
        Ok(group_json(group))
    }

    async fn delete_group(
        &self,
        path_name: Option<&str>,
        account: &str,
        region: &str,
    ) -> Result<Value, SchedulerError> {
        let group_name = name(path_name, "schedule group")?;
        if group_name == "default" {
            return Err(SchedulerError::Validation(
                "the default schedule group cannot be deleted".into(),
            ));
        }
        let scope = self.store.scope(account, region).await;
        let mut state = scope.write().await;
        if state.schedule_groups.remove(group_name).is_none() {
            return Err(SchedulerError::ResourceNotFound(format!(
                "Schedule group {group_name} does not exist"
            )));
        }
        state.schedules.retain(|(group, _), _| group != group_name);
        drop(state);
        self.abort_prefix(&format!("{account}:{region}:{group_name}:"));
        Ok(json!({}))
    }

    async fn list_groups(
        &self,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, SchedulerError> {
        let prefix = body.get("NamePrefix").and_then(Value::as_str).unwrap_or("");
        let scope = self.store.scope(account, region).await;
        let state = scope.read().await;
        let groups = state
            .schedule_groups
            .values()
            .filter(|group| group.name.starts_with(prefix))
            .map(group_json)
            .collect();
        paginate(body, "ScheduleGroups", groups)
    }

    async fn tag_resource(
        &self,
        arn: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, SchedulerError> {
        let arn = name(arn, "resource ARN")?;
        let supplied = parse_scheduler_tags(body);
        self.mutate_tags(account, region, arn, |tags| tags.extend(supplied))
            .await?;
        Ok(json!({}))
    }
    async fn untag_resource(
        &self,
        arn: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, SchedulerError> {
        let arn = name(arn, "resource ARN")?;
        let keys: Vec<_> = body
            .get("TagKeys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        self.mutate_tags(account, region, arn, |tags| {
            tags.retain(|key, _| !keys.contains(key))
        })
        .await?;
        Ok(json!({}))
    }
    async fn list_tags(
        &self,
        arn: Option<&str>,
        account: &str,
        region: &str,
    ) -> Result<Value, SchedulerError> {
        let arn = name(arn, "resource ARN")?;
        let parsed = EbArn::parse(arn)
            .map_err(|_| SchedulerError::ResourceNotFound("resource does not exist".into()))?;
        if parsed.account() != account || parsed.region() != region {
            return Err(SchedulerError::ResourceNotFound(
                "resource does not exist".into(),
            ));
        }
        let scope = self.store.scope(account, region).await;
        let state = scope.read().await;
        let tags = match parsed {
            EbArn::Schedule { group, name, .. } => {
                state.schedules.get(&(group, name)).map(|value| &value.tags)
            }
            EbArn::ScheduleGroup { name, .. } => {
                state.schedule_groups.get(&name).map(|value| &value.tags)
            }
            _ => None,
        }
        .ok_or_else(|| SchedulerError::ResourceNotFound("resource does not exist".into()))?;
        Ok(
            json!({"Tags":tags.iter().map(|(key,value)|json!({"Key":key,"Value":value})).collect::<Vec<_>>() }),
        )
    }
    async fn mutate_tags(
        &self,
        account: &str,
        region: &str,
        arn: &str,
        mutation: impl FnOnce(&mut BTreeMap<String, String>),
    ) -> Result<(), SchedulerError> {
        let parsed = EbArn::parse(arn)
            .map_err(|_| SchedulerError::ResourceNotFound("resource does not exist".into()))?;
        if parsed.account() != account || parsed.region() != region {
            return Err(SchedulerError::ResourceNotFound(
                "resource does not exist".into(),
            ));
        }
        let scope = self.store.scope(account, region).await;
        let mut state = scope.write().await;
        let tags = match parsed {
            EbArn::Schedule { group, name, .. } => state
                .schedules
                .get_mut(&(group, name))
                .map(|value| &mut value.tags),
            EbArn::ScheduleGroup { name, .. } => state
                .schedule_groups
                .get_mut(&name)
                .map(|value| &mut value.tags),
            _ => None,
        }
        .ok_or_else(|| SchedulerError::ResourceNotFound("resource does not exist".into()))?;
        mutation(tags);
        Ok(())
    }
}

fn parse_scheduler_tags(body: &Value) -> BTreeMap<String, String> {
    body.get("Tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tag| {
            Some((
                tag.get("Key")?.as_str()?.into(),
                tag.get("Value")?.as_str()?.into(),
            ))
        })
        .collect()
}
fn group_json(group: &ScheduleGroup) -> Value {
    json!({"Name":group.name,"Arn":group.arn,"State":"ACTIVE","CreationDate":group.created_at.unix_timestamp(),"LastModificationDate":group.modified_at.unix_timestamp()})
}
fn schedule_summary(schedule: &Schedule) -> Value {
    json!({"Name":schedule.name,"Arn":schedule.arn,"GroupName":schedule.group,"State":schedule.state,"Target":{"Arn":schedule.target.get("Arn").cloned().unwrap_or(Value::Null)}})
}
fn schedule_json(schedule: &Schedule) -> Value {
    let mut value = json!({"Name":schedule.name,"Arn":schedule.arn,"GroupName":schedule.group,"ScheduleExpression":schedule.expression,"ScheduleExpressionTimezone":schedule.timezone,"FlexibleTimeWindow":schedule.flexible_window,"StartDate":schedule.start_date.map(OffsetDateTime::unix_timestamp),"EndDate":schedule.end_date.map(OffsetDateTime::unix_timestamp),"State":schedule.state,"ActionAfterCompletion":schedule.action_after_completion,"KmsKeyArn":schedule.kms_key_arn,"Target":schedule.target});
    if let Some(description) = &schedule.description {
        value["Description"] = json!(description);
    }
    value
}
impl SchedulerService {
    pub async fn resume_schedules(&self) {
        for (account, region) in self.store.scope_keys() {
            let scope = self.store.scope(&account, &region).await;
            let schedules: Vec<_> = scope.read().await.schedules.values().cloned().collect();
            for item in schedules {
                self.reconcile(&account, &region, &item).await;
            }
        }
    }

    async fn reconcile(&self, account: &str, region: &str, schedule: &Schedule) {
        let key = worker_key(account, region, &schedule.group, &schedule.name);
        self.abort(&key);
        let has_pending = self
            .store
            .pending_firings("scheduler", &schedule.arn)
            .is_ok_and(|rows| !rows.is_empty());
        if schedule.state != "ENABLED" && !has_pending {
            return;
        }
        let Ok(expression) = schedule::parse(&schedule.expression, true) else {
            return;
        };
        let registry = self.registry.clone();
        let store = self.store.clone();
        let clock = self.clock.clone();
        let account = account.to_string();
        let region = region.to_string();
        let item = schedule.clone();
        let worker = tokio::spawn(async move {
            let now = clock.now();
            let initial_anchor = item.start_date.unwrap_or(now);
            let initial = match (&expression, item.start_date) {
                (ScheduleExpr::Rate(_), Some(start)) if start >= now => {
                    start - time::Duration::nanoseconds(1)
                }
                (ScheduleExpr::At(_), _) => now - time::Duration::nanoseconds(1),
                (_, Some(start)) if start > now => start - time::Duration::minutes(1),
                _ => now,
            };
            let (saved_cursor, saved_anchor) = match store.firing_cursor(
                "scheduler",
                &item.arn,
                item.generation,
                initial.unix_timestamp_nanos() as i64,
                initial_anchor.unix_timestamp_nanos() as i64,
            ) {
                Ok(value) => value,
                Err(error) => {
                    tracing::error!(%error, "Scheduler cursor unavailable");
                    return;
                }
            };
            let mut cursor =
                OffsetDateTime::from_unix_timestamp_nanos(saved_cursor as i128).unwrap_or(initial);
            let rate_anchor = OffsetDateTime::from_unix_timestamp_nanos(saved_anchor as i128)
                .unwrap_or(initial_anchor);
            loop {
                if !deliver_pending_schedule(&store, &registry, &account, &region, &item).await {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                if item.state != "ENABLED" {
                    break;
                }
                let Some(mut due) =
                    schedule::next_after_anchored(&expression, cursor, &item.timezone, rate_anchor)
                        .ok()
                        .flatten()
                else {
                    if matches!(expression, ScheduleExpr::At(_)) {
                        delete_completed_schedule(&store, &account, &region, &item).await;
                    }
                    break;
                };
                let scheduled_due = due;
                if item.start_date.is_some_and(|start| due < start) {
                    cursor = item.start_date.unwrap_or(due) - time::Duration::minutes(1);
                    continue;
                }
                if item.end_date.is_some_and(|end| due > end) {
                    break;
                }
                if item.flexible_window.get("Mode").and_then(Value::as_str) == Some("FLEXIBLE") {
                    let max = item
                        .flexible_window
                        .get("MaximumWindowInMinutes")
                        .and_then(Value::as_u64)
                        .unwrap_or(1);
                    due = flexible_fire_time(&item.name, due, max);
                    if item.end_date.is_some_and(|end| due > end) {
                        break;
                    }
                }
                schedule::sleep_until(clock.as_ref(), due).await;
                let scope = store.scope(&account, &region).await;
                let guard = scope.read().await;
                let current = guard
                    .schedules
                    .get(&(item.group.clone(), item.name.clone()))
                    .filter(|current| {
                        current.state == "ENABLED" && current.generation == item.generation
                    })
                    .cloned();
                let Some(current) = current else {
                    break;
                };
                let payload = serde_json::to_value(&current).unwrap_or(Value::Null);
                if let Err(error) = store.enqueue_firing(
                    "scheduler",
                    &item.arn,
                    item.generation,
                    scheduled_due.unix_timestamp_nanos() as i64,
                    &payload,
                ) {
                    tracing::error!(%error, "Scheduler firing journal unavailable");
                    break;
                }
                drop(guard);
                if store.state_db().is_none() {
                    if let Some(registry) = registry.upgrade() {
                        let _ = delivery::deliver(
                            &registry,
                            &schedule_delivery(&current, scheduled_due),
                            &region,
                            &account,
                        )
                        .await;
                    }
                    if matches!(expression, ScheduleExpr::At(_)) {
                        delete_completed_schedule(&store, &account, &region, &current).await;
                        break;
                    }
                }
                cursor = scheduled_due;
            }
        });
        if let Ok(mut workers) = self.workers.lock() {
            workers.retain(|_, worker| !worker.is_finished());
            workers.insert(key, worker);
        }
    }

    fn reap_finished_workers(&self) {
        if let Ok(mut workers) = self.workers.lock() {
            workers.retain(|_, worker| !worker.is_finished());
        }
    }

    fn abort(&self, key: &str) {
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

async fn deliver_pending_schedule(
    store: &EbStore,
    registry: &Weak<ServiceRegistry>,
    account: &str,
    region: &str,
    item: &Schedule,
) -> bool {
    let pending = match store.pending_firings("scheduler", &item.arn) {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(%error, "Scheduler pending firings unavailable");
            return false;
        }
    };
    for (due_ns, payload) in pending {
        let Ok(snapshot) = serde_json::from_value::<Schedule>(payload) else {
            tracing::error!("Scheduler firing snapshot is invalid");
            return false;
        };
        match store.firing_ready(
            "scheduler",
            &item.arn,
            due_ns,
            OffsetDateTime::now_utc().unix_timestamp_nanos() as i64,
        ) {
            Ok(true) => {}
            Ok(false) => return false,
            Err(error) => {
                tracing::error!(%error, "Scheduler retry metadata unavailable");
                return false;
            }
        }
        let Some(registry) = registry.upgrade() else {
            let _ = store.defer_firing(
                "scheduler",
                &item.arn,
                due_ns,
                OffsetDateTime::now_utc().unix_timestamp_nanos() as i64,
            );
            return false;
        };
        let Ok(due) = OffsetDateTime::from_unix_timestamp_nanos(due_ns as i128) else {
            return false;
        };
        if delivery::deliver(
            &registry,
            &schedule_delivery(&snapshot, due),
            region,
            account,
        )
        .await
        .is_err()
        {
            let retry = snapshot.target.get("RetryPolicy").unwrap_or(&Value::Null);
            let max_age = retry
                .get("MaximumEventAgeInSeconds")
                .and_then(Value::as_u64)
                .unwrap_or(86_400);
            let outer_limit = if retry.get("MaximumRetryAttempts").is_some() {
                1
            } else {
                185
            };
            let now_ns = OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
            let attempts = store
                .firing_attempts("scheduler", &item.arn, due_ns)
                .unwrap_or(0);
            let exhausted = attempts + 1 >= outer_limit
                || now_ns.saturating_sub(due_ns) >= (max_age as i64).saturating_mul(1_000_000_000);
            let result = if exhausted {
                store.terminal_firing("scheduler", &item.arn, due_ns, "retry policy exhausted")
            } else {
                store.defer_firing("scheduler", &item.arn, due_ns, now_ns)
            };
            if let Err(error) = result {
                tracing::error!(%error, "Scheduler retry metadata unavailable");
            }
            return false;
        }
        if let Err(error) = store.complete_firing("scheduler", &item.arn, due_ns) {
            tracing::error!(%error, "Scheduler firing completion unavailable");
            return false;
        }
        if matches!(
            schedule::parse(&snapshot.expression, true),
            Ok(ScheduleExpr::At(_))
        ) {
            delete_completed_schedule(store, account, region, &snapshot).await;
        }
    }
    true
}

async fn delete_completed_schedule(
    store: &EbStore,
    account: &str,
    region: &str,
    schedule: &Schedule,
) {
    if schedule.action_after_completion != "DELETE" {
        return;
    }
    let _gate = store.scheduler_gate.write().await;
    let scope = store.scope(account, region).await;
    let mut state = scope.write().await;
    let key = (schedule.group.clone(), schedule.name.clone());
    if state
        .schedules
        .get(&key)
        .is_some_and(|current| current.generation == schedule.generation)
    {
        state.schedules.remove(&key);
        drop(state);
        if let Err(error) = store
            .persist_scheduler(account, region, OffsetDateTime::now_utc())
            .await
        {
            tracing::error!(%error, "Scheduler completion metadata unavailable");
        }
    }
}

fn worker_key(account: &str, region: &str, group: &str, name: &str) -> String {
    format!("{account}:{region}:{group}:{name}")
}

pub(crate) fn flexible_fire_time(
    name: &str,
    scheduled_due: OffsetDateTime,
    maximum_window_minutes: u64,
) -> OffsetDateTime {
    let hash = name.bytes().fold(0u64, |sum, byte| {
        sum.wrapping_mul(31).wrapping_add(u64::from(byte))
    });
    let window_seconds = maximum_window_minutes.saturating_mul(60);
    let offset = hash % window_seconds.saturating_add(1);
    scheduled_due + time::Duration::seconds(offset.min(i64::MAX as u64) as i64)
}

fn schedule_delivery(schedule: &Schedule, scheduled_due: OffsetDateTime) -> DeliveryRequest {
    let retry = schedule.target.get("RetryPolicy").unwrap_or(&Value::Null);
    DeliveryRequest {
        source_service: "scheduler",
        source_arn: schedule
            .arn
            .split_once(":schedule/")
            .map(|(prefix, _)| format!("{prefix}:schedule-group/{}", schedule.group)),
        arn: schedule
            .target
            .get("Arn")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        payload: schedule
            .target
            .get("Input")
            .and_then(Value::as_str)
            .unwrap_or("{}")
            .into(),
        role_arn: schedule
            .target
            .get("RoleArn")
            .and_then(Value::as_str)
            .map(str::to_string),
        sqs_parameters: schedule.target.get("SqsParameters").cloned(),
        target_parameters: Some(schedule.target.clone()),
        retry: RetryPolicy {
            maximum_attempts: retry
                .get("MaximumRetryAttempts")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32,
            maximum_age_seconds: retry
                .get("MaximumEventAgeInSeconds")
                .and_then(Value::as_u64),
        },
        dead_letter_arn: schedule
            .target
            .get("DeadLetterConfig")
            .and_then(|value| value.get("Arn"))
            .and_then(Value::as_str)
            .map(str::to_string),
        scheduled_at: Some(scheduled_due),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_names_and_windows() {
        assert!(valid_name("ok-name_1.2"));
        assert!(!valid_name("bad/name"));
        assert!(flexible_window(Some(
            &json!({"Mode":"FLEXIBLE","MaximumWindowInMinutes":30})
        ))
        .is_ok());
        assert!(flexible_window(Some(&json!({"Mode":"OFF","MaximumWindowInMinutes":1}))).is_err());
    }

    #[test]
    fn scheduler_retry_limits_match_api() {
        let base = json!({"Arn":"arn:aws:sqs:us-east-1:000000000000:q",
            "RoleArn":"arn:aws:iam::000000000000:role/r"});
        let mut target = base.clone();
        target["RetryPolicy"] = json!({"MaximumRetryAttempts":185,"MaximumEventAgeInSeconds":60});
        assert!(validate_target(Some(&target)).is_ok());
        target["RetryPolicy"]["MaximumRetryAttempts"] = json!(186);
        assert!(validate_target(Some(&target)).is_err());
        target["RetryPolicy"] = json!({"MaximumEventAgeInSeconds":59});
        assert!(validate_target(Some(&target)).is_err());

        let schedule = Schedule {
            description: None,
            name: "a".into(),
            arn: "a".into(),
            group: "default".into(),
            expression: "rate(1 minute)".into(),
            timezone: "UTC".into(),
            flexible_window: json!({"Mode":"OFF"}),
            start_date: None,
            end_date: None,
            state: "ENABLED".into(),
            action_after_completion: "NONE".into(),
            kms_key_arn: None,
            target: base,
            tags: BTreeMap::new(),
            generation: 1,
        };
        let request = schedule_delivery(&schedule, OffsetDateTime::UNIX_EPOCH);
        assert_eq!(request.retry.maximum_attempts, 0);
        assert_eq!(request.retry.maximum_age_seconds, None);
    }

    #[test]
    fn date_range_and_pagination_are_validated() {
        let start = OffsetDateTime::from_unix_timestamp(20).unwrap();
        let end = OffsetDateTime::from_unix_timestamp(10).unwrap();
        assert!(validate_date_range(Some(start), Some(end)).is_err());
        assert!(validate_date_range(Some(end), Some(start)).is_ok());

        let first = paginate(
            &json!({"MaxResults":2}),
            "Schedules",
            vec![json!("a"), json!("b"), json!("c")],
        )
        .unwrap();
        assert_eq!(first["Schedules"], json!(["a", "b"]));
        assert_eq!(first["NextToken"], "2");
        let second = paginate(
            &json!({"MaxResults":2,"NextToken":"2"}),
            "Schedules",
            vec![json!("a"), json!("b"), json!("c")],
        )
        .unwrap();
        assert_eq!(second["Schedules"], json!(["c"]));
        assert!(second.get("NextToken").is_none());
    }

    #[tokio::test]
    async fn recurring_completion_delete_removes_current_generation() {
        let store = EbStore::new();
        let schedule = Schedule {
            description: None,
            name: "rate".into(),
            arn: "arn:aws:scheduler:r:a:schedule/default/rate".into(),
            group: "default".into(),
            expression: "rate(1 minute)".into(),
            timezone: "UTC".into(),
            flexible_window: json!({"Mode":"OFF"}),
            start_date: None,
            end_date: Some(OffsetDateTime::UNIX_EPOCH),
            state: "ENABLED".into(),
            action_after_completion: "DELETE".into(),
            kms_key_arn: None,
            target: json!({}),
            tags: BTreeMap::new(),
            generation: 1,
        };
        let scope = store.scope("a", "r").await;
        scope
            .write()
            .await
            .schedules
            .insert(("default".into(), "rate".into()), schedule.clone());
        delete_completed_schedule(&store, "a", "r", &schedule).await;
        assert!(!scope
            .read()
            .await
            .schedules
            .contains_key(&("default".into(), "rate".into())));
    }
    #[tokio::test]
    async fn disable_preserves_accepted_firing_and_delete_marks_it_cancelled() {
        use locallycloud_state::StateDb;
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
        let store = Arc::new(EbStore::with_state(db.clone()).unwrap());
        let service = SchedulerService::new(
            store.clone(),
            Weak::new(),
            Arc::new(crate::schedule::SystemClock),
        );
        let body = json!({"Description":"first description","ScheduleExpression":"at(2099-01-01T00:00:00)",
            "FlexibleTimeWindow":{"Mode":"OFF"},"Target":{"Arn":"arn:aws:sqs:r:a:q",
            "RoleArn":"arn:aws:iam::a:role/r","Input":"{}"}});
        service
            .dispatch("CreateSchedule", Some("job"), "a", "r", &body)
            .await
            .unwrap();
        assert_eq!(
            service
                .dispatch("GetSchedule", Some("job"), "a", "r", &json!({}))
                .await
                .unwrap()["Description"],
            "first description"
        );
        let schedule = store.scope("a", "r").await.read().await.schedules
            [&("default".into(), "job".into())]
            .clone();
        let due_ns = 2_000_000_000_i64 * 1_000_000_000;
        store
            .enqueue_firing(
                "scheduler",
                &schedule.arn,
                schedule.generation,
                due_ns,
                &serde_json::to_value(&schedule).unwrap(),
            )
            .unwrap();
        let mut disabled = body.clone();
        disabled["State"] = json!("DISABLED");
        disabled.as_object_mut().unwrap().remove("Description");
        service
            .dispatch("UpdateSchedule", Some("job"), "a", "r", &disabled)
            .await
            .unwrap();
        assert!(service
            .dispatch("GetSchedule", Some("job"), "a", "r", &json!({}))
            .await
            .unwrap()
            .get("Description")
            .is_none());
        let mut invalid = disabled.clone();
        invalid["Description"] = json!(false);
        assert!(service
            .dispatch("UpdateSchedule", Some("job"), "a", "r", &invalid)
            .await
            .is_err());
        assert!(schedule_description(&json!({"Description":"x".repeat(513)})).is_err());
        assert!(schedule_description(&json!({"Description":""})).is_ok());
        assert_eq!(
            store
                .pending_firings("scheduler", &schedule.arn)
                .unwrap()
                .len(),
            1
        );
        service
            .dispatch("DeleteSchedule", Some("job"), "a", "r", &json!({}))
            .await
            .unwrap();
        assert!(store
            .pending_firings("scheduler", &schedule.arn)
            .unwrap()
            .is_empty());
        let status: String = db.connection().unwrap().query_row(
            "SELECT status FROM events_pending_firing WHERE kind='scheduler' AND arn=?1 AND due_ns=?2",
            rusqlite::params![schedule.arn,due_ns], |row| row.get(0)).unwrap();
        assert_eq!(status, "CANCELLED");
    }

    #[tokio::test]
    async fn acknowledged_schedule_and_pending_firing_survive_restart() {
        use locallycloud_state::StateDb;
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
        let store = Arc::new(EbStore::with_state(db.clone()).unwrap());
        let service = SchedulerService::new(
            store.clone(),
            Weak::new(),
            Arc::new(crate::schedule::SystemClock),
        );
        service
            .dispatch("CreateScheduleGroup", Some("etl"), "a", "r", &json!({}))
            .await
            .unwrap();
        let body = json!({"Description":"durable description","GroupName":"etl","ScheduleExpression":"at(2099-01-01T00:00:00)",
            "FlexibleTimeWindow":{"Mode":"OFF"},"Target":{"Arn":"arn:aws:sqs:r:a:q",
            "RoleArn":"arn:aws:iam::a:role/r","Input":"{}"}});
        service
            .dispatch("CreateSchedule", Some("job"), "a", "r", &body)
            .await
            .unwrap();
        let schedule = store.scope("a", "r").await.read().await.schedules
            [&("etl".into(), "job".into())]
            .clone();
        let due = OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();
        let initial = due - time::Duration::seconds(1);
        store
            .firing_cursor(
                "scheduler",
                &schedule.arn,
                schedule.generation,
                initial.unix_timestamp_nanos() as i64,
                initial.unix_timestamp_nanos() as i64,
            )
            .unwrap();
        store
            .enqueue_firing(
                "scheduler",
                &schedule.arn,
                schedule.generation,
                due.unix_timestamp_nanos() as i64,
                &serde_json::to_value(&schedule).unwrap(),
            )
            .unwrap();
        drop(service);
        drop(store);
        let reopened = EbStore::with_state(db.clone()).unwrap();
        let scope = reopened.scope("a", "r").await;
        let guard = scope.read().await;
        assert!(guard.schedule_groups.contains_key("etl"));
        assert_eq!(
            guard.schedules[&("etl".into(), "job".into())]
                .description
                .as_deref(),
            Some("durable description")
        );
        let mut legacy = serde_json::to_value(&schedule).unwrap();
        legacy.as_object_mut().unwrap().remove("description");
        assert!(serde_json::from_value::<Schedule>(legacy)
            .unwrap()
            .description
            .is_none());
        assert_eq!(
            guard.schedules[&("etl".into(), "job".into())].target["Input"],
            "{}"
        );
        drop(guard);
        assert_eq!(
            reopened
                .pending_firings("scheduler", &schedule.arn)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            reopened
                .firing_cursor("scheduler", &schedule.arn, schedule.generation, 0, 0)
                .unwrap()
                .0,
            due.unix_timestamp_nanos() as i64
        );
        let now = OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
        reopened
            .defer_firing(
                "scheduler",
                &schedule.arn,
                due.unix_timestamp_nanos() as i64,
                now,
            )
            .unwrap();
        assert!(!reopened
            .firing_ready(
                "scheduler",
                &schedule.arn,
                due.unix_timestamp_nanos() as i64,
                now
            )
            .unwrap());
        assert!(reopened
            .firing_ready(
                "scheduler",
                &schedule.arn,
                due.unix_timestamp_nanos() as i64,
                now + 2_000_000_000
            )
            .unwrap());
        reopened
            .terminal_firing(
                "scheduler",
                &schedule.arn,
                due.unix_timestamp_nanos() as i64,
                "retry policy exhausted",
            )
            .unwrap();
        assert!(reopened
            .pending_firings("scheduler", &schedule.arn)
            .unwrap()
            .is_empty());
        let status: String = db
            .connection()
            .unwrap()
            .query_row(
                "SELECT status FROM events_pending_firing WHERE kind='scheduler' AND arn=?1",
                rusqlite::params![schedule.arn],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "FAILED");
    }
}
