//! Basic metric alarm aggregate and API operations.
mod delivery;
mod evaluation;
mod pagination;
mod store;
#[cfg(test)]
mod tests;
mod wire;
use super::*;
pub(super) use delivery::start_worker;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
pub(super) use wire::{query_json, query_xml};

pub(super) const ACTIONS: &[&str] = &[
    "PutMetricAlarm",
    "DescribeAlarms",
    "DeleteAlarms",
    "SetAlarmState",
    "DescribeAlarmHistory",
    "EnableAlarmActions",
    "DisableAlarmActions",
];
pub(super) fn supported(action: &str) -> bool {
    ACTIONS.contains(&action)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Config {
    alarm_name: String,
    #[serde(default)]
    alarm_description: String,
    namespace: String,
    metric_name: String,
    #[serde(default)]
    dimensions: Vec<Dimension>,
    statistic: String,
    #[serde(default)]
    unit: Option<String>,
    period: u64,
    evaluation_periods: u64,
    #[serde(default)]
    datapoints_to_alarm: Option<u64>,
    threshold: f64,
    comparison_operator: String,
    #[serde(default = "missing")]
    treat_missing_data: String,
    #[serde(default = "enabled")]
    actions_enabled: bool,
    #[serde(default)]
    alarm_actions: Vec<String>,
    #[serde(rename = "OKActions", default)]
    ok_actions: Vec<String>,
    #[serde(default)]
    insufficient_data_actions: Vec<String>,
}
fn missing() -> String {
    "missing".into()
}
fn enabled() -> bool {
    true
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Dimension {
    name: String,
    value: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    config: Config,
    state: String,
    reason: String,
    reason_data: Option<String>,
    updated: i64,
    changed: i64,
    next_eval: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    history: Vec<Value>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Pending {
    id: i64,
    scope: ScopeKey,
    target: String,
    message: String,
    #[serde(default)]
    alarm_name: String,
}

#[derive(Default)]
struct State {
    records: BTreeMap<(ScopeKey, String), Record>,
    pending: BTreeMap<i64, Pending>,
    next_id: i64,
    delivery_cursor: i64,
    next_history_id: i64,
    history: BTreeMap<i64, HistoryEntry>,
}

pub(super) struct Alarms {
    state: Mutex<State>,
    persistence: Option<Arc<persistence::Persistence>>,
    wake: tokio::sync::Notify,
    ephemeral_cipher: Option<locallycloud_state::StateCipher>,
}

#[derive(Clone)]
struct HistoryEntry {
    id: i64,
    scope: ScopeKey,
    name: String,
    entry: Value,
}
const HISTORY_RETENTION_MS: i64 = 30 * 86400 * 1000;
fn history_timestamp(entry: &Value) -> i64 {
    (entry["Timestamp"].as_f64().unwrap_or(0.0) * 1000.0).round() as i64
}

fn invalid(message: &str) -> MonitoringError {
    MonitoringError::InvalidParameter(message.into())
}
fn lock_error() -> MonitoringError {
    MonitoringError::Internal("alarm store lock poisoned".into())
}
fn arn(scope: &ScopeKey, name: &str) -> String {
    format!(
        "arn:aws:cloudwatch:{}:{}:alarm:{name}",
        scope.region, scope.account_id
    )
}

impl Alarms {
    pub(super) fn process(
        &self,
        action: &str,
        body: &Value,
        scope: &ScopeKey,
    ) -> Result<Value, MonitoringError> {
        let mut state = self.state.lock().map_err(|_| lock_error())?;
        match action {
            "PutMetricAlarm" => {
                let mut config: Config = serde_json::from_value(body.clone()).map_err(|_|invalid("Basic alarms require one metric/statistic; unsupported properties are rejected"))?;
                if config.namespace == "AWS/DynamoDB" && body.get("TreatMissingData").is_none() {
                    config.treat_missing_data = "ignore".into();
                }
                validate(&config, scope)?;
                let now = now_ms();
                let mut record = state
                    .records
                    .get(&(scope.clone(), config.alarm_name.clone()))
                    .cloned()
                    .unwrap_or(Record {
                        config: config.clone(),
                        state: "INSUFFICIENT_DATA".into(),
                        reason: "Unchecked: Initial alarm creation".into(),
                        reason_data: None,
                        updated: now,
                        changed: now,
                        next_eval: 0,
                        history: Vec::new(),
                    });
                record.config = config;
                record.updated = now;
                record.next_eval = 0;
                record.history.push(history(
                    &record.config.alarm_name,
                    "ConfigurationUpdate",
                    "Alarm configuration updated",
                    json!({"configuration":record.config}),
                    now,
                ));
                self.commit(
                    &mut state,
                    scope,
                    &record.config.alarm_name,
                    Some(&record),
                    vec![],
                )?;
                Ok(json!({}))
            }
            "DescribeAlarms" => {
                allowed(
                    body,
                    &[
                        "AlarmNames",
                        "AlarmNamePrefix",
                        "StateValue",
                        "ActionPrefix",
                        "MaxRecords",
                        "NextToken",
                        "AlarmTypes",
                    ],
                )?;
                let mut cursor = self.cursor(action, body, scope)?;
                if body.get("AlarmTypes").is_some_and(|v| {
                    v.as_array()
                        .is_none_or(|a| a.iter().any(|t| t != "MetricAlarm"))
                }) {
                    return Err(invalid("Composite alarms are not supported"));
                }
                let max = body
                    .get("MaxRecords")
                    .map(|v| {
                        v.as_u64()
                            .filter(|n| (1..=100).contains(n))
                            .ok_or_else(|| invalid("MaxRecords must be 1–100"))
                    })
                    .transpose()?
                    .unwrap_or(100) as usize;
                let names = names(body, "AlarmNames")?;
                if !names.is_empty() && body.get("AlarmNamePrefix").is_some() {
                    return Err(invalid("AlarmNames and AlarmNamePrefix cannot be combined"));
                }
                for field in ["AlarmNamePrefix", "StateValue", "ActionPrefix"] {
                    optional_string(body, field)?;
                }
                if optional_string(body, "StateValue")?
                    .is_some_and(|value| !matches!(value, "OK" | "ALARM" | "INSUFFICIENT_DATA"))
                {
                    return Err(invalid("Invalid StateValue"));
                }
                let records: Vec<_> = state
                    .records
                    .iter()
                    .filter(|((s, name), r)| {
                        s == scope
                            && cursor.last_name.as_ref().is_none_or(|last| name > last)
                            && (names.is_empty() || names.contains(name))
                            && body
                                .get("AlarmNamePrefix")
                                .and_then(Value::as_str)
                                .is_none_or(|p| name.starts_with(p))
                            && body
                                .get("StateValue")
                                .and_then(Value::as_str)
                                .is_none_or(|v| r.state == v)
                            && body
                                .get("ActionPrefix")
                                .and_then(Value::as_str)
                                .is_none_or(|p| {
                                    r.config
                                        .alarm_actions
                                        .iter()
                                        .chain(&r.config.ok_actions)
                                        .chain(&r.config.insufficient_data_actions)
                                        .any(|a| a.starts_with(p))
                                })
                    })
                    .take(max + 1)
                    .map(|((_, name), r)| (name.clone(), view(scope, r)))
                    .collect();
                let more = records.len() > max;
                let mut response = json!({"MetricAlarms":records.iter().take(max).map(|(_,view)|view.clone()).collect::<Vec<_>>(),"CompositeAlarms":[]});
                if more {
                    cursor.last_name = Some(records[max - 1].0.clone());
                    response["NextToken"] = self.next_token(action, body, scope, &cursor)?.into();
                }
                Ok(response)
            }

            "DeleteAlarms" | "EnableAlarmActions" | "DisableAlarmActions" => {
                allowed(body, &["AlarmNames"])?;
                let names = names(body, "AlarmNames")?;
                if names.is_empty() || names.len() > 100 {
                    return Err(invalid("AlarmNames must contain 1–100 names"));
                }
                let now = now_ms();
                let mut updates = Vec::new();
                let mut history = Vec::new();
                for name in names {
                    let record = state.records.get(&(scope.clone(), name.clone())).cloned();
                    if action == "DeleteAlarms" {
                        if record.is_some() {
                            history.push((
                                name.clone(),
                                self::history(
                                    &name,
                                    "ConfigurationUpdate",
                                    "Alarm deleted",
                                    json!({"deleted":true}),
                                    now,
                                ),
                            ));
                        }
                        updates.push((name, None));
                    } else if let Some(mut record) = record {
                        record.config.actions_enabled = action == "EnableAlarmActions";
                        record.updated = now;
                        record.history.push(self::history(
                            &name,
                            "ConfigurationUpdate",
                            "Alarm actions changed",
                            json!({"actionsEnabled":record.config.actions_enabled}),
                            now,
                        ));
                        updates.push((name, Some(record)));
                    }
                }
                self.commit_batch(&mut state, scope, &updates, vec![], None, history)?;
                Ok(json!({}))
            }
            "SetAlarmState" => {
                allowed(
                    body,
                    &["AlarmName", "StateValue", "StateReason", "StateReasonData"],
                )?;
                let name = json_string(body, "AlarmName")?;
                let value = json_string(body, "StateValue")?;
                if !matches!(value, "OK" | "ALARM" | "INSUFFICIENT_DATA") {
                    return Err(invalid("Invalid StateValue"));
                }
                let reason = json_string(body, "StateReason")?;
                if reason.len() > 1023 {
                    return Err(invalid("StateReason is too long"));
                }
                let mut record = state
                    .records
                    .get(&(scope.clone(), name.into()))
                    .cloned()
                    .ok_or_else(|| MonitoringError::NotFound("Alarm does not exist".into()))?;
                let reason_data = optional_string(body, "StateReasonData")?.map(str::to_owned);
                if reason_data
                    .as_ref()
                    .is_some_and(|s| s.len() > 4000 || serde_json::from_str::<Value>(s).is_err())
                {
                    return Err(invalid("StateReasonData must be JSON"));
                }
                let pending = transition(scope, &mut record, value, reason, now_ms());
                record.reason = reason.to_owned();
                record.changed = now_ms();
                record.reason_data = reason_data;
                record.next_eval = now_ms() + evaluation::evaluation_interval(&record.config);
                self.commit(&mut state, scope, name, Some(&record), pending)?;
                Ok(json!({}))
            }
            "DescribeAlarmHistory" => {
                allowed(
                    body,
                    &[
                        "AlarmName",
                        "HistoryItemType",
                        "StartDate",
                        "EndDate",
                        "MaxRecords",
                        "NextToken",
                        "ScanBy",
                    ],
                )?;
                let mut cursor = self.cursor(action, body, scope)?;
                let alarm_name = optional_string(body, "AlarmName")?;
                let kind = optional_string(body, "HistoryItemType")?;
                if kind.is_some_and(|value| {
                    !matches!(value, "ConfigurationUpdate" | "StateUpdate" | "Action")
                }) {
                    return Err(invalid("Unsupported HistoryItemType"));
                }
                let scan = optional_string(body, "ScanBy")?.unwrap_or("TimestampDescending");
                if !matches!(scan, "TimestampAscending" | "TimestampDescending") {
                    return Err(invalid("Invalid ScanBy"));
                }
                let ascending = scan == "TimestampAscending";
                let start = body
                    .get("StartDate")
                    .map(parse_json_timestamp)
                    .transpose()?;
                let end = body.get("EndDate").map(parse_json_timestamp).transpose()?;
                if start.zip(end).is_some_and(|(s, e)| s > e) {
                    return Err(invalid("StartDate must precede EndDate"));
                }
                let limit = body
                    .get("MaxRecords")
                    .map(|v| {
                        v.as_u64()
                            .filter(|n| (1..=100).contains(n))
                            .ok_or_else(|| invalid("MaxRecords must be 1–100"))
                    })
                    .transpose()?
                    .unwrap_or(100) as usize;
                let high = cursor
                    .high_history
                    .unwrap_or_else(|| state.history.keys().next_back().copied().unwrap_or(0));
                cursor.high_history = Some(high);
                let cutoff = now_ms() - HISTORY_RETENTION_MS;
                let mut entries: Vec<_> = state
                    .history
                    .values()
                    .filter(|h| {
                        let key = (history_timestamp(&h.entry), h.id);
                        h.scope == *scope
                            && h.id <= high
                            && key.0 >= cutoff
                            && alarm_name.is_none_or(|name| h.name == name)
                            && kind.is_none_or(|kind| h.entry["HistoryItemType"] == kind)
                            && start.is_none_or(|start| key.0 >= start)
                            && end.is_none_or(|end| key.0 <= end)
                            && cursor.last_history.is_none_or(|last| {
                                if ascending {
                                    key > last
                                } else {
                                    key < last
                                }
                            })
                    })
                    .collect();
                entries.sort_by_key(|h| (history_timestamp(&h.entry), h.id));
                if !ascending {
                    entries.reverse();
                }
                let mut response = json!({"AlarmHistoryItems":entries.iter().take(limit).map(|h|h.entry.clone()).collect::<Vec<_>>()});
                if entries.len() > limit {
                    let last = entries[limit - 1];
                    cursor.last_history = Some((history_timestamp(&last.entry), last.id));
                    response["NextToken"] = self.next_token(action, body, scope, &cursor)?.into();
                }
                Ok(response)
            }

            _ => Err(MonitoringError::InvalidAction(action.into())),
        }
    }

    fn active(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|s| !s.records.is_empty() || !s.pending.is_empty())
    }
    fn pending(&self) -> Result<Vec<Pending>, MonitoringError> {
        let mut state = self.state.lock().map_err(|_| lock_error())?;
        let selected: Vec<_> = state
            .pending
            .range((
                std::ops::Bound::Excluded(state.delivery_cursor),
                std::ops::Bound::Unbounded,
            ))
            .chain(state.pending.range(..=state.delivery_cursor))
            .take(64)
            .map(|(_, action)| action.clone())
            .collect();
        if let Some(last) = selected.last() {
            state.delivery_cursor = last.id;
        }
        Ok(selected)
    }
    fn finish_action(&self, id: i64, failure: Option<&str>) -> Result<(), MonitoringError> {
        let mut state = self.state.lock().map_err(|_| lock_error())?;
        let Some(action) = state.pending.get(&id).cloned() else {
            return Ok(());
        };
        let name = if action.alarm_name.is_empty() {
            serde_json::from_str::<Value>(&action.message)
                .ok()
                .and_then(|v| v["AlarmName"].as_str().map(str::to_owned))
                .unwrap_or_default()
        } else {
            action.alarm_name
        };
        let entry = history(
            &name,
            "Action",
            &format!(
                "{} action {}",
                if failure.is_some() {
                    "Failed to execute"
                } else {
                    "Successfully executed"
                },
                action.target
            ),
            json!({"actionState":if failure.is_some(){"Failed"}else{"Succeeded"},"notificationResource":action.target,"error":failure}),
            now_ms(),
        );
        self.commit_batch(
            &mut state,
            &action.scope,
            &[],
            vec![],
            Some(id),
            vec![(name, entry)],
        )
    }
}

fn validate(config: &Config, scope: &ScopeKey) -> Result<(), MonitoringError> {
    if config.alarm_name.is_empty()
        || config.alarm_name.len() > 255
        || config.alarm_name.chars().any(char::is_control)
        || config.alarm_description.len() > 1024
        || config.namespace.is_empty()
        || config.namespace.len() > 255
        || config.metric_name.is_empty()
        || config.metric_name.len() > 255
        || !config.threshold.is_finite()
    {
        return Err(invalid("Invalid alarm name/metric/threshold"));
    }
    if !matches!(config.period, 10 | 20 | 30)
        && (config.period < 60 || !config.period.is_multiple_of(60))
    {
        return Err(invalid("Period must be 10, 20, 30 or a multiple of 60"));
    }
    let window = config
        .period
        .checked_mul(config.evaluation_periods)
        .ok_or_else(|| invalid("Evaluation window is too large"))?;
    if config.evaluation_periods == 0
        || window > 604800
        || (config.period < 3600 && window > 86400)
        || config
            .datapoints_to_alarm
            .is_some_and(|n| n == 0 || n > config.evaluation_periods)
    {
        return Err(invalid("Invalid evaluation window/datapoints"));
    }
    if !matches!(
        config.statistic.as_str(),
        "Average" | "Sum" | "Minimum" | "Maximum" | "SampleCount"
    ) || !matches!(
        config.comparison_operator.as_str(),
        "GreaterThanThreshold"
            | "GreaterThanOrEqualToThreshold"
            | "LessThanThreshold"
            | "LessThanOrEqualToThreshold"
    ) || !matches!(
        config.treat_missing_data.as_str(),
        "missing" | "ignore" | "breaching" | "notBreaching"
    ) {
        return Err(invalid(
            "Unsupported statistic, comparison or missing-data policy",
        ));
    }
    if config
        .unit
        .as_ref()
        .is_some_and(|u| MetricUnit::parse(u).is_none())
        || config.dimensions.len() > 30
        || config
            .dimensions
            .iter()
            .any(|d| d.name.is_empty() || d.value.is_empty())
        || config
            .dimensions
            .iter()
            .map(|d| &d.name)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != config.dimensions.len()
    {
        return Err(invalid("Invalid dimensions or unit"));
    }
    for actions in [
        &config.alarm_actions,
        &config.ok_actions,
        &config.insufficient_data_actions,
    ] {
        if actions.len() > 5
            || actions.iter().any(|a| {
                !a.starts_with(&format!(
                    "arn:aws:sns:{}:{}:",
                    scope.region, scope.account_id
                )) || a.ends_with(':')
                    || a.ends_with(".fifo")
            })
        {
            return Err(invalid(
                "Only same-account/region standard SNS alarm actions are supported",
            ));
        }
    }
    Ok(())
}
fn breaches(c: &Config, v: f64) -> bool {
    match c.comparison_operator.as_str() {
        "GreaterThanThreshold" => v > c.threshold,
        "GreaterThanOrEqualToThreshold" => v >= c.threshold,
        "LessThanThreshold" => v < c.threshold,
        _ => v <= c.threshold,
    }
}
fn statistic(name: &str, values: &[f64]) -> f64 {
    match name {
        "Sum" => values.iter().sum(),
        "SampleCount" => values.len() as f64,
        "Minimum" => values.iter().copied().fold(f64::INFINITY, f64::min),
        "Maximum" => values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        _ => values.iter().sum::<f64>() / values.len() as f64,
    }
}
fn history(name: &str, kind: &str, summary: &str, data: Value, now: i64) -> Value {
    json!({"AlarmName":name,"Timestamp":now as f64/1000.0,"HistoryItemType":kind,"HistorySummary":summary,"HistoryData":data.to_string()})
}
fn transition(
    scope: &ScopeKey,
    r: &mut Record,
    value: &str,
    reason: &str,
    now: i64,
) -> Vec<Pending> {
    if r.state == value {
        return vec![];
    }
    let previous = std::mem::replace(&mut r.state, value.into());
    r.reason = reason.into();
    r.changed = now;
    r.reason_data = None;
    r.history.retain(|h| {
        h["Timestamp"].as_f64().unwrap_or(0.0) > ((now - 30 * 86400 * 1000) as f64 / 1000.0)
    });
    r.history.push(history(
        &r.config.alarm_name,
        "StateUpdate",
        reason,
        json!({"oldState":{"stateValue":previous},"newState":{"stateValue":value}}),
        now,
    ));
    if !r.config.actions_enabled {
        return vec![];
    }
    let actions = match value {
        "ALARM" => &r.config.alarm_actions,
        "OK" => &r.config.ok_actions,
        _ => &r.config.insufficient_data_actions,
    };
    let message=json!({"AlarmName":r.config.alarm_name,"AlarmDescription":r.config.alarm_description,"AWSAccountId":scope.account_id,"NewStateValue":value,"NewStateReason":reason,"StateChangeTime":format_timestamp(now).unwrap_or_default(),"Region":scope.region,"AlarmArn":arn(scope,&r.config.alarm_name),"OldStateValue":previous,"Trigger":{"Namespace":r.config.namespace,"MetricName":r.config.metric_name,"Statistic":r.config.statistic,"Period":r.config.period,"EvaluationPeriods":r.config.evaluation_periods,"ComparisonOperator":r.config.comparison_operator,"Threshold":r.config.threshold,"TreatMissingData":r.config.treat_missing_data}}).to_string();
    actions
        .iter()
        .map(|target| Pending {
            id: 0,
            scope: scope.clone(),
            target: target.clone(),
            message: message.clone(),
            alarm_name: r.config.alarm_name.clone(),
        })
        .collect()
}
fn view(scope: &ScopeKey, r: &Record) -> Value {
    let mut v = serde_json::to_value(&r.config).expect("finite validated alarm");
    let object = v.as_object_mut().unwrap();
    object.insert("AlarmArn".into(), arn(scope, &r.config.alarm_name).into());
    object.insert("StateValue".into(), r.state.clone().into());
    object.insert("StateReason".into(), r.reason.clone().into());
    object.insert(
        "StateUpdatedTimestamp".into(),
        json!(r.changed as f64 / 1000.0),
    );
    object.insert(
        "AlarmConfigurationUpdatedTimestamp".into(),
        json!(r.updated as f64 / 1000.0),
    );
    if let Some(data) = &r.reason_data {
        object.insert("StateReasonData".into(), data.clone().into());
    }
    object.retain(|_, v| !v.is_null());
    v
}
fn allowed(body: &Value, keys: &[&str]) -> Result<(), MonitoringError> {
    if body
        .as_object()
        .is_none_or(|m| m.keys().any(|k| !keys.contains(&k.as_str())))
    {
        Err(invalid("Unsupported alarm property"))
    } else {
        Ok(())
    }
}
fn names(body: &Value, key: &str) -> Result<Vec<String>, MonitoringError> {
    body.get(key)
        .map(|v| {
            v.as_array()
                .ok_or_else(|| invalid("Names must be an array"))?
                .iter()
                .map(|n| {
                    n.as_str()
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .ok_or_else(|| invalid("Invalid name"))
                })
                .collect()
        })
        .unwrap_or_else(|| Ok(vec![]))
}

fn optional_string<'a>(body: &'a Value, key: &str) -> Result<Option<&'a str>, MonitoringError> {
    body.get(key)
        .map(|value| {
            value
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| invalid(&format!("{key} must be a non-empty string")))
        })
        .transpose()
}
