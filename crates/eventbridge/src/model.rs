use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub maximum_attempts: u32,
    pub maximum_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub arn: String,
    pub role_arn: Option<String>,
    pub input: Option<String>,
    pub input_path: Option<String>,
    pub input_transformer: Option<(BTreeMap<String, String>, String)>,
    pub sqs_parameters: Option<Value>,
    pub retry: RetryPolicy,
    pub dead_letter_arn: Option<String>,
    pub extra: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub arn: String,
    pub state: String,
    pub event_pattern: Option<Value>,
    pub schedule_expression: Option<String>,
    pub description: Option<String>,
    pub role_arn: Option<String>,
    pub targets: Vec<Target>,
    pub tags: BTreeMap<String, String>,
    pub generation: u64,
}

impl Rule {
    pub fn enabled(&self) -> bool {
        self.state == "ENABLED" || self.state == "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBus {
    pub name: String,
    pub arn: String,
    pub description: Option<String>,
    pub event_source_name: Option<String>,
    pub policy: Option<Value>,
    pub kms_key_identifier: Option<String>,
    pub dead_letter_config: Option<Value>,
    pub log_config: Option<Value>,
    pub rules: BTreeMap<String, Rule>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedEvent {
    pub event: Value,
    pub time: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Archive {
    pub name: String,
    pub arn: String,
    pub source_arn: String,
    pub description: Option<String>,
    pub event_pattern: Option<Value>,
    pub retention_days: i64,
    pub tags: BTreeMap<String, String>,
    pub events: Vec<ArchivedEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Replay {
    pub name: String,
    pub arn: String,
    pub source_arn: String,
    pub destination: Value,
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,
    pub state: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub name: String,
    pub arn: String,
    pub auth_type: String,
    pub auth_parameters: Value,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiDestination {
    pub name: String,
    pub arn: String,
    pub connection_arn: String,
    pub endpoint: String,
    pub method: String,
    pub rate_limit: Option<i64>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleGroup {
    pub name: String,
    pub arn: String,
    pub created_at: OffsetDateTime,
    pub modified_at: OffsetDateTime,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub name: String,
    pub arn: String,
    pub group: String,
    pub expression: String,
    pub timezone: String,
    pub flexible_window: Value,
    pub start_date: Option<OffsetDateTime>,
    pub end_date: Option<OffsetDateTime>,
    pub state: String,
    pub action_after_completion: String,
    pub kms_key_arn: Option<String>,
    pub target: Value,
    pub tags: BTreeMap<String, String>,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pipe {
    pub name: String,
    pub arn: String,
    pub description: Option<String>,
    pub source: String,
    pub source_parameters: Value,
    pub enrichment: Option<String>,
    pub enrichment_parameters: Value,
    pub target: String,
    pub target_parameters: Value,
    pub role_arn: String,
    pub desired_state: String,
    pub current_state: String,
    pub tags: BTreeMap<String, String>,
    pub generation: u64,
    /// Last successfully processed sequence number for each stream shard.
    pub source_checkpoints: BTreeMap<String, String>,
    #[serde(default)]
    pub source_creation_timestamp: Option<f64>,
    #[serde(default = "source_start_timestamp")]
    pub source_start_timestamp: f64,
    #[serde(default)]
    pub source_cursor: usize,
}

pub(crate) fn source_start_timestamp() -> f64 {
    OffsetDateTime::now_utc().unix_timestamp_nanos() as f64 / 1_000_000_000.0
}
