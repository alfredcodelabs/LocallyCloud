use std::collections::BTreeMap;
use std::sync::Arc;

use localcloud_core::integration::metrics::MetricObservation;

use crate::pattern::FilterPattern;
use crate::protocol::MetricTransformation;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScopeKey {
    pub account_id: String,
    pub region: String,
}

impl ScopeKey {
    pub fn new(account_id: &str, region: &str) -> Self {
        Self {
            account_id: account_id.to_owned(),
            region: region.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GroupKey {
    pub scope: ScopeKey,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogClass {
    Standard,
}

#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub id: String,
    pub timestamp_ms: i64,
    pub ingestion_time_ms: i64,
    pub put_ordinal: u64,
    pub event_ordinal: u32,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PagedEvent {
    pub log_stream_name: String,
    pub event: StoredEvent,
}

#[derive(Debug, Clone)]
pub struct PendingLogEvent {
    pub timestamp_ms: i64,
    pub event_ordinal: u32,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct RejectedEventIndexes {
    pub too_old_end: Option<u32>,
    pub expired_end: Option<u32>,
    pub too_new_start: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct PutEventsResult {
    pub next_sequence_token: String,
    pub rejected: RejectedEventIndexes,
}

#[derive(Debug, Clone)]
pub struct LogStream {
    pub name: String,
    pub arn: String,
    pub creation_time_ms: i64,
    pub events: Vec<StoredEvent>,
    pub first_event_timestamp_ms: Option<i64>,
    pub last_event_timestamp_ms: Option<i64>,
    pub last_ingestion_time_ms: Option<i64>,
    pub stored_bytes: u64,
    pub revision: u64,
}

#[derive(Clone)]
pub struct MetricFilter {
    pub name: String,
    pub pattern_text: String,
    pub pattern: Arc<FilterPattern>,
    pub transformation: MetricTransformation,
    pub creation_time_ms: i64,
    pub revision: u64,
}

#[derive(Debug, Clone)]
pub struct PendingMetricEffect {
    pub id: u64,
    pub group_key: GroupKey,
    pub source: MetricEffectSource,
    pub observation: MetricObservation,
    pub status: MetricEffectStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricEffectSource {
    Filter { name: String, revision: u64 },
    EmbeddedMetricFormat,
}

impl MetricEffectSource {
    pub fn is_filter(&self, filter_name: &str) -> bool {
        matches!(self, Self::Filter { name, .. } if name == filter_name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricEffectStatus {
    Pending,
    Failed,
}

pub struct MetricEffectCandidate {
    pub filter_name: String,
    pub filter_revision: u64,
    pub default_minute: Option<i64>,
    pub observation: MetricObservation,
}

#[derive(Clone)]
pub struct SubscriptionFilter {
    pub name: String,
    pub pattern_text: String,
    pub pattern: Arc<FilterPattern>,
    pub destination_arn: String,
    pub function_name: String,
    pub distribution: String,
    pub creation_time_ms: i64,
    pub revision: u64,
}

#[derive(Debug, Clone)]
pub struct PendingSubscriptionDelivery {
    pub id: u64,
    pub group_key: GroupKey,
    pub filter_name: String,
    pub filter_revision: u64,
    pub function_name: String,
    pub log_stream_name: String,
    pub events: Vec<StoredEvent>,
    pub status: SubscriptionDeliveryStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionDeliveryStatus {
    Pending,
    Failed,
}

pub struct SubscriptionDeliveryCandidate {
    pub filter_name: String,
    pub filter_revision: u64,
    pub function_name: String,
    pub events: Vec<StoredEvent>,
}

#[derive(Clone)]
pub struct LogGroup {
    pub name: String,
    pub arn: String,
    pub creation_time_ms: i64,
    pub retention_days: Option<u16>,
    pub class: LogClass,
    pub tags: BTreeMap<String, String>,
    pub streams: BTreeMap<String, LogStream>,
    pub metric_filters: BTreeMap<String, MetricFilter>,
    pub subscription_filters: BTreeMap<String, SubscriptionFilter>,
    pub revision: u64,
}

impl LogGroup {
    pub fn legacy_arn(&self) -> String {
        format!("{}:*", self.arn)
    }
}
