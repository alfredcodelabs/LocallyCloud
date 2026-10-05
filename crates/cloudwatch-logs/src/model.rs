use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

use locallycloud_core::integration::metrics::MetricObservation;

use crate::pattern::FilterPattern;
use crate::protocol::MetricTransformation;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GroupKey {
    pub scope: ScopeKey,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogClass {
    Standard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: String,
    pub timestamp_ms: i64,
    pub ingestion_time_ms: i64,
    pub put_ordinal: u64,
    pub event_ordinal: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStream {
    pub name: String,
    pub arn: String,
    pub creation_time_ms: i64,
    #[serde(skip)]
    pub events: Vec<StoredEvent>,
    pub first_event_timestamp_ms: Option<i64>,
    pub last_event_timestamp_ms: Option<i64>,
    pub last_ingestion_time_ms: Option<i64>,
    pub stored_bytes: u64,
    pub revision: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MetricFilter {
    pub name: String,
    pub pattern_text: String,
    #[serde(skip, default = "empty_pattern")]
    pub pattern: Arc<FilterPattern>,
    pub transformation: MetricTransformation,
    pub creation_time_ms: i64,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMetricEffect {
    pub id: u64,
    pub group_key: GroupKey,
    pub source: MetricEffectSource,
    pub observation: MetricObservation,
    pub status: MetricEffectStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricEffectSource {
    Filter { name: String, revision: u64 },
    EmbeddedMetricFormat,
}

impl MetricEffectSource {
    pub fn is_filter(&self, filter_name: &str) -> bool {
        matches!(self, Self::Filter { name, .. } if name == filter_name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
pub struct SubscriptionFilter {
    pub name: String,
    pub pattern_text: String,
    #[serde(skip, default = "empty_pattern")]
    pub pattern: Arc<FilterPattern>,
    pub destination_arn: String,
    pub function_name: String,
    pub distribution: String,
    pub creation_time_ms: i64,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
pub struct LogGroup {
    pub name: String,
    pub arn: String,
    pub creation_time_ms: i64,
    pub retention_days: Option<u16>,
    pub class: LogClass,
    pub tags: BTreeMap<String, String>,
    #[serde(default)]
    pub streams: BTreeMap<String, LogStream>,
    pub metric_filters: BTreeMap<String, MetricFilter>,
    pub subscription_filters: BTreeMap<String, SubscriptionFilter>,
    pub revision: u64,
}

impl LogGroup {
    /// Describe responses and cursors need configuration, never historical event bodies.
    pub(crate) fn metadata(&self) -> Self {
        let mut group = self.metadata_without_streams();
        group.streams = self
            .streams
            .iter()
            .map(|(name, stream)| (name.clone(), stream.metadata()))
            .collect();
        group
    }

    pub(crate) fn metadata_without_streams(&self) -> Self {
        Self {
            name: self.name.clone(),
            arn: self.arn.clone(),
            creation_time_ms: self.creation_time_ms,
            retention_days: self.retention_days,
            class: self.class,
            tags: self.tags.clone(),
            streams: BTreeMap::new(),
            metric_filters: self.metric_filters.clone(),
            subscription_filters: self.subscription_filters.clone(),
            revision: self.revision,
        }
    }

    pub fn legacy_arn(&self) -> String {
        format!("{}:*", self.arn)
    }
}

fn empty_pattern() -> Arc<FilterPattern> {
    Arc::new(FilterPattern::compile(None).expect("empty filter pattern is valid"))
}

impl LogStream {
    pub(crate) fn metadata(&self) -> Self {
        Self {
            name: self.name.clone(),
            arn: self.arn.clone(),
            creation_time_ms: self.creation_time_ms,
            events: Vec::new(),
            first_event_timestamp_ms: self.first_event_timestamp_ms,
            last_event_timestamp_ms: self.last_event_timestamp_ms,
            last_ingestion_time_ms: self.last_ingestion_time_ms,
            stored_bytes: self.stored_bytes,
            revision: self.revision,
        }
    }
}
