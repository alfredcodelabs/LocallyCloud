//! Typed, protocol-neutral CloudWatch metric delivery between native services.

use std::collections::BTreeMap;
use std::fmt;

/// Contract version understood by the registry and native producers.
pub const METRIC_SINK_VERSION: u16 = 1;

/// One fully resolved metric sample.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MetricObservation {
    pub account_id: String,
    pub region: String,
    pub namespace: String,
    pub metric_name: String,
    pub dimensions: BTreeMap<String, String>,
    pub timestamp_ms: i64,
    pub value: f64,
    pub unit: Option<MetricUnit>,
    pub storage_resolution: u16,
    pub origin: MetricOrigin,
    pub correlation_id: String,
}

impl fmt::Debug for MetricObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetricObservation")
            .field("account_id", &self.account_id)
            .field("region", &self.region)
            .field("namespace", &self.namespace)
            .field("metric_name", &self.metric_name)
            .field("dimension_count", &self.dimensions.len())
            .field("timestamp_ms", &self.timestamp_ms)
            .field("value", &self.value)
            .field("unit", &self.unit)
            .field("storage_resolution", &self.storage_resolution)
            .field("origin", &self.origin)
            .field("correlation_id", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MetricOrigin {
    CloudWatchLogs,
    PublicPutMetricData,
    /// Vended metrics published by a native service into its own `AWS/<Service>` namespace.
    AwsService,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MetricUnit {
    Seconds,
    Microseconds,
    Milliseconds,
    Bytes,
    Kilobytes,
    Megabytes,
    Gigabytes,
    Terabytes,
    Bits,
    Kilobits,
    Megabits,
    Gigabits,
    Terabits,
    Percent,
    Count,
    BytesPerSecond,
    KilobytesPerSecond,
    MegabytesPerSecond,
    GigabytesPerSecond,
    TerabytesPerSecond,
    BitsPerSecond,
    KilobitsPerSecond,
    MegabitsPerSecond,
    GigabitsPerSecond,
    TerabitsPerSecond,
    CountPerSecond,
    None,
}

impl MetricUnit {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "Seconds" => Some(Self::Seconds),
            "Microseconds" => Some(Self::Microseconds),
            "Milliseconds" => Some(Self::Milliseconds),
            "Bytes" => Some(Self::Bytes),
            "Kilobytes" => Some(Self::Kilobytes),
            "Megabytes" => Some(Self::Megabytes),
            "Gigabytes" => Some(Self::Gigabytes),
            "Terabytes" => Some(Self::Terabytes),
            "Bits" => Some(Self::Bits),
            "Kilobits" => Some(Self::Kilobits),
            "Megabits" => Some(Self::Megabits),
            "Gigabits" => Some(Self::Gigabits),
            "Terabits" => Some(Self::Terabits),
            "Percent" => Some(Self::Percent),
            "Count" => Some(Self::Count),
            "Bytes/Second" => Some(Self::BytesPerSecond),
            "Kilobytes/Second" => Some(Self::KilobytesPerSecond),
            "Megabytes/Second" => Some(Self::MegabytesPerSecond),
            "Gigabytes/Second" => Some(Self::GigabytesPerSecond),
            "Terabytes/Second" => Some(Self::TerabytesPerSecond),
            "Bits/Second" => Some(Self::BitsPerSecond),
            "Kilobits/Second" => Some(Self::KilobitsPerSecond),
            "Megabits/Second" => Some(Self::MegabitsPerSecond),
            "Gigabits/Second" => Some(Self::GigabitsPerSecond),
            "Terabits/Second" => Some(Self::TerabitsPerSecond),
            "Count/Second" => Some(Self::CountPerSecond),
            "None" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seconds => "Seconds",
            Self::Microseconds => "Microseconds",
            Self::Milliseconds => "Milliseconds",
            Self::Bytes => "Bytes",
            Self::Kilobytes => "Kilobytes",
            Self::Megabytes => "Megabytes",
            Self::Gigabytes => "Gigabytes",
            Self::Terabytes => "Terabytes",
            Self::Bits => "Bits",
            Self::Kilobits => "Kilobits",
            Self::Megabits => "Megabits",
            Self::Gigabits => "Gigabits",
            Self::Terabits => "Terabits",
            Self::Percent => "Percent",
            Self::Count => "Count",
            Self::BytesPerSecond => "Bytes/Second",
            Self::KilobytesPerSecond => "Kilobytes/Second",
            Self::MegabytesPerSecond => "Megabytes/Second",
            Self::GigabytesPerSecond => "Gigabytes/Second",
            Self::TerabytesPerSecond => "Terabytes/Second",
            Self::BitsPerSecond => "Bits/Second",
            Self::KilobitsPerSecond => "Kilobits/Second",
            Self::MegabitsPerSecond => "Megabits/Second",
            Self::GigabitsPerSecond => "Gigabits/Second",
            Self::TerabitsPerSecond => "Terabits/Second",
            Self::CountPerSecond => "Count/Second",
            Self::None => "None",
        }
    }
}

/// Receiver outcome. For `emit_durable`, `Accepted` acknowledges a committed batch;
/// for `try_emit`, it only acknowledges bounded queue acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitOutcome {
    Accepted,
    Unavailable,
    Full,
    Dropped,
    IncompatibleVersion,
}

/// Bounded metric receiver capability.
#[async_trait::async_trait]
pub trait MetricSink: Send + Sync {
    fn version(&self) -> u16 {
        METRIC_SINK_VERSION
    }

    fn try_emit(&self, observations: Vec<MetricObservation>) -> EmitOutcome;

    /// Acknowledge only after the receiver commits every observation to durable state.
    /// Queue acceptance from `try_emit` does not satisfy this contract. Receivers
    /// without durable storage deliberately leave an outbox delivery pending.
    async fn emit_durable(&self, _observations: Vec<MetricObservation>) -> EmitOutcome {
        EmitOutcome::Unavailable
    }
}

#[derive(Debug, Default)]
pub struct NoopMetricSink;

impl MetricSink for NoopMetricSink {
    fn try_emit(&self, _observations: Vec<MetricObservation>) -> EmitOutcome {
        EmitOutcome::Unavailable
    }
}
