//! Typed, protocol-neutral log delivery between native services.

use async_trait::async_trait;

use super::correlation::CorrelationContext;
use super::identity::CallerIdentity;

/// Contract version understood by the registry and native producers.
pub const INTERNAL_LOG_SINK_VERSION: u16 = 2;
/// Maximum number of nested producer-to-Logs hops in one causal flow.
pub const MAX_INTERNAL_LOG_DEPTH: u8 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogScope {
    pub account_id: String,
    pub region: String,
}

impl LogScope {
    pub fn new(account_id: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            region: region.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerGroupSpec {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerStreamSpec {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRef {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRef {
    pub group_name: String,
    pub stream_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerLogEvent {
    pub timestamp_ms: i64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerContext {
    pub source_service: String,
    pub identity: CallerIdentity,
    pub correlation: CorrelationContext,
    pub loop_depth: u8,
}

impl ProducerContext {
    pub fn next_hop(&self) -> Result<Self, SinkError> {
        if self.loop_depth >= MAX_INTERNAL_LOG_DEPTH {
            return Err(SinkError::LoopDetected);
        }
        Ok(Self {
            source_service: self.source_service.clone(),
            identity: self.identity.clone(),
            correlation: self.correlation.child(),
            loop_depth: self.loop_depth + 1,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendOutcome {
    pub stored_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SinkError {
    #[error("CloudWatch Logs sink is unavailable")]
    Unavailable,
    #[error("CloudWatch Logs sink is at capacity")]
    Backpressure,
    #[error("internal log producer loop limit exceeded")]
    LoopDetected,
    #[error("producer log request is invalid: {0}")]
    InvalidRequest(String),
    #[error("producer log resource is incompatible: {0}")]
    Incompatible(String),
    #[error("producer log resource was not found: {0}")]
    NotFound(String),
    #[error("CloudWatch Logs rejected the producer write: {0}")]
    Rejected(String),
    #[error("CloudWatch Logs producer write failed: {0}")]
    Internal(String),
}

/// Concrete CloudWatch Logs capability. Successful append means the batch committed.
#[async_trait]
pub trait InternalLogSink: Send + Sync {
    fn version(&self) -> u16 {
        INTERNAL_LOG_SINK_VERSION
    }

    async fn resolve_group(
        &self,
        scope: LogScope,
        spec: ProducerGroupSpec,
        context: ProducerContext,
    ) -> Result<GroupRef, SinkError>;

    async fn ensure_group(
        &self,
        scope: LogScope,
        spec: ProducerGroupSpec,
        context: ProducerContext,
    ) -> Result<GroupRef, SinkError>;

    async fn ensure_stream(
        &self,
        scope: LogScope,
        group: GroupRef,
        spec: ProducerStreamSpec,
        context: ProducerContext,
    ) -> Result<StreamRef, SinkError>;

    async fn append(
        &self,
        scope: LogScope,
        target: StreamRef,
        events: Vec<ProducerLogEvent>,
        context: ProducerContext,
    ) -> Result<AppendOutcome, SinkError>;
}
