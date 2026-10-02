//! Vended `AWS/SQS` CloudWatch metrics delivered through the internal Monitoring sink.
//!
//! Operation counters are aggregated in memory into one-minute buckets per queue (the AWS
//! one-minute granularity) so traffic never turns into one observation per API call;
//! `SentMessageSize` keeps one sample per message, capped per bucket. A sampler task flushes
//! the buckets and samples the queue-depth gauges every period. It starts lazily on first
//! queue use and exits once there are no queues and nothing is pending, so an idle SQS service
//! runs no background work. Delivery is best effort and never affects an SQS API result.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use localcloud_core::integration::metrics::{
    EmitOutcome, MetricObservation, MetricOrigin, MetricUnit,
};
use localcloud_core::registry::{ServiceName, ServiceRegistry};
use tokio::task::JoinHandle;

use crate::model::QueueArn;
use crate::store::{QueueState, SqsStore};

const NAMESPACE: &str = "AWS/SQS";
const SAMPLE_PERIOD: Duration = Duration::from_secs(60);
const MINUTE_MS: i64 = 60_000;
/// Monitoring rejects batches above 1000 observations.
const MAX_BATCH: usize = 1_000;
/// Bound on per-message `SentMessageSize` samples kept per queue and minute.
const MAX_SIZE_SAMPLES: usize = 1_000;
const VENDED_ORIGIN: MetricOrigin = MetricOrigin::AwsService;

/// (account, region, queue name, minute start in ms).
type BucketKey = (String, String, String, i64);

#[derive(Default)]
struct Counters {
    sent: u64,
    received: u64,
    empty_receives: u64,
    deleted: u64,
    sizes: Vec<f64>,
}

/// Visible / in-flight / delayed message counts, as reported by `GetQueueAttributes`.
pub(crate) fn message_counts(state: &QueueState, now: Instant) -> (u64, u64, u64) {
    let mut counts = (0, 0, 0);
    for message in &state.messages {
        if message.is_visible(now) {
            counts.0 += 1;
        } else if message.receipt_handle.is_some() {
            counts.1 += 1;
        } else {
            counts.2 += 1;
        }
    }
    counts
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Shared recorder used by operations and by the sampler task.
pub struct MetricsRecorder {
    store: Arc<SqsStore>,
    registry: Weak<ServiceRegistry>,
    period: Duration,
    pending: Mutex<BTreeMap<BucketKey, Counters>>,
    sampler: Mutex<Option<JoinHandle<()>>>,
}

impl MetricsRecorder {
    pub fn record_sent(self: &Arc<Self>, arn: &QueueArn, size: usize) {
        self.record(arn, |counters| {
            counters.sent += 1;
            if counters.sizes.len() < MAX_SIZE_SAMPLES {
                counters.sizes.push(size as f64);
            }
        });
    }

    /// One receive call: `count` messages returned, or an empty receive when zero.
    pub fn record_received(self: &Arc<Self>, arn: &QueueArn, count: usize) {
        self.record(arn, |counters| {
            if count == 0 {
                counters.empty_receives += 1;
            } else {
                counters.received += count as u64;
            }
        });
    }

    pub fn record_deleted(self: &Arc<Self>, arn: &QueueArn, count: usize) {
        if count > 0 {
            self.record(arn, |counters| counters.deleted += count as u64);
        }
    }

    /// Start the gauge sampler on queue use (no-op when already running).
    pub fn touch(self: &Arc<Self>) {
        if let Ok(mut sampler) = self.sampler.lock() {
            self.start_locked(&mut sampler);
        }
    }

    fn record(self: &Arc<Self>, arn: &QueueArn, update: impl FnOnce(&mut Counters)) {
        // The sampler lock is held while updating so the sampler cannot exit between the
        // start check and the insert, which would strand the bucket.
        let Ok(mut sampler) = self.sampler.lock() else {
            return;
        };
        if !self.start_locked(&mut sampler) {
            return;
        }
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        let minute = now_ms() / MINUTE_MS * MINUTE_MS;
        let key = (
            arn.account.clone(),
            arn.region.clone(),
            arn.name.clone(),
            minute,
        );
        update(pending.entry(key).or_default());
    }

    /// Ensure the sampler runs. Without a Monitoring sink nothing could be delivered, so
    /// nothing is started and callers drop their samples.
    fn start_locked(self: &Arc<Self>, sampler: &mut Option<JoinHandle<()>>) -> bool {
        if sampler.as_ref().is_some_and(|handle| !handle.is_finished()) {
            return true;
        }
        if resolve_sink(&self.registry).is_none() {
            return false;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return false;
        };
        *sampler = Some(runtime.spawn(run(self.clone())));
        true
    }

    /// Flush pending counters and sample gauges once; returns the emitted observations count.
    pub(crate) async fn tick(&self) -> usize {
        let mut observations = self.drain_counters();
        observations.extend(self.sample_gauges().await);
        let emitted = observations.len();
        if observations.is_empty() {
            return 0;
        }
        let Some(sink) = resolve_sink(&self.registry) else {
            tracing::debug!(
                count = emitted,
                "AWS/SQS metrics dropped: monitoring unavailable"
            );
            return 0;
        };
        while !observations.is_empty() {
            let rest = observations.split_off(observations.len().min(MAX_BATCH));
            let outcome = sink.try_emit(std::mem::replace(&mut observations, rest));
            if outcome != EmitOutcome::Accepted {
                tracing::debug!(?outcome, "AWS/SQS metric batch not accepted");
            }
        }
        emitted
    }

    #[cfg(test)]
    pub(crate) fn sampler_running(&self) -> bool {
        self.sampler
            .lock()
            .map(|sampler| sampler.as_ref().is_some_and(|handle| !handle.is_finished()))
            .unwrap_or(false)
    }

    /// Exit when no queue exists and nothing is pending; decided under the sampler lock.
    fn should_stop(&self) -> bool {
        let Ok(mut sampler) = self.sampler.lock() else {
            return true;
        };
        let idle = self.store.is_empty()
            && self
                .pending
                .lock()
                .map(|pending| pending.is_empty())
                .unwrap_or(true);
        if idle {
            *sampler = None;
        }
        idle
    }

    fn drain_counters(&self) -> Vec<MetricObservation> {
        let pending = match self.pending.lock() {
            Ok(mut pending) => std::mem::take(&mut *pending),
            Err(_) => return Vec::new(),
        };
        let mut observations = Vec::new();
        for ((account, region, queue, minute), counters) in pending {
            let mut push = |name: &str, value: f64, unit: MetricUnit| {
                observations.push(observation(
                    &account, &region, &queue, name, minute, value, unit,
                ));
            };
            push(
                "NumberOfMessagesSent",
                counters.sent as f64,
                MetricUnit::Count,
            );
            push(
                "NumberOfMessagesReceived",
                counters.received as f64,
                MetricUnit::Count,
            );
            push(
                "NumberOfEmptyReceives",
                counters.empty_receives as f64,
                MetricUnit::Count,
            );
            push(
                "NumberOfMessagesDeleted",
                counters.deleted as f64,
                MetricUnit::Count,
            );
            for size in counters.sizes {
                push("SentMessageSize", size, MetricUnit::Bytes);
            }
        }
        observations
    }

    async fn sample_gauges(&self) -> Vec<MetricObservation> {
        let mut observations = Vec::new();
        for queue in self.store.all() {
            let timestamp = now_ms();
            let (visible, not_visible, delayed, oldest) = {
                let state = queue.state.lock().await;
                let cutoff =
                    timestamp.saturating_sub(state.retention_period().saturating_mul(1_000));
                let (visible, not_visible, delayed) = message_counts(&state, Instant::now());
                let oldest = state
                    .messages
                    .iter()
                    .map(|message| message.sent_timestamp_ms)
                    .filter(|sent| *sent > cutoff)
                    .min();
                (visible, not_visible, delayed, oldest)
            };
            let age = oldest.map_or(0, |sent| timestamp.saturating_sub(sent).max(0) / 1_000);
            let arn = &queue.arn;
            for (name, value, unit) in [
                (
                    "ApproximateNumberOfMessagesVisible",
                    visible as f64,
                    MetricUnit::Count,
                ),
                (
                    "ApproximateNumberOfMessagesNotVisible",
                    not_visible as f64,
                    MetricUnit::Count,
                ),
                (
                    "ApproximateNumberOfMessagesDelayed",
                    delayed as f64,
                    MetricUnit::Count,
                ),
                (
                    "ApproximateAgeOfOldestMessage",
                    age as f64,
                    MetricUnit::Seconds,
                ),
            ] {
                observations.push(observation(
                    &arn.account,
                    &arn.region,
                    &arn.name,
                    name,
                    timestamp,
                    value,
                    unit,
                ));
            }
        }
        observations
    }
}

fn resolve_sink(
    registry: &Weak<ServiceRegistry>,
) -> Option<Arc<dyn localcloud_core::integration::metrics::MetricSink>> {
    registry
        .upgrade()
        .and_then(|registry| registry.metric_sink(&ServiceName::new("monitoring")))
}

fn observation(
    account: &str,
    region: &str,
    queue: &str,
    metric_name: &str,
    timestamp_ms: i64,
    value: f64,
    unit: MetricUnit,
) -> MetricObservation {
    MetricObservation {
        account_id: account.to_owned(),
        region: region.to_owned(),
        namespace: NAMESPACE.to_owned(),
        metric_name: metric_name.to_owned(),
        dimensions: BTreeMap::from([("QueueName".to_owned(), queue.to_owned())]),
        timestamp_ms,
        value,
        unit: Some(unit),
        storage_resolution: 60,
        origin: VENDED_ORIGIN,
        correlation_id: format!("sqs:{metric_name}:{timestamp_ms}"),
    }
}

async fn run(recorder: Arc<MetricsRecorder>) {
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + recorder.period,
        recorder.period,
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        recorder.tick().await;
        if recorder.should_stop() {
            return;
        }
    }
}

/// Owner held by the handler; aborts the sampler when the handler is dropped.
pub struct SqsMetrics {
    recorder: Arc<MetricsRecorder>,
}

impl SqsMetrics {
    pub fn new(store: Arc<SqsStore>, registry: Weak<ServiceRegistry>) -> Self {
        Self::build(store, registry, SAMPLE_PERIOD)
    }

    #[cfg(test)]
    pub(crate) fn with_period(
        store: Arc<SqsStore>,
        registry: Weak<ServiceRegistry>,
        period: Duration,
    ) -> Self {
        Self::build(store, registry, period)
    }

    fn build(store: Arc<SqsStore>, registry: Weak<ServiceRegistry>, period: Duration) -> Self {
        Self {
            recorder: Arc::new(MetricsRecorder {
                store,
                registry,
                period,
                pending: Mutex::new(BTreeMap::new()),
                sampler: Mutex::new(None),
            }),
        }
    }

    pub fn recorder(&self) -> Arc<MetricsRecorder> {
        self.recorder.clone()
    }
}

impl Drop for SqsMetrics {
    fn drop(&mut self) {
        if let Ok(mut sampler) = self.recorder.sampler.lock() {
            if let Some(handle) = sampler.take() {
                handle.abort();
            }
        }
    }
}
