//! Vended `AWS/Lambda` CloudWatch metrics delivered through the internal Monitoring sink.
//!
//! Invocations are aggregated in memory into one-minute buckets per function (the AWS
//! one-minute granularity), so a burst becomes a handful of observations instead of one
//! channel send per invocation. `Invocations`, `Errors` and `Throttles` are summed per bucket;
//! `Duration` keeps one sample per invocation, capped at [`MAX_DURATION_SAMPLES`] per function
//! and minute within one flush (later samples of a full bucket are not recorded; the counters
//! stay exact). A minute split across two flushes can carry up to twice the cap.
//!
//! A flush task starts lazily on the first recorded invocation, and only when Monitoring is
//! registered: without a sink nothing is buffered and no task runs. The task flushes every
//! period and exits once nothing is pending. Batches the sink cannot take right now (`Full`,
//! `Unavailable`) are merged back and retried on the next tick; at most
//! [`MAX_PENDING_BUCKETS`] buckets are retained and the oldest minutes are dropped beyond
//! that. Invalid batches (`Dropped`) are discarded. `Executor::shutdown` flushes once more into
//! Monitoring's queue; samples still buffered (at most one period) are lost on a crash.
//! Delivery is best effort and never affects an invocation.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use locallycloud_core::integration::metrics::{
    EmitOutcome, MetricObservation, MetricOrigin, MetricSink, MetricUnit,
};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use tokio::task::JoinHandle;
use uuid::Uuid;

const NAMESPACE: &str = "AWS/Lambda";
const FLUSH_PERIOD: Duration = Duration::from_secs(60);
const MINUTE_MS: i64 = 60_000;
/// Monitoring rejects batches above 1000 observations.
const MAX_BATCH: usize = 1_000;
/// Bound on per-invocation `Duration` samples kept per function and minute.
pub(crate) const MAX_DURATION_SAMPLES: usize = 1_000;
/// Bound on buckets retained while Monitoring is saturated; the oldest minutes are dropped.
pub(crate) const MAX_PENDING_BUCKETS: usize = 10_000;

/// (account, region, function name, minute start in ms).
type BucketKey = (String, String, String, i64);

#[derive(Default)]
struct Counters {
    invocations: u64,
    errors: u64,
    throttles: u64,
    /// AWS reports `Errors` (Sum 0) for every minute with invocations, not only failed ones.
    report_errors: bool,
    durations: Vec<f64>,
}

impl Counters {
    fn push_duration(&mut self, duration_ms: f64) {
        if self.durations.len() < MAX_DURATION_SAMPLES {
            self.durations.push(duration_ms);
        }
    }

    fn apply(&mut self, part: Part) {
        match part {
            Part::Invocations(count) => self.invocations += count,
            Part::Errors(count) => {
                self.errors += count;
                self.report_errors = true;
            }
            Part::Throttles(count) => self.throttles += count,
            Part::Duration(duration_ms) => self.push_duration(duration_ms),
        }
    }

    fn into_parts(self) -> impl Iterator<Item = Part> {
        let invocations = (self.invocations > 0).then_some(Part::Invocations(self.invocations));
        let errors = self.report_errors.then_some(Part::Errors(self.errors));
        let throttles = (self.throttles > 0).then_some(Part::Throttles(self.throttles));
        invocations
            .into_iter()
            .chain(errors)
            .chain(throttles)
            .chain(self.durations.into_iter().map(Part::Duration))
    }
}

/// One observation of a bucket, kept structured so an undelivered batch can be merged back.
#[derive(Clone, Copy)]
enum Part {
    Invocations(u64),
    Errors(u64),
    Throttles(u64),
    Duration(f64),
}

impl Part {
    fn metric(self) -> (&'static str, f64, MetricUnit) {
        match self {
            Part::Invocations(count) => ("Invocations", count as f64, MetricUnit::Count),
            Part::Errors(count) => ("Errors", count as f64, MetricUnit::Count),
            Part::Throttles(count) => ("Throttles", count as f64, MetricUnit::Count),
            Part::Duration(duration_ms) => ("Duration", duration_ms, MetricUnit::Milliseconds),
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Merge into `pending`, dropping the oldest minute when a new bucket would exceed the cap.
fn merge(
    pending: &mut BTreeMap<BucketKey, Counters>,
    key: BucketKey,
    update: impl FnOnce(&mut Counters),
) {
    if !pending.contains_key(&key) && pending.len() >= MAX_PENDING_BUCKETS {
        let oldest = pending.keys().min_by_key(|bucket| bucket.3).cloned();
        match oldest {
            Some(oldest) if oldest.3 <= key.3 => {
                pending.remove(&oldest);
            }
            _ => {
                tracing::debug!("AWS/Lambda metric bucket dropped: pending buffer full");
                return;
            }
        }
        tracing::debug!("oldest AWS/Lambda metric bucket dropped: pending buffer full");
    }
    update(pending.entry(key).or_default());
}

/// Shared recorder used by the executor and by the flush task.
pub(crate) struct MetricsRecorder {
    registry: Weak<ServiceRegistry>,
    period: Duration,
    pending: Mutex<BTreeMap<BucketKey, Counters>>,
    sampler: Mutex<Option<JoinHandle<()>>>,
}

impl MetricsRecorder {
    /// One completed (or failed-to-start) invocation.
    pub(crate) fn record_invocation(
        self: &Arc<Self>,
        account: &str,
        region: &str,
        function_name: &str,
        errored: bool,
        duration_ms: Option<f64>,
    ) {
        self.record(account, region, function_name, |counters| {
            counters.invocations += 1;
            counters.report_errors = true;
            if errored {
                counters.errors += 1;
            }
            if let Some(duration_ms) = duration_ms {
                counters.push_duration(duration_ms);
            }
        });
    }

    /// One invocation rejected for concurrency.
    pub(crate) fn record_throttle(self: &Arc<Self>, account: &str, region: &str, function: &str) {
        self.record(account, region, function, |counters| {
            counters.throttles += 1
        });
    }

    fn record(
        self: &Arc<Self>,
        account: &str,
        region: &str,
        function_name: &str,
        update: impl FnOnce(&mut Counters),
    ) {
        // Lock order: sampler → pending. The sampler lock is held while updating so the task
        // cannot decide to exit between the start check and the insert, stranding the bucket.
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
            account.to_owned(),
            region.to_owned(),
            function_name.to_owned(),
            minute,
        );
        merge(&mut pending, key, update);
    }

    /// Ensure the flush task runs. Without a Monitoring sink nothing could be delivered, so
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

    /// Flush pending buckets once; returns the number of accepted observations. Batches the
    /// sink cannot take now are merged back for the next tick.
    pub(crate) fn tick(&self) -> usize {
        let drained = match self.pending.lock() {
            Ok(mut pending) => std::mem::take(&mut *pending),
            Err(_) => return 0,
        };
        if drained.is_empty() {
            return 0;
        }
        let Some(sink) = resolve_sink(&self.registry) else {
            tracing::debug!("AWS/Lambda metrics dropped: monitoring unavailable");
            return 0;
        };
        let mut keys = Vec::with_capacity(drained.len());
        let mut parts = Vec::new();
        for (key, counters) in drained {
            let index = keys.len();
            keys.push(key);
            parts.extend(counters.into_parts().map(|part| (index, part)));
        }
        let mut accepted = 0;
        let mut remaining = parts.into_iter();
        loop {
            let batch: Vec<(usize, Part)> = remaining.by_ref().take(MAX_BATCH).collect();
            if batch.is_empty() {
                break;
            }
            // Monitoring deduplicates by (correlation, ordinal in batch): one id per batch
            // keeps every flush distinct even when a minute is flushed more than once.
            let correlation_id = format!("lambda-metrics:{}", Uuid::new_v4());
            let observations = batch
                .iter()
                .map(|(index, part)| observation(&keys[*index], *part, &correlation_id))
                .collect();
            match sink.try_emit(observations) {
                EmitOutcome::Accepted => accepted += batch.len(),
                outcome @ (EmitOutcome::Full | EmitOutcome::Unavailable) => {
                    tracing::debug!(?outcome, "AWS/Lambda metrics deferred to the next flush");
                    self.requeue(&keys, batch.into_iter().chain(remaining));
                    break;
                }
                outcome @ (EmitOutcome::Dropped | EmitOutcome::IncompatibleVersion) => {
                    tracing::debug!(?outcome, "AWS/Lambda metric batch discarded");
                }
            }
        }
        accepted
    }

    fn requeue(&self, keys: &[BucketKey], parts: impl Iterator<Item = (usize, Part)>) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        for (index, part) in parts {
            merge(&mut pending, keys[index].clone(), |counters| {
                counters.apply(part)
            });
        }
    }

    /// Exit when nothing is pending; decided under the sampler lock so a concurrent record
    /// either restarts the task or is observed here.
    fn should_stop(&self) -> bool {
        let Ok(mut sampler) = self.sampler.lock() else {
            return true;
        };
        let idle = self
            .pending
            .lock()
            .map(|pending| pending.is_empty())
            .unwrap_or(true);
        if idle {
            *sampler = None;
        }
        idle
    }

    #[cfg(test)]
    pub(crate) fn sampler_running(&self) -> bool {
        self.sampler
            .lock()
            .map(|sampler| sampler.as_ref().is_some_and(|handle| !handle.is_finished()))
            .unwrap_or(false)
    }

    #[cfg(test)]
    pub(crate) fn pending_buckets(&self) -> usize {
        self.pending
            .lock()
            .map(|pending| pending.len())
            .unwrap_or(0)
    }
}

fn resolve_sink(registry: &Weak<ServiceRegistry>) -> Option<Arc<dyn MetricSink>> {
    registry
        .upgrade()
        .and_then(|registry| registry.metric_sink(&ServiceName::new("monitoring")))
}

fn observation(key: &BucketKey, part: Part, correlation_id: &str) -> MetricObservation {
    let (account, region, function_name, minute) = key;
    let (metric_name, value, unit) = part.metric();
    MetricObservation {
        account_id: account.clone(),
        region: region.clone(),
        namespace: NAMESPACE.to_owned(),
        metric_name: metric_name.to_owned(),
        dimensions: BTreeMap::from([("FunctionName".to_owned(), function_name.clone())]),
        timestamp_ms: *minute,
        value,
        unit: Some(unit),
        storage_resolution: 60,
        origin: MetricOrigin::AwsService,
        correlation_id: correlation_id.to_owned(),
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
        recorder.tick();
        if recorder.should_stop() {
            return;
        }
    }
}

/// Owner held by the executor; stops the task and flushes once more when dropped.
pub(crate) struct LambdaMetrics {
    recorder: Arc<MetricsRecorder>,
}

impl LambdaMetrics {
    pub(crate) fn new(registry: Weak<ServiceRegistry>) -> Self {
        Self::with_period(registry, FLUSH_PERIOD)
    }

    pub(crate) fn with_period(registry: Weak<ServiceRegistry>, period: Duration) -> Self {
        Self {
            recorder: Arc::new(MetricsRecorder {
                registry,
                period,
                pending: Mutex::new(BTreeMap::new()),
                sampler: Mutex::new(None),
            }),
        }
    }

    pub(crate) fn recorder(&self) -> &Arc<MetricsRecorder> {
        &self.recorder
    }
}

impl Drop for LambdaMetrics {
    fn drop(&mut self) {
        let handle = self
            .recorder
            .sampler
            .lock()
            .ok()
            .and_then(|mut sampler| sampler.take());
        if let Some(handle) = handle {
            handle.abort();
        }
        self.recorder.tick();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};

    struct StubHandler;

    #[async_trait]
    impl locallycloud_core::handler::NativeHandler for StubHandler {
        async fn handle(
            &self,
            _request: locallycloud_core::handler::ServiceRequest,
        ) -> axum::response::Response {
            axum::response::IntoResponse::into_response(http::StatusCode::OK)
        }
    }

    /// Records accepted batches; answers `outcome_before` for the first `refusals` attempts.
    struct TestSink {
        refusals: Mutex<usize>,
        outcome_before: EmitOutcome,
        batches: Mutex<Vec<Vec<MetricObservation>>>,
    }

    impl TestSink {
        fn new(refusals: usize, outcome_before: EmitOutcome) -> Arc<Self> {
            Arc::new(Self {
                refusals: Mutex::new(refusals),
                outcome_before,
                batches: Mutex::new(Vec::new()),
            })
        }

        fn observations(&self) -> Vec<MetricObservation> {
            self.batches.lock().unwrap().concat()
        }

        fn sum(&self, metric: &str) -> f64 {
            self.observations()
                .iter()
                .filter(|observation| observation.metric_name == metric)
                .map(|observation| observation.value)
                .sum()
        }

        fn count(&self, metric: &str) -> usize {
            self.observations()
                .iter()
                .filter(|observation| observation.metric_name == metric)
                .count()
        }
    }

    impl MetricSink for TestSink {
        fn try_emit(&self, observations: Vec<MetricObservation>) -> EmitOutcome {
            let mut refusals = self.refusals.lock().unwrap();
            if *refusals > 0 {
                *refusals -= 1;
                return self.outcome_before;
            }
            self.batches.lock().unwrap().push(observations);
            EmitOutcome::Accepted
        }
    }

    fn registry_with(sink: Arc<dyn MetricSink>) -> Arc<ServiceRegistry> {
        let registry = ServiceRegistry::with_known_services();
        registry.register_native_with_metric_sink(
            ServiceName::new("monitoring"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            Arc::new(StubHandler),
            sink,
        );
        registry
    }

    #[tokio::test]
    async fn without_monitoring_there_is_no_task_and_no_buffer() {
        let registry = ServiceRegistry::with_known_services();
        let metrics = LambdaMetrics::new(Arc::downgrade(&registry));
        let recorder = metrics.recorder();
        recorder.record_invocation("000000000000", "us-east-1", "fn", false, Some(1.0));
        recorder.record_throttle("000000000000", "us-east-1", "fn");
        assert!(!recorder.sampler_running());
        assert_eq!(recorder.pending_buckets(), 0);
    }

    #[tokio::test]
    async fn counters_are_summed_per_minute_and_errors_reported_as_zero() {
        let sink = TestSink::new(0, EmitOutcome::Full);
        let registry = registry_with(sink.clone());
        let metrics = LambdaMetrics::new(Arc::downgrade(&registry));
        let recorder = metrics.recorder();
        recorder.record_invocation("000000000000", "us-east-1", "ok", false, Some(2.0));
        recorder.record_invocation("000000000000", "us-east-1", "ok", false, Some(3.0));
        recorder.record_invocation("000000000000", "us-east-1", "bad", true, None);
        recorder.record_throttle("000000000000", "us-east-1", "throttled");
        assert!(recorder.sampler_running());
        recorder.tick();
        let observations = sink.observations();
        let find = |function: &str, metric: &str| -> Vec<f64> {
            observations
                .iter()
                .filter(|observation| {
                    observation.dimensions["FunctionName"] == function
                        && observation.metric_name == metric
                })
                .map(|observation| observation.value)
                .collect()
        };
        assert_eq!(find("ok", "Invocations"), vec![2.0]);
        assert_eq!(find("ok", "Errors"), vec![0.0]);
        assert_eq!(find("ok", "Duration"), vec![2.0, 3.0]);
        assert_eq!(find("bad", "Invocations"), vec![1.0]);
        assert_eq!(find("bad", "Errors"), vec![1.0]);
        assert!(find("bad", "Duration").is_empty());
        assert_eq!(find("throttled", "Throttles"), vec![1.0]);
        assert!(find("throttled", "Invocations").is_empty());
        assert!(find("throttled", "Errors").is_empty());
        for observation in &observations {
            assert_eq!(observation.namespace, "AWS/Lambda");
            assert_eq!(observation.timestamp_ms % MINUTE_MS, 0);
            assert_eq!(observation.storage_resolution, 60);
            assert_eq!(observation.origin, MetricOrigin::AwsService);
        }
        assert_eq!(recorder.pending_buckets(), 0);
    }

    #[tokio::test]
    async fn duration_samples_are_capped_and_batches_bounded() {
        let sink = TestSink::new(0, EmitOutcome::Full);
        let registry = registry_with(sink.clone());
        let metrics = LambdaMetrics::new(Arc::downgrade(&registry));
        let recorder = metrics.recorder();
        for _ in 0..1_500 {
            recorder.record_invocation("000000000000", "us-east-1", "fn", false, Some(1.0));
        }
        recorder.tick();
        assert_eq!(sink.sum("Invocations"), 1_500.0);
        assert_eq!(sink.count("Duration"), MAX_DURATION_SAMPLES);
        let batches = sink.batches.lock().unwrap();
        assert_eq!(batches.len(), 2);
        assert!(batches.iter().all(|batch| batch.len() <= MAX_BATCH));
        assert_ne!(batches[0][0].correlation_id, batches[1][0].correlation_id);
    }

    #[tokio::test]
    async fn saturated_sink_keeps_batches_and_invalid_batches_are_discarded() {
        for outcome in [EmitOutcome::Full, EmitOutcome::Unavailable] {
            let sink = TestSink::new(2, outcome);
            let registry = registry_with(sink.clone());
            let metrics = LambdaMetrics::new(Arc::downgrade(&registry));
            let recorder = metrics.recorder();
            recorder.record_invocation("000000000000", "us-east-1", "fn", true, Some(5.0));
            assert_eq!(recorder.tick(), 0);
            recorder.record_invocation("000000000000", "us-east-1", "fn", false, Some(6.0));
            assert_eq!(recorder.tick(), 0);
            assert_eq!(recorder.pending_buckets(), 1);
            assert!(recorder.tick() > 0);
            assert_eq!(sink.sum("Invocations"), 2.0);
            assert_eq!(sink.sum("Errors"), 1.0);
            assert_eq!(sink.count("Duration"), 2);
            assert_eq!(recorder.pending_buckets(), 0);
        }
        let sink = TestSink::new(1, EmitOutcome::Dropped);
        let registry = registry_with(sink.clone());
        let metrics = LambdaMetrics::new(Arc::downgrade(&registry));
        let recorder = metrics.recorder();
        recorder.record_invocation("000000000000", "us-east-1", "fn", false, None);
        assert_eq!(recorder.tick(), 0);
        assert_eq!(recorder.pending_buckets(), 0);
        assert!(sink.observations().is_empty());
    }

    #[test]
    fn pending_buckets_are_bounded_by_dropping_the_oldest_minute() {
        let mut pending = BTreeMap::new();
        let key = |function: usize, minute: i64| {
            (
                "000000000000".to_owned(),
                "us-east-1".to_owned(),
                format!("fn-{function}"),
                minute * MINUTE_MS,
            )
        };
        for function in 0..MAX_PENDING_BUCKETS {
            merge(&mut pending, key(function, 10), |c| c.invocations += 1);
        }
        merge(&mut pending, key(0, 9), |c| c.invocations += 1);
        assert_eq!(pending.len(), MAX_PENDING_BUCKETS);
        assert!(!pending.contains_key(&key(0, 9)));
        merge(&mut pending, key(0, 11), |c| c.invocations += 1);
        assert_eq!(pending.len(), MAX_PENDING_BUCKETS);
        assert!(pending.contains_key(&key(0, 11)));
        merge(&mut pending, key(1, 10), |c| c.invocations += 1);
        assert_eq!(pending.len(), MAX_PENDING_BUCKETS);
    }

    #[tokio::test]
    async fn task_flushes_each_period_and_exits_when_idle() {
        let sink = TestSink::new(1, EmitOutcome::Full);
        let registry = registry_with(sink.clone());
        let metrics =
            LambdaMetrics::with_period(Arc::downgrade(&registry), Duration::from_millis(20));
        let recorder = metrics.recorder();
        recorder.record_invocation("000000000000", "us-east-1", "fn", false, Some(1.0));
        assert!(recorder.sampler_running());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while recorder.sampler_running() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!recorder.sampler_running());
        assert_eq!(sink.sum("Invocations"), 1.0);
        recorder.record_invocation("000000000000", "us-east-1", "fn", false, Some(1.0));
        assert!(recorder.sampler_running());
    }

    #[tokio::test]
    async fn drop_flushes_pending_buckets() {
        let sink = TestSink::new(0, EmitOutcome::Full);
        let registry = registry_with(sink.clone());
        let metrics = LambdaMetrics::new(Arc::downgrade(&registry));
        metrics
            .recorder()
            .record_invocation("000000000000", "us-east-1", "fn", false, Some(1.0));
        drop(metrics);
        assert_eq!(sink.sum("Invocations"), 1.0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_thousand_concurrent_records_sum_exactly_under_backpressure() {
        const TASKS: usize = 50;
        const PER_TASK: usize = 40;
        let sink = TestSink::new(5, EmitOutcome::Full);
        let registry = registry_with(sink.clone());
        let metrics = LambdaMetrics::new(Arc::downgrade(&registry));
        let recorder = metrics.recorder().clone();
        let ticker = {
            let recorder = recorder.clone();
            tokio::spawn(async move {
                loop {
                    recorder.tick();
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
        };
        let workers: Vec<_> = (0..TASKS)
            .map(|task| {
                let recorder = recorder.clone();
                tokio::spawn(async move {
                    for call in 0..PER_TASK {
                        recorder.record_invocation(
                            "000000000000",
                            "us-east-1",
                            "fn",
                            (task + call) % 4 == 0,
                            Some(1.0),
                        );
                        tokio::task::yield_now().await;
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.await.unwrap();
        }
        ticker.abort();
        let _ = ticker.await;
        for _ in 0..10 {
            if recorder.pending_buckets() == 0 {
                break;
            }
            recorder.tick();
        }
        assert_eq!(recorder.pending_buckets(), 0);
        assert_eq!(sink.sum("Invocations"), (TASKS * PER_TASK) as f64);
        assert_eq!(sink.sum("Errors"), (TASKS * PER_TASK / 4) as f64);
        assert_eq!(*sink.refusals.lock().unwrap(), 0);
    }
}
