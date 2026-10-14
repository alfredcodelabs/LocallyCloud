//! Best-effort vended execution metrics and an exact local active-execution gauge.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use locallycloud_core::integration::metrics::{MetricObservation, MetricOrigin, MetricUnit};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};

use crate::store::Status;

pub(crate) struct ExecutionMetrics {
    registry: Weak<ServiceRegistry>,
    active: Arc<Mutex<BTreeMap<String, u32>>>,
    account: String,
    region: String,
    machine: String,
    started: Instant,
    finished: bool,
}

impl ExecutionMetrics {
    pub(crate) fn start(interpreter: &crate::interpreter::Interpreter) -> Self {
        let metrics = Self {
            registry: interpreter.registry.clone(),
            active: interpreter.store.active_metrics.clone(),
            account: interpreter.account.clone(),
            region: interpreter.region.clone(),
            machine: format!(
                "arn:aws:states:{}:{}:stateMachine:{}",
                interpreter.region, interpreter.account, interpreter.sm_name
            ),
            started: Instant::now(),
            finished: false,
        };
        if let Ok(mut active) = metrics.active.lock() {
            let count = active.entry(metrics.machine.clone()).or_default();
            *count = count.saturating_add(1);
            metrics.emit(
                "LocallyCloud/States",
                "ActiveExecutions",
                f64::from(*count),
                MetricUnit::Count,
            );
        }
        metrics.emit("AWS/States", "ExecutionsStarted", 1.0, MetricUnit::Count);
        ensure_sampler(interpreter);
        metrics
    }

    fn emit(&self, namespace: &str, name: &str, value: f64, unit: MetricUnit) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let Some(sink) = registry.metric_sink(&ServiceName::new("monitoring")) else {
            return;
        };
        let sample = observation(
            &self.account,
            &self.region,
            &self.machine,
            (namespace, name, value, unit),
        );
        let _ = sink.try_emit(vec![sample]);
    }

    pub(crate) fn finish(mut self, status: Status) {
        self.terminal(status);
        self.finished = true;
    }

    fn terminal(&self, status: Status) {
        let name = match status {
            Status::Succeeded => "ExecutionsSucceeded",
            Status::Failed => "ExecutionsFailed",
            Status::TimedOut => "ExecutionsTimedOut",
            Status::Aborted | Status::Running => "ExecutionsAborted",
        };
        self.emit("AWS/States", name, 1.0, MetricUnit::Count);
        self.emit("AWS/States", "ExecutionsStarted", 0.0, MetricUnit::Count);
        self.emit(
            "AWS/States",
            "ExecutionTime",
            self.started.elapsed().as_secs_f64() * 1000.0,
            MetricUnit::Milliseconds,
        );
    }
}

fn observation(
    account: &str,
    region: &str,
    machine: &str,
    metric: (&str, &str, f64, MetricUnit),
) -> MetricObservation {
    let (namespace, name, value, unit) = metric;
    MetricObservation {
        account_id: account.into(),
        region: region.into(),
        namespace: namespace.into(),
        metric_name: name.into(),
        dimensions: BTreeMap::from([("StateMachineArn".into(), machine.into())]),
        timestamp_ms: (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64,
        value,
        unit: Some(unit),
        storage_resolution: if namespace == "AWS/States" { 60 } else { 1 },
        origin: MetricOrigin::AwsService,
        correlation_id: uuid::Uuid::new_v4().to_string(),
    }
}

fn ensure_sampler(interpreter: &crate::interpreter::Interpreter) {
    let Some(registry) = interpreter.registry.upgrade() else {
        return;
    };
    if registry
        .metric_sink(&ServiceName::new("monitoring"))
        .is_none()
    {
        return;
    }
    let Ok(mut sampler) = interpreter.store.metric_sampler.lock() else {
        return;
    };
    if sampler.as_ref().is_some_and(|task| !task.is_finished()) {
        return;
    }
    let active = Arc::downgrade(&interpreter.store.active_metrics);
    let registry = interpreter.registry.clone();
    *sampler = Some(tokio::spawn(async move {
        let mut ticks = tokio::time::interval(std::time::Duration::from_secs(1));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            let (Some(active), Some(registry)) = (active.upgrade(), registry.upgrade()) else {
                break;
            };
            let Some(sink) = registry.metric_sink(&ServiceName::new("monitoring")) else {
                continue;
            };
            let Ok(active) = active.lock() else { break };
            // Keep each receiver batch bounded even when many workflows are active.
            let mut batch = Vec::with_capacity(20);
            for (machine, count) in active.iter() {
                let mut fields = machine.split(':');
                let (Some(region), Some(account)) = (fields.nth(3), fields.next()) else {
                    continue;
                };
                batch.push(observation(
                    account,
                    region,
                    machine,
                    (
                        "LocallyCloud/States",
                        "ActiveExecutions",
                        f64::from(*count),
                        MetricUnit::Count,
                    ),
                ));
                if batch.len() == 20 {
                    let _ = sink.try_emit(std::mem::take(&mut batch));
                }
            }
            if !batch.is_empty() {
                let _ = sink.try_emit(batch);
            }
        }
    }));
}

impl Drop for ExecutionMetrics {
    fn drop(&mut self) {
        if !self.finished {
            self.terminal(Status::Aborted);
        }
        if let Ok(mut active) = self.active.lock() {
            if let Some(count) = active.get_mut(&self.machine) {
                *count = count.saturating_sub(1);
                self.emit(
                    "LocallyCloud/States",
                    "ActiveExecutions",
                    f64::from(*count),
                    MetricUnit::Count,
                );
                if *count == 0 {
                    active.remove(&self.machine);
                }
            }
        }
    }
}
