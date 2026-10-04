//! Region/account-scoped store for state machines, immutable versions, and executions.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use serde_json::Value;
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::time::Instant;

pub const MAX_HISTORY_EVENTS: usize = 25_000;
pub const MAX_STATE_MACHINES: usize = 100_000;
pub const MAX_ACTIVITIES: usize = 100_000;
pub const MAX_OPEN_EXECUTIONS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaExceeded;

/// A history event recorded during a STANDARD execution.
#[derive(Debug, Clone)]
pub struct HistoryEvent {
    pub id: u64,
    pub previous_event_id: Option<u64>,
    pub event_type: String,
    pub timestamp: String,
    pub details: Value,
}

/// An immutable published snapshot of a state machine.
#[derive(Debug, Clone)]
pub struct StateMachineVersion {
    pub arn: String,
    pub version: u64,
    pub definition: String,
    pub role_arn: String,
    pub revision_id: String,
    pub description: Option<String>,
    pub creation_date: f64,
}

/// One weighted destination in a state-machine alias.
#[derive(Debug, Clone)]
pub struct AliasRouting {
    pub state_machine_version_arn: String,
    pub version: u64,
    pub weight: u32,
}

/// A named alias routing executions to one or two immutable versions.
#[derive(Debug, Clone)]
pub struct StateMachineAlias {
    pub arn: String,
    pub name: String,
    pub routing_configuration: Vec<AliasRouting>,
    pub description: Option<String>,
    pub creation_date: f64,
    pub update_date: f64,
    pub tags: BTreeMap<String, String>,
}

/// Lifecycle status of a state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateMachineStatus {
    Active,
    Deleting,
}

impl StateMachineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            StateMachineStatus::Active => "ACTIVE",
            StateMachineStatus::Deleting => "DELETING",
        }
    }
}

/// A stored state machine and its published immutable versions.
#[derive(Debug, Clone)]
pub struct StateMachineRecord {
    pub arn: String,
    pub name: String,
    pub definition: String,
    pub role_arn: String,
    pub type_: String, // STANDARD | EXPRESS
    pub status: StateMachineStatus,
    pub creation_date: String,
    pub creation_epoch: f64,
    pub revision_id: String,
    pub logging_configuration: Option<Value>,
    pub tracing_configuration: Option<Value>,
    pub encryption_configuration: Option<Value>,
    pub tags: BTreeMap<String, String>,
    pub versions: BTreeMap<u64, StateMachineVersion>,
    pub aliases: BTreeMap<String, StateMachineAlias>,
}

impl StateMachineRecord {
    /// Snapshot the current mutable definition as the next monotonically increasing version.
    pub fn publish_version(
        &mut self,
        description: Option<String>,
        creation_date: f64,
    ) -> StateMachineVersion {
        let version = self
            .versions
            .last_key_value()
            .map(|(number, _)| number + 1)
            .unwrap_or(1);
        let snapshot = StateMachineVersion {
            arn: format!("{}:{version}", self.arn),
            version,
            definition: self.definition.clone(),
            role_arn: self.role_arn.clone(),
            revision_id: self.revision_id.clone(),
            description,
            creation_date,
        };
        self.versions.insert(version, snapshot.clone());
        snapshot
    }
}

/// Execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Running,
    Succeeded,
    Failed,
    Aborted,
    TimedOut,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Running => "RUNNING",
            Status::Succeeded => "SUCCEEDED",
            Status::Failed => "FAILED",
            Status::Aborted => "ABORTED",
            Status::TimedOut => "TIMED_OUT",
        }
    }
    pub fn is_terminal(self) -> bool {
        !matches!(self, Status::Running)
    }
}

/// A stored execution, including the immutable state-machine snapshot used for the run.
#[derive(Debug, Clone)]
pub struct Execution {
    pub arn: String,
    pub name: String,
    pub state_machine_arn: String,
    pub state_machine_type: String,
    pub definition: String,
    pub role_arn: String,
    pub logging_configuration: Option<Value>,
    pub tracing_configuration: Option<Value>,
    pub encryption_configuration: Option<Value>,
    pub status: Status,
    pub input: Value,
    pub output: Option<Value>,
    pub error: Option<String>,
    pub cause: Option<String>,
    pub start_date: f64,
    pub start_time: String,
    pub stop_date: Option<f64>,
    pub current_state: Option<String>,
    pub current_input: Option<Value>,
    /// Workflow variables assigned by completed states, retained for redrive.
    pub variables: BTreeMap<String, Value>,
    pub redrive_count: u32,
    pub redrive_date: Option<f64>,
    pub history: Vec<HistoryEvent>,
}

impl Execution {
    pub fn record(&mut self, event_type: &str, details: Value) -> Option<u64> {
        let previous_event_id = self.history.last().map(|event| event.id);
        self.record_after(event_type, details, previous_event_id)
    }

    pub fn record_after(
        &mut self,
        event_type: &str,
        details: Value,
        previous_event_id: Option<u64>,
    ) -> Option<u64> {
        if self.history.len() >= MAX_HISTORY_EVENTS {
            return None;
        }
        let id = self.history.len() as u64 + 1;
        self.history.push(HistoryEvent {
            id,
            previous_event_id,
            event_type: event_type.to_string(),
            timestamp: crate::clock::now_iso(),
            details,
        });
        Some(id)
    }
}

#[derive(Debug, Clone)]
pub enum TaskOutcome {
    Success(Value),
    Failure { error: String, cause: String },
}

/// A callback or activity task waiting for SendTask* completion.
pub struct PendingTask {
    pub execution_arn: String,
    pub heartbeat_seconds: Option<u64>,
    pub last_heartbeat: Mutex<Instant>,
    pub outcome: Mutex<Option<TaskOutcome>>,
    pub notify: Notify,
}

impl PendingTask {
    pub fn new(execution_arn: String, heartbeat_seconds: Option<u64>) -> Self {
        Self {
            execution_arn,
            heartbeat_seconds,
            last_heartbeat: Mutex::new(Instant::now()),
            outcome: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    pub async fn heartbeat_expired(&self) -> bool {
        match self.heartbeat_seconds {
            Some(seconds) => {
                self.last_heartbeat.lock().await.elapsed() >= Duration::from_secs(seconds)
            }
            None => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActivityTask {
    pub token: String,
    pub input: Value,
}

pub struct ActivityRecord {
    pub arn: String,
    pub name: String,
    pub creation_date: f64,
    pub tags: RwLock<BTreeMap<String, String>>,
    pub queue: Mutex<VecDeque<ActivityTask>>,
    pub notify: Notify,
}

impl ActivityRecord {
    pub fn new(
        arn: String,
        name: String,
        creation_date: f64,
        tags: BTreeMap<String, String>,
    ) -> Self {
        Self {
            arn,
            name,
            creation_date,
            tags: RwLock::new(tags),
            queue: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }
}

type Key = (String, String, String);

pub enum InsertExecutionResult {
    Created(Arc<RwLock<Execution>>),
    Existing(Arc<RwLock<Execution>>),
    LimitExceeded,
}

#[derive(Clone, Default)]
pub struct SfnStore {
    machines: Arc<DashMap<Key, Arc<RwLock<StateMachineRecord>>>>,
    executions: Arc<DashMap<String, Arc<RwLock<Execution>>>>,
    activities: Arc<DashMap<Key, Arc<ActivityRecord>>>,
    pending_tasks: Arc<DashMap<String, Arc<PendingTask>>>,
    quota_lock: Arc<Mutex<()>>,
}

fn key(account: &str, region: &str, name: &str) -> Key {
    (account.to_string(), region.to_string(), name.to_string())
}

impl SfnStore {
    pub(crate) fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        Ok(self
            .machines
            .iter()
            .map(|e| e.key().clone())
            .chain(self.activities.iter().map(|e| e.key().clone()))
            .filter(|k| k.0 == account)
            .map(|k| k.1)
            .collect())
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_machine(&self, account: &str, region: &str, rec: StateMachineRecord) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.machines.entry(key(account, region, &rec.name)) {
            Entry::Occupied(_) => false,
            Entry::Vacant(slot) => {
                slot.insert(Arc::new(RwLock::new(rec)));
                true
            }
        }
    }

    /// Atomically enforce the regional/account state-machine quota and create the record.
    pub async fn create_machine_bounded(
        &self,
        account: &str,
        region: &str,
        rec: StateMachineRecord,
    ) -> Result<bool, QuotaExceeded> {
        let _guard = self.quota_lock.lock().await;
        if self.machines.contains_key(&key(account, region, &rec.name)) {
            return Ok(false);
        }
        let count = self
            .machines
            .iter()
            .filter(|entry| entry.key().0 == account && entry.key().1 == region)
            .count();
        if count >= MAX_STATE_MACHINES {
            return Err(QuotaExceeded);
        }
        Ok(self.create_machine(account, region, rec))
    }

    pub fn get_machine(
        &self,
        account: &str,
        region: &str,
        name: &str,
    ) -> Option<Arc<RwLock<StateMachineRecord>>> {
        self.machines
            .get(&key(account, region, name))
            .map(|e| e.clone())
    }

    pub fn remove_machine(
        &self,
        account: &str,
        region: &str,
        name: &str,
    ) -> Option<Arc<RwLock<StateMachineRecord>>> {
        self.machines
            .remove(&key(account, region, name))
            .map(|(_, v)| v)
    }

    pub fn list_machines(
        &self,
        account: &str,
        region: &str,
    ) -> Vec<Arc<RwLock<StateMachineRecord>>> {
        let mut out: Vec<_> = self
            .machines
            .iter()
            .filter(|e| e.key().0 == account && e.key().1 == region)
            .map(|e| e.value().clone())
            .collect();
        out.sort_by(|a, b| {
            let an = a.try_read().map(|s| s.name.clone()).unwrap_or_default();
            let bn = b.try_read().map(|s| s.name.clone()).unwrap_or_default();
            an.cmp(&bn)
        });
        out
    }

    pub fn insert_execution(&self, exec: Execution) -> Arc<RwLock<Execution>> {
        let handle = Arc::new(RwLock::new(exec.clone()));
        self.executions.insert(exec.arn.clone(), handle.clone());
        handle
    }

    /// Insert a STANDARD execution without replacing an existing execution with the same ARN.
    pub fn insert_execution_exclusive(&self, exec: Execution) -> InsertExecutionResult {
        use dashmap::mapref::entry::Entry;
        match self.executions.entry(exec.arn.clone()) {
            Entry::Occupied(entry) => InsertExecutionResult::Existing(entry.get().clone()),
            Entry::Vacant(entry) => {
                let handle = Arc::new(RwLock::new(exec));
                entry.insert(handle.clone());
                InsertExecutionResult::Created(handle)
            }
        }
    }

    pub async fn insert_execution_exclusive_bounded(
        &self,
        account: &str,
        region: &str,
        exec: Execution,
    ) -> InsertExecutionResult {
        let _guard = self.quota_lock.lock().await;
        if let Some(existing) = self.get_execution(&exec.arn) {
            return InsertExecutionResult::Existing(existing);
        }
        let prefix = format!("arn:aws:states:{region}:{account}:execution:");
        let open = self
            .executions
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .filter(|entry| {
                entry
                    .value()
                    .try_read()
                    .map(|execution| execution.status == Status::Running)
                    .unwrap_or(true)
            })
            .count();
        if open >= MAX_OPEN_EXECUTIONS {
            return InsertExecutionResult::LimitExceeded;
        }
        self.insert_execution_exclusive(exec)
    }

    pub fn get_execution(&self, arn: &str) -> Option<Arc<RwLock<Execution>>> {
        self.executions.get(arn).map(|e| e.clone())
    }

    pub fn list_executions(&self, state_machine_arn: &str) -> Vec<Arc<RwLock<Execution>>> {
        self.executions
            .iter()
            .filter(|e| {
                e.value()
                    .try_read()
                    .map(|x| x.state_machine_arn == state_machine_arn)
                    .unwrap_or(false)
            })
            .map(|e| e.value().clone())
            .collect()
    }

    pub fn create_activity(
        &self,
        account: &str,
        region: &str,
        activity: ActivityRecord,
    ) -> Arc<ActivityRecord> {
        use dashmap::mapref::entry::Entry;
        match self.activities.entry(key(account, region, &activity.name)) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let activity = Arc::new(activity);
                entry.insert(activity.clone());
                activity
            }
        }
    }

    pub async fn create_activity_bounded(
        &self,
        account: &str,
        region: &str,
        activity: ActivityRecord,
    ) -> Result<Arc<ActivityRecord>, QuotaExceeded> {
        let _guard = self.quota_lock.lock().await;
        if let Some(existing) = self.get_activity(account, region, &activity.name) {
            return Ok(existing);
        }
        let count = self
            .activities
            .iter()
            .filter(|entry| entry.key().0 == account && entry.key().1 == region)
            .count();
        if count >= MAX_ACTIVITIES {
            return Err(QuotaExceeded);
        }
        Ok(self.create_activity(account, region, activity))
    }

    pub fn get_activity(
        &self,
        account: &str,
        region: &str,
        name: &str,
    ) -> Option<Arc<ActivityRecord>> {
        self.activities
            .get(&key(account, region, name))
            .map(|entry| entry.clone())
    }

    pub fn remove_activity(
        &self,
        account: &str,
        region: &str,
        name: &str,
    ) -> Option<Arc<ActivityRecord>> {
        self.activities
            .remove(&key(account, region, name))
            .map(|(_, activity)| activity)
    }

    pub fn list_activities(&self, account: &str, region: &str) -> Vec<Arc<ActivityRecord>> {
        let mut activities: Vec<_> = self
            .activities
            .iter()
            .filter(|entry| entry.key().0 == account && entry.key().1 == region)
            .map(|entry| entry.value().clone())
            .collect();
        activities.sort_by(|left, right| left.name.cmp(&right.name));
        activities
    }

    pub fn insert_pending_task(&self, token: String, task: PendingTask) -> Arc<PendingTask> {
        let task = Arc::new(task);
        self.pending_tasks.insert(token, task.clone());
        task
    }

    pub fn get_pending_task(&self, token: &str) -> Option<Arc<PendingTask>> {
        self.pending_tasks.get(token).map(|entry| entry.clone())
    }

    pub fn remove_pending_task(&self, token: &str) -> Option<Arc<PendingTask>> {
        self.pending_tasks.remove(token).map(|(_, task)| task)
    }

    pub async fn remove_queued_activity_task(&self, token: &str) {
        let activities: Vec<_> = self
            .activities
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        for activity in activities {
            activity
                .queue
                .lock()
                .await
                .retain(|task| task.token != token);
        }
    }

    pub async fn cancel_pending_tasks(&self, execution_arn: &str) {
        let tokens: HashSet<_> = self
            .pending_tasks
            .iter()
            .filter(|entry| entry.value().execution_arn == execution_arn)
            .map(|entry| entry.key().clone())
            .collect();
        if tokens.is_empty() {
            return;
        }
        let activities: Vec<_> = self
            .activities
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        for activity in activities {
            activity
                .queue
                .lock()
                .await
                .retain(|task| !tokens.contains(&task.token));
        }
        for token in tokens {
            if let Some(task) = self.remove_pending_task(&token) {
                *task.outcome.lock().await = Some(TaskOutcome::Failure {
                    error: "States.TaskFailed".into(),
                    cause: "execution was stopped".into(),
                });
                task.notify.notify_waiters();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_strings() {
        assert_eq!(Status::Running.as_str(), "RUNNING");
        assert!(Status::Succeeded.is_terminal());
        assert!(!Status::Running.is_terminal());
    }

    #[test]
    fn create_is_exclusive() {
        let store = SfnStore::new();
        let rec = StateMachineRecord {
            arn: "arn".into(),
            name: "m".into(),
            definition: "{}".into(),
            role_arn: "role".into(),
            type_: "STANDARD".into(),
            status: StateMachineStatus::Active,
            creation_date: "now".into(),
            creation_epoch: 0.0,
            revision_id: "revision".into(),
            logging_configuration: None,
            tracing_configuration: None,
            encryption_configuration: None,
            tags: BTreeMap::new(),
            versions: BTreeMap::new(),
            aliases: BTreeMap::new(),
        };
        assert!(store.create_machine("0", "us-east-1", rec.clone()));
        assert!(!store.create_machine("0", "us-east-1", rec));
    }
}
