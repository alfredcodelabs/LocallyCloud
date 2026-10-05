//! SQLite journals are injected; execution writes commit while their lock is held.
use super::*;
use locallycloud_state::{StateCipher, StateDb};
use rusqlite::params;
use std::ops::{Deref, DerefMut};

#[derive(Serialize, Deserialize)]
struct ScopeSnapshot {
    machines: Vec<StateMachineRecord>,
    activities: Vec<ActivitySnapshot>,
}
#[derive(Serialize, Deserialize)]
struct ActivitySnapshot {
    arn: String,
    name: String,
    creation_date: f64,
    tags: BTreeMap<String, String>,
}

pub(crate) struct Persistence {
    state: Arc<StateDb>,
    cipher: StateCipher,
}
impl Persistence {
    pub(crate) fn new(state: Arc<StateDb>, cipher: StateCipher) -> Result<Self, String> {
        state.connection().map_err(|e|e.to_string())?.execute_batch(
            "CREATE TABLE IF NOT EXISTS sfn_scopes(account TEXT NOT NULL,region TEXT NOT NULL,version INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(account,region));
             CREATE TABLE IF NOT EXISTS sfn_executions(arn TEXT PRIMARY KEY,version INTEGER NOT NULL,payload BLOB NOT NULL);"
        ).map_err(|e|e.to_string())?;
        Ok(Self { state, cipher })
    }
    fn seal<T: Serialize>(&self, context: &[&str], value: &T) -> Result<Vec<u8>, String> {
        let clear = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        self.cipher.seal(context, &clear).map_err(|e| e.to_string())
    }
    pub(crate) fn save_execution(&self, execution: &Execution) -> Result<(), String> {
        let payload = self.seal(&["stepfunctions", "execution", &execution.arn], execution)?;
        self.state.connection().map_err(|e|e.to_string())?.execute(
            "INSERT INTO sfn_executions(arn,version,payload) VALUES(?1,1,?2) ON CONFLICT(arn) DO UPDATE SET version=excluded.version,payload=excluded.payload",
            params![execution.arn,payload],
        ).map_err(|e|e.to_string())?;
        Ok(())
    }
    fn save_scope(
        &self,
        account: &str,
        region: &str,
        snapshot: &ScopeSnapshot,
    ) -> Result<(), String> {
        let payload = self.seal(&["stepfunctions", "scope", account, region], snapshot)?;
        self.state.connection().map_err(|e|e.to_string())?.execute(
            "INSERT INTO sfn_scopes(account,region,version,payload) VALUES(?1,?2,1,?3) ON CONFLICT(account,region) DO UPDATE SET version=excluded.version,payload=excluded.payload",
            params![account,region,payload],
        ).map_err(|e|e.to_string())?;
        Ok(())
    }
    pub(crate) fn restore(&self, store: &SfnStore) -> Result<(), String> {
        let connection = self.state.connection().map_err(|e| e.to_string())?;
        let mut statement = connection
            .prepare("SELECT account,region,version,payload FROM sfn_scopes")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (account, region, version, payload) = row.map_err(|e| e.to_string())?;
            if version != 1 {
                return Err("unsupported Step Functions scope schema".into());
            }
            let clear = self
                .cipher
                .open(&["stepfunctions", "scope", &account, &region], &payload)
                .map_err(|e| e.to_string())?;
            let snapshot: ScopeSnapshot =
                serde_json::from_slice(&clear).map_err(|e| e.to_string())?;
            for machine in snapshot.machines {
                // A committed asynchronous delete is completed after recovering interrupted workers.
                if machine.status != StateMachineStatus::Deleting {
                    store.create_machine(&account, &region, machine);
                }
            }
            for activity in snapshot.activities {
                store.create_activity(
                    &account,
                    &region,
                    ActivityRecord::new(
                        activity.arn,
                        activity.name,
                        activity.creation_date,
                        activity.tags,
                    ),
                );
            }
        }
        drop(statement);
        let mut statement = connection
            .prepare("SELECT arn,version,payload FROM sfn_executions")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (arn, version, payload) = row.map_err(|e| e.to_string())?;
            if version != 1 {
                return Err("unsupported Step Functions execution schema".into());
            }
            let clear = self
                .cipher
                .open(&["stepfunctions", "execution", &arn], &payload)
                .map_err(|e| e.to_string())?;
            let mut execution: Execution =
                serde_json::from_slice(&clear).map_err(|e| e.to_string())?;
            if execution.arn != arn || execution.state_machine_type != "STANDARD" {
                return Err("invalid persisted STANDARD execution identity".into());
            }
            if execution.status == Status::Running {
                execution.status = Status::Aborted;
                execution.error = Some("LocallyCloud.ExecutionInterrupted".into());
                execution.cause=Some("The locallycloud process stopped; external task effects are not replayed automatically".into());
                execution.stop_date = Some(crate::clock::now_epoch());
                let details = serde_json::json!({"error":execution.error,"cause":execution.cause});
                execution.record("ExecutionAborted", details);
                self.save_execution(&execution)?;
            }
            let cell = Arc::new(ExecutionCell::new(
                execution,
                store.persistence.clone(),
                store.persistence_failed.clone(),
            ));
            store.executions.insert(arn, cell);
        }
        Ok(())
    }
}

impl SfnStore {
    pub(crate) fn with_state(state: Arc<StateDb>, cipher: StateCipher) -> Result<Self, String> {
        let persistence = Arc::new(Persistence::new(state, cipher)?);
        let store = Self {
            persistence: Some(persistence.clone()),
            ..Self::default()
        };
        persistence.restore(&store)?;
        Ok(store)
    }
    pub(crate) fn healthy(&self) -> bool {
        !self.persistence_failed.load(Ordering::Acquire)
    }
    pub(crate) async fn persist_scope(&self, account: &str, region: &str) -> Result<(), String> {
        let Some(persistence) = &self.persistence else {
            return Ok(());
        };
        let mut snapshot = ScopeSnapshot {
            machines: Vec::new(),
            activities: Vec::new(),
        };
        for machine in self.list_machines(account, region) {
            snapshot.machines.push(machine.read().await.clone());
        }
        for activity in self.list_activities(account, region) {
            snapshot.activities.push(ActivitySnapshot {
                arn: activity.arn.clone(),
                name: activity.name.clone(),
                creation_date: activity.creation_date,
                tags: activity.tags.read().await.clone(),
            });
        }
        let commit = || persistence.save_scope(account, region, &snapshot);
        let result = blocking_commit(commit);
        if result.is_err() {
            self.persistence_failed.store(true, Ordering::Release);
        }
        result
    }
}

pub(super) fn blocking_commit<T>(commit: impl FnOnce() -> T) -> T {
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(commit)
    } else {
        commit()
    }
}

/// Every interpreter history/status mutation uses this one durable lock boundary.
pub struct ExecutionCell {
    value: RwLock<Execution>,
    persistence: Option<Arc<Persistence>>,
    failed: Arc<AtomicBool>,
}
impl ExecutionCell {
    pub(crate) fn new(
        value: Execution,
        persistence: Option<Arc<Persistence>>,
        failed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            value: RwLock::new(value),
            persistence,
            failed,
        }
    }
    pub(crate) fn ephemeral(value: Execution) -> Self {
        Self::new(value, None, Arc::new(AtomicBool::new(false)))
    }
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, Execution> {
        self.value.read().await
    }
    pub fn try_read(
        &self,
    ) -> Result<tokio::sync::RwLockReadGuard<'_, Execution>, tokio::sync::TryLockError> {
        self.value.try_read()
    }
    pub async fn write(&self) -> ExecutionWriteGuard<'_> {
        let guard = self.value.write().await;
        let backup = self.persistence.as_ref().map(|_| guard.clone());
        ExecutionWriteGuard {
            guard,
            backup,
            persistence: self.persistence.as_ref(),
            failed: &self.failed,
        }
    }
}
pub struct ExecutionWriteGuard<'a> {
    guard: tokio::sync::RwLockWriteGuard<'a, Execution>,
    backup: Option<Execution>,
    persistence: Option<&'a Arc<Persistence>>,
    failed: &'a AtomicBool,
}
impl Deref for ExecutionWriteGuard<'_> {
    type Target = Execution;
    fn deref(&self) -> &Execution {
        &self.guard
    }
}
impl DerefMut for ExecutionWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Execution {
        &mut self.guard
    }
}
impl Drop for ExecutionWriteGuard<'_> {
    fn drop(&mut self) {
        let Some(persistence) = self.persistence else {
            return;
        };
        // ponytail: one bounded STANDARD execution snapshot, never the whole service store.
        // Keep the lock until commit/rollback so readers cannot acknowledge provisional status.
        if self.failed.load(Ordering::Acquire)
            || blocking_commit(|| persistence.save_execution(&self.guard)).is_err()
        {
            if let Some(backup) = self.backup.take() {
                *self.guard = backup;
            }
            self.failed.store(true, Ordering::Release);
        }
    }
}
