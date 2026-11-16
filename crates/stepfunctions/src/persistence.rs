//! SQLite journals are injected; execution writes commit while their lock is held.
use super::*;
use locallycloud_state::{StateCipher, StateDb};
use rusqlite::{params, OptionalExtension};
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
    connection: std::sync::Mutex<rusqlite::Connection>,
    cipher: StateCipher,
}
impl Persistence {
    pub(crate) fn new(state: Arc<StateDb>, cipher: StateCipher) -> Result<Self, String> {
        let connection = state.connection().map_err(|e| e.to_string())?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS sfn_scopes(account TEXT NOT NULL,region TEXT NOT NULL,version INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(account,region));
             CREATE TABLE IF NOT EXISTS sfn_executions(arn TEXT PRIMARY KEY,version INTEGER NOT NULL,payload BLOB NOT NULL,history_count INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS sfn_execution_events(execution_arn TEXT NOT NULL,event_id INTEGER NOT NULL,version INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(execution_arn,event_id),FOREIGN KEY(execution_arn) REFERENCES sfn_executions(arn) ON DELETE CASCADE);"
        ).map_err(|e|e.to_string())?;
        let has_history_count = connection
            .prepare("PRAGMA table_info(sfn_executions)")
            .map_err(|e| e.to_string())?
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
            .iter()
            .any(|name| name == "history_count");
        if !has_history_count {
            connection.execute_batch("ALTER TABLE sfn_executions ADD COLUMN history_count INTEGER NOT NULL DEFAULT 0;").map_err(|e| e.to_string())?;
        }
        connection
            .pragma_update(None, "foreign_keys", true)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            state,
            connection: std::sync::Mutex::new(connection),
            cipher,
        })
    }
    fn connection(&self) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, String> {
        self.connection
            .lock()
            .map_err(|_| "Step Functions persistence connection is poisoned".into())
    }

    fn seal<T: Serialize>(&self, context: &[&str], value: &T) -> Result<Vec<u8>, String> {
        let clear = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        self.cipher.seal(context, &clear).map_err(|e| e.to_string())
    }
    /// Live updates use ExecutionWriteGuard; direct calls are for initial insert or validated recovery.
    pub(crate) fn save_execution(&self, execution: &Execution) -> Result<(), String> {
        if execution.arn.is_empty() || execution.state_machine_type != "STANDARD" {
            return Err("invalid persisted STANDARD execution identity".into());
        }
        if execution.history.len() > MAX_HISTORY_EVENTS {
            return Err("persisted execution exceeds the history limit".into());
        }
        let count = execution.history.len();
        let count_context = count.to_string();
        let payload = self.seal(
            &[
                "stepfunctions",
                "execution",
                "2",
                &execution.arn,
                &count_context,
            ],
            execution,
        )?;
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let stored: Option<(i64, i64)> = tx
            .query_row(
                "SELECT version,history_count FROM sfn_executions WHERE arn=?1",
                [&execution.arn],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let committed = match stored {
            None | Some((1, _)) => {
                let existing: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sfn_execution_events WHERE execution_arn=?1)",
                        [&execution.arn],
                        |row| row.get(0),
                    )
                    .map_err(|e| e.to_string())?;
                if existing {
                    return Err("unexpected events before execution journal migration".into());
                }
                0
            }
            Some((2, committed)) => usize::try_from(committed)
                .ok()
                .filter(|n| *n <= count)
                .ok_or_else(|| "execution history is not append-only".to_string())?,
            Some(_) => return Err("unsupported Step Functions execution schema".into()),
        };
        tx.execute(
            "INSERT INTO sfn_executions(arn,version,payload,history_count) VALUES(?1,2,?2,?3) ON CONFLICT(arn) DO UPDATE SET version=excluded.version,payload=excluded.payload,history_count=excluded.history_count",
            params![execution.arn,payload,count as i64],
        ).map_err(|e|e.to_string())?;
        if committed < count {
            let mut insert = tx.prepare("INSERT INTO sfn_execution_events(execution_arn,event_id,version,payload) VALUES(?1,?2,1,?3)").map_err(|e|e.to_string())?;
            for (offset, event) in execution.history.iter().enumerate().skip(committed) {
                validate_event(event, offset + 1)?;
                let id = event.id.to_string();
                let payload = self.seal(
                    &["stepfunctions", "execution-event", "1", &execution.arn, &id],
                    event.as_ref(),
                )?;
                insert
                    .execute(params![execution.arn, event.id as i64, payload])
                    .map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())
    }

    fn restore_history(
        &self,
        connection: &rusqlite::Connection,
        execution: &mut Execution,
        count: i64,
    ) -> Result<(), String> {
        let count = usize::try_from(count)
            .ok()
            .filter(|count| *count <= MAX_HISTORY_EVENTS)
            .ok_or_else(|| "invalid persisted execution history count".to_string())?;
        if !execution.history.is_empty() {
            return Err("version 2 execution metadata contains an embedded history".into());
        }
        let mut statement = connection.prepare("SELECT event_id,version,payload FROM sfn_execution_events WHERE execution_arn=?1 ORDER BY event_id").map_err(|e|e.to_string())?;
        let rows = statement
            .query_map([&execution.arn], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        execution.history.reserve(count);
        for row in rows {
            let (id, version, payload) = row.map_err(|e| e.to_string())?;
            if version != 1
                || id <= 0
                || id as usize != execution.history.len() + 1
                || execution.history.len() >= count
            {
                return Err("invalid persisted execution event sequence".into());
            }
            let id_context = id.to_string();
            let clear = self
                .cipher
                .open(
                    &[
                        "stepfunctions",
                        "execution-event",
                        "1",
                        &execution.arn,
                        &id_context,
                    ],
                    &payload,
                )
                .map_err(|e| e.to_string())?;
            let event: HistoryEvent = serde_json::from_slice(&clear).map_err(|e| e.to_string())?;
            validate_event(&event, execution.history.len() + 1)?;
            execution.history.push(Arc::new(event));
        }
        if execution.history.len() != count {
            return Err("persisted execution history is incomplete".into());
        }
        Ok(())
    }

    fn save_scope(
        &self,
        account: &str,
        region: &str,
        snapshot: &ScopeSnapshot,
    ) -> Result<(), String> {
        let payload = self.seal(&["stepfunctions", "scope", account, region], snapshot)?;
        self.connection()?.execute(
            "INSERT INTO sfn_scopes(account,region,version,payload) VALUES(?1,?2,1,?3) ON CONFLICT(account,region) DO UPDATE SET version=excluded.version,payload=excluded.payload",
            params![account,region,payload],
        ).map_err(|e|e.to_string())?;
        Ok(())
    }
    pub(crate) fn restore(&self, store: &SfnStore) -> Result<(), String> {
        // Restore may save interrupted executions; its read cursor must not hold the writer mutex.
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
            .prepare("SELECT arn,version,payload,history_count FROM sfn_executions")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (arn, version, payload, history_count) = row.map_err(|e| e.to_string())?;
            let count_context = history_count.to_string();
            let context = match version {
                1 => vec!["stepfunctions", "execution", arn.as_str()],
                2 => vec![
                    "stepfunctions",
                    "execution",
                    "2",
                    arn.as_str(),
                    count_context.as_str(),
                ],
                _ => return Err("unsupported Step Functions execution schema".into()),
            };
            let clear = self
                .cipher
                .open(&context, &payload)
                .map_err(|e| e.to_string())?;
            let mut execution: Execution =
                serde_json::from_slice(&clear).map_err(|e| e.to_string())?;
            drop(clear);
            drop(payload);
            if version == 2 {
                self.restore_history(&connection, &mut execution, history_count)?;
            } else {
                if execution.history.len() > MAX_HISTORY_EVENTS {
                    return Err("legacy execution exceeds the history limit".into());
                }
                for (offset, event) in execution.history.iter().enumerate() {
                    validate_event(event, offset + 1)?;
                }
            }
            if execution.arn != arn || execution.state_machine_type != "STANDARD" {
                return Err("invalid persisted STANDARD execution identity".into());
            }
            let interrupted = execution.status == Status::Running;
            if interrupted {
                execution.status = Status::Aborted;
                execution.error = Some("LocallyCloud.ExecutionInterrupted".into());
                execution.cause=Some("The locallycloud process stopped; external task effects are not replayed automatically".into());
                execution.stop_date = Some(crate::clock::now_epoch());
                let details = serde_json::json!({"error":execution.error,"cause":execution.cause});
                execution.record("ExecutionAborted", details);
            }
            if version == 1 || interrupted {
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

fn validate_event(event: &HistoryEvent, expected_id: usize) -> Result<(), String> {
    if event.id != expected_id as u64
        || event
            .previous_event_id
            .is_some_and(|previous| previous >= event.id)
    {
        return Err("invalid persisted execution event identity".into());
    }
    Ok(())
}

impl SfnStore {
    #[cfg(test)]
    pub(crate) fn with_state(state: Arc<StateDb>, cipher: StateCipher) -> Result<Self, String> {
        Self::with_state_and_config(state, cipher, crate::StepFunctionsConfig::default())
    }

    pub(crate) fn with_state_and_config(
        state: Arc<StateDb>,
        cipher: StateCipher,
        config: crate::StepFunctionsConfig,
    ) -> Result<Self, String> {
        config.validate()?;
        let persistence = Arc::new(Persistence::new(state, cipher)?);
        let store = Self {
            config,
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
        // The rollback snapshot shares immutable events. Any prefix edit must fail closed,
        // rather than leave runtime history different from the append-only journal.
        let append_only = self.backup.as_ref().is_some_and(|backup| {
            self.guard.history.len() >= backup.history.len()
                && self
                    .guard
                    .history
                    .iter()
                    .zip(&backup.history)
                    .all(|(current, previous)| Arc::ptr_eq(current, previous))
                && self.guard.arn == backup.arn
        });
        // Keep the lock until commit/rollback so readers never observe provisional status.
        if self.failed.load(Ordering::Acquire)
            || !append_only
            || blocking_commit(|| persistence.save_execution(&self.guard)).is_err()
        {
            if let Some(backup) = self.backup.take() {
                *self.guard = backup;
            }
            self.failed.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(account: &str, value: &str) -> ScopeSnapshot {
        ScopeSnapshot {
            machines: Vec::new(),
            activities: vec![ActivitySnapshot {
                arn: format!("arn:aws:states:us-east-1:{account}:activity:work"),
                name: "work".into(),
                creation_date: 1.0,
                tags: BTreeMap::from([("private".into(), value.into())]),
            }],
        }
    }

    #[test]
    #[ignore = "manual history clone/commit measurement; run with --ignored --nocapture"]
    fn execution_history_cost() {
        use std::hint::black_box;
        use std::time::Instant;
        let root = std::env::temp_dir().join(format!("sfn-history-cost-{}", uuid::Uuid::new_v4()));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let persistence =
            Arc::new(Persistence::new(state.clone(), StateCipher::with_key(&[7; 32])).unwrap());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mut execution: Execution = serde_json::from_value(serde_json::json!({
            "arn":"arn:aws:states:us-east-1:000000000000:execution:bench:run",
            "name":"run", "state_machine_arn":"arn:aws:states:us-east-1:000000000000:stateMachine:bench",
            "state_machine_type":"STANDARD", "definition":"{}", "role_arn":"role",
            "status":"Succeeded", "input":{}, "start_date":1.0, "start_time":"time",
            "variables":{}, "redrive_count":0, "history":[]
        })).unwrap();
        for count in [0, 1_000, MAX_HISTORY_EVENTS - 1] {
            while execution.history.len() < count {
                execution.record(
                    "PassStateExited",
                    serde_json::json!({"output":"x".repeat(256)}),
                );
            }
            // Initial history population is outside the append/metadata hot-path timing.
            persistence.save_execution(&execution).unwrap();
            let start = Instant::now();
            for _ in 0..20 {
                black_box(
                    execution
                        .history
                        .iter()
                        .map(|event| (**event).clone())
                        .collect::<Vec<_>>(),
                );
            }
            let deep_clone_us = start.elapsed().as_micros() / 20;
            let start = Instant::now();
            for _ in 0..20 {
                black_box(execution.clone());
            }
            let clone_us = start.elapsed().as_micros() / 20;
            let start = Instant::now();
            for _ in 0..5 {
                persistence.save_execution(&execution).unwrap();
            }
            let commit_us = start.elapsed().as_micros() / 5;
            let cell = ExecutionCell::new(
                execution.clone(),
                Some(persistence.clone()),
                Arc::new(AtomicBool::new(false)),
            );
            let start = Instant::now();
            runtime.block_on(async {
                let mut guard = cell.write().await;
                guard.record(
                    "PassStateExited",
                    serde_json::json!({"output":"x".repeat(256)}),
                );
            });
            let append_guard_commit_us = start.elapsed().as_micros();
            execution = runtime.block_on(async { cell.read().await.clone() });
            let start = Instant::now();
            let restored =
                SfnStore::with_state(state.clone(), StateCipher::with_key(&[7; 32])).unwrap();
            let restore_us = start.elapsed().as_micros();
            let restored_history = restored
                .executions
                .get(&execution.arn)
                .unwrap()
                .try_read()
                .unwrap()
                .history
                .len();
            assert_eq!(restored_history, execution.history.len());
            eprintln!("history={count} deep_history_clone_us={deep_clone_us} execution_clone_us={clone_us} metadata_commit_us={commit_us} append_guard_commit_us={append_guard_commit_us} restored_history={restored_history} restore_us={restore_us}");
        }
        drop(persistence);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reused_writer_recovers_from_sql_failure_and_preserves_encrypted_scopes() {
        let root = std::env::temp_dir().join(format!("sfn-writer-{}", uuid::Uuid::new_v4()));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let persistence =
            Arc::new(Persistence::new(state.clone(), StateCipher::with_key(&[7; 32])).unwrap());
        let account = "000000000000";
        persistence
            .save_scope(account, "us-east-1", &snapshot(account, "original"))
            .unwrap();
        let connection = state.connection().unwrap();
        connection.execute_batch("CREATE TRIGGER reject_scope BEFORE UPDATE ON sfn_scopes BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;").unwrap();
        assert!(persistence
            .save_scope(account, "us-east-1", &snapshot(account, "changed"))
            .is_err());
        {
            let writer = persistence.connection().unwrap();
            assert!(writer.is_autocommit());
            assert_eq!(
                writer
                    .pragma_query_value(None, "synchronous", |row| row.get::<_, i64>(0))
                    .unwrap(),
                2
            );
            assert_eq!(
                writer
                    .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
                    .unwrap(),
                "wal"
            );
        }
        let payload: Vec<u8> = connection
            .query_row(
                "SELECT payload FROM sfn_scopes WHERE account=?1",
                [account],
                |row| row.get(0),
            )
            .unwrap();
        let clear = persistence
            .cipher
            .open(&["stepfunctions", "scope", account, "us-east-1"], &payload)
            .unwrap();
        let restored: ScopeSnapshot = serde_json::from_slice(&clear).unwrap();
        assert_eq!(restored.activities[0].tags["private"], "original");
        assert!(persistence
            .cipher
            .open(
                &["stepfunctions", "scope", "111111111111", "us-east-1"],
                &payload
            )
            .is_err());
        connection
            .execute_batch("DROP TRIGGER reject_scope")
            .unwrap();
        persistence
            .save_scope(
                account,
                "us-east-1",
                &snapshot(account, "sensitive_scope_snapshot"),
            )
            .unwrap();
        let mut writers = Vec::new();
        for index in 1..=4 {
            let persistence = persistence.clone();
            writers.push(tokio::task::spawn_blocking(move || {
                let account = format!("{index:012}");
                persistence.save_scope(&account, "us-east-1", &snapshot(&account, &account))
            }));
        }
        for writer in writers {
            writer.await.unwrap().unwrap();
        }
        let payloads: Vec<Vec<u8>> = connection
            .prepare("SELECT payload FROM sfn_scopes")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(payloads.iter().all(|payload| !payload
            .windows(b"sensitive_scope_snapshot".len())
            .any(|part| part == b"sensitive_scope_snapshot")));
        drop(persistence);
        assert!(SfnStore::with_state(state.clone(), StateCipher::with_key(&[8; 32])).is_err());
        let reopened = SfnStore::with_state(state, StateCipher::with_key(&[7; 32])).unwrap();
        for index in 0..=4 {
            let account = format!("{index:012}");
            let activity = reopened
                .get_activity(&account, "us-east-1", "work")
                .unwrap();
            let expected = if index == 0 {
                "sensitive_scope_snapshot"
            } else {
                &account
            };
            assert_eq!(activity.tags.read().await["private"], expected);
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod journal_tests;
