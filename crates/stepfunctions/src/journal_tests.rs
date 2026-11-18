use super::*;

struct TestState {
    state: Arc<StateDb>,
    root: std::path::PathBuf,
}
impl TestState {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("sfn-journal-{}", uuid::Uuid::new_v4()));
        Self {
            state: Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap()),
            root,
        }
    }
    fn persistence(&self) -> Arc<Persistence> {
        Arc::new(Persistence::new(self.state.clone(), StateCipher::with_key(&[7; 32])).unwrap())
    }
    fn restore(&self) -> Result<SfnStore, String> {
        SfnStore::with_state(self.state.clone(), StateCipher::with_key(&[7; 32]))
    }
}
impl Drop for TestState {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn execution(name: &str, count: usize) -> Execution {
    let mut execution: Execution = serde_json::from_value(serde_json::json!({
        "arn":format!("arn:aws:states:us-east-1:000000000000:execution:journal:{name}"),
        "name":name,"state_machine_arn":"arn:aws:states:us-east-1:000000000000:stateMachine:journal",
        "state_machine_type":"STANDARD","definition":"{}","role_arn":"role",
        "status":"Succeeded","input":{},"start_date":1.0,"start_time":"time",
        "variables":{},"redrive_count":0,"history":[]
    })).unwrap();
    for _ in 0..count {
        execution.record(
            "PassStateExited",
            serde_json::json!({"output":"sensitive_history_journal_payload"}),
        );
    }
    execution
}

fn legacy_payload(cipher: &StateCipher, execution: &Execution) -> Vec<u8> {
    let mut snapshot = serde_json::to_value(execution).unwrap();
    snapshot["history"] = serde_json::to_value(&execution.history).unwrap();
    cipher
        .seal(
            &["stepfunctions", "execution", &execution.arn],
            &serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap()
}

#[test]
fn incremental_journal_preserves_old_rows_and_authenticates_event_identity() {
    let fixture = TestState::new();
    let persistence = fixture.persistence();
    let mut execution = execution("incremental", 2);
    persistence.save_execution(&execution).unwrap();
    let db = fixture.state.connection().unwrap();
    let first: Vec<u8> = db
        .query_row(
            "SELECT payload FROM sfn_execution_events WHERE execution_arn=?1 AND event_id=1",
            [&execution.arn],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!first
        .windows(b"sensitive_history_journal_payload".len())
        .any(|part| part == b"sensitive_history_journal_payload"));
    assert!(persistence
        .cipher
        .open(
            &["stepfunctions", "execution-event", "1", &execution.arn, "2"],
            &first
        )
        .is_err());
    assert!(persistence
        .cipher
        .open(
            &[
                "stepfunctions",
                "execution-event",
                "1",
                "different-arn",
                "1"
            ],
            &first
        )
        .is_err());
    db.execute_batch("CREATE TRIGGER protect_old_events_update BEFORE UPDATE ON sfn_execution_events BEGIN SELECT RAISE(ABORT,'old event update'); END; CREATE TRIGGER protect_old_events_delete BEFORE DELETE ON sfn_execution_events BEGIN SELECT RAISE(ABORT,'old event delete'); END;").unwrap();
    execution.record("ExecutionSucceeded", serde_json::json!({"output":"done"}));
    persistence.save_execution(&execution).unwrap();
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM sfn_execution_events WHERE execution_arn=?1",
            [&execution.arn],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 3);
    let unchanged: Vec<u8> = db
        .query_row(
            "SELECT payload FROM sfn_execution_events WHERE execution_arn=?1 AND event_id=1",
            [&execution.arn],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(first, unchanged);
    let payload: Vec<u8> = db
        .query_row(
            "SELECT payload FROM sfn_executions WHERE arn=?1",
            [&execution.arn],
            |row| row.get(0),
        )
        .unwrap();
    let clear = persistence
        .cipher
        .open(
            &["stepfunctions", "execution", "2", &execution.arn, "3"],
            &payload,
        )
        .unwrap();
    let metadata: Value = serde_json::from_slice(&clear).unwrap();
    assert!(metadata.get("history").is_none());
    assert!(!clear
        .windows(b"sensitive_history_journal_payload".len())
        .any(|part| part == b"sensitive_history_journal_payload"));
    let reopened = fixture.restore().unwrap();
    let restored = reopened.executions.get(&execution.arn).unwrap().clone();
    let restored = restored.try_read().unwrap();
    assert_eq!(
        restored
            .history
            .iter()
            .map(|event| event.id)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(restored.history[2].event_type, "ExecutionSucceeded");
}

#[test]
fn legacy_schema_and_embedded_histories_migrate_once_without_losing_data() {
    let fixture = TestState::new();
    let db = fixture.state.connection().unwrap();
    db.execute_batch("CREATE TABLE sfn_executions(arn TEXT PRIMARY KEY,version INTEGER NOT NULL,payload BLOB NOT NULL)").unwrap();
    let original = execution("legacy", 3);
    let payload = legacy_payload(&StateCipher::with_key(&[7; 32]), &original);
    db.execute(
        "INSERT INTO sfn_executions(arn,version,payload) VALUES(?1,1,?2)",
        params![original.arn, payload],
    )
    .unwrap();
    let store = fixture.restore().unwrap();
    let restored = store.executions.get(&original.arn).unwrap().clone();
    let restored = restored.try_read().unwrap();
    assert_eq!(restored.history.len(), 3);
    assert_eq!(restored.history[0].details, original.history[0].details);
    assert_eq!(
        db.query_row(
            "SELECT version,history_count FROM sfn_executions WHERE arn=?1",
            [&original.arn],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        )
        .unwrap(),
        (2, 3)
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM sfn_execution_events", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        3
    );
    drop(restored);
    drop(store);
    fixture.restore().unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM sfn_execution_events", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        3
    );
}

#[test]
fn legacy_migration_failure_keeps_original_snapshot_and_no_partial_events() {
    let fixture = TestState::new();
    let persistence = fixture.persistence();
    let original = execution("legacy-failure", 3);
    let payload = legacy_payload(&persistence.cipher, &original);
    let db = fixture.state.connection().unwrap();
    db.execute(
        "INSERT INTO sfn_executions(arn,version,payload) VALUES(?1,1,?2)",
        params![original.arn, payload],
    )
    .unwrap();
    db.execute_batch("CREATE TRIGGER reject_event BEFORE INSERT ON sfn_execution_events WHEN NEW.event_id=2 BEGIN SELECT RAISE(ABORT,'injected migration failure'); END;").unwrap();
    assert!(persistence.restore(&SfnStore::default()).is_err());
    assert_eq!(
        db.query_row(
            "SELECT version,payload FROM sfn_executions WHERE arn=?1",
            [&original.arn],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        )
        .unwrap(),
        (1, payload)
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM sfn_execution_events", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
    db.execute_batch("DROP TRIGGER reject_event").unwrap();
    fixture.restore().unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM sfn_execution_events", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        3
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_failure_rolls_back_status_history_and_journal_and_rejects_prefix_edits() {
    let fixture = TestState::new();
    let persistence = fixture.persistence();
    let original = execution("rollback", 1);
    persistence.save_execution(&original).unwrap();
    let failed = Arc::new(AtomicBool::new(false));
    let cell = ExecutionCell::new(original.clone(), Some(persistence.clone()), failed.clone());
    let db = fixture.state.connection().unwrap();
    db.execute_batch("CREATE TRIGGER reject_event BEFORE INSERT ON sfn_execution_events BEGIN SELECT RAISE(ABORT,'injected append failure'); END;").unwrap();
    {
        let mut guard = cell.write().await;
        guard.status = Status::Failed;
        guard.record("ExecutionFailed", serde_json::json!({"error":"failure"}));
    }
    assert!(failed.load(Ordering::Acquire));
    assert_eq!(cell.read().await.status, Status::Succeeded);
    assert_eq!(cell.read().await.history.len(), 1);
    assert_eq!(
        db.query_row(
            "SELECT history_count FROM sfn_executions WHERE arn=?1",
            [&original.arn],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM sfn_execution_events", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        1
    );
    db.execute_batch("DROP TRIGGER reject_event").unwrap();
    let failed = Arc::new(AtomicBool::new(false));
    let cell = ExecutionCell::new(original.clone(), Some(persistence), failed.clone());
    {
        let mut guard = cell.write().await;
        Arc::make_mut(&mut Arc::make_mut(&mut guard.history)[0]).details =
            serde_json::json!({"output":"modified"});
    }
    assert!(failed.load(Ordering::Acquire));
    assert_eq!(
        cell.read().await.history[0].details,
        original.history[0].details
    );
    let reopened = fixture.restore().unwrap();
    assert_eq!(
        reopened
            .executions
            .get(&original.arn)
            .unwrap()
            .try_read()
            .unwrap()
            .history
            .len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_writer_commits_one_atomic_history_and_metadata_update() {
    let fixture = TestState::new();
    let persistence = fixture.persistence();
    let original = execution("cancelled", 1);
    persistence.save_execution(&original).unwrap();
    let cell = Arc::new(ExecutionCell::new(
        original.clone(),
        Some(persistence),
        Arc::new(AtomicBool::new(false)),
    ));
    let writing = cell.clone();
    let (ready, received) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut guard = writing.write().await;
        guard.record("ExecutionSucceeded", serde_json::json!({"output":"done"}));
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    received.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(cell.read().await.history.len(), 2);
    let reopened = fixture.restore().unwrap();
    assert_eq!(
        reopened
            .executions
            .get(&original.arn)
            .unwrap()
            .try_read()
            .unwrap()
            .history
            .len(),
        2
    );
}

#[test]
fn missing_misnumbered_or_rebound_events_fail_restore_closed() {
    for corruption in ["DELETE FROM sfn_execution_events WHERE event_id=2", "UPDATE sfn_execution_events SET event_id=7 WHERE event_id=2", "UPDATE sfn_executions SET history_count=1", "UPDATE sfn_execution_events SET payload=(SELECT payload FROM sfn_execution_events WHERE event_id=1) WHERE event_id=2"] {
        let fixture=TestState::new();
        let persistence=fixture.persistence();
        let original=execution("corrupt",2);
        persistence.save_execution(&original).unwrap();
        fixture.state.connection().unwrap().execute_batch(corruption).unwrap();
        assert!(fixture.restore().is_err(),"{corruption}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_and_redriven_executions_append_monotonic_events_on_restart() {
    let fixture = TestState::new();
    let persistence = fixture.persistence();
    let mut original = execution("interrupted", 1);
    original.status = Status::Running;
    persistence.save_execution(&original).unwrap();
    let reopened = fixture.restore().unwrap();
    let cell = reopened.executions.get(&original.arn).unwrap().clone();
    assert_eq!(cell.read().await.status, Status::Aborted);
    assert_eq!(cell.read().await.history[1].event_type, "ExecutionAborted");
    {
        let mut guard = cell.write().await;
        guard.status = Status::Running;
        guard.redrive_count += 1;
        guard.error = None;
        guard.record("ExecutionRedriven", serde_json::json!({"redriveCount":1}));
    }
    drop(cell);
    drop(reopened);
    let restarted = fixture.restore().unwrap();
    let cell = restarted.executions.get(&original.arn).unwrap().clone();
    let execution = cell.read().await;
    assert_eq!(execution.status, Status::Aborted);
    assert_eq!(execution.redrive_count, 1);
    assert_eq!(
        execution
            .history
            .iter()
            .map(|event| event.id)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert_eq!(execution.history[3].event_type, "ExecutionAborted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_backups_share_history_and_append_detaches_without_changing_prior_snapshots() {
    let fixture = TestState::new();
    let persistence = fixture.persistence();
    let original = execution("shared-backup", 1024);
    persistence.save_execution(&original).unwrap();
    let failed = Arc::new(AtomicBool::new(false));
    let cell = ExecutionCell::new(original.clone(), Some(persistence.clone()), failed.clone());
    {
        let mut guard = cell.write().await;
        assert!(Arc::ptr_eq(
            &guard.history,
            &guard.backup.as_ref().unwrap().history
        ));
        assert!(Arc::ptr_eq(&guard.history, &original.history));
        // Cloning/backing up the execution does not touch each event's reference count.
        assert_eq!(Arc::strong_count(&original.history[0]), 1);
        guard.current_state = Some("updated".into());
    }
    assert!(!failed.load(Ordering::Acquire));
    assert!(Arc::ptr_eq(&cell.read().await.history, &original.history));
    {
        let mut guard = cell.write().await;
        assert_eq!(
            guard.record("ExecutionSucceeded", serde_json::json!({"output":"ok"})),
            Some(1025)
        );
        assert!(!Arc::ptr_eq(&guard.history, &original.history));
        assert!(Arc::ptr_eq(&guard.history[0], &original.history[0]));
    }
    assert!(!failed.load(Ordering::Acquire));
    assert_eq!(original.history.len(), 1024);
    assert_eq!(cell.read().await.history.len(), 1025);
    let restored = fixture.restore().unwrap();
    let restored = restored.executions.get(&original.arn).unwrap().clone();
    let restored = restored.read().await;
    assert_eq!(restored.current_state.as_deref(), Some("updated"));
    assert_eq!(restored.history.len(), 1025);
    assert_eq!(restored.history[1024].event_type, "ExecutionSucceeded");

    // Failed metadata writes roll back without replacing/copying the committed history.
    let committed = cell.read().await.history.clone();
    fixture.state.connection().unwrap().execute_batch("CREATE TRIGGER reject_metadata BEFORE UPDATE ON sfn_executions BEGIN SELECT RAISE(ABORT,'injected metadata failure'); END;").unwrap();
    {
        let mut guard = cell.write().await;
        guard.current_state = Some("uncommitted".into());
        guard.status = Status::Failed;
    }
    assert!(failed.load(Ordering::Acquire));
    let value = cell.read().await;
    assert_eq!(value.current_state.as_deref(), Some("updated"));
    assert_eq!(value.status, original.status);
    assert!(Arc::ptr_eq(&value.history, &committed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_history_guard_rejects_truncation_reordering_and_identity_changes() {
    let fixture = TestState::new();
    let persistence = fixture.persistence();
    let original = execution("shared-invariants", 3);
    persistence.save_execution(&original).unwrap();
    for edit in 0..3 {
        let failed = Arc::new(AtomicBool::new(false));
        let cell = ExecutionCell::new(original.clone(), Some(persistence.clone()), failed.clone());
        {
            let mut guard = cell.write().await;
            match edit {
                0 => Arc::make_mut(&mut guard.history).truncate(1),
                1 => Arc::make_mut(&mut guard.history).swap(0, 1),
                _ => guard.arn = "different-execution".into(),
            }
        }
        assert!(failed.load(Ordering::Acquire));
        let value = cell.read().await;
        assert_eq!(value.arn, original.arn);
        assert!(Arc::ptr_eq(&value.history, &original.history));
    }
    let restored = fixture.restore().unwrap();
    let restored = restored.executions.get(&original.arn).unwrap().clone();
    assert_eq!(restored.read().await.history.len(), 3);
}
