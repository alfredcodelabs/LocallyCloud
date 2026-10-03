use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use http::{Method, StatusCode};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{Connection, OpenFlags, Statement};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::config::RdsDataConfig;
use crate::error::RdsDataError;
use crate::model::{
    BatchRequest, BatchResponse, BeginRequest, BeginResponse, ColumnMetadata, DecimalReturnType,
    ExecuteRequest, ExecuteResponse, Field, FinalizeRequest, FinalizeResponse, FormatRecordsAs,
    LongReturnType, ResultSetOptions, SqlParameter, TypeHint, UpdateResult,
};

const MAX_SQL_BYTES: usize = 65_536;
const MIN_ARN_BYTES: usize = 11;
const MAX_ARN_BYTES: usize = 100;
const MAX_DATABASE_BYTES: usize = 64;
const MAX_TRANSACTION_ID_BYTES: usize = 192;
const DEFAULT_DATABASE: &str = "local";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RdsDataStats {
    pub stores: usize,
    pub open_connections: usize,
    pub blocking_operations: usize,
    pub transactions: usize,
}

#[derive(Default)]
struct Counters {
    open_connections: AtomicUsize,
    blocking_operations: AtomicUsize,
}

struct BlockingGuard {
    counters: Arc<Counters>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for BlockingGuard {
    fn drop(&mut self) {
        self.counters
            .blocking_operations
            .fetch_sub(1, Ordering::AcqRel);
    }
}

struct AdmissionGuard {
    state: Arc<State>,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        if self.state.admitted_requests.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.state.admission_idle.notify_waiters();
        }
    }
}

#[derive(Default)]
struct ReaperControl {
    running: bool,
    tasks: Vec<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct RdsDataHandle {
    state: Arc<State>,
    pub(crate) pg_state: Option<Arc<crate::postgres::PgState>>,
}

impl RdsDataHandle {
    pub fn statistics(&self) -> RdsDataStats {
        self.state.statistics()
    }

    pub async fn shutdown(&self) {
        if let Some(pg_state) = &self.pg_state {
            pg_state.shutdown().await;
        }
        if self.state.shutdown.swap(true, Ordering::AcqRel) {
            loop {
                let completed = self.state.shutdown_completed.notified();
                if self.state.shutdown_complete.load(Ordering::Acquire) {
                    return;
                }
                completed.await;
            }
        }
        loop {
            let idle = self.state.admission_idle.notified();
            if self.state.admitted_requests.load(Ordering::Acquire) == 0 {
                break;
            }
            idle.await;
        }
        self.state.reaper_wakeup.notify_one();
        let reaper_tasks = {
            let mut reaper = self.state.reaper.lock().expect("reaper lock");
            reaper.running = false;
            std::mem::take(&mut reaper.tasks)
        };
        let records = {
            let mut transactions = self.state.transactions.lock().expect("transactions lock");
            transactions
                .drain()
                .map(|(_, record)| {
                    record.claimed.store(true, Ordering::Release);
                    record
                })
                .collect::<Vec<_>>()
        };
        for record in records {
            let _operation = record.operation_lock.lock().await;
            let connection = record.connection.clone();
            let _ = self
                .state
                .run_blocking(move || {
                    if let Some(connection) = connection.lock().expect("connection lock").take() {
                        let _ = connection.conn.execute_batch("ROLLBACK");
                    }
                    Ok(())
                })
                .await;
        }
        for task in reaper_tasks {
            let _ = task.await;
        }
        let all_permits = self
            .state
            .semaphore
            .clone()
            .acquire_many_owned(self.state.config.limits.max_blocking_operations as u32)
            .await
            .ok();
        self.state.slots.lock().expect("slots lock").clear();
        self.state
            .identities
            .lock()
            .expect("identities lock")
            .clear();
        drop(all_permits);
        self.state.shutdown_complete.store(true, Ordering::Release);
        self.state.shutdown_completed.notify_waiters();
    }
}

pub(crate) struct RdsDataHandler {
    state: Arc<State>,
}

impl RdsDataHandler {
    pub(crate) fn new(config: RdsDataConfig) -> (Self, RdsDataHandle) {
        let state = Arc::new(State {
            semaphore: Arc::new(Semaphore::new(config.limits.max_blocking_operations)),
            config,
            slots: Mutex::new(HashMap::new()),
            identities: Mutex::new(HashMap::new()),
            transactions: Mutex::new(HashMap::new()),
            counters: Arc::new(Counters::default()),
            shutdown: AtomicBool::new(false),
            shutdown_complete: AtomicBool::new(false),
            shutdown_completed: Notify::new(),
            admitted_requests: AtomicUsize::new(0),
            admission_idle: Notify::new(),
            reaper: Mutex::new(ReaperControl::default()),
            reaper_wakeup: Notify::new(),
        });
        (
            Self {
                state: state.clone(),
            },
            RdsDataHandle {
                state,
                pg_state: None,
            },
        )
    }

    async fn process(&self, request: &ServiceRequest) -> Result<Vec<u8>, RdsDataError> {
        let _admission = self.state.admit()?;
        if request.method != Method::POST || request.uri.query().is_some() {
            return Err(RdsDataError::BadRequest(
                "RDS Data operations require POST and do not accept query parameters",
            ));
        }
        if request.headers.contains_key("x-amz-target") {
            return Err(RdsDataError::BadRequest(
                "X-Amz-Target is not accepted by the RDS Data REST-JSON endpoint",
            ));
        }
        let content_type = request
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if content_type != Some("application/json") {
            return Err(RdsDataError::BadRequest(
                "content-type must be application/json",
            ));
        }
        if request.body.len() > self.state.config.limits.request_bytes {
            return Err(RdsDataError::BadRequest("request exceeds the 4 MiB limit"));
        }
        match request.uri.path() {
            "/Execute" => {
                let input: ExecuteRequest = decode(&request.body)?;
                self.execute(input, request).await
            }
            "/BatchExecute" => {
                let input: BatchRequest = decode(&request.body)?;
                self.batch(input, request).await
            }
            "/BeginTransaction" => {
                let input: BeginRequest = decode(&request.body)?;
                self.begin(input, request).await
            }
            "/CommitTransaction" => {
                let input: FinalizeRequest = decode(&request.body)?;
                self.finalize(input, request, true).await
            }
            "/RollbackTransaction" => {
                let input: FinalizeRequest = decode(&request.body)?;
                self.finalize(input, request, false).await
            }
            _ => Err(RdsDataError::BadRequest("unsupported RDS Data operation")),
        }
    }

    async fn execute(
        &self,
        input: ExecuteRequest,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, RdsDataError> {
        let scope = Scope::new(
            &request.account_id,
            &request.region,
            &input.resource_arn,
            &input.secret_arn,
            input.database.as_deref(),
            input.schema.as_deref(),
        )?;
        validate_sql(&input.sql)?;
        let parameters = validate_parameters(&input.parameters, &self.state.config)?;
        if input.continue_after_timeout {
            // Accepted for wire compatibility. Embedded execution has no post-timeout continuation.
        }
        if let Some(transaction_id) = input.transaction_id.as_deref() {
            validate_transaction_id(transaction_id)?;
            let record = self.state.transaction(transaction_id, &scope)?;
            return self
                .execute_in_transaction(record, transaction_id.to_owned(), input, parameters)
                .await;
        }
        let state = self.state.clone();
        let slot = state.slot(scope)?;
        let sql = input.sql;
        let limits = state.config.limits.clone();
        let include_metadata = input.include_result_metadata;
        let options = input.result_set_options;
        let format = input
            .format_records_as
            .filter(|value| *value == FormatRecordsAs::Json);
        state
            .clone()
            .run_blocking(move || {
                let store = state.store_for_statement(&slot, &sql, &[&parameters], false)?;
                let connection = state.open_connection(&store)?;
                connection
                    .conn
                    .execute_batch("BEGIN")
                    .map_err(|_| RdsDataError::Database("database transaction could not start"))?;
                let result = execute_statement(
                    &connection.conn,
                    &sql,
                    &parameters,
                    include_metadata,
                    options,
                    format,
                    &limits,
                );
                match result {
                    Ok(bytes) => {
                        connection.conn.execute_batch("COMMIT").map_err(|_| {
                            RdsDataError::Database("database transaction could not commit")
                        })?;
                        Ok(bytes)
                    }
                    Err(error) => {
                        let _ = connection.conn.execute_batch("ROLLBACK");
                        Err(error)
                    }
                }
            })
            .await
    }

    async fn execute_in_transaction(
        &self,
        record: Arc<TransactionRecord>,
        transaction_id: String,
        input: ExecuteRequest,
        parameters: Vec<(String, SqlValue)>,
    ) -> Result<Vec<u8>, RdsDataError> {
        let state = self.state.clone();
        let _operation = record.operation_lock.lock().await;
        if record.claimed.load(Ordering::Acquire) {
            return Err(RdsDataError::TransactionNotFound);
        }
        if record.is_expired(&state.config, Instant::now()) {
            state.expire_locked(&transaction_id, &record).await?;
            return Err(RdsDataError::TransactionNotFound);
        }
        *record.last_activity.lock().expect("activity lock") = Instant::now();
        let sql = input.sql;
        let limits = state.config.limits.clone();
        let include_metadata = input.include_result_metadata;
        let options = input.result_set_options;
        let format = input
            .format_records_as
            .filter(|value| *value == FormatRecordsAs::Json);
        let connection = record.connection.clone();
        let result = state
            .run_blocking(move || {
                let mut holder = connection.lock().expect("connection lock");
                let connection = holder.as_mut().ok_or(RdsDataError::TransactionNotFound)?;
                connection
                    .conn
                    .execute_batch("SAVEPOINT lc_statement")
                    .map_err(|_| RdsDataError::Database("statement savepoint could not start"))?;
                let result = execute_statement(
                    &connection.conn,
                    &sql,
                    &parameters,
                    include_metadata,
                    options,
                    format,
                    &limits,
                );
                finish_savepoint(&mut holder, SavepointKind::Statement, result)
            })
            .await;
        *record.last_activity.lock().expect("activity lock") = Instant::now();
        if record.connection.lock().expect("connection lock").is_none() {
            state.remove_broken(&transaction_id, &record);
        }
        result
    }

    async fn batch(
        &self,
        input: BatchRequest,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, RdsDataError> {
        let scope = Scope::new(
            &request.account_id,
            &request.region,
            &input.resource_arn,
            &input.secret_arn,
            input.database.as_deref(),
            input.schema.as_deref(),
        )?;
        validate_sql(&input.sql)?;
        if input.parameter_sets.len() > self.state.config.limits.max_batch_sets {
            return Err(RdsDataError::BadRequest("too many batch parameter sets"));
        }
        let parameter_sets = input
            .parameter_sets
            .iter()
            .map(|set| validate_parameters(set, &self.state.config))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(transaction_id) = input.transaction_id {
            validate_transaction_id(&transaction_id)?;
            let record = self.state.transaction(&transaction_id, &scope)?;
            return self
                .batch_in_transaction(record, transaction_id, input.sql, parameter_sets)
                .await;
        }
        let state = self.state.clone();
        let slot = state.slot(scope)?;
        let sql = input.sql;
        let response_limit = state.config.limits.response_bytes;
        state
            .clone()
            .run_blocking(move || {
                let bindings = parameter_sets.iter().map(Vec::as_slice).collect::<Vec<_>>();
                let store = state.store_for_statement(&slot, &sql, &bindings, true)?;
                let connection = state.open_connection(&store)?;
                connection
                    .conn
                    .execute_batch("BEGIN")
                    .map_err(|_| RdsDataError::Database("database transaction could not start"))?;
                let result = execute_batch(&connection.conn, &sql, &parameter_sets, response_limit);
                match result {
                    Ok(bytes) => {
                        connection.conn.execute_batch("COMMIT").map_err(|_| {
                            RdsDataError::Database("database transaction could not commit")
                        })?;
                        Ok(bytes)
                    }
                    Err(error) => {
                        let _ = connection.conn.execute_batch("ROLLBACK");
                        Err(error)
                    }
                }
            })
            .await
    }

    async fn batch_in_transaction(
        &self,
        record: Arc<TransactionRecord>,
        transaction_id: String,
        sql: String,
        parameter_sets: Vec<Vec<(String, SqlValue)>>,
    ) -> Result<Vec<u8>, RdsDataError> {
        let state = self.state.clone();
        let response_limit = state.config.limits.response_bytes;
        let _operation = record.operation_lock.lock().await;
        if record.claimed.load(Ordering::Acquire) {
            return Err(RdsDataError::TransactionNotFound);
        }
        if record.is_expired(&state.config, Instant::now()) {
            state.expire_locked(&transaction_id, &record).await?;
            return Err(RdsDataError::TransactionNotFound);
        }
        *record.last_activity.lock().expect("activity lock") = Instant::now();
        let connection = record.connection.clone();
        let result = state
            .run_blocking(move || {
                let mut holder = connection.lock().expect("connection lock");
                let connection = holder.as_mut().ok_or(RdsDataError::TransactionNotFound)?;
                connection
                    .conn
                    .execute_batch("SAVEPOINT lc_batch")
                    .map_err(|_| RdsDataError::Database("batch savepoint could not start"))?;
                let result = execute_batch(&connection.conn, &sql, &parameter_sets, response_limit);
                finish_savepoint(&mut holder, SavepointKind::Batch, result)
            })
            .await;
        *record.last_activity.lock().expect("activity lock") = Instant::now();
        if record.connection.lock().expect("connection lock").is_none() {
            state.remove_broken(&transaction_id, &record);
        }
        result
    }

    async fn begin(
        &self,
        input: BeginRequest,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, RdsDataError> {
        let scope = Scope::new(
            &request.account_id,
            &request.region,
            &input.resource_arn,
            &input.secret_arn,
            input.database.as_deref(),
            input.schema.as_deref(),
        )?;
        let state = self.state.clone();
        let slot = state.slot(scope.clone())?;
        let connection = state
            .clone()
            .run_blocking(move || state.connection_for_begin(&slot))
            .await?;
        let transaction_id = Uuid::new_v4().to_string();
        let now = Instant::now();
        let record = Arc::new(TransactionRecord {
            scope,
            operation_lock: AsyncMutex::new(()),
            connection: Arc::new(Mutex::new(Some(connection))),
            created: now,
            last_activity: Mutex::new(now),
            claimed: AtomicBool::new(false),
        });
        self.state
            .publish_transaction(transaction_id.clone(), record);
        serialize_bounded(
            &BeginResponse { transaction_id },
            self.state.config.limits.response_bytes,
        )
    }

    async fn finalize(
        &self,
        input: FinalizeRequest,
        request: &ServiceRequest,
        commit: bool,
    ) -> Result<Vec<u8>, RdsDataError> {
        validate_transaction_id(&input.transaction_id)?;
        validate_arn(
            &input.resource_arn,
            "rds",
            &request.account_id,
            &request.region,
        )?;
        validate_arn(
            &input.secret_arn,
            "secretsmanager",
            &request.account_id,
            &request.region,
        )?;
        let record = self.state.claim_for_finalize(
            &input.transaction_id,
            &request.account_id,
            &request.region,
            &input.resource_arn,
            &input.secret_arn,
        )?;
        let _operation = record.operation_lock.lock().await;
        let expired = record.is_expired(&self.state.config, Instant::now());
        let connection = record.connection.clone();
        let state = self.state.clone();
        state
            .run_blocking(move || {
                let connection = connection
                    .lock()
                    .expect("connection lock")
                    .take()
                    .ok_or(RdsDataError::TransactionNotFound)?;
                let sql = if expired || !commit {
                    "ROLLBACK"
                } else {
                    "COMMIT"
                };
                connection.conn.execute_batch(sql).map_err(|_| {
                    RdsDataError::Database("database transaction could not be finalized")
                })?;
                Ok(())
            })
            .await?;
        if expired {
            return Err(RdsDataError::TransactionNotFound);
        }
        serialize_bounded(
            &FinalizeResponse {
                transaction_status: if commit {
                    "Transaction Committed"
                } else {
                    "Transaction Rolled Back"
                },
            },
            self.state.config.limits.response_bytes,
        )
    }
}

#[async_trait]
impl NativeHandler for RdsDataHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let request_id = request.request_id.clone();
        match self.process(&request).await {
            Ok(body) => http::Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/json")
                .header("x-amzn-RequestId", request_id)
                .body(Body::from(body))
                .expect("RDS Data response is valid"),
            Err(error) => error.into_response(request_id),
        }
    }
}

struct State {
    config: RdsDataConfig,
    semaphore: Arc<Semaphore>,
    slots: Mutex<HashMap<Scope, Arc<StoreSlot>>>,
    identities: Mutex<HashMap<String, Scope>>,
    transactions: Mutex<HashMap<String, Arc<TransactionRecord>>>,
    counters: Arc<Counters>,
    shutdown: AtomicBool,
    shutdown_complete: AtomicBool,
    shutdown_completed: Notify,
    admitted_requests: AtomicUsize,
    admission_idle: Notify,
    reaper: Mutex<ReaperControl>,
    reaper_wakeup: Notify,
}

impl State {
    fn admit(self: &Arc<Self>) -> Result<AdmissionGuard, RdsDataError> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(RdsDataError::Unavailable);
        }
        self.admitted_requests.fetch_add(1, Ordering::AcqRel);
        let guard = AdmissionGuard {
            state: self.clone(),
        };
        if self.shutdown.load(Ordering::Acquire) {
            drop(guard);
            return Err(RdsDataError::Unavailable);
        }
        Ok(guard)
    }

    fn statistics(&self) -> RdsDataStats {
        let stores = self
            .slots
            .lock()
            .expect("slots lock")
            .values()
            .filter(|slot| slot.store.lock().expect("store lock").is_some())
            .count();
        RdsDataStats {
            stores,
            open_connections: self.counters.open_connections.load(Ordering::Acquire),
            blocking_operations: self.counters.blocking_operations.load(Ordering::Acquire),
            transactions: self.transactions.lock().expect("transactions lock").len(),
        }
    }

    async fn run_blocking<T, F>(&self, work: F) -> Result<T, RdsDataError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, RdsDataError> + Send + 'static,
    {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RdsDataError::Unavailable)?;
        let counters = self.counters.clone();
        counters.blocking_operations.fetch_add(1, Ordering::AcqRel);
        tokio::task::spawn_blocking(move || {
            let _guard = BlockingGuard {
                counters,
                _permit: permit,
            };
            work()
        })
        .await
        .map_err(|_| RdsDataError::Internal)?
    }

    fn slot(self: &Arc<Self>, scope: Scope) -> Result<SlotLease, RdsDataError> {
        let digest = scope.digest();
        let mut identities = self.identities.lock().expect("identities lock");
        if let Some(existing) = identities.get(&digest) {
            if existing != &scope {
                return Err(RdsDataError::Internal);
            }
        } else {
            identities.insert(digest.clone(), scope.clone());
        }
        let mut slots = self.slots.lock().expect("slots lock");
        let slot = slots
            .entry(scope.clone())
            .or_insert_with(|| Arc::new(StoreSlot::new(self.config.state_root.join(&digest))))
            .clone();
        slot.users.fetch_add(1, Ordering::AcqRel);
        Ok(SlotLease {
            state: self.clone(),
            scope,
            digest,
            slot,
        })
    }

    fn store_for_statement(
        &self,
        slot: &SlotLease,
        sql: &str,
        parameter_sets: &[&[(String, SqlValue)]],
        batch: bool,
    ) -> Result<Arc<Store>, RdsDataError> {
        let _initializing = slot.initializing.lock().expect("initializing lock");
        if let Some(store) = slot.store.lock().expect("store lock").clone() {
            return Ok(store);
        }
        let store = Arc::new(Store {
            path: slot.path.with_extension("sqlite3"),
        });
        let existed = store.path.exists();
        let validation = (|| {
            let connection = self.open_connection(&store)?;
            let mut statement = connection
                .conn
                .prepare(sql)
                .map_err(|_| RdsDataError::Database("SQL statement could not be prepared"))?;
            if batch && statement.column_count() != 0 {
                return Err(RdsDataError::Unsupported(
                    "BatchExecuteStatement does not support result sets",
                ));
            }
            for parameters in parameter_sets {
                statement.clear_bindings();
                bind_parameters(&mut statement, parameters)?;
            }
            Ok(())
        })();
        if let Err(error) = validation {
            if !existed {
                remove_sqlite_files(&store.path);
            }
            return Err(error);
        }
        *slot.store.lock().expect("store lock") = Some(store.clone());
        Ok(store)
    }

    fn connection_for_begin(&self, slot: &SlotLease) -> Result<TrackedConnection, RdsDataError> {
        let _initializing = slot.initializing.lock().expect("initializing lock");
        if let Some(store) = slot.store.lock().expect("store lock").clone() {
            let connection = self.open_connection(&store)?;
            connection
                .conn
                .execute_batch("BEGIN IMMEDIATE")
                .map_err(|_| RdsDataError::Database("database transaction could not start"))?;
            return Ok(connection);
        }
        let store = Arc::new(Store {
            path: slot.path.with_extension("sqlite3"),
        });
        let existed = store.path.exists();
        let result = (|| {
            let connection = self.open_connection(&store)?;
            connection
                .conn
                .execute_batch("BEGIN IMMEDIATE")
                .map_err(|_| RdsDataError::Database("database transaction could not start"))?;
            Ok(connection)
        })();
        match result {
            Ok(connection) => {
                *slot.store.lock().expect("store lock") = Some(store);
                Ok(connection)
            }
            Err(error) => {
                if !existed {
                    remove_sqlite_files(&store.path);
                }
                Err(error)
            }
        }
    }

    fn open_connection(&self, store: &Store) -> Result<TrackedConnection, RdsDataError> {
        locallycloud_state::StateDb::private_dir(&self.config.state_root)
            .map_err(|_| RdsDataError::Unavailable)?;
        let connection = Connection::open_with_flags(
            &store.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| RdsDataError::Unavailable)?;
        connection
            .busy_timeout(self.config.busy_timeout)
            .map_err(|_| RdsDataError::Unavailable)?;
        connection
            .execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;")
            .map_err(|_| RdsDataError::Unavailable)?;
        self.counters
            .open_connections
            .fetch_add(1, Ordering::AcqRel);
        Ok(TrackedConnection {
            conn: connection,
            counters: self.counters.clone(),
        })
    }

    fn publish_transaction(
        self: &Arc<Self>,
        transaction_id: String,
        record: Arc<TransactionRecord>,
    ) {
        let mut transactions = self.transactions.lock().expect("transactions lock");
        transactions.insert(transaction_id, record);
        let mut reaper = self.reaper.lock().expect("reaper lock");
        if !reaper.running {
            reaper.tasks.retain(|task| !task.is_finished());
            reaper.running = true;
            let state = self.clone();
            reaper
                .tasks
                .push(tokio::spawn(async move { state.reap_transactions().await }));
        }
    }

    async fn reap_transactions(self: Arc<Self>) {
        let shortest_timeout = self
            .config
            .transaction_idle_timeout
            .min(self.config.transaction_absolute_timeout);
        let interval = (shortest_timeout / 2).max(Duration::from_millis(1));
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = self.reaper_wakeup.notified() => {}
            }
            if self.shutdown.load(Ordering::Acquire) {
                break;
            }
            let candidates = {
                let now = Instant::now();
                self.transactions
                    .lock()
                    .expect("transactions lock")
                    .iter()
                    .filter(|(_, record)| record.is_expired(&self.config, now))
                    .map(|(transaction_id, record)| (transaction_id.clone(), record.clone()))
                    .collect::<Vec<_>>()
            };
            for (transaction_id, record) in candidates {
                let _operation = record.operation_lock.lock().await;
                if !record.is_expired(&self.config, Instant::now()) {
                    continue;
                }
                let claimed = {
                    let mut transactions = self.transactions.lock().expect("transactions lock");
                    if !transactions
                        .get(&transaction_id)
                        .is_some_and(|current| Arc::ptr_eq(current, &record))
                        || record.claimed.swap(true, Ordering::AcqRel)
                    {
                        false
                    } else {
                        transactions.remove(&transaction_id);
                        true
                    }
                };
                if !claimed {
                    continue;
                }
                let connection = record.connection.clone();
                let _ = self
                    .run_blocking(move || {
                        if let Some(connection) = connection.lock().expect("connection lock").take()
                        {
                            let _ = connection.conn.execute_batch("ROLLBACK");
                        }
                        Ok(())
                    })
                    .await;
            }
            let transactions = self.transactions.lock().expect("transactions lock");
            if transactions.is_empty() {
                let mut reaper = self.reaper.lock().expect("reaper lock");
                if transactions.is_empty() {
                    reaper.running = false;
                    return;
                }
            }
        }
        self.reaper.lock().expect("reaper lock").running = false;
    }

    fn claim_for_finalize(
        &self,
        transaction_id: &str,
        account: &str,
        region: &str,
        resource_arn: &str,
        secret_arn: &str,
    ) -> Result<Arc<TransactionRecord>, RdsDataError> {
        let mut transactions = self.transactions.lock().expect("transactions lock");
        let record = transactions
            .get(transaction_id)
            .filter(|record| {
                record.scope.account == account
                    && record.scope.region == region
                    && record.scope.resource_arn == resource_arn
                    && record.scope.secret_arn == secret_arn
            })
            .cloned()
            .ok_or(RdsDataError::TransactionNotFound)?;
        if record.claimed.swap(true, Ordering::AcqRel) {
            return Err(RdsDataError::TransactionNotFound);
        }
        transactions.remove(transaction_id);
        if transactions.is_empty() {
            self.reaper_wakeup.notify_one();
        }
        Ok(record)
    }

    fn transaction(
        &self,
        transaction_id: &str,
        scope: &Scope,
    ) -> Result<Arc<TransactionRecord>, RdsDataError> {
        self.transactions
            .lock()
            .expect("transactions lock")
            .get(transaction_id)
            .filter(|record| record.scope == *scope)
            .cloned()
            .ok_or(RdsDataError::TransactionNotFound)
    }

    async fn expire_locked(
        &self,
        transaction_id: &str,
        record: &Arc<TransactionRecord>,
    ) -> Result<(), RdsDataError> {
        {
            let mut transactions = self.transactions.lock().expect("transactions lock");
            if !transactions
                .get(transaction_id)
                .is_some_and(|current| Arc::ptr_eq(current, record))
                || record.claimed.swap(true, Ordering::AcqRel)
            {
                return Err(RdsDataError::TransactionNotFound);
            }
            transactions.remove(transaction_id);
            if transactions.is_empty() {
                self.reaper_wakeup.notify_one();
            }
        }
        let connection = record.connection.clone();
        self.run_blocking(move || {
            if let Some(connection) = connection.lock().expect("connection lock").take() {
                let _ = connection.conn.execute_batch("ROLLBACK");
            }
            Ok(())
        })
        .await
    }

    fn remove_broken(&self, transaction_id: &str, record: &Arc<TransactionRecord>) {
        let mut transactions = self.transactions.lock().expect("transactions lock");
        if transactions
            .get(transaction_id)
            .is_some_and(|current| Arc::ptr_eq(current, record))
        {
            record.claimed.store(true, Ordering::Release);
            transactions.remove(transaction_id);
            if transactions.is_empty() {
                self.reaper_wakeup.notify_one();
            }
        }
    }
}

struct SlotLease {
    state: Arc<State>,
    scope: Scope,
    digest: String,
    slot: Arc<StoreSlot>,
}

impl std::ops::Deref for SlotLease {
    type Target = StoreSlot;

    fn deref(&self) -> &Self::Target {
        &self.slot
    }
}

impl Drop for SlotLease {
    fn drop(&mut self) {
        let mut identities = self.state.identities.lock().expect("identities lock");
        let mut slots = self.state.slots.lock().expect("slots lock");
        let remaining = self.slot.users.fetch_sub(1, Ordering::AcqRel) - 1;
        if remaining == 0
            && self.slot.store.lock().expect("store lock").is_none()
            && slots
                .get(&self.scope)
                .is_some_and(|current| Arc::ptr_eq(current, &self.slot))
        {
            slots.remove(&self.scope);
            if identities
                .get(&self.digest)
                .is_some_and(|current| current == &self.scope)
            {
                identities.remove(&self.digest);
            }
        }
    }
}

struct StoreSlot {
    path: PathBuf,
    initializing: Mutex<()>,
    store: Mutex<Option<Arc<Store>>>,
    users: AtomicUsize,
}

impl StoreSlot {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            initializing: Mutex::new(()),
            store: Mutex::new(None),
            users: AtomicUsize::new(0),
        }
    }
}

struct Store {
    path: PathBuf,
}

struct TrackedConnection {
    conn: Connection,
    counters: Arc<Counters>,
}

impl Drop for TrackedConnection {
    fn drop(&mut self) {
        self.counters
            .open_connections
            .fetch_sub(1, Ordering::AcqRel);
    }
}

struct TransactionRecord {
    scope: Scope,
    operation_lock: AsyncMutex<()>,
    connection: Arc<Mutex<Option<TrackedConnection>>>,
    created: Instant,
    last_activity: Mutex<Instant>,
    claimed: AtomicBool,
}

impl TransactionRecord {
    fn is_expired(&self, config: &RdsDataConfig, now: Instant) -> bool {
        now.duration_since(self.created) > config.transaction_absolute_timeout
            || now.duration_since(*self.last_activity.lock().expect("activity lock"))
                > config.transaction_idle_timeout
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Scope {
    account: String,
    region: String,
    resource_arn: String,
    secret_arn: String,
    database: String,
}

impl Scope {
    fn new(
        account: &str,
        region: &str,
        resource_arn: &str,
        secret_arn: &str,
        database: Option<&str>,
        schema: Option<&str>,
    ) -> Result<Self, RdsDataError> {
        validate_arn(resource_arn, "rds", account, region)?;
        validate_arn(secret_arn, "secretsmanager", account, region)?;
        if schema.is_some_and(|value| value.len() > MAX_DATABASE_BYTES) {
            return Err(RdsDataError::BadRequest("schema must not exceed 64 bytes"));
        }
        if schema.is_some_and(|value| !value.is_empty()) {
            return Err(RdsDataError::Unsupported(
                "non-empty schema is unsupported by the local SQLite backend",
            ));
        }
        let database = database.unwrap_or(DEFAULT_DATABASE);
        if database.is_empty() || database.len() > MAX_DATABASE_BYTES {
            return Err(RdsDataError::BadRequest(
                "database must contain between 1 and 64 bytes",
            ));
        }
        Ok(Self {
            account: account.to_owned(),
            region: region.to_owned(),
            resource_arn: resource_arn.to_owned(),
            secret_arn: secret_arn.to_owned(),
            database: database.to_owned(),
        })
    }

    fn digest(&self) -> String {
        let mut digest = Sha256::new();
        for value in [
            &self.account,
            &self.region,
            &self.resource_arn,
            &self.secret_arn,
            &self.database,
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

fn validate_arn(arn: &str, service: &str, account: &str, region: &str) -> Result<(), RdsDataError> {
    if !(MIN_ARN_BYTES..=MAX_ARN_BYTES).contains(&arn.len()) {
        return Err(RdsDataError::BadRequest(
            "ARN must contain between 11 and 100 bytes",
        ));
    }
    let parts = arn.splitn(6, ':').collect::<Vec<_>>();
    let resource_ok = match service {
        "rds" => parts
            .get(5)
            .is_some_and(|value| value.starts_with("cluster:") && value.len() > "cluster:".len()),
        "secretsmanager" => parts
            .get(5)
            .is_some_and(|value| value.starts_with("secret:") && value.len() > "secret:".len()),
        _ => false,
    };
    if parts.len() != 6
        || parts[0] != "arn"
        || parts[1].is_empty()
        || parts[2] != service
        || parts[3] != region
        || parts[4] != account
        || !resource_ok
    {
        return Err(RdsDataError::BadRequest(
            "ARN does not match the request account, region, or resource type",
        ));
    }
    Ok(())
}

fn validate_sql(sql: &str) -> Result<(), RdsDataError> {
    if sql.is_empty() || sql.len() > MAX_SQL_BYTES || sql.contains('\0') {
        return Err(RdsDataError::BadRequest(
            "SQL must contain between 1 and 65536 bytes",
        ));
    }
    let keywords = leading_sql_keywords(sql);
    let operation = if keywords.first().is_some_and(|word| word == "EXPLAIN") {
        keywords
            .iter()
            .skip(1)
            .find(|word| word.as_str() != "QUERY" && word.as_str() != "PLAN")
    } else {
        keywords.first()
    };
    if operation.is_some_and(|word| {
        matches!(
            word.as_str(),
            "BEGIN"
                | "COMMIT"
                | "END"
                | "ROLLBACK"
                | "SAVEPOINT"
                | "RELEASE"
                | "ATTACH"
                | "DETACH"
                | "PRAGMA"
                | "VACUUM"
        )
    }) {
        return Err(RdsDataError::BadRequest(
            "transaction, attachment, and pragma SQL is managed by the service",
        ));
    }
    Ok(())
}

fn leading_sql_keywords(sql: &str) -> Vec<String> {
    let bytes = sql.as_bytes();
    let mut index = 0;
    let mut words = Vec::new();
    while index < bytes.len() && words.len() < 4 {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index..index + 2) == Some(b"--") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"/*") {
            index += 2;
            while index + 1 < bytes.len() && &bytes[index..index + 2] != b"*/" {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            continue;
        }
        let start = index;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        if start == index {
            break;
        }
        words.push(sql[start..index].to_ascii_uppercase());
    }
    words
}

fn validate_transaction_id(transaction_id: &str) -> Result<(), RdsDataError> {
    if transaction_id.is_empty() || transaction_id.len() > MAX_TRANSACTION_ID_BYTES {
        return Err(RdsDataError::BadRequest("invalid transactionId"));
    }
    Ok(())
}

fn validate_parameters(
    parameters: &[SqlParameter],
    config: &RdsDataConfig,
) -> Result<Vec<(String, SqlValue)>, RdsDataError> {
    if parameters.len() > config.limits.max_parameters {
        return Err(RdsDataError::BadRequest("too many SQL parameters"));
    }
    let mut names = HashSet::new();
    parameters
        .iter()
        .map(|parameter| {
            if parameter.name.is_empty()
                || parameter.name.len() > 128
                || !parameter
                    .name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
                || !names.insert(parameter.name.clone())
            {
                return Err(RdsDataError::BadRequest(
                    "parameter names must be unique ASCII identifiers",
                ));
            }
            let value = field_to_sql(&parameter.value, parameter.type_hint, config)?;
            Ok((parameter.name.clone(), value))
        })
        .collect()
}

fn field_to_sql(
    field: &Field,
    hint: Option<TypeHint>,
    config: &RdsDataConfig,
) -> Result<SqlValue, RdsDataError> {
    let count = [
        field.is_null.is_some(),
        field.boolean_value.is_some(),
        field.long_value.is_some(),
        field.double_value.is_some(),
        field.string_value.is_some(),
        field.blob_value.is_some(),
        field.array_value.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if count != 1 {
        return Err(RdsDataError::BadRequest(
            "Field must contain exactly one union member",
        ));
    }
    if field.array_value.is_some() {
        return Err(RdsDataError::Unsupported(
            "array parameters are not supported by the RDS Data API",
        ));
    }
    let value = if let Some(is_null) = field.is_null {
        if !is_null {
            return Err(RdsDataError::BadRequest("isNull must be true"));
        }
        SqlValue::Null
    } else if let Some(value) = field.boolean_value {
        SqlValue::Integer(i64::from(value))
    } else if let Some(value) = field.long_value {
        SqlValue::Integer(value)
    } else if let Some(value) = field.double_value {
        if !value.is_finite() {
            return Err(RdsDataError::BadRequest("doubleValue must be finite"));
        }
        SqlValue::Real(value)
    } else if let Some(value) = &field.string_value {
        if value.len() > config.limits.max_field_bytes {
            return Err(RdsDataError::BadRequest("stringValue is too large"));
        }
        validate_hint(value, hint)?;
        SqlValue::Text(value.clone())
    } else if let Some(value) = &field.blob_value {
        let bytes = BASE64
            .decode(value)
            .map_err(|_| RdsDataError::BadRequest("blobValue must be valid base64"))?;
        if bytes.len() > config.limits.max_field_bytes {
            return Err(RdsDataError::BadRequest("blobValue is too large"));
        }
        if hint.is_some() {
            return Err(RdsDataError::BadRequest("typeHint requires stringValue"));
        }
        SqlValue::Blob(bytes)
    } else {
        return Err(RdsDataError::BadRequest("invalid Field"));
    };
    if hint.is_some() && !matches!(value, SqlValue::Text(_)) {
        return Err(RdsDataError::BadRequest("typeHint requires stringValue"));
    }
    Ok(value)
}

fn validate_hint(value: &str, hint: Option<TypeHint>) -> Result<(), RdsDataError> {
    let valid = match hint {
        None => true,
        Some(TypeHint::Date) => valid_date(value),
        Some(TypeHint::Time) => valid_time(value),
        Some(TypeHint::Timestamp) => {
            let split = value.split_once(['T', ' ']);
            split.is_some_and(|(date, time)| valid_date(date) && valid_time(time))
        }
        Some(TypeHint::Decimal) => valid_decimal(value),
        Some(TypeHint::Json) => serde_json::from_str::<Value>(value).is_ok(),
        Some(TypeHint::Uuid) => Uuid::parse_str(value)
            .is_ok_and(|uuid| value.len() == 36 && uuid.hyphenated().to_string() == value),
    };
    if valid {
        Ok(())
    } else {
        Err(RdsDataError::BadRequest("invalid value for typeHint"))
    }
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return false;
    }
    let month = value[5..7].parse::<u8>().ok();
    let day = value[8..10].parse::<u8>().ok();
    let max_day = match month {
        Some(1 | 3 | 5 | 7 | 8 | 10 | 12) => 31,
        Some(4 | 6 | 9 | 11) => 30,
        Some(2) => {
            let year = value[..4].parse::<u16>().unwrap_or(0);
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    max_day != 0 && day.is_some_and(|day| (1..=max_day).contains(&day))
}

fn valid_time(value: &str) -> bool {
    let (main, fraction) = value
        .split_once('.')
        .map_or((value, None), |(main, fraction)| (main, Some(fraction)));
    let fraction_valid = fraction.is_none_or(|fraction| {
        (1..=9).contains(&fraction.len())
            && fraction.chars().all(|character| character.is_ascii_digit())
    });
    let parts = main
        .split(':')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>();
    fraction_valid
        && matches!(parts.as_deref(), Ok([hour, minute, second]) if *hour < 24 && *minute < 60 && *second < 60)
}

fn valid_decimal(value: &str) -> bool {
    let value = value.strip_prefix(['-', '+']).unwrap_or(value);
    let (mantissa, exponent) = value
        .split_once(['e', 'E'])
        .map_or((value, None), |(mantissa, exponent)| {
            (mantissa, Some(exponent))
        });
    let mantissa_valid = !mantissa.is_empty()
        && mantissa
            .chars()
            .filter(|character| *character == '.')
            .count()
            <= 1
        && mantissa.chars().any(|character| character.is_ascii_digit())
        && mantissa
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.');
    let exponent_valid = exponent.is_none_or(|exponent| {
        let exponent = exponent.strip_prefix(['-', '+']).unwrap_or(exponent);
        !exponent.is_empty() && exponent.chars().all(|character| character.is_ascii_digit())
    });
    mantissa_valid && exponent_valid
}

fn bind_parameters(
    statement: &mut Statement<'_>,
    parameters: &[(String, SqlValue)],
) -> Result<(), RdsDataError> {
    let supplied = parameters
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<HashSet<_>>();
    let mut required = HashSet::new();
    for index in 1..=statement.parameter_count() {
        let raw = statement
            .parameter_name(index)
            .ok_or(RdsDataError::BadRequest(
                "positional SQL placeholders are not supported",
            ))?;
        let name = raw.strip_prefix(':').ok_or(RdsDataError::BadRequest(
            "SQL parameters must use :name placeholders",
        ))?;
        required.insert(name);
    }
    if required != supplied {
        return Err(RdsDataError::BadRequest(
            "SQL parameters are missing or contain unused names",
        ));
    }
    for (name, value) in parameters {
        let index = statement
            .parameter_index(&format!(":{name}"))
            .map_err(|_| RdsDataError::Database("SQL parameters could not be inspected"))?
            .ok_or(RdsDataError::BadRequest("SQL parameter is unused"))?;
        statement
            .raw_bind_parameter(index, value)
            .map_err(|_| RdsDataError::Database("SQL parameters could not be bound"))?;
    }
    Ok(())
}

enum SavepointKind {
    Statement,
    Batch,
}

impl SavepointKind {
    fn release_sql(&self) -> &'static str {
        match self {
            Self::Statement => "RELEASE lc_statement",
            Self::Batch => "RELEASE lc_batch",
        }
    }

    fn recovery_sql(&self) -> &'static str {
        match self {
            Self::Statement => "ROLLBACK TO lc_statement; RELEASE lc_statement",
            Self::Batch => "ROLLBACK TO lc_batch; RELEASE lc_batch",
        }
    }

    fn release_error(&self) -> &'static str {
        match self {
            Self::Statement => {
                "statement savepoint could not finish and the transaction was closed"
            }
            Self::Batch => "batch savepoint could not finish and the transaction was closed",
        }
    }

    fn recovery_error(&self) -> &'static str {
        match self {
            Self::Statement => "statement recovery failed and the transaction was closed",
            Self::Batch => "batch recovery failed and the transaction was closed",
        }
    }
}

fn close_broken_transaction(holder: &mut Option<TrackedConnection>) {
    if let Some(connection) = holder.take() {
        let _ = connection.conn.execute_batch("ROLLBACK");
    }
}

fn finish_savepoint<T>(
    holder: &mut Option<TrackedConnection>,
    kind: SavepointKind,
    result: Result<T, RdsDataError>,
) -> Result<T, RdsDataError> {
    let connection = holder.as_ref().ok_or(RdsDataError::TransactionNotFound)?;
    match result {
        Ok(value) => {
            if connection.conn.execute_batch(kind.release_sql()).is_err() {
                close_broken_transaction(holder);
                return Err(RdsDataError::Database(kind.release_error()));
            }
            Ok(value)
        }
        Err(error) => {
            if connection.conn.execute_batch(kind.recovery_sql()).is_err() {
                close_broken_transaction(holder);
                return Err(RdsDataError::Database(kind.recovery_error()));
            }
            Err(error)
        }
    }
}

fn execute_statement(
    connection: &Connection,
    sql: &str,
    parameters: &[(String, SqlValue)],
    include_metadata: bool,
    options: ResultSetOptions,
    format: Option<FormatRecordsAs>,
    limits: &crate::RdsDataLimits,
) -> Result<Vec<u8>, RdsDataError> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|_| RdsDataError::Database("SQL statement could not be prepared"))?;
    bind_parameters(&mut statement, parameters)?;
    if statement.column_count() == 0 {
        if format.is_some() {
            return Err(RdsDataError::Unsupported(
                "formattedRecords requires a result set",
            ));
        }
        let updated = statement
            .raw_execute()
            .map_err(|_| RdsDataError::Database("SQL statement execution failed"))?;
        return serialize_bounded(
            &ExecuteResponse {
                column_metadata: None,
                number_of_records_updated: Some(updated as i64),
                records: None,
                formatted_records: None,
            },
            limits.response_bytes,
        );
    }
    let columns = statement
        .column_names()
        .into_iter()
        .map(|name| ColumnMetadata {
            label: name.to_owned(),
            name: name.to_owned(),
            type_name: None,
            r#type: None,
        })
        .collect::<Vec<_>>();
    let column_names = columns
        .iter()
        .map(|column| column.name.clone())
        .collect::<Vec<_>>();
    if format.is_some() && column_names.iter().collect::<HashSet<_>>().len() != column_names.len() {
        return Err(RdsDataError::Unsupported(
            "formattedRecords does not support duplicate column labels",
        ));
    }
    let mut rows = statement.raw_query();
    let mut records = Vec::new();
    let mut formatted = Vec::new();
    let budget = if format.is_some() {
        limits.formatted_records_bytes
    } else {
        limits.response_bytes
    };
    let mut used = serde_json::to_vec(&columns)
        .map_err(|_| RdsDataError::Internal)?
        .len();
    let mut row_count = 0;
    while let Some(row) = rows
        .next()
        .map_err(|_| RdsDataError::Database("SQL statement execution failed"))?
    {
        if row_count >= limits.max_rows {
            return Err(RdsDataError::Unsupported("result contains too many rows"));
        }
        row_count += 1;
        let mut record = Vec::with_capacity(column_names.len());
        let mut formatted_row = Map::new();
        for (index, name) in column_names.iter().enumerate() {
            let value = row
                .get_ref(index)
                .map_err(|_| RdsDataError::Unsupported("result value could not be converted"))?;
            ensure_result_value_fits(value, budget.saturating_sub(used))?;
            if format.is_some() {
                let value = value_ref_to_json(value, options)?;
                used = used
                    .checked_add(name.len() + serialized_len(&value)? + 8)
                    .ok_or(RdsDataError::Unsupported("result size overflow"))?;
                if used > budget {
                    return Err(RdsDataError::Unsupported(
                        "response exceeds the local result size limit",
                    ));
                }
                formatted_row.insert(name.clone(), value);
            } else {
                let value = value_ref_to_field(value, options)?;
                used = used
                    .checked_add(serialized_len(&value)? + 1)
                    .ok_or(RdsDataError::Unsupported("result size overflow"))?;
                if used > budget {
                    return Err(RdsDataError::Unsupported(
                        "response exceeds the local result size limit",
                    ));
                }
                record.push(value);
            }
        }
        if format.is_some() {
            formatted.push(Value::Object(formatted_row));
        } else {
            records.push(record);
        }
    }
    let formatted_records = if format == Some(FormatRecordsAs::Json) {
        let bytes = serde_json::to_vec(&formatted).map_err(|_| RdsDataError::Internal)?;
        if bytes.len() > limits.formatted_records_bytes {
            return Err(RdsDataError::Unsupported(
                "formattedRecords exceeds the 10 MiB limit",
            ));
        }
        Some(String::from_utf8(bytes).map_err(|_| RdsDataError::Internal)?)
    } else {
        None
    };
    let response = ExecuteResponse {
        column_metadata: include_metadata.then_some(columns),
        number_of_records_updated: Some(0),
        records: format.is_none().then_some(records),
        formatted_records,
    };
    serialize_bounded(
        &response,
        if format.is_some() {
            limits.formatted_records_bytes
        } else {
            limits.response_bytes
        },
    )
}

fn execute_batch(
    connection: &Connection,
    sql: &str,
    parameter_sets: &[Vec<(String, SqlValue)>],
    response_limit: usize,
) -> Result<Vec<u8>, RdsDataError> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|_| RdsDataError::Database("SQL statement could not be prepared"))?;
    if statement.column_count() != 0 {
        return Err(RdsDataError::Unsupported(
            "BatchExecuteStatement does not support result sets",
        ));
    }
    for parameters in parameter_sets {
        statement.clear_bindings();
        bind_parameters(&mut statement, parameters)?;
    }
    let mut update_results = Vec::with_capacity(parameter_sets.len());
    for parameters in parameter_sets {
        statement.clear_bindings();
        bind_parameters(&mut statement, parameters)?;
        statement
            .raw_execute()
            .map_err(|_| RdsDataError::Database("batch statement execution failed"))?;
        update_results.push(UpdateResult {});
    }
    serialize_bounded(&BatchResponse { update_results }, response_limit)
}

fn ensure_result_value_fits(value: ValueRef<'_>, remaining: usize) -> Result<(), RdsDataError> {
    let minimum = match value {
        ValueRef::Null | ValueRef::Integer(_) | ValueRef::Real(_) => 32,
        ValueRef::Text(value) => value.len(),
        ValueRef::Blob(value) => value
            .len()
            .checked_add(2)
            .and_then(|length| length.checked_div(3))
            .and_then(|length| length.checked_mul(4))
            .ok_or(RdsDataError::Unsupported("result size overflow"))?,
    };
    if minimum > remaining {
        return Err(RdsDataError::Unsupported(
            "response exceeds the local result size limit",
        ));
    }
    Ok(())
}

fn serialized_len(value: &Value) -> Result<usize, RdsDataError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|_| RdsDataError::Internal)
}

fn value_ref_to_field(
    value: ValueRef<'_>,
    options: ResultSetOptions,
) -> Result<Value, RdsDataError> {
    Ok(match value {
        ValueRef::Null => json!({ "isNull": true }),
        ValueRef::Integer(value) if options.long_return_type == LongReturnType::String => {
            json!({ "stringValue": value.to_string() })
        }
        ValueRef::Integer(value) => json!({ "longValue": value }),
        ValueRef::Real(value) if options.decimal_return_type == DecimalReturnType::String => {
            json!({ "stringValue": value.to_string() })
        }
        ValueRef::Real(value) if value.is_finite() => json!({ "doubleValue": value }),
        ValueRef::Real(_) => {
            return Err(RdsDataError::Unsupported(
                "non-finite floating-point results are unsupported",
            ))
        }
        ValueRef::Text(value) => json!({
            "stringValue": std::str::from_utf8(value)
                .map_err(|_| RdsDataError::Unsupported("result text is not UTF-8"))?
        }),
        ValueRef::Blob(value) => json!({ "blobValue": BASE64.encode(value) }),
    })
}

fn value_ref_to_json(
    value: ValueRef<'_>,
    options: ResultSetOptions,
) -> Result<Value, RdsDataError> {
    Ok(match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) if options.long_return_type == LongReturnType::String => {
            Value::String(value.to_string())
        }
        ValueRef::Integer(value) => Value::Number(value.into()),
        ValueRef::Real(value) if options.decimal_return_type == DecimalReturnType::String => {
            Value::String(value.to_string())
        }
        ValueRef::Real(value) => serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or(RdsDataError::Unsupported(
                "non-finite floating-point results are unsupported",
            ))?,
        ValueRef::Text(value) => Value::String(
            std::str::from_utf8(value)
                .map_err(|_| RdsDataError::Unsupported("result text is not UTF-8"))?
                .to_owned(),
        ),
        ValueRef::Blob(value) => Value::String(BASE64.encode(value)),
    })
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, RdsDataError> {
    serde_json::from_slice(body)
        .map_err(|_| RdsDataError::BadRequest("request body is not a valid operation shape"))
}

fn serialize_bounded<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, RdsDataError> {
    let bytes = serde_json::to_vec(value).map_err(|_| RdsDataError::Internal)?;
    if bytes.len() > limit {
        return Err(RdsDataError::Unsupported(
            "response exceeds the local result size limit",
        ));
    }
    Ok(bytes)
}

fn remove_sqlite_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    let path = path.to_string_lossy();
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Uri};
    use locallycloud_core::registry::{AwsProtocol, Disposition, ServiceName, ServiceRegistry};

    const ACCOUNT: &str = "123456789012";
    const REGION: &str = "us-east-1";
    const RESOURCE: &str = "arn:aws:rds:us-east-1:123456789012:cluster:test";
    const RESOURCE_TWO: &str = "arn:aws:rds:us-east-1:123456789012:cluster:other";
    const SECRET: &str = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test";

    fn test_config() -> RdsDataConfig {
        RdsDataConfig {
            state_root: std::env::temp_dir().join(format!("lc-rds-data-test-{}", Uuid::new_v4())),
            ..RdsDataConfig::default()
        }
    }

    fn handler() -> (RdsDataHandler, RdsDataHandle, PathBuf) {
        let config = test_config();
        let root = config.state_root.clone();
        let (handler, handle) = RdsDataHandler::new(config);
        (handler, handle, root)
    }

    fn request(path: &str, body: Value) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        ServiceRequest {
            method: Method::POST,
            uri: Uri::try_from(path).unwrap(),
            headers,
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
            region: REGION.into(),
            account_id: ACCOUNT.into(),
            request_id: "request-123".into(),
        }
    }

    fn scope_body(sql: &str) -> Value {
        json!({
            "resourceArn": RESOURCE,
            "secretArn": SECRET,
            "sql": sql
        })
    }

    async fn call(handler: &RdsDataHandler, path: &str, body: Value) -> (u16, HeaderMap, Value) {
        call_request(handler, request(path, body)).await
    }

    async fn call_request(
        handler: &RdsDataHandler,
        request: ServiceRequest,
    ) -> (u16, HeaderMap, Value) {
        let response = handler.handle(request).await;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 12 * 1024 * 1024)
            .await
            .unwrap();
        (status, headers, serde_json::from_slice(&body).unwrap())
    }

    fn assert_error(status: u16, headers: &HeaderMap, code: &str) {
        assert_ne!(status, 200);
        assert_eq!(headers.get("x-amzn-errortype").unwrap(), code);
        assert_eq!(headers.get("x-amzn-requestid").unwrap(), "request-123");
    }

    async fn execute_ok(handler: &RdsDataHandler, sql: &str) -> Value {
        let (status, headers, body) = call(handler, "/Execute", scope_body(sql)).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(headers.get("x-amzn-requestid").unwrap(), "request-123");
        body
    }

    async fn begin(handler: &RdsDataHandler) -> String {
        let (status, _, body) = call(
            handler,
            "/BeginTransaction",
            json!({ "resourceArn": RESOURCE, "secretArn": SECRET }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        body["transactionId"].as_str().unwrap().to_owned()
    }

    async fn finalize(
        handler: &RdsDataHandler,
        path: &str,
        transaction_id: &str,
        resource: &str,
    ) -> (u16, HeaderMap, Value) {
        call(
            handler,
            path,
            json!({
                "resourceArn": resource,
                "secretArn": SECRET,
                "transactionId": transaction_id
            }),
        )
        .await
    }

    #[tokio::test]
    async fn routes_are_exact_post_without_query_or_target() {
        let (handler, handle, root) = handler();
        let mut get = request("/Execute", scope_body("SELECT 1"));
        get.method = Method::GET;
        let (status, headers, _) = call_request(&handler, get).await;
        assert_error(status, &headers, "BadRequestException");

        let (status, headers, _) = call(&handler, "/Execute?x=1", scope_body("SELECT 1")).await;
        assert_error(status, &headers, "BadRequestException");
        let (status, headers, _) = call(&handler, "/execute", scope_body("SELECT 1")).await;
        assert_error(status, &headers, "BadRequestException");

        let mut targeted = request("/Execute", scope_body("SELECT 1"));
        targeted.headers.insert(
            "x-amz-target",
            HeaderValue::from_static("RDSData.ExecuteStatement"),
        );
        let (status, headers, _) = call_request(&handler, targeted).await;
        assert_error(status, &headers, "BadRequestException");
        assert_eq!(handle.statistics(), RdsDataStats::default());
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn none_format_returns_normal_records() {
        let (handler, _, root) = handler();
        let mut body = scope_body("SELECT 1 AS value");
        body["formatRecordsAs"] = json!("NONE");
        let (status, _, response) = call(&handler, "/Execute", body).await;
        assert_eq!(status, 200, "{response}");
        assert_eq!(response["records"][0][0]["longValue"], 1);
        assert!(response.get("formattedRecords").is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn field_union_and_arrays_are_rejected_before_store_creation() {
        let (handler, handle, root) = handler();
        for value in [
            json!({ "longValue": 1, "stringValue": "x" }),
            json!({}),
            json!({ "isNull": false }),
            json!({ "arrayValue": { "longValues": [1] } }),
        ] {
            let mut body = scope_body("SELECT :v");
            body["parameters"] = json!([{ "name": "v", "value": value }]);
            let (status, headers, _) = call(&handler, "/Execute", body).await;
            let code = headers.get("x-amzn-errortype").unwrap().to_str().unwrap();
            assert!(matches!(
                code,
                "BadRequestException" | "UnsupportedResultException"
            ));
            assert_ne!(status, 200);
        }
        assert_eq!(handle.statistics().stores, 0);
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn arn_scope_is_structural_and_matches_request_identity() {
        let (handler, _, root) = handler();
        let mut body = scope_body("SELECT 1");
        body["resourceArn"] = json!("arn:aws:rds:eu-west-1:123456789012:cluster:test");
        let (status, headers, _) = call(&handler, "/Execute", body).await;
        assert_error(status, &headers, "BadRequestException");

        let mut wrong_account = request("/Execute", scope_body("SELECT 1"));
        wrong_account.account_id = "999999999999".into();
        let (status, headers, _) = call_request(&handler, wrong_account).await;
        assert_error(status, &headers, "BadRequestException");
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn errors_do_not_mutate_and_parameters_are_exact() {
        let (handler, _, root) = handler();
        execute_ok(&handler, "CREATE TABLE items(v INTEGER)").await;
        let body = scope_body("INSERT INTO items(v) VALUES(:v)");
        let (status, headers, _) = call(&handler, "/Execute", body).await;
        assert_error(status, &headers, "BadRequestException");

        let (status, headers, _) = call(
            &handler,
            "/Execute",
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "INSERT INTO items(v) VALUES(?1)",
                "parameters": [{ "name": "v", "value": { "longValue": 1 } }]
            }),
        )
        .await;
        assert_error(status, &headers, "BadRequestException");

        let result = execute_ok(&handler, "SELECT count(*) AS n FROM items").await;
        assert_eq!(result["records"][0][0]["longValue"], 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn execute_binds_strings_and_blobs_without_interpolation() {
        let (handler, _, root) = handler();
        execute_ok(
            &handler,
            "CREATE TABLE values_test(id INTEGER, text_value TEXT, blob_value BLOB)",
        )
        .await;
        let payload = BASE64.encode([0, 1, 2, 255]);
        let (status, _, body) = call(
            &handler,
            "/Execute",
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "INSERT INTO values_test VALUES(:id, :text, :blob)",
                "parameters": [
                    { "name": "id", "value": { "longValue": 7 } },
                    { "name": "text", "value": { "stringValue": "x'); DROP TABLE values_test; --" } },
                    { "name": "blob", "value": { "blobValue": payload } }
                ]
            }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let result = execute_ok(
            &handler,
            "SELECT id, text_value, blob_value FROM values_test",
        )
        .await;
        assert_eq!(result["records"][0][0]["longValue"], 7);
        assert_eq!(
            result["records"][0][1]["stringValue"],
            "x'); DROP TABLE values_test; --"
        );
        assert_eq!(result["records"][0][2]["blobValue"], payload);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn scopes_have_isolated_sqlite_files() {
        let (handler, handle, root) = handler();
        execute_ok(&handler, "CREATE TABLE isolated(v TEXT)").await;
        execute_ok(&handler, "INSERT INTO isolated VALUES('first')").await;
        let (status, _, body) = call(
            &handler,
            "/Execute",
            json!({
                "resourceArn": RESOURCE_TWO,
                "secretArn": SECRET,
                "sql": "CREATE TABLE isolated(v TEXT)"
            }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (status, _, body) = call(
            &handler,
            "/Execute",
            json!({
                "resourceArn": RESOURCE_TWO,
                "secretArn": SECRET,
                "sql": "SELECT count(*) AS n FROM isolated"
            }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["records"][0][0]["longValue"], 0);
        assert_eq!(handle.statistics().stores, 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn batch_failure_rolls_back_every_item() {
        let (handler, _, root) = handler();
        execute_ok(&handler, "CREATE TABLE batch_items(v INTEGER UNIQUE)").await;
        let (status, headers, _) = call(
            &handler,
            "/BatchExecute",
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "INSERT INTO batch_items(v) VALUES(:v)",
                "parameterSets": [
                    [{ "name": "v", "value": { "longValue": 1 } }],
                    [{ "name": "v", "value": { "longValue": 1 } }]
                ]
            }),
        )
        .await;
        assert_error(status, &headers, "DatabaseErrorException");
        let result = execute_ok(&handler, "SELECT count(*) AS n FROM batch_items").await;
        assert_eq!(result["records"][0][0]["longValue"], 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn transactions_commit_rollback_repeat_and_reject_wrong_scope() {
        let (handler, handle, root) = handler();
        execute_ok(&handler, "CREATE TABLE tx_items(v INTEGER)").await;

        let transaction_id = begin(&handler).await;
        let (status, _, body) = call(
            &handler,
            "/Execute",
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "INSERT INTO tx_items VALUES(1)",
                "transactionId": transaction_id
            }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (status, headers, _) = finalize(
            &handler,
            "/CommitTransaction",
            &transaction_id,
            RESOURCE_TWO,
        )
        .await;
        assert_error(status, &headers, "TransactionNotFoundException");
        let (status, _, body) =
            finalize(&handler, "/CommitTransaction", &transaction_id, RESOURCE).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["transactionStatus"], "Transaction Committed");
        let (status, headers, _) =
            finalize(&handler, "/CommitTransaction", &transaction_id, RESOURCE).await;
        assert_error(status, &headers, "TransactionNotFoundException");

        let rollback_id = begin(&handler).await;
        let (status, _, body) = call(
            &handler,
            "/Execute",
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "INSERT INTO tx_items VALUES(2)",
                "transactionId": rollback_id
            }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (status, _, body) =
            finalize(&handler, "/RollbackTransaction", &rollback_id, RESOURCE).await;
        assert_eq!(status, 200, "{body}");
        let result = execute_ok(&handler, "SELECT sum(v) AS total FROM tx_items").await;
        assert_eq!(result["records"][0][0]["longValue"], 1);
        assert_eq!(handle.statistics().transactions, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn response_overflow_rolls_back_mutation() {
        let (handler, _, root) = handler();
        execute_ok(&handler, "CREATE TABLE large_results(v BLOB)").await;
        let (status, headers, _) = call(
            &handler,
            "/Execute",
            scope_body("INSERT INTO large_results(v) VALUES(zeroblob(1048576)) RETURNING v"),
        )
        .await;
        assert_error(status, &headers, "UnsupportedResultException");
        let result = execute_ok(&handler, "SELECT count(*) AS n FROM large_results").await;
        assert_eq!(result["records"][0][0]["longValue"], 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn registration_is_native_rest_json_and_zero_idle() {
        let registry = ServiceRegistry::with_known_services();
        let config = test_config();
        let root = config.state_root.clone();
        let handle = crate::register_with_config(&registry, config).unwrap();
        let entry = registry.lookup(&ServiceName::new("rds-data")).unwrap();
        assert_eq!(entry.disposition, Disposition::Native);
        assert_eq!(entry.metadata.protocol, AwsProtocol::RestJson);
        assert!(entry.metadata.target_prefix.is_none());
        assert!(entry.handler.is_some());
        assert_eq!(handle.statistics(), RdsDataStats::default());
        assert!(handle
            .state
            .reaper
            .lock()
            .expect("reaper lock")
            .tasks
            .is_empty());
        assert!(!root.exists());
        handle.shutdown().await;
        assert_eq!(handle.statistics(), RdsDataStats::default());
    }

    #[tokio::test]
    async fn rejects_multiple_statements_without_publishing_a_store() {
        let (handler, handle, root) = handler();
        let (status, headers, _) = call(
            &handler,
            "/Execute",
            scope_body("CREATE TABLE first(v); CREATE TABLE second(v)"),
        )
        .await;
        assert_error(status, &headers, "DatabaseErrorException");
        assert_eq!(handle.statistics().stores, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn first_invalid_bindings_do_not_publish_or_accumulate_scopes() {
        let (handler, handle, root) = handler();
        let invalid_requests = [
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "SELECT :v"
            }),
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "SELECT ?1",
                "parameters": [{ "name": "v", "value": { "longValue": 1 } }]
            }),
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "SELECT 1",
                "parameters": [{ "name": "v", "value": { "longValue": 1 } }]
            }),
        ];
        for body in invalid_requests {
            let (status, headers, _) = call(&handler, "/Execute", body).await;
            assert_error(status, &headers, "BadRequestException");
        }
        let scope = Scope::new(ACCOUNT, REGION, RESOURCE, SECRET, None, None).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let existing_path = root.join(scope.digest()).with_extension("sqlite3");
        let existing = Connection::open(&existing_path).unwrap();
        existing
            .execute_batch("CREATE TABLE staged_batch(v INTEGER)")
            .unwrap();
        drop(existing);
        let (status, headers, _) = call(
            &handler,
            "/BatchExecute",
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "INSERT INTO staged_batch(v) VALUES(:v)",
                "parameterSets": [
                    [{ "name": "v", "value": { "longValue": 1 } }],
                    [{ "name": "extra", "value": { "longValue": 2 } }]
                ]
            }),
        )
        .await;
        assert_error(status, &headers, "BadRequestException");
        for index in 0..8 {
            let resource =
                format!("arn:aws:rds:{REGION}:{ACCOUNT}:cluster:invalid-binding-{index}");
            let (status, headers, _) = call(
                &handler,
                "/Execute",
                json!({
                    "resourceArn": resource,
                    "secretArn": SECRET,
                    "sql": "SELECT :v"
                }),
            )
            .await;
            assert_error(status, &headers, "BadRequestException");
        }
        assert_eq!(handle.statistics().stores, 0);
        assert_eq!(handle.statistics().open_connections, 0);
        assert!(handler.state.slots.lock().expect("slots lock").is_empty());
        assert!(handler
            .state
            .identities
            .lock()
            .expect("identities lock")
            .is_empty());
        let existing = Connection::open(&existing_path).unwrap();
        let count: i64 = existing
            .query_row("SELECT count(*) FROM staged_batch", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        drop(existing);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn transaction_batch_failure_rolls_back_to_savepoint() {
        let (handler, _, root) = handler();
        execute_ok(&handler, "CREATE TABLE tx_batch(v INTEGER UNIQUE)").await;
        let transaction_id = begin(&handler).await;
        let (status, _, body) = call(
            &handler,
            "/Execute",
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "INSERT INTO tx_batch VALUES(9)",
                "transactionId": transaction_id
            }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (status, headers, _) = call(
            &handler,
            "/BatchExecute",
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "INSERT INTO tx_batch VALUES(:v)",
                "transactionId": transaction_id,
                "parameterSets": [
                    [{ "name": "v", "value": { "longValue": 10 } }],
                    [{ "name": "v", "value": { "longValue": 10 } }]
                ]
            }),
        )
        .await;
        assert_error(status, &headers, "DatabaseErrorException");
        let (status, _, body) = call(
            &handler,
            "/Execute",
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "SELECT sum(v) AS total FROM tx_batch",
                "transactionId": transaction_id
            }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["records"][0][0]["longValue"], 9);
        let (status, _, _) =
            finalize(&handler, "/CommitTransaction", &transaction_id, RESOURCE).await;
        assert_eq!(status, 200);
        let result = execute_ok(&handler, "SELECT sum(v) AS total FROM tx_batch").await;
        assert_eq!(result["records"][0][0]["longValue"], 9);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn transaction_sql_cannot_bypass_service_finalization() {
        let (handler, _, root) = handler();
        execute_ok(&handler, "CREATE TABLE controlled(v INTEGER)").await;
        let transaction_id = begin(&handler).await;
        let (status, _, body) = call(
            &handler,
            "/Execute",
            json!({
                "resourceArn": RESOURCE,
                "secretArn": SECRET,
                "sql": "INSERT INTO controlled VALUES(1)",
                "transactionId": transaction_id
            }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        for sql in ["COMMIT", "/* hidden */ ROLLBACK", "SAVEPOINT lc_statement"] {
            let (status, headers, _) = call(
                &handler,
                "/Execute",
                json!({
                    "resourceArn": RESOURCE,
                    "secretArn": SECRET,
                    "sql": sql,
                    "transactionId": transaction_id
                }),
            )
            .await;
            assert_error(status, &headers, "BadRequestException");
        }
        let (status, _, _) =
            finalize(&handler, "/RollbackTransaction", &transaction_id, RESOURCE).await;
        assert_eq!(status, 200);
        let result = execute_ok(&handler, "SELECT count(*) AS n FROM controlled").await;
        assert_eq!(result["records"][0][0]["longValue"], 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn shutdown_waits_for_an_admitted_begin_before_draining() {
        let mut config = test_config();
        config.limits.max_blocking_operations = 1;
        let root = config.state_root.clone();
        let (handler, handle) = RdsDataHandler::new(config);
        let handler = Arc::new(handler);
        let state = handler.state.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::spawn(async move {
            state
                .run_blocking(move || {
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();

        let begin_handler = handler.clone();
        let begin_task = tokio::spawn(async move { begin(&begin_handler).await });
        for _ in 0..100 {
            if handler.state.admitted_requests.load(Ordering::Acquire) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(handler.state.admitted_requests.load(Ordering::Acquire), 1);

        let shutdown_handle = handle.clone();
        let shutdown_task = tokio::spawn(async move { shutdown_handle.shutdown().await });
        for _ in 0..100 {
            if handle.state.shutdown.load(Ordering::Acquire) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(handle.state.shutdown.load(Ordering::Acquire));
        let second_shutdown_handle = handle.clone();
        let second_shutdown = tokio::spawn(async move { second_shutdown_handle.shutdown().await });
        tokio::task::yield_now().await;
        assert!(!second_shutdown.is_finished());
        release_tx.send(()).unwrap();
        blocker.await.unwrap().unwrap();
        let _ = begin_task.await.unwrap();
        shutdown_task.await.unwrap();
        second_shutdown.await.unwrap();

        assert_eq!(handle.statistics(), RdsDataStats::default());
        assert_eq!(handler.state.admitted_requests.load(Ordering::Acquire), 0);
        assert!(handle
            .state
            .reaper
            .lock()
            .expect("reaper lock")
            .tasks
            .is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn cancelled_waiter_keeps_blocking_permit_until_work_finishes() {
        let (handler, handle, _) = handler();
        let state = handler.state.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            state
                .run_blocking(move || {
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        task.abort();
        tokio::task::yield_now().await;
        assert_eq!(handle.statistics().blocking_operations, 1);
        release_tx.send(()).unwrap();
        for _ in 0..100 {
            if handle.statistics().blocking_operations == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(handle.statistics().blocking_operations, 0);
    }

    #[test]
    fn release_failure_closes_the_transaction_holder() {
        let counters = Arc::new(Counters::default());
        counters.open_connections.store(1, Ordering::Release);
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("BEGIN").unwrap();
        let mut holder = Some(TrackedConnection {
            conn: connection,
            counters: counters.clone(),
        });

        let result = finish_savepoint(
            &mut holder,
            SavepointKind::Statement,
            Ok::<_, RdsDataError>(()),
        );

        assert!(matches!(result, Err(RdsDataError::Database(_))));
        assert!(holder.is_none());
        assert_eq!(counters.open_connections.load(Ordering::Acquire), 0);
    }

    #[test]
    fn unsupported_identity_mode_is_rejected_before_registration() {
        let registry = ServiceRegistry::with_known_services();
        let mut config = test_config();
        config.identity_mode = crate::IdentityMode::SecretsValidation;
        assert!(crate::register_with_config(&registry, config).is_err());
        let entry = registry.lookup(&ServiceName::new("rds-data")).unwrap();
        assert_eq!(entry.disposition, Disposition::Proxied);
        assert!(entry.handler.is_none());
    }

    #[tokio::test]
    async fn finalizing_last_transaction_stops_reaper_promptly() {
        let mut config = test_config();
        let root = config.state_root.clone();
        config.transaction_idle_timeout = Duration::from_secs(10);
        config.transaction_absolute_timeout = Duration::from_secs(20);
        let (handler, handle) = RdsDataHandler::new(config);
        let transaction_id = begin(&handler).await;
        let (status, _, _) =
            finalize(&handler, "/RollbackTransaction", &transaction_id, RESOURCE).await;
        assert_eq!(status, 200);

        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if !handle.state.reaper.lock().expect("reaper lock").running {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("transaction reaper did not stop after finalization");

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn active_transaction_is_not_reaped_by_idle_timeout() {
        let mut config = test_config();
        let root = config.state_root.clone();
        config.transaction_idle_timeout = Duration::from_millis(50);
        config.transaction_absolute_timeout = Duration::from_secs(1);
        let (handler, handle) = RdsDataHandler::new(config);
        let transaction_id = begin(&handler).await;
        let record = handler
            .state
            .transactions
            .lock()
            .expect("transactions lock")
            .get(&transaction_id)
            .cloned()
            .unwrap();
        let operation = record.operation_lock.lock().await;

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(handle.statistics().transactions, 1);
        *record.last_activity.lock().expect("activity lock") = Instant::now();
        drop(operation);
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(handle.statistics().transactions, 1);

        let (status, _, _) =
            finalize(&handler, "/RollbackTransaction", &transaction_id, RESOURCE).await;
        assert_eq!(status, 200);
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn inactive_transaction_is_reaped_without_another_request() {
        let mut config = test_config();
        let root = config.state_root.clone();
        config.transaction_idle_timeout = Duration::from_millis(10);
        config.transaction_absolute_timeout = Duration::from_secs(1);
        let (handler, handle) = RdsDataHandler::new(config);
        let _transaction_id = begin(&handler).await;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let stats = handle.statistics();
                if stats.transactions == 0 && stats.open_connections == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("transaction reaper timed out");
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let stopped = {
                    let reaper = handle.state.reaper.lock().expect("reaper lock");
                    !reaper.running && reaper.tasks.iter().all(JoinHandle::is_finished)
                };
                if stopped {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("transaction reaper did not stop after expiring the last transaction");

        let _second_transaction_id = begin(&handler).await;
        assert!(handle.state.reaper.lock().expect("reaper lock").running);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let stats = handle.statistics();
                if stats.transactions == 0 && stats.open_connections == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("restarted transaction reaper timed out");

        handle.shutdown().await;
        assert_eq!(handle.statistics(), RdsDataStats::default());
        assert!(handle
            .state
            .reaper
            .lock()
            .expect("reaper lock")
            .tasks
            .is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn expired_transaction_is_rolled_back_on_finalize_access() {
        let mut config = test_config();
        let root = config.state_root.clone();
        config.transaction_idle_timeout = std::time::Duration::from_millis(1);
        config.transaction_absolute_timeout = std::time::Duration::from_secs(1);
        let (handler, handle) = RdsDataHandler::new(config);
        let transaction_id = begin(&handler).await;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let (status, headers, _) =
            finalize(&handler, "/CommitTransaction", &transaction_id, RESOURCE).await;
        assert_error(status, &headers, "TransactionNotFoundException");
        assert_eq!(handle.statistics().transactions, 0);
        let _ = std::fs::remove_dir_all(root);
    }
}
