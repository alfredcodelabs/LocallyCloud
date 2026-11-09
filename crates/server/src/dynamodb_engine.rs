//! Lazy, private ExtendDB workers. Only the LocalCloud front door authorizes clients.
mod table_storage;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use table_storage::{TableCall, TableStorage};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_dynamodb::error::DdbError;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::{component_catalog, component_manager};

const FRAME_LIMIT: usize = 32 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_WORKERS: usize = 4;
type Reply = Result<(u16, Value), String>;
type WorkerScope = (String, String, Option<uuid::Uuid>);

pub fn bind_store(state: &locallycloud_state::StateDb, engine: &str) -> io::Result<()> {
    crate::dynamodb_migration::ensure_no_pending(state.path())?;
    let connection = state.connection().map_err(io::Error::other)?;
    connection.execute_batch("CREATE TABLE IF NOT EXISTS locallycloud_service_engines (service TEXT PRIMARY KEY, engine TEXT NOT NULL)")
        .map_err(io::Error::other)?;
    let mut statement = connection
        .prepare("SELECT engine FROM locallycloud_service_engines WHERE service='dynamodb'")
        .map_err(io::Error::other)?;
    let mut rows = statement.query([]).map_err(io::Error::other)?;
    let selected = rows
        .next()
        .map_err(io::Error::other)?
        .map(|row| row.get::<_, String>(0))
        .transpose()
        .map_err(io::Error::other)?;
    drop(rows);
    drop(statement);
    if let Some(selected) = selected {
        if selected != engine {
            return Err(io::Error::other("DynamoDB engine differs from this state's engine; keep the original engine or use a fresh state database. migrate-dynamodb --dry-run inspects native state; use migrate-dynamodb --apply for a supported offline cutover"));
        }
        return Ok(());
    }
    let native_schema: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='dynamodb_tables')", [], |row| row.get(0)).map_err(io::Error::other)?;
    if engine == "extenddb" && native_schema {
        let populated: bool = connection
            .query_row("SELECT EXISTS(SELECT 1 FROM dynamodb_tables)", [], |row| {
                row.get(0)
            })
            .map_err(io::Error::other)?;
        if populated {
            return Err(io::Error::other(
                "native DynamoDB tables exist; keep the native engine or use a fresh state database. migrate-dynamodb --dry-run inspects state; use migrate-dynamodb --apply for a supported offline cutover",
            ));
        }
    }
    connection
        .execute(
            "INSERT INTO locallycloud_service_engines(service,engine) VALUES('dynamodb',?1)",
            [engine],
        )
        .map_err(io::Error::other)?;
    Ok(())
}

struct WorkerBudget {
    slots: Arc<Semaphore>,
    waiting: watch::Sender<usize>,
}

struct WaitingWorker<'a>(&'a watch::Sender<usize>);

impl Drop for WaitingWorker<'_> {
    fn drop(&mut self) {
        self.0.send_modify(|count| *count = count.saturating_sub(1));
    }
}

impl WorkerBudget {
    fn new(limit: usize) -> Arc<Self> {
        let (waiting, _) = watch::channel(0);
        Arc::new(Self {
            slots: Arc::new(Semaphore::new(limit)),
            waiting,
        })
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        if let Ok(slot) = self.slots.clone().try_acquire_owned() {
            return Ok(slot);
        }
        self.waiting
            .send_modify(|count| *count = count.saturating_add(1));
        let waiting = WaitingWorker(&self.waiting);
        let slot = self.slots.clone().acquire_owned().await;
        drop(waiting);
        slot
    }
}

struct Request {
    operation: String,
    body: Value,
    reply: oneshot::Sender<Reply>,
    deadline: tokio::time::Instant,
    table: Option<TableCall>,
}

pub struct ExtendDb {
    pool: Arc<WorkerPool>,
    coordinator: Arc<crate::dynamodb_replication::Coordinator>,
}

impl ExtendDb {
    pub async fn new(
        state: Arc<locallycloud_state::StateDb>,
        registry: std::sync::Weak<locallycloud_core::registry::ServiceRegistry>,
    ) -> io::Result<Self> {
        let notifier = crate::dynamodb_replication::RelayNotifier::new();
        let mut pool = WorkerPool::new(&state, notifier.clone())?;
        pool.table_storage = Some(TableStorage::new(state.clone(), registry));
        let pool = Arc::new(pool);
        let coordinator =
            crate::dynamodb_replication::Coordinator::new(pool.clone(), state, notifier).await?;
        Ok(Self { pool, coordinator })
    }
    pub fn resume(&self) {
        self.coordinator.resume();
    }
    pub async fn shutdown(&self) {
        self.coordinator.shutdown().await;
        self.pool.shutdown().await;
    }
}

#[async_trait]
impl NativeHandler for ExtendDb {
    async fn handle(&self, request: ServiceRequest) -> Response {
        self.coordinator.handle(request).await
    }
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        self.pool.resource_regions(account).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerMode {
    Normal,
    Migration,
}

impl WorkerMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Migration => "migration",
        }
    }
}

#[derive(Clone)]
struct WorkerLaunch {
    components: PathBuf,
    mode: WorkerMode,
}

pub(crate) struct WorkerPool {
    launch: WorkerLaunch,
    data: PathBuf,
    key: Arc<Zeroizing<String>>,
    workers: Mutex<HashMap<WorkerScope, WorkerTask>>,
    table_storage: Option<Arc<TableStorage>>,
    closing: AtomicBool,
    notifier: Arc<crate::dynamodb_replication::RelayNotifier>,
    budget: Arc<WorkerBudget>,
}

struct WorkerTask {
    sender: mpsc::Sender<Request>,
    task: tokio::task::JoinHandle<()>,
}

impl WorkerPool {
    async fn stream_position(
        &self,
        account: &str,
        region: &str,
        token: &str,
    ) -> Result<Value, DdbError> {
        if account.len() != 12
            || !account.bytes().all(|b| b.is_ascii_digit())
            || !(3..=64).contains(&region.len())
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(DdbError::Validation("invalid stream scope".into()));
        }
        let (status, body) = self
            .query(
                account,
                region,
                "__locallycloud_resolve_stream_iterator".into(),
                json!({"ShardIterator":token}),
            )
            .await
            .map_err(DdbError::Internal)?;
        match status {
            200 => Ok(body),
            400 if body
                .get("__type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.ends_with("ExpiredIteratorException")) =>
            {
                Err(DdbError::ExpiredIterator(
                    "Shard iterator has expired".into(),
                ))
            }
            400 => Err(DdbError::Validation("Invalid ShardIterator".into())),
            _ => Err(DdbError::Internal(
                "could not resolve stream iterator".into(),
            )),
        }
    }

    pub async fn shutdown(&self) {
        self.closing.store(true, Ordering::Release);
        let workers = match self.workers.lock() {
            Ok(mut workers) => workers
                .drain()
                .map(|(_, worker)| worker)
                .collect::<Vec<_>>(),
            Err(_) => return,
        };
        for WorkerTask { sender, mut task } in workers {
            drop(sender);
            if tokio::time::timeout(REQUEST_TIMEOUT + Duration::from_secs(5), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
    }

    pub(crate) async fn query(
        &self,
        account: &str,
        region: &str,
        operation: String,
        body: Value,
    ) -> Reply {
        self.query_for(account, region, operation, body, None).await
    }

    pub(crate) async fn query_external(
        &self,
        request: &ServiceRequest,
        operation: String,
        body: Value,
    ) -> Reply {
        self.query_for(
            &request.account_id,
            &request.region,
            operation,
            body,
            Some(request),
        )
        .await
    }

    async fn query_for(
        &self,
        account: &str,
        region: &str,
        operation: String,
        body: Value,
        request: Option<&ServiceRequest>,
    ) -> Reply {
        let table = match &self.table_storage {
            Some(storage) => match storage
                .resolve(account, region, &operation, &body, request)
                .await
            {
                Ok(table) => table,
                Err(error) => return error_reply(error).await,
            },
            None => None,
        };
        let Some(table) = table else {
            return self.query_regional(account, region, operation, body).await;
        };
        let sender = match self.worker(account, region, Some(&table)) {
            Ok(sender) => sender,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return error_reply(DdbError::Throttling(error.to_string())).await
            }
            Err(error) => return Err(error.to_string()),
        };
        self.enqueue(sender, operation, body, Some(table)).await
    }

    async fn enqueue(
        &self,
        sender: mpsc::Sender<Request>,
        operation: String,
        body: Value,
        table: Option<TableCall>,
    ) -> Reply {
        let (reply, response) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        match sender.try_send(Request {
            operation,
            body,
            reply,
            deadline,
            table,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                return error_reply(DdbError::Throttling(
                    "ExtendDB worker is busy; retry later".into(),
                ))
                .await
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err("ExtendDB worker stopped".into())
            }
        }
        tokio::time::timeout_at(deadline + Duration::from_secs(5), response)
            .await
            .map_err(|_| "ExtendDB queue wait timed out")?
            .map_err(|_| "ExtendDB worker stopped")?
    }

    async fn query_regional(
        &self,
        account: &str,
        region: &str,
        operation: String,
        body: Value,
    ) -> Reply {
        if operation == "UpdateTable" && body.get("SSESpecification").is_some() {
            let (status, description) = self
                .query_raw(
                    account,
                    region,
                    "DescribeTable".into(),
                    json!({"TableName":body.get("TableName")}),
                )
                .await?;
            if status != 200 {
                return Ok((status, description));
            }
            let description = match owned_encryption_description(description) {
                Ok(description) => description,
                Err(error) => return error_reply(error).await,
            };
            if body.as_object().is_some_and(|body| body.len() == 2) {
                return Ok((200, description));
            }
        }
        self.query_raw(account, region, operation, body).await
    }

    async fn query_raw(
        &self,
        account: &str,
        region: &str,
        operation: String,
        body: Value,
    ) -> Reply {
        let sender = self
            .worker(account, region, None)
            .map_err(|e| e.to_string())?;
        self.enqueue(sender, operation, body, None).await
    }

    pub fn new(
        state: &locallycloud_state::StateDb,
        notifier: Arc<crate::dynamodb_replication::RelayNotifier>,
    ) -> io::Result<Self> {
        let mut data = state.path().as_os_str().to_owned();
        data.push(".extenddb");
        Self::in_directory(PathBuf::from(data), notifier)
    }

    pub(crate) fn in_directory(
        data: PathBuf,
        notifier: Arc<crate::dynamodb_replication::RelayNotifier>,
    ) -> io::Result<Self> {
        Self::with_mode(data, notifier, WorkerMode::Normal)
    }

    pub(crate) fn for_migration(
        data: PathBuf,
        notifier: Arc<crate::dynamodb_replication::RelayNotifier>,
    ) -> io::Result<Self> {
        Self::with_mode(data, notifier, WorkerMode::Migration)
    }

    fn with_mode(
        data: PathBuf,
        notifier: Arc<crate::dynamodb_replication::RelayNotifier>,
        mode: WorkerMode,
    ) -> io::Result<Self> {
        let key = std::env::var("LOCALLYCLOUD_KMS_MASTER_KEY")
            .map_err(|_| io::Error::other("LOCALLYCLOUD_KMS_MASTER_KEY is required"))?;
        // Validate before ever passing key material to the private worker.
        locallycloud_state::StateCipher::from_env().map_err(io::Error::other)?;
        Ok(Self {
            launch: WorkerLaunch {
                components: component_manager::directory()?,
                mode,
            },
            data,
            key: Arc::new(Zeroizing::new(key)),
            workers: Mutex::new(HashMap::new()),
            table_storage: None,
            closing: AtomicBool::new(false),
            notifier,
            budget: WorkerBudget::new(MAX_WORKERS),
        })
    }

    fn worker(
        &self,
        account: &str,
        region: &str,
        table: Option<&TableCall>,
    ) -> io::Result<mpsc::Sender<Request>> {
        let scope = (
            account.to_string(),
            region.to_string(),
            table.map(|t| t.record.scope().storage_id()),
        );
        let mut workers = self
            .workers
            .lock()
            .map_err(|_| io::Error::other("worker registry unavailable"))?;
        if self.closing.load(Ordering::Acquire) {
            return Err(io::Error::other("ExtendDB is shutting down"));
        }
        workers.retain(|_, worker| !worker.sender.is_closed());
        if let Some(worker) = workers.get(&scope) {
            return Ok(worker.sender.clone());
        }
        if workers.len() >= MAX_WORKERS * 2 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "ExtendDB worker capacity reached; retry after idle workers stop",
            ));
        }
        let (sender, receiver) = mpsc::channel(8);
        let database = match table {
            Some(table) => self
                .data
                .join(account)
                .join(region)
                .join(table.record.file_name()),
            None => self.data.join(account).join(format!("{region}.sqlite3")),
        };
        let task = tokio::spawn(serve_worker(
            self.launch.clone(),
            database,
            (scope.0.clone(), scope.1.clone()),
            self.key.clone(),
            self.budget.clone(),
            self.notifier.clone(),
            receiver,
        ));
        workers.insert(
            scope,
            WorkerTask {
                sender: sender.clone(),
                task,
            },
        );
        Ok(sender)
    }
}

#[async_trait]
impl locallycloud_dynamodb::DynamoEngine for ExtendDb {
    fn supports_pitr(&self) -> bool {
        true
    }
    fn supports_owned_encryption(&self) -> bool {
        true
    }
    fn supports_backups(&self) -> bool {
        true
    }
    fn supports_mrec(&self) -> bool {
        true
    }
    async fn resolve_stream_iterator(
        &self,
        account: &str,
        region: &str,
        token: &str,
    ) -> Result<String, DdbError> {
        self.pool
            .stream_position(account, region, token)
            .await?
            .get("StreamArn")
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| DdbError::Internal("iterator resolver omitted stream ARN".into()))
    }

    async fn resolve_stream_sequence(
        &self,
        account: &str,
        region: &str,
        token: &str,
    ) -> Result<String, DdbError> {
        self.pool
            .stream_position(account, region, token)
            .await?
            .get("Sequence")
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| DdbError::Internal("iterator resolver omitted sequence".into()))
    }
}

struct Worker {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    _lease: std::fs::File,
    _slot: OwnedSemaphorePermit,
}

async fn frame(output: &mut BufReader<ChildStdout>) -> io::Result<Value> {
    let mut bytes = Vec::new();
    loop {
        let chunk = output.fill_buf().await?;
        if chunk.is_empty() {
            return Err(io::Error::other("ExtendDB worker closed its response pipe"));
        }
        let end = chunk.iter().position(|b| *b == b'\n').map(|n| n + 1);
        let count = end.unwrap_or(chunk.len());
        if bytes.len().saturating_add(count) > FRAME_LIMIT {
            return Err(io::Error::other("ExtendDB response exceeds frame limit"));
        }
        bytes.extend_from_slice(&chunk[..count]);
        output.consume(count);
        if end.is_some() {
            return serde_json::from_slice(&bytes).map_err(io::Error::other);
        }
    }
}

fn ready_for_mode(ready: &Value, mode: WorkerMode) -> bool {
    let Some(features) = ready.get("features").and_then(Value::as_array) else {
        return false;
    };
    ready.get("ready").and_then(Value::as_bool) == Some(true)
        && ready.get("version").and_then(Value::as_u64) == Some(1)
        && ready.get("mode").and_then(Value::as_str) == Some(mode.as_str())
        && component_catalog::REQUIRED_CAPABILITIES
            .iter()
            .all(|required| {
                features
                    .iter()
                    .any(|feature| feature.as_str() == Some(*required))
            })
        && (mode == WorkerMode::Normal
            || features
                .iter()
                .any(|feature| feature.as_str() == Some("migration-ttl-v1")))
}

#[derive(Serialize)]
struct TableBinding<'a> {
    table_name: &'a str,
    storage_id: String,
}

#[derive(Serialize)]
struct WorkerInitialize<'a> {
    version: u32,
    key: &'a str,
    database: &'a std::path::Path,
    account_id: &'a str,
    region: &'a str,
    mode: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    table_file: Option<&'a TableBinding<'a>>,
}

fn ready_for_table(ready: &Value, table: Option<&TableBinding<'_>>) -> bool {
    match table {
        None => ready.get("table_file").is_none_or(Value::is_null),
        Some(table) => {
            ready
                .get("features")
                .and_then(Value::as_array)
                .is_some_and(|features| features.iter().any(|v| v == "table-file-v1"))
                && ready["table_file"]["table_name"] == table.table_name
                && ready["table_file"]["storage_id"] == table.storage_id
        }
    }
}

impl Worker {
    async fn start(
        launch: WorkerLaunch,
        database: PathBuf,
        scope: &(String, String),
        key: &str,
        slot: OwnedSemaphorePermit,
        table: Option<&locallycloud_dynamodb::encryption::catalog::TableFileRecord>,
    ) -> io::Result<Self> {
        let WorkerLaunch { components, mode } = launch;
        let (_, executable, lease) =
            tokio::task::spawn_blocking(move || component_manager::verified(&components))
                .await
                .map_err(io::Error::other)??;
        let table_file = table.is_some();
        let existing_table = table.is_some_and(|t| {
            t.phase() == locallycloud_dynamodb::encryption::catalog::FilePhase::Active
        });
        let expected_database = database.clone();
        let parent = database
            .parent()
            .ok_or_else(|| io::Error::other("invalid database directory"))?
            .to_owned();
        tokio::task::spawn_blocking(move || {
            let data_root = parent
                .parent()
                .ok_or_else(|| io::Error::other("invalid data directory"))?;
            if table_file {
                if let Some(root) = data_root.parent() {
                    component_manager::private_directory(root)?;
                }
            }
            if existing_table {
                let metadata = std::fs::symlink_metadata(&expected_database).map_err(|_| {
                    io::Error::other("Encrypted table data file is missing or unsafe")
                })?;
                if !metadata.is_file() || metadata.len() == 0 {
                    return Err(io::Error::other(
                        "Encrypted table data file is missing or unsafe",
                    ));
                }
            }
            component_manager::private_directory(data_root)
                .and_then(|()| component_manager::private_directory(&parent))
                .map_err(|_| {
                    io::Error::other(
                        "ExtendDB data directory must be owned by the current user with mode 0700",
                    )
                })
        })
        .await
        .map_err(io::Error::other)??;
        use std::os::fd::AsRawFd;
        let executable_path = format!("/proc/{}/fd/{}", std::process::id(), executable.as_raw_fd());
        let mut child = Command::new(executable_path)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("worker stdin unavailable"))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("worker stdout unavailable"))?;
        let mut worker = Self {
            child,
            input,
            output: BufReader::new(output),
            _lease: lease,
            _slot: slot,
        };
        // Borrow key material: a temporary serde_json::Value would leave an unzeroized copy.
        let binding = table.map(|record| TableBinding {
            table_name: record.scope().table_name(),
            storage_id: record.scope().storage_id().to_string(),
        });
        let mut init = Zeroizing::new(
            serde_json::to_vec(&WorkerInitialize {
                version: 1,
                key,
                database: &database,
                account_id: &scope.0,
                region: &scope.1,
                mode: mode.as_str(),
                table_file: binding.as_ref(),
            })
            .map_err(io::Error::other)?,
        );
        init.push(b'\n');
        worker.input.write_all(&init).await?;
        worker.input.flush().await?;
        let ready = frame(&mut worker.output).await?;
        if !ready_for_mode(&ready, mode) || !ready_for_table(&ready, binding.as_ref()) {
            return Err(io::Error::other("ExtendDB worker handshake, mode, or table binding is incompatible; install a current worker"));
        }
        drop(executable);
        Ok(worker)
    }

    async fn request(&mut self, request: &Request) -> io::Result<(u16, Value)> {
        let mut bytes =
            serde_json::to_vec(&json!({"id":1,"operation":request.operation,"body":request.body}))
                .map_err(io::Error::other)?;
        if bytes.len() >= FRAME_LIMIT {
            return Err(io::Error::other("ExtendDB request exceeds frame limit"));
        }
        bytes.push(b'\n');
        self.input.write_all(&bytes).await?;
        self.input.flush().await?;
        let mut result = frame(&mut self.output).await?;
        let status = result
            .get("status")
            .and_then(Value::as_u64)
            .filter(|s| (200..=599).contains(s))
            .ok_or_else(|| io::Error::other("invalid worker status"))? as u16;
        if result.get("id").and_then(Value::as_u64) != Some(1) {
            return Err(io::Error::other("invalid worker correlation id"));
        }
        let body = result
            .get_mut("body")
            .map(Value::take)
            .ok_or_else(|| io::Error::other("worker response body missing"))?;
        Ok((status, body))
    }

    async fn stop(mut self) {
        drop(self.input);
        if tokio::time::timeout(Duration::from_secs(3), self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.kill().await;
            let _ = self.child.wait().await;
        }
    }
}

async fn serve_worker(
    launch: WorkerLaunch,
    database: PathBuf,
    scope: (String, String),
    key: Arc<Zeroizing<String>>,
    budget: Arc<WorkerBudget>,
    notifier: Arc<crate::dynamodb_replication::RelayNotifier>,
    mut requests: mpsc::Receiver<Request>,
) {
    let mut worker: Option<Worker> = None;
    let mut waiting = budget.waiting.subscribe();
    let mut idle_until = tokio::time::Instant::now() + IDLE_TIMEOUT;
    loop {
        let request = tokio::select! {
            // Yield cached capacity before more work when another actor needs a process.
            biased;
            changed=waiting.changed()=> {
                if changed.is_err() { break; }
                let release=*waiting.borrow_and_update()>0;
                if release {
                    if let Some(worker)=worker.take() { worker.stop().await; }
                }
                continue;
            }
            received=tokio::time::timeout_at(idle_until,requests.recv())=>match received {
                Ok(Some(request))=>request,
                _=>break,
            },
        };
        idle_until = tokio::time::Instant::now() + IDLE_TIMEOUT;
        if request.reply.is_closed() || tokio::time::Instant::now() >= request.deadline {
            let _ = request
                .reply
                .send(Err("ExtendDB request expired before execution".into()));
            continue;
        }
        let result = tokio::time::timeout_at(request.deadline, async {
            if worker.is_none() {
                let slot = budget
                    .acquire()
                    .await
                    .map_err(|_| DdbError::Internal("ExtendDB is shutting down".into()))?;
                let table_key = match &request.table {
                    Some(table) => Some(table.unlock().await?),
                    None => None,
                };
                let key = table_key
                    .as_ref()
                    .map(|v| v.as_str())
                    .unwrap_or(key.as_str());
                worker = Some(
                    Worker::start(
                        launch.clone(),
                        database.clone(),
                        &scope,
                        key,
                        slot,
                        request.table.as_ref().map(|t| &t.record),
                    )
                    .await
                    .map_err(|e| DdbError::Internal(e.to_string()))?,
                );
            }
            if let Some(table) = &request.table {
                table.authorize().await?;
            }
            match worker.as_mut() {
                Some(worker) => worker
                    .request(&request)
                    .await
                    .map_err(|e| DdbError::Internal(e.to_string())),
                None => Err(DdbError::Internal("ExtendDB worker unavailable".into())),
            }
        })
        .await
        .unwrap_or_else(|_| {
            Err(DdbError::Internal(
                "ExtendDB worker request timed out; outcome may be unknown".into(),
            ))
        });
        if result.is_err() {
            if let Some(worker) = worker.take() {
                worker.stop().await;
            }
        }
        if matches!(
            request.operation.as_str(),
            "PutItem" | "UpdateItem" | "DeleteItem" | "BatchWriteItem" | "TransactWriteItems"
        ) {
            notifier.notify(&scope.0, &scope.1);
        }
        let result = match result {
            Ok(value) => Ok(value),
            Err(error) => error_reply(error).await,
        };
        let _ = request.reply.send(result);
        idle_until = tokio::time::Instant::now() + IDLE_TIMEOUT;
    }
    if let Some(worker) = worker {
        worker.stop().await;
    }
}

#[async_trait]
impl NativeHandler for WorkerPool {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
            return Err("invalid account");
        }
        let mut entries = match tokio::fs::read_dir(self.data.join(account)).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err("ExtendDB inventory unavailable"),
        };
        let mut regions = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|_| "ExtendDB inventory unavailable")?
        {
            let name = entry.file_name();
            let Some(region) = name.to_str().and_then(|s| s.strip_suffix(".sqlite3")) else {
                continue;
            };
            if !(3..=64).contains(&region.len())
                || !region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                continue;
            }
            let (status, result) = self
                .query(account, region, "ListTables".into(), json!({"Limit":1}))
                .await
                .map_err(|_| "ExtendDB inventory query failed")?;
            if status != 200 {
                return Err("ExtendDB inventory query failed");
            }
            if result
                .get("TableNames")
                .and_then(Value::as_array)
                .is_some_and(|tables| !tables.is_empty())
            {
                regions.push(region.to_owned());
            }
        }
        Ok(regions)
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let result = async {
            let operation = request
                .headers
                .get("x-amz-target")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split_once('.'))
                .map(|(_, op)| op.to_string())
                .ok_or("missing operation")?;
            let body = serde_json::from_slice(&request.body).map_err(|_| "invalid request body")?;
            self.query(&request.account_id, &request.region, operation, body)
                .await
        }
        .await;
        engine_response(&request.request_id, result.map_err(DdbError::Internal))
    }
}

async fn error_reply(error: DdbError) -> Reply {
    // Reuse the service's protocol renderer instead of maintaining another AWS error map.
    let response = error.into_response("");
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .map_err(|_| "could not render engine error")?;
    Ok((
        status,
        serde_json::from_slice(&body).map_err(|_| "could not render engine error")?,
    ))
}

fn owned_encryption_description(body: Value) -> Result<Value, DdbError> {
    let description = body
        .get("Table")
        .ok_or_else(|| DdbError::Internal("missing owned-encryption table description".into()))?;
    if description.get("TableStatus").and_then(Value::as_str) != Some("ACTIVE") {
        return Err(DdbError::ResourceInUse(
            "Table must be ACTIVE to update encryption".into(),
        ));
    }
    if description
        .get("SSEDescription")
        .is_some_and(|description| !description.is_null())
    {
        return Err(DdbError::Validation(
            "Changing customer-managed encryption is not supported by this DynamoDB engine".into(),
        ));
    }
    Ok(json!({"TableDescription":description}))
}

fn engine_response(request_id: &str, result: Result<(u16, Value), DdbError>) -> Response {
    match result {
        Ok((status, body)) => match Response::builder()
            .status(status)
            .header("content-type", "application/x-amz-json-1.0")
            .header("x-amzn-requestid", request_id)
            .body(Body::from(body.to_string()))
        {
            Ok(response) => response,
            Err(_) => DdbError::Internal("could not encode engine response".into())
                .into_response(request_id),
        },
        Err(error) => error.into_response(request_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scripted_pool(
        replies: Vec<(&'static str, (u16, Value))>,
    ) -> (WorkerPool, Arc<Mutex<Vec<String>>>) {
        let (sender, mut receiver) = mpsc::channel::<Request>(8);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        let task = tokio::spawn(async move {
            for (expected, reply) in replies {
                let request = receiver.recv().await.unwrap();
                assert_eq!(request.operation, expected);
                observed.lock().unwrap().push(request.operation);
                request.reply.send(Ok(reply)).unwrap();
            }
        });
        let pool = WorkerPool {
            launch: WorkerLaunch {
                components: PathBuf::from("/never-executed"),
                mode: WorkerMode::Normal,
            },
            data: PathBuf::from("/never-opened"),
            key: Arc::new(Zeroizing::new(String::new())),
            workers: Mutex::new(HashMap::from([(
                ("000000000000".into(), "us-east-1".into(), None),
                WorkerTask { sender, task },
            )])),
            table_storage: None,
            closing: AtomicBool::new(false),
            notifier: crate::dynamodb_replication::RelayNotifier::new(),
            budget: WorkerBudget::new(1),
        };
        (pool, calls)
    }

    #[tokio::test]
    async fn owned_encryption_noop_reads_real_active_table_without_updating_storage() {
        let description = json!({"TableName":"owned","TableStatus":"ACTIVE","TableArn":"arn:aws:dynamodb:us-east-1:000000000000:table/owned","ItemCount":3});
        for specification in [json!({}), json!({"Enabled":false})] {
            let (pool, calls) =
                scripted_pool(vec![("DescribeTable", (200, json!({"Table":description})))]);
            let (status, body) = pool
                .query(
                    "000000000000",
                    "us-east-1",
                    "UpdateTable".into(),
                    json!({"TableName":"owned","SSESpecification":specification}),
                )
                .await
                .unwrap();
            assert_eq!(status, 200);
            assert_eq!(body, json!({"TableDescription":description}));
            assert_eq!(*calls.lock().unwrap(), ["DescribeTable"]);
            pool.shutdown().await;
        }
    }

    #[tokio::test]
    async fn owned_encryption_combined_update_checks_current_security_then_runs_real_update() {
        let updated = json!({"TableDescription":{"TableName":"owned","TableStatus":"ACTIVE","DeletionProtectionEnabled":true}});
        let (pool, calls) = scripted_pool(vec![
            (
                "DescribeTable",
                (
                    200,
                    json!({"Table":{"TableName":"owned","TableStatus":"ACTIVE"}}),
                ),
            ),
            ("UpdateTable", (200, updated.clone())),
        ]);
        let result=pool.query("000000000000","us-east-1","UpdateTable".into(),json!({"TableName":"owned","SSESpecification":{"Enabled":false},"DeletionProtectionEnabled":true})).await.unwrap();
        assert_eq!(result, (200, updated));
        assert_eq!(*calls.lock().unwrap(), ["DescribeTable", "UpdateTable"]);
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn owned_encryption_update_never_claims_a_missing_inactive_or_customer_key_table() {
        for (status, source, expected) in [
            (
                400,
                json!({"__type":"com.amazonaws.dynamodb.v20120810#ResourceNotFoundException","message":"missing"}),
                "ResourceNotFoundException",
            ),
            (
                200,
                json!({"Table":{"TableName":"owned","TableStatus":"CREATING"}}),
                "ResourceInUseException",
            ),
            (
                200,
                json!({"Table":{"TableName":"owned","TableStatus":"ACTIVE","SSEDescription":{"Status":"ENABLED","SSEType":"KMS","KMSMasterKeyArn":"legacy-placeholder"}}}),
                "ValidationException",
            ),
        ] {
            for combined in [false, true] {
                let (pool, calls) =
                    scripted_pool(vec![("DescribeTable", (status, source.clone()))]);
                let mut body = json!({"TableName":"owned","SSESpecification":{"Enabled":false}});
                if combined {
                    body["DeletionProtectionEnabled"] = json!(true);
                }
                let (status, result) = pool
                    .query("000000000000", "us-east-1", "UpdateTable".into(), body)
                    .await
                    .unwrap();
                assert_eq!(status, 400);
                assert!(result["__type"].as_str().unwrap().ends_with(expected));
                assert_eq!(*calls.lock().unwrap(), ["DescribeTable"]);
                pool.shutdown().await;
            }
        }
    }

    #[test]
    fn engine_selection_cannot_hide_existing_data() {
        let root = std::env::temp_dir().join(format!("engine-binding-{}", uuid::Uuid::new_v4()));
        let state = locallycloud_state::StateDb::open(root.join("state.sqlite3")).unwrap();
        state.connection().unwrap().execute_batch("CREATE TABLE dynamodb_tables(name TEXT); INSERT INTO dynamodb_tables VALUES('existing')").unwrap();
        assert!(bind_store(&state, "extenddb")
            .unwrap_err()
            .to_string()
            .contains("native DynamoDB tables exist"));
        bind_store(&state, "native").unwrap();
        assert!(bind_store(&state, "extenddb").is_err());
        bind_store(&state, "native").unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn an_expired_queued_write_never_starts_a_worker() {
        let (sender, receiver) = mpsc::channel(1);
        let (reply, result) = oneshot::channel();
        sender
            .send(Request {
                operation: "PutItem".into(),
                body: json!({}),
                reply,
                deadline: tokio::time::Instant::now() - Duration::from_secs(1),
                table: None,
            })
            .await
            .unwrap();
        drop(sender);
        serve_worker(
            WorkerLaunch {
                components: PathBuf::from("/missing-component"),
                mode: WorkerMode::Normal,
            },
            PathBuf::from("/missing-database"),
            ("000000000000".into(), "us-east-1".into()),
            Arc::new(Zeroizing::new(String::new())),
            WorkerBudget::new(1),
            crate::dynamodb_replication::RelayNotifier::new(),
            receiver,
        )
        .await;
        assert_eq!(
            result.await.unwrap().unwrap_err(),
            "ExtendDB request expired before execution"
        );
    }

    #[tokio::test]
    async fn cancelled_slot_waiters_remove_cache_pressure() {
        let budget = WorkerBudget::new(1);
        let cached = budget.acquire().await.unwrap();
        let mut changed = budget.waiting.subscribe();
        let waiting = budget.clone();
        let task = tokio::spawn(async move { waiting.acquire().await });
        tokio::time::timeout(Duration::from_secs(1), changed.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*changed.borrow_and_update(), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(*budget.waiting.borrow(), 0);
        drop(cached);
        assert_eq!(budget.slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn a_full_worker_queue_returns_aws_throttling_without_executing() {
        let (pool, _) = scripted_pool(vec![]);
        let (sender, receiver) = mpsc::channel(1);
        let (reply, _) = oneshot::channel();
        sender
            .try_send(Request {
                operation: "GetItem".into(),
                body: json!({}),
                reply,
                deadline: tokio::time::Instant::now() + REQUEST_TIMEOUT,
                table: None,
            })
            .unwrap_or_else(|_| panic!("fixture queue unexpectedly full"));
        let (status, body) = pool
            .enqueue(sender, "PutItem".into(), json!({}), None)
            .await
            .unwrap();
        assert_eq!(status, 400);
        assert!(body["__type"]
            .as_str()
            .unwrap()
            .ends_with("#ThrottlingException"));
        drop(receiver);
        pool.shutdown().await;
    }

    #[test]
    fn table_handshake_rejects_missing_capability_and_wrong_generation() {
        let table = TableBinding {
            table_name: "orders",
            storage_id: uuid::Uuid::new_v4().to_string(),
        };
        let mut ready = json!({"features":["table-file-v1"],"table_file":{"table_name":table.table_name,"storage_id":table.storage_id}});
        assert!(ready_for_table(&ready, Some(&table)));
        assert!(!ready_for_table(&ready, None));
        ready["table_file"]["storage_id"] = json!(uuid::Uuid::new_v4().to_string());
        assert!(!ready_for_table(&ready, Some(&table)));
        ready["table_file"]["storage_id"] = json!(table.storage_id);
        ready["features"] = json!([]);
        assert!(!ready_for_table(&ready, Some(&table)));
        assert!(ready_for_table(&json!({}), None));
    }

    #[test]
    fn worker_mode_handshake_requires_exact_mode_and_all_capabilities() {
        let features = component_catalog::REQUIRED_CAPABILITIES
            .iter()
            .map(|feature| json!(feature))
            .collect::<Vec<_>>();
        for mode in [WorkerMode::Normal, WorkerMode::Migration] {
            let mut ready =
                json!({"ready":true,"version":1,"mode":mode.as_str(),"features":features});
            assert!(ready_for_mode(&ready, mode));
            let other = match mode {
                WorkerMode::Normal => WorkerMode::Migration,
                WorkerMode::Migration => WorkerMode::Normal,
            };
            assert!(!ready_for_mode(&ready, other));
            ready.as_object_mut().unwrap().remove("mode");
            assert!(!ready_for_mode(&ready, mode));
        }
        for required in component_catalog::REQUIRED_CAPABILITIES {
            let missing = features
                .iter()
                .filter(|feature| feature.as_str() != Some(*required))
                .cloned()
                .collect::<Vec<_>>();
            for mode in [WorkerMode::Normal, WorkerMode::Migration] {
                assert!(
                    !ready_for_mode(
                        &json!({"ready":true,"version":1,"mode":mode.as_str(),"features":missing}),
                        mode
                    ),
                    "must reject a worker missing {required}"
                );
            }
        }
    }
}
