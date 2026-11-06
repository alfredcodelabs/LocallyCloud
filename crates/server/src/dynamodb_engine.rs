//! Lazy, private ExtendDB workers. Only the LocalCloud front door authorizes clients.
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_dynamodb::error::DdbError;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::component_manager;

const FRAME_LIMIT: usize = 32 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_WORKERS: usize = 4;
type Reply = Result<(u16, Value), String>;

pub fn bind_store(state: &locallycloud_state::StateDb, engine: &str) -> io::Result<()> {
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
            return Err(io::Error::other("DynamoDB engine differs from this state's engine; use a fresh state database or an explicit migration"));
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
                "native DynamoDB tables exist; use a fresh state database or an explicit migration",
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

struct Request {
    operation: String,
    body: Value,
    reply: oneshot::Sender<Reply>,
    deadline: tokio::time::Instant,
}

pub struct ExtendDb {
    pool: Arc<WorkerPool>,
    coordinator: Arc<crate::dynamodb_replication::Coordinator>,
}

impl ExtendDb {
    pub async fn new(state: Arc<locallycloud_state::StateDb>) -> io::Result<Self> {
        let notifier = crate::dynamodb_replication::RelayNotifier::new();
        let pool = Arc::new(WorkerPool::new(&state, notifier.clone())?);
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

pub(crate) struct WorkerPool {
    components: PathBuf,
    data: PathBuf,
    key: Arc<Zeroizing<String>>,
    workers: Mutex<HashMap<(String, String), WorkerTask>>,
    closing: AtomicBool,
    notifier: Arc<crate::dynamodb_replication::RelayNotifier>,
    slots: Arc<Semaphore>,
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
        let sender = self.worker(account, region).map_err(|e| e.to_string())?;
        let (reply, response) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        sender
            .try_send(Request {
                operation,
                body,
                reply,
                deadline,
            })
            .map_err(|_| "ExtendDB worker busy or stopped")?;
        tokio::time::timeout_at(deadline + Duration::from_secs(5), response)
            .await
            .map_err(|_| "ExtendDB queue wait timed out")?
            .map_err(|_| "ExtendDB worker stopped")?
    }

    pub fn new(
        state: &locallycloud_state::StateDb,
        notifier: Arc<crate::dynamodb_replication::RelayNotifier>,
    ) -> io::Result<Self> {
        let mut data = state.path().as_os_str().to_owned();
        data.push(".extenddb");
        let key = std::env::var("LOCALLYCLOUD_KMS_MASTER_KEY")
            .map_err(|_| io::Error::other("LOCALLYCLOUD_KMS_MASTER_KEY is required"))?;
        // Validate before ever passing key material to the private worker.
        locallycloud_state::StateCipher::from_env().map_err(io::Error::other)?;
        Ok(Self {
            components: component_manager::directory()?,
            data: PathBuf::from(data),
            key: Arc::new(Zeroizing::new(key)),
            workers: Mutex::new(HashMap::new()),
            closing: AtomicBool::new(false),
            notifier,
            slots: Arc::new(Semaphore::new(MAX_WORKERS)),
        })
    }

    fn worker(&self, account: &str, region: &str) -> io::Result<mpsc::Sender<Request>> {
        let scope = (account.to_string(), region.to_string());
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
            return Err(io::Error::other(
                "ExtendDB worker capacity reached; retry after idle workers stop",
            ));
        }
        let (sender, receiver) = mpsc::channel(8);
        let database = self.data.join(account).join(format!("{region}.sqlite3"));
        let task = tokio::spawn(serve_worker(
            self.components.clone(),
            database,
            scope.clone(),
            self.key.clone(),
            self.slots.clone(),
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

impl Worker {
    async fn start(
        components: PathBuf,
        database: PathBuf,
        scope: &(String, String),
        key: &str,
        slots: Arc<Semaphore>,
    ) -> io::Result<Self> {
        let slot = slots
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("ExtendDB is shutting down"))?;
        let (_, executable, lease) =
            tokio::task::spawn_blocking(move || component_manager::verified(&components))
                .await
                .map_err(io::Error::other)??;
        let parent = database
            .parent()
            .ok_or_else(|| io::Error::other("invalid database directory"))?
            .to_owned();
        tokio::task::spawn_blocking(move || {
            let data_root = parent
                .parent()
                .ok_or_else(|| io::Error::other("invalid data directory"))?;
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
        let mut init = Zeroizing::new(serde_json::to_vec(&json!({"version":1,"key":key,"database":database,"account_id":scope.0,"region":scope.1})).map_err(io::Error::other)?);
        init.push(b'\n');
        worker.input.write_all(&init).await?;
        worker.input.flush().await?;
        let ready = frame(&mut worker.output).await?;
        if ready.get("ready").and_then(Value::as_bool) != Some(true)
            || ready.get("version").and_then(Value::as_u64) != Some(1)
        {
            return Err(io::Error::other(
                "ExtendDB initialization failed; check worker compatibility or database master key",
            ));
        }
        let features = ready.get("features").and_then(Value::as_array);
        if !["stream-cursors-v1", "mrec-outbox-v1"]
            .iter()
            .all(|required| {
                features.is_some_and(|features| {
                    features
                        .iter()
                        .any(|feature| feature.as_str() == Some(*required))
                })
            })
        {
            return Err(io::Error::other("Installed ExtendDB worker is outdated; reinstall a worker supporting stream cursors and durable MREC"));
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
    components: PathBuf,
    database: PathBuf,
    scope: (String, String),
    key: Arc<Zeroizing<String>>,
    slots: Arc<Semaphore>,
    notifier: Arc<crate::dynamodb_replication::RelayNotifier>,
    mut requests: mpsc::Receiver<Request>,
) {
    let mut worker = None;
    while let Ok(Some(request)) = tokio::time::timeout(IDLE_TIMEOUT, requests.recv()).await {
        if request.reply.is_closed() || tokio::time::Instant::now() >= request.deadline {
            let _ = request
                .reply
                .send(Err("ExtendDB request expired before execution".into()));
            continue;
        }
        let result = tokio::time::timeout_at(request.deadline, async {
            if worker.is_none() {
                worker = Some(
                    Worker::start(
                        components.clone(),
                        database.clone(),
                        &scope,
                        key.as_str(),
                        slots.clone(),
                    )
                    .await?,
                );
            }
            match worker.as_mut() {
                Some(worker) => worker.request(&request).await,
                None => Err(io::Error::other("ExtendDB worker unavailable")),
            }
        })
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::other(
                "ExtendDB worker request timed out; outcome may be unknown",
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
        let _ = request.reply.send(result.map_err(|e| e.to_string()));
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
        match result {
            Ok((status, body)) => match Response::builder()
                .status(status)
                .header("content-type", "application/x-amz-json-1.0")
                .header("x-amzn-requestid", &request.request_id)
                .body(Body::from(body.to_string()))
            {
                Ok(response) => response,
                Err(_) => DdbError::Internal("could not encode engine response".into())
                    .into_response(&request.request_id),
            },
            Err(error) => DdbError::Internal(error).into_response(&request.request_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            })
            .await
            .unwrap();
        drop(sender);
        serve_worker(
            PathBuf::from("/missing-component"),
            PathBuf::from("/missing-database"),
            ("000000000000".into(), "us-east-1".into()),
            Arc::new(Zeroizing::new(String::new())),
            Arc::new(Semaphore::new(1)),
            crate::dynamodb_replication::RelayNotifier::new(),
            receiver,
        )
        .await;
        assert_eq!(
            result.await.unwrap().unwrap_err(),
            "ExtendDB request expired before execution"
        );
    }
}
