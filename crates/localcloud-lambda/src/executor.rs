//! Data-plane execution engine: run a function via the Core `ComputeRuntime` and correlate
//! its result through the Runtime API broker.
//!
//! One synchronous invocation, end to end: extract the code, build the guest rootfs, assemble
//! the execution environment (pointing the guest's `AWS_LAMBDA_RUNTIME_API` at this host's
//! Runtime API), submit the invocation to the broker, launch the guest, and await the outcome
//! bounded by the function timeout. The environment is ephemeral (stopped after the invoke);
//! warm pooling and snapshot reuse layer on top later (task 12).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use localcloud_compute::runtime::{ComputeRuntime, TaskSpec};
use localcloud_core::integration::correlation::CorrelationContext;
use localcloud_core::integration::identity::CallerIdentity;
use localcloud_core::integration::logs::{
    LogScope, ProducerContext, ProducerGroupSpec, ProducerLogEvent, ProducerStreamSpec,
};
use localcloud_core::registry::{ServiceName, ServiceRegistry};
use uuid::Uuid;

use crate::code_store::CodeStore;
use crate::error::LambdaError;
use crate::exec_env::{build_execution_env, ExecEnvInputs};
use crate::model::{LambdaFunction, LayerStore};
use crate::rootfs::build_rootfs;
use crate::runtime_api::{FunctionErrorType, InvocationBroker, Outcome};

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}

const ROOTFS_BUILDING: &[u8] = b"localcloud-rootfs-v1 building\n";
const ROOTFS_STARTING: &[u8] = b"localcloud-rootfs-v1 starting\n";
const ROOTFS_RUNNING: &[u8] = b"localcloud-rootfs-v1 running\n";

fn flock(file: &File, flags: libc::c_int) -> io::Result<()> {
    loop {
        let result = unsafe { libc::flock(file.as_raw_fd(), flags) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn rootfs_owner_dir(root: &Path) -> io::Result<PathBuf> {
    let name = root.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "rootfs root has no directory name",
        )
    })?;
    let mut sidecar_name = std::ffi::OsString::from(".");
    sidecar_name.push(name);
    sidecar_name.push(".localcloud-owners");
    Ok(root.with_file_name(sidecar_name))
}

fn owner_marker_path(owner_dir: &Path, env_key: &str) -> PathBuf {
    owner_dir.join(format!("{env_key}.owner"))
}

fn remove_owned_rootfs(root: &Path, env_key: &str) -> io::Result<()> {
    let path = root.join(env_key);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            std::fs::remove_dir_all(path)
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owned rootfs is no longer a real directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Shared execution dependencies for the Lambda data plane.
pub struct Executor {
    broker: Arc<InvocationBroker>,
    /// Set after construction so extension phase completion can return an env to the pool
    /// without delaying the HTTP response from the runtime.
    self_ref: OnceLock<Weak<Executor>>,
    code_store: Arc<CodeStore>,
    layers: Arc<LayerStore>,
    rootfs_root: PathBuf,
    runtime: Arc<dyn ComputeRuntime>,
    /// Host `host:port[/prefix]` a guest reaches the Runtime API on (no scheme).
    runtime_api_base: String,
    /// localcloud endpoint URL injected for in-guest SDK calls.
    aws_endpoint_url: String,
    access_key_id: String,
    secret_access_key: String,
    /// Optional router for async destinations/DLQ (absent → destinations are not routed).
    destination_router: Option<Arc<dyn DestinationRouter>>,
    /// Registry is resolved lazily so Logs may register after Lambda during startup.
    registry: Weak<ServiceRegistry>,
    install_host_runtime: bool,
    /// Per-environment stream identity and cumulative-output cursor.
    log_state: DashMap<String, ExecutionLogState>,
    /// Rootfs owned by this process, including environments not yet returned to a warm pool.
    owned_envs: DashMap<String, File>,
    closed: AtomicBool,
    invocations: tokio::sync::RwLock<()>,
    reaper_gate: tokio::sync::Mutex<()>,
    /// Warm pools keyed by `"<arn>:<version>"`; each generation changes on invalidation.
    warm: DashMap<String, Mutex<WarmPool>>,
    /// Serializes idle-pool changes across function keys.
    warm_gate: Mutex<()>,
    warm_sequence: AtomicU64,
    /// Idle timeout after which a retained environment is evicted.
    idle_timeout: Duration,
    /// Maximum retained environments per function+version.
    max_warm_per_key: usize,
    /// Maximum idle environments retained across all functions and versions.
    max_warm_total: usize,
}

/// The result of a synchronous invocation: the outcome plus captured guest logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeResult {
    pub outcome: Outcome,
    /// Captured stdout/stderr produced by this invocation only.
    pub logs: String,
    /// Runtime API request identifier, when execution reached the runtime.
    pub request_id: Option<String>,
    /// Stable stream associated with this execution environment.
    pub log_stream_name: Option<String>,
    /// Billed duration in milliseconds (invoke phase only; no accrual while frozen).
    pub billed_duration_ms: u64,
}

struct ExecutionLogState {
    stream_name: String,
    output_bytes: usize,
}

/// Pool state guarded as one unit so invalidation cannot race with returning an environment.
#[derive(Default)]
struct WarmPool {
    generation: u64,
    envs: Vec<WarmEnv>,
}

/// A retained (frozen) warm execution environment available for reuse.
struct WarmEnv {
    env_key: String,
    last_used: Instant,
    sequence: u64,
}

/// Routes an asynchronous invocation record to an `OnSuccess`/`OnFailure` destination or DLQ
/// ARN. Implemented in production over the integration `DeliveryEngine`; the trait keeps the
/// executor decoupled from cross-service wiring.
#[async_trait::async_trait]
pub trait DestinationRouter: Send + Sync {
    async fn route(&self, target_arn: &str, record: serde_json::Value);
}

/// The effective asynchronous-invocation configuration for a function.
#[derive(Debug, Clone, Default)]
pub struct AsyncConfig {
    pub max_retry_attempts: u32,
    pub on_success_arn: Option<String>,
    pub on_failure_arn: Option<String>,
}

impl Executor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        broker: Arc<InvocationBroker>,
        code_store: Arc<CodeStore>,
        rootfs_root: impl Into<PathBuf>,
        runtime: Arc<dyn ComputeRuntime>,
        runtime_api_base: impl Into<String>,
        aws_endpoint_url: impl Into<String>,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        Executor {
            broker,
            self_ref: OnceLock::new(),
            code_store,
            layers: Arc::new(LayerStore::new()),
            rootfs_root: rootfs_root.into(),
            runtime,
            runtime_api_base: runtime_api_base.into(),
            aws_endpoint_url: aws_endpoint_url.into(),
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            destination_router: None,
            registry: Weak::new(),
            install_host_runtime: false,
            log_state: DashMap::new(),
            owned_envs: DashMap::new(),
            closed: AtomicBool::new(false),
            invocations: tokio::sync::RwLock::new(()),
            reaper_gate: tokio::sync::Mutex::new(()),
            warm: DashMap::new(),
            warm_gate: Mutex::new(()),
            warm_sequence: AtomicU64::new(0),
            idle_timeout: Duration::from_secs(300),
            max_warm_per_key: 10,
            max_warm_total: 16,
        }
    }

    pub(crate) fn bind_arc(self: &Arc<Self>) {
        let _ = self.self_ref.set(Arc::downgrade(self));
    }

    pub fn with_layer_store(mut self, layers: Arc<LayerStore>) -> Self {
        self.layers = layers;
        self
    }

    pub(crate) fn layer_store(&self) -> Arc<LayerStore> {
        self.layers.clone()
    }

    pub(crate) fn parse_max_warm_total(value: Option<&str>) -> Result<usize, String> {
        match value {
            None => Ok(16),
            Some(raw) => match raw.parse::<usize>() {
                Ok(limit) if limit <= 1024 => Ok(limit),
                _ => Err("expected an integer from 0 to 1024".into()),
            },
        }
    }

    pub(crate) fn with_max_warm_total(mut self, limit: usize) -> Self {
        self.max_warm_total = limit;
        self
    }

    /// Attach a router for async `OnSuccess`/`OnFailure` destinations and DLQ.
    pub fn with_destination_router(mut self, router: Arc<dyn DestinationRouter>) -> Self {
        self.destination_router = Some(router);
        self
    }

    /// Attach the shared service registry for lazy producer-log capability resolution.
    pub fn with_service_registry(mut self, registry: Weak<ServiceRegistry>) -> Self {
        self.registry = registry;
        self
    }

    /// Install a host-provided managed runtime into OCI rootfses. In-process test backends do
    /// not need this payload and leave the option disabled.
    pub fn with_host_managed_runtime(mut self) -> Self {
        self.install_host_runtime = true;
        self
    }

    /// Run one synchronous invocation of `func` with `payload`, returning its outcome, logs,
    /// and billed duration. Reuses a warm (frozen) environment when available, otherwise
    /// cold-starts one; a healthy environment is frozen for reuse, a failed one is discarded.
    pub async fn invoke_sync(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        payload: Vec<u8>,
    ) -> Result<InvokeResult, LambdaError> {
        let _admitted = self.invocations.read().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(LambdaError::InternalError(
                "Lambda executor is shutting down".into(),
            ));
        }
        if func.package_type != "Zip" {
            return Err(LambdaError::NotImplemented(
                "image-package invocation is not yet supported".into(),
            ));
        }
        let code = func.code_zip.as_ref().ok_or_else(|| {
            LambdaError::InvalidParameterValue("function has no executable code package".into())
        })?;

        let pool_key = format!("{}:{}", func.function_arn, func.version);
        self.evict_expired(&pool_key).await;

        // Reuse a warm environment, or cold-start a new one. The generation is captured
        // atomically with removal so invalidation can prevent a stale environment returning.
        let (generation, warm_env, expired) = self.take_warm(&pool_key);
        for expired_key in expired {
            self.stop_env(&expired_key).await;
        }
        let warm_env = if let Some(key) = warm_env {
            if self.broker.environment_healthy(&key) {
                Some(key)
            } else {
                self.stop_env_reason(&key, "FAILURE").await;
                None
            }
        } else {
            None
        };
        let env_key = match warm_env {
            Some(key) => key,
            None => match self.cold_start(account, region, func, code).await {
                Ok(key) => key,
                Err(e) => {
                    return Ok(InvokeResult {
                        outcome: Outcome::Error {
                            error_type: FunctionErrorType::Unhandled,
                            payload: format!("{{\"errorMessage\":\"{e}\"}}").into_bytes(),
                        },
                        logs: String::new(),
                        request_id: None,
                        log_stream_name: None,
                        billed_duration_ms: 0,
                    })
                }
            },
        };

        let timeout_ms = (func.timeout as i64) * 1000;
        let started = Instant::now();
        let (request_id, rx) =
            self.broker
                .submit(&env_key, payload, &func.function_arn, timeout_ms);

        let mut timed_out = false;
        let outcome =
            match tokio::time::timeout(Duration::from_millis(timeout_ms.max(0) as u64), rx).await {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(_)) => Outcome::Error {
                    error_type: FunctionErrorType::Unhandled,
                    payload: b"runtime exited without responding".to_vec(),
                },
                Err(_) => {
                    timed_out = true;
                    self.broker
                        .fail_unhandled(&request_id, b"timed out".to_vec());
                    Outcome::Error {
                        error_type: FunctionErrorType::Unhandled,
                        payload: format!(
                            "{{\"errorMessage\":\"{} timed out after {} seconds\"}}",
                            func.function_name, func.timeout
                        )
                        .into_bytes(),
                    }
                }
            };
        // Billed duration covers the invoke phase only (no accrual while frozen).
        let billed_duration_ms = started.elapsed().as_millis() as u64;
        let broker_logs = self.broker.take_logs(&request_id);
        let captured = self.runtime.get_output(&env_key).await.unwrap_or_default();
        let (fallback_logs, log_stream_name) = match self.log_state.get_mut(&env_key) {
            Some(mut state) => {
                let start = if captured.len() >= state.output_bytes
                    && captured.is_char_boundary(state.output_bytes)
                {
                    state.output_bytes
                } else {
                    0
                };
                let logs = captured[start..].to_string();
                state.output_bytes = captured.len();
                (logs, Some(state.stream_name.clone()))
            }
            None => (captured, None),
        };
        let has_extensions = self.broker.has_extensions(&env_key);
        let logs = if has_extensions || crate::rootfs::is_custom(func.runtime.as_deref()) {
            fallback_logs
        } else {
            broker_logs
                .map(|chunks| chunks.concat())
                .unwrap_or(fallback_logs)
        };
        let result = InvokeResult {
            outcome,
            logs,
            request_id: Some(request_id.clone()),
            log_stream_name,
            billed_duration_ms,
        };

        if matches!(result.outcome, Outcome::Success(_)) && has_extensions {
            let deadline = tokio::time::Instant::from_std(
                started + Duration::from_millis(timeout_ms.max(0) as u64),
            );
            if let Some(executor) = self.self_ref.get().and_then(Weak::upgrade) {
                let account = account.to_string();
                let region = region.to_string();
                let function = func.clone();
                let background_result = result.clone();
                tokio::spawn(async move {
                    let phase = executor
                        .broker
                        .wait_extensions_rearmed(&env_key, &request_id, deadline)
                        .await;
                    let mut complete = background_result;
                    let captured = executor
                        .runtime
                        .get_output(&env_key)
                        .await
                        .unwrap_or_default();
                    if let Some(mut state) = executor.log_state.get_mut(&env_key) {
                        if captured.len() >= state.output_bytes
                            && captured.is_char_boundary(state.output_bytes)
                        {
                            complete.logs.push_str(&captured[state.output_bytes..]);
                        }
                        state.output_bytes = captured.len();
                    }
                    complete.billed_duration_ms = started.elapsed().as_millis() as u64;
                    if let Err(error) = executor
                        .publish_invocation_logs(&account, &region, &function, &complete)
                        .await
                    {
                        tracing::warn!(%error, "extension invocation logs not published");
                    }
                    if phase.is_ok() {
                        executor.return_warm(&pool_key, &env_key, generation).await;
                    } else {
                        let reason = if tokio::time::Instant::now() >= deadline {
                            "TIMEOUT"
                        } else {
                            "FAILURE"
                        };
                        executor.stop_env_reason(&env_key, reason).await;
                    }
                });
                return Ok(result);
            }
            // Standalone test executors have no Arc owner to hold the environment lease.
            if self
                .broker
                .wait_extensions_rearmed(&env_key, &request_id, deadline)
                .await
                .is_ok()
            {
                self.return_warm(&pool_key, &env_key, generation).await;
            } else {
                self.stop_env_reason(&env_key, "TIMEOUT").await;
            }
        } else if matches!(result.outcome, Outcome::Success(_)) {
            self.return_warm(&pool_key, &env_key, generation).await;
        } else {
            let reason = if timed_out { "TIMEOUT" } else { "FAILURE" };
            if has_extensions {
                if let Some(executor) = self.self_ref.get().and_then(Weak::upgrade) {
                    let env_key = env_key.clone();
                    tokio::spawn(async move {
                        executor.stop_env_reason(&env_key, reason).await;
                    });
                } else {
                    self.stop_env_reason(&env_key, reason).await;
                }
            } else {
                self.stop_env_reason(&env_key, reason).await;
            }
        }
        self.publish_invocation_logs(account, region, func, &result)
            .await?;
        Ok(result)
    }

    async fn publish_invocation_logs(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        result: &InvokeResult,
    ) -> Result<(), LambdaError> {
        let Some(registry) = self.registry.upgrade() else {
            return Ok(());
        };
        let sink = registry
            .log_sink(&ServiceName::new("logs"))
            .ok_or_else(|| LambdaError::InternalError("CloudWatch Logs is unavailable".into()))?;
        let (Some(request_id), Some(stream_name)) = (
            result.request_id.as_deref(),
            result.log_stream_name.as_deref(),
        ) else {
            return Ok(());
        };
        let scope = LogScope::new(account, region);
        let context = ProducerContext {
            source_service: "lambda".into(),
            identity: CallerIdentity::AssumedRole {
                role_arn: func.role.clone(),
                session_name: request_id.to_string(),
            },
            correlation: CorrelationContext {
                flow_id: request_id.to_string(),
                span_id: Uuid::new_v4().to_string(),
            },
            loop_depth: 0,
        };
        let group = sink
            .ensure_group(
                scope.clone(),
                ProducerGroupSpec {
                    name: format!("/aws/lambda/{}", func.function_name),
                },
                context.clone(),
            )
            .await
            .map_err(|_| {
                LambdaError::InternalError("CloudWatch Logs group publication failed".into())
            })?;
        let target = sink
            .ensure_stream(
                scope.clone(),
                group,
                ProducerStreamSpec {
                    name: stream_name.to_string(),
                },
                context.clone(),
            )
            .await
            .map_err(|_| {
                LambdaError::InternalError("CloudWatch Logs stream publication failed".into())
            })?;
        let timestamp_ms = now_ms();
        let mut events = Vec::with_capacity(result.logs.lines().count() + 3);
        events.push(ProducerLogEvent {
            timestamp_ms,
            message: format!("START RequestId: {request_id} Version: {}", func.version),
        });
        events.extend(result.logs.lines().map(|line| ProducerLogEvent {
            timestamp_ms,
            message: line.to_string(),
        }));
        events.push(ProducerLogEvent {
            timestamp_ms,
            message: format!("END RequestId: {request_id}"),
        });
        events.push(ProducerLogEvent {
            timestamp_ms,
            message: format!(
                "REPORT RequestId: {request_id}\tDuration: {}.00 ms\tBilled Duration: {} ms\tMemory Size: {} MB",
                result.billed_duration_ms, result.billed_duration_ms, func.memory_size
            ),
        });
        sink.append(scope, target, events, context)
            .await
            .map_err(|_| {
                LambdaError::InternalError("CloudWatch Logs event publication failed".into())
            })?;
        Ok(())
    }

    /// The global lock serializes registration with recovery across localcloud processes.
    /// A marker is published only while this lock is held; its per-environment lock stays
    /// open throughout construction, invocation, and warm retention.
    fn with_owner_lock<T>(&self, action: impl FnOnce(&Path) -> io::Result<T>) -> io::Result<T> {
        std::fs::create_dir_all(&self.rootfs_root)?;
        let owner_dir = rootfs_owner_dir(&self.rootfs_root)?;
        match std::fs::DirBuilder::new().mode(0o700).create(&owner_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = std::fs::symlink_metadata(&owner_dir)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "owner path must be a private directory of the current user",
            ));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(owner_dir.join(".lock"))?;
        flock(&lock, libc::LOCK_EX)?;
        action(&owner_dir)
    }

    fn recover_building_rootfs(&self, owner_dir: &Path) -> io::Result<()> {
        for entry in std::fs::read_dir(owner_dir)? {
            let entry = entry?;
            let filename = entry.file_name();
            let Some(name) = filename.to_str() else {
                continue;
            };
            let Some(env_key) = name.strip_suffix(".owner") else {
                continue;
            };
            if env_key.is_empty() || env_key == "." || env_key == ".." {
                continue;
            }
            if !entry.file_type()?.is_file() {
                continue;
            }
            let mut marker = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(entry.path())?;
            match flock(&marker, libc::LOCK_EX | libc::LOCK_NB) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
            let mut phase = Vec::new();
            marker.read_to_end(&mut phase)?;
            // Unknown and starting markers may represent an OCI guest still running
            // after the parent died. Only pre-start construction is safe to collect.
            if phase != ROOTFS_BUILDING {
                continue;
            }
            if let Err(error) = remove_owned_rootfs(&self.rootfs_root, env_key) {
                tracing::warn!(%env_key, %error, "could not recover building rootfs");
                continue;
            }
            std::fs::remove_file(entry.path())?;
        }
        Ok(())
    }

    fn orphaned_running_rootfs(&self, owner_dir: &Path) -> io::Result<Vec<(String, File)>> {
        let mut candidates = Vec::new();
        for entry in std::fs::read_dir(owner_dir)? {
            let entry = entry?;
            let filename = entry.file_name();
            let Some(env_key) = filename
                .to_str()
                .and_then(|name| name.strip_suffix(".owner"))
            else {
                continue;
            };
            if env_key.is_empty()
                || self.owned_envs.contains_key(env_key)
                || !entry.file_type()?.is_file()
            {
                continue;
            }
            let mut marker = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(entry.path())?;
            match flock(&marker, libc::LOCK_EX | libc::LOCK_NB) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
            let mut phase = Vec::new();
            marker.read_to_end(&mut phase)?;
            if phase == ROOTFS_RUNNING {
                candidates.push((env_key.to_owned(), marker));
            }
        }
        Ok(candidates)
    }

    async fn recover_orphaned_guests(&self) {
        let Ok(owner_dir) = rootfs_owner_dir(&self.rootfs_root) else {
            return;
        };
        if !owner_dir.is_dir() {
            return;
        }
        let candidates = match self.with_owner_lock(|dir| self.orphaned_running_rootfs(dir)) {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::warn!(%error, "OCI orphan scan deferred");
                return;
            }
        };
        for (env_key, marker) in candidates {
            match self.runtime.reconcile_orphaned_task(&env_key).await {
                Ok(true) => self.cleanup_rootfs_with_marker(&env_key, marker),
                Ok(false) => {}
                Err(error) => tracing::warn!(%env_key, %error, "OCI orphan recovery deferred"),
            }
        }
    }

    fn reserve_rootfs(&self, env_key: &str) -> io::Result<()> {
        self.with_owner_lock(|owner_dir| {
            self.recover_building_rootfs(owner_dir)?;
            match std::fs::symlink_metadata(self.rootfs_root.join(env_key)) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "rootfs name already exists",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let path = owner_marker_path(owner_dir, env_key);
            let mut marker = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            flock(&marker, libc::LOCK_EX)?;
            marker.write_all(ROOTFS_BUILDING)?;
            marker.sync_all()?;
            self.owned_envs.insert(env_key.to_string(), marker);
            Ok(())
        })
    }

    fn mark_rootfs_starting(&self, env_key: &str) -> io::Result<()> {
        let mut marker = self.owned_envs.get_mut(env_key).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "rootfs owner marker not held")
        })?;
        marker.set_len(0)?;
        marker.seek(SeekFrom::Start(0))?;
        marker.write_all(ROOTFS_STARTING)?;
        marker.sync_all()
    }

    fn mark_rootfs_running(&self, env_key: &str) -> io::Result<()> {
        let mut marker = self.owned_envs.get_mut(env_key).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "rootfs owner marker not held")
        })?;
        marker.set_len(0)?;
        marker.seek(SeekFrom::Start(0))?;
        marker.write_all(ROOTFS_RUNNING)?;
        marker.sync_all()
    }

    fn cleanup_rootfs_with_marker(&self, env_key: &str, marker: File) {
        let result = self.with_owner_lock(|owner_dir| {
            remove_owned_rootfs(&self.rootfs_root, env_key)?;
            std::fs::remove_file(owner_marker_path(owner_dir, env_key))
        });
        if let Err(error) = result {
            tracing::warn!(%env_key, %error, "rootfs cleanup deferred");
        }
        drop(marker);
    }

    fn cleanup_owned_rootfs(&self, env_key: &str) {
        if let Some((_, marker)) = self.owned_envs.remove(env_key) {
            self.cleanup_rootfs_with_marker(env_key, marker);
        }
    }

    /// Cold-start a new execution environment (extract code, build rootfs, launch the guest).
    async fn cold_start(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        code: &[u8],
    ) -> Result<String, String> {
        let env_key = format!("{}-{}", sanitize(&func.function_arn), Uuid::new_v4());
        let stored = self
            .code_store
            .store_zip(account, region, &func.function_name, code)
            .map_err(|e| e.to_string())?;
        let rootfs_path = self.rootfs_root.join(&env_key);
        self.reserve_rootfs(&env_key)
            .map_err(|error| format!("rootfs ownership failed: {error}"))?;
        let mut layer_dirs = Vec::with_capacity(func.layers.len());
        let layer_result: Result<(), String> = (|| {
            for arn in &func.layers {
                let parts: Vec<&str> = arn.split(':').collect();
                let name = parts
                    .get(6)
                    .ok_or_else(|| format!("invalid layer ARN: {arn}"))?;
                let version = parts
                    .get(7)
                    .ok_or_else(|| format!("invalid layer ARN: {arn}"))?
                    .parse::<u64>()
                    .map_err(|_| format!("invalid layer ARN: {arn}"))?;
                let layer = self
                    .layers
                    .get_version_for_execution(account, region, name, version)
                    .ok_or_else(|| format!("layer version unavailable: {arn}"))?;
                let extracted = self
                    .code_store
                    .store_zip(
                        account,
                        region,
                        &format!("layer-{name}-{version}"),
                        &layer.code_zip,
                    )
                    .map_err(|error| error.to_string())?;
                layer_dirs.push(extracted.dir);
            }
            Ok(())
        })();
        if let Err(error) = layer_result {
            for dir in &layer_dirs {
                let _ = std::fs::remove_dir_all(dir);
            }
            let _ = std::fs::remove_dir_all(&stored.dir);
            self.cleanup_owned_rootfs(&env_key);
            return Err(error);
        }
        let rootfs = build_rootfs(
            &rootfs_path,
            func.runtime.as_deref(),
            &stored.dir,
            &layer_dirs,
        );
        let _ = std::fs::remove_dir_all(&stored.dir);
        for dir in &layer_dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
        let rootfs = match rootfs {
            Ok(rootfs) => rootfs,
            Err(error) => {
                self.cleanup_owned_rootfs(&env_key);
                return Err(error.to_string());
            }
        };
        if self.install_host_runtime {
            let cache_root = self.rootfs_root.with_file_name("runtime-cache");
            if let Err(error) = crate::rootfs::install_managed_runtime_with_cache(
                &rootfs.path,
                func.runtime.as_deref(),
                &cache_root,
            ) {
                self.cleanup_owned_rootfs(&env_key);
                return Err(error.to_string());
            }
        }

        if let Err(error) = self.broker.discover_expected_extensions(
            &env_key,
            rootfs.extension_names.clone(),
            &func.function_name,
            &func.version,
            func.handler.as_deref().unwrap_or_default(),
        ) {
            self.cleanup_owned_rootfs(&env_key);
            return Err(format!("extension discovery failed: {error}"));
        }

        let runtime_api = format!("{}/e/{}", self.runtime_api_base, env_key);
        let log_stream = format!("{}/[{}]{}", today(), func.version, Uuid::new_v4().simple());
        let env_map = build_execution_env(&ExecEnvInputs {
            function_name: &func.function_name,
            function_version: &func.version,
            runtime: func.runtime.as_deref(),
            handler: func.handler.as_deref(),
            memory_size: func.memory_size,
            region,
            log_stream: &log_stream,
            runtime_api: &runtime_api,
            aws_endpoint_url: &self.aws_endpoint_url,
            access_key_id: &self.access_key_id,
            secret_access_key: &self.secret_access_key,
            session_token: None,
            user_env: &func.environment,
        });
        let spec = TaskSpec {
            name: func.function_name.clone(),
            image: rootfs.path.display().to_string(),
            command: rootfs.entrypoint.clone(),
            env: env_map.into_iter().collect::<HashMap<_, _>>(),
            memory_mb: func.memory_size,
            vcpu_count: 1,
        };
        if let Err(error) = self.mark_rootfs_starting(&env_key) {
            self.cleanup_owned_rootfs(&env_key);
            return Err(format!("rootfs ownership transition failed: {error}"));
        }
        if let Err(error) = self.runtime.start_task(&env_key, &spec).await {
            self.owned_envs.remove(&env_key);
            self.broker.cleanup_extensions(&env_key);
            return Err(format!("guest start failed: {error}"));
        }
        if let Err(error) = self.mark_rootfs_running(&env_key) {
            match self.runtime.stop_task(&env_key).await {
                Ok(_) => self.cleanup_owned_rootfs(&env_key),
                Err(stop_error) => {
                    self.owned_envs.remove(&env_key);
                    tracing::warn!(%env_key, %stop_error, "guest may remain after owner marker failure");
                }
            }
            return Err(format!("rootfs ownership transition failed: {error}"));
        }
        self.log_state.insert(
            env_key.clone(),
            ExecutionLogState {
                stream_name: log_stream,
                output_bytes: 0,
            },
        );
        if self.broker.has_extensions(&env_key) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            if let Err(error) = self.broker.wait_init_ready(&env_key, deadline).await {
                self.stop_env_reason(&env_key, "FAILURE").await;
                return Err(format!("extension initialization failed: {error}"));
            }
        }
        Ok(env_key)
    }

    /// Take a non-expired warm environment and its generation for `pool_key`.
    fn take_warm(&self, pool_key: &str) -> (u64, Option<String>, Vec<String>) {
        let _gate = self.warm_gate.lock().unwrap();
        let entry = self.warm.entry(pool_key.to_string()).or_default();
        let mut pool = entry.lock().unwrap();
        let mut expired = Vec::new();
        while let Some(w) = pool.envs.pop() {
            if w.last_used.elapsed() < self.idle_timeout {
                return (pool.generation, Some(w.env_key), expired);
            }
            expired.push(w.env_key);
        }
        (pool.generation, None, expired)
    }

    /// Return a healthy environment to the warm pool, evicting the oldest idle environment
    /// across all keys if the global limit is reached. No stop runs with pool locks held.
    async fn return_warm(&self, pool_key: &str, env_key: &str, generation: u64) {
        let to_stop = {
            let _gate = self.warm_gate.lock().unwrap();
            let mut to_stop = Vec::new();
            {
                let entry = self.warm.entry(pool_key.to_string()).or_default();
                let mut pool = entry.lock().unwrap();
                if pool.generation != generation
                    || pool.envs.len() >= self.max_warm_per_key
                    || self.max_warm_total == 0
                {
                    to_stop.push(env_key.to_string());
                } else {
                    pool.envs.push(WarmEnv {
                        env_key: env_key.to_string(),
                        last_used: Instant::now(),
                        sequence: self.warm_sequence.fetch_add(1, Ordering::Relaxed),
                    });
                }
            }
            // A return can add at most one idle environment. All pool changes share warm_gate.
            let mut total = 0;
            let mut oldest: Option<(u64, String, String)> = None;
            for entry in &self.warm {
                let pool = entry.lock().unwrap();
                total += pool.envs.len();
                for warm in &pool.envs {
                    let candidate = (warm.sequence, entry.key().clone(), warm.env_key.clone());
                    if oldest.as_ref().is_none_or(|current| candidate < *current) {
                        oldest = Some(candidate);
                    }
                }
            }
            if total > self.max_warm_total {
                let (_, key, victim) = oldest.expect("nonempty warm pool exceeds limit");
                if let Some(entry) = self.warm.get(&key) {
                    let mut pool = entry.lock().unwrap();
                    let position = pool
                        .envs
                        .iter()
                        .position(|warm| warm.env_key == victim)
                        .expect("warm pool changed while global gate was held");
                    to_stop.push(pool.envs.remove(position).env_key);
                }
            }
            to_stop
        };
        for key in to_stop {
            self.stop_env(&key).await;
        }
    }

    /// Evict warm environments idle beyond the timeout for `pool_key`.
    async fn evict_expired(&self, pool_key: &str) {
        let expired: Vec<String> = {
            let _gate = self.warm_gate.lock().unwrap();
            match self.warm.get(pool_key) {
                Some(entry) => {
                    let mut pool = entry.lock().unwrap();
                    let (keep, drop_): (Vec<_>, Vec<_>) = pool
                        .envs
                        .drain(..)
                        .partition(|w| w.last_used.elapsed() < self.idle_timeout);
                    pool.envs = keep;
                    drop_.into_iter().map(|w| w.env_key).collect()
                }
                None => Vec::new(),
            }
        };
        for env_key in expired {
            self.stop_env(&env_key).await;
        }
    }

    /// Reap expired environments across all function pools, including functions never invoked again.
    pub async fn reap_expired_warm(&self) {
        let _reaper = self.reaper_gate.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        // The service calls this every minute even when no function is invoked. Avoid
        // provisioning an owner namespace on an installation that has never used Lambda.
        if let Ok(owner_dir) = rootfs_owner_dir(&self.rootfs_root) {
            if owner_dir.is_dir() {
                if let Err(error) = self.with_owner_lock(|dir| self.recover_building_rootfs(dir)) {
                    tracing::warn!(%error, "rootfs recovery deferred");
                }
            }
        }
        self.recover_orphaned_guests().await;
        let keys: Vec<String> = self.warm.iter().map(|entry| entry.key().clone()).collect();
        for key in keys {
            self.evict_expired(&key).await;
        }
    }

    /// Drain retained environments after the public server has stopped accepting requests.
    pub async fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        let _drained = self.invocations.write().await;
        let _reaper = self.reaper_gate.lock().await;
        let keys: Vec<String> = self.warm.iter().map(|entry| entry.key().clone()).collect();
        for key in keys {
            self.invalidate_warm(&key).await;
            self.warm.remove(&key);
        }
        let remaining: Vec<String> = self
            .owned_envs
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        for env_key in remaining {
            self.stop_env(&env_key).await;
        }
    }

    /// Stop an environment and free its resources.
    async fn stop_env(&self, env_key: &str) {
        self.stop_env_reason(env_key, "SPINDOWN").await;
    }

    async fn stop_env_reason(&self, env_key: &str, reason: &str) {
        let Some((_, marker)) = self.owned_envs.remove(env_key) else {
            return;
        };
        if self.broker.has_extensions(env_key) {
            let grace = Duration::from_secs(2);
            let deadline_ms = unix_ms() + grace.as_millis() as i64;
            let shutdown_marker = self
                .rootfs_root
                .join(env_key)
                .join("tmp/.localcloud-extension-shutdown");
            if let Err(error) = std::fs::write(&shutdown_marker, b"") {
                tracing::warn!(%env_key, %error, "extension shutdown marker unavailable");
            }
            self.broker.begin_shutdown(env_key, reason, deadline_ms);
            // External extensions receive SHUTDOWN from their outstanding Next request.
            // The current guest supervisor has no process-exit channel to the host, so the
            // full grace period is needed before the sandbox is terminated.
            tokio::time::sleep(grace).await;
        }
        self.broker.stop(env_key);
        self.broker.cleanup_extensions(env_key);
        self.log_state.remove(env_key);
        match self.runtime.stop_task(env_key).await {
            Ok(_) => self.cleanup_rootfs_with_marker(env_key, marker),
            Err(error) => {
                // A failed stop may leave an OCI guest alive. Keep its marker and rootfs.
                drop(marker);
                tracing::warn!(%env_key, %error, "guest stop failed; rootfs retained");
            }
        }
    }

    /// Invalidate every published version and $LATEST when a function is deleted.
    pub async fn invalidate_function_warm(&self, function_arn: &str) {
        let prefix = format!("{function_arn}:");
        let keys: Vec<String> = self
            .warm
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys {
            self.invalidate_warm(&key).await;
        }
    }

    /// Advance the pool generation, drain every retained environment, then finish teardown.
    /// The pool mutex is released before any asynchronous stop operation.
    pub async fn invalidate_warm(&self, pool_key: &str) {
        let envs = {
            let _gate = self.warm_gate.lock().unwrap();
            let entry = self.warm.entry(pool_key.to_string()).or_default();
            let mut pool = entry.lock().unwrap();
            pool.generation = pool.generation.wrapping_add(1);
            std::mem::take(&mut pool.envs)
        };
        for warm in envs {
            self.stop_env(&warm.env_key).await;
        }
    }
    /// Run a Function URL invocation: build the v2 event, invoke synchronously, and translate
    /// the structured response back to HTTP (Requirement 14.7).
    pub async fn invoke_url(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        request: crate::function_url::UrlRequest,
    ) -> Result<crate::function_url::UrlHttpResponse, LambdaError> {
        let event = crate::function_url::build_v2_event(&request)
            .to_string()
            .into_bytes();
        let result = self.invoke_sync(account, region, func, event).await?;
        Ok(match result.outcome {
            Outcome::Success(payload) => crate::function_url::interpret_v2_response(&payload),
            Outcome::Error { .. } => crate::function_url::error_response(),
        })
    }

    /// Run an asynchronous (Event) invocation: execute with retries up to
    /// `config.max_retry_attempts`, then route the invocation record to the `OnSuccess`
    /// destination (success) or `OnFailure` destination/DLQ (exhausted failure).
    pub async fn invoke_async(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        payload: Vec<u8>,
        config: &AsyncConfig,
    ) {
        let total = config.max_retry_attempts.saturating_add(1); // initial + retries
        let mut invoke_count = 0u32;
        let mut last: Option<InvokeResult> = None;
        for attempt in 1..=total {
            invoke_count = attempt;
            match self
                .invoke_sync(account, region, func, payload.clone())
                .await
            {
                Ok(result) => {
                    let is_success = matches!(result.outcome, Outcome::Success(_));
                    last = Some(result);
                    if is_success {
                        break;
                    }
                    // Retry on function error/timeout until attempts are exhausted.
                }
                Err(_) => break, // a control error (e.g. bad config) is not retried
            }
        }

        let Some(result) = last else { return };
        let succeeded = matches!(result.outcome, Outcome::Success(_));
        let target = if succeeded {
            config.on_success_arn.as_deref()
        } else {
            config.on_failure_arn.as_deref()
        };
        if let (Some(arn), Some(router)) = (target, &self.destination_router) {
            let record = async_record(func, &payload, &result, invoke_count, succeeded);
            router.route(arn, record).await;
        }
    }
}

/// Build the AWS asynchronous-invocation destination record envelope.
fn async_record(
    func: &LambdaFunction,
    request_payload: &[u8],
    result: &InvokeResult,
    invoke_count: u32,
    succeeded: bool,
) -> serde_json::Value {
    let request_json: serde_json::Value =
        serde_json::from_slice(request_payload).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(request_payload).into_owned())
        });
    let (status_code, function_error, response_bytes) = match &result.outcome {
        Outcome::Success(p) => (200, None, p.as_slice()),
        Outcome::Error {
            error_type,
            payload,
        } => (200, Some(error_type.as_str()), payload.as_slice()),
    };
    let response_json: serde_json::Value =
        serde_json::from_slice(response_bytes).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(response_bytes).into_owned())
        });
    let mut response_context = serde_json::json!({
        "statusCode": status_code,
        "executedVersion": func.version,
    });
    if let Some(err) = function_error {
        response_context["functionError"] = serde_json::Value::String(err.to_string());
    }
    serde_json::json!({
        "version": "1.0",
        "timestamp": now_iso(),
        "requestContext": {
            "requestId": Uuid::new_v4().to_string(),
            "functionArn": format!("{}:{}", func.function_arn, func.version),
            "condition": if succeeded { "Success" } else { "RetriesExhausted" },
            "approximateInvokeCount": invoke_count,
        },
        "requestPayload": request_json,
        "responseContext": response_context,
        "responsePayload": response_json,
    })
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

/// Replace characters that are awkward in a path/URL segment.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn today() -> String {
    let date = time::OffsetDateTime::now_utc().date();
    format!(
        "{:04}/{:02}/{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_api_server::router;
    use async_trait::async_trait;
    use localcloud_compute::runtime::{RuntimeError, TaskHandle, TaskState};
    use std::io::Write;

    /// A test `ComputeRuntime` that launches a real in-process guest: it reads the injected
    /// `AWS_LAMBDA_RUNTIME_API`, polls `next` over HTTP, and posts a transformed response —
    /// exercising the whole host orchestration without a hypervisor. (The real crun/Firecracker
    /// path is validated separately by the compute crate's `oci_hello_task` test.)
    struct InProcessGuest {
        behavior: GuestBehavior,
        starts: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[derive(Clone, Copy)]
    enum GuestBehavior {
        EchoUppercaseLen,
        ReportError,
        Hang,
        ReturnV2,
    }

    #[async_trait]
    impl ComputeRuntime for InProcessGuest {
        async fn start_task(&self, _id: &str, spec: &TaskSpec) -> Result<TaskHandle, RuntimeError> {
            assert!(
                std::path::Path::new(&spec.image)
                    .join("var/task/index.js")
                    .exists(),
                "guest must not start before its function code is present"
            );
            self.starts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let api = spec.env.get("AWS_LAMBDA_RUNTIME_API").cloned().unwrap();
            let behavior = self.behavior;
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                // The runtime interface client loops until the environment is stopped (204).
                loop {
                    let next = match client
                        .get(format!("http://{api}/2018-06-01/runtime/invocation/next"))
                        .send()
                        .await
                    {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    if next.status() == 204 {
                        break;
                    }
                    let rid = next
                        .headers()
                        .get("Lambda-Runtime-Aws-Request-Id")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string();
                    let event = next.text().await.unwrap();
                    match behavior {
                        GuestBehavior::EchoUppercaseLen => {
                            let body = format!("{{\"len\":{}}}", event.len());
                            let _ = client
                                .post(format!(
                                    "http://{api}/2018-06-01/runtime/invocation/{rid}/response"
                                ))
                                .body(body)
                                .send()
                                .await;
                        }
                        GuestBehavior::ReportError => {
                            let _ = client
                                .post(format!(
                                    "http://{api}/2018-06-01/runtime/invocation/{rid}/error"
                                ))
                                .header("Lambda-Runtime-Function-Error-Type", "Handled")
                                .body(r#"{"errorMessage":"boom"}"#)
                                .send()
                                .await;
                        }
                        GuestBehavior::Hang => {
                            // Never respond; the executor's timeout must fire.
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        }
                        GuestBehavior::ReturnV2 => {
                            let _ = client
                                .post(format!(
                                    "http://{api}/2018-06-01/runtime/invocation/{rid}/response"
                                ))
                                .body(
                                    r#"{"statusCode":200,"headers":{"x-test":"1"},"body":"pong"}"#,
                                )
                                .send()
                                .await;
                        }
                    }
                }
            });
            Ok(TaskHandle {
                task_id: _id.to_string(),
                state: TaskState::Running,
            })
        }
        async fn stop_task(&self, id: &str) -> Result<TaskHandle, RuntimeError> {
            Ok(TaskHandle {
                task_id: id.to_string(),
                state: TaskState::Stopped,
            })
        }
        async fn get_output(&self, _id: &str) -> Result<String, RuntimeError> {
            Ok(String::new())
        }
    }

    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts = zip::write::SimpleFileOptions::default();
            for (name, contents) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(contents).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    async fn serve_runtime_api(broker: Arc<InvocationBroker>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(broker)).await.unwrap() });
        addr.to_string()
    }

    fn func(runtime: &str, timeout: u32, code: Vec<u8>) -> LambdaFunction {
        LambdaFunction {
            function_name: "fn".into(),
            function_arn: "arn:aws:lambda:us-east-1:000000000000:function:fn".into(),
            runtime: Some(runtime.into()),
            role: "arn:aws:iam::000000000000:role/r".into(),
            handler: Some("index.handler".into()),
            package_type: "Zip".into(),
            code_sha256: "x".into(),
            code_size: code.len() as u64,
            description: String::new(),
            timeout,
            memory_size: 128,
            ephemeral_storage: 512,
            architectures: vec!["x86_64".into()],
            environment: Default::default(),
            layers: Vec::new(),
            version: "$LATEST".into(),
            last_modified: "now".into(),
            revision_id: "rev".into(),
            state: "Active".into(),
            code_zip: Some(code),
            dead_letter_arn: None,
        }
    }

    async fn build_executor(broker: Arc<InvocationBroker>, behavior: GuestBehavior) -> Executor {
        build_executor_tracked(broker, behavior).await.0
    }

    async fn build_executor_tracked(
        broker: Arc<InvocationBroker>,
        behavior: GuestBehavior,
    ) -> (Executor, Arc<std::sync::atomic::AtomicUsize>) {
        let base = serve_runtime_api(broker.clone()).await;
        let tmp = std::env::temp_dir().join(format!("lc-exec-{}", Uuid::new_v4()));
        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let exec = Executor::new(
            broker,
            Arc::new(CodeStore::new(tmp.join("code"))),
            tmp.join("rootfs"),
            Arc::new(InProcessGuest {
                behavior,
                starts: starts.clone(),
            }),
            base,
            "http://127.0.0.1:4566",
            "test",
            "test",
        );
        (exec, starts)
    }

    #[tokio::test]
    async fn recovery_only_collects_unlocked_prestart_rootfs() {
        let broker = Arc::new(InvocationBroker::new());
        let (first, _) = build_executor_tracked(broker, GuestBehavior::EchoUppercaseLen).await;
        let second = Executor::new(
            first.broker.clone(),
            first.code_store.clone(),
            first.rootfs_root.clone(),
            first.runtime.clone(),
            first.runtime_api_base.clone(),
            first.aws_endpoint_url.clone(),
            "test",
            "test",
        );
        first.reserve_rootfs("building").unwrap();
        std::fs::create_dir_all(first.rootfs_root.join("building")).unwrap();
        std::fs::write(first.rootfs_root.join("building/payload"), b"partial").unwrap();
        second.reserve_rootfs("other").unwrap();
        assert!(first.rootfs_root.join("building/payload").exists());
        first.reserve_rootfs("starting").unwrap();
        std::fs::create_dir_all(first.rootfs_root.join("starting")).unwrap();
        first.mark_rootfs_starting("starting").unwrap();
        let unknown = first.rootfs_root.join("unknown");
        std::fs::create_dir_all(&unknown).unwrap();
        drop(first); // Simulates process death: lock descriptors close without teardown.
        second.reserve_rootfs("trigger").unwrap();
        assert!(!second.rootfs_root.join("building").exists());
        assert!(second.rootfs_root.join("starting").exists());
        assert!(unknown.exists());
        second.cleanup_owned_rootfs("other");
        second.cleanup_owned_rootfs("trigger");
    }

    struct ConfirmedOrphan;

    #[async_trait]
    impl ComputeRuntime for ConfirmedOrphan {
        async fn start_task(&self, _: &str, _: &TaskSpec) -> Result<TaskHandle, RuntimeError> {
            unreachable!()
        }
        async fn stop_task(&self, _: &str) -> Result<TaskHandle, RuntimeError> {
            unreachable!()
        }
        async fn get_output(&self, _: &str) -> Result<String, RuntimeError> {
            unreachable!()
        }
        async fn reconcile_orphaned_task(&self, task_id: &str) -> Result<bool, RuntimeError> {
            Ok(task_id == "orphan")
        }
    }

    #[tokio::test]
    async fn confirmed_orphan_is_reaped_only_after_owner_lock_closes() {
        let broker = Arc::new(InvocationBroker::new());
        let (first, _) = build_executor_tracked(broker, GuestBehavior::EchoUppercaseLen).await;
        first.reserve_rootfs("orphan").unwrap();
        std::fs::create_dir_all(first.rootfs_root.join("orphan")).unwrap();
        std::fs::write(first.rootfs_root.join("orphan/payload"), b"data").unwrap();
        first.mark_rootfs_starting("orphan").unwrap();
        first.mark_rootfs_running("orphan").unwrap();
        let second = Executor::new(
            first.broker.clone(),
            first.code_store.clone(),
            first.rootfs_root.clone(),
            Arc::new(ConfirmedOrphan),
            first.runtime_api_base.clone(),
            first.aws_endpoint_url.clone(),
            "test",
            "test",
        );
        second.recover_orphaned_guests().await;
        assert!(first.rootfs_root.join("orphan/payload").exists());
        drop(first);
        second.recover_orphaned_guests().await;
        assert!(!second.rootfs_root.join("orphan").exists());
        assert!(
            !owner_marker_path(&rootfs_owner_dir(&second.rootfs_root).unwrap(), "orphan").exists()
        );
    }

    #[tokio::test]
    async fn warm_pool_reuses_environment_across_invokes() {
        let broker = Arc::new(InvocationBroker::new());
        let (exec, starts) = build_executor_tracked(broker, GuestBehavior::EchoUppercaseLen).await;
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        // Two sequential invokes of the same function+version reuse one warm environment.
        let r1 = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"aa".to_vec())
            .await
            .unwrap();
        let r2 = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"bbb".to_vec())
            .await
            .unwrap();
        assert_eq!(r1.outcome, Outcome::Success(b"{\"len\":2}".to_vec()));
        assert_eq!(r2.outcome, Outcome::Success(b"{\"len\":3}".to_vec()));
        assert_eq!(
            starts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "second invoke reused the warm env"
        );
    }

    #[test]
    fn global_warm_limit_configuration_is_validated() {
        assert_eq!(Executor::parse_max_warm_total(None).unwrap(), 16);
        assert_eq!(Executor::parse_max_warm_total(Some("0")).unwrap(), 0);
        assert_eq!(Executor::parse_max_warm_total(Some("1024")).unwrap(), 1024);
        for value in ["", "-1", "1.5", "1025", "many"] {
            assert!(Executor::parse_max_warm_total(Some(value)).is_err());
        }
    }

    #[tokio::test]
    async fn global_warm_limit_evicts_least_recently_used_across_functions() {
        let broker = Arc::new(InvocationBroker::new());
        let (exec, starts) = build_executor_tracked(broker, GuestBehavior::EchoUppercaseLen).await;
        let exec = exec.with_max_warm_total(2);
        let code = zip_with(&[("index.js", b"x")]);
        let function = |name: &str| {
            let mut f = func("nodejs22.x", 10, code.clone());
            f.function_name = name.into();
            f.function_arn = format!("arn:aws:lambda:us-east-1:000000000000:function:{name}");
            f
        };
        let a = function("a");
        let b = function("b");
        let c = function("c");
        for f in [&a, &b] {
            exec.invoke_sync("000000000000", "us-east-1", f, b"x".to_vec())
                .await
                .unwrap();
        }
        // Reusing A makes B the least recently used idle environment.
        exec.invoke_sync("000000000000", "us-east-1", &a, b"x".to_vec())
            .await
            .unwrap();
        exec.invoke_sync("000000000000", "us-east-1", &c, b"x".to_vec())
            .await
            .unwrap();
        assert_eq!(starts.load(Ordering::SeqCst), 3);
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 2);
        exec.invoke_sync("000000000000", "us-east-1", &a, b"x".to_vec())
            .await
            .unwrap();
        assert_eq!(starts.load(Ordering::SeqCst), 3, "A remains warm");
        exec.invoke_sync("000000000000", "us-east-1", &b, b"x".to_vec())
            .await
            .unwrap();
        assert_eq!(starts.load(Ordering::SeqCst), 4, "B was evicted");
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 2);
        exec.shutdown().await;
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn global_limit_does_not_evict_an_active_invocation() {
        let broker = Arc::new(InvocationBroker::new());
        let (exec, _) = build_executor_tracked(broker, GuestBehavior::Hang).await;
        let exec = Arc::new(exec.with_max_warm_total(1));
        let code = zip_with(&[("index.js", b"x")]);
        let mut active = func("nodejs22.x", 1, code.clone());
        active.function_name = "active".into();
        active.function_arn.push_str(":active");
        let invoking = tokio::spawn({
            let exec = exec.clone();
            let active = active.clone();
            async move {
                exec.invoke_sync("000000000000", "us-east-1", &active, b"x".to_vec())
                    .await
            }
        });
        for _ in 0..100 {
            if exec.owned_envs.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(exec.owned_envs.len(), 1);
        for name in ["one", "two"] {
            let mut f = func("nodejs22.x", 10, code.clone());
            f.function_name = name.into();
            f.function_arn = format!("arn:aws:lambda:us-east-1:000000000000:function:{name}");
            let env = exec
                .cold_start("000000000000", "us-east-1", &f, &code)
                .await
                .unwrap();
            let key = format!("{}:{}", f.function_arn, f.version);
            exec.return_warm(&key, &env, 0).await;
        }
        assert_eq!(
            exec.warm
                .iter()
                .map(|entry| entry.lock().unwrap().envs.len())
                .sum::<usize>(),
            1
        );
        assert_eq!(
            exec.owned_envs.len(),
            2,
            "active plus one retained idle environment"
        );
        assert!(invoking.await.unwrap().is_ok());
        exec.shutdown().await;
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn idle_reaper_removes_rootfs_without_another_invocation() {
        let broker = Arc::new(InvocationBroker::new());
        let (mut exec, _) = build_executor_tracked(broker, GuestBehavior::EchoUppercaseLen).await;
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        exec.invoke_sync("000000000000", "us-east-1", &f, b"a".to_vec())
            .await
            .unwrap();
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 1);
        exec.idle_timeout = Duration::ZERO;
        exec.reap_expired_warm().await;
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn shutdown_waits_for_invoke_and_rejects_later_work() {
        let broker = Arc::new(InvocationBroker::new());
        let (exec, _) = build_executor_tracked(broker, GuestBehavior::Hang).await;
        let exec = Arc::new(exec);
        let f = func("nodejs22.x", 1, zip_with(&[("index.js", b"x")]));
        let invoking = tokio::spawn({
            let exec = exec.clone();
            let f = f.clone();
            async move {
                exec.invoke_sync("000000000000", "us-east-1", &f, b"a".to_vec())
                    .await
            }
        });
        for _ in 0..100 {
            if exec.owned_envs.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(exec.owned_envs.len(), 1);
        let closing = tokio::spawn({
            let exec = exec.clone();
            async move { exec.shutdown().await }
        });
        assert!(invoking.await.unwrap().is_ok());
        closing.await.unwrap();
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 0);
        assert!(exec
            .invoke_sync("000000000000", "us-east-1", &f, b"b".to_vec())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn shutdown_removes_environment_not_yet_pooled() {
        let broker = Arc::new(InvocationBroker::new());
        let (exec, _) = build_executor_tracked(broker, GuestBehavior::Hang).await;
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        exec.cold_start(
            "000000000000",
            "us-east-1",
            &f,
            f.code_zip.as_ref().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 1);
        exec.shutdown().await;
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn failed_cold_start_removes_partial_rootfs() {
        let broker = Arc::new(InvocationBroker::new());
        let (exec, _) = build_executor_tracked(broker, GuestBehavior::EchoUppercaseLen).await;
        let f = func("provided.al2", 10, zip_with(&[("index.js", b"x")]));
        let error = exec
            .cold_start(
                "000000000000",
                "us-east-1",
                &f,
                f.code_zip.as_ref().unwrap(),
            )
            .await
            .unwrap_err();
        assert!(error.contains("bootstrap"));
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn shutdown_removes_all_retained_rootfs() {
        let broker = Arc::new(InvocationBroker::new());
        let (exec, _) = build_executor_tracked(broker, GuestBehavior::EchoUppercaseLen).await;
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        exec.invoke_sync("000000000000", "us-east-1", &f, b"a".to_vec())
            .await
            .unwrap();
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 1);
        exec.shutdown().await;
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn concurrent_cold_starts_keep_function_code_in_both_rootfses() {
        let broker = Arc::new(InvocationBroker::new());
        let (exec, starts) = build_executor_tracked(broker, GuestBehavior::EchoUppercaseLen).await;
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let (first, second) = tokio::join!(
            exec.invoke_sync("000000000000", "us-east-1", &f, b"a".to_vec()),
            exec.invoke_sync("000000000000", "us-east-1", &f, b"bb".to_vec()),
        );
        assert_eq!(
            first.unwrap().outcome,
            Outcome::Success(b"{\"len\":1}".to_vec())
        );
        assert_eq!(
            second.unwrap().outcome,
            Outcome::Success(b"{\"len\":2}".to_vec())
        );
        assert_eq!(starts.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn sync_invoke_runs_guest_and_returns_response() {
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::EchoUppercaseLen).await;
        let f = func(
            "nodejs22.x",
            10,
            zip_with(&[("index.js", b"exports.handler=()=>{}")]),
        );
        let res = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{\"a\":1}".to_vec())
            .await
            .unwrap();
        // The guest reported the event length (7 bytes).
        assert_eq!(res.outcome, Outcome::Success(b"{\"len\":7}".to_vec()));
    }

    #[tokio::test]
    async fn sync_invoke_surfaces_function_error() {
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::ReportError).await;
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let res = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        match res.outcome {
            Outcome::Error {
                error_type,
                payload,
            } => {
                assert_eq!(error_type, FunctionErrorType::Handled);
                assert_eq!(payload, br#"{"errorMessage":"boom"}"#);
            }
            other => panic!("expected function error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sync_invoke_times_out_unhandled() {
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::Hang).await;
        // 1s timeout; the hanging guest never responds.
        let f = func("nodejs22.x", 1, zip_with(&[("index.js", b"x")]));
        let res = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        match res.outcome {
            Outcome::Error {
                error_type,
                payload,
            } => {
                assert_eq!(error_type, FunctionErrorType::Unhandled);
                assert!(String::from_utf8_lossy(&payload).contains("timed out"));
            }
            other => panic!("expected timeout error, got {other:?}"),
        }
    }

    /// Records async destination deliveries for assertions.
    #[derive(Default)]
    struct RecordingRouter {
        records: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
    }

    #[async_trait]
    impl DestinationRouter for RecordingRouter {
        async fn route(&self, target_arn: &str, record: serde_json::Value) {
            self.records
                .lock()
                .unwrap()
                .push((target_arn.to_string(), record));
        }
    }

    #[tokio::test]
    async fn async_invoke_routes_success_destination() {
        let broker = Arc::new(InvocationBroker::new());
        let router = Arc::new(RecordingRouter::default());
        let exec = build_executor(broker, GuestBehavior::EchoUppercaseLen)
            .await
            .with_destination_router(router.clone());
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let cfg = AsyncConfig {
            max_retry_attempts: 2,
            on_success_arn: Some("arn:aws:sqs:us-east-1:000000000000:ok".into()),
            on_failure_arn: Some("arn:aws:sqs:us-east-1:000000000000:dlq".into()),
        };
        exec.invoke_async("000000000000", "us-east-1", &f, b"hi".to_vec(), &cfg)
            .await;
        let recs = router.records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].0, "arn:aws:sqs:us-east-1:000000000000:ok");
        assert_eq!(recs[0].1["requestContext"]["condition"], "Success");
        assert_eq!(recs[0].1["requestContext"]["approximateInvokeCount"], 1);
    }

    #[tokio::test]
    async fn async_invoke_retries_then_routes_failure() {
        let broker = Arc::new(InvocationBroker::new());
        let router = Arc::new(RecordingRouter::default());
        let exec = build_executor(broker, GuestBehavior::ReportError)
            .await
            .with_destination_router(router.clone());
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let cfg = AsyncConfig {
            max_retry_attempts: 2,
            on_success_arn: None,
            on_failure_arn: Some("arn:aws:sqs:us-east-1:000000000000:dlq".into()),
        };
        exec.invoke_async("000000000000", "us-east-1", &f, b"{}".to_vec(), &cfg)
            .await;
        let recs = router.records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].0, "arn:aws:sqs:us-east-1:000000000000:dlq");
        assert_eq!(recs[0].1["requestContext"]["condition"], "RetriesExhausted");
        // initial + 2 retries = 3 attempts.
        assert_eq!(recs[0].1["requestContext"]["approximateInvokeCount"], 3);
        assert_eq!(recs[0].1["responseContext"]["functionError"], "Handled");
    }

    #[tokio::test]
    async fn function_url_invoke_translates_v2() {
        use crate::function_url::UrlRequest;
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::ReturnV2).await;
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let request = UrlRequest {
            method: "GET".into(),
            raw_path: "/".into(),
            raw_query: String::new(),
            headers: vec![("User-Agent".into(), "test".into())],
            body: Vec::new(),
            url_id: "abc".into(),
            region: "us-east-1".into(),
            account: "000000000000".into(),
            request_id: "rid".into(),
        };
        let resp = exec
            .invoke_url("000000000000", "us-east-1", &f, request)
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"pong");
        assert!(resp.headers.iter().any(|(k, v)| k == "x-test" && v == "1"));
    }

    /// Full wire-level path: create a function through the control plane, then invoke it over
    /// `POST /2015-03-31/functions/{name}/invocations` and read the HTTP invoke response.
    #[tokio::test]
    async fn handler_invoke_route_end_to_end() {
        use crate::service::LambdaHandler;
        use base64::Engine as _;
        use bytes::Bytes;
        use http::Method;
        use localcloud_core::handler::{NativeHandler, ServiceRequest};

        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::EchoUppercaseLen).await;
        let handler = LambdaHandler::with_executor(Arc::new(exec));

        fn req(
            method: Method,
            path: &str,
            body: Vec<u8>,
            invocation_type: Option<&str>,
        ) -> ServiceRequest {
            let mut headers = http::HeaderMap::new();
            if let Some(t) = invocation_type {
                headers.insert(
                    "x-amz-invocation-type",
                    http::HeaderValue::from_str(t).unwrap(),
                );
            }
            ServiceRequest {
                method,
                uri: path.parse().unwrap(),
                headers,
                body: Bytes::from(body),
                region: "us-east-1".into(),
                account_id: "000000000000".into(),
                request_id: "rid".into(),
            }
        }

        // Create the function with a real (nodejs) zip package.
        let zip = zip_with(&[("index.js", b"exports.handler=async()=>({})")]);
        let zip_b64 = base64::engine::general_purpose::STANDARD.encode(&zip);
        let create_body = serde_json::json!({
            "FunctionName": "fn",
            "Role": "arn:aws:iam::000000000000:role/r",
            "Runtime": "nodejs22.x",
            "Handler": "index.handler",
            "Code": { "ZipFile": zip_b64 }
        })
        .to_string()
        .into_bytes();
        let create = handler
            .handle(req(
                Method::POST,
                "/2015-03-31/functions",
                create_body,
                None,
            ))
            .await;
        assert_eq!(create.status(), 201);

        // Invoke synchronously; the in-process guest reports the 5-byte event length.
        let resp = handler
            .handle(req(
                Method::POST,
                "/2015-03-31/functions/fn/invocations",
                b"hello".to_vec(),
                None,
            ))
            .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-amz-executed-version").unwrap(),
            "$LATEST"
        );
        assert!(resp.headers().get("x-amz-function-error").is_none());
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"{\"len\":5}");

        // DryRun validates without executing → 204.
        let dry = handler
            .handle(req(
                Method::POST,
                "/2015-03-31/functions/fn/invocations",
                b"{}".to_vec(),
                Some("DryRun"),
            ))
            .await;
        assert_eq!(dry.status(), 204);

        // An unknown qualifier → 404.
        let bad_qual = handler
            .handle(req(
                Method::POST,
                "/2015-03-31/functions/fn/invocations?Qualifier=99",
                b"{}".to_vec(),
                None,
            ))
            .await;
        assert_eq!(bad_qual.status(), 404);

        // An oversized async payload → 413 RequestTooLarge.
        let big = vec![b'x'; 256 * 1024 + 1];
        let too_big = handler
            .handle(req(
                Method::POST,
                "/2015-03-31/functions/fn/invocations",
                big,
                Some("Event"),
            ))
            .await;
        assert_eq!(too_big.status(), 413);
    }
}
