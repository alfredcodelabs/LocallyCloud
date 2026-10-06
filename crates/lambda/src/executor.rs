//! Data-plane execution engine: run a function via the Core `ComputeRuntime` and correlate
//! its result through the Runtime API broker.
//!
//! One synchronous invocation, end to end: extract the code, build the guest rootfs, assemble
//! the execution environment (pointing the guest's `AWS_LAMBDA_RUNTIME_API` at this host's
//! Runtime API), submit the invocation to the broker, launch the guest, and await the outcome
//! bounded by the function timeout. The environment is ephemeral (stopped after the invoke);
//! warm pooling and snapshot reuse layer on top later (task 12).

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use axum::{
    body::{to_bytes, Body},
    extract::Request,
    routing::any,
    Router,
};
use dashmap::DashMap;
use http::{StatusCode, Uri};
use locallycloud_compute::runtime::{ComputeRuntime, RuntimeError, TaskSpec};
use locallycloud_core::integration::correlation::CorrelationContext;
use locallycloud_core::integration::identity::CallerIdentity;
use locallycloud_core::integration::logs::{
    LogScope, ProducerContext, ProducerGroupSpec, ProducerLogEvent, ProducerStreamSpec,
};
use locallycloud_core::integration::metrics::{
    EmitOutcome, MetricObservation, MetricOrigin, MetricUnit,
};
use locallycloud_core::proxy::{forward_to_legacy, ProxyConfig};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use locallycloud_core::router::extract_service_from_credential_scope;
use locallycloud_ec2::{Ec2Handler, TaskNetworkLease};
use uuid::Uuid;

use crate::code_store::CodeStore;
use crate::error::LambdaError;
use crate::exec_env::{build_execution_env, ExecEnvInputs};
use crate::model::{FunctionStore, LambdaFunction, LayerStore};
use crate::rootfs::build_rootfs;
use crate::runtime_api::{FunctionErrorType, InvocationBroker, Outcome};

#[derive(Clone)]
struct VpcProxyPolicy {
    ec2: Arc<Ec2Handler>,
    account: String,
    region: String,
    subnet_id: String,
    source_ip: Ipv4Addr,
    source_group_ids: Vec<String>,
}

fn loopback_port(url: &str) -> Result<u16, String> {
    let uri: Uri = url
        .parse()
        .map_err(|_| format!("invalid guest URL: {url}"))?;
    if uri.scheme_str() != Some("http") || !matches!(uri.host(), Some("127.0.0.1" | "localhost")) {
        return Err(format!("VPC guest URL must be HTTP on loopback: {url}"));
    }
    uri.port_u16()
        .ok_or_else(|| format!("VPC guest URL needs an explicit port: {url}"))
}

fn proxy_listener(
    listener: tokio::net::TcpListener,
    backend_url: String,
    policy: Option<VpcProxyPolicy>,
    runtime_prefix: Option<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let app = Router::new().fallback(any(move |request: Request| {
            let backend_url = backend_url.clone();
            let policy = policy.clone();
            let runtime_prefix = runtime_prefix.clone();
            async move {
                let (parts, body) = request.into_parts();
                if let Some(prefix) = &runtime_prefix {
                    if !parts.uri.path().starts_with(prefix) {
                        return http::Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Body::empty())
                            .unwrap();
                    }
                }
                if let Some(policy) = &policy {
                    let service = parts
                        .headers
                        .get(http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|auth| extract_service_from_credential_scope(Some(auth), None));
                    if !service.as_ref().is_some_and(|service| {
                        policy.ec2.vpc_endpoint_access(
                            &policy.account,
                            &policy.region,
                            &policy.subnet_id,
                            policy.source_ip,
                            &policy.source_group_ids,
                            service.as_str(),
                        )
                    }) {
                        // Keep the guest SDK error parseable. AWS would normally
                        // surface a connection failure when there is no route;
                        // this explicit local error identifies the missing endpoint.
                        let name = service.as_ref().map(|name| name.as_str()).unwrap_or("unknown");
                        let message = format!("VPC endpoint or security group egress unavailable for AWS service {name}");
                        if name == "s3" {
                            // S3 uses REST-XML; its SDK would reject a JSON error.
                            return http::Response::builder()
                                .status(StatusCode::SERVICE_UNAVAILABLE)
                                .header(http::header::CONTENT_TYPE, "application/xml")
                                .body(Body::from(format!(
                                    "<Error><Code>VpcEndpointUnavailable</Code><Message>{message}</Message></Error>"
                                )))
                                .unwrap();
                        }
                        let payload = serde_json::json!({
                            "__type": "VpcEndpointUnavailableException",
                            "message": message,
                        });
                        return http::Response::builder()
                            .status(StatusCode::SERVICE_UNAVAILABLE)
                            .header(http::header::CONTENT_TYPE, "application/x-amz-json-1.1")
                            .header("x-amzn-errortype", "VpcEndpointUnavailableException")
                            .body(Body::from(payload.to_string()))
                            .unwrap();
                    }
                }
                // A guest is untrusted input to the host proxy. Bound buffering until
                // the shared proxy supports streaming bodies end to end.
                let body = match to_bytes(body, 32 * 1024 * 1024).await {
                    Ok(body) => body,
                    Err(_) => {
                        return http::Response::builder()
                            .status(StatusCode::PAYLOAD_TOO_LARGE)
                            .body(Body::empty())
                            .unwrap();
                    }
                };
                let config = ProxyConfig {
                    backend_url,
                    upstream_timeout: Duration::from_secs(30),
                };
                forward_to_legacy(&parts.method, &parts.uri, &parts.headers, body, &config)
                    .await
                    .unwrap_or_else(|error| {
                        http::Response::builder()
                            .status(error.http_status())
                            .body(Body::from(error.to_string()))
                            .unwrap()
                    })
            }
        }));
        if let Err(error) = axum::serve(listener, app).await {
            tracing::warn!(%error, "VPC Lambda proxy stopped");
        }
    })
}

fn private_tcp_listener(
    listener: tokio::net::TcpListener,
    ec2: Arc<Ec2Handler>,
    account: String,
    region: String,
    source_eni_id: String,
    target_ip: Ipv4Addr,
    port: u16,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let slots = Arc::new(tokio::sync::Semaphore::new(64));
        loop {
            let (mut guest, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%error, %target_ip, port, "private TCP listener stopped");
                    break;
                }
            };
            let Some(backend) =
                ec2.private_tcp_access(&account, &region, &source_eni_id, target_ip, port)
            else {
                continue;
            };
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                continue;
            };
            tokio::spawn(async move {
                let _slot = slot;
                if let Ok(mut server) = tokio::net::TcpStream::connect(backend).await {
                    let _ = tokio::io::copy_bidirectional(&mut guest, &mut server).await;
                }
            });
        }
    })
}

fn public_egress_tools_available() -> bool {
    [("ip", "-Version"), ("nft", "--version")]
        .into_iter()
        .all(|(program, version)| {
            std::process::Command::new(program)
                .arg(version)
                .output()
                .is_ok_and(|output| output.status.success())
        })
}

fn original_tcp_destination(stream: &tokio::net::TcpStream) -> io::Result<std::net::SocketAddrV4> {
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: getsockopt writes no more than the provided sockaddr_in buffer.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            80, // SO_ORIGINAL_DST
            (&mut address as *mut libc::sockaddr_in).cast(),
            &mut size,
        )
    } != 0
        || size as usize != std::mem::size_of::<libc::sockaddr_in>()
        || address.sin_family != libc::AF_INET as u16
    {
        return Err(io::Error::last_os_error());
    }
    Ok(std::net::SocketAddrV4::new(
        Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(address.sin_port),
    ))
}

fn public_tcp_listener(
    listener: tokio::net::TcpListener,
    ec2: Arc<Ec2Handler>,
    account: String,
    region: String,
    source_eni_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let slots = Arc::new(tokio::sync::Semaphore::new(64));
        loop {
            let (mut guest, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%error, "public TCP listener stopped");
                    break;
                }
            };
            let Ok(destination) = original_tcp_destination(&guest) else {
                continue;
            };
            if !ec2.public_tcp_access(
                &account,
                &region,
                &source_eni_id,
                *destination.ip(),
                destination.port(),
            ) {
                continue;
            }
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let ec2 = ec2.clone();
            let account = account.clone();
            let region = region.clone();
            let source_eni_id = source_eni_id.clone();
            tokio::spawn(async move {
                let _slot = slot;
                if let Ok(Ok(mut server)) = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::TcpStream::connect(destination),
                )
                .await
                {
                    let mut policy_tick = tokio::time::interval(Duration::from_millis(250));
                    let copy = tokio::io::copy_bidirectional(&mut guest, &mut server);
                    tokio::pin!(copy);
                    loop {
                        tokio::select! {
                            _ = policy_tick.tick() => {
                                if !ec2.public_tcp_access(&account, &region, &source_eni_id, *destination.ip(), destination.port()) {
                                    break;
                                }
                            }
                            _ = &mut copy => break,
                        }
                    }
                }
            });
        }
    })
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}

const ROOTFS_BUILDING: &[u8] = b"locallycloud-rootfs-v1 building\n";
const ROOTFS_STARTING: &[u8] = b"locallycloud-rootfs-v1 starting\n";
const ROOTFS_RUNNING: &[u8] = b"locallycloud-rootfs-v1 running\n";
const VPC_WAIT_SCRIPT: &str = r#"#!/bin/bash
set -eu
for ((attempt=0; attempt<500; attempt++)); do
    if [[ -e /tmp/locallycloud-vpc-ready ]] &&
       (: > "/dev/tcp/127.0.0.1/$LOCALLYCLOUD_VPC_RUNTIME_PORT") 2>/dev/null &&
       (: > "/dev/tcp/127.0.0.1/$LOCALLYCLOUD_VPC_AWS_PORT") 2>/dev/null; then
        exec "$@"
    fi
    /bin/sleep 0.02
done
printf 'LocallyCloud VPC endpoint readiness timed out\n' >&2
exit 111
"#;

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
    sidecar_name.push(".locallycloud-owners");
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
    function_store: Mutex<Weak<FunctionStore>>,
    code_store: Arc<CodeStore>,
    layers: Arc<LayerStore>,
    rootfs_root: PathBuf,
    runtime: Arc<dyn ComputeRuntime>,
    ec2: Mutex<Option<Arc<Ec2Handler>>>,
    vpc_networks: DashMap<String, TaskNetworkLease>,
    vpc_public_egress: DashMap<String, bool>,
    vpc_proxies: DashMap<String, Vec<tokio::task::JoinHandle<()>>>,
    /// Host `host:port[/prefix]` a guest reaches the Runtime API on (no scheme).
    runtime_api_base: String,
    /// locallycloud endpoint URL injected for in-guest SDK calls.
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
    environment_functions: DashMap<String, String>,
    memory_budget_mb: u64,
    memory_reservations: Arc<Mutex<HashMap<String, u64>>>,
    stopping: DashMap<String, Arc<tokio::sync::Mutex<bool>>>,
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
    output_bytes: u64,
    account: String,
    region: String,
    function_name: String,
    role: String,
}

/// Cancellation keeps ownership until asynchronous process cleanup confirms termination.
struct EnvironmentLease {
    executor: Weak<Executor>,
    env_key: String,
    armed: bool,
}

impl Drop for EnvironmentLease {
    fn drop(&mut self) {
        if self.armed {
            if let Some(executor) = self.executor.upgrade() {
                let key = self.env_key.clone();
                tokio::spawn(async move {
                    executor.stop_env_reason(&key, "FAILURE").await;
                });
            }
        }
    }
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
            function_store: Mutex::new(Weak::new()),
            code_store,
            layers: Arc::new(LayerStore::new()),
            rootfs_root: rootfs_root.into(),
            runtime,
            ec2: Mutex::new(None),
            vpc_networks: DashMap::new(),
            vpc_public_egress: DashMap::new(),
            vpc_proxies: DashMap::new(),
            runtime_api_base: runtime_api_base.into(),
            aws_endpoint_url: aws_endpoint_url.into(),
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            destination_router: None,
            registry: Weak::new(),
            install_host_runtime: false,
            log_state: DashMap::new(),
            owned_envs: DashMap::new(),
            environment_functions: DashMap::new(),
            memory_budget_mb: 1024,
            memory_reservations: Arc::new(Mutex::new(HashMap::new())),
            stopping: DashMap::new(),
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

    /// Attach the EC2 control plane used for real VPC ENI and endpoint policy.
    pub fn attach_ec2(&self, ec2: Arc<Ec2Handler>) {
        *self.ec2.lock().unwrap() = Some(ec2);
    }

    pub(crate) fn attach_function_store(&self, store: &Arc<FunctionStore>) {
        *self.function_store.lock().unwrap() = Arc::downgrade(store);
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

    pub(crate) fn parse_memory_budget(value: Option<&str>) -> Result<u64, String> {
        match value {
            None => Ok(1024),
            Some(raw) => raw
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0 && *value <= u64::from(u32::MAX))
                .ok_or_else(|| "expected a positive memory budget in MiB".into()),
        }
    }

    pub(crate) fn with_memory_budget(mut self, memory_mb: u64) -> Self {
        self.memory_budget_mb = memory_mb;
        self
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
        self.invoke_sync_traced(account, region, func, payload, None)
            .await
    }

    /// [`invoke_sync`](Self::invoke_sync) continuing the caller's `X-Amzn-Trace-Id` when it
    /// carries a valid X-Ray root.
    pub async fn invoke_sync_traced(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        payload: Vec<u8>,
        incoming_trace: Option<&str>,
    ) -> Result<InvokeResult, LambdaError> {
        let _admitted = self.invocations.read().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(LambdaError::InternalError(
                "Lambda executor is shutting down".into(),
            ));
        }
        if let Some(store) = self.function_store.lock().unwrap().upgrade() {
            if !store.execution_snapshot_exists(account, region, func) {
                return Err(LambdaError::ResourceNotFound(format!(
                    "function no longer exists: {}",
                    func.function_arn
                )));
            }
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
            let missing_public_transport =
                self.vpc_public_egress.get(&key).is_some_and(|enabled| {
                    !*enabled
                        && self.vpc_networks.get(&key).is_some_and(|lease| {
                            self.ec2.lock().unwrap().as_ref().is_some_and(|ec2| {
                                ec2.public_nat_route(account, region, &lease.eni_id)
                            })
                        })
                });
            if missing_public_transport {
                self.stop_env(&key).await;
                None
            } else if self.broker.environment_healthy(&key) {
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
                Err(e @ LambdaError::TooManyRequests(_)) => {
                    self.publish_throttle_metric(
                        account,
                        region,
                        func,
                        &Uuid::new_v4().to_string(),
                    );
                    return Err(e);
                }
                Err(e) => {
                    self.publish_invocation_metrics(
                        account,
                        region,
                        func,
                        &Uuid::new_v4().to_string(),
                        true,
                        None,
                    );
                    return Ok(InvokeResult {
                        outcome: Outcome::Error {
                            error_type: FunctionErrorType::Unhandled,
                            payload: serde_json::json!({"errorMessage": e.to_string()})
                                .to_string()
                                .into_bytes(),
                        },
                        logs: String::new(),
                        request_id: None,
                        log_stream_name: None,
                        billed_duration_ms: 0,
                    });
                }
            },
        };

        let mut environment_lease = self.environment_lease(&env_key);
        let timeout_ms = (func.timeout as i64) * 1000;
        let started = Instant::now();
        let (request_id, rx) = self.broker.submit_traced(
            &env_key,
            payload,
            &func.function_arn,
            timeout_ms,
            crate::trace_header::invocation_trace_header(incoming_trace),
        );

        let mut timed_out = false;
        let mut timeout_logs = None;
        let mut timeout_broker_logs = None;
        let mut timeout_elapsed = None;
        let outcome =
            match tokio::time::timeout(Duration::from_millis(timeout_ms.max(0) as u64), rx).await {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(_)) => Outcome::Error {
                    error_type: FunctionErrorType::Unhandled,
                    payload: b"runtime exited without responding".to_vec(),
                },
                Err(_) => {
                    timed_out = true;
                    timeout_elapsed = Some(started.elapsed());
                    self.broker
                        .fail_unhandled(&request_id, b"timed out".to_vec());
                    timeout_broker_logs = self.broker.take_logs(&request_id);
                    let has_extensions = self.broker.has_extensions(&env_key);
                    // Fence the guest before any log/metric delivery can await and let
                    // timed-out user code perform more application writes.
                    if let Some((fallback, stream)) =
                        self.stop_env_reason_inner(&env_key, "TIMEOUT", true).await
                    {
                        timeout_logs = Some((fallback, stream, has_extensions));
                    }
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
        let invoke_elapsed = timeout_elapsed.unwrap_or_else(|| started.elapsed());
        let billed_duration_ms = invoke_elapsed.as_millis() as u64;
        self.publish_invocation_metrics(
            account,
            region,
            func,
            &request_id,
            matches!(outcome, Outcome::Error { .. }),
            Some(invoke_elapsed.as_secs_f64() * 1000.0),
        );
        let (broker_logs, fallback_logs, log_stream_name, has_extensions) =
            if let Some((fallback, stream, extensions)) = timeout_logs {
                (timeout_broker_logs, fallback, stream, extensions)
            } else {
                let broker_logs = if timed_out {
                    timeout_broker_logs
                } else {
                    self.broker.take_logs(&request_id)
                };
                let (fallback, stream) = self.read_environment_logs(&env_key).await;
                (
                    broker_logs,
                    fallback,
                    stream,
                    self.broker.has_extensions(&env_key),
                )
            };
        let logs = if has_extensions || crate::rootfs::is_custom(func.runtime.as_deref()) {
            fallback_logs
        } else {
            broker_logs
                .map(|chunks| chunks.concat())
                .unwrap_or(fallback_logs)
        };
        let mut result = InvokeResult {
            outcome,
            logs,
            request_id: Some(request_id.clone()),
            log_stream_name,
            billed_duration_ms,
        };

        if !matches!(result.outcome, Outcome::Success(_)) || !has_extensions {
            self.publish_invocation_logs(account, region, func, &result)
                .await?;
        }

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
                    let (tail, _) = executor.read_environment_logs(&env_key).await;
                    complete.logs.push_str(&tail);
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
                environment_lease.armed = false;
                return Ok(result);
            }
            // Standalone test executors have no Arc owner to hold the environment lease.
            let phase = self
                .broker
                .wait_extensions_rearmed(&env_key, &request_id, deadline)
                .await;
            let (tail, _) = self.read_environment_logs(&env_key).await;
            result.logs.push_str(&tail);
            self.publish_invocation_logs(account, region, func, &result)
                .await?;
            if phase.is_ok() {
                self.return_warm(&pool_key, &env_key, generation).await;
            } else {
                self.stop_env_reason(&env_key, "TIMEOUT").await;
            }
        } else if matches!(result.outcome, Outcome::Success(_)) {
            self.return_warm(&pool_key, &env_key, generation).await;
        } else {
            let reason = if timed_out { "TIMEOUT" } else { "FAILURE" };
            if has_extensions && !timed_out {
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
        environment_lease.armed = false;
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

    /// Publish the vended `AWS/Lambda` Invocations, Errors, and Duration metrics for one
    /// invocation. Delivery is best effort and never affects the invocation result.
    fn publish_invocation_metrics(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        correlation_id: &str,
        errored: bool,
        duration_ms: Option<f64>,
    ) {
        let mut metrics = vec![
            ("Invocations", 1.0, MetricUnit::Count),
            ("Errors", if errored { 1.0 } else { 0.0 }, MetricUnit::Count),
        ];
        if let Some(duration_ms) = duration_ms {
            metrics.push(("Duration", duration_ms, MetricUnit::Milliseconds));
        }
        self.emit_lambda_metrics(account, region, func, correlation_id, &metrics);
    }

    /// Publish the vended `AWS/Lambda` Throttles metric for a rejected invocation.
    pub(crate) fn publish_throttle_metric(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        correlation_id: &str,
    ) {
        self.emit_lambda_metrics(
            account,
            region,
            func,
            correlation_id,
            &[("Throttles", 1.0, MetricUnit::Count)],
        );
    }

    fn emit_lambda_metrics(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        correlation_id: &str,
        metrics: &[(&str, f64, MetricUnit)],
    ) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let Some(sink) = registry.metric_sink(&ServiceName::new("monitoring")) else {
            tracing::debug!("CloudWatch Monitoring unavailable; Lambda metrics skipped");
            return;
        };
        let timestamp_ms = now_ms();
        let dimensions = BTreeMap::from([("FunctionName".to_string(), func.function_name.clone())]);
        let observations = metrics
            .iter()
            .map(|(name, value, unit)| MetricObservation {
                account_id: account.to_string(),
                region: region.to_string(),
                namespace: "AWS/Lambda".into(),
                metric_name: (*name).to_string(),
                dimensions: dimensions.clone(),
                timestamp_ms,
                value: *value,
                unit: Some(*unit),
                storage_resolution: 60,
                origin: MetricOrigin::AwsService,
                correlation_id: correlation_id.to_string(),
            })
            .collect();
        let outcome = sink.try_emit(observations);
        if outcome != EmitOutcome::Accepted {
            tracing::debug!(
                ?outcome,
                "Lambda metrics not accepted by CloudWatch Monitoring"
            );
        }
    }

    /// The global lock serializes registration with recovery across locallycloud processes.
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
                Ok(true) => {
                    self.release_vpc_runtime(&env_key);
                    self.cleanup_rootfs_with_marker(&env_key, marker);
                }
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
            tracing::warn!(%env_key, %error, "rootfs cleanup deferred; ownership retained");
            self.owned_envs.insert(env_key.to_owned(), marker);
            let gate = self.stopping.entry(env_key.to_owned()).or_default().clone();
            if let Ok(mut finalized) = gate.try_lock() {
                *finalized = true;
            }
            return;
        }
        drop(marker);
    }

    fn cleanup_owned_rootfs(&self, env_key: &str) {
        self.broker.release(env_key);
        if let Some((_, marker)) = self.owned_envs.remove(env_key) {
            self.cleanup_rootfs_with_marker(env_key, marker);
            if !self.owned_envs.contains_key(env_key) {
                self.environment_functions.remove(env_key);
            }
            self.memory_reservations.lock().unwrap().remove(env_key);
        }
    }

    async fn reserve_memory(&self, env_key: &str, memory_mb: u64) -> Result<(), LambdaError> {
        // Include bounded log capture and supervisor overhead in addition to guest memory.
        let required = memory_mb.saturating_add(32);
        loop {
            {
                let mut reservations = self.memory_reservations.lock().unwrap();
                let used: u64 = reservations.values().sum();
                if required <= self.memory_budget_mb.saturating_sub(used) {
                    reservations.insert(env_key.to_owned(), required);
                    return Ok(());
                }
            }
            let idle = {
                let _gate = self.warm_gate.lock().unwrap();
                let oldest = self
                    .warm
                    .iter()
                    .flat_map(|entry| {
                        let pool = entry.lock().unwrap();
                        pool.envs
                            .iter()
                            .map(|env| (env.sequence, entry.key().clone(), env.env_key.clone()))
                            .collect::<Vec<_>>()
                    })
                    .min_by_key(|entry| entry.0);
                oldest.map(|(_, pool_key, key)| {
                    if let Some(pool) = self.warm.get(&pool_key) {
                        pool.lock().unwrap().envs.retain(|env| env.env_key != key);
                    }
                    key
                })
            };
            match idle {
                Some(key) => self.stop_env(&key).await,
                None => return Err(LambdaError::TooManyRequests(
                    format!("Local compute memory budget exhausted ({required} MiB required, {} MiB budget)", self.memory_budget_mb)
                )),
            }
        }
    }

    fn environment_lease(&self, env_key: &str) -> EnvironmentLease {
        EnvironmentLease {
            executor: self.self_ref.get().cloned().unwrap_or_default(),
            env_key: env_key.to_owned(),
            armed: true,
        }
    }

    async fn read_environment_logs(&self, env_key: &str) -> (String, Option<String>) {
        let (cursor, stream) = self
            .log_state
            .get(env_key)
            .map(|state| (state.output_bytes, Some(state.stream_name.clone())))
            .unwrap_or((0, None));
        let output = match self.runtime.read_output(env_key, cursor).await {
            Ok(output) => output,
            Err(error) => {
                tracing::warn!(%env_key, %error, "guest logs could not be read");
                return (String::new(), stream);
            }
        };
        if let Some(mut state) = self.log_state.get_mut(env_key) {
            state.output_bytes = output.next_cursor;
        }
        let mut logs = output.text;
        if output.dropped_bytes > 0 {
            logs.insert_str(
                0,
                &format!(
                    "[locallycloud: {} log bytes dropped because the capture limit was exceeded]\n",
                    output.dropped_bytes
                ),
            );
        }
        (logs, stream)
    }

    async fn publish_environment_tail(&self, env_key: &str) -> Result<(), LambdaError> {
        let Some(state) = self.log_state.get(env_key) else {
            return Ok(());
        };
        let (account, region, name, role) = (
            state.account.clone(),
            state.region.clone(),
            state.function_name.clone(),
            state.role.clone(),
        );
        drop(state);
        let (logs, stream) = self.read_environment_logs(env_key).await;
        if logs.is_empty() {
            return Ok(());
        }
        let Some(registry) = self.registry.upgrade() else {
            return Ok(());
        };
        let sink = registry
            .log_sink(&ServiceName::new("logs"))
            .ok_or_else(|| LambdaError::InternalError("CloudWatch Logs is unavailable".into()))?;
        let scope = LogScope::new(&account, &region);
        let correlation = Uuid::new_v4().to_string();
        let context = ProducerContext {
            source_service: "lambda".into(),
            identity: CallerIdentity::AssumedRole {
                role_arn: role,
                session_name: correlation.clone(),
            },
            correlation: CorrelationContext {
                flow_id: correlation,
                span_id: Uuid::new_v4().to_string(),
            },
            loop_depth: 0,
        };
        // Resolve rather than recreate: stack deletion may intentionally remove the group.
        let group = sink
            .resolve_group(
                scope.clone(),
                ProducerGroupSpec {
                    name: format!("/aws/lambda/{name}"),
                },
                context.clone(),
            )
            .await
            .map_err(|error| {
                LambdaError::InternalError(format!("final logs publication failed: {error}"))
            })?;
        let target = sink
            .ensure_stream(
                scope.clone(),
                group,
                ProducerStreamSpec {
                    name: stream.unwrap_or_else(|| env_key.to_owned()),
                },
                context.clone(),
            )
            .await
            .map_err(|error| {
                LambdaError::InternalError(format!("final logs publication failed: {error}"))
            })?;
        let timestamp_ms = now_ms();
        sink.append(
            scope,
            target,
            logs.lines()
                .map(|line| ProducerLogEvent {
                    timestamp_ms,
                    message: line.to_owned(),
                })
                .collect(),
            context,
        )
        .await
        .map_err(|error| {
            LambdaError::InternalError(format!("final logs publication failed: {error}"))
        })?;
        Ok(())
    }

    /// Cold-start a new execution environment (extract code, build rootfs, launch the guest).
    async fn cold_start(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        code: &[u8],
    ) -> Result<String, LambdaError> {
        let env_key = format!("{}-{}", sanitize(&func.function_arn), Uuid::new_v4());
        self.reserve_memory(&env_key, u64::from(func.memory_size))
            .await?;
        self.environment_functions.insert(
            env_key.clone(),
            crate::model::function_arn(region, account, &func.function_name),
        );
        let mut lease = self.environment_lease(&env_key);
        let result = self
            .cold_start_inner(account, region, func, code, env_key.clone())
            .await;
        if result.is_ok() {
            lease.armed = false;
        }
        if result.is_err() && !self.owned_envs.contains_key(&env_key) {
            self.environment_functions.remove(&env_key);
            self.memory_reservations.lock().unwrap().remove(&env_key);
        }
        result.map_err(LambdaError::InternalError)
    }

    async fn cold_start_inner(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        code: &[u8],
        env_key: String,
    ) -> Result<String, String> {
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

        let vpc_launch = if let Some(vpc) = &func.vpc_config {
            let prepared = (|| -> Result<_, String> {
                let ec2 = self
                    .ec2
                    .lock()
                    .unwrap()
                    .clone()
                    .ok_or("Lambda VPC requires the EC2 control plane")?;
                let subnet_id = vpc
                    .subnet_ids
                    .first()
                    .ok_or("Lambda VPC needs at least one subnet")?;
                let lease = ec2
                    .reserve_task_network(
                        account,
                        region,
                        subnet_id,
                        &vpc.security_group_ids,
                        &env_key,
                    )
                    .ok_or("Lambda VPC could not reserve a private network interface")?;
                let destinations = ec2.private_tcp_destinations(account, region, &lease.eni_id);
                let dns = ec2.private_tcp_dns(account, region, &lease.eni_id);
                let mut hosts = String::from("127.0.0.1 localhost\n");
                for (hostname, address) in dns {
                    if hostname
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-')
                    {
                        hosts.push_str(&format!("{address} {hostname}\n"));
                    }
                }
                let etc = rootfs.path.join("etc");
                std::fs::create_dir_all(&etc)
                    .map_err(|e| format!("creating VPC guest DNS directory: {e}"))?;
                std::fs::write(etc.join("hosts"), hosts)
                    .map_err(|e| format!("writing VPC guest DNS hosts: {e}"))?;
                std::fs::write(
                    etc.join("resolv.conf"),
                    "nameserver 169.254.169.253\noptions timeout:2 attempts:1\n",
                )
                .map_err(|e| format!("writing VPC guest resolver configuration: {e}"))?;
                let runtime_port = loopback_port(&format!("http://{}", self.runtime_api_base))?;
                let aws_port = loopback_port(&self.aws_endpoint_url)?;
                if runtime_port == aws_port {
                    return Err("Runtime API and AWS endpoint must use different ports".into());
                }
                crate::rootfs::install_vpc_wait_tools(&rootfs.path).map_err(|e| e.to_string())?;
                let script = rootfs.path.join("var/runtime/vpc-wait");
                std::fs::write(&script, VPC_WAIT_SCRIPT)
                    .map_err(|e| format!("writing VPC guest bootstrap: {e}"))?;
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
                    .map_err(|e| format!("setting VPC bootstrap permissions: {e}"))?;
                Ok((ec2, lease, runtime_port, aws_port, destinations))
            })();
            match prepared {
                Ok(value) => Some(value),
                Err(error) => {
                    self.cleanup_owned_rootfs(&env_key);
                    return Err(error);
                }
            }
        } else {
            None
        };

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
        let role_credentials = self
            .registry
            .upgrade()
            .and_then(|registry| registry.authorization_evaluator(&ServiceName::new("iam")))
            .filter(|evaluator| evaluator.strict_sigv4_required())
            .map(|evaluator| {
                evaluator.issue_service_role_credentials(
                    account,
                    &func.role,
                    "lambda.amazonaws.com",
                )
            })
            .transpose()
            .map_err(|error| {
                self.cleanup_owned_rootfs(&env_key);
                format!("Lambda execution role credentials unavailable: {error}")
            })?;
        let mut env_map = build_execution_env(&ExecEnvInputs {
            function_name: &func.function_name,
            function_version: &func.version,
            runtime: func.runtime.as_deref(),
            handler: func.handler.as_deref(),
            memory_size: func.memory_size,
            region,
            log_stream: &log_stream,
            runtime_api: &runtime_api,
            aws_endpoint_url: &self.aws_endpoint_url,
            access_key_id: role_credentials
                .as_ref()
                .map(|credentials| credentials.access_key_id.as_str())
                .unwrap_or(&self.access_key_id),
            secret_access_key: role_credentials
                .as_ref()
                .map(|credentials| credentials.secret_access_key.as_str())
                .unwrap_or(&self.secret_access_key),
            session_token: role_credentials
                .as_ref()
                .map(|credentials| credentials.session_token.as_str()),
            user_env: &func.environment,
        });
        let mut command = rootfs.entrypoint.clone();
        if let Some((_, _, runtime_port, aws_port, _)) = &vpc_launch {
            env_map.insert(
                "LOCALLYCLOUD_VPC_RUNTIME_PORT".into(),
                runtime_port.to_string(),
            );
            env_map.insert("LOCALLYCLOUD_VPC_AWS_PORT".into(), aws_port.to_string());
            command.splice(0..0, ["/bin/bash".into(), "/var/runtime/vpc-wait".into()]);
        }
        let spec = TaskSpec {
            name: func.function_name.clone(),
            image: rootfs.path.display().to_string(),
            command,
            env: env_map.into_iter().collect::<HashMap<_, _>>(),
            memory_mb: func.memory_size,
            vcpu_count: 1,
        };
        if let Err(error) = self.mark_rootfs_starting(&env_key) {
            self.cleanup_owned_rootfs(&env_key);
            return Err(format!("rootfs ownership transition failed: {error}"));
        }
        if let Some((ec2, lease, runtime_port, aws_port, destinations)) = vpc_launch {
            let (handle, mut listeners) = match self
                .runtime
                .start_task_isolated_with_loopback(&env_key, &spec, &[runtime_port, aws_port])
                .await
            {
                Ok(result) => result,
                Err(error) => {
                    self.cleanup_failed_start(&env_key, Some(lease)).await;
                    return Err(format!("isolated VPC guest start failed: {error}"));
                }
            };
            debug_assert_eq!(
                handle.state,
                locallycloud_compute::runtime::TaskState::Running
            );
            let runtime_listener = listeners.remove(0);
            let aws_listener = listeners.remove(0);
            let mut private_listeners = Vec::with_capacity(destinations.len());
            for (address, port) in destinations {
                match self
                    .runtime
                    .bind_isolated_private_tcp(&env_key, address, port)
                    .await
                {
                    Ok(listener) => private_listeners.push((listener, address, port)),
                    Err(error) => {
                        self.cleanup_failed_start(&env_key, Some(lease)).await;
                        return Err(format!("private VPC listener failed: {error}"));
                    }
                }
            }
            let public_tcp = if public_egress_tools_available() {
                let private_addresses = private_listeners
                    .iter()
                    .map(|(_, address, _)| *address)
                    .collect::<Vec<_>>();
                match self
                    .runtime
                    .bind_isolated_public_egress(&env_key, &private_addresses)
                    .await
                {
                    Ok(listener) => Some(listener),
                    Err(error) => {
                        self.cleanup_failed_start(&env_key, Some(lease)).await;
                        return Err(format!("public VPC egress setup failed: {error}"));
                    }
                }
            } else if ec2.public_nat_route(account, region, &lease.eni_id) {
                self.cleanup_failed_start(&env_key, Some(lease)).await;
                return Err("public VPC egress requires host ip and nft".into());
            } else {
                None
            };
            let upstream = match crate::vpc_dns::system_resolver() {
                Ok(resolver) => resolver,
                Err(error) => {
                    self.cleanup_failed_start(&env_key, Some(lease)).await;
                    return Err(format!("VPC DNS system resolver unavailable: {error}"));
                }
            };
            let (dns_udp, dns_tcp) = match self.runtime.bind_isolated_dns(&env_key).await {
                Ok(sockets) => sockets,
                Err(error) => {
                    self.cleanup_failed_start(&env_key, Some(lease)).await;
                    return Err(format!("VPC DNS setup failed: {error}"));
                }
            };
            let public_egress_enabled = public_tcp.is_some();
            let mut proxies = private_listeners
                .into_iter()
                .map(|(listener, address, port)| {
                    private_tcp_listener(
                        listener,
                        ec2.clone(),
                        account.to_string(),
                        region.to_string(),
                        lease.eni_id.clone(),
                        address,
                        port,
                    )
                })
                .collect::<Vec<_>>();
            if let Some(listener) = public_tcp {
                proxies.push(public_tcp_listener(
                    listener,
                    ec2.clone(),
                    account.to_string(),
                    region.to_string(),
                    lease.eni_id.clone(),
                ));
            }
            proxies.extend(crate::vpc_dns::serve(
                dns_udp,
                dns_tcp,
                upstream,
                ec2.clone(),
                account.to_string(),
                region.to_string(),
                lease.eni_id.clone(),
            ));
            let policy = VpcProxyPolicy {
                ec2,
                account: account.to_string(),
                region: region.to_string(),
                subnet_id: lease.subnet_id.clone(),
                source_ip: lease.private_ip,
                source_group_ids: lease.security_group_ids.clone(),
            };
            proxies.extend([
                proxy_listener(
                    runtime_listener,
                    format!("http://{}", self.runtime_api_base),
                    None,
                    Some(format!("/e/{env_key}/")),
                ),
                proxy_listener(
                    aws_listener,
                    self.aws_endpoint_url.clone(),
                    Some(policy),
                    None,
                ),
            ]);
            if let Err(error) =
                std::fs::write(rootfs.path.join("tmp/locallycloud-vpc-ready"), b"ready")
            {
                for proxy in proxies {
                    proxy.abort();
                }
                self.cleanup_failed_start(&env_key, Some(lease)).await;
                return Err(format!("VPC guest readiness marker failed: {error}"));
            }
            self.vpc_proxies.insert(env_key.clone(), proxies);
            self.vpc_networks.insert(env_key.clone(), lease);
            self.vpc_public_egress
                .insert(env_key.clone(), public_egress_enabled);
        } else if let Err(error) = self.runtime.start_task(&env_key, &spec).await {
            self.cleanup_failed_start(&env_key, None).await;
            return Err(format!("guest start failed: {error}"));
        }
        if let Err(error) = self.mark_rootfs_running(&env_key) {
            self.cleanup_failed_start(&env_key, None).await;
            return Err(format!("rootfs ownership transition failed: {error}"));
        }
        self.log_state.insert(
            env_key.clone(),
            ExecutionLogState {
                stream_name: log_stream,
                output_bytes: 0,
                account: account.to_owned(),
                region: region.to_owned(),
                function_name: func.function_name.clone(),
                role: func.role.clone(),
            },
        );
        if self.broker.has_extensions(&env_key) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            if let Err(error) = self.broker.wait_init_ready(&env_key, deadline).await {
                self.stop_env_reason(&env_key, "FAILURE").await;
                return Err(format!("extension initialization failed: {error}"));
            }
        }
        Ok(env_key.clone())
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
            if !self.owned_envs.contains_key(env_key) {
                return;
            }
            let mut to_stop = Vec::new();
            {
                let entry = self.warm.entry(pool_key.to_string()).or_default();
                let mut pool = entry.lock().unwrap();
                if self.closed.load(Ordering::Acquire)
                    || pool.generation != generation
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
        let failed: Vec<String> = self
            .stopping
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        for key in failed {
            self.stop_env(&key).await;
        }
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

    async fn cleanup_failed_start(&self, env_key: &str, lease: Option<TaskNetworkLease>) {
        if let Some(lease) = lease {
            self.vpc_networks.insert(env_key.to_owned(), lease);
        }
        // Keep the same confirmed-process-absence boundary as normal spindown.
        self.stop_env(env_key).await;
    }

    fn release_vpc_runtime(&self, env_key: &str) {
        if let Some((_, proxies)) = self.vpc_proxies.remove(env_key) {
            for proxy in proxies {
                proxy.abort();
            }
        }
        self.vpc_networks.remove(env_key);
        self.vpc_public_egress.remove(env_key);
    }

    /// Stop an environment and free its resources.
    async fn stop_env(&self, env_key: &str) {
        self.stop_env_reason(env_key, "SPINDOWN").await;
    }

    async fn stop_env_reason(&self, env_key: &str, reason: &str) {
        self.stop_env_reason_inner(env_key, reason, false).await;
    }

    async fn stop_env_reason_inner(
        &self,
        env_key: &str,
        reason: &str,
        capture_logs: bool,
    ) -> Option<(String, Option<String>)> {
        let gate = self.stopping.entry(env_key.to_owned()).or_default().clone();
        let mut finalized = gate.lock().await;
        if !self.owned_envs.contains_key(env_key) {
            self.broker.release(env_key);
            self.log_state.remove(env_key);
            self.environment_functions.remove(env_key);
            self.memory_reservations.lock().unwrap().remove(env_key);
            self.stopping.remove(env_key);
            return None;
        }
        if self.broker.has_extensions(env_key) {
            let grace = Duration::from_secs(2);
            let deadline_ms = unix_ms() + grace.as_millis() as i64;
            let shutdown_marker = self
                .rootfs_root
                .join(env_key)
                .join("tmp/.locallycloud-extension-shutdown");
            if let Err(error) = std::fs::write(&shutdown_marker, b"") {
                tracing::warn!(%env_key, %error, "extension shutdown marker unavailable");
            }
            self.broker.begin_shutdown(env_key, reason, deadline_ms);
            // External extensions receive SHUTDOWN from their outstanding Next request.
            // The current guest supervisor has no process-exit channel to the host, so the
            // normal shutdown grace is skipped on timeout: user code must already stop.
            if reason != "TIMEOUT" {
                tokio::time::sleep(grace).await;
            }
        }
        self.broker.stop(env_key);
        let stopped = if *finalized {
            true
        } else {
            match self.runtime.stop_task(env_key).await {
                Ok(_) | Err(RuntimeError::TaskAlreadyCompleted { .. }) => true,
                Err(error) => match self.runtime.reconcile_orphaned_task(env_key).await {
                    Ok(true) => true,
                    Ok(false) => {
                        tracing::warn!(%env_key, %error, "guest stop could not be confirmed; rootfs retained");
                        false
                    }
                    Err(reconcile_error) => {
                        tracing::warn!(%env_key, %error, %reconcile_error, "guest stop could not be confirmed; rootfs retained");
                        false
                    }
                },
            }
        };
        let captured = if stopped && capture_logs {
            Some(self.read_environment_logs(env_key).await)
        } else {
            None
        };
        if stopped {
            if !*finalized {
                if !capture_logs {
                    if let Err(error) = self.publish_environment_tail(env_key).await {
                        tracing::warn!(%env_key, %error, "final guest logs could not be published");
                    }
                }
                if let Err(error) = self.runtime.release_task(env_key).await {
                    tracing::warn!(%env_key, %error, "guest runtime cleanup deferred; ownership retained");
                    return captured;
                }
                *finalized = true;
            }
            self.broker.release(env_key);
            self.log_state.remove(env_key);
            self.release_vpc_runtime(env_key);
            if let Some((_, marker)) = self.owned_envs.remove(env_key) {
                self.cleanup_rootfs_with_marker(env_key, marker);
            }
            self.memory_reservations.lock().unwrap().remove(env_key);
            if !self.owned_envs.contains_key(env_key) {
                self.environment_functions.remove(env_key);
                self.stopping.remove(env_key);
            }
        }
        captured
    }

    pub(crate) async fn delete_function_resources(
        &self,
        store: &FunctionStore,
        region: &str,
        account: &str,
        name: &str,
    ) -> Result<(u16, Option<serde_json::Value>), LambdaError> {
        // ponytail: deletion pauses admission globally; per-function gates only if throughput needs it.
        let _drained = self.invocations.write().await;
        let resolved = crate::model::resolve_function_name(name, region)?;
        let arn = crate::model::function_arn(region, account, &resolved);
        self.invalidate_function_warm(&arn).await;
        let active: Vec<String> = self
            .environment_functions
            .iter()
            .filter(|entry| entry.value() == &arn)
            .map(|entry| entry.key().clone())
            .collect();
        for key in &active {
            self.stop_env(key).await;
        }
        let remaining: Vec<String> = active
            .into_iter()
            .filter(|key| self.owned_envs.contains_key(key))
            .collect();
        if !remaining.is_empty() {
            return Err(LambdaError::InternalError(format!(
                "function cleanup incomplete; retained environments: {}",
                remaining.join(", ")
            )));
        }
        self.code_store.remove(account, region, &resolved)?;
        let result = crate::control_plane::delete_function(store, region, account, name)?;
        let pool_prefix = format!("{arn}:");
        self.warm.retain(|key, _| !key.starts_with(&pool_prefix));
        Ok(result)
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
    use locallycloud_compute::runtime::{RuntimeError, TaskHandle, TaskState};
    use locallycloud_core::integration::logs::{
        AppendOutcome, GroupRef, InternalLogSink, SinkError, StreamRef,
    };
    use locallycloud_core::integration::metrics::MetricSink;
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
        async fn release_task(&self, _: &str) -> Result<(), RuntimeError> {
            Ok(())
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
            code_zip: Some(code.into()),
            dead_letter_arn: None,
            vpc_config: None,
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
    async fn memory_budget_evicts_warm_and_releases_after_shutdown_and_start_failure() {
        assert_eq!(Executor::parse_memory_budget(None).unwrap(), 1024);
        for invalid in ["0", "-1", "oops", "18446744073709551615"] {
            assert!(Executor::parse_memory_budget(Some(invalid)).is_err());
        }
        let broker = Arc::new(InvocationBroker::new());
        let mut exec = build_executor(broker, GuestBehavior::EchoUppercaseLen).await;
        exec.memory_budget_mb = 160; // 128 MiB guest + 32 MiB host overhead.
        let code = zip_with(&[("index.js", b"x")]);
        let first = func("nodejs22.x", 10, code.clone());
        let mut second = first.clone();
        second.function_name = "second".into();
        second.function_arn.push_str("-second");
        exec.invoke_sync("000000000000", "us-east-1", &first, b"{}".to_vec())
            .await
            .unwrap();
        let previous = exec.owned_envs.iter().next().unwrap().key().clone();
        exec.invoke_sync("000000000000", "us-east-1", &second, b"{}".to_vec())
            .await
            .unwrap();
        assert!(!exec.owned_envs.contains_key(&previous));
        assert_eq!(
            exec.memory_reservations
                .lock()
                .unwrap()
                .values()
                .sum::<u64>(),
            160
        );
        let oversized = {
            let mut function = first.clone();
            function.memory_size = 256;
            function
        };
        assert!(matches!(
            exec.invoke_sync("000000000000", "us-east-1", &oversized, b"{}".to_vec())
                .await,
            Err(LambdaError::TooManyRequests(_))
        ));
        assert!(exec.memory_reservations.lock().unwrap().is_empty());
        let invalid = func("provided.al2023", 10, code);
        assert!(exec
            .cold_start(
                "000000000000",
                "us-east-1",
                &invalid,
                invalid.code_zip.as_ref().unwrap()
            )
            .await
            .is_err());
        assert!(exec.memory_reservations.lock().unwrap().is_empty());
        exec.shutdown().await;
        assert!(exec.owned_envs.is_empty());
        assert!(exec.log_state.is_empty());
        assert!(exec.stopping.is_empty());
    }

    #[tokio::test]
    async fn function_deletion_cleans_owned_environments_and_rejects_stale_invocations() {
        let broker = Arc::new(InvocationBroker::new());
        let exec = Arc::new(build_executor(broker, GuestBehavior::EchoUppercaseLen).await);
        exec.bind_arc();
        let store = Arc::new(FunctionStore::new());
        exec.attach_function_store(&store);
        let function = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        store
            .create("000000000000", "us-east-1", function.clone())
            .unwrap();
        exec.invoke_sync("000000000000", "us-east-1", &function, b"{}".to_vec())
            .await
            .unwrap();
        assert_eq!(exec.owned_envs.len(), 1);
        exec.delete_function_resources(&store, "us-east-1", "000000000000", "fn")
            .await
            .unwrap();
        assert!(exec.owned_envs.is_empty());
        assert!(exec.warm.is_empty());
        let code_path = exec
            .rootfs_root
            .parent()
            .unwrap()
            .join("code/000000000000/us-east-1/fn");
        assert!(!code_path.exists());
        exec.return_warm("deleted-function:$LATEST", "released-environment", 0)
            .await;
        assert!(exec.warm.is_empty());
        assert!(exec.memory_reservations.lock().unwrap().is_empty());
        assert!(matches!(
            exec.invoke_sync("000000000000", "us-east-1", &function, b"{}".to_vec())
                .await,
            Err(LambdaError::ResourceNotFound(_))
        ));
        let mut recreated = function.clone();
        recreated.revision_id = "recreated".into();
        store
            .create("000000000000", "us-east-1", recreated.clone())
            .unwrap();
        assert!(matches!(
            exec.invoke_sync("000000000000", "us-east-1", &function, b"{}".to_vec())
                .await,
            Err(LambdaError::ResourceNotFound(_))
        ));
        exec.invoke_sync("000000000000", "us-east-1", &recreated, b"{}".to_vec())
            .await
            .unwrap();
        std::fs::remove_dir_all(&code_path).unwrap();
        std::fs::write(&code_path, b"cleanup obstruction").unwrap();
        assert!(exec
            .delete_function_resources(&store, "us-east-1", "000000000000", "fn")
            .await
            .is_err());
        assert!(store.get("000000000000", "us-east-1", "fn").is_some());
        std::fs::remove_file(&code_path).unwrap();
        exec.delete_function_resources(&store, "us-east-1", "000000000000", "fn")
            .await
            .unwrap();
        exec.shutdown().await;
    }

    #[tokio::test]
    async fn cancelled_invocation_releases_environment_and_budget() {
        let broker = Arc::new(InvocationBroker::new());
        let exec = Arc::new(build_executor(broker, GuestBehavior::Hang).await);
        exec.bind_arc();
        let function = func("nodejs22.x", 30, zip_with(&[("index.js", b"x")]));
        let running = {
            let exec = exec.clone();
            tokio::spawn(async move {
                exec.invoke_sync("000000000000", "us-east-1", &function, b"{}".to_vec())
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while exec.log_state.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        running.abort();
        let _ = running.await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !exec.owned_envs.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(exec.memory_reservations.lock().unwrap().is_empty());
        assert!(exec.environment_functions.is_empty());
        assert_eq!(exec.broker.inflight_count(), 0);
        exec.shutdown().await;
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

    struct StopRace {
        absent: Arc<AtomicBool>,
    }

    #[async_trait]
    impl ComputeRuntime for StopRace {
        async fn start_task(&self, _: &str, _: &TaskSpec) -> Result<TaskHandle, RuntimeError> {
            Err(RuntimeError::ExecutionFailed {
                reason: "nft: \"unsupported\"\nsecond line\\path".into(),
            })
        }

        async fn stop_task(&self, _: &str) -> Result<TaskHandle, RuntimeError> {
            Err(RuntimeError::ExecutionFailed {
                reason: "crun container does not exist".into(),
            })
        }

        async fn reconcile_orphaned_task(&self, _: &str) -> Result<bool, RuntimeError> {
            Ok(self.absent.load(Ordering::Acquire))
        }

        async fn release_task(&self, _: &str) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn get_output(&self, _: &str) -> Result<String, RuntimeError> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn stopped_guest_releases_vpc_only_after_absence_is_confirmed() {
        let tmp = std::env::temp_dir().join(format!("lc-stop-race-{}", Uuid::new_v4()));
        let absent = Arc::new(AtomicBool::new(false));
        let exec = Executor::new(
            Arc::new(InvocationBroker::new()),
            Arc::new(CodeStore::new(tmp.join("code"))),
            tmp.join("rootfs"),
            Arc::new(StopRace {
                absent: absent.clone(),
            }),
            "127.0.0.1:4566",
            "http://127.0.0.1:4566",
            "test",
            "test",
        );
        for env in ["late", "immediate"] {
            exec.reserve_rootfs(env).unwrap();
            std::fs::create_dir_all(exec.rootfs_root.join(env)).unwrap();
            exec.mark_rootfs_starting(env).unwrap();
            exec.mark_rootfs_running(env).unwrap();
            exec.vpc_public_egress.insert(env.into(), true);
            if env == "immediate" {
                absent.store(true, Ordering::Release);
            }
            exec.cleanup_failed_start(env, None).await;
            assert_eq!(exec.rootfs_root.join(env).exists(), env == "late");
            assert_eq!(exec.vpc_public_egress.contains_key(env), env == "late");
        }
        assert!(exec.owned_envs.contains_key("late"));
        exec.reap_expired_warm().await;
        assert!(!exec.owned_envs.contains_key("late"));
        assert!(!exec.rootfs_root.join("late").exists());
        assert!(!exec.vpc_public_egress.contains_key("late"));
        let function = func(
            "provided.al2023",
            10,
            zip_with(&[("bootstrap", b"#!/bin/sh\nexit 1\n")]),
        );
        let result = exec
            .invoke_sync("000000000000", "us-east-1", &function, b"{}".to_vec())
            .await
            .unwrap();
        match result.outcome {
            Outcome::Error { payload, .. } => {
                let error: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                assert!(error["errorMessage"]
                    .as_str()
                    .unwrap()
                    .contains("nft: \"unsupported\"\nsecond line\\path"));
            }
            outcome => panic!("Expected startup error, got {outcome:?}"),
        }
        assert_eq!(std::fs::read_dir(&exec.rootfs_root).unwrap().count(), 0);
        exec.reserve_rootfs("cleanup-failure").unwrap();
        std::os::unix::fs::symlink(&tmp, exec.rootfs_root.join("cleanup-failure")).unwrap();
        exec.cleanup_owned_rootfs("cleanup-failure");
        assert!(exec.owned_envs.contains_key("cleanup-failure"));
        assert!(exec.stopping.contains_key("cleanup-failure"));
        std::fs::remove_file(exec.rootfs_root.join("cleanup-failure")).unwrap();
        exec.reap_expired_warm().await;
        assert!(!exec.owned_envs.contains_key("cleanup-failure"));
        std::fs::remove_dir_all(tmp).unwrap();
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
        async fn release_task(&self, _: &str) -> Result<(), RuntimeError> {
            Ok(())
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
        assert!(error.to_string().contains("bootstrap"));
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

    struct TimeoutFenceGuest {
        guest: InProcessGuest,
        stopped: Arc<AtomicBool>,
    }

    #[async_trait]
    impl ComputeRuntime for TimeoutFenceGuest {
        async fn start_task(&self, id: &str, spec: &TaskSpec) -> Result<TaskHandle, RuntimeError> {
            self.stopped.store(false, Ordering::Release);
            self.guest.start_task(id, spec).await
        }
        async fn stop_task(&self, id: &str) -> Result<TaskHandle, RuntimeError> {
            self.stopped.store(true, Ordering::Release);
            self.guest.stop_task(id).await
        }
        async fn release_task(&self, _: &str) -> Result<(), RuntimeError> {
            Ok(())
        }
        async fn get_output(&self, _: &str) -> Result<String, RuntimeError> {
            assert!(
                self.stopped.load(Ordering::Acquire),
                "timed-out guest must stop before awaited log capture"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok("captured before timeout\n".into())
        }
    }

    #[tokio::test]
    async fn timeout_stops_before_log_capture_and_extension_grace() {
        let broker = Arc::new(InvocationBroker::new());
        let mut exec = build_executor(broker.clone(), GuestBehavior::Hang).await;
        let stopped = Arc::new(AtomicBool::new(false));
        exec.runtime = Arc::new(TimeoutFenceGuest {
            guest: InProcessGuest {
                behavior: GuestBehavior::Hang,
                starts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            },
            stopped: stopped.clone(),
        });
        let f = func("nodejs22.x", 1, zip_with(&[("index.js", b"x")]));
        let invocation_started = Instant::now();
        let result = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        assert!(
            invocation_started.elapsed().as_millis() >= u128::from(result.billed_duration_ms) + 80,
            "timeout log capture/cleanup must not accrue billed invoke duration"
        );
        assert!(matches!(result.outcome, Outcome::Error { .. }));
        assert!(stopped.load(Ordering::Acquire));
        assert!(exec.owned_envs.is_empty());
        // Registered extensions must receive shutdown notification without leaving
        // the timed-out handler alive for the normal two-second shutdown grace.
        let env = "timeout-extension";
        stopped.store(false, Ordering::Release);
        exec.reserve_rootfs(env).unwrap();
        std::fs::create_dir_all(exec.rootfs_root.join(env).join("tmp")).unwrap();
        exec.mark_rootfs_starting(env).unwrap();
        exec.mark_rootfs_running(env).unwrap();
        broker
            .discover_expected_extensions(env, vec!["extension".into()], "fn", "1", "handler")
            .unwrap();
        broker
            .register_extension(env, "extension", vec!["SHUTDOWN".into()])
            .unwrap();
        let captured = tokio::time::timeout(
            Duration::from_secs(1),
            exec.stop_env_reason_inner(env, "TIMEOUT", true),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(captured.0, "captured before timeout\n");
        assert!(stopped.load(Ordering::Acquire));
        assert!(!exec.owned_envs.contains_key(env));
    }

    #[derive(Default)]
    struct RecordingMetrics {
        observations: Mutex<Vec<MetricObservation>>,
    }

    impl MetricSink for RecordingMetrics {
        fn try_emit(&self, observations: Vec<MetricObservation>) -> EmitOutcome {
            self.observations.lock().unwrap().extend(observations);
            EmitOutcome::Accepted
        }
    }

    struct RejectingMetrics;

    impl MetricSink for RejectingMetrics {
        fn try_emit(&self, _observations: Vec<MetricObservation>) -> EmitOutcome {
            EmitOutcome::Full
        }
    }

    struct AcceptingLogs;

    #[async_trait]
    impl InternalLogSink for AcceptingLogs {
        async fn resolve_group(
            &self,
            _scope: LogScope,
            spec: ProducerGroupSpec,
            _context: ProducerContext,
        ) -> Result<GroupRef, SinkError> {
            Ok(GroupRef { name: spec.name })
        }
        async fn ensure_group(
            &self,
            _scope: LogScope,
            spec: ProducerGroupSpec,
            _context: ProducerContext,
        ) -> Result<GroupRef, SinkError> {
            Ok(GroupRef { name: spec.name })
        }
        async fn ensure_stream(
            &self,
            _scope: LogScope,
            group: GroupRef,
            spec: ProducerStreamSpec,
            _context: ProducerContext,
        ) -> Result<StreamRef, SinkError> {
            Ok(StreamRef {
                group_name: group.name,
                stream_name: spec.name,
            })
        }
        async fn append(
            &self,
            _scope: LogScope,
            _target: StreamRef,
            events: Vec<ProducerLogEvent>,
            _context: ProducerContext,
        ) -> Result<AppendOutcome, SinkError> {
            Ok(AppendOutcome {
                stored_events: events.len(),
            })
        }
    }

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

    fn observability_registry(metrics: Arc<dyn MetricSink>) -> Arc<ServiceRegistry> {
        use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};
        let registry = ServiceRegistry::with_known_services();
        registry.register_native_with_log_sink(
            ServiceName::new("logs"),
            ServiceMetadata::new(AwsProtocol::Json11, None),
            Arc::new(StubHandler),
            Arc::new(AcceptingLogs),
        );
        registry.register_native_with_metric_sink(
            ServiceName::new("monitoring"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            Arc::new(StubHandler),
            metrics,
        );
        registry
    }

    fn metric_values(observations: &[MetricObservation]) -> Vec<(String, f64)> {
        observations
            .iter()
            .map(|observation| (observation.metric_name.clone(), observation.value))
            .collect()
    }

    fn assert_lambda_metric_shape(observations: &[MetricObservation], request_id: &str) {
        for observation in observations {
            assert_eq!(observation.namespace, "AWS/Lambda");
            assert_eq!(observation.account_id, "000000000000");
            assert_eq!(observation.region, "us-east-1");
            assert_eq!(
                observation.dimensions,
                BTreeMap::from([("FunctionName".to_string(), "fn".to_string())])
            );
            assert_eq!(observation.correlation_id, request_id);
            assert_eq!(observation.storage_resolution, 60);
            assert_ne!(observation.origin, MetricOrigin::PublicPutMetricData);
            let expected_unit = if observation.metric_name == "Duration" {
                MetricUnit::Milliseconds
            } else {
                MetricUnit::Count
            };
            assert_eq!(observation.unit, Some(expected_unit));
        }
    }

    #[tokio::test]
    async fn successful_invoke_emits_vended_lambda_metrics() {
        let metrics = Arc::new(RecordingMetrics::default());
        let registry = observability_registry(metrics.clone());
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::EchoUppercaseLen)
            .await
            .with_service_registry(Arc::downgrade(&registry));
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let result = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        assert!(matches!(result.outcome, Outcome::Success(_)));
        let observations = metrics.observations.lock().unwrap().clone();
        let values = metric_values(&observations);
        assert_eq!(values[0], ("Invocations".to_string(), 1.0));
        assert_eq!(values[1], ("Errors".to_string(), 0.0));
        assert_eq!(values[2].0, "Duration");
        assert!(values[2].1 >= 0.0);
        assert_eq!(values.len(), 3);
        assert_lambda_metric_shape(&observations, result.request_id.as_deref().unwrap());
    }

    #[tokio::test]
    async fn function_error_emits_error_metric() {
        let metrics = Arc::new(RecordingMetrics::default());
        let registry = observability_registry(metrics.clone());
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::ReportError)
            .await
            .with_service_registry(Arc::downgrade(&registry));
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let result = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        assert!(matches!(result.outcome, Outcome::Error { .. }));
        let observations = metrics.observations.lock().unwrap().clone();
        let values = metric_values(&observations);
        assert_eq!(values[0], ("Invocations".to_string(), 1.0));
        assert_eq!(values[1], ("Errors".to_string(), 1.0));
        assert_eq!(values[2].0, "Duration");
        assert_lambda_metric_shape(&observations, result.request_id.as_deref().unwrap());
    }

    #[tokio::test]
    async fn rejected_metrics_do_not_fail_the_invocation() {
        let registry = observability_registry(Arc::new(RejectingMetrics));
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::EchoUppercaseLen)
            .await
            .with_service_registry(Arc::downgrade(&registry));
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let result = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        assert_eq!(result.outcome, Outcome::Success(b"{\"len\":2}".to_vec()));
    }

    #[tokio::test]
    async fn throttled_invoke_emits_throttle_metric() {
        use crate::service::LambdaHandler;
        use base64::Engine as _;
        use locallycloud_core::handler::{NativeHandler, ServiceRequest};

        let metrics = Arc::new(RecordingMetrics::default());
        let registry = observability_registry(metrics.clone());
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::EchoUppercaseLen)
            .await
            .with_service_registry(Arc::downgrade(&registry));
        let handler = LambdaHandler::with_executor(Arc::new(exec));
        let request = |method: http::Method, path: &str, body: Vec<u8>| ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers: http::HeaderMap::new(),
            body: bytes::Bytes::from(body),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "throttled-rid".into(),
        };
        let zip = zip_with(&[("index.js", b"x")]);
        let create = serde_json::json!({
            "FunctionName": "fn",
            "Role": "arn:aws:iam::000000000000:role/r",
            "Runtime": "nodejs22.x",
            "Handler": "index.handler",
            "Code": { "ZipFile": base64::engine::general_purpose::STANDARD.encode(&zip) }
        });
        let created = handler
            .handle(request(
                http::Method::POST,
                "/2015-03-31/functions",
                create.to_string().into_bytes(),
            ))
            .await;
        assert_eq!(created.status(), 201);
        let reserved = handler
            .handle(request(
                http::Method::PUT,
                "/2017-10-31/functions/fn/concurrency",
                br#"{"ReservedConcurrentExecutions":0}"#.to_vec(),
            ))
            .await;
        assert_eq!(reserved.status(), 200);
        let throttled = handler
            .handle(request(
                http::Method::POST,
                "/2015-03-31/functions/fn/invocations",
                b"{}".to_vec(),
            ))
            .await;
        assert_eq!(throttled.status(), 429);
        let observations = metrics.observations.lock().unwrap().clone();
        assert_eq!(
            metric_values(&observations),
            vec![("Throttles".to_string(), 1.0)]
        );
        assert_lambda_metric_shape(&observations, "throttled-rid");
    }

    #[tokio::test]
    async fn sync_invoke_continues_caller_trace_root() {
        let broker = Arc::new(InvocationBroker::new());
        let base = serve_runtime_api(broker.clone()).await;
        let tmp = std::env::temp_dir().join(format!("lc-exec-{}", Uuid::new_v4()));
        let traces = Arc::new(Mutex::new(Vec::new()));
        let exec = Executor::new(
            broker,
            Arc::new(CodeStore::new(tmp.join("code"))),
            tmp.join("rootfs"),
            Arc::new(TraceRecordingGuest {
                traces: traces.clone(),
            }),
            base,
            "http://127.0.0.1:4566",
            "test",
            "test",
        );
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let root = "Root=1-5759e988-bd862e3fe1be46a994272793";
        exec.invoke_sync_traced(
            "000000000000",
            "us-east-1",
            &f,
            b"{}".to_vec(),
            Some(&format!("{root};Parent=53995c3f42cd8ad8;Sampled=1")),
        )
        .await
        .unwrap();
        exec.invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        let traces = traces.lock().unwrap().clone();
        assert_eq!(traces.len(), 2);
        assert!(traces[0].starts_with(&format!("{root};Parent=")));
        assert!(traces[0].ends_with(";Sampled=0"));
        assert!(!traces[1].starts_with(root));
        assert!(traces[1].starts_with("Root=1-"));
        exec.shutdown().await;
    }

    /// A guest that records each invocation's `Lambda-Runtime-Trace-Id` header.
    struct TraceRecordingGuest {
        traces: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl ComputeRuntime for TraceRecordingGuest {
        async fn start_task(&self, id: &str, spec: &TaskSpec) -> Result<TaskHandle, RuntimeError> {
            let api = spec.env.get("AWS_LAMBDA_RUNTIME_API").cloned().unwrap();
            let traces = self.traces.clone();
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                loop {
                    let Ok(next) = client
                        .get(format!("http://{api}/2018-06-01/runtime/invocation/next"))
                        .send()
                        .await
                    else {
                        break;
                    };
                    if next.status() == 204 {
                        break;
                    }
                    let header = |name: &str| {
                        next.headers()
                            .get(name)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string()
                    };
                    let rid = header("Lambda-Runtime-Aws-Request-Id");
                    traces
                        .lock()
                        .unwrap()
                        .push(header("Lambda-Runtime-Trace-Id"));
                    let _ = client
                        .post(format!(
                            "http://{api}/2018-06-01/runtime/invocation/{rid}/response"
                        ))
                        .body("null")
                        .send()
                        .await;
                }
            });
            Ok(TaskHandle {
                task_id: id.to_string(),
                state: TaskState::Running,
            })
        }
        async fn stop_task(&self, id: &str) -> Result<TaskHandle, RuntimeError> {
            Ok(TaskHandle {
                task_id: id.to_string(),
                state: TaskState::Stopped,
            })
        }
        async fn release_task(&self, _: &str) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn get_output(&self, _id: &str) -> Result<String, RuntimeError> {
            Ok(String::new())
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
        use locallycloud_core::handler::{NativeHandler, ServiceRequest};

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
    #[tokio::test]
    async fn isolated_public_tcp_without_eni_route_is_closed() {
        use locallycloud_compute::youki::YoukiRuntime;
        let Some(runtime) = YoukiRuntime::discover() else {
            return;
        };
        if !std::process::Command::new("cc")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return;
        }
        let rootfs =
            std::env::temp_dir().join(format!("locallycloud-egress-deny-{}", Uuid::new_v4()));
        std::fs::create_dir_all(rootfs.join("bin")).unwrap();
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../compute/tests/fixtures/isolated_client.c");
        assert!(std::process::Command::new("cc")
            .args(["-static", "-O2"])
            .arg(source)
            .arg("-o")
            .arg(rootfs.join("bin/client"))
            .status()
            .unwrap()
            .success());
        let task_id = format!("public-deny-{}", Uuid::new_v4().simple());
        let port = 39000;
        let spec = TaskSpec {
            name: task_id.clone(),
            image: rootfs.display().to_string(),
            command: vec!["/bin/client".into(), port.to_string(), "8.8.8.8".into()],
            env: HashMap::new(),
            memory_mb: 128,
            vcpu_count: 1,
        };
        let (_, _loopback) = runtime
            .start_task_isolated_with_loopback(&task_id, &spec, &[port])
            .await
            .unwrap();
        let listener = runtime
            .bind_isolated_public_egress(&task_id, &[])
            .await
            .unwrap();
        let proxy = public_tcp_listener(
            listener,
            Arc::new(Ec2Handler::default()),
            "111111111111".into(),
            "us-east-1".into(),
            "eni-missing".into(),
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while runtime.task_state(&task_id).await.unwrap() == TaskState::Running {
            assert!(
                tokio::time::Instant::now() < deadline,
                "denied guest did not exit"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(!runtime
            .get_output(&task_id)
            .await
            .unwrap()
            .contains("isolated-loopback-ok"));
        proxy.abort();
        std::fs::remove_dir_all(rootfs).unwrap();
    }
}
