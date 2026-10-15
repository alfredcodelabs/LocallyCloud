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
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
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
use locallycloud_compute::runtime::{ComputeRuntime, RuntimeError, TaskSpec, TaskState};
use locallycloud_core::integration::correlation::CorrelationContext;
use locallycloud_core::integration::identity::CallerIdentity;
use locallycloud_core::integration::logs::{
    LogScope, ProducerContext, ProducerGroupSpec, ProducerLogEvent, ProducerStreamSpec,
};
use locallycloud_core::proxy::{forward_to_legacy, ProxyConfig};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use locallycloud_core::router::extract_service_from_credential_scope;
use locallycloud_ec2::{Ec2Handler, TaskNetworkLease};
use uuid::Uuid;

use crate::code_store::CodeStore;
use crate::error::LambdaError;
use crate::exec_env::{build_execution_env, ExecEnvInputs};
use crate::metrics::LambdaMetrics;
use crate::model::{FunctionStore, LambdaFunction, LayerStore, TracingMode};
use crate::rootfs::build_rootfs;
use crate::runtime_api::{FunctionErrorType, InitError, InvocationBroker, Outcome};

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
    concurrency: Mutex<Option<Arc<crate::concurrency::ConcurrencyLimiter>>>,
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
    /// Aggregates vended `AWS/Lambda` metrics; flushed lazily to Monitoring.
    metrics: LambdaMetrics,
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
    /// The on-demand Init limit ([`INIT_TIMEOUT`]; shortened by tests).
    init_timeout: Duration,
    /// Lambda's sampling rule for `Active` invocations without a caller decision.
    sampler: crate::trace_header::Sampler,
    /// Per-environment X-Ray daemon endpoints (address as seen by the guest, receiver task,
    /// sampled roots the receiver accepts). Created at cold start, closed when the environment
    /// stops.
    xray_daemons: DashMap<
        String,
        (
            SocketAddr,
            tokio::task::JoinHandle<()>,
            Arc<crate::xray_daemon::TraceRoots>,
        ),
    >,
}

/// The X-Ray daemon endpoint inside a VPC guest's network namespace: the guest-loopback
/// address that already serves AmazonProvidedDNS, on the daemon's default port.
const VPC_XRAY_DAEMON: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(169, 254, 169, 253), 2000);

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
    /// Invoke-phase duration in microseconds; it never includes Init.
    pub duration_us: u64,
    /// Billed milliseconds: the invoke phase plus, on a cold start, the Init phase, rounded
    /// up (no accrual while frozen).
    pub billed_duration_ms: u64,
    /// The Init phase of the environment, on the invocation that cold-started it.
    pub init: Option<InitReport>,
    /// Output a managed runtime produced during Init, emitted before `START`.
    pub init_logs: String,
}

/// `X-Amz-Log-Result` carries at most the last 4 KB of the invocation's log.
const LOG_TAIL_BYTES: usize = 4096;

impl InvokeResult {
    /// The CloudWatch Logs lines of this invocation, in order: Init output, `INIT_REPORT`
    /// (failed or timed-out Init), `START`, invocation output, `END`, `REPORT`.
    pub fn log_lines(&self, version: &str, memory_size: u32) -> Vec<String> {
        let Some(request_id) = self.request_id.as_deref() else {
            return self.logs.lines().map(str::to_owned).collect();
        };
        let mut lines =
            Vec::with_capacity(self.init_logs.lines().count() + self.logs.lines().count() + 4);
        lines.extend(self.init_logs.lines().map(str::to_owned));
        let init_status = self.init.as_ref().and_then(|init| match &init.status {
            InitStatus::Success => None,
            InitStatus::Timeout => Some("Status: timeout".to_string()),
            InitStatus::Error(error_type) => {
                Some(format!("Status: error\tError Type: {error_type}"))
            }
        });
        if let (Some(init), Some(status)) = (&self.init, &init_status) {
            lines.push(format!(
                "INIT_REPORT Init Duration: {} ms\tPhase: init\t{status}",
                format_ms(init.duration_us)
            ));
        }
        lines.push(format!("START RequestId: {request_id} Version: {version}"));
        lines.extend(self.logs.lines().map(str::to_owned));
        lines.push(format!("END RequestId: {request_id}"));
        let mut report = format!(
            "REPORT RequestId: {request_id}\tDuration: {} ms\tBilled Duration: {} ms\tMemory Size: {memory_size} MB",
            format_ms(self.duration_us),
            self.billed_duration_ms,
        );
        match self
            .init
            .as_ref()
            .map(|init| (&init.status, init.duration_us))
        {
            Some((InitStatus::Success, duration_us)) => {
                report.push_str(&format!("\tInit Duration: {} ms", format_ms(duration_us)));
            }
            Some((InitStatus::Error(error_type), _)) => {
                report.push_str(&format!("\tStatus: error\tError Type: {error_type}"));
            }
            Some((InitStatus::Timeout, _)) | None => {}
        }
        lines.push(report);
        lines
    }

    /// The `--log-type Tail` bytes: the last 4 KB of [`log_lines`](Self::log_lines).
    pub fn log_tail(&self, version: &str, memory_size: u32) -> Vec<u8> {
        let mut text = self.log_lines(version, memory_size).join("\n");
        text.push('\n');
        let bytes = text.into_bytes();
        bytes[bytes.len().saturating_sub(LOG_TAIL_BYTES)..].to_vec()
    }
}

/// Init-phase facts reported on the platform log lines of a cold start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitReport {
    pub duration_us: u64,
    pub status: InitStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitStatus {
    /// The runtime and extensions reached `Next`; `REPORT` carries `Init Duration`.
    Success,
    /// Init exceeded its 10 s limit and continued within the invocation.
    Timeout,
    /// Init failed with this error type; the invocation never reached the runtime.
    Error(String),
}

/// AWS limits the on-demand Init phase to 10 seconds.
const INIT_TIMEOUT: Duration = Duration::from_secs(10);

/// How often Init checks whether the guest task has already exited.
const GUEST_EXIT_POLL: Duration = Duration::from_millis(75);

#[derive(Debug)]
struct ColdStart {
    env_key: String,
    init: InitReport,
}

/// An environment whose Init failed after its guest launched.
#[derive(Debug)]
struct InitFailure {
    report: InitReport,
    /// Invoke response payload (`errorType`, `errorMessage`, ...).
    payload: Vec<u8>,
    logs: String,
    log_stream_name: String,
}

#[derive(Debug)]
enum ColdStartError {
    /// No runtime was launched (capacity, code, rootfs, network, or guest start).
    Failed(LambdaError),
    Init(InitFailure),
}

/// How long a failed Init with extensions waits for the supervisor's exit report.
const SUPERVISOR_REPORT_GRACE: Duration = Duration::from_secs(2);

/// The invoke response payload for a reported Init failure: the runtime's `ErrorRequest`
/// when it is a JSON object, otherwise a generated one.
fn init_failure_payload(reported: &InitError) -> Vec<u8> {
    let valid = serde_json::from_slice::<serde_json::Value>(&reported.payload)
        .is_ok_and(|value| value.is_object());
    if valid {
        reported.payload.clone()
    } else {
        init_error_payload(&reported.error_type, "Runtime failed to initialize")
    }
}

fn init_error_payload(error_type: &str, message: &str) -> Vec<u8> {
    serde_json::json!({"errorType": error_type, "errorMessage": message})
        .to_string()
        .into_bytes()
}

fn new_log_stream_name(version: &str) -> String {
    format!("{}/[{}]{}", today(), version, Uuid::new_v4().simple())
}

fn billed_ms(duration_us: u64, init: Option<&InitReport>) -> u64 {
    (duration_us + init.map_or(0, |init| init.duration_us)).div_ceil(1000)
}

/// Milliseconds with two decimals, as on Lambda platform log lines.
fn format_ms(us: u64) -> String {
    format!("{}.{:02}", us / 1000, us % 1000 / 10)
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
            concurrency: Mutex::new(None),
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
            metrics: LambdaMetrics::new(Weak::new()),
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
            init_timeout: INIT_TIMEOUT,
            sampler: crate::trace_header::Sampler::default(),
            xray_daemons: DashMap::new(),
        }
    }

    /// Attach the EC2 control plane used for real VPC ENI and endpoint policy.
    pub fn attach_ec2(&self, ec2: Arc<Ec2Handler>) {
        *self.ec2.lock().unwrap() = Some(ec2);
    }

    pub(crate) fn attach_concurrency(
        &self,
        concurrency: Arc<crate::concurrency::ConcurrencyLimiter>,
    ) {
        *self.concurrency.lock().unwrap() = Some(concurrency);
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

    pub(crate) fn metrics_recorder(&self) -> Arc<crate::metrics::MetricsRecorder> {
        self.metrics.recorder().clone()
    }

    /// Attach the shared service registry for lazy producer-log capability resolution.
    pub fn with_service_registry(mut self, registry: Weak<ServiceRegistry>) -> Self {
        self.metrics = LambdaMetrics::new(registry.clone());
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
    /// cold-starts one. After a success or a handler error the environment is frozen for
    /// reuse; after a timeout, crash, or runtime fault it is discarded.
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
        // The `AWS::Lambda` service segment covers routing, queuing and environment setup.
        let admitted_at = std::time::SystemTime::now();
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
        let concurrency = self
            .concurrency
            .lock()
            .map_err(|_| {
                LambdaError::InternalError("Lambda concurrency wiring lock poisoned".into())
            })?
            .clone();
        let _slot = concurrency
            .map(|limiter| {
                limiter.acquire(&func.function_arn).ok_or_else(|| {
                    self.publish_throttle_metric(account, region, func, "");
                    LambdaError::TooManyRequests(
                        "Rate Exceeded: concurrent execution limit reached".into(),
                    )
                })
            })
            .transpose()?;
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
        let (env_key, init) = match warm_env {
            Some(key) => (key, None),
            None => match self.cold_start(account, region, func, code).await {
                Ok(cold) => (cold.env_key, Some(cold.init)),
                Err(ColdStartError::Failed(e @ LambdaError::LocalCapacityExceeded(_))) => {
                    self.metrics.recorder().record_host_capacity(
                        account,
                        region,
                        &func.function_name,
                    );
                    tracing::warn!(account, region, function = %func.function_name, "local Lambda compute memory capacity exhausted");
                    return Err(e);
                }
                Err(ColdStartError::Failed(e)) => {
                    self.publish_invocation_metrics(account, region, func, true, None);
                    let request_id = Uuid::new_v4().to_string();
                    let result = InvokeResult {
                        outcome: Outcome::Error {
                            error_type: FunctionErrorType::Unhandled,
                            payload: serde_json::json!({"errorMessage": e.to_string()})
                                .to_string()
                                .into_bytes(),
                        },
                        logs: format!("RequestId: {request_id} Error: {e}\n"),
                        request_id: Some(request_id),
                        log_stream_name: Some(new_log_stream_name(&func.version)),
                        duration_us: 0,
                        billed_duration_ms: 0,
                        init: None,
                        init_logs: String::new(),
                    };
                    self.publish_invocation_logs(account, region, func, &result)
                        .await?;
                    return Ok(result);
                }
                Err(ColdStartError::Init(failure)) => {
                    // Errors=1 and no Duration: the invocation never reached the handler.
                    self.publish_invocation_metrics(account, region, func, true, None);
                    let result = InvokeResult {
                        outcome: Outcome::Error {
                            error_type: FunctionErrorType::Unhandled,
                            payload: failure.payload,
                        },
                        logs: String::new(),
                        request_id: Some(Uuid::new_v4().to_string()),
                        log_stream_name: Some(failure.log_stream_name),
                        duration_us: 0,
                        billed_duration_ms: billed_ms(0, Some(&failure.report)),
                        init: Some(failure.report),
                        init_logs: failure.logs,
                    };
                    self.publish_invocation_logs(account, region, func, &result)
                        .await?;
                    return Ok(result);
                }
            },
        };

        // Guest output already carries Init output for custom runtimes and extensions.
        let init_logs = self
            .broker
            .take_init_logs(&env_key)
            .filter(|_| {
                !self.broker.has_extensions(&env_key)
                    && !crate::rootfs::is_custom(func.runtime.as_deref())
            })
            .map(|chunks| chunks.concat())
            .unwrap_or_default();
        let mut environment_lease = self.environment_lease(&env_key);
        let timeout_ms = (func.timeout as i64) * 1000;
        let trace = crate::trace_header::invocation_trace(
            incoming_trace,
            func.tracing_mode,
            &self.sampler,
            &crate::model::function_arn(region, account, &func.function_name),
        );
        // The environment's daemon endpoint only forwards documents of roots it was handed;
        // admit this one before the runtime can see it. The guard finishes the root even if
        // this future is dropped (a disconnected caller).
        let admitted_root = self
            .xray_daemons
            .get(&env_key)
            .map(|daemon| daemon.value().2.clone())
            .filter(|_| trace.sampled)
            .map(|roots| crate::xray_daemon::AdmittedRoot::new(roots, &trace.root));
        let segment_start = std::time::SystemTime::now();
        let started = Instant::now();
        let (request_id, rx) = self.broker.submit_traced(
            &env_key,
            payload,
            &func.function_arn,
            timeout_ms,
            trace.header(),
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
        // Init that exceeded its limit continued inside this invocation: surface a late
        // `/init/error` (which stopped the environment) and the Init output posted late.
        let init_timed_out = init
            .as_ref()
            .is_some_and(|init| init.status == InitStatus::Timeout);
        let late_init_error = init_timed_out
            .then(|| self.broker.take_init_error(&env_key))
            .flatten();
        let late_init_logs = init_timed_out
            .then(|| self.broker.take_init_logs(&env_key))
            .flatten()
            .filter(|_| !crate::rootfs::is_custom(func.runtime.as_deref()));
        let outcome = match &late_init_error {
            Some(reported) => Outcome::Error {
                error_type: FunctionErrorType::Unhandled,
                payload: init_failure_payload(reported),
            },
            _ => outcome,
        };
        let init_logs = match &late_init_logs {
            Some(chunks) => init_logs + &chunks.concat(),
            None => init_logs,
        };
        // Duration covers the invoke phase only; Init ended before submission.
        let invoke_elapsed = timeout_elapsed.unwrap_or_else(|| started.elapsed());
        drop(admitted_root);
        let duration_us = invoke_elapsed.as_micros() as u64;
        self.publish_invocation_metrics(
            account,
            region,
            func,
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
        } else if late_init_error.is_some() && late_init_logs.is_some() && broker_logs.is_none() {
            // The guest output repeats the Init output already taken from the runtime.
            String::new()
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
            duration_us,
            billed_duration_ms: billed_ms(duration_us, init.as_ref()),
            init,
            init_logs,
        };
        if func.tracing_mode == TracingMode::Active && trace.sampled {
            self.emit_lambda_segments(
                account,
                region,
                func,
                &trace,
                admitted_at,
                (segment_start, invoke_elapsed),
                &result,
            );
        }

        // A handler error reported through `/invocation/{id}/error` leaves the runtime
        // running, so the environment is kept exactly as after a success; crashes, timeouts,
        // runtime faults and stops reset it.
        let reusable = matches!(
            result.outcome,
            Outcome::Success(_)
                | Outcome::Error {
                    error_type: FunctionErrorType::Reported,
                    ..
                }
        );
        if !reusable || !has_extensions {
            self.publish_invocation_logs(account, region, func, &result)
                .await?;
        }

        if reusable && has_extensions {
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
                    complete.duration_us = started.elapsed().as_micros() as u64;
                    complete.billed_duration_ms =
                        billed_ms(complete.duration_us, complete.init.as_ref());
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
        } else if reusable {
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

    /// Send the two segments Lambda records for a sampled `Active` invocation, in one call:
    /// - `AWS::Lambda` (the service): id `trace.service`, `parent_id` = the caller's `Parent`,
    ///   from request admission (`admitted_at`) until now, when the response is ready.
    /// - `AWS::Lambda::Function`: id = the `Parent` handed to the runtime, so SDK subsegments
    ///   (whose facade segment carries that id) attach to it; `parent_id` = the service
    ///   segment; it spans the invoke phase (`(start, elapsed)`, the same elapsed time
    ///   reported as `Duration`) and carries `fault` when the function failed.
    ///
    /// Delivery runs in the background and never delays the response.
    #[allow(clippy::too_many_arguments)]
    fn emit_lambda_segments(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        trace: &crate::trace_header::InvocationTrace,
        admitted_at: std::time::SystemTime,
        (start, elapsed): (std::time::SystemTime, Duration),
        result: &InvokeResult,
    ) {
        let epoch_seconds = |at: std::time::SystemTime| {
            at.duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_secs_f64())
                .unwrap_or_default()
        };
        let start_time = epoch_seconds(start);
        let end_time = start_time + elapsed.as_secs_f64();
        let mut service = serde_json::json!({
            "name": func.function_name,
            "id": trace.service,
            "trace_id": trace.root,
            "start_time": epoch_seconds(admitted_at),
            // The clocks differ (wall vs monotonic); never end before the function segment.
            "end_time": epoch_seconds(std::time::SystemTime::now()).max(end_time),
            "origin": "AWS::Lambda",
            "resource_arn": func.function_arn,
        });
        if let Some(request_id) = &result.request_id {
            service["aws"] = serde_json::json!({ "request_id": request_id });
        }
        if let Some(parent) = &trace.caller_parent {
            service["parent_id"] = serde_json::json!(parent);
        }
        let mut function = serde_json::json!({
            "name": func.function_name,
            "id": trace.parent,
            "parent_id": trace.service,
            "trace_id": trace.root,
            "start_time": start_time,
            "end_time": end_time,
            "origin": "AWS::Lambda::Function",
            "resource_arn": func.function_arn,
        });
        if matches!(result.outcome, Outcome::Error { .. }) {
            function["fault"] = serde_json::json!(true);
        }
        let registry = self.registry.clone();
        let account = account.to_owned();
        let region = region.to_owned();
        tokio::spawn(async move {
            crate::xray_daemon::put_trace_segments(
                &registry,
                &account,
                &region,
                vec![service.to_string(), function.to_string()],
            )
            .await;
        });
    }

    /// Close the X-Ray daemon endpoint of an environment, waiting until its socket is dropped.
    async fn stop_xray_daemon(&self, env_key: &str) {
        if let Some((_, (_, receiver, _))) = self.xray_daemons.remove(env_key) {
            receiver.abort();
            let _ = receiver.await;
        }
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
        let events = result
            .log_lines(&func.version, func.memory_size)
            .into_iter()
            .map(|message| ProducerLogEvent {
                timestamp_ms,
                message,
            })
            .collect();
        sink.append(scope, target, events, context)
            .await
            .map_err(|_| {
                LambdaError::InternalError("CloudWatch Logs event publication failed".into())
            })?;
        Ok(())
    }

    /// Record the vended `AWS/Lambda` Invocations, Errors, and Duration metrics for one
    /// invocation into the per-minute buckets. Delivery is best effort and never affects the
    /// invocation result.
    fn publish_invocation_metrics(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        errored: bool,
        duration_ms: Option<f64>,
    ) {
        self.metrics.recorder().record_invocation(
            account,
            region,
            &func.function_name,
            errored,
            duration_ms,
        );
    }

    /// Record the vended `AWS/Lambda` Throttles metric for a rejected invocation. Aggregated
    /// observations carry a per-batch correlation id, so the request id is not used.
    pub(crate) fn publish_throttle_metric(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        _correlation_id: &str,
    ) {
        self.metrics
            .recorder()
            .record_throttle(account, region, &func.function_name);
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
                None => return Err(LambdaError::LocalCapacityExceeded(
                    format!("Local compute memory budget exhausted ({required} MiB required, {} MiB budget). Reduce simultaneous work or increase LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB within available host RAM.", self.memory_budget_mb)
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
    ) -> Result<ColdStart, ColdStartError> {
        let env_key = format!("{}-{}", sanitize(&func.function_arn), Uuid::new_v4());
        self.reserve_memory(&env_key, u64::from(func.memory_size))
            .await
            .map_err(ColdStartError::Failed)?;
        self.environment_functions.insert(
            env_key.clone(),
            crate::model::function_arn(region, account, &func.function_name),
        );
        let mut lease = self.environment_lease(&env_key);
        let result = match self
            .cold_start_inner(account, region, func, code, env_key.clone())
            .await
        {
            Ok(launched) => self
                .complete_init(func, &env_key, launched)
                .await
                .map(|init| ColdStart {
                    env_key: env_key.clone(),
                    init,
                }),
            Err(error) => Err(ColdStartError::Failed(LambdaError::InternalError(error))),
        };
        if result.is_ok() {
            lease.armed = false;
        }
        if result.is_err() && !self.owned_envs.contains_key(&env_key) {
            self.environment_functions.remove(&env_key);
            self.memory_reservations.lock().unwrap().remove(&env_key);
        }
        result
    }

    async fn cold_start_inner(
        &self,
        account: &str,
        region: &str,
        func: &LambdaFunction,
        code: &[u8],
        env_key: String,
    ) -> Result<Instant, String> {
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
            )
            .await
            {
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
        let log_stream = new_log_stream_name(&func.version);
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
        // Every environment gets its own daemon endpoint (Lambda runs the daemon in both
        // tracing modes, and a caller-sampled `PassThrough` invocation still sends SDK
        // documents), bound before the guest starts: an ephemeral loopback port for guests in
        // the host netns, a fixed address inside the isolated netns of VPC guests (bound once
        // that netns exists).
        let mut xray_socket = None;
        let xray_endpoint = if vpc_launch.is_some() {
            SocketAddr::V4(VPC_XRAY_DAEMON)
        } else {
            let socket = match tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await {
                Ok(socket) => socket,
                Err(error) => {
                    self.cleanup_owned_rootfs(&env_key);
                    return Err(format!("X-Ray daemon endpoint unavailable: {error}"));
                }
            };
            let address = match socket.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    self.cleanup_owned_rootfs(&env_key);
                    return Err(format!("X-Ray daemon endpoint unavailable: {error}"));
                }
            };
            xray_socket = Some(socket);
            address
        };
        crate::exec_env::insert_xray_daemon_env(&mut env_map, xray_endpoint);
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
            match self
                .runtime
                .bind_isolated_udp(&env_key, *VPC_XRAY_DAEMON.ip(), VPC_XRAY_DAEMON.port())
                .await
            {
                Ok(socket) => xray_socket = Some(socket),
                Err(error) => {
                    self.cleanup_failed_start(&env_key, Some(lease)).await;
                    return Err(format!("VPC X-Ray daemon endpoint failed: {error}"));
                }
            }
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
        if let Some(socket) = xray_socket {
            let roots = Arc::new(crate::xray_daemon::TraceRoots::default());
            let receiver = crate::xray_daemon::serve(
                socket,
                roots.clone(),
                self.registry.clone(),
                account.to_owned(),
                region.to_owned(),
            );
            self.xray_daemons
                .insert(env_key.clone(), (xray_endpoint, receiver, roots));
        }
        // Init (and its 10 s limit) starts once the guest runs and, for VPC, its network
        // proxies are ready; emulator setup is not part of the Init phase.
        let launched = Instant::now();
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
        Ok(launched)
    }

    /// Wait for the Init phase of a launched environment: it ends when the runtime (and every
    /// extension) first calls `Next`. Init is limited to 10 s; past that, a runtime without
    /// extensions keeps initializing within the invocation, as Lambda retries Init with the
    /// function timeout.
    async fn complete_init(
        &self,
        func: &LambdaFunction,
        env_key: &str,
        launched: Instant,
    ) -> Result<InitReport, ColdStartError> {
        let has_extensions = self.broker.has_extensions(env_key);
        let deadline = tokio::time::Instant::from_std(launched + self.init_timeout);
        // A runtime that dies without reporting `/init/error` must fail Init at once.
        let waited = tokio::select! {
            biased;
            waited = self.broker.wait_init_ready(env_key, deadline) => Some(waited),
            () = self.wait_guest_exit(env_key) => None,
        };
        let duration_us = launched.elapsed().as_micros() as u64;
        let exited = waited.is_none();
        if let Some(Ok(())) = waited {
            return Ok(InitReport {
                duration_us,
                status: InitStatus::Success,
            });
        }
        // Any failure report stops the environment, so a live one past the deadline timed out.
        let timed_out =
            !exited && tokio::time::Instant::now() >= deadline && !self.broker.init_failed(env_key);
        if timed_out && !has_extensions {
            return Ok(InitReport {
                duration_us,
                status: InitStatus::Timeout,
            });
        }
        if has_extensions && !exited && !timed_out {
            // The supervisor reports an exit only after the process exited, so the process's
            // own error (runtime `/init/error`, extension error) is recorded before it.
            self.broker
                .wait_supervisor_exit(
                    env_key,
                    tokio::time::Instant::now() + SUPERVISOR_REPORT_GRACE,
                )
                .await;
        }
        let (status, payload) = match self.broker.take_init_error(env_key) {
            Some(reported) => {
                let payload = init_failure_payload(&reported);
                (InitStatus::Error(reported.error_type), payload)
            }
            None if timed_out => (
                InitStatus::Timeout,
                init_error_payload(
                    "Sandbox.Timedout",
                    "Init did not complete within the Init limit",
                ),
            ),
            None if has_extensions && !exited => (
                InitStatus::Error("Extension.Crash".to_owned()),
                init_error_payload("Extension.Crash", "extension initialization failed"),
            ),
            None => (
                InitStatus::Error("Runtime.ExitError".to_owned()),
                init_error_payload("Runtime.ExitError", "Runtime exited during Init"),
            ),
        };
        let init_logs = self.broker.take_init_logs(env_key);
        let log_stream_name = self
            .log_state
            .get(env_key)
            .map(|state| state.stream_name.clone());
        let reason = if timed_out { "TIMEOUT" } else { "FAILURE" };
        let captured = self.stop_env_reason_inner(env_key, reason, true).await;
        let managed = !has_extensions && !crate::rootfs::is_custom(func.runtime.as_deref());
        // A managed runtime that did not post its Init output keeps what the guest wrote.
        let logs = match init_logs {
            Some(chunks) if managed => chunks.concat(),
            _ => captured.map(|(logs, _)| logs).unwrap_or_default(),
        };
        Err(ColdStartError::Init(InitFailure {
            report: InitReport {
                duration_us,
                status,
            },
            payload,
            logs,
            log_stream_name: log_stream_name.unwrap_or_else(|| new_log_stream_name(&func.version)),
        }))
    }

    /// Resolve once the guest task is no longer running. Never resolves on backends that
    /// cannot report task state, which keeps the plain Init wait.
    async fn wait_guest_exit(&self, env_key: &str) {
        loop {
            tokio::time::sleep(GUEST_EXIT_POLL).await;
            match self.runtime.task_state(env_key).await {
                Ok(TaskState::Running) => {}
                Ok(_) | Err(RuntimeError::TaskNotFound { .. }) => return,
                Err(_) => std::future::pending().await,
            }
        }
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
        // Final best-effort flush; anything Monitoring cannot take now is retried by the
        // flush task or on drop.
        self.metrics.recorder().tick();
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
            self.stop_xray_daemon(env_key).await;
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
            self.stop_xray_daemon(env_key).await;
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
        let trace = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-amzn-trace-id"))
            .map(|(_, value)| value.as_str());
        let result = self
            .invoke_sync_traced(account, region, func, event, trace)
            .await?;
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
        incoming_trace: Option<&str>,
    ) {
        let total = config.max_retry_attempts.saturating_add(1); // initial + retries
        let mut invoke_count = 0u32;
        let mut last: Option<InvokeResult> = None;
        for attempt in 1..=total {
            invoke_count = attempt;
            match self
                .invoke_sync_traced(account, region, func, payload.clone(), incoming_trace)
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
    use locallycloud_core::integration::metrics::{
        EmitOutcome, MetricObservation, MetricOrigin, MetricSink, MetricUnit,
    };
    use std::collections::BTreeMap;
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
        /// Spend 300 ms in Init (like a slow import), then echo.
        SlowInit,
        /// Report `/init/error` with captured Init output and exit.
        InitError,
        /// Crash during Init: write to the console and exit without any Runtime API call.
        ExitDuringInit,
        /// Finish Init after 300 ms (past a shortened Init limit), then echo.
        LateInit,
        /// Report `/init/error` after 300 ms (past a shortened Init limit).
        LateInitError,
        /// Act as the extension supervisor reporting this process class exited during Init.
        SupervisorExit(&'static str),
        /// Report `call <n>` through `/invocation/{id}/error`, `n` counting the calls this
        /// runtime process served (module state); hang on the event `"hang"`. Also runs the
        /// `ext` extension when the rootfs has one.
        CountingError,
    }
    const GUEST_INIT_ERROR: &str = r#"{"errorType":"Runtime.ImportModuleError","errorMessage":"Error: Cannot find module 'index'","stackTrace":[]}"#;

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
            let has_extension = std::path::Path::new(&spec.image)
                .join("opt/extensions/ext")
                .exists();
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                match behavior {
                    GuestBehavior::SlowInit => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        let _ = client
                            .post(format!("http://{api}/2018-06-01/runtime/init/logs"))
                            .body(r#"["init output\n"]"#)
                            .send()
                            .await;
                    }
                    GuestBehavior::InitError => {
                        let _ = client
                            .post(format!("http://{api}/2018-06-01/runtime/init/logs"))
                            .body(r#"["init output\n","undefined\tERROR\tUncaught Exception\n"]"#)
                            .send()
                            .await;
                        let _ = client
                            .post(format!("http://{api}/2018-06-01/runtime/init/error"))
                            .header(
                                "Lambda-Runtime-Function-Error-Type",
                                "Runtime.ImportModuleError",
                            )
                            .body(GUEST_INIT_ERROR)
                            .send()
                            .await;
                        return;
                    }
                    GuestBehavior::ExitDuringInit => return,
                    GuestBehavior::LateInit | GuestBehavior::LateInitError => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        let _ = client
                            .post(format!("http://{api}/2018-06-01/runtime/init/logs"))
                            .body(r#"["late init output\n"]"#)
                            .send()
                            .await;
                        if matches!(behavior, GuestBehavior::LateInitError) {
                            let _ = client
                                .post(format!("http://{api}/2018-06-01/runtime/init/error"))
                                .header(
                                    "Lambda-Runtime-Function-Error-Type",
                                    "Runtime.ImportModuleError",
                                )
                                .body(GUEST_INIT_ERROR)
                                .send()
                                .await;
                            return;
                        }
                    }
                    GuestBehavior::SupervisorExit(exited) => {
                        let _ = client
                            .post(format!("http://{api}/locallycloud/supervisor/exit"))
                            .header("Locallycloud-Exited", exited)
                            .send()
                            .await;
                        return;
                    }
                    GuestBehavior::CountingError if has_extension => {
                        tokio::spawn(run_test_extension(client.clone(), api.clone()));
                    }
                    _ => {}
                }
                let mut calls = 0u32;
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
                        GuestBehavior::EchoUppercaseLen
                        | GuestBehavior::SlowInit
                        | GuestBehavior::InitError
                        | GuestBehavior::ExitDuringInit
                        | GuestBehavior::LateInit
                        | GuestBehavior::LateInitError
                        | GuestBehavior::SupervisorExit(_) => {
                            let body = format!("{{\"len\":{}}}", event.len());
                            let _ = client
                                .post(format!(
                                    "http://{api}/2018-06-01/runtime/invocation/{rid}/response"
                                ))
                                .body(body)
                                .send()
                                .await;
                        }
                        // Like the AWS clients, no `Lambda-Runtime-Function-Error-Type`.
                        GuestBehavior::ReportError => {
                            let _ = client
                                .post(format!(
                                    "http://{api}/2018-06-01/runtime/invocation/{rid}/error"
                                ))
                                .body(r#"{"errorMessage":"boom"}"#)
                                .send()
                                .await;
                        }
                        GuestBehavior::CountingError => {
                            calls += 1;
                            if event == "\"hang\"" {
                                tokio::time::sleep(Duration::from_secs(30)).await;
                                continue;
                            }
                            let _ = client
                                .post(format!(
                                    "http://{api}/2018-06-01/runtime/invocation/{rid}/error"
                                ))
                                .body(format!(
                                    r#"{{"errorType":"Error","errorMessage":"call {calls}"}}"#
                                ))
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
            match self.behavior {
                GuestBehavior::ExitDuringInit => Ok("Segmentation fault\n".into()),
                _ => Ok(String::new()),
            }
        }

        async fn task_state(&self, _id: &str) -> Result<TaskState, RuntimeError> {
            match self.behavior {
                GuestBehavior::ExitDuringInit => Ok(TaskState::Failed),
                _ => Ok(TaskState::Running),
            }
        }
    }

    /// The `ext` external extension: register, then poll `event/next` until `SHUTDOWN`.
    async fn run_test_extension(client: reqwest::Client, api: String) {
        let Ok(registered) = client
            .post(format!("http://{api}/2020-01-01/extension/register"))
            .header("Lambda-Extension-Name", "ext")
            .body(r#"{"events":["INVOKE","SHUTDOWN"]}"#)
            .send()
            .await
        else {
            return;
        };
        let Some(id) = registered
            .headers()
            .get("Lambda-Extension-Identifier")
            .cloned()
        else {
            return;
        };
        loop {
            let Ok(next) = client
                .get(format!("http://{api}/2020-01-01/extension/event/next"))
                .header("Lambda-Extension-Identifier", id.clone())
                .send()
                .await
            else {
                return;
            };
            if next.status() != 200 {
                return;
            }
            let event: serde_json::Value = next.json().await.unwrap_or_default();
            if event["eventType"] == "SHUTDOWN" {
                return;
            }
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
            tracing_mode: crate::model::TracingMode::PassThrough,
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
            Err(LambdaError::LocalCapacityExceeded(_))
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
                .unwrap()
                .env_key;
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
        let ColdStartError::Failed(error) = error else {
            panic!("expected a failed start, got {error:?}");
        };
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
                assert_eq!(error_type, FunctionErrorType::Reported);
                assert_eq!(error_type.as_str(), "Unhandled");
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

    fn reported_call(result: &InvokeResult) -> String {
        let Outcome::Error {
            error_type: FunctionErrorType::Reported,
            payload,
        } = &result.outcome
        else {
            panic!(
                "expected a reported function error, got {:?}",
                result.outcome
            );
        };
        let payload: serde_json::Value = serde_json::from_slice(payload).unwrap();
        payload["errorMessage"].as_str().unwrap().to_owned()
    }

    /// A handler error reported through `/invocation/{id}/error` keeps the environment: the
    /// runtime's state survives, Init runs once, and only the first `REPORT` has
    /// `Init Duration`. With an extension the environment is reused after the rearm wait.
    #[tokio::test]
    async fn reported_function_error_keeps_environment_warm() {
        let mut cases = vec![false];
        if crate::rootfs::find_host_executable("bash").is_some() {
            cases.push(true);
        }
        for with_extension in cases {
            let logs = Arc::new(RecordingLogs::default());
            let registry = observability_registry_with_logs(
                Arc::new(RecordingMetrics::default()),
                logs.clone(),
            );
            let broker = Arc::new(InvocationBroker::new());
            let (exec, starts) =
                build_executor_tracked(broker.clone(), GuestBehavior::CountingError).await;
            let mut f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
            let exec = if with_extension {
                with_extension_layer(exec, &mut f)
            } else {
                exec
            }
            .with_service_registry(Arc::downgrade(&registry));
            let mut results = Vec::new();
            for _ in 0..3 {
                results.push(
                    exec.invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
                        .await
                        .unwrap(),
                );
            }
            let calls: Vec<String> = results.iter().map(reported_call).collect();
            assert_eq!(calls, ["call 1", "call 2", "call 3"], "{with_extension}");
            assert_eq!(starts.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert!(results[0].init.is_some());
            assert!(results[1..].iter().all(|result| result.init.is_none()));
            let stream = results[0].log_stream_name.clone().unwrap();
            assert!(results
                .iter()
                .all(|result| result.log_stream_name.as_deref() == Some(stream.as_str())));
            let messages = stream_messages(&logs, &stream);
            for (index, result) in results.iter().enumerate() {
                let id = result.request_id.clone().unwrap();
                let report = messages
                    .iter()
                    .find(|message| message.starts_with(&format!("REPORT RequestId: {id}\t")))
                    .unwrap_or_else(|| panic!("no REPORT for {id}: {messages:?}"));
                assert_eq!(report.contains("\tInit Duration: "), index == 0, "{report}");
                assert!(!report.contains("Status:"), "{report}");
            }
            assert_eq!(exec.owned_envs.len(), 1);
            let env_key = exec.owned_envs.iter().next().unwrap().key().clone();
            assert_eq!(broker.has_extensions(&env_key), with_extension);
        }
    }

    /// A timeout still resets the environment: the next invocation runs Init again in a new
    /// runtime process.
    #[tokio::test]
    async fn timeout_after_reported_error_resets_environment() {
        let broker = Arc::new(InvocationBroker::new());
        let (exec, starts) = build_executor_tracked(broker, GuestBehavior::CountingError).await;
        let f = func("nodejs22.x", 1, zip_with(&[("index.js", b"x")]));
        let invoke = |payload: &'static [u8]| {
            exec.invoke_sync("000000000000", "us-east-1", &f, payload.to_vec())
        };
        assert_eq!(reported_call(&invoke(b"{}").await.unwrap()), "call 1");
        assert_eq!(reported_call(&invoke(b"{}").await.unwrap()), "call 2");
        let timed_out = invoke(b"\"hang\"").await.unwrap();
        assert!(matches!(
            timed_out.outcome,
            Outcome::Error {
                error_type: FunctionErrorType::Unhandled,
                ..
            }
        ));
        let after = invoke(b"{}").await.unwrap();
        assert_eq!(reported_call(&after), "call 1");
        assert!(after.init.is_some());
        assert_eq!(starts.load(std::sync::atomic::Ordering::SeqCst), 2);
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

    /// Records every appended event as `(group, stream, message)`.
    #[derive(Default)]
    struct RecordingLogs {
        events: Mutex<Vec<(String, String, String)>>,
    }
    #[async_trait]
    impl InternalLogSink for RecordingLogs {
        async fn resolve_group(
            &self,
            scope: LogScope,
            spec: ProducerGroupSpec,
            context: ProducerContext,
        ) -> Result<GroupRef, SinkError> {
            AcceptingLogs.resolve_group(scope, spec, context).await
        }
        async fn ensure_group(
            &self,
            scope: LogScope,
            spec: ProducerGroupSpec,
            context: ProducerContext,
        ) -> Result<GroupRef, SinkError> {
            AcceptingLogs.ensure_group(scope, spec, context).await
        }
        async fn ensure_stream(
            &self,
            scope: LogScope,
            group: GroupRef,
            spec: ProducerStreamSpec,
            context: ProducerContext,
        ) -> Result<StreamRef, SinkError> {
            AcceptingLogs
                .ensure_stream(scope, group, spec, context)
                .await
        }
        async fn append(
            &self,
            _scope: LogScope,
            target: StreamRef,
            events: Vec<ProducerLogEvent>,
            _context: ProducerContext,
        ) -> Result<AppendOutcome, SinkError> {
            let stored_events = events.len();
            self.events
                .lock()
                .unwrap()
                .extend(events.into_iter().map(|event| {
                    (
                        target.group_name.clone(),
                        target.stream_name.clone(),
                        event.message,
                    )
                }));
            Ok(AppendOutcome { stored_events })
        }
    }
    fn observability_registry(metrics: Arc<dyn MetricSink>) -> Arc<ServiceRegistry> {
        observability_registry_with_logs(metrics, Arc::new(AcceptingLogs))
    }
    fn observability_registry_with_logs(
        metrics: Arc<dyn MetricSink>,
        logs: Arc<dyn InternalLogSink>,
    ) -> Arc<ServiceRegistry> {
        use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};
        let registry = ServiceRegistry::with_known_services();
        registry.register_native_with_log_sink(
            ServiceName::new("logs"),
            ServiceMetadata::new(AwsProtocol::Json11, None),
            Arc::new(StubHandler),
            logs,
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

    /// Flush the aggregated metric buckets as the periodic task would.
    fn flush_metrics(exec: &Executor) {
        exec.metrics.recorder().tick();
    }

    fn assert_lambda_metric_shape(observations: &[MetricObservation]) {
        let correlation = observations
            .first()
            .map(|observation| observation.correlation_id.clone())
            .unwrap_or_default();
        assert!(correlation.starts_with("lambda-metrics:"));
        for observation in observations {
            assert_eq!(observation.timestamp_ms % 60_000, 0);
            assert_eq!(observation.namespace, "AWS/Lambda");
            assert_eq!(observation.account_id, "000000000000");
            assert_eq!(observation.region, "us-east-1");
            assert_eq!(
                observation.dimensions,
                BTreeMap::from([("FunctionName".to_string(), "fn".to_string())])
            );
            assert_eq!(observation.correlation_id, correlation);
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
    async fn sync_async_and_function_urls_share_execution_admission() {
        let metrics = Arc::new(RecordingMetrics::default());
        let registry = observability_registry(metrics.clone());
        let exec = build_executor(
            Arc::new(InvocationBroker::new()),
            GuestBehavior::EchoUppercaseLen,
        )
        .await
        .with_service_registry(Arc::downgrade(&registry));
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let limiter = crate::concurrency::ConcurrencyLimiter::with_config(
            locallycloud_core::config::LambdaConcurrencyConfig::new(10, 2).unwrap(),
        );
        limiter.set_reserved(&f.function_arn, 0);
        exec.attach_concurrency(limiter);
        assert!(matches!(
            exec.invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
                .await,
            Err(LambdaError::TooManyRequests(_))
        ));
        let url = crate::function_url::UrlRequest {
            method: "GET".into(),
            raw_path: "/".into(),
            raw_query: String::new(),
            headers: Default::default(),
            body: Vec::new(),
            region: "us-east-1".into(),
            url_id: "url-quota".into(),
            account: "000000000000".into(),
            request_id: "url-quota".into(),
        };
        assert!(matches!(
            exec.invoke_url("000000000000", "us-east-1", &f, url).await,
            Err(LambdaError::TooManyRequests(_))
        ));
        exec.invoke_async(
            "000000000000",
            "us-east-1",
            &f,
            b"{}".to_vec(),
            &AsyncConfig {
                max_retry_attempts: 0,
                on_success_arn: None,
                on_failure_arn: None,
            },
            None,
        )
        .await;
        flush_metrics(&exec);
        let points = metrics.observations.lock().unwrap();
        assert_eq!(
            points
                .iter()
                .filter(|point| point.metric_name == "Throttles")
                .map(|point| point.value)
                .sum::<f64>(),
            3.0
        );
        assert!(points
            .iter()
            .all(|point| point.metric_name != "Invocations"));
        assert!(exec.owned_envs.is_empty());
    }

    #[tokio::test]
    async fn host_capacity_rejection_does_not_publish_aws_throttles() {
        let metrics = Arc::new(RecordingMetrics::default());
        let registry = observability_registry(metrics.clone());
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::EchoUppercaseLen)
            .await
            .with_service_registry(Arc::downgrade(&registry))
            .with_memory_budget(1);
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let error = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap_err();
        assert!(
            matches!(&error, LambdaError::LocalCapacityExceeded(message) if message.contains("LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB"))
        );
        let response = error.into_response("capacity-test");
        assert_eq!(response.status(), 503);
        assert_eq!(
            response.headers()["x-amzn-errortype"],
            "LocalCapacityExceededException"
        );
        flush_metrics(&exec);
        let observations = metrics.observations.lock().unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].namespace, "LocallyCloud/Lambda");
        assert_eq!(observations[0].metric_name, "HostCapacityExceeded");
        assert_eq!(observations[0].value, 1.0);
        assert!(exec.memory_reservations.lock().unwrap().is_empty());
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
        flush_metrics(&exec);
        let observations = metrics.observations.lock().unwrap().clone();
        let values = metric_values(&observations);
        assert_eq!(values[0], ("Invocations".to_string(), 1.0));
        assert_eq!(values[1], ("Errors".to_string(), 0.0));
        assert_eq!(values[2].0, "Duration");
        assert!(values[2].1 >= 0.0);
        assert_eq!(values.len(), 3);
        assert_lambda_metric_shape(&observations);
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
        flush_metrics(&exec);
        let observations = metrics.observations.lock().unwrap().clone();
        let values = metric_values(&observations);
        assert_eq!(values[0], ("Invocations".to_string(), 1.0));
        assert_eq!(values[1], ("Errors".to_string(), 1.0));
        assert_eq!(values[2].0, "Duration");
        assert_lambda_metric_shape(&observations);
    }

    #[tokio::test]
    async fn timeout_emits_error_metric_and_timeout_duration() {
        let metrics = Arc::new(RecordingMetrics::default());
        let registry = observability_registry(metrics.clone());
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::Hang)
            .await
            .with_service_registry(Arc::downgrade(&registry));
        let f = func("nodejs22.x", 1, zip_with(&[("index.js", b"x")]));
        let result = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        assert!(matches!(result.outcome, Outcome::Error { .. }));
        flush_metrics(&exec);
        let observations = metrics.observations.lock().unwrap().clone();
        let values = metric_values(&observations);
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], ("Invocations".to_string(), 1.0));
        assert_eq!(values[1], ("Errors".to_string(), 1.0));
        assert_eq!(values[2].0, "Duration");
        assert!(
            (1000.0..1500.0).contains(&values[2].1),
            "timeout Duration should match the 1s timeout, got {}",
            values[2].1
        );
        assert_lambda_metric_shape(&observations);
    }

    #[tokio::test]
    async fn failed_cold_start_emits_error_metric_without_duration() {
        let metrics = Arc::new(RecordingMetrics::default());
        let registry = observability_registry(metrics.clone());
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::EchoUppercaseLen)
            .await
            .with_service_registry(Arc::downgrade(&registry));
        // A custom runtime without `bootstrap` fails before any guest starts.
        let f = func("provided.al2", 10, zip_with(&[("index.js", b"x")]));
        let result = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        assert!(matches!(result.outcome, Outcome::Error { .. }));
        flush_metrics(&exec);
        let observations = metrics.observations.lock().unwrap().clone();
        assert_eq!(
            metric_values(&observations),
            vec![
                ("Invocations".to_string(), 1.0),
                ("Errors".to_string(), 1.0)
            ]
        );
        assert_lambda_metric_shape(&observations);
    }

    fn stream_messages(logs: &RecordingLogs, stream: &str) -> Vec<String> {
        logs.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(group, name, _)| group == "/aws/lambda/fn" && name == stream)
            .map(|(_, _, message)| message.clone())
            .collect()
    }

    /// Init (a 300 ms import) is measured once, reported only on the cold-start `REPORT`,
    /// billed, and kept out of Duration and the `AWS/Lambda` Duration metric.
    #[tokio::test]
    async fn slow_init_is_reported_once_and_excluded_from_duration() {
        let metrics = Arc::new(RecordingMetrics::default());
        let logs = Arc::new(RecordingLogs::default());
        let registry = observability_registry_with_logs(metrics.clone(), logs.clone());
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::SlowInit)
            .await
            .with_service_registry(Arc::downgrade(&registry));
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let cold = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        let warm = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        assert!(matches!(cold.outcome, Outcome::Success(_)));
        assert!(matches!(warm.outcome, Outcome::Success(_)));
        let init = cold.init.clone().unwrap();
        assert_eq!(init.status, InitStatus::Success);
        assert!(init.duration_us >= 300_000, "{init:?}");
        assert!(cold.duration_us < 300_000, "{}", cold.duration_us);
        assert_eq!(
            cold.billed_duration_ms,
            (cold.duration_us + init.duration_us).div_ceil(1000)
        );
        assert!(warm.init.is_none());
        assert_eq!(warm.billed_duration_ms, warm.duration_us.div_ceil(1000));
        assert_eq!(cold.log_stream_name, warm.log_stream_name);

        let messages = stream_messages(&logs, cold.log_stream_name.as_deref().unwrap());
        let cold_id = cold.request_id.clone().unwrap();
        let warm_id = warm.request_id.clone().unwrap();
        assert_eq!(messages[0], "init output");
        assert_eq!(
            messages[1],
            format!("START RequestId: {cold_id} Version: $LATEST")
        );
        let report = |id: &str| {
            messages
                .iter()
                .find(|message| message.starts_with(&format!("REPORT RequestId: {id}\t")))
                .unwrap()
                .clone()
        };
        assert_eq!(
            report(&cold_id),
            format!(
                "REPORT RequestId: {cold_id}\tDuration: {} ms\tBilled Duration: {} ms\tMemory Size: 128 MB\tInit Duration: {} ms",
                format_ms(cold.duration_us),
                cold.billed_duration_ms,
                format_ms(init.duration_us)
            )
        );
        assert!(!report(&warm_id).contains("Init Duration"));
        assert_eq!(messages.iter().filter(|m| *m == "init output").count(), 1);
        // `--log-type Tail` shows the import-time output and platform lines of the cold start.
        let tail = String::from_utf8(cold.log_tail("$LATEST", 128)).unwrap();
        assert!(
            tail.starts_with("init output\nSTART RequestId: "),
            "{tail:?}"
        );
        assert!(
            tail.ends_with(&format!("{}\n", report(&cold_id))),
            "{tail:?}"
        );
        assert!(!String::from_utf8(warm.log_tail("$LATEST", 128))
            .unwrap()
            .contains("init output"));

        flush_metrics(&exec);
        let observations = metrics.observations.lock().unwrap().clone();
        let durations: Vec<f64> = observations
            .iter()
            .filter(|observation| observation.metric_name == "Duration")
            .map(|observation| observation.value)
            .collect();
        assert!(!durations.is_empty());
        assert!(
            durations.iter().all(|value| *value < 300.0),
            "{durations:?}"
        );
    }

    /// An Init failure returns the runtime's error as an `Unhandled` function error and
    /// writes the Init output, `INIT_REPORT`, and the invocation lines to a log stream.
    #[tokio::test]
    async fn init_error_is_returned_and_logged() {
        let metrics = Arc::new(RecordingMetrics::default());
        let logs = Arc::new(RecordingLogs::default());
        let registry = observability_registry_with_logs(metrics.clone(), logs.clone());
        let broker = Arc::new(InvocationBroker::new());
        let (exec, starts) = build_executor_tracked(broker.clone(), GuestBehavior::InitError).await;
        let exec = exec.with_service_registry(Arc::downgrade(&registry));
        let mut f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        f.environment
            .insert("SECRET_SETTING".into(), "do-not-log".into());
        let result = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        assert_eq!(
            result.outcome,
            Outcome::Error {
                error_type: FunctionErrorType::Unhandled,
                payload: GUEST_INIT_ERROR.as_bytes().to_vec(),
            }
        );
        let request_id = result.request_id.clone().unwrap();
        let stream = result.log_stream_name.clone().unwrap();
        let messages = stream_messages(&logs, &stream);
        let init = result.init.clone().unwrap();
        assert_eq!(
            init.status,
            InitStatus::Error("Runtime.ImportModuleError".into())
        );
        assert_eq!(
            messages,
            vec![
                "init output".to_string(),
                "undefined\tERROR\tUncaught Exception".to_string(),
                format!(
                    "INIT_REPORT Init Duration: {} ms\tPhase: init\tStatus: error\tError Type: Runtime.ImportModuleError",
                    format_ms(init.duration_us)
                ),
                format!("START RequestId: {request_id} Version: $LATEST"),
                format!("END RequestId: {request_id}"),
                format!(
                    "REPORT RequestId: {request_id}\tDuration: 0.00 ms\tBilled Duration: {} ms\tMemory Size: 128 MB\tStatus: error\tError Type: Runtime.ImportModuleError",
                    result.billed_duration_ms
                ),
            ]
        );
        // `--log-type Tail` carries the same lines, including the Init error.
        assert_eq!(
            String::from_utf8(result.log_tail("$LATEST", 128)).unwrap(),
            format!("{}\n", messages.join("\n"))
        );
        assert!(logs
            .events
            .lock()
            .unwrap()
            .iter()
            .all(|(_, _, message)| !message.contains("do-not-log")));
        // The failed environment is discarded; the next invocation starts a new one.
        assert!(exec.owned_envs.is_empty());
        assert_eq!(broker.inflight_count(), 0);
        let again = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        assert!(matches!(again.outcome, Outcome::Error { .. }));
        assert_eq!(starts.load(Ordering::SeqCst), 2);

        flush_metrics(&exec);
        let observations = metrics.observations.lock().unwrap().clone();
        assert_eq!(
            metric_values(&observations),
            vec![
                ("Invocations".to_string(), 2.0),
                ("Errors".to_string(), 2.0)
            ]
        );
    }

    /// A runtime that dies during Init without `/init/error` fails at once as
    /// `Runtime.ExitError`, not after the Init limit plus the function timeout.
    #[tokio::test]
    async fn runtime_exit_during_init_fails_promptly() {
        let logs = Arc::new(RecordingLogs::default());
        let registry =
            observability_registry_with_logs(Arc::new(RecordingMetrics::default()), logs.clone());
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker.clone(), GuestBehavior::ExitDuringInit)
            .await
            .with_service_registry(Arc::downgrade(&registry));
        let f = func("nodejs22.x", 30, zip_with(&[("index.js", b"x")]));
        let started = Instant::now();
        let result = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        let Outcome::Error {
            error_type: FunctionErrorType::Unhandled,
            payload,
        } = &result.outcome
        else {
            panic!("unexpected outcome {:?}", result.outcome);
        };
        let payload: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert_eq!(payload["errorType"], "Runtime.ExitError");
        let init = result.init.clone().unwrap();
        assert_eq!(init.status, InitStatus::Error("Runtime.ExitError".into()));
        let request_id = result.request_id.clone().unwrap();
        let messages = stream_messages(&logs, &result.log_stream_name.clone().unwrap());
        assert_eq!(
            messages,
            vec![
                "Segmentation fault".to_string(),
                format!(
                    "INIT_REPORT Init Duration: {} ms\tPhase: init\tStatus: error\tError Type: Runtime.ExitError",
                    format_ms(init.duration_us)
                ),
                format!("START RequestId: {request_id} Version: $LATEST"),
                format!("END RequestId: {request_id}"),
                format!(
                    "REPORT RequestId: {request_id}\tDuration: 0.00 ms\tBilled Duration: {} ms\tMemory Size: 128 MB\tStatus: error\tError Type: Runtime.ExitError",
                    result.billed_duration_ms
                ),
            ]
        );
        assert!(exec.owned_envs.is_empty());
        assert_eq!(broker.inflight_count(), 0);
    }

    /// Past the Init limit, Init continues inside the invocation: Init output posted late is
    /// still emitted, and a late `/init/error` returns the runtime's own payload.
    #[tokio::test]
    async fn late_init_after_timeout_keeps_output_and_error() {
        for behavior in [GuestBehavior::LateInit, GuestBehavior::LateInitError] {
            let logs = Arc::new(RecordingLogs::default());
            let registry = observability_registry_with_logs(
                Arc::new(RecordingMetrics::default()),
                logs.clone(),
            );
            let broker = Arc::new(InvocationBroker::new());
            let mut exec = build_executor(broker.clone(), behavior)
                .await
                .with_service_registry(Arc::downgrade(&registry));
            exec.init_timeout = Duration::from_millis(100);
            let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
            let result = exec
                .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
                .await
                .unwrap();
            let init = result.init.clone().unwrap();
            assert_eq!(init.status, InitStatus::Timeout);
            if matches!(behavior, GuestBehavior::LateInitError) {
                assert_eq!(
                    result.outcome,
                    Outcome::Error {
                        error_type: FunctionErrorType::Unhandled,
                        payload: GUEST_INIT_ERROR.as_bytes().to_vec(),
                    }
                );
            } else {
                assert!(matches!(result.outcome, Outcome::Success(_)));
            }
            let messages = stream_messages(&logs, &result.log_stream_name.clone().unwrap());
            assert_eq!(messages[0], "late init output", "{messages:?}");
            assert_eq!(
                messages[1],
                format!(
                    "INIT_REPORT Init Duration: {} ms\tPhase: init\tStatus: timeout",
                    format_ms(init.duration_us)
                )
            );
            assert_eq!(
                messages.iter().filter(|m| *m == "late init output").count(),
                1
            );
            assert_eq!(broker.inflight_count(), 0);
            exec.shutdown().await;
            assert!(exec.owned_envs.is_empty());
        }
    }

    /// Attach a layer holding one executable external extension to `f`.
    fn with_extension_layer(exec: Executor, f: &mut LambdaFunction) -> Executor {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
            zw.start_file("extensions/ext", opts).unwrap();
            zw.write_all(b"#!/bin/sh\n").unwrap();
            zw.finish().unwrap();
        }
        let layers = Arc::new(LayerStore::new());
        let published = layers.publish(
            "000000000000",
            "us-east-1",
            "ext",
            crate::model::LayerVersion {
                version: 0,
                description: String::new(),
                created_date: "now".into(),
                code_sha256: "x".into(),
                code_size: buf.len() as u64,
                code_zip: buf,
                compatible_runtimes: Vec::new(),
                compatible_architectures: Vec::new(),
            },
        );
        f.layers = vec![format!(
            "arn:aws:lambda:us-east-1:000000000000:layer:ext:{}",
            published.version
        )];
        exec.with_layer_store(layers)
    }

    /// With extensions, Init fails with the supervisor's classification of the process that
    /// exited, and an Init timeout logs `Status: timeout`.
    #[tokio::test]
    async fn extension_init_failures_are_classified() {
        if crate::rootfs::find_host_executable("bash").is_none() {
            return;
        }
        for (behavior, status, payload_type) in [
            (
                GuestBehavior::SupervisorExit("extension"),
                InitStatus::Error("Extension.Crash".into()),
                "Extension.Crash",
            ),
            (
                GuestBehavior::SupervisorExit("runtime"),
                InitStatus::Error("Runtime.ExitError".into()),
                "Runtime.ExitError",
            ),
            // The runtime is ready but the extension never registers.
            (
                GuestBehavior::EchoUppercaseLen,
                InitStatus::Timeout,
                "Sandbox.Timedout",
            ),
        ] {
            let logs = Arc::new(RecordingLogs::default());
            let registry = observability_registry_with_logs(
                Arc::new(RecordingMetrics::default()),
                logs.clone(),
            );
            let broker = Arc::new(InvocationBroker::new());
            let mut f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
            let mut exec =
                with_extension_layer(build_executor(broker.clone(), behavior).await, &mut f)
                    .with_service_registry(Arc::downgrade(&registry));
            exec.init_timeout = Duration::from_millis(200);
            let result = exec
                .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
                .await
                .unwrap();
            let Outcome::Error {
                error_type: FunctionErrorType::Unhandled,
                payload,
            } = &result.outcome
            else {
                panic!("unexpected outcome {:?}", result.outcome);
            };
            let payload: serde_json::Value = serde_json::from_slice(payload).unwrap();
            assert_eq!(payload["errorType"], payload_type);
            let init = result.init.clone().unwrap();
            assert_eq!(init.status, status);
            let expected = match &status {
                InitStatus::Timeout => "Status: timeout".to_string(),
                InitStatus::Error(error_type) => format!("Status: error\tError Type: {error_type}"),
                InitStatus::Success => unreachable!(),
            };
            let messages = stream_messages(&logs, &result.log_stream_name.clone().unwrap());
            assert!(
                messages.contains(&format!(
                    "INIT_REPORT Init Duration: {} ms\tPhase: init\t{expected}",
                    format_ms(init.duration_us)
                )),
                "{messages:?}"
            );
            assert!(exec.owned_envs.is_empty());
            assert_eq!(broker.inflight_count(), 0);
        }
    }

    #[tokio::test]
    async fn failed_start_writes_error_to_a_log_stream() {
        let logs = Arc::new(RecordingLogs::default());
        let registry =
            observability_registry_with_logs(Arc::new(RecordingMetrics::default()), logs.clone());
        let broker = Arc::new(InvocationBroker::new());
        let exec = build_executor(broker, GuestBehavior::EchoUppercaseLen)
            .await
            .with_service_registry(Arc::downgrade(&registry));
        // A custom runtime without `bootstrap` fails before any guest starts.
        let f = func("provided.al2", 10, zip_with(&[("index.js", b"x")]));
        let result = exec
            .invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
            .await
            .unwrap();
        let request_id = result.request_id.clone().unwrap();
        let messages = stream_messages(&logs, result.log_stream_name.as_deref().unwrap());
        assert_eq!(messages.len(), 4, "{messages:?}");
        assert_eq!(
            messages[0],
            format!("START RequestId: {request_id} Version: $LATEST")
        );
        assert!(
            messages[1].starts_with(&format!("RequestId: {request_id} Error: ")),
            "{messages:?}"
        );
        assert!(messages[1].contains("bootstrap"), "{messages:?}");
        assert_eq!(messages[2], format!("END RequestId: {request_id}"));
        assert!(messages[3].starts_with(&format!("REPORT RequestId: {request_id}\t")));
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
        // A saturated sink keeps the bucket for the next flush instead of losing it.
        assert_eq!(exec.metrics.recorder().tick(), 0);
        assert_eq!(exec.metrics.recorder().pending_buckets(), 1);
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
        let exec = Arc::new(exec);
        let handler = LambdaHandler::with_executor(exec.clone());
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
        flush_metrics(&exec);
        let observations = metrics.observations.lock().unwrap().clone();
        assert_eq!(
            metric_values(&observations),
            vec![("Throttles".to_string(), 1.0)]
        );
        assert_lambda_metric_shape(&observations);
    }

    /// Refuses the first `full` batches as a saturated Monitoring channel would.
    struct SaturatedMetrics {
        full: Mutex<usize>,
        observations: Mutex<Vec<MetricObservation>>,
    }

    impl MetricSink for SaturatedMetrics {
        fn try_emit(&self, observations: Vec<MetricObservation>) -> EmitOutcome {
            let mut full = self.full.lock().unwrap();
            if *full > 0 {
                *full -= 1;
                return EmitOutcome::Full;
            }
            self.observations.lock().unwrap().extend(observations);
            EmitOutcome::Accepted
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_invocations_sum_exactly_under_saturated_monitoring() {
        const INVOCATIONS: usize = 200;
        let metrics = Arc::new(SaturatedMetrics {
            full: Mutex::new(3),
            observations: Mutex::new(Vec::new()),
        });
        let registry = observability_registry(metrics.clone());
        let broker = Arc::new(InvocationBroker::new());
        let mut exec = build_executor(broker, GuestBehavior::EchoUppercaseLen)
            .await
            .with_service_registry(Arc::downgrade(&registry));
        // Room for every guest so no invocation is throttled by the host memory budget.
        exec.memory_budget_mb = 160 * INVOCATIONS as u64;
        let exec = Arc::new(exec);
        exec.bind_arc();
        let f = Arc::new(func("nodejs22.x", 30, zip_with(&[("index.js", b"x")])));
        let ticker = {
            let exec = exec.clone();
            tokio::spawn(async move {
                loop {
                    flush_metrics(&exec);
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
        };
        let invocations: Vec<_> = (0..INVOCATIONS)
            .map(|_| {
                let exec = exec.clone();
                let f = f.clone();
                tokio::spawn(async move {
                    exec.invoke_sync("000000000000", "us-east-1", &f, b"{}".to_vec())
                        .await
                })
            })
            .collect();
        for invocation in invocations {
            let result = invocation.await.unwrap().unwrap();
            assert_eq!(result.outcome, Outcome::Success(b"{\"len\":2}".to_vec()));
        }
        ticker.abort();
        let _ = ticker.await;
        for _ in 0..10 {
            if exec.metrics.recorder().pending_buckets() == 0 {
                break;
            }
            flush_metrics(&exec);
        }
        exec.shutdown().await;
        let observations = metrics.observations.lock().unwrap().clone();
        let sum = |name: &str| -> f64 {
            observations
                .iter()
                .filter(|observation| observation.metric_name == name)
                .map(|observation| observation.value)
                .sum()
        };
        assert_eq!(*metrics.full.lock().unwrap(), 0);
        assert_eq!(sum("Invocations"), INVOCATIONS as f64);
        assert_eq!(sum("Errors"), 0.0);
        assert_eq!(
            observations
                .iter()
                .filter(|observation| observation.metric_name == "Duration")
                .count(),
            INVOCATIONS
        );
    }

    const CALLER_ROOT: &str = "Root=1-5759e988-bd862e3fe1be46a994272793";

    async fn trace_executor(fail: bool) -> (Executor, Arc<Mutex<Vec<String>>>) {
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
                fail,
            }),
            base,
            "http://127.0.0.1:4566",
            "test",
            "test",
        );
        (exec, traces)
    }

    fn assert_continues_caller_root(trace: &str) {
        assert!(
            trace.starts_with(&format!("{CALLER_ROOT};Parent=")),
            "{trace}"
        );
        assert!(!trace.contains("Parent=53995c3f42cd8ad8"), "{trace}");
        // PassThrough keeps the caller's sampling decision.
        assert!(trace.ends_with(";Sampled=1"), "{trace}");
    }

    #[tokio::test]
    async fn async_invoke_continues_caller_trace_root_on_every_attempt() {
        let (exec, traces) = trace_executor(true).await;
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let cfg = AsyncConfig {
            max_retry_attempts: 2,
            on_success_arn: None,
            on_failure_arn: None,
        };
        let incoming = format!("{CALLER_ROOT};Parent=53995c3f42cd8ad8;Sampled=1");
        exec.invoke_async(
            "000000000000",
            "us-east-1",
            &f,
            b"{}".to_vec(),
            &cfg,
            Some(&incoming),
        )
        .await;
        let traces = traces.lock().unwrap().clone();
        assert_eq!(traces.len(), 3);
        for trace in &traces {
            assert_continues_caller_root(trace);
        }
        exec.shutdown().await;
    }

    #[tokio::test]
    async fn function_url_invoke_continues_caller_trace_root() {
        use crate::function_url::UrlRequest;
        let (exec, traces) = trace_executor(false).await;
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let request = UrlRequest {
            method: "GET".into(),
            raw_path: "/".into(),
            raw_query: String::new(),
            headers: vec![(
                "X-Amzn-Trace-Id".into(),
                format!("{CALLER_ROOT};Parent=53995c3f42cd8ad8;Sampled=1"),
            )],
            body: Vec::new(),
            url_id: "abc".into(),
            region: "us-east-1".into(),
            account: "000000000000".into(),
            request_id: "rid".into(),
        };
        exec.invoke_url("000000000000", "us-east-1", &f, request)
            .await
            .unwrap();
        let traces = traces.lock().unwrap().clone();
        assert_eq!(traces.len(), 1);
        assert_continues_caller_root(&traces[0]);
        exec.shutdown().await;
    }

    #[tokio::test]
    async fn sync_invoke_continues_caller_trace_root() {
        let (exec, traces) = trace_executor(false).await;
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let root = CALLER_ROOT;
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
        assert!(traces[0].ends_with(";Sampled=1"));
        assert!(!traces[1].starts_with(root));
        assert!(traces[1].starts_with("Root=1-"));
        assert!(traces[1].ends_with(";Sampled=0"));
        exec.shutdown().await;
    }

    /// Records what the fake X-Ray service receives through internal dispatch.
    #[derive(Default)]
    struct RecordingXray {
        calls: Mutex<Vec<(String, String, Vec<String>)>>,
    }

    #[async_trait]
    impl locallycloud_core::handler::NativeHandler for RecordingXray {
        async fn handle(
            &self,
            request: locallycloud_core::handler::ServiceRequest,
        ) -> axum::response::Response {
            assert_eq!(request.uri.path(), "/TraceSegments");
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let documents = body["TraceSegmentDocuments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|document| document.as_str().unwrap().to_owned())
                .collect();
            self.calls
                .lock()
                .unwrap()
                .push((request.account_id, request.region, documents));
            axum::response::IntoResponse::into_response(axum::Json(
                serde_json::json!({"UnprocessedTraceSegments": []}),
            ))
        }
    }

    /// A guest that behaves like an X-Ray SDK in Lambda: each invocation sends one
    /// subsegment datagram, parented on the header's `Parent`, to `AWS_XRAY_DAEMON_ADDRESS`.
    struct XrayGuest {
        envs: Arc<Mutex<Vec<HashMap<String, String>>>>,
        traces: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl ComputeRuntime for XrayGuest {
        async fn start_task(&self, id: &str, spec: &TaskSpec) -> Result<TaskHandle, RuntimeError> {
            self.envs.lock().unwrap().push(spec.env.clone());
            let api = spec.env.get("AWS_LAMBDA_RUNTIME_API").cloned().unwrap();
            let daemon = spec.env.get("AWS_XRAY_DAEMON_ADDRESS").cloned();
            let traces = self.traces.clone();
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
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
                    let header = |name: &str| next.headers()[name].to_str().unwrap().to_string();
                    let rid = header("Lambda-Runtime-Aws-Request-Id");
                    let trace = header("Lambda-Runtime-Trace-Id");
                    traces.lock().unwrap().push(trace.clone());
                    // `"hang"` never answers (the invocation times out), `"fail"` reports
                    // a function error.
                    let event = next.text().await.unwrap_or_default();
                    if event == "\"hang\"" {
                        break;
                    }
                    let field = |name: &str| {
                        trace
                            .split(';')
                            .find_map(|part| part.strip_prefix(name))
                            .unwrap()
                            .to_string()
                    };
                    if let (Some(daemon), "1") = (&daemon, field("Sampled=").as_str()) {
                        let subsegment = serde_json::json!({
                            "name": "## handler", "id": "00000000000000aa",
                            "trace_id": field("Root="), "parent_id": field("Parent="),
                            "type": "subsegment", "start_time": 1.0, "end_time": 2.0,
                        });
                        let mut foreign = subsegment.clone();
                        foreign["trace_id"] = "1-5759e988-000000000000000000000000".into();
                        for document in [foreign, subsegment] {
                            let datagram =
                                format!("{{\"format\": \"json\", \"version\": 1}}\n{document}");
                            udp.send_to(datagram.as_bytes(), daemon).await.unwrap();
                        }
                        // Invalid datagrams are dropped without affecting the endpoint.
                        udp.send_to(b"garbage", daemon).await.unwrap();
                    }
                    let (outcome, body) = if event == "\"fail\"" {
                        ("error", r#"{"errorMessage":"boom","errorType":"Error"}"#)
                    } else {
                        ("response", "null")
                    };
                    let _ = client
                        .post(format!(
                            "http://{api}/2018-06-01/runtime/invocation/{rid}/{outcome}"
                        ))
                        .body(body)
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

    #[tokio::test]
    async fn every_environment_owns_a_daemon_endpoint_and_active_emits_lambda_segments() {
        use locallycloud_core::integration::InternalDispatcher;
        use locallycloud_core::proxy::LegacyHealth;
        use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};

        let registry = observability_registry(Arc::new(RecordingMetrics::default()));
        let xray = Arc::new(RecordingXray::default());
        registry.register_native(
            ServiceName::new("xray"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            xray.clone(),
        );
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        )));
        let broker = Arc::new(InvocationBroker::new());
        let base = serve_runtime_api(broker.clone()).await;
        let tmp = std::env::temp_dir().join(format!("lc-exec-{}", Uuid::new_v4()));
        let envs = Arc::new(Mutex::new(Vec::new()));
        let traces = Arc::new(Mutex::new(Vec::new()));
        let exec = Executor::new(
            broker,
            Arc::new(CodeStore::new(tmp.join("code"))),
            tmp.join("rootfs"),
            Arc::new(XrayGuest {
                envs: envs.clone(),
                traces: traces.clone(),
            }),
            base,
            "http://127.0.0.1:4566",
            "test",
            "test",
        )
        .with_service_registry(Arc::downgrade(&registry));
        let (account, region) = ("123456789012", "eu-west-1");

        // Every document the fake X-Ray received, in scope.
        let documents = || -> Vec<serde_json::Value> {
            xray.calls
                .lock()
                .unwrap()
                .iter()
                .inspect(|(call_account, call_region, _)| {
                    assert_eq!(
                        (call_account.as_str(), call_region.as_str()),
                        (account, region)
                    );
                })
                .flat_map(|(_, _, documents)| documents.iter())
                .map(|document| serde_json::from_str(document).unwrap())
                .collect()
        };
        let wait_for = |count: usize| {
            let documents = &documents;
            async move {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let found = documents();
                    if found.len() >= count || Instant::now() > deadline {
                        // Let anything sent after the expected documents arrive too.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        return documents();
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        };
        let field = |trace: &str, name: &str| {
            trace
                .split(';')
                .find_map(|part| part.strip_prefix(name))
                .unwrap()
                .to_string()
        };
        let last_trace = || traces.lock().unwrap().last().unwrap().clone();
        let daemon_addresses = || -> Vec<SocketAddr> {
            exec.xray_daemons
                .iter()
                .map(|entry| entry.value().0)
                .collect()
        };

        // PassThrough also gets an endpoint and the daemon variables, but no Lambda segment.
        let plain = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        exec.invoke_sync(account, region, &plain, b"{}".to_vec())
            .await
            .unwrap();
        let [plain_daemon] = daemon_addresses()[..] else {
            panic!("one endpoint per environment");
        };
        assert!(plain_daemon.ip().is_loopback() && plain_daemon.port() != 0);
        let env = envs.lock().unwrap()[0].clone();
        assert_eq!(env["AWS_XRAY_DAEMON_ADDRESS"], plain_daemon.to_string());
        assert_eq!(
            env["_AWS_XRAY_DAEMON_PORT"],
            plain_daemon.port().to_string()
        );
        assert!(last_trace().ends_with(";Sampled=0"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(documents().is_empty());
        // A caller-sampled PassThrough invocation: the SDK subsegment is stored, the
        // foreign-trace datagram the guest also sent is not, and Lambda adds no segment.
        exec.invoke_sync_traced(
            account,
            region,
            &plain,
            b"{}".to_vec(),
            Some(&format!("{CALLER_ROOT};Parent=53995c3f42cd8ad8;Sampled=1")),
        )
        .await
        .unwrap();
        let found = wait_for(1).await;
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0]["type"], "subsegment");
        assert_eq!(
            found[0]["trace_id"],
            CALLER_ROOT.strip_prefix("Root=").unwrap()
        );
        // A local process that does not know a live root cannot add segments either.
        let outsider = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forged = serde_json::json!({"name": "forged", "id": "00000000000000bb",
            "trace_id": "1-5759e988-111111111111111111111111", "start_time": 1.0, "end_time": 2.0});
        outsider
            .send_to(
                format!("{{\"format\": \"json\", \"version\": 1}}\n{forged}").as_bytes(),
                plain_daemon,
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(documents().len(), 1);

        // Active: the cold start binds another endpoint and hands its address to the guest.
        let mut traced = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        traced.function_name = "traced".into();
        traced.function_arn = crate::model::function_arn(region, account, "traced");
        traced.tracing_mode = TracingMode::Active;
        let result = exec
            .invoke_sync(account, region, &traced, b"{}".to_vec())
            .await
            .unwrap();
        assert_eq!(exec.xray_daemons.len(), 2);
        let daemon = daemon_addresses()
            .into_iter()
            .find(|address| *address != plain_daemon)
            .unwrap();
        let env = envs.lock().unwrap()[1].clone();
        assert_eq!(env["AWS_XRAY_DAEMON_ADDRESS"], daemon.to_string());
        assert_eq!(env["_AWS_XRAY_DAEMON_ADDRESS"], "127.0.0.1");
        assert_eq!(env["_AWS_XRAY_DAEMON_PORT"], daemon.port().to_string());
        assert_eq!(env["AWS_XRAY_CONTEXT_MISSING"], "LOG_ERROR");
        // The first Active request of the second falls in the reservoir.
        let trace = last_trace();
        assert!(trace.ends_with(";Sampled=1"), "{trace}");
        let parent = field(&trace, "Parent=");
        let root = field(&trace, "Root=");

        // The SDK subsegment (via UDP), the service segment and the function segment arrive
        // in scope; the guest's foreign-trace datagram is dropped.
        let found = wait_for(4).await;
        assert_eq!(found.len(), 4, "{found:?}");
        let service = found
            .iter()
            .find(|document| document["origin"] == "AWS::Lambda")
            .unwrap();
        let function = found
            .iter()
            .find(|document| document["origin"] == "AWS::Lambda::Function")
            .unwrap();
        // Without a caller the service segment is the trace's root.
        assert_eq!(service["name"], "traced");
        assert_eq!(service["trace_id"], root.as_str());
        assert_eq!(service["resource_arn"], traced.function_arn.as_str());
        assert_eq!(
            service["aws"]["request_id"],
            result.request_id.as_deref().unwrap()
        );
        assert!(service.get("parent_id").is_none());
        assert!(service.get("fault").is_none());
        assert_ne!(service["id"], parent.as_str());
        assert_eq!(function["id"], parent.as_str());
        assert_eq!(function["trace_id"], root.as_str());
        assert_eq!(function["name"], "traced");
        assert_eq!(function["parent_id"], service["id"]);
        assert!(function.get("fault").is_none());
        // The service segment covers the function segment.
        assert!(service["start_time"].as_f64() <= function["start_time"].as_f64());
        assert!(service["end_time"].as_f64() >= function["end_time"].as_f64());
        // The segment spans the invoke phase reported as Duration.
        let span =
            function["end_time"].as_f64().unwrap() - function["start_time"].as_f64().unwrap();
        assert!(
            (span - result.duration_us as f64 / 1e6).abs() < 1e-3,
            "{span} vs {}",
            result.duration_us
        );
        let subsegment = found
            .iter()
            .find(|document| {
                document["type"] == "subsegment" && document["trace_id"] == root.as_str()
            })
            .unwrap();
        assert_eq!(subsegment["parent_id"], parent.as_str());

        // A caller's `Sampled=0` wins over Active: no segment for that invocation.
        let calls_before = xray.calls.lock().unwrap().len();
        exec.invoke_sync_traced(
            account,
            region,
            &traced,
            b"{}".to_vec(),
            Some(&format!("{CALLER_ROOT};Parent=53995c3f42cd8ad8;Sampled=0")),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(xray.calls.lock().unwrap().len(), calls_before);

        // A failed invocation with a caller parent: caller → service → function, and only
        // the function segment carries `fault` (the Lambda service did not fail).
        exec.invoke_sync_traced(
            account,
            region,
            &traced,
            b"\"fail\"".to_vec(),
            Some(&format!("{CALLER_ROOT};Parent=53995c3f42cd8ad8;Sampled=1")),
        )
        .await
        .unwrap();
        let failed_parent = field(&last_trace(), "Parent=");
        let found = wait_for(7).await;
        assert_eq!(found.len(), 7, "{found:?}");
        let function = found
            .iter()
            .find(|document| document["id"] == failed_parent.as_str())
            .unwrap();
        assert_eq!(function["origin"], "AWS::Lambda::Function");
        assert_eq!(function["fault"], true);
        let service = found
            .iter()
            .find(|document| document["id"] == function["parent_id"])
            .unwrap();
        assert_eq!(service["origin"], "AWS::Lambda");
        assert_eq!(service["parent_id"], "53995c3f42cd8ad8");
        assert_eq!(
            service["trace_id"],
            CALLER_ROOT.strip_prefix("Root=").unwrap()
        );
        assert!(service.get("fault").is_none());

        // Invalidation (code or configuration update) closes the environment's endpoint.
        exec.invalidate_warm(&format!("{}:$LATEST", traced.function_arn))
            .await;
        assert_eq!(daemon_addresses(), vec![plain_daemon]);
        tokio::net::UdpSocket::bind(daemon).await.unwrap();

        // A timeout stops the environment and closes its endpoint.
        let mut slow = traced.clone();
        slow.timeout = 1;
        exec.invoke_sync(account, region, &slow, b"\"hang\"".to_vec())
            .await
            .unwrap();
        let timed_out: SocketAddr = envs.lock().unwrap().last().unwrap()["AWS_XRAY_DAEMON_ADDRESS"]
            .parse()
            .unwrap();
        assert_ne!(timed_out, plain_daemon);
        assert_eq!(daemon_addresses(), vec![plain_daemon]);
        tokio::net::UdpSocket::bind(timed_out).await.unwrap();

        // Stopping the environments closes the remaining socket.
        exec.shutdown().await;
        assert!(exec.xray_daemons.is_empty());
        tokio::net::UdpSocket::bind(plain_daemon).await.unwrap();
    }

    /// A guest that records each invocation's `Lambda-Runtime-Trace-Id` header.
    struct TraceRecordingGuest {
        traces: Arc<Mutex<Vec<String>>>,
        /// Report a function error so asynchronous invocations retry.
        fail: bool,
    }

    #[async_trait]
    impl ComputeRuntime for TraceRecordingGuest {
        async fn start_task(&self, id: &str, spec: &TaskSpec) -> Result<TaskHandle, RuntimeError> {
            let api = spec.env.get("AWS_LAMBDA_RUNTIME_API").cloned().unwrap();
            let traces = self.traces.clone();
            let outcome = if self.fail { "error" } else { "response" };
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
                            "http://{api}/2018-06-01/runtime/invocation/{rid}/{outcome}"
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
        exec.invoke_async("000000000000", "us-east-1", &f, b"hi".to_vec(), &cfg, None)
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
        let (exec, starts) = build_executor_tracked(broker, GuestBehavior::ReportError).await;
        let exec = exec.with_destination_router(router.clone());
        let f = func("nodejs22.x", 10, zip_with(&[("index.js", b"x")]));
        let cfg = AsyncConfig {
            max_retry_attempts: 2,
            on_success_arn: None,
            on_failure_arn: Some("arn:aws:sqs:us-east-1:000000000000:dlq".into()),
        };
        exec.invoke_async("000000000000", "us-east-1", &f, b"{}".to_vec(), &cfg, None)
            .await;
        let recs = router.records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].0, "arn:aws:sqs:us-east-1:000000000000:dlq");
        assert_eq!(recs[0].1["requestContext"]["condition"], "RetriesExhausted");
        // initial + 2 retries = 3 attempts.
        assert_eq!(recs[0].1["requestContext"]["approximateInvokeCount"], 3);
        assert_eq!(recs[0].1["responseContext"]["functionError"], "Unhandled");
        // The retries reuse the environment the handler error left running.
        assert_eq!(starts.load(std::sync::atomic::Ordering::SeqCst), 1);
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
