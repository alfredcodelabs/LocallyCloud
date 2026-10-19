//! Daemonless OCI fallback backend.
//!
//! Implements [`ComputeRuntime`] using a daemonless OCI runtime (`youki` / `crun`).
//! Requires neither `/dev/kvm` nor Docker / the Docker daemon / `bollard`. See Requirement 16.
//!
//! Execution model (shared with [`crate::firecracker`]): `start_task` builds an OCI bundle
//! around the caller-supplied rootfs (`TaskSpec::image`), launches it in the background and
//! reports `Running`; the workload's stdout is captured as it runs and exposed via
//! `get_output`; `stop_task` terminates a still-running task. A one-shot task transitions to
//! `Completed` on its own.
//!
//! Runtime-footprint principle: the runtime binary is resolved lazily (explicit path or
//! [`YoukiRuntime::discover`] on `PATH`); nothing is installed eagerly.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use dashmap::{mapref::entry::Entry, DashMap};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::Mutex;

use crate::runtime::{ComputeRuntime, RuntimeError, TaskHandle, TaskOutput, TaskSpec, TaskState};
pub use crate::youki_setup::{is_setup_address, run_oci_setup_hook, IsolatedGuestSetup};
use crate::youki_setup::{NamespaceFiles, NamespaceLease, SetupGate, SETUP_TIMEOUT};

struct TaskRecord {
    state: TaskState,
    output: crate::output::OutputCapture,
    finished: bool,
    bundle: PathBuf,
    isolated_network: bool,
}

type Slot = Arc<Mutex<TaskRecord>>;

/// Guest loopback port reserved for the host-owned transparent IPv4 TCP relay.
pub const VPC_EGRESS_PORT: u16 = 49152;

#[derive(Clone, Copy)]
enum EgressCapture {
    PublicOnly,
    Vpc,
}
impl EgressCapture {
    fn excluded_ranges(self, private_addresses: &[std::net::Ipv4Addr]) -> Vec<String> {
        let mut excluded = private_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        excluded.extend(["127.0.0.0/8", "169.254.0.0/16"].map(str::to_owned));
        if matches!(self, Self::PublicOnly) {
            excluded.extend(
                [
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "100.64.0.0/10",
                ]
                .map(str::to_owned),
            );
        }
        excluded
    }
}

/// Read the kernel-attested original IPv4 TCP destination of a redirected socket.
pub fn original_tcp_destination(
    stream: &tokio::net::TcpStream,
) -> std::io::Result<std::net::SocketAddrV4> {
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: address and size are valid writable getsockopt output buffers.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            80,
            (&mut address as *mut libc::sockaddr_in).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of::<libc::sockaddr_in>()
        || address.sin_family != libc::AF_INET as u16
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "redirected TCP destination is not IPv4",
        ));
    }
    Ok(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(address.sin_port),
    ))
}

#[derive(Clone)]
pub struct YoukiRuntime {
    /// Path to the `youki` or `crun` binary.
    runtime_binary: PathBuf,
    /// Base directory under which per-task OCI bundles are created.
    bundle_root: PathBuf,
    tasks: Arc<DashMap<String, Slot>>,
    setup_namespaces: Arc<DashMap<String, Arc<NamespaceFiles>>>,
}

impl YoukiRuntime {
    pub fn new(runtime_binary: impl Into<PathBuf>) -> Self {
        YoukiRuntime {
            runtime_binary: runtime_binary.into(),
            bundle_root: crate::private_dir::work_dir("oci"),
            tasks: Arc::new(DashMap::new()),
            setup_namespaces: Arc::new(DashMap::new()),
        }
    }

    /// Locate a daemonless OCI runtime on `PATH` (`crun` preferred, then `youki`).
    /// Returns `None` when neither is present, so callers can surface an actionable error.
    pub fn discover() -> Option<Self> {
        for name in ["crun", "youki"] {
            if let Some(path) = which(name) {
                return Some(Self::new(path));
            }
        }
        None
    }

    async fn oci_command(&self, args: &[&str]) -> Result<std::process::Output, RuntimeError> {
        let mut command = Command::new(&self.runtime_binary);
        command.args(args).kill_on_drop(true);
        tokio::time::timeout(std::time::Duration::from_secs(5), command.output())
            .await
            .map_err(|_| exec_failed("OCI reconciliation command timed out"))?
            .map_err(|e| exec_failed(format!("invoking OCI reconciliation command: {e}")))
    }

    fn ensure_runtime_available(&self) -> Result<(), RuntimeError> {
        if self.runtime_binary.exists() {
            Ok(())
        } else {
            Err(RuntimeError::OciRuntimeNotFound {
                binary: self.runtime_binary.display().to_string(),
            })
        }
    }

    /// Generate a rootless OCI `config.json` in `bundle`, then rewrite its process/root
    /// fields for this task. Uses the runtime's own `spec` subcommand so the rootless
    /// uid/gid mappings and standard mounts are produced correctly.
    async fn write_bundle_config(
        &self,
        bundle: &Path,
        spec: &TaskSpec,
        rootfs: &Path,
        isolated_network: bool,
        cpu_units: u32,
        setup_gate: Option<&SetupGate>,
    ) -> Result<(), RuntimeError> {
        let gen = Command::new(&self.runtime_binary)
            .arg("spec")
            .arg("--rootless")
            .current_dir(bundle)
            .output()
            .await
            .map_err(|e| exec_failed(format!("invoking `spec`: {e}")))?;
        if !gen.status.success() {
            return Err(exec_failed(format!(
                "`spec` failed: {}",
                String::from_utf8_lossy(&gen.stderr).trim()
            )));
        }

        let config_path = bundle.join("config.json");
        let raw = tokio::fs::read(&config_path)
            .await
            .map_err(|e| exec_failed(format!("reading config.json: {e}")))?;
        let mut config: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| exec_failed(format!("parsing config.json: {e}")))?;

        let mut env = vec![serde_json::Value::from("PATH=/usr/local/bin:/usr/bin:/bin")];
        for (key, value) in &spec.env {
            env.push(serde_json::Value::from(format!("{key}={value}")));
        }
        let args: Vec<serde_json::Value> = spec
            .command
            .iter()
            .map(|a| serde_json::Value::from(a.as_str()))
            .collect();

        config["process"]["terminal"] = serde_json::Value::Bool(false);
        config["process"]["args"] = serde_json::Value::Array(args);
        config["process"]["env"] = serde_json::Value::Array(env);
        config["process"]["cwd"] = serde_json::Value::from("/");
        config["root"]["path"] = serde_json::Value::from(rootfs.display().to_string());
        config["root"]["readonly"] = serde_json::Value::Bool(true);
        if spec.memory_mb == 0 {
            return Err(exec_failed("OCI memory_mb must be positive"));
        }
        let quota = cpu_quota(cpu_units)?;
        config["linux"]["resources"]["cpu"]["period"] = serde_json::json!(CPU_PERIOD_US);
        config["linux"]["resources"]["cpu"]["quota"] = serde_json::json!(quota);
        let memory_bytes = u64::from(spec.memory_mb) * 1024 * 1024;
        config["linux"]["resources"]["memory"]["limit"] = serde_json::json!(memory_bytes);
        // OCI swap counts RAM+swap; equal values disable host swap for the guest.
        config["linux"]["resources"]["memory"]["swap"] = serde_json::json!(memory_bytes);

        // Lambda rootfses provide a per-environment /tmp. Bind it writable while the
        // rest of the rootfs stays read-only; generic OCI tasks may omit this directory.
        let guest_tmp = rootfs.join("tmp");
        if guest_tmp.is_dir() {
            let mounts = config["mounts"]
                .as_array_mut()
                .ok_or_else(|| exec_failed("OCI spec has no mounts array"))?;
            mounts.push(serde_json::json!({
                "destination": "/tmp",
                "type": "bind",
                "source": guest_tmp.display().to_string(),
                "options": ["rbind", "rw", "nosuid", "nodev"]
            }));
        }

        // Share the host network namespace so the guest reaches the Runtime API and the
        // locallycloud endpoint on the host loopback. This is the daemonless egress mechanism
        // for the OCI backend (Firecracker uses vsock + TAP/nftables instead). Removing the
        // `network` namespace entry makes the container inherit the host netns.
        if !isolated_network {
            if let Some(namespaces) = config["linux"]["namespaces"].as_array_mut() {
                namespaces.retain(|ns| ns.get("type").and_then(|t| t.as_str()) != Some("network"));
            }
        } else {
            let namespaces = config["linux"]["namespaces"]
                .as_array_mut()
                .ok_or_else(|| exec_failed("OCI spec has no namespaces array"))?;
            if !namespaces
                .iter()
                .any(|ns| ns.get("type").and_then(|t| t.as_str()) == Some("network"))
            {
                namespaces.push(serde_json::json!({"type": "network"}));
            }
        }

        if let Some(gate) = setup_gate {
            config["hooks"]["createContainer"] = serde_json::json!([gate.hook()]);
        }

        let serialized = serde_json::to_vec_pretty(&config)
            .map_err(|e| exec_failed(format!("serializing config.json: {e}")))?;
        tokio::fs::write(&config_path, serialized)
            .await
            .map_err(|e| exec_failed(format!("writing config.json: {e}")))?;
        Ok(())
    }

    async fn start_task_with_network(
        &self,
        task_id: &str,
        spec: &TaskSpec,
        isolated_network: bool,
    ) -> Result<TaskHandle, RuntimeError> {
        let cpu_units = spec
            .vcpu_count
            .checked_mul(1024)
            .ok_or_else(|| exec_failed("OCI vcpu_count exceeds supported CPU units"))?;
        self.start_task_with_network_and_cpu(task_id, spec, isolated_network, cpu_units, None)
            .await
    }

    async fn start_task_with_network_and_cpu(
        &self,
        task_id: &str,
        spec: &TaskSpec,
        isolated_network: bool,
        cpu_units: u32,
        setup: Option<Arc<dyn IsolatedGuestSetup>>,
    ) -> Result<TaskHandle, RuntimeError> {
        let expected_cpu_quota = cpu_quota(cpu_units)?;
        self.ensure_runtime_available()?;
        let controllers = tokio::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
            .await
            .map_err(|e| {
                exec_failed(format!(
                    "OCI requires cgroup v2 CPU and memory delegation: {e}"
                ))
            })?;
        for controller in ["memory", "cpu"] {
            if !controllers
                .split_whitespace()
                .any(|name| name == controller)
            {
                return Err(exec_failed(format!("OCI {controller} controller unavailable; enable rootless systemd cgroup v2 CPU and memory delegation")));
            }
        }
        if task_id.is_empty()
            || !task_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(exec_failed(
                "OCI task ID must contain only ASCII letters, digits, hyphen or underscore",
            ));
        }
        if spec.command.is_empty() {
            return Err(exec_failed("OCI task command is empty"));
        }
        if self.tasks.contains_key(task_id) {
            return Err(exec_failed(format!(
                "OCI task ID already exists: {task_id}"
            )));
        }
        let rootfs = PathBuf::from(&spec.image);
        if !rootfs.is_dir() {
            return Err(exec_failed(format!("rootfs not found: {}", spec.image)));
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let bundle = self
            .bundle_root
            .join(format!("locallycloud-{task_id}-{nanos}"));
        let bundle_root = self.bundle_root.clone();
        tokio::task::spawn_blocking(move || crate::private_dir::ensure(&bundle_root))
            .await
            .map_err(|error| exec_failed(format!("checking bundle directory: {error}")))?
            .map_err(|error| exec_failed(format!("checking bundle directory: {error}")))?;
        let setup_gate = if setup.is_some() {
            Some(SetupGate::new().await?)
        } else {
            None
        };
        tokio::fs::create_dir(&bundle)
            .await
            .map_err(|error| exec_failed(format!("creating bundle dir: {error}")))?;
        if let Err(error) = self
            .write_bundle_config(
                &bundle,
                spec,
                &rootfs,
                isolated_network,
                cpu_units,
                setup_gate.as_ref(),
            )
            .await
        {
            let _ = tokio::fs::remove_dir_all(&bundle).await;
            return Err(error);
        }
        let slot: Slot = Arc::new(Mutex::new(TaskRecord {
            state: TaskState::Running,
            output: crate::output::OutputCapture::default(),
            finished: false,
            bundle: bundle.clone(),
            isolated_network,
        }));
        match self.tasks.entry(task_id.to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(slot.clone());
            }
            Entry::Occupied(_) => {
                let _ = tokio::fs::remove_dir_all(&bundle).await;
                return Err(exec_failed(format!(
                    "OCI task ID already exists: {task_id}"
                )));
            }
        }

        let runtime_pid = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let published_pid = runtime_pid.clone();
        let owned_bundle = bundle.clone();
        let owned_slot = slot.clone();
        let runtime_binary = self.runtime_binary.clone();
        let id = task_id.to_string();
        tokio::spawn(async move {
            let child = Command::new(&runtime_binary)
                .arg("--systemd-cgroup")
                .arg("run")
                .arg("--pid-file")
                .arg(bundle.join("pid"))
                .arg("--bundle")
                .arg(&bundle)
                .arg(&id)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();
            match child {
                Ok(mut child) => {
                    published_pid.store(
                        child.id().unwrap_or(0),
                        std::sync::atomic::Ordering::Release,
                    );
                    let stdout = child
                        .stdout
                        .take()
                        .map(|pipe| tokio::spawn(stream_output(pipe, slot.clone())));
                    let stderr = child
                        .stderr
                        .take()
                        .map(|pipe| tokio::spawn(stream_output(pipe, slot.clone())));
                    let status = child.wait().await;
                    if let Some(reader) = stdout {
                        let _ = reader.await;
                    }
                    if let Some(reader) = stderr {
                        let _ = reader.await;
                    }
                    let mut record = slot.lock().await;
                    match status {
                        Ok(status) if record.state == TaskState::Running => {
                            record.state = if status.success() {
                                TaskState::Completed
                            } else {
                                TaskState::Failed
                            };
                        }
                        Err(error) => {
                            record
                                .output
                                .extend_from_slice(format!("invoking `run`: {error}").as_bytes());
                            if record.state == TaskState::Running {
                                record.state = TaskState::Failed;
                            }
                        }
                        _ => {}
                    }
                }
                Err(error) => {
                    let mut record = slot.lock().await;
                    record
                        .output
                        .extend_from_slice(format!("invoking `run`: {error}").as_bytes());
                    if record.state == TaskState::Running {
                        record.state = TaskState::Failed;
                    }
                }
            }
            slot.lock().await.finished = true;
        });
        if let (Some(setup), Some(gate)) = (setup, setup_gate) {
            let result = async {
                let connection = gate.accept(task_id, &owned_bundle, &runtime_pid).await?;
                if !effective_limits_match(connection.init_pid,u64::from(spec.memory_mb)*1024*1024,expected_cpu_quota).await {
                    return Err(exec_failed("OCI pre-exec CPU/memory limits are not applied; enable systemd user CPU and memory delegation"));
                }
                let _namespace_lease = NamespaceLease::install(
                    self.setup_namespaces.clone(),
                    task_id,
                    connection.namespaces.clone(),
                );
                tokio::time::timeout(
                    SETUP_TIMEOUT,
                    setup.prepare(Arc::new(self.clone()), task_id),
                )
                .await
                .map_err(|_| exec_failed("OCI pre-exec guest setup timed out"))??;
                let current = self.tasks.get(task_id).map(|entry| entry.clone());
                if current
                    .as_ref()
                    .is_none_or(|slot| !Arc::ptr_eq(slot, &owned_slot))
                    || owned_slot.lock().await.finished
                {
                    return Err(exec_failed(
                        "OCI task ownership changed during pre-exec setup",
                    ));
                }
                connection.acknowledge().await
            }
            .await;
            if let Err(error) = result {
                if let Err(cleanup) = self.release_task(task_id).await {
                    return Err(exec_failed(format!("{error}; cleanup pending: {cleanup}")));
                }
                return Err(error);
            }
        }
        // Do not advertise Running until the native runtime has applied the kernel limit.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let expected = u64::from(spec.memory_mb) * 1024 * 1024;
        let launch = loop {
            let slot = self.tasks.get(task_id).map(|s| s.clone()).ok_or_else(|| {
                RuntimeError::TaskNotFound {
                    task_id: task_id.into(),
                }
            })?;
            let record = slot.lock().await;
            if record.finished {
                // A successful native run also proves required resources were accepted;
                // short-lived tasks can exit before /proc exposes their cgroup to us.
                if record.state == TaskState::Completed {
                    break Ok(());
                }
                break Err(exec_failed(format!(
                    "OCI launch failed: {}",
                    record.output.text()
                )));
            }
            let pid_path = record.bundle.join("pid");
            drop(record);
            if let Ok(pid) = tokio::fs::read_to_string(pid_path).await {
                if let Ok(pid) = pid.trim().parse::<u32>() {
                    if effective_limits_match(pid, expected, expected_cpu_quota).await {
                        break Ok(());
                    }
                }
            }
            if tokio::time::Instant::now() >= deadline {
                break Err(exec_failed(
                    "OCI CPU/memory limits could not be verified; enable systemd user CPU and memory delegation",
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        if let Err(error) = launch {
            // Keep ownership if termination cannot be proven; the caller can retry release.
            if let Err(cleanup) = self.release_task(task_id).await {
                return Err(exec_failed(format!("{error}; cleanup pending: {cleanup}")));
            }
            return Err(error);
        }
        Ok(TaskHandle {
            task_id: task_id.into(),
            state: TaskState::Running,
        })
    }

    /// Launch an OCI workload with its own network namespace and wait until its loopback
    /// TCP service accepts connections. Lambda tasks continue using `start_task` and host net.
    pub async fn start_isolated_service(
        &self,
        task_id: &str,
        spec: &TaskSpec,
        guest_port: u16,
        readiness_timeout: Duration,
    ) -> Result<TaskHandle, RuntimeError> {
        let cpu_units = spec
            .vcpu_count
            .checked_mul(1024)
            .ok_or_else(|| exec_failed("OCI vcpu_count exceeds supported CPU units"))?;
        self.start_isolated_service_with_cpu_units(
            task_id,
            spec,
            guest_port,
            readiness_timeout,
            cpu_units,
        )
        .await
    }

    /// Start a service with an exact ECS-style CPU allocation (1024 units per vCPU).
    pub async fn start_isolated_service_with_cpu_units(
        &self,
        task_id: &str,
        spec: &TaskSpec,
        guest_port: u16,
        readiness_timeout: Duration,
        cpu_units: u32,
    ) -> Result<TaskHandle, RuntimeError> {
        self.start_service(
            task_id,
            spec,
            guest_port,
            readiness_timeout,
            cpu_units,
            None,
        )
        .await
    }

    /// Install owned guest endpoints before the image entrypoint is allowed to execute.
    pub async fn start_isolated_service_with_setup(
        &self,
        task_id: &str,
        spec: &TaskSpec,
        guest_port: u16,
        readiness_timeout: Duration,
        cpu_units: u32,
        setup: Arc<dyn IsolatedGuestSetup>,
    ) -> Result<TaskHandle, RuntimeError> {
        self.start_service(
            task_id,
            spec,
            guest_port,
            readiness_timeout,
            cpu_units,
            Some(setup),
        )
        .await
    }

    async fn start_service(
        &self,
        task_id: &str,
        spec: &TaskSpec,
        guest_port: u16,
        readiness_timeout: Duration,
        cpu_units: u32,
        setup: Option<Arc<dyn IsolatedGuestSetup>>,
    ) -> Result<TaskHandle, RuntimeError> {
        if guest_port == 0 {
            return Err(exec_failed("guest TCP port must be nonzero"));
        }
        let handle = self
            .start_task_with_network_and_cpu(task_id, spec, true, cpu_units, setup)
            .await?;
        let deadline = Instant::now() + readiness_timeout;
        loop {
            if self.task_state(task_id).await? != TaskState::Running {
                let output = self.get_output(task_id).await.unwrap_or_default();
                return Err(exec_failed(format!(
                    "OCI service exited before readiness: {output}"
                )));
            }
            let probe_error = match self
                .connect_isolated_tcp(task_id, guest_port, Duration::from_millis(150))
                .await
            {
                Ok(_) => return Ok(handle),
                Err(error) => error,
            };
            if Instant::now() >= deadline {
                let output = self.get_output(task_id).await.unwrap_or_default();
                let _ = self.stop_task(task_id).await;
                return Err(exec_failed(format!(
                    "OCI service readiness timed out on port {guest_port}: {probe_error}; output: {output}"
                )));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Connect to a service listening on 127.0.0.1 in an isolated OCI task's netns.
    /// A short-lived child enters the namespace and passes back the socket descriptor.
    pub async fn connect_isolated_tcp(
        &self,
        task_id: &str,
        guest_port: u16,
        timeout: Duration,
    ) -> Result<tokio::net::TcpStream, RuntimeError> {
        let (user_ns, net_ns) = self.isolated_namespace_files(task_id, false).await?;
        let stream = tokio::task::spawn_blocking(move || {
            crate::netns_socket::connect(user_ns, net_ns, guest_port, timeout)
        })
        .await
        .map_err(|e| exec_failed(format!("OCI connector worker failed: {e}")))?
        .map_err(|e| exec_failed(format!("connecting to isolated OCI service: {e}")))?;
        tokio::net::TcpStream::from_std(stream)
            .map_err(|e| exec_failed(format!("adopting OCI TCP socket: {e}")))
    }

    /// Bind a TCP listener on isolated guest loopback without exposing a host port.
    /// The returned listener can be serviced by the host's Tokio runtime.
    pub async fn bind_isolated_tcp(
        &self,
        task_id: &str,
        guest_port: u16,
    ) -> Result<tokio::net::TcpListener, RuntimeError> {
        if guest_port == 0 {
            return Err(exec_failed("guest TCP port must be nonzero"));
        }
        let (user_ns, net_ns) = self.isolated_namespace_files(task_id, true).await?;
        let listener = tokio::task::spawn_blocking(move || {
            crate::netns_socket::bind_listener(
                user_ns,
                net_ns,
                std::net::Ipv4Addr::LOCALHOST,
                guest_port,
            )
        })
        .await
        .map_err(|e| exec_failed(format!("OCI listener worker failed: {e}")))?
        .map_err(|e| exec_failed(format!("binding isolated OCI listener: {e}")))?;
        tokio::net::TcpListener::from_std(listener)
            .map_err(|e| exec_failed(format!("adopting OCI TCP listener: {e}")))
    }

    /// Bind a private IPv4 address in the guest netns while retaining the accepted
    /// socket in the host process. The address is assigned only to guest loopback.
    pub async fn bind_isolated_private_tcp(
        &self,
        task_id: &str,
        address: std::net::Ipv4Addr,
        port: u16,
    ) -> Result<tokio::net::TcpListener, RuntimeError> {
        if port == 0 || address.is_loopback() || address.is_unspecified() {
            return Err(exec_failed(
                "private guest listener needs a non-loopback IPv4 address and port",
            ));
        }
        let (user_ns, net_ns) = self.isolated_namespace_files(task_id, false).await?;
        let listener = tokio::task::spawn_blocking(move || {
            crate::netns_socket::bind_listener(user_ns, net_ns, address, port)
        })
        .await
        .map_err(|e| exec_failed(format!("private listener worker failed: {e}")))?
        .map_err(|e| exec_failed(format!("binding private OCI listener: {e}")))?;
        tokio::net::TcpListener::from_std(listener)
            .map_err(|e| exec_failed(format!("adopting private OCI listener: {e}")))
    }

    pub async fn bind_isolated_dns(
        &self,
        task_id: &str,
    ) -> Result<(tokio::net::UdpSocket, tokio::net::TcpListener), RuntimeError> {
        let (user_ns, net_ns) = self.isolated_namespace_files(task_id, false).await?;
        let tcp_user = user_ns
            .try_clone()
            .map_err(|e| exec_failed(e.to_string()))?;
        let tcp_net = net_ns.try_clone().map_err(|e| exec_failed(e.to_string()))?;
        let address = std::net::Ipv4Addr::new(169, 254, 169, 253);
        let udp = tokio::task::spawn_blocking(move || {
            crate::netns_socket::bind_udp(user_ns, net_ns, address, 53)
        })
        .await
        .map_err(|e| exec_failed(format!("OCI DNS UDP worker failed: {e}")))?
        .map_err(|e| exec_failed(format!("binding isolated OCI DNS UDP: {e}")))?;
        let tcp = tokio::task::spawn_blocking(move || {
            crate::netns_socket::bind_listener(tcp_user, tcp_net, address, 53)
        })
        .await
        .map_err(|e| exec_failed(format!("OCI DNS TCP worker failed: {e}")))?
        .map_err(|e| exec_failed(format!("binding isolated OCI DNS TCP: {e}")))?;
        Ok((
            tokio::net::UdpSocket::from_std(udp)
                .map_err(|e| exec_failed(format!("adopting isolated OCI DNS UDP: {e}")))?,
            tokio::net::TcpListener::from_std(tcp)
                .map_err(|e| exec_failed(format!("adopting isolated OCI DNS TCP: {e}")))?,
        ))
    }

    /// Bind a UDP socket on a link-local guest-loopback address of the isolated netns.
    pub async fn bind_isolated_udp(
        &self,
        task_id: &str,
        address: std::net::Ipv4Addr,
        port: u16,
    ) -> Result<tokio::net::UdpSocket, RuntimeError> {
        if port == 0 || !address.is_link_local() {
            return Err(exec_failed(
                "isolated UDP endpoint needs a link-local IPv4 address and port",
            ));
        }
        let (user_ns, net_ns) = self.isolated_namespace_files(task_id, false).await?;
        let socket = tokio::task::spawn_blocking(move || {
            crate::netns_socket::bind_udp(user_ns, net_ns, address, port)
        })
        .await
        .map_err(|e| exec_failed(format!("OCI UDP worker failed: {e}")))?
        .map_err(|e| exec_failed(format!("binding isolated OCI UDP endpoint: {e}")))?;
        tokio::net::UdpSocket::from_std(socket)
            .map_err(|e| exec_failed(format!("adopting isolated OCI UDP endpoint: {e}")))
    }

    pub async fn bind_isolated_public_egress(
        &self,
        task_id: &str,
        private_addresses: &[std::net::Ipv4Addr],
    ) -> Result<tokio::net::TcpListener, RuntimeError> {
        self.bind_isolated_egress(task_id, EgressCapture::PublicOnly, private_addresses)
            .await
    }

    /// Capture all non-local IPv4 TCP; the host must authorize every original destination.
    pub async fn bind_isolated_vpc_egress(
        &self,
        task_id: &str,
    ) -> Result<tokio::net::TcpListener, RuntimeError> {
        self.bind_isolated_egress(task_id, EgressCapture::Vpc, &[])
            .await
    }

    async fn bind_isolated_egress(
        &self,
        task_id: &str,
        mode: EgressCapture,
        private_addresses: &[std::net::Ipv4Addr],
    ) -> Result<tokio::net::TcpListener, RuntimeError> {
        let (user_ns, net_ns) = self.isolated_namespace_files(task_id, false).await?;
        let user_for_tcp = user_ns
            .try_clone()
            .map_err(|e| exec_failed(e.to_string()))?;
        let net_for_tcp = net_ns.try_clone().map_err(|e| exec_failed(e.to_string()))?;
        let tcp = tokio::task::spawn_blocking(move || {
            crate::netns_socket::bind_listener(
                user_for_tcp,
                net_for_tcp,
                std::net::Ipv4Addr::LOCALHOST,
                VPC_EGRESS_PORT,
            )
        })
        .await
        .map_err(|e| exec_failed(format!("public listener worker failed: {e}")))?
        .map_err(|e| exec_failed(format!("binding public OCI listener: {e}")))?;
        let (user_ns, net_ns) = self.isolated_namespace_files(task_id, false).await?;
        let excluded = private_addresses.to_vec();
        async move {
            async fn run(
                user_ns: &std::fs::File,
                net_ns: &std::fs::File,
                program: &str,
                args: &[&str],
            ) -> std::io::Result<()> {
                let mut command = Command::new(program);
                command.args(args).kill_on_drop(true);
                let user_fd = user_ns.as_raw_fd();
                let net_fd = net_ns.as_raw_fd();
                // SAFETY: pre_exec invokes only async-signal-safe setns calls.
                unsafe {
                    command.pre_exec(move || {
                        if libc::setns(user_fd, libc::CLONE_NEWUSER) != 0
                            || libc::setns(net_fd, libc::CLONE_NEWNET) != 0
                        {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let output = tokio::time::timeout(Duration::from_secs(5), command.output())
                    .await
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{program} guest-network setup timed out")))??;
                if !output.status.success() {
                    return Err(std::io::Error::other(format!(
                        "{program}: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    )));
                }
                Ok(())
            }
            run(
                &user_ns,
                &net_ns,
                "nft",
                &["add", "table", "ip", "locallycloud"],
            ).await?;
            run(
                &user_ns,
                &net_ns,
                "nft",
                &[
                    "add",
                    "chain",
                    "ip",
                    "locallycloud",
                    "output",
                    "{ type nat hook output priority dstnat; policy accept; }",
                ],
            ).await?;
            let excluded = mode.excluded_ranges(&excluded);
            let rule = format!(
                "ip daddr != {{ {} }} meta l4proto tcp redirect to :{VPC_EGRESS_PORT}",
                excluded.join(", ")
            );
            run(
                &user_ns,
                &net_ns,
                "nft",
                &["add", "rule", "ip", "locallycloud", "output", &rule],
            ).await?;
            run(
                &user_ns,
                &net_ns,
                "ip",
                &[
                    "route", "add", "local", "default", "dev", "lo", "table", "local",
                ],
            ).await
        }
        .await
        .map_err(|e| {
            exec_failed(format!(
                "isolated IPv4 TCP egress requires rootless ip/nft and kernel nft_redir support; if kernel modules no longer match the running kernel after an upgrade, reboot into the installed kernel: {e}"
            ))
        })?;
        let tcp = tokio::net::TcpListener::from_std(tcp)
            .map_err(|e| exec_failed(format!("adopting public OCI listener: {e}")))?;
        Ok(tcp)
    }

    async fn isolated_namespace_files(
        &self,
        task_id: &str,
        allow_created: bool,
    ) -> Result<(std::fs::File, std::fs::File), RuntimeError> {
        let slot = self.tasks.get(task_id).map(|s| s.clone()).ok_or_else(|| {
            RuntimeError::TaskNotFound {
                task_id: task_id.to_string(),
            }
        })?;
        let record = slot.lock().await;
        if !record.isolated_network || record.state != TaskState::Running {
            return Err(exec_failed("task is not a running isolated OCI service"));
        }
        let expected_bundle = record.bundle.clone();
        drop(record);
        let setup_namespaces = self
            .setup_namespaces
            .get(task_id)
            .map(|entry| entry.clone());
        if let Some(files) = setup_namespaces {
            if files.bundle != expected_bundle {
                return Err(exec_failed("OCI setup namespace ownership mismatch"));
            }
            return files.duplicate();
        }
        let state = self.oci_command(&["state", task_id]).await?;
        if !state.status.success() {
            return Err(exec_failed(format!(
                "reading OCI service state: {}",
                String::from_utf8_lossy(&state.stderr).trim()
            )));
        }
        let state: serde_json::Value = serde_json::from_slice(&state.stdout)
            .map_err(|e| exec_failed(format!("parsing OCI service state: {e}")))?;
        if state["id"].as_str() != Some(task_id)
            || state["bundle"].as_str() != expected_bundle.to_str()
            || !(state["status"].as_str() == Some("running")
                || allow_created && state["status"].as_str() == Some("created"))
        {
            return Err(exec_failed("OCI service state does not match running task"));
        }
        let pid = state["pid"]
            .as_u64()
            .filter(|pid| *pid > 0)
            .ok_or_else(|| exec_failed("OCI service state has no valid PID"))?;
        tokio::task::spawn_blocking(move || {
            let user_ns = std::fs::File::open(format!("/proc/{pid}/ns/user"))
                .map_err(|e| exec_failed(format!("opening OCI user namespace: {e}")))?;
            let net_ns = std::fs::File::open(format!("/proc/{pid}/ns/net"))
                .map_err(|e| exec_failed(format!("opening OCI network namespace: {e}")))?;
            Ok((user_ns, net_ns))
        })
        .await
        .map_err(|e| exec_failed(format!("opening OCI namespace worker failed: {e}")))?
    }
}

#[async_trait]
impl ComputeRuntime for YoukiRuntime {
    async fn start_task(&self, task_id: &str, spec: &TaskSpec) -> Result<TaskHandle, RuntimeError> {
        self.start_task_with_network(task_id, spec, false).await
    }

    async fn start_task_isolated_with_loopback(
        &self,
        task_id: &str,
        spec: &TaskSpec,
        ports: &[u16],
    ) -> Result<(TaskHandle, Vec<tokio::net::TcpListener>), RuntimeError> {
        if ports.is_empty() {
            return Err(exec_failed(
                "isolated task requires at least one loopback listener",
            ));
        }
        let handle = self.start_task_with_network(task_id, spec, true).await?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut listeners = Vec::with_capacity(ports.len());
        for &port in ports {
            loop {
                match self.bind_isolated_tcp(task_id, port).await {
                    Ok(listener) => {
                        listeners.push(listener);
                        break;
                    }
                    Err(error)
                        if Instant::now() < deadline
                            && self.task_state(task_id).await? == TaskState::Running =>
                    {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        tracing::trace!(%error, "waiting for OCI guest namespace");
                    }
                    Err(error) => {
                        let _ = self.stop_task(task_id).await;
                        return Err(error);
                    }
                }
            }
        }
        Ok((handle, listeners))
    }

    async fn bind_isolated_private_tcp(
        &self,
        task_id: &str,
        address: std::net::Ipv4Addr,
        port: u16,
    ) -> Result<tokio::net::TcpListener, RuntimeError> {
        YoukiRuntime::bind_isolated_private_tcp(self, task_id, address, port).await
    }

    async fn bind_isolated_public_egress(
        &self,
        task_id: &str,
        private_addresses: &[std::net::Ipv4Addr],
    ) -> Result<tokio::net::TcpListener, RuntimeError> {
        YoukiRuntime::bind_isolated_public_egress(self, task_id, private_addresses).await
    }

    async fn bind_isolated_dns(
        &self,
        task_id: &str,
    ) -> Result<(tokio::net::UdpSocket, tokio::net::TcpListener), RuntimeError> {
        YoukiRuntime::bind_isolated_dns(self, task_id).await
    }

    async fn bind_isolated_udp(
        &self,
        task_id: &str,
        address: std::net::Ipv4Addr,
        port: u16,
    ) -> Result<tokio::net::UdpSocket, RuntimeError> {
        YoukiRuntime::bind_isolated_udp(self, task_id, address, port).await
    }

    async fn stop_task(&self, task_id: &str) -> Result<TaskHandle, RuntimeError> {
        let slot = self.tasks.get(task_id).map(|s| s.clone()).ok_or_else(|| {
            RuntimeError::TaskNotFound {
                task_id: task_id.to_string(),
            }
        })?;

        let state = slot.lock().await.state;
        if state == TaskState::Completed {
            return Err(RuntimeError::TaskAlreadyCompleted {
                task_id: task_id.to_string(),
            });
        }
        if state == TaskState::Stopped || state == TaskState::Failed {
            wait_finished(&slot).await?;
            return Ok(TaskHandle {
                task_id: task_id.to_string(),
                state,
            });
        }

        let killed = self
            .oci_command(&["kill", "--all", task_id, "KILL"])
            .await?;
        if !killed.status.success() {
            let stderr = String::from_utf8_lossy(&killed.stderr);
            let error = exec_failed(format!("stopping OCI task: {}", stderr.trim()));
            if !oci_state_missing(&stderr, task_id) {
                return Err(error);
            }
            // `run` can exit and remove OCI state after the initial Running snapshot.
            // Only the owned monitor and drained readers establish the terminal outcome.
            wait_finished(&slot).await?;
            let state = slot.lock().await.state;
            return match state {
                TaskState::Completed => Err(RuntimeError::TaskAlreadyCompleted {
                    task_id: task_id.into(),
                }),
                TaskState::Stopped | TaskState::Failed => Ok(TaskHandle {
                    task_id: task_id.into(),
                    state,
                }),
                TaskState::Running => Err(error),
            };
        }
        let mut record = slot.lock().await;
        if record.state == TaskState::Running {
            record.state = TaskState::Stopped;
        }
        let state = record.state;
        drop(record);
        wait_finished(&slot).await?;
        Ok(TaskHandle {
            task_id: task_id.into(),
            state,
        })
    }

    async fn reconcile_orphaned_task(&self, task_id: &str) -> Result<bool, RuntimeError> {
        self.ensure_runtime_available()?;
        let state = self.oci_command(&["state", task_id]).await?;
        if !state.status.success() {
            // `run` can remove its state after the owning server dies. Preserve
            // the rootfs on any error other than an explicit missing container.
            let stderr = String::from_utf8_lossy(&state.stderr);
            if !oci_state_missing(&stderr, task_id) {
                return Ok(false);
            }
            // A successful runtime inventory must also omit this exact ID.
            let listed = self.oci_command(&["list", "--quiet"]).await?;
            if !listed.status.success() {
                return Ok(false);
            }
            let inventory = String::from_utf8_lossy(&listed.stdout);
            return Ok(!inventory.lines().any(|id| id.trim() == task_id));
        }
        let value: serde_json::Value = serde_json::from_slice(&state.stdout)
            .map_err(|e| exec_failed(format!("parsing OCI state: {e}")))?;
        if value.get("id").and_then(|id| id.as_str()) != Some(task_id) {
            return Err(exec_failed("OCI state ID differs from rootfs owner"));
        }
        let bundle = value
            .get("bundle")
            .and_then(|bundle| bundle.as_str())
            .map(Path::new)
            .ok_or_else(|| exec_failed("OCI state has no bundle path"))?;
        let expected_prefix = format!("locallycloud-{task_id}-");
        if !bundle.starts_with(&self.bundle_root)
            || !bundle
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&expected_prefix))
        {
            return Err(exec_failed("OCI state bundle is not owned by LocallyCloud"));
        }
        match value.get("status").and_then(|status| status.as_str()) {
            Some("running" | "created" | "creating") => {
                let killed = self
                    .oci_command(&["kill", "--all", task_id, "KILL"])
                    .await?;
                if !killed.status.success() {
                    return Err(exec_failed(format!(
                        "stopping orphaned OCI guest: {}",
                        String::from_utf8_lossy(&killed.stderr).trim()
                    )));
                }
            }
            Some("stopped") => {}
            _ => return Ok(false),
        }
        let deleted = self.oci_command(&["delete", "--force", task_id]).await?;
        if !deleted.status.success() {
            // `crun run` may remove its own state between observation and deletion.
            // Confirm both exact state absence and inventory absence before accepting it.
            let state = self.oci_command(&["state", task_id]).await?;
            let missing = String::from_utf8_lossy(&state.stderr);
            if !state.status.success() && oci_state_missing(&missing, task_id) {
                let listed = self.oci_command(&["list", "--quiet"]).await?;
                if listed.status.success()
                    && !String::from_utf8_lossy(&listed.stdout)
                        .lines()
                        .any(|id| id.trim() == task_id)
                {
                    return Ok(true);
                }
            }
            return Err(exec_failed(format!(
                "deleting orphaned OCI guest: {}",
                String::from_utf8_lossy(&deleted.stderr).trim()
            )));
        }
        Ok(true)
    }

    async fn task_state(&self, task_id: &str) -> Result<TaskState, RuntimeError> {
        let slot = self.tasks.get(task_id).map(|s| s.clone()).ok_or_else(|| {
            RuntimeError::TaskNotFound {
                task_id: task_id.to_string(),
            }
        })?;
        let state = slot.lock().await.state;
        Ok(state)
    }

    async fn read_output(&self, task_id: &str, cursor: u64) -> Result<TaskOutput, RuntimeError> {
        let slot = self.tasks.get(task_id).map(|s| s.clone()).ok_or_else(|| {
            RuntimeError::TaskNotFound {
                task_id: task_id.into(),
            }
        })?;
        let output = slot.lock().await.output.read(cursor);
        Ok(output)
    }

    async fn release_task(&self, task_id: &str) -> Result<(), RuntimeError> {
        let Some(slot) = self.tasks.get(task_id).map(|s| s.clone()) else {
            return Ok(());
        };
        // Terminate descendants before draining: inherited pipes may otherwise never reach EOF.
        if !self.reconcile_orphaned_task(task_id).await? {
            return Err(exec_failed(
                "OCI task termination could not be verified; retaining bundle",
            ));
        }
        wait_finished(&slot).await?;
        let bundle = slot.lock().await.bundle.clone();
        match tokio::fs::remove_dir_all(&bundle).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(exec_failed(format!("removing OCI bundle: {error}"))),
        }
        self.tasks
            .remove_if(task_id, |_, current| Arc::ptr_eq(current, &slot));
        Ok(())
    }

    async fn get_output(&self, task_id: &str) -> Result<String, RuntimeError> {
        let slot = self.tasks.get(task_id).map(|s| s.clone()).ok_or_else(|| {
            RuntimeError::TaskNotFound {
                task_id: task_id.to_string(),
            }
        })?;
        let captured = slot.lock().await.output.text();
        Ok(captured)
    }
}

async fn wait_finished(slot: &Slot) -> Result<(), RuntimeError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !slot.lock().await.finished {
        if tokio::time::Instant::now() >= deadline {
            return Err(exec_failed(
                "OCI task output drain timed out; retaining task and bundle",
            ));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

async fn stream_output(mut pipe: impl AsyncRead + Unpin, slot: Slot) {
    let mut chunk = [0_u8; 8192];
    loop {
        match pipe.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(count) => slot.lock().await.output.extend_from_slice(&chunk[..count]),
        }
    }
}

fn oci_state_missing(stderr: &str, task_id: &str) -> bool {
    let message = stderr.trim();
    if [
        format!("container {task_id} does not exist"),
        format!("container `{task_id}` does not exist"),
        format!("container {task_id} not found"),
        format!("container `{task_id}` not found"),
    ]
    .iter()
    .any(|prefix| {
        message
            .strip_prefix(prefix.as_str())
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(':'))
    }) {
        return true;
    }
    // crun reports an absent container as ENOENT for its own status file.
    // Other missing files, permission failures and another container are not absence.
    let Some(path) = stderr
        .trim()
        .strip_prefix("error opening file `")
        .or_else(|| stderr.trim().strip_prefix("open `"))
        .and_then(|message| {
            [
                "': No such file or directory",
                "`: No such file or directory",
            ]
            .iter()
            .find_map(|suffix| message.strip_suffix(*suffix))
        })
    else {
        return false;
    };
    let path = Path::new(path);
    let Some(container) = path.parent() else {
        return false;
    };
    path.is_absolute()
        && path.file_name().is_some_and(|name| name == "status")
        && container.file_name().is_some_and(|name| name == task_id)
        && container
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "crun")
}

fn exec_failed(reason: impl Into<String>) -> RuntimeError {
    RuntimeError::ExecutionFailed {
        reason: reason.into(),
    }
}

const CPU_PERIOD_US: u64 = 100_000;

fn cpu_quota(cpu_units: u32) -> Result<u64, RuntimeError> {
    let quota = u64::from(cpu_units)
        .checked_mul(CPU_PERIOD_US)
        .map(|value| value / 1024)
        .ok_or_else(|| exec_failed("OCI CPU quota exceeds supported range"))?;
    if quota < 1000 {
        return Err(exec_failed("OCI CPU allocation must provide at least 1000 microseconds per 100000 microsecond period"));
    }
    Ok(quota)
}

async fn effective_limits_match(pid: u32, expected_memory: u64, expected_cpu_quota: u64) -> bool {
    let Ok(groups) = tokio::fs::read_to_string(format!("/proc/{pid}/cgroup")).await else {
        return false;
    };
    let Some(group) = groups.lines().find_map(|line| line.strip_prefix("0::")) else {
        return false;
    };
    let path = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    let Ok(memory) = tokio::fs::read_to_string(path.join("memory.max")).await else {
        return false;
    };
    let Ok(swap) = tokio::fs::read_to_string(path.join("memory.swap.max")).await else {
        return false;
    };
    let Ok(cpu) = tokio::fs::read_to_string(path.join("cpu.max")).await else {
        return false;
    };
    memory.trim().parse::<u64>() == Ok(expected_memory)
        && swap.trim() == "0"
        && cpu_limit_matches(&cpu, expected_cpu_quota)
}

fn cpu_limit_matches(value: &str, expected_quota: u64) -> bool {
    let mut fields = value.split_whitespace();
    fields.next().and_then(|value| value.parse::<u64>().ok()) == Some(expected_quota)
        && fields.next().and_then(|value| value.parse::<u64>().ok()) == Some(CPU_PERIOD_US)
        && fields.next().is_none()
}

/// Resolve an executable name against `PATH`, returning the first match.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn spec() -> TaskSpec {
        TaskSpec {
            name: "hello".into(),
            image: "busybox".into(),
            command: vec!["echo".into(), "hi".into()],
            env: HashMap::new(),
            memory_mb: 128,
            vcpu_count: 1,
        }
    }

    fn slot_with(state: TaskState) -> Slot {
        Arc::new(Mutex::new(TaskRecord {
            state,
            output: {
                let mut out = crate::output::OutputCapture::default();
                out.extend_from_slice(b"out");
                out
            },
            finished: state != TaskState::Running,
            bundle: PathBuf::new(),
            isolated_network: false,
        }))
    }

    #[test]
    fn vpc_capture_includes_private_ranges_but_preserves_guest_metadata_and_loopback() {
        let vpc = EgressCapture::Vpc.excluded_ranges(&[]);
        assert_eq!(vpc, ["127.0.0.0/8", "169.254.0.0/16"]);
        let private_ip = "10.0.1.2".parse().unwrap();
        let public = EgressCapture::PublicOnly.excluded_ranges(&[private_ip]);
        for range in [
            "127.0.0.0/8",
            "169.254.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "10.0.1.2",
        ] {
            assert!(public.iter().any(|entry| entry == range), "{range}");
        }
    }

    #[tokio::test]
    async fn oci_bundle_requires_exact_memory_limit() {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::env::temp_dir().join(format!("compute-memory-config-{}", std::process::id()));
        crate::private_dir::ensure(&root).unwrap();
        let binary = root.join("runtime");
        std::fs::write(&binary, "#!/bin/sh\nprintf '%s' '{\"process\":{},\"root\":{},\"linux\":{\"namespaces\":[]},\"mounts\":[]}' > config.json\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let rt = YoukiRuntime::new(binary);
        let mut task = spec();
        task.memory_mb = 257;
        rt.write_bundle_config(&root, &task, &root, false, 1024, None)
            .await
            .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("config.json")).unwrap()).unwrap();
        assert_eq!(
            value["linux"]["resources"]["memory"]["limit"],
            257_u64 * 1024 * 1024
        );
        assert_eq!(
            value["linux"]["resources"]["memory"]["swap"],
            257_u64 * 1024 * 1024
        );
        for (units, quota) in [
            (256, 25_000),
            (512, 50_000),
            (1024, 100_000),
            (2048, 200_000),
        ] {
            rt.write_bundle_config(&root, &task, &root, true, units, None)
                .await
                .unwrap();
            let value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join("config.json")).unwrap()).unwrap();
            assert_eq!(value["linux"]["resources"]["cpu"]["period"], 100_000);
            assert_eq!(value["linux"]["resources"]["cpu"]["quota"], quota);
            assert!(value["linux"]["namespaces"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value["type"] == "network"));
        }
        let gate = SetupGate::for_test();
        rt.write_bundle_config(&root, &task, &root, true, 256, Some(&gate))
            .await
            .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("config.json")).unwrap()).unwrap();
        assert_eq!(
            value["hooks"]["createContainer"][0]["args"][1],
            "--internal-oci-setup-gate"
        );
        assert_eq!(
            value["hooks"]["createContainer"][0]["args"][2],
            gate.address
        );
        assert_eq!(value["hooks"]["createContainer"][0]["timeout"], 50);
        assert_eq!(value["process"]["args"], serde_json::json!(["echo", "hi"]));
        for units in [0, 1, 10] {
            assert!(rt
                .write_bundle_config(&root, &task, &root, false, units, None)
                .await
                .is_err());
        }
        task.memory_mb = 0;
        assert!(rt
            .write_bundle_config(&root, &task, &root, false, 1024, None)
            .await
            .is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cpu_max_verification_rejects_unlimited_or_wrong_limits() {
        assert_eq!(cpu_quota(256).unwrap(), 25_000);
        assert_eq!(cpu_quota(u32::MAX).unwrap(), 419_430_399_902);
        assert!(cpu_limit_matches("25000 100000\n", 25_000));
        for value in [
            "max 100000",
            "50000 100000",
            "25000 50000",
            "25000",
            "25000 100000 extra",
            "",
            "-1 100000",
        ] {
            assert!(!cpu_limit_matches(value, 25_000), "{value}");
        }
    }

    #[tokio::test]
    async fn finalized_task_churn_and_failed_cleanup_retry() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("compute-release-{}", std::process::id()));
        crate::private_dir::ensure(&root).unwrap();
        let binary = root.join("runtime");
        std::fs::write(&binary, "#!/bin/sh\ncase \"$1\" in state) echo \"container $2 does not exist\" >&2; exit 1;; list) exit 0;; esac\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let rt = YoukiRuntime::new(binary);
        for n in 0..32 {
            let id = format!("ended-{n}");
            let slot = slot_with(TaskState::Completed);
            let bundle = root.join(&id);
            std::fs::create_dir(&bundle).unwrap();
            slot.lock().await.bundle = bundle.clone();
            slot.lock()
                .await
                .output
                .extend_from_slice(&vec![b'x'; 2 * 1024 * 1024]);
            rt.tasks.insert(id.clone(), slot);
            rt.release_task(&id).await.unwrap();
            assert!(!bundle.exists());
            assert!(rt.tasks.is_empty());
            rt.release_task(&id).await.unwrap();
        }
        let slot = slot_with(TaskState::Failed);
        let bundle = root.join("failed-bundle");
        std::fs::write(&bundle, "not a directory").unwrap();
        slot.lock().await.bundle = bundle.clone();
        rt.tasks.insert("retry".into(), slot);
        assert!(rt.release_task("retry").await.is_err());
        assert!(rt.tasks.contains_key("retry"));
        std::fs::remove_file(&bundle).unwrap();
        std::fs::create_dir(&bundle).unwrap();
        rt.release_task("retry").await.unwrap();
        assert!(rt.tasks.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn crun_missing_status_requires_successful_exact_inventory_absence() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "compute-crun-absence-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        crate::private_dir::ensure(&root).unwrap();
        for (index, inventory, released) in [
            (0, "exit 0", true),
            (1, "echo owned-other; exit 0", true),
            (2, "echo owned; exit 0", false),
            (3, "exit 1", false),
        ] {
            let binary = root.join(format!("runtime-{index}"));
            let script = format!(
                r#"#!/bin/sh
case "$1" in
state) printf "error opening file \`/run/user/1000/crun/$2/status': No such file or directory\n" >&2; exit 1 ;;
list) {inventory} ;;
*) exit 1 ;;
esac
"#
            );
            tokio::fs::write(&binary, script).await.unwrap();
            tokio::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
                .await
                .unwrap();
            let runtime = YoukiRuntime::new(binary);
            let slot = slot_with(TaskState::Completed);
            let bundle = root.join(format!("bundle-{index}"));
            tokio::fs::create_dir(&bundle).await.unwrap();
            slot.lock().await.bundle = bundle.clone();
            runtime.tasks.insert("owned".into(), slot);
            assert_eq!(runtime.release_task("owned").await.is_ok(), released);
            assert_eq!(bundle.exists(), !released);
            assert_eq!(runtime.tasks.contains_key("owned"), !released);
        }
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[test]
    fn missing_state_classifier_rejects_unrelated_enoent_and_permission_errors() {
        assert!(oci_state_missing("container owned does not exist", "owned"));
        assert!(oci_state_missing("container owned not found", "owned"));
        assert!(oci_state_missing(
            "error opening file `/run/user/1000/crun/owned/status': No such file or directory\n",
            "owned"
        ));
        assert!(oci_state_missing(
            "error opening file `/run/user/1000/crun/owned/status`: No such file or directory\n",
            "owned"
        ));
        assert!(oci_state_missing(
            "open `/run/user/1000/crun/owned/status`: No such file or directory",
            "owned"
        ));
        for error in [
            "open `/run/user/1000/crun/another/status`: No such file or directory",
            "open `/run/user/1000/crun/owned/status`: Permission denied",
            "OCI configuration not found",
            "container another does not exist",
            "container owned-copy not found",
            "container owned does not existx",
            "No such file or directory",
            "error opening file `/usr/bin/crun': No such file or directory",
            "error opening file `/run/user/1000/crun/another/status': No such file or directory",
            "error opening file `/run/user/1000/crun/owned/config.json': No such file or directory",
            "error opening file `/run/user/1000/crun/owned/status': Permission denied",
            "error opening file `/run/user/1000/other/owned/status': No such file or directory",
            "error opening file `crun/owned/status': No such file or directory",
        ] {
            assert!(!oci_state_missing(error, "owned"), "{error}");
        }
    }

    #[tokio::test]
    async fn crun_state_disappearing_during_delete_still_requires_inventory_absence() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "compute-crun-delete-race-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir(&root).await.unwrap();
        tokio::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
        for (index, inventory, released) in [
            (0, "exit 0", true),
            (1, "echo owned; exit 0", false),
            (2, "exit 1", false),
        ] {
            let binary = root.join(format!("runtime-{index}"));
            let bundle = root.join(format!("locallycloud-owned-{index}"));
            tokio::fs::create_dir(&bundle).await.unwrap();
            let initial_state = serde_json::json!({
                "id": "owned", "status": "stopped", "bundle": bundle
            });
            let script = format!(
                r#"#!/bin/sh
case "$1" in
state)
    if test -f "$0.deleted"; then
        printf "error opening file \`/run/user/1000/crun/$2/status': No such file or directory\n" >&2
        exit 1
    fi
    printf '%s\n' '{initial_state}' ;;
delete) touch "$0.deleted"; echo 'state disappeared during delete' >&2; exit 1 ;;
list) {inventory} ;;
*) exit 1 ;;
esac
"#
            );
            tokio::fs::write(&binary, script).await.unwrap();
            tokio::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
                .await
                .unwrap();
            let mut runtime = YoukiRuntime::new(&binary);
            runtime.bundle_root = root.clone();
            let slot = slot_with(TaskState::Completed);
            slot.lock().await.bundle = bundle.clone();
            runtime.tasks.insert("owned".into(), slot);
            assert_eq!(runtime.release_task("owned").await.is_ok(), released);
            assert!(tokio::fs::try_exists(binary.with_extension("deleted"))
                .await
                .unwrap());
            assert_eq!(tokio::fs::try_exists(&bundle).await.unwrap(), !released);
            assert_eq!(runtime.tasks.contains_key("owned"), !released);
        }
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn stop_reconciles_disappearing_container_with_owned_completion() {
        use std::os::unix::fs::PermissionsExt;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/compute-stop-tests")
            .join(format!(
                "stop-race-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
        let missing = "container `owned` does not exist: open `/run/user/1000/crun/owned/status`: No such file or directory";
        for (index, error, state, finished) in [
            (0, missing, TaskState::Completed, true),
            (1, missing, TaskState::Failed, true),
            (2, missing, TaskState::Stopped, true),
            (3, "permission denied", TaskState::Completed, true),
            (4, missing, TaskState::Running, false),
            (5, missing, TaskState::Completed, false),
            (
                6,
                "error opening file `/usr/bin/crun': No such file or directory",
                TaskState::Completed,
                true,
            ),
            (7, "OCI configuration not found", TaskState::Completed, true),
        ] {
            let binary = root.join(format!("runtime-{index}"));
            let bundle = root.join(format!("bundle-{index}"));
            tokio::fs::create_dir(&bundle).await.unwrap();
            tokio::fs::write(binary.with_extension("stderr"), error)
                .await
                .unwrap();
            tokio::fs::write(
                &binary,
                r#"#!/bin/sh
[ "$1" = kill ] || exit 99
: > "$0.entered"
while [ ! -f "$0.release" ]; do sleep 0.01; done
cat "$0.stderr" >&2
exit 1
"#,
            )
            .await
            .unwrap();
            tokio::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
                .await
                .unwrap();
            let runtime = Arc::new(YoukiRuntime::new(&binary));
            let slot = slot_with(TaskState::Running);
            slot.lock().await.bundle = bundle.clone();
            runtime.tasks.insert("owned".into(), slot.clone());
            let runner = runtime.clone();
            let stop = tokio::spawn(async move { runner.stop_task("owned").await });
            tokio::time::timeout(Duration::from_secs(3), async {
                while !tokio::fs::try_exists(binary.with_extension("entered"))
                    .await
                    .unwrap()
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            // The kill command is in flight: the original Running observation is stale.
            {
                let mut record = slot.lock().await;
                record.state = state;
                record.finished = finished;
            }
            tokio::fs::write(binary.with_extension("release"), [])
                .await
                .unwrap();
            if index == 5 {
                tokio::time::sleep(Duration::from_millis(30)).await;
                assert!(
                    !stop.is_finished(),
                    "completion must wait for owned output readers"
                );
                slot.lock().await.finished = true;
            }
            let result = tokio::time::timeout(Duration::from_secs(7), stop)
                .await
                .unwrap()
                .unwrap();
            match index {
                0 | 5 => assert!(matches!(
                    result,
                    Err(RuntimeError::TaskAlreadyCompleted { .. })
                )),
                1 | 2 => assert_eq!(result.unwrap().state, state),
                3 | 6 | 7 => assert!(
                    matches!(result, Err(RuntimeError::ExecutionFailed { reason }) if reason.contains(error))
                ),
                4 => assert!(
                    matches!(result, Err(RuntimeError::ExecutionFailed { reason }) if reason.contains("output drain timed out"))
                ),
                _ => unreachable!(),
            }
            assert_eq!(slot.lock().await.state, state);
            assert_eq!(runtime.get_output("owned").await.unwrap(), "out");
            assert!(runtime.tasks.contains_key("owned"));
            assert!(tokio::fs::try_exists(bundle).await.unwrap());
        }
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn missing_runtime_binary_is_typed_error() {
        let rt = YoukiRuntime::new("/nonexistent/path/to/youki");
        let err = rt.start_task("t1", &spec()).await.unwrap_err();
        assert!(matches!(err, RuntimeError::OciRuntimeNotFound { .. }));
    }

    #[tokio::test]
    async fn stop_unknown_task_is_not_found() {
        let rt = YoukiRuntime::new("/nonexistent/path/to/youki");
        let err = rt.stop_task("nope").await.unwrap_err();
        assert!(matches!(err, RuntimeError::TaskNotFound { .. }));
    }

    #[tokio::test]
    async fn stop_completed_task_is_already_completed() {
        let rt = YoukiRuntime::new("/nonexistent/path/to/youki");
        rt.tasks
            .insert("done".into(), slot_with(TaskState::Completed));
        let err = rt.stop_task("done").await.unwrap_err();
        assert!(matches!(err, RuntimeError::TaskAlreadyCompleted { .. }));
    }

    #[tokio::test]
    async fn task_state_distinguishes_running_and_failed() {
        let rt = YoukiRuntime::new("/nonexistent/path/to/youki");
        rt.tasks
            .insert("running".into(), slot_with(TaskState::Running));
        rt.tasks
            .insert("failed".into(), slot_with(TaskState::Failed));
        assert_eq!(rt.task_state("running").await.unwrap(), TaskState::Running);
        assert_eq!(rt.task_state("failed").await.unwrap(), TaskState::Failed);
        assert!(matches!(
            rt.task_state("missing").await,
            Err(RuntimeError::TaskNotFound { .. })
        ));
    }

    #[tokio::test]
    async fn get_output_unknown_task_is_not_found() {
        let rt = YoukiRuntime::new("/nonexistent/path/to/youki");
        let err = rt.get_output("nope").await.unwrap_err();
        assert!(matches!(err, RuntimeError::TaskNotFound { .. }));
    }
}
