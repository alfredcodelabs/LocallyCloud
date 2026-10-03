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

use crate::runtime::{ComputeRuntime, RuntimeError, TaskHandle, TaskSpec, TaskState};

struct TaskRecord {
    state: TaskState,
    output: Vec<u8>,
    bundle: PathBuf,
    isolated_network: bool,
}

type Slot = Arc<Mutex<TaskRecord>>;

pub struct YoukiRuntime {
    /// Path to the `youki` or `crun` binary.
    runtime_binary: PathBuf,
    /// Base directory under which per-task OCI bundles are created.
    bundle_root: PathBuf,
    tasks: Arc<DashMap<String, Slot>>,
}

impl YoukiRuntime {
    pub fn new(runtime_binary: impl Into<PathBuf>) -> Self {
        YoukiRuntime {
            runtime_binary: runtime_binary.into(),
            bundle_root: crate::private_dir::work_dir("oci"),
            tasks: Arc::new(DashMap::new()),
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
        self.ensure_runtime_available()?;
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
        tokio::fs::create_dir(&bundle)
            .await
            .map_err(|error| exec_failed(format!("creating bundle dir: {error}")))?;
        if let Err(error) = self
            .write_bundle_config(&bundle, spec, &rootfs, isolated_network)
            .await
        {
            let _ = tokio::fs::remove_dir_all(&bundle).await;
            return Err(error);
        }
        let slot: Slot = Arc::new(Mutex::new(TaskRecord {
            state: TaskState::Running,
            output: Vec::new(),
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

        let runtime_binary = self.runtime_binary.clone();
        let id = task_id.to_string();
        tokio::spawn(async move {
            let child = Command::new(&runtime_binary)
                .arg("run")
                .arg("--bundle")
                .arg(&bundle)
                .arg(&id)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();
            match child {
                Ok(mut child) => {
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
            let _ = tokio::fs::remove_dir_all(&bundle).await;
        });
        Ok(TaskHandle {
            task_id: task_id.to_string(),
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
        if guest_port == 0 {
            return Err(exec_failed("guest TCP port must be nonzero"));
        }
        let handle = self.start_task_with_network(task_id, spec, true).await?;
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

    pub async fn bind_isolated_public_egress(
        &self,
        task_id: &str,
        private_addresses: &[std::net::Ipv4Addr],
    ) -> Result<tokio::net::TcpListener, RuntimeError> {
        const EGRESS_PORT: u16 = 49152;
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
                EGRESS_PORT,
            )
        })
        .await
        .map_err(|e| exec_failed(format!("public listener worker failed: {e}")))?
        .map_err(|e| exec_failed(format!("binding public OCI listener: {e}")))?;
        let (user_ns, net_ns) = self.isolated_namespace_files(task_id, false).await?;
        let excluded = private_addresses.to_vec();
        tokio::task::spawn_blocking(move || {
            use std::os::unix::process::CommandExt;
            fn run(
                user_ns: &std::fs::File,
                net_ns: &std::fs::File,
                program: &str,
                args: &[&str],
            ) -> std::io::Result<()> {
                let mut command = std::process::Command::new(program);
                command.args(args);
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
                let output = command.output()?;
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
            )?;
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
            )?;
            let mut excluded = excluded.iter().map(ToString::to_string).collect::<Vec<_>>();
            excluded.extend(
                [
                    "127.0.0.0/8",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "169.254.0.0/16",
                    "100.64.0.0/10",
                ]
                .map(str::to_owned),
            );
            let rule = format!(
                "ip daddr != {{ {} }} meta l4proto tcp redirect to :{EGRESS_PORT}",
                excluded.join(", ")
            );
            run(
                &user_ns,
                &net_ns,
                "nft",
                &["add", "rule", "ip", "locallycloud", "output", &rule],
            )?;
            run(
                &user_ns,
                &net_ns,
                "ip",
                &[
                    "route", "add", "local", "default", "dev", "lo", "table", "local",
                ],
            )
        })
        .await
        .map_err(|e| exec_failed(format!("public egress setup worker failed: {e}")))?
        .map_err(|e| {
            exec_failed(format!(
                "isolated public egress requires rootless ip and nft: {e}"
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
        let user_ns = std::fs::File::open(format!("/proc/{pid}/ns/user"))
            .map_err(|e| exec_failed(format!("opening OCI user namespace: {e}")))?;
        let net_ns = std::fs::File::open(format!("/proc/{pid}/ns/net"))
            .map_err(|e| exec_failed(format!("opening OCI network namespace: {e}")))?;
        Ok((user_ns, net_ns))
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
            return Ok(TaskHandle {
                task_id: task_id.to_string(),
                state,
            });
        }

        let killed = self.oci_command(&["kill", task_id, "KILL"]).await?;
        if !killed.status.success() {
            return Err(exec_failed(format!(
                "stopping OCI task: {}",
                String::from_utf8_lossy(&killed.stderr).trim()
            )));
        }
        let mut record = slot.lock().await;
        if record.state == TaskState::Running {
            record.state = TaskState::Stopped;
        }
        Ok(TaskHandle {
            task_id: task_id.to_string(),
            state: record.state,
        })
    }

    async fn reconcile_orphaned_task(&self, task_id: &str) -> Result<bool, RuntimeError> {
        self.ensure_runtime_available()?;
        let state = self.oci_command(&["state", task_id]).await?;
        if !state.status.success() {
            // `run` can remove its state after the owning server dies. Preserve
            // the rootfs on any error other than an explicit missing container.
            let stderr = String::from_utf8_lossy(&state.stderr);
            if !stderr.contains("does not exist") && !stderr.contains("not found") {
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

    async fn get_output(&self, task_id: &str) -> Result<String, RuntimeError> {
        let slot = self.tasks.get(task_id).map(|s| s.clone()).ok_or_else(|| {
            RuntimeError::TaskNotFound {
                task_id: task_id.to_string(),
            }
        })?;
        let captured = slot.lock().await.output.clone();
        Ok(String::from_utf8_lossy(&captured).into_owned())
    }
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

fn exec_failed(reason: impl Into<String>) -> RuntimeError {
    RuntimeError::ExecutionFailed {
        reason: reason.into(),
    }
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
            output: b"out".to_vec(),
            bundle: PathBuf::new(),
            isolated_network: false,
        }))
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
