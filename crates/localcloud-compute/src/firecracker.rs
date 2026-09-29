//! Firecracker microVM backend (primary).
//!
//! Implements [`ComputeRuntime`] by launching microVMs through the Firecracker control
//! socket and `/dev/kvm`, the same isolation model AWS Lambda uses. A microVM is
//! long-lived: `start_task` boots it and reports `Running`, `get_output` returns the serial
//! console captured so far, and `stop_task` shuts it down. See Requirements 15 and 17.
//! This backend currently boots a preconfigured guest image. It rejects task commands,
//! environment variables, and alternate images until a guest-side task launcher exists.
//!
//! Boot sequence (Firecracker HTTP API over a per-task Unix socket):
//! 1. spawn `firecracker --api-sock <socket>`
//! 2. `PUT /machine-config`  (vcpu / mem)
//! 3. `PUT /boot-source`     (kernel + boot args, serial console on ttyS0)
//! 4. `PUT /drives/rootfs`   (root device)
//! 5. `PUT /actions`         (`InstanceStart`)
//! 6. capture the guest serial console from the firecracker process stdout
//! 7. stop: `PUT /actions` (`SendCtrlAltDel`) then terminate the process
//!
//! Live boot is validated on a host with `/dev/kvm` + a firecracker binary + kernel/rootfs
//! (gated integration suite, Req 15.2 / 17.4). The control-plane mechanics (request
//! serialization, response/fault parsing, prerequisite errors) are unit-tested here.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use crate::runtime::{ComputeRuntime, RuntimeError, TaskHandle, TaskSpec, TaskState};

/// Future interface for fast warm starts. Implementation detail is deferred to the Lambda
/// spec (Req 15.4); declared here so the contract is part of the compute layer.
#[async_trait]
pub trait SnapshotCapable {
    async fn create_snapshot(
        &self,
        task_id: &str,
        snapshot_path: &Path,
    ) -> Result<(), RuntimeError>;
    async fn restore_from_snapshot(&self, snapshot_path: &Path)
        -> Result<TaskHandle, RuntimeError>;
}

struct RunningTask {
    process: Child,
    socket: PathBuf,
    state: TaskState,
    output: Arc<Mutex<String>>,
    _reader: tokio::task::JoinHandle<()>,
}

pub struct FirecrackerRuntime {
    /// Path to the `firecracker` binary.
    firecracker_bin: PathBuf,
    /// vmlinux kernel image.
    kernel_path: PathBuf,
    /// ext4 rootfs for the hello-task.
    rootfs_path: PathBuf,
    /// Directory under which per-task API sockets are created.
    socket_dir: PathBuf,
    tasks: Arc<DashMap<String, RunningTask>>,
}

impl FirecrackerRuntime {
    pub fn new(
        firecracker_bin: impl Into<PathBuf>,
        kernel_path: impl Into<PathBuf>,
        rootfs_path: impl Into<PathBuf>,
    ) -> Self {
        FirecrackerRuntime {
            firecracker_bin: firecracker_bin.into(),
            kernel_path: kernel_path.into(),
            rootfs_path: rootfs_path.into(),
            socket_dir: crate::private_dir::work_dir("firecracker"),
            tasks: Arc::new(DashMap::new()),
        }
    }

    /// Locate the `firecracker` binary on `PATH` (lazy resolution); `None` when absent.
    pub fn discover(
        kernel_path: impl Into<PathBuf>,
        rootfs_path: impl Into<PathBuf>,
    ) -> Option<Self> {
        which("firecracker").map(|bin| Self::new(bin, kernel_path, rootfs_path))
    }

    fn ensure_kvm(&self) -> Result<(), RuntimeError> {
        let path = Path::new("/dev/kvm");
        let usable = path.exists()
            && std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .is_ok();
        if usable {
            Ok(())
        } else {
            Err(RuntimeError::KvmUnavailable {
                reason: "/dev/kvm is missing or not readable+writable".to_string(),
            })
        }
    }

    fn ensure_artifacts(&self) -> Result<(), RuntimeError> {
        if !self.firecracker_bin.exists() {
            return Err(boot_failed(format!(
                "firecracker binary not found: {}",
                self.firecracker_bin.display()
            )));
        }
        if !self.kernel_path.exists() {
            return Err(boot_failed(format!(
                "kernel image not found: {}",
                self.kernel_path.display()
            )));
        }
        if !self.rootfs_path.exists() {
            return Err(boot_failed(format!(
                "rootfs image not found: {}",
                self.rootfs_path.display()
            )));
        }
        Ok(())
    }

    fn ensure_supported_spec(&self, spec: &TaskSpec) -> Result<(), RuntimeError> {
        if Path::new(&spec.image) != self.rootfs_path {
            return Err(RuntimeError::ExecutionFailed {
                reason: format!(
                    "Firecracker requires its configured rootfs image {}; requested {}",
                    self.rootfs_path.display(),
                    spec.image
                ),
            });
        }
        if !spec.command.is_empty() || !spec.env.is_empty() {
            return Err(RuntimeError::ExecutionFailed {
                reason:
                    "Firecracker guest task command and environment require a guest-side launcher"
                        .to_string(),
            });
        }
        Ok(())
    }

    async fn boot(
        &self,
        task_id: &str,
        spec: &TaskSpec,
        socket: &Path,
    ) -> Result<(), RuntimeError> {
        wait_for_socket(socket, Duration::from_secs(2)).await?;

        fc_put(
            socket,
            "/machine-config",
            &format!(
                r#"{{"vcpu_count":{},"mem_size_mib":{}}}"#,
                spec.vcpu_count.max(1),
                spec.memory_mb.max(128)
            ),
        )
        .await?;
        fc_put(
            socket,
            "/boot-source",
            &format!(
                r#"{{"kernel_image_path":{},"boot_args":"console=ttyS0 reboot=k panic=1 pci=off"}}"#,
                json_str(&self.kernel_path.display().to_string())
            ),
        )
        .await?;
        fc_put(
            socket,
            "/drives/rootfs",
            &format!(
                r#"{{"drive_id":"rootfs","path_on_host":{},"is_root_device":true,"is_read_only":true}}"#,
                json_str(&self.rootfs_path.display().to_string())
            ),
        )
        .await?;
        fc_put(socket, "/actions", r#"{"action_type":"InstanceStart"}"#).await?;
        let _ = task_id;
        Ok(())
    }
}

#[async_trait]
impl ComputeRuntime for FirecrackerRuntime {
    async fn start_task(&self, task_id: &str, spec: &TaskSpec) -> Result<TaskHandle, RuntimeError> {
        self.ensure_supported_spec(spec)?;
        self.ensure_kvm()?;
        self.ensure_artifacts()?;

        let socket_dir = self.socket_dir.clone();
        tokio::task::spawn_blocking(move || crate::private_dir::ensure(&socket_dir))
            .await
            .map_err(|error| boot_failed(format!("checking socket directory: {error}")))?
            .map_err(|error| boot_failed(format!("checking socket directory: {error}")))?;
        let socket = self
            .socket_dir
            .join(format!("localcloud-fc-{task_id}.sock"));
        let _ = std::fs::remove_file(&socket);

        let mut process = Command::new(&self.firecracker_bin)
            .arg("--api-sock")
            .arg(&socket)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| boot_failed(format!("spawning firecracker: {e}")))?;

        let output = Arc::new(Mutex::new(String::new()));
        let reader = spawn_serial_reader(process.stdout.take(), output.clone());

        if let Err(err) = self.boot(task_id, spec, &socket).await {
            let _ = process.start_kill();
            let _ = std::fs::remove_file(&socket);
            reader.abort();
            return Err(err);
        }

        self.tasks.insert(
            task_id.to_string(),
            RunningTask {
                process,
                socket,
                state: TaskState::Running,
                output,
                _reader: reader,
            },
        );
        Ok(TaskHandle {
            task_id: task_id.to_string(),
            state: TaskState::Running,
        })
    }

    async fn stop_task(&self, task_id: &str) -> Result<TaskHandle, RuntimeError> {
        let socket = {
            let entry = self
                .tasks
                .get(task_id)
                .ok_or_else(|| RuntimeError::TaskNotFound {
                    task_id: task_id.to_string(),
                })?;
            if entry.state == TaskState::Completed {
                return Err(RuntimeError::TaskAlreadyCompleted {
                    task_id: task_id.to_string(),
                });
            }
            entry.socket.clone()
        };

        let _ = fc_put(&socket, "/actions", r#"{"action_type":"SendCtrlAltDel"}"#).await;

        let mut entry = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| RuntimeError::TaskNotFound {
                task_id: task_id.to_string(),
            })?;
        let _ = entry.process.start_kill();
        let _ = std::fs::remove_file(&entry.socket);
        entry.state = TaskState::Stopped;
        Ok(TaskHandle {
            task_id: task_id.to_string(),
            state: TaskState::Stopped,
        })
    }

    async fn task_state(&self, task_id: &str) -> Result<TaskState, RuntimeError> {
        let mut entry = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| RuntimeError::TaskNotFound {
                task_id: task_id.to_string(),
            })?;
        if entry.state == TaskState::Running {
            if let Some(status) = entry
                .process
                .try_wait()
                .map_err(|error| boot_failed(format!("checking microVM state: {error}")))?
            {
                entry.state = if status.success() {
                    TaskState::Completed
                } else {
                    TaskState::Failed
                };
            }
        }
        Ok(entry.state)
    }

    async fn get_output(&self, task_id: &str) -> Result<String, RuntimeError> {
        let output = {
            let entry = self
                .tasks
                .get(task_id)
                .ok_or_else(|| RuntimeError::TaskNotFound {
                    task_id: task_id.to_string(),
                })?;
            entry.output.clone()
        };
        let captured = output.lock().await.clone();
        Ok(captured)
    }
}

fn boot_failed(reason: impl Into<String>) -> RuntimeError {
    RuntimeError::BootFailed {
        reason: reason.into(),
    }
}

/// Quote a string as a JSON scalar (escaping `\` and `"`), for embedding host paths.
fn json_str(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Read the firecracker process stdout (guest serial console) line-by-line into `sink`.
fn spawn_serial_reader(
    stdout: Option<tokio::process::ChildStdout>,
    sink: Arc<Mutex<String>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(stdout) = stdout else { return };
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let mut buf = sink.lock().await;
            buf.push_str(&line);
            buf.push('\n');
        }
    })
}

/// Poll for the API socket to appear and accept a connection, up to `timeout`.
async fn wait_for_socket(socket: &Path, timeout: Duration) -> Result<(), RuntimeError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if socket.exists() && UnixStream::connect(socket).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(RuntimeError::FirecrackerSocketUnreachable {
                path: socket.display().to_string(),
            });
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Issue a `PUT` with a JSON body to the Firecracker API over its Unix socket and require a
/// 2xx response. A non-2xx status surfaces the `fault_message` body as a boot failure.
async fn fc_put(socket: &Path, path: &str, body: &str) -> Result<(), RuntimeError> {
    let mut stream = UnixStream::connect(socket).await.map_err(|_| {
        RuntimeError::FirecrackerSocketUnreachable {
            path: socket.display().to_string(),
        }
    })?;

    let request = format!(
        "PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| boot_failed(format!("writing to firecracker socket: {e}")))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|e| boot_failed(format!("reading firecracker response: {e}")))?;

    match parse_status(&raw) {
        Some(code) if (200..300).contains(&code) => Ok(()),
        Some(code) => Err(boot_failed(format!(
            "{path} returned HTTP {code}: {}",
            response_body(&raw)
        ))),
        None => Err(boot_failed(format!(
            "{path}: malformed firecracker response"
        ))),
    }
}

/// Extract the numeric status code from an HTTP/1.1 status line.
fn parse_status(raw: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(raw).ok()?;
    let status_line = text.lines().next()?;
    status_line.split_whitespace().nth(1)?.parse().ok()
}

/// The body after the header terminator, for surfacing fault messages.
fn response_body(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    match text.split_once("\r\n\r\n") {
        Some((_, body)) => body.trim().to_string(),
        None => String::new(),
    }
}

/// Resolve an executable name against `PATH`.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|c| c.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::net::UnixListener;

    fn spec() -> TaskSpec {
        TaskSpec {
            name: "hello".into(),
            image: "rootfs.ext4".into(),
            command: vec![],
            env: HashMap::new(),
            memory_mb: 128,
            vcpu_count: 1,
        }
    }

    /// Spawn a one-shot mock that accepts a single connection and replies with `response`.
    fn mock_api(socket: PathBuf, response: &'static str) {
        let listener = UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
    }

    #[tokio::test]
    async fn fc_put_accepts_2xx() {
        let socket = std::env::temp_dir().join(format!("lc-fc-ok-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        mock_api(
            socket.clone(),
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
        );
        let result = fc_put(&socket, "/machine-config", "{}").await;
        let _ = std::fs::remove_file(&socket);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn fc_put_surfaces_fault_on_4xx() {
        let socket = std::env::temp_dir().join(format!("lc-fc-err-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        mock_api(
            socket.clone(),
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 38\r\n\r\n{\"fault_message\":\"invalid kernel path\"}",
        );
        let err = fc_put(&socket, "/boot-source", "{}").await.unwrap_err();
        let _ = std::fs::remove_file(&socket);
        match err {
            RuntimeError::BootFailed { reason } => {
                assert!(reason.contains("400"));
                assert!(reason.contains("invalid kernel path"));
            }
            other => panic!("expected BootFailed, got {other:?}"),
        }
    }

    #[test]
    fn parse_status_reads_code() {
        assert_eq!(parse_status(b"HTTP/1.1 204 No Content\r\n\r\n"), Some(204));
        assert_eq!(parse_status(b"HTTP/1.1 400 Bad Request\r\n\r\n"), Some(400));
        assert_eq!(parse_status(b"garbage"), None);
    }

    #[test]
    fn json_str_escapes() {
        assert_eq!(json_str("/a/b"), "\"/a/b\"");
        assert_eq!(json_str(r#"a"b"#), "\"a\\\"b\"");
    }

    #[tokio::test]
    async fn start_task_missing_binary_is_typed_error() {
        let rt = FirecrackerRuntime::new(
            "/nonexistent/firecracker",
            "/tmp/vmlinux",
            "/tmp/rootfs.ext4",
        );
        let mut requested = spec();
        requested.image = "/tmp/rootfs.ext4".into();
        let err = rt.start_task("t1", &requested).await.unwrap_err();
        // /dev/kvm is world-rw on this host, so the failed prerequisite is the binary.
        assert!(matches!(
            err,
            RuntimeError::BootFailed { .. } | RuntimeError::KvmUnavailable { .. }
        ));
    }

    #[tokio::test]
    async fn task_command_cannot_be_reported_as_running_without_guest_launcher() {
        let rt = FirecrackerRuntime::new("/tmp/fc", "/tmp/vmlinux", "rootfs.ext4");
        let mut requested = spec();
        requested.command = vec!["/bin/echo".into(), "hello".into()];
        assert!(matches!(
            rt.start_task("task", &requested).await,
            Err(RuntimeError::ExecutionFailed { reason }) if reason.contains("guest-side launcher")
        ));
    }

    #[test]
    fn task_environment_cannot_be_reported_as_running_without_guest_launcher() {
        let rt = FirecrackerRuntime::new("/tmp/fc", "/tmp/vmlinux", "rootfs.ext4");
        let mut requested = spec();
        requested
            .env
            .insert("AWS_LAMBDA_FUNCTION_NAME".into(), "fn".into());
        assert!(matches!(
            rt.ensure_supported_spec(&requested),
            Err(RuntimeError::ExecutionFailed { reason }) if reason.contains("guest-side launcher")
        ));
    }

    #[test]
    fn task_image_must_match_configured_rootfs() {
        let rt = FirecrackerRuntime::new("/tmp/fc", "/tmp/vmlinux", "rootfs.ext4");
        let mut requested = spec();
        requested.image = "other.ext4".into();
        assert!(matches!(
            rt.ensure_supported_spec(&requested),
            Err(RuntimeError::ExecutionFailed { reason }) if reason.contains("configured rootfs")
        ));
        assert!(rt.ensure_supported_spec(&spec()).is_ok());
    }

    #[tokio::test]
    async fn stop_unknown_task_is_not_found() {
        let rt = FirecrackerRuntime::new("/tmp/fc", "/tmp/vmlinux", "/tmp/rootfs.ext4");
        let err = rt.stop_task("nope").await.unwrap_err();
        assert!(matches!(err, RuntimeError::TaskNotFound { .. }));
    }

    #[tokio::test]
    async fn get_output_unknown_task_is_not_found() {
        let rt = FirecrackerRuntime::new("/tmp/fc", "/tmp/vmlinux", "/tmp/rootfs.ext4");
        let err = rt.get_output("nope").await.unwrap_err();
        assert!(matches!(err, RuntimeError::TaskNotFound { .. }));
    }
}
