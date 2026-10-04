//! `ComputeRuntime` trait and shared task types.
//!
//! Async start/stop/output operations over a [`TaskSpec`], surfacing failures as a typed
//! [`RuntimeError`] rather than terminating the process. See Requirement 13.

use async_trait::async_trait;
use std::collections::HashMap;

/// Specification for a task to be executed by a [`ComputeRuntime`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSpec {
    /// Human-readable task name.
    pub name: String,
    /// Container image reference or rootfs path.
    pub image: String,
    /// Command to execute.
    pub command: Vec<String>,
    /// Environment variables injected into the task.
    pub env: HashMap<String, String>,
    /// Memory limit in MB.
    pub memory_mb: u32,
    /// vCPU count (used by the Firecracker backend).
    pub vcpu_count: u32,
}

/// Lifecycle state of a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Running,
    Completed,
    Failed,
    Stopped,
}

/// Handle to a running or finished task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskHandle {
    pub task_id: String,
    pub state: TaskState,
}

/// A typed compute failure. Operations return this instead of panicking (Req 13.7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    #[error("task not found: {task_id}")]
    TaskNotFound { task_id: String },
    #[error("task already completed: {task_id}")]
    TaskAlreadyCompleted { task_id: String },
    #[error("KVM unavailable: {reason}")]
    KvmUnavailable { reason: String },
    #[error("firecracker control socket unreachable: {path}")]
    FirecrackerSocketUnreachable { path: String },
    #[error("microVM boot failed: {reason}")]
    BootFailed { reason: String },
    #[error("OCI runtime not found: {binary}")]
    OciRuntimeNotFound { binary: String },
    #[error("task execution failed: {reason}")]
    ExecutionFailed { reason: String },
}

/// Incremental captured output. Cursors count original bytes, including evicted bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskOutput {
    pub text: String,
    pub next_cursor: u64,
    pub dropped_bytes: u64,
}

/// Abstraction over a workload-execution backend.
#[async_trait]
pub trait ComputeRuntime: Send + Sync {
    /// Start a task. On success the returned handle is in [`TaskState::Running`].
    async fn start_task(&self, task_id: &str, spec: &TaskSpec) -> Result<TaskHandle, RuntimeError>;

    /// Start a network-isolated task after binding guest-loopback listeners.
    /// Unsupported backends fail closed; callers operate the returned listeners
    /// as the only explicitly allowed paths back to host services.
    async fn start_task_isolated_with_loopback(
        &self,
        _task_id: &str,
        _spec: &TaskSpec,
        _ports: &[u16],
    ) -> Result<(TaskHandle, Vec<tokio::net::TcpListener>), RuntimeError> {
        Err(RuntimeError::ExecutionFailed {
            reason: "isolated task loopback is unavailable for this backend".into(),
        })
    }

    /// Add a private IPv4 listener inside an already-running isolated task.
    async fn bind_isolated_private_tcp(
        &self,
        _task_id: &str,
        _address: std::net::Ipv4Addr,
        _port: u16,
    ) -> Result<tokio::net::TcpListener, RuntimeError> {
        Err(RuntimeError::ExecutionFailed {
            reason: "private TCP is unavailable for this backend".into(),
        })
    }

    /// Capture outbound IPv4 TCP in a rootless network namespace.
    /// The caller must check each original destination before forwarding.
    async fn bind_isolated_public_egress(
        &self,
        _task_id: &str,
        _private_addresses: &[std::net::Ipv4Addr],
    ) -> Result<tokio::net::TcpListener, RuntimeError> {
        Err(RuntimeError::ExecutionFailed {
            reason: "isolated public egress is unavailable for this backend".into(),
        })
    }

    /// Bind AmazonProvidedDNS in the isolated guest; host code answers only DNS packets.
    async fn bind_isolated_dns(
        &self,
        _task_id: &str,
    ) -> Result<(tokio::net::UdpSocket, tokio::net::TcpListener), RuntimeError> {
        Err(RuntimeError::ExecutionFailed {
            reason: "isolated DNS is unavailable for this backend".into(),
        })
    }

    /// Stop a running task. Returns [`RuntimeError::TaskNotFound`] for an identifier that
    /// was never started and [`RuntimeError::TaskAlreadyCompleted`] for one that already
    /// finished naturally (Req 13.4, 13.5).
    async fn stop_task(&self, task_id: &str) -> Result<TaskHandle, RuntimeError>;

    /// Observe a task after launch. A service can use this with its own readiness
    /// probe to avoid advertising a workload that has already exited.
    async fn task_state(&self, _task_id: &str) -> Result<TaskState, RuntimeError> {
        Err(RuntimeError::ExecutionFailed {
            reason: "task state is unavailable for this backend".into(),
        })
    }

    /// Reconcile a task after its owning server process died. Return `true` only after
    /// the backend has verified that the guest can no longer use its root filesystem.
    /// Backends without durable task state retain the rootfs for manual recovery.
    async fn reconcile_orphaned_task(&self, _task_id: &str) -> Result<bool, RuntimeError> {
        Ok(false)
    }

    /// Consume output after an absolute byte cursor. Native backends bound retained output.
    async fn read_output(&self, task_id: &str, cursor: u64) -> Result<TaskOutput, RuntimeError> {
        let text = self.get_output(task_id).await?;
        let next_cursor = text.len() as u64;
        let start = (cursor as usize).min(text.len());
        let start = (start..=text.len())
            .find(|&i| text.is_char_boundary(i))
            .unwrap_or(text.len());
        Ok(TaskOutput {
            text: text[start..].into(),
            next_cursor,
            dropped_bytes: 0,
        })
    }

    /// Finalize resources only after the backend has confirmed termination.
    async fn release_task(&self, _task_id: &str) -> Result<(), RuntimeError> {
        Err(RuntimeError::ExecutionFailed {
            reason: "task finalization unavailable for this backend".into(),
        })
    }

    /// Retrieve the captured stdout of a completed or stopped task.
    async fn get_output(&self, task_id: &str) -> Result<String, RuntimeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_errors_distinguish_not_found_from_completed() {
        let nf = RuntimeError::TaskNotFound {
            task_id: "a".into(),
        };
        let done = RuntimeError::TaskAlreadyCompleted {
            task_id: "a".into(),
        };
        assert_ne!(nf, done);
        assert!(nf.to_string().contains("not found"));
        assert!(done.to_string().contains("already completed"));
    }
}
