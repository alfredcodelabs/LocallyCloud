//! Integration: run a one-shot hello task through the daemonless OCI runtime.
//!
//! Proves the `YoukiRuntime` boots a real OCI bundle (no Docker, no KVM), runs the task,
//! and captures its stdout. Gated on a runtime being present on `PATH`; skips cleanly
//! otherwise so the suite stays green on hosts without `crun`/`youki`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use locallycloud_compute::runtime::{ComputeRuntime, TaskSpec, TaskState};
use locallycloud_compute::youki::YoukiRuntime;

/// Build a throwaway rootfs containing `/usr/bin/echo` and the shared libraries it needs,
/// so the OCI runtime has a real filesystem to exec into. Returns `None` when the host
/// lacks the tools to assemble one.
fn build_min_rootfs(root: &Path) -> Option<()> {
    let bin = Path::new("/usr/bin/echo");
    if !bin.exists() {
        return None;
    }
    let script = format!(
        r#"set -e
ROOT="{root}"
mkdir -p "$ROOT/bin"
cp /usr/bin/echo "$ROOT/bin/echo"
for lib in $(ldd /usr/bin/echo | grep -oE '/[^ ]+\.so[^ ]*'); do
  mkdir -p "$ROOT$(dirname "$lib")"
  cp "$lib" "$ROOT$lib"
done
"#,
        root = root.display()
    );
    let status = Command::new("sh").arg("-c").arg(script).status().ok()?;
    status.success().then_some(())
}

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("locallycloud-test-{tag}-{nanos}"))
}

#[tokio::test]
async fn oci_runtime_runs_hello_task_and_captures_output() {
    let runtime = match YoukiRuntime::discover() {
        Some(rt) => rt,
        None => {
            eprintln!("skipping: no `crun`/`youki` on PATH");
            return;
        }
    };

    let rootfs = unique_dir("rootfs");
    if build_min_rootfs(&rootfs).is_none() {
        eprintln!("skipping: could not assemble a minimal rootfs on this host");
        return;
    }

    let spec = TaskSpec {
        name: "hello".into(),
        image: rootfs.display().to_string(),
        command: vec!["/bin/echo".into(), "hello-locallycloud".into()],
        env: HashMap::new(),
        memory_mb: 128,
        vcpu_count: 1,
    };

    let handle = runtime
        .start_task("hello-task", &spec)
        .await
        .expect("task should start");
    assert_eq!(handle.state, TaskState::Running);

    // The one-shot task completes in the background; poll its captured output.
    let mut output = String::new();
    for _ in 0..150 {
        output = runtime
            .get_output("hello-task")
            .await
            .expect("output available");
        if !output.trim().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(output.trim(), "hello-locallycloud");
    let mut state = runtime.task_state("hello-task").await.unwrap();
    for _ in 0..150 {
        if state != TaskState::Running {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        state = runtime.task_state("hello-task").await.unwrap();
    }
    assert_eq!(state, TaskState::Completed);
    let _ = std::fs::remove_dir_all(&rootfs);
}

#[tokio::test]
async fn oci_runtime_reports_failed_guest_process() {
    let Some(runtime) = YoukiRuntime::discover() else {
        eprintln!("skipping: no `crun`/`youki` on PATH");
        return;
    };
    let rootfs = unique_dir("failed-rootfs");
    if build_min_rootfs(&rootfs).is_none() {
        eprintln!("skipping: could not assemble a minimal rootfs on this host");
        return;
    }
    let spec = TaskSpec {
        name: "failed".into(),
        image: rootfs.display().to_string(),
        command: vec!["/bin/does-not-exist".into()],
        env: HashMap::new(),
        memory_mb: 128,
        vcpu_count: 1,
    };
    runtime.start_task("failed-task", &spec).await.unwrap();
    let mut state = TaskState::Running;
    for _ in 0..150 {
        state = runtime.task_state("failed-task").await.unwrap();
        if state != TaskState::Running {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let _ = std::fs::remove_dir_all(&rootfs);
    assert_eq!(state, TaskState::Failed);
}
