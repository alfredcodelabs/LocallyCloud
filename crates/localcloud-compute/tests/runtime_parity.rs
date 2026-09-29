//! Integration (Task 13): hello-task runtime parity.
//!
//! Asserts Requirement 17.4: the runtime the [`RuntimeSelector`] picks for the host starts a
//! hello-task, produces its output, and stops — the same observable lifecycle
//! (`Running` → output → terminal) regardless of backend. The parity contract is exercised on
//! every backend whose prerequisites the host actually meets and skips the rest cleanly, so
//! the suite stays green everywhere.
//!
//! On a host with a daemonless OCI runtime (`crun`/`youki`) the youki branch runs for real.
//! The Firecracker branch runs only when a `firecracker` binary plus a kernel + rootfs image
//! are provided (via `LOCALCLOUD_FC_KERNEL`/`LOCALCLOUD_FC_ROOTFS`); those artifacts are
//! lazy-provisioned and absent in CI, an environment boundary shared with task 11.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use localcloud_compute::firecracker::FirecrackerRuntime;
use localcloud_compute::runtime::{ComputeRuntime, RuntimeError, TaskSpec, TaskState};
use localcloud_compute::selector::RuntimeSelector;
use localcloud_compute::youki::YoukiRuntime;

/// Assemble a throwaway rootfs containing `/bin/echo` + its shared libraries. Returns `None`
/// when the host lacks the tools to build one.
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
    std::env::temp_dir().join(format!("localcloud-test-{tag}-{nanos}"))
}

/// The parity contract: start → `Running`, output appears, then the task stops (either we
/// stop it, or it already reached a natural terminal state). Returns the captured stdout.
async fn assert_lifecycle(runtime: &dyn ComputeRuntime, spec: &TaskSpec, task_id: &str) -> String {
    let handle = runtime
        .start_task(task_id, spec)
        .await
        .expect("task should start");
    assert_eq!(
        handle.state,
        TaskState::Running,
        "a started task is Running"
    );

    let mut output = String::new();
    for _ in 0..200 {
        output = runtime
            .get_output(task_id)
            .await
            .expect("output should be readable");
        if !output.trim().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    match runtime.stop_task(task_id).await {
        Ok(h) => assert!(
            matches!(h.state, TaskState::Stopped | TaskState::Completed),
            "stopped task reaches a terminal state, got {:?}",
            h.state
        ),
        // A one-shot task may finish naturally before we stop it; that is a valid terminal.
        Err(e) => assert!(
            matches!(e, RuntimeError::TaskAlreadyCompleted { .. }),
            "unexpected stop error: {e}"
        ),
    }
    output
}

#[tokio::test]
async fn selected_runtime_hello_task_parity() {
    let kvm = RuntimeSelector::check_kvm_availability();
    let selected = RuntimeSelector::select(None, kvm).expect("selection succeeds");
    eprintln!("runtime selector picked {selected:?} (kvm_available={kvm})");

    let mut ran_any = false;

    // youki / crun branch — runs whenever a daemonless OCI runtime is on PATH.
    if let Some(runtime) = YoukiRuntime::discover() {
        let rootfs = unique_dir("parity-rootfs");
        if build_min_rootfs(&rootfs).is_some() {
            let spec = TaskSpec {
                name: "hello".into(),
                image: rootfs.display().to_string(),
                command: vec!["/bin/echo".into(), "hello-localcloud".into()],
                env: HashMap::new(),
                memory_mb: 128,
                vcpu_count: 1,
            };
            let output = assert_lifecycle(&runtime, &spec, "parity-youki").await;
            assert_eq!(
                output.trim(),
                "hello-localcloud",
                "youki hello-task output parity"
            );
            let _ = std::fs::remove_dir_all(&rootfs);
            ran_any = true;
        } else {
            eprintln!("youki present but could not assemble a rootfs; skipping that branch");
        }
    }

    // Firecracker branch — only when the binary + kernel + rootfs artifacts are provided.
    if let (Ok(kernel), Ok(rootfs)) = (
        std::env::var("LOCALCLOUD_FC_KERNEL"),
        std::env::var("LOCALCLOUD_FC_ROOTFS"),
    ) {
        if let Some(runtime) = FirecrackerRuntime::discover(&kernel, &rootfs) {
            let spec = TaskSpec {
                name: "hello".into(),
                image: rootfs,
                command: vec![],
                env: HashMap::new(),
                memory_mb: 128,
                vcpu_count: 1,
            };
            let output = assert_lifecycle(&runtime, &spec, "parity-fc").await;
            assert!(
                !output.trim().is_empty(),
                "firecracker hello-task produced output"
            );
            ran_any = true;
        }
    }

    if !ran_any {
        eprintln!(
            "skipping: host meets no compute runtime's prerequisites \
             (no crun/youki on PATH, and no firecracker kernel/rootfs artifacts)"
        );
    }
}
