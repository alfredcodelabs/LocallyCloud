use super::*;
use std::os::unix::fs::PermissionsExt;

fn poll_once<F: std::future::Future>(future: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
    future.poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
}

#[tokio::test]
async fn successful_stop_reconciles_a_reaped_kill_without_hiding_unrelated_exits() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.kiro/localcloud-tmp/compute-stop-tests")
        .join(format!(
            "ack-race-{}-{}",
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
    for (index, exit_status, terminal, kill_exit, expected) in [
        (0, libc::SIGKILL, TaskState::Failed, 0, TaskState::Stopped),
        (
            1,
            (128 + libc::SIGKILL) << 8,
            TaskState::Failed,
            0,
            TaskState::Stopped,
        ),
        (2, 1 << 8, TaskState::Failed, 0, TaskState::Failed),
        (3, 0, TaskState::Completed, 0, TaskState::Completed),
        (4, libc::SIGKILL, TaskState::Failed, 1, TaskState::Failed),
    ] {
        let binary = root.join(format!("runtime-{index}"));
        tokio::fs::write(
            &binary,
            format!(
                r#"#!/bin/sh
[ "$1" = kill ] || exit 99
: > "$0.entered"
while [ ! -f "$0.release" ]; do sleep 0.01; done
echo 'controlled stop result' >&2
exit {kill_exit}
"#
            ),
        )
        .await
        .unwrap();
        tokio::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
        let runtime = Arc::new(YoukiRuntime::new(&binary));
        let slot = Arc::new(Mutex::new(TaskRecord {
            state: TaskState::Running,
            output: crate::output::OutputCapture::default(),
            finished: false,
            exit_status: None,
            bundle: root.clone(),
            isolated_network: false,
        }));
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
        // Force the observed ordering: the monitor reaps before the kill CLI acknowledges.
        {
            let mut record = slot.lock().await;
            record.state = terminal;
            record.exit_status = Some(std::process::ExitStatus::from_raw(exit_status));
            record.finished = true;
        }
        tokio::fs::write(binary.with_extension("release"), [])
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), stop)
            .await
            .unwrap()
            .unwrap();
        if kill_exit == 0 {
            assert_eq!(result.unwrap().state, expected);
        } else {
            assert!(result.is_err());
        }
        assert_eq!(runtime.task_state("owned").await.unwrap(), expected);
    }
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn acknowledged_stop_waits_for_the_monitor_before_classifying_the_exit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.kiro/localcloud-tmp/compute-stop-tests")
        .join(format!(
            "monitor-after-ack-{}-{}",
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

    for (index, exit_status, expected) in [
        (0, 0, TaskState::Completed),
        (1, 1 << 8, TaskState::Failed),
        (2, libc::SIGKILL, TaskState::Stopped),
        (3, (128 + libc::SIGKILL) << 8, TaskState::Stopped),
    ] {
        let binary = root.join(format!("runtime-{index}"));
        tokio::fs::write(
            &binary,
            r#"#!/bin/sh
[ "$1" = kill ] || exit 99
: > "$0.entered"
while [ ! -f "$0.release" ]; do sleep 0.01; done
exit 0
"#,
        )
        .await
        .unwrap();
        tokio::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
        let runtime = YoukiRuntime::new(&binary);
        let slot = Arc::new(Mutex::new(TaskRecord {
            state: TaskState::Running,
            output: crate::output::OutputCapture::default(),
            finished: false,
            exit_status: None,
            bundle: root.clone(),
            isolated_network: false,
        }));
        runtime.tasks.insert("owned".into(), slot.clone());
        // Manual polling prevents the stop task from advancing outside the gates below.
        let mut stop = Box::pin(runtime.stop_task("owned"));
        assert!(poll_once(stop.as_mut()).is_pending());
        tokio::time::timeout(Duration::from_secs(3), async {
            while !tokio::fs::try_exists(binary.with_extension("entered"))
                .await
                .unwrap()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::fs::write(binary.with_extension("release"), [])
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(
                Instant::now() < deadline,
                "kill acknowledgement was not observed"
            );
            let guard = slot.lock().await;
            assert!(poll_once(stop.as_mut()).is_pending());
            let mut observer = Box::pin(slot.lock());
            assert!(poll_once(observer.as_mut()).is_pending());
            drop(guard);
            // FIFO locking proves stop passed the kill ACK, rather than just observing
            // a child-side marker before Command::output had consumed its exit status.
            let stop_is_waiting_on_record = match poll_once(observer.as_mut()) {
                std::task::Poll::Ready(guard) => {
                    drop(guard);
                    false
                }
                std::task::Poll::Pending => true,
            };
            drop(observer);
            if stop_is_waiting_on_record {
                assert!(poll_once(stop.as_mut()).is_pending());
                break;
            }
            tokio::task::yield_now().await;
        }
        {
            let mut record = slot.lock().await;
            assert_eq!(record.state, TaskState::Running);
            assert!(!record.finished);
            record.record_exit(std::process::ExitStatus::from_raw(exit_status));
            record.finished = true;
        }
        let result = tokio::time::timeout(Duration::from_secs(5), stop)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.state, expected);
        assert_eq!(runtime.task_state("owned").await.unwrap(), expected);
    }
    tokio::fs::remove_dir_all(root).await.unwrap();
}
