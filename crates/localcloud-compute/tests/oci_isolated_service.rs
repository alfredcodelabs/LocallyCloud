//! Real OCI network isolation and host-to-guest TCP integration.
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use localcloud_compute::runtime::{ComputeRuntime, TaskSpec, TaskState};
use localcloud_compute::youki::YoukiRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn unique_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "localcloud-isolated-{}-{nanos}",
        std::process::id()
    ))
}

#[tokio::test]
async fn isolated_http_service_is_reachable_only_through_runtime_connector() {
    let Some(runtime) = YoukiRuntime::discover() else {
        eprintln!("skipping: no OCI runtime on PATH");
        return;
    };
    if !Command::new("cc")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
    {
        eprintln!("skipping: no C compiler for static guest fixture");
        return;
    }
    let rootfs = unique_dir();
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ec2-httpd.c");
    let binary = rootfs.join("bin/httpd");
    let built = Command::new("cc")
        .args(["-static", "-O2"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .status()
        .unwrap();
    assert!(built.success(), "static C fixture must compile");
    let task_id = format!("isolated-test-{}", std::process::id());
    let port = 18000 + (std::process::id() % 10000) as u16;
    let spec = TaskSpec {
        name: task_id.clone(),
        image: rootfs.display().to_string(),
        command: vec!["/bin/httpd".into(), port.to_string()],
        env: HashMap::new(),
        memory_mb: 128,
        vcpu_count: 1,
    };
    let handle = runtime
        .start_isolated_service(&task_id, &spec, port, Duration::from_secs(5))
        .await
        .expect("isolated HTTP service becomes TCP-ready");
    assert_eq!(handle.state, TaskState::Running);
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", port)).is_err(),
        "guest loopback must not be exposed on host loopback"
    );
    let mut stream = runtime
        .connect_isolated_tcp(&task_id, port, Duration::from_secs(1))
        .await
        .expect("host can enter guest netns to connect");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: guest\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.ends_with("hello-localcloud"), "{response}");
    runtime.stop_task(&task_id).await.expect("stop OCI guest");
    assert!(
        runtime
            .connect_isolated_tcp(&task_id, port, Duration::from_millis(100))
            .await
            .is_err(),
        "stopped guest cannot be connected"
    );
    std::fs::remove_dir_all(&rootfs).unwrap();
}

#[tokio::test]
async fn readiness_timeout_stops_the_isolated_guest() {
    let Some(runtime) = YoukiRuntime::discover() else {
        eprintln!("skipping: no OCI runtime on PATH");
        return;
    };
    if !Command::new("cc")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
    {
        eprintln!("skipping: no C compiler for static guest fixture");
        return;
    }
    let rootfs = unique_dir();
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ec2-httpd.c");
    assert!(Command::new("cc")
        .args(["-static", "-O2"])
        .arg(source)
        .arg("-o")
        .arg(rootfs.join("bin/httpd"))
        .status()
        .unwrap()
        .success());
    let task_id = format!("timeout-test-{}", std::process::id());
    let actual_port = 28000 + (std::process::id() % 10000) as u16;
    let spec = TaskSpec {
        name: task_id.clone(),
        image: rootfs.display().to_string(),
        command: vec!["/bin/httpd".into(), actual_port.to_string()],
        env: HashMap::new(),
        memory_mb: 128,
        vcpu_count: 1,
    };
    let error = runtime
        .start_isolated_service(&task_id, &spec, actual_port + 1, Duration::from_millis(250))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("readiness timed out"), "{error}");
    assert_eq!(
        runtime.task_state(&task_id).await.unwrap(),
        TaskState::Stopped
    );
    assert!(runtime
        .connect_isolated_tcp(&task_id, actual_port, Duration::from_millis(100))
        .await
        .is_err());
    std::fs::remove_dir_all(rootfs).unwrap();
}
