//! Real OCI network isolation and host-to-guest TCP integration.
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use locallycloud_compute::runtime::{ComputeRuntime, TaskSpec, TaskState};
use locallycloud_compute::youki::YoukiRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn unique_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "locallycloud-isolated-{}-{nanos}",
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
    assert!(response.ends_with("hello-locallycloud"), "{response}");
    runtime.stop_task(&task_id).await.expect("stop OCI guest");
    assert!(
        runtime
            .connect_isolated_tcp(&task_id, port, Duration::from_millis(100))
            .await
            .is_err(),
        "stopped guest cannot be connected"
    );
    runtime
        .release_task(&task_id)
        .await
        .expect("release isolated guest");
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
    runtime
        .release_task(&task_id)
        .await
        .expect("release isolated guest");
    std::fs::remove_dir_all(rootfs).unwrap();
}

#[tokio::test]
async fn isolated_guest_reaches_host_listener_only_through_its_own_loopback() {
    let Some(runtime) = YoukiRuntime::discover() else {
        return;
    };
    if !Command::new("cc")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        return;
    }
    let rootfs = unique_dir();
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/isolated_client.c");
    assert!(Command::new("cc")
        .args(["-static", "-O2"])
        .arg(source)
        .arg("-o")
        .arg(rootfs.join("bin/client"))
        .status()
        .unwrap()
        .success());
    let task_id = format!("isolated-client-{}", std::process::id());
    let port = 38000 + (std::process::id() % 10000) as u16;
    let spec = TaskSpec {
        name: task_id.clone(),
        image: rootfs.display().to_string(),
        command: vec!["/bin/client".into(), port.to_string()],
        env: HashMap::new(),
        memory_mb: 128,
        vcpu_count: 1,
    };
    let (_, mut listeners) = runtime
        .start_task_isolated_with_loopback(&task_id, &spec, &[port])
        .await
        .expect("bind guest listener before running the client");
    let listener = listeners.pop().unwrap();
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut request = [0; 4];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"ping");
    stream.write_all(b"pong").await.unwrap();
    drop(stream);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let state = runtime.task_state(&task_id).await.unwrap();
        if state != TaskState::Running {
            assert_eq!(state, TaskState::Completed);
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "guest did not exit");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(runtime
        .get_output(&task_id)
        .await
        .unwrap()
        .contains("isolated-loopback-ok"));
    runtime
        .release_task(&task_id)
        .await
        .expect("release isolated guest");
    std::fs::remove_dir_all(rootfs).unwrap();
}

#[tokio::test]
async fn isolated_guest_connects_to_private_ip_without_host_route() {
    let Some(runtime) = YoukiRuntime::discover() else {
        return;
    };
    if !Command::new("cc")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        return;
    }
    let rootfs = unique_dir();
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/isolated_client.c");
    assert!(Command::new("cc")
        .args(["-static", "-O2"])
        .arg(source)
        .arg("-o")
        .arg(rootfs.join("bin/client"))
        .status()
        .unwrap()
        .success());
    let task_id = format!("private-client-{}", std::process::id());
    let port = 48000 + (std::process::id() % 10000) as u16;
    let address: std::net::Ipv4Addr = "10.123.45.67".parse().unwrap();
    let second: std::net::Ipv4Addr = "10.123.45.68".parse().unwrap();
    let spec = TaskSpec {
        name: task_id.clone(),
        image: rootfs.display().to_string(),
        command: vec![
            "/bin/client".into(),
            port.to_string(),
            address.to_string(),
            second.to_string(),
        ],
        env: HashMap::new(),
        memory_mb: 128,
        vcpu_count: 1,
    };
    let (_, _loopback) = runtime
        .start_task_isolated_with_loopback(&task_id, &spec, &[port])
        .await
        .expect("start isolated guest");
    let listener = runtime
        .bind_isolated_private_tcp(&task_id, address, port)
        .await
        .expect("bind private address inside guest network namespace");
    let second_listener = runtime
        .bind_isolated_private_tcp(&task_id, second, port)
        .await
        .expect("bind second private address on same TCP port");
    let _public = runtime
        .bind_isolated_public_egress(&task_id, &[address, second])
        .await
        .expect("public capture excludes registered private destinations");
    assert!(
        std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from((address, port)),
            Duration::from_millis(200)
        )
        .is_err(),
        "private listener must not appear in host network namespace"
    );
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut request = [0; 4];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"ping");
    stream.write_all(b"pong").await.unwrap();
    drop(stream);
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), second_listener.accept())
        .await
        .unwrap()
        .unwrap();
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"ping");
    stream.write_all(b"pong").await.unwrap();
    drop(stream);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let state = runtime.task_state(&task_id).await.unwrap();
        if state != TaskState::Running {
            assert_eq!(state, TaskState::Completed);
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "guest did not exit");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(runtime
        .get_output(&task_id)
        .await
        .unwrap()
        .contains("isolated-loopback-ok"));
    runtime
        .release_task(&task_id)
        .await
        .expect("release isolated guest");
    std::fs::remove_dir_all(rootfs).unwrap();
}

#[tokio::test]
async fn isolated_guest_public_tcp_keeps_original_destination() {
    let Some(runtime) = YoukiRuntime::discover() else {
        return;
    };
    if !Command::new("cc")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        return;
    }
    let rootfs = unique_dir();
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/isolated_client.c");
    assert!(Command::new("cc")
        .args(["-static", "-O2"])
        .arg(source)
        .arg("-o")
        .arg(rootfs.join("bin/client"))
        .status()
        .unwrap()
        .success());
    let task_id = format!("public-client-{}", std::process::id());
    let port = 36000 + (std::process::id() % 10000) as u16;
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
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    use std::os::fd::AsRawFd;
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&address) as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_IP,
                80,
                (&mut address as *mut libc::sockaddr_in).cast(),
                &mut len,
            )
        },
        0
    );
    assert_eq!(
        std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()).to_string(),
        "8.8.8.8"
    );
    assert_eq!(u16::from_be(address.sin_port), port);
    let mut request = [0; 4];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"ping");
    stream.write_all(b"pong").await.unwrap();
    drop(stream);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while runtime.task_state(&task_id).await.unwrap() == TaskState::Running {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(runtime
        .get_output(&task_id)
        .await
        .unwrap()
        .contains("isolated-loopback-ok"));
    runtime
        .release_task(&task_id)
        .await
        .expect("release isolated guest");
    std::fs::remove_dir_all(rootfs).unwrap();
}
