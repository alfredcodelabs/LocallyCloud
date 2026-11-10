//! Opt-in validation of the upstream PostgreSQL pack through the real rootless runtime.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use locallycloud_compute::runtime::{ComputeRuntime, RuntimeError, TaskSpec, TaskState, TaskUser};
use locallycloud_compute::runtime_pack::{read_guest_file, RuntimePacks};
use locallycloud_compute::youki::YoukiRuntime;
use tokio_postgres::NoTls;

async fn completed(runtime: &YoukiRuntime, id: &str) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            match runtime.task_state(id).await.map_err(|e| e.to_string())? {
                TaskState::Running => tokio::time::sleep(Duration::from_millis(25)).await,
                TaskState::Completed => return Ok(()),
                state => return Err(format!("PostgreSQL preparation {state:?}")),
            }
        }
    })
    .await
    .map_err(|_| "PostgreSQL preparation timed out".to_owned())?
}

async fn dispose(runtime: &YoukiRuntime, id: &str) -> Result<(), String> {
    match runtime.stop_task(id).await {
        Ok(_) | Err(RuntimeError::TaskAlreadyCompleted { .. }) => {}
        Err(RuntimeError::TaskNotFound { .. }) => return Ok(()),
        Err(error) => return Err(error.to_string()),
    }
    runtime.release_task(id).await.map_err(|e| e.to_string())
}

#[tokio::test]
async fn postgres_pack_persists_sql_across_isolated_guest_restarts() {
    let Some(packs) = std::env::var_os("LOCALLYCLOUD_TEST_POSTGRES_PACKS") else {
        eprintln!("skipping real PostgreSQL: set LOCALLYCLOUD_TEST_POSTGRES_PACKS to an explicitly installed store");
        return;
    };
    let runtime =
        YoukiRuntime::discover().expect("explicit PostgreSQL validation requires an OCI runtime");
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "arm64",
        _ => panic!("unsupported host"),
    };
    let loader = Arc::new(RuntimePacks::new(PathBuf::from(packs)));
    let pack = loader.load("postgres16", architecture).await.unwrap();
    let root = std::env::temp_dir().join(format!("postgres-oci-{}", uuid::Uuid::new_v4()));
    let installing = root.clone();
    let installing_pack = pack.clone();
    let identity = tokio::task::spawn_blocking(move || {
        installing_pack.install(&installing)?;
        let passwd = String::from_utf8(read_guest_file(
            &installing,
            Path::new("/etc/passwd"),
            65536,
        )?)
        .map_err(std::io::Error::other)?;
        let user: Vec<_> = passwd
            .lines()
            .find(|line| line.starts_with("postgres:"))
            .ok_or_else(|| std::io::Error::other("missing postgres user"))?
            .split(':')
            .collect();
        Ok::<_, std::io::Error>(TaskUser {
            uid: user[2].parse().map_err(std::io::Error::other)?,
            gid: user[3].parse().map_err(std::io::Error::other)?,
        })
    })
    .await
    .unwrap()
    .unwrap();
    let mut spec = TaskSpec {
        mounts: Vec::new(),
        user: Some(identity),
        name: "postgres-validation".into(),
        image: root.display().to_string(),
        command: vec![
            "/usr/lib/postgresql/16/bin/initdb".into(),
            "-D".into(),
            "/tmp/pgdata".into(),
            "-U".into(),
            "app".into(),
            "--auth-host=trust".into(),
            "--auth-local=trust".into(),
            "--no-locale".into(),
            "--encoding=UTF8".into(),
        ],
        env: pack
            .environment
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        memory_mb: 256,
        vcpu_count: 1,
    };
    let mut owned = Vec::new();
    // Trust is confined to the guest network namespace and this disposable fixture.
    let result = tokio::time::timeout(Duration::from_secs(90), async {
        let init = format!("pg-init-{}",uuid::Uuid::new_v4());
        owned.push(init.clone());
        runtime.start_task_isolated(&init, &spec).await.map_err(|e|e.to_string())?;
        completed(&runtime, &init).await?;
        dispose(&runtime,&init).await?;
        spec.command = vec!["/usr/lib/postgresql/16/bin/postgres".into(), "-D".into(), "/tmp/pgdata".into(), "-c".into(), "listen_addresses=127.0.0.1".into(), "-c".into(), "unix_socket_directories=/tmp".into()];
        for round in 0..2 {
            let id=format!("pg-server-{}",uuid::Uuid::new_v4());
            owned.push(id.clone());
            runtime.start_isolated_service(&id,&spec,5432,Duration::from_secs(30)).await.map_err(|e|e.to_string())?;
            let (client, connection) = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let socket = runtime.connect_isolated_tcp(&id,5432,Duration::from_secs(5)).await.map_err(|e|e.to_string())?;
                    match tokio_postgres::Config::new().user("app").dbname("postgres").connect_raw(socket,NoTls).await {
                        Ok(connection) => return Ok::<_,String>(connection),
                        Err(error) if error.as_db_error().is_some_and(|db| db.code().code()=="57P03") => {
                            tokio::time::sleep(Duration::from_millis(25)).await;
                        }
                        Err(error) => return Err(format!("PostgreSQL connection failed: {error:?}")),
                    }
                }
            }).await.map_err(|_|"PostgreSQL SQL readiness timed out".to_owned())??;
            let connection=tokio::spawn(connection);
            if round==0 { client.batch_execute("CREATE TABLE proof (id integer PRIMARY KEY, value text NOT NULL); INSERT INTO proof VALUES (1,'persisted');").await.map_err(|e|e.to_string())?; }
            let row=client.query_one("SELECT value FROM proof WHERE id=1",&[]).await.map_err(|e|e.to_string())?;
            if row.get::<_,String>(0)!="persisted" { return Err("SQL data was not preserved".to_owned()); }
            drop(client);
            connection.await.map_err(|e|e.to_string())?.map_err(|e|e.to_string())?;
            dispose(&runtime,&id).await?;
        }
        Ok::<_,String>(())
    }).await.unwrap_or_else(|_| Err("PostgreSQL probe timed out".to_owned()));
    if let Err(error) = &result {
        eprintln!("PostgreSQL probe failed: {error}");
        for id in &owned {
            eprintln!("{id}: {}", runtime.get_output(id).await.unwrap_or_default());
        }
    }
    let mut cleanup = Vec::new();
    for id in owned.iter().rev() {
        if let Err(error) = dispose(&runtime, id).await {
            cleanup.push(format!("{id}: {error}"));
        }
    }
    if cleanup.is_empty() {
        tokio::fs::remove_dir_all(root).await.unwrap();
    }
    assert!(
        cleanup.is_empty(),
        "PostgreSQL cleanup pending: {cleanup:?}"
    );
    result.unwrap();
    eprintln!("Real rootless PostgreSQL: SQL survived guest termination and restart without host PostgreSQL or Docker daemon");
}
