mod cipher;

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use extenddb_core::limits::LimitsConfig;
use extenddb_engine::OperationContext;
use extenddb_storage::bootstrapper::Bootstrapper;
use extenddb_storage::hooks::{CancellationToken, WorkerContext};
use extenddb_storage::server_components::ServerComponentsOptions;
use extenddb_storage_sqlite::{SqliteBootstrapper, SqliteConfig};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{ConnectOptions, Connection};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tracing_subscriber::prelude::*;
use zeroize::{Zeroize, Zeroizing};

const MAX_FRAME: usize = 32 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Initialize {
    version: u32,
    key: String,
    database: String,
    account_id: String,
    region: String,
}

impl Drop for Initialize {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u64,
    operation: String,
    body: Value,
}

async fn read_frame(reader: &mut (impl AsyncBufRead + Unpin)) -> io::Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete frame",
                ))
            };
        }
        let end = available.iter().position(|byte| *byte == b'\n');
        let count = end.map_or(available.len(), |position| position + 1);
        if frame.len() + count > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        frame.extend_from_slice(&available[..count]);
        reader.consume(count);
        if end.is_some() {
            return Ok(Some(frame));
        }
    }
}

async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), body: &Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(body)?;
    if bytes.len() >= MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response too large",
        ));
    }
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

fn validate_initialize(init: &Initialize) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    if init.version != 1 {
        return Err("unsupported protocol version");
    }
    if init.account_id.len() != 12 || !init.account_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid account");
    }
    if init.region.is_empty()
        || init.region.len() > 64
        || !init
            .region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("invalid region");
    }
    let path = Path::new(&init.database);
    if !path.is_absolute()
        || path.file_name().is_none()
        || init.database.contains(['\0', '?', '#'])
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("invalid database path");
    }
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(&init.key)
            .map_err(|_| "invalid storage key")?,
    );
    let mut key = Zeroizing::new([0; 32]);
    if decoded.len() != key.len() {
        return Err("invalid storage key");
    }
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn aws_error(error: &extenddb_core::error::DynamoDbError) -> Value {
    let mut body = json!({"__type": error.full_error_type(), "message": error.message()});
    if let Some(reasons) = error.cancellation_reasons() {
        body["CancellationReasons"] = json!(reasons);
    }
    if let Some(item) = error.condition_check_item() {
        body["Item"] = json!(item);
    }
    body
}

fn storage<T>(result: extenddb_storage::management_store::OpResult<T>) -> Result<T, &'static str> {
    result.map_err(|_| "cannot initialize encrypted storage")
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut writer = BufWriter::new(tokio::io::stdout());
    let mut first = Zeroizing::new(
        read_frame(&mut reader)
            .await?
            .ok_or("initialization required")?,
    );
    let mut init: Initialize = serde_json::from_slice(&first)?;
    first.zeroize();
    cipher::install(validate_initialize(&init)?)?;
    init.key.zeroize();

    // Bootstrap explicitly: the upstream serve-time dev bootstrap prints a
    // generated admin password to stdout. This worker exposes no HTTP/admin API.
    extenddb_storage::set_backend(extenddb_storage_sqlite::backend())?;
    let bootstrap = SqliteBootstrapper::new(&init.database);
    storage(bootstrap.acquire_migration_lock().await)?;
    // A single connection fails immediately on a wrong key. Pool startup
    // otherwise retries the same unreadable database until its timeout.
    let mut probe = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&init.database)
        .create_if_missing(true)
        .connect()
        .await?;
    sqlx::query("SELECT count(*) FROM sqlite_master")
        .execute(&mut probe)
        .await?;
    probe.close().await?;
    let initialized = storage(bootstrap.is_catalog_initialized().await)?;
    if !initialized {
        storage(bootstrap.run_catalog_migrations().await)?;
        storage(bootstrap.bootstrap_encryption_key().await)?;
        storage(bootstrap.bootstrap_default_account().await)?;
        let password =
            Zeroizing::new(extenddb_storage::bootstrapper::helpers::generate_random_password());
        storage(
            bootstrap
                .bootstrap_admin_user(Some("locallycloud"), Some(&password))
                .await,
        )?;
    }
    let scope = format!("{}:{}", init.account_id, init.region);
    let settings = (extenddb_storage_sqlite::backend().settings_store)(&init.database).await?;
    match storage(settings.get_setting("locallycloud_scope").await)? {
        Some(stored) if stored != scope => return Err("database belongs to another scope".into()),
        Some(_) => {}
        None if initialized => return Err("database has no LocalCloud scope binding".into()),
        None => storage(settings.set_setting("locallycloud_scope", &scope).await)?,
    }
    drop(settings);
    storage(bootstrap.release_migration_lock().await)?;
    let config = SqliteConfig {
        path: init.database.clone(),
        pool_size: 1,
    };
    let components = extenddb_storage::create_server_components(
        &config,
        &init.region,
        ServerComponentsOptions::default(),
    )
    .await?;
    if storage(
        components
            .catalog_store
            .get_account_detail(&init.account_id)
            .await,
    )?
    .is_none()
    {
        storage(
            components
                .catalog_store
                .create_account(&init.account_id, &init.account_id)
                .await,
        )?;
    }
    let (filter, reload_handle) =
        tracing_subscriber::reload::Layer::new(tracing_subscriber::EnvFilter::new("warn"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init()?;
    let shutdown = CancellationToken::new();
    let worker_context = WorkerContext {
        metrics: Arc::new(extenddb_core::metrics::MetricsCollector::new()),
        catalog_store: components.catalog_store.clone(),
        reload_handle,
        config_log_level: "warn".to_owned(),
        shutdown: shutdown.clone(),
    };
    let workers = match components.runtime_hooks {
        Some(hooks) => hooks.spawn_workers(&worker_context).await,
        None => Vec::new(),
    };
    let context = OperationContext {
        storage: components.engine,
        limits: Arc::new(LimitsConfig::default()),
        region: Arc::from(init.region.as_str()),
        account_id: Arc::from(init.account_id.as_str()),
        import_paths: Arc::from([]),
        export_paths: Arc::from([]),
        authorized_key_info: HashMap::new(),
        auth_cache: extenddb_auth::AuthCacheRegistry::empty(),
        table_key_info_lookup: None,
    };
    write_frame(&mut writer, &json!({"version":1,"ready":true})).await?;
    let result: Result<(), Box<dyn std::error::Error>> = async {
        loop {
            let frame = tokio::select! {
                frame = read_frame(&mut reader) => frame?,
                _ = tokio::signal::ctrl_c() => break,
            };
            let Some(frame) = frame else {
                break;
            };
            let request: Request = serde_json::from_slice(&frame)?;
            let (status, body) = match extenddb_engine::dispatch(
                &request.operation,
                request.body,
                &context,
                "localhost",
            )
            .await
            {
                Ok(result) => (200, result.body),
                Err(error) => (error.status_code(), aws_error(&error)),
            };
            write_frame(
                &mut writer,
                &json!({"id":request.id,"status":status,"body":body}),
            )
            .await?;
        }
        Ok(())
    }
    .await;
    shutdown.cancel();
    for worker in workers {
        let mut worker = worker;
        if tokio::time::timeout(Duration::from_secs(5), &mut worker)
            .await
            .is_err()
        {
            worker.abort();
        }
    }
    result
}

fn main() {
    // SAFETY: Linux prctl/getppid have no pointer arguments here. Set the
    // parent-death signal before starting threads and close the exit race.
    unsafe {
        let parent = libc::getppid();
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
            || parent == 1
            || libc::getppid() != parent
        {
            eprintln!("worker requires a live supervising parent");
            std::process::exit(1);
        }
    }
    match std::env::args().nth(1).as_deref() {
        Some("--version") => {
            println!("locallycloud-extenddb-worker 0.1.0 (ExtendDB 0.1.14; protocol 1)");
            return;
        }
        Some("--help") => {
            println!("Private LocalCloud ExtendDB worker. Receives initialization and requests over stdin; responses over stdout. No listening sockets.");
            return;
        }
        Some(_) => {
            eprintln!("unsupported argument");
            std::process::exit(2);
        }
        None => {}
    }
    // SAFETY: main has not started threads; restrict created database sidecars.
    unsafe {
        libc::umask(0o077);
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("cannot initialize worker runtime");
            std::process::exit(1);
        }
    };
    if runtime.block_on(run()).is_err() {
        // Upstream error strings may contain paths or SQL input. Keep this
        // boundary generic; domain errors above retain their AWS error shape.
        eprintln!("ExtendDB worker failed to initialize or process its private channel");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn framing_rejects_partial_requests() {
        let mut reader = BufReader::new(&b"{\"id\":1}"[..]);
        assert_eq!(
            read_frame(&mut reader).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn framing_bounds_unterminated_input() {
        let bytes = vec![b'x'; MAX_FRAME + 1];
        let mut reader = BufReader::new(bytes.as_slice());
        assert_eq!(
            read_frame(&mut reader).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn initialization_rejects_scope_and_path_injection() {
        let mut init = Initialize {
            version: 1,
            key: base64::engine::general_purpose::STANDARD.encode([7; 32]),
            database: "/tmp/test.sqlite".to_owned(),
            account_id: "000000000000".to_owned(),
            region: "us-east-1".to_owned(),
        };
        assert!(validate_initialize(&init).is_ok());
        init.database = "/tmp/test.sqlite?mode=memory".to_owned();
        assert!(validate_initialize(&init).is_err());
        init.database = "/tmp/test.sqlite".to_owned();
        init.account_id = "../other".to_owned();
        assert!(validate_initialize(&init).is_err());
    }
}
