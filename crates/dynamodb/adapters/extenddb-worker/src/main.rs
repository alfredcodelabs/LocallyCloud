mod backups;
mod cipher;
mod migration;
mod pitr;
mod replication;
mod streams;
mod table_file;

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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{ConnectOptions, Connection};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tracing_subscriber::prelude::*;
use zeroize::{Zeroize, Zeroizing};

const MAX_FRAME: usize = 32 * 1024 * 1024;

const FEATURES: &[&str] = &[
    "stream-cursors-v1",
    "mrec-outbox-v1",
    "backups-v1",
    "migration-ttl-v1",
    "migration-history-v1",
    "pitr-history-v1",
    "pitr-global-v1",
    "table-file-v1",
];

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum WorkerMode {
    #[default]
    Normal,
    Migration,
}

fn capabilities() -> Value {
    json!({"version":1,"features":FEATURES})
}

fn ready(mode: WorkerMode) -> Value {
    json!({"version":1,"ready":true,"features":FEATURES,"mode":mode})
}

fn runtime_options(mode: WorkerMode) -> ServerComponentsOptions {
    let mut options = ServerComponentsOptions::default();
    options.suspend_ttl_expiration = mode == WorkerMode::Migration;
    options
}

fn scope_matches(stored: &str, expected: &str) -> bool {
    stored == expected || stored.strip_suffix(":migration-history-v1") == Some(expected)
}

#[derive(Debug, PartialEq, Eq)]
enum CliCommand {
    Run,
    Version,
    Help,
    Capabilities,
}

fn cli(arguments: &[String]) -> Result<CliCommand, &'static str> {
    match arguments {
        [] => Ok(CliCommand::Run),
        [argument] => match argument.as_str() {
            "--version" => Ok(CliCommand::Version),
            "--help" => Ok(CliCommand::Help),
            "--capabilities" => Ok(CliCommand::Capabilities),
            _ => Err("unsupported argument"),
        },
        _ => Err("unsupported arguments"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Initialize {
    version: u32,
    key: String,
    database: String,
    account_id: String,
    region: String,
    #[serde(default)]
    mode: WorkerMode,
    #[serde(default)]
    table_file: Option<table_file::TableFile>,
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
    if let Some(table) = &init.table_file {
        table.validate()?;
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
    let encoding = match &init.table_file {
        Some(_) => cipher::KeyEncoding::Raw,
        None => cipher::KeyEncoding::LegacyPassphrase,
    };
    cipher::install(validate_initialize(&init)?, encoding)?;
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
    let scope = match &init.table_file {
        Some(table) => table.scope(&init.account_id, &init.region)?,
        None => format!("{}:{}", init.account_id, init.region),
    };
    let settings = (extenddb_storage_sqlite::backend().settings_store)(&init.database).await?;
    match storage(settings.get_setting("locallycloud_scope").await)? {
        Some(stored) if !scope_matches(&stored, &scope) => {
            return Err("database belongs to another scope".into());
        }
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
        runtime_options(init.mode),
    )
    .await?;
    let engine: Arc<dyn std::any::Any + Send + Sync> = components.engine.clone();
    let sqlite = engine
        .downcast::<extenddb_storage_sqlite::SqliteEngine>()
        .map_err(|_| "SQLite replication extension is unavailable")?;
    let replication =
        replication::Replication::open(&init.database, &init.account_id, &init.region).await?;
    sqlite.install_mutation_hook(replication.clone())?;
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
    let mut hello = ready(init.mode);
    hello["table_file"] = serde_json::to_value(&init.table_file)?;
    write_frame(&mut writer, &hello).await?;
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
            if let Some(table) = &init.table_file {
                if let Err(error) = table.authorize(&request.operation, &request.body, &init.account_id, &init.region) {
                    write_frame(&mut writer, &json!({"id":request.id,"status":error.status_code(),"body":aws_error(&error)})).await?;
                    continue;
                }
            }
            let result = match request.operation.as_str() {
                op if op.starts_with("__locallycloud_migration_history_") => {
                    migration::dispatch(op, request.body, init.mode, &context, &sqlite).await
                }
                "__locallycloud_resolve_stream_iterator" => streams::resolve(&request.body),
                "GetRecords" => streams::get_records(request.body, &context).await,
                op @ ("DescribeContinuousBackups"
                | "UpdateContinuousBackups"
                | "RestoreTableToPointInTime") => {
                    pitr::dispatch(op, request.body, &context, &sqlite).await
                }
                op @ ("CreateBackup"
                | "DescribeBackup"
                | "ListBackups"
                | "DeleteBackup"
                | "RestoreTableFromBackup") => {
                    backups::dispatch(op, request.body, &context, &sqlite).await
                }
                op if op.starts_with("__locallycloud_global_") => replication
                    .dispatch(&sqlite, op, request.body)
                    .await
                    .map_err(|error| match error {
                        extenddb_storage::error::StorageError::Validation(message) => {
                            extenddb_core::error::DynamoDbError::ValidationException(message)
                        }
                        extenddb_storage::error::StorageError::TableNotFound(_) => {
                            extenddb_core::error::DynamoDbError::ResourceNotFoundException(
                                "Table not found".into(),
                            )
                        }
                        extenddb_storage::error::StorageError::IndexesInUse(_) => {
                            extenddb_core::error::DynamoDbError::ResourceInUseException(
                                "replica has pending writes or is retiring".into(),
                            )
                        }
                        extenddb_storage::error::StorageError::TableAlreadyExists(_) => {
                            extenddb_core::error::DynamoDbError::ResourceInUseException(
                                "Table already exists".into(),
                            )
                        }
                        _ => extenddb_core::error::DynamoDbError::InternalServerError(
                            "replication control operation failed".into(),
                        ),
                    }),
                _ => extenddb_engine::dispatch(
                    &request.operation,
                    request.body,
                    &context,
                    "localhost",
                )
                .await
                .map(|result| result.body),
            };
            let (status, body) = match result {
                Ok(body) => (200, body),
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
    match cli(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(CliCommand::Version) => {
            println!("locallycloud-extenddb-worker 0.1.0 (ExtendDB 0.1.14 + mutation hook 1; protocol 1)");
            return;
        }
        Ok(CliCommand::Help) => {
            println!("Private LocalCloud ExtendDB worker. Receives initialization and requests over stdin; responses over stdout. No listening sockets.");
            return;
        }
        Ok(CliCommand::Capabilities) => {
            println!("{}", capabilities());
            return;
        }
        Ok(CliCommand::Run) => {}
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
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
    let result = runtime.block_on(run());
    drop(runtime);
    if result.is_err() {
        // Upstream error strings may contain paths or SQL input. Keep this
        // boundary generic; domain errors above retain their AWS error shape.
        eprintln!("ExtendDB worker failed to initialize or process its private channel");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrated_scope_is_exact_and_legacy_scope_stays_readable() {
        let scope = "000000000000:us-east-1";
        assert!(scope_matches(scope, scope));
        assert!(scope_matches(
            &format!("{scope}:migration-history-v1"),
            scope
        ));
        for other in [
            "000000000001:us-east-1:migration-history-v1",
            "000000000000:us-east-2:migration-history-v1",
            "000000000000:us-east-1:migration-history-v2",
            "000000000000:us-east-1:migration-history-v1:extra",
        ] {
            assert!(!scope_matches(other, scope));
        }
    }

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
            mode: WorkerMode::Normal,
            table_file: None,
        };
        assert!(validate_initialize(&init).is_ok());
        init.database = "/tmp/test.sqlite?mode=memory".to_owned();
        assert!(validate_initialize(&init).is_err());
        init.database = "/tmp/test.sqlite".to_owned();
        init.account_id = "../other".to_owned();
        assert!(validate_initialize(&init).is_err());
    }

    #[test]
    fn migration_is_explicit_and_controls_only_ttl_runtime_option() {
        let mut value = json!({"version":1,"key":"not-used","database":"/not/opened.sqlite3","account_id":"000000000000","region":"us-east-1"});
        let default: Initialize = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(default.mode, WorkerMode::Normal);
        assert!(!runtime_options(default.mode).suspend_ttl_expiration);
        value["mode"] = json!("migration");
        let migration: Initialize = serde_json::from_value(value.clone()).unwrap();
        let options = runtime_options(migration.mode);
        assert!(options.suspend_ttl_expiration);
        assert!(!options.bootstrap_if_uninitialized);
        assert_eq!(ready(migration.mode)["mode"], "migration");
        assert_eq!(ready(default.mode)["mode"], "normal");
        value["mode"] = json!("pretend-migration");
        assert!(serde_json::from_value::<Initialize>(value.clone()).is_err());
        value["mode"] = Value::Null;
        assert!(serde_json::from_value::<Initialize>(value).is_err());
    }

    #[test]
    fn capabilities_are_static_bounded_and_match_ready_features() {
        let value = capabilities();
        assert_eq!(value["version"], 1);
        assert_eq!(value["features"], ready(WorkerMode::Migration)["features"]);
        assert!(value["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|feature| feature == "migration-ttl-v1"));
        assert!(serde_json::to_vec(&value).unwrap().len() < 4096);
        assert_eq!(
            cli(&["--capabilities".into()]),
            Ok(CliCommand::Capabilities)
        );
        assert!(cli(&["--capabilities".into(), "extra".into()]).is_err());
        assert!(cli(&["--unknown".into()]).is_err());
    }
}
