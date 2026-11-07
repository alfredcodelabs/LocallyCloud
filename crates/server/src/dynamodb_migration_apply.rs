//! Durable intent bridges filesystem publication and the shared SQLite engine binding.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use locallycloud_dynamodb::migration::{export_native, export_native_recovery, NativeRecord};
use locallycloud_state::{StateCipher, StateDb};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::dynamodb_engine::WorkerPool;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u32,
    stage: String,
    phase: Phase,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Phase {
    Copying,
    Verified,
}

fn sibling(source: &Path, suffix: &str) -> PathBuf {
    let mut name = source.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

pub(crate) fn ensure_no_pending(source: &Path) -> io::Result<()> {
    match fs::symlink_metadata(sibling(source, ".dynamodb-migration.json")) {
        Ok(_) => Err(io::Error::other("An interrupted DynamoDB migration requires recovery; stop the server and run migrate-dynamodb --apply with the original master key")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn private(path: &Path, directory: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments or preconditions.
    let uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(io::Error::other(
            "Migration paths must be private, user-owned, and contain no symlinks",
        ));
    }
    Ok(())
}

fn sync_parent(path: &Path) -> io::Result<()> {
    File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("Migration path has no parent"))?,
    )?
    .sync_all()
}

fn journal_write(path: &Path, journal: &Journal) -> io::Result<()> {
    let temporary = sibling(path, &format!(".{}", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    let result = (|| {
        serde_json::to_writer(&mut file, journal).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn journal_read(path: &Path, source: &Path) -> io::Result<Journal> {
    private(path, false)?;
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(io::Error::other("Migration journal is too large"));
    }
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|_| {
        io::Error::other(
            "Invalid migration journal; preserve the source and destination for recovery",
        )
    })?;
    let name = source
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::other("Source filename must be UTF-8"))?;
    let prefix = format!("{name}.extenddb-migration-");
    let suffix = journal
        .stage
        .strip_prefix(&prefix)
        .ok_or_else(|| io::Error::other("Migration journal has another source scope"))?;
    if journal.schema != 1
        || uuid::Uuid::parse_str(suffix).is_err()
        || Path::new(&journal.stage).components().count() != 1
    {
        return Err(io::Error::other("Invalid migration journal stage"));
    }
    Ok(journal)
}

fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

// Only known worker database layout is accepted before syncing or discarding a partial stage.
fn sync_tree(path: &Path, depth: usize) -> io::Result<()> {
    private(path, true)?;
    if depth > 2 {
        return Err(io::Error::other("Unexpected migration directory nesting"));
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            sync_tree(&entry.path(), depth + 1)?;
        } else {
            private(&entry.path(), false)?;
            File::open(entry.path())?.sync_all()?;
        }
    }
    File::open(path)?.sync_all()
}

fn worker_leases(path: &Path, depth: usize, leases: &mut Vec<File>) -> io::Result<()> {
    private(path, true)?;
    if depth > 2 {
        return Err(io::Error::other("Unexpected migration directory nesting"));
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            worker_leases(&entry.path(), depth + 1, leases)?;
        } else {
            private(&entry.path(), false)?;
            if entry
                .file_name()
                .as_encoded_bytes()
                .ends_with(b".sqlite3.lock")
            {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(entry.path())?;
                file.try_lock().map_err(|_|io::Error::other("An interrupted migration worker is still shutting down; wait a moment and retry migrate-dynamodb --apply"))?;
                leases.push(file);
            }
        }
    }
    Ok(())
}

fn discard_stage(stage: &Path) -> io::Result<()> {
    let mut leases = Vec::new();
    worker_leases(stage, 0, &mut leases)?;
    sync_tree(stage, 0)?;
    fs::remove_dir_all(stage)?;
    // All official worker flock leases remain held until the old directory is gone.
    drop(leases);
    Ok(())
}

struct Prepared {
    source: PathBuf,
    stage: PathBuf,
    destination: PathBuf,
    marker: PathBuf,
    journal: Journal,
    state: StateDb,
    _lock: File,
    _component: (PathBuf, File, File),
    completed: bool,
    published: bool,
}

#[cfg(test)]
fn binding(state: &StateDb) -> Result<Option<String>, String> {
    let connection = state.connection().map_err(|e| e.to_string())?;
    let present: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='locallycloud_service_engines' AND type='table')", [], |r| r.get(0)).map_err(|e| e.to_string())?;
    if !present {
        return Ok(None);
    }
    let mut statement = connection
        .prepare("SELECT engine FROM locallycloud_service_engines WHERE service='dynamodb'")
        .map_err(|e| e.to_string())?;
    let mut rows = statement.query([]).map_err(|e| e.to_string())?;
    rows.next()
        .map_err(|e| e.to_string())?
        .map(|row| row.get(0))
        .transpose()
        .map_err(|e| e.to_string())
}

fn authenticate_source(path: &Path, cipher: &StateCipher) -> Result<(), String> {
    let authenticated = locallycloud_iam_sts::authenticate_state_key(path, cipher)
        .map_err(|error| error.to_string())?;
    if !authenticated {
        return Err("Cannot authenticate the source master key: start the native server once with its original LOCALLYCLOUD_KMS_MASTER_KEY, stop it, then retry migrate-dynamodb --apply".into());
    }
    Ok(())
}

struct SourceGuard {
    source: PathBuf,
    cipher: StateCipher,
    lock: File,
    component: (PathBuf, File, File),
}

fn source_guard() -> Result<SourceGuard, String> {
    let source = StateDb::default_path().map_err(|e| e.to_string())?;
    let lock = super::lock_source(&source)?;
    let cipher = StateCipher::from_env().map_err(|e| e.to_string())?;
    authenticate_source(&source, &cipher)?;
    let component = crate::component_manager::verified(
        &crate::component_manager::directory().map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(SourceGuard {
        source,
        cipher,
        lock,
        component,
    })
}

fn supports_migration_ttl(bytes: &[u8]) -> bool {
    if bytes.len() > 4096 {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    let Some(features) = value.get("features").and_then(Value::as_array) else {
        return false;
    };
    value.get("version").and_then(Value::as_u64) == Some(1)
        && features
            .iter()
            .any(|feature| feature.as_str() == Some("migration-ttl-v1"))
        && crate::component_catalog::REQUIRED_CAPABILITIES
            .iter()
            .all(|required| {
                features
                    .iter()
                    .any(|feature| feature.as_str() == Some(*required))
            })
}

async fn require_migration_ttl(component: &(PathBuf, File, File)) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    // Execute the checksum-verified inode while its shared installation lease remains held.
    let executable = format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        component.1.as_raw_fd()
    );
    let mut child = tokio::process::Command::new(executable)
        .arg("--capabilities")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "Cannot inspect installed ExtendDB worker capabilities".to_owned())?;
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let output = child.stdout.take().ok_or("ExtendDB capability output unavailable")?;
        let mut bytes = Vec::new();
        output.take(4097).read_to_end(&mut bytes).await
            .map_err(|_| "Cannot read ExtendDB worker capabilities")?;
        if bytes.len() > 4096 {
            return Err("ExtendDB capability output exceeds its limit");
        }
        let status = child.wait().await.map_err(|_| "Cannot reap ExtendDB capability probe")?;
        if !status.success() || !supports_migration_ttl(&bytes) {
            return Err("Installed ExtendDB worker lacks migration TTL support; install a current worker before retrying");
        }
        Ok(())
    }).await;
    let error = match result {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(error)) => error.to_owned(),
        Err(_) => "ExtendDB capability probe timed out".to_owned(),
    };
    // Every failure path kills and reaps the probe before source/component guards drop.
    let _ = child.start_kill();
    let _ = child.wait().await;
    Err(error)
}

fn prepare(guard: SourceGuard) -> Result<Prepared, String> {
    let SourceGuard {
        source,
        cipher,
        lock,
        component,
    } = guard;
    let marker = sibling(&source, ".dynamodb-migration.json");
    let destination = sibling(&source, ".extenddb");
    let selected =
        locallycloud_dynamodb::migration::engine_binding(&source).map_err(|e| e.to_string())?;
    let pending = exists(&marker).map_err(|e| e.to_string())?;
    let journal = if pending {
        journal_read(&marker, &source).map_err(|e| e.to_string())?
    } else {
        Journal {
            schema: 1,
            stage: format!(
                "{}.extenddb-migration-{}",
                source
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or("Source filename must be UTF-8")?,
                uuid::Uuid::new_v4()
            ),
            phase: Phase::Copying,
        }
    };
    let stage = source
        .parent()
        .ok_or("Source has no parent")?
        .join(&journal.stage);
    let published = exists(&destination).map_err(|e| e.to_string())?;
    let staged = exists(&stage).map_err(|e| e.to_string())?;
    // The verified intent was durable before publication/binding. Startup cannot serve while it exists.
    let completed = pending
        && journal.phase == Phase::Verified
        && published
        && !staged
        && selected.as_deref() == Some("extenddb");
    if completed {
        private(&destination, true).map_err(|e| e.to_string())?;
        export_native_recovery(&source, &cipher, |_| Ok(())).map_err(|e| e.to_string())?;
        let state = StateDb::open(source.clone()).map_err(|e| e.to_string())?;
        return Ok(Prepared {
            source,
            stage,
            destination,
            marker,
            journal,
            state,
            _lock: lock,
            _component: component,
            completed,
            published,
        });
    }
    if selected.as_deref().is_some_and(|engine| engine != "native") {
        return Err("Source is not bound to the native engine; migrations never switch a written ExtendDB store back to native".into());
    }
    // Export authenticates every encrypted row and rejects every blocker before yielding any record.
    let summary = export_native(&source, &cipher, |_| Ok(())).map_err(|e| e.to_string())?;
    if summary.table_count == 0 {
        return Err(
            "Native source has no tables to migrate; use a fresh state for ExtendDB".into(),
        );
    }
    match (pending, &journal.phase, published, staged) {
        (false, _, true, _) => return Err("ExtendDB destination already exists; it will never be overwritten".into()),
        (true, Phase::Copying, true, _) => return Err("Unexpected published destination for an incomplete copy; preserve both stores for recovery".into()),
        (true, Phase::Verified, true, true) => return Err("Both migration stage and final destination exist; refusing ambiguous recovery".into()),
        (true, Phase::Verified, false, false) => return Err("Verified migration destination is missing; preserve the source and journal".into()),
        _ => {}
    }
    let state = StateDb::open(source.clone()).map_err(|e| e.to_string())?;
    if journal.phase == Phase::Copying {
        if staged {
            discard_stage(&stage).map_err(|e| e.to_string())?;
        }
        journal_write(&marker, &journal).map_err(|e| e.to_string())?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&stage)
            .map_err(|e| e.to_string())?;
        sync_parent(&stage).map_err(|e| e.to_string())?;
    } else {
        private(if published { &destination } else { &stage }, true).map_err(|e| e.to_string())?;
    }
    Ok(Prepared {
        source,
        stage,
        destination,
        marker,
        journal,
        state,
        _lock: lock,
        _component: component,
        completed,
        published,
    })
}

async fn query(
    pool: &WorkerPool,
    account: &str,
    region: &str,
    operation: &str,
    body: Value,
) -> Result<Value, String> {
    let (status, value) = pool.query(account, region, operation.into(), body).await?;
    if status != 200 {
        return Err(format!(
            "Migration {operation} failed: {}",
            value
                .get("__type")
                .and_then(Value::as_str)
                .unwrap_or("worker error")
        ));
    }
    Ok(value)
}

fn schema_matches(expected: &Value, actual: &Value) -> bool {
    fn projection(value: &Value) -> Value {
        let mut result = serde_json::Map::new();
        for key in ["TableName", "KeySchema", "AttributeDefinitions"] {
            if let Some(value) = value.get(key) {
                result.insert(key.into(), value.clone());
            }
        }
        let billing = value
            .get("BillingMode")
            .or_else(|| value.pointer("/BillingModeSummary/BillingMode"))
            .and_then(Value::as_str)
            .unwrap_or("PROVISIONED");
        result.insert("BillingMode".into(), json!(billing));
        fn throughput(value: &Value) -> Value {
            json!({"ReadCapacityUnits":value.get("ReadCapacityUnits"),"WriteCapacityUnits":value.get("WriteCapacityUnits")})
        }
        if billing == "PROVISIONED" {
            result.insert(
                "ProvisionedThroughput".into(),
                throughput(&value["ProvisionedThroughput"]),
            );
        }
        for field in ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"] {
            let mut indexes: Vec<_> = value.get(field).and_then(Value::as_array).into_iter().flatten().map(|index| {
                let mut projected=json!({"IndexName":index.get("IndexName"),"KeySchema":index.get("KeySchema"),"Projection":index.get("Projection")});
                if field == "GlobalSecondaryIndexes" && billing == "PROVISIONED" { projected["ProvisionedThroughput"]=throughput(&index["ProvisionedThroughput"]); }
                projected
            }).collect();
            indexes.sort_by_key(|i| i["IndexName"].as_str().unwrap_or("").to_owned());
            result.insert(field.into(), json!(indexes));
        }
        if let Some(definitions) = result
            .get_mut("AttributeDefinitions")
            .and_then(Value::as_array_mut)
        {
            definitions.sort_by_key(|v| v["AttributeName"].as_str().unwrap_or("").to_owned());
        }
        fn normalize(value: &mut Value) {
            let Some(object) = value.as_object_mut() else {
                return;
            };
            if let Some(keys) = object.get_mut("KeySchema").and_then(Value::as_array_mut) {
                keys.sort_by_key(|key| {
                    (
                        key["KeyType"].as_str().unwrap_or("").to_owned(),
                        key["AttributeName"].as_str().unwrap_or("").to_owned(),
                    )
                });
            }
            if let Some(attributes) = object
                .get_mut("Projection")
                .and_then(Value::as_object_mut)
                .and_then(|p| p.get_mut("NonKeyAttributes"))
                .and_then(Value::as_array_mut)
            {
                attributes.sort_by_key(|v| v.as_str().unwrap_or("").to_owned());
            }
            for field in ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"] {
                if let Some(indexes) = object.get_mut(field).and_then(Value::as_array_mut) {
                    for index in indexes {
                        normalize(index);
                    }
                }
            }
        }
        let mut projected = Value::Object(result);
        normalize(&mut projected);
        projected
    }
    projection(expected) == projection(actual)
}

struct Table {
    account: String,
    region: String,
    name: String,
    count: u64,
}

async fn verify_count(pool: &WorkerPool, table: &Table) -> Result<(), String> {
    let mut count = 0u64;
    let mut key = None;
    loop {
        let mut body =
            json!({"TableName":table.name,"Select":"COUNT","ConsistentRead":true,"Limit":100});
        if let Some(key) = key {
            body["ExclusiveStartKey"] = key;
        }
        let page = query(pool, &table.account, &table.region, "Scan", body).await?;
        count = count
            .checked_add(
                page.get("Count")
                    .and_then(Value::as_u64)
                    .ok_or("Missing migration item count")?,
            )
            .ok_or("Migration item count overflow")?;
        key = page
            .get("LastEvaluatedKey")
            .filter(|key| key.as_object().is_some_and(|v| !v.is_empty()))
            .cloned();
        if count > table.count
            || (key.is_some() && page.get("Count").and_then(Value::as_u64) == Some(0))
        {
            return Err(format!(
                "Invalid migration scan progress for {}",
                table.name
            ));
        }
        if key.is_none() {
            break;
        }
    }
    if count != table.count {
        return Err(format!("Migration item count differs for {}", table.name));
    }
    Ok(())
}

async fn verify_table(
    pool: &WorkerPool,
    table: &Table,
    create: &Value,
    tags: &Value,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let description = loop {
        let value = query(
            pool,
            &table.account,
            &table.region,
            "DescribeTable",
            json!({"TableName":table.name}),
        )
        .await?;
        let description = value
            .get("Table")
            .ok_or("Missing migrated table description")?
            .clone();
        let ready = description.get("TableStatus").and_then(Value::as_str) == Some("ACTIVE")
            && description
                .get("GlobalSecondaryIndexes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .all(|i| i.get("IndexStatus").and_then(Value::as_str) == Some("ACTIVE"));
        if ready {
            break description;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("Migrated table did not become ACTIVE".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    if !schema_matches(create, &description) {
        return Err(format!("Migration schema differs for {}", table.name));
    }
    let arn = description
        .get("TableArn")
        .and_then(Value::as_str)
        .ok_or("Missing migrated table ARN")?;
    let actual = query(
        pool,
        &table.account,
        &table.region,
        "ListTagsOfResource",
        json!({"ResourceArn":arn}),
    )
    .await?;
    let normalized = |value: &Value| {
        let mut tags = value.as_array().cloned().unwrap_or_default();
        tags.sort_by_key(|tag| tag["Key"].as_str().unwrap_or("").to_owned());
        tags
    };
    if normalized(tags) != normalized(&actual["Tags"]) {
        return Err(format!("Migration tags differ for {}", table.name));
    }
    Ok(())
}

fn ttl_matches(expected: Option<&str>, actual: &Value) -> bool {
    let Some(description) = actual
        .get("TimeToLiveDescription")
        .and_then(Value::as_object)
    else {
        return false;
    };
    match expected {
        Some(attribute) => {
            description.get("TimeToLiveStatus").and_then(Value::as_str) == Some("ENABLED")
                && description.get("AttributeName").and_then(Value::as_str) == Some(attribute)
        }
        None => {
            description.get("TimeToLiveStatus").and_then(Value::as_str) == Some("DISABLED")
                && !description.contains_key("AttributeName")
        }
    }
}

async fn verify_ttl(
    pool: &WorkerPool,
    table: &Table,
    attribute: Option<&str>,
) -> Result<(), String> {
    let actual = query(
        pool,
        &table.account,
        &table.region,
        "DescribeTimeToLive",
        json!({"TableName":table.name}),
    )
    .await?;
    if !ttl_matches(attribute, &actual) {
        return Err(format!(
            "Migration TTL configuration differs for {}",
            table.name
        ));
    }
    Ok(())
}

async fn transfer(
    source: PathBuf,
    destination: PathBuf,
    import: bool,
    recovery: bool,
) -> Result<(), String> {
    let notifier = crate::dynamodb_replication::RelayNotifier::new();
    let mut pool = WorkerPool::for_migration(destination.clone(), notifier.clone())
        .map_err(|e| e.to_string())?;
    let (sender, mut receiver) = mpsc::channel(4);
    let producer = tokio::task::spawn_blocking(move || {
        let cipher = StateCipher::from_env().map_err(|e| e.to_string())?;
        let emit = |record| {
            sender.blocking_send(record).map_err(|_| {
                locallycloud_dynamodb::error::DdbError::Internal(
                    "Migration consumer stopped".into(),
                )
            })
        };
        if recovery {
            export_native_recovery(&source, &cipher, emit)
        } else {
            export_native(&source, &cipher, emit)
        }
        .map_err(|e| e.to_string())
    });
    let mut current: Option<Table> = None;
    let result = async {
        while let Some(record) = receiver.recv().await {
            match record {
                NativeRecord::Table {
                    account,
                    region,
                    table,
                    mut create,
                    tags,
                    item_count,
                    ttl_attribute,
                } => {
                    if let Some(previous) = current.take() {
                        verify_count(&pool, &previous).await?;
                        if previous.account != account || previous.region != region {
                            pool.shutdown().await;
                            pool = WorkerPool::for_migration(destination.clone(), notifier.clone())
                                .map_err(|e| e.to_string())?;
                        }
                    }
                    let table = Table {
                        account,
                        region,
                        name: table,
                        count: item_count,
                    };
                    if import {
                        if tags.as_array().is_some_and(|tags| !tags.is_empty()) {
                            create["Tags"] = tags.clone();
                        }
                        query(
                            &pool,
                            &table.account,
                            &table.region,
                            "CreateTable",
                            create.clone(),
                        )
                        .await?;
                    }
                    verify_table(&pool, &table, &create, &tags).await?;
                    if let (true, Some(attribute)) = (import, &ttl_attribute) {
                        query(
                            &pool, &table.account, &table.region, "UpdateTimeToLive",
                            json!({"TableName":table.name,"TimeToLiveSpecification":{"Enabled":true,"AttributeName":attribute}}),
                        ).await?;
                    }
                    verify_ttl(&pool, &table, ttl_attribute.as_deref()).await?;
                    current = Some(table);
                }
                NativeRecord::Item {
                    account,
                    region,
                    table,
                    item,
                    key,
                } => {
                    if import {
                        query(
                            &pool,
                            &account,
                            &region,
                            "PutItem",
                            json!({"TableName":table,"Item":item}),
                        )
                        .await?;
                    }
                    let actual = query(
                        &pool,
                        &account,
                        &region,
                        "GetItem",
                        json!({"TableName":table,"Key":key,"ConsistentRead":true}),
                    )
                    .await?;
                    let expected = locallycloud_dynamodb::value::item_from_json(&item)
                        .map_err(|_| "Invalid source migration item")?;
                    let actual = actual.get("Item").ok_or("Missing migrated item")?;
                    let actual = locallycloud_dynamodb::value::item_from_json(actual)
                        .map_err(|_| "Invalid destination migration item")?;
                    if actual != expected {
                        return Err(format!("Migration item differs for {table}"));
                    }
                }
            }
        }
        if let Some(table) = current {
            verify_count(&pool, &table).await?;
        }
        Ok(())
    }
    .await;
    drop(receiver);
    pool.shutdown().await;
    let exported = producer
        .await
        .map_err(|_| "Native migration export task failed".to_owned())?;
    result?;
    exported?;
    Ok(())
}

fn commit(prepared: &mut Prepared) -> Result<(), String> {
    if !prepared.completed {
        sync_tree(
            if prepared.published {
                &prepared.destination
            } else {
                &prepared.stage
            },
            0,
        )
        .map_err(|e| e.to_string())?;
        prepared.journal.phase = Phase::Verified;
        journal_write(&prepared.marker, &prepared.journal).map_err(|e| e.to_string())?;
        if !prepared.published {
            // renameat2 NOREPLACE also refuses a destination created after preflight.
            let source = std::ffi::CString::new(prepared.stage.as_os_str().as_encoded_bytes())
                .map_err(|_| "Invalid stage path")?;
            let target =
                std::ffi::CString::new(prepared.destination.as_os_str().as_encoded_bytes())
                    .map_err(|_| "Invalid destination path")?;
            // SAFETY: both C strings are live, NUL-terminated paths; no borrowed output pointers.
            let status = unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    source.as_ptr(),
                    libc::AT_FDCWD,
                    target.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if status != 0 {
                return Err(format!(
                    "Cannot publish verified migration: {}",
                    io::Error::last_os_error()
                ));
            }
            sync_parent(&prepared.destination).map_err(|e| e.to_string())?;
        }
        let connection = prepared.state.connection().map_err(|e| e.to_string())?;
        connection.execute_batch("BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS locallycloud_service_engines(service TEXT PRIMARY KEY,engine TEXT NOT NULL);").map_err(|e|e.to_string())?;
        connection.execute("INSERT INTO locallycloud_service_engines(service,engine) VALUES('dynamodb','extenddb') ON CONFLICT(service) DO UPDATE SET engine=excluded.engine",[]).map_err(|e|e.to_string())?;
        connection
            .execute_batch("COMMIT")
            .map_err(|e| e.to_string())?;
    }
    fs::remove_file(&prepared.marker).map_err(|e| e.to_string())?;
    sync_parent(&prepared.marker).map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) async fn apply() -> Result<(), String> {
    let guard = tokio::task::spawn_blocking(source_guard)
        .await
        .map_err(|_| "Migration source preflight task failed".to_owned())??;
    require_migration_ttl(&guard.component).await?;
    let mut prepared = tokio::task::spawn_blocking(move || prepare(guard))
        .await
        .map_err(|_| "Migration destination preflight task failed".to_owned())??;
    if prepared.completed {
        // Trusted recovery is restricted to the validated, already-committed durable intent.
        // A full reopened destination read authenticates its key before clearing the startup guard.
        transfer(
            prepared.source.clone(),
            prepared.destination.clone(),
            false,
            true,
        )
        .await?;
    } else {
        let destination = if prepared.published {
            prepared.destination.clone()
        } else {
            prepared.stage.clone()
        };
        if prepared.journal.phase == Phase::Copying {
            transfer(prepared.source.clone(), destination.clone(), true, false).await?;
        }
        // Every pool has shut down. This opens fresh workers and verifies all source records again.
        transfer(prepared.source.clone(), destination, false, false).await?;
    }
    tokio::task::spawn_blocking(move || commit(&mut prepared))
        .await
        .map_err(|_| "Migration cutover task failed".to_owned())??;
    println!(
        "{}",
        json!({"kind":"migration-complete","engine":"extenddb","nativeRowsRetained":true,
        "preserved":["logicalSchema","billingAndCapacity","indexes","tags","ttl","items"],
        "physicalTableIdentity":"regenerated"})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Prepared {
        let root = std::env::temp_dir().join(format!("ddb-cutover-{}", uuid::Uuid::new_v4()));
        let source = root.join("state.db");
        let state = StateDb::open(source.clone()).unwrap();
        let lock = state.lock_runtime().unwrap();
        let connection = state.connection().unwrap();
        connection.execute_batch("CREATE TABLE locallycloud_service_engines(service TEXT PRIMARY KEY,engine TEXT NOT NULL); INSERT INTO locallycloud_service_engines VALUES('dynamodb','native'); CREATE TABLE native_fixture(payload TEXT); INSERT INTO native_fixture VALUES('native-row-preserved');").unwrap();
        drop(connection);
        let stage = sibling(
            &source,
            &format!(".extenddb-migration-{}", uuid::Uuid::new_v4()),
        );
        fs::DirBuilder::new().mode(0o700).create(&stage).unwrap();
        let fake = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(stage.join("fixture.db"))
            .unwrap();
        fake.sync_all().unwrap();
        let journal = Journal {
            schema: 1,
            stage: stage.file_name().unwrap().to_str().unwrap().into(),
            phase: Phase::Copying,
        };
        let marker = sibling(&source, ".dynamodb-migration.json");
        journal_write(&marker, &journal).unwrap();
        let destination = sibling(&source, ".extenddb");
        Prepared {
            source,
            stage,
            destination,
            marker,
            journal,
            state,
            _lock: lock,
            _component: (PathBuf::new(), fake.try_clone().unwrap(), fake),
            completed: false,
            published: false,
        }
    }

    #[test]
    fn plaintext_native_source_requires_shared_key_evidence_without_migration_side_effects() {
        let root = std::env::temp_dir().join(format!("ddb-cutover-key-{}", uuid::Uuid::new_v4()));
        let source = root.join("state.db");
        let state = StateDb::open(source.clone()).unwrap();
        let correct = StateCipher::with_key(&[7; 32]);
        assert!(authenticate_source(&source, &correct)
            .unwrap_err()
            .contains("start the native server once"));
        let payload = correct
            .seal(
                &["iam", "000000000000", "global", "policy", "managed"],
                b"{}",
            )
            .unwrap();
        state.connection().unwrap().execute_batch("CREATE TABLE iam_resources(account TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(account,kind,name));").unwrap();
        state
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO iam_resources VALUES('000000000000','policy','managed',?1)",
                [payload],
            )
            .unwrap();
        let before = fs::read(&source).unwrap();
        assert!(authenticate_source(&source, &StateCipher::with_key(&[8; 32])).is_err());
        assert_eq!(fs::read(&source).unwrap(), before);
        assert!(!sibling(&source, ".dynamodb-migration.json").exists());
        assert!(!sibling(&source, ".extenddb").exists());
        authenticate_source(&source, &correct).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publication_precedes_binding_and_preserves_native_rows() {
        let mut prepared = fixture();
        assert!(ensure_no_pending(&prepared.source).is_err());
        assert_eq!(binding(&prepared.state).unwrap().as_deref(), Some("native"));
        commit(&mut prepared).unwrap();
        assert!(prepared.destination.join("fixture.db").is_file());
        assert!(!prepared.stage.exists());
        assert!(!prepared.marker.exists());
        assert_eq!(
            binding(&prepared.state).unwrap().as_deref(),
            Some("extenddb")
        );
        assert_eq!(
            prepared
                .state
                .connection()
                .unwrap()
                .query_row("SELECT payload FROM native_fixture", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "native-row-preserved"
        );
        ensure_no_pending(&prepared.source).unwrap();
        fs::remove_dir_all(prepared.source.parent().unwrap()).unwrap();
    }

    #[test]
    fn conflicting_destination_never_gets_overwritten_or_bound() {
        let mut prepared = fixture();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&prepared.destination)
            .unwrap();
        fs::write(prepared.destination.join("untouched"), b"original").unwrap();
        // Publication helper must independently reject a late collision, not skip renaming.
        assert!(commit(&mut prepared).is_err());
        assert_eq!(binding(&prepared.state).unwrap().as_deref(), Some("native"));
        assert_eq!(
            fs::read(prepared.destination.join("untouched")).unwrap(),
            b"original"
        );
        assert!(ensure_no_pending(&prepared.source).is_err());
        fs::remove_dir_all(prepared.source.parent().unwrap()).unwrap();
    }

    #[test]
    fn verified_publication_keeps_startup_closed_until_binding_recovery() {
        let mut prepared = fixture();
        prepared.journal.phase = Phase::Verified;
        journal_write(&prepared.marker, &prepared.journal).unwrap();
        fs::rename(&prepared.stage, &prepared.destination).unwrap();
        sync_parent(&prepared.destination).unwrap();
        prepared.published = true;
        assert!(crate::dynamodb_engine::bind_store(&prepared.state, "native").is_err());
        assert!(crate::dynamodb_engine::bind_store(&prepared.state, "extenddb").is_err());
        assert_eq!(binding(&prepared.state).unwrap().as_deref(), Some("native"));
        let journal = journal_read(&prepared.marker, &prepared.source).unwrap();
        assert!(journal.phase == Phase::Verified);
        commit(&mut prepared).unwrap();
        assert_eq!(
            binding(&prepared.state).unwrap().as_deref(),
            Some("extenddb")
        );
        fs::remove_dir_all(prepared.source.parent().unwrap()).unwrap();
    }

    #[test]
    fn journal_refuses_paths_from_another_source_or_symlinks() {
        let prepared = fixture();
        let bad = Journal {
            schema: 1,
            stage: "../other.extenddb-migration-00000000-0000-0000-0000-000000000000".into(),
            phase: Phase::Verified,
        };
        journal_write(&prepared.marker, &bad).unwrap();
        assert!(journal_read(&prepared.marker, &prepared.source).is_err());
        fs::remove_file(&prepared.marker).unwrap();
        std::os::unix::fs::symlink(&prepared.source, &prepared.marker).unwrap();
        assert!(journal_read(&prepared.marker, &prepared.source).is_err());
        fs::remove_dir_all(prepared.source.parent().unwrap()).unwrap();
    }

    #[test]
    fn partial_stage_with_live_official_worker_lock_is_not_discarded() {
        let prepared = fixture();
        let lock_path = prepared.stage.join("us-east-1.sqlite3.lock");
        let lock = OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        lock.try_lock().unwrap();
        assert!(discard_stage(&prepared.stage)
            .unwrap_err()
            .to_string()
            .contains("still shutting down"));
        assert!(prepared.stage.join("fixture.db").exists());
        drop(lock);
        discard_stage(&prepared.stage).unwrap();
        assert!(!prepared.stage.exists());
        fs::remove_dir_all(prepared.source.parent().unwrap()).unwrap();
    }

    #[test]
    fn schema_comparison_checks_capacity_projection_and_all_scalar_indexes() {
        let expected = json!({"TableName":"orders","BillingMode":"PROVISIONED","ProvisionedThroughput":{"ReadCapacityUnits":7,"WriteCapacityUnits":9},
            "AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],"KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],
            "GlobalSecondaryIndexes":[{"IndexName":"lookup","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],"Projection":{"ProjectionType":"ALL"},"ProvisionedThroughput":{"ReadCapacityUnits":3,"WriteCapacityUnits":4}}]});
        let mut actual = expected.clone();
        actual["TableId"] = json!("new-physical-id");
        actual["CreationDateTime"] = json!(1234);
        assert!(schema_matches(&expected, &actual));
        actual["GlobalSecondaryIndexes"][0]["Projection"]["ProjectionType"] = json!("KEYS_ONLY");
        assert!(!schema_matches(&expected, &actual));
        actual = expected.clone();
        actual["ProvisionedThroughput"]["WriteCapacityUnits"] = json!(8);
        assert!(!schema_matches(&expected, &actual));
    }

    #[test]
    fn capability_probe_rejects_old_malformed_or_oversized_descriptions() {
        let features = crate::component_catalog::REQUIRED_CAPABILITIES
            .iter()
            .map(|feature| json!(feature))
            .chain(std::iter::once(json!("migration-ttl-v1")))
            .collect::<Vec<_>>();
        let valid = json!({"version":1,"features":features});
        assert!(supports_migration_ttl(&serde_json::to_vec(&valid).unwrap()));
        for invalid in [
            json!({"version":1,"features":["stream-cursors-v1"]}),
            json!({"version":2,"features":valid["features"]}),
            json!({"version":1,"features":"migration-ttl-v1"}),
        ] {
            assert!(!supports_migration_ttl(
                &serde_json::to_vec(&invalid).unwrap()
            ));
        }
        assert!(!supports_migration_ttl(&vec![b' '; 4097]));
        assert!(!supports_migration_ttl(b"not json"));
    }

    #[test]
    fn ttl_verification_preserves_enabled_disabled_and_attribute_identity() {
        let enabled = json!({"TimeToLiveDescription":{"TimeToLiveStatus":"ENABLED","AttributeName":"expires"}});
        let disabled = json!({"TimeToLiveDescription":{"TimeToLiveStatus":"DISABLED"}});
        assert!(ttl_matches(Some("expires"), &enabled));
        assert!(ttl_matches(None, &disabled));
        assert!(!ttl_matches(None, &enabled));
        assert!(!ttl_matches(Some("other"), &enabled));
        assert!(!ttl_matches(Some("expires"), &disabled));
        assert!(!ttl_matches(
            None,
            &json!({"TimeToLiveDescription":{"TimeToLiveStatus":"DISABLED","AttributeName":"old"}})
        ));
    }
}
