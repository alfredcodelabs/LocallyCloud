//! Optional official DuckDB query engine behind the Athena authorization boundary.
use super::*;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod select;

const MAX_MIRROR_OBJECTS: usize = 4096;
const MAX_MIRROR_MANIFESTS: usize = 256;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);

#[async_trait]
pub(super) trait IcebergQueryEngine: Send + Sync {
    async fn query_sql(
        &self,
        access: QueryAccess<'_>,
        sql: &str,
        database: Option<&str>,
    ) -> Result<(QueryResult, u64), WorkerFailure>;
    async fn query(
        &self,
        access: QueryAccess<'_>,
        table: &GlueTableOutput,
        parsed: &sql::ParsedQuery,
    ) -> Result<(QueryResult, u64), WorkerFailure>;
}

#[async_trait]
impl IcebergQueryEngine for DuckDbEngine {
    async fn query_sql(
        &self,
        access: QueryAccess<'_>,
        sql: &str,
        database: Option<&str>,
    ) -> Result<(QueryResult, u64), WorkerFailure> {
        self.run(access, QueryInput::Sql(sql, database)).await
    }
    async fn query(
        &self,
        access: QueryAccess<'_>,
        table: &GlueTableOutput,
        parsed: &sql::ParsedQuery,
    ) -> Result<(QueryResult, u64), WorkerFailure> {
        self.run(access, QueryInput::Simple(table, parsed)).await
    }
}

enum QueryInput<'a> {
    Simple(&'a GlueTableOutput, &'a sql::ParsedQuery),
    Sql(&'a str, Option<&'a str>),
}

#[derive(Clone)]
pub struct DuckDbEngine {
    executable: PathBuf,
    extensions: PathBuf,
    work_dir: PathBuf,
    permits: Arc<tokio::sync::Semaphore>,
}

impl DuckDbEngine {
    pub fn new(executable: PathBuf, extensions: PathBuf, work_dir: PathBuf) -> Self {
        let absolute = |path: PathBuf| {
            if path.is_absolute() {
                path
            } else {
                std::env::current_dir()
                    .map(|cwd| cwd.join(&path))
                    .unwrap_or(path)
            }
        };
        Self {
            executable: absolute(executable),
            extensions: absolute(extensions),
            work_dir: absolute(work_dir),
            permits: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }

    async fn run(
        &self,
        access: QueryAccess<'_>,
        input: QueryInput<'_>,
    ) -> Result<(QueryResult, u64), WorkerFailure> {
        for name in ["avro", "iceberg"] {
            let path = self.extensions.join(format!("{name}.duckdb_extension"));
            if tokio::fs::metadata(path).await.is_err() {
                return Err(failure(format!("DuckDB extension {name} is missing; prepare official avro and iceberg extensions matching the CLI version and architecture in LOCALLYCLOUD_DUCKDB_EXTENSIONS_DIR"), 0));
            }
        }
        ensure_running(access.record)?;
        let cancelled = async {
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                if let Err(error) = ensure_running(access.record) {
                    break error;
                }
            }
        };
        let _permit = tokio::select! {
            permit = self.permits.acquire() => permit.map_err(|_|failure("DuckDB engine is shutting down",0))?,
            error = cancelled => return Err(error),
        };
        tokio::fs::create_dir_all(&self.work_dir)
            .await
            .map_err(|_| failure("Cannot create DuckDB work directory", 0))?;
        let work = self.work_dir.join(Uuid::new_v4().to_string());
        tokio::fs::create_dir(&work)
            .await
            .map_err(|_| failure("Cannot create private DuckDB query directory", 0))?;
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|_| failure("Cannot secure DuckDB query directory", 0))?;
        let result = match input {
            QueryInput::Simple(table, parsed) => self.query_in(&work, access, table, parsed).await,
            QueryInput::Sql(sql, database) => self.select_in(&work, access, sql, database).await,
        };
        let cleanup = tokio::fs::remove_dir_all(&work).await;
        match (result, cleanup) {
            (Ok(_), Err(_)) => Err(failure("Cannot clean DuckDB query directory", 0)),
            (result, _) => result,
        }
    }

    async fn query_in(
        &self,
        work: &Path,
        access: QueryAccess<'_>,
        table: &GlueTableOutput,
        parsed: &sql::ParsedQuery,
    ) -> Result<(QueryResult, u64), WorkerFailure> {
        let (metadata, metadata_body, manifest_list, scanned) = iceberg_snapshot_objects(
            access.registry,
            access.scope,
            access.caller,
            access.record,
            table,
            0,
        )
        .await?;
        let mut fields = match &parsed.projection {
            Projection::Columns(names) => names.clone(),
            Projection::Sum { column, .. } => vec![column.clone()],
            Projection::Count(_) => Vec::new(),
        };
        let projected = fields.len();
        for predicate in &parsed.predicates {
            if !fields.contains(&predicate.column) {
                fields.push(predicate.column.clone());
            }
        }
        let columns = iceberg_columns(&metadata, &fields, scanned)?;
        let mut mirror = SnapshotMirror::new(work, &metadata, scanned)?;
        let metadata_uri = table
            .parameters
            .get("metadata_location")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("Iceberg metadata_location is missing", scanned))?;
        let metadata_path = mirror.save(metadata_uri, metadata_body).await?;
        mirror
            .prepare(access, &metadata, manifest_list, &parsed.predicates)
            .await?;
        let (statement, output) = render(parsed, &columns, projected, &metadata_path)?;
        let script = self.script(work, &mirror.allowed_paths, &statement)?;
        let values = self
            .execute(work, &script, access.record, mirror.scanned)
            .await?;
        let mut rows = vec![output.iter().map(|c| Some(c.name.clone())).collect()];
        let values = values
            .as_array()
            .ok_or_else(|| failure("DuckDB returned an invalid result envelope", mirror.scanned))?;
        if values.len() > MAX_RESULT_ROWS {
            return Err(failure(
                "Query exceeded the 100000 row result limit",
                mirror.scanned,
            ));
        }
        for value in values {
            let mut row = Vec::with_capacity(output.len());
            for (index, column) in output.iter().enumerate() {
                let value = value
                    .get(format!("c{index}"))
                    .ok_or_else(|| failure("DuckDB result column is missing", mirror.scanned))?;
                row.push(
                    decode_value(column.kind, value)
                        .map_err(|reason| failure(reason, mirror.scanned))?,
                );
            }
            rows.push(row);
        }
        Ok((
            QueryResult {
                columns: output,
                rows,
            },
            mirror.scanned,
        ))
    }

    fn script(
        &self,
        work: &Path,
        allowed: &[PathBuf],
        statement: &str,
    ) -> Result<String, WorkerFailure> {
        let extension =
            |name: &str| sql_path(&self.extensions.join(format!("{name}.duckdb_extension")));
        let allowed = allowed
            .iter()
            .map(|p| sql_path(p))
            .collect::<Result<Vec<_>, _>>()?
            .join(",");
        Ok(format!(
            "SET threads=2; SET memory_limit='128MiB'; SET max_temp_directory_size='0B'; SET temp_directory=''; SET home_directory={home}; SET autoinstall_known_extensions=false; SET autoload_known_extensions=false;\nLOAD {avro}; LOAD {iceberg};\nSET allow_persistent_secrets=false;\nSET allowed_paths=[{allowed}]; SET enable_external_access=false; SET lock_configuration=true;\n{statement};\n",
            home=sql_path(work)?, avro=extension("avro")?, iceberg=extension("iceberg")?,
        ))
    }

    async fn execute(
        &self,
        work: &Path,
        script: &str,
        record: &Arc<Mutex<QueryRecord>>,
        scanned: u64,
    ) -> Result<Value, WorkerFailure> {
        ensure_running(record)?;
        let mut command = tokio::process::Command::new(&self.executable);
        command
            .args(["-no-init", "-bail", "-batch", "-json", ":memory:"])
            .env_clear()
            .current_dir(work)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        unsafe {
            command.pre_exec(|| {
                for (resource, limit) in [
                    (libc::RLIMIT_AS, 4 * 1024 * 1024 * 1024),
                    (libc::RLIMIT_CPU, 30),
                    (libc::RLIMIT_CORE, 0),
                    (libc::RLIMIT_NOFILE, 128),
                    (libc::RLIMIT_FSIZE, 64 * 1024 * 1024),
                ] {
                    let limits = libc::rlimit {
                        rlim_cur: limit,
                        rlim_max: limit,
                    };
                    if libc::setrlimit(resource, &limits) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|_| {
            failure(
                "DuckDB is unavailable; prepare the official CLI and signed Iceberg extensions",
                scanned,
            )
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| failure("DuckDB input pipe unavailable", scanned))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| failure("DuckDB output pipe unavailable", scanned))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| failure("DuckDB error pipe unavailable", scanned))?;
        let outcome = {
            let run = async {
                let write = async {
                    let mut stdin = stdin;
                    stdin.write_all(script.as_bytes()).await?;
                    stdin.shutdown().await
                };
                let out = async {
                    let mut bytes = Vec::new();
                    stdout
                        .take(MAX_RESULT_BYTES as u64 + 1)
                        .read_to_end(&mut bytes)
                        .await?;
                    Ok::<_, std::io::Error>(bytes)
                };
                let err = async {
                    let mut bytes = Vec::new();
                    stderr.take(8193).read_to_end(&mut bytes).await?;
                    Ok::<_, std::io::Error>(bytes)
                };
                let (write, out, err, status) = tokio::join!(write, out, err, child.wait());
                let out = out.map_err(|_| failure("DuckDB output unavailable", scanned))?;
                let err = err.map_err(|_| failure("DuckDB diagnostics unavailable", scanned))?;
                write.map_err(|_| failure("DuckDB input unavailable", scanned))?;
                if out.len() > MAX_RESULT_BYTES || err.len() > 8192 {
                    return Err(failure("DuckDB exceeded its output limit", scanned));
                }
                if !status
                    .map_err(|_| failure("DuckDB process failed", scanned))?
                    .success()
                {
                    let diagnostic = String::from_utf8_lossy(&err);
                    let reason = if diagnostic.contains("extension")
                        || diagnostic.contains("Extension")
                    {
                        "DuckDB could not load an extension; prepare official avro and iceberg extensions matching the CLI version and architecture in LOCALLYCLOUD_DUCKDB_EXTENSIONS_DIR"
                    } else if diagnostic.contains("Binder Error")
                        || diagnostic.contains("Parser Error")
                    {
                        "DuckDB could not bind or parse the SELECT; verify table names, columns, functions and SQL dialect"
                    } else {
                        "DuckDB Iceberg execution failed; verify snapshot and result type compatibility"
                    };
                    return Err(failure(reason, scanned));
                }
                serde_json::from_slice(&out)
                    .map_err(|_| failure("DuckDB returned invalid JSON", scanned))
            };
            let cancelled = async {
                loop {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    if let Err(error) = ensure_running(record) {
                        break error;
                    }
                }
            };
            tokio::select! {
                result = tokio::time::timeout(PROCESS_TIMEOUT, run) => result.unwrap_or_else(|_| Err(failure("DuckDB query timed out", scanned))),
                failure = cancelled => Err(failure),
            }
        };
        if outcome.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        outcome
    }
}

#[derive(Clone, Copy)]
pub(super) struct QueryAccess<'a> {
    pub registry: &'a Weak<ServiceRegistry>,
    pub scope: &'a Scope,
    pub caller: Option<&'a AthenaCaller>,
    pub record: &'a Arc<Mutex<QueryRecord>>,
}

struct SnapshotMirror<'a> {
    directory: &'a Path,
    root: S3Location,
    scanned: u64,
    paths: HashMap<String, PathBuf>,
    allowed_paths: Vec<PathBuf>,
    object_limit: usize,
    manifest_limit: usize,
    manifests: usize,
}

impl<'a> SnapshotMirror<'a> {
    fn new(directory: &'a Path, metadata: &Value, scanned: u64) -> Result<Self, WorkerFailure> {
        let root = parse_s3_location(
            metadata
                .get("location")
                .and_then(Value::as_str)
                .ok_or_else(|| failure("Iceberg table location is missing", scanned))?,
        )
        .map_err(|_| failure("Iceberg table location is invalid", scanned))?;
        Ok(Self {
            directory,
            root,
            scanned,
            paths: HashMap::new(),
            allowed_paths: Vec::new(),
            object_limit: MAX_MIRROR_OBJECTS,
            manifest_limit: MAX_MIRROR_MANIFESTS,
            manifests: 0,
        })
    }

    fn local_path(&self, uri: &str) -> Result<PathBuf, WorkerFailure> {
        let location = parse_s3_location(uri)
            .map_err(|_| failure("Iceberg object location is invalid", self.scanned))?;
        let prefix = self.root.key.trim_end_matches('/');
        let relative = if prefix.is_empty() {
            location.key.as_str()
        } else {
            location
                .key
                .strip_prefix(&format!("{prefix}/"))
                .ok_or_else(|| {
                    failure(
                        "Iceberg object lies outside the table location",
                        self.scanned,
                    )
                })?
        };
        if location.bucket != self.root.bucket
            || relative.is_empty()
            || relative.len() > 4096
            || relative.contains(['\\', '\0'])
            || relative
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
            || relative.to_ascii_lowercase().contains("%2f")
            || relative.to_ascii_lowercase().contains("%5c")
            || Path::new(relative)
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(failure(
                "Iceberg object cannot be safely mirrored",
                self.scanned,
            ));
        }
        Ok(self.directory.join("table").join(relative))
    }

    async fn save(&mut self, uri: &str, bytes: Bytes) -> Result<PathBuf, WorkerFailure> {
        if let Some(path) = self.paths.get(uri) {
            return Ok(path.clone());
        }
        if self.paths.len() >= self.object_limit {
            return Err(failure(
                "Iceberg snapshot exceeds the object limit",
                self.scanned,
            ));
        }
        let path = self.local_path(uri)?;
        if self.allowed_paths.iter().any(|existing| existing == &path) {
            return Err(failure(
                "Iceberg object paths collide in the private mirror",
                self.scanned,
            ));
        }
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|_| failure("Cannot create Iceberg mirror directory", self.scanned))?;
        }
        tokio::fs::write(&path, bytes)
            .await
            .map_err(|_| failure("Cannot write authorized Iceberg mirror", self.scanned))?;
        self.paths.insert(uri.to_owned(), path.clone());
        self.allowed_paths.push(path.clone());
        Ok(path)
    }

    async fn fetch(&mut self, access: QueryAccess<'_>, uri: &str) -> Result<Bytes, WorkerFailure> {
        self.local_path(uri)?;
        let location = parse_s3_location(uri)
            .map_err(|_| failure("Iceberg object location is invalid", self.scanned))?;
        ensure_running(access.record)?;
        let bytes = get_object(
            access.registry,
            access.scope,
            access.caller,
            &location.bucket,
            &location.key,
            self.scanned,
        )
        .await?;
        self.scanned = add_scan(access.record, self.scanned, bytes.len())?;
        self.save(uri, bytes.clone()).await?;
        Ok(bytes)
    }

    async fn prepare(
        &mut self,
        access: QueryAccess<'_>,
        metadata: &Value,
        manifest_list: Bytes,
        predicates: &[Predicate],
    ) -> Result<(), WorkerFailure> {
        if manifest_list.is_empty() {
            return Ok(());
        }
        let snapshot_id = metadata
            .get("current-snapshot-id")
            .and_then(Value::as_i64)
            .ok_or_else(|| failure("Iceberg snapshot is missing", self.scanned))?;
        let uri = metadata
            .get("snapshots")
            .and_then(Value::as_array)
            .and_then(|s| {
                s.iter()
                    .find(|s| s.get("snapshot-id").and_then(Value::as_i64) == Some(snapshot_id))
            })
            .and_then(|s| s.get("manifest-list"))
            .and_then(Value::as_str)
            .ok_or_else(|| failure("Iceberg manifest list is missing", self.scanned))?;
        self.save(uri, manifest_list.clone()).await?;
        let list = AvroReader::new(&manifest_list[..])
            .map_err(|_| failure("Iceberg manifest list Avro is invalid", self.scanned))?;
        let mut objects = HashSet::new();
        for (index, descriptor) in list.enumerate() {
            if index >= self.manifest_limit {
                return Err(failure(
                    "Iceberg snapshot exceeds the manifest limit",
                    self.scanned,
                ));
            }
            self.manifests += 1;
            let descriptor = descriptor
                .map_err(|_| failure("Iceberg manifest descriptor is invalid", self.scanned))?;
            let content = avro_integer(
                avro_field(&descriptor, "content", self.scanned)?,
                self.scanned,
            )?;
            if !matches!(content, 0 | 1) {
                return Err(failure(
                    "Iceberg manifest content is unsupported",
                    self.scanned,
                ));
            }
            let spec = avro_integer(
                avro_field(&descriptor, "partition_spec_id", self.scanned)?,
                self.scanned,
            )?;
            let partition = iceberg_partition(metadata, spec, self.scanned)?;
            let path = avro_string(
                avro_field(&descriptor, "manifest_path", self.scanned)?,
                self.scanned,
            )?;
            let bytes = self.fetch(access, path).await?;
            let manifest = AvroReader::new(&bytes[..])
                .map_err(|_| failure("Iceberg manifest Avro is invalid", self.scanned))?;
            for entry in manifest {
                let entry = entry
                    .map_err(|_| failure("Iceberg manifest entry is invalid", self.scanned))?;
                match avro_integer(avro_field(&entry, "status", self.scanned)?, self.scanned)? {
                    2 => continue,
                    0 | 1 => {}
                    _ => {
                        return Err(failure(
                            "Iceberg manifest entry status is invalid",
                            self.scanned,
                        ))
                    }
                }
                let file = avro_field(&entry, "data_file", self.scanned)?;
                if let Some(partition) = &partition {
                    let tuple = avro_field(file, "partition", self.scanned)?;
                    let value = partition.value(
                        avro_field(tuple, &partition.name, self.scanned)?,
                        self.scanned,
                    )?;
                    let mut result = QueryResult {
                        columns: vec![ResultColumn {
                            name: partition.source.clone(),
                            kind: partition.kind,
                        }],
                        rows: vec![vec![Some(partition.source.clone())], vec![value]],
                    };
                    let applicable = predicates
                        .iter()
                        .filter(|p| p.column == partition.source)
                        .map(|p| Predicate {
                            column: p.column.clone(),
                            operator: p.operator.clone(),
                            value: p.value.clone(),
                        })
                        .collect::<Vec<_>>();
                    apply_predicates(&mut result, &applicable)
                        .map_err(|reason| failure(reason, self.scanned))?;
                    if result.rows.len() == 1 {
                        continue;
                    }
                }
                let path = avro_string(avro_field(file, "file_path", self.scanned)?, self.scanned)?;
                if objects.insert(path.to_owned()) {
                    self.fetch(access, path).await?;
                }
            }
        }
        Ok(())
    }
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
fn sql_path(path: &Path) -> Result<String, WorkerFailure> {
    path.to_str()
        .map(sql_literal)
        .ok_or_else(|| failure("DuckDB paths must be UTF-8", 0))
}
fn failure(reason: impl Into<String>, scanned: u64) -> WorkerFailure {
    WorkerFailure::failed(reason, scanned)
}

fn decode_value(kind: &str, value: &Value) -> Result<Option<String>, &'static str> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) if matches!(kind, "timestamp" | "timestamptz") => {
            let micros = value
                .parse::<i64>()
                .map_err(|_| "DuckDB returned an invalid timestamp")?;
            time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1000)
                .map_err(|_| "DuckDB timestamp is out of range")?
                .format(&time::format_description::well_known::Rfc3339)
                .map(Some)
                .map_err(|_| "DuckDB timestamp formatting failed")
        }
        Value::String(value) => Ok(Some(value.clone())),
        _ => Err("DuckDB returned an invalid typed result"),
    }
}

fn snapshot_scan(path: &Path) -> Result<String, WorkerFailure> {
    let metadata_directory = path
        .parent()
        .filter(|parent| parent.file_name().is_some_and(|name| name == "metadata"))
        .ok_or_else(|| {
            failure(
                "DuckDB snapshot metadata must be in the table metadata directory",
                0,
            )
        })?;
    let table_root = metadata_directory
        .parent()
        .ok_or_else(|| failure("DuckDB snapshot table root is missing", 0))?;
    let version = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".metadata.json"))
        .filter(|version| !version.is_empty())
        .ok_or_else(|| {
            failure(
                "DuckDB snapshot metadata must have a .metadata.json suffix",
                0,
            )
        })?;
    Ok(format!("iceberg_scan({},version={},version_name_format='%s%s.metadata.json',allow_moved_paths=true)",
        sql_path(table_root)?, sql_literal(version)))
}

fn render(
    parsed: &sql::ParsedQuery,
    columns: &[ResultColumn],
    projected: usize,
    path: &Path,
) -> Result<(String, Vec<ResultColumn>), WorkerFailure> {
    let (select, output) = match &parsed.projection {
        Projection::Count(alias) => (
            "CAST(COUNT(*) AS VARCHAR) AS c0".into(),
            vec![ResultColumn {
                name: alias.clone(),
                kind: "bigint",
            }],
        ),
        Projection::Sum { column, alias } => {
            let column_kind = columns
                .first()
                .map(|c| c.kind)
                .ok_or_else(|| failure("SUM column missing", 0))?;
            if !matches!(column_kind, "integer" | "bigint" | "decimal(18,2)") {
                return Err(failure("SUM requires a numeric column", 0));
            }
            let kind = if column_kind == "decimal(18,2)" {
                "decimal(38,2)"
            } else {
                "bigint"
            };
            (
                format!(
                    "CAST(CAST(SUM({}) AS {kind}) AS VARCHAR) AS c0",
                    identifier(column)
                ),
                vec![ResultColumn {
                    name: alias.clone(),
                    kind,
                }],
            )
        }
        Projection::Columns(_) => (
            columns
                .iter()
                .take(projected)
                .enumerate()
                .map(|(i, c)| {
                    let column = identifier(&c.name);
                    let value = match c.kind {
                        "timestamp" | "timestamptz" => format!("epoch_us({column})"),
                        _ => column,
                    };
                    format!("CAST({value} AS VARCHAR) AS c{i}")
                })
                .collect::<Vec<_>>()
                .join(","),
            columns
                .iter()
                .take(projected)
                .map(|c| ResultColumn {
                    name: c.name.clone(),
                    kind: c.kind,
                })
                .collect(),
        ),
    };
    let mut query = format!("SELECT {select} FROM {}", snapshot_scan(path)?);
    if !parsed.predicates.is_empty() {
        let predicates = parsed
            .predicates
            .iter()
            .map(|p| {
                let kind = columns
                    .iter()
                    .find(|c| c.name == p.column)
                    .map(|c| c.kind)
                    .ok_or_else(|| failure("Predicate column missing", 0))?;
                if !matches!(
                    p.operator.as_str(),
                    "=" | "!=" | "<>" | "<" | ">" | "<=" | ">="
                ) {
                    return Err(failure("Unsupported predicate operator", 0));
                }
                Ok(format!(
                    "{} {} CAST({} AS {kind})",
                    identifier(&p.column),
                    p.operator,
                    sql_literal(&p.value)
                ))
            })
            .collect::<Result<Vec<_>, WorkerFailure>>()?;
        query.push_str(" WHERE ");
        query.push_str(&predicates.join(" AND "));
    }
    Ok((query, output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn real_cli_keeps_explicit_json_compatible_with_duckdb_1_5() {
        let Some(executable) = std::env::var_os("LOCALLYCLOUD_TEST_DUCKDB_BIN") else {
            eprintln!("Set LOCALLYCLOUD_TEST_DUCKDB_BIN to validate the real DuckDB CLI");
            return;
        };
        let work = std::env::temp_dir().join(format!("duckdb-cli-{}", Uuid::new_v4()));
        tokio::fs::create_dir(&work).await.unwrap();
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
        let record = Arc::new(Mutex::new(QueryRecord {
            id: "cli-compatibility".into(),
            spec: QuerySpec {
                query_string: "SELECT 1 AS ok".into(),
                context: None,
                result_configuration: ResultConfiguration {
                    output_location: "s3://results/cli/".into(),
                },
                work_group: None,
            },
            effective_output_location: S3Location {
                bucket: "results".into(),
                key: "cli/result.csv".into(),
            },
            state: QueryState::Running,
            submission_time: 0.0,
            completion_time: None,
            reason: None,
            scanned_bytes: 0,
            result: None,
            result_token: "cli-result".into(),
            caller: None,
        }));
        let engine = DuckDbEngine::new(executable.into(), work.join("extensions"), work.clone());
        let result = engine
            .execute(&work, "SET threads=2; SELECT 1 AS ok;\n", &record, 0)
            .await;
        tokio::fs::remove_dir_all(&work).await.unwrap();
        let result = match result {
            Ok(value) => value,
            Err(WorkerFailure::Failed { reason, .. }) => panic!("DuckDB CLI failed: {reason}"),
            Err(WorkerFailure::Cancelled) => panic!("DuckDB CLI fixture was cancelled"),
        };
        assert_eq!(result, serde_json::json!([{"ok": 1}]));
        eprintln!("Real DuckDB CLI: JSON compatibility passed");
    }

    #[test]
    fn trusted_ast_rendering_preserves_values_and_rejects_client_commands() {
        assert!(
            SqlParser::new("SELECT id FROM lake.events; SET enable_external_access=true")
                .parse()
                .is_err()
        );
        assert!(SqlParser::new("SELECT * FROM read_csv('/etc/passwd')")
            .parse()
            .is_err());
        let parsed = SqlParser::new(
            "SELECT id FROM lake.events WHERE payload = 'x''; COPY secrets TO ''/tmp/stolen'",
        )
        .parse()
        .unwrap();
        let columns = vec![
            ResultColumn {
                name: "id".into(),
                kind: "bigint",
            },
            ResultColumn {
                name: "payload".into(),
                kind: "varchar",
            },
        ];
        let (query, output) = render(
            &parsed,
            &columns,
            1,
            Path::new("/private/table/metadata/v1.metadata.json"),
        )
        .unwrap();
        assert_eq!(output.len(), 1);
        assert!(query.contains("iceberg_scan('/private/table',version='v1',version_name_format='%s%s.metadata.json',allow_moved_paths=true)"));
        assert!(query.contains("CAST('x''; COPY secrets TO ''/tmp/stolen' AS varchar)"));
        assert!(
            query.starts_with("SELECT CAST(\"id\" AS VARCHAR) AS c0 FROM iceberg_scan('/private/")
        );
    }

    #[test]
    fn aggregates_enforce_aws_width_and_timestamps_preserve_native_text() {
        let path = Path::new("/private/query/table/metadata/v1.metadata.json");
        for (input_kind, output_kind) in [
            ("integer", "bigint"),
            ("bigint", "bigint"),
            ("decimal(18,2)", "decimal(38,2)"),
        ] {
            let parsed = SqlParser::new("SELECT SUM(amount) AS total FROM lake.events")
                .parse()
                .unwrap();
            let columns = vec![ResultColumn {
                name: "amount".into(),
                kind: input_kind,
            }];
            let (query, output) = render(&parsed, &columns, 1, path).unwrap();
            assert!(query.contains(&format!("CAST(SUM(\"amount\") AS {output_kind})")));
            assert_eq!(output[0].kind, output_kind);
        }
        let parsed = SqlParser::new("SELECT happened_at FROM lake.events")
            .parse()
            .unwrap();
        let columns = vec![ResultColumn {
            name: "happened_at".into(),
            kind: "timestamp",
        }];
        let (query, _) = render(&parsed, &columns, 1, path).unwrap();
        assert!(query.contains("epoch_us(\"happened_at\")"));
        assert_eq!(
            decode_value("timestamp", &json!("1234567"))
                .unwrap()
                .as_deref(),
            Some("1970-01-01T00:00:01.234567Z")
        );
        assert_eq!(
            decode_value("timestamptz", &json!("-1"))
                .unwrap()
                .as_deref(),
            Some("1969-12-31T23:59:59.999999Z")
        );
        assert_eq!(decode_value("timestamp", &Value::Null).unwrap(), None);
        assert!(decode_value("timestamp", &json!("not-a-timestamp")).is_err());
        assert!(decode_value("bigint", &json!(9007199254740993_u64)).is_err());
    }

    #[test]
    fn mirror_confines_metadata_paths_and_engine_locks_external_access() {
        let directory = Path::new("/private/query");
        let metadata = json!({"location":"s3://lake/table"});
        let mirror = SnapshotMirror::new(directory, &metadata, 0).unwrap();
        assert_eq!(
            mirror.local_path("s3://lake/table/data/a.parquet").unwrap(),
            directory.join("table/data/a.parquet")
        );
        for uri in [
            "s3://foreign/table/data/a",
            "s3://lake/table/../secret",
            "s3://lake/table/%2fsecret",
            "s3://lake/table/data/../../secret",
            "file:///etc/passwd",
            "https://example.com/secret",
        ] {
            assert!(mirror.local_path(uri).is_err(), "{uri}");
        }
        let engine = DuckDbEngine::new(
            "/engine/duckdb".into(),
            "/engine/extensions".into(),
            directory.into(),
        );
        let script = engine
            .script(
                directory,
                &[directory.join("table/data/a.parquet")],
                "SELECT 'safe' AS c0",
            )
            .unwrap();
        assert!(script.contains("SET autoinstall_known_extensions=false"));
        assert!(script.contains("SET autoload_known_extensions=false"));
        assert!(script.contains("SET allow_persistent_secrets=false"));
        assert!(script.contains("SET enable_external_access=false; SET lock_configuration=true"));
        assert!(script.contains("LOAD '/engine/extensions/iceberg.duckdb_extension'"));
        assert!(!script.contains("INSTALL"));
    }
}
