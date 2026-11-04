//! Metadata extraction is an injected host capability; routing decisions are journaled before writes.
use super::*;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

const MAX_QUERY_BYTES: usize = 4096;
const MAX_ROUTING_BYTES: usize = 2 * 1024 * 1024;
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct RoutingConfiguration {
    pub query: Option<String>,
    pub append_only: bool,
    pub tables: Vec<DestinationTableConfiguration>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(super) struct ProcessingConfiguration {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub processors: Vec<Processor>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(super) struct Processor {
    #[serde(rename = "Type")]
    pub kind: String,
    #[serde(default)]
    pub parameters: Vec<ProcessorParameter>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(super) struct ProcessorParameter {
    pub parameter_name: String,
    pub parameter_value: String,
}

impl RoutingConfiguration {
    pub fn parse(
        processing: Option<&ProcessingConfiguration>,
        append_only: bool,
        tables: Vec<DestinationTableConfiguration>,
    ) -> Result<Option<Self>, FirehoseError> {
        let query = match processing.filter(|config| config.enabled) {
            None => None,
            Some(config) => {
                if config.processors.len() != 1 {
                    return Err(unsupported(
                        "Iceberg supports one MetadataExtraction processor",
                    ));
                }
                let processor = config.processors.first().ok_or(FirehoseError::Internal)?;
                if processor.kind != "MetadataExtraction" {
                    return Err(unsupported(
                        "Iceberg processing currently supports MetadataExtraction",
                    ));
                }
                let mut parameters = BTreeMap::new();
                for parameter in &processor.parameters {
                    if !matches!(
                        parameter.parameter_name.as_str(),
                        "MetadataExtractionQuery" | "JsonParsingEngine"
                    ) || parameters
                        .insert(
                            parameter.parameter_name.as_str(),
                            parameter.parameter_value.as_str(),
                        )
                        .is_some()
                    {
                        return Err(FirehoseError::InvalidArgument(
                            "MetadataExtraction parameters must be unique and supported".into(),
                        ));
                    }
                }
                if parameters.get("JsonParsingEngine") != Some(&"JQ-1.6") {
                    return Err(FirehoseError::InvalidArgument(
                        "MetadataExtraction requires JsonParsingEngine=JQ-1.6".into(),
                    ));
                }
                let query = parameters.get("MetadataExtractionQuery").ok_or_else(|| {
                    FirehoseError::InvalidArgument("MetadataExtractionQuery is required".into())
                })?;
                validate_query(query)?;
                Some((*query).to_owned())
            }
        };
        if query.is_none() && tables.len() != 1 {
            return Err(FirehoseError::InvalidArgument(
                "Multiple Iceberg tables require MetadataExtraction routing".into(),
            ));
        }
        if query.is_none()
            && append_only
            && tables
                .first()
                .is_some_and(|table| table.unique_keys.is_empty())
        {
            return Ok(None);
        }
        Ok(Some(Self {
            query,
            append_only,
            tables,
        }))
    }

    pub fn description(&self) -> Option<ProcessingConfiguration> {
        self.query.as_ref().map(|query| ProcessingConfiguration {
            enabled: true,
            processors: vec![Processor {
                kind: "MetadataExtraction".into(),
                parameters: vec![
                    ProcessorParameter {
                        parameter_name: "MetadataExtractionQuery".into(),
                        parameter_value: query.clone(),
                    },
                    ProcessorParameter {
                        parameter_name: "JsonParsingEngine".into(),
                        parameter_value: "JQ-1.6".into(),
                    },
                ],
            }],
        })
    }
}

fn validate_query(query: &str) -> Result<(), FirehoseError> {
    if query.is_empty() || query.len() > MAX_QUERY_BYTES || query.contains('\0') {
        return Err(FirehoseError::InvalidArgument(
            "MetadataExtractionQuery must contain 1-4096 bytes".into(),
        ));
    }
    // Capability validation is separate from jq parsing. Strings and comments do not
    // load modules, but interpolation switches back into executable jq expressions.
    if loads_host_module(query) {
        return Err(FirehoseError::InvalidArgument(
            "MetadataExtractionQuery cannot load host modules".into(),
        ));
    }
    Ok(())
}

fn loads_host_module(query: &str) -> bool {
    enum Context {
        Code(usize),
        String,
    }
    let bytes = query.as_bytes();
    let mut contexts = vec![Context::Code(0)];
    let mut index = 0;
    while index < bytes.len() {
        match contexts.last_mut() {
            Some(Context::String) => match bytes[index] {
                b'"' => {
                    contexts.pop();
                    index += 1;
                }
                b'\\' if bytes.get(index + 1) == Some(&b'(') => {
                    contexts.push(Context::Code(1));
                    index += 2;
                }
                b'\\' => index = (index + 2).min(bytes.len()),
                _ => index += 1,
            },
            Some(Context::Code(depth)) => match bytes[index] {
                b'#' => {
                    while index < bytes.len() && bytes[index] != b'\n' {
                        index += 1;
                    }
                }
                b'"' => {
                    contexts.push(Context::String);
                    index += 1;
                }
                b'(' if *depth > 0 => {
                    *depth += 1;
                    index += 1;
                }
                b')' if *depth > 0 => {
                    *depth -= 1;
                    if *depth == 0 {
                        contexts.pop();
                    }
                    index += 1;
                }
                byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                    let start = index;
                    index += 1;
                    while bytes
                        .get(index)
                        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                    {
                        index += 1;
                    }
                    if matches!(&query[start..index], "import" | "include" | "modulemeta") {
                        return true;
                    }
                }
                _ => index += 1,
            },
            None => return true,
        }
    }
    false
}

#[derive(Debug)]
pub(super) enum ExtractionError {
    Unavailable,
    Invalid,
    Limit,
}

#[async_trait]
pub(super) trait MetadataEvaluator: Send + Sync {
    async fn validate(&self, query: &str) -> Result<(), ExtractionError>;
    async fn extract(
        &self,
        query: &str,
        records: &[Vec<u8>],
    ) -> Result<Vec<Value>, ExtractionError>;
}

pub(super) struct JqEvaluator {
    executable: PathBuf,
    capacity: Arc<tokio::sync::Semaphore>,
}

impl Default for JqEvaluator {
    fn default() -> Self {
        Self {
            executable: PathBuf::from("/usr/bin/jq"),
            capacity: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }
}

impl JqEvaluator {
    #[cfg(test)]
    pub fn new(executable: PathBuf) -> Self {
        Self {
            executable,
            capacity: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }

    async fn execute(&self, program: &str, input: Vec<u8>) -> Result<Vec<u8>, ExtractionError> {
        let _permit = tokio::time::timeout(QUERY_TIMEOUT, self.capacity.acquire())
            .await
            .map_err(|_| ExtractionError::Limit)?
            .map_err(|_| ExtractionError::Unavailable)?;
        let mut command = tokio::process::Command::new(&self.executable);
        command
            .args([
                "--compact-output",
                "--slurp",
                "-L",
                "/dev/null",
                "--",
                program,
            ])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // SAFETY: only async-signal-safe setrlimit calls execute between fork and exec.
        unsafe {
            command.pre_exec(|| {
                for (resource, limit) in [
                    (libc::RLIMIT_AS, 256_u64 * 1024 * 1024),
                    (libc::RLIMIT_CPU, 2),
                    (libc::RLIMIT_FSIZE, 0),
                    (libc::RLIMIT_CORE, 0),
                    (libc::RLIMIT_NOFILE, 32),
                ] {
                    let limit = libc::rlimit {
                        rlim_cur: limit,
                        rlim_max: limit,
                    };
                    if libc::setrlimit(resource, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|_| ExtractionError::Unavailable)?;
        let mut stdin = child.stdin.take().ok_or(ExtractionError::Unavailable)?;
        let stdout = child.stdout.take().ok_or(ExtractionError::Unavailable)?;
        let stderr = child.stderr.take().ok_or(ExtractionError::Unavailable)?;
        let result = tokio::time::timeout(QUERY_TIMEOUT, async {
            tokio::try_join!(
                async move {
                    stdin.write_all(&input).await?;
                    stdin.shutdown().await
                },
                bounded_output(stdout, MAX_ROUTING_BYTES),
                bounded_output(stderr, 8192),
                child.wait(),
            )
        })
        .await;
        match result {
            Ok(Ok(((), output, _, status))) if status.success() => Ok(output),
            outcome => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                match outcome {
                    Ok(Ok(_)) => Err(ExtractionError::Invalid),
                    _ => Err(ExtractionError::Limit),
                }
            }
        }
    }
}

async fn bounded_output(reader: impl AsyncRead + Unpin, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = vec![];
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > limit {
        return Err(std::io::Error::other("jq output limit exceeded"));
    }
    Ok(bytes)
}

#[async_trait]
impl MetadataEvaluator for JqEvaluator {
    async fn validate(&self, query: &str) -> Result<(), ExtractionError> {
        validate_query(query).map_err(|_| ExtractionError::Invalid)?;
        self.execute(&format!("if false then ({query}) else null end"), vec![])
            .await
            .map(|_| ())
    }

    async fn extract(
        &self,
        query: &str,
        records: &[Vec<u8>],
    ) -> Result<Vec<Value>, ExtractionError> {
        validate_query(query).map_err(|_| ExtractionError::Invalid)?;
        let mut input = Vec::new();
        for record in records {
            input.extend(record);
            input.push(b'\n');
        }
        let output = self
            .execute(
                &format!(
                    "map(try ([({query})] | if length == 1 then .[0] else null end) catch null)"
                ),
                input,
            )
            .await?;
        let results: Vec<Value> =
            serde_json::from_slice(&output).map_err(|_| ExtractionError::Invalid)?;
        if results.len() != records.len() {
            return Err(ExtractionError::Invalid);
        }
        Ok(results)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Operation {
    Insert,
    Update,
    Delete,
}
impl Operation {
    fn parse(value: &Value) -> Option<Self> {
        match value.as_str().unwrap_or("insert") {
            "insert" if value.is_null() || value.is_string() => Some(Self::Insert),
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }
    pub fn iceberg(self) -> iceberg::WriteOperation {
        match self {
            Self::Insert => iceberg::WriteOperation::Insert,
            Self::Update => iceberg::WriteOperation::Update,
            Self::Delete => iceberg::WriteOperation::Delete,
        }
    }
}

pub(super) fn backup_token(token: Uuid, prefix: &str) -> Uuid {
    let mut hash = Sha256::new();
    hash.update(token.as_bytes());
    hash.update(b"backup\0");
    hash.update(prefix.as_bytes());
    let digest = hash.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(id)
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Group {
    pub table: usize,
    pub operation: Operation,
    pub token: Uuid,
    pub records: Vec<usize>,
    pub delivered: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Plan {
    pub groups: Vec<Group>,
    pub failed: Vec<usize>,
    pub record_count: usize,
}

impl Plan {
    pub fn build(
        config: &RoutingConfiguration,
        metadata: Vec<Value>,
        token: Uuid,
        record_count: usize,
    ) -> Self {
        let mut groups: BTreeMap<(usize, Operation), Vec<usize>> = BTreeMap::new();
        let mut failed = vec![];
        for (index, value) in metadata.into_iter().enumerate() {
            let selected = config.tables.iter().position(|table| {
                value.get("destinationDatabaseName").and_then(Value::as_str)
                    == Some(table.destination_database_name.as_str())
                    && value.get("destinationTableName").and_then(Value::as_str)
                        == Some(table.destination_table_name.as_str())
            });
            let operation = Operation::parse(&value["operation"]);
            match (selected, operation) {
                (Some(table), Some(operation)) if value.is_object() => {
                    groups.entry((table, operation)).or_default().push(index);
                }
                _ => failed.push(index),
            }
        }
        Self {
            groups: groups
                .into_iter()
                .map(|((table, operation), records)| {
                    let mut hash = Sha256::new();
                    hash.update(token.as_bytes());
                    hash.update(config.tables[table].destination_database_name.as_bytes());
                    hash.update([0]);
                    hash.update(config.tables[table].destination_table_name.as_bytes());
                    hash.update([0, operation as u8]);
                    let digest = hash.finalize();
                    let mut id = [0_u8; 16];
                    id.copy_from_slice(&digest[..16]);
                    Group {
                        table,
                        operation,
                        token: Uuid::from_bytes(id),
                        records,
                        delivered: false,
                    }
                })
                .collect(),
            failed,
            record_count,
        }
    }

    pub fn undelivered(&self) -> Vec<usize> {
        let mut records = self.failed.clone();
        records.extend(
            self.groups
                .iter()
                .filter(|group| !group.delivered)
                .flat_map(|group| group.records.iter().copied()),
        );
        records.sort_unstable();
        records
    }
}

impl Plan {
    fn validate(&self, config: &RoutingConfiguration, count: usize) -> bool {
        if self.record_count != count || self.groups.len() > count || self.failed.len() > count {
            return false;
        }
        let mut indices = self.failed.clone();
        let mut groups = std::collections::BTreeSet::new();
        for group in &self.groups {
            if group.table >= config.tables.len()
                || group.records.is_empty()
                || !groups.insert((group.table, group.operation))
            {
                return false;
            }
            indices.extend(&group.records);
        }
        indices.sort_unstable();
        indices.len() == count && indices.into_iter().eq(0..count)
    }
}

impl Inner {
    fn load_routing_plan(
        &self,
        stream: &StreamKey,
        token: Uuid,
    ) -> Result<Option<Plan>, FailureCode> {
        let key = (stream.clone(), token);
        if let Some(plan) = self
            .routing_plans
            .lock()
            .map_err(|_| FailureCode::InternalError)?
            .get(&key)
            .cloned()
        {
            return Ok(Some(plan));
        }
        let Some(state) = &self.state else {
            return Ok(None);
        };
        let plan = {
            use rusqlite::OptionalExtension;
            let connection = state.connection().map_err(|_| FailureCode::InternalError)?;
            let bytes: Option<String> = connection.query_row(
                "SELECT plan FROM firehose_routing_plans WHERE account=?1 AND region=?2 AND name=?3 AND token=?4",
                rusqlite::params![stream.scope.account_id,stream.scope.region,stream.name,token.to_string()],
                |row| row.get(0),
            ).optional().map_err(|_| FailureCode::InternalError)?;
            bytes
                .map(|bytes| {
                    if bytes.len() > MAX_ROUTING_BYTES {
                        return Err(FailureCode::InternalError);
                    }
                    serde_json::from_str::<Plan>(&bytes).map_err(|_| FailureCode::InternalError)
                })
                .transpose()?
        };
        if let Some(plan) = &plan {
            self.routing_plans
                .lock()
                .map_err(|_| FailureCode::InternalError)?
                .insert(key, plan.clone());
        }
        Ok(plan)
    }

    pub(super) fn pending_backup_bytes(&self, key: &StreamKey, stream: &DeliveryStream) -> usize {
        let all_bytes = || stream.retained.iter().map(Vec::len).sum();
        let Some(config) = &stream.destination.routing else {
            return all_bytes();
        };
        let Some(token) = stream.retry_token else {
            return all_bytes();
        };
        match self.load_routing_plan(key, token) {
            Ok(Some(plan)) if plan.validate(config, stream.retained.len()) => plan
                .undelivered()
                .into_iter()
                .filter_map(|index| stream.retained.get(index))
                .map(Vec::len)
                .sum(),
            Ok(None) => all_bytes(),
            // If the journal is unavailable/corrupt, never claim the size threshold was met.
            _ => 0,
        }
    }

    async fn remember_routing_plan(
        self: &Arc<Self>,
        batch: &Batch,
        plan: Plan,
    ) -> Result<(), FailureCode> {
        let inner = self.clone();
        let key = batch.key.clone();
        let token = batch.token;
        tokio::task::spawn_blocking(move || {
            if let Some(state) = &inner.state {
                let bytes = serde_json::to_string(&plan).map_err(|_| FailureCode::InternalError)?;
                if bytes.len() > MAX_ROUTING_BYTES { return Err(FailureCode::InternalError); }
                let connection = state.connection().map_err(|_| FailureCode::InternalError)?;
                connection.execute(
                    "INSERT INTO firehose_routing_plans(account,region,name,token,plan) VALUES(?1,?2,?3,?4,?5)
                     ON CONFLICT(account,region,name,token) DO UPDATE SET plan=excluded.plan",
                    rusqlite::params![key.scope.account_id,key.scope.region,key.name,token.to_string(),bytes],
                ).map_err(|_| FailureCode::InternalError)?;
            }
            inner.routing_plans.lock().map_err(|_| FailureCode::InternalError)?.insert((key,token),plan);
            Ok(())
        }).await.map_err(|_| FailureCode::InternalError)?
    }

    async fn routing_plan(
        self: &Arc<Self>,
        batch: &Batch,
        config: &RoutingConfiguration,
    ) -> Result<Plan, FailureCode> {
        let inner = self.clone();
        let lookup = batch.clone();
        let cached =
            tokio::task::spawn_blocking(move || inner.load_routing_plan(&lookup.key, lookup.token))
                .await
                .map_err(|_| FailureCode::InternalError)??;
        if let Some(plan) = cached {
            return if plan.validate(config, batch.records.len()) {
                Ok(plan)
            } else {
                Err(FailureCode::InternalError)
            };
        }
        let metadata = match &config.query {
            Some(query) => self
                .metadata_evaluator
                .extract(query, &batch.records)
                .await
                .map_err(|_| FailureCode::MetadataExtractionFailed)?,
            None => {
                let table = config.tables.first().ok_or(FailureCode::InternalError)?;
                vec![
                    json!({"destinationDatabaseName":table.destination_database_name,"destinationTableName":table.destination_table_name,"operation":"insert"});
                    batch.records.len()
                ]
            }
        };
        if metadata.len() != batch.records.len() {
            return Err(FailureCode::MetadataExtractionFailed);
        }
        let plan = Plan::build(config, metadata, batch.token, batch.records.len());
        self.remember_routing_plan(batch, plan.clone()).await?;
        Ok(plan)
    }

    pub(super) async fn deliver_routed_batch(
        self: &Arc<Self>,
        batch: &Batch,
        config: &RoutingConfiguration,
        dispatcher: &locallycloud_core::integration::InternalDispatcher,
    ) -> Result<(), FailureCode> {
        let mut plan = self.routing_plan(batch, config).await?;
        for index in 0..plan.groups.len() {
            let group = plan
                .groups
                .get(index)
                .cloned()
                .ok_or(FailureCode::InternalError)?;
            if group.delivered {
                continue;
            }
            let table = config
                .tables
                .get(group.table)
                .ok_or(FailureCode::InternalError)?;
            let target = iceberg::Target {
                database: table.destination_database_name.clone(),
                table: table.destination_table_name.clone(),
                bucket: batch.destination.bucket.clone(),
            };
            let records = group
                .records
                .iter()
                .map(|index| {
                    batch
                        .records
                        .get(*index)
                        .cloned()
                        .ok_or(FailureCode::InternalError)
                })
                .collect::<Result<Vec<_>, _>>()?;
            iceberg::write(
                iceberg::Context {
                    dispatcher,
                    account: &batch.key.scope.account_id,
                    region: &batch.key.scope.region,
                    bucket: &target.bucket,
                    role_arn: &batch.destination.role_arn,
                },
                &target,
                group.token,
                &records,
                group.operation.iceberg(),
                &table.unique_keys,
            )
            .await
            .map_err(FailureCode::from)?;
            plan.groups
                .get_mut(index)
                .ok_or(FailureCode::InternalError)?
                .delivered = true;
            self.remember_routing_plan(batch, plan.clone()).await?;
        }
        if plan.failed.is_empty() {
            Ok(())
        } else {
            Err(FailureCode::MetadataExtractionFailed)
        }
    }

    pub(super) async fn backup_groups(
        self: &Arc<Self>,
        batch: &Batch,
    ) -> Result<BTreeMap<String, Vec<usize>>, FailureCode> {
        let backup = batch
            .destination
            .error_backup
            .as_ref()
            .ok_or(FailureCode::InternalError)?;
        let Some(config) = &batch.destination.routing else {
            return Ok(BTreeMap::from([(
                backup.prefix.clone(),
                (0..batch.records.len()).collect(),
            )]));
        };
        let inner = self.clone();
        let lookup = batch.clone();
        let plan =
            tokio::task::spawn_blocking(move || inner.load_routing_plan(&lookup.key, lookup.token))
                .await
                .map_err(|_| FailureCode::InternalError)??;
        let Some(plan) = plan else {
            return Ok(BTreeMap::from([(
                backup
                    .global_prefix
                    .clone()
                    .unwrap_or_else(|| backup.prefix.clone()),
                (0..batch.records.len()).collect(),
            )]));
        };
        if !plan.validate(config, batch.records.len()) {
            return Err(FailureCode::InternalError);
        }
        let mut groups = BTreeMap::new();
        if !plan.failed.is_empty() {
            groups.insert(
                backup
                    .global_prefix
                    .clone()
                    .unwrap_or_else(|| backup.prefix.clone()),
                plan.failed,
            );
        }
        for group in plan.groups.into_iter().filter(|group| !group.delivered) {
            let table = config
                .tables
                .get(group.table)
                .ok_or(FailureCode::InternalError)?;
            let prefix = table
                .s3_error_output_prefix
                .as_ref()
                .or(backup.global_prefix.as_ref())
                .unwrap_or(&backup.prefix);
            groups
                .entry(prefix.clone())
                .or_insert_with(Vec::new)
                .extend(group.records);
        }
        for records in groups.values_mut() {
            records.sort_unstable();
        }
        Ok(groups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(name: &str) -> DestinationTableConfiguration {
        DestinationTableConfiguration {
            destination_database_name: "ledger".into(),
            destination_table_name: name.into(),
            unique_keys: vec!["id".into()],
            s3_error_output_prefix: Some(format!("errors/{name}/")),
            partition_spec: None,
        }
    }

    fn config() -> RoutingConfiguration {
        RoutingConfiguration { query:Some("{destinationDatabaseName:\"ledger\",destinationTableName:(if has(\"sap_status\") then \"sap\" else \"present\" end),operation:\"update\"}".into()),
            append_only:false,tables:vec![table("present"),table("sap")] }
    }

    #[test]
    fn capability_guard_allows_literals_but_checks_interpolation_and_code() {
        for query in [
            "include \"/tmp/secret\"; .",
            "import \"x\" as x; .",
            ".|modulemeta",
            "\"prefix \\(include \"x\"; .)\"",
            "\"prefix \\(\"nested \\(modulemeta)\")\"",
            "# harmless comment\ninclude \"x\"; .",
        ] {
            assert!(validate_query(query).is_err(), "{query}");
        }
        for query in [
            "{destinationTableName:\"include\"}",
            "# include is only a comment\n.",
            "\"escaped \\\\(include)\"",
            ".foo // \"import\"",
        ] {
            assert!(validate_query(query).is_ok(), "{query}");
        }
    }

    #[tokio::test]
    async fn real_jq_routes_both_branches_clears_environment_and_rejects_multiple_outputs() {
        if tokio::fs::metadata("/usr/bin/jq").await.is_err() {
            eprintln!("jq integration not executed: optional jq capability is not installed");
            return;
        }
        let evaluator = JqEvaluator::default();
        let config = config();
        let query = config.query.as_deref().unwrap();
        evaluator.validate(query).await.unwrap();
        let metadata = evaluator
            .extract(
                query,
                &[
                    br#"{"id":1}"#.to_vec(),
                    br#"{"id":2,"sap_status":"delivered"}"#.to_vec(),
                ],
            )
            .await
            .unwrap();
        assert_eq!(metadata[0]["destinationTableName"], "present");
        assert_eq!(metadata[1]["destinationTableName"], "sap");
        let environment = evaluator
            .extract("{environment:env}", &[b"{}".to_vec()])
            .await
            .unwrap();
        assert_eq!(environment, vec![json!({"environment":{}})]);
        let ambiguous = evaluator.extract("1,2", &[b"{}".to_vec()]).await.unwrap();
        assert_eq!(ambiguous, vec![Value::Null]);
        let failed = evaluator
            .extract("error(\"must remain private\")", &[b"{}".to_vec()])
            .await
            .unwrap();
        assert_eq!(failed, vec![Value::Null]);
        assert!(evaluator
            .extract("range(0;100000000)", &[b"{}".to_vec()])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn missing_jq_is_a_typed_capability_error() {
        let evaluator = JqEvaluator::new(PathBuf::from("/locallycloud-does-not-exist/jq"));
        assert!(matches!(
            evaluator.validate(".").await,
            Err(ExtractionError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn saturated_evaluator_waits_before_spawning_and_releases_cancelled_waiters() {
        let evaluator = JqEvaluator::new(PathBuf::from("/locallycloud-does-not-exist/jq"));
        let permits = evaluator.capacity.acquire_many(2).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), evaluator.validate("."))
                .await
                .is_err()
        );
        drop(permits);
        assert!(matches!(
            evaluator.validate(".").await,
            Err(ExtractionError::Unavailable)
        ));
        assert_eq!(evaluator.capacity.available_permits(), 2);
    }

    #[test]
    fn plans_keep_stable_group_tokens_and_partition_failures_without_duplicate_records() {
        let config = config();
        let token = Uuid::new_v4();
        let metadata = vec![
            json!({"destinationDatabaseName":"ledger","destinationTableName":"present","operation":"update"}),
            json!({"destinationDatabaseName":"ledger","destinationTableName":"sap","operation":"update"}),
            Value::Null,
        ];
        let mut append_hint = config.clone();
        append_hint.append_only = true;
        let hinted = Plan::build(&append_hint, metadata.clone(), token, 3);
        assert_eq!(hinted.failed, vec![2]);
        let mut plan = Plan::build(&config, metadata.clone(), token, 3);
        assert!(plan.validate(&config, 3));
        assert_eq!(plan.failed, vec![2]);
        let repeated = Plan::build(&config, metadata, token, 3);
        assert_eq!(
            plan.groups.iter().map(|g| g.token).collect::<Vec<_>>(),
            repeated.groups.iter().map(|g| g.token).collect::<Vec<_>>()
        );
        assert_ne!(plan.groups[0].token, plan.groups[1].token);
        plan.groups[0].delivered = true;
        assert_eq!(plan.undelivered(), vec![1, 2]);
        plan.groups[1].records.push(0);
        assert!(!plan.validate(&config, 3));
    }

    fn sample_stream(destination: DestinationConfig) -> DeliveryStream {
        DeliveryStream {
            source: None,
            generation: Uuid::new_v4(),
            created_at: 0.0,
            destination,
            role_caller: None,
            pending: VecDeque::new(),
            retained: VecDeque::new(),
            retry_token: None,
            in_flight: None,
            delivery_attempts: 0,
            retry_at: None,
            pending_since: None,
            retry_started: None,
            terminal_failure: false,
            phase: DeliveryPhase::Primary,
            backup_attempts: 0,
            backed_up_records: 0,
            primary_failure: FailureCode::InternalError,
            encryption: None,
        }
    }

    fn destination() -> DestinationConfig {
        DestinationConfig {
            role_arn: "arn:aws:iam::000000000000:role/firehose".into(),
            s3_role_arn: "arn:aws:iam::000000000000:role/firehose".into(),
            bucket_arn: "arn:aws:s3:::ledger".into(),
            bucket: "ledger".into(),
            prefix: "errors/".into(),
            iceberg: Some(iceberg::Target {
                database: "ledger".into(),
                table: "present".into(),
                bucket: "ledger".into(),
            }),
            routing: Some(config()),
            s3_buffering_hints: Some(BufferingHints {
                size_in_m_bs: Some(64),
                interval_in_seconds: Some(300),
            }),
            iceberg_delivery: Some(IcebergDeliveryPolicy::default()),
            error_backup: Some(ErrorBackup {
                prefix: "errors/present/".into(),
                global_prefix: Some("errors/global/".into()),
                table_prefix: Some("errors/present/".into()),
                logging: None,
            }),
            logging: None,
        }
    }

    #[tokio::test]
    async fn journal_survives_restart_and_backup_excludes_confirmed_table_groups() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../compatibility-tests/.work/firehose-routing")
            .join(Uuid::new_v4().to_string());
        tokio::fs::create_dir_all(&root).await.unwrap();
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
        let path = root.join("state.sqlite3");
        let state = Arc::new(StateDb::open(path.clone()).unwrap());
        let (handler, _) = FirehoseHandler::with_state(Weak::new(), state.clone()).unwrap();
        let key = StreamKey {
            scope: Scope {
                account_id: "000000000000".into(),
                region: "us-east-1".into(),
            },
            name: "routing".into(),
        };
        let stream = sample_stream(destination());
        handler.inner.persist_create(&key, &stream).unwrap();
        let batch = Batch {
            phase: DeliveryPhase::Primary,
            primary_failure: FailureCode::InternalError,
            key: key.clone(),
            generation: stream.generation,
            token: Uuid::new_v4(),
            destination: stream.destination.clone(),
            role_caller: None,
            records: vec![vec![0; 1024 * 1024], b"{}".to_vec(), b"{}".to_vec()],
        };
        let mut plan = Plan::build(
            &config(),
            vec![
                json!({"destinationDatabaseName":"ledger","destinationTableName":"present","operation":"update"}),
                json!({"destinationDatabaseName":"ledger","destinationTableName":"sap","operation":"update"}),
                Value::Null,
            ],
            batch.token,
            3,
        );
        plan.groups[0].delivered = true;
        handler
            .inner
            .remember_routing_plan(&batch, plan)
            .await
            .unwrap();
        drop(handler);
        drop(state);
        let reopened = Arc::new(StateDb::open(path.clone()).unwrap());
        let (restored, _) = FirehoseHandler::with_state(Weak::new(), reopened).unwrap();
        let plan = restored
            .inner
            .load_routing_plan(&batch.key, batch.token)
            .unwrap()
            .unwrap();
        assert!(plan.groups[0].delivered);
        let groups = restored.inner.backup_groups(&batch).await.unwrap();
        assert_eq!(groups.get("errors/global/"), Some(&vec![2]));
        assert_eq!(groups.get("errors/sap/"), Some(&vec![1]));
        assert!(!groups.contains_key("errors/present/"));
        let mut retained = sample_stream(batch.destination.clone());
        retained.retained = VecDeque::from(batch.records.clone());
        retained.retry_token = Some(batch.token);
        retained.destination.s3_buffering_hints = Some(BufferingHints {
            size_in_m_bs: Some(1),
            interval_in_seconds: Some(300),
        });
        let pending = restored.inner.pending_backup_bytes(&batch.key, &retained);
        assert_eq!(pending, 4);
        let now = Instant::now();
        retained.exhaust_primary_at(now, pending);
        assert_eq!(retained.delivery_delay(now), Some(Duration::from_secs(300)));
        drop(restored);
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[test]
    fn s3_backup_buffering_honors_interval_and_size_threshold() {
        let now = Instant::now();
        let mut stream = sample_stream(destination());
        stream.retained.push_back(b"{}".to_vec());
        let bytes = stream.retained.iter().map(Vec::len).sum();
        stream.exhaust_primary_at(now, bytes);
        assert_eq!(stream.delivery_delay(now), Some(Duration::from_secs(300)));
        assert_eq!(
            stream.delivery_delay(now + Duration::from_secs(300)),
            Some(Duration::ZERO)
        );
        stream.destination.s3_buffering_hints = Some(BufferingHints {
            size_in_m_bs: Some(1),
            interval_in_seconds: Some(300),
        });
        stream.retained = VecDeque::from([vec![0; 1024 * 1024]]);
        let bytes = stream.retained.iter().map(Vec::len).sum();
        stream.exhaust_primary_at(now, bytes);
        assert_eq!(stream.delivery_delay(now), Some(Duration::ZERO));
    }
}
