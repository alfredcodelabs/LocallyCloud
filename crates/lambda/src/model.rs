//! Lambda domain model and the region/account-scoped function store.

use crate::persistence::LambdaPersistence;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use dashmap::DashMap;
use locallycloud_ec2::LambdaNetworkLease;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::error::LambdaError;

/// AWS-supported runtime identifiers (see the Lambda spec resolution table). `go1.x` and
/// other deprecated/unknown runtimes are intentionally absent.
pub const SUPPORTED_RUNTIMES: &[&str] = &[
    "nodejs22.x",
    "nodejs20.x",
    "python3.13",
    "python3.12",
    "provided.al2023",
    "provided.al2",
];

/// Default function configuration values (resolution table).
pub const DEFAULT_TIMEOUT_SECS: u32 = 3;
pub const DEFAULT_MEMORY_MB: u32 = 128;
pub const DEFAULT_EPHEMERAL_MB: u32 = 512;

/// Valid configuration ranges (resolution table).
pub const MIN_MEMORY_MB: u32 = 128;
pub const MAX_MEMORY_MB: u32 = 10240;
pub const MIN_TIMEOUT_SECS: u32 = 1;
pub const MAX_TIMEOUT_SECS: u32 = 900;
pub const MIN_EPHEMERAL_MB: u32 = 512;
pub const MAX_EPHEMERAL_MB: u32 = 10240;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpcConfig {
    pub subnet_ids: Vec<String>,
    pub security_group_ids: Vec<String>,
    pub vpc_id: String,
    pub ipv6_allowed_for_dual_stack: bool,
    // Retains EC2 dependencies for $LATEST and every published version.
    #[serde(skip)]
    pub lease: Option<LambdaNetworkLease>,
}

impl VpcConfig {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "SubnetIds": self.subnet_ids,
            "SecurityGroupIds": self.security_group_ids,
            "VpcId": self.vpc_id,
            "Ipv6AllowedForDualStack": self.ipv6_allowed_for_dual_stack,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaFunction {
    pub function_name: String,
    pub function_arn: String,
    pub runtime: Option<String>,
    pub role: String,
    pub handler: Option<String>,
    pub package_type: String, // "Zip" | "Image"
    pub code_sha256: String,
    pub code_size: u64,
    pub description: String,
    pub timeout: u32,
    pub memory_size: u32,
    pub ephemeral_storage: u32,
    pub architectures: Vec<String>,
    pub environment: BTreeMap<String, String>,
    /// Ordered layer version ARNs mounted under /opt on cold start.
    pub layers: Vec<String>,
    pub version: String, // "$LATEST"
    pub last_modified: String,
    pub revision_id: String,
    pub state: String, // "Active"
    /// Raw Zip package bytes (inline `Code.ZipFile`), retained so the data plane can extract
    /// and execute the function. `None` for image packages or when set from a non-inline source.
    #[serde(with = "crate::persistence::optional_archive")]
    pub code_zip: Option<Vec<u8>>,
    /// `DeadLetterConfig.TargetArn` for asynchronous invocation failures, if configured.
    pub dead_letter_arn: Option<String>,
    pub vpc_config: Option<VpcConfig>,
}

impl LambdaFunction {
    /// The `FunctionConfiguration` JSON returned by control-plane operations.
    pub fn to_configuration_json(&self) -> serde_json::Value {
        let mut json = serde_json::json!({
            "FunctionName": self.function_name,
            "FunctionArn": self.function_arn,
            "Runtime": self.runtime,
            "Role": self.role,
            "Handler": self.handler,
            "PackageType": self.package_type,
            "CodeSha256": self.code_sha256,
            "CodeSize": self.code_size,
            "Description": self.description,
            "Timeout": self.timeout,
            "MemorySize": self.memory_size,
            "EphemeralStorage": { "Size": self.ephemeral_storage },
            "Architectures": self.architectures,
            "Environment": { "Variables": self.environment },
            "Layers": self.layers.iter().map(|arn| serde_json::json!({"Arn": arn})).collect::<Vec<_>>(),
            "Version": self.version,
            "LastModified": self.last_modified,
            "RevisionId": self.revision_id,
            "State": self.state,
        });
        if let Some(config) = &self.vpc_config {
            json["VpcConfig"] = config.to_json();
        }
        json
    }
}

/// Build a function ARN: `arn:aws:lambda:<region>:<account>:function:<name>`.
pub fn function_arn(region: &str, account_id: &str, name: &str) -> String {
    format!("arn:aws:lambda:{region}:{account_id}:function:{name}")
}

/// Synthesize the deterministic Function URL host id (32 lowercase hex chars) from the
/// unqualified function ARN, so the URL is stable across calls.
pub fn function_url_id(function_arn: &str) -> String {
    let digest = Sha256::digest(function_arn.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    hex[..32].to_string()
}

/// Whether the runtime identifier is currently supported.
pub fn is_supported_runtime(runtime: &str) -> bool {
    SUPPORTED_RUNTIMES.contains(&runtime)
}

/// Resolve a function reference (a bare name, a partial ARN `account:function:name`, or a
/// full ARN `arn:aws:lambda:region:account:function:name[:qualifier]`) to its canonical
/// short name. A full ARN whose region differs from the request region is rejected. Any
/// qualifier suffix is ignored (control-plane operations target the function).
pub fn resolve_function_name(reference: &str, region: &str) -> Result<String, LambdaError> {
    let parts: Vec<&str> = reference.split(':').collect();
    if let Some(pos) = parts.iter().position(|&p| p == "function") {
        if reference.starts_with("arn:") {
            // arn : aws : lambda : <region> : <account> : function : <name> [: qualifier]
            if parts.len() < 7 {
                return Err(LambdaError::InvalidParameterValue(format!(
                    "invalid function ARN: {reference}"
                )));
            }
            if parts[3] != region {
                return Err(LambdaError::InvalidParameterValue(format!(
                    "function ARN region {} does not match request region {region}",
                    parts[3]
                )));
            }
        }
        return parts
            .get(pos + 1)
            .copied()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                LambdaError::InvalidParameterValue(format!("missing function name in {reference}"))
            });
    }
    // Bare name, with an optional `:qualifier` suffix.
    let name = parts[0];
    if name.is_empty() {
        return Err(LambdaError::InvalidParameterValue(
            "function name is empty".into(),
        ));
    }
    Ok(name.to_string())
}

/// Decode an inline base64 zip package and compute its `CodeSha256` (base64-encoded
/// SHA-256 of the package bytes) and size.
pub fn compute_zip_code(zip_base64: &str) -> Result<(String, u64), LambdaError> {
    let bytes = BASE64.decode(zip_base64.as_bytes()).map_err(|_| {
        LambdaError::InvalidParameterValue("Code.ZipFile is not valid base64".into())
    })?;
    crate::code_store::validate_zip(&bytes)?;
    let digest = Sha256::digest(&bytes);
    Ok((BASE64.encode(digest), bytes.len() as u64))
}

/// Decode an inline base64 zip package to its raw bytes (for the data plane to execute).
pub fn decode_inline_zip(zip_base64: &str) -> Option<Vec<u8>> {
    BASE64.decode(zip_base64.as_bytes()).ok()
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FunctionKey {
    pub account_id: String,
    pub region: String,
    pub name: String,
}

/// A function alias pointing at a published version (or `$LATEST`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alias {
    pub name: String,
    pub function_version: String,
    pub description: String,
    pub revision_id: String,
}

impl Alias {
    /// `AliasArn` is the unqualified function ARN plus `:<alias-name>`.
    pub fn to_json(&self, function_base_arn: &str) -> serde_json::Value {
        serde_json::json!({
            "AliasArn": format!("{function_base_arn}:{}", self.name),
            "Name": self.name,
            "FunctionVersion": self.function_version,
            "Description": self.description,
            "RevisionId": self.revision_id,
        })
    }
}

/// Reserved-concurrency / URL / event-invoke configuration is faithfully echoed back, so we
/// keep the parsed values on the function record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionUrlConfig {
    pub function_url: String,
    pub auth_type: String,
    pub invoke_mode: String,
    pub cors: Option<serde_json::Value>,
    pub creation_time: String,
    pub last_modified_time: String,
}

impl FunctionUrlConfig {
    /// The shared URL config response shape (`Create`/`Get`/`Update`).
    pub fn to_json(&self, function_arn: &str) -> serde_json::Value {
        serde_json::json!({
            "FunctionUrl": self.function_url,
            "FunctionArn": function_arn,
            "AuthType": self.auth_type,
            "InvokeMode": self.invoke_mode,
            "Cors": self.cors,
            "CreationTime": self.creation_time,
            "LastModifiedTime": self.last_modified_time,
        })
    }
}

/// Per-function asynchronous-invocation configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventInvokeConfig {
    pub maximum_retry_attempts: Option<u32>,
    pub maximum_event_age_in_seconds: Option<u32>,
    pub destination_config: Option<serde_json::Value>,
    pub last_modified: String,
}

impl EventInvokeConfig {
    /// The shared event-invoke config response shape.
    pub fn to_json(&self, function_arn: &str) -> serde_json::Value {
        serde_json::json!({
            "LastModified": self.last_modified,
            "FunctionArn": function_arn,
            "MaximumRetryAttempts": self.maximum_retry_attempts,
            "MaximumEventAgeInSeconds": self.maximum_event_age_in_seconds,
            "DestinationConfig": self.destination_config,
        })
    }
}

/// Per-qualifier provisioned-concurrency configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionedConfig {
    pub requested: u32,
    pub last_modified: String,
}

impl ProvisionedConfig {
    /// The shared response shape. Provisioning is instantaneous in the emulator, so allocated
    /// and available equal the requested amount and the status is `READY`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "RequestedProvisionedConcurrentExecutions": self.requested,
            "AvailableProvisionedConcurrentExecutions": self.requested,
            "AllocatedProvisionedConcurrentExecutions": self.requested,
            "Status": "READY",
            "LastModified": self.last_modified,
        })
    }
}

/// All state for one function name in a scope: the mutable `$LATEST`, immutable published
/// versions, aliases, tags, and the reserved-concurrency / URL / event-invoke configs.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct FunctionRecord {
    latest: LambdaFunction,
    versions: BTreeMap<u64, LambdaFunction>,
    next_version: u64,
    aliases: BTreeMap<String, Alias>,
    tags: BTreeMap<String, String>,
    reserved_concurrent_executions: Option<u32>,
    url_config: Option<FunctionUrlConfig>,
    event_invoke_config: Option<EventInvokeConfig>,
    provisioned: BTreeMap<String, ProvisionedConfig>,
    policy: BTreeMap<String, serde_json::Value>,
}

/// Region/account-scoped function store. No unsynchronized global mutable state.
#[derive(Default)]
pub struct FunctionStore {
    pub(crate) records: DashMap<FunctionKey, FunctionRecord>,
    pub(crate) persistence: Mutex<Option<Arc<LambdaPersistence>>>,
}

impl FunctionStore {
    pub(crate) fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        Ok(self
            .records
            .iter()
            .filter(|e| e.key().account_id == account)
            .map(|e| e.key().region.clone())
            .collect())
    }

    pub(crate) fn function_scopes(&self) -> Vec<(String, String, String)> {
        self.records
            .iter()
            .map(|entry| {
                (
                    entry.key().account_id.clone(),
                    entry.key().region.clone(),
                    entry.key().name.clone(),
                )
            })
            .collect()
    }
    pub(crate) fn restore_network_leases(&self, ec2: &locallycloud_ec2::Ec2Handler) {
        for mut entry in self.records.iter_mut() {
            let key = entry.key().clone();
            let record = entry.value_mut();
            for function in std::iter::once(&mut record.latest).chain(record.versions.values_mut())
            {
                if let Some(config) = &mut function.vpc_config {
                    config.lease = ec2.network_selection_lease(
                        &key.account_id,
                        &key.region,
                        &config.subnet_ids,
                        &config.security_group_ids,
                    );
                }
            }
        }
    }

    pub fn new() -> Self {
        Self::default()
    }

    fn key(account_id: &str, region: &str, name: &str) -> FunctionKey {
        FunctionKey {
            account_id: account_id.into(),
            region: region.into(),
            name: name.into(),
        }
    }

    /// Insert a new function, failing if the name already exists in this scope.
    pub fn create(
        &self,
        account_id: &str,
        region: &str,
        func: LambdaFunction,
    ) -> Result<(), LambdaError> {
        let key = Self::key(account_id, region, &func.function_name);
        use dashmap::mapref::entry::Entry;
        match self.records.entry(key) {
            Entry::Occupied(_) => Err(LambdaError::ResourceConflict(format!(
                "Function already exist: {}",
                func.function_name
            ))),
            Entry::Vacant(v) => {
                v.insert(FunctionRecord {
                    latest: func,
                    versions: BTreeMap::new(),
                    next_version: 1,
                    aliases: BTreeMap::new(),
                    tags: BTreeMap::new(),
                    reserved_concurrent_executions: None,
                    url_config: None,
                    event_invoke_config: None,
                    provisioned: BTreeMap::new(),
                    policy: BTreeMap::new(),
                });
                Ok(())
            }
        }
    }

    /// The `$LATEST` view of a function.
    pub fn get(&self, account_id: &str, region: &str, name: &str) -> Option<LambdaFunction> {
        self.records
            .get(&Self::key(account_id, region, name))
            .map(|r| r.latest.clone())
    }

    /// Check an execution snapshot without cloning its code archive.
    pub(crate) fn execution_snapshot_exists(
        &self,
        account_id: &str,
        region: &str,
        function: &LambdaFunction,
    ) -> bool {
        self.records
            .get(&Self::key(account_id, region, &function.function_name))
            .is_some_and(|record| {
                let current = if function.version == "$LATEST" {
                    Some(&record.latest)
                } else {
                    function
                        .version
                        .parse::<u64>()
                        .ok()
                        .and_then(|version| record.versions.get(&version))
                };
                current.is_some_and(|current| current.revision_id == function.revision_id)
            })
    }

    /// A specific published version's function snapshot.
    pub fn get_version(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        version: u64,
    ) -> Option<LambdaFunction> {
        self.records
            .get(&Self::key(account_id, region, name))
            .and_then(|r| r.versions.get(&version).cloned())
    }

    pub fn delete(&self, account_id: &str, region: &str, name: &str) -> Result<bool, LambdaError> {
        use dashmap::mapref::entry::Entry;
        let key = Self::key(account_id, region, name);
        match self.records.entry(key) {
            Entry::Vacant(_) => Ok(false),
            Entry::Occupied(entry) => {
                if let Some(persistence) = self.persistence.lock().unwrap().as_ref() {
                    persistence.delete_function(account_id, region, name)?;
                }
                entry.remove();
                Ok(true)
            }
        }
    }

    /// Mutate `$LATEST` in place, returning the updated clone, or `None` if absent.
    pub fn update<F: FnOnce(&mut LambdaFunction)>(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        mutate: F,
    ) -> Option<LambdaFunction> {
        let mut record = self.records.get_mut(&Self::key(account_id, region, name))?;
        mutate(&mut record.latest);
        Some(record.latest.clone())
    }

    /// All functions (their `$LATEST`) in the scope, sorted by name.
    pub fn list(&self, account_id: &str, region: &str) -> Vec<LambdaFunction> {
        let mut out: Vec<LambdaFunction> = self
            .records
            .iter()
            .filter(|e| e.key().account_id == account_id && e.key().region == region)
            .map(|e| e.value().latest.clone())
            .collect();
        out.sort_by(|a, b| a.function_name.cmp(&b.function_name));
        out
    }

    /// Publish an immutable version snapshot of `$LATEST`, returning the published version.
    pub fn publish_version(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
    ) -> Option<LambdaFunction> {
        let mut record = self.records.get_mut(&Self::key(account_id, region, name))?;
        let version = record.next_version;
        record.next_version += 1;
        let mut published = record.latest.clone();
        published.function_arn = format!("{}:{version}", record.latest.function_arn);
        published.version = version.to_string();
        record.versions.insert(version, published.clone());
        Some(published)
    }

    /// `$LATEST` followed by all published versions in ascending order.
    pub fn list_versions(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
    ) -> Option<Vec<LambdaFunction>> {
        let record = self.records.get(&Self::key(account_id, region, name))?;
        let mut out = vec![record.latest.clone()];
        out.extend(record.versions.values().cloned());
        Some(out)
    }

    /// Whether a version label (`$LATEST` or a published number) exists for the function.
    pub fn version_exists(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        version: &str,
    ) -> bool {
        if version == "$LATEST" {
            return self
                .records
                .contains_key(&Self::key(account_id, region, name));
        }
        match self.records.get(&Self::key(account_id, region, name)) {
            Some(record) => version
                .parse::<u64>()
                .map(|v| record.versions.contains_key(&v))
                .unwrap_or(false),
            None => false,
        }
    }

    pub fn get_alias(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        alias: &str,
    ) -> Option<Alias> {
        self.records
            .get(&Self::key(account_id, region, name))
            .and_then(|r| r.aliases.get(alias).cloned())
    }

    /// Insert or replace an alias. Returns `false` if the function does not exist.
    pub fn put_alias(&self, account_id: &str, region: &str, name: &str, alias: Alias) -> bool {
        match self.records.get_mut(&Self::key(account_id, region, name)) {
            Some(mut record) => {
                record.aliases.insert(alias.name.clone(), alias);
                true
            }
            None => false,
        }
    }

    pub fn delete_alias(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        alias: &str,
    ) -> Option<Alias> {
        self.records
            .get_mut(&Self::key(account_id, region, name))
            .and_then(|mut r| r.aliases.remove(alias))
    }

    pub fn list_aliases(&self, account_id: &str, region: &str, name: &str) -> Option<Vec<Alias>> {
        self.records
            .get(&Self::key(account_id, region, name))
            .map(|r| r.aliases.values().cloned().collect())
    }

    /// The unqualified function ARN, used to build alias ARNs.
    pub fn function_base_arn(&self, account_id: &str, region: &str, name: &str) -> Option<String> {
        self.records
            .get(&Self::key(account_id, region, name))
            .map(|r| r.latest.function_arn.clone())
    }

    /// Add a resource-policy statement. Duplicate statement ids are rejected.
    pub fn add_permission(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        statement_id: &str,
        statement: serde_json::Value,
    ) -> Result<bool, LambdaError> {
        let Some(mut record) = self.records.get_mut(&Self::key(account_id, region, name)) else {
            return Ok(false);
        };
        if record.policy.contains_key(statement_id) {
            return Err(LambdaError::ResourceConflict(format!(
                "The statement id ({statement_id}) provided already exists"
            )));
        }
        record.policy.insert(statement_id.to_string(), statement);
        Ok(true)
    }

    pub fn permissions(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
    ) -> Option<Vec<serde_json::Value>> {
        self.records
            .get(&Self::key(account_id, region, name))
            .map(|record| record.policy.values().cloned().collect())
    }

    pub fn remove_permission(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        statement_id: &str,
    ) -> Option<bool> {
        self.records
            .get_mut(&Self::key(account_id, region, name))
            .map(|mut record| record.policy.remove(statement_id).is_some())
    }

    /// Merge tags into the function. Returns `false` if the function does not exist.
    pub fn set_tags(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        tags: BTreeMap<String, String>,
    ) -> bool {
        match self.records.get_mut(&Self::key(account_id, region, name)) {
            Some(mut record) => {
                record.tags.extend(tags);
                true
            }
            None => false,
        }
    }

    /// Remove the named tag keys. Returns `false` if the function does not exist.
    pub fn remove_tags(&self, account_id: &str, region: &str, name: &str, keys: &[String]) -> bool {
        match self.records.get_mut(&Self::key(account_id, region, name)) {
            Some(mut record) => {
                for k in keys {
                    record.tags.remove(k);
                }
                true
            }
            None => false,
        }
    }

    pub fn get_tags(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
    ) -> Option<BTreeMap<String, String>> {
        self.records
            .get(&Self::key(account_id, region, name))
            .map(|r| r.tags.clone())
    }

    // ---- Reserved concurrency ----

    /// Set the reserved concurrent executions. Returns `false` if the function is absent.
    pub fn set_reserved_concurrency(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        value: u32,
    ) -> bool {
        match self.records.get_mut(&Self::key(account_id, region, name)) {
            Some(mut record) => {
                record.reserved_concurrent_executions = Some(value);
                true
            }
            None => false,
        }
    }

    /// Read the reserved concurrent executions. Outer `None` means the function is absent;
    /// inner `None` means it exists but no reservation is set.
    pub fn get_reserved_concurrency(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
    ) -> Option<Option<u32>> {
        self.records
            .get(&Self::key(account_id, region, name))
            .map(|r| r.reserved_concurrent_executions)
    }

    /// Clear the reserved concurrent executions. Returns `false` if the function is absent.
    pub fn delete_reserved_concurrency(&self, account_id: &str, region: &str, name: &str) -> bool {
        match self.records.get_mut(&Self::key(account_id, region, name)) {
            Some(mut record) => {
                record.reserved_concurrent_executions = None;
                true
            }
            None => false,
        }
    }

    // ---- Function URL config ----

    /// Read the URL config. `None` if the function or its URL config is absent.
    pub fn get_url_config(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
    ) -> Option<FunctionUrlConfig> {
        self.records
            .get(&Self::key(account_id, region, name))
            .and_then(|r| r.url_config.clone())
    }

    /// Insert or replace the URL config. Returns `false` if the function is absent.
    pub fn set_url_config(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        config: FunctionUrlConfig,
    ) -> bool {
        match self.records.get_mut(&Self::key(account_id, region, name)) {
            Some(mut record) => {
                record.url_config = Some(config);
                true
            }
            None => false,
        }
    }

    /// Remove the URL config. Returns `true` only if a URL config was present.
    pub fn delete_url_config(&self, account_id: &str, region: &str, name: &str) -> bool {
        match self.records.get_mut(&Self::key(account_id, region, name)) {
            Some(mut record) => record.url_config.take().is_some(),
            None => false,
        }
    }

    // ---- Event-invoke config ----

    /// Read the event-invoke config. `None` if the function or its config is absent.
    pub fn get_event_invoke_config(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
    ) -> Option<EventInvokeConfig> {
        self.records
            .get(&Self::key(account_id, region, name))
            .and_then(|r| r.event_invoke_config.clone())
    }

    /// Insert or replace the event-invoke config. Returns `false` if the function is absent.
    pub fn set_event_invoke_config(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        config: EventInvokeConfig,
    ) -> bool {
        match self.records.get_mut(&Self::key(account_id, region, name)) {
            Some(mut record) => {
                record.event_invoke_config = Some(config);
                true
            }
            None => false,
        }
    }

    /// Remove the event-invoke config. Returns `true` only if a config was present.
    pub fn delete_event_invoke_config(&self, account_id: &str, region: &str, name: &str) -> bool {
        match self.records.get_mut(&Self::key(account_id, region, name)) {
            Some(mut record) => record.event_invoke_config.take().is_some(),
            None => false,
        }
    }

    // ---- Provisioned concurrency (per qualifier) ----

    /// Set the provisioned config for a qualifier. Returns `false` if the function is absent.
    pub fn set_provisioned(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        qualifier: &str,
        config: ProvisionedConfig,
    ) -> bool {
        match self.records.get_mut(&Self::key(account_id, region, name)) {
            Some(mut record) => {
                record.provisioned.insert(qualifier.to_string(), config);
                true
            }
            None => false,
        }
    }

    pub fn get_provisioned(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        qualifier: &str,
    ) -> Option<ProvisionedConfig> {
        self.records
            .get(&Self::key(account_id, region, name))
            .and_then(|r| r.provisioned.get(qualifier).cloned())
    }

    /// Remove a qualifier's provisioned config. Returns `true` only if one was present.
    pub fn delete_provisioned(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        qualifier: &str,
    ) -> bool {
        match self.records.get_mut(&Self::key(account_id, region, name)) {
            Some(mut record) => record.provisioned.remove(qualifier).is_some(),
            None => false,
        }
    }

    /// All provisioned configs for a function (qualifier + config), or `None` if absent.
    pub fn list_provisioned(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
    ) -> Option<Vec<(String, ProvisionedConfig)>> {
        self.records
            .get(&Self::key(account_id, region, name))
            .map(|r| {
                r.provisioned
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
    }
}

/// A published layer version snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerVersion {
    pub version: u64,
    pub description: String,
    pub created_date: String,
    pub code_sha256: String,
    pub code_size: u64,
    /// Published ZIP payload retained for execution.
    #[serde(with = "crate::persistence::archive")]
    pub code_zip: Vec<u8>,
    pub compatible_runtimes: Vec<String>,
    pub compatible_architectures: Vec<String>,
}

/// Build a layer ARN: `arn:aws:lambda:<region>:<account>:layer:<name>`.
pub fn layer_arn(region: &str, account_id: &str, name: &str) -> String {
    format!("arn:aws:lambda:{region}:{account_id}:layer:{name}")
}

impl LayerVersion {
    /// The `LayerVersionArn`: the layer ARN plus `:<version>`.
    pub fn version_arn(&self, region: &str, account_id: &str, name: &str) -> String {
        format!("{}:{}", layer_arn(region, account_id, name), self.version)
    }

    /// The version detail shape (no `Content`) used by list responses and as a sub-object.
    pub fn detail_json(&self, region: &str, account_id: &str, name: &str) -> serde_json::Value {
        serde_json::json!({
            "LayerVersionArn": self.version_arn(region, account_id, name),
            "Version": self.version,
            "Description": self.description,
            "CreatedDate": self.created_date,
            "CompatibleRuntimes": self.compatible_runtimes,
            "CompatibleArchitectures": self.compatible_architectures,
        })
    }

    /// The full layer-version response (`PublishLayerVersion`/`GetLayerVersion`) including
    /// the `Content` block and `LayerArn`.
    pub fn to_json(&self, region: &str, account_id: &str, name: &str) -> serde_json::Value {
        serde_json::json!({
            "Content": {
                "CodeSha256": self.code_sha256,
                "CodeSize": self.code_size,
                "Location": format!("{}/code", self.version_arn(region, account_id, name)),
            },
            "LayerArn": layer_arn(region, account_id, name),
            "LayerVersionArn": self.version_arn(region, account_id, name),
            "Description": self.description,
            "CreatedDate": self.created_date,
            "Version": self.version,
            "CompatibleRuntimes": self.compatible_runtimes,
            "CompatibleArchitectures": self.compatible_architectures,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct LayerKey {
    pub(crate) account_id: String,
    pub(crate) region: String,
    pub(crate) name: String,
}

/// All published versions for one layer name in a scope.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LayerRecord {
    next_version: u64,
    /// Versions visible through the Lambda control plane.
    versions: BTreeMap<u64, LayerVersion>,
    /// Deleted versions retained for functions already configured with their ARNs.
    retained_versions: BTreeMap<u64, LayerVersion>,
}

/// Account/region-scoped layer store, independent of the function store.
#[derive(Default)]
pub struct LayerStore {
    pub(crate) records: DashMap<LayerKey, LayerRecord>,
}

impl LayerStore {
    pub(crate) fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        Ok(self
            .records
            .iter()
            .filter(|e| e.key().account_id == account && !e.value().versions.is_empty())
            .map(|e| e.key().region.clone())
            .collect())
    }

    pub fn new() -> Self {
        LayerStore {
            records: DashMap::new(),
        }
    }

    fn key(account_id: &str, region: &str, name: &str) -> LayerKey {
        LayerKey {
            account_id: account_id.into(),
            region: region.into(),
            name: name.into(),
        }
    }

    /// Publish the next version for a layer name, creating the layer if needed. The
    /// `version` field of `layer_version` is assigned by the store.
    pub fn publish(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        mut layer_version: LayerVersion,
    ) -> LayerVersion {
        let mut record = self
            .records
            .entry(Self::key(account_id, region, name))
            .or_insert_with(|| LayerRecord {
                next_version: 1,
                versions: BTreeMap::new(),
                retained_versions: BTreeMap::new(),
            });
        let version = record.next_version;
        record.next_version += 1;
        layer_version.version = version;
        record.versions.insert(version, layer_version.clone());
        layer_version
    }

    pub fn get_version(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        version: u64,
    ) -> Option<LayerVersion> {
        self.records
            .get(&Self::key(account_id, region, name))
            .and_then(|r| r.versions.get(&version).cloned())
    }

    /// Resolve a layer attached to an existing function, including a version since deleted
    /// from the public control plane. New attachments must use `get_version`.
    pub fn get_version_for_execution(
        &self,
        account_id: &str,
        region: &str,
        name: &str,
        version: u64,
    ) -> Option<LayerVersion> {
        self.records
            .get(&Self::key(account_id, region, name))
            .and_then(|record| {
                record
                    .versions
                    .get(&version)
                    .or_else(|| record.retained_versions.get(&version))
                    .cloned()
            })
    }

    /// Hide a version from the control plane while retaining its payload for existing functions.
    pub fn delete_version(&self, account_id: &str, region: &str, name: &str, version: u64) -> bool {
        match self.records.get_mut(&Self::key(account_id, region, name)) {
            Some(mut record) => match record.versions.remove(&version) {
                Some(layer) => {
                    record.retained_versions.insert(version, layer);
                    true
                }
                None => false,
            },
            None => false,
        }
    }

    /// All layers in the scope (name + latest version), sorted by name. Layers with no
    /// remaining versions are omitted.
    pub fn list_layers(&self, account_id: &str, region: &str) -> Vec<(String, LayerVersion)> {
        let mut out: Vec<(String, LayerVersion)> = self
            .records
            .iter()
            .filter(|e| e.key().account_id == account_id && e.key().region == region)
            .filter_map(|e| {
                e.value()
                    .versions
                    .values()
                    .next_back()
                    .cloned()
                    .map(|latest| (e.key().name.clone(), latest))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// All versions of a layer in descending version order, or an empty vec if the layer
    /// is absent (AWS returns an empty list rather than 404 for `ListLayerVersions`).
    pub fn list_versions(&self, account_id: &str, region: &str, name: &str) -> Vec<LayerVersion> {
        match self.records.get(&Self::key(account_id, region, name)) {
            Some(record) => record.versions.values().rev().cloned().collect(),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn valid_zip() -> (String, u64) {
        let mut bytes = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(Cursor::new(&mut bytes));
            writer
                .start_file("index.js", zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"exports.handler=async()=>({})").unwrap();
            writer.finish().unwrap();
        }
        let size = bytes.len() as u64;
        (BASE64.encode(bytes), size)
    }

    #[test]
    fn arn_format() {
        assert_eq!(
            function_arn("us-east-1", "000000000000", "fn"),
            "arn:aws:lambda:us-east-1:000000000000:function:fn"
        );
    }

    #[test]
    fn supported_runtime_set_excludes_go1x() {
        assert!(is_supported_runtime("nodejs22.x"));
        assert!(is_supported_runtime("provided.al2023"));
        assert!(!is_supported_runtime("go1.x"));
        assert!(!is_supported_runtime("python2.7"));
    }

    #[test]
    fn resolve_function_name_handles_bare_arn_and_qualifier() {
        assert_eq!(resolve_function_name("fn", "us-east-1").unwrap(), "fn");
        assert_eq!(resolve_function_name("fn:1", "us-east-1").unwrap(), "fn");
        assert_eq!(
            resolve_function_name("000000000000:function:fn", "us-east-1").unwrap(),
            "fn"
        );
        assert_eq!(
            resolve_function_name(
                "arn:aws:lambda:us-east-1:000000000000:function:fn",
                "us-east-1"
            )
            .unwrap(),
            "fn"
        );
        assert_eq!(
            resolve_function_name(
                "arn:aws:lambda:us-east-1:000000000000:function:fn:5",
                "us-east-1"
            )
            .unwrap(),
            "fn"
        );
    }

    #[test]
    fn resolve_function_name_rejects_region_mismatch() {
        let err = resolve_function_name(
            "arn:aws:lambda:eu-west-1:000000000000:function:fn",
            "us-east-1",
        )
        .unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
    }

    #[test]
    fn compute_zip_code_is_deterministic_base64_sha256() {
        let (zip, expected_size) = valid_zip();
        let (sha1, size1) = compute_zip_code(&zip).unwrap();
        let (sha2, size2) = compute_zip_code(&zip).unwrap();
        assert_eq!(sha1, sha2);
        assert_eq!(size1, expected_size);
        assert_eq!(size2, expected_size);
    }

    #[test]
    fn compute_zip_code_rejects_invalid_base64() {
        assert!(compute_zip_code("not base64!!!").is_err());
    }

    #[test]
    fn store_scopes_by_account_and_region() {
        let store = FunctionStore::new();
        let f = |name: &str| LambdaFunction {
            function_name: name.into(),
            function_arn: function_arn("us-east-1", "000000000000", name),
            runtime: Some("nodejs22.x".into()),
            role: "arn:aws:iam::000000000000:role/r".into(),
            handler: Some("index.handler".into()),
            package_type: "Zip".into(),
            code_sha256: "x".into(),
            code_size: 1,
            description: String::new(),
            timeout: 3,
            memory_size: 128,
            ephemeral_storage: 512,
            architectures: vec!["x86_64".into()],
            environment: Default::default(),
            layers: Vec::new(),
            version: "$LATEST".into(),
            last_modified: "now".into(),
            revision_id: "rev".into(),
            state: "Active".into(),
            code_zip: None,
            dead_letter_arn: None,
            vpc_config: None,
        };
        store.create("000000000000", "us-east-1", f("a")).unwrap();
        // same name, different region is a distinct function
        store.create("000000000000", "eu-west-1", f("a")).unwrap();
        assert!(store.get("000000000000", "us-east-1", "a").is_some());
        assert!(store.get("000000000000", "eu-west-1", "a").is_some());
        assert!(store.get("000000000000", "ap-south-1", "a").is_none());
        // duplicate in same scope -> conflict
        assert!(store.create("000000000000", "us-east-1", f("a")).is_err());
        assert_eq!(store.list("000000000000", "us-east-1").len(), 1);
    }
}
