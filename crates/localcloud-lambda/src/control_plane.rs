//! Lambda control-plane operations (REST-JSON).
//!
//! Each operation returns `(http_status, optional_json_body)` or a [`LambdaError`]. The
//! service handler turns these into HTTP responses. Region and account come from the
//! resolved request context, never hardcoded.

use serde_json::Value;
use uuid::Uuid;

use crate::error::LambdaError;
use crate::model::{
    compute_zip_code, function_arn, function_url_id, is_supported_runtime, layer_arn,
    resolve_function_name, Alias, EventInvokeConfig, FunctionStore, FunctionUrlConfig,
    LambdaFunction, LayerStore, LayerVersion, DEFAULT_EPHEMERAL_MB, DEFAULT_MEMORY_MB,
    DEFAULT_TIMEOUT_SECS, MAX_EPHEMERAL_MB, MAX_MEMORY_MB, MAX_TIMEOUT_SECS, MIN_EPHEMERAL_MB,
    MIN_MEMORY_MB, MIN_TIMEOUT_SECS,
};

type OpResult = Result<(u16, Option<Value>), LambdaError>;

/// `CreateFunction` — validates, stores, and returns HTTP 201 with the configuration.
pub fn create_function(
    store: &FunctionStore,
    region: &str,
    account: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(require_str(input, "FunctionName")?, region)?;
    let role = require_str(input, "Role")?;

    let package_type = input
        .get("PackageType")
        .and_then(Value::as_str)
        .unwrap_or("Zip");
    let is_image = match package_type {
        "Zip" => false,
        "Image" => true,
        other => {
            return Err(LambdaError::InvalidParameterValue(format!(
                "invalid PackageType: {other}"
            )))
        }
    };
    validate_env(input)?;
    let environment = environment_variables(input);

    // Image requests are shape-validated and rejected before any state is created. Zip carries
    // the only executable package supported by this module.
    if is_image {
        if input.get("Runtime").is_some() || input.get("Handler").is_some() {
            return Err(LambdaError::InvalidParameterValue(
                "Runtime and Handler are not valid for Image package functions".into(),
            ));
        }
        let _ = input
            .get("Code")
            .and_then(|c| c.get("ImageUri"))
            .and_then(Value::as_str)
            .filter(|uri| !uri.is_empty())
            .ok_or_else(|| {
                LambdaError::InvalidParameterValue(
                    "Code.ImageUri is required for Image packages".into(),
                )
            })?;
        return Err(LambdaError::NotImplemented(
            "Image package functions require an OCI image data plane, which is not supported"
                .into(),
        ));
    }

    let runtime = require_str(input, "Runtime")?;
    if !is_supported_runtime(runtime) {
        return Err(LambdaError::InvalidParameterValue(format!(
            "Value {runtime} at 'runtime' failed to satisfy constraint: a supported runtime"
        )));
    }
    let handler = require_str(input, "Handler")?;
    let (code_sha256, code_size) = resolve_code(input)?;
    let code_zip = input
        .get("Code")
        .and_then(|c| c.get("ZipFile"))
        .and_then(Value::as_str)
        .and_then(crate::model::decode_inline_zip);

    let timeout = u32_field(input, "Timeout").unwrap_or(DEFAULT_TIMEOUT_SECS);
    let memory_size = u32_field(input, "MemorySize").unwrap_or(DEFAULT_MEMORY_MB);
    let ephemeral_storage = input
        .get("EphemeralStorage")
        .and_then(|e| e.get("Size"))
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .unwrap_or(DEFAULT_EPHEMERAL_MB);
    validate_range("MemorySize", memory_size, MIN_MEMORY_MB, MAX_MEMORY_MB)?;
    validate_range("Timeout", timeout, MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS)?;
    validate_range(
        "EphemeralStorage",
        ephemeral_storage,
        MIN_EPHEMERAL_MB,
        MAX_EPHEMERAL_MB,
    )?;

    let architectures = input
        .get("Architectures")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec!["x86_64".to_string()]);
    let description = input
        .get("Description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let dead_letter_arn = input
        .get("DeadLetterConfig")
        .and_then(|d| d.get("TargetArn"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let func = LambdaFunction {
        function_arn: function_arn(region, account, &name),
        function_name: name,
        runtime: Some(runtime.to_string()),
        role: role.to_string(),
        handler: Some(handler.to_string()),
        package_type: package_type.to_string(),
        code_sha256,
        code_size,
        description,
        timeout,
        memory_size,
        ephemeral_storage,
        architectures,
        environment,
        layers: parse_layers(input)?,
        version: "$LATEST".to_string(),
        last_modified: now_iso8601(),
        revision_id: Uuid::new_v4().to_string(),
        state: "Active".to_string(),
        code_zip,
        dead_letter_arn,
    };
    store.create(account, region, func.clone())?;
    Ok((201, Some(func.to_configuration_json())))
}

/// Reject a user `Environment` that sets a reserved variable (Requirement 21.7).
fn validate_env(input: &Value) -> Result<(), LambdaError> {
    crate::exec_env::validate_environment(&environment_variables(input))
}

fn environment_variables(input: &Value) -> std::collections::BTreeMap<String, String> {
    input
        .get("Environment")
        .and_then(|environment| environment.get("Variables"))
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
        .collect()
}

// ---- Provisioned concurrency ----

/// Confirm a qualifier names an existing published version or alias (not `$LATEST`).
fn require_qualifier(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    qualifier: &str,
) -> Result<(), LambdaError> {
    if qualifier.is_empty() || qualifier == "$LATEST" {
        return Err(LambdaError::InvalidParameterValue(
            "provisioned concurrency requires a version or alias qualifier, not $LATEST".into(),
        ));
    }
    let exists = store.version_exists(account, region, name, qualifier)
        || store.get_alias(account, region, name, qualifier).is_some();
    if exists {
        Ok(())
    } else {
        Err(not_found(name))
    }
}

/// `PutProvisionedConcurrencyConfig` (HTTP 202).
pub fn put_provisioned_concurrency(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    qualifier: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    require_qualifier(store, region, account, &name, qualifier)?;
    let requested = input
        .get("ProvisionedConcurrentExecutions")
        .and_then(Value::as_u64)
        .filter(|v| *v >= 1)
        .ok_or_else(|| {
            LambdaError::InvalidParameterValue(
                "ProvisionedConcurrentExecutions must be at least 1".into(),
            )
        })? as u32;
    let config = crate::model::ProvisionedConfig {
        requested,
        last_modified: now_iso8601(),
    };
    store.set_provisioned(account, region, &name, qualifier, config.clone());
    Ok((202, Some(config.to_json())))
}

/// `GetProvisionedConcurrencyConfig` (HTTP 200).
pub fn get_provisioned_concurrency(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    qualifier: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let config = store
        .get_provisioned(account, region, &name, qualifier)
        .ok_or_else(|| not_found(&name))?;
    Ok((200, Some(config.to_json())))
}

/// `DeleteProvisionedConcurrencyConfig` (HTTP 204).
pub fn delete_provisioned_concurrency(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    qualifier: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    store.delete_provisioned(account, region, &name, qualifier);
    Ok((204, None))
}

/// `ListProvisionedConcurrencyConfigs` (HTTP 200).
pub fn list_provisioned_concurrency(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let base = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let configs = store
        .list_provisioned(account, region, &name)
        .unwrap_or_default();
    let list: Vec<Value> = configs
        .into_iter()
        .map(|(qualifier, c)| {
            let mut obj = c.to_json();
            obj["FunctionArn"] = Value::String(format!("{base}:{qualifier}"));
            obj
        })
        .collect();
    Ok((
        200,
        Some(serde_json::json!({ "ProvisionedConcurrencyConfigs": list })),
    ))
}

/// `GetFunction` — returns the configuration plus a `Code` location.
pub fn get_function(store: &FunctionStore, region: &str, account: &str, name: &str) -> OpResult {
    let f = lookup(store, region, account, name)?;
    let code = serde_json::json!({
        "RepositoryType": "S3",
        "Location": format!("{}/code", f.function_arn)
    });
    let body = serde_json::json!({
        "Configuration": f.to_configuration_json(),
        "Code": code,
    });
    Ok((200, Some(body)))
}

/// `GetFunctionConfiguration` — returns the configuration only.
pub fn get_function_configuration(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
) -> OpResult {
    let f = lookup(store, region, account, name)?;
    Ok((200, Some(f.to_configuration_json())))
}

/// `ListFunctions` — returns the scope's functions sorted by name.
pub fn list_functions(store: &FunctionStore, region: &str, account: &str) -> OpResult {
    let functions: Vec<Value> = store
        .list(account, region)
        .iter()
        .map(LambdaFunction::to_configuration_json)
        .collect();
    Ok((200, Some(serde_json::json!({ "Functions": functions }))))
}

/// `DeleteFunction` — removes the function, returning HTTP 204.
pub fn delete_function(store: &FunctionStore, region: &str, account: &str, name: &str) -> OpResult {
    let name = resolve_function_name(name, region)?;
    if store.delete(account, region, &name) {
        Ok((204, None))
    } else {
        Err(not_found(&name))
    }
}

/// `AddPermission` — add one statement to the function resource policy.
pub fn add_permission(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let statement_id = require_str(input, "StatementId")?;
    let action = require_str(input, "Action")?;
    let principal = require_str(input, "Principal")?;
    let resource = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let principal = if principal.ends_with(".amazonaws.com") {
        serde_json::json!({ "Service": principal })
    } else {
        serde_json::json!({ "AWS": principal })
    };
    let mut statement = serde_json::json!({
        "Sid": statement_id,
        "Effect": "Allow",
        "Principal": principal,
        "Action": action,
        "Resource": resource,
    });
    let mut condition = serde_json::Map::new();
    if let Some(source_arn) = input.get("SourceArn").and_then(Value::as_str) {
        condition.insert(
            "ArnLike".into(),
            serde_json::json!({ "AWS:SourceArn": source_arn }),
        );
    }
    if let Some(source_account) = input.get("SourceAccount").and_then(Value::as_str) {
        condition.insert(
            "StringEquals".into(),
            serde_json::json!({ "AWS:SourceAccount": source_account }),
        );
    }
    if !condition.is_empty() {
        statement["Condition"] = Value::Object(condition);
    }
    if !store.add_permission(account, region, &name, statement_id, statement.clone())? {
        return Err(not_found(&name));
    }
    Ok((
        201,
        Some(serde_json::json!({ "Statement": statement.to_string() })),
    ))
}

/// `GetPolicy` — return the serialized resource policy for a function.
pub fn get_policy(store: &FunctionStore, region: &str, account: &str, name: &str) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let statements = store
        .permissions(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Id": "default",
        "Statement": statements,
    });
    Ok((
        200,
        Some(serde_json::json!({ "Policy": policy.to_string() })),
    ))
}

/// `RemovePermission` — remove one statement from the function resource policy.
pub fn remove_permission(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    statement_id: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    match store.remove_permission(account, region, &name, statement_id) {
        Some(true) => Ok((204, None)),
        Some(false) => Err(LambdaError::ResourceNotFound(format!(
            "Statement not found: {statement_id}"
        ))),
        None => Err(not_found(&name)),
    }
}

/// `UpdateFunctionConfiguration` — updates supplied fields, leaving the rest unchanged, and
/// assigns a new revision id and last-modified time.
pub fn update_function_configuration(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    validate_env(input)?;

    // Validate supplied fields before mutating anything.
    if let Some(runtime) = input.get("Runtime").and_then(Value::as_str) {
        if !is_supported_runtime(runtime) {
            return Err(LambdaError::InvalidParameterValue(format!(
                "Value {runtime} at 'runtime' failed to satisfy constraint: a supported runtime"
            )));
        }
    }
    let timeout = u32_field(input, "Timeout");
    if let Some(t) = timeout {
        validate_range("Timeout", t, MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS)?;
    }
    let memory = u32_field(input, "MemorySize");
    if let Some(m) = memory {
        validate_range("MemorySize", m, MIN_MEMORY_MB, MAX_MEMORY_MB)?;
    }
    let ephemeral = input
        .get("EphemeralStorage")
        .and_then(|e| e.get("Size"))
        .and_then(Value::as_u64)
        .map(|v| v as u32);
    if let Some(e) = ephemeral {
        validate_range("EphemeralStorage", e, MIN_EPHEMERAL_MB, MAX_EPHEMERAL_MB)?;
    }

    let runtime = input
        .get("Runtime")
        .and_then(Value::as_str)
        .map(String::from);
    let handler = input
        .get("Handler")
        .and_then(Value::as_str)
        .map(String::from);
    let role = input.get("Role").and_then(Value::as_str).map(String::from);
    let description = input
        .get("Description")
        .and_then(Value::as_str)
        .map(String::from);
    let environment = input
        .get("Environment")
        .map(|_| environment_variables(input));
    let layers = input
        .get("Layers")
        .map(|_| parse_layers(input))
        .transpose()?;

    let updated = store
        .update(account, region, &name, |f| {
            if let Some(v) = runtime {
                f.runtime = Some(v);
            }
            if let Some(v) = handler {
                f.handler = Some(v);
            }
            if let Some(v) = role {
                f.role = v;
            }
            if let Some(v) = description {
                f.description = v;
            }
            if let Some(v) = timeout {
                f.timeout = v;
            }
            if let Some(v) = memory {
                f.memory_size = v;
            }
            if let Some(v) = ephemeral {
                f.ephemeral_storage = v;
            }
            if let Some(v) = environment {
                f.environment = v;
            }
            if let Some(v) = layers {
                f.layers = v;
            }
            f.last_modified = now_iso8601();
            f.revision_id = Uuid::new_v4().to_string();
        })
        .ok_or_else(|| not_found(&name))?;
    Ok((200, Some(updated.to_configuration_json())))
}

/// `UpdateFunctionCode` — replaces the code, recomputing `CodeSha256`/`CodeSize`.
pub fn update_function_code(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let (code_sha256, code_size) = resolve_update_code(input)?;
    let code_zip = input
        .get("ZipFile")
        .and_then(Value::as_str)
        .and_then(crate::model::decode_inline_zip);
    let updated = store
        .update(account, region, &name, |f| {
            f.code_sha256 = code_sha256;
            f.code_size = code_size;
            if code_zip.is_some() {
                f.code_zip = code_zip.clone();
            }
            f.last_modified = now_iso8601();
            f.revision_id = Uuid::new_v4().to_string();
        })
        .ok_or_else(|| not_found(&name))?;
    Ok((200, Some(updated.to_configuration_json())))
}

fn lookup(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
) -> Result<LambdaFunction, LambdaError> {
    let name = resolve_function_name(name, region)?;
    store
        .get(account, region, &name)
        .ok_or_else(|| not_found(&name))
}

// ---- Versions ----

/// `PublishVersion` — snapshots `$LATEST` into the next immutable version (HTTP 201).
pub fn publish_version(store: &FunctionStore, region: &str, account: &str, name: &str) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let published = store
        .publish_version(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    Ok((201, Some(published.to_configuration_json())))
}

/// `ListVersionsByFunction` — `$LATEST` plus all published versions.
pub fn list_versions_by_function(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let versions = store
        .list_versions(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let versions: Vec<Value> = versions
        .iter()
        .map(LambdaFunction::to_configuration_json)
        .collect();
    Ok((200, Some(serde_json::json!({ "Versions": versions }))))
}

// ---- Aliases ----

/// `CreateAlias` — points an alias at an existing version (HTTP 201).
pub fn create_alias(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let base_arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let alias_name = require_str(input, "Name")?.to_string();
    let function_version = require_str(input, "FunctionVersion")?.to_string();
    let description = input
        .get("Description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    if !store.version_exists(account, region, &name, &function_version) {
        return Err(LambdaError::InvalidParameterValue(format!(
            "Function version {function_version} does not exist"
        )));
    }
    if store
        .get_alias(account, region, &name, &alias_name)
        .is_some()
    {
        return Err(LambdaError::ResourceConflict(format!(
            "Alias already exists: {alias_name}"
        )));
    }
    let alias = Alias {
        name: alias_name,
        function_version,
        description,
        revision_id: Uuid::new_v4().to_string(),
    };
    store.put_alias(account, region, &name, alias.clone());
    Ok((201, Some(alias.to_json(&base_arn))))
}

/// `GetAlias`.
pub fn get_alias(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    alias: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let base_arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let alias = store
        .get_alias(account, region, &name, alias)
        .ok_or_else(|| LambdaError::ResourceNotFound(format!("Alias not found: {alias}")))?;
    Ok((200, Some(alias.to_json(&base_arn))))
}

/// `UpdateAlias` — updates the target version and/or description.
pub fn update_alias(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    alias_name: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let base_arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let mut alias = store
        .get_alias(account, region, &name, alias_name)
        .ok_or_else(|| LambdaError::ResourceNotFound(format!("Alias not found: {alias_name}")))?;

    if let Some(version) = input.get("FunctionVersion").and_then(Value::as_str) {
        if !store.version_exists(account, region, &name, version) {
            return Err(LambdaError::InvalidParameterValue(format!(
                "Function version {version} does not exist"
            )));
        }
        alias.function_version = version.to_string();
    }
    if let Some(description) = input.get("Description").and_then(Value::as_str) {
        alias.description = description.to_string();
    }
    alias.revision_id = Uuid::new_v4().to_string();
    store.put_alias(account, region, &name, alias.clone());
    Ok((200, Some(alias.to_json(&base_arn))))
}

/// `DeleteAlias` (HTTP 204).
pub fn delete_alias(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    alias: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    match store.delete_alias(account, region, &name, alias) {
        Some(_) => Ok((204, None)),
        None => Err(LambdaError::ResourceNotFound(format!(
            "Alias not found: {alias}"
        ))),
    }
}

/// `ListAliases`.
pub fn list_aliases(store: &FunctionStore, region: &str, account: &str, name: &str) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let base_arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let aliases = store
        .list_aliases(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let aliases: Vec<Value> = aliases.iter().map(|a| a.to_json(&base_arn)).collect();
    Ok((200, Some(serde_json::json!({ "Aliases": aliases }))))
}

// ---- Tags ----

/// `TagResource` — merges tags onto the function named by the resource ARN (HTTP 204).
pub fn tag_resource(
    store: &FunctionStore,
    region: &str,
    account: &str,
    arn: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(arn, region)?;
    let tags = input
        .get("Tags")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    if store.set_tags(account, region, &name, tags) {
        Ok((204, None))
    } else {
        Err(not_found(&name))
    }
}

/// `UntagResource` — removes the named tag keys (HTTP 204).
pub fn untag_resource(
    store: &FunctionStore,
    region: &str,
    account: &str,
    arn: &str,
    tag_keys: &[String],
) -> OpResult {
    let name = resolve_function_name(arn, region)?;
    if store.remove_tags(account, region, &name, tag_keys) {
        Ok((204, None))
    } else {
        Err(not_found(&name))
    }
}

/// `ListTags`.
pub fn list_tags(store: &FunctionStore, region: &str, account: &str, arn: &str) -> OpResult {
    let name = resolve_function_name(arn, region)?;
    let tags = store
        .get_tags(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let map: serde_json::Map<String, Value> = tags
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .collect();
    Ok((200, Some(serde_json::json!({ "Tags": map }))))
}

// ---- Reserved concurrency ----

/// `PutFunctionConcurrency` — set the reserved concurrent executions (HTTP 200).
pub fn put_function_concurrency(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let value = u32_field(input, "ReservedConcurrentExecutions").ok_or_else(|| {
        LambdaError::InvalidParameterValue("ReservedConcurrentExecutions is required".into())
    })?;
    if store.set_reserved_concurrency(account, region, &name, value) {
        Ok((
            200,
            Some(serde_json::json!({ "ReservedConcurrentExecutions": value })),
        ))
    } else {
        Err(not_found(&name))
    }
}

/// `GetFunctionConcurrency` — returns the reservation, or `{}` when unset (HTTP 200).
pub fn get_function_concurrency(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    match store.get_reserved_concurrency(account, region, &name) {
        Some(Some(value)) => Ok((
            200,
            Some(serde_json::json!({ "ReservedConcurrentExecutions": value })),
        )),
        Some(None) => Ok((200, Some(serde_json::json!({})))),
        None => Err(not_found(&name)),
    }
}

/// `DeleteFunctionConcurrency` — clears the reservation (HTTP 204).
pub fn delete_function_concurrency(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    if store.delete_reserved_concurrency(account, region, &name) {
        Ok((204, None))
    } else {
        Err(not_found(&name))
    }
}

// ---- Function URL config ----

/// Validate an `AuthType` value (`NONE` or `AWS_IAM`).
fn validate_auth_type(auth: &str) -> Result<(), LambdaError> {
    match auth {
        "NONE" | "AWS_IAM" => Ok(()),
        other => Err(LambdaError::InvalidParameterValue(format!(
            "Value {other} at 'authType' failed to satisfy constraint: one of NONE, AWS_IAM"
        ))),
    }
}

/// `CreateFunctionUrlConfig` — create the (single) URL config for a function (HTTP 201).
pub fn create_function_url_config(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    if store.get_url_config(account, region, &name).is_some() {
        return Err(LambdaError::ResourceConflict(format!(
            "FunctionUrlConfig already exists for function {name}"
        )));
    }
    let auth_type = require_str(input, "AuthType")?;
    validate_auth_type(auth_type)?;
    let invoke_mode = input
        .get("InvokeMode")
        .and_then(Value::as_str)
        .unwrap_or("BUFFERED")
        .to_string();
    let now = now_iso8601();
    let config = FunctionUrlConfig {
        function_url: format!(
            "https://{}.lambda-url.{region}.on.aws/",
            function_url_id(&arn)
        ),
        auth_type: auth_type.to_string(),
        invoke_mode,
        cors: input.get("Cors").cloned(),
        creation_time: now.clone(),
        last_modified_time: now,
    };
    store.set_url_config(account, region, &name, config.clone());
    Ok((201, Some(config.to_json(&arn))))
}

/// `GetFunctionUrlConfig`.
pub fn get_function_url_config(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let config = store
        .get_url_config(account, region, &name)
        .ok_or_else(|| url_config_not_found(&name))?;
    Ok((200, Some(config.to_json(&arn))))
}

/// `UpdateFunctionUrlConfig` — updates supplied fields (HTTP 200).
pub fn update_function_url_config(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let mut config = store
        .get_url_config(account, region, &name)
        .ok_or_else(|| url_config_not_found(&name))?;

    if let Some(auth) = input.get("AuthType").and_then(Value::as_str) {
        validate_auth_type(auth)?;
        config.auth_type = auth.to_string();
    }
    if let Some(mode) = input.get("InvokeMode").and_then(Value::as_str) {
        config.invoke_mode = mode.to_string();
    }
    if input.get("Cors").is_some() {
        config.cors = input.get("Cors").cloned();
    }
    config.last_modified_time = now_iso8601();
    store.set_url_config(account, region, &name, config.clone());
    Ok((200, Some(config.to_json(&arn))))
}

/// `DeleteFunctionUrlConfig` (HTTP 204).
pub fn delete_function_url_config(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    if store.function_base_arn(account, region, &name).is_none() {
        return Err(not_found(&name));
    }
    if store.delete_url_config(account, region, &name) {
        Ok((204, None))
    } else {
        Err(url_config_not_found(&name))
    }
}

// ---- Event-invoke config ----

/// Valid ranges for the asynchronous-invocation configuration.
const MIN_RETRY_ATTEMPTS: u32 = 0;
const MAX_RETRY_ATTEMPTS: u32 = 2;
const MIN_EVENT_AGE_SECS: u32 = 60;
const MAX_EVENT_AGE_SECS: u32 = 21600;

/// Parse and validate the event-invoke fields into a config (with `last_modified` set).
fn parse_event_invoke(input: &Value) -> Result<EventInvokeConfig, LambdaError> {
    let retries = u32_field(input, "MaximumRetryAttempts");
    if let Some(r) = retries {
        validate_range(
            "MaximumRetryAttempts",
            r,
            MIN_RETRY_ATTEMPTS,
            MAX_RETRY_ATTEMPTS,
        )?;
    }
    let age = u32_field(input, "MaximumEventAgeInSeconds");
    if let Some(a) = age {
        validate_range(
            "MaximumEventAgeInSeconds",
            a,
            MIN_EVENT_AGE_SECS,
            MAX_EVENT_AGE_SECS,
        )?;
    }
    Ok(EventInvokeConfig {
        maximum_retry_attempts: retries,
        maximum_event_age_in_seconds: age,
        destination_config: input.get("DestinationConfig").cloned(),
        last_modified: now_iso8601(),
    })
}

/// `PutFunctionEventInvokeConfig` — replace the config (HTTP 200).
pub fn put_function_event_invoke_config(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let config = parse_event_invoke(input)?;
    store.set_event_invoke_config(account, region, &name, config.clone());
    Ok((200, Some(config.to_json(&arn))))
}

/// `UpdateFunctionEventInvokeConfig` — merge supplied fields into the existing config (HTTP 200).
pub fn update_function_event_invoke_config(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    input: &Value,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let mut config = store
        .get_event_invoke_config(account, region, &name)
        .ok_or_else(|| event_invoke_not_found(&name))?;

    if let Some(r) = u32_field(input, "MaximumRetryAttempts") {
        validate_range(
            "MaximumRetryAttempts",
            r,
            MIN_RETRY_ATTEMPTS,
            MAX_RETRY_ATTEMPTS,
        )?;
        config.maximum_retry_attempts = Some(r);
    }
    if let Some(a) = u32_field(input, "MaximumEventAgeInSeconds") {
        validate_range(
            "MaximumEventAgeInSeconds",
            a,
            MIN_EVENT_AGE_SECS,
            MAX_EVENT_AGE_SECS,
        )?;
        config.maximum_event_age_in_seconds = Some(a);
    }
    if input.get("DestinationConfig").is_some() {
        config.destination_config = input.get("DestinationConfig").cloned();
    }
    config.last_modified = now_iso8601();
    store.set_event_invoke_config(account, region, &name, config.clone());
    Ok((200, Some(config.to_json(&arn))))
}

/// `GetFunctionEventInvokeConfig`.
pub fn get_function_event_invoke_config(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let config = store
        .get_event_invoke_config(account, region, &name)
        .ok_or_else(|| event_invoke_not_found(&name))?;
    Ok((200, Some(config.to_json(&arn))))
}

/// `DeleteFunctionEventInvokeConfig` (HTTP 204).
pub fn delete_function_event_invoke_config(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    if store.function_base_arn(account, region, &name).is_none() {
        return Err(not_found(&name));
    }
    if store.delete_event_invoke_config(account, region, &name) {
        Ok((204, None))
    } else {
        Err(event_invoke_not_found(&name))
    }
}

/// `ListFunctionEventInvokeConfigs` — zero or one config for the function (HTTP 200).
pub fn list_function_event_invoke_configs(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    let arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    let configs: Vec<Value> = store
        .get_event_invoke_config(account, region, &name)
        .map(|c| vec![c.to_json(&arn)])
        .unwrap_or_default();
    Ok((
        200,
        Some(serde_json::json!({ "FunctionEventInvokeConfigs": configs })),
    ))
}

pub(crate) fn parse_layers(input: &Value) -> Result<Vec<String>, LambdaError> {
    let Some(raw) = input.get("Layers") else {
        return Ok(Vec::new());
    };
    let entries = raw
        .as_array()
        .ok_or_else(|| LambdaError::InvalidParameterValue("Layers must be an array".into()))?;
    if entries.len() > 5 {
        return Err(LambdaError::InvalidParameterValue(
            "Layers exceeds maximum of 5".into(),
        ));
    }
    entries
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|arn| !arn.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    LambdaError::InvalidParameterValue(
                        "Layers entries must be non-empty ARNs".into(),
                    )
                })
        })
        .collect()
}

// ---- Layers ----

/// `PublishLayerVersion` — publish the next version of a layer (HTTP 201).
pub fn publish_layer_version(
    store: &LayerStore,
    region: &str,
    account: &str,
    name: &str,
    input: &Value,
) -> OpResult {
    let (code_sha256, code_size) = resolve_layer_code(input)?;
    let code_zip = input["Content"]["ZipFile"]
        .as_str()
        .and_then(crate::model::decode_inline_zip)
        .ok_or_else(|| LambdaError::InvalidParameterValue("Content.ZipFile is required".into()))?;
    let description = input
        .get("Description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let compatible_runtimes = string_array(input, "CompatibleRuntimes");
    let compatible_architectures = string_array(input, "CompatibleArchitectures");
    let published = store.publish(
        account,
        region,
        name,
        LayerVersion {
            version: 0, // assigned by the store
            description,
            created_date: now_iso8601(),
            code_sha256,
            code_size,
            code_zip,
            compatible_runtimes,
            compatible_architectures,
        },
    );
    Ok((201, Some(published.to_json(region, account, name))))
}

/// `GetLayerVersion`.
pub fn get_layer_version(
    store: &LayerStore,
    region: &str,
    account: &str,
    name: &str,
    version: &str,
) -> OpResult {
    let version = parse_layer_version(version)?;
    let layer_version = store
        .get_version(account, region, name, version)
        .ok_or_else(|| layer_not_found(name, version))?;
    Ok((200, Some(layer_version.to_json(region, account, name))))
}

/// `DeleteLayerVersion` (HTTP 204).
pub fn delete_layer_version(
    store: &LayerStore,
    region: &str,
    account: &str,
    name: &str,
    version: &str,
) -> OpResult {
    let version = parse_layer_version(version)?;
    if store.delete_version(account, region, name, version) {
        Ok((204, None))
    } else {
        Err(layer_not_found(name, version))
    }
}

/// `ListLayers` — each layer with its latest version (HTTP 200).
pub fn list_layers(store: &LayerStore, region: &str, account: &str) -> OpResult {
    let layers: Vec<Value> = store
        .list_layers(account, region)
        .into_iter()
        .map(|(layer_name, latest)| {
            serde_json::json!({
                "LayerName": layer_name,
                "LayerArn": layer_arn(region, account, &layer_name),
                "LatestMatchingVersion": latest.detail_json(region, account, &layer_name),
            })
        })
        .collect();
    Ok((200, Some(serde_json::json!({ "Layers": layers }))))
}

/// `ListLayerVersions` — all versions of a layer in descending order (HTTP 200).
pub fn list_layer_versions(
    store: &LayerStore,
    region: &str,
    account: &str,
    name: &str,
) -> OpResult {
    let versions: Vec<Value> = store
        .list_versions(account, region, name)
        .iter()
        .map(|lv| lv.detail_json(region, account, name))
        .collect();
    Ok((200, Some(serde_json::json!({ "LayerVersions": versions }))))
}

fn validate_range(field: &str, value: u32, min: u32, max: u32) -> Result<(), LambdaError> {
    if value < min || value > max {
        Err(LambdaError::InvalidParameterValue(format!(
            "{field} value {value} is outside the valid range [{min}, {max}]"
        )))
    } else {
        Ok(())
    }
}

/// Resolve the code package for `UpdateFunctionCode` (fields at the request top level).
fn resolve_update_code(input: &Value) -> Result<(String, u64), LambdaError> {
    if let Some(zip) = input.get("ZipFile").and_then(Value::as_str) {
        return compute_zip_code(zip);
    }
    if input.get("S3Bucket").is_some() {
        return Err(LambdaError::NotImplemented(
            "Code.S3Bucket source is not yet supported".into(),
        ));
    }
    if input.get("ImageUri").is_some() {
        return Err(LambdaError::NotImplemented(
            "Image package functions are not yet supported".into(),
        ));
    }
    Err(LambdaError::InvalidParameterValue(
        "ZipFile is required".into(),
    ))
}

/// `GetFunctionCodeSigningConfig` — a function created without code signing reports no
/// `CodeSigningConfigArn` (HTTP 200). Terraform's `aws_lambda_function` reads this on refresh.
/// Served at `/2020-06-30/functions/{name}/code-signing-config`.
pub fn get_function_code_signing_config(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
) -> OpResult {
    let name = resolve_function_name(name, region)?;
    store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| not_found(&name))?;
    Ok((200, Some(serde_json::json!({ "FunctionName": name }))))
}

fn not_found(name: &str) -> LambdaError {
    LambdaError::ResourceNotFound(format!("Function not found: {name}"))
}

fn url_config_not_found(name: &str) -> LambdaError {
    LambdaError::ResourceNotFound(format!("FunctionUrlConfig not found for function {name}"))
}

fn event_invoke_not_found(name: &str) -> LambdaError {
    LambdaError::ResourceNotFound(format!("EventInvokeConfig not found for function {name}"))
}

fn layer_not_found(name: &str, version: u64) -> LambdaError {
    LambdaError::ResourceNotFound(format!("Layer version {name}:{version} not found"))
}

/// Parse a layer version path segment into a numeric version.
fn parse_layer_version(version: &str) -> Result<u64, LambdaError> {
    version.parse::<u64>().map_err(|_| {
        LambdaError::InvalidParameterValue(format!("invalid layer version: {version}"))
    })
}

/// Collect a JSON array of strings field into a `Vec<String>` (empty if absent).
fn string_array(input: &Value, field: &str) -> Vec<String> {
    input
        .get(field)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve the layer code package from inline `Content.ZipFile`.
fn resolve_layer_code(input: &Value) -> Result<(String, u64), LambdaError> {
    let content = input
        .get("Content")
        .ok_or_else(|| LambdaError::InvalidParameterValue("Content is required".into()))?;
    if let Some(zip) = content.get("ZipFile").and_then(Value::as_str) {
        return compute_zip_code(zip);
    }
    if content.get("S3Bucket").is_some() {
        return Err(LambdaError::NotImplemented(
            "Content.S3Bucket source is not yet supported".into(),
        ));
    }
    Err(LambdaError::InvalidParameterValue(
        "Content.ZipFile is required".into(),
    ))
}

fn require_str<'a>(input: &'a Value, field: &str) -> Result<&'a str, LambdaError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| LambdaError::InvalidParameterValue(format!("{field} is required")))
}

fn u32_field(input: &Value, field: &str) -> Option<u32> {
    input.get(field).and_then(Value::as_u64).map(|v| v as u32)
}

/// Resolve the code package, returning `(code_sha256, code_size)`. Only inline zip is
/// supported in this slice; S3 and image sources are deferred.
fn resolve_code(input: &Value) -> Result<(String, u64), LambdaError> {
    let code = input
        .get("Code")
        .ok_or_else(|| LambdaError::InvalidParameterValue("Code is required".into()))?;
    if let Some(zip) = code.get("ZipFile").and_then(Value::as_str) {
        return compute_zip_code(zip);
    }
    if code.get("S3Bucket").is_some() {
        return Err(LambdaError::NotImplemented(
            "Code.S3Bucket source is not yet supported".into(),
        ));
    }
    if code.get("ImageUri").is_some() {
        return Err(LambdaError::NotImplemented(
            "Image package functions are not yet supported".into(),
        ));
    }
    Err(LambdaError::InvalidParameterValue(
        "Code.ZipFile is required".into(),
    ))
}

fn now_iso8601() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::io::{Cursor, Write};

    fn zip_base64(contents: &[u8]) -> String {
        let mut bytes = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(Cursor::new(&mut bytes));
            writer
                .start_file("index.js", zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(contents).unwrap();
            writer.finish().unwrap();
        }
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn create_input(name: &str) -> Value {
        serde_json::json!({
            "FunctionName": name,
            "Role": "arn:aws:iam::000000000000:role/svc",
            "Runtime": "nodejs22.x",
            "Handler": "index.handler",
            "Code": { "ZipFile": zip_base64(b"exports.handler=async()=>({})") }
        })
    }

    #[test]
    fn create_then_get_round_trips() {
        let store = FunctionStore::new();
        let (status, body) =
            create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();
        assert_eq!(status, 201);
        let cfg = body.unwrap();
        assert_eq!(
            cfg["FunctionArn"],
            "arn:aws:lambda:us-east-1:000000000000:function:fn"
        );
        assert_eq!(cfg["Runtime"], "nodejs22.x");
        assert_eq!(cfg["State"], "Active");
        assert_eq!(cfg["Version"], "$LATEST");
        assert_eq!(cfg["MemorySize"], 128);
        assert!(cfg["CodeSize"].as_u64().unwrap() > 0);

        let (status, body) = get_function(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.unwrap()["Configuration"]["FunctionName"], "fn");
    }

    #[test]
    fn create_duplicate_is_conflict() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();
        let err =
            create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap_err();
        assert!(matches!(err, LambdaError::ResourceConflict(_)));
    }

    #[test]
    fn create_missing_required_fields() {
        let store = FunctionStore::new();
        let err = create_function(&store, "us-east-1", "000000000000", &serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
    }

    #[test]
    fn create_rejects_base64_that_is_not_a_zip_before_mutation() {
        let store = FunctionStore::new();
        let mut input = create_input("fn");
        input["Code"]["ZipFile"] =
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(b"not a zip"));
        let err = create_function(&store, "us-east-1", "000000000000", &input).unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
        assert!(store.get("000000000000", "us-east-1", "fn").is_none());
    }

    #[test]
    fn create_unsupported_runtime_rejected() {
        let store = FunctionStore::new();
        let mut input = create_input("fn");
        input["Runtime"] = serde_json::json!("go1.x");
        let err = create_function(&store, "us-east-1", "000000000000", &input).unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
    }

    #[test]
    fn create_image_package_never_creates_an_unexecutable_active_function() {
        let store = FunctionStore::new();
        let input = serde_json::json!({
            "FunctionName": "img",
            "Role": "arn:aws:iam::000000000000:role/svc",
            "PackageType": "Image",
            "Code": { "ImageUri": "repo/img:latest" },
            "ImageConfig": { "Command": ["app.handler"] }
        });
        let err = create_function(&store, "us-east-1", "000000000000", &input).unwrap_err();
        assert!(matches!(err, LambdaError::NotImplemented(_)));
        assert!(store.get("000000000000", "us-east-1", "img").is_none());

        // Runtime/Handler are invalid for an Image package even when its data plane is absent.
        let bad = serde_json::json!({
            "FunctionName": "img2",
            "Role": "arn:aws:iam::000000000000:role/svc",
            "PackageType": "Image",
            "Runtime": "nodejs22.x",
            "Code": { "ImageUri": "repo/img:latest" }
        });
        let err = create_function(&store, "us-east-1", "000000000000", &bad).unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));

        // ImageUri is required and remains a validation error.
        let missing = serde_json::json!({
            "FunctionName": "img3",
            "Role": "arn:aws:iam::000000000000:role/svc",
            "PackageType": "Image",
            "Code": {}
        });
        let err = create_function(&store, "us-east-1", "000000000000", &missing).unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
    }

    #[test]
    fn get_missing_is_not_found() {
        let store = FunctionStore::new();
        let err = get_function(&store, "us-east-1", "000000000000", "nope").unwrap_err();
        assert!(matches!(err, LambdaError::ResourceNotFound(_)));
    }

    #[test]
    fn delete_then_get_is_not_found() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();
        let (status, _) = delete_function(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(status, 204);
        assert!(get_function(&store, "us-east-1", "000000000000", "fn").is_err());
        let err = delete_function(&store, "us-east-1", "000000000000", "fn").unwrap_err();
        assert!(matches!(err, LambdaError::ResourceNotFound(_)));
    }

    #[test]
    fn create_rejects_out_of_range_memory() {
        let store = FunctionStore::new();
        let mut input = create_input("fn");
        input["MemorySize"] = serde_json::json!(64);
        let err = create_function(&store, "us-east-1", "000000000000", &input).unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
    }

    #[test]
    fn update_configuration_changes_fields_and_revision() {
        let store = FunctionStore::new();
        let (_, body) =
            create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();
        let rev0 = body.unwrap()["RevisionId"].as_str().unwrap().to_string();

        let patch =
            serde_json::json!({ "Timeout": 60, "MemorySize": 256, "Description": "updated" });
        let (status, body) =
            update_function_configuration(&store, "us-east-1", "000000000000", "fn", &patch)
                .unwrap();
        assert_eq!(status, 200);
        let cfg = body.unwrap();
        assert_eq!(cfg["Timeout"], 60);
        assert_eq!(cfg["MemorySize"], 256);
        assert_eq!(cfg["Description"], "updated");
        // unchanged fields preserved, revision rotated
        assert_eq!(cfg["Runtime"], "nodejs22.x");
        assert_ne!(cfg["RevisionId"].as_str().unwrap(), rev0);
    }

    #[test]
    fn update_configuration_rejects_bad_runtime_without_mutating() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();
        let patch = serde_json::json!({ "Runtime": "go1.x" });
        let err = update_function_configuration(&store, "us-east-1", "000000000000", "fn", &patch)
            .unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
        // original runtime intact
        let (_, body) = get_function(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(body.unwrap()["Configuration"]["Runtime"], "nodejs22.x");
    }

    #[test]
    fn update_code_recomputes_sha_and_size() {
        let store = FunctionStore::new();
        let (_, body) =
            create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();
        let sha0 = body.unwrap()["CodeSha256"].as_str().unwrap().to_string();
        let patch = serde_json::json!({
            "ZipFile": zip_base64(b"exports.handler=async()=>({updated:true})")
        });
        let (status, body) =
            update_function_code(&store, "us-east-1", "000000000000", "fn", &patch).unwrap();
        assert_eq!(status, 200);
        let cfg = body.unwrap();
        assert!(cfg["CodeSize"].as_u64().unwrap() > 0);
        assert_ne!(cfg["CodeSha256"].as_str().unwrap(), sha0);
    }

    #[test]
    fn get_resolves_full_arn() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();
        let (status, _) = get_function(
            &store,
            "us-east-1",
            "000000000000",
            "arn:aws:lambda:us-east-1:000000000000:function:fn",
        )
        .unwrap();
        assert_eq!(status, 200);
    }

    #[test]
    fn publish_and_list_versions() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();
        let (status, body) = publish_version(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(status, 201);
        let v = body.unwrap();
        assert_eq!(v["Version"], "1");
        assert_eq!(
            v["FunctionArn"],
            "arn:aws:lambda:us-east-1:000000000000:function:fn:1"
        );

        let (_, body) =
            list_versions_by_function(&store, "us-east-1", "000000000000", "fn").unwrap();
        let versions = body.unwrap();
        let labels: Vec<&str> = versions["Versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["Version"].as_str().unwrap())
            .collect();
        assert_eq!(labels, vec!["$LATEST", "1"]);
    }

    #[test]
    fn alias_lifecycle() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();
        publish_version(&store, "us-east-1", "000000000000", "fn").unwrap();

        let create =
            serde_json::json!({ "Name": "prod", "FunctionVersion": "1", "Description": "live" });
        let (status, body) =
            create_alias(&store, "us-east-1", "000000000000", "fn", &create).unwrap();
        assert_eq!(status, 201);
        let alias = body.unwrap();
        assert_eq!(alias["Name"], "prod");
        assert_eq!(alias["FunctionVersion"], "1");
        assert_eq!(
            alias["AliasArn"],
            "arn:aws:lambda:us-east-1:000000000000:function:fn:prod"
        );

        // duplicate -> conflict
        let err = create_alias(&store, "us-east-1", "000000000000", "fn", &create).unwrap_err();
        assert!(matches!(err, LambdaError::ResourceConflict(_)));

        // unknown version -> invalid
        let bad = serde_json::json!({ "Name": "x", "FunctionVersion": "99" });
        let err = create_alias(&store, "us-east-1", "000000000000", "fn", &bad).unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));

        let (status, _) = get_alias(&store, "us-east-1", "000000000000", "fn", "prod").unwrap();
        assert_eq!(status, 200);
        let (status, _) = delete_alias(&store, "us-east-1", "000000000000", "fn", "prod").unwrap();
        assert_eq!(status, 204);
        assert!(get_alias(&store, "us-east-1", "000000000000", "fn", "prod").is_err());
    }

    #[test]
    fn tag_round_trip() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();
        let arn = "arn:aws:lambda:us-east-1:000000000000:function:fn";
        let tags = serde_json::json!({ "Tags": { "team": "core", "env": "dev" } });
        let (status, _) = tag_resource(&store, "us-east-1", "000000000000", arn, &tags).unwrap();
        assert_eq!(status, 204);

        let (_, body) = list_tags(&store, "us-east-1", "000000000000", arn).unwrap();
        let listed = body.unwrap();
        assert_eq!(listed["Tags"]["team"], "core");
        assert_eq!(listed["Tags"]["env"], "dev");

        let (status, _) = untag_resource(
            &store,
            "us-east-1",
            "000000000000",
            arn,
            &["team".to_string()],
        )
        .unwrap();
        assert_eq!(status, 204);
        let (_, body) = list_tags(&store, "us-east-1", "000000000000", arn).unwrap();
        let listed = body.unwrap();
        assert!(listed["Tags"].get("team").is_none());
        assert_eq!(listed["Tags"]["env"], "dev");
    }

    #[test]
    fn list_returns_created_functions_sorted() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("b")).unwrap();
        create_function(&store, "us-east-1", "000000000000", &create_input("a")).unwrap();
        let (_, body) = list_functions(&store, "us-east-1", "000000000000").unwrap();
        let body = body.unwrap();
        let names: Vec<&str> = body["Functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["FunctionName"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    // ---- Reserved concurrency ----

    #[test]
    fn concurrency_put_get_delete_round_trip() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();

        // unset -> {}
        let (status, body) =
            get_function_concurrency(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.unwrap(), serde_json::json!({}));

        let put = serde_json::json!({ "ReservedConcurrentExecutions": 5 });
        let (status, body) =
            put_function_concurrency(&store, "us-east-1", "000000000000", "fn", &put).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.unwrap()["ReservedConcurrentExecutions"], 5);

        let (_, body) =
            get_function_concurrency(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(body.unwrap()["ReservedConcurrentExecutions"], 5);

        let (status, _) =
            delete_function_concurrency(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(status, 204);
        let (_, body) =
            get_function_concurrency(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(body.unwrap(), serde_json::json!({}));
    }

    #[test]
    fn concurrency_missing_function_is_not_found() {
        let store = FunctionStore::new();
        let put = serde_json::json!({ "ReservedConcurrentExecutions": 1 });
        let err = put_function_concurrency(&store, "us-east-1", "000000000000", "nope", &put)
            .unwrap_err();
        assert!(matches!(err, LambdaError::ResourceNotFound(_)));
        let err =
            get_function_concurrency(&store, "us-east-1", "000000000000", "nope").unwrap_err();
        assert!(matches!(err, LambdaError::ResourceNotFound(_)));
        let err =
            delete_function_concurrency(&store, "us-east-1", "000000000000", "nope").unwrap_err();
        assert!(matches!(err, LambdaError::ResourceNotFound(_)));
    }

    // ---- Function URL config ----

    #[test]
    fn url_config_lifecycle() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();

        let create = serde_json::json!({ "AuthType": "NONE" });
        let (status, body) =
            create_function_url_config(&store, "us-east-1", "000000000000", "fn", &create).unwrap();
        assert_eq!(status, 201);
        let cfg = body.unwrap();
        assert_eq!(cfg["AuthType"], "NONE");
        assert_eq!(cfg["InvokeMode"], "BUFFERED");
        assert!(cfg["FunctionUrl"]
            .as_str()
            .unwrap()
            .ends_with(".lambda-url.us-east-1.on.aws/"));
        assert_eq!(
            cfg["FunctionArn"],
            "arn:aws:lambda:us-east-1:000000000000:function:fn"
        );
        let url = cfg["FunctionUrl"].as_str().unwrap().to_string();

        // deterministic url on get
        let (status, body) =
            get_function_url_config(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.unwrap()["FunctionUrl"].as_str().unwrap(), url);

        // duplicate create -> conflict
        let err = create_function_url_config(&store, "us-east-1", "000000000000", "fn", &create)
            .unwrap_err();
        assert!(matches!(err, LambdaError::ResourceConflict(_)));

        let update = serde_json::json!({ "AuthType": "AWS_IAM", "InvokeMode": "RESPONSE_STREAM" });
        let (status, body) =
            update_function_url_config(&store, "us-east-1", "000000000000", "fn", &update).unwrap();
        assert_eq!(status, 200);
        let cfg = body.unwrap();
        assert_eq!(cfg["AuthType"], "AWS_IAM");
        assert_eq!(cfg["InvokeMode"], "RESPONSE_STREAM");

        let (status, _) =
            delete_function_url_config(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(status, 204);
        let err = get_function_url_config(&store, "us-east-1", "000000000000", "fn").unwrap_err();
        assert!(matches!(err, LambdaError::ResourceNotFound(_)));
    }

    #[test]
    fn url_config_rejects_bad_auth_type() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();
        let create = serde_json::json!({ "AuthType": "BOGUS" });
        let err = create_function_url_config(&store, "us-east-1", "000000000000", "fn", &create)
            .unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
    }

    #[test]
    fn url_config_missing_function_is_not_found() {
        let store = FunctionStore::new();
        let create = serde_json::json!({ "AuthType": "NONE" });
        let err = create_function_url_config(&store, "us-east-1", "000000000000", "nope", &create)
            .unwrap_err();
        assert!(matches!(err, LambdaError::ResourceNotFound(_)));
    }

    // ---- Event-invoke config ----

    #[test]
    fn event_invoke_config_lifecycle() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();

        let put = serde_json::json!({ "MaximumRetryAttempts": 1, "MaximumEventAgeInSeconds": 120 });
        let (status, body) =
            put_function_event_invoke_config(&store, "us-east-1", "000000000000", "fn", &put)
                .unwrap();
        assert_eq!(status, 200);
        let cfg = body.unwrap();
        assert_eq!(cfg["MaximumRetryAttempts"], 1);
        assert_eq!(cfg["MaximumEventAgeInSeconds"], 120);
        assert_eq!(
            cfg["FunctionArn"],
            "arn:aws:lambda:us-east-1:000000000000:function:fn"
        );

        // update merges: only change retries, age preserved
        let update = serde_json::json!({ "MaximumRetryAttempts": 2 });
        let (_, body) =
            update_function_event_invoke_config(&store, "us-east-1", "000000000000", "fn", &update)
                .unwrap();
        let cfg = body.unwrap();
        assert_eq!(cfg["MaximumRetryAttempts"], 2);
        assert_eq!(cfg["MaximumEventAgeInSeconds"], 120);

        let (status, _) =
            get_function_event_invoke_config(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(status, 200);

        let (_, body) =
            list_function_event_invoke_configs(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(
            body.unwrap()["FunctionEventInvokeConfigs"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let (status, _) =
            delete_function_event_invoke_config(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert_eq!(status, 204);
        let err = get_function_event_invoke_config(&store, "us-east-1", "000000000000", "fn")
            .unwrap_err();
        assert!(matches!(err, LambdaError::ResourceNotFound(_)));

        // list now empty (function still exists)
        let (_, body) =
            list_function_event_invoke_configs(&store, "us-east-1", "000000000000", "fn").unwrap();
        assert!(body.unwrap()["FunctionEventInvokeConfigs"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn event_invoke_config_validates_ranges() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();

        let bad_retry = serde_json::json!({ "MaximumRetryAttempts": 3 });
        let err =
            put_function_event_invoke_config(&store, "us-east-1", "000000000000", "fn", &bad_retry)
                .unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));

        let bad_age = serde_json::json!({ "MaximumEventAgeInSeconds": 30 });
        let err =
            put_function_event_invoke_config(&store, "us-east-1", "000000000000", "fn", &bad_age)
                .unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
    }

    #[test]
    fn event_invoke_update_without_existing_is_not_found() {
        let store = FunctionStore::new();
        create_function(&store, "us-east-1", "000000000000", &create_input("fn")).unwrap();
        let update = serde_json::json!({ "MaximumRetryAttempts": 1 });
        let err =
            update_function_event_invoke_config(&store, "us-east-1", "000000000000", "fn", &update)
                .unwrap_err();
        assert!(matches!(err, LambdaError::ResourceNotFound(_)));
    }

    // ---- Layers ----

    fn layer_input() -> Value {
        serde_json::json!({
            "Description": "shared deps",
            "Content": { "ZipFile": zip_base64(b"module.exports={}") },
            "CompatibleRuntimes": ["nodejs22.x"],
            "CompatibleArchitectures": ["x86_64"]
        })
    }

    #[test]
    fn layer_publish_increments_versions() {
        let store = LayerStore::new();
        let (status, body) =
            publish_layer_version(&store, "us-east-1", "000000000000", "libs", &layer_input())
                .unwrap();
        assert_eq!(status, 201);
        let v1 = body.unwrap();
        assert_eq!(v1["Version"], 1);
        assert_eq!(
            v1["LayerArn"],
            "arn:aws:lambda:us-east-1:000000000000:layer:libs"
        );
        assert_eq!(
            v1["LayerVersionArn"],
            "arn:aws:lambda:us-east-1:000000000000:layer:libs:1"
        );
        assert!(v1["Content"]["CodeSize"].as_u64().unwrap() > 0);

        let (_, body) =
            publish_layer_version(&store, "us-east-1", "000000000000", "libs", &layer_input())
                .unwrap();
        assert_eq!(body.unwrap()["Version"], 2);

        let (status, body) =
            get_layer_version(&store, "us-east-1", "000000000000", "libs", "1").unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.unwrap()["Version"], 1);

        let (_, body) = list_layer_versions(&store, "us-east-1", "000000000000", "libs").unwrap();
        let versions = body.unwrap();
        let labels: Vec<u64> = versions["LayerVersions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["Version"].as_u64().unwrap())
            .collect();
        assert_eq!(labels, vec![2, 1]);

        let (_, body) = list_layers(&store, "us-east-1", "000000000000").unwrap();
        let layers = body.unwrap();
        assert_eq!(layers["Layers"].as_array().unwrap().len(), 1);
        assert_eq!(layers["Layers"][0]["LayerName"], "libs");
        assert_eq!(layers["Layers"][0]["LatestMatchingVersion"]["Version"], 2);
    }

    #[test]
    fn layer_delete_then_get_is_not_found() {
        let store = LayerStore::new();
        publish_layer_version(&store, "us-east-1", "000000000000", "libs", &layer_input()).unwrap();
        let (status, _) =
            delete_layer_version(&store, "us-east-1", "000000000000", "libs", "1").unwrap();
        assert_eq!(status, 204);
        let err = get_layer_version(&store, "us-east-1", "000000000000", "libs", "1").unwrap_err();
        assert!(matches!(err, LambdaError::ResourceNotFound(_)));
        assert!(store
            .get_version("000000000000", "us-east-1", "libs", 1)
            .is_none());
        assert!(store
            .get_version_for_execution("000000000000", "us-east-1", "libs", 1)
            .is_some());
        let (_, listed) = list_layer_versions(&store, "us-east-1", "000000000000", "libs").unwrap();
        assert!(listed.unwrap()["LayerVersions"]
            .as_array()
            .unwrap()
            .is_empty());
        let err =
            delete_layer_version(&store, "us-east-1", "000000000000", "libs", "1").unwrap_err();
        assert!(matches!(err, LambdaError::ResourceNotFound(_)));
    }

    #[test]
    fn layer_get_missing_version_is_not_found() {
        let store = LayerStore::new();
        let err = get_layer_version(&store, "us-east-1", "000000000000", "libs", "9").unwrap_err();
        assert!(matches!(err, LambdaError::ResourceNotFound(_)));
    }

    #[test]
    fn layer_publish_requires_content() {
        let store = LayerStore::new();
        let err = publish_layer_version(
            &store,
            "us-east-1",
            "000000000000",
            "libs",
            &serde_json::json!({ "Description": "no content" }),
        )
        .unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
    }
}
