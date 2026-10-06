//! Step Functions operations: control plane and execution lifecycle. `StartExecution`
//! spawns the interpreter, which drives the workflow and cross-service Task integrations.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use serde_json::{json, Value};
use uuid::Uuid;

use locallycloud_core::registry::ServiceRegistry;

use crate::asl::{validate_single_state, StateMachine, MAX_DEFINITION_BYTES};
use crate::clock::{now_epoch, now_iso};
use crate::error::{AslError, SfnError};
use crate::interpreter::{Interpreter, TestStateMock};
use crate::store::{
    AliasRouting, Execution, InsertExecutionResult, SfnStore, StateMachineAlias,
    StateMachineRecord, StateMachineStatus, Status,
};

pub struct Ctx<'a> {
    pub store: &'a SfnStore,
    pub registry: Weak<ServiceRegistry>,
    pub region: &'a str,
    pub account: &'a str,
    pub request_id: &'a str,
}

impl Ctx<'_> {
    fn execution(&self, arn: &str) -> Result<Arc<crate::store::ExecutionCell>, SfnError> {
        let prefix = format!("arn:aws:states:{}:{}:execution:", self.region, self.account);
        if !arn.starts_with(&prefix) {
            return Err(SfnError::ExecutionDoesNotExist(format!(
                "{arn} does not exist"
            )));
        }
        self.store
            .get_execution(arn)
            .ok_or_else(|| SfnError::ExecutionDoesNotExist(format!("{arn} does not exist")))
    }
    fn pending_task(&self, token: &str) -> Result<Arc<crate::store::PendingTask>, SfnError> {
        let prefix = format!("arn:aws:states:{}:{}:", self.region, self.account);
        self.store
            .get_pending_task(token)
            .filter(|task| task.execution_arn.starts_with(&prefix))
            .ok_or_else(|| SfnError::TaskDoesNotExist("task token does not exist".into()))
    }
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn req_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, SfnError> {
    str_field(v, key).ok_or_else(|| SfnError::Validation(format!("{key} is required")))
}

fn validate_role_arn(role_arn: &str) -> Result<(), SfnError> {
    if !role_arn.starts_with("arn:aws:iam::") || !role_arn.contains(":role/") {
        return Err(SfnError::Validation(
            "roleArn must be an IAM role ARN".into(),
        ));
    }
    Ok(())
}

fn validate_tracing_configuration(value: Option<&Value>) -> Result<(), SfnError> {
    let Some(value) = value else { return Ok(()) };
    let object = value.as_object().ok_or_else(|| {
        SfnError::InvalidTracingConfiguration("tracingConfiguration must be an object".into())
    })?;
    if object
        .get("enabled")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(SfnError::InvalidTracingConfiguration(
            "tracingConfiguration.enabled must be boolean".into(),
        ));
    }
    Ok(())
}

fn validate_encryption_configuration(value: Option<&Value>) -> Result<(), SfnError> {
    let Some(value) = value else { return Ok(()) };
    let object = value.as_object().ok_or_else(|| {
        SfnError::InvalidEncryptionConfiguration("encryptionConfiguration must be an object".into())
    })?;
    let encryption_type = object.get("type").and_then(Value::as_str).ok_or_else(|| {
        SfnError::InvalidEncryptionConfiguration("encryptionConfiguration.type is required".into())
    })?;
    if !matches!(
        encryption_type,
        "AWS_OWNED_KEY" | "CUSTOMER_MANAGED_KMS_KEY"
    ) {
        return Err(SfnError::InvalidEncryptionConfiguration(
            "encryptionConfiguration.type is invalid".into(),
        ));
    }
    if encryption_type == "CUSTOMER_MANAGED_KMS_KEY"
        && object.get("kmsKeyId").and_then(Value::as_str).is_none()
    {
        return Err(SfnError::InvalidEncryptionConfiguration(
            "CUSTOMER_MANAGED_KMS_KEY requires kmsKeyId".into(),
        ));
    }
    if let Some(period) = object.get("kmsDataKeyReusePeriodSeconds") {
        if !period
            .as_u64()
            .is_some_and(|period| (60..=900).contains(&period))
        {
            return Err(SfnError::InvalidEncryptionConfiguration(
                "kmsDataKeyReusePeriodSeconds must be between 60 and 900".into(),
            ));
        }
    }
    Ok(())
}

fn pagination_offset(v: &Value) -> Result<usize, SfnError> {
    str_field(v, "nextToken")
        .map(|token| {
            token
                .parse::<usize>()
                .map_err(|_| SfnError::Validation("nextToken is invalid".into()))
        })
        .transpose()
        .map(|offset| offset.unwrap_or(0))
}

fn max_results(v: &Value, default: usize, maximum: usize) -> usize {
    v.get("maxResults")
        .and_then(Value::as_u64)
        .unwrap_or(default as u64)
        .clamp(1, maximum as u64) as usize
}

fn sm_arn(region: &str, account: &str, name: &str) -> String {
    format!("arn:aws:states:{region}:{account}:stateMachine:{name}")
}

/// A state-machine target may be the mutable base resource or an immutable numeric version.
struct StateMachineTarget {
    name: String,
    version: Option<u64>,
    alias: Option<String>,
}

/// Parse an ARN in the current account/region scope without losing a numeric qualifier.
fn parse_sm_target(ctx: &Ctx<'_>, arn: &str) -> Result<StateMachineTarget, SfnError> {
    let prefix = format!(
        "arn:aws:states:{}:{}:stateMachine:",
        ctx.region, ctx.account
    );
    let resource = arn
        .strip_prefix(&prefix)
        .ok_or_else(|| SfnError::InvalidArn(arn.to_string()))?;
    let mut parts = resource.split(':');
    let name = parts
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| SfnError::InvalidArn(arn.to_string()))?;
    let qualifier = parts.next();
    if parts.next().is_some() {
        return Err(SfnError::InvalidArn(arn.to_string()));
    }
    let (version, alias) = match qualifier {
        Some("") => return Err(SfnError::InvalidArn(arn.to_string())),
        Some(value) => match value.parse::<u64>() {
            Ok(0) => return Err(SfnError::InvalidArn(arn.to_string())),
            Ok(number) => (Some(number), None),
            Err(_) => (None, Some(value.to_string())),
        },
        None => (None, None),
    };
    Ok(StateMachineTarget {
        name: name.to_string(),
        version,
        alias,
    })
}

fn immutable_version_error(arn: &str) -> SfnError {
    SfnError::Validation(format!("State machine version {arn} is immutable"))
}

// ============================ control plane ====================================

pub async fn create_state_machine(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let name = req_str(v, "name")?.to_string();
    if name.len() > 80
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(SfnError::InvalidName(format!(
            "State machine name {name} is invalid"
        )));
    }
    let definition = req_str(v, "definition")?.to_string();
    let role_arn = req_str(v, "roleArn")?.to_string();
    validate_role_arn(&role_arn)?;
    let type_ = str_field(v, "type").unwrap_or("STANDARD").to_string();
    if !matches!(type_.as_str(), "STANDARD" | "EXPRESS") {
        return Err(SfnError::Validation(
            "type must be STANDARD or EXPRESS".into(),
        ));
    }
    StateMachine::parse_for_type(&definition, Some(&type_))?;
    let arn = sm_arn(ctx.region, ctx.account, &name);
    let logging_configuration = v.get("loggingConfiguration").cloned();
    let tracing_configuration = v.get("tracingConfiguration").cloned();
    let encryption_configuration = v.get("encryptionConfiguration").cloned();
    crate::logging::preflight_configuration(
        logging_configuration.as_ref(),
        &ctx.registry,
        ctx.region,
        ctx.account,
    )
    .await?;
    validate_tracing_configuration(tracing_configuration.as_ref())?;
    validate_encryption_configuration(encryption_configuration.as_ref())?;

    if let Some(handle) = ctx.store.get_machine(ctx.account, ctx.region, &name) {
        let existing = handle.read().await;
        if existing.status == StateMachineStatus::Deleting {
            return Err(SfnError::StateMachineDeleting(format!(
                "State machine {arn} is deleting"
            )));
        }
        if existing.definition == definition
            && existing.role_arn == role_arn
            && existing.type_ == type_
            && existing.logging_configuration == logging_configuration
            && existing.tracing_configuration == tracing_configuration
            && existing.encryption_configuration == encryption_configuration
        {
            return Ok(json!({
                "stateMachineArn": existing.arn,
                "creationDate": existing.creation_epoch,
                "revisionId": existing.revision_id,
            }));
        }
        return Err(SfnError::StateMachineAlreadyExists(format!(
            "state machine {arn} already exists"
        )));
    }

    let tags = parse_tags(v);
    let revision_id = Uuid::new_v4().to_string();
    let creation_epoch = now_epoch();
    let mut rec = StateMachineRecord {
        arn: arn.clone(),
        name,
        definition,
        role_arn,
        type_,
        status: StateMachineStatus::Active,
        creation_date: now_iso(),
        creation_epoch,
        revision_id: revision_id.clone(),
        logging_configuration,
        tracing_configuration,
        encryption_configuration,
        tags,
        versions: BTreeMap::new(),
        aliases: BTreeMap::new(),
    };
    let published = if v.get("publish").and_then(Value::as_bool).unwrap_or(false) {
        Some(rec.publish_version(
            str_field(v, "versionDescription").map(String::from),
            creation_epoch,
        ))
    } else {
        None
    };
    match ctx
        .store
        .create_machine_bounded(ctx.account, ctx.region, rec)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Err(SfnError::StateMachineAlreadyExists(format!(
                "state machine {arn} already exists"
            )));
        }
        Err(_) => {
            return Err(SfnError::StateMachineLimitExceeded(format!(
                "State machine quota exceeded for {} in {}",
                ctx.account, ctx.region
            )));
        }
    }
    let mut response = json!({
        "stateMachineArn": arn,
        "creationDate": creation_epoch,
        "revisionId": revision_id,
    });
    if let Some(version) = published {
        response
            .as_object_mut()
            .unwrap()
            .insert("stateMachineVersionArn".into(), json!(version.arn));
    }
    Ok(response)
}

pub async fn describe_state_machine(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "stateMachineArn")?;
    let target = parse_sm_target(ctx, arn)?;
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
    let rec = handle.read().await;
    if let Some(number) = target.version {
        let version = rec
            .versions
            .get(&number)
            .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
        let mut response = json!({
            "stateMachineArn": version.arn,
            "name": rec.name,
            "definition": version.definition,
            "roleArn": version.role_arn,
            "type": rec.type_,
            "creationDate": version.creation_date,
            "revisionId": version.revision_id,
            "label": version.version.to_string(),
            "status": "ACTIVE",
        });
        if let Some(description) = &version.description {
            response
                .as_object_mut()
                .unwrap()
                .insert("description".into(), json!(description));
        }
        return Ok(response);
    }
    if let Some(alias_name) = &target.alias {
        let alias = rec
            .aliases
            .get(alias_name)
            .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
        let number = choose_alias_version(&alias.routing_configuration)
            .ok_or_else(|| SfnError::Validation(format!("Alias {arn} has no routable version")))?;
        let version = rec
            .versions
            .get(&number)
            .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
        return Ok(json!({
            "stateMachineArn": alias.arn,
            "name": rec.name,
            "definition": version.definition,
            "roleArn": version.role_arn,
            "type": rec.type_,
            "creationDate": alias.creation_date,
            "revisionId": version.revision_id,
            "label": alias.name,
            "status": "ACTIVE",
        }));
    }
    let mut response = json!({
        "stateMachineArn": rec.arn,
        "name": rec.name,
        "definition": rec.definition,
        "roleArn": rec.role_arn,
        "type": rec.type_,
        "creationDate": rec.creation_epoch,
        "revisionId": rec.revision_id,
        "status": rec.status.as_str(),
    });
    let object = response.as_object_mut().unwrap();
    if let Some(configuration) = &rec.logging_configuration {
        object.insert("loggingConfiguration".into(), configuration.clone());
    }
    if let Some(configuration) = &rec.tracing_configuration {
        object.insert("tracingConfiguration".into(), configuration.clone());
    }
    if let Some(configuration) = &rec.encryption_configuration {
        object.insert("encryptionConfiguration".into(), configuration.clone());
    }
    Ok(response)
}

pub async fn update_state_machine(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "stateMachineArn")?;
    let target = parse_sm_target(ctx, arn)?;
    if target.version.is_some() || target.alias.is_some() {
        return Err(immutable_version_error(arn));
    }
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
    if let Some(definition) = str_field(v, "definition") {
        let machine_type = handle.read().await.type_.clone();
        StateMachine::parse_for_type(definition, Some(&machine_type))?;
    }
    if let Some(role_arn) = str_field(v, "roleArn") {
        validate_role_arn(role_arn)?;
    }
    crate::logging::preflight_configuration(
        v.get("loggingConfiguration"),
        &ctx.registry,
        ctx.region,
        ctx.account,
    )
    .await?;
    validate_tracing_configuration(v.get("tracingConfiguration"))?;
    validate_encryption_configuration(v.get("encryptionConfiguration"))?;
    let mut rec = handle.write().await;
    if rec.status == StateMachineStatus::Deleting {
        return Err(SfnError::StateMachineDeleting(format!(
            "State machine {arn} is deleting"
        )));
    }
    let mut changed = false;
    if let Some(definition) = str_field(v, "definition") {
        rec.definition = definition.to_string();
        changed = true;
    }
    if let Some(role_arn) = str_field(v, "roleArn") {
        rec.role_arn = role_arn.to_string();
        changed = true;
    }
    if let Some(configuration) = v.get("loggingConfiguration") {
        rec.logging_configuration = Some(configuration.clone());
        changed = true;
    }
    if let Some(configuration) = v.get("tracingConfiguration") {
        rec.tracing_configuration = Some(configuration.clone());
        changed = true;
    }
    if let Some(configuration) = v.get("encryptionConfiguration") {
        rec.encryption_configuration = Some(configuration.clone());
        changed = true;
    }
    if changed {
        rec.revision_id = Uuid::new_v4().to_string();
    }
    let published = if v.get("publish").and_then(Value::as_bool).unwrap_or(false) {
        Some(rec.publish_version(
            str_field(v, "versionDescription").map(String::from),
            now_epoch(),
        ))
    } else {
        None
    };
    let mut response = json!({ "updateDate": now_epoch(), "revisionId": rec.revision_id });
    if let Some(version) = published {
        response
            .as_object_mut()
            .unwrap()
            .insert("stateMachineVersionArn".into(), json!(version.arn));
    }
    Ok(response)
}

pub async fn delete_state_machine(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "stateMachineArn")?;
    let target = parse_sm_target(ctx, arn)?;
    if target.version.is_some() || target.alias.is_some() {
        return Err(immutable_version_error(arn));
    }
    let Some(handle) = ctx.store.get_machine(ctx.account, ctx.region, &target.name) else {
        return Ok(json!({}));
    };
    {
        let mut machine = handle.write().await;
        if machine.status == StateMachineStatus::Deleting {
            return Ok(json!({}));
        }
        machine.status = StateMachineStatus::Deleting;
    }

    let store = (*ctx.store).clone();
    let account = ctx.account.to_string();
    let region = ctx.region.to_string();
    let name = target.name;
    tokio::spawn(async move {
        // Preserve an observable DELETING state before completing the asynchronous delete.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        store
            .wait_for_execution_workers(&account, &region, &name)
            .await;
        let _configuration = store.configuration_gate.write().await;
        if !store.healthy() {
            return;
        }
        store.remove_machine(&account, &region, &name);
        let _ = store.persist_scope(&account, &region).await;
    });
    Ok(json!({}))
}

pub async fn list_state_machines(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let offset = pagination_offset(v)?;
    let max_results = max_results(v, 100, 1000);
    let handles = ctx.store.list_machines(ctx.account, ctx.region);
    let total = handles.len();
    let mut machines = Vec::new();
    for handle in handles.into_iter().skip(offset).take(max_results) {
        let record = handle.read().await;
        machines.push(json!({
            "stateMachineArn": record.arn,
            "name": record.name,
            "type": record.type_,
            "creationDate": record.creation_epoch,
        }));
    }
    let mut response = json!({ "stateMachines": machines });
    let consumed = offset + response["stateMachines"].as_array().map_or(0, Vec::len);
    if consumed < total {
        response
            .as_object_mut()
            .unwrap()
            .insert("nextToken".into(), json!(consumed.to_string()));
    }
    Ok(response)
}

pub async fn publish_state_machine_version(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "stateMachineArn")?;
    let target = parse_sm_target(ctx, arn)?;
    if target.version.is_some() || target.alias.is_some() {
        return Err(immutable_version_error(arn));
    }
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
    let mut rec = handle.write().await;
    if rec.status == StateMachineStatus::Deleting {
        return Err(SfnError::StateMachineDeleting(format!(
            "State machine {arn} is deleting"
        )));
    }
    if let Some(revision_id) = str_field(v, "revisionId") {
        if revision_id != rec.revision_id {
            return Err(SfnError::Validation(format!(
                "Revision {revision_id} does not match the current state machine revision"
            )));
        }
    }
    let version = rec.publish_version(str_field(v, "description").map(String::from), now_epoch());
    Ok(json!({
        "stateMachineVersionArn": version.arn,
        "creationDate": version.creation_date,
    }))
}

pub async fn list_state_machine_versions(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "stateMachineArn")?;
    let target = parse_sm_target(ctx, arn)?;
    if target.version.is_some() || target.alias.is_some() {
        return Err(SfnError::InvalidArn(arn.to_string()));
    }
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
    let rec = handle.read().await;
    let offset = str_field(v, "nextToken")
        .map(|token| {
            token
                .parse::<usize>()
                .map_err(|_| SfnError::Validation("nextToken is invalid".into()))
        })
        .transpose()?
        .unwrap_or(0);
    let max_results = v
        .get("maxResults")
        .and_then(Value::as_u64)
        .unwrap_or(100)
        .clamp(1, 1000) as usize;
    let versions: Vec<_> = rec
        .versions
        .values()
        .rev()
        .skip(offset)
        .take(max_results)
        .collect();
    let mut response = json!({
        "stateMachineVersions": versions
            .iter()
            .map(|version| json!({
                "stateMachineVersionArn": version.arn,
                "version": version.version.to_string(),
                "creationDate": version.creation_date,
            }))
            .collect::<Vec<_>>()
    });
    let consumed = offset + versions.len();
    if consumed < rec.versions.len() {
        response
            .as_object_mut()
            .unwrap()
            .insert("nextToken".into(), json!(consumed.to_string()));
    }
    Ok(response)
}

pub async fn create_state_machine_alias(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let name = req_str(v, "name")?;
    if name.parse::<u64>().is_ok() || name.contains(':') {
        return Err(SfnError::InvalidName(format!(
            "Alias name {name} is invalid"
        )));
    }
    let routes = v
        .get("routingConfiguration")
        .and_then(Value::as_array)
        .ok_or_else(|| SfnError::Validation("routingConfiguration is required".into()))?;
    let first_arn = routes
        .first()
        .and_then(|route| str_field(route, "stateMachineVersionArn"))
        .ok_or_else(|| {
            SfnError::Validation("routingConfiguration must contain a version".into())
        })?;
    let first_target = parse_sm_target(ctx, first_arn)?;
    if first_target.version.is_none() || first_target.alias.is_some() {
        return Err(SfnError::Validation(format!(
            "{first_arn} is not a state machine version ARN"
        )));
    }
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &first_target.name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{first_arn} does not exist")))?;
    let mut rec = handle.write().await;
    if rec.status == StateMachineStatus::Deleting {
        return Err(SfnError::StateMachineDeleting(format!(
            "State machine {} is deleting",
            rec.arn
        )));
    }
    if rec.aliases.contains_key(name) {
        return Err(SfnError::Validation(format!(
            "State machine alias {name} already exists"
        )));
    }
    let routing_configuration = parse_alias_routing(ctx, &rec, v)?;
    let timestamp = now_epoch();
    let arn = format!("{}:{name}", rec.arn);
    rec.aliases.insert(
        name.to_string(),
        StateMachineAlias {
            arn: arn.clone(),
            name: name.to_string(),
            routing_configuration,
            description: str_field(v, "description").map(String::from),
            creation_date: timestamp,
            update_date: timestamp,
            tags: parse_tags(v),
        },
    );
    Ok(json!({ "stateMachineAliasArn": arn, "creationDate": timestamp }))
}

pub async fn update_state_machine_alias(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "stateMachineAliasArn")?;
    let target = parse_sm_target(ctx, arn)?;
    let alias_name = target
        .alias
        .ok_or_else(|| SfnError::InvalidArn(arn.to_string()))?;
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
    let mut rec = handle.write().await;
    if rec.status == StateMachineStatus::Deleting {
        return Err(SfnError::StateMachineDeleting(format!(
            "State machine {} is deleting",
            rec.arn
        )));
    }
    if !rec.aliases.contains_key(&alias_name) {
        return Err(SfnError::StateMachineDoesNotExist(format!(
            "{arn} does not exist"
        )));
    }
    let routing = if v.get("routingConfiguration").is_some() {
        Some(parse_alias_routing(ctx, &rec, v)?)
    } else {
        None
    };
    let alias = rec
        .aliases
        .get_mut(&alias_name)
        .expect("alias existence checked");
    if let Some(routing) = routing {
        alias.routing_configuration = routing;
    }
    if let Some(description) = str_field(v, "description") {
        alias.description = Some(description.to_string());
    }
    alias.update_date = now_epoch();
    Ok(json!({ "updateDate": alias.update_date }))
}

pub async fn describe_state_machine_alias(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "stateMachineAliasArn")?;
    let target = parse_sm_target(ctx, arn)?;
    let alias_name = target
        .alias
        .ok_or_else(|| SfnError::InvalidArn(arn.to_string()))?;
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
    let rec = handle.read().await;
    let alias = rec
        .aliases
        .get(&alias_name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
    let mut response = json!({
        "stateMachineAliasArn": alias.arn,
        "name": alias.name,
        "routingConfiguration": routing_json(&alias.routing_configuration),
        "creationDate": alias.creation_date,
        "updateDate": alias.update_date,
    });
    if let Some(description) = &alias.description {
        response
            .as_object_mut()
            .unwrap()
            .insert("description".into(), json!(description));
    }
    Ok(response)
}

pub async fn delete_state_machine_alias(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "stateMachineAliasArn")?;
    let target = parse_sm_target(ctx, arn)?;
    let alias_name = target
        .alias
        .ok_or_else(|| SfnError::InvalidArn(arn.to_string()))?;
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
    let removed = handle.write().await.aliases.remove(&alias_name);
    if removed.is_none() {
        return Err(SfnError::StateMachineDoesNotExist(format!(
            "{arn} does not exist"
        )));
    }
    Ok(json!({}))
}

pub async fn list_state_machine_aliases(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "stateMachineArn")?;
    let target = parse_sm_target(ctx, arn)?;
    if target.version.is_some() || target.alias.is_some() {
        return Err(SfnError::InvalidArn(arn.to_string()));
    }
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
    let rec = handle.read().await;
    let offset = str_field(v, "nextToken")
        .map(|token| {
            token
                .parse::<usize>()
                .map_err(|_| SfnError::Validation("nextToken is invalid".into()))
        })
        .transpose()?
        .unwrap_or(0);
    let max_results = v
        .get("maxResults")
        .and_then(Value::as_u64)
        .unwrap_or(100)
        .clamp(1, 1000) as usize;
    let aliases: Vec<_> = rec
        .aliases
        .values()
        .skip(offset)
        .take(max_results)
        .collect();
    let mut response = json!({
        "stateMachineAliases": aliases
            .iter()
            .map(|alias| json!({
                "stateMachineAliasArn": alias.arn,
                "creationDate": alias.creation_date,
            }))
            .collect::<Vec<_>>()
    });
    let consumed = offset + aliases.len();
    if consumed < rec.aliases.len() {
        response
            .as_object_mut()
            .unwrap()
            .insert("nextToken".into(), json!(consumed.to_string()));
    }
    Ok(response)
}

fn parse_alias_routing(
    ctx: &Ctx<'_>,
    rec: &StateMachineRecord,
    v: &Value,
) -> Result<Vec<AliasRouting>, SfnError> {
    let routes = v
        .get("routingConfiguration")
        .and_then(Value::as_array)
        .ok_or_else(|| SfnError::Validation("routingConfiguration is required".into()))?;
    if !(1..=2).contains(&routes.len()) {
        return Err(SfnError::Validation(
            "routingConfiguration must contain one or two versions".into(),
        ));
    }
    let mut parsed = Vec::with_capacity(routes.len());
    for route in routes {
        let version_arn = req_str(route, "stateMachineVersionArn")?;
        let target = parse_sm_target(ctx, version_arn)?;
        let version = target.version.ok_or_else(|| {
            SfnError::Validation(format!("{version_arn} is not a state machine version ARN"))
        })?;
        if target.name != rec.name || target.alias.is_some() || !rec.versions.contains_key(&version)
        {
            return Err(SfnError::Validation(format!(
                "State machine version {version_arn} does not exist"
            )));
        }
        let weight = route
            .get("weight")
            .and_then(Value::as_u64)
            .ok_or_else(|| SfnError::Validation("routing weight is required".into()))?;
        if weight > 100 {
            return Err(SfnError::Validation(
                "routing weight must be between 0 and 100".into(),
            ));
        }
        if parsed
            .iter()
            .any(|existing: &AliasRouting| existing.version == version)
        {
            return Err(SfnError::Validation(
                "routingConfiguration contains a duplicate version".into(),
            ));
        }
        parsed.push(AliasRouting {
            state_machine_version_arn: version_arn.to_string(),
            version,
            weight: weight as u32,
        });
    }
    if parsed.iter().map(|route| route.weight).sum::<u32>() != 100 {
        return Err(SfnError::Validation(
            "routing weights must sum to 100".into(),
        ));
    }
    Ok(parsed)
}

fn routing_json(routes: &[AliasRouting]) -> Vec<Value> {
    routes
        .iter()
        .map(|route| {
            json!({
                "stateMachineVersionArn": route.state_machine_version_arn,
                "weight": route.weight,
            })
        })
        .collect()
}

fn choose_alias_version(routes: &[AliasRouting]) -> Option<u64> {
    let sample = (Uuid::new_v4().as_u128() % 100) as u32;
    let mut upper = 0u32;
    for route in routes {
        upper = upper.saturating_add(route.weight);
        if sample < upper {
            return Some(route.version);
        }
    }
    routes.last().map(|route| route.version)
}

pub async fn validate_state_machine_definition(
    _ctx: &Ctx<'_>,
    v: &Value,
) -> Result<Value, SfnError> {
    let definition = req_str(v, "definition")?;
    let machine_type = str_field(v, "type");
    if machine_type.is_some_and(|value| !matches!(value, "STANDARD" | "EXPRESS")) {
        return Err(SfnError::Validation(
            "type must be STANDARD or EXPRESS".into(),
        ));
    }
    let all_diagnostics = StateMachine::diagnostics(definition, machine_type);
    let maximum = max_results(v, 100, 100);
    let truncated = all_diagnostics.len() > maximum;
    let diagnostics: Vec<Value> = all_diagnostics
        .into_iter()
        .take(maximum)
        .map(|message| {
            json!({
                "severity": "ERROR",
                "code": "SCHEMA_VALIDATION_FAILED",
                "message": message,
            })
        })
        .collect();
    Ok(json!({
        "result": if diagnostics.is_empty() { "OK" } else { "FAIL" },
        "diagnostics": diagnostics,
        "truncated": truncated,
    }))
}

pub async fn test_state(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let definition = req_str(v, "definition")?;
    if definition.len() > MAX_DEFINITION_BYTES {
        return Err(SfnError::Validation(format!(
            "definition exceeds the {MAX_DEFINITION_BYTES}-byte limit"
        )));
    }
    let state: Value = serde_json::from_str(definition).map_err(|error| {
        SfnError::InvalidDefinition(format!("definition is not valid JSON: {error}"))
    })?;
    let diagnostics = validate_single_state(&state);
    if let Some(message) = diagnostics.first() {
        return Err(SfnError::InvalidDefinition(message.clone()));
    }
    let inspection_level = str_field(v, "inspectionLevel").unwrap_or("INFO");
    if !matches!(inspection_level, "INFO" | "DEBUG" | "TRACE") {
        return Err(SfnError::Validation(
            "inspectionLevel must be INFO, DEBUG, or TRACE".into(),
        ));
    }
    let input = match str_field(v, "input") {
        Some(input) => serde_json::from_str(input)
            .map_err(|error| SfnError::InvalidExecutionInput(error.to_string()))?,
        None => json!({}),
    };
    validate_payload_size(&input)?;
    let variables = parse_json_object_field(v.get("variables"), "variables")?;
    let mock = parse_test_state_mock(v.get("mock"))?;
    let state_type = state
        .get("Type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let resource = state
        .get("Resource")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let requires_mock = matches!(state_type, "Map" | "Parallel")
        || (state_type == "Task"
            && (resource.contains(":activity:")
                || resource.ends_with(".sync")
                || resource.ends_with(".sync:2")
                || resource.ends_with(".waitForTaskToken")));
    if requires_mock && mock.is_none() {
        return Err(SfnError::Validation(
            "TestState requires mock for Map, Parallel, Activity, .sync, and callback states"
                .into(),
        ));
    }
    let initial_retry_count = parse_test_state_configuration(v.get("stateConfiguration"))?;
    if let Some(role_arn) = str_field(v, "roleArn") {
        validate_role_arn(role_arn)?;
    }
    if state_type == "Task" && mock.is_none() && str_field(v, "roleArn").is_none() {
        return Err(SfnError::Validation(
            "roleArn is required for a Task when mock is omitted".into(),
        ));
    }
    let context_override = match v.get("context") {
        Some(_) if mock.is_none() => {
            return Err(SfnError::Validation("context requires mock".into()))
        }
        value => parse_optional_json_value(value, "context")?,
    };
    let state_name = str_field(v, "stateName").unwrap_or("TestState").to_string();
    let mut states = serde_json::Map::new();
    states.insert(state_name.clone(), state.clone());
    let machine_definition = json!({
        "StartAt": state_name,
        "QueryLanguage": state.get("QueryLanguage").and_then(Value::as_str).unwrap_or("JSONPath"),
        "States": states,
    });
    let machine = Arc::new(StateMachine {
        start_at: state_name.clone(),
        states: machine_definition
            .get("States")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default(),
        definition: machine_definition,
    });
    let mut interpreter = interpreter_for(
        ctx,
        machine,
        "arn:aws:states:local:test:stateMachine:TestState".into(),
        "TestState".into(),
        str_field(v, "roleArn").unwrap_or_default().to_string(),
        "arn:aws:states:local:test:execution:TestState:TestState".into(),
        "TestState".into(),
        "STANDARD".into(),
        false,
    );
    interpreter.record_history = false;
    interpreter.test_mock = mock;
    interpreter.context_override = context_override;
    interpreter.execution_input = input.clone();
    interpreter.initial_retry_count = initial_retry_count;
    interpreter.test_state_mode = true;
    let outcome = interpreter
        .test_state(&state_name, &state, input, variables, inspection_level)
        .await;

    let mut response = json!({
        "status": outcome.status,
    });
    let object = response.as_object_mut().expect("response is an object");
    if let Some(next) = outcome.next_state {
        object.insert("nextState".into(), Value::String(next));
    }
    if let Some(output) = outcome.output {
        object.insert("output".into(), Value::String(output.to_string()));
    }
    if let Some(error) = outcome.error {
        object.insert("error".into(), Value::String(error.error));
        object.insert("cause".into(), Value::String(error.cause));
    }
    if let Some(mut inspection) = outcome.inspection_data {
        if let Some(data) = inspection
            .as_object_mut()
            .filter(|_| !outcome.variables.is_empty())
        {
            data.insert(
                "variables".into(),
                Value::String(Value::Object(outcome.variables.into_iter().collect()).to_string()),
            );
        }
        object.insert("inspectionData".into(), inspection);
    }
    Ok(response)
}

fn parse_json_object_field(
    value: Option<&Value>,
    field: &str,
) -> Result<BTreeMap<String, Value>, SfnError> {
    let Some(value) = parse_optional_json_value(value, field)? else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| SfnError::Validation(format!("{field} must be a JSON object")))?;
    Ok(object
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

fn parse_optional_json_value(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<Value>, SfnError> {
    match value {
        None => Ok(None),
        Some(Value::String(value)) => serde_json::from_str(value)
            .map(Some)
            .map_err(|error| SfnError::Validation(format!("{field} is not valid JSON: {error}"))),
        Some(value) => Ok(Some(value.clone())),
    }
}

fn parse_test_state_configuration(value: Option<&Value>) -> Result<u32, SfnError> {
    let Some(configuration) = value else {
        return Ok(0);
    };
    let object = configuration
        .as_object()
        .ok_or_else(|| SfnError::Validation("stateConfiguration must be an object".into()))?;
    let retry_count = object
        .get("retrierRetryCount")
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| {
                    SfnError::Validation(
                        "stateConfiguration.retrierRetryCount must be a non-negative 32-bit integer".into(),
                    )
                })
        })
        .transpose()?
        .unwrap_or(0);
    if object
        .get("errorCausedByState")
        .is_some_and(|value| !value.is_string())
    {
        return Err(SfnError::Validation(
            "stateConfiguration.errorCausedByState must be a string".into(),
        ));
    }
    if object
        .get("mapIterationFailureCount")
        .is_some_and(|value| value.as_u64().is_none())
    {
        return Err(SfnError::Validation(
            "stateConfiguration.mapIterationFailureCount must be a non-negative integer".into(),
        ));
    }
    if let Some(data) = object.get("mapItemReaderData") {
        let data = data.as_str().ok_or_else(|| {
            SfnError::Validation(
                "stateConfiguration.mapItemReaderData must be a JSON string".into(),
            )
        })?;
        serde_json::from_str::<Value>(data).map_err(|error| {
            SfnError::Validation(format!(
                "stateConfiguration.mapItemReaderData is not valid JSON: {error}"
            ))
        })?;
    }
    Ok(retry_count)
}

fn parse_test_state_mock(value: Option<&Value>) -> Result<Option<TestStateMock>, SfnError> {
    let Some(mock) = value else { return Ok(None) };
    let mock = mock
        .as_object()
        .ok_or_else(|| SfnError::Validation("mock must be an object".into()))?;
    if mock
        .get("fieldValidationMode")
        .and_then(Value::as_str)
        .is_some_and(|value| !matches!(value, "STRICT" | "PRESENT" | "NONE"))
    {
        return Err(SfnError::Validation(
            "mock.fieldValidationMode must be STRICT, PRESENT, or NONE".into(),
        ));
    }
    let result = parse_optional_json_value(mock.get("result"), "mock.result")?;
    let error =
        mock.get("errorOutput")
            .map(|error| {
                let error_name = error.get("error").and_then(Value::as_str).ok_or_else(|| {
                    SfnError::Validation("mock.errorOutput.error is required".into())
                })?;
                let cause = error
                    .get("cause")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                Ok::<_, SfnError>(AslError::new(error_name, cause))
            })
            .transpose()?;
    if result.is_some() == error.is_some() {
        return Err(SfnError::Validation(
            "mock must specify exactly one of result or errorOutput".into(),
        ));
    }
    Ok(Some(TestStateMock { result, error }))
}

// ============================ executions =======================================

struct ResolvedExecutionTarget {
    name: String,
    type_: String,
    definition: String,
    role_arn: String,
    logging_configuration: Option<Value>,
    tracing_configuration: Option<Value>,
    encryption_configuration: Option<Value>,
}

async fn resolve_execution_target(
    ctx: &Ctx<'_>,
    state_machine_arn: &str,
) -> Result<ResolvedExecutionTarget, SfnError> {
    let target = parse_sm_target(ctx, state_machine_arn)?;
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .ok_or_else(|| {
            SfnError::StateMachineDoesNotExist(format!("{state_machine_arn} does not exist"))
        })?;
    let rec = handle.read().await;
    if rec.status == StateMachineStatus::Deleting {
        return Err(SfnError::StateMachineDeleting(format!(
            "State machine {state_machine_arn} is deleting"
        )));
    }
    let (definition, role_arn) = if let Some(number) = target.version {
        let version = rec.versions.get(&number).ok_or_else(|| {
            SfnError::StateMachineDoesNotExist(format!("{state_machine_arn} does not exist"))
        })?;
        (version.definition.clone(), version.role_arn.clone())
    } else if let Some(alias_name) = &target.alias {
        let alias = rec.aliases.get(alias_name).ok_or_else(|| {
            SfnError::StateMachineDoesNotExist(format!("{state_machine_arn} does not exist"))
        })?;
        let number = choose_alias_version(&alias.routing_configuration).ok_or_else(|| {
            SfnError::Validation(format!("Alias {state_machine_arn} has no routable version"))
        })?;
        let version = rec.versions.get(&number).ok_or_else(|| {
            SfnError::StateMachineDoesNotExist(format!("{state_machine_arn} does not exist"))
        })?;
        (version.definition.clone(), version.role_arn.clone())
    } else {
        (rec.definition.clone(), rec.role_arn.clone())
    };
    Ok(ResolvedExecutionTarget {
        name: target.name,
        type_: rec.type_.clone(),
        definition,
        role_arn,
        logging_configuration: rec.logging_configuration.clone(),
        tracing_configuration: rec.tracing_configuration.clone(),
        encryption_configuration: rec.encryption_configuration.clone(),
    })
}

fn execution_input(v: &Value) -> Result<Value, SfnError> {
    match str_field(v, "input") {
        Some(raw) => serde_json::from_str(raw)
            .map_err(|_| SfnError::InvalidExecutionInput("input is not valid JSON".into())),
        None => Ok(json!({})),
    }
}

fn validate_execution_name(name: &str) -> Result<(), SfnError> {
    if name.len() > 80
        || name.is_empty()
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(SfnError::InvalidName(format!(
            "Execution name {name} is invalid"
        )));
    }
    Ok(())
}

fn validate_payload_size(value: &Value) -> Result<(), SfnError> {
    if serde_json::to_vec(value).map_or(true, |payload| payload.len() > 256 * 1024) {
        return Err(SfnError::Validation(
            "Execution input exceeds the 256 KiB limit".into(),
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "construction keeps execution identity fields explicit at lifecycle call sites"
)]
fn interpreter_for(
    ctx: &Ctx<'_>,
    sm: Arc<StateMachine>,
    state_machine_arn: String,
    state_machine_name: String,
    role_arn: String,
    execution_arn: String,
    execution_name: String,
    execution_type: String,
    logging_enabled: bool,
) -> Interpreter {
    let default_ql = sm
        .definition
        .get("QueryLanguage")
        .and_then(Value::as_str)
        .unwrap_or("JSONPath")
        .to_string();
    let record_history = execution_type == "STANDARD" || logging_enabled;
    Interpreter {
        sm,
        store: ctx.store.clone(),
        registry: ctx.registry.clone(),
        region: ctx.region.to_string(),
        account: ctx.account.to_string(),
        sm_arn: state_machine_arn,
        sm_name: state_machine_name,
        role_arn,
        exec_arn: execution_arn,
        exec_name: execution_name,
        execution_type,
        record_history,
        default_ql,
        test_mock: None,
        context_override: None,
        execution_input: json!({}),
        execution_start_time: now_iso(),
        initial_retry_count: 0,
        test_state_mode: false,
    }
}

pub async fn start_execution(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let configuration = ctx.store.configuration_gate.read().await;
    if !ctx.store.healthy() {
        return Err(SfnError::Internal(
            "Step Functions durable state is unavailable".into(),
        ));
    }
    let state_machine_arn = req_str(v, "stateMachineArn")?.to_string();
    let target = resolve_execution_target(ctx, &state_machine_arn).await?;
    crate::logging::preflight_configuration(
        target.logging_configuration.as_ref(),
        &ctx.registry,
        ctx.region,
        ctx.account,
    )
    .await?;
    let logging_enabled = crate::logging::is_enabled(
        target.logging_configuration.as_ref(),
        ctx.region,
        ctx.account,
    );
    let worker = ctx
        .store
        .admit_execution_worker(ctx.account, ctx.region, &target.name)
        .await
        .ok_or_else(|| {
            SfnError::StateMachineDeleting(format!(
                "State machine {state_machine_arn} is deleting or was deleted"
            ))
        })?;
    let sm = Arc::new(StateMachine::parse(&target.definition)?);
    let execution_name = str_field(v, "name")
        .map(String::from)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    validate_execution_name(&execution_name)?;
    let input = execution_input(v)?;
    validate_payload_size(&input)?;
    let execution_arn = if target.type_ == "EXPRESS" {
        format!(
            "arn:aws:states:{}:{}:express:{}:{}:{}",
            ctx.region,
            ctx.account,
            target.name,
            execution_name,
            Uuid::new_v4()
        )
    } else {
        format!(
            "arn:aws:states:{}:{}:execution:{}:{}",
            ctx.region, ctx.account, target.name, execution_name
        )
    };
    let start = now_epoch();
    let start_time = now_iso();
    let execution = Execution {
        arn: execution_arn.clone(),
        name: execution_name.clone(),
        state_machine_arn: state_machine_arn.clone(),
        state_machine_type: target.type_.clone(),
        definition: target.definition.clone(),
        role_arn: target.role_arn.clone(),
        logging_configuration: target.logging_configuration.clone(),
        tracing_configuration: target.tracing_configuration.clone(),
        encryption_configuration: target.encryption_configuration.clone(),
        status: Status::Running,
        input: input.clone(),
        output: None,
        error: None,
        cause: None,
        start_date: start,
        start_time: start_time.clone(),
        stop_date: None,
        current_state: None,
        current_input: None,
        variables: BTreeMap::new(),
        redrive_count: 0,
        redrive_date: None,
        history: Vec::new(),
    };
    let exec_handle = if target.type_ == "STANDARD" {
        match ctx
            .store
            .insert_execution_exclusive_bounded(ctx.account, ctx.region, execution)
            .await
        {
            InsertExecutionResult::Created(handle) => handle,
            InsertExecutionResult::Existing(handle) => {
                let existing = handle.read().await;
                if existing.input == input {
                    return Ok(json!({
                        "executionArn": existing.arn,
                        "startDate": existing.start_date,
                    }));
                }
                return Err(SfnError::ExecutionAlreadyExists(format!(
                    "Execution {} already exists with different input",
                    existing.arn
                )));
            }
            InsertExecutionResult::PersistenceFailed => {
                return Err(SfnError::Internal(
                    "Execution admission could not be committed".into(),
                ))
            }
            InsertExecutionResult::LimitExceeded => {
                return Err(SfnError::ExecutionLimitExceeded(format!(
                    "Open execution quota exceeded for {} in {}",
                    ctx.account, ctx.region
                )));
            }
        }
    } else {
        // EXPRESS execution metadata and history are not durable or queryable in AWS.
        Arc::new(crate::store::ExecutionCell::ephemeral(execution))
    };

    drop(configuration);
    if !ctx.store.healthy() {
        return Err(SfnError::Internal(
            "Execution admission could not be committed".into(),
        ));
    }
    let mut interpreter = interpreter_for(
        ctx,
        sm,
        state_machine_arn,
        target.name,
        target.role_arn,
        execution_arn.clone(),
        execution_name,
        target.type_,
        logging_enabled,
    );
    interpreter.execution_input = input.clone();
    interpreter.execution_start_time = start_time;
    let run_handle = exec_handle.clone();
    tokio::spawn(async move {
        let _worker = worker;
        if let Err(error) = interpreter.run(run_handle.clone()).await {
            let mut execution = run_handle.write().await;
            execution.status = Status::Failed;
            execution.error = Some("States.LoggingFailed".into());
            execution.cause = Some(error.to_string());
            execution.stop_date.get_or_insert_with(now_epoch);
        }
    });

    Ok(json!({ "executionArn": execution_arn, "startDate": start }))
}

pub async fn start_sync_execution(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let configuration = ctx.store.configuration_gate.read().await;
    if !ctx.store.healthy() {
        return Err(SfnError::Internal(
            "Step Functions durable state is unavailable".into(),
        ));
    }
    let state_machine_arn = req_str(v, "stateMachineArn")?.to_string();
    let target = resolve_execution_target(ctx, &state_machine_arn).await?;
    drop(configuration);
    if target.type_ != "EXPRESS" {
        return Err(SfnError::StateMachineTypeNotSupported(
            "StartSyncExecution is not supported for STANDARD workflows".into(),
        ));
    }
    crate::logging::preflight_configuration(
        target.logging_configuration.as_ref(),
        &ctx.registry,
        ctx.region,
        ctx.account,
    )
    .await?;
    let logging_enabled = crate::logging::is_enabled(
        target.logging_configuration.as_ref(),
        ctx.region,
        ctx.account,
    );
    let worker = ctx
        .store
        .admit_execution_worker(ctx.account, ctx.region, &target.name)
        .await
        .ok_or_else(|| {
            SfnError::StateMachineDeleting(format!(
                "State machine {state_machine_arn} is deleting or was deleted"
            ))
        })?;
    let sm = Arc::new(StateMachine::parse(&target.definition)?);
    let execution_name = str_field(v, "name")
        .map(String::from)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    validate_execution_name(&execution_name)?;
    let input = execution_input(v)?;
    validate_payload_size(&input)?;
    let execution_arn = format!(
        "arn:aws:states:{}:{}:express:{}:{}:{}",
        ctx.region,
        ctx.account,
        target.name,
        execution_name,
        Uuid::new_v4()
    );
    let start = now_epoch();
    let start_time = now_iso();
    let execution = Arc::new(crate::store::ExecutionCell::ephemeral(Execution {
        arn: execution_arn.clone(),
        name: execution_name.clone(),
        state_machine_arn: state_machine_arn.clone(),
        state_machine_type: target.type_.clone(),
        definition: target.definition.clone(),
        role_arn: target.role_arn.clone(),
        logging_configuration: target.logging_configuration.clone(),
        tracing_configuration: target.tracing_configuration.clone(),
        encryption_configuration: target.encryption_configuration.clone(),
        status: Status::Running,
        input: input.clone(),
        output: None,
        error: None,
        cause: None,
        start_date: start,
        start_time: start_time.clone(),
        stop_date: None,
        current_state: None,
        current_input: None,
        variables: BTreeMap::new(),
        redrive_count: 0,
        redrive_date: None,
        history: Vec::new(),
    }));
    let mut interpreter = interpreter_for(
        ctx,
        sm,
        state_machine_arn.clone(),
        target.name,
        target.role_arn,
        execution_arn.clone(),
        execution_name,
        target.type_,
        logging_enabled,
    );
    interpreter.execution_input = input.clone();
    interpreter.execution_start_time = start_time;
    let _worker = worker;
    interpreter.run(execution.clone()).await?;
    let completed = execution.read().await;
    let mut response = json!({
        "executionArn": execution_arn,
        "stateMachineArn": state_machine_arn,
        "name": completed.name,
        "status": completed.status.as_str(),
        "startDate": start,
        "stopDate": completed.stop_date.unwrap_or_else(now_epoch),
        "input": input.to_string(),
    });
    let object = response.as_object_mut().unwrap();
    if let Some(output) = &completed.output {
        object.insert("output".into(), json!(output.to_string()));
    }
    if let Some(error) = &completed.error {
        object.insert("error".into(), json!(error));
    }
    if let Some(cause) = &completed.cause {
        object.insert("cause".into(), json!(cause));
    }
    Ok(response)
}

pub async fn describe_execution(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "executionArn")?;
    let handle = ctx.execution(arn)?;
    let e = handle.read().await;
    let mut out = json!({
        "executionArn": e.arn,
        "stateMachineArn": e.state_machine_arn,
        "name": e.name,
        "status": e.status.as_str(),
        "startDate": e.start_date,
        "input": e.input.to_string(),
    });
    let obj = out.as_object_mut().unwrap();
    if let Some(stop) = e.stop_date {
        obj.insert("stopDate".into(), json!(stop));
    }
    if let Some(output) = &e.output {
        obj.insert("output".into(), json!(output.to_string()));
    }
    if let Some(err) = &e.error {
        obj.insert("error".into(), json!(err));
    }
    if let Some(cause) = &e.cause {
        obj.insert("cause".into(), json!(cause));
    }
    Ok(out)
}

pub async fn describe_state_machine_for_execution(
    ctx: &Ctx<'_>,
    v: &Value,
) -> Result<Value, SfnError> {
    let arn = req_str(v, "executionArn")?;
    let handle = ctx.execution(arn)?;
    let execution = handle.read().await;
    let mut response = json!({
        "stateMachineArn": execution.state_machine_arn,
        "name": execution.state_machine_arn.split(':').nth(6).unwrap_or_default(),
        "definition": execution.definition,
        "roleArn": execution.role_arn,
    });
    let object = response.as_object_mut().unwrap();
    if let Some(configuration) = &execution.logging_configuration {
        object.insert("loggingConfiguration".into(), configuration.clone());
    }
    if let Some(configuration) = &execution.tracing_configuration {
        object.insert("tracingConfiguration".into(), configuration.clone());
    }
    if let Some(configuration) = &execution.encryption_configuration {
        object.insert("encryptionConfiguration".into(), configuration.clone());
    }
    Ok(response)
}

pub async fn stop_execution(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "executionArn")?;
    let handle = ctx.execution(arn)?;
    let (stop_date, cancelled) = {
        let mut execution = handle.write().await;
        let cancelled = execution.status == Status::Running;
        if cancelled {
            execution.status = Status::Aborted;
            execution.error = str_field(v, "error").map(String::from);
            execution.cause = str_field(v, "cause").map(String::from);
            execution.stop_date = Some(now_epoch());
            let details = json!({ "error": execution.error, "cause": execution.cause });
            execution.record("ExecutionAborted", details);
        }
        (execution.stop_date.unwrap_or_else(now_epoch), cancelled)
    };
    if cancelled {
        ctx.store.cancel_pending_tasks(arn).await;
    }
    Ok(json!({ "stopDate": stop_date }))
}

pub async fn list_executions(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "stateMachineArn")?;
    let target = parse_sm_target(ctx, arn)?;
    if ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .is_none()
    {
        return Err(SfnError::StateMachineDoesNotExist(format!(
            "{arn} does not exist"
        )));
    }
    let status_filter = str_field(v, "statusFilter");
    let redrive_filter = str_field(v, "redriveFilter");
    let offset = pagination_offset(v)?;
    let maximum = max_results(v, 100, 1000);
    let mut handles = ctx.store.list_executions(arn);
    handles.sort_by(|left, right| {
        let left_date = left
            .try_read()
            .map(|execution| execution.start_date)
            .unwrap_or_default();
        let right_date = right
            .try_read()
            .map(|execution| execution.start_date)
            .unwrap_or_default();
        right_date.total_cmp(&left_date)
    });
    let mut summaries = Vec::new();
    for handle in handles {
        let execution = handle.read().await;
        if status_filter.is_some_and(|status| status != execution.status.as_str()) {
            continue;
        }
        if redrive_filter == Some("REDRIVEN") && execution.redrive_count == 0 {
            continue;
        }
        if redrive_filter == Some("NOT_REDRIVEN") && execution.redrive_count > 0 {
            continue;
        }
        let mut summary = json!({
            "executionArn": execution.arn,
            "stateMachineArn": execution.state_machine_arn,
            "name": execution.name,
            "status": execution.status.as_str(),
            "startDate": execution.start_date,
            "redriveCount": execution.redrive_count,
        });
        if let Some(stop_date) = execution.stop_date {
            summary
                .as_object_mut()
                .unwrap()
                .insert("stopDate".into(), json!(stop_date));
        }
        if let Some(redrive_date) = execution.redrive_date {
            summary
                .as_object_mut()
                .unwrap()
                .insert("redriveDate".into(), json!(redrive_date));
        }
        summaries.push(summary);
    }
    let total = summaries.len();
    let executions: Vec<_> = summaries.into_iter().skip(offset).take(maximum).collect();
    let consumed = offset + executions.len();
    let mut response = json!({ "executions": executions });
    if consumed < total {
        response
            .as_object_mut()
            .unwrap()
            .insert("nextToken".into(), json!(consumed.to_string()));
    }
    Ok(response)
}

pub async fn get_execution_history(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "executionArn")?;
    let handle = ctx.execution(arn)?;
    let execution = handle.read().await;
    if execution.state_machine_type != "STANDARD" {
        return Err(SfnError::Validation(
            "Execution history is not supported for EXPRESS workflows".into(),
        ));
    }
    let include_execution_data = v
        .get("includeExecutionData")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mut events: Vec<_> = execution.history.iter().collect();
    if v.get("reverseOrder")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        events.reverse();
    }
    let offset = pagination_offset(v)?;
    let maximum = max_results(v, 100, 1000);
    let total = events.len();
    let page: Vec<Value> = events
        .into_iter()
        .skip(offset)
        .take(maximum)
        .map(|event| {
            let mut details = event.details.clone();
            if let Some(object) = details.as_object_mut() {
                if include_execution_data {
                    for field in ["input", "output", "parameters"] {
                        if let Some(value) = object.get_mut(field) {
                            *value = Value::String(value.to_string());
                        }
                    }
                } else {
                    object.remove("input");
                    object.remove("output");
                    object.remove("parameters");
                }
            }
            let mut rendered = json!({
                "id": event.id,
                "type": event.event_type,
                "timestamp": event.timestamp,
            });
            if let Some(previous_event_id) = event.previous_event_id {
                rendered
                    .as_object_mut()
                    .unwrap()
                    .insert("previousEventId".into(), json!(previous_event_id));
            }
            if !details.as_object().is_some_and(serde_json::Map::is_empty) {
                rendered
                    .as_object_mut()
                    .unwrap()
                    .insert(history_details_key(&event.event_type), details);
            }
            rendered
        })
        .collect();
    let consumed = offset + page.len();
    let mut response = json!({ "events": page });
    if consumed < total {
        response
            .as_object_mut()
            .unwrap()
            .insert("nextToken".into(), json!(consumed.to_string()));
    }
    Ok(response)
}

fn history_details_key(event_type: &str) -> String {
    let mut characters = event_type.chars();
    match characters.next() {
        Some(first) => format!(
            "{}{}EventDetails",
            first.to_ascii_lowercase(),
            characters.as_str()
        ),
        None => "eventDetails".into(),
    }
}

pub async fn redrive_execution(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let configuration = ctx.store.configuration_gate.read().await;
    if !ctx.store.healthy() {
        return Err(SfnError::Internal(
            "Step Functions durable state is unavailable".into(),
        ));
    }
    let arn = req_str(v, "executionArn")?;
    let handle = ctx.execution(arn)?;
    let machine_name = handle
        .read()
        .await
        .state_machine_arn
        .split(':')
        .nth(6)
        .unwrap_or_default()
        .to_owned();
    let worker = ctx
        .store
        .admit_execution_worker(ctx.account, ctx.region, &machine_name)
        .await
        .ok_or_else(|| {
            SfnError::StateMachineDeleting("State machine is deleting or was deleted".into())
        })?;
    let (
        state,
        input,
        definition,
        role_arn,
        state_machine_arn,
        state_machine_name,
        execution_name,
        execution_input,
        execution_start_time,
    ) = {
        let mut execution = handle.write().await;
        if execution.state_machine_type != "STANDARD"
            || !matches!(
                execution.status,
                Status::Failed | Status::Aborted | Status::TimedOut
            )
        {
            return Err(SfnError::ExecutionNotRedrivable(format!(
                "Execution {arn} is not eligible for redrive"
            )));
        }
        if execution.error.as_deref() == Some("LocallyCloud.ExecutionInterrupted") {
            return Err(SfnError::ExecutionNotRedrivable("Interrupted executions cannot be redriven because external task effects may already have completed".into()));
        }
        let state = execution.current_state.clone().ok_or_else(|| {
            SfnError::ExecutionNotRedrivable(format!(
                "Execution {arn} has no unsuccessful state to redrive"
            ))
        })?;
        let input = execution.current_input.clone().ok_or_else(|| {
            SfnError::ExecutionNotRedrivable(format!(
                "Execution {arn} has no state input to redrive"
            ))
        })?;
        execution.status = Status::Running;
        execution.output = None;
        execution.error = None;
        execution.cause = None;
        execution.stop_date = None;
        execution.redrive_count += 1;
        let redrive_count = execution.redrive_count;
        let redrive_date = now_epoch();
        execution.redrive_date = Some(redrive_date);
        execution.record(
            "ExecutionRedriven",
            json!({ "redriveCount": redrive_count }),
        );
        (
            state,
            input,
            execution.definition.clone(),
            execution.role_arn.clone(),
            execution.state_machine_arn.clone(),
            execution
                .state_machine_arn
                .split(':')
                .nth(6)
                .unwrap_or_default()
                .to_string(),
            execution.name.clone(),
            execution.input.clone(),
            execution.start_time.clone(),
        )
    };
    drop(configuration);
    if !ctx.store.healthy() {
        return Err(SfnError::Internal(
            "Execution redrive could not be committed".into(),
        ));
    }
    let state_machine = Arc::new(StateMachine::parse(&definition)?);
    let mut interpreter = interpreter_for(
        ctx,
        state_machine,
        state_machine_arn,
        state_machine_name,
        role_arn,
        arn.to_string(),
        execution_name,
        "STANDARD".into(),
        false,
    );
    interpreter.execution_input = execution_input;
    interpreter.execution_start_time = execution_start_time;
    let run_handle = handle.clone();
    tokio::spawn(async move {
        let _worker = worker;
        if let Err(error) = interpreter.redrive(run_handle.clone(), state, input).await {
            let mut execution = run_handle.write().await;
            execution.status = Status::Failed;
            execution.error = Some("States.LoggingFailed".into());
            execution.cause = Some(error.to_string());
            execution.stop_date.get_or_insert_with(now_epoch);
        }
    });
    Ok(json!({ "redriveDate": handle.read().await.redrive_date.unwrap_or_else(now_epoch) }))
}

fn parse_activity_name(ctx: &Ctx<'_>, arn: &str) -> Result<String, SfnError> {
    let prefix = format!("arn:aws:states:{}:{}:activity:", ctx.region, ctx.account);
    arn.strip_prefix(&prefix)
        .filter(|name| !name.is_empty() && !name.contains(':'))
        .map(String::from)
        .ok_or_else(|| SfnError::InvalidArn(arn.to_string()))
}

pub async fn create_activity(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let name = req_str(v, "name")?.to_string();
    validate_execution_name(&name)?;
    let arn = format!(
        "arn:aws:states:{}:{}:activity:{name}",
        ctx.region, ctx.account
    );
    let activity = ctx
        .store
        .create_activity_bounded(
            ctx.account,
            ctx.region,
            crate::store::ActivityRecord::new(arn, name, now_epoch(), parse_tags(v)),
        )
        .await
        .map_err(|_| {
            SfnError::ActivityLimitExceeded(format!(
                "Activity quota exceeded for {} in {}",
                ctx.account, ctx.region
            ))
        })?;
    Ok(json!({ "activityArn": activity.arn, "creationDate": activity.creation_date }))
}

pub async fn describe_activity(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "activityArn")?;
    let name = parse_activity_name(ctx, arn)?;
    let activity = ctx
        .store
        .get_activity(ctx.account, ctx.region, &name)
        .ok_or_else(|| SfnError::ActivityDoesNotExist(format!("{arn} does not exist")))?;
    Ok(json!({
        "activityArn": activity.arn,
        "name": activity.name,
        "creationDate": activity.creation_date,
    }))
}

pub async fn delete_activity(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "activityArn")?;
    let name = parse_activity_name(ctx, arn)?;
    ctx.store.remove_activity(ctx.account, ctx.region, &name);
    Ok(json!({}))
}

pub async fn list_activities(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let offset = pagination_offset(v)?;
    let maximum = max_results(v, 100, 1000);
    let activities = ctx.store.list_activities(ctx.account, ctx.region);
    let total = activities.len();
    let page: Vec<_> = activities
        .into_iter()
        .skip(offset)
        .take(maximum)
        .map(|activity| {
            json!({
                "activityArn": activity.arn,
                "name": activity.name,
                "creationDate": activity.creation_date,
            })
        })
        .collect();
    let consumed = offset + page.len();
    let mut response = json!({ "activities": page });
    if consumed < total {
        response
            .as_object_mut()
            .unwrap()
            .insert("nextToken".into(), json!(consumed.to_string()));
    }
    Ok(response)
}

pub async fn get_activity_task(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "activityArn")?;
    let name = parse_activity_name(ctx, arn)?;
    let activity = ctx
        .store
        .get_activity(ctx.account, ctx.region, &name)
        .ok_or_else(|| SfnError::ActivityDoesNotExist(format!("{arn} does not exist")))?;
    let poll = async {
        loop {
            let notified = activity.notify.notified();
            if let Some(task) = activity.queue.lock().await.pop_front() {
                if ctx.store.get_pending_task(&task.token).is_some() {
                    return task;
                }
                continue;
            }
            notified.await;
        }
    };
    match tokio::time::timeout(std::time::Duration::from_secs(1), poll).await {
        Ok(task) => Ok(json!({ "taskToken": task.token, "input": task.input.to_string() })),
        Err(_) => Ok(json!({ "taskToken": "" })),
    }
}

pub async fn send_task_success(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let token = req_str(v, "taskToken")?;
    let output_text = req_str(v, "output")?;
    if output_text.len() > 256 * 1024 {
        return Err(SfnError::Validation(
            "output exceeds the 256 KiB limit".into(),
        ));
    }
    let output: Value = serde_json::from_str(output_text)
        .map_err(|_| SfnError::Validation("output is not valid JSON".into()))?;
    let task = ctx.pending_task(token)?;
    let mut outcome = task.outcome.lock().await;
    if ctx.store.get_pending_task(token).is_none() || outcome.is_some() {
        return Err(SfnError::TaskDoesNotExist(
            "task token does not exist".into(),
        ));
    }
    if task.heartbeat_expired().await {
        *outcome = Some(crate::store::TaskOutcome::Failure {
            error: "States.HeartbeatTimeout".into(),
            cause: "task heartbeat timed out".into(),
        });
        drop(outcome);
        task.notify.notify_one();
        return Err(SfnError::TaskTimedOut(
            "task heartbeat has timed out".into(),
        ));
    }
    *outcome = Some(crate::store::TaskOutcome::Success(output));
    drop(outcome);
    task.notify.notify_one();
    Ok(json!({}))
}

pub async fn send_task_failure(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let token = req_str(v, "taskToken")?;
    let task = ctx.pending_task(token)?;
    let mut outcome = task.outcome.lock().await;
    if ctx.store.get_pending_task(token).is_none() || outcome.is_some() {
        return Err(SfnError::TaskDoesNotExist(
            "task token does not exist".into(),
        ));
    }
    if task.heartbeat_expired().await {
        *outcome = Some(crate::store::TaskOutcome::Failure {
            error: "States.HeartbeatTimeout".into(),
            cause: "task heartbeat timed out".into(),
        });
        drop(outcome);
        task.notify.notify_one();
        return Err(SfnError::TaskTimedOut(
            "task heartbeat has timed out".into(),
        ));
    }
    *outcome = Some(crate::store::TaskOutcome::Failure {
        error: str_field(v, "error")
            .unwrap_or("States.TaskFailed")
            .to_string(),
        cause: str_field(v, "cause").unwrap_or_default().to_string(),
    });
    drop(outcome);
    task.notify.notify_one();
    Ok(json!({}))
}

pub async fn send_task_heartbeat(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let token = req_str(v, "taskToken")?;
    let task = ctx.pending_task(token)?;
    let mut outcome = task.outcome.lock().await;
    if ctx.store.get_pending_task(token).is_none() || outcome.is_some() {
        return Err(SfnError::TaskDoesNotExist(
            "task token does not exist".into(),
        ));
    }
    if task.heartbeat_expired().await {
        *outcome = Some(crate::store::TaskOutcome::Failure {
            error: "States.HeartbeatTimeout".into(),
            cause: "task heartbeat timed out".into(),
        });
        drop(outcome);
        task.notify.notify_one();
        return Err(SfnError::TaskTimedOut(
            "task heartbeat has timed out".into(),
        ));
    }
    *task.last_heartbeat.lock().await = tokio::time::Instant::now();
    drop(outcome);
    task.notify.notify_one();
    Ok(json!({}))
}

// ============================ tags =============================================

pub async fn tag_resource(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "resourceArn")?;
    if arn.contains(":activity:") {
        let name = parse_activity_name(ctx, arn)?;
        let activity = ctx
            .store
            .get_activity(ctx.account, ctx.region, &name)
            .ok_or_else(|| SfnError::ActivityDoesNotExist(format!("{arn} does not exist")))?;
        activity.tags.write().await.extend(parse_tags(v));
        return Ok(json!({}));
    }
    let target = parse_sm_target(ctx, arn)?;
    if target.version.is_some() {
        return Err(SfnError::Validation(
            "Published state machine versions cannot be tagged".into(),
        ));
    }
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
    let tags = parse_tags(v);
    let mut rec = handle.write().await;
    match target.alias {
        Some(alias_name) => rec
            .aliases
            .get_mut(&alias_name)
            .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?
            .tags
            .extend(tags),
        None => rec.tags.extend(tags),
    }
    Ok(json!({}))
}

pub async fn untag_resource(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "resourceArn")?;
    let keys: Vec<String> = v
        .get("tagKeys")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if arn.contains(":activity:") {
        let name = parse_activity_name(ctx, arn)?;
        let activity = ctx
            .store
            .get_activity(ctx.account, ctx.region, &name)
            .ok_or_else(|| SfnError::ActivityDoesNotExist(format!("{arn} does not exist")))?;
        activity
            .tags
            .write()
            .await
            .retain(|key, _| !keys.contains(key));
        return Ok(json!({}));
    }
    let target = parse_sm_target(ctx, arn)?;
    if target.version.is_some() {
        return Err(SfnError::Validation(
            "Published state machine versions cannot be tagged".into(),
        ));
    }
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
    let mut rec = handle.write().await;
    let tags = match target.alias {
        Some(alias_name) => {
            &mut rec
                .aliases
                .get_mut(&alias_name)
                .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?
                .tags
        }
        None => &mut rec.tags,
    };
    tags.retain(|key, _| !keys.contains(key));
    Ok(json!({}))
}

pub async fn list_tags_for_resource(ctx: &Ctx<'_>, v: &Value) -> Result<Value, SfnError> {
    let arn = req_str(v, "resourceArn")?;
    if arn.contains(":activity:") {
        let name = parse_activity_name(ctx, arn)?;
        let activity = ctx
            .store
            .get_activity(ctx.account, ctx.region, &name)
            .ok_or_else(|| SfnError::ActivityDoesNotExist(format!("{arn} does not exist")))?;
        let tags = activity.tags.read().await;
        return Ok(json!({
            "tags": tags.iter().map(|(key, value)| json!({ "key": key, "value": value })).collect::<Vec<_>>()
        }));
    }
    let target = parse_sm_target(ctx, arn)?;
    if target.version.is_some() {
        return Err(SfnError::Validation(
            "Published state machine versions cannot be tagged".into(),
        ));
    }
    let handle = ctx
        .store
        .get_machine(ctx.account, ctx.region, &target.name)
        .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?;
    let rec = handle.read().await;
    let tags = match target.alias {
        Some(alias_name) => {
            &rec.aliases
                .get(&alias_name)
                .ok_or_else(|| SfnError::StateMachineDoesNotExist(format!("{arn} does not exist")))?
                .tags
        }
        None => &rec.tags,
    };
    Ok(json!({
        "tags": tags.iter().map(|(key, value)| json!({ "key": key, "value": value })).collect::<Vec<_>>()
    }))
}

fn parse_tags(v: &Value) -> BTreeMap<String, String> {
    v.get("tags")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|t| {
                    Some((
                        t.get("key")?.as_str()?.to_string(),
                        t.get("value")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}
