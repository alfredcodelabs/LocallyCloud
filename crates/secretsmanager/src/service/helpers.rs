use super::*;

pub(super) fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, SecretsError> {
    serde_json::from_slice(body).map_err(|_| SecretsError::InvalidParameter)
}

pub(super) fn serialize<T: Serialize>(value: T) -> Result<Vec<u8>, SecretsError> {
    serde_json::to_vec(&value).map_err(|_| SecretsError::Internal)
}

pub(super) fn lock(
    slot: &Arc<Mutex<Option<SecretRecord>>>,
) -> Result<std::sync::MutexGuard<'_, Option<SecretRecord>>, SecretsError> {
    slot.lock().map_err(|_| SecretsError::Internal)
}

pub(super) fn active_record<'a>(
    guard: &'a std::sync::MutexGuard<'_, Option<SecretRecord>>,
) -> Result<&'a SecretRecord, SecretsError> {
    let record = guard.as_ref().ok_or(SecretsError::ResourceNotFound)?;
    if record.deleted_date.is_some() {
        Err(SecretsError::InvalidRequest)
    } else {
        Ok(record)
    }
}

pub(super) fn active_record_mut<'a>(
    guard: &'a mut std::sync::MutexGuard<'_, Option<SecretRecord>>,
) -> Result<&'a mut SecretRecord, SecretsError> {
    let record = guard.as_mut().ok_or(SecretsError::ResourceNotFound)?;
    if record.deleted_date.is_some() {
        Err(SecretsError::InvalidRequest)
    } else {
        Ok(record)
    }
}

pub(super) fn optional_value(
    secret_string: Option<crate::model::SensitiveString>,
    secret_binary: Option<crate::model::SensitiveBinary>,
) -> Result<Option<PlainValue>, SecretsError> {
    match (secret_string, secret_binary) {
        (Some(value), None) => Ok(Some(PlainValue::new(ValueKind::String, value.into_bytes()))),
        (None, Some(value)) => Ok(Some(PlainValue::new(ValueKind::Binary, value.into_bytes()))),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(SecretsError::InvalidParameter),
    }
}

pub(super) fn required_value(
    secret_string: Option<crate::model::SensitiveString>,
    secret_binary: Option<crate::model::SensitiveBinary>,
) -> Result<PlainValue, SecretsError> {
    optional_value(secret_string, secret_binary)?.ok_or(SecretsError::InvalidParameter)
}

pub(super) fn map_lambda_error(error: LambdaInternalError) -> SecretsError {
    match error {
        LambdaInternalError::InvalidRequest => SecretsError::InvalidParameter,
        LambdaInternalError::NotFound => SecretsError::ResourceNotFound,
        LambdaInternalError::InvalidState => SecretsError::InvalidRequest,
        LambdaInternalError::Unavailable
        | LambdaInternalError::Throttled
        | LambdaInternalError::Internal => SecretsError::Internal,
    }
}

pub(super) fn validate_rotation_lambda_arn(arn: &str, scope: &Scope) -> Result<(), SecretsError> {
    let prefix = format!(
        "arn:aws:lambda:{}:{}:function:",
        scope.region, scope.account_id
    );
    if arn
        .strip_prefix(&prefix)
        .is_some_and(|function| !function.is_empty())
    {
        Ok(())
    } else {
        Err(SecretsError::InvalidParameter)
    }
}

pub(super) fn validate_value(value: &PlainValue) -> Result<(), SecretsError> {
    if value.bytes.as_slice().is_empty() || value.bytes.as_slice().len() > MAX_SECRET_BYTES {
        Err(SecretsError::InvalidParameter)
    } else {
        Ok(())
    }
}

pub(super) fn version_id(token: Option<&str>) -> Result<String, SecretsError> {
    match token {
        Some(token) => {
            validate_token(token)?;
            Ok(token.to_owned())
        }
        None => Ok(Uuid::new_v4().to_string()),
    }
}

pub(super) fn validate_optional_token(token: Option<&str>) -> Result<(), SecretsError> {
    token.map(validate_token).transpose().map(|_| ())
}

pub(super) fn validate_token(token: &str) -> Result<(), SecretsError> {
    if (32..=64).contains(&token.len())
        && token
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
    {
        Ok(())
    } else {
        Err(SecretsError::InvalidParameter)
    }
}

pub(super) fn validate_name(name: &str) -> Result<(), SecretsError> {
    if name.is_empty()
        || name.len() > 512
        || name.starts_with("arn:")
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/_+=.@-".contains(character))
    {
        Err(SecretsError::InvalidParameter)
    } else {
        Ok(())
    }
}

pub(super) fn validate_description(description: Option<&str>) -> Result<(), SecretsError> {
    if description.is_some_and(|description| description.len() > 2048) {
        Err(SecretsError::InvalidParameter)
    } else {
        Ok(())
    }
}

pub(super) fn validate_stages(
    stages: Option<Vec<String>>,
    default_current: bool,
) -> Result<BTreeSet<String>, SecretsError> {
    let values = stages.unwrap_or_else(|| {
        if default_current {
            vec!["AWSCURRENT".to_owned()]
        } else {
            Vec::new()
        }
    });
    if values.is_empty() || values.len() > 20 {
        return Err(SecretsError::InvalidParameter);
    }
    let mut result = BTreeSet::new();
    for stage in values {
        validate_stage(&stage)?;
        if !result.insert(stage) {
            return Err(SecretsError::InvalidParameter);
        }
    }
    Ok(result)
}

pub(super) fn validate_stage(stage: &str) -> Result<(), SecretsError> {
    if stage.is_empty()
        || stage.len() > 256
        || !stage
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_+=.@-".contains(character))
    {
        Err(SecretsError::InvalidParameter)
    } else {
        Ok(())
    }
}

pub(super) fn validate_tags(tags: Vec<Tag>) -> Result<BTreeMap<String, String>, SecretsError> {
    if tags.len() > 50 {
        return Err(SecretsError::InvalidParameter);
    }
    let mut result = BTreeMap::new();
    for tag in tags {
        validate_tag_key(&tag.key)?;
        if tag.value.len() > 256 || result.insert(tag.key, tag.value).is_some() {
            return Err(SecretsError::InvalidParameter);
        }
    }
    Ok(result)
}

pub(super) fn validate_tag_key(key: &str) -> Result<(), SecretsError> {
    if key.is_empty() || key.len() > 128 || key.to_ascii_lowercase().starts_with("aws:") {
        Err(SecretsError::InvalidParameter)
    } else {
        Ok(())
    }
}

pub(super) fn validate_max_results(max: Option<u32>) -> Result<usize, SecretsError> {
    let max = max.unwrap_or(DEFAULT_MAX_RESULTS as u32);
    if !(1..=DEFAULT_MAX_RESULTS as u32).contains(&max) {
        Err(SecretsError::InvalidParameter)
    } else {
        Ok(max as usize)
    }
}

pub(super) fn version_matches(
    record: &SecretRecord,
    version_id: &str,
    value: &PlainValue,
    operation: VersionOperation,
    requested_stages: &BTreeSet<String>,
) -> bool {
    record.versions.get(version_id).is_some_and(|version| {
        version.kind == value.kind
            && version.operation == operation
            && version.digest == value.digest
            && version.requested_stages == *requested_stages
    })
}

pub(super) fn prepared_version_matches(
    record: &SecretRecord,
    version_id: &str,
    prepared: &SecretVersion,
) -> bool {
    record.versions.get(version_id).is_some_and(|existing| {
        existing.kind == prepared.kind
            && existing.operation == prepared.operation
            && existing.digest == prepared.digest
            && existing.requested_stages == prepared.requested_stages
    })
}

pub(super) fn apply_stages(
    record: &mut SecretRecord,
    version_id: &str,
    stages: &BTreeSet<String>,
) -> Result<(), SecretsError> {
    for stage in stages {
        if stage == "AWSCURRENT" {
            promote_current(record, version_id)?;
        } else {
            move_stage(record, stage, version_id)?;
        }
    }
    Ok(())
}

pub(super) fn promote_current(
    record: &mut SecretRecord,
    destination: &str,
) -> Result<(), SecretsError> {
    if !record.versions.contains_key(destination) {
        return Err(SecretsError::ResourceNotFound);
    }
    if record.stage_index.get("AWSCURRENT").map(String::as_str) == Some(destination) {
        return Ok(());
    }
    if let Some(old_previous) = record.stage_index.remove("AWSPREVIOUS") {
        record
            .versions
            .get_mut(&old_previous)
            .ok_or(SecretsError::Internal)?
            .stages
            .remove("AWSPREVIOUS");
    }
    if let Some(old_current) = record.stage_index.remove("AWSCURRENT") {
        let previous = record
            .versions
            .get_mut(&old_current)
            .ok_or(SecretsError::Internal)?;
        previous.stages.remove("AWSCURRENT");
        previous.stages.insert("AWSPREVIOUS".to_owned());
        record
            .stage_index
            .insert("AWSPREVIOUS".to_owned(), old_current);
    }
    let destination_version = record
        .versions
        .get_mut(destination)
        .ok_or(SecretsError::Internal)?;
    destination_version.stages.insert("AWSCURRENT".to_owned());
    record
        .stage_index
        .insert("AWSCURRENT".to_owned(), destination.to_owned());
    Ok(())
}

pub(super) fn move_stage(
    record: &mut SecretRecord,
    stage: &str,
    destination: &str,
) -> Result<(), SecretsError> {
    if !record.versions.contains_key(destination) {
        return Err(SecretsError::ResourceNotFound);
    }
    if let Some(owner) = record
        .stage_index
        .insert(stage.to_owned(), destination.to_owned())
    {
        record
            .versions
            .get_mut(&owner)
            .ok_or(SecretsError::Internal)?
            .stages
            .remove(stage);
    }
    record
        .versions
        .get_mut(destination)
        .ok_or(SecretsError::Internal)?
        .stages
        .insert(stage.to_owned());
    Ok(())
}

pub(super) fn remove_stage(
    record: &mut SecretRecord,
    stage: &str,
    owner: &str,
) -> Result<(), SecretsError> {
    if record.stage_index.get(stage).map(String::as_str) != Some(owner) {
        return Err(SecretsError::InvalidRequest);
    }
    record.stage_index.remove(stage);
    record
        .versions
        .get_mut(owner)
        .ok_or(SecretsError::Internal)?
        .stages
        .remove(stage);
    Ok(())
}

pub(super) fn describe_value(record: &SecretRecord) -> Value {
    let tags: Vec<Value> = record
        .tags
        .iter()
        .map(|(key, value)| json!({"Key": key, "Value": value}))
        .collect();
    let version_ids_to_stages: BTreeMap<String, BTreeSet<String>> = record
        .versions
        .iter()
        .map(|(id, version)| (id.clone(), version.stages.clone()))
        .collect();
    let mut response = json!({
        "ARN": record.arn,
        "Name": record.name,
        "CreatedDate": record.created_date,
        "LastChangedDate": record.last_changed_date,
        "Tags": tags,
        "VersionIdsToStages": version_ids_to_stages,
        "RotationEnabled": record.rotation.as_ref().is_some_and(|rotation| rotation.enabled)
    });
    let object = response
        .as_object_mut()
        .expect("Secrets Manager describe response is an object");
    if let Some(description) = &record.description {
        object.insert("Description".to_owned(), description.clone().into());
    }
    if let Some(kms_key_id) = &record.kms_key_id {
        object.insert("KmsKeyId".to_owned(), kms_key_id.clone().into());
    }
    if let Some(rotation) = record.rotation.as_ref().filter(|rotation| rotation.enabled) {
        object.insert(
            "RotationLambdaARN".to_owned(),
            rotation.lambda_arn.clone().into(),
        );
        if let Some(last_rotated_date) = rotation.last_rotated_date {
            object.insert("LastRotatedDate".to_owned(), last_rotated_date.into());
        }
    }
    if let Some(deleted_date) = record.deleted_date {
        object.insert("DeletedDate".to_owned(), deleted_date.into());
    }
    response
}

pub(super) fn kms_call(request: &ServiceRequest, scope: &Scope) -> KmsCallContext {
    KmsCallContext {
        source_service: "secretsmanager".to_owned(),
        account_id: scope.account_id.clone(),
        region: scope.region.clone(),
        request_id: request.request_id.clone(),
        caller_arn: None,
        iam_policy_allowed: false,
        iam_policy_denied: false,
    }
}

pub(super) fn encryption_context(arn: &str, version_id: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("SecretARN".to_owned(), arn.to_owned()),
        ("SecretVersionId".to_owned(), version_id.to_owned()),
    ])
}

pub(super) fn now_epoch() -> Result<f64, SecretsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .map_err(|_| SecretsError::Internal)
}

pub(super) fn policy_is_public(policy: &Value) -> bool {
    policy.get("Statement").is_some_and(|statements| {
        statements
            .as_array()
            .into_iter()
            .flatten()
            .any(|statement| {
                statement.get("Effect").and_then(Value::as_str) == Some("Allow")
                    && statement.get("Principal").is_some_and(|principal| {
                        principal.as_str() == Some("*")
                            || principal
                                .get("AWS")
                                .is_some_and(|aws| aws.as_str() == Some("*"))
                    })
            })
    })
}
