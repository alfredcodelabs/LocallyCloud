use super::*;

impl SecretsManagerHandler {
    pub(super) async fn create_secret(
        &self,
        input: CreateSecretRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        validate_name(&input.name)?;
        validate_description(input.description.as_deref())?;
        if input.add_replica_regions.is_some()
            || input.force_overwrite_replica_secret.unwrap_or(false)
            || input.secret_type.is_some()
        {
            return Err(SecretsError::UnsupportedOperation);
        }
        let tags = validate_tags(input.tags.unwrap_or_default())?;
        let value = optional_value(input.secret_string, input.secret_binary)?;
        let version_id = value
            .as_ref()
            .map(|_| version_id(input.client_request_token.as_deref()))
            .transpose()?;
        let slot = self.store.slot_for_name(scope, &input.name);
        let arn = {
            let guard = lock(&slot)?;
            guard.as_ref().map_or_else(
                || {
                    let suffix = Uuid::new_v4().simple().to_string()[..6].to_owned();
                    scope.secret_arn(&input.name, &suffix)
                },
                |record| record.arn.clone(),
            )
        };
        self.authorize(request, "CreateSecret", &arn)?;
        if let Some(existing) = lock(&slot)?.as_ref() {
            if let (Some(value), Some(version_id)) = (value.as_ref(), version_id.as_deref()) {
                if version_matches(
                    existing,
                    version_id,
                    value,
                    VersionOperation::Create,
                    &BTreeSet::from(["AWSCURRENT".to_owned()]),
                ) {
                    return serialize(json!({
                        "ARN": existing.arn,
                        "Name": existing.name,
                        "VersionId": version_id
                    }));
                }
            }
            return Err(SecretsError::ResourceExists);
        }

        let now = now_epoch()?;
        let mut record = SecretRecord {
            arn: arn.clone(),
            name: input.name,
            description: input.description,
            kms_key_id: input.kms_key_id.clone(),
            created_date: now,
            last_changed_date: now,
            deleted_date: None,
            tags,
            resource_policy: None,
            rotation: None,
            versions: BTreeMap::new(),
            stage_index: BTreeMap::new(),
        };
        if let (Some(value), Some(version_id)) = (value, version_id.as_deref()) {
            let stages = BTreeSet::from(["AWSCURRENT".to_owned()]);
            let version = self
                .encrypt_version(
                    request,
                    scope,
                    &arn,
                    version_id,
                    value,
                    input.kms_key_id.as_deref(),
                    VersionOperation::Create,
                    stages.clone(),
                    now,
                )
                .await?;
            if input.kms_key_id.is_some() {
                record.kms_key_id = Some(version.key_arn.clone());
            }
            record.versions.insert(version_id.to_owned(), version);
            apply_stages(&mut record, version_id, &stages)?;
        }
        let name = record.name.clone();
        let mut guard = lock(&slot)?;
        if let Some(existing) = guard.as_ref() {
            if version_id.as_deref().is_some_and(|id| {
                record
                    .versions
                    .get(id)
                    .is_some_and(|prepared| prepared_version_matches(existing, id, prepared))
            }) {
                return serialize(json!({
                    "ARN": existing.arn,
                    "Name": existing.name,
                    "VersionId": version_id
                }));
            }
            return Err(SecretsError::ResourceExists);
        }
        *guard = Some(record);
        let mut response = json!({"ARN": arn, "Name": name});
        if let Some(version_id) = version_id {
            response
                .as_object_mut()
                .ok_or(SecretsError::Internal)?
                .insert("VersionId".to_owned(), version_id.into());
        }
        serialize(response)
    }

    pub(super) async fn put_secret_value(
        &self,
        input: PutSecretValueRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        if input.rotation_token.is_some() {
            return Err(SecretsError::UnsupportedOperation);
        }
        let value = required_value(input.secret_string, input.secret_binary)?;
        validate_value(&value)?;
        let version_id = version_id(input.client_request_token.as_deref())?;
        let stages = validate_stages(input.version_stages, true)?;
        let slot =
            self.resolve_and_authorize(scope, &input.secret_id, request, "PutSecretValue")?;
        let (arn, key_id) = {
            let guard = lock(&slot)?;
            let record = active_record(&guard)?;
            if version_matches(record, &version_id, &value, VersionOperation::Put, &stages) {
                return serialize(json!({
                    "ARN": record.arn,
                    "Name": record.name,
                    "VersionId": version_id,
                    "VersionStages": record.versions.get(&version_id).ok_or(SecretsError::Internal)?.stages
                }));
            }
            if record.versions.contains_key(&version_id) {
                return Err(SecretsError::ResourceExists);
            }
            (record.arn.clone(), record.kms_key_id.clone())
        };
        let now = now_epoch()?;
        let version = self
            .encrypt_version(
                request,
                scope,
                &arn,
                &version_id,
                value,
                key_id.as_deref(),
                VersionOperation::Put,
                stages.clone(),
                now,
            )
            .await?;
        let mut guard = lock(&slot)?;
        let record = active_record_mut(&mut guard)?;
        if record.arn != arn || record.kms_key_id != key_id {
            return Err(SecretsError::InvalidRequest);
        }
        if prepared_version_matches(record, &version_id, &version) {
            return serialize(json!({
                "ARN": record.arn,
                "Name": record.name,
                "VersionId": version_id,
                "VersionStages": record.versions.get(&version_id).ok_or(SecretsError::Internal)?.stages
            }));
        }
        if record.versions.contains_key(&version_id) {
            return Err(SecretsError::ResourceExists);
        }
        record.versions.insert(version_id.clone(), version);
        apply_stages(record, &version_id, &stages)?;
        record.last_changed_date = now;
        serialize(json!({
            "ARN": record.arn,
            "Name": record.name,
            "VersionId": version_id,
            "VersionStages": record.versions.get(&version_id).ok_or(SecretsError::Internal)?.stages
        }))
    }

    pub(super) async fn update_secret(
        &self,
        input: UpdateSecretRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        validate_description(input.description.as_deref())?;
        let value = optional_value(input.secret_string, input.secret_binary)?;
        if value.is_none() && input.description.is_none() && input.kms_key_id.is_none() {
            return Err(SecretsError::InvalidParameter);
        }
        let version_id = value
            .as_ref()
            .map(|_| version_id(input.client_request_token.as_deref()))
            .transpose()?;
        let slot = self.resolve_and_authorize(scope, &input.secret_id, request, "UpdateSecret")?;
        let stages = BTreeSet::from(["AWSCURRENT".to_owned()]);
        let (arn, current_key_id) = {
            let guard = lock(&slot)?;
            let record = active_record(&guard)?;
            if let (Some(value), Some(version_id)) = (value.as_ref(), version_id.as_deref()) {
                if version_matches(record, version_id, value, VersionOperation::Update, &stages) {
                    return serialize(json!({
                        "ARN": record.arn,
                        "Name": record.name,
                        "VersionId": version_id
                    }));
                }
                if record.versions.contains_key(version_id) {
                    return Err(SecretsError::ResourceExists);
                }
            }
            (record.arn.clone(), record.kms_key_id.clone())
        };
        let now = now_epoch()?;
        let version = if let (Some(value), Some(version_id)) = (value, version_id.as_deref()) {
            let key = input.kms_key_id.as_deref().or(current_key_id.as_deref());
            Some(
                self.encrypt_version(
                    request,
                    scope,
                    &arn,
                    version_id,
                    value,
                    key,
                    VersionOperation::Update,
                    stages.clone(),
                    now,
                )
                .await?,
            )
        } else {
            None
        };
        let mut guard = lock(&slot)?;
        let record = active_record_mut(&mut guard)?;
        if record.arn != arn || record.kms_key_id != current_key_id {
            return Err(SecretsError::InvalidRequest);
        }
        if let (Some(prepared), Some(id)) = (version.as_ref(), version_id.as_deref()) {
            if prepared_version_matches(record, id, prepared) {
                return serialize(json!({
                    "ARN": record.arn,
                    "Name": record.name,
                    "VersionId": id
                }));
            }
            if record.versions.contains_key(id) {
                return Err(SecretsError::ResourceExists);
            }
        }
        if let (Some(version), Some(version_id)) = (version, version_id.as_deref()) {
            if input.kms_key_id.is_some() {
                record.kms_key_id = Some(version.key_arn.clone());
            }
            record.versions.insert(version_id.to_owned(), version);
            apply_stages(record, version_id, &stages)?;
        } else if let Some(key_id) = input.kms_key_id {
            record.kms_key_id = Some(key_id);
        }
        if let Some(description) = input.description {
            record.description = Some(description);
        }
        record.last_changed_date = now;
        let mut response = json!({"ARN": record.arn, "Name": record.name});
        if let Some(version_id) = version_id {
            response
                .as_object_mut()
                .ok_or(SecretsError::Internal)?
                .insert("VersionId".to_owned(), version_id.into());
        }
        serialize(response)
    }

    pub(super) fn update_secret_version_stage(
        &self,
        input: UpdateSecretVersionStageRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        validate_stage(&input.version_stage)?;
        validate_optional_token(input.move_to_version_id.as_deref())?;
        validate_optional_token(input.remove_from_version_id.as_deref())?;
        if input.move_to_version_id.is_none() && input.remove_from_version_id.is_none() {
            return Err(SecretsError::InvalidParameter);
        }
        let slot = self.resolve_and_authorize(
            scope,
            &input.secret_id,
            request,
            "UpdateSecretVersionStage",
        )?;
        let mut guard = lock(&slot)?;
        let record = active_record_mut(&mut guard)?;
        if let Some(id) = input.move_to_version_id.as_deref() {
            if !record.versions.contains_key(id) {
                return Err(SecretsError::ResourceNotFound);
            }
        }
        if let Some(id) = input.remove_from_version_id.as_deref() {
            if !record.versions.contains_key(id) {
                return Err(SecretsError::ResourceNotFound);
            }
        }
        let owner = record.stage_index.get(&input.version_stage).cloned();
        if let Some(remove) = input.remove_from_version_id.as_deref() {
            if owner.as_deref() != Some(remove) {
                return Err(SecretsError::InvalidRequest);
            }
        }
        match input.move_to_version_id.as_deref() {
            Some(destination) => {
                if owner.as_deref() != Some(destination)
                    && owner.is_some()
                    && input.remove_from_version_id.is_none()
                {
                    return Err(SecretsError::InvalidRequest);
                }
                if input.version_stage == "AWSCURRENT" {
                    promote_current(record, destination)?;
                } else {
                    move_stage(record, &input.version_stage, destination)?;
                }
            }
            None => {
                let owner = owner.ok_or(SecretsError::InvalidRequest)?;
                remove_stage(record, &input.version_stage, &owner)?;
            }
        }
        record.last_changed_date = now_epoch()?;
        serialize(json!({"ARN": record.arn, "Name": record.name}))
    }

    pub(super) fn delete_secret(
        &self,
        input: DeleteSecretRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        let force = input.force_delete_without_recovery.unwrap_or(false);
        if force && input.recovery_window_in_days.is_some() {
            return Err(SecretsError::InvalidParameter);
        }
        let days = input.recovery_window_in_days.unwrap_or(30);
        if !force && !(7..=30).contains(&days) {
            return Err(SecretsError::InvalidParameter);
        }
        let slot = self.resolve_and_authorize(scope, &input.secret_id, request, "DeleteSecret")?;
        let mut guard = lock(&slot)?;
        let record = guard.as_mut().ok_or(SecretsError::ResourceNotFound)?;
        if record.deleted_date.is_some() {
            return Err(SecretsError::InvalidRequest);
        }
        let deletion_date = if force {
            now_epoch()?
        } else {
            now_epoch()? + f64::from(days) * 86_400.0
        };
        let arn = record.arn.clone();
        let name = record.name.clone();
        if force {
            *guard = None;
        } else {
            record.deleted_date = Some(deletion_date);
            record.last_changed_date = now_epoch()?;
        }
        serialize(json!({
            "ARN": arn,
            "Name": name,
            "DeletionDate": deletion_date
        }))
    }

    pub(super) fn restore_secret(
        &self,
        input: SecretIdRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        let slot = self.resolve_and_authorize(scope, &input.secret_id, request, "RestoreSecret")?;
        let mut guard = lock(&slot)?;
        let record = guard.as_mut().ok_or(SecretsError::ResourceNotFound)?;
        if record.deleted_date.is_none() {
            return Err(SecretsError::InvalidRequest);
        }
        record.deleted_date = None;
        record.last_changed_date = now_epoch()?;
        serialize(json!({"ARN": record.arn, "Name": record.name}))
    }

    pub(super) fn tag_resource(
        &self,
        input: TagResourceRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        let additions = validate_tags(input.tags)?;
        let slot = self.resolve_and_authorize(scope, &input.secret_id, request, "TagResource")?;
        let mut guard = lock(&slot)?;
        let record = active_record_mut(&mut guard)?;
        let mut tags = record.tags.clone();
        tags.extend(additions);
        if tags.len() > 50 {
            return Err(SecretsError::InvalidParameter);
        }
        record.tags = tags;
        record.last_changed_date = now_epoch()?;
        serialize(json!({}))
    }

    pub(super) fn untag_resource(
        &self,
        input: UntagResourceRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        if input.tag_keys.is_empty() {
            return Err(SecretsError::InvalidParameter);
        }
        for key in &input.tag_keys {
            validate_tag_key(key)?;
        }
        let slot = self.resolve_and_authorize(scope, &input.secret_id, request, "UntagResource")?;
        let mut guard = lock(&slot)?;
        let record = active_record_mut(&mut guard)?;
        for key in input.tag_keys {
            record.tags.remove(&key);
        }
        record.last_changed_date = now_epoch()?;
        serialize(json!({}))
    }

    pub(super) fn put_resource_policy(
        &self,
        input: PutResourcePolicyRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        let policy: Value = serde_json::from_str(&input.resource_policy)
            .map_err(|_| SecretsError::InvalidParameter)?;
        if !policy.is_object() || input.resource_policy.len() > 20_480 {
            return Err(SecretsError::InvalidParameter);
        }
        if input.block_public_policy.unwrap_or(false) && policy_is_public(&policy) {
            return Err(SecretsError::InvalidRequest);
        }
        let slot =
            self.resolve_and_authorize(scope, &input.secret_id, request, "PutResourcePolicy")?;
        let mut guard = lock(&slot)?;
        let record = active_record_mut(&mut guard)?;
        record.resource_policy = Some(input.resource_policy);
        record.last_changed_date = now_epoch()?;
        serialize(json!({"ARN": record.arn, "Name": record.name}))
    }

    pub(super) fn delete_resource_policy(
        &self,
        input: SecretIdRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        let slot =
            self.resolve_and_authorize(scope, &input.secret_id, request, "DeleteResourcePolicy")?;
        let mut guard = lock(&slot)?;
        let record = active_record_mut(&mut guard)?;
        record.resource_policy = None;
        record.last_changed_date = now_epoch()?;
        serialize(json!({"ARN": record.arn, "Name": record.name}))
    }
}
