use super::*;

impl SecretsManagerHandler {
    pub(super) async fn get_secret_value(
        &self,
        input: GetSecretValueRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        validate_optional_token(input.version_id.as_deref())?;
        if let Some(stage) = input.version_stage.as_deref() {
            validate_stage(stage)?;
        }
        let slot =
            self.resolve_and_authorize(scope, &input.secret_id, request, "GetSecretValue")?;
        let (arn, name, version_id, stages, created_date, kind, ciphertext, key_arn) = {
            let guard = lock(&slot)?;
            let record = active_record(&guard)?;
            let selected = match (input.version_id.as_deref(), input.version_stage.as_deref()) {
                (Some(id), Some(stage)) => {
                    let stage_id = record
                        .stage_index
                        .get(stage)
                        .ok_or(SecretsError::ResourceNotFound)?;
                    if id != stage_id {
                        return Err(SecretsError::InvalidRequest);
                    }
                    id
                }
                (Some(id), None) => id,
                (None, Some(stage)) => record
                    .stage_index
                    .get(stage)
                    .map(String::as_str)
                    .ok_or(SecretsError::ResourceNotFound)?,
                (None, None) => record
                    .stage_index
                    .get("AWSCURRENT")
                    .map(String::as_str)
                    .ok_or(SecretsError::ResourceNotFound)?,
            };
            let version = record
                .versions
                .get(selected)
                .ok_or(SecretsError::ResourceNotFound)?;
            (
                record.arn.clone(),
                record.name.clone(),
                version.id.clone(),
                version.stages.clone(),
                version.created_date,
                version.kind,
                SensitiveBytes::new(version.ciphertext.as_slice().to_vec()),
                version.key_arn.clone(),
            )
        };
        let plaintext = self
            .decrypt_value(request, scope, &arn, &version_id, &key_arn, ciphertext)
            .await?;
        let (secret_string, secret_binary) = match kind {
            ValueKind::String => (Some(plaintext), None),
            ValueKind::Binary => (None, Some(plaintext)),
        };
        serialize(GetSecretValueOutput {
            arn,
            name,
            version_id,
            secret_string,
            secret_binary,
            version_stages: stages,
            created_date,
        })
    }

    pub(super) fn list_secret_version_ids(
        &self,
        input: ListSecretVersionIdsRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        let max = validate_max_results(input.max_results)?;
        let include_deprecated = input.include_deprecated.unwrap_or(false);
        let slot =
            self.resolve_and_authorize(scope, &input.secret_id, request, "ListSecretVersionIds")?;
        let guard = lock(&slot)?;
        let record = active_record(&guard)?;
        let ids: Vec<String> = record
            .versions
            .values()
            .filter(|version| include_deprecated || !version.stages.is_empty())
            .map(|version| version.id.clone())
            .collect();
        let query = format!("{}:{include_deprecated}:{max}", record.arn);
        let page = self.store.paginate(
            scope,
            "ListSecretVersionIds",
            query,
            ids,
            max,
            input.next_token.as_deref(),
        )?;
        let versions: Vec<Value> = page
            .ids
            .iter()
            .filter_map(|id| record.versions.get(id))
            .map(|version| {
                json!({
                    "VersionId": version.id,
                    "VersionStages": version.stages,
                    "CreatedDate": version.created_date,
                    "KmsKeyIds": [version.key_arn.clone()]
                })
            })
            .collect();
        let mut response = json!({
            "ARN": record.arn,
            "Name": record.name,
            "Versions": versions
        });
        if let Some(next_token) = page.next_token {
            response
                .as_object_mut()
                .ok_or(SecretsError::Internal)?
                .insert("NextToken".to_owned(), next_token.into());
        }
        serialize(response)
    }

    pub(super) fn describe_secret(
        &self,
        input: SecretIdRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        let slot =
            self.resolve_and_authorize(scope, &input.secret_id, request, "DescribeSecret")?;
        let guard = lock(&slot)?;
        let record = guard.as_ref().ok_or(SecretsError::ResourceNotFound)?;
        serialize(describe_value(record))
    }

    pub(super) fn list_secrets(
        &self,
        input: ListSecretsRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        if input.filters.is_some() || input.sort_order.is_some() {
            return Err(SecretsError::UnsupportedOperation);
        }
        let max = validate_max_results(input.max_results)?;
        let include_deleted = input.include_planned_deletion.unwrap_or(false);
        self.authorize(request, "ListSecrets", "*")?;
        let names = self.store.list_names(scope, include_deleted);
        let query = format!("{include_deleted}:{max}");
        let page = self.store.paginate(
            scope,
            "ListSecrets",
            query,
            names,
            max,
            input.next_token.as_deref(),
        )?;
        let secrets = self.store.records_for_names(scope, &page.ids)?;
        let mut response = json!({"SecretList": secrets});
        if let Some(next_token) = page.next_token {
            response
                .as_object_mut()
                .ok_or(SecretsError::Internal)?
                .insert("NextToken".to_owned(), next_token.into());
        }
        serialize(response)
    }

    pub(super) fn get_resource_policy(
        &self,
        input: SecretIdRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        let slot =
            self.resolve_and_authorize(scope, &input.secret_id, request, "GetResourcePolicy")?;
        let guard = lock(&slot)?;
        let record = active_record(&guard)?;
        let mut response = json!({"ARN": record.arn, "Name": record.name});
        if let Some(policy) = &record.resource_policy {
            response
                .as_object_mut()
                .ok_or(SecretsError::Internal)?
                .insert("ResourcePolicy".to_owned(), policy.clone().into());
        }
        serialize(response)
    }
}
