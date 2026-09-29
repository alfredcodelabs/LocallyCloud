use super::*;

impl SecretsManagerHandler {
    pub(super) async fn rotate_secret(
        &self,
        input: RotateSecretRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        if input.rotate_immediately == Some(false) {
            return Err(SecretsError::UnsupportedOperation);
        }
        if let Some(rules) = input.rotation_rules {
            let _ = (
                rules.automatically_after_days,
                rules.duration,
                rules.schedule_expression,
            );
            return Err(SecretsError::UnsupportedOperation);
        }
        let version_id = version_id(input.client_request_token.as_deref())?;
        let slot = self.resolve_and_authorize(scope, &input.secret_id, request, "RotateSecret")?;
        {
            let mut guard = lock(&slot)?;
            let record = active_record_mut(&mut guard)?;
            let configured_lambda = record
                .rotation
                .as_ref()
                .map(|rotation| rotation.lambda_arn.clone());
            let lambda_arn = input
                .rotation_lambda_arn
                .or(configured_lambda)
                .ok_or(SecretsError::InvalidParameter)?;
            validate_rotation_lambda_arn(&lambda_arn, scope)?;

            if let Some(rotation) = record.rotation.as_ref() {
                if let Some(occurrence) = rotation.occurrence.as_ref() {
                    if occurrence.version_id == version_id
                        && occurrence.step == RotationStep::Complete
                    {
                        return serialize(json!({
                            "ARN": record.arn,
                            "Name": record.name,
                            "VersionId": version_id
                        }));
                    }
                    if occurrence.step != RotationStep::Complete
                        && (occurrence.version_id != version_id
                            || rotation.lambda_arn != lambda_arn
                            || occurrence.in_flight)
                    {
                        return Err(SecretsError::InvalidRequest);
                    }
                }
            }

            let rotation = record.rotation.get_or_insert_with(|| RotationState {
                enabled: true,
                lambda_arn: lambda_arn.clone(),
                occurrence: None,
                last_rotated_date: None,
            });
            rotation.enabled = true;
            rotation.lambda_arn = lambda_arn;
            if rotation.occurrence.as_ref().is_none_or(|occurrence| {
                occurrence.step == RotationStep::Complete && occurrence.version_id != version_id
            }) {
                rotation.occurrence = Some(RotationOccurrence {
                    version_id: version_id.clone(),
                    step: RotationStep::Create,
                    in_flight: false,
                });
            }
            record.last_changed_date = now_epoch()?;
        }

        self.persist().await?;
        loop {
            let (arn, name, lambda_arn, step) = {
                let mut guard = lock(&slot)?;
                let record = active_record_mut(&mut guard)?;
                let rotation = record
                    .rotation
                    .as_mut()
                    .ok_or(SecretsError::InvalidRequest)?;
                if !rotation.enabled {
                    return Err(SecretsError::InvalidRequest);
                }
                let occurrence = rotation
                    .occurrence
                    .as_mut()
                    .ok_or(SecretsError::InvalidRequest)?;
                if occurrence.version_id != version_id {
                    return Err(SecretsError::InvalidRequest);
                }
                if occurrence.step == RotationStep::Complete {
                    return serialize(json!({
                        "ARN": record.arn,
                        "Name": record.name,
                        "VersionId": version_id
                    }));
                }
                if occurrence.in_flight {
                    return Err(SecretsError::InvalidRequest);
                }
                occurrence.in_flight = true;
                (
                    record.arn.clone(),
                    record.name.clone(),
                    rotation.lambda_arn.clone(),
                    occurrence.step,
                )
            };

            self.persist().await?;
            let invocation = self
                .invoke_rotation_step(request, scope, &lambda_arn, &arn, &version_id, step)
                .await;

            let completed = {
                let mut guard = lock(&slot)?;
                let record = active_record_mut(&mut guard)?;
                let state_matches = record.rotation.as_ref().is_some_and(|rotation| {
                    rotation.enabled
                        && rotation.occurrence.as_ref().is_some_and(|occurrence| {
                            occurrence.version_id == version_id && occurrence.step == step
                        })
                });
                if !state_matches {
                    return Err(SecretsError::InvalidRequest);
                }
                if let Err(error) = invocation {
                    if let Some(occurrence) = record
                        .rotation
                        .as_mut()
                        .and_then(|rotation| rotation.occurrence.as_mut())
                    {
                        occurrence.in_flight = false;
                    }
                    return Err(error);
                }

                match step {
                    RotationStep::Create => {
                        let pending = record.stage_index.get("AWSPENDING");
                        let version = record.versions.get(&version_id);
                        if pending.map(String::as_str) != Some(version_id.as_str())
                            || version.is_none_or(|version| !version.stages.contains("AWSPENDING"))
                        {
                            if let Some(occurrence) = record
                                .rotation
                                .as_mut()
                                .and_then(|rotation| rotation.occurrence.as_mut())
                            {
                                occurrence.in_flight = false;
                            }
                            return Err(SecretsError::InvalidRequest);
                        }
                    }
                    RotationStep::Finish => {
                        if record.stage_index.get("AWSCURRENT").map(String::as_str)
                            != Some(version_id.as_str())
                        {
                            promote_current(record, &version_id)?;
                        }
                        if record.stage_index.get("AWSPENDING").map(String::as_str)
                            == Some(version_id.as_str())
                        {
                            remove_stage(record, "AWSPENDING", &version_id)?;
                        }
                    }
                    RotationStep::Set | RotationStep::Test => {}
                    RotationStep::Complete => return Err(SecretsError::Internal),
                }

                let now = now_epoch()?;
                let rotation = record.rotation.as_mut().ok_or(SecretsError::Internal)?;
                let occurrence = rotation.occurrence.as_mut().ok_or(SecretsError::Internal)?;
                occurrence.in_flight = false;
                occurrence.step = step.next();
                if occurrence.step == RotationStep::Complete {
                    rotation.last_rotated_date = Some(now);
                }
                record.last_changed_date = now;

                occurrence.step == RotationStep::Complete
            };
            self.persist().await?;
            if completed {
                return serialize(json!({
                    "ARN": arn,
                    "Name": name,
                    "VersionId": version_id
                }));
            }
        }
    }

    pub(super) fn cancel_rotate_secret(
        &self,
        input: SecretIdRequest,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Vec<u8>, SecretsError> {
        let slot =
            self.resolve_and_authorize(scope, &input.secret_id, request, "CancelRotateSecret")?;
        let mut guard = lock(&slot)?;
        let record = active_record_mut(&mut guard)?;
        let rotation = record
            .rotation
            .as_mut()
            .ok_or(SecretsError::InvalidRequest)?;
        if rotation.occurrence.as_ref().is_some_and(|occurrence| {
            occurrence.step != RotationStep::Complete || occurrence.in_flight
        }) {
            return Err(SecretsError::InvalidRequest);
        }
        rotation.enabled = false;
        record.last_changed_date = now_epoch()?;
        serialize(json!({"ARN": record.arn, "Name": record.name}))
    }

    async fn invoke_rotation_step(
        &self,
        request: &ServiceRequest,
        scope: &Scope,
        lambda_arn: &str,
        secret_arn: &str,
        version_id: &str,
        step: RotationStep,
    ) -> Result<(), SecretsError> {
        let step = step.event_name().ok_or(SecretsError::Internal)?;
        let payload = serde_json::to_vec(&json!({
            "Step": step,
            "SecretId": secret_arn,
            "ClientRequestToken": version_id
        }))
        .map_err(|_| SecretsError::Internal)?;
        let output = self
            .dispatcher()?
            .lambda_invoke(LambdaInvokeRequest {
                call: LambdaCallContext {
                    source_service: "secretsmanager".to_owned(),
                    account_id: scope.account_id.clone(),
                    region: scope.region.clone(),
                    request_id: request.request_id.clone(),
                    caller_arn: None,
                },
                function_name: lambda_arn.to_owned(),
                qualifier: None,
                payload: SensitivePayload::new(payload),
            })
            .await
            .map_err(map_lambda_error)?;
        if output.function_error.is_some() {
            return Err(SecretsError::Internal);
        }
        Ok(())
    }
}
