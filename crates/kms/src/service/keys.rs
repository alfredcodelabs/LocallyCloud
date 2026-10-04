use super::*;

impl KmsService {
    pub(super) fn create_key(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(
            body,
            &[
                "Policy",
                "Description",
                "KeyUsage",
                "CustomerMasterKeySpec",
                "KeySpec",
                "Origin",
                "CustomKeyStoreId",
                "BypassPolicyLockoutSafetyCheck",
                "Tags",
                "MultiRegion",
                "XksKeyId",
            ],
        )?;
        for unsupported in ["CustomKeyStoreId", "Tags", "XksKeyId"] {
            if body.contains_key(unsupported) {
                return Err(KmsError::Unsupported);
            }
        }
        require_enum(body, "KeyUsage", "ENCRYPT_DECRYPT")?;
        require_enum(body, "CustomerMasterKeySpec", "SYMMETRIC_DEFAULT")?;
        require_enum(body, "KeySpec", "SYMMETRIC_DEFAULT")?;
        require_enum(body, "Origin", "AWS_KMS")?;
        if optional_bool(body, "MultiRegion")?.unwrap_or(false) {
            return Err(KmsError::Unsupported);
        }
        let description = optional_string(body, "Description")?
            .unwrap_or_default()
            .to_owned();
        if description.len() > 8192 {
            return Err(KmsError::Validation);
        }

        let material = crypto::generate_material()?;
        let creation_date = now_epoch()?;
        let key_id = Uuid::new_v4().to_string();
        let policy = match optional_string(body, "Policy")? {
            Some(raw) => KeyPolicy::parse(raw.to_owned())?,
            None => KeyPolicy::default_for(&scope.account_id),
        };
        let explicit_policy = body.contains_key("Policy");
        if explicit_policy
            && !optional_bool(body, "BypassPolicyLockoutSafetyCheck")?.unwrap_or(false)
            && !policy.allows(
                Some(&format!("arn:aws:iam::{}:root", scope.account_id)),
                "kms:PutKeyPolicy",
                None,
                &scope.account_id,
            )
        {
            return Err(KmsError::AccessDenied);
        }
        let record = KeyRecord {
            key_id: key_id.clone(),
            description,
            creation_date,
            state: KeyState::Enabled,
            manager: KeyManager::Customer,
            owner_service: None,
            policy,
            explicit_policy,
            material_version: 1,
            material,
        };
        if !self.store.insert(scope, record)? {
            return Err(KmsError::Internal);
        }
        let metadata = self
            .store
            .with_key(scope, &key_id, |key| key.metadata(scope))
            .ok_or(KmsError::Internal)?;
        Ok(json!({ "KeyMetadata": metadata }))
    }

    pub(crate) fn key_admin_policy(
        &self,
        selector: &str,
        account: &str,
        region: &str,
    ) -> Result<(String, KeyPolicy, bool), KmsError> {
        let scope = Scope::new(account, region);
        let id = self.resolve_key_id(selector, &scope)?;
        self.store
            .with_key(&scope, &id, |key| {
                (scope.key_arn(&id), key.policy.clone(), key.explicit_policy)
            })
            .ok_or(KmsError::NotFound)
    }

    pub(super) fn set_enabled(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
        enabled: bool,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["KeyId"])?;
        let selector = required_string(body, "KeyId")?;
        // Enable/DisableKey accepts a key ID/ARN, never an alias.
        if selector.starts_with("alias/") || selector.contains(":alias/") {
            return Err(KmsError::Validation);
        }
        let key_id = self.resolve_key_id(selector, scope)?;
        self.store
            .with_key_mut(scope, &key_id, |key| {
                if key.manager != KeyManager::Customer {
                    return Err(KmsError::AccessDenied);
                }
                if matches!(key.state, KeyState::PendingDeletion { .. }) {
                    return Err(KmsError::InvalidState);
                }
                key.state = if enabled {
                    KeyState::Enabled
                } else {
                    KeyState::Disabled
                };
                Ok(())
            })?
            .ok_or(KmsError::NotFound)?;
        Ok(json!({}))
    }

    pub(super) fn describe_key(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["KeyId", "GrantTokens"])?;
        reject_nonempty_array(body, "GrantTokens")?;
        let key_id = self.resolve_key_id(required_string(body, "KeyId")?, scope)?;
        let metadata = self
            .store
            .with_key(scope, &key_id, |key| key.metadata(scope))
            .ok_or(KmsError::NotFound)?;
        Ok(json!({ "KeyMetadata": metadata }))
    }

    pub(super) fn list_keys(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["Limit", "Marker"])?;
        if body.contains_key("Limit") || body.contains_key("Marker") {
            return Err(KmsError::Unsupported);
        }
        let keys: Vec<Value> = self
            .store
            .list(scope)
            .into_iter()
            .map(|key| json!({ "KeyId": key.key_id, "KeyArn": key.key_arn }))
            .collect();
        Ok(json!({ "Keys": keys, "Truncated": false }))
    }

    pub(super) fn list_resource_tags(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["KeyId", "Limit", "Marker"])?;
        let key_id = self.resolve_key_id(required_string(body, "KeyId")?, scope)?;
        self.store
            .with_key(
                scope,
                &key_id,
                |_| json!({ "Tags": [], "Truncated": false }),
            )
            .ok_or(KmsError::NotFound)
    }

    pub(super) fn get_key_rotation_status(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["KeyId"])?;
        let key_id = self.resolve_key_id(required_string(body, "KeyId")?, scope)?;
        self.store
            .with_key(scope, &key_id, |_| json!({ "KeyRotationEnabled": false }))
            .ok_or(KmsError::NotFound)
    }

    pub(super) fn get_key_policy(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["KeyId", "PolicyName"])?;
        policy_name(body)?;
        let key_id = self.resolve_key_id(required_string(body, "KeyId")?, scope)?;
        let policy = self
            .store
            .with_key(scope, &key_id, |key| key.policy.raw().to_owned())
            .ok_or(KmsError::NotFound)?;
        Ok(json!({"Policy": policy}))
    }

    pub(super) fn put_key_policy(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(
            body,
            &[
                "KeyId",
                "PolicyName",
                "Policy",
                "BypassPolicyLockoutSafetyCheck",
            ],
        )?;
        policy_name(body)?;
        let key_id = self.resolve_key_id(required_string(body, "KeyId")?, scope)?;
        let policy = KeyPolicy::parse(required_string(body, "Policy")?.to_owned())?;
        if !optional_bool(body, "BypassPolicyLockoutSafetyCheck")?.unwrap_or(false)
            && !policy.allows(
                Some(&format!("arn:aws:iam::{}:root", scope.account_id)),
                "kms:PutKeyPolicy",
                None,
                &scope.account_id,
            )
        {
            return Err(KmsError::AccessDenied);
        }
        self.store
            .with_key_mut(scope, &key_id, |key| {
                if key.manager != KeyManager::Customer {
                    return Err(KmsError::AccessDenied);
                }
                key.policy = policy;
                key.explicit_policy = true;
                Ok(())
            })?
            .ok_or(KmsError::NotFound)?;
        Ok(json!({}))
    }

    pub(super) fn schedule_key_deletion(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["KeyId", "PendingWindowInDays"])?;
        let key_id = self.resolve_key_id(required_string(body, "KeyId")?, scope)?;
        let pending_window_days = match body.get("PendingWindowInDays") {
            None => 30,
            Some(value) => u32::try_from(value.as_u64().ok_or(KmsError::Validation)?)
                .map_err(|_| KmsError::Validation)?,
        };
        if !(7..=30).contains(&pending_window_days) {
            return Err(KmsError::Validation);
        }
        let deletion_date = now_epoch()? + f64::from(pending_window_days) * 86_400.0;
        let result = self
            .store
            .with_key_mut(scope, &key_id, |key| {
                if key.manager != KeyManager::Customer {
                    return Err(KmsError::AccessDenied);
                }
                if !matches!(key.state, KeyState::Enabled | KeyState::Disabled) {
                    return Err(KmsError::InvalidState);
                }
                key.state = KeyState::PendingDeletion {
                    deletion_date,
                    pending_window_days,
                };
                Ok((scope.key_arn(&key.key_id), key.pending_window_days()))
            })?
            .ok_or(KmsError::NotFound)?;
        Ok(json!({
            "KeyId": result.0,
            "DeletionDate": deletion_date,
            "KeyState": "PendingDeletion",
            "PendingWindowInDays": result.1
        }))
    }
}
