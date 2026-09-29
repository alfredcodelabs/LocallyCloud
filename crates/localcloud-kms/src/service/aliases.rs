use super::*;

impl KmsService {
    pub(super) fn create_alias(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["AliasName", "TargetKeyId"])?;
        let alias_name = required_alias_name(body, "AliasName")?;
        let target_key_id =
            self.validate_alias_target(required_string(body, "TargetKeyId")?, scope)?;
        let now = now_epoch()?;
        if !self.store.insert_alias(
            scope,
            AliasRecord {
                alias_name: alias_name.to_owned(),
                target_key_id,
                creation_date: now,
                last_updated_date: now,
            },
        )? {
            return Err(KmsError::AlreadyExists);
        }
        Ok(json!({}))
    }

    pub(super) fn update_alias(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["AliasName", "TargetKeyId"])?;
        let alias_name = required_alias_name(body, "AliasName")?;
        let target_key_id =
            self.validate_alias_target(required_string(body, "TargetKeyId")?, scope)?;
        if !self
            .store
            .update_alias(scope, alias_name, target_key_id, now_epoch()?)?
        {
            return Err(KmsError::NotFound);
        }
        Ok(json!({}))
    }

    pub(super) fn delete_alias(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["AliasName"])?;
        let alias_name = required_alias_name(body, "AliasName")?;
        if !self.store.remove_alias(scope, alias_name)? {
            return Err(KmsError::NotFound);
        }
        Ok(json!({}))
    }

    pub(super) fn list_aliases(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["KeyId", "Limit", "Marker"])?;
        if body.contains_key("Limit") || body.contains_key("Marker") {
            return Err(KmsError::Unsupported);
        }
        let target_filter = optional_string(body, "KeyId")?
            .map(|key_id| self.resolve_key_id(key_id, scope))
            .transpose()?;
        let aliases: Vec<Value> = self
            .store
            .list_aliases(scope)
            .into_iter()
            .filter(|alias| {
                target_filter
                    .as_ref()
                    .is_none_or(|target| alias.target_key_id == *target)
            })
            .map(|alias| {
                let alias_arn = scope.alias_arn(&alias.alias_name);
                json!({
                    "AliasName": alias.alias_name,
                    "AliasArn": alias_arn,
                    "TargetKeyId": alias.target_key_id,
                    "CreationDate": alias.creation_date,
                    "LastUpdatedDate": alias.last_updated_date
                })
            })
            .collect();
        Ok(json!({ "Aliases": aliases, "Truncated": false }))
    }
}
