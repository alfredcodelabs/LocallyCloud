use locallycloud_state::StateDb;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use locallycloud_core::integration::kms::{
    KmsCallContext, KmsDecryptOutput, KmsDecryptRequest, KmsEncryptOutput, KmsEncryptRequest,
    KmsGenerateDataKeyOutput, KmsGenerateDataKeyRequest, KmsKeySelector, KmsValidateKeyOutput,
    KmsValidateKeyRequest, SensitiveBytes,
};
use serde_json::{json, Map, Value};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self};
use crate::error::KmsError;
use crate::model::{AliasRecord, KeyManager, KeyRecord, KeyState, Scope};
use crate::policy::KeyPolicy;
use crate::store::KmsStore;

mod aliases;
mod keys;

pub(crate) struct KmsService {
    store: KmsStore,
}

impl KmsService {
    pub(crate) fn new(db: Arc<StateDb>) -> Result<Self, KmsError> {
        Ok(Self {
            store: KmsStore::new(db)?,
        })
    }

    pub(crate) fn dispatch(
        &self,
        operation: &str,
        body: &Map<String, Value>,
        account_id: &str,
        region: &str,
    ) -> Result<Value, KmsError> {
        let scope = Scope::new(account_id, region);
        match operation {
            "CreateKey" => self.create_key(body, &scope),
            "CreateAlias" => self.create_alias(body, &scope),
            "UpdateAlias" => self.update_alias(body, &scope),
            "DeleteAlias" => self.delete_alias(body, &scope),
            "ListAliases" => self.list_aliases(body, &scope),
            "DescribeKey" => self.describe_key(body, &scope),
            "ListKeys" => self.list_keys(body, &scope),
            "ListResourceTags" => self.list_resource_tags(body, &scope),
            "Encrypt" => self.encrypt(body, &scope),
            "Decrypt" => self.decrypt(body, &scope),
            "GenerateDataKey" => self.generate_data_key(body, &scope),
            "GetKeyPolicy" => self.get_key_policy(body, &scope),
            "GetKeyRotationStatus" => self.get_key_rotation_status(body, &scope),
            "PutKeyPolicy" => self.put_key_policy(body, &scope),
            "ScheduleKeyDeletion" => self.schedule_key_deletion(body, &scope),
            _ => Err(KmsError::Unsupported),
        }
    }

    pub(crate) fn generate_data_key_internal(
        &self,
        request: KmsGenerateDataKeyRequest,
    ) -> Result<KmsGenerateDataKeyOutput, KmsError> {
        let KmsGenerateDataKeyRequest {
            call,
            key_id,
            number_of_bytes,
            encryption_context,
        } = request;
        validate_internal_call(&call)?;
        if !(1..=1024).contains(&number_of_bytes) {
            return Err(KmsError::Validation);
        }
        validate_internal_context(&encryption_context)?;
        let scope = Scope::new(&call.account_id, &call.region);
        let key_id = self.resolve_key_id(&key_id, &scope)?;
        let context = crypto::canonical_context(&encryption_context)?;
        let mut plaintext = Zeroizing::new(crypto::generate_data_key(number_of_bytes)?);
        let result = self
            .store
            .with_key(&scope, &key_id, |key| {
                if !key.is_enabled() {
                    return Err(KmsError::InvalidState);
                }
                if key
                    .owner_service
                    .as_deref()
                    .is_some_and(|owner| owner != call.source_service)
                    || !policy_allows(
                        key,
                        call.caller_arn.as_deref(),
                        "kms:GenerateDataKey",
                        None,
                        &scope,
                        call.iam_policy_allowed,
                    )
                {
                    return Err(KmsError::AccessDenied);
                }
                crypto::seal(
                    &key.material,
                    &scope,
                    &key.key_id,
                    key.material_version,
                    &context,
                    plaintext.to_vec(),
                )
                .map(|ciphertext| (ciphertext, scope.key_arn(&key.key_id)))
            })
            .ok_or(KmsError::NotFound)??;
        Ok(KmsGenerateDataKeyOutput {
            plaintext: SensitiveBytes::new(std::mem::take(&mut *plaintext)),
            ciphertext: SensitiveBytes::new(result.0),
            key_id: result.1,
        })
    }

    pub(crate) fn encrypt_internal(
        &self,
        request: KmsEncryptRequest,
    ) -> Result<KmsEncryptOutput, KmsError> {
        let KmsEncryptRequest {
            call,
            key,
            plaintext,
            encryption_context,
        } = request;
        validate_internal_call(&call)?;
        validate_internal_context(&encryption_context)?;
        let scope = Scope::new(&call.account_id, &call.region);
        let key_id = match key {
            KmsKeySelector::Explicit(key_id) => {
                if self.is_own_managed_alias(&key_id, &scope, &call.source_service) {
                    self.service_default_key(&scope, &call.source_service)?
                } else {
                    self.resolve_key_id(&key_id, &scope)?
                }
            }
            KmsKeySelector::ServiceDefault(service) => {
                if call.source_service != service.service_name() {
                    return Err(KmsError::AccessDenied);
                }
                self.service_default_key(&scope, service.service_name())?
            }
        };
        let context = crypto::canonical_context(&encryption_context)?;
        let ciphertext = self
            .store
            .with_key(&scope, &key_id, |key| {
                if key
                    .owner_service
                    .as_deref()
                    .is_some_and(|owner| owner != call.source_service)
                {
                    return Err(KmsError::AccessDenied);
                }
                if !key.is_enabled() {
                    return Err(KmsError::InvalidState);
                }
                crypto::seal(
                    &key.material,
                    &scope,
                    &key.key_id,
                    key.material_version,
                    &context,
                    plaintext.into_vec(),
                )
            })
            .ok_or(KmsError::NotFound)??;
        Ok(KmsEncryptOutput {
            ciphertext: SensitiveBytes::new(ciphertext),
            key_id: scope.key_arn(&key_id),
        })
    }

    pub(crate) fn decrypt_internal(
        &self,
        request: KmsDecryptRequest,
    ) -> Result<KmsDecryptOutput, KmsError> {
        let KmsDecryptRequest {
            call,
            key_id: requested_key_id,
            ciphertext,
            encryption_context,
        } = request;
        validate_internal_call(&call)?;
        validate_internal_context(&encryption_context)?;
        let scope = Scope::new(&call.account_id, &call.region);
        let ciphertext = Zeroizing::new(ciphertext.into_vec());
        let envelope = crypto::parse_envelope(&ciphertext)?;
        if envelope.scope != scope {
            return Err(KmsError::InvalidCiphertext);
        }
        if let Some(requested) = requested_key_id {
            if self.resolve_key_id(&requested, &scope)? != envelope.key_id {
                return Err(KmsError::InvalidCiphertext);
            }
        }
        let context = crypto::canonical_context(&encryption_context)?;
        let key_id = envelope.key_id.clone();
        let plaintext = self
            .store
            .with_key(&scope, &key_id, |key| {
                if key
                    .owner_service
                    .as_deref()
                    .is_some_and(|owner| owner != call.source_service)
                {
                    return Err(KmsError::AccessDenied);
                }
                if !key.is_enabled() {
                    return Err(KmsError::InvalidState);
                }
                if !policy_allows(
                    key,
                    call.caller_arn.as_deref(),
                    "kms:Decrypt",
                    None,
                    &scope,
                    call.iam_policy_allowed,
                ) {
                    return Err(KmsError::AccessDenied);
                }
                if key.material_version != envelope.material_version {
                    return Err(KmsError::InvalidCiphertext);
                }
                crypto::open(&key.material, envelope, &context)
            })
            .ok_or(KmsError::InvalidCiphertext)??;
        Ok(KmsDecryptOutput {
            plaintext: SensitiveBytes::new(plaintext),
            key_id: scope.key_arn(&key_id),
        })
    }

    pub(crate) fn validate_key_internal(
        &self,
        request: KmsValidateKeyRequest,
    ) -> Result<KmsValidateKeyOutput, KmsError> {
        validate_internal_call(&request.call)?;
        let scope = Scope::new(&request.call.account_id, &request.call.region);
        let key_id = self.resolve_key_id(&request.key_id, &scope)?;
        self.store
            .with_key(&scope, &key_id, |key| {
                if key
                    .owner_service
                    .as_deref()
                    .is_some_and(|owner| owner != request.call.source_service)
                {
                    Err(KmsError::AccessDenied)
                } else if key.is_enabled() {
                    Ok(())
                } else {
                    Err(KmsError::InvalidState)
                }
            })
            .ok_or(KmsError::NotFound)??;
        Ok(KmsValidateKeyOutput {
            key_arn: scope.key_arn(&key_id),
        })
    }

    fn service_default_key(&self, scope: &Scope, service: &str) -> Result<String, KmsError> {
        if !matches!(service, "ssm" | "secretsmanager") {
            return Err(KmsError::AccessDenied);
        }
        self.store.service_default_key(scope, service, || {
            let mut record =
                new_key_record(format!("Default key for {service}"), KeyManager::Aws, scope)?;
            record.owner_service = Some(service.to_owned());
            Ok(record)
        })
    }

    fn is_own_managed_alias(&self, key_id: &str, scope: &Scope, service: &str) -> bool {
        if !matches!(service, "ssm" | "secretsmanager") {
            return false;
        }
        let alias = format!("alias/aws/{service}");
        key_id == alias || key_id == scope.alias_arn(&alias)
    }

    fn encrypt(&self, body: &Map<String, Value>, scope: &Scope) -> Result<Value, KmsError> {
        require_known_fields(
            body,
            &[
                "KeyId",
                "Plaintext",
                "EncryptionContext",
                "GrantTokens",
                "EncryptionAlgorithm",
                "DryRun",
            ],
        )?;
        reject_nonempty_array(body, "GrantTokens")?;
        require_enum(body, "EncryptionAlgorithm", "SYMMETRIC_DEFAULT")?;
        if optional_bool(body, "DryRun")?.unwrap_or(false) {
            return Err(KmsError::Unsupported);
        }
        let key_id = self.resolve_key_id(required_string(body, "KeyId")?, scope)?;
        let plaintext = decode_blob(body, "Plaintext", 4096)?;
        let context = crypto::canonical_context(&encryption_context(body)?)?;
        let result = self
            .store
            .with_key(scope, &key_id, |key| {
                if !key.is_enabled() {
                    return Err(KmsError::InvalidState);
                }
                crypto::seal(
                    &key.material,
                    scope,
                    &key.key_id,
                    key.material_version,
                    &context,
                    plaintext,
                )
                .map(|ciphertext| (ciphertext, scope.key_arn(&key.key_id)))
            })
            .ok_or(KmsError::NotFound)??;
        Ok(json!({
            "CiphertextBlob": STANDARD.encode(result.0),
            "KeyId": result.1,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"
        }))
    }

    fn decrypt(&self, body: &Map<String, Value>, scope: &Scope) -> Result<Value, KmsError> {
        require_known_fields(
            body,
            &[
                "CiphertextBlob",
                "EncryptionContext",
                "GrantTokens",
                "KeyId",
                "EncryptionAlgorithm",
                "Recipient",
                "DryRun",
                "DryRunModifiers",
            ],
        )?;
        reject_nonempty_array(body, "GrantTokens")?;
        reject_nonempty_array(body, "DryRunModifiers")?;
        require_enum(body, "EncryptionAlgorithm", "SYMMETRIC_DEFAULT")?;
        if body.contains_key("Recipient") || optional_bool(body, "DryRun")?.unwrap_or(false) {
            return Err(KmsError::Unsupported);
        }
        let ciphertext = decode_blob(body, "CiphertextBlob", crypto::MAX_ENVELOPE)?;
        let envelope = crypto::parse_envelope(&ciphertext)?;
        if envelope.scope != *scope {
            return Err(KmsError::InvalidCiphertext);
        }
        if let Some(requested) = optional_string(body, "KeyId")? {
            if self.resolve_key_id(requested, scope)? != envelope.key_id {
                return Err(KmsError::InvalidCiphertext);
            }
        }
        let context = crypto::canonical_context(&encryption_context(body)?)?;
        let key_id = envelope.key_id.clone();
        let key_arn = scope.key_arn(&key_id);
        let mut plaintext = self
            .store
            .with_key(scope, &key_id, |key| {
                if !key.is_enabled() {
                    return Err(KmsError::InvalidState);
                }
                if !policy_allows(key, None, "kms:Decrypt", None, scope, false) {
                    return Err(KmsError::AccessDenied);
                }
                if key.material_version != envelope.material_version {
                    return Err(KmsError::InvalidCiphertext);
                }
                crypto::open(&key.material, envelope, &context)
            })
            .ok_or(KmsError::InvalidCiphertext)??;
        let encoded_plaintext = STANDARD.encode(&plaintext);
        plaintext.zeroize();
        Ok(json!({
            "KeyId": key_arn,
            "Plaintext": encoded_plaintext,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"
        }))
    }

    fn generate_data_key(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(
            body,
            &[
                "KeyId",
                "KeySpec",
                "NumberOfBytes",
                "EncryptionContext",
                "GrantTokens",
                "DryRun",
                "Recipient",
            ],
        )?;
        reject_nonempty_array(body, "GrantTokens")?;
        if body.contains_key("Recipient") || optional_bool(body, "DryRun")?.unwrap_or(false) {
            return Err(KmsError::Unsupported);
        }
        let length = match (body.get("KeySpec"), body.get("NumberOfBytes")) {
            (Some(Value::String(spec)), None) if spec == "AES_128" => 16,
            (Some(Value::String(spec)), None) if spec == "AES_256" => 32,
            (None, Some(Value::Number(number))) => {
                usize::try_from(number.as_u64().ok_or(KmsError::Validation)?)
                    .map_err(|_| KmsError::Validation)?
            }
            _ => return Err(KmsError::Validation),
        };
        let key_id = self.resolve_key_id(required_string(body, "KeyId")?, scope)?;
        let context = crypto::canonical_context(&encryption_context(body)?)?;
        let plaintext = Zeroizing::new(crypto::generate_data_key(length)?);
        let result = self
            .store
            .with_key(scope, &key_id, |key| {
                if !key.is_enabled() {
                    return Err(KmsError::InvalidState);
                }
                if !policy_allows(key, None, "kms:GenerateDataKey", None, scope, false) {
                    return Err(KmsError::AccessDenied);
                }
                crypto::seal(
                    &key.material,
                    scope,
                    &key.key_id,
                    key.material_version,
                    &context,
                    plaintext.to_vec(),
                )
                .map(|ciphertext| (ciphertext, scope.key_arn(&key.key_id)))
            })
            .ok_or(KmsError::NotFound)??;
        let encoded_plaintext = STANDARD.encode(&plaintext);
        Ok(
            json!({"CiphertextBlob": STANDARD.encode(result.0), "Plaintext": encoded_plaintext, "KeyId": result.1}),
        )
    }

    fn validate_alias_target(&self, value: &str, scope: &Scope) -> Result<String, KmsError> {
        let key_id = parse_direct_key_id(value, scope)?;
        self.store
            .with_key(scope, &key_id, |key| {
                if key.manager != KeyManager::Customer {
                    Err(KmsError::AccessDenied)
                } else if !key.is_enabled() {
                    Err(KmsError::InvalidState)
                } else {
                    Ok(())
                }
            })
            .ok_or(KmsError::NotFound)??;
        Ok(key_id)
    }

    fn resolve_key_id(&self, value: &str, scope: &Scope) -> Result<String, KmsError> {
        let alias_name = if value.starts_with("alias/") {
            validate_alias_name(value)?;
            Some(value.to_owned())
        } else if value.starts_with("arn:") {
            let alias_prefix = format!("arn:aws:kms:{}:{}:alias/", scope.region, scope.account_id);
            if let Some(suffix) = value.strip_prefix(&alias_prefix) {
                let alias_name = format!("alias/{suffix}");
                validate_alias_name(&alias_name)?;
                Some(alias_name)
            } else {
                return parse_direct_key_id(value, scope);
            }
        } else {
            None
        };

        match alias_name {
            Some(alias_name) => self
                .store
                .alias_target(scope, &alias_name)
                .ok_or(KmsError::NotFound),
            None => parse_direct_key_id(value, scope),
        }
    }
}

fn new_key_record(
    description: String,
    manager: KeyManager,
    scope: &Scope,
) -> Result<KeyRecord, KmsError> {
    Ok(KeyRecord {
        key_id: Uuid::new_v4().to_string(),
        description,
        creation_date: now_epoch()?,
        state: KeyState::Enabled,
        manager,
        owner_service: None,
        policy: KeyPolicy::default_for(&scope.account_id),
        explicit_policy: false,
        material_version: 1,
        material: crypto::generate_material()?,
    })
}

fn policy_allows(
    key: &KeyRecord,
    principal: Option<&str>,
    action: &str,
    source_arn: Option<&str>,
    scope: &Scope,
    iam_policy_allowed: bool,
) -> bool {
    !key.explicit_policy
        || key.policy.allows_with_iam(
            principal,
            action,
            source_arn,
            &scope.account_id,
            iam_policy_allowed,
        )
}

fn policy_name(body: &Map<String, Value>) -> Result<(), KmsError> {
    match optional_string(body, "PolicyName")? {
        None | Some("default") => Ok(()),
        _ => Err(KmsError::NotFound),
    }
}

fn validate_internal_call(call: &KmsCallContext) -> Result<(), KmsError> {
    if call.source_service.is_empty()
        || call.account_id.is_empty()
        || call.region.is_empty()
        || call.request_id.is_empty()
    {
        Err(KmsError::Validation)
    } else {
        Ok(())
    }
}

fn validate_internal_context(context: &BTreeMap<String, String>) -> Result<(), KmsError> {
    if context.len() > 64
        || context
            .iter()
            .any(|(key, value)| key.is_empty() || value.is_empty())
    {
        Err(KmsError::Validation)
    } else {
        Ok(())
    }
}

fn now_epoch() -> Result<f64, KmsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .map_err(|_| KmsError::Internal)
}

fn required_string<'a>(body: &'a Map<String, Value>, field: &str) -> Result<&'a str, KmsError> {
    body.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(KmsError::Validation)
}

fn optional_string<'a>(
    body: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, KmsError> {
    body.get(field)
        .map(|value| value.as_str().ok_or(KmsError::Validation))
        .transpose()
}

fn optional_bool(body: &Map<String, Value>, field: &str) -> Result<Option<bool>, KmsError> {
    body.get(field)
        .map(|value| value.as_bool().ok_or(KmsError::Validation))
        .transpose()
}

fn require_enum(body: &Map<String, Value>, field: &str, supported: &str) -> Result<(), KmsError> {
    match optional_string(body, field)? {
        Some(value) if value != supported => Err(KmsError::Unsupported),
        _ => Ok(()),
    }
}

fn reject_nonempty_array(body: &Map<String, Value>, field: &str) -> Result<(), KmsError> {
    let Some(value) = body.get(field) else {
        return Ok(());
    };
    let values = value.as_array().ok_or(KmsError::Validation)?;
    if values.is_empty() {
        Ok(())
    } else {
        Err(KmsError::Unsupported)
    }
}

fn require_known_fields(body: &Map<String, Value>, known: &[&str]) -> Result<(), KmsError> {
    if body.keys().all(|field| known.contains(&field.as_str())) {
        Ok(())
    } else {
        Err(KmsError::Validation)
    }
}

fn encryption_context(body: &Map<String, Value>) -> Result<BTreeMap<String, String>, KmsError> {
    let Some(value) = body.get("EncryptionContext") else {
        return Ok(BTreeMap::new());
    };
    let object = value.as_object().ok_or(KmsError::Validation)?;
    if object.len() > 64 {
        return Err(KmsError::Validation);
    }
    object
        .iter()
        .map(|(key, value)| {
            let value = value.as_str().ok_or(KmsError::Validation)?;
            if key.is_empty() || value.is_empty() {
                return Err(KmsError::Validation);
            }
            Ok((key.clone(), value.to_owned()))
        })
        .collect()
}

fn decode_blob(
    body: &Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<Vec<u8>, KmsError> {
    let encoded = required_string(body, field)?;
    if encoded.len() > maximum.saturating_mul(2) {
        return Err(KmsError::Validation);
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| KmsError::Serialization)?;
    if decoded.len() > maximum {
        return Err(KmsError::Validation);
    }
    Ok(decoded)
}

fn parse_direct_key_id(value: &str, scope: &Scope) -> Result<String, KmsError> {
    if value.starts_with("arn:") {
        let prefix = format!("arn:aws:kms:{}:{}:key/", scope.region, scope.account_id);
        let key_id = value.strip_prefix(&prefix).ok_or(KmsError::NotFound)?;
        if key_id.is_empty() || key_id.contains('/') {
            return Err(KmsError::Validation);
        }
        return Ok(key_id.to_owned());
    }
    if value.is_empty() || value.contains('/') {
        return Err(KmsError::Validation);
    }
    Ok(value.to_owned())
}

fn validate_alias_name(value: &str) -> Result<(), KmsError> {
    if value.len() > 256 {
        return Err(KmsError::LimitExceeded);
    }
    let suffix = value
        .strip_prefix("alias/")
        .ok_or(KmsError::InvalidAliasName)?;
    if suffix.is_empty()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-'))
    {
        return Err(KmsError::InvalidAliasName);
    }
    Ok(())
}

fn required_alias_name<'a>(body: &'a Map<String, Value>, field: &str) -> Result<&'a str, KmsError> {
    let value = required_string(body, field)?;
    validate_alias_name(value)?;
    if value.starts_with("alias/aws/") {
        Err(KmsError::InvalidAliasName)
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
