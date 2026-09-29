use http::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::error::SecretsError;
use crate::model::{SensitiveBinary, SensitiveString};

pub(crate) const TARGET_PREFIX: &str = "secretsmanager";
pub(crate) const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
pub(crate) const MAX_REQUEST_BODY: usize = 128 * 1024;

pub(crate) fn validate_content_type(headers: &HeaderMap) -> Result<(), SecretsError> {
    let media_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .ok_or(SecretsError::InvalidParameter)?;
    if media_type.eq_ignore_ascii_case(CONTENT_TYPE) {
        Ok(())
    } else {
        Err(SecretsError::InvalidParameter)
    }
}

pub(crate) fn operation(headers: &HeaderMap) -> Result<&str, SecretsError> {
    headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .and_then(|target| target.strip_prefix(&format!("{TARGET_PREFIX}.")))
        .filter(|operation| !operation.is_empty() && !operation.contains('.'))
        .ok_or(SecretsError::UnknownOperation)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct Tag {
    pub(crate) key: String,
    pub(crate) value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct CreateSecretRequest {
    pub(crate) name: String,
    pub(crate) client_request_token: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) kms_key_id: Option<String>,
    pub(crate) secret_binary: Option<SensitiveBinary>,
    pub(crate) secret_string: Option<SensitiveString>,
    pub(crate) tags: Option<Vec<Tag>>,
    pub(crate) add_replica_regions: Option<serde_json::Value>,
    pub(crate) force_overwrite_replica_secret: Option<bool>,
    #[serde(rename = "Type")]
    pub(crate) secret_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct PutSecretValueRequest {
    pub(crate) secret_id: String,
    pub(crate) client_request_token: Option<String>,
    pub(crate) secret_binary: Option<SensitiveBinary>,
    pub(crate) secret_string: Option<SensitiveString>,
    pub(crate) version_stages: Option<Vec<String>>,
    pub(crate) rotation_token: Option<SensitiveString>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct GetSecretValueRequest {
    pub(crate) secret_id: String,
    pub(crate) version_id: Option<String>,
    pub(crate) version_stage: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct UpdateSecretRequest {
    pub(crate) secret_id: String,
    pub(crate) client_request_token: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) kms_key_id: Option<String>,
    pub(crate) secret_binary: Option<SensitiveBinary>,
    pub(crate) secret_string: Option<SensitiveString>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct UpdateSecretVersionStageRequest {
    pub(crate) secret_id: String,
    pub(crate) version_stage: String,
    pub(crate) remove_from_version_id: Option<String>,
    pub(crate) move_to_version_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct ListSecretVersionIdsRequest {
    pub(crate) secret_id: String,
    pub(crate) include_deprecated: Option<bool>,
    pub(crate) max_results: Option<u32>,
    pub(crate) next_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct DeleteSecretRequest {
    pub(crate) secret_id: String,
    pub(crate) recovery_window_in_days: Option<u32>,
    pub(crate) force_delete_without_recovery: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct SecretIdRequest {
    pub(crate) secret_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct ListSecretsRequest {
    pub(crate) include_planned_deletion: Option<bool>,
    pub(crate) filters: Option<serde_json::Value>,
    pub(crate) max_results: Option<u32>,
    pub(crate) next_token: Option<String>,
    pub(crate) sort_order: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct TagResourceRequest {
    pub(crate) secret_id: String,
    pub(crate) tags: Vec<Tag>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct UntagResourceRequest {
    pub(crate) secret_id: String,
    pub(crate) tag_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct PutResourcePolicyRequest {
    pub(crate) secret_id: String,
    pub(crate) resource_policy: String,
    pub(crate) block_public_policy: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct RotateSecretRequest {
    pub(crate) secret_id: String,
    pub(crate) client_request_token: Option<String>,
    #[serde(rename = "RotationLambdaARN")]
    pub(crate) rotation_lambda_arn: Option<String>,
    pub(crate) rotation_rules: Option<RotationRules>,
    pub(crate) rotate_immediately: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct RotationRules {
    pub(crate) automatically_after_days: Option<u32>,
    pub(crate) duration: Option<String>,
    pub(crate) schedule_expression: Option<String>,
}
