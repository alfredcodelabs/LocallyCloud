use http::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::error::SsmError;

pub(crate) const TARGET_PREFIX: &str = "AmazonSSM";
pub(crate) const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
pub(crate) const MAX_REQUEST_BODY: usize = 64 * 1024;

const OPERATIONS: &[&str] = &[
    "PutParameter",
    "GetParameter",
    "GetParametersByPath",
    "DescribeParameters",
    "DeleteParameter",
    "AddTagsToResource",
    "RemoveTagsFromResource",
    "ListTagsForResource",
];

pub(crate) fn validate_content_type(headers: &HeaderMap) -> Result<(), SsmError> {
    let media_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .ok_or(SsmError::Validation)?;
    if media_type.eq_ignore_ascii_case(CONTENT_TYPE) {
        Ok(())
    } else {
        Err(SsmError::Validation)
    }
}

pub(crate) fn operation(headers: &HeaderMap) -> Result<&str, SsmError> {
    let target = headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .ok_or(SsmError::UnknownOperation)?;
    target
        .strip_prefix(TARGET_PREFIX)
        .and_then(|suffix| suffix.strip_prefix('.'))
        .filter(|operation| !operation.is_empty() && !operation.contains('.'))
        .ok_or(SsmError::UnknownOperation)
}

pub(crate) fn is_allowed(operation: &str) -> bool {
    OPERATIONS.contains(&operation)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct PutParameterRequest {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) value: String,
    #[serde(rename = "Type")]
    pub(crate) parameter_type: Option<String>,
    pub(crate) key_id: Option<String>,
    pub(crate) overwrite: Option<bool>,
    pub(crate) allowed_pattern: Option<String>,
    pub(crate) tags: Option<Vec<TagInput>>,
    pub(crate) tier: Option<String>,
    pub(crate) policies: Option<String>,
    pub(crate) data_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct GetParameterRequest {
    pub(crate) name: String,
    pub(crate) with_decryption: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct DescribeParametersRequest {
    pub(crate) filters: Option<Vec<DescribeParametersLegacyFilter>>,
    pub(crate) parameter_filters: Option<Vec<DescribeParametersFilter>>,
    pub(crate) max_results: Option<u32>,
    pub(crate) next_token: Option<String>,
    pub(crate) shared: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct DescribeParametersLegacyFilter {
    pub(crate) key: String,
    pub(crate) values: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct DescribeParametersFilter {
    pub(crate) key: String,
    pub(crate) option: Option<String>,
    pub(crate) values: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct DeleteParameterRequest {
    pub(crate) name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct AddTagsToResourceRequest {
    pub(crate) resource_type: String,
    pub(crate) resource_id: String,
    pub(crate) tags: Vec<TagInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct RemoveTagsFromResourceRequest {
    pub(crate) resource_type: String,
    pub(crate) resource_id: String,
    pub(crate) tag_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct ListTagsForResourceRequest {
    pub(crate) resource_type: String,
    pub(crate) resource_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct TagInput {
    pub(crate) key: String,
    pub(crate) value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct PutParameterResponse {
    pub(crate) version: u64,
    pub(crate) tier: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct GetParameterResponse {
    pub(crate) parameter: ParameterOutput,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct DescribeParametersResponse {
    pub(crate) parameters: Vec<ParameterMetadataOutput>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ParameterMetadataOutput {
    pub(crate) name: String,
    #[serde(rename = "Type")]
    pub(crate) parameter_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    pub(crate) last_modified_date: f64,
    pub(crate) version: u64,
    pub(crate) tier: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) key_id: Option<String>,
    pub(crate) data_type: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ParameterOutput {
    pub(crate) name: String,
    #[serde(rename = "Type")]
    pub(crate) parameter_type: &'static str,
    pub(crate) value: String,
    pub(crate) version: u64,
    pub(crate) last_modified_date: f64,
    #[serde(rename = "ARN")]
    pub(crate) arn: String,
    pub(crate) data_type: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ListTagsForResourceResponse {
    pub(crate) tag_list: Vec<TagOutput>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct TagOutput {
    pub(crate) key: String,
    pub(crate) value: String,
}
