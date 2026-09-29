use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExecuteRequest {
    pub resource_arn: String,
    pub secret_arn: String,
    pub sql: String,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub parameters: Vec<SqlParameter>,
    #[serde(default)]
    pub transaction_id: Option<String>,
    #[serde(default)]
    pub include_result_metadata: bool,
    #[serde(default)]
    pub continue_after_timeout: bool,
    #[serde(default)]
    pub result_set_options: ResultSetOptions,
    #[serde(default)]
    pub format_records_as: Option<FormatRecordsAs>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BatchRequest {
    pub resource_arn: String,
    pub secret_arn: String,
    pub sql: String,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub parameter_sets: Vec<Vec<SqlParameter>>,
    #[serde(default)]
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BeginRequest {
    pub resource_arn: String,
    pub secret_arn: String,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub schema: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FinalizeRequest {
    pub resource_arn: String,
    pub secret_arn: String,
    pub transaction_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SqlParameter {
    pub name: String,
    pub value: Field,
    #[serde(default)]
    pub type_hint: Option<TypeHint>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Field {
    #[serde(default)]
    pub is_null: Option<bool>,
    #[serde(default)]
    pub boolean_value: Option<bool>,
    #[serde(default)]
    pub long_value: Option<i64>,
    #[serde(default)]
    pub double_value: Option<f64>,
    #[serde(default)]
    pub string_value: Option<String>,
    #[serde(default)]
    pub blob_value: Option<String>,
    #[serde(default)]
    pub array_value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum TypeHint {
    Date,
    Time,
    Timestamp,
    Decimal,
    Json,
    Uuid,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub(crate) enum FormatRecordsAs {
    #[serde(rename = "NONE")]
    None,
    #[serde(rename = "JSON")]
    Json,
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResultSetOptions {
    #[serde(default)]
    pub decimal_return_type: DecimalReturnType,
    #[serde(default)]
    pub long_return_type: LongReturnType,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
pub(crate) enum DecimalReturnType {
    #[default]
    #[serde(rename = "DOUBLE_OR_LONG")]
    DoubleOrLong,
    #[serde(rename = "STRING")]
    String,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
pub(crate) enum LongReturnType {
    #[default]
    #[serde(rename = "LONG")]
    Long,
    #[serde(rename = "STRING")]
    String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ColumnMetadata {
    pub label: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<i32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExecuteResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_metadata: Option<Vec<ColumnMetadata>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_records_updated: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<Vec<serde_json::Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted_records: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BatchResponse {
    pub update_results: Vec<UpdateResult>,
}

#[derive(Debug, Serialize)]
pub(crate) struct UpdateResult {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BeginResponse {
    pub transaction_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FinalizeResponse {
    pub transaction_status: &'static str,
}
