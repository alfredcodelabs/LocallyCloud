use std::collections::BTreeMap;

use http::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::error::LogsError;

pub const TARGET_PREFIX: &str = "Logs_20140328";
pub const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
pub const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const DESCRIBE_LOG_GROUPS_DEFAULT_LIMIT: u16 = 50;
pub const DESCRIBE_LOG_GROUPS_MAX_LIMIT: u16 = 50;
pub const DESCRIBE_LOG_STREAMS_DEFAULT_LIMIT: u16 = 50;
pub const DESCRIBE_LOG_STREAMS_MAX_LIMIT: u16 = 50;
pub const PUT_LOG_EVENTS_MAX_EVENTS: usize = 10_000;
pub const PUT_LOG_EVENTS_MAX_BATCH_BYTES: usize = 1_048_576;
pub const PUT_LOG_EVENTS_MAX_MESSAGE_BYTES: usize = 1_048_576;
pub const PUT_LOG_EVENTS_EVENT_OVERHEAD_BYTES: usize = 26;
pub const PUT_LOG_EVENTS_MAX_SPAN_MS: i64 = 24 * 60 * 60 * 1_000;
pub const EVENT_PAGE_DEFAULT_LIMIT: u32 = 10_000;
pub const EVENT_PAGE_MAX_LIMIT: u32 = 10_000;
pub const EVENT_PAGE_MAX_BYTES: usize = 1_048_576;
pub const RETENTION_DAYS: &[u16] = &[
    1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922,
    3288, 3653,
];

const OPERATIONS: &[&str] = &[
    "CreateLogGroup",
    "DescribeLogGroups",
    "DeleteLogGroup",
    "PutRetentionPolicy",
    "DeleteRetentionPolicy",
    "CreateLogStream",
    "DescribeLogStreams",
    "DeleteLogStream",
    "PutLogEvents",
    "GetLogEvents",
    "FilterLogEvents",
    "PutMetricFilter",
    "DescribeMetricFilters",
    "DeleteMetricFilter",
    "TestMetricFilter",
    "PutSubscriptionFilter",
    "DescribeSubscriptionFilters",
    "DeleteSubscriptionFilter",
    "PutDestination",
    "PutDestinationPolicy",
    "DescribeDestinations",
    "DeleteDestination",
    "StartQuery",
    "GetQueryResults",
    "StopQuery",
    "DescribeQueries",
    "TagResource",
    "UntagResource",
    "ListTagsForResource",
    "TagLogGroup",
    "UntagLogGroup",
    "ListTagsLogGroup",
];

pub fn validate_content_type(headers: &HeaderMap) -> Result<(), LogsError> {
    let value = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| LogsError::InvalidParameter("content-type must be AWS JSON 1.1".into()))?;
    let media_type = value.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case(CONTENT_TYPE) {
        Ok(())
    } else {
        Err(LogsError::InvalidParameter(
            "content-type must be AWS JSON 1.1".into(),
        ))
    }
}

pub fn operation(headers: &HeaderMap) -> Result<&str, LogsError> {
    let target = headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| LogsError::UnknownOperation("x-amz-target is missing or invalid".into()))?;
    let operation = target
        .strip_prefix(TARGET_PREFIX)
        .and_then(|suffix| suffix.strip_prefix('.'))
        .filter(|operation| !operation.is_empty() && !operation.contains('.'))
        .ok_or_else(|| LogsError::UnknownOperation("x-amz-target is invalid".into()))?;
    Ok(operation)
}

pub fn is_allowed(operation: &str) -> bool {
    OPERATIONS.contains(&operation)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateLogGroupRequest {
    pub log_group_name: String,
    pub kms_key_id: Option<String>,
    pub tags: Option<BTreeMap<String, String>>,
    pub log_group_class: Option<String>,
    pub deletion_protection_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeLogGroupsRequest {
    pub log_group_name_prefix: Option<String>,
    pub limit: Option<u16>,
    pub next_token: Option<String>,
    pub account_identifiers: Option<Vec<String>>,
    pub include_linked_accounts: Option<bool>,
    pub log_group_class: Option<String>,
    pub log_group_identifiers: Option<Vec<String>>,
    pub log_group_name_pattern: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeLogGroupsResponse {
    pub log_groups: Vec<LogGroupDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogGroupDescription {
    pub log_group_name: String,
    pub creation_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_in_days: Option<u16>,
    pub metric_filter_count: u64,
    pub arn: String,
    pub stored_bytes: u64,
    pub log_group_class: &'static str,
    pub log_group_arn: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteLogGroupRequest {
    pub log_group_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutRetentionPolicyRequest {
    pub log_group_name: String,
    pub retention_in_days: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteRetentionPolicyRequest {
    pub log_group_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateLogStreamRequest {
    pub log_group_name: String,
    pub log_stream_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeLogStreamsRequest {
    pub log_group_name: Option<String>,
    pub log_group_identifier: Option<String>,
    pub log_stream_name_prefix: Option<String>,
    pub order_by: Option<String>,
    pub descending: Option<bool>,
    pub next_token: Option<String>,
    pub limit: Option<u16>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeLogStreamsResponse {
    pub log_streams: Vec<LogStreamDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogStreamDescription {
    pub log_stream_name: String,
    pub creation_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_event_timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ingestion_time: Option<i64>,
    pub arn: String,
    pub stored_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteLogStreamRequest {
    pub log_group_name: String,
    pub log_stream_name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputLogEvent {
    pub timestamp: i64,
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutLogEventsRequest {
    pub log_group_name: String,
    pub log_stream_name: String,
    pub log_events: Vec<InputLogEvent>,
    pub sequence_token: Option<String>,
    pub entity: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PutLogEventsResponse {
    pub next_sequence_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_log_events_info: Option<RejectedLogEventsInfo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RejectedLogEventsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub too_old_log_event_end_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired_log_event_end_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub too_new_log_event_start_index: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetLogEventsRequest {
    pub log_group_name: Option<String>,
    pub log_group_identifier: Option<String>,
    pub log_stream_name: String,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub next_token: Option<String>,
    pub limit: Option<u32>,
    pub start_from_head: Option<bool>,
    pub unmask: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLogEventsResponse {
    pub events: Vec<OutputLogEvent>,
    pub next_forward_token: String,
    pub next_backward_token: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputLogEvent {
    pub timestamp: i64,
    pub message: String,
    pub ingestion_time: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilterLogEventsRequest {
    pub log_group_name: Option<String>,
    pub log_group_identifier: Option<String>,
    pub log_stream_names: Option<Vec<String>>,
    pub log_stream_name_prefix: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub filter_pattern: Option<String>,
    pub next_token: Option<String>,
    pub limit: Option<u32>,
    pub start_from_head: Option<bool>,
    pub interleaved: Option<bool>,
    pub unmask: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterLogEventsResponse {
    pub events: Vec<FilteredLogEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilteredLogEvent {
    pub log_stream_name: String,
    pub timestamp: i64,
    pub message: String,
    pub ingestion_time: i64,
    pub event_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TagResourceRequest {
    pub resource_arn: String,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UntagResourceRequest {
    pub resource_arn: String,
    pub tag_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListTagsForResourceRequest {
    pub resource_arn: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TagLogGroupRequest {
    pub log_group_name: String,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UntagLogGroupRequest {
    pub log_group_name: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListTagsLogGroupRequest {
    pub log_group_name: String,
}

#[derive(Debug, Serialize)]
pub struct ListTagsForResourceResponse {
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricTransformation {
    pub metric_name: String,
    pub metric_namespace: String,
    pub metric_value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutMetricFilterRequest {
    pub filter_name: String,
    pub filter_pattern: String,
    pub log_group_name: String,
    pub metric_transformations: Vec<MetricTransformation>,
    pub apply_on_transformed_logs: Option<bool>,
    pub field_selection_criteria: Option<String>,
    pub emit_system_field_dimensions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeMetricFiltersRequest {
    pub log_group_name: Option<String>,
    pub filter_name_prefix: Option<String>,
    pub next_token: Option<String>,
    pub limit: Option<u16>,
    pub metric_name: Option<String>,
    pub metric_namespace: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeMetricFiltersResponse {
    pub metric_filters: Vec<MetricFilterDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricFilterDescription {
    pub filter_name: String,
    pub filter_pattern: String,
    pub metric_transformations: Vec<MetricTransformation>,
    pub creation_time: i64,
    pub log_group_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteMetricFilterRequest {
    pub filter_name: String,
    pub log_group_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestMetricFilterRequest {
    pub filter_pattern: String,
    pub log_event_messages: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestMetricFilterResponse {
    pub matches: Vec<MetricFilterMatchRecord>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricFilterMatchRecord {
    pub event_number: usize,
    pub event_message: String,
    pub extracted_values: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutSubscriptionFilterRequest {
    pub log_group_name: String,
    pub filter_name: String,
    pub filter_pattern: String,
    pub destination_arn: String,
    pub role_arn: Option<String>,
    pub distribution: Option<String>,
    pub apply_on_transformed_logs: Option<bool>,
    pub field_selection_criteria: Option<String>,
    pub emit_system_fields: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeSubscriptionFiltersRequest {
    pub log_group_name: String,
    pub filter_name_prefix: Option<String>,
    pub next_token: Option<String>,
    pub limit: Option<u16>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeSubscriptionFiltersResponse {
    pub subscription_filters: Vec<SubscriptionFilterDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionFilterDescription {
    pub filter_name: String,
    pub log_group_name: String,
    pub filter_pattern: String,
    pub destination_arn: String,
    pub distribution: String,
    pub creation_time: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteSubscriptionFilterRequest {
    pub log_group_name: String,
    pub filter_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartQueryRequest {
    pub query_language: Option<String>,
    pub log_group_name: Option<String>,
    pub log_group_names: Option<Vec<String>>,
    pub log_group_identifiers: Option<Vec<String>>,
    pub start_time: i64,
    pub end_time: i64,
    pub query_string: String,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartQueryResponse {
    pub query_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetQueryResultsRequest {
    pub query_id: String,
    pub next_token: Option<String>,
    pub max_items: Option<u32>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResultField {
    pub field: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QueryStatistics {
    pub records_matched: f64,
    pub records_scanned: f64,
    pub bytes_scanned: f64,
    pub log_groups_scanned: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetQueryResultsResponse {
    pub query_language: &'static str,
    pub results: Vec<Vec<ResultField>>,
    pub statistics: QueryStatistics,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StopQueryRequest {
    pub query_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopQueryResponse {
    pub success: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeQueriesRequest {
    pub log_group_name: Option<String>,
    pub status: Option<String>,
    pub max_results: Option<u16>,
    pub next_token: Option<String>,
    pub query_language: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryInfo {
    pub query_language: &'static str,
    pub query_id: String,
    pub query_string: String,
    pub status: String,
    pub create_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_group_name: Option<String>,
    pub query_duration: i64,
    pub bytes_scanned: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeQueriesResponse {
    pub queries: Vec<QueryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}
