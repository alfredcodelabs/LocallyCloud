use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use locallycloud_core::integration::metrics::{MetricObservation, MetricOrigin};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::LogsError;
use crate::groups::validate_group_name;
use crate::model::{GroupKey, MetricEffectCandidate, MetricFilter, ScopeKey, StoredEvent};
use crate::pattern::FilterPattern;
use crate::protocol::{
    DeleteMetricFilterRequest, DescribeMetricFiltersRequest, DescribeMetricFiltersResponse,
    MetricFilterDescription, MetricFilterMatchRecord, MetricTransformation, PutMetricFilterRequest,
    TestMetricFilterRequest, TestMetricFilterResponse,
};
use crate::store::LogsStore;

const MAX_FILTERS_PER_GROUP: usize = 100;
const MAX_REGEX_PER_GROUP: usize = 5;
const MAX_DESCRIBE_LIMIT: u16 = 50;
const MAX_TEST_MESSAGES: usize = 50;

pub fn put(
    store: &LogsStore,
    request: PutMetricFilterRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<(), LogsError> {
    validate_group_name(&request.log_group_name)?;
    validate_filter_name(&request.filter_name)?;
    if request.apply_on_transformed_logs.is_some()
        || request.field_selection_criteria.is_some()
        || request.emit_system_field_dimensions.is_some()
    {
        return Err(LogsError::InvalidParameter(
            "transformed-log and system-field metric filters are not supported".into(),
        ));
    }
    if request.metric_transformations.len() != 1 {
        return Err(LogsError::InvalidParameter(
            "exactly one metric transformation is supported".into(),
        ));
    }
    let pattern = Arc::new(FilterPattern::compile(Some(&request.filter_pattern))?);
    let transformation = request
        .metric_transformations
        .into_iter()
        .next()
        .expect("one transformation was validated");
    validate_transformation(&transformation)?;
    store.put_metric_filter(
        &GroupKey {
            scope,
            name: request.log_group_name,
        },
        MetricFilter {
            name: request.filter_name,
            pattern_text: request.filter_pattern,
            pattern,
            transformation,
            creation_time_ms: now_ms,
            revision: 0,
        },
        MAX_FILTERS_PER_GROUP,
        MAX_REGEX_PER_GROUP,
    )
}

pub fn describe(
    store: &LogsStore,
    request: DescribeMetricFiltersRequest,
    scope: ScopeKey,
) -> Result<DescribeMetricFiltersResponse, LogsError> {
    let group_name = request.log_group_name.ok_or_else(|| {
        LogsError::InvalidParameter("logGroupName is required by this implementation".into())
    })?;
    validate_group_name(&group_name)?;
    if let Some(prefix) = request.filter_name_prefix.as_deref() {
        validate_filter_name(prefix)?;
    }
    let limit = request.limit.unwrap_or(MAX_DESCRIBE_LIMIT);
    if !(1..=MAX_DESCRIBE_LIMIT).contains(&limit) {
        return Err(LogsError::InvalidParameter(
            "limit must be between 1 and 50".into(),
        ));
    }
    let key = GroupKey {
        scope: scope.clone(),
        name: group_name.clone(),
    };
    let mut filters = store.describe_metric_filters(&key)?;
    filters.retain(|filter| {
        request
            .filter_name_prefix
            .as_deref()
            .is_none_or(|prefix| filter.name.starts_with(prefix))
            && request
                .metric_name
                .as_deref()
                .is_none_or(|name| filter.transformation.metric_name == name)
            && request
                .metric_namespace
                .as_deref()
                .is_none_or(|namespace| filter.transformation.metric_namespace == namespace)
    });
    let binding = TokenBinding {
        account_id: scope.account_id,
        region: scope.region,
        group_name: group_name.clone(),
        prefix: request.filter_name_prefix.clone(),
        metric_name: request.metric_name.clone(),
        metric_namespace: request.metric_namespace.clone(),
    };
    let offset = request
        .next_token
        .as_deref()
        .map(|token| decode_token(token, &binding))
        .transpose()?
        .unwrap_or(0);
    if offset > filters.len() {
        return Err(LogsError::InvalidParameter(
            "nextToken is outside the metric filter result".into(),
        ));
    }
    let end = offset.saturating_add(usize::from(limit)).min(filters.len());
    let metric_filters = filters[offset..end]
        .iter()
        .map(|filter| MetricFilterDescription {
            filter_name: filter.name.clone(),
            filter_pattern: filter.pattern_text.clone(),
            metric_transformations: vec![filter.transformation.clone()],
            creation_time: filter.creation_time_ms,
            log_group_name: group_name.clone(),
        })
        .collect();
    let next_token = (end < filters.len())
        .then(|| encode_token(&binding, end))
        .transpose()?;
    Ok(DescribeMetricFiltersResponse {
        metric_filters,
        next_token,
    })
}

pub fn delete(
    store: &LogsStore,
    request: DeleteMetricFilterRequest,
    scope: ScopeKey,
) -> Result<(), LogsError> {
    validate_group_name(&request.log_group_name)?;
    validate_filter_name(&request.filter_name)?;
    store.delete_metric_filter(
        &GroupKey {
            scope,
            name: request.log_group_name,
        },
        &request.filter_name,
    )
}

pub fn test(request: TestMetricFilterRequest) -> Result<TestMetricFilterResponse, LogsError> {
    if request.log_event_messages.is_empty() || request.log_event_messages.len() > MAX_TEST_MESSAGES
    {
        return Err(LogsError::InvalidParameter(
            "logEventMessages must contain between 1 and 50 messages".into(),
        ));
    }
    let pattern = FilterPattern::compile(Some(&request.filter_pattern))?;
    let matches = request
        .log_event_messages
        .into_iter()
        .enumerate()
        .filter(|(_, message)| pattern.matches(message))
        .map(|(event_number, event_message)| MetricFilterMatchRecord {
            event_number,
            event_message,
            extracted_values: BTreeMap::new(),
        })
        .collect();
    Ok(TestMetricFilterResponse { matches })
}

pub(crate) fn effects_for_events(
    group_key: &GroupKey,
    filters: &[MetricFilter],
    events: &[StoredEvent],
) -> Vec<MetricEffectCandidate> {
    let mut effects = Vec::new();
    for filter in filters {
        let mut occupied_minutes = BTreeSet::new();
        let mut matching_minutes = BTreeSet::new();
        for event in events {
            let minute = event.timestamp_ms.div_euclid(60_000);
            occupied_minutes.insert(minute);
            if !filter.pattern.matches(&event.message) {
                continue;
            }
            matching_minutes.insert(minute);
            if let Some(observation) = transform_event(group_key, filter, event) {
                effects.push(MetricEffectCandidate {
                    filter_name: filter.name.clone(),
                    filter_revision: filter.revision,
                    default_minute: None,
                    observation,
                });
            }
        }
        if let Some(default_value) = filter.transformation.default_value {
            for minute in occupied_minutes.difference(&matching_minutes) {
                effects.push(MetricEffectCandidate {
                    filter_name: filter.name.clone(),
                    filter_revision: filter.revision,
                    default_minute: Some(*minute),
                    observation: MetricObservation {
                        account_id: group_key.scope.account_id.clone(),
                        region: group_key.scope.region.clone(),
                        namespace: filter.transformation.metric_namespace.clone(),
                        metric_name: filter.transformation.metric_name.clone(),
                        dimensions: BTreeMap::new(),
                        timestamp_ms: minute.saturating_mul(60_000),
                        value: default_value,
                        unit: filter
                            .transformation
                            .unit
                            .as_deref()
                            .and_then(locallycloud_core::integration::metrics::MetricUnit::parse),
                        storage_resolution: 60,
                        origin: MetricOrigin::CloudWatchLogs,
                        correlation_id: format!(
                            "logs-default:{}:{}:{}",
                            group_key.name, filter.name, minute
                        ),
                    },
                });
            }
        }
    }
    effects
}

fn transform_event(
    group_key: &GroupKey,
    filter: &MetricFilter,
    event: &StoredEvent,
) -> Option<MetricObservation> {
    let parsed = serde_json::from_str::<Value>(&event.message).ok();
    let value = resolve_numeric(&filter.transformation.metric_value, parsed.as_ref())?;
    let mut dimensions = BTreeMap::new();
    for (name, selector) in filter
        .transformation
        .dimensions
        .as_ref()
        .into_iter()
        .flat_map(|dimensions| dimensions.iter())
    {
        dimensions.insert(name.clone(), resolve_text(selector, parsed.as_ref())?);
    }
    Some(MetricObservation {
        account_id: group_key.scope.account_id.clone(),
        region: group_key.scope.region.clone(),
        namespace: filter.transformation.metric_namespace.clone(),
        metric_name: filter.transformation.metric_name.clone(),
        dimensions,
        timestamp_ms: event.timestamp_ms,
        value,
        unit: filter
            .transformation
            .unit
            .as_deref()
            .and_then(locallycloud_core::integration::metrics::MetricUnit::parse),
        storage_resolution: 60,
        origin: MetricOrigin::CloudWatchLogs,
        correlation_id: event.id.clone(),
    })
}

fn validate_transformation(transformation: &MetricTransformation) -> Result<(), LogsError> {
    validate_metric_component("metricNamespace", &transformation.metric_namespace)?;
    validate_metric_component("metricName", &transformation.metric_name)?;
    if let Some(default) = transformation.default_value {
        if !default.is_finite() {
            return Err(LogsError::InvalidParameter(
                "defaultValue must be finite".into(),
            ));
        }
    }
    let dimensions = transformation.dimensions.as_ref();
    if dimensions.is_some_and(|dimensions| dimensions.len() > 3) {
        return Err(LogsError::InvalidParameter(
            "at most three metric dimensions are supported".into(),
        ));
    }
    if transformation.default_value.is_some()
        && dimensions.is_some_and(|dimensions| !dimensions.is_empty())
    {
        return Err(LogsError::InvalidParameter(
            "defaultValue cannot be combined with dimensions".into(),
        ));
    }
    if let Some(dimensions) = dimensions {
        for (name, selector) in dimensions {
            validate_metric_component("dimension name", name)?;
            parse_selector(selector)?;
        }
    }
    if transformation.metric_value.starts_with('$') {
        parse_selector(&transformation.metric_value)?;
    } else {
        let value = transformation
            .metric_value
            .parse::<f64>()
            .map_err(|_| LogsError::InvalidParameter("metricValue is invalid".into()))?;
        if !value.is_finite() {
            return Err(LogsError::InvalidParameter(
                "metricValue must be finite".into(),
            ));
        }
    }
    if let Some(unit) = transformation.unit.as_deref() {
        validate_unit(unit)?;
    }
    Ok(())
}

fn validate_filter_name(name: &str) -> Result<(), LogsError> {
    if (1..=512).contains(&name.len()) && !name.contains(':') && !name.contains('*') {
        Ok(())
    } else {
        Err(LogsError::InvalidParameter(
            "filterName is outside supported limits".into(),
        ))
    }
}

fn validate_metric_component(label: &str, value: &str) -> Result<(), LogsError> {
    if (1..=255).contains(&value.len()) && !value.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(LogsError::InvalidParameter(format!(
            "{label} is outside supported limits"
        )))
    }
}

fn validate_unit(unit: &str) -> Result<(), LogsError> {
    const UNITS: &[&str] = &[
        "Seconds",
        "Microseconds",
        "Milliseconds",
        "Bytes",
        "Kilobytes",
        "Megabytes",
        "Gigabytes",
        "Terabytes",
        "Bits",
        "Kilobits",
        "Megabits",
        "Gigabits",
        "Terabits",
        "Percent",
        "Count",
        "Bytes/Second",
        "Kilobytes/Second",
        "Megabytes/Second",
        "Gigabytes/Second",
        "Terabytes/Second",
        "Bits/Second",
        "Kilobits/Second",
        "Megabits/Second",
        "Gigabits/Second",
        "Terabits/Second",
        "Count/Second",
        "None",
    ];
    if UNITS.contains(&unit) {
        Ok(())
    } else {
        Err(LogsError::InvalidParameter(
            "unit is not a supported CloudWatch metric unit".into(),
        ))
    }
}

fn resolve_numeric(source: &str, root: Option<&Value>) -> Option<f64> {
    let value = if source.starts_with('$') {
        selected_value(root?, source)?
    } else {
        return source.parse::<f64>().ok().filter(|value| value.is_finite());
    };
    match value {
        Value::Number(number) => number.as_f64().filter(|value| value.is_finite()),
        Value::String(value) => value.parse::<f64>().ok().filter(|value| value.is_finite()),
        _ => None,
    }
}

fn resolve_text(source: &str, root: Option<&Value>) -> Option<String> {
    match selected_value(root?, source)? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn selected_value<'a>(root: &'a Value, source: &str) -> Option<&'a Value> {
    let segments = parse_selector(source).ok()?;
    let mut value = root;
    for segment in segments {
        value = match segment {
            PathSegment::Key(key) => value.as_object()?.get(&key)?,
            PathSegment::Index(index) => value.as_array()?.get(index)?,
        };
    }
    Some(value)
}

#[derive(Debug)]
enum PathSegment {
    Key(String),
    Index(usize),
}

fn parse_selector(source: &str) -> Result<Vec<PathSegment>, LogsError> {
    if source.len() > 256 || !source.starts_with('$') {
        return Err(LogsError::InvalidParameter(
            "metric selector is invalid".into(),
        ));
    }
    let bytes = source.as_bytes();
    let mut index = 1;
    let mut segments = Vec::new();
    while index < bytes.len() {
        if segments.len() >= 32 {
            return Err(LogsError::InvalidParameter(
                "metric selector is too deep".into(),
            ));
        }
        match bytes[index] {
            b'.' => {
                index += 1;
                let start = index;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'-'))
                {
                    index += 1;
                }
                if start == index {
                    return Err(LogsError::InvalidParameter(
                        "metric selector is invalid".into(),
                    ));
                }
                segments.push(PathSegment::Key(source[start..index].to_owned()));
            }
            b'[' => {
                let close = source[index + 1..]
                    .find(']')
                    .map(|offset| index + 1 + offset)
                    .ok_or_else(|| {
                        LogsError::InvalidParameter("metric selector is invalid".into())
                    })?;
                let content = &source[index + 1..close];
                if let Ok(value) = content.parse::<usize>() {
                    segments.push(PathSegment::Index(value));
                } else if content.len() >= 2
                    && ((content.starts_with('\'') && content.ends_with('\''))
                        || (content.starts_with('"') && content.ends_with('"')))
                {
                    segments.push(PathSegment::Key(content[1..content.len() - 1].to_owned()));
                } else {
                    return Err(LogsError::InvalidParameter(
                        "metric selector is invalid".into(),
                    ));
                }
                index = close + 1;
            }
            _ => {
                return Err(LogsError::InvalidParameter(
                    "metric selector is invalid".into(),
                ))
            }
        }
    }
    if segments.is_empty() {
        return Err(LogsError::InvalidParameter(
            "metric selector is invalid".into(),
        ));
    }
    Ok(segments)
}

#[derive(Serialize, Deserialize)]
struct MetricPageToken {
    binding: TokenBinding,
    offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TokenBinding {
    account_id: String,
    region: String,
    group_name: String,
    prefix: Option<String>,
    metric_name: Option<String>,
    metric_namespace: Option<String>,
}

fn encode_token(binding: &TokenBinding, offset: usize) -> Result<String, LogsError> {
    let bytes = serde_json::to_vec(&MetricPageToken {
        binding: binding.clone(),
        offset,
    })
    .map_err(|_| LogsError::ServiceUnavailable("failed to encode metric filter token".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_token(token: &str, binding: &TokenBinding) -> Result<usize, LogsError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| LogsError::InvalidParameter("nextToken is invalid".into()))?;
    let page: MetricPageToken = serde_json::from_slice(&bytes)
        .map_err(|_| LogsError::InvalidParameter("nextToken is invalid".into()))?;
    if &page.binding != binding {
        return Err(LogsError::InvalidParameter(
            "nextToken does not match the metric filter request".into(),
        ));
    }
    Ok(page.offset)
}
