use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use localcloud_core::integration::delivery::DeliveryEngine;
use localcloud_core::registry::{ServiceName, ServiceRegistry};
use serde::{Deserialize, Serialize};

use crate::error::LogsError;
use crate::groups::validate_group_name;
use crate::model::{
    GroupKey, ScopeKey, StoredEvent, SubscriptionDeliveryCandidate, SubscriptionFilter,
};
use crate::pattern::FilterPattern;
use crate::protocol::{
    DeleteSubscriptionFilterRequest, DescribeSubscriptionFiltersRequest,
    DescribeSubscriptionFiltersResponse, PutSubscriptionFilterRequest,
    SubscriptionFilterDescription,
};
use crate::store::LogsStore;
use crate::subscription_delivery::lambda_call;

const MAX_FILTERS_PER_GROUP: usize = 2;
const MAX_REGEX_PER_GROUP: usize = 5;
const MAX_DESCRIBE_LIMIT: u16 = 50;

pub async fn put(
    store: &LogsStore,
    registry: &ServiceRegistry,
    request: PutSubscriptionFilterRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<(), LogsError> {
    validate_group_name(&request.log_group_name)?;
    validate_filter_name(&request.filter_name)?;
    if request.role_arn.is_some() {
        return Err(LogsError::InvalidParameter(
            "roleArn is not supported for direct Lambda subscriptions".into(),
        ));
    }
    if request.apply_on_transformed_logs.is_some()
        || request.field_selection_criteria.is_some()
        || request.emit_system_fields.is_some()
    {
        return Err(LogsError::InvalidParameter(
            "transformed-log and system-field subscription filters are not supported".into(),
        ));
    }
    let distribution = request.distribution.unwrap_or_else(|| "ByLogStream".into());
    if !matches!(distribution.as_str(), "ByLogStream" | "Random") {
        return Err(LogsError::InvalidParameter(
            "distribution must be ByLogStream or Random".into(),
        ));
    }
    let function_name = lambda_function_name(&request.destination_arn, &scope)?;
    if request.log_group_name == format!("/aws/lambda/{function_name}") {
        return Err(LogsError::InvalidParameter(
            "a Lambda function cannot subscribe its own conventional log group".into(),
        ));
    }
    let pattern = Arc::new(FilterPattern::compile(Some(&request.filter_pattern))?);

    let lambda = ServiceName::new("lambda");
    if registry.native_handler(&lambda).is_none() {
        return Err(LogsError::OperationUnavailable(
            "a concrete Lambda service is required".into(),
        ));
    }
    let dispatcher = registry.internal_dispatcher().ok_or_else(|| {
        LogsError::OperationUnavailable("the internal dispatcher is unavailable".into())
    })?;
    let response = DeliveryEngine::new(dispatcher)
        .deliver_sync(lambda_call(
            &scope,
            &function_name,
            b"{}".to_vec(),
            "DryRun",
        )?)
        .await;
    if response.status().as_u16() != 204 {
        return Err(LogsError::InvalidParameter(
            "destinationArn must identify an active Lambda function in this scope".into(),
        ));
    }

    store.put_subscription_filter(
        &GroupKey {
            scope,
            name: request.log_group_name,
        },
        SubscriptionFilter {
            name: request.filter_name,
            pattern_text: request.filter_pattern,
            pattern,
            destination_arn: request.destination_arn,
            function_name,
            distribution,
            creation_time_ms: now_ms,
            revision: 0,
        },
        MAX_FILTERS_PER_GROUP,
        MAX_REGEX_PER_GROUP,
    )
}

pub fn describe(
    store: &LogsStore,
    request: DescribeSubscriptionFiltersRequest,
    scope: ScopeKey,
) -> Result<DescribeSubscriptionFiltersResponse, LogsError> {
    validate_group_name(&request.log_group_name)?;
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
        name: request.log_group_name.clone(),
    };
    let mut filters = store.describe_subscription_filters(&key)?;
    filters.retain(|filter| {
        request
            .filter_name_prefix
            .as_deref()
            .is_none_or(|prefix| filter.name.starts_with(prefix))
    });
    let binding = TokenBinding {
        account_id: scope.account_id,
        region: scope.region,
        group_name: request.log_group_name.clone(),
        prefix: request.filter_name_prefix,
    };
    let offset = request
        .next_token
        .as_deref()
        .map(|token| decode_token(token, &binding))
        .transpose()?
        .unwrap_or(0);
    if offset > filters.len() {
        return Err(LogsError::InvalidParameter(
            "nextToken is outside the subscription filter result".into(),
        ));
    }
    let end = offset.saturating_add(usize::from(limit)).min(filters.len());
    let subscription_filters = filters[offset..end]
        .iter()
        .map(|filter| SubscriptionFilterDescription {
            filter_name: filter.name.clone(),
            log_group_name: request.log_group_name.clone(),
            filter_pattern: filter.pattern_text.clone(),
            destination_arn: filter.destination_arn.clone(),
            distribution: filter.distribution.clone(),
            creation_time: filter.creation_time_ms,
        })
        .collect();
    let next_token = (end < filters.len())
        .then(|| encode_token(&binding, end))
        .transpose()?;
    Ok(DescribeSubscriptionFiltersResponse {
        subscription_filters,
        next_token,
    })
}

pub fn delete(
    store: &LogsStore,
    request: DeleteSubscriptionFilterRequest,
    scope: ScopeKey,
) -> Result<(), LogsError> {
    validate_group_name(&request.log_group_name)?;
    validate_filter_name(&request.filter_name)?;
    store.delete_subscription_filter(
        &GroupKey {
            scope,
            name: request.log_group_name,
        },
        &request.filter_name,
    )
}

pub(crate) fn deliveries_for_events(
    filters: &[SubscriptionFilter],
    events: &[StoredEvent],
) -> Vec<SubscriptionDeliveryCandidate> {
    filters
        .iter()
        .filter_map(|filter| {
            let matches: Vec<_> = events
                .iter()
                .filter(|event| filter.pattern.matches(&event.message))
                .cloned()
                .collect();
            (!matches.is_empty()).then(|| SubscriptionDeliveryCandidate {
                filter_name: filter.name.clone(),
                filter_revision: filter.revision,
                function_name: filter.function_name.clone(),
                events: matches,
            })
        })
        .collect()
}

fn lambda_function_name(arn: &str, scope: &ScopeKey) -> Result<String, LogsError> {
    let parts: Vec<_> = arn.split(':').collect();
    if parts.len() != 7
        || parts[0] != "arn"
        || parts[1] != "aws"
        || parts[2] != "lambda"
        || parts[3] != scope.region
        || parts[4] != scope.account_id
        || parts[5] != "function"
        || parts[6].is_empty()
        || parts[6].len() > 64
        || !parts[6]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(LogsError::InvalidParameter(
            "destinationArn must be a same-scope unqualified Lambda function ARN".into(),
        ));
    }
    Ok(parts[6].to_owned())
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

#[derive(Serialize, Deserialize)]
struct SubscriptionPageToken {
    binding: TokenBinding,
    offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TokenBinding {
    account_id: String,
    region: String,
    group_name: String,
    prefix: Option<String>,
}

fn encode_token(binding: &TokenBinding, offset: usize) -> Result<String, LogsError> {
    let bytes = serde_json::to_vec(&SubscriptionPageToken {
        binding: binding.clone(),
        offset,
    })
    .map_err(|_| {
        LogsError::ServiceUnavailable("failed to encode subscription filter token".into())
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_token(token: &str, binding: &TokenBinding) -> Result<usize, LogsError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| LogsError::InvalidParameter("nextToken is invalid".into()))?;
    let page: SubscriptionPageToken = serde_json::from_slice(&bytes)
        .map_err(|_| LogsError::InvalidParameter("nextToken is invalid".into()))?;
    if &page.binding != binding {
        return Err(LogsError::InvalidParameter(
            "nextToken does not match the subscription filter request".into(),
        ));
    }
    Ok(page.offset)
}
