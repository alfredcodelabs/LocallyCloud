use std::collections::BTreeMap;

use crate::error::LogsError;
use crate::model::{GroupKey, LogClass, LogGroup, ScopeKey};
use crate::pagination::{DescribePaginator, Page};
use crate::protocol::{
    CreateLogGroupRequest, DeleteLogGroupRequest, DeleteRetentionPolicyRequest,
    DescribeLogGroupsRequest, DescribeLogGroupsResponse, ListTagsForResourceRequest,
    ListTagsForResourceResponse, ListTagsLogGroupRequest, LogGroupDescription,
    PutRetentionPolicyRequest, TagLogGroupRequest, TagResourceRequest, UntagLogGroupRequest,
    UntagResourceRequest, DESCRIBE_LOG_GROUPS_DEFAULT_LIMIT, DESCRIBE_LOG_GROUPS_MAX_LIMIT,
    RETENTION_DAYS,
};
use crate::store::LogsStore;

pub fn create(
    store: &LogsStore,
    request: CreateLogGroupRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<(), LogsError> {
    validate_group_name(&request.log_group_name)?;
    if request.log_group_name.starts_with("aws/") {
        return Err(LogsError::InvalidParameter(
            "logGroupName must not start with aws/".into(),
        ));
    }
    if request.kms_key_id.is_some() {
        return Err(LogsError::InvalidParameter(
            "kmsKeyId is not supported".into(),
        ));
    }
    if request.deletion_protection_enabled.is_some() {
        return Err(LogsError::InvalidParameter(
            "deletionProtectionEnabled is not supported".into(),
        ));
    }
    if request.log_group_class.as_deref().unwrap_or("STANDARD") != "STANDARD" {
        return Err(LogsError::InvalidParameter(
            "only the STANDARD log group class is supported".into(),
        ));
    }
    let tags = request.tags.unwrap_or_default();
    validate_tags(&tags)?;
    let name = request.log_group_name;
    let group = LogGroup {
        arn: format!(
            "arn:aws:logs:{}:{}:log-group:{}",
            scope.region, scope.account_id, name
        ),
        name: name.clone(),
        creation_time_ms: now_ms,
        retention_days: None,
        class: LogClass::Standard,
        tags,
        streams: BTreeMap::new(),
        metric_filters: BTreeMap::new(),
        subscription_filters: BTreeMap::new(),
        revision: 0,
    };
    store.create_group(GroupKey { scope, name }, group)
}

pub fn describe(
    store: &LogsStore,
    paginator: &DescribePaginator,
    request: DescribeLogGroupsRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<DescribeLogGroupsResponse, LogsError> {
    reject_unsupported_describe_fields(&request)?;
    let prefix = request.log_group_name_prefix;
    if let Some(prefix) = prefix.as_deref() {
        validate_group_name(prefix)?;
    }
    let limit = request.limit.unwrap_or(DESCRIBE_LOG_GROUPS_DEFAULT_LIMIT);
    if !(1..=DESCRIBE_LOG_GROUPS_MAX_LIMIT).contains(&limit) {
        return Err(LogsError::InvalidParameter(
            "limit must be between 1 and 50".into(),
        ));
    }

    let page = if let Some(token) = request.next_token {
        paginator.next_page(
            &token,
            &scope,
            prefix.as_deref(),
            usize::from(limit),
            now_ms,
        )?
    } else {
        let (revision, groups) = store.describe_groups(&scope, prefix.as_deref())?;
        paginator.first_page(groups, scope, prefix, usize::from(limit), revision, now_ms)?
    };
    Ok(describe_response(page))
}

pub fn delete(
    store: &LogsStore,
    request: DeleteLogGroupRequest,
    scope: ScopeKey,
) -> Result<(), LogsError> {
    validate_group_name(&request.log_group_name)?;
    store.delete_group(&GroupKey {
        scope,
        name: request.log_group_name,
    })
}

pub fn put_retention(
    store: &LogsStore,
    request: PutRetentionPolicyRequest,
    scope: ScopeKey,
) -> Result<(), LogsError> {
    validate_group_name(&request.log_group_name)?;
    if !RETENTION_DAYS.contains(&request.retention_in_days) {
        return Err(LogsError::InvalidParameter(
            "retentionInDays is not an allowed CloudWatch Logs retention period".into(),
        ));
    }
    store.set_retention(
        &GroupKey {
            scope,
            name: request.log_group_name,
        },
        Some(request.retention_in_days),
    )
}

pub fn delete_retention(
    store: &LogsStore,
    request: DeleteRetentionPolicyRequest,
    scope: ScopeKey,
) -> Result<(), LogsError> {
    validate_group_name(&request.log_group_name)?;
    store.set_retention(
        &GroupKey {
            scope,
            name: request.log_group_name,
        },
        None,
    )
}

pub fn tag_resource(
    store: &LogsStore,
    request: TagResourceRequest,
    scope: ScopeKey,
) -> Result<(), LogsError> {
    validate_tags(&request.tags)?;
    let key = group_key_from_arn(&request.resource_arn, scope)?;
    store.tag_group(&key, request.tags)
}

pub fn untag_resource(
    store: &LogsStore,
    request: UntagResourceRequest,
    scope: ScopeKey,
) -> Result<(), LogsError> {
    validate_tag_keys(&request.tag_keys)?;
    let key = group_key_from_arn(&request.resource_arn, scope)?;
    store.untag_group(&key, &request.tag_keys)
}

pub fn list_tags_for_resource(
    store: &LogsStore,
    request: ListTagsForResourceRequest,
    scope: ScopeKey,
) -> Result<ListTagsForResourceResponse, LogsError> {
    let key = group_key_from_arn(&request.resource_arn, scope)?;
    Ok(ListTagsForResourceResponse {
        tags: store.list_tags(&key)?,
    })
}

pub fn tag_log_group(
    store: &LogsStore,
    request: TagLogGroupRequest,
    scope: ScopeKey,
) -> Result<(), LogsError> {
    validate_group_name(&request.log_group_name)?;
    validate_tags(&request.tags)?;
    store.tag_group(
        &GroupKey {
            scope,
            name: request.log_group_name,
        },
        request.tags,
    )
}

pub fn untag_log_group(
    store: &LogsStore,
    request: UntagLogGroupRequest,
    scope: ScopeKey,
) -> Result<(), LogsError> {
    validate_group_name(&request.log_group_name)?;
    validate_tag_keys(&request.tags)?;
    store.untag_group(
        &GroupKey {
            scope,
            name: request.log_group_name,
        },
        &request.tags,
    )
}

pub fn list_tags_log_group(
    store: &LogsStore,
    request: ListTagsLogGroupRequest,
    scope: ScopeKey,
) -> Result<ListTagsForResourceResponse, LogsError> {
    validate_group_name(&request.log_group_name)?;
    Ok(ListTagsForResourceResponse {
        tags: store.list_tags(&GroupKey {
            scope,
            name: request.log_group_name,
        })?,
    })
}

fn group_key_from_arn(arn: &str, scope: ScopeKey) -> Result<GroupKey, LogsError> {
    let expected_prefix = format!(
        "arn:aws:logs:{}:{}:log-group:",
        scope.region, scope.account_id
    );
    if arn.starts_with("arn:aws:logs:") && !arn.starts_with(&expected_prefix) {
        return Err(LogsError::ResourceNotFound(
            "log group does not exist in this account and region".into(),
        ));
    }
    let name = arn
        .strip_prefix(&expected_prefix)
        .filter(|name| !name.ends_with(":*"))
        .ok_or_else(|| LogsError::InvalidParameter("resourceArn is not a log group ARN".into()))?;
    validate_group_name(name)?;
    Ok(GroupKey {
        scope,
        name: name.to_string(),
    })
}

fn reject_unsupported_describe_fields(request: &DescribeLogGroupsRequest) -> Result<(), LogsError> {
    if request.account_identifiers.is_some()
        || request.include_linked_accounts.is_some()
        || request.log_group_class.is_some()
        || request.log_group_identifiers.is_some()
        || request.log_group_name_pattern.is_some()
    {
        return Err(LogsError::InvalidParameter(
            "linked-account, identifier, pattern, and class filters are not supported".into(),
        ));
    }
    Ok(())
}

fn describe_response(page: Page) -> DescribeLogGroupsResponse {
    DescribeLogGroupsResponse {
        log_groups: page.groups.into_iter().map(group_description).collect(),
        next_token: page.next_token,
    }
}

fn group_description(group: LogGroup) -> LogGroupDescription {
    let legacy_arn = group.legacy_arn();
    LogGroupDescription {
        log_group_name: group.name,
        creation_time: group.creation_time_ms,
        retention_in_days: group.retention_days,
        metric_filter_count: group.metric_filters.len() as u64,
        arn: legacy_arn,
        stored_bytes: group.streams.values().fold(0_u64, |total, stream| {
            total.saturating_add(stream.stored_bytes)
        }),
        log_group_class: "STANDARD",
        log_group_arn: group.arn,
    }
}

pub(crate) fn validate_group_name(name: &str) -> Result<(), LogsError> {
    let valid = (1..=512).contains(&name.len())
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/' | b'#')
        });
    if valid {
        Ok(())
    } else {
        Err(LogsError::InvalidParameter(
            "logGroupName must be 1-512 AWS-compatible characters".into(),
        ))
    }
}

fn validate_tag_keys(tag_keys: &[String]) -> Result<(), LogsError> {
    if tag_keys.len() > 50 || tag_keys.iter().any(|key| key.is_empty() || key.len() > 128) {
        Err(LogsError::InvalidParameter(
            "tag keys exceed the supported CloudWatch Logs limits".into(),
        ))
    } else {
        Ok(())
    }
}

fn validate_tags(tags: &BTreeMap<String, String>) -> Result<(), LogsError> {
    if tags.len() > 50
        || tags
            .iter()
            .any(|(key, value)| key.is_empty() || key.len() > 128 || value.len() > 256)
    {
        return Err(LogsError::InvalidParameter(
            "tags exceed the supported CloudWatch Logs limits".into(),
        ));
    }
    Ok(())
}
