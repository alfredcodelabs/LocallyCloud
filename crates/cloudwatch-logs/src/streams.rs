use crate::error::LogsError;
use crate::groups::validate_group_name;
use crate::model::{GroupKey, LogStream, ScopeKey};
use crate::pagination::{StreamDescribePaginator, StreamPage};
use crate::protocol::{
    CreateLogStreamRequest, DeleteLogStreamRequest, DescribeLogStreamsRequest,
    DescribeLogStreamsResponse, LogStreamDescription, DESCRIBE_LOG_STREAMS_DEFAULT_LIMIT,
    DESCRIBE_LOG_STREAMS_MAX_LIMIT,
};
use crate::store::LogsStore;

const ORDER_BY_NAME: &str = "LogStreamName";
const ORDER_BY_LAST_EVENT_TIME: &str = "LastEventTime";

pub fn create(
    store: &LogsStore,
    request: CreateLogStreamRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<(), LogsError> {
    validate_group_name(&request.log_group_name)?;
    validate_stream_name(&request.log_stream_name)?;
    let group_name = request.log_group_name;
    let stream_name = request.log_stream_name;
    let stream = LogStream {
        arn: format!(
            "arn:aws:logs:{}:{}:log-group:{}:log-stream:{}",
            scope.region, scope.account_id, group_name, stream_name
        ),
        name: stream_name.clone(),
        creation_time_ms: now_ms,
        events: Vec::new(),
        first_event_timestamp_ms: None,
        last_event_timestamp_ms: None,
        last_ingestion_time_ms: None,
        stored_bytes: 0,
        revision: 0,
    };
    store.create_stream(
        &GroupKey {
            scope,
            name: group_name,
        },
        stream,
    )
}

pub fn describe(
    store: &LogsStore,
    paginator: &StreamDescribePaginator,
    request: DescribeLogStreamsRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<DescribeLogStreamsResponse, LogsError> {
    let group_name = resolve_group_name(
        request.log_group_name.as_deref(),
        request.log_group_identifier.as_deref(),
        &scope,
    )?;
    let prefix = request.log_stream_name_prefix;
    if let Some(prefix) = prefix.as_deref() {
        validate_stream_name(prefix)?;
    }
    let order_by = request.order_by.unwrap_or_else(|| ORDER_BY_NAME.into());
    if !matches!(order_by.as_str(), ORDER_BY_NAME | ORDER_BY_LAST_EVENT_TIME) {
        return Err(LogsError::InvalidParameter(
            "orderBy must be LogStreamName or LastEventTime".into(),
        ));
    }
    if order_by == ORDER_BY_LAST_EVENT_TIME && prefix.is_some() {
        return Err(LogsError::InvalidParameter(
            "logStreamNamePrefix cannot be specified with LastEventTime ordering".into(),
        ));
    }
    let descending = request.descending.unwrap_or(false);
    let limit = request.limit.unwrap_or(DESCRIBE_LOG_STREAMS_DEFAULT_LIMIT);
    if !(1..=DESCRIBE_LOG_STREAMS_MAX_LIMIT).contains(&limit) {
        return Err(LogsError::InvalidParameter(
            "limit must be between 1 and 50".into(),
        ));
    }
    let key = GroupKey {
        scope: scope.clone(),
        name: group_name.clone(),
    };
    let page = if let Some(token) = request.next_token {
        paginator.next_page(
            &token,
            &scope,
            &group_name,
            prefix.as_deref(),
            &order_by,
            descending,
            usize::from(limit),
            now_ms,
        )?
    } else {
        let (revision, mut streams) = store.describe_streams(&key, prefix.as_deref())?;
        if order_by == ORDER_BY_LAST_EVENT_TIME {
            streams.sort_by(|left, right| {
                left.last_event_timestamp_ms
                    .cmp(&right.last_event_timestamp_ms)
                    .then_with(|| left.name.cmp(&right.name))
            });
        } else {
            streams.sort_by(|left, right| left.name.cmp(&right.name));
        }
        if descending {
            streams.reverse();
        }
        paginator.first_page(
            streams,
            scope,
            group_name,
            prefix,
            order_by,
            descending,
            usize::from(limit),
            revision,
            now_ms,
        )?
    };
    Ok(describe_response(page))
}

pub fn delete(
    store: &LogsStore,
    request: DeleteLogStreamRequest,
    scope: ScopeKey,
) -> Result<(), LogsError> {
    validate_group_name(&request.log_group_name)?;
    validate_stream_name(&request.log_stream_name)?;
    store.delete_stream(
        &GroupKey {
            scope,
            name: request.log_group_name,
        },
        &request.log_stream_name,
    )
}

pub(crate) fn resolve_group_name(
    name: Option<&str>,
    identifier: Option<&str>,
    scope: &ScopeKey,
) -> Result<String, LogsError> {
    match (name, identifier) {
        (Some(name), None) => {
            validate_group_name(name)?;
            Ok(name.to_owned())
        }
        (None, Some(identifier)) => {
            let prefix = format!(
                "arn:aws:logs:{}:{}:log-group:",
                scope.region, scope.account_id
            );
            let name = identifier
                .strip_prefix(&prefix)
                .and_then(|value| value.strip_suffix(":*").or(Some(value)))
                .ok_or_else(|| {
                    LogsError::ResourceNotFound(
                        "log group does not exist in this account and region".into(),
                    )
                })?;
            validate_group_name(name)?;
            Ok(name.to_owned())
        }
        _ => Err(LogsError::InvalidParameter(
            "exactly one of logGroupName and logGroupIdentifier is required".into(),
        )),
    }
}

fn describe_response(page: StreamPage) -> DescribeLogStreamsResponse {
    DescribeLogStreamsResponse {
        log_streams: page
            .streams
            .into_iter()
            .map(|stream| LogStreamDescription {
                log_stream_name: stream.name,
                creation_time: stream.creation_time_ms,
                first_event_timestamp: stream.first_event_timestamp_ms,
                last_event_timestamp: stream.last_event_timestamp_ms,
                last_ingestion_time: stream.last_ingestion_time_ms,
                arn: stream.arn,
                stored_bytes: stream.stored_bytes,
            })
            .collect(),
        next_token: page.next_token,
    }
}

pub(crate) fn validate_stream_name(name: &str) -> Result<(), LogsError> {
    if (1..=512).contains(&name.len()) && !name.bytes().any(|byte| matches!(byte, b':' | b'*')) {
        Ok(())
    } else {
        Err(LogsError::InvalidParameter(
            "logStreamName must be 1-512 characters and must not contain ':' or '*'".into(),
        ))
    }
}
