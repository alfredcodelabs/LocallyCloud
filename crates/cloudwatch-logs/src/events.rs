use crate::error::LogsError;
use crate::groups::validate_group_name;
use crate::model::{GroupKey, PagedEvent, PendingLogEvent, RejectedEventIndexes, ScopeKey};
use crate::pagination::{EventNextPageRequest, EventPage, EventPaginator};
use crate::pattern::FilterPattern;
use crate::protocol::{
    FilterLogEventsRequest, FilterLogEventsResponse, FilteredLogEvent, GetLogEventsRequest,
    GetLogEventsResponse, OutputLogEvent, PutLogEventsRequest, PutLogEventsResponse,
    RejectedLogEventsInfo, EVENT_PAGE_DEFAULT_LIMIT, EVENT_PAGE_MAX_BYTES, EVENT_PAGE_MAX_LIMIT,
    PUT_LOG_EVENTS_EVENT_OVERHEAD_BYTES, PUT_LOG_EVENTS_MAX_BATCH_BYTES, PUT_LOG_EVENTS_MAX_EVENTS,
    PUT_LOG_EVENTS_MAX_MESSAGE_BYTES,
};
use crate::store::LogsStore;
use crate::streams::{resolve_group_name, validate_stream_name};

pub fn put(
    store: &LogsStore,
    request: PutLogEventsRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<PutLogEventsResponse, LogsError> {
    validate_group_name(&request.log_group_name)?;
    validate_stream_name(&request.log_stream_name)?;
    if request.entity.is_some() {
        return Err(LogsError::InvalidParameter(
            "entity is not supported".into(),
        ));
    }
    let _ignored_sequence_token = request.sequence_token;
    let events = validate_batch(request.log_events)?;
    let result = store.put_events(
        &GroupKey {
            scope,
            name: request.log_group_name,
        },
        &request.log_stream_name,
        events,
        now_ms,
    )?;
    Ok(PutLogEventsResponse {
        next_sequence_token: result.next_sequence_token,
        rejected_log_events_info: rejected_info(result.rejected),
    })
}

fn validate_batch(
    events: Vec<crate::protocol::InputLogEvent>,
) -> Result<Vec<PendingLogEvent>, LogsError> {
    if events.is_empty() || events.len() > PUT_LOG_EVENTS_MAX_EVENTS {
        return Err(LogsError::InvalidParameter(
            "logEvents must contain between 1 and 10000 events".into(),
        ));
    }
    let mut bytes = 0_usize;
    for (index, event) in events.iter().enumerate() {
        let message_bytes = event.message.len();
        if message_bytes > PUT_LOG_EVENTS_MAX_MESSAGE_BYTES {
            return Err(LogsError::InvalidParameter(
                "an event message exceeds 1048576 UTF-8 bytes".into(),
            ));
        }
        bytes = bytes
            .checked_add(message_bytes)
            .and_then(|value| value.checked_add(PUT_LOG_EVENTS_EVENT_OVERHEAD_BYTES))
            .ok_or_else(|| LogsError::InvalidParameter("logEvents batch size overflow".into()))?;
        if bytes > PUT_LOG_EVENTS_MAX_BATCH_BYTES {
            return Err(LogsError::InvalidParameter(
                "logEvents exceed the 1048576-byte batch limit".into(),
            ));
        }
        if index > 0 && events[index - 1].timestamp > event.timestamp {
            return Err(LogsError::InvalidParameter(
                "logEvents must be in nondecreasing timestamp order".into(),
            ));
        }
    }
    events
        .into_iter()
        .enumerate()
        .map(|(index, event)| {
            Ok(PendingLogEvent {
                timestamp_ms: event.timestamp,
                event_ordinal: u32::try_from(index).map_err(|_| {
                    LogsError::InvalidParameter("too many log events in the batch".into())
                })?,
                message: event.message,
            })
        })
        .collect()
}

fn rejected_info(indexes: RejectedEventIndexes) -> Option<RejectedLogEventsInfo> {
    if indexes.too_old_end.is_none()
        && indexes.expired_end.is_none()
        && indexes.too_new_start.is_none()
    {
        None
    } else {
        Some(RejectedLogEventsInfo {
            too_old_log_event_end_index: indexes.too_old_end,
            expired_log_event_end_index: indexes.expired_end,
            too_new_log_event_start_index: indexes.too_new_start,
        })
    }
}

pub fn get(
    store: &LogsStore,
    paginator: &EventPaginator,
    request: GetLogEventsRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<GetLogEventsResponse, LogsError> {
    let group_name = resolve_group_name(
        request.log_group_name.as_deref(),
        request.log_group_identifier.as_deref(),
        &scope,
    )?;
    validate_stream_name(&request.log_stream_name)?;
    let limit = event_limit(request.limit)?;
    validate_time_range(request.start_time, request.end_time)?;
    let start_from_head = request.start_from_head.unwrap_or(false);
    let _unmask = request.unmask.unwrap_or(false);
    let request_key = serde_json::json!({
        "operation": "GetLogEvents",
        "group": group_name,
        "stream": request.log_stream_name,
        "startTime": request.start_time,
        "endTime": request.end_time,
        "limit": limit,
        "unmask": _unmask,
    })
    .to_string();
    let page = if let Some(token) = request.next_token {
        paginator.next_page(EventNextPageRequest {
            token: &token,
            scope: &scope,
            request_key: &request_key,
            limit,
            max_bytes: EVENT_PAGE_MAX_BYTES,
            require_forward_head: true,
            start_from_head,
            now_ms,
        })?
    } else {
        let (revision, mut events) = store.visible_stream_events(
            &GroupKey {
                scope: scope.clone(),
                name: group_name,
            },
            &request.log_stream_name,
            now_ms,
        )?;
        retain_time_range(&mut events, request.start_time, request.end_time);
        sort_events(&mut events);
        paginator.first_page(
            events,
            scope,
            request_key,
            limit,
            EVENT_PAGE_MAX_BYTES,
            revision,
            start_from_head,
            now_ms,
        )?
    };
    Ok(get_response(page))
}

pub fn filter(
    store: &LogsStore,
    paginator: &EventPaginator,
    request: FilterLogEventsRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<FilterLogEventsResponse, LogsError> {
    let group_name = resolve_group_name(
        request.log_group_name.as_deref(),
        request.log_group_identifier.as_deref(),
        &scope,
    )?;
    if request.log_stream_names.is_some() && request.log_stream_name_prefix.is_some() {
        return Err(LogsError::InvalidParameter(
            "logStreamNames and logStreamNamePrefix cannot both be specified".into(),
        ));
    }
    let mut stream_names = request.log_stream_names;
    if let Some(names) = stream_names.as_mut() {
        if names.is_empty() || names.len() > 100 {
            return Err(LogsError::InvalidParameter(
                "logStreamNames must contain between 1 and 100 names".into(),
            ));
        }
        for name in names.iter() {
            validate_stream_name(name)?;
        }
        names.sort();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(LogsError::InvalidParameter(
                "logStreamNames must not contain duplicates".into(),
            ));
        }
    }
    if let Some(prefix) = request.log_stream_name_prefix.as_deref() {
        validate_stream_name(prefix)?;
    }
    let limit = event_limit(request.limit)?;
    validate_time_range(request.start_time, request.end_time)?;
    let start_from_head = request.start_from_head.unwrap_or(true);
    if !start_from_head
        && request
            .start_time
            .is_none_or(|start_time| start_time < 1_704_067_200_000)
    {
        return Err(LogsError::InvalidParameter(
            "startFromHead=false requires startTime on or after 2024-01-01".into(),
        ));
    }
    let matcher = FilterPattern::compile(request.filter_pattern.as_deref())?;
    let pattern = request.filter_pattern.unwrap_or_default();
    let _ignored_interleaved = request.interleaved;
    let _unmask = request.unmask.unwrap_or(false);
    let request_key = serde_json::json!({
        "operation": "FilterLogEvents",
        "group": group_name,
        "streams": stream_names,
        "streamPrefix": request.log_stream_name_prefix,
        "startTime": request.start_time,
        "endTime": request.end_time,
        "filterPattern": pattern,
        "limit": limit,
        "interleaved": true,
        "unmask": _unmask,
    })
    .to_string();
    let page = if let Some(token) = request.next_token {
        paginator.next_page(EventNextPageRequest {
            token: &token,
            scope: &scope,
            request_key: &request_key,
            limit,
            max_bytes: EVENT_PAGE_MAX_BYTES,
            require_forward_head: false,
            start_from_head,
            now_ms,
        })?
    } else {
        let (revision, mut events) = store.visible_events(
            &GroupKey {
                scope: scope.clone(),
                name: group_name,
            },
            stream_names.as_deref(),
            request.log_stream_name_prefix.as_deref(),
            now_ms,
        )?;
        retain_time_range(&mut events, request.start_time, request.end_time);
        events.retain(|event| matcher.matches(&event.event.message));
        sort_events(&mut events);
        paginator.first_page(
            events,
            scope,
            request_key,
            limit,
            EVENT_PAGE_MAX_BYTES,
            revision,
            start_from_head,
            now_ms,
        )?
    };
    Ok(filter_response(page))
}

fn event_limit(limit: Option<u32>) -> Result<usize, LogsError> {
    let limit = limit.unwrap_or(EVENT_PAGE_DEFAULT_LIMIT);
    if !(1..=EVENT_PAGE_MAX_LIMIT).contains(&limit) {
        return Err(LogsError::InvalidParameter(
            "limit must be between 1 and 10000".into(),
        ));
    }
    Ok(limit as usize)
}

fn validate_time_range(start: Option<i64>, end: Option<i64>) -> Result<(), LogsError> {
    if start.is_some_and(|value| value < 0) || end.is_some_and(|value| value < 0) {
        return Err(LogsError::InvalidParameter(
            "startTime and endTime must be nonnegative".into(),
        ));
    }
    if start.zip(end).is_some_and(|(start, end)| start > end) {
        Err(LogsError::InvalidParameter(
            "startTime must not be greater than endTime".into(),
        ))
    } else {
        Ok(())
    }
}

fn retain_time_range(events: &mut Vec<PagedEvent>, start: Option<i64>, end: Option<i64>) {
    events.retain(|event| {
        start.is_none_or(|start| event.event.timestamp_ms >= start)
            && end.is_none_or(|end| event.event.timestamp_ms < end)
    });
}

fn sort_events(events: &mut [PagedEvent]) {
    events.sort_by(|left, right| {
        left.event
            .timestamp_ms
            .cmp(&right.event.timestamp_ms)
            .then_with(|| {
                left.event
                    .ingestion_time_ms
                    .cmp(&right.event.ingestion_time_ms)
            })
            .then_with(|| left.event.put_ordinal.cmp(&right.event.put_ordinal))
            .then_with(|| left.event.event_ordinal.cmp(&right.event.event_ordinal))
            .then_with(|| left.log_stream_name.cmp(&right.log_stream_name))
    });
}

fn get_response(page: EventPage) -> GetLogEventsResponse {
    GetLogEventsResponse {
        events: page
            .events
            .into_iter()
            .map(|event| OutputLogEvent {
                timestamp: event.event.timestamp_ms,
                message: event.event.message,
                ingestion_time: event.event.ingestion_time_ms,
            })
            .collect(),
        next_forward_token: page.next_forward_token,
        next_backward_token: page.next_backward_token,
    }
}

fn filter_response(page: EventPage) -> FilterLogEventsResponse {
    let EventPage {
        mut events,
        next_forward_token,
        next_backward_token,
        backward,
        has_more,
    } = page;
    if backward {
        events.reverse();
    }
    let next_token = has_more.then_some(if backward {
        next_backward_token
    } else {
        next_forward_token
    });
    FilterLogEventsResponse {
        events: events
            .into_iter()
            .map(|event| FilteredLogEvent {
                log_stream_name: event.log_stream_name,
                timestamp: event.event.timestamp_ms,
                message: event.event.message,
                ingestion_time: event.event.ingestion_time_ms,
                event_id: event.event.id,
            })
            .collect(),
        next_token,
    }
}
