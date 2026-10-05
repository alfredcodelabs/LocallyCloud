use std::sync::{Arc, Weak};

use locallycloud_core::integration::correlation::CorrelationContext;
use locallycloud_core::integration::identity::CallerIdentity;
use locallycloud_core::integration::logs::{
    InternalLogSink, LogScope, ProducerContext, ProducerGroupSpec, ProducerLogEvent,
    ProducerStreamSpec, SinkError, StreamRef,
};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::SfnError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoggingLevel {
    All,
    Error,
    Fatal,
    Off,
}

#[derive(Clone, Debug)]
struct LoggingConfiguration {
    level: LoggingLevel,
    include_execution_data: bool,
    group_name: Option<String>,
}

pub fn is_enabled(value: Option<&Value>, region: &str, account: &str) -> bool {
    parse_configuration(value, region, account)
        .is_ok_and(|configuration| configuration.level != LoggingLevel::Off)
}

pub async fn preflight_configuration(
    value: Option<&Value>,
    registry: &Weak<ServiceRegistry>,
    region: &str,
    account: &str,
) -> Result<(), SfnError> {
    let configuration = parse_configuration(value, region, account)?;
    let Some(group_name) = configuration.group_name else {
        return Ok(());
    };
    let registry = registry
        .upgrade()
        .ok_or_else(|| invalid_configuration("CloudWatch Logs service registry is unavailable"))?;
    let sink = registry
        .log_sink(&ServiceName::new("logs"))
        .ok_or_else(|| invalid_configuration("CloudWatch Logs sink is unavailable"))?;
    sink.resolve_group(
        LogScope::new(account, region),
        ProducerGroupSpec { name: group_name },
        producer_context(CallerIdentity::ServicePrincipal {
            service: "states".into(),
        }),
    )
    .await
    .map_err(|error| {
        invalid_configuration(format!("CloudWatch Logs destination is invalid: {error}"))
    })?;
    Ok(())
}

pub async fn deliver_execution(
    registry: &Weak<ServiceRegistry>,
    region: &str,
    account: &str,
    execution: &Arc<crate::store::ExecutionCell>,
) -> Result<(), SfnError> {
    let (configuration, group_name, stream_name, identity, events) = {
        let execution = execution.read().await;
        let configuration =
            parse_configuration(execution.logging_configuration.as_ref(), region, account)?;
        let Some(group_name) = configuration.group_name.clone() else {
            return Ok(());
        };
        let events = execution
            .history
            .iter()
            .filter(|event| includes_event(configuration.level, &event.event_type))
            .map(|event| {
                let mut details = event.details.clone();
                if !configuration.include_execution_data {
                    redact_execution_data(&mut details);
                }
                let mut message = json!({
                    "id": event.id,
                    "type": event.event_type,
                    "timestamp": event.timestamp,
                    "execution_arn": execution.arn,
                    "state_machine_arn": execution.state_machine_arn,
                    "details": details,
                });
                if let Some(previous_event_id) = event.previous_event_id {
                    message["previous_event_id"] = json!(previous_event_id);
                }
                ProducerLogEvent {
                    timestamp_ms: OffsetDateTime::parse(&event.timestamp, &Rfc3339)
                        .map(|timestamp| timestamp.unix_timestamp_nanos() / 1_000_000)
                        .ok()
                        .and_then(|timestamp| i64::try_from(timestamp).ok())
                        .unwrap_or_else(|| {
                            i64::try_from(
                                OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000,
                            )
                            .unwrap_or(i64::MAX)
                        }),
                    message: message.to_string(),
                }
            })
            .collect::<Vec<_>>();
        (
            configuration,
            group_name,
            format!(
                "{}/{}",
                execution
                    .state_machine_arn
                    .rsplit(':')
                    .next()
                    .unwrap_or_default(),
                execution.name
            ),
            CallerIdentity::AssumedRole {
                role_arn: execution.role_arn.clone(),
                session_name: execution.name.clone(),
            },
            events,
        )
    };

    if configuration.level == LoggingLevel::Off || events.is_empty() {
        return Ok(());
    }
    let registry = registry
        .upgrade()
        .ok_or_else(|| delivery_error(SinkError::Unavailable))?;
    let sink = registry
        .log_sink(&ServiceName::new("logs"))
        .ok_or_else(|| delivery_error(SinkError::Unavailable))?;
    let scope = LogScope::new(account, region);
    let context = producer_context(identity);
    let group = sink
        .resolve_group(
            scope.clone(),
            ProducerGroupSpec { name: group_name },
            context.clone(),
        )
        .await
        .map_err(delivery_error)?;
    let stream = sink
        .ensure_stream(
            scope.clone(),
            group,
            ProducerStreamSpec { name: stream_name },
            context.clone(),
        )
        .await
        .map_err(delivery_error)?;
    context
        .correlation
        .log_hop("states", "logs", "producer-log", "Native");
    const MAX_BATCH_EVENTS: usize = 10_000;
    const MAX_BATCH_BYTES: usize = 1_048_576;
    const EVENT_OVERHEAD_BYTES: usize = 26;

    let mut batch = Vec::new();
    let mut batch_bytes = 0_usize;
    for event in events {
        let event_bytes = event
            .message
            .len()
            .checked_add(EVENT_OVERHEAD_BYTES)
            .ok_or_else(|| {
                delivery_error(SinkError::InvalidRequest(
                    "Step Functions log event size overflow".into(),
                ))
            })?;
        if event_bytes > MAX_BATCH_BYTES {
            return Err(delivery_error(SinkError::InvalidRequest(
                "Step Functions log event exceeds the CloudWatch Logs batch limit".into(),
            )));
        }
        if !batch.is_empty()
            && (batch.len() == MAX_BATCH_EVENTS || batch_bytes + event_bytes > MAX_BATCH_BYTES)
        {
            append_batch(sink.as_ref(), &scope, &stream, &context, &batch).await?;
            batch.clear();
            batch_bytes = 0;
        }
        batch_bytes += event_bytes;
        batch.push(event);
    }
    if !batch.is_empty() {
        append_batch(sink.as_ref(), &scope, &stream, &context, &batch).await?;
    }
    Ok(())
}

async fn append_batch(
    sink: &dyn InternalLogSink,
    scope: &LogScope,
    stream: &StreamRef,
    context: &ProducerContext,
    batch: &[ProducerLogEvent],
) -> Result<(), SfnError> {
    let outcome = sink
        .append(
            scope.clone(),
            stream.clone(),
            batch.to_vec(),
            context.clone(),
        )
        .await
        .map_err(delivery_error)?;
    if outcome.stored_events != batch.len() {
        return Err(delivery_error(SinkError::Rejected(format!(
            "stored {} of {} events",
            outcome.stored_events,
            batch.len()
        ))));
    }
    Ok(())
}

fn parse_configuration(
    value: Option<&Value>,
    region: &str,
    account: &str,
) -> Result<LoggingConfiguration, SfnError> {
    let Some(value) = value else {
        return Ok(LoggingConfiguration {
            level: LoggingLevel::Off,
            include_execution_data: false,
            group_name: None,
        });
    };
    let object = value
        .as_object()
        .ok_or_else(|| invalid_configuration("loggingConfiguration must be an object"))?;
    reject_unknown_fields(
        object,
        &["level", "includeExecutionData", "destinations"],
        "loggingConfiguration",
    )?;
    let level = match object.get("level").and_then(Value::as_str).unwrap_or("OFF") {
        "ALL" => LoggingLevel::All,
        "ERROR" => LoggingLevel::Error,
        "FATAL" => LoggingLevel::Fatal,
        "OFF" => LoggingLevel::Off,
        _ => {
            return Err(invalid_configuration(
                "loggingConfiguration.level must be ALL, ERROR, FATAL, or OFF",
            ))
        }
    };
    let include_execution_data = match object.get("includeExecutionData") {
        Some(value) => value.as_bool().ok_or_else(|| {
            invalid_configuration("loggingConfiguration.includeExecutionData must be boolean")
        })?,
        None => false,
    };
    let destinations: &[Value] = match object.get("destinations") {
        Some(value) => value.as_array().ok_or_else(|| {
            invalid_configuration("loggingConfiguration.destinations must be an array")
        })?,
        None => &[],
    };
    if destinations.len() > 1 {
        return Err(invalid_configuration(
            "loggingConfiguration supports exactly one CloudWatch Logs destination",
        ));
    }
    if level != LoggingLevel::Off && destinations.len() != 1 {
        return Err(invalid_configuration(
            "active logging requires exactly one CloudWatch Logs destination",
        ));
    }
    let group_name = destinations
        .first()
        .map(|destination| parse_destination(destination, region, account))
        .transpose()?;
    Ok(LoggingConfiguration {
        level,
        include_execution_data,
        group_name,
    })
}

fn parse_destination(value: &Value, region: &str, account: &str) -> Result<String, SfnError> {
    let destination = value
        .as_object()
        .ok_or_else(|| invalid_configuration("logging destination must be an object"))?;
    reject_unknown_fields(
        destination,
        &["cloudWatchLogsLogGroup"],
        "logging destination",
    )?;
    let group = destination
        .get("cloudWatchLogsLogGroup")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            invalid_configuration("logging destination requires cloudWatchLogsLogGroup")
        })?;
    reject_unknown_fields(group, &["logGroupArn"], "cloudWatchLogsLogGroup")?;
    let arn = group
        .get("logGroupArn")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_configuration("cloudWatchLogsLogGroup.logGroupArn is required"))?;
    parse_group_arn(arn, region, account)
}

fn parse_group_arn(arn: &str, region: &str, account: &str) -> Result<String, SfnError> {
    let mut parts = arn.splitn(6, ':');
    let valid_scope = parts.next() == Some("arn")
        && parts.next() == Some("aws")
        && parts.next() == Some("logs")
        && parts.next() == Some(region)
        && parts.next() == Some(account);
    let resource = parts.next().unwrap_or_default();
    let Some(name) = resource.strip_prefix("log-group:") else {
        return Err(invalid_configuration(
            "logGroupArn must reference a log group",
        ));
    };
    let name = name.strip_suffix(":*").unwrap_or(name);
    if !valid_scope || name.is_empty() || name.contains(":log-stream:") || name.ends_with(':') {
        return Err(invalid_configuration(format!(
            "logGroupArn must be an arn:aws:logs ARN in {region}/{account}"
        )));
    }
    Ok(name.to_string())
}

fn reject_unknown_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), SfnError> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid_configuration(format!(
            "{context} contains unsupported field {field}"
        )));
    }
    Ok(())
}

// [VERIFY-AWS] This explicit table is intentionally conservative until live AWS classification
// is captured. It avoids fragile substring matching and documents every emitted failure class.
fn includes_event(level: LoggingLevel, event_type: &str) -> bool {
    match level {
        LoggingLevel::All => true,
        LoggingLevel::Error => matches!(
            event_type,
            "TaskFailed"
                | "TaskTimedOut"
                | "ParallelStateFailed"
                | "ParallelStateBranchFailed"
                | "ParallelStateBranchAborted"
                | "MapStateFailed"
                | "MapIterationFailed"
                | "ExecutionFailed"
                | "ExecutionTimedOut"
                | "ExecutionAborted"
        ),
        LoggingLevel::Fatal => matches!(
            event_type,
            "ExecutionFailed" | "ExecutionTimedOut" | "ExecutionAborted"
        ),
        LoggingLevel::Off => false,
    }
}

fn redact_execution_data(value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        for field in ["input", "output", "parameters"] {
            object.remove(field);
        }
    }
}

fn producer_context(identity: CallerIdentity) -> ProducerContext {
    ProducerContext {
        source_service: "states".into(),
        identity,
        correlation: CorrelationContext::root(),
        loop_depth: 0,
    }
}

fn invalid_configuration(message: impl Into<String>) -> SfnError {
    SfnError::InvalidLoggingConfiguration(message.into())
}

fn delivery_error(error: SinkError) -> SfnError {
    SfnError::ConflictException(format!("Step Functions log delivery failed: {error}"))
}
