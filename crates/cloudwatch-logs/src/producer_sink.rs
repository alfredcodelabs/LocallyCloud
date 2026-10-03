use std::sync::Weak;

use async_trait::async_trait;
use axum::body::{to_bytes, Bytes};
use http::{HeaderMap, HeaderValue, Method, Uri};
use locallycloud_core::integration::identity::IdentityPropagator;
use locallycloud_core::integration::logs::{
    AppendOutcome, GroupRef, InternalLogSink, LogScope, ProducerContext, ProducerGroupSpec,
    ProducerLogEvent, ProducerStreamSpec, SinkError, StreamRef,
};
use locallycloud_core::registry::ServiceRegistry;
use serde_json::{json, Value};
use tokio::sync::Semaphore;

use crate::protocol;

const MAX_IN_FLIGHT: usize = 64;

pub(crate) struct LogsProducerSink {
    registry: Weak<ServiceRegistry>,
    permits: Semaphore,
}

impl LogsProducerSink {
    pub(crate) fn new(registry: Weak<ServiceRegistry>) -> Self {
        Self {
            registry,
            permits: Semaphore::new(MAX_IN_FLIGHT),
        }
    }

    async fn call(
        &self,
        scope: &LogScope,
        operation: &str,
        body: Value,
        context: &ProducerContext,
    ) -> Result<Value, DispatchFailure> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(DispatchFailure::Unavailable)?;
        let dispatcher = registry
            .internal_dispatcher()
            .ok_or(DispatchFailure::Unavailable)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static(protocol::CONTENT_TYPE),
        );
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("{}.{}", protocol::TARGET_PREFIX, operation))
                .map_err(|_| DispatchFailure::Internal)?,
        );
        IdentityPropagator::attach(&mut headers, &context.identity);
        context
            .correlation
            .log_hop(&context.source_service, "logs", "producer-log", "sync");
        let response = dispatcher
            .dispatch_scoped(
                &Method::POST,
                &Uri::from_static("/"),
                &headers,
                Bytes::from(body.to_string()),
                &context.correlation.flow_id,
                &scope.account_id,
                &scope.region,
            )
            .await;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), protocol::MAX_REQUEST_BODY_BYTES)
            .await
            .map_err(|_| DispatchFailure::Internal)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| DispatchFailure::Internal)?;
        if (200..300).contains(&status) {
            Ok(value)
        } else {
            let code = value
                .get("__type")
                .and_then(Value::as_str)
                .unwrap_or("InternalFailure")
                .rsplit('#')
                .next()
                .unwrap_or("InternalFailure")
                .to_string();
            Err(DispatchFailure::Rejected { status, code })
        }
    }

    async fn group_exists(
        &self,
        scope: &LogScope,
        name: &str,
        context: &ProducerContext,
    ) -> Result<bool, SinkError> {
        let value = self
            .call(
                scope,
                "DescribeLogGroups",
                json!({ "logGroupNamePrefix": name, "limit": 50 }),
                context,
            )
            .await
            .map_err(SinkError::from)?;
        Ok(value
            .get("logGroups")
            .and_then(Value::as_array)
            .is_some_and(|groups| {
                groups.iter().any(|group| {
                    group.get("logGroupName").and_then(Value::as_str) == Some(name)
                        && group.get("logGroupClass").and_then(Value::as_str) == Some("STANDARD")
                })
            }))
    }

    async fn stream_exists(
        &self,
        scope: &LogScope,
        group_name: &str,
        stream_name: &str,
        context: &ProducerContext,
    ) -> Result<bool, SinkError> {
        let value = self
            .call(
                scope,
                "DescribeLogStreams",
                json!({
                    "logGroupName": group_name,
                    "logStreamNamePrefix": stream_name,
                    "limit": 50
                }),
                context,
            )
            .await
            .map_err(SinkError::from)?;
        Ok(value
            .get("logStreams")
            .and_then(Value::as_array)
            .is_some_and(|streams| {
                streams.iter().any(|stream| {
                    stream.get("logStreamName").and_then(Value::as_str) == Some(stream_name)
                })
            }))
    }
}

#[async_trait]
impl InternalLogSink for LogsProducerSink {
    async fn resolve_group(
        &self,
        scope: LogScope,
        spec: ProducerGroupSpec,
        context: ProducerContext,
    ) -> Result<GroupRef, SinkError> {
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| SinkError::Backpressure)?;
        let context = context.next_hop()?;
        if self.group_exists(&scope, &spec.name, &context).await? {
            Ok(GroupRef { name: spec.name })
        } else {
            Err(SinkError::NotFound("log group".into()))
        }
    }

    async fn ensure_group(
        &self,
        scope: LogScope,
        spec: ProducerGroupSpec,
        context: ProducerContext,
    ) -> Result<GroupRef, SinkError> {
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| SinkError::Backpressure)?;
        let context = context.next_hop()?;
        match self
            .call(
                &scope,
                "CreateLogGroup",
                json!({ "logGroupName": spec.name }),
                &context,
            )
            .await
        {
            Ok(_) => Ok(GroupRef { name: spec.name }),
            Err(DispatchFailure::Rejected { ref code, .. })
                if code == "ResourceAlreadyExistsException" =>
            {
                if self.group_exists(&scope, &spec.name, &context).await? {
                    Ok(GroupRef { name: spec.name })
                } else {
                    Err(SinkError::Incompatible("log group".into()))
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn ensure_stream(
        &self,
        scope: LogScope,
        group: GroupRef,
        spec: ProducerStreamSpec,
        context: ProducerContext,
    ) -> Result<StreamRef, SinkError> {
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| SinkError::Backpressure)?;
        let context = context.next_hop()?;
        match self
            .call(
                &scope,
                "CreateLogStream",
                json!({
                    "logGroupName": group.name,
                    "logStreamName": spec.name
                }),
                &context,
            )
            .await
        {
            Ok(_) => Ok(StreamRef {
                group_name: group.name,
                stream_name: spec.name,
            }),
            Err(DispatchFailure::Rejected { ref code, .. })
                if code == "ResourceAlreadyExistsException" =>
            {
                if self
                    .stream_exists(&scope, &group.name, &spec.name, &context)
                    .await?
                {
                    Ok(StreamRef {
                        group_name: group.name,
                        stream_name: spec.name,
                    })
                } else {
                    Err(SinkError::Incompatible("log stream".into()))
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn append(
        &self,
        scope: LogScope,
        target: StreamRef,
        events: Vec<ProducerLogEvent>,
        context: ProducerContext,
    ) -> Result<AppendOutcome, SinkError> {
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| SinkError::Backpressure)?;
        let context = context.next_hop()?;
        let count = events.len();
        let value = self
            .call(
                &scope,
                "PutLogEvents",
                json!({
                    "logGroupName": target.group_name,
                    "logStreamName": target.stream_name,
                    "logEvents": events.into_iter().map(|event| json!({
                        "timestamp": event.timestamp_ms,
                        "message": event.message,
                    })).collect::<Vec<_>>()
                }),
                &context,
            )
            .await
            .map_err(SinkError::from)?;
        if value.get("rejectedLogEventsInfo").is_some() {
            return Err(SinkError::Rejected("event age policy".into()));
        }
        Ok(AppendOutcome {
            stored_events: count,
        })
    }
}

#[derive(Debug)]
enum DispatchFailure {
    Unavailable,
    Rejected { status: u16, code: String },
    Internal,
}

impl From<DispatchFailure> for SinkError {
    fn from(error: DispatchFailure) -> Self {
        match error {
            DispatchFailure::Unavailable => SinkError::Unavailable,
            DispatchFailure::Internal => SinkError::Internal("invalid internal response".into()),
            DispatchFailure::Rejected { status, code } => match code.as_str() {
                "InvalidParameterException" | "SerializationException" => {
                    SinkError::InvalidRequest(code)
                }
                "ResourceNotFoundException" => SinkError::NotFound(code),
                "ResourceAlreadyExistsException" => SinkError::Incompatible(code),
                _ if status == 429 => SinkError::Backpressure,
                _ if status >= 500 => SinkError::Internal(code),
                _ => SinkError::Rejected(code),
            },
        }
    }
}
