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
        if let Some(source) = &context.source_arn {
            headers.insert(
                "x-locallycloud-source-arn",
                HeaderValue::from_str(source).map_err(|_| DispatchFailure::Internal)?,
            );
            headers.insert(
                "x-locallycloud-source-account",
                HeaderValue::from_str(&scope.account_id).map_err(|_| DispatchFailure::Internal)?,
            );
        }
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
                // The authorized create response proves this exact group exists. Asking
                // to describe groups would require an extra read permission that standard
                // Lambda execution roles do not need to publish invocation logs.
                Ok(GroupRef { name: spec.name })
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
                // The authorized CreateLogStream response proves this exact stream exists.
                Ok(StreamRef {
                    group_name: group.name,
                    stream_name: spec.name,
                })
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

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_core::integration::authorization::AuthorizationRequest;
    use locallycloud_core::integration::{
        correlation::CorrelationContext, identity::CallerIdentity, InternalDispatcher,
        RequestIdentity,
    };
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
    use locallycloud_core::registry::ServiceName;
    use locallycloud_iam_sts::{
        enforcement::EnforcementMode, iam, query::QueryRequest, store::IamStore, sts::SessionStore,
    };
    use std::{sync::Arc, time::Duration};

    #[tokio::test]
    async fn lambda_basic_execution_role_can_publish_repeatedly_without_describe_permissions() {
        let registry = ServiceRegistry::with_known_services();
        crate::register(&registry).unwrap();
        let account = "000000000000";
        let region = "us-east-1";
        let group = "/aws/lambda/basic-role";
        let store = Arc::new(IamStore::new());
        iam::seed_aws_managed_policies(&store);
        let trust = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]});
        iam::create_role(
            &store,
            account,
            &QueryRequest::parse(
                format!("RoleName=basic&AssumeRolePolicyDocument={trust}").as_bytes(),
            ),
        )
        .unwrap();
        iam::attach_policy(&store,account,iam::Entity::Role,&QueryRequest::parse(b"RoleName=basic&PolicyArn=arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")).unwrap();
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            store.clone(),
            Arc::new(SessionStore::new()),
            EnforcementMode::Strict,
        );
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            region.into(),
            account.into(),
        )));
        let context = ProducerContext {
            source_arn: None,
            source_service: "lambda".into(),
            identity: CallerIdentity::AssumedRole {
                role_arn: "arn:aws:iam::000000000000:role/basic".into(),
                session_name: "invocation".into(),
            },
            correlation: CorrelationContext::root(),
            loop_depth: 0,
        };
        let scope = LogScope::new(account, region);
        let sink = registry.log_sink(&ServiceName::new("logs")).unwrap();
        let evaluator = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .unwrap();
        for action in ["logs:DescribeLogGroups", "logs:DescribeLogStreams"] {
            assert!(evaluator
                .authorize(AuthorizationRequest {
                    request_identity: RequestIdentity {
                        account_id: account.into(),
                        access_key_id: None,
                        arn: None
                    },
                    delegated_identity: Some(context.identity.clone()),
                    source_service: "lambda".into(),
                    action: action.into(),
                    resource: "*".into(),
                    context: Default::default()
                })
                .is_err());
        }
        for index in 0..2 {
            let group = sink
                .ensure_group(
                    scope.clone(),
                    ProducerGroupSpec { name: group.into() },
                    context.clone(),
                )
                .await
                .unwrap();
            let stream = sink
                .ensure_stream(
                    scope.clone(),
                    group,
                    ProducerStreamSpec {
                        name: "same-warm-environment".into(),
                    },
                    context.clone(),
                )
                .await
                .unwrap();
            let result = sink
                .append(
                    scope.clone(),
                    stream,
                    vec![ProducerLogEvent {
                        timestamp_ms: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as i64,
                        message: format!("handler-error-{index}"),
                    }],
                    context.clone(),
                )
                .await
                .unwrap();
            assert_eq!(result.stored_events, 1);
        }
        let deny = json!({"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"logs:CreateLogGroup","Resource":"*"}]});
        iam::put_inline_policy(
            &store,
            account,
            iam::Entity::Role,
            &QueryRequest::parse(
                format!("RoleName=basic&PolicyName=deny-create&PolicyDocument={deny}").as_bytes(),
            ),
        )
        .unwrap();
        assert!(matches!(
            sink.ensure_group(scope, ProducerGroupSpec { name: group.into() }, context)
                .await,
            Err(SinkError::Rejected(_))
        ));
    }
}
