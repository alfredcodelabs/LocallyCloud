//! Step Functions service handler: AWS JSON 1.0 dispatch by `X-Amz-Target`, registered
//! `Native`. Task integrations dispatch to other native services through the registry
//! (held as a `Weak` reference to avoid a cycle).

use std::sync::{Arc, Weak};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use serde_json::Value;

use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

use crate::authorization;
use crate::error::SfnError;
use crate::ops::{self, Ctx};
use crate::store::SfnStore;

const TARGET_PREFIX: &str = "AWSStepFunctions";

pub struct SfnHandler {
    store: Arc<SfnStore>,
    registry: Weak<ServiceRegistry>,
}

// Cancelling an operation after a live mutation must not expose an uncommitted configuration.
struct ConfigurationCommit<'a> {
    store: &'a SfnStore,
    completed: bool,
}
impl Drop for ConfigurationCommit<'_> {
    fn drop(&mut self) {
        if !self.completed && self.store.persistence.is_some() {
            self.store
                .persistence_failed
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

impl SfnHandler {
    fn new(registry: Weak<ServiceRegistry>) -> Self {
        SfnHandler {
            store: Arc::new(SfnStore::new()),
            registry,
        }
    }

    fn operation(req: &ServiceRequest) -> Option<String> {
        req.headers
            .get("x-amz-target")?
            .to_str()
            .ok()?
            .rsplit('.')
            .next()
            .map(str::to_string)
    }

    async fn dispatch(&self, op: &str, ctx: &Ctx<'_>, body: &Value) -> Result<Value, SfnError> {
        match op {
            "CreateStateMachine" => ops::create_state_machine(ctx, body).await,
            "DescribeStateMachine" => ops::describe_state_machine(ctx, body).await,
            "DescribeStateMachineForExecution" => {
                ops::describe_state_machine_for_execution(ctx, body).await
            }
            "UpdateStateMachine" => ops::update_state_machine(ctx, body).await,
            "DeleteStateMachine" => ops::delete_state_machine(ctx, body).await,
            "ListStateMachines" => ops::list_state_machines(ctx, body).await,
            "PublishStateMachineVersion" => ops::publish_state_machine_version(ctx, body).await,
            "ListStateMachineVersions" => ops::list_state_machine_versions(ctx, body).await,
            "CreateStateMachineAlias" => ops::create_state_machine_alias(ctx, body).await,
            "UpdateStateMachineAlias" => ops::update_state_machine_alias(ctx, body).await,
            "DeleteStateMachineAlias" => ops::delete_state_machine_alias(ctx, body).await,
            "DescribeStateMachineAlias" => ops::describe_state_machine_alias(ctx, body).await,
            "ListStateMachineAliases" => ops::list_state_machine_aliases(ctx, body).await,
            "ValidateStateMachineDefinition" => {
                ops::validate_state_machine_definition(ctx, body).await
            }
            "TestState" => ops::test_state(ctx, body).await,
            "StartExecution" => ops::start_execution(ctx, body).await,
            "StartSyncExecution" => ops::start_sync_execution(ctx, body).await,
            "DescribeExecution" => ops::describe_execution(ctx, body).await,
            "StopExecution" => ops::stop_execution(ctx, body).await,
            "ListExecutions" => ops::list_executions(ctx, body).await,
            "GetExecutionHistory" => ops::get_execution_history(ctx, body).await,
            "RedriveExecution" => ops::redrive_execution(ctx, body).await,
            "CreateActivity" => ops::create_activity(ctx, body).await,
            "DeleteActivity" => ops::delete_activity(ctx, body).await,
            "DescribeActivity" => ops::describe_activity(ctx, body).await,
            "ListActivities" => ops::list_activities(ctx, body).await,
            "GetActivityTask" => ops::get_activity_task(ctx, body).await,
            "SendTaskSuccess" => ops::send_task_success(ctx, body).await,
            "SendTaskFailure" => ops::send_task_failure(ctx, body).await,
            "SendTaskHeartbeat" => ops::send_task_heartbeat(ctx, body).await,
            "TagResource" => ops::tag_resource(ctx, body).await,
            "UntagResource" => ops::untag_resource(ctx, body).await,
            "ListTagsForResource" => ops::list_tags_for_resource(ctx, body).await,
            other => Err(SfnError::UnknownOperation(format!(
                "unsupported operation {other}"
            ))),
        }
    }
}

#[async_trait]
impl NativeHandler for SfnHandler {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        let _configuration = self.store.configuration_gate.read().await;
        if !self.store.healthy() {
            return Err("Step Functions durable state is unavailable");
        }
        self.store.resource_regions(account)
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let op = match Self::operation(&request) {
            Some(o) => o,
            None => {
                return SfnError::UnknownOperation("missing X-Amz-Target".into())
                    .into_response(&request.request_id)
            }
        };
        let body: Value = if request.body.is_empty() {
            Value::Object(serde_json::Map::new())
        } else {
            match serde_json::from_slice(&request.body) {
                Ok(v) => v,
                Err(e) => {
                    return SfnError::Validation(format!("invalid JSON body: {e}"))
                        .into_response(&request.request_id)
                }
            }
        };
        let ctx = Ctx {
            store: &self.store,
            registry: self.registry.clone(),
            region: &request.region,
            account: &request.account_id,
            request_id: &request.request_id,
        };
        let Some(registry) = self.registry.upgrade() else {
            return SfnError::AccessDenied.into_response(&request.request_id);
        };
        if let Err(error) = authorization::authorize(&registry, &request, &op, &body) {
            return error.into_response(&request.request_id);
        }
        if let Err(error) =
            authorization::authorize_role_assignment(&registry, &request, &op, &body)
        {
            return error.into_response(&request.request_id);
        }
        let configuration_write = matches!(
            op.as_str(),
            "CreateStateMachine"
                | "UpdateStateMachine"
                | "DeleteStateMachine"
                | "PublishStateMachineVersion"
                | "CreateStateMachineAlias"
                | "UpdateStateMachineAlias"
                | "DeleteStateMachineAlias"
                | "CreateActivity"
                | "DeleteActivity"
                | "TagResource"
                | "UntagResource"
        );
        let configuration_read = op.starts_with("DescribeStateMachine")
            || op.starts_with("ListStateMachine")
            || matches!(
                op.as_str(),
                "DescribeActivity" | "ListActivities" | "ListTagsForResource"
            );
        let _write = if configuration_write {
            Some(self.store.configuration_gate.write().await)
        } else {
            None
        };
        let _read = if configuration_read {
            Some(self.store.configuration_gate.read().await)
        } else {
            None
        };
        if !self.store.healthy() {
            return SfnError::Internal("Step Functions durable state is unavailable".into())
                .into_response(&request.request_id);
        }
        let mut commit_guard = configuration_write.then(|| ConfigurationCommit {
            store: &self.store,
            completed: false,
        });
        let mut result = self.dispatch(&op, &ctx, &body).await;
        if configuration_write
            && result.is_ok()
            && self
                .store
                .persist_scope(&request.account_id, &request.region)
                .await
                .is_err()
        {
            result = Err(SfnError::Internal(
                "Step Functions configuration could not be committed".into(),
            ));
        }
        if let Some(guard) = commit_guard.as_mut() {
            guard.completed = true;
        }
        // Execution guard commits can fail inside a worker/operation; never acknowledge them.
        if !self.store.healthy() {
            result = Err(SfnError::Internal(
                "Step Functions durable state is unavailable".into(),
            ));
        }
        match result {
            Ok(value) => json_response(value),
            Err(err) => err.into_response(&request.request_id),
        }
    }
}

fn json_response(value: Value) -> Response {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/x-amz-json-1.0")
        .body(Body::from(value.to_string()))
        .expect("json 1.0 response is valid")
}

/// Register Step Functions (`states`) as a `Native` JSON 1.0 service.
fn ensure_dispatcher(registry: &Arc<ServiceRegistry>) {
    if registry.internal_dispatcher().is_none() {
        let dispatcher = Arc::new(InternalDispatcher::new_shared(
            registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: std::time::Duration::from_secs(2),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        ));
        registry.set_internal_dispatcher(dispatcher);
    }
}

pub fn register(registry: &Arc<ServiceRegistry>) {
    ensure_dispatcher(registry);
    register_handler(registry, SfnHandler::new(Arc::downgrade(registry)));
}

pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    state: Arc<locallycloud_state::StateDb>,
) -> Result<(), String> {
    let store = SfnStore::with_state(
        state,
        locallycloud_state::StateCipher::from_env().map_err(|e| e.to_string())?,
    )?;
    ensure_dispatcher(registry);
    register_handler(
        registry,
        SfnHandler {
            store: Arc::new(store),
            registry: Arc::downgrade(registry),
        },
    );
    Ok(())
}

fn register_handler(registry: &Arc<ServiceRegistry>, handler: SfnHandler) {
    let handler: Arc<dyn NativeHandler> = Arc::new(handler);
    registry.register_native(
        ServiceName::new("states"),
        ServiceMetadata::new(AwsProtocol::Json10, Some(TARGET_PREFIX)),
        handler,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method};
    use locallycloud_core::integration::logs::{
        AppendOutcome, GroupRef, InternalLogSink, LogScope, ProducerContext, ProducerGroupSpec,
        ProducerLogEvent, ProducerStreamSpec, SinkError, StreamRef,
    };
    use serde_json::json;
    use std::time::Duration;

    fn durable_handler(
        registry: &Arc<ServiceRegistry>,
        state: Arc<locallycloud_state::StateDb>,
    ) -> Arc<SfnHandler> {
        Arc::new(SfnHandler {
            store: Arc::new(
                SfnStore::with_state(state, locallycloud_state::StateCipher::with_key(&[7; 32]))
                    .unwrap(),
            ),
            registry: Arc::downgrade(registry),
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn durable_standard_history_and_configuration_restore_without_replaying_effects() {
        let root =
            std::env::temp_dir().join(format!("locallycloud-sfn-durable-{}", uuid::Uuid::new_v4()));
        let state =
            Arc::new(locallycloud_state::StateDb::open(root.join("state.sqlite3")).unwrap());
        let registry = registry();
        let concrete = durable_handler(&registry, state.clone());
        let handler: Arc<dyn NativeHandler> = concrete.clone();
        let definition = json!({"StartAt":"Done","States":{"Done":{"Type":"Pass","Result":{"durable":true},"End":true}}});
        let arn = create_sm(&handler, "durable-completed", definition.clone()).await;
        let version = sfn(
            &handler,
            "PublishStateMachineVersion",
            json!({"stateMachineArn":arn}),
        )
        .await;
        let alias=sfn(&handler,"CreateStateMachineAlias",json!({"name":"prod","routingConfiguration":[{"stateMachineVersionArn":version["stateMachineVersionArn"],"weight":100}]})).await;
        let activity = sfn(
            &handler,
            "CreateActivity",
            json!({"name":"durable-activity","tags":[{"key":"owner","value":"durable"}]}),
        )
        .await;
        let started = sfn(
            &handler,
            "StartExecution",
            json!({"stateMachineArn":arn,"name":"completed"}),
        )
        .await;
        let completed = await_execution(&handler, started["executionArn"].as_str().unwrap()).await;
        assert_eq!(completed["status"], "SUCCEEDED");
        let sqs = registry.native_handler(&ServiceName::new("sqs")).unwrap();
        let (_, queue) = body_of(
            sqs.handle(req(
                "AmazonSQS",
                "CreateQueue",
                json!({"QueueName":"durable-sfn-effects"}),
            ))
            .await,
        )
        .await;
        let waiting_definition = json!({"StartAt":"Send","States":{
            "Send":{"Type":"Task","Resource":"arn:aws:states:::sqs:sendMessage","Parameters":{"QueueUrl":queue["QueueUrl"],"MessageBody":"one effect"},"Next":"Wait"},
            "Wait":{"Type":"Wait","Seconds":3600,"Next":"Done"},"Done":{"Type":"Pass","End":true}
        }});
        let waiting_arn = create_sm(&handler, "durable-interrupted", waiting_definition).await;
        let waiting = sfn(
            &handler,
            "StartExecution",
            json!({"stateMachineArn":waiting_arn,"name":"interrupted"}),
        )
        .await;
        let execution_arn = waiting["executionArn"].as_str().unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let history = sfn(
                    &handler,
                    "GetExecutionHistory",
                    json!({"executionArn":execution_arn}),
                )
                .await;
                if history["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|event| event["type"] == "WaitStateEntered")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let restored: Arc<dyn NativeHandler> = durable_handler(&registry, state.clone());
        assert_eq!(
            sfn(
                &restored,
                "DescribeStateMachine",
                json!({"stateMachineArn":arn})
            )
            .await["definition"],
            definition.to_string()
        );
        assert_eq!(
            sfn(
                &restored,
                "DescribeStateMachineAlias",
                json!({"stateMachineAliasArn":alias["stateMachineAliasArn"]})
            )
            .await["name"],
            "prod"
        );
        assert_eq!(
            sfn(
                &restored,
                "DescribeActivity",
                json!({"activityArn":activity["activityArn"]})
            )
            .await["name"],
            "durable-activity"
        );
        assert_eq!(
            sfn(
                &restored,
                "DescribeExecution",
                json!({"executionArn":started["executionArn"]})
            )
            .await["status"],
            "SUCCEEDED"
        );
        let interrupted = sfn(
            &restored,
            "DescribeExecution",
            json!({"executionArn":execution_arn}),
        )
        .await;
        assert_eq!(interrupted["status"], "ABORTED");
        assert_eq!(interrupted["error"], "LocallyCloud.ExecutionInterrupted");
        let history = sfn(
            &restored,
            "GetExecutionHistory",
            json!({"executionArn":execution_arn}),
        )
        .await;
        assert_eq!(
            history["events"].as_array().unwrap().last().unwrap()["type"],
            "ExecutionAborted"
        );
        assert_eq!(
            body_of(
                restored
                    .handle(req(
                        "AWSStepFunctions",
                        "RedriveExecution",
                        json!({"executionArn":execution_arn})
                    ))
                    .await
            )
            .await
            .0,
            400
        );
        let (_,attributes)=body_of(sqs.handle(req("AmazonSQS","GetQueueAttributes",json!({"QueueUrl":queue["QueueUrl"],"AttributeNames":["ApproximateNumberOfMessages"]}))).await).await;
        assert_eq!(attributes["Attributes"]["ApproximateNumberOfMessages"], "1");
        let mut other = req(
            "AWSStepFunctions",
            "DescribeExecution",
            json!({"executionArn":execution_arn}),
        );
        other.region = "eu-west-1".into();
        assert_eq!(restored.handle(other).await.status(), 400);
        let raw: Vec<u8> = state
            .connection()
            .unwrap()
            .query_row("SELECT payload FROM sfn_scopes", [], |row| row.get(0))
            .unwrap();
        assert!(!raw
            .windows(b"durable-completed".len())
            .any(|window| window == b"durable-completed"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn durable_commit_failure_rolls_back_execution_and_never_acknowledges_configuration() {
        let root =
            std::env::temp_dir().join(format!("locallycloud-sfn-failure-{}", uuid::Uuid::new_v4()));
        let state =
            Arc::new(locallycloud_state::StateDb::open(root.join("state.sqlite3")).unwrap());
        let registry = registry();
        let concrete = durable_handler(&registry, state.clone());
        let handler: Arc<dyn NativeHandler> = concrete.clone();
        let definition =
            json!({"StartAt":"Wait","States":{"Wait":{"Type":"Wait","Seconds":3600,"End":true}}});
        let arn = create_sm(&handler, "durable-failure", definition.clone()).await;
        let started = sfn(
            &handler,
            "StartExecution",
            json!({"stateMachineArn":arn,"name":"blocked"}),
        )
        .await;
        let execution_arn = started["executionArn"].as_str().unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let execution = concrete.store.get_execution(execution_arn).unwrap();
                if execution
                    .read()
                    .await
                    .history
                    .iter()
                    .any(|event| event.event_type == "WaitStateEntered")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let mut connection = state.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let writer_handler = handler.clone();
        let stop_request = req(
            "AWSStepFunctions",
            "StopExecution",
            json!({"executionArn":execution_arn}),
        );
        let writer = tokio::spawn(async move { writer_handler.handle(stop_request).await });
        let cell = concrete.store.get_execution(execution_arn).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while cell.try_read().is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let reader_handler = handler.clone();
        let read_request = req(
            "AWSStepFunctions",
            "DescribeExecution",
            json!({"executionArn":execution_arn}),
        );
        let mut reader = tokio::spawn(async move { reader_handler.handle(read_request).await });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut reader)
                .await
                .is_err()
        );
        transaction.commit().unwrap();
        assert_eq!(writer.await.unwrap().status(), 200);
        assert_eq!(body_of(reader.await.unwrap()).await.1["status"], "ABORTED");
        let again = sfn(
            &handler,
            "StartExecution",
            json!({"stateMachineArn":arn,"name":"failed-stop"}),
        )
        .await;
        let failed_arn = again["executionArn"].as_str().unwrap();
        // Wait until the worker has completed its entry checkpoint before installing the fault.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let cell = concrete.store.get_execution(failed_arn).unwrap();
                if cell
                    .read()
                    .await
                    .history
                    .iter()
                    .any(|event| event.event_type == "WaitStateEntered")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        state.connection().unwrap().execute_batch("CREATE TRIGGER reject_sfn_execution BEFORE UPDATE ON sfn_executions BEGIN SELECT RAISE(ABORT,'forced execution failure'); END;").unwrap();
        assert_eq!(
            body_of(
                handler
                    .handle(req(
                        "AWSStepFunctions",
                        "StopExecution",
                        json!({"executionArn":failed_arn})
                    ))
                    .await
            )
            .await
            .0,
            500
        );
        assert_eq!(
            concrete
                .store
                .get_execution(failed_arn)
                .unwrap()
                .read()
                .await
                .status,
            crate::store::Status::Running
        );
        assert!(!concrete.store.healthy());
        assert!(SfnStore::with_state(
            state.clone(),
            locallycloud_state::StateCipher::with_key(&[7; 32])
        )
        .is_err());
        state
            .connection()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_sfn_execution;")
            .unwrap();
        let restored: Arc<dyn NativeHandler> = durable_handler(&registry, state.clone());
        state.connection().unwrap().execute_batch("CREATE TRIGGER reject_sfn_scope BEFORE UPDATE ON sfn_scopes BEGIN SELECT RAISE(ABORT,'forced configuration failure'); END;").unwrap();
        assert_eq!(body_of(restored.handle(req("AWSStepFunctions","UpdateStateMachine",json!({"stateMachineArn":arn,"definition":"{\"StartAt\":\"Done\",\"States\":{\"Done\":{\"Type\":\"Pass\",\"End\":true}}}"}))).await).await.0,500);
        let reopened: Arc<dyn NativeHandler> = durable_handler(&registry, state.clone());
        assert_eq!(
            sfn(
                &reopened,
                "DescribeStateMachine",
                json!({"stateMachineArn":arn})
            )
            .await["definition"],
            definition.to_string()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    fn registry() -> Arc<ServiceRegistry> {
        let reg = ServiceRegistry::with_known_services();
        locallycloud_sqs::register(&reg);
        crate::register(&reg);
        reg
    }

    fn handler(reg: &Arc<ServiceRegistry>, service: &str) -> Arc<dyn NativeHandler> {
        reg.native_handler(&ServiceName::new(service)).unwrap()
    }

    fn req(prefix: &str, op: &str, body: Value) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("{prefix}.{op}")).unwrap(),
        );
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(body.to_string()),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        }
    }

    async fn body_of(resp: Response) -> (u16, Value) {
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn sfn(h: &Arc<dyn NativeHandler>, op: &str, body: Value) -> Value {
        let (status, v) = body_of(h.handle(req("AWSStepFunctions", op, body)).await).await;
        assert_eq!(status, 200, "op {op} failed: {v}");
        v
    }

    /// Poll DescribeExecution until terminal (or timeout).
    async fn await_execution(h: &Arc<dyn NativeHandler>, exec_arn: &str) -> Value {
        for _ in 0..200 {
            let d = sfn(h, "DescribeExecution", json!({ "executionArn": exec_arn })).await;
            if d["status"] != "RUNNING" {
                return d;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("execution did not terminate");
    }

    async fn create_sm(h: &Arc<dyn NativeHandler>, name: &str, definition: Value) -> String {
        let v = sfn(
            h,
            "CreateStateMachine",
            json!({
                "name": name,
                "definition": definition.to_string(),
                "roleArn": "arn:aws:iam::000000000000:role/sfn"
            }),
        )
        .await;
        v["stateMachineArn"].as_str().unwrap().to_string()
    }

    async fn activity_task(h: &Arc<dyn NativeHandler>, activity_arn: &str) -> Value {
        for _ in 0..5 {
            let task = sfn(h, "GetActivityTask", json!({ "activityArn": activity_arn })).await;
            if task["taskToken"]
                .as_str()
                .is_some_and(|token| !token.is_empty())
            {
                return task;
            }
        }
        panic!("activity task was not scheduled");
    }

    #[tokio::test]
    async fn pass_state_machine_succeeds() {
        let reg = registry();
        let h = handler(&reg, "states");
        let def = json!({ "StartAt": "A", "States": { "A": { "Type": "Pass", "Result": { "ok": true }, "End": true } } });
        let arn = create_sm(&h, "pass", def).await;
        let start = sfn(&h, "StartExecution", json!({ "stateMachineArn": arn })).await;
        let exec = await_execution(&h, start["executionArn"].as_str().unwrap()).await;
        assert_eq!(exec["status"], "SUCCEEDED");
        let output: Value = serde_json::from_str(exec["output"].as_str().unwrap()).unwrap();
        assert_eq!(output, json!({ "ok": true }));
    }

    #[tokio::test]
    async fn choice_routes_and_fail_state() {
        let reg = registry();
        let h = handler(&reg, "states");
        let def = json!({
            "StartAt": "Check",
            "States": {
                "Check": { "Type": "Choice",
                    "Choices": [{ "Variable": "$.n", "NumericGreaterThan": 5, "Next": "Big" }],
                    "Default": "Small" },
                "Big": { "Type": "Pass", "Result": "big", "End": true },
                "Small": { "Type": "Fail", "Error": "TooSmall", "Cause": "n <= 5" }
            }
        });
        let arn = create_sm(&h, "choice", def).await;
        let big = sfn(
            &h,
            "StartExecution",
            json!({ "stateMachineArn": arn, "input": "{\"n\":10}" }),
        )
        .await;
        let e = await_execution(&h, big["executionArn"].as_str().unwrap()).await;
        assert_eq!(e["status"], "SUCCEEDED");

        let small = sfn(
            &h,
            "StartExecution",
            json!({ "stateMachineArn": arn, "input": "{\"n\":1}" }),
        )
        .await;
        let e = await_execution(&h, small["executionArn"].as_str().unwrap()).await;
        assert_eq!(e["status"], "FAILED");
        assert_eq!(e["error"], "TooSmall");
    }

    #[tokio::test]
    async fn task_orchestration_to_sqs() {
        let reg = registry();
        let sfn_h = handler(&reg, "states");
        let sqs = handler(&reg, "sqs");
        sqs.handle(req(
            "AmazonSQS",
            "CreateQueue",
            json!({ "QueueName": "sfn-q" }),
        ))
        .await;

        let def = json!({
            "StartAt": "Send",
            "States": {
                "Send": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sqs:sendMessage",
                    "Parameters": {
                        "QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/sfn-q",
                        "MessageBody.$": "$.text"
                    },
                    "End": true
                }
            }
        });
        let arn = create_sm(&sfn_h, "orch", def).await;
        let start = sfn(
            &sfn_h,
            "StartExecution",
            json!({ "stateMachineArn": arn, "input": "{\"text\":\"from-sfn\"}" }),
        )
        .await;
        let exec = await_execution(&sfn_h, start["executionArn"].as_str().unwrap()).await;
        assert_eq!(exec["status"], "SUCCEEDED", "exec: {exec}");

        // The message reached the real SQS queue.
        let recv = sqs
            .handle(req(
                "AmazonSQS",
                "ReceiveMessage",
                json!({ "QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/sfn-q" }),
            ))
            .await;
        let (_, rv) = body_of(recv).await;
        assert_eq!(rv["Messages"][0]["Body"], "from-sfn");
    }

    struct FailingLambda;

    #[async_trait]
    impl NativeHandler for FailingLambda {
        async fn handle(&self, _request: ServiceRequest) -> Response {
            Response::builder()
                .status(200)
                .header("x-amz-function-error", "Handled")
                .body(Body::from(
                    json!({
                        "errorType": "LedgerPhaseContentConflictError",
                        "errorMessage": "slot conflict",
                        "trace": ["index.js:12"]
                    })
                    .to_string(),
                ))
                .unwrap()
        }
    }

    #[tokio::test]
    async fn lambda_error_type_routes_named_catch_and_preserves_cause() {
        let reg = registry();
        reg.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            Arc::new(FailingLambda),
        );
        let h = handler(&reg, "states");
        let def = json!({
            "StartAt": "Invoke",
            "States": {
                "Invoke": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {
                        "FunctionName": "ledger",
                        "Payload": {}
                    },
                    "Catch": [
                        {
                            "ErrorEquals": ["LedgerPhaseContentConflictError"],
                            "ResultPath": "$.failure",
                            "Next": "Named"
                        },
                        {
                            "ErrorEquals": ["States.ALL"],
                            "Next": "Fallback"
                        }
                    ],
                    "End": true
                },
                "Named": { "Type": "Pass", "End": true },
                "Fallback": { "Type": "Pass", "Result": "wrong catch", "End": true }
            }
        });
        let arn = create_sm(&h, "lambda-named-catch", def).await;
        let start = sfn(&h, "StartExecution", json!({ "stateMachineArn": arn })).await;
        let execution = await_execution(&h, start["executionArn"].as_str().unwrap()).await;
        assert_eq!(execution["status"], "SUCCEEDED");
        let output: Value = serde_json::from_str(execution["output"].as_str().unwrap()).unwrap();
        assert_eq!(
            output["failure"]["Error"],
            "LedgerPhaseContentConflictError"
        );
        let cause: Value =
            serde_json::from_str(output["failure"]["Cause"].as_str().unwrap()).unwrap();
        assert_eq!(cause["errorMessage"], "slot conflict");
        assert_eq!(cause["trace"], json!(["index.js:12"]));
    }

    #[tokio::test]
    async fn aws_sdk_dynamodb_condition_error_uses_sdk_name() {
        let reg = registry();
        locallycloud_dynamodb::register(&reg);
        let dynamodb = handler(&reg, "dynamodb");
        let states = handler(&reg, "states");

        let (status, _) = body_of(
            dynamodb
                .handle(req(
                    "DynamoDB_20120810",
                    "CreateTable",
                    json!({
                        "TableName": "sfn-conditional",
                        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                        "BillingMode": "PAY_PER_REQUEST"
                    }),
                ))
                .await,
        )
        .await;
        assert_eq!(status, 200);
        let (status, _) = body_of(
            dynamodb
                .handle(req(
                    "DynamoDB_20120810",
                    "PutItem",
                    json!({"TableName":"sfn-conditional","Item":{"pk":{"S":"duplicate"}}}),
                ))
                .await,
        )
        .await;
        assert_eq!(status, 200);

        for (resource, expected) in [
            (
                "arn:aws:states:::aws-sdk:dynamodb:putItem",
                "DynamoDb.ConditionalCheckFailedException",
            ),
            (
                "arn:aws:states:::dynamodb:putItem",
                "DynamoDB.ConditionalCheckFailedException",
            ),
        ] {
            let definition = json!({
                "StartAt": "Put",
                "States": {
                    "Put": {
                        "Type": "Task",
                        "Resource": resource,
                        "Parameters": {
                            "TableName": "sfn-conditional",
                            "Item": {"pk":{"S":"duplicate"}},
                            "ConditionExpression": "attribute_not_exists(pk)"
                        },
                        "Catch": [
                            {"ErrorEquals":[expected],"ResultPath":"$.failure","Next":"Named"},
                            {"ErrorEquals":["States.ALL"],"Next":"Fallback"}
                        ],
                        "End": true
                    },
                    "Named": {"Type":"Pass","End":true},
                    "Fallback": {"Type":"Pass","Result":"wrong catch","End":true}
                }
            });
            let name = if resource.contains("aws-sdk") {
                "sdk-conditional"
            } else {
                "optimized-conditional"
            };
            let arn = create_sm(&states, name, definition).await;
            let started = sfn(&states, "StartExecution", json!({"stateMachineArn":arn})).await;
            let execution =
                await_execution(&states, started["executionArn"].as_str().unwrap()).await;
            assert_eq!(execution["status"], "SUCCEEDED", "{execution}");
            let output: Value =
                serde_json::from_str(execution["output"].as_str().unwrap()).unwrap();
            assert_eq!(output["failure"]["Error"], expected, "{output}");
        }
    }

    #[tokio::test]
    async fn catch_routes_task_failure() {
        let reg = registry();
        let h = handler(&reg, "states");
        // Task to a missing queue → SQS QueueDoesNotExist → States.TaskFailed → Catch.
        let def = json!({
            "StartAt": "Send",
            "States": {
                "Send": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sqs:sendMessage",
                    "Parameters": { "QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/ghost", "MessageBody": "x" },
                    "Catch": [{ "ErrorEquals": ["States.ALL"], "Next": "Handled" }],
                    "End": true
                },
                "Handled": { "Type": "Pass", "Result": "recovered", "End": true }
            }
        });
        let arn = create_sm(&h, "catch", def).await;
        let start = sfn(&h, "StartExecution", json!({ "stateMachineArn": arn })).await;
        let exec = await_execution(&h, start["executionArn"].as_str().unwrap()).await;
        assert_eq!(exec["status"], "SUCCEEDED");
        let output: Value = serde_json::from_str(exec["output"].as_str().unwrap()).unwrap();
        assert_eq!(output, json!("recovered"));
    }

    #[tokio::test]
    async fn parallel_and_map() {
        let reg = registry();
        let h = handler(&reg, "states");
        let def = json!({
            "StartAt": "P",
            "States": {
                "P": {
                    "Type": "Parallel",
                    "Branches": [
                        { "StartAt": "B1", "States": { "B1": { "Type": "Pass", "Result": 1, "End": true } } },
                        { "StartAt": "B2", "States": { "B2": { "Type": "Pass", "Result": 2, "End": true } } }
                    ],
                    "End": true
                }
            }
        });
        let arn = create_sm(&h, "par", def).await;
        let start = sfn(&h, "StartExecution", json!({ "stateMachineArn": arn })).await;
        let exec = await_execution(&h, start["executionArn"].as_str().unwrap()).await;
        let output: Value = serde_json::from_str(exec["output"].as_str().unwrap()).unwrap();
        assert_eq!(output, json!([1, 2]));

        let mdef = json!({
            "StartAt": "M",
            "States": {
                "M": {
                    "Type": "Map",
                    "ItemsPath": "$.items",
                    "ItemProcessor": { "StartAt": "I", "States": { "I": { "Type": "Pass", "Result": "x", "End": true } } },
                    "End": true
                }
            }
        });
        let marn = create_sm(&h, "map", mdef).await;
        let start = sfn(
            &h,
            "StartExecution",
            json!({ "stateMachineArn": marn, "input": "{\"items\":[1,2,3]}" }),
        )
        .await;
        let exec = await_execution(&h, start["executionArn"].as_str().unwrap()).await;
        let output: Value = serde_json::from_str(exec["output"].as_str().unwrap()).unwrap();
        assert_eq!(output, json!(["x", "x", "x"]));
    }

    #[tokio::test]
    async fn invalid_definition_rejected() {
        let reg = registry();
        let h = handler(&reg, "states");
        let (status, body) = body_of(
            h.handle(req(
                "AWSStepFunctions",
                "CreateStateMachine",
                json!({
                    "name": "bad",
                    "definition": "{\"States\":{}}",
                    "roleArn": "arn:aws:iam::000000000000:role/sfn"
                }),
            ))
            .await,
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(body["__type"], "InvalidDefinition");
    }

    #[tokio::test]
    async fn jsonata_output_expression() {
        let reg = registry();
        let h = handler(&reg, "states");
        let def = json!({
            "QueryLanguage": "JSONata",
            "StartAt": "Hello",
            "States": { "Hello": { "Type": "Pass", "Output": { "greeting": "{% 'hi ' & $states.input.name %}" }, "End": true } }
        });
        let arn = create_sm(&h, "jsonata", def).await;
        let start = sfn(
            &h,
            "StartExecution",
            json!({ "stateMachineArn": arn, "input": "{\"name\":\"ada\"}" }),
        )
        .await;
        let exec = await_execution(&h, start["executionArn"].as_str().unwrap()).await;
        assert_eq!(exec["status"], "SUCCEEDED");
        let output: Value = serde_json::from_str(exec["output"].as_str().unwrap()).unwrap();
        assert_eq!(output, json!({ "greeting": "hi ada" }));
    }

    #[tokio::test]
    async fn jsonata_choice_condition() {
        let reg = registry();
        let h = handler(&reg, "states");
        let def = json!({
            "QueryLanguage": "JSONata",
            "StartAt": "C",
            "States": {
                "C": { "Type": "Choice",
                    "Choices": [{ "Condition": "{% $states.input.n > 5 %}", "Next": "Big" }],
                    "Default": "Small" },
                "Big": { "Type": "Pass", "Output": { "size": "big" }, "End": true },
                "Small": { "Type": "Pass", "Output": { "size": "small" }, "End": true }
            }
        });
        let arn = create_sm(&h, "jchoice", def).await;
        let s = sfn(
            &h,
            "StartExecution",
            json!({ "stateMachineArn": arn, "input": "{\"n\":10}" }),
        )
        .await;
        let e = await_execution(&h, s["executionArn"].as_str().unwrap()).await;
        let out: Value = serde_json::from_str(e["output"].as_str().unwrap()).unwrap();
        assert_eq!(out, json!({ "size": "big" }));
    }

    #[tokio::test]
    async fn jsonata_rejects_mixed_jsonpath_fields() {
        let reg = registry();
        let h = handler(&reg, "states");
        // JSONata machine using a JSONPath field (Parameters) → InvalidDefinition (as AWS).
        let resp = h
            .handle(req(
                "AWSStepFunctions",
                "CreateStateMachine",
                json!({
                    "name": "mixed",
                    "definition": json!({
                        "QueryLanguage": "JSONata",
                        "StartAt": "A",
                        "States": { "A": { "Type": "Pass", "Parameters": { "x": 1 }, "End": true } }
                    }).to_string(),
                    "roleArn": "arn:aws:iam::000000000000:role/r"
                }),
            ))
            .await;
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn jsonata_task_arguments_to_sqs() {
        let reg = registry();
        let sfn_h = handler(&reg, "states");
        let sqs = handler(&reg, "sqs");
        sqs.handle(req(
            "AmazonSQS",
            "CreateQueue",
            json!({ "QueueName": "jq" }),
        ))
        .await;
        let def = json!({
            "QueryLanguage": "JSONata",
            "StartAt": "Send",
            "States": {
                "Send": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sqs:sendMessage",
                    "Arguments": {
                        "QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/jq",
                        "MessageBody": "{% 'order:' & $string($states.input.id) %}"
                    },
                    "End": true
                }
            }
        });
        let arn = create_sm(&sfn_h, "jtask", def).await;
        let s = sfn(
            &sfn_h,
            "StartExecution",
            json!({ "stateMachineArn": arn, "input": "{\"id\":7}" }),
        )
        .await;
        let e = await_execution(&sfn_h, s["executionArn"].as_str().unwrap()).await;
        assert_eq!(e["status"], "SUCCEEDED", "{e}");
        let recv = sqs
            .handle(req(
                "AmazonSQS",
                "ReceiveMessage",
                json!({ "QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/jq" }),
            ))
            .await;
        let (_, rv) = body_of(recv).await;
        assert_eq!(rv["Messages"][0]["Body"], "order:7");
    }

    #[tokio::test]
    async fn inherited_jsonata_assign_and_choice_output() {
        let reg = registry();
        let h = handler(&reg, "states");
        let definition = json!({
            "StartAt": "Assign",
            "States": {
                "Assign": {
                    "Type": "Pass",
                    "Assign": { "x": "{% $states.input.n %}" },
                    "Next": "Parallel"
                },
                "Parallel": {
                    "Type": "Parallel",
                    "QueryLanguage": "JSONata",
                    "Branches": [
                        {
                            "StartAt": "UseVariable",
                            "States": {
                                "UseVariable": { "Type": "Pass", "Output": "{% $x %}", "End": true }
                            }
                        },
                        {
                            "StartAt": "Map",
                            "States": {
                                "Map": {
                                    "Type": "Map",
                                    "Items": "{% [1, 2] %}",
                                    "ItemProcessor": {
                                        "StartAt": "Double",
                                        "States": {
                                            "Double": {
                                                "Type": "Pass",
                                                "Output": "{% $states.input * 2 %}",
                                                "End": true
                                            }
                                        }
                                    },
                                    "End": true
                                }
                            }
                        }
                    ],
                    "Next": "Choice"
                },
                "Choice": {
                    "Type": "Choice",
                    "QueryLanguage": "JSONata",
                    "Choices": [{
                        "Condition": "{% true %}",
                        "Next": "Done"
                    }],
                    "Output": { "snapshot": "{% $states.input %}" }
                },
                "Done": { "Type": "Succeed" }
            }
        });
        let arn = create_sm(&h, "ql-inheritance", definition).await;
        let start = sfn(
            &h,
            "StartExecution",
            json!({ "stateMachineArn": arn, "input": "{\"n\":3}" }),
        )
        .await;
        let execution = await_execution(&h, start["executionArn"].as_str().unwrap()).await;
        assert_eq!(execution["status"], "SUCCEEDED", "{execution}");
        let output: Value = serde_json::from_str(execution["output"].as_str().unwrap()).unwrap();
        assert_eq!(output["snapshot"][0].as_f64(), Some(3.0));
        assert_eq!(output["snapshot"][1][0].as_f64(), Some(2.0));
        assert_eq!(output["snapshot"][1][1].as_f64(), Some(4.0));
    }

    #[tokio::test]
    async fn test_state_reports_single_attempt_retry_and_catch() {
        let reg = registry();
        let h = handler(&reg, "states");
        let pass = sfn(
            &h,
            "TestState",
            json!({
                "definition": json!({
                    "Type": "Pass",
                    "Assign": { "seen": "{% $states.input.value %}" },
                    "End": true
                }).to_string(),
                "input": "{\"value\":9}",
                "inspectionLevel": "TRACE"
            }),
        )
        .await;
        assert_eq!(pass["status"], "SUCCEEDED");
        let variables: Value = serde_json::from_str(
            pass.pointer("/inspectionData/variables")
                .and_then(Value::as_str)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(variables["seen"].as_f64(), Some(9.0));

        let task = json!({
            "Type": "Task",
            "Resource": "arn:aws:states:::sqs:sendMessage",
            "Retry": [{ "ErrorEquals": ["Boom"], "MaxAttempts": 2 }],
            "Catch": [{ "ErrorEquals": ["States.ALL"], "Next": "Handled" }],
            "End": true
        });
        let retriable = sfn(
            &h,
            "TestState",
            json!({
                "definition": task.to_string(),
                "mock": { "errorOutput": { "error": "Boom", "cause": "first" } },
                "stateConfiguration": { "retrierRetryCount": 0 }
            }),
        )
        .await;
        assert_eq!(retriable["status"], "RETRIABLE");
        assert_eq!(retriable["error"], "Boom");

        let caught = sfn(
            &h,
            "TestState",
            json!({
                "definition": task.to_string(),
                "mock": { "errorOutput": { "error": "Boom", "cause": "last" } },
                "stateConfiguration": { "retrierRetryCount": 2 }
            }),
        )
        .await;
        assert_eq!(caught["status"], "CAUGHT_ERROR");
        assert_eq!(caught["nextState"], "Handled");
    }

    #[tokio::test]
    async fn versions_aliases_tags_and_validation_are_consistent() {
        let reg = registry();
        let h = handler(&reg, "states");
        let first_definition = json!({
            "StartAt": "Result",
            "States": { "Result": { "Type": "Pass", "Result": 1, "End": true } }
        });
        let created = sfn(
            &h,
            "CreateStateMachine",
            json!({
                "name": "versioned",
                "definition": first_definition.to_string(),
                "roleArn": "arn:aws:iam::000000000000:role/sfn",
                "publish": true,
                "tags": [{ "key": "env", "value": "qa" }]
            }),
        )
        .await;
        let machine_arn = created["stateMachineArn"].as_str().unwrap();
        let version_one = created["stateMachineVersionArn"].as_str().unwrap();
        let second_definition = json!({
            "StartAt": "Result",
            "States": { "Result": { "Type": "Pass", "Result": 2, "End": true } }
        });
        let updated = sfn(
            &h,
            "UpdateStateMachine",
            json!({
                "stateMachineArn": machine_arn,
                "definition": second_definition.to_string(),
                "publish": true
            }),
        )
        .await;
        let version_two = updated["stateMachineVersionArn"].as_str().unwrap();
        let versions = sfn(
            &h,
            "ListStateMachineVersions",
            json!({ "stateMachineArn": machine_arn }),
        )
        .await;
        assert_eq!(
            versions["stateMachineVersions"].as_array().unwrap().len(),
            2
        );

        let alias = sfn(
            &h,
            "CreateStateMachineAlias",
            json!({
                "name": "live",
                "routingConfiguration": [{
                    "stateMachineVersionArn": version_one,
                    "weight": 100
                }]
            }),
        )
        .await;
        let alias_arn = alias["stateMachineAliasArn"].as_str().unwrap();
        let first = sfn(
            &h,
            "StartExecution",
            json!({ "stateMachineArn": alias_arn }),
        )
        .await;
        let first = await_execution(&h, first["executionArn"].as_str().unwrap()).await;
        assert_eq!(
            serde_json::from_str::<Value>(first["output"].as_str().unwrap()).unwrap(),
            1
        );
        sfn(
            &h,
            "UpdateStateMachineAlias",
            json!({
                "stateMachineAliasArn": alias_arn,
                "routingConfiguration": [{
                    "stateMachineVersionArn": version_two,
                    "weight": 100
                }]
            }),
        )
        .await;
        let second = sfn(
            &h,
            "StartExecution",
            json!({ "stateMachineArn": alias_arn }),
        )
        .await;
        let second = await_execution(&h, second["executionArn"].as_str().unwrap()).await;
        assert_eq!(
            serde_json::from_str::<Value>(second["output"].as_str().unwrap()).unwrap(),
            2
        );

        let tags = sfn(
            &h,
            "ListTagsForResource",
            json!({ "resourceArn": machine_arn }),
        )
        .await;
        assert_eq!(tags["tags"], json!([{ "key": "env", "value": "qa" }]));
        let valid = sfn(
            &h,
            "ValidateStateMachineDefinition",
            json!({ "definition": second_definition.to_string(), "type": "STANDARD" }),
        )
        .await;
        assert_eq!(valid["result"], "OK");
        let (status, body) = body_of(
            h.handle(req(
                "AWSStepFunctions",
                "UpdateStateMachine",
                json!({
                    "stateMachineArn": version_one,
                    "definition": second_definition.to_string()
                }),
            ))
            .await,
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(body["__type"], "ValidationException");
    }

    #[tokio::test]
    async fn history_is_causal_and_execution_data_is_encoded() {
        let reg = registry();
        let h = handler(&reg, "states");
        let sqs = handler(&reg, "sqs");
        sqs.handle(req(
            "AmazonSQS",
            "CreateQueue",
            json!({ "QueueName": "history-q" }),
        ))
        .await;
        let definition = json!({
            "StartAt": "Send",
            "States": {
                "Send": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sqs:sendMessage",
                    "Parameters": {
                        "QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/history-q",
                        "MessageBody": "history"
                    },
                    "End": true
                }
            }
        });
        let arn = create_sm(&h, "history", definition).await;
        let started = sfn(&h, "StartExecution", json!({ "stateMachineArn": arn })).await;
        let execution_arn = started["executionArn"].as_str().unwrap();
        let execution = await_execution(&h, execution_arn).await;
        assert_eq!(execution["status"], "SUCCEEDED");
        let history = sfn(
            &h,
            "GetExecutionHistory",
            json!({ "executionArn": execution_arn }),
        )
        .await;
        let events = history["events"].as_array().unwrap();
        let ids: std::collections::HashSet<u64> = events
            .iter()
            .filter_map(|event| event["id"].as_u64())
            .collect();
        for event in events {
            if let Some(previous) = event["previousEventId"].as_u64() {
                assert!(previous < event["id"].as_u64().unwrap());
                assert!(ids.contains(&previous));
            }
            if let Some(details) = event
                .as_object()
                .and_then(|object| object.iter().find(|(key, _)| key.ends_with("EventDetails")))
                .and_then(|(_, value)| value.as_object())
            {
                for field in ["input", "output", "parameters"] {
                    if let Some(value) = details.get(field) {
                        assert!(value.is_string(), "{field} was not encoded in {event}");
                    }
                }
            }
        }
        let scheduled = events
            .iter()
            .find(|event| event["type"] == "TaskScheduled")
            .unwrap();
        let parameters = scheduled["taskScheduledEventDetails"]["parameters"]
            .as_str()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(parameters).unwrap()["MessageBody"],
            "history"
        );

        let without_data = sfn(
            &h,
            "GetExecutionHistory",
            json!({ "executionArn": execution_arn, "includeExecutionData": false }),
        )
        .await;
        for event in without_data["events"].as_array().unwrap() {
            if let Some(details) = event
                .as_object()
                .and_then(|object| object.iter().find(|(key, _)| key.ends_with("EventDetails")))
                .and_then(|(_, value)| value.as_object())
            {
                assert!(!details.contains_key("input"));
                assert!(!details.contains_key("output"));
                assert!(!details.contains_key("parameters"));
            }
        }
    }

    #[tokio::test]
    async fn activity_retries_use_fresh_tokens_and_preserve_oversized_token() {
        let reg = registry();
        let h = handler(&reg, "states");
        let activity = sfn(&h, "CreateActivity", json!({ "name": "retry-activity" })).await;
        let activity_arn = activity["activityArn"].as_str().unwrap();
        let definition = json!({
            "StartAt": "Work",
            "States": {
                "Work": {
                    "Type": "Task",
                    "Resource": activity_arn,
                    "Retry": [{
                        "ErrorEquals": ["Boom"],
                        "IntervalSeconds": 0,
                        "MaxAttempts": 1
                    }],
                    "End": true
                }
            }
        });
        let machine_arn = create_sm(&h, "activity-retry", definition).await;
        let started = sfn(
            &h,
            "StartExecution",
            json!({ "stateMachineArn": machine_arn }),
        )
        .await;
        let execution_arn = started["executionArn"].as_str().unwrap();
        let first = activity_task(&h, activity_arn).await;
        let first_token = first["taskToken"].as_str().unwrap();
        sfn(&h, "SendTaskHeartbeat", json!({ "taskToken": first_token })).await;
        sfn(
            &h,
            "SendTaskFailure",
            json!({ "taskToken": first_token, "error": "Boom", "cause": "retry" }),
        )
        .await;
        let second = activity_task(&h, activity_arn).await;
        let second_token = second["taskToken"].as_str().unwrap();
        assert_ne!(first_token, second_token);
        let (stale_status, _) = body_of(
            h.handle(req(
                "AWSStepFunctions",
                "SendTaskSuccess",
                json!({
                    "taskToken": first_token,
                    "output": "{}"
                }),
            ))
            .await,
        )
        .await;
        assert_eq!(stale_status, 400);

        let oversized = format!("\"{}\"", "x".repeat(256 * 1024));
        let (oversized_status, _) = body_of(
            h.handle(req(
                "AWSStepFunctions",
                "SendTaskSuccess",
                json!({
                    "taskToken": second_token,
                    "output": oversized
                }),
            ))
            .await,
        )
        .await;
        assert_eq!(oversized_status, 400);
        sfn(
            &h,
            "SendTaskSuccess",
            json!({ "taskToken": second_token, "output": "{\"ok\":true}" }),
        )
        .await;
        let execution = await_execution(&h, execution_arn).await;
        assert_eq!(execution["status"], "SUCCEEDED", "{execution}");
    }

    #[tokio::test]
    async fn stop_execution_invalidates_activity_and_freezes_history() {
        let reg = registry();
        let h = handler(&reg, "states");
        let activity = sfn(&h, "CreateActivity", json!({ "name": "stop-activity" })).await;
        let activity_arn = activity["activityArn"].as_str().unwrap();
        let definition = json!({
            "StartAt": "Work",
            "States": { "Work": { "Type": "Task", "Resource": activity_arn, "End": true } }
        });
        let machine_arn = create_sm(&h, "activity-stop", definition).await;
        let started = sfn(
            &h,
            "StartExecution",
            json!({ "stateMachineArn": machine_arn }),
        )
        .await;
        let execution_arn = started["executionArn"].as_str().unwrap();
        let task = activity_task(&h, activity_arn).await;
        let token = task["taskToken"].as_str().unwrap();
        sfn(
            &h,
            "StopExecution",
            json!({ "executionArn": execution_arn, "error": "Stopped", "cause": "qa" }),
        )
        .await;
        let (status, _) = body_of(
            h.handle(req(
                "AWSStepFunctions",
                "SendTaskSuccess",
                json!({
                    "taskToken": token,
                    "output": "{}"
                }),
            ))
            .await,
        )
        .await;
        assert_eq!(status, 400);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let execution = sfn(
            &h,
            "DescribeExecution",
            json!({ "executionArn": execution_arn }),
        )
        .await;
        assert_eq!(execution["status"], "ABORTED");
        let history = sfn(
            &h,
            "GetExecutionHistory",
            json!({ "executionArn": execution_arn }),
        )
        .await;
        assert_eq!(
            history["events"].as_array().unwrap().last().unwrap()["type"],
            "ExecutionAborted"
        );
    }

    #[tokio::test]
    async fn oversized_parameters_fail_before_sqs_side_effect() {
        let reg = registry();
        let h = handler(&reg, "states");
        let sqs = handler(&reg, "sqs");
        let queue_url = "https://sqs.us-east-1.amazonaws.com/000000000000/no-side-effect";
        sqs.handle(req(
            "AmazonSQS",
            "CreateQueue",
            json!({ "QueueName": "no-side-effect" }),
        ))
        .await;
        let definition = json!({
            "StartAt": "Send",
            "States": {
                "Send": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sqs:sendMessage",
                    "Parameters": {
                        "QueueUrl": queue_url,
                        "MessageBody": "x".repeat(256 * 1024)
                    },
                    "End": true
                }
            }
        });
        let machine_arn = create_sm(&h, "oversized-parameters", definition).await;
        let started = sfn(
            &h,
            "StartExecution",
            json!({ "stateMachineArn": machine_arn }),
        )
        .await;
        let execution = await_execution(&h, started["executionArn"].as_str().unwrap()).await;
        assert_eq!(execution["status"], "FAILED");
        assert_eq!(execution["error"], "States.DataLimitExceeded");
        let response = sqs
            .handle(req(
                "AmazonSQS",
                "ReceiveMessage",
                json!({ "QueueUrl": queue_url }),
            ))
            .await;
        let (_, body) = body_of(response).await;
        assert!(body["Messages"].as_array().is_none_or(Vec::is_empty));
    }
    #[tokio::test]
    async fn deletion_waits_for_standard_transition_and_rejects_new_executions() {
        let reg = registry();
        let h = handler(&reg, "states");
        let arn = create_sm(
            &h,
            "delete-running",
            json!({
                "StartAt": "Pause", "States": {
                    "Pause": { "Type": "Wait", "Seconds": 1, "Next": "Done" },
                    "Done": { "Type": "Pass", "End": true }
                }
            }),
        )
        .await;
        let started = sfn(&h, "StartExecution", json!({"stateMachineArn": arn})).await;
        let exec = started["executionArn"].as_str().unwrap();
        for _ in 0..100 {
            let history = sfn(&h, "GetExecutionHistory", json!({"executionArn": exec})).await;
            if history["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["type"] == "WaitStateEntered")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        sfn(&h, "DeleteStateMachine", json!({"stateMachineArn": arn})).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let machine = sfn(&h, "DescribeStateMachine", json!({"stateMachineArn": arn})).await;
        assert_eq!(machine["status"], "DELETING");
        let (status, body) = body_of(
            h.handle(req(
                "AWSStepFunctions",
                "StartExecution",
                json!({"stateMachineArn": arn}),
            ))
            .await,
        )
        .await;
        assert_eq!(status, 400);
        assert!(body["__type"]
            .as_str()
            .unwrap()
            .contains("StateMachineDeleting"));
        let execution = await_execution(&h, exec).await;
        assert_eq!(execution["status"], "ABORTED");
        let history = sfn(&h, "GetExecutionHistory", json!({"executionArn": exec})).await;
        assert!(history["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["type"] == "ExecutionAborted"));
        assert!(!history["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["stateEnteredEventDetails"]["name"] == "Done"));
        await_machine_deleted(&h, &arn).await;
    }

    async fn await_machine_deleted(h: &Arc<dyn NativeHandler>, arn: &str) {
        for _ in 0..100 {
            let (status, body) = body_of(
                h.handle(req(
                    "AWSStepFunctions",
                    "DescribeStateMachine",
                    json!({"stateMachineArn": arn}),
                ))
                .await,
            )
            .await;
            if status == 400 {
                assert!(body["__type"]
                    .as_str()
                    .unwrap()
                    .contains("StateMachineDoesNotExist"));
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("state machine remained after its workers completed");
    }

    #[derive(Default)]
    struct GatedLogs {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait]
    impl InternalLogSink for GatedLogs {
        async fn resolve_group(
            &self,
            _: LogScope,
            spec: ProducerGroupSpec,
            _: ProducerContext,
        ) -> Result<GroupRef, SinkError> {
            Ok(GroupRef { name: spec.name })
        }
        async fn ensure_group(
            &self,
            scope: LogScope,
            spec: ProducerGroupSpec,
            context: ProducerContext,
        ) -> Result<GroupRef, SinkError> {
            self.resolve_group(scope, spec, context).await
        }
        async fn ensure_stream(
            &self,
            _: LogScope,
            group: GroupRef,
            spec: ProducerStreamSpec,
            _: ProducerContext,
        ) -> Result<StreamRef, SinkError> {
            Ok(StreamRef {
                group_name: group.name,
                stream_name: spec.name,
            })
        }
        async fn append(
            &self,
            _: LogScope,
            _: StreamRef,
            events: Vec<ProducerLogEvent>,
            _: ProducerContext,
        ) -> Result<AppendOutcome, SinkError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(AppendOutcome {
                stored_events: events.len(),
            })
        }
    }

    #[tokio::test]
    async fn express_deletion_waits_for_final_log_delivery() {
        let reg = registry();
        let h = handler(&reg, "states");
        let sink = Arc::new(GatedLogs::default());
        reg.register_native_with_log_sink(
            ServiceName::new("logs"),
            ServiceMetadata::new(AwsProtocol::Json11, Some("Logs_20140328")),
            h.clone(),
            sink.clone(),
        );
        let created = sfn(&h, "CreateStateMachine", json!({
            "name": "express-drain", "type": "EXPRESS",
            "roleArn": "arn:aws:iam::000000000000:role/sfn",
            "definition": json!({"StartAt":"Done", "States":{"Done":{"Type":"Pass", "End":true}}}).to_string(),
            "loggingConfiguration": {"level":"ALL", "destinations":[{"cloudWatchLogsLogGroup":{"logGroupArn":"arn:aws:logs:us-east-1:000000000000:log-group:/test/express:*"}}]}
        })).await;
        let arn = created["stateMachineArn"].as_str().unwrap().to_string();
        let sync_h = h.clone();
        let sync_arn = arn.clone();
        let sync = tokio::spawn(async move {
            sfn(
                &sync_h,
                "StartSyncExecution",
                json!({"stateMachineArn":sync_arn}),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), sink.entered.notified())
            .await
            .unwrap();
        sfn(&h, "DeleteStateMachine", json!({"stateMachineArn":arn})).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            sfn(&h, "DescribeStateMachine", json!({"stateMachineArn":arn})).await["status"],
            "DELETING"
        );
        assert!(!sync.is_finished());
        sink.release.notify_one();
        assert_eq!(sync.await.unwrap()["status"], "SUCCEEDED");
        await_machine_deleted(&h, &arn).await;
    }
}
