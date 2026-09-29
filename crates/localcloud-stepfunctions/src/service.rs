//! Step Functions service handler: AWS JSON 1.0 dispatch by `X-Amz-Target`, registered
//! `Native`. Task integrations dispatch to other native services through the registry
//! (held as a `Weak` reference to avoid a cycle).

use std::sync::{Arc, Weak};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use serde_json::Value;

use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::integration::InternalDispatcher;
use localcloud_core::proxy::{LegacyHealth, ProxyConfig};
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

use crate::authorization;
use crate::error::SfnError;
use crate::ops::{self, Ctx};
use crate::store::SfnStore;

const TARGET_PREFIX: &str = "AWSStepFunctions";

pub struct SfnHandler {
    store: Arc<SfnStore>,
    registry: Weak<ServiceRegistry>,
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
        match self.dispatch(&op, &ctx, &body).await {
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
pub fn register(registry: &Arc<ServiceRegistry>) {
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
    let handler: Arc<dyn NativeHandler> = Arc::new(SfnHandler::new(Arc::downgrade(registry)));
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
    use serde_json::json;
    use std::time::Duration;

    fn registry() -> Arc<ServiceRegistry> {
        let reg = ServiceRegistry::with_known_services();
        localcloud_sqs::register(&reg);
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
        localcloud_dynamodb::register(&reg);
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
}
