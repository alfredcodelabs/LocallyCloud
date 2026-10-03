//! Property-based coverage for design Properties 1–19.

use std::sync::Arc;
use std::time::Duration;

use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use proptest::prelude::*;
use serde_json::{json, Map, Value};

use crate::asl::StateMachine;
use crate::error::{AslError, SfnError};
use crate::interpreter::retry_backoff_seconds;

const ROLE_ARN: &str = "arn:aws:iam::000000000000:role/property-tests";

fn async_config() -> ProptestConfig {
    ProptestConfig {
        cases: 8,
        max_shrink_iters: 128,
        ..ProptestConfig::default()
    }
}

fn pure_config() -> ProptestConfig {
    ProptestConfig {
        cases: 128,
        max_shrink_iters: 512,
        ..ProptestConfig::default()
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("property-test runtime")
}
fn registry() -> Arc<ServiceRegistry> {
    let registry = ServiceRegistry::with_known_services();
    locallycloud_sqs::register(&registry);
    crate::register(&registry);
    registry
}

fn handler(registry: &Arc<ServiceRegistry>, service: &str) -> Arc<dyn NativeHandler> {
    registry
        .native_handler(&ServiceName::new(service))
        .expect("registered native handler")
}

fn request(
    prefix: &str,
    operation: &str,
    body: Value,
    region: &str,
    account: &str,
) -> ServiceRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("{prefix}.{operation}")).expect("valid target"),
    );
    ServiceRequest {
        method: Method::POST,
        uri: "/".parse().expect("valid URI"),
        headers,
        body: Bytes::from(body.to_string()),
        region: region.to_string(),
        account_id: account.to_string(),
        request_id: "property-test".to_string(),
    }
}

async fn response_body(response: Response) -> (u16, Value) {
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn call_scoped(
    handler: &Arc<dyn NativeHandler>,
    operation: &str,
    body: Value,
    region: &str,
    account: &str,
) -> (u16, Value) {
    response_body(
        handler
            .handle(request(
                "AWSStepFunctions",
                operation,
                body,
                region,
                account,
            ))
            .await,
    )
    .await
}

async fn call(handler: &Arc<dyn NativeHandler>, operation: &str, body: Value) -> (u16, Value) {
    call_scoped(handler, operation, body, "us-east-1", "000000000000").await
}
async fn ok(handler: &Arc<dyn NativeHandler>, operation: &str, body: Value) -> Value {
    let (status, body) = call(handler, operation, body).await;
    assert_eq!(status, 200, "{operation} failed: {body}");
    body
}

async fn create_machine(
    handler: &Arc<dyn NativeHandler>,
    name: &str,
    definition: Value,
    machine_type: &str,
) -> String {
    let body = ok(
        handler,
        "CreateStateMachine",
        json!({
            "name": name,
            "definition": definition.to_string(),
            "roleArn": ROLE_ARN,
            "type": machine_type,
        }),
    )
    .await;
    body["stateMachineArn"]
        .as_str()
        .expect("state machine ARN")
        .to_string()
}

async fn await_execution(handler: &Arc<dyn NativeHandler>, arn: &str) -> Value {
    for _ in 0..300 {
        let body = ok(handler, "DescribeExecution", json!({ "executionArn": arn })).await;
        if body["status"] != "RUNNING" {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("execution did not terminate: {arn}");
}

async fn start_and_wait(
    handler: &Arc<dyn NativeHandler>,
    machine_arn: &str,
    input: Value,
) -> Value {
    let started = ok(
        handler,
        "StartExecution",
        json!({ "stateMachineArn": machine_arn, "input": input.to_string() }),
    )
    .await;
    await_execution(
        handler,
        started["executionArn"].as_str().expect("execution ARN"),
    )
    .await
}

fn short_text() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<char>(), 0..24).prop_map(|characters| {
        characters
            .into_iter()
            .filter(|character| *character != '\0')
            .collect()
    })
}

fn error_for(index: u8, message: String) -> SfnError {
    match index % 24 {
        0 => SfnError::StateMachineDoesNotExist(message),
        1 => SfnError::StateMachineAlreadyExists(message),
        2 => SfnError::StateMachineDeleting(message),
        3 => SfnError::StateMachineLimitExceeded(message),
        4 => SfnError::ExecutionDoesNotExist(message),
        5 => SfnError::ExecutionAlreadyExists(message),
        6 => SfnError::ExecutionLimitExceeded(message),
        7 => SfnError::ExecutionNotRedrivable(message),
        8 => SfnError::ActivityDoesNotExist(message),
        9 => SfnError::ActivityLimitExceeded(message),
        10 => SfnError::TaskDoesNotExist(message),
        11 => SfnError::TaskTimedOut(message),
        12 => SfnError::InvalidExecutionInput(message),
        13 => SfnError::InvalidDefinition(message),
        14 => SfnError::InvalidName(message),
        15 => SfnError::InvalidArn(message),
        16 => SfnError::StateMachineTypeNotSupported(message),
        17 => SfnError::InvalidLoggingConfiguration(message),
        18 => SfnError::InvalidTracingConfiguration(message),
        19 => SfnError::InvalidEncryptionConfiguration(message),
        20 => SfnError::ConflictException(message),
        21 => SfnError::ResourceNotFound(message),
        22 => SfnError::Validation(message),
        _ => SfnError::UnknownOperation(message),
    }
}
proptest! {
    #![proptest_config(pure_config())]

    // Property 5: Retry Backoff Bounds.
    #[test]
    fn property_5_retry_backoff_bounds(
        interval in 0u16..30,
        backoff_hundredths in 100u16..500,
        attempt in 1u32..8,
        max_delay in 0u16..120,
        sample_thousandths in 0u16..=1000,
    ) {
        let interval = f64::from(interval);
        let backoff = f64::from(backoff_hundredths) / 100.0;
        let max_delay = f64::from(max_delay);
        let sample = f64::from(sample_thousandths) / 1000.0;
        let ceiling = (interval * backoff.powi((attempt - 1) as i32)).min(max_delay).max(0.0);
        let none = retry_backoff_seconds(interval, backoff, attempt, max_delay, false, sample);
        let full = retry_backoff_seconds(interval, backoff, attempt, max_delay, true, sample);
        prop_assert_eq!(none, ceiling);
        prop_assert!((0.0..=ceiling).contains(&full));
        prop_assert!((full - ceiling * sample).abs() < f64::EPSILON * ceiling.max(1.0));
    }

    // Property 8: States.ALL Catch-All.
    #[test]
    fn property_8_states_all_catch_all(error in "[A-Za-z.]{1,24}") {
        let asl_error = AslError::new(error.clone(), "cause");
        let excluded = matches!(error.as_str(), "States.DataLimitExceeded" | "States.Runtime");
        prop_assert_eq!(asl_error.matches("States.ALL"), !excluded);

        let good = json!({
            "StartAt": "Work",
            "States": {
                "Work": { "Type": "Task", "Resource": "arn:aws:states:::sqs:sendMessage", "Catch": [
                    { "ErrorEquals": [error], "Next": "Handled" },
                    { "ErrorEquals": ["States.ALL"], "Next": "Handled" }
                ], "End": true },
                "Handled": { "Type": "Succeed" }
            }
        });
        let bad = json!({
            "StartAt": "Work",
            "States": {
                "Work": { "Type": "Task", "Resource": "arn:aws:states:::sqs:sendMessage", "Catch": [
                    { "ErrorEquals": ["States.ALL"], "Next": "Handled" },
                    { "ErrorEquals": [error], "Next": "Handled" }
                ], "End": true },
                "Handled": { "Type": "Succeed" }
            }
        });
        prop_assert!(StateMachine::parse(&good.to_string()).is_ok());
        prop_assert!(StateMachine::parse(&bad.to_string()).is_err());
    }
    // Property 9: Choice Determinism.
    #[test]
    fn property_9_choice_determinism(value in -100i32..100, first_limit in -100i32..100) {
        let state = json!({
            "Type": "Choice",
            "Choices": [
                { "Variable": "$.value", "NumericGreaterThanEquals": first_limit, "Next": "First" },
                { "Variable": "$.value", "IsNumeric": true, "Next": "Second" }
            ],
            "Default": "Default"
        });
        let input = json!({ "value": value });
        let first = crate::choice::evaluate(&state, &input).expect("choice evaluates");
        let second = crate::choice::evaluate(&state, &input).expect("choice evaluates twice");
        prop_assert_eq!(&first, &second);
        prop_assert_eq!(first, if value >= first_limit { "First" } else { "Second" });
    }

    // Property 10: Intrinsic Correctness.
    #[test]
    fn property_10_intrinsic_correctness(left in -10_000i32..10_000, right in -10_000i32..10_000) {
        let valid = json!({ "sum.$": format!("States.MathAdd({left}, {right})") });
        let output = crate::path::process_payload(&valid, &json!({}), &json!({}))
            .expect("valid intrinsic");
        prop_assert_eq!(output["sum"].as_i64(), Some(i64::from(left) + i64::from(right)));

        let invalid = json!({ "sum.$": format!("States.MathAdd({left})") });
        let error = crate::path::process_payload(&invalid, &json!({}), &json!({}))
            .expect_err("invalid intrinsic");
        prop_assert_eq!(error.error, "States.IntrinsicFailure");
    }
}

proptest! {
    #![proptest_config(async_config())]

    // Property 1: Error Deserialization.
    #[test]
    fn property_1_error_deserialization(index in any::<u8>(), message in short_text()) {
        runtime().block_on(async move {
            let error = error_for(index, message.clone());
            let expected_code = error.code();
            let (status, body) = response_body(error.into_response("request-id")).await;
            assert_eq!(status, 400);
            assert_eq!(body["__type"], expected_code);
            assert_eq!(body["message"], message);
            assert_eq!(body.as_object().and_then(|object| object.get("__type")).and_then(Value::as_str), Some(expected_code));
        });
    }

    // Property 2: JSONPath Processing Order.
    #[test]
    fn property_2_jsonpath_processing_order(value in any::<i32>()) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let state = json!({
                "Type": "Pass",
                "InputPath": "$.source",
                "Parameters": { "picked.$": "$.value" },
                "ResultSelector": { "selected.$": "$.picked" },
                "ResultPath": "$.joined",
                "OutputPath": "$.joined.selected",
                "End": true
            });
            let body = ok(&states, "TestState", json!({
                "definition": state.to_string(),
                "input": json!({ "source": { "value": value }, "value": "wrong" }).to_string()
            })).await;
            let output: Value = serde_json::from_str(body["output"].as_str().expect("output string")).expect("JSON output");
            assert_eq!(output, value);
        });
    }
    // Property 3: Payload UTF-8 Fidelity.
    #[test]
    fn property_3_payload_utf8_fidelity(text in short_text(), number in any::<i32>()) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let sqs = handler(&registry, "sqs");
            let queue_url = "https://sqs.us-east-1.amazonaws.com/000000000000/property-utf8";
            sqs.handle(request("AmazonSQS", "CreateQueue", json!({ "QueueName": "property-utf8" }), "us-east-1", "000000000000")).await;
            let nested = json!({ "text": text, "array": [number, { "unicode": "λ雪🙂" }] });
            let message = nested.to_string();
            let definition = json!({
                "StartAt": "Send",
                "States": { "Send": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sqs:sendMessage",
                    "Parameters": { "QueueUrl": queue_url, "MessageBody.$": "$.message" },
                    "End": true
                }}
            });
            let machine = create_machine(&states, "utf8", definition, "STANDARD").await;
            let execution = start_and_wait(&states, &machine, json!({ "message": message })).await;
            assert_eq!(execution["status"], "SUCCEEDED");
            let (_, received) = response_body(sqs.handle(request(
                "AmazonSQS", "ReceiveMessage", json!({ "QueueUrl": queue_url }), "us-east-1", "000000000000"
            )).await).await;
            assert_eq!(received["Messages"][0]["Body"], nested.to_string());
            assert_eq!(received["Messages"][0]["Body"].as_str().expect("message").as_bytes(), nested.to_string().as_bytes());
        });
    }

    // Property 4: Integration Dispatch Equivalence.
    #[test]
    fn property_4_integration_dispatch_equivalence(message in short_text()) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let sqs = handler(&registry, "sqs");
            let direct_url = "https://sqs.us-east-1.amazonaws.com/000000000000/direct-q";
            let task_url = "https://sqs.us-east-1.amazonaws.com/000000000000/task-q";
            for queue in ["direct-q", "task-q"] {
                sqs.handle(request("AmazonSQS", "CreateQueue", json!({ "QueueName": queue }), "us-east-1", "000000000000")).await;
            }
            let (direct_status, direct_response) = response_body(sqs.handle(request(
                "AmazonSQS", "SendMessage", json!({ "QueueUrl": direct_url, "MessageBody": message }),
                "us-east-1", "000000000000",
            )).await).await;
            let definition = json!({
                "StartAt": "Send",
                "States": { "Send": { "Type": "Task", "Resource": "arn:aws:states:::sqs:sendMessage",
                    "Parameters": { "QueueUrl": task_url, "MessageBody.$": "$.message" }, "End": true } }
            });
            let machine = create_machine(&states, "dispatch-equivalence", definition, "STANDARD").await;
            let execution = start_and_wait(&states, &machine, json!({ "message": message })).await;
            if direct_status == 200 {
                assert_eq!(execution["status"], "SUCCEEDED", "{execution}");
                let mut bodies = Vec::new();
                for queue_url in [direct_url, task_url] {
                    let (_, received) = response_body(sqs.handle(request(
                        "AmazonSQS", "ReceiveMessage", json!({ "QueueUrl": queue_url }),
                        "us-east-1", "000000000000",
                    )).await).await;
                    bodies.push(received["Messages"][0]["Body"].clone());
                }
                assert_eq!(bodies[0], bodies[1]);
            } else {
                assert_eq!(direct_status, 400, "{direct_response}");
                assert_eq!(execution["status"], "FAILED", "{execution}");
                let direct_code = direct_response["__type"]
                    .as_str()
                    .unwrap_or("InvalidParameterValue")
                    .rsplit(['#', ':'])
                    .next()
                    .unwrap();
                assert_eq!(execution["error"], format!("SQS.{direct_code}"));
                assert_eq!(execution["cause"], direct_response["message"]);
            }
        });
    }
    // Property 6: Retry Attempt Bound.
    #[test]
    fn property_6_retry_attempt_bound(max_attempts in 0u32..4) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let definition = json!({
                "StartAt": "Try",
                "States": {
                    "Try": { "Type": "Task", "Resource": "arn:aws:states:::sqs:sendMessage",
                        "Parameters": { "QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/missing", "MessageBody": "x" },
                        "Retry": [{ "ErrorEquals": ["States.ALL"], "IntervalSeconds": 0, "MaxAttempts": max_attempts }],
                        "Catch": [{ "ErrorEquals": ["States.ALL"], "Next": "Handled" }], "End": true },
                    "Handled": { "Type": "Succeed" }
                }
            });
            let machine = create_machine(&states, "retry-bound", definition, "STANDARD").await;
            let started = ok(&states, "StartExecution", json!({ "stateMachineArn": machine })).await;
            let execution_arn = started["executionArn"].as_str().expect("execution ARN");
            assert_eq!(await_execution(&states, execution_arn).await["status"], "SUCCEEDED");
            let history = ok(&states, "GetExecutionHistory", json!({ "executionArn": execution_arn })).await;
            let attempts = history["events"].as_array().expect("events").iter()
                .filter(|event| event["type"] == "TaskStarted").count();
            assert_eq!(attempts, 1 + max_attempts as usize);
        });
    }

    // Property 7: Catch Routing.
    #[test]
    fn property_7_catch_routing(key in "[a-z]{1,8}", error in "[A-Z][A-Za-z]{0,12}", cause in short_text()) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let state = json!({
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage",
                "Catch": [{ "ErrorEquals": [error], "ResultPath": format!("$.{key}"), "Next": "Recovered" }],
                "End": true
            });
            let body = ok(&states, "TestState", json!({
                "definition": state.to_string(),
                "input": "{\"original\":true}",
                "mock": { "errorOutput": { "error": error, "cause": cause } }
            })).await;
            assert_eq!(body["status"], "CAUGHT_ERROR");
            assert_eq!(body["nextState"], "Recovered");
            let output: Value = serde_json::from_str(body["output"].as_str().expect("output")).expect("JSON output");
            assert_eq!(output["original"], true);
            assert_eq!(output[&key]["Error"], error);
            assert_eq!(output[&key]["Cause"], cause);
        });
    }
    // Property 11: Parallel Output Order.
    #[test]
    fn property_11_parallel_output_order(values in proptest::collection::vec(any::<i16>(), 1..6)) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let branches: Vec<Value> = values.iter().enumerate().map(|(index, value)| {
                let name = format!("Branch{index}");
                json!({ "StartAt": name, "States": { name: { "Type": "Pass", "Result": value, "End": true } } })
            }).collect();
            let definition = json!({
                "StartAt": "Parallel",
                "States": { "Parallel": { "Type": "Parallel", "Branches": branches, "End": true } }
            });
            let machine = create_machine(&states, "parallel-order", definition, "STANDARD").await;
            let execution = start_and_wait(&states, &machine, json!({})).await;
            assert_eq!(execution["status"], "SUCCEEDED");
            let output: Value = serde_json::from_str(execution["output"].as_str().expect("output")).expect("JSON output");
            assert_eq!(output, json!(values));
        });
    }

    // Property 12: Map Tolerated-Failure Threshold.
    #[test]
    fn property_12_map_tolerated_failure_threshold(
        total in 1usize..6,
        failed_seed in any::<usize>(),
        limit_seed in any::<usize>(),
        percentage_mode in any::<bool>(),
    ) {
        runtime().block_on(async move {
            let failed = failed_seed % (total + 1);
            let limit = limit_seed % (total + 1);
            let registry = registry();
            let states = handler(&registry, "states");
            let items: Vec<Value> = (0..total).map(|index| json!({ "fail": index < failed })).collect();
            let mut map_state = json!({
                "Type": "Map",
                "ItemsPath": "$.items",
                "ItemProcessor": {
                    "ProcessorConfig": { "Mode": "DISTRIBUTED", "ExecutionType": "STANDARD" },
                    "StartAt": "Choose",
                    "States": {
                        "Choose": { "Type": "Choice", "Choices": [
                            { "Variable": "$.fail", "BooleanEquals": true, "Next": "Bad" }
                        ], "Default": "Good" },
                        "Bad": { "Type": "Fail", "Error": "ItemFailed", "Cause": "generated" },
                        "Good": { "Type": "Pass", "End": true }
                    }
                },
                "End": true
            });
            let expected_success = if percentage_mode {
                let percentage_limit = limit as f64 * 100.0 / total as f64;
                map_state["ToleratedFailurePercentage"] = json!(percentage_limit);
                failed as f64 * 100.0 / total as f64 <= percentage_limit
            } else {
                map_state["ToleratedFailureCount"] = json!(limit);
                failed <= limit
            };
            let definition = json!({ "StartAt": "Map", "States": { "Map": map_state } });
            let machine = create_machine(&states, "map-threshold", definition, "STANDARD").await;
            let execution = start_and_wait(&states, &machine, json!({ "items": items })).await;
            if expected_success {
                assert_eq!(execution["status"], "SUCCEEDED", "{execution}");
            } else {
                assert_eq!(execution["status"], "FAILED", "{execution}");
                assert_eq!(execution["error"], "States.ExceedToleratedFailureThreshold");
            }
        });
    }
    // Property 13: Callback Resume.
    #[test]
    fn property_13_callback_resume(value in any::<i16>(), let_timeout in any::<bool>()) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let sqs = handler(&registry, "sqs");
            let queue_url = "https://sqs.us-east-1.amazonaws.com/000000000000/callback-q";
            sqs.handle(request(
                "AmazonSQS", "CreateQueue", json!({ "QueueName": "callback-q" }),
                "us-east-1", "000000000000",
            )).await;
            let definition = json!({
                "StartAt": "Callback",
                "States": { "Callback": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sqs:sendMessage.waitForTaskToken",
                    "Parameters": { "QueueUrl": queue_url, "MessageBody.$": "$$.Task.Token" },
                    "HeartbeatSeconds": 1,
                    "End": true
                }}
            });
            let machine = create_machine(&states, "callback-resume", definition, "STANDARD").await;
            let started = ok(&states, "StartExecution", json!({ "stateMachineArn": machine })).await;
            let execution_arn = started["executionArn"].as_str().expect("execution ARN");
            let token = loop {
                let (_, received) = response_body(sqs.handle(request(
                    "AmazonSQS", "ReceiveMessage", json!({ "QueueUrl": queue_url }),
                    "us-east-1", "000000000000",
                )).await).await;
                if let Some(token) = received.pointer("/Messages/0/Body").and_then(Value::as_str) {
                    break token.to_string();
                }
                tokio::task::yield_now().await;
            };
            let running = ok(&states, "DescribeExecution", json!({ "executionArn": execution_arn })).await;
            assert_eq!(running["status"], "RUNNING");
            if let_timeout {
                let execution = await_execution(&states, execution_arn).await;
                assert_eq!(execution["status"], "FAILED", "{execution}");
                assert_eq!(execution["error"], "States.HeartbeatTimeout");
            } else {
                ok(&states, "SendTaskSuccess", json!({
                    "taskToken": token,
                    "output": json!({ "value": value }).to_string()
                })).await;
                let execution = await_execution(&states, execution_arn).await;
                assert_eq!(execution["status"], "SUCCEEDED", "{execution}");
                let output: Value = serde_json::from_str(execution["output"].as_str().expect("output"))
                    .expect("JSON output");
                assert_eq!(output, json!({ "value": value }));
            }
        });
    }

    // Property 14: Run-a-Job Terminal Mapping.
    #[test]
    fn property_14_run_a_job_terminal_mapping(child_fails in any::<bool>(), value in any::<i16>()) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let child_state = if child_fails {
                json!({ "Type": "Fail", "Error": "ChildError", "Cause": "generated" })
            } else {
                json!({ "Type": "Pass", "Result": value, "End": true })
            };
            let child = create_machine(&states, "sync-child", json!({
                "StartAt": "Child", "States": { "Child": child_state }
            }), "STANDARD").await;
            let parent = create_machine(&states, "sync-parent", json!({
                "StartAt": "RunChild",
                "States": { "RunChild": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::states:startExecution.sync",
                    "Parameters": { "StateMachineArn": child, "Input": "{}" },
                    "End": true
                }}
            }), "STANDARD").await;
            let execution = start_and_wait(&states, &parent, json!({})).await;
            if child_fails {
                assert_eq!(execution["status"], "FAILED", "{execution}");
                assert_eq!(execution["error"], "States.TaskFailed");
                assert!(execution["cause"].as_str().is_some_and(|cause| cause.contains("ChildError")));
            } else {
                assert_eq!(execution["status"], "SUCCEEDED", "{execution}");
                let output: Value = serde_json::from_str(execution["output"].as_str().expect("output"))
                    .expect("JSON output");
                assert_eq!(output["Status"], "SUCCEEDED");
            }
        });
    }

    // Property 15: Execution Name Dedup.
    #[test]
    fn property_15_execution_name_dedup(value in any::<i32>(), different in any::<i32>()) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let machine = create_machine(&states, "dedup", json!({
                "StartAt": "Done", "States": { "Done": { "Type": "Pass", "End": true } }
            }), "STANDARD").await;
            let name = "property-execution";
            let first = ok(&states, "StartExecution", json!({
                "stateMachineArn": machine, "name": name, "input": json!({ "value": value }).to_string()
            })).await;
            let repeated = ok(&states, "StartExecution", json!({
                "stateMachineArn": machine, "name": name, "input": json!({ "value": value }).to_string()
            })).await;
            assert_eq!(first["executionArn"], repeated["executionArn"]);
            let other = if different == value { value.wrapping_add(1) } else { different };
            let (status, body) = call(&states, "StartExecution", json!({
                "stateMachineArn": machine, "name": name, "input": json!({ "value": other }).to_string()
            })).await;
            assert_eq!(status, 400);
            assert_eq!(body["__type"], "ExecutionAlreadyExists");
        });
    }

    // Property 16: Express Sync Type Gate.
    #[test]
    fn property_16_express_sync_type_gate(value in any::<i32>()) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let definition = json!({
                "StartAt": "Done", "States": { "Done": { "Type": "Pass", "Result": value, "End": true } }
            });
            let standard = create_machine(&states, "sync-standard", definition.clone(), "STANDARD").await;
            let express = create_machine(&states, "sync-express", definition, "EXPRESS").await;
            let (status, body) = call(&states, "StartSyncExecution", json!({ "stateMachineArn": standard })).await;
            assert_eq!(status, 400);
            assert_eq!(body["__type"], "StateMachineTypeNotSupported");
            let synced = ok(&states, "StartSyncExecution", json!({ "stateMachineArn": express })).await;
            assert_eq!(synced["status"], "SUCCEEDED", "{synced}");
            assert_eq!(serde_json::from_str::<Value>(synced["output"].as_str().expect("output")).unwrap(), value);
        });
    }

    // Property 17: History Ordering.
    #[test]
    fn property_17_history_ordering(state_count in 1usize..6) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let mut state_map = Map::new();
            for index in 0..state_count {
                let name = format!("State{index}");
                let state = if index + 1 == state_count {
                    json!({ "Type": "Pass", "End": true })
                } else {
                    json!({ "Type": "Pass", "Next": format!("State{}", index + 1) })
                };
                state_map.insert(name, state);
            }
            let machine = create_machine(&states, "history-order", json!({
                "StartAt": "State0", "States": Value::Object(state_map)
            }), "STANDARD").await;
            let started = ok(&states, "StartExecution", json!({ "stateMachineArn": machine })).await;
            let execution_arn = started["executionArn"].as_str().expect("execution ARN");
            assert_eq!(await_execution(&states, execution_arn).await["status"], "SUCCEEDED");
            let history = ok(&states, "GetExecutionHistory", json!({ "executionArn": execution_arn })).await;
            let events = history["events"].as_array().expect("events");
            let ids: Vec<u64> = events.iter().map(|event| event["id"].as_u64().expect("event id")).collect();
            assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
            for index in 0..state_count {
                let name = format!("State{index}");
                for event_type in ["PassStateEntered", "PassStateExited"] {
                    assert!(events.iter().any(|event| {
                        event["type"] == event_type
                            && event.pointer(&format!("/passState{}EventDetails/name", if event_type.ends_with("Entered") { "Entered" } else { "Exited" }))
                                == Some(&Value::String(name.clone()))
                    }), "missing {event_type} for {name}: {events:?}");
                }
            }
        });
    }

    // Property 18: Data-Limit Enforcement.
    #[test]
    fn property_18_data_limit_enforcement(excess in 1usize..256) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let machine = create_machine(&states, "data-limit", json!({
                "StartAt": "TooLarge",
                "States": { "TooLarge": {
                    "Type": "Pass", "Result": "x".repeat(256 * 1024 + excess), "End": true
                }}
            }), "STANDARD").await;
            let execution = start_and_wait(&states, &machine, json!({})).await;
            assert_eq!(execution["status"], "FAILED", "{execution}");
            assert_eq!(execution["error"], "States.DataLimitExceeded");
        });
    }

    // Property 19: Region/Account Scoping.
    #[test]
    fn property_19_region_account_scoping(value_a in any::<i16>(), value_b in any::<i16>()) {
        runtime().block_on(async move {
            let registry = registry();
            let states = handler(&registry, "states");
            let scopes = [
                ("us-east-1", "111111111111", value_a),
                ("eu-west-1", "222222222222", value_b),
            ];
            let mut arns = Vec::new();
            for (region, account, value) in scopes {
                let (status, body) = call_scoped(&states, "CreateStateMachine", json!({
                    "name": "same-name",
                    "definition": json!({
                        "StartAt": "Done", "States": { "Done": { "Type": "Pass", "Result": value, "End": true } }
                    }).to_string(),
                    "roleArn": format!("arn:aws:iam::{account}:role/property-tests")
                }), region, account).await;
                assert_eq!(status, 200, "{body}");
                arns.push(body["stateMachineArn"].as_str().expect("ARN").to_string());
                let (_, listed) = call_scoped(&states, "ListStateMachines", json!({}), region, account).await;
                let machines = listed["stateMachines"].as_array().expect("state machines");
                assert_eq!(machines.len(), 1);
                assert_eq!(machines[0]["stateMachineArn"], arns.last().unwrap().as_str());
            }
            assert_ne!(arns[0], arns[1]);
            assert!(arns[0].contains("us-east-1:111111111111"));
            assert!(arns[1].contains("eu-west-1:222222222222"));
        });
    }
}
