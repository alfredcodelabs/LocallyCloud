//! ASL acceptance fixtures use public service requests and independently read S3 effects.
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{body::Body, response::Response};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use locallycloud_core::{
    handler::{NativeHandler, ServiceRequest},
    registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry},
};
use serde_json::{json, Value};

#[tokio::test]
async fn jsonata_range_matches_observed_aws_test_state_contracts() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/aws-range-2026-10-06.json")).unwrap();
    let registry = registry();
    for case in fixture["cases"].as_array().unwrap() {
        let definition = json!({
            "Type": "Pass", "QueryLanguage": "JSONata", "End": true,
            "Output": format!("{{% {} %}}", case["expression"].as_str().unwrap())
        });
        let result = api(
            &registry,
            "states",
            "TestState",
            json!({"definition": definition.to_string(), "input": case["input"].to_string(),
                "inspectionLevel": "DEBUG"}),
        )
        .await;
        assert_eq!(
            result["status"], case["status"],
            "{}: {result}",
            case["name"]
        );
        if case["status"] == "SUCCEEDED" {
            let output: Value = serde_json::from_str(result["output"].as_str().unwrap()).unwrap();
            assert_eq!(output, case["output"], "{}", case["name"]);
        } else {
            assert_eq!(result["error"], case["error"], "{}", case["name"]);
            if case.get("local_limitation").is_some() {
                assert!(
                    result["cause"]
                        .as_str()
                        .unwrap()
                        .starts_with("Local $range limit:"),
                    "{result}"
                );
            } else {
                assert_eq!(result["cause"], case["cause"], "{}", case["name"]);
            }
        }
    }
}

#[tokio::test]
async fn test_state_matches_recorded_aws_choices_errors_and_inspection() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/aws-test-state-contract-2026-10-06.json"
    ))
    .unwrap();
    let registry = registry();
    // JSON text fields preserve values and omissions; their whitespace/order is not a contract.
    fn decoded(mut response: Value) -> Value {
        if let Some(text) = response.get("output").and_then(Value::as_str) {
            response["output"] = serde_json::from_str(text).unwrap();
        }
        if let Some(data) = response
            .get_mut("inspectionData")
            .and_then(Value::as_object_mut)
        {
            for field in [
                "input",
                "afterInputPath",
                "afterParameters",
                "afterArguments",
                "result",
                "afterResultSelector",
                "afterResultPath",
                "variables",
            ] {
                if let Some(text) = data.get(field).and_then(Value::as_str) {
                    let value = serde_json::from_str(text).unwrap();
                    data.insert(field.into(), value);
                }
            }
        }
        response
    }
    for case in fixture["cases"].as_array().unwrap() {
        let actual = api(&registry, "states", "TestState", case["request"].clone()).await;
        assert_eq!(
            decoded(actual),
            decoded(case["response"].clone()),
            "{}",
            case["name"]
        );
    }
}

#[tokio::test]
async fn jsonata_choice_type_errors_also_fail_executions() {
    let registry = registry();
    for (index, expression) in ["null", "7"].iter().enumerate() {
        let machine = api(&registry, "states", "CreateStateMachine", json!({
            "name": format!("choice-type-{index}"), "type": "EXPRESS",
            "roleArn": "arn:aws:iam::000000000000:role/test",
            "definition": json!({
                "StartAt": "Choose", "QueryLanguage": "JSONata",
                "States": {
                    "Choose": {"Type": "Choice", "Choices": [{"Condition": format!("{{% {expression} %}}"), "Next": "Matched"}], "Default": "Default"},
                    "Matched": {"Type": "Succeed"}, "Default": {"Type": "Succeed"}
                }
            }).to_string()
        })).await;
        let execution = api(
            &registry,
            "states",
            "StartSyncExecution",
            json!({
                "stateMachineArn": machine["stateMachineArn"], "input": "{}"
            }),
        )
        .await;
        assert_eq!(execution["status"], "FAILED", "{execution}");
        assert_eq!(
            execution["error"], "States.QueryEvaluationError",
            "{execution}"
        );
        assert!(execution["cause"]
            .as_str()
            .unwrap()
            .contains("Choices[0]/Condition"));
    }
}

fn registry() -> Arc<ServiceRegistry> {
    let registry = ServiceRegistry::with_known_services();
    locallycloud_s3::register(&registry);
    locallycloud_analytics::register(&registry);
    locallycloud_stepfunctions::register(&registry);
    registry
}

fn request(method: Method, uri: &str, body: impl Into<Bytes>) -> ServiceRequest {
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("localhost:4566"));
    ServiceRequest {
        method,
        uri: uri.parse().unwrap(),
        headers,
        body: body.into(),
        region: "us-east-1".into(),
        account_id: "000000000000".into(),
        request_id: "etl-fixture".into(),
    }
}

async fn api(
    registry: &Arc<ServiceRegistry>,
    service: &str,
    operation: &str,
    body: Value,
) -> Value {
    let prefix = match service {
        "states" => "AWSStepFunctions",
        "glue" => "AWSGlue",
        _ => panic!("unexpected fixture service"),
    };
    let mut request = request(Method::POST, "/", body.to_string());
    request.headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("{prefix}.{operation}")).unwrap(),
    );
    request.headers.insert(
        "content-type",
        HeaderValue::from_static(if service == "states" {
            "application/x-amz-json-1.0"
        } else {
            "application/x-amz-json-1.1"
        }),
    );
    let response = registry
        .native_handler(&ServiceName::new(service))
        .unwrap()
        .handle(request)
        .await;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let output: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, 200, "{service}:{operation}: {output}");
    output
}

async fn s3(registry: &Arc<ServiceRegistry>, request: ServiceRequest) -> Response {
    let response = registry
        .native_handler(&ServiceName::new("s3"))
        .unwrap()
        .handle(request)
        .await;
    assert!(
        response.status().is_success(),
        "S3 fixture failed: {}",
        response.status()
    );
    response
}

async fn execute(registry: &Arc<ServiceRegistry>, name: &str, definition: Value) -> Value {
    let machine = api(
        registry,
        "states",
        "CreateStateMachine",
        json!({
            "name":name,"definition":definition.to_string(),
            "roleArn":"arn:aws:iam::000000000000:role/etl"
        }),
    )
    .await;
    let execution = api(
        registry,
        "states",
        "StartExecution",
        json!({
            "stateMachineArn":machine["stateMachineArn"],"input":"{}"
        }),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let result = api(
                registry,
                "states",
                "DescribeExecution",
                json!({
                    "executionArn":execution["executionArn"]
                }),
            )
            .await;
            if result["status"] != "RUNNING" {
                assert_eq!(result["status"], "SUCCEEDED", "{result}");
                return serde_json::from_str(result["output"].as_str().unwrap()).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("ASL execution must terminate")
}

#[tokio::test]
async fn s3_asl_pages_lists_and_conditionally_copies_a_source_version() {
    let registry = registry();
    s3(&registry, request(Method::PUT, "/etl-data", "")).await;
    s3(&registry, request(Method::PUT, "/etl-data?versioning", "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>")).await;
    let original = s3(
        &registry,
        request(
            Method::PUT,
            "/etl-data/cache%20%26/a%20%2B%20caf%C3%A9",
            "original",
        ),
    )
    .await;
    let version = original.headers()["x-amz-version-id"]
        .to_str()
        .unwrap()
        .to_string();
    let etag = original.headers()["etag"].to_str().unwrap().to_string();
    for (key, value) in [
        ("cache%20%26/a%20%2B%20caf%C3%A9", "new version"),
        ("cache%20%26/b", "second"),
        ("cache%20%26/nested/item", "nested"),
    ] {
        s3(
            &registry,
            request(Method::PUT, &format!("/etl-data/{key}"), value),
        )
        .await;
    }
    let source = format!("etl-data/cache%20%26/a%20%2B%20caf%C3%A9?versionId={version}");
    let output = execute(&registry, "s3-etl", json!({"StartAt":"First","States":{
        "First":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:s3:listObjectsV2",
            "Parameters":{"Bucket":"etl-data","Prefix":"cache &/","MaxKeys":1},"ResultPath":"$.first","Next":"Second"},
        "Second":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:s3:listObjectsV2",
            "Parameters":{"Bucket":"etl-data","Prefix":"cache &/","MaxKeys":1,"ContinuationToken.$":"$.first.NextContinuationToken"},"ResultPath":"$.second","Next":"Prefixes"},
        "Prefixes":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:s3:listObjectsV2",
            "Parameters":{"Bucket":"etl-data","Prefix":"cache &/","Delimiter":"/"},"ResultPath":"$.prefixes","Next":"Encoded"},
        "Encoded":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:s3:listObjectsV2",
            "Parameters":{"Bucket":"etl-data","Prefix":"cache &/","EncodingType":"url"},"ResultPath":"$.encoded","Next":"Copy"},
        "Copy":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:s3:copyObject",
            "Parameters":{"Bucket":"etl-data","Key":"claim","CopySource":source,"CopySourceIfMatch":etag,"IfNoneMatch":"*"},"ResultPath":"$.copied","Next":"Repeat"},
        "Repeat":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:s3:copyObject",
            "Parameters":{"Bucket":"etl-data","Key":"claim","CopySource":source,"IfNoneMatch":"*"},
            "Catch":[{"ErrorEquals":["S3.PreconditionFailedException"],"ResultPath":"$.failure","Next":"Done"}],"End":true},
        "Done":{"Type":"Pass","End":true}
    }})).await;
    assert_eq!(output["first"]["Contents"][0]["Key"], "cache &/a + café");
    assert_eq!(output["first"]["IsTruncated"], true);
    assert_eq!(output["first"]["KeyCount"], 1);
    assert_eq!(output["second"]["Contents"][0]["Key"], "cache &/b");
    assert_eq!(
        output["prefixes"]["CommonPrefixes"][0]["Prefix"],
        "cache &/nested/"
    );
    assert_eq!(
        output["encoded"]["Contents"][0]["Key"],
        "cache%20%26/a%20%2B%20caf%C3%A9"
    );
    assert_eq!(output["copied"]["CopyObjectResult"]["ETag"], etag);
    assert_eq!(output["failure"]["Error"], "S3.PreconditionFailedException");
    let body = axum::body::to_bytes(
        s3(&registry, request(Method::GET, "/etl-data/claim", ""))
            .await
            .into_body(),
        1024,
    )
    .await
    .unwrap();
    assert_eq!(
        body.as_ref(),
        b"original",
        "versioned source and failed repeat preserve the claimed content"
    );
}

struct CopyBodyFailure;

#[async_trait]
impl NativeHandler for CopyBodyFailure {
    async fn handle(&self, request: ServiceRequest) -> Response {
        assert_eq!(request.method, Method::PUT);
        assert_eq!(request.uri.path(), "/etl-data/claim");
        assert_eq!(request.headers["x-amz-copy-source"], "etl-data/source");
        http::Response::builder().status(200).header("content-type", "application/xml")
            .body(Body::from("<Error><Code>InternalError</Code><Message>copy &amp; commit failed</Message></Error>")).unwrap()
    }
}

#[tokio::test]
async fn s3_copy_http_200_error_body_uses_named_asl_catch() {
    let registry = registry();
    registry.register_native(
        ServiceName::new("s3"),
        ServiceMetadata::new(AwsProtocol::RestXml, None),
        Arc::new(CopyBodyFailure),
    );
    let output = execute(&registry, "copy-body-failure", json!({"StartAt":"Copy","States":{
        "Copy":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:s3:copyObject",
            "Parameters":{"Bucket":"etl-data","Key":"claim","CopySource":"etl-data/source"},
            "Catch":[{"ErrorEquals":["S3.InternalErrorException"],"ResultPath":"$.failure","Next":"Done"}],"End":true},
        "Done":{"Type":"Pass","End":true}
    }})).await;
    assert_eq!(output["failure"]["Error"], "S3.InternalErrorException");
    assert_eq!(output["failure"]["Cause"], "copy & commit failed");
}

#[tokio::test]
async fn athena_asl_sync_pages_real_results_and_catches_a_query_failure() {
    let registry = registry();
    s3(&registry, request(Method::PUT, "/etl-data", "")).await;
    s3(
        &registry,
        request(
            Method::PUT,
            "/etl-data/events/part.json",
            "{\"id\":1}\n{\"id\":2}\n{\"id\":3}\n",
        ),
    )
    .await;
    api(
        &registry,
        "glue",
        "CreateDatabase",
        json!({"DatabaseInput":{"Name":"etl"}}),
    )
    .await;
    api(&registry, "glue", "CreateTable", json!({"DatabaseName":"etl","TableInput":{
        "Name":"events","PartitionKeys":[],"StorageDescriptor":{
            "Location":"s3://etl-data/events/","InputFormat":"org.apache.hadoop.mapred.TextInputFormat",
            "SerdeInfo":{"SerializationLibrary":"org.openx.data.jsonserde.JsonSerDe"}
        }
    }})).await;
    let output = execute(&registry, "athena-etl", json!({"StartAt":"Query","States":{
        "Query":{"Type":"Task","Resource":"arn:aws:states:::athena:startQueryExecution.sync",
            "Parameters":{"QueryString":"SELECT COUNT(*) AS n FROM events","QueryExecutionContext":{"Database":"etl"},"WorkGroup":"primary","ResultConfiguration":{"OutputLocation":"s3://etl-data/results/"}},
            "ResultPath":"$.query","Next":"Header"},
        "Header":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:athena:getQueryResults",
            "Parameters":{"QueryExecutionId.$":"$.query.QueryExecution.QueryExecutionId","MaxResults":1},"ResultPath":"$.header","Next":"Data"},
        "Data":{"Type":"Task","Resource":"arn:aws:states:::athena:getQueryResults",
            "Parameters":{"QueryExecutionId.$":"$.query.QueryExecution.QueryExecutionId","MaxResults":1,"NextToken.$":"$.header.NextToken"},"ResultPath":"$.data","Next":"Terminal"},
        "Terminal":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:athena:getQueryResults",
            "Parameters":{"QueryExecutionId.$":"$.query.QueryExecution.QueryExecutionId","MaxResults":1,"NextToken.$":"$.data.NextToken"},"ResultPath":"$.terminal","Next":"FailedQuery"},
        "FailedQuery":{"Type":"Task","Resource":"arn:aws:states:::athena:startQueryExecution.sync",
            "Parameters":{"QueryString":"SELECT COUNT(*) FROM missing","QueryExecutionContext":{"Database":"etl"},"ResultConfiguration":{"OutputLocation":"s3://etl-data/results/"}},
            "Catch":[{"ErrorEquals":["States.TaskFailed"],"ResultPath":"$.failure","Next":"Done"}],"End":true},
        "Done":{"Type":"Pass","End":true}
    }})).await;
    assert_eq!(
        output["query"]["QueryExecution"]["Status"]["State"],
        "SUCCEEDED"
    );
    assert_eq!(output["query"]["QueryExecution"]["WorkGroup"], "primary");
    assert_eq!(
        output["header"]["ResultSet"]["Rows"],
        json!([{"Data":[{"VarCharValue":"n"}]}])
    );
    assert_eq!(
        output["data"]["ResultSet"]["Rows"],
        json!([{"Data":[{"VarCharValue":"3"}]}])
    );
    assert!(output["data"].get("NextToken").is_some());
    assert_eq!(output["terminal"]["ResultSet"]["Rows"], json!([]));
    assert!(output["terminal"].get("NextToken").is_none());
    assert_eq!(output["failure"]["Error"], "States.TaskFailed");
    let id = output["query"]["QueryExecution"]["QueryExecutionId"]
        .as_str()
        .unwrap();
    let result = s3(
        &registry,
        request(Method::GET, &format!("/etl-data/results/{id}.csv"), ""),
    )
    .await;
    let body = axum::body::to_bytes(result.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(
        body.as_ref(),
        b"\"n\"\n\"3\"\n",
        "query result persisted by the native Athena worker"
    );
}

#[derive(Default)]
struct RunningAthena {
    starts: AtomicUsize,
    polls: AtomicUsize,
    stops: Mutex<Vec<ServiceRequest>>,
}

#[async_trait]
impl NativeHandler for RunningAthena {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let operation = request.headers["x-amz-target"].to_str().unwrap();
        let output = match operation {
            "AmazonAthena.StartQueryExecution" => {
                self.starts.fetch_add(1, Ordering::SeqCst);
                json!({"QueryExecutionId":"running-query"})
            }
            "AmazonAthena.GetQueryExecution" => {
                self.polls.fetch_add(1, Ordering::SeqCst);
                json!({"QueryExecution":{"QueryExecutionId":"running-query","Status":{"State":"RUNNING"}}})
            }
            "AmazonAthena.StopQueryExecution" => {
                assert_eq!(request.account_id, "000000000000");
                assert_eq!(request.region, "us-east-1");
                assert!(matches!(
                    locallycloud_core::integration::identity::trusted_role(&request),
                    Some(locallycloud_core::integration::identity::CallerIdentity::AssumedRole {role_arn, ..})
                        if role_arn == "arn:aws:iam::000000000000:role/etl"
                ));
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!({"QueryExecutionId":"running-query"})
                );
                self.stops.lock().unwrap().push(request);
                json!({})
            }
            _ => panic!("unexpected Athena operation {operation}"),
        };
        http::Response::builder()
            .status(200)
            .header("content-type", "application/x-amz-json-1.1")
            .body(Body::from(output.to_string()))
            .unwrap()
    }
}

fn running_athena(registry: &Arc<ServiceRegistry>) -> Arc<RunningAthena> {
    let handler = Arc::new(RunningAthena::default());
    registry.register_native(
        ServiceName::new("athena"),
        ServiceMetadata::new(AwsProtocol::Json11, Some("AmazonAthena")),
        handler.clone(),
    );
    handler
}

fn running_definition() -> Value {
    json!({"StartAt":"Query","States":{"Query":{
        "Type":"Task","Resource":"arn:aws:states:::athena:startQueryExecution.sync",
        "Parameters":{"QueryString":"SELECT COUNT(*) FROM events","WorkGroup":"primary","ResultConfiguration":{"OutputLocation":"s3://etl-data/results/"}},"End":true
    }}})
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expected Athena lifecycle transition");
}

#[tokio::test]
async fn athena_task_timeout_catches_timeout_and_cancels_query_once() {
    let registry = registry();
    let athena = running_athena(&registry);
    let mut definition = running_definition();
    definition["States"]["Query"]["TimeoutSeconds"] = json!(1);
    definition["States"]["Query"]["Catch"] =
        json!([{"ErrorEquals":["States.Timeout"],"ResultPath":"$.failure","Next":"Done"}]);
    definition["States"]["Done"] = json!({"Type":"Pass","End":true});
    let output = execute(&registry, "athena-task-timeout", definition).await;
    assert_eq!(output["failure"]["Error"], "States.Timeout");
    wait_until(|| !athena.stops.lock().unwrap().is_empty()).await;
    assert_eq!(athena.starts.load(Ordering::SeqCst), 1);
    assert_eq!(athena.stops.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn athena_execution_timeout_and_public_abort_each_cancel_query_once() {
    for abort in [false, true] {
        let registry = registry();
        let athena = running_athena(&registry);
        let mut definition = running_definition();
        if !abort {
            definition["TimeoutSeconds"] = json!(1);
        }
        let machine = api(
            &registry,
            "states",
            "CreateStateMachine",
            json!({
                "name":"athena-execution-cancel","definition":definition.to_string(),
                "roleArn":"arn:aws:iam::000000000000:role/etl"
            }),
        )
        .await;
        let execution = api(
            &registry,
            "states",
            "StartExecution",
            json!({"stateMachineArn":machine["stateMachineArn"]}),
        )
        .await;
        wait_until(|| athena.polls.load(Ordering::SeqCst) > 0).await;
        if abort {
            api(&registry, "states", "StopExecution", json!({"executionArn":execution["executionArn"],"error":"ClientAbort","cause":"fixture abort"})).await;
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let result = api(
                    &registry,
                    "states",
                    "DescribeExecution",
                    json!({"executionArn":execution["executionArn"]}),
                )
                .await;
                if result["status"] != "RUNNING" {
                    assert_eq!(
                        result["status"],
                        if abort { "ABORTED" } else { "TIMED_OUT" }
                    );
                    assert_eq!(
                        result["error"],
                        if abort {
                            "ClientAbort"
                        } else {
                            "States.Timeout"
                        }
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("execution terminates");
        wait_until(|| !athena.stops.lock().unwrap().is_empty()).await;
        assert_eq!(athena.starts.load(Ordering::SeqCst), 1);
        assert_eq!(athena.stops.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn express_rejects_athena_sync_before_starting_a_query() {
    let registry = registry();
    let athena = running_athena(&registry);
    let mut request = request(
        Method::POST,
        "/",
        json!({
            "name":"athena-express","type":"EXPRESS","definition":running_definition().to_string(),
            "roleArn":"arn:aws:iam::000000000000:role/etl"
        })
        .to_string(),
    );
    request.headers.insert(
        "x-amz-target",
        HeaderValue::from_static("AWSStepFunctions.CreateStateMachine"),
    );
    let response = registry
        .native_handler(&ServiceName::new("states"))
        .unwrap()
        .handle(request)
        .await;
    assert_eq!(response.status(), 400);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let error: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(error["__type"], "InvalidDefinition");
    assert_eq!(athena.starts.load(Ordering::SeqCst), 0);
    assert!(athena.stops.lock().unwrap().is_empty());
}
