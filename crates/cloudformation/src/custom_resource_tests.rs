//! Contract tests: stack orchestration, native S3 callbacks, and a controlled Lambda provider.
use super::*;
use serde_json::json;
use std::sync::Mutex;

struct Provider {
    registry: Weak<ServiceRegistry>,
    requests: Arc<Mutex<Vec<Value>>>,
    override_mode: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl NativeHandler for Provider {
    async fn handle(&self, request: ServiceRequest) -> Response {
        assert_eq!(
            request.headers.get("x-amz-invocation-type").unwrap(),
            "Event"
        );
        let event: Value = serde_json::from_slice(&request.body).unwrap();
        self.requests.lock().unwrap().push(event.clone());
        let props = &event["ResourceProperties"];
        let mode = self
            .override_mode
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| props["Mode"].as_str().unwrap_or("Success").into());
        let mode = if mode == "DeleteFailed" && event["RequestType"] == "Delete" {
            "Failed"
        } else {
            &mode
        };
        if mode == "ComputeUnavailable" {
            return Response::builder()
                .status(501)
                .body(Body::from(
                    json!({"Message":"Lambda invocation is disabled: install crun or youki"})
                        .to_string(),
                ))
                .unwrap();
        }
        if mode != "Timeout" {
            let mut response = json!({
                "Status": if mode == "Failed" { "FAILED" } else { "SUCCESS" },
                "Reason": "provider diagnostic", "StackId": event["StackId"],
                "RequestId": event["RequestId"], "LogicalResourceId": event["LogicalResourceId"],
                "PhysicalResourceId": props["Identity"].as_str().unwrap_or("physical-one"),
                "Data": {"Answer": "from-provider"}
            });
            if mode == "Mismatch" {
                response["RequestId"] = json!("wrong");
            }
            let uri: http::Uri = event["ResponseURL"].as_str().unwrap().parse().unwrap();
            let mut headers = http::HeaderMap::new();
            headers.insert("host", uri.authority().unwrap().as_str().parse().unwrap());
            let callback = ServiceRequest {
                method: Method::PUT,
                uri,
                headers,
                body: Bytes::from(response.to_string()),
                region: request.region,
                account_id: request.account_id,
                request_id: "callback".into(),
            };
            let result = self
                .registry
                .upgrade()
                .unwrap()
                .native_handler(&ServiceName::new("s3"))
                .unwrap()
                .handle(callback)
                .await;
            assert_eq!(result.status(), 200);
        }
        Response::new(Body::from("{}"))
    }
}

type Fixture = (
    Arc<ServiceRegistry>,
    CfnHandler,
    Arc<Mutex<Vec<Value>>>,
    Arc<Mutex<Option<String>>>,
);

fn fixture() -> Fixture {
    let registry = Arc::new(ServiceRegistry::new());
    locallycloud_s3::register(&registry);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let override_mode = Arc::new(Mutex::new(None));
    registry.register_native(
        ServiceName::new("lambda"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        Arc::new(Provider {
            registry: Arc::downgrade(&registry),
            requests: requests.clone(),
            override_mode: override_mode.clone(),
        }),
    );
    let handler = CfnHandler::new(Arc::downgrade(&registry));
    (registry, handler, requests, override_mode)
}

fn template(mode: &str, identity: &str, revision: u32) -> String {
    json!({"Resources":{"Role":{"Type":"Custom::ApiGatewayAccountRole", "Properties":{
        "ServiceToken":"arn:aws:lambda:us-east-1:000000000000:function:provider",
        "ServiceTimeout":1,"Mode":mode,"Identity":identity,"Revision":revision
    }}},"Outputs":{"Id":{"Value":{"Ref":"Role"}},"Answer":{"Value":{"Fn::GetAtt":["Role","Answer"]}}}}).to_string()
}

async fn operation(handler: &CfnHandler, action: &str, body: Option<String>) {
    let mut pairs = vec![format!("Action={action}"), "StackName=custom-stack".into()];
    if let Some(body) = body {
        pairs.push(format!("TemplateBody={}", encode(&body)));
    }
    let query = Query::parse(pairs.join("&").as_bytes());
    handler
        .dispatch(action, &query, "us-east-1", "000000000000")
        .await
        .unwrap();
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[tokio::test]
async fn custom_resource_stack_lifecycle_and_replacement_use_provider_identity() {
    let (_registry, handler, requests, _control) = fixture();
    operation(
        &handler,
        "CreateStack",
        Some(template("Success", "physical-one", 1)),
    )
    .await;
    let stack = handler
        .store
        .get("000000000000", "us-east-1", "custom-stack")
        .unwrap();
    assert_eq!(stack.status, StackStatus::CreateComplete);
    assert_eq!(stack.resources[0].physical_id, "physical-one");
    assert_eq!(
        stack
            .outputs
            .iter()
            .find(|o| o.key == "Answer")
            .unwrap()
            .value,
        "from-provider"
    );
    operation(
        &handler,
        "UpdateStack",
        Some(template("Success", "physical-two", 2)),
    )
    .await;
    let stack = handler
        .store
        .get("000000000000", "us-east-1", "custom-stack")
        .unwrap();
    assert_eq!(stack.status, StackStatus::UpdateComplete);
    assert_eq!(stack.resources[0].physical_id, "physical-two");
    operation(&handler, "DeleteStack", None).await;
    let events = requests.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .map(|e| e["RequestType"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["Create", "Update", "Delete", "Delete"]
    );
    assert_eq!(events[1]["PhysicalResourceId"], "physical-one");
    assert_eq!(events[1]["OldResourceProperties"]["Revision"], 1);
    assert_eq!(events[2]["PhysicalResourceId"], "physical-one");
    assert_eq!(events[3]["PhysicalResourceId"], "physical-two");
    assert!(events.iter().all(|e| e["StackId"] == stack.stack_id));
}

#[tokio::test]
async fn failed_missing_and_mismatched_provider_callbacks_fail_stack() {
    for mode in ["Failed", "Timeout", "Mismatch", "ComputeUnavailable"] {
        let (_registry, handler, _requests, _control) = fixture();
        operation(
            &handler,
            "CreateStack",
            Some(template(mode, "physical-one", 1)),
        )
        .await;
        let stack = handler
            .store
            .get("000000000000", "us-east-1", "custom-stack")
            .unwrap();
        assert_eq!(stack.status, StackStatus::RollbackComplete, "{mode}");
        assert!(stack
            .events
            .iter()
            .any(|e| e.logical_id == "Role" && e.status == "CREATE_FAILED"));
        assert!(!stack.events.iter().any(|e| e.status == "CREATE_COMPLETE"));
        if mode == "ComputeUnavailable" {
            assert!(stack.events.iter().any(|event| event
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("install crun or youki"))));
        }
    }
}

#[test]
fn accounting_template_custom_type_is_admitted_and_invalid_contracts_rejected() {
    Template::parse(&template("Success", "id", 1)).unwrap();
    let generic = template("Success", "id", 1).replace(
        "Custom::ApiGatewayAccountRole",
        "AWS::CloudFormation::CustomResource",
    );
    Template::parse(&generic).unwrap();
    for timeout in [0, 3601] {
        let invalid = template("Success", "id", 1).replace(
            "\"ServiceTimeout\":1",
            &format!("\"ServiceTimeout\":{timeout}"),
        );
        assert!(Template::parse(&invalid).is_err());
    }
}

#[tokio::test]
async fn provider_update_and_delete_failures_are_visible_and_delete_can_retry() {
    for mode in ["Failed", "Timeout"] {
        let (_registry, handler, requests, control) = fixture();
        operation(
            &handler,
            "CreateStack",
            Some(template("Success", "original", 1)),
        )
        .await;
        *control.lock().unwrap() = Some(mode.into());
        operation(
            &handler,
            "UpdateStack",
            Some(template("Success", "updated", 2)),
        )
        .await;
        let stack = handler
            .store
            .get("000000000000", "us-east-1", "custom-stack")
            .unwrap();
        assert_eq!(stack.status, StackStatus::UpdateRollbackFailed);
        assert_eq!(stack.resources[0].physical_id, "original");
        operation(&handler, "DeleteStack", None).await;
        let stack = handler
            .store
            .get("000000000000", "us-east-1", "custom-stack")
            .unwrap();
        assert_eq!(stack.status, StackStatus::DeleteFailed);
        assert_eq!(stack.resources[0].physical_id, "original");
        assert!(stack
            .events
            .iter()
            .any(|e| e.status == "DELETE_FAILED" && e.logical_id == "Role"));
        *control.lock().unwrap() = None;
        operation(&handler, "DeleteStack", None).await;
        let events = requests.lock().unwrap();
        assert_eq!(events.last().unwrap()["RequestType"], "Delete");
        assert_eq!(events.last().unwrap()["PhysicalResourceId"], "original");
        assert_eq!(events.last().unwrap()["ResourceProperties"]["Revision"], 1);
    }
}

#[tokio::test]
async fn rollback_delete_failure_preserves_provider_dependencies_for_retry() {
    let (_registry, handler, _requests, control) = fixture();
    let mut value: Value =
        serde_json::from_str(&template("DeleteFailed", "physical-one", 1)).unwrap();
    value["Resources"]["Bucket"] = json!({"Type":"AWS::S3::Bucket"});
    value["Resources"]["Role"]["Properties"]["Dependency"] = json!({"Ref":"Bucket"});
    value["Resources"]["ZFailure"] = json!({"Type":"Custom::Contract", "DependsOn":"Role", "Properties":{
        "ServiceToken":"arn:aws:lambda:us-east-1:000000000000:function:provider", "ServiceTimeout":1,"Mode":"Failed"
    }});
    operation(&handler, "CreateStack", Some(value.to_string())).await;
    let stack = handler
        .store
        .get("000000000000", "us-east-1", "custom-stack")
        .unwrap();
    assert_eq!(stack.status, StackStatus::RollbackFailed);
    for logical in ["Role", "Bucket"] {
        assert_eq!(
            stack
                .resources
                .iter()
                .find(|r| r.logical_id == logical)
                .unwrap()
                .status,
            "DELETE_FAILED"
        );
    }
    *control.lock().unwrap() = Some("Success".into());
    operation(&handler, "DeleteStack", None).await;
    assert_eq!(
        handler
            .store
            .find("000000000000", "us-east-1", &stack.stack_id)
            .unwrap()
            .status,
        StackStatus::DeleteComplete
    );
}
