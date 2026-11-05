//! CloudFormation must provision response mappings before snapshotting a deployment.
use std::time::Duration;

use locallycloud_core::{
    config::LocallyCloudConfig, registry::ServiceRegistry, server::LocallyCloudServer,
};
use serde_json::{json, Value};

struct Fixture {
    endpoint: String,
    client: reqwest::Client,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

impl Fixture {
    async fn cfn(&self, action: &str, fields: &[(&str, String)]) -> String {
        let mut body = format!("Action={action}");
        for (key, value) in fields {
            body.push('&');
            body.push_str(key);
            body.push('=');
            for byte in value.bytes() {
                body.push_str(&format!("%{byte:02X}"));
            }
        }
        let response = self.client.post(&self.endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=test/20261105/us-east-1/cloudformation/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000")
            .body(body).send().await.unwrap();
        let status = response.status();
        let text = response.text().await.unwrap();
        assert!(status.is_success(), "{action}: {status}: {text}");
        text
    }

    async fn stack_status(&self, expected: &str) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let text = self
                    .cfn(
                        "DescribeStacks",
                        &[("StackName", "response-mapping".into())],
                    )
                    .await;
                if text.contains(&format!("<StackStatus>{expected}</StackStatus>")) {
                    return;
                }
                assert!(!text.contains("_FAILED</StackStatus>"), "{text}");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn physical_id(&self, logical: &str) -> String {
        let response = self
            .cfn(
                "DescribeStackResource",
                &[
                    ("StackName", "response-mapping".into()),
                    ("LogicalResourceId", logical.into()),
                ],
            )
            .await;
        response
            .split_once("<PhysicalResourceId>")
            .unwrap()
            .1
            .split_once("</PhysicalResourceId>")
            .unwrap()
            .0
            .to_owned()
    }

    async fn get_method(&self, api: &str, resource: &str) -> Value {
        let response = self.client.get(format!("{}/restapis/{api}/resources/{resource}/methods/GET", self.endpoint))
            .header("authorization", "AWS4-HMAC-SHA256 Credential=test/20261105/us-east-1/apigateway/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000")
            .send().await.unwrap();
        assert!(response.status().is_success());
        response.json().await.unwrap()
    }

    async fn invoke(&self, api: &str, status: u16) {
        let response = self
            .client
            .get(format!(
                "{}/restapis/{api}/test/_user_request_/flows?limit=5",
                self.endpoint
            ))
            .header("host", "fixture.execute-api.localhost")
            .header("content-type", "application/json")
            .body(json!({"marker":"O'Reilly"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        let value: Value = response.json().await.unwrap();
        assert_eq!(value["body"]["marker"], "O'Reilly");
        assert_eq!(value["params"]["querystring"]["limit"], "5");
        assert!(value["params"].get("header").is_none());
    }
}

fn template(updated: bool) -> Value {
    let request =
        include_str!("../../apigateway/tests/fixtures/accounting-stepfunctions-request.vtl")
            .replace("\"0\"", "\"000000000000\"");
    let name = request.lines().next().unwrap().split('"').nth(1).unwrap();
    let mut response =
        include_str!("../../apigateway/tests/fixtures/accounting-stepfunctions-response.vtl")
            .to_owned();
    if updated {
        response.push_str("#set($context.responseOverride.status = 202)");
    }
    let alternate = if updated { "409" } else { "400" };
    json!({"Resources":{
        "Workflow":{"Type":"AWS::StepFunctions::StateMachine","Properties":{
            "StateMachineName":name,"StateMachineType":"EXPRESS",
            "RoleArn":"arn:aws:iam::000000000000:role/response-fixture",
            "Definition":{"StartAt":"Echo","States":{"Echo":{"Type":"Pass","Parameters":{"statusCode":201,"body.$":"$"},"End":true}}}
        }},
        "Api":{"Type":"AWS::ApiGateway::RestApi","Properties":{"Name":"response-fixture"}},
        "Resource":{"Type":"AWS::ApiGateway::Resource","Properties":{"RestApiId":{"Ref":"Api"},"ParentId":{"Fn::GetAtt":["Api","RootResourceId"]},"PathPart":"flows"}},
        "Method":{"Type":"AWS::ApiGateway::Method","DependsOn":"Workflow","Properties":{
            "RestApiId":{"Ref":"Api"},"ResourceId":{"Ref":"Resource"},"HttpMethod":"GET","AuthorizationType":"NONE",
            "MethodResponses":[{"StatusCode":"200","ResponseParameters":{"method.response.header.Access-Control-Allow-Origin":false},"ResponseModels":{"application/json":"Empty"}},{"StatusCode":alternate}],
            "Integration":{"Type":"AWS","IntegrationHttpMethod":"POST","Uri":"arn:aws:apigateway:us-east-1:states:action/StartSyncExecution",
                "RequestTemplates":{"application/json":request},
                "IntegrationResponses":[{"StatusCode":200,"SelectionPattern":"","ResponseParameters":{"method.response.header.Access-Control-Allow-Origin":"'*'"},"ResponseTemplates":{"application/json":response}},{"StatusCode":alternate,"SelectionPattern":alternate}]
            }
        }},
        "Deployment":{"Type":"AWS::ApiGateway::Deployment","DependsOn":"Method","Properties":{"RestApiId":{"Ref":"Api"},"StageName":"test","Description":if updated {"updated"} else {"initial"}}}
    }})
}

#[tokio::test]
async fn cfn_method_responses_reach_real_sync_workflow_on_create_and_update() {
    let registry = ServiceRegistry::with_known_services();
    locallycloud_stepfunctions::register(&registry);
    locallycloud_apigateway::register(&registry);
    locallycloud_cloudformation::register(&registry);
    let config = LocallyCloudConfig::resolve(&|name| match name {
        "LOCALLYCLOUD_UI" => Some("off".into()),
        "LOCALLYCLOUD_LEGACY_BACKEND_URL" => Some("http://127.0.0.1:1".into()),
        _ => None,
    })
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(LocallyCloudServer::new(config, registry).run_on_listener(
        listener,
        async {
            let _ = stopped.await;
        },
        || {},
    ));
    let mut fixture = Fixture {
        endpoint,
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap(),
        shutdown: Some(shutdown),
    };
    fixture
        .cfn(
            "CreateStack",
            &[
                ("StackName", "response-mapping".into()),
                ("TemplateBody", template(false).to_string()),
            ],
        )
        .await;
    fixture.stack_status("CREATE_COMPLETE").await;
    let api = fixture.physical_id("Api").await;
    let resource = fixture.physical_id("Resource").await;
    let method = fixture.get_method(&api, &resource).await;
    assert_eq!(
        method["methodResponses"]["200"]["responseModels"]["application/json"],
        "Empty"
    );
    assert!(method["methodResponses"].get("400").is_some());
    assert_eq!(
        method["methodIntegration"]["integrationResponses"]["200"]["selectionPattern"],
        ""
    );
    assert!(method["methodIntegration"]["integrationResponses"]
        .get("400")
        .is_some());
    fixture.invoke(&api, 201).await;
    fixture
        .cfn(
            "UpdateStack",
            &[
                ("StackName", "response-mapping".into()),
                ("TemplateBody", template(true).to_string()),
            ],
        )
        .await;
    fixture.stack_status("UPDATE_COMPLETE").await;
    let method = fixture.get_method(&api, &resource).await;
    assert!(method["methodResponses"].get("400").is_none());
    assert!(method["methodResponses"].get("409").is_some());
    assert!(method["methodIntegration"]["integrationResponses"]
        .get("400")
        .is_none());
    assert!(method["methodIntegration"]["integrationResponses"]
        .get("409")
        .is_some());
    fixture.invoke(&api, 202).await;
    fixture
        .cfn("DeleteStack", &[("StackName", "response-mapping".into())])
        .await;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let response = fixture.cfn("ListStacks", &[]).await;
            if response.contains("<StackStatus>DELETE_COMPLETE</StackStatus>") {
                break;
            }
            assert!(!response.contains("DELETE_FAILED"), "{response}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    fixture.shutdown.take().unwrap().send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
