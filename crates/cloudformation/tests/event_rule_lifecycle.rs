use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Method};
use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use serde_json::{json, Value};

async fn call(
    registry: &ServiceRegistry,
    service: &str,
    region: &str,
    operation: &str,
    body: Value,
) -> String {
    let mut headers = HeaderMap::new();
    let content_type = match service {
        "cloudformation" => "application/x-www-form-urlencoded",
        "events" => "application/x-amz-json-1.1",
        "sqs" => "application/x-amz-json-1.0",
        _ => panic!("unexpected test service {service}"),
    };
    headers.insert("content-type", content_type.parse().unwrap());
    let payload = if service == "cloudformation" {
        let mut params = vec![format!("Action={operation}")];
        for (key, value) in body.as_object().unwrap() {
            let value = value.as_str().unwrap();
            let encoded: String = value.bytes().map(|b| format!("%{b:02X}")).collect();
            params.push(format!("{key}={encoded}"));
        }
        params.join("&")
    } else {
        let prefix = if service == "events" {
            "AWSEvents"
        } else {
            "AmazonSQS"
        };
        headers.insert(
            "x-amz-target",
            format!("{prefix}.{operation}").parse().unwrap(),
        );
        body.to_string()
    };
    let response = registry
        .native_handler(&ServiceName::new(service))
        .unwrap()
        .handle(ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(payload),
            region: region.into(),
            account_id: "000000000000".into(),
            request_id: "accounting-event-rule-regression".into(),
        })
        .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        status.is_success(),
        "{service}.{operation}: {status}: {text}"
    );
    text
}

async fn wait_stack(registry: &ServiceRegistry, region: &str, expected: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let stack = call(registry, "cloudformation", region, "ListStacks", json!({})).await;
            if stack.contains(&format!("<StackStatus>{expected}</StackStatus>")) {
                return;
            }
            assert!(!stack.contains("_FAILED</StackStatus>"), "{stack}");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn accounting_rules_keep_distinct_names_crons_and_support_update_and_recovery_delete() {
    let registry = Arc::new(ServiceRegistry::new());
    locallycloud_sqs::register(&registry);
    locallycloud_eventbridge::register(&registry);
    locallycloud_cloudformation::register(&registry);
    let definitions = [
        (
            "LedgerMaintenanceStepFunctionsEventsRuleSchedule1",
            "cron(30 3 * * ? *)",
        ),
        (
            "LedgerMaintenanceStepFunctionsEventsRuleSchedule2",
            "cron(45 3 * * ? *)",
        ),
        (
            "InputAthenaStepFunctionsEventsRuleSchedule1",
            "cron(37 2 ? * TUE-SAT *)",
        ),
        (
            "InputAthenaStepFunctionsEventsRuleSchedule2",
            "cron(37 2 ? * TUE-SAT *)",
        ),
    ];
    for region in ["us-east-1", "us-east-2"] {
        let mut resources = serde_json::Map::new();
        resources.insert(
            "Queue".into(),
            json!({"Type":"AWS::SQS::Queue", "Properties":{"QueueName":"accounting-queue"}}),
        );
        for (logical, cron) in definitions {
            resources.insert(
                logical.into(),
                json!({"Type":"AWS::Events::Rule", "Properties":{
                    "ScheduleExpression":cron,
                    "Targets":[{"Id":"queue", "Arn":{"Fn::GetAtt":["Queue","Arn"]}}]
                }}),
            );
        }
        resources.insert(
            "ExplicitRule".into(),
            json!({"Type":"AWS::Events::Rule", "Properties":{
                "Name":"explicit-review-rule", "EventPattern":{"source":["review"]}
            }}),
        );
        let mut template = json!({"Resources":resources});
        call(
            &registry,
            "cloudformation",
            region,
            "CreateStack",
            json!({
                "StackName":"accounting-stubs", "TemplateBody":template.to_string()
            }),
        )
        .await;
        wait_stack(&registry, region, "CREATE_COMPLETE").await;
        let rules: Value =
            serde_json::from_str(&call(&registry, "events", region, "ListRules", json!({})).await)
                .unwrap();
        assert_eq!(rules["Rules"].as_array().unwrap().len(), 5);
        let mut names = BTreeMap::new();
        for (logical, cron) in definitions {
            let response = call(
                &registry,
                "cloudformation",
                region,
                "DescribeStackResource",
                json!({
                    "StackName":"accounting-stubs", "LogicalResourceId":logical
                }),
            )
            .await;
            let name = response
                .split_once("<PhysicalResourceId>")
                .unwrap()
                .1
                .split_once("</PhysicalResourceId>")
                .unwrap()
                .0
                .to_string();
            assert!(name.len() <= 64);
            assert_eq!(name.rsplit_once('-').unwrap().1.len(), 12);
            assert!(!names.values().any(|existing| existing == &name));
            let rule: Value = serde_json::from_str(
                &call(
                    &registry,
                    "events",
                    region,
                    "DescribeRule",
                    json!({"Name":name}),
                )
                .await,
            )
            .unwrap();
            assert_eq!(rule["ScheduleExpression"], cron);
            names.insert(logical, name);
        }
        assert!(rules["Rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["Name"] == "explicit-review-rule"));
        let first = definitions[0].0;
        template["Resources"][first]["Properties"]["ScheduleExpression"] =
            json!("cron(31 3 * * ? *)");
        call(
            &registry,
            "cloudformation",
            region,
            "UpdateStack",
            json!({
                "StackName":"accounting-stubs", "TemplateBody":template.to_string()
            }),
        )
        .await;
        wait_stack(&registry, region, "UPDATE_COMPLETE").await;
        for (logical, cron) in definitions {
            let rule: Value = serde_json::from_str(
                &call(
                    &registry,
                    "events",
                    region,
                    "DescribeRule",
                    json!({"Name":names[logical]}),
                )
                .await,
            )
            .unwrap();
            assert_eq!(
                rule["ScheduleExpression"],
                if logical == first {
                    "cron(31 3 * * ? *)"
                } else {
                    cron
                }
            );
        }
        // Remove one rule out of band: deletion must tolerate an already absent physical resource.
        let second = &names[definitions[1].0];
        call(
            &registry,
            "events",
            region,
            "RemoveTargets",
            json!({"Rule":second,"Ids":["queue"]}),
        )
        .await;
        call(
            &registry,
            "events",
            region,
            "DeleteRule",
            json!({"Name":second}),
        )
        .await;
        // Live discovery must also remove targets added after the template was deployed.
        call(
            &registry,
            "events",
            region,
            "PutTargets",
            json!({"Rule":names[first],"Targets":[{
                "Id":"extra", "Arn":format!("arn:aws:sqs:{region}:000000000000:accounting-queue")
            }]}),
        )
        .await;
        call(
            &registry,
            "cloudformation",
            region,
            "DeleteStack",
            json!({"StackName":"accounting-stubs"}),
        )
        .await;
        wait_stack(&registry, region, "DELETE_COMPLETE").await;
        let rules: Value =
            serde_json::from_str(&call(&registry, "events", region, "ListRules", json!({})).await)
                .unwrap();
        assert!(rules["Rules"].as_array().unwrap().is_empty());
        let queues: Value =
            serde_json::from_str(&call(&registry, "sqs", region, "ListQueues", json!({})).await)
                .unwrap();
        assert!(queues
            .get("QueueUrls")
            .and_then(Value::as_array)
            .is_none_or(|q| q.is_empty()));
    }
}
