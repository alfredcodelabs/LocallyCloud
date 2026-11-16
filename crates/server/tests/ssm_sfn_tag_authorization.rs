//! Tag conditions use the requested tags and the destination's current resource tags.
#![cfg(feature = "services")]

use std::{collections::BTreeMap, sync::Arc};

use axum::body::to_bytes;
use http::{HeaderMap, Method};
use locallycloud_core::{
    handler::ServiceRequest,
    registry::{ServiceName, ServiceRegistry},
};
use locallycloud_iam_sts::{
    enforcement::EnforcementMode,
    model::{AccessKey, IamRole, IamUser},
    store::IamStore,
    sts::SessionStore,
};
use serde_json::{json, Value};

const ACCOUNT: &str = "000000000000";
const ADMIN: &str = "AKIATAGADMIN000000001";
const CLIENT: &str = "AKIATAGCLIENT00000001";
const ROLE: &str = "arn:aws:iam::000000000000:role/states-execution";

struct Fixture {
    registry: Arc<ServiceRegistry>,
    iam: Arc<IamStore>,
}

impl Fixture {
    fn new() -> Self {
        let registry = ServiceRegistry::with_known_services();
        let iam = Arc::new(IamStore::new());
        for (name, key) in [("admin", ADMIN), ("client", CLIENT)] {
            iam.create_user(
                ACCOUNT,
                IamUser {
                    user_name: name.into(),
                    user_id: format!("AIDA{name}"),
                    arn: format!("arn:aws:iam::{ACCOUNT}:user/{name}"),
                    path: "/".into(),
                    create_date: "2026-01-01T00:00:00Z".into(),
                    tags: BTreeMap::new(),
                    attached_policies: vec![],
                    groups: vec![],
                    permission_boundary: None,
                    inline_policies: BTreeMap::from([(
                        "permissions".into(),
                        json!({"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}})
                            .to_string(),
                    )]),
                    access_keys: vec![AccessKey {
                        access_key_id: key.into(),
                        secret_access_key: "secret".into(),
                        status: "Active".into(),
                        create_date: "2026-01-01T00:00:00Z".into(),
                    }],
                },
            );
        }
        iam.create_role(ACCOUNT, IamRole {
            role_name:"states-execution".into(),role_id:"AROASTATESEXECUTION".into(),arn:ROLE.into(),path:"/".into(),
            create_date:"2026-01-01T00:00:00Z".into(),description:None,max_session_duration:3600,tags:BTreeMap::new(),
            attached_policies:vec![],inline_policies:BTreeMap::new(),permission_boundary:None,
            assume_role_policy_document:json!({"Statement":{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}}).to_string(),
        });
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            iam.clone(),
            Arc::new(SessionStore::new()),
            EnforcementMode::Strict,
        );
        locallycloud_ssm::register(&registry);
        locallycloud_stepfunctions::register(&registry);
        Self { registry, iam }
    }

    fn policy(&self, statements: Value) {
        assert!(self.iam.update_user(ACCOUNT, "client", |user| {
            user.inline_policies = BTreeMap::from([(
                "permissions".into(),
                json!({"Statement":statements}).to_string(),
            )]);
        }));
    }

    async fn call(&self, key: &str, service: &str, operation: &str, body: Value) -> (u16, Value) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            "application/x-amz-json-1.1".parse().unwrap(),
        );
        let target = match service {
            "ssm" => "AmazonSSM",
            "states" => "AWSStepFunctions",
            _ => unreachable!(),
        };
        headers.insert(
            "x-amz-target",
            format!("{target}.{operation}").parse().unwrap(),
        );
        headers.insert(
            "authorization",
            format!("AWS4-HMAC-SHA256 Credential={key}/20261116/us-east-1/{service}/aws4_request")
                .parse()
                .unwrap(),
        );
        // Native fixture models cryptographically verified ingress; no client header is trusted on wire.
        headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        let response = self
            .registry
            .native_handler(&ServiceName::new(service))
            .unwrap()
            .handle(ServiceRequest {
                method: Method::POST,
                uri: "/".parse().unwrap(),
                headers,
                body: body.to_string().into(),
                region: "us-east-1".into(),
                account_id: ACCOUNT.into(),
                request_id: "tag-auth".into(),
            })
            .await;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn ok(&self, key: &str, service: &str, operation: &str, body: Value) -> Value {
        let (status, value) = self.call(key, service, operation, body).await;
        assert_eq!(status, 200, "{operation}: {value}");
        value
    }

    async fn denied(&self, service: &str, operation: &str, body: Value) {
        let (status, value) = self.call(CLIENT, service, operation, body).await;
        assert_eq!(status, 403, "{operation}: {value}");
        assert!(value["__type"]
            .as_str()
            .unwrap()
            .ends_with("AccessDeniedException"));
    }

    async fn machine(&self, name: &str, env: &str) -> String {
        self.ok(ADMIN,"states","CreateStateMachine",json!({"name":name,"roleArn":ROLE,"definition":json!({"StartAt":"Done","States":{"Done":{"Type":"Pass","End":true}}}).to_string(),"tags":[{"key":"env","value":env}]})).await["stateMachineArn"].as_str().unwrap().into()
    }
}

#[tokio::test]
async fn ssm_resource_tags_enforce_both_aws_and_ssm_prefixes_without_mutation() {
    let f = Fixture::new();
    for (name, env) in [("/protected", "prod"), ("/open", "dev")] {
        f.ok(ADMIN,"ssm","PutParameter",json!({"Name":name,"Value":"original","Type":"String","Tags":[{"Key":"env","Value":env}]})).await;
    }
    for condition in ["aws:ResourceTag/env", "ssm:resourceTag/env"] {
        f.policy(json!([
            {"Effect":"Allow","Action":"ssm:*","Resource":"*"},
            {"Effect":"Deny","Action":["ssm:GetParameter","ssm:DeleteParameter","ssm:PutParameter"],"Resource":"*","Condition":{"StringEquals":{condition:"prod"}}}
        ]));
        f.denied("ssm", "GetParameter", json!({"Name":"/protected"}))
            .await;
        f.denied("ssm", "DeleteParameter", json!({"Name":"/protected"}))
            .await;
        f.denied(
            "ssm",
            "PutParameter",
            json!({"Name":"/protected","Value":"changed","Type":"String","Overwrite":true}),
        )
        .await;
        assert_eq!(
            f.ok(ADMIN, "ssm", "GetParameter", json!({"Name":"/protected"}))
                .await["Parameter"]["Value"],
            "original"
        );
        f.ok(CLIENT, "ssm", "GetParameter", json!({"Name":"/open"}))
            .await;
    }
    f.policy(json!({"Effect":"Allow","Action":"ssm:GetParameter","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/env":"prod"}}}));
    f.ok(CLIENT, "ssm", "GetParameter", json!({"Name":"/protected"}))
        .await;
    f.denied("ssm", "GetParameter", json!({"Name":"/open"}))
        .await;
}

#[tokio::test]
async fn ssm_request_tags_and_tag_keys_deny_before_creating_or_changing_resources() {
    let f = Fixture::new();
    f.policy(json!([
        {"Effect":"Allow","Action":"ssm:*","Resource":"*"},
        {"Effect":"Deny","Action":["ssm:PutParameter","ssm:AddTagsToResource"],"Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/env":"prod"}}},
        {"Effect":"Deny","Action":"ssm:RemoveTagsFromResource","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":"protected"}}}
    ]));
    f.denied(
        "ssm",
        "PutParameter",
        json!({"Name":"/denied","Value":"v","Tags":[{"Key":"env","Value":"prod"}]}),
    )
    .await;
    assert_eq!(
        f.call(ADMIN, "ssm", "GetParameter", json!({"Name":"/denied"}))
            .await
            .0,
        400
    );
    f.ok(CLIENT,"ssm","PutParameter",json!({"Name":"/allowed","Value":"v","Tags":[{"Key":"env","Value":"dev"},{"Key":"protected","Value":"yes"}]})).await;
    f.denied("ssm","AddTagsToResource",json!({"ResourceType":"Parameter","ResourceId":"/allowed","Tags":[{"Key":"env","Value":"prod"}]})).await;
    f.denied(
        "ssm",
        "RemoveTagsFromResource",
        json!({"ResourceType":"Parameter","ResourceId":"/allowed","TagKeys":["env","protected"]}),
    )
    .await;
    let tags = f
        .ok(
            ADMIN,
            "ssm",
            "ListTagsForResource",
            json!({"ResourceType":"Parameter","ResourceId":"/allowed"}),
        )
        .await;
    assert_eq!(
        tags["TagList"],
        json!([{"Key":"env","Value":"dev"},{"Key":"protected","Value":"yes"}])
    );
    f.ok(
        CLIENT,
        "ssm",
        "RemoveTagsFromResource",
        json!({"ResourceType":"Parameter","ResourceId":"/allowed","TagKeys":["env"]}),
    )
    .await;
}

#[tokio::test]
async fn states_existing_tags_protect_machines_activities_and_execution_access() {
    let f = Fixture::new();
    let machine = f.machine("protected", "prod").await;
    let activity = f
        .ok(
            ADMIN,
            "states",
            "CreateActivity",
            json!({"name":"protected","tags":[{"key":"env","value":"prod"}]}),
        )
        .await["activityArn"]
        .as_str()
        .unwrap()
        .to_owned();
    let execution = f
        .ok(
            ADMIN,
            "states",
            "StartExecution",
            json!({"stateMachineArn":machine,"name":"run"}),
        )
        .await["executionArn"]
        .as_str()
        .unwrap()
        .to_owned();
    f.policy(json!([
        {"Effect":"Allow","Action":"states:*","Resource":"*"},
        {"Effect":"Deny","Action":["states:DeleteStateMachine","states:DeleteActivity","states:DescribeExecution","states:StartExecution"],"Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/env":"prod"}}}
    ]));
    f.denied(
        "states",
        "DeleteStateMachine",
        json!({"stateMachineArn":machine}),
    )
    .await;
    f.denied("states", "DeleteActivity", json!({"activityArn":activity}))
        .await;
    f.denied(
        "states",
        "DescribeExecution",
        json!({"executionArn":execution}),
    )
    .await;
    f.denied(
        "states",
        "StartExecution",
        json!({"stateMachineArn":machine,"name":"denied"}),
    )
    .await;
    f.ok(
        ADMIN,
        "states",
        "DescribeStateMachine",
        json!({"stateMachineArn":machine}),
    )
    .await;
    f.ok(
        ADMIN,
        "states",
        "DescribeActivity",
        json!({"activityArn":activity}),
    )
    .await;
    assert_eq!(
        f.ok(
            ADMIN,
            "states",
            "ListExecutions",
            json!({"stateMachineArn":machine})
        )
        .await["executions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    f.policy(json!({"Effect":"Allow","Action":"states:DescribeStateMachine","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/env":"prod"}}}));
    f.ok(
        CLIENT,
        "states",
        "DescribeStateMachine",
        json!({"stateMachineArn":machine}),
    )
    .await;
}

#[tokio::test]
async fn states_request_tags_and_tag_keys_reject_mutations_atomically() {
    let f = Fixture::new();
    f.policy(json!([
        {"Effect":"Allow","Action":"states:*","Resource":"*"},
        {"Effect":"Deny","Action":["states:CreateActivity","states:TagResource"],"Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/env":"prod"}}},
        {"Effect":"Deny","Action":"states:UntagResource","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":"protected"}}}
    ]));
    f.denied(
        "states",
        "CreateActivity",
        json!({"name":"denied","tags":[{"key":"env","value":"prod"}]}),
    )
    .await;
    assert!(
        f.ok(ADMIN, "states", "ListActivities", json!({})).await["activities"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let arn=f.ok(CLIENT,"states","CreateActivity",json!({"name":"allowed","tags":[{"key":"env","value":"dev"},{"key":"protected","value":"yes"}]})).await["activityArn"].as_str().unwrap().to_owned();
    f.denied(
        "states",
        "TagResource",
        json!({"resourceArn":arn,"tags":[{"key":"env","value":"prod"}]}),
    )
    .await;
    f.denied(
        "states",
        "UntagResource",
        json!({"resourceArn":arn,"tagKeys":["env","protected"]}),
    )
    .await;
    assert_eq!(
        f.ok(
            ADMIN,
            "states",
            "ListTagsForResource",
            json!({"resourceArn":arn})
        )
        .await["tags"],
        json!([{"key":"env","value":"dev"},{"key":"protected","value":"yes"}])
    );
    f.ok(
        CLIENT,
        "states",
        "UntagResource",
        json!({"resourceArn":arn,"tagKeys":["env"]}),
    )
    .await;
}

#[tokio::test]
async fn tagged_state_creation_requires_tag_resource_and_permitted_request_tags() {
    let f = Fixture::new();
    f.policy(json!([
        {"Effect":"Allow","Action":["states:CreateActivity","states:CreateStateMachine","iam:PassRole"],"Resource":"*"},
        {"Effect":"Deny","Action":"states:TagResource","Resource":"*"}
    ]));
    f.denied(
        "states",
        "CreateActivity",
        json!({"name":"denied","tags":[{"key":"env","value":"dev"}]}),
    )
    .await;
    f.denied("states", "CreateStateMachine", json!({"name":"denied","roleArn":ROLE,"definition":json!({"StartAt":"Done","States":{"Done":{"Type":"Pass","End":true}}}).to_string(),"tags":[{"key":"env","value":"dev"}]})).await;
    assert!(
        f.ok(ADMIN, "states", "ListActivities", json!({})).await["activities"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        f.ok(ADMIN, "states", "ListStateMachines", json!({})).await["stateMachines"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    f.policy(json!({"Effect":"Allow","Action":["states:CreateActivity","states:TagResource","ssm:PutParameter"],"Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/env":"dev"}}}));
    f.ok(
        CLIENT,
        "states",
        "CreateActivity",
        json!({"name":"allowed","tags":[{"key":"env","value":"dev"}]}),
    )
    .await;
    f.denied(
        "states",
        "CreateActivity",
        json!({"name":"denied","tags":[{"key":"env","value":"prod"}]}),
    )
    .await;
    f.ok(
        CLIENT,
        "ssm",
        "PutParameter",
        json!({"Name":"/allowed","Value":"v","Tags":[{"Key":"env","Value":"dev"}]}),
    )
    .await;
    f.denied(
        "ssm",
        "PutParameter",
        json!({"Name":"/denied","Value":"v","Tags":[{"Key":"env","Value":"prod"}]}),
    )
    .await;
}
