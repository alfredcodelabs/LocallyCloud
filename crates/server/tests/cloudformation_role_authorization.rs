//! Real CloudFormation dispatch must preserve the caller's IAM restrictions.
#![cfg(feature = "services")]
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{HeaderMap, Method};
use locallycloud_core::{
    handler::ServiceRequest,
    integration::InternalDispatcher,
    proxy::{LegacyHealth, ProxyConfig},
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
const KEY: &str = "AKIACFNCREATOR000001";
const REGION: &str = "us-east-1";
const CFN_ROLE: &str = "arn:aws:iam::000000000000:role/cfn-execution";

#[tokio::test]
async fn target_permissions_do_not_replace_cloudformation_create_stack_permission() {
    let fixture = Fixture::new();
    fixture.iam.update_user(ACCOUNT, "creator", |user| user.inline_policies = [(
        "targets-only".into(), json!({"Statement":{"Effect":"Allow","Action":["lambda:*","events:*","scheduler:*","iam:PassRole","cloudformation:DescribeStacks"],"Resource":"*"}}).to_string(),
    )].into());
    for (index, (kind, properties)) in resources("no-stack-permission").into_iter().enumerate() {
        let template = json!({"Resources":{"Resource":{"Type":kind,"Properties":properties}}});
        let name = format!("no-permission-{index}");
        let (status, body) = fixture
            .query(
                KEY,
                "cloudformation",
                "CreateStack",
                &[
                    ("StackName", name.clone()),
                    ("TemplateBody", template.to_string()),
                ],
            )
            .await;
        assert_eq!(status, 403, "{body}");
        let (status, body) = fixture
            .query(
                KEY,
                "cloudformation",
                "DescribeStacks",
                &[("StackName", name)],
            )
            .await;
        assert_eq!(status, 400, "{body}");
        assert!(!fixture.exists(&kind, "no-stack-permission").await);
    }
}

struct Fixture {
    registry: Arc<ServiceRegistry>,
    iam: Arc<IamStore>,
    lambda: Arc<locallycloud_lambda::LambdaHandler>,
}

fn policy(deny_pass: bool) -> BTreeMap<String, String> {
    let mut statements = vec![json!({"Effect":"Allow","Action":"*","Resource":"*"})];
    if deny_pass {
        statements.push(json!({"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}));
    }
    [(
        "permissions".into(),
        json!({"Statement":statements}).to_string(),
    )]
    .into()
}

fn role(name: &str, path: &str, service: &str, deny_pass: bool) -> IamRole {
    IamRole {
        role_name: name.into(), role_id: format!("AROA{name}"),
        arn: format!("arn:aws:iam::{ACCOUNT}:role{path}{name}"), path: path.into(),
        create_date: "2026-01-01T00:00:00Z".into(),
        assume_role_policy_document: json!({"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":service}},{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:user/creator")}}]}).to_string(),
        description: None, max_session_duration: 3600, tags: BTreeMap::new(),
        attached_policies: vec![], inline_policies: policy(deny_pass), permission_boundary: None,
    }
}

fn form(params: &[(&str, String)]) -> String {
    fn encode(value: &str) -> String {
        value
            .bytes()
            .map(|byte| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    char::from(byte).to_string()
                }
                _ => format!("%{byte:02X}"),
            })
            .collect()
    }
    params
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn xml_value<'a>(xml: &'a str, name: &str) -> &'a str {
    xml.split_once(&format!("<{name}>"))
        .unwrap()
        .1
        .split_once(&format!("</{name}>"))
        .unwrap()
        .0
}

impl Fixture {
    fn new() -> Self {
        let registry = ServiceRegistry::with_known_services();
        let iam = Arc::new(IamStore::new());
        iam.create_user(
            ACCOUNT,
            IamUser {
                user_name: "creator".into(),
                user_id: "AIDACREATOR".into(),
                arn: format!("arn:aws:iam::{ACCOUNT}:user/creator"),
                path: "/".into(),
                create_date: "2026-01-01T00:00:00Z".into(),
                tags: BTreeMap::new(),
                attached_policies: vec![],
                inline_policies: policy(true),
                groups: vec![],
                permission_boundary: None,
                access_keys: vec![AccessKey {
                    access_key_id: KEY.into(),
                    secret_access_key: "s".repeat(40),
                    status: "Active".into(),
                    create_date: "2026-01-01T00:00:00Z".into(),
                }],
            },
        );
        for (name, service) in [
            ("lambda-execution", "lambda.amazonaws.com"),
            ("events-execution", "events.amazonaws.com"),
            ("scheduler-execution", "scheduler.amazonaws.com"),
        ] {
            iam.create_role(ACCOUNT, role(name, "/", service, false));
        }
        // The path must never be misread as privileged role `team`, session `creator`.
        iam.create_role(
            ACCOUNT,
            role("team", "/", "cloudformation.amazonaws.com", false),
        );
        iam.create_role(
            ACCOUNT,
            role("creator", "/team/", "cloudformation.amazonaws.com", true),
        );
        iam.create_role(
            ACCOUNT,
            role("cfn-execution", "/", "cloudformation.amazonaws.com", true),
        );
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            iam.clone(),
            Arc::new(SessionStore::new()),
            EnforcementMode::Strict,
        );
        let lambda = locallycloud_lambda::register(&registry);
        locallycloud_eventbridge::register(&registry);
        locallycloud_cloudformation::register(&registry);
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            REGION.into(),
            ACCOUNT.into(),
        )));
        Self {
            registry,
            iam,
            lambda,
        }
    }

    async fn call(
        &self,
        key: &str,
        service: &str,
        method: Method,
        path: &str,
        target: Option<&str>,
        body: String,
    ) -> (u16, String) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        headers.insert(
            http::header::AUTHORIZATION,
            format!("AWS4-HMAC-SHA256 Credential={key}/20261116/{REGION}/{service}/aws4_request")
                .parse()
                .unwrap(),
        );
        if let Some(target) = target {
            headers.insert("x-amz-target", target.parse().unwrap());
        }
        let response = self
            .registry
            .native_handler(&ServiceName::new(service))
            .unwrap()
            .handle(ServiceRequest {
                method,
                uri: path.parse().unwrap(),
                headers,
                body: Bytes::from(body),
                region: REGION.into(),
                account_id: ACCOUNT.into(),
                request_id: "cfn-authorization".into(),
            })
            .await;
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    async fn query(
        &self,
        key: &str,
        service: &str,
        action: &str,
        params: &[(&str, String)],
    ) -> (u16, String) {
        let mut params = params.to_vec();
        params.push(("Action", action.into()));
        self.call(key, service, Method::POST, "/", None, form(&params))
            .await
    }

    async fn assume(&self, name: &str) -> String {
        let (status, body) = self
            .query(
                KEY,
                "sts",
                "AssumeRole",
                &[
                    ("RoleArn", format!("arn:aws:iam::{ACCOUNT}:role/{name}")),
                    ("RoleSessionName", "cfn-session".into()),
                ],
            )
            .await;
        assert_eq!(status, 200, "{body}");
        xml_value(&body, "AccessKeyId").into()
    }

    async fn stack(
        &self,
        key: &str,
        name: &str,
        kind: &str,
        properties: Value,
        role_arn: Option<&str>,
    ) -> String {
        let mut template = json!({"Resources":{"Resource":{"Type":kind,"Properties":properties}}});
        if kind == "AWS::IAM::Role" {
            template["Outputs"] = json!({
                "CreatedRoleArn":{"Value":{"Fn::GetAtt":["Resource","Arn"]}},
                "CreatedRoleId":{"Value":{"Fn::GetAtt":["Resource","RoleId"]}},
            });
        }
        let mut params = vec![
            ("StackName", name.into()),
            ("TemplateBody", template.to_string()),
            ("DisableRollback", "true".into()),
        ];
        if kind == "AWS::IAM::Role" {
            params.push(("Capabilities.member.1", "CAPABILITY_NAMED_IAM".into()));
        }
        if let Some(role) = role_arn {
            params.push(("RoleARN", role.into()));
        }
        let (status, body) = self
            .query(key, "cloudformation", "CreateStack", &params)
            .await;
        assert_eq!(status, 200, "{body}");
        self.wait_stack(key, name).await
    }

    async fn wait_stack(&self, key: &str, name: &str) -> String {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (status, body) = self
                    .query(
                        key,
                        "cloudformation",
                        "DescribeStacks",
                        &[("StackName", name.into())],
                    )
                    .await;
                assert_eq!(status, 200, "{body}");
                let state = xml_value(&body, "StackStatus");
                if !state.ends_with("_IN_PROGRESS") {
                    return body;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("CloudFormation operation completed")
    }

    async fn exists(&self, kind: &str, name: &str) -> bool {
        let (status, body) = match kind {
            "AWS::Lambda::Function" => {
                self.call(
                    KEY,
                    "lambda",
                    Method::GET,
                    &format!("/2015-03-31/functions/{name}"),
                    None,
                    String::new(),
                )
                .await
            }
            "AWS::Events::Rule" => {
                self.call(
                    KEY,
                    "events",
                    Method::POST,
                    "/",
                    Some("AWSEvents.DescribeRule"),
                    json!({"Name":name}).to_string(),
                )
                .await
            }
            "AWS::Scheduler::Schedule" => {
                self.call(
                    KEY,
                    "scheduler",
                    Method::GET,
                    &format!("/schedules/{name}"),
                    None,
                    String::new(),
                )
                .await
            }
            _ => unreachable!(),
        };
        assert!(
            matches!(status, 200 | 404 | 400),
            "unexpected read status {status}: {body}"
        );
        if status != 200 {
            assert!(
                body.contains("ResourceNotFoundException")
                    || (kind == "AWS::Lambda::Function"
                        && status == 404
                        && body.contains("Function not found:"))
                    || (kind == "AWS::Scheduler::Schedule"
                        && status == 404
                        && body.contains("does not exist")),
                "{kind}: {status}: {body}"
            );
        }
        status == 200
    }

    async fn attach_state(&self, state: Arc<locallycloud_state::StateDb>) {
        let lambda = self.lambda.clone();
        let registry = self.registry.clone();
        tokio::task::spawn_blocking(move || {
            lambda.attach_state(state.clone()).unwrap();
            locallycloud_cloudformation::register_with_state(&registry, state).unwrap();
        })
        .await
        .unwrap();
    }
}

fn resources(name: &str) -> [(String, Value); 3] {
    [
        (
            "AWS::Lambda::Function".into(),
            json!({"FunctionName":name,"Runtime":"nodejs22.x","Handler":"index.handler","Role":format!("arn:aws:iam::{ACCOUNT}:role/lambda-execution"),"Code":{"ZipFile":"exports.handler = async () => ({});"}}),
        ),
        (
            "AWS::Events::Rule".into(),
            json!({"Name":name,"State":"DISABLED","EventPattern":{"source":["test"]},"RoleArn":format!("arn:aws:iam::{ACCOUNT}:role/events-execution")}),
        ),
        (
            "AWS::Scheduler::Schedule".into(),
            json!({"Name":name,"State":"DISABLED","ScheduleExpression":"rate(1 hour)","FlexibleTimeWindow":{"Mode":"OFF"},"Target":{"Arn":format!("arn:aws:lambda:{REGION}:{ACCOUNT}:function:target"),"RoleArn":format!("arn:aws:iam::{ACCOUNT}:role/scheduler-execution")}}),
        ),
    ]
}

#[tokio::test]
async fn caller_pass_role_deny_reaches_lambda_eventbridge_and_scheduler_without_partial_resources()
{
    let fixture = Fixture::new();
    for (index, (kind, properties)) in resources("denied-resource").into_iter().enumerate() {
        let body = fixture
            .stack(KEY, &format!("denied-{index}"), &kind, properties, None)
            .await;
        assert!(
            body.contains("<StackStatus>CREATE_FAILED</StackStatus>"),
            "{body}"
        );
        assert!(
            !fixture.exists(&kind, "denied-resource").await,
            "{kind} was created despite PassRole denial"
        );
    }
    fixture.iam.update_user(ACCOUNT, "creator", |user| {
        user.inline_policies = policy(false)
    });
    for (index, (kind, properties)) in resources("allowed-resource").into_iter().enumerate() {
        let body = fixture
            .stack(KEY, &format!("allowed-{index}"), &kind, properties, None)
            .await;
        assert!(
            body.contains("<StackStatus>CREATE_COMPLETE</StackStatus>"),
            "{body}"
        );
        assert!(
            fixture.exists(&kind, "allowed-resource").await,
            "{kind} control was not created"
        );
    }
}

#[tokio::test]
async fn canonical_role_with_path_cannot_be_reinterpreted_as_a_privileged_parent_role_session() {
    let fixture = Fixture::new();
    let key = fixture.assume("team/creator").await;
    for (index, (kind, properties)) in resources("path-denied").into_iter().enumerate() {
        let body = fixture
            .stack(&key, &format!("path-{index}"), &kind, properties, None)
            .await;
        assert!(
            body.contains("<StackStatus>CREATE_FAILED</StackStatus>"),
            "{body}"
        );
        assert!(!fixture.exists(&kind, "path-denied").await);
    }
    fixture.iam.update_role(ACCOUNT, "creator", |role| {
        role.inline_policies = policy(false)
    });
    let (kind, properties) = resources("path-allowed").into_iter().next().unwrap();
    let body = fixture
        .stack(&key, "path-allowed", &kind, properties, None)
        .await;
    assert!(
        body.contains("<StackStatus>CREATE_COMPLETE</StackStatus>"),
        "{body}"
    );
    assert!(fixture.exists(&kind, "path-allowed").await);
}

#[tokio::test]
async fn execution_role_permissions_and_pass_role_deny_replace_the_admin_operator_permissions() {
    let fixture = Fixture::new();
    fixture.iam.update_user(ACCOUNT, "creator", |user| {
        user.inline_policies = policy(false)
    });
    fixture.iam.update_role(ACCOUNT, "cfn-execution", |role| {
        role.inline_policies = [(
            "narrow".into(),
            json!({"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}})
                .to_string(),
        )]
        .into()
    });
    let (kind, properties) = resources("narrow-role").into_iter().next().unwrap();
    let body = fixture
        .stack(KEY, "narrow-role", &kind, properties, Some(CFN_ROLE))
        .await;
    assert!(
        body.contains("<StackStatus>CREATE_FAILED</StackStatus>"),
        "{body}"
    );
    assert_eq!(xml_value(&body, "RoleARN"), CFN_ROLE);
    assert!(!fixture.exists(&kind, "narrow-role").await);
    fixture.iam.update_role(ACCOUNT, "cfn-execution", |role| {
        role.inline_policies = policy(true)
    });
    for (index, (kind, properties)) in resources("role-pass-denied").into_iter().enumerate() {
        let body = fixture
            .stack(
                KEY,
                &format!("role-denied-{index}"),
                &kind,
                properties,
                Some(CFN_ROLE),
            )
            .await;
        assert!(
            body.contains("<StackStatus>CREATE_FAILED</StackStatus>"),
            "{body}"
        );
        assert!(!fixture.exists(&kind, "role-pass-denied").await);
    }
    fixture.iam.update_role(ACCOUNT, "cfn-execution", |role| {
        role.inline_policies = policy(false)
    });
    for (index, (kind, properties)) in resources("role-allowed").into_iter().enumerate() {
        let body = fixture
            .stack(
                KEY,
                &format!("role-allowed-{index}"),
                &kind,
                properties,
                Some(CFN_ROLE),
            )
            .await;
        assert!(
            body.contains("<StackStatus>CREATE_COMPLETE</StackStatus>"),
            "{body}"
        );
        assert_eq!(xml_value(&body, "RoleARN"), CFN_ROLE);
        assert!(fixture.exists(&kind, "role-allowed").await);
    }
}

#[tokio::test]
async fn execution_role_assignment_checks_pass_role_trust_and_account_before_admission() {
    let fixture = Fixture::new();
    let template = json!({"Resources":{"Function":{"Type":"AWS::Lambda::Function","Properties":resources("unassigned")[0].1}}});
    let params = |role: &str| {
        vec![
            ("StackName", "unassigned".into()),
            ("TemplateBody", template.to_string()),
            ("RoleARN", role.into()),
        ]
    };
    let (status, body) = fixture
        .query(KEY, "cloudformation", "CreateStack", &params(CFN_ROLE))
        .await;
    assert_eq!(status, 403, "{body}");
    fixture.iam.update_user(ACCOUNT, "creator", |user| {
        user.inline_policies = policy(false)
    });
    fixture.iam.update_role(ACCOUNT, "cfn-execution", |role| role.assume_role_policy_document = json!({"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}}).to_string());
    let (status, body) = fixture
        .query(KEY, "cloudformation", "CreateStack", &params(CFN_ROLE))
        .await;
    assert_eq!(status, 403, "{body}");
    for role in [
        "arn:aws:iam::111111111111:role/foreign",
        "arn:aws:iam::000000000000:user/creator",
        "",
        "arn:aws:iam::000000000000:role/missing",
    ] {
        let (status, body) = fixture
            .query(KEY, "cloudformation", "CreateStack", &params(role))
            .await;
        assert!(matches!(status, 400 | 403), "{status}: {body}");
    }
    let (status, body) = fixture
        .query(
            KEY,
            "cloudformation",
            "DescribeStacks",
            &[("StackName", "unassigned".into())],
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(!fixture.exists("AWS::Lambda::Function", "unassigned").await);
}

#[tokio::test]
async fn persisted_stack_role_is_reused_for_update_and_delete_without_operator_pass_role() {
    let fixture = Fixture::new();
    fixture.iam.update_user(ACCOUNT, "creator", |user| {
        user.inline_policies = policy(false)
    });
    fixture.iam.update_role(ACCOUNT, "cfn-execution", |role| {
        role.inline_policies = policy(false)
    });
    let (kind, mut properties) = resources("reused-role").into_iter().next().unwrap();
    let body = fixture
        .stack(
            KEY,
            "reused-role",
            &kind,
            properties.clone(),
            Some(CFN_ROLE),
        )
        .await;
    assert!(
        body.contains("<StackStatus>CREATE_COMPLETE</StackStatus>"),
        "{body}"
    );
    fixture.iam.update_user(ACCOUNT, "creator", |user| {
        user.inline_policies = policy(true)
    });
    properties["Description"] = json!("updated using the saved role");
    let template = json!({"Resources":{"Resource":{"Type":kind,"Properties":properties}}});
    let (status, body) = fixture
        .query(
            KEY,
            "cloudformation",
            "UpdateStack",
            &[
                ("StackName", "reused-role".into()),
                ("TemplateBody", template.to_string()),
            ],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let body = fixture.wait_stack(KEY, "reused-role").await;
    assert!(
        body.contains("<StackStatus>UPDATE_COMPLETE</StackStatus>"),
        "{body}"
    );
    assert_eq!(xml_value(&body, "RoleARN"), CFN_ROLE);
    let stack_arn = xml_value(&body, "StackId").to_owned();
    let (status, body) = fixture
        .call(
            KEY,
            "lambda",
            Method::GET,
            "/2015-03-31/functions/reused-role",
            None,
            String::new(),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["Configuration"]["Description"],
        "updated using the saved role"
    );
    let (status, body) = fixture
        .query(
            KEY,
            "cloudformation",
            "DeleteStack",
            &[("StackName", "reused-role".into())],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let body = fixture.wait_stack(KEY, &stack_arn).await;
    assert!(
        body.contains("<StackStatus>DELETE_COMPLETE</StackStatus>"),
        "{body}"
    );
    assert!(!fixture.exists(&kind, "reused-role").await);
}

#[tokio::test]
async fn change_sets_preserve_role_selection_and_require_authorization_before_execution() {
    let fixture = Fixture::new();
    fixture.iam.update_user(ACCOUNT, "creator", |user| {
        user.inline_policies = policy(false)
    });
    fixture.iam.update_role(ACCOUNT, "cfn-execution", |role| {
        role.inline_policies = policy(false)
    });
    let template = json!({"Resources":{"Resource":{"Type":"AWS::Lambda::Function","Properties":resources("change-role")[0].1}}});
    let params = [
        ("StackName", "change-role".into()),
        ("ChangeSetName", "change-role".into()),
        ("ChangeSetType", "CREATE".into()),
        ("TemplateBody", template.to_string()),
        ("RoleARN", CFN_ROLE.into()),
    ];
    fixture.iam.update_user(ACCOUNT, "creator", |user| {
        user.inline_policies = policy(true)
    });
    let (status, body) = fixture
        .query(KEY, "cloudformation", "CreateChangeSet", &params)
        .await;
    assert_eq!(status, 403, "{body}");
    fixture.iam.update_user(ACCOUNT, "creator", |user| {
        user.inline_policies = policy(false)
    });
    let (status, body) = fixture
        .query(KEY, "cloudformation", "CreateChangeSet", &params)
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = fixture
        .query(
            KEY,
            "cloudformation",
            "DescribeStacks",
            &[("StackName", "change-role".into())],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(xml_value(&body, "RoleARN"), CFN_ROLE);
    let execute = [
        ("StackName", "change-role".into()),
        ("ChangeSetName", "change-role".into()),
    ];
    fixture.iam.update_user(ACCOUNT, "creator", |user| {
        user.inline_policies = policy(true)
    });
    let (status, body) = fixture
        .query(KEY, "cloudformation", "ExecuteChangeSet", &execute)
        .await;
    assert_eq!(status, 200, "{body}");
    let body = fixture.wait_stack(KEY, "change-role").await;
    assert!(
        body.contains("<StackStatus>CREATE_COMPLETE</StackStatus>"),
        "{body}"
    );
    assert_eq!(xml_value(&body, "RoleARN"), CFN_ROLE);
    assert!(fixture.exists("AWS::Lambda::Function", "change-role").await);
}

#[test]
fn execution_role_survives_restart_and_failed_persistence_does_not_publish_role_changes() {
    const CHILD_PATH: &str = "LOCALLYCLOUD_CFN_ROLE_TEST_DB";
    let Some(path) = std::env::var_os(CHILD_PATH) else {
        use std::os::unix::fs::DirBuilderExt;
        let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../compatibility-tests/.work")
            .join(format!("cfn-role-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "execution_role_survives_restart_and_failed_persistence_does_not_publish_role_changes", "--nocapture"])
            .env(CHILD_PATH, directory.join("state.sqlite3"))
            .env("LOCALLYCLOUD_KMS_MASTER_KEY", "cXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXE=")
            .status().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        assert!(status.success());
        return;
    };
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let state = Arc::new(tokio::task::spawn_blocking(move || locallycloud_state::StateDb::open(path.into())).await.unwrap().unwrap());
        let fixture = Fixture::new();
        fixture.iam.update_user(ACCOUNT, "creator", |user| user.inline_policies = policy(false));
        fixture.iam.update_role(ACCOUNT, "cfn-execution", |role| role.inline_policies = policy(false));
        fixture.attach_state(state.clone()).await;
        let (kind, mut properties) = resources("restart-role").into_iter().next().unwrap();
        let body = fixture.stack(KEY, "restart-role", &kind, properties.clone(), Some(CFN_ROLE)).await;
        assert!(body.contains("<StackStatus>CREATE_COMPLETE</StackStatus>"), "{body}");
        let database = state.clone();
        tokio::task::spawn_blocking(move || database.connection().unwrap().execute_batch("CREATE TRIGGER reject_cfn_role BEFORE INSERT ON cfn_metadata_v1 WHEN NEW.kind='stack' BEGIN SELECT RAISE(FAIL,'injected persistence failure'); END;")).await.unwrap().unwrap();
        let template = json!({"Resources":{"Resource":{"Type":kind,"Properties":properties}}});
        let (status, body) = fixture.query(KEY, "cloudformation", "UpdateStack", &[("StackName", "restart-role".into()), ("TemplateBody", template.to_string()), ("RoleARN", format!("arn:aws:iam::{ACCOUNT}:role/team"))]).await;
        assert_eq!(status, 500, "{body}");
        let (_, body) = fixture.query(KEY, "cloudformation", "DescribeStacks", &[("StackName", "restart-role".into())]).await;
        assert_eq!(xml_value(&body, "RoleARN"), CFN_ROLE);
        let database = state.clone();
        tokio::task::spawn_blocking(move || database.connection().unwrap().execute_batch("DROP TRIGGER reject_cfn_role;")).await.unwrap().unwrap();
        drop(fixture);
        let restored = Fixture::new();
        restored.iam.update_role(ACCOUNT, "cfn-execution", |role| role.inline_policies = policy(false));
        restored.attach_state(state.clone()).await;
        let (status, body) = restored.query(KEY, "cloudformation", "DescribeStacks", &[("StackName", "restart-role".into())]).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(xml_value(&body, "RoleARN"), CFN_ROLE);
        properties["Description"] = json!("after restart");
        let template = json!({"Resources":{"Resource":{"Type":kind,"Properties":properties}}});
        let (status, body) = restored.query(KEY, "cloudformation", "UpdateStack", &[("StackName", "restart-role".into()), ("TemplateBody", template.to_string())]).await;
        assert_eq!(status, 200, "{body}");
        let body = restored.wait_stack(KEY, "restart-role").await;
        assert!(body.contains("<StackStatus>UPDATE_COMPLETE</StackStatus>"), "{body}");
        assert_eq!(xml_value(&body, "RoleARN"), CFN_ROLE);
        assert!(restored.exists(&kind, "restart-role").await);
        // A legacy change set has no server-validated role binding. A same-named
        // query parameter cannot forge that proof after upgrade.
        let legacy_properties = resources("legacy-role")[0].1.clone();
        let legacy_template = json!({"Resources":{"Resource":{"Type":kind,"Properties":legacy_properties}}});
        let legacy: locallycloud_cloudformation::store::ChangeSet = serde_json::from_value(json!({
            "id":format!("arn:aws:cloudformation:{REGION}:{ACCOUNT}:changeSet/legacy-role/id"),
            "name":"legacy-role", "stack_name":"legacy-role",
            "stack_id":format!("arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/legacy-role/id"),
            "change_type":"CREATE", "status":"CREATE_COMPLETE", "reason":null, "executed":false,
            "request":{"params":{"StackName":"legacy-role", "RoleARN":CFN_ROLE, "validated_role_arn":CFN_ROLE, "TemplateBody":legacy_template.to_string()}}, "changes":[]
        })).unwrap();
        let database = state.clone();
        tokio::task::spawn_blocking(move || locallycloud_cloudformation::store::CfnStore::with_state(&database).unwrap().insert_change_set(ACCOUNT, REGION, legacy)).await.unwrap().unwrap();
        restored.attach_state(state).await;
        let (status, body) = restored.query(KEY, "cloudformation", "ExecuteChangeSet", &[("StackName", "legacy-role".into()), ("ChangeSetName", "legacy-role".into())]).await;
        assert_eq!(status, 403, "{body}");
        assert!(!restored.exists(&kind, "legacy-role").await);
    });
}

#[tokio::test]
async fn execution_role_creates_iam_role_and_inline_policy_and_its_deny_wins_over_admin() {
    let fixture = Fixture::new();
    fixture.iam.update_user(ACCOUNT, "creator", |user| {
        user.inline_policies = policy(false)
    });
    let allowed = json!({"Effect":"Allow","Action":["iam:CreateRole","iam:PutRolePolicy"],"Resource":format!("arn:aws:iam::{ACCOUNT}:role/cfn-child-*"),"Condition":{
        "StringEquals":{"aws:PrincipalArn":CFN_ROLE,"aws:userid":"AROAcfn-execution:cloudformation"},
        "Bool":{"aws:MultiFactorAuthPresent":"false"},"NumericGreaterThan":{"aws:EpochTime":"0"}
    }});
    fixture.iam.update_role(ACCOUNT, "cfn-execution", |role| {
        role.inline_policies = [(
            "narrow".into(),
            json!({"Statement":[allowed.clone()]}).to_string(),
        )]
        .into();
    });
    // This operation used to fail at IAM's synthetic locallycloud-cloudformation key,
    // despite Core's attested execution role. Its identity, not the operator's, applies.
    for (name, denied) in [("cfn-child-allowed", false), ("cfn-child-denied", true)] {
        if denied {
            fixture.iam.update_role(ACCOUNT, "cfn-execution", |role| {
                role.inline_policies = [("narrow".into(),json!({"Statement":[allowed.clone(),{
                    "Effect":"Deny","Action":"iam:CreateRole","Resource":format!("arn:aws:iam::{ACCOUNT}:role/{name}")
                }]}).to_string())].into();
            });
        }
        let inline = json!({"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/*"}});
        let template = json!({"Resources":{"Role":{"Type":"AWS::IAM::Role","Properties":{
            "RoleName":name,"AssumeRolePolicyDocument":{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}},
            "Policies":[{"PolicyName":"read","PolicyDocument":inline}]
        }}}});
        let (status, body) = fixture
            .query(
                KEY,
                "cloudformation",
                "CreateStack",
                &[
                    ("StackName", name.into()),
                    ("TemplateBody", template.to_string()),
                    ("RoleARN", CFN_ROLE.into()),
                    ("Capabilities.member.1", "CAPABILITY_NAMED_IAM".into()),
                    ("DisableRollback", "true".into()),
                ],
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let body = fixture.wait_stack(KEY, name).await;
        if denied {
            assert!(
                body.contains("<StackStatus>CREATE_FAILED</StackStatus>"),
                "{body}"
            );
            assert!(
                fixture.iam.get_role(ACCOUNT, name).is_none(),
                "denied execution role created IAM resource using the admin operator"
            );
        } else {
            assert!(
                body.contains("<StackStatus>CREATE_COMPLETE</StackStatus>"),
                "{body}"
            );
            let role = fixture
                .iam
                .get_role(ACCOUNT, name)
                .expect("authorized role was created");
            let actual: Value = serde_json::from_str(&role.inline_policies["read"]).unwrap();
            assert_eq!(actual, inline);
        }
    }
}

#[tokio::test]
async fn cfn_role_creation_keeps_boundary_and_tags_in_the_authorized_create_call() {
    let fixture = Fixture::new();
    fixture.iam.update_user(ACCOUNT, "creator", |user| {
        user.inline_policies = policy(false)
    });
    locallycloud_s3::register(&fixture.registry);
    let (status, body) = fixture
        .query(
            KEY,
            "iam",
            "CreatePolicy",
            &[
                ("PolicyName", "read-only".into()),
                ("Path", "/guardrails/".into()),
                (
                    "PolicyDocument",
                    json!({"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}})
                        .to_string(),
                ),
            ],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let boundary = xml_value(&body, "Arn").to_owned();
    let props = json!({
        "RoleName":"bounded-from-stack", "Path":"/team/&ops/",
        "AssumeRolePolicyDocument":{"Statement":{"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:user/creator")},"Action":"sts:AssumeRole"}},
        "PermissionsBoundary":boundary,
        "Tags":[{"Key":"team/name","Value":"platform dev"}],
        "Policies":[{"PolicyName":"s3","PolicyDocument":{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}}],
    });
    let stack = fixture
        .stack(KEY, "bounded-role", "AWS::IAM::Role", props, Some(CFN_ROLE))
        .await;
    assert!(
        stack.contains("<StackStatus>CREATE_COMPLETE</StackStatus>"),
        "{stack}"
    );
    assert_eq!(xml_value(&stack, "RoleARN"), CFN_ROLE);
    let (status, role) = fixture
        .query(
            KEY,
            "iam",
            "GetRole",
            &[("RoleName", "bounded-from-stack".into())],
        )
        .await;
    assert_eq!(status, 200, "{role}");
    assert_eq!(xml_value(&role, "PermissionsBoundaryArn"), boundary);
    assert!(
        role.contains("<Key>team/name</Key><Value>platform dev</Value>"),
        "{role}"
    );
    let output = |key: &str| {
        let (_, tail) = stack
            .split_once(&format!("<OutputKey>{key}</OutputKey>"))
            .unwrap();
        xml_value(tail, "OutputValue").to_owned()
    };
    assert_eq!(output("CreatedRoleArn"), xml_value(&role, "Arn"));
    let role_arn = fixture
        .iam
        .get_role(ACCOUNT, "bounded-from-stack")
        .unwrap()
        .arn;
    assert_eq!(output("CreatedRoleId"), xml_value(&role, "RoleId"));
    for (path, value) in [("/cfn-bounded", ""), ("/cfn-bounded/read", "seed")] {
        assert_eq!(
            fixture
                .call(KEY, "s3", Method::PUT, path, None, value.into())
                .await
                .0,
            200
        );
    }
    let (status, credentials) = fixture
        .query(
            KEY,
            "sts",
            "AssumeRole",
            &[
                ("RoleArn", role_arn),
                ("RoleSessionName", "boundary-check".into()),
            ],
        )
        .await;
    assert_eq!(status, 200);
    let session = xml_value(&credentials, "AccessKeyId");
    let (status, body) = fixture
        .call(
            session,
            "s3",
            Method::GET,
            "/cfn-bounded/read",
            None,
            String::new(),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, "seed");
    let (status, body) = fixture
        .call(
            session,
            "s3",
            Method::PUT,
            "/cfn-bounded/forbidden",
            None,
            "must not be stored".into(),
        )
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        fixture
            .call(
                KEY,
                "s3",
                Method::GET,
                "/cfn-bounded/forbidden",
                None,
                String::new()
            )
            .await
            .0,
        404
    );
}

#[tokio::test]
async fn cfn_tag_dependency_denial_and_malformed_role_security_properties_create_no_role() {
    let fixture = Fixture::new();
    fixture.iam.update_user(ACCOUNT, "creator", |user| {
        user.inline_policies = [("tag-deny".into(), json!({"Statement":[
            {"Effect":"Allow","Action":"*","Resource":"*"},
            {"Effect":"Deny","Action":"iam:TagRole","Resource":format!("arn:aws:iam::{ACCOUNT}:role/team/denied-tagged")},
        ]}).to_string())].into();
    });
    let trust = json!({"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}});
    let props = json!({"RoleName":"denied-tagged","Path":"/team/","AssumeRolePolicyDocument":trust,"Tags":[{"Key":"env","Value":"prod"}]});
    let stack = fixture
        .stack(KEY, "tag-dependency-denied", "AWS::IAM::Role", props, None)
        .await;
    assert!(
        stack.contains("<StackStatus>CREATE_FAILED</StackStatus>"),
        "{stack}"
    );
    assert!(fixture.iam.get_role(ACCOUNT, "denied-tagged").is_none());
    assert_eq!(
        fixture
            .query(
                KEY,
                "iam",
                "GetRole",
                &[("RoleName", "denied-tagged".into())]
            )
            .await
            .0,
        404
    );
    for (index, security) in [
        json!({"Tags":null}),
        json!({"Tags":{}}),
        json!({"Tags":[{"Key":"env","Value":12}]}),
        json!({"PermissionsBoundary":null}),
        json!({"PermissionsBoundary":12}),
        json!({"PermissionsBoundary":""}),
        json!({"PermissionsBoundary":"arn:aws:s3:::wrong-service"}),
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("malformed-security-{index}");
        let mut props = json!({"RoleName":name,"AssumeRolePolicyDocument":trust});
        props
            .as_object_mut()
            .unwrap()
            .extend(security.as_object().unwrap().clone());
        let stack = fixture
            .stack(
                KEY,
                &format!("invalid-security-{index}"),
                "AWS::IAM::Role",
                props,
                None,
            )
            .await;
        assert!(
            stack.contains("<StackStatus>CREATE_FAILED</StackStatus>"),
            "{stack}"
        );
        assert!(fixture.iam.get_role(ACCOUNT, &name).is_none());
    }
}
