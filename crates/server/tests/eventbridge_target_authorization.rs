//! EventBridge roles compose with destination resource policies, without premature identity denial.
#![cfg(feature = "services")]
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::to_bytes;
use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, Method};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_iam_sts::{
    enforcement::EnforcementMode,
    model::{AccessKey, IamRole, IamUser},
    store::IamStore,
    sts::SessionStore,
};
use serde_json::{json, Value};
use tokio::sync::Notify;

const ACCOUNT: &str = "000000000000";
const KEY: &str = "AKIASSSSSSSSSSSSSSSS";
const FUNCTION: &str = "arn:aws:lambda:us-east-1:000000000000:function:notification";
const ROLE: &str = "arn:aws:iam::000000000000:role/event-target";

struct Observer {
    inner: Arc<dyn NativeHandler>,
    statuses: Arc<Mutex<Vec<u16>>>,
    changed: Arc<Notify>,
}
#[async_trait::async_trait]
impl NativeHandler for Observer {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let internal = request
            .headers
            .get("x-locallycloud-verified-internal-scope")
            .is_some_and(|value| value == "1");
        if internal {
            assert_eq!(
                request.headers["x-locallycloud-caller-principal"],
                format!("{ROLE}/eventbridge").as_str()
            );
        }
        let response = self.inner.handle(request).await;
        if internal {
            self.statuses
                .lock()
                .unwrap()
                .push(response.status().as_u16());
            self.changed.notify_one();
        }
        response
    }
}
struct Fixture {
    registry: Arc<ServiceRegistry>,
    iam: Arc<IamStore>,
    statuses: Arc<Mutex<Vec<u16>>>,
    changed: Arc<Notify>,
}
impl Fixture {
    async fn new(target: &str) -> Self {
        let registry = ServiceRegistry::with_known_services();
        locallycloud_eventbridge::register(&registry);
        locallycloud_sqs::register(&registry);
        locallycloud_lambda::register(&registry);
        let fixture = Self {
            registry,
            iam: Arc::new(IamStore::new()),
            statuses: Arc::default(),
            changed: Arc::default(),
        };
        fixture.call("lambda", Method::POST, "/2015-03-31/functions", Bytes::from(json!({
            "FunctionName":"notification", "Runtime":"nodejs22.x", "Handler":"index.handler",
            "Role":format!("arn:aws:iam::{ACCOUNT}:role/execution"), "Code":{"ZipFile":"UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA=="}
        }).to_string()), None).await;
        let iam = fixture.iam.clone();
        iam.create_user(
            ACCOUNT,
            IamUser {
                user_name: "admin".into(),
                user_id: "AIDAADMIN".into(),
                arn: format!("arn:aws:iam::{ACCOUNT}:user/admin"),
                path: "/".into(),
                create_date: "2026-01-01T00:00:00Z".into(),
                tags: BTreeMap::new(),
                attached_policies: Vec::new(),
                inline_policies: BTreeMap::from([(
                    "admin".into(),
                    json!({"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}).to_string(),
                )]),
                groups: Vec::new(),
                permission_boundary: None,
                access_keys: vec![AccessKey {
                    access_key_id: KEY.into(),
                    secret_access_key: "secret".into(),
                    status: "Active".into(),
                    create_date: "2026-01-01T00:00:00Z".into(),
                }],
            },
        );
        iam.create_role(ACCOUNT, IamRole {
            role_name:"event-target".into(), role_id:"AROAEVENTTARGET".into(), arn:ROLE.into(), path:"/".into(),
            create_date:"2026-01-01T00:00:00Z".into(),
            assume_role_policy_document:json!({"Statement":{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}}).to_string(),
            description:None,max_session_duration:3600,tags:BTreeMap::new(),attached_policies:Vec::new(),inline_policies:BTreeMap::new(),permission_boundary:None,
        });
        locallycloud_iam_sts::register_with_store_and_mode(
            &fixture.registry,
            iam,
            Arc::new(SessionStore::new()),
            EnforcementMode::Strict,
        );
        fixture
            .registry
            .set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
                &fixture.registry,
                ProxyConfig {
                    backend_url: "http://127.0.0.1:1".into(),
                    upstream_timeout: Duration::from_secs(1),
                },
                LegacyHealth::new(false),
                "us-east-1".into(),
                ACCOUNT.into(),
            )));
        let inner = fixture
            .registry
            .native_handler(&ServiceName::new(target))
            .unwrap();
        fixture.registry.register_native(
            ServiceName::new(target),
            ServiceMetadata::new(
                if target == "sqs" {
                    AwsProtocol::Json10
                } else {
                    AwsProtocol::RestJson
                },
                None,
            ),
            Arc::new(Observer {
                inner,
                statuses: fixture.statuses.clone(),
                changed: fixture.changed.clone(),
            }),
        );
        fixture
    }
    async fn call(
        &self,
        service: &str,
        method: Method,
        path: &str,
        body: Bytes,
        operation: Option<&str>,
    ) -> Vec<u8> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        headers.insert(
            "authorization",
            format!("AWS4-HMAC-SHA256 Credential={KEY}/20261116/us-east-1/{service}/aws4_request")
                .parse()
                .unwrap(),
        );
        if let Some(operation) = operation {
            headers.insert(
                "x-amz-target",
                format!(
                    "{}.{operation}",
                    if service == "events" {
                        "AWSEvents"
                    } else {
                        "AmazonSQS"
                    }
                )
                .parse()
                .unwrap(),
            );
        }
        let handler = self
            .registry
            .native_handler(&ServiceName::new(service))
            .unwrap();
        let response = handler
            .handle(ServiceRequest {
                method,
                uri: path.parse().unwrap(),
                headers,
                body,
                region: "us-east-1".into(),
                account_id: ACCOUNT.into(),
                request_id: "s3-notification-policy".into(),
            })
            .await;
        let status = response.status();
        let body = to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec();
        assert!(
            status.is_success(),
            "{service} {path}: {status}: {}",
            String::from_utf8_lossy(&body)
        );
        body
    }
    async fn json(&self, service: &str, operation: &str, body: Value) -> Value {
        let bytes = self
            .call(
                service,
                Method::POST,
                "/",
                body.to_string().into(),
                Some(operation),
            )
            .await;
        serde_json::from_slice(&bytes).unwrap()
    }
    async fn publish(&self, target: &str) {
        self.json(
            "events",
            "PutRule",
            json!({"Name":"orders","EventPattern":json!({"source":["review"]}).to_string()}),
        )
        .await;
        let result = self
            .json(
                "events",
                "PutTargets",
                json!({"Rule":"orders","Targets":[{"Id":"target","Arn":target,"RoleArn":ROLE}]}),
            )
            .await;
        assert_eq!(result["FailedEntryCount"], 0);
        self.json(
            "events",
            "PutEvents",
            json!({"Entries":[{"Source":"review","DetailType":"review","Detail":"{}"}]}),
        )
        .await;
    }
    async fn observed(&self, expected: u16) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let notified = self.changed.notified();
                if self.statuses.lock().unwrap().contains(&expected) {
                    return;
                }
                notified.await;
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn event_role_queue_resource_grant_needs_no_identity_allow_but_denies_still_win() {
    for case in ["missing", "grant", "identity-deny"] {
        let fixture = Fixture::new("sqs").await;
        let resource = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:notifications");
        let attributes = if case == "missing" {
            json!({})
        } else {
            json!({"Policy":json!({"Statement":{
            "Effect":"Allow","Principal":{"AWS":ROLE},"Action":"sqs:SendMessage","Resource":resource
        }}).to_string()})
        };
        let queue = fixture
            .json(
                "sqs",
                "CreateQueue",
                json!({"QueueName":"notifications","Attributes":attributes}),
            )
            .await;
        if case == "identity-deny" {
            fixture.iam.update_role(ACCOUNT,"event-target", |role| { role.inline_policies.insert("deny".into(),json!({"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}).to_string()); });
        }
        fixture.publish(&resource).await;
        let allowed = case == "grant";
        fixture.observed(if allowed { 200 } else { 403 }).await;
        let response = fixture
            .json(
                "sqs",
                "ReceiveMessage",
                json!({"QueueUrl":queue["QueueUrl"]}),
            )
            .await;
        assert_eq!(
            response["Messages"].as_array().map_or(0, Vec::len),
            usize::from(allowed)
        );
    }
}

#[tokio::test]
async fn event_role_lambda_resource_grant_reaches_real_destination_authorization() {
    for case in ["missing", "grant", "identity-deny"] {
        let fixture = Fixture::new("lambda").await;
        if case != "missing" {
            fixture
                .call(
                    "lambda",
                    Method::POST,
                    "/2015-03-31/functions/notification/policy",
                    json!({
                        "StatementId":"event-role","Principal":ROLE,"Action":"lambda:InvokeFunction"
                    })
                    .to_string()
                    .into(),
                    None,
                )
                .await;
        }
        if case == "identity-deny" {
            fixture.iam.update_role(ACCOUNT,"event-target", |role| { role.inline_policies.insert("deny".into(),json!({"Statement":{"Effect":"Deny","Action":"lambda:InvokeFunction","Resource":"*"}}).to_string()); });
        }
        fixture.publish(FUNCTION).await;
        // The control-plane-only Lambda's 501 proves the real authorization gate passed.
        fixture
            .observed(if case == "grant" { 501 } else { 403 })
            .await;
    }
}
