//! S3 notifications retain attested bucket identity at real destination authorization gates.
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
    model::{AccessKey, IamUser},
    store::IamStore,
    sts::SessionStore,
};
use serde_json::{json, Value};
use tokio::sync::Notify;

const ACCOUNT: &str = "000000000000";
const KEY: &str = "AKIASSSSSSSSSSSSSSSS";
const FUNCTION: &str = "arn:aws:lambda:us-east-1:000000000000:function:notification";

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
                "s3.amazonaws.com"
            );
            assert_eq!(
                request.headers["x-locallycloud-source-arn"],
                "arn:aws:s3:::notify-source"
            );
            assert_eq!(request.headers["x-locallycloud-source-account"], ACCOUNT);
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
    statuses: Arc<Mutex<Vec<u16>>>,
    changed: Arc<Notify>,
}
impl Fixture {
    async fn new(target: &str) -> Self {
        let registry = ServiceRegistry::with_known_services();
        locallycloud_s3::register(&registry);
        locallycloud_sqs::register(&registry);
        locallycloud_eventbridge::register(&registry);
        locallycloud_lambda::register(&registry);
        let fixture = Self {
            registry,
            statuses: Arc::default(),
            changed: Arc::default(),
        };
        fixture.call("lambda", Method::POST, "/2015-03-31/functions", Bytes::from(json!({
            "FunctionName":"notification", "Runtime":"nodejs22.x", "Handler":"index.handler",
            "Role":format!("arn:aws:iam::{ACCOUNT}:role/execution"), "Code":{"ZipFile":"UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA=="}
        }).to_string()), None).await;
        let iam = Arc::new(IamStore::new());
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
                match target {
                    "sqs" => AwsProtocol::Json10,
                    "events" => AwsProtocol::Json11,
                    _ => AwsProtocol::RestJson,
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
        let (status, body) = self.raw_call(service, method, path, body, operation).await;
        assert!(
            (200..300).contains(&status),
            "{service} {path}: {status}: {}",
            String::from_utf8_lossy(&body)
        );
        body
    }
    async fn events(&self, operation: &str, body: Value) -> Value {
        serde_json::from_slice(
            &self
                .call(
                    "events",
                    Method::POST,
                    "/",
                    body.to_string().into(),
                    Some(operation),
                )
                .await,
        )
        .unwrap()
    }
    async fn raw_call(
        &self,
        service: &str,
        method: Method,
        path: &str,
        body: Bytes,
        operation: Option<&str>,
    ) -> (u16, Vec<u8>) {
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
        (status.as_u16(), body)
    }
    async fn sqs(&self, operation: &str, body: Value) -> Value {
        let bytes = self
            .call(
                "sqs",
                Method::POST,
                "/",
                body.to_string().into(),
                Some(operation),
            )
            .await;
        serde_json::from_slice(&bytes).unwrap()
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
async fn s3_queue_notifications_require_matching_bucket_policy_and_leave_no_denied_messages() {
    for policy_bucket in [None, Some("other-bucket"), Some("notify-source")] {
        let fixture = Fixture::new("sqs").await;
        let resource = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:notifications");
        let attributes = policy_bucket.map(|bucket| json!({"Policy":json!({"Statement":{
            "Effect":"Allow", "Principal":{"Service":"s3.amazonaws.com"}, "Action":"sqs:SendMessage", "Resource":resource,
            "Condition":{"ArnEquals":{"aws:SourceArn":format!("arn:aws:s3:::{bucket}")},"StringEquals":{"aws:SourceAccount":ACCOUNT}}
        }}).to_string()})).unwrap_or(json!({}));
        let queue = fixture
            .sqs(
                "CreateQueue",
                json!({"QueueName":"notifications","Attributes":attributes}),
            )
            .await;
        fixture
            .call("s3", Method::PUT, "/notify-source", Bytes::new(), None)
            .await;
        fixture.call("s3", Method::PUT, "/notify-source?notification", format!("<NotificationConfiguration><QueueConfiguration><Id>queue</Id><Queue>{resource}</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration></NotificationConfiguration>").into(), None).await;
        fixture
            .call(
                "s3",
                Method::PUT,
                "/notify-source/object",
                Bytes::from_static(b"body"),
                None,
            )
            .await;
        let allowed = policy_bucket == Some("notify-source");
        fixture.observed(if allowed { 200 } else { 403 }).await;
        let response = fixture
            .sqs("ReceiveMessage", json!({"QueueUrl":queue["QueueUrl"]}))
            .await;
        let messages = response["Messages"].as_array();
        assert_eq!(messages.map_or(0, Vec::len), usize::from(allowed));
        if allowed {
            assert!(messages.unwrap()[0]["Body"]
                .as_str()
                .unwrap()
                .contains("notify-source"));
        }
    }
}

#[tokio::test]
async fn s3_lambda_notifications_reach_execution_only_after_matching_bucket_grant() {
    for policy_bucket in [None, Some("other-bucket"), Some("notify-source")] {
        let fixture = Fixture::new("lambda").await;
        if let Some(bucket) = policy_bucket {
            fixture.call("lambda", Method::POST, "/2015-03-31/functions/notification/policy", json!({
                "StatementId":"s3", "Principal":"s3.amazonaws.com", "Action":"lambda:InvokeFunction", "SourceAccount":ACCOUNT,
                "SourceArn":format!("arn:aws:s3:::{bucket}")
            }).to_string().into(), None).await;
        }
        fixture
            .call("s3", Method::PUT, "/notify-source", Bytes::new(), None)
            .await;
        fixture.call("s3", Method::PUT, "/notify-source?notification", format!("<NotificationConfiguration><CloudFunctionConfiguration><Id>lambda</Id><CloudFunction>{FUNCTION}</CloudFunction><Event>s3:ObjectCreated:*</Event></CloudFunctionConfiguration></NotificationConfiguration>").into(), None).await;
        fixture
            .call(
                "s3",
                Method::PUT,
                "/notify-source/object",
                Bytes::from_static(b"body"),
                None,
            )
            .await;
        // 501 proves the real handler passed authorization and reached its missing executor;
        // actual OCI execution is validated separately by the private-guest CLI harness.
        fixture
            .observed(if policy_bucket == Some("notify-source") {
                501
            } else {
                403
            })
            .await;
    }
}

#[tokio::test]
async fn s3_eventbridge_delivery_composes_managed_source_grant_with_bus_denies() {
    for denied in [false, true] {
        let fixture = Fixture::new("events").await;
        let queue_arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:s3-events");
        let rule_arn = format!("arn:aws:events:us-east-1:{ACCOUNT}:rule/s3-events");
        let bus_arn = format!("arn:aws:events:us-east-1:{ACCOUNT}:event-bus/default");
        let queue = fixture.sqs("CreateQueue", json!({"QueueName":"s3-events","Attributes":{"Policy":json!({"Statement":{
            "Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":queue_arn,
            "Condition":{"ArnEquals":{"aws:SourceArn":rule_arn}}
        }}).to_string()}})).await;
        fixture
            .events(
                "PutRule",
                json!({"Name":"s3-events","EventPattern":json!({"source":["aws.s3"]}).to_string()}),
            )
            .await;
        fixture
            .events(
                "PutTargets",
                json!({"Rule":"s3-events","Targets":[{"Id":"queue","Arn":queue_arn}]}),
            )
            .await;
        if denied {
            fixture.events("PutPermission", json!({"Policy":json!({"Statement":{"Effect":"Deny","Principal":{"Service":"s3.amazonaws.com"},"Action":"events:PutEvents","Resource":bus_arn}}).to_string()})).await;
        }
        fixture
            .call("s3", Method::PUT, "/notify-source", Bytes::new(), None)
            .await;
        fixture.call("s3", Method::PUT, "/notify-source?notification", Bytes::from_static(b"<NotificationConfiguration><EventBridgeConfiguration/></NotificationConfiguration>"), None).await;
        fixture
            .call(
                "s3",
                Method::PUT,
                "/notify-source/object",
                Bytes::from_static(b"body"),
                None,
            )
            .await;
        fixture.observed(if denied { 403 } else { 200 }).await;
        let received = fixture
            .sqs(
                "ReceiveMessage",
                json!({"QueueUrl":queue["QueueUrl"],"WaitTimeSeconds":if denied {0}else{1}}),
            )
            .await;
        assert_eq!(
            received["Messages"].as_array().map_or(0, Vec::len),
            usize::from(!denied)
        );
        if !denied {
            let event: Value =
                serde_json::from_str(received["Messages"][0]["Body"].as_str().unwrap()).unwrap();
            assert_eq!(event["source"], "aws.s3");
            assert_eq!(event["detail"]["bucket"]["name"], "notify-source");
        }
    }
}

#[tokio::test]
async fn external_put_events_honors_bus_deny_and_policy_validation_is_atomic() {
    let fixture = Fixture::new("events").await;
    let bus_arn = format!("arn:aws:events:us-east-1:{ACCOUNT}:event-bus/default");
    let policy=json!({"Statement":{"Sid":"deny-user","Effect":"Deny","Principal":"*","Action":"events:PutEvents","Resource":bus_arn,"Condition":{"StringEquals":{"events:source":"blocked"}}}}).to_string();
    fixture
        .events("PutPermission", json!({"Policy":policy}))
        .await;
    let blocked = fixture
        .raw_call(
            "events",
            Method::POST,
            "/",
            json!({"Entries":[{"Source":"blocked","DetailType":"test","Detail":"{}"}]})
                .to_string()
                .into(),
            Some("PutEvents"),
        )
        .await;
    assert_eq!(blocked.0, 403);
    assert_eq!(
        fixture
            .events(
                "PutEvents",
                json!({"Entries":[{"Source":"allowed","DetailType":"test","Detail":"{}"}]})
            )
            .await["FailedEntryCount"],
        0
    );
    let unsupported=fixture.raw_call("events",Method::POST,"/",json!({"Policy":json!({"Statement":{"Effect":"Allow","NotPrincipal":"*","Action":"events:PutEvents","Resource":"*"}}).to_string()}).to_string().into(),Some("PutPermission")).await;
    assert_eq!(unsupported.0, 400);
    let described = fixture.events("DescribeEventBus", json!({})).await;
    assert_eq!(
        serde_json::from_str::<Value>(described["Policy"].as_str().unwrap()).unwrap(),
        serde_json::from_str::<Value>(&policy).unwrap()
    );
    assert_eq!(fixture.raw_call("events",Method::POST,"/",json!({"Entries":[{"EventBusName":"arn:aws:events:us-east-1:111111111111:event-bus/default","Source":"allowed","DetailType":"test","Detail":"{}"}]}).to_string().into(),Some("PutEvents")).await.0,403);
}

#[tokio::test]
async fn reserved_source_fails_per_entry_while_normal_batch_entry_delivers() {
    let fixture = Fixture::new("events").await;
    let queue_arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:mixed-events");
    let rule_arn = format!("arn:aws:events:us-east-1:{ACCOUNT}:rule/mixed-events");
    let queue=fixture.sqs("CreateQueue",json!({"QueueName":"mixed-events","Attributes":{"Policy":json!({"Statement":{
        "Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":queue_arn,
        "Condition":{"ArnEquals":{"aws:SourceArn":rule_arn}}
    }}).to_string()}})).await;
    fixture.events("PutRule",json!({"Name":"mixed-events","EventPattern":json!({"source":["aws.s3","app.test"]}).to_string()})).await;
    fixture
        .events(
            "PutTargets",
            json!({"Rule":"mixed-events","Targets":[{"Id":"queue","Arn":queue_arn}]}),
        )
        .await;
    let result = fixture
        .events(
            "PutEvents",
            json!({"Entries":[
                {"Source":"aws.s3","DetailType":"spoof","Detail":"{}"},
                {"Source":"app.test","DetailType":"legitimate","Detail":"{}"}
            ]}),
        )
        .await;
    assert_eq!(result["FailedEntryCount"], 1);
    assert_eq!(
        result["Entries"][0]["ErrorCode"],
        "NotAuthorizedForSourceException"
    );
    assert!(result["Entries"][1]["EventId"].is_string());
    let received = fixture
        .sqs(
            "ReceiveMessage",
            json!({"QueueUrl":queue["QueueUrl"],"WaitTimeSeconds":1,"MaxNumberOfMessages":10}),
        )
        .await;
    assert_eq!(received["Messages"].as_array().unwrap().len(), 1);
    let event: Value =
        serde_json::from_str(received["Messages"][0]["Body"].as_str().unwrap()).unwrap();
    assert_eq!(event["source"], "app.test");
    assert_eq!(fixture.raw_call("events",Method::POST,"/",json!({"Entries":vec![json!({"Source":"app.test","DetailType":"limit","Detail":"{}"});11]}).to_string().into(),Some("PutEvents")).await.0,400);
    assert_eq!(fixture.raw_call("events",Method::POST,"/",json!({"Entries":[{"Source":"aws.partner/example","DetailType":"partner","Detail":"{}"}]}).to_string().into(),Some("PutPartnerEvents")).await.0,501);
}
