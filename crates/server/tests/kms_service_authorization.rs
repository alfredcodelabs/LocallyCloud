//! Native credential and key-policy composition across KMS, SSM and Secrets Manager.
#![cfg(feature = "services")]

use axum::body::to_bytes;
use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use locallycloud_iam_sts::enforcement::EnforcementMode;
use locallycloud_iam_sts::model::{AccessKey, IamUser};
use locallycloud_iam_sts::store::IamStore;
use locallycloud_iam_sts::sts::SessionStore;
use locallycloud_state::StateDb;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Once};
use std::time::Duration;

const ACCOUNT: &str = "000000000000";
const ADMIN: &str = "AKIAADMIN000000000001";
const ACTOR: &str = "AKIAACTOR000000000001";

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    registry: Arc<ServiceRegistry>,
    iam: Arc<IamStore>,
    _directory: Directory,
}

impl Fixture {
    fn new() -> Self {
        static MASTER: Once = Once::new();
        MASTER.call_once(|| {
            std::env::set_var(
                "LOCALLYCLOUD_KMS_MASTER_KEY",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            )
        });
        let directory = std::env::temp_dir().join(format!(
            "locallycloud-kms-authorization-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = Arc::new(StateDb::open(directory.join("state.sqlite3")).unwrap());
        let registry = ServiceRegistry::with_known_services();
        let iam = Arc::new(IamStore::new());
        for (name, key, actions) in [
            ("admin", ADMIN, json!("*")),
            ("actor", ACTOR, json!(["ssm:*", "secretsmanager:*"])),
        ] {
            iam.create_user(
                ACCOUNT,
                IamUser {
                    user_name: name.into(),
                    user_id: format!("AIDA{name}"),
                    arn: format!("arn:aws:iam::{ACCOUNT}:user/{name}"),
                    path: "/".into(),
                    create_date: "2026-01-01T00:00:00Z".into(),
                    tags: BTreeMap::new(),
                    attached_policies: Vec::new(),
                    inline_policies: BTreeMap::from([(
                        "test".into(),
                        json!({"Statement":{"Effect":"Allow","Action":actions,"Resource":"*"}})
                            .to_string(),
                    )]),
                    groups: Vec::new(),
                    permission_boundary: None,
                    access_keys: vec![AccessKey {
                        access_key_id: key.into(),
                        secret_access_key: "secret".into(),
                        status: "Active".into(),
                        create_date: "2026-01-01T00:00:00Z".into(),
                    }],
                },
            );
        }
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            iam.clone(),
            Arc::new(SessionStore::new()),
            EnforcementMode::Strict,
        );
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            ACCOUNT.into(),
        )));
        locallycloud_kms::register_with_state(&registry, db.clone()).unwrap();
        locallycloud_sqs::register_with_state(&registry, db.clone()).unwrap();
        locallycloud_ssm::register_with_state(&registry, db.clone()).unwrap();
        locallycloud_stepfunctions::register_with_state(&registry, db.clone()).unwrap();
        locallycloud_secretsmanager::register_with_state(&registry, db).unwrap();
        Self {
            registry,
            iam,
            _directory: Directory(directory),
        }
    }

    async fn call(&self, key: &str, service: &str, operation: &str, body: Value) -> (u16, Value) {
        self.call_with_headers(key, service, operation, body, http::HeaderMap::new())
            .await
    }

    async fn call_with_headers(
        &self,
        key: &str,
        service: &str,
        operation: &str,
        body: Value,
        extra_headers: http::HeaderMap,
    ) -> (u16, Value) {
        let prefix = match service {
            "ssm" => "AmazonSSM",
            "sqs" => "AmazonSQS",
            "states" => "AWSStepFunctions",
            "kms" => "TrentService",
            "secretsmanager" => "secretsmanager",
            _ => unreachable!(),
        };
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "content-type",
            if service == "states" {
                "application/x-amz-json-1.0"
            } else {
                "application/x-amz-json-1.1"
            }
            .parse()
            .unwrap(),
        );
        headers.insert(
            "x-amz-target",
            format!("{prefix}.{operation}").parse().unwrap(),
        );
        // These are trusted native-handler fixtures; ingress signature verification is tested separately.
        headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        headers.insert(http::header::AUTHORIZATION, format!("AWS4-HMAC-SHA256 Credential={key}/20261116/us-east-1/{service}/aws4_request, SignedHeaders=host, Signature=test").parse().unwrap());
        headers.insert(
            "x-locallycloud-verified-secure-transport",
            "true".parse().unwrap(),
        );
        headers.extend(extra_headers);
        let response = self
            .registry
            .native_handler(&ServiceName::new(service))
            .unwrap()
            .handle(ServiceRequest {
                method: http::Method::POST,
                uri: "/".parse().unwrap(),
                headers,
                body: body.to_string().into(),
                region: "us-east-1".into(),
                account_id: ACCOUNT.into(),
                request_id: "kms-authorization-test".into(),
            })
            .await;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        (
            status,
            if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        )
    }

    async fn ok(&self, key: &str, service: &str, operation: &str, body: Value) -> Value {
        let (status, result) = self.call(key, service, operation, body).await;
        assert_eq!(status, 200, "{service}:{operation}: {result}");
        result
    }

    fn actor_policy(&self, statements: Value) {
        assert!(self.iam.update_user(ACCOUNT, "actor", |user| {
            user.inline_policies = if statements.as_array().is_some_and(Vec::is_empty) {
                BTreeMap::new()
            } else {
                BTreeMap::from([("test".into(), json!({"Statement":statements}).to_string())])
            };
        }));
    }

    async fn key(&self, actor_direct: bool) -> String {
        let principals = if actor_direct {
            json!([
                format!("arn:aws:iam::{ACCOUNT}:user/admin"),
                format!("arn:aws:iam::{ACCOUNT}:user/actor")
            ])
        } else {
            json!(format!("arn:aws:iam::{ACCOUNT}:user/admin"))
        };
        let created = self.ok(ADMIN, "kms", "CreateKey", json!({"Policy":json!({"Statement":{"Effect":"Allow","Principal":{"AWS":principals},"Action":"kms:*","Resource":"*"}}).to_string()})).await;
        created["KeyMetadata"]["KeyId"].as_str().unwrap().into()
    }
}

#[tokio::test]
async fn explicit_customer_key_policy_and_iam_deny_gate_ssm_and_secrets_without_partial_writes() {
    let fixture = Fixture::new();
    let denied = fixture.key(false).await;
    fixture.actor_policy(
        json!({"Effect":"Allow","Action":["ssm:*","secretsmanager:*","kms:*"],"Resource":"*"}),
    );
    for (service, operation, body) in [
        (
            "ssm",
            "PutParameter",
            json!({"Name":"/denied","Value":"secret","Type":"SecureString","KeyId":denied}),
        ),
        (
            "secretsmanager",
            "CreateSecret",
            json!({"Name":"denied","SecretString":"secret","KmsKeyId":denied}),
        ),
    ] {
        let (status, error) = fixture.call(ACTOR, service, operation, body).await;
        assert!(status >= 400, "{service}: {error}");
    }
    assert_eq!(
        fixture
            .call(ADMIN, "ssm", "GetParameter", json!({"Name":"/denied"}))
            .await
            .1["__type"],
        "ParameterNotFound"
    );
    assert_eq!(
        fixture
            .call(
                ADMIN,
                "secretsmanager",
                "DescribeSecret",
                json!({"SecretId":"denied"})
            )
            .await
            .1["__type"],
        "ResourceNotFoundException"
    );

    let allowed = fixture.key(true).await;
    fixture.actor_policy(
        json!({"Effect":"Allow","Action":["ssm:*","secretsmanager:*"],"Resource":"*"}),
    );
    fixture
        .ok(
            ACTOR,
            "ssm",
            "PutParameter",
            json!({"Name":"/allowed","Value":"secret","Type":"SecureString","KeyId":allowed}),
        )
        .await;
    fixture
        .ok(
            ACTOR,
            "secretsmanager",
            "CreateSecret",
            json!({"Name":"allowed","SecretString":"secret","KmsKeyId":allowed}),
        )
        .await;
    assert_eq!(
        fixture
            .ok(
                ACTOR,
                "ssm",
                "GetParameter",
                json!({"Name":"/allowed","WithDecryption":true})
            )
            .await["Parameter"]["Value"],
        "secret"
    );
    assert_eq!(
        fixture
            .ok(
                ACTOR,
                "secretsmanager",
                "GetSecretValue",
                json!({"SecretId":"allowed"})
            )
            .await["SecretString"],
        "secret"
    );

    fixture.actor_policy(json!([
        {"Effect":"Allow","Action":["ssm:*","secretsmanager:*"],"Resource":"*"},
        {"Effect":"Deny","Action":["kms:Encrypt","kms:Decrypt"],"Resource":"*"}
    ]));
    for (service, operation, body) in [
        (
            "ssm",
            "PutParameter",
            json!({"Name":"/allowed","Value":"modified","Type":"SecureString","KeyId":allowed,"Overwrite":true}),
        ),
        (
            "secretsmanager",
            "PutSecretValue",
            json!({"SecretId":"allowed","SecretString":"modified"}),
        ),
        (
            "ssm",
            "GetParameter",
            json!({"Name":"/allowed","WithDecryption":true}),
        ),
        (
            "secretsmanager",
            "GetSecretValue",
            json!({"SecretId":"allowed"}),
        ),
    ] {
        let (status, error) = fixture.call(ACTOR, service, operation, body).await;
        assert!(status >= 400, "{service}:{operation}: {error}");
    }
    assert_eq!(
        fixture
            .ok(
                ADMIN,
                "ssm",
                "GetParameter",
                json!({"Name":"/allowed","WithDecryption":true})
            )
            .await["Parameter"]["Value"],
        "secret"
    );
    assert_eq!(
        fixture
            .ok(
                ADMIN,
                "secretsmanager",
                "GetSecretValue",
                json!({"SecretId":"allowed"})
            )
            .await["SecretString"],
        "secret"
    );
}

#[tokio::test]
async fn customer_default_policy_requires_iam_delegation_while_service_managed_defaults_work() {
    let fixture = Fixture::new();
    let key =
        fixture.ok(ADMIN, "kms", "CreateKey", json!({})).await["KeyMetadata"]["KeyId"].clone();
    let body = json!({"Name":"/delegated","Value":"secret","Type":"SecureString","KeyId":key});
    assert!(
        fixture
            .call(ACTOR, "ssm", "PutParameter", body.clone())
            .await
            .0
            >= 400
    );
    fixture.actor_policy(json!({"Effect":"Allow","Action":["ssm:*","secretsmanager:*","kms:Encrypt","kms:Decrypt"],"Resource":"*"}));
    fixture.ok(ACTOR, "ssm", "PutParameter", body).await;
    fixture
        .ok(
            ACTOR,
            "secretsmanager",
            "CreateSecret",
            json!({"Name":"delegated","SecretString":"secret","KmsKeyId":key}),
        )
        .await;
    fixture.actor_policy(
        json!({"Effect":"Allow","Action":["ssm:*","secretsmanager:*"],"Resource":"*"}),
    );
    fixture
        .ok(
            ACTOR,
            "ssm",
            "PutParameter",
            json!({"Name":"/managed","Value":"secret","Type":"SecureString"}),
        )
        .await;
    fixture
        .ok(
            ACTOR,
            "secretsmanager",
            "CreateSecret",
            json!({"Name":"managed","SecretString":"secret"}),
        )
        .await;
    fixture
        .ok(
            ACTOR,
            "ssm",
            "GetParameter",
            json!({"Name":"/managed","WithDecryption":true}),
        )
        .await;
    fixture
        .ok(
            ACTOR,
            "secretsmanager",
            "GetSecretValue",
            json!({"SecretId":"managed"}),
        )
        .await;
}

#[tokio::test]
async fn ssm_authorizes_mutations_and_the_requested_path_action_without_get_parameter_permission() {
    let fixture = Fixture::new();
    fixture
        .ok(
            ADMIN,
            "ssm",
            "PutParameter",
            json!({"Name":"/app/child","Value":"plain"}),
        )
        .await;
    fixture.actor_policy(json!([
        {"Effect":"Allow","Action":"ssm:GetParametersByPath","Resource":format!("arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/app")},
        {"Effect":"Deny","Action":"ssm:GetParameter","Resource":"*"}
    ]));
    let result = fixture
        .ok(
            ACTOR,
            "ssm",
            "GetParametersByPath",
            json!({"Path":"/app","Recursive":true}),
        )
        .await;
    assert_eq!(result["Parameters"][0]["Name"], "/app/child");
    for (operation, body) in [
        ("GetParameter", json!({"Name":"/app/child"})),
        (
            "PutParameter",
            json!({"Name":"/app/child","Value":"modified","Overwrite":true}),
        ),
        ("DeleteParameter", json!({"Name":"/app/child"})),
        ("DescribeParameters", json!({})),
        (
            "AddTagsToResource",
            json!({"ResourceType":"Parameter","ResourceId":"/app/child","Tags":[{"Key":"team","Value":"test"}]}),
        ),
        (
            "RemoveTagsFromResource",
            json!({"ResourceType":"Parameter","ResourceId":"/app/child","TagKeys":["team"]}),
        ),
        (
            "ListTagsForResource",
            json!({"ResourceType":"Parameter","ResourceId":"/app/child"}),
        ),
    ] {
        let (status, error) = fixture.call(ACTOR, "ssm", operation, body).await;
        assert_eq!(status, 403, "{operation}: {error}");
        assert_eq!(error["__type"], "AccessDeniedException");
    }
    assert_eq!(
        fixture
            .ok(ADMIN, "ssm", "GetParameter", json!({"Name":"/app/child"}))
            .await["Parameter"]["Value"],
        "plain"
    );
    fixture.actor_policy(json!({"Effect":"Allow","Action":"ssm:GetParametersByPath","Resource":"*","Condition":{"StringEquals":{"ssm:Recursive":"false"}}}));
    fixture
        .ok(ACTOR, "ssm", "GetParametersByPath", json!({"Path":"/app"}))
        .await;
    assert_eq!(
        fixture
            .call(
                ACTOR,
                "ssm",
                "GetParametersByPath",
                json!({"Path":"/app","Recursive":true})
            )
            .await
            .0,
        403
    );
}

#[tokio::test]
async fn secrets_resource_policy_grants_access_without_identity_allow_but_not_over_explicit_deny() {
    let fixture = Fixture::new();
    fixture
        .ok(
            ADMIN,
            "secretsmanager",
            "CreateSecret",
            json!({"Name":"resource-grant","SecretString":"secret"}),
        )
        .await;
    fixture.ok(ADMIN, "secretsmanager", "PutResourcePolicy", json!({"SecretId":"resource-grant","ResourcePolicy":json!({"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:user/actor")},"Action":"secretsmanager:GetSecretValue","Resource":"*"}}).to_string()})).await;
    fixture.actor_policy(json!([]));
    assert_eq!(
        fixture
            .ok(
                ACTOR,
                "secretsmanager",
                "GetSecretValue",
                json!({"SecretId":"resource-grant"})
            )
            .await["SecretString"],
        "secret"
    );
    fixture.actor_policy(
        json!({"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*"}),
    );
    assert_eq!(
        fixture
            .call(
                ACTOR,
                "secretsmanager",
                "GetSecretValue",
                json!({"SecretId":"resource-grant"})
            )
            .await
            .1["__type"],
        "AccessDeniedException"
    );
}

#[tokio::test]
async fn sqs_direct_key_grants_preserve_queue_context_old_message_keys_and_explicit_denies() {
    let fixture = Fixture::new();
    fixture.actor_policy(json!({"Effect":"Allow","Action":"sqs:*","Resource":"*"}));
    let key = fixture.key(true).await;
    let created = fixture
        .ok(
            ADMIN,
            "sqs",
            "CreateQueue",
            json!({"QueueName":"kms-direct-grant","Attributes":{"KmsMasterKeyId":key}}),
        )
        .await;
    let url = &created["QueueUrl"];
    let attributes = fixture
        .ok(
            ADMIN,
            "sqs",
            "GetQueueAttributes",
            json!({"QueueUrl":url,"AttributeNames":["QueueArn"]}),
        )
        .await;
    let arn = &attributes["Attributes"]["QueueArn"];
    fixture.ok(ADMIN, "kms", "PutKeyPolicy", json!({"KeyId":key,"Policy":json!({"Statement":[
        {"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:user/admin")},"Action":"kms:*","Resource":"*"},
        {"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:user/actor")},"Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*","Condition":{"StringEquals":{"kms:ViaService":"sqs.us-east-1.amazonaws.com","kms:EncryptionContext:aws:sqs:queuearn":arn}}}
    ]}).to_string()})).await;
    fixture
        .ok(
            ACTOR,
            "sqs",
            "SendMessage",
            json!({"QueueUrl":url,"MessageBody":"direct"}),
        )
        .await;
    assert_eq!(
        fixture
            .ok(
                ACTOR,
                "sqs",
                "ReceiveMessage",
                json!({"QueueUrl":url,"VisibilityTimeout":0})
            )
            .await["Messages"][0]["Body"],
        "direct"
    );
    let other = fixture.key(false).await;
    fixture
        .ok(
            ADMIN,
            "sqs",
            "SetQueueAttributes",
            json!({"QueueUrl":url,"Attributes":{"KmsMasterKeyId":other}}),
        )
        .await;
    assert_eq!(
        fixture
            .ok(
                ACTOR,
                "sqs",
                "ReceiveMessage",
                json!({"QueueUrl":url,"VisibilityTimeout":0})
            )
            .await["Messages"][0]["Body"],
        "direct"
    );
    fixture.actor_policy(json!([
        {"Effect":"Allow","Action":"sqs:*","Resource":"*"},
        {"Effect":"Deny","Action":"kms:Decrypt","Resource":"*"}
    ]));
    assert_eq!(
        fixture
            .call(
                ACTOR,
                "sqs",
                "ReceiveMessage",
                json!({"QueueUrl":url,"VisibilityTimeout":0})
            )
            .await
            .1["__type"],
        "com.amazonaws.sqs#KMS.AccessDeniedException"
    );
    fixture.actor_policy(json!({"Effect":"Allow","Action":"sqs:*","Resource":"*"}));
    fixture
        .ok(
            ADMIN,
            "sqs",
            "SetQueueAttributes",
            json!({"QueueUrl":url,"Attributes":{"KmsMasterKeyId":key}}),
        )
        .await;
    fixture
        .ok(
            ACTOR,
            "sqs",
            "SendMessage",
            json!({"QueueUrl":url,"MessageBody":"second"}),
        )
        .await;
    fixture.actor_policy(json!([
        {"Effect":"Allow","Action":"sqs:*","Resource":"*"},
        {"Effect":"Deny","Action":"kms:GenerateDataKey","Resource":"*"}
    ]));
    assert_eq!(
        fixture
            .call(
                ACTOR,
                "sqs",
                "SendMessage",
                json!({"QueueUrl":url,"MessageBody":"denied"})
            )
            .await
            .1["__type"],
        "com.amazonaws.sqs#KMS.AccessDeniedException"
    );
    assert_eq!(
        fixture
            .ok(
                ADMIN,
                "sqs",
                "GetQueueAttributes",
                json!({"QueueUrl":url,"AttributeNames":["ApproximateNumberOfMessages"]})
            )
            .await["Attributes"]["ApproximateNumberOfMessages"],
        "2"
    );
}

#[tokio::test]
async fn encrypted_queue_delivery_requires_an_attested_service_and_its_key_policy_grant() {
    let fixture = Fixture::new();
    let key = fixture.key(false).await;
    let created = fixture
        .ok(
            ADMIN,
            "sqs",
            "CreateQueue",
            json!({"QueueName":"kms-service-grant","Attributes":{"KmsMasterKeyId":key}}),
        )
        .await;
    let url = created["QueueUrl"].as_str().unwrap();
    let attributes = fixture
        .ok(
            ADMIN,
            "sqs",
            "GetQueueAttributes",
            json!({"QueueUrl":url,"AttributeNames":["QueueArn"]}),
        )
        .await;
    let arn = &attributes["Attributes"]["QueueArn"];
    let source = format!("arn:aws:events:us-east-1:{ACCOUNT}:rule/orders");
    fixture.ok(ADMIN, "sqs", "SetQueueAttributes", json!({"QueueUrl":url,"Attributes":{"Policy":json!({"Statement":{"Effect":"Allow","Principal":{"Service":["events.amazonaws.com","sns.amazonaws.com"]},"Action":"sqs:SendMessage","Resource":arn,"Condition":{"ArnEquals":{"aws:SourceArn":[source,format!("arn:aws:sns:us-east-1:{ACCOUNT}:orders")]}}}}).to_string()}})).await;
    fixture.ok(ADMIN, "kms", "PutKeyPolicy", json!({"KeyId":key,"Policy":json!({"Statement":[
        {"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:user/admin")},"Action":"kms:*","Resource":"*"},
        {"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*","Condition":{"StringEquals":{"kms:ViaService":"sqs.us-east-1.amazonaws.com"}}}
    ]}).to_string()})).await;
    for (principal, internal, expected) in [
        ("events.amazonaws.com", true, 200),
        ("sns.amazonaws.com", true, 400),
        ("events.amazonaws.com", false, 403),
    ] {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "content-type",
            "application/x-amz-json-1.0".parse().unwrap(),
        );
        headers.insert("x-amz-target", "AmazonSQS.SendMessage".parse().unwrap());
        headers.insert(
            "x-locallycloud-caller-principal",
            principal.parse().unwrap(),
        );
        headers.insert(
            "x-locallycloud-source-arn",
            if principal == "sns.amazonaws.com" {
                format!("arn:aws:sns:us-east-1:{ACCOUNT}:orders")
            } else {
                source.clone()
            }
            .parse()
            .unwrap(),
        );
        headers.insert("x-locallycloud-source-account", ACCOUNT.parse().unwrap());
        if internal {
            headers.insert(
                "x-locallycloud-verified-internal-scope",
                "1".parse().unwrap(),
            );
        } else {
            headers.insert(
                "x-locallycloud-verified-secure-transport",
                "true".parse().unwrap(),
            );
            headers.insert(
                "x-locallycloud-verified-external-sigv4",
                "1".parse().unwrap(),
            );
            headers.insert(http::header::AUTHORIZATION, format!("AWS4-HMAC-SHA256 Credential={ACTOR}/20261116/us-east-1/sqs/aws4_request, SignedHeaders=host, Signature=test").parse().unwrap());
        }
        let response = fixture
            .registry
            .native_handler(&ServiceName::new("sqs"))
            .unwrap()
            .handle(ServiceRequest {
                method: http::Method::POST,
                uri: "/".parse().unwrap(),
                headers,
                body: json!({"QueueUrl":url,"MessageBody":"service"})
                    .to_string()
                    .into(),
                account_id: ACCOUNT.into(),
                region: "us-east-1".into(),
                request_id: "kms-service-test".into(),
            })
            .await;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            status, expected,
            "principal={principal}, internal={internal}: {result}"
        );
        if internal && status != 200 {
            assert_eq!(
                result["__type"],
                "com.amazonaws.sqs#KMS.AccessDeniedException"
            );
        }
    }
    assert_eq!(
        fixture
            .ok(
                ADMIN,
                "sqs",
                "GetQueueAttributes",
                json!({"QueueUrl":url,"AttributeNames":["ApproximateNumberOfMessages"]})
            )
            .await["Attributes"]["ApproximateNumberOfMessages"],
        "1"
    );
}

fn network_headers(secure: bool, ip: &str) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-locallycloud-verified-secure-transport",
        if secure { "true" } else { "false" }.parse().unwrap(),
    );
    headers.insert("x-locallycloud-trusted-peer-ip", ip.parse().unwrap());
    // Claimed forwarding metadata must never replace Core's physical connection context.
    headers.insert("x-forwarded-proto", "https".parse().unwrap());
    headers.insert("x-forwarded-for", "198.51.100.20".parse().unwrap());
    headers
}

#[tokio::test]
async fn public_iam_network_conditions_use_core_transport_and_peer_in_every_handler() {
    let fixture = Fixture::new();
    let key = fixture.key(true).await;
    fixture
        .ok(
            ADMIN,
            "ssm",
            "PutParameter",
            json!({"Name":"/network","Value":"plain"}),
        )
        .await;
    fixture
        .ok(
            ADMIN,
            "secretsmanager",
            "CreateSecret",
            json!({"Name":"network","SecretString":"secret"}),
        )
        .await;
    let operations = [
        ("kms", "DescribeKey", json!({"KeyId":key})),
        ("kms", "ListKeys", json!({})),
        ("ssm", "GetParameter", json!({"Name":"/network"})),
        (
            "secretsmanager",
            "DescribeSecret",
            json!({"SecretId":"network"}),
        ),
    ];
    for condition in [
        json!({"Bool":{"aws:SecureTransport":"false"}}),
        json!({"IpAddress":{"aws:SourceIp":"127.0.0.1/32"}}),
    ] {
        fixture.actor_policy(json!([
            {"Effect":"Allow","Action":["kms:*","ssm:*","secretsmanager:*"],"Resource":"*"},
            {"Effect":"Deny","Action":["kms:*","ssm:*","secretsmanager:*"],"Resource":"*","Condition":condition}
        ]));
        let transport_case = condition.get("Bool").is_some();
        for (service, operation, body) in &operations {
            let denied_headers = network_headers(!transport_case, "127.0.0.1");
            let (status, result) = fixture
                .call_with_headers(ACTOR, service, operation, body.clone(), denied_headers)
                .await;
            assert!(
                status >= 400,
                "{service}:{operation} allowed despite network deny: {result}"
            );
            assert_eq!(result["__type"], "AccessDeniedException");
            let allowed_headers = network_headers(
                true,
                if transport_case {
                    "127.0.0.1"
                } else {
                    "198.51.100.10"
                },
            );
            let (status, result) = fixture
                .call_with_headers(ACTOR, service, operation, body.clone(), allowed_headers)
                .await;
            assert_eq!(
                status, 200,
                "{service}:{operation} denied despite allowed connection: {result}"
            );
        }
    }
}

#[tokio::test]
async fn native_kms_forward_access_sessions_redact_the_original_clients_network_context() {
    let fixture = Fixture::new();
    let key = fixture.key(true).await;
    fixture.actor_policy(json!([
        {"Effect":"Allow","Action":["ssm:*","secretsmanager:*"],"Resource":"*"},
        {"Effect":"Deny","Action":"kms:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}},
        {"Effect":"Deny","Action":"kms:*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"127.0.0.1/32"}}}
    ]));
    for (service, operation, body) in [
        (
            "ssm",
            "PutParameter",
            json!({"Name":"/redacted","Value":"secret","Type":"SecureString","KeyId":key}),
        ),
        (
            "ssm",
            "GetParameter",
            json!({"Name":"/redacted","WithDecryption":true}),
        ),
        (
            "secretsmanager",
            "CreateSecret",
            json!({"Name":"redacted","SecretString":"secret","KmsKeyId":key}),
        ),
        (
            "secretsmanager",
            "GetSecretValue",
            json!({"SecretId":"redacted"}),
        ),
    ] {
        let (status, result) = fixture
            .call_with_headers(
                ACTOR,
                service,
                operation,
                body,
                network_headers(false, "127.0.0.1"),
            )
            .await;
        assert_eq!(
            status, 200,
            "{service}:{operation} leaked client network context into KMS hop: {result}"
        );
    }
}

#[tokio::test]
async fn scoped_sdk_kms_calls_use_the_execution_role_and_cannot_forge_it_externally() {
    use locallycloud_core::integration::identity::{CallerIdentity, IdentityPropagator};
    use locallycloud_iam_sts::model::IamRole;
    let fixture = Fixture::new();
    let role_arn = format!("arn:aws:iam::{ACCOUNT}:role/sdk-key-user");
    fixture.iam.create_role(ACCOUNT, IamRole {
        role_name: "sdk-key-user".into(), role_id: "AROASDKKEYUSER".into(), arn: role_arn.clone(), path: "/".into(), create_date: "2026-01-01T00:00:00Z".into(),
        assume_role_policy_document: json!({"Statement":{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}}).to_string(), description: None, max_session_duration:3600, tags: BTreeMap::new(), attached_policies: Vec::new(),
        inline_policies: BTreeMap::from([("kms".into(),json!({"Statement":{"Effect":"Allow","Action":"kms:*","Resource":"*"}}).to_string())]), permission_boundary:None,
    });
    let delegated =
        fixture.ok(ADMIN, "kms", "CreateKey", json!({})).await["KeyMetadata"]["KeyId"].clone();
    let excluded = fixture.key(false).await;
    let granted = fixture.ok(ADMIN,"kms","CreateKey",json!({"Policy":json!({"Statement":{"Effect":"Allow","Principal":{"AWS":[format!("arn:aws:iam::{ACCOUNT}:user/admin"),role_arn]},"Action":"kms:*","Resource":"*"}}).to_string()})).await["KeyMetadata"]["KeyId"].clone();
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "content-type",
        "application/x-amz-json-1.1".parse().unwrap(),
    );
    headers.insert("x-amz-target", "TrentService.Encrypt".parse().unwrap());
    IdentityPropagator::attach(
        &mut headers,
        &CallerIdentity::AssumedRole {
            role_arn: role_arn.clone(),
            session_name: "sdk-task".into(),
        },
    );
    let dispatcher = fixture.registry.internal_dispatcher().unwrap();
    let mut create = headers.clone();
    create.insert("x-amz-target", "TrentService.CreateKey".parse().unwrap());
    assert_eq!(
        dispatcher
            .dispatch_scoped(
                &http::Method::POST,
                &"/".parse().unwrap(),
                &create,
                "{}".into(),
                "sdk-create",
                ACCOUNT,
                "us-east-1"
            )
            .await
            .status(),
        200
    );
    for (key, expected) in [
        (&delegated, 200),
        (&Value::String(excluded), 400),
        (&granted, 200),
    ] {
        let response = dispatcher
            .dispatch_scoped(
                &http::Method::POST,
                &"/".parse().unwrap(),
                &headers,
                json!({"KeyId":key,"Plaintext":"c2VjcmV0"})
                    .to_string()
                    .into(),
                "sdk-kms",
                ACCOUNT,
                "us-east-1",
            )
            .await;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status, expected, "{result}");
        if status == 400 {
            assert_eq!(result["__type"], "AccessDeniedException");
        }
    }
    // Resource-policy grants may supply the allow, while the role's explicit denies remain binding.
    fixture
        .iam
        .update_role(ACCOUNT, "sdk-key-user", |role| role.inline_policies.clear());
    assert_eq!(
        dispatcher
            .dispatch_scoped(
                &http::Method::POST,
                &"/".parse().unwrap(),
                &create,
                "{}".into(),
                "sdk-create-denied",
                ACCOUNT,
                "us-east-1"
            )
            .await
            .status(),
        400
    );
    let response = dispatcher
        .dispatch_scoped(
            &http::Method::POST,
            &"/".parse().unwrap(),
            &headers,
            json!({"KeyId":granted,"Plaintext":"c2VjcmV0"})
                .to_string()
                .into(),
            "sdk-direct-key",
            ACCOUNT,
            "us-east-1",
        )
        .await;
    assert_eq!(response.status(), 200);
    fixture.iam.update_role(ACCOUNT, "sdk-key-user", |role| {
        role.inline_policies.insert(
            "deny".into(),
            json!({"Statement":{"Effect":"Deny","Action":"kms:Encrypt","Resource":"*"}})
                .to_string(),
        );
    });
    let response = dispatcher
        .dispatch_scoped(
            &http::Method::POST,
            &"/".parse().unwrap(),
            &headers,
            json!({"KeyId":granted,"Plaintext":"c2VjcmV0"})
                .to_string()
                .into(),
            "sdk-explicit-deny",
            ACCOUNT,
            "us-east-1",
        )
        .await;
    assert_eq!(response.status(), 400);
    // A public caller carrying the same principal string has no internal attestation.
    fixture
        .iam
        .update_role(ACCOUNT, "sdk-key-user", |role| role.inline_policies.clear());
    let mut spoof = http::HeaderMap::new();
    IdentityPropagator::attach(
        &mut spoof,
        &CallerIdentity::AssumedRole {
            role_arn,
            session_name: "sdk-task".into(),
        },
    );
    let (status, error) = fixture
        .call_with_headers(
            ACTOR,
            "kms",
            "Encrypt",
            json!({"KeyId":granted,"Plaintext":"c2VjcmV0"}),
            spoof,
        )
        .await;
    assert_eq!(status, 400, "{error}");
    assert_eq!(error["__type"], "AccessDeniedException");
}

#[tokio::test]
async fn stepfunctions_defers_native_resource_grants_to_the_destination_without_ignoring_denies() {
    use locallycloud_iam_sts::model::IamRole;
    let fixture = Fixture::new();
    let role = format!("arn:aws:iam::{ACCOUNT}:role/workflow-resource-grant");
    fixture.iam.create_role(ACCOUNT,IamRole {
        role_name:"workflow-resource-grant".into(),role_id:"AROAWORKFLOWRESOURCE".into(),arn:role.clone(),path:"/".into(),create_date:"2026-01-01T00:00:00Z".into(),
        assume_role_policy_document:json!({"Statement":{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}}).to_string(),description:None,max_session_duration:3600,tags:BTreeMap::new(),attached_policies:Vec::new(),inline_policies:BTreeMap::new(),permission_boundary:None,
    });
    let queue = fixture
        .ok(
            ADMIN,
            "sqs",
            "CreateQueue",
            json!({"QueueName":"workflow-grant"}),
        )
        .await;
    let url = &queue["QueueUrl"];
    let attrs = fixture
        .ok(
            ADMIN,
            "sqs",
            "GetQueueAttributes",
            json!({"QueueUrl":url,"AttributeNames":["QueueArn"]}),
        )
        .await;
    let queue_policy=json!({"Statement":{"Effect":"Allow","Principal":{"AWS":role},"Action":"sqs:SendMessage","Resource":attrs["Attributes"]["QueueArn"]}}).to_string();
    fixture
        .ok(
            ADMIN,
            "sqs",
            "SetQueueAttributes",
            json!({"QueueUrl":url,"Attributes":{"Policy":queue_policy}}),
        )
        .await;
    let definition = json!({"StartAt":"Send","States":{"Send":{"Type":"Task","Resource":"arn:aws:states:::sqs:sendMessage","Parameters":{"QueueUrl":url,"MessageBody":"resource-policy"},"End":true}}});
    let machine = fixture
        .ok(
            ADMIN,
            "states",
            "CreateStateMachine",
            json!({"name":"resource-grant","roleArn":role,"definition":definition.to_string()}),
        )
        .await;
    let arn = &machine["stateMachineArn"];
    for (name, expected) in [
        ("granted", "SUCCEEDED"),
        ("missing-policy", "FAILED"),
        ("explicit-deny", "FAILED"),
    ] {
        if name == "missing-policy" {
            fixture
                .ok(
                    ADMIN,
                    "sqs",
                    "SetQueueAttributes",
                    json!({"QueueUrl":url,"Attributes":{"Policy":""}}),
                )
                .await;
        } else if name == "explicit-deny" {
            fixture
                .ok(
                    ADMIN,
                    "sqs",
                    "SetQueueAttributes",
                    json!({"QueueUrl":url,"Attributes":{"Policy":queue_policy}}),
                )
                .await;
            fixture.iam.update_role(ACCOUNT,"workflow-resource-grant",|role| {
                role.inline_policies.insert("deny".into(),json!({"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}).to_string());
            });
        }
        let started = fixture
            .ok(
                ADMIN,
                "states",
                "StartExecution",
                json!({"stateMachineArn":arn,"name":name}),
            )
            .await;
        let execution = &started["executionArn"];
        let final_status = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = fixture
                    .ok(
                        ADMIN,
                        "states",
                        "DescribeExecution",
                        json!({"executionArn":execution}),
                    )
                    .await;
                if status["status"] != "RUNNING" {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(final_status["status"], expected, "{final_status}");
        if name == "missing-policy" {
            let before = fixture
                .ok(
                    ADMIN,
                    "states",
                    "GetExecutionHistory",
                    json!({"executionArn":execution}),
                )
                .await["events"]
                .as_array()
                .unwrap()
                .len();
            fixture
                .ok(
                    ADMIN,
                    "sqs",
                    "SetQueueAttributes",
                    json!({"QueueUrl":url,"Attributes":{"Policy":queue_policy}}),
                )
                .await;
            fixture
                .ok(
                    ADMIN,
                    "states",
                    "RedriveExecution",
                    json!({"executionArn":execution}),
                )
                .await;
            let redriven = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let status = fixture
                        .ok(
                            ADMIN,
                            "states",
                            "DescribeExecution",
                            json!({"executionArn":execution}),
                        )
                        .await;
                    if status["status"] != "RUNNING" {
                        break status;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(redriven["status"], "SUCCEEDED", "{redriven}");
            assert_eq!(redriven["redriveCount"], 1);
            let history = fixture
                .ok(
                    ADMIN,
                    "states",
                    "GetExecutionHistory",
                    json!({"executionArn":execution}),
                )
                .await;
            let events = history["events"].as_array().unwrap();
            assert!(events.len() > before);
            assert!(events
                .iter()
                .any(|event| event["type"] == "ExecutionRedriven"));
            for (index, event) in events.iter().enumerate() {
                assert_eq!(event["id"], (index + 1) as u64);
            }
        }
    }
    assert_eq!(
        fixture
            .ok(
                ADMIN,
                "sqs",
                "GetQueueAttributes",
                json!({"QueueUrl":url,"AttributeNames":["ApproximateNumberOfMessages"]})
            )
            .await["Attributes"]["ApproximateNumberOfMessages"],
        "2"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_operators_and_roles_keep_destination_and_pass_role_checks() {
    use locallycloud_core::integration::identity::{
        CallerIdentity, IdentityPropagator, PRINCIPAL_HEADER,
    };
    use locallycloud_iam_sts::model::IamRole;
    let fixture = Fixture::new();
    locallycloud_firehose::register(&fixture.registry);
    let role_arn = format!("arn:aws:iam::{ACCOUNT}:role/scoped-operator");
    fixture.iam.create_role(ACCOUNT, IamRole {
        role_name:"scoped-operator".into(),role_id:"AROASCOPED".into(),arn:role_arn.clone(),path:"/".into(),create_date:"2026-01-01T00:00:00Z".into(),
        assume_role_policy_document:json!({"Statement":{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}}).to_string(),
        description:None,max_session_duration:3600,tags:BTreeMap::new(),attached_policies:Vec::new(),permission_boundary:None,
        inline_policies:BTreeMap::from([("allow".into(),json!({"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}).to_string())]),
    });
    let dispatcher = fixture.registry.internal_dispatcher().unwrap();
    let cases = [
        (
            "AmazonSSM.PutParameter",
            json!({"Name":"/scoped/operator","Type":"String","Value":"ok","Overwrite":true}),
        ),
        ("Firehose_20150804.ListDeliveryStreams", json!({})),
        (
            "AWSStepFunctions.CreateStateMachine",
            json!({"name":"scoped-operator","roleArn":role_arn,"definition":json!({"StartAt":"Done","States":{"Done":{"Type":"Succeed"}}}).to_string()}),
        ),
    ];
    for delegated in [false, true] {
        for (target, mut body) in cases.clone() {
            if delegated && target.starts_with("AWSStepFunctions") {
                body["name"] = json!("scoped-role");
            }
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "content-type",
                "application/x-amz-json-1.1".parse().unwrap(),
            );
            headers.insert("x-amz-target", target.parse().unwrap());
            let service = match target.split('.').next().unwrap() {
                "AmazonSSM" => "ssm",
                "Firehose_20150804" => "firehose",
                _ => "states",
            };
            headers.insert(
                http::header::AUTHORIZATION,
                format!(
                    "AWS4-HMAC-SHA256 Credential={ADMIN}/20261116/us-east-1/{service}/aws4_request"
                )
                .parse()
                .unwrap(),
            );
            if delegated {
                IdentityPropagator::attach(
                    &mut headers,
                    &CallerIdentity::AssumedRole {
                        role_arn: role_arn.clone(),
                        session_name: "operator".into(),
                    },
                );
            } else {
                headers.insert(
                    PRINCIPAL_HEADER,
                    format!("arn:aws:iam::{ACCOUNT}:user/admin")
                        .parse()
                        .unwrap(),
                );
            }
            let response = dispatcher
                .dispatch_scoped(
                    &http::Method::POST,
                    &"/".parse().unwrap(),
                    &headers,
                    body.to_string().into(),
                    "scoped-operator",
                    ACCOUNT,
                    "us-east-1",
                )
                .await;
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            assert_eq!(
                status,
                200,
                "{target} delegated={delegated}: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }
    // Original admin credentials cannot override the execution role's PassRole denial.
    fixture.iam.update_role(ACCOUNT, "scoped-operator", |role| {
        role.inline_policies.insert(
            "deny-pass-role".into(),
            json!({"Statement":{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}})
                .to_string(),
        );
    });
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-amz-target",
        "AWSStepFunctions.CreateStateMachine".parse().unwrap(),
    );
    headers.insert(
        http::header::AUTHORIZATION,
        format!("AWS4-HMAC-SHA256 Credential={ADMIN}/20261116/us-east-1/states/aws4_request")
            .parse()
            .unwrap(),
    );
    IdentityPropagator::attach(
        &mut headers,
        &CallerIdentity::AssumedRole {
            role_arn,
            session_name: "operator".into(),
        },
    );
    let mut body = cases[2].1.clone();
    body["name"] = json!("denied-pass-role");
    let response = dispatcher
        .dispatch_scoped(
            &http::Method::POST,
            &"/".parse().unwrap(),
            &headers,
            body.to_string().into(),
            "denied-pass-role",
            ACCOUNT,
            "us-east-1",
        )
        .await;
    assert_eq!(response.status(), 403);
    fixture.iam.update_role(ACCOUNT, "scoped-operator", |role| {
        role.inline_policies.clear()
    });
    for (target, body) in &cases[..2] {
        let service = if target.starts_with("AmazonSSM") {
            "ssm"
        } else {
            "firehose"
        };
        headers.insert("x-amz-target", target.parse().unwrap());
        headers.insert(
            http::header::AUTHORIZATION,
            format!(
                "AWS4-HMAC-SHA256 Credential={ADMIN}/20261116/us-east-1/{service}/aws4_request"
            )
            .parse()
            .unwrap(),
        );
        let response = dispatcher
            .dispatch_scoped(
                &http::Method::POST,
                &"/".parse().unwrap(),
                &headers,
                body.to_string().into(),
                "denied-role-action",
                ACCOUNT,
                "us-east-1",
            )
            .await;
        assert!(
            !response.status().is_success(),
            "Original admin credentials must not authorize {target}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_machine_publication_requires_its_own_permission_before_any_mutation() {
    use locallycloud_iam_sts::model::IamRole;
    let fixture = Fixture::new();
    let role_arn = format!("arn:aws:iam::{ACCOUNT}:role/publisher");
    fixture.iam.create_role(ACCOUNT, IamRole {
        role_name:"publisher".into(),role_id:"AROAPUBLISHER".into(),arn:role_arn.clone(),path:"/".into(),create_date:"2026-01-01T00:00:00Z".into(),
        assume_role_policy_document:json!({"Statement":{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}}).to_string(),
        description:None,max_session_duration:3600,tags:BTreeMap::new(),attached_policies:Vec::new(),permission_boundary:None,inline_policies:BTreeMap::new(),
    });
    let base = json!({"name":"publish-guard","roleArn":role_arn,"publish":true,"definition":json!({"StartAt":"Done","States":{"Done":{"Type":"Succeed"}}}).to_string()});
    fixture.actor_policy(json!({"Effect":"Allow","Action":["states:CreateStateMachine","states:UpdateStateMachine","iam:PassRole"],"Resource":"*"}));
    assert_eq!(
        fixture
            .call(ACTOR, "states", "CreateStateMachine", base.clone())
            .await
            .0,
        403
    );
    let arn = format!("arn:aws:states:us-east-1:{ACCOUNT}:stateMachine:publish-guard");
    assert_eq!(
        fixture
            .call(
                ADMIN,
                "states",
                "DescribeStateMachine",
                json!({"stateMachineArn":arn})
            )
            .await
            .0,
        400
    );
    fixture.actor_policy(json!({"Effect":"Allow","Action":["states:CreateStateMachine","states:PublishStateMachineVersion","iam:PassRole"],"Resource":"*"}));
    let created = fixture
        .ok(ACTOR, "states", "CreateStateMachine", base)
        .await;
    assert_eq!(created["stateMachineVersionArn"], format!("{arn}:1"));
    fixture.actor_policy(
        json!({"Effect":"Allow","Action":"states:UpdateStateMachine","Resource":"*"}),
    );
    assert_eq!(fixture.call(ACTOR,"states","UpdateStateMachine",json!({"stateMachineArn":arn,"publish":true,"definition":json!({"StartAt":"Changed","States":{"Changed":{"Type":"Succeed"}}}).to_string()})).await.0,403);
    let described = fixture
        .ok(
            ADMIN,
            "states",
            "DescribeStateMachine",
            json!({"stateMachineArn":arn}),
        )
        .await;
    assert_eq!(
        serde_json::from_str::<Value>(described["definition"].as_str().unwrap()).unwrap()
            ["StartAt"],
        "Done"
    );
    let versions = fixture
        .ok(
            ADMIN,
            "states",
            "ListStateMachineVersions",
            json!({"stateMachineArn":arn}),
        )
        .await;
    assert_eq!(
        versions["stateMachineVersions"].as_array().unwrap().len(),
        1
    );
}
