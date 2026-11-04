use super::*;
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_iam_sts::enforcement::EnforcementMode;
use locallycloud_iam_sts::model::{AccessKey, IamUser};
use locallycloud_iam_sts::store::IamStore;
use locallycloud_iam_sts::sts::SessionStore;
use serde_json::json;
use std::collections::BTreeMap;

const ACCOUNT: &str = "000000000000";
const USER: &str = "policy-admin";
const ACCESS_KEY: &str = "AKIAPOLICYADMIN000001";

struct Fixture {
    _registry: Arc<ServiceRegistry>,
    store: Arc<IamStore>,
    handler: KmsHandler,
}

impl Fixture {
    fn new(mode: EnforcementMode) -> Self {
        let registry = ServiceRegistry::with_known_services();
        let store = Arc::new(IamStore::new());
        store.create_user(
            ACCOUNT,
            IamUser {
                user_name: USER.into(),
                user_id: "AIDAPOLICYADMIN".into(),
                arn: format!("arn:aws:iam::{ACCOUNT}:user/{USER}"),
                path: "/".into(),
                create_date: "2026-01-01T00:00:00Z".into(),
                tags: BTreeMap::new(),
                attached_policies: Vec::new(),
                inline_policies: BTreeMap::from([(
                    "administrator".into(),
                    json!({"Statement":{"Effect":"Allow","Action":"kms:*","Resource":"*"}})
                        .to_string(),
                )]),
                groups: Vec::new(),
                permission_boundary: None,
                access_keys: vec![AccessKey {
                    access_key_id: ACCESS_KEY.into(),
                    secret_access_key: "secret".into(),
                    status: "Active".into(),
                    create_date: "2026-01-01T00:00:00Z".into(),
                }],
            },
        );
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            store.clone(),
            Arc::new(SessionStore::new()),
            mode,
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
        let handler = KmsHandler::with_registry(&registry, test_db()).unwrap();
        Self {
            _registry: registry,
            store,
            handler,
        }
    }

    async fn call(&self, key: &str, operation: &str, body: Value) -> (u16, Value) {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-target",
            format!("TrentService.{operation}").parse().unwrap(),
        );
        headers.insert(http::header::AUTHORIZATION, format!("AWS4-HMAC-SHA256 Credential={key}/20261104/us-east-1/kms/aws4_request, SignedHeaders=host;x-amz-date, Signature=test").parse().unwrap());
        let response = self
            .handler
            .handle(ServiceRequest {
                method: http::Method::POST,
                uri: "/".parse().unwrap(),
                headers,
                body: body.to_string().into(),
                region: "us-east-1".into(),
                account_id: ACCOUNT.into(),
                request_id: "key-policy-safety".into(),
            })
            .await;
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (
            status,
            if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        )
    }

    fn policy(&self, key: &str) -> Value {
        let stored = self
            .handler
            .service
            .dispatch(
                "GetKeyPolicy",
                json!({"KeyId":key,"PolicyName":"default"})
                    .as_object()
                    .unwrap(),
                ACCOUNT,
                "us-east-1",
            )
            .unwrap();
        serde_json::from_str(stored["Policy"].as_str().unwrap()).unwrap()
    }
}

fn key_policy(principal: &str, actions: Value) -> Value {
    json!({"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":principal},"Action":actions,"Resource":"*"}})
}

#[tokio::test]
async fn account_policy_delegates_key_administration_to_the_actual_iam_caller() {
    for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
        let fixture = Fixture::new(mode);
        let policy = key_policy(&format!("arn:aws:iam::{ACCOUNT}:root"), json!("kms:*"));
        let (status, created) = fixture
            .call(
                ACCESS_KEY,
                "CreateKey",
                json!({"Policy":policy.to_string()}),
            )
            .await;
        assert_eq!(status, 200, "{created}");
        let key = created["KeyMetadata"]["KeyId"].as_str().unwrap();
        for operation in ["EnableKeyRotation", "ScheduleKeyDeletion"] {
            let (status, result) = fixture
                .call(ACCESS_KEY, operation, json!({"KeyId":key}))
                .await;
            assert_eq!(status, 200, "{operation}: {result}");
        }
    }
}

#[tokio::test]
async fn unknown_permissive_caller_acts_as_account_root_like_sts() {
    let fixture = Fixture::new(EnforcementMode::Permissive);
    let policy = key_policy(&format!("arn:aws:iam::{ACCOUNT}:root"), json!("kms:*"));
    let (status, created) = fixture
        .call(
            "unregistered",
            "CreateKey",
            json!({"Policy":policy.to_string()}),
        )
        .await;
    assert_eq!(status, 200, "{created}");
    let key = created["KeyMetadata"]["KeyId"].as_str().unwrap();
    for operation in ["EnableKeyRotation", "ScheduleKeyDeletion"] {
        let (status, result) = fixture
            .call("unregistered", operation, json!({"KeyId":key}))
            .await;
        assert_eq!(status, 200, "{operation}: {result}");
    }

    let other = key_policy(
        &format!("arn:aws:iam::{ACCOUNT}:user/{USER}"),
        json!("kms:*"),
    );
    let before = fixture.call("unregistered", "ListKeys", json!({})).await;
    for bypass in [None, Some(false)] {
        let mut body = json!({"Policy":other.to_string()});
        if let Some(value) = bypass {
            body["BypassPolicyLockoutSafetyCheck"] = value.into();
        }
        let (status, error) = fixture.call("unregistered", "CreateKey", body).await;
        assert_eq!(status, 400);
        assert_eq!(error["__type"], "MalformedPolicyDocumentException");
        assert_eq!(
            fixture.call("unregistered", "ListKeys", json!({})).await,
            before
        );
    }
    let (status, bypassed) = fixture
        .call(
            "unregistered",
            "CreateKey",
            json!({"Policy":other.to_string(),"BypassPolicyLockoutSafetyCheck":true}),
        )
        .await;
    assert_eq!(status, 200, "{bypassed}");
    let locked = bypassed["KeyMetadata"]["KeyId"].as_str().unwrap();
    let (status, error) = fixture
        .call("unregistered", "EnableKeyRotation", json!({"KeyId":locked}))
        .await;
    assert_eq!(status, 400);
    assert_eq!(error["__type"], "AccessDeniedException");
    let (status, default_key) = fixture.call("unregistered", "CreateKey", json!({})).await;
    assert_eq!(status, 200, "{default_key}");
}

#[tokio::test]
async fn caller_only_policy_is_valid_and_a_future_lockout_requires_explicit_bypass() {
    let fixture = Fixture::new(EnforcementMode::Strict);
    let principal = format!("arn:aws:iam::{ACCOUNT}:user/{USER}");
    let original = key_policy(&principal, json!("kms:*"));
    let (status, created) = fixture
        .call(
            ACCESS_KEY,
            "CreateKey",
            json!({"Policy":original.to_string()}),
        )
        .await;
    assert_eq!(status, 200, "{created}");
    let key = created["KeyMetadata"]["KeyId"].as_str().unwrap();
    let original = key_policy(&principal, json!(["kms:*"]));
    let (status, updated) = fixture
        .call(
            ACCESS_KEY,
            "PutKeyPolicy",
            json!({"KeyId":key,"PolicyName":"default","Policy":original.to_string()}),
        )
        .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(fixture.policy(key), original);
    let readable_only = key_policy(&principal, json!("kms:GetKeyPolicy"));
    for bypass in [None, Some(false)] {
        let mut body =
            json!({"KeyId":key,"PolicyName":"default","Policy":readable_only.to_string()});
        if let Some(value) = bypass {
            body["BypassPolicyLockoutSafetyCheck"] = value.into();
        }
        let (status, error) = fixture.call(ACCESS_KEY, "PutKeyPolicy", body).await;
        assert_eq!(status, 400);
        assert_eq!(error["__type"], "MalformedPolicyDocumentException");
        assert_eq!(fixture.policy(key), original);
    }
    fixture.store.update_user(ACCOUNT, USER, |user| {
        user.inline_policies.insert(
            "deny-replacement".into(),
            json!({"Statement":{"Effect":"Deny","Action":"kms:PutKeyPolicy","Resource":"*"}})
                .to_string(),
        );
    });
    let replacement = json!({"KeyId":key,"PolicyName":"default","Policy":readable_only.to_string(),"BypassPolicyLockoutSafetyCheck":true});
    let (status, error) = fixture
        .call(ACCESS_KEY, "PutKeyPolicy", replacement.clone())
        .await;
    assert_eq!(status, 400);
    assert_eq!(error["__type"], "AccessDeniedException");
    assert_eq!(fixture.policy(key), original);
    fixture.store.update_user(ACCOUNT, USER, |user| {
        user.inline_policies.remove("deny-replacement");
    });
    let (status, updated) = fixture.call(ACCESS_KEY, "PutKeyPolicy", replacement).await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(fixture.policy(key), readable_only);
}

#[tokio::test]
async fn malformed_safety_flag_is_rejected_without_creating_a_key() {
    let fixture = Fixture::new(EnforcementMode::Strict);
    let policy = key_policy(&format!("arn:aws:iam::{ACCOUNT}:root"), json!("kms:*"));
    let before = fixture.call(ACCESS_KEY, "ListKeys", json!({})).await;
    for flag in [json!("true"), json!(0), json!({"enabled":true})] {
        let (status, error) = fixture
            .call(
                ACCESS_KEY,
                "CreateKey",
                json!({"Policy":policy.to_string(),"BypassPolicyLockoutSafetyCheck":flag}),
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(error["__type"], "ValidationException");
        assert_eq!(
            fixture.call(ACCESS_KEY, "ListKeys", json!({})).await,
            before
        );
    }
}
