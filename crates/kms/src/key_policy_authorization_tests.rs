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
    sessions: Arc<SessionStore>,
    handler: Arc<KmsHandler>,
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
        let sessions = Arc::new(SessionStore::new());
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            store.clone(),
            sessions.clone(),
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
        let handler = test_handler(&registry, test_db());
        Self {
            _registry: registry,
            store,
            sessions,
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

#[tokio::test]
async fn explicit_key_policy_gates_every_public_key_operation_despite_iam_allow() {
    let fixture = Fixture::new(EnforcementMode::Strict);
    let own = key_policy(
        &format!("arn:aws:iam::{ACCOUNT}:user/{USER}"),
        json!("kms:*"),
    );
    let (status, created) = fixture
        .call(ACCESS_KEY, "CreateKey", json!({"Policy":own.to_string()}))
        .await;
    assert_eq!(status, 200, "{created}");
    let key = &created["KeyMetadata"]["KeyId"];
    let (status, encrypted) = fixture
        .call(
            ACCESS_KEY,
            "Encrypt",
            json!({"KeyId":key,"Plaintext":"c2VjcmV0"}),
        )
        .await;
    assert_eq!(status, 200, "{encrypted}");
    let excluded = key_policy(
        &format!("arn:aws:iam::{ACCOUNT}:user/someone-else"),
        json!("kms:*"),
    );
    let (status, updated) = fixture.call(ACCESS_KEY, "PutKeyPolicy", json!({"KeyId":key,"Policy":excluded.to_string(),"BypassPolicyLockoutSafetyCheck":true})).await;
    assert_eq!(status, 200, "{updated}");
    for (operation, body) in [
        ("Encrypt", json!({"KeyId":key,"Plaintext":"c2VjcmV0"})),
        (
            "Decrypt",
            json!({"CiphertextBlob":encrypted["CiphertextBlob"]}),
        ),
        ("GenerateDataKey", json!({"KeyId":key,"KeySpec":"AES_256"})),
        ("DescribeKey", json!({"KeyId":key})),
        ("GetKeyPolicy", json!({"KeyId":key})),
        ("EnableKeyRotation", json!({"KeyId":key})),
        (
            "CreateAlias",
            json!({"AliasName":"alias/forbidden","TargetKeyId":key}),
        ),
    ] {
        let (status, result) = fixture.call(ACCESS_KEY, operation, body).await;
        assert_eq!(status, 400, "{operation}: {result}");
        assert_eq!(
            result["__type"], "AccessDeniedException",
            "{operation}: {result}"
        );
    }
}

#[tokio::test]
async fn direct_key_grant_supports_crypto_without_identity_allow_and_preserves_iam_deny() {
    let fixture = Fixture::new(EnforcementMode::Strict);
    let own = key_policy(
        &format!("arn:aws:iam::{ACCOUNT}:user/{USER}"),
        json!("kms:*"),
    );
    let (status, created) = fixture
        .call(ACCESS_KEY, "CreateKey", json!({"Policy":own.to_string()}))
        .await;
    assert_eq!(status, 200, "{created}");
    let key = &created["KeyMetadata"]["KeyId"];
    fixture
        .store
        .update_user(ACCOUNT, USER, |user| user.inline_policies.clear());
    let (status, encrypted) = fixture
        .call(
            ACCESS_KEY,
            "Encrypt",
            json!({"KeyId":key,"Plaintext":"c2VjcmV0"}),
        )
        .await;
    assert_eq!(status, 200, "{encrypted}");
    let (status, decrypted) = fixture
        .call(
            ACCESS_KEY,
            "Decrypt",
            json!({"CiphertextBlob":encrypted["CiphertextBlob"]}),
        )
        .await;
    assert_eq!(status, 200, "{decrypted}");
    assert_eq!(decrypted["Plaintext"], "c2VjcmV0");
    let (status, generated) = fixture
        .call(
            ACCESS_KEY,
            "GenerateDataKey",
            json!({"KeyId":key,"KeySpec":"AES_256"}),
        )
        .await;
    assert_eq!(status, 200, "{generated}");
    let (status, described) = fixture
        .call(ACCESS_KEY, "DescribeKey", json!({"KeyId":key}))
        .await;
    assert_eq!(status, 200, "{described}");
    for operation in ["CreateKey", "ListKeys", "ListAliases"] {
        let (status, result) = fixture.call(ACCESS_KEY, operation, json!({})).await;
        assert_eq!(status, 400, "{operation}: {result}");
        assert_eq!(result["__type"], "AccessDeniedException");
    }
    fixture.store.update_user(ACCOUNT, USER, |user| {
        user.inline_policies.insert(
            "deny-encryption".into(),
            json!({"Statement":{"Effect":"Deny","Action":"kms:Encrypt","Resource":"*"}})
                .to_string(),
        );
    });
    let (status, denied) = fixture
        .call(
            ACCESS_KEY,
            "Encrypt",
            json!({"KeyId":key,"Plaintext":"c2VjcmV0"}),
        )
        .await;
    assert_eq!(status, 400, "{denied}");
    assert_eq!(denied["__type"], "AccessDeniedException");
}

#[tokio::test]
async fn key_policy_encryption_context_and_action_patterns_apply_to_public_crypto() {
    let fixture = Fixture::new(EnforcementMode::Strict);
    let principal = format!("arn:aws:iam::{ACCOUNT}:user/{USER}");
    let policy = json!({"Statement":[
        {"Effect":"Allow","Principal":{"AWS":principal},"Action":"kms:PutKeyPolicy","Resource":"*"},
        {"Effect":"Allow","Principal":{"AWS":principal},"Action":["KMS:Encry*","kms:Decry*","kms:GenerateDataKey*"],"Resource":"*","Condition":{"StringEquals":{"kms:EncryptionContext:purpose":"billing"}}}
    ]});
    let (status, created) = fixture
        .call(
            ACCESS_KEY,
            "CreateKey",
            json!({"Policy":policy.to_string()}),
        )
        .await;
    assert_eq!(status, 200, "{created}");
    let key = &created["KeyMetadata"]["KeyId"];
    let (status, encrypted) = fixture
        .call(
            ACCESS_KEY,
            "Encrypt",
            json!({"KeyId":key,"Plaintext":"c2VjcmV0","EncryptionContext":{"purpose":"billing"}}),
        )
        .await;
    assert_eq!(status, 200, "{encrypted}");
    for (operation, mut body) in [
        ("Encrypt", json!({"KeyId":key,"Plaintext":"c2VjcmV0"})),
        (
            "Decrypt",
            json!({"CiphertextBlob":encrypted["CiphertextBlob"]}),
        ),
        ("GenerateDataKey", json!({"KeyId":key,"KeySpec":"AES_256"})),
    ] {
        for context in [
            Value::Null,
            json!({"purpose":"other"}),
            json!({"purpose":"billing"}),
        ] {
            if context.is_null() {
                body.as_object_mut().unwrap().remove("EncryptionContext");
            } else {
                body["EncryptionContext"] = context.clone();
            }
            let (status, result) = fixture.call(ACCESS_KEY, operation, body.clone()).await;
            assert_eq!(
                status,
                if context == json!({"purpose":"billing"}) {
                    200
                } else {
                    400
                },
                "{operation}: {context}: {result}"
            );
            if status != 200 {
                assert_eq!(result["__type"], "AccessDeniedException");
            }
        }
    }
}

#[tokio::test]
async fn direct_role_key_grants_respect_implicit_session_and_boundary_limits() {
    use locallycloud_iam_sts::model::{urlencode_doc, IamPolicy, IamRole, PolicyVersion};
    use locallycloud_iam_sts::query::QueryRequest;
    let fixture = Fixture::new(EnforcementMode::Strict);
    let role = format!("arn:aws:iam::{ACCOUNT}:role/key-user");
    fixture.store.create_role(ACCOUNT, IamRole {
        role_name: "key-user".into(), role_id: "AROAKEYUSER".into(), arn: role.clone(), path: "/".into(),
        create_date: "2026-01-01T00:00:00Z".into(), assume_role_policy_document: json!({"Statement":{"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:user/{USER}")},"Action":"sts:AssumeRole"}}).to_string(),
        description: None, max_session_duration: 3600, tags: BTreeMap::new(), attached_policies: Vec::new(), inline_policies: BTreeMap::new(), permission_boundary: None,
    });
    let policy = key_policy(
        &format!("arn:aws:iam::{ACCOUNT}:user/{USER}"),
        json!("kms:*"),
    );
    let mut policy = policy;
    policy["Statement"]["Principal"]["AWS"] =
        json!([format!("arn:aws:iam::{ACCOUNT}:user/{USER}"), role]);
    let (status, created) = fixture
        .call(
            ACCESS_KEY,
            "CreateKey",
            json!({"Policy":policy.to_string()}),
        )
        .await;
    assert_eq!(status, 200, "{created}");
    let key = &created["KeyMetadata"]["KeyId"];
    let restricted =
        json!({"Statement":{"Effect":"Allow","Action":"kms:DescribeKey","Resource":"*"}})
            .to_string();
    let session = |policy: Option<&str>| {
        let raw = format!(
            "RoleArn={role}&RoleSessionName=key-test{}",
            policy
                .map(|policy| format!("&Policy={}", urlencode_doc(policy)))
                .unwrap_or_default()
        );
        let result = locallycloud_iam_sts::sts::assume_role(
            &fixture.store,
            &fixture.sessions,
            ACCOUNT,
            &QueryRequest::parse(raw.as_bytes()),
        )
        .unwrap();
        result
            .split("<AccessKeyId>")
            .nth(1)
            .unwrap()
            .split("</AccessKeyId>")
            .next()
            .unwrap()
            .to_string()
    };
    let unrestricted = session(None);
    let (status, result) = fixture
        .call(
            &unrestricted,
            "Encrypt",
            json!({"KeyId":key,"Plaintext":"c2VjcmV0"}),
        )
        .await;
    assert_eq!(status, 200, "{result}");
    let limited = session(Some(&restricted));
    let (status, result) = fixture
        .call(
            &limited,
            "Encrypt",
            json!({"KeyId":key,"Plaintext":"c2VjcmV0"}),
        )
        .await;
    assert_eq!(status, 400, "{result}");
    assert_eq!(result["__type"], "AccessDeniedException");
    assert_eq!(
        fixture
            .call(&limited, "DescribeKey", json!({"KeyId":key}))
            .await
            .0,
        200
    );
    let boundary = format!("arn:aws:iam::{ACCOUNT}:policy/key-boundary");
    fixture.store.insert_policy(
        ACCOUNT,
        IamPolicy {
            policy_name: "key-boundary".into(),
            policy_id: "ANPAKEYBOUNDARY".into(),
            arn: boundary.clone(),
            path: "/".into(),
            create_date: "2026-01-01T00:00:00Z".into(),
            default_version_id: "v1".into(),
            versions: vec![PolicyVersion {
                version_id: "v1".into(),
                document: restricted,
                is_default: true,
                create_date: "2026-01-01T00:00:00Z".into(),
            }],
            attachment_count: 1,
            description: None,
            tags: BTreeMap::new(),
            is_aws_managed: false,
        },
    );
    fixture.store.update_role(ACCOUNT, "key-user", |role| {
        role.permission_boundary = Some(boundary)
    });
    let (status, result) = fixture
        .call(
            &unrestricted,
            "Encrypt",
            json!({"KeyId":key,"Plaintext":"c2VjcmV0"}),
        )
        .await;
    assert_eq!(status, 400, "{result}");
    assert_eq!(result["__type"], "AccessDeniedException");
    assert_eq!(
        fixture
            .call(&unrestricted, "DescribeKey", json!({"KeyId":key}))
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn alias_retarget_cannot_switch_the_authorized_crypto_key_or_old_alias_target() {
    let fixture = Fixture::new(EnforcementMode::Strict);
    let principal = format!("arn:aws:iam::{ACCOUNT}:user/{USER}");
    let original = key_policy(&principal, json!("kms:*"));
    let (_, first) = fixture
        .call(
            ACCESS_KEY,
            "CreateKey",
            json!({"Policy":original.to_string()}),
        )
        .await;
    let first_id = &first["KeyMetadata"]["KeyId"];
    let restricted = key_policy(&principal, json!(["kms:PutKeyPolicy", "kms:UpdateAlias"]));
    let (_, second) = fixture
        .call(
            ACCESS_KEY,
            "CreateKey",
            json!({"Policy":restricted.to_string()}),
        )
        .await;
    let second_id = &second["KeyMetadata"]["KeyId"];
    let (status, result) = fixture
        .call(
            ACCESS_KEY,
            "CreateAlias",
            json!({"AliasName":"alias/race","TargetKeyId":first_id}),
        )
        .await;
    assert_eq!(status, 200, "{result}");
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::AUTHORIZATION,format!("AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/20261116/us-east-1/kms/aws4_request, SignedHeaders=host, Signature=test").parse().unwrap());
    let request = ServiceRequest {
        method: http::Method::POST,
        uri: "/".parse().unwrap(),
        headers,
        body: bytes::Bytes::new(),
        region: "us-east-1".into(),
        account_id: ACCOUNT.into(),
        request_id: "alias-race".into(),
    };
    let mut encrypt = json!({"KeyId":"alias/race","Plaintext":"c2VjcmV0"})
        .as_object()
        .unwrap()
        .clone();
    fixture
        .handler
        .service
        .authorize_request(
            &fixture.handler.registry,
            &request,
            &mut encrypt,
            "Encrypt",
            None,
        )
        .unwrap();
    let mut update = json!({"AliasName":"alias/race","TargetKeyId":first_id})
        .as_object()
        .unwrap()
        .clone();
    let old = fixture
        .handler
        .service
        .authorize_request(
            &fixture.handler.registry,
            &request,
            &mut update,
            "UpdateAlias",
            None,
        )
        .unwrap()
        .unwrap();
    let (status, result) = fixture
        .call(
            ACCESS_KEY,
            "UpdateAlias",
            json!({"AliasName":"alias/race","TargetKeyId":second_id}),
        )
        .await;
    assert_eq!(status, 200, "{result}");
    let encrypted = fixture
        .handler
        .service
        .dispatch("Encrypt", &encrypt, ACCOUNT, "us-east-1")
        .unwrap();
    assert_eq!(encrypted["KeyId"], first["KeyMetadata"]["Arn"]);
    assert!(matches!(
        fixture.handler.service.update_alias_checked(
            &update,
            &crate::model::Scope::new(ACCOUNT, "us-east-1"),
            Some(&old)
        ),
        Err(KmsError::Internal)
    ));
    let (status, result) = fixture
        .call(
            ACCESS_KEY,
            "Encrypt",
            json!({"KeyId":"alias/race","Plaintext":"c2VjcmV0"}),
        )
        .await;
    assert_eq!(status, 400, "{result}");
    assert_eq!(result["__type"], "AccessDeniedException");
}
