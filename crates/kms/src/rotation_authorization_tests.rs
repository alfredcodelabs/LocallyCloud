use super::*;
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_iam_sts::enforcement::EnforcementMode;
use locallycloud_iam_sts::model::{AccessKey, IamUser};
use locallycloud_iam_sts::store::IamStore;
use locallycloud_iam_sts::sts::SessionStore;
use std::collections::BTreeMap;

#[tokio::test]
async fn rotation_period_conditions_use_requested_and_default_period_with_native_iam() {
    let account = "000000000000";
    let registry = ServiceRegistry::with_known_services();
    let store = Arc::new(IamStore::new());
    store.create_user(
        account,
        IamUser {
            user_name: "rotation-admin".into(),
            user_id: "AIDAROTATION".into(),
            arn: format!("arn:aws:iam::{account}:user/rotation-admin"),
            path: "/".into(),
            create_date: "2026-01-01T00:00:00Z".into(),
            tags: BTreeMap::new(),
            attached_policies: Vec::new(),
            inline_policies: BTreeMap::new(),
            groups: Vec::new(),
            permission_boundary: None,
            access_keys: vec![AccessKey {
                access_key_id: "AKIAROTATION".into(),
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
        account.into(),
    )));
    let handler = KmsHandler::with_registry(&registry, test_db()).unwrap();
    let created = handler
        .service
        .dispatch(
            "CreateKey",
            serde_json::json!({}).as_object().unwrap(),
            account,
            "us-east-1",
        )
        .unwrap();
    let key = created["KeyMetadata"]["KeyId"].as_str().unwrap();
    let status = || {
        handler
            .service
            .dispatch(
                "GetKeyRotationStatus",
                serde_json::json!({"KeyId":key}).as_object().unwrap(),
                account,
                "us-east-1",
            )
            .unwrap()
    };
    for policy in [
        serde_json::json!({"Statement":[
            {"Effect":"Allow","Action":"kms:EnableKeyRotation","Resource":"*"},
            {"Effect":"Deny","Action":"kms:EnableKeyRotation","Resource":"*","Condition":{"NumericGreaterThan":{"kms:RotationPeriodInDays":90}}}
        ]}),
        serde_json::json!({"Statement":{"Effect":"Allow","Action":"kms:EnableKeyRotation","Resource":"*","Condition":{"NumericLessThanEqualsIfExists":{"kms:RotationPeriodInDays":90}}}}),
    ] {
        store.update_user(account, "rotation-admin", |user| {
            user.inline_policies
                .insert("rotation".into(), policy.to_string());
        });
        for period in [Some(365), None, Some(90), Some(365), None] {
            let before = status();
            let mut body = serde_json::json!({"KeyId":key});
            if let Some(period) = period {
                body["RotationPeriodInDays"] = period.into();
            }
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "x-amz-target",
                "TrentService.EnableKeyRotation".parse().unwrap(),
            );
            headers.insert(http::header::AUTHORIZATION, "AWS4-HMAC-SHA256 Credential=AKIAROTATION/20260101/us-east-1/kms/aws4_request, SignedHeaders=host;x-amz-date, Signature=test".parse().unwrap());
            let response = handler
                .handle(ServiceRequest {
                    method: http::Method::POST,
                    uri: "/".parse().unwrap(),
                    headers,
                    body: bytes::Bytes::from(body.to_string()),
                    region: "us-east-1".into(),
                    account_id: account.into(),
                    request_id: "rotation-policy".into(),
                })
                .await;
            if period == Some(90) {
                assert_eq!(response.status(), 200);
                assert_eq!(status()["RotationPeriodInDays"], 90);
                assert_eq!(status()["KeyRotationEnabled"], true);
            } else {
                assert_eq!(response.status(), 400);
                let error: Value = serde_json::from_slice(
                    &axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(error["__type"], "AccessDeniedException");
                assert_eq!(
                    status(),
                    before,
                    "denied rotation must not change configuration"
                );
            }
        }
    }
}
