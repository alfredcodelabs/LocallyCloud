//! Strict IAM receives `dynamodb:LeadingKeys` from the native DynamoDB handler.
use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use locallycloud_iam_sts::enforcement::EnforcementMode;
use locallycloud_iam_sts::model::{AccessKey, IamUser};
use locallycloud_iam_sts::store::IamStore;
use locallycloud_iam_sts::sts::SessionStore;
use serde_json::{json, Value};

const ACCOUNT: &str = "000000000000";
const REGION: &str = "us-east-1";
const ACCESS_KEY: &str = "AKIALEADINGKEYS00001";

fn registry() -> Arc<ServiceRegistry> {
    let registry = Arc::new(ServiceRegistry::new());
    locallycloud_dynamodb::register(&registry);
    let store = Arc::new(IamStore::new());
    let policy = json!({"Version":"2012-10-17","Statement":[{
        "Effect":"Allow",
        "Action":["dynamodb:GetItem","dynamodb:PutItem","dynamodb:Query","dynamodb:BatchGetItem"],
        "Resource":"*",
        "Condition":{"ForAllValues:StringEquals":{"dynamodb:LeadingKeys":["a"]}}
    }]});
    store.create_user(
        ACCOUNT,
        IamUser {
            user_name: "tenant-a".into(),
            user_id: "AIDALEADINGKEYS".into(),
            arn: format!("arn:aws:iam::{ACCOUNT}:user/tenant-a"),
            path: "/".into(),
            create_date: "2026-01-01T00:00:00Z".into(),
            tags: BTreeMap::new(),
            attached_policies: Vec::new(),
            inline_policies: BTreeMap::from([("tenant".into(), policy.to_string())]),
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
        store,
        Arc::new(SessionStore::new()),
        EnforcementMode::Strict,
    );
    registry
}

/// Unsigned requests are trusted internal calls; signed ones are evaluated as the user.
async fn call(registry: &ServiceRegistry, signed: bool, op: &str, body: Value) -> (u16, Value) {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-amz-target",
        format!("DynamoDB_20120810.{op}").parse().unwrap(),
    );
    if signed {
        headers.insert(
            http::header::AUTHORIZATION,
            format!("AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/20260101/{REGION}/dynamodb/aws4_request, SignedHeaders=host, Signature=0")
                .parse()
                .unwrap(),
        );
    }
    let response = registry
        .native_handler(&ServiceName::new("dynamodb"))
        .unwrap()
        .handle(ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(body.to_string()),
            region: REGION.into(),
            account_id: ACCOUNT.into(),
            request_id: "leading-keys".into(),
        })
        .await;
    let status = response.status().as_u16();
    let data = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&data).unwrap_or(Value::Null))
}

async fn table(registry: &ServiceRegistry) {
    let (status, body) = call(
        registry,
        false,
        "CreateTable",
        json!({
            "TableName":"tenants",
            "KeySchema":[{"AttributeName":"pk","KeyType":"HASH"},{"AttributeName":"sk","KeyType":"RANGE"}],
            "AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"},{"AttributeName":"sk","AttributeType":"S"}],
            "BillingMode":"PAY_PER_REQUEST"
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

fn assert_denied((status, body): (u16, Value)) {
    assert_eq!(status, 400, "{body}");
    assert!(
        body["__type"]
            .as_str()
            .is_some_and(|kind| kind.ends_with("AccessDeniedException")),
        "{body}"
    );
}

fn key(pk: &str) -> Value {
    json!({"pk":{"S":pk},"sk":{"S":"1"}})
}

#[tokio::test]
async fn item_operations_allow_only_the_policy_leading_key() {
    let registry = registry();
    table(&registry).await;
    for pk in ["a", "b"] {
        let request = json!({"TableName":"tenants","Item":key(pk)});
        let put = call(&registry, true, "PutItem", request).await;
        if pk == "a" {
            assert_eq!(put.0, 200, "{}", put.1);
        } else {
            assert_denied(put);
        }
        let get = call(
            &registry,
            true,
            "GetItem",
            json!({"TableName":"tenants","Key":key(pk)}),
        )
        .await;
        if pk == "a" {
            assert_eq!(get.1["Item"], key("a"));
        } else {
            assert_denied(get);
        }
    }
}

#[tokio::test]
async fn query_uses_the_key_condition_partition_value() {
    let registry = registry();
    table(&registry).await;
    let query = |pk: &str| {
        json!({
            "TableName":"tenants",
            "KeyConditionExpression":"#p = :p",
            "ExpressionAttributeNames":{"#p":"pk"},
            "ExpressionAttributeValues":{":p":{"S":pk}}
        })
    };
    let (status, body) = call(&registry, true, "Query", query("a")).await;
    assert_eq!(status, 200, "{body}");
    assert_denied(call(&registry, true, "Query", query("b")).await);
    // Without a partition equality the leading key is unknown, so IAM must not allow it.
    let scan_like = json!({
        "TableName":"tenants",
        "KeyConditionExpression":"sk = :s",
        "ExpressionAttributeValues":{":s":{"S":"1"}}
    });
    let (status, body) = call(&registry, true, "Query", scan_like).await;
    assert_eq!(status, 400, "{body}");
    assert!(body["__type"]
        .as_str()
        .is_some_and(|kind| kind.ends_with("ValidationException")));
}

#[tokio::test]
async fn batch_get_denies_when_any_key_is_outside_the_policy() {
    let registry = registry();
    table(&registry).await;
    let batch = |keys: Vec<Value>| json!({"RequestItems":{"tenants":{"Keys":keys}}});
    let (status, body) = call(&registry, true, "BatchGetItem", batch(vec![key("a")])).await;
    assert_eq!(status, 200, "{body}");
    assert_denied(
        call(
            &registry,
            true,
            "BatchGetItem",
            batch(vec![key("a"), key("b")]),
        )
        .await,
    );
}
