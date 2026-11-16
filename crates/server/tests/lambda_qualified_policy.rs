//! Lambda resource policies remain isolated by function/version/alias ARN across commits.
#![cfg(feature = "services")]
use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Method};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::ServiceRegistry;
use locallycloud_iam_sts::{
    enforcement::EnforcementMode,
    model::IamRole,
    store::IamStore,
    sts::{issue_service_role_credentials, SessionStore},
};
use serde_json::{json, Value};

const ACCOUNT: &str = "000000000000";
const FUNCTION: &str = "qualified-policy";
const BASE: &str = "/2015-03-31/functions/qualified-policy/policy";
const GRANTEE: &str = "arn:aws:iam::000000000000:role/grantee";
const ZIP: &str = "UEsDBBQAAAAAAOUBcF3HPNg2OwAAADsAAAAIAAAAaW5kZXguanNleHBvcnRzLmhhbmRsZXIgPSBhc3luYyAoKSA9PiAoe3N0YXR1c0NvZGU6MjAwLGJvZHk6Im9rIn0pO1BLAQIUAxQAAAAAAOUBcF3HPNg2OwAAADsAAAAIAAAAAAAAAAAAAACAAQAAAABpbmRleC5qc1BLBQYAAAAAAQABADYAAABhAAAAAAA=";

struct Fixture {
    _registry: Arc<ServiceRegistry>,
    lambda: Arc<locallycloud_lambda::LambdaHandler>,
    iam: Arc<IamStore>,
    grantor: String,
    grantee: String,
}
impl Fixture {
    async fn new() -> Self {
        let registry = ServiceRegistry::with_known_services();
        let store = Arc::new(IamStore::new());
        let sessions = Arc::new(SessionStore::new());
        for name in ["grantor", "grantee", "execution"] {
            store.create_role(ACCOUNT, IamRole {
                role_name: name.into(), role_id: format!("AROA{name}"),
                arn: format!("arn:aws:iam::{ACCOUNT}:role/{name}"), path: "/".into(),
                create_date: "2026-01-01T00:00:00Z".into(),
                assume_role_policy_document: json!({"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}).to_string(),
                description: None, max_session_duration: 3600, tags: BTreeMap::new(),
                attached_policies: Vec::new(), permission_boundary: None,
                inline_policies: if name == "grantor" { BTreeMap::from([("manage".into(), json!({"Statement":{
                    "Effect":"Allow","Action":["lambda:CreateFunction","lambda:AddPermission","lambda:GetPolicy","lambda:RemovePermission","lambda:PublishVersion","lambda:CreateAlias","lambda:DeleteAlias","lambda:GetFunction","lambda:DeleteFunction","iam:PassRole"],"Resource":"*"
                }}).to_string())]) } else { BTreeMap::new() },
            });
        }
        let grantor = issue_service_role_credentials(
            &store,
            &sessions,
            ACCOUNT,
            &format!("arn:aws:iam::{ACCOUNT}:role/grantor"),
        )
        .unwrap()
        .access_key_id;
        let grantee = issue_service_role_credentials(&store, &sessions, ACCOUNT, GRANTEE)
            .unwrap()
            .access_key_id;
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            store.clone(),
            sessions,
            EnforcementMode::Strict,
        );
        let lambda = locallycloud_lambda::register(&registry);
        let fixture = Self {
            _registry: registry,
            lambda,
            iam: store,
            grantor,
            grantee,
        };
        let (status, body) = fixture
            .call(
                Method::POST,
                "/2015-03-31/functions",
                json!({
                    "FunctionName":FUNCTION,"Role":format!("arn:aws:iam::{ACCOUNT}:role/execution"),
                    "Runtime":"nodejs22.x","Handler":"index.handler","Code":{"ZipFile":ZIP}
                }),
                &fixture.grantor,
            )
            .await;
        assert_eq!(status, 201, "{body}");
        fixture
    }
    async fn call(&self, method: Method, path: &str, body: Value, key: &str) -> (u16, Value) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        headers.insert(
            http::header::AUTHORIZATION,
            format!("AWS4-HMAC-SHA256 Credential={key}/20261116/us-east-1/lambda/aws4_request")
                .parse()
                .unwrap(),
        );
        let response = self
            .lambda
            .handle(ServiceRequest {
                method,
                uri: path.parse().unwrap(),
                headers,
                body: Bytes::from(body.to_string()),
                region: "us-east-1".into(),
                account_id: ACCOUNT.into(),
                request_id: "qualified-policy".into(),
            })
            .await;
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
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
    async fn publish_aliases(&self) -> String {
        let (status, version) = self
            .call(
                Method::POST,
                &format!("/2015-03-31/functions/{FUNCTION}/versions"),
                json!({}),
                &self.grantor,
            )
            .await;
        assert_eq!(status, 201, "{version}");
        let version = version["Version"].as_str().unwrap();
        for alias in ["prod", "other"] {
            let (status, body) = self
                .call(
                    Method::POST,
                    &format!("/2015-03-31/functions/{FUNCTION}/aliases"),
                    json!({"Name":alias,"FunctionVersion":version}),
                    &self.grantor,
                )
                .await;
            assert_eq!(status, 201, "{body}");
        }
        version.into()
    }
    async fn policy_at(&self, path: &str) -> Value {
        let (status, body) = self
            .call(Method::GET, path, Value::Null, &self.grantor)
            .await;
        assert_eq!(status, 200, "{path}: {body}");
        serde_json::from_str(body["Policy"].as_str().unwrap()).unwrap()
    }
    async fn invoke(&self, qualifier: Option<&str>, expected: u16) {
        let path = qualifier.map_or_else(
            || format!("/2015-03-31/functions/{FUNCTION}/invocations"),
            |qualifier| format!("/2015-03-31/functions/{FUNCTION}:{qualifier}/invocations"),
        );
        let (status, body) = self
            .call(Method::POST, &path, json!({}), &self.grantee)
            .await;
        assert_eq!(status, expected, "{path}: {body}");
    }
    async fn policy(&self) -> Value {
        let (status, body) = self
            .call(Method::GET, BASE, Value::Null, &self.grantor)
            .await;
        if status == 404 {
            return json!({"Statement":[]});
        }
        assert_eq!(status, 200, "{body}");
        serde_json::from_str(body["Policy"].as_str().unwrap()).unwrap()
    }
}
fn permission(id: &str, principal: &str) -> Value {
    json!({"StatementId":id,"Action":"lambda:InvokeFunction","Principal":principal})
}
#[tokio::test]
async fn unsupported_or_invalid_restrictions_never_become_unconditional_grants() {
    let fixture = Fixture::new().await;
    for (field, value, expected) in [
        ("PrincipalOrgID", json!("o-123456789012"), 501),
        ("FunctionUrlAuthType", json!("AWS_IAM"), 501),
        ("InvokedViaFunctionUrl", json!(true), 501),
        ("EventSourceToken", json!("required-token"), 501),
        ("RevisionId", json!("stale-revision"), 501),
        ("SourceArn", json!([]), 400),
        ("SourceArn", json!("not-an-arn"), 400),
        ("SourceAccount", json!(123456789012u64), 400),
        ("SourceAccount", json!("123"), 400),
        ("SourceAccount", json!("not-numeric!"), 400),
        ("StatementId", json!("invalid statement"), 400),
        ("StatementId", json!("x".repeat(101)), 400),
        ("Action", json!("s3:GetObject"), 400),
        ("Principal", json!("invalid principal"), 400),
    ] {
        let mut input = permission("restricted", GRANTEE);
        input[field] = value;
        let (status, body) = fixture
            .call(Method::POST, BASE, input, &fixture.grantor)
            .await;
        assert_eq!(status, expected, "{field}: {body}");
        assert!(fixture.policy().await["Statement"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    let mut wildcard = permission("wildcard-source", "s3.amazonaws.com");
    wildcard["SourceArn"] = json!("arn:aws:s3:::allowed-bucket-*");
    wildcard["SourceAccount"] = json!(ACCOUNT);
    let (status, body) = fixture
        .call(Method::POST, BASE, wildcard, &fixture.grantor)
        .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        fixture.policy().await["Statement"][0]["Condition"]["ArnLike"]["AWS:SourceArn"],
        "arn:aws:s3:::allowed-bucket-*"
    );
}

#[tokio::test]
async fn qualified_grants_do_not_authorize_latest_other_aliases_or_versions() {
    let fixture = Fixture::new().await;
    let version = fixture.publish_aliases().await;
    let alias = format!("{BASE}?Qualifier=prod");
    let (status, body) = fixture
        .call(
            Method::POST,
            &alias,
            permission("shared", GRANTEE),
            &fixture.grantor,
        )
        .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        fixture
            .call(Method::GET, BASE, Value::Null, &fixture.grantor)
            .await
            .0,
        404
    );
    let policy = fixture.policy_at(&alias).await;
    assert_eq!(
        policy["Statement"][0]["Resource"],
        format!("arn:aws:lambda:us-east-1:{ACCOUNT}:function:{FUNCTION}:prod")
    );
    fixture.invoke(Some("prod"), 501).await;
    fixture.invoke(None, 403).await;
    fixture.invoke(Some("other"), 403).await;
    fixture.invoke(Some(&version), 403).await;
    assert_eq!(
        fixture
            .call(
                Method::POST,
                &alias,
                permission("shared", GRANTEE),
                &fixture.grantor
            )
            .await
            .0,
        409
    );
    assert_eq!(
        fixture
            .call(
                Method::POST,
                &format!("{BASE}?Qualifier={version}"),
                permission("shared", GRANTEE),
                &fixture.grantor
            )
            .await
            .0,
        201
    );
    fixture.invoke(Some(&version), 501).await;
    assert_eq!(
        fixture
            .call(
                Method::POST,
                BASE,
                permission("shared", GRANTEE),
                &fixture.grantor
            )
            .await
            .0,
        201
    );
    fixture.invoke(None, 501).await;
    assert_eq!(
        fixture
            .call(
                Method::DELETE,
                &format!("{BASE}/shared"),
                Value::Null,
                &fixture.grantor
            )
            .await
            .0,
        204
    );
    fixture.invoke(None, 403).await;
    fixture.invoke(Some("prod"), 501).await;
    fixture.invoke(Some(&version), 501).await;
    assert_eq!(
        fixture
            .call(
                Method::DELETE,
                &format!("{BASE}/shared?Qualifier=prod"),
                Value::Null,
                &fixture.grantor
            )
            .await
            .0,
        204
    );
    fixture.invoke(Some("prod"), 403).await;
    fixture.invoke(Some(&version), 501).await;
}

#[tokio::test]
async fn qualified_policy_paths_decode_consistently_and_reject_conflicts() {
    let fixture = Fixture::new().await;
    fixture.publish_aliases().await;
    let paths = [
        format!("{BASE}?Qualifier=prod"),
        format!("{BASE}?%51ualifier=%70rod"),
        format!("/2015-03-31/functions/{FUNCTION}:prod/policy"),
        format!("/2015-03-31/functions/{FUNCTION}%3Aprod/policy"),
        format!("/2015-03-31/functions/arn:aws:lambda:us-east-1:{ACCOUNT}:function:{FUNCTION}:prod/policy"),
        format!("/2015-03-31/functions/{ACCOUNT}:function:{FUNCTION}:prod/policy"),
    ];
    for (index, path) in paths.iter().enumerate() {
        let (status, body) = fixture
            .call(
                Method::POST,
                path,
                permission(&format!("statement-{index}"), GRANTEE),
                &fixture.grantor,
            )
            .await;
        assert_eq!(status, 201, "{path}: {body}");
        assert_eq!(
            fixture.policy_at(path).await["Statement"]
                .as_array()
                .unwrap()
                .len(),
            index + 1
        );
    }
    let before = fixture.policy_at(&paths[0]).await;
    for (path, expected) in [
        (format!("{BASE}?Qualifier="), 400),
        (format!("{BASE}?Qualifier=$LATEST"), 400),
        (format!("{BASE}?Qualifier=missing"), 404),
        (format!("{BASE}?Qualifier=99"), 404),
        (format!("{BASE}?Qualifier=prod&Qualifier=other"), 400),
        (
            format!("/2015-03-31/functions/{FUNCTION}:prod/policy?Qualifier=other"),
            400,
        ),
    ] {
        let (status, body) = fixture
            .call(
                Method::POST,
                &path,
                permission("invalid", GRANTEE),
                &fixture.grantor,
            )
            .await;
        assert_eq!(status, expected, "{path}: {body}");
    }
    assert_eq!(fixture.policy_at(&paths[0]).await, before);
    let mut body = permission("body-qualifier", GRANTEE);
    body["Qualifier"] = json!("prod");
    assert_eq!(
        fixture
            .call(Method::POST, BASE, body, &fixture.grantor)
            .await
            .0,
        400
    );
}

#[tokio::test]
async fn policy_iam_permissions_are_evaluated_against_the_qualified_arn() {
    let fixture = Fixture::new().await;
    fixture.publish_aliases().await;
    fixture.iam.update_role(ACCOUNT, "grantor", |role| role.inline_policies = BTreeMap::from([("prod-only".into(), json!({"Statement":{
        "Effect":"Allow","Action":"lambda:AddPermission","Resource":format!("arn:aws:lambda:us-east-1:{ACCOUNT}:function:{FUNCTION}:prod")
    }}).to_string())]));
    assert_eq!(
        fixture
            .call(
                Method::POST,
                BASE,
                permission("base", GRANTEE),
                &fixture.grantor
            )
            .await
            .0,
        403
    );
    assert_eq!(
        fixture
            .call(
                Method::POST,
                &format!("{BASE}?%51ualifier=prod"),
                permission("alias", GRANTEE),
                &fixture.grantor
            )
            .await
            .0,
        201
    );
    assert_eq!(
        fixture
            .call(
                Method::POST,
                &format!("{BASE}?Qualifier=other"),
                permission("other", GRANTEE),
                &fixture.grantor
            )
            .await
            .0,
        403
    );
}

#[tokio::test]
async fn deleting_alias_clears_its_policy_and_qualified_delete_never_deletes_the_function() {
    let fixture = Fixture::new().await;
    fixture.publish_aliases().await;
    assert_eq!(
        fixture
            .call(
                Method::POST,
                &format!("{BASE}?Qualifier=prod"),
                permission("alias", GRANTEE),
                &fixture.grantor
            )
            .await
            .0,
        201
    );
    assert_eq!(
        fixture
            .call(
                Method::DELETE,
                &format!("/2015-03-31/functions/{FUNCTION}/aliases/prod"),
                Value::Null,
                &fixture.grantor
            )
            .await
            .0,
        204
    );
    assert_eq!(
        fixture
            .call(
                Method::POST,
                &format!("/2015-03-31/functions/{FUNCTION}/aliases"),
                json!({"Name":"prod","FunctionVersion":"1"}),
                &fixture.grantor
            )
            .await
            .0,
        201
    );
    fixture.invoke(Some("prod"), 403).await;
    for path in [
        format!("/2015-03-31/functions/{FUNCTION}:1"),
        format!("/2015-03-31/functions/{FUNCTION}?Qualifier=1"),
    ] {
        assert_eq!(
            fixture
                .call(Method::DELETE, &path, Value::Null, &fixture.grantor)
                .await
                .0,
            501
        );
    }
    assert_eq!(
        fixture
            .call(
                Method::GET,
                &format!("/2015-03-31/functions/{FUNCTION}"),
                Value::Null,
                &fixture.grantor
            )
            .await
            .0,
        200
    );
}

#[test]
fn qualified_policy_persistence_and_rollback() {
    const CHILD_PATH: &str = "LOCALLYCLOUD_QUALIFIED_POLICY_TEST_DB";
    let Some(path) = std::env::var_os(CHILD_PATH) else {
        use std::os::unix::fs::DirBuilderExt;
        let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../compatibility-tests/.work")
            .join(format!("qualified-policy-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "qualified_policy_persistence_and_rollback",
                "--nocapture",
            ])
            .env(CHILD_PATH, directory.join("state.sqlite3"))
            .env(
                "LOCALLYCLOUD_KMS_MASTER_KEY",
                "cXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXE=",
            )
            .status()
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        assert!(status.success());
        return;
    };
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let database = Arc::new(tokio::task::spawn_blocking(move || locallycloud_state::StateDb::open(path.into())).await.unwrap().unwrap());
        let fixture = Fixture::new().await;
        let lambda = fixture.lambda.clone();
        let state = database.clone();
        tokio::task::spawn_blocking(move || lambda.attach_state(state)).await.unwrap().unwrap();
        fixture.publish_aliases().await;
        for path in [BASE.to_owned(), format!("{BASE}?Qualifier=prod"), format!("{BASE}?Qualifier=1")] {
            let (status, body) = fixture.call(Method::POST, &path, permission("shared", GRANTEE), &fixture.grantor).await;
            assert_eq!(status, 201, "{body}");
        }
        let base = fixture.policy().await;
        let alias = fixture.policy_at(&format!("{BASE}?Qualifier=prod")).await;
        let version = fixture.policy_at(&format!("{BASE}?Qualifier=1")).await;
        let state = database.clone();
        tokio::task::spawn_blocking(move || state.connection().unwrap().execute_batch(
            "CREATE TRIGGER reject_qualified_policy BEFORE INSERT ON lambda_entities BEGIN SELECT RAISE(FAIL,'injected persistence failure'); END;"
        )).await.unwrap().unwrap();
        assert_eq!(fixture.call(Method::POST, &format!("{BASE}?Qualifier=prod"), permission("failed", GRANTEE), &fixture.grantor).await.0, 500);
        assert_eq!(fixture.call(Method::DELETE, &format!("{BASE}/shared?Qualifier=1"), Value::Null, &fixture.grantor).await.0, 500);
        assert_eq!(fixture.policy().await, base);
        assert_eq!(fixture.policy_at(&format!("{BASE}?Qualifier=prod")).await, alias);
        assert_eq!(fixture.policy_at(&format!("{BASE}?Qualifier=1")).await, version);
        drop(fixture);
        let restored = Fixture::new().await;
        let lambda = restored.lambda.clone();
        let state = database.clone();
        tokio::task::spawn_blocking(move || lambda.attach_state(state)).await.unwrap().unwrap();
        assert_eq!(restored.policy().await, base);
        assert_eq!(restored.policy_at(&format!("{BASE}?Qualifier=prod")).await, alias);
        assert_eq!(restored.policy_at(&format!("{BASE}?Qualifier=1")).await, version);
        restored.invoke(None, 501).await;
        restored.invoke(Some("prod"), 501).await;
        restored.invoke(Some("1"), 501).await;
        let state = database.clone();
        tokio::task::spawn_blocking(move || state.connection().unwrap().execute_batch("DROP TRIGGER reject_qualified_policy;")).await.unwrap().unwrap();
        assert_eq!(restored.call(Method::DELETE, &format!("{BASE}/shared"), Value::Null, &restored.grantor).await.0, 204);
        restored.invoke(None, 403).await;
        restored.invoke(Some("prod"), 501).await;
    });
}
