//! Registry Basic tokens retain their issuer's live IAM, session and repository restrictions.
#![cfg(feature = "services")]

use axum::body::to_bytes;
use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, Method};
use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use locallycloud_iam_sts::enforcement::EnforcementMode;
use locallycloud_iam_sts::model::{AccessKey, IamPolicy, IamRole, IamUser, PolicyVersion};
use locallycloud_iam_sts::store::IamStore;
use locallycloud_iam_sts::sts::SessionStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const ACCOUNT: &str = "000000000000";
const ADMIN: &str = "AKIAECRADMIN000000001";
const REPOSITORY: &str = "team/app";
const REPOSITORY_ARN: &str = "arn:aws:ecr:us-east-1:000000000000:repository/team/app";
const MANIFEST_PATH: &str = "/v2/team/app/manifests/latest";

struct Fixture {
    registry: Arc<ServiceRegistry>,
    iam: Arc<IamStore>,
    ecr: Arc<locallycloud_ecr::EcrHandler>,
}

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

impl Fixture {
    async fn new() -> Self {
        let registry = ServiceRegistry::with_known_services();
        let iam = Arc::new(IamStore::new());
        iam.create_user(
            ACCOUNT,
            IamUser {
                user_name: "admin".into(),
                user_id: "AIDAECRADMIN".into(),
                arn: format!("arn:aws:iam::{ACCOUNT}:user/admin"),
                path: "/".into(),
                create_date: "2026-01-01T00:00:00Z".into(),
                tags: BTreeMap::new(),
                attached_policies: Vec::new(),
                groups: Vec::new(),
                permission_boundary: None,
                inline_policies: BTreeMap::from([(
                    "admin".into(),
                    json!({"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}).to_string(),
                )]),
                access_keys: vec![AccessKey {
                    access_key_id: ADMIN.into(),
                    secret_access_key: "secret".into(),
                    status: "Active".into(),
                    create_date: "2026-01-01T00:00:00Z".into(),
                }],
            },
        );
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
        let ecr = locallycloud_ecr::register_with_handle_and_endpoint(
            &registry,
            "https://aws.localhost:4566",
        )
        .unwrap();
        let fixture = Self { registry, iam, ecr };
        fixture
            .ok(
                ADMIN,
                "CreateRepository",
                json!({"repositoryName":REPOSITORY}),
            )
            .await;
        fixture
    }

    fn role(&self, name: &str, statements: Value) -> String {
        let arn = format!("arn:aws:iam::{ACCOUNT}:role/{name}");
        self.iam.create_role(ACCOUNT,IamRole {
            role_name:name.into(),role_id:format!("AROA{name}"),arn:arn.clone(),path:"/".into(),create_date:"2026-01-01T00:00:00Z".into(),
            assume_role_policy_document:json!({"Statement":{"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:user/admin")},"Action":"sts:AssumeRole"}}).to_string(),
            description:None,max_session_duration:3600,tags:BTreeMap::new(),attached_policies:Vec::new(),permission_boundary:None,
            inline_policies:BTreeMap::from([("permissions".into(),json!({"Statement":statements}).to_string())]),
        });
        arn
    }

    fn role_policy(&self, name: &str, statements: Value) {
        assert!(self.iam.update_role(ACCOUNT, name, |role| {
            role.inline_policies = BTreeMap::from([(
                "permissions".into(),
                json!({"Statement":statements}).to_string(),
            )]);
        }));
    }

    fn headers(key: &str, service: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", "aws.localhost:4566".parse().unwrap());
        headers.insert(
            "authorization",
            format!("AWS4-HMAC-SHA256 Credential={key}/20261116/us-east-1/{service}/aws4_request")
                .parse()
                .unwrap(),
        );
        // Trusted native fixtures model ingress attestation; Core's cryptographic verifier is tested separately.
        headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        headers.insert("x-locallycloud-verified-ecr-sigv4", "1".parse().unwrap());
        headers.insert(
            "x-locallycloud-verified-secure-transport",
            "true".parse().unwrap(),
        );
        headers.insert(
            "x-locallycloud-trusted-peer-ip",
            "127.0.0.1".parse().unwrap(),
        );
        headers
    }

    async fn assume(&self, name: &str, policy: Option<Value>) -> String {
        let mut body = format!(
            "Action=AssumeRole&RoleArn={}&RoleSessionName=ecr-client",
            encode(&format!("arn:aws:iam::{ACCOUNT}:role/{name}"))
        );
        if let Some(policy) = policy {
            body.push_str(&format!("&Policy={}", encode(&policy.to_string())));
        }
        let response = self
            .registry
            .native_handler(&ServiceName::new("sts"))
            .unwrap()
            .handle(ServiceRequest {
                method: Method::POST,
                uri: "/".parse().unwrap(),
                headers: Self::headers(ADMIN, "sts"),
                body: body.into(),
                region: "us-east-1".into(),
                account_id: ACCOUNT.into(),
                request_id: "ecr-assume".into(),
            })
            .await;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
        let xml = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(status, 200, "{xml}");
        xml.split_once("<AccessKeyId>")
            .unwrap()
            .1
            .split_once("</AccessKeyId>")
            .unwrap()
            .0
            .to_owned()
    }

    async fn control(&self, key: &str, operation: &str, body: Value) -> (u16, Value) {
        let mut headers = Self::headers(key, "ecr");
        headers.insert(
            "x-amz-target",
            format!("AmazonEC2ContainerRegistry_V20150921.{operation}")
                .parse()
                .unwrap(),
        );
        let response = self
            .registry
            .native_handler(&ServiceName::new("ecr"))
            .unwrap()
            .handle(ServiceRequest {
                method: Method::POST,
                uri: "/".parse().unwrap(),
                headers,
                body: body.to_string().into(),
                region: "us-east-1".into(),
                account_id: ACCOUNT.into(),
                request_id: "ecr-control".into(),
            })
            .await;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn ok(&self, key: &str, operation: &str, body: Value) -> Value {
        let (status, value) = self.control(key, operation, body).await;
        assert_eq!(status, 200, "{operation}: {value}");
        value
    }

    async fn token(&self, key: &str) -> String {
        self.ok(key, "GetAuthorizationToken", json!({})).await["authorizationData"][0]
            ["authorizationToken"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn registry(&self, token: &str, method: Method, path: &str, body: &[u8]) -> Response {
        self.registry_with_headers(token, method, path, body, HeaderMap::new())
            .await
    }

    async fn registry_with_headers(
        &self,
        token: &str,
        method: Method,
        path: &str,
        body: &[u8],
        extra_headers: HeaderMap,
    ) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert("host", "aws.localhost:4566".parse().unwrap());
        headers.insert("authorization", format!("Basic {token}").parse().unwrap());
        headers.insert(
            "x-locallycloud-verified-secure-transport",
            "true".parse().unwrap(),
        );
        headers.insert(
            "x-locallycloud-trusted-peer-ip",
            "127.0.0.1".parse().unwrap(),
        );
        headers.insert(
            "content-type",
            if path.contains("/manifests/") {
                "application/vnd.oci.image.manifest.v1+json"
            } else {
                "application/octet-stream"
            }
            .parse()
            .unwrap(),
        );
        headers.extend(extra_headers);
        self.registry
            .native_handler(&ServiceName::new("ecr"))
            .unwrap()
            .handle(ServiceRequest {
                method,
                uri: path.parse().unwrap(),
                headers,
                body: Bytes::copy_from_slice(body),
                region: "us-east-1".into(),
                account_id: ACCOUNT.into(),
                request_id: "ecr-registry".into(),
            })
            .await
    }

    async fn begin(&self, token: &str) -> String {
        let response = self
            .registry(token, Method::POST, "/v2/team/app/blobs/uploads/", b"")
            .await;
        assert_eq!(response.status(), 202);
        response.headers()["location"].to_str().unwrap().to_owned()
    }

    async fn seed_image(&self, token: &str) -> String {
        let config=br#"{"architecture":"amd64","os":"linux","config":{},"rootfs":{"type":"layers","diff_ids":[]}}"#;
        let digest = format!("sha256:{:x}", Sha256::digest(config));
        let upload = self.begin(token).await;
        assert_eq!(
            self.registry(
                token,
                Method::PUT,
                &format!("{upload}?digest={digest}"),
                config
            )
            .await
            .status(),
            201
        );
        let manifest=json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":digest,"size":config.len()},"layers":[]}).to_string();
        assert_eq!(
            self.registry(token, Method::PUT, MANIFEST_PATH, manifest.as_bytes())
                .await
                .status(),
            201
        );
        digest
    }

    async fn repository_policy(&self, policy: Value) {
        self.ok(
            ADMIN,
            "SetRepositoryPolicy",
            json!({"repositoryName":REPOSITORY,"policyText":policy.to_string(),"force":true}),
        )
        .await;
    }
}

fn token_permission() -> Value {
    json!({"Effect":"Allow","Action":"ecr:GetAuthorizationToken","Resource":"*"})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registry_token_is_not_a_push_or_pull_grant_and_denied_uploads_do_not_mutate() {
    let fixture = Fixture::new().await;
    fixture.role("token-only", token_permission());
    let actor = fixture.assume("token-only", None).await;
    let token = fixture.token(&actor).await;
    let admin = fixture.token(ADMIN).await;
    let blob = fixture.seed_image(&admin).await;
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        403
    );
    assert_eq!(
        fixture
            .registry(
                &token,
                Method::GET,
                &format!("/v2/team/app/blobs/{blob}"),
                b""
            )
            .await
            .status(),
        403
    );
    let denied = fixture
        .registry(&token, Method::POST, "/v2/team/app/blobs/uploads/", b"")
        .await;
    assert_eq!(denied.status(), 403);
    assert!(denied.headers().get("location").is_none());
    let upload = fixture.begin(&admin).await;
    assert_eq!(
        fixture
            .registry(&token, Method::PATCH, &upload, b"forbidden bytes")
            .await
            .status(),
        403
    );
    assert_eq!(
        fixture
            .registry(
                &token,
                Method::PUT,
                &format!(
                    "{upload}?digest=sha256:{:x}",
                    Sha256::digest(b"forbidden bytes")
                ),
                b"forbidden bytes"
            )
            .await
            .status(),
        403
    );
    let empty = format!("sha256:{:x}", Sha256::digest(b""));
    assert_eq!(
        fixture
            .registry(
                &admin,
                Method::PUT,
                &format!("{upload}?digest={empty}"),
                b""
            )
            .await
            .status(),
        201
    );
    assert_eq!(
        fixture
            .registry(&admin, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_registry_token_rechecks_updated_identity_permissions_and_explicit_denies() {
    let fixture = Fixture::new().await;
    fixture.role("changing", token_permission());
    let actor = fixture.assume("changing", None).await;
    let token = fixture.token(&actor).await;
    let admin = fixture.token(ADMIN).await;
    fixture.seed_image(&admin).await;
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        403
    );
    fixture.role_policy(
        "changing",
        json!({"Effect":"Allow","Action":"ecr:*","Resource":"*"}),
    );
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        200
    );
    fixture.role_policy("changing", json!([
        {"Effect":"Allow","Action":"ecr:*","Resource":"*"},
        {"Effect":"Deny","Action":"ecr:BatchGetImage","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}
    ]));
    let mut http = HeaderMap::new();
    http.insert(
        "x-locallycloud-verified-secure-transport",
        "false".parse().unwrap(),
    );
    assert_eq!(
        fixture
            .registry_with_headers(&token, Method::GET, MANIFEST_PATH, b"", http)
            .await
            .status(),
        403
    );
    fixture.role_policy("changing", json!([
        {"Effect":"Allow","Action":"ecr:*","Resource":"*"},
        {"Effect":"Deny","Action":"ecr:BatchGetImage","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"127.0.0.2/32"}}}
    ]));
    let mut peer = HeaderMap::new();
    peer.insert(
        "x-locallycloud-trusted-peer-ip",
        "127.0.0.2".parse().unwrap(),
    );
    assert_eq!(
        fixture
            .registry_with_headers(&token, Method::GET, MANIFEST_PATH, b"", peer)
            .await
            .status(),
        403
    );
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        200
    );
    fixture.role_policy(
        "changing",
        json!([
            {"Effect":"Allow","Action":"ecr:*","Resource":"*"},
            {"Effect":"Deny","Action":"ecr:BatchGetImage","Resource":REPOSITORY_ARN}
        ]),
    );
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        403
    );
    fixture.role_policy("changing", json!([]));
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        403
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repository_policy_can_supply_allow_but_not_override_identity_or_repository_deny() {
    let fixture = Fixture::new().await;
    let role = fixture.role("repository-grant", token_permission());
    let actor = fixture.assume("repository-grant", None).await;
    let token = fixture.token(&actor).await;
    let admin = fixture.token(ADMIN).await;
    let blob = fixture.seed_image(&admin).await;
    let allow = json!({"Effect":"Allow","Principal":{"AWS":role},"Action":["ecr:BatchGetImage","ecr:BatchCheckLayerAvailability","ecr:GetDownloadUrlForLayer"]});
    fixture.repository_policy(json!({"Statement":allow})).await;
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        200
    );
    assert_eq!(
        fixture
            .registry(
                &token,
                Method::HEAD,
                &format!("/v2/team/app/blobs/{blob}"),
                b""
            )
            .await
            .status(),
        200
    );
    fixture.role_policy(
        "repository-grant",
        json!([token_permission(),{"Effect":"Deny","Action":"ecr:BatchGetImage","Resource":"*"}]),
    );
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        403
    );
    fixture.role_policy("repository-grant", token_permission());
    fixture.repository_policy(json!({"Statement":[allow,{"Effect":"Deny","Principal":{"AWS":role},"Action":"ecr:GetDownloadUrlForLayer"}]})).await;
    assert_eq!(
        fixture
            .registry(
                &token,
                Method::GET,
                &format!("/v2/team/app/blobs/{blob}"),
                b""
            )
            .await
            .status(),
        403
    );
    let prior = fixture
        .ok(
            ADMIN,
            "GetRepositoryPolicy",
            json!({"repositoryName":REPOSITORY}),
        )
        .await;
    let unsupported = fixture.control(ADMIN,"SetRepositoryPolicy",json!({"repositoryName":REPOSITORY,"force":true,"policyText":json!({"Statement":{"Effect":"Allow","NotPrincipal":"*","Action":"ecr:*"}}).to_string()})).await;
    assert_eq!(
        unsupported.0, 501,
        "An unsupported policy construct must be rejected explicitly: {}",
        unsupported.1
    );
    assert_eq!(unsupported.1["__type"], "UnsupportedOperationException");
    assert_eq!(
        fixture
            .ok(
                ADMIN,
                "GetRepositoryPolicy",
                json!({"repositoryName":REPOSITORY})
            )
            .await["policyText"],
        prior["policyText"]
    );
    fixture
        .ok(
            ADMIN,
            "DeleteRepositoryPolicy",
            json!({"repositoryName":REPOSITORY}),
        )
        .await;
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        403
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registry_repository_grants_respect_session_and_permission_boundary_limits() {
    let fixture = Fixture::new().await;
    let role = fixture.role(
        "limited",
        json!({"Effect":"Allow","Action":"ecr:*","Resource":"*"}),
    );
    let actor = fixture
        .assume(
            "limited",
            Some(json!({"Statement":[
                {"Effect":"Allow","Action":"ecr:*","Resource":"*"},
                {"Effect":"Deny","Action":"ecr:BatchGetImage","Resource":"*"}
            ]})),
        )
        .await;
    let token = fixture.token(&actor).await;
    let unrestricted = fixture.assume("limited", None).await;
    let unrestricted_token = fixture.token(&unrestricted).await;
    let admin = fixture.token(ADMIN).await;
    fixture.seed_image(&admin).await;
    fixture.repository_policy(json!({"Statement":{"Effect":"Allow","Principal":{"AWS":role},"Action":"ecr:BatchGetImage"}})).await;
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        403
    );
    assert_eq!(
        fixture
            .registry(&unrestricted_token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        200
    );
    let boundary = format!("arn:aws:iam::{ACCOUNT}:policy/ecr-boundary");
    fixture.iam.insert_policy(
        ACCOUNT,
        IamPolicy {
            policy_name: "ecr-boundary".into(),
            policy_id: "ANPAECRBOUNDARY".into(),
            arn: boundary.clone(),
            path: "/".into(),
            create_date: "2026-01-01T00:00:00Z".into(),
            default_version_id: "v1".into(),
            versions: vec![PolicyVersion {
                version_id: "v1".into(),
                document: json!({"Statement":token_permission()}).to_string(),
                is_default: true,
                create_date: "2026-01-01T00:00:00Z".into(),
            }],
            attachment_count: 1,
            description: None,
            tags: BTreeMap::new(),
            is_aws_managed: false,
        },
    );
    fixture.iam.update_role(ACCOUNT, "limited", |role| {
        role.permission_boundary = Some(boundary)
    });
    assert_eq!(
        fixture
            .registry(&unrestricted_token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        403
    );
    fixture
        .iam
        .update_role(ACCOUNT, "limited", |role| role.permission_boundary = None);
    assert_eq!(
        fixture
            .registry(&unrestricted_token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        200
    );
    fixture.iam.remove_role(ACCOUNT, "limited");
    assert_eq!(
        fixture
            .registry(&unrestricted_token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        403
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repository_policy_survives_restore_and_failed_updates_do_not_publish_partial_state() {
    const CHILD: &str = "LOCALLYCLOUD_ECR_POLICY_TEST_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("repository_policy_survives_restore_and_failed_updates_do_not_publish_partial_state")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env("LOCALLYCLOUD_KMS_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .output().await.unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory =
        Directory(std::env::temp_dir().join(format!("ecr-policy-state-{}", uuid::Uuid::new_v4())));
    locallycloud_state::StateDb::private_dir(&directory.0).unwrap();
    let database =
        Arc::new(locallycloud_state::StateDb::open(directory.0.join("state.sqlite3")).unwrap());
    let fixture = Fixture::new().await;
    locallycloud_ecr::register_with_state_and_endpoint(
        &fixture.registry,
        database.clone(),
        "https://aws.localhost:4566",
    )
    .await
    .unwrap();
    fixture
        .ok(
            ADMIN,
            "CreateRepository",
            json!({"repositoryName":REPOSITORY}),
        )
        .await;
    let role = fixture.role("durable-policy", token_permission());
    let actor = fixture.assume("durable-policy", None).await;
    let admin = fixture.token(ADMIN).await;
    fixture.seed_image(&admin).await;
    let policy = json!({"Statement":{"Sid":"durable-repository-grant-unique-marker","Effect":"Allow","Principal":{"AWS":role},"Action":"ecr:BatchGetImage"}});
    fixture.repository_policy(policy.clone()).await;
    locallycloud_ecr::register_with_state_and_endpoint(
        &fixture.registry,
        database.clone(),
        "https://aws.localhost:4566",
    )
    .await
    .unwrap();
    let restored = fixture
        .ok(
            ADMIN,
            "GetRepositoryPolicy",
            json!({"repositoryName":REPOSITORY}),
        )
        .await;
    assert_eq!(
        serde_json::from_str::<Value>(restored["policyText"].as_str().unwrap()).unwrap(),
        policy
    );
    let token = fixture.token(&actor).await;
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        200
    );
    let payload: Vec<u8> = database
        .connection()
        .unwrap()
        .query_row(
            "SELECT payload FROM ecr_records WHERE kind='repository'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!payload
        .windows(b"durable-repository-grant-unique-marker".len())
        .any(|window| window == b"durable-repository-grant-unique-marker"));
    database.connection().unwrap().execute_batch("CREATE TRIGGER fail_policy_update AFTER UPDATE ON ecr_records WHEN NEW.kind='repository' BEGIN SELECT RAISE(FAIL,'injected policy update failure'); END;").unwrap();
    let failed=fixture.control(ADMIN,"SetRepositoryPolicy",json!({"repositoryName":REPOSITORY,"force":true,"policyText":json!({"Statement":{"Effect":"Deny","Principal":"*","Action":"ecr:BatchGetImage"}}).to_string()})).await;
    assert_eq!(failed.0, 500);
    assert_eq!(
        fixture
            .ok(
                ADMIN,
                "GetRepositoryPolicy",
                json!({"repositoryName":REPOSITORY})
            )
            .await["policyText"],
        restored["policyText"]
    );
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        200
    );
    locallycloud_ecr::register_with_state_and_endpoint(
        &fixture.registry,
        database.clone(),
        "https://aws.localhost:4566",
    )
    .await
    .unwrap();
    assert_eq!(
        fixture
            .ok(
                ADMIN,
                "GetRepositoryPolicy",
                json!({"repositoryName":REPOSITORY})
            )
            .await["policyText"],
        restored["policyText"]
    );
    database
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_policy_update")
        .unwrap();
    fixture
        .ok(
            ADMIN,
            "DeleteRepositoryPolicy",
            json!({"repositoryName":REPOSITORY}),
        )
        .await;
    locallycloud_ecr::register_with_state_and_endpoint(
        &fixture.registry,
        database,
        "https://aws.localhost:4566",
    )
    .await
    .unwrap();
    let absent = fixture
        .control(
            ADMIN,
            "GetRepositoryPolicy",
            json!({"repositoryName":REPOSITORY}),
        )
        .await;
    assert_eq!(absent.0, 400);
    assert_eq!(absent.1["__type"], "RepositoryPolicyNotFoundException");
    let token = fixture.token(&actor).await;
    assert_eq!(
        fixture
            .registry(&token, Method::GET, MANIFEST_PATH, b"")
            .await
            .status(),
        403
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_execution_image_pull_rechecks_trust_and_repository_policies() {
    use locallycloud_core::integration::identity::CallerIdentity;
    let fixture = Fixture::new().await;
    let role = fixture.role("image-pull", token_permission());
    fixture.iam.update_role(ACCOUNT,"image-pull",|role| role.assume_role_policy_document=json!({"Statement":{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}}).to_string());
    let admin = fixture.token(ADMIN).await;
    fixture.seed_image(&admin).await;
    let caller = CallerIdentity::AssumedRole {
        role_arn: role.clone(),
        session_name: "ecs-task".into(),
    };
    assert!(fixture
        .ecr
        .authorize_image_pull(ACCOUNT, "us-east-1", REPOSITORY, caller.clone())
        .await
        .is_err());
    fixture.repository_policy(json!({"Statement":{"Effect":"Allow","Principal":{"AWS":role},"Action":"ecr:BatchGetImage"}})).await;
    assert!(fixture
        .ecr
        .authorize_image_pull(ACCOUNT, "us-east-1", REPOSITORY, caller.clone())
        .await
        .is_err());
    let allow = json!({"Effect":"Allow","Principal":{"AWS":role},"Action":["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"]});
    fixture.repository_policy(json!({"Statement":allow})).await;
    fixture
        .ecr
        .authorize_image_pull(ACCOUNT, "us-east-1", REPOSITORY, caller.clone())
        .await
        .unwrap();
    fixture.repository_policy(json!({"Statement":[allow,{"Effect":"Deny","Principal":{"AWS":role},"Action":"ecr:GetDownloadUrlForLayer"}]})).await;
    assert!(fixture
        .ecr
        .authorize_image_pull(ACCOUNT, "us-east-1", REPOSITORY, caller.clone())
        .await
        .is_err());
    fixture.repository_policy(json!({"Statement":allow})).await;
    fixture.role_policy(
        "image-pull",
        json!([token_permission(),{"Effect":"Deny","Action":"ecr:BatchGetImage","Resource":"*"}]),
    );
    assert!(fixture
        .ecr
        .authorize_image_pull(ACCOUNT, "us-east-1", REPOSITORY, caller.clone())
        .await
        .is_err());
    fixture.role_policy("image-pull", token_permission());
    fixture.iam.update_role(ACCOUNT,"image-pull",|role| role.assume_role_policy_document=json!({"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}).to_string());
    assert!(fixture
        .ecr
        .authorize_image_pull(ACCOUNT, "us-east-1", REPOSITORY, caller)
        .await
        .is_err());
}
