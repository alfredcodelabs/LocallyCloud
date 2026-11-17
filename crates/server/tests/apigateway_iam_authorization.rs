//! Real HTTP front door and IAM evaluator: no forged Core attestation in invocation fixtures.
#![cfg(feature = "services")]
use axum::{response::IntoResponse, routing::any, Router};
use hmac::{Hmac, Mac};
use http::Method;
use locallycloud::server::LocallyCloudServer;
use locallycloud_core::{
    config::{LambdaConcurrencyConfig, LocallyCloudConfig},
    registry::ServiceRegistry,
};
use locallycloud_iam_sts::{
    enforcement::EnforcementMode,
    model::{AccessKey, IamPolicy, IamUser, PolicyVersion},
    store::IamStore,
    sts::SessionStore,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

const ACCOUNT: &str = "000000000000";
const ADMIN: &str = "AKIAADMINTEST00000001";
const ACTOR: &str = "AKIAACTORTEST00000001";
const SECRET: &str = "owned-test-secret";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(key: &[u8], value: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(value.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
fn timestamp() -> (String, String) {
    let t = time::OffsetDateTime::now_utc();
    let day = format!("{:04}{:02}{:02}", t.year(), u8::from(t.month()), t.day());
    (
        format!("{day}T{:02}{:02}{:02}Z", t.hour(), t.minute(), t.second()),
        day,
    )
}
fn signing_key(secret: &str, day: &str, service: &str) -> Vec<u8> {
    digest(
        &digest(
            &digest(
                &digest(format!("AWS4{secret}").as_bytes(), day),
                "us-east-1",
            ),
            service,
        ),
        "aws4_request",
    )
}
fn signature(
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    body: &[u8],
    (key, secret): (&str, &str),
    service: &str,
) -> [(String, String); 2] {
    let (stamp, day) = timestamp();
    let scope = format!("{day}/us-east-1/{service}/aws4_request");
    let canonical_path = path.split('/').map(encode).collect::<Vec<_>>().join("/");
    let canonical = format!(
        "{method}\n{canonical_path}\n{query}\nhost:{host}\nx-amz-date:{stamp}\n\nhost;x-amz-date\n{}",
        hex(&Sha256::digest(body))
    );
    let signing = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    [("x-amz-date".into(),stamp),("authorization".into(),format!("AWS4-HMAC-SHA256 Credential={key}/{scope}, SignedHeaders=host;x-amz-date, Signature={}",hex(&digest(&signing_key(secret,&day,service),&signing))))]
}
fn allow(resource: &str) -> Value {
    json!({"Statement":[{"Effect":"Allow","Action":"execute-api:Invoke","Resource":resource}]})
}
fn user(name: &str, key: &str, policy: Value) -> IamUser {
    IamUser {
        user_name: name.into(),
        user_id: format!("AIDA{name}"),
        arn: format!("arn:aws:iam::{ACCOUNT}:user/{name}"),
        path: "/".into(),
        create_date: "2026-01-01T00:00:00Z".into(),
        tags: BTreeMap::new(),
        attached_policies: vec![],
        inline_policies: BTreeMap::from([("test".into(), policy.to_string())]),
        groups: vec![],
        permission_boundary: None,
        access_keys: vec![AccessKey {
            access_key_id: key.into(),
            secret_access_key: SECRET.into(),
            status: "Active".into(),
            create_date: "2026-01-01T00:00:00Z".into(),
        }],
    }
}
struct Fixture {
    base: String,
    host: String,
    backend: String,
    client: reqwest::Client,
    iam: Arc<IamStore>,
    registry: Arc<ServiceRegistry>,
    hits: Arc<AtomicUsize>,
    redirect_hits: Arc<AtomicUsize>,
    workers: Vec<JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
    }
}
impl Fixture {
    async fn new(mode: EnforcementMode) -> Self {
        Self::new_with_origins(mode, true).await
    }
    async fn new_with_origins(mode: EnforcementMode, allow_backend: bool) -> Self {
        let registry = ServiceRegistry::with_known_services();
        let iam = Arc::new(IamStore::new());
        iam.create_user(
            ACCOUNT,
            user(
                "admin",
                ADMIN,
                json!({"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}),
            ),
        );
        iam.create_user(ACCOUNT, user("actor", ACTOR, allow("*")));
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            iam.clone(),
            Arc::new(SessionStore::new()),
            mode,
        );
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_origin = format!("http://{}", backend.local_addr().unwrap());
        let backend_url = format!("{backend_origin}/owned");
        locallycloud_apigateway::register_with_config(
            &registry,
            locallycloud_apigateway::ApiGatewayConfig {
                http_local_origins: if allow_backend {
                    vec![backend_origin]
                } else {
                    Vec::new()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let redirect_hits = Arc::new(AtomicUsize::new(0));
        let redirects = redirect_hits.clone();
        let hits = Arc::new(AtomicUsize::new(0));
        let count = hits.clone();
        let backend_task = tokio::spawn(async move {
            axum::serve(
                backend,
                Router::new().fallback(any(move |uri: http::Uri| {
                    let count = count.clone();
                    let redirects = redirects.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        match uri.path() {
                            "/redirect" => (
                                http::StatusCode::FOUND,
                                [(http::header::LOCATION, "/redirect-target")],
                                "owned redirect",
                            )
                                .into_response(),
                            "/redirect-target" => {
                                redirects.fetch_add(1, Ordering::SeqCst);
                                "owned target".into_response()
                            }
                            _ => "owned".into_response(),
                        }
                    }
                })),
            )
            .await
            .unwrap();
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = LocallyCloudConfig {
            listen_addr: address,
            legacy_backend_url: "http://127.0.0.1:1".into(),
            external_endpoint: None,
            upstream_timeout: Duration::from_secs(2),
            legacy_health_check_interval: Duration::from_secs(60),
            max_request_body_bytes: 1024 * 1024,
            shutdown_grace_period: Duration::from_secs(1),
            ignored_settings: vec![],
            account_id: ACCOUNT.into(),
            default_region: "us-east-1".into(),
            tls: None,
            allow_http: true,
            ui_enabled: false,
            lambda_concurrency: LambdaConcurrencyConfig::default(),
            sqs_esm_max_pollers: 2,
        };
        let (ready, started) = tokio::sync::oneshot::channel();
        let server_registry = registry.clone();
        let task = tokio::spawn(async move {
            LocallyCloudServer::new(config, server_registry)
                .run_on_listener(listener, std::future::pending::<()>(), move || {
                    let _ = ready.send(());
                })
                .await
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), started)
            .await
            .unwrap()
            .unwrap();
        Self {
            base: format!("http://{address}"),
            host: address.to_string(),
            backend: backend_url,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            iam,
            registry,
            hits,
            redirect_hits,
            workers: vec![backend_task, task],
        }
    }
    async fn query(&self, service: &str, fields: &[(&str, String)]) -> String {
        let body = fields
            .iter()
            .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let mut request = self
            .client
            .post(&self.base)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.clone());
        for (name, value) in signature(
            "POST",
            "/",
            "",
            &self.host,
            body.as_bytes(),
            (ADMIN, SECRET),
            service,
        ) {
            request = request.header(name, value);
        }
        let response = request.send().await.unwrap();
        assert!(
            response.status().is_success(),
            "fixture Query operation failed"
        );
        response.text().await.unwrap()
    }
    fn actor_policy(&self, policy: Value) {
        self.iam.update_user(ACCOUNT, "actor", |u| {
            u.inline_policies = BTreeMap::from([("test".into(), policy.to_string())]);
        });
    }
    fn clear_actor_policies(&self) {
        self.iam.update_user(ACCOUNT, "actor", |u| {
            u.inline_policies.clear();
        });
    }
    async fn manage(&self, method: Method, path: &str, body: Value) -> Value {
        let bytes = body.to_string();
        let signed = signature(
            method.as_str(),
            path,
            "",
            &self.host,
            bytes.as_bytes(),
            (ADMIN, SECRET),
            "apigateway",
        );
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base))
            .header("content-type", "application/json")
            .body(bytes);
        for (name, value) in signed {
            request = request.header(name, value);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert!(status.is_success(), "{path}: {status} {body}");
        serde_json::from_str(&body).unwrap()
    }
    async fn rest(&self, authorization: &str, policy: Option<Value>) -> String {
        self.rest_to(authorization, policy, &self.backend).await
    }
    async fn rest_to(&self, authorization: &str, policy: Option<Value>, backend: &str) -> String {
        let mut body = json!({"name":"owned"});
        if let Some(policy) = policy {
            body["policy"] = json!(policy.to_string());
        }
        let api = self.manage(Method::POST, "/restapis", body).await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let root = self
            .manage(
                Method::GET,
                &format!("/restapis/{api}/resources"),
                Value::Null,
            )
            .await["item"][0]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        self.manage(
            Method::PUT,
            &format!("/restapis/{api}/resources/{root}/methods/ANY"),
            json!({"authorizationType":authorization}),
        )
        .await;
        self.manage(
            Method::PUT,
            &format!("/restapis/{api}/resources/{root}/methods/ANY/integration"),
            json!({"type":"HTTP_PROXY","httpMethod":"POST","uri":backend}),
        )
        .await;
        self.manage(
            Method::POST,
            &format!("/restapis/{api}/deployments"),
            json!({"stageName":"dev"}),
        )
        .await;
        api
    }
    async fn invoke(&self, method: Method, api: &str, sign: Option<&str>, expected: u16) {
        let path = format!("/restapis/{api}/dev/_user_request_/");
        let before = self.hits.load(Ordering::SeqCst);
        let mut request = self
            .client
            .request(method.clone(), format!("{}{path}", self.base));
        if let Some(secret) = sign {
            for (name, value) in signature(
                method.as_str(),
                &path,
                "",
                &self.host,
                b"",
                (ACTOR, secret),
                "execute-api",
            ) {
                request = request.header(name, value);
            }
        }
        let response = request.send().await.unwrap();
        assert_eq!(
            response.status().as_u16(),
            expected,
            "{}",
            response.text().await.unwrap()
        );
        assert_eq!(
            self.hits.load(Ordering::SeqCst) - before,
            usize::from(expected == 200)
        );
    }
}
#[tokio::test]
async fn rest_iam_requires_real_signature_and_permission_in_both_modes() {
    for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
        let f = Fixture::new(mode).await;
        let api = f.rest("AWS_IAM", None).await;
        f.actor_policy(allow(&format!(
            "arn:aws:execute-api:us-east-1:{ACCOUNT}:{api}/dev/GET/"
        )));
        f.invoke(Method::GET, &api, Some(SECRET), 200).await;
        f.invoke(Method::POST, &api, Some(SECRET), 403).await; // ANY must authorize the actual verb.
        f.invoke(Method::GET, &api, None, 403).await;
        f.invoke(Method::GET, &api, Some("wrong-secret"), 403).await;
        f.clear_actor_policies();
        f.invoke(Method::GET, &api, Some(SECRET), 403).await;
        f.actor_policy(json!({"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"execute-api:Invoke","Resource":"*"}]}));
        f.invoke(Method::GET, &api, Some(SECRET), 403).await;
        let public = f.rest("NONE", None).await;
        f.invoke(Method::GET, &public, None, 200).await;
    }
}
#[tokio::test]
async fn rest_resource_grant_composes_with_iam_and_explicit_deny() {
    let f = Fixture::new(EnforcementMode::Strict).await;
    let policy = json!({"Statement":[{"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:user/actor")},"Action":"execute-api:Invoke","Resource":"execute-api:/*"}]});
    let api = f.rest("AWS_IAM", Some(policy)).await;
    f.clear_actor_policies();
    f.invoke(Method::GET, &api, Some(SECRET), 200).await;
    f.actor_policy(
        json!({"Statement":[{"Effect":"Deny","Action":"execute-api:Invoke","Resource":"*"}]}),
    );
    f.invoke(Method::GET, &api, Some(SECRET), 403).await;
}

#[tokio::test]
async fn websocket_connect_authentication_precedes_live_upgrade() {
    let f = Fixture::new(EnforcementMode::Strict).await;
    for (authorization, sign, expected) in [
        ("NONE", false, 101),
        ("AWS_IAM", false, 403),
        ("AWS_IAM", true, 101),
    ] {
        let api=f.manage(Method::POST,"/v2/apis",json!({"name":"owned-ws","protocolType":"WEBSOCKET","routeSelectionExpression":"$request.body.action"})).await["apiId"].as_str().unwrap().to_owned();
        let integration = f
            .manage(
                Method::POST,
                &format!("/v2/apis/{api}/integrations"),
                json!({"integrationType":"MOCK"}),
            )
            .await["integrationId"]
            .as_str()
            .unwrap()
            .to_owned();
        f.manage(Method::POST,&format!("/v2/apis/{api}/routes"),json!({"routeKey":"$connect","authorizationType":authorization,"target":format!("integrations/{integration}")})).await;
        let deployment = f
            .manage(
                Method::POST,
                &format!("/v2/apis/{api}/deployments"),
                json!({}),
            )
            .await["deploymentId"]
            .as_str()
            .unwrap()
            .to_owned();
        f.manage(
            Method::POST,
            &format!("/v2/apis/{api}/stages"),
            json!({"stageName":"dev","deploymentId":deployment}),
        )
        .await;
        let host = format!("{api}.execute-api.us-east-1.amazonaws.com");
        let path = "/dev";
        let mut request=format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
        if sign {
            for (name, value) in
                signature("GET", path, "", &host, b"", (ACTOR, SECRET), "execute-api")
            {
                request.push_str(&format!("{name}: {value}\r\n"));
            }
        }
        request.push_str("\r\n");
        let mut socket = TcpStream::connect(&f.host).await.unwrap();
        socket.write_all(request.as_bytes()).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), async {
            let mut data = Vec::new();
            loop {
                let byte = socket.read_u8().await.unwrap();
                data.push(byte);
                assert!(data.len() < 8192);
                if data.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            String::from_utf8(data).unwrap()
        })
        .await
        .unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected} ")),
            "{response}"
        );
    }
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}
#[tokio::test]
async fn execute_api_presigned_get_and_post_check_signature_body_and_expiration() {
    let f = Fixture::new(EnforcementMode::Permissive).await;
    let api = f.rest("AWS_IAM", None).await;
    let (http_api, _) =
        http_api::create_http_api(&f, "ANY /items/{id}", "AWS_IAM", "dev", None).await;
    for (path, host) in [
        (
            format!("/restapis/{api}/dev/_user_request_/"),
            f.host.clone(),
        ),
        (
            "/dev/items/42".into(),
            format!("{http_api}.execute-api.us-east-1.amazonaws.com"),
        ),
    ] {
        for (method, payload) in [(Method::GET, ""), (Method::POST, "owned-body")] {
            for (expires, expected) in [("60", 200), ("0", 403), ("604801", 403)] {
                let (stamp, day) = timestamp();
                let scope = format!("{day}/us-east-1/execute-api/aws4_request");
                let query = BTreeMap::from([
                    ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_owned()),
                    ("X-Amz-Credential", format!("{ACTOR}/{scope}")),
                    ("X-Amz-Date", stamp.clone()),
                    ("X-Amz-Expires", expires.to_owned()),
                    ("X-Amz-SignedHeaders", "host".to_owned()),
                ])
                .iter()
                .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
                .collect::<Vec<_>>()
                .join("&");
                let canonical = format!(
                    "{}\n{path}\n{query}\nhost:{}\n\nhost\n{}",
                    method.as_str(),
                    host,
                    hex(&Sha256::digest(payload.as_bytes()))
                );
                let string = format!(
                    "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
                    hex(&Sha256::digest(canonical.as_bytes()))
                );
                let signature = hex(&digest(&signing_key(SECRET, &day, "execute-api"), &string));
                let before = f.hits.load(Ordering::SeqCst);
                let response = f
                    .client
                    .request(
                        method.clone(),
                        format!("{}{path}?{query}&X-Amz-Signature={signature}", f.base),
                    )
                    .header(http::header::HOST, &host)
                    .body(payload)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(
                    response.status().as_u16(),
                    expected,
                    "{}",
                    response.text().await.unwrap()
                );
                assert_eq!(
                    f.hits.load(Ordering::SeqCst) - before,
                    usize::from(expected == 200)
                );
            }
        }
    }
}
#[tokio::test]
async fn identity_grant_cannot_escape_permissions_boundary() {
    let f = Fixture::new(EnforcementMode::Strict).await;
    let api = f.rest("AWS_IAM", None).await;
    let arn = format!("arn:aws:iam::{ACCOUNT}:policy/boundary");
    f.iam.insert_policy(
        ACCOUNT,
        IamPolicy {
            policy_name: "boundary".into(),
            policy_id: "ANPABOUNDARY".into(),
            arn: arn.clone(),
            path: "/".into(),
            create_date: "2026-01-01T00:00:00Z".into(),
            default_version_id: "v1".into(),
            versions: vec![PolicyVersion {
                version_id: "v1".into(),
                document: json!({"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]})
                    .to_string(),
                is_default: true,
                create_date: "2026-01-01T00:00:00Z".into(),
            }],
            attachment_count: 0,
            description: None,
            tags: BTreeMap::new(),
            is_aws_managed: false,
        },
    );
    f.iam.update_user(ACCOUNT, "actor", |u| {
        u.permission_boundary = Some(arn);
    });
    f.invoke(Method::GET, &api, Some(SECRET), 403).await;
}

fn xml_field<'a>(xml: &'a str, name: &str) -> &'a str {
    xml.split_once(&format!("<{name}>"))
        .and_then(|(_, rest)| rest.split_once(&format!("</{name}>")))
        .map(|(value, _)| value)
        .expect("field in owned STS fixture response")
}

#[tokio::test]
async fn sts_session_policy_cannot_expand_role_invoke_permission() {
    for mode in [EnforcementMode::Permissive, EnforcementMode::Strict] {
        let f = Fixture::new(mode).await;
        let api = f.rest("AWS_IAM", None).await;
        let trust = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:root")},"Action":"sts:AssumeRole"}]}).to_string();
        f.query(
            "iam",
            &[
                ("Action", "CreateRole".into()),
                ("RoleName", "invoke-role".into()),
                ("AssumeRolePolicyDocument", trust),
            ],
        )
        .await;
        f.query(
            "iam",
            &[
                ("Action", "PutRolePolicy".into()),
                ("RoleName", "invoke-role".into()),
                ("PolicyName", "invoke".into()),
                ("PolicyDocument", allow("*").to_string()),
            ],
        )
        .await;
        for (policy, expected) in [
            (allow("*"), 200),
            (
                json!({"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}),
                403,
            ),
            (
                json!({"Statement":[{"Effect":"Deny","Action":"execute-api:Invoke","Resource":"*"}]}),
                403,
            ),
        ] {
            let response = f
                .query(
                    "sts",
                    &[
                        ("Action", "AssumeRole".into()),
                        (
                            "RoleArn",
                            format!("arn:aws:iam::{ACCOUNT}:role/invoke-role"),
                        ),
                        ("RoleSessionName", "invoke-test".into()),
                        ("Policy", policy.to_string()),
                    ],
                )
                .await;
            let key = xml_field(&response, "AccessKeyId");
            let secret = xml_field(&response, "SecretAccessKey");
            let token = xml_field(&response, "SessionToken");
            let path = format!("/restapis/{api}/dev/_user_request_/");
            let (stamp, day) = timestamp();
            let scope = format!("{day}/us-east-1/execute-api/aws4_request");
            let canonical=format!("GET\n{path}\n\nhost:{}\nx-amz-date:{stamp}\nx-amz-security-token:{token}\n\nhost;x-amz-date;x-amz-security-token\n{}",f.host,hex(&Sha256::digest(b"")));
            let to_sign = format!(
                "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
                hex(&Sha256::digest(canonical.as_bytes()))
            );
            let auth=format!("AWS4-HMAC-SHA256 Credential={key}/{scope}, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature={}",hex(&digest(&signing_key(secret,&day,"execute-api"),&to_sign)));
            let before = f.hits.load(Ordering::SeqCst);
            let result = f
                .client
                .get(format!("{}{path}", f.base))
                .header("x-amz-date", stamp)
                .header("x-amz-security-token", token)
                .header("authorization", auth)
                .send()
                .await
                .unwrap();
            assert_eq!(result.status().as_u16(), expected);
            assert_eq!(
                f.hits.load(Ordering::SeqCst) - before,
                usize::from(expected == 200)
            );
        }
    }
}

#[tokio::test]
async fn http_integration_egress_checks_origins_after_valid_iam_in_both_modes() {
    for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
        let denied = Fixture::new_with_origins(mode, false).await;
        let api = denied.rest("AWS_IAM", None).await;
        // The same valid identity has invoke permission; the outbound origin gate denies it.
        denied.invoke(Method::GET, &api, Some(SECRET), 500).await;

        let mut allowed = Fixture::new_with_origins(mode, true).await;
        let api = allowed.rest("AWS_IAM", None).await;
        allowed.invoke(Method::GET, &api, Some(SECRET), 200).await;
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!("http://{}/owned", second.local_addr().unwrap());
        let second_hits = Arc::new(AtomicUsize::new(0));
        let counter = second_hits.clone();
        allowed.workers.push(tokio::spawn(async move {
            axum::serve(
                second,
                Router::new().fallback(any(move || {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        "wrong port"
                    }
                })),
            )
            .await
            .unwrap();
        }));
        let wrong_port = allowed.rest_to("AWS_IAM", None, &target).await;
        allowed
            .invoke(Method::GET, &wrong_port, Some(SECRET), 500)
            .await;
        assert_eq!(second_hits.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn allowed_http_integration_returns_redirect_without_following_it() {
    let fixture = Fixture::new(EnforcementMode::Strict).await;
    let target = fixture.backend.replace("/owned", "/redirect");
    let api = fixture.rest_to("AWS_IAM", None, &target).await;
    let path = format!("/restapis/{api}/dev/_user_request_/");
    let mut request = fixture.client.get(format!("{}{path}", fixture.base));
    for (name, value) in signature(
        "GET",
        &path,
        "",
        &fixture.host,
        b"",
        (ACTOR, SECRET),
        "execute-api",
    ) {
        request = request.header(name, value);
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), http::StatusCode::FOUND);
    assert_eq!(
        response.headers()[http::header::LOCATION],
        "/redirect-target"
    );
    assert_eq!(response.text().await.unwrap(), "owned redirect");
    assert_eq!(fixture.hits.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.redirect_hits.load(Ordering::SeqCst), 0);
}

#[path = "apigateway_iam_authorization/http_api.rs"]
mod http_api;
