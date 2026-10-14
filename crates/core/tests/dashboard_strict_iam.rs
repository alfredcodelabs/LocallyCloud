//! Dashboard reads under strict IAM.
//!
//! These tests run the real Axum front door on an ephemeral loopback port. Strict IAM is
//! modeled by an evaluator that requires SigV4 at ingress and verifies signatures with
//! Core's real verifier, so the dashboard read only succeeds when the server-held local
//! profile actually signed it. The dashboard has no unsigned exception.
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::response::Response;
use http::{HeaderMap, Method, Uri};
use locallycloud_core::audit::{CompletionObserver, DispatchOutcome};
use locallycloud_core::config::LocallyCloudConfig;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::{
    AuthorizationError, AuthorizationEvaluator, AuthorizationRequest, SigningCredentials,
};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_core::server::LocallyCloudServer;

const ACCESS_KEY: &str = "AKIDLOCALDASHBOARD";
const SECRET: &str = "local-dashboard-secret";
const PROFILE_ACCOUNT: &str = "111122223333";

struct StrictEvaluator;

impl AuthorizationEvaluator for StrictEvaluator {
    fn strict_sigv4_required(&self) -> bool {
        true
    }

    fn authorize(&self, _request: AuthorizationRequest) -> Result<(), AuthorizationError> {
        Ok(())
    }

    fn credential_account(
        &self,
        access_key_id: &str,
    ) -> Result<Option<String>, AuthorizationError> {
        Ok((access_key_id == ACCESS_KEY).then(|| PROFILE_ACCOUNT.to_owned()))
    }

    fn verify_sigv4(
        &self,
        account: &str,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
        region: &str,
        service: &str,
    ) -> bool {
        account == PROFILE_ACCOUNT
            && locallycloud_core::integration::sigv4::verify(
                method,
                uri,
                headers,
                body,
                region,
                service,
                |key| {
                    (key == ACCESS_KEY).then(|| SigningCredentials {
                        secret_access_key: SECRET.into(),
                        session_token: None,
                    })
                },
            )
    }
}

#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<(String, String)>>,
}

struct RecordingDynamo(Arc<Recorder>);

#[async_trait::async_trait]
impl NativeHandler for RecordingDynamo {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let target = request
            .headers
            .get("x-amz-target")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        self.0
            .calls
            .lock()
            .unwrap()
            .push((target, request.account_id));
        Response::builder()
            .status(200)
            .header("content-type", "application/x-amz-json-1.0")
            .body(axum::body::Body::from(r#"{"TableNames":["orders"]}"#))
            .unwrap()
    }
}

struct StubIam;

#[async_trait::async_trait]
impl NativeHandler for StubIam {
    async fn handle(&self, _request: ServiceRequest) -> Response {
        Response::builder()
            .status(200)
            .body(axum::body::Body::empty())
            .unwrap()
    }
}

#[derive(Default)]
struct CaptureObserver(Mutex<Vec<DispatchOutcome>>);

impl CompletionObserver for CaptureObserver {
    fn observe(&self, outcome: DispatchOutcome) {
        self.0.lock().unwrap().push(outcome);
    }
}

/// Per-process HOME/AWS file isolation; never read the developer's real `~/.aws`.
fn aws_home() -> &'static PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "locallycloud-dashboard-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("HOME", &dir);
        std::env::set_var("AWS_CONFIG_FILE", dir.join("config"));
        std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", dir.join("credentials"));
        dir
    })
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start(port: u16, extra: &[(&str, &str)], registry: Arc<ServiceRegistry>) -> String {
    let port_value = port.to_string();
    let mut vars = vec![
        ("LOCALLYCLOUD_PORT", port_value.as_str()),
        ("LOCALLYCLOUD_LEGACY_BACKEND_URL", "http://127.0.0.1:1"),
    ];
    vars.extend_from_slice(extra);
    let config = LocallyCloudConfig::resolve(&|name| {
        vars.iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.to_string())
    })
    .unwrap();
    tokio::spawn(LocallyCloudServer::new(config, registry).run());
    let base = format!("http://127.0.0.1:{port}");
    for _ in 0..200 {
        if reqwest::get(format!("{base}/_locallycloud/health"))
            .await
            .is_ok_and(|r| r.status() == 200)
        {
            return base;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("server did not become ready");
}

async fn read(
    client: &reqwest::Client,
    base: &str,
    body: serde_json::Value,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let mut request = client
        .post(format!("{base}/_locallycloud/explore/read"))
        .header("content-type", "application/json")
        .body(body.to_string());
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let error_type = response
        .headers()
        .get("x-amzn-errortype")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = response.text().await.unwrap();
    (status, format!("{error_type} {body}"))
}

#[tokio::test]
async fn strict_iam_dashboard_reads_are_signed_audited_and_bounded() {
    let home = aws_home();
    let port = free_port();
    std::fs::write(
        home.join("config"),
        format!(
            "[profile dev]\nregion = us-east-1\nendpoint_url = http://localhost:{port}\n\
             [profile stale]\nregion = us-east-1\nendpoint_url = http://localhost:{port}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        home.join("credentials"),
        format!(
            "[dev]\naws_access_key_id = {ACCESS_KEY}\naws_secret_access_key = {SECRET}\n\
             [stale]\naws_access_key_id = {ACCESS_KEY}\naws_secret_access_key = rotated\n"
        ),
    )
    .unwrap();

    let registry = ServiceRegistry::with_known_services();
    registry.register_native_with_authorization_evaluator(
        ServiceName::new("iam"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        Arc::new(StubIam),
        Arc::new(StrictEvaluator),
    );
    let recorder = Arc::new(Recorder::default());
    registry.register_native(
        ServiceName::new("dynamodb"),
        ServiceMetadata::new(AwsProtocol::Json10, Some("DynamoDB_20120810")),
        Arc::new(RecordingDynamo(recorder.clone())),
    );
    let observer = Arc::new(CaptureObserver::default());
    registry.set_completion_observer(observer.clone());
    let base = start(port, &[], registry).await;
    let client = reqwest::Client::new();
    let list = serde_json::json!({"profile": "dev", "service": "dynamodb", "operation": "ListTables", "body": {}});

    // 5.1: an allowlisted read signed with the local profile passes strict SigV4.
    let (status, body) = read(&client, &base, list.clone(), &[]).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("orders"));
    assert_eq!(
        recorder.calls.lock().unwrap().as_slice(),
        &[(
            "DynamoDB_20120810.ListTables".to_owned(),
            PROFILE_ACCOUNT.to_owned()
        )]
    );
    // The audit observer records the read under the profile's verified identity.
    let mut audited = None;
    for _ in 0..200 {
        audited = observer
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|o| o.service == "dynamodb" && o.operation == "ListTables")
            .cloned();
        if audited.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let audited = audited.expect("dashboard read must reach the audit observer");
    assert_eq!(audited.account_id, PROFILE_ACCOUNT);
    assert_eq!(audited.region, "us-east-1");
    assert_eq!(audited.http_status, 200);

    // Verification is real: a profile holding a stale secret is rejected by strict SigV4.
    let (status, body) = read(
        &client,
        &base,
        serde_json::json!({"profile": "stale", "service": "dynamodb", "operation": "ListTables", "body": {}}),
        &[],
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("SignatureDoesNotMatch"), "{body}");
    assert_eq!(recorder.calls.lock().unwrap().len(), 1);

    // 5.1: the unsigned `instance` profile gets an actionable error, not an exception.
    for profile in [serde_json::json!("instance"), serde_json::Value::Null] {
        let (status, body) = read(
            &client,
            &base,
            serde_json::json!({"profile": profile, "service": "dynamodb", "operation": "ListTables", "body": {}}),
            &[],
        )
        .await;
        assert_eq!(status, 403, "{body}");
        assert!(body.contains("MissingAuthenticationToken"), "{body}");
        assert!(body.contains("IAM enforcement is strict"), "{body}");
        assert!(body.contains("endpoint_url"), "{body}");
    }
    let (status, _) = read(
        &client,
        &base,
        serde_json::json!({"profile": "missing", "service": "dynamodb", "operation": "ListTables"}),
        &[],
    )
    .await;
    assert_eq!(status, 400);

    // 5.2: operations outside `read_target` and writes are refused before dispatch.
    for (service, operation) in [
        ("dynamodb", "ListBackups"),
        ("dynamodb", "PutItem"),
        ("dynamodb", "DeleteTable"),
        ("sqs", "SendMessage"),
        ("secretsmanager", "GetSecretValue"),
        ("sns", "Publish"),
        ("cloudformation", "DeleteStack"),
    ] {
        let (status, body) = read(
            &client,
            &base,
            serde_json::json!({"profile": "dev", "service": service, "operation": operation, "body": {}}),
            &[],
        )
        .await;
        assert_eq!(status, 400, "{service}.{operation}: {body}");
        assert!(body.contains("unsupported dashboard"), "{body}");
    }
    for path in ["functions/demo/invocations", "functions/demo/code"] {
        let (status, _) = read(
            &client,
            &base,
            serde_json::json!({"profile": "dev", "service": "lambda", "path": path}),
            &[],
        )
        .await;
        assert_eq!(status, 400, "{path}");
    }

    // 5.2: foreign browser origins and rebinding hosts are refused.
    let same_origin = format!("http://127.0.0.1:{port}");
    let other_port = format!("http://127.0.0.1:{}", port.wrapping_add(1));
    for origin in [
        "https://attacker.example",
        "null",
        other_port.as_str(),
        &format!("http://localhost:{port}"),
        &format!("https://127.0.0.1:{port}"),
    ] {
        let (status, body) = read(&client, &base, list.clone(), &[("origin", origin)]).await;
        assert_eq!(status, 403, "{origin}: {body}");
    }
    let rebound = format!("attacker.example:{port}");
    let (status, _) = read(&client, &base, list.clone(), &[("host", rebound.as_str())]).await;
    assert_eq!(status, 403);
    // Profile names and the account ID are not readable through a rebinding host either.
    let context = |host: Option<&str>| {
        let mut request = client.get(format!("{base}/_locallycloud/context"));
        if let Some(host) = host {
            request = request.header("host", host);
        }
        request.send()
    };
    assert_eq!(context(Some(rebound.as_str())).await.unwrap().status(), 403);
    let local = context(None).await.unwrap();
    assert_eq!(local.status(), 200);
    assert!(local.text().await.unwrap().contains("\"dev\""));
    let (status, body) = read(
        &client,
        &base,
        list.clone(),
        &[("origin", same_origin.as_str())],
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // 5.2: a CORS "simple" request (no preflight) cannot carry application/json.
    for content_type in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
    ] {
        let response = client
            .post(format!("{base}/_locallycloud/explore/read"))
            .header("content-type", content_type)
            .header("origin", "https://attacker.example")
            .body(list.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 415, "{content_type}");
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }

    // Only the two accepted reads reached the handler.
    assert_eq!(recorder.calls.lock().unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(home);
}
