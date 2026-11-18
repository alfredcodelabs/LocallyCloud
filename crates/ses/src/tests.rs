use super::*;
use crate::{
    config::Provider,
    error::Error,
    model::Identity,
    provider::Delivery,
    service::{Handler, Service},
    store::Store,
};
use locallycloud_core::handler::ServiceRequest;
use locallycloud_state::{StateCipher, StateDb};
use serde_json::{json, Value};
use std::time::Duration;

const ACCOUNT: &str = "000000000000";
fn request(method: &str, path: &str, body: Value) -> ServiceRequest {
    ServiceRequest {
        method: method.parse().unwrap(),
        uri: path.parse().unwrap(),
        headers: [(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        )]
        .into_iter()
        .collect(),
        body: body.to_string().into(),
        account_id: ACCOUNT.into(),
        region: "us-east-1".into(),
        request_id: "ses-test".into(),
    }
}
fn verified(name: &str) -> Identity {
    let mut identity = Identity::new(name, Vec::new()).unwrap();
    identity.verified = true;
    identity
}
fn mail() -> Value {
    json!({"FromEmailAddress":"Sender <sender@example.com>","Destination":{"ToAddresses":["recipient@example.net"],"BccAddresses":["hidden@example.net"]},"ReplyToAddresses":["reply@example.com"],"Content":{"Simple":{"Subject":{"Data":"A subject"},"Body":{"Text":{"Data":"sensitive message body"},"Html":{"Data":"<p>HTML</p>"}}}}})
}
struct Fixture {
    root: std::path::PathBuf,
    db: Arc<StateDb>,
    store: Arc<Store>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-state")
            .join(format!("ses-{}", uuid::Uuid::new_v4()));
        let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let store = Store::open(db.clone(), StateCipher::with_key(&[42; 32])).unwrap();
        Self { root, db, store }
    }
    fn handler(&self, config: SesConfig) -> Arc<Handler> {
        let credentials =
            SesCredentials::from_lookup(&config, &|_| Some("re_synthetic_fixture_key".into()))
                .unwrap();
        Handler::new(self.store.clone(), config, credentials, Weak::new(), &[]).unwrap()
    }
    fn state(&self, id: &str) -> String {
        self.db
            .connection()
            .unwrap()
            .query_row("SELECT status FROM ses_messages WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
use std::sync::Weak;
async fn call(handler: &Arc<Handler>, method: &str, path: &str, body: Value) -> (u16, Value) {
    let response = Service(handler.clone())
        .handle(request(method, path, body))
        .await;
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 20 * 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
async fn identity(handler: &Arc<Handler>, name: &str) {
    assert_eq!(
        call(
            handler,
            "POST",
            "/v2/email/identities",
            json!({"EmailIdentity":name})
        )
        .await
        .0,
        200
    );
    // Model a completed verification independently from the default pending AWS response.
    let identity = verified(name);
    handler
        .store
        .run(move |store| store.create(ACCOUNT, "us-east-1", &identity, true))
        .await
        .unwrap();
}

#[test]
fn configuration_precedence_secrets_and_invalid_inputs_are_explicit() {
    let base: SesConfig =
        serde_json::from_value(json!({"provider":"resend","max_concurrency":3})).unwrap();
    let configured = base
        .resolve_with(&|key| match key {
            "LOCALLYCLOUD_SES_PROVIDER" => Some("capture".into()),
            "LOCALLYCLOUD_SES_MAX_CONCURRENCY" => Some("4".into()),
            _ => None,
        })
        .unwrap();
    assert_eq!(configured.provider, Provider::Capture);
    assert_eq!(configured.max_concurrency, 4);
    for (key, value) in [
        ("LOCALLYCLOUD_SES_PROVIDER", "smtp"),
        ("LOCALLYCLOUD_SES_PROVIDER", ""),
        ("LOCALLYCLOUD_SES_MAX_CONCURRENCY", "0"),
        ("LOCALLYCLOUD_SES_REQUEST_TIMEOUT_SECS", "301"),
        ("LOCALLYCLOUD_SES_MAX_PENDING_BYTES", "1"),
    ] {
        assert!(SesConfig::default()
            .resolve_with(&|name| (name == key).then(|| value.into()))
            .is_err());
    }
    let real = SesConfig {
        provider: Provider::Resend,
        ..SesConfig::default()
    };
    assert!(SesCredentials::from_lookup(&real, &|_| None).is_err());
    for secret in ["", "short", "re_secret\nheader"] {
        let error = SesCredentials::from_lookup(&real, &|_| Some(secret.into()))
            .err()
            .unwrap();
        assert!(!error.contains("re_secret"));
    }
    for input in [
        json!({"provider":null}),
        json!({"request_timeout_secs":null}),
        json!({"api_key":"synthetic-secret"}),
        json!({"credential_ref":"not-yet-supported"}),
    ] {
        assert!(serde_json::from_value::<SesConfig>(input).is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_is_encrypted_scoped_persistent_and_pagination_is_bound() {
    let f = Fixture::new();
    let h = f.handler(SesConfig::default());
    assert!(!h.store.run(|s| s.has_pending()).await.unwrap());
    assert_eq!(
        call(&h, "POST", "/v2/email/outbound-emails", mail())
            .await
            .0,
        400
    );
    for name in ["a.example.com", "example.com", "z.example.com"] {
        identity(&h, name).await;
    }
    assert_eq!(
        call(
            &h,
            "POST",
            "/v2/email/identities",
            json!({"EmailIdentity":"example.com"})
        )
        .await
        .0,
        400
    );
    let (status, sent) = call(&h, "POST", "/v2/email/outbound-emails", mail()).await;
    assert_eq!(status, 200);
    let id = sent["MessageId"].as_str().unwrap();
    assert_eq!(f.state(id), "captured");
    let payload: Vec<u8> =
        f.db.connection()
            .unwrap()
            .query_row("SELECT payload FROM ses_messages WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .unwrap();
    for clear in [
        "sensitive message body",
        "sender@example.com",
        "hidden@example.net",
        "re_synthetic_fixture_key",
    ] {
        assert!(!payload
            .windows(clear.len())
            .any(|part| part == clear.as_bytes()));
    }
    assert!(Store::open(f.db.clone(), StateCipher::with_key(&[7; 32])).is_err());
    let restored = Store::open(f.db.clone(), StateCipher::with_key(&[42; 32])).unwrap();
    assert_eq!(
        restored
            .identity(ACCOUNT, "us-east-1", "example.com")
            .unwrap()
            .kind,
        "DOMAIN"
    );
    let (_, page) = call(&h, "GET", "/v2/email/identities?PageSize=1", json!({})).await;
    let token = page["NextToken"].as_str().unwrap();
    assert_eq!(page["EmailIdentities"][0]["IdentityName"], "a.example.com");
    assert_eq!(
        call(
            &h,
            "GET",
            &format!("/v2/email/identities?PageSize=1&NextToken={token}"),
            json!({})
        )
        .await
        .1["EmailIdentities"][0]["IdentityName"],
        "example.com"
    );
    let mut cross = request(
        "GET",
        &format!("/v2/email/identities?NextToken={token}"),
        json!({}),
    );
    cross.region = "eu-west-1".into();
    assert_eq!(Service(h.clone()).handle(cross).await.status(), 400);
    let mut cross = request("POST", "/v2/email/outbound-emails", mail());
    cross.account_id = "111111111111".into();
    assert_eq!(Service(h.clone()).handle(cross).await.status(), 400);
    assert_eq!(
        call(&h, "DELETE", "/v2/email/identities/example.com", json!({}))
            .await
            .0,
        200
    );
    assert_eq!(
        call(&h, "POST", "/v2/email/outbound-emails", mail())
            .await
            .0,
        400
    );
    assert!(!h.store.run(|s| s.has_pending()).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_mail_and_failed_commits_leave_no_captures() {
    let f = Fixture::new();
    let h = f.handler(SesConfig::default());
    identity(&h, "example.com").await;
    for change in 0..5 {
        let mut input = mail();
        match change {
            0 => input["Destination"]["ToAddresses"] = json!(["invalid"]),
            1 => input["Content"]["Simple"]["Subject"]["Data"] = json!("injected\r\nHeader: x"),
            2 => input["Destination"]["ToAddresses"] = json!(vec!["a@example.com"; 51]),
            3 => input["Content"]["Simple"]["Attachments"] = json!([]),
            _ => input["ConfigurationSetName"] = json!("unsupported"),
        }
        assert_eq!(
            call(&h, "POST", "/v2/email/outbound-emails", input).await.0,
            400
        );
    }
    f.db.connection().unwrap().execute_batch("CREATE TRIGGER reject_message BEFORE INSERT ON ses_messages BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
    assert_eq!(
        call(&h, "POST", "/v2/email/outbound-emails", mail())
            .await
            .0,
        500
    );
    let count: i64 =
        f.db.connection()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM ses_messages", [], |r| r.get(0))
            .unwrap();
    assert_eq!(count, 0);
}

#[derive(Clone)]
struct ProviderFixture {
    requests: Arc<std::sync::Mutex<Vec<(String, Value)>>>,
    attempts: Arc<std::sync::atomic::AtomicUsize>,
}
async fn fixture_send(
    axum::extract::State(state): axum::extract::State<ProviderFixture>,
    headers: http::HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let key = headers
        .get("Idempotency-Key")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    state.requests.lock().unwrap().push((key, body));
    if state
        .attempts
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        == 0
    {
        Response::builder()
            .status(429)
            .header("retry-after", "1")
            .body(axum::body::Body::empty())
            .unwrap()
    } else {
        Response::builder()
            .header("content-type", "application/json")
            .body(axum::body::Body::from("{\"id\":\"provider-fixture-id\"}"))
            .unwrap()
    }
}
use axum::response::Response;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_retry_keeps_payload_and_idempotency_and_changed_credentials_block_jobs() {
    let f = Fixture::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let state = ProviderFixture {
        requests: Default::default(),
        attempts: Default::default(),
    };
    let app = axum::Router::new()
        .route("/emails", axum::routing::post(fixture_send))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let config = SesConfig {
        provider: Provider::Resend,
        ..SesConfig::default()
    };
    let credentials =
        SesCredentials::from_lookup(&config, &|_| Some("re_fixture_secret".into())).unwrap();
    let delivery = Delivery::fixture(&config, credentials, &origin);
    let binding = delivery.binding.clone();
    let h = Handler::with_delivery(f.store.clone(), config.clone(), delivery, Weak::new());
    identity(&h, "example.com").await;
    let (_, value) = call(&h, "POST", "/v2/email/outbound-emails", mail()).await;
    let id = value["MessageId"].as_str().unwrap().to_owned();
    tokio::time::timeout(Duration::from_secs(8), async {
        while f.state(&id) != "provider_accepted" {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let observed = state.requests.lock().unwrap().clone();
    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0], observed[1]);
    assert_eq!(observed[0].1["from"], "Sender <sender@example.com>");
    assert_eq!(observed[0].1["bcc"], json!(["hidden@example.net"]));
    assert_eq!(observed[0].1["reply_to"], json!(["reply@example.com"]));
    let input = crate::model::Mail::parse(&mail()).unwrap();
    let id = f
        .store
        .accept(
            ACCOUNT,
            "us-east-1",
            input,
            &config,
            &binding,
            "example.com",
        )
        .unwrap();
    assert!(f
        .store
        .claim("different-credential-binding", 1)
        .unwrap()
        .is_none());
    assert_eq!(f.state(&id), "blocked");
    // Changing delivery mode does not promote previously captured messages.
    let capture = crate::model::Mail::parse(&mail()).unwrap();
    let capture_id = f
        .store
        .accept(
            ACCOUNT,
            "us-east-1",
            capture,
            &SesConfig::default(),
            "capture",
            "example.com",
        )
        .unwrap();
    assert!(f.store.claim(&binding, 1).unwrap().is_none());
    assert_eq!(f.state(&capture_id), "captured");
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_admission_is_atomic_under_concurrent_writers() {
    let f = Fixture::new();
    f.store
        .create(ACCOUNT, "us-east-1", &verified("example.com"), false)
        .unwrap();
    let config = SesConfig {
        provider: Provider::Resend,
        max_pending_messages: 1,
        ..SesConfig::default()
    };
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let store = f.store.clone();
        let config = config.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            store.accept(
                ACCOUNT,
                "us-east-1",
                crate::model::Mail::parse(&mail()).unwrap(),
                &config,
                "binding",
                "example.com",
            )
        }));
    }
    let mut accepted = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => accepted += 1,
            Err(Error::Capacity) => {}
            Err(error) => panic!("unexpected {error:?}"),
        }
    }
    assert_eq!(accepted, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorization_uses_verified_domain_identity_and_denials_have_no_effect() {
    use locallycloud_core::integration::authorization::{
        AuthorizationError, AuthorizationEvaluator, AuthorizationRequest,
    };
    struct Gate {
        allow: std::sync::atomic::AtomicBool,
        seen: std::sync::Mutex<Vec<AuthorizationRequest>>,
    }
    impl AuthorizationEvaluator for Gate {
        fn strict_sigv4_required(&self) -> bool {
            true
        }
        fn authorize(&self, request: AuthorizationRequest) -> Result<(), AuthorizationError> {
            self.seen.lock().unwrap().push(request);
            if self.allow.load(std::sync::atomic::Ordering::Acquire) {
                Ok(())
            } else {
                Err(AuthorizationError::Denied)
            }
        }
    }
    #[async_trait::async_trait]
    impl NativeHandler for Gate {
        async fn handle(&self, _: ServiceRequest) -> Response {
            Response::new(axum::body::Body::empty())
        }
    }
    let f = Fixture::new();
    let registry = ServiceRegistry::with_known_services();
    let config = SesConfig::default();
    let credentials = SesCredentials::from_lookup(&config, &|_| None).unwrap();
    let h = Handler::new(
        f.store.clone(),
        config,
        credentials,
        Arc::downgrade(&registry),
        &[],
    )
    .unwrap();
    f.store
        .create(ACCOUNT, "us-east-1", &verified("example.com"), false)
        .unwrap();
    let gate = Arc::new(Gate {
        allow: std::sync::atomic::AtomicBool::new(false),
        seen: Default::default(),
    });
    registry.register_native_with_authorization_evaluator(
        ServiceName::new("iam"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        gate.clone(),
        gate.clone(),
    );
    let mut input = request("POST", "/v2/email/outbound-emails", mail());
    input.headers.insert(
        "authorization",
        "AWS4-HMAC-SHA256 Credential=test/20261118/us-east-1/ses/aws4_request"
            .parse()
            .unwrap(),
    );
    // Model a Core-verified ingress here; wire-level forging is tested at the actual server.
    input.headers.insert(
        "x-locallycloud-verified-external-sigv4",
        "1".parse().unwrap(),
    );
    assert_eq!(Service(h.clone()).handle(input.clone()).await.status(), 403);
    let count: i64 =
        f.db.connection()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM ses_messages", [], |r| r.get(0))
            .unwrap();
    assert_eq!(count, 0);
    gate.allow.store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(Service(h.clone()).handle(input.clone()).await.status(), 200);
    {
        let observations = gate.seen.lock().unwrap();
        assert!(observations
            .iter()
            .all(|r| r.resource == "arn:aws:ses:us-east-1:000000000000:identity/example.com"));
        assert_eq!(
            observations.last().unwrap().context["ses:fromaddress"],
            vec!["sender@example.com"]
        );
    }
    input
        .headers
        .remove("x-locallycloud-verified-external-sigv4");
    assert_eq!(Service(h.clone()).handle(input).await.status(), 403);
}

#[tokio::test]
async fn cancelled_sender_keeps_its_commit_and_starts_delivery_off_the_async_thread() {
    let f = Fixture::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let state = ProviderFixture {
        requests: Default::default(),
        attempts: Default::default(),
    };
    state
        .attempts
        .store(1, std::sync::atomic::Ordering::Release);
    let app = axum::Router::new()
        .route("/emails", axum::routing::post(fixture_send))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let config = SesConfig {
        provider: Provider::Resend,
        ..SesConfig::default()
    };
    let credentials =
        SesCredentials::from_lookup(&config, &|_| Some("re_cancel_fixture".into())).unwrap();
    let h = Handler::with_delivery(
        f.store.clone(),
        config.clone(),
        Delivery::fixture(&config, credentials, &origin),
        Weak::new(),
    );
    identity(&h, "example.com").await;
    let db = f.db.clone();
    let (ready, wait) = tokio::sync::oneshot::channel();
    let (release, held) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let connection = db.connection().unwrap();
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        ready.send(()).unwrap();
        let _ = held.recv_timeout(Duration::from_secs(3));
        connection.execute_batch("ROLLBACK").unwrap();
    });
    wait.await.unwrap();
    let handler = h.clone();
    let sending =
        tokio::spawn(
            async move { call(&handler, "POST", "/v2/email/outbound-emails", mail()).await },
        );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !sending.is_finished(),
        "the async timer must run while SQLite is blocked"
    );
    sending.abort();
    assert!(sending.await.unwrap_err().is_cancelled());
    release.send(()).unwrap();
    tokio::task::spawn_blocking(move || writer.join().unwrap())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let accepted: i64 =
                f.db.connection()
                    .unwrap()
                    .query_row(
                        "SELECT COUNT(*) FROM ses_messages WHERE status='provider_accepted'",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
            if accepted == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.requests.lock().unwrap().len(), 1);
    server.abort();
}

#[test]
fn durable_leases_resume_the_same_job_and_expired_retry_windows_stay_uncertain() {
    let f = Fixture::new();
    f.store
        .create(ACCOUNT, "us-east-1", &verified("example.com"), false)
        .unwrap();
    let config = SesConfig {
        provider: Provider::Resend,
        ..SesConfig::default()
    };
    let id = f
        .store
        .accept(
            ACCOUNT,
            "us-east-1",
            crate::model::Mail::parse(&mail()).unwrap(),
            &config,
            "binding",
            "example.com",
        )
        .unwrap();
    let first = f.store.claim("binding", 1).unwrap().unwrap();
    assert_eq!(first.id, id);
    assert!(f.store.claim("binding", 1).unwrap().is_none());
    let restored = Store::open(f.db.clone(), StateCipher::with_key(&[42; 32])).unwrap();
    f.db.connection()
        .unwrap()
        .execute("UPDATE ses_messages SET next_at=0 WHERE id=?1", [&id])
        .unwrap();
    let resumed = restored.claim("binding", 1).unwrap().unwrap();
    assert_eq!(resumed.id, first.id);
    assert_eq!(resumed.attempts, 2);
    assert_eq!(
        serde_json::to_value(&resumed.envelope.mail).unwrap(),
        serde_json::to_value(&first.envelope.mail).unwrap()
    );
    let mut envelope = resumed.envelope;
    envelope.created = crate::store::now() - 24 * 3600;
    let payload = StateCipher::with_key(&[42; 32])
        .seal(
            &["ses", ACCOUNT, "us-east-1", "message", &id],
            &serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
    f.db.connection()
        .unwrap()
        .execute(
            "UPDATE ses_messages SET payload=?2,next_at=0 WHERE id=?1",
            rusqlite::params![id, payload],
        )
        .unwrap();
    assert!(restored.claim("binding", 1).unwrap().is_none());
    assert_eq!(f.state(&id), "uncertain");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_rejections_redirects_and_oversized_responses_are_bounded() {
    for status in [401u16, 302, 200] {
        let f = Fixture::new();
        f.store
            .create(ACCOUNT, "us-east-1", &verified("example.com"), false)
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let redirect = format!("{origin}/redirect");
        let app=axum::Router::new().route("/emails",axum::routing::post(move|| {
            let redirect=redirect.clone();
            async move {
                Response::builder().status(status).header("location",redirect)
                    .body(axum::body::Body::from(if status==200 {
                        serde_json::json!({"id":"otherwise-valid-provider-id","padding":"x".repeat(65537)}).to_string()
                    } else {"untrusted provider diagnostic".into()})).unwrap()
            }
        })).route("/redirect",axum::routing::any(||async {
            axum::Json(serde_json::json!({"id":"redirect-must-not-be-followed"}))
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = SesConfig {
            provider: Provider::Resend,
            ..SesConfig::default()
        };
        let credentials =
            SesCredentials::from_lookup(&config, &|_| Some("re_synthetic_provider_key".into()))
                .unwrap();
        let delivery = Delivery::fixture(&config, credentials, &origin);
        f.store
            .accept(
                ACCOUNT,
                "us-east-1",
                crate::model::Mail::parse(&mail()).unwrap(),
                &config,
                &delivery.binding,
                "example.com",
            )
            .unwrap();
        let job = f.store.claim(&delivery.binding, 1).unwrap().unwrap();
        match (status, delivery.send(&job).await) {
            (200, crate::provider::Outcome::Retry(_)) => {}
            (401 | 302, crate::provider::Outcome::Failed("provider_rejected")) => {}
            _ => panic!("provider outcome must stay classified and bounded"),
        }
        server.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verification_starts_pending_and_completion_requires_explicit_local_simulation() {
    let f = Fixture::new();
    let h = f.handler(SesConfig::default());
    let (status, created) = call(
        &h,
        "POST",
        "/v2/email/identities",
        json!({"EmailIdentity":"example.com"}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(created["VerifiedForSendingStatus"], false);
    assert_eq!(created["DkimAttributes"]["Status"], "PENDING");
    assert_eq!(
        created["DkimAttributes"]["Tokens"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let (_, read) = call(&h, "GET", "/v2/email/identities/example.com", json!({})).await;
    assert_eq!(read["VerificationStatus"], "PENDING");
    assert_eq!(read["DkimAttributes"], created["DkimAttributes"]);
    assert_eq!(
        call(&h, "POST", "/v2/email/outbound-emails", mail())
            .await
            .0,
        400
    );
    let simulated = f.handler(SesConfig {
        auto_verify_identities: true,
        ..SesConfig::default()
    });
    let (_, created) = call(
        &simulated,
        "POST",
        "/v2/email/identities",
        json!({"EmailIdentity":"sender@example.com"}),
    )
    .await;
    assert_eq!(created["VerifiedForSendingStatus"], true);
    assert_eq!(
        call(&simulated, "POST", "/v2/email/outbound-emails", mail())
            .await
            .0,
        200
    );
    assert_eq!(
        call(
            &simulated,
            "GET",
            "/v2/email/identities/example.com",
            json!({})
        )
        .await
        .1["VerificationStatus"],
        "PENDING"
    );
    assert!(SesConfig::default()
        .resolve_with(
            &|key| (key == "LOCALLYCLOUD_SES_AUTO_VERIFY_IDENTITIES").then(|| "yes".into())
        )
        .is_err());
    assert!(serde_json::from_value::<SesConfig>(json!({"auto_verify_identities":null})).is_err());
}

#[test]
fn query_empty_results_keep_the_sdk_result_wrapper() {
    for action in [
        "VerifyEmailIdentity",
        "VerifyEmailAddress",
        "DeleteIdentity",
    ] {
        let xml = crate::protocol::query_result(action, &json!({}), "request-id");
        assert!(xml.contains(&format!("<{action}Result></{action}Result>")));
    }
}
