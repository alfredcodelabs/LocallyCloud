use super::*;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use registry_v2::{sha256, OCI_MANIFEST};
use serde_json::json;

struct TestDb {
    root: std::path::PathBuf,
    database: Arc<StateDb>,
}
impl TestDb {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("ecr-state-{}", Uuid::new_v4()));
        StateDb::private_dir(&root).unwrap();
        let database = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        Self { root, database }
    }
    fn handler(&self, key: u8) -> Result<Arc<EcrHandler>, EcrStateError> {
        let persistence = Arc::new(Persistence::new(
            self.database.clone(),
            StateCipher::with_key(&[key; 32]),
        )?);
        let mut handler = EcrHandler::new();
        handler.registry_v2 = Arc::new(registry_v2::RegistryV2Handler::with_persistence(
            persistence.clone(),
        ));
        persistence.restore(&handler)?;
        Ok(Arc::new(handler))
    }
    fn sql(&self, sql: &str) {
        self.database
            .connection()
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
    fn count(&self) -> i64 {
        self.database
            .connection()
            .unwrap()
            .query_row("SELECT count(*) FROM ecr_records", [], |row| row.get(0))
            .unwrap()
    }
}
impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn request(method: Method, path: &str, body: Bytes) -> ServiceRequest {
    ServiceRequest {
        method,
        uri: path.parse().unwrap(),
        headers: HeaderMap::new(),
        body,
        account_id: "111111111111".into(),
        region: "us-east-1".into(),
        request_id: "ecr-state-test".into(),
    }
}
async fn control(handler: &EcrHandler, operation: &str, body: Value) -> (StatusCode, Value) {
    let mut request = request(Method::POST, "/", Bytes::from(body.to_string()));
    request.headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("{TARGET_PREFIX}.{operation}")).unwrap(),
    );
    request.headers.insert(
        "x-locallycloud-verified-ecr-sigv4",
        HeaderValue::from_static("1"),
    );
    request.headers.insert(
        http::header::HOST,
        HeaderValue::from_static("127.0.0.1:4566"),
    );
    let response = handler.handle(request).await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}
async fn token(handler: &EcrHandler) -> String {
    let (status, body) = control(handler, "GetAuthorizationToken", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    format!(
        "Basic {}",
        body["authorizationData"][0]["authorizationToken"]
            .as_str()
            .unwrap()
    )
}
async fn registry(
    handler: &EcrHandler,
    authorization: &str,
    method: Method,
    path: &str,
    body: &[u8],
    media: Option<&str>,
) -> Response {
    let mut request = request(method, path, Bytes::copy_from_slice(body));
    request.headers.insert(
        http::header::HOST,
        HeaderValue::from_static("111111111111.dkr.ecr.us-east-1.amazonaws.com"),
    );
    request.headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(authorization).unwrap(),
    );
    if let Some(media) = media {
        request.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(media).unwrap(),
        );
    }
    handler.handle(request).await
}
async fn start(handler: &EcrHandler, token: &str) -> String {
    let response = registry(
        handler,
        token,
        Method::POST,
        "/v2/team/app/blobs/uploads/",
        b"",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    response.headers()[http::header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned()
}
async fn blob(handler: &EcrHandler, token: &str, body: &[u8]) -> String {
    let upload = start(handler, token).await;
    let digest = sha256(body);
    let response = registry(
        handler,
        token,
        Method::PUT,
        &format!("{upload}?digest={digest}"),
        body,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    digest
}
fn manifest(config: &str, config_size: usize, layer: &str, layer_size: usize) -> String {
    json!({"schemaVersion":2,"mediaType":OCI_MANIFEST,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":config,"size":config_size},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":layer,"size":layer_size}]}).to_string()
}

#[tokio::test]
async fn committed_images_restore_lazily_scoped_and_delete_durably() {
    let db = TestDb::new();
    let handler = db.handler(7).unwrap();
    assert_eq!(
        control(
            &handler,
            "CreateRepository",
            json!({"repositoryName":"team/app","imageTagMutability":"IMMUTABLE"})
        )
        .await
        .0,
        StatusCode::OK
    );
    let auth = token(&handler).await;
    let config = b"{}";
    let layer = b"bounded saved layer content";
    let config_digest = blob(&handler, &auth, config).await;
    let layer_digest = blob(&handler, &auth, layer).await;
    let body = manifest(&config_digest, config.len(), &layer_digest, layer.len());
    assert_eq!(
        registry(
            &handler,
            &auth,
            Method::PUT,
            "/v2/team/app/manifests/latest",
            body.as_bytes(),
            Some(OCI_MANIFEST)
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    let unfinished = start(&handler, &auth).await;
    assert_eq!(
        control(
            &handler,
            "DeleteRepository",
            json!({"repositoryName":"team/app"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let count = db.count();
    drop(handler);
    assert!(db.handler(8).is_err());
    let handler = db.handler(7).unwrap();
    assert_eq!(
        registry(
            &handler,
            &auth,
            Method::GET,
            "/v2/team/app/manifests/latest",
            b"",
            None
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let auth = token(&handler).await;
    assert_eq!(
        registry(
            &handler,
            &auth,
            Method::PUT,
            &format!("{unfinished}?digest={layer_digest}"),
            layer,
            None
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    let response = registry(
        &handler,
        &auth,
        Method::GET,
        "/v2/team/app/manifests/latest",
        b"",
        None,
    )
    .await;
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap(),
        body.as_bytes()
    );
    assert_eq!(
        registry(
            &handler,
            &auth,
            Method::PUT,
            "/v2/team/app/manifests/latest",
            body.as_bytes(),
            Some(OCI_MANIFEST)
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let (actual_config, layers) = handler
        .image_blobs_async("111111111111", "us-east-1", "team/app", "latest")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(actual_config, config.as_slice());
    assert_eq!(layers, vec![(Bytes::copy_from_slice(layer), false)]);
    assert!(handler
        .image_blobs_async("222222222222", "us-east-1", "team/app", "latest")
        .await
        .unwrap()
        .is_none());
    assert!(handler
        .image_blobs_async("111111111111", "us-west-2", "team/app", "latest")
        .await
        .unwrap()
        .is_none());
    assert_eq!(db.count(), count);
    // Blob payload corruption is not eagerly read on restart; use fails closed.
    db.sql("UPDATE ecr_records SET payload=randomblob(length(payload)) WHERE kind='blob'");
    drop(handler);
    let handler = db.handler(7).unwrap();
    assert!(handler
        .image_blobs_async("111111111111", "us-east-1", "team/app", "latest")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        control(
            &handler,
            "DeleteRepository",
            json!({"repositoryName":"team/app","force":true})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(db.count(), 0);
    drop(handler);
    let handler = db.handler(7).unwrap();
    assert_eq!(
        control(
            &handler,
            "DescribeRepositories",
            json!({"repositoryNames":["team/app"]})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        control(
            &handler,
            "CreateRepository",
            json!({"repositoryName":"team/app"})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(handler
        .image_blobs_async("111111111111", "us-east-1", "team/app", "latest")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn failed_durable_mutations_preserve_uploads_tags_and_repositories() {
    let db = TestDb::new();
    let handler = db.handler(7).unwrap();
    db.sql("CREATE TRIGGER fail_repo BEFORE INSERT ON ecr_records WHEN NEW.kind='repository' BEGIN SELECT RAISE(ABORT,'injected repository failure'); END;");
    assert_eq!(
        control(
            &handler,
            "CreateRepository",
            json!({"repositoryName":"team/app"})
        )
        .await
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(db.count(), 0);
    assert_eq!(
        control(
            &handler,
            "DescribeRepositories",
            json!({"repositoryNames":["team/app"]})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    db.sql("DROP TRIGGER fail_repo;");
    assert_eq!(
        control(
            &handler,
            "CreateRepository",
            json!({"repositoryName":"team/app"})
        )
        .await
        .0,
        StatusCode::OK
    );
    let auth = token(&handler).await;
    let upload = start(&handler, &auth).await;
    let layer = b"layer";
    let digest = sha256(layer);
    db.sql("CREATE TRIGGER fail_index BEFORE INSERT ON ecr_records WHEN NEW.kind='blob-index' BEGIN SELECT RAISE(ABORT,'injected index failure'); END;");
    assert_eq!(
        registry(
            &handler,
            &auth,
            Method::PUT,
            &format!("{upload}?digest={digest}"),
            layer,
            None
        )
        .await
        .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(db.count(), 1);
    assert_eq!(
        registry(
            &handler,
            &auth,
            Method::GET,
            &format!("/v2/team/app/blobs/{digest}"),
            b"",
            None
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    db.sql("DROP TRIGGER fail_index;");
    assert_eq!(
        registry(
            &handler,
            &auth,
            Method::PUT,
            &format!("{upload}?digest={digest}"),
            layer,
            None
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    let config = blob(&handler, &auth, b"{}").await;
    let body = manifest(&config, 2, &digest, layer.len());
    let before = db.count();
    db.sql("CREATE TRIGGER fail_tag BEFORE INSERT ON ecr_records WHEN NEW.kind='tag' BEGIN SELECT RAISE(ABORT,'injected tag failure'); END;");
    assert_eq!(
        registry(
            &handler,
            &auth,
            Method::PUT,
            "/v2/team/app/manifests/latest",
            body.as_bytes(),
            Some(OCI_MANIFEST)
        )
        .await
        .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(db.count(), before);
    assert_eq!(
        registry(
            &handler,
            &auth,
            Method::GET,
            "/v2/team/app/manifests/latest",
            b"",
            None
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    db.sql("DROP TRIGGER fail_tag;");
    assert_eq!(
        registry(
            &handler,
            &auth,
            Method::PUT,
            "/v2/team/app/manifests/latest",
            body.as_bytes(),
            Some(OCI_MANIFEST)
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    let before = db.count();
    db.sql("CREATE TRIGGER fail_delete BEFORE DELETE ON ecr_records WHEN OLD.kind='blob' BEGIN SELECT RAISE(ABORT,'injected deletion failure'); END;");
    assert_eq!(
        control(
            &handler,
            "DeleteRepository",
            json!({"repositoryName":"team/app","force":true})
        )
        .await
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(db.count(), before);
    assert!(handler
        .image_blobs_async("111111111111", "us-east-1", "team/app", "latest")
        .await
        .unwrap()
        .is_some());
    drop(handler);
    let handler = db.handler(7).unwrap();
    assert!(handler
        .image_blobs_async("111111111111", "us-east-1", "team/app", "latest")
        .await
        .unwrap()
        .is_some());
    db.sql("DROP TRIGGER fail_delete;");
    assert_eq!(
        control(
            &handler,
            "DeleteRepository",
            json!({"repositoryName":"team/app","force":true})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(db.count(), 0);
}
