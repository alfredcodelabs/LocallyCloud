use super::*;
use locallycloud_state::{StateCipher, StateDb};
use std::io::{Cursor, Write};

fn package(text: &str) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file("index.js", zip::write::SimpleFileOptions::default())
        .unwrap();
    writer.write_all(text.as_bytes()).unwrap();
    writer.finish().unwrap().into_inner()
}
fn restore_handler(db: Arc<StateDb>, key: u8) -> Result<LambdaHandler, LambdaError> {
    let handler = LambdaHandler::new();
    let persistence = Arc::new(crate::persistence::LambdaPersistence::with_cipher(
        db.clone(),
        StateCipher::with_key(&[key; 32]),
    )?);
    handler.initialize_state(db, persistence)?;
    Ok(handler)
}
fn request(method: Method, path: &str, body: Value) -> ServiceRequest {
    ServiceRequest {
        method,
        uri: path.parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::from(body.to_string()),
        account_id: "000000000000".into(),
        region: "us-east-1".into(),
        request_id: "durability-test".into(),
    }
}
async fn call(handler: &LambdaHandler, method: Method, path: &str, body: Value) -> (u16, Value) {
    let response = handler.handle(request(method, path, body)).await;
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
fn create(name: &str, bytes: &[u8]) -> Value {
    json!({"FunctionName":name,"Runtime":"nodejs22.x","Role":"arn:aws:iam::000000000000:role/executor","Handler":"index.handler","Code":{"ZipFile":base64::engine::general_purpose::STANDARD.encode(bytes)},"Environment":{"Variables":{"SECRET":"durable-test-secret-never-plaintext"}}})
}
#[tokio::test]
async fn scoped_code_versions_aliases_layers_configuration_survive_restart() {
    let root = std::env::temp_dir().join(format!(
        "locallycloud-lambda-state-{}",
        uuid::Uuid::new_v4()
    ));
    let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
    let handler = restore_handler(db.clone(), 0x51).unwrap();
    let zip = package("exports.handler=async()=>({version:1})");
    let (status, body) = call(
        &handler,
        Method::POST,
        "/2018-10-31/layers/libs/versions",
        json!({"Content":{"ZipFile":base64::engine::general_purpose::STANDARD.encode(&zip)}}),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let mut input = create("orders", &zip);
    input["Layers"] = json!([body["LayerVersionArn"]]);
    assert_eq!(
        call(&handler, Method::POST, "/2015-03-31/functions", input)
            .await
            .0,
        201
    );
    assert_eq!(
        call(
            &handler,
            Method::POST,
            "/2015-03-31/functions/orders/versions",
            json!({})
        )
        .await
        .0,
        201
    );
    assert_eq!(
        call(
            &handler,
            Method::POST,
            "/2015-03-31/functions/orders/aliases",
            json!({"Name":"live","FunctionVersion":"1"})
        )
        .await
        .0,
        201
    );
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/2017-10-31/functions/orders/concurrency",
            json!({"ReservedConcurrentExecutions":2})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(
            &handler,
            Method::POST,
            "/2021-10-31/functions/orders/url",
            json!({"AuthType":"NONE"})
        )
        .await
        .0,
        201
    );
    let newer = package("exports.handler=async()=>({version:2})");
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/2015-03-31/functions/orders/code",
            json!({"ZipFile":base64::engine::general_purpose::STANDARD.encode(&newer)})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(
            &handler,
            Method::DELETE,
            "/2018-10-31/layers/libs/versions/1",
            json!({})
        )
        .await
        .0,
        204
    );
    drop(handler);
    let restored = restore_handler(db.clone(), 0x51).unwrap();
    let latest = restored
        .store
        .get("000000000000", "us-east-1", "orders")
        .unwrap();
    assert_eq!(latest.code_zip.as_deref(), Some(newer.as_slice()));
    assert_eq!(
        latest.environment.get("SECRET").unwrap(),
        "durable-test-secret-never-plaintext"
    );
    assert_eq!(
        restored
            .store
            .get_version("000000000000", "us-east-1", "orders", 1)
            .unwrap()
            .code_zip
            .as_deref(),
        Some(zip.as_slice())
    );
    assert_eq!(
        restored
            .store
            .get_alias("000000000000", "us-east-1", "orders", "live")
            .unwrap()
            .function_version,
        "1"
    );
    assert!(restored
        .store
        .get_url_config("000000000000", "us-east-1", "orders")
        .is_some());
    assert_eq!(
        restored
            .store
            .get_reserved_concurrency("000000000000", "us-east-1", "orders"),
        Some(Some(2))
    );
    assert!(restored
        .layers
        .get_version("000000000000", "us-east-1", "libs", 1)
        .is_none());
    assert_eq!(
        restored
            .layers
            .get_version_for_execution("000000000000", "us-east-1", "libs", 1)
            .unwrap()
            .code_zip,
        zip
    );
    assert!(restored
        .store
        .get("000000000000", "us-west-2", "orders")
        .is_none());
    assert!(restored
        .store
        .get("111111111111", "us-east-1", "orders")
        .is_none());
    let connection = db.connection().unwrap();
    let mut stmt = connection
        .prepare("SELECT payload FROM lambda_entities")
        .unwrap();
    for payload in stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)).unwrap() {
        let payload = payload.unwrap();
        let secret = b"durable-test-secret-never-plaintext";
        assert!(!payload.windows(secret.len()).any(|part| part == secret));
    }
    assert!(restore_handler(db.clone(), 0x52).is_err());
    assert_eq!(
        call(
            &restored,
            Method::DELETE,
            "/2015-03-31/functions/orders",
            json!({})
        )
        .await
        .0,
        204
    );
    assert!(restore_handler(db, 0x51)
        .unwrap()
        .store
        .get("000000000000", "us-east-1", "orders")
        .is_none());
    std::fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn failed_commit_preserves_metadata_and_version_numbers() {
    let root = std::env::temp_dir().join(format!(
        "locallycloud-lambda-rollback-{}",
        uuid::Uuid::new_v4()
    ));
    let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
    let handler = restore_handler(db.clone(), 0x61).unwrap();
    let zip = package("exports.handler=async()=>true");
    assert_eq!(
        call(
            &handler,
            Method::POST,
            "/2015-03-31/functions",
            create("orders", &zip)
        )
        .await
        .0,
        201
    );
    db.connection().unwrap().execute_batch("CREATE TRIGGER reject_lambda BEFORE INSERT ON lambda_entities BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
    assert_eq!(
        call(
            &handler,
            Method::POST,
            "/2015-03-31/functions",
            create("tentative", &zip)
        )
        .await
        .0,
        500
    );
    assert!(handler
        .store
        .get("000000000000", "us-east-1", "tentative")
        .is_none());
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/2015-03-31/functions/orders/configuration",
            json!({"Description":"tentative"})
        )
        .await
        .0,
        500
    );
    assert_eq!(
        handler
            .store
            .get("000000000000", "us-east-1", "orders")
            .unwrap()
            .description,
        ""
    );
    assert_eq!(
        call(
            &handler,
            Method::POST,
            "/2015-03-31/functions/orders/versions",
            json!({})
        )
        .await
        .0,
        500
    );
    db.connection().unwrap().execute_batch("DROP TRIGGER reject_lambda; CREATE TRIGGER reject_delete BEFORE DELETE ON lambda_entities BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
    assert_eq!(
        call(
            &handler,
            Method::DELETE,
            "/2015-03-31/functions/orders",
            json!({})
        )
        .await
        .0,
        500
    );
    assert!(handler
        .store
        .get("000000000000", "us-east-1", "orders")
        .is_some());
    db.connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_delete;")
        .unwrap();
    let (status, version) = call(
        &handler,
        Method::POST,
        "/2015-03-31/functions/orders/versions",
        json!({}),
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(version["Version"], "1");
    drop(handler);
    let restored = restore_handler(db.clone(), 0x61).unwrap();
    assert!(restored
        .store
        .get("000000000000", "us-east-1", "tentative")
        .is_none());
    assert_eq!(
        restored
            .store
            .get("000000000000", "us-east-1", "orders")
            .unwrap()
            .description,
        ""
    );
    assert!(restored
        .store
        .get_version("000000000000", "us-east-1", "orders", 1)
        .is_some());
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn reserved_concurrency_get_function_restart_failure_and_delete() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!("lambda-reservation-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
    let handler = restore_handler(db.clone(), 0x63).unwrap();
    assert_eq!(
        call(
            &handler,
            Method::POST,
            "/2015-03-31/functions",
            create("reserved", &package("exports.handler=async()=>true"))
        )
        .await
        .0,
        201
    );
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/2017-10-31/functions/reserved/concurrency",
            json!({"ReservedConcurrentExecutions":4})
        )
        .await
        .0,
        200
    );
    drop(handler);
    let restored = restore_handler(db.clone(), 0x63).unwrap();
    let (status, body) = call(
        &restored,
        Method::GET,
        "/2015-03-31/functions/reserved",
        Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["Concurrency"]["ReservedConcurrentExecutions"], 4);
    assert_eq!(
        call(
            &restored,
            Method::GET,
            "/2019-09-30/functions/reserved/concurrency",
            Value::Null
        )
        .await
        .1["ReservedConcurrentExecutions"],
        4
    );
    let arn = "arn:aws:lambda:us-east-1:000000000000:function:reserved";
    let slots = (0..4)
        .map(|_| restored.concurrency.acquire(arn).unwrap())
        .collect::<Vec<_>>();
    assert!(restored.concurrency.acquire(arn).is_none());
    drop(slots);
    db.connection().unwrap().execute_batch("CREATE TRIGGER reject_reservation BEFORE INSERT ON lambda_entities BEGIN SELECT RAISE(ABORT,'injected reservation failure'); END;").unwrap();
    assert_eq!(
        call(
            &restored,
            Method::PUT,
            "/2017-10-31/functions/reserved/concurrency",
            json!({"ReservedConcurrentExecutions":1})
        )
        .await
        .0,
        500
    );
    assert_eq!(
        call(
            &restored,
            Method::GET,
            "/2015-03-31/functions/reserved",
            Value::Null
        )
        .await
        .1["Concurrency"]["ReservedConcurrentExecutions"],
        4
    );
    let slots = (0..4)
        .map(|_| restored.concurrency.acquire(arn).unwrap())
        .collect::<Vec<_>>();
    assert!(restored.concurrency.acquire(arn).is_none());
    drop(slots);
    db.connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_reservation")
        .unwrap();
    assert_eq!(
        call(
            &restored,
            Method::DELETE,
            "/2017-10-31/functions/reserved/concurrency",
            Value::Null
        )
        .await
        .0,
        204
    );
    drop(restored);
    let cleared = restore_handler(db.clone(), 0x63).unwrap();
    assert!(call(
        &cleared,
        Method::GET,
        "/2015-03-31/functions/reserved",
        Value::Null
    )
    .await
    .1
    .get("Concurrency")
    .is_none());
    let slots = (0..5)
        .map(|_| cleared.concurrency.acquire(arn).unwrap())
        .collect::<Vec<_>>();
    drop(slots);
    assert_eq!(
        call(
            &cleared,
            Method::DELETE,
            "/2015-03-31/functions/reserved",
            Value::Null
        )
        .await
        .0,
        204
    );
    drop(cleared);
    let deleted = restore_handler(db.clone(), 0x63).unwrap();
    assert_eq!(
        call(
            &deleted,
            Method::GET,
            "/2015-03-31/functions/reserved",
            Value::Null
        )
        .await
        .0,
        404
    );
    drop(deleted);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}
