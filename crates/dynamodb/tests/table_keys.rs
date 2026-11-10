//! Real KMS envelopes; the optional worker probe also exercises actual SQLCipher files.
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::integration::kms::{KmsCallContext, KmsInternalError, SensitiveBytes};
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use locallycloud_dynamodb::encryption::{TableKeyEnvelope, TableKeyScope, TableKeys};
use locallycloud_state::{StateCipher, StateDb};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use uuid::Uuid;
use zeroize::Zeroizing;

const ACCOUNT: &str = "000000000000";
const REGION: &str = "us-east-1";

fn caller() -> KmsCallContext {
    KmsCallContext {
        source_service: "dynamodb".into(),
        account_id: ACCOUNT.into(),
        region: REGION.into(),
        request_id: "table-key-test".into(),
        caller_arn: Some(format!("arn:aws:iam::{ACCOUNT}:root")),
        iam_policy_allowed: false,
        iam_policy_denied: false,
    }
}

fn dispatcher(registry: &Arc<ServiceRegistry>) -> Arc<InternalDispatcher> {
    let dispatcher = Arc::new(InternalDispatcher::new_shared(
        registry,
        ProxyConfig {
            backend_url: "http://127.0.0.1:1".into(),
            upstream_timeout: Duration::from_secs(1),
        },
        LegacyHealth::new(false),
        REGION.into(),
        ACCOUNT.into(),
    ));
    registry.set_internal_dispatcher(dispatcher.clone());
    dispatcher
}

async fn kms(registry: &Arc<ServiceRegistry>, operation: &str, body: Value) -> Value {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-amz-target",
        format!("TrentService.{operation}").parse().unwrap(),
    );
    let response = registry
        .native_handler(&ServiceName::new("kms"))
        .unwrap()
        .handle(ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(body.to_string()),
            region: REGION.into(),
            account_id: ACCOUNT.into(),
            request_id: "native-table-key-probe".into(),
        })
        .await;
    let status = response.status();
    let data = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(
        status,
        http::StatusCode::OK,
        "KMS {operation}: {}",
        String::from_utf8_lossy(&data)
    );
    if data.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&data).unwrap()
    }
}

struct Worker {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Worker {
    async fn start(
        binary: &Path,
        database: &Path,
        scope: &TableKeyScope,
        key: &SensitiveBytes,
    ) -> Option<Self> {
        let mut child = Command::new(binary)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        let mut worker = Self {
            child,
            input,
            output,
        };
        let key = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(key.as_slice()));
        #[derive(Serialize)]
        struct File<'a> {
            table_name: &'a str,
            storage_id: String,
        }
        #[derive(Serialize)]
        struct Init<'a> {
            version: u8,
            key: &'a str,
            database: &'a Path,
            account_id: &'a str,
            region: &'a str,
            table_file: File<'a>,
        }
        let init = Init {
            version: 1,
            key: &key,
            database,
            account_id: scope.account(),
            region: scope.region(),
            table_file: File {
                table_name: scope.table_name(),
                storage_id: scope.storage_id().to_string(),
            },
        };
        let mut frame = Zeroizing::new(serde_json::to_vec(&init).unwrap());
        frame.push(b'\n');
        worker.input.write_all(&frame).await.unwrap();
        worker.input.flush().await.unwrap();
        let ready = worker.read().await;
        if ready.is_none() {
            let status = tokio::time::timeout(Duration::from_secs(5), worker.child.wait())
                .await
                .unwrap()
                .unwrap();
            assert!(!status.success(), "wrong scope/key must fail startup");
            return None;
        }
        let ready = ready.unwrap();
        assert_eq!(ready["ready"], true);
        assert_eq!(
            ready["table_file"]["storage_id"],
            scope.storage_id().to_string()
        );
        Some(worker)
    }

    async fn read(&mut self) -> Option<Value> {
        let mut line = String::new();
        let size = tokio::time::timeout(Duration::from_secs(40), self.output.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        (size > 0).then(|| serde_json::from_str(&line).unwrap())
    }

    async fn call(&mut self, operation: &str, body: Value) -> Value {
        let mut frame =
            serde_json::to_vec(&json!({"id":1,"operation":operation,"body":body})).unwrap();
        frame.push(b'\n');
        self.input.write_all(&frame).await.unwrap();
        self.input.flush().await.unwrap();
        self.read().await.unwrap()
    }

    async fn stop(mut self) {
        self.input.shutdown().await.unwrap();
        drop(self.input);
        assert!(
            tokio::time::timeout(Duration::from_secs(40), self.child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }
}

async fn physical_files(
    binary: &Path,
    root: &Path,
    scopes: &[TableKeyScope; 2],
    keys: [&SensitiveBytes; 2],
) {
    let mut paths = Vec::new();
    for (scope, key) in scopes.iter().zip(keys) {
        let path = root.join(format!("{}.sqlite3", scope.storage_id()));
        let mut worker = Worker::start(binary, &path, scope, key).await.unwrap();
        let table = scope.table_name();
        assert_eq!(worker.call("CreateTable", json!({"TableName":table,"BillingMode":"PAY_PER_REQUEST","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"},{"AttributeName":"payload","AttributeType":"S"}],"GlobalSecondaryIndexes":[{"IndexName":"lookup","KeySchema":[{"AttributeName":"payload","KeyType":"HASH"}],"Projection":{"ProjectionType":"ALL"}}],"StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_AND_OLD_IMAGES"}})).await["status"],200);
        for _ in 0..100 {
            let description = worker
                .call("DescribeTable", json!({"TableName":table}))
                .await;
            let description = &description["body"]["Table"];
            if description["TableStatus"] == "ACTIVE"
                && description["GlobalSecondaryIndexes"]
                    .as_array()
                    .is_some_and(|indexes| {
                        indexes.iter().all(|index| index["IndexStatus"] == "ACTIVE")
                    })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(worker.call("UpdateContinuousBackups",json!({"TableName":table,"PointInTimeRecoverySpecification":{"PointInTimeRecoveryEnabled":true}})).await["status"],200);
        assert_eq!(worker.call("PutItem",json!({"TableName":table,"Item":{"pk":{"S":"sensitive-key-marker"},"payload":{"S":"sensitive-table-payload-marker"}}})).await["status"],200);
        let mut indexed = false;
        for _ in 0..100 {
            let result = worker.call("Query",json!({"TableName":table,"IndexName":"lookup","KeyConditionExpression":"#p = :p","ExpressionAttributeNames":{"#p":"payload"},"ExpressionAttributeValues":{":p":{"S":"sensitive-table-payload-marker"}}})).await;
            if result["body"]["Items"][0]["pk"]["S"] == "sensitive-key-marker" {
                indexed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            indexed,
            "the official engine must maintain the encrypted table's GSI"
        );
        assert_eq!(
            worker
                .call(
                    "CreateBackup",
                    json!({"TableName":table,"BackupName":"sensitive-backup-marker"})
                )
                .await["status"],
            200
        );
        assert_eq!(
            worker
                .call("CreateTable", json!({"TableName":"another-table"}))
                .await["status"],
            400
        );
        assert_eq!(worker.call("TransactWriteItems",json!({"TransactItems":[{"Delete":{"TableName":table,"Key":{"pk":{"S":"sensitive-key-marker"}}}},{"Delete":{"TableName":"another-table","Key":{"pk":{"S":"x"}}}}]})).await["status"],400);
        let fetched = worker
            .call(
                "GetItem",
                json!({"TableName":table,"Key":{"pk":{"S":"sensitive-key-marker"}}}),
            )
            .await;
        assert_eq!(
            fetched["body"]["Item"]["payload"]["S"],
            "sensitive-table-payload-marker"
        );
        worker.stop().await;
        let bytes = tokio::fs::read(&path).await.unwrap();
        assert!(!bytes.starts_with(b"SQLite format 3"));
        for marker in [
            b"sensitive-key-marker".as_slice(),
            b"sensitive-table-payload-marker".as_slice(),
        ] {
            assert!(!bytes.windows(marker.len()).any(|v| v == marker));
        }
        paths.push(path);
    }
    assert!(Worker::start(binary, &paths[0], &scopes[0], keys[1])
        .await
        .is_none());
    assert!(Worker::start(binary, &paths[0], &scopes[1], keys[0])
        .await
        .is_none());
    let replaced = TableKeyScope::new(
        scopes[0].account(),
        scopes[0].region(),
        scopes[0].table_name(),
        Uuid::new_v4(),
    )
    .unwrap();
    assert!(Worker::start(binary, &paths[0], &replaced, keys[0])
        .await
        .is_none());
    for (i, key) in keys.into_iter().enumerate() {
        let mut worker = Worker::start(binary, &paths[i], &scopes[i], key)
            .await
            .unwrap();
        let fetched = worker.call("GetItem",json!({"TableName":scopes[i].table_name(),"Key":{"pk":{"S":"sensitive-key-marker"}}})).await;
        assert_eq!(
            fetched["body"]["Item"]["payload"]["S"],
            "sensitive-table-payload-marker"
        );
        worker.stop().await;
    }
}

async fn catalog_recovery(registry: &Arc<ServiceRegistry>, state: Arc<StateDb>) {
    use locallycloud_dynamodb::encryption::catalog::{FilePhase, TableCatalog};
    use locallycloud_dynamodb::error::DdbError;
    let keys = Arc::new(TableKeys::new(
        dispatcher(registry),
        Arc::new(StateCipher::with_key(&[13; 32])),
    ));
    let catalog = TableCatalog::new(state.clone(), keys.clone())
        .await
        .unwrap();
    assert!(catalog.page(None, 1).await.unwrap().is_empty());
    for limit in [0, 101, usize::MAX] {
        assert!(matches!(
            catalog.page(None, limit).await,
            Err(DdbError::Validation(_))
        ));
    }
    // Synthetic payload sizes exercise the catalog's bound independently of provider validation.
    let mut large_records = Vec::new();
    for name in ["catalog-large-a", "catalog-large-b"] {
        let scope = TableKeyScope::new(ACCOUNT, REGION, name, Uuid::new_v4()).unwrap();
        let key = keys.generate(&scope, caller(), None).await.unwrap();
        let intent = json!({"TableName":name,"ResourcePolicy":"x".repeat(600 * 1024)});
        let record = catalog
            .reserve_with_intent(scope, key.envelope, intent.clone())
            .await
            .unwrap();
        assert_eq!(record.create_intent(), Some(&intent));
        let description = json!({
            "TableName":name,
            "TableArn":format!("arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{name}"),
            "TableStatus":"ACTIVE",
            "ProviderField":"y".repeat(600 * 1024)
        });
        let record = catalog
            .activate(&record, description.clone())
            .await
            .unwrap();
        assert_eq!(record.description(), Some(&description));
        large_records.push(record);
    }
    let first = catalog.page(None, 100).await.unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].scope().table_name(), "catalog-large-a");
    let second = catalog.page(first.last(), 100).await.unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].create_intent(), large_records[1].create_intent());
    assert_eq!(second[0].description(), large_records[1].description());
    assert!(catalog.page(second.last(), 100).await.unwrap().is_empty());
    let db = state.clone();
    let saved = tokio::task::spawn_blocking(move || {
        let conn = db.connection().unwrap();
        let saved: Vec<u8> = conn
            .query_row(
                "SELECT metadata FROM lc_dynamodb_table_files WHERE name='catalog-large-b'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut corrupt = saved.clone();
        corrupt[0] ^= 1;
        conn.execute(
            "UPDATE lc_dynamodb_table_files SET metadata=?1 WHERE name='catalog-large-b'",
            [corrupt],
        )
        .unwrap();
        saved
    })
    .await
    .unwrap();
    let first = catalog.page(None, 100).await.unwrap();
    assert_eq!(first.len(), 1);
    assert!(matches!(
        catalog.page(first.last(), 100).await,
        Err(DdbError::Internal(_))
    ));
    let db = state.clone();
    tokio::task::spawn_blocking(move || {
        db.connection()
            .unwrap()
            .execute(
                "UPDATE lc_dynamodb_table_files SET metadata=?1 WHERE name='catalog-large-b'",
                [saved],
            )
            .unwrap();
    })
    .await
    .unwrap();
    for record in large_records {
        let deleting = catalog
            .transition(&record, FilePhase::Deleting)
            .await
            .unwrap();
        catalog.forget_deleted(&deleting).await.unwrap();
    }
    let scope = TableKeyScope::new(ACCOUNT, REGION, "catalog-orders", Uuid::new_v4()).unwrap();
    let key = keys.generate(&scope, caller(), None).await.unwrap();
    let competitor = TableKeyScope::new(ACCOUNT, REGION, "catalog-orders", Uuid::new_v4()).unwrap();
    let competitor_key = keys.generate(&competitor, caller(), None).await.unwrap();
    let intent = json!({
        "TableName":"catalog-orders",
        "AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],
        "KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],
        "BillingMode":"PAY_PER_REQUEST",
        "StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_AND_OLD_IMAGES"},
        "Tags":[{"Key":"owner","Value":"durable-create-intent-marker"}],
        "DeletionProtectionEnabled":true
    });
    // Rejected intent must leave no reservation, even with an otherwise valid envelope.
    let mut wrong = intent.clone();
    wrong["TableName"] = json!("another-table");
    let mut oversized = intent.clone();
    oversized["Tags"][0]["Value"] = json!("x".repeat(1024 * 1024));
    let mut nested = json!(null);
    for _ in 0..34 {
        nested = json!([nested]);
    }
    let mut too_deep = intent.clone();
    too_deep["Tags"] = nested;
    let mut raw_request = intent.clone();
    raw_request["headers"] = json!({"authorization":"must-not-be-persisted"});
    let mut sse = intent.clone();
    sse["SSESpecification"] = json!({"Enabled":true});
    for invalid in [json!(null), wrong, oversized, too_deep, raw_request, sse] {
        assert!(matches!(
            catalog
                .reserve_with_intent(scope.clone(), key.envelope.clone(), invalid)
                .await,
            Err(DdbError::Validation(_))
        ));
        assert!(catalog
            .load(ACCOUNT, REGION, "catalog-orders")
            .await
            .unwrap()
            .is_none());
        assert!(catalog.page(None, 1).await.unwrap().is_empty());
    }
    // Competing creates with different files and keys must elect exactly one owner.
    let (a, b) = tokio::join!(
        catalog.reserve_with_intent(scope.clone(), key.envelope.clone(), intent.clone()),
        catalog.reserve_with_intent(competitor, competitor_key.envelope.clone(), intent.clone())
    );
    let (creating, expected_key) = match (a, b) {
        (Ok(record), Err(DdbError::ResourceInUse(_))) => (record, &key.plaintext),
        (Err(DdbError::ResourceInUse(_)), Ok(record)) => (record, &competitor_key.plaintext),
        other => panic!("unexpected reservation results: {other:?}"),
    };
    assert_eq!(creating.phase(), FilePhase::Creating);
    assert_eq!(creating.create_intent(), Some(&intent));
    let mut invalid_scope = serde_json::to_value(creating.scope()).unwrap();
    invalid_scope["storage_id"] = json!(Uuid::nil().to_string());
    assert!(serde_json::from_value::<TableKeyScope>(invalid_scope).is_err());
    assert!(catalog.forget_deleted(&creating).await.is_err());
    let path = state.path().to_owned();
    let reopened = Arc::new(
        tokio::task::spawn_blocking(move || StateDb::open(path).unwrap())
            .await
            .unwrap(),
    );
    let catalog = TableCatalog::new(reopened, keys.clone()).await.unwrap();
    let loaded = catalog
        .load(ACCOUNT, REGION, "catalog-orders")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.phase(), FilePhase::Creating);
    assert_eq!(loaded.create_intent(), Some(&intent));
    assert_eq!(
        catalog.page(None, 1).await.unwrap()[0].create_intent(),
        Some(&intent)
    );
    assert_eq!(
        keys.open(loaded.scope(), caller(), loaded.envelope())
            .await
            .unwrap()
            .as_slice(),
        expected_key.as_slice()
    );
    let description = json!({
        "TableName":"catalog-orders",
        "TableArn":format!("arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/catalog-orders"),
        "TableStatus":"ACTIVE",
        "ItemCount":7,
        "ProviderField":{"preserved":true}
    });
    let mut wrong_name = description.clone();
    wrong_name["TableName"] = json!("another-table");
    let mut wrong_arn = description.clone();
    wrong_arn["TableArn"] = json!(format!(
        "arn:aws:dynamodb:us-east-2:{ACCOUNT}:table/catalog-orders"
    ));
    let mut pending = description.clone();
    pending["TableStatus"] = json!("CREATING");
    let mut oversized = description.clone();
    oversized["ProviderField"] = json!("x".repeat(1024 * 1024));
    let mut nested = json!(null);
    for _ in 0..34 {
        nested = json!([nested]);
    }
    let mut too_deep = description.clone();
    too_deep["ProviderField"] = nested;
    for invalid in [
        json!(null),
        wrong_name,
        wrong_arn,
        pending,
        oversized,
        too_deep,
    ] {
        assert!(matches!(
            catalog.activate(&loaded, invalid).await,
            Err(DdbError::Validation(_))
        ));
        let unchanged = catalog
            .load(ACCOUNT, REGION, "catalog-orders")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.revision(), loaded.revision());
        assert_eq!(unchanged.phase(), FilePhase::Creating);
        assert!(unchanged.description().is_none());
    }
    let active = catalog
        .activate(&loaded, description.clone())
        .await
        .unwrap();
    assert_eq!(active.create_intent(), Some(&intent));
    assert_eq!(active.description(), Some(&description));
    let mut updated = description.clone();
    updated["ItemCount"] = json!(8);
    let refreshed = catalog
        .refresh_description(&active, updated.clone())
        .await
        .unwrap();
    assert_eq!(refreshed.revision(), active.revision() + 1);
    assert!(matches!(
        catalog
            .refresh_description(&active, description.clone())
            .await,
        Err(DdbError::ResourceInUse(_))
    ));
    assert!(matches!(
        catalog.activate(&active, description).await,
        Err(DdbError::Validation(_))
    ));
    let path = state.path().to_owned();
    let reopened = Arc::new(
        tokio::task::spawn_blocking(move || StateDb::open(path).unwrap())
            .await
            .unwrap(),
    );
    let catalog = TableCatalog::new(reopened, keys.clone()).await.unwrap();
    let active = catalog
        .load(ACCOUNT, REGION, "catalog-orders")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.description(), Some(&updated));
    assert_eq!(
        catalog.page(None, 1).await.unwrap()[0].description(),
        Some(&updated)
    );
    let update_intent = json!({"TableName":"catalog-orders","DeletionProtectionEnabled":true});
    for invalid in [
        json!({"TableName":"another-table","DeletionProtectionEnabled":true}),
        json!({"TableName":"catalog-orders","DeletionProtectionEnabled":"true"}),
        json!({"TableName":"catalog-orders","DeletionProtectionEnabled":true,"Extra":0}),
    ] {
        assert!(matches!(
            catalog.begin_update(&active, invalid).await,
            Err(DdbError::Validation(_))
        ));
    }
    let updating = catalog
        .begin_update(&active, update_intent.clone())
        .await
        .unwrap();
    assert!(matches!(
        catalog.begin_update(&active, update_intent.clone()).await,
        Err(DdbError::ResourceInUse(_))
    ));
    assert!(matches!(
        catalog.transition(&updating, FilePhase::Deleting).await,
        Err(DdbError::Validation(_))
    ));
    let path = state.path().to_owned();
    let reopened = Arc::new(
        tokio::task::spawn_blocking(move || StateDb::open(path).unwrap())
            .await
            .unwrap(),
    );
    let catalog = TableCatalog::new(reopened, keys.clone()).await.unwrap();
    let updating = catalog
        .load(ACCOUNT, REGION, "catalog-orders")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updating.phase(), FilePhase::Updating);
    assert_eq!(updating.pending_update(), Some(&update_intent));
    assert_eq!(updating.description(), Some(&updated));
    let mut actual = updated.clone();
    actual["DeletionProtectionEnabled"] = json!(true);
    let mut wrong_flag = actual.clone();
    wrong_flag["DeletionProtectionEnabled"] = json!(false);
    let mut wrong_scope = actual.clone();
    wrong_scope["TableArn"] = json!(format!(
        "arn:aws:dynamodb:us-east-2:{ACCOUNT}:table/catalog-orders"
    ));
    for invalid in [wrong_flag, wrong_scope] {
        assert!(matches!(
            catalog.complete_update(&updating, invalid).await,
            Err(DdbError::Validation(_))
        ));
        let unchanged = catalog
            .load(ACCOUNT, REGION, "catalog-orders")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.revision(), updating.revision());
        assert_eq!(unchanged.phase(), FilePhase::Updating);
    }
    let active = catalog
        .complete_update(&updating, actual.clone())
        .await
        .unwrap();
    assert_eq!(active.phase(), FilePhase::Active);
    assert!(active.pending_update().is_none());
    assert_eq!(active.description(), Some(&actual));
    assert_eq!(active.create_intent(), Some(&intent));
    assert_eq!(active.scope().storage_id(), updating.scope().storage_id());
    assert!(matches!(
        catalog.complete_update(&updating, actual).await,
        Err(DdbError::ResourceInUse(_))
    ));
    assert!(matches!(
        catalog.transition(&creating, FilePhase::Deleting).await,
        Err(DdbError::ResourceInUse(_))
    ));
    assert!(matches!(
        catalog.transition(&active, FilePhase::Creating).await,
        Err(DdbError::Validation(_))
    ));
    assert!(catalog
        .load(ACCOUNT, "us-east-2", "catalog-orders")
        .await
        .unwrap()
        .is_none());
    assert!(catalog
        .load("111111111111", REGION, "catalog-orders")
        .await
        .unwrap()
        .is_none());
    // Authenticated metadata cannot be moved to a different revision or corrupted.
    let db = state.clone();
    let saved = tokio::task::spawn_blocking(move || {
        let conn = db.connection().unwrap();
        let saved: Vec<u8> = conn
            .query_row(
                "SELECT metadata FROM lc_dynamodb_table_files WHERE name='catalog-orders'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let marker = b"durable-create-intent-marker";
        assert!(!saved.windows(marker.len()).any(|bytes| bytes == marker));
        conn.execute(
            "UPDATE lc_dynamodb_table_files SET revision=revision+1 WHERE name='catalog-orders'",
            [],
        )
        .unwrap();
        saved
    })
    .await
    .unwrap();
    assert!(matches!(
        catalog.load(ACCOUNT, REGION, "catalog-orders").await,
        Err(DdbError::Internal(_))
    ));
    assert!(matches!(
        catalog.page(None, 100).await,
        Err(DdbError::Internal(_))
    ));
    let db = state.clone();
    tokio::task::spawn_blocking(move || {
        let conn=db.connection().unwrap();
        conn.execute("UPDATE lc_dynamodb_table_files SET revision=revision-1,metadata=?1 WHERE name='catalog-orders'",[vec![0u8;32]]).unwrap();
    }).await.unwrap();
    assert!(matches!(
        catalog.load(ACCOUNT, REGION, "catalog-orders").await,
        Err(DdbError::Internal(_))
    ));
    let db = state.clone();
    tokio::task::spawn_blocking(move || {
        db.connection()
            .unwrap()
            .execute(
                "UPDATE lc_dynamodb_table_files SET metadata=?1 WHERE name='catalog-orders'",
                [saved],
            )
            .unwrap();
    })
    .await
    .unwrap();
    let deleting = catalog
        .transition(&active, FilePhase::Deleting)
        .await
        .unwrap();
    catalog.forget_deleted(&deleting).await.unwrap();
    assert!(catalog
        .load(ACCOUNT, REGION, "catalog-orders")
        .await
        .unwrap()
        .is_none());
    let replacement =
        TableKeyScope::new(ACCOUNT, REGION, "catalog-orders", Uuid::new_v4()).unwrap();
    let replacement_key = keys.generate(&replacement, caller(), None).await.unwrap();
    let fresh = catalog
        .reserve(replacement.clone(), replacement_key.envelope)
        .await
        .unwrap();
    assert_ne!(fresh.file_name(), creating.file_name());
    assert!(fresh.create_intent().is_none());
    assert!(fresh.description().is_none());
    assert!(catalog
        .load(ACCOUNT, REGION, "catalog-orders")
        .await
        .unwrap()
        .unwrap()
        .create_intent()
        .is_none());
    assert!(matches!(
        catalog.forget_deleted(&deleting).await,
        Err(DdbError::ResourceInUse(_))
    ));
    assert_eq!(
        catalog
            .load(ACCOUNT, REGION, "catalog-orders")
            .await
            .unwrap()
            .unwrap()
            .file_name(),
        fresh.file_name()
    );
    let other = TableKeyScope::new(ACCOUNT, REGION, "wrong-catalog-table", Uuid::new_v4()).unwrap();
    assert!(catalog.reserve(other, key.envelope).await.is_err());

    for (account, region, name) in [
        (ACCOUNT, REGION, "aaa-orders"),
        (ACCOUNT, "us-east-2", "aaa-orders"),
        ("111111111111", REGION, "aaa-orders"),
    ] {
        let scope = TableKeyScope::new(account, region, name, Uuid::new_v4()).unwrap();
        let mut call = caller();
        call.account_id = account.into();
        call.region = region.into();
        call.caller_arn = Some(format!("arn:aws:iam::{account}:root"));
        let key = keys.generate(&scope, call, None).await.unwrap();
        let record = catalog.reserve(scope, key.envelope).await.unwrap();
        let active = catalog
            .transition(&record, FilePhase::Active)
            .await
            .unwrap();
        assert!(active.description().is_none());
        if account != ACCOUNT {
            catalog
                .transition(&active, FilePhase::Deleting)
                .await
                .unwrap();
        }
    }
    let mut cursor = None;
    let mut inventory = Vec::new();
    loop {
        let page = catalog.page(cursor.as_ref(), 1).await.unwrap();
        if page.is_empty() {
            break;
        }
        assert_eq!(page.len(), 1);
        cursor = page.last().cloned();
        inventory.extend(page);
    }
    let scopes: Vec<_> = inventory
        .iter()
        .map(|record| {
            let scope = record.scope();
            (scope.account(), scope.region(), scope.table_name())
        })
        .collect();
    assert_eq!(
        scopes,
        vec![
            (ACCOUNT, REGION, "aaa-orders"),
            (ACCOUNT, REGION, "catalog-orders"),
            (ACCOUNT, "us-east-2", "aaa-orders"),
            ("111111111111", REGION, "aaa-orders"),
        ]
    );
    assert_eq!(inventory[1].phase(), FilePhase::Creating);
    assert_eq!(inventory[3].phase(), FilePhase::Deleting);
    let all = catalog.page(None, 100).await.unwrap();
    assert_eq!(all.len(), inventory.len());
    for (account, region, expected) in [
        (ACCOUNT, REGION, vec!["aaa-orders", "catalog-orders"]),
        (ACCOUNT, "us-east-2", vec!["aaa-orders"]),
        ("111111111111", REGION, vec!["aaa-orders"]),
    ] {
        let page = catalog
            .page_scope(account, region, None, 100)
            .await
            .unwrap();
        assert_eq!(
            page.iter()
                .map(|record| record.scope().table_name())
                .collect::<Vec<_>>(),
            expected
        );
        assert!(
            page.iter()
                .all(|record| record.scope().account() == account
                    && record.scope().region() == region)
        );
    }
    let after_missing = catalog
        .page_scope(ACCOUNT, REGION, Some("bbb-missing"), 100)
        .await
        .unwrap();
    assert_eq!(after_missing.len(), 1);
    assert_eq!(after_missing[0].scope().table_name(), "catalog-orders");
    assert!(matches!(
        catalog.page_scope(ACCOUNT, REGION, Some("../bad"), 1).await,
        Err(DdbError::Validation(_))
    ));
    for limit in [0, 101] {
        assert!(matches!(
            catalog.page_scope(ACCOUNT, REGION, None, limit).await,
            Err(DdbError::Validation(_))
        ));
    }

    // A deleted cursor still advances by its logical key without requiring the row.
    let deleting = catalog
        .transition(&fresh, FilePhase::Deleting)
        .await
        .unwrap();
    catalog.forget_deleted(&deleting).await.unwrap();
    assert_eq!(catalog.page(Some(&fresh), 100).await.unwrap().len(), 2);
    let db = state.clone();
    tokio::task::spawn_blocking(move || {
        db.connection()
            .unwrap()
            .execute(
                "UPDATE lc_dynamodb_table_files SET name=?1 WHERE account=?2 AND region=?3",
                ("x".repeat(256), "111111111111", REGION),
            )
            .unwrap();
    })
    .await
    .unwrap();
    assert!(matches!(
        catalog.page(None, 100).await,
        Err(DdbError::Internal(_))
    ));
    let db = state.clone();
    tokio::task::spawn_blocking(move || {
        db.connection().unwrap().execute(
            "UPDATE lc_dynamodb_table_files SET account='',region='',name='' WHERE account='111111111111'",
            [],
        ).unwrap();
    }).await.unwrap();
    assert!(matches!(
        catalog.page(None, 100).await,
        Err(DdbError::Internal(_))
    ));
}

async fn action_specific_authorization(registry: &Arc<ServiceRegistry>, broker: &TableKeys) {
    use locallycloud_core::integration::identity::CallerIdentity;
    use locallycloud_core::integration::RequestIdentity;
    use locallycloud_iam_sts::enforcement::EnforcementMode;
    use locallycloud_iam_sts::model::IamRole;
    use locallycloud_iam_sts::store::IamStore;
    use locallycloud_iam_sts::sts::SessionStore;
    use std::collections::BTreeMap;

    let scope = TableKeyScope::new(ACCOUNT, REGION, "iam-orders", Uuid::new_v4()).unwrap();
    let created = kms(registry, "CreateKey", json!({})).await;
    let arn = created["KeyMetadata"]["Arn"].as_str().unwrap();
    let key_id = created["KeyMetadata"]["KeyId"].as_str().unwrap();
    kms(
        registry,
        "CreateAlias",
        json!({"AliasName":"alias/iam-table","TargetKeyId":arn}),
    )
    .await;
    let material = broker.generate(&scope, caller(), Some(arn)).await.unwrap();
    let denied = kms(registry, "CreateKey", json!({})).await;
    let denied_arn = denied["KeyMetadata"]["Arn"].as_str().unwrap();
    let root = json!({"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:root")},"Action":"kms:*","Resource":"*"});
    kms(registry,"PutKeyPolicy",json!({"KeyId":denied_arn,"PolicyName":"default","Policy":json!({"Version":"2012-10-17","Statement":[root,{"Effect":"Deny","Principal":"*","Action":"kms:GenerateDataKey","Resource":"*"}]}).to_string()})).await;

    let store = Arc::new(IamStore::new());
    for (name, allow, deny) in [
        ("generator", "kms:GenerateDataKey", "kms:Decrypt"),
        ("reader", "kms:Decrypt", "kms:GenerateDataKey"),
    ] {
        let policy = json!({"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":allow,"Resource":[arn,denied_arn],"Condition":{"StringEquals":{"kms:ViaService":format!("dynamodb.{REGION}.amazonaws.com"),"kms:EncryptionContext:aws:dynamodb:tableName":"iam-orders"}}},
            {"Effect":"Deny","Action":deny,"Resource":"*"}
        ]}).to_string();
        store.create_role(
            ACCOUNT,
            IamRole {
                role_name: name.into(),
                role_id: format!("role-{name}"),
                arn: format!("arn:aws:iam::{ACCOUNT}:role/{name}"),
                path: "/".into(),
                create_date: "2026-01-01T00:00:00Z".into(),
                assume_role_policy_document: "{}".into(),
                description: None,
                max_session_duration: 3600,
                tags: BTreeMap::new(),
                attached_policies: Vec::new(),
                inline_policies: BTreeMap::from([("key".into(), policy)]),
                permission_boundary: None,
            },
        );
    }
    locallycloud_iam_sts::register_with_store_and_mode(
        registry,
        store,
        Arc::new(SessionStore::new()),
        EnforcementMode::Strict,
    );
    let identity = RequestIdentity {
        account_id: ACCOUNT.into(),
        ..Default::default()
    };
    let role = |name: &str| {
        Some(CallerIdentity::AssumedRole {
            role_arn: format!("arn:aws:iam::{ACCOUNT}:role/{name}"),
            session_name: "table".into(),
        })
    };
    // All selectors authorize against the resolved key ARN, including aliases and bare IDs.
    for selector in [arn, key_id, "alias/iam-table"] {
        let (call, canonical) = broker
            .generation_context(
                &scope,
                Some(selector),
                "generate",
                identity.clone(),
                role("generator"),
            )
            .await
            .unwrap();
        assert!(call.iam_policy_allowed);
        assert!(!call.iam_policy_denied);
        assert_eq!(canonical, arn);
        broker
            .generate(&scope, call, Some(&canonical))
            .await
            .unwrap();
    }
    let call = broker
        .decryption_context(
            &scope,
            &material.envelope,
            "read",
            identity.clone(),
            role("generator"),
        )
        .unwrap();
    assert!(call.iam_policy_denied);
    assert!(matches!(
        broker.open(&scope, call, &material.envelope).await,
        Err(KmsInternalError::AccessDenied)
    ));
    let call = broker
        .decryption_context(
            &scope,
            &material.envelope,
            "read",
            identity.clone(),
            role("reader"),
        )
        .unwrap();
    assert!(call.iam_policy_allowed);
    broker.open(&scope, call, &material.envelope).await.unwrap();
    let (call, canonical) = broker
        .generation_context(
            &scope,
            Some("alias/iam-table"),
            "generate",
            identity.clone(),
            role("reader"),
        )
        .await
        .unwrap();
    assert!(call.iam_policy_denied);
    assert!(matches!(
        broker.generate(&scope, call, Some(&canonical)).await,
        Err(KmsInternalError::AccessDenied)
    ));
    assert!(matches!(
        broker
            .generation_context(&scope, None, "unknown", identity.clone(), None)
            .await,
        Err(KmsInternalError::AccessDenied)
    ));
    let (call, canonical) = broker
        .generation_context(
            &scope,
            Some(denied_arn),
            "generate",
            identity,
            role("generator"),
        )
        .await
        .unwrap();
    assert!(call.iam_policy_allowed);
    assert!(matches!(
        broker.generate(&scope, call, Some(&canonical)).await,
        Err(KmsInternalError::AccessDenied)
    ));
}

#[tokio::test]
async fn real_kms_table_keys_are_unique_scope_bound_persistent_and_revocable() {
    // This integration binary has one test and owns its complete throwaway environment.
    std::env::set_var(
        "LOCALLYCLOUD_KMS_MASTER_KEY",
        base64::engine::general_purpose::STANDARD.encode([13; 32]),
    );
    std::env::set_var("LOCALLYCLOUD_IAM_ENFORCEMENT", "permissive");
    let root = std::env::temp_dir().join(format!("dynamodb-table-keys-{}", Uuid::new_v4()));
    let path = root.join("state.db");
    let state = Arc::new(
        tokio::task::spawn_blocking(move || StateDb::open(path).unwrap())
            .await
            .unwrap(),
    );
    let registry = ServiceRegistry::with_known_services();
    let dispatch = dispatcher(&registry);
    locallycloud_iam_sts::service::register_with_state(&registry, ACCOUNT, state.clone()).unwrap();
    locallycloud_kms::register_with_state(&registry, state.clone()).unwrap();
    let cipher = Arc::new(StateCipher::with_key(&[13; 32]));
    let broker = TableKeys::new(dispatch, cipher.clone());
    let mut scopes = Vec::new();
    let mut materials = Vec::new();
    for table in ["orders", "payments"] {
        let created = kms(&registry, "CreateKey", json!({})).await;
        let arn = created["KeyMetadata"]["Arn"].as_str().unwrap();
        let scope = TableKeyScope::new(ACCOUNT, REGION, table, Uuid::new_v4()).unwrap();
        let material = broker.generate(&scope, caller(), Some(arn)).await.unwrap();
        assert_eq!(material.key_arn, arn);
        assert_eq!(
            broker
                .open(&scope, caller(), &material.envelope)
                .await
                .unwrap()
                .as_slice(),
            material.plaintext.as_slice()
        );
        scopes.push(scope);
        materials.push(material);
    }
    assert_ne!(
        materials[0].plaintext.as_slice(),
        materials[1].plaintext.as_slice()
    );
    let scopes: [TableKeyScope; 2] = scopes.try_into().unwrap();
    let shadow_scope =
        TableKeyScope::new(ACCOUNT, REGION, "archive-orders", Uuid::new_v4()).unwrap();
    let shadow = broker
        .generate(&shadow_scope, caller(), Some(&materials[0].key_arn))
        .await
        .unwrap();
    for wrong in [
        TableKeyScope::new(ACCOUNT, REGION, "orders", Uuid::new_v4()).unwrap(),
        scopes[1].clone(),
        TableKeyScope::new(ACCOUNT, "us-east-2", "orders", scopes[0].storage_id()).unwrap(),
    ] {
        let mut call = caller();
        call.region = wrong.region().into();
        assert!(matches!(
            broker.open(&wrong, call, &materials[0].envelope).await,
            Err(KmsInternalError::InvalidCiphertext)
        ));
    }
    let mut corrupt = serde_json::to_value(&materials[0].envelope).unwrap();
    let byte = corrupt["sealed"][0].as_u64().unwrap();
    corrupt["sealed"][0] = json!(byte ^ 1);
    let corrupt: TableKeyEnvelope = serde_json::from_value(corrupt).unwrap();
    assert!(matches!(
        broker.open(&scopes[0], caller(), &corrupt).await,
        Err(KmsInternalError::InvalidCiphertext)
    ));
    let mut wrong_service = caller();
    wrong_service.source_service = "s3".into();
    assert!(matches!(
        broker
            .open(&scopes[0], wrong_service, &materials[0].envelope)
            .await,
        Err(KmsInternalError::InvalidRequest)
    ));
    let mut denied = caller();
    denied.iam_policy_denied = true;
    assert!(matches!(
        broker
            .open(&scopes[0], denied, &materials[0].envelope)
            .await,
        Err(KmsInternalError::AccessDenied)
    ));
    let managed = broker.generate(&scopes[0], caller(), None).await.unwrap();
    assert_ne!(
        managed.plaintext.as_slice(),
        materials[0].plaintext.as_slice()
    );
    let repeated = broker
        .generate(&scopes[0], caller(), Some(&materials[0].key_arn))
        .await
        .unwrap();
    assert_ne!(
        repeated.plaintext.as_slice(),
        materials[0].plaintext.as_slice()
    );
    kms(
        &registry,
        "CreateAlias",
        json!({"AliasName":"alias/table-key-test","TargetKeyId":materials[0].key_arn}),
    )
    .await;
    let aliased = broker
        .generate(&scopes[0], caller(), Some("alias/table-key-test"))
        .await
        .unwrap();
    assert_eq!(aliased.key_arn, materials[0].key_arn);
    kms(
        &registry,
        "UpdateAlias",
        json!({"AliasName":"alias/table-key-test","TargetKeyId":materials[1].key_arn}),
    )
    .await;
    assert_eq!(
        broker
            .open(&scopes[0], caller(), &aliased.envelope)
            .await
            .unwrap()
            .as_slice(),
        aliased.plaintext.as_slice()
    );
    kms(
        &registry,
        "RotateKeyOnDemand",
        json!({"KeyId":materials[0].key_arn}),
    )
    .await;
    assert_eq!(
        broker
            .open(&scopes[0], caller(), &materials[0].envelope)
            .await
            .unwrap()
            .as_slice(),
        materials[0].plaintext.as_slice()
    );
    let saved: TableKeyEnvelope =
        serde_json::from_slice(&serde_json::to_vec(&materials[0].envelope).unwrap()).unwrap();
    drop(broker);
    drop(registry);
    let registry = ServiceRegistry::with_known_services();
    let broker = TableKeys::new(dispatcher(&registry), cipher);
    locallycloud_iam_sts::service::register_with_state(&registry, ACCOUNT, state.clone()).unwrap();
    locallycloud_kms::register_with_state(&registry, state.clone()).unwrap();
    assert_eq!(
        broker
            .open(&scopes[0], caller(), &saved)
            .await
            .unwrap()
            .as_slice(),
        materials[0].plaintext.as_slice()
    );
    kms(
        &registry,
        "DisableKey",
        json!({"KeyId":materials[0].key_arn}),
    )
    .await;
    assert!(matches!(
        broker.open(&scopes[0], caller(), &saved).await,
        Err(KmsInternalError::Disabled)
    ));
    assert_eq!(
        broker
            .open(&scopes[1], caller(), &materials[1].envelope)
            .await
            .unwrap()
            .as_slice(),
        materials[1].plaintext.as_slice()
    );
    kms(
        &registry,
        "EnableKey",
        json!({"KeyId":materials[0].key_arn}),
    )
    .await;
    let root_statement = json!({"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:root")},"Action":"kms:*","Resource":"*"});
    let deny_policy = json!({"Version":"2012-10-17","Statement":[root_statement.clone(),{"Effect":"Deny","Principal":"*","Action":"kms:Decrypt","Resource":"*","Condition":{"StringEquals":{"kms:ViaService":format!("dynamodb.{REGION}.amazonaws.com"),"kms:EncryptionContext:aws:dynamodb:tableName":"orders"}}}]}).to_string();
    kms(
        &registry,
        "PutKeyPolicy",
        json!({"KeyId":materials[0].key_arn,"PolicyName":"default","Policy":deny_policy}),
    )
    .await;
    assert!(matches!(
        broker.open(&scopes[0], caller(), &saved).await,
        Err(KmsInternalError::AccessDenied)
    ));
    assert_eq!(
        broker
            .open(&shadow_scope, caller(), &shadow.envelope)
            .await
            .unwrap()
            .as_slice(),
        shadow.plaintext.as_slice()
    );
    kms(&registry,"PutKeyPolicy",json!({"KeyId":materials[0].key_arn,"PolicyName":"default","Policy":json!({"Version":"2012-10-17","Statement":[root_statement]}).to_string()})).await;
    let opened = broker.open(&scopes[0], caller(), &saved).await.unwrap();
    if let Some(binary) = std::env::var_os("LOCALLYCLOUD_TEST_TABLE_WORKER") {
        physical_files(
            &PathBuf::from(binary),
            &root,
            &scopes,
            [&opened, &materials[1].plaintext],
        )
        .await;
        eprintln!("Real SQLCipher worker: two independent KMS keys; wrong key and physical scope rejected; restart preserved data");
    }
    catalog_recovery(&registry, state.clone()).await;
    action_specific_authorization(&registry, &broker).await;
    drop(broker);
    drop(registry);
    drop(state);
    tokio::fs::remove_dir_all(root).await.unwrap();
}
