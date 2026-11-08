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
    let scope = TableKeyScope::new(ACCOUNT, REGION, "catalog-orders", Uuid::new_v4()).unwrap();
    let key = keys.generate(&scope, caller(), None).await.unwrap();
    let competitor = TableKeyScope::new(ACCOUNT, REGION, "catalog-orders", Uuid::new_v4()).unwrap();
    let competitor_key = keys.generate(&competitor, caller(), None).await.unwrap();
    // Competing creates with different files and keys must elect exactly one owner.
    let (a, b) = tokio::join!(
        catalog.reserve(scope.clone(), key.envelope.clone()),
        catalog.reserve(competitor, competitor_key.envelope.clone())
    );
    let (creating, expected_key) = match (a, b) {
        (Ok(record), Err(DdbError::ResourceInUse(_))) => (record, &key.plaintext),
        (Err(DdbError::ResourceInUse(_)), Ok(record)) => (record, &competitor_key.plaintext),
        other => panic!("unexpected reservation results: {other:?}"),
    };
    assert_eq!(creating.phase(), FilePhase::Creating);
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
    assert_eq!(
        keys.open(loaded.scope(), caller(), loaded.envelope())
            .await
            .unwrap()
            .as_slice(),
        expected_key.as_slice()
    );
    let active = catalog
        .transition(&loaded, FilePhase::Active)
        .await
        .unwrap();
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
    drop(broker);
    drop(registry);
    drop(state);
    tokio::fs::remove_dir_all(root).await.unwrap();
}
