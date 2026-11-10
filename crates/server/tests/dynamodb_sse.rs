//! Public DynamoDB SSE lifecycle against an explicitly supplied real ExtendDB worker.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::ServiceRegistry;
use locallycloud_dynamodb::encryption::catalog::TableCatalog;
use locallycloud_dynamodb::encryption::TableKeys;
use locallycloud_state::{StateCipher, StateDb};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const TEST_MASTER_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

struct Server {
    child: Child,
    endpoint: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl Server {
    async fn stop(&mut self) {
        tokio::time::timeout(Duration::from_secs(15), self.child.kill())
            .await
            .expect("server shutdown deadline")
            .expect("kill and reap server");
        assert!(self.child.try_wait().unwrap().is_some());
    }
}

async fn fixture(binary: PathBuf) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("dynamodb-sse-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    tokio::fs::create_dir(dir.join("home")).await.unwrap();
    let bytes = tokio::fs::read(binary).await.expect("read actual worker");
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let version = dir.join("components/extenddb/versions").join(&digest);
    tokio::fs::create_dir_all(&version).await.unwrap();
    tokio::fs::write(version.join("worker"), bytes)
        .await
        .unwrap();
    tokio::fs::set_permissions(
        version.join("worker"),
        std::fs::Permissions::from_mode(0o700),
    )
    .await
    .unwrap();
    tokio::fs::write(
        dir.join("components/extenddb/active.json"),
        json!({"protocol":1,"sha256":digest}).to_string(),
    )
    .await
    .unwrap();
    dir
}

async fn start(dir: &Path) -> Server {
    let mut child = Command::new(env!("CARGO_BIN_EXE_locallycloud"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir.join("home"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("XDG_CACHE_HOME", dir.join("cache"))
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("AWS_CONFIG_FILE", dir.join("aws-config"))
        .env("AWS_SHARED_CREDENTIALS_FILE", dir.join("aws-credentials"))
        .env("LOCALLYCLOUD_STATE_DB", dir.join("state.sqlite3"))
        .env("LOCALLYCLOUD_WORK_DIR", dir.join("work"))
        .env("LOCALLYCLOUD_COMPONENTS_DIR", dir.join("components"))
        .env("LOCALLYCLOUD_KMS_MASTER_KEY", TEST_MASTER_KEY)
        .env("LOCALLYCLOUD_DYNAMODB_ENGINE", "extenddb")
        .env("LOCALLYCLOUD_IAM_ENFORCEMENT", "permissive")
        .env("LOCALLYCLOUD_HOST", "127.0.0.1")
        .env("LOCALLYCLOUD_PORT", "0")
        .env(
            "RUST_LOG",
            "locallycloud=info,locallycloud_core::server=info",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn locallycloud");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    for stream in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stream).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx.send(line);
            }
        });
    }
    drop(tx);
    let endpoint = tokio::time::timeout(Duration::from_secs(60), async {
        let mut seen = Vec::new();
        while let Some(line) = rx.recv().await {
            if let Some((_, rest)) = line.split_once("\"addr\":\"127.0.0.1:") {
                let port: String = rest.chars().take_while(char::is_ascii_digit).collect();
                return format!("http://127.0.0.1:{port}");
            }
            seen.push(line);
        }
        panic!("server exited before listening: {}", seen.join("\n"));
    })
    .await
    .expect("server readiness deadline");
    Server { child, endpoint }
}

async fn call(
    client: &reqwest::Client,
    server: &Server,
    region: &str,
    service: &str,
    operation: &str,
    body: Value,
) -> (u16, Value) {
    let target = if service == "kms" {
        "TrentService"
    } else {
        "DynamoDB_20120810"
    };
    let response = client
        .post(format!("{}/", server.endpoint))
        .header("content-type", if service == "kms" { "application/x-amz-json-1.1" } else { "application/x-amz-json-1.0" })
        .header("x-amz-target", format!("{target}.{operation}"))
        .header("authorization", format!("AWS4-HMAC-SHA256 Credential=test/20240101/{region}/{service}/aws4_request, SignedHeaders=host, Signature=0"))
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|error| panic!("{service}:{operation}: {error}"));
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap();
    if bytes.is_empty() {
        return (status, Value::Null);
    }
    let value = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "{operation} HTTP {status}: {error}; {}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, value)
}

async fn ok(
    client: &reqwest::Client,
    server: &Server,
    region: &str,
    service: &str,
    operation: &str,
    body: Value,
) -> Value {
    let (status, value) = call(client, server, region, service, operation, body).await;
    assert_eq!(status, 200, "{service}:{operation}: {value}");
    value
}

fn error(reply: (u16, Value), kind: &str) {
    assert_eq!(reply.0, 400, "{}", reply.1);
    assert!(
        reply.1["__type"]
            .as_str()
            .unwrap_or_default()
            .ends_with(kind),
        "{}",
        reply.1
    );
}

fn create(name: &str, key: Option<&str>) -> Value {
    let mut body = json!({"TableName":name,"BillingMode":"PAY_PER_REQUEST","AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],"KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}]});
    if let Some(key) = key {
        body["SSESpecification"] = json!({"Enabled":true,"KMSMasterKeyId":key});
    }
    body
}

async fn active(client: &reqwest::Client, server: &Server, region: &str, name: &str) -> Value {
    for _ in 0..100 {
        let value = ok(
            client,
            server,
            region,
            "dynamodb",
            "DescribeTable",
            json!({"TableName":name}),
        )
        .await;
        if value["Table"]["TableStatus"] == "ACTIVE" {
            return value["Table"].clone();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("table {name} did not become ACTIVE");
}

// Called only after the subprocess has exited: persist the accepted update intent,
// leaving the provider unchanged as a crash before its UpdateTable call would.
async fn interrupt_protection_update(dir: &Path) -> PathBuf {
    let previous = std::env::var_os("LOCALLYCLOUD_KMS_MASTER_KEY");
    std::env::set_var("LOCALLYCLOUD_KMS_MASTER_KEY", TEST_MASTER_KEY);
    let path = dir.join("state.sqlite3");
    let opened = tokio::task::spawn_blocking(move || StateDb::open(path)).await;
    match previous {
        Some(value) => std::env::set_var("LOCALLYCLOUD_KMS_MASTER_KEY", value),
        None => std::env::remove_var("LOCALLYCLOUD_KMS_MASTER_KEY"),
    }
    let state = Arc::new(opened.unwrap().unwrap());
    let registry = ServiceRegistry::with_known_services();
    let dispatcher = Arc::new(InternalDispatcher::new_shared(
        &registry,
        ProxyConfig {
            backend_url: "http://127.0.0.1:1".into(),
            upstream_timeout: Duration::from_secs(1),
        },
        LegacyHealth::new(false),
        "us-east-1".into(),
        "000000000000".into(),
    ));
    let keys = Arc::new(TableKeys::new(
        dispatcher,
        Arc::new(StateCipher::with_key(&[0; 32])),
    ));
    let catalog = TableCatalog::new(state, keys).await.unwrap();
    let record = catalog
        .load("000000000000", "us-east-1", "encrypted")
        .await
        .unwrap()
        .unwrap();
    catalog
        .begin_update(
            &record,
            json!({"TableName":"encrypted","DeletionProtectionEnabled":true}),
        )
        .await
        .unwrap();
    dir.join("state.sqlite3.extenddb")
        .join(record.scope().account())
        .join(record.scope().region())
        .join(record.file_name())
}

#[tokio::test]
async fn real_public_sse_lifecycle() {
    let Some(binary) = std::env::var_os("LOCALLYCLOUD_TEST_TABLE_WORKER") else {
        return;
    };
    let dir = fixture(PathBuf::from(binary)).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .build()
        .unwrap();
    let mut server = start(&dir).await;
    let region = "us-east-1";
    let key = ok(&client, &server, region, "kms", "CreateKey", json!({})).await;
    let key_id = key["KeyMetadata"]["KeyId"].as_str().unwrap();
    let key_arn = key["KeyMetadata"]["Arn"].as_str().unwrap();
    let mut managed = create("managed", None);
    managed["SSESpecification"] = json!({"Enabled":true});
    ok(&client, &server, region, "dynamodb", "CreateTable", managed).await;
    let managed = active(&client, &server, region, "managed").await;
    assert_eq!(managed["SSEDescription"]["SSEType"], "KMS");
    assert!(managed["SSEDescription"]["KMSMasterKeyArn"]
        .as_str()
        .unwrap()
        .starts_with("arn:aws:kms:us-east-1:000000000000:key/"));
    assert_ne!(managed["SSEDescription"]["KMSMasterKeyArn"], key_arn);
    ok(
        &client,
        &server,
        region,
        "dynamodb",
        "DeleteTable",
        json!({"TableName":"managed"}),
    )
    .await;
    ok(
        &client,
        &server,
        region,
        "dynamodb",
        "CreateTable",
        create("encrypted", Some(key_id)),
    )
    .await;
    let descriptor = active(&client, &server, region, "encrypted").await;
    assert_eq!(descriptor["SSEDescription"]["Status"], "ENABLED");
    assert_eq!(descriptor["SSEDescription"]["SSEType"], "KMS");
    assert_eq!(descriptor["SSEDescription"]["KMSMasterKeyArn"], key_arn);
    let table_arn = descriptor["TableArn"].as_str().unwrap().to_owned();
    let item = json!({"pk":{"S":"durable"},"value":{"S":"secret"}});
    ok(
        &client,
        &server,
        region,
        "dynamodb",
        "PutItem",
        json!({"TableName":"encrypted","Item":item}),
    )
    .await;
    let get = json!({"TableName":table_arn,"Key":{"pk":{"S":"durable"}},"ConsistentRead":true});
    assert_eq!(
        ok(&client, &server, region, "dynamodb", "GetItem", get.clone()).await["Item"],
        item
    );
    ok(
        &client,
        &server,
        region,
        "dynamodb",
        "CreateTable",
        create("plain", None),
    )
    .await;
    active(&client, &server, region, "plain").await;
    let owned_item = json!({"pk":{"S":"owned"},"value":{"S":"before"}});
    let written = ok(
        &client,
        &server,
        region,
        "dynamodb",
        "BatchWriteItem",
        json!({"RequestItems":{"plain":[{"PutRequest":{"Item":owned_item}}]}}),
    )
    .await;
    assert!(
        written["UnprocessedItems"]
            .as_object()
            .is_some_and(|items| items.is_empty()),
        "{written}"
    );
    error(call(
        &client, &server, region, "dynamodb", "BatchWriteItem",
        json!({"RequestItems":{
            "plain":[{"PutRequest":{"Item":{"pk":{"S":"owned"},"value":{"S":"forbidden"}}}}],
            "encrypted":[{"PutRequest":{"Item":{"pk":{"S":"durable"},"value":{"S":"forbidden"}}}}]
        }}),
    ).await, "ValidationException");
    assert_eq!(
        ok(
            &client,
            &server,
            region,
            "dynamodb",
            "GetItem",
            json!({"TableName":"plain","Key":{"pk":{"S":"owned"}},"ConsistentRead":true}),
        )
        .await["Item"],
        owned_item
    );
    error(
        call(
            &client,
            &server,
            region,
            "dynamodb",
            "CreateTable",
            create("encrypted", None),
        )
        .await,
        "ResourceInUseException",
    );
    error(
        call(
            &client,
            &server,
            region,
            "dynamodb",
            "CreateTable",
            create("plain", Some(key_id)),
        )
        .await,
        "ResourceInUseException",
    );
    let mut names = Vec::new();
    let mut page = json!({"Limit":1});
    for _ in 0..5 {
        let result = ok(
            &client,
            &server,
            region,
            "dynamodb",
            "ListTables",
            page.clone(),
        )
        .await;
        let listed = result["TableNames"].as_array().unwrap();
        assert!(listed.len() <= 1, "{result}");
        names.extend(listed.iter().map(|name| name.as_str().unwrap().to_owned()));
        let Some(last) = result["LastEvaluatedTableName"]
            .as_str()
            .filter(|name| !name.is_empty())
        else {
            break;
        };
        page["ExclusiveStartTableName"] = json!(last);
    }
    assert_eq!(names, ["encrypted", "plain"]);
    ok(&client, &server, region, "dynamodb", "UpdateTable", json!({"TableName":"encrypted","SSESpecification":{"Enabled":true,"KMSMasterKeyId":key_id},"DeletionProtectionEnabled":true})).await;
    error(
        call(
            &client,
            &server,
            region,
            "dynamodb",
            "DeleteTable",
            json!({"TableName":"encrypted"}),
        )
        .await,
        "ValidationException",
    );
    let (updated, _) = tokio::join!(
        ok(
            &client,
            &server,
            region,
            "dynamodb",
            "UpdateTable",
            json!({"TableName":"encrypted","DeletionProtectionEnabled":false}),
        ),
        ok(
            &client,
            &server,
            region,
            "dynamodb",
            "DescribeTable",
            json!({"TableName":"encrypted"}),
        )
    );
    assert_eq!(
        updated["TableDescription"]["DeletionProtectionEnabled"],
        false
    );
    assert_eq!(
        active(&client, &server, region, "encrypted").await["DeletionProtectionEnabled"],
        false
    );

    let (_, observed) = tokio::join!(
        ok(
            &client,
            &server,
            region,
            "dynamodb",
            "CreateTable",
            create("observing", Some(key_id)),
        ),
        async {
            let mut seen = false;
            for _ in 0..100 {
                let reply = call(
                    &client,
                    &server,
                    region,
                    "dynamodb",
                    "DescribeTable",
                    json!({"TableName":"observing"}),
                )
                .await;
                if reply.0 == 200 {
                    seen = true;
                    if reply.1["Table"]["TableStatus"] == "ACTIVE" {
                        return reply.1;
                    }
                } else {
                    assert!(!seen, "table disappeared during create: {reply:?}");
                    error(reply, "ResourceNotFoundException");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("concurrently observed create did not become ACTIVE");
        }
    );
    assert_eq!(
        observed["Table"]["SSEDescription"]["KMSMasterKeyArn"],
        key_arn
    );
    ok(
        &client,
        &server,
        region,
        "dynamodb",
        "DeleteTable",
        json!({"TableName":"observing"}),
    )
    .await;
    let other_key = ok(&client, &server, region, "kms", "CreateKey", json!({})).await;
    error(call(&client, &server, region, "dynamodb", "UpdateTable", json!({"TableName":"encrypted","SSESpecification":{"Enabled":true,"KMSMasterKeyId":other_key["KeyMetadata"]["KeyId"]}})).await, "ValidationException");
    error(call(&client, &server, region, "dynamodb", "BatchGetItem", json!({"RequestItems":{"encrypted":{"Keys":[{"pk":{"S":"durable"}}]},"plain":{"Keys":[{"pk":{"S":"durable"}}]}}})).await, "ValidationException");
    assert_eq!(
        ok(&client, &server, region, "dynamodb", "GetItem", get.clone()).await["Item"],
        item
    );
    let mut invalid = create("invalid-schema", Some(key_id));
    invalid["KeySchema"] = json!([]);
    error(
        call(&client, &server, region, "dynamodb", "CreateTable", invalid).await,
        "ValidationException",
    );
    error(
        call(
            &client,
            &server,
            region,
            "dynamodb",
            "DescribeTable",
            json!({"TableName":"invalid-schema"}),
        )
        .await,
        "ResourceNotFoundException",
    );
    let mut invalid = create("invalid-type", Some(key_id));
    invalid["DeletionProtectionEnabled"] = json!("yes");
    error(
        call(&client, &server, region, "dynamodb", "CreateTable", invalid).await,
        "SerializationException",
    );
    let listed = ok(
        &client,
        &server,
        region,
        "dynamodb",
        "ListTables",
        json!({}),
    )
    .await;
    assert!(!listed["TableNames"]
        .as_array()
        .unwrap()
        .contains(&json!("invalid-schema")));
    assert!(!listed["TableNames"]
        .as_array()
        .unwrap()
        .contains(&json!("invalid-type")));

    let (plain_race, cmk_race) = tokio::join!(
        call(
            &client,
            &server,
            region,
            "dynamodb",
            "CreateTable",
            create("racing", None)
        ),
        call(
            &client,
            &server,
            region,
            "dynamodb",
            "CreateTable",
            create("racing", Some(key_id))
        )
    );
    assert_eq!(
        usize::from(plain_race.0 == 200) + usize::from(cmk_race.0 == 200),
        1,
        "{plain_race:?} {cmk_race:?}"
    );
    error(
        if plain_race.0 == 200 {
            cmk_race
        } else {
            plain_race
        },
        "ResourceInUseException",
    );
    active(&client, &server, region, "racing").await;
    ok(
        &client,
        &server,
        region,
        "dynamodb",
        "DeleteTable",
        json!({"TableName":"racing"}),
    )
    .await;

    let west = "us-west-2";
    let west_key = ok(&client, &server, west, "kms", "CreateKey", json!({})).await;
    ok(
        &client,
        &server,
        west,
        "dynamodb",
        "CreateTable",
        create("encrypted", west_key["KeyMetadata"]["KeyId"].as_str()),
    )
    .await;
    active(&client, &server, west, "encrypted").await;
    assert!(ok(
        &client,
        &server,
        west,
        "dynamodb",
        "GetItem",
        json!({"TableName":"encrypted","Key":{"pk":{"S":"durable"}}})
    )
    .await
    .get("Item")
    .is_none());
    let west_item = json!({"pk":{"S":"durable"},"value":{"S":"west"}});
    ok(
        &client,
        &server,
        west,
        "dynamodb",
        "PutItem",
        json!({"TableName":"encrypted","Item":west_item}),
    )
    .await;
    assert_eq!(
        ok(
            &client,
            &server,
            west,
            "dynamodb",
            "GetItem",
            json!({"TableName":"encrypted","Key":{"pk":{"S":"durable"}}})
        )
        .await["Item"],
        west_item
    );
    assert_eq!(
        ok(&client, &server, region, "dynamodb", "GetItem", get.clone()).await["Item"],
        item
    );
    server.stop().await;
    let database = tokio::time::timeout(Duration::from_secs(15), interrupt_protection_update(&dir))
        .await
        .expect("persist interrupted update deadline");
    let saved_database = database.with_extension("sqlite3.saved");
    tokio::fs::rename(&database, &saved_database)
        .await
        .expect("hide fixture table file while server is stopped");
    server = start(&dir).await;
    let interrupted = ok(
        &client,
        &server,
        region,
        "dynamodb",
        "DescribeTable",
        json!({"TableName":"encrypted"}),
    )
    .await;
    assert_eq!(interrupted["Table"]["TableStatus"], "UPDATING");
    error(
        call(
            &client,
            &server,
            region,
            "dynamodb",
            "DeleteTable",
            json!({"TableName":"encrypted"}),
        )
        .await,
        "ResourceInUseException",
    );
    assert!(
        !tokio::fs::try_exists(&database).await.unwrap(),
        "Describe recreated a missing encrypted table file"
    );
    server.stop().await;
    tokio::fs::rename(&saved_database, &database)
        .await
        .expect("restore fixture table file while server is stopped");
    server = start(&dir).await;
    ok(
        &client,
        &server,
        region,
        "dynamodb",
        "UpdateTable",
        json!({"TableName":"encrypted","DeletionProtectionEnabled":true}),
    )
    .await;
    assert_eq!(
        active(&client, &server, region, "encrypted").await["DeletionProtectionEnabled"],
        true
    );
    ok(
        &client,
        &server,
        region,
        "dynamodb",
        "UpdateTable",
        json!({"TableName":"encrypted","DeletionProtectionEnabled":false}),
    )
    .await;
    let restored = active(&client, &server, region, "encrypted").await;
    assert_eq!(restored["SSEDescription"], descriptor["SSEDescription"]);
    assert_eq!(restored["TableArn"], table_arn);
    assert_eq!(
        ok(&client, &server, region, "dynamodb", "GetItem", get.clone()).await["Item"],
        item
    );
    ok(
        &client,
        &server,
        region,
        "kms",
        "DisableKey",
        json!({"KeyId":key_id}),
    )
    .await;
    error(
        call(&client, &server, region, "dynamodb", "GetItem", get).await,
        "AccessDeniedException",
    );
    ok(
        &client,
        &server,
        region,
        "dynamodb",
        "DescribeTable",
        json!({"TableName":"encrypted"}),
    )
    .await;
    ok(
        &client,
        &server,
        region,
        "dynamodb",
        "DeleteTable",
        json!({"TableName":"encrypted"}),
    )
    .await;
    error(
        call(
            &client,
            &server,
            region,
            "dynamodb",
            "DescribeTable",
            json!({"TableName":"encrypted"}),
        )
        .await,
        "ResourceNotFoundException",
    );
    ok(
        &client,
        &server,
        region,
        "dynamodb",
        "CreateTable",
        create("encrypted", None),
    )
    .await;
    let reused = active(&client, &server, region, "encrypted").await;
    assert_ne!(reused["SSEDescription"]["KMSMasterKeyArn"], key_arn);
    assert!(ok(
        &client,
        &server,
        region,
        "dynamodb",
        "GetItem",
        json!({"TableName":"encrypted","Key":{"pk":{"S":"durable"}}})
    )
    .await
    .get("Item")
    .is_none());
    for (region, name) in [
        (region, "encrypted"),
        (region, "plain"),
        (west, "encrypted"),
    ] {
        ok(
            &client,
            &server,
            region,
            "dynamodb",
            "DeleteTable",
            json!({"TableName":name}),
        )
        .await;
    }
    server.stop().await;
    tokio::fs::remove_dir_all(&dir)
        .await
        .expect("remove private fixture");
    println!("Real public SSE lifecycle: passed");
}
