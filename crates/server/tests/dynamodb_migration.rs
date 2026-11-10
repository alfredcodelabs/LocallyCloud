//! Offline native PITR cutover and historical restores with an explicitly supplied worker.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use locallycloud_state::{StateCipher, StateDb};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::{Child, Command};

const ACCOUNT: &str = "000000000000";
const REGIONS: [&str; 2] = ["us-east-1", "us-east-2"];
const MASTER_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

#[derive(Clone, Copy)]
struct Timeline {
    started: f64,
    changed: f64,
    deleted: f64,
    latest: f64,
}

fn command(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_locallycloud"));
    command
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
        .env("LOCALLYCLOUD_KMS_MASTER_KEY", MASTER_KEY)
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
        .kill_on_drop(true);
    command
}

async fn migrate(dir: &Path, normalize: bool) -> Output {
    let mut command = command(dir);
    command.args(["migrate-dynamodb", "--apply"]);
    if normalize {
        command.arg("--normalize-legacy-aes256");
    }
    let mut child = command.spawn().expect("spawn migration CLI");
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let collect = |stream: Box<dyn tokio::io::AsyncRead + Send + Unpin>| {
        tokio::spawn(async move {
            let mut bytes = Vec::new();
            stream
                .take(1024 * 1024)
                .read_to_end(&mut bytes)
                .await
                .unwrap();
            bytes
        })
    };
    let stdout = collect(Box::new(stdout));
    let stderr = collect(Box::new(stderr));
    let status = match tokio::time::timeout(Duration::from_secs(180), child.wait()).await {
        Ok(status) => status.expect("reap migration CLI"),
        Err(_) => {
            child
                .kill()
                .await
                .expect("kill and reap timed-out migration");
            panic!("migration CLI timed out");
        }
    };
    Output {
        status,
        stdout: stdout.await.unwrap(),
        stderr: stderr.await.unwrap(),
    }
}

fn successful(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("migration completion JSON")
}

async fn fixture(worker: PathBuf) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("native-pitr-migration-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    tokio::fs::create_dir(dir.join("home")).await.unwrap();
    let bytes = tokio::fs::read(worker).await.expect("read actual worker");
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

fn encoded(cipher: &StateCipher, encrypted: bool, context: &[&str], value: &Value) -> String {
    let text = value.to_string();
    if !encrypted {
        return text;
    }
    format!(
        "dynamodb-sealed-v1:{}",
        base64::engine::general_purpose::STANDARD
            .encode(cipher.seal(context, text.as_bytes()).unwrap())
    )
}

fn native_fixture(path: PathBuf, timeline: Timeline) {
    let state = StateDb::open(path).unwrap();
    let connection = state.connection().unwrap();
    connection.execute_batch(
        "CREATE TABLE locallycloud_service_engines(service TEXT PRIMARY KEY,engine TEXT NOT NULL);
         INSERT INTO locallycloud_service_engines VALUES('dynamodb','native');
         CREATE TABLE iam_resources(account TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(account,kind,name));
         CREATE TABLE dynamodb_tables(account TEXT NOT NULL,region TEXT NOT NULL,name TEXT NOT NULL,metadata TEXT NOT NULL,PRIMARY KEY(account,region,name));
         CREATE TABLE dynamodb_items(account TEXT NOT NULL,region TEXT NOT NULL,name TEXT NOT NULL,item_key TEXT NOT NULL,item TEXT NOT NULL,PRIMARY KEY(account,region,name,item_key));
         CREATE TABLE dynamodb_recovery(account TEXT NOT NULL,region TEXT NOT NULL,name TEXT NOT NULL,enabled INTEGER NOT NULL,started REAL NOT NULL,latest REAL NOT NULL,days INTEGER NOT NULL,PRIMARY KEY(account,region,name));
         CREATE TABLE dynamodb_recovery_items(account TEXT NOT NULL,region TEXT NOT NULL,name TEXT NOT NULL,item_key TEXT NOT NULL,at REAL NOT NULL,item TEXT,PRIMARY KEY(account,region,name,item_key,at));",
    ).unwrap();
    let cipher = StateCipher::with_key(&[0; 32]);
    let evidence = cipher
        .seal(
            &["iam", ACCOUNT, "global", "bootstrap", "initialized"],
            b"true",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO iam_resources VALUES(?1,'bootstrap','initialized',?2)",
            (ACCOUNT, evidence),
        )
        .unwrap();
    for (region, name, enabled, encrypted) in [
        (REGIONS[0], "history-source", true, false),
        (REGIONS[1], "history-source", true, false),
        (REGIONS[0], "frozen-history", false, false),
        (REGIONS[0], "legacy-history", true, true),
    ] {
        let metadata = json!({"def":{"sse_type":if encrypted {Some("AES256")} else {None},
            "name":name,"arn":format!("arn:aws:dynamodb:{region}:{ACCOUNT}:table/{name}"),
            "key_schema":[{"name":"pk","key_type":"Hash"}],"attribute_definitions":[{"name":"pk","attr_type":"S"}],
            "indexes":[{"name":"lookup","key_schema":[{"name":"pk","key_type":"Hash"}],"projection":{"projection_type":"All","non_key_attributes":[]},"global":true,"read_capacity":0,"write_capacity":0,"warm_throughput":null}],
            "billing_mode":"PAY_PER_REQUEST","read_capacity":0,"write_capacity":0,"warm_throughput":null,
            "stream_spec":null,"creation_date":"1","status":"ACTIVE","replicas":[]},
            "persist_id":"fixture","tags":{"review":"native-history"},"ttl_attribute":null,"pitr_enabled":enabled,"stream_seq":0,
            "kinesis_destinations":[],"kinesis_pending":[],"exports":[],"replica_pending":[]});
        let metadata = encoded(
            &cipher,
            encrypted,
            &["dynamodb-metadata", ACCOUNT, region, name],
            &metadata,
        );
        connection
            .execute(
                "INSERT INTO dynamodb_tables VALUES(?1,?2,?3,?4)",
                (ACCOUNT, region, name, metadata),
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO dynamodb_recovery VALUES(?1,?2,?3,?4,?5,?6,7)",
                (
                    ACCOUNT,
                    region,
                    name,
                    i64::from(enabled),
                    timeline.started,
                    timeline.latest,
                ),
            )
            .unwrap();
        for (key, value, at, current) in [
            ("kept", Some("kept"), timeline.started, true),
            ("changed", Some("old"), timeline.started, false),
            ("changed", Some("new"), timeline.changed, true),
            ("removed", Some("removed"), timeline.started, false),
            ("removed", None, timeline.deleted, false),
        ] {
            let saved_key = json!({"partition":{"S":key},"sort":null}).to_string();
            let item = value.map(|value| {
                encoded(
                    &cipher,
                    encrypted,
                    &["dynamodb-item", ACCOUNT, region, name, &saved_key],
                    &json!({"pk":{"S":key},"value":{"S":format!("{region}:{value}")}}),
                )
            });
            if current {
                connection
                    .execute(
                        "INSERT INTO dynamodb_items VALUES(?1,?2,?3,?4,?5)",
                        (ACCOUNT, region, name, &saved_key, item.as_ref().unwrap()),
                    )
                    .unwrap();
            }
            connection
                .execute(
                    "INSERT INTO dynamodb_recovery_items VALUES(?1,?2,?3,?4,?5,?6)",
                    (ACCOUNT, region, name, saved_key, at, item),
                )
                .unwrap();
        }
    }
}

async fn source_rows(dir: &Path) -> Vec<Value> {
    let path = dir.join("state.sqlite3");
    tokio::task::spawn_blocking(move || {
        let state = StateDb::open(path).unwrap();
        let connection = state.connection().unwrap();
        let mut values = Vec::new();
        let mut query = connection.prepare("SELECT account,region,name,metadata FROM dynamodb_tables ORDER BY account,region,name").unwrap();
        let rows = query.query_map([], |row| Ok(json!(["table",row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?]))).unwrap();
        values.extend(rows.map(Result::unwrap));
        let mut query = connection.prepare("SELECT account,region,name,item_key,item FROM dynamodb_items ORDER BY account,region,name,item_key").unwrap();
        let rows = query.query_map([], |row| Ok(json!(["item",row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?]))).unwrap();
        values.extend(rows.map(Result::unwrap));
        let mut query = connection.prepare("SELECT account,region,name,enabled,started,latest,days FROM dynamodb_recovery ORDER BY account,region,name").unwrap();
        let rows = query.query_map([], |row| Ok(json!(["window",row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,i64>(3)?,row.get::<_,f64>(4)?.to_bits(),row.get::<_,f64>(5)?.to_bits(),row.get::<_,i64>(6)?]))).unwrap();
        values.extend(rows.map(Result::unwrap));
        let mut query = connection.prepare("SELECT account,region,name,item_key,at,item FROM dynamodb_recovery_items ORDER BY account,region,name,item_key,at").unwrap();
        let rows = query.query_map([], |row| Ok(json!(["version",row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,f64>(4)?.to_bits(),row.get::<_,Option<String>>(5)?]))).unwrap();
        values.extend(rows.map(Result::unwrap));
        values
    }).await.unwrap()
}

async fn binding(dir: &Path) -> String {
    let path = dir.join("state.sqlite3");
    tokio::task::spawn_blocking(move || {
        StateDb::open(path)
            .unwrap()
            .connection()
            .unwrap()
            .query_row(
                "SELECT engine FROM locallycloud_service_engines WHERE service='dynamodb'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    })
    .await
    .unwrap()
}

fn sibling(dir: &Path, suffix: &str) -> PathBuf {
    dir.join(format!("state.sqlite3{suffix}"))
}

async fn exists(path: &Path) -> bool {
    tokio::fs::try_exists(path).await.unwrap()
}

async fn journal(dir: &Path, phase: &str) -> PathBuf {
    let stage = format!("state.sqlite3.extenddb-migration-{}", uuid::Uuid::new_v4());
    let marker = sibling(dir, ".dynamodb-migration.json");
    tokio::fs::write(
        &marker,
        json!({"schema":1,"stage":stage,"phase":phase,"normalize_legacy_aes256":true}).to_string(),
    )
    .await
    .unwrap();
    tokio::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o600))
        .await
        .unwrap();
    dir.join(stage)
}

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
    }
}

async fn start(dir: &Path) -> Server {
    let mut child = command(dir).spawn().expect("spawn migrated server");
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    for stream in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stream).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx.send(line).await;
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
            if seen.len() < 64 {
                seen.push(line);
            }
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
    operation: &str,
    body: Value,
) -> (u16, Value) {
    let response = client.post(format!("{}/",server.endpoint))
        .header("content-type","application/x-amz-json-1.0")
        .header("x-amz-target",format!("DynamoDB_20120810.{operation}"))
        .header("authorization",format!("AWS4-HMAC-SHA256 Credential=test/20240101/{region}/dynamodb/aws4_request, SignedHeaders=host, Signature=0"))
        .json(&body).send().await.expect("DynamoDB HTTP response");
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap();
    let value = serde_json::from_slice(&bytes).expect("DynamoDB JSON response");
    (status, value)
}

async fn ok(
    client: &reqwest::Client,
    server: &Server,
    region: &str,
    operation: &str,
    body: Value,
) -> Value {
    let (status, value) = call(client, server, region, operation, body).await;
    assert_eq!(status, 200, "{operation}: {value}");
    value
}

async fn active(client: &reqwest::Client, server: &Server, region: &str, name: &str) {
    for _ in 0..300 {
        let table = ok(
            client,
            server,
            region,
            "DescribeTable",
            json!({"TableName":name}),
        )
        .await;
        if table["Table"]["TableStatus"] == "ACTIVE"
            && table["Table"]["GlobalSecondaryIndexes"]
                .as_array()
                .into_iter()
                .flatten()
                .all(|index| index["IndexStatus"] == "ACTIVE")
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("restored table did not become ACTIVE");
}

async fn get(
    client: &reqwest::Client,
    server: &Server,
    region: &str,
    table: &str,
    key: &str,
) -> Value {
    ok(
        client,
        server,
        region,
        "GetItem",
        json!({"TableName":table,"Key":{"pk":{"S":key}},"ConsistentRead":true}),
    )
    .await
}

async fn restored(
    client: &reqwest::Client,
    server: &Server,
    region: &str,
    source: &str,
    target: &str,
    at: f64,
    expected: (&str, bool),
) {
    let (expected, removed) = expected;
    ok(
        client,
        server,
        region,
        "RestoreTableToPointInTime",
        json!({"SourceTableName":source,"TargetTableName":target,"RestoreDateTime":at}),
    )
    .await;
    active(client, server, region, target).await;
    let item = get(client, server, region, target, "changed").await;
    assert_eq!(item["Item"]["value"]["S"], format!("{region}:{expected}"));
    let item = get(client, server, region, target, "removed").await;
    assert_eq!(item.get("Item").is_none(), removed, "{item}");
    for _ in 0..100 {
        let query=ok(client,server,region,"Query",json!({"TableName":target,"IndexName":"lookup","KeyConditionExpression":"#pk = :pk","ExpressionAttributeNames":{"#pk":"pk"},"ExpressionAttributeValues":{":pk":{"S":"changed"}}})).await;
        if query["Count"] == 1 && query["Items"][0]["value"]["S"] == format!("{region}:{expected}")
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("restored index did not project the historical value");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_pitr_cutover_preserves_exact_history_and_recovers_durable_intents() {
    let Some(worker) = std::env::var_os("LOCALLYCLOUD_TEST_TABLE_WORKER") else {
        eprintln!("Set LOCALLYCLOUD_TEST_TABLE_WORKER to validate real native PITR migration");
        return;
    };
    let dir = fixture(PathBuf::from(worker)).await;
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
        .floor()
        - 120.0
        + 0.125;
    let timeline = Timeline {
        started,
        changed: f64::from_bits(started.to_bits() + 1),
        deleted: f64::from_bits(started.to_bits() + 2),
        latest: started + 5.0,
    };
    assert!(timeline.changed - timeline.started < 0.000001);
    let path = dir.join("state.sqlite3");
    tokio::task::spawn_blocking(move || native_fixture(path, timeline))
        .await
        .unwrap();

    let original = source_rows(&dir).await;
    let rejected = migrate(&dir, false).await;
    assert!(
        !rejected.status.success(),
        "legacy encryption requires explicit consent"
    );
    assert_eq!(binding(&dir).await, "native");
    assert_eq!(source_rows(&dir).await, original);
    assert!(!exists(&sibling(&dir, ".dynamodb-migration.json")).await);
    assert!(!exists(&sibling(&dir, ".extenddb")).await);

    let path = dir.join("state.sqlite3");
    tokio::task::spawn_blocking(move || StateDb::open(path).unwrap().connection().unwrap().execute("UPDATE dynamodb_recovery SET latest=-1 WHERE region='us-east-1' AND name='history-source'",[]).unwrap()).await.unwrap();
    let corrupted = source_rows(&dir).await;
    let rejected = migrate(&dir, true).await;
    assert!(
        !rejected.status.success(),
        "malformed history must block cutover"
    );
    assert_eq!(binding(&dir).await, "native");
    assert_eq!(source_rows(&dir).await, corrupted);
    assert!(!exists(&sibling(&dir, ".dynamodb-migration.json")).await);
    assert!(!exists(&sibling(&dir, ".extenddb")).await);
    let path = dir.join("state.sqlite3");
    tokio::task::spawn_blocking(move || StateDb::open(path).unwrap().connection().unwrap().execute("UPDATE dynamodb_recovery SET latest=?1 WHERE region='us-east-1' AND name='history-source'",[timeline.latest]).unwrap()).await.unwrap();

    let stage = journal(&dir, "copying").await;
    tokio::fs::create_dir(&stage).await.unwrap();
    tokio::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    tokio::fs::write(stage.join("uncommitted"), b"interrupted copy")
        .await
        .unwrap();
    tokio::fs::set_permissions(
        stage.join("uncommitted"),
        std::fs::Permissions::from_mode(0o600),
    )
    .await
    .unwrap();
    let completion = successful(migrate(&dir, true).await);
    assert_eq!(completion["kind"], "migration-complete");
    assert_eq!(completion["engine"], "extenddb");
    assert_eq!(completion["nativeRowsRetained"], true);
    assert_eq!(binding(&dir).await, "extenddb");
    assert_eq!(source_rows(&dir).await, original);
    assert!(!exists(&stage).await);
    assert!(!exists(&sibling(&dir, ".dynamodb-migration.json")).await);

    // A crash after binding but before removing the verified journal must reverify,
    // rather than copy native state over the already-published database.
    let stage = journal(&dir, "verified").await;
    assert!(!exists(&stage).await);
    successful(migrate(&dir, true).await);
    assert!(!exists(&sibling(&dir, ".dynamodb-migration.json")).await);
    assert_eq!(source_rows(&dir).await, original);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let mut server = start(&dir).await;
    for region in REGIONS {
        let descriptor = ok(
            &client,
            &server,
            region,
            "DescribeContinuousBackups",
            json!({"TableName":"history-source"}),
        )
        .await;
        let recovery =
            &descriptor["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"];
        assert_eq!(recovery["PointInTimeRecoveryStatus"], "ENABLED");
        assert_eq!(recovery["RecoveryPeriodInDays"], 7);
        assert_eq!(
            recovery["EarliestRestorableDateTime"].as_f64(),
            Some(timeline.started)
        );
        assert_eq!(
            get(&client, &server, region, "history-source", "changed").await["Item"]["value"]["S"],
            format!("{region}:new")
        );
        restored(
            &client,
            &server,
            region,
            "history-source",
            "before-write",
            f64::from_bits(timeline.changed.to_bits() - 1),
            ("old", false),
        )
        .await;
        restored(
            &client,
            &server,
            region,
            "history-source",
            "at-write",
            timeline.changed,
            ("new", false),
        )
        .await;
        restored(
            &client,
            &server,
            region,
            "history-source",
            "at-delete",
            timeline.deleted,
            ("new", true),
        )
        .await;
    }
    restored(
        &client,
        &server,
        REGIONS[0],
        "legacy-history",
        "legacy-restored",
        timeline.started,
        ("old", false),
    )
    .await;
    let frozen_description = ok(
        &client,
        &server,
        REGIONS[0],
        "DescribeContinuousBackups",
        json!({"TableName":"frozen-history"}),
    )
    .await;
    assert_eq!(
        frozen_description["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]
            ["PointInTimeRecoveryStatus"],
        "DISABLED"
    );
    let (status,frozen)=call(&client,&server,REGIONS[0],"RestoreTableToPointInTime",json!({"SourceTableName":"frozen-history","TargetTableName":"frozen-target","RestoreDateTime":timeline.started})).await;
    assert_eq!(status, 400, "{frozen}");
    assert!(
        frozen["__type"]
            .as_str()
            .unwrap()
            .ends_with("PointInTimeRecoveryUnavailableException"),
        "{frozen}"
    );
    ok(&client,&server,REGIONS[0],"PutItem",json!({"TableName":"history-source","Item":{"pk":{"S":"changed"},"value":{"S":"after-cutover"}}})).await;
    server.stop().await;
    let mut server = start(&dir).await;
    restored(
        &client,
        &server,
        REGIONS[0],
        "history-source",
        "after-restart",
        timeline.started,
        ("old", false),
    )
    .await;
    ok(&client,&server,REGIONS[0],"RestoreTableToPointInTime",json!({"SourceTableName":"history-source","TargetTableName":"latest-restored","UseLatestRestorableTime":true})).await;
    active(&client, &server, REGIONS[0], "latest-restored").await;
    assert_eq!(
        get(&client, &server, REGIONS[0], "latest-restored", "changed").await["Item"]["value"]["S"],
        "after-cutover"
    );
    server.stop().await;
    assert_eq!(source_rows(&dir).await, original);
    tokio::fs::remove_dir_all(&dir).await.unwrap();
    eprintln!("Real native PITR migration: passed");
}
