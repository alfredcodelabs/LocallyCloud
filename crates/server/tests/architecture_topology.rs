//! Black-box check of the architecture view: the real binary on a port-zero listener, with
//! throwaway state, cache and AWS configuration, deploys a stack through the CloudFormation
//! API and reads its topology through the dashboard endpoint.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

/// Test-only master key for a throwaway state database.
const TEST_MASTER_KEY: &str = "dGhyb3dhd2F5LWFyY2hpdGVjdHVyZS10ZXN0LWtleSE=";
const STACK: &str = "architecture-review";

struct Server {
    child: Child,
    endpoint: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn isolated_dir() -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("architecture-topology-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("home")).unwrap();
    // The server refuses a state directory other users can read.
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
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
        .env("LOCALLYCLOUD_KMS_MASTER_KEY", TEST_MASTER_KEY)
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
    .expect("server readiness");
    Server { child, endpoint }
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

async fn cloudformation(
    client: &reqwest::Client,
    endpoint: &str,
    pairs: &[(&str, &str)],
) -> String {
    let mut all = vec![("Version", "2010-05-15")];
    all.extend_from_slice(pairs);
    let response = client
        .post(format!("{endpoint}/"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=test/20240101/us-east-1/cloudformation/aws4_request, \
             SignedHeaders=host, Signature=0",
        )
        .body(form(&all))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "{status}: {body}");
    body
}

fn xml_text<'a>(body: &'a str, element: &str) -> Option<&'a str> {
    let (_, rest) = body.split_once(&format!("<{element}>"))?;
    rest.split_once(&format!("</{element}>"))
        .map(|(text, _)| text)
}

async fn topology(client: &reqwest::Client, endpoint: &str, stack: &str) -> (u16, Value) {
    let response = client
        .post(format!(
            "{endpoint}/_locallycloud/views/architecture/topology"
        ))
        .header("x-locallycloud-dashboard", "1")
        .json(&serde_json::json!({ "stack": stack }))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn deployed_stack_topology_through_the_dashboard_endpoint() {
    let dir = isolated_dir();
    let server = start(&dir).await;
    let client = reqwest::Client::new();
    let template = serde_json::json!({"Resources": {
        "Inbox": {"Type": "AWS::SQS::Queue"},
        "Bus": {"Type": "AWS::Events::EventBus", "Properties": {"Name": "architecture-review-bus"}},
        "Deliver": {"Type": "AWS::Events::Rule", "Properties": {
            "EventBusName": {"Ref": "Bus"},
            "EventPattern": {"source": ["architecture-review"]},
            "Targets": [{"Id": "queue", "Arn": {"Fn::GetAtt": ["Inbox", "Arn"]}}]
        }}
    }})
    .to_string();
    cloudformation(
        &client,
        &server.endpoint,
        &[
            ("Action", "CreateStack"),
            ("StackName", STACK),
            ("TemplateBody", &template),
        ],
    )
    .await;
    let mut status = String::new();
    for _ in 0..200 {
        let body = cloudformation(
            &client,
            &server.endpoint,
            &[("Action", "DescribeStacks"), ("StackName", STACK)],
        )
        .await;
        status = xml_text(&body, "StackStatus")
            .unwrap_or_default()
            .to_owned();
        if !status.ends_with("_IN_PROGRESS") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(status, "CREATE_COMPLETE");

    let (code, model) = topology(&client, &server.endpoint, STACK).await;
    assert_eq!(code, 200, "{model}");
    assert_eq!(model["version"], 1);
    assert_eq!(model["documentType"], "snapshot");
    assert_eq!(model["source"], "snapshot");
    assert_eq!(model["title"], STACK);
    assert_eq!(model["scope"]["region"], "us-east-1");
    assert_eq!(model["scope"]["account"], "000000000000");
    assert!(model["id"]
        .as_str()
        .unwrap()
        .starts_with("arn:aws:cloudformation:us-east-1:000000000000:stack/architecture-review/"));
    let nodes = model["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 3, "{model}");
    assert!(
        nodes
            .iter()
            .all(|n| n["status"] == "CREATE_COMPLETE"
                && !n["physicalId"].as_str().unwrap().is_empty())
    );
    let edge = |kind: &str, from: &str, to: &str| {
        model["edges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == kind && e["from"] == from && e["to"] == to)
    };
    assert!(edge("configured", "Deliver", "Inbox"), "{model}");
    assert!(edge("configured", "Bus", "Deliver"), "{model}");
    assert!(edge("dependency", "Inbox", "Deliver"), "{model}");
    assert!(edge("dependency", "Bus", "Deliver"), "{model}");
    assert!(!model.to_string().contains("EventPattern"));
    assert!(!model
        .to_string()
        .contains("\"source\":[\"architecture-review\"]"));

    let (code, missing) = topology(&client, &server.endpoint, "no-such-stack").await;
    assert_eq!(code, 404, "{missing}");

    drop(server);
    let _ = tokio::fs::remove_dir_all(&dir).await;
}
