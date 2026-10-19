//! Public HTTP ingestion gates using the real Core front door and native workers.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::response::Response;
use base64::Engine;
use bytes::Bytes;
use locallycloud_core::config::LocallyCloudConfig;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::{
    AuthorizationError, AuthorizationEvaluator, AuthorizationRequest,
    ServiceRoleAuthorizationRequest,
};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use locallycloud_core::server::LocallyCloudServer;
use serde_json::{json, Value};
use tokio::sync::{oneshot, Barrier, Notify};

use crate::commit_test::{pointer, read_physical_rows, ConcurrentReads, FailOnce, Fixture, Stage};

struct WireServer {
    base: String,
    client: reqwest::Client,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), locallycloud_core::server::ServerError>>,
    firehose: crate::FirehoseHandle,
}

impl WireServer {
    async fn start(registry: Arc<ServiceRegistry>) -> Self {
        let firehose = crate::register(&registry);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = LocallyCloudConfig::resolve(&|key| match key {
            "LOCALLYCLOUD_UI" => Some("off".into()),
            "LOCALLYCLOUD_LEGACY_BACKEND_URL" => Some("http://127.0.0.1:1".into()),
            _ => None,
        })
        .unwrap();
        let (shutdown, stop) = oneshot::channel();
        let (ready, started) = oneshot::channel();
        let task = tokio::spawn(LocallyCloudServer::new(config, registry).run_on_listener(
            listener,
            async move {
                let _ = stop.await;
            },
            move || {
                ready.send(()).unwrap();
            },
        ));
        tokio::time::timeout(Duration::from_secs(10), started)
            .await
            .unwrap()
            .unwrap();
        Self {
            base: format!("http://{address}"),
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap(),
            shutdown,
            task,
            firehose,
        }
    }

    async fn send(&self, target: &str, body: Value) -> (reqwest::StatusCode, Value) {
        let service = match target.split('.').next().unwrap() {
            "Firehose_20150804" => "firehose",
            "AWSGlue" => "glue",
            "AmazonAthena" => "athena",
            "Logs_20140328" => "logs",
            _ => panic!("unknown test service"),
        };
        let response = self
            .client
            .post(&self.base)
            .header("x-amz-target", target)
            .header("content-type", "application/x-amz-json-1.1")
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential=test/19700101/us-east-1/{service}/aws4_request"
                ),
            )
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.bytes().await.unwrap();
        let value = if bytes.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    async fn call(&self, target: &str, body: Value) -> Value {
        let (status, value) = self.send(target, body).await;
        assert!(status.is_success(), "{target}: {status}: {value}");
        value
    }

    async fn get(&self, uri: &str) -> Bytes {
        let path = uri.strip_prefix("s3:/").unwrap();
        let response = self
            .client
            .get(format!("{}{path}", self.base))
            .header(
                "authorization",
                "AWS4-HMAC-SHA256 Credential=test/19700101/us-east-1/s3/aws4_request",
            )
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "GET {uri}");
        response.bytes().await.unwrap()
    }

    async fn create_stream(&self, name: &str) {
        self.create_stream_with_policy(name, 0, 300).await;
    }

    async fn create_stream_with_policy(&self, name: &str, interval: u32, retry: u32) {
        self.call(
            "Firehose_20150804.CreateDeliveryStream",
            Self::stream_config(name, interval, retry),
        )
        .await;
    }

    fn stream_config(name: &str, interval: u32, retry: u32) -> Value {
        let role = "arn:aws:iam::000000000000:role/firehose";
        json!({"DeliveryStreamName":name,"IcebergDestinationConfiguration":{"AppendOnly":true,
            "BufferingHints":{"SizeInMBs":1,"IntervalInSeconds":interval},"RetryOptions":{"DurationInSeconds":retry},
            "CatalogConfiguration":{"CatalogARN":"arn:aws:glue:us-east-1:000000000000:catalog"},
            "RoleARN":role,"S3Configuration":{"RoleARN":role,"BucketARN":"arn:aws:s3:::ack-loss-lake"},
            "DestinationTableConfigurationList":[{"DestinationDatabaseName":"lake","DestinationTableName":"events"}]}})
    }

    async fn backup_keys(&self) -> Vec<String> {
        let xml = String::from_utf8(
            self.get("s3://ack-loss-lake/?prefix=errors/")
                .await
                .to_vec(),
        )
        .unwrap();
        xml.split("<Key>")
            .skip(1)
            .map(|s| s.split("</Key>").next().unwrap().to_owned())
            .collect()
    }

    async fn wait_backup(&self, name: &str) -> Value {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let d = self
                    .call(
                        "Firehose_20150804.DescribeDeliveryStream",
                        json!({"DeliveryStreamName":name}),
                    )
                    .await;
                if d["DeliveryStreamDescription"]["LocallyCloudBackup"]["BackedUpRecordCount"] == 1
                {
                    return d;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn put(&self, name: &str, id: i64, batch: bool) {
        let record = json!({"Data":base64::engine::general_purpose::STANDARD.encode(json!({"id":id,"payload":format!("row-{id}")}).to_string())});
        let value = if batch {
            let value = self
                .call(
                    "Firehose_20150804.PutRecordBatch",
                    json!({"DeliveryStreamName":name,"Records":[record]}),
                )
                .await;
            assert_eq!(value["FailedPutCount"], 0);
            value["RequestResponses"][0].clone()
        } else {
            self.call(
                "Firehose_20150804.PutRecord",
                json!({"DeliveryStreamName":name,"Record":record}),
            )
            .await
        };
        assert!(!value["RecordId"].as_str().unwrap().is_empty());
    }

    async fn table(&self) -> Value {
        self.call(
            "AWSGlue.GetTable",
            json!({"DatabaseName":"lake","Name":"events"}),
        )
        .await
    }

    async fn rows(&self) -> Vec<(i64, String)> {
        let id = self.call("AmazonAthena.StartQueryExecution", json!({
            "QueryString":"SELECT id, payload FROM lake.events", "QueryExecutionContext":{"Database":"lake"},
            "ResultConfiguration":{"OutputLocation":"s3://ack-loss-lake/results/"}})).await["QueryExecutionId"].as_str().unwrap().to_owned();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let execution = self
                    .call(
                        "AmazonAthena.GetQueryExecution",
                        json!({"QueryExecutionId":id}),
                    )
                    .await;
                match execution["QueryExecution"]["Status"]["State"]
                    .as_str()
                    .unwrap()
                {
                    "SUCCEEDED" => break,
                    "FAILED" | "CANCELLED" => panic!("query failed: {execution}"),
                    _ => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .unwrap();
        let result = self
            .call(
                "AmazonAthena.GetQueryResults",
                json!({"QueryExecutionId":id}),
            )
            .await;
        let mut rows: Vec<_> = result["ResultSet"]["Rows"]
            .as_array()
            .unwrap()
            .iter()
            .skip(1)
            .map(|r| {
                (
                    r["Data"][0]["VarCharValue"]
                        .as_str()
                        .unwrap()
                        .parse::<i64>()
                        .unwrap(),
                    r["Data"][1]["VarCharValue"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        rows.sort();
        rows
    }

    async fn wait_rows(&self, expected: &[(i64, String)]) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if self.rows().await == expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn drain_delete(&self, name: &str) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let (status, value) = self
                    .send(
                        "Firehose_20150804.DeleteDeliveryStream",
                        json!({"DeliveryStreamName":name}),
                    )
                    .await;
                if status.is_success() {
                    break;
                }
                assert_eq!(value["__type"], "ResourceInUseException");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn stop(self) {
        self.firehose.shutdown().await;
        self.shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

struct HoldFailure {
    inner: Arc<dyn NativeHandler>,
    ready: Notify,
    release: Notify,
}

#[async_trait]
impl NativeHandler for HoldFailure {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let response = self.inner.handle(request).await;
        if response.status() == 503 {
            self.ready.notify_one();
            self.release.notified().await;
        }
        response
    }
}

#[tokio::test]
async fn http_firehose_workers_retry_real_catalog_conflict_and_preserve_both_batches() {
    let fixture = Fixture::new().await;
    let second_registry = ServiceRegistry::with_known_services();
    for service in ["s3", "glue", "athena"] {
        let name = ServiceName::new(service);
        let shared = fixture.registry.lookup(&name).unwrap();
        second_registry.register_native(name, shared.metadata, shared.handler.unwrap());
    }
    let first = WireServer::start(fixture.registry.clone()).await;
    let second = WireServer::start(second_registry.clone()).await;
    first.create_stream("writer-a").await;
    second.create_stream("writer-b").await;
    let original = fixture.registry.lookup(&ServiceName::new("glue")).unwrap();
    let gate = Arc::new(ConcurrentReads {
        inner: original.handler.unwrap(),
        barrier: Barrier::new(2),
        reads: AtomicUsize::new(0),
        conflicts: AtomicUsize::new(0),
        versions: Mutex::new(Vec::new()),
    });
    for registry in [&fixture.registry, &second_registry] {
        registry.register_native(
            ServiceName::new("glue"),
            original.metadata.clone(),
            gate.clone(),
        );
    }
    tokio::join!(
        first.put("writer-a", 1, false),
        second.put("writer-b", 2, true)
    );
    // Keep observer queries out of the first two catalog reads used by the gate.
    tokio::time::timeout(Duration::from_secs(8), async {
        while gate.reads.load(Ordering::Acquire) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let expected = [
        (0, "row-0".into()),
        (1, "row-1".into()),
        (2, "row-2".into()),
    ];
    first.wait_rows(&expected).await;
    first.drain_delete("writer-a").await;
    second.drain_delete("writer-b").await;
    assert_eq!(*gate.versions.lock().unwrap(), ["2", "2"]);
    assert_eq!(gate.conflicts.load(Ordering::Acquire), 1);
    let table = first.table().await;
    let (metadata, physical) =
        read_physical_rows(async |uri| first.get(uri).await, pointer(&table)).await;
    assert_eq!(physical, expected);
    assert_eq!(metadata["snapshots"].as_array().unwrap().len(), 3);
    assert_eq!(metadata["last-sequence-number"], 3);
    first.stop().await;
    second.stop().await;
}

#[tokio::test]
async fn http_ingestion_recovers_each_publication_fault_without_partial_snapshots() {
    for stage in [
        Stage::Data,
        Stage::Manifest,
        Stage::ManifestList,
        Stage::Metadata,
        Stage::Catalog,
    ] {
        for after_write in [false, true] {
            let fixture = Fixture::new().await;
            let wire = WireServer::start(fixture.registry.clone()).await;
            wire.create_stream("fault-stream").await;
            let previous = wire.table().await;
            let service = ServiceName::new(if stage == Stage::Catalog {
                "glue"
            } else {
                "s3"
            });
            let original = fixture.registry.lookup(&service).unwrap();
            let fault = Arc::new(FailOnce {
                inner: original.handler.unwrap(),
                stage,
                after_write,
                fired: AtomicBool::new(false),
            });
            let held = Arc::new(HoldFailure {
                inner: fault.clone(),
                ready: Notify::new(),
                release: Notify::new(),
            });
            fixture
                .registry
                .register_native(service, original.metadata, held.clone());
            wire.put("fault-stream", 1, after_write).await;
            tokio::time::timeout(Duration::from_secs(8), held.ready.notified())
                .await
                .unwrap();
            assert!(fault.fired.load(Ordering::Acquire));
            let failed = wire.table().await;
            let expected_before_retry = if stage == Stage::Catalog && after_write {
                assert_ne!(pointer(&failed), pointer(&previous));
                vec![(0, "row-0".into()), (1, "row-1".into())]
            } else {
                assert_eq!(failed, previous);
                vec![(0, "row-0".into())]
            };
            assert_eq!(wire.rows().await, expected_before_retry);
            assert_eq!(
                read_physical_rows(async |uri| wire.get(uri).await, pointer(&previous))
                    .await
                    .1,
                [(0, "row-0".into())]
            );
            held.release.notify_one();
            let expected = [(0, "row-0".into()), (1, "row-1".into())];
            wire.wait_rows(&expected).await;
            wire.drain_delete("fault-stream").await;
            let table = wire.table().await;
            let (metadata, physical) =
                read_physical_rows(async |uri| wire.get(uri).await, pointer(&table)).await;
            assert_eq!(physical, expected);
            assert_eq!(metadata["snapshots"].as_array().unwrap().len(), 2);
            wire.stop().await;
        }
    }
}

#[tokio::test]
async fn http_buffering_is_per_stream_and_timer_flushes_without_more_ingestion() {
    let fixture = Fixture::new().await;
    let wire = WireServer::start(fixture.registry.clone()).await;
    wire.create_stream_with_policy("slow", 900, 300).await;
    wire.create_stream("fast").await;
    wire.put("slow", 1, false).await;
    wire.put("fast", 2, true).await;
    wire.wait_rows(&[(0, "row-0".into()), (2, "row-2".into())])
        .await;
    let description = wire
        .call(
            "Firehose_20150804.DescribeDeliveryStream",
            json!({"DeliveryStreamName":"slow"}),
        )
        .await;
    let destination = &description["DeliveryStreamDescription"]["Destinations"][0]
        ["IcebergDestinationDescription"];
    assert_eq!(destination["BufferingHints"]["IntervalInSeconds"], 900);
    assert_eq!(destination["RetryOptions"]["DurationInSeconds"], 300);
    let (status, value) = wire
        .send(
            "Firehose_20150804.DeleteDeliveryStream",
            json!({"DeliveryStreamName":"slow"}),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(value["__type"], "ResourceInUseException");
    wire.create_stream_with_policy("timer", 1, 300).await;
    let before = std::time::Instant::now();
    wire.put("timer", 3, false).await;
    wire.wait_rows(&[
        (0, "row-0".into()),
        (2, "row-2".into()),
        (3, "row-3".into()),
    ])
    .await;
    assert!(before.elapsed() >= Duration::from_secs(1));
    wire.drain_delete("fast").await;
    wire.drain_delete("timer").await;
    wire.stop().await;
}

#[tokio::test]
async fn http_zero_retry_duration_retains_failure_and_explicit_retry_preserves_rows() {
    let fixture = Fixture::new().await;
    let wire = WireServer::start(fixture.registry.clone()).await;
    wire.create_stream_with_policy("no-retry", 0, 0).await;
    let original = fixture.registry.lookup(&ServiceName::new("s3")).unwrap();
    let fault = Arc::new(FailOnce {
        inner: original.handler.unwrap(),
        stage: Stage::Metadata,
        after_write: false,
        fired: AtomicBool::new(false),
    });
    fixture
        .registry
        .register_native(ServiceName::new("s3"), original.metadata, fault.clone());
    wire.put("no-retry", 1, false).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let description = wire
                .call(
                    "Firehose_20150804.DescribeDeliveryStream",
                    json!({"DeliveryStreamName":"no-retry"}),
                )
                .await;
            let failure = &description["DeliveryStreamDescription"]["LocallyCloudDeliveryFailure"];
            if failure["State"] == "RETRY_EXHAUSTED" {
                assert_eq!(failure["Attempts"], 1);
                assert_eq!(failure["RetainedRecordCount"], 1);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(fault.fired.load(Ordering::Acquire));
    assert_eq!(wire.rows().await, [(0, "row-0".into())]);
    wire.call(
        "Firehose_20150804.LocallyCloudRetryDeliveryStream",
        json!({"DeliveryStreamName":"no-retry"}),
    )
    .await;
    wire.wait_rows(&[(0, "row-0".into()), (1, "row-1".into())])
        .await;
    wire.drain_delete("no-retry").await;
    let table = wire.table().await;
    let (metadata, rows) =
        read_physical_rows(async |uri| wire.get(uri).await, pointer(&table)).await;
    assert_eq!(rows, [(0, "row-0".into()), (1, "row-1".into())]);
    assert_eq!(metadata["snapshots"].as_array().unwrap().len(), 2);
    wire.stop().await;
}

struct BackupAckLoss {
    inner: Arc<dyn NativeHandler>,
    fired: AtomicBool,
}

#[async_trait]
impl NativeHandler for BackupAckLoss {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let fail = request.method == http::Method::PUT
            && request.uri.path().starts_with("/ack-loss-lake/errors/")
            && !self.fired.swap(true, Ordering::AcqRel);
        let response = self.inner.handle(request).await;
        if fail {
            assert!(response.status().is_success());
            return Response::builder()
                .status(503)
                .body(axum::body::Body::from(
                    "<Error><Code>InternalError</Code></Error>",
                ))
                .unwrap();
        }
        response
    }
}

#[tokio::test]
async fn http_backup_ack_loss_retries_only_backup_and_logs_are_sanitized() {
    let fixture = Fixture::new().await;
    locallycloud_cloudwatch_logs::register(&fixture.registry).unwrap();
    let wire = WireServer::start(fixture.registry.clone()).await;
    wire.call(
        "Logs_20140328.CreateLogGroup",
        json!({"logGroupName":"/test/firehose"}),
    )
    .await;
    for name in ["primary", "backup"] {
        wire.call(
            "Logs_20140328.CreateLogStream",
            json!({"logGroupName":"/test/firehose","logStreamName":name}),
        )
        .await;
    }
    let mut config = WireServer::stream_config("backup", 0, 0);
    let dest = &mut config["IcebergDestinationConfiguration"];
    dest["S3BackupMode"] = json!("FailedDataOnly");
    dest["CloudWatchLoggingOptions"] =
        json!({"Enabled":true,"LogGroupName":"/test/firehose","LogStreamName":"primary"});
    dest["S3Configuration"]["ErrorOutputPrefix"] = json!("unused-global/");
    dest["S3Configuration"]["CloudWatchLoggingOptions"] =
        json!({"Enabled":true,"LogGroupName":"/test/firehose","LogStreamName":"backup"});
    dest["DestinationTableConfigurationList"][0]["S3ErrorOutputPrefix"] = json!("errors/");
    wire.call("Firehose_20150804.CreateDeliveryStream", config)
        .await;
    let description = wire
        .call(
            "Firehose_20150804.DescribeDeliveryStream",
            json!({"DeliveryStreamName":"backup"}),
        )
        .await;
    let destination = &description["DeliveryStreamDescription"]["Destinations"][0]
        ["IcebergDestinationDescription"];
    assert_eq!(
        destination["S3DestinationDescription"]["ErrorOutputPrefix"],
        "unused-global/"
    );
    assert_eq!(
        destination["DestinationTableConfigurationList"][0]["S3ErrorOutputPrefix"],
        "errors/"
    );
    let original = fixture.registry.lookup(&ServiceName::new("s3")).unwrap();
    let primary = Arc::new(FailOnce {
        inner: original.handler.unwrap(),
        stage: Stage::Metadata,
        after_write: false,
        fired: AtomicBool::new(false),
    });
    let backup = Arc::new(BackupAckLoss {
        inner: primary,
        fired: AtomicBool::new(false),
    });
    let held = Arc::new(HoldFailure {
        inner: backup.clone(),
        ready: Notify::new(),
        release: Notify::new(),
    });
    fixture
        .registry
        .register_native(ServiceName::new("s3"), original.metadata, held.clone());
    let raw = br#"{"id":1,"payload":"DO_NOT_LOG_RECORD_OR_CREDENTIALS"}"#;
    wire.call("Firehose_20150804.PutRecord",json!({"DeliveryStreamName":"backup","Record":{"Data":base64::engine::general_purpose::STANDARD.encode(raw)}})).await;
    tokio::time::timeout(Duration::from_secs(5), held.ready.notified())
        .await
        .unwrap();
    held.release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), held.ready.notified())
        .await
        .unwrap();
    assert!(backup.fired.load(Ordering::Acquire));
    assert_eq!(wire.rows().await, [(0, "row-0".into())]);
    let keys = wire.backup_keys().await;
    assert_eq!(keys.len(), 1);
    let bytes = wire.get(&format!("s3://ack-loss-lake/{}", keys[0])).await;
    let envelope: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(envelope["rawData"].as_str().unwrap())
            .unwrap(),
        raw
    );
    held.release.notify_one();
    let completed = wire.wait_backup("backup").await;
    assert_eq!(
        completed["DeliveryStreamDescription"]["LocallyCloudBackup"]["Phase"],
        "Primary"
    );
    assert_eq!(wire.backup_keys().await, keys);
    assert_eq!(
        wire.get(&format!("s3://ack-loss-lake/{}", keys[0])).await,
        bytes
    );
    assert_eq!(wire.rows().await, [(0, "row-0".into())]);
    for name in ["primary", "backup"] {
        let logs = wire
            .call(
                "Logs_20140328.GetLogEvents",
                json!({"logGroupName":"/test/firehose","logStreamName":name}),
            )
            .await;
        let events = logs["events"].as_array().unwrap();
        if name == "backup" {
            assert!(
                events.is_empty(),
                "FailedDataOnly must use the primary log stream"
            );
            continue;
        }
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|e| e["message"]
            .as_str()
            .unwrap()
            .contains("Iceberg delivery failed")));
        assert!(events.iter().any(|e| e["message"]
            .as_str()
            .unwrap()
            .contains("S3 error backup failed")));
        let text = logs.to_string();
        assert!(!text.contains("DO_NOT_LOG_RECORD_OR_CREDENTIALS"));
        assert!(!text.contains("rawData"));
        assert!(!text.contains("Credential="));
        let event: Value =
            serde_json::from_str(logs["events"][0]["message"].as_str().unwrap()).unwrap();
        assert_eq!(event["errorCode"], "InternalError");
    }
    wire.drain_delete("backup").await;
    wire.stop().await;
}

#[tokio::test]
async fn http_backup_validation_and_log_failure_do_not_fake_delivery() {
    let fixture = Fixture::new().await;
    locallycloud_cloudwatch_logs::register(&fixture.registry).unwrap();
    let wire = WireServer::start(fixture.registry.clone()).await;
    for (field, value) in [
        ("S3BackupMode", json!("AllData")),
        ("CloudWatchLoggingOptions", json!({"Enabled":true})),
    ] {
        let mut config = WireServer::stream_config("invalid", 0, 0);
        config["IcebergDestinationConfiguration"][field] = value;
        let (status, value) = wire
            .send("Firehose_20150804.CreateDeliveryStream", config)
            .await;
        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(value["__type"], "InvalidArgumentException");
    }
    let streams = wire
        .call("Firehose_20150804.ListDeliveryStreams", json!({}))
        .await;
    assert!(streams["DeliveryStreamNames"]
        .as_array()
        .unwrap()
        .is_empty());
    let mut config = WireServer::stream_config("missing-logs", 0, 0);
    config["IcebergDestinationConfiguration"]["S3BackupMode"] = json!("FailedDataOnly");
    config["IcebergDestinationConfiguration"]["S3Configuration"]["ErrorOutputPrefix"] =
        json!("errors/");
    config["IcebergDestinationConfiguration"]["CloudWatchLoggingOptions"] =
        json!({"Enabled":true,"LogGroupName":"/missing","LogStreamName":"missing"});
    wire.call("Firehose_20150804.CreateDeliveryStream", config)
        .await;
    let original = fixture.registry.lookup(&ServiceName::new("s3")).unwrap();
    let fault = Arc::new(FailOnce {
        inner: original.handler.unwrap(),
        stage: Stage::Metadata,
        after_write: false,
        fired: AtomicBool::new(false),
    });
    fixture
        .registry
        .register_native(ServiceName::new("s3"), original.metadata, fault);
    wire.put("missing-logs", 1, false).await;
    wire.wait_backup("missing-logs").await;
    assert_eq!(wire.rows().await, [(0, "row-0".into())]);
    assert_eq!(wire.backup_keys().await.len(), 1);
    wire.drain_delete("missing-logs").await;
    wire.stop().await;
}

#[tokio::test]
async fn http_disabled_logging_emits_no_events_and_unsafe_prefixes_create_no_stream() {
    let fixture = Fixture::new().await;
    locallycloud_cloudwatch_logs::register(&fixture.registry).unwrap();
    let wire = WireServer::start(fixture.registry.clone()).await;
    wire.call(
        "Logs_20140328.CreateLogGroup",
        json!({"logGroupName":"/test/disabled"}),
    )
    .await;
    wire.call(
        "Logs_20140328.CreateLogStream",
        json!({"logGroupName":"/test/disabled","logStreamName":"delivery"}),
    )
    .await;
    for prefix in [
        "../escape/",
        "/absolute/",
        "!{timestamp:yyyy}/",
        "encoded%2f/",
    ] {
        let mut config = WireServer::stream_config("invalid-prefix", 0, 0);
        config["IcebergDestinationConfiguration"]["S3BackupMode"] = json!("FailedDataOnly");
        config["IcebergDestinationConfiguration"]["S3Configuration"]["ErrorOutputPrefix"] =
            json!(prefix);
        let (status, value) = wire
            .send("Firehose_20150804.CreateDeliveryStream", config)
            .await;
        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(value["__type"], "InvalidArgumentException");
    }
    let mut config = WireServer::stream_config("disabled-logs", 0, 0);
    config["IcebergDestinationConfiguration"]["CloudWatchLoggingOptions"] =
        json!({"Enabled":false,"LogGroupName":"/test/disabled","LogStreamName":"delivery"});
    config["IcebergDestinationConfiguration"]["S3BackupMode"] = json!("FailedDataOnly");
    config["IcebergDestinationConfiguration"]["S3Configuration"]["ErrorOutputPrefix"] =
        json!("errors/");
    config["IcebergDestinationConfiguration"]["S3Configuration"]["CloudWatchLoggingOptions"] =
        json!({"Enabled":true,"LogGroupName":"/test/disabled","LogStreamName":"delivery"});
    wire.call("Firehose_20150804.CreateDeliveryStream", config)
        .await;
    let original = fixture.registry.lookup(&ServiceName::new("s3")).unwrap();
    let fault = Arc::new(BackupAckLoss {
        inner: Arc::new(FailOnce {
            inner: original.handler.unwrap(),
            stage: Stage::Metadata,
            after_write: false,
            fired: AtomicBool::new(false),
        }),
        fired: AtomicBool::new(false),
    });
    fixture
        .registry
        .register_native(ServiceName::new("s3"), original.metadata, fault);
    wire.put("disabled-logs", 1, false).await;
    wire.wait_backup("disabled-logs").await;
    let logs = wire
        .call(
            "Logs_20140328.GetLogEvents",
            json!({"logGroupName":"/test/disabled","logStreamName":"delivery"}),
        )
        .await;
    assert!(logs["events"].as_array().unwrap().is_empty());
    assert_eq!(wire.rows().await, [(0, "row-0".into())]);
    let streams = wire
        .call("Firehose_20150804.ListDeliveryStreams", json!({}))
        .await;
    assert_eq!(streams["DeliveryStreamNames"], json!(["disabled-logs"]));
    wire.drain_delete("disabled-logs").await;
    wire.stop().await;
}

struct DenyBackup {
    inner: Arc<dyn NativeHandler>,
    denied: AtomicBool,
}

#[async_trait]
impl NativeHandler for DenyBackup {
    async fn handle(&self, request: ServiceRequest) -> Response {
        if request.method == http::Method::PUT
            && request.uri.path().starts_with("/ack-loss-lake/errors/")
            && self.denied.load(Ordering::Acquire)
        {
            return Response::builder()
                .status(503)
                .body(axum::body::Body::from(
                    "<Error><Code>InternalError</Code></Error>",
                ))
                .unwrap();
        }
        self.inner.handle(request).await
    }
}

#[tokio::test]
async fn http_exhausted_backup_retains_bytes_and_manual_retry_does_not_reenter_iceberg() {
    let fixture = Fixture::new().await;
    let wire = WireServer::start(fixture.registry.clone()).await;
    let mut config = WireServer::stream_config("blocked-backup", 0, 0);
    config["IcebergDestinationConfiguration"]["S3BackupMode"] = json!("FailedDataOnly");
    config["IcebergDestinationConfiguration"]["S3Configuration"]["ErrorOutputPrefix"] =
        json!("errors/");
    wire.call("Firehose_20150804.CreateDeliveryStream", config)
        .await;
    let original = fixture.registry.lookup(&ServiceName::new("s3")).unwrap();
    let primary = Arc::new(FailOnce {
        inner: original.handler.unwrap(),
        stage: Stage::Metadata,
        after_write: false,
        fired: AtomicBool::new(false),
    });
    let denied = Arc::new(DenyBackup {
        inner: primary,
        denied: AtomicBool::new(true),
    });
    fixture
        .registry
        .register_native(ServiceName::new("s3"), original.metadata, denied.clone());
    wire.put("blocked-backup", 1, false).await;
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let description = wire
                .call(
                    "Firehose_20150804.DescribeDeliveryStream",
                    json!({"DeliveryStreamName":"blocked-backup"}),
                )
                .await;
            let d = &description["DeliveryStreamDescription"];
            if d["LocallyCloudDeliveryFailure"]["State"] == "RETRY_EXHAUSTED" {
                assert_eq!(d["LocallyCloudBackup"]["Phase"], "Backup");
                assert_eq!(d["LocallyCloudBackup"]["Attempts"], 6);
                assert_eq!(d["LocallyCloudBackup"]["BackedUpRecordCount"], 0);
                assert_eq!(d["LocallyCloudDeliveryFailure"]["RetainedRecordCount"], 1);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(wire.rows().await, [(0, "row-0".into())]);
    assert!(wire.backup_keys().await.is_empty());
    denied.denied.store(false, Ordering::Release);
    wire.call(
        "Firehose_20150804.LocallyCloudRetryDeliveryStream",
        json!({"DeliveryStreamName":"blocked-backup"}),
    )
    .await;
    wire.wait_backup("blocked-backup").await;
    assert_eq!(wire.rows().await, [(0, "row-0".into())]);
    let keys = wire.backup_keys().await;
    assert_eq!(keys.len(), 1);
    let value: Value =
        serde_json::from_slice(&wire.get(&format!("s3://ack-loss-lake/{}", keys[0])).await)
            .unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value["rawData"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        json!({"id":1,"payload":"row-1"})
    );
    wire.drain_delete("blocked-backup").await;
    wire.stop().await;
}

#[tokio::test]
async fn http_missing_table_code_reaches_backup_without_becoming_backup_failure() {
    let fixture = Fixture::new().await;
    locallycloud_cloudwatch_logs::register(&fixture.registry).unwrap();
    let wire = WireServer::start(fixture.registry.clone()).await;
    wire.call(
        "Logs_20140328.CreateLogGroup",
        json!({"logGroupName":"/test/missing-table"}),
    )
    .await;
    wire.call(
        "Logs_20140328.CreateLogStream",
        json!({"logGroupName":"/test/missing-table","logStreamName":"delivery"}),
    )
    .await;
    let mut config = WireServer::stream_config("missing-table", 0, 0);
    let dest = &mut config["IcebergDestinationConfiguration"];
    dest["S3BackupMode"] = json!("FailedDataOnly");
    dest["S3Configuration"]["ErrorOutputPrefix"] = json!("errors/");
    dest["CloudWatchLoggingOptions"] =
        json!({"Enabled":true,"LogGroupName":"/test/missing-table","LogStreamName":"delivery"});
    wire.call("Firehose_20150804.CreateDeliveryStream", config)
        .await;
    let original = fixture.registry.lookup(&ServiceName::new("s3")).unwrap();
    fixture.registry.register_native(
        ServiceName::new("s3"),
        original.metadata,
        Arc::new(BackupAckLoss {
            inner: original.handler.unwrap(),
            fired: AtomicBool::new(false),
        }),
    );
    wire.call(
        "AWSGlue.DeleteTable",
        json!({"DatabaseName":"lake","Name":"events"}),
    )
    .await;
    let raw = br#"{"id":1,"payload":"DO_NOT_LOG_RECORD_OR_CREDENTIALS"}"#;
    wire.call("Firehose_20150804.PutRecord", json!({"DeliveryStreamName":"missing-table","Record":{"Data":base64::engine::general_purpose::STANDARD.encode(raw)}})).await;
    wire.wait_backup("missing-table").await;
    let keys = wire.backup_keys().await;
    assert_eq!(keys.len(), 1);
    let envelope: Value =
        serde_json::from_slice(&wire.get(&format!("s3://ack-loss-lake/{}", keys[0])).await)
            .unwrap();
    assert_eq!(envelope["errorCode"], "Iceberg.NoSuchTable");
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(envelope["rawData"].as_str().unwrap())
            .unwrap(),
        raw
    );
    let logs = wire
        .call(
            "Logs_20140328.GetLogEvents",
            json!({"logGroupName":"/test/missing-table","logStreamName":"delivery"}),
        )
        .await;
    let codes = logs["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| {
            let message: Value = serde_json::from_str(event["message"].as_str().unwrap()).unwrap();
            message["errorCode"].as_str().unwrap().to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(codes, ["Iceberg.NoSuchTable", "InternalError"]);
    assert!(!logs
        .to_string()
        .contains("DO_NOT_LOG_RECORD_OR_CREDENTIALS"));
    wire.drain_delete("missing-table").await;
    wire.stop().await;
}

struct GlueReadFailure {
    status: u16,
    body: Value,
}

#[async_trait]
impl NativeHandler for GlueReadFailure {
    async fn handle(&self, request: ServiceRequest) -> Response {
        assert_eq!(request.headers["x-amz-target"], "AWSGlue.GetTable");
        Response::builder()
            .status(self.status)
            .header("content-type", "application/x-amz-json-1.1")
            .body(axum::body::Body::from(self.body.to_string()))
            .unwrap()
    }
}

#[tokio::test]
async fn http_glue_error_classification_uses_status_and_modeled_type() {
    for (status, body, expected) in [
        (
            403,
            json!({"__type":"AccessDeniedException","message":"DO_NOT_LOG_BACKEND_SECRET"}),
            "Glue.AccessDenied",
        ),
        (
            403,
            json!({"__type":"com.amazonaws.glue#AccessDeniedException"}),
            "Glue.AccessDenied",
        ),
        (
            403,
            json!({"__type":"ExpiredTokenException"}),
            "InternalError",
        ),
        (
            500,
            json!({"__type":"EntityNotFoundException"}),
            "InternalError",
        ),
        (
            400,
            json!({"__type":"AccessDeniedException"}),
            "Glue.AccessDenied",
        ),
        (
            500,
            json!({"__type":"AccessDeniedException"}),
            "InternalError",
        ),
        (
            400,
            json!({"__type":"NotEntityNotFoundException"}),
            "InternalError",
        ),
        (
            400,
            json!({"message":"EntityNotFoundException"}),
            "InternalError",
        ),
        (
            400,
            json!({"__type":"com.amazonaws.glue#EntityNotFoundException"}),
            "Iceberg.NoSuchTable",
        ),
    ] {
        let fixture = Fixture::new().await;
        let wire = WireServer::start(fixture.registry.clone()).await;
        let mut config = WireServer::stream_config("unknown-failure", 0, 0);
        config["IcebergDestinationConfiguration"]["S3BackupMode"] = json!("FailedDataOnly");
        config["IcebergDestinationConfiguration"]["S3Configuration"]["ErrorOutputPrefix"] =
            json!("errors/");
        wire.call("Firehose_20150804.CreateDeliveryStream", config)
            .await;
        let original = fixture.registry.lookup(&ServiceName::new("glue")).unwrap();
        fixture.registry.register_native(
            ServiceName::new("glue"),
            original.metadata,
            Arc::new(GlueReadFailure { status, body }),
        );
        wire.put("unknown-failure", 1, false).await;
        wire.wait_backup("unknown-failure").await;
        let keys = wire.backup_keys().await;
        assert_eq!(keys.len(), 1);
        let envelope: Value =
            serde_json::from_slice(&wire.get(&format!("s3://ack-loss-lake/{}", keys[0])).await)
                .unwrap();
        assert_eq!(envelope["errorCode"], expected);
        wire.drain_delete("unknown-failure").await;
        wire.stop().await;
    }
}

#[derive(Clone, Copy)]
enum DeniedOperation {
    S3Read,
    S3Write,
    S3Backup,
    GlueRead,
    GlueUpdate,
}

struct DenyOnce {
    inner: Arc<dyn NativeHandler>,
    operation: DeniedOperation,
    fired: AtomicBool,
}

#[async_trait]
impl NativeHandler for DenyOnce {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let backup = request.uri.path().starts_with("/ack-loss-lake/errors/");
        let target = request
            .headers
            .get("x-amz-target")
            .and_then(|v| v.to_str().ok());
        let matches = match self.operation {
            DeniedOperation::S3Read => request.method == http::Method::GET && !backup,
            DeniedOperation::S3Write => request.method == http::Method::PUT && !backup,
            DeniedOperation::S3Backup => request.method == http::Method::PUT && backup,
            DeniedOperation::GlueRead => target == Some("AWSGlue.GetTable"),
            DeniedOperation::GlueUpdate => target == Some("AWSGlue.UpdateTable"),
        };
        if matches && !self.fired.swap(true, Ordering::AcqRel) {
            let (content_type, body) = match self.operation {
                DeniedOperation::GlueRead | DeniedOperation::GlueUpdate => ("application/x-amz-json-1.1", json!({"__type":"AccessDeniedException","message":"DO_NOT_LOG_BACKEND_SECRET"}).to_string()),
                DeniedOperation::S3Read | DeniedOperation::S3Write | DeniedOperation::S3Backup => ("application/xml", "<Error><Code>AccessDenied</Code><Message>DO_NOT_LOG_BACKEND_SECRET</Message></Error>".into()),
            };
            return Response::builder()
                .status(403)
                .header("content-type", content_type)
                .body(axum::body::Body::from(body))
                .unwrap();
        }
        self.inner.handle(request).await
    }
}

#[tokio::test]
async fn http_observed_access_denials_keep_primary_and_backup_causes_separate() {
    for operation in [
        DeniedOperation::GlueRead,
        DeniedOperation::GlueUpdate,
        DeniedOperation::S3Read,
        DeniedOperation::S3Write,
    ] {
        let fixture = Fixture::new().await;
        locallycloud_cloudwatch_logs::register(&fixture.registry).unwrap();
        let wire = WireServer::start(fixture.registry.clone()).await;
        wire.call(
            "Logs_20140328.CreateLogGroup",
            json!({"logGroupName":"/test/access"}),
        )
        .await;
        wire.call(
            "Logs_20140328.CreateLogStream",
            json!({"logGroupName":"/test/access","logStreamName":"delivery"}),
        )
        .await;
        let mut config = WireServer::stream_config("denied", 0, 0);
        let dest = &mut config["IcebergDestinationConfiguration"];
        dest["S3BackupMode"] = json!("FailedDataOnly");
        dest["S3Configuration"]["ErrorOutputPrefix"] = json!("errors/");
        dest["CloudWatchLoggingOptions"] =
            json!({"Enabled":true,"LogGroupName":"/test/access","LogStreamName":"delivery"});
        wire.call("Firehose_20150804.CreateDeliveryStream", config)
            .await;
        let original = fixture.registry.lookup(&ServiceName::new("s3")).unwrap();
        fixture.registry.register_native(
            ServiceName::new("s3"),
            original.metadata,
            Arc::new(DenyOnce {
                inner: original.handler.unwrap(),
                operation: DeniedOperation::S3Backup,
                fired: AtomicBool::new(false),
            }),
        );
        let (service, expected) = match operation {
            DeniedOperation::GlueRead | DeniedOperation::GlueUpdate => {
                ("glue", "Glue.AccessDenied")
            }
            DeniedOperation::S3Read | DeniedOperation::S3Write => ("s3", "S3.AccessDenied"),
            DeniedOperation::S3Backup => unreachable!(),
        };
        let original = fixture.registry.lookup(&ServiceName::new(service)).unwrap();
        fixture.registry.register_native(
            ServiceName::new(service),
            original.metadata,
            Arc::new(DenyOnce {
                inner: original.handler.unwrap(),
                operation,
                fired: AtomicBool::new(false),
            }),
        );
        wire.put("denied", 1, false).await;
        wire.wait_backup("denied").await;
        let keys = wire.backup_keys().await;
        assert_eq!(keys.len(), 1);
        let envelope: Value =
            serde_json::from_slice(&wire.get(&format!("s3://ack-loss-lake/{}", keys[0])).await)
                .unwrap();
        assert_eq!(envelope["errorCode"], expected);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(envelope["rawData"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&raw).unwrap(),
            json!({"id":1,"payload":"row-1"})
        );
        let logs = wire
            .call(
                "Logs_20140328.GetLogEvents",
                json!({"logGroupName":"/test/access","logStreamName":"delivery"}),
            )
            .await;
        let codes = logs["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let message: Value = serde_json::from_str(e["message"].as_str().unwrap()).unwrap();
                message["errorCode"].as_str().unwrap().to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(codes, [expected, "S3.AccessDenied"]);
        assert!(!logs.to_string().contains("DO_NOT_LOG_BACKEND_SECRET"));
        assert!(!envelope.to_string().contains("DO_NOT_LOG_BACKEND_SECRET"));
        assert_eq!(wire.rows().await, [(0, "row-0".into())]);
        wire.drain_delete("denied").await;
        wire.stop().await;
    }
}

#[tokio::test]
async fn http_preflight_denial_does_not_create_a_stream() {
    for operation in [DeniedOperation::GlueRead, DeniedOperation::S3Read] {
        let fixture = Fixture::new().await;
        let wire = WireServer::start(fixture.registry.clone()).await;
        let service = match operation {
            DeniedOperation::GlueRead => "glue",
            DeniedOperation::S3Read => "s3",
            _ => unreachable!(),
        };
        let original = fixture.registry.lookup(&ServiceName::new(service)).unwrap();
        fixture.registry.register_native(
            ServiceName::new(service),
            original.metadata,
            Arc::new(DenyOnce {
                inner: original.handler.unwrap(),
                operation,
                fired: AtomicBool::new(false),
            }),
        );
        let config = WireServer::stream_config("preflight-denied", 0, 0);
        let (status, value) = wire
            .send("Firehose_20150804.CreateDeliveryStream", config.clone())
            .await;
        assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
        assert_eq!(value["__type"], "AccessDeniedException");
        assert_eq!(
            wire.call("Firehose_20150804.ListDeliveryStreams", json!({}))
                .await["DeliveryStreamNames"],
            json!([])
        );
        wire.call("Firehose_20150804.CreateDeliveryStream", config)
            .await;
        wire.drain_delete("preflight-denied").await;
        wire.stop().await;
    }
}

// A typed evaluator double exercises the worker contract, not IAM policy/SigV4 fidelity.
#[derive(Default)]
struct RoleDecisions {
    deny_primary_put: AtomicBool,
    resource_requests: Mutex<Vec<AuthorizationRequest>>,
    role_requests: Mutex<Vec<ServiceRoleAuthorizationRequest>>,
    failures: Mutex<std::collections::VecDeque<(&'static str, usize, AuthorizationError)>>,
}

impl AuthorizationEvaluator for RoleDecisions {
    fn strict_sigv4_required(&self) -> bool {
        true
    }

    fn credential_account(&self, _: &str) -> Result<Option<String>, AuthorizationError> {
        Ok(Some("000000000000".into()))
    }

    fn verify_sigv4(
        &self,
        _: &str,
        _: &http::Method,
        _: &http::Uri,
        _: &http::HeaderMap,
        _: &[u8],
        _: &str,
        _: &str,
    ) -> bool {
        true
    }

    fn authorize(&self, _: AuthorizationRequest) -> Result<(), AuthorizationError> {
        Ok(())
    }

    fn authorize_resource_policy(
        &self,
        request: AuthorizationRequest,
        _: Option<&str>,
        _: &str,
    ) -> Result<(), AuthorizationError> {
        let internal = matches!(
            request.request_identity.access_key_id.as_deref(),
            Some("local" | "locallycloud")
        );
        let missing_role = internal && request.delegated_identity.is_none();
        let deny_put = internal
            && request.action == "s3:PutObject"
            && !request.resource.contains("/errors/")
            && self.deny_primary_put.swap(false, Ordering::AcqRel);
        self.resource_requests.lock().unwrap().push(request);
        if missing_role || deny_put {
            return Err(AuthorizationError::Denied);
        }
        Ok(())
    }

    fn authorize_service_role(
        &self,
        request: ServiceRoleAuthorizationRequest,
    ) -> Result<(), AuthorizationError> {
        self.role_requests.lock().unwrap().push(request);
        Ok(())
    }

    fn authorize_service_role_execution(
        &self,
        request: ServiceRoleAuthorizationRequest,
    ) -> Result<(), AuthorizationError> {
        assert_eq!(request.caller.account_id, "000000000000");
        assert_eq!(request.service_principal, "firehose.amazonaws.com");
        assert!(matches!(
            request.role_arn.as_str(),
            "arn:aws:iam::000000000000:role/firehose" | "arn:aws:iam::000000000000:role/backup"
        ));
        self.role_requests.lock().unwrap().push(request.clone());
        assert!(
            request.resource == "arn:aws:s3:::ack-loss-lake/*"
                || request.resource == "arn:aws:glue:us-east-1:000000000000:table/lake/events"
        );
        let mut failures = self.failures.lock().unwrap();
        if let Some((action, skip, error)) = failures.front_mut() {
            if request.action == *action {
                if *skip > 0 {
                    *skip -= 1;
                } else {
                    let error = *error;
                    failures.pop_front();
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl NativeHandler for RoleDecisions {
    async fn handle(&self, _: ServiceRequest) -> Response {
        Response::builder()
            .status(501)
            .body(axum::body::Body::empty())
            .unwrap()
    }
}

struct CountDispatches {
    inner: Arc<dyn NativeHandler>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl NativeHandler for CountDispatches {
    async fn handle(&self, request: ServiceRequest) -> Response {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.inner.handle(request).await
    }
}

#[tokio::test]
async fn http_role_rejections_consume_retry_budget_without_dispatching_denied_work() {
    use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};
    for (action, error, expected) in [
        (
            "glue:GetTable",
            AuthorizationError::Denied,
            "Glue.AccessDenied",
        ),
        (
            "glue:UpdateTable",
            AuthorizationError::Denied,
            "Glue.AccessDenied",
        ),
        (
            "s3:GetObject",
            AuthorizationError::Denied,
            "S3.AccessDenied",
        ),
        (
            "s3:PutObject",
            AuthorizationError::Denied,
            "S3.AccessDenied",
        ),
        (
            "glue:GetTable",
            AuthorizationError::Unavailable,
            "InternalError",
        ),
        (
            "glue:GetTable",
            AuthorizationError::InvalidRequest,
            "InternalError",
        ),
        (
            "glue:GetTable",
            AuthorizationError::Internal,
            "InternalError",
        ),
    ] {
        let fixture = Fixture::new().await;
        locallycloud_cloudwatch_logs::register(&fixture.registry).unwrap();
        let decisions = Arc::new(RoleDecisions::default());
        fixture
            .registry
            .register_native_with_authorization_evaluator(
                ServiceName::new("iam"),
                ServiceMetadata::new(AwsProtocol::Query, None),
                decisions.clone(),
                decisions.clone(),
            );
        let wire = WireServer::start(fixture.registry.clone()).await;
        wire.create_stream("control").await;
        wire.put("control", 1, false).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while wire.rows().await.len() != 2 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        wire.drain_delete("control").await;
        wire.call(
            "Logs_20140328.CreateLogGroup",
            json!({"logGroupName":"/test/roles"}),
        )
        .await;
        wire.call(
            "Logs_20140328.CreateLogStream",
            json!({"logGroupName":"/test/roles","logStreamName":"delivery"}),
        )
        .await;
        let mut config = WireServer::stream_config("revoked", 0, 0);
        let dest = &mut config["IcebergDestinationConfiguration"];
        dest["S3BackupMode"] = json!("FailedDataOnly");
        dest["S3Configuration"]["ErrorOutputPrefix"] = json!("errors/");
        dest["CloudWatchLoggingOptions"] =
            json!({"Enabled":true,"LogGroupName":"/test/roles","LogStreamName":"delivery"});
        wire.call("Firehose_20150804.CreateDeliveryStream", config)
            .await;
        let glue_calls = Arc::new(AtomicUsize::new(0));
        let s3_calls = Arc::new(AtomicUsize::new(0));
        for (service, calls) in [("glue", glue_calls.clone()), ("s3", s3_calls.clone())] {
            let original = fixture.registry.lookup(&ServiceName::new(service)).unwrap();
            fixture.registry.register_native(
                ServiceName::new(service),
                original.metadata,
                Arc::new(CountDispatches {
                    inner: original.handler.unwrap(),
                    calls,
                }),
            );
        }
        // Allow ingress's runtime check, then reject the worker. Reject backup once too.
        *decisions.failures.lock().unwrap() = std::collections::VecDeque::from([
            (action, 1, error),
            ("s3:PutObject", 0, AuthorizationError::Denied),
        ]);
        wire.put("revoked", 2, false).await;
        wire.wait_backup("revoked").await;
        assert!(decisions.failures.lock().unwrap().is_empty());
        assert_eq!(
            glue_calls.load(Ordering::Acquire),
            0,
            "denied primary must not dispatch"
        );
        assert_eq!(
            s3_calls.load(Ordering::Acquire),
            1,
            "only authorized backup may dispatch"
        );
        let keys = wire.backup_keys().await;
        assert_eq!(keys.len(), 1);
        let envelope: Value =
            serde_json::from_slice(&wire.get(&format!("s3://ack-loss-lake/{}", keys[0])).await)
                .unwrap();
        assert_eq!(envelope["errorCode"], expected);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(envelope["rawData"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&raw).unwrap(),
            json!({"id":2,"payload":"row-2"})
        );
        let logs = wire
            .call(
                "Logs_20140328.GetLogEvents",
                json!({"logGroupName":"/test/roles","logStreamName":"delivery"}),
            )
            .await;
        let messages: Vec<Value> = logs["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| serde_json::from_str(e["message"].as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(
            messages
                .iter()
                .map(|v| v["errorCode"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [expected, "S3.AccessDenied"]
        );
        assert!(!logs.to_string().contains("rawData"));
        assert!(!logs.to_string().contains("row-2"));
        assert_eq!(
            wire.rows().await,
            [(0, "row-0".into()), (1, "row-1".into())]
        );
        wire.drain_delete("revoked").await;
        wire.stop().await;
    }
}

#[tokio::test]
async fn http_iceberg_and_backup_propagate_separate_execution_roles() {
    use locallycloud_core::integration::identity::CallerIdentity;
    use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};
    let fixture = Fixture::new().await;
    let decisions = Arc::new(RoleDecisions::default());
    fixture
        .registry
        .register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            decisions.clone(),
            decisions.clone(),
        );
    let wire = WireServer::start(fixture.registry.clone()).await;
    let mut config = WireServer::stream_config("delegated", 0, 0);
    let dest = &mut config["IcebergDestinationConfiguration"];
    dest["S3Configuration"]["RoleARN"] = json!("arn:aws:iam::000000000000:role/backup");
    dest["S3BackupMode"] = json!("FailedDataOnly");
    dest["S3Configuration"]["ErrorOutputPrefix"] = json!("errors/");
    wire.call("Firehose_20150804.CreateDeliveryStream", config)
        .await;
    let assignment_checks = decisions.role_requests.lock().unwrap().len();
    wire.put("delegated", 1, false).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while wire.rows().await.len() != 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // Primary checks and actual S3 resource-policy composition must agree on the role.
    {
        let roles = decisions.role_requests.lock().unwrap();
        assert!(roles[assignment_checks..]
            .iter()
            .all(|r| r.role_arn.ends_with("/firehose")));
        assert!(roles
            .iter()
            .any(|r| r.action == "s3:PutObject" && r.role_arn.ends_with("/backup")));
        assert!(roles
            .iter()
            .any(|r| r.action == "s3:PutObject" && r.role_arn.ends_with("/firehose")));
        assert!(roles
            .iter()
            .filter(|r| r.action == "s3:GetObject")
            .all(|r| r.role_arn.ends_with("/firehose")));
    }
    // The native S3 policy boundary rejects the next primary PUT, after Firehose's checks.
    decisions.deny_primary_put.store(true, Ordering::Release);
    wire.put("delegated", 2, false).await;
    wire.wait_backup("delegated").await;
    let keys = wire.backup_keys().await;
    assert_eq!(keys.len(), 1);
    let envelope: Value =
        serde_json::from_slice(&wire.get(&format!("s3://ack-loss-lake/{}", keys[0])).await)
            .unwrap();
    assert_eq!(envelope["errorCode"], "S3.AccessDenied");
    let raw = base64::engine::general_purpose::STANDARD
        .decode(envelope["rawData"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&raw).unwrap(),
        json!({"id":2,"payload":"row-2"})
    );
    {
        let requests = decisions.resource_requests.lock().unwrap();
        let internal: Vec<_> = requests
            .iter()
            .filter(|r| {
                matches!(
                    r.request_identity.access_key_id.as_deref(),
                    Some("local" | "locallycloud")
                )
            })
            .collect();
        assert!(internal.iter().any(|r| r.action == "s3:GetObject"));
        assert!(internal
            .iter()
            .any(|r| r.action == "s3:PutObject" && !r.resource.contains("/errors/")));
        assert!(internal
            .iter()
            .any(|r| r.action == "s3:PutObject" && r.resource.contains("/errors/")));
        for request in internal {
            let role = if request.resource.contains("/errors/") {
                "backup"
            } else {
                "firehose"
            };
            assert!(
                matches!(&request.delegated_identity, Some(CallerIdentity::AssumedRole { role_arn, session_name }) if role_arn == &format!("arn:aws:iam::000000000000:role/{role}") && !session_name.is_empty()),
                "{request:?}"
            );
        }
    }
    assert_eq!(
        wire.rows().await,
        [(0, "row-0".into()), (1, "row-1".into())]
    );
    wire.drain_delete("delegated").await;
    wire.stop().await;
}
