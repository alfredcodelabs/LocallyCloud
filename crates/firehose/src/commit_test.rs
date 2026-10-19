//! Deterministic writer conflicts and publication failures through native dispatch.
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ::iceberg::spec::{FormatVersion, Manifest, ManifestList};
use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::response::Response;
use bytes::Bytes;
use http::{Method, StatusCode};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::RowAccessor;
use serde_json::{json, Value};
use tokio::sync::Barrier;
use uuid::Uuid;

use crate::ack_loss_test::{call, json_call, query_results};
use crate::iceberg::{self, Context, Target};

pub(super) struct Fixture {
    pub(super) registry: Arc<ServiceRegistry>,
    dispatcher: Arc<InternalDispatcher>,
    target: Target,
}

impl Fixture {
    pub(super) async fn new() -> Self {
        let registry = ServiceRegistry::with_known_services();
        locallycloud_s3::register(&registry);
        locallycloud_analytics::register(&registry);
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
        registry.set_internal_dispatcher(dispatcher.clone());
        let (status, _) = call(
            &dispatcher,
            Method::PUT,
            "/ack-loss-lake",
            None,
            Bytes::new(),
        )
        .await;
        assert!(status.is_success());
        let metadata = json!({
            "format-version":2,"table-uuid":Uuid::new_v4().to_string(),"location":"s3://ack-loss-lake/events",
            "last-sequence-number":0,"last-updated-ms":1,"last-column-id":2,"current-schema-id":0,
            "schemas":[{"type":"struct","schema-id":0,"fields":[
                {"id":1,"name":"id","required":true,"type":"long"},
                {"id":2,"name":"payload","required":false,"type":"string"}]}],
            "default-spec-id":0,"partition-specs":[{"spec-id":0,"fields":[]}],"last-partition-id":999,
            "default-sort-order-id":0,"sort-orders":[{"order-id":0,"fields":[]}],
            "properties":{},"snapshots":[],"snapshot-log":[],"metadata-log":[],"refs":{}
        });
        let (status, _) = call(
            &dispatcher,
            Method::PUT,
            "/ack-loss-lake/events/metadata/initial.json",
            None,
            Bytes::from(metadata.to_string()),
        )
        .await;
        assert!(status.is_success());
        json_call(
            &dispatcher,
            "CreateDatabase",
            json!({"DatabaseInput":{"Name":"lake"}}),
        )
        .await;
        json_call(&dispatcher, "CreateTable", json!({"DatabaseName":"lake","TableInput":{
            "Name":"events","TableType":"EXTERNAL_TABLE",
            "Parameters":{"table_type":"ICEBERG","metadata_location":"s3://ack-loss-lake/events/metadata/initial.json"},
            "StorageDescriptor":{"Location":"s3://ack-loss-lake/events/"}
        }})).await;
        let fixture = Self {
            registry,
            dispatcher,
            target: Target {
                database: "lake".into(),
                table: "events".into(),
                bucket: "ack-loss-lake".into(),
            },
        };
        fixture.append(Uuid::new_v4(), 0).await.unwrap();
        fixture
    }

    async fn append(&self, token: Uuid, id: i64) -> Result<(), iceberg::Error> {
        iceberg::append(
            Context {
                dispatcher: &self.dispatcher,
                account: "000000000000",
                region: "us-east-1",
                bucket: &self.target.bucket,
                role_arn: "arn:aws:iam::000000000000:role/firehose",
            },
            &self.target,
            token,
            &[json!({"id":id,"payload":format!("row-{id}")})
                .to_string()
                .into_bytes()],
        )
        .await
    }

    async fn table(&self) -> Value {
        json_call(
            &self.dispatcher,
            "GetTable",
            json!({"DatabaseName":"lake","Name":"events"}),
        )
        .await
    }

    async fn get(&self, uri: &str) -> Bytes {
        let path = uri.strip_prefix("s3:/").unwrap();
        let (status, bytes) = call(&self.dispatcher, Method::GET, path, None, Bytes::new()).await;
        assert!(status.is_success(), "GET {uri}");
        bytes
    }

    async fn replace_metadata(&self, metadata: &Value) -> Value {
        let location = format!(
            "s3://ack-loss-lake/events/metadata/{}.metadata.json",
            Uuid::new_v4()
        );
        let (status, _) = call(
            &self.dispatcher,
            Method::PUT,
            location.strip_prefix("s3:/").unwrap(),
            None,
            Bytes::from(metadata.to_string()),
        )
        .await;
        assert!(status.is_success());
        let current = self.table().await;
        let mut input = current["Table"].as_object().unwrap().clone();
        for key in [
            "CatalogId",
            "DatabaseName",
            "CreateTime",
            "UpdateTime",
            "VersionId",
        ] {
            input.remove(key);
        }
        input.get_mut("Parameters").unwrap()["metadata_location"] = json!(location);
        json_call(&self.dispatcher, "UpdateTable", json!({"DatabaseName":"lake", "TableInput":input, "VersionId":current["Table"]["VersionId"]})).await;
        self.table().await
    }

    pub(super) async fn physical_rows(&self, metadata_uri: &str) -> (Value, Vec<(i64, String)>) {
        read_physical_rows(async |uri| self.get(uri).await, metadata_uri).await
    }
}

pub(super) async fn read_physical_rows(
    get: impl std::ops::AsyncFn(&str) -> Bytes,
    metadata_uri: &str,
) -> (Value, Vec<(i64, String)>) {
    let metadata: Value = serde_json::from_slice(&get(metadata_uri).await).unwrap();
    assert_eq!(metadata["format-version"], 2);
    let snapshot = metadata["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["snapshot-id"] == metadata["current-snapshot-id"])
        .unwrap();
    let list = get(snapshot["manifest-list"].as_str().unwrap()).await;
    let manifests = ManifestList::parse_with_version(&list, FormatVersion::V2)
        .unwrap()
        .consume_entries();
    let mut files = BTreeSet::new();
    let mut rows = Vec::new();
    for manifest in manifests {
        let bytes = get(&manifest.manifest_path).await;
        let manifest = Manifest::parse_avro(&bytes).unwrap();
        for entry in manifest.entries().iter().filter(|e| e.is_alive()) {
            assert!(
                files.insert(entry.file_path().to_owned()),
                "duplicate live file"
            );
            let parquet = SerializedFileReader::new(get(entry.file_path()).await).unwrap();
            for row in parquet.get_row_iter(None).unwrap() {
                let row = row.unwrap();
                rows.push((row.get_long(0).unwrap(), row.get_string(1).unwrap().clone()));
            }
        }
    }
    rows.sort();
    (metadata, rows)
}

pub(super) fn pointer(table: &Value) -> &str {
    table["Table"]["Parameters"]["metadata_location"]
        .as_str()
        .unwrap()
}

pub(super) struct ConcurrentReads {
    pub(super) inner: Arc<dyn NativeHandler>,
    pub(super) barrier: Barrier,
    pub(super) reads: AtomicUsize,
    pub(super) conflicts: AtomicUsize,
    pub(super) versions: Mutex<Vec<String>>,
}

#[async_trait]
impl NativeHandler for ConcurrentReads {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let get = request
            .headers
            .get("x-amz-target")
            .is_some_and(|v| v == "AWSGlue.GetTable");
        let update = request
            .headers
            .get("x-amz-target")
            .is_some_and(|v| v == "AWSGlue.UpdateTable");
        let response = self.inner.handle(request).await;
        if get && self.reads.fetch_add(1, Ordering::AcqRel) < 2 {
            let (parts, body) = response.into_parts();
            let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            self.versions
                .lock()
                .unwrap()
                .push(value["Table"]["VersionId"].as_str().unwrap().into());
            self.barrier.wait().await;
            return Response::from_parts(parts, Body::from(bytes));
        }
        if update && response.status() == StatusCode::BAD_REQUEST {
            let (parts, body) = response.into_parts();
            let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["__type"], "ConcurrentModificationException");
            self.conflicts.fetch_add(1, Ordering::AcqRel);
            return Response::from_parts(parts, Body::from(bytes));
        }
        response
    }
}

#[tokio::test]
async fn concurrent_writers_reload_after_real_cas_conflict_without_losing_rows() {
    let fixture = Fixture::new().await;
    let baseline = fixture.table().await;
    let glue = fixture.registry.lookup(&ServiceName::new("glue")).unwrap();
    let gate = Arc::new(ConcurrentReads {
        inner: glue.handler.unwrap(),
        barrier: Barrier::new(2),
        reads: AtomicUsize::new(0),
        conflicts: AtomicUsize::new(0),
        versions: Mutex::new(Vec::new()),
    });
    fixture
        .registry
        .register_native(ServiceName::new("glue"), glue.metadata, gate.clone());
    let tokens = [Uuid::new_v4(), Uuid::new_v4()];
    let (first, second) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(fixture.append(tokens[0], 1), fixture.append(tokens[1], 2))
    })
    .await
    .unwrap();
    first.unwrap();
    second.unwrap();
    assert_eq!(*gate.versions.lock().unwrap(), ["2", "2"]);
    assert_eq!(gate.conflicts.load(Ordering::Acquire), 1);
    let current = fixture.table().await;
    assert_eq!(current["Table"]["VersionId"], "4");
    let (metadata, rows) = fixture.physical_rows(pointer(&current)).await;
    assert_eq!(
        rows,
        [
            (0, "row-0".into()),
            (1, "row-1".into()),
            (2, "row-2".into())
        ]
    );
    assert_eq!(metadata["last-sequence-number"], 3);
    assert_eq!(metadata["snapshots"].as_array().unwrap().len(), 3);
    assert_eq!(
        fixture.physical_rows(pointer(&baseline)).await.1,
        [(0, "row-0".into())]
    );
    for (index, token) in tokens.into_iter().enumerate() {
        fixture.append(token, index as i64 + 1).await.unwrap();
    }
    assert_eq!(fixture.table().await, current);
    let results = query_results(&fixture.dispatcher, "SELECT id, payload FROM lake.events").await;
    let mut actual: Vec<_> = results["ResultSet"]["Rows"]
        .as_array()
        .unwrap()
        .iter()
        .skip(1)
        .map(|row| {
            (
                row["Data"][0]["VarCharValue"]
                    .as_str()
                    .unwrap()
                    .parse::<i64>()
                    .unwrap(),
                row["Data"][1]["VarCharValue"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    actual.sort();
    assert_eq!(actual, rows);
}

struct CountHistoryReads {
    inner: Arc<dyn NativeHandler>,
    reads: Mutex<std::collections::BTreeMap<String, usize>>,
    writes: AtomicUsize,
}

#[async_trait]
impl NativeHandler for CountHistoryReads {
    async fn handle(&self, request: ServiceRequest) -> Response {
        if request.method == Method::GET
            && (request.uri.path().ends_with(".avro")
                || request.uri.path().contains("/firehose-replay/"))
        {
            *self
                .reads
                .lock()
                .unwrap()
                .entry(request.uri.path().into())
                .or_default() += 1;
        }
        if request.method == Method::PUT {
            self.writes.fetch_add(1, Ordering::AcqRel);
        }
        self.inner.handle(request).await
    }
}

#[tokio::test]
async fn retained_history_reads_shared_manifests_once_and_replays_at_snapshot_limit() {
    let fixture = Fixture::new().await;
    let baseline = fixture.table().await;
    let baseline_metadata: Value =
        serde_json::from_slice(&fixture.get(pointer(&baseline)).await).unwrap();
    let first_token = Uuid::parse_str(
        baseline_metadata["snapshots"][0]["summary"]["locallycloud.batch-token"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let s3 = fixture.registry.lookup(&ServiceName::new("s3")).unwrap();
    let counter = Arc::new(CountHistoryReads {
        inner: s3.handler.unwrap(),
        reads: Mutex::default(),
        writes: AtomicUsize::new(0),
    });
    fixture
        .registry
        .register_native(ServiceName::new("s3"), s3.metadata, counter.clone());
    let mut last_token = first_token;
    for id in 1..32 {
        counter.reads.lock().unwrap().clear();
        last_token = Uuid::new_v4();
        fixture.append(last_token, id).await.unwrap();
    }
    {
        let reads = counter.reads.lock().unwrap();
        assert_eq!(
            reads.len(),
            62,
            "31 historical lists and 31 distinct manifests"
        );
        assert!(
            reads.values().all(|count| *count == 1),
            "shared manifests must not be reread"
        );
    }
    let current = fixture.table().await;
    let (metadata, rows) = fixture.physical_rows(pointer(&current)).await;
    assert_eq!(metadata["snapshots"].as_array().unwrap().len(), 32);
    assert_eq!(
        rows,
        (0..32)
            .map(|id| (id, format!("row-{id}")))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        fixture.physical_rows(pointer(&baseline)).await.1,
        [(0, "row-0".into())]
    );
    let writes = counter.writes.load(Ordering::Acquire);
    fixture.append(first_token, 0).await.unwrap();
    fixture.append(last_token, 31).await.unwrap();
    assert!(matches!(
        fixture.append(Uuid::new_v4(), 32).await,
        Err(iceberg::Error::Unsupported)
    ));
    assert_eq!(counter.writes.load(Ordering::Acquire), writes);
    assert_eq!(fixture.table().await, current);
    let mut pinned_metadata = metadata.clone();
    pinned_metadata["properties"] = json!({"locallycloud.firehose.snapshot-retention-enabled":"true", "history.expire.max-snapshot-age-ms":"1", "history.expire.min-snapshots-to-keep":"2"});
    for (index, snapshot) in metadata["snapshots"].as_array().unwrap().iter().enumerate() {
        if snapshot["snapshot-id"] != metadata["current-snapshot-id"] {
            pinned_metadata["refs"][format!("pin-{index}")] =
                json!({"snapshot-id":snapshot["snapshot-id"],"type":"tag"});
        }
    }
    let unchanged = fixture.replace_metadata(&pinned_metadata).await;
    let writes = counter.writes.load(Ordering::Acquire);
    assert!(matches!(
        fixture.append(Uuid::new_v4(), 32).await,
        Err(iceberg::Error::Unsupported)
    ));
    assert_eq!(counter.writes.load(Ordering::Acquire), writes);
    assert_eq!(fixture.table().await, unchanged);
}

#[tokio::test]
async fn opted_in_retention_preserves_pins_receipts_and_rejects_invalid_policy_before_writes() {
    let fixture = Fixture::new().await;
    let baseline = fixture.table().await;
    let mut metadata: Value =
        serde_json::from_slice(&fixture.get(pointer(&baseline)).await).unwrap();
    let pinned = metadata["current-snapshot-id"].clone();
    metadata["properties"] = json!({"locallycloud.firehose.snapshot-retention-enabled":"true", "history.expire.max-snapshot-age-ms":"1", "history.expire.min-snapshots-to-keep":"4"});
    metadata["refs"]["audit"] = json!({"snapshot-id":pinned,"type":"tag"});
    metadata["refs"]["branch"] = json!({"snapshot-id":pinned,"type":"branch"});
    fixture.replace_metadata(&metadata).await;
    let s3 = fixture.registry.lookup(&ServiceName::new("s3")).unwrap();
    let counter = Arc::new(CountHistoryReads {
        inner: s3.handler.unwrap(),
        reads: Mutex::default(),
        writes: AtomicUsize::new(0),
    });
    fixture
        .registry
        .register_native(ServiceName::new("s3"), s3.metadata, counter.clone());
    let first_token = Uuid::new_v4();
    fixture.append(first_token, 1).await.unwrap();
    let first = fixture.table().await;
    let first_metadata: Value =
        serde_json::from_slice(&fixture.get(pointer(&first)).await).unwrap();
    let expired_id = first_metadata["current-snapshot-id"].clone();
    let mut last_token = first_token;
    for id in 2..256 {
        last_token = Uuid::new_v4();
        fixture.append(last_token, id).await.unwrap();
    }
    let glue = fixture.registry.lookup(&ServiceName::new("glue")).unwrap();
    let gate = Arc::new(ConcurrentReads {
        inner: glue.handler.unwrap(),
        barrier: Barrier::new(2),
        reads: AtomicUsize::new(0),
        conflicts: AtomicUsize::new(0),
        versions: Mutex::new(Vec::new()),
    });
    fixture
        .registry
        .register_native(ServiceName::new("glue"), glue.metadata, gate.clone());
    let (left, right) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            fixture.append(Uuid::new_v4(), 256),
            fixture.append(Uuid::new_v4(), 257)
        )
    })
    .await
    .unwrap();
    left.unwrap();
    right.unwrap();
    assert_eq!(gate.conflicts.load(Ordering::Acquire), 1);
    let current = fixture.table().await;
    let (metadata, rows) = fixture.physical_rows(pointer(&current)).await;
    assert_eq!(metadata["last-sequence-number"], 258);
    let snapshot = metadata["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|snapshot| snapshot["snapshot-id"] == metadata["current-snapshot-id"])
        .unwrap();
    let list = fixture
        .get(snapshot["manifest-list"].as_str().unwrap())
        .await;
    let manifests = ManifestList::parse_with_version(&list, FormatVersion::V2)
        .unwrap()
        .consume_entries()
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(
        manifests.len(),
        2,
        "concurrent writers must reload the compacted list"
    );
    let merged = manifests
        .iter()
        .find(|manifest| manifest.existing_files_count == Some(256))
        .unwrap();
    let bytes = fixture.get(&merged.manifest_path).await;
    let entries = Manifest::parse_avro(&bytes).unwrap();
    let mut sequences = BTreeSet::new();
    for entry in entries
        .entries()
        .iter()
        .filter(|entry| entry.status == ::iceberg::spec::ManifestStatus::Existing)
    {
        assert!(entry.snapshot_id.is_some());
        assert_eq!(entry.sequence_number, entry.file_sequence_number);
        sequences.insert(entry.sequence_number.unwrap());
    }
    assert_eq!(sequences, (1..=256).collect());
    assert!(metadata["snapshots"].as_array().unwrap().len() <= 6);
    assert!(metadata["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["snapshot-id"] == pinned));
    assert!(!metadata["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["snapshot-id"] == expired_id));
    assert_eq!(metadata["refs"]["audit"]["snapshot-id"], pinned);
    assert_eq!(metadata["refs"]["branch"]["snapshot-id"], pinned);
    let receipts: Vec<String> = serde_json::from_str(
        metadata["properties"]["locallycloud.firehose.committed-batch-tokens"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(receipts.contains(&first_token.to_string()));
    assert_eq!(
        rows,
        (0..258)
            .map(|id| (id, format!("row-{id}")))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        fixture.physical_rows(pointer(&baseline)).await.1,
        [(0, "row-0".into())]
    );
    let writes = counter.writes.load(Ordering::Acquire);
    fixture.append(first_token, 1).await.unwrap();
    fixture.append(last_token, 255).await.unwrap();
    assert_eq!(fixture.table().await, current);
    assert_eq!(counter.writes.load(Ordering::Acquire), writes);
    let mut disabled = metadata.clone();
    disabled["properties"]["locallycloud.firehose.snapshot-retention-enabled"] = json!("false");
    let unchanged = fixture.replace_metadata(&disabled).await;
    let writes = counter.writes.load(Ordering::Acquire);
    fixture.append(first_token, 1).await.unwrap();
    assert_eq!(fixture.table().await, unchanged);
    assert_eq!(counter.writes.load(Ordering::Acquire), writes);
    for (key, value) in [
        ("locallycloud.firehose.snapshot-retention-enabled", "yes"),
        ("gc.enabled", "false"),
        ("history.expire.min-snapshots-to-keep", "0"),
        ("history.expire.max-snapshot-age-ms", "0"),
        (
            "locallycloud.firehose.committed-batch-tokens",
            "[\"invalid\"]",
        ),
    ] {
        let mut invalid = metadata.clone();
        invalid["properties"][key] = json!(value);
        let unchanged = fixture.replace_metadata(&invalid).await;
        let writes = counter.writes.load(Ordering::Acquire);
        assert!(matches!(
            fixture.append(Uuid::new_v4(), 99).await,
            Err(iceberg::Error::Unsupported)
        ));
        assert_eq!(fixture.table().await, unchanged);
        assert_eq!(counter.writes.load(Ordering::Acquire), writes);
    }
    let mut full = metadata.clone();
    let mut receipts = receipts;
    while receipts.len() < 256 {
        receipts.push(Uuid::new_v4().to_string());
    }
    full["properties"]["locallycloud.firehose.committed-batch-tokens"] =
        json!(serde_json::to_string(&receipts).unwrap());
    let mut oversized_location = full.clone();
    oversized_location["location"] = json!(format!("s3://ack-loss-lake/{}", "x".repeat(2048)));
    let unchanged = fixture.replace_metadata(&oversized_location).await;
    let writes = counter.writes.load(Ordering::Acquire);
    assert!(matches!(
        fixture.append(Uuid::new_v4(), 99).await,
        Err(iceberg::Error::Unsupported)
    ));
    assert_eq!(fixture.table().await, unchanged);
    assert_eq!(counter.writes.load(Ordering::Acquire), writes);
    let unchanged = fixture.replace_metadata(&full).await;
    let writes = counter.writes.load(Ordering::Acquire);
    fixture.append(Uuid::new_v4(), 99).await.unwrap();
    let migrated = fixture.table().await;
    assert_ne!(migrated, unchanged);
    let metadata: Value = serde_json::from_slice(&fixture.get(pointer(&migrated)).await).unwrap();
    assert!(metadata["properties"]
        .get("locallycloud.firehose.committed-batch-tokens")
        .is_none());
    assert!(metadata["properties"]["locallycloud.firehose.replay-index"].is_string());
    assert!(counter.writes.load(Ordering::Acquire) > writes);
    let writes = counter.writes.load(Ordering::Acquire);
    fixture.append(first_token, 1).await.unwrap();
    assert_eq!(fixture.table().await, migrated);
    assert_eq!(counter.writes.load(Ordering::Acquire), writes);
}

#[tokio::test]
async fn paged_receipts_preserve_old_replay_across_splits_cas_and_corruption() {
    let fixture = Fixture::new().await;
    let table = fixture.table().await;
    let mut metadata: Value = serde_json::from_slice(&fixture.get(pointer(&table)).await).unwrap();
    let first_token = Uuid::parse_str(
        metadata["snapshots"][0]["summary"]["locallycloud.batch-token"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    metadata["properties"] = json!({"locallycloud.firehose.snapshot-retention-enabled":"true", "history.expire.max-snapshot-age-ms":"1", "history.expire.min-snapshots-to-keep":"4"});
    fixture.replace_metadata(&metadata).await;
    let s3 = fixture.registry.lookup(&ServiceName::new("s3")).unwrap();
    let counter = Arc::new(CountHistoryReads {
        inner: s3.handler.unwrap(),
        reads: Mutex::default(),
        writes: AtomicUsize::new(0),
    });
    fixture
        .registry
        .register_native(ServiceName::new("s3"), s3.metadata, counter.clone());
    let mut historical = None;
    for id in 1..600 {
        fixture.append(Uuid::new_v4(), id).await.unwrap();
        if id == 270 {
            let table = fixture.table().await;
            let metadata: Value =
                serde_json::from_slice(&fixture.get(pointer(&table)).await).unwrap();
            let root: Value = serde_json::from_str(
                metadata["properties"]["locallycloud.firehose.replay-index"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            let uri = root["ranges"][0]["location"].as_str().unwrap().to_owned();
            let bytes = fixture.get(&uri).await;
            historical = Some((uri, bytes));
        }
    }
    let glue = fixture.registry.lookup(&ServiceName::new("glue")).unwrap();
    let gate = Arc::new(ConcurrentReads {
        inner: glue.handler.unwrap(),
        barrier: Barrier::new(2),
        reads: AtomicUsize::new(0),
        conflicts: AtomicUsize::new(0),
        versions: Mutex::new(Vec::new()),
    });
    fixture
        .registry
        .register_native(ServiceName::new("glue"), glue.metadata, gate.clone());
    let (left, right) = tokio::join!(
        fixture.append(Uuid::new_v4(), 600),
        fixture.append(Uuid::new_v4(), 601)
    );
    left.unwrap();
    right.unwrap();
    assert_eq!(gate.conflicts.load(Ordering::Acquire), 1);
    let current = fixture.table().await;
    let (mut metadata, rows) = fixture.physical_rows(pointer(&current)).await;
    assert_eq!(
        rows,
        (0..602)
            .map(|id| (id, format!("row-{id}")))
            .collect::<Vec<_>>()
    );
    let root: Value = serde_json::from_str(
        metadata["properties"]["locallycloud.firehose.replay-index"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mut archived = BTreeSet::new();
    for range in root["ranges"].as_array().unwrap() {
        let page: Value =
            serde_json::from_slice(&fixture.get(range["location"].as_str().unwrap()).await)
                .unwrap();
        let tokens = page["tokens"].as_array().unwrap();
        assert_eq!(tokens.len(), range["count"].as_u64().unwrap() as usize);
        assert!(tokens.len() <= 256);
        for token in tokens {
            assert!(archived.insert(token.as_str().unwrap().to_owned()));
        }
    }
    assert_eq!(
        archived.len(),
        602 - metadata["snapshots"].as_array().unwrap().len()
    );
    assert!(archived.contains(&first_token.to_string()));
    let (uri, bytes) = historical.unwrap();
    assert_eq!(
        fixture.get(&uri).await,
        bytes,
        "old published receipt pages are immutable"
    );
    metadata["properties"]["locallycloud.firehose.snapshot-retention-enabled"] = json!("false");
    let unchanged = fixture.replace_metadata(&metadata).await;
    counter.reads.lock().unwrap().clear();
    let writes = counter.writes.load(Ordering::Acquire);
    fixture.append(first_token, 0).await.unwrap();
    assert_eq!(fixture.table().await, unchanged);
    assert_eq!(counter.writes.load(Ordering::Acquire), writes);
    assert_eq!(
        counter
            .reads
            .lock()
            .unwrap()
            .iter()
            .filter(|(uri, _)| uri.contains("/firehose-replay/"))
            .map(|(_, count)| count)
            .sum::<usize>(),
        1
    );
    for field in ["table_uuid", "version", "ranges"] {
        let mut invalid_root = root.clone();
        invalid_root[field] = match field {
            "table_uuid" => json!(Uuid::new_v4().to_string()),
            "version" => json!(2),
            _ => json!([]),
        };
        let mut invalid = metadata.clone();
        invalid["properties"]["locallycloud.firehose.replay-index"] =
            json!(invalid_root.to_string());
        let unchanged = fixture.replace_metadata(&invalid).await;
        let writes = counter.writes.load(Ordering::Acquire);
        assert!(matches!(
            fixture.append(first_token, 0).await,
            Err(iceberg::Error::Unsupported)
        ));
        assert_eq!(fixture.table().await, unchanged);
        assert_eq!(counter.writes.load(Ordering::Acquire), writes);
    }
    for (field, value) in [
        (
            "location",
            json!("s3://other/metadata/firehose-replay/invalid.json"),
        ),
        ("count", json!(0)),
        ("lower", json!("invalid")),
    ] {
        let mut invalid_root = root.clone();
        invalid_root["ranges"][0][field] = value;
        let mut invalid = metadata.clone();
        invalid["properties"]["locallycloud.firehose.replay-index"] =
            json!(invalid_root.to_string());
        let unchanged = fixture.replace_metadata(&invalid).await;
        let writes = counter.writes.load(Ordering::Acquire);
        assert!(matches!(
            fixture.append(first_token, 0).await,
            Err(iceberg::Error::Unsupported)
        ));
        assert_eq!(fixture.table().await, unchanged);
        assert_eq!(counter.writes.load(Ordering::Acquire), writes);
    }
    let unchanged = fixture.replace_metadata(&metadata).await;
    let range = root["ranges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|range| {
            range["lower"].as_str().unwrap() <= first_token.to_string().as_str()
                && range["upper"].as_str().unwrap() >= first_token.to_string().as_str()
        })
        .unwrap();
    let location = range["location"].as_str().unwrap();
    let original = fixture.get(location).await;
    for body in [
        vec![b'x'; 16 * 1024 + 1],
        json!({"table_uuid":Uuid::new_v4(), "tokens":[]})
            .to_string()
            .into_bytes(),
    ] {
        let (status, _) = call(
            &fixture.dispatcher,
            Method::PUT,
            location.strip_prefix("s3:/").unwrap(),
            None,
            Bytes::from(body),
        )
        .await;
        assert!(status.is_success());
        let writes = counter.writes.load(Ordering::Acquire);
        assert!(fixture.append(first_token, 0).await.is_err());
        assert_eq!(fixture.table().await, unchanged);
        assert_eq!(counter.writes.load(Ordering::Acquire), writes);
    }
    let (status, _) = call(
        &fixture.dispatcher,
        Method::PUT,
        location.strip_prefix("s3:/").unwrap(),
        None,
        original,
    )
    .await;
    assert!(status.is_success());
    fixture.append(first_token, 0).await.unwrap();
}

#[tokio::test]
async fn full_receipt_index_rejects_split_before_writes_and_still_acknowledges_known_tokens() {
    let fixture = Fixture::new().await;
    fixture.append(Uuid::new_v4(), 1).await.unwrap();
    let table = fixture.table().await;
    let mut metadata: Value = serde_json::from_slice(&fixture.get(pointer(&table)).await).unwrap();
    let mut ranges = Vec::new();
    for page in 0..256 {
        let tokens: Vec<_> = (page * 256..(page + 1) * 256)
            .map(|id| Uuid::from_u128(id).to_string())
            .collect();
        let location = format!(
            "s3://ack-loss-lake/events/metadata/firehose-replay/{}.json",
            Uuid::new_v4()
        );
        let body = json!({"table_uuid":metadata["table-uuid"], "tokens":tokens});
        let (status, _) = call(
            &fixture.dispatcher,
            Method::PUT,
            location.strip_prefix("s3:/").unwrap(),
            None,
            Bytes::from(body.to_string()),
        )
        .await;
        assert!(status.is_success());
        ranges.push(json!({"lower":tokens.first().unwrap(), "upper":tokens.last().unwrap(), "count":256, "location":location}));
    }
    metadata["properties"] = json!({"locallycloud.firehose.snapshot-retention-enabled":"true", "history.expire.max-snapshot-age-ms":"1", "history.expire.min-snapshots-to-keep":"1", "locallycloud.firehose.replay-index":json!({"version":1,"table_uuid":metadata["table-uuid"],"ranges":ranges}).to_string()});
    let unchanged = fixture.replace_metadata(&metadata).await;
    let s3 = fixture.registry.lookup(&ServiceName::new("s3")).unwrap();
    let counter = Arc::new(CountHistoryReads {
        inner: s3.handler.unwrap(),
        reads: Mutex::default(),
        writes: AtomicUsize::new(0),
    });
    fixture
        .registry
        .register_native(ServiceName::new("s3"), s3.metadata, counter.clone());
    assert!(matches!(
        fixture.append(Uuid::new_v4(), 2).await,
        Err(iceberg::Error::Unsupported)
    ));
    assert_eq!(counter.writes.load(Ordering::Acquire), 0);
    assert_eq!(fixture.table().await, unchanged);
    fixture.append(Uuid::from_u128(42), 42).await.unwrap();
    assert_eq!(counter.writes.load(Ordering::Acquire), 0);
    assert_eq!(fixture.table().await, unchanged);
}

#[tokio::test]
async fn oversized_next_metadata_never_replaces_the_readable_catalog_pointer() {
    let fixture = Fixture::new().await;
    let baseline = fixture.table().await;
    let mut metadata: Value =
        serde_json::from_slice(&fixture.get(pointer(&baseline)).await).unwrap();
    metadata["properties"]["padding"] = json!("");
    let size = serde_json::to_vec(&metadata).unwrap().len();
    metadata["properties"]["padding"] = json!("x".repeat(12 * 1024 * 1024 - size - 1));
    assert_eq!(
        serde_json::to_vec(&metadata).unwrap().len(),
        12 * 1024 * 1024 - 1
    );
    let current = fixture.replace_metadata(&metadata).await;
    assert!(matches!(
        fixture.append(Uuid::new_v4(), 1).await,
        Err(iceberg::Error::Unsupported)
    ));
    assert_eq!(fixture.table().await, current);
    let (metadata, rows) = fixture.physical_rows(pointer(&current)).await;
    assert_eq!(metadata["last-sequence-number"], 1);
    assert_eq!(rows, [(0, "row-0".into())]);
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Stage {
    Data,
    Manifest,
    ManifestList,
    Metadata,
    Catalog,
    Receipt,
}

pub(super) struct FailOnce {
    pub(super) inner: Arc<dyn NativeHandler>,
    pub(super) stage: Stage,
    pub(super) after_write: bool,
    pub(super) fired: AtomicBool,
}

impl FailOnce {
    fn matches(&self, request: &ServiceRequest) -> bool {
        if self.stage == Stage::Catalog {
            return request
                .headers
                .get("x-amz-target")
                .is_some_and(|v| v == "AWSGlue.UpdateTable");
        }
        if request.method != Method::PUT {
            return false;
        }
        if self.stage == Stage::Receipt {
            return request.uri.path().contains("/firehose-replay/");
        }
        let suffixes = [
            (Stage::ManifestList, "-list.avro"),
            (Stage::Manifest, ".avro"),
            (Stage::Data, ".parquet"),
            (Stage::Metadata, ".metadata.json"),
        ];
        suffixes
            .iter()
            .find(|(_, suffix)| request.uri.path().ends_with(suffix))
            .is_some_and(|(stage, _)| *stage == self.stage)
    }
}

#[async_trait]
impl NativeHandler for FailOnce {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let fail = self.matches(&request) && !self.fired.swap(true, Ordering::AcqRel);
        if !fail {
            return self.inner.handle(request).await;
        }
        if self.after_write {
            let response = self.inner.handle(request).await;
            assert!(response.status().is_success());
        }
        let (content_type, body) = match self.stage {
            Stage::Catalog => (
                "application/x-amz-json-1.1",
                r#"{"__type":"ServiceUnavailableException"}"#,
            ),
            _ => (
                "application/xml",
                "<Error><Code>ServiceUnavailable</Code><Message>Injected failure</Message></Error>",
            ),
        };
        Response::builder()
            .status(503)
            .header("content-type", content_type)
            .body(Body::from(body))
            .unwrap()
    }
}

#[tokio::test]
async fn each_publication_failure_preserves_old_snapshot_and_replays_batch_once() {
    publication_failures(Maintenance::Disabled).await;
}

#[tokio::test]
async fn compaction_publication_failures_preserve_history_and_replay_once() {
    publication_failures(Maintenance::Compaction).await;
}

#[tokio::test]
async fn receipt_migration_publication_failures_do_not_prove_uncommitted_batches() {
    publication_failures(Maintenance::Receipts).await;
}

#[derive(Clone, Copy, PartialEq)]
enum Maintenance {
    Disabled,
    Compaction,
    Receipts,
}

async fn publication_failures(maintenance: Maintenance) {
    let stages = match maintenance {
        Maintenance::Receipts => vec![Stage::Receipt, Stage::Metadata, Stage::Catalog],
        Maintenance::Disabled | Maintenance::Compaction => vec![
            Stage::Data,
            Stage::Manifest,
            Stage::ManifestList,
            Stage::Metadata,
            Stage::Catalog,
        ],
    };
    for stage in stages {
        for after_write in [false, true] {
            let fixture = Fixture::new().await;
            let next_id = if maintenance != Maintenance::Disabled {
                let table = fixture.table().await;
                let mut metadata: Value =
                    serde_json::from_slice(&fixture.get(pointer(&table)).await).unwrap();
                metadata["properties"] = json!({"locallycloud.firehose.snapshot-retention-enabled":"true", "history.expire.max-snapshot-age-ms":"1", "history.expire.min-snapshots-to-keep":"4"});
                if maintenance == Maintenance::Receipts {
                    metadata["properties"]["locallycloud.firehose.committed-batch-tokens"] =
                        json!(serde_json::to_string(
                            &(0..256)
                                .map(|_| Uuid::new_v4().to_string())
                                .collect::<Vec<_>>()
                        )
                        .unwrap());
                    metadata["properties"]["history.expire.min-snapshots-to-keep"] = json!("1");
                }
                fixture.replace_metadata(&metadata).await;
                let next = if maintenance == Maintenance::Compaction {
                    16
                } else {
                    2
                };
                for id in 1..next {
                    fixture.append(Uuid::new_v4(), id).await.unwrap();
                }
                next
            } else {
                1
            };
            let previous_rows = (0..next_id)
                .map(|id| (id, format!("row-{id}")))
                .collect::<Vec<_>>();
            let expected_rows = (0..=next_id)
                .map(|id| (id, format!("row-{id}")))
                .collect::<Vec<_>>();
            let previous = fixture.table().await;
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
            fixture
                .registry
                .register_native(service, original.metadata, fault.clone());
            let token = Uuid::new_v4();
            assert!(
                matches!(
                    fixture.append(token, next_id).await,
                    Err(iceberg::Error::Transient)
                ),
                "{stage:?}, after={after_write}"
            );
            assert!(fault.fired.load(Ordering::Acquire));
            let failed = fixture.table().await;
            let visible = if stage == Stage::Catalog && after_write {
                assert_ne!(pointer(&failed), pointer(&previous));
                expected_rows.clone()
            } else {
                assert_eq!(failed, previous);
                previous_rows.clone()
            };
            assert_eq!(fixture.physical_rows(pointer(&failed)).await.1, visible);
            assert_eq!(
                fixture.physical_rows(pointer(&previous)).await.1,
                previous_rows
            );
            fixture.append(token, next_id).await.unwrap();
            let committed = fixture.table().await;
            let (metadata, rows) = fixture.physical_rows(pointer(&committed)).await;
            assert_eq!(rows, expected_rows);
            assert_eq!(metadata["last-sequence-number"], next_id + 1);
            if maintenance == Maintenance::Receipts {
                assert!(metadata["properties"]["locallycloud.firehose.replay-index"].is_string());
                assert!(metadata["properties"]
                    .get("locallycloud.firehose.committed-batch-tokens")
                    .is_none());
            }
            if maintenance == Maintenance::Compaction {
                let snapshot = metadata["snapshots"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|snapshot| snapshot["snapshot-id"] == metadata["current-snapshot-id"])
                    .unwrap();
                let bytes = fixture
                    .get(snapshot["manifest-list"].as_str().unwrap())
                    .await;
                assert_eq!(
                    ManifestList::parse_with_version(&bytes, FormatVersion::V2)
                        .unwrap()
                        .entries()
                        .len(),
                    1
                );
            }
            assert_eq!(
                metadata["snapshots"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|snapshot| snapshot["summary"]["locallycloud.batch-token"]
                        == token.to_string())
                    .count(),
                1
            );
            fixture.append(token, next_id).await.unwrap();
            assert_eq!(fixture.table().await, committed);
        }
    }
}
