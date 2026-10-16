//! Actual worker/journal replay after catalog commit but before acknowledgement.
use super::*;
use crate::ack_loss_test::{call, json_call, query_results};
use axum::response::Response;
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::ServiceName;

struct HoldFirstCommitAck {
    glue: Arc<dyn NativeHandler>,
    held: AtomicBool,
    committed: Notify,
}

#[async_trait]
impl NativeHandler for HoldFirstCommitAck {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let update = request
            .headers
            .get("x-amz-target")
            .is_some_and(|target| target == "AWSGlue.UpdateTable");
        let response = self.glue.handle(request).await;
        if update && response.status().is_success() && !self.held.swap(true, Ordering::AcqRel) {
            self.committed.notify_one();
            return std::future::pending().await;
        }
        response
    }
}

async fn firehose(dispatcher: &InternalDispatcher, operation: &str, body: Value) -> Value {
    let (status, bytes) = call(
        dispatcher,
        Method::POST,
        "/",
        Some(&format!("Firehose_20150804.{operation}")),
        Bytes::from(body.to_string()),
    )
    .await;
    assert!(
        status.is_success(),
        "{operation}: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn worker_restart_replays_committed_batch_without_duplicate_snapshot_or_rows() {
    // S3/Glue stay live here to isolate Firehose journal recovery; the public CLI
    // gate separately restarts the complete server and restores the Glue catalog.
    let registry = ServiceRegistry::with_known_services();
    locallycloud_s3::register(&registry);
    locallycloud_analytics::register(&registry);
    let glue = registry.lookup(&ServiceName::new("glue")).unwrap();
    let held = Arc::new(HoldFirstCommitAck {
        glue: glue.handler.unwrap(),
        held: AtomicBool::new(false),
        committed: Notify::new(),
    });
    registry.register_native(ServiceName::new("glue"), glue.metadata, held.clone());
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
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/firehose-tests")
        .join(Uuid::new_v4().to_string());
    let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
    let (handler, handle) =
        FirehoseHandler::with_state(Arc::downgrade(&registry), state.clone()).unwrap();
    crate::register_handler(&registry, handler);
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
        "Name":"events","TableType":"EXTERNAL_TABLE","Parameters":{"table_type":"ICEBERG","metadata_location":"s3://ack-loss-lake/events/metadata/initial.json"},
        "StorageDescriptor":{"Location":"s3://ack-loss-lake/events/"}
    }})).await;
    let role = "arn:aws:iam::000000000000:role/firehose";
    firehose(&dispatcher, "CreateDeliveryStream", json!({"DeliveryStreamName":"journal-stream","IcebergDestinationConfiguration":{
        "CatalogConfiguration":{"CatalogARN":"arn:aws:glue:us-east-1:000000000000:catalog"},
        "RoleARN":role,"S3Configuration":{"BucketARN":"arn:aws:s3:::ack-loss-lake","RoleARN":role},
        "AppendOnly":true,"DestinationTableConfigurationList":[{"DestinationDatabaseName":"lake","DestinationTableName":"events"}]
    }})).await;
    firehose(&dispatcher, "PutRecord", json!({"DeliveryStreamName":"journal-stream","Record":{"Data":base64::engine::general_purpose::STANDARD.encode(br#"{"id":7,"payload":"once"}"#)}})).await;
    tokio::time::timeout(Duration::from_secs(5), held.committed.notified())
        .await
        .unwrap();
    let committed = json_call(
        &dispatcher,
        "GetTable",
        json!({"DatabaseName":"lake","Name":"events"}),
    )
    .await;

    let journal = state.clone();
    let token: String = tokio::task::spawn_blocking(move || {
        journal
            .connection()
            .unwrap()
            .query_row(
                "SELECT token FROM firehose_records WHERE state='inflight'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    })
    .await
    .unwrap();
    // Cancel the real worker while it is awaiting ACK: no completion/requeue runs.
    let worker = handle.inner.worker.lock().unwrap().take().unwrap();
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    drop(handle);
    let (handler, resumed) =
        FirehoseHandler::with_state(Arc::downgrade(&registry), state.clone()).unwrap();
    crate::register_handler(&registry, handler);
    {
        let streams = resumed.inner.lock_streams().unwrap();
        let replay = streams.values().next().unwrap();
        assert_eq!(replay.retained.len(), 1);
        assert_eq!(replay.retry_token, Some(Uuid::parse_str(&token).unwrap()));
        assert!(replay.in_flight.is_none());
    }
    resumed.resume().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let state = state.clone();
            let remaining: i64 = tokio::task::spawn_blocking(move || {
                state
                    .connection()
                    .unwrap()
                    .query_row("SELECT COUNT(*) FROM firehose_records", [], |row| {
                        row.get(0)
                    })
                    .unwrap()
            })
            .await
            .unwrap();
            if remaining == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let recovered = json_call(
        &dispatcher,
        "GetTable",
        json!({"DatabaseName":"lake","Name":"events"}),
    )
    .await;
    assert_eq!(recovered, committed);
    let pointer = recovered["Table"]["Parameters"]["metadata_location"]
        .as_str()
        .unwrap();
    let path = pointer.strip_prefix("s3:/").unwrap();
    let (status, body) = call(&dispatcher, Method::GET, path, None, Bytes::new()).await;
    assert!(status.is_success());
    let metadata: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(metadata["snapshots"].as_array().unwrap().len(), 1);
    assert_eq!(
        metadata["snapshots"][0]["summary"]["locallycloud.batch-token"],
        token
    );
    let result = query_results(&dispatcher, "SELECT id, payload FROM lake.events").await;
    let rows = result["ResultSet"]["Rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["Data"][0]["VarCharValue"], "7");
    assert_eq!(rows[1]["Data"][1]["VarCharValue"], "once");
    resumed.shutdown().await;
    std::fs::remove_dir_all(root).unwrap();
}
