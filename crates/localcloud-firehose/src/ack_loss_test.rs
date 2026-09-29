//! Test-only lost Glue ACK after a committed Iceberg catalog update.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::integration::InternalDispatcher;
use localcloud_core::proxy::{LegacyHealth, ProxyConfig};
use localcloud_core::registry::{ServiceName, ServiceRegistry};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::iceberg::{self, Context, Target};

const ACCOUNT: &str = "000000000000";
const REGION: &str = "us-east-1";
const BUCKET: &str = "ack-loss-lake";

struct LoseFirstUpdateAck {
    glue: Arc<dyn NativeHandler>,
    lost: AtomicBool,
}

#[async_trait]
impl NativeHandler for LoseFirstUpdateAck {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let update = request
            .headers
            .get("x-amz-target")
            .is_some_and(|target| target == "AWSGlue.UpdateTable");
        let response = self.glue.handle(request).await;
        if update && response.status().is_success() && !self.lost.swap(true, Ordering::AcqRel) {
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("content-type", "application/x-amz-json-1.1")
                .body(Body::from(r#"{"__type":"ServiceUnavailableException"}"#))
                .unwrap();
        }
        response
    }
}

async fn call(
    dispatcher: &InternalDispatcher,
    method: Method,
    path: &str,
    target: Option<&str>,
    body: Bytes,
) -> (StatusCode, Bytes) {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_static(match target {
            Some(target) if target.starts_with("AmazonAthena.") => {
                "AWS4-HMAC-SHA256 Credential=test/19700101/us-east-1/athena/aws4_request"
            }
            Some(_) => "AWS4-HMAC-SHA256 Credential=test/19700101/us-east-1/glue/aws4_request",
            None => "AWS4-HMAC-SHA256 Credential=test/19700101/us-east-1/s3/aws4_request",
        }),
    );
    if let Some(target) = target {
        headers.insert("x-amz-target", HeaderValue::from_str(target).unwrap());
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-amz-json-1.1"),
        );
    }
    let uri: Uri = path.parse().unwrap();
    let response = dispatcher
        .dispatch_scoped(
            &method,
            &uri,
            &headers,
            body,
            &Uuid::new_v4().to_string(),
            ACCOUNT,
            REGION,
        )
        .await;
    let status = response.status();
    let body = to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    (status, body)
}

async fn json_call(dispatcher: &InternalDispatcher, operation: &str, body: Value) -> Value {
    let (status, body) = call(
        dispatcher,
        Method::POST,
        "/",
        Some(&format!("AWSGlue.{operation}")),
        Bytes::from(body.to_string()),
    )
    .await;
    assert!(
        status.is_success(),
        "{operation}: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).unwrap()
}

async fn athena_call(dispatcher: &InternalDispatcher, operation: &str, body: Value) -> Value {
    let (status, body) = call(
        dispatcher,
        Method::POST,
        "/",
        Some(&format!("AmazonAthena.{operation}")),
        Bytes::from(body.to_string()),
    )
    .await;
    assert!(
        status.is_success(),
        "{operation}: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn committed_glue_update_with_lost_ack_retries_once_without_duplicate_rows() {
    let registry = ServiceRegistry::with_known_services();
    localcloud_s3::register(&registry);
    localcloud_analytics::register(&registry);
    let glue_name = ServiceName::new("glue");
    let original = registry.lookup(&glue_name).unwrap();
    let lost_ack = Arc::new(LoseFirstUpdateAck {
        glue: original.handler.unwrap(),
        lost: AtomicBool::new(false),
    });
    registry.register_native(glue_name, original.metadata, lost_ack.clone());
    let dispatcher = Arc::new(InternalDispatcher::new_shared(
        &registry,
        ProxyConfig {
            backend_url: "http://127.0.0.1:1".into(),
            upstream_timeout: Duration::from_secs(2),
        },
        LegacyHealth::new(false),
        REGION.into(),
        ACCOUNT.into(),
    ));
    registry.set_internal_dispatcher(dispatcher.clone());
    let (status, _) = call(
        &dispatcher,
        Method::PUT,
        &format!("/{BUCKET}"),
        None,
        Bytes::new(),
    )
    .await;
    assert!(status.is_success());
    let root = format!("s3://{BUCKET}/lake/events");
    let initial_uri = format!("{root}/metadata/00000.metadata.json");
    let metadata = json!({
        "format-version": 2, "table-uuid": Uuid::new_v4().to_string(), "location": root,
        "last-sequence-number": 0, "last-updated-ms": 1,
        "last-column-id": 2, "current-schema-id": 0,
        "schemas": [{"type":"struct","schema-id":0,"fields":[
            {"id":1,"name":"id","required":true,"type":"long"},
            {"id":2,"name":"payload","required":false,"type":"string"}]}],
        "default-spec-id":0,"partition-specs":[{"spec-id":0,"fields":[]}],
        "last-partition-id":999,"default-sort-order-id":0,
        "sort-orders":[{"order-id":0,"fields":[]}],
        "properties":{},"snapshots":[],"snapshot-log":[],"metadata-log":[],"refs":{}
    });
    let metadata_path = format!("/{BUCKET}/lake/events/metadata/00000.metadata.json");
    let (status, _) = call(
        &dispatcher,
        Method::PUT,
        &metadata_path,
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
    json_call(
        &dispatcher,
        "CreateTable",
        json!({
            "DatabaseName":"lake", "TableInput":{
                "Name":"events", "TableType":"EXTERNAL_TABLE",
                "Parameters":{"table_type":"ICEBERG","metadata_location":initial_uri},
                "StorageDescriptor":{"Location":format!("{root}/")}
            }
        }),
    )
    .await;
    let target = Target {
        database: "lake".into(),
        table: "events".into(),
        bucket: BUCKET.into(),
    };
    let token = Uuid::new_v4();
    let records = vec![br#"{"id":7,"payload":"once"}"#.to_vec()];
    let context = || Context {
        dispatcher: &dispatcher,
        account: ACCOUNT,
        region: REGION,
        bucket: BUCKET,
    };
    assert!(matches!(
        iceberg::append(context(), &target, token, &records).await,
        Err(iceberg::Error::Transient)
    ));
    assert!(lost_ack.lost.load(Ordering::Acquire));
    let committed = json_call(
        &dispatcher,
        "GetTable",
        json!({"DatabaseName":"lake","Name":"events"}),
    )
    .await;
    let pointer = committed["Table"]["Parameters"]["metadata_location"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(pointer, initial_uri);
    iceberg::append(context(), &target, token, &records)
        .await
        .unwrap();
    let after_retry = json_call(
        &dispatcher,
        "GetTable",
        json!({"DatabaseName":"lake","Name":"events"}),
    )
    .await;
    assert_eq!(
        after_retry["Table"]["Parameters"]["metadata_location"],
        pointer
    );
    let key = pointer.strip_prefix(&format!("s3://{BUCKET}/")).unwrap();
    let (status, metadata_bytes) = call(
        &dispatcher,
        Method::GET,
        &format!("/{BUCKET}/{key}"),
        None,
        Bytes::new(),
    )
    .await;
    assert!(status.is_success());
    let committed_metadata: Value = serde_json::from_slice(&metadata_bytes).unwrap();
    assert_eq!(committed_metadata["snapshots"].as_array().unwrap().len(), 1);
    assert_eq!(
        committed_metadata["snapshots"][0]["summary"]["localcloud.batch-token"],
        token.to_string()
    );
    let query_id = athena_call(
        &dispatcher,
        "StartQueryExecution",
        json!({
            "QueryString":"SELECT id, payload FROM lake.events",
            "QueryExecutionContext":{"Database":"lake"},
            "ResultConfiguration":{"OutputLocation":format!("s3://{BUCKET}/query/")}
        }),
    )
    .await["QueryExecutionId"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut succeeded = false;
    for _ in 0..100 {
        let execution = athena_call(
            &dispatcher,
            "GetQueryExecution",
            json!({"QueryExecutionId":query_id}),
        )
        .await;
        match execution["QueryExecution"]["Status"]["State"].as_str() {
            Some("SUCCEEDED") => {
                succeeded = true;
                break;
            }
            Some("FAILED" | "CANCELLED") => panic!("Athena failed: {execution}"),
            _ => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
    assert!(succeeded, "Athena query did not finish");
    let results = athena_call(
        &dispatcher,
        "GetQueryResults",
        json!({"QueryExecutionId":query_id}),
    )
    .await;
    let rows = results["ResultSet"]["Rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["Data"][0]["VarCharValue"], "7");
    assert_eq!(rows[1]["Data"][1]["VarCharValue"], "once");
}
