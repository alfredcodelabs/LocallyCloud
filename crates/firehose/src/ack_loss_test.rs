//! Test-only lost Glue ACK after a committed Iceberg catalog update.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
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

async fn query_results(dispatcher: &InternalDispatcher, sql: &str) -> Value {
    let id = athena_call(dispatcher, "StartQueryExecution", json!({"QueryString":sql,"QueryExecutionContext":{"Database":"lake"},"ResultConfiguration":{"OutputLocation":format!("s3://{BUCKET}/query/")}})).await["QueryExecutionId"].as_str().unwrap().to_owned();
    for _ in 0..100 {
        let execution = athena_call(
            dispatcher,
            "GetQueryExecution",
            json!({"QueryExecutionId":id}),
        )
        .await;
        match execution["QueryExecution"]["Status"]["State"].as_str() {
            Some("SUCCEEDED") => {
                return athena_call(
                    dispatcher,
                    "GetQueryResults",
                    json!({"QueryExecutionId":id}),
                )
                .await
            }
            Some("FAILED" | "CANCELLED") => panic!("Athena failed: {execution}"),
            _ => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
    panic!("Athena query did not complete");
}

#[tokio::test]
async fn committed_glue_update_with_lost_ack_retries_once_without_duplicate_rows() {
    let registry = ServiceRegistry::with_known_services();
    locallycloud_s3::register(&registry);
    locallycloud_analytics::register(&registry);
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
        "last-column-id": 7, "current-schema-id": 0,
        "schemas": [{"type":"struct","schema-id":0,"fields":[
            {"id":1,"name":"id","required":true,"type":"long"},
            {"id":2,"name":"payload","required":false,"type":"string"},
            {"id":3,"name":"order_id","required":true,"type":"string"},
            {"id":4,"name":"total","required":true,"type":"decimal(18, 2)"},
            {"id":5,"name":"ordered_at","required":true,"type":"timestamptz"},
            {"id":6,"name":"order_date","required":true,"type":"date"},
            {"id":7,"name":"paid","required":true,"type":"boolean"}]}],
        "default-spec-id":0,"partition-specs":[{"spec-id":0,"fields":[{"source-id":6,"field-id":1000,"name":"order_day","transform":"identity"}]}],
        "last-partition-id":1000,"default-sort-order-id":0,
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
    let records = vec![br#"{"id":7,"payload":"once","order_id":"order-001","total":"90071992547409.93","ordered_at":"2026-10-03T16:00:00Z","order_date":"2026-10-03","paid":true}"#.to_vec()];
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
        committed_metadata["snapshots"][0]["summary"]["locallycloud.batch-token"],
        token.to_string()
    );
    // Add an optional field by ID, then read both the old and new physical schemas.
    let mut evolved = committed_metadata.clone();
    let mut schema = evolved["schemas"][0].clone();
    schema["schema-id"] = json!(1);
    schema["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":8,"name":"status","required":false,"type":"string"}));
    evolved["schemas"].as_array_mut().unwrap().push(schema);
    evolved["current-schema-id"] = json!(1);
    evolved["last-column-id"] = json!(8);
    let evolved_uri = format!("{root}/metadata/evolved.metadata.json");
    let (status, _) = call(
        &dispatcher,
        Method::PUT,
        &format!("/{BUCKET}/lake/events/metadata/evolved.metadata.json"),
        None,
        Bytes::from(evolved.to_string()),
    )
    .await;
    assert!(status.is_success());
    let current = json_call(
        &dispatcher,
        "GetTable",
        json!({"DatabaseName":"lake","Name":"events"}),
    )
    .await;
    let mut input = current["Table"].clone();
    for key in [
        "CatalogId",
        "DatabaseName",
        "CreateTime",
        "UpdateTime",
        "VersionId",
    ] {
        input.as_object_mut().unwrap().remove(key);
    }
    input["Parameters"]["metadata_location"] = json!(evolved_uri);
    json_call(&dispatcher, "UpdateTable", json!({"DatabaseName":"lake","TableInput":input,"VersionId":current["Table"]["VersionId"],"SkipArchive":true})).await;
    let second = br#"{"id":8,"payload":null,"order_id":"order-002","total":"10.25","ordered_at":"2026-10-04T16:00:00Z","order_date":"2026-10-04","paid":false,"status":"CANCELLED"}"#.to_vec();
    iceberg::append(context(), &target, Uuid::new_v4(), &[second])
        .await
        .unwrap();

    let query_id = athena_call(
        &dispatcher,
        "StartQueryExecution",
        json!({
            "QueryString":"SELECT id, payload, order_id, total, ordered_at, order_date, paid, status FROM lake.events WHERE total >= 0 AND order_date >= '2026-10-03'",
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
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[1]["Data"][0]["VarCharValue"], "7");
    assert_eq!(rows[1]["Data"][1]["VarCharValue"], "once");
    assert_eq!(rows[1]["Data"][2]["VarCharValue"], "order-001");
    assert_eq!(rows[1]["Data"][3]["VarCharValue"], "90071992547409.93");
    assert_eq!(rows[1]["Data"][4]["VarCharValue"], "2026-10-03T16:00:00Z");
    assert_eq!(rows[1]["Data"][5]["VarCharValue"], "2026-10-03");
    assert_eq!(rows[1]["Data"][6]["VarCharValue"], "true");
    assert!(rows[1]["Data"][7].get("VarCharValue").is_none());
    assert_eq!(rows[2]["Data"][3]["VarCharValue"], "10.25");
    assert_eq!(rows[2]["Data"][7]["VarCharValue"], "CANCELLED");
    // A pruned partition is never fetched: remove its file after validating its rows.
    let old_file = format!("/{BUCKET}/lake/events/data/{token}-2026-10-03.parquet");
    let (status, _) = call(&dispatcher, Method::DELETE, &old_file, None, Bytes::new()).await;
    assert!(status.is_success());
    let count = query_results(&dispatcher, "SELECT COUNT(*) AS orders FROM lake.events WHERE order_date = '2026-10-04' AND paid = false").await;
    assert_eq!(
        count["ResultSet"]["Rows"][1]["Data"][0]["VarCharValue"],
        "1"
    );
    let sum = query_results(
        &dispatcher,
        "SELECT SUM(total) AS amount FROM lake.events WHERE order_date = '2026-10-04'",
    )
    .await;
    assert_eq!(
        sum["ResultSet"]["Rows"][1]["Data"][0]["VarCharValue"],
        "10.25"
    );
}
