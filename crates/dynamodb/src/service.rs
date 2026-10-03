//! DynamoDB and DynamoDB Streams JSON 1.0 handlers.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use serde_json::Value;

use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::AuthorizationRequest;
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_state::StateDb;

use crate::error::DdbError;
use crate::ops::{self, Ctx};
use crate::partiql;
use crate::store::TableStore;
use crate::streams;

const TARGET_PREFIX: &str = "DynamoDB_20120810";
const STREAMS_TARGET_PREFIX: &str = "DynamoDBStreams_20120810";

/// The natively-implemented DynamoDB service.
pub struct DynamoHandler {
    store: Arc<TableStore>,
    registry: Weak<ServiceRegistry>,
    reaper_started: AtomicBool,
}

/// DynamoDB Streams uses a separate target prefix while sharing the same table store.
pub struct StreamsHandler {
    store: Arc<TableStore>,
}

impl Default for DynamoHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamoHandler {
    pub fn new() -> Self {
        Self::with_store(Arc::new(TableStore::new()), Weak::new())
    }

    fn with_store(store: Arc<TableStore>, registry: Weak<ServiceRegistry>) -> Self {
        DynamoHandler {
            store,
            registry,
            reaper_started: AtomicBool::new(false),
        }
    }

    /// Return a Streams handler over the same in-memory state (used by direct integration tests).
    pub fn streams_handler(&self) -> StreamsHandler {
        StreamsHandler {
            store: self.store.clone(),
        }
    }

    fn ensure_reaper(&self) {
        if self
            .reaper_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let store = Arc::downgrade(&self.store);
        let registry = self.registry.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                let Some(store) = store.upgrade() else {
                    break;
                };
                ops::run_maintenance(&store, &registry).await;
            }
        });
    }

    async fn dispatch(&self, op: &str, ctx: &Ctx<'_>, body: &Value) -> Result<Value, DdbError> {
        match op {
            "CreateTable" => ops::create_table(ctx, body).await,
            "DescribeTable" => ops::describe_table(ctx, body).await,
            "UpdateTable" => ops::update_table(ctx, body).await,
            "DeleteTable" => ops::delete_table(ctx, body).await,
            "ListTables" => ops::list_tables(ctx, body).await,
            "PutItem" => ops::put_item(ctx, body).await,
            "GetItem" => ops::get_item(ctx, body).await,
            "DeleteItem" => ops::delete_item(ctx, body).await,
            "UpdateItem" => ops::update_item(ctx, body).await,
            "Query" => ops::query(ctx, body).await,
            "Scan" => ops::scan(ctx, body).await,
            "BatchWriteItem" => ops::batch_write_item(ctx, body).await,
            "BatchGetItem" => ops::batch_get_item(ctx, body).await,
            "TransactWriteItems" => ops::transact_write_items(ctx, body).await,
            "TransactGetItems" => ops::transact_get_items(ctx, body).await,
            "DescribeTimeToLive" => ops::describe_time_to_live(ctx, body).await,
            "UpdateTimeToLive" => ops::update_time_to_live(ctx, body).await,
            "DescribeContinuousBackups" => ops::describe_continuous_backups(ctx, body).await,
            "UpdateContinuousBackups" => ops::update_continuous_backups(ctx, body).await,
            "ListTagsOfResource" => ops::list_tags_of_resource(ctx, body).await,
            "TagResource" => ops::tag_resource(ctx, body).await,
            "UntagResource" => ops::untag_resource(ctx, body).await,
            "EnableKinesisStreamingDestination" => {
                ops::enable_kinesis_streaming_destination(ctx, body).await
            }
            "DisableKinesisStreamingDestination" => {
                ops::disable_kinesis_streaming_destination(ctx, body).await
            }
            "DescribeKinesisStreamingDestination" => {
                ops::describe_kinesis_streaming_destination(ctx, body).await
            }
            "ExportTableToPointInTime" => ops::export_table_to_point_in_time(ctx, body).await,
            "DescribeExport" => ops::describe_export(ctx, body).await,
            "ListExports" => ops::list_exports(ctx, body).await,
            "ExecuteStatement" => partiql::execute_statement(ctx, body).await,
            "ExecuteTransaction" => partiql::execute_transaction(ctx, body).await,
            "BatchExecuteStatement" => partiql::batch_execute_statement(ctx, body).await,
            other => Err(DdbError::UnknownOperation(format!(
                "unsupported operation {other}"
            ))),
        }
    }
}

fn operation(request: &ServiceRequest, prefix: &str) -> Option<String> {
    let target = request.headers.get("x-amz-target")?.to_str().ok()?;
    let op = target.strip_prefix(prefix)?.strip_prefix('.')?;
    (!op.is_empty() && !op.contains('.')).then(|| op.to_string())
}

fn parse_body(request: &ServiceRequest) -> Result<Value, DdbError> {
    let body = if request.body.is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_slice(&request.body)
            .map_err(|e| DdbError::Validation(format!("invalid JSON body: {e}")))?
    };
    if !body.is_object() {
        return Err(DdbError::Validation(
            "request body must be a JSON object".into(),
        ));
    }
    Ok(body)
}

fn context<'a>(store: &'a TableStore, request: &'a ServiceRequest) -> Ctx<'a> {
    Ctx {
        store,
        region: &request.region,
        account: &request.account_id,
    }
}

fn authorize(
    registry: &Weak<ServiceRegistry>,
    request: &ServiceRequest,
    op: &str,
    body: &Value,
) -> Result<(), DdbError> {
    let Some(registry) = registry.upgrade() else {
        return Ok(());
    };
    let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
        return Ok(());
    };
    if !evaluator.strict_sigv4_required() {
        return Ok(());
    }
    // Core rejects unsigned external requests in strict mode. Requests that reach
    // this handler without a signature are internal service calls.
    let Some(access_key) = request
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(RequestIdentity::access_key_from_authorization)
    else {
        return Ok(());
    };
    for (action, table) in authorization_targets(op, body)? {
        let resource = if table == "*" {
            table
        } else {
            let table_arn = if table.starts_with("arn:") {
                table
            } else {
                format!(
                    "arn:aws:dynamodb:{}:{}:table/{table}",
                    request.region, request.account_id
                )
            };
            if matches!(op, "Query" | "Scan") {
                body.get("IndexName")
                    .and_then(Value::as_str)
                    .map(|index| format!("{table_arn}/index/{index}"))
                    .unwrap_or(table_arn)
            } else {
                table_arn
            }
        };
        evaluator
            .authorize(AuthorizationRequest {
                request_identity: RequestIdentity {
                    account_id: request.account_id.clone(),
                    access_key_id: Some(access_key.clone()),
                    arn: None,
                },
                delegated_identity: None,
                source_service: "dynamodb".into(),
                action: format!("dynamodb:{action}"),
                resource,
                context: Default::default(),
            })
            .map_err(|_| {
                DdbError::AccessDenied(format!("not authorized to perform dynamodb:{action}"))
            })?;
    }
    Ok(())
}

fn authorization_targets(op: &str, body: &Value) -> Result<Vec<(String, String)>, DdbError> {
    let mut targets = Vec::new();
    match op {
        "BatchGetItem" | "BatchWriteItem" => {
            let items = body
                .get("RequestItems")
                .and_then(Value::as_object)
                .ok_or_else(|| DdbError::Validation("RequestItems is required".into()))?;
            targets.extend(items.keys().map(|table| (op.to_string(), table.clone())));
        }
        "TransactGetItems" | "TransactWriteItems" => {
            let items = body
                .get("TransactItems")
                .and_then(Value::as_array)
                .ok_or_else(|| DdbError::Validation("TransactItems is required".into()))?;
            for item in items {
                let action = if op == "TransactGetItems" {
                    "Get"
                } else {
                    ["Put", "Update", "Delete", "ConditionCheck"]
                        .iter()
                        .find(|action| item.get(**action).is_some())
                        .copied()
                        .ok_or_else(|| DdbError::Validation("invalid transaction action".into()))?
                };
                let table = item
                    .get(action)
                    .and_then(|value| value.get("TableName"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| DdbError::Validation("TableName is required".into()))?;
                let iam_action = match action {
                    "Get" => "GetItem",
                    "Put" => "PutItem",
                    "Update" => "UpdateItem",
                    "Delete" => "DeleteItem",
                    _ => "ConditionCheckItem",
                };
                targets.push((iam_action.into(), table.into()));
            }
        }
        "ExecuteStatement" | "ExecuteTransaction" | "BatchExecuteStatement" => {
            targets = partiql::authorization_targets(op, body)?;
        }
        _ => {
            let table = body
                .get("TableName")
                .or_else(|| body.get("ResourceArn"))
                .or_else(|| body.get("TableArn"))
                .and_then(Value::as_str)
                .unwrap_or("*");
            targets.push((op.into(), table.into()));
        }
    }
    Ok(targets)
}

#[async_trait]
impl NativeHandler for DynamoHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        self.ensure_reaper();
        let op = match operation(&request, TARGET_PREFIX) {
            Some(op) => op,
            None => {
                return DdbError::UnknownOperation(
                    "invalid or missing DynamoDB X-Amz-Target".into(),
                )
                .into_response(&request.request_id)
            }
        };
        let body = match parse_body(&request) {
            Ok(body) => body,
            Err(err) => return err.into_response(&request.request_id),
        };
        if let Err(error) = authorize(&self.registry, &request, &op, &body) {
            return error.into_response(&request.request_id);
        }
        let _gate = self.store.operation_gate.lock().await;
        if self.store.has_uncommitted() {
            if let Err(err) = self.store.persist().await {
                return err.into_response(&request.request_id);
            }
        }
        let read_only = matches!(
            op.as_str(),
            "DescribeTable"
                | "ListTables"
                | "GetItem"
                | "Query"
                | "Scan"
                | "BatchGetItem"
                | "TransactGetItems"
                | "DescribeTimeToLive"
                | "DescribeContinuousBackups"
                | "ListTagsOfResource"
                | "DescribeKinesisStreamingDestination"
                | "DescribeExport"
                | "ListExports"
        );
        let may_mutate = !read_only || matches!(op.as_str(), "GetItem" | "Query" | "Scan");
        if may_mutate {
            self.store.mark_uncommitted();
        }
        let result = self
            .dispatch(&op, &context(&self.store, &request), &body)
            .await;
        if may_mutate || self.store.has_dirty_items().await {
            if let Err(err) = self.store.persist().await {
                return err.into_response(&request.request_id);
            }
        }
        match result {
            Ok(value) => json_response(value),
            Err(err) => err.into_response(&request.request_id),
        }
    }
}

#[async_trait]
impl NativeHandler for StreamsHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let op = match operation(&request, STREAMS_TARGET_PREFIX) {
            Some(op) => op,
            None => {
                return DdbError::UnknownOperation(
                    "invalid or missing DynamoDB Streams X-Amz-Target".into(),
                )
                .into_response(&request.request_id)
            }
        };
        let body = match parse_body(&request) {
            Ok(body) => body,
            Err(err) => return err.into_response(&request.request_id),
        };
        let _gate = self.store.operation_gate.lock().await;
        if self.store.has_uncommitted() {
            if let Err(err) = self.store.persist().await {
                return err.into_response(&request.request_id);
            }
        }
        let ctx = context(&self.store, &request);
        let result = match op.as_str() {
            "ListStreams" => streams::list_streams(&ctx, &body).await,
            "DescribeStream" => streams::describe_stream(&ctx, &body).await,
            "GetShardIterator" => streams::get_shard_iterator(&ctx, &body).await,
            "GetRecords" => streams::get_records(&ctx, &body).await,
            other => Err(DdbError::UnknownOperation(format!(
                "unsupported operation {other}"
            ))),
        };
        match result {
            Ok(value) => json_response(value),
            Err(err) => err.into_response(&request.request_id),
        }
    }
}

fn json_response(value: Value) -> Response {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/x-amz-json-1.0")
        .body(Body::from(value.to_string()))
        .expect("json 1.0 response is always valid")
}

/// Register DynamoDB and DynamoDB Streams as separate Native JSON 1.0 services.
pub fn register(registry: &Arc<ServiceRegistry>) {
    register_store(registry, Arc::new(TableStore::new()));
}

pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    state: Arc<StateDb>,
) -> Result<(), DdbError> {
    register_store(registry, Arc::new(TableStore::with_state(state)?));
    Ok(())
}

fn register_store(registry: &Arc<ServiceRegistry>, store: Arc<TableStore>) {
    let registry_ref = Arc::downgrade(registry);
    registry.register_native(
        ServiceName::new("dynamodb"),
        ServiceMetadata::new(AwsProtocol::Json10, Some(TARGET_PREFIX)),
        Arc::new(DynamoHandler::with_store(
            store.clone(),
            registry_ref.clone(),
        )),
    );
    registry.register_native(
        ServiceName::new("streams.dynamodb"),
        ServiceMetadata::new(AwsProtocol::Json10, Some(STREAMS_TARGET_PREFIX)),
        Arc::new(StreamsHandler { store }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method};
    use std::sync::Mutex;

    #[derive(Default)]
    struct KinesisRecorder {
        requests: Mutex<Vec<ServiceRequest>>,
    }

    #[async_trait]
    impl NativeHandler for KinesisRecorder {
        async fn handle(&self, request: ServiceRequest) -> Response {
            self.requests.lock().unwrap().push(request);
            http::Response::builder()
                .status(200)
                .body(Body::from(r#"{"SequenceNumber":"1","ShardId":"shard-0"}"#))
                .unwrap()
        }
    }

    fn request_with_prefix(prefix: &str, op: &str, body: &str) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("{prefix}.{op}")).unwrap(),
        );
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::copy_from_slice(body.as_bytes()),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        }
    }

    fn request(op: &str, body: &str) -> ServiceRequest {
        request_with_prefix(TARGET_PREFIX, op, body)
    }

    async fn call(h: &DynamoHandler, op: &str, body: &str) -> Response {
        h.handle(request(op, body)).await
    }

    #[tokio::test]
    async fn table_and_item_lifecycle() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        assert_eq!(call(&h, "CreateTable", create).await.status(), 200);

        let put = r#"{"TableName":"t","Item":{"id":{"S":"a"},"n":{"N":"1"}}}"#;
        assert_eq!(call(&h, "PutItem", put).await.status(), 200);

        let get = r#"{"TableName":"t","Key":{"id":{"S":"a"}}}"#;
        let resp = call(&h, "GetItem", get).await;
        assert_eq!(resp.status(), 200);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["Item"]["n"]["N"], "1");
    }

    #[tokio::test]
    async fn acknowledged_api_writes_survive_restart() {
        let root = std::env::temp_dir().join(format!(
            "locallycloud-ddb-api-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let h = DynamoHandler::with_store(
            Arc::new(TableStore::with_state(state.clone()).unwrap()),
            Weak::new(),
        );
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST","StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_AND_OLD_IMAGES"}}"#;
        assert_eq!(call(&h, "CreateTable", create).await.status(), 200);
        assert_eq!(
            call(
                &h,
                "PutItem",
                r#"{"TableName":"t","Item":{"id":{"S":"a"},"n":{"N":"1"}}}"#
            )
            .await
            .status(),
            200
        );
        let transaction = r#"{"ClientRequestToken":"restart-token","TransactItems":[{"Put":{"TableName":"t","Item":{"id":{"S":"b"}}}}]}"#;
        assert_eq!(
            call(&h, "TransactWriteItems", transaction).await.status(),
            200
        );
        drop(h);
        let h = DynamoHandler::with_store(
            Arc::new(TableStore::with_state(state).unwrap()),
            Weak::new(),
        );
        let (status, body) =
            call_json(&h, "GetItem", r#"{"TableName":"t","Key":{"id":{"S":"a"}}}"#).await;
        assert_eq!(status, 200);
        assert_eq!(body["Item"]["n"]["N"], "1");
        assert_eq!(
            call(&h, "TransactWriteItems", transaction).await.status(),
            200
        );
        let table = h.store.get("000000000000", "us-east-1", "t").unwrap();
        assert_eq!(table.read().await.stream_seq, 2);
        drop(h);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn cancelled_metadata_commit_is_flushed_before_read() {
        let root = std::env::temp_dir().join(format!(
            "locallycloud-ddb-poison-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let store = Arc::new(TableStore::with_state(state.clone()).unwrap());
        let h = DynamoHandler::with_store(store.clone(), Weak::new());
        // Keep this test deterministic: no maintenance task can commit the simulated cancelled write.
        h.reaper_started.store(true, Ordering::Release);
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        assert_eq!(call(&h, "CreateTable", create).await.status(), 200);
        store.mark_uncommitted();
        store
            .get("000000000000", "us-east-1", "t")
            .unwrap()
            .write()
            .await
            .def
            .billing_mode = "PROVISIONED".into();
        let (status, body) = call_json(&h, "DescribeTable", r#"{"TableName":"t"}"#).await;
        assert_eq!(status, 200);
        assert_eq!(
            body["Table"]["BillingModeSummary"]["BillingMode"],
            "PROVISIONED"
        );
        assert!(!store.has_uncommitted());
        drop(h);
        drop(store);
        let reopened = TableStore::with_state(state).unwrap();
        assert_eq!(
            reopened
                .get("000000000000", "us-east-1", "t")
                .unwrap()
                .read()
                .await
                .def
                .billing_mode,
            "PROVISIONED"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn rejected_metadata_update_keeps_original_definition() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        assert_eq!(call(&h, "CreateTable", create).await.status(), 200);
        let rejected = r#"{"TableName":"t","BillingMode":"PROVISIONED","ProvisionedThroughput":{"ReadCapacityUnits":1,"WriteCapacityUnits":1},"GlobalSecondaryIndexUpdates":[{"Delete":{"IndexName":"missing"}}]}"#;
        assert_eq!(call(&h, "UpdateTable", rejected).await.status(), 400);
        let (_, body) = call_json(&h, "DescribeTable", r#"{"TableName":"t"}"#).await;
        assert_eq!(
            body["Table"]["BillingModeSummary"]["BillingMode"],
            "PAY_PER_REQUEST"
        );
    }

    #[tokio::test]
    async fn get_missing_table_is_400_resource_not_found() {
        let h = DynamoHandler::new();
        let resp = call(
            &h,
            "GetItem",
            r#"{"TableName":"nope","Key":{"id":{"S":"a"}}}"#,
        )
        .await;
        assert_eq!(resp.status(), 400);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["__type"]
            .as_str()
            .unwrap()
            .contains("ResourceNotFoundException"));
    }

    #[tokio::test]
    async fn conditional_put_fails_when_exists() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        call(&h, "CreateTable", create).await;
        let put = r#"{"TableName":"t","Item":{"id":{"S":"a"}}}"#;
        call(&h, "PutItem", put).await;
        let cond = r#"{"TableName":"t","Item":{"id":{"S":"a"}},"ConditionExpression":"attribute_not_exists(id)"}"#;
        let resp = call(&h, "PutItem", cond).await;
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn unknown_operation_is_400() {
        let h = DynamoHandler::new();
        assert_eq!(call(&h, "Frobnicate", "{}").await.status(), 400);
    }

    async fn call_json(h: &DynamoHandler, op: &str, body: &str) -> (u16, Value) {
        let resp = if matches!(
            op,
            "ListStreams" | "DescribeStream" | "GetShardIterator" | "GetRecords"
        ) {
            h.streams_handler()
                .handle(request_with_prefix(STREAMS_TARGET_PREFIX, op, body))
                .await
        } else {
            call(h, op, body).await
        };
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn create_provisioned(h: &DynamoHandler) {
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PROVISIONED","ProvisionedThroughput":{"ReadCapacityUnits":5,"WriteCapacityUnits":5}}"#;
        assert_eq!(call(h, "CreateTable", create).await.status(), 200);
    }

    #[tokio::test]
    async fn update_table_throughput_and_gsi_lifecycle() {
        let h = DynamoHandler::new();
        create_provisioned(&h).await;

        // Bump throughput.
        let (s, v) = call_json(
            &h,
            "UpdateTable",
            r#"{"TableName":"t","ProvisionedThroughput":{"ReadCapacityUnits":10,"WriteCapacityUnits":20}}"#,
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(
            v["TableDescription"]["ProvisionedThroughput"]["ReadCapacityUnits"],
            10
        );
        assert_eq!(
            v["TableDescription"]["ProvisionedThroughput"]["WriteCapacityUnits"],
            20
        );

        // Create a GSI (new attribute definition supplied).
        let create_gsi = r#"{"TableName":"t","AttributeDefinitions":[{"AttributeName":"gsk","AttributeType":"S"}],"GlobalSecondaryIndexUpdates":[{"Create":{"IndexName":"gsi1","KeySchema":[{"AttributeName":"gsk","KeyType":"HASH"}],"Projection":{"ProjectionType":"ALL"}}}]}"#;
        let (s, v) = call_json(&h, "UpdateTable", create_gsi).await;
        assert_eq!(s, 200);
        assert_eq!(
            v["TableDescription"]["GlobalSecondaryIndexes"][0]["IndexName"],
            "gsi1"
        );

        // Creating the same GSI again is rejected.
        let (s, _) = call_json(&h, "UpdateTable", create_gsi).await;
        assert_eq!(s, 400);

        // Delete the GSI.
        let (s, v) = call_json(
            &h,
            "UpdateTable",
            r#"{"TableName":"t","GlobalSecondaryIndexUpdates":[{"Delete":{"IndexName":"gsi1"}}]}"#,
        )
        .await;
        assert_eq!(s, 200);
        assert!(v["TableDescription"]
            .get("GlobalSecondaryIndexes")
            .is_none());

        // Deleting a missing GSI is a 400 (ResourceNotFound).
        let (s, _) = call_json(
            &h,
            "UpdateTable",
            r#"{"TableName":"t","GlobalSecondaryIndexUpdates":[{"Delete":{"IndexName":"nope"}}]}"#,
        )
        .await;
        assert_eq!(s, 400);
    }

    #[tokio::test]
    async fn update_table_stream_enable_disable() {
        let h = DynamoHandler::new();
        create_provisioned(&h).await;
        let (s, v) = call_json(
            &h,
            "UpdateTable",
            r#"{"TableName":"t","StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_AND_OLD_IMAGES"}}"#,
        )
        .await;
        assert_eq!(s, 200);
        assert!(v["TableDescription"]["LatestStreamArn"]
            .as_str()
            .unwrap()
            .contains("/stream/"));
        // Disable.
        let (s, v) = call_json(
            &h,
            "UpdateTable",
            r#"{"TableName":"t","StreamSpecification":{"StreamEnabled":false}}"#,
        )
        .await;
        assert_eq!(s, 200);
        assert!(v["TableDescription"].get("LatestStreamArn").is_none());
    }

    #[tokio::test]
    async fn update_table_switch_to_provisioned_requires_throughput() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        call(&h, "CreateTable", create).await;
        let (s, _) = call_json(
            &h,
            "UpdateTable",
            r#"{"TableName":"t","BillingMode":"PROVISIONED"}"#,
        )
        .await;
        assert_eq!(s, 400);
    }

    #[tokio::test]
    async fn legacy_expected_value_and_exists() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        call(&h, "CreateTable", create).await;
        call(
            &h,
            "PutItem",
            r#"{"TableName":"t","Item":{"id":{"S":"a"},"v":{"N":"1"}}}"#,
        )
        .await;

        // Expected: v == 1 → succeeds (update v to 2).
        let ok = r#"{"TableName":"t","Item":{"id":{"S":"a"},"v":{"N":"2"}},"Expected":{"v":{"Value":{"N":"1"}}}}"#;
        let (s, _) = call_json(&h, "PutItem", ok).await;
        assert_eq!(s, 200);

        // Expected: v == 1 now fails (v is 2).
        let stale = r#"{"TableName":"t","Item":{"id":{"S":"a"},"v":{"N":"9"}},"Expected":{"v":{"Value":{"N":"1"}}}}"#;
        let (s, v) = call_json(&h, "PutItem", stale).await;
        assert_eq!(s, 400);
        assert!(v["__type"]
            .as_str()
            .unwrap()
            .contains("ConditionalCheckFailedException"));

        // Expected: id must not exist → fails for an existing item.
        let exists =
            r#"{"TableName":"t","Item":{"id":{"S":"a"}},"Expected":{"id":{"Exists":false}}}"#;
        let (s, _) = call_json(&h, "PutItem", exists).await;
        assert_eq!(s, 400);
    }

    #[tokio::test]
    async fn legacy_expected_comparison_operator_and_or() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        call(&h, "CreateTable", create).await;
        call(
            &h,
            "PutItem",
            r#"{"TableName":"t","Item":{"id":{"S":"a"},"n":{"N":"5"}}}"#,
        )
        .await;

        // GT 3 (true) AND NOT_NULL n (true) → delete succeeds.
        let del = r#"{"TableName":"t","Key":{"id":{"S":"a"}},"Expected":{"n":{"ComparisonOperator":"GT","AttributeValueList":[{"N":"3"}]},"id":{"ComparisonOperator":"NOT_NULL"}}}"#;
        let (s, _) = call_json(&h, "DeleteItem", del).await;
        assert_eq!(s, 200);

        // Re-put, then OR where one branch is false but the other true → succeeds.
        call(
            &h,
            "PutItem",
            r#"{"TableName":"t","Item":{"id":{"S":"a"},"n":{"N":"5"}}}"#,
        )
        .await;
        let or = r#"{"TableName":"t","Item":{"id":{"S":"a"},"n":{"N":"6"}},"ConditionalOperator":"OR","Expected":{"n":{"ComparisonOperator":"LT","AttributeValueList":[{"N":"0"}]},"id":{"ComparisonOperator":"EQ","AttributeValueList":[{"S":"a"}]}}}"#;
        let (s, _) = call_json(&h, "PutItem", or).await;
        assert_eq!(s, 200);
    }

    #[tokio::test]
    async fn rejects_condition_expression_with_expected() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        call(&h, "CreateTable", create).await;
        let mixed = r#"{"TableName":"t","Item":{"id":{"S":"a"}},"ConditionExpression":"attribute_not_exists(id)","Expected":{"id":{"Exists":false}}}"#;
        let (s, v) = call_json(&h, "PutItem", mixed).await;
        assert_eq!(s, 400);
        assert!(v["__type"]
            .as_str()
            .unwrap()
            .contains("ValidationException"));
    }

    #[tokio::test]
    async fn tag_lifecycle_and_invalid_arn() {
        let h = DynamoHandler::new();
        create_provisioned(&h).await;
        let arn = "arn:aws:dynamodb:us-east-1:000000000000:table/t";
        let tag = format!(r#"{{"ResourceArn":"{arn}","Tags":[{{"Key":"env","Value":"prod"}}]}}"#);
        assert_eq!(call(&h, "TagResource", &tag).await.status(), 200);
        let (s, v) = call_json(
            &h,
            "ListTagsOfResource",
            &format!(r#"{{"ResourceArn":"{arn}"}}"#),
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(v["Tags"][0]["Key"], "env");
        assert_eq!(v["Tags"][0]["Value"], "prod");
        // Untag.
        let untag = format!(r#"{{"ResourceArn":"{arn}","TagKeys":["env"]}}"#);
        assert_eq!(call(&h, "UntagResource", &untag).await.status(), 200);
        let (_, v) = call_json(
            &h,
            "ListTagsOfResource",
            &format!(r#"{{"ResourceArn":"{arn}"}}"#),
        )
        .await;
        assert!(v["Tags"].as_array().unwrap().is_empty());
        // Invalid ARN → ValidationException.
        let (s, v) = call_json(&h, "ListTagsOfResource", r#"{"ResourceArn":"not-an-arn"}"#).await;
        assert_eq!(s, 400);
        assert!(v["__type"]
            .as_str()
            .unwrap()
            .contains("ValidationException"));
    }

    #[tokio::test]
    async fn continuous_backups_pitr_toggle() {
        let h = DynamoHandler::new();
        create_provisioned(&h).await;
        let (s, v) = call_json(&h, "DescribeContinuousBackups", r#"{"TableName":"t"}"#).await;
        assert_eq!(s, 200);
        assert_eq!(
            v["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]
                ["PointInTimeRecoveryStatus"],
            "DISABLED"
        );
        let enable = r#"{"TableName":"t","PointInTimeRecoverySpecification":{"PointInTimeRecoveryEnabled":true}}"#;
        let (s, v) = call_json(&h, "UpdateContinuousBackups", enable).await;
        assert_eq!(s, 400);
        assert!(v["message"].as_str().unwrap().contains("unavailable"));
        // Enabling PITR must not claim a recoverable backup.
        let (_, v) = call_json(&h, "DescribeContinuousBackups", r#"{"TableName":"t"}"#).await;
        assert_eq!(
            v["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]
                ["PointInTimeRecoveryStatus"],
            "DISABLED"
        );
    }

    async fn create_streamed(h: &DynamoHandler) {
        let create = r#"{"TableName":"s","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST","StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_AND_OLD_IMAGES"}}"#;
        assert_eq!(call(h, "CreateTable", create).await.status(), 200);
    }

    #[tokio::test]
    async fn streams_capture_changes_and_read_in_order() {
        let h = DynamoHandler::new();
        create_streamed(&h).await;

        // INSERT, MODIFY, REMOVE produce three ordered records.
        call(
            &h,
            "PutItem",
            r#"{"TableName":"s","Item":{"id":{"S":"a"},"v":{"N":"1"}}}"#,
        )
        .await;
        call(
            &h,
            "PutItem",
            r#"{"TableName":"s","Item":{"id":{"S":"a"},"v":{"N":"2"}}}"#,
        )
        .await;
        call(
            &h,
            "DeleteItem",
            r#"{"TableName":"s","Key":{"id":{"S":"a"}}}"#,
        )
        .await;

        // ListStreams returns the stream.
        let (s, v) = call_json(&h, "ListStreams", r#"{"TableName":"s"}"#).await;
        assert_eq!(s, 200);
        let stream_arn = v["Streams"][0]["StreamArn"].as_str().unwrap().to_string();
        assert!(stream_arn.contains("/stream/"));

        // DescribeStream exposes a single shard.
        let (s, v) = call_json(
            &h,
            "DescribeStream",
            &format!(r#"{{"StreamArn":"{stream_arn}"}}"#),
        )
        .await;
        assert_eq!(s, 200);
        let shard_id = v["StreamDescription"]["Shards"][0]["ShardId"]
            .as_str()
            .unwrap()
            .to_string();

        // TRIM_HORIZON iterator → all three records in commit order.
        let it_req = format!(
            r#"{{"StreamArn":"{stream_arn}","ShardId":"{shard_id}","ShardIteratorType":"TRIM_HORIZON"}}"#
        );
        let (s, v) = call_json(&h, "GetShardIterator", &it_req).await;
        assert_eq!(s, 200);
        let iterator = v["ShardIterator"].as_str().unwrap().to_string();

        let (s, v) = call_json(
            &h,
            "GetRecords",
            &format!(r#"{{"ShardIterator":"{iterator}"}}"#),
        )
        .await;
        assert_eq!(s, 200);
        let records = v["Records"].as_array().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["eventName"], "INSERT");
        assert_eq!(records[0]["dynamodb"]["NewImage"]["v"]["N"], "1");
        assert_eq!(records[1]["eventName"], "MODIFY");
        assert_eq!(records[1]["dynamodb"]["OldImage"]["v"]["N"], "1");
        assert_eq!(records[1]["dynamodb"]["NewImage"]["v"]["N"], "2");
        assert_eq!(records[2]["eventName"], "REMOVE");
        assert_eq!(records[2]["dynamodb"]["OldImage"]["v"]["N"], "2");
        // Strictly increasing sequence numbers.
        let s0 = records[0]["dynamodb"]["SequenceNumber"].as_str().unwrap();
        let s1 = records[1]["dynamodb"]["SequenceNumber"].as_str().unwrap();
        assert!(s1 > s0);
        // The shard stays open: a next iterator is always returned.
        assert!(v["NextShardIterator"].as_str().is_some());
    }

    #[tokio::test]
    async fn streams_latest_iterator_skips_existing() {
        let h = DynamoHandler::new();
        create_streamed(&h).await;
        call(
            &h,
            "PutItem",
            r#"{"TableName":"s","Item":{"id":{"S":"a"}}}"#,
        )
        .await;
        let (_, v) = call_json(&h, "ListStreams", r#"{"TableName":"s"}"#).await;
        let arn = v["Streams"][0]["StreamArn"].as_str().unwrap().to_string();
        let (_, d) = call_json(&h, "DescribeStream", &format!(r#"{{"StreamArn":"{arn}"}}"#)).await;
        let shard_id = d["StreamDescription"]["Shards"][0]["ShardId"]
            .as_str()
            .unwrap()
            .to_string();
        let (_, v) = call_json(
            &h,
            "GetShardIterator",
            &format!(
                r#"{{"StreamArn":"{arn}","ShardId":"{shard_id}","ShardIteratorType":"LATEST"}}"#
            ),
        )
        .await;
        let it = v["ShardIterator"].as_str().unwrap().to_string();
        // LATEST starts at the end → no existing records.
        let (_, v) = call_json(&h, "GetRecords", &format!(r#"{{"ShardIterator":"{it}"}}"#)).await;
        assert_eq!(v["Records"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn describe_stream_unknown_is_not_found() {
        let h = DynamoHandler::new();
        let arn = "arn:aws:dynamodb:us-east-1:000000000000:table/missing/stream/0";
        let (s, v) = call_json(&h, "DescribeStream", &format!(r#"{{"StreamArn":"{arn}"}}"#)).await;
        assert_eq!(s, 400);
        assert!(v["__type"]
            .as_str()
            .unwrap()
            .contains("ResourceNotFoundException"));
    }

    #[tokio::test]
    async fn gsi_query_applies_keys_only_projection() {
        let h = DynamoHandler::new();
        // Table with a KEYS_ONLY GSI on `gsk`.
        let create = r#"{"TableName":"g","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"},{"AttributeName":"gsk","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST","GlobalSecondaryIndexes":[{"IndexName":"gsi","KeySchema":[{"AttributeName":"gsk","KeyType":"HASH"}],"Projection":{"ProjectionType":"KEYS_ONLY"}}]}"#;
        assert_eq!(call(&h, "CreateTable", create).await.status(), 200);
        call(
            &h,
            "PutItem",
            r#"{"TableName":"g","Item":{"id":{"S":"a"},"gsk":{"S":"x"},"extra":{"S":"hidden"}}}"#,
        )
        .await;

        let q = r#"{"TableName":"g","IndexName":"gsi","KeyConditionExpression":"gsk = :v","ExpressionAttributeValues":{":v":{"S":"x"}}}"#;
        let (s, v) = call_json(&h, "Query", q).await;
        assert_eq!(s, 200);
        let item = &v["Items"][0];
        // KEYS_ONLY → only table key + index key, never `extra`.
        assert_eq!(item["id"]["S"], "a");
        assert_eq!(item["gsk"]["S"], "x");
        assert!(item.get("extra").is_none());

        // GSI consistent read is rejected.
        let qc = r#"{"TableName":"g","IndexName":"gsi","ConsistentRead":true,"KeyConditionExpression":"gsk = :v","ExpressionAttributeValues":{":v":{"S":"x"}}}"#;
        assert_eq!(call(&h, "Query", qc).await.status(), 400);
    }

    #[tokio::test]
    async fn gsi_query_include_projection() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"g","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"},{"AttributeName":"gsk","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST","GlobalSecondaryIndexes":[{"IndexName":"gsi","KeySchema":[{"AttributeName":"gsk","KeyType":"HASH"}],"Projection":{"ProjectionType":"INCLUDE","NonKeyAttributes":["keep"]}}]}"#;
        call(&h, "CreateTable", create).await;
        call(&h, "PutItem", r#"{"TableName":"g","Item":{"id":{"S":"a"},"gsk":{"S":"x"},"keep":{"S":"yes"},"drop":{"S":"no"}}}"#).await;
        let q = r#"{"TableName":"g","IndexName":"gsi","KeyConditionExpression":"gsk = :v","ExpressionAttributeValues":{":v":{"S":"x"}}}"#;
        let (_, v) = call_json(&h, "Query", q).await;
        let item = &v["Items"][0];
        assert_eq!(item["keep"]["S"], "yes");
        assert!(item.get("drop").is_none());
    }

    #[tokio::test]
    async fn ttl_reaps_expired_items_on_read() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST","StreamSpecification":{"StreamEnabled":true,"StreamViewType":"OLD_IMAGE"}}"#;
        call(&h, "CreateTable", create).await;
        let (s, _) = call_json(
            &h,
            "UpdateTimeToLive",
            r#"{"TableName":"t","TimeToLiveSpecification":{"Enabled":true,"AttributeName":"exp"}}"#,
        )
        .await;
        assert_eq!(s, 200);
        // An already-expired item (epoch 1) and a far-future item.
        call(
            &h,
            "PutItem",
            r#"{"TableName":"t","Item":{"id":{"S":"old"},"exp":{"N":"1"}}}"#,
        )
        .await;
        call(
            &h,
            "PutItem",
            r#"{"TableName":"t","Item":{"id":{"S":"new"},"exp":{"N":"99999999999"}}}"#,
        )
        .await;

        // GetItem on the expired item reaps it → no Item.
        let (_, v) = call_json(
            &h,
            "GetItem",
            r#"{"TableName":"t","Key":{"id":{"S":"old"}}}"#,
        )
        .await;
        assert!(v.get("Item").is_none());
        // The live item remains.
        let (_, v) = call_json(
            &h,
            "GetItem",
            r#"{"TableName":"t","Key":{"id":{"S":"new"}}}"#,
        )
        .await;
        assert_eq!(v["Item"]["id"]["S"], "new");

        // A REMOVE stream record was emitted for the reaped item.
        let (_, ls) = call_json(&h, "ListStreams", r#"{"TableName":"t"}"#).await;
        let arn = ls["Streams"][0]["StreamArn"].as_str().unwrap().to_string();
        let (_, d) = call_json(&h, "DescribeStream", &format!(r#"{{"StreamArn":"{arn}"}}"#)).await;
        let shard = d["StreamDescription"]["Shards"][0]["ShardId"]
            .as_str()
            .unwrap()
            .to_string();
        let (_, it) = call_json(
            &h,
            "GetShardIterator",
            &format!(
                r#"{{"StreamArn":"{arn}","ShardId":"{shard}","ShardIteratorType":"TRIM_HORIZON"}}"#
            ),
        )
        .await;
        let iter = it["ShardIterator"].as_str().unwrap().to_string();
        let (_, rec) = call_json(
            &h,
            "GetRecords",
            &format!(r#"{{"ShardIterator":"{iter}"}}"#),
        )
        .await;
        let names: Vec<&str> = rec["Records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["eventName"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"REMOVE"));
    }

    #[tokio::test]
    async fn ttl_reenable_with_different_attribute_rejected() {
        let h = DynamoHandler::new();
        create_provisioned(&h).await;
        let en =
            r#"{"TableName":"t","TimeToLiveSpecification":{"Enabled":true,"AttributeName":"exp"}}"#;
        assert_eq!(call(&h, "UpdateTimeToLive", en).await.status(), 200);
        let other = r#"{"TableName":"t","TimeToLiveSpecification":{"Enabled":true,"AttributeName":"different"}}"#;
        assert_eq!(call(&h, "UpdateTimeToLive", other).await.status(), 400);
    }

    #[tokio::test]
    async fn kinesis_streaming_destination_lifecycle() {
        let h = DynamoHandler::new();
        create_provisioned(&h).await;
        let arn = "arn:aws:kinesis:us-east-1:000000000000:stream/s";
        let en = format!(r#"{{"TableName":"t","StreamArn":"{arn}"}}"#);
        let (s, v) = call_json(&h, "EnableKinesisStreamingDestination", &en).await;
        assert_eq!(s, 200);
        assert_eq!(v["DestinationStatus"], "ACTIVE");
        let (_, v) = call_json(
            &h,
            "DescribeKinesisStreamingDestination",
            r#"{"TableName":"t"}"#,
        )
        .await;
        assert_eq!(v["KinesisDataStreamDestinations"][0]["StreamArn"], arn);
        let (_, v) = call_json(&h, "DisableKinesisStreamingDestination", &en).await;
        assert_eq!(v["DestinationStatus"], "DISABLED");
        let (_, v) = call_json(
            &h,
            "DescribeKinesisStreamingDestination",
            r#"{"TableName":"t"}"#,
        )
        .await;
        assert!(v["KinesisDataStreamDestinations"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn export_rejects_without_materialized_backup() {
        let h = DynamoHandler::new();
        create_provisioned(&h).await;
        let arn = "arn:aws:dynamodb:us-east-1:000000000000:table/t";
        let req = format!(r#"{{"TableArn":"{arn}","S3Bucket":"my-bucket"}}"#);
        let (status, body) = call_json(&h, "ExportTableToPointInTime", &req).await;
        assert_eq!(status, 400);
        assert!(body["message"].as_str().unwrap().contains("unavailable"));
        let (_, listed) = call_json(&h, "ListExports", r#"{}"#).await;
        assert!(listed["ExportSummaries"].as_array().unwrap().is_empty());
    }

    /// Region/account scoping: same table name in different scopes is independent.
    #[tokio::test]
    async fn tables_are_scoped_by_account_and_region() {
        let h = DynamoHandler::new();
        let create = |account: &str, region: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-amz-target",
                HeaderValue::from_str(&format!("{TARGET_PREFIX}.CreateTable")).unwrap(),
            );
            ServiceRequest {
                method: Method::POST,
                uri: "/".parse().unwrap(),
                headers,
                body: Bytes::from(
                    r#"{"TableName":"shared","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#,
                ),
                region: region.to_string(),
                account_id: account.to_string(),
                request_id: "rid".to_string(),
            }
        };
        // Same name in account A / region us-east-1 and account B / eu-west-1.
        assert_eq!(
            h.handle(create("111111111111", "us-east-1")).await.status(),
            200
        );
        assert_eq!(
            h.handle(create("222222222222", "eu-west-1")).await.status(),
            200
        );

        // Put in scope A; it must not be visible from scope B.
        let put_a = ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: {
                let mut hm = HeaderMap::new();
                hm.insert(
                    "x-amz-target",
                    HeaderValue::from_static("DynamoDB_20120810.PutItem"),
                );
                hm
            },
            body: Bytes::from(r#"{"TableName":"shared","Item":{"id":{"S":"only-a"}}}"#),
            region: "us-east-1".to_string(),
            account_id: "111111111111".to_string(),
            request_id: "rid".to_string(),
        };
        assert_eq!(h.handle(put_a).await.status(), 200);

        let get_b = ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: {
                let mut hm = HeaderMap::new();
                hm.insert(
                    "x-amz-target",
                    HeaderValue::from_static("DynamoDB_20120810.GetItem"),
                );
                hm
            },
            body: Bytes::from(r#"{"TableName":"shared","Key":{"id":{"S":"only-a"}}}"#),
            region: "eu-west-1".to_string(),
            account_id: "222222222222".to_string(),
            request_id: "rid".to_string(),
        };
        let resp = h.handle(get_b).await;
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            v.get("Item").is_none(),
            "item from scope A must not appear in scope B"
        );
    }

    #[tokio::test]
    async fn partiql_insert_select_update_delete() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        call(&h, "CreateTable", create).await;

        // INSERT with a parameter and literals.
        let ins = r#"{"Statement":"INSERT INTO t VALUE {'id': ?, 'n': 1, 'live': true}","Parameters":[{"S":"a"}]}"#;
        assert_eq!(call(&h, "ExecuteStatement", ins).await.status(), 200);

        // SELECT with a filter.
        let sel = r#"{"Statement":"SELECT * FROM t WHERE n >= ?","Parameters":[{"N":"1"}]}"#;
        let (s, v) = call_json(&h, "ExecuteStatement", sel).await;
        assert_eq!(s, 200);
        assert_eq!(v["Items"].as_array().unwrap().len(), 1);
        assert_eq!(v["Items"][0]["id"]["S"], "a");

        // UPDATE then verify.
        let upd = r#"{"Statement":"UPDATE t SET n = ? WHERE id = ?","Parameters":[{"N":"42"},{"S":"a"}]}"#;
        assert_eq!(call(&h, "ExecuteStatement", upd).await.status(), 200);
        let (_, g) = call_json(&h, "GetItem", r#"{"TableName":"t","Key":{"id":{"S":"a"}}}"#).await;
        assert_eq!(g["Item"]["n"]["N"], "42");

        // DELETE then verify gone.
        let del = r#"{"Statement":"DELETE FROM t WHERE id = ?","Parameters":[{"S":"a"}]}"#;
        assert_eq!(call(&h, "ExecuteStatement", del).await.status(), 200);
        let (_, g) = call_json(&h, "GetItem", r#"{"TableName":"t","Key":{"id":{"S":"a"}}}"#).await;
        assert!(g.get("Item").is_none());
    }

    #[tokio::test]
    async fn partiql_transaction_is_atomic() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        call(&h, "CreateTable", create).await;
        let tx = r#"{"TransactStatements":[
            {"Statement":"INSERT INTO t VALUE {'id': ?}","Parameters":[{"S":"x"}]},
            {"Statement":"INSERT INTO t VALUE {'id': ?}","Parameters":[{"S":"y"}]}
        ]}"#;
        assert_eq!(call(&h, "ExecuteTransaction", tx).await.status(), 200);
        let (_, gx) = call_json(&h, "GetItem", r#"{"TableName":"t","Key":{"id":{"S":"x"}}}"#).await;
        assert_eq!(gx["Item"]["id"]["S"], "x");
        let (_, gy) = call_json(&h, "GetItem", r#"{"TableName":"t","Key":{"id":{"S":"y"}}}"#).await;
        assert_eq!(gy["Item"]["id"]["S"], "y");
    }

    #[tokio::test]
    async fn partiql_batch_reports_per_statement() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        call(&h, "CreateTable", create).await;
        call(
            &h,
            "PutItem",
            r#"{"TableName":"t","Item":{"id":{"S":"a"}}}"#,
        )
        .await;
        let batch = r#"{"Statements":[
            {"Statement":"SELECT * FROM t WHERE id = ?","Parameters":[{"S":"a"}]},
            {"Statement":"SELECT * FROM missing WHERE id = ?","Parameters":[{"S":"a"}]}
        ]}"#;
        let (s, v) = call_json(&h, "BatchExecuteStatement", batch).await;
        assert_eq!(s, 200);
        let responses = v["Responses"].as_array().unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["Item"]["id"]["S"], "a");
        assert!(responses[1]["Error"]["Code"]
            .as_str()
            .unwrap()
            .contains("ResourceNotFound"));
    }

    #[tokio::test]
    async fn target_prefixes_are_strict_and_services_are_separate() {
        let registry = ServiceRegistry::with_known_services();
        register(&registry);
        assert_eq!(
            registry.disposition(&ServiceName::new("dynamodb")),
            locallycloud_core::registry::Disposition::Native
        );
        assert_eq!(
            registry.disposition(&ServiceName::new("streams.dynamodb")),
            locallycloud_core::registry::Disposition::Native
        );

        let h = DynamoHandler::new();
        let wrong = h
            .handle(request_with_prefix(
                STREAMS_TARGET_PREFIX,
                "ListStreams",
                "{}",
            ))
            .await;
        assert_eq!(wrong.status(), 400);
        let wrong = h
            .streams_handler()
            .handle(request_with_prefix(TARGET_PREFIX, "ListStreams", "{}"))
            .await;
        assert_eq!(wrong.status(), 400);
    }

    #[tokio::test]
    async fn transaction_token_replays_once_and_rejects_mismatch() {
        let h = DynamoHandler::new();
        create_streamed(&h).await;
        let transaction = r#"{"ClientRequestToken":"token-1","TransactItems":[{"Put":{"TableName":"s","Item":{"id":{"S":"a"},"v":{"N":"1"}}}}]}"#;
        assert_eq!(
            call(&h, "TransactWriteItems", transaction).await.status(),
            200
        );
        assert_eq!(
            call(&h, "TransactWriteItems", transaction).await.status(),
            200
        );

        let (_, listed) = call_json(&h, "ListStreams", r#"{"TableName":"s"}"#).await;
        let arn = listed["Streams"][0]["StreamArn"].as_str().unwrap();
        let (_, described) =
            call_json(&h, "DescribeStream", &format!(r#"{{"StreamArn":"{arn}"}}"#)).await;
        let shard = described["StreamDescription"]["Shards"][0]["ShardId"]
            .as_str()
            .unwrap();
        let (_, iterator) = call_json(
            &h,
            "GetShardIterator",
            &format!(
                r#"{{"StreamArn":"{arn}","ShardId":"{shard}","ShardIteratorType":"TRIM_HORIZON"}}"#
            ),
        )
        .await;
        let iterator = iterator["ShardIterator"].as_str().unwrap();
        let (_, records) = call_json(
            &h,
            "GetRecords",
            &format!(r#"{{"ShardIterator":"{iterator}"}}"#),
        )
        .await;
        assert_eq!(records["Records"].as_array().unwrap().len(), 1);

        let mismatch = r#"{"ClientRequestToken":"token-1","TransactItems":[{"Put":{"TableName":"s","Item":{"id":{"S":"b"}}}}]}"#;
        let (status, body) = call_json(&h, "TransactWriteItems", mismatch).await;
        assert_eq!(status, 400);
        assert!(body["__type"]
            .as_str()
            .unwrap()
            .contains("IdempotentParameterMismatchException"));
    }

    #[tokio::test]
    async fn transaction_stages_late_update_errors_before_commit() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"t","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        call(&h, "CreateTable", create).await;
        call(
            &h,
            "PutItem",
            r#"{"TableName":"t","Item":{"id":{"S":"a"}}}"#,
        )
        .await;
        let transaction = r#"{"TransactItems":[
            {"Put":{"TableName":"t","Item":{"id":{"S":"b"}}}},
            {"Update":{"TableName":"t","Key":{"id":{"S":"a"}},"UpdateExpression":"SET value = :missing"}}
        ]}"#;
        assert_eq!(
            call(&h, "TransactWriteItems", transaction).await.status(),
            400
        );
        let (_, item) =
            call_json(&h, "GetItem", r#"{"TableName":"t","Key":{"id":{"S":"b"}}}"#).await;
        assert!(item.get("Item").is_none());
    }

    #[tokio::test]
    async fn kinesis_destination_forwards_through_internal_dispatcher() {
        let registry = ServiceRegistry::with_known_services();
        let recorder = Arc::new(KinesisRecorder::default());
        registry.register_native(
            ServiceName::new("kinesis"),
            ServiceMetadata::new(AwsProtocol::Json11, Some("Kinesis_20131202")),
            recorder.clone(),
        );
        register(&registry);
        registry.set_internal_dispatcher(Arc::new(
            locallycloud_core::integration::InternalDispatcher::new_shared(
                &registry,
                locallycloud_core::proxy::ProxyConfig {
                    backend_url: "http://127.0.0.1:1".into(),
                    upstream_timeout: Duration::from_secs(1),
                },
                locallycloud_core::proxy::LegacyHealth::new(true),
                "us-east-1".into(),
                "000000000000".into(),
            ),
        ));
        let handler = registry
            .native_handler(&ServiceName::new("dynamodb"))
            .unwrap();
        let create = r#"{"TableName":"k","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        assert_eq!(
            handler
                .handle(request("CreateTable", create))
                .await
                .status(),
            200
        );
        let destination = r#"{"TableName":"k","StreamArn":"arn:aws:kinesis:us-east-1:000000000000:stream/events"}"#;
        assert_eq!(
            handler
                .handle(request("EnableKinesisStreamingDestination", destination))
                .await
                .status(),
            200
        );
        assert_eq!(
            handler
                .handle(request(
                    "PutItem",
                    r#"{"TableName":"k","Item":{"id":{"S":"one"}}}"#,
                ))
                .await
                .status(),
            200
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        let requests = recorder.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let payload: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(payload["StreamName"], "events");
        assert!(payload["Data"].as_str().is_some());
    }

    #[tokio::test]
    async fn ttl_reaper_runs_without_a_read_trigger() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"ttl","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST","StreamSpecification":{"StreamEnabled":true,"StreamViewType":"OLD_IMAGE"}}"#;
        call(&h, "CreateTable", create).await;
        call(
            &h,
            "UpdateTimeToLive",
            r#"{"TableName":"ttl","TimeToLiveSpecification":{"Enabled":true,"AttributeName":"exp"}}"#,
        )
        .await;
        call(
            &h,
            "PutItem",
            r#"{"TableName":"ttl","Item":{"id":{"S":"old"},"exp":{"N":"1"}}}"#,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(250)).await;

        let table = h.store.get("000000000000", "us-east-1", "ttl").unwrap();
        let guard = table.read().await;
        assert!(guard.items.is_empty());
        assert_eq!(
            guard
                .stream_records
                .iter()
                .filter(|record| record.event_name == "REMOVE")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn partiql_next_token_resumes_without_duplicates() {
        let h = DynamoHandler::new();
        let create = r#"{"TableName":"p","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        call(&h, "CreateTable", create).await;
        for id in ["a", "b", "c"] {
            call(
                &h,
                "PutItem",
                &format!(r#"{{"TableName":"p","Item":{{"id":{{"S":"{id}"}}}}}}"#),
            )
            .await;
        }
        let (_, first) = call_json(
            &h,
            "ExecuteStatement",
            r#"{"Statement":"SELECT * FROM p","Limit":2}"#,
        )
        .await;
        assert_eq!(first["Items"].as_array().unwrap().len(), 2);
        let token = first["NextToken"].as_str().unwrap();
        let (_, second) = call_json(
            &h,
            "ExecuteStatement",
            &format!(r#"{{"Statement":"SELECT * FROM p","Limit":2,"NextToken":"{token}"}}"#),
        )
        .await;
        assert_eq!(second["Items"].as_array().unwrap().len(), 1);
        assert_ne!(first["Items"][0]["id"], second["Items"][0]["id"]);
        assert_ne!(first["Items"][1]["id"], second["Items"][0]["id"]);
    }
}
