//! Optional engine boundary. IAM and AWS protocol routing stay in LocalCloud.

use std::sync::{Arc, Weak};

use async_trait::async_trait;
use axum::response::Response;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::dynamodb::DynamoDbStreamsApi;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use serde_json::{json, Value};

use crate::error::DdbError;
use crate::service::{self, STREAMS_TARGET_PREFIX, TARGET_PREFIX};

struct EngineHandler {
    engine: Arc<dyn DynamoEngine>,
    registry: Weak<ServiceRegistry>,
    prefix: &'static str,
}

/// Backend capability used before IAM authorizes an opaque Streams iterator.
/// The backend resolves its own token format; the wrapper owns authorization.
#[async_trait]
pub trait DynamoEngine: NativeHandler {
    fn supports_backups(&self) -> bool {
        false
    }
    fn supports_mrec(&self) -> bool {
        false
    }
    async fn resolve_stream_iterator(
        &self,
        account: &str,
        region: &str,
        token: &str,
    ) -> Result<String, DdbError>;

    async fn resolve_stream_sequence(
        &self,
        _account: &str,
        _region: &str,
        _token: &str,
    ) -> Result<String, DdbError> {
        Err(DdbError::Validation(
            "stream frontier metadata is unavailable".into(),
        ))
    }
}

struct EngineStreamsApi {
    engine: Arc<dyn DynamoEngine>,
}

#[async_trait]
impl DynamoDbStreamsApi for EngineStreamsApi {
    async fn sequence_after_iterator(
        &self,
        account: &str,
        region: &str,
        iterator: &str,
    ) -> Result<String, String> {
        if iterator.is_empty() || iterator.len() > 2048 {
            return Err("invalid shard iterator".into());
        }
        crate::streams::validate_scope_values(account, region)
            .map_err(|error| error.to_string())?;
        let arn = self
            .engine
            .resolve_stream_iterator(account, region, iterator)
            .await
            .map_err(|error| error.to_string())?;
        crate::streams::validate_stream_scope(account, region, &arn)
            .map_err(|error| error.to_string())?;
        self.engine
            .resolve_stream_sequence(account, region, iterator)
            .await
            .map_err(|error| error.to_string())
    }
}

/// Select one injected engine for both DynamoDB and Streams. This does not open,
/// migrate, or fall back to the native store. The engine owns account/region isolation.
pub fn register_with_engine(registry: &Arc<ServiceRegistry>, engine: Arc<dyn DynamoEngine>) {
    for (name, prefix) in [
        ("dynamodb", TARGET_PREFIX),
        ("streams.dynamodb", STREAMS_TARGET_PREFIX),
    ] {
        let handler = Arc::new(EngineHandler {
            engine: engine.clone(),
            registry: Arc::downgrade(registry),
            prefix,
        });
        let name = ServiceName::new(name);
        let metadata = ServiceMetadata::new(AwsProtocol::Json10, Some(prefix));
        match prefix {
            STREAMS_TARGET_PREFIX => registry.register_native_with_dynamodb_streams_api(
                name,
                metadata,
                handler,
                Arc::new(EngineStreamsApi {
                    engine: engine.clone(),
                }),
            ),
            _ => registry.register_native(name, metadata, handler),
        }
    }
}

fn supported(prefix: &str, op: &str) -> bool {
    match prefix {
        TARGET_PREFIX => matches!(
            op,
            "CreateTable"
                | "DescribeTable"
                | "UpdateTable"
                | "DeleteTable"
                | "ListTables"
                | "DescribeLimits"
                | "PutItem"
                | "GetItem"
                | "DeleteItem"
                | "UpdateItem"
                | "Query"
                | "Scan"
                | "BatchWriteItem"
                | "BatchGetItem"
                | "TransactWriteItems"
                | "TransactGetItems"
                | "SearchVectors"
                | "DescribeTimeToLive"
                | "UpdateTimeToLive"
                | "CreateBackup"
                | "DescribeBackup"
                | "ListBackups"
                | "DeleteBackup"
                | "RestoreTableFromBackup"
                | "ListTagsOfResource"
                | "TagResource"
                | "UntagResource"
        ),
        STREAMS_TARGET_PREFIX => matches!(
            op,
            "ListStreams" | "DescribeStream" | "GetShardIterator" | "GetRecords"
        ),
        _ => false,
    }
}

fn validate_account_region(request: &ServiceRequest) -> Result<(), DdbError> {
    crate::streams::validate_scope_values(&request.account_id, &request.region)
}

fn validate_scope(
    request: &ServiceRequest,
    op: &str,
    body: &Value,
    supports_mrec: bool,
) -> Result<(), DdbError> {
    validate_account_region(request)?;
    let arn_prefix = format!(
        "arn:aws:dynamodb:{}:{}:",
        request.region, request.account_id
    );
    for (_, resource) in service::authorization_targets(op, body)? {
        if resource.starts_with("arn:") && !resource.starts_with(&arn_prefix) {
            return Err(DdbError::Validation(
                "resource ARN must match the request account and region".into(),
            ));
        }
    }
    if op == "ListBackups" {
        if let Some(table) = body.get("TableName").and_then(Value::as_str) {
            if table.starts_with("arn:") && !table.starts_with(&arn_prefix) {
                return Err(DdbError::Validation(
                    "table ARN must match the request account and region".into(),
                ));
            }
        }
    }
    if matches!(
        op,
        "DescribeBackup" | "DeleteBackup" | "RestoreTableFromBackup"
    ) {
        let arn = body
            .get("BackupArn")
            .and_then(Value::as_str)
            .ok_or_else(|| DdbError::Validation("BackupArn is required".into()))?;
        let resource = arn
            .strip_prefix(&format!("{arn_prefix}table/"))
            .ok_or_else(|| {
                DdbError::Validation("backup ARN must match the request account and region".into())
            })?;
        let (table, backup) = resource
            .split_once("/backup/")
            .ok_or_else(|| DdbError::Validation("invalid backup ARN".into()))?;
        if arn.len() > 1024
            || table.is_empty()
            || backup.is_empty()
            || table.contains('/')
            || backup.contains('/')
        {
            return Err(DdbError::Validation("invalid backup ARN".into()));
        }
    }
    if op == "RestoreTableFromBackup" {
        let unsupported = [
            "BillingModeOverride",
            "ProvisionedThroughputOverride",
            "OnDemandThroughputOverride",
            "GlobalSecondaryIndexOverride",
            "LocalSecondaryIndexOverride",
            "SSESpecificationOverride",
            "VectorIndexOverride",
        ];
        if let Some(field) = unsupported.iter().find(|field| body.get(**field).is_some()) {
            return Err(DdbError::Validation(format!(
                "{field} is not supported by the optional DynamoDB engine"
            )));
        }
        let target = body
            .get("TargetTableName")
            .and_then(Value::as_str)
            .ok_or_else(|| DdbError::Validation("TargetTableName is required".into()))?;
        if !(3..=255).contains(&target.len())
            || !target
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            return Err(DdbError::Validation("invalid TargetTableName".into()));
        }
    }
    if matches!(op, "CreateTable" | "UpdateTable") {
        if body.get("ReplicaUpdates").is_some() && (!supports_mrec || op != "UpdateTable") {
            return Err(DdbError::Validation(
                "ReplicaUpdates is not supported by this DynamoDB engine".into(),
            ));
        }
        if let Some(consistency) = body.get("MultiRegionConsistency") {
            if !supports_mrec || consistency.as_str() != Some("EVENTUAL") {
                return Err(DdbError::Validation(
                    "only MREC global tables are supported".into(),
                ));
            }
        }
        const UNSUPPORTED_FIELDS: &[&str] = &[
            "SSESpecification",
            "Replicas",
            "GlobalTableVersion",
            "GlobalTableSettingsReplicationMode",
            "GlobalTableWitnesses",
            "GlobalTableWitnessUpdates",
            "ResourcePolicy",
        ];
        if let Some(field) = UNSUPPORTED_FIELDS
            .iter()
            .find(|field| body.get(**field).is_some())
        {
            return Err(DdbError::Validation(format!(
                "{field} is not supported by the optional DynamoDB engine"
            )));
        }
    }
    Ok(())
}

impl EngineHandler {
    async fn authorization_body(
        &self,
        request: &ServiceRequest,
        operation: &str,
        body: &Value,
    ) -> Result<Value, DdbError> {
        match (self.prefix, operation) {
            (STREAMS_TARGET_PREFIX, "GetRecords") => {
                crate::streams::get_records_limit(body)?;
                let token = body
                    .get("ShardIterator")
                    .and_then(Value::as_str)
                    .filter(|token| !token.is_empty() && token.len() <= 2048)
                    .ok_or_else(|| {
                        DdbError::Validation(
                            "ShardIterator must contain between 1 and 2048 bytes".into(),
                        )
                    })?;
                let arn = self
                    .engine
                    .resolve_stream_iterator(&request.account_id, &request.region, token)
                    .await?;
                Ok(json!({"StreamArn":arn}))
            }
            (STREAMS_TARGET_PREFIX, "DescribeStream" | "GetShardIterator") => {
                let arn = body
                    .get("StreamArn")
                    .and_then(Value::as_str)
                    .filter(|arn| !arn.is_empty())
                    .ok_or_else(|| DdbError::Validation("StreamArn is required".into()))?;
                Ok(json!({"StreamArn":arn}))
            }
            _ => Ok(body.clone()),
        }
    }
}

#[async_trait]
impl NativeHandler for EngineHandler {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        if self.prefix == STREAMS_TARGET_PREFIX {
            return Ok(Vec::new());
        }
        self.engine.resource_regions(account).await
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let op = match service::operation(&request, self.prefix) {
            Some(op) if supported(self.prefix, &op) => op,
            _ => {
                return DdbError::UnknownOperation(
                    "operation is not supported by the optional DynamoDB engine".into(),
                )
                .into_response(&request.request_id);
            }
        };
        if matches!(
            op.as_str(),
            "CreateBackup"
                | "DescribeBackup"
                | "ListBackups"
                | "DeleteBackup"
                | "RestoreTableFromBackup"
        ) && !self.engine.supports_backups()
        {
            return DdbError::UnknownOperation(
                "backups are not supported by this DynamoDB engine".into(),
            )
            .into_response(&request.request_id);
        }
        let body = match service::parse_body(&request) {
            Ok(body) => body,
            Err(error) => return error.into_response(&request.request_id),
        };
        if let Err(error) = validate_account_region(&request) {
            return error.into_response(&request.request_id);
        }
        let authorization_body = match self.authorization_body(&request, &op, &body).await {
            Ok(body) => body,
            Err(error) => return error.into_response(&request.request_id),
        };
        if let Err(error) = validate_scope(
            &request,
            &op,
            &authorization_body,
            self.engine.supports_mrec(),
        )
        .and_then(|()| service::authorize(&self.registry, &request, &op, &authorization_body))
        {
            return error.into_response(&request.request_id);
        }
        self.engine.handle(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method};
    use locallycloud_core::integration::authorization::{
        AuthorizationError, AuthorizationEvaluator, AuthorizationRequest,
    };
    use std::sync::Mutex;

    #[derive(Default)]
    struct Engine {
        calls: Mutex<Vec<ServiceRequest>>,
    }

    #[async_trait]
    impl NativeHandler for Engine {
        async fn handle(&self, request: ServiceRequest) -> Response {
            let request_id = request.request_id.clone();
            self.calls.lock().unwrap().push(request);
            DdbError::Internal("engine is unavailable".into()).into_response(&request_id)
        }
    }

    #[async_trait]
    impl DynamoEngine for Engine {
        fn supports_backups(&self) -> bool {
            true
        }
        async fn resolve_stream_iterator(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<String, DdbError> {
            Err(DdbError::Validation("invalid shard iterator".into()))
        }
    }

    #[derive(Default)]
    struct Deny {
        calls: Mutex<Vec<AuthorizationRequest>>,
    }

    impl AuthorizationEvaluator for Deny {
        fn strict_sigv4_required(&self) -> bool {
            true
        }

        fn authorize(&self, request: AuthorizationRequest) -> Result<(), AuthorizationError> {
            self.calls.lock().unwrap().push(request);
            Err(AuthorizationError::Denied)
        }
    }

    fn request(prefix: &str, op: &str, body: &str) -> ServiceRequest {
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
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "engine-test".into(),
        }
    }

    fn handler(registry: &Arc<ServiceRegistry>, engine: &Arc<Engine>) -> EngineHandler {
        EngineHandler {
            engine: engine.clone(),
            registry: Arc::downgrade(registry),
            prefix: TARGET_PREFIX,
        }
    }

    #[tokio::test]
    async fn engine_failure_is_returned_and_scope_is_preserved() {
        let registry = Arc::new(ServiceRegistry::new());
        let engine = Arc::new(Engine::default());
        let handler = handler(&registry, &engine);
        let response = handler
            .handle(request(TARGET_PREFIX, "ListTables", "{}"))
            .await;
        assert_eq!(response.status(), 500);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["message"], "engine is unavailable");
        let calls = engine.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].account_id, "000000000000");
        assert_eq!(calls[0].region, "us-east-1");
    }

    #[tokio::test]
    async fn unsupported_filesystem_operations_and_foreign_scope_never_reach_engine() {
        let registry = Arc::new(ServiceRegistry::new());
        let engine = Arc::new(Engine::default());
        let handler = handler(&registry, &engine);
        for (op, body) in [
            ("ImportTable", r#"{"FileSource":"/etc/passwd"}"#),
            ("ExportTableToPointInTime", "{}"),
            ("DescribeEndpoints", "{}"),
            ("ExecuteStatement", "{}"),
            ("Unknown", "{}"),
            (
                "GetItem",
                r#"{"TableName":"arn:aws:dynamodb:us-east-2:000000000000:table/other"}"#,
            ),
            (
                "GetItem",
                r#"{"TableName":"arn:aws:dynamodb:us-east-1:999999999999:table/other"}"#,
            ),
            ("CreateTable", r#"{"SSESpecification":{"SSEType":"KMS"}}"#),
            ("CreateTable", r#"{"SSESpecification":{"Enabled":false}}"#),
            ("UpdateTable", r#"{"ReplicaUpdates":[]}"#),
            ("CreateTable", r#"{"Replicas":[]}"#),
            ("UpdateTable", r#"{"GlobalTableVersion":"2019.11.21"}"#),
            ("UpdateTable", r#"{"GlobalTableWitnessUpdates":[]}"#),
            ("CreateTable", r#"{"MultiRegionConsistency":"STRONG"}"#),
            ("CreateTable", r#"{"ResourcePolicy":"{}"}"#),
        ] {
            assert_eq!(
                handler
                    .handle(request(TARGET_PREFIX, op, body))
                    .await
                    .status(),
                400
            );
        }
        assert!(engine.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn strict_authorization_rejects_signed_and_delegated_denials_before_engine() {
        let registry = Arc::new(ServiceRegistry::new());
        let engine = Arc::new(Engine::default());
        let evaluator = Arc::new(Deny::default());
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            engine.clone(),
            evaluator.clone(),
        );
        let handler = handler(&registry, &engine);
        let mut signed = request(TARGET_PREFIX, "GetItem", r#"{"TableName":"orders"}"#);
        signed.headers.insert(http::header::AUTHORIZATION, HeaderValue::from_static(
            "AWS4-HMAC-SHA256 Credential=AKIATEST/20261106/us-east-1/dynamodb/aws4_request, SignedHeaders=host, Signature=test",
        ));
        assert_eq!(handler.handle(signed).await.status(), 400);
        let mut delegated = request(TARGET_PREFIX, "GetItem", r#"{"TableName":"orders"}"#);
        delegated.headers.insert(
            "x-locallycloud-verified-internal-scope",
            HeaderValue::from_static("1"),
        );
        delegated.headers.insert(
            "x-locallycloud-caller-principal",
            HeaderValue::from_static("arn:aws:iam::000000000000:role/worker/sfn"),
        );
        assert_eq!(handler.handle(delegated).await.status(), 400);
        assert!(engine.calls.lock().unwrap().is_empty());
        let evaluations = evaluator.calls.lock().unwrap();
        assert_eq!(evaluations.len(), 2);
        assert_eq!(evaluations[0].action, "dynamodb:GetItem");
        assert_eq!(
            evaluations[0].resource,
            "arn:aws:dynamodb:us-east-1:000000000000:table/orders"
        );
        assert!(evaluations[1].request_identity.access_key_id.is_none());
        assert!(evaluations[1].delegated_identity.is_some());
    }

    #[tokio::test]
    async fn streams_use_same_engine_with_the_original_target() {
        let registry = Arc::new(ServiceRegistry::new());
        let engine = Arc::new(Engine::default());
        let mut handler = handler(&registry, &engine);
        handler.prefix = STREAMS_TARGET_PREFIX;
        let response = handler
            .handle(request(STREAMS_TARGET_PREFIX, "ListStreams", "{}"))
            .await;
        assert_eq!(response.status(), 500);
        assert_eq!(
            engine.calls.lock().unwrap()[0].headers["x-amz-target"],
            "DynamoDBStreams_20120810.ListStreams"
        );
    }

    #[tokio::test]
    async fn backup_scope_and_restore_overrides_fail_before_dispatch() {
        let registry = Arc::new(ServiceRegistry::new());
        let engine = Arc::new(Engine::default());
        let handler = handler(&registry, &engine);
        let backup = "arn:aws:dynamodb:us-east-1:000000000000:table/orders/backup/123-abc";
        for body in [
            json!({"BackupArn":backup,"TargetTableName":"target","SSESpecificationOverride":{"Enabled":true}}),
            json!({"BackupArn":backup,"TargetTableName":"target","GlobalSecondaryIndexOverride":[]}),
            json!({"BackupArn":backup,"TargetTableName":"../target"}),
            json!({"BackupArn":"arn:aws:dynamodb:us-east-2:000000000000:table/orders/backup/123-abc","TargetTableName":"target"}),
        ] {
            assert_eq!(
                handler
                    .handle(request(
                        TARGET_PREFIX,
                        "RestoreTableFromBackup",
                        &body.to_string()
                    ))
                    .await
                    .status(),
                400
            );
        }
        assert!(engine.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn backup_iam_targets_ignore_forged_table_fields_and_cover_restore_writes() {
        let arn = "arn:aws:dynamodb:us-east-1:000000000000:table/orders/backup/123-abc";
        let targets = service::authorization_targets(
            "DescribeBackup",
            &json!({"BackupArn":arn,"TableName":"forged"}),
        )
        .unwrap();
        assert_eq!(targets, vec![("DescribeBackup".into(), arn.into())]);
        assert_eq!(
            service::authorization_targets("ListBackups", &json!({"TableName":"orders"})).unwrap(),
            vec![("ListBackups".into(), "*".into())]
        );
        let targets = service::authorization_targets(
            "RestoreTableFromBackup",
            &json!({"BackupArn":arn,"TargetTableName":"restored"}),
        )
        .unwrap();
        assert_eq!(targets.len(), 9);
        assert_eq!(targets[0], ("RestoreTableFromBackup".into(), arn.into()));
        assert!(targets
            .iter()
            .any(|(action, table)| action == "PutItem" && table == "restored"));
        assert!(targets
            .iter()
            .any(|(action, table)| action == "GetItem" && table == "restored"));
    }

    const ALLOWED_STREAM: &str =
        "arn:aws:dynamodb:us-east-1:000000000000:table/orders/stream/2026-11-06T01:02:03.000";
    const OTHER_STREAM: &str =
        "arn:aws:dynamodb:us-east-1:000000000000:table/private/stream/2026-11-06T01:02:03.000";

    #[derive(Default)]
    struct IteratorEngine {
        calls: Mutex<Vec<ServiceRequest>>,
        resolutions: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl NativeHandler for IteratorEngine {
        async fn handle(&self, request: ServiceRequest) -> Response {
            self.calls.lock().unwrap().push(request);
            http::Response::builder()
                .status(200)
                .body(axum::body::Body::from(
                    r#"{"Records":[],"NextShardIterator":"next"}"#,
                ))
                .unwrap()
        }
    }

    #[async_trait]
    impl DynamoEngine for IteratorEngine {
        async fn resolve_stream_iterator(
            &self,
            account: &str,
            region: &str,
            token: &str,
        ) -> Result<String, DdbError> {
            assert_eq!(account, "000000000000");
            assert_eq!(region, "us-east-1");
            self.resolutions.lock().unwrap().push(token.into());
            match token {
                "allowed" | "next" => Ok(ALLOWED_STREAM.into()),
                "other" => Ok(OTHER_STREAM.into()),
                "foreign-region" => Ok(ALLOWED_STREAM.replace("us-east-1", "us-east-2")),
                "foreign-account" => Ok(ALLOWED_STREAM.replace("000000000000", "999999999999")),
                "expired" => Err(DdbError::ExpiredIterator(
                    "Shard iterator has expired".into(),
                )),
                _ => Err(DdbError::Validation("Invalid ShardIterator".into())),
            }
        }
    }

    #[derive(Default)]
    struct StreamPolicy {
        calls: Mutex<Vec<AuthorizationRequest>>,
        allowed: Option<String>,
    }

    impl AuthorizationEvaluator for StreamPolicy {
        fn strict_sigv4_required(&self) -> bool {
            true
        }

        fn authorize(&self, request: AuthorizationRequest) -> Result<(), AuthorizationError> {
            let allowed = self.allowed.as_ref().map_or_else(
                || {
                    request.resource == ALLOWED_STREAM
                        || request.resource
                            == "arn:aws:dynamodb:us-east-1:000000000000:table/orders"
                },
                |arn| request.resource == *arn,
            );
            self.calls.lock().unwrap().push(request);
            if allowed {
                Ok(())
            } else {
                Err(AuthorizationError::Denied)
            }
        }
    }

    fn signed_stream_request(operation: &str, body: Value) -> ServiceRequest {
        let mut request = request(STREAMS_TARGET_PREFIX, operation, &body.to_string());
        request.headers.insert(http::header::AUTHORIZATION, HeaderValue::from_static(
            "AWS4-HMAC-SHA256 Credential=AKIATEST/20261106/us-east-1/dynamodb/aws4_request, SignedHeaders=host, Signature=test",
        ));
        request
    }

    #[tokio::test]
    async fn opaque_iterators_authorize_the_backend_stream_and_forward_original_body() {
        let registry = Arc::new(ServiceRegistry::new());
        let engine = Arc::new(IteratorEngine::default());
        let policy = Arc::new(StreamPolicy::default());
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            engine.clone(),
            policy.clone(),
        );
        let handler = EngineHandler {
            engine: engine.clone(),
            registry: Arc::downgrade(&registry),
            prefix: STREAMS_TARGET_PREFIX,
        };
        let original = json!({"ShardIterator":"allowed","StreamArn":OTHER_STREAM});
        assert_eq!(
            handler
                .handle(signed_stream_request("GetRecords", original.clone()))
                .await
                .status(),
            200
        );
        assert_eq!(
            handler
                .handle(signed_stream_request(
                    "GetRecords",
                    json!({"ShardIterator":"next"})
                ))
                .await
                .status(),
            200
        );
        assert_eq!(
            handler
                .handle(signed_stream_request(
                    "GetRecords",
                    json!({"ShardIterator":"other","StreamArn":ALLOWED_STREAM,"TableName":"orders"})
                ))
                .await
                .status(),
            400
        );
        let requests = engine.calls.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
            original
        );
        let evaluations = policy.calls.lock().unwrap();
        assert_eq!(
            evaluations
                .iter()
                .map(|request| request.resource.as_str())
                .collect::<Vec<_>>(),
            vec![ALLOWED_STREAM, ALLOWED_STREAM, OTHER_STREAM]
        );
        assert!(evaluations
            .iter()
            .all(|request| request.action == "dynamodb:GetRecords"));
    }

    #[tokio::test]
    async fn invalid_expired_and_cross_scope_iterators_never_read_engine_data() {
        let registry = Arc::new(ServiceRegistry::new());
        let engine = Arc::new(IteratorEngine::default());
        let handler = EngineHandler {
            engine: engine.clone(),
            registry: Arc::downgrade(&registry),
            prefix: STREAMS_TARGET_PREFIX,
        };
        for (token, error) in [
            ("malformed", "ValidationException"),
            ("expired", "ExpiredIteratorException"),
            ("foreign-account", "ValidationException"),
            ("foreign-region", "ValidationException"),
        ] {
            let response = handler
                .handle(signed_stream_request(
                    "GetRecords",
                    json!({"ShardIterator":token,"StreamArn":ALLOWED_STREAM}),
                ))
                .await;
            assert_eq!(response.status(), 400);
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                    .unwrap();
            assert!(body["__type"].as_str().unwrap().ends_with(error));
        }
        let response = handler
            .handle(signed_stream_request(
                "GetRecords",
                json!({"ShardIterator":"x".repeat(2049)}),
            ))
            .await;
        assert_eq!(response.status(), 400);
        for (limit, error) in [
            (json!(0), "ValidationException"),
            (json!(-1), "ValidationException"),
            (json!(1001), "LimitExceededException"),
            (json!("100"), "ValidationException"),
        ] {
            let response = handler
                .handle(signed_stream_request(
                    "GetRecords",
                    json!({"ShardIterator":"allowed","Limit":limit}),
                ))
                .await;
            assert_eq!(response.status(), 400);
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                    .unwrap();
            assert!(body["__type"].as_str().unwrap().ends_with(error));
        }
        assert_eq!(engine.resolutions.lock().unwrap().len(), 4);
        assert!(engine.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unknown_table_name_fields_cannot_override_stream_or_tag_authorization() {
        let registry = Arc::new(ServiceRegistry::new());
        let engine = Arc::new(IteratorEngine::default());
        let policy = Arc::new(StreamPolicy::default());
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            engine.clone(),
            policy.clone(),
        );
        let mut handler = EngineHandler {
            engine: engine.clone(),
            registry: Arc::downgrade(&registry),
            prefix: STREAMS_TARGET_PREFIX,
        };
        for op in ["DescribeStream", "GetShardIterator"] {
            assert_eq!(
                handler
                    .handle(signed_stream_request(
                        op,
                        json!({"StreamArn":OTHER_STREAM,"TableName":"orders"})
                    ))
                    .await
                    .status(),
                400
            );
        }
        handler.prefix = TARGET_PREFIX;
        let other_table = "arn:aws:dynamodb:us-east-1:000000000000:table/private";
        for op in ["TagResource", "UntagResource", "ListTagsOfResource"] {
            let mut req =
                signed_stream_request(op, json!({"ResourceArn":other_table,"TableName":"orders"}));
            req.headers.insert(
                "x-amz-target",
                HeaderValue::from_str(&format!("{TARGET_PREFIX}.{op}")).unwrap(),
            );
            assert_eq!(handler.handle(req).await.status(), 400);
        }
        assert!(engine.calls.lock().unwrap().is_empty());
        let evaluations = policy.calls.lock().unwrap();
        assert_eq!(evaluations.len(), 5);
        assert!(evaluations[..2]
            .iter()
            .all(|request| request.resource == OTHER_STREAM));
        assert!(evaluations[2..]
            .iter()
            .all(|request| request.resource == other_table));
    }

    async fn native_json(
        handler: &Arc<dyn NativeHandler>,
        prefix: &str,
        op: &str,
        body: Value,
    ) -> Value {
        let response = handler.handle(request(prefix, op, &body.to_string())).await;
        assert_eq!(response.status(), 200);
        serde_json::from_slice(&to_bytes(response.into_body(), 1_048_576).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn native_stream_frontiers_and_strict_permissions_use_actual_iterator_ownership() {
        let registry = Arc::new(ServiceRegistry::new());
        service::register(&registry);
        let data = registry
            .native_handler(&ServiceName::new("dynamodb"))
            .unwrap();
        let stream = registry
            .native_handler(&ServiceName::new("streams.dynamodb"))
            .unwrap();
        let api = registry
            .dynamodb_streams_api(&ServiceName::new("streams.dynamodb"))
            .unwrap();
        let mut sources = Vec::new();
        for name in ["orders", "private"] {
            let table = native_json(&data,TARGET_PREFIX,"CreateTable",json!({"TableName":name,"KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST","StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_AND_OLD_IMAGES"}})).await;
            let arn = table["TableDescription"]["LatestStreamArn"]
                .as_str()
                .unwrap()
                .to_owned();
            let description = native_json(
                &stream,
                STREAMS_TARGET_PREFIX,
                "DescribeStream",
                json!({"StreamArn":arn}),
            )
            .await;
            let shard = description["StreamDescription"]["Shards"][0]["ShardId"]
                .as_str()
                .unwrap();
            let iterator = native_json(
                &stream,
                STREAMS_TARGET_PREFIX,
                "GetShardIterator",
                json!({"StreamArn":arn,"ShardId":shard,"ShardIteratorType":"LATEST"}),
            )
            .await;
            let iterator = iterator["ShardIterator"].as_str().unwrap().to_owned();
            assert_eq!(
                api.sequence_after_iterator("000000000000", "us-east-1", &iterator)
                    .await
                    .unwrap(),
                ""
            );
            native_json(
                &data,
                TARGET_PREFIX,
                "PutItem",
                json!({"TableName":name,"Item":{"id":{"S":"first"}}}),
            )
            .await;
            let records = native_json(
                &stream,
                STREAMS_TARGET_PREFIX,
                "GetRecords",
                json!({"ShardIterator":iterator}),
            )
            .await;
            let sequence = records["Records"][0]["dynamodb"]["SequenceNumber"]
                .as_str()
                .unwrap()
                .to_owned();
            let frontier = records["NextShardIterator"].as_str().unwrap().to_owned();
            assert_eq!(
                api.sequence_after_iterator("000000000000", "us-east-1", &frontier)
                    .await
                    .unwrap(),
                sequence
            );
            native_json(
                &data,
                TARGET_PREFIX,
                "PutItem",
                json!({"TableName":name,"Item":{"id":{"S":"second"}}}),
            )
            .await;
            assert_eq!(
                api.sequence_after_iterator("000000000000", "us-east-1", &frontier)
                    .await
                    .unwrap(),
                sequence
            );
            assert!(api
                .sequence_after_iterator("999999999999", "us-east-1", &frontier)
                .await
                .is_err());
            assert!(api
                .sequence_after_iterator("000000000000", "us-east-2", &frontier)
                .await
                .is_err());
            sources.push((arn, frontier));
        }
        let policy = Arc::new(StreamPolicy {
            allowed: Some(sources[0].0.clone()),
            ..Default::default()
        });
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            data.clone(),
            policy.clone(),
        );
        assert_eq!(
            stream
                .handle(signed_stream_request(
                    "GetRecords",
                    json!({"ShardIterator":sources[0].1})
                ))
                .await
                .status(),
            200
        );
        assert_eq!(stream.handle(signed_stream_request("GetRecords",json!({"ShardIterator":sources[1].1,"StreamArn":sources[0].0,"TableName":"orders"}))).await.status(),400);
        let calls = policy.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].resource, sources[0].0);
        assert_eq!(calls[1].resource, sources[1].0);
    }

    #[tokio::test]
    async fn native_large_stream_pages_preserve_the_unread_record() {
        let registry = Arc::new(ServiceRegistry::new());
        service::register(&registry);
        let data = registry
            .native_handler(&ServiceName::new("dynamodb"))
            .unwrap();
        let stream = registry
            .native_handler(&ServiceName::new("streams.dynamodb"))
            .unwrap();
        let table = native_json(&data,TARGET_PREFIX,"CreateTable",json!({"TableName":"large","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST","StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_AND_OLD_IMAGES"}})).await;
        let arn = table["TableDescription"]["LatestStreamArn"]
            .as_str()
            .unwrap();
        let description = native_json(
            &stream,
            STREAMS_TARGET_PREFIX,
            "DescribeStream",
            json!({"StreamArn":arn}),
        )
        .await;
        let shard = description["StreamDescription"]["Shards"][0]["ShardId"]
            .as_str()
            .unwrap();
        for index in 0..3 {
            native_json(&data,TARGET_PREFIX,"PutItem",json!({"TableName":"large","Item":{"id":{"S":index.to_string()},"payload":{"S":"x".repeat(360*1024)}}})).await;
        }
        let start = native_json(
            &stream,
            STREAMS_TARGET_PREFIX,
            "GetShardIterator",
            json!({"StreamArn":arn,"ShardId":shard,"ShardIteratorType":"TRIM_HORIZON"}),
        )
        .await;
        let first = native_json(
            &stream,
            STREAMS_TARGET_PREFIX,
            "GetRecords",
            json!({"ShardIterator":start["ShardIterator"]}),
        )
        .await;
        let second = native_json(
            &stream,
            STREAMS_TARGET_PREFIX,
            "GetRecords",
            json!({"ShardIterator":first["NextShardIterator"]}),
        )
        .await;
        assert_eq!(first["Records"].as_array().unwrap().len(), 2);
        assert_eq!(second["Records"].as_array().unwrap().len(), 1);
        let keys = first["Records"]
            .as_array()
            .unwrap()
            .iter()
            .chain(second["Records"].as_array().unwrap())
            .map(|record| record["dynamodb"]["Keys"]["id"]["S"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["0", "1", "2"]);
        let end = native_json(
            &stream,
            STREAMS_TARGET_PREFIX,
            "GetRecords",
            json!({"ShardIterator":second["NextShardIterator"]}),
        )
        .await;
        assert!(end["Records"].as_array().unwrap().is_empty());
    }
}
