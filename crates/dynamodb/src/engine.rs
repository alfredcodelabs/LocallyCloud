//! Optional engine boundary. IAM and AWS protocol routing stay in LocalCloud.

use std::sync::{Arc, Weak};

use async_trait::async_trait;
use axum::response::Response;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use serde_json::Value;

use crate::error::DdbError;
use crate::service::{self, STREAMS_TARGET_PREFIX, TARGET_PREFIX};

struct EngineHandler {
    engine: Arc<dyn NativeHandler>,
    registry: Weak<ServiceRegistry>,
    prefix: &'static str,
}

/// Select one injected engine for both DynamoDB and Streams. This does not open,
/// migrate, or fall back to the native store. The engine owns account/region isolation.
pub fn register_with_engine(registry: &Arc<ServiceRegistry>, engine: Arc<dyn NativeHandler>) {
    for (name, prefix) in [
        ("dynamodb", TARGET_PREFIX),
        ("streams.dynamodb", STREAMS_TARGET_PREFIX),
    ] {
        registry.register_native(
            ServiceName::new(name),
            ServiceMetadata::new(AwsProtocol::Json10, Some(prefix)),
            Arc::new(EngineHandler {
                engine: engine.clone(),
                registry: Arc::downgrade(registry),
                prefix,
            }),
        );
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

fn validate_scope(request: &ServiceRequest, op: &str, body: &Value) -> Result<(), DdbError> {
    if request.account_id.len() != 12
        || !request.account_id.bytes().all(|c| c.is_ascii_digit())
        || !(3..=64).contains(&request.region.len())
        || !request
            .region
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err(DdbError::Validation(
            "invalid account or region scope".into(),
        ));
    }
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
    if matches!(op, "CreateTable" | "UpdateTable") {
        const UNSUPPORTED_FIELDS: &[&str] = &[
            "SSESpecification",
            "Replicas",
            "ReplicaUpdates",
            "GlobalTableVersion",
            "GlobalTableSettingsReplicationMode",
            "GlobalTableWitnesses",
            "GlobalTableWitnessUpdates",
            "MultiRegionConsistency",
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
        let body = match service::parse_body(&request) {
            Ok(body) => body,
            Err(error) => return error.into_response(&request.request_id),
        };
        if let Err(error) = validate_scope(&request, &op, &body)
            .and_then(|()| service::authorize(&self.registry, &request, &op, &body))
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
}
