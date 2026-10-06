//! DynamoDB errors mapped to the AWS JSON 1.0 `__type` shape.
//!
//! Each variant renders as `{"__type":"com.amazonaws.dynamodb.v20120810#<Exception>",
//! "message":...}` with the AWS-faithful HTTP status. `TransactionCanceledException`
//! additionally serializes ordered `CancellationReasons`.

use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::registry::AwsProtocol;

const TYPE_PREFIX: &str = "com.amazonaws.dynamodb.v20120810#";

/// A DynamoDB API error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DdbError {
    #[error("{0}")]
    AccessDenied(String),
    #[error("{0}")]
    ResourceNotFound(String),
    #[error("{0}")]
    ResourceInUse(String),
    #[error("{0}")]
    ConditionalCheckFailed(String),
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    ProvisionedThroughputExceeded(String),
    #[error("{0}")]
    Throttling(String),
    #[error("transaction cancelled")]
    TransactionCanceled(Vec<CancellationReason>),
    #[error("{0}")]
    TransactionConflict(String),
    #[error("{0}")]
    IdempotentParameterMismatch(String),
    #[error("{0}")]
    ExportNotFound(String),
    #[error("{0}")]
    UnknownOperation(String),
    #[error("{0}")]
    Internal(String),
}

/// A per-action reason in a cancelled transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancellationReason {
    pub code: String,
    pub message: Option<String>,
}

impl CancellationReason {
    pub fn none() -> Self {
        CancellationReason {
            code: "None".to_string(),
            message: None,
        }
    }
    pub fn new(code: &str, message: Option<String>) -> Self {
        CancellationReason {
            code: code.to_string(),
            message,
        }
    }
}

impl DdbError {
    fn exception(&self) -> &'static str {
        match self {
            DdbError::AccessDenied(_) => "AccessDeniedException",
            DdbError::ResourceNotFound(_) => "ResourceNotFoundException",
            DdbError::ResourceInUse(_) => "ResourceInUseException",
            DdbError::ConditionalCheckFailed(_) => "ConditionalCheckFailedException",
            DdbError::Validation(_) => "ValidationException",
            DdbError::ProvisionedThroughputExceeded(_) => "ProvisionedThroughputExceededException",
            DdbError::Throttling(_) => "ThrottlingException",
            DdbError::TransactionCanceled(_) => "TransactionCanceledException",
            DdbError::TransactionConflict(_) => "TransactionConflictException",
            DdbError::IdempotentParameterMismatch(_) => "IdempotentParameterMismatchException",
            DdbError::ExportNotFound(_) => "ExportNotFoundException",
            DdbError::UnknownOperation(_) => "UnknownOperationException",
            DdbError::Internal(_) => "InternalServerError",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            DdbError::ResourceNotFound(_)
            | DdbError::AccessDenied(_)
            | DdbError::ResourceInUse(_)
            | DdbError::ConditionalCheckFailed(_)
            | DdbError::Validation(_)
            | DdbError::ProvisionedThroughputExceeded(_)
            | DdbError::Throttling(_)
            | DdbError::TransactionCanceled(_)
            | DdbError::TransactionConflict(_)
            | DdbError::IdempotentParameterMismatch(_)
            | DdbError::ExportNotFound(_)
            | DdbError::UnknownOperation(_) => 400,
            DdbError::Internal(_) => 500,
        }
    }

    fn qualified_type(&self) -> String {
        format!("{TYPE_PREFIX}{}", self.exception())
    }

    /// Short error code used in `BatchExecuteStatement` per-statement error entries.
    pub fn batch_code(&self) -> &'static str {
        match self {
            DdbError::AccessDenied(_) => "AccessDenied",
            DdbError::ResourceNotFound(_) => "ResourceNotFound",
            DdbError::ConditionalCheckFailed(_) => "ConditionalCheckFailed",
            DdbError::ProvisionedThroughputExceeded(_) => "ProvisionedThroughputExceeded",
            DdbError::Throttling(_) => "ThrottlingError",
            DdbError::TransactionConflict(_) => "TransactionConflict",
            DdbError::IdempotentParameterMismatch(_) => "IdempotentParameterMismatch",
            _ => "ValidationError",
        }
    }

    /// Render to an Axum response as the JSON 1.0 error shape.
    pub fn into_response(self, request_id: &str) -> axum::response::Response {
        if let DdbError::TransactionCanceled(reasons) = &self {
            return self.render_transaction_canceled(reasons, request_id);
        }
        AwsError::new(self.qualified_type(), self.to_string(), self.http_status())
            .with_request_id(request_id.to_string())
            .render(AwsProtocol::Json10)
            .into_response()
    }

    fn render_transaction_canceled(
        &self,
        reasons: &[CancellationReason],
        request_id: &str,
    ) -> axum::response::Response {
        let reasons_json: Vec<serde_json::Value> = reasons
            .iter()
            .map(|r| {
                let mut obj = serde_json::Map::new();
                obj.insert(
                    "Code".to_string(),
                    serde_json::Value::String(r.code.clone()),
                );
                if let Some(m) = &r.message {
                    obj.insert("Message".to_string(), serde_json::Value::String(m.clone()));
                }
                serde_json::Value::Object(obj)
            })
            .collect();
        let body = serde_json::json!({
            "__type": self.qualified_type(),
            "message": "Transaction cancelled, please refer cancellation reasons for specific reasons",
            "CancellationReasons": reasons_json,
        });
        http::Response::builder()
            .status(self.http_status())
            .header("content-type", "application/x-amz-json-1.0")
            .header("x-amzn-RequestId", request_id)
            .body(axum::body::Body::from(body.to_string()))
            .expect("transaction-canceled error is always valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_type_has_prefix() {
        assert_eq!(
            DdbError::ResourceNotFound("x".into()).qualified_type(),
            "com.amazonaws.dynamodb.v20120810#ResourceNotFoundException"
        );
    }

    #[test]
    fn statuses() {
        assert_eq!(DdbError::Validation("x".into()).http_status(), 400);
        assert_eq!(DdbError::Internal("x".into()).http_status(), 500);
    }

    #[test]
    fn transaction_canceled_includes_reasons() {
        let err = DdbError::TransactionCanceled(vec![
            CancellationReason::none(),
            CancellationReason::new("ConditionalCheckFailed", Some("nope".into())),
        ]);
        let resp = err.into_response("rid");
        assert_eq!(resp.status(), 400);
    }
}
