//! Lambda control-plane errors mapped to the AWS REST-JSON error shape.

use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::registry::AwsProtocol;

/// A Lambda API error. Rendered as REST-JSON (`{"Message": ...}` body +
/// `x-amzn-errortype` header) via the Core error mapper.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LambdaError {
    #[error("{0}")]
    AccessDenied(String),
    #[error("{0}")]
    ResourceNotFound(String),
    #[error("{0}")]
    ResourceConflict(String),
    #[error("{0}")]
    InvalidParameterValue(String),
    #[error("{0}")]
    InvalidRequestContent(String),
    #[error("{0}")]
    CodeStorageExceeded(String),
    #[error("{0}")]
    PolicyLengthExceeded(String),
    #[error("{0}")]
    RequestTooLarge(String),
    #[error("{0}")]
    TooManyRequests(String),
    #[error("{0}")]
    InternalError(String),
    #[error("{0}")]
    LocalCapacityExceeded(String),
    #[error("{0}")]
    NotImplemented(String),
}

impl LambdaError {
    pub fn code(&self) -> &'static str {
        match self {
            LambdaError::AccessDenied(_) => "AccessDeniedException",
            LambdaError::ResourceNotFound(_) => "ResourceNotFoundException",
            LambdaError::ResourceConflict(_) => "ResourceConflictException",
            LambdaError::InvalidParameterValue(_) => "InvalidParameterValueException",
            LambdaError::InvalidRequestContent(_) => "InvalidRequestContentException",
            LambdaError::CodeStorageExceeded(_) => "CodeStorageExceededException",
            LambdaError::PolicyLengthExceeded(_) => "PolicyLengthExceededException",
            LambdaError::RequestTooLarge(_) => "RequestTooLargeException",
            LambdaError::TooManyRequests(_) => "TooManyRequestsException",
            LambdaError::InternalError(_) => "ServiceException",
            LambdaError::LocalCapacityExceeded(_) => "TooManyRequestsException",
            LambdaError::NotImplemented(_) => "NotImplementedException",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            LambdaError::AccessDenied(_) => 403,
            LambdaError::ResourceNotFound(_) => 404,
            LambdaError::ResourceConflict(_) => 409,
            LambdaError::InvalidParameterValue(_) => 400,
            LambdaError::InvalidRequestContent(_) => 400,
            LambdaError::CodeStorageExceeded(_) => 400,
            LambdaError::PolicyLengthExceeded(_) => 400,
            LambdaError::RequestTooLarge(_) => 413,
            LambdaError::TooManyRequests(_) => 429,
            LambdaError::InternalError(_) => 500,
            LambdaError::LocalCapacityExceeded(_) => 429,
            LambdaError::NotImplemented(_) => 501,
        }
    }

    /// Render to an Axum response in the REST-JSON shape.
    pub fn into_response(self, request_id: &str) -> axum::response::Response {
        locallycloud_core::observability::log_service_error(
            "lambda",
            None,
            request_id,
            self.code(),
            self.http_status(),
        );
        let throttled = matches!(
            self,
            Self::TooManyRequests(_) | Self::LocalCapacityExceeded(_)
        );
        let mut response = AwsError::new(self.code(), self.to_string(), self.http_status())
            .with_request_id(request_id.to_string())
            .with_rest_json_message_key("Message")
            .render(AwsProtocol::RestJson)
            .into_response();
        if throttled {
            response
                .headers_mut()
                .insert("retry-after", http::HeaderValue::from_static("1"));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn internal_failures_use_lambda_service_exception_and_request_correlation() {
        let response =
            LambdaError::InternalError("The Lambda service encountered an internal error".into())
                .into_response("owned-request");
        assert_eq!(response.status(), 500);
        assert_eq!(response.headers()["x-amzn-errortype"], "ServiceException");
        assert_eq!(response.headers()["x-amzn-requestid"], "owned-request");
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["Message"],
            "The Lambda service encountered an internal error"
        );
    }
}
