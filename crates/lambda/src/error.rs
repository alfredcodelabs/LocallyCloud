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
    RequestTooLarge(String),
    #[error("{0}")]
    TooManyRequests(String),
    #[error("{0}")]
    InternalError(String),
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
            LambdaError::RequestTooLarge(_) => "RequestTooLargeException",
            LambdaError::TooManyRequests(_) => "TooManyRequestsException",
            LambdaError::InternalError(_) => "InternalServerError",
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
            LambdaError::RequestTooLarge(_) => 413,
            LambdaError::TooManyRequests(_) => 429,
            LambdaError::InternalError(_) => 500,
            LambdaError::NotImplemented(_) => 501,
        }
    }

    /// Render to an Axum response in the REST-JSON shape.
    pub fn into_response(self, request_id: &str) -> axum::response::Response {
        AwsError::new(self.code(), self.to_string(), self.http_status())
            .with_request_id(request_id.to_string())
            .with_rest_json_message_key("Message")
            .render(AwsProtocol::RestJson)
            .into_response()
    }
}
