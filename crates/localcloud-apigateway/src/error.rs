//! API Gateway error model rendered as the REST-JSON `{"message":...}` shape with an
//! `x-amzn-errortype` header (shared by the v1 and v2 control planes).

use axum::http::{header::RETRY_AFTER, HeaderValue};
use localcloud_core::error_mapping::AwsError;
use localcloud_core::registry::AwsProtocol;

const RETRY_AFTER_SECONDS: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiGwError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    LimitExceeded(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    TooManyRequests(String),
    #[error("{0}")]
    Internal(String),
    #[error("{0}")]
    Gone(String),
    #[error("{0}")]
    PayloadTooLarge(String),
}

impl ApiGwError {
    pub fn code(&self) -> &'static str {
        match self {
            ApiGwError::NotFound(_) => "NotFoundException",
            ApiGwError::BadRequest(_) => "BadRequestException",
            ApiGwError::Conflict(_) => "ConflictException",
            ApiGwError::LimitExceeded(_) => "LimitExceededException",
            ApiGwError::Unauthorized(_) => "UnauthorizedException",
            ApiGwError::Forbidden(_) => "ForbiddenException",
            ApiGwError::TooManyRequests(_) => "TooManyRequestsException",
            ApiGwError::Internal(_) => "InternalFailureException",
            ApiGwError::Gone(_) => "GoneException",
            ApiGwError::PayloadTooLarge(_) => "PayloadTooLargeException",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            ApiGwError::NotFound(_) => 404,
            ApiGwError::BadRequest(_) => 400,
            ApiGwError::Conflict(_) => 409,
            ApiGwError::LimitExceeded(_) | ApiGwError::TooManyRequests(_) => 429,
            ApiGwError::Unauthorized(_) => 401,
            ApiGwError::Forbidden(_) => 403,
            ApiGwError::Internal(_) => 500,
            ApiGwError::Gone(_) => 410,
            ApiGwError::PayloadTooLarge(_) => 413,
        }
    }

    pub fn into_response(self, request_id: &str) -> axum::response::Response {
        let is_throttled = self.http_status() == 429;
        let mut response = AwsError::new(self.code(), self.to_string(), self.http_status())
            .with_request_id(request_id.to_string())
            .render(AwsProtocol::RestJson)
            .into_response();
        if is_throttled {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER_SECONDS));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_statuses() {
        let cases = [
            (ApiGwError::NotFound("x".into()), "NotFoundException", 404),
            (
                ApiGwError::BadRequest("x".into()),
                "BadRequestException",
                400,
            ),
            (ApiGwError::Conflict("x".into()), "ConflictException", 409),
            (
                ApiGwError::LimitExceeded("x".into()),
                "LimitExceededException",
                429,
            ),
            (
                ApiGwError::Unauthorized("x".into()),
                "UnauthorizedException",
                401,
            ),
            (
                ApiGwError::TooManyRequests("x".into()),
                "TooManyRequestsException",
                429,
            ),
            (
                ApiGwError::Internal("x".into()),
                "InternalFailureException",
                500,
            ),
            (ApiGwError::Gone("x".into()), "GoneException", 410),
            (
                ApiGwError::PayloadTooLarge("x".into()),
                "PayloadTooLargeException",
                413,
            ),
        ];

        for (error, code, status) in cases {
            assert_eq!(error.code(), code);
            assert_eq!(error.http_status(), status);
        }
    }

    #[test]
    fn renders_rest_json_error_headers() {
        let response = ApiGwError::BadRequest("bad".into()).into_response("rid");
        assert_eq!(response.status(), 400);
        assert_eq!(
            response.headers().get("x-amzn-errortype").unwrap(),
            "BadRequestException"
        );
        assert_eq!(response.headers().get("x-amzn-requestid").unwrap(), "rid");
        assert!(!response.headers().contains_key(RETRY_AFTER));
    }

    #[test]
    fn throttling_responses_include_retry_after() {
        for error in [
            ApiGwError::LimitExceeded("quota exceeded".into()),
            ApiGwError::TooManyRequests("slow down".into()),
        ] {
            let response = error.into_response("rid");
            assert_eq!(response.status(), 429);
            assert_eq!(
                response.headers().get(RETRY_AFTER).unwrap(),
                RETRY_AFTER_SECONDS
            );
        }
    }
}
