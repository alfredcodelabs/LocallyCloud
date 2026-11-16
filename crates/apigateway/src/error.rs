//! API Gateway error model rendered as the REST-JSON `{"message":...}` shape with an
//! `x-amzn-errortype` header (shared by the v1 and v2 control planes).

use axum::http::{header::RETRY_AFTER, HeaderValue};
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::registry::AwsProtocol;

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
            ApiGwError::Internal(_) => "InternalFailure",
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
        locallycloud_core::observability::log_service_error(
            "apigateway",
            None,
            request_id,
            self.code(),
            self.http_status(),
        );
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

/// Internal invocation causes remain distinct from control-plane AWS exceptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InvokeFailure {
    Configuration,
    Dispatch,
    Timeout,
    Http(crate::http_integration::HttpIntegrationError),
    ResponseTooLarge,
    ResponseRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewayFailure {
    Configuration,
    Integration,
    Timeout,
    Internal,
}

impl GatewayFailure {
    pub(crate) fn response_type(self) -> &'static str {
        match self {
            Self::Configuration => "API_CONFIGURATION_ERROR",
            Self::Integration => "INTEGRATION_FAILURE",
            Self::Timeout => "INTEGRATION_TIMEOUT",
            Self::Internal => "DEFAULT_5XX",
        }
    }

    pub(crate) fn status(self) -> u16 {
        match self {
            Self::Configuration | Self::Internal => 500,
            Self::Integration | Self::Timeout => 504,
        }
    }

    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Timeout => "Endpoint request timed out",
            Self::Configuration | Self::Integration | Self::Internal => "Internal server error",
        }
    }
}

impl InvokeFailure {
    pub(crate) fn http_api_status(self) -> u16 {
        use crate::http_integration::HttpIntegrationError as HttpError;
        match self {
            Self::Timeout | Self::Http(HttpError::Timeout) => 504,
            Self::Configuration
            | Self::Dispatch
            | Self::ResponseTooLarge
            | Self::ResponseRead
            | Self::Http(
                HttpError::InvalidUrl
                | HttpError::InvalidOrigin(_)
                | HttpError::DestinationDenied
                | HttpError::HostProbe
                | HttpError::DnsResolution
                | HttpError::DnsAnswers
                | HttpError::CacheUnavailable
                | HttpError::ClientInitialization
                | HttpError::TlsConfiguration
                | HttpError::Connection,
            ) => 500,
        }
    }

    pub(crate) fn gateway_failure(self) -> GatewayFailure {
        use crate::http_integration::HttpIntegrationError as HttpError;
        match self {
            Self::Configuration => GatewayFailure::Configuration,
            Self::Timeout | Self::Http(HttpError::Timeout) => GatewayFailure::Timeout,
            Self::Http(HttpError::Connection) | Self::ResponseRead => GatewayFailure::Integration,
            Self::Http(
                HttpError::InvalidUrl
                | HttpError::InvalidOrigin(_)
                | HttpError::DestinationDenied
                | HttpError::HostProbe
                | HttpError::DnsResolution
                | HttpError::DnsAnswers
                | HttpError::CacheUnavailable
                | HttpError::ClientInitialization
                | HttpError::TlsConfiguration,
            ) => GatewayFailure::Configuration,
            // AWS's exact oversized backend response error is not yet verified.
            // Preserve its existing generic 500, rather than treating it as request 413.
            Self::ResponseTooLarge | Self::Dispatch => GatewayFailure::Internal,
        }
    }

    pub(crate) fn cause_code(self) -> &'static str {
        use crate::http_integration::HttpIntegrationError as HttpError;
        match self {
            Self::Configuration => "integration_configuration",
            Self::Dispatch => "integration_dispatch",
            Self::Timeout | Self::Http(HttpError::Timeout) => "integration_timeout",
            Self::Http(HttpError::InvalidUrl | HttpError::InvalidOrigin(_)) => {
                "invalid_integration_url"
            }
            Self::Http(HttpError::DestinationDenied) => "destination_denied",
            Self::Http(HttpError::HostProbe) => "host_address_check_failed",
            Self::Http(HttpError::DnsAnswers) => "dns_answer_limit",
            Self::Http(HttpError::DnsResolution) => "dns_resolution_failed",
            Self::Http(HttpError::CacheUnavailable) => "http_client_cache_unavailable",
            Self::Http(HttpError::ClientInitialization) => "http_client_initialization_failed",
            Self::Http(HttpError::TlsConfiguration) => "tls_configuration_failed",
            Self::Http(HttpError::Connection) => "connection_failed",
            Self::ResponseTooLarge => "integration_response_too_large",
            Self::ResponseRead => "integration_response_read_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integration_contracts_distinguish_configuration_transport_and_response_size() {
        use crate::http_integration::HttpIntegrationError as HttpError;
        let configuration = InvokeFailure::Http(HttpError::DestinationDenied);
        let transport = InvokeFailure::Http(HttpError::Connection);
        let timeout = InvokeFailure::Http(HttpError::Timeout);
        assert_eq!(
            configuration.gateway_failure().response_type(),
            "API_CONFIGURATION_ERROR"
        );
        assert_eq!(configuration.gateway_failure().status(), 500);
        assert_eq!(
            transport.gateway_failure().response_type(),
            "INTEGRATION_FAILURE"
        );
        assert_eq!(transport.gateway_failure().status(), 504);
        assert_eq!(
            timeout.gateway_failure().response_type(),
            "INTEGRATION_TIMEOUT"
        );
        assert_eq!(timeout.gateway_failure().status(), 504);
        assert_eq!(
            InvokeFailure::ResponseTooLarge
                .gateway_failure()
                .response_type(),
            "DEFAULT_5XX"
        );
        assert_eq!(
            InvokeFailure::ResponseTooLarge.gateway_failure().status(),
            500
        );
        assert_eq!(transport.http_api_status(), 500);
        assert_eq!(timeout.http_api_status(), 504);
    }

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
            (ApiGwError::Internal("x".into()), "InternalFailure", 500),
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
