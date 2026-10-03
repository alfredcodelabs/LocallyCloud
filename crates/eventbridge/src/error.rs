use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::registry::AwsProtocol;

macro_rules! error_type {
    ($name:ident, $protocol:expr, {$($variant:ident => ($code:literal, $status:literal)),+ $(,)?}) => {
        #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
        pub enum $name {
            $(#[error("{0}")] $variant(String),)+
        }
        impl $name {
            pub fn code(&self) -> &'static str {
                match self { $(Self::$variant(_) => $code,)+ }
            }
            pub fn http_status(&self) -> u16 {
                match self { $(Self::$variant(_) => $status,)+ }
            }
            pub fn into_response(self, request_id: &str) -> axum::response::Response {
                AwsError::new(self.code(), self.to_string(), self.http_status())
                    .with_request_id(request_id.to_string())
                    .render($protocol)
                    .into_response()
            }
        }
    };
}

error_type!(EventsError, AwsProtocol::Json11, {
    AccessDenied => ("AccessDeniedException", 403),
    ResourceNotFound => ("ResourceNotFoundException", 404),
    ResourceAlreadyExists => ("ResourceAlreadyExistsException", 409),
    InvalidEventPattern => ("InvalidEventPatternException", 400),
    Validation => ("ValidationException", 400),
    ConcurrentModification => ("ConcurrentModificationException", 400),
    LimitExceeded => ("LimitExceededException", 400),
    UnknownOperation => ("UnknownOperationException", 400),
    Internal => ("InternalException", 500),
});

error_type!(SchedulerError, AwsProtocol::RestJson, {
    AccessDenied => ("AccessDeniedException", 403),
    ResourceNotFound => ("ResourceNotFoundException", 404),
    Conflict => ("ConflictException", 409),
    Validation => ("ValidationException", 400),
    ServiceQuotaExceeded => ("ServiceQuotaExceededException", 402),
    Throttling => ("ThrottlingException", 429),
    Internal => ("InternalServerException", 500),
});

error_type!(PipesError, AwsProtocol::RestJson, {
    AccessDenied => ("AccessDeniedException", 403),
    NotFound => ("NotFoundException", 404),
    Conflict => ("ConflictException", 409),
    Validation => ("ValidationException", 400),
    ServiceQuotaExceeded => ("ServiceQuotaExceededException", 402),
    Throttling => ("ThrottlingException", 429),
    Internal => ("InternalException", 500),
});
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_and_rest_errors_use_distinct_protocol_shapes() {
        let events = EventsError::InvalidEventPattern("bad".into()).into_response("r");
        assert_eq!(events.status(), 400);
        assert_eq!(
            events.headers()["content-type"],
            "application/x-amz-json-1.1"
        );
        let scheduler = SchedulerError::Conflict("exists".into()).into_response("r");
        assert_eq!(scheduler.status(), 409);
        assert_eq!(scheduler.headers()["content-type"], "application/json");
        assert_eq!(scheduler.headers()["x-amzn-errortype"], "ConflictException");
        let pipes = PipesError::NotFound("gone".into()).into_response("r");
        assert_eq!(pipes.status(), 404);
        assert_eq!(pipes.headers()["x-amzn-errortype"], "NotFoundException");
    }
}
