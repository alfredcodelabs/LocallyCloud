//! SNS error model rendered in the request's protocol (XML for Query, JSON for JSON).

use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::registry::AwsProtocol;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnsError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    InvalidParameter(String),
    #[error("{0}")]
    AuthorizationError(String),
    #[error("Empty batch request.")]
    EmptyBatchRequest,
    #[error("The batch request contains more entries than permissible (more than 10).")]
    TooManyEntriesInBatchRequest,
    #[error("Two or more batch entries in the request have the same Id.")]
    BatchEntryIdsNotDistinct,
    #[error("The length of all the batch messages put together is more than the limit.")]
    BatchRequestTooLong,
    #[error("{0}")]
    UnsupportedOperation(String),
    #[error("Internal error.")]
    InternalError,
}

impl SnsError {
    pub fn code(&self) -> &'static str {
        match self {
            SnsError::NotFound(_) => "NotFound",
            SnsError::InvalidParameter(_) => "InvalidParameter",
            SnsError::AuthorizationError(_) => "AuthorizationError",
            SnsError::EmptyBatchRequest => "EmptyBatchRequest",
            SnsError::TooManyEntriesInBatchRequest => "TooManyEntriesInBatchRequest",
            SnsError::BatchEntryIdsNotDistinct => "BatchEntryIdsNotDistinct",
            SnsError::BatchRequestTooLong => "BatchRequestTooLong",
            SnsError::UnsupportedOperation(_) => "UnsupportedOperation",
            SnsError::InternalError => "InternalError",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            SnsError::NotFound(_) => 404,
            SnsError::AuthorizationError(_) => 403,
            SnsError::InternalError => 500,
            _ => 400,
        }
    }

    pub(crate) fn sender_fault(&self) -> bool {
        !matches!(self, SnsError::InternalError)
    }

    /// Render to a response in the given wire protocol (`Query` → XML, `Json10` → JSON).
    pub fn into_response(
        self,
        protocol: AwsProtocol,
        request_id: &str,
    ) -> axum::response::Response {
        self.into_response_for_operation(protocol, request_id, None)
    }

    pub(crate) fn into_response_for_operation(
        self,
        protocol: AwsProtocol,
        request_id: &str,
        operation: Option<&'static str>,
    ) -> axum::response::Response {
        locallycloud_core::observability::log_service_error(
            "sns",
            operation,
            request_id,
            self.code(),
            self.http_status(),
        );
        let mut err = AwsError::new(self.code(), self.to_string(), self.http_status())
            .with_request_id(request_id.to_string())
            .with_xml_namespace("http://sns.amazonaws.com/doc/2010-03-31/");
        err.sender_fault = self.sender_fault();
        err.render(protocol).into_response()
    }
}

/// Return only an implemented, static operation name; never log arbitrary request headers.
pub(crate) fn operation_name(value: &str) -> Option<&'static str> {
    const OPERATIONS: &[&str] = &[
        "CreateTopic",
        "DeleteTopic",
        "ListTopics",
        "GetTopicAttributes",
        "SetTopicAttributes",
        "Subscribe",
        "ConfirmSubscription",
        "Unsubscribe",
        "ListSubscriptions",
        "ListSubscriptionsByTopic",
        "GetSubscriptionAttributes",
        "SetSubscriptionAttributes",
        "TagResource",
        "UntagResource",
        "ListTagsForResource",
        "Publish",
        "PublishBatch",
    ];
    OPERATIONS.iter().copied().find(|name| *name == value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses() {
        assert_eq!(SnsError::NotFound("x".into()).http_status(), 404);
        assert_eq!(SnsError::AuthorizationError("x".into()).http_status(), 403);
        assert_eq!(SnsError::InvalidParameter("x".into()).http_status(), 400);
    }

    #[test]
    fn renders_in_both_protocols() {
        let xml = SnsError::NotFound("topic".into()).into_response(AwsProtocol::Query, "rid");
        assert_eq!(xml.status(), 404);
        assert_eq!(
            xml.headers().get("content-type").unwrap(),
            "application/xml"
        );

        let js = SnsError::NotFound("topic".into()).into_response(AwsProtocol::Json10, "rid");
        assert_eq!(js.status(), 404);
    }
}
