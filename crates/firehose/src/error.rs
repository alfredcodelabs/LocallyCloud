//! Typed service failures and protocol mapping. Internal causes never become client messages.
use locallycloud_core::error_mapping::AwsError;
#[derive(Debug)]
pub(crate) enum FirehoseError {
    Serialization(String),
    InvalidArgument(String),
    UnknownOperation,
    ResourceInUse(String),
    ResourceNotFound(String),
    AccessDenied,
    DeliveryRoleDenied,
    ServiceUnavailable(String),
    Persistence,
    Worker,
    Internal,
}

impl From<FirehoseError> for AwsError {
    fn from(error: FirehoseError) -> Self {
        let (code, message, status) = match error {
            FirehoseError::Serialization(message) => ("SerializationException", message, 400),
            FirehoseError::InvalidArgument(message) => ("InvalidArgumentException", message, 400),
            FirehoseError::UnknownOperation => (
                "UnknownOperationException",
                "The requested Firehose operation is not supported by this milestone".into(),
                400,
            ),
            FirehoseError::ResourceInUse(message) => ("ResourceInUseException", message, 400),
            FirehoseError::ResourceNotFound(message) => ("ResourceNotFoundException", message, 400),
            FirehoseError::AccessDenied => ("AccessDeniedException", "Access denied".into(), 403),
            FirehoseError::DeliveryRoleDenied => (
                "ServiceUnavailableException",
                "Firehose role authorization is denied".into(),
                500,
            ),
            FirehoseError::ServiceUnavailable(message) => {
                ("ServiceUnavailableException", message, 500)
            }
            FirehoseError::Persistence | FirehoseError::Worker | FirehoseError::Internal => (
                "InternalFailureException",
                "The request could not be completed".into(),
                500,
            ),
        };
        AwsError::new(code, message, status)
    }
}

/// Return only an implemented, static operation name; never log arbitrary request headers.
pub(crate) fn operation_name(value: &str) -> Option<&'static str> {
    const OPERATIONS: &[&str] = &[
        "CreateDeliveryStream",
        "ListDeliveryStreams",
        "DescribeDeliveryStream",
        "PutRecord",
        "PutRecordBatch",
        "DeleteDeliveryStream",
        "LocallyCloudRetryDeliveryStream",
    ];
    OPERATIONS.iter().copied().find(|name| *name == value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unavailable_matches_documented_firehose_status() {
        let error = AwsError::from(FirehoseError::ServiceUnavailable(
            "Service unavailable".into(),
        ));
        assert_eq!(error.code, "ServiceUnavailableException");
        assert_eq!(error.http_status, 500);
        assert_eq!(operation_name("PutRecord"), Some("PutRecord"));
        assert_eq!(operation_name("private-request-canary"), None);
    }
}
