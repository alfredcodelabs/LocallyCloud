//! SQS error model rendered as the AWS JSON 1.0 `__type` shape.
//!
//! Each variant renders as `{"__type":"com.amazonaws.sqs#<Code>","message":...}` with the
//! AWS-faithful HTTP status via the Core error mapper.

use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::registry::AwsProtocol;

const TYPE_PREFIX: &str = "com.amazonaws.sqs#";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SqsError {
    #[error("SQS state storage is unavailable")]
    StorageUnavailable,
    #[error("The specified queue does not exist.")]
    QueueDoesNotExist,
    #[error("A queue with this name already exists with different attributes.")]
    QueueNameExists,
    #[error("You must wait 60 seconds after deleting a queue before you can create another with the same name.")]
    QueueDeletedRecently,
    #[error("{0}")]
    ResourceNotFound(String),
    #[error("{0}")]
    InvalidParameterValue(String),
    #[error("{0}")]
    MissingParameter(String),
    #[error("{0}")]
    InvalidAttributeName(String),
    #[error("{0}")]
    InvalidAttributeValue(String),
    #[error("The input receipt handle is invalid.")]
    ReceiptHandleIsInvalid,
    #[error("The message referred to is not in flight.")]
    MessageNotInflight,
    #[error("The message contains characters outside the allowed set.")]
    InvalidMessageContents,
    #[error("{0}")]
    InvalidBatchEntryId(String),
    #[error("Maximum number of entries per request is 10.")]
    TooManyEntriesInBatchRequest,
    #[error("The batch request doesn't contain any entries.")]
    EmptyBatchRequest,
    #[error("Two or more batch entries in the request have the same Id.")]
    BatchEntryIdsNotDistinct,
    #[error("The length of all the messages put together is more than the limit.")]
    BatchRequestTooLong,
    #[error("Indicates that the message referred to by the receipt handle has expired.")]
    PurgeQueueInProgress,
    #[error("{0}")]
    UnsupportedOperation(String),
    #[error("{0}")]
    OverLimit(String),
    #[error("Access to the specified resource is denied.")]
    AccessDenied,
    #[error("The caller does not have the required AWS KMS access for this queue.")]
    KmsAccessDenied,
}

impl SqsError {
    pub fn code(&self) -> &'static str {
        match self {
            SqsError::StorageUnavailable => "InternalError",
            SqsError::QueueDoesNotExist => "QueueDoesNotExist",
            SqsError::QueueNameExists => "QueueNameExists",
            SqsError::QueueDeletedRecently => "QueueDeletedRecently",
            SqsError::ResourceNotFound(_) => "ResourceNotFoundException",
            SqsError::InvalidParameterValue(_) => "InvalidParameterValue",
            SqsError::MissingParameter(_) => "MissingParameter",
            SqsError::InvalidAttributeName(_) => "InvalidAttributeName",
            SqsError::InvalidAttributeValue(_) => "InvalidAttributeValue",
            SqsError::ReceiptHandleIsInvalid => "ReceiptHandleIsInvalid",
            SqsError::MessageNotInflight => "MessageNotInflight",
            SqsError::InvalidMessageContents => "InvalidMessageContents",
            SqsError::InvalidBatchEntryId(_) => "InvalidBatchEntryId",
            SqsError::TooManyEntriesInBatchRequest => "TooManyEntriesInBatchRequest",
            SqsError::EmptyBatchRequest => "EmptyBatchRequest",
            SqsError::BatchEntryIdsNotDistinct => "BatchEntryIdsNotDistinct",
            SqsError::BatchRequestTooLong => "BatchRequestTooLong",
            SqsError::PurgeQueueInProgress => "PurgeQueueInProgress",
            SqsError::UnsupportedOperation(_) => "UnsupportedOperation",
            SqsError::OverLimit(_) => "OverLimit",
            SqsError::AccessDenied => "AccessDenied",
            SqsError::KmsAccessDenied => "KMS.AccessDeniedException",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            SqsError::StorageUnavailable => 500,
            SqsError::QueueDoesNotExist => 400,
            SqsError::OverLimit(_) | SqsError::AccessDenied => 403,
            _ => 400,
        }
    }

    /// The legacy AWS Query error code, surfaced via the `x-amzn-query-error` response
    /// header to `awsQueryCompatible` SDK clients (Terraform, AWS SDK v2 in query mode).
    /// SDK v2 maps not-found/conflict control flow off this code, not the JSON `__type`.
    pub fn query_code(&self) -> &'static str {
        match self {
            SqsError::StorageUnavailable => "InternalError",
            SqsError::QueueDoesNotExist => "AWS.SimpleQueueService.NonExistentQueue",
            SqsError::QueueNameExists => "QueueAlreadyExists",
            SqsError::QueueDeletedRecently => "AWS.SimpleQueueService.QueueDeletedRecently",
            SqsError::PurgeQueueInProgress => "AWS.SimpleQueueService.PurgeQueueInProgress",
            SqsError::ResourceNotFound(_) => "ResourceNotFoundException",
            SqsError::MessageNotInflight => "AWS.SimpleQueueService.MessageNotInflight",
            SqsError::TooManyEntriesInBatchRequest => {
                "AWS.SimpleQueueService.TooManyEntriesInBatchRequest"
            }
            SqsError::EmptyBatchRequest => "AWS.SimpleQueueService.EmptyBatchRequest",
            SqsError::BatchEntryIdsNotDistinct => "AWS.SimpleQueueService.BatchEntryIdsNotDistinct",
            SqsError::BatchRequestTooLong => "AWS.SimpleQueueService.BatchRequestTooLong",
            SqsError::InvalidBatchEntryId(_) => "AWS.SimpleQueueService.InvalidBatchEntryId",
            SqsError::UnsupportedOperation(_) => "AWS.SimpleQueueService.UnsupportedOperation",
            SqsError::InvalidParameterValue(_) => "InvalidParameterValue",
            SqsError::MissingParameter(_) => "MissingParameter",
            SqsError::InvalidAttributeName(_) => "InvalidAttributeName",
            SqsError::InvalidAttributeValue(_) => "InvalidAttributeValue",
            SqsError::ReceiptHandleIsInvalid => "ReceiptHandleIsInvalid",
            SqsError::InvalidMessageContents => "InvalidMessageContents",
            SqsError::OverLimit(_) => "OverLimit",
            SqsError::AccessDenied => "AccessDenied",
            SqsError::KmsAccessDenied => "KMS.AccessDeniedException",
        }
    }

    /// `SenderFault` is true for all client errors (the SQS catalog here is client-fault).
    pub fn render_json(&self, request_id: &str) -> locallycloud_core::error_mapping::RenderedError {
        let mut rendered = AwsError::new(
            format!("{TYPE_PREFIX}{}", self.code()),
            self.to_string(),
            self.http_status(),
        )
        .with_request_id(request_id.to_string())
        .render(AwsProtocol::Json10);
        rendered
            .headers
            .push(("x-amzn-errortype", format!("{TYPE_PREFIX}{}", self.code())));
        rendered
    }

    /// The legacy Query/XML error shape, using the AWS Query error code (e.g.
    /// `AWS.SimpleQueueService.NonExistentQueue`) in `<Code>`.
    pub fn render_query(
        &self,
        request_id: &str,
    ) -> locallycloud_core::error_mapping::RenderedError {
        AwsError::new(self.query_code(), self.to_string(), self.http_status())
            .with_request_id(request_id.to_string())
            .render(AwsProtocol::Query)
    }

    /// Render the error in `protocol` (JSON `__type` shape or Query `<ErrorResponse>` XML).
    pub fn render(
        &self,
        request_id: &str,
        protocol: AwsProtocol,
    ) -> locallycloud_core::error_mapping::RenderedError {
        match protocol {
            AwsProtocol::Query | AwsProtocol::RestXml => self.render_query(request_id),
            _ => self.render_json(request_id),
        }
    }

    pub fn into_response(self, request_id: &str) -> axum::response::Response {
        self.render_json(request_id).into_response()
    }

    /// Build the Axum error response in the request's protocol.
    pub fn into_protocol_response(
        self,
        request_id: &str,
        protocol: AwsProtocol,
    ) -> axum::response::Response {
        self.render(request_id, protocol).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_json_type_with_namespace() {
        let r = SqsError::QueueDoesNotExist.render_json("rid");
        assert!(r.body.contains("com.amazonaws.sqs#QueueDoesNotExist"));
        assert!(r.headers.iter().any(|(name, value)| {
            *name == "x-amzn-errortype" && value == "com.amazonaws.sqs#QueueDoesNotExist"
        }));
        assert_eq!(r.status, 400);
    }

    #[test]
    fn over_limit_is_403() {
        assert_eq!(SqsError::OverLimit("x".into()).http_status(), 403);
    }

    #[test]
    fn renders_query_xml_with_legacy_code() {
        let r = SqsError::QueueDoesNotExist.render_query("rid");
        assert_eq!(r.content_type, "application/xml");
        assert_eq!(r.status, 400);
        assert!(r
            .body
            .contains("<Code>AWS.SimpleQueueService.NonExistentQueue</Code>"));
        assert!(r.body.contains("<Type>Sender</Type>"));
        assert!(r.body.contains("<RequestId>rid</RequestId>"));
    }
}
