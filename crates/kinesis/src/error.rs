//! Typed service failures and protocol mapping. Internal causes never become client messages.
use locallycloud_core::error_mapping::AwsError;
#[derive(Debug)]
pub(crate) enum KinesisError {
    Serialization(String),
    Validation(String),
    UnknownOperation,
    ResourceInUse(String),
    ResourceNotFound(String),
    InvalidArgument(String),
    ExpiredIterator(String),
    ExpiredNextToken,
    LimitExceeded(String),
    Capacity(String),
    Persistence,
    Worker,
    Internal,
}

impl From<KinesisError> for AwsError {
    fn from(error: KinesisError) -> Self {
        let (code, message, status) = match error {
            KinesisError::Serialization(message) => ("SerializationException", message, 400),
            KinesisError::Validation(message) => ("ValidationException", message, 400),
            KinesisError::UnknownOperation => (
                "UnknownOperationException",
                "The requested Kinesis operation is not supported".into(),
                400,
            ),
            KinesisError::ResourceInUse(message) => ("ResourceInUseException", message, 400),
            KinesisError::ResourceNotFound(message) => ("ResourceNotFoundException", message, 400),
            KinesisError::InvalidArgument(message) => ("InvalidArgumentException", message, 400),
            KinesisError::ExpiredIterator(message) => ("ExpiredIteratorException", message, 400),
            KinesisError::LimitExceeded(message) => ("LimitExceededException", message, 400),
            KinesisError::ExpiredNextToken => (
                "ExpiredNextTokenException",
                "The pagination token has expired".into(),
                400,
            ),
            KinesisError::Capacity(message) => {
                ("ProvisionedThroughputExceededException", message, 400)
            }
            KinesisError::Persistence | KinesisError::Worker | KinesisError::Internal => (
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
        "ListStreams",
        "DescribeStreamSummary",
        "DescribeLimits",
        "IncreaseStreamRetentionPeriod",
        "DecreaseStreamRetentionPeriod",
        "ListTagsForStream",
        "AddTagsToStream",
        "RemoveTagsFromStream",
        "ListTagsForResource",
        "TagResource",
        "UntagResource",
        "CreateStream",
        "DescribeStream",
        "ListShards",
        "PutRecords",
        "PutRecord",
        "GetShardIterator",
        "GetRecords",
        "DeleteStream",
    ];
    OPERATIONS.iter().copied().find(|name| *name == value)
}
