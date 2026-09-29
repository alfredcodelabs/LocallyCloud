use localcloud_core::error_mapping::AwsError;

#[derive(Debug)]
pub(crate) enum AnalyticsError {
    InvalidInput,
    AlreadyExists,
    EntityNotFound,
    ConcurrentModification,
    AccessDenied,
    UnknownOperation,
    Internal,
}

impl From<AnalyticsError> for AwsError {
    fn from(error: AnalyticsError) -> Self {
        let (code, message, status) = match error {
            AnalyticsError::InvalidInput => (
                "InvalidInputException",
                "The request contains invalid input",
                400,
            ),
            AnalyticsError::AlreadyExists => (
                "AlreadyExistsException",
                "The requested catalog resource already exists",
                400,
            ),
            AnalyticsError::EntityNotFound => (
                "EntityNotFoundException",
                "The requested catalog resource was not found",
                400,
            ),
            AnalyticsError::ConcurrentModification => (
                "ConcurrentModificationException",
                "The table was modified concurrently",
                400,
            ),
            AnalyticsError::AccessDenied => (
                "AccessDeniedException",
                "User is not authorized to perform this action",
                400,
            ),
            AnalyticsError::UnknownOperation => (
                "UnknownOperationException",
                "The requested Glue operation is unknown",
                400,
            ),
            AnalyticsError::Internal => (
                "InternalServiceException",
                "Glue could not complete the request",
                500,
            ),
        };
        AwsError::new(code, message, status)
    }
}
