use locallycloud_core::error_mapping::AwsError;

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("service registry is unavailable while constructing CloudWatch Logs")]
    RegistryUnavailable,
    #[error(
        "CloudWatch Logs state could not be loaded; check the database and external master key"
    )]
    StateUnavailable,
}

#[derive(Debug, thiserror::Error)]
pub enum LogsError {
    #[error("{0}")]
    InvalidParameter(String),
    #[error("{0}")]
    Serialization(String),
    #[error("{0}")]
    MalformedQuery(String),
    #[error("{0}")]
    UnknownOperation(String),
    #[error("{0}")]
    OperationUnavailable(String),
    #[error("{0}")]
    ResourceAlreadyExists(String),
    #[error("{0}")]
    ResourceNotFound(String),
    #[error("{0}")]
    LimitExceeded(String),
    #[error("{0}")]
    ServiceUnavailable(String),
}

impl From<LogsError> for AwsError {
    fn from(error: LogsError) -> Self {
        match error {
            LogsError::InvalidParameter(message) => {
                AwsError::new("InvalidParameterException", message, 400)
            }
            LogsError::Serialization(message) => {
                AwsError::new("SerializationException", message, 400)
            }
            LogsError::MalformedQuery(message) => {
                AwsError::new("MalformedQueryException", message, 400)
            }
            LogsError::UnknownOperation(message) => {
                AwsError::new("UnknownOperationException", message, 400)
            }
            LogsError::OperationUnavailable(message) => {
                AwsError::new("InvalidOperationException", message, 400)
            }
            LogsError::ResourceAlreadyExists(message) => {
                AwsError::new("ResourceAlreadyExistsException", message, 400)
            }
            LogsError::ResourceNotFound(message) => {
                AwsError::new("ResourceNotFoundException", message, 400)
            }
            LogsError::LimitExceeded(message) => {
                AwsError::new("LimitExceededException", message, 400)
            }
            LogsError::ServiceUnavailable(message) => {
                AwsError::new("ServiceUnavailableException", message, 500)
            }
        }
    }
}
