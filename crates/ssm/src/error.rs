use locallycloud_core::error_mapping::AwsError;

#[derive(Debug)]
pub(crate) enum SsmError {
    Serialization,
    Validation,
    UnknownOperation,
    UnsupportedParameterType,
    ParameterAlreadyExists,
    ParameterNotFound,
    InvalidKeyId,
    InvalidResourceType,
    InvalidResourceId,
    InvalidNextToken,
    InvalidFilterKey,
    InvalidFilterOption,
    InvalidFilterValue,
    Internal,
}

impl From<SsmError> for AwsError {
    fn from(error: SsmError) -> Self {
        let (code, message, status) = match error {
            SsmError::InvalidNextToken => {
                ("InvalidNextToken", "The specified token is invalid", 400)
            }
            SsmError::InvalidFilterKey => (
                "InvalidFilterKey",
                "The specified filter key is unsupported",
                400,
            ),
            SsmError::InvalidFilterOption => (
                "InvalidFilterOption",
                "The specified filter option is invalid",
                400,
            ),
            SsmError::InvalidFilterValue => (
                "InvalidFilterValue",
                "The specified filter value is invalid",
                400,
            ),
            SsmError::Serialization => (
                "SerializationException",
                "The request could not be deserialized",
                400,
            ),
            SsmError::Validation => (
                "ValidationException",
                "The request contains invalid parameters",
                400,
            ),
            SsmError::UnknownOperation => (
                "UnknownOperationException",
                "The requested SSM operation is not supported by this milestone",
                400,
            ),
            SsmError::UnsupportedParameterType => (
                "UnsupportedParameterType",
                "Only Standard String and SecureString parameters are supported by this milestone",
                400,
            ),
            SsmError::ParameterAlreadyExists => (
                "ParameterAlreadyExists",
                "The parameter already exists and overwrite was not enabled",
                400,
            ),
            SsmError::InvalidKeyId => {
                ("InvalidKeyId", "The KMS key is invalid or unavailable", 400)
            }
            SsmError::ParameterNotFound => (
                "ParameterNotFound",
                "The requested parameter was not found",
                400,
            ),
            SsmError::InvalidResourceType => (
                "InvalidResourceType",
                "The resource type must be Parameter",
                400,
            ),
            SsmError::InvalidResourceId => (
                "InvalidResourceId",
                "The requested parameter resource was not found",
                400,
            ),
            SsmError::Internal => (
                "InternalServerError",
                "The request could not be completed",
                500,
            ),
        };
        AwsError::new(code, message, status)
    }
}
