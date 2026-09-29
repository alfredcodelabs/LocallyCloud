use localcloud_core::error_mapping::AwsError;

#[derive(Debug, Clone, Copy)]
pub(crate) enum KmsError {
    Serialization,
    Validation,
    InvalidAliasName,
    LimitExceeded,
    AlreadyExists,
    NotFound,
    InvalidState,
    InvalidCiphertext,
    AccessDenied,
    Unsupported,
    Internal,
}

impl KmsError {
    pub(crate) fn into_aws(self) -> AwsError {
        let (code, message, status) = match self {
            Self::Serialization => (
                "SerializationException",
                "The request could not be deserialized",
                400,
            ),
            Self::Validation => (
                "ValidationException",
                "The request contains invalid parameters",
                400,
            ),
            Self::InvalidAliasName => (
                "InvalidAliasNameException",
                "The alias name is invalid",
                400,
            ),
            Self::LimitExceeded => (
                "LimitExceededException",
                "The alias name exceeds the maximum length",
                400,
            ),
            Self::AlreadyExists => (
                "AlreadyExistsException",
                "The requested alias already exists",
                400,
            ),
            Self::NotFound => ("NotFoundException", "The requested key was not found", 400),
            Self::InvalidState => (
                "KMSInvalidStateException",
                "The key is not in a valid state for this operation",
                400,
            ),
            Self::InvalidCiphertext => (
                "InvalidCiphertextException",
                "The ciphertext or encryption context is invalid",
                400,
            ),
            Self::AccessDenied => (
                "AccessDeniedException",
                "The caller is not authorized to use this key",
                400,
            ),
            Self::Unsupported => (
                "UnsupportedOperationException",
                "This KMS operation or parameter is not supported by this milestone",
                400,
            ),
            Self::Internal => (
                "KMSInternalException",
                "The request could not be completed",
                500,
            ),
        };
        AwsError::new(code, message, status)
    }
}

pub(crate) fn unknown_operation() -> AwsError {
    AwsError::new(
        "UnknownOperationException",
        "The requested KMS operation is not supported",
        400,
    )
}
