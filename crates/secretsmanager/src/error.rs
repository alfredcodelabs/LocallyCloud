use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::integration::authorization::AuthorizationError;
use locallycloud_core::integration::kms::KmsInternalError;

#[derive(Debug)]
pub(crate) enum SecretsError {
    InvalidParameter,
    InvalidRequest,
    InvalidNextToken,
    ResourceExists,
    ResourceNotFound,
    EncryptionFailure,
    DecryptionFailure,
    AccessDenied,
    UnsupportedOperation,
    UnknownOperation,
    Internal,
}

impl SecretsError {
    pub(crate) fn from_authorization(error: AuthorizationError) -> Self {
        match error {
            AuthorizationError::Denied => Self::AccessDenied,
            AuthorizationError::Unavailable
            | AuthorizationError::InvalidRequest
            | AuthorizationError::Internal => Self::Internal,
        }
    }

    pub(crate) fn from_encrypt(error: KmsInternalError) -> Self {
        match error {
            KmsInternalError::AccessDenied => Self::AccessDenied,
            KmsInternalError::Unavailable | KmsInternalError::Internal => Self::EncryptionFailure,
            KmsInternalError::InvalidRequest
            | KmsInternalError::NotFound
            | KmsInternalError::InvalidState
            | KmsInternalError::InvalidCiphertext => Self::EncryptionFailure,
        }
    }

    pub(crate) fn from_decrypt(error: KmsInternalError) -> Self {
        match error {
            KmsInternalError::AccessDenied => Self::AccessDenied,
            KmsInternalError::Unavailable | KmsInternalError::Internal => Self::DecryptionFailure,
            KmsInternalError::InvalidRequest
            | KmsInternalError::NotFound
            | KmsInternalError::InvalidState
            | KmsInternalError::InvalidCiphertext => Self::DecryptionFailure,
        }
    }
}

impl From<SecretsError> for AwsError {
    fn from(error: SecretsError) -> Self {
        let (code, message, status) = match error {
            SecretsError::InvalidParameter => (
                "InvalidParameterException",
                "The request contains invalid parameters",
                400,
            ),
            SecretsError::InvalidRequest => (
                "InvalidRequestException",
                "The request is not valid for the current secret state",
                400,
            ),
            SecretsError::InvalidNextToken => (
                "InvalidNextTokenException",
                "The pagination token is invalid for this request",
                400,
            ),
            SecretsError::ResourceExists => (
                "ResourceExistsException",
                "The requested secret or version already exists",
                400,
            ),
            SecretsError::ResourceNotFound => (
                "ResourceNotFoundException",
                "The requested secret or version was not found",
                400,
            ),
            SecretsError::EncryptionFailure => (
                "EncryptionFailure",
                "Secrets Manager could not encrypt the secret value",
                400,
            ),
            SecretsError::DecryptionFailure => (
                "DecryptionFailure",
                "Secrets Manager could not decrypt the secret value",
                400,
            ),
            SecretsError::AccessDenied => (
                "AccessDeniedException",
                "The request is not authorized",
                400,
            ),
            SecretsError::UnsupportedOperation => (
                "UnsupportedOperationException",
                "The requested Secrets Manager operation is not implemented",
                400,
            ),
            SecretsError::UnknownOperation => (
                "UnknownOperationException",
                "The requested Secrets Manager operation is unknown",
                400,
            ),
            SecretsError::Internal => (
                "InternalServiceError",
                "Secrets Manager could not complete the request",
                500,
            ),
        };
        AwsError::new(code, message, status)
    }
}
