//! Cognito User Pools exception contracts, separate from startup and token responses.
use locallycloud_core::error_mapping::AwsError;
#[derive(Debug, Clone, Copy)]
pub(crate) enum CognitoError {
    InvalidParameter,
    CodeMismatch,
    ExpiredCode,
    CodeDeliveryFailure,
    TooManyFailedAttempts,
    ResourceNotFound,
    UserNotFound,
    UsernameExists,
    InvalidPassword,
    NotAuthorized,
    UserNotConfirmed,
    AccessDenied,
    Unsupported,
    UnknownOperation,
    Internal,
}

impl CognitoError {
    pub(crate) fn into_aws(self) -> AwsError {
        let (code, message, status) = match self {
            Self::CodeMismatch => ("CodeMismatchException", "Invalid verification code", 400),
            Self::ExpiredCode => ("ExpiredCodeException", "Verification code has expired", 400),
            Self::CodeDeliveryFailure => (
                "CodeDeliveryFailureException",
                "Verification code delivery failed",
                400,
            ),
            Self::TooManyFailedAttempts => (
                "TooManyFailedAttemptsException",
                "Too many failed verification attempts",
                400,
            ),
            Self::AccessDenied => (
                "AccessDeniedException",
                "Caller is not authorized for this Cognito operation",
                403,
            ),
            Self::UserNotConfirmed => ("UserNotConfirmedException", "User is not confirmed", 400),
            Self::InvalidParameter => (
                "InvalidParameterException",
                "Invalid request parameter",
                400,
            ),
            Self::ResourceNotFound => (
                "ResourceNotFoundException",
                "User pool or client not found",
                400,
            ),
            Self::UserNotFound => ("UserNotFoundException", "User does not exist", 400),
            Self::UsernameExists => ("UsernameExistsException", "User already exists", 400),
            Self::InvalidPassword => (
                "InvalidPasswordException",
                "Password does not meet policy",
                400,
            ),
            Self::NotAuthorized => (
                "NotAuthorizedException",
                "Incorrect username or password",
                400,
            ),
            Self::Unsupported => (
                "UnsupportedOperationException",
                "Cognito operation or property is not supported",
                400,
            ),
            Self::UnknownOperation => (
                "UnknownOperationException",
                "Unknown Cognito operation",
                400,
            ),
            Self::Internal => ("InternalErrorException", "Cognito request failed", 500),
        };
        AwsError::new(code, message, status)
    }
}

/// Return only an implemented, static operation name; never log arbitrary request headers.
pub(crate) fn operation_name(value: &str) -> Option<&'static str> {
    const OPERATIONS: &[&str] = &[
        "CreateUserPool",
        "DescribeUserPool",
        "ListUserPools",
        "DeleteUserPool",
        "CreateUserPoolClient",
        "DescribeUserPoolClient",
        "ListUserPoolClients",
        "DeleteUserPoolClient",
        "AdminCreateUser",
        "AdminSetUserPassword",
        "AdminGetUser",
        "GetUser",
        "ListUsers",
        "AdminDeleteUser",
        "AdminInitiateAuth",
        "SignUp",
        "ConfirmSignUp",
        "AdminConfirmSignUp",
        "InitiateAuth",
        "RespondToAuthChallenge",
        "AdminRespondToAuthChallenge",
    ];
    OPERATIONS.iter().copied().find(|name| *name == value)
}
