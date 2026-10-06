//! Native Cognito User Pools subset. Identity Pools are intentionally not registered.

mod crypto;
mod mailbox;
pub use mailbox::ConfirmationMailbox;
mod service;

use std::sync::Arc;

use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

pub use service::CognitoHandler;

const TARGET_PREFIX: &str = "AWSCognitoIdentityProviderService";

#[derive(Debug, Clone, Copy)]
enum CognitoError {
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
    fn into_aws(self) -> AwsError {
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

/// Register only `cognito-idp` as Native; `cognito-identity` remains untouched.
pub fn register(registry: &Arc<ServiceRegistry>) -> Arc<CognitoHandler> {
    let handler = Arc::new(CognitoHandler::with_registry(Arc::downgrade(registry)));
    registry.register_native(
        ServiceName::new("cognito-idp"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        handler.clone(),
    );
    handler
}

/// Configure opt-in local delivery; invalid directory settings fail startup.
pub fn register_with_mailbox(
    registry: &Arc<ServiceRegistry>,
) -> Result<Arc<CognitoHandler>, String> {
    let mailbox = std::env::var_os("LOCALLYCLOUD_COGNITO_MAILBOX_DIR")
        .map(|path| ConfirmationMailbox::new(path.into()).map(Arc::new))
        .transpose()?;
    let handler = Arc::new(CognitoHandler::with_registry_and_mailbox(
        Arc::downgrade(registry),
        mailbox,
    ));
    registry.register_native(
        ServiceName::new("cognito-idp"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        handler.clone(),
    );
    Ok(handler)
}
