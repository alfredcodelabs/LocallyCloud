//! Native Cognito User Pools subset. Identity Pools are intentionally not registered.

mod crypto;
mod service;

use std::sync::Arc;

use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

pub use service::CognitoHandler;

const TARGET_PREFIX: &str = "AWSCognitoIdentityProviderService";

#[derive(Debug, Clone, Copy)]
enum CognitoError {
    InvalidParameter,
    ResourceNotFound,
    UserNotFound,
    UsernameExists,
    InvalidPassword,
    NotAuthorized,
    Unsupported,
    UnknownOperation,
    Internal,
}

impl CognitoError {
    fn into_aws(self) -> AwsError {
        let (code, message, status) = match self {
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
    let handler = Arc::new(CognitoHandler::new());
    registry.register_native(
        ServiceName::new("cognito-idp"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        handler.clone(),
    );
    handler
}
