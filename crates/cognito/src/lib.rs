//! Native Cognito User Pools subset. Identity Pools are intentionally not registered.

mod config;
pub use config::CognitoConfig;

mod crypto;
mod error;
use error::CognitoError;
mod mailbox;
pub use mailbox::ConfirmationMailbox;
mod service;

use std::sync::Arc;

use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

pub use service::CognitoHandler;

const TARGET_PREFIX: &str = "AWSCognitoIdentityProviderService";

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
    register_with_config(registry, CognitoConfig::default())
}

pub fn register_with_config(
    registry: &Arc<ServiceRegistry>,
    config: CognitoConfig,
) -> Result<Arc<CognitoHandler>, String> {
    config.validate()?;
    let mailbox = config
        .mailbox_dir
        .map(|path| ConfirmationMailbox::new(path).map(Arc::new))
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
