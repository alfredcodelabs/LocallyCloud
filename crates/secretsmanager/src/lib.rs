mod error;
mod model;
mod protocol;
mod service;
mod store;

use std::sync::Arc;

use locallycloud_core::handler::NativeHandler;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

use crate::service::SecretsManagerHandler;

/// Register the native Secrets Manager lifecycle and customer-Lambda rotation handler.
pub fn register(registry: &Arc<ServiceRegistry>) {
    let handler: Arc<dyn NativeHandler> =
        Arc::new(SecretsManagerHandler::new(Arc::downgrade(registry)));
    registry.register_native(
        ServiceName::new("secretsmanager"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(protocol::TARGET_PREFIX)),
        handler,
    );
}

/// Register Secrets Manager with durable state shared by small control-plane services.
pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    state: Arc<locallycloud_state::StateDb>,
) -> Result<(), String> {
    let handler: Arc<dyn NativeHandler> = Arc::new(
        SecretsManagerHandler::with_state(Arc::downgrade(registry), state)
            .map_err(|error| format!("Secrets Manager state: {error:?}"))?,
    );
    registry.register_native(
        ServiceName::new("secretsmanager"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(protocol::TARGET_PREFIX)),
        handler,
    );
    Ok(())
}
