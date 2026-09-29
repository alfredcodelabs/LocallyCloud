mod error;
mod model;
mod protocol;
mod service;
mod store;

use std::sync::Arc;

use localcloud_core::handler::NativeHandler;
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

use crate::service::SsmHandler;

/// Register the partial Parameter Store milestone as a concrete native JSON 1.1 handler.
pub fn register(registry: &Arc<ServiceRegistry>) {
    let handler: Arc<dyn NativeHandler> = Arc::new(SsmHandler::new(Arc::downgrade(registry)));
    registry.register_native(
        ServiceName::new("ssm"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(protocol::TARGET_PREFIX)),
        handler,
    );
}

/// Register Parameter Store with durable shared control-plane state.
pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    state: Arc<localcloud_state::StateDb>,
) -> Result<(), String> {
    let handler: Arc<dyn NativeHandler> = Arc::new(
        SsmHandler::with_state(Arc::downgrade(registry), state)
            .map_err(|_| "SSM state initialization failed".to_owned())?,
    );
    registry.register_native(
        ServiceName::new("ssm"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(protocol::TARGET_PREFIX)),
        handler,
    );
    Ok(())
}
