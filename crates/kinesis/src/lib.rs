mod config;
pub use config::KinesisConfig;

mod error;
mod service;

use std::sync::Arc;

use locallycloud_core::handler::NativeHandler;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_state::StateDb;

use crate::service::KinesisHandler;

const TARGET_PREFIX: &str = "Kinesis_20131202";

/// Register the native static multishard Kinesis backend.
pub fn register(registry: &Arc<ServiceRegistry>) {
    register_handler(registry, KinesisHandler::new());
}

pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    state: Arc<StateDb>,
) -> Result<(), locallycloud_state::StateError> {
    register_handler(registry, KinesisHandler::with_state(state)?);
    Ok(())
}

pub fn register_with_state_and_config(
    registry: &Arc<ServiceRegistry>,
    state: Arc<StateDb>,
    config: KinesisConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    config.validate()?;
    register_handler(
        registry,
        KinesisHandler::with_state_and_config(state, config)?,
    );
    Ok(())
}

fn register_handler(registry: &Arc<ServiceRegistry>, mut handler: KinesisHandler) {
    handler.registry = Arc::downgrade(registry);
    let handler: Arc<dyn NativeHandler> = Arc::new(handler);
    registry.register_native(
        ServiceName::new("kinesis"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        handler,
    );
}
