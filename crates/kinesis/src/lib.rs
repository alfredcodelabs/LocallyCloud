mod service;

use std::sync::Arc;

use locallycloud_core::handler::NativeHandler;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_state::StateDb;

use crate::service::KinesisHandler;

const TARGET_PREFIX: &str = "Kinesis_20131202";

/// Register the native static multishard Kinesis backend.
pub fn register(registry: &Arc<ServiceRegistry>) {
    let handler: Arc<dyn NativeHandler> = Arc::new(KinesisHandler::new());
    registry.register_native(
        ServiceName::new("kinesis"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        handler,
    );
}

pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    state: Arc<StateDb>,
) -> Result<(), locallycloud_state::StateError> {
    let handler: Arc<dyn NativeHandler> = Arc::new(KinesisHandler::with_state(state)?);
    registry.register_native(
        ServiceName::new("kinesis"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        handler,
    );
    Ok(())
}
