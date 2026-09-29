mod service;

use std::sync::Arc;

use localcloud_core::handler::NativeHandler;
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use localcloud_state::StateDb;

use crate::service::KinesisHandler;

const TARGET_PREFIX: &str = "Kinesis_20131202";

/// Register the narrow native one-shard Kinesis milestone.
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
) -> Result<(), localcloud_state::StateError> {
    let handler: Arc<dyn NativeHandler> = Arc::new(KinesisHandler::with_state(state)?);
    registry.register_native(
        ServiceName::new("kinesis"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        handler,
    );
    Ok(())
}
