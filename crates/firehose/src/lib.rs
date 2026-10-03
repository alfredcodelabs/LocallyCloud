mod iceberg;
mod service;

use locallycloud_state::StateDb;
use std::sync::Arc;

use locallycloud_core::handler::NativeHandler;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
pub use service::FirehoseHandle;

use crate::service::FirehoseHandler;

const TARGET_PREFIX: &str = "Firehose_20150804";

/// Register the narrow native DirectPut to Extended S3 Firehose milestone.
pub fn register(registry: &Arc<ServiceRegistry>) -> FirehoseHandle {
    let (handler, handle) = FirehoseHandler::new(Arc::downgrade(registry));
    register_handler(registry, handler);
    handle
}

pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    state: Arc<StateDb>,
) -> Result<FirehoseHandle, Box<dyn std::error::Error + Send + Sync>> {
    let (handler, handle) = FirehoseHandler::with_state(Arc::downgrade(registry), state)?;
    register_handler(registry, handler);
    handle.resume()?;
    Ok(handle)
}

fn register_handler(registry: &Arc<ServiceRegistry>, handler: FirehoseHandler) {
    let handler: Arc<dyn NativeHandler> = Arc::new(handler);
    registry.register_native(
        ServiceName::new("firehose"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        handler,
    );
}

#[cfg(test)]
mod ack_loss_test;
