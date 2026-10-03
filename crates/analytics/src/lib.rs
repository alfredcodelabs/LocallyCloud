mod athena;
mod error;
mod glue;
mod state;

use std::sync::Arc;

use locallycloud_core::handler::NativeHandler;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

use crate::athena::AthenaHandler;
use crate::glue::GlueHandler;
use crate::state::AnalyticsState;

/// Register the native analytics services.
pub fn register(registry: &Arc<ServiceRegistry>) {
    let state = Arc::new(AnalyticsState::new());
    let glue_handler: Arc<dyn NativeHandler> = Arc::new(GlueHandler::with_registry(
        Arc::clone(&state),
        Arc::downgrade(registry),
    ));
    registry.register_native(
        ServiceName::new("glue"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(glue::TARGET_PREFIX)),
        glue_handler,
    );
    let athena_handler: Arc<dyn NativeHandler> =
        Arc::new(AthenaHandler::new(Arc::downgrade(registry)));
    registry.register_native(
        ServiceName::new("athena"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(athena::TARGET_PREFIX)),
        athena_handler,
    );
}
