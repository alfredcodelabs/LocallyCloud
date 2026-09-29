//! ECS Fargate control plane with an injectable task runtime.
mod service;

use localcloud_core::handler::NativeHandler;
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use std::sync::Arc;

pub const TARGET_PREFIX: &str = "AmazonEC2ContainerServiceV20141113";

pub use service::{TaskLaunch, TaskNetworkInfo, TaskRuntime};

pub fn register(registry: &Arc<ServiceRegistry>) {
    register_with_runtime(registry, None);
}

pub fn register_with_runtime(
    registry: &Arc<ServiceRegistry>,
    runtime: Option<Arc<dyn TaskRuntime>>,
) {
    let handler: Arc<dyn NativeHandler> = Arc::new(service::EcsHandler::with_runtime(runtime));
    registry.register_native(
        ServiceName::new("ecs"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        handler,
    );
}
