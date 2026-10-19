//! ECS Fargate control plane with an injectable task runtime.
mod service;

use locallycloud_core::handler::NativeHandler;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use std::sync::Arc;

pub const TARGET_PREFIX: &str = "AmazonEC2ContainerServiceV20141113";

pub use service::{TaskLaunch, TaskLogConfiguration, TaskNetworkInfo, TaskRuntime};

pub fn register(registry: &Arc<ServiceRegistry>) {
    register_with_runtime(registry, None);
}

pub fn register_with_runtime(
    registry: &Arc<ServiceRegistry>,
    runtime: Option<Arc<dyn TaskRuntime>>,
) {
    let handler: Arc<dyn NativeHandler> = Arc::new(service::EcsHandler::with_registry(
        runtime,
        Arc::downgrade(registry),
    ));
    registry.register_native(
        ServiceName::new("ecs"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        handler,
    );
}

/// Register ECS with scoped cross-service dispatch for managed ALB targets.
pub fn register_with_runtime_and_dispatcher(
    registry: &Arc<ServiceRegistry>,
    runtime: Option<Arc<dyn TaskRuntime>>,
    dispatcher: Arc<locallycloud_core::integration::InternalDispatcher>,
) {
    registry.register_native(
        ServiceName::new("ecs"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        Arc::new(service::EcsHandler::with_dispatcher(
            runtime,
            dispatcher,
            Arc::downgrade(registry),
        )),
    );
}

/// Restored desired services resume only after their network and ALB dependencies are ready.
pub struct RecoveryHandle {
    handler: std::sync::Weak<service::EcsHandler>,
}
impl RecoveryHandle {
    pub fn resume(&self) -> Result<(), String> {
        let handler = self.handler.upgrade().ok_or("ECS handler is unavailable")?;
        handler.start_reconciler();
        Ok(())
    }
}
/// Restore durable ECS configuration without reviving stale host tasks or sockets.
pub async fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    runtime: Option<Arc<dyn TaskRuntime>>,
    state: Arc<locallycloud_state::StateDb>,
) -> Result<RecoveryHandle, Box<dyn std::error::Error + Send + Sync>> {
    let handler =
        Arc::new(service::EcsHandler::with_state(runtime, Arc::downgrade(registry), state).await?);
    let recovery = RecoveryHandle {
        handler: Arc::downgrade(&handler),
    };
    registry.register_native(
        ServiceName::new("ecs"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        handler,
    );
    Ok(recovery)
}
