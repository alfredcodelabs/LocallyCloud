//! Fail-closed AWS CloudWatch Logs protocol entry point.

mod clock;
mod emf;
mod error;
mod events;
mod groups;
mod insights;
mod metric_delivery;
mod metric_filters;
mod model;
mod pagination;
mod pattern;
mod producer_sink;
mod protocol;
mod query_worker;
mod retention;
mod service;
mod store;
mod streams;
mod subscription_delivery;
mod subscriptions;

use std::sync::{Arc, Weak};

pub use error::RegistrationError;
use locallycloud_core::handler::NativeHandler;
use locallycloud_core::integration::logs::InternalLogSink;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use producer_sink::LogsProducerSink;
use service::LogsHandler;

pub fn register(registry: &Arc<ServiceRegistry>) -> Result<(), RegistrationError> {
    register_with_builder(registry, LogsHandler::new)
}

fn register_with_builder<F>(
    registry: &Arc<ServiceRegistry>,
    build: F,
) -> Result<(), RegistrationError>
where
    F: FnOnce(Weak<ServiceRegistry>) -> Result<LogsHandler, RegistrationError>,
{
    let registry_weak = Arc::downgrade(registry);
    let handler: Arc<dyn NativeHandler> = Arc::new(build(registry_weak.clone())?);
    let sink: Arc<dyn InternalLogSink> = Arc::new(LogsProducerSink::new(registry_weak));
    registry.register_native_with_log_sink(
        ServiceName::new("logs"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(protocol::TARGET_PREFIX)),
        handler,
        sink,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_core::registry::Disposition;

    #[test]
    fn logs_starts_proxied_and_registers_with_a_handler() {
        let registry = ServiceRegistry::with_known_services();
        let name = ServiceName::new("logs");
        let initial = registry.lookup(&name).unwrap();
        assert_eq!(initial.disposition, Disposition::Proxied);
        assert!(initial.handler.is_none());
        assert_eq!(initial.metadata.protocol, AwsProtocol::Json11);
        assert_eq!(
            initial.metadata.target_prefix.as_deref(),
            Some(protocol::TARGET_PREFIX)
        );

        register(&registry).unwrap();
        let registered = registry.lookup(&name).unwrap();
        assert_eq!(registered.disposition, Disposition::Native);
        assert!(registered.handler.is_some());
    }

    #[test]
    fn construction_failure_leaves_logs_proxied() {
        let registry = ServiceRegistry::with_known_services();
        let result =
            register_with_builder(&registry, |_| Err(RegistrationError::RegistryUnavailable));
        assert!(result.is_err());
        let entry = registry.lookup(&ServiceName::new("logs")).unwrap();
        assert_eq!(entry.disposition, Disposition::Proxied);
        assert!(entry.handler.is_none());
    }
}
