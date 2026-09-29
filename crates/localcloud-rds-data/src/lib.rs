//! Native AWS RDS Data API backed by an Aurora PostgreSQL writer.

mod bound;
mod config;
mod error;
mod model;
mod postgres;
mod service;

use std::sync::Arc;

pub use config::{IdentityMode, RdsDataConfig, RdsDataLimits};
use localcloud_core::handler::NativeHandler;
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
pub use postgres::{ClusterResolver, PgClusterEndpoint};
pub use service::{RdsDataHandle, RdsDataStats};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StartupError {
    #[error("invalid RDS Data configuration: {0}")]
    InvalidConfig(String),
}

pub fn register(registry: &Arc<ServiceRegistry>) -> Result<RdsDataHandle, StartupError> {
    register_with_config(registry, RdsDataConfig::default())
}

pub fn register_with_config(
    registry: &Arc<ServiceRegistry>,
    config: RdsDataConfig,
) -> Result<RdsDataHandle, StartupError> {
    register_with_cluster_resolver(registry, config, None)
}

pub fn register_with_cluster_resolver(
    registry: &Arc<ServiceRegistry>,
    config: RdsDataConfig,
    resolver: Option<Arc<dyn ClusterResolver>>,
) -> Result<RdsDataHandle, StartupError> {
    config.validate()?;
    let (_, mut handle) = service::RdsDataHandler::new(config.clone());
    let handler = postgres::PgHandler::new(registry.clone(), resolver, config.clone());
    handle.pg_state = Some(handler.state.clone());
    let handler: Arc<dyn NativeHandler> = Arc::new(handler);
    registry.register_native(
        ServiceName::new("rds-data"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        handler,
    );
    Ok(handle)
}
