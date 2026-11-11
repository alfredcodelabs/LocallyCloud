//! PostgreSQL-backed RDS Query control plane.

pub mod runtime;
mod service;
mod version;

pub use service::{register, RdsClusterEndpoint, RdsHandler, RdsInstanceEndpoint};
