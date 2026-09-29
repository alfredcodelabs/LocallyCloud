//! PostgreSQL-backed RDS Query control plane.

pub mod runtime;
mod service;

pub use service::{register, RdsClusterEndpoint, RdsHandler, RdsInstanceEndpoint};
