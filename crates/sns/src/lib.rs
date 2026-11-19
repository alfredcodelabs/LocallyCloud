//! locallycloud AWS SNS service.
//!
//! Implements SNS as a `Native` dual-protocol service (Query/XML GA + AWS JSON) registered
//! in the Core `ServiceRegistry`. Fanout (SNS→SQS, SNS→Lambda) is performed in-process by
//! dispatching to the target native services through the registry.

mod config;
pub use config::SnsConfig;

pub mod digest;
pub mod envelope;
pub mod error;
pub mod fanout;
pub mod filter;
pub mod model;
pub mod ops;
mod persistence;
pub mod proto;
pub mod reply;
pub mod service;
pub mod store;
pub mod xml;

pub use service::{
    register, register_with_config_and_endpoint, register_with_state,
    register_with_state_config_and_endpoint,
};
