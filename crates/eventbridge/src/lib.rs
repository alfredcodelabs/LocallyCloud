//! Native AWS EventBridge, EventBridge Scheduler, and EventBridge Pipes services.

pub mod arn;
pub mod config;
pub mod delivery;
pub mod error;
pub mod events;
pub mod http_client;
pub mod model;
pub mod pattern;
pub mod pipes;
pub mod schedule;
pub mod scheduler;
pub mod schemas;
pub mod service;
pub mod store;
pub mod transform;

pub use config::EventBridgeConfig;
pub use service::{
    register, register_with_clock, register_with_config, register_with_state,
    register_with_state_and_config,
};

#[cfg(test)]
mod property_tests;
