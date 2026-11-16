//! locallycloud AWS API Gateway control plane (v1 REST + v2 HTTP/WebSocket).
//!
//! Registered `Native` in the Core `ServiceRegistry` under the `apigateway` service name.
//! Both control planes speak REST-JSON; the operation is resolved from HTTP method + path.
//! The execute/invoke path (`execute-api`) and the WebSocket runtime are later increments.

pub mod auth;
pub mod config;
mod domains;
mod endpoint;
pub mod error;
pub mod execute;
pub mod logging;
pub mod proxy_event;
mod resource_policy;
pub mod service;
mod stage_path;
pub mod store;
mod tags;
pub mod v1;
pub mod v2;
pub mod vtl;
pub mod websocket;
mod xray;

#[cfg(test)]
mod property_tests;

pub use config::ApiGatewayConfig;
pub use service::{
    register, register_with_acm, register_with_state, register_with_state_and_config,
};
