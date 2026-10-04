//! locallycloud AWS API Gateway control plane (v1 REST + v2 HTTP/WebSocket).
//!
//! Registered `Native` in the Core `ServiceRegistry` under the `apigateway` service name.
//! Both control planes speak REST-JSON; the operation is resolved from HTTP method + path.
//! The execute/invoke path (`execute-api`) and the WebSocket runtime are later increments.

pub mod auth;
mod domains;
pub mod error;
pub mod execute;
pub mod logging;
pub mod proxy_event;
pub mod service;
pub mod store;
pub mod v1;
pub mod v2;
pub mod vtl;
pub mod websocket;

#[cfg(test)]
mod property_tests;

pub use service::{register, register_with_acm};
