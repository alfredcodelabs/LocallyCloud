//! locallycloud AWS Lambda service.
//!
//! Implements the Lambda control plane as a `Native` REST-JSON service registered in the
//! Core `ServiceRegistry`. The data plane (invocation) and the remaining control-plane
//! operations are added incrementally on top of this skeleton.

pub mod code_store;
pub mod concurrency;
pub mod control_plane;
pub mod error;
pub mod esm;
pub mod exec_env;
pub mod executor;
pub mod function_url;
pub mod model;
mod persistence;
pub mod rootfs;
pub mod runtime_api;
pub mod runtime_api_server;
pub mod service;
pub mod trace_header;
mod vpc_dns;

pub use service::{register, register_with_execution, LambdaHandler};
