//! locallycloud AWS IAM and STS services.
//!
//! Implements IAM and STS as two `Native` Query-protocol services registered in the Core
//! `ServiceRegistry`. IAM and STS responses and errors are XML only (never JSON).

pub mod arn;
pub mod enforcement;
pub mod error;
pub mod iam;
pub mod ids;
pub mod model;
mod persistence;
pub mod policy;
pub mod query;
mod resource_policy;
pub mod service;
pub mod store;
pub mod sts;

pub use service::register;
