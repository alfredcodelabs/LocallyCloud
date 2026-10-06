//! locallycloud AWS DynamoDB service.
//!
//! Implements DynamoDB as a `Native` JSON 1.0 service registered in the Core
//! `ServiceRegistry`. Operations are selected from the `X-Amz-Target` header.

mod capacity;
pub mod error;
pub mod expression;
pub mod ops;
pub mod partiql;
pub mod service;
pub mod store;
pub mod streams;
pub mod value;

pub use service::{register, register_with_state};
