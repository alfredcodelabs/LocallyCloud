//! locallycloud AWS SQS service.
//!
//! Implements SQS as a `Native` AWS JSON 1.0 service registered in the Core
//! `ServiceRegistry`, selected from the `X-Amz-Target: AmazonSQS.*` header. Visibility
//! timeouts, long polling, FIFO ordering/deduplication, and dead-letter redrive are all
//! enforced.

pub mod error;
pub mod md5;
pub mod metrics;
pub mod model;
pub mod ops;
mod persistence;
mod policy;
pub mod proto;
pub mod service;
pub mod store;

pub use service::{register, register_with_state};
