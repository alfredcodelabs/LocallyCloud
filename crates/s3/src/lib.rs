//! locallycloud AWS S3 service.
//!
//! Implements S3 as a `Native` REST-XML service registered in the Core `ServiceRegistry`.
//! Operations are selected by HTTP method, request shape (service/bucket/object), and
//! query-string sub-resource markers — never an `X-Amz-Target` header.

pub mod addr;
pub mod error;
pub mod integrity;
pub mod notifications;
pub mod ops;
pub mod presign;
pub mod query;
pub mod select;
pub mod service;
pub mod store;
pub mod xml;

pub use service::{register, register_with_state};
