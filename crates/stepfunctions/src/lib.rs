//! locallycloud AWS Step Functions service.
//!
//! Implements the Step Functions (`states`) control plane and a JSONPath ASL interpreter as
//! a `Native` AWS JSON 1.0 service. Task states dispatch to other native services through
//! the Core registry, giving real in-process orchestration (SFn → SQS/SNS/DynamoDB/
//! EventBridge/Lambda). JSONata, Distributed Map, activities/callbacks, and versions/aliases
//! are additive layers.

pub mod asl;
mod authorization;
pub mod choice;
pub mod clock;
pub mod error;
pub mod interpreter;
pub mod jsonata;
pub mod logging;
pub mod ops;
pub mod path;
mod s3_integration;
pub mod service;
pub mod store;

#[cfg(test)]
mod property_tests;

pub use service::{register, register_with_state};
