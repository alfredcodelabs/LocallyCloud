//! locallycloud AWS CloudFormation service.
//!
//! Implements CloudFormation as a `Native` Query-protocol service registered in the Core
//! `ServiceRegistry`. A stack's template is parsed, its resources are topologically ordered by
//! their `Ref`/`Fn::GetAtt`/`DependsOn` dependencies, and each resource is provisioned by
//! dispatching to the owning native service through the registry (S3 bucket, IAM role, Lambda
//! function, …) — never by faking state. Intrinsic functions (`Ref`, `Fn::GetAtt`, `Fn::Sub`,
//! `Fn::Join`, `Fn::Select`, `Fn::Split`) are resolved against provisioned resources.
//!
//! This is the surface the Serverless Framework (which deploys exclusively via CloudFormation)
//! and other CloudFormation-based tools consume.

pub mod error;
pub mod model;
mod persistence;
pub mod proto;
pub mod provision;
pub mod sam;
pub mod service;
pub mod store;
pub mod template;
pub mod xml;

pub use service::{register, register_with_state};
