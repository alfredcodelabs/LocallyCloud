//! localcloud core foundation library.
//!
//! Shared infrastructure every native AWS service builds upon:
//! - [`server`]: Axum HTTP server, binding, graceful shutdown
//! - [`router`]: multi-protocol service router (SigV4 scope → X-Amz-Target → host/path → Action)
//! - [`proxy`]: SigV4-preserving reverse proxy to an optional external backend
//! - [`registry`]: concurrent service registry (Native / Proxied disposition)
//! - [`error_mapping`]: AWS-faithful per-protocol error shapes
//! - [`config`]: environment-driven configuration with compatibility aliases
//! - [`endpoint`]: inter-service endpoint resolution (cross-service communication)
//! - [`health`]: health / readiness endpoints
//! - [`observability`]: structured tracing and per-request correlation
//!
//! Each module is currently a skeleton; behavior is filled in by the core
//! implementation tasks.

pub mod audit;
pub mod config;
pub mod cost;
pub mod endpoint;
pub mod error_mapping;
pub mod handler;
pub mod health;
pub mod integration;
pub mod metering;
pub mod observability;
pub mod proxy;
pub mod registry;
pub mod router;
pub mod server;
pub mod status;
