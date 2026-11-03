//! Architecture-review topology for the dashboard.
//!
//! - [`domain`]: the review model (nodes, edges, unresolved gaps, limits) and its JSON shape.
//! - [`acl`]: the anti-corruption layer that reads deployed AWS state through Core's
//!   [`locallycloud_core::views::architecture::AwsReader`] and translates it into the model.
//!
//! The composition root injects [`CloudFormationTopology`] into the server with
//! `LocallyCloudServer::with_architecture_source`.

pub mod acl;
pub mod domain;

pub use acl::{CloudFormationTopology, Limits};
