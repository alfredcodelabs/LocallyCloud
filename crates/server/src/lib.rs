//! Concrete HTTP front door and embedded dashboard for the locallycloud binary.
use locallycloud_core::{
    config, cost, error_mapping, health, integration, metering, observability, proxy, registry,
    router,
};

mod dashboard_context;
pub mod server;
mod status;
mod tls;
mod views;
