//! Native SES sending milestone with encrypted capture and managed HTTPS delivery.
pub mod config;
mod error;
mod model;
mod protocol;
mod provider;
mod service;
mod store;

pub use config::{SesConfig, SesCredentials};
use locallycloud_core::{
    handler::NativeHandler,
    registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry},
};
use std::sync::Arc;

pub fn register_with_state_and_config(
    registry: &Arc<ServiceRegistry>,
    state: Arc<locallycloud_state::StateDb>,
    config: SesConfig,
    credentials: SesCredentials,
    listeners: &[std::net::SocketAddr],
) -> Result<(), String> {
    let cipher = locallycloud_state::StateCipher::from_env()
        .map_err(|_| "SES encryption key unavailable")?;
    let store = store::Store::open(state, cipher).map_err(|_| {
        "SES state initialization failed; check the database and original master key"
    })?;
    let pending = store
        .has_pending()
        .map_err(|_| "SES state could not be restored")?;
    let handler = service::Handler::new(
        store,
        config,
        credentials,
        Arc::downgrade(registry),
        listeners,
    )?;
    let mut metadata = ServiceMetadata::new(AwsProtocol::RestJson, None);
    metadata.known_actions = [
        "VerifyEmailIdentity",
        "VerifyEmailAddress",
        "DeleteIdentity",
        "ListIdentities",
        "SendEmail",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let native: Arc<dyn NativeHandler> = Arc::new(service::Service(handler.clone()));
    registry.register_native(ServiceName::new("ses"), metadata, native);
    if pending {
        handler.start();
    }
    Ok(())
}

#[cfg(test)]
mod tests;
