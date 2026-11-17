//! HTTP integration egress through the shared destination policy.
mod body;
pub(crate) use body::{read_response, BodyError, MAX_RESPONSE_BYTES};

use std::net::SocketAddr;
use std::time::Duration;

use locallycloud_core::egress::{EgressClient, EgressSettings};
use reqwest::{Method, RequestBuilder};

pub(crate) use locallycloud_core::egress::EgressError as HttpIntegrationError;

pub(crate) struct HttpIntegrationClient(EgressClient);

impl HttpIntegrationClient {
    #[cfg(test)]
    pub(crate) fn new(local_origins: &[String], listeners: &[SocketAddr]) -> Result<Self, String> {
        Self::with_config(
            &crate::ApiGatewayConfig {
                http_local_origins: local_origins.to_vec(),
                ..Default::default()
            },
            listeners,
        )
    }

    pub(crate) fn with_config(
        config: &crate::ApiGatewayConfig,
        listeners: &[SocketAddr],
    ) -> Result<Self, String> {
        config.validate()?;
        EgressClient::new(
            EgressSettings {
                local_origins: config.http_local_origins.clone(),
                client_capacity: config.http_client_cache_capacity,
                max_idle_per_host: config.http_max_idle_per_host,
                idle_timeout: Duration::from_secs(config.http_idle_timeout_secs as u64),
                ..Default::default()
            },
            listeners,
        )
        .map(Self)
    }

    pub(crate) fn request(
        &self,
        method: Method,
        url: &str,
    ) -> Result<RequestBuilder, HttpIntegrationError> {
        self.0.request(method, url)
    }
}

pub(crate) fn validate_local_origins(local_origins: &[String]) -> Result<(), String> {
    locallycloud_core::egress::validate_local_origins(local_origins)
        .map_err(|error| format!("apigateway.http_local_origins: {error}"))
}
