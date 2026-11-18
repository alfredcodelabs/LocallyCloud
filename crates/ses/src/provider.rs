//! One managed-provider adapter, a fixed origin and bounded, secret-safe results.
use crate::{
    config::{Provider, SesConfig, SesCredentials},
    store::Job,
};
use locallycloud_core::egress::{EgressClient, EgressSettings};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub(crate) enum Outcome {
    Accepted(String),
    Retry(u64),
    Failed(&'static str),
}
pub(crate) struct Delivery {
    client: EgressClient,
    credentials: SesCredentials,
    pub binding: String,
    endpoint: String,
}
impl Delivery {
    pub fn new(
        config: &SesConfig,
        credentials: SesCredentials,
        listeners: &[std::net::SocketAddr],
    ) -> Result<Self, String> {
        if config.provider == Provider::Resend && credentials.api_key.is_none() {
            return Err("Resend delivery requires a provider credential".into());
        }
        let binding = match &credentials.api_key {
            Some(key) => format!("resend:{:x}", Sha256::digest(key.as_bytes())),
            None => "capture".into(),
        };
        Ok(Self {
            client: EgressClient::new(
                EgressSettings {
                    client_capacity: 1,
                    max_idle_per_host: config.max_concurrency,
                    connect_timeout: Some(Duration::from_secs(5)),
                    request_timeout: Some(Duration::from_secs(config.request_timeout_secs)),
                    ..EgressSettings::default()
                },
                listeners,
            )?,
            credentials,
            binding,
            endpoint: "https://api.resend.com/emails".into(),
        })
    }
    pub async fn send(&self, job: &Job) -> Outcome {
        let Some(key) = &self.credentials.api_key else {
            return Outcome::Failed("missing_provider_credential");
        };
        let Ok(request) = self.client.request(http::Method::POST, &self.endpoint) else {
            return Outcome::Failed("provider_destination_rejected");
        };
        let result = request
            .bearer_auth(key.as_str())
            .header("Idempotency-Key", format!("locallycloud-ses-{}", job.id))
            .json(&job.envelope.mail)
            .send()
            .await;
        let Ok(mut response) = result else {
            return Outcome::Retry(backoff(job.attempts));
        };
        let status = response.status();
        if status.as_u16() == 429 || status.is_server_error() {
            let delay = response
                .headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or_else(|| backoff(job.attempts));
            return Outcome::Retry(delay.clamp(1, 86400));
        }
        if !status.is_success() {
            return Outcome::Failed("provider_rejected");
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if body.len().saturating_add(chunk.len()) <= 65536 => {
                    body.extend_from_slice(&chunk)
                }
                Ok(None) => break,
                _ => return Outcome::Retry(backoff(job.attempts)),
            }
        }
        let id = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("id").and_then(|v| v.as_str()).map(str::to_owned));
        match id
            .filter(|v| !v.is_empty() && v.len() <= 256 && v.bytes().all(|b| b.is_ascii_graphic()))
        {
            Some(id) => Outcome::Accepted(id),
            None => Outcome::Retry(backoff(job.attempts)),
        }
    }
    pub fn enabled(config: &SesConfig) -> bool {
        config.provider == Provider::Resend
    }
}
fn backoff(attempt: i64) -> u64 {
    1u64.checked_shl(attempt.clamp(1, 10) as u32)
        .unwrap_or(1024)
}

#[cfg(test)]
impl Delivery {
    pub(crate) fn fixture(config: &SesConfig, credentials: SesCredentials, origin: &str) -> Self {
        let mut delivery = Self::new(config, credentials, &[]).unwrap();
        delivery.client = EgressClient::new(
            EgressSettings {
                local_origins: vec![origin.into()],
                request_timeout: Some(Duration::from_secs(config.request_timeout_secs)),
                ..EgressSettings::default()
            },
            &[],
        )
        .unwrap();
        delivery.endpoint = format!("{origin}/emails");
        delivery
    }
}
