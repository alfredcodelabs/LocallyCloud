//! Guest endpoint injection.
//!
//! Produces the environment a started compute Guest (a Firecracker microVM or a youki/OCI
//! container) receives so an in-Guest AWS SDK targets localcloud instead of real AWS: the
//! Core-resolved endpoint, the region, and the development credentials. In-Guest SDK calls
//! then re-enter through the same [`InternalDispatcher`](super::InternalDispatcher) path as
//! any other cross-service call, so they honour the target's disposition identically.
//!
//! The injector is backend-agnostic: it yields a plain variable map that both the Firecracker
//! and youki backends merge into their `TaskSpec` environment, keeping `localcloud-core`
//! decoupled from the compute crate. It also probes the endpoint's reachability from the host
//! and emits a diagnostic when it cannot be reached, so an in-Guest SDK failure is
//! explainable rather than silent. See Requirement 4.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use crate::endpoint::EndpointResolver;

/// Development credentials injected into a Guest so its AWS SDK is accepted by localcloud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl GuestCredentials {
    /// The fixed local development identity used when IAM enforcement is off.
    pub fn development() -> Self {
        GuestCredentials {
            access_key_id: "test".into(),
            secret_access_key: "test".into(),
            session_token: None,
        }
    }
}

/// Builds the endpoint/region/credential environment injected into a started Guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestEndpointInjector {
    endpoint: String,
    region: String,
    credentials: GuestCredentials,
}

impl GuestEndpointInjector {
    /// Build from the Core [`EndpointResolver`] (the single source of the guest-reachable
    /// endpoint), the default region, and the development credentials.
    pub fn new(
        resolver: &EndpointResolver,
        region: impl Into<String>,
        credentials: GuestCredentials,
    ) -> Self {
        GuestEndpointInjector {
            endpoint: resolver.guest_endpoint().to_string(),
            region: region.into(),
            credentials,
        }
    }

    /// The endpoint injected into the Guest, e.g. `http://127.0.0.1:4566`.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The AWS SDK discovery variables injected into a Guest. Standard names so any AWS SDK
    /// (any language) picks them up without further configuration.
    pub fn env_vars(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("AWS_ENDPOINT_URL".into(), self.endpoint.clone());
        env.insert("AWS_REGION".into(), self.region.clone());
        env.insert("AWS_DEFAULT_REGION".into(), self.region.clone());
        env.insert(
            "AWS_ACCESS_KEY_ID".into(),
            self.credentials.access_key_id.clone(),
        );
        env.insert(
            "AWS_SECRET_ACCESS_KEY".into(),
            self.credentials.secret_access_key.clone(),
        );
        if let Some(token) = &self.credentials.session_token {
            env.insert("AWS_SESSION_TOKEN".into(), token.clone());
        }
        env
    }

    /// Merge the injected variables into a Guest's environment map (the compute `TaskSpec`
    /// env). The injected endpoint/credentials take precedence so a Guest cannot be
    /// misconfigured to bypass localcloud.
    pub fn inject_into(&self, env: &mut HashMap<String, String>) {
        for (key, value) in self.env_vars() {
            env.insert(key, value);
        }
    }

    /// Probe the resolved endpoint from the host and emit a diagnostic if it cannot be
    /// reached, so a later in-Guest SDK failure is explainable (Req 4.4). This never fails
    /// the caller — injection still proceeds; the returned diagnostic is informational.
    pub async fn check_reachable(&self, timeout: Duration) -> ReachabilityDiagnostic {
        let Some(addr) = host_port(&self.endpoint) else {
            return ReachabilityDiagnostic::unreachable(
                &self.endpoint,
                "endpoint is not a parseable host:port URL",
            );
        };
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_stream)) => ReachabilityDiagnostic::Reachable,
            Ok(Err(e)) => ReachabilityDiagnostic::unreachable(&self.endpoint, &e.to_string()),
            Err(_) => ReachabilityDiagnostic::unreachable(&self.endpoint, "connection timed out"),
        }
    }
}

/// The outcome of an endpoint reachability probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityDiagnostic {
    Reachable,
    Unreachable { endpoint: String, cause: String },
}

impl ReachabilityDiagnostic {
    fn unreachable(endpoint: &str, cause: &str) -> Self {
        tracing::warn!(
            endpoint,
            cause,
            "injected localcloud endpoint is unreachable from the host; in-Guest SDK calls will fail"
        );
        ReachabilityDiagnostic::Unreachable {
            endpoint: endpoint.to_string(),
            cause: cause.to_string(),
        }
    }

    pub fn is_reachable(&self) -> bool {
        matches!(self, ReachabilityDiagnostic::Reachable)
    }
}

/// Parse the `host:port` connect target from an `http(s)://host:port[/...]` endpoint URL,
/// defaulting the port from the scheme when absent.
fn host_port(endpoint: &str) -> Option<String> {
    let (scheme, rest) = endpoint.split_once("://")?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    // Strip any path/query, keeping only the authority.
    let authority = rest.split(['/', '?']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    // IPv6 literal, e.g. [::1]:4566 or [::1].
    if let Some(after_bracket) = authority.strip_prefix('[') {
        let (host, tail) = after_bracket.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Some(format!("[{host}]:{port}"));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => Some(format!("{host}:{port}")),
        _ => Some(format!("{authority}:{default_port}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn injector(endpoint_addr: SocketAddr) -> GuestEndpointInjector {
        let resolver = EndpointResolver::resolve(None, endpoint_addr);
        GuestEndpointInjector::new(&resolver, "us-east-1", GuestCredentials::development())
    }

    #[test]
    fn env_vars_carry_endpoint_region_and_credentials() {
        let inj = injector("127.0.0.1:4566".parse().unwrap());
        let env = inj.env_vars();
        assert_eq!(env["AWS_ENDPOINT_URL"], "http://127.0.0.1:4566");
        assert_eq!(env["AWS_REGION"], "us-east-1");
        assert_eq!(env["AWS_DEFAULT_REGION"], "us-east-1");
        assert_eq!(env["AWS_ACCESS_KEY_ID"], "test");
        assert_eq!(env["AWS_SECRET_ACCESS_KEY"], "test");
        assert!(!env.contains_key("AWS_SESSION_TOKEN"));
    }

    #[test]
    fn session_token_injected_when_present() {
        let resolver = EndpointResolver::resolve(None, "127.0.0.1:4566".parse().unwrap());
        let creds = GuestCredentials {
            access_key_id: "ASIA".into(),
            secret_access_key: "s".into(),
            session_token: Some("tok".into()),
        };
        let inj = GuestEndpointInjector::new(&resolver, "eu-west-1", creds);
        let env = inj.env_vars();
        assert_eq!(env["AWS_SESSION_TOKEN"], "tok");
        assert_eq!(env["AWS_REGION"], "eu-west-1");
    }

    #[test]
    fn inject_into_overwrites_guest_supplied_endpoint() {
        let inj = injector("127.0.0.1:4566".parse().unwrap());
        let mut env: HashMap<String, String> = HashMap::new();
        env.insert("AWS_ENDPOINT_URL".into(), "https://real.aws".into());
        env.insert("KEEP".into(), "me".into());
        inj.inject_into(&mut env);
        // Guest cannot bypass localcloud: the injected endpoint wins.
        assert_eq!(env["AWS_ENDPOINT_URL"], "http://127.0.0.1:4566");
        // Unrelated guest variables are preserved.
        assert_eq!(env["KEEP"], "me");
    }

    #[test]
    fn host_port_parses_variants() {
        assert_eq!(
            host_port("http://127.0.0.1:4566").unwrap(),
            "127.0.0.1:4566"
        );
        assert_eq!(
            host_port("https://example.com/path").unwrap(),
            "example.com:443"
        );
        assert_eq!(host_port("http://example.com").unwrap(), "example.com:80");
        assert_eq!(host_port("http://[::1]:4566").unwrap(), "[::1]:4566");
        assert_eq!(host_port("http://[::1]").unwrap(), "[::1]:80");
        assert!(host_port("ftp://example.com").is_none());
        assert!(host_port("not-a-url").is_none());
    }

    #[tokio::test]
    async fn reachable_endpoint_reports_reachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let inj = injector(addr);
        let diag = inj.check_reachable(Duration::from_secs(2)).await;
        assert!(
            diag.is_reachable(),
            "a live listener must be reachable: {diag:?}"
        );
    }

    #[tokio::test]
    async fn dead_endpoint_reports_unreachable_diagnostic() {
        // Bind then drop to obtain a port nothing is listening on.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let inj = injector(addr);
        let diag = inj.check_reachable(Duration::from_secs(1)).await;
        assert!(!diag.is_reachable());
        match diag {
            ReachabilityDiagnostic::Unreachable { endpoint, .. } => {
                assert!(endpoint.contains(&addr.port().to_string()));
            }
            ReachabilityDiagnostic::Reachable => panic!("expected unreachable"),
        }
    }
}
