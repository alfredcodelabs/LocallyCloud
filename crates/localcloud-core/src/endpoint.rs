//! Inter-service endpoint resolution.
//!
//! Resolves the externally-reachable endpoint that running workloads (and cross-service
//! integrations such as Step Functions -> Lambda -> S3) use to call back into localcloud,
//! across host / container / CI environments. See Requirement 23 and the
//! `localcloud-integration` spec.

use std::net::SocketAddr;

/// Resolves the endpoint advertised to compute guests and used for cross-service calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointResolver {
    external_base_url: String,
}

impl EndpointResolver {
    /// Build from the configured external endpoint (e.g. `AWS_ENDPOINT_URL`) when present,
    /// otherwise derive a reachable URL from the listen address. A wildcard bind
    /// (`0.0.0.0` / `[::]`) is rewritten to loopback because the wildcard is not a usable
    /// target address (Req 23.2, 23.6).
    pub fn resolve(external_endpoint: Option<&str>, listen_addr: SocketAddr) -> Self {
        let external_base_url = match external_endpoint {
            Some(url) if !url.is_empty() => url.trim_end_matches('/').to_string(),
            _ => derive_from_listen_addr(listen_addr),
        };
        EndpointResolver { external_base_url }
    }

    /// The endpoint a compute guest's AWS SDK should target to reach localcloud.
    pub fn guest_endpoint(&self) -> &str {
        &self.external_base_url
    }
}

fn derive_from_listen_addr(addr: SocketAddr) -> String {
    let ip = addr.ip();
    let host = if ip.is_unspecified() {
        if ip.is_ipv6() {
            "[::1]".to_string()
        } else {
            "127.0.0.1".to_string()
        }
    } else if ip.is_ipv6() {
        format!("[{ip}]")
    } else {
        ip.to_string()
    };
    format!("http://{host}:{}", addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_endpoint_is_used_verbatim_without_trailing_slash() {
        let r = EndpointResolver::resolve(
            Some("http://host.docker.internal:4566/"),
            "0.0.0.0:4566".parse().unwrap(),
        );
        assert_eq!(r.guest_endpoint(), "http://host.docker.internal:4566");
    }

    #[test]
    fn wildcard_bind_is_rewritten_to_loopback() {
        let r = EndpointResolver::resolve(None, "0.0.0.0:4566".parse().unwrap());
        assert_eq!(r.guest_endpoint(), "http://127.0.0.1:4566");
    }

    #[test]
    fn explicit_bind_address_is_used() {
        let r = EndpointResolver::resolve(None, "192.168.1.10:4566".parse().unwrap());
        assert_eq!(r.guest_endpoint(), "http://192.168.1.10:4566");
    }

    #[test]
    fn empty_external_falls_back_to_listen_addr() {
        let r = EndpointResolver::resolve(Some(""), "127.0.0.1:4566".parse().unwrap());
        assert_eq!(r.guest_endpoint(), "http://127.0.0.1:4566");
    }
}
