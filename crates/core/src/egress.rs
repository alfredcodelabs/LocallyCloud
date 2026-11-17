//! Destination policy for outbound HTTP(S) calls to user-configured endpoints.
//!
//! API Gateway HTTP integrations and EventBridge API destinations accept URLs from
//! clients, so every connection is checked against the addresses it actually uses:
//! literals before the request, DNS answers inside the connector.
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, Method, RequestBuilder, Url};

const MAX_DNS_ADDRESSES: usize = 64;
const MAX_LOCAL_ORIGINS: usize = 128;
const MAX_LISTENERS: usize = 4096;
const MAX_ORIGIN_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EgressError {
    #[error("Invalid outbound HTTP URL")]
    InvalidUrl,
    #[error("{0}")]
    InvalidOrigin(&'static str),
    #[error("Outbound HTTP destination is not permitted")]
    DestinationDenied,
    #[error("Outbound HTTP host-address check failed")]
    HostProbe,
    #[error("Outbound HTTP DNS resolution failed")]
    DnsResolution,
    #[error("Outbound HTTP DNS answer count is invalid")]
    DnsAnswers,
    #[error("Outbound HTTP client cache unavailable")]
    CacheUnavailable,
    #[error("Outbound HTTP client initialization failed")]
    ClientInitialization,
    #[error("Outbound HTTP TLS configuration is invalid")]
    TlsConfiguration,
    #[error("Outbound HTTP connection failed")]
    Connection,
    #[error("Outbound HTTP request timed out")]
    Timeout,
}

impl EgressError {
    pub fn from_request(error: &reqwest::Error) -> Self {
        let is_https = error.url().is_some_and(|url| url.scheme() == "https");
        let mut invalid_tls = false;
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
        while let Some(cause) = source {
            if let Some(error) = cause.downcast_ref::<Self>() {
                return *error;
            }
            if let Some(error) = cause.downcast_ref::<std::io::Error>() {
                invalid_tls |= is_https
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput
                    );
                if let Some(inner) = error.get_ref() {
                    source = Some(inner);
                    continue;
                }
            }
            source = cause.source();
        }
        if error.is_timeout() {
            Self::Timeout
        } else if invalid_tls {
            Self::TlsConfiguration
        } else {
            Self::Connection
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    fn parse(value: &str) -> Result<(Self, Url), EgressError> {
        let url = Url::parse(value).map_err(|_| EgressError::InvalidUrl)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || value.chars().any(char::is_control)
        {
            return Err(EgressError::InvalidOrigin(
                "Outbound HTTP requires HTTP(S) without credentials or fragments",
            ));
        }
        let host = url.host_str().ok_or(EgressError::InvalidOrigin(
            "Outbound HTTP URL requires a host",
        ))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.contains('*') {
            return Err(EgressError::InvalidOrigin(
                "Outbound HTTP hosts cannot contain wildcards",
            ));
        }
        let port = url
            .port_or_known_default()
            .ok_or(EgressError::InvalidOrigin("Invalid outbound HTTP port"))?;
        if port == 0 {
            return Err(EgressError::InvalidOrigin(
                "Outbound HTTP port must be nonzero",
            ));
        }
        Ok((
            Self {
                scheme: url.scheme().into(),
                host: host.strip_suffix('.').unwrap_or(host).to_owned(),
                port,
            },
            url,
        ))
    }
}

struct Policy {
    local_origins: Vec<Origin>,
    listeners: Vec<SocketAddr>,
}

impl Policy {
    fn new(local_origins: &[String], listeners: &[SocketAddr]) -> Result<Self, EgressError> {
        if local_origins.len() > MAX_LOCAL_ORIGINS || listeners.len() > MAX_LISTENERS {
            return Err(EgressError::InvalidOrigin(
                "Too many local origins or listener addresses",
            ));
        }
        let mut origins = Vec::new();
        for value in local_origins {
            if value.len() > MAX_ORIGIN_BYTES {
                return Err(EgressError::InvalidOrigin(
                    "Local origin exceeds 2048 bytes",
                ));
            }
            let (origin, url) = Origin::parse(value)?;
            if url.path() != "/" || url.query().is_some() {
                return Err(EgressError::InvalidOrigin(
                    "Local origins cannot contain a path or query",
                ));
            }
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
        let policy = Policy {
            local_origins: origins,
            listeners: listeners.to_vec(),
        };
        for origin in &policy.local_origins {
            if let Ok(ip) = origin.host.parse() {
                policy.check(origin, ip)?;
            }
        }
        Ok(policy)
    }

    fn check(&self, origin: &Origin, address: IpAddr) -> Result<(), EgressError> {
        self.check_with_local(origin, address, is_host_address)
    }

    fn check_with_local(
        &self,
        origin: &Origin,
        address: IpAddr,
        is_local: impl Fn(IpAddr) -> Result<bool, EgressError>,
    ) -> Result<(), EgressError> {
        let address = normalize(address);
        let mut known_local = None;
        for listener in &self.listeners {
            if listener.port() != origin.port {
                continue;
            }
            let bound = normalize(listener.ip());
            if bound == address {
                return Err(EgressError::DestinationDenied);
            }
            if bound.is_unspecified() && (bound.is_ipv6() || address.is_ipv4()) {
                if address.is_loopback() {
                    return Err(EgressError::DestinationDenied);
                }
                let local = is_local(address)?;
                if local {
                    return Err(EgressError::DestinationDenied);
                }
                known_local = Some(local);
            }
        }
        let permitted = match address {
            IpAddr::V4(ip) => {
                if forbidden_v4(ip) {
                    false
                } else if ip.is_loopback() || ip.is_private() || in_v4(ip, 0x6440_0000, 10) {
                    self.local_origins.contains(origin)
                } else {
                    true
                }
            }
            IpAddr::V6(ip) => {
                let bits = u128::from(ip);
                // AWS reserves this namespace for IMDS and Pod Identity credentials.
                // ISATAP interface identifiers embed an IPv4 destination (RFC 5214).
                if bits >> 96 == 0xfd00_0ec2
                    || matches!((bits >> 32) & 0xffff_ffff, 0x0000_5efe | 0x0200_5efe)
                {
                    false
                } else if ip.is_loopback() || bits >> 121 == 0x7e {
                    self.local_origins.contains(origin)
                } else {
                    // Globally allocated unicast, excluding documentation and transition
                    // mechanisms that embed another destination outside this IP policy.
                    bits >> 125 == 1
                        && bits >> 96 != 0x2001_0000
                        && bits >> 112 != 0x2002
                        && bits >> 96 != 0x2001_0db8
                        && bits >> 100 != 0x0200_1001
                        && bits >> 100 != 0x0200_1002
                        && bits >> 80 != 0x2001_0002_0000
                        && bits >> 108 != 0x3fff0
                }
            }
        };
        if !permitted {
            return Err(EgressError::DestinationDenied);
        }
        if !self.local_origins.contains(origin)
            && match known_local {
                Some(local) => local,
                None => is_local(address)?,
            }
        {
            return Err(EgressError::DestinationDenied);
        }
        Ok(())
    }

    fn addresses(&self, origin: &Origin, addresses: Addrs) -> Result<Addrs, EgressError> {
        let addresses: Vec<_> = addresses.take(MAX_DNS_ADDRESSES + 1).collect();
        if addresses.is_empty() || addresses.len() > MAX_DNS_ADDRESSES {
            return Err(EgressError::DnsAnswers);
        }
        let mut checked = Vec::with_capacity(addresses.len());
        for address in addresses {
            self.check(origin, address.ip())?;
            checked.push(SocketAddr::new(normalize(address.ip()), origin.port));
        }
        Ok(Box::new(checked.into_iter()))
    }
}

// A successful port-zero bind identifies a currently assigned host address without
// listening or sending traffic. Unexpected errors deny the destination conservatively.
fn is_host_address(address: IpAddr) -> Result<bool, EgressError> {
    let socket = match address {
        IpAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
        IpAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
    }
    .map_err(|_| EgressError::HostProbe)?;
    match socket.bind(SocketAddr::new(address, 0)) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => Ok(false),
        Err(_) => Err(EgressError::HostProbe),
    }
}

/// Validates an allowlist of exact local origins (`scheme://host[:port]`).
pub fn validate_local_origins(local_origins: &[String]) -> Result<(), String> {
    Policy::new(local_origins, &[])
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}

fn in_v4(ip: Ipv4Addr, network: u32, prefix: u32) -> bool {
    u32::from(ip) >> (32 - prefix) == network >> (32 - prefix)
}

fn forbidden_v4(ip: Ipv4Addr) -> bool {
    // IANA special-purpose ranges without ordinary destination semantics.
    let n = u32::from(ip);
    ip.is_link_local()
        || n == 0x6464_64c8
        || n >> 24 == 0
        || n >> 28 >= 14
        || (in_v4(ip, 0xc000_0000, 24) && !matches!(n, 0xc000_0009 | 0xc000_000a))
        || in_v4(ip, 0xc000_0200, 24)
        || in_v4(ip, 0xc058_6300, 24)
        || in_v4(ip, 0xc612_0000, 15)
        || in_v4(ip, 0xc633_6400, 24)
        || in_v4(ip, 0xcb00_7100, 24)
}

struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .take(MAX_DNS_ADDRESSES + 1)
                .collect();
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

struct FilteredResolver {
    origin: Origin,
    policy: Arc<Policy>,
    source: Arc<dyn Resolve>,
}

impl Resolve for FilteredResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let origin = self.origin.clone();
        let policy = self.policy.clone();
        if name.as_str().strip_suffix('.').unwrap_or(name.as_str()) != origin.host {
            return Box::pin(async { Err(EgressError::DestinationDenied.into()) });
        }
        let result = self.source.resolve(name);
        Box::pin(async move {
            policy
                .addresses(
                    &origin,
                    result.await.map_err(|_| EgressError::DnsResolution)?,
                )
                .map_err(Into::into)
        })
    }
}

/// Connection settings owned by the calling service's typed configuration.
#[derive(Clone)]
pub struct EgressSettings {
    /// Exact origins allowed to reach host, loopback and private addresses.
    pub local_origins: Vec<String>,
    pub client_capacity: usize,
    pub max_idle_per_host: usize,
    pub idle_timeout: Duration,
    pub connect_timeout: Option<Duration>,
    pub request_timeout: Option<Duration>,
    /// Extra trust anchors; production callers leave this empty.
    pub root_certificates: Vec<reqwest::Certificate>,
}

impl Default for EgressSettings {
    fn default() -> Self {
        Self {
            local_origins: Vec::new(),
            client_capacity: 16,
            max_idle_per_host: 1,
            idle_timeout: Duration::from_secs(30),
            connect_timeout: None,
            request_timeout: None,
            root_certificates: Vec::new(),
        }
    }
}

/// Per-origin clients whose connector applies the destination policy, without
/// proxies or redirects. Clients are built on first use and the cache is bounded.
pub struct EgressClient {
    policy: Arc<Policy>,
    resolver: Arc<dyn Resolve>,
    clients: Mutex<VecDeque<(Origin, Client)>>,
    settings: EgressSettings,
}

impl EgressClient {
    /// `listeners` are LocallyCloud's own bound addresses, which are never reachable.
    pub fn new(settings: EgressSettings, listeners: &[SocketAddr]) -> Result<Self, String> {
        if settings.client_capacity == 0 {
            return Err("Outbound HTTP client cache capacity must be at least 1".into());
        }
        let policy = Arc::new(
            Policy::new(&settings.local_origins, listeners).map_err(|error| error.to_string())?,
        );
        Ok(Self {
            policy,
            resolver: Arc::new(SystemResolver),
            clients: Mutex::new(VecDeque::new()),
            settings,
        })
    }

    pub fn request(&self, method: Method, url: &str) -> Result<RequestBuilder, EgressError> {
        let (origin, url) = Origin::parse(url)?;
        // Hyper bypasses DNS resolution for literals, so they must pass the same check here.
        if let Ok(ip) = origin.host.parse() {
            self.policy.check(&origin, ip)?;
        }
        {
            let mut clients = self
                .clients
                .lock()
                .map_err(|_| EgressError::CacheUnavailable)?;
            if let Some(index) = clients.iter().position(|(key, _)| key == &origin) {
                if let Some((key, client)) = clients.remove(index) {
                    let request = client.request(method, url);
                    clients.push_back((key, client));
                    return Ok(request);
                }
            }
        }
        let client = self.build_client(&origin)?;
        let request = client.request(method, url);
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| EgressError::CacheUnavailable)?;
        if clients.len() >= self.settings.client_capacity {
            clients.pop_front();
        }
        clients.push_back((origin, client));
        Ok(request)
    }

    fn build_client(&self, origin: &Origin) -> Result<Client, EgressError> {
        let settings = &self.settings;
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(settings.max_idle_per_host)
            .pool_idle_timeout(settings.idle_timeout)
            .dns_resolver(Arc::new(FilteredResolver {
                origin: origin.clone(),
                policy: self.policy.clone(),
                source: self.resolver.clone(),
            }));
        if let Some(timeout) = settings.connect_timeout {
            builder = builder.connect_timeout(timeout);
        }
        if let Some(timeout) = settings.request_timeout {
            builder = builder.timeout(timeout);
        }
        for certificate in &settings.root_certificates {
            builder = builder.add_root_certificate(certificate.clone());
        }
        builder
            .build()
            .map_err(|_| EgressError::ClientInitialization)
    }
}

#[cfg(test)]
mod tests;
