//! HTTP integration egress checks applied to the addresses used by the connector.
mod body;
pub(crate) use body::{read_response, BodyError, MAX_RESPONSE_BYTES};

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, Method, RequestBuilder, Url};

const MAX_DNS_ADDRESSES: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum HttpIntegrationError {
    #[error("Invalid HTTP integration URL")]
    InvalidUrl,
    #[error("{0}")]
    InvalidOrigin(&'static str),
    #[error("HTTP integration destination is not permitted")]
    DestinationDenied,
    #[error("HTTP integration host-address check failed")]
    HostProbe,
    #[error("HTTP integration DNS resolution failed")]
    DnsResolution,
    #[error("HTTP integration DNS answer count is invalid")]
    DnsAnswers,
    #[error("HTTP integration client cache unavailable")]
    CacheUnavailable,
    #[error("HTTP integration client initialization failed")]
    ClientInitialization,
    #[error("HTTP integration TLS configuration is invalid")]
    TlsConfiguration,
    #[error("HTTP integration connection failed")]
    Connection,
    #[error("HTTP integration timed out")]
    Timeout,
}

impl HttpIntegrationError {
    pub(crate) fn from_request(error: &reqwest::Error) -> Self {
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
    fn parse(value: &str) -> Result<(Self, Url), HttpIntegrationError> {
        let url = Url::parse(value).map_err(|_| HttpIntegrationError::InvalidUrl)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || value.chars().any(char::is_control)
        {
            return Err(HttpIntegrationError::InvalidOrigin(
                "HTTP integrations require HTTP(S) without credentials or fragments",
            ));
        }
        let host = url.host_str().ok_or(HttpIntegrationError::InvalidOrigin(
            "HTTP integration URL requires a host",
        ))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.contains('*') {
            return Err(HttpIntegrationError::InvalidOrigin(
                "HTTP integration hosts cannot contain wildcards",
            ));
        }
        let port = url
            .port_or_known_default()
            .ok_or(HttpIntegrationError::InvalidOrigin(
                "Invalid HTTP integration port",
            ))?;
        if port == 0 {
            return Err(HttpIntegrationError::InvalidOrigin(
                "HTTP integration port must be nonzero",
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
    fn new(
        local_origins: &[String],
        listeners: &[SocketAddr],
    ) -> Result<Self, HttpIntegrationError> {
        if local_origins.len() > 128 || listeners.len() > 4096 {
            return Err(HttpIntegrationError::InvalidOrigin(
                "Too many HTTP integration origins or listener addresses",
            ));
        }
        let mut origins = Vec::new();
        for value in local_origins {
            if value.len() > 2048 {
                return Err(HttpIntegrationError::InvalidOrigin(
                    "HTTP integration origin exceeds 2048 bytes",
                ));
            }
            let (origin, url) = Origin::parse(value)?;
            if url.path() != "/" || url.query().is_some() {
                return Err(HttpIntegrationError::InvalidOrigin(
                    "HTTP integration origins cannot contain a path or query",
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

    fn check(&self, origin: &Origin, address: IpAddr) -> Result<(), HttpIntegrationError> {
        self.check_with_local(origin, address, is_host_address)
    }

    fn check_with_local(
        &self,
        origin: &Origin,
        address: IpAddr,
        is_local: impl Fn(IpAddr) -> Result<bool, HttpIntegrationError>,
    ) -> Result<(), HttpIntegrationError> {
        let address = normalize(address);
        let mut known_local = None;
        for listener in &self.listeners {
            if listener.port() != origin.port {
                continue;
            }
            let bound = normalize(listener.ip());
            if bound == address {
                return Err(HttpIntegrationError::DestinationDenied);
            }
            if bound.is_unspecified() && (bound.is_ipv6() || address.is_ipv4()) {
                if address.is_loopback() {
                    return Err(HttpIntegrationError::DestinationDenied);
                }
                let local = is_local(address)?;
                if local {
                    return Err(HttpIntegrationError::DestinationDenied);
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
            return Err(HttpIntegrationError::DestinationDenied);
        }
        if !self.local_origins.contains(origin)
            && match known_local {
                Some(local) => local,
                None => is_local(address)?,
            }
        {
            return Err(HttpIntegrationError::DestinationDenied);
        }
        Ok(())
    }

    fn addresses(&self, origin: &Origin, addresses: Addrs) -> Result<Addrs, HttpIntegrationError> {
        let addresses: Vec<_> = addresses.take(MAX_DNS_ADDRESSES + 1).collect();
        if addresses.is_empty() || addresses.len() > MAX_DNS_ADDRESSES {
            return Err(HttpIntegrationError::DnsAnswers);
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
fn is_host_address(address: IpAddr) -> Result<bool, HttpIntegrationError> {
    let socket = match address {
        IpAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
        IpAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
    }
    .map_err(|_| HttpIntegrationError::HostProbe)?;
    match socket.bind(SocketAddr::new(address, 0)) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => Ok(false),
        Err(_) => Err(HttpIntegrationError::HostProbe),
    }
}

pub(crate) fn validate_local_origins(local_origins: &[String]) -> Result<(), String> {
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
            return Box::pin(async { Err(HttpIntegrationError::DestinationDenied.into()) });
        }
        let result = self.source.resolve(name);
        Box::pin(async move {
            policy
                .addresses(
                    &origin,
                    result
                        .await
                        .map_err(|_| HttpIntegrationError::DnsResolution)?,
                )
                .map_err(Into::into)
        })
    }
}

pub(crate) struct HttpIntegrationClient {
    policy: Arc<Policy>,
    resolver: Arc<dyn Resolve>,
    clients: Mutex<VecDeque<(Origin, Client)>>,
    client_capacity: usize,
    max_idle_per_host: usize,
    idle_timeout: Duration,
}

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
        let policy = Arc::new(
            Policy::new(&config.http_local_origins, listeners)
                .map_err(|error| error.to_string())?,
        );
        Ok(Self {
            policy,
            resolver: Arc::new(SystemResolver),
            clients: Mutex::new(VecDeque::new()),
            client_capacity: config.http_client_cache_capacity,
            max_idle_per_host: config.http_max_idle_per_host,
            idle_timeout: Duration::from_secs(config.http_idle_timeout_secs as u64),
        })
    }

    pub(crate) fn request(
        &self,
        method: Method,
        url: &str,
    ) -> Result<RequestBuilder, HttpIntegrationError> {
        let (origin, url) = Origin::parse(url)?;
        // Hyper bypasses DNS resolution for literals, so they must pass the same check here.
        if let Ok(ip) = origin.host.parse() {
            self.policy.check(&origin, ip)?;
        }
        {
            let mut clients = self
                .clients
                .lock()
                .map_err(|_| HttpIntegrationError::CacheUnavailable)?;
            if let Some(index) = clients.iter().position(|(key, _)| key == &origin) {
                if let Some((key, client)) = clients.remove(index) {
                    let request = client.request(method, url);
                    clients.push_back((key, client));
                    return Ok(request);
                }
            }
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(self.max_idle_per_host)
            .pool_idle_timeout(self.idle_timeout)
            .dns_resolver(Arc::new(FilteredResolver {
                origin: origin.clone(),
                policy: self.policy.clone(),
                source: self.resolver.clone(),
            }))
            .build()
            .map_err(|_| HttpIntegrationError::ClientInitialization)?;
        let request = client.request(method, url);
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| HttpIntegrationError::CacheUnavailable)?;
        if clients.len() >= self.client_capacity {
            clients.pop_front();
        }
        clients.push_back((origin, client));
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn origin(value: &str) -> Origin {
        Origin::parse(value).unwrap().0
    }

    #[test]
    fn local_permissions_are_exact_origins_and_special_destinations_are_never_excepted() {
        let client = HttpIntegrationClient::new(&["http://127.0.0.1:8080".into()], &[]).unwrap();
        assert!(client
            .request(Method::GET, "http://127.0.0.1:8080/path?query=yes")
            .is_ok());
        for url in [
            "http://127.0.0.1:8081",
            "https://127.0.0.1:8080",
            "http://127.1:8081",
            "http://10.0.0.1",
            "http://100.64.0.1",
            "http://[fd01::1]",
            "http://user:secret@example.com",
            "http://example.com/#fragment",
            "file:///etc/passwd",
        ] {
            assert!(client.request(Method::GET, url).is_err(), "{url}");
        }
        for url in [
            "http://169.254.169.254",
            "http://100.100.100.200",
            "http://[fd00:ec2::254]",
            "http://[fd00:ec2::23]",
            "http://[fd00:ec2:ffff::1]",
            "http://192.88.99.1",
            "http://[2001:4860::5efe:a9fe:a9fe]",
            "http://[fd01::200:5efe:7f00:1]",
            "http://[::ffff:169.254.169.254]",
            "http://0.0.0.0",
            "http://224.0.0.1",
            "http://255.255.255.255",
            "http://[fe80::1]",
            "http://[ff02::1]",
            "http://[64:ff9b::a00:1]",
        ] {
            assert!(
                HttpIntegrationClient::new(&[url.into()], &[]).is_err(),
                "{url}"
            );
        }
        for url in [
            "http://example.com/path",
            "http://example.com/?q=yes",
            "http://example.com/#fragment",
            "http://*.example.com",
            "http://api.*.example.com",
        ] {
            assert!(
                HttpIntegrationClient::new(&[url.into()], &[]).is_err(),
                "{url}"
            );
        }
        assert_eq!(
            origin("http://EXAMPLE.com:80"),
            origin("http://example.com")
        );
        assert_eq!(origin("http://example.com."), origin("http://example.com"));
        assert_ne!(origin("http://example.com.."), origin("http://example.com"));
        assert!(client.request(Method::GET, "http://*.example.com").is_err());
        assert!(HttpIntegrationClient::new(&["http://[fd01::1]".into()], &[]).is_ok());
    }

    #[test]
    fn self_listener_overrides_explicit_origin_permission() {
        assert!(HttpIntegrationClient::new(
            &["http://127.0.0.1:4566".into()],
            &["127.0.0.1:4566".parse().unwrap()]
        )
        .is_err());
        assert!(HttpIntegrationClient::new(
            &["http://127.0.0.2:4566".into()],
            &["0.0.0.0:4566".parse().unwrap()]
        )
        .is_err());
        assert!(HttpIntegrationClient::new(
            &["http://[::ffff:127.0.0.1]:4566".into()],
            &["127.0.0.1:4566".parse().unwrap()]
        )
        .is_err());
    }

    #[test]
    fn public_host_addresses_require_explicit_permission_and_probe_errors_deny() {
        let origin = origin("http://public-backend.test:8080");
        let address = "8.8.8.8".parse().unwrap();
        let denied = Policy::new(&[], &[]).unwrap();
        assert!(denied
            .check_with_local(&origin, address, |_| Ok(true))
            .is_err());
        assert!(denied
            .check_with_local(&origin, address, |_| Ok(false))
            .is_ok());
        assert!(denied
            .check_with_local(&origin, address, |_| Err(HttpIntegrationError::HostProbe))
            .is_err());
        let allowed = Policy::new(&["http://public-backend.test:8080".into()], &[]).unwrap();
        assert!(allowed
            .check_with_local(&origin, address, |_| panic!("unneeded host probe"))
            .is_ok());
        assert!(is_host_address("127.0.0.1".parse().unwrap()).unwrap());
    }

    struct Answers(Mutex<VecDeque<Vec<SocketAddr>>>);

    impl Resolve for Answers {
        fn resolve(&self, _: Name) -> Resolving {
            let answer = self.0.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { Ok(Box::new(answer.into_iter()) as Addrs) })
        }
    }

    #[tokio::test]
    async fn resolver_checks_each_connection_and_rejects_mixed_answers() {
        let client = HttpIntegrationClient::new(&[], &[]).unwrap();
        let source = Arc::new(Answers(Mutex::new(VecDeque::from([
            vec!["1.1.1.1:0".parse().unwrap()],
            vec!["127.0.0.1:0".parse().unwrap()],
            vec!["1.1.1.1:0".parse().unwrap(), "10.0.0.1:0".parse().unwrap()],
        ]))));
        let resolver = FilteredResolver {
            origin: origin("https://backend.test:8443"),
            policy: client.policy,
            source,
        };
        let addresses: Vec<_> = resolver
            .resolve("backend.test".parse().unwrap())
            .await
            .unwrap()
            .collect();
        assert_eq!(addresses, ["1.1.1.1:8443".parse().unwrap()]);
        assert!(resolver
            .resolve("backend.test".parse().unwrap())
            .await
            .is_err());
        assert!(resolver
            .resolve("backend.test".parse().unwrap())
            .await
            .is_err());
    }

    async fn backend(response: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let size = socket.read(&mut request).await.unwrap();
            request.truncate(size);
            socket.write_all(response).await.unwrap();
            request
        });
        (address, server)
    }

    #[tokio::test]
    async fn actual_connector_enforces_dns_and_literal_policy_without_following_redirects() {
        let (address, server) = backend(b"HTTP/1.1 302 Found\r\nLocation: /owned-redirect-target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        let literal = format!("http://{address}");
        let denied = HttpIntegrationClient::new(&[], &[]).unwrap();
        assert!(denied.request(Method::GET, &literal).is_err());
        let hostname = format!("http://backend.test:{}", address.port());
        let mut client = HttpIntegrationClient::new(std::slice::from_ref(&hostname), &[]).unwrap();
        client.resolver = Arc::new(Answers(Mutex::new(VecDeque::from([vec![address]]))));
        let response = client
            .request(Method::GET, &hostname)
            .unwrap()
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 302);
        let request = server.await.unwrap();
        assert!(String::from_utf8_lossy(&request)
            .contains(&format!("host: backend.test:{}", address.port())));
        let mut denied = HttpIntegrationClient::new(&[], &[]).unwrap();
        denied.resolver = Arc::new(Answers(Mutex::new(VecDeque::from([vec![address]]))));
        let error = denied
            .request(Method::GET, &hostname)
            .unwrap()
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .unwrap_err();
        assert_eq!(
            HttpIntegrationError::from_request(&error),
            HttpIntegrationError::DestinationDenied
        );
    }

    #[tokio::test]
    async fn failed_dns_resolution_is_preserved_as_a_configuration_failure() {
        struct FailedDns;
        impl Resolve for FailedDns {
            fn resolve(&self, _: Name) -> Resolving {
                Box::pin(async { Err(std::io::Error::from(std::io::ErrorKind::NotFound).into()) })
            }
        }
        let mut client = HttpIntegrationClient::new(&[], &[]).unwrap();
        client.resolver = Arc::new(FailedDns);
        let error = client
            .request(Method::GET, "https://owned-dns-failure.test")
            .unwrap()
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .unwrap_err();
        let failure = HttpIntegrationError::from_request(&error);
        assert_eq!(failure, HttpIntegrationError::DnsResolution);
        assert_eq!(
            crate::error::InvokeFailure::Http(failure)
                .gateway_failure()
                .status(),
            500
        );
    }

    #[tokio::test]
    async fn untrusted_tls_certificate_is_a_configuration_failure_without_sending_http() {
        use axum::{routing::get, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let identity = Arc::new(
            locallycloud_core::tls::GuestCallbackTls::new()
                .await
                .unwrap(),
        );
        let server = identity.clone().spawn(
            listener,
            Router::new().route(
                "/",
                get(move || {
                    let observed = observed.clone();
                    async move {
                        observed.fetch_add(1, Ordering::SeqCst);
                        "owned TLS backend"
                    }
                }),
            ),
            false,
        );
        let trusted = Client::builder()
            .no_proxy()
            .add_root_certificate(
                reqwest::Certificate::from_pem(identity.ca_pem().as_bytes()).unwrap(),
            )
            .build()
            .unwrap();
        assert_eq!(
            trusted
                .get(&origin)
                .timeout(Duration::from_secs(5))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        let client = HttpIntegrationClient::new(std::slice::from_ref(&origin), &[]).unwrap();
        let error = client
            .request(Method::GET, &origin)
            .unwrap()
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .unwrap_err();
        let failure = HttpIntegrationError::from_request(&error);
        assert_eq!(failure, HttpIntegrationError::TlsConfiguration);
        assert_eq!(
            crate::error::InvokeFailure::Http(failure)
                .gateway_failure()
                .status(),
            500
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[test]
    fn client_cache_is_bounded_under_many_origins() {
        let config = crate::ApiGatewayConfig {
            http_client_cache_capacity: 2,
            http_max_idle_per_host: 3,
            http_idle_timeout_secs: 4,
            ..Default::default()
        };
        let client = HttpIntegrationClient::with_config(&config, &[]).unwrap();
        assert_eq!(client.max_idle_per_host, 3);
        assert_eq!(client.idle_timeout, Duration::from_secs(4));
        for index in 0..config.http_client_cache_capacity + 4 {
            let _request = client
                .request(Method::GET, &format!("https://backend-{index}.example"))
                .unwrap();
        }
        assert_eq!(
            client.clients.lock().unwrap().len(),
            config.http_client_cache_capacity
        );
    }
}
