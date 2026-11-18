//! An ephemeral trust domain for HTTPS callbacks inside an isolated compute guest.
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
};

use axum::{extract::ConnectInfo, Extension, Router};
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::OnceCell,
    task::JoinHandle,
};
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

use super::{DomainListener, TlsIdentity, TlsIdentityResolver};

/// The CA is installed only in owned guests. Private keys never leave the host process.
/// Construct lazily and share across execution environments belonging to one executor.
pub struct GuestCallbackTls {
    ca_pem: String,
    hostname: String,
    identity: TlsIdentity,
    ca: Arc<CaMaterial>,
    regions: Mutex<BTreeMap<String, Arc<OnceCell<Arc<ExecuteApiTls>>>>>,
}

// Local bounded certificate cache, not an AWS region quota. Existing resolvers remain
// usable after their cache entry is evicted.
const MAX_CACHED_REGIONS: usize = 64;

struct CaMaterial {
    params: CertificateParams,
    private_key: Zeroizing<Vec<u8>>,
}

struct ExecuteApiTls {
    region: String,
    identity: TlsIdentity,
}

fn certificate_error(_: rcgen::Error) -> io::Error {
    io::Error::other("guest callback TLS certificate generation failed")
}

fn leaf_identity(names: Vec<String>, ca: &CaMaterial) -> io::Result<TlsIdentity> {
    let ca_key = KeyPair::try_from(ca.private_key.as_slice()).map_err(certificate_error)?;
    let leaf_key = KeyPair::generate().map_err(certificate_error)?;
    let mut params = CertificateParams::new(names).map_err(certificate_error)?;
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.not_before = ca.params.not_before;
    params.not_after = ca.params.not_after;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    let leaf = params
        .signed_by(&leaf_key, &Issuer::from_params(&ca.params, &ca_key))
        .map_err(certificate_error)?;
    let private_key: PrivateKeyDer<'static> = leaf_key.into();
    let identity = TlsIdentity {
        certificate_der: leaf.der().to_vec(),
        private_key_der: Zeroizing::new(private_key.secret_der().to_vec()),
    };
    super::tls_config(&identity)?;
    Ok(identity)
}

fn valid_region(region: &str) -> bool {
    region.len() <= 32
        && region.rsplit_once('-').is_some_and(|(area, number)| {
            (1..=2).contains(&number.len())
                && !number.starts_with('0')
                && number.bytes().all(|byte| byte.is_ascii_digit())
                && (2..=4).contains(&area.split('-').count())
                && area.split('-').all(|label| {
                    (1..=12).contains(&label.len())
                        && label.bytes().all(|byte| byte.is_ascii_lowercase())
                })
        })
}

fn valid_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[async_trait::async_trait]
impl TlsIdentityResolver for ExecuteApiTls {
    async fn resolve(&self, server_name: &str) -> Option<TlsIdentity> {
        let server_name = server_name.to_ascii_lowercase();
        let ordinary = format!(".execute-api.{}.amazonaws.com", self.region);
        let endpoint = format!(".execute-api.{}.vpce.amazonaws.com", self.region);
        let allowed = server_name.strip_suffix(&ordinary).is_some_and(valid_label)
            || server_name
                .strip_suffix(&endpoint)
                .is_some_and(|label| label.starts_with("vpce-") && valid_label(label));
        allowed.then(|| TlsIdentity {
            certificate_der: self.identity.certificate_der.clone(),
            private_key_der: self.identity.private_key_der.clone(),
        })
    }
}

impl GuestCallbackTls {
    /// Generate certificates off the async worker threads, without a host openssl dependency.
    pub async fn new() -> io::Result<Self> {
        Self::for_hostname("localhost".into()).await
    }

    pub async fn for_hostname(hostname: String) -> io::Result<Self> {
        if hostname.is_empty()
            || hostname.len() > 253
            || !hostname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid guest endpoint hostname",
            ));
        }
        tokio::task::spawn_blocking(move || Self::generate(hostname))
            .await
            .map_err(|_| io::Error::other("guest callback TLS certificate worker failed"))?
    }

    fn generate(hostname: String) -> io::Result<Self> {
        let now = time::OffsetDateTime::now_utc();
        let not_before = now - time::Duration::minutes(5);
        // Long-running desktop sessions must not lose their callback path after a few days.
        // Every executor receives fresh keys; nothing is persisted or trusted by the host.
        let not_after = now + time::Duration::days(3650);
        let ca_key = KeyPair::generate().map_err(certificate_error)?;
        let mut ca_params =
            CertificateParams::new(Vec::<String>::new()).map_err(certificate_error)?;
        ca_params.not_before = not_before;
        ca_params.not_after = not_after;
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "LocalCloud guest callback CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_pem = ca_params
            .self_signed(&ca_key)
            .map_err(certificate_error)?
            .pem();

        let ca_private_key: PrivateKeyDer<'static> = ca_key.into();
        let ca = Arc::new(CaMaterial {
            params: ca_params,
            private_key: Zeroizing::new(ca_private_key.secret_der().to_vec()),
        });
        let mut names = vec!["localhost".into(), "127.0.0.1".into(), hostname.clone()];
        if hostname.parse::<std::net::IpAddr>().is_err() {
            names.extend([format!("*.{hostname}"), format!("sync-{hostname}")]);
        }
        let identity = leaf_identity(names, &ca)?;
        Ok(Self {
            ca_pem,
            hostname,
            identity,
            ca,
            regions: Mutex::new(BTreeMap::new()),
        })
    }

    /// Resolve only the execute-api DNS names modeled for this region, using the
    /// same guest CA. No key material is written to disk or exposed to the guest.
    pub async fn for_execute_api_region(
        &self,
        region: &str,
    ) -> io::Result<Arc<dyn TlsIdentityResolver>> {
        if !valid_region(region) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid execute-api TLS region",
            ));
        }
        let cell = {
            let mut cache = self
                .regions
                .lock()
                .map_err(|_| io::Error::other("guest TLS region cache unavailable"))?;
            if let Some(cell) = cache.get(region) {
                cell.clone()
            } else {
                if cache.len() >= MAX_CACHED_REGIONS {
                    let ready = cache
                        .iter()
                        .find(|(_, cell)| cell.initialized())
                        .map(|(name, _)| name.clone());
                    let Some(ready) = ready else {
                        return Err(io::Error::other(
                            "guest TLS region issuance capacity reached",
                        ));
                    };
                    cache.remove(&ready);
                }
                let cell = Arc::new(OnceCell::new());
                cache.insert(region.to_owned(), cell.clone());
                cell
            }
        };
        let ca = self.ca.clone();
        let region = region.to_owned();
        let identity = cell
            .get_or_try_init(|| async move {
                tokio::task::spawn_blocking(move || {
                    let identity = leaf_identity(
                        vec![
                            format!("*.execute-api.{region}.amazonaws.com"),
                            format!("*.execute-api.{region}.vpce.amazonaws.com"),
                        ],
                        &ca,
                    )?;
                    Ok::<_, io::Error>(Arc::new(ExecuteApiTls { region, identity }))
                })
                .await
                .map_err(|_| io::Error::other("guest TLS region certificate worker failed"))?
            })
            .await?;
        Ok(identity.clone())
    }

    /// Serve one already accepted, host-owned socket with TLS only. The caller owns
    /// connection admission, lifetime and any private ingress extensions on the router.
    /// Transport attestation comes only from the negotiated socket, never HTTP headers.
    pub async fn serve_connection(
        stream: TcpStream,
        app: Router,
        resolver: Arc<dyn TlsIdentityResolver>,
    ) -> io::Result<()> {
        let peer = stream.peer_addr()?;
        let (io, connection) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            super::negotiate(stream, peer, Some(resolver), false),
        )
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "private TLS handshake timed out")
        })??;
        let app = app
            .layer(Extension(ConnectInfo(connection)))
            .layer(axum::middleware::from_fn(
                |mut request: axum::extract::Request, next: axum::middleware::Next| async move {
                    use axum::response::IntoResponse;
                    if let Err(status) = super::normalize_http2_authority(&mut request) {
                        return status.into_response();
                    }
                    next.run(request).await
                },
            ));
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection_with_upgrades(TokioIo::new(io), TowerToHyperService::new(app))
            .await
            .map_err(io::Error::other)
    }

    /// Append to the guest's existing CA bundle; never replace its public trust anchors.
    /// Node may alternatively read this public CA through NODE_EXTRA_CA_CERTS.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// The caller binds port443 inside the guest namespace and owns the task's lifecycle.
    /// Its router retains normal dispatch, authorization, body limits and VPC policy.
    pub fn spawn(
        self: Arc<Self>,
        listener: TcpListener,
        app: Router,
        allow_http: bool,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let resolver: Arc<dyn TlsIdentityResolver> = self;
            if let Err(error) = axum::serve(
                DomainListener::new(listener, Some(resolver)).with_plain_http(allow_http),
                app.into_make_service_with_connect_info::<super::ConnectionInfo>(),
            )
            .await
            {
                tracing::warn!(%error, "guest callback TLS listener stopped");
            }
        })
    }
}

#[async_trait::async_trait]
impl TlsIdentityResolver for GuestCallbackTls {
    async fn resolve(&self, server_name: &str) -> Option<TlsIdentity> {
        (super::endpoint_hostname_matches(server_name, &self.hostname)
            || matches!(server_name, "localhost" | "127.0.0.1"))
        .then(|| TlsIdentity {
            certificate_der: self.identity.certificate_der.clone(),
            private_key_der: self.identity.private_key_der.clone(),
        })
    }
    async fn resolve_without_sni(&self) -> Option<TlsIdentity> {
        self.resolve("localhost").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::time::Duration;

    #[tokio::test]
    async fn endpoint_wildcard_and_prefix_require_its_guest_ca() {
        let tls = Arc::new(
            GuestCallbackTls::for_hostname("aws.localhost".into())
                .await
                .unwrap(),
        );
        assert!(tls.resolve("s3.amazonaws.com").await.is_none());
        assert!(tls.resolve("aws.localhost").await.is_some());
        assert!(tls.resolve("bucket.aws.localhost").await.is_some());
        assert!(tls.resolve("nested.bucket.aws.localhost").await.is_none());
        assert!(!tls.ca_pem().contains("PRIVATE KEY"));
        // DER OID 2.5.29.35 identifies the issuer key for strict X.509 clients.
        assert!(tls
            .identity
            .certificate_der
            .windows(5)
            .any(|oid| oid == [0x06, 0x03, 0x55, 0x1d, 0x23]));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tls.clone().spawn(
            listener,
            Router::new().route("/", get(|| async { "callback" })),
            false,
        );
        let root = reqwest::Certificate::from_pem(tls.ca_pem().as_bytes()).unwrap();
        let trusted = reqwest::Client::builder()
            .no_proxy()
            .resolve(
                "aws.localhost",
                (std::net::Ipv4Addr::LOCALHOST, port).into(),
            )
            .resolve(
                "bucket.aws.localhost",
                (std::net::Ipv4Addr::LOCALHOST, port).into(),
            )
            .resolve(
                "sync-aws.localhost",
                (std::net::Ipv4Addr::LOCALHOST, port).into(),
            )
            .resolve(
                "s3.amazonaws.com",
                (std::net::Ipv4Addr::LOCALHOST, port).into(),
            )
            .add_root_certificate(root)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("https://aws.localhost:{port}/");
        assert_eq!(
            trusted
                .get(format!("https://sync-aws.localhost:{port}/"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            trusted
                .get(&url)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "callback"
        );
        assert_eq!(
            trusted
                .get(format!("https://bucket.aws.localhost:{port}/"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        let untrusted = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        assert!(untrusted.get(&url).send().await.is_err());
        assert_eq!(
            trusted
                .get(format!("https://127.0.0.1:{port}/"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert!(trusted
            .get(format!("https://s3.amazonaws.com:{port}/"))
            .send()
            .await
            .is_err());
        let other = GuestCallbackTls::new().await.unwrap();
        let unrelated = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(
                reqwest::Certificate::from_pem(other.ca_pem().as_bytes()).unwrap(),
            )
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        assert!(unrelated.get(&url).send().await.is_err());
        server.abort();
        let _ = server.await;
    }
}

#[cfg(test)]
mod execute_api_tests {
    use super::*;
    use axum::routing::get;
    use std::{net::Ipv4Addr, time::Duration};

    #[tokio::test]
    async fn regional_resolvers_share_guest_ca_and_restrict_sni_to_their_scope() {
        let tls = GuestCallbackTls::for_hostname("aws.localhost".into())
            .await
            .unwrap();
        let resolver = tls.for_execute_api_region("us-east-1").await.unwrap();
        for name in [
            "abc123.execute-api.us-east-1.amazonaws.com",
            "abc123-vpce-123.execute-api.us-east-1.amazonaws.com",
            "vpce-123-abc.execute-api.us-east-1.vpce.amazonaws.com",
            "ABC123.EXECUTE-API.US-EAST-1.AMAZONAWS.COM",
        ] {
            assert!(resolver.resolve(name).await.is_some(), "{name}");
        }
        for name in [
            "localhost",
            "127.0.0.1",
            "aws.localhost",
            "s3.amazonaws.com",
            "abc.execute-api.us-west-2.amazonaws.com",
            "nested.abc.execute-api.us-east-1.amazonaws.com",
            "execute-api.us-east-1.amazonaws.com",
            "abc.execute-api.us-east-1.vpce.amazonaws.com",
            "vpce-.execute-api.us-east-1.vpce.amazonaws.com",
            "abc.execute-api.us-east-1.amazonaws.com.attacker.invalid",
        ] {
            assert!(resolver.resolve(name).await.is_none(), "{name}");
        }
        assert!(resolver.resolve_without_sni().await.is_none());
        assert!(!tls.ca_pem().contains("PRIVATE KEY"));

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/",
                get(
                    |ConnectInfo(connection): ConnectInfo<super::super::ConnectionInfo>,
                     Extension(source): Extension<&'static str>| async move {
                        format!(
                            "{}/{}/{}",
                            connection.secure_transport,
                            connection.server_name.unwrap_or_default(),
                            source,
                        )
                    },
                ),
            )
            .layer(Extension("owned-source-eni"));
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let app = app.clone();
                        let resolver = resolver.clone();
                        connections.spawn(async move {
                            GuestCallbackTls::serve_connection(stream, app, resolver).await
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        let api = "abc123.execute-api.us-east-1.amazonaws.com";
        let vpce = "vpce-123-abc.execute-api.us-east-1.vpce.amazonaws.com";
        let outside = "abc.execute-api.us-west-2.amazonaws.com";
        let client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_pem(tls.ca_pem().as_bytes()).unwrap())
            .resolve(api, address)
            .resolve(vpce, address)
            .resolve(outside, address)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        for name in [api, vpce] {
            let response = client
                .get(format!("https://{name}:{}/", address.port()))
                .header("x-locallycloud-verified-secure-transport", "false")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(
                response.text().await.unwrap(),
                format!("true/{name}/owned-source-eni")
            );
        }
        assert!(client
            .get(format!("https://{outside}:{}/", address.port()))
            .send()
            .await
            .is_err());
        let untrusted = reqwest::Client::builder()
            .no_proxy()
            .resolve(api, address)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        assert!(untrusted
            .get(format!("https://{api}:{}/", address.port()))
            .send()
            .await
            .is_err());
        assert!(client
            .get(format!("http://{api}:{}/", address.port()))
            .send()
            .await
            .is_err());
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn invalid_regions_fail_before_issuing_and_concurrent_requests_share_one_leaf() {
        let tls = GuestCallbackTls::new().await.unwrap();
        for region in [
            "",
            "us-east-0",
            "us-east",
            "US-east-1",
            "us-east-1.attacker.invalid",
            "us-east-1/",
            "us--east-1",
            "us-éast-1",
            "us-east-100",
        ] {
            assert!(
                tls.for_execute_api_region(region).await.is_err(),
                "{region}"
            );
        }
        assert!(tls.regions.lock().unwrap().is_empty());
        let (first, second, third) = tokio::join!(
            tls.for_execute_api_region("us-gov-west-1"),
            tls.for_execute_api_region("us-gov-west-1"),
            tls.for_execute_api_region("us-gov-west-1"),
        );
        let first = first.unwrap();
        assert!(Arc::ptr_eq(&first, &second.unwrap()));
        assert!(Arc::ptr_eq(&first, &third.unwrap()));
        assert_eq!(tls.regions.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn bounded_region_cache_eviction_does_not_invalidate_retained_resolver() {
        let tls = GuestCallbackTls::new().await.unwrap();
        let first = tls.for_execute_api_region("us-test-1").await.unwrap();
        for index in 2..=MAX_CACHED_REGIONS + 1 {
            tls.for_execute_api_region(&format!("us-test-{index}"))
                .await
                .unwrap();
        }
        assert_eq!(tls.regions.lock().unwrap().len(), MAX_CACHED_REGIONS);
        assert!(first
            .resolve("api.execute-api.us-test-1.amazonaws.com")
            .await
            .is_some());
    }
}
