//! HTTP and SNI TLS on the same unprivileged listener. Certificate material stays in memory.
use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    },
    LazyConfigAcceptor,
};
use zeroize::Zeroizing;

pub struct TlsIdentity {
    pub certificate_der: Vec<u8>,
    pub private_key_der: Zeroizing<Vec<u8>>,
}

#[async_trait::async_trait]
pub trait TlsIdentityResolver: Send + Sync {
    async fn resolve(&self, server_name: &str) -> Option<TlsIdentity>;
}

/// Loaded once at startup. Other SNI names remain owned by the existing domain resolver.
pub(crate) struct ControlPlaneResolver {
    hostname: String,
    identity: TlsIdentity,
    domains: Option<Arc<dyn TlsIdentityResolver>>,
}

impl ControlPlaneResolver {
    pub async fn load(
        config: &crate::config::ControlPlaneTls,
        domains: Option<Arc<dyn TlsIdentityResolver>>,
    ) -> io::Result<Self> {
        use tokio::io::AsyncReadExt;
        async fn bounded(path: &str, max: u64) -> io::Result<Zeroizing<Vec<u8>>> {
            let mut bytes = Zeroizing::new(Vec::new());
            tokio::fs::File::open(path)
                .await?
                .take(max + 1)
                .read_to_end(&mut bytes)
                .await?;
            if bytes.len() as u64 > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS material exceeds size limit",
                ));
            }
            Ok(bytes)
        }
        let cert = bounded(&config.certificate_path, 32768).await?;
        let key = bounded(&config.private_key_path, 16384).await?;
        let mut certs = pem::parse_many(cert.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid certificate PEM"))?;
        let mut keys = pem::parse_many(key.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid private key PEM"))?;
        if certs.len() != 1
            || keys.len() != 1
            || certs[0].tag() != "CERTIFICATE"
            || keys[0].tag() != "PRIVATE KEY"
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS requires one certificate and one PKCS#8 private key",
            ));
        }
        let identity = TlsIdentity {
            certificate_der: certs.remove(0).into_contents(),
            private_key_der: Zeroizing::new(keys.remove(0).into_contents()),
        };
        // Validate the key/certificate pair at startup, before reporting readiness.
        tls_config(&identity)?;
        Ok(Self {
            hostname: config.hostname.clone(),
            identity,
            domains,
        })
    }
}

#[async_trait::async_trait]
impl TlsIdentityResolver for ControlPlaneResolver {
    async fn resolve(&self, server_name: &str) -> Option<TlsIdentity> {
        if server_name == self.hostname {
            return Some(TlsIdentity {
                certificate_der: self.identity.certificate_der.clone(),
                private_key_der: self.identity.private_key_der.clone(),
            });
        }
        match &self.domains {
            Some(domains) => domains.resolve(server_name).await,
            None => None,
        }
    }
}

fn tls_config(identity: &TlsIdentity) -> io::Result<ServerConfig> {
    let provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(identity.certificate_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.private_key_der.to_vec())),
        )
        .map_err(io::Error::other)
}

#[derive(Clone, Debug)]
pub(crate) struct ConnectionInfo {
    pub peer: SocketAddr,
    pub server_name: Option<String>,
}

pub(crate) struct DomainListener {
    tcp: TcpListener,
    resolver: Option<Arc<dyn TlsIdentityResolver>>,
    pending: JoinSet<()>,
    ready_tx: mpsc::Sender<(DomainIo, ConnectionInfo)>,
    ready_rx: mpsc::Receiver<(DomainIo, ConnectionInfo)>,
}

impl DomainListener {
    pub fn new(tcp: TcpListener, resolver: Option<Arc<dyn TlsIdentityResolver>>) -> Self {
        let (ready_tx, ready_rx) = mpsc::channel(64);
        Self {
            tcp,
            resolver,
            pending: JoinSet::new(),
            ready_tx,
            ready_rx,
        }
    }
}

impl Connected<IncomingStream<'_, DomainListener>> for ConnectionInfo {
    fn connect_info(stream: IncomingStream<'_, DomainListener>) -> Self {
        stream.remote_addr().clone()
    }
}

impl Listener for DomainListener {
    type Io = DomainIo;
    type Addr = ConnectionInfo;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            tokio::select! {
                Some(connection) = self.ready_rx.recv() => return connection,
                Some(_) = self.pending.join_next(), if !self.pending.is_empty() => {},
                accepted = self.tcp.accept() => {
                    match accepted {
                        Ok((tcp, peer)) if self.pending.len() < 64 => {
                            let resolver = self.resolver.clone();
                            let tx = self.ready_tx.clone();
                            self.pending.spawn(async move {
                                // Bound both stalled HTTP peers and TLS handshakes without blocking acceptance.
                                if let Ok(Ok(connection)) = tokio::time::timeout(
                                    Duration::from_secs(5), negotiate(tcp, peer, resolver),
                                ).await {
                                    let _ = tx.send(connection).await;
                                }
                            });
                        }
                        Ok(_) => {},
                        Err(error) => {
                            tracing::warn!(%error, "HTTP/TLS listener accept failed");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.tcp.local_addr().map(|peer| ConnectionInfo {
            peer,
            server_name: None,
        })
    }
}

async fn negotiate(
    tcp: TcpStream,
    peer: SocketAddr,
    resolver: Option<Arc<dyn TlsIdentityResolver>>,
) -> io::Result<(DomainIo, ConnectionInfo)> {
    let mut first = [0];
    if tcp.peek(&mut first).await? == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    if first[0] != 22 {
        return Ok((
            DomainIo::Http(tcp),
            ConnectionInfo {
                peer,
                server_name: None,
            },
        ));
    }
    let resolver = resolver.ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
    let start =
        LazyConfigAcceptor::new(tokio_rustls::rustls::server::Acceptor::default(), tcp).await?;
    let server_name = start
        .client_hello()
        .server_name()
        .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?
        .to_ascii_lowercase();
    let identity = resolver
        .resolve(&server_name)
        .await
        .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
    let config = tls_config(&identity)?;
    let stream = start.into_stream(Arc::new(config)).await?;
    Ok((
        DomainIo::Https(Box::new(stream)),
        ConnectionInfo {
            peer,
            server_name: Some(server_name),
        },
    ))
}

pub(crate) enum DomainIo {
    Http(TcpStream),
    Https(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl AsyncRead for DomainIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Http(io) => Pin::new(io).poll_read(cx, buf),
            Self::Https(io) => Pin::new(io.as_mut()).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for DomainIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Http(io) => Pin::new(io).poll_write(cx, buf),
            Self::Https(io) => Pin::new(io.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Http(io) => Pin::new(io).poll_flush(cx),
            Self::Https(io) => Pin::new(io.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Http(io) => Pin::new(io).poll_shutdown(cx),
            Self::Https(io) => Pin::new(io.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn configured_identity_serves_real_tls_and_keeps_http_available() {
        struct TempDirectory(std::path::PathBuf);
        impl Drop for TempDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = TempDirectory(
            std::env::temp_dir().join(format!("locallycloud-tls-{}", uuid::Uuid::new_v4())),
        );
        std::fs::create_dir(&directory.0).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let certificate = directory.0.join("cert.pem");
        let key = directory.0.join("key.pem");
        let generated = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&certificate)
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "openssl certificate generation failed"
        );
        let config = crate::config::ControlPlaneTls {
            hostname: "localhost".into(),
            certificate_path: certificate.to_str().unwrap().into(),
            private_key_path: key.to_str().unwrap().into(),
        };
        let resolver = Arc::new(ControlPlaneResolver::load(&config, None).await.unwrap());
        assert!(resolver.resolve("other.localhost").await.is_none());
        // Files can disappear after startup: connections use the bounded in-memory identity.
        let trusted =
            reqwest::Certificate::from_pem(&std::fs::read(&certificate).unwrap()).unwrap();
        std::fs::remove_file(&certificate).unwrap();
        std::fs::remove_file(&key).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let app =
            axum::Router::new().route(
                "/",
                axum::routing::get(
                    |axum::extract::ConnectInfo(info): axum::extract::ConnectInfo<
                        ConnectionInfo,
                    >| async move {
                        assert!(info.peer.ip().is_loopback());
                        info.server_name.unwrap_or_else(|| "plain-http".into())
                    },
                ),
            );
        let server = tokio::spawn(async move {
            axum::serve(
                DomainListener::new(tcp, Some(resolver)),
                app.into_make_service_with_connect_info::<ConnectionInfo>(),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .resolve("localhost", addr)
            .resolve("other.localhost", addr)
            .add_root_certificate(trusted)
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        assert_eq!(
            client
                .get(format!("https://localhost:{}/", addr.port()))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "localhost"
        );
        assert_eq!(
            client
                .get(format!("http://{addr}/"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "plain-http"
        );
        assert!(client
            .get(format!("https://other.localhost:{}/", addr.port()))
            .send()
            .await
            .is_err());
        server.abort();
    }

    #[tokio::test]
    async fn invalid_tls_files_are_rejected_at_startup() {
        let config = crate::config::ControlPlaneTls {
            hostname: "localhost".into(),
            certificate_path: "/dev/null".into(),
            private_key_path: "/dev/null".into(),
        };
        assert!(ControlPlaneResolver::load(&config, None).await.is_err());
    }

    #[tokio::test]
    async fn stalled_peers_and_unknown_tls_do_not_block_plain_http() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let app =
            axum::Router::new().route(
                "/",
                axum::routing::get(
                    |axum::extract::ConnectInfo(info): axum::extract::ConnectInfo<
                        ConnectionInfo,
                    >| async move {
                        assert!(info.peer.ip().is_loopback());
                        assert!(info.server_name.is_none());
                        "ok"
                    },
                ),
            );
        let server = tokio::spawn(async move {
            axum::serve(
                DomainListener::new(tcp, None),
                app.into_make_service_with_connect_info::<ConnectionInfo>(),
            )
            .await
            .unwrap();
        });
        let idle = TcpStream::connect(addr).await.unwrap();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let tls_error = client
            .get(format!("https://{addr}/"))
            .send()
            .await
            .unwrap_err();
        assert!(!tls_error.is_timeout());
        assert_eq!(
            client
                .get(format!("http://{addr}/"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "ok"
        );
        drop(idle);
        server.abort();
    }
}
