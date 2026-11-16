//! HTTP and SNI TLS on the same unprivileged listener. Certificate material stays in memory.
mod guest_callback;
pub use guest_callback::GuestCallbackTls;

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
    /// Isolated guest listeners can serve an IP certificate without SNI.
    /// Public/domain listeners require SNI unless explicitly overridden.
    async fn resolve_without_sni(&self) -> Option<TlsIdentity> {
        None
    }
}

pub fn tls_config(identity: &TlsIdentity) -> io::Result<ServerConfig> {
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
pub struct ConnectionInfo {
    pub peer: SocketAddr,
    pub server_name: Option<String>,
    pub secure_transport: bool,
}

/// Names covered by one endpoint certificate and its single-label wildcard SAN.
pub fn endpoint_hostname_matches(name: &str, endpoint: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let endpoint = endpoint.to_ascii_lowercase();
    name == endpoint
        || name == format!("sync-{endpoint}")
        || name
            .strip_suffix(&format!(".{endpoint}"))
            .is_some_and(|label| {
                !label.is_empty()
                    && !label.contains('.')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
}

pub struct DomainListener {
    tcp: TcpListener,
    resolver: Option<Arc<dyn TlsIdentityResolver>>,
    allow_plain_http: bool,
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
            allow_plain_http: true,
            pending: JoinSet::new(),
            ready_tx,
            ready_rx,
        }
    }

    pub fn with_plain_http(mut self, allow: bool) -> Self {
        self.allow_plain_http = allow;
        self
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
                            let allow_plain_http = self.allow_plain_http;
                            self.pending.spawn(async move {
                                // Bound both stalled HTTP peers and TLS handshakes without blocking acceptance.
                                if let Ok(Ok(connection)) = tokio::time::timeout(
                                    Duration::from_secs(5), negotiate(tcp, peer, resolver, allow_plain_http),
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
            secure_transport: false,
        })
    }
}

async fn negotiate(
    tcp: TcpStream,
    peer: SocketAddr,
    resolver: Option<Arc<dyn TlsIdentityResolver>>,
    allow_plain_http: bool,
) -> io::Result<(DomainIo, ConnectionInfo)> {
    let mut first = [0];
    if tcp.peek(&mut first).await? == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    if first[0] != 22 {
        if !allow_plain_http {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        return Ok((
            DomainIo::Http(tcp),
            ConnectionInfo {
                peer,
                server_name: None,
                secure_transport: false,
            },
        ));
    }
    let resolver = resolver.ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
    let start =
        LazyConfigAcceptor::new(tokio_rustls::rustls::server::Acceptor::default(), tcp).await?;
    let server_name = start
        .client_hello()
        .server_name()
        .map(str::to_ascii_lowercase);
    let identity = match &server_name {
        Some(name) => resolver.resolve(name).await,
        None => resolver.resolve_without_sni().await,
    }
    .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
    let config = tls_config(&identity)?;
    let stream = start.into_stream(Arc::new(config)).await?;
    Ok((
        DomainIo::Https(Box::new(stream)),
        ConnectionInfo {
            peer,
            server_name,
            secure_transport: true,
        },
    ))
}

pub enum DomainIo {
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
