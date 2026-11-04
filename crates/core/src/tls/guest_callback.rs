//! An ephemeral trust domain for HTTPS callbacks inside an isolated compute guest.
use std::{io, sync::Arc};

use axum::Router;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

use super::{DomainListener, TlsIdentity, TlsIdentityResolver};

/// The CA is installed only in owned guests. Private keys never leave the host process.
/// Construct lazily and share across execution environments belonging to one executor.
pub struct GuestCallbackTls {
    ca_pem: String,
    identity: TlsIdentity,
}

impl GuestCallbackTls {
    pub const ENDPOINT: &'static str = "https://localhost";

    /// Generate certificates off the async worker threads, without a host openssl dependency.
    pub async fn new() -> io::Result<Self> {
        tokio::task::spawn_blocking(Self::generate)
            .await
            .map_err(|_| io::Error::other("guest callback TLS certificate worker failed"))?
    }

    fn generate() -> io::Result<Self> {
        fn invalid(error: rcgen::Error) -> io::Error {
            io::Error::other(format!(
                "guest callback TLS certificate generation failed: {error}"
            ))
        }
        let now = time::OffsetDateTime::now_utc();
        let not_before = now - time::Duration::minutes(5);
        // Long-running desktop sessions must not lose their callback path after a few days.
        // Every executor receives fresh keys; nothing is persisted or trusted by the host.
        let not_after = now + time::Duration::days(3650);
        let ca_key = KeyPair::generate().map_err(invalid)?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).map_err(invalid)?;
        ca_params.not_before = not_before;
        ca_params.not_after = not_after;
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "LocalCloud guest callback CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params.self_signed(&ca_key).map_err(invalid)?;

        let leaf_key = KeyPair::generate().map_err(invalid)?;
        let mut leaf_params = CertificateParams::new(vec!["localhost".into()]).map_err(invalid)?;
        leaf_params.not_before = not_before;
        leaf_params.not_after = not_after;
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params
            .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
            .map_err(invalid)?;
        // Move serialized keys into rustls' zeroizing key type before dropping rcgen handles.
        let ca_private_key: PrivateKeyDer<'static> = ca_key.into();
        drop(ca_private_key);
        let private_key: PrivateKeyDer<'static> = leaf_key.into();
        let identity = TlsIdentity {
            certificate_der: leaf.der().to_vec(),
            private_key_der: Zeroizing::new(private_key.secret_der().to_vec()),
        };
        super::tls_config(&identity)?;
        Ok(Self {
            ca_pem: ca.pem(),
            identity,
        })
    }

    /// Append to the guest's existing CA bundle; never replace its public trust anchors.
    /// Node may alternatively read this public CA through NODE_EXTRA_CA_CERTS.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// The caller binds port443 inside the guest namespace and owns the task's lifecycle.
    /// Its router retains normal dispatch, authorization, body limits and VPC policy.
    pub fn spawn(self: Arc<Self>, listener: TcpListener, app: Router) -> JoinHandle<()> {
        tokio::spawn(async move {
            let resolver: Arc<dyn TlsIdentityResolver> = self;
            if let Err(error) =
                axum::serve(DomainListener::new(listener, Some(resolver)), app).await
            {
                tracing::warn!(%error, "guest callback TLS listener stopped");
            }
        })
    }
}

#[async_trait::async_trait]
impl TlsIdentityResolver for GuestCallbackTls {
    async fn resolve(&self, server_name: &str) -> Option<TlsIdentity> {
        (server_name == "localhost").then(|| TlsIdentity {
            certificate_der: self.identity.certificate_der.clone(),
            private_key_der: self.identity.private_key_der.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::time::Duration;

    #[tokio::test]
    async fn only_its_guest_ca_and_localhost_identity_are_trusted() {
        let tls = Arc::new(GuestCallbackTls::new().await.unwrap());
        assert!(tls.resolve("s3.amazonaws.com").await.is_none());
        assert!(tls.resolve("localhost").await.is_some());
        assert!(!tls.ca_pem().contains("PRIVATE KEY"));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tls.clone().spawn(
            listener,
            Router::new().route("/", get(|| async { "callback" })),
        );
        let root = reqwest::Certificate::from_pem(tls.ca_pem().as_bytes()).unwrap();
        let trusted = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(root)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("https://localhost:{port}/");
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
        let untrusted = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        assert!(untrusted.get(&url).send().await.is_err());
        // The certificate does not authorize a different host, including a raw IP address.
        assert!(trusted
            .get(format!("https://127.0.0.1:{port}/"))
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
