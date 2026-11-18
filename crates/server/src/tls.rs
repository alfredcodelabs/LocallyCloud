use locallycloud_core::tls::tls_config;
pub use locallycloud_core::tls::{
    normalize_http2_authority, ConnectionInfo, DomainListener, TlsIdentity, TlsIdentityResolver,
};
use std::{io, sync::Arc};
use zeroize::Zeroizing;

#[cfg(feature = "services")]
mod automatic;

/// Loaded once at startup. Other SNI names remain owned by the existing domain resolver.
pub(crate) struct ControlPlaneResolver {
    hostname: String,
    identity: TlsIdentity,
    domains: Option<Arc<dyn TlsIdentityResolver>>,
}

impl ControlPlaneResolver {
    #[cfg(feature = "services")]
    pub async fn automatic(
        state: Arc<locallycloud_state::StateDb>,
        domains: Option<Arc<dyn TlsIdentityResolver>>,
    ) -> io::Result<(Self, std::path::PathBuf)> {
        let (identity, ca_path) = tokio::task::spawn_blocking(move || {
            let cipher = locallycloud_state::StateCipher::from_env()
                .map_err(|_| io::Error::other("automatic TLS requires the state master key"))?;
            automatic::identity(&state, &cipher)
        })
        .await
        .map_err(|_| io::Error::other("automatic TLS initialization worker failed"))??;
        Ok((
            Self {
                hostname: "aws.localhost".into(),
                identity,
                domains,
            },
            ca_path,
        ))
    }

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
        if locallycloud_core::tls::endpoint_hostname_matches(server_name, &self.hostname) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[test]
    fn configured_identity_serves_real_tls_and_explicit_http_compatibility() {
        use std::os::unix::fs::DirBuilderExt;
        let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../compatibility-tests/.work")
            .join(format!("tls-override-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let certificate = directory.join("cert.pem");
        let key = directory.join("key.pem");
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(&certificate, generated.cert.pem()).unwrap();
        std::fs::write(&key, generated.signing_key.serialize_pem()).unwrap();
        let config = crate::config::ControlPlaneTls {
            hostname: "localhost".into(),
            certificate_path: certificate.to_str().unwrap().into(),
            private_key_path: key.to_str().unwrap().into(),
        };
        let trusted = reqwest::Certificate::from_pem(generated.cert.pem().as_bytes()).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let resolver = Arc::new(ControlPlaneResolver::load(&config, None).await.unwrap());
                assert!(resolver.resolve("unrelated.invalid").await.is_none());
                tokio::fs::remove_file(&certificate).await.unwrap();
                tokio::fs::remove_file(&key).await.unwrap();
                let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = tcp.local_addr().unwrap();
                let app = axum::Router::new().route(
                    "/",
                    axum::routing::get(
                        |axum::extract::ConnectInfo(info): axum::extract::ConnectInfo<
                            ConnectionInfo,
                        >| async move {
                            assert!(info.peer.ip().is_loopback());
                            if info.secure_transport {
                                info.server_name.unwrap()
                            } else {
                                "plain-http".into()
                            }
                        },
                    ),
                );
                let server = tokio::spawn(async move {
                    axum::serve(
                        DomainListener::new(tcp, Some(resolver)).with_plain_http(true),
                        app.into_make_service_with_connect_info::<ConnectionInfo>(),
                    )
                    .await
                    .unwrap();
                });
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .resolve("localhost", addr)
                    .resolve("unrelated.invalid", addr)
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
                    .get(format!("https://unrelated.invalid:{}/", addr.port()))
                    .send()
                    .await
                    .is_err());
                assert!(client
                    .get(format!("https://127.0.0.1:{}/", addr.port()))
                    .send()
                    .await
                    .is_err());
                server.abort();
            });
        std::fs::remove_dir_all(directory).unwrap();
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
}
