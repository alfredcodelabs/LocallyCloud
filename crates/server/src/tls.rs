use locallycloud_core::tls::tls_config;
pub use locallycloud_core::tls::{
    ConnectionInfo, DomainListener, TlsIdentity, TlsIdentityResolver,
};
use std::{io, sync::Arc};
use zeroize::Zeroizing;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;
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
}
