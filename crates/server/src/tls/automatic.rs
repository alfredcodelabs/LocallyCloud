//! Persistent local trust anchor; only public CA material is exported to the filesystem.
use super::{io, tls_config, TlsIdentity, Zeroizing};
use base64::Engine;
use locallycloud_state::{StateCipher, StateDb};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use time::{Duration, OffsetDateTime};
use tokio_rustls::rustls::pki_types::PrivateKeyDer;

const MAX_CERTIFICATE: usize = 32_768;
const MAX_KEY_ENVELOPE: usize = 16_384;
const CA_NAME: &str = "LocalCloud development CA";

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "automatic TLS CA state is invalid or cannot be decrypted with this master key",
    )
}

fn ca_parameters() -> io::Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|_| invalid())?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, CA_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.key_identifier_method = KeyIdMethod::Sha256;
    Ok(params)
}

fn binding(certificate: &[u8], expires: i64) -> String {
    format!(
        "{}:{expires}",
        base64::engine::general_purpose::STANDARD.encode(certificate)
    )
}

pub(super) fn identity(
    state: &StateDb,
    cipher: &StateCipher,
) -> io::Result<(TlsIdentity, PathBuf)> {
    let mut connection = state.connection().map_err(|_| invalid())?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS control_plane_ca_v1 (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        certificate BLOB NOT NULL, private_key BLOB NOT NULL, expires INTEGER NOT NULL
    );",
        )
        .map_err(|_| invalid())?;
    let transaction = connection.transaction().map_err(|_| invalid())?;
    let saved = {
        let mut statement = transaction.prepare("SELECT certificate, private_key, expires FROM control_plane_ca_v1 WHERE singleton = 1").map_err(|_| invalid())?;
        let mut rows = statement.query([]).map_err(|_| invalid())?;
        rows.next()
            .map_err(|_| invalid())?
            .map(|row| {
                Ok::<_, io::Error>((
                    row.get::<_, Vec<u8>>(0).map_err(|_| invalid())?,
                    row.get::<_, Vec<u8>>(1).map_err(|_| invalid())?,
                    row.get::<_, i64>(2).map_err(|_| invalid())?,
                ))
            })
            .transpose()?
    };
    let now = OffsetDateTime::now_utc();
    let (certificate, ca_key, expires) = match saved {
        Some((certificate, encrypted_key, expires)) => {
            if certificate.is_empty()
                || certificate.len() > MAX_CERTIFICATE
                || encrypted_key.len() > MAX_KEY_ENVELOPE
            {
                return Err(invalid());
            }
            let bound = binding(&certificate, expires);
            let key = cipher
                .open(&["tls", "control-plane-ca-v1", &bound], &encrypted_key)
                .map_err(|_| invalid())?;
            let key = KeyPair::try_from(key.as_slice()).map_err(|_| invalid())?;
            (certificate, key, expires)
        }
        None => {
            let ca_key = KeyPair::generate().map_err(|_| invalid())?;
            let mut params = ca_parameters()?;
            params.not_before = now - Duration::minutes(5);
            params.not_after = now + Duration::days(3650);
            let expires = params.not_after.unix_timestamp();
            let certificate = params
                .self_signed(&ca_key)
                .map_err(|_| invalid())?
                .der()
                .to_vec();
            let key = Zeroizing::new(ca_key.serialize_der());
            let encrypted_key = cipher
                .seal(
                    &[
                        "tls",
                        "control-plane-ca-v1",
                        &binding(&certificate, expires),
                    ],
                    &key,
                )
                .map_err(|_| invalid())?;
            transaction.execute("INSERT INTO control_plane_ca_v1 (singleton, certificate, private_key, expires) VALUES (1, ?1, ?2, ?3)", (&certificate, &encrypted_key, expires)).map_err(|_| invalid())?;
            (certificate, ca_key, expires)
        }
    };
    transaction.commit().map_err(|_| invalid())?;
    let expires = OffsetDateTime::from_unix_timestamp(expires).map_err(|_| invalid())?;
    if expires <= now + Duration::minutes(5) {
        return Err(io::Error::other(
            "automatic TLS CA has expired; configure an explicit TLS certificate",
        ));
    }
    let mut leaf = CertificateParams::new(vec![
        "aws.localhost".into(),
        "*.aws.localhost".into(),
        "sync-aws.localhost".into(),
        "localhost".into(),
        "127.0.0.1".into(),
        "::1".into(),
    ])
    .map_err(|_| invalid())?;
    leaf.distinguished_name = DistinguishedName::new();
    leaf.distinguished_name
        .push(DnType::CommonName, "aws.localhost");
    leaf.not_before = now - Duration::minutes(5);
    leaf.not_after = (now + Duration::days(365)).min(expires);
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.use_authority_key_identifier_extension = true;
    let leaf_key = KeyPair::generate().map_err(|_| invalid())?;
    let ca_params = ca_parameters()?;
    let leaf = leaf
        .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
        .map_err(|_| invalid())?;
    // rcgen owns raw key storage; rustls's PrivateKeyDer zeroizes serialized keys on drop.
    let ca_private: PrivateKeyDer<'static> = ca_key.into();
    drop(ca_private);
    let leaf_private: PrivateKeyDer<'static> = leaf_key.into();
    let identity = TlsIdentity {
        certificate_der: leaf.der().to_vec(),
        private_key_der: Zeroizing::new(leaf_private.secret_der().to_vec()),
    };
    tls_config(&identity)?;
    let mut name = state.path().as_os_str().to_os_string();
    name.push(".ca.pem");
    let path = PathBuf::from(name);
    export_ca(
        &path,
        pem::encode(&pem::Pem::new("CERTIFICATE", certificate)).as_bytes(),
    )?;
    Ok((identity, path))
}

fn export_ca(path: &Path, certificate: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(invalid)?;
    let metadata = fs::symlink_metadata(parent)?;
    // SAFETY: geteuid takes no pointers and has no memory safety preconditions.
    let owner = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TLS CA export requires a user-owned directory that other users cannot modify",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.uid() != owner {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TLS CA export must be a regular file owned by this user",
                ));
            }
            let mut existing = Vec::new();
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?
                .take((MAX_CERTIFICATE + 1) as u64)
                .read_to_end(&mut existing)?;
            if existing == certificate && metadata.permissions().mode() & 0o777 == 0o600 {
                return Ok(());
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let temporary = parent.join(format!(".locallycloud-ca-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(certificate)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{ConnectionInfo, ControlPlaneResolver, DomainListener};
    use std::{os::unix::fs::DirBuilderExt, sync::Arc};

    fn state() -> (StateDb, PathBuf) {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../compatibility-tests/.work")
            .join(format!("automatic-tls-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)
            .unwrap();
        (
            StateDb::open(directory.join("state.sqlite3")).unwrap(),
            directory,
        )
    }

    #[test]
    fn persistent_ca_trusts_restarted_tls_for_endpoint_aliases_and_http_stays_closed() {
        let (state, directory) = state();
        let cipher = StateCipher::with_key(&[19; 32]);
        let (_, path) = identity(&state, &cipher).unwrap();
        let ca = fs::read(&path).unwrap();
        let (restored, restored_path) = identity(&state, &cipher).unwrap();
        // DER OID 2.5.29.35 is required on issuer-signed leaves by strict X.509 clients.
        assert!(restored
            .certificate_der
            .windows(5)
            .any(|oid| oid == [0x06, 0x03, 0x55, 0x1d, 0x23]));
        assert_eq!(path, restored_path);
        assert_eq!(fs::read(&path).unwrap(), ca);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let connection = state.connection().unwrap();
        let encrypted: Vec<u8> = connection
            .query_row("SELECT private_key FROM control_plane_ca_v1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(!encrypted
            .windows(b"PRIVATE KEY".len())
            .any(|window| window == b"PRIVATE KEY"));
        assert!(identity(&state, &StateCipher::with_key(&[20; 32])).is_err());
        assert_eq!(fs::read(&path).unwrap(), ca);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let resolver = Arc::new(ControlPlaneResolver {
                    hostname: "aws.localhost".into(),
                    identity: restored,
                    domains: None,
                });
                let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = tcp.local_addr().unwrap();
                let app = axum::Router::new().route(
                    "/",
                    axum::routing::get(
                        |axum::extract::ConnectInfo(info): axum::extract::ConnectInfo<
                            ConnectionInfo,
                        >| async move {
                            assert!(info.secure_transport);
                            info.server_name.unwrap()
                        },
                    ),
                );
                let server = tokio::spawn(async move {
                    axum::serve(
                        DomainListener::new(tcp, Some(resolver)).with_plain_http(false),
                        app.into_make_service_with_connect_info::<ConnectionInfo>(),
                    )
                    .await
                    .unwrap();
                });
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .resolve("aws.localhost", address)
                    .resolve("bucket.aws.localhost", address)
                    .resolve("sync-aws.localhost", address)
                    .resolve("foreign.invalid", address)
                    .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
                    .timeout(std::time::Duration::from_secs(2))
                    .build()
                    .unwrap();
                for hostname in [
                    "aws.localhost",
                    "bucket.aws.localhost",
                    "sync-aws.localhost",
                ] {
                    assert_eq!(
                        client
                            .get(format!("https://{hostname}:{}/", address.port()))
                            .send()
                            .await
                            .unwrap()
                            .text()
                            .await
                            .unwrap(),
                        hostname
                    );
                }
                assert!(client
                    .get(format!("https://foreign.invalid:{}/", address.port()))
                    .send()
                    .await
                    .is_err());
                assert!(client
                    .get(format!("http://{address}/"))
                    .send()
                    .await
                    .is_err());
                server.abort();
            });
        drop(connection);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn ca_export_rejects_symlinks_and_database_certificate_substitution() {
        let (state, directory) = state();
        let cipher = StateCipher::with_key(&[21; 32]);
        let (_, path) = identity(&state, &cipher).unwrap();
        let original = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let sentinel = directory.join("untouched");
        fs::write(&sentinel, b"untouched").unwrap();
        std::os::unix::fs::symlink(&sentinel, &path).unwrap();
        assert!(identity(&state, &cipher).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"untouched");
        fs::remove_file(&path).unwrap();
        identity(&state, &cipher).unwrap();
        assert_eq!(fs::read(&path).unwrap(), original);
        state
            .connection()
            .unwrap()
            .execute(
                "UPDATE control_plane_ca_v1 SET certificate = ?1",
                [vec![1_u8, 2, 3]],
            )
            .unwrap();
        assert!(identity(&state, &cipher).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::remove_dir_all(directory).unwrap();
    }
}
