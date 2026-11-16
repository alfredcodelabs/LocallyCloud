//! Lambda-specific trust overlays for shared verified runtime packs.
pub use locallycloud_compute::runtime_pack::{official_image, validate};
pub(crate) use locallycloud_compute::runtime_pack::{RuntimePack, RuntimePacks};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

pub(crate) fn install_guest_trust(
    root: &Path,
    environment: &mut BTreeMap<String, String>,
    ca: &str,
    endpoint: &str,
) -> Result<(), String> {
    let configured = ["AWS_CA_BUNDLE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"]
        .into_iter()
        .filter_map(|key| environment.get(key).map(String::as_str))
        .collect::<Vec<_>>();
    let bundle = locallycloud_compute::runtime_pack::install_guest_ca(root, &configured, ca)
        .map_err(|error| format!("guest trust bundle unavailable: {error}"))?;
    let resolver = root.join("etc/resolv.conf");
    let etc = root.join("etc");
    let metadata = fs::symlink_metadata(&etc).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("guest resolver directory must be a real directory".into());
    }
    match fs::remove_file(&resolver) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    fs::write(
        resolver,
        b"nameserver 169.254.169.253\noptions timeout:2 attempts:1\n",
    )
    .map_err(|error| error.to_string())?;
    for key in ["AWS_CA_BUNDLE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"] {
        environment.insert(key.into(), bundle.into());
    }
    environment.retain(|key, _| !key.starts_with("AWS_ENDPOINT_URL_"));
    environment.insert("AWS_ENDPOINT_URL".into(), endpoint.into());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt};
    #[test]
    fn guest_endpoint_and_resolver_do_not_mutate_shared_pack_files() {
        for symlinked in [false, true] {
            let fixture = Fixture::new();
            let root = fixture.0.join("guest");
            fs::create_dir_all(root.join("etc/pki/tls/certs")).unwrap();
            fs::create_dir_all(root.join("var/runtime")).unwrap();
            fs::write(
                root.join("etc/pki/tls/certs/ca-bundle.crt"),
                b"system trust",
            )
            .unwrap();
            let shared_hosts = fixture.0.join("pack-hosts");
            let original = b"10.0.0.10 private.database.internal\n";
            fs::write(&shared_hosts, original).unwrap();
            if symlinked {
                fs::hard_link(&shared_hosts, root.join("etc/hosts-source")).unwrap();
                symlink("hosts-source", root.join("etc/hosts")).unwrap();
            } else {
                fs::hard_link(&shared_hosts, root.join("etc/hosts")).unwrap();
            }
            let original_inode = fs::metadata(&shared_hosts).unwrap().ino();
            let mut environment = BTreeMap::new();
            environment.insert("AWS_ENDPOINT_URL".into(), "http://127.0.0.1:4566".into());
            environment.insert("AWS_ENDPOINT_URL_S3".into(), "http://other-instance".into());

            install_guest_trust(
                &root,
                &mut environment,
                "guest callback CA",
                "https://aws.localhost:4566",
            )
            .unwrap();
            assert_eq!(
                environment["AWS_ENDPOINT_URL"],
                "https://aws.localhost:4566"
            );
            assert!(!environment.contains_key("AWS_ENDPOINT_URL_S3"));

            assert_eq!(fs::read(&shared_hosts).unwrap(), original);
            assert_eq!(fs::metadata(&shared_hosts).unwrap().ino(), original_inode);
            assert_eq!(fs::read(root.join("etc/hosts")).unwrap(), original);
            assert_eq!(
                fs::read(root.join("etc/resolv.conf")).unwrap(),
                b"nameserver 169.254.169.253\noptions timeout:2 attempts:1\n"
            );
            assert!(!environment.contains_key("AWS_ENDPOINT_URL_SFN"));
        }
    }
    #[test]
    fn replacing_overlay_does_not_modify_shared_runtime() {
        let fixture = Fixture::new();
        let guest = fixture.0.join("guest");
        fs::create_dir_all(guest.join("etc")).unwrap();
        fs::create_dir_all(fixture.0.join("rootfs/etc")).unwrap();
        fs::write(fixture.0.join("rootfs/etc/trust.pem"), b"original").unwrap();
        fs::hard_link(
            fixture.0.join("rootfs/etc/trust.pem"),
            guest.join("etc/trust.pem"),
        )
        .unwrap();
        let overlay = fixture.0.join("overlay");
        fs::create_dir_all(&overlay).unwrap();
        fs::write(overlay.join("trust.pem"), b"overlay").unwrap();
        // The same overlay function is used for function and layer deployment.
        crate::rootfs::copy_pack_overlay(&overlay, &guest.join("etc")).unwrap();
        assert_eq!(fs::read(guest.join("etc/trust.pem")).unwrap(), b"overlay");
        assert_eq!(
            fs::read(fixture.0.join("rootfs/etc/trust.pem")).unwrap(),
            b"original"
        );
    }

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("lambda-pack-overlay-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
