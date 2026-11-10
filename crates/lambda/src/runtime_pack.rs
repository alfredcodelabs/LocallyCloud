//! Lambda-specific trust overlays for shared verified runtime packs.
use locallycloud_compute::runtime_pack::read_guest_file;
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
) -> Result<(), String> {
    const BUNDLE: &str = "/var/runtime/locallycloud-ca-bundle.pem";
    let root = root.to_path_buf();
    let mut configured = Vec::new();
    for key in ["AWS_CA_BUNDLE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"] {
        if let Some(path) = environment.get(key) {
            if !path.starts_with('/') || path.len() > 4096 {
                return Err(format!("{key} must name an absolute path inside the guest"));
            }
            configured.push(path.clone());
        }
    }
    let ca = ca.to_owned();
    (|| -> io::Result<()> {
        let mut bundle = read_guest_file(
            &root,
            Path::new("/etc/pki/tls/certs/ca-bundle.crt"),
            4 * 1024 * 1024,
        )?;
        for path in configured {
            bundle.push(b'\n');
            bundle.extend(read_guest_file(&root, Path::new(&path), 4 * 1024 * 1024)?);
        }
        bundle.push(b'\n');
        bundle.extend(ca.as_bytes());
        let target = root.join(BUNDLE.trim_start_matches('/'));
        match fs::remove_file(&target) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::write(target, bundle)?;
        let hosts = root.join("etc/hosts");
        let mut contents = match read_guest_file(&root, Path::new("/etc/hosts"), 65536) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        // These are the supported isolated guest endpoint hosts. Smithy prefixes
        // StartSyncExecution with `sync-`; it must reach the same private proxy.
        contents.extend(b"\n127.0.0.1 localhost sync-localhost sync-127.0.0.1\n");
        match fs::remove_file(&hosts) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::write(hosts, contents)
    })()
    .map_err(|e| format!("guest trust bundle unavailable: {e}"))?;
    for key in ["AWS_CA_BUNDLE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"] {
        environment.insert(key.into(), BUNDLE.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt};
    #[test]
    fn guest_hosts_include_sdk_prefixes_without_mutating_pack_files() {
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

            install_guest_trust(&root, &mut environment, "guest callback CA").unwrap();

            assert_eq!(fs::read(&shared_hosts).unwrap(), original);
            assert_ne!(
                fs::metadata(root.join("etc/hosts")).unwrap().ino(),
                original_inode
            );
            let hosts = fs::read_to_string(root.join("etc/hosts")).unwrap();
            assert!(hosts.contains("10.0.0.10 private.database.internal"));
            for endpoint in ["127.0.0.1", "localhost"] {
                let prefixed = format!("sync-{endpoint}");
                let resolved = hosts.lines().find_map(|line| {
                    let mut fields = line.split_whitespace();
                    let address = fields.next()?;
                    fields.any(|name| name == prefixed).then_some(address)
                });
                assert_eq!(resolved, Some("127.0.0.1"));
            }
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
