//! Explicit installation of optional, digest-pinned native components.
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

pub const USAGE: &str = "Usage: locallycloud component <install|update|list|rollback|remove> [extenddb]\n\nInstall/update: component install|update extenddb --source PATH|HTTPS_URL --sha256 HEX\n\nInstalls the private ExtendDB worker, not the upstream development HTTP server.\nDownloads occur only through install/update. Rollback is offline. Database files are preserved.";
const MAX_BINARY: usize = 128 * 1024 * 1024;
const MISSING_COMPONENT: &str = "ExtendDB worker is not installed; use locallycloud component install extenddb --source PATH --sha256 HEX";

#[derive(Debug, PartialEq, Eq)]
pub enum Options {
    Help,
    List,
    Install { source: String, digest: String },
    Update { source: String, digest: String },
    Rollback,
    Remove,
}

pub fn parse(args: &[String]) -> Result<Options, String> {
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["--help" | "-h"] => Ok(Options::Help),
        ["list"] => Ok(Options::List),
        ["remove", "extenddb"] => Ok(Options::Remove),
        ["rollback", "extenddb"] => Ok(Options::Rollback),
        [action @ ("install" | "update"), "extenddb", "--source", source, "--sha256", digest]
            if valid_digest(digest) && !source.is_empty() =>
        {
            let (source, digest) = ((*source).into(), (*digest).into());
            Ok(match *action {
                "update" => Options::Update { source, digest },
                _ => Options::Install { source, digest },
            })
        }
        _ => Err(USAGE.into()),
    }
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn directory() -> io::Result<PathBuf> {
    let path = std::env::var_os("LOCALLYCLOUD_COMPONENTS_DIR")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(|| {
            locallycloud_state::StateDb::data_dir()
                .map(|p| p.join("components"))
                .map_err(io::Error::other)
        })?;
    if !path.is_absolute() {
        return Err(io::Error::other(
            "LOCALLYCLOUD_COMPONENTS_DIR must be absolute",
        ));
    }
    Ok(path)
}

pub fn private_directory(path: &Path) -> io::Result<()> {
    locallycloud_state::StateDb::private_dir(path).map_err(io::Error::other)
}

#[derive(Deserialize, Serialize)]
struct Manifest {
    protocol: u32,
    sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_sha256: Option<String>,
}

fn manifest(root: &Path) -> io::Result<Manifest> {
    use std::io::Read;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join("extenddb/active.json"))?;
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(io::Error::other("invalid ExtendDB component manifest size"));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if manifest.protocol != 1
        || !valid_digest(&manifest.sha256)
        || manifest
            .previous_sha256
            .as_deref()
            .is_some_and(|v| !valid_digest(v))
    {
        return Err(io::Error::other("invalid ExtendDB component manifest"));
    }
    Ok(manifest)
}

fn version_path(root: &Path, digest: &str) -> PathBuf {
    root.join("extenddb/versions").join(digest).join("worker")
}

pub fn active(root: &Path) -> io::Result<(PathBuf, String)> {
    let manifest = manifest(root).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::other(MISSING_COMPONENT)
        } else {
            error
        }
    })?;
    Ok((version_path(root, &manifest.sha256), manifest.sha256))
}

fn installation_lock(root: &Path) -> io::Result<std::fs::File> {
    private_directory(root)?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(".extenddb-install.lock"))?;
    lock.try_lock()
        .map_err(|_| io::Error::other("another ExtendDB component operation is running"))?;
    Ok(lock)
}

fn usage_lock(root: &Path, exclusive: bool) -> io::Result<std::fs::File> {
    let lease = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(".extenddb-usage.lock"))?;
    if exclusive {
        lease.try_lock().map_err(|_| {
            io::Error::other(
                "ExtendDB is in use; stop workers before changing or removing its version",
            )
        })?;
    } else {
        lease
            .try_lock_shared()
            .map_err(|_| io::Error::other("ExtendDB component is being changed or removed"))?;
    }
    Ok(lease)
}

pub fn verified(root: &Path) -> io::Result<(PathBuf, std::fs::File, std::fs::File)> {
    let lease = usage_lock(root, false).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::other(MISSING_COMPONENT)
        } else {
            error
        }
    })?;
    let (path, expected) = active(root)?;
    let file = verify_version(root, &expected)?;
    Ok((path, file, lease))
}

fn verify_version(root: &Path, expected: &str) -> io::Result<std::fs::File> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(version_path(root, expected))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > MAX_BINARY as u64
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::other("unsafe ExtendDB worker file"));
    }
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest)?;
    if format!("{:x}", digest.finalize()) != expected {
        return Err(io::Error::other(
            "ExtendDB worker checksum mismatch; reinstall component",
        ));
    }
    Ok(file)
}

pub async fn execute(options: &Options) -> io::Result<()> {
    if *options == Options::Help {
        println!("{USAGE}");
        return Ok(());
    }
    let root = directory()?;
    match options {
        Options::Help => unreachable!(),
        Options::List => {
            let result = tokio::task::spawn_blocking(move || match manifest(&root) {
                Ok(manifest) => Ok(json!({"extenddb": {
                    "path": version_path(&root, &manifest.sha256),
                    "sha256": manifest.sha256,
                    "previousSha256": manifest.previous_sha256,
                }})),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    Ok(json!({"extenddb": null}))
                }
                Err(error) => Err(error),
            })
            .await
            .map_err(io::Error::other)??;
            println!("{result}");
        }
        Options::Remove => {
            tokio::task::spawn_blocking(move || remove(&root))
                .await
                .map_err(io::Error::other)??;
            println!("ExtendDB removed; database files preserved");
        }
        Options::Rollback => {
            let digest = tokio::task::spawn_blocking(move || rollback(&root))
                .await
                .map_err(io::Error::other)??;
            println!("{}", json!({"operation":"rollback", "sha256":digest}));
        }
        Options::Install { source, digest } | Options::Update { source, digest } => {
            let update = matches!(options, Options::Update { .. });
            if update {
                let root = root.clone();
                tokio::task::spawn_blocking(move || manifest(&root))
                    .await
                    .map_err(io::Error::other)??;
            }
            let bytes = if source.starts_with("https://") {
                let client = reqwest::Client::builder()
                    .https_only(true)
                    .redirect(reqwest::redirect::Policy::limited(5))
                    .timeout(std::time::Duration::from_secs(180))
                    .build()
                    .map_err(io::Error::other)?;
                let mut response = client
                    .get(source)
                    .send()
                    .await
                    .map_err(|error| io::Error::other(error.without_url()))?
                    .error_for_status()
                    .map_err(|error| io::Error::other(error.without_url()))?;
                let mut bytes = Vec::new();
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|error| io::Error::other(error.without_url()))?
                {
                    if bytes.len().saturating_add(chunk.len()) > MAX_BINARY {
                        return Err(io::Error::other("component exceeds 128 MiB"));
                    }
                    bytes.extend_from_slice(&chunk);
                }
                bytes
            } else {
                let file = tokio::fs::File::open(source).await?;
                let mut bytes = Vec::new();
                use tokio::io::AsyncReadExt;
                file.take(MAX_BINARY as u64 + 1)
                    .read_to_end(&mut bytes)
                    .await?;
                bytes
            };
            if bytes.len() > MAX_BINARY
                || !bytes.starts_with(b"\x7fELF")
                || format!("{:x}", Sha256::digest(&bytes)) != *digest
            {
                return Err(io::Error::other(
                    "component is not an ELF executable with the expected SHA-256",
                ));
            }
            let digest = digest.clone();
            tokio::task::spawn_blocking(move || install(&root, &digest, &bytes, update))
                .await
                .map_err(io::Error::other)??;
            println!("ExtendDB worker installed");
        }
    }
    Ok(())
}

fn install(root: &Path, digest: &str, bytes: &[u8], update: bool) -> io::Result<()> {
    let _installation = installation_lock(root)?;
    let prior = match manifest(root) {
        Ok(value) => Some(value),
        Err(error) if !update && error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let component = root.join("extenddb");
    private_directory(&component)?;
    let changes_version = prior.as_ref().is_some_and(|m| m.sha256 != digest);
    let _usage = usage_lock(root, changes_version)?;
    let version = component.join("versions").join(digest);
    private_directory(&version)?;
    let staging_worker = version.join(format!("worker-{}", uuid::Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&staging_worker)?;
    use std::io::Write;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(staging_worker, version.join("worker"))?;
    std::fs::File::open(&version)?.sync_all()?;
    let previous_sha256 = match prior {
        Some(prior) if prior.sha256 != digest => Some(prior.sha256),
        Some(prior) => prior.previous_sha256,
        None => None,
    };
    activate(
        root,
        &Manifest {
            protocol: 1,
            sha256: digest.into(),
            previous_sha256,
        },
    )
}

fn activate(root: &Path, value: &Manifest) -> io::Result<()> {
    let component = root.join("extenddb");
    let staging = component.join(format!("active-{}.json", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut manifest = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staging)?;
        serde_json::to_writer(&mut manifest, value).map_err(io::Error::other)?;
        manifest.sync_all()?;
        std::fs::rename(&staging, component.join("active.json"))?;
        std::fs::File::open(&component)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(staging);
    }
    result
}

fn rollback(root: &Path) -> io::Result<String> {
    let _installation = installation_lock(root)?;
    let _usage = usage_lock(root, true)?;
    let prior = manifest(root)?;
    let digest = prior.previous_sha256.ok_or_else(|| {
        io::Error::other("no previous ExtendDB version is available for rollback")
    })?;
    let _verified = verify_version(root, &digest)?;
    activate(
        root,
        &Manifest {
            protocol: 1,
            sha256: digest.clone(),
            previous_sha256: Some(prior.sha256),
        },
    )?;
    Ok(digest)
}

fn remove(root: &Path) -> io::Result<()> {
    let _installation = installation_lock(root)?;
    let component = root.join("extenddb");
    if !component.exists() {
        return Ok(());
    }
    private_directory(&component)?;
    let _usage = usage_lock(root, true)?;
    std::fs::remove_dir_all(component)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn install_requires_an_explicit_source_and_digest() {
        for args in [
            vec!["install", "extenddb"],
            vec![
                "install",
                "extenddb",
                "--source",
                "x",
                "--sha256",
                "../invalid",
            ],
        ] {
            assert!(parse(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
        }
        assert_eq!(parse(&["list".into()]).unwrap(), Options::List);
    }

    #[test]
    fn install_is_atomic_repeatable_and_repairs_corruption() {
        let root = std::env::temp_dir().join(format!("component-install-{}", uuid::Uuid::new_v4()));
        let bytes = b"\x7fELFcomponent fixture";
        let digest = format!("{:x}", Sha256::digest(bytes));
        install(&root, &digest, bytes, false).unwrap();
        let (path, original, lease) = verified(&root).unwrap();
        assert!(remove(&root).is_err());
        install(&root, &digest, bytes, false).unwrap();
        // Atomic replacement preserves the already-open, verified executable inode.
        assert_eq!(original.metadata().unwrap().len(), bytes.len() as u64);
        std::fs::write(&path, b"corrupted").unwrap();
        assert!(verified(&root).is_err());
        install(&root, &digest, bytes, false).unwrap();
        assert!(verified(&root).is_ok());
        drop(lease);
        remove(&root).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn update_and_rollback_keep_a_verified_previous_version() {
        let root = std::env::temp_dir().join(format!("component-history-{}", uuid::Uuid::new_v4()));
        let old = b"\x7fELFold";
        let new = b"\x7fELFnew";
        let old_digest = format!("{:x}", Sha256::digest(old));
        let new_digest = format!("{:x}", Sha256::digest(new));
        assert!(install(&root, &new_digest, new, true).is_err());
        install(&root, &old_digest, old, false).unwrap();
        assert!(rollback(&root).is_err());
        install(&root, &new_digest, new, true).unwrap();
        install(&root, &new_digest, new, true).unwrap();
        assert_eq!(
            manifest(&root).unwrap().previous_sha256.as_deref(),
            Some(old_digest.as_str())
        );
        assert_eq!(rollback(&root).unwrap(), old_digest);
        assert_eq!(active(&root).unwrap().1, old_digest);
        assert_eq!(rollback(&root).unwrap(), new_digest);
        let (path, file, lease) = verified(&root).unwrap();
        assert_eq!(path, version_path(&root, &new_digest));
        drop((file, lease));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn changing_version_is_blocked_while_a_worker_holds_its_lease() {
        let root = std::env::temp_dir().join(format!("component-lease-{}", uuid::Uuid::new_v4()));
        let old = b"\x7fELFold";
        let new = b"\x7fELFnew";
        let old_digest = format!("{:x}", Sha256::digest(old));
        let new_digest = format!("{:x}", Sha256::digest(new));
        install(&root, &old_digest, old, false).unwrap();
        let (_, file, lease) = verified(&root).unwrap();
        assert!(install(&root, &new_digest, new, true).is_err());
        assert_eq!(active(&root).unwrap().1, old_digest);
        drop((file, lease));
        install(&root, &new_digest, new, true).unwrap();
        let (_, file, lease) = verified(&root).unwrap();
        assert!(rollback(&root).is_err());
        assert!(remove(&root).is_err());
        assert_eq!(active(&root).unwrap().1, new_digest);
        drop((file, lease));
        assert_eq!(rollback(&root).unwrap(), old_digest);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_rollback_target_and_invalid_manifest_never_activate() {
        let root = std::env::temp_dir().join(format!("component-corrupt-{}", uuid::Uuid::new_v4()));
        let old = b"\x7fELFold";
        let new = b"\x7fELFnew";
        let old_digest = format!("{:x}", Sha256::digest(old));
        let new_digest = format!("{:x}", Sha256::digest(new));
        install(&root, &old_digest, old, false).unwrap();
        install(&root, &new_digest, new, true).unwrap();
        std::fs::write(version_path(&root, &old_digest), b"corrupt").unwrap();
        assert!(rollback(&root).is_err());
        assert_eq!(active(&root).unwrap().1, new_digest);
        std::fs::write(
            root.join("extenddb/active.json"),
            b"{\"protocol\":99,\"sha256\":\"../escape\"}",
        )
        .unwrap();
        assert!(active(&root).is_err());
        assert!(install(&root, &old_digest, old, false).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn component_operations_are_serialized() {
        let root = std::env::temp_dir().join(format!("component-lock-{}", uuid::Uuid::new_v4()));
        let bytes = b"\x7fELFfixture";
        let digest = format!("{:x}", Sha256::digest(bytes));
        install(&root, &digest, bytes, false).unwrap();
        let guard = installation_lock(&root).unwrap();
        assert!(install(&root, &digest, bytes, true).is_err());
        assert!(remove(&root).is_err());
        assert!(rollback(&root).is_err());
        drop(guard);
        remove(&root).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lifecycle_commands_parse_and_missing_component_is_actionable() {
        let digest = "a".repeat(64);
        let args = [
            "update", "extenddb", "--source", "/fixture", "--sha256", &digest,
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
        assert_eq!(
            parse(&args).unwrap(),
            Options::Update {
                source: "/fixture".into(),
                digest
            }
        );
        assert_eq!(
            parse(&["rollback".into(), "extenddb".into()]).unwrap(),
            Options::Rollback
        );
        let root = std::env::temp_dir().join(format!("component-missing-{}", uuid::Uuid::new_v4()));
        assert!(verified(&root)
            .unwrap_err()
            .to_string()
            .contains("component install extenddb"));
        assert!(!root.exists());
    }
}
