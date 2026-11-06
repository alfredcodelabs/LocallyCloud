//! Explicit installation of optional, digest-pinned native components.
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::component_catalog;

pub const USAGE: &str = "Usage: locallycloud component <install|update|check-updates|list|rollback|remove> [extenddb]\n\nInstall/update: component install|update extenddb [--catalog PATH|HTTPS_URL]\nCheck: component check-updates extenddb [--catalog PATH|HTTPS_URL]\nExplicit artifact: component install|update extenddb --source PATH|HTTPS_URL --sha256 HEX\n\nThe default catalog is pinned to this LocalCloud release and selects this machine's architecture.\nDownloads occur only through explicit install/update/check-updates commands. Rollback is offline. Database files are preserved.";
pub(super) const MAX_BINARY: usize = 128 * 1024 * 1024;
const MISSING_COMPONENT: &str =
    "ExtendDB worker is not installed; use locallycloud component install extenddb";

#[derive(Debug, PartialEq, Eq)]
pub enum CatalogAction {
    Install,
    Update,
    CheckUpdates,
}

impl CatalogAction {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "install" => Ok(Self::Install),
            "update" => Ok(Self::Update),
            "check-updates" => Ok(Self::CheckUpdates),
            _ => Err(USAGE.into()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Options {
    Help,
    List,
    Install {
        source: String,
        digest: String,
    },
    Update {
        source: String,
        digest: String,
    },
    Rollback,
    Remove,
    Catalog {
        action: CatalogAction,
        source: Option<String>,
    },
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
        [action, "extenddb"] if matches!(*action, "install" | "update" | "check-updates") => {
            Ok(Options::Catalog {
                action: CatalogAction::parse(action)?,
                source: None,
            })
        }
        [action, "extenddb", "--catalog", source] if !source.is_empty() => Ok(Options::Catalog {
            action: CatalogAction::parse(action)?,
            source: Some((*source).into()),
        }),
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

pub(super) fn valid_digest(digest: &str) -> bool {
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
        Options::Catalog { action, source } => {
            let installed_root = root.clone();
            let installed = tokio::task::spawn_blocking(move || match manifest(&installed_root) {
                Ok(value) => Ok(Some(value.sha256)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            })
            .await
            .map_err(io::Error::other)??;
            if *action == CatalogAction::Update && installed.is_none() {
                return Err(io::Error::other(MISSING_COMPONENT));
            }
            let release = component_catalog::resolve(source.as_deref()).await?;
            let digest = release.digest().to_owned();
            match action {
                CatalogAction::CheckUpdates => {
                    println!(
                        "{}",
                        json!({"component":"extenddb", "version":release.version,
                        "installedSha256":installed, "availableSha256":digest,
                        "updateAvailable":installed.as_deref() != Some(digest.as_str())})
                    );
                }
                CatalogAction::Install | CatalogAction::Update => {
                    let (binary, notices) = release.download().await?;
                    let update = *action == CatalogAction::Update;
                    tokio::task::spawn_blocking(move || {
                        install_version(&root, &digest, &binary, update, Some(&notices))
                    })
                    .await
                    .map_err(io::Error::other)??;
                    println!("ExtendDB worker installed from verified release catalog");
                }
            }
        }

        Options::Install { source, digest } | Options::Update { source, digest } => {
            let update = matches!(options, Options::Update { .. });
            if update {
                let root = root.clone();
                tokio::task::spawn_blocking(move || manifest(&root))
                    .await
                    .map_err(io::Error::other)??;
            }
            let bytes = component_catalog::download_explicit(source, digest).await?;
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
    install_version(root, digest, bytes, update, None)
}

fn install_version(
    root: &Path,
    digest: &str,
    bytes: &[u8],
    update: bool,
    notices: Option<&[u8]>,
) -> io::Result<()> {
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
    write_atomic(&version, "worker", bytes, 0o700)?;
    if let Some(notices) = notices {
        write_atomic(&version, "LICENSES.txt", notices, 0o600)?;
    }
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
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    write_atomic(&root.join("extenddb"), "active.json", &bytes, 0o600)
}

fn write_atomic(directory: &Path, name: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write;
    let staging = directory.join(format!(".{name}-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&staging)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&staging, directory.join(name))?;
        std::fs::File::open(directory)?.sync_all()
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
    fn explicit_artifacts_require_a_valid_digest() {
        let args = [
            "install",
            "extenddb",
            "--source",
            "x",
            "--sha256",
            "../invalid",
        ]
        .map(String::from);
        assert!(parse(&args).is_err());
        assert_eq!(parse(&["list".into()]).unwrap(), Options::List);
        assert_eq!(
            parse(&["install".into(), "extenddb".into()]).unwrap(),
            Options::Catalog {
                action: CatalogAction::Install,
                source: None
            }
        );
        assert_eq!(
            parse(&[
                "check-updates".into(),
                "extenddb".into(),
                "--catalog".into(),
                "/index".into()
            ])
            .unwrap(),
            Options::Catalog {
                action: CatalogAction::CheckUpdates,
                source: Some("/index".into())
            }
        );
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
    #[test]
    fn catalog_notices_are_persisted_before_activation_and_failed_writes_preserve_active() {
        let root = std::env::temp_dir().join(format!("component-notices-{}", uuid::Uuid::new_v4()));
        let bytes = b"\x7fELFfixture";
        let digest = format!("{:x}", Sha256::digest(bytes));
        install_version(&root, &digest, bytes, false, Some(b"license notices")).unwrap();
        let version = version_path(&root, &digest).parent().unwrap().to_owned();
        assert_eq!(
            std::fs::read(version.join("LICENSES.txt")).unwrap(),
            b"license notices"
        );
        let other_bytes = b"\x7fELFnext";
        let other_digest = format!("{:x}", Sha256::digest(other_bytes));
        let other_version = root.join("extenddb/versions").join(&other_digest);
        private_directory(&other_version).unwrap();
        std::fs::create_dir(other_version.join("LICENSES.txt")).unwrap();
        assert!(install_version(
            &root,
            &other_digest,
            other_bytes,
            true,
            Some(b"license notices")
        )
        .is_err());
        assert_eq!(active(&root).unwrap().1, digest);
        assert!(
            !std::fs::read_dir(&other_version).unwrap().any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with('.'))
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
