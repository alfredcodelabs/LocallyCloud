//! Explicit installation of optional, digest-pinned native components.
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const USAGE: &str = "Usage: locallycloud component <install|list|remove> [extenddb]\n\nInstall: component install extenddb --source PATH|HTTPS_URL --sha256 HEX\n\nInstalls the private ExtendDB worker, not the upstream development HTTP server.\nDownloads occur only through install. Existing versions are retained.";
const MAX_BINARY: usize = 128 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Options {
    Help,
    List,
    Install { source: String, digest: String },
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
        ["install", "extenddb", "--source", source, "--sha256", digest]
            if valid_digest(digest) && !source.is_empty() =>
        {
            Ok(Options::Install {
                source: (*source).into(),
                digest: (*digest).into(),
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

pub fn active(root: &Path) -> io::Result<(PathBuf, String)> {
    let bytes = std::fs::read(root.join("extenddb/active.json"))
        .map_err(|_| io::Error::other("ExtendDB worker is not installed; use locallycloud component install extenddb --source PATH --sha256 HEX"))?;
    let manifest: Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let digest = manifest
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|v| valid_digest(v))
        .ok_or_else(|| io::Error::other("invalid ExtendDB component manifest"))?;
    Ok((
        root.join("extenddb/versions").join(digest).join("worker"),
        digest.into(),
    ))
}

pub fn verified(root: &Path) -> io::Result<(PathBuf, std::fs::File, std::fs::File)> {
    let (path, expected) = active(root)?;
    let lease = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(".extenddb-usage.lock"))?;
    lease
        .try_lock_shared()
        .map_err(|_| io::Error::other("ExtendDB component is being removed"))?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
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
    Ok((path, file, lease))
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
            let result = tokio::task::spawn_blocking(move || match active(&root) {
                Ok((path, digest)) => json!({"extenddb": {"path": path, "sha256": digest}}),
                Err(_) => json!({"extenddb": null}),
            })
            .await
            .map_err(io::Error::other)?;
            println!("{result}");
        }
        Options::Remove => {
            tokio::task::spawn_blocking(move || remove(&root))
                .await
                .map_err(io::Error::other)??;
            println!("ExtendDB removed; database files preserved");
        }
        Options::Install { source, digest } => {
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
            tokio::task::spawn_blocking(move || install(&root, &digest, &bytes))
                .await
                .map_err(io::Error::other)??;
            println!("ExtendDB worker installed");
        }
    }
    Ok(())
}

fn install(root: &Path, digest: &str, bytes: &[u8]) -> io::Result<()> {
    private_directory(root)?;
    let component = root.join("extenddb");
    private_directory(&component)?;
    let lease = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(".extenddb-usage.lock"))?;
    lease
        .try_lock_shared()
        .map_err(|_| io::Error::other("ExtendDB component is being removed"))?;
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
    let staging = component.join(format!("active-{}.json", uuid::Uuid::new_v4()));
    let mut manifest = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staging)?;
    write!(manifest, "{}", json!({"protocol":1,"sha256":digest}))?;
    manifest.sync_all()?;
    std::fs::rename(staging, component.join("active.json"))?;
    std::fs::File::open(component)?.sync_all()?;
    Ok(())
}

fn remove(root: &Path) -> io::Result<()> {
    let component = root.join("extenddb");
    if !component.exists() {
        return Ok(());
    }
    private_directory(&component)?;
    let lease = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(".extenddb-usage.lock"))?;
    lease
        .try_lock()
        .map_err(|_| io::Error::other("ExtendDB is in use; stop the server before removal"))?;
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
        install(&root, &digest, bytes).unwrap();
        let (path, original, lease) = verified(&root).unwrap();
        assert!(remove(&root).is_err());
        install(&root, &digest, bytes).unwrap();
        // Atomic replacement preserves the already-open, verified executable inode.
        assert_eq!(original.metadata().unwrap().len(), bytes.len() as u64);
        std::fs::write(&path, b"corrupted").unwrap();
        assert!(verified(&root).is_err());
        install(&root, &digest, bytes).unwrap();
        assert!(verified(&root).is_ok());
        drop(lease);
        remove(&root).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
