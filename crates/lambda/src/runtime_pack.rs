//! Pre-imported official Lambda filesystems. Network access belongs to the import tool,
//! never to server startup or invocation.
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    runtime: String,
    architecture: String,
    rootfs: String,
    inventory: String,
    inventory_sha256: String,
    environment: BTreeMap<String, String>,
    entrypoint: Vec<String>,
    working_directory: String,
    source: Source,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Source {
    registry: String,
    repository: String,
    image_digest: String,
    config_digest: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Entry {
    File {
        path: PathBuf,
        sha256: String,
        mode: u32,
    },
    Directory {
        path: PathBuf,
    },
    Symlink {
        path: PathBuf,
        target: PathBuf,
    },
}

impl Entry {
    fn path(&self) -> &Path {
        match self {
            Self::File { path, .. } | Self::Directory { path } | Self::Symlink { path, .. } => path,
        }
    }
}

pub(crate) struct RuntimePack {
    root: PathBuf,
    runtime: String,
    architecture: String,
    entries: Vec<Entry>,
    pub environment: BTreeMap<String, String>,
    entrypoint: Vec<String>,
    _lease: fs::File,
}

fn shared_lock(directory: &Path, name: &str) -> io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join(name))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(invalid(
            "runtime pack lock must be a regular file with one link",
        ));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    loop {
        // SAFETY: file owns this descriptor throughout the call and the shared lease.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } == 0 {
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Verify a local runtime pack while holding its shared version lease.
/// This performs blocking filesystem work; async callers must use spawn_blocking.
pub fn validate(directory: &Path, runtime: &str, architecture: &str) -> io::Result<()> {
    repository(runtime)?;
    if !matches!(architecture, "x86_64" | "arm64") {
        return Err(invalid("unsupported runtime pack architecture"));
    }
    RuntimePack::load(&fs::canonicalize(directory)?, runtime, architecture).map(drop)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn relative(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty()
        || path.as_os_str().len() > 4096
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || path.components().count() > 64
    {
        return Err(invalid("runtime pack contains an unsafe path"));
    }
    Ok(())
}

fn bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("runtime pack metadata exceeds its limit"));
    }
    Ok(bytes)
}

fn digest(bytes: &[u8], expected: &str) -> bool {
    let expected = expected.strip_prefix("sha256:").unwrap_or(expected);
    format!("{:x}", Sha256::digest(bytes)) == expected
}

fn file_digest(path: &Path, expected: &str) -> io::Result<bool> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()) == expected.strip_prefix("sha256:").unwrap_or(expected))
}

/// Map an AWS runtime identifier to its official image repository and tag.
pub fn official_image(runtime: &str) -> io::Result<(&'static str, String)> {
    let number = |value: &str| {
        !value.is_empty()
            && value.len() <= 2
            && value.bytes().all(|b| b.is_ascii_digit())
            && !value.starts_with('0')
    };
    let decimal = |value: &str| {
        value.split_once('.').is_some_and(|(major, minor)| {
            number(major)
                && !minor.is_empty()
                && minor.len() <= 2
                && minor.bytes().all(|b| b.is_ascii_digit())
        })
    };
    if let Some(version) = runtime
        .strip_prefix("nodejs")
        .and_then(|s| s.strip_suffix(".x"))
    {
        if number(version) {
            return Ok(("lambda/nodejs", version.into()));
        }
    }
    if let Some(version) = runtime.strip_prefix("dotnet") {
        if number(version) {
            return Ok(("lambda/dotnet", version.into()));
        }
    }
    for (prefix, repository) in [("python", "lambda/python"), ("ruby", "lambda/ruby")] {
        if let Some(version) = runtime.strip_prefix(prefix) {
            if decimal(version) && (prefix != "python" || version.starts_with("3.")) {
                return Ok((repository, version.into()));
            }
        }
    }
    match runtime {
        "provided.al2" => Ok(("lambda/provided", "al2".into())),
        "provided.al2023" => Ok(("lambda/provided", "al2023".into())),
        _ => Err(invalid("no official runtime pack mapping for this runtime")),
    }
}

fn repository(runtime: &str) -> io::Result<&'static str> {
    official_image(runtime).map(|(repository, _)| repository)
}

impl RuntimePack {
    fn load(directory: &Path, runtime: &str, architecture: &str) -> io::Result<Self> {
        let lease = shared_lock(directory, ".lease")?;
        Self::load_leased(directory, runtime, architecture, lease)
    }

    fn load_leased(
        directory: &Path,
        runtime: &str,
        architecture: &str,
        lease: fs::File,
    ) -> io::Result<Self> {
        let manifest: Manifest =
            serde_json::from_slice(&bounded(&directory.join("manifest.json"), 65536)?)?;
        if manifest.schema_version != 1
            || manifest.runtime != runtime
            || manifest.architecture != architecture
            || manifest.rootfs != "rootfs"
            || manifest.inventory != "inventory.json"
            || manifest.working_directory != "/var/task"
            || manifest.source.registry != "public.ecr.aws"
            || manifest.source.repository != repository(runtime)?
            || ![
                &manifest.source.image_digest,
                &manifest.source.config_digest,
            ]
            .iter()
            .all(|d| {
                d.strip_prefix("sha256:")
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            })
            || manifest.entrypoint != ["/lambda-entrypoint.sh"]
            || manifest.environment.len() > 128
            || manifest.environment.iter().any(|(key, value)| {
                key.len() > 256 || value.len() > 16384 || key.contains('\0') || value.contains('\0')
            })
        {
            return Err(invalid(
                "runtime pack identity or launch configuration is invalid",
            ));
        }
        let inventory = bounded(&directory.join("inventory.json"), 32 * 1024 * 1024)?;
        if !digest(&inventory, &manifest.inventory_sha256) {
            return Err(invalid("runtime pack inventory checksum mismatch"));
        }
        let mut entries: Vec<Entry> = serde_json::from_slice(&inventory)?;
        if entries.len() > 100_000 {
            return Err(invalid("runtime pack has too many entries"));
        }
        entries.sort_by(|a, b| a.path().cmp(b.path()));
        let root = directory.join("rootfs");
        if !fs::symlink_metadata(&root)?.is_dir() {
            return Err(invalid("runtime pack rootfs must be a real directory"));
        }
        let mut directories = HashSet::from([PathBuf::new()]);
        let mut seen = HashSet::new();
        let mut bytes = 0u64;
        for entry in &entries {
            let path = entry.path();
            relative(path)?;
            if !seen.insert(path.to_path_buf())
                || !directories.contains(path.parent().unwrap_or(Path::new("")))
            {
                return Err(invalid(
                    "runtime pack has duplicate paths or a linked parent",
                ));
            }
            let source = root.join(path);
            let metadata = fs::symlink_metadata(&source)?;
            match entry {
                Entry::Directory { .. } if metadata.is_dir() => {
                    directories.insert(path.to_path_buf());
                }
                Entry::File { sha256, mode, .. } if metadata.is_file() => {
                    bytes = bytes
                        .checked_add(metadata.len())
                        .ok_or_else(|| invalid("runtime pack size overflow"))?;
                    if bytes > 2 * 1024 * 1024 * 1024
                        || metadata.permissions().mode() & 0o7777 != *mode
                        || !file_digest(&source, sha256)?
                    {
                        return Err(invalid("runtime pack file checksum or size mismatch"));
                    }
                }
                Entry::Symlink { target, .. }
                    if metadata.file_type().is_symlink()
                        && target.as_os_str().len() <= 4096
                        && fs::read_link(&source)? == *target => {}
                _ => return Err(invalid("runtime pack entry type mismatch")),
            }
        }
        for path in ["var", "var/task", "var/runtime", "opt", "tmp", "etc"] {
            if !directories.contains(Path::new(path)) {
                return Err(invalid(
                    "runtime pack writable overlay paths must be real directories",
                ));
            }
        }
        Ok(Self {
            root,
            runtime: manifest.runtime,
            architecture: manifest.architecture,
            entries,
            environment: manifest.environment,
            entrypoint: manifest.entrypoint,
            _lease: lease,
        })
    }

    /// The compute backend mounts the guest root read-only. Per-environment directories
    /// remain writable on the host for overlays and deletion; runtime files are shared.
    pub fn install(&self, destination: &Path) -> io::Result<()> {
        fs::create_dir_all(destination)?;
        for entry in &self.entries {
            let target = destination.join(entry.path());
            match entry {
                Entry::Directory { .. } => fs::create_dir(&target)?,
                Entry::File { path, .. } => {
                    let source = self.root.join(path);
                    if fs::hard_link(&source, &target).is_err() {
                        fs::copy(source, target)?;
                    }
                }
                Entry::Symlink { target: link, .. } => symlink(link, target)?,
            }
        }
        // tmp is the only writable guest mount; never share its original files.
        let tmp = destination.join("tmp");
        fs::remove_dir_all(&tmp)?;
        fs::create_dir(&tmp)?;
        fs::set_permissions(tmp, fs::Permissions::from_mode(0o1777))?;
        Ok(())
    }

    pub fn command(&self, runtime: &str, handler: Option<&str>) -> Vec<String> {
        if runtime.starts_with("provided.") {
            return vec!["/var/task/bootstrap".into()];
        }
        let mut command = self.entrypoint.clone();
        command.push(handler.unwrap_or_default().to_string());
        command
    }
}

pub(crate) struct RuntimePacks {
    directory: PathBuf,
    verified: Mutex<HashMap<PathBuf, Weak<RuntimePack>>>,
}

impl RuntimePacks {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            verified: Mutex::new(HashMap::new()),
        }
    }

    pub async fn load(
        self: &Arc<Self>,
        runtime: &str,
        architecture: &str,
    ) -> Result<Arc<RuntimePack>, String> {
        repository(runtime).map_err(|e| e.to_string())?;
        if !matches!(architecture, "x86_64" | "arm64") {
            return Err("unsupported runtime pack architecture".into());
        }
        let loader = self.clone();
        let runtime = runtime.to_owned();
        let architecture = architecture.to_owned();
        tokio::task::spawn_blocking(move || {
            let load = || -> io::Result<Arc<RuntimePack>> {
                let root = fs::canonicalize(&loader.directory)?;
                let catalog = shared_lock(&root, ".catalog.lock")?;
                let directory = fs::canonicalize(root.join(&runtime).join(&architecture))?;
                if directory == root || !directory.starts_with(&root) {
                    return Err(invalid("active runtime pack escapes its configured root"));
                }
                {
                    let cache = loader.verified.lock().map_err(|_| invalid("runtime pack lock poisoned"))?;
                    if let Some(pack) = cache.get(&directory).and_then(Weak::upgrade) {
                        if pack.runtime != runtime || pack.architecture != architecture {
                            return Err(invalid("active runtime pack identity does not match the requested runtime"));
                        }
                        return Ok(pack);
                    }
                }
                let lease = shared_lock(&directory, ".lease")?;
                // CLI mutations are excluded only until the immutable version is pinned.
                // Hashing a large pack must not block unrelated installs or activation.
                drop(catalog);
                let pack = Arc::new(RuntimePack::load_leased(&directory, &runtime, &architecture, lease)?);
                let mut cache = loader.verified.lock().map_err(|_| invalid("runtime pack lock poisoned"))?;
                cache.retain(|_, pack| pack.strong_count() != 0);
                cache.insert(directory, Arc::downgrade(&pack));
                Ok(pack)
            };
            load().map_err(|error| format!(
                "Official runtime pack {runtime}/{architecture} unavailable or invalid: {error}. Run locallycloud runtime install {runtime}. Runtime packs directory: {}",
                loader.directory.display()
            ))
        }).await.map_err(|e| e.to_string())?
    }
}

/// Resolve absolute symlinks as guest paths, never as paths in the host filesystem.
fn guest_path(root: &Path, path: &Path) -> io::Result<PathBuf> {
    use std::collections::VecDeque;
    let mut pending: VecDeque<_> = path
        .components()
        .map(|c| c.as_os_str().to_os_string())
        .collect();
    let mut resolved = PathBuf::new();
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        match part.to_str() {
            Some("/") => resolved.clear(),
            Some(".") => {}
            Some("..") => {
                if !resolved.pop() {
                    return Err(invalid("guest path escapes root"));
                }
            }
            _ => {
                resolved.push(&part);
                let candidate = root.join(&resolved);
                if fs::symlink_metadata(&candidate)?.file_type().is_symlink() {
                    links += 1;
                    if links > 40 {
                        return Err(invalid("guest symlink cycle"));
                    }
                    let target = fs::read_link(candidate)?;
                    resolved.pop();
                    for part in target.components().rev() {
                        pending.push_front(part.as_os_str().to_os_string());
                    }
                }
            }
        }
    }
    Ok(root.join(resolved))
}

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
        let mut bundle = bounded(
            &guest_path(&root, Path::new("/etc/pki/tls/certs/ca-bundle.crt"))?,
            4 * 1024 * 1024,
        )?;
        for path in configured {
            bundle.push(b'\n');
            bundle.extend(bounded(
                &guest_path(&root, Path::new(&path))?,
                4 * 1024 * 1024,
            )?);
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
        let mut contents = match bounded(&guest_path(&root, Path::new("/etc/hosts"))?, 65536) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        contents.extend(b"\n127.0.0.1 localhost\n");
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
    use serde_json::json;

    #[test]
    fn official_images_map_managed_families_and_reject_invalid_names() {
        for (name, repository, tag) in [
            ("nodejs24.x", "lambda/nodejs", "24"),
            ("python3.14", "lambda/python", "3.14"),
            ("ruby4.0", "lambda/ruby", "4.0"),
            ("ruby3.4", "lambda/ruby", "3.4"),
            ("dotnet10", "lambda/dotnet", "10"),
            ("dotnet8", "lambda/dotnet", "8"),
            ("provided.al2023", "lambda/provided", "al2023"),
        ] {
            assert_eq!(official_image(name).unwrap(), (repository, tag.into()));
        }
        for name in [
            "ruby../4",
            "dotnet10/../../",
            "python2.7",
            "ruby4",
            "dotnet",
            "dotnet010",
            "nodejs24.x;exit",
        ] {
            assert!(official_image(name).is_err(), "{name}");
        }
    }

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    impl Fixture {
        fn new() -> Self {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../compatibility-tests/.work/runtime-pack-unit")
                .join(uuid::Uuid::new_v4().to_string());
            fs::create_dir_all(path.join("rootfs")).unwrap();
            let fixture = Self(path);
            for name in ["etc", "opt", "tmp", "var", "var/runtime", "var/task"] {
                fs::create_dir_all(fixture.0.join("rootfs").join(name)).unwrap();
            }
            fs::write(fixture.0.join("rootfs/etc/trust.pem"), b"original").unwrap();
            fixture.publish(None);
            fixture
        }
        fn publish(&self, extra: Option<serde_json::Value>) {
            let mut entries = vec![];
            for name in ["etc", "opt", "tmp", "var", "var/runtime", "var/task"] {
                entries.push(json!({"path":name,"kind":"directory"}));
            }
            entries.push(json!({"path":"etc/trust.pem","kind":"file","mode":fs::metadata(self.0.join("rootfs/etc/trust.pem")).unwrap().permissions().mode() & 0o7777,"sha256":format!("sha256:{:x}",Sha256::digest(b"original"))}));
            if let Some(extra) = extra {
                entries.push(extra);
            }
            let inventory = serde_json::to_vec(&entries).unwrap();
            fs::write(self.0.join("inventory.json"), &inventory).unwrap();
            let manifest = json!({"schemaVersion":1,"runtime":"python3.13","architecture":"x86_64","rootfs":"rootfs","inventory":"inventory.json","inventorySha256":format!("sha256:{:x}",Sha256::digest(&inventory)),"environment":{},"entrypoint":["/lambda-entrypoint.sh"],"workingDirectory":"/var/task","source":{"registry":"public.ecr.aws","repository":"lambda/python","imageDigest":format!("sha256:{}","a".repeat(64)),"configDigest":format!("sha256:{}","b".repeat(64))}});
            fs::write(
                self.0.join("manifest.json"),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
        }
        fn load(&self) -> io::Result<RuntimePack> {
            RuntimePack::load(&self.0, "python3.13", "x86_64")
        }
    }

    #[test]
    fn rejects_modified_content_inventory_and_parent_traversal() {
        let fixture = Fixture::new();
        assert!(fixture.load().is_ok());
        fs::write(fixture.0.join("rootfs/etc/trust.pem"), b"modified").unwrap();
        assert!(fixture.load().is_err());
        fs::write(fixture.0.join("rootfs/etc/trust.pem"), b"original").unwrap();
        fs::write(fixture.0.join("inventory.json"), b"[]").unwrap();
        assert!(fixture.load().is_err());
        fixture.publish(Some(json!({"path":"../escape","kind":"directory"})));
        assert!(fixture.load().is_err());
        fixture.publish(Some(
            json!({"path":"etc/trust.pem/escape","kind":"directory"}),
        ));
        assert!(fixture.load().is_err());
    }

    #[test]
    fn guest_absolute_links_stay_in_guest_and_cannot_escape() {
        let fixture = Fixture::new();
        let root = fixture.0.join("rootfs");
        symlink("/etc/trust.pem", root.join("opt/cert")).unwrap();
        assert_eq!(
            guest_path(&root, Path::new("/opt/cert")).unwrap(),
            root.join("etc/trust.pem")
        );
        symlink("../../../outside", root.join("opt/escape")).unwrap();
        assert!(guest_path(&root, Path::new("/opt/escape")).is_err());
    }

    #[test]
    fn replacing_overlay_does_not_modify_shared_runtime() {
        let fixture = Fixture::new();
        let pack = fixture.load().unwrap();
        let guest = fixture.0.join("guest");
        pack.install(&guest).unwrap();
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

    #[tokio::test]
    async fn active_version_changes_preserve_existing_leases_and_weak_cache_releases_them() {
        let fixture = Fixture::new();
        let root = fixture.0.join("packs");
        let versions = root.join(".versions/python3.13/x86_64");
        let first_directory = versions.join("first");
        fs::create_dir_all(&first_directory).unwrap();
        for name in ["rootfs", "manifest.json", "inventory.json"] {
            fs::rename(fixture.0.join(name), first_directory.join(name)).unwrap();
        }
        let first_directory = fs::canonicalize(first_directory).unwrap();
        let second_fixture = Fixture::new();
        let second_directory = versions.join("second");
        fs::rename(&second_fixture.0, &second_directory).unwrap();
        let second_directory = fs::canonicalize(second_directory).unwrap();
        fs::create_dir(root.join("python3.13")).unwrap();
        let active = root.join("python3.13/x86_64");
        symlink("../.versions/python3.13/x86_64/first", &active).unwrap();
        let loader = Arc::new(RuntimePacks::new(root.clone()));
        let first = loader.load("python3.13", "x86_64").await.unwrap();
        assert_eq!(first.root, first_directory.join("rootfs"));
        let first_weak = Arc::downgrade(&first);
        let exclusive = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(first_directory.join(".lease"))
            .unwrap();
        // SAFETY: exclusive owns the descriptor and NONBLOCK keeps the test bounded.
        assert_eq!(
            unsafe { libc::flock(exclusive.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            -1
        );
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
        let replacement = root.join("python3.13/next");
        symlink("../.versions/python3.13/x86_64/second", &replacement).unwrap();
        fs::rename(replacement, &active).unwrap();
        let second = loader.load("python3.13", "x86_64").await.unwrap();
        assert_eq!(second.root, second_directory.join("rootfs"));
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(first.root, first_directory.join("rootfs"));
        drop(first);
        assert!(first_weak.upgrade().is_none());
        // The loader's cache must not retain an unused version lease.
        // SAFETY: exclusive still owns the descriptor used for the lock attempt.
        assert_eq!(
            unsafe { libc::flock(exclusive.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
    }

    #[tokio::test]
    async fn active_paths_cannot_escape_the_catalog_and_lock_files_cannot_be_symlinks() {
        let fixture = Fixture::new();
        let root = fixture.0.join("packs");
        fs::create_dir_all(root.join("python3.13")).unwrap();
        let outside = Fixture::new();
        symlink(&outside.0, root.join("python3.13/x86_64")).unwrap();
        let loader = Arc::new(RuntimePacks::new(root));
        assert!(loader.load("python3.13", "x86_64").await.is_err());
        symlink("rootfs/etc/trust.pem", outside.0.join(".lease")).unwrap();
        assert!(validate(&outside.0, "python3.13", "x86_64").is_err());
        assert_eq!(
            fs::read(outside.0.join("rootfs/etc/trust.pem")).unwrap(),
            b"original"
        );
    }
}
