use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub fn work_dir(kind: &str) -> PathBuf {
    let cache = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    resolve_work_dir(kind, cache.as_deref(), home.as_deref())
}

fn resolve_work_dir(kind: &str, cache: Option<&Path>, home: Option<&Path>) -> PathBuf {
    if let Some(cache) = cache.filter(|p| p.is_absolute()) {
        return cache.join("locallycloud").join(kind);
    }
    if let Some(home) = home.filter(|p| p.is_absolute()) {
        return home.join(".cache/locallycloud").join(kind);
    }
    std::env::temp_dir().join(format!("locallycloud-{kind}-{}", unsafe {
        libc::geteuid()
    }))
}

pub fn ensure(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "work directory must be absolute",
        ));
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "work directory is insecure",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_absolute_user_disk_cache() {
        assert_eq!(
            resolve_work_dir(
                "oci",
                Some(Path::new("/disk/cache")),
                Some(Path::new("/home/user"))
            ),
            PathBuf::from("/disk/cache/locallycloud/oci")
        );
        assert_eq!(
            resolve_work_dir(
                "oci",
                Some(Path::new("relative")),
                Some(Path::new("/home/user"))
            ),
            PathBuf::from("/home/user/.cache/locallycloud/oci")
        );
    }

    #[test]
    fn rejects_symlink_and_public_work_directory() {
        let root = std::env::temp_dir().join(format!(
            "locallycloud-compute-private-{}",
            std::process::id()
        ));
        ensure(&root).expect("private root");
        let public = root.join("public");
        fs::create_dir(&public).expect("public directory");
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755))
            .expect("public permissions");
        assert!(ensure(&public).is_err());
        let link = root.join("link");
        std::os::unix::fs::symlink(&public, &link).expect("symlink");
        assert!(ensure(&link).is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
