//! Lazy discovery of a compatible PostgreSQL toolchain.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command;

const TOOLS: [&str; 5] = ["initdb", "pg_ctl", "postgres", "psql", "pg_basebackup"];
/// Version pinned by the opt-in, checksum-verified native source build script.
pub const CACHE_VERSION: &str = "16.15";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresRuntime {
    pub bin_dir: PathBuf,
    pub version: String,
}

impl PostgresRuntime {
    pub fn tool(&self, name: &str) -> Option<PathBuf> {
        TOOLS.contains(&name).then(|| self.bin_dir.join(name))
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("PostgreSQL runtime unavailable: set LOCALCLOUD_PG_BIN_DIR to a PostgreSQL 16+ bin directory containing initdb, pg_ctl, postgres, psql and pg_basebackup; no distribution is cached")]
    Missing,
    #[error("PostgreSQL cache directory is unavailable or insecure: {0}")]
    CacheDirectory(String),
    #[error("PostgreSQL toolchain in {directory} is incomplete: missing {tool}")]
    Incomplete {
        directory: PathBuf,
        tool: &'static str,
    },
    #[error("PostgreSQL tool {tool} in {directory} could not be executed: {reason}")]
    Execution {
        directory: PathBuf,
        tool: &'static str,
        reason: String,
    },
    #[error("PostgreSQL tool {tool} in {directory} reports an unsupported or malformed version: {output}")]
    Version {
        directory: PathBuf,
        tool: &'static str,
        output: String,
    },
    #[error("PostgreSQL tool {tool} in {directory} has version {actual}, expected {expected}")]
    MixedVersion {
        directory: PathBuf,
        tool: &'static str,
        actual: String,
        expected: String,
    },
}

/// Resolve without installing anything. An explicit path is authoritative; PATH
/// candidates must contain the entire toolchain in one directory. The cache is
/// considered only after PATH and is never downloaded implicitly.
pub async fn resolve(
    explicit: Option<&Path>,
    path: Option<&OsStr>,
    cache_root: &Path,
) -> Result<PostgresRuntime, RuntimeError> {
    if let Some(directory) = explicit {
        return validate(directory).await;
    }

    if let Some(path) = path {
        for directory in std::env::split_paths(path) {
            if directory.join("postgres").is_file() {
                if let Ok(runtime) = validate(&directory).await {
                    return Ok(runtime);
                }
            }
        }
    }

    let cached = cache_root
        .join("postgresql")
        .join(CACHE_VERSION)
        .join("bin");
    if cached.exists() {
        let runtime = validate(&cached).await?;
        if runtime.version != CACHE_VERSION {
            return Err(RuntimeError::MixedVersion {
                directory: runtime.bin_dir,
                tool: "postgres",
                actual: runtime.version,
                expected: CACHE_VERSION.to_owned(),
            });
        }
        return Ok(runtime);
    }
    Err(RuntimeError::Missing)
}

/// Resolve from localcloud configuration. A relative explicit path is resolved
/// against the process working directory, matching other localcloud work paths.
pub async fn resolve_from_env() -> Result<PostgresRuntime, RuntimeError> {
    let explicit = std::env::var_os("LOCALCLOUD_PG_BIN_DIR").map(PathBuf::from);
    let path: Option<OsString> = std::env::var_os("PATH");
    let cache_base = std::env::var_os("XDG_CACHE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|home| home.join(".cache"))
        })
        .unwrap_or_else(|| localcloud_state::StateDb::work_dir("cache"));
    let cache_root = cache_base.join("localcloud");
    localcloud_state::StateDb::private_dir(&cache_root)
        .map_err(|error| RuntimeError::CacheDirectory(error.to_string()))?;
    resolve(explicit.as_deref(), path.as_deref(), &cache_root).await
}

async fn validate(directory: &Path) -> Result<PostgresRuntime, RuntimeError> {
    let mut common_version: Option<String> = None;
    for tool in TOOLS {
        let binary = directory.join(tool);
        if !binary.is_file() {
            return Err(RuntimeError::Incomplete {
                directory: directory.to_path_buf(),
                tool,
            });
        }
        let output = tokio::time::timeout(
            Duration::from_secs(5),
            Command::new(&binary)
                .kill_on_drop(true)
                .arg("--version")
                .output(),
        )
        .await
        .map_err(|_| RuntimeError::Execution {
            directory: directory.to_path_buf(),
            tool,
            reason: "version check timed out after 5 seconds".to_owned(),
        })?
        .map_err(|error| RuntimeError::Execution {
            directory: directory.to_path_buf(),
            tool,
            reason: error.to_string(),
        })?;
        if !output.status.success() {
            return Err(RuntimeError::Execution {
                directory: directory.to_path_buf(),
                tool,
                reason: format!("exit status {}", output.status),
            });
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let reported = parse_version(&stdout).ok_or_else(|| RuntimeError::Version {
            directory: directory.to_path_buf(),
            tool,
            output: stdout.trim().to_owned(),
        })?;
        if let Some(expected) = &common_version {
            if expected != &reported {
                return Err(RuntimeError::MixedVersion {
                    directory: directory.to_path_buf(),
                    tool,
                    actual: reported,
                    expected: expected.clone(),
                });
            }
        } else {
            common_version = Some(reported);
        }
    }
    Ok(PostgresRuntime {
        bin_dir: directory
            .canonicalize()
            .unwrap_or_else(|_| directory.to_path_buf()),
        version: common_version.expect("five PostgreSQL tools were checked"),
    })
}

fn parse_version(output: &str) -> Option<String> {
    let (_, version) = output.trim().split_once("(PostgreSQL) ")?;
    let version = version.split_whitespace().next()?;
    let mut parts = version.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    if major < 16 || !parts.all(|part| part.parse::<u32>().is_ok()) {
        return None;
    }
    Some(version.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "localcloud-rds-runtime-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn bin(&self, version: &str) -> PathBuf {
            let dir = self.0.join("bin");
            std::fs::create_dir_all(&dir).unwrap();
            for tool in TOOLS {
                let file = dir.join(tool);
                std::fs::write(
                    &file,
                    format!("#!/bin/sh\necho '{tool} (PostgreSQL) {version}'\n"),
                )
                .unwrap();
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            dir
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn explicit_toolchain_resolves_and_is_authoritative() {
        let temp = TempDir::new();
        let bin = temp.bin("16.4");
        let runtime = resolve(Some(&bin), None, &temp.0).await.unwrap();
        assert_eq!(runtime.version, "16.4");
        std::fs::remove_file(bin.join("psql")).unwrap();
        assert!(matches!(
            resolve(Some(&bin), None, &temp.0).await,
            Err(RuntimeError::Incomplete { tool: "psql", .. })
        ));
    }

    #[tokio::test]
    async fn path_and_cache_fallback_are_version_checked() {
        let temp = TempDir::new();
        let bin = temp.bin("17.2");
        let runtime = resolve(None, Some(bin.as_os_str()), &temp.0).await.unwrap();
        assert_eq!(runtime.version, "17.2");
        let cached = temp.0.join("postgresql").join(CACHE_VERSION).join("bin");
        std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
        std::fs::rename(&bin, &cached).unwrap();
        assert!(matches!(
            resolve(None, None, &temp.0).await,
            Err(RuntimeError::MixedVersion {
                tool: "postgres",
                ..
            })
        ));
        for tool in TOOLS {
            std::fs::write(
                cached.join(tool),
                format!("#!/bin/sh\necho '{tool} (PostgreSQL) {CACHE_VERSION}'\n"),
            )
            .unwrap();
        }
        assert_eq!(
            resolve(None, None, &temp.0).await.unwrap().version,
            CACHE_VERSION
        );
        std::fs::write(
            cached.join("psql"),
            "#!/bin/sh\necho 'psql (PostgreSQL) 15.9'\n",
        )
        .unwrap();
        assert!(matches!(
            resolve(None, None, &temp.0).await,
            Err(RuntimeError::Version { tool: "psql", .. })
        ));
    }

    #[tokio::test]
    async fn missing_runtime_is_typed() {
        let temp = TempDir::new();
        assert!(matches!(
            resolve(None, None, &temp.0).await,
            Err(RuntimeError::Missing)
        ));
    }
}
