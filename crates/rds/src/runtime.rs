//! Lazy discovery of a compatible PostgreSQL toolchain.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command;

const TOOLS: [&str; 5] = ["initdb", "pg_ctl", "postgres", "psql", "pg_basebackup"];
/// Oldest supported PostgreSQL major version (Ubuntu 24.04 LTS ships 16).
const MIN_MAJOR: u32 = 16;
/// Debian and Ubuntu install each major version under `<root>/<major>/bin`, outside PATH.
const DISTRIBUTION_ROOTS: [&str; 1] = ["/usr/lib/postgresql"];

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
    #[error("PostgreSQL runtime unavailable: install PostgreSQL 16 or later from your distribution (the newest it provides) or set LOCALLYCLOUD_PG_BIN_DIR to a bin directory containing initdb, pg_ctl, postgres, psql and pg_basebackup")]
    Missing,
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
/// candidates must contain the entire toolchain in one directory. Distribution roots
/// (`<root>/<major>/bin`) are tried last, newest major version first.
pub async fn resolve(
    explicit: Option<&Path>,
    path: Option<&OsStr>,
    distribution_roots: &[PathBuf],
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

    for directory in distribution_candidates(distribution_roots) {
        if let Ok(runtime) = validate(&directory).await {
            return Ok(runtime);
        }
    }
    Err(RuntimeError::Missing)
}

/// `<root>/<major>/bin` directories with a supported major version, newest first.
fn distribution_candidates(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut candidates: Vec<(u32, PathBuf)> = roots
        .iter()
        .filter_map(|root| std::fs::read_dir(root).ok())
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let major = entry.file_name().to_str()?.parse::<u32>().ok()?;
            let bin = entry.path().join("bin");
            (major >= MIN_MAJOR && bin.join("postgres").is_file()).then_some((major, bin))
        })
        .collect();
    candidates.sort_by_key(|(major, _)| std::cmp::Reverse(*major));
    candidates.into_iter().map(|(_, bin)| bin).collect()
}

/// Resolve from locallycloud configuration. A relative explicit path is resolved
/// against the process working directory, matching other locallycloud work paths.
pub async fn resolve_from_env() -> Result<PostgresRuntime, RuntimeError> {
    let explicit = std::env::var_os("LOCALLYCLOUD_PG_BIN_DIR").map(PathBuf::from);
    let path: Option<OsString> = std::env::var_os("PATH");
    let roots: Vec<PathBuf> = DISTRIBUTION_ROOTS.iter().map(PathBuf::from).collect();
    resolve(explicit.as_deref(), path.as_deref(), &roots).await
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
    if major < MIN_MAJOR || !parts.all(|part| part.parse::<u32>().is_ok()) {
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
                "locallycloud-rds-runtime-{}-{nonce}",
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
        let runtime = resolve(Some(&bin), None, &[]).await.unwrap();
        assert_eq!(runtime.version, "16.4");
        std::fs::remove_file(bin.join("psql")).unwrap();
        assert!(matches!(
            resolve(Some(&bin), None, &[]).await,
            Err(RuntimeError::Incomplete { tool: "psql", .. })
        ));
    }

    #[tokio::test]
    async fn path_toolchain_is_version_checked() {
        let temp = TempDir::new();
        let bin = temp.bin("17.2");
        let runtime = resolve(None, Some(bin.as_os_str()), &[]).await.unwrap();
        assert_eq!(runtime.version, "17.2");
        std::fs::write(
            bin.join("psql"),
            "#!/bin/sh\necho 'psql (PostgreSQL) 15.9'\n",
        )
        .unwrap();
        assert!(matches!(
            resolve(None, Some(bin.as_os_str()), &[]).await,
            Err(RuntimeError::Missing)
        ));
    }

    #[tokio::test]
    async fn distribution_root_prefers_newest_supported_major() {
        let temp = TempDir::new();
        let root = temp.0.join("postgresql");
        for (major, version) in [("15", "15.9"), ("17", "17.6"), ("18", "18.1")] {
            let bin = temp.bin(version);
            std::fs::create_dir_all(root.join(major)).unwrap();
            std::fs::rename(&bin, root.join(major).join("bin")).unwrap();
        }
        let roots = [root.clone()];
        assert_eq!(resolve(None, None, &roots).await.unwrap().version, "18.1");
        std::fs::remove_file(root.join("18/bin/psql")).unwrap();
        assert_eq!(resolve(None, None, &roots).await.unwrap().version, "17.6");
        std::fs::remove_dir_all(root.join("17")).unwrap();
        assert!(matches!(
            resolve(None, None, &roots).await,
            Err(RuntimeError::Missing)
        ));
    }

    #[tokio::test]
    async fn missing_runtime_is_typed() {
        let temp = TempDir::new();
        assert!(matches!(
            resolve(None, None, std::slice::from_ref(&temp.0)).await,
            Err(RuntimeError::Missing)
        ));
    }
}
