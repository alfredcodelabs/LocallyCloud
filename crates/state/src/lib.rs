//! Shared SQLite connection settings for durable local service state.

use std::fs::{self, OpenOptions, Permissions};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use thiserror::Error;

const MIN_SQLITE_VERSION: i32 = 3_053_004;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("state filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("state SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("SQLite 3.53.4 or newer is required; linked version is {0}")]
    SqliteTooOld(String),
    #[error("state database path is a symlink")]
    Symlink,
    #[error("state database path has no parent directory")]
    MissingParent,
    #[error("state directory is accessible by other users: {0}")]
    InsecureDirectory(PathBuf),
    #[error("{0} must be an absolute path")]
    InvalidPath(&'static str),
    #[error("set HOME or XDG_DATA_HOME for persistent state")]
    MissingDataHome,
}

#[derive(Clone, Debug)]
pub struct StateDb {
    path: PathBuf,
}

impl StateDb {
    pub fn data_dir() -> Result<PathBuf, StateError> {
        let base = match std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
            Some(value) => {
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    return Err(StateError::InvalidPath("XDG_DATA_HOME"));
                }
                path
            }
            None => {
                let home = std::env::var_os("HOME")
                    .filter(|value| !value.is_empty())
                    .ok_or(StateError::MissingDataHome)?;
                let home = PathBuf::from(home);
                if !home.is_absolute() {
                    return Err(StateError::InvalidPath("HOME"));
                }
                home.join(".local/share")
            }
        };
        Ok(base.join("locallycloud"))
    }

    pub fn default_path() -> Result<PathBuf, StateError> {
        if let Some(value) =
            std::env::var_os("LOCALLYCLOUD_STATE_DB").filter(|value| !value.is_empty())
        {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(StateError::InvalidPath("LOCALLYCLOUD_STATE_DB"));
            }
            return Ok(path);
        }
        Ok(Self::data_dir()?.join("state.sqlite3"))
    }

    pub fn work_dir(kind: &str) -> PathBuf {
        std::env::temp_dir().join(format!("locallycloud-{kind}-{}", unsafe {
            libc::geteuid()
        }))
    }

    pub fn private_dir(path: &Path) -> Result<(), StateError> {
        if !path.is_absolute() {
            return Err(StateError::InvalidPath("private directory"));
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
            return Err(StateError::InsecureDirectory(path.to_path_buf()));
        }
        Ok(())
    }

    pub fn open(path: PathBuf) -> Result<Self, StateError> {
        if rusqlite::version_number() < MIN_SQLITE_VERSION {
            return Err(StateError::SqliteTooOld(rusqlite::version().to_owned()));
        }
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(StateError::MissingParent)?;
        Self::private_dir(parent)?;
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(StateError::Symlink);
        }
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)?;
        fs::set_permissions(&path, Permissions::from_mode(0o600))?;
        let state = Self { path };
        let connection = state.connection()?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        Ok(state)
    }

    pub fn connection(&self) -> Result<Connection, StateError> {
        let connection =
            Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        Ok(connection)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_dir_rejects_public_directory_and_symlink() {
        let root =
            std::env::temp_dir().join(format!("locallycloud-private-dir-{}", std::process::id()));
        StateDb::private_dir(&root).expect("create private directory");
        let public = root.join("public");
        fs::create_dir(&public).expect("create public directory");
        fs::set_permissions(&public, Permissions::from_mode(0o755)).expect("make directory public");
        assert!(matches!(
            StateDb::private_dir(&public),
            Err(StateError::InsecureDirectory(_))
        ));
        let link = root.join("link");
        std::os::unix::fs::symlink(&public, &link).expect("create symlink");
        assert!(StateDb::private_dir(&link).is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn committed_state_survives_restart_with_private_permissions() {
        let root = std::env::temp_dir().join(format!(
            "locallycloud-state-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = root.join("state.sqlite3");
        {
            let state = StateDb::open(path.clone()).expect("state opens");
            let connection = state.connection().expect("connection opens");
            connection
                .execute_batch(
                    "CREATE TABLE checkpoint(value INTEGER); INSERT INTO checkpoint VALUES (42);",
                )
                .expect("commit");
            let mode: String = connection
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .expect("journal mode");
            assert_eq!(mode.to_ascii_lowercase(), "wal");
            let synchronous: i64 = connection
                .query_row("PRAGMA synchronous", [], |row| row.get(0))
                .expect("synchronous");
            assert_eq!(synchronous, 2);
        }
        assert_eq!(
            fs::metadata(&root).expect("directory").permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).expect("database").permissions().mode() & 0o777,
            0o600
        );
        let reopened = StateDb::open(path).expect("reopen");
        let value: i64 = reopened
            .connection()
            .expect("connection")
            .query_row("SELECT value FROM checkpoint", [], |row| row.get(0))
            .expect("committed value");
        assert_eq!(value, 42);
        drop(reopened);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
