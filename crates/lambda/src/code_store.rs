//! Lambda code store: validate a Zip package, extract it to a unique directory
//! (rejecting path-traversal entries), and record its base64 SHA-256 and size.
//!
//! Each cold start gets its own directory under `<root>/<account>/<region>/<name>/`.
//! Concurrent starts must not delete or overwrite each other's extracted code.

use std::fs;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::LambdaError;

/// Maximum total unzipped size accepted for a function package (AWS limit: 250 MB).
pub const MAX_UNZIPPED_SIZE: u64 = 262_144_000;

/// The result of storing a code package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCode {
    /// Directory containing the extracted code (the future `LAMBDA_TASK_ROOT`).
    pub dir: PathBuf,
    /// Base64-encoded SHA-256 of the original package bytes (AWS `CodeSha256`).
    pub code_sha256: String,
    /// Size of the original package bytes.
    pub code_size: u64,
}

/// On-disk store for extracted function code.
pub struct CodeStore {
    root: PathBuf,
}

impl CodeStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        CodeStore { root: root.into() }
    }

    fn function_dir(&self, account: &str, region: &str, name: &str) -> PathBuf {
        self.root.join(account).join(region).join(name)
    }

    /// Validate and extract a Zip package for a function, returning its directory + digest.
    /// Each extraction is isolated so concurrent cold starts cannot remove each other's code.
    pub fn store_zip(
        &self,
        account: &str,
        region: &str,
        name: &str,
        zip_bytes: &[u8],
    ) -> Result<StoredCode, LambdaError> {
        let code_sha256 = BASE64.encode(Sha256::digest(zip_bytes));
        let code_size = zip_bytes.len() as u64;

        let dir = self
            .function_dir(account, region, name)
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&dir).map_err(|e| {
            LambdaError::InternalError(format!("could not create code directory: {e}"))
        })?;

        if let Err(error) = extract_zip_into(zip_bytes, &dir) {
            let _ = fs::remove_dir_all(&dir);
            return Err(error);
        }

        Ok(StoredCode {
            dir,
            code_sha256,
            code_size,
        })
    }

    /// Remove extracted code before reporting a function deletion as complete.
    pub fn remove(&self, account: &str, region: &str, name: &str) -> Result<(), LambdaError> {
        match fs::remove_dir_all(self.function_dir(account, region, name)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(LambdaError::InternalError(format!(
                "function code cleanup failed: {error}"
            ))),
        }
    }
}

/// Validate a Zip archive before a control-plane mutation. This reads every entry so malformed
/// compressed data is rejected immediately, checks traversal, and enforces the unzipped-size cap.
pub fn validate_zip(zip_bytes: &[u8]) -> Result<(), LambdaError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes))
        .map_err(|e| LambdaError::InvalidParameterValue(format!("invalid Zip archive: {e}")))?;
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|e| LambdaError::InvalidParameterValue(format!("invalid Zip entry: {e}")))?;
        if entry.enclosed_name().is_none() {
            return Err(LambdaError::InvalidParameterValue(format!(
                "Zip entry escapes the archive root: {}",
                entry.name()
            )));
        }
        if entry.is_dir() {
            continue;
        }
        total = total.saturating_add(entry.size());
        if total > MAX_UNZIPPED_SIZE {
            return Err(LambdaError::CodeStorageExceeded(format!(
                "unzipped code exceeds the {MAX_UNZIPPED_SIZE}-byte limit"
            )));
        }
        io::copy(&mut entry, &mut io::sink()).map_err(|e| {
            LambdaError::InvalidParameterValue(format!("could not read Zip entry: {e}"))
        })?;
    }
    Ok(())
}

/// Extract a Zip archive into `dest`, rejecting traversal entries and enforcing the size cap.
fn extract_zip_into(zip_bytes: &[u8], dest: &Path) -> Result<(), LambdaError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes))
        .map_err(|e| LambdaError::InvalidParameterValue(format!("invalid Zip archive: {e}")))?;

    let mut total: u64 = 0;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| LambdaError::InvalidParameterValue(format!("invalid Zip entry: {e}")))?;

        // `enclosed_name` returns `None` for any path that escapes the root (Zip-Slip).
        let relative = match entry.enclosed_name() {
            Some(path) => path,
            None => {
                return Err(LambdaError::InvalidParameterValue(format!(
                    "Zip entry escapes the archive root: {}",
                    entry.name()
                )))
            }
        };
        let target = dest.join(&relative);

        if entry.is_dir() {
            fs::create_dir_all(&target).map_err(|e| {
                LambdaError::InternalError(format!("could not create directory: {e}"))
            })?;
            continue;
        }

        total = total.saturating_add(entry.size());
        if total > MAX_UNZIPPED_SIZE {
            return Err(LambdaError::CodeStorageExceeded(format!(
                "unzipped code exceeds the {MAX_UNZIPPED_SIZE}-byte limit"
            )));
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                LambdaError::InternalError(format!("could not create directory: {e}"))
            })?;
        }
        let mut contents = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut contents).map_err(|e| {
            LambdaError::InvalidParameterValue(format!("could not read Zip entry: {e}"))
        })?;
        fs::write(&target, &contents)
            .map_err(|e| LambdaError::InternalError(format!("could not write code file: {e}")))?;

        // Preserve the executable bit (so a custom-runtime `bootstrap` stays runnable).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = entry.unix_mode().unwrap_or(0o644);
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode(mode));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn temp_root() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lc-codestore-{}", uuid::Uuid::new_v4()));
        dir
    }

    /// Build an in-memory zip from `(name, contents)` entries.
    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default();
            for (name, contents) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(contents).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    #[test]
    fn extracts_files_and_computes_digest() {
        let root = temp_root();
        let store = CodeStore::new(&root);
        let zip = make_zip(&[
            ("bootstrap", b"#!/bin/sh\necho hi\n"),
            ("lib/util.js", b"x"),
        ]);
        let stored = store.store_zip("0", "us-east-1", "fn", &zip).unwrap();

        assert!(stored.dir.join("bootstrap").exists());
        assert!(stored.dir.join("lib/util.js").exists());
        assert_eq!(stored.code_size, zip.len() as u64);
        assert_eq!(stored.code_sha256, BASE64.encode(Sha256::digest(&zip)));
        assert_eq!(
            fs::read(stored.dir.join("bootstrap")).unwrap(),
            b"#!/bin/sh\necho hi\n"
        );

        store.remove("0", "us-east-1", "fn").unwrap();
        assert!(!stored.dir.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_invalid_archive() {
        let root = temp_root();
        let store = CodeStore::new(&root);
        let err = store
            .store_zip("0", "us-east-1", "fn", b"not a zip")
            .unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_path_traversal_entry() {
        let root = temp_root();
        let store = CodeStore::new(&root);
        let zip = make_zip(&[("../escape.txt", b"evil")]);
        let err = store.store_zip("0", "us-east-1", "fn", &zip).unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
        // Nothing escaped the function directory.
        assert!(!root.join("0").join("us-east-1").join("escape.txt").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn concurrent_extractions_keep_independent_code() {
        let root = temp_root();
        let store = CodeStore::new(&root);
        let first = store
            .store_zip("0", "us-east-1", "fn", &make_zip(&[("a.txt", b"1")]))
            .unwrap();
        let second = store
            .store_zip("0", "us-east-1", "fn", &make_zip(&[("b.txt", b"2")]))
            .unwrap();
        assert_ne!(first.dir, second.dir);
        assert_eq!(fs::read(first.dir.join("a.txt")).unwrap(), b"1");
        assert_eq!(fs::read(second.dir.join("b.txt")).unwrap(), b"2");
        let _ = fs::remove_dir_all(&root);
    }
}
