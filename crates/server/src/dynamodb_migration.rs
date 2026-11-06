//! Explicit offline native inspection and verified ExtendDB cutover.
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use locallycloud_dynamodb::error::DdbError;
use locallycloud_dynamodb::migration::InspectionSummary;
use locallycloud_state::{StateCipher, StateDb};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Completion {
    kind: &'static str,
    inspection_only: bool,
    #[serde(flatten)]
    summary: InspectionSummary,
    next_step: &'static str,
}

fn write_json(output: &mut impl Write, value: &impl Serialize) -> Result<(), DdbError> {
    serde_json::to_writer(&mut *output, value)
        .map_err(|_| DdbError::Internal("Cannot write migration inspection output".into()))?;
    output
        .write_all(b"\n")
        .map_err(|_| DdbError::Internal("Cannot write migration inspection output".into()))
}

fn lock_source(path: &Path) -> Result<std::fs::File, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "Native source database must already exist".to_owned())?;
    let parent = path
        .parent()
        .ok_or("Native source database has no parent directory")?;
    let directory =
        fs::symlink_metadata(parent).map_err(|_| "Cannot inspect source directory".to_owned())?;
    // SAFETY: geteuid takes no pointers and has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
        || !directory.is_dir()
        || directory.file_type().is_symlink()
        || directory.uid() != uid
        || directory.permissions().mode() & 0o077 != 0
    {
        return Err(
            "Native source database and directory must be private, user-owned regular paths".into(),
        );
    }
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".runtime.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path)
        .map_err(|_| "Cannot open the source runtime lock".to_owned())?;
    lock.try_lock()
        .map_err(|_| "Stop the server before inspecting native DynamoDB state".to_owned())?;
    Ok(lock)
}

fn inspect_path(path: &Path, cipher: &StateCipher, output: &mut impl Write) -> Result<(), String> {
    let _lock = lock_source(path)?;
    let summary = locallycloud_dynamodb::migration::inspect_native(path, cipher, |table| {
        write_json(
            output,
            &serde_json::json!({"kind":"table-inspection","inspectionOnly":true,"table":table}),
        )
    })
    .map_err(|error| error.to_string())?;
    write_json(output,&Completion {kind:"summary",inspection_only:true,summary,
        next_step:"Run migrate-dynamodb --apply offline to migrate supported state; blockers must be resolved first"})
        .map_err(|error|error.to_string())
}

pub async fn inspect() -> Result<(), String> {
    tokio::task::spawn_blocking(|| {
        let path = StateDb::default_path().map_err(|error| error.to_string())?;
        let cipher = StateCipher::from_env().map_err(|error| error.to_string())?;
        inspect_path(&path, &cipher, &mut io::stdout().lock())
    })
    .await
    .map_err(|_| "Migration inspection task failed".to_owned())?
}

#[path = "dynamodb_migration_apply.rs"]
mod cutover;
pub(crate) use cutover::{apply, ensure_no_pending};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_does_not_create_a_missing_source_or_lock_file() {
        let root = std::env::temp_dir().join(format!(
            "dynamodb-migration-missing-{}",
            uuid::Uuid::new_v4()
        ));
        let mut output = Vec::new();
        assert!(inspect_path(
            &root.join("state.db"),
            &StateCipher::with_key(&[1; 32]),
            &mut output
        )
        .is_err());
        assert!(!root.exists());
        assert!(output.is_empty());
    }

    #[test]
    fn active_runtime_blocks_inspection_without_changing_source() {
        let root =
            std::env::temp_dir().join(format!("dynamodb-migration-lock-{}", uuid::Uuid::new_v4()));
        let state = StateDb::open(root.join("state.db")).unwrap();
        let runtime = state.lock_runtime().unwrap();
        let before = fs::read(state.path()).unwrap();
        let mut output = Vec::new();
        assert!(
            inspect_path(state.path(), &StateCipher::with_key(&[1; 32]), &mut output)
                .unwrap_err()
                .contains("Stop the server")
        );
        assert!(output.is_empty());
        assert_eq!(fs::read(state.path()).unwrap(), before);
        drop(runtime);
        inspect_path(state.path(), &StateCipher::with_key(&[1; 32]), &mut output).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["applyReady"], false);
        assert_eq!(result["inspectionOnly"], true);
        assert_eq!(result["sourceKeyAuthenticated"], false);
        assert_eq!(fs::read(state.path()).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_symlinks_are_refused_without_output() {
        let root = std::env::temp_dir().join(format!(
            "dynamodb-migration-symlink-{}",
            uuid::Uuid::new_v4()
        ));
        let state = StateDb::open(root.join("state.db")).unwrap();
        let link = root.join("link.db");
        std::os::unix::fs::symlink(state.path(), &link).unwrap();
        let mut output = Vec::new();
        assert!(inspect_path(&link, &StateCipher::with_key(&[1; 32]), &mut output).is_err());
        assert!(output.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
