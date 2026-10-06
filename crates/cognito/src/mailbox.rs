//! Opt-in local delivery: private atomic files, never API responses or logs.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

pub struct ConfirmationMailbox {
    root: PathBuf,
}

impl ConfirmationMailbox {
    pub fn new(root: PathBuf) -> Result<Self, String> {
        if !root.is_absolute() {
            return Err("Cognito mailbox directory must be absolute".into());
        }
        if !root.exists() {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .map_err(|_| "Cannot create Cognito mailbox directory")?;
        }
        let metadata =
            fs::symlink_metadata(&root).map_err(|_| "Cannot inspect Cognito mailbox directory")?;
        let owner = fs::metadata("/proc/self")
            .map_err(|_| "Cannot resolve mailbox owner")?
            .uid();
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.mode() & 0o777 != 0o700
            || metadata.uid() != owner
        {
            return Err(
                "Cognito mailbox directory must be owned by this user with mode 0700".into(),
            );
        }
        let canonical =
            fs::canonicalize(&root).map_err(|_| "Cannot resolve Cognito mailbox directory")?;
        if canonical != root {
            return Err(
                "Cognito mailbox directory must be canonical and contain no symlinks".into(),
            );
        }
        Ok(Self { root })
    }

    pub(crate) fn deliver(&self, message: &serde_json::Value) -> Result<(), crate::CognitoError> {
        use crate::CognitoError;
        let temporary = self
            .root
            .join(format!(".{}.tmp", crate::crypto::opaque_token()));
        let destination = self
            .root
            .join(format!("{}.json", crate::crypto::opaque_token()));
        let result = (|| {
            // O_NOFOLLOW is a Linux platform flag; create_new also rejects existing links.
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(0x20000)
                .open(&temporary)?;
            serde_json::to_writer(&mut file, message)?;
            file.flush()?;
            file.sync_all()?;
            fs::rename(&temporary, &destination)?;
            fs::File::open(&self.root)?.sync_all()?;
            Ok::<_, std::io::Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
            let _ = fs::remove_file(&destination);
        }
        result.map_err(|_| CognitoError::CodeDeliveryFailure)
    }
}

use std::os::unix::fs::DirBuilderExt;
