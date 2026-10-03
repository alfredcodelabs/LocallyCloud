//! Runtime selection and KVM detection.
//!
//! Selects `FirecrackerRuntime` when `/dev/kvm` is usable, otherwise `YoukiRuntime`,
//! honouring an explicit configuration override and hard-failing if Firecracker is
//! forced without KVM. See Requirement 14.

use std::path::Path;

/// Which compute backend to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeKind {
    Firecracker,
    Youki,
}

/// Why selection terminated startup.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectionError {
    #[error("FirecrackerRuntime was requested but /dev/kvm is unavailable")]
    FirecrackerRequiresKvm,
}

pub struct RuntimeSelector;

impl RuntimeSelector {
    /// Whether `/dev/kvm` exists and is readable + writable by the current process.
    pub fn check_kvm_availability() -> bool {
        kvm_usable(Path::new("/dev/kvm"))
    }

    /// Decide the backend (Req 14.1–14.4):
    /// - explicit override wins; `Firecracker` without KVM is a hard error,
    /// - otherwise `Firecracker` when KVM is available, else `Youki`.
    pub fn select(
        config_override: Option<RuntimeKind>,
        kvm_available: bool,
    ) -> Result<RuntimeKind, SelectionError> {
        match config_override {
            Some(RuntimeKind::Firecracker) => {
                if kvm_available {
                    Ok(RuntimeKind::Firecracker)
                } else {
                    Err(SelectionError::FirecrackerRequiresKvm)
                }
            }
            Some(RuntimeKind::Youki) => Ok(RuntimeKind::Youki),
            None if kvm_available => Ok(RuntimeKind::Firecracker),
            None => Ok(RuntimeKind::Youki),
        }
    }
}

/// Check that a path exists and the current process can read and write it.
fn kvm_usable(path: &Path) -> bool {
    use std::fs::OpenOptions;
    path.exists() && OpenOptions::new().read(true).write(true).open(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_selects_firecracker_when_kvm_present() {
        assert_eq!(
            RuntimeSelector::select(None, true),
            Ok(RuntimeKind::Firecracker)
        );
    }

    #[test]
    fn auto_selects_youki_without_kvm() {
        assert_eq!(RuntimeSelector::select(None, false), Ok(RuntimeKind::Youki));
    }

    #[test]
    fn override_youki_is_honored_regardless_of_kvm() {
        assert_eq!(
            RuntimeSelector::select(Some(RuntimeKind::Youki), true),
            Ok(RuntimeKind::Youki)
        );
    }

    #[test]
    fn override_firecracker_with_kvm_ok() {
        assert_eq!(
            RuntimeSelector::select(Some(RuntimeKind::Firecracker), true),
            Ok(RuntimeKind::Firecracker)
        );
    }

    #[test]
    fn override_firecracker_without_kvm_is_hard_error() {
        assert_eq!(
            RuntimeSelector::select(Some(RuntimeKind::Firecracker), false),
            Err(SelectionError::FirecrackerRequiresKvm)
        );
    }
}
