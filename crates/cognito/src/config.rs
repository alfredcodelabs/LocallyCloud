//! Opt-in confirmation mailbox location; no passwords, codes or keys belong in configuration.
use serde::Deserialize;
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CognitoConfig {
    #[serde(deserialize_with = "mailbox_path")]
    pub mailbox_dir: Option<PathBuf>,
}
impl CognitoConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.mailbox_dir.as_ref().is_some_and(|p| !p.is_absolute()) {
            return Err("cognito.mailbox_dir must be an absolute path".into());
        }
        Ok(())
    }
    pub fn resolve_with(mut self, get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        if let Some(value) = get("LOCALLYCLOUD_COGNITO_MAILBOX_DIR") {
            self.mailbox_dir = Some(value.into());
        }
        self.validate()?;
        Ok(self)
    }
}

fn mailbox_path<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PathBuf>, D::Error> {
    PathBuf::deserialize(deserializer).map(Some)
}
