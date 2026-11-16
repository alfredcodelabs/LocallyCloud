//! Operational execution settings resolved once by the composition root.
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer};

fn path_override<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<PathBuf>, D::Error> {
    PathBuf::deserialize(deserializer).map(Some)
}

pub(crate) const DEFAULT_MAX_WARM_TOTAL: usize = 16;
pub(crate) const DEFAULT_MEMORY_BUDGET_MB: u64 = 4096;
pub(crate) const DEFAULT_MAX_WARM_PER_KEY: usize = 10;
pub(crate) const DEFAULT_WARM_IDLE_TIMEOUT_SECS: u64 = 300;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LambdaExecutionConfig {
    pub max_warm_total: usize,
    pub memory_budget_mb: u64,
    pub max_warm_per_key: usize,
    pub warm_idle_timeout_secs: u64,
    #[serde(deserialize_with = "path_override")]
    pub work_dir: Option<PathBuf>,
    #[serde(deserialize_with = "path_override")]
    pub runtime_packs_dir: Option<PathBuf>,
}

impl Default for LambdaExecutionConfig {
    fn default() -> Self {
        Self {
            max_warm_total: DEFAULT_MAX_WARM_TOTAL,
            memory_budget_mb: DEFAULT_MEMORY_BUDGET_MB,
            max_warm_per_key: DEFAULT_MAX_WARM_PER_KEY,
            warm_idle_timeout_secs: DEFAULT_WARM_IDLE_TIMEOUT_SECS,
            work_dir: None,
            runtime_packs_dir: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedLambdaExecutionConfig {
    pub max_warm_total: usize,
    pub memory_budget_mb: u64,
    pub max_warm_per_key: usize,
    pub warm_idle_timeout_secs: u64,
    pub work_dir: PathBuf,
    pub runtime_packs_dir: PathBuf,
}

impl ResolvedLambdaExecutionConfig {
    pub fn validate(&self) -> Result<(), String> {
        LambdaExecutionConfig {
            max_warm_total: self.max_warm_total,
            memory_budget_mb: self.memory_budget_mb,
            max_warm_per_key: self.max_warm_per_key,
            warm_idle_timeout_secs: self.warm_idle_timeout_secs,
            work_dir: None,
            runtime_packs_dir: None,
        }
        .validate()?;
        if !self.work_dir.is_absolute() || !self.runtime_packs_dir.is_absolute() {
            return Err("Resolved Lambda execution directories must be absolute".into());
        }
        Ok(())
    }
}

impl LambdaExecutionConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_warm_total > 1024 {
            return Err("lambda.max_warm_total must be between 0 and 1024".into());
        }
        if !(1..=1024).contains(&self.max_warm_per_key) {
            return Err("lambda.max_warm_per_key must be between 1 and 1024".into());
        }
        if !(1..=3600).contains(&self.warm_idle_timeout_secs) {
            return Err("lambda.warm_idle_timeout_secs must be between 1 and 3600".into());
        }
        if !(1..=u64::from(u32::MAX)).contains(&self.memory_budget_mb) {
            return Err("lambda.memory_budget_mb must be between 1 and 4294967295".into());
        }
        for (name, path) in [
            ("work_dir", &self.work_dir),
            ("runtime_packs_dir", &self.runtime_packs_dir),
        ] {
            if path
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            {
                return Err(format!("lambda.{name} must not be empty"));
            }
        }
        Ok(())
    }

    pub fn resolve_with(
        mut self,
        get: &dyn Fn(&str) -> Option<OsString>,
        current_dir: &Path,
    ) -> Result<ResolvedLambdaExecutionConfig, String> {
        if let Some(value) = get("LOCALLYCLOUD_LAMBDA_MAX_WARM_TOTAL") {
            self.max_warm_total = value
                .to_str()
                .and_then(|raw| raw.parse().ok())
                .ok_or("LOCALLYCLOUD_LAMBDA_MAX_WARM_TOTAL must be an integer")?;
        }
        if let Some(value) = get("LOCALLYCLOUD_LAMBDA_MAX_WARM_PER_KEY") {
            self.max_warm_per_key = value
                .to_str()
                .and_then(|raw| raw.parse().ok())
                .ok_or("LOCALLYCLOUD_LAMBDA_MAX_WARM_PER_KEY must be an integer")?;
        }
        if let Some(value) = get("LOCALLYCLOUD_LAMBDA_WARM_IDLE_TIMEOUT_SECS") {
            self.warm_idle_timeout_secs = value
                .to_str()
                .and_then(|raw| raw.parse().ok())
                .ok_or("LOCALLYCLOUD_LAMBDA_WARM_IDLE_TIMEOUT_SECS must be an integer")?;
        }
        if let Some(value) = get("LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB") {
            self.memory_budget_mb = value
                .to_str()
                .and_then(|raw| raw.parse().ok())
                .ok_or("LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB must be an integer")?;
        }
        for (name, target) in [
            ("LOCALLYCLOUD_WORK_DIR", &mut self.work_dir),
            (
                "LOCALLYCLOUD_RUNTIME_PACKS_DIR",
                &mut self.runtime_packs_dir,
            ),
        ] {
            if let Some(value) = get(name) {
                *target = Some(value.into());
            }
        }
        self.validate()?;
        if !current_dir.is_absolute() {
            return Err("Lambda startup current directory must be absolute".into());
        }
        let absolute = |path: PathBuf| {
            if path.is_absolute() {
                path
            } else {
                current_dir.join(path)
            }
        };
        let work_dir = match self.work_dir {
            Some(path) => absolute(path),
            None => {
                if let Some(path) = get("XDG_CACHE_HOME")
                    .map(PathBuf::from)
                    .filter(|path| path.is_absolute())
                {
                    path.join("locallycloud/lambda")
                } else if let Some(path) = get("HOME")
                    .map(PathBuf::from)
                    .filter(|path| path.is_absolute())
                {
                    path.join(".cache/locallycloud/lambda")
                } else {
                    let temporary = get("TMPDIR")
                        .filter(|value| !value.is_empty())
                        .map(PathBuf::from)
                        .unwrap_or_else(|| PathBuf::from("/tmp"));
                    if !temporary.is_absolute() {
                        return Err("TMPDIR must be absolute".into());
                    }
                    temporary.join(format!("locallycloud-lambda-{}", unsafe {
                        libc::geteuid()
                    }))
                }
            }
        };
        let runtime_packs_dir = self
            .runtime_packs_dir
            .map(absolute)
            .unwrap_or_else(|| work_dir.join("runtime-packs"));
        Ok(ResolvedLambdaExecutionConfig {
            max_warm_total: self.max_warm_total,
            memory_budget_mb: self.memory_budget_mb,
            max_warm_per_key: self.max_warm_per_key,
            warm_idle_timeout_secs: self.warm_idle_timeout_secs,
            work_dir,
            runtime_packs_dir,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_defaults_file_and_environment_without_process_mutation() {
        let get = |name: &str| (name == "HOME").then(|| OsString::from("/owned/home"));
        let defaults = LambdaExecutionConfig::default()
            .resolve_with(&get, Path::new("/owned/cwd"))
            .unwrap();
        assert_eq!(defaults.max_warm_total, 16);
        assert_eq!(defaults.memory_budget_mb, 4096);
        assert_eq!(defaults.max_warm_per_key, 10);
        assert_eq!(defaults.warm_idle_timeout_secs, 300);
        assert_eq!(
            defaults.work_dir,
            Path::new("/owned/home/.cache/locallycloud/lambda")
        );
        assert_eq!(
            defaults.runtime_packs_dir,
            defaults.work_dir.join("runtime-packs")
        );
        let file: LambdaExecutionConfig = serde_json::from_str(r#"{"max_warm_total":2,"memory_budget_mb":512,"max_warm_per_key":5,"warm_idle_timeout_secs":10,"work_dir":"local-work","runtime_packs_dir":"local-packs"}"#).unwrap();
        let resolved = file
            .clone()
            .resolve_with(&get, Path::new("/owned/cwd"))
            .unwrap();
        assert_eq!(
            (resolved.max_warm_per_key, resolved.warm_idle_timeout_secs),
            (5, 10)
        );
        assert_eq!(resolved.work_dir, Path::new("/owned/cwd/local-work"));
        assert_eq!(
            resolved.runtime_packs_dir,
            Path::new("/owned/cwd/local-packs")
        );
        let env = |name: &str| match name {
            "LOCALLYCLOUD_LAMBDA_MAX_WARM_TOTAL" => Some("0".into()),
            "LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB" => Some("1024".into()),
            "LOCALLYCLOUD_LAMBDA_MAX_WARM_PER_KEY" => Some("3".into()),
            "LOCALLYCLOUD_LAMBDA_WARM_IDLE_TIMEOUT_SECS" => Some("30".into()),
            "LOCALLYCLOUD_WORK_DIR" => Some("/env/work".into()),
            "LOCALLYCLOUD_RUNTIME_PACKS_DIR" => Some("/env/packs".into()),
            _ => None,
        };
        let resolved = file.resolve_with(&env, Path::new("/owned/cwd")).unwrap();
        assert_eq!(
            (resolved.max_warm_total, resolved.memory_budget_mb),
            (0, 1024)
        );
        assert_eq!(
            (resolved.max_warm_per_key, resolved.warm_idle_timeout_secs),
            (3, 30)
        );
        assert_eq!(resolved.work_dir, Path::new("/env/work"));
        assert_eq!(resolved.runtime_packs_dir, Path::new("/env/packs"));
    }

    #[test]
    fn global_warm_limit_configuration_is_validated() {
        let resolve = |value: Option<&str>| {
            LambdaExecutionConfig::default().resolve_with(
                &|key| {
                    (key == "LOCALLYCLOUD_LAMBDA_MAX_WARM_TOTAL")
                        .then(|| value.map(OsString::from))
                        .flatten()
                },
                Path::new("/owned"),
            )
        };
        assert_eq!(resolve(None).unwrap().max_warm_total, 16);
        assert_eq!(resolve(Some("0")).unwrap().max_warm_total, 0);
        assert_eq!(resolve(Some("1024")).unwrap().max_warm_total, 1024);
        for value in ["", "-1", "1.5", "1025", "many"] {
            assert!(resolve(Some(value)).is_err());
        }
        for value in ["0", "-1", "oops", "18446744073709551615"] {
            assert!(LambdaExecutionConfig::default()
                .resolve_with(
                    &|key| (key == "LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB")
                        .then(|| OsString::from(value)),
                    Path::new("/owned")
                )
                .is_err());
        }
    }

    #[test]
    fn rejects_invalid_operational_settings() {
        for document in [
            r#"{"max_warm_total":null}"#,
            r#"{"memory_budget_mb":null}"#,
            r#"{"max_warm_per_key":null}"#,
            r#"{"warm_idle_timeout_secs":null}"#,
            r#"{"typo":1}"#,
            r#"{"work_dir":null}"#,
            r#"{"runtime_packs_dir":null}"#,
        ] {
            assert!(serde_json::from_str::<LambdaExecutionConfig>(document).is_err());
        }
        for (name, value) in [
            ("LOCALLYCLOUD_LAMBDA_MAX_WARM_TOTAL", "1025"),
            ("LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB", "0"),
            ("LOCALLYCLOUD_LAMBDA_MAX_WARM_PER_KEY", "0"),
            ("LOCALLYCLOUD_LAMBDA_MAX_WARM_PER_KEY", "1025"),
            ("LOCALLYCLOUD_LAMBDA_WARM_IDLE_TIMEOUT_SECS", "0"),
            ("LOCALLYCLOUD_LAMBDA_WARM_IDLE_TIMEOUT_SECS", "3601"),
            ("LOCALLYCLOUD_WORK_DIR", ""),
            ("LOCALLYCLOUD_RUNTIME_PACKS_DIR", ""),
        ] {
            assert!(LambdaExecutionConfig::default()
                .resolve_with(
                    &|key| (key == name).then(|| value.into()),
                    Path::new("/owned")
                )
                .is_err());
        }
    }
}
