//! Resolve startup inputs once; services receive validated, immutable settings.
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use crate::ec2_runtime::Ec2RuntimeConfig;
use locallycloud_apigateway::ApiGatewayConfig;
use locallycloud_cloudformation::CloudFormationConfig;
use locallycloud_core::config::LocallyCloudConfig;
use locallycloud_core::observability::{LogColor, LogFormat, LoggingConfig};
use locallycloud_iam_sts::{IamConfig, IamCredentials};
use locallycloud_lambda::config::{LambdaExecutionConfig, ResolvedLambdaExecutionConfig};
use locallycloud_state::StateDb;
use serde::{Deserialize, Deserializer};
use tokio::io::AsyncReadExt;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("invalid startup configuration: {0}")]
    Invalid(String),
    #[error("configuration file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid configuration document at line {line}, column {column}; check field names and types")]
    Document { line: usize, column: usize },
    #[error(transparent)]
    State(#[from] locallycloud_state::StateError),
    #[error("state startup task failed")]
    StateTask,
}

pub struct StartupConfig {
    pub common: LocallyCloudConfig,
    pub iam: IamConfig,
    pub iam_credentials: IamCredentials,
    pub lambda: ResolvedLambdaExecutionConfig,
    pub ec2: Ec2RuntimeConfig,
    pub cloudformation: CloudFormationConfig,
    pub apigateway: ApiGatewayConfig,
    pub state: StateConfig,
    pub logging: LoggingConfig,
}

pub struct StateConfig {
    pub path: PathBuf,
}

impl StateConfig {
    pub async fn open(&self) -> Result<StateDb, StartupError> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || StateDb::open(path))
            .await
            .map_err(|_| StartupError::StateTask)?
            .map_err(StartupError::from)
    }
}

// Omitted fields inherit defaults; explicit null is a configuration error.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CommonOverrides {
    #[serde(deserialize_with = "present")]
    host: Option<String>,
    #[serde(deserialize_with = "present")]
    port: Option<u16>,
    #[serde(deserialize_with = "present")]
    region: Option<String>,
    #[serde(deserialize_with = "present")]
    account_id: Option<String>,
    #[serde(deserialize_with = "present")]
    allow_http: Option<bool>,
    #[serde(deserialize_with = "present")]
    ui_enabled: Option<bool>,
    #[serde(deserialize_with = "present")]
    upstream_timeout_secs: Option<u64>,
    #[serde(deserialize_with = "present")]
    max_request_body_bytes: Option<usize>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct StateOverrides {
    #[serde(deserialize_with = "present")]
    path: Option<PathBuf>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    common: CommonOverrides,
    iam: IamConfig,
    lambda: LambdaExecutionConfig,
    ec2: Ec2RuntimeConfig,
    cloudformation: CloudFormationConfig,
    apigateway: ApiGatewayConfig,
    state: StateOverrides,
    logging: LoggingConfig,
}

fn invalid(setting: &str) -> StartupError {
    StartupError::Invalid(format!("{setting} is empty, invalid or not UTF-8"))
}

fn absolute(path: PathBuf, setting: &str) -> Result<PathBuf, StartupError> {
    if !path.is_absolute() {
        return Err(StartupError::Invalid(format!(
            "{setting} must be an absolute path"
        )));
    }
    Ok(path)
}

fn configuration_path(
    get: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Option<(PathBuf, bool)>, StartupError> {
    if let Some(path) = get("LOCALLYCLOUD_CONFIG_FILE") {
        return Ok(Some((
            absolute(path.into(), "LOCALLYCLOUD_CONFIG_FILE")?,
            true,
        )));
    }
    let base = match get("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(path) => absolute(path.into(), "XDG_CONFIG_HOME")?,
        None => match get("HOME").filter(|v| !v.is_empty()) {
            Some(path) => absolute(path.into(), "HOME")?.join(".config"),
            None => return Ok(None),
        },
    };
    Ok(Some((base.join("locallycloud/config.json"), false)))
}

impl StartupConfig {
    pub async fn load() -> Result<Self, StartupError> {
        Self::load_with(&|name| std::env::var_os(name)).await
    }

    async fn load_with(get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, StartupError> {
        let document = match configuration_path(get)? {
            Some((path, explicit)) => read_file(path, explicit).await?,
            None => FileConfig::default(),
        };
        Self::resolve(document, get)
    }

    fn resolve(
        document: FileConfig,
        get: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Self, StartupError> {
        let common = resolve_common(document.common, get)?;
        let mut logging = document.logging;
        if let Some(value) = get("RUST_LOG") {
            logging.filter = value.into_string().map_err(|_| invalid("RUST_LOG"))?;
        }
        if let Some(value) = get("LOCALLYCLOUD_LOG_FORMAT") {
            logging.format = match value.to_str() {
                Some("auto") => LogFormat::Auto,
                Some("pretty") => LogFormat::Pretty,
                Some("json") => LogFormat::Json,
                _ => return Err(invalid("LOCALLYCLOUD_LOG_FORMAT")),
            };
        }
        if let Some(value) = get("LOCALLYCLOUD_LOG_COLOR") {
            logging.color = match value.to_str() {
                Some("auto") => LogColor::Auto,
                Some("always") => LogColor::Always,
                Some("never") => LogColor::Never,
                _ => return Err(invalid("LOCALLYCLOUD_LOG_COLOR")),
            };
        }
        if logging.color == LogColor::Auto && get("NO_COLOR").is_some_and(|value| !value.is_empty())
        {
            logging.color = LogColor::Never;
        }
        logging.validate().map_err(StartupError::Invalid)?;
        let iam = if ["LOCALLYCLOUD_IAM_ENFORCEMENT", "LOCALSTACK_IAM_ENFORCEMENT"]
            .iter()
            .any(|key| get(key).is_some())
        {
            IamConfig::from_lookup(get).map_err(|error| StartupError::Invalid(error.to_string()))?
        } else {
            document.iam
        };
        let iam_credentials = IamCredentials::from_lookup(&common.account_id, iam, get)
            .map_err(|error| StartupError::Invalid(error.to_string()))?;
        let current_dir = std::env::current_dir()?;
        let lambda = document
            .lambda
            .resolve_with(get, &current_dir)
            .map_err(StartupError::Invalid)?;
        let ec2 = document
            .ec2
            .resolve_with(get, &current_dir)
            .map_err(StartupError::Invalid)?;
        let mut cloudformation = document.cloudformation;
        if let Some(value) = get("LOCALLYCLOUD_CLOUDFORMATION_OPERATION_CAPACITY") {
            cloudformation.operation_capacity = value
                .to_str()
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| invalid("LOCALLYCLOUD_CLOUDFORMATION_OPERATION_CAPACITY"))?;
        }
        cloudformation.validate().map_err(StartupError::Invalid)?;
        let mut apigateway = document.apigateway;
        for (name, target) in [
            (
                "LOCALLYCLOUD_APIGATEWAY_HTTP_CLIENT_CACHE_CAPACITY",
                &mut apigateway.http_client_cache_capacity,
            ),
            (
                "LOCALLYCLOUD_APIGATEWAY_HTTP_MAX_IDLE_PER_HOST",
                &mut apigateway.http_max_idle_per_host,
            ),
            (
                "LOCALLYCLOUD_APIGATEWAY_HTTP_IDLE_TIMEOUT_SECS",
                &mut apigateway.http_idle_timeout_secs,
            ),
            (
                "LOCALLYCLOUD_APIGATEWAY_WEBSOCKET_OUTBOUND_CHANNEL_CAPACITY",
                &mut apigateway.websocket_outbound_channel_capacity,
            ),
            (
                "LOCALLYCLOUD_APIGATEWAY_WEBSOCKET_OUTBOUND_HISTORY_CAPACITY",
                &mut apigateway.websocket_outbound_history_capacity,
            ),
            (
                "LOCALLYCLOUD_APIGATEWAY_AUTHORIZER_CACHE_CAPACITY",
                &mut apigateway.authorizer_cache_capacity,
            ),
        ] {
            if let Some(value) = get(name) {
                *target = value
                    .to_str()
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| invalid(name))?;
            }
        }
        if let Some(value) = get("LOCALLYCLOUD_HTTP_INTEGRATION_LOCAL_ORIGINS") {
            apigateway.http_local_origins = serde_json::from_str(
                value
                    .to_str()
                    .ok_or_else(|| invalid("LOCALLYCLOUD_HTTP_INTEGRATION_LOCAL_ORIGINS"))?,
            )
            .map_err(|_| invalid("LOCALLYCLOUD_HTTP_INTEGRATION_LOCAL_ORIGINS"))?;
        }
        apigateway.validate().map_err(StartupError::Invalid)?;
        let path = match get("LOCALLYCLOUD_STATE_DB") {
            Some(path) => absolute(path.into(), "LOCALLYCLOUD_STATE_DB")?,
            None => match document.state.path {
                Some(path) => absolute(path, "state.path")?,
                None => StateDb::default_path_from_lookup(get)?,
            },
        };
        Ok(Self {
            common,
            iam,
            iam_credentials,
            lambda,
            ec2,
            cloudformation,
            apigateway,
            state: StateConfig { path },
            logging,
        })
    }
}

async fn read_file(path: PathBuf, explicit: bool) -> Result<FileConfig, StartupError> {
    let file = match tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
        .await
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !explicit => {
            return Ok(FileConfig::default())
        }
        Err(error) => return Err(error.into()),
    };
    if !file.metadata().await?.is_file() {
        return Err(StartupError::Invalid(
            "configuration must be a regular JSON file".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(StartupError::Invalid("configuration exceeds 64 KiB".into()));
    }
    serde_json::from_slice(&bytes).map_err(|error| StartupError::Document {
        line: error.line(),
        column: error.column(),
    })
}

fn resolve_common(
    values: CommonOverrides,
    get: &dyn Fn(&str) -> Option<OsString>,
) -> Result<LocallyCloudConfig, StartupError> {
    let bindings: &[(&[&str], Option<String>)] = &[
        (&["LOCALLYCLOUD_HOST", "LOCALSTACK_HOST"], values.host),
        (
            &["LOCALLYCLOUD_PORT", "LOCALSTACK_PORT"],
            values.port.map(|v| v.to_string()),
        ),
        (
            &[
                "LOCALLYCLOUD_DEFAULT_REGION",
                "AWS_REGION",
                "AWS_DEFAULT_REGION",
                "LOCALSTACK_DEFAULT_REGION",
            ],
            values.region,
        ),
        (
            &["LOCALLYCLOUD_ACCOUNT_ID", "LOCALSTACK_ACCOUNT_ID"],
            values.account_id,
        ),
        (
            &["LOCALLYCLOUD_ALLOW_HTTP"],
            values.allow_http.map(|v| v.to_string()),
        ),
        (
            &["LOCALLYCLOUD_UI"],
            values
                .ui_enabled
                .map(|v| if v { "on" } else { "off" }.into()),
        ),
        (
            &[
                "LOCALLYCLOUD_UPSTREAM_TIMEOUT_SECS",
                "LOCALSTACK_UPSTREAM_TIMEOUT_SECS",
            ],
            values.upstream_timeout_secs.map(|v| v.to_string()),
        ),
        (
            &[
                "LOCALLYCLOUD_MAX_REQUEST_BODY_BYTES",
                "LOCALSTACK_MAX_REQUEST_BODY_BYTES",
            ],
            values.max_request_body_bytes.map(|v| v.to_string()),
        ),
    ];
    let mut defaults = BTreeMap::new();
    for (names, value) in bindings {
        if let Some(value) = value {
            if value.is_empty() {
                return Err(invalid(names[0]));
            }
            if !names.iter().any(|name| get(name).is_some()) {
                defaults.insert(names[0], value.clone());
            }
        }
    }
    // Adapt Core's existing infallible lookup without treating invalid OS values as absent.
    let invalid_settings = RefCell::new(Vec::new());
    let config = LocallyCloudConfig::resolve(&|name| match get(name) {
        Some(value) => match value.into_string() {
            Ok(value) if !value.is_empty() => Some(value),
            _ => {
                invalid_settings.borrow_mut().push(name.to_owned());
                Some(String::new())
            }
        },
        None => defaults.get(name).cloned(),
    });
    let config = config.map_err(|error| StartupError::Invalid(error.to_string()))?;
    for setting in invalid_settings.into_inner() {
        if !config.ignored_settings.contains(&setting.as_str()) {
            return Err(invalid(&setting));
        }
    }
    if config.default_region.is_empty()
        || config.account_id.len() != 12
        || !config.account_id.bytes().all(|b| b.is_ascii_digit())
        || config.max_request_body_bytes == 0
        || config.upstream_timeout.is_zero()
    {
        return Err(StartupError::Invalid(
            "common requires a region, a 12-digit account, and positive request/timeout limits"
                .into(),
        ));
    }
    Ok(config)
}

#[cfg(test)]
#[path = "startup_config/tests.rs"]
mod tests;
