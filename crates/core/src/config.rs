//! Configuration.
//!
//! Native variables use the `LOCALLYCLOUD_*` prefix but the configuration layer is
//! name-independent: each setting is resolved from the native name first, then the
//! `LOCALSTACK_*` compatibility aliases, and the external endpoint also
//! honours the standard `AWS_ENDPOINT_URL`. See Requirements 21, 22 and 23.

use std::net::SocketAddr;
use std::time::Duration;

/// Which compute runtime to use, when overridden explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeChoice {
    Firecracker,
    Youki,
}

/// Shape of the SQS queue URLs returned to clients (`LOCALLYCLOUD_SQS_ENDPOINT_STRATEGY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqsEndpointStrategy {
    /// `<guest endpoint>/<account>/<queue>`: SDKs that use the queue URL as their endpoint
    /// keep calling this instance.
    Path,
    /// `https://sqs.<region>.amazonaws.com/<account>/<queue>`.
    Aws,
}

/// All resolved configuration values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocallyCloudConfig {
    /// TCP address to bind. Default: `127.0.0.1:4566` (loopback only, safe for a local
    /// developer beta); set `LOCALLYCLOUD_HOST` (or its aliases) explicitly to bind an
    /// external interface such as `0.0.0.0`.
    pub listen_addr: SocketAddr,
    /// Legacy backend base URL. Default: `http://localhost:4567`.
    pub legacy_backend_url: String,
    /// Externally-reachable endpoint advertised to compute guests and used for
    /// cross-service calls. `None` means "derive from the listen address". Sourced from
    /// `AWS_ENDPOINT_URL` or `LOCALLYCLOUD_ENDPOINT_URL`.
    pub external_endpoint: Option<String>,
    /// Upstream proxy timeout. Default: 30s.
    pub upstream_timeout: Duration,
    /// Interval between legacy-backend liveness probes. Default: 5s.
    pub legacy_health_check_interval: Duration,
    /// Maximum buffered request body size, in bytes. Requests larger than this are
    /// rejected with HTTP 413. Default: 128 MiB.
    pub max_request_body_bytes: usize,
    /// Graceful shutdown grace period. Default: 5s.
    pub shutdown_grace_period: Duration,
    /// Runtime override: `None` = auto-detect.
    pub runtime_override: Option<RuntimeChoice>,
    /// AWS account id used in ARNs and responses. Default: `000000000000`.
    pub account_id: String,
    /// Default AWS region applied when a request carries none. Default: `us-east-1`.
    pub default_region: String,
    /// Optional AWS control-plane TLS identity, separate from API Gateway custom domains.
    pub tls: Option<ControlPlaneTls>,
    /// Serve the embedded dashboard and its `/_locallycloud/explore/*` read path.
    /// `LOCALLYCLOUD_UI=off` removes every dashboard route. Default: on.
    pub ui_enabled: bool,
    pub lambda_concurrency: LambdaConcurrencyConfig,
    /// Duration of one simulated EventBridge retry second; defaults to real time.
    pub events_retry_second: Duration,
    pub sqs_esm_max_pollers: u32,
    /// Default: [`SqsEndpointStrategy::Path`].
    pub sqs_endpoint_strategy: SqsEndpointStrategy,
}

const LAMBDA_ACCOUNT_CONCURRENCY: &str = "LOCALLYCLOUD_LAMBDA_ACCOUNT_CONCURRENCY";

fn retry_second(get: &dyn Fn(&str) -> Option<String>) -> Result<Duration, ConfigError> {
    let Some(value) = get("LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE") else {
        return Ok(Duration::from_secs(1));
    };
    let scale = value
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && (0.000001..=1.0).contains(value))
        .ok_or_else(|| {
            ConfigError::new(
                "LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE",
                "expected a finite number from 0.000001 to 1",
            )
        })?;
    Ok(Duration::from_secs_f64(scale))
}
const LAMBDA_MIN_UNRESERVED: &str = "LOCALLYCLOUD_LAMBDA_MIN_UNRESERVED_CONCURRENCY";

/// Validated simulation limits. Every account/region receives its own independent pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LambdaConcurrencyConfig {
    account_limit: u32,
    min_unreserved: u32,
}

impl Default for LambdaConcurrencyConfig {
    fn default() -> Self {
        Self {
            account_limit: 1000,
            min_unreserved: 100,
        }
    }
}

impl LambdaConcurrencyConfig {
    pub fn new(account_limit: u32, min_unreserved: u32) -> Result<Self, ConfigError> {
        if account_limit == 0 || account_limit > i32::MAX as u32 {
            return Err(ConfigError::new(
                LAMBDA_ACCOUNT_CONCURRENCY,
                "expected an integer from 1 to 2147483647",
            ));
        }
        if min_unreserved > account_limit {
            return Err(ConfigError::new(LAMBDA_MIN_UNRESERVED, "must be between 0 and LOCALLYCLOUD_LAMBDA_ACCOUNT_CONCURRENCY; set it explicitly when using a quota below 100"));
        }
        Ok(Self {
            account_limit,
            min_unreserved,
        })
    }

    pub fn account_limit(self) -> u32 {
        self.account_limit
    }
    pub fn min_unreserved(self) -> u32 {
        self.min_unreserved
    }

    fn resolve(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let defaults = Self::default();
        let number = |setting, default| match get(setting) {
            Some(value) => value
                .parse::<u32>()
                .map_err(|_| ConfigError::new(setting, "expected a nonnegative decimal integer")),
            None => Ok(default),
        };
        Self::new(
            number(LAMBDA_ACCOUNT_CONCURRENCY, defaults.account_limit)?,
            number(LAMBDA_MIN_UNRESERVED, defaults.min_unreserved)?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneTls {
    pub hostname: String,
    pub certificate_path: String,
    pub private_key_path: String,
}

/// A configuration parsing failure. Carries the setting and the offending value so the
/// caller can emit a precise startup log record (Requirement 21.4).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid value for {setting}: {reason}")]
pub struct ConfigError {
    pub setting: &'static str,
    pub reason: String,
}

impl ConfigError {
    fn new(setting: &'static str, reason: impl Into<String>) -> Self {
        ConfigError {
            setting,
            reason: reason.into(),
        }
    }
}

// Loopback by default so a local beta does not expose the emulator on all interfaces;
// an explicit `LOCALLYCLOUD_HOST` (including `0.0.0.0`) still binds as requested.
const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 4566;
const DEFAULT_LEGACY_BACKEND_URL: &str = "http://localhost:4567";
const DEFAULT_UPSTREAM_TIMEOUT_SECS: u64 = 30;
const DEFAULT_SHUTDOWN_GRACE_SECS: u64 = 5;
const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u64 = 5;
const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 128 * 1024 * 1024;
const DEFAULT_ACCOUNT_ID: &str = "000000000000";
const DEFAULT_REGION: &str = "us-east-1";

impl LocallyCloudConfig {
    /// Resolve configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        for setting in [
            LAMBDA_ACCOUNT_CONCURRENCY,
            LAMBDA_MIN_UNRESERVED,
            "LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE",
            "LOCALLYCLOUD_SQS_ESM_MAX_POLLERS",
        ] {
            if matches!(
                std::env::var(setting),
                Err(std::env::VarError::NotUnicode(_))
            ) {
                return Err(ConfigError::new(
                    setting,
                    "expected a UTF-8 decimal integer",
                ));
            }
        }
        Self::resolve(&|name| std::env::var(name).ok())
    }

    /// Resolve configuration from an arbitrary variable lookup. Each setting falls back to
    /// its documented default independently of the others; the winning variable name for
    /// each value is returned alongside it so startup can log the effective source
    /// (Requirements 21.3, 22.2, 22.5).
    pub fn resolve(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let host = resolve(get, &["LOCALLYCLOUD_HOST", "LOCALSTACK_HOST"])
            .map(|(v, _)| v)
            .unwrap_or_else(|| DEFAULT_HOST.to_string());

        let port = match resolve(get, &["LOCALLYCLOUD_PORT", "LOCALSTACK_PORT"]) {
            Some((v, src)) => v
                .parse::<u16>()
                .map_err(|e| ConfigError::new(src, format!("expected a TCP port: {e}")))?,
            None => DEFAULT_PORT,
        };

        let listen_addr = format!("{host}:{port}")
            .parse::<SocketAddr>()
            .map_err(|e| {
                ConfigError::new("LOCALLYCLOUD_HOST", format!("invalid host/port: {e}"))
            })?;

        let legacy_backend_url = resolve(
            get,
            &[
                "LOCALLYCLOUD_LEGACY_BACKEND_URL",
                "LOCALSTACK_LEGACY_BACKEND_URL",
            ],
        )
        .map(|(v, _)| v)
        .unwrap_or_else(|| DEFAULT_LEGACY_BACKEND_URL.to_string());

        // The standard AWS endpoint override takes priority over the native/alias names,
        // matching what AWS SDKs already honour (Requirement 23.2).
        let external_endpoint = resolve(
            get,
            &[
                "AWS_ENDPOINT_URL",
                "LOCALLYCLOUD_ENDPOINT_URL",
                "LOCALSTACK_ENDPOINT_URL",
            ],
        )
        .map(|(v, _)| v);

        let upstream_timeout = resolve_secs(
            get,
            &[
                "LOCALLYCLOUD_UPSTREAM_TIMEOUT_SECS",
                "LOCALSTACK_UPSTREAM_TIMEOUT_SECS",
            ],
            DEFAULT_UPSTREAM_TIMEOUT_SECS,
        )?;

        let shutdown_grace_period = resolve_secs(
            get,
            &[
                "LOCALLYCLOUD_SHUTDOWN_GRACE_PERIOD_SECS",
                "LOCALSTACK_SHUTDOWN_GRACE_PERIOD_SECS",
            ],
            DEFAULT_SHUTDOWN_GRACE_SECS,
        )?;

        let legacy_health_check_interval = resolve_secs(
            get,
            &[
                "LOCALLYCLOUD_LEGACY_HEALTH_CHECK_INTERVAL_SECS",
                "LOCALSTACK_LEGACY_HEALTH_CHECK_INTERVAL_SECS",
            ],
            DEFAULT_HEALTH_CHECK_INTERVAL_SECS,
        )?;

        let max_request_body_bytes = match resolve(
            get,
            &[
                "LOCALLYCLOUD_MAX_REQUEST_BODY_BYTES",
                "LOCALSTACK_MAX_REQUEST_BODY_BYTES",
            ],
        ) {
            Some((v, src)) => v
                .parse::<usize>()
                .map_err(|e| ConfigError::new(src, format!("expected a byte count: {e}")))?,
            None => DEFAULT_MAX_REQUEST_BODY_BYTES,
        };

        let runtime_override = match resolve(get, &["LOCALLYCLOUD_RUNTIME", "LOCALSTACK_RUNTIME"]) {
            Some((v, src)) => parse_runtime(&v, src)?,
            None => None,
        };

        let account_id = resolve(get, &["LOCALLYCLOUD_ACCOUNT_ID", "LOCALSTACK_ACCOUNT_ID"])
            .map(|(v, _)| v)
            .unwrap_or_else(|| DEFAULT_ACCOUNT_ID.to_string());

        let default_region = resolve(
            get,
            &[
                "LOCALLYCLOUD_DEFAULT_REGION",
                "AWS_REGION",
                "AWS_DEFAULT_REGION",
                "LOCALSTACK_DEFAULT_REGION",
            ],
        )
        .map(|(v, _)| v)
        .unwrap_or_else(|| DEFAULT_REGION.to_string());

        let tls = match (
            get("LOCALLYCLOUD_TLS_HOSTNAME"),
            get("LOCALLYCLOUD_TLS_CERT_PATH"),
            get("LOCALLYCLOUD_TLS_KEY_PATH"),
        ) {
            (None, None, None) => None,
            (Some(hostname), Some(certificate_path), Some(private_key_path))
                if valid_tls_hostname(&hostname)
                    && !certificate_path.is_empty()
                    && !private_key_path.is_empty() =>
            {
                Some(ControlPlaneTls {
                    hostname: hostname.to_ascii_lowercase(),
                    certificate_path,
                    private_key_path,
                })
            }
            _ => {
                return Err(ConfigError::new(
                    "LOCALLYCLOUD_TLS_HOSTNAME",
                    "TLS requires a DNS hostname, certificate path and PKCS#8 key path",
                ))
            }
        };

        let ui_enabled = match resolve(get, &["LOCALLYCLOUD_UI"]) {
            Some((v, src)) => parse_ui(&v, src)?,
            None => true,
        };

        Ok(LocallyCloudConfig {
            listen_addr,
            legacy_backend_url,
            external_endpoint,
            upstream_timeout,
            legacy_health_check_interval,
            max_request_body_bytes,
            shutdown_grace_period,
            runtime_override,
            account_id,
            default_region,
            tls,
            ui_enabled,
            lambda_concurrency: LambdaConcurrencyConfig::resolve(get)?,
            events_retry_second: retry_second(get)?,
            sqs_esm_max_pollers: match get("LOCALLYCLOUD_SQS_ESM_MAX_POLLERS") {
                None => 10,
                Some(value) => value
                    .parse::<u32>()
                    .ok()
                    .filter(|value| (2..=1000).contains(value))
                    .ok_or_else(|| {
                        ConfigError::new(
                            "LOCALLYCLOUD_SQS_ESM_MAX_POLLERS",
                            "expected an integer from 2 to 1000",
                        )
                    })?,
            },
            sqs_endpoint_strategy: match resolve(get, &["LOCALLYCLOUD_SQS_ENDPOINT_STRATEGY"]) {
                Some((v, src)) => parse_sqs_endpoint_strategy(&v, src)?,
                None => SqsEndpointStrategy::Path,
            },
        })
    }
}

fn parse_sqs_endpoint_strategy(
    value: &str,
    src: &'static str,
) -> Result<SqsEndpointStrategy, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "path" => Ok(SqsEndpointStrategy::Path),
        "aws" => Ok(SqsEndpointStrategy::Aws),
        other => Err(ConfigError::new(
            src,
            format!("expected one of path|aws, got `{other}`"),
        )),
    }
}

fn parse_ui(value: &str, src: &'static str) -> Result<bool, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(ConfigError::new(
            src,
            format!("expected one of on|off, got `{other}`"),
        )),
    }
}

fn valid_tls_hostname(hostname: &str) -> bool {
    !hostname.is_empty()
        && hostname.len() <= 253
        && hostname.parse::<std::net::IpAddr>().is_err()
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Probe the accepted names in precedence order, returning the first present non-empty
/// value and the name that supplied it.
fn resolve<'a>(
    get: &dyn Fn(&str) -> Option<String>,
    names: &[&'a str],
) -> Option<(String, &'a str)> {
    for name in names {
        if let Some(value) = get(name) {
            if !value.is_empty() {
                return Some((value, name));
            }
        }
    }
    None
}

fn resolve_secs(
    get: &dyn Fn(&str) -> Option<String>,
    names: &[&'static str],
    default: u64,
) -> Result<Duration, ConfigError> {
    match resolve(get, names) {
        Some((v, src)) => {
            let secs = v.parse::<u64>().map_err(|e| {
                ConfigError::new(src, format!("expected a whole number of seconds: {e}"))
            })?;
            Ok(Duration::from_secs(secs))
        }
        None => Ok(Duration::from_secs(default)),
    }
}

fn parse_runtime(value: &str, src: &'static str) -> Result<Option<RuntimeChoice>, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "auto" => Ok(None),
        "firecracker" => Ok(Some(RuntimeChoice::Firecracker)),
        "youki" => Ok(Some(RuntimeChoice::Youki)),
        other => Err(ConfigError::new(
            src,
            format!("expected one of auto|firecracker|youki, got `{other}`"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn lambda_concurrency_defaults_and_scaled_limits_are_validated() {
        assert_eq!(
            LocallyCloudConfig::resolve(&env(&[]))
                .unwrap()
                .lambda_concurrency,
            LambdaConcurrencyConfig::new(1000, 100).unwrap()
        );
        assert_eq!(
            LocallyCloudConfig::resolve(&env(&[(LAMBDA_ACCOUNT_CONCURRENCY, "3000")]))
                .unwrap()
                .lambda_concurrency,
            LambdaConcurrencyConfig::new(3000, 100).unwrap()
        );
        assert_eq!(
            LocallyCloudConfig::resolve(&env(&[
                (LAMBDA_ACCOUNT_CONCURRENCY, "10"),
                (LAMBDA_MIN_UNRESERVED, "2")
            ]))
            .unwrap()
            .lambda_concurrency,
            LambdaConcurrencyConfig::new(10, 2).unwrap()
        );
        assert_eq!(
            LocallyCloudConfig::resolve(&env(&[(LAMBDA_MIN_UNRESERVED, "0")]))
                .unwrap()
                .lambda_concurrency
                .min_unreserved(),
            0
        );
        for value in ["", "0", "-1", "1.5", "bogus", "2147483648", "4294967296"] {
            let error = LocallyCloudConfig::resolve(&env(&[(LAMBDA_ACCOUNT_CONCURRENCY, value)]))
                .unwrap_err();
            assert_eq!(error.setting, LAMBDA_ACCOUNT_CONCURRENCY, "{value}");
        }
        for pairs in [
            vec![(LAMBDA_ACCOUNT_CONCURRENCY, "10")],
            vec![(LAMBDA_MIN_UNRESERVED, "1001")],
            vec![(LAMBDA_MIN_UNRESERVED, "-1")],
        ] {
            assert_eq!(
                LocallyCloudConfig::resolve(&env(&pairs))
                    .unwrap_err()
                    .setting,
                LAMBDA_MIN_UNRESERVED
            );
        }
    }

    #[test]
    fn retry_time_scale_and_poller_ceiling_have_independent_validated_defaults() {
        let config = LocallyCloudConfig::resolve(&env(&[])).unwrap();
        assert_eq!(config.events_retry_second, Duration::from_secs(1));
        assert_eq!(config.sqs_esm_max_pollers, 10);
        let config = LocallyCloudConfig::resolve(&env(&[
            ("LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE", "0.001"),
            ("LOCALLYCLOUD_SQS_ESM_MAX_POLLERS", "20"),
        ]))
        .unwrap();
        assert_eq!(config.events_retry_second, Duration::from_millis(1));
        assert_eq!(config.sqs_esm_max_pollers, 20);
        for value in ["0", "-1", "NaN", "inf", "1.1", "0.0000001", "bad"] {
            assert!(LocallyCloudConfig::resolve(&env(&[(
                "LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE",
                value
            )]))
            .is_err());
        }
        for value in ["0", "1", "1001", "1.5", "-1", "bad"] {
            assert!(LocallyCloudConfig::resolve(&env(&[(
                "LOCALLYCLOUD_SQS_ESM_MAX_POLLERS",
                value
            )]))
            .is_err());
        }
    }

    #[test]
    fn control_plane_tls_is_explicit_and_validated() {
        assert!(LocallyCloudConfig::resolve(&env(&[]))
            .unwrap()
            .tls
            .is_none());
        for invalid in [
            "",
            "https://localhost",
            "*.localhost",
            "127.0.0.1",
            "bad_host",
            "-bad.test",
        ] {
            assert!(LocallyCloudConfig::resolve(&env(&[
                ("LOCALLYCLOUD_TLS_HOSTNAME", invalid),
                ("LOCALLYCLOUD_TLS_CERT_PATH", "cert.pem"),
                ("LOCALLYCLOUD_TLS_KEY_PATH", "key.pem")
            ]))
            .is_err());
        }
        assert!(
            LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_TLS_CERT_PATH", "cert.pem")]))
                .is_err()
        );
        let config = LocallyCloudConfig::resolve(&env(&[
            ("LOCALLYCLOUD_TLS_HOSTNAME", "LOCALHOST"),
            ("LOCALLYCLOUD_TLS_CERT_PATH", "cert.pem"),
            ("LOCALLYCLOUD_TLS_KEY_PATH", "key.pem"),
        ]))
        .unwrap();
        assert_eq!(config.tls.unwrap().hostname, "localhost");
    }

    #[test]
    fn all_defaults_when_empty() {
        let cfg = LocallyCloudConfig::resolve(&env(&[])).unwrap();
        // Default is loopback only (local beta safety), not all interfaces.
        assert_eq!(cfg.listen_addr, "127.0.0.1:4566".parse().unwrap());
        assert_eq!(cfg.legacy_backend_url, "http://localhost:4567");
        assert_eq!(cfg.external_endpoint, None);
        assert_eq!(cfg.upstream_timeout, Duration::from_secs(30));
        assert_eq!(cfg.legacy_health_check_interval, Duration::from_secs(5));
        assert_eq!(cfg.max_request_body_bytes, 128 * 1024 * 1024);
        assert_eq!(cfg.shutdown_grace_period, Duration::from_secs(5));
        assert_eq!(cfg.runtime_override, None);
        assert_eq!(cfg.account_id, "000000000000");
        assert_eq!(cfg.default_region, "us-east-1");
    }

    #[test]
    fn account_and_region_are_configurable() {
        let cfg = LocallyCloudConfig::resolve(&env(&[
            ("LOCALLYCLOUD_ACCOUNT_ID", "123456789012"),
            ("AWS_REGION", "eu-west-1"),
        ]))
        .unwrap();
        assert_eq!(cfg.account_id, "123456789012");
        assert_eq!(cfg.default_region, "eu-west-1");
    }

    #[test]
    fn max_request_body_bytes_parsed_and_validated() {
        let cfg = LocallyCloudConfig::resolve(&env(&[(
            "LOCALLYCLOUD_MAX_REQUEST_BODY_BYTES",
            "1048576",
        )]))
        .unwrap();
        assert_eq!(cfg.max_request_body_bytes, 1_048_576);
        let err =
            LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_MAX_REQUEST_BODY_BYTES", "big")]))
                .unwrap_err();
        assert_eq!(err.setting, "LOCALLYCLOUD_MAX_REQUEST_BODY_BYTES");
    }

    #[test]
    fn native_takes_precedence_over_aliases() {
        let cfg = LocallyCloudConfig::resolve(&env(&[
            ("LOCALLYCLOUD_PORT", "4566"),
            ("LOCALSTACK_PORT", "4599"),
        ]))
        .unwrap();
        assert_eq!(cfg.listen_addr.port(), 4566);
    }

    #[test]
    fn explicit_external_binding_overrides_loopback_default() {
        // An explicit host, including the old `0.0.0.0` all-interfaces value, is honoured
        // under the same precedence as before; only the default changed.
        let all_ifaces =
            LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_HOST", "0.0.0.0")])).unwrap();
        assert_eq!(all_ifaces.listen_addr, "0.0.0.0:4566".parse().unwrap());
        let alias =
            LocallyCloudConfig::resolve(&env(&[("LOCALSTACK_HOST", "192.168.1.20")])).unwrap();
        assert_eq!(alias.listen_addr, "192.168.1.20:4566".parse().unwrap());
    }

    #[test]
    fn localstack_alias_used_when_native_absent() {
        let cfg = LocallyCloudConfig::resolve(&env(&[("LOCALSTACK_PORT", "4599")])).unwrap();
        assert_eq!(cfg.listen_addr.port(), 4599);
    }

    #[test]
    fn empty_value_falls_through_to_next_source() {
        let cfg = LocallyCloudConfig::resolve(&env(&[
            ("LOCALLYCLOUD_PORT", ""),
            ("LOCALSTACK_PORT", "4599"),
        ]))
        .unwrap();
        assert_eq!(cfg.listen_addr.port(), 4599);
    }

    #[test]
    fn aws_endpoint_url_wins_for_external_endpoint() {
        let cfg = LocallyCloudConfig::resolve(&env(&[
            ("AWS_ENDPOINT_URL", "http://host.docker.internal:4566"),
            ("LOCALLYCLOUD_ENDPOINT_URL", "http://localhost:4566"),
        ]))
        .unwrap();
        assert_eq!(
            cfg.external_endpoint.as_deref(),
            Some("http://host.docker.internal:4566")
        );
    }

    #[test]
    fn runtime_override_parsing() {
        let fc =
            LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_RUNTIME", "firecracker")])).unwrap();
        assert_eq!(fc.runtime_override, Some(RuntimeChoice::Firecracker));
        let yk = LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_RUNTIME", "YOUKI")])).unwrap();
        assert_eq!(yk.runtime_override, Some(RuntimeChoice::Youki));
        let auto = LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_RUNTIME", "auto")])).unwrap();
        assert_eq!(auto.runtime_override, None);
    }

    #[test]
    fn invalid_port_is_rejected_with_setting_name() {
        let err = LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_PORT", "70000")])).unwrap_err();
        assert_eq!(err.setting, "LOCALLYCLOUD_PORT");
    }

    #[test]
    fn invalid_timeout_is_rejected() {
        let err =
            LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_UPSTREAM_TIMEOUT_SECS", "soon")]))
                .unwrap_err();
        assert_eq!(err.setting, "LOCALLYCLOUD_UPSTREAM_TIMEOUT_SECS");
    }

    #[test]
    fn dashboard_ui_toggle_defaults_on_and_rejects_unknown_values() {
        assert!(LocallyCloudConfig::resolve(&env(&[])).unwrap().ui_enabled);
        assert!(
            LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_UI", "ON")]))
                .unwrap()
                .ui_enabled
        );
        assert!(
            !LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_UI", "off")]))
                .unwrap()
                .ui_enabled
        );
        let err =
            LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_UI", "disabled")])).unwrap_err();
        assert_eq!(err.setting, "LOCALLYCLOUD_UI");
        assert!(err.to_string().contains("on|off"));
    }

    #[test]
    fn sqs_endpoint_strategy_defaults_to_path_and_rejects_unknown_values() {
        let strategy = |value: &str| {
            LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_SQS_ENDPOINT_STRATEGY", value)]))
        };
        assert_eq!(
            LocallyCloudConfig::resolve(&env(&[]))
                .unwrap()
                .sqs_endpoint_strategy,
            SqsEndpointStrategy::Path
        );
        assert_eq!(
            strategy("AWS").unwrap().sqs_endpoint_strategy,
            SqsEndpointStrategy::Aws
        );
        assert_eq!(
            strategy("path").unwrap().sqs_endpoint_strategy,
            SqsEndpointStrategy::Path
        );
        let err = strategy("domain").unwrap_err();
        assert_eq!(err.setting, "LOCALLYCLOUD_SQS_ENDPOINT_STRATEGY");
        assert!(err.to_string().contains("path|aws"));
    }

    #[test]
    fn invalid_runtime_is_rejected() {
        let err =
            LocallyCloudConfig::resolve(&env(&[("LOCALLYCLOUD_RUNTIME", "podman")])).unwrap_err();
        assert_eq!(err.setting, "LOCALLYCLOUD_RUNTIME");
    }
}
