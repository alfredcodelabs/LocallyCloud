//! Service settings follow the shared startup precedence; secrets stay outside JSON.
use serde::Deserialize;
use std::ffi::OsString;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    #[default]
    Capture,
    Resend,
}
impl Provider {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Resend => "resend",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SesConfig {
    pub provider: Provider,
    pub auto_verify_identities: bool,
    pub request_timeout_secs: u64,
    pub max_concurrency: usize,
    pub max_pending_messages: usize,
    pub max_pending_bytes: usize,
}
impl Default for SesConfig {
    fn default() -> Self {
        Self {
            provider: Provider::Capture,
            auto_verify_identities: false,
            request_timeout_secs: 30,
            max_concurrency: 2,
            max_pending_messages: 1000,
            max_pending_bytes: 64 * 1024 * 1024,
        }
    }
}
impl SesConfig {
    pub fn resolve_with(mut self, get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        if let Some(value) = get("LOCALLYCLOUD_SES_PROVIDER") {
            self.provider = match value.to_str() {
                Some("capture") => Provider::Capture,
                Some("resend") => Provider::Resend,
                _ => return Err("LOCALLYCLOUD_SES_PROVIDER must be capture or resend".into()),
            };
        }
        if let Some(value) = get("LOCALLYCLOUD_SES_AUTO_VERIFY_IDENTITIES") {
            self.auto_verify_identities = match value.to_str() {
                Some("true") => true,
                Some("false") => false,
                _ => {
                    return Err(
                        "LOCALLYCLOUD_SES_AUTO_VERIFY_IDENTITIES must be true or false".into(),
                    )
                }
            };
        }
        if let Some(value) = get("LOCALLYCLOUD_SES_REQUEST_TIMEOUT_SECS") {
            self.request_timeout_secs = value
                .to_str()
                .and_then(|v| v.parse().ok())
                .ok_or("LOCALLYCLOUD_SES_REQUEST_TIMEOUT_SECS must be an integer")?;
        }
        for (name, target) in [
            (
                "LOCALLYCLOUD_SES_MAX_CONCURRENCY",
                &mut self.max_concurrency,
            ),
            (
                "LOCALLYCLOUD_SES_MAX_PENDING_MESSAGES",
                &mut self.max_pending_messages,
            ),
            (
                "LOCALLYCLOUD_SES_MAX_PENDING_BYTES",
                &mut self.max_pending_bytes,
            ),
        ] {
            if let Some(value) = get(name) {
                *target = value
                    .to_str()
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| format!("{name} must be an integer"))?;
            }
        }
        self.validate()?;
        Ok(self)
    }
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=300).contains(&self.request_timeout_secs)
            || !(1..=16).contains(&self.max_concurrency)
            || !(1..=100_000).contains(&self.max_pending_messages)
            || !(1024..=1024 * 1024 * 1024).contains(&self.max_pending_bytes)
        {
            return Err("SES operational budgets are outside their supported bounds".into());
        }
        Ok(())
    }
}

/// Deliberately neither serializable nor Debug; callers only inspect presence.
pub struct SesCredentials {
    pub(crate) api_key: Option<Zeroizing<String>>,
}
impl SesCredentials {
    pub fn from_lookup(
        config: &SesConfig,
        get: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Self, String> {
        let api_key = get("LOCALLYCLOUD_SES_PROVIDER_API_KEY")
            .map(|value| {
                let value = Zeroizing::new(
                    value
                        .into_string()
                        .map_err(|_| "SES provider credential must be valid UTF-8")?,
                );
                if !(8..=1024).contains(&value.len())
                    || !value.bytes().all(|b| b.is_ascii_graphic())
                {
                    return Err("SES provider credential is empty or invalid");
                }
                Ok(value)
            })
            .transpose()
            .map_err(str::to_owned)?;
        if config.provider == Provider::Resend && api_key.is_none() {
            return Err("Resend delivery requires LOCALLYCLOUD_SES_PROVIDER_API_KEY".into());
        }
        Ok(Self { api_key })
    }
}
