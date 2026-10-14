//! Stateless authenticated cursors, bound to scope, operation and filters.
use super::*;

const MAX_TOKEN_LEN: usize = 8192;

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Cursor {
    pub(super) last_name: Option<String>,
    pub(super) last_history: Option<(i64, i64)>,
    pub(super) high_history: Option<i64>,
    expires: i64,
}
fn invalid_token() -> MonitoringError {
    MonitoringError::InvalidNextToken("Invalid or expired alarm pagination token".into())
}
impl Alarms {
    fn cipher(&self) -> &locallycloud_state::StateCipher {
        self.persistence
            .as_ref()
            .map(|p| &p.cipher)
            .unwrap_or_else(|| {
                self.ephemeral_cipher
                    .as_ref()
                    .expect("in-memory cipher initialized")
            })
    }
    /// Seal an opaque, authenticated pagination token bound to scope, action and request.
    pub(crate) fn seal_token(
        &self,
        action: &str,
        binding: &str,
        scope: &ScopeKey,
        plaintext: &[u8],
    ) -> Result<String, MonitoringError> {
        let bytes = self
            .cipher()
            .seal(
                &[
                    "monitoring-pagination",
                    &scope.account_id,
                    &scope.region,
                    action,
                    binding,
                ],
                plaintext,
            )
            .map_err(persistence::internal)?;
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
    /// Open a token produced by `seal_token`; `None` if it is malformed, forged or rebound.
    pub(crate) fn open_token(
        &self,
        action: &str,
        binding: &str,
        scope: &ScopeKey,
        token: &str,
    ) -> Option<Vec<u8>> {
        if token.len() > MAX_TOKEN_LEN || token.is_empty() || !token.len().is_multiple_of(2) {
            return None;
        }
        let data: Vec<u8> = token
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .and_then(|s| u8::from_str_radix(s, 16).ok())
            })
            .collect::<Option<_>>()?;
        self.cipher()
            .open(
                &[
                    "monitoring-pagination",
                    &scope.account_id,
                    &scope.region,
                    action,
                    binding,
                ],
                &data,
            )
            .ok()
            .map(|plaintext| plaintext.to_vec())
    }
    pub(super) fn cursor(
        &self,
        action: &str,
        body: &Value,
        scope: &ScopeKey,
    ) -> Result<Cursor, MonitoringError> {
        let Some(token) = body.get("NextToken") else {
            return Ok(Cursor {
                expires: now_ms() + 86400 * 1000,
                ..Default::default()
            });
        };
        let token = token.as_str().ok_or_else(invalid_token)?;
        let plaintext = self
            .open_token(action, &binding(body), scope, token)
            .ok_or_else(invalid_token)?;
        let cursor: Cursor = serde_json::from_slice(&plaintext).map_err(|_| invalid_token())?;
        if cursor.expires <= now_ms() {
            return Err(invalid_token());
        }
        Ok(cursor)
    }
    pub(super) fn next_token(
        &self,
        action: &str,
        body: &Value,
        scope: &ScopeKey,
        cursor: &Cursor,
    ) -> Result<String, MonitoringError> {
        self.seal_token(
            action,
            &binding(body),
            scope,
            &serde_json::to_vec(cursor).map_err(persistence::internal)?,
        )
    }
}
fn binding(body: &Value) -> String {
    let mut query = body.clone();
    if let Some(object) = query.as_object_mut() {
        object.remove("NextToken");
    }
    query.to_string()
}
