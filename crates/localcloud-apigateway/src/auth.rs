//! Real JWT validation for HTTP API v2 JWT authorizers, faithful to the AWS workflow
//! (see the API Gateway "Control access to HTTP APIs with JWT authorizers" guide):
//!
//! 1. take the token from the identity source (optionally `Bearer`-prefixed),
//! 2. decode the header and require an RSA algorithm (AWS only supports RSA),
//! 3. fetch the issuer signing key from its `jwks_uri` (OIDC discovery), matched by `kid`,
//!    cached for up to two hours,
//! 4. verify the signature and the `iss`, `aud`/`client_id`, `exp`, `nbf`, `iat` claims, plus
//!    the route's required scopes (`scope`/`scp`).
//!
//! Any failure denies the request (HTTP 401). An issuer/JWKS that cannot be reached is an
//! infrastructure error (HTTP 500), distinct from a token that is simply invalid.

use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use localcloud_cognito::CognitoHandler;
use serde_json::Value;

/// Evaluate an IAM-style Lambda authorizer policy for the current execute-api ARN.
/// Only statements whose Action and Resource apply participate; an applicable Deny wins.
pub(crate) fn policy_allows(result: &Value, route_arn: &str) -> bool {
    let Some(statements) = result
        .pointer("/policyDocument/Statement")
        .and_then(Value::as_array)
    else {
        return false;
    };
    let mut allowed = false;
    for statement in statements {
        if !policy_values(statement.get("Action"))
            .into_iter()
            .any(|action| wildcard_matches(action, "execute-api:Invoke"))
            || !policy_values(statement.get("Resource"))
                .into_iter()
                .any(|resource| wildcard_matches(resource, route_arn))
        {
            continue;
        }
        match statement.get("Effect").and_then(Value::as_str) {
            Some("Deny") => return false,
            Some("Allow") => allowed = true,
            _ => {}
        }
    }
    allowed
}

fn policy_values(value: Option<&Value>) -> Vec<&str> {
    match value {
        Some(Value::String(value)) => vec![value.as_str()],
        Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }
    let mut remainder = value;
    let mut parts = pattern.split('*').peekable();
    if !pattern.starts_with('*') {
        let Some(prefix) = parts.next() else {
            return value.is_empty();
        };
        let Some(rest) = remainder.strip_prefix(prefix) else {
            return false;
        };
        remainder = rest;
    }
    while let Some(part) = parts.next() {
        if part.is_empty() {
            continue;
        }
        if parts.peek().is_none() && !pattern.ends_with('*') {
            return remainder.ends_with(part);
        }
        let Some(index) = remainder.find(part) else {
            return false;
        };
        remainder = &remainder[index + part.len()..];
    }
    true
}

/// AWS caches issuer public keys for up to two hours.
const JWKS_TTL: Duration = Duration::from_secs(2 * 60 * 60);

/// JWT authorizer configuration (`JwtConfiguration` on the authorizer resource).
#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub issuer: String,
    pub audiences: Vec<String>,
}

/// The result of evaluating a JWT authorizer for one request.
#[derive(Debug)]
pub enum AuthOutcome {
    /// Token valid: carries the claims (for `requestContext.authorizer.jwt.claims`) and the
    /// granted scopes (for `requestContext.authorizer.jwt.scopes`).
    Allow { claims: Value, scopes: Vec<String> },
    /// Token invalid/absent/expired/wrong-claims/insufficient-scope → HTTP 401.
    Deny(String),
    /// Issuer or JWKS unreachable / malformed → HTTP 500.
    Error(String),
}

#[derive(serde::Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

/// Fetches and caches issuer JWKS, then verifies tokens. One instance is shared by the
/// handler; the cache is keyed by issuer.
pub struct JwtValidator {
    http: reqwest::Client,
    cache: DashMap<String, (Instant, JwkSet)>,
    local_cognito: RwLock<Option<Weak<CognitoHandler>>>,
}

impl Default for JwtValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl JwtValidator {
    pub fn new() -> Self {
        JwtValidator {
            http: reqwest::Client::new(),
            cache: DashMap::new(),
            local_cognito: RwLock::new(None),
        }
    }

    /// Build a validator that reuses an existing HTTP client.
    pub fn with_client(http: reqwest::Client) -> Self {
        JwtValidator {
            http,
            cache: DashMap::new(),
            local_cognito: RwLock::new(None),
        }
    }

    /// Bind the native Cognito User Pools public-key capability. The provider is held weakly;
    /// the service registry owns its lifetime.
    pub fn set_local_cognito(&self, provider: Arc<CognitoHandler>) {
        *self
            .local_cognito
            .write()
            .expect("Cognito binding lock poisoned") = Some(Arc::downgrade(&provider));
    }

    fn local_jwks(
        &self,
        account: &str,
        region: &str,
        issuer: &str,
    ) -> Option<Result<JwkSet, String>> {
        if !issuer.starts_with("https://cognito-idp.") {
            return None;
        }
        Some((|| {
            let pool_id = local_cognito_pool_id(issuer, region)?;
            let provider = self
                .local_cognito
                .read()
                .map_err(|_| "Cognito binding is unavailable".to_string())?
                .as_ref()
                .and_then(Weak::upgrade)
                .ok_or_else(|| "Cognito provider is unavailable".to_string())?;
            let value = provider
                .jwks_for_pool(account, region, pool_id)
                .ok_or_else(|| {
                    "Cognito pool is unavailable in this account and region".to_string()
                })?;
            serde_json::from_value(value).map_err(|_| "local Cognito JWKS is malformed".to_string())
        })())
    }

    /// Resolve the issuer's `jwks_uri` via OIDC discovery.
    async fn discover_jwks_uri(&self, issuer: &str) -> Result<String, String> {
        let base = issuer.trim_end_matches('/');
        let url = format!("{base}/.well-known/openid-configuration");
        let doc: OidcDiscovery = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("OIDC discovery request failed: {e}"))?
            .error_for_status()
            .map_err(|e| format!("OIDC discovery returned an error status: {e}"))?
            .json()
            .await
            .map_err(|e| format!("OIDC discovery document was not valid JSON: {e}"))?;
        Ok(doc.jwks_uri)
    }

    /// Return the issuer's JWKS, fetching and caching it when missing or stale.
    async fn jwks(&self, account: &str, region: &str, issuer: &str) -> Result<JwkSet, String> {
        if let Some(local) = self.local_jwks(account, region, issuer) {
            return local;
        }
        if let Some(entry) = self.cache.get(issuer) {
            if entry.0.elapsed() < JWKS_TTL {
                return Ok(entry.1.clone());
            }
        }
        let jwks_uri = self.discover_jwks_uri(issuer).await?;
        let set: JwkSet = self
            .http
            .get(&jwks_uri)
            .send()
            .await
            .map_err(|e| format!("JWKS request failed: {e}"))?
            .error_for_status()
            .map_err(|e| format!("JWKS endpoint returned an error status: {e}"))?
            .json()
            .await
            .map_err(|e| format!("JWKS document was not valid JSON: {e}"))?;
        self.cache
            .insert(issuer.to_string(), (Instant::now(), set.clone()));
        Ok(set)
    }

    /// Validate `token` against `cfg` and the route's `required_scopes` (empty = no scope
    /// requirement). Never logs or returns the token value.
    pub async fn authorize(
        &self,
        token: &str,
        cfg: &JwtConfig,
        required_scopes: &[String],
    ) -> AuthOutcome {
        self.authorize_scoped(token, cfg, required_scopes, "", "")
            .await
    }

    /// Authorize in the API's account and region, allowing a matching native Cognito pool
    /// to supply its public JWKS without changing the token's AWS issuer.
    pub async fn authorize_scoped(
        &self,
        token: &str,
        cfg: &JwtConfig,
        required_scopes: &[String],
        account: &str,
        region: &str,
    ) -> AuthOutcome {
        let token = token.trim();
        let token = token
            .strip_prefix("Bearer ")
            .or_else(|| token.strip_prefix("bearer "))
            .unwrap_or(token)
            .trim();
        if token.is_empty() {
            return AuthOutcome::Deny("missing bearer token".into());
        }

        // Header: algorithm must be RSA, and a `kid` is required to select the signing key.
        let header = match decode_header(token) {
            Ok(h) => h,
            Err(e) => return AuthOutcome::Deny(format!("malformed token header: {e}")),
        };
        if !matches!(
            header.alg,
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
        ) {
            return AuthOutcome::Deny("unsupported token algorithm; only RSA is supported".into());
        }
        if cfg.issuer.starts_with("https://cognito-idp.") && header.alg != Algorithm::RS256 {
            return AuthOutcome::Deny("Cognito tokens must use RS256".into());
        }
        let kid = match header.kid {
            Some(k) => k,
            None => return AuthOutcome::Deny("token header is missing the kid".into()),
        };

        // Signing key from the issuer JWKS, matched by kid.
        let jwks = match self.jwks(account, region, &cfg.issuer).await {
            Ok(set) => set,
            Err(e) => return AuthOutcome::Error(e),
        };
        let jwk = match jwks.find(&kid) {
            Some(j) => j,
            None => return AuthOutcome::Deny("no JWKS key matches the token kid".into()),
        };
        let key = match DecodingKey::from_jwk(jwk) {
            Ok(k) => k,
            Err(e) => return AuthOutcome::Error(format!("issuer key could not be parsed: {e}")),
        };

        // Verify signature + iss + exp + nbf. Audience is validated manually below to honour
        // the AWS `aud`-or-`client_id` rule, so disable the library's audience check.
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[cfg.issuer.as_str()]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = false;
        let claims: Value = match decode::<Value>(token, &key, &validation) {
            Ok(data) => data.claims,
            Err(e) => return AuthOutcome::Deny(format!("token verification failed: {e}")),
        };

        // aud (preferred) or client_id must match a configured audience.
        if let Err(reason) = check_audience(&claims, &cfg.audiences) {
            return AuthOutcome::Deny(reason);
        }
        // iat, if present, must be in the past.
        if let Some(iat) = claims.get("iat").and_then(Value::as_i64) {
            if iat > now_secs() {
                return AuthOutcome::Deny("token iat is in the future".into());
            }
        }
        // The token must carry at least one of the route's required scopes.
        let token_scopes = extract_scopes(&claims);
        if !required_scopes.is_empty() && !required_scopes.iter().any(|s| token_scopes.contains(s))
        {
            return AuthOutcome::Deny("token is missing a required scope".into());
        }

        AuthOutcome::Allow {
            claims,
            scopes: token_scopes,
        }
    }
}

fn local_cognito_pool_id<'a>(issuer: &'a str, region: &str) -> Result<&'a str, String> {
    let invalid = || "Cognito issuer does not match the API region".to_string();
    let suffix = issuer
        .strip_prefix("https://cognito-idp.")
        .ok_or_else(invalid)?;
    let (issuer_region, pool_id) = suffix.split_once(".amazonaws.com/").ok_or_else(invalid)?;
    let pool_suffix = pool_id
        .strip_prefix(&format!("{region}_"))
        .ok_or_else(invalid)?;
    if region.is_empty()
        || issuer_region != region
        || pool_id.len() > 128
        || pool_suffix.is_empty()
        || !pool_suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(invalid());
    }
    Ok(pool_id)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// AWS rule: validate `aud` if present; otherwise validate `client_id`. The matching value
/// must equal one of the configured audiences.
fn check_audience(claims: &Value, audiences: &[String]) -> Result<(), String> {
    let candidates: Vec<String> = match claims.get("aud") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => match claims.get("client_id").and_then(Value::as_str) {
            Some(c) => vec![c.to_string()],
            None => return Err("token has neither aud nor client_id".into()),
        },
    };
    if candidates.iter().any(|c| audiences.iter().any(|a| a == c)) {
        Ok(())
    } else {
        Err("token audience does not match the authorizer".into())
    }
}

/// Collect scopes from the `scope` (space-delimited string) or `scp` (array) claims.
fn extract_scopes(claims: &Value) -> Vec<String> {
    if let Some(scope) = claims.get("scope").and_then(Value::as_str) {
        return scope.split_whitespace().map(str::to_string).collect();
    }
    match claims.get("scp") {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(s)) => s.split_whitespace().map(str::to_string).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cognito_issuer_requires_exact_region_and_pool_path() {
        assert_eq!(
            local_cognito_pool_id(
                "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123",
                "us-east-1"
            )
            .unwrap(),
            "us-east-1_abc123"
        );
        for issuer in [
            "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_abc123",
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123/extra",
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123?x=1",
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_",
        ] {
            assert!(local_cognito_pool_id(issuer, "us-east-1").is_err());
        }
    }

    #[test]
    fn cognito_issuer_without_local_pool_fails_closed() {
        let provider = Arc::new(CognitoHandler::new());
        let validator = JwtValidator::new();
        validator.set_local_cognito(provider.clone());
        let issuer = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_missing";
        assert!(validator
            .local_jwks("000000000000", "us-east-1", issuer)
            .unwrap()
            .is_err());
        assert!(validator
            .local_jwks("000000000000", "us-west-2", issuer)
            .unwrap()
            .is_err());
        assert!(validator
            .local_jwks("000000000000", "us-east-1", "https://example.test")
            .is_none());
    }

    #[test]
    fn audience_prefers_aud_over_client_id() {
        let claims = json!({ "aud": "good", "client_id": "bad" });
        assert!(check_audience(&claims, &["good".into()]).is_ok());
        // aud present but wrong → deny even though client_id would match.
        let claims = json!({ "aud": "wrong", "client_id": "good" });
        assert!(check_audience(&claims, &["good".into()]).is_err());
    }

    #[test]
    fn audience_falls_back_to_client_id_when_aud_absent() {
        let claims = json!({ "client_id": "svc" });
        assert!(check_audience(&claims, &["svc".into()]).is_ok());
        assert!(check_audience(&json!({}), &["svc".into()]).is_err());
    }

    #[test]
    fn audience_accepts_array() {
        let claims = json!({ "aud": ["a", "b"] });
        assert!(check_audience(&claims, &["b".into()]).is_ok());
        assert!(check_audience(&claims, &["c".into()]).is_err());
    }

    #[test]
    fn scopes_from_scope_and_scp() {
        assert_eq!(
            extract_scopes(&json!({ "scope": "read write" })),
            vec!["read", "write"]
        );
        assert_eq!(
            extract_scopes(&json!({ "scp": ["a", "b"] })),
            vec!["a", "b"]
        );
        assert!(extract_scopes(&json!({})).is_empty());
    }
}
