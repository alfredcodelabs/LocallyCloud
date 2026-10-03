//! Scoped native ACM import slice for locally supplied RSA certificates.
//! Material is validated before mutation. Only certificate metadata is retained.
mod material;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use serde_json::{json, Map, Value};
use uuid::Uuid;
use zeroize::Zeroizing;

const PREFIX: &str = "CertificateManager.";
const MAX_BODY: usize = 3 * 1024 * 1024;
const MAX_CERTS: usize = 1000;

#[derive(Clone, PartialEq, Eq, Hash)]
struct Scope {
    account: String,
    region: String,
}

#[derive(Clone)]
struct Certificate {
    arn: String,
    metadata: material::MaterialMetadata,
    tags: BTreeMap<String, String>,
    imported_at: i64,
}

#[derive(Default)]
struct State {
    certs: HashMap<Scope, BTreeMap<String, Certificate>>,
}

/// Read-only eligibility decision for an owning consumer's preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssociationDecision {
    Eligible,
    NotFound,
    NameNotCovered,
    UnsupportedMaterial,
    StateUnavailable,
}

/// A typed certificate association preflight. It never exports private material.
pub trait AcmAssociationApi: Send + Sync {
    fn preflight(
        &self,
        account: &str,
        region: &str,
        arn: &str,
        dns_name: &str,
    ) -> AssociationDecision;
}

#[derive(Default)]
pub struct AcmHandler {
    state: Mutex<State>,
}

impl AcmHandler {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn execute(
        &self,
        op: &str,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, AwsError> {
        match op {
            "ImportCertificate" => self.import(req, body),
            "DescribeCertificate" => self.describe(req, body),
            "ListCertificates" => self.list(req, body),
            "DeleteCertificate" => self.delete(req, body),
            "AddTagsToCertificate" => self.add_tags(req, body),
            "RemoveTagsFromCertificate" => self.remove_tags(req, body),
            "ListTagsForCertificate" => self.list_tags(req, body),
            _ => Err(err("UnknownOperationException", "Unknown operation")),
        }
    }

    fn import(&self, req: &ServiceRequest, body: &Map<String, Value>) -> Result<Value, AwsError> {
        fields(
            body,
            &[
                "Certificate",
                "PrivateKey",
                "CertificateChain",
                "CertificateArn",
                "Tags",
            ],
        )?;
        let cert = blob(body, "Certificate", true)?.ok_or_else(invalid_parameter)?;
        let key = blob(body, "PrivateKey", true)?.ok_or_else(invalid_parameter)?;
        let chain = blob(body, "CertificateChain", false)?;
        let replacement = optional_string(body, "CertificateArn")?;
        if cert.is_empty() || cert.len() > 32768 || key.is_empty() || key.len() > 5120 {
            return Err(invalid_parameter());
        }
        // Full path verification is required before accepting any supplied chain.
        if chain.is_some() {
            return Err(invalid_parameter());
        }
        if replacement.is_some() && body.contains_key("Tags") {
            return Err(invalid_parameter());
        }
        let tags = if replacement.is_none() {
            tags(body, "Tags", false)?
        } else {
            BTreeMap::new()
        };
        let now = now();
        let metadata = material::validate(&cert, &key, now).map_err(|_| invalid_parameter())?;
        let scope = scope(req);
        let mut state = self.state.lock().map_err(|_| internal())?;
        if let Some(arn) = replacement {
            validate_arn(req, arn)?;
            let existing = state
                .certs
                .get_mut(&scope)
                .and_then(|certs| certs.get_mut(arn))
                .ok_or_else(not_found)?;
            existing.metadata = metadata;
            existing.imported_at = now;
            return Ok(json!({"CertificateArn": arn}));
        }
        let certs = state.certs.entry(scope).or_default();
        if certs.len() >= MAX_CERTS {
            return Err(err("LimitExceededException", "Certificate limit exceeded"));
        }
        let arn = format!(
            "arn:aws:acm:{}:{}:certificate/{}",
            req.region,
            req.account_id,
            Uuid::new_v4()
        );
        certs.insert(
            arn.clone(),
            Certificate {
                arn: arn.clone(),
                metadata,
                tags,
                imported_at: now,
            },
        );
        Ok(json!({"CertificateArn": arn}))
    }

    fn describe(&self, req: &ServiceRequest, body: &Map<String, Value>) -> Result<Value, AwsError> {
        fields(body, &["CertificateArn"])?;
        let arn = required_string(body, "CertificateArn")?;
        validate_arn(req, arn)?;
        let state = self.state.lock().map_err(|_| internal())?;
        let cert = state
            .certs
            .get(&scope(req))
            .and_then(|certs| certs.get(arn))
            .ok_or_else(not_found)?;
        let m = &cert.metadata;
        let status = if now() >= m.not_after {
            "EXPIRED"
        } else {
            "ISSUED"
        };
        Ok(json!({"Certificate": {
            "CertificateArn": cert.arn,
            "DomainName": m.domain,
            "SubjectAlternativeNames": m.names,
            "Status": status,
            "Type": "IMPORTED",
            "CertificateKeyPairOrigin": "CUSTOMER_PROVIDED",
            "KeyAlgorithm": m.key_algorithm,
            "Serial": m.serial,
            "Subject": m.subject,
            "Issuer": m.issuer,
            "NotBefore": m.not_before,
            "NotAfter": m.not_after,
            "ImportedAt": cert.imported_at,
            "InUseBy": [],
            "RenewalEligibility": "INELIGIBLE"
        }}))
    }

    fn list(&self, req: &ServiceRequest, body: &Map<String, Value>) -> Result<Value, AwsError> {
        fields(
            body,
            &["CertificateStatuses", "Includes", "MaxItems", "NextToken"],
        )?;
        if body.contains_key("NextToken") {
            return Err(invalid_parameter());
        }
        let max = match body.get("MaxItems") {
            None => 100,
            Some(v) => v
                .as_u64()
                .filter(|n| (1..=1000).contains(n))
                .ok_or_else(invalid_parameter)? as usize,
        };
        let statuses = optional_strings(body, "CertificateStatuses")?;
        if statuses.as_ref().is_some_and(|v| {
            v.iter().any(|s| {
                ![
                    "ISSUED",
                    "EXPIRED",
                    "PENDING_VALIDATION",
                    "FAILED",
                    "REVOKED",
                    "INACTIVE",
                    "VALIDATION_TIMED_OUT",
                ]
                .contains(&s.as_str())
            })
        }) {
            return Err(invalid_parameter());
        }
        let types = match body.get("Includes") {
            None => None,
            Some(Value::Object(map)) => {
                fields(map, &["keyTypes"])?;
                optional_strings(map, "keyTypes")?
            }
            Some(_) => return Err(invalid_parameter()),
        };
        let state = self.state.lock().map_err(|_| internal())?;
        let all = state.certs.get(&scope(req));
        let mut summaries = Vec::new();
        if let Some(certs) = all {
            for cert in certs.values() {
                let key_type = cert.metadata.key_algorithm;
                let status = if now() >= cert.metadata.not_after {
                    "EXPIRED"
                } else {
                    "ISSUED"
                };
                if statuses
                    .as_ref()
                    .is_some_and(|v| !v.iter().any(|s| s == status))
                {
                    continue;
                }
                let allowed_type = types
                    .as_ref()
                    .is_some_and(|v| v.iter().any(|t| t == key_type))
                    || (types.is_none() && key_type == "RSA_2048");
                if allowed_type {
                    summaries.push(json!({"CertificateArn": cert.arn, "DomainName": cert.metadata.domain,
                            "SubjectAlternativeNameSummaries": cert.metadata.names, "Status": status, "Type": "IMPORTED",
                            "KeyAlgorithm": key_type, "HasAdditionalSubjectAlternativeNames": false}));
                }
            }
        }
        if summaries.len() > max {
            return Err(invalid_parameter());
        }
        Ok(json!({"CertificateSummaryList": summaries}))
    }

    fn delete(&self, req: &ServiceRequest, body: &Map<String, Value>) -> Result<Value, AwsError> {
        fields(body, &["CertificateArn"])?;
        let arn = required_string(body, "CertificateArn")?;
        validate_arn(req, arn)?;
        let mut state = self.state.lock().map_err(|_| internal())?;
        let removed = state
            .certs
            .get_mut(&scope(req))
            .and_then(|certs| certs.remove(arn));
        if removed.is_none() {
            return Err(not_found());
        }
        Ok(json!({}))
    }

    fn add_tags(&self, req: &ServiceRequest, body: &Map<String, Value>) -> Result<Value, AwsError> {
        fields(body, &["CertificateArn", "Tags"])?;
        let arn = required_string(body, "CertificateArn")?;
        validate_arn(req, arn)?;
        let additions = tags(body, "Tags", true)?;
        let mut state = self.state.lock().map_err(|_| internal())?;
        let cert = state
            .certs
            .get_mut(&scope(req))
            .and_then(|certs| certs.get_mut(arn))
            .ok_or_else(not_found)?;
        let new_count = cert
            .tags
            .keys()
            .chain(additions.keys())
            .collect::<BTreeSet<_>>()
            .len();
        if new_count > 50 {
            return Err(err("TooManyTagsException", "Tag limit exceeded"));
        }
        cert.tags.extend(additions);
        Ok(json!({}))
    }

    fn remove_tags(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, AwsError> {
        fields(body, &["CertificateArn", "Tags"])?;
        let arn = required_string(body, "CertificateArn")?;
        validate_arn(req, arn)?;
        let removals = tags(body, "Tags", true)?;
        let mut state = self.state.lock().map_err(|_| internal())?;
        let cert = state
            .certs
            .get_mut(&scope(req))
            .and_then(|certs| certs.get_mut(arn))
            .ok_or_else(not_found)?;
        for key in removals.keys() {
            cert.tags.remove(key);
        }
        Ok(json!({}))
    }

    fn list_tags(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, AwsError> {
        fields(body, &["CertificateArn"])?;
        let arn = required_string(body, "CertificateArn")?;
        validate_arn(req, arn)?;
        let state = self.state.lock().map_err(|_| internal())?;
        let cert = state
            .certs
            .get(&scope(req))
            .and_then(|certs| certs.get(arn))
            .ok_or_else(not_found)?;
        Ok(
            json!({"Tags": cert.tags.iter().map(|(key, value)| json!({"Key": key, "Value": value})).collect::<Vec<_>>()}),
        )
    }
}

impl AcmAssociationApi for AcmHandler {
    fn preflight(
        &self,
        account: &str,
        region: &str,
        arn: &str,
        dns_name: &str,
    ) -> AssociationDecision {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return AssociationDecision::StateUnavailable,
        };
        let scope = Scope {
            account: account.to_owned(),
            region: region.to_owned(),
        };
        let Some(cert) = state.certs.get(&scope).and_then(|certs| certs.get(arn)) else {
            return AssociationDecision::NotFound;
        };
        if cert
            .metadata
            .names
            .iter()
            .any(|name| covers(name, dns_name))
        {
            AssociationDecision::Eligible
        } else {
            AssociationDecision::NameNotCovered
        }
    }
}

fn covers(pattern: &str, name: &str) -> bool {
    if pattern.eq_ignore_ascii_case(name) {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if let Some(prefix) = name.strip_suffix(suffix) {
            return prefix.ends_with('.')
                && prefix[..prefix.len() - 1].bytes().all(|b| b != b'.')
                && prefix.len() > 1;
        }
    }
    false
}

#[async_trait]
impl NativeHandler for AcmHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let result = if request.method != http::Method::POST
            || request.uri.path() != "/"
            || request.uri.query().is_some()
        {
            Err(err("UnknownOperationException", "Unknown operation"))
        } else if request.body.len() > MAX_BODY {
            Err(invalid_parameter())
        } else {
            let op = request
                .headers
                .get("x-amz-target")
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.strip_prefix(PREFIX));
            match op {
                None => Err(err("UnknownOperationException", "Unknown operation")),
                Some(op) => match serde_json::from_slice::<Value>(&request.body) {
                    Ok(Value::Object(body)) => self.execute(op, &request, &body),
                    _ => Err(invalid_parameter()),
                },
            }
        };
        match result {
            Ok(value) => Response::builder()
                .status(200)
                .header("content-type", "application/x-amz-json-1.1")
                .header("x-amzn-RequestId", &request.request_id)
                .body(Body::from(if value == json!({}) {
                    String::new()
                } else {
                    value.to_string()
                }))
                .expect("valid ACM response"),
            Err(error) => error
                .with_request_id(request.request_id)
                .render(AwsProtocol::Json11)
                .into_response(),
        }
    }
}

pub fn register(registry: &Arc<ServiceRegistry>) -> Arc<AcmHandler> {
    let handler = AcmHandler::new();
    registry.register_native(
        ServiceName::new("acm"),
        ServiceMetadata::new(AwsProtocol::Json11, Some("CertificateManager")),
        handler.clone(),
    );
    handler
}

fn scope(req: &ServiceRequest) -> Scope {
    Scope {
        account: req.account_id.clone(),
        region: req.region.clone(),
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
fn err(code: &str, message: &str) -> AwsError {
    AwsError::new(code, message, 400)
}
fn invalid_parameter() -> AwsError {
    err("InvalidParameterException", "Invalid parameter")
}
fn not_found() -> AwsError {
    err("ResourceNotFoundException", "Certificate not found")
}
fn internal() -> AwsError {
    AwsError::new("InternalFailureException", "Internal error", 500)
}
fn fields(body: &Map<String, Value>, allowed: &[&str]) -> Result<(), AwsError> {
    if body.keys().any(|key| !allowed.contains(&key.as_str())) {
        Err(invalid_parameter())
    } else {
        Ok(())
    }
}
fn required_string<'a>(body: &'a Map<String, Value>, key: &str) -> Result<&'a str, AwsError> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(invalid_parameter)
}
fn optional_string<'a>(
    body: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, AwsError> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(s)),
        _ => Err(invalid_parameter()),
    }
}
fn optional_strings(body: &Map<String, Value>, key: &str) -> Result<Option<Vec<String>>, AwsError> {
    let Some(value) = body.get(key) else {
        return Ok(None);
    };
    let array = value.as_array().ok_or_else(invalid_parameter)?;
    if array.is_empty() || array.len() > 100 {
        return Err(invalid_parameter());
    }
    array
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or_else(invalid_parameter)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}
fn blob(
    body: &Map<String, Value>,
    key: &str,
    required: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, AwsError> {
    let Some(value) = body.get(key) else {
        return if required {
            Err(invalid_parameter())
        } else {
            Ok(None)
        };
    };
    let text = value.as_str().ok_or_else(invalid_parameter)?;
    let decoded = STANDARD.decode(text).map_err(|_| invalid_parameter())?;
    Ok(Some(Zeroizing::new(decoded)))
}
fn tags(
    body: &Map<String, Value>,
    key: &str,
    required: bool,
) -> Result<BTreeMap<String, String>, AwsError> {
    let Some(value) = body.get(key) else {
        return if required {
            Err(invalid_parameter())
        } else {
            Ok(BTreeMap::new())
        };
    };
    let list = value
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 50)
        .ok_or_else(invalid_parameter)?;
    let mut result = BTreeMap::new();
    for item in list {
        let map = item.as_object().ok_or_else(invalid_parameter)?;
        fields(map, &["Key", "Value"])?;
        let tag_key = required_string(map, "Key")?;
        let tag_value = match map.get("Value") {
            None => "",
            Some(Value::String(value)) => value.as_str(),
            _ => return Err(err("InvalidTagException", "Invalid tag")),
        };
        if tag_key.len() > 128
            || tag_value.len() > 256
            || tag_key.to_ascii_lowercase().starts_with("aws:")
            || tag_value.to_ascii_lowercase().starts_with("aws:")
        {
            return Err(err("InvalidTagException", "Invalid tag"));
        }
        if result
            .insert(tag_key.to_owned(), tag_value.to_owned())
            .is_some()
        {
            return Err(err("InvalidTagException", "Duplicate tag"));
        }
    }
    Ok(result)
}
fn validate_arn(req: &ServiceRequest, arn: &str) -> Result<(), AwsError> {
    let prefix = format!("arn:aws:acm:{}:{}:certificate/", req.region, req.account_id);
    let id = arn
        .strip_prefix(&prefix)
        .ok_or_else(|| err("InvalidArnException", "Invalid certificate ARN"))?;
    if Uuid::parse_str(id).is_err() {
        return Err(err("InvalidArnException", "Invalid certificate ARN"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_covers_exactly_one_label() {
        assert!(covers("*.example.test", "api.example.test"));
        assert!(!covers("*.example.test", "deep.api.example.test"));
        assert!(!covers("*.example.test", "example.test"));
        assert!(!covers("*.example.test", "evilexample.test"));
    }

    #[test]
    fn preflight_does_not_cross_region_or_account() {
        let handler = AcmHandler::new();
        let arn =
            "arn:aws:acm:us-east-1:000000000000:certificate/00000000-0000-4000-8000-000000000001";
        let metadata = material::MaterialMetadata {
            domain: "example.test".to_owned(),
            names: vec!["*.example.test".to_owned()],
            subject: "CN=example.test".to_owned(),
            issuer: "CN=example.test".to_owned(),
            serial: "1".to_owned(),
            not_before: 0,
            not_after: i64::MAX,
            key_algorithm: "RSA_2048",
        };
        handler
            .state
            .lock()
            .unwrap()
            .certs
            .entry(Scope {
                account: "000000000000".to_owned(),
                region: "us-east-1".to_owned(),
            })
            .or_default()
            .insert(
                arn.to_owned(),
                Certificate {
                    arn: arn.to_owned(),
                    metadata,
                    tags: BTreeMap::new(),
                    imported_at: 0,
                },
            );
        assert_eq!(
            handler.preflight("000000000000", "us-east-1", arn, "api.example.test"),
            AssociationDecision::Eligible
        );
        assert_eq!(
            handler.preflight("000000000000", "us-east-1", arn, "other.test"),
            AssociationDecision::NameNotCovered
        );
        assert_eq!(
            handler.preflight("000000000000", "eu-west-1", arn, "api.example.test"),
            AssociationDecision::NotFound
        );
        assert_eq!(
            handler.preflight("111111111111", "us-east-1", arn, "api.example.test"),
            AssociationDecision::NotFound
        );
    }
}
