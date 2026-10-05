//! Scoped native ACM import slice for locally supplied RSA certificates.
//! Material is validated before mutation. Private DER stays zeroized in memory and is
//! available only through the scoped internal TLS capability, never the AWS API.
mod material;
mod persistence;

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
    tls: Option<Arc<AcmTlsIdentity>>,
    associations: BTreeMap<String, String>,
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

/// Validated local TLS material for an internal consumer. Never log or serialize it.
/// The private PKCS8 DER is zeroized on drop and only stored in authenticated ciphertext.
pub struct AcmTlsIdentity {
    pub certificate_der: Vec<u8>,
    pub private_key_der: Zeroizing<Vec<u8>>,
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

    fn tls_identity(
        &self,
        account: &str,
        region: &str,
        arn: &str,
        dns_name: &str,
    ) -> Result<AcmTlsIdentity, AssociationDecision>;

    fn acquire(
        &self,
        account: &str,
        region: &str,
        arn: &str,
        dns_name: &str,
        consumer_id: &str,
    ) -> Result<(), AssociationDecision>;

    fn release(
        &self,
        account: &str,
        region: &str,
        arn: &str,
        consumer_id: &str,
    ) -> Result<(), AssociationDecision>;
}

#[derive(Clone, Default)]
pub struct AcmHandler {
    state: Arc<Mutex<State>>,
    persistence: Option<Arc<persistence::AcmPersistence>>,
}

impl AcmHandler {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn save(&self, scope: &Scope, cert: &Certificate) -> Result<(), AwsError> {
        if let Some(persistence) = &self.persistence {
            persistence.save(scope, cert)?;
        }
        Ok(())
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
        let material = material::validate(&cert, &key, now).map_err(|_| invalid_parameter())?;
        let metadata = material.metadata;
        let tls = Arc::new(AcmTlsIdentity {
            certificate_der: material.certificate_der,
            private_key_der: material.private_key_der,
        });
        let scope = scope(req);
        let mut state = self.state.lock().map_err(|_| internal())?;
        if let Some(arn) = replacement {
            validate_arn(req, arn)?;
            let existing = state
                .certs
                .get_mut(&scope)
                .and_then(|certs| certs.get_mut(arn))
                .ok_or_else(not_found)?;
            if existing.metadata.key_algorithm != metadata.key_algorithm {
                return Err(invalid_parameter());
            }
            if existing
                .associations
                .values()
                .any(|dns_name| !metadata.names.iter().any(|name| covers(name, dns_name)))
            {
                return Err(invalid_parameter());
            }
            let mut replacement = existing.clone();
            replacement.metadata = metadata;
            replacement.tls = Some(tls);
            replacement.imported_at = now;
            self.save(&scope, &replacement)?;
            *existing = replacement;
            return Ok(json!({"CertificateArn": arn}));
        }
        let certs = state.certs.entry(scope.clone()).or_default();
        if certs.len() >= MAX_CERTS {
            return Err(err("LimitExceededException", "Certificate limit exceeded"));
        }
        let arn = format!(
            "arn:aws:acm:{}:{}:certificate/{}",
            req.region,
            req.account_id,
            Uuid::new_v4()
        );
        let certificate = Certificate {
            arn: arn.clone(),
            metadata,
            tags,
            imported_at: now,
            tls: Some(tls),
            associations: BTreeMap::new(),
        };
        self.save(&scope, &certificate)?;
        certs.insert(arn.clone(), certificate);
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
            "InUseBy": cert.associations.keys().collect::<Vec<_>>(),
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
                let key_type = cert.metadata.key_algorithm.as_str();
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
                            "KeyAlgorithm": key_type, "HasAdditionalSubjectAlternativeNames": false, "InUse": !cert.associations.is_empty()}));
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
        let certs = state.certs.get_mut(&scope(req)).ok_or_else(not_found)?;
        let cert = certs.get(arn).ok_or_else(not_found)?;
        if !cert.associations.is_empty() {
            return Err(err("ResourceInUseException", "The certificate is in use"));
        }
        if let Some(persistence) = &self.persistence {
            persistence.delete(&scope(req), arn)?;
        }
        certs.remove(arn);
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
        let mut updated = cert.clone();
        updated.tags.extend(additions);
        self.save(&scope(req), &updated)?;
        *cert = updated;
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
        let mut updated = cert.clone();
        for key in removals.keys() {
            updated.tags.remove(key);
        }
        self.save(&scope(req), &updated)?;
        *cert = updated;
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

fn eligible_certificate<'a>(
    state: &'a State,
    account: &str,
    region: &str,
    arn: &str,
    dns_name: &str,
) -> Result<&'a Certificate, AssociationDecision> {
    let scope = Scope {
        account: account.to_owned(),
        region: region.to_owned(),
    };
    let cert = state
        .certs
        .get(&scope)
        .and_then(|certs| certs.get(arn))
        .ok_or(AssociationDecision::NotFound)?;
    let now = now();
    if now < cert.metadata.not_before || now >= cert.metadata.not_after {
        return Err(AssociationDecision::UnsupportedMaterial);
    }
    if !cert
        .metadata
        .names
        .iter()
        .any(|name| covers(name, dns_name))
    {
        return Err(AssociationDecision::NameNotCovered);
    }
    Ok(cert)
}

impl AcmAssociationApi for AcmHandler {
    fn preflight(
        &self,
        account: &str,
        region: &str,
        arn: &str,
        dns_name: &str,
    ) -> AssociationDecision {
        let Ok(state) = self.state.lock() else {
            return AssociationDecision::StateUnavailable;
        };
        eligible_certificate(&state, account, region, arn, dns_name)
            .map(|_| AssociationDecision::Eligible)
            .unwrap_or_else(|decision| decision)
    }

    fn tls_identity(
        &self,
        account: &str,
        region: &str,
        arn: &str,
        dns_name: &str,
    ) -> Result<AcmTlsIdentity, AssociationDecision> {
        let state = self
            .state
            .lock()
            .map_err(|_| AssociationDecision::StateUnavailable)?;
        let material = eligible_certificate(&state, account, region, arn, dns_name)?
            .tls
            .as_ref()
            .ok_or(AssociationDecision::UnsupportedMaterial)?;
        Ok(AcmTlsIdentity {
            certificate_der: material.certificate_der.clone(),
            private_key_der: Zeroizing::new(material.private_key_der.to_vec()),
        })
    }

    fn acquire(
        &self,
        account: &str,
        region: &str,
        arn: &str,
        dns_name: &str,
        consumer_id: &str,
    ) -> Result<(), AssociationDecision> {
        if consumer_id.is_empty() || consumer_id.len() > 2048 {
            return Err(AssociationDecision::UnsupportedMaterial);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| AssociationDecision::StateUnavailable)?;
        eligible_certificate(&state, account, region, arn, dns_name)?;
        let scope = Scope {
            account: account.into(),
            region: region.into(),
        };
        state
            .certs
            .get_mut(&scope)
            .and_then(|certs| certs.get_mut(arn))
            .ok_or(AssociationDecision::NotFound)?
            .associations
            .insert(consumer_id.into(), dns_name.into());
        Ok(())
    }

    fn release(
        &self,
        account: &str,
        region: &str,
        arn: &str,
        consumer_id: &str,
    ) -> Result<(), AssociationDecision> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AssociationDecision::StateUnavailable)?;
        let scope = Scope {
            account: account.into(),
            region: region.into(),
        };
        let cert = state
            .certs
            .get_mut(&scope)
            .and_then(|certs| certs.get_mut(arn))
            .ok_or(AssociationDecision::NotFound)?;
        cert.associations.remove(consumer_id);
        Ok(())
    }
}

fn covers(pattern: &str, name: &str) -> bool {
    if pattern.eq_ignore_ascii_case(name) {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let normalized = name.to_ascii_lowercase();
        let suffix = suffix.to_ascii_lowercase();
        if let Some(prefix) = normalized.strip_suffix(&suffix) {
            return prefix.ends_with('.')
                && prefix[..prefix.len() - 1].bytes().all(|b| b != b'.')
                && prefix.len() > 1;
        }
    }
    false
}

#[async_trait]
impl NativeHandler for AcmHandler {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "ACM inventory unavailable")?
            .certs
            .iter()
            .filter(|(k, v)| k.account == account && !v.is_empty())
            .map(|(k, _)| k.region.clone())
            .collect())
    }

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
                    Ok(Value::Object(body)) => {
                        let handler = self.clone();
                        let op = op.to_owned();
                        let request = request.clone();
                        tokio::task::spawn_blocking(move || handler.execute(&op, &request, &body))
                            .await
                            .unwrap_or_else(|_| Err(internal()))
                    }
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
    register_handler(registry, AcmHandler::new())
}

pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    db: Arc<locallycloud_state::StateDb>,
) -> Result<Arc<AcmHandler>, AwsError> {
    let persistence = persistence::AcmPersistence::new(db)?;
    let state = persistence.restore()?;
    Ok(register_handler(
        registry,
        Arc::new(AcmHandler {
            state: Arc::new(Mutex::new(state)),
            persistence: Some(Arc::new(persistence)),
        }),
    ))
}

fn register_handler(registry: &Arc<ServiceRegistry>, handler: Arc<AcmHandler>) -> Arc<AcmHandler> {
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

    use std::io::Write;
    use std::process::{Command, Stdio};
    pub(super) fn fixture(dns_name: &str, bits: &str) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
        let generated = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                &format!("rsa_keygen_bits:{bits}"),
            ])
            .output()
            .unwrap();
        let private_pem = Zeroizing::new(generated.stdout);
        assert!(generated.status.success());
        let mut child = Command::new("openssl")
            .args([
                "req",
                "-new",
                "-x509",
                "-key",
                "/dev/stdin",
                "-days",
                "1",
                "-subj",
                &format!("/CN={dns_name}"),
                "-addext",
                &format!("subjectAltName=DNS:{dns_name}"),
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-addext",
                "keyUsage=digitalSignature,keyEncipherment",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&private_pem).unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success());
        (result.stdout, private_pem)
    }
    #[test]
    fn tls_material_import_is_scoped_atomic_redacted_and_revocable() {
        let handler = AcmHandler::new();
        let req = ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: http::HeaderMap::new(),
            body: Default::default(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "tls-import".into(),
        };
        let (cert, key) = fixture("api.example.test", "2048");
        let mut import =
            json!({"Certificate":STANDARD.encode(&cert), "PrivateKey":STANDARD.encode(&key)})
                .as_object()
                .unwrap()
                .clone();
        let arn = handler.import(&req, &import).unwrap()["CertificateArn"]
            .as_str()
            .unwrap()
            .to_owned();
        let first = handler
            .tls_identity(&req.account_id, &req.region, &arn, "api.example.test")
            .unwrap();
        assert_eq!(
            first.certificate_der,
            pem::parse(&cert).unwrap().into_contents()
        );
        assert!(
            first.private_key_der.as_slice() == pem::parse(&key).unwrap().contents(),
            "private DER mismatch"
        );
        assert!(matches!(
            handler.tls_identity(&req.account_id, "eu-west-1", &arn, "api.example.test"),
            Err(AssociationDecision::NotFound)
        ));
        assert!(matches!(
            handler.tls_identity("111111111111", &req.region, &arn, "api.example.test"),
            Err(AssociationDecision::NotFound)
        ));
        assert!(matches!(
            handler.tls_identity(&req.account_id, &req.region, &arn, "other.example.test"),
            Err(AssociationDecision::NameNotCovered)
        ));
        let lookup = json!({"CertificateArn":arn}).as_object().unwrap().clone();
        let described = handler.describe(&req, &lookup).unwrap().to_string();
        assert!(!described.contains("PrivateKey") && !described.contains(&STANDARD.encode(&key)));
        let consumer = "arn:aws:apigateway:us-east-1::/domainnames/api.example.test";
        handler
            .acquire(
                &req.account_id,
                &req.region,
                &arn,
                "api.example.test",
                consumer,
            )
            .unwrap();
        assert_eq!(
            handler.describe(&req, &lookup).unwrap()["Certificate"]["InUseBy"],
            json!([consumer])
        );
        assert!(handler.delete(&req, &lookup).is_err());
        assert!(handler
            .release("111111111111", &req.region, &arn, consumer)
            .is_err());
        assert!(handler.delete(&req, &lookup).is_err());
        let (wrong_name_cert, wrong_name_key) = fixture("other.example.test", "2048");
        let wrong_name = json!({"CertificateArn":arn,"Certificate":STANDARD.encode(&wrong_name_cert),"PrivateKey":STANDARD.encode(&wrong_name_key)}).as_object().unwrap().clone();
        assert!(handler.import(&req, &wrong_name).is_err());
        assert_eq!(
            handler
                .tls_identity(&req.account_id, &req.region, &arn, "api.example.test")
                .unwrap()
                .certificate_der,
            first.certificate_der
        );
        let (different_size_cert, different_size_key) = fixture("api.example.test", "3072");
        let different_size = json!({"CertificateArn":arn,"Certificate":STANDARD.encode(&different_size_cert),"PrivateKey":STANDARD.encode(&different_size_key)}).as_object().unwrap().clone();
        assert!(handler.import(&req, &different_size).is_err());
        let (next_cert, next_key) = fixture("api.example.test", "2048");
        import.insert("CertificateArn".into(), json!(arn));
        import.insert("Certificate".into(), json!(STANDARD.encode(&next_cert)));
        assert!(handler.import(&req, &import).is_err()); // Invalid pair cannot replace live TLS material.
        assert_eq!(
            handler
                .tls_identity(&req.account_id, &req.region, &arn, "api.example.test")
                .unwrap()
                .certificate_der,
            first.certificate_der
        );
        import.insert("PrivateKey".into(), json!(STANDARD.encode(&next_key)));
        handler.import(&req, &import).unwrap();
        let updated = handler
            .tls_identity(&req.account_id, &req.region, &arn, "api.example.test")
            .unwrap();
        assert_ne!(updated.certificate_der, first.certificate_der);
        assert!(
            updated.private_key_der.as_slice() != first.private_key_der.as_slice(),
            "private DER was not replaced"
        );
        handler
            .state
            .lock()
            .unwrap()
            .certs
            .get_mut(&scope(&req))
            .unwrap()
            .get_mut(&arn)
            .unwrap()
            .metadata
            .not_after = now();
        assert!(matches!(
            handler.tls_identity(&req.account_id, &req.region, &arn, "api.example.test"),
            Err(AssociationDecision::UnsupportedMaterial)
        ));
        handler
            .release(&req.account_id, &req.region, &arn, consumer)
            .unwrap();
        handler
            .release(&req.account_id, &req.region, &arn, consumer)
            .unwrap(); // Same consumer release is idempotent.
        handler.delete(&req, &lookup).unwrap();
        assert!(matches!(
            handler.tls_identity(&req.account_id, &req.region, &arn, "api.example.test"),
            Err(AssociationDecision::NotFound)
        ));
    }

    #[test]
    fn wildcard_covers_exactly_one_label() {
        assert!(covers("*.example.test", "api.example.test"));
        assert!(covers("*.EXAMPLE.TEST", "API.example.test"));
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
            key_algorithm: "RSA_2048".to_owned(),
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
                    tls: None,
                    associations: BTreeMap::new(),
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
