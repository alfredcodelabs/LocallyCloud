//! Public certificate requests remain pending until ownership is validated.
use super::*;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct PendingRequest {
    pub token: Option<String>,
    pub validation: Vec<Value>,
    pub options: Value,
}

impl Certificate {
    pub(super) fn status(&self) -> &'static str {
        if self.request.is_some() {
            "PENDING_VALIDATION"
        } else if now() >= self.metadata.not_after {
            "EXPIRED"
        } else {
            "ISSUED"
        }
    }
    pub(super) fn certificate_type(&self) -> &'static str {
        if self.request.is_some() {
            "AMAZON_ISSUED"
        } else {
            "IMPORTED"
        }
    }
}

fn domain(value: &str, max: usize) -> Result<String, AwsError> {
    if value.len() > max {
        return Err(invalid_parameter());
    }
    let name = value.strip_prefix("*.").unwrap_or(value);
    if !name.contains('.')
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                || label.starts_with('-')
                || label.ends_with('-')
        })
    {
        return Err(invalid_parameter());
    }
    Ok(value.to_ascii_lowercase())
}

impl AcmHandler {
    pub(super) fn request_certificate(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, AwsError> {
        fields(
            body,
            &[
                "DomainName",
                "ValidationMethod",
                "SubjectAlternativeNames",
                "IdempotencyToken",
                "KeyAlgorithm",
                "Tags",
                "Options",
                "DomainValidationOptions",
            ],
        )?;
        let domain = domain(required_string(body, "DomainName")?, 64)?;
        let mut names = vec![domain.clone()];
        if let Some(sans) = optional_strings(body, "SubjectAlternativeNames")? {
            if sans.len() > 100 {
                return Err(invalid_parameter());
            }
            for name in sans {
                let name = self::domain(&name, 253)?;
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        if names.len() > 100 {
            return Err(invalid_parameter());
        }
        let method = optional_string(body, "ValidationMethod")?.unwrap_or("EMAIL");
        if !matches!(method, "EMAIL" | "DNS") {
            return Err(invalid_parameter());
        }
        let algorithm = optional_string(body, "KeyAlgorithm")?.unwrap_or("RSA_2048");
        if !matches!(algorithm, "RSA_2048" | "EC_prime256v1" | "EC_secp384r1") {
            return Err(invalid_parameter());
        }
        let token = optional_string(body, "IdempotencyToken")?;
        if token.is_some_and(|v| {
            v.is_empty()
                || v.len() > 32
                || !v.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        }) {
            return Err(invalid_parameter());
        }
        let tags = tags(body, "Tags", false)?;
        let options = match body.get("Options") {
            None => json!({"CertificateTransparencyLoggingPreference":"ENABLED"}),
            Some(Value::Object(options)) => {
                fields(options, &["CertificateTransparencyLoggingPreference"])?;
                let preference =
                    optional_string(options, "CertificateTransparencyLoggingPreference")?
                        .unwrap_or("ENABLED");
                if !matches!(preference, "ENABLED" | "DISABLED") {
                    return Err(invalid_parameter());
                }
                json!({"CertificateTransparencyLoggingPreference":preference})
            }
            _ => return Err(invalid_parameter()),
        };
        let mut validation_domains = BTreeMap::new();
        if let Some(values) = body.get("DomainValidationOptions") {
            let values = values
                .as_array()
                .filter(|values| !values.is_empty() && values.len() <= 100)
                .ok_or_else(invalid_parameter)?;
            for entry in values {
                let entry = entry.as_object().ok_or_else(invalid_parameter)?;
                fields(entry, &["DomainName", "ValidationDomain"])?;
                let name = self::domain(required_string(entry, "DomainName")?, 253)?;
                let parent = self::domain(required_string(entry, "ValidationDomain")?, 253)?;
                let plain = name.strip_prefix("*.").unwrap_or(&name);
                if !names.contains(&name)
                    || !(plain == parent || plain.ends_with(&format!(".{parent}")))
                    || validation_domains.insert(name, parent).is_some()
                {
                    return Err(invalid_parameter());
                }
            }
        }
        let scope = scope(req);
        let current = now();
        let mut state = self.state.lock().map_err(|_| internal())?;
        let certs = state.certs.entry(scope.clone()).or_default();
        if let Some(token) = token {
            if let Some(existing) = certs.values().find(|cert| {
                current.saturating_sub(cert.imported_at) < 3600
                    && cert
                        .request
                        .as_ref()
                        .is_some_and(|r| r.token.as_deref() == Some(token))
            }) {
                return Ok(json!({"CertificateArn":existing.arn}));
            }
        }
        if certs.len() >= MAX_CERTS {
            return Err(err("LimitExceededException", "Certificate limit exceeded"));
        }
        let mut records = BTreeMap::new();
        let validation = names.iter().map(|name| {
            let mut value = json!({"DomainName":name,"ValidationStatus":"PENDING_VALIDATION","ValidationMethod":method});
            if method == "DNS" {
                let label = name.strip_prefix("*.").unwrap_or(name);
                value["ResourceRecord"] = records.entry(label.to_owned()).or_insert_with(|| json!({"Name":format!("_{}.{label}.",Uuid::new_v4().simple()),"Type":"CNAME","Value":format!("_{}.acm-validations.aws.",Uuid::new_v4().simple())})).clone();
            } else {
                let parent = validation_domains.get(name).map(String::as_str).unwrap_or_else(|| name.strip_prefix("*.").unwrap_or(name));
                value["ValidationDomain"] = json!(parent);
                value["ValidationEmails"] = json!(["admin","administrator","hostmaster","postmaster","webmaster"].map(|local| format!("{local}@{parent}")));
            }
            value
        }).collect();
        let arn = format!(
            "arn:aws:acm:{}:{}:certificate/{}",
            req.region,
            req.account_id,
            Uuid::new_v4()
        );
        let certificate = Certificate {
            arn: arn.clone(),
            metadata: material::MaterialMetadata {
                domain: domain.clone(),
                names,
                subject: format!("CN={domain}"),
                issuer: String::new(),
                serial: String::new(),
                not_before: 0,
                not_after: 0,
                key_algorithm: algorithm.into(),
            },
            tags,
            imported_at: current,
            tls: None,
            associations: BTreeMap::new(),
            request: Some(PendingRequest {
                token: token.map(str::to_owned),
                validation,
                options,
            }),
        };
        self.save(&scope, &certificate)?;
        certs.insert(arn.clone(), certificate);
        Ok(json!({"CertificateArn":arn}))
    }
}
