//! Resource policy principal filtering over the shared IAM statement engine.
use crate::policy::{PolicyDocument, Statement};
use locallycloud_core::integration::authorization::ResourcePolicyError;
use serde_json::Value;

pub(crate) struct ResourceStatement {
    pub statement: Statement,
    principals: Vec<Principal>,
}
#[derive(Debug)]
enum Principal {
    Any,
    Account(String),
    Arn(String),
    Service(String),
}

pub(crate) fn parse(document: &str) -> Result<Vec<ResourceStatement>, ResourcePolicyError> {
    let malformed = |message: String| ResourcePolicyError::Malformed(message);
    let root: Value = serde_json::from_str(document).map_err(|e| malformed(e.to_string()))?;
    let object = root
        .as_object()
        .ok_or_else(|| malformed("policy must be an object".into()))?;
    for key in object.keys() {
        if !matches!(key.as_str(), "Version" | "Id" | "Statement") {
            return Err(ResourcePolicyError::Unsupported(format!(
                "policy member {key}"
            )));
        }
    }
    if root.get("Id").is_some_and(|value| !value.is_string()) {
        return Err(malformed("policy Id must be a string".into()));
    }
    if let Some(version) = root.get("Version") {
        if !matches!(version.as_str(), Some("2012-10-17" | "2008-10-17")) {
            return Err(malformed("invalid policy Version".into()));
        }
    }
    if document.contains("${") {
        return Err(ResourcePolicyError::Unsupported("policy variables".into()));
    }
    let parsed = PolicyDocument::parse(document).map_err(|e| malformed(e.to_string()))?;
    let raw = match &root["Statement"] {
        Value::Array(items) => items.iter().collect::<Vec<_>>(),
        item => vec![item],
    };
    raw.into_iter()
        .zip(parsed.statements)
        .map(|(raw, statement)| {
            if raw.get("Sid").is_some_and(|value| !value.is_string()) {
                return Err(malformed("statement Sid must be a string".into()));
            }
            for key in raw.as_object().expect("parsed statement").keys() {
                if !matches!(
                    key.as_str(),
                    "Sid"
                        | "Effect"
                        | "Principal"
                        | "Action"
                        | "NotAction"
                        | "Resource"
                        | "NotResource"
                        | "Condition"
                ) {
                    return Err(ResourcePolicyError::Unsupported(format!(
                        "statement member {key}"
                    )));
                }
            }
            for operator in statement.conditions.keys() {
                let base = operator.strip_suffix("IfExists").unwrap_or(operator);
                if !matches!(
                    base,
                    "Null"
                        | "Bool"
                        | "StringEquals"
                        | "StringNotEquals"
                        | "StringEqualsIgnoreCase"
                        | "StringNotEqualsIgnoreCase"
                        | "StringLike"
                        | "StringNotLike"
                        | "ArnEquals"
                        | "ArnLike"
                        | "ArnNotEquals"
                        | "ArnNotLike"
                        | "IpAddress"
                        | "NotIpAddress"
                        | "NumericEquals"
                        | "NumericNotEquals"
                        | "NumericLessThan"
                        | "NumericLessThanEquals"
                        | "NumericGreaterThan"
                        | "NumericGreaterThanEquals"
                ) {
                    return Err(ResourcePolicyError::Unsupported(format!(
                        "condition operator {operator}"
                    )));
                }
            }
            for (operator, keys) in &statement.conditions {
                if operator.starts_with("Numeric") {
                    if keys.keys().any(|key| key != "s3:max-keys") {
                        return Err(ResourcePolicyError::Unsupported(
                            "numeric resource condition key".into(),
                        ));
                    }
                    if keys
                        .values()
                        .flatten()
                        .any(|value| !value.parse::<f64>().is_ok_and(f64::is_finite))
                    {
                        return Err(malformed(
                            "numeric conditions require finite numbers".into(),
                        ));
                    }
                }
            }
            for (operator, keys) in &statement.conditions {
                if matches!(
                    operator.strip_suffix("IfExists").unwrap_or(operator),
                    "Bool" | "Null"
                ) && keys
                    .values()
                    .flatten()
                    .any(|value| !matches!(value.as_str(), "true" | "false"))
                {
                    return Err(malformed("Bool and Null require true or false".into()));
                }
            }
            for (operator, keys) in &statement.conditions {
                if matches!(
                    operator.strip_suffix("IfExists").unwrap_or(operator),
                    "IpAddress" | "NotIpAddress"
                ) {
                    for value in keys.values().flatten() {
                        let (address, bits) = value.split_once('/').unwrap_or((value, "32"));
                        if address.parse::<std::net::Ipv4Addr>().is_err()
                            || !matches!(bits.parse::<u8>(), Ok(0..=32))
                        {
                            return Err(ResourcePolicyError::Unsupported(
                                "non-IPv4 condition address".into(),
                            ));
                        }
                    }
                }
            }
            for keys in statement.conditions.values() {
                for key in keys.keys() {
                    if !matches!(
                        key.as_str(),
                        "aws:securetransport"
                            | "aws:principalarn"
                            | "aws:principalaccount"
                            | "aws:principaltype"
                            | "aws:principalisawsservice"
                            | "aws:sourcearn"
                            | "aws:sourceaccount"
                            | "aws:requestedregion"
                            | "aws:sourceip"
                            | "s3:prefix"
                            | "s3:delimiter"
                            | "s3:max-keys"
                    ) {
                        return Err(ResourcePolicyError::Unsupported(format!(
                            "condition key {key}"
                        )));
                    }
                }
            }
            let principals = match raw.get("Principal") {
                Some(Value::String(value)) if value == "*" => vec![Principal::Any],
                Some(Value::Object(map)) if !map.is_empty() => {
                    let mut principals = Vec::new();
                    for (kind, value) in map {
                        if !matches!(kind.as_str(), "AWS" | "Service") {
                            return Err(ResourcePolicyError::Unsupported(format!(
                                "principal kind {kind}"
                            )));
                        }
                        let values = match value {
                            Value::String(value) => vec![value.as_str()],
                            Value::Array(items) if !items.is_empty() => items
                                .iter()
                                .map(|v| {
                                    v.as_str().ok_or_else(|| {
                                        malformed("principal must contain strings".into())
                                    })
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                            _ => return Err(malformed("invalid principal".into())),
                        };
                        for value in values {
                            principals.push(match kind.as_str() {
                                "Service"
                                    if value.ends_with(".amazonaws.com")
                                        && !value.contains(['*', '?']) =>
                                {
                                    Principal::Service(value.into())
                                }
                                "AWS" if value == "*" => Principal::Any,
                                "AWS" if account_id(value) => Principal::Account(value.into()),
                                "AWS" => {
                                    let parts = value.splitn(6, ':').collect::<Vec<_>>();
                                    if parts.len() != 6
                                        || parts[0] != "arn"
                                        || parts[1].is_empty()
                                        || parts[2].is_empty()
                                        || !account_id(parts[4])
                                        || parts[5].is_empty()
                                        || value.contains(['*', '?'])
                                    {
                                        return Err(malformed(
                                            "invalid AWS principal syntax".into(),
                                        ));
                                    }
                                    if parts[1] != "aws" || parts[2] != "iam" {
                                        return Err(ResourcePolicyError::Unsupported(
                                            "AWS principal partition or service".into(),
                                        ));
                                    }
                                    if !parts[3].is_empty() {
                                        return Err(malformed(
                                            "IAM principal ARN region must be empty".into(),
                                        ));
                                    }
                                    match parts[5] {
                                        "root" => Principal::Account(parts[4].into()),
                                        resource
                                            if (resource.starts_with("user/")
                                                || resource.starts_with("role/"))
                                                && resource
                                                    .split_once('/')
                                                    .is_some_and(|(_, name)| !name.is_empty()) =>
                                        {
                                            Principal::Arn(value.into())
                                        }
                                        _ => {
                                            return Err(ResourcePolicyError::Unsupported(
                                                "AWS principal type".into(),
                                            ))
                                        }
                                    }
                                }
                                _ => return Err(malformed("invalid service principal".into())),
                            });
                        }
                    }
                    principals
                }
                _ => return Err(malformed("statement requires Principal".into())),
            };
            Ok(ResourceStatement {
                statement,
                principals,
            })
        })
        .collect()
}
fn account_id(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|v| v.is_ascii_digit())
}
impl ResourceStatement {
    pub(crate) fn grants_principal_arn_session(&self) -> bool {
        self.principals
            .iter()
            .any(|principal| matches!(principal, Principal::Any))
            && self
                .statement
                .conditions
                .values()
                .any(|keys| keys.contains_key("aws:principalarn"))
    }

    /// True means a direct grant; account grants require identity delegation.
    pub(crate) fn principal_match(
        &self,
        account: &str,
        arn: Option<&str>,
        service: Option<&str>,
    ) -> Option<bool> {
        let mut delegated = false;
        for principal in &self.principals {
            match principal {
                Principal::Any => return Some(true),
                Principal::Arn(value) if Some(value.as_str()) == arn => return Some(true),
                Principal::Service(value) if Some(value.as_str()) == service => return Some(true),
                Principal::Account(value)
                    if value == account && service.is_none() && arn.is_some() =>
                {
                    delegated = true
                }
                _ => {}
            }
        }
        delegated.then_some(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_policy_metadata_and_principals_are_rejected() {
        let base = serde_json::json!({"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Principal":{"AWS":"123456789012"}}});
        for location in ["Id", "Sid"] {
            let mut document = base.clone();
            if location == "Id" {
                document[location] = serde_json::json!(42);
            } else {
                document["Statement"][location] = serde_json::json!([]);
            }
            assert!(matches!(
                parse(&document.to_string()),
                Err(ResourcePolicyError::Malformed(_))
            ));
        }
        for principal in ["junk", "123", "arn:aws:iam::123456789012:user/*"] {
            let mut document = base.clone();
            document["Statement"]["Principal"]["AWS"] = serde_json::json!(principal);
            assert!(matches!(
                parse(&document.to_string()),
                Err(ResourcePolicyError::Malformed(_))
            ));
        }
        for principal in [
            "arn:aws-cn:iam::123456789012:user/person",
            "arn:aws:sts::123456789012:assumed-role/role/session",
        ] {
            let mut document = base.clone();
            document["Statement"]["Principal"]["AWS"] = serde_json::json!(principal);
            assert!(matches!(
                parse(&document.to_string()),
                Err(ResourcePolicyError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn principals_and_unimplemented_constructs_fail_closed() {
        let policy = |principal: Value| {
            serde_json::json!({"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Principal":principal}}).to_string()
        };
        let parsed = parse(&policy(serde_json::json!({"AWS":["123456789012","arn:aws:iam::123456789012:user/a"],"Service":"logs.amazonaws.com"}))).unwrap();
        assert_eq!(
            parsed[0].principal_match(
                "123456789012",
                Some("arn:aws:iam::123456789012:user/a"),
                None
            ),
            Some(true)
        );
        assert_eq!(
            parsed[0].principal_match(
                "123456789012",
                Some("arn:aws:iam::123456789012:user/b"),
                None
            ),
            Some(false)
        );
        assert_eq!(
            parsed[0].principal_match("123456789012", None, Some("other.amazonaws.com")),
            None
        );
        assert!(matches!(
            parse(&policy(
                serde_json::json!({"AWS":"arn:aws:iam::123456789012:user/*"})
            )),
            Err(ResourcePolicyError::Malformed(_))
        ));
        assert_eq!(parsed[0].principal_match("123456789012", None, None), None);
        let unknown = serde_json::json!({"Statement":{"Effect":"Deny","Action":"*","Resource":"*","Principal":"*","Condition":{"UnknownIfExists":{"aws:SecureTransport":"false"}}}});
        assert!(matches!(
            parse(&unknown.to_string()),
            Err(ResourcePolicyError::Unsupported(_))
        ));
        let unknown = serde_json::json!({"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Principal":"*","Condition":{"StringEqualsIfExists":{"aws:Unknown":"anything"}}}});
        assert!(matches!(
            parse(&unknown.to_string()),
            Err(ResourcePolicyError::Unsupported(_))
        ));
    }
}
