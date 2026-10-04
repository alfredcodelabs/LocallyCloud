//! Deliberately small KMS key-policy evaluator. Unsupported policy constructs fail closed.
use serde_json::Value;
use std::collections::BTreeMap;

use crate::error::KmsError;

#[derive(Clone)]
pub(crate) struct KeyPolicy {
    raw: String,
    statements: Vec<Statement>,
}

#[derive(Clone)]
struct Statement {
    deny: bool,
    principals: Vec<String>,
    actions: Vec<String>,
    resources: Vec<String>,
    conditions: Vec<(String, String, Vec<String>)>,
}

impl KeyPolicy {
    pub(crate) fn default_for(account: &str) -> Self {
        let raw = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {"AWS": format!("arn:aws:iam::{account}:root")},
                "Action": "kms:*",
                "Resource": "*"
            }]
        })
        .to_string();
        Self::parse(raw).expect("default policy is valid")
    }

    pub(crate) fn parse(raw: String) -> Result<Self, KmsError> {
        if raw.is_empty() || raw.len() > 32_768 {
            return Err(KmsError::Validation);
        }
        let root: Value = serde_json::from_str(&raw).map_err(|_| KmsError::Validation)?;
        let entries = match root.get("Statement") {
            Some(Value::Array(entries)) if !entries.is_empty() => entries.clone(),
            Some(Value::Object(_)) => vec![root["Statement"].clone()],
            _ => return Err(KmsError::Validation),
        };
        let mut statements = Vec::with_capacity(entries.len());
        for entry in entries {
            let effect = entry
                .get("Effect")
                .and_then(Value::as_str)
                .ok_or(KmsError::Validation)?;
            let deny = match effect {
                "Deny" => true,
                "Allow" => false,
                _ => return Err(KmsError::Validation),
            };
            let principal = entry.get("Principal").ok_or(KmsError::Validation)?;
            let principals = match principal {
                Value::String(s) if s == "*" => vec![s.clone()],
                Value::Object(map) if map.len() == 1 => {
                    let (kind, value) = map.iter().next().ok_or(KmsError::Validation)?;
                    if kind != "AWS" && kind != "Service" {
                        return Err(KmsError::Unsupported);
                    }
                    strings(value)?
                }
                _ => return Err(KmsError::Unsupported),
            };
            if principals.is_empty() {
                return Err(KmsError::Validation);
            }
            let actions = strings(entry.get("Action").ok_or(KmsError::Validation)?)?;
            let resources = strings(entry.get("Resource").ok_or(KmsError::Validation)?)?;
            if actions.is_empty() || resources.is_empty() || resources.iter().any(|r| r != "*") {
                return Err(KmsError::Unsupported);
            }
            if entry.get("NotAction").is_some()
                || entry.get("NotPrincipal").is_some()
                || entry.get("NotResource").is_some()
            {
                return Err(KmsError::Unsupported);
            }
            let mut parsed_conditions = Vec::new();
            if let Some(conditions) = entry.get("Condition") {
                let map = conditions.as_object().ok_or(KmsError::Validation)?;
                for (operator, values) in map {
                    if !matches!(
                        operator.as_str(),
                        "StringEquals"
                            | "StringLike"
                            | "ArnEquals"
                            | "ArnLike"
                            | "StringEqualsIfExists"
                            | "StringLikeIfExists"
                            | "ArnEqualsIfExists"
                            | "ArnLikeIfExists"
                            | "Null"
                    ) {
                        return Err(KmsError::Unsupported);
                    }
                    let values = values.as_object().ok_or(KmsError::Validation)?;
                    for (name, value) in values {
                        let name = name.to_ascii_lowercase();
                        if !matches!(
                            name.as_str(),
                            "aws:sourcearn"
                                | "aws:sourceaccount"
                                | "kms:viaservice"
                                | "kms:calleraccount"
                                | "kms:encryptioncontextkeys"
                        ) && !name.starts_with("kms:encryptioncontext:")
                        {
                            return Err(KmsError::Unsupported);
                        }
                        let candidates = strings(value)?;
                        if operator == "Null"
                            && candidates
                                .iter()
                                .any(|value| value != "true" && value != "false")
                        {
                            return Err(KmsError::Validation);
                        }
                        parsed_conditions.push((operator.clone(), name, candidates));
                    }
                }
            }
            statements.push(Statement {
                deny,
                principals,
                actions,
                resources,
                conditions: parsed_conditions,
            });
        }
        Ok(Self { raw, statements })
    }

    pub(crate) fn raw(&self) -> &str {
        &self.raw
    }

    pub(crate) fn allows(
        &self,
        principal: Option<&str>,
        action: &str,
        source_arn: Option<&str>,
        source_account: &str,
    ) -> bool {
        self.allows_with_iam(principal, action, source_arn, source_account, false)
    }

    pub(crate) fn allows_with_iam(
        &self,
        principal: Option<&str>,
        action: &str,
        source_arn: Option<&str>,
        source_account: &str,
        iam_policy_allowed: bool,
    ) -> bool {
        let mut context = BTreeMap::new();
        if let Some(arn) = source_arn {
            context.insert("aws:sourcearn".into(), vec![arn.into()]);
            context.insert("aws:sourceaccount".into(), vec![source_account.into()]);
        }
        self.allows_in_context(
            principal,
            action,
            source_account,
            iam_policy_allowed,
            &context,
        )
    }

    pub(crate) fn allows_in_context(
        &self,
        principal: Option<&str>,
        action: &str,
        source_account: &str,
        iam_policy_allowed: bool,
        context: &BTreeMap<String, Vec<String>>,
    ) -> bool {
        let root = format!("arn:aws:iam::{source_account}:root");
        let same_account = principal.is_some_and(|arn| {
            arn.starts_with(&format!("arn:aws:iam::{source_account}:"))
                || arn.starts_with(&format!("arn:aws:sts::{source_account}:"))
        });
        let mut allowed = false;
        for statement in &self.statements {
            let direct = statement
                .principals
                .iter()
                .any(|p| p == "*" || Some(p.as_str()) == principal);
            let account = same_account && statement.principals.iter().any(|p| p == &root);
            if !(direct || (account && (statement.deny || iam_policy_allowed)))
                || !statement
                    .actions
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case("kms:*") || a.eq_ignore_ascii_case(action))
                || statement.resources.is_empty()
                || !statement
                    .conditions
                    .iter()
                    .all(|(op, key, values)| condition_matches(op, key, values, context))
            {
                continue;
            }
            if statement.deny {
                return false;
            }
            allowed = true;
        }
        allowed
    }
}

fn condition_matches(
    op: &str,
    key: &str,
    values: &[String],
    context: &BTreeMap<String, Vec<String>>,
) -> bool {
    let actual = context.get(key).filter(|values| !values.is_empty());
    if op == "Null" {
        return values
            .iter()
            .any(|value| (value == "true") == actual.is_none());
    }
    let (base, if_exists) = op
        .strip_suffix("IfExists")
        .map_or((op, false), |base| (base, true));
    let Some(actual) = actual else {
        return if_exists;
    };
    actual.iter().any(|value| {
        values.iter().any(|candidate| match base {
            "StringEquals" => candidate == value,
            "StringLike" | "ArnLike" | "ArnEquals" => wildcard(candidate, value),
            _ => false,
        })
    })
}

// Case-sensitive wildcard matching for condition values; never case-fold object ARNs.
fn wildcard(pattern: &str, value: &str) -> bool {
    let p: Vec<_> = pattern.chars().collect();
    let v: Vec<_> = value.chars().collect();
    let (mut pi, mut vi, mut star, mut retry) = (0, 0, None, 0);
    while vi < v.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            retry = vi;
        } else if let Some(index) = star {
            pi = index + 1;
            retry += 1;
            vi = retry;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn strings(value: &Value) -> Result<Vec<String>, KmsError> {
    match value {
        Value::String(s) if !s.is_empty() => Ok(vec![s.clone()]),
        Value::Array(items) if !items.is_empty() => items
            .iter()
            .map(|item| {
                item.as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .ok_or(KmsError::Validation)
            })
            .collect(),
        _ => Err(KmsError::Validation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_deny_overrides_allow_and_unknown_principal_fails_closed() {
        let policy = KeyPolicy::parse(serde_json::json!({
            "Statement": [
                {"Effect":"Allow","Principal":"*","Action":"kms:GenerateDataKey","Resource":"*"},
                {"Effect":"Deny","Principal":{"Service":"events.amazonaws.com"},"Action":"kms:GenerateDataKey","Resource":"*"}
            ]
        }).to_string()).unwrap();
        assert!(policy.allows(None, "kms:GenerateDataKey", None, "000000000000"));
        assert!(!policy.allows(
            Some("events.amazonaws.com"),
            "kms:GenerateDataKey",
            None,
            "000000000000"
        ));
        assert!(!policy.allows(None, "kms:Decrypt", None, "000000000000"));
    }

    #[test]
    fn account_principal_requires_iam_allow_and_deny_wins() {
        let account = "000000000000";
        let user = format!("arn:aws:iam::{account}:user/alice");
        let root = format!("arn:aws:iam::{account}:root");
        let policy = KeyPolicy::parse(
            serde_json::json!({
                "Statement": [{
                    "Effect": "Allow", "Principal": {"AWS": root},
                    "Action": "kms:Decrypt", "Resource": "*"
                }]
            })
            .to_string(),
        )
        .unwrap();
        assert!(!policy.allows_with_iam(Some(&user), "kms:Decrypt", None, account, false));
        assert!(policy.allows_with_iam(Some(&user), "kms:Decrypt", None, account, true));
        assert!(!policy.allows_with_iam(
            Some("arn:aws:iam::999999999999:user/alice"),
            "kms:Decrypt",
            None,
            account,
            true
        ));
        let denied = KeyPolicy::parse(serde_json::json!({
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": root}, "Action": "kms:Decrypt", "Resource": "*"},
                {"Effect": "Deny", "Principal": {"AWS": user}, "Action": "kms:Decrypt", "Resource": "*"}
            ]
        }).to_string()).unwrap();
        assert!(!denied.allows_with_iam(Some(&user), "kms:Decrypt", None, account, true));
    }

    #[test]
    fn source_arn_condition_needs_matching_context() {
        let policy = KeyPolicy::parse(serde_json::json!({
            "Statement": {"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"kms:GenerateDataKey","Resource":"*","Condition":{"ArnEquals":{"aws:SourceArn":"arn:aws:events:us-east-1:000000000000:rule/test"}}}
        }).to_string()).unwrap();
        let principal = Some("events.amazonaws.com");
        assert!(!policy.allows(principal, "kms:GenerateDataKey", None, "000000000000"));
        assert!(policy.allows(
            principal,
            "kms:GenerateDataKey",
            Some("arn:aws:events:us-east-1:000000000000:rule/test"),
            "000000000000"
        ));
    }
}
