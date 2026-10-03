//! Narrow SQS resource-policy check for data-plane dispatch.
//! Unsupported constructs fail closed while the full IAM resource-policy evaluator is pending.

use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    Allow,
    Deny,
    Unmatched,
}

fn values(value: Option<&Value>) -> Option<Vec<&str>> {
    match value? {
        Value::String(value) if !value.is_empty() => Some(vec![value]),
        Value::Array(values) if !values.is_empty() => {
            values.iter().map(Value::as_str).collect::<Option<Vec<_>>>()
        }
        _ => None,
    }
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    pattern == "*"
        || pattern.eq_ignore_ascii_case(value)
        || pattern.strip_suffix('*').is_some_and(|prefix| {
            value
                .to_ascii_lowercase()
                .starts_with(&prefix.to_ascii_lowercase())
        })
}

fn principal_matches(statement: &Value, principal: &str, account: &str) -> Option<bool> {
    let raw = statement.get("Principal")?;
    if raw.as_str() == Some("*") {
        return Some(true);
    }
    let map = raw.as_object()?;
    if map.len() != 1 {
        return None;
    }
    let (kind, principals) = map.iter().next()?;
    if kind != "AWS" && kind != "Service" {
        return None;
    }
    let principals = values(Some(principals))?;
    let root = format!("arn:aws:iam::{account}:root");
    Some(principals.into_iter().any(|candidate| {
        candidate == "*"
            || candidate == principal
            || (kind == "AWS"
                && candidate == root
                && (principal.starts_with(&format!("arn:aws:iam::{account}:"))
                    || principal.starts_with(&format!("arn:aws:sts::{account}:"))))
            || (kind == "AWS" && principal.starts_with(&format!("{candidate}/")))
    }))
}

pub(crate) fn evaluate(
    raw: &str,
    principal: &str,
    account: &str,
    action: &str,
    resource: &str,
) -> Decision {
    // ponytail: parse per request; cache by queue policy revision if profiling shows cost.
    let Ok(policy) = serde_json::from_str::<Value>(raw) else {
        return Decision::Deny;
    };
    let Some(statements) = policy.get("Statement") else {
        return Decision::Deny;
    };
    let entries = match statements {
        Value::Array(entries) if !entries.is_empty() => entries.iter().collect::<Vec<_>>(),
        Value::Object(_) => vec![statements],
        _ => return Decision::Deny,
    };
    let mut allowed = false;
    for statement in entries {
        // A policy accepted by control-plane validation may use more IAM constructs.
        // Reject them on the data plane until they have a tested evaluator.
        if statement.get("NotAction").is_some()
            || statement.get("NotResource").is_some()
            || statement.get("NotPrincipal").is_some()
            || statement.get("Condition").is_some()
        {
            return Decision::Deny;
        }
        let Some(effect) = statement.get("Effect").and_then(Value::as_str) else {
            return Decision::Deny;
        };
        let Some(actions) = values(statement.get("Action")) else {
            return Decision::Deny;
        };
        let Some(resources) = values(statement.get("Resource")) else {
            return Decision::Deny;
        };
        let Some(principal_matches) = principal_matches(statement, principal, account) else {
            return Decision::Deny;
        };
        if !principal_matches
            || !actions
                .into_iter()
                .any(|item| matches_pattern(item, action))
            || !resources
                .into_iter()
                .any(|item| matches_pattern(item, resource))
        {
            continue;
        }
        if effect == "Deny" {
            return Decision::Deny;
        }
        if effect != "Allow" {
            return Decision::Deny;
        }
        allowed = true;
    }
    if allowed {
        Decision::Allow
    } else {
        Decision::Unmatched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_requires_matching_principal_action_resource_and_deny_wins() {
        let raw = r#"{"Statement":[{"Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:000000000000:q"},{"Effect":"Deny","Principal":"*","Action":"sqs:DeleteMessage","Resource":"*"}]}"#;
        assert!(matches!(
            evaluate(
                raw,
                "s3.amazonaws.com",
                "000000000000",
                "sqs:SendMessage",
                "arn:aws:sqs:us-east-1:000000000000:q"
            ),
            Decision::Allow
        ));
        assert!(matches!(
            evaluate(
                raw,
                "lambda.amazonaws.com",
                "000000000000",
                "sqs:SendMessage",
                "arn:aws:sqs:us-east-1:000000000000:q"
            ),
            Decision::Unmatched
        ));
        assert!(matches!(
            evaluate(
                raw,
                "s3.amazonaws.com",
                "000000000000",
                "sqs:DeleteMessage",
                "arn:aws:sqs:us-east-1:000000000000:q"
            ),
            Decision::Deny
        ));
    }
}
