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

#[derive(Clone, Copy, Default)]
pub(crate) struct SourceContext<'a> {
    pub arn: Option<&'a str>,
    pub account: Option<&'a str>,
}

// ARN conditions are case sensitive and support IAM's '*' and '?' wildcards.
fn arn_like(pattern: &str, value: &str) -> bool {
    let pattern = pattern.splitn(6, ':').collect::<Vec<_>>();
    let value = value.splitn(6, ':').collect::<Vec<_>>();
    pattern.len() == 6
        && value.len() == 6
        && pattern
            .into_iter()
            .zip(value)
            .all(|(pattern, value)| component_like(pattern, value))
}

fn component_like(pattern: &str, value: &str) -> bool {
    let (pattern, value) = (pattern.as_bytes(), value.as_bytes());
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(last_star) = star {
            p = last_star + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|byte| *byte == b'*')
}

fn conditions_match(statement: &Value, source: SourceContext<'_>) -> Option<bool> {
    let Some(condition) = statement.get("Condition") else {
        return Some(true);
    };
    let operators = condition.as_object()?;
    if operators.is_empty() {
        return None;
    }
    let mut matches = true;
    for (operator, raw_conditions) in operators {
        let conditions = raw_conditions.as_object()?;
        if conditions.is_empty() {
            return None;
        }
        for (key, expected) in conditions {
            let candidates = values(Some(expected))?;
            let (actual, wildcard) = match (operator.as_str(), key.to_ascii_lowercase().as_str()) {
                ("ArnEquals" | "ArnLike", "aws:sourcearn") => (source.arn, true),
                ("StringEquals", "aws:sourceaccount") => (source.account, false),
                _ => return None,
            };
            matches &= actual.is_some_and(|actual| {
                candidates.into_iter().any(|candidate| {
                    if wildcard {
                        arn_like(candidate, actual)
                    } else {
                        candidate == actual
                    }
                })
            });
        }
    }
    Some(matches)
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
    source: SourceContext<'_>,
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
        let Some(conditions_match) = conditions_match(statement, source) else {
            return Decision::Deny;
        };
        if !conditions_match
            || !principal_matches
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
                "arn:aws:sqs:us-east-1:000000000000:q",
                SourceContext::default(),
            ),
            Decision::Allow
        ));
        assert!(matches!(
            evaluate(
                raw,
                "lambda.amazonaws.com",
                "000000000000",
                "sqs:SendMessage",
                "arn:aws:sqs:us-east-1:000000000000:q",
                SourceContext::default(),
            ),
            Decision::Unmatched
        ));
        assert!(matches!(
            evaluate(
                raw,
                "s3.amazonaws.com",
                "000000000000",
                "sqs:DeleteMessage",
                "arn:aws:sqs:us-east-1:000000000000:q",
                SourceContext::default(),
            ),
            Decision::Deny
        ));
    }
    #[test]
    fn source_conditions_match_case_sensitive_values_and_keep_deny_precedence() {
        assert!(!arn_like(
            "arn:aws:sns:*orders-created",
            "arn:aws:sns:us-east-1:000000000000:orders-created"
        ));
        assert!(arn_like(
            "arn:aws:sns:*:*:orders-*",
            "arn:aws:sns:us-east-1:000000000000:orders-created"
        ));
        let resource = "arn:aws:sqs:us-east-1:000000000000:q";
        let source = SourceContext {
            arn: Some("arn:aws:sns:us-east-1:000000000000:orders-created"),
            account: Some("000000000000"),
        };
        let evaluate_policy = |condition: Value, effect: &str, context| {
            let raw = serde_json::json!({"Statement":[
                {"Effect":"Allow", "Principal":{"Service":"sns.amazonaws.com"}, "Action":"sqs:SendMessage", "Resource":resource, "Condition":condition},
                {"Effect":effect, "Principal":"*", "Action":"sqs:SendMessage", "Resource":resource, "Condition":{"StringEquals":{"aws:SourceAccount":"000000000000"}}}
            ]}).to_string();
            evaluate(
                &raw,
                "sns.amazonaws.com",
                "000000000000",
                "sqs:SendMessage",
                resource,
                context,
            )
        };
        // Both ARN operators have the same AWS wildcard semantics; arrays are OR,
        // while separate keys/operators are AND. Missing context never grants.
        for operator in ["ArnEquals", "ArnLike"] {
            let condition = serde_json::json!({operator:{"AWS:SourceArn":["wrong", "arn:aws:sns:us-east-1:000000000000:orders-?reated"]}, "StringEquals":{"aws:SourceAccount":["wrong", "000000000000"]}});
            assert!(matches!(
                evaluate_policy(condition.clone(), "Deny", source),
                Decision::Deny
            ));
            let raw = serde_json::json!({"Statement":{"Effect":"Allow", "Principal":{"Service":"sns.amazonaws.com"}, "Action":"sqs:SendMessage", "Resource":resource, "Condition":condition}}).to_string();
            for (context, expected) in [
                (source, Decision::Allow),
                (SourceContext::default(), Decision::Unmatched),
                (
                    SourceContext {
                        arn: Some("arn:aws:sns:us-east-1:000000000000:Orders-created"),
                        ..source
                    },
                    Decision::Unmatched,
                ),
                (
                    SourceContext {
                        account: Some("111111111111"),
                        ..source
                    },
                    Decision::Unmatched,
                ),
            ] {
                assert!(
                    evaluate(
                        &raw,
                        "sns.amazonaws.com",
                        "000000000000",
                        "sqs:SendMessage",
                        resource,
                        context
                    ) == expected
                );
            }
            assert!(matches!(
                evaluate(
                    &raw,
                    "sns.amazonaws.com",
                    "000000000000",
                    "sqs:ReceiveMessage",
                    resource,
                    source
                ),
                Decision::Unmatched
            ));
        }
        for condition in [
            serde_json::json!({"Bool":{"aws:SecureTransport":"true"}}),
            serde_json::json!({"ArnLike":{"aws:SourceArn":42}}),
            serde_json::json!({}),
        ] {
            assert!(matches!(
                evaluate_policy(condition, "Allow", source),
                Decision::Deny
            ));
        }
    }
}
