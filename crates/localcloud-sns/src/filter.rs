//! SNS subscription filter-policy parsing and evaluation.
//!
//! A policy is a JSON object mapping keys to arrays of match rules. Keys are AND-ed; the
//! rule array for a key is OR-ed. Scope `MessageAttributes` matches the message attributes;
//! `MessageBody` matches the parsed JSON body (fail-closed on non-JSON). Supported operators:
//! exact string/number, `prefix`, `anything-but`, `exists`, and `numeric` comparisons/ranges.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::SnsError;
use crate::model::{AttributeValue, MessageAttribute};

/// Validate a filter policy: must be a JSON object whose values are arrays.
pub fn validate(policy: &str) -> Result<Value, SnsError> {
    let parsed: Value = serde_json::from_str(policy)
        .map_err(|_| SnsError::InvalidParameter("FilterPolicy is not valid JSON".into()))?;
    if !parsed.is_object() {
        return Err(SnsError::InvalidParameter(
            "FilterPolicy must be a JSON object".into(),
        ));
    }
    validate_node(&parsed)?;
    Ok(parsed)
}

fn validate_node(node: &Value) -> Result<(), SnsError> {
    let object = node.as_object().ok_or_else(|| {
        SnsError::InvalidParameter("FilterPolicy nested values must be objects".into())
    })?;
    if object.is_empty() {
        return Err(SnsError::InvalidParameter(
            "FilterPolicy must not be empty".into(),
        ));
    }
    for rules in object.values() {
        if let Some(nested) = rules.as_object() {
            if nested.is_empty() {
                return Err(SnsError::InvalidParameter(
                    "FilterPolicy nested objects must not be empty".into(),
                ));
            }
            validate_node(rules)?;
            continue;
        }
        let array = rules.as_array().ok_or_else(|| {
            SnsError::InvalidParameter("FilterPolicy values must be rule arrays".into())
        })?;
        if array.is_empty() || array.iter().any(|rule| !valid_rule(rule)) {
            return Err(SnsError::InvalidParameter(
                "FilterPolicy contains an invalid rule".into(),
            ));
        }
    }
    Ok(())
}

fn valid_rule(rule: &Value) -> bool {
    match rule {
        Value::String(_) | Value::Number(_) => true,
        Value::Object(map) if map.len() == 1 => {
            let Some((name, value)) = map.iter().next() else {
                return false;
            };
            match name.as_str() {
                "prefix" => value.is_string(),
                "exists" => value.is_boolean(),
                "anything-but" => match value {
                    Value::String(_) | Value::Number(_) => true,
                    Value::Array(values) => {
                        !values.is_empty()
                            && values
                                .iter()
                                .all(|v| matches!(v, Value::String(_) | Value::Number(_)))
                    }
                    _ => false,
                },
                "numeric" => value.as_array().is_some_and(|parts| {
                    !parts.is_empty()
                        && parts.len() % 2 == 0
                        && parts.as_chunks::<2>().0.iter().all(|pair| {
                            matches!(
                                pair[0].as_str(),
                                Some("=") | Some(">") | Some(">=") | Some("<") | Some("<=")
                            ) && pair[1].is_number()
                        })
                }),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Evaluate a parsed policy against message attributes (MessageAttributes scope).
pub fn matches_attributes(policy: &Value, attrs: &BTreeMap<String, MessageAttribute>) -> bool {
    let Some(obj) = policy.as_object() else {
        return true;
    };
    obj.iter().all(|(key, rules)| {
        let candidate = attrs.get(key).map(attr_to_value);
        rule_array_matches(rules, candidate.as_ref())
    })
}

/// Evaluate a parsed policy against the message body (MessageBody scope); fail-closed when
/// the body is not a JSON object.
pub fn matches_body(policy: &Value, body: &str) -> bool {
    let Ok(parsed) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    matches_node(policy, &parsed)
}

fn matches_node(policy: &Value, node: &Value) -> bool {
    let Some(obj) = policy.as_object() else {
        return true;
    };
    obj.iter().all(|(key, rules)| {
        let child = node.get(key);
        match rules {
            // Nested object policy → descend into the body node.
            Value::Object(_) => child.map(|c| matches_node(rules, c)).unwrap_or(false),
            // Rule array → match the body value (or each element of a body array).
            Value::Array(_) => match child {
                Some(Value::Array(items)) => {
                    items.iter().any(|it| rule_array_matches(rules, Some(it)))
                }
                other => rule_array_matches(rules, other),
            },
            _ => false,
        }
    })
}

/// A candidate value reduced to a string and optional number for matching.
fn attr_to_value(attr: &MessageAttribute) -> Value {
    match &attr.value {
        AttributeValue::String(s) => {
            if attr.data_type == "Number" {
                s.parse::<f64>()
                    .ok()
                    .map(json_num)
                    .unwrap_or(Value::String(s.clone()))
            } else {
                Value::String(s.clone())
            }
        }
        AttributeValue::Binary(_) => Value::Null,
    }
}

fn json_num(n: f64) -> Value {
    serde_json::Number::from_f64(n)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

/// Whether any rule in the array matches the candidate (OR within the array).
fn rule_array_matches(rules: &Value, candidate: Option<&Value>) -> bool {
    let Some(arr) = rules.as_array() else {
        return false;
    };
    arr.iter().any(|rule| rule_matches(rule, candidate))
}

fn rule_matches(rule: &Value, candidate: Option<&Value>) -> bool {
    match rule {
        // Exact string / number match (requires a present candidate).
        Value::String(s) => candidate.and_then(Value::as_str) == Some(s.as_str()),
        Value::Number(n) => candidate
            .and_then(Value::as_f64)
            .zip(n.as_f64())
            .map(|(a, b)| a == b)
            .unwrap_or(false),
        Value::Object(map) => operator_matches(map, candidate),
        _ => false,
    }
}

fn operator_matches(map: &serde_json::Map<String, Value>, candidate: Option<&Value>) -> bool {
    if let Some(prefix) = map.get("prefix").and_then(Value::as_str) {
        return candidate
            .and_then(Value::as_str)
            .map(|s| s.starts_with(prefix))
            .unwrap_or(false);
    }
    if let Some(exists) = map.get("exists").and_then(Value::as_bool) {
        return candidate.is_some() == exists;
    }
    if let Some(anything_but) = map.get("anything-but") {
        // Matches when present and not equal to any listed value.
        let Some(c) = candidate else { return false };
        let excluded: Vec<&Value> = match anything_but {
            Value::Array(a) => a.iter().collect(),
            other => vec![other],
        };
        return !excluded.iter().any(|e| values_equal(e, c));
    }
    if let Some(numeric) = map.get("numeric").and_then(Value::as_array) {
        return numeric_matches(numeric, candidate);
    }
    false
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) => x == y,
        _ => a
            .as_f64()
            .zip(b.as_f64())
            .map(|(x, y)| x == y)
            .unwrap_or(false),
    }
}

/// Evaluate a `numeric` rule: `["op", n]` or a bounded range `[">", a, "<=", b]`.
fn numeric_matches(rule: &[Value], candidate: Option<&Value>) -> bool {
    let Some(value) = candidate.and_then(Value::as_f64) else {
        return false;
    };
    let mut i = 0;
    while i + 1 < rule.len() {
        let op = rule[i].as_str().unwrap_or("");
        let bound = match rule[i + 1].as_f64() {
            Some(b) => b,
            None => return false,
        };
        let ok = match op {
            "=" => value == bound,
            ">" => value > bound,
            ">=" => value >= bound,
            "<" => value < bound,
            "<=" => value <= bound,
            _ => return false,
        };
        if !ok {
            return false;
        }
        i += 2;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str, &str)]) -> BTreeMap<String, MessageAttribute> {
        pairs
            .iter()
            .map(|(k, dt, v)| {
                (
                    k.to_string(),
                    MessageAttribute {
                        data_type: dt.to_string(),
                        value: AttributeValue::String(v.to_string()),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn exact_and_or() {
        let policy = validate(r#"{"color":["red","blue"]}"#).unwrap();
        assert!(matches_attributes(
            &policy,
            &attrs(&[("color", "String", "red")])
        ));
        assert!(!matches_attributes(
            &policy,
            &attrs(&[("color", "String", "green")])
        ));
    }

    #[test]
    fn and_across_keys() {
        let policy = validate(r#"{"color":["red"],"size":["L"]}"#).unwrap();
        assert!(matches_attributes(
            &policy,
            &attrs(&[("color", "String", "red"), ("size", "String", "L")])
        ));
        assert!(!matches_attributes(
            &policy,
            &attrs(&[("color", "String", "red")])
        ));
    }

    #[test]
    fn prefix_exists_anything_but_numeric() {
        let p = validate(r#"{"k":[{"prefix":"ab"}]}"#).unwrap();
        assert!(matches_attributes(&p, &attrs(&[("k", "String", "abc")])));
        let p = validate(r#"{"k":[{"exists":false}]}"#).unwrap();
        assert!(matches_attributes(&p, &attrs(&[])));
        let p = validate(r#"{"k":[{"anything-but":"x"}]}"#).unwrap();
        assert!(matches_attributes(&p, &attrs(&[("k", "String", "y")])));
        let p = validate(r#"{"n":[{"numeric":[">",5]}]}"#).unwrap();
        assert!(matches_attributes(&p, &attrs(&[("n", "Number", "10")])));
        assert!(!matches_attributes(&p, &attrs(&[("n", "Number", "3")])));
    }

    #[test]
    fn body_scope_and_nesting() {
        let p = validate(r#"{"detail":{"state":["ok"]}}"#).unwrap();
        assert!(matches_body(&p, r#"{"detail":{"state":"ok"}}"#));
        assert!(!matches_body(&p, r#"{"detail":{"state":"bad"}}"#));
        assert!(!matches_body(&p, "not json"));
    }
}
