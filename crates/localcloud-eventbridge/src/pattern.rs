//! EventBridge event-pattern compiler and matcher.
//!
//! A pattern is a JSON object. A key maps to a match array (leaf), a nested object (descend
//! into the event), or `$or` (an array of alternative sub-patterns). Top-level keys are
//! AND-ed; a match array is OR-ed. Matching is a pure deterministic function of
//! `(pattern, event)`. Operators: exact, `prefix`/`suffix` (with nested `equals-ignore-case`),
//! `equals-ignore-case`, `wildcard`, `anything-but`, `exists`, `numeric`, `cidr`.

use std::net::IpAddr;

use serde_json::Value;

use crate::error::EventsError;

/// Validate (compile) an event pattern, returning it on success.
pub fn compile(pattern: &Value) -> Result<Value, EventsError> {
    validate_node(pattern)?;
    Ok(pattern.clone())
}

fn invalid(msg: &str) -> EventsError {
    EventsError::InvalidEventPattern(msg.to_string())
}

fn validate_node(node: &Value) -> Result<(), EventsError> {
    let obj = node
        .as_object()
        .ok_or_else(|| invalid("pattern must be a JSON object"))?;
    for (key, value) in obj {
        if key == "$or" {
            let alts = value
                .as_array()
                .ok_or_else(|| invalid("$or must be an array"))?;
            if alts.is_empty() {
                return Err(invalid("$or must not be empty"));
            }
            for alt in alts {
                validate_node(alt)?;
            }
            continue;
        }
        match value {
            Value::Array(rules) => {
                if rules.is_empty() {
                    return Err(invalid("match array must not be empty"));
                }
                for rule in rules {
                    validate_rule(rule)?;
                }
            }
            Value::Object(_) => validate_node(value)?,
            _ => {
                return Err(invalid(
                    "a pattern key must map to an array or a nested object",
                ))
            }
        }
    }
    Ok(())
}

fn validate_rule(rule: &Value) -> Result<(), EventsError> {
    match rule {
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => Ok(()),
        Value::Object(map) => {
            if map.len() != 1 {
                return Err(invalid("operator object must contain exactly one operator"));
            }
            let (op, arg) = map.iter().next().expect("length checked");
            match op.as_str() {
                "prefix" | "suffix" => validate_string_or_case(arg, op),
                "equals-ignore-case" | "cidr" => arg
                    .as_str()
                    .map(|_| ())
                    .ok_or_else(|| invalid(&format!("{op} must be a string"))),
                "wildcard" => {
                    let value = arg
                        .as_str()
                        .ok_or_else(|| invalid("wildcard must be a string"))?;
                    if value.contains("**") {
                        Err(invalid("consecutive wildcard characters are not allowed"))
                    } else {
                        Ok(())
                    }
                }
                "anything-but" => validate_anything_but(arg),
                "exists" => arg
                    .as_bool()
                    .map(|_| ())
                    .ok_or_else(|| invalid("exists must be boolean")),
                "numeric" => validate_numeric(arg),
                other => Err(invalid(&format!("unsupported operator {other}"))),
            }
        }
        Value::Array(_) => Err(invalid("nested arrays are not valid match rules")),
    }
}

fn validate_string_or_case(arg: &Value, op: &str) -> Result<(), EventsError> {
    if arg.is_string() {
        return Ok(());
    }
    let Some(map) = arg.as_object() else {
        return Err(invalid(&format!(
            "{op} must be a string or equals-ignore-case"
        )));
    };
    if map.len() == 1 && map.get("equals-ignore-case").is_some_and(Value::is_string) {
        Ok(())
    } else {
        Err(invalid(&format!("invalid {op} operator")))
    }
}

fn validate_anything_but(arg: &Value) -> Result<(), EventsError> {
    match arg {
        Value::String(_) | Value::Number(_) => Ok(()),
        Value::Array(values)
            if !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.is_string() || value.is_number()) =>
        {
            Ok(())
        }
        Value::Object(map) if map.len() == 1 => {
            let (op, value) = map.iter().next().expect("length checked");
            match op.as_str() {
                "prefix" | "suffix" => validate_string_or_case(value, op),
                "equals-ignore-case" if value.is_string() => Ok(()),
                _ => Err(invalid("invalid anything-but operator")),
            }
        }
        _ => Err(invalid("invalid anything-but value")),
    }
}

fn validate_numeric(arg: &Value) -> Result<(), EventsError> {
    let values = arg
        .as_array()
        .ok_or_else(|| invalid("numeric must be an array"))?;
    if values.is_empty() || values.len() % 2 != 0 {
        return Err(invalid("numeric requires operator/number pairs"));
    }
    for pair in values.as_chunks::<2>().0 {
        if !matches!(pair[0].as_str(), Some("=" | ">" | ">=" | "<" | "<=")) || !pair[1].is_number()
        {
            return Err(invalid("invalid numeric comparison"));
        }
    }
    Ok(())
}

/// Match an event against a compiled pattern.
pub fn matches(pattern: &Value, event: &Value) -> bool {
    matches_at(pattern, event, "")
}

fn matches_at(pattern: &Value, event: &Value, prefix: &str) -> bool {
    let Some(obj) = pattern.as_object() else {
        return false;
    };
    obj.iter().all(|(key, rule)| {
        if key == "$or" {
            return rule
                .as_array()
                .map(|alts| alts.iter().any(|p| matches_at(p, event, prefix)))
                .unwrap_or(false);
        }
        let path = if prefix.is_empty() {
            key.to_string()
        } else {
            format!("{prefix}.{key}")
        };
        match rule {
            Value::Array(rules) => {
                let values = find_path(event, &path);
                if values.is_empty() {
                    match_leaf(rules, None)
                } else {
                    values
                        .into_iter()
                        .any(|value| match_leaf(rules, Some(value)))
                }
            }
            Value::Object(_) => matches_at(rule, event, &path),
            _ => false,
        }
    })
}

// EventBridge joins nested keys with dots, so a dotted key and nested objects are equivalent.
fn find_path<'a>(event: &'a Value, path: &str) -> Vec<&'a Value> {
    fn visit<'a>(node: &'a Value, path: &str, out: &mut Vec<&'a Value>) {
        if let Some(items) = node.as_array() {
            for item in items {
                visit(item, path, out);
            }
            return;
        }
        let Some(object) = node.as_object() else {
            return;
        };
        if let Some(value) = object.get(path) {
            out.push(value);
        }
        for (index, ch) in path.char_indices() {
            if ch == '.' {
                if let Some(value) = object.get(&path[..index]) {
                    visit(value, &path[index + 1..], out);
                }
            }
        }
    }
    let mut values = Vec::new();
    visit(event, path, &mut values);
    values
}

/// Whether any rule matches the event value (which may itself be an array).
fn match_leaf(rules: &[Value], ev: Option<&Value>) -> bool {
    rules.iter().any(|rule| rule_matches(rule, ev))
}

fn rule_matches(rule: &Value, ev: Option<&Value>) -> bool {
    match rule {
        Value::Object(map) => operator_matches(map, ev),
        scalar => match ev {
            Some(Value::Array(items)) => items.iter().any(|it| scalar_eq(scalar, it)),
            Some(v) => scalar_eq(scalar, v),
            None => false,
        },
    }
}

fn scalar_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(left), Value::Number(right)) => left == right,
        _ => a == b,
    }
}

fn operator_matches(map: &serde_json::Map<String, Value>, ev: Option<&Value>) -> bool {
    let Some((op, arg)) = map.iter().next() else {
        return false;
    };
    match op.as_str() {
        "exists" => arg
            .as_bool()
            .map(|want| ev.is_some() == want)
            .unwrap_or(false),
        "prefix" => string_op(ev, |s| starts_with_arg(s, arg)),
        "suffix" => string_op(ev, |s| ends_with_arg(s, arg)),
        "equals-ignore-case" => string_op(ev, |s| {
            arg.as_str()
                .map(|a| a.eq_ignore_ascii_case(s))
                .unwrap_or(false)
        }),
        "wildcard" => string_op(ev, |s| {
            arg.as_str().map(|p| wildcard(p, s)).unwrap_or(false)
        }),
        "numeric" => match ev {
            Some(Value::Array(items)) => items.iter().any(|item| {
                numeric_matches(arg.as_array().map(Vec::as_slice).unwrap_or(&[]), Some(item))
            }),
            _ => numeric_matches(arg.as_array().map(Vec::as_slice).unwrap_or(&[]), ev),
        },
        "cidr" => string_op(ev, |s| {
            arg.as_str().map(|c| ip_in_cidr(s, c)).unwrap_or(false)
        }),
        "anything-but" => anything_but(arg, ev),
        _ => false,
    }
}

/// Apply a string predicate over the event value (or any element of an event array).
fn string_op(ev: Option<&Value>, pred: impl Fn(&str) -> bool) -> bool {
    match ev {
        Some(Value::String(s)) => pred(s),
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).any(&pred),
        _ => false,
    }
}

/// `prefix` argument is a string or a nested `{"equals-ignore-case": s}`.
fn starts_with_arg(s: &str, arg: &Value) -> bool {
    if let Some(p) = arg.as_str() {
        return s.starts_with(p);
    }
    if let Some(eic) = arg.get("equals-ignore-case").and_then(Value::as_str) {
        return s
            .to_ascii_lowercase()
            .starts_with(&eic.to_ascii_lowercase());
    }
    false
}

fn ends_with_arg(s: &str, arg: &Value) -> bool {
    if let Some(p) = arg.as_str() {
        return s.ends_with(p);
    }
    if let Some(eic) = arg.get("equals-ignore-case").and_then(Value::as_str) {
        return s.to_ascii_lowercase().ends_with(&eic.to_ascii_lowercase());
    }
    false
}

fn anything_but(arg: &Value, ev: Option<&Value>) -> bool {
    let Some(value) = ev else { return false };
    let excluded: Vec<&Value> = match arg {
        Value::Array(a) => a.iter().collect(),
        // Nested {"prefix": s}: matches when NOT prefixed.
        Value::Object(map) => {
            return match value {
                Value::Array(items) => items.iter().any(|item| !operator_matches(map, Some(item))),
                _ => !operator_matches(map, ev),
            };
        }
        other => vec![other],
    };
    match value {
        Value::Array(items) => items
            .iter()
            .any(|it| !excluded.iter().any(|e| scalar_eq(e, it))),
        v => !excluded.iter().any(|e| scalar_eq(e, v)),
    }
}

/// `["op", n, ...]` numeric rule, supporting `= > >= < <=` and bounded ranges.
fn numeric_matches(rule: &[Value], ev: Option<&Value>) -> bool {
    let Some(value) = ev.and_then(Value::as_f64) else {
        return false;
    };
    let mut i = 0;
    while i + 1 < rule.len() {
        let op = rule[i].as_str().unwrap_or("");
        let Some(bound) = rule[i + 1].as_f64() else {
            return false;
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

/// Case-sensitive wildcard match where unescaped `*` matches any sequence and `\*` is literal.
fn wildcard(pattern: &str, text: &str) -> bool {
    #[derive(Clone, Copy)]
    enum Token {
        Star,
        Literal(char),
    }
    let mut tokens = Vec::new();
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            tokens.push(Token::Literal(chars.next().unwrap_or('\\')));
        } else if ch == '*' {
            tokens.push(Token::Star);
        } else {
            tokens.push(Token::Literal(ch));
        }
    }
    let text: Vec<char> = text.chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, None, 0usize);
    while ti < text.len() {
        match tokens.get(pi).copied() {
            Some(Token::Star) => {
                star = Some(pi);
                mark = ti;
                pi += 1;
            }
            Some(Token::Literal(ch)) if ch == text[ti] => {
                pi += 1;
                ti += 1;
            }
            _ if star.is_some() => {
                pi = star.expect("checked") + 1;
                mark += 1;
                ti = mark;
            }
            _ => return false,
        }
    }
    while matches!(tokens.get(pi), Some(Token::Star)) {
        pi += 1;
    }
    pi == tokens.len()
}

fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return false;
    };
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(net) = network.parse::<IpAddr>() else {
        return false;
    };
    let Ok(bits) = prefix.parse::<u32>() else {
        return false;
    };
    match (addr, net) {
        (IpAddr::V4(addr), IpAddr::V4(net)) if bits <= 32 => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            (u32::from(addr) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(addr), IpAddr::V6(net)) if bits <= 128 => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            (u128::from(addr) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_and_nested_detail() {
        let p = json!({ "source": ["aws.ec2"], "detail": { "state": ["running"] } });
        let compiled = compile(&p).unwrap();
        assert!(matches(
            &compiled,
            &json!({ "source": "aws.ec2", "detail": { "state": "running" } })
        ));
        assert!(!matches(
            &compiled,
            &json!({ "source": "aws.ec2", "detail": { "state": "stopped" } })
        ));
        assert!(!matches(
            &compiled,
            &json!({ "source": "aws.s3", "detail": { "state": "running" } })
        ));
    }

    #[test]
    fn array_event_value_membership() {
        let p = compile(&json!({ "resources": ["arn:1"] })).unwrap();
        assert!(matches(&p, &json!({ "resources": ["arn:0", "arn:1"] })));
    }

    #[test]
    fn operators() {
        assert!(matches(
            &compile(&json!({"k":[{"prefix":"ab"}]})).unwrap(),
            &json!({"k":"abc"})
        ));
        assert!(matches(
            &compile(&json!({"k":[{"suffix":"bc"}]})).unwrap(),
            &json!({"k":"abc"})
        ));
        assert!(matches(
            &compile(&json!({"k":[{"equals-ignore-case":"ABC"}]})).unwrap(),
            &json!({"k":"abc"})
        ));
        assert!(matches(
            &compile(&json!({"k":[{"wildcard":"a*c"}]})).unwrap(),
            &json!({"k":"axxc"})
        ));
        assert!(matches(
            &compile(&json!({"k":[{"exists":true}]})).unwrap(),
            &json!({"k":"v"})
        ));
        assert!(matches(
            &compile(&json!({"k":[{"exists":false}]})).unwrap(),
            &json!({})
        ));
        assert!(matches(
            &compile(&json!({"k":[{"anything-but":"x"}]})).unwrap(),
            &json!({"k":"y"})
        ));
        assert!(matches(
            &compile(&json!({"n":[{"numeric":[">",5,"<=",10]}]})).unwrap(),
            &json!({"n":7})
        ));
        assert!(!matches(
            &compile(&json!({"n":[{"numeric":[">",5]}]})).unwrap(),
            &json!({"n":3})
        ));
        assert!(matches(
            &compile(&json!({"ip":[{"cidr":"10.0.0.0/24"}]})).unwrap(),
            &json!({"ip":"10.0.0.5"})
        ));
        assert!(matches(
            &compile(&json!({"n":[{"numeric":[">",5]}]})).unwrap(),
            &json!({"n":[1, 7]})
        ));
        assert!(matches(
            &compile(&json!({"k":[{"anything-but":{"prefix":"blocked"}}]})).unwrap(),
            &json!({"k":["blocked-value", "allowed"]})
        ));
        assert!(matches(
            &compile(&json!({"ip":[{"cidr":"2001:db8::/32"}]})).unwrap(),
            &json!({"ip":"2001:db8::1"})
        ));
    }

    #[test]
    fn exact_numbers_preserve_json_number_representation() {
        let pattern = compile(&json!({"detail":{"count":[300]}})).unwrap();
        assert!(matches(&pattern, &json!({"detail":{"count":300}})));
        assert!(!matches(&pattern, &json!({"detail":{"count":300.0}})));
    }

    #[test]
    fn dotted_and_nested_keys_match_either_event_shape() {
        for pattern in [
            json!({"detail":{"state.status":["running"]}}),
            json!({"detail":{"state":{"status":["running"]}}}),
        ] {
            let pattern = compile(&pattern).unwrap();
            assert!(matches(
                &pattern,
                &json!({"detail":{"state.status":"running"}})
            ));
            assert!(matches(
                &pattern,
                &json!({"detail":{"state":{"status":"running"}}})
            ));
            assert!(matches(
                &pattern,
                &json!({"detail":[{"state":{"status":"running"}}]})
            ));
            assert!(!matches(
                &pattern,
                &json!({"detail":{"state":{"status":"stopped"}}})
            ));
        }
    }

    #[test]
    fn or_composition() {
        let p = compile(&json!({ "$or": [ { "source": ["a"] }, { "source": ["b"] } ] })).unwrap();
        assert!(matches(&p, &json!({ "source": "a" })));
        assert!(matches(&p, &json!({ "source": "b" })));
        assert!(!matches(&p, &json!({ "source": "c" })));
    }

    #[test]
    fn compile_rejects_bad_operator() {
        assert!(compile(&json!({ "k": [{ "bogus": 1 }] })).is_err());
        assert!(compile(&json!({ "k": "not-array" })).is_err());
        assert!(compile(&json!({ "k": [] })).is_err());
    }
}
