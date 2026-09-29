//! JSONPath Choice-state evaluation: comparison operators, `And`/`Or`/`Not`, `Is*` checks,
//! `StringMatches`, and `*Path` variants. Selects the first matching `Next`, else `Default`.

use std::cmp::Ordering;

use serde_json::Value;

use crate::error::AslError;
use crate::path::get_path;

/// Evaluate a Choice state against its input, returning the chosen `Next` state name.
pub fn evaluate(state: &Value, input: &Value) -> Result<String, AslError> {
    let choices = state
        .get("Choices")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for choice in &choices {
        if rule_matches(choice, input) {
            if let Some(next) = choice.get("Next").and_then(Value::as_str) {
                return Ok(next.to_string());
            }
        }
    }
    state
        .get("Default")
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| {
            AslError::new(
                "States.NoChoiceMatched",
                "no Choice rule matched and no Default",
            )
        })
}

fn rule_matches(rule: &Value, input: &Value) -> bool {
    if let Some(and) = rule.get("And").and_then(Value::as_array) {
        return and.iter().all(|r| rule_matches(r, input));
    }
    if let Some(or) = rule.get("Or").and_then(Value::as_array) {
        return or.iter().any(|r| rule_matches(r, input));
    }
    if let Some(not) = rule.get("Not") {
        return !rule_matches(not, input);
    }
    comparison(rule, input)
}

fn comparison(rule: &Value, input: &Value) -> bool {
    let Some(var_path) = rule.get("Variable").and_then(Value::as_str) else {
        return false;
    };
    let var = get_path(input, var_path);
    let Some(obj) = rule.as_object() else {
        return false;
    };
    for (op, operand) in obj {
        if op == "Variable" || op == "Next" || op == "Comment" {
            continue;
        }
        return apply_operator(op, var.as_ref(), operand, input);
    }
    false
}

fn apply_operator(op: &str, var: Option<&Value>, operand: &Value, input: &Value) -> bool {
    // Existence / type checks.
    match op {
        "IsPresent" => return var.is_some() == operand.as_bool().unwrap_or(false),
        "IsNull" => return matches!(var, Some(Value::Null)) == operand.as_bool().unwrap_or(false),
        "IsString" => {
            return var.map(Value::is_string).unwrap_or(false) == operand.as_bool().unwrap_or(false)
        }
        "IsNumeric" => {
            return var.map(Value::is_number).unwrap_or(false) == operand.as_bool().unwrap_or(false)
        }
        "IsBoolean" => {
            return var.map(Value::is_boolean).unwrap_or(false)
                == operand.as_bool().unwrap_or(false)
        }
        "IsTimestamp" => {
            return var
                .and_then(Value::as_str)
                .map(is_timestamp)
                .unwrap_or(false)
                == operand.as_bool().unwrap_or(false)
        }
        _ => {}
    }
    // A `*Path` operator resolves the operand as a path against the input.
    let resolved;
    let (base_op, effective_operand) = if let Some(b) = op.strip_suffix("Path") {
        resolved = operand.as_str().and_then(|p| get_path(input, p));
        match &resolved {
            Some(v) => (b, v),
            None => return false,
        }
    } else {
        (op, operand)
    };
    let Some(var) = var else { return false };
    match base_op {
        "StringEquals" => var.as_str() == effective_operand.as_str(),
        "StringLessThan" => str_cmp(var, effective_operand) == Some(Ordering::Less),
        "StringGreaterThan" => str_cmp(var, effective_operand) == Some(Ordering::Greater),
        "StringLessThanEquals" => matches!(
            str_cmp(var, effective_operand),
            Some(Ordering::Less | Ordering::Equal)
        ),
        "StringGreaterThanEquals" => matches!(
            str_cmp(var, effective_operand),
            Some(Ordering::Greater | Ordering::Equal)
        ),
        "StringMatches" => match (var.as_str(), effective_operand.as_str()) {
            (Some(s), Some(p)) => glob(p, s),
            _ => false,
        },
        "NumericEquals" => num_cmp(var, effective_operand) == Some(Ordering::Equal),
        "NumericLessThan" => num_cmp(var, effective_operand) == Some(Ordering::Less),
        "NumericGreaterThan" => num_cmp(var, effective_operand) == Some(Ordering::Greater),
        "NumericLessThanEquals" => matches!(
            num_cmp(var, effective_operand),
            Some(Ordering::Less | Ordering::Equal)
        ),
        "NumericGreaterThanEquals" => matches!(
            num_cmp(var, effective_operand),
            Some(Ordering::Greater | Ordering::Equal)
        ),
        "BooleanEquals" => var.as_bool() == effective_operand.as_bool(),
        "TimestampEquals" => var.as_str() == effective_operand.as_str(),
        "TimestampLessThan" => str_cmp(var, effective_operand) == Some(Ordering::Less),
        "TimestampGreaterThan" => str_cmp(var, effective_operand) == Some(Ordering::Greater),
        "TimestampLessThanEquals" => matches!(
            str_cmp(var, effective_operand),
            Some(Ordering::Less | Ordering::Equal)
        ),
        "TimestampGreaterThanEquals" => matches!(
            str_cmp(var, effective_operand),
            Some(Ordering::Greater | Ordering::Equal)
        ),
        _ => false,
    }
}

fn str_cmp(a: &Value, b: &Value) -> Option<Ordering> {
    Some(a.as_str()?.cmp(b.as_str()?))
}

fn num_cmp(a: &Value, b: &Value) -> Option<Ordering> {
    a.as_f64()?.partial_cmp(&b.as_f64()?)
}

fn is_timestamp(s: &str) -> bool {
    // A reasonable ISO-8601 heuristic: contains a date and `T`.
    s.len() >= 10 && s.contains('T') && s.as_bytes()[4] == b'-'
}

/// Case-sensitive glob where `*` matches any sequence.
fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, None, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn choices(rules: Value, default: &str) -> Value {
        json!({ "Type": "Choice", "Choices": rules, "Default": default })
    }

    #[test]
    fn string_and_numeric_comparisons() {
        let state = choices(
            json!([
                { "Variable": "$.color", "StringEquals": "red", "Next": "Red" },
                { "Variable": "$.n", "NumericGreaterThan": 10, "Next": "Big" }
            ]),
            "Other",
        );
        assert_eq!(evaluate(&state, &json!({ "color": "red" })).unwrap(), "Red");
        assert_eq!(evaluate(&state, &json!({ "n": 20 })).unwrap(), "Big");
        assert_eq!(evaluate(&state, &json!({ "n": 5 })).unwrap(), "Other");
    }

    #[test]
    fn and_or_not_and_is_present() {
        let state = choices(
            json!([{
                "And": [
                    { "Variable": "$.a", "IsPresent": true },
                    { "Variable": "$.a", "NumericGreaterThanEquals": 1 }
                ],
                "Next": "Ok"
            }]),
            "No",
        );
        assert_eq!(evaluate(&state, &json!({ "a": 3 })).unwrap(), "Ok");
        assert_eq!(evaluate(&state, &json!({})).unwrap(), "No");
    }

    #[test]
    fn string_matches_glob_and_path() {
        let state = choices(
            json!([{ "Variable": "$.file", "StringMatches": "*.json", "Next": "J" }]),
            "D",
        );
        assert_eq!(evaluate(&state, &json!({ "file": "a.json" })).unwrap(), "J");
        assert_eq!(evaluate(&state, &json!({ "file": "a.txt" })).unwrap(), "D");

        let state = choices(
            json!([{ "Variable": "$.a", "NumericEqualsPath": "$.b", "Next": "Eq" }]),
            "Ne",
        );
        assert_eq!(evaluate(&state, &json!({ "a": 5, "b": 5 })).unwrap(), "Eq");
        assert_eq!(evaluate(&state, &json!({ "a": 5, "b": 6 })).unwrap(), "Ne");
    }

    #[test]
    fn no_match_no_default_errors() {
        let state = json!({ "Type": "Choice", "Choices": [{ "Variable": "$.x", "StringEquals": "y", "Next": "N" }] });
        assert!(evaluate(&state, &json!({ "x": "z" })).is_err());
    }
}
