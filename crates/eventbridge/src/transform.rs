//! Target input transformation: `None`, `Input` (constant), `InputPath`, and
//! `InputTransformer` (`InputPathsMap` + `<variable>` template substitution).

use std::collections::BTreeMap;

use serde_json::Value;

/// How a target's input is shaped from the event.
#[derive(Debug, Clone)]
pub enum InputMode {
    /// Deliver the full event.
    None,
    /// Deliver a constant string.
    Constant(String),
    /// Deliver the value at a JSONPath (unresolved → JSON `null`).
    Path(String),
    /// Extract `paths` and substitute `<variable>` references in `template`.
    Transformer {
        paths: BTreeMap<String, String>,
        template: String,
    },
}

/// Predefined values for `<aws.events.*>` template variables.
pub struct Context<'a> {
    pub rule_arn: &'a str,
    pub rule_name: &'a str,
    pub event_json: &'a str,
    pub ingestion_time: &'a str,
}

/// Apply the input mode to an event, returning the string delivered to the target.
pub fn apply(mode: &InputMode, event: &Value, ctx: &Context<'_>) -> String {
    match mode {
        InputMode::None => event.to_string(),
        InputMode::Constant(s) => s.clone(),
        InputMode::Path(path) => extract(event, path).to_string(),
        InputMode::Transformer { paths, template } => {
            let mut values = BTreeMap::new();
            for (var, path) in paths {
                let value = extract(event, path);
                if !value.is_null() {
                    values.insert(var.as_str(), value);
                }
            }
            values.insert("aws.events.rule-arn", Value::String(ctx.rule_arn.into()));
            values.insert("aws.events.rule-name", Value::String(ctx.rule_name.into()));
            values.insert(
                "aws.events.event.json",
                serde_json::from_str(ctx.event_json).unwrap_or(Value::Null),
            );
            let mut event_without_detail = event.clone();
            if let Some(object) = event_without_detail.as_object_mut() {
                object.remove("detail");
            }
            values.insert("aws.events.event", event_without_detail);
            values.insert(
                "aws.events.event.ingestion-time",
                Value::String(ctx.ingestion_time.into()),
            );
            substitute_template(template, &values)
        }
    }
}

fn substitute_template(template: &str, values: &BTreeMap<&str, Value>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut offset = 0;
    let mut quoted = false;
    let mut escaped = false;
    while offset < template.len() {
        let remaining = &template[offset..];
        if remaining.starts_with('<') {
            if let Some(end) = remaining.find('>') {
                let name = &remaining[1..end];
                if let Some(value) = values.get(name) {
                    let content = if quoted {
                        match value {
                            Value::String(s) => s.clone(),
                            other => other.to_string().replace('"', ""),
                        }
                    } else {
                        value.to_string()
                    };
                    if quoted {
                        let encoded =
                            serde_json::to_string(&content).expect("string serialization");
                        out.push_str(&encoded[1..encoded.len() - 1]);
                    } else {
                        out.push_str(&content);
                    }
                }
                offset += end + 1;
                continue;
            }
        }
        let ch = remaining.chars().next().expect("remaining input");
        out.push(ch);
        offset += ch.len_utf8();
        if escaped {
            escaped = false;
        } else if ch == '\\' && quoted {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        }
    }
    out
}

/// Minimal JSONPath: `$`, `$.a.b`, `$.a[0]`. Unresolved paths yield `null`.
pub fn extract(event: &Value, path: &str) -> Value {
    let trimmed = path.strip_prefix('$').unwrap_or(path);
    let mut current = event;
    for segment in segments(trimmed) {
        let next = match segment {
            Segment::Key(k) => current.get(&k),
            Segment::Index(i) => current.get(i),
        };
        match next {
            Some(v) => current = v,
            None => return Value::Null,
        }
    }
    current.clone()
}

enum Segment {
    Key(String),
    Index(usize),
}

fn segments(path: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut chars = path.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            '.' => {
                chars.next();
                let mut key = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '.' || c == '[' {
                        break;
                    }
                    key.push(c);
                    chars.next();
                }
                if !key.is_empty() {
                    out.push(Segment::Key(key));
                }
            }
            '[' => {
                chars.next();
                let mut idx = String::new();
                while let Some(&c) = chars.peek() {
                    if c == ']' {
                        break;
                    }
                    idx.push(c);
                    chars.next();
                }
                chars.next(); // consume ']'
                let trimmed = idx.trim_matches(['\'', '"']);
                if let Ok(i) = trimmed.parse::<usize>() {
                    out.push(Segment::Index(i));
                } else if !trimmed.is_empty() {
                    out.push(Segment::Key(trimmed.to_string()));
                }
            }
            _ => {
                chars.next();
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> Context<'static> {
        Context {
            rule_arn: "arn:rule",
            rule_name: "r",
            event_json: "{}",
            ingestion_time: "t",
        }
    }

    #[test]
    fn extract_paths() {
        let ev = json!({ "detail": { "state": "ok", "items": ["a", "b"] } });
        assert_eq!(extract(&ev, "$.detail.state"), json!("ok"));
        assert_eq!(extract(&ev, "$.detail.items[1]"), json!("b"));
        assert_eq!(extract(&ev, "$"), ev);
        assert_eq!(extract(&ev, "$.missing"), Value::Null);
    }

    #[test]
    fn none_and_constant_and_path() {
        let ev = json!({ "detail": { "x": 1 } });
        assert_eq!(apply(&InputMode::None, &ev, &ctx()), ev.to_string());
        assert_eq!(
            apply(&InputMode::Constant("\"hi\"".into()), &ev, &ctx()),
            "\"hi\""
        );
        assert_eq!(
            apply(&InputMode::Path("$.detail".into()), &ev, &ctx()),
            json!({"x":1}).to_string()
        );
    }

    #[test]
    fn transformer_string_quotes_follow_template_context() {
        let ev = json!({"detail":{"message":"he said \"hi\" \\ ready"}});
        let paths = BTreeMap::from([("message".to_string(), "$.detail.message".to_string())]);
        let mode = InputMode::Transformer {
            paths,
            template: r#"{"quoted":"<message>","bare":<message>,"text":"prefix <message> suffix"}"#
                .into(),
        };
        let out = apply(&mode, &ev, &ctx());
        let parsed: Value = serde_json::from_str(&out).expect("valid JSON after substitution");
        assert_eq!(parsed["quoted"], ev["detail"]["message"]);
        assert_eq!(parsed["bare"], ev["detail"]["message"]);
        assert_eq!(
            parsed["text"],
            format!(
                "prefix {} suffix",
                ev["detail"]["message"].as_str().unwrap()
            )
        );
    }

    #[test]
    fn transformer_preserves_object_and_array_values() {
        let ev = json!({"detail":{"object":{"x":"a"},"array":["a",2]}});
        let paths = BTreeMap::from([
            ("object".to_string(), "$.detail.object".to_string()),
            ("array".to_string(), "$.detail.array".to_string()),
        ]);
        let mode = InputMode::Transformer {
            paths,
            template: r#"{"object":<object>,"array":<array>,"summary":"object <object>"}"#.into(),
        };
        let out = apply(&mode, &ev, &ctx());
        let parsed: Value = serde_json::from_str(&out).expect("valid JSON after substitution");
        assert_eq!(parsed["object"], ev["detail"]["object"]);
        assert_eq!(parsed["array"], ev["detail"]["array"]);
        assert_eq!(parsed["summary"], "object {x:a}");
    }

    #[test]
    fn transformer_missing_path_keeps_empty_substitution() {
        let ev = json!({"detail":{}});
        let paths = BTreeMap::from([("missing".to_string(), "$.detail.absent".to_string())]);
        let mode = InputMode::Transformer {
            paths,
            template: r#"{"value":"<missing>"}"#.into(),
        };
        assert_eq!(apply(&mode, &ev, &ctx()), r#"{"value":""}"#);
    }

    #[test]
    fn reserved_event_excludes_detail() {
        let event = json!({"id":"e1","detail":{"secret":"value"}});
        let mode = InputMode::Transformer {
            paths: BTreeMap::new(),
            template: r#"{"envelope":<aws.events.event>,"full":<aws.events.event.json>}"#.into(),
        };
        let context = Context {
            event_json: r#"{"id":"e1","detail":{"secret":"value"}}"#,
            ..ctx()
        };
        let output: Value = serde_json::from_str(&apply(&mode, &event, &context)).unwrap();
        assert_eq!(output["envelope"], json!({"id":"e1"}));
        assert_eq!(output["full"], event);
    }

    #[test]
    fn transformer_substitutes_user_and_predefined_vars() {
        let ev = json!({ "detail": { "state": "running" } });
        let mut paths = BTreeMap::new();
        paths.insert("st".to_string(), "$.detail.state".to_string());
        let mode = InputMode::Transformer {
            paths,
            template: "{\"status\":\"<st>\",\"rule\":\"<aws.events.rule-name>\"}".into(),
        };
        let out = apply(&mode, &ev, &ctx());
        assert_eq!(out, "{\"status\":\"running\",\"rule\":\"r\"}");
    }
}
