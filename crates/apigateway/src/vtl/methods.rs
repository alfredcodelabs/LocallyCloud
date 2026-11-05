use super::{value_kind, VtlError, MAX_VTL_VALUE_BYTES};
use serde_json::{Number, Value};

pub(super) fn extend_pointer(pointer: &mut Option<String>, key: &str) {
    if let Some(pointer) = pointer {
        pointer.push('/');
        pointer.push_str(&key.replace('~', "~0").replace('/', "~1"));
    }
}

pub(super) fn apply_value_method(
    receiver: &mut Value,
    method: &str,
    arguments: &[Value],
) -> Result<Value, VtlError> {
    let expected = match method {
        "isEmpty" | "keySet" | "toLowerCase" | "size" | "length" => 0..=0,
        "get" | "startsWith" | "split" | "containsKey" | "remove" => 1..=1,
        "substring" => 1..=2,
        "replaceAll" => 2..=2,
        _ => {
            return Err(VtlError::Unsupported(format!(
                "method `{method}` on a value"
            )))
        }
    };
    if !expected.contains(&arguments.len()) {
        return Err(VtlError::Evaluation(format!(
            "invalid argument count for {method}"
        )));
    }
    for value in std::iter::once(&*receiver).chain(arguments) {
        if value
            .as_str()
            .is_some_and(|value| value.len() > MAX_VTL_VALUE_BYTES)
        {
            return Err(VtlError::Evaluation("method input exceeds 1 MiB".into()));
        }
    }
    let kind = value_kind(receiver);
    let unsupported = || VtlError::Evaluation(format!("{method} is not supported on {kind}"));
    match (method, &mut *receiver) {
        ("isEmpty", Value::String(value)) => Ok(Value::Bool(value.is_empty())),
        ("isEmpty", Value::Array(value)) => Ok(Value::Bool(value.is_empty())),
        ("isEmpty", Value::Object(value)) => Ok(Value::Bool(value.is_empty())),
        ("size", Value::Object(value)) => Ok(Value::Number(Number::from(value.len()))),
        ("size", Value::Array(value)) => Ok(Value::Number(Number::from(value.len()))),
        ("length", Value::String(value)) => {
            Ok(Value::Number(Number::from(value.encode_utf16().count())))
        }
        ("keySet", Value::Object(value)) => Ok(Value::Array(
            value.keys().cloned().map(Value::String).collect(),
        )),
        ("get", Value::Object(value)) => Ok(value
            .get(&string_argument(arguments, 0)?)
            .cloned()
            .unwrap_or_default()),
        ("get", Value::Array(value)) => value
            .get(index_argument(arguments, 0)?)
            .cloned()
            .ok_or_else(|| VtlError::Evaluation("list index out of bounds".into())),
        ("containsKey", Value::Object(value)) => Ok(Value::Bool(
            value.contains_key(&string_argument(arguments, 0)?),
        )),
        ("remove", Value::Object(value)) => Ok(value
            .remove(&string_argument(arguments, 0)?)
            .unwrap_or_default()),
        ("remove", Value::Array(value)) => {
            let index = index_argument(arguments, 0)?;
            if index >= value.len() {
                return Err(VtlError::Evaluation("list index out of bounds".into()));
            }
            Ok(value.remove(index))
        }
        ("toLowerCase", Value::String(value)) => {
            let mut output = String::new();
            for character in value.chars().flat_map(char::to_lowercase) {
                append_bounded(&mut output, &character.to_string())?;
            }
            Ok(Value::String(output))
        }
        ("startsWith", Value::String(value)) => Ok(Value::Bool(
            value.starts_with(&string_argument(arguments, 0)?),
        )),
        ("substring", Value::String(value)) => {
            let start = index_argument(arguments, 0)?;
            let end = if arguments.len() == 2 {
                index_argument(arguments, 1)?
            } else {
                value.encode_utf16().count()
            };
            let units = value.encode_utf16().collect::<Vec<_>>();
            let selected = units
                .get(start..end)
                .ok_or_else(|| VtlError::Evaluation("substring index out of bounds".into()))?;
            String::from_utf16(selected)
                .map(Value::String)
                .map_err(|_| {
                    VtlError::Evaluation("substring splits a UTF-16 surrogate pair".into())
                })
        }
        ("split", Value::String(value)) => {
            let regex = compile_regex(&string_argument(arguments, 0)?)?;
            if value.is_empty() {
                return Ok(Value::Array(vec![Value::String(String::new())]));
            }
            let mut values = Vec::new();
            let mut size = 0usize;
            for part in regex.split(value) {
                size = size.saturating_add(part.len()).saturating_add(4);
                if size > MAX_VTL_VALUE_BYTES {
                    return Err(VtlError::Evaluation("split output exceeds 1 MiB".into()));
                }
                values.push(part.to_owned());
            }
            if regex
                .find(value)
                .is_some_and(|matched| matched.start() == 0 && matched.end() == 0)
                && values.first().is_some_and(String::is_empty)
            {
                values.remove(0);
            }
            while values.last().is_some_and(String::is_empty) {
                values.pop();
            }
            Ok(Value::Array(
                values.into_iter().map(Value::String).collect(),
            ))
        }
        ("replaceAll", Value::String(value)) => {
            let regex = compile_regex(&string_argument(arguments, 0)?)?;
            let replacement = string_argument(arguments, 1)?;
            let mut output = String::new();
            let mut end = 0;
            for captures in regex.captures_iter(value) {
                let Some(matched) = captures.get(0) else {
                    continue;
                };
                append_bounded(&mut output, &value[end..matched.start()])?;
                expand_java_replacement(&mut output, &replacement, &captures)?;
                end = matched.end();
            }
            append_bounded(&mut output, &value[end..])?;
            Ok(Value::String(output))
        }
        _ => Err(unsupported()),
    }
}

fn string_argument(arguments: &[Value], index: usize) -> Result<String, VtlError> {
    match arguments.get(index) {
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(VtlError::Evaluation(
            "method requires a string argument".into(),
        )),
    }
}

fn index_argument(arguments: &[Value], index: usize) -> Result<usize, VtlError> {
    arguments
        .get(index)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| VtlError::Evaluation("method requires a nonnegative integer index".into()))
}

fn compile_regex(pattern: &str) -> Result<regex::Regex, VtlError> {
    regex::RegexBuilder::new(pattern)
        .size_limit(1024 * 1024)
        .nest_limit(64)
        .build()
        .map_err(|_| VtlError::Evaluation("invalid or unsupported regular expression".into()))
}

pub(super) fn append_bounded(output: &mut String, text: &str) -> Result<(), VtlError> {
    if output.len().saturating_add(text.len()) > MAX_VTL_VALUE_BYTES {
        return Err(VtlError::Evaluation("method output exceeds 1 MiB".into()));
    }
    output.push_str(text);
    Ok(())
}

fn expand_java_replacement(
    output: &mut String,
    replacement: &str,
    captures: &regex::Captures<'_>,
) -> Result<(), VtlError> {
    let mut characters = replacement.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' => {
                let escaped = characters
                    .next()
                    .ok_or_else(|| VtlError::Evaluation("invalid replacement escape".into()))?;
                append_bounded(output, &escaped.to_string())?;
            }
            '$' => {
                let first = characters
                    .next()
                    .and_then(|character| character.to_digit(10))
                    .ok_or_else(|| {
                        VtlError::Evaluation("replacement requires a capture group".into())
                    })?;
                let mut index = first as usize;
                if index >= captures.len() {
                    return Err(VtlError::Evaluation(
                        "unknown replacement capture group".into(),
                    ));
                }
                while let Some(digit) = characters
                    .peek()
                    .and_then(|character| character.to_digit(10))
                {
                    let next = index.saturating_mul(10).saturating_add(digit as usize);
                    if next >= captures.len() {
                        break;
                    }
                    characters.next();
                    index = next;
                }
                if let Some(value) = captures.get(index) {
                    append_bounded(output, value.as_str())?;
                }
            }
            other => append_bounded(output, &other.to_string())?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtl::{ContextBinding, InputBinding, UtilBinding, VtlContext, VtlEngine};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn call(mut receiver: Value, method: &str, arguments: &[Value]) -> Result<Value, VtlError> {
        apply_value_method(&mut receiver, method, arguments)
    }

    #[test]
    fn java_collection_and_string_methods_validate_types_and_bounds() {
        assert_eq!(
            call(json!({"x": 3}), "get", &[json!("x")]).unwrap(),
            json!(3)
        );
        assert_eq!(
            call(json!({"x": 3}), "containsKey", &[json!("x")]).unwrap(),
            json!(true)
        );
        assert_eq!(call(json!({"x": 3}), "keySet", &[]).unwrap(), json!(["x"]));
        assert_eq!(call(json!([]), "isEmpty", &[]).unwrap(), json!(true));
        assert_eq!(call(json!([1, 2]), "size", &[]).unwrap(), json!(2));
        assert_eq!(call(json!([1, 2]), "get", &[json!(1)]).unwrap(), json!(2));
        assert_eq!(
            call(json!("ÄUTH"), "toLowerCase", &[]).unwrap(),
            json!("äuth")
        );
        assert_eq!(
            call(json!("Bearer token"), "startsWith", &[json!("Bearer ")]).unwrap(),
            json!(true)
        );
        assert_eq!(call(json!("a😀b"), "length", &[]).unwrap(), json!(4));
        assert_eq!(
            call(json!("a😀b"), "substring", &[json!(1), json!(3)]).unwrap(),
            json!("😀")
        );
        assert!(call(json!("a😀b"), "substring", &[json!(2)]).is_err());
        assert!(call(json!("abc"), "substring", &[json!(3), json!(1)]).is_err());
        assert!(call(json!([]), "get", &[json!(0)]).is_err());
        assert!(call(json!([]), "get", &[json!(-1)]).is_err());
        assert!(call(json!("abc"), "size", &[]).is_err());
        assert!(call(json!("abc"), "length", &[json!(1)]).is_err());
    }

    #[test]
    fn java_regex_split_and_replacement_are_bounded() {
        assert_eq!(
            call(json!("a.b."), "split", &[json!(r"\.")]).unwrap(),
            json!(["a", "b"])
        );
        assert_eq!(
            call(json!("abc"), "split", &[json!("")]).unwrap(),
            json!(["a", "b", "c"])
        );
        assert_eq!(
            call(json!(""), "split", &[json!(",")]).unwrap(),
            json!([""])
        );
        assert_eq!(
            call(
                json!("a\r\nb"),
                "replaceAll",
                &[json!(r"[\r\n]"), json!("")]
            )
            .unwrap(),
            json!("ab")
        );
        assert_eq!(
            call(json!(r"a\'b"), "replaceAll", &[json!(r"\\'"), json!("'")]).unwrap(),
            json!("a'b")
        );
        assert_eq!(
            call(
                json!("ab"),
                "replaceAll",
                &[json!("(a)(b)"), json!("$2$1\\$")]
            )
            .unwrap(),
            json!("ba$")
        );
        assert!(call(json!("abc"), "replaceAll", &[json!("["), json!("")]).is_err());
        assert!(call(json!("abc"), "replaceAll", &[json!("a"), json!("$9")]).is_err());
        assert!(call(
            json!("a".repeat(2048)),
            "replaceAll",
            &[json!("a"), json!("b".repeat(2048))]
        )
        .is_err());
    }

    #[test]
    fn quiet_removal_mutates_root_and_nested_map_without_rendering() {
        let empty = BTreeMap::new();
        let context_values = BTreeMap::new();
        let context = VtlContext {
            input: InputBinding {
                body: "{}",
                querystring: &empty,
                path: &empty,
                header: &empty,
            },
            util: UtilBinding,
            context: ContextBinding {
                values: &context_values,
            },
            stage_variables: &empty,
        };
        let result = VtlEngine::new().evaluate(
            "#set($params = $input.params())$util.qr($params.remove('header'))$params.containsKey('header')|#set($data = {'nested': {'a/b': 1, 'kept': 2}})$util.qr($data.get('nested').remove('a/b'))$data.nested.containsKey('a/b')|$data.nested.get('kept')",
            &context,
        ).unwrap();
        assert_eq!(result.output, "false|false|2");
    }
}
