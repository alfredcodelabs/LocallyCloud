use super::*;

pub(crate) fn query_json(query: &QueryRequest) -> Result<Value, MonitoringError> {
    let mut body = serde_json::Map::new();
    for (key, value) in &query.params {
        if matches!(key.as_str(), "Action" | "Version") {
            continue;
        }
        if key.contains(".member.") {
            if [
                "Dimensions",
                "AlarmNames",
                "AlarmTypes",
                "AlarmActions",
                "OKActions",
                "InsufficientDataActions",
            ]
            .iter()
            .any(|prefix| key.starts_with(&format!("{prefix}.member.")))
            {
                continue;
            }
            return Err(invalid("Unsupported alarm list property"));
        }
        let value = match key.as_str() {
            "Period" | "EvaluationPeriods" | "DatapointsToAlarm" | "MaxRecords" => {
                json!(parse_u64(value, key)?)
            }
            "Threshold" => json!(parse_f64(value, key)?),
            "ActionsEnabled" => match value.as_str() {
                "true" => json!(true),
                "false" => json!(false),
                _ => return Err(invalid("Invalid boolean")),
            },
            _ => json!(value),
        };
        body.insert(key.clone(), value);
    }
    for key in [
        "AlarmNames",
        "AlarmTypes",
        "AlarmActions",
        "OKActions",
        "InsufficientDataActions",
    ] {
        let values = query.list(&format!("{key}.member"));
        if !values.is_empty() {
            body.insert(key.into(), json!(values));
        }
    }
    let dimensions = parse_dimensions(query, "Dimensions.member")?;
    if !dimensions.is_empty() {
        body.insert(
            "Dimensions".into(),
            json!(dimensions
                .into_iter()
                .map(|(name, value)| json!({"Name":name,"Value":value}))
                .collect::<Vec<_>>()),
        );
    }
    Ok(body.into())
}
pub(crate) fn query_xml(value: &Value) -> Result<String, MonitoringError> {
    fn element(key: &str, value: &Value) -> Result<String, MonitoringError> {
        let body = match value {
            Value::Object(m) => {
                let mut result = String::new();
                for (k, v) in m {
                    result.push_str(&element(k, v)?);
                }
                result
            }
            Value::Array(a) => {
                let mut result = String::new();
                for v in a {
                    result.push_str(&element("member", v)?);
                }
                result
            }
            Value::Number(n) if key.ends_with("Timestamp") => {
                format_timestamp((n.as_f64().unwrap_or(0.0) * 1000.0) as i64)?
            }
            Value::String(s) => xml_escape(s),
            Value::Null => return Ok(String::new()),
            v => xml_escape(&v.to_string()),
        };
        Ok(format!("<{key}>{body}</{key}>"))
    }
    let mut result = String::new();
    if let Some(m) = value.as_object() {
        for (k, v) in m {
            result.push_str(&element(k, v)?);
        }
    }
    Ok(result)
}
