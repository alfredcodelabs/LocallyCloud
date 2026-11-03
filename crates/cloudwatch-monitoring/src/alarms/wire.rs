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
                "Metrics",
                "Tags",
                "TagKeys",
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
        "TagKeys",
    ] {
        let values = query.list(&format!("{key}.member"));
        if !values.is_empty() {
            body.insert(key.into(), json!(values));
        }
    }
    let mut tags = Vec::new();
    for index in 1.. {
        let Some(key) = query.get(&format!("Tags.member.{index}.Key")) else {
            break;
        };
        let value = query
            .params
            .get(&format!("Tags.member.{index}.Value"))
            .ok_or_else(|| invalid("Tag Value is required"))?;
        tags.push(json!({"Key":key,"Value":value}));
    }
    if !tags.is_empty() {
        body.insert("Tags".into(), json!(tags));
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
    if query.has_prefix("Metrics.member.") {
        let mapped = QueryRequest {
            params: query
                .params
                .iter()
                .filter_map(|(key, value)| {
                    key.strip_prefix("Metrics.member.")
                        .map(|suffix| (format!("MetricDataQueries.member.{suffix}"), value.clone()))
                })
                .collect(),
        };
        let parsed = crate::metric_data::query_body(&mapped)?;
        let metrics = parsed
            .get("MetricDataQueries")
            .cloned()
            .ok_or_else(|| invalid("Invalid Metrics queries"))?;
        // Reject malformed/unknown flattened fields instead of silently discarding them.
        for key in mapped.params.keys() {
            let suffix = key
                .strip_prefix("MetricDataQueries.member.")
                .unwrap_or_default();
            let (_, field) = suffix
                .split_once('.')
                .ok_or_else(|| invalid("Invalid Metrics member"))?;
            let known = matches!(
                field,
                "Id" | "Label"
                    | "Expression"
                    | "ReturnData"
                    | "AccountId"
                    | "MetricStat.Period"
                    | "MetricStat.Stat"
                    | "MetricStat.Unit"
                    | "MetricStat.Metric.Namespace"
                    | "MetricStat.Metric.MetricName"
            ) || field
                .strip_prefix("MetricStat.Metric.Dimensions.member.")
                .is_some_and(|dimension| {
                    dimension.split_once('.').is_some_and(|(index, field)| {
                        index.parse::<usize>().is_ok_and(|n| n > 0 && n <= 30)
                            && matches!(field, "Name" | "Value")
                    })
                });
            if !known {
                return Err(invalid("Unsupported Metrics query field"));
            }
            let index = suffix
                .split('.')
                .next()
                .and_then(|s| s.parse::<usize>().ok())
                .ok_or_else(|| invalid("Invalid Metrics index"))?;
            if index == 0
                || index > metrics.as_array().map_or(0, Vec::len)
                || index > 20
                || !suffix.starts_with(&format!("{index}."))
            {
                return Err(invalid("Metrics must use contiguous indices 1..20"));
            }
            if let Some(dimension) = field.strip_prefix("MetricStat.Metric.Dimensions.member.") {
                let (dimension_index, _) = dimension
                    .split_once('.')
                    .ok_or_else(|| invalid("Invalid metric dimension"))?;
                let dimension_index = dimension_index
                    .parse::<usize>()
                    .map_err(|_| invalid("Invalid metric dimension index"))?;
                let count = metrics
                    .get(index - 1)
                    .and_then(|query| query.get("MetricStat"))
                    .and_then(|stat| stat.get("Metric"))
                    .and_then(|metric| metric.get("Dimensions"))
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                if dimension_index == 0
                    || dimension_index > count
                    || !dimension.starts_with(&format!("{dimension_index}."))
                {
                    return Err(invalid(
                        "Metric dimensions must use contiguous indices 1..30",
                    ));
                }
            }
        }
        body.insert("Metrics".into(), metrics);
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
