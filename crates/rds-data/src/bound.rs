use std::collections::HashMap;

use futures_util::TryStreamExt;
use serde_json::{json, Value};
use tokio_postgres::types::{ToSql, Type};
use tokio_postgres::Client;

use crate::config::RdsDataLimits;
use crate::error::RdsDataError;
use crate::model::{Field, SqlParameter};

/// Rewrites Data API :name placeholders only outside quoted SQL text.
fn rewrite(sql: &str, parameters: &[SqlParameter]) -> Result<(String, Vec<usize>), RdsDataError> {
    if sql.contains("--") || sql.contains("/*") || sql.contains("*/") || sql.contains("$$") {
        return Err(RdsDataError::Unsupported(
            "SQL comments and dollar quotes are unsupported with named parameters",
        ));
    }
    let mut names = HashMap::new();
    for (index, parameter) in parameters.iter().enumerate() {
        if parameter.name.is_empty()
            || !parameter
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || names.insert(parameter.name.as_str(), index).is_some()
        {
            return Err(RdsDataError::BadRequest(
                "SQL parameter name is invalid or duplicated",
            ));
        }
    }
    let bytes = sql.as_bytes();
    let mut rewritten = String::with_capacity(sql.len());
    let mut order = Vec::new();
    let mut indexes = HashMap::<&str, usize>::new();
    let mut i = 0;
    let mut quoted = None;
    while i < bytes.len() {
        if bytes[i] >= 128 {
            let ch = sql[i..].chars().next().expect("valid UTF-8");
            rewritten.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let ch = bytes[i] as char;
        if let Some(quote) = quoted {
            rewritten.push(ch);
            i += 1;
            if ch == quote {
                if i < bytes.len() && bytes[i] as char == quote {
                    rewritten.push(quote);
                    i += 1;
                } else {
                    quoted = None;
                }
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quoted = Some(ch);
            rewritten.push(ch);
            i += 1;
            continue;
        }
        if ch == '$' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            return Err(RdsDataError::BadRequest(
                "positional SQL parameters are unsupported",
            ));
        }
        if ch == ':'
            && bytes.get(i + 1) != Some(&b':')
            && (i == 0 || bytes[i - 1] != b':')
            && bytes
                .get(i + 1)
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            let name = &sql[start..end];
            let source = *names
                .get(name)
                .ok_or(RdsDataError::BadRequest("SQL parameter is missing"))?;
            let position = *indexes.entry(name).or_insert_with(|| {
                order.push(source);
                order.len()
            });
            rewritten.push('$');
            rewritten.push_str(&position.to_string());
            i = end;
            continue;
        }
        rewritten.push(ch);
        i += 1;
    }
    if quoted.is_some() || order.len() != parameters.len() {
        return Err(RdsDataError::BadRequest(
            "SQL parameters are unused or SQL quotes are incomplete",
        ));
    }
    Ok((rewritten, order))
}

fn value(field: &Field, expected: &Type) -> Result<Box<dyn ToSql + Sync + Send>, RdsDataError> {
    let mut count = 0;
    count += usize::from(field.is_null == Some(true));
    count += usize::from(field.boolean_value.is_some());
    count += usize::from(field.long_value.is_some());
    count += usize::from(field.double_value.is_some());
    count += usize::from(field.string_value.is_some());
    count += usize::from(field.blob_value.is_some());
    count += usize::from(field.array_value.is_some());
    if count != 1 || field.is_null == Some(false) || field.array_value.is_some() {
        return Err(RdsDataError::BadRequest(
            "SQL parameter value must contain one scalar field",
        ));
    }
    if field.is_null == Some(true) {
        return Ok(match *expected {
            Type::BOOL => Box::new(Option::<bool>::None),
            Type::INT2 => Box::new(Option::<i16>::None),
            Type::INT4 => Box::new(Option::<i32>::None),
            Type::INT8 => Box::new(Option::<i64>::None),
            Type::FLOAT4 => Box::new(Option::<f32>::None),
            Type::FLOAT8 => Box::new(Option::<f64>::None),
            _ => Box::new(Option::<String>::None),
        });
    }
    if let Some(v) = field.boolean_value {
        return Ok(Box::new(v));
    }
    if let Some(v) = field.long_value {
        return Ok(match *expected {
            Type::INT2 => Box::new(
                i16::try_from(v)
                    .map_err(|_| RdsDataError::BadRequest("integer parameter overflows int2"))?,
            ),
            Type::INT4 => Box::new(
                i32::try_from(v)
                    .map_err(|_| RdsDataError::BadRequest("integer parameter overflows int4"))?,
            ),
            _ => Box::new(v),
        });
    }
    if let Some(v) = field.double_value {
        return Ok(match *expected {
            Type::FLOAT4 => Box::new(v as f32),
            _ => Box::new(v),
        });
    }
    if let Some(v) = &field.string_value {
        return Ok(Box::new(v.clone()));
    }
    Err(RdsDataError::Unsupported(
        "blob SQL parameters are unsupported",
    ))
}

pub(crate) async fn execute(
    client: &Client,
    sql: &str,
    parameters: &[SqlParameter],
    include_metadata: bool,
    limits: &RdsDataLimits,
) -> Result<Value, RdsDataError> {
    if parameters.len() > limits.max_parameters {
        return Err(RdsDataError::BadRequest("too many SQL parameters"));
    }
    let (sql, order) = rewrite(sql, parameters)?;
    let statement = client
        .prepare(&sql)
        .await
        .map_err(|_| RdsDataError::Database("SQL statement could not be prepared"))?;
    if statement.params().len() != order.len() {
        return Err(RdsDataError::BadRequest(
            "SQL parameters do not match placeholders",
        ));
    }
    let values = order
        .iter()
        .enumerate()
        .map(|(position, source)| {
            if parameters[*source].type_hint.is_some() {
                return Err(RdsDataError::Unsupported(
                    "SQL parameter type hints are unsupported",
                ));
            }
            value(&parameters[*source].value, &statement.params()[position])
        })
        .collect::<Result<Vec<_>, _>>()?;
    let references = values
        .iter()
        .map(|value| &**value as &(dyn ToSql + Sync))
        .collect::<Vec<_>>();
    let stream = client
        .query_raw(&statement, references)
        .await
        .map_err(|_| RdsDataError::Database("SQL statement failed"))?;
    tokio::pin!(stream);
    let mut records = Vec::new();
    let mut estimated = 0usize;
    while let Some(row) = stream
        .try_next()
        .await
        .map_err(|_| RdsDataError::Database("SQL statement failed"))?
    {
        if records.len() >= limits.max_rows {
            return Err(RdsDataError::Database("result exceeds row limit"));
        }
        let mut fields = Vec::new();
        for (i, column) in statement.columns().iter().enumerate() {
            macro_rules! decode {
                ($ty:ty, $key:literal) => {
                    row.try_get::<_, Option<$ty>>(i)
                        .map_err(|_| RdsDataError::Unsupported("SQL result type cannot be decoded"))?
                        .map(|value| json!({$key: value}))
                };
            }
            let field = match *column.type_() {
                Type::BOOL => decode!(bool, "booleanValue"),
                Type::INT2 => decode!(i16, "longValue"),
                Type::INT4 => decode!(i32, "longValue"),
                Type::INT8 => decode!(i64, "longValue"),
                Type::FLOAT4 => decode!(f32, "doubleValue"),
                Type::FLOAT8 => decode!(f64, "doubleValue"),
                Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => {
                    decode!(String, "stringValue")
                }
                _ => return Err(RdsDataError::Unsupported("SQL result type is unsupported")),
            }
            .unwrap_or_else(|| json!({"isNull": true}));
            let size = field.to_string().len();
            if size > limits.max_field_bytes
                || estimated.saturating_add(size) > limits.response_bytes
            {
                return Err(RdsDataError::Database("result exceeds response limit"));
            }
            estimated += size;
            fields.push(field);
        }
        records.push(fields);
    }
    if !statement.columns().is_empty() {
        let mut result = json!({"records": records});
        if include_metadata {
            result["columnMetadata"] = Value::Array(statement.columns().iter().map(|column| {
                json!({"name": column.name(), "label": column.name(), "typeName": column.type_().name()})
            }).collect());
        }
        Ok(result)
    } else {
        Ok(json!({"numberOfRecordsUpdated": stream.rows_affected().unwrap_or(0)}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_named_parameters_without_touching_literals_or_casts() {
        let parameters = vec![SqlParameter {
            name: "id".into(),
            value: Field {
                is_null: None,
                boolean_value: None,
                long_value: Some(1),
                double_value: None,
                string_value: None,
                blob_value: None,
                array_value: None,
            },
            type_hint: None,
        }];
        let (sql, order) = rewrite("SELECT ':id', :id::int4, :id", &parameters).unwrap();
        assert_eq!(sql, "SELECT ':id', $1::int4, $1");
        assert_eq!(order, vec![0]);
    }
}
