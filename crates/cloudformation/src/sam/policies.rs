use serde_json::{json, Value};

use super::{intrinsic, object, only_keys, unsupported};
use crate::error::CfnError;

// Definition from aws-sam-translator 1.113.0 (Apache-2.0):
// https://github.com/aws/serverless-application-model/blob/v1.113.0/samtranslator/policy_templates_data/policy_templates.json
const DYNAMODB_CRUD: &str = include_str!("dynamodb-crud-policy.json");

fn bind_table(definition: &mut Value, table: &Value) {
    match definition {
        Value::Object(map)
            if map.len() == 1 && map.get("Ref").and_then(Value::as_str) == Some("TableName") =>
        {
            *definition = table.clone();
        }
        Value::Object(map) => {
            for value in map.values_mut() {
                bind_table(value, table);
            }
        }
        Value::Array(values) => {
            for value in values {
                bind_table(value, table);
            }
        }
        _ => {}
    }
}

pub(super) fn role_policies(
    role_id: &str,
    policies: Option<&Value>,
) -> Result<(Vec<Value>, Vec<Value>), CfnError> {
    let values: Vec<&Value> = match policies {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(values)) => values.iter().collect(),
        Some(value) => vec![value],
    };
    let mut managed = Vec::new();
    let mut inline = Vec::new();
    for (index, policy) in values.into_iter().enumerate() {
        let document = match policy {
            Value::String(arn) if arn.starts_with("arn:") => {
                if !managed.contains(policy) {
                    managed.push(policy.clone());
                }
                continue;
            }
            Value::String(_) => {
                return Err(unsupported(
                    "Policies managed entries require full policy ARNs",
                ));
            }
            Value::Object(map) if map.contains_key("Statement") => policy.clone(),
            Value::Object(map) if map.len() == 1 && map.contains_key("DynamoDBCrudPolicy") => {
                let parameters = object(
                    map.get("DynamoDBCrudPolicy").ok_or(CfnError::Internal)?,
                    "DynamoDBCrudPolicy",
                )?;
                only_keys(parameters, &["TableName"], "DynamoDBCrudPolicy")?;
                let table = parameters
                    .get("TableName")
                    .filter(|value| {
                        value.as_str().is_some_and(|name| !name.is_empty()) || intrinsic(value)
                    })
                    .ok_or_else(|| unsupported("DynamoDBCrudPolicy requires TableName"))?;
                let mut definition: Value =
                    serde_json::from_str(DYNAMODB_CRUD).map_err(|_| CfnError::Internal)?;
                // Traverse only the bundled definition, never substituted client values.
                bind_table(&mut definition, table);
                definition
            }
            _ => {
                return Err(unsupported(
                    "unsupported or invalid Function Policies entry",
                ))
            }
        };
        inline.push(
            json!({"PolicyName":format!("{role_id}Policy{index}"),"PolicyDocument":document}),
        );
    }
    Ok((managed, inline))
}
