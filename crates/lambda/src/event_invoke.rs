//! Qualified asynchronous invocation configuration, shared by REST and the executor.
use crate::{
    error::LambdaError,
    model::{resolve_function_name, EventInvokeConfig, FunctionStore},
};
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

type ResultBody = Result<(u16, Option<Value>), LambdaError>;
fn invalid(message: &str) -> LambdaError {
    LambdaError::InvalidParameterValue(message.into())
}

/// Combine URI and query qualifiers without allowing one to silently override another.
pub(crate) fn reference(name: &str, qualifier: Option<&str>) -> Result<String, LambdaError> {
    let parts: Vec<_> = name.split(':').collect();
    let embedded = match parts.as_slice() {
        ["arn", "aws", "lambda", _, _, "function", _, q] => Some(*q),
        ["arn", "aws", "lambda", _, _, "function", _] => None,
        [account, "function", _, q]
            if account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some(*q)
        }
        [account, "function", _]
            if account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit()) =>
        {
            None
        }
        [_, q] => Some(*q),
        [_] => None,
        _ => return Err(invalid("Invalid Lambda function reference")),
    };
    if let (Some(a), Some(b)) = (embedded, qualifier) {
        if a != b {
            return Err(invalid("FunctionName and Qualifier disagree"));
        }
    }
    let qualifier = qualifier.or(embedded).unwrap_or("$LATEST");
    if qualifier.is_empty()
        || qualifier.len() > 128
        || !(qualifier == "$LATEST"
            || qualifier
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c)))
    {
        return Err(invalid("Invalid asynchronous invocation qualifier"));
    }
    if qualifier.bytes().all(|b| b.is_ascii_digit())
        && qualifier
            .parse::<u64>()
            .ok()
            .filter(|version| *version > 0 && version.to_string() == qualifier)
            .is_none()
    {
        return Err(invalid("Invalid function version qualifier"));
    }
    if embedded.is_some() {
        Ok(name.into())
    } else {
        Ok(format!("{name}:{qualifier}"))
    }
}

fn scoped_name(reference: &str, region: &str, account: &str) -> Result<String, LambdaError> {
    if reference.starts_with("arn:") && reference.split(':').nth(4) != Some(account) {
        return Err(invalid("Function ARN account does not match request scope"));
    }
    if !reference.starts_with("arn:")
        && reference.contains(":function:")
        && reference.split(':').next() != Some(account)
    {
        return Err(invalid("Function ARN account does not match request scope"));
    }
    resolve_function_name(reference, region)
}

fn target(
    store: &FunctionStore,
    region: &str,
    account: &str,
    reference: &str,
) -> Result<(String, String), LambdaError> {
    let reference = self::reference(reference, None)?;
    let name = scoped_name(&reference, region, account)?;
    let qualifier = reference
        .rsplit(':')
        .next()
        .ok_or_else(|| invalid("Invalid function reference"))?;
    let arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| LambdaError::ResourceNotFound(format!("Function not found: {name}")))?;
    if qualifier != "$LATEST" {
        let exists = match qualifier.parse::<u64>() {
            Ok(version) => store.get_version(account, region, &name, version).is_some(),
            Err(_) => store.get_alias(account, region, &name, qualifier).is_some(),
        };
        if !exists {
            return Err(LambdaError::ResourceNotFound(format!(
                "Function qualifier not found: {qualifier}"
            )));
        }
    }
    Ok((format!("{name}:{qualifier}"), format!("{arn}:{qualifier}")))
}

fn fields(input: &Value, allowed: &[&str]) -> Result<(), LambdaError> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("Configuration must be an object"))?;
    if object
        .keys()
        .any(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(
            "Unsupported asynchronous invocation configuration field",
        ));
    }
    Ok(())
}
fn number(
    input: &Value,
    field: &str,
    minimum: u64,
    maximum: u64,
) -> Result<Option<u32>, LambdaError> {
    input
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .filter(|n| (minimum..=maximum).contains(n))
                .map(|n| n as u32)
                .ok_or_else(|| {
                    invalid(&format!(
                        "{field} must be an integer between {minimum} and {maximum}"
                    ))
                })
        })
        .transpose()
}
fn destinations(value: &Value) -> Result<Value, LambdaError> {
    fields(value, &["OnSuccess", "OnFailure"])?;
    for (kind, target) in value.as_object().into_iter().flatten() {
        fields(target, &["Destination"])?;
        let arn = target
            .get("Destination")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Destination must be a string"))?;
        if arn.is_empty() {
            continue;
        } // AWS uses empty destination to remove an existing route.
        if arn.len() > 350 || arn.chars().any(char::is_control) {
            return Err(invalid("Invalid destination ARN"));
        }
        let parts: Vec<_> = arn.splitn(6, ':').collect();
        let ["arn", "aws", service, region, account, resource] = parts.as_slice() else {
            return Err(invalid("Invalid destination ARN"));
        };
        if *service != "sqs" || resource.ends_with(".fifo") {
            return Err(LambdaError::NotImplemented(format!(
                "Only standard SQS {kind} destinations are currently implemented"
            )));
        }
        if region.is_empty()
            || region.len() > 64
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || account.len() != 12
            || !account.bytes().all(|b| b.is_ascii_digit())
            || resource.is_empty()
            || resource.len() > 80
            || !resource
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err(invalid("Invalid standard SQS destination ARN"));
        }
    }
    Ok(value.clone())
}
fn config(input: &Value) -> Result<EventInvokeConfig, LambdaError> {
    fields(
        input,
        &[
            "MaximumRetryAttempts",
            "MaximumEventAgeInSeconds",
            "DestinationConfig",
        ],
    )?;
    let mut destination = input
        .get("DestinationConfig")
        .map(destinations)
        .transpose()?;
    if let Some(Value::Object(map)) = &mut destination {
        map.retain(|_, v| v.get("Destination").and_then(Value::as_str) != Some(""));
    }
    Ok(EventInvokeConfig {
        maximum_retry_attempts: number(input, "MaximumRetryAttempts", 0, 2)?,
        maximum_event_age_in_seconds: number(input, "MaximumEventAgeInSeconds", 60, 21600)?,
        destination_config: destination,
        last_modified: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| invalid("Cannot format timestamp"))?,
    })
}

pub(crate) enum Operation {
    Put,
    Update,
    Get,
    Delete,
}
pub(crate) fn handle(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    operation: Operation,
    input: &Value,
) -> ResultBody {
    let (key, arn) = target(store, region, account, name)?;
    let missing =
        || LambdaError::ResourceNotFound(format!("EventInvokeConfig not found for {key}"));
    match operation {
        Operation::Get => Ok((
            200,
            Some(
                store
                    .get_event_invoke_config(account, region, &key)
                    .ok_or_else(missing)?
                    .to_json(&arn),
            ),
        )),
        Operation::Delete => {
            if !store.delete_event_invoke_config(account, region, &key) {
                return Err(missing());
            }
            Ok((204, None))
        }
        Operation::Put | Operation::Update => {
            let mut next = config(input)?;
            if matches!(operation, Operation::Update) {
                let old = store
                    .get_event_invoke_config(account, region, &key)
                    .ok_or_else(missing)?;
                if input.as_object().is_none_or(|v| v.is_empty()) {
                    return Err(invalid("Update must contain a configuration field"));
                }
                if input.get("MaximumRetryAttempts").is_none() {
                    next.maximum_retry_attempts = old.maximum_retry_attempts;
                }
                if input.get("MaximumEventAgeInSeconds").is_none() {
                    next.maximum_event_age_in_seconds = old.maximum_event_age_in_seconds;
                }
                if let Some(old_destination) = old.destination_config {
                    let mut merged = old_destination.as_object().cloned().unwrap_or_default();
                    if let Some(updates) = input.get("DestinationConfig").and_then(Value::as_object)
                    {
                        for (kind, value) in updates {
                            if value.get("Destination").and_then(Value::as_str) == Some("") {
                                merged.remove(kind);
                            } else {
                                merged.insert(kind.clone(), value.clone());
                            }
                        }
                    }
                    next.destination_config = Some(Value::Object(merged));
                }
            }
            if next
                .destination_config
                .as_ref()
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .any(|(_, entry)| {
                    entry
                        .get("Destination")
                        .and_then(Value::as_str)
                        .and_then(|arn| arn.split(':').nth(4))
                        != Some(account)
                })
            {
                return Err(LambdaError::NotImplemented(
                    "Cross-account asynchronous destinations are not implemented".into(),
                ));
            }
            if !store.set_event_invoke_config(account, region, &key, next.clone()) {
                return Err(missing());
            }
            Ok((200, Some(next.to_json(&arn))))
        }
    }
}

pub(crate) fn list(
    store: &FunctionStore,
    region: &str,
    account: &str,
    name: &str,
    marker: Option<&str>,
    maximum: Option<&str>,
) -> ResultBody {
    let reference = reference(name, None)?;
    let name = scoped_name(&reference, region, account)?;
    let arn = store
        .function_base_arn(account, region, &name)
        .ok_or_else(|| LambdaError::ResourceNotFound(format!("Function not found: {name}")))?;
    let limit = maximum
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|_| invalid("Invalid MaxItems"))?
        .unwrap_or(50);
    if !(1..=50).contains(&limit) {
        return Err(invalid("MaxItems must be between 1 and 50"));
    }
    let prefix = format!("{arn}:");
    let marker = marker
        .map(|marker| {
            marker
                .strip_prefix(&prefix)
                .ok_or_else(|| invalid("Invalid pagination marker"))
        })
        .transpose()?;
    let configs = store
        .event_invoke_configs_page(account, region, &name, marker, limit)
        .ok_or_else(|| invalid("Invalid pagination marker"))?;
    let page = configs
        .iter()
        .take(limit)
        .map(|(q, c)| c.to_json(&format!("{arn}:{q}")))
        .collect::<Vec<_>>();
    let mut body = json!({"FunctionEventInvokeConfigs":page});
    if configs.len() > limit {
        if let Some((q, _)) = configs.get(limit - 1) {
            body["NextMarker"] = json!(format!("{arn}:{q}"));
        }
    }
    Ok((200, Some(body)))
}
