//! REST API Gateway tagging operates on the same records as resource CRUD.

use http::Method;
use serde_json::{json, Map, Value};

use crate::{error::ApiGwError, v1::Ctx};

type Out = Result<(u16, Value), ApiGwError>;

enum Target<'a> {
    RestApi(&'a str),
    Stage(&'a str, &'a str),
    ApiKey(&'a str),
    UsagePlan(&'a str),
    Domain(&'a str),
    PrivateDomain,
    Association,
}

fn bad_request(message: &str) -> ApiGwError {
    ApiGwError::BadRequest(message.into())
}

fn target<'a>(arn: &'a str, ctx: &Ctx<'_>) -> Result<Target<'a>, ApiGwError> {
    if arn.len() > 2048 || arn.chars().any(char::is_control) {
        return Err(bad_request("Invalid resource ARN"));
    }
    let fields: Vec<_> = arn.splitn(6, ':').collect();
    let ["arn", "aws", "apigateway", region, account, resource] = fields.as_slice() else {
        return Err(bad_request("Invalid API Gateway resource ARN"));
    };
    if *region != ctx.region || (!account.is_empty() && *account != ctx.account) {
        return Err(bad_request("Resource ARN does not match the request scope"));
    }
    let parts: Vec<_> = resource.split('/').collect();
    if parts
        .iter()
        .skip(1)
        .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        return Err(bad_request("Invalid resource ARN path"));
    }
    match parts.as_slice() {
        ["", "restapis", id] if account.is_empty() => Ok(Target::RestApi(id)),
        ["", "restapis", id, "stages", stage] if account.is_empty() => Ok(Target::Stage(id, stage)),
        ["", "apikeys", id] if account.is_empty() => Ok(Target::ApiKey(id)),
        ["", "usageplans", id] if account.is_empty() => Ok(Target::UsagePlan(id)),
        ["", "domainnames", name] if account.is_empty() => Ok(Target::Domain(name)),
        ["", "domainnames", name] if *account == ctx.account && name.contains('+') => {
            Ok(Target::PrivateDomain)
        }
        ["", "domainnameaccessassociations", "domainname", _, "vpcesource", _]
            if *account == ctx.account =>
        {
            Ok(Target::Association)
        }
        _ => Err(bad_request(
            "Unsupported resource type for REST API Gateway tagging",
        )),
    }
}

/// URI path decoding keeps literal plus signs (private domain ARNs contain them).
fn decode(value: &str, query: bool) -> Result<String, ApiGwError> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut source = value.bytes();
    while let Some(byte) = source.next() {
        match byte {
            b'%' => {
                let high = source.next().and_then(|byte| (byte as char).to_digit(16));
                let low = source.next().and_then(|byte| (byte as char).to_digit(16));
                match (high, low) {
                    (Some(high), Some(low)) => bytes.push((high * 16 + low) as u8),
                    _ => return Err(bad_request("Invalid percent encoding")),
                }
            }
            b'+' if query => bytes.push(b' '),
            byte => bytes.push(byte),
        }
    }
    String::from_utf8(bytes).map_err(|_| bad_request("Invalid UTF-8 encoding"))
}

fn valid_text(value: &str, max: usize) -> bool {
    value.chars().count() <= max
        && value
            .chars()
            .all(|ch| ch.is_alphanumeric() || ch == ' ' || ".:+=@_/-".contains(ch))
}

fn validate_key(key: &str) -> Result<(), ApiGwError> {
    if key.is_empty() || !valid_text(key, 128) || key.to_ascii_lowercase().starts_with("aws:") {
        return Err(bad_request("Invalid tag key"));
    }
    Ok(())
}

pub(crate) fn input_tags(value: &Value) -> Result<Map<String, Value>, ApiGwError> {
    let tags = value
        .as_object()
        .ok_or_else(|| bad_request("tags must be a string map"))?;
    if tags.len() > 50 {
        return Err(bad_request("A resource may have at most 50 tags"));
    }
    for (key, value) in tags {
        validate_key(key)?;
        let value = value
            .as_str()
            .ok_or_else(|| bad_request("Tag values must be strings"))?;
        if !valid_text(value, 256) {
            return Err(bad_request("Invalid tag value"));
        }
    }
    Ok(tags.clone())
}

enum Operation {
    Get,
    Put(Map<String, Value>),
    Delete(Vec<String>),
}

impl Operation {
    fn parse(method: &Method, query: Option<&str>, body: &Value) -> Result<Self, ApiGwError> {
        match *method {
            Method::GET => Ok(Self::Get),
            Method::PUT => Ok(Self::Put(input_tags(
                body.get("tags")
                    .ok_or_else(|| bad_request("tags is required"))?,
            )?)),
            Method::DELETE => {
                let mut keys = Vec::new();
                for entry in query
                    .unwrap_or("")
                    .split('&')
                    .filter(|entry| !entry.is_empty())
                {
                    let (key, value) = entry.split_once('=').unwrap_or((entry, ""));
                    if decode(key, true)? == "tagKeys" {
                        let key = decode(value, true)?;
                        validate_key(&key)?;
                        keys.push(key);
                        if keys.len() > 50 {
                            return Err(bad_request("At most 50 tag keys may be removed"));
                        }
                    }
                }
                if keys.is_empty() {
                    return Err(bad_request("tagKeys is required"));
                }
                Ok(Self::Delete(keys))
            }
            _ => Err(ApiGwError::NotFound("Unknown tagging operation".into())),
        }
    }

    fn apply(self, resource: &mut Value) -> Out {
        let mut tags = match resource.get("tags") {
            Some(Value::Object(tags)) => tags.clone(),
            None => Map::new(),
            Some(_) => return Err(ApiGwError::Internal("Invalid stored resource tags".into())),
        };
        match self {
            Self::Get => return Ok((200, json!({"tags": tags}))),
            Self::Put(additions) => {
                tags.extend(additions);
                if tags.len() > 50 {
                    return Err(bad_request("A resource may have at most 50 tags"));
                }
            }
            Self::Delete(keys) => {
                for key in keys {
                    tags.remove(&key);
                }
            }
        }
        let resource = resource
            .as_object_mut()
            .ok_or_else(|| ApiGwError::Internal("Invalid stored resource".into()))?;
        resource.insert("tags".into(), Value::Object(tags));
        Ok((204, Value::Null))
    }
}

pub(crate) async fn route(
    method: &Method,
    encoded: &str,
    query: Option<&str>,
    ctx: &Ctx<'_>,
    body: &Value,
) -> Out {
    if encoded.len() > 6144 {
        return Err(bad_request("Resource ARN is too long"));
    }
    let arn = decode(encoded, false)?;
    let target = target(&arn, ctx)?;
    let operation = Operation::parse(method, query, body)?;
    let missing = || ApiGwError::NotFound("Invalid resource identifier specified".into());
    match target {
        Target::RestApi(id) | Target::Stage(id, _) => {
            let record = ctx
                .store
                .rest(ctx.account, ctx.region, id)
                .ok_or_else(missing)?;
            let mut record = record.write().await;
            let resource = match target {
                Target::RestApi(_) => &mut record.api,
                Target::Stage(_, stage) => record.stages.get_mut(stage).ok_or_else(missing)?,
                _ => unreachable!("REST API targets selected above"),
            };
            operation.apply(resource)
        }
        Target::ApiKey(_)
        | Target::UsagePlan(_)
        | Target::Domain(_)
        | Target::PrivateDomain
        | Target::Association => {
            let shared = ctx.store.shared(ctx.account, ctx.region);
            let mut shared = shared.write().await;
            let resource = match target {
                Target::ApiKey(id) => shared.api_keys.get_mut(id),
                Target::UsagePlan(id) => shared.usage_plans.get_mut(id),
                Target::Domain(name) => shared.domains.get_mut(name),
                Target::PrivateDomain => shared.private_domains.values_mut().find(|domain| {
                    domain.get("domainNameArn").and_then(Value::as_str) == Some(&arn)
                }),
                Target::Association => shared.domain_access_associations.get_mut(&arn),
                Target::RestApi(_) | Target::Stage(_, _) => {
                    unreachable!("shared targets selected above")
                }
            }
            .ok_or_else(missing)?;
            operation.apply(resource)
        }
    }
}
