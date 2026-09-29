//! API Gateway v1 (REST) control-plane operations. Each returns `(status, body)` or an error.
//! Resources are addressed by method + path segments under `/restapis`.

use std::sync::{RwLock, Weak};

use localcloud_wafv2::WafEvaluator;

use http::{HeaderName, HeaderValue};
use localcloud_core::registry::ServiceRegistry;
use serde_json::{json, Value};

use crate::error::ApiGwError;
use crate::logging::{preflight, rest_stage_logging};
use crate::store::{gen_id, ApiGwStore, RestApiRecord};

pub struct Ctx<'a> {
    pub store: &'a ApiGwStore,
    pub registry: &'a Weak<ServiceRegistry>,
    pub region: &'a str,
    pub account: &'a str,
    pub request_id: &'a str,
    pub waf: Option<&'a RwLock<Option<Weak<dyn WafEvaluator>>>>,
}

type Out = Result<(u16, Value), ApiGwError>;

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn req_str<'a>(body: &'a Value, key: &str) -> Result<&'a str, ApiGwError> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiGwError::BadRequest(format!("{key} is required")))
}

fn optional_object(body: &Value, key: &str) -> Result<Value, ApiGwError> {
    match body.get(key) {
        Some(value) if !value.is_object() => {
            Err(ApiGwError::BadRequest(format!("{key} must be an object")))
        }
        Some(value) => Ok(value.clone()),
        None => Ok(json!({})),
    }
}

fn patch_segments(path: &str) -> Result<Vec<String>, ApiGwError> {
    if !path.starts_with('/') {
        return Err(ApiGwError::BadRequest(format!(
            "Invalid patch path: {path}"
        )));
    }
    Ok(path[1..]
        .split('/')
        .map(|part| part.replace("~1", "/").replace("~0", "~"))
        .collect())
}

fn coerced_patch_value(value: &Value, current: Option<&Value>) -> Result<Value, ApiGwError> {
    let Some(text) = value.as_str() else {
        return Ok(value.clone());
    };
    match current {
        Some(Value::Bool(_)) => text
            .parse::<bool>()
            .map(Value::Bool)
            .map_err(|_| ApiGwError::BadRequest(format!("Invalid boolean patch value: {text}"))),
        Some(Value::Number(_)) => serde_json::from_str(text)
            .map_err(|_| ApiGwError::BadRequest(format!("Invalid numeric patch value: {text}"))),
        Some(Value::Array(_) | Value::Object(_)) => serde_json::from_str(text)
            .map_err(|_| ApiGwError::BadRequest("Patch value must contain valid JSON".into())),
        _ => Ok(Value::String(text.to_string())),
    }
}

fn apply_patch_operations<F>(target: &mut Value, body: &Value, allowed: F) -> Result<(), ApiGwError>
where
    F: Fn(&str) -> bool,
{
    let operations = body
        .get("patchOperations")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiGwError::BadRequest("patchOperations is required".into()))?;
    for operation in operations {
        let op = req_str(operation, "op")?;
        let path = req_str(operation, "path")?;
        if !matches!(op, "add" | "replace" | "remove") {
            return Err(ApiGwError::BadRequest(format!(
                "Unsupported patch operation: {op}"
            )));
        }
        if !allowed(path) {
            return Err(ApiGwError::BadRequest(format!(
                "Invalid patch path: {path}"
            )));
        }
        let segments = patch_segments(path)?;
        let (last, parents) = segments
            .split_last()
            .ok_or_else(|| ApiGwError::BadRequest("Patch path cannot be empty".into()))?;
        let mut parent = &mut *target;
        for segment in parents {
            parent = match parent {
                Value::Object(map) => map.get_mut(segment),
                Value::Array(items) => segment
                    .parse::<usize>()
                    .ok()
                    .and_then(|index| items.get_mut(index)),
                _ => None,
            }
            .ok_or_else(|| ApiGwError::BadRequest(format!("Invalid patch path: {path}")))?;
        }
        match parent {
            Value::Object(map) => {
                if op == "remove" {
                    if map.remove(last).is_none() {
                        return Err(ApiGwError::BadRequest(format!(
                            "Invalid patch path: {path}"
                        )));
                    }
                } else {
                    if op == "replace" && !map.contains_key(last) {
                        return Err(ApiGwError::BadRequest(format!(
                            "Invalid patch path: {path}"
                        )));
                    }
                    let raw = operation.get("value").ok_or_else(|| {
                        ApiGwError::BadRequest(format!("value is required for patch {op}"))
                    })?;
                    let value = coerced_patch_value(raw, map.get(last))?;
                    map.insert(last.clone(), value);
                }
            }
            Value::Array(items) => {
                if last == "-" && op == "add" {
                    let raw = operation.get("value").ok_or_else(|| {
                        ApiGwError::BadRequest("value is required for patch add".into())
                    })?;
                    items.push(coerced_patch_value(raw, None)?);
                    continue;
                }
                let index = last
                    .parse::<usize>()
                    .map_err(|_| ApiGwError::BadRequest(format!("Invalid patch path: {path}")))?;
                if op == "remove" {
                    if index >= items.len() {
                        return Err(ApiGwError::BadRequest(format!(
                            "Invalid patch path: {path}"
                        )));
                    }
                    items.remove(index);
                } else {
                    let raw = operation.get("value").ok_or_else(|| {
                        ApiGwError::BadRequest(format!("value is required for patch {op}"))
                    })?;
                    if op == "add" && index == items.len() {
                        items.push(coerced_patch_value(raw, None)?);
                    } else if index < items.len() {
                        items[index] = coerced_patch_value(raw, items.get(index))?;
                    } else {
                        return Err(ApiGwError::BadRequest(format!(
                            "Invalid patch path: {path}"
                        )));
                    }
                }
            }
            _ => {
                return Err(ApiGwError::BadRequest(format!(
                    "Invalid patch path: {path}"
                )));
            }
        }
    }
    Ok(())
}

async fn rest(
    ctx: &Ctx<'_>,
    api_id: &str,
) -> Result<std::sync::Arc<tokio::sync::RwLock<RestApiRecord>>, ApiGwError> {
    ctx.store
        .rest(ctx.account, ctx.region, api_id)
        .ok_or_else(|| {
            ApiGwError::NotFound(format!("Invalid REST API identifier specified: {api_id}"))
        })
}

// ============================ REST APIs ========================================

pub async fn create_rest_api(ctx: &Ctx<'_>, body: &Value) -> Out {
    let name = req_str(body, "name")?;
    let id = gen_id();
    let root_id = gen_id();
    let api = json!({
        "id": id,
        "name": name,
        "description": body.get("description").cloned().unwrap_or(Value::Null),
        "createdDate": now_epoch(),
        "version": body.get("version").cloned().unwrap_or(Value::Null),
        "rootResourceId": root_id,
        "apiKeySource": body.get("apiKeySource").and_then(Value::as_str).unwrap_or("HEADER"),
        "endpointConfiguration": body.get("endpointConfiguration").cloned().unwrap_or(json!({ "types": ["EDGE"] })),
        "binaryMediaTypes": body.get("binaryMediaTypes").cloned().unwrap_or(json!([])),
        "minimumCompressionSize": body.get("minimumCompressionSize").cloned().unwrap_or(Value::Null),
        "policy": body.get("policy").cloned().unwrap_or(Value::Null),
        "tags": body.get("tags").cloned().unwrap_or(json!({})),
        "disableExecuteApiEndpoint": body.get("disableExecuteApiEndpoint").and_then(Value::as_bool).unwrap_or(false),
    });
    let root = json!({ "id": root_id, "path": "/", "resourceMethods": {} });
    let mut rec = RestApiRecord {
        api: api.clone(),
        ..Default::default()
    };
    rec.resources.insert(root_id, root);
    ctx.store.insert_rest(ctx.account, ctx.region, &id, rec);
    Ok((201, api))
}

pub async fn get_rest_apis(ctx: &Ctx<'_>) -> Out {
    let mut items = Vec::new();
    for r in ctx.store.list_rest(ctx.account, ctx.region) {
        items.push(r.read().await.api.clone());
    }
    Ok((200, json!({ "item": items })))
}

pub async fn get_rest_api(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let api = r.read().await.api.clone();
    Ok((200, api))
}

pub async fn update_rest_api(ctx: &Ctx<'_>, api_id: &str, body: &Value) -> Out {
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    let mut updated = guard.api.clone();
    apply_patch_operations(&mut updated, body, |path| {
        matches!(
            path,
            "/name"
                | "/description"
                | "/version"
                | "/apiKeySource"
                | "/minimumCompressionSize"
                | "/disableExecuteApiEndpoint"
                | "/policy"
                | "/endpointConfiguration/types"
                | "/binaryMediaTypes/-"
        ) || path
            .strip_prefix("/binaryMediaTypes/")
            .is_some_and(|index| index.parse::<usize>().is_ok())
    })?;
    guard.api = updated.clone();
    Ok((200, updated))
}

pub async fn delete_rest_api(ctx: &Ctx<'_>, api_id: &str) -> Out {
    if !ctx.store.remove_rest(ctx.account, ctx.region, api_id) {
        return Err(ApiGwError::NotFound(format!(
            "Invalid REST API identifier specified: {api_id}"
        )));
    }
    Ok((202, json!({})))
}

// ============================ Resources ========================================

pub async fn get_resources(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let items: Vec<Value> = r.read().await.resources.values().cloned().collect();
    Ok((200, json!({ "item": items })))
}

pub async fn get_resource(ctx: &Ctx<'_>, api_id: &str, resource_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let guard = r.read().await;
    guard
        .resources
        .get(resource_id)
        .cloned()
        .map(|v| (200, v))
        .ok_or_else(|| {
            ApiGwError::NotFound(format!(
                "Invalid resource identifier specified: {resource_id}"
            ))
        })
}

pub async fn create_resource(ctx: &Ctx<'_>, api_id: &str, parent_id: &str, body: &Value) -> Out {
    let path_part = req_str(body, "pathPart")?.to_string();
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    let parent = guard.resources.get(parent_id).ok_or_else(|| {
        ApiGwError::NotFound(format!(
            "Invalid resource identifier specified: {parent_id}"
        ))
    })?;
    let parent_path = parent
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("/")
        .to_string();
    // Sibling pathPart conflict.
    let conflict = guard.resources.values().any(|res| {
        res.get("parentId").and_then(Value::as_str) == Some(parent_id)
            && res.get("pathPart").and_then(Value::as_str) == Some(path_part.as_str())
    });
    if conflict {
        return Err(ApiGwError::Conflict(format!(
            "Another resource with the same parent already has this name: {path_part}"
        )));
    }
    let new_path = if parent_path == "/" {
        format!("/{path_part}")
    } else {
        format!("{parent_path}/{path_part}")
    };
    let id = gen_id();
    let resource = json!({
        "id": id,
        "parentId": parent_id,
        "pathPart": path_part,
        "path": new_path,
        "resourceMethods": {},
    });
    guard.resources.insert(id, resource.clone());
    Ok((201, resource))
}

pub async fn delete_resource(ctx: &Ctx<'_>, api_id: &str, resource_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    let resource = guard.resources.get(resource_id).ok_or_else(|| {
        ApiGwError::NotFound(format!(
            "Invalid resource identifier specified: {resource_id}"
        ))
    })?;
    if resource.get("parentId").is_none() {
        return Err(ApiGwError::BadRequest(
            "The root resource cannot be deleted".into(),
        ));
    }

    let mut pending = vec![resource_id.to_string()];
    let mut remove = Vec::new();
    while let Some(parent_id) = pending.pop() {
        remove.push(parent_id.clone());
        pending.extend(
            guard
                .resources
                .iter()
                .filter(|(_, resource)| {
                    resource.get("parentId").and_then(Value::as_str) == Some(&parent_id)
                })
                .map(|(id, _)| id.clone()),
        );
    }
    for id in remove {
        guard.resources.remove(&id);
    }
    Ok((202, json!({})))
}

// ============================ Methods & integrations ===========================

fn with_method<F, T>(resource: &mut Value, http_method: &str, f: F) -> Option<T>
where
    F: FnOnce(&mut Value) -> T,
{
    let methods = resource.get_mut("resourceMethods")?.as_object_mut()?;
    methods.get_mut(http_method).map(f)
}

pub async fn put_method(
    ctx: &Ctx<'_>,
    api_id: &str,
    resource_id: &str,
    http_method: &str,
    body: &Value,
) -> Out {
    let auth_type = match body.get("authorizationType") {
        Some(value) => value
            .as_str()
            .ok_or_else(|| ApiGwError::BadRequest("authorizationType must be a string".into()))?,
        None => "NONE",
    };
    if !matches!(auth_type, "NONE" | "CUSTOM") {
        return Err(ApiGwError::BadRequest(format!(
            "Unsupported authorizationType: {auth_type}"
        )));
    }
    let authorizer_id = body.get("authorizerId").and_then(Value::as_str);
    if auth_type == "CUSTOM" && authorizer_id.is_none() {
        return Err(ApiGwError::BadRequest(
            "CUSTOM authorization requires authorizerId".into(),
        ));
    }
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    if let Some(authorizer_id) = authorizer_id {
        if auth_type == "CUSTOM" && !guard.authorizers.contains_key(authorizer_id) {
            return Err(ApiGwError::NotFound(
                "Invalid authorizer identifier specified".into(),
            ));
        }
    }
    let resource = guard.resources.get_mut(resource_id).ok_or_else(|| {
        ApiGwError::NotFound(format!(
            "Invalid resource identifier specified: {resource_id}"
        ))
    })?;
    let method = json!({
        "httpMethod": http_method,
        "authorizationType": auth_type,
        "authorizerId": body.get("authorizerId").cloned().unwrap_or(Value::Null),
        "authorizationScopes": body.get("authorizationScopes").cloned().unwrap_or(json!([])),
        "apiKeyRequired": body.get("apiKeyRequired").and_then(Value::as_bool).unwrap_or(false),
        "requestParameters": body.get("requestParameters").cloned().unwrap_or(json!({})),
        "requestModels": body.get("requestModels").cloned().unwrap_or(json!({})),
        "requestValidatorId": body.get("requestValidatorId").cloned().unwrap_or(Value::Null),
        "operationName": body.get("operationName").cloned().unwrap_or(Value::Null),
    });
    resource
        .get_mut("resourceMethods")
        .and_then(Value::as_object_mut)
        .unwrap()
        .insert(http_method.to_string(), method.clone());
    Ok((201, method))
}

pub async fn get_method(ctx: &Ctx<'_>, api_id: &str, resource_id: &str, http_method: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let guard = r.read().await;
    guard
        .resources
        .get(resource_id)
        .and_then(|res| res.get("resourceMethods"))
        .and_then(|m| m.get(http_method))
        .cloned()
        .map(|v| (200, v))
        .ok_or_else(|| ApiGwError::NotFound("Invalid method identifier specified".into()))
}

pub async fn delete_method(
    ctx: &Ctx<'_>,
    api_id: &str,
    resource_id: &str,
    http_method: &str,
) -> Out {
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    let methods = guard
        .resources
        .get_mut(resource_id)
        .and_then(|resource| resource.get_mut("resourceMethods"))
        .and_then(Value::as_object_mut)
        .ok_or_else(method_not_found)?;
    if methods.remove(http_method).is_none() {
        return Err(method_not_found());
    }
    Ok((204, Value::Null))
}

pub async fn put_integration(
    ctx: &Ctx<'_>,
    api_id: &str,
    resource_id: &str,
    http_method: &str,
    body: &Value,
) -> Out {
    let integration_type = req_str(body, "type")?.to_string();
    if !matches!(
        integration_type.as_str(),
        "AWS_PROXY" | "AWS" | "HTTP" | "HTTP_PROXY" | "MOCK"
    ) {
        return Err(ApiGwError::BadRequest(format!(
            "Invalid integration type specified: {integration_type}"
        )));
    }
    if integration_type != "MOCK" && body.get("uri").and_then(Value::as_str).is_none() {
        return Err(ApiGwError::BadRequest(
            "Integration uri is required for non-MOCK integrations".into(),
        ));
    }
    let integration_http_method = body
        .get("integrationHttpMethod")
        .or_else(|| body.get("httpMethod"))
        .and_then(Value::as_str);
    if integration_type != "MOCK" && integration_http_method.is_none() {
        return Err(ApiGwError::BadRequest(
            "integrationHttpMethod is required for non-MOCK integrations".into(),
        ));
    }
    if let Some(timeout) = body.get("timeoutInMillis") {
        let timeout = timeout
            .as_u64()
            .ok_or_else(|| ApiGwError::BadRequest("timeoutInMillis must be an integer".into()))?;
        if !(50..=29_000).contains(&timeout) {
            return Err(ApiGwError::BadRequest(
                "timeoutInMillis must be between 50 and 29000".into(),
            ));
        }
    }
    for key in [
        "requestTemplates",
        "requestParameters",
        "cacheKeyParameters",
    ] {
        if let Some(value) = body.get(key) {
            let valid = if key == "cacheKeyParameters" {
                value.is_array()
            } else {
                value.is_object()
            };
            if !valid {
                return Err(ApiGwError::BadRequest(format!("{key} has an invalid type")));
            }
        }
    }
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    let resource = guard.resources.get_mut(resource_id).ok_or_else(|| {
        ApiGwError::NotFound(format!(
            "Invalid resource identifier specified: {resource_id}"
        ))
    })?;
    let integration = json!({
        "type": integration_type,
        "httpMethod": integration_http_method.map(Value::from).unwrap_or(Value::Null),
        "uri": body.get("uri").cloned().unwrap_or(Value::Null),
        "credentials": body.get("credentials").cloned().unwrap_or(Value::Null),
        "cacheNamespace": body.get("cacheNamespace").cloned().unwrap_or(Value::Null),
        "cacheKeyParameters": body.get("cacheKeyParameters").cloned().unwrap_or(json!([])),
        "passthroughBehavior": body.get("passthroughBehavior").and_then(Value::as_str).unwrap_or("WHEN_NO_MATCH"),
        "contentHandling": body.get("contentHandling").cloned().unwrap_or(Value::Null),
        "timeoutInMillis": body.get("timeoutInMillis").and_then(Value::as_i64).unwrap_or(29000),
        "tlsConfig": body.get("tlsConfig").cloned().unwrap_or(Value::Null),
        "requestParameters": body.get("requestParameters").cloned().unwrap_or(json!({})),
        "requestTemplates": body.get("requestTemplates").cloned().unwrap_or(json!({})),
        "integrationResponses": json!({}),
    });
    let updated = with_method(resource, http_method, |m| {
        if let Some(obj) = m.as_object_mut() {
            obj.insert("methodIntegration".to_string(), integration.clone());
        }
    });
    if updated.is_none() {
        return Err(ApiGwError::NotFound(
            "Invalid method identifier specified".into(),
        ));
    }
    Ok((201, integration))
}

pub async fn get_integration(
    ctx: &Ctx<'_>,
    api_id: &str,
    resource_id: &str,
    http_method: &str,
) -> Out {
    let r = rest(ctx, api_id).await?;
    let guard = r.read().await;
    guard
        .resources
        .get(resource_id)
        .and_then(|res| res.get("resourceMethods"))
        .and_then(|m| m.get(http_method))
        .and_then(|method| method.get("methodIntegration"))
        .cloned()
        .map(|v| (200, v))
        .ok_or_else(|| ApiGwError::NotFound("Invalid integration identifier specified".into()))
}

fn method_not_found() -> ApiGwError {
    ApiGwError::NotFound("Invalid method identifier specified".into())
}

fn validate_status_code(status_code: &str) -> Result<(), ApiGwError> {
    let status = status_code
        .parse::<u16>()
        .map_err(|_| ApiGwError::BadRequest("statusCode must be an integer".into()))?;
    if !(100..=599).contains(&status) {
        return Err(ApiGwError::BadRequest(
            "statusCode must be between 100 and 599".into(),
        ));
    }
    Ok(())
}

fn validate_response_parameters(
    body: &Value,
    field: &str,
    prefix: &str,
    validate_values: bool,
) -> Result<(), ApiGwError> {
    let parameters = optional_object(body, field)?;
    for (target, value) in parameters.as_object().into_iter().flatten() {
        let name = target.strip_prefix(prefix).ok_or_else(|| {
            ApiGwError::BadRequest(format!("Invalid response header target: {target}"))
        })?;
        HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ApiGwError::BadRequest(format!("Invalid response header: {name}")))?;
        if validate_values {
            let value = value.as_str().ok_or_else(|| {
                ApiGwError::BadRequest("Response header value must be a string".into())
            })?;
            HeaderValue::from_str(value.trim_matches('\''))
                .map_err(|_| ApiGwError::BadRequest("Invalid response header value".into()))?;
        }
    }
    Ok(())
}

pub async fn put_method_response(
    ctx: &Ctx<'_>,
    api_id: &str,
    resource_id: &str,
    http_method: &str,
    status_code: &str,
    body: &Value,
) -> Out {
    validate_status_code(status_code)?;
    validate_response_parameters(body, "responseParameters", "method.response.header.", false)?;
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    let method = guard
        .resources
        .get_mut(resource_id)
        .and_then(|res| res.get_mut("resourceMethods"))
        .and_then(|m| m.as_object_mut())
        .and_then(|m| m.get_mut(http_method))
        .ok_or_else(method_not_found)?;
    let response = json!({
        "statusCode": status_code,
        "responseParameters": body.get("responseParameters").cloned().unwrap_or(json!({})),
        "responseModels": body.get("responseModels").cloned().unwrap_or(json!({})),
    });
    method
        .as_object_mut()
        .unwrap()
        .entry("methodResponses")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .unwrap()
        .insert(status_code.to_string(), response.clone());
    Ok((201, response))
}

pub async fn get_method_response(
    ctx: &Ctx<'_>,
    api_id: &str,
    resource_id: &str,
    http_method: &str,
    status_code: &str,
) -> Out {
    let r = rest(ctx, api_id).await?;
    let guard = r.read().await;
    guard
        .resources
        .get(resource_id)
        .and_then(|res| res.get("resourceMethods"))
        .and_then(|m| m.get(http_method))
        .and_then(|method| method.get("methodResponses"))
        .and_then(|mr| mr.get(status_code))
        .cloned()
        .map(|v| (200, v))
        .ok_or_else(|| {
            ApiGwError::NotFound(format!(
                "Invalid method response identifier specified: {status_code}"
            ))
        })
}

pub async fn put_integration_response(
    ctx: &Ctx<'_>,
    api_id: &str,
    resource_id: &str,
    http_method: &str,
    status_code: &str,
    body: &Value,
) -> Out {
    validate_status_code(status_code)?;
    validate_response_parameters(body, "responseParameters", "method.response.header.", false)?;
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    let integration = guard
        .resources
        .get_mut(resource_id)
        .and_then(|res| res.get_mut("resourceMethods"))
        .and_then(|m| m.as_object_mut())
        .and_then(|m| m.get_mut(http_method))
        .and_then(|method| method.get_mut("methodIntegration"))
        .ok_or_else(|| ApiGwError::NotFound("Invalid integration identifier specified".into()))?;
    let response = json!({
        "statusCode": status_code,
        "selectionPattern": body.get("selectionPattern").cloned().unwrap_or(Value::Null),
        "responseParameters": body.get("responseParameters").cloned().unwrap_or(json!({})),
        "responseTemplates": body.get("responseTemplates").cloned().unwrap_or(json!({})),
    });
    integration
        .as_object_mut()
        .unwrap()
        .entry("integrationResponses")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .unwrap()
        .insert(status_code.to_string(), response.clone());
    Ok((201, response))
}

pub async fn get_integration_response(
    ctx: &Ctx<'_>,
    api_id: &str,
    resource_id: &str,
    http_method: &str,
    status_code: &str,
) -> Out {
    let r = rest(ctx, api_id).await?;
    let guard = r.read().await;
    guard
        .resources
        .get(resource_id)
        .and_then(|res| res.get("resourceMethods"))
        .and_then(|m| m.get(http_method))
        .and_then(|method| method.get("methodIntegration"))
        .and_then(|integration| integration.get("integrationResponses"))
        .and_then(|ir| ir.get(status_code))
        .cloned()
        .map(|v| (200, v))
        .ok_or_else(|| {
            ApiGwError::NotFound(format!(
                "Invalid integration response identifier specified: {status_code}"
            ))
        })
}

// ============================ Deployments & stages =============================

pub async fn create_deployment(ctx: &Ctx<'_>, api_id: &str, body: &Value) -> Out {
    let id = gen_id();
    let deployment = json!({
        "id": id,
        "description": body.get("description").cloned().unwrap_or(Value::Null),
        "createdDate": now_epoch(),
    });
    let stage_candidate = match body.get("stageName") {
        Some(value) => {
            let stage_name = value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    ApiGwError::BadRequest("stageName must be a non-empty string".into())
                })?;
            let stage_description = match body.get("stageDescription") {
                Some(value) if value.is_object() => value.clone(),
                Some(_) => {
                    return Err(ApiGwError::BadRequest(
                        "stageDescription must be an object".into(),
                    ))
                }
                None => json!({}),
            };
            let stage = stage_value(stage_name, &id, &stage_description);
            let logging = rest_stage_logging(&stage, ctx.account, ctx.region, api_id, stage_name)?;
            preflight(
                ctx.registry,
                ctx.account,
                ctx.region,
                ctx.request_id,
                &logging,
            )
            .await?;
            Some((stage_name.to_string(), stage))
        }
        None => None,
    };

    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    let snapshot = guard.snapshot();
    guard.deployments.insert(id.clone(), deployment.clone());
    guard.deployment_snapshots.insert(id.clone(), snapshot);
    if let Some((stage_name, stage)) = stage_candidate {
        guard.stages.insert(stage_name, stage);
    }
    Ok((201, deployment))
}

pub async fn get_deployment(ctx: &Ctx<'_>, api_id: &str, deployment_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let guard = r.read().await;
    guard
        .deployments
        .get(deployment_id)
        .cloned()
        .map(|v| (200, v))
        .ok_or_else(|| {
            ApiGwError::NotFound(format!(
                "Invalid deployment identifier specified: {deployment_id}"
            ))
        })
}

pub async fn get_deployments(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let items: Vec<Value> = r.read().await.deployments.values().cloned().collect();
    Ok((200, json!({ "item": items })))
}

fn stage_value(name: &str, deployment_id: &str, body: &Value) -> Value {
    let mut stage = json!({
        "stageName": name,
        "deploymentId": deployment_id,
        "description": body.get("description").cloned().unwrap_or(Value::Null),
        "createdDate": now_epoch(),
        "variables": body.get("variables").cloned().unwrap_or(json!({})),
        "methodSettings": body.get("methodSettings").cloned().unwrap_or(json!({})),
    });
    if let Some(settings) = body.get("accessLogSettings") {
        stage["accessLogSettings"] = settings.clone();
    }
    stage
}

pub async fn create_stage(ctx: &Ctx<'_>, api_id: &str, body: &Value) -> Out {
    let stage_name = req_str(body, "stageName")?;
    let deployment_id = req_str(body, "deploymentId")?;
    let stage = stage_value(stage_name, deployment_id, body);
    let logging = rest_stage_logging(&stage, ctx.account, ctx.region, api_id, stage_name)?;
    let r = rest(ctx, api_id).await?;
    {
        let guard = r.read().await;
        if guard.stages.contains_key(stage_name) {
            return Err(ApiGwError::Conflict(format!(
                "Stage already exists: {stage_name}"
            )));
        }
        if !guard.deployments.contains_key(deployment_id) {
            return Err(ApiGwError::NotFound(format!(
                "Invalid deployment identifier specified: {deployment_id}"
            )));
        }
    }
    preflight(
        ctx.registry,
        ctx.account,
        ctx.region,
        ctx.request_id,
        &logging,
    )
    .await?;
    let mut guard = r.write().await;
    if guard.stages.contains_key(stage_name) {
        return Err(ApiGwError::Conflict(format!(
            "Stage already exists: {stage_name}"
        )));
    }
    if !guard.deployments.contains_key(deployment_id) {
        return Err(ApiGwError::NotFound(format!(
            "Invalid deployment identifier specified: {deployment_id}"
        )));
    }
    guard.stages.insert(stage_name.to_string(), stage.clone());
    Ok((201, stage))
}

pub async fn get_stage(ctx: &Ctx<'_>, api_id: &str, stage_name: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let guard = r.read().await;
    guard
        .stages
        .get(stage_name)
        .cloned()
        .map(|v| (200, v))
        .ok_or_else(|| {
            ApiGwError::NotFound(format!("Invalid stage identifier specified: {stage_name}"))
        })
}

// ============================ Authorizers ======================================

fn validate_authorizer(value: &Value) -> Result<(), ApiGwError> {
    let authorizer_type = req_str(value, "type")?;
    if !matches!(authorizer_type, "TOKEN" | "REQUEST") {
        return Err(ApiGwError::BadRequest(format!(
            "Invalid authorizer type specified: {authorizer_type}"
        )));
    }
    req_str(value, "name")?;
    req_str(value, "authorizerUri")?;
    req_str(value, "identitySource")?;
    Ok(())
}

fn authorizer_value(id: &str, body: &Value) -> Result<Value, ApiGwError> {
    let value = json!({
        "id": id,
        "name": req_str(body, "name")?,
        "type": req_str(body, "type")?,
        "providerARNs": body.get("providerARNs").cloned().unwrap_or(json!([])),
        "authType": body.get("authType").cloned().unwrap_or(Value::Null),
        "authorizerUri": req_str(body, "authorizerUri")?,
        "authorizerCredentials": body.get("authorizerCredentials").cloned().unwrap_or(Value::Null),
        "identitySource": req_str(body, "identitySource")?,
        "identityValidationExpression": body.get("identityValidationExpression").cloned().unwrap_or(Value::Null),
        "authorizerResultTtlInSeconds": body.get("authorizerResultTtlInSeconds").and_then(Value::as_i64).unwrap_or(300),
    });
    validate_authorizer(&value)?;
    Ok(value)
}

pub async fn create_authorizer(ctx: &Ctx<'_>, api_id: &str, body: &Value) -> Out {
    let id = gen_id();
    let authorizer = authorizer_value(&id, body)?;
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    if guard.authorizers.values().any(|value| {
        value.get("name").and_then(Value::as_str) == authorizer.get("name").and_then(Value::as_str)
    }) {
        return Err(ApiGwError::Conflict(
            "Authorizer name already exists".into(),
        ));
    }
    guard.authorizers.insert(id, authorizer.clone());
    Ok((201, authorizer))
}

pub async fn get_authorizer(ctx: &Ctx<'_>, api_id: &str, authorizer_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let guard = r.read().await;
    guard
        .authorizers
        .get(authorizer_id)
        .cloned()
        .map(|value| (200, value))
        .ok_or_else(|| ApiGwError::NotFound("Invalid authorizer identifier specified".into()))
}

pub async fn get_authorizers(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let item = r
        .read()
        .await
        .authorizers
        .values()
        .cloned()
        .collect::<Vec<_>>();
    Ok((200, json!({ "item": item })))
}

pub async fn update_authorizer(
    ctx: &Ctx<'_>,
    api_id: &str,
    authorizer_id: &str,
    body: &Value,
) -> Out {
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    let current = guard
        .authorizers
        .get(authorizer_id)
        .cloned()
        .ok_or_else(|| ApiGwError::NotFound("Invalid authorizer identifier specified".into()))?;
    let mut updated = current;
    apply_patch_operations(&mut updated, body, |path| {
        matches!(
            path,
            "/name"
                | "/type"
                | "/authorizerUri"
                | "/authorizerCredentials"
                | "/identitySource"
                | "/identityValidationExpression"
                | "/authorizerResultTtlInSeconds"
                | "/providerARNs"
                | "/authType"
        )
    })?;
    validate_authorizer(&updated)?;
    guard
        .authorizers
        .insert(authorizer_id.to_string(), updated.clone());
    Ok((200, updated))
}

pub async fn delete_authorizer(ctx: &Ctx<'_>, api_id: &str, authorizer_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    if r.write().await.authorizers.remove(authorizer_id).is_none() {
        return Err(ApiGwError::NotFound(
            "Invalid authorizer identifier specified".into(),
        ));
    }
    Ok((202, json!({})))
}

// ============================ Models ===========================================

fn compile_model_schema(schema: &str) -> Result<(), ApiGwError> {
    let parsed: Value = serde_json::from_str(schema)
        .map_err(|error| ApiGwError::BadRequest(format!("Invalid model schema: {error}")))?;
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .build(&parsed)
        .map_err(|error| ApiGwError::BadRequest(format!("Invalid model schema: {error}")))?;
    Ok(())
}

fn model_value(body: &Value) -> Result<Value, ApiGwError> {
    let schema = req_str(body, "schema")?;
    compile_model_schema(schema)?;
    Ok(json!({
        "id": gen_id(),
        "name": req_str(body, "name")?,
        "description": body.get("description").cloned().unwrap_or(Value::Null),
        "schema": schema,
        "contentType": req_str(body, "contentType")?,
    }))
}

pub async fn create_model(ctx: &Ctx<'_>, api_id: &str, body: &Value) -> Out {
    let model = model_value(body)?;
    let name = model
        .get("name")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    if guard.models.contains_key(&name) {
        return Err(ApiGwError::Conflict(format!(
            "Model already exists: {name}"
        )));
    }
    guard.models.insert(name, model.clone());
    Ok((201, model))
}

pub async fn get_model(ctx: &Ctx<'_>, api_id: &str, model_name: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let guard = r.read().await;
    guard
        .models
        .get(model_name)
        .cloned()
        .map(|value| (200, value))
        .ok_or_else(|| ApiGwError::NotFound(format!("Invalid model specified: {model_name}")))
}

pub async fn get_models(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let item = r.read().await.models.values().cloned().collect::<Vec<_>>();
    Ok((200, json!({ "item": item })))
}

pub async fn update_model(ctx: &Ctx<'_>, api_id: &str, model_name: &str, body: &Value) -> Out {
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    let mut updated =
        guard.models.get(model_name).cloned().ok_or_else(|| {
            ApiGwError::NotFound(format!("Invalid model specified: {model_name}"))
        })?;
    apply_patch_operations(&mut updated, body, |path| {
        matches!(path, "/description" | "/schema" | "/contentType")
    })?;
    compile_model_schema(req_str(&updated, "schema")?)?;
    guard.models.insert(model_name.to_string(), updated.clone());
    Ok((200, updated))
}

pub async fn delete_model(ctx: &Ctx<'_>, api_id: &str, model_name: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    if r.write().await.models.remove(model_name).is_none() {
        return Err(ApiGwError::NotFound(format!(
            "Invalid model specified: {model_name}"
        )));
    }
    Ok((202, json!({})))
}

// ============================ Request validators ===============================

fn request_validator_value(id: &str, body: &Value) -> Result<Value, ApiGwError> {
    Ok(json!({
        "id": id,
        "name": req_str(body, "name")?,
        "validateRequestBody": body.get("validateRequestBody").and_then(Value::as_bool).unwrap_or(false),
        "validateRequestParameters": body.get("validateRequestParameters").and_then(Value::as_bool).unwrap_or(false),
    }))
}

pub async fn create_request_validator(ctx: &Ctx<'_>, api_id: &str, body: &Value) -> Out {
    let id = gen_id();
    let validator = request_validator_value(&id, body)?;
    let r = rest(ctx, api_id).await?;
    r.write()
        .await
        .request_validators
        .insert(id, validator.clone());
    Ok((201, validator))
}

pub async fn get_request_validator(ctx: &Ctx<'_>, api_id: &str, validator_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let guard = r.read().await;
    guard
        .request_validators
        .get(validator_id)
        .cloned()
        .map(|value| (200, value))
        .ok_or_else(|| {
            ApiGwError::NotFound("Invalid request validator identifier specified".into())
        })
}

pub async fn get_request_validators(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let item = r
        .read()
        .await
        .request_validators
        .values()
        .cloned()
        .collect::<Vec<_>>();
    Ok((200, json!({ "item": item })))
}

pub async fn update_request_validator(
    ctx: &Ctx<'_>,
    api_id: &str,
    validator_id: &str,
    body: &Value,
) -> Out {
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    let mut updated = guard
        .request_validators
        .get(validator_id)
        .cloned()
        .ok_or_else(|| {
            ApiGwError::NotFound("Invalid request validator identifier specified".into())
        })?;
    apply_patch_operations(&mut updated, body, |path| {
        matches!(
            path,
            "/name" | "/validateRequestBody" | "/validateRequestParameters"
        )
    })?;
    req_str(&updated, "name")?;
    guard
        .request_validators
        .insert(validator_id.to_string(), updated.clone());
    Ok((200, updated))
}

pub async fn delete_request_validator(ctx: &Ctx<'_>, api_id: &str, validator_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    if r.write()
        .await
        .request_validators
        .remove(validator_id)
        .is_none()
    {
        return Err(ApiGwError::NotFound(
            "Invalid request validator identifier specified".into(),
        ));
    }
    Ok((202, json!({})))
}

// ============================ Remaining deployments & stages ==================

pub async fn delete_deployment(ctx: &Ctx<'_>, api_id: &str, deployment_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let mut guard = r.write().await;
    if guard.deployments.remove(deployment_id).is_none() {
        return Err(ApiGwError::NotFound(format!(
            "Invalid deployment identifier specified: {deployment_id}"
        )));
    }
    guard.deployment_snapshots.remove(deployment_id);
    Ok((202, json!({})))
}

pub async fn get_stages(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let item = r.read().await.stages.values().cloned().collect::<Vec<_>>();
    Ok((200, json!({ "item": item })))
}

fn normalized_stage_patch(stage: &mut Value, body: &Value) -> Result<Value, ApiGwError> {
    let mut body = body.clone();
    let operations = body
        .get_mut("patchOperations")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| ApiGwError::BadRequest("patchOperations is required".into()))?;
    for operation in &mut *operations {
        let path = operation
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiGwError::BadRequest("path is required".into()))?;
        let normalized = match path {
            "/*/*/logging/loglevel" => Some("/methodSettings/*~1*/loggingLevel"),
            "/*/*/logging/dataTrace" => Some("/methodSettings/*~1*/dataTraceEnabled"),
            "/*/*/metrics/enabled" => Some("/methodSettings/*~1*/metricsEnabled"),
            "/*/*/throttling/burstLimit" => Some("/methodSettings/*~1*/throttlingBurstLimit"),
            "/*/*/throttling/rateLimit" => Some("/methodSettings/*~1*/throttlingRateLimit"),
            "/*/*/caching/enabled" => Some("/methodSettings/*~1*/cachingEnabled"),
            "/*/*/caching/ttlInSeconds" => Some("/methodSettings/*~1*/cacheTtlInSeconds"),
            "/*/*/caching/dataEncrypted" => Some("/methodSettings/*~1*/cacheDataEncrypted"),
            "/*/*/caching/requireAuthorizationForCacheControl" => {
                Some("/methodSettings/*~1*/requireAuthorizationForCacheControl")
            }
            "/*/*/caching/unauthorizedCacheControlHeaderStrategy" => {
                Some("/methodSettings/*~1*/unauthorizedCacheControlHeaderStrategy")
            }
            _ => None,
        };
        if let Some(normalized) = normalized {
            operation["path"] = json!(normalized);
        }
    }
    let paths = operations
        .iter()
        .filter_map(|operation| operation.get("path").and_then(Value::as_str))
        .collect::<Vec<_>>();
    if paths
        .iter()
        .any(|path| path.starts_with("/accessLogSettings/"))
        && stage.get("accessLogSettings").is_none()
    {
        stage["accessLogSettings"] = json!({});
    }
    if paths
        .iter()
        .any(|path| path.starts_with("/methodSettings/*~1*/"))
    {
        if !stage.get("methodSettings").is_some_and(Value::is_object) {
            stage["methodSettings"] = json!({});
        }
        if stage["methodSettings"].get("*/*").is_none() {
            stage["methodSettings"]["*/*"] = json!({});
        }
    }
    Ok(body)
}

pub async fn update_stage(ctx: &Ctx<'_>, api_id: &str, stage_name: &str, body: &Value) -> Out {
    let r = rest(ctx, api_id).await?;
    let mut updated = {
        let guard = r.read().await;
        guard.stages.get(stage_name).cloned().ok_or_else(|| {
            ApiGwError::NotFound(format!("Invalid stage identifier specified: {stage_name}"))
        })?
    };
    let body = normalized_stage_patch(&mut updated, body)?;
    apply_patch_operations(&mut updated, &body, |path| {
        matches!(
            path,
            "/deploymentId"
                | "/description"
                | "/cacheClusterEnabled"
                | "/cacheClusterSize"
                | "/tracingEnabled"
                | "/documentationVersion"
                | "/accessLogSettings"
                | "/methodSettings"
        ) || path.starts_with("/variables/")
            || path.starts_with("/accessLogSettings/")
            || path.starts_with("/methodSettings/")
    })?;
    let logging = rest_stage_logging(&updated, ctx.account, ctx.region, api_id, stage_name)?;
    {
        let guard = r.read().await;
        if let Some(deployment_id) = updated.get("deploymentId").and_then(Value::as_str) {
            if !guard.deployments.contains_key(deployment_id) {
                return Err(ApiGwError::NotFound(format!(
                    "Invalid deployment identifier specified: {deployment_id}"
                )));
            }
        }
    }
    preflight(
        ctx.registry,
        ctx.account,
        ctx.region,
        ctx.request_id,
        &logging,
    )
    .await?;
    let mut guard = r.write().await;
    if !guard.stages.contains_key(stage_name) {
        return Err(ApiGwError::NotFound(format!(
            "Invalid stage identifier specified: {stage_name}"
        )));
    }
    if let Some(deployment_id) = updated.get("deploymentId").and_then(Value::as_str) {
        if !guard.deployments.contains_key(deployment_id) {
            return Err(ApiGwError::NotFound(format!(
                "Invalid deployment identifier specified: {deployment_id}"
            )));
        }
    }
    guard.stages.insert(stage_name.to_string(), updated.clone());
    Ok((200, updated))
}

pub async fn delete_stage(ctx: &Ctx<'_>, api_id: &str, stage_name: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let mut record = r.write().await;
    if !record.stages.contains_key(stage_name) {
        return Err(ApiGwError::NotFound(format!(
            "Invalid stage identifier specified: {stage_name}"
        )));
    }
    if let Some(binding) = ctx.waf {
        let guard = binding
            .read()
            .map_err(|_| ApiGwError::Internal("WAF evaluator unavailable".into()))?;
        if let Some(evaluator) = guard.as_ref() {
            let evaluator = evaluator
                .upgrade()
                .ok_or_else(|| ApiGwError::Internal("WAF evaluator unavailable".into()))?;
            let arn = format!(
                "arn:aws:apigateway:{}::/restapis/{api_id}/stages/{stage_name}",
                ctx.region
            );
            evaluator
                .detach_stage(ctx.account, ctx.region, &arn)
                .map_err(|_| ApiGwError::Internal("WAF association cleanup failed".into()))?;
        }
    }
    record.stages.remove(stage_name);
    Ok((202, json!({})))
}

// ============================ Gateway responses ================================

const GATEWAY_RESPONSE_DEFAULTS: &[(&str, &str)] = &[
    ("ACCESS_DENIED", "403"),
    ("API_CONFIGURATION_ERROR", "500"),
    ("AUTHORIZER_CONFIGURATION_ERROR", "500"),
    ("AUTHORIZER_FAILURE", "500"),
    ("BAD_REQUEST_BODY", "400"),
    ("BAD_REQUEST_PARAMETERS", "400"),
    ("DEFAULT_4XX", "400"),
    ("DEFAULT_5XX", "500"),
    ("EXPIRED_TOKEN", "403"),
    ("INTEGRATION_FAILURE", "504"),
    ("INTEGRATION_TIMEOUT", "504"),
    ("INVALID_API_KEY", "403"),
    ("INVALID_SIGNATURE", "403"),
    ("MISSING_AUTHENTICATION_TOKEN", "403"),
    ("QUOTA_EXCEEDED", "429"),
    ("REQUEST_TOO_LARGE", "413"),
    ("RESOURCE_NOT_FOUND", "404"),
    ("THROTTLED", "429"),
    ("UNAUTHORIZED", "401"),
    ("UNSUPPORTED_MEDIA_TYPE", "415"),
    ("WAF_FILTERED", "403"),
];

fn default_gateway_response(response_type: &str) -> Option<Value> {
    let status = GATEWAY_RESPONSE_DEFAULTS
        .iter()
        .find_map(|(kind, status)| (*kind == response_type).then_some(*status))?;
    Some(json!({
        "responseType": response_type,
        "statusCode": status,
        "defaultResponse": true,
        "responseParameters": {},
        "responseTemplates": {
            "application/json": "{\"message\":$context.error.messageString}"
        },
    }))
}

pub async fn put_gateway_response(
    ctx: &Ctx<'_>,
    api_id: &str,
    response_type: &str,
    body: &Value,
) -> Out {
    if default_gateway_response(response_type).is_none() {
        return Err(ApiGwError::BadRequest(format!(
            "Invalid gateway response type: {response_type}"
        )));
    }
    let status_code = body
        .get("statusCode")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            GATEWAY_RESPONSE_DEFAULTS
                .iter()
                .find_map(|(kind, status)| (*kind == response_type).then_some(*status))
                .unwrap()
                .to_string()
        });
    validate_status_code(&status_code)?;
    validate_response_parameters(body, "responseParameters", "gatewayresponse.header.", true)?;
    let response = json!({
        "responseType": response_type,
        "statusCode": status_code,
        "defaultResponse": false,
        "responseParameters": optional_object(body, "responseParameters")?,
        "responseTemplates": optional_object(body, "responseTemplates")?,
    });
    let r = rest(ctx, api_id).await?;
    r.write()
        .await
        .gateway_responses
        .insert(response_type.to_string(), response.clone());
    Ok((201, response))
}

pub async fn get_gateway_response(ctx: &Ctx<'_>, api_id: &str, response_type: &str) -> Out {
    let default = default_gateway_response(response_type).ok_or_else(|| {
        ApiGwError::NotFound(format!("Invalid gateway response type: {response_type}"))
    })?;
    let r = rest(ctx, api_id).await?;
    let response = r
        .read()
        .await
        .gateway_responses
        .get(response_type)
        .cloned()
        .unwrap_or(default);
    Ok((200, response))
}

pub async fn get_gateway_responses(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let r = rest(ctx, api_id).await?;
    let guard = r.read().await;
    let item = GATEWAY_RESPONSE_DEFAULTS
        .iter()
        .filter_map(|(response_type, _)| {
            guard
                .gateway_responses
                .get(*response_type)
                .cloned()
                .or_else(|| default_gateway_response(response_type))
        })
        .collect::<Vec<_>>();
    Ok((200, json!({ "item": item })))
}

// ============================ API keys =========================================

fn public_api_key(value: &Value, include_value: bool) -> Value {
    let mut value = value.clone();
    if !include_value {
        value.as_object_mut().unwrap().remove("value");
    }
    value
}

pub async fn create_api_key(ctx: &Ctx<'_>, body: &Value) -> Out {
    if let Some(enabled) = body.get("enabled") {
        if !enabled.is_boolean() {
            return Err(ApiGwError::BadRequest("enabled must be a boolean".into()));
        }
    }
    let id = gen_id();
    let now = now_epoch();
    let api_key = json!({
        "id": id,
        "value": body.get("value").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| format!("{}{}", gen_id(), gen_id())),
        "name": body.get("name").cloned().unwrap_or(Value::Null),
        "customerId": body.get("customerId").cloned().unwrap_or(Value::Null),
        "description": body.get("description").cloned().unwrap_or(Value::Null),
        "enabled": body.get("enabled").and_then(Value::as_bool).unwrap_or(true),
        "createdDate": now,
        "lastUpdatedDate": now,
        "stageKeys": body.get("stageKeys").cloned().unwrap_or(json!([])),
        "tags": body.get("tags").cloned().unwrap_or(json!({})),
    });
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    if let Some(value) = api_key.get("value").and_then(Value::as_str) {
        if guard
            .api_keys
            .values()
            .any(|key| key.get("value").and_then(Value::as_str) == Some(value))
        {
            return Err(ApiGwError::Conflict("API key value already exists".into()));
        }
    }
    guard.api_keys.insert(id, api_key.clone());
    Ok((201, api_key))
}

pub async fn get_api_key(ctx: &Ctx<'_>, api_key_id: &str, include_value: bool) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    guard
        .api_keys
        .get(api_key_id)
        .map(|value| (200, public_api_key(value, include_value)))
        .ok_or_else(|| ApiGwError::NotFound("Invalid API key identifier specified".into()))
}

pub async fn get_api_keys(ctx: &Ctx<'_>, include_values: bool) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let item = shared
        .read()
        .await
        .api_keys
        .values()
        .map(|value| public_api_key(value, include_values))
        .collect::<Vec<_>>();
    Ok((200, json!({ "item": item })))
}

pub async fn update_api_key(ctx: &Ctx<'_>, api_key_id: &str, body: &Value) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    let mut updated = guard
        .api_keys
        .get(api_key_id)
        .cloned()
        .ok_or_else(|| ApiGwError::NotFound("Invalid API key identifier specified".into()))?;
    apply_patch_operations(&mut updated, body, |path| {
        matches!(
            path,
            "/name" | "/description" | "/enabled" | "/customerId" | "/value"
        )
    })?;
    let final_value = updated.get("value").and_then(Value::as_str);
    if guard.api_keys.iter().any(|(id, key)| {
        id != api_key_id && key.get("value").and_then(Value::as_str) == final_value
    }) {
        return Err(ApiGwError::Conflict("API key value already exists".into()));
    }
    updated
        .as_object_mut()
        .unwrap()
        .insert("lastUpdatedDate".into(), json!(now_epoch()));
    guard
        .api_keys
        .insert(api_key_id.to_string(), updated.clone());
    Ok((200, updated))
}

pub async fn delete_api_key(ctx: &Ctx<'_>, api_key_id: &str) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    if guard.api_keys.remove(api_key_id).is_none() {
        return Err(ApiGwError::NotFound(
            "Invalid API key identifier specified".into(),
        ));
    }
    for plan in guard.usage_plans.values_mut() {
        if let Some(keys) = plan.get_mut("__keys").and_then(Value::as_object_mut) {
            keys.remove(api_key_id);
        }
    }
    Ok((202, json!({})))
}

// ============================ Usage plans ======================================

fn public_usage_plan(value: &Value) -> Value {
    let mut value = value.clone();
    value.as_object_mut().unwrap().remove("__keys");
    value
}

pub async fn create_usage_plan(ctx: &Ctx<'_>, body: &Value) -> Out {
    let name = req_str(body, "name")?;
    let id = gen_id();
    let plan = json!({
        "id": id,
        "name": name,
        "description": body.get("description").cloned().unwrap_or(Value::Null),
        "apiStages": body.get("apiStages").cloned().unwrap_or(json!([])),
        "throttle": body.get("throttle").cloned().unwrap_or(json!({})),
        "quota": body.get("quota").cloned().unwrap_or(json!({})),
        "productCode": body.get("productCode").cloned().unwrap_or(Value::Null),
        "tags": body.get("tags").cloned().unwrap_or(json!({})),
        "__keys": {},
    });
    let shared = ctx.store.shared(ctx.account, ctx.region);
    shared.write().await.usage_plans.insert(id, plan.clone());
    Ok((201, public_usage_plan(&plan)))
}

pub async fn get_usage_plan(ctx: &Ctx<'_>, usage_plan_id: &str) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    guard
        .usage_plans
        .get(usage_plan_id)
        .map(|value| (200, public_usage_plan(value)))
        .ok_or_else(|| ApiGwError::NotFound("Invalid usage plan identifier specified".into()))
}

pub async fn get_usage_plans(ctx: &Ctx<'_>) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let item = shared
        .read()
        .await
        .usage_plans
        .values()
        .map(public_usage_plan)
        .collect::<Vec<_>>();
    Ok((200, json!({ "item": item })))
}

pub async fn update_usage_plan(ctx: &Ctx<'_>, usage_plan_id: &str, body: &Value) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    let mut updated = guard
        .usage_plans
        .get(usage_plan_id)
        .cloned()
        .ok_or_else(|| ApiGwError::NotFound("Invalid usage plan identifier specified".into()))?;
    apply_patch_operations(&mut updated, body, |path| {
        matches!(path, "/name" | "/description" | "/productCode")
            || path.starts_with("/apiStages/")
            || path.starts_with("/throttle/")
            || path.starts_with("/quota/")
    })?;
    req_str(&updated, "name")?;
    guard
        .usage_plans
        .insert(usage_plan_id.to_string(), updated.clone());
    Ok((200, public_usage_plan(&updated)))
}

pub async fn delete_usage_plan(ctx: &Ctx<'_>, usage_plan_id: &str) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    if shared
        .write()
        .await
        .usage_plans
        .remove(usage_plan_id)
        .is_none()
    {
        return Err(ApiGwError::NotFound(
            "Invalid usage plan identifier specified".into(),
        ));
    }
    Ok((202, json!({})))
}

fn usage_plan_key(value: &Value) -> Value {
    json!({
        "id": value.get("id").cloned().unwrap_or(Value::Null),
        "type": "API_KEY",
        "name": value.get("name").cloned().unwrap_or(Value::Null),
        "value": value.get("value").cloned().unwrap_or(Value::Null),
    })
}

pub async fn create_usage_plan_key(ctx: &Ctx<'_>, usage_plan_id: &str, body: &Value) -> Out {
    let key_id = req_str(body, "keyId")?;
    let key_type = req_str(body, "keyType")?;
    if key_type != "API_KEY" {
        return Err(ApiGwError::BadRequest(format!(
            "Invalid usage plan key type: {key_type}"
        )));
    }
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    let key = guard
        .api_keys
        .get(key_id)
        .cloned()
        .ok_or_else(|| ApiGwError::NotFound("Invalid API key identifier specified".into()))?;
    let plan = guard
        .usage_plans
        .get_mut(usage_plan_id)
        .ok_or_else(|| ApiGwError::NotFound("Invalid usage plan identifier specified".into()))?;
    let association = usage_plan_key(&key);
    plan.get_mut("__keys")
        .and_then(Value::as_object_mut)
        .unwrap()
        .insert(key_id.to_string(), association.clone());
    Ok((201, association))
}

pub async fn get_usage_plan_key(ctx: &Ctx<'_>, usage_plan_id: &str, key_id: &str) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    guard
        .usage_plans
        .get(usage_plan_id)
        .ok_or_else(|| ApiGwError::NotFound("Invalid usage plan identifier specified".into()))?
        .get("__keys")
        .and_then(|keys| keys.get(key_id))
        .cloned()
        .map(|value| (200, value))
        .ok_or_else(|| ApiGwError::NotFound("Invalid usage plan key identifier specified".into()))
}

pub async fn get_usage_plan_keys(ctx: &Ctx<'_>, usage_plan_id: &str) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    let plan = guard
        .usage_plans
        .get(usage_plan_id)
        .ok_or_else(|| ApiGwError::NotFound("Invalid usage plan identifier specified".into()))?;
    let item = plan
        .get("__keys")
        .and_then(Value::as_object)
        .unwrap()
        .values()
        .cloned()
        .collect::<Vec<_>>();
    Ok((200, json!({ "item": item })))
}

pub async fn delete_usage_plan_key(ctx: &Ctx<'_>, usage_plan_id: &str, key_id: &str) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    let plan = guard
        .usage_plans
        .get_mut(usage_plan_id)
        .ok_or_else(|| ApiGwError::NotFound("Invalid usage plan identifier specified".into()))?;
    if plan
        .get_mut("__keys")
        .and_then(Value::as_object_mut)
        .and_then(|keys| keys.remove(key_id))
        .is_none()
    {
        return Err(ApiGwError::NotFound(
            "Invalid usage plan key identifier specified".into(),
        ));
    }
    Ok((202, json!({})))
}

// ============================ Domains & base-path mappings =====================

fn public_domain(value: &Value) -> Value {
    let mut value = value.clone();
    let object = value.as_object_mut().unwrap();
    object.remove("__basePathMappings");
    object.remove("__apiMappings");
    value
}

fn private_domain_requested(value: &Value) -> bool {
    value
        .get("endpointConfiguration")
        .and_then(|config| config.get("types"))
        .and_then(Value::as_array)
        .is_some_and(|types| types.iter().any(|kind| kind.as_str() == Some("PRIVATE")))
}

fn validate_private_config(value: &Value) -> Result<(), ApiGwError> {
    let config = value.get("endpointConfiguration").unwrap_or(&Value::Null);
    if config
        .get("types")
        .and_then(Value::as_array)
        .is_none_or(|types| types.len() != 1 || types[0].as_str() != Some("PRIVATE"))
    {
        return Err(ApiGwError::BadRequest(
            "PRIVATE must be the sole endpoint type".into(),
        ));
    }
    if config
        .get("ipAddressType")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind != "dualstack")
    {
        return Err(ApiGwError::BadRequest(
            "PRIVATE endpoint ipAddressType must be dualstack".into(),
        ));
    }
    if let Some(mode) = value.get("routingMode") {
        if !matches!(
            mode.as_str(),
            Some(
                "BASE_PATH_MAPPING_ONLY"
                    | "ROUTING_RULE_ONLY"
                    | "ROUTING_RULE_THEN_BASE_PATH_MAPPING"
            )
        ) {
            return Err(ApiGwError::BadRequest("Invalid routingMode".into()));
        }
    }
    for field in ["policy", "managementPolicy"] {
        if let Some(value) = value.get(field) {
            let policy = value
                .as_str()
                .ok_or_else(|| ApiGwError::BadRequest(format!("{field} must be a JSON string")))?;
            let parsed: Value = serde_json::from_str(policy)
                .map_err(|_| ApiGwError::BadRequest(format!("{field} must contain valid JSON")))?;
            if !parsed.is_object() {
                return Err(ApiGwError::BadRequest(format!(
                    "{field} must contain a JSON object"
                )));
            }
        }
    }
    Ok(())
}

fn domain_ref<'a>(
    shared: &'a crate::store::SharedRecord,
    name: &str,
    domain_id: Option<&str>,
) -> Result<&'a Value, ApiGwError> {
    if let Some(id) = domain_id {
        if let Some(domain) = shared.private_domains.get(id) {
            if domain.get("domainName").and_then(Value::as_str) == Some(name) {
                return Ok(domain);
            }
        }
        return Err(ApiGwError::NotFound(format!(
            "Invalid domain name or domainNameId: {name}"
        )));
    }
    if let Some(domain) = shared.domains.get(name) {
        return Ok(domain);
    }
    if shared
        .private_domains
        .values()
        .any(|domain| domain.get("domainName").and_then(Value::as_str) == Some(name))
    {
        return Err(ApiGwError::BadRequest(
            "domainNameId is required for a PRIVATE custom domain".into(),
        ));
    }
    Err(ApiGwError::NotFound(format!("Invalid domain name: {name}")))
}

fn domain_mut<'a>(
    shared: &'a mut crate::store::SharedRecord,
    name: &str,
    domain_id: Option<&str>,
) -> Result<&'a mut Value, ApiGwError> {
    domain_ref(shared, name, domain_id)?;
    match domain_id {
        Some(id) => Ok(shared.private_domains.get_mut(id).unwrap()),
        None => Ok(shared.domains.get_mut(name).unwrap()),
    }
}

pub async fn create_domain_name(ctx: &Ctx<'_>, body: &Value) -> Out {
    let domain_name = req_str(body, "domainName")?;
    let private = private_domain_requested(body);
    if private {
        validate_private_config(body)?;
    }
    let domain_id = if private {
        Some(gen_id()[..8].to_string())
    } else {
        None
    };
    let mut domain = json!({
        "domainName": domain_name,
        "certificateName": body.get("certificateName").cloned().unwrap_or(Value::Null),
        "certificateArn": body.get("certificateArn").cloned().unwrap_or(Value::Null),
        "certificateUploadDate": now_epoch(),
        "regionalCertificateName": body.get("regionalCertificateName").cloned().unwrap_or(Value::Null),
        "regionalCertificateArn": body.get("regionalCertificateArn").cloned().unwrap_or(Value::Null),
        "distributionDomainName": format!("{domain_name}.cloudfront.localcloud"),
        "distributionHostedZoneId": "Z2FDTNDATAQYW2",
        "endpointConfiguration": body.get("endpointConfiguration").cloned().unwrap_or(json!({ "types": ["EDGE"] })),
        "regionalDomainName": format!("{domain_name}.regional.localcloud"),
        "regionalHostedZoneId": "ZLOCALCLOUD",
        "securityPolicy": body.get("securityPolicy").and_then(Value::as_str).unwrap_or("TLS_1_2"),
        "mutualTlsAuthentication": body.get("mutualTlsAuthentication").cloned().unwrap_or(Value::Null),
        "ownershipVerificationCertificateArn": body.get("ownershipVerificationCertificateArn").cloned().unwrap_or(Value::Null),
        "tags": body.get("tags").cloned().unwrap_or(json!({})),
        "__basePathMappings": {},
        "__apiMappings": {},
    });
    if let Some(id) = domain_id.as_deref() {
        domain["domainNameId"] = json!(id);
        domain["domainNameArn"] = json!(format!(
            "arn:aws:apigateway:{}:{}:/domainnames/{}+{}",
            ctx.region, ctx.account, domain_name, id
        ));
        domain["domainNameStatus"] = json!("AVAILABLE");
        domain["routingMode"] = body
            .get("routingMode")
            .cloned()
            .unwrap_or(json!("BASE_PATH_MAPPING_ONLY"));
        for field in ["policy", "managementPolicy"] {
            if let Some(value) = body.get(field) {
                domain[field] = value.clone();
            }
        }
    }
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    if let Some(id) = domain_id {
        guard.private_domains.insert(id, domain.clone());
    } else {
        if guard.domains.contains_key(domain_name) {
            return Err(ApiGwError::Conflict(format!(
                "Domain name already exists: {domain_name}"
            )));
        }
        guard
            .domains
            .insert(domain_name.to_string(), domain.clone());
    }
    Ok((201, public_domain(&domain)))
}

pub async fn get_domain_name(ctx: &Ctx<'_>, domain_name: &str, domain_id: Option<&str>) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    Ok((
        200,
        public_domain(domain_ref(&guard, domain_name, domain_id)?),
    ))
}

pub async fn get_domain_names(ctx: &Ctx<'_>) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    let item = guard
        .domains
        .values()
        .chain(guard.private_domains.values())
        .map(public_domain)
        .collect::<Vec<_>>();
    Ok((200, json!({ "item": item })))
}

pub async fn update_domain_name(
    ctx: &Ctx<'_>,
    domain_name: &str,
    domain_id: Option<&str>,
    body: &Value,
) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    let domain = domain_mut(&mut guard, domain_name, domain_id)?;
    let private = domain_id.is_some();
    let mut updated = domain.clone();
    if private {
        if let Some(operations) = body.get("patchOperations").and_then(Value::as_array) {
            for operation in operations {
                if operation.get("op").and_then(Value::as_str) == Some("replace") {
                    if let Some(path) = operation.get("path").and_then(Value::as_str) {
                        if matches!(path, "/policy" | "/managementPolicy")
                            && updated.get(&path[1..]).is_none()
                        {
                            updated[&path[1..]] = Value::String(String::new());
                        }
                    }
                }
            }
        }
    }
    apply_patch_operations(&mut updated, body, |path| {
        matches!(
            path,
            "/certificateName"
                | "/certificateArn"
                | "/regionalCertificateName"
                | "/regionalCertificateArn"
                | "/endpointConfiguration/types"
                | "/securityPolicy"
                | "/mutualTlsAuthentication"
                | "/ownershipVerificationCertificateArn"
        ) || (private && matches!(path, "/policy" | "/managementPolicy" | "/routingMode"))
    })?;
    if private {
        validate_private_config(&updated)?;
    } else if private_domain_requested(&updated) {
        return Err(ApiGwError::BadRequest(
            "Cannot change a public custom domain to PRIVATE".into(),
        ));
    }
    *domain = updated.clone();
    Ok((200, public_domain(&updated)))
}

pub async fn delete_domain_name(ctx: &Ctx<'_>, domain_name: &str, domain_id: Option<&str>) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    let domain = domain_ref(&guard, domain_name, domain_id)?;
    let arn = domain
        .get("domainNameArn")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(id) = domain_id {
        guard.private_domains.remove(id);
        if let Some(arn) = arn {
            guard.domain_access_associations.retain(|_, association| {
                association.get("domainNameArn").and_then(Value::as_str) != Some(&arn)
            });
        }
    } else {
        guard.domains.remove(domain_name);
    }
    Ok((202, json!({})))
}

pub async fn create_domain_name_access_association(ctx: &Ctx<'_>, body: &Value) -> Out {
    let domain_arn = req_str(body, "domainNameArn")?;
    let source = req_str(body, "accessAssociationSource")?;
    let source_type = req_str(body, "accessAssociationSourceType")?;
    if source_type != "VPCE"
        || !source.starts_with("vpce-")
        || source.len() <= 5
        || !source[5..].chars().all(|ch| ch.is_ascii_alphanumeric())
    {
        return Err(ApiGwError::BadRequest(
            "accessAssociationSourceType must be VPCE with a valid VPC endpoint ID".into(),
        ));
    }
    if body.get("tags").is_some_and(|tags| !tags.is_object()) {
        return Err(ApiGwError::BadRequest("tags must be an object".into()));
    }
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    let domain = guard
        .private_domains
        .values()
        .find(|domain| domain.get("domainNameArn").and_then(Value::as_str) == Some(domain_arn))
        .ok_or_else(|| {
            ApiGwError::NotFound(format!("Invalid private domain name ARN: {domain_arn}"))
        })?;
    let name = req_str(domain, "domainName")?;
    let id = req_str(domain, "domainNameId")?;
    let association_arn = format!(
        "arn:aws:apigateway:{}:{}:/domainnameaccessassociations/domainname/{}+{}/vpcesource/{}",
        ctx.region, ctx.account, name, id, source
    );
    if guard
        .domain_access_associations
        .contains_key(&association_arn)
    {
        return Err(ApiGwError::Conflict(
            "Domain name access association already exists".into(),
        ));
    }
    let association = json!({
        "accessAssociationSource": source,
        "accessAssociationSourceType": "VPCE",
        "domainNameAccessAssociationArn": association_arn,
        "domainNameArn": domain_arn,
        "tags": body.get("tags").cloned().unwrap_or(json!({})),
    });
    guard
        .domain_access_associations
        .insert(association_arn, association.clone());
    Ok((201, association))
}

pub async fn get_domain_name_access_associations(
    ctx: &Ctx<'_>,
    resource_owner: Option<&str>,
    limit: Option<&str>,
    position: Option<&str>,
) -> Out {
    if resource_owner.is_some_and(|owner| !matches!(owner, "SELF" | "OTHER_ACCOUNTS")) {
        return Err(ApiGwError::BadRequest("Invalid resourceOwner".into()));
    }
    let limit = limit
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|_| ApiGwError::BadRequest("Invalid limit".into()))?
        .unwrap_or(25);
    if !(1..=500).contains(&limit) {
        return Err(ApiGwError::BadRequest(
            "limit must be between 1 and 500".into(),
        ));
    }
    let offset = position
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|_| ApiGwError::BadRequest("Invalid position".into()))?
        .unwrap_or(0);
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    let all = if resource_owner == Some("OTHER_ACCOUNTS") {
        Vec::new()
    } else {
        guard
            .domain_access_associations
            .values()
            .cloned()
            .collect::<Vec<_>>()
    };
    if offset > all.len() {
        return Err(ApiGwError::BadRequest("Invalid position".into()));
    }
    let next = offset.saturating_add(limit);
    let item = all.into_iter().skip(offset).take(limit).collect::<Vec<_>>();
    let mut response = json!({ "item": item });
    if next < guard.domain_access_associations.len() && resource_owner != Some("OTHER_ACCOUNTS") {
        response["position"] = json!(next.to_string());
    }
    Ok((200, response))
}

pub async fn delete_domain_name_access_association(ctx: &Ctx<'_>, arn: &str) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    if guard.domain_access_associations.remove(arn).is_none() {
        return Err(ApiGwError::NotFound(
            "Invalid domain name access association ARN".into(),
        ));
    }
    Ok((202, json!({})))
}

fn equivalent_mapping_key(value: &str) -> &str {
    let value = value.trim_matches('/');
    if value == "(none)" {
        ""
    } else {
        value
    }
}

fn domain_has_mapping_key(domain: &Value, wanted: &str, excluded_v2_id: Option<&str>) -> bool {
    let wanted = equivalent_mapping_key(wanted);
    domain
        .get("__basePathMappings")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .any(|(key, _)| equivalent_mapping_key(key) == wanted)
        || domain
            .get("__apiMappings")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .any(|(id, mapping)| {
                Some(id.as_str()) != excluded_v2_id
                    && mapping
                        .get("apiMappingKey")
                        .and_then(Value::as_str)
                        .is_some_and(|key| equivalent_mapping_key(key) == wanted)
            })
}

async fn validate_mapping_target(
    ctx: &Ctx<'_>,
    rest_api_id: &str,
    stage_name: &str,
    private_domain: bool,
) -> Result<(), ApiGwError> {
    let api = rest(ctx, rest_api_id).await?;
    let guard = api.read().await;
    if private_domain && !private_domain_requested(&guard.api) {
        return Err(ApiGwError::BadRequest(
            "PRIVATE custom domains require a PRIVATE REST API".into(),
        ));
    }
    if !guard.stages.contains_key(stage_name) {
        return Err(ApiGwError::BadRequest(
            "Invalid stage identifier specified".into(),
        ));
    }
    Ok(())
}

pub async fn create_base_path_mapping(
    ctx: &Ctx<'_>,
    domain_name: &str,
    domain_id: Option<&str>,
    body: &Value,
) -> Out {
    let base_path = req_str(body, "basePath")?;
    let rest_api_id = req_str(body, "restApiId")?;
    let stage = req_str(body, "stage")?;
    {
        let shared = ctx.store.shared(ctx.account, ctx.region);
        let guard = shared.read().await;
        domain_ref(&guard, domain_name, domain_id)?;
    }
    validate_mapping_target(ctx, rest_api_id, stage, domain_id.is_some()).await?;
    let mapping = json!({
        "basePath": base_path,
        "restApiId": rest_api_id,
        "stage": stage,
    });
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    let domain = domain_mut(&mut guard, domain_name, domain_id)?;
    if domain_has_mapping_key(domain, base_path, None) {
        return Err(ApiGwError::Conflict(format!(
            "Base path mapping already exists: {base_path}"
        )));
    }
    let mappings = domain
        .get_mut("__basePathMappings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| ApiGwError::Internal("Domain mapping storage is invalid".into()))?;
    mappings.insert(base_path.to_string(), mapping.clone());
    Ok((201, mapping))
}

pub async fn get_base_path_mapping(
    ctx: &Ctx<'_>,
    domain_name: &str,
    domain_id: Option<&str>,
    base_path: &str,
) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    domain_ref(&guard, domain_name, domain_id)?
        .get("__basePathMappings")
        .and_then(|mappings| mappings.get(base_path))
        .cloned()
        .map(|value| (200, value))
        .ok_or_else(|| ApiGwError::NotFound(format!("Invalid base path: {base_path}")))
}

pub async fn get_base_path_mappings(
    ctx: &Ctx<'_>,
    domain_name: &str,
    domain_id: Option<&str>,
) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    let domain = domain_ref(&guard, domain_name, domain_id)?;
    let item = domain
        .get("__basePathMappings")
        .and_then(Value::as_object)
        .unwrap()
        .values()
        .cloned()
        .collect::<Vec<_>>();
    Ok((200, json!({ "item": item })))
}

pub async fn update_base_path_mapping(
    ctx: &Ctx<'_>,
    domain_name: &str,
    domain_id: Option<&str>,
    base_path: &str,
    body: &Value,
) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut updated = {
        let guard = shared.read().await;
        domain_ref(&guard, domain_name, domain_id)?
            .get("__basePathMappings")
            .and_then(|mappings| mappings.get(base_path))
            .cloned()
            .ok_or_else(|| ApiGwError::NotFound(format!("Invalid base path: {base_path}")))?
    };
    apply_patch_operations(&mut updated, body, |path| {
        matches!(path, "/basePath" | "/restApiId" | "/stage")
    })?;
    let new_base_path = req_str(&updated, "basePath")?.to_string();
    let rest_api_id = req_str(&updated, "restApiId")?;
    let stage = req_str(&updated, "stage")?;
    validate_mapping_target(ctx, rest_api_id, stage, domain_id.is_some()).await?;

    let mut guard = shared.write().await;
    let domain = domain_mut(&mut guard, domain_name, domain_id)?;
    let conflicts = domain
        .get("__basePathMappings")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .any(|(key, _)| {
            key != base_path
                && equivalent_mapping_key(key) == equivalent_mapping_key(&new_base_path)
        })
        || domain
            .get("__apiMappings")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .any(|(_, mapping)| {
                mapping
                    .get("apiMappingKey")
                    .and_then(Value::as_str)
                    .is_some_and(|key| {
                        equivalent_mapping_key(key) == equivalent_mapping_key(&new_base_path)
                    })
            });
    if conflicts {
        return Err(ApiGwError::Conflict(format!(
            "Base path mapping already exists: {new_base_path}"
        )));
    }
    let mappings = domain
        .get_mut("__basePathMappings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| ApiGwError::Internal("Domain mapping storage is invalid".into()))?;
    mappings.remove(base_path);
    mappings.insert(new_base_path, updated.clone());
    Ok((200, updated))
}

pub async fn delete_base_path_mapping(
    ctx: &Ctx<'_>,
    domain_name: &str,
    domain_id: Option<&str>,
    base_path: &str,
) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    let mappings = domain_mut(&mut guard, domain_name, domain_id)?
        .get_mut("__basePathMappings")
        .and_then(Value::as_object_mut)
        .unwrap();
    if mappings.remove(base_path).is_none() {
        return Err(ApiGwError::NotFound(format!(
            "Invalid base path: {base_path}"
        )));
    }
    Ok((202, json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_supports_coercion_and_rejects_unknown_operations() {
        let mut target = json!({ "enabled": false, "name": "old" });
        apply_patch_operations(
            &mut target,
            &json!({ "patchOperations": [
                { "op": "replace", "path": "/enabled", "value": "true" },
                { "op": "replace", "path": "/name", "value": "new" }
            ]}),
            |_| true,
        )
        .unwrap();
        assert_eq!(target, json!({ "enabled": true, "name": "new" }));

        let error = apply_patch_operations(
            &mut target,
            &json!({ "patchOperations": [{ "op": "move", "path": "/name" }] }),
            |_| true,
        );
        assert!(matches!(error, Err(ApiGwError::BadRequest(_))));
    }

    #[test]
    fn model_schema_is_compiled_as_draft_seven() {
        assert!(compile_model_schema(r#"{"type":"object","required":["id"]}"#).is_ok());
        assert!(compile_model_schema(r#"{"type":17}"#).is_err());
        assert!(compile_model_schema("not-json").is_err());
    }

    #[test]
    fn gateway_response_defaults_cover_core_failures() {
        let missing = default_gateway_response("MISSING_AUTHENTICATION_TOKEN").unwrap();
        assert_eq!(missing["statusCode"], "403");
        assert_eq!(missing["defaultResponse"], true);
        assert!(default_gateway_response("NOT_A_RESPONSE_TYPE").is_none());
    }

    #[tokio::test]
    async fn base_path_mapping_rejects_missing_stage_with_bad_request() {
        let store = ApiGwStore::new();
        let registry = Weak::new();
        let ctx = Ctx {
            store: &store,
            registry: &registry,
            region: "us-east-1",
            account: "000000000000",
            request_id: "test",
            waf: None,
        };
        let (_, api) = create_rest_api(&ctx, &json!({ "name": "test" }))
            .await
            .unwrap();
        let api_id = api["id"].as_str().unwrap();
        create_domain_name(
            &ctx,
            &json!({
                "domainName": "internal.example.test",
                "endpointConfiguration": { "types": ["REGIONAL"] }
            }),
        )
        .await
        .unwrap();

        let error = create_base_path_mapping(
            &ctx,
            "internal.example.test",
            None,
            &json!({
                "basePath": "ledger",
                "restApiId": api_id,
                "stage": "missing"
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            ApiGwError::BadRequest("Invalid stage identifier specified".into())
        );
        let (_, mappings) = get_base_path_mappings(&ctx, "internal.example.test", None)
            .await
            .unwrap();
        assert!(mappings["item"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleting_resource_removes_all_descendants_and_protects_root() {
        let store = ApiGwStore::new();
        let registry = Weak::new();
        let ctx = Ctx {
            store: &store,
            registry: &registry,
            region: "us-east-1",
            account: "000000000000",
            request_id: "test",
            waf: None,
        };
        let (_, api) = create_rest_api(&ctx, &json!({ "name": "test" }))
            .await
            .unwrap();
        let api_id = api["id"].as_str().unwrap();
        let root_id = api["rootResourceId"].as_str().unwrap();
        let (_, child) = create_resource(&ctx, api_id, root_id, &json!({ "pathPart": "a" }))
            .await
            .unwrap();
        let child_id = child["id"].as_str().unwrap();
        let (_, grandchild) = create_resource(&ctx, api_id, child_id, &json!({ "pathPart": "b" }))
            .await
            .unwrap();
        let grandchild_id = grandchild["id"].as_str().unwrap().to_string();

        delete_resource(&ctx, api_id, child_id).await.unwrap();
        assert!(get_resource(&ctx, api_id, &grandchild_id).await.is_err());
        assert!(matches!(
            delete_resource(&ctx, api_id, root_id).await,
            Err(ApiGwError::BadRequest(_))
        ));
    }
}
