//! API Gateway v2 (HTTP + WebSocket) control-plane operations. Each returns `(status, body)`
//! or an error. Resources are addressed by method + path segments under `/v2/apis`.

use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::ApiGwError;
use crate::logging::{http_stage_logging, preflight};
use crate::store::{gen_id, ApiV2Record};
use crate::v1::Ctx;

type Out = Result<(u16, Value), ApiGwError>;

const API_MUTABLE_FIELDS: &[&str] = &[
    "apiKeySelectionExpression",
    "corsConfiguration",
    "credentialsArn",
    "description",
    "disableExecuteApiEndpoint",
    "name",
    "routeSelectionExpression",
    "version",
];
const INTEGRATION_FIELDS: &[&str] = &[
    "connectionId",
    "connectionType",
    "contentHandlingStrategy",
    "credentialsArn",
    "description",
    "integrationMethod",
    "integrationSubtype",
    "integrationType",
    "integrationUri",
    "passthroughBehavior",
    "payloadFormatVersion",
    "requestParameters",
    "requestTemplates",
    "responseParameters",
    "templateSelectionExpression",
    "timeoutInMillis",
    "tlsConfig",
];
const INTERNAL_MAPPINGS: &str = "__apiMappings";
const INTERNAL_BASE_PATH_MAPPINGS: &str = "__basePathMappings";

fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

fn req_str<'a>(body: &'a Value, key: &str) -> Result<&'a str, ApiGwError> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiGwError::BadRequest(format!("{key} is required")))
}

fn check_type(
    body: &Value,
    key: &str,
    predicate: impl FnOnce(&Value) -> bool,
) -> Result<(), ApiGwError> {
    if let Some(value) = body.get(key) {
        if !value.is_null() && !predicate(value) {
            return Err(ApiGwError::BadRequest(format!("{key} has an invalid type")));
        }
    }
    Ok(())
}

fn copy_fields(target: &mut Value, source: &Value, fields: &[&str]) {
    for field in fields {
        if let Some(value) = source.get(*field) {
            target[*field] = value.clone();
        }
    }
}

fn validate_cors(body: &Value) -> Result<(), ApiGwError> {
    let Some(cors) = body.get("corsConfiguration") else {
        return Ok(());
    };
    if cors.is_null() {
        return Ok(());
    }
    let object = cors
        .as_object()
        .ok_or_else(|| ApiGwError::BadRequest("corsConfiguration must be an object".into()))?;
    let allowed = [
        "allowCredentials",
        "allowHeaders",
        "allowMethods",
        "allowOrigins",
        "exposeHeaders",
        "maxAge",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ApiGwError::BadRequest(
            "corsConfiguration contains unsupported fields".into(),
        ));
    }
    for key in [
        "allowHeaders",
        "allowMethods",
        "allowOrigins",
        "exposeHeaders",
    ] {
        if let Some(value) = object.get(key) {
            if !value
                .as_array()
                .map(|values| values.iter().all(Value::is_string))
                .unwrap_or(false)
            {
                return Err(ApiGwError::BadRequest(format!(
                    "corsConfiguration.{key} must be a list of strings"
                )));
            }
        }
    }
    if object
        .get("allowCredentials")
        .is_some_and(|v| !v.is_boolean())
    {
        return Err(ApiGwError::BadRequest(
            "corsConfiguration.allowCredentials must be a boolean".into(),
        ));
    }
    if object
        .get("maxAge")
        .is_some_and(|v| !v.is_i64() && !v.is_u64())
    {
        return Err(ApiGwError::BadRequest(
            "corsConfiguration.maxAge must be an integer".into(),
        ));
    }
    if object.get("allowCredentials").and_then(Value::as_bool) == Some(true)
        && object
            .get("allowOrigins")
            .and_then(Value::as_array)
            .is_some_and(|origins| origins.iter().any(|origin| origin.as_str() == Some("*")))
    {
        return Err(ApiGwError::BadRequest(
            "corsConfiguration cannot combine allowCredentials=true with allowOrigins=*".into(),
        ));
    }
    Ok(())
}

fn validate_api_fields(body: &Value, creating: bool) -> Result<(), ApiGwError> {
    for key in [
        "apiKeySelectionExpression",
        "credentialsArn",
        "description",
        "name",
        "routeSelectionExpression",
        "version",
    ] {
        check_type(body, key, Value::is_string)?;
    }
    check_type(body, "disableExecuteApiEndpoint", Value::is_boolean)?;
    validate_cors(body)?;
    if creating {
        let protocol = req_str(body, "protocolType")?;
        if protocol != "HTTP" && protocol != "WEBSOCKET" {
            return Err(ApiGwError::BadRequest(format!(
                "Invalid protocol type specified. Valid types are HTTP and WEBSOCKET: {protocol}"
            )));
        }
    } else if body.get("protocolType").is_some() {
        return Err(ApiGwError::BadRequest(
            "protocolType cannot be updated".into(),
        ));
    }
    if body.get("name").is_some() {
        req_str(body, "name")?;
    }
    Ok(())
}

async fn api(
    ctx: &Ctx<'_>,
    api_id: &str,
) -> Result<std::sync::Arc<tokio::sync::RwLock<ApiV2Record>>, ApiGwError> {
    ctx.store
        .v2(ctx.account, ctx.region, api_id)
        .ok_or_else(|| ApiGwError::NotFound(format!("Invalid API identifier specified {api_id}")))
}

fn protocol(record: &ApiV2Record) -> &str {
    record
        .api
        .get("protocolType")
        .and_then(Value::as_str)
        .unwrap_or("HTTP")
}

fn deployment_value(description: Option<&Value>, auto_deployed: bool) -> Value {
    json!({
        "autoDeployed": auto_deployed,
        "createdDate": now_iso(),
        "deploymentId": gen_id(),
        "deploymentStatus": "DEPLOYED",
        "description": description.cloned().unwrap_or(Value::Null),
    })
}

/// Create one deployment for a route/integration mutation and point every auto-deploy stage
/// at it. A single mutation produces a single shared snapshot even when several stages follow it.
fn auto_deploy(record: &mut ApiV2Record) {
    if !record
        .stages
        .values()
        .any(|stage| stage.get("autoDeploy").and_then(Value::as_bool) == Some(true))
    {
        return;
    }
    let deployment = deployment_value(None, true);
    let deployment_id = deployment["deploymentId"].as_str().unwrap().to_string();
    let snapshot = record.snapshot();
    record.deployments.insert(deployment_id.clone(), deployment);
    record
        .deployment_snapshots
        .insert(deployment_id.clone(), snapshot);
    let updated = now_iso();
    for stage in record.stages.values_mut() {
        if stage.get("autoDeploy").and_then(Value::as_bool) == Some(true) {
            stage["deploymentId"] = json!(deployment_id);
            stage["lastDeploymentStatusMessage"] = json!("Deployment successful");
            stage["lastUpdatedDate"] = json!(updated);
        }
    }
}

// ============================ APIs =============================================

pub async fn create_api(ctx: &Ctx<'_>, body: &Value) -> Out {
    validate_api_fields(body, true)?;
    let name = req_str(body, "name")?;
    let protocol_type = req_str(body, "protocolType")?.to_string();
    let route_selection = match body.get("routeSelectionExpression").and_then(Value::as_str) {
        Some(expr) if !expr.is_empty() => expr.to_string(),
        _ if protocol_type == "WEBSOCKET" => {
            return Err(ApiGwError::BadRequest(
                "RouteSelectionExpression is required for WEBSOCKET protocol".into(),
            ));
        }
        _ => "$request.method $request.path".to_string(),
    };
    let id = gen_id();
    let scheme = if protocol_type == "WEBSOCKET" {
        "wss"
    } else {
        "https"
    };
    let mut api = json!({
        "apiId": id,
        "name": name,
        "protocolType": protocol_type,
        "routeSelectionExpression": route_selection,
        "apiKeySelectionExpression": body.get("apiKeySelectionExpression").and_then(Value::as_str).unwrap_or("$request.header.x-api-key"),
        "apiEndpoint": format!("{scheme}://{id}.execute-api.{}.amazonaws.com", ctx.region),
        "description": body.get("description").cloned().unwrap_or(Value::Null),
        "version": body.get("version").cloned().unwrap_or(Value::Null),
        "createdDate": now_iso(),
        "disableExecuteApiEndpoint": body.get("disableExecuteApiEndpoint").and_then(Value::as_bool).unwrap_or(false),
    });
    for field in ["corsConfiguration", "credentialsArn"] {
        if let Some(value) = body.get(field) {
            api[field] = value.clone();
        }
    }
    let rec = ApiV2Record {
        api: api.clone(),
        ..Default::default()
    };
    ctx.store.insert_v2(ctx.account, ctx.region, &id, rec);
    Ok((201, api))
}

pub async fn get_apis(ctx: &Ctx<'_>) -> Out {
    let mut items = Vec::new();
    for record in ctx.store.list_v2(ctx.account, ctx.region) {
        items.push(record.read().await.api.clone());
    }
    Ok((200, json!({ "items": items })))
}

pub async fn get_api(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let value = record.read().await.api.clone();
    Ok((200, value))
}

pub async fn update_api(ctx: &Ctx<'_>, api_id: &str, body: &Value) -> Out {
    validate_api_fields(body, false)?;
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    copy_fields(&mut guard.api, body, API_MUTABLE_FIELDS);
    let result = guard.api.clone();
    auto_deploy(&mut guard);
    Ok((200, result))
}

pub async fn delete_api(ctx: &Ctx<'_>, api_id: &str) -> Out {
    if !ctx.store.remove_v2(ctx.account, ctx.region, api_id) {
        return Err(ApiGwError::NotFound(format!(
            "Invalid API identifier specified {api_id}"
        )));
    }
    Ok((204, json!({})))
}

// ============================ Routes ===========================================

fn validate_route_target(record: &ApiV2Record, target: &Value) -> Result<(), ApiGwError> {
    if target.is_null() {
        return Ok(());
    }
    let target = target
        .as_str()
        .ok_or_else(|| ApiGwError::BadRequest("target must be a string".into()))?;
    let integration_id = target.strip_prefix("integrations/").ok_or_else(|| {
        ApiGwError::BadRequest("target must have the form integrations/{IntegrationId}".into())
    })?;
    if !record.integrations.contains_key(integration_id) {
        return Err(ApiGwError::NotFound(format!(
            "Invalid integration identifier specified {integration_id}"
        )));
    }
    Ok(())
}

fn validate_route_authorization(
    record: &ApiV2Record,
    authorization_type: &str,
    authorizer_id: Option<&str>,
) -> Result<(), ApiGwError> {
    let expected_authorizer = match (protocol(record), authorization_type) {
        ("HTTP", "NONE") | ("WEBSOCKET", "NONE") => return Ok(()),
        ("HTTP", "JWT") => "JWT",
        ("HTTP", "CUSTOM") | ("WEBSOCKET", "CUSTOM") => "REQUEST",
        (api_protocol, other) => {
            return Err(ApiGwError::BadRequest(format!(
                "Unsupported authorizationType {other} for {api_protocol} API"
            )))
        }
    };
    let authorizer_id = authorizer_id.ok_or_else(|| {
        ApiGwError::BadRequest(format!(
            "{authorization_type} authorization requires authorizerId"
        ))
    })?;
    let authorizer = record.authorizers.get(authorizer_id).ok_or_else(|| {
        ApiGwError::NotFound(format!(
            "Invalid authorizer identifier specified {authorizer_id}"
        ))
    })?;
    if authorizer.get("authorizerType").and_then(Value::as_str) != Some(expected_authorizer) {
        return Err(ApiGwError::BadRequest(format!(
            "{authorization_type} authorization requires a {expected_authorizer} authorizer"
        )));
    }
    Ok(())
}

pub async fn create_route(ctx: &Ctx<'_>, api_id: &str, body: &Value) -> Out {
    let route_key = req_str(body, "routeKey")?.to_string();
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    if guard
        .routes
        .values()
        .any(|route| route.get("routeKey").and_then(Value::as_str) == Some(&route_key))
    {
        return Err(ApiGwError::Conflict(format!(
            "Route with key {route_key} already exists"
        )));
    }
    if let Some(target) = body.get("target") {
        validate_route_target(&guard, target)?;
    }
    let authorization_type = match body.get("authorizationType") {
        Some(value) => value
            .as_str()
            .ok_or_else(|| ApiGwError::BadRequest("authorizationType must be a string".into()))?,
        None => "NONE",
    };
    let authorizer_id = match body.get("authorizerId") {
        Some(Value::Null) | None => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| ApiGwError::BadRequest("authorizerId must be a string".into()))?,
        ),
    };
    validate_route_authorization(&guard, authorization_type, authorizer_id)?;
    let id = gen_id();
    let route = json!({
        "routeId": id,
        "routeKey": route_key,
        "target": body.get("target").cloned().unwrap_or(Value::Null),
        "authorizationType": authorization_type,
        "authorizerId": body.get("authorizerId").cloned().unwrap_or(Value::Null),
        "authorizationScopes": body.get("authorizationScopes").cloned().unwrap_or(json!([])),
        "apiKeyRequired": body.get("apiKeyRequired").and_then(Value::as_bool).unwrap_or(false),
        "modelSelectionExpression": body.get("modelSelectionExpression").cloned().unwrap_or(Value::Null),
        "operationName": body.get("operationName").cloned().unwrap_or(Value::Null),
        "requestModels": body.get("requestModels").cloned().unwrap_or(json!({})),
        "requestParameters": body.get("requestParameters").cloned().unwrap_or(json!({})),
        "routeResponseSelectionExpression": body.get("routeResponseSelectionExpression").cloned().unwrap_or(Value::Null),
    });
    guard.routes.insert(id, route.clone());
    auto_deploy(&mut guard);
    Ok((201, route))
}

pub async fn get_routes(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let items: Vec<Value> = record.read().await.routes.values().cloned().collect();
    Ok((200, json!({ "items": items })))
}

pub async fn get_route(ctx: &Ctx<'_>, api_id: &str, route_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let guard = record.read().await;
    guard
        .routes
        .get(route_id)
        .cloned()
        .map(|v| (200, v))
        .ok_or_else(|| {
            ApiGwError::NotFound(format!("Invalid route identifier specified {route_id}"))
        })
}

pub async fn update_route(ctx: &Ctx<'_>, api_id: &str, route_id: &str, body: &Value) -> Out {
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    if let Some(target) = body.get("target") {
        validate_route_target(&guard, target)?;
    }
    if let Some(route_key) = body.get("routeKey") {
        let route_key = route_key
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ApiGwError::BadRequest("routeKey must be a non-empty string".into()))?;
        if guard.routes.iter().any(|(id, route)| {
            id != route_id && route.get("routeKey").and_then(Value::as_str) == Some(route_key)
        }) {
            return Err(ApiGwError::Conflict(format!(
                "Route with key {route_key} already exists"
            )));
        }
    }
    let current_route = guard.routes.get(route_id).ok_or_else(|| {
        ApiGwError::NotFound(format!("Invalid route identifier specified {route_id}"))
    })?;
    let authorization_type = match body.get("authorizationType") {
        Some(value) => value
            .as_str()
            .ok_or_else(|| ApiGwError::BadRequest("authorizationType must be a string".into()))?,
        None => current_route
            .get("authorizationType")
            .and_then(Value::as_str)
            .unwrap_or("NONE"),
    };
    let authorizer_id = match body.get("authorizerId") {
        Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| ApiGwError::BadRequest("authorizerId must be a string".into()))?,
        ),
        None => current_route.get("authorizerId").and_then(Value::as_str),
    };
    validate_route_authorization(&guard, authorization_type, authorizer_id)?;
    let route = guard.routes.get_mut(route_id).ok_or_else(|| {
        ApiGwError::NotFound(format!("Invalid route identifier specified {route_id}"))
    })?;
    copy_fields(
        route,
        body,
        &[
            "apiKeyRequired",
            "authorizationScopes",
            "authorizationType",
            "authorizerId",
            "modelSelectionExpression",
            "operationName",
            "requestModels",
            "requestParameters",
            "routeKey",
            "routeResponseSelectionExpression",
            "target",
        ],
    );
    let result = route.clone();
    auto_deploy(&mut guard);
    Ok((200, result))
}

pub async fn delete_route(ctx: &Ctx<'_>, api_id: &str, route_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    if guard.routes.remove(route_id).is_none() {
        return Err(ApiGwError::NotFound(format!(
            "Invalid route identifier specified {route_id}"
        )));
    }
    auto_deploy(&mut guard);
    Ok((204, json!({})))
}

// ============================ Integrations =====================================

fn validate_integration(
    body: &Value,
    protocol: &str,
    existing: Option<&Value>,
) -> Result<(), ApiGwError> {
    let integration_type = body
        .get("integrationType")
        .or_else(|| existing.and_then(|value| value.get("integrationType")))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiGwError::BadRequest("integrationType is required".into()))?;
    let valid = if protocol == "HTTP" {
        matches!(integration_type, "AWS_PROXY" | "HTTP_PROXY")
    } else {
        matches!(
            integration_type,
            "AWS" | "AWS_PROXY" | "HTTP" | "HTTP_PROXY" | "MOCK"
        )
    };
    if !valid {
        return Err(ApiGwError::BadRequest(format!(
            "Invalid integration type for {protocol} API: {integration_type}"
        )));
    }
    for key in [
        "connectionId",
        "connectionType",
        "contentHandlingStrategy",
        "credentialsArn",
        "description",
        "integrationMethod",
        "integrationSubtype",
        "integrationType",
        "integrationUri",
        "passthroughBehavior",
        "payloadFormatVersion",
        "templateSelectionExpression",
    ] {
        check_type(body, key, Value::is_string)?;
    }
    for key in [
        "requestParameters",
        "requestTemplates",
        "responseParameters",
        "tlsConfig",
    ] {
        check_type(body, key, Value::is_object)?;
    }
    let connection_type = body
        .get("connectionType")
        .or_else(|| existing.and_then(|value| value.get("connectionType")))
        .and_then(Value::as_str)
        .unwrap_or("INTERNET");
    if !matches!(connection_type, "INTERNET" | "VPC_LINK") {
        return Err(ApiGwError::BadRequest(format!(
            "Invalid connectionType: {connection_type}"
        )));
    }
    let connection_id = body
        .get("connectionId")
        .or_else(|| existing.and_then(|value| value.get("connectionId")))
        .and_then(Value::as_str);
    if connection_type == "VPC_LINK" && connection_id.is_none() {
        return Err(ApiGwError::BadRequest(
            "connectionId is required for VPC_LINK integrations".into(),
        ));
    }
    if let Some(strategy) = body.get("contentHandlingStrategy").and_then(Value::as_str) {
        if !matches!(strategy, "CONVERT_TO_BINARY" | "CONVERT_TO_TEXT") {
            return Err(ApiGwError::BadRequest(format!(
                "Invalid contentHandlingStrategy: {strategy}"
            )));
        }
    }
    let payload_format = body
        .get("payloadFormatVersion")
        .or_else(|| existing.and_then(|value| value.get("payloadFormatVersion")))
        .and_then(Value::as_str)
        .unwrap_or("2.0");
    if protocol == "HTTP" && !matches!(payload_format, "1.0" | "2.0") {
        return Err(ApiGwError::BadRequest(format!(
            "PayloadFormatVersion must be 1.0 or 2.0: {payload_format}"
        )));
    }
    if let Some(timeout) = body.get("timeoutInMillis") {
        let timeout = timeout
            .as_u64()
            .ok_or_else(|| ApiGwError::BadRequest("timeoutInMillis must be an integer".into()))?;
        if !(50..=30_000).contains(&timeout) {
            return Err(ApiGwError::BadRequest(
                "timeoutInMillis must be between 50 and 30000".into(),
            ));
        }
    }
    let uri = body
        .get("integrationUri")
        .or_else(|| existing.and_then(|value| value.get("integrationUri")))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let subtype = body
        .get("integrationSubtype")
        .or_else(|| existing.and_then(|value| value.get("integrationSubtype")))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    if uri.is_none() && subtype.is_none() && integration_type != "MOCK" {
        return Err(ApiGwError::BadRequest(
            "integrationUri is required unless integrationSubtype is supplied".into(),
        ));
    }
    if let Some(uri) = uri {
        let valid_uri = if matches!(integration_type, "HTTP" | "HTTP_PROXY") {
            uri.parse::<http::Uri>().ok().is_some_and(|parsed| {
                matches!(parsed.scheme_str(), Some("http" | "https"))
                    && parsed.authority().is_some()
            })
        } else {
            uri.starts_with("arn:")
                || uri
                    .parse::<http::Uri>()
                    .ok()
                    .is_some_and(|parsed| parsed.scheme().is_some())
        };
        if !valid_uri {
            return Err(ApiGwError::BadRequest(format!(
                "Invalid integrationUri for integration type {integration_type}"
            )));
        }
    }
    Ok(())
}

fn integration_value(body: &Value, protocol: &str, id: String) -> Value {
    let mut integration = json!({
        "integrationId": id,
        "integrationType": body.get("integrationType").cloned().unwrap_or(Value::Null),
        "integrationUri": body.get("integrationUri").cloned().unwrap_or(Value::Null),
        "integrationMethod": body.get("integrationMethod").cloned().unwrap_or(Value::Null),
        "connectionType": body.get("connectionType").and_then(Value::as_str).unwrap_or("INTERNET"),
        "timeoutInMillis": body.get("timeoutInMillis").cloned().unwrap_or(json!(30000)),
    });
    copy_fields(&mut integration, body, INTEGRATION_FIELDS);
    if protocol == "HTTP" && integration.get("payloadFormatVersion").is_none() {
        integration["payloadFormatVersion"] = json!("2.0");
    }
    integration
}

pub async fn create_integration(ctx: &Ctx<'_>, api_id: &str, body: &Value) -> Out {
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    let api_protocol = protocol(&guard).to_string();
    validate_integration(body, &api_protocol, None)?;
    let id = gen_id();
    let integration = integration_value(body, &api_protocol, id.clone());
    guard.integrations.insert(id, integration.clone());
    auto_deploy(&mut guard);
    Ok((201, integration))
}

pub async fn get_integrations(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let items: Vec<Value> = record.read().await.integrations.values().cloned().collect();
    Ok((200, json!({ "items": items })))
}

pub async fn get_integration(ctx: &Ctx<'_>, api_id: &str, integration_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let guard = record.read().await;
    guard
        .integrations
        .get(integration_id)
        .cloned()
        .map(|v| (200, v))
        .ok_or_else(|| {
            ApiGwError::NotFound(format!(
                "Invalid integration identifier specified {integration_id}"
            ))
        })
}

pub async fn update_integration(
    ctx: &Ctx<'_>,
    api_id: &str,
    integration_id: &str,
    body: &Value,
) -> Out {
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    let api_protocol = protocol(&guard).to_string();
    let current = guard.integrations.get(integration_id).ok_or_else(|| {
        ApiGwError::NotFound(format!(
            "Invalid integration identifier specified {integration_id}"
        ))
    })?;
    validate_integration(body, &api_protocol, Some(current))?;
    let integration = guard.integrations.get_mut(integration_id).unwrap();
    copy_fields(integration, body, INTEGRATION_FIELDS);
    let result = integration.clone();
    auto_deploy(&mut guard);
    Ok((200, result))
}

pub async fn delete_integration(ctx: &Ctx<'_>, api_id: &str, integration_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    let target = format!("integrations/{integration_id}");
    if guard
        .routes
        .values()
        .any(|route| route.get("target").and_then(Value::as_str) == Some(&target))
    {
        return Err(ApiGwError::Conflict(format!(
            "Integration {integration_id} is referenced by a route"
        )));
    }
    if guard.integrations.remove(integration_id).is_none() {
        return Err(ApiGwError::NotFound(format!(
            "Invalid integration identifier specified {integration_id}"
        )));
    }
    auto_deploy(&mut guard);
    Ok((204, json!({})))
}

// ============================ Deployments ======================================

pub async fn create_deployment(ctx: &Ctx<'_>, api_id: &str, body: &Value) -> Out {
    check_type(body, "description", Value::is_string)?;
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    let deployment = deployment_value(body.get("description"), false);
    let id = deployment["deploymentId"].as_str().unwrap().to_string();
    let snapshot = guard.snapshot();
    guard.deployments.insert(id.clone(), deployment.clone());
    guard.deployment_snapshots.insert(id, snapshot);
    Ok((201, deployment))
}

pub async fn get_deployments(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let items: Vec<Value> = record.read().await.deployments.values().cloned().collect();
    Ok((200, json!({ "items": items })))
}

pub async fn get_deployment(ctx: &Ctx<'_>, api_id: &str, deployment_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let guard = record.read().await;
    guard
        .deployments
        .get(deployment_id)
        .cloned()
        .map(|value| (200, value))
        .ok_or_else(|| {
            ApiGwError::NotFound(format!(
                "Invalid deployment identifier specified {deployment_id}"
            ))
        })
}

pub async fn delete_deployment(ctx: &Ctx<'_>, api_id: &str, deployment_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    if guard.deployments.remove(deployment_id).is_none() {
        return Err(ApiGwError::NotFound(format!(
            "Invalid deployment identifier specified {deployment_id}"
        )));
    }
    guard.deployment_snapshots.remove(deployment_id);
    Ok((204, json!({})))
}

// ============================ Stages ===========================================

fn validate_stage_fields(record: &ApiV2Record, body: &Value) -> Result<(), ApiGwError> {
    for key in ["clientCertificateId", "deploymentId", "description"] {
        check_type(body, key, Value::is_string)?;
    }
    check_type(body, "autoDeploy", Value::is_boolean)?;
    for key in [
        "accessLogSettings",
        "defaultRouteSettings",
        "routeSettings",
        "stageVariables",
    ] {
        check_type(body, key, Value::is_object)?;
    }
    if let Some(deployment_id) = body.get("deploymentId").and_then(Value::as_str) {
        if !record.deployments.contains_key(deployment_id) {
            return Err(ApiGwError::NotFound(format!(
                "Invalid deployment identifier specified {deployment_id}"
            )));
        }
    }
    Ok(())
}

fn new_stage_value(stage_name: &str, body: &Value) -> Value {
    let mut stage = json!({
        "stageName": stage_name,
        "autoDeploy": body.get("autoDeploy").and_then(Value::as_bool).unwrap_or(false),
        "description": body.get("description").cloned().unwrap_or(Value::Null),
        "createdDate": now_iso(),
        "lastUpdatedDate": now_iso(),
        "stageVariables": body.get("stageVariables").cloned().unwrap_or(json!({})),
        "defaultRouteSettings": body.get("defaultRouteSettings").cloned().unwrap_or(json!({})),
        "routeSettings": body.get("routeSettings").cloned().unwrap_or(json!({})),
    });
    copy_fields(
        &mut stage,
        body,
        &["accessLogSettings", "clientCertificateId", "deploymentId"],
    );
    stage
}

pub async fn create_stage(ctx: &Ctx<'_>, api_id: &str, body: &Value) -> Out {
    let stage_name = req_str(body, "stageName")?;
    let record = api(ctx, api_id).await?;
    let (stage, protocol_type) = {
        let guard = record.read().await;
        if guard.stages.contains_key(stage_name) {
            return Err(ApiGwError::Conflict(format!(
                "Stage already exists: {stage_name}"
            )));
        }
        validate_stage_fields(&guard, body)?;
        (
            new_stage_value(stage_name, body),
            protocol(&guard).to_string(),
        )
    };
    let logging = http_stage_logging(&stage, ctx.account, ctx.region, &protocol_type)?;
    preflight(
        ctx.registry,
        ctx.account,
        ctx.region,
        ctx.request_id,
        &logging,
    )
    .await?;
    let mut guard = record.write().await;
    if guard.stages.contains_key(stage_name) {
        return Err(ApiGwError::Conflict(format!(
            "Stage already exists: {stage_name}"
        )));
    }
    validate_stage_fields(&guard, body)?;
    if protocol(&guard) != protocol_type {
        return Err(ApiGwError::Conflict(
            "API protocol changed during stage creation".into(),
        ));
    }
    guard.stages.insert(stage_name.to_string(), stage);
    if body.get("autoDeploy").and_then(Value::as_bool) == Some(true) {
        auto_deploy(&mut guard);
    }
    let stage = guard
        .stages
        .get(stage_name)
        .cloned()
        .ok_or_else(|| ApiGwError::Internal("Stage creation failed".into()))?;
    Ok((201, stage))
}

pub async fn get_stages(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let items: Vec<Value> = record.read().await.stages.values().cloned().collect();
    Ok((200, json!({ "items": items })))
}

pub async fn get_stage(ctx: &Ctx<'_>, api_id: &str, stage_name: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let guard = record.read().await;
    guard
        .stages
        .get(stage_name)
        .cloned()
        .map(|value| (200, value))
        .ok_or_else(|| {
            ApiGwError::NotFound(format!("Invalid stage identifier specified {stage_name}"))
        })
}

pub async fn update_stage(ctx: &Ctx<'_>, api_id: &str, stage_name: &str, body: &Value) -> Out {
    let record = api(ctx, api_id).await?;
    let (mut updated, protocol_type) = {
        let guard = record.read().await;
        validate_stage_fields(&guard, body)?;
        let stage = guard.stages.get(stage_name).cloned().ok_or_else(|| {
            ApiGwError::NotFound(format!("Invalid stage identifier specified {stage_name}"))
        })?;
        (stage, protocol(&guard).to_string())
    };
    copy_fields(
        &mut updated,
        body,
        &[
            "accessLogSettings",
            "autoDeploy",
            "clientCertificateId",
            "defaultRouteSettings",
            "deploymentId",
            "description",
            "routeSettings",
            "stageVariables",
        ],
    );
    updated["lastUpdatedDate"] = json!(now_iso());
    let logging = http_stage_logging(&updated, ctx.account, ctx.region, &protocol_type)?;
    preflight(
        ctx.registry,
        ctx.account,
        ctx.region,
        ctx.request_id,
        &logging,
    )
    .await?;
    let mut guard = record.write().await;
    validate_stage_fields(&guard, body)?;
    if !guard.stages.contains_key(stage_name) {
        return Err(ApiGwError::NotFound(format!(
            "Invalid stage identifier specified {stage_name}"
        )));
    }
    if protocol(&guard) != protocol_type {
        return Err(ApiGwError::Conflict(
            "API protocol changed during stage update".into(),
        ));
    }
    guard.stages.insert(stage_name.to_string(), updated.clone());
    Ok((200, updated))
}

pub async fn delete_stage(ctx: &Ctx<'_>, api_id: &str, stage_name: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    if guard.stages.remove(stage_name).is_none() {
        return Err(ApiGwError::NotFound(format!(
            "Invalid stage identifier specified {stage_name}"
        )));
    }
    Ok((204, json!({})))
}

// ============================ Authorizers ======================================

fn validate_authorizer(value: &Value) -> Result<(), ApiGwError> {
    let authorizer_type = req_str(value, "authorizerType")?;
    if !matches!(authorizer_type, "JWT" | "REQUEST") {
        return Err(ApiGwError::BadRequest(format!(
            "AuthorizerType must be JWT or REQUEST: {authorizer_type}"
        )));
    }
    req_str(value, "name")?;
    let identity_source = value
        .get("identitySource")
        .ok_or_else(|| ApiGwError::BadRequest("identitySource must be a non-empty list".into()))?;
    if !identity_source
        .as_array()
        .map(|values| !values.is_empty() && values.iter().all(Value::is_string))
        .unwrap_or(false)
    {
        return Err(ApiGwError::BadRequest(
            "identitySource must be a non-empty list of strings".into(),
        ));
    }
    if authorizer_type == "JWT" {
        let config = value.get("jwtConfiguration").ok_or_else(|| {
            ApiGwError::BadRequest("JWT authorizers require jwtConfiguration".into())
        })?;
        let issuer = config
            .get("issuer")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        let audience = config
            .get("audience")
            .and_then(Value::as_array)
            .filter(|values| !values.is_empty() && values.iter().all(Value::is_string));
        if issuer.is_none() || audience.is_none() {
            return Err(ApiGwError::BadRequest(
                "jwtConfiguration requires a non-empty issuer and audience".into(),
            ));
        }
    } else {
        req_str(value, "authorizerUri")?;
        if let Some(format) = value.get("authorizerPayloadFormatVersion") {
            let format = format.as_str().ok_or_else(|| {
                ApiGwError::BadRequest("authorizerPayloadFormatVersion must be a string".into())
            })?;
            if !matches!(format, "1.0" | "2.0") {
                return Err(ApiGwError::BadRequest(
                    "authorizerPayloadFormatVersion must be 1.0 or 2.0".into(),
                ));
            }
        }
        if value.get("enableSimpleResponses").and_then(Value::as_bool) == Some(true)
            && value
                .get("authorizerPayloadFormatVersion")
                .and_then(Value::as_str)
                != Some("2.0")
        {
            return Err(ApiGwError::BadRequest(
                "enableSimpleResponses requires authorizerPayloadFormatVersion 2.0".into(),
            ));
        }
    }
    if let Some(ttl) = value.get("authorizerResultTtlInSeconds") {
        let ttl = ttl.as_u64().ok_or_else(|| {
            ApiGwError::BadRequest("authorizerResultTtlInSeconds must be an integer".into())
        })?;
        if ttl > 3600 {
            return Err(ApiGwError::BadRequest(
                "authorizerResultTtlInSeconds must be between 0 and 3600".into(),
            ));
        }
    }
    Ok(())
}

fn authorizer_value(body: &Value, id: String) -> Value {
    let mut authorizer = json!({
        "authorizerId": id,
        "name": body.get("name").cloned().unwrap_or(Value::Null),
        "authorizerType": body.get("authorizerType").cloned().unwrap_or(Value::Null),
        "identitySource": body.get("identitySource").cloned().unwrap_or(json!(["$request.header.Authorization"])),
    });
    copy_fields(
        &mut authorizer,
        body,
        &[
            "authorizerCredentialsArn",
            "authorizerPayloadFormatVersion",
            "authorizerResultTtlInSeconds",
            "authorizerUri",
            "enableSimpleResponses",
            "identityValidationExpression",
            "jwtConfiguration",
        ],
    );
    authorizer
}

pub async fn create_authorizer(ctx: &Ctx<'_>, api_id: &str, body: &Value) -> Out {
    let mut candidate = body.clone();
    if candidate.get("identitySource").is_none() {
        candidate["identitySource"] = json!(["$request.header.Authorization"]);
    }
    validate_authorizer(&candidate)?;
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    if protocol(&guard) == "WEBSOCKET"
        && candidate.get("authorizerType").and_then(Value::as_str) != Some("REQUEST")
    {
        return Err(ApiGwError::BadRequest(
            "WEBSOCKET APIs only support REQUEST authorizers".into(),
        ));
    }
    let id = gen_id();
    let authorizer = authorizer_value(&candidate, id.clone());
    guard.authorizers.insert(id, authorizer.clone());
    auto_deploy(&mut guard);
    Ok((201, authorizer))
}

pub async fn get_authorizers(ctx: &Ctx<'_>, api_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let items: Vec<Value> = record.read().await.authorizers.values().cloned().collect();
    Ok((200, json!({ "items": items })))
}

pub async fn get_authorizer(ctx: &Ctx<'_>, api_id: &str, authorizer_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let guard = record.read().await;
    guard
        .authorizers
        .get(authorizer_id)
        .cloned()
        .map(|value| (200, value))
        .ok_or_else(|| {
            ApiGwError::NotFound(format!(
                "Invalid authorizer identifier specified {authorizer_id}"
            ))
        })
}

pub async fn update_authorizer(
    ctx: &Ctx<'_>,
    api_id: &str,
    authorizer_id: &str,
    body: &Value,
) -> Out {
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    let current = guard.authorizers.get(authorizer_id).ok_or_else(|| {
        ApiGwError::NotFound(format!(
            "Invalid authorizer identifier specified {authorizer_id}"
        ))
    })?;
    let mut candidate = current.clone();
    copy_fields(
        &mut candidate,
        body,
        &[
            "authorizerCredentialsArn",
            "authorizerPayloadFormatVersion",
            "authorizerResultTtlInSeconds",
            "authorizerType",
            "authorizerUri",
            "enableSimpleResponses",
            "identitySource",
            "identityValidationExpression",
            "jwtConfiguration",
            "name",
        ],
    );
    validate_authorizer(&candidate)?;
    if protocol(&guard) == "WEBSOCKET"
        && candidate.get("authorizerType").and_then(Value::as_str) != Some("REQUEST")
    {
        return Err(ApiGwError::BadRequest(
            "WEBSOCKET APIs only support REQUEST authorizers".into(),
        ));
    }
    guard
        .authorizers
        .insert(authorizer_id.to_string(), candidate.clone());
    auto_deploy(&mut guard);
    Ok((200, candidate))
}

pub async fn delete_authorizer(ctx: &Ctx<'_>, api_id: &str, authorizer_id: &str) -> Out {
    let record = api(ctx, api_id).await?;
    let mut guard = record.write().await;
    if guard.authorizers.remove(authorizer_id).is_none() {
        return Err(ApiGwError::NotFound(format!(
            "Invalid authorizer identifier specified {authorizer_id}"
        )));
    }
    auto_deploy(&mut guard);
    Ok((204, json!({})))
}

// ============================ Domains & API mappings ===========================

fn public_domain(domain: &Value) -> Value {
    let mut result = domain.clone();
    if let Some(object) = result.as_object_mut() {
        object.remove(INTERNAL_MAPPINGS);
        object.remove(INTERNAL_BASE_PATH_MAPPINGS);
    }
    result
}

fn mappings(domain: &Value) -> Option<&Map<String, Value>> {
    domain.get(INTERNAL_MAPPINGS).and_then(Value::as_object)
}

fn equivalent_mapping_key(value: &str) -> &str {
    let value = value.trim_matches('/');
    if value == "(none)" {
        ""
    } else {
        value
    }
}

fn has_equivalent_mapping(
    domain: &Value,
    mapping_key: &str,
    excluded_api_mapping: Option<&str>,
) -> bool {
    let wanted = equivalent_mapping_key(mapping_key);
    domain
        .get(INTERNAL_BASE_PATH_MAPPINGS)
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .any(|(key, _)| equivalent_mapping_key(key) == wanted)
        || mappings(domain).is_some_and(|values| {
            values.iter().any(|(id, mapping)| {
                Some(id.as_str()) != excluded_api_mapping
                    && mapping
                        .get("apiMappingKey")
                        .and_then(Value::as_str)
                        .is_some_and(|key| equivalent_mapping_key(key) == wanted)
            })
        })
}

fn mappings_mut(domain: &mut Value) -> &mut Map<String, Value> {
    if domain
        .get(INTERNAL_MAPPINGS)
        .and_then(Value::as_object)
        .is_none()
    {
        domain[INTERNAL_MAPPINGS] = json!({});
    }
    domain[INTERNAL_MAPPINGS].as_object_mut().unwrap()
}

fn reject_private_domain_configurations(body: &Value) -> Result<(), ApiGwError> {
    if body
        .get("domainNameConfigurations")
        .and_then(Value::as_array)
        .is_some_and(|configs| {
            configs
                .iter()
                .any(|config| config.get("endpointType").and_then(Value::as_str) == Some("PRIVATE"))
        })
    {
        return Err(ApiGwError::BadRequest(
            "PRIVATE custom domains are not supported".into(),
        ));
    }
    Ok(())
}

pub async fn create_domain_name(ctx: &Ctx<'_>, body: &Value) -> Out {
    let domain_name = req_str(body, "domainName")?;
    check_type(body, "domainNameConfigurations", Value::is_array)?;
    reject_private_domain_configurations(body)?;
    check_type(body, "mutualTlsAuthentication", Value::is_object)?;
    check_type(body, "tags", Value::is_object)?;
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    if guard.domains.keys().any(|existing| {
        crate::domains::canonical(existing) == crate::domains::canonical(domain_name)
    }) {
        return Err(ApiGwError::Conflict(format!(
            "Domain name already exists: {domain_name}"
        )));
    }
    let binding = crate::domains::http_binding(ctx, body, None)?;
    let mut domain = json!({
        "domainName": domain_name,
        "apiMappingSelectionExpression": "$request.basepath",
        "domainNameConfigurations": body["domainNameConfigurations"].clone(),
        "tags": body.get("tags").cloned().unwrap_or(json!({})),
    });
    domain["domainNameConfigurations"][0]["apiGatewayDomainName"] = json!(binding.target);
    domain["domainNameConfigurations"][0]["hostedZoneId"] = json!(binding.zone);
    domain["domainNameConfigurations"][0]["endpointType"] = json!("REGIONAL");
    domain["domainNameConfigurations"][0]["securityPolicy"] = json!("TLS_1_2");
    domain["domainNameConfigurations"][0]["domainNameStatus"] = json!("AVAILABLE");
    ctx.domains.publish(binding)?;
    domain[INTERNAL_MAPPINGS] = json!({});
    domain[INTERNAL_BASE_PATH_MAPPINGS] = json!({});
    if let Some(value) = body.get("mutualTlsAuthentication") {
        domain["mutualTlsAuthentication"] = value.clone();
    }
    guard
        .domains
        .insert(domain_name.to_string(), domain.clone());
    Ok((201, public_domain(&domain)))
}

pub async fn get_domain_names(ctx: &Ctx<'_>) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    let items: Vec<Value> = guard.domains.values().map(public_domain).collect();
    Ok((200, json!({ "items": items })))
}

pub async fn get_domain_name(ctx: &Ctx<'_>, domain_name: &str) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    guard
        .domains
        .get(domain_name)
        .map(public_domain)
        .map(|value| (200, value))
        .ok_or_else(|| ApiGwError::NotFound(format!("Invalid domain name {domain_name}")))
}

pub async fn update_domain_name(ctx: &Ctx<'_>, domain_name: &str, body: &Value) -> Out {
    check_type(body, "domainNameConfigurations", Value::is_array)?;
    reject_private_domain_configurations(body)?;
    check_type(body, "mutualTlsAuthentication", Value::is_object)?;
    check_type(body, "tags", Value::is_object)?;
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    let domain = guard
        .domains
        .get_mut(domain_name)
        .ok_or_else(|| ApiGwError::NotFound(format!("Invalid domain name {domain_name}")))?;
    let mut updated = domain.clone();
    copy_fields(
        &mut updated,
        body,
        &[
            "domainNameConfigurations",
            "mutualTlsAuthentication",
            "tags",
        ],
    );
    let target = domain
        .pointer("/domainNameConfigurations/0/apiGatewayDomainName")
        .and_then(Value::as_str);
    let binding = crate::domains::http_binding(ctx, &updated, target)?;
    updated["domainNameConfigurations"][0]["apiGatewayDomainName"] = json!(binding.target);
    updated["domainNameConfigurations"][0]["hostedZoneId"] = json!(binding.zone);
    updated["domainNameConfigurations"][0]["endpointType"] = json!("REGIONAL");
    updated["domainNameConfigurations"][0]["securityPolicy"] = json!("TLS_1_2");
    updated["domainNameConfigurations"][0]["domainNameStatus"] = json!("AVAILABLE");
    ctx.domains.publish(binding)?;
    *domain = updated.clone();
    Ok((200, public_domain(&updated)))
}

pub async fn delete_domain_name(ctx: &Ctx<'_>, domain_name: &str) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    if !guard.domains.contains_key(domain_name) {
        return Err(ApiGwError::NotFound(format!(
            "Invalid domain name {domain_name}"
        )));
    }
    ctx.domains.remove(ctx.account, ctx.region, domain_name)?;
    guard.domains.remove(domain_name);
    Ok((204, json!({})))
}

async fn validate_mapping_target(
    ctx: &Ctx<'_>,
    api_id: &str,
    stage_name: &str,
) -> Result<(), ApiGwError> {
    let record = api(ctx, api_id).await?;
    if !record.read().await.stages.contains_key(stage_name) {
        return Err(ApiGwError::NotFound(format!(
            "Invalid stage identifier specified {stage_name}"
        )));
    }
    Ok(())
}

pub async fn create_api_mapping(ctx: &Ctx<'_>, domain_name: &str, body: &Value) -> Out {
    let api_id = req_str(body, "apiId")?;
    let stage = req_str(body, "stage")?;
    let mapping_key = body
        .get("apiMappingKey")
        .and_then(Value::as_str)
        .unwrap_or("");
    validate_mapping_target(ctx, api_id, stage).await?;
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    let domain = guard
        .domains
        .get_mut(domain_name)
        .ok_or_else(|| ApiGwError::NotFound(format!("Invalid domain name {domain_name}")))?;
    if has_equivalent_mapping(domain, mapping_key, None) {
        return Err(ApiGwError::Conflict(format!(
            "ApiMappingKey already exists: {mapping_key}"
        )));
    }
    let id = gen_id();
    let mapping = json!({
        "apiId": api_id,
        "apiMappingId": id,
        "apiMappingKey": mapping_key,
        "stage": stage,
    });
    mappings_mut(domain).insert(id, mapping.clone());
    Ok((201, mapping))
}

pub async fn get_api_mappings(ctx: &Ctx<'_>, domain_name: &str) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    let domain = guard
        .domains
        .get(domain_name)
        .ok_or_else(|| ApiGwError::NotFound(format!("Invalid domain name {domain_name}")))?;
    let items: Vec<Value> = mappings(domain)
        .map(|values| values.values().cloned().collect())
        .unwrap_or_default();
    Ok((200, json!({ "items": items })))
}

pub async fn get_api_mapping(ctx: &Ctx<'_>, domain_name: &str, mapping_id: &str) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    guard
        .domains
        .get(domain_name)
        .and_then(mappings)
        .and_then(|values| values.get(mapping_id))
        .cloned()
        .map(|value| (200, value))
        .ok_or_else(|| ApiGwError::NotFound(format!("Invalid API mapping identifier {mapping_id}")))
}

pub async fn update_api_mapping(
    ctx: &Ctx<'_>,
    domain_name: &str,
    mapping_id: &str,
    body: &Value,
) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let current = {
        let guard = shared.read().await;
        guard
            .domains
            .get(domain_name)
            .and_then(mappings)
            .and_then(|values| values.get(mapping_id))
            .cloned()
            .ok_or_else(|| {
                ApiGwError::NotFound(format!("Invalid API mapping identifier {mapping_id}"))
            })?
    };
    let api_id = body
        .get("apiId")
        .or_else(|| current.get("apiId"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiGwError::BadRequest("apiId is required".into()))?;
    let stage = body
        .get("stage")
        .or_else(|| current.get("stage"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiGwError::BadRequest("stage is required".into()))?;
    let mapping_key = body
        .get("apiMappingKey")
        .or_else(|| current.get("apiMappingKey"))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiGwError::BadRequest("apiMappingKey must be a string".into()))?;
    validate_mapping_target(ctx, api_id, stage).await?;
    let mut guard = shared.write().await;
    let domain = guard
        .domains
        .get_mut(domain_name)
        .ok_or_else(|| ApiGwError::NotFound(format!("Invalid domain name {domain_name}")))?;
    if has_equivalent_mapping(domain, mapping_key, Some(mapping_id)) {
        return Err(ApiGwError::Conflict(format!(
            "ApiMappingKey already exists: {mapping_key}"
        )));
    }
    let values = mappings_mut(domain);
    let mapping = values.get_mut(mapping_id).ok_or_else(|| {
        ApiGwError::NotFound(format!("Invalid API mapping identifier {mapping_id}"))
    })?;
    copy_fields(mapping, body, &["apiId", "apiMappingKey", "stage"]);
    Ok((200, mapping.clone()))
}

pub async fn delete_api_mapping(ctx: &Ctx<'_>, domain_name: &str, mapping_id: &str) -> Out {
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let mut guard = shared.write().await;
    let domain = guard
        .domains
        .get_mut(domain_name)
        .ok_or_else(|| ApiGwError::NotFound(format!("Invalid domain name {domain_name}")))?;
    if mappings_mut(domain).remove(mapping_id).is_none() {
        return Err(ApiGwError::NotFound(format!(
            "Invalid API mapping identifier {mapping_id}"
        )));
    }
    Ok((204, json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_proxy_requires_http_uri() {
        let body = json!({
            "integrationType": "HTTP_PROXY",
            "integrationUri": "arn:aws:lambda:us-east-1:0:function:f"
        });
        assert!(validate_integration(&body, "HTTP", None).is_err());
    }

    #[test]
    fn lambda_proxy_accepts_arn_and_defaults_payload_version() {
        let body = json!({
            "integrationType": "AWS_PROXY",
            "integrationUri": "arn:aws:lambda:us-east-1:0:function:f"
        });
        assert!(validate_integration(&body, "HTTP", None).is_ok());
        assert_eq!(
            integration_value(&body, "HTTP", "id".into())["payloadFormatVersion"],
            "2.0"
        );
    }

    #[test]
    fn public_domain_hides_mapping_storage() {
        let mut domain = json!({"domainName": "api.example.com"});
        domain[INTERNAL_MAPPINGS] = json!({"id": {}});
        domain[INTERNAL_BASE_PATH_MAPPINGS] = json!({"base": {}});
        let public = public_domain(&domain);
        assert!(public.get(INTERNAL_MAPPINGS).is_none());
        assert!(public.get(INTERNAL_BASE_PATH_MAPPINGS).is_none());
    }

    #[test]
    fn auto_deploy_repoints_every_enabled_stage() {
        let mut record = ApiV2Record::default();
        record.stages.insert(
            "one".into(),
            json!({"stageName": "one", "autoDeploy": true}),
        );
        record.stages.insert(
            "two".into(),
            json!({"stageName": "two", "autoDeploy": true}),
        );
        record.stages.insert(
            "manual".into(),
            json!({"stageName": "manual", "autoDeploy": false}),
        );

        auto_deploy(&mut record);

        assert_eq!(record.deployments.len(), 1);
        let deployment_id = record.deployments.keys().next().unwrap();
        assert_eq!(record.stages["one"]["deploymentId"], *deployment_id);
        assert_eq!(record.stages["two"]["deploymentId"], *deployment_id);
        assert!(record.stages["manual"].get("deploymentId").is_none());
    }
}
