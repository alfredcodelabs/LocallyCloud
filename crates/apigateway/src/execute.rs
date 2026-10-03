//! REST API v1 and HTTP API v2 execute paths.

use std::collections::BTreeMap;
use std::sync::Weak;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, Method, Uri};
use regex::Regex;
use serde_json::{json, Map, Value};
use tokio::time::timeout;

use locallycloud_core::registry::ServiceRegistry;
use locallycloud_wafv2::{WafDecision, WafEvaluator, WafRequest};

use crate::auth::{policy_allows, AuthOutcome, JwtConfig, JwtValidator};
use crate::logging::{
    emit as emit_logs, http_stage_logging, request_source_ip, request_user_agent,
    rest_stage_logging, RequestLogValues, StageLogging,
};
use crate::proxy_event::{
    build_event, interpret_response, percent_decode, EventInput, ProxyResponse,
};
use crate::store::ApiGwStore;
use crate::vtl::{ContextBinding, InputBinding, UtilBinding, VtlContext, VtlEngine};

pub struct ExecuteCtx<'a> {
    pub store: &'a ApiGwStore,
    pub validator: &'a JwtValidator,
    pub http: &'a reqwest::Client,
    pub registry: &'a Weak<ServiceRegistry>,
    pub account: &'a str,
    pub region: &'a str,
    pub request_id: &'a str,
    pub waf: Option<std::sync::Arc<dyn WafEvaluator>>,
    pub trusted_peer_ip: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiKind {
    Rest,
    Http,
}

#[derive(Debug)]
struct InvokeTarget<'a> {
    api_id: &'a str,
    stage: Option<&'a str>,
    path: String,
    kind: Option<ApiKind>,
}

struct IncomingRequest<'a> {
    method: &'a Method,
    host: &'a str,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    body: Bytes,
}

struct InvocationLogContext {
    settings: StageLogging,
    stage: String,
    path: String,
    resource_path: Option<String>,
    route_key: Option<String>,
    method: String,
    domain_name: String,
    source_ip: Option<String>,
    user_agent: Option<String>,
    cors: Option<Value>,
    request_headers: HeaderMap,
    is_http: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct RouteMatch {
    pub(crate) template: String,
    pub(crate) resource_id: String,
    pub(crate) params: BTreeMap<String, String>,
    pub(crate) value: Value,
}

#[derive(Debug)]
struct LambdaOutput {
    status: u16,
    headers: HeaderMap,
    function_error: bool,
    body: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AwsIntegrationOperation<'a> {
    Lambda,
    Action(&'a str),
    Path(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AwsIntegrationUri<'a> {
    region: &'a str,
    service: &'a str,
    operation: AwsIntegrationOperation<'a>,
}

#[derive(Debug, Clone, Copy)]
enum InvokeFailure {
    Configuration,
    Dispatch,
    Timeout,
}

#[derive(Debug, Default)]
struct AuthContext {
    jwt: Option<(Value, Vec<String>)>,
    lambda: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValidationFailure {
    Parameters(Vec<String>),
    Body,
}

impl ValidationFailure {
    fn response_type(&self) -> &'static str {
        match self {
            Self::Parameters(_) => "BAD_REQUEST_PARAMETERS",
            Self::Body => "BAD_REQUEST_BODY",
        }
    }

    fn message(&self) -> String {
        match self {
            Self::Parameters(names) => {
                format!(
                    "Missing required request parameters: [{}]",
                    names.join(", ")
                )
            }
            Self::Body => "Invalid request body".to_string(),
        }
    }
}

fn safe_response(builder: http::response::Builder, body: Body) -> Response {
    builder.body(body).unwrap_or_else(|_| {
        let mut response = Response::new(Body::from(
            json!({ "message": "Internal server error" }).to_string(),
        ));
        *response.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response
    })
}

fn plain(status: u16, message: &str) -> Response {
    safe_response(
        http::Response::builder()
            .status(status)
            .header("content-type", "application/json"),
        Body::from(json!({ "message": message }).to_string()),
    )
}

fn api_id_from_host(host: &str) -> Option<&str> {
    let host = host.split(':').next().unwrap_or(host);
    let lower = host.to_ascii_lowercase();
    let idx = lower.find(".execute-api.")?;
    let label = &host[..idx];
    (!label.is_empty()).then_some(label)
}

fn invocation_target<'a>(host: &'a str, path: &'a str) -> Option<InvokeTarget<'a>> {
    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if segments.first() == Some(&"restapis") && segments.len() >= 3 {
        let offset = if segments.get(3) == Some(&"_user_request_") {
            4
        } else {
            3
        };
        return Some(InvokeTarget {
            api_id: segments[1],
            stage: Some(segments[2]),
            path: resource_path(&segments[offset..]),
            kind: Some(ApiKind::Rest),
        });
    }
    if segments.first() == Some(&"execute-api") && segments.len() >= 3 {
        return Some(InvokeTarget {
            api_id: segments[1],
            stage: Some(segments[2]),
            path: resource_path(&segments[3..]),
            kind: Some(ApiKind::Http),
        });
    }
    api_id_from_host(host).map(|api_id| InvokeTarget {
        api_id,
        stage: None,
        path: path.to_string(),
        kind: None,
    })
}

fn resource_path(segments: &[&str]) -> String {
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn stage_vars(stage: &Value) -> BTreeMap<String, String> {
    stage
        .get("variables")
        .or_else(|| stage.get("stageVariables"))
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
        .collect()
}

fn split_stage<'a>(
    target: &InvokeTarget<'a>,
    stages: &'a BTreeMap<String, Value>,
) -> Option<(String, String, &'a Value)> {
    if let Some(stage) = target.stage {
        return stages
            .get(stage)
            .map(|value| (stage.to_string(), target.path.clone(), value));
    }
    let parts: Vec<&str> = target
        .path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if let Some(first) = parts.first().filter(|name| stages.contains_key(**name)) {
        let value = stages.get(*first)?;
        return Some((first.to_string(), resource_path(&parts[1..]), value));
    }
    stages
        .get("$default")
        .map(|value| ("$default".to_string(), target.path.clone(), value))
}

fn match_template(template: &str, path: &str) -> Option<(Vec<u8>, BTreeMap<String, String>)> {
    let wanted: Vec<&str> = template
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let actual: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let mut score = Vec::with_capacity(wanted.len());
    let mut params = BTreeMap::new();
    let mut index = 0;
    for part in wanted {
        if let Some(name) = part
            .strip_prefix('{')
            .and_then(|part| part.strip_suffix("+}"))
        {
            if index >= actual.len() {
                return None;
            }
            params.insert(name.to_string(), actual[index..].join("/"));
            score.push(1);
            index = actual.len();
            break;
        }
        let current = actual.get(index)?;
        if let Some(name) = part
            .strip_prefix('{')
            .and_then(|part| part.strip_suffix('}'))
        {
            params.insert(name.to_string(), (*current).to_string());
            score.push(2);
        } else if part == *current {
            score.push(3);
        } else {
            return None;
        }
        index += 1;
    }
    (index == actual.len()).then_some((score, params))
}

pub(crate) fn best_match<'a, I>(entries: I, path: &str) -> Option<RouteMatch>
where
    I: Iterator<Item = (&'a str, &'a Value)>,
{
    entries
        .filter_map(|(template, value)| {
            match_template(template, path)
                .map(|(score, params)| (score, template.to_string(), params, value))
        })
        .max_by(|left, right| left.0.cmp(&right.0).then(left.1.len().cmp(&right.1.len())))
        .map(|(_, template, params, value)| {
            let resource_id = value
                .get("id")
                .or_else(|| value.get("routeId"))
                .and_then(Value::as_str)
                .unwrap_or(&template)
                .to_string();
            RouteMatch {
                template,
                resource_id,
                params,
                value: value.clone(),
            }
        })
}

fn rest_route(
    resources: &BTreeMap<String, Value>,
    method: &Method,
    path: &str,
) -> Option<RouteMatch> {
    let mut matched = best_match(
        resources
            .values()
            .filter_map(|resource| Some((resource.get("path")?.as_str()?, resource))),
        path,
    )?;
    let methods = matched.value.get("resourceMethods")?.as_object()?;
    let selected = methods
        .get(method.as_str())
        .or_else(|| methods.get("ANY"))?
        .clone();
    matched.value = selected;
    Some(matched)
}

pub(crate) fn http_route(
    routes: &BTreeMap<String, Value>,
    method: &Method,
    path: &str,
) -> Option<RouteMatch> {
    routes
        .values()
        .filter_map(|route| {
            let key = route.get("routeKey")?.as_str()?;
            let (route_method, template) = key.split_once(' ')?;
            if route_method != method.as_str() && route_method != "ANY" {
                return None;
            }
            let (score, params) = match_template(template, path)?;
            Some((
                score,
                route_method == method.as_str(),
                template.to_string(),
                params,
                route,
            ))
        })
        .max_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then(left.1.cmp(&right.1))
                .then(left.2.len().cmp(&right.2.len()))
        })
        .map(|(_, _, template, params, route)| RouteMatch {
            resource_id: route
                .get("routeId")
                .and_then(Value::as_str)
                .unwrap_or(&template)
                .to_string(),
            template,
            params,
            value: route.clone(),
        })
        .or_else(|| {
            routes.values().find_map(|route| {
                (route.get("routeKey").and_then(Value::as_str) == Some("$default")).then(|| {
                    RouteMatch {
                        resource_id: route
                            .get("routeId")
                            .and_then(Value::as_str)
                            .unwrap_or("$default")
                            .to_string(),
                        template: "$default".to_string(),
                        params: BTreeMap::new(),
                        value: route.clone(),
                    }
                })
            })
        })
}

pub async fn invoke(
    ctx: &ExecuteCtx<'_>,
    method: &Method,
    host: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
    custom_domain: bool,
) -> Response {
    let target = match invocation_target(host, uri.path()) {
        Some(target) => target,
        None => return plain(404, "Not Found"),
    };
    let incoming = IncomingRequest {
        method,
        host,
        uri,
        headers,
        body,
    };
    if target.kind != Some(ApiKind::Http) {
        if let Some(record) = ctx.store.rest(ctx.account, ctx.region, target.api_id) {
            return invoke_rest(ctx, &target, record, incoming, custom_domain).await;
        }
    }
    if target.kind != Some(ApiKind::Rest) {
        if let Some(record) = ctx.store.v2(ctx.account, ctx.region, target.api_id) {
            return invoke_http(ctx, &target, record, incoming, custom_domain).await;
        }
    }
    plain(404, "Not Found")
}

async fn finish_logging(
    ctx: &ExecuteCtx<'_>,
    response: Response,
    logging: InvocationLogContext,
) -> Response {
    if !logging.settings.enabled() {
        return response;
    }
    let status = response.status().as_u16();
    let (parts, body) = response.into_parts();
    let body = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(request_id = ctx.request_id, cause = %error, "failed to buffer response for API Gateway logging");
            return logging_failure(&logging);
        }
    };
    let values = RequestLogValues {
        request_id: ctx.request_id,
        status,
        method: &logging.method,
        path: &logging.path,
        resource_path: logging.resource_path.as_deref(),
        route_key: logging.route_key.as_deref(),
        stage: &logging.stage,
        protocol: "HTTP/1.1",
        domain_name: &logging.domain_name,
        source_ip: logging.source_ip.as_deref(),
        user_agent: logging.user_agent.as_deref(),
        response_length: body.len(),
        integration_status: logging.resource_path.as_ref().map(|_| status),
    };
    if let Err(error) = emit_logs(
        ctx.registry,
        ctx.account,
        ctx.region,
        &logging.settings,
        &values,
    )
    .await
    {
        tracing::warn!(request_id = ctx.request_id, cause = %error, "API Gateway log delivery failed");
        return logging_failure(&logging);
    }
    Response::from_parts(parts, Body::from(body))
}

fn logging_failure(logging: &InvocationLogContext) -> Response {
    let response = plain(500, "Internal Server Error");
    if logging.is_http {
        with_cors(response, logging.cors.as_ref(), &logging.request_headers)
    } else {
        response
    }
}

async fn invoke_rest(
    ctx: &ExecuteCtx<'_>,
    target: &InvokeTarget<'_>,
    record: std::sync::Arc<tokio::sync::RwLock<crate::store::RestApiRecord>>,
    incoming: IncomingRequest<'_>,
    custom_domain: bool,
) -> Response {
    let logging = {
        let guard = record.read().await;
        split_stage(target, &guard.stages).map(|(stage, path, stage_value)| {
            let settings =
                rest_stage_logging(stage_value, ctx.account, ctx.region, target.api_id, &stage)?;
            let snapshot = stage_value
                .get("deploymentId")
                .and_then(Value::as_str)
                .and_then(|deployment_id| guard.deployment_snapshots.get(deployment_id).cloned())
                .or_else(|| {
                    stage_value
                        .get("deploymentId")
                        .is_none()
                        .then(|| guard.snapshot())
                });
            let route = snapshot
                .as_ref()
                .and_then(|snapshot| rest_route(&snapshot.resources, incoming.method, &path));
            Ok::<_, crate::error::ApiGwError>(InvocationLogContext {
                settings,
                stage,
                path,
                resource_path: route.as_ref().map(|route| route.template.clone()),
                route_key: route
                    .as_ref()
                    .map(|route| format!("{} {}", incoming.method.as_str(), route.template)),
                method: incoming.method.as_str().to_string(),
                domain_name: incoming
                    .host
                    .split(':')
                    .next()
                    .unwrap_or(incoming.host)
                    .to_string(),
                source_ip: request_source_ip(incoming.headers).map(str::to_string),
                user_agent: request_user_agent(incoming.headers).map(str::to_string),
                cors: None,
                request_headers: incoming.headers.clone(),
                is_http: false,
            })
        })
    };
    let logging = match logging.transpose() {
        Ok(logging) => logging,
        Err(error) => {
            tracing::warn!(request_id = ctx.request_id, cause = %error, "invalid stored API Gateway logging configuration");
            return plain(500, "Internal Server Error");
        }
    };
    let response = invoke_rest_inner(ctx, target, record, incoming, custom_domain).await;
    match logging {
        Some(logging) => finish_logging(ctx, response, logging).await,
        None => response,
    }
}

async fn invoke_rest_inner(
    ctx: &ExecuteCtx<'_>,
    target: &InvokeTarget<'_>,
    record: std::sync::Arc<tokio::sync::RwLock<crate::store::RestApiRecord>>,
    incoming: IncomingRequest<'_>,
    custom_domain: bool,
) -> Response {
    let IncomingRequest {
        method,
        host,
        uri,
        headers,
        body,
    } = incoming;
    let guard = record.read().await;
    if !custom_domain
        && guard
            .api
            .get("disableExecuteApiEndpoint")
            .and_then(Value::as_bool)
            == Some(true)
    {
        return plain(403, "Forbidden");
    }
    let (stage, path, stage_value) = match split_stage(target, &guard.stages) {
        Some(value) => value,
        None => {
            return rest_error(
                &guard.gateway_responses,
                "MISSING_AUTHENTICATION_TOKEN",
                403,
                "Missing Authentication Token",
            )
        }
    };
    if let Some(waf) = ctx.waf.as_ref() {
        let resource_arn = format!(
            "arn:aws:apigateway:{}::/restapis/{}/stages/{}",
            ctx.region, target.api_id, stage
        );
        let decision = waf.evaluate(&WafRequest {
            account_id: ctx.account,
            region: ctx.region,
            resource_arn: &resource_arn,
            source_ip: ctx.trusted_peer_ip.unwrap_or(""),
            method: method.as_str(),
            uri_path: &path,
            headers,
        });
        if !matches!(decision, Ok(WafDecision::Unassociated | WafDecision::Allow)) {
            return plain(403, "Forbidden");
        }
    }
    let variables = stage_vars(stage_value);
    let snapshot = match stage_value.get("deploymentId").and_then(Value::as_str) {
        Some(deployment_id) => match guard.deployment_snapshots.get(deployment_id) {
            Some(snapshot) => snapshot.clone(),
            None => return plain(500, "Internal server error"),
        },
        None => guard.snapshot(),
    };
    drop(guard);
    let route = match rest_route(&snapshot.resources, method, &path) {
        Some(route) => route,
        None => {
            return rest_error(
                &snapshot.gateway_responses,
                "MISSING_AUTHENTICATION_TOKEN",
                403,
                "Missing Authentication Token",
            )
        }
    };
    let gateway_responses = snapshot.gateway_responses.clone();
    if route
        .value
        .get("apiKeyRequired")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && !valid_api_key(ctx, target.api_id, &stage, headers).await
    {
        return rest_error(&gateway_responses, "INVALID_API_KEY", 403, "Forbidden");
    }
    if let Err(failure) = validate_request(
        &snapshot.request_validators,
        &snapshot.models,
        &route.value,
        &route.params,
        uri,
        headers,
        &body,
    ) {
        return rest_error(
            &gateway_responses,
            failure.response_type(),
            400,
            &failure.message(),
        );
    }
    let integration = match route.value.get("methodIntegration").cloned() {
        Some(value) => value,
        None => {
            return rest_error(
                &gateway_responses,
                "INTEGRATION_FAILURE",
                500,
                "Internal server error",
            )
        }
    };
    let authorizer = route
        .value
        .get("authorizerId")
        .and_then(Value::as_str)
        .and_then(|id| {
            snapshot
                .authorizers
                .get(id)
                .map(|value| (id.to_string(), value.clone()))
        });

    let auth_type = route
        .value
        .get("authorizationType")
        .and_then(Value::as_str)
        .unwrap_or("NONE");
    if !matches!(auth_type, "NONE" | "CUSTOM") {
        return rest_error(&gateway_responses, "ACCESS_DENIED", 403, "Forbidden");
    }
    let auth = if auth_type == "CUSTOM" {
        match authorizer {
            Some((id, authorizer)) => match lambda_authorize(
                ctx,
                ApiKind::Rest,
                target.api_id,
                &id,
                &authorizer,
                method,
                host,
                &stage,
                &path,
                uri,
                headers,
                &body,
                &route.template,
                &route.params,
                &variables,
            )
            .await
            {
                Ok(auth) => auth,
                Err(status) => {
                    return rest_error(
                        &gateway_responses,
                        if status == 401 {
                            "UNAUTHORIZED"
                        } else {
                            "ACCESS_DENIED"
                        },
                        status,
                        if status == 401 {
                            "Unauthorized"
                        } else {
                            "Forbidden"
                        },
                    )
                }
            },
            None => {
                return rest_error(
                    &gateway_responses,
                    "AUTHORIZER_FAILURE",
                    500,
                    "Internal server error",
                )
            }
        }
    } else {
        AuthContext::default()
    };

    let request = IntegrationRequest {
        method,
        host,
        uri,
        headers,
        body,
        api_id: target.api_id,
        stage: &stage,
        path: &path,
        route_template: &route.template,
        resource_id: &route.resource_id,
        path_params: &route.params,
        variables: &variables,
        auth,
    };
    execute_rest_integration(ctx, &integration, &gateway_responses, request).await
}

struct IntegrationRequest<'a> {
    method: &'a Method,
    host: &'a str,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    body: Bytes,
    api_id: &'a str,
    stage: &'a str,
    path: &'a str,
    route_template: &'a str,
    resource_id: &'a str,
    path_params: &'a BTreeMap<String, String>,
    variables: &'a BTreeMap<String, String>,
    auth: AuthContext,
}

fn rest_error(
    responses: &BTreeMap<String, Value>,
    response_type: &str,
    default_status: u16,
    default_message: &str,
) -> Response {
    let configured = responses.get(response_type).or_else(|| {
        responses.get(if default_status >= 500 {
            "DEFAULT_5XX"
        } else {
            "DEFAULT_4XX"
        })
    });
    let status = configured
        .and_then(|value| value.get("statusCode"))
        .and_then(|value| {
            value
                .as_str()
                .and_then(|value| value.parse().ok())
                .or_else(|| value.as_u64().map(|value| value as u16))
        })
        .unwrap_or(default_status);
    let template = configured
        .and_then(|value| value.get("responseTemplates"))
        .and_then(Value::as_object)
        .and_then(|templates| templates.get("application/json"))
        .and_then(Value::as_str);
    let body = template
        .map(|template| {
            template
                .replace(
                    "$context.error.messageString",
                    &json!(default_message).to_string(),
                )
                .replace("$context.error.message", default_message)
        })
        .unwrap_or_else(|| json!({ "message": default_message }).to_string());
    let mut builder = http::Response::builder()
        .status(status)
        .header("content-type", "application/json");
    if let Some(parameters) = configured
        .and_then(|value| value.get("responseParameters"))
        .and_then(Value::as_object)
    {
        for (name, value) in parameters {
            if let (Some(name), Some(value)) = (
                name.strip_prefix("gatewayresponse.header."),
                value.as_str().map(unquote),
            ) {
                builder = builder.header(name, value);
            }
        }
    }
    safe_response(builder, Body::from(body))
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .unwrap_or(value)
}

pub(crate) fn validate_request(
    request_validators: &BTreeMap<String, Value>,
    models: &BTreeMap<String, Value>,
    method: &Value,
    path: &BTreeMap<String, String>,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), ValidationFailure> {
    let validator = match method
        .get("requestValidatorId")
        .and_then(Value::as_str)
        .and_then(|id| request_validators.get(id))
    {
        Some(value) => value,
        None => return Ok(()),
    };
    if validator
        .get("validateRequestParameters")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let query = query_map(uri.query().unwrap_or(""));
        let mut missing = Vec::new();
        for (name, required) in method
            .get("requestParameters")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            if !required.as_bool().unwrap_or(false) {
                continue;
            }
            let present = name
                .strip_prefix("method.request.header.")
                .is_some_and(|name| headers.get(name).is_some())
                || name
                    .strip_prefix("method.request.querystring.")
                    .is_some_and(|name| query.contains_key(name))
                || name
                    .strip_prefix("method.request.path.")
                    .is_some_and(|name| path.contains_key(name));
            if !present {
                missing.push(name.clone());
            }
        }
        if !missing.is_empty() {
            missing.sort();
            return Err(ValidationFailure::Parameters(missing));
        }
    }
    if validator
        .get("validateRequestBody")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let request_models = method.get("requestModels").and_then(Value::as_object);
        let content_type = content_type(headers).unwrap_or("application/json");
        let model_name = request_models.and_then(|request_models| {
            request_models
                .get(content_type)
                .or_else(|| request_models.get("application/json"))
                .and_then(Value::as_str)
        });
        if let Some(model) = model_name.and_then(|name| models.get(name)) {
            let schema = model.get("schema").unwrap_or(model);
            let schema: Value = match schema {
                Value::String(schema) => {
                    serde_json::from_str(schema).map_err(|_| ValidationFailure::Body)?
                }
                schema => schema.clone(),
            };
            let instance: Value =
                serde_json::from_slice(body).map_err(|_| ValidationFailure::Body)?;
            let validator =
                jsonschema::validator_for(&schema).map_err(|_| ValidationFailure::Body)?;
            if !validator.is_valid(&instance) {
                return Err(ValidationFailure::Body);
            }
        }
    }
    Ok(())
}

pub(crate) async fn valid_api_key(
    ctx: &ExecuteCtx<'_>,
    api_id: &str,
    stage: &str,
    headers: &HeaderMap,
) -> bool {
    let supplied = match headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
    {
        Some(value) if !value.is_empty() => value,
        _ => return false,
    };
    let shared = ctx.store.shared(ctx.account, ctx.region);
    let guard = shared.read().await;
    let key = guard.api_keys.values().find(|key| {
        key.get("enabled").and_then(Value::as_bool).unwrap_or(true)
            && key.get("value").and_then(Value::as_str) == Some(supplied)
    });
    let key = match key {
        Some(key) => key,
        None => return false,
    };
    let key_id = key.get("id").and_then(Value::as_str).unwrap_or(supplied);
    guard.usage_plans.iter().any(|(plan_id, plan)| {
        let associated_in_control_plane = plan
            .get("__keys")
            .and_then(Value::as_object)
            .is_some_and(|keys| keys.contains_key(key_id));
        plan_covers(plan, api_id, stage)
            && (associated_in_control_plane
                || value_list_contains(plan.get("keys"), key_id)
                || value_list_contains(plan.get("apiKeys"), key_id)
                || value_list_contains(plan.get("usagePlanKeys"), key_id)
                || value_list_contains(key.get("usagePlanIds"), plan_id)
                || plan.get("keyId").and_then(Value::as_str) == Some(key_id))
    })
}

fn plan_covers(plan: &Value, api_id: &str, stage: &str) -> bool {
    plan.get("apiStages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|entry| {
            entry.get("apiId").and_then(Value::as_str) == Some(api_id)
                && entry
                    .get("stage")
                    .and_then(Value::as_str)
                    .is_none_or(|configured| configured == stage)
        })
}

fn value_list_contains(value: Option<&Value>, wanted: &str) -> bool {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|value| {
            value.as_str() == Some(wanted)
                || value.get("id").and_then(Value::as_str) == Some(wanted)
                || value.get("keyId").and_then(Value::as_str) == Some(wanted)
        })
}

async fn invoke_http(
    ctx: &ExecuteCtx<'_>,
    target: &InvokeTarget<'_>,
    record: std::sync::Arc<tokio::sync::RwLock<crate::store::ApiV2Record>>,
    incoming: IncomingRequest<'_>,
    custom_domain: bool,
) -> Response {
    let logging = {
        let guard = record.read().await;
        split_stage(target, &guard.stages).map(|(stage, path, stage_value)| {
            let settings = http_stage_logging(
                stage_value,
                ctx.account,
                ctx.region,
                guard
                    .api
                    .get("protocolType")
                    .and_then(Value::as_str)
                    .unwrap_or("HTTP"),
            )?;
            let snapshot = stage_value
                .get("deploymentId")
                .and_then(Value::as_str)
                .and_then(|deployment_id| guard.deployment_snapshots.get(deployment_id).cloned())
                .or_else(|| {
                    stage_value
                        .get("deploymentId")
                        .is_none()
                        .then(|| guard.snapshot())
                });
            let cors = snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.api.get("corsConfiguration").cloned());
            let route = if incoming.method == Method::OPTIONS && cors.is_some() {
                None
            } else {
                snapshot
                    .as_ref()
                    .and_then(|snapshot| http_route(&snapshot.routes, incoming.method, &path))
            };
            Ok::<_, crate::error::ApiGwError>(InvocationLogContext {
                settings,
                stage,
                path,
                resource_path: route.as_ref().map(|route| route.template.clone()),
                route_key: route.as_ref().and_then(|route| {
                    route
                        .value
                        .get("routeKey")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                }),
                method: incoming.method.as_str().to_string(),
                domain_name: incoming
                    .host
                    .split(':')
                    .next()
                    .unwrap_or(incoming.host)
                    .to_string(),
                source_ip: request_source_ip(incoming.headers).map(str::to_string),
                user_agent: request_user_agent(incoming.headers).map(str::to_string),
                cors,
                request_headers: incoming.headers.clone(),
                is_http: true,
            })
        })
    };
    let logging = match logging.transpose() {
        Ok(logging) => logging,
        Err(error) => {
            tracing::warn!(request_id = ctx.request_id, cause = %error, "invalid stored API Gateway logging configuration");
            return plain(500, "Internal Server Error");
        }
    };
    let response = invoke_http_inner(ctx, target, record, incoming, custom_domain).await;
    match logging {
        Some(logging) => finish_logging(ctx, response, logging).await,
        None => response,
    }
}

async fn invoke_http_inner(
    ctx: &ExecuteCtx<'_>,
    target: &InvokeTarget<'_>,
    record: std::sync::Arc<tokio::sync::RwLock<crate::store::ApiV2Record>>,
    incoming: IncomingRequest<'_>,
    custom_domain: bool,
) -> Response {
    let IncomingRequest {
        method,
        host,
        uri,
        headers,
        body,
    } = incoming;
    let guard = record.read().await;
    if !custom_domain
        && guard
            .api
            .get("disableExecuteApiEndpoint")
            .and_then(Value::as_bool)
            == Some(true)
    {
        return plain(403, "Forbidden");
    }
    let (stage, path, stage_value) = match split_stage(target, &guard.stages) {
        Some(value) => value,
        None => return plain(404, "Not Found"),
    };
    let variables = stage_vars(stage_value);
    let snapshot = match stage_value.get("deploymentId").and_then(Value::as_str) {
        Some(deployment_id) => match guard.deployment_snapshots.get(deployment_id) {
            Some(snapshot) => snapshot.clone(),
            None => return plain(500, "Internal Server Error"),
        },
        None => guard.snapshot(),
    };
    drop(guard);
    let cors = snapshot.api.get("corsConfiguration").cloned();
    if method == Method::OPTIONS {
        if let Some(cors) = cors.as_ref() {
            return cors_preflight(cors, headers);
        }
    }
    let route = match http_route(&snapshot.routes, method, &path) {
        Some(route) => route,
        None => return with_cors(plain(404, "Not Found"), cors.as_ref(), headers),
    };
    if route
        .value
        .get("apiKeyRequired")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && !valid_api_key(ctx, target.api_id, &stage, headers).await
    {
        return with_cors(plain(403, "Forbidden"), cors.as_ref(), headers);
    }
    let authorizer = route
        .value
        .get("authorizerId")
        .and_then(Value::as_str)
        .and_then(|id| {
            snapshot
                .authorizers
                .get(id)
                .map(|value| (id.to_string(), value.clone()))
        });
    let target_name = route
        .value
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("");
    let integration_id = target_name.strip_prefix("integrations/").unwrap_or("");
    let integration = match snapshot.integrations.get(integration_id) {
        Some(value) => value.clone(),
        None => return with_cors(plain(500, "Internal Server Error"), cors.as_ref(), headers),
    };

    let auth_type = route
        .value
        .get("authorizationType")
        .and_then(Value::as_str)
        .unwrap_or("NONE");
    let auth = if auth_type == "JWT" {
        match authorizer {
            Some((_, authorizer)) => {
                match jwt_authorize(ctx, &route.value, &authorizer, headers).await {
                    Ok(auth) => auth,
                    Err(status) => {
                        return with_cors(
                            plain(
                                status,
                                if status == 401 {
                                    "Unauthorized"
                                } else {
                                    "Internal Server Error"
                                },
                            ),
                            cors.as_ref(),
                            headers,
                        )
                    }
                }
            }
            None => return with_cors(plain(500, "Internal Server Error"), cors.as_ref(), headers),
        }
    } else if auth_type == "CUSTOM" {
        match authorizer {
            Some((id, authorizer)) => match lambda_authorize(
                ctx,
                ApiKind::Http,
                target.api_id,
                &id,
                &authorizer,
                method,
                host,
                &stage,
                &path,
                uri,
                headers,
                &body,
                &route.template,
                &route.params,
                &variables,
            )
            .await
            {
                Ok(auth) => auth,
                Err(status) => {
                    return with_cors(
                        plain(
                            status,
                            if status == 401 {
                                "Unauthorized"
                            } else {
                                "Forbidden"
                            },
                        ),
                        cors.as_ref(),
                        headers,
                    )
                }
            },
            None => return with_cors(plain(500, "Internal Server Error"), cors.as_ref(), headers),
        }
    } else if auth_type == "NONE" {
        AuthContext::default()
    } else {
        return with_cors(plain(403, "Forbidden"), cors.as_ref(), headers);
    };

    let request = IntegrationRequest {
        method,
        host,
        uri,
        headers,
        body,
        api_id: target.api_id,
        stage: &stage,
        path: &path,
        route_template: &route.template,
        resource_id: &route.resource_id,
        path_params: &route.params,
        variables: &variables,
        auth,
    };
    let response = execute_http_integration(ctx, &integration, request).await;
    with_cors(response, cors.as_ref(), headers)
}

async fn jwt_authorize(
    ctx: &ExecuteCtx<'_>,
    route: &Value,
    authorizer: &Value,
    headers: &HeaderMap,
) -> Result<AuthContext, u16> {
    let cfg = jwt_config(authorizer).ok_or(500u16)?;
    let token = identity_token(authorizer, headers).ok_or(401u16)?;
    let scopes: Vec<String> = route
        .get("authorizationScopes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect();
    match ctx
        .validator
        .authorize_scoped(&token, &cfg, &scopes, ctx.account, ctx.region)
        .await
    {
        AuthOutcome::Allow { claims, scopes } => Ok(AuthContext {
            jwt: Some((claims, scopes)),
            lambda: None,
        }),
        AuthOutcome::Deny(reason) => {
            tracing::info!(request_id = ctx.request_id, reason = %reason, "JWT authorizer denied request");
            Err(401)
        }
        AuthOutcome::Error(reason) => {
            tracing::warn!(request_id = ctx.request_id, reason = %reason, "JWT authorizer failed");
            Err(500)
        }
    }
}

fn jwt_config(authorizer: &Value) -> Option<JwtConfig> {
    let cfg = authorizer.get("jwtConfiguration")?;
    Some(JwtConfig {
        issuer: cfg.get("issuer")?.as_str()?.to_string(),
        audiences: cfg
            .get("audience")?
            .as_array()?
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
    })
}

fn identity_token(authorizer: &Value, headers: &HeaderMap) -> Option<String> {
    identity_values(authorizer, None, headers, &BTreeMap::new())
        .into_iter()
        .next()
        .filter(|value| !value.is_empty())
}

fn cors_preflight(cors: &Value, headers: &HeaderMap) -> Response {
    let origin = headers.get("origin").and_then(|value| value.to_str().ok());
    let requested_method = headers
        .get("access-control-request-method")
        .and_then(|value| value.to_str().ok());
    if !cors_origin(cors, origin) || !cors_allows(cors, "allowMethods", requested_method) {
        return plain(403, "Forbidden");
    }
    with_cors(
        safe_response(http::Response::builder().status(204), Body::empty()),
        Some(cors),
        headers,
    )
}

fn with_cors(
    mut response: Response,
    cors: Option<&Value>,
    request_headers: &HeaderMap,
) -> Response {
    let Some(cors) = cors else { return response };
    let origin = request_headers
        .get("origin")
        .and_then(|value| value.to_str().ok());
    if !cors_origin(cors, origin) {
        return response;
    }
    let allow_origin = if value_array(cors.get("allowOrigins"))
        .iter()
        .any(|value| value == "*")
    {
        "*"
    } else {
        origin.unwrap_or("")
    };
    set_header(&mut response, "access-control-allow-origin", allow_origin);
    for (field, header) in [
        ("allowMethods", "access-control-allow-methods"),
        ("allowHeaders", "access-control-allow-headers"),
        ("exposeHeaders", "access-control-expose-headers"),
    ] {
        let values = value_array(cors.get(field));
        if !values.is_empty() {
            set_header(&mut response, header, &values.join(","));
        }
    }
    if cors.get("allowCredentials").and_then(Value::as_bool) == Some(true) {
        set_header(&mut response, "access-control-allow-credentials", "true");
    }
    if let Some(age) = cors.get("maxAge").and_then(Value::as_u64) {
        set_header(&mut response, "access-control-max-age", &age.to_string());
    }
    response
}

fn set_header(response: &mut Response, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (
        http::header::HeaderName::from_bytes(name.as_bytes()),
        http::HeaderValue::from_str(value),
    ) {
        response.headers_mut().insert(name, value);
    }
}

fn cors_origin(cors: &Value, origin: Option<&str>) -> bool {
    let allowed = value_array(cors.get("allowOrigins"));
    allowed.iter().any(|value| value == "*")
        || origin.is_some_and(|origin| allowed.iter().any(|value| value == origin))
}

fn cors_allows(cors: &Value, field: &str, requested: Option<&str>) -> bool {
    let allowed = value_array(cors.get(field));
    requested.is_none_or(|requested| {
        allowed
            .iter()
            .any(|value| value == "*" || value.eq_ignore_ascii_case(requested))
    })
}

fn value_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn lambda_authorize(
    ctx: &ExecuteCtx<'_>,
    kind: ApiKind,
    api_id: &str,
    authorizer_id: &str,
    authorizer: &Value,
    method: &Method,
    host: &str,
    stage: &str,
    path: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    route_template: &str,
    path_params: &BTreeMap<String, String>,
    stage_variables: &BTreeMap<String, String>,
) -> Result<AuthContext, u16> {
    let query = query_map(uri.query().unwrap_or(""));
    let identities = identity_values(authorizer, Some(&query), headers, path_params);
    if identities.is_empty() || identities.iter().any(String::is_empty) {
        return Err(401);
    }
    let method_arn = format!(
        "arn:aws:execute-api:{}:{}:{}/{}/{}{}",
        ctx.region, ctx.account, api_id, stage, method, path
    );
    let cache_key = format!(
        "{}:{}:{}:{}",
        kind_name(kind),
        authorizer_id,
        method_arn,
        identities.join("\u{1f}")
    );
    let ttl = authorizer
        .get("authorizerResultTtlInSeconds")
        .and_then(Value::as_u64)
        .unwrap_or(300);
    if ttl > 0 {
        let shared = ctx.store.shared(ctx.account, ctx.region);
        let cached = {
            let mut guard = shared.write().await;
            let now = now_secs();
            guard.authorizer_cache.retain(|_, value| {
                value.get("expiresAt").and_then(Value::as_u64).unwrap_or(0) > now
            });
            cached_authorizer(&guard.authorizer_cache, &cache_key)
        };
        if let Some(result) = cached {
            return interpret_authorizer(kind, authorizer, &result, &method_arn);
        }
    }

    let format = authorizer
        .get("authorizerPayloadFormatVersion")
        .and_then(Value::as_str)
        .unwrap_or("2.0");
    let event = if kind == ApiKind::Rest
        && authorizer.get("type").and_then(Value::as_str) == Some("TOKEN")
    {
        json!({
            "type": "TOKEN",
            "authorizationToken": identities[0],
            "methodArn": method_arn,
        })
    } else if kind == ApiKind::Rest {
        json!({
            "type": "REQUEST",
            "methodArn": method_arn,
            "resource": route_template,
            "path": path,
            "httpMethod": method.as_str(),
            "headers": headers_object(headers),
            "multiValueHeaders": multi_headers_object(headers),
            "queryStringParameters": string_object(&query),
            "multiValueQueryStringParameters": multi_query_object(uri.query().unwrap_or("")),
            "pathParameters": string_object(path_params),
            "stageVariables": string_object(stage_variables),
            "requestContext": {
                "accountId": ctx.account,
                "apiId": api_id,
                "httpMethod": method.as_str(),
                "identity": { "sourceIp": source_ip(headers) },
                "path": path,
                "requestId": ctx.request_id,
                "resourcePath": route_template,
                "stage": stage,
            }
        })
    } else {
        let route_key = if route_template == "$default" {
            "$default".to_string()
        } else {
            format!("{} {}", method, route_template)
        };
        let mut event = build_event(
            format,
            &EventInput {
                method: method.as_str(),
                host,
                stage,
                raw_path: path,
                resource_path: path,
                raw_query: uri.query().unwrap_or(""),
                route_key: &route_key,
                headers,
                body,
                account: ctx.account,
                api_id,
                request_id: ctx.request_id,
                jwt: None,
            },
        );
        event["type"] = Value::String("REQUEST".into());
        event["stageVariables"] = string_object(stage_variables);
        event["routeKey"] = Value::String(route_key.clone());
        event["requestContext"]["routeKey"] = Value::String(route_key);
        event["routeArn"] = Value::String(method_arn.clone());
        event["methodArn"] = Value::String(method_arn.clone());
        event["identitySource"] = json!(identities);
        event
    };
    let function = authorizer
        .get("authorizerUri")
        .or_else(|| authorizer.get("authorizerURI"))
        .and_then(Value::as_str)
        .ok_or(500u16)?;
    let output = invoke_lambda(ctx, function, Bytes::from(event.to_string()), 29_000)
        .await
        .map_err(|_| 500u16)?;
    if output.function_error {
        return Err(500);
    }
    let result: Value = serde_json::from_slice(&output.body).map_err(|_| 500u16)?;
    let interpreted = interpret_authorizer(kind, authorizer, &result, &method_arn)?;
    if ttl > 0 {
        const MAX_AUTHORIZER_CACHE_ENTRIES: usize = 1024;
        let shared = ctx.store.shared(ctx.account, ctx.region);
        let mut guard = shared.write().await;
        while guard.authorizer_cache.len() >= MAX_AUTHORIZER_CACHE_ENTRIES {
            let Some(oldest) = guard.authorizer_cache.keys().next().cloned() else {
                break;
            };
            guard.authorizer_cache.remove(&oldest);
        }
        guard.authorizer_cache.insert(
            cache_key,
            json!({ "expiresAt": now_secs() + ttl, "result": result }),
        );
    }
    Ok(interpreted)
}

fn kind_name(kind: ApiKind) -> &'static str {
    match kind {
        ApiKind::Rest => "v1",
        ApiKind::Http => "v2",
    }
}

pub(crate) fn cached_authorizer(cache: &BTreeMap<String, Value>, key: &str) -> Option<Value> {
    let value = cache.get(key)?;
    (value.get("expiresAt")?.as_u64()? > now_secs())
        .then(|| value.get("result").cloned())
        .flatten()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn interpret_authorizer(
    kind: ApiKind,
    authorizer: &Value,
    result: &Value,
    route_arn: &str,
) -> Result<AuthContext, u16> {
    if kind == ApiKind::Http
        && authorizer
            .get("enableSimpleResponses")
            .and_then(Value::as_bool)
            == Some(true)
    {
        if result.get("isAuthorized").and_then(Value::as_bool) != Some(true) {
            return Err(403);
        }
        return Ok(AuthContext {
            jwt: None,
            lambda: Some(result.get("context").cloned().unwrap_or_else(|| json!({}))),
        });
    }
    if !policy_allows(result, route_arn) {
        return Err(403);
    }
    let mut context = result
        .get("context")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(principal_id) = result.get("principalId") {
        context.insert("principalId".into(), principal_id.clone());
    }
    Ok(AuthContext {
        jwt: None,
        lambda: Some(Value::Object(context)),
    })
}

fn identity_values(
    authorizer: &Value,
    query: Option<&BTreeMap<String, String>>,
    headers: &HeaderMap,
    path: &BTreeMap<String, String>,
) -> Vec<String> {
    let sources: Vec<&str> = match authorizer.get("identitySource") {
        Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).collect(),
        Some(Value::String(value)) => value.split(',').map(str::trim).collect(),
        _ => vec!["method.request.header.Authorization"],
    };
    sources
        .into_iter()
        .map(|source| {
            source
                .strip_prefix("$request.header.")
                .or_else(|| source.strip_prefix("method.request.header."))
                .and_then(|name| headers.get(name))
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
                .or_else(|| {
                    source
                        .strip_prefix("$request.querystring.")
                        .or_else(|| source.strip_prefix("method.request.querystring."))
                        .and_then(|name| query.and_then(|query| query.get(name)).cloned())
                })
                .or_else(|| {
                    source
                        .strip_prefix("$request.path.")
                        .or_else(|| source.strip_prefix("method.request.path."))
                        .and_then(|name| path.get(name).cloned())
                })
                .unwrap_or_default()
        })
        .collect()
}

fn query_map(raw: &str) -> BTreeMap<String, String> {
    raw.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
        .map(|(key, value)| (percent_decode(key), percent_decode(value)))
        .collect()
}

fn headers_map(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect()
}

fn headers_object(headers: &HeaderMap) -> Value {
    Value::Object(
        headers_map(headers)
            .into_iter()
            .map(|(key, value)| (key, Value::String(value)))
            .collect(),
    )
}

fn multi_headers_object(headers: &HeaderMap) -> Value {
    let mut object = Map::new();
    for name in headers.keys() {
        let values = headers
            .get_all(name)
            .iter()
            .map(|value| Value::String(String::from_utf8_lossy(value.as_bytes()).into_owned()))
            .collect();
        object.insert(name.to_string(), Value::Array(values));
    }
    if object.is_empty() {
        Value::Null
    } else {
        Value::Object(object)
    }
}

fn multi_query_object(raw: &str) -> Value {
    let mut object = Map::new();
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key);
        if key.is_empty() {
            continue;
        }
        if let Some(values) = object
            .entry(key)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
        {
            values.push(Value::String(percent_decode(value)));
        }
    }
    if object.is_empty() {
        Value::Null
    } else {
        Value::Object(object)
    }
}

fn string_object(values: &BTreeMap<String, String>) -> Value {
    if values.is_empty() {
        Value::Null
    } else {
        Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                .collect(),
        )
    }
}

fn source_ip(headers: &HeaderMap) -> &str {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .unwrap_or("")
}

fn integration_event(
    ctx: &ExecuteCtx<'_>,
    request: &IntegrationRequest<'_>,
    format: &str,
) -> Value {
    let route_key = if request.route_template == "$default" {
        format!("{} {}", request.method, request.path)
    } else {
        format!("{} {}", request.method, request.route_template)
    };
    let mut event = build_event(
        format,
        &EventInput {
            method: request.method.as_str(),
            host: request.host,
            stage: request.stage,
            raw_path: request.path,
            resource_path: request.route_template,
            raw_query: request.uri.query().unwrap_or(""),
            route_key: &route_key,
            headers: request.headers,
            body: &request.body,
            account: ctx.account,
            api_id: request.api_id,
            request_id: ctx.request_id,
            jwt: request.auth.jwt.clone(),
        },
    );
    if format == "1.0" {
        event["requestContext"]["resourceId"] = Value::String(request.resource_id.to_string());
    }
    event["stageVariables"] = string_object(request.variables);
    if let Some(lambda) = &request.auth.lambda {
        if format == "1.0" {
            event["requestContext"]["authorizer"] = lambda.clone();
        } else {
            event["requestContext"]["authorizer"]["lambda"] = lambda.clone();
        }
    }
    event
}

async fn execute_http_integration(
    ctx: &ExecuteCtx<'_>,
    integration: &Value,
    request: IntegrationRequest<'_>,
) -> Response {
    match integration
        .get("integrationType")
        .and_then(Value::as_str)
        .unwrap_or("")
    {
        "AWS_PROXY" => {
            let format = integration
                .get("payloadFormatVersion")
                .and_then(Value::as_str)
                .unwrap_or("2.0");
            let event = integration_event(ctx, &request, format);
            let function = substitute_uri(
                integration
                    .get("integrationUri")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                request.variables,
                request.path_params,
            );
            match invoke_lambda(
                ctx,
                &function,
                Bytes::from(event.to_string()),
                timeout_ms(integration),
            )
            .await
            {
                Ok(output) => render_proxy(interpret_response(
                    format,
                    output.function_error,
                    &output.body,
                )),
                Err(InvokeFailure::Timeout) => plain(504, "Endpoint request timed out"),
                Err(_) => plain(500, "Internal Server Error"),
            }
        }
        "HTTP_PROXY" => {
            let uri = substitute_uri(
                integration
                    .get("integrationUri")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                request.variables,
                request.path_params,
            );
            forward_http(ctx, integration, &request, &uri, request.body.clone()).await
        }
        _ => plain(500, "Internal Server Error"),
    }
}

async fn execute_rest_integration(
    ctx: &ExecuteCtx<'_>,
    integration: &Value,
    gateway_responses: &BTreeMap<String, Value>,
    request: IntegrationRequest<'_>,
) -> Response {
    match integration
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
    {
        "AWS_PROXY" => {
            let event = integration_event(ctx, &request, "1.0");
            let function = substitute_uri(
                integration.get("uri").and_then(Value::as_str).unwrap_or(""),
                request.variables,
                request.path_params,
            );
            match invoke_lambda(
                ctx,
                &function,
                Bytes::from(event.to_string()),
                timeout_ms(integration),
            )
            .await
            {
                Ok(output) => render_proxy(interpret_response(
                    "1.0",
                    output.function_error,
                    &output.body,
                )),
                Err(InvokeFailure::Timeout) => rest_error(
                    gateway_responses,
                    "INTEGRATION_TIMEOUT",
                    504,
                    "Endpoint request timed out",
                ),
                Err(_) => rest_error(
                    gateway_responses,
                    "INTEGRATION_FAILURE",
                    500,
                    "Internal server error",
                ),
            }
        }
        "AWS" => {
            let mapped = match map_request(integration, &request) {
                Ok(body) => body,
                Err(415) => {
                    return rest_error(
                        gateway_responses,
                        "UNSUPPORTED_MEDIA_TYPE",
                        415,
                        "Unsupported Media Type",
                    )
                }
                Err(_) => {
                    return rest_error(
                        gateway_responses,
                        "INTEGRATION_FAILURE",
                        500,
                        "Internal server error",
                    )
                }
            };
            let uri = substitute_uri(
                integration.get("uri").and_then(Value::as_str).unwrap_or(""),
                request.variables,
                request.path_params,
            );
            let target = match parse_aws_integration_uri(&uri) {
                Some(target) => target,
                None => {
                    return rest_error(
                        gateway_responses,
                        "INTEGRATION_FAILURE",
                        500,
                        "Internal server error",
                    )
                }
            };
            let response = match target.operation {
                AwsIntegrationOperation::Lambda => {
                    invoke_lambda(ctx, &uri, mapped, timeout_ms(integration))
                        .await
                        .map(|output| {
                            let selection = if output.function_error {
                                String::from_utf8_lossy(&output.body).into_owned()
                            } else {
                                output.status.to_string()
                            };
                            RawIntegrationResponse {
                                status: output.status,
                                headers: output.headers,
                                body: output.body,
                                selection,
                            }
                        })
                }
                AwsIntegrationOperation::Action(_) | AwsIntegrationOperation::Path(_) => {
                    invoke_aws_native(ctx, integration, &request, target, mapped).await
                }
            };
            match response {
                Ok(response) => map_integration_response(integration, response, &request),
                Err(InvokeFailure::Timeout) => rest_error(
                    gateway_responses,
                    "INTEGRATION_TIMEOUT",
                    504,
                    "Endpoint request timed out",
                ),
                Err(_) => rest_error(
                    gateway_responses,
                    "INTEGRATION_FAILURE",
                    500,
                    "Internal server error",
                ),
            }
        }
        "HTTP_PROXY" => {
            let uri = substitute_uri(
                integration.get("uri").and_then(Value::as_str).unwrap_or(""),
                request.variables,
                request.path_params,
            );
            forward_http(ctx, integration, &request, &uri, request.body.clone()).await
        }
        "HTTP" => {
            let mapped = match map_request(integration, &request) {
                Ok(body) => body,
                Err(415) => {
                    return rest_error(
                        gateway_responses,
                        "UNSUPPORTED_MEDIA_TYPE",
                        415,
                        "Unsupported Media Type",
                    )
                }
                Err(_) => {
                    return rest_error(
                        gateway_responses,
                        "INTEGRATION_FAILURE",
                        500,
                        "Internal server error",
                    )
                }
            };
            let uri = substitute_uri(
                integration.get("uri").and_then(Value::as_str).unwrap_or(""),
                request.variables,
                request.path_params,
            );
            let response = forward_http_raw(ctx, integration, &request, &uri, mapped).await;
            match response {
                Ok(response) => map_integration_response(integration, response, &request),
                Err(InvokeFailure::Timeout) => rest_error(
                    gateway_responses,
                    "INTEGRATION_TIMEOUT",
                    504,
                    "Endpoint request timed out",
                ),
                Err(_) => rest_error(
                    gateway_responses,
                    "INTEGRATION_FAILURE",
                    500,
                    "Internal server error",
                ),
            }
        }
        "MOCK" => {
            let mapped = match map_request(integration, &request) {
                Ok(body) => body,
                Err(415) => {
                    return rest_error(
                        gateway_responses,
                        "UNSUPPORTED_MEDIA_TYPE",
                        415,
                        "Unsupported Media Type",
                    )
                }
                Err(_) => {
                    return rest_error(
                        gateway_responses,
                        "INTEGRATION_FAILURE",
                        500,
                        "Internal server error",
                    )
                }
            };
            let status = serde_json::from_slice::<Value>(&mapped)
                .ok()
                .and_then(|value| value.get("statusCode").and_then(Value::as_u64))
                .unwrap_or(200) as u16;
            map_integration_response(
                integration,
                RawIntegrationResponse {
                    status,
                    headers: HeaderMap::new(),
                    body: mapped,
                    selection: status.to_string(),
                },
                &request,
            )
        }
        _ => rest_error(
            gateway_responses,
            "INTEGRATION_FAILURE",
            500,
            "Internal server error",
        ),
    }
}

fn parse_aws_integration_uri(uri: &str) -> Option<AwsIntegrationUri<'_>> {
    let mut parts = uri.splitn(6, ':');
    if parts.next()? != "arn" || parts.next()? != "aws" || parts.next()? != "apigateway" {
        return None;
    }
    let region = parts.next()?;
    let service = parts.next()?;
    let resource = parts.next()?;
    if region.is_empty() || service.is_empty() {
        return None;
    }
    let operation = if service == "lambda" && resource.starts_with("path/") {
        AwsIntegrationOperation::Lambda
    } else if let Some(operation) = resource.strip_prefix("action/") {
        if operation.is_empty() {
            return None;
        }
        AwsIntegrationOperation::Action(operation)
    } else {
        let path = resource.strip_prefix("path/")?;
        AwsIntegrationOperation::Path(path)
    };
    Some(AwsIntegrationUri {
        region,
        service,
        operation,
    })
}

fn action_target(service: &str, operation: &str) -> String {
    let prefix = match service {
        "dynamodb" => "DynamoDB_20120810",
        "sqs" => "AmazonSQS",
        "sns" => "AmazonSNS",
        "events" => "AWSEvents",
        "states" => "AWSStepFunctions",
        _ => service,
    };
    format!("{prefix}.{operation}")
}

async fn invoke_aws_native(
    ctx: &ExecuteCtx<'_>,
    integration: &Value,
    request: &IntegrationRequest<'_>,
    target: AwsIntegrationUri<'_>,
    body: Bytes,
) -> Result<RawIntegrationResponse, InvokeFailure> {
    let registry = ctx.registry.upgrade().ok_or(InvokeFailure::Configuration)?;
    let dispatcher = registry
        .internal_dispatcher()
        .ok_or(InvokeFailure::Configuration)?;
    let method = integration
        .get("httpMethod")
        .and_then(Value::as_str)
        .and_then(|value| Method::from_bytes(value.as_bytes()).ok())
        .unwrap_or_else(|| request.method.clone());
    let mut headers = request.headers.clone();
    headers.remove(http::header::HOST);
    set_dispatch_authorization(&mut headers, target.region, target.service)?;
    let uri = match target.operation {
        AwsIntegrationOperation::Action(operation) => {
            headers.insert(
                "x-amz-target",
                http::HeaderValue::from_str(&action_target(target.service, operation))
                    .map_err(|_| InvokeFailure::Configuration)?,
            );
            Uri::from_static("/")
        }
        AwsIntegrationOperation::Path(path) => {
            let path = if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{path}")
            };
            path.parse().map_err(|_| InvokeFailure::Configuration)?
        }
        AwsIntegrationOperation::Lambda => return Err(InvokeFailure::Configuration),
    };
    let response = timeout(
        Duration::from_millis(timeout_ms(integration)),
        dispatcher.dispatch(&method, &uri, &headers, body, ctx.request_id),
    )
    .await
    .map_err(|_| InvokeFailure::Timeout)?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(|_| InvokeFailure::Dispatch)?;
    Ok(RawIntegrationResponse {
        status,
        headers,
        body,
        selection: status.to_string(),
    })
}

fn timeout_ms(integration: &Value) -> u64 {
    integration
        .get("timeoutInMillis")
        .and_then(Value::as_u64)
        .unwrap_or(29_000)
}

struct RawIntegrationResponse {
    status: u16,
    headers: HeaderMap,
    body: Bytes,
    selection: String,
}

async fn forward_http(
    ctx: &ExecuteCtx<'_>,
    integration: &Value,
    request: &IntegrationRequest<'_>,
    uri: &str,
    body: Bytes,
) -> Response {
    match forward_http_raw(ctx, integration, request, uri, body).await {
        Ok(response) => {
            let mut builder = http::Response::builder().status(response.status);
            for (name, value) in response.headers.iter() {
                builder = builder.header(name, value);
            }
            safe_response(builder, Body::from(response.body))
        }
        Err(InvokeFailure::Timeout) => plain(504, "Endpoint request timed out"),
        Err(_) => plain(500, "Internal Server Error"),
    }
}

async fn forward_http_raw(
    ctx: &ExecuteCtx<'_>,
    integration: &Value,
    request: &IntegrationRequest<'_>,
    uri: &str,
    body: Bytes,
) -> Result<RawIntegrationResponse, InvokeFailure> {
    if uri.is_empty() {
        return Err(InvokeFailure::Configuration);
    }
    let uri = append_query(uri, request.uri.query());
    let method = integration
        .get("httpMethod")
        .or_else(|| integration.get("integrationMethod"))
        .and_then(Value::as_str)
        .and_then(|value| Method::from_bytes(value.as_bytes()).ok())
        .unwrap_or_else(|| request.method.clone());
    let mut builder = ctx
        .http
        .request(method, uri)
        .timeout(Duration::from_millis(timeout_ms(integration)));
    for (name, value) in request.headers.iter() {
        if name != http::header::HOST {
            builder = builder.header(name, value);
        }
    }
    let response = builder.body(body.to_vec()).send().await.map_err(|error| {
        if error.is_timeout() {
            InvokeFailure::Timeout
        } else {
            tracing::warn!(request_id = ctx.request_id, cause = %error, "HTTP integration failed");
            InvokeFailure::Dispatch
        }
    })?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .map_err(|_| InvokeFailure::Dispatch)?;
    Ok(RawIntegrationResponse {
        status,
        headers,
        body,
        selection: status.to_string(),
    })
}

fn append_query(uri: &str, query: Option<&str>) -> String {
    match query.filter(|query| !query.is_empty()) {
        Some(query) if !uri.contains('?') => format!("{uri}?{query}"),
        _ => uri.to_string(),
    }
}

fn map_request(integration: &Value, request: &IntegrationRequest<'_>) -> Result<Bytes, u16> {
    let templates = string_map(integration.get("requestTemplates"));
    let engine = VtlEngine::new();
    let selected = engine.select_template(&templates, content_type(request.headers));
    let passthrough = integration
        .get("passthroughBehavior")
        .and_then(Value::as_str)
        .unwrap_or("WHEN_NO_MATCH");
    let Some(template) = selected else {
        return match passthrough {
            "NEVER" => Err(415),
            "WHEN_NO_TEMPLATES" if !templates.is_empty() => Err(415),
            _ => Ok(request.body.clone()),
        };
    };
    let body = String::from_utf8_lossy(&request.body);
    evaluate_vtl(request, template, &body)
        .map(|mapped| Bytes::from(mapped.0))
        .map_err(|_| 500)
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
        .collect()
}

fn content_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
}

type EvaluatedVtl = (String, Option<u16>, BTreeMap<String, String>);

fn evaluate_vtl(
    request: &IntegrationRequest<'_>,
    template: &str,
    body: &str,
) -> Result<EvaluatedVtl, ()> {
    let query = query_map(request.uri.query().unwrap_or(""));
    let header = headers_map(request.headers);
    let values = BTreeMap::from([
        (
            "httpMethod".to_string(),
            Value::String(request.method.to_string()),
        ),
        ("path".to_string(), Value::String(request.path.to_string())),
        (
            "resourcePath".to_string(),
            Value::String(request.route_template.to_string()),
        ),
        (
            "stage".to_string(),
            Value::String(request.stage.to_string()),
        ),
    ]);
    let context = VtlContext {
        input: InputBinding {
            body,
            querystring: &query,
            path: request.path_params,
            header: &header,
        },
        util: UtilBinding,
        context: ContextBinding { values: &values },
        stage_variables: request.variables,
    };
    VtlEngine::new()
        .evaluate(template, &context)
        .map(|mapped| {
            (
                mapped.output,
                mapped.status_override,
                mapped.header_overrides,
            )
        })
        .map_err(|_| ())
}

fn map_integration_response(
    integration: &Value,
    raw: RawIntegrationResponse,
    request: &IntegrationRequest<'_>,
) -> Response {
    let responses = integration
        .get("integrationResponses")
        .and_then(Value::as_object);
    let selected = responses
        .and_then(|responses| select_integration_response(responses, raw.status, &raw.selection));
    let Some(selected) = selected else {
        return plain(500, "Internal server error");
    };
    let mut status = selected
        .get("statusCode")
        .and_then(|value| {
            value
                .as_str()
                .and_then(|value| value.parse().ok())
                .or_else(|| value.as_u64().map(|value| value as u16))
        })
        .unwrap_or(raw.status);
    let templates = string_map(selected.get("responseTemplates"));
    let mut body = raw.body.clone();
    let mut overrides = BTreeMap::new();
    if !templates.is_empty() {
        let engine = VtlEngine::new();
        let selected_template = engine.select_template(
            &templates,
            raw.headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
        );
        if let Some(template) = selected_template {
            let text = String::from_utf8_lossy(&raw.body);
            match evaluate_vtl(request, template, &text) {
                Ok((output, status_override, header_overrides)) => {
                    body = Bytes::from(output);
                    if let Some(override_status) = status_override {
                        status = override_status;
                    }
                    overrides = header_overrides;
                }
                Err(_) => return plain(500, "Internal server error"),
            }
        }
    }
    let mut builder = http::Response::builder().status(status);
    if let Some(parameters) = selected
        .get("responseParameters")
        .and_then(Value::as_object)
    {
        for (target, source) in parameters {
            let Some(name) = target.strip_prefix("method.response.header.") else {
                continue;
            };
            let value = source.as_str().and_then(|source| {
                source
                    .strip_prefix("integration.response.header.")
                    .and_then(|header| raw.headers.get(header))
                    .and_then(|value| value.to_str().ok())
                    .or_else(|| Some(unquote(source)))
            });
            if let Some(value) = value {
                builder = builder.header(name, value);
            }
        }
    }
    for (name, value) in overrides {
        builder = builder.header(name, value);
    }
    safe_response(builder, Body::from(body))
}

pub(crate) fn select_integration_response<'a>(
    responses: &'a Map<String, Value>,
    status: u16,
    selection: &str,
) -> Option<&'a Value> {
    let mut patterned: Vec<(&String, &Value)> = responses
        .iter()
        .filter(|(_, response)| {
            response
                .get("selectionPattern")
                .and_then(Value::as_str)
                .is_some()
        })
        .collect();
    patterned.sort_by(|left, right| left.0.cmp(right.0));
    for (_, response) in patterned {
        let pattern = response.get("selectionPattern").and_then(Value::as_str)?;
        let anchored = format!("^(?:{pattern})$");
        if Regex::new(&anchored)
            .ok()
            .is_some_and(|regex| regex.is_match(selection))
        {
            return Some(response);
        }
    }
    responses.get(&status.to_string()).or_else(|| {
        responses
            .iter()
            .filter(|(_, response)| response.get("selectionPattern").is_none_or(Value::is_null))
            .min_by(|left, right| left.0.cmp(right.0))
            .map(|(_, response)| response)
    })
}

pub(crate) fn substitute_uri(
    uri: &str,
    variables: &BTreeMap<String, String>,
    path: &BTreeMap<String, String>,
) -> String {
    let stage_variable = Regex::new(r"\$\{stageVariables\.([A-Za-z0-9_]+)\}")
        .expect("stage-variable pattern is valid");
    let mut output = stage_variable
        .replace_all(uri, |captures: &regex::Captures<'_>| {
            variables
                .get(&captures[1])
                .map(String::as_str)
                .unwrap_or("")
        })
        .into_owned();
    for (name, value) in path {
        output = output.replace(&format!("{{{name}}}"), value);
    }
    output
}

fn set_dispatch_authorization(
    headers: &mut HeaderMap,
    region: &str,
    service: &str,
) -> Result<(), InvokeFailure> {
    let value = format!(
        "AWS4-HMAC-SHA256 Credential=locallycloud/19700101/{region}/{service}/aws4_request"
    );
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&value).map_err(|_| InvokeFailure::Configuration)?,
    );
    Ok(())
}

async fn invoke_lambda(
    ctx: &ExecuteCtx<'_>,
    integration_uri: &str,
    body: Bytes,
    timeout_millis: u64,
) -> Result<LambdaOutput, InvokeFailure> {
    let registry = ctx.registry.upgrade().ok_or(InvokeFailure::Configuration)?;
    let dispatcher = registry
        .internal_dispatcher()
        .ok_or(InvokeFailure::Configuration)?;
    let function = function_from_uri(integration_uri).ok_or(InvokeFailure::Configuration)?;
    let uri: Uri = format!("/2015-03-31/functions/{function}/invocations")
        .parse()
        .map_err(|_| InvokeFailure::Configuration)?;
    let region = parse_aws_integration_uri(integration_uri)
        .map(|target| target.region)
        .unwrap_or(ctx.region);
    let mut headers = HeaderMap::new();
    set_dispatch_authorization(&mut headers, region, "lambda")?;
    let response = timeout(
        Duration::from_millis(timeout_millis),
        dispatcher.dispatch(&Method::POST, &uri, &headers, body, ctx.request_id),
    )
    .await
    .map_err(|_| InvokeFailure::Timeout)?;
    if !response.status().is_success() {
        return Err(InvokeFailure::Dispatch);
    }
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let function_error = headers.contains_key("x-amz-function-error");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(|_| InvokeFailure::Dispatch)?;
    Ok(LambdaOutput {
        status,
        headers,
        function_error,
        body,
    })
}

fn function_from_uri(uri: &str) -> Option<&str> {
    if let Some(value) = uri.split("/functions/").nth(1) {
        return value
            .split("/invocations")
            .next()
            .filter(|value| !value.is_empty());
    }
    (!uri.is_empty()).then_some(uri)
}

fn render_proxy(response: ProxyResponse) -> Response {
    let mut builder = http::Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    safe_response(builder, Body::from(response.body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use locallycloud_core::handler::{NativeHandler, ServiceRequest};
    use locallycloud_core::integration::InternalDispatcher;
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
    use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName};

    fn install_dispatcher(registry: &Arc<ServiceRegistry>) {
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(true),
            "us-east-1".into(),
            "000000000000".into(),
        )));
    }

    #[derive(Default)]
    struct Recorder {
        request: Mutex<Option<ServiceRequest>>,
    }

    #[async_trait]
    impl NativeHandler for Recorder {
        async fn handle(&self, request: ServiceRequest) -> Response {
            *self.request.lock().expect("recorder lock") = Some(request);
            http::Response::builder()
                .status(202)
                .header("x-backend", "captured")
                .body(Body::from(r#"{"backend":true}"#))
                .expect("recorder response")
        }
    }

    #[test]
    fn invocation_paths_and_host_are_recognized() {
        let target =
            invocation_target("execute-api", "/restapis/a/prod/_user_request_/x/y").unwrap();
        assert_eq!(target.api_id, "a");
        assert_eq!(target.stage, Some("prod"));
        assert_eq!(target.path, "/x/y");
        assert_eq!(target.kind, Some(ApiKind::Rest));

        let target = invocation_target("execute-api", "/execute-api/b/dev/items").unwrap();
        assert_eq!(target.api_id, "b");
        assert_eq!(target.path, "/items");
        assert_eq!(target.kind, Some(ApiKind::Http));

        let target = invocation_target("abc.execute-api.localhost:4566", "/prod/items").unwrap();
        assert_eq!(target.api_id, "abc");
        assert_eq!(target.stage, None);
    }

    #[test]
    fn route_precedence_is_literal_param_then_greedy() {
        let values = [
            ("/{proxy+}", json!("greedy")),
            ("/items/{id}", json!("param")),
            ("/items/special", json!("literal")),
        ];
        let found = best_match(
            values.iter().map(|(key, value)| (*key, value)),
            "/items/special",
        )
        .unwrap();
        assert_eq!(found.value, "literal");
        let found =
            best_match(values.iter().map(|(key, value)| (*key, value)), "/items/42").unwrap();
        assert_eq!(found.value, "param");
        assert_eq!(found.params.get("id").map(String::as_str), Some("42"));
        let found = best_match(
            values.iter().map(|(key, value)| (*key, value)),
            "/other/path",
        )
        .unwrap();
        assert_eq!(found.value, "greedy");
    }

    #[test]
    fn substitution_replaces_stage_and_path_values() {
        let variables = BTreeMap::from([("host".into(), "backend.test".into())]);
        let path = BTreeMap::from([("id".into(), "42".into())]);
        assert_eq!(
            substitute_uri(
                "https://${stageVariables.host}/items/{id}",
                &variables,
                &path
            ),
            "https://backend.test/items/42"
        );
    }

    #[test]
    fn selection_pattern_wins_then_default_is_used() {
        let responses: Map<String, Value> = [
            ("200".into(), json!({ "statusCode": "200" })),
            (
                "500".into(),
                json!({ "statusCode": "502", "selectionPattern": "5\\d\\d" }),
            ),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            select_integration_response(&responses, 500, "503").unwrap()["statusCode"],
            "502"
        );
        assert_eq!(
            select_integration_response(&responses, 200, "200").unwrap()["statusCode"],
            "200"
        );
    }

    #[test]
    fn aws_integration_uri_and_action_targets_are_parsed() {
        assert_eq!(
            parse_aws_integration_uri(
                "arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/f/invocations"
            ),
            Some(AwsIntegrationUri {
                region: "eu-west-1",
                service: "lambda",
                operation: AwsIntegrationOperation::Lambda,
            })
        );
        assert_eq!(
            parse_aws_integration_uri("arn:aws:apigateway:us-east-2:dynamodb:action/PutItem"),
            Some(AwsIntegrationUri {
                region: "us-east-2",
                service: "dynamodb",
                operation: AwsIntegrationOperation::Action("PutItem"),
            })
        );
        assert_eq!(
            parse_aws_integration_uri("arn:aws:apigateway:us-west-2:s3:path/bucket/key"),
            Some(AwsIntegrationUri {
                region: "us-west-2",
                service: "s3",
                operation: AwsIntegrationOperation::Path("bucket/key"),
            })
        );
        assert!(parse_aws_integration_uri("arn:aws:lambda:us-east-1:x").is_none());

        for (service, prefix) in [
            ("dynamodb", "DynamoDB_20120810"),
            ("sqs", "AmazonSQS"),
            ("sns", "AmazonSNS"),
            ("events", "AWSEvents"),
            ("states", "AWSStepFunctions"),
            ("custom", "custom"),
        ] {
            assert_eq!(
                action_target(service, "DoThing"),
                format!("{prefix}.DoThing")
            );
        }
    }

    #[tokio::test]
    async fn aws_action_maps_and_dispatches_to_native_handler() {
        let recorder = Arc::new(Recorder::default());
        let registry = Arc::new(ServiceRegistry::new());
        registry.register_native(
            ServiceName::new("dynamodb"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("DynamoDB_20120810")),
            recorder.clone(),
        );
        install_dispatcher(&registry);
        let weak = Arc::downgrade(&registry);
        let store = ApiGwStore::new();
        let validator = JwtValidator::new();
        let http = reqwest::Client::new();
        let ctx = ExecuteCtx {
            store: &store,
            validator: &validator,
            http: &http,
            registry: &weak,
            account: "000000000000",
            region: "us-east-1",
            request_id: "rid",
            waf: None,
            trusted_peer_ip: None,
        };
        let method = Method::POST;
        let uri: Uri = "/source".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        let path_params = BTreeMap::new();
        let variables = BTreeMap::new();
        let request = IntegrationRequest {
            method: &method,
            host: "api.example",
            uri: &uri,
            headers: &headers,
            body: Bytes::from_static(br#"{"original":true}"#),
            api_id: "api",
            stage: "prod",
            path: "/source",
            route_template: "/source",
            resource_id: "resource",
            path_params: &path_params,
            variables: &variables,
            auth: AuthContext::default(),
        };
        let integration = json!({
            "type": "AWS",
            "uri": "arn:aws:apigateway:eu-west-1:dynamodb:action/PutItem",
            "httpMethod": "PUT",
            "requestTemplates": {
                "application/json": "{\"mapped\":true}"
            },
            "integrationResponses": {
                "202": {
                    "statusCode": "201",
                    "responseParameters": {
                        "method.response.header.X-Captured": "integration.response.header.x-backend"
                    }
                }
            }
        });

        let response =
            execute_rest_integration(&ctx, &integration, &BTreeMap::new(), request).await;
        assert_eq!(response.status(), 201);
        assert_eq!(response.headers().get("x-captured").unwrap(), "captured");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, Bytes::from_static(br#"{"backend":true}"#));

        let recorded = recorder.request.lock().expect("recorder lock");
        let recorded = recorded.as_ref().expect("native request");
        assert_eq!(recorded.method, Method::PUT);
        assert_eq!(recorded.uri, Uri::from_static("/"));
        assert_eq!(recorded.region, "eu-west-1");
        assert_eq!(recorded.body, Bytes::from_static(br#"{"mapped":true}"#));
        assert_eq!(
            recorded.headers.get("x-amz-target").unwrap(),
            "DynamoDB_20120810.PutItem"
        );
    }

    #[tokio::test]
    async fn valid_api_key_accepts_v1_control_plane_keys_association() {
        let store = ApiGwStore::new();
        let shared = store.shared("000000000000", "us-east-1");
        {
            let mut guard = shared.write().await;
            guard.api_keys.insert(
                "key-id".into(),
                json!({ "id": "key-id", "value": "secret", "enabled": true }),
            );
            guard.usage_plans.insert(
                "plan-id".into(),
                json!({
                    "apiStages": [{ "apiId": "api-id", "stage": "prod" }],
                    "__keys": {
                        "key-id": { "id": "key-id", "type": "API_KEY", "value": "secret" }
                    }
                }),
            );
        }
        let registry = Arc::new(ServiceRegistry::new());
        let weak = Arc::downgrade(&registry);
        let validator = JwtValidator::new();
        let http = reqwest::Client::new();
        let ctx = ExecuteCtx {
            store: &store,
            validator: &validator,
            http: &http,
            registry: &weak,
            account: "000000000000",
            region: "us-east-1",
            request_id: "rid",
            waf: None,
            trusted_peer_ip: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", http::HeaderValue::from_static("secret"));

        assert!(valid_api_key(&ctx, "api-id", "prod", &headers).await);
    }

    #[test]
    fn exact_method_precedes_any_for_rest() {
        let resources = BTreeMap::from([(
            "r".into(),
            json!({
                "path": "/x",
                "resourceMethods": {
                    "ANY": { "httpMethod": "ANY" },
                    "GET": { "httpMethod": "GET" }
                }
            }),
        )]);
        let route = rest_route(&resources, &Method::GET, "/x").unwrap();
        assert_eq!(route.value["httpMethod"], "GET");
    }
}
