//! API Gateway service handler. The v1 REST and v2 (HTTP/WebSocket) control planes sign with
//! the `apigateway` service name and speak REST-JSON; the operation is resolved from the HTTP
//! method + path. The v2 HTTP invoke path signs as `execute-api` and is recognised by the
//! `*.execute-api.*` host; it is dispatched to the execute module. The WebSocket runtime is a
//! later increment.

use std::sync::{Arc, RwLock, Weak};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::ws::WebSocketUpgrade;
use axum::response::Response;
use http::Method;
use serde_json::Value;

use locallycloud_cognito::CognitoHandler;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_wafv2::{StageResolver, WafEvaluator};

use crate::auth::JwtValidator;
use crate::error::ApiGwError;
use crate::execute::{self, ExecuteCtx};
use crate::store::ApiGwStore;
use crate::v1::Ctx;
use crate::{v1, v2, websocket};

pub(crate) struct ApiGwHandler {
    store: Arc<ApiGwStore>,
    validator: JwtValidator,
    http: reqwest::Client,
    registry: Weak<ServiceRegistry>,
    waf: RwLock<Option<Weak<dyn WafEvaluator>>>,
}

#[derive(Clone)]
pub struct ApiGatewayWafBinding {
    handler: Arc<ApiGwHandler>,
}

impl ApiGatewayWafBinding {
    pub fn set_cognito_jwks(&self, provider: Arc<CognitoHandler>) {
        self.handler.validator.set_local_cognito(provider);
    }

    pub fn set_waf_evaluator(&self, evaluator: Arc<dyn WafEvaluator>) {
        *self.handler.waf.write().expect("WAF binding lock poisoned") =
            Some(Arc::downgrade(&evaluator));
    }
}

impl StageResolver for ApiGatewayWafBinding {
    fn stage_exists(&self, account_id: &str, region: &str, stage_arn: &str) -> bool {
        let prefix = format!("arn:aws:apigateway:{region}::/restapis/");
        let Some((api_id, stage)) = stage_arn
            .strip_prefix(&prefix)
            .and_then(|tail| tail.split_once("/stages/"))
        else {
            return false;
        };
        if api_id.is_empty() || api_id.contains('/') || stage.is_empty() || stage.contains('/') {
            return false;
        }
        self.handler
            .store
            .rest(account_id, region, api_id)
            .and_then(|record| {
                record
                    .try_read()
                    .ok()
                    .map(|record| record.stages.contains_key(stage))
            })
            .unwrap_or(false)
    }
}

impl ApiGwHandler {
    pub(crate) fn new(registry: Weak<ServiceRegistry>) -> Self {
        let http = reqwest::Client::new();
        ApiGwHandler {
            store: Arc::new(ApiGwStore::new()),
            validator: JwtValidator::with_client(http.clone()),
            http,
            registry,
            waf: RwLock::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn store(&self) -> &ApiGwStore {
        &self.store
    }

    async fn route(
        &self,
        method: &Method,
        segs: &[&str],
        query: Option<&str>,
        ctx: &Ctx<'_>,
        body: &Value,
    ) -> Result<(u16, Value), ApiGwError> {
        match segs.first().copied() {
            Some(
                "restapis"
                | "apikeys"
                | "usageplans"
                | "domainnames"
                | "domainnameaccessassociations",
            ) => route_v1(method, segs, query, ctx, body).await,
            Some("v2") => route_v2(method, segs, ctx, body).await,
            _ => Err(ApiGwError::NotFound("Unknown API Gateway resource".into())),
        }
    }
}

async fn route_v1(
    method: &Method,
    segs: &[&str],
    query: Option<&str>,
    ctx: &Ctx<'_>,
    body: &Value,
) -> Result<(u16, Value), ApiGwError> {
    match (method, segs) {
        (&Method::POST, ["restapis"]) => v1::create_rest_api(ctx, body).await,
        (&Method::GET, ["restapis"]) => v1::get_rest_apis(ctx).await,
        (&Method::GET, ["restapis", id]) => v1::get_rest_api(ctx, id).await,
        (&Method::PATCH, ["restapis", id]) => v1::update_rest_api(ctx, id, body).await,
        (&Method::DELETE, ["restapis", id]) => v1::delete_rest_api(ctx, id).await,
        (&Method::GET, ["restapis", id, "resources"]) => v1::get_resources(ctx, id).await,
        (&Method::POST, ["restapis", id, "resources", parent]) => {
            v1::create_resource(ctx, id, parent, body).await
        }
        (&Method::GET, ["restapis", id, "resources", rid]) => v1::get_resource(ctx, id, rid).await,
        (&Method::DELETE, ["restapis", id, "resources", rid]) => {
            v1::delete_resource(ctx, id, rid).await
        }
        (&Method::PUT, ["restapis", id, "resources", rid, "methods", m]) => {
            v1::put_method(ctx, id, rid, m, body).await
        }
        (&Method::GET, ["restapis", id, "resources", rid, "methods", m]) => {
            v1::get_method(ctx, id, rid, m).await
        }
        (&Method::DELETE, ["restapis", id, "resources", rid, "methods", m]) => {
            v1::delete_method(ctx, id, rid, m).await
        }
        (&Method::PUT, ["restapis", id, "resources", rid, "methods", m, "integration"]) => {
            v1::put_integration(ctx, id, rid, m, body).await
        }
        (&Method::GET, ["restapis", id, "resources", rid, "methods", m, "integration"]) => {
            v1::get_integration(ctx, id, rid, m).await
        }
        (&Method::PUT, ["restapis", id, "resources", rid, "methods", m, "responses", sc]) => {
            v1::put_method_response(ctx, id, rid, m, sc, body).await
        }
        (&Method::GET, ["restapis", id, "resources", rid, "methods", m, "responses", sc]) => {
            v1::get_method_response(ctx, id, rid, m, sc).await
        }
        (
            &Method::PUT,
            ["restapis", id, "resources", rid, "methods", m, "integration", "responses", sc],
        ) => v1::put_integration_response(ctx, id, rid, m, sc, body).await,
        (
            &Method::GET,
            ["restapis", id, "resources", rid, "methods", m, "integration", "responses", sc],
        ) => v1::get_integration_response(ctx, id, rid, m, sc).await,
        (&Method::POST, ["restapis", id, "deployments"]) => {
            v1::create_deployment(ctx, id, body).await
        }
        (&Method::GET, ["restapis", id, "deployments"]) => v1::get_deployments(ctx, id).await,
        (&Method::GET, ["restapis", id, "deployments", dep]) => {
            v1::get_deployment(ctx, id, dep).await
        }
        (&Method::DELETE, ["restapis", id, "deployments", dep]) => {
            v1::delete_deployment(ctx, id, dep).await
        }
        (&Method::POST, ["restapis", id, "stages"]) => v1::create_stage(ctx, id, body).await,
        (&Method::GET, ["restapis", id, "stages"]) => v1::get_stages(ctx, id).await,
        (&Method::GET, ["restapis", id, "stages", name]) => v1::get_stage(ctx, id, name).await,
        (&Method::PATCH, ["restapis", id, "stages", name]) => {
            v1::update_stage(ctx, id, name, body).await
        }
        (&Method::DELETE, ["restapis", id, "stages", name]) => {
            v1::delete_stage(ctx, id, name).await
        }
        (&Method::POST, ["restapis", id, "authorizers"]) => {
            v1::create_authorizer(ctx, id, body).await
        }
        (&Method::GET, ["restapis", id, "authorizers"]) => v1::get_authorizers(ctx, id).await,
        (&Method::GET, ["restapis", id, "authorizers", aid]) => {
            v1::get_authorizer(ctx, id, aid).await
        }
        (&Method::PATCH, ["restapis", id, "authorizers", aid]) => {
            v1::update_authorizer(ctx, id, aid, body).await
        }
        (&Method::DELETE, ["restapis", id, "authorizers", aid]) => {
            v1::delete_authorizer(ctx, id, aid).await
        }
        (&Method::POST, ["restapis", id, "models"]) => v1::create_model(ctx, id, body).await,
        (&Method::GET, ["restapis", id, "models"]) => v1::get_models(ctx, id).await,
        (&Method::GET, ["restapis", id, "models", name]) => v1::get_model(ctx, id, name).await,
        (&Method::PATCH, ["restapis", id, "models", name]) => {
            v1::update_model(ctx, id, name, body).await
        }
        (&Method::DELETE, ["restapis", id, "models", name]) => {
            v1::delete_model(ctx, id, name).await
        }
        (&Method::POST, ["restapis", id, "requestvalidators"]) => {
            v1::create_request_validator(ctx, id, body).await
        }
        (&Method::GET, ["restapis", id, "requestvalidators"]) => {
            v1::get_request_validators(ctx, id).await
        }
        (&Method::GET, ["restapis", id, "requestvalidators", vid]) => {
            v1::get_request_validator(ctx, id, vid).await
        }
        (&Method::PATCH, ["restapis", id, "requestvalidators", vid]) => {
            v1::update_request_validator(ctx, id, vid, body).await
        }
        (&Method::DELETE, ["restapis", id, "requestvalidators", vid]) => {
            v1::delete_request_validator(ctx, id, vid).await
        }
        (&Method::PUT, ["restapis", id, "gatewayresponses", response_type]) => {
            v1::put_gateway_response(ctx, id, response_type, body).await
        }
        (&Method::GET, ["restapis", id, "gatewayresponses"]) => {
            v1::get_gateway_responses(ctx, id).await
        }
        (&Method::GET, ["restapis", id, "gatewayresponses", response_type]) => {
            v1::get_gateway_response(ctx, id, response_type).await
        }
        (&Method::POST, ["apikeys"]) => v1::create_api_key(ctx, body).await,
        (&Method::GET, ["apikeys"]) => {
            v1::get_api_keys(ctx, query_flag(query, "includeValues")).await
        }
        (&Method::GET, ["apikeys", id]) => {
            v1::get_api_key(ctx, id, query_flag(query, "includeValue")).await
        }
        (&Method::PATCH, ["apikeys", id]) => v1::update_api_key(ctx, id, body).await,
        (&Method::DELETE, ["apikeys", id]) => v1::delete_api_key(ctx, id).await,
        (&Method::POST, ["usageplans"]) => v1::create_usage_plan(ctx, body).await,
        (&Method::GET, ["usageplans"]) => v1::get_usage_plans(ctx).await,
        (&Method::GET, ["usageplans", id]) => v1::get_usage_plan(ctx, id).await,
        (&Method::PATCH, ["usageplans", id]) => v1::update_usage_plan(ctx, id, body).await,
        (&Method::DELETE, ["usageplans", id]) => v1::delete_usage_plan(ctx, id).await,
        (&Method::POST, ["usageplans", id, "keys"]) => {
            v1::create_usage_plan_key(ctx, id, body).await
        }
        (&Method::GET, ["usageplans", id, "keys"]) => v1::get_usage_plan_keys(ctx, id).await,
        (&Method::GET, ["usageplans", id, "keys", key]) => {
            v1::get_usage_plan_key(ctx, id, key).await
        }
        (&Method::DELETE, ["usageplans", id, "keys", key]) => {
            v1::delete_usage_plan_key(ctx, id, key).await
        }
        (&Method::POST, ["domainnames"]) => v1::create_domain_name(ctx, body).await,
        (&Method::GET, ["domainnames"]) => v1::get_domain_names(ctx).await,
        (&Method::GET, ["domainnames", name]) => {
            let id = query_value(query, "domainNameId");
            v1::get_domain_name(ctx, name, id.as_deref()).await
        }
        (&Method::PATCH, ["domainnames", name]) => {
            let id = query_value(query, "domainNameId");
            v1::update_domain_name(ctx, name, id.as_deref(), body).await
        }
        (&Method::DELETE, ["domainnames", name]) => {
            let id = query_value(query, "domainNameId");
            v1::delete_domain_name(ctx, name, id.as_deref()).await
        }
        (&Method::POST, ["domainnameaccessassociations"]) => {
            v1::create_domain_name_access_association(ctx, body).await
        }
        (&Method::GET, ["domainnameaccessassociations"]) => {
            let owner = query_value(query, "resourceOwner");
            let limit = query_value(query, "limit");
            let position = query_value(query, "position");
            v1::get_domain_name_access_associations(
                ctx,
                owner.as_deref(),
                limit.as_deref(),
                position.as_deref(),
            )
            .await
        }
        (&Method::DELETE, ["domainnameaccessassociations", arn @ ..]) if !arn.is_empty() => {
            let encoded = arn.join("/").replace('+', "%2B");
            let decoded = crate::proxy_event::percent_decode(&encoded);
            v1::delete_domain_name_access_association(ctx, &decoded).await
        }
        (&Method::POST, ["domainnames", name, "basepathmappings"]) => {
            let id = query_value(query, "domainNameId");
            v1::create_base_path_mapping(ctx, name, id.as_deref(), body).await
        }
        (&Method::GET, ["domainnames", name, "basepathmappings"]) => {
            let id = query_value(query, "domainNameId");
            v1::get_base_path_mappings(ctx, name, id.as_deref()).await
        }
        (&Method::GET, ["domainnames", name, "basepathmappings", base]) => {
            let id = query_value(query, "domainNameId");
            v1::get_base_path_mapping(ctx, name, id.as_deref(), base).await
        }
        (&Method::PATCH, ["domainnames", name, "basepathmappings", base]) => {
            let id = query_value(query, "domainNameId");
            v1::update_base_path_mapping(ctx, name, id.as_deref(), base, body).await
        }
        (&Method::DELETE, ["domainnames", name, "basepathmappings", base]) => {
            let id = query_value(query, "domainNameId");
            v1::delete_base_path_mapping(ctx, name, id.as_deref(), base).await
        }
        _ => Err(ApiGwError::NotFound(
            "Unknown API Gateway v1 operation".into(),
        )),
    }
}

async fn route_v2(
    method: &Method,
    segs: &[&str],
    ctx: &Ctx<'_>,
    body: &Value,
) -> Result<(u16, Value), ApiGwError> {
    match (method, segs) {
        (&Method::POST, ["v2", "apis"]) => v2::create_api(ctx, body).await,
        (&Method::GET, ["v2", "apis"]) => v2::get_apis(ctx).await,
        (&Method::GET, ["v2", "apis", id]) => v2::get_api(ctx, id).await,
        (&Method::PATCH, ["v2", "apis", id]) => v2::update_api(ctx, id, body).await,
        (&Method::DELETE, ["v2", "apis", id]) => v2::delete_api(ctx, id).await,
        (&Method::POST, ["v2", "apis", id, "routes"]) => v2::create_route(ctx, id, body).await,
        (&Method::GET, ["v2", "apis", id, "routes"]) => v2::get_routes(ctx, id).await,
        (&Method::GET, ["v2", "apis", id, "routes", rid]) => v2::get_route(ctx, id, rid).await,
        (&Method::PATCH, ["v2", "apis", id, "routes", rid]) => {
            v2::update_route(ctx, id, rid, body).await
        }
        (&Method::DELETE, ["v2", "apis", id, "routes", rid]) => {
            v2::delete_route(ctx, id, rid).await
        }
        (&Method::POST, ["v2", "apis", id, "integrations"]) => {
            v2::create_integration(ctx, id, body).await
        }
        (&Method::GET, ["v2", "apis", id, "integrations"]) => v2::get_integrations(ctx, id).await,
        (&Method::GET, ["v2", "apis", id, "integrations", iid]) => {
            v2::get_integration(ctx, id, iid).await
        }
        (&Method::PATCH, ["v2", "apis", id, "integrations", iid]) => {
            v2::update_integration(ctx, id, iid, body).await
        }
        (&Method::DELETE, ["v2", "apis", id, "integrations", iid]) => {
            v2::delete_integration(ctx, id, iid).await
        }
        (&Method::POST, ["v2", "apis", id, "deployments"]) => {
            v2::create_deployment(ctx, id, body).await
        }
        (&Method::GET, ["v2", "apis", id, "deployments"]) => v2::get_deployments(ctx, id).await,
        (&Method::GET, ["v2", "apis", id, "deployments", did]) => {
            v2::get_deployment(ctx, id, did).await
        }
        (&Method::DELETE, ["v2", "apis", id, "deployments", did]) => {
            v2::delete_deployment(ctx, id, did).await
        }
        (&Method::POST, ["v2", "apis", id, "stages"]) => v2::create_stage(ctx, id, body).await,
        (&Method::GET, ["v2", "apis", id, "stages"]) => v2::get_stages(ctx, id).await,
        (&Method::GET, ["v2", "apis", id, "stages", name]) => v2::get_stage(ctx, id, name).await,
        (&Method::PATCH, ["v2", "apis", id, "stages", name]) => {
            v2::update_stage(ctx, id, name, body).await
        }
        (&Method::DELETE, ["v2", "apis", id, "stages", name]) => {
            v2::delete_stage(ctx, id, name).await
        }
        (&Method::POST, ["v2", "apis", id, "authorizers"]) => {
            v2::create_authorizer(ctx, id, body).await
        }
        (&Method::GET, ["v2", "apis", id, "authorizers"]) => v2::get_authorizers(ctx, id).await,
        (&Method::GET, ["v2", "apis", id, "authorizers", aid]) => {
            v2::get_authorizer(ctx, id, aid).await
        }
        (&Method::PATCH, ["v2", "apis", id, "authorizers", aid]) => {
            v2::update_authorizer(ctx, id, aid, body).await
        }
        (&Method::DELETE, ["v2", "apis", id, "authorizers", aid]) => {
            v2::delete_authorizer(ctx, id, aid).await
        }
        (&Method::POST, ["v2", "domainnames"]) => v2::create_domain_name(ctx, body).await,
        (&Method::GET, ["v2", "domainnames"]) => v2::get_domain_names(ctx).await,
        (&Method::GET, ["v2", "domainnames", name]) => v2::get_domain_name(ctx, name).await,
        (&Method::PATCH, ["v2", "domainnames", name]) => {
            v2::update_domain_name(ctx, name, body).await
        }
        (&Method::DELETE, ["v2", "domainnames", name]) => v2::delete_domain_name(ctx, name).await,
        (&Method::POST, ["v2", "domainnames", name, "apimappings"]) => {
            v2::create_api_mapping(ctx, name, body).await
        }
        (&Method::GET, ["v2", "domainnames", name, "apimappings"]) => {
            v2::get_api_mappings(ctx, name).await
        }
        (&Method::GET, ["v2", "domainnames", name, "apimappings", mid]) => {
            v2::get_api_mapping(ctx, name, mid).await
        }
        (&Method::PATCH, ["v2", "domainnames", name, "apimappings", mid]) => {
            v2::update_api_mapping(ctx, name, mid, body).await
        }
        (&Method::DELETE, ["v2", "domainnames", name, "apimappings", mid]) => {
            v2::delete_api_mapping(ctx, name, mid).await
        }
        _ => Err(ApiGwError::NotFound(
            "Unknown API Gateway v2 operation".into(),
        )),
    }
}

fn query_value(query: Option<&str>, name: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| crate::proxy_event::percent_decode(value))
}

fn query_flag(query: Option<&str>, name: &str) -> bool {
    query
        .into_iter()
        .flat_map(|query| query.split('&'))
        .filter_map(|pair| pair.split_once('='))
        .any(|(key, value)| key == name && value.eq_ignore_ascii_case("true"))
}

fn is_invoke_path(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if matches!(segs.as_slice(), ["execute-api", _, _, ..]) {
        return true;
    }
    if !matches!(segs.as_slice(), ["restapis", _, _, ..]) {
        return false;
    }
    if segs.get(3) == Some(&"_user_request_") {
        return true;
    }
    !matches!(
        segs[2],
        "resources"
            | "deployments"
            | "stages"
            | "authorizers"
            | "models"
            | "requestvalidators"
            | "gatewayresponses"
    )
}

fn mapping_remainder<'a>(path: &'a str, mapping_key: &str) -> Option<&'a str> {
    let path = path.trim_start_matches('/');
    let mapping_key = if mapping_key == "(none)" {
        ""
    } else {
        mapping_key.trim_matches('/')
    };
    if mapping_key.is_empty() {
        return Some(path);
    }
    if path == mapping_key {
        return Some("");
    }
    path.strip_prefix(mapping_key)?.strip_prefix('/')
}

async fn is_private_domain_host(
    store: &ApiGwStore,
    account: &str,
    region: &str,
    host: &str,
) -> bool {
    let domain_host = host.split(':').next().unwrap_or(host);
    let shared = store.shared(account, region);
    let guard = shared.read().await;
    if guard
        .domains
        .keys()
        .any(|name| name.eq_ignore_ascii_case(domain_host))
    {
        return false;
    }
    guard.private_domains.values().any(|domain| {
        domain
            .get("domainName")
            .and_then(Value::as_str)
            .is_some_and(|name| name.eq_ignore_ascii_case(domain_host))
    })
}

pub(crate) async fn custom_domain_target(
    store: &ApiGwStore,
    account: &str,
    region: &str,
    host: &str,
    uri: &http::Uri,
) -> Option<(String, http::Uri)> {
    let domain_host = host.split(':').next().unwrap_or(host);
    let shared = store.shared(account, region);
    let guard = shared.read().await;
    let domain = guard
        .domains
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(domain_host))
        .map(|(_, domain)| domain)?;

    let mut best: Option<(usize, bool, String, String, String)> = None;
    for (storage_key, is_v2) in [("__basePathMappings", false), ("__apiMappings", true)] {
        for mapping in domain
            .get(storage_key)
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(_, mapping)| mapping)
        {
            let mapping_key = mapping
                .get(if is_v2 { "apiMappingKey" } else { "basePath" })
                .and_then(Value::as_str)
                .unwrap_or("");
            let remainder = match mapping_remainder(uri.path(), mapping_key) {
                Some(remainder) => remainder,
                None => continue,
            };
            let api_id = mapping
                .get(if is_v2 { "apiId" } else { "restApiId" })
                .and_then(Value::as_str)?;
            let stage = mapping.get("stage").and_then(Value::as_str)?;
            let score = mapping_key.trim_matches('/').len();
            if best.as_ref().is_none_or(|current| score > current.0) {
                best = Some((
                    score,
                    is_v2,
                    api_id.to_string(),
                    stage.to_string(),
                    remainder.to_string(),
                ));
            }
        }
    }
    drop(guard);

    let (_, is_v2, api_id, stage, remainder) = best?;
    let suffix = if remainder.is_empty() {
        String::new()
    } else {
        format!("/{remainder}")
    };
    let path = if is_v2 {
        format!("/execute-api/{api_id}/{stage}{suffix}")
    } else {
        format!("/restapis/{api_id}/{stage}/_user_request_{suffix}")
    };
    let path_and_query = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    let rewritten_uri = path_and_query.parse().ok()?;
    let rewritten_host = format!("{api_id}.execute-api.{region}.amazonaws.com");
    Some((rewritten_host, rewritten_uri))
}

fn management_target<'a>(host: &str, path: &'a str) -> Option<(&'a str, &'a str, String)> {
    let api_id = host
        .split(':')
        .next()
        .unwrap_or(host)
        .split(".execute-api.")
        .next()?;
    if api_id.is_empty() || !host.to_ascii_lowercase().contains(".execute-api.") {
        return None;
    }
    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    match segments.as_slice() {
        ["@connections", connection_id] => Some(("$default", *connection_id, api_id.to_string())),
        [stage, "@connections", connection_id] => {
            Some((*stage, *connection_id, api_id.to_string()))
        }
        _ => None,
    }
}

async fn connection_belongs_to_endpoint(
    store: &ApiGwStore,
    account: &str,
    region: &str,
    api_id: &str,
    stage: &str,
    connection_id: &str,
) -> bool {
    let shared = store.shared(account, region);
    let guard = shared.read().await;
    guard
        .connections
        .get(connection_id)
        .is_some_and(|connection| {
            connection.get("open").and_then(Value::as_bool) == Some(true)
                && connection.get("apiId").and_then(Value::as_str) == Some(api_id)
                && connection.get("stage").and_then(Value::as_str) == Some(stage)
        })
}

#[async_trait]
impl NativeHandler for ApiGwHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let mut request = request;
        let trusted_peer_ip = request
            .headers
            .remove("x-locallycloud-trusted-peer-ip")
            .and_then(|value| value.to_str().ok().map(str::to_string));
        let host = request
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if is_private_domain_host(&self.store, &request.account_id, &request.region, host).await {
            return ApiGwError::Forbidden("Forbidden".into()).into_response(&request.request_id);
        }
        if let Some((stage, connection_id, api_id)) = management_target(host, request.uri.path()) {
            if !connection_belongs_to_endpoint(
                &self.store,
                &request.account_id,
                &request.region,
                &api_id,
                stage,
                connection_id,
            )
            .await
            {
                return ApiGwError::Gone(format!("The connection with id {connection_id} is gone"))
                    .into_response(&request.request_id);
            }
            let empty_success = request.method == Method::POST;
            let result = match request.method {
                Method::POST => {
                    websocket::post_to_connection(
                        &self.store,
                        &request.account_id,
                        &request.region,
                        connection_id,
                        &request.body,
                    )
                    .await
                }
                Method::GET => {
                    websocket::get_connection(
                        &self.store,
                        &request.account_id,
                        &request.region,
                        connection_id,
                    )
                    .await
                }
                Method::DELETE => {
                    websocket::delete_connection(
                        &self.store,
                        &request.account_id,
                        &request.region,
                        connection_id,
                    )
                    .await
                }
                _ => Err(ApiGwError::BadRequest(
                    "Unsupported @connections operation".into(),
                )),
            };
            return match result {
                Ok((status, _)) if empty_success => http::Response::builder()
                    .status(status)
                    .body(Body::empty())
                    .expect("management response is valid"),
                Ok((status, value)) => json_response(status, value),
                Err(error) => error.into_response(&request.request_id),
            };
        }
        let path_invoke = is_invoke_path(request.uri.path());
        let execute_host = host.to_ascii_lowercase().contains(".execute-api.");
        let custom_target = if execute_host || path_invoke || host.is_empty() {
            None
        } else {
            custom_domain_target(
                &self.store,
                &request.account_id,
                &request.region,
                host,
                &request.uri,
            )
            .await
        };
        if execute_host || path_invoke || custom_target.is_some() {
            let waf = match self.waf.read() {
                Ok(binding) => match binding.as_ref() {
                    Some(evaluator) => match evaluator.upgrade() {
                        Some(evaluator) => Some(evaluator),
                        None => {
                            return ApiGwError::Internal("WAF evaluator unavailable".into())
                                .into_response(&request.request_id)
                        }
                    },
                    None => None,
                },
                Err(_) => {
                    return ApiGwError::Internal("WAF evaluator unavailable".into())
                        .into_response(&request.request_id)
                }
            };
            let (invoke_host, invoke_uri) = custom_target
                .as_ref()
                .map(|(host, uri)| (host.as_str(), uri))
                .unwrap_or((host, &request.uri));
            let ctx = ExecuteCtx {
                store: &self.store,
                validator: &self.validator,
                http: &self.http,
                registry: &self.registry,
                account: &request.account_id,
                region: &request.region,
                request_id: &request.request_id,
                waf,
                trusted_peer_ip: trusted_peer_ip.as_deref(),
            };
            return execute::invoke(
                &ctx,
                &request.method,
                invoke_host,
                invoke_uri,
                &request.headers,
                request.body,
                custom_target.is_some(),
            )
            .await;
        }

        let path = request.uri.path().to_string();
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let body: Value = if request.body.is_empty() {
            Value::Object(serde_json::Map::new())
        } else {
            match serde_json::from_slice(&request.body) {
                Ok(v) => v,
                Err(e) => {
                    return ApiGwError::BadRequest(format!("invalid JSON body: {e}"))
                        .into_response(&request.request_id)
                }
            }
        };
        let ctx = Ctx {
            store: &self.store,
            registry: &self.registry,
            region: &request.region,
            account: &request.account_id,
            request_id: &request.request_id,
            waf: Some(&self.waf),
        };
        match self
            .route(&request.method, &segs, request.uri.query(), &ctx, &body)
            .await
        {
            Ok((status, value)) => json_response(status, value),
            Err(err) => err.into_response(&request.request_id),
        }
    }

    async fn handle_websocket(
        &self,
        mut request: ServiceRequest,
        upgrade: WebSocketUpgrade,
    ) -> Response {
        let host = request
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        if is_private_domain_host(&self.store, &request.account_id, &request.region, &host).await {
            return ApiGwError::Forbidden("Forbidden".into()).into_response(&request.request_id);
        }
        let direct = host.to_ascii_lowercase().contains(".execute-api.");
        let mut custom_domain = None;
        if !direct {
            if let Some((target_host, target_uri)) = custom_domain_target(
                &self.store,
                &request.account_id,
                &request.region,
                &host,
                &request.uri,
            )
            .await
            {
                let segments = target_uri
                    .path()
                    .split('/')
                    .filter(|segment| !segment.is_empty())
                    .collect::<Vec<_>>();
                if let ["execute-api", _, stage, remainder @ ..] = segments.as_slice() {
                    let mut path = format!("/{stage}");
                    if !remainder.is_empty() {
                        path.push('/');
                        path.push_str(&remainder.join("/"));
                    }
                    if let Some(query) = target_uri.query() {
                        path.push('?');
                        path.push_str(query);
                    }
                    if let (Ok(uri), Ok(parsed_host)) = (path.parse(), target_host.parse()) {
                        request.uri = uri;
                        request.headers.insert(http::header::HOST, parsed_host);
                        custom_domain = Some(host.clone());
                    }
                }
            }
        }
        websocket::handle_websocket(
            self.store.clone(),
            self.registry.clone(),
            request,
            upgrade,
            custom_domain,
        )
        .await
    }
}

fn json_response(status: u16, value: Value) -> Response {
    // 204 No Content must not carry a body.
    let body = if status == 204 {
        Body::empty()
    } else {
        Body::from(value.to_string())
    };
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body)
        .expect("rest-json response is valid")
}

/// Register API Gateway under both control-plane service names and `execute-api`; all names
/// share one handler and one in-memory store.
pub fn register(registry: &Arc<ServiceRegistry>) -> ApiGatewayWafBinding {
    let handler = Arc::new(ApiGwHandler::new(Arc::downgrade(registry)));
    let binding = ApiGatewayWafBinding {
        handler: handler.clone(),
    };
    let handler: Arc<dyn NativeHandler> = handler;
    for service in ["apigateway", "apigatewayv2", "execute-api"] {
        registry.register_native(
            ServiceName::new(service),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            handler.clone(),
        );
    }
    binding
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::HeaderMap;
    use serde_json::json;

    fn req(method: Method, path: &str, body: Value) -> ServiceRequest {
        let body = if body.is_null() {
            Bytes::new()
        } else {
            Bytes::from(body.to_string())
        };
        ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers: HeaderMap::new(),
            body,
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        }
    }

    async fn call(h: &ApiGwHandler, method: Method, path: &str, body: Value) -> (u16, Value) {
        let resp = h.handle(req(method, path, body)).await;
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    struct PeerProbe(std::sync::Mutex<Vec<(String, bool)>>);

    impl WafEvaluator for PeerProbe {
        fn detach_stage(
            &self,
            _account_id: &str,
            _region: &str,
            _resource_arn: &str,
        ) -> Result<(), locallycloud_wafv2::WafEvaluationError> {
            Ok(())
        }

        fn evaluate(
            &self,
            request: &locallycloud_wafv2::WafRequest<'_>,
        ) -> Result<locallycloud_wafv2::WafDecision, locallycloud_wafv2::WafEvaluationError>
        {
            self.0.lock().unwrap().push((
                request.source_ip.to_string(),
                request
                    .headers
                    .contains_key("x-locallycloud-trusted-peer-ip"),
            ));
            Ok(if request.source_ip.is_empty() {
                locallycloud_wafv2::WafDecision::Block
            } else {
                locallycloud_wafv2::WafDecision::Allow
            })
        }
    }

    #[tokio::test]
    async fn waf_uses_only_internal_peer_and_strips_it_from_request_headers() {
        let handler = Arc::new(ApiGwHandler::new(Weak::new()));
        let mut record = crate::store::RestApiRecord::default();
        record.stages.insert("prod".into(), json!({}));
        handler
            .store
            .insert_rest("000000000000", "us-east-1", "api123", record);
        let binding = ApiGatewayWafBinding {
            handler: handler.clone(),
        };
        let stage_arn = "arn:aws:apigateway:us-east-1::/restapis/api123/stages/prod";
        assert!(binding.stage_exists("000000000000", "us-east-1", stage_arn));
        assert!(!binding.stage_exists(
            "000000000000",
            "us-east-1",
            "arn:aws:apigateway:us-east-1::/restapis/api123/stages/missing"
        ));
        let probe = Arc::new(PeerProbe(std::sync::Mutex::new(Vec::new())));
        binding.set_waf_evaluator(probe.clone());

        let path = "/restapis/api123/prod/_user_request_/";
        let mut no_peer = req(Method::GET, path, Value::Null);
        no_peer
            .headers
            .insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
        let response = handler.handle(no_peer).await;
        assert_eq!(response.status(), 403);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["message"],
            "Forbidden"
        );

        let mut peer = req(Method::GET, path, Value::Null);
        peer.headers.insert(
            "x-locallycloud-trusted-peer-ip",
            "127.0.0.1".parse().unwrap(),
        );
        let response = handler.handle(peer).await;
        assert_eq!(response.status(), 403);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["message"],
            "Missing Authentication Token"
        );
        assert_eq!(
            *probe.0.lock().unwrap(),
            vec![(String::new(), false), ("127.0.0.1".into(), false)]
        );
    }

    #[tokio::test]
    async fn v1_rest_api_full_lifecycle() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (s, api) = call(&h, Method::POST, "/restapis", json!({ "name": "my-api" })).await;
        assert_eq!(s, 201);
        let api_id = api["id"].as_str().unwrap().to_string();
        let root_id = api["rootResourceId"].as_str().unwrap().to_string();

        // Child resource off the root.
        let (s, res) = call(
            &h,
            Method::POST,
            &format!("/restapis/{api_id}/resources/{root_id}"),
            json!({ "pathPart": "items" }),
        )
        .await;
        assert_eq!(s, 201);
        assert_eq!(res["path"], "/items");
        let res_id = res["id"].as_str().unwrap().to_string();

        // Method + integration.
        let (s, _) = call(
            &h,
            Method::PUT,
            &format!("/restapis/{api_id}/resources/{res_id}/methods/GET"),
            json!({ "authorizationType": "NONE" }),
        )
        .await;
        assert_eq!(s, 201);
        let (s, _) = call(
            &h,
            Method::PUT,
            &format!("/restapis/{api_id}/resources/{res_id}/methods/GET/integration"),
            json!({ "type": "MOCK" }),
        )
        .await;
        assert_eq!(s, 201);

        // Integration is readable back, with the AWS-default timeout.
        let (s, integ) = call(
            &h,
            Method::GET,
            &format!("/restapis/{api_id}/resources/{res_id}/methods/GET/integration"),
            Value::Null,
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(integ["timeoutInMillis"], 29000);

        // Method response + integration response round-trip.
        let mr_path = format!("/restapis/{api_id}/resources/{res_id}/methods/GET/responses/200");
        let (s, _) = call(&h, Method::PUT, &mr_path, json!({})).await;
        assert_eq!(s, 201);
        let (s, mr) = call(&h, Method::GET, &mr_path, Value::Null).await;
        assert_eq!(s, 200);
        assert_eq!(mr["statusCode"], "200");
        let ir_path =
            format!("/restapis/{api_id}/resources/{res_id}/methods/GET/integration/responses/200");
        let (s, _) = call(&h, Method::PUT, &ir_path, json!({})).await;
        assert_eq!(s, 201);
        let (s, ir) = call(&h, Method::GET, &ir_path, Value::Null).await;
        assert_eq!(s, 200);
        assert_eq!(ir["statusCode"], "200");

        // Deployment with an inline stage.
        let (s, dep) = call(
            &h,
            Method::POST,
            &format!("/restapis/{api_id}/deployments"),
            json!({ "stageName": "prod" }),
        )
        .await;
        assert_eq!(s, 201);
        assert!(dep["id"].is_string());
        let dep_id = dep["id"].as_str().unwrap().to_string();
        let (s, got) = call(
            &h,
            Method::GET,
            &format!("/restapis/{api_id}/deployments/{dep_id}"),
            Value::Null,
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(got["id"], dep_id);
        let (s, stage) = call(
            &h,
            Method::GET,
            &format!("/restapis/{api_id}/stages/prod"),
            Value::Null,
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(stage["stageName"], "prod");

        // List then delete (202).
        let (s, list) = call(&h, Method::GET, "/restapis", Value::Null).await;
        assert_eq!(s, 200);
        assert_eq!(list["item"].as_array().unwrap().len(), 1);
        let (s, _) = call(
            &h,
            Method::DELETE,
            &format!("/restapis/{api_id}"),
            Value::Null,
        )
        .await;
        assert_eq!(s, 202);
        let (s, _) = call(&h, Method::GET, &format!("/restapis/{api_id}"), Value::Null).await;
        assert_eq!(s, 404);
    }

    #[tokio::test]
    async fn v1_missing_name_is_bad_request() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (s, body) = call(&h, Method::POST, "/restapis", json!({ "description": "x" })).await;
        assert_eq!(s, 400);
        assert_eq!(body["message"], "name is required");
    }

    #[tokio::test]
    async fn v1_sibling_path_part_conflict() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (_, api) = call(&h, Method::POST, "/restapis", json!({ "name": "a" })).await;
        let api_id = api["id"].as_str().unwrap().to_string();
        let root_id = api["rootResourceId"].as_str().unwrap().to_string();
        let base = format!("/restapis/{api_id}/resources/{root_id}");
        let (s, _) = call(&h, Method::POST, &base, json!({ "pathPart": "x" })).await;
        assert_eq!(s, 201);
        let (s, _) = call(&h, Method::POST, &base, json!({ "pathPart": "x" })).await;
        assert_eq!(s, 409);
    }

    #[tokio::test]
    async fn v2_http_api_lifecycle() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (s, api) = call(
            &h,
            Method::POST,
            "/v2/apis",
            json!({ "name": "http-api", "protocolType": "HTTP" }),
        )
        .await;
        assert_eq!(s, 201);
        assert_eq!(api["protocolType"], "HTTP");
        assert_eq!(
            api["routeSelectionExpression"],
            "$request.method $request.path"
        );
        assert!(api["apiEndpoint"].as_str().unwrap().starts_with("https://"));
        let api_id = api["apiId"].as_str().unwrap().to_string();

        // Integration (default payload format 2.0).
        let (s, integ) = call(
            &h,
            Method::POST,
            &format!("/v2/apis/{api_id}/integrations"),
            json!({ "integrationType": "AWS_PROXY", "integrationUri": "arn:aws:lambda:us-east-1:000000000000:function:f" }),
        )
        .await;
        assert_eq!(s, 201);
        assert_eq!(integ["payloadFormatVersion"], "2.0");

        // Route + stage.
        let (s, route) = call(
            &h,
            Method::POST,
            &format!("/v2/apis/{api_id}/routes"),
            json!({ "routeKey": "GET /items", "target": format!("integrations/{}", integ["integrationId"].as_str().unwrap()) }),
        )
        .await;
        assert_eq!(s, 201);
        assert_eq!(route["routeKey"], "GET /items");
        let (s, _) = call(
            &h,
            Method::POST,
            &format!("/v2/apis/{api_id}/stages"),
            json!({ "stageName": "$default", "autoDeploy": true }),
        )
        .await;
        assert_eq!(s, 201);

        // Delete is 204 with no body.
        let (s, body) = call(
            &h,
            Method::DELETE,
            &format!("/v2/apis/{api_id}"),
            Value::Null,
        )
        .await;
        assert_eq!(s, 204);
        assert!(body.is_null());
    }

    #[tokio::test]
    async fn v2_websocket_api_with_reserved_routes() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (s, api) = call(
            &h,
            Method::POST,
            "/v2/apis",
            json!({ "name": "ws", "protocolType": "WEBSOCKET", "routeSelectionExpression": "$request.body.action" }),
        )
        .await;
        assert_eq!(s, 201);
        assert_eq!(api["protocolType"], "WEBSOCKET");
        assert_eq!(api["routeSelectionExpression"], "$request.body.action");
        assert!(api["apiEndpoint"].as_str().unwrap().starts_with("wss://"));
        let api_id = api["apiId"].as_str().unwrap().to_string();

        for key in ["$connect", "$disconnect", "$default", "sendMessage"] {
            let (s, _) = call(
                &h,
                Method::POST,
                &format!("/v2/apis/{api_id}/routes"),
                json!({ "routeKey": key }),
            )
            .await;
            assert_eq!(s, 201, "route {key}");
        }
        let (s, routes) = call(
            &h,
            Method::GET,
            &format!("/v2/apis/{api_id}/routes"),
            Value::Null,
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(routes["items"].as_array().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn v2_websocket_requires_route_selection_expression() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (s, _) = call(
            &h,
            Method::POST,
            "/v2/apis",
            json!({ "name": "ws", "protocolType": "WEBSOCKET" }),
        )
        .await;
        assert_eq!(s, 400);
    }

    #[tokio::test]
    async fn v2_invalid_protocol_type_is_bad_request() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (s, _) = call(
            &h,
            Method::POST,
            "/v2/apis",
            json!({ "name": "x", "protocolType": "GRPC" }),
        )
        .await;
        assert_eq!(s, 400);
    }

    #[tokio::test]
    async fn v1_api_key_route_honors_include_value_query() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (status, key) = call(
            &h,
            Method::POST,
            "/apikeys",
            json!({ "name": "key", "value": "secret" }),
        )
        .await;
        assert_eq!(status, 201);
        let key_id = key["id"].as_str().unwrap();

        let (status, hidden) =
            call(&h, Method::GET, &format!("/apikeys/{key_id}"), Value::Null).await;
        assert_eq!(status, 200);
        assert!(hidden.get("value").is_none());

        let (status, included) = call(
            &h,
            Method::GET,
            &format!("/apikeys/{key_id}?includeValue=true"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(included["value"], "secret");
    }

    #[tokio::test]
    async fn v2_deployment_route_is_dispatched() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (_, api) = call(
            &h,
            Method::POST,
            "/v2/apis",
            json!({ "name": "deploy", "protocolType": "HTTP" }),
        )
        .await;
        let api_id = api["apiId"].as_str().unwrap();
        let (status, deployment) = call(
            &h,
            Method::POST,
            &format!("/v2/apis/{api_id}/deployments"),
            json!({ "description": "first" }),
        )
        .await;
        assert_eq!(status, 201);
        assert_eq!(deployment["description"], "first");
        assert!(deployment["deploymentId"].is_string());
    }

    #[test]
    fn register_installs_apigatewayv2_alias() {
        let registry = Arc::new(ServiceRegistry::with_known_services());
        register(&registry);
        assert!(registry
            .native_handler(&ServiceName::new("apigatewayv2"))
            .is_some());
    }

    #[test]
    fn path_invoke_forms_are_distinguished_from_control_plane_paths() {
        assert!(is_invoke_path("/restapis/api/prod"));
        assert!(is_invoke_path("/restapis/api/prod/_user_request_/items"));
        assert!(is_invoke_path("/execute-api/api/prod/items"));
        assert!(!is_invoke_path("/restapis/api/resources"));
    }

    #[tokio::test]
    async fn custom_domain_mapping_dispatches_to_execute() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (_, api) = call(
            &h,
            Method::POST,
            "/v2/apis",
            json!({ "name": "custom", "protocolType": "HTTP" }),
        )
        .await;
        let api_id = api["apiId"].as_str().unwrap();
        call(
            &h,
            Method::POST,
            &format!("/v2/apis/{api_id}/stages"),
            json!({ "stageName": "prod" }),
        )
        .await;
        call(
            &h,
            Method::POST,
            &format!("/v2/apis/{api_id}/routes"),
            json!({ "routeKey": "$default" }),
        )
        .await;
        call(
            &h,
            Method::POST,
            "/v2/domainnames",
            json!({ "domainName": "api.example.test" }),
        )
        .await;
        let (status, _) = call(
            &h,
            Method::POST,
            "/v2/domainnames/api.example.test/apimappings",
            json!({ "apiId": api_id, "stage": "prod", "apiMappingKey": "api" }),
        )
        .await;
        assert_eq!(status, 201);

        let mut request = req(Method::GET, "/api/items?x=1", Value::Null);
        request.headers.insert(
            "host",
            http::HeaderValue::from_static("api.example.test:4566"),
        );
        let response = h.handle(request).await;
        assert_eq!(response.status(), 500);
    }

    #[tokio::test]
    async fn private_domain_requires_id_and_preserves_public_domain() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let name = "ledger.example.test";
        let policy = r#"{"Version":"2012-10-17","Statement":[]}"#;
        let (status, private) = call(
            &h,
            Method::POST,
            "/domainnames",
            json!({
                "domainName": name,
                "certificateArn": "arn:aws:acm:us-east-1:000000000000:certificate/test",
                "endpointConfiguration": {"types": ["PRIVATE"], "ipAddressType": "dualstack"},
                "policy": policy,
            }),
        )
        .await;
        assert_eq!(status, 201);
        let id = private["domainNameId"].as_str().unwrap();
        assert_eq!(id.len(), 8);
        assert_eq!(private["domainNameStatus"], "AVAILABLE");
        assert_eq!(
            private["domainNameArn"],
            format!("arn:aws:apigateway:us-east-1:000000000000:/domainnames/{name}+{id}")
        );
        assert_eq!(private["policy"], policy);

        let (status, _) = call(
            &h,
            Method::GET,
            &format!("/domainnames/{name}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 400);
        let (status, _) = call(
            &h,
            Method::GET,
            &format!("/domainnames/{name}?domainNameId=wrong"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 404);
        let (status, fetched) = call(
            &h,
            Method::GET,
            &format!("/domainnames/{name}?domainNameId={id}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(fetched["domainNameArn"], private["domainNameArn"]);

        let (status, patched) = call(&h, Method::PATCH, &format!("/domainnames/{name}?domainNameId={id}"),
            json!({"patchOperations": [{"op": "replace", "path": "/managementPolicy", "value": policy}]})).await;
        assert_eq!(status, 200);
        assert_eq!(patched["managementPolicy"], policy);

        let (status, public) = call(
            &h,
            Method::POST,
            "/domainnames",
            json!({"domainName": name, "endpointConfiguration": {"types": ["REGIONAL"]}}),
        )
        .await;
        assert_eq!(status, 201);
        assert!(public.get("domainNameId").is_none());
        let (status, fetched_public) = call(
            &h,
            Method::GET,
            &format!("/domainnames/{name}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 200);
        assert!(fetched_public.get("domainNameId").is_none());
        let (status, listed) = call(&h, Method::GET, "/domainnames", Value::Null).await;
        assert_eq!(status, 200);
        assert_eq!(listed["item"].as_array().unwrap().len(), 2);

        let (status, _) = call(
            &h,
            Method::DELETE,
            &format!("/domainnames/{name}?domainNameId={id}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 202);
        let (status, _) = call(
            &h,
            Method::GET,
            &format!("/domainnames/{name}?domainNameId={id}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 404);
        let (status, _) = call(
            &h,
            Method::GET,
            &format!("/domainnames/{name}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn private_domain_associations_paginate_and_delete_by_encoded_arn() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (_, domain) = call(&h, Method::POST, "/domainnames", json!({
            "domainName": "private.example.test", "endpointConfiguration": {"types": ["PRIVATE"]}
        })).await;
        let domain_arn = domain["domainNameArn"].as_str().unwrap();
        let id = domain["domainNameId"].as_str().unwrap();
        let (status, _) = call(&h, Method::POST, "/domainnameaccessassociations", json!({
            "domainNameArn": domain_arn, "accessAssociationSourceType": "VPC", "accessAssociationSource": "vpce-aaaa"
        })).await;
        assert_eq!(status, 400);
        let (status, first) = call(&h, Method::POST, "/domainnameaccessassociations", json!({
            "domainNameArn": domain_arn, "accessAssociationSourceType": "VPCE", "accessAssociationSource": "vpce-aaaa"
        })).await;
        assert_eq!(status, 201);
        let association_arn = first["domainNameAccessAssociationArn"].as_str().unwrap();
        assert!(
            association_arn.contains(&format!("private.example.test+{id}/vpcesource/vpce-aaaa"))
        );
        let (status, _) = call(&h, Method::POST, "/domainnameaccessassociations", json!({
            "domainNameArn": domain_arn, "accessAssociationSourceType": "VPCE", "accessAssociationSource": "vpce-aaaa"
        })).await;
        assert_eq!(status, 409);
        let (status, _) = call(&h, Method::POST, "/domainnameaccessassociations", json!({
            "domainNameArn": domain_arn, "accessAssociationSourceType": "VPCE", "accessAssociationSource": "vpce-bbbb"
        })).await;
        assert_eq!(status, 201);
        let (status, page) = call(
            &h,
            Method::GET,
            "/domainnameaccessassociations?limit=1",
            Value::Null,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(page["item"].as_array().unwrap().len(), 1);
        assert_eq!(page["position"], "1");
        let (status, page) = call(
            &h,
            Method::GET,
            "/domainnameaccessassociations?limit=1&position=1",
            Value::Null,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(page["item"].as_array().unwrap().len(), 1);
        assert!(page.get("position").is_none());
        let encoded = association_arn.replace('+', "%2B").replace('/', "%2F");
        let (status, _) = call(
            &h,
            Method::DELETE,
            &format!("/domainnameaccessassociations/{encoded}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 202);
        let (status, _) = call(
            &h,
            Method::DELETE,
            &format!("/domainnameaccessassociations/{encoded}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn private_base_path_mapping_requires_matching_domain_id() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (_, domain) = call(&h, Method::POST, "/domainnames", json!({
            "domainName": "mapping.example.test", "endpointConfiguration": {"types": ["PRIVATE"]}
        })).await;
        let id = domain["domainNameId"].as_str().unwrap();
        let (_, public_api) =
            call(&h, Method::POST, "/restapis", json!({"name": "public-api"})).await;
        let public_api_id = public_api["id"].as_str().unwrap();
        h.store
            .rest("000000000000", "us-east-1", public_api_id)
            .unwrap()
            .write()
            .await
            .stages
            .insert("prod".into(), json!({}));
        let public_mapping =
            json!({"basePath": "ledger", "restApiId": public_api_id, "stage": "prod"});
        let (status, _) = call(
            &h,
            Method::POST,
            "/domainnames/mapping.example.test/basepathmappings",
            public_mapping.clone(),
        )
        .await;
        assert_eq!(status, 400);
        let (status, _) = call(
            &h,
            Method::POST,
            "/domainnames/mapping.example.test/basepathmappings?domainNameId=wrong",
            public_mapping.clone(),
        )
        .await;
        assert_eq!(status, 404);
        let (status, error) = call(
            &h,
            Method::POST,
            &format!("/domainnames/mapping.example.test/basepathmappings?domainNameId={id}"),
            public_mapping,
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(
            error["message"],
            "PRIVATE custom domains require a PRIVATE REST API"
        );

        let (_, private_api) = call(
            &h,
            Method::POST,
            "/restapis",
            json!({"name": "private-api", "endpointConfiguration": {"types": ["PRIVATE"]}}),
        )
        .await;
        let private_api_id = private_api["id"].as_str().unwrap();
        h.store
            .rest("000000000000", "us-east-1", private_api_id)
            .unwrap()
            .write()
            .await
            .stages
            .insert("prod".into(), json!({}));
        let mapping = json!({"basePath": "ledger", "restApiId": private_api_id, "stage": "prod"});
        let (status, created) = call(
            &h,
            Method::POST,
            &format!("/domainnames/mapping.example.test/basepathmappings?domainNameId={id}"),
            mapping,
        )
        .await;
        assert_eq!(status, 201);
        assert_eq!(created["basePath"], "ledger");
        let (status, mappings) = call(
            &h,
            Method::GET,
            &format!("/domainnames/mapping.example.test/basepathmappings?domainNameId={id}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(mappings["item"].as_array().unwrap().len(), 1);
        let (status, _) = call(
            &h,
            Method::PATCH,
            &format!("/domainnames/mapping.example.test/basepathmappings/ledger?domainNameId={id}"),
            json!({"patchOperations": [{"op": "replace", "path": "/restApiId", "value": public_api_id}]}),
        )
        .await;
        assert_eq!(status, 400);
        let (status, existing) = call(
            &h,
            Method::GET,
            &format!("/domainnames/mapping.example.test/basepathmappings/ledger?domainNameId={id}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(existing["restApiId"], private_api_id);
    }

    #[tokio::test]
    async fn public_domain_host_routes_when_private_domain_has_same_name() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let name = "shared.example.test";
        let (_, api) = call(
            &h,
            Method::POST,
            "/v2/apis",
            json!({
                "name": "public-http", "protocolType": "HTTP"
            }),
        )
        .await;
        let api_id = api["apiId"].as_str().unwrap();
        let (status, _) = call(
            &h,
            Method::POST,
            &format!("/v2/apis/{api_id}/stages"),
            json!({"stageName": "prod"}),
        )
        .await;
        assert_eq!(status, 201);
        let (status, _) = call(
            &h,
            Method::POST,
            "/v2/domainnames",
            json!({"domainName": name}),
        )
        .await;
        assert_eq!(status, 201);
        let (status, _) = call(
            &h,
            Method::POST,
            &format!("/v2/domainnames/{name}/apimappings"),
            json!({
                "apiId": api_id, "stage": "prod", "apiMappingKey": "api"
            }),
        )
        .await;
        assert_eq!(status, 201);
        let (status, _) = call(
            &h,
            Method::POST,
            "/domainnames",
            json!({
                "domainName": name, "endpointConfiguration": {"types": ["PRIVATE"]}
            }),
        )
        .await;
        assert_eq!(status, 201);
        let uri: http::Uri = "/api/items".parse().unwrap();
        let (target_host, target_uri) =
            custom_domain_target(&h.store, "000000000000", "us-east-1", name, &uri)
                .await
                .unwrap();
        assert!(target_host.contains(api_id));
        assert_eq!(
            target_uri.path(),
            format!("/execute-api/{api_id}/prod/items")
        );
        let mut request = req(Method::GET, "/api/items", Value::Null);
        request.headers.insert(
            "host",
            http::HeaderValue::from_static("shared.example.test:4566"),
        );
        let response = h.handle(request).await;
        assert_ne!(response.status(), 403);
    }

    #[tokio::test]
    async fn private_domain_host_is_forbidden_even_with_association() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (_, private) = call(&h, Method::POST, "/domainnames", json!({
            "domainName": "private.example.test", "endpointConfiguration": {"types": ["PRIVATE"]}
        })).await;
        let (_, _) = call(&h, Method::POST, "/domainnameaccessassociations", json!({
            "domainNameArn": private["domainNameArn"], "accessAssociationSourceType": "VPCE", "accessAssociationSource": "vpce-aaaa"
        })).await;
        let mut request = req(Method::GET, "/prod/items", Value::Null);
        request.headers.insert(
            "host",
            http::HeaderValue::from_static("private.example.test:4566"),
        );
        request.headers.insert(
            "x-amzn-vpce-id",
            http::HeaderValue::from_static("vpce-aaaa"),
        );
        let response = h.handle(request).await;
        assert_eq!(response.status(), 403);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["message"],
            "Forbidden"
        );
    }

    #[tokio::test]
    async fn unknown_resource_is_not_found() {
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let (s, _) = call(&h, Method::GET, "/bogus", Value::Null).await;
        assert_eq!(s, 404);
    }
}

/// End-to-end JWT authorizer tests: a real RSA-signed token is validated against a real
/// local JWKS endpoint, and the integration only runs when the token is valid.
#[cfg(test)]
mod jwt_authorizer_e2e {
    use super::*;
    use axum::routing::get;
    use axum::Router;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;

    const SIGNING_KEY_PEM: &str = include_str!("../tests/fixtures/jwt_signing_key.pem");
    const JWKS_JSON: &str = include_str!("../tests/fixtures/jwks.json");

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Control-plane call (no execute-api host) returning `(status, json)`.
    async fn call(h: &ApiGwHandler, method: Method, path: &str, body: Value) -> (u16, Value) {
        let req = ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from(body.to_string()),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        };
        let resp = h.handle(req).await;
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    /// A real OIDC issuer: serves discovery + JWKS. Returns its base URL (the issuer).
    async fn spawn_issuer() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let disco_base = base.clone();
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let base = disco_base.clone();
                    async move {
                        axum::Json(
                            json!({ "issuer": base, "jwks_uri": format!("{base}/jwks.json") }),
                        )
                    }
                }),
            )
            .route(
                "/jwks.json",
                get(|| async { ([("content-type", "application/json")], JWKS_JSON) }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    /// A real backend for the HTTP_PROXY integration.
    async fn spawn_backend() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(get(|| async { "backend-ok" }));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    fn sign(issuer: &str, claims: Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());
        let key =
            EncodingKey::from_rsa_pem(SIGNING_KEY_PEM.as_bytes()).expect("fixture key parses");
        let mut full = claims;
        full["iss"] = json!(issuer);
        encode(&header, &full, &key).expect("sign")
    }

    /// Build an invoke request to the execute path.
    fn invoke_req(api_id: &str, path: &str, auth: Option<&str>) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_str(&format!("{api_id}.execute-api.us-east-1.amazonaws.com"))
                .unwrap(),
        );
        if let Some(a) = auth {
            headers.insert("authorization", HeaderValue::from_str(a).unwrap());
        }
        ServiceRequest {
            method: Method::GET,
            uri: path.parse().unwrap(),
            headers,
            body: Bytes::new(),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        }
    }

    /// Wire an HTTP API with a `$default` route guarded by a JWT authorizer and an HTTP_PROXY
    /// integration, returning the api id.
    async fn wire_api(h: &ApiGwHandler, issuer: &str, backend: &str) -> String {
        let (_, api) = call(
            h,
            Method::POST,
            "/v2/apis",
            json!({ "name": "secured", "protocolType": "HTTP" }),
        )
        .await;
        let api_id = api["apiId"].as_str().unwrap().to_string();
        let (_, integ) = call(
            h,
            Method::POST,
            &format!("/v2/apis/{api_id}/integrations"),
            json!({ "integrationType": "HTTP_PROXY", "integrationUri": backend, "integrationMethod": "GET" }),
        )
        .await;
        let integ_id = integ["integrationId"].as_str().unwrap().to_string();
        let (_, auth) = call(
            h,
            Method::POST,
            &format!("/v2/apis/{api_id}/authorizers"),
            json!({
                "name": "jwt",
                "authorizerType": "JWT",
                "identitySource": ["$request.header.Authorization"],
                "jwtConfiguration": { "issuer": issuer, "audience": ["my-aud"] }
            }),
        )
        .await;
        let auth_id = auth["authorizerId"].as_str().unwrap().to_string();
        let (_, route) = call(
            h,
            Method::POST,
            &format!("/v2/apis/{api_id}/routes"),
            json!({ "routeKey": "$default", "target": format!("integrations/{integ_id}") }),
        )
        .await;
        let route_id = route["routeId"].as_str().unwrap().to_string();
        let (s, _) = call(
            h,
            Method::PATCH,
            &format!("/v2/apis/{api_id}/routes/{route_id}"),
            json!({ "authorizationType": "JWT", "authorizerId": auth_id }),
        )
        .await;
        assert_eq!(s, 200);
        call(
            h,
            Method::POST,
            &format!("/v2/apis/{api_id}/stages"),
            json!({ "stageName": "prod" }),
        )
        .await;
        api_id
    }

    #[tokio::test]
    async fn valid_token_reaches_integration() {
        let issuer = spawn_issuer().await;
        let backend = spawn_backend().await;
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let api_id = wire_api(&h, &issuer, &backend).await;

        let token = sign(
            &issuer,
            json!({ "aud": "my-aud", "exp": now() + 3600, "iat": now() - 5, "sub": "u1" }),
        );
        let resp = h
            .handle(invoke_req(
                &api_id,
                "/prod/anything",
                Some(&format!("Bearer {token}")),
            ))
            .await;
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"backend-ok");
    }

    #[tokio::test]
    async fn missing_token_is_401() {
        let issuer = spawn_issuer().await;
        let backend = spawn_backend().await;
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let api_id = wire_api(&h, &issuer, &backend).await;
        let resp = h.handle(invoke_req(&api_id, "/prod/anything", None)).await;
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn expired_token_is_401() {
        let issuer = spawn_issuer().await;
        let backend = spawn_backend().await;
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let api_id = wire_api(&h, &issuer, &backend).await;
        let token = sign(
            &issuer,
            json!({ "aud": "my-aud", "exp": now() - 3600, "iat": now() - 7200 }),
        );
        let resp = h
            .handle(invoke_req(
                &api_id,
                "/prod/anything",
                Some(&format!("Bearer {token}")),
            ))
            .await;
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn malformed_nbf_is_401() {
        let issuer = spawn_issuer().await;
        let backend = spawn_backend().await;
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let api_id = wire_api(&h, &issuer, &backend).await;
        let token = sign(
            &issuer,
            json!({ "aud": "my-aud", "exp": now() + 3600, "nbf": "99999999999" }),
        );
        let resp = h
            .handle(invoke_req(
                &api_id,
                "/prod/anything",
                Some(&format!("Bearer {token}")),
            ))
            .await;
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn wrong_audience_is_401() {
        let issuer = spawn_issuer().await;
        let backend = spawn_backend().await;
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let api_id = wire_api(&h, &issuer, &backend).await;
        let token = sign(
            &issuer,
            json!({ "aud": "other", "exp": now() + 3600, "iat": now() - 5 }),
        );
        let resp = h
            .handle(invoke_req(
                &api_id,
                "/prod/anything",
                Some(&format!("Bearer {token}")),
            ))
            .await;
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn wrong_issuer_is_401() {
        let issuer = spawn_issuer().await;
        let backend = spawn_backend().await;
        let h = ApiGwHandler::new(std::sync::Weak::new());
        let api_id = wire_api(&h, &issuer, &backend).await;
        // Sign with a different iss than the authorizer's configured issuer.
        let token = sign(
            "http://evil.example",
            json!({ "aud": "my-aud", "exp": now() + 3600, "iat": now() - 5 }),
        );
        let resp = h
            .handle(invoke_req(
                &api_id,
                "/prod/anything",
                Some(&format!("Bearer {token}")),
            ))
            .await;
        assert_eq!(resp.status(), 401);
    }
}

/// AWS_PROXY execute path: verifies the proxy event is built and dispatched to the Lambda
/// service through the registry, and the structured Lambda response is interpreted. A
/// stand-in Lambda handler stands for the (not-yet-implemented) Lambda data plane.
#[cfg(test)]
mod aws_proxy_e2e {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue};
    use locallycloud_core::integration::InternalDispatcher;
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
    use serde_json::json;
    use std::time::Duration;

    /// Echoes the proxy event's routeKey back inside a structured v2 proxy response.
    struct EchoLambda;

    #[async_trait]
    impl NativeHandler for EchoLambda {
        async fn handle(&self, request: ServiceRequest) -> Response {
            let event: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
            let route_key = event
                .get("routeKey")
                .and_then(Value::as_str)
                .unwrap_or("none");
            let claims_sub = event
                .pointer("/requestContext/authorizer/jwt/claims/sub")
                .and_then(Value::as_str)
                .unwrap_or("no-sub");
            let out = json!({
                "statusCode": 200,
                "headers": { "x-route": route_key, "x-sub": claims_sub },
                "body": "lambda-ok"
            });
            http::Response::builder()
                .status(200)
                .body(Body::from(out.to_string()))
                .unwrap()
        }
    }

    async fn call(h: &Arc<dyn NativeHandler>, method: Method, path: &str, body: Value) -> Value {
        let req = ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from(body.to_string()),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        };
        let resp = h.handle(req).await;
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        }
    }

    #[derive(Default)]
    struct RecordingLambda(std::sync::Mutex<Vec<Value>>);

    #[async_trait]
    impl NativeHandler for RecordingLambda {
        async fn handle(&self, request: ServiceRequest) -> Response {
            self.0
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&request.body).unwrap());
            http::Response::builder()
                .status(200)
                .body(Body::from(r#"{"statusCode":200,"body":"reached"}"#))
                .unwrap()
        }
    }

    async fn waf_call(waf: &locallycloud_wafv2::WafHandler, operation: &str, body: Value) -> Value {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-amz-json-1.1"),
        );
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("AWSWAF_20190729.{operation}")).unwrap(),
        );
        let response = waf
            .handle(ServiceRequest {
                method: Method::POST,
                uri: "/".parse().unwrap(),
                headers,
                body: Bytes::from(body.to_string()),
                region: "us-east-1".into(),
                account_id: "000000000000".into(),
                request_id: "rid".into(),
            })
            .await;
        assert_eq!(response.status(), 200, "WAF {operation}");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn deleting_stage_detaches_only_its_waf_association_before_name_reuse() {
        let registry = ServiceRegistry::with_known_services();
        let binding = crate::register(&registry);
        let waf =
            locallycloud_wafv2::WafHandler::new_with_stage_resolver(Arc::new(binding.clone()));
        binding.set_waf_evaluator(waf.clone());
        let gateway = registry
            .native_handler(&ServiceName::new("apigateway"))
            .unwrap();
        let api = call(
            &gateway,
            Method::POST,
            "/restapis",
            json!({"name":"cleanup"}),
        )
        .await;
        let api_id = api["id"].as_str().unwrap();
        let deployment = call(
            &gateway,
            Method::POST,
            &format!("/restapis/{api_id}/deployments"),
            json!({"stageName":"prod"}),
        )
        .await;
        let deployment_id = deployment["id"].as_str().unwrap();
        call(
            &gateway,
            Method::POST,
            &format!("/restapis/{api_id}/stages"),
            json!({"stageName":"other","deploymentId":deployment_id}),
        )
        .await;
        let visibility = json!({"CloudWatchMetricsEnabled":false,"SampledRequestsEnabled":false,"MetricName":"cleanup"});
        let acl = waf_call(
            &waf,
            "CreateWebACL",
            json!({"Name":"deny","Scope":"REGIONAL","DefaultAction":{"Block":{}},"Rules":[],"VisibilityConfig":visibility}),
        )
        .await;
        let acl_arn = acl["Summary"]["ARN"].as_str().unwrap();
        let prod_arn = format!("arn:aws:apigateway:us-east-1::/restapis/{api_id}/stages/prod");
        let other_arn = format!("arn:aws:apigateway:us-east-1::/restapis/{api_id}/stages/other");
        for arn in [&prod_arn, &other_arn] {
            waf_call(
                &waf,
                "AssociateWebACL",
                json!({"WebACLArn":acl_arn,"ResourceArn":arn}),
            )
            .await;
        }
        let before = waf_call(
            &waf,
            "ListResourcesForWebACL",
            json!({"WebACLArn":acl_arn,"ResourceType":"API_GATEWAY"}),
        )
        .await;
        assert_eq!(before["ResourceArns"].as_array().unwrap().len(), 2);

        let deleted = gateway
            .handle(ServiceRequest {
                method: Method::DELETE,
                uri: format!("/restapis/{api_id}/stages/prod").parse().unwrap(),
                headers: HeaderMap::new(),
                body: Bytes::new(),
                region: "us-east-1".into(),
                account_id: "000000000000".into(),
                request_id: "rid".into(),
            })
            .await;
        assert_eq!(deleted.status(), 202);
        let remaining = waf_call(
            &waf,
            "ListResourcesForWebACL",
            json!({"WebACLArn":acl_arn,"ResourceType":"API_GATEWAY"}),
        )
        .await;
        assert_eq!(remaining["ResourceArns"], json!([other_arn]));

        let recreated = call(
            &gateway,
            Method::POST,
            &format!("/restapis/{api_id}/stages"),
            json!({"stageName":"prod","deploymentId":deployment_id}),
        )
        .await;
        assert_eq!(recreated["stageName"], "prod");
        let no_acl = waf.evaluate(&locallycloud_wafv2::WafRequest {
            account_id: "000000000000",
            region: "us-east-1",
            resource_arn: &prod_arn,
            source_ip: "127.0.0.1",
            method: "GET",
            uri_path: "/",
            headers: &HeaderMap::new(),
        });
        assert_eq!(no_acl, Ok(locallycloud_wafv2::WafDecision::Unassociated));
    }

    #[tokio::test]
    async fn associated_waf_blocks_without_peer_and_hides_internal_header_from_lambda() {
        let reg = ServiceRegistry::with_known_services();
        let lambda = Arc::new(RecordingLambda::default());
        reg.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            lambda.clone(),
        );
        reg.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &reg,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(true),
            "us-east-1".into(),
            "000000000000".into(),
        )));
        let binding = crate::register(&reg);
        let waf =
            locallycloud_wafv2::WafHandler::new_with_stage_resolver(Arc::new(binding.clone()));
        binding.set_waf_evaluator(waf.clone());
        let gateway = reg.native_handler(&ServiceName::new("apigateway")).unwrap();
        let api = call(
            &gateway,
            Method::POST,
            "/restapis",
            json!({"name":"waf-test"}),
        )
        .await;
        let api_id = api["id"].as_str().unwrap();
        let root_id = api["rootResourceId"].as_str().unwrap();
        call(
            &gateway,
            Method::PUT,
            &format!("/restapis/{api_id}/resources/{root_id}/methods/GET"),
            json!({"authorizationType":"NONE"}),
        )
        .await;
        call(&gateway, Method::PUT, &format!("/restapis/{api_id}/resources/{root_id}/methods/GET/integration"),
            json!({"type":"AWS_PROXY","integrationHttpMethod":"POST","uri":"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/f/invocations"})).await;
        call(
            &gateway,
            Method::POST,
            &format!("/restapis/{api_id}/deployments"),
            json!({"stageName":"prod"}),
        )
        .await;
        let visibility = json!({"CloudWatchMetricsEnabled":false,"SampledRequestsEnabled":false,"MetricName":"wafTest"});
        let acl = waf_call(
            &waf,
            "CreateWebACL",
            json!({"Name":"deny", "Scope":"REGIONAL",
            "DefaultAction":{"Block":{}}, "Rules":[], "VisibilityConfig":visibility}),
        )
        .await;
        let arn = acl["Summary"]["ARN"].as_str().unwrap();
        let id = acl["Summary"]["Id"].as_str().unwrap();
        let lock = acl["Summary"]["LockToken"].as_str().unwrap();
        let stage_arn = format!("arn:aws:apigateway:us-east-1::/restapis/{api_id}/stages/prod");
        waf_call(
            &waf,
            "AssociateWebACL",
            json!({"WebACLArn":arn,"ResourceArn":stage_arn}),
        )
        .await;

        let path = format!("/restapis/{api_id}/prod/_user_request_/");
        let mut no_peer = ServiceRequest {
            method: Method::GET,
            uri: path.parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "rid".into(),
        };
        no_peer
            .headers
            .insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        let response = gateway.handle(no_peer).await;
        assert_eq!(response.status(), 403);
        assert!(lambda.0.lock().unwrap().is_empty());

        waf_call(&waf, "UpdateWebACL", json!({"Name":"deny","Scope":"REGIONAL","Id":id,
            "LockToken":lock,"DefaultAction":{"Allow":{}},"Rules":[],"VisibilityConfig":visibility})).await;
        let mut trusted = ServiceRequest {
            method: Method::GET,
            uri: format!("/restapis/{api_id}/prod/_user_request_/")
                .parse()
                .unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "rid".into(),
        };
        trusted.headers.insert(
            "x-locallycloud-trusted-peer-ip",
            HeaderValue::from_static("127.0.0.1"),
        );
        let response = gateway.handle(trusted).await;
        assert_eq!(response.status(), 200);
        let events = lambda.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0]["headers"]
            .get("x-locallycloud-trusted-peer-ip")
            .is_none());
        assert!(events[0]["multiValueHeaders"]
            .get("x-locallycloud-trusted-peer-ip")
            .is_none());
    }

    #[tokio::test]
    async fn aws_proxy_dispatches_event_and_interprets_response() {
        let reg = ServiceRegistry::with_known_services();
        reg.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            Arc::new(EchoLambda),
        );
        reg.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &reg,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(true),
            "us-east-1".into(),
            "000000000000".into(),
        )));
        crate::register(&reg);
        let h = reg.native_handler(&ServiceName::new("apigateway")).unwrap();

        let api = call(
            &h,
            Method::POST,
            "/v2/apis",
            json!({ "name": "p", "protocolType": "HTTP" }),
        )
        .await;
        let api_id = api["apiId"].as_str().unwrap().to_string();
        let integ = call(
            &h,
            Method::POST,
            &format!("/v2/apis/{api_id}/integrations"),
            json!({ "integrationType": "AWS_PROXY", "integrationUri": "arn:aws:lambda:us-east-1:000000000000:function:f", "payloadFormatVersion": "2.0" }),
        )
        .await;
        let integ_id = integ["integrationId"].as_str().unwrap().to_string();
        call(
            &h,
            Method::POST,
            &format!("/v2/apis/{api_id}/routes"),
            json!({ "routeKey": "$default", "target": format!("integrations/{integ_id}") }),
        )
        .await;
        call(
            &h,
            Method::POST,
            &format!("/v2/apis/{api_id}/stages"),
            json!({ "stageName": "prod" }),
        )
        .await;

        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_str(&format!("{api_id}.execute-api.us-east-1.amazonaws.com"))
                .unwrap(),
        );
        let invoke = ServiceRequest {
            method: Method::GET,
            uri: "/prod/thing".parse().unwrap(),
            headers,
            body: Bytes::new(),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        };
        let resp = h.handle(invoke).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-route").unwrap(), "GET /thing");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"lambda-ok");

        // The `$default` stage carries no stage segment in the invoke path.
        call(
            &h,
            Method::POST,
            &format!("/v2/apis/{api_id}/stages"),
            json!({ "stageName": "$default" }),
        )
        .await;
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_str(&format!("{api_id}.execute-api.us-east-1.amazonaws.com"))
                .unwrap(),
        );
        let invoke = ServiceRequest {
            method: Method::GET,
            uri: "/thing2".parse().unwrap(),
            headers,
            body: Bytes::new(),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        };
        let resp = h.handle(invoke).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-route").unwrap(), "GET /thing2");
    }
}
