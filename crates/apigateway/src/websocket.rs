//! WebSocket connection state, management operations, routing, and Lambda event helpers.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, Method, Uri};
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::timeout;
use uuid::Uuid;

use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::registry::ServiceRegistry;

use crate::auth::policy_allows;
use crate::error::ApiGwError;
use crate::proxy_event::percent_decode;
use crate::store::ApiGwStore;

const MAX_POST_PAYLOAD_BYTES: usize = 128 * 1024;
const OUTBOUND_CHANNEL_CAPACITY: usize = 32;
const OUTBOUND_HISTORY_CAPACITY: usize = 64;
const OUTBOUND_MESSAGES: &str = "__outboundMessages";

#[cfg(test)]
pub(crate) const MAX_CONNECTION_PAYLOAD_BYTES: usize = MAX_POST_PAYLOAD_BYTES;

type Out = Result<(u16, Value), ApiGwError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WebSocketEventType {
    Connect,
    Message,
    Disconnect,
}

impl WebSocketEventType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "CONNECT",
            Self::Message => "MESSAGE",
            Self::Disconnect => "DISCONNECT",
        }
    }
}

pub(crate) struct WebSocketEventInput<'a> {
    pub connection_id: &'a str,
    pub route_key: &'a str,
    pub event_type: WebSocketEventType,
    pub api_id: &'a str,
    pub stage: &'a str,
    pub domain_name: &'a str,
    pub request_id: &'a str,
    pub account_id: &'a str,
    pub source_ip: &'a str,
    pub body: Option<&'a [u8]>,
    pub is_binary: bool,
}

struct ConnectionRegistration<'a> {
    account: &'a str,
    region: &'a str,
    connection_id: &'a str,
    api_id: &'a str,
    stage: &'a str,
    domain_name: &'a str,
    source_ip: &'a str,
}

fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

fn now_epoch_millis() -> i128 {
    OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000
}

fn gone(connection_id: &str) -> ApiGwError {
    ApiGwError::Gone(format!("The connection with id {connection_id} is gone"))
}

fn is_open(connection: &Value) -> bool {
    connection.get("open").and_then(Value::as_bool) == Some(true)
}

#[derive(Clone)]
struct WebSocketRuntime {
    store: Arc<ApiGwStore>,
    registry: Weak<ServiceRegistry>,
    account: String,
    region: String,
    api_id: String,
    stage: String,
    domain_name: String,
    source_ip: String,
    route_selection_expression: String,
    routes: Vec<Value>,
    integrations: BTreeMap<String, Value>,
    authorizer_context: Option<Value>,
}

struct LambdaOutput {
    function_error: bool,
    body: Bytes,
}

#[derive(Debug)]
struct UpgradeFailure {
    status: u16,
    message: String,
}

impl UpgradeFailure {
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn into_response(self) -> Response {
        http::Response::builder()
            .status(self.status)
            .header("content-type", "application/json")
            .body(Body::from(json!({ "message": self.message }).to_string()))
            .unwrap_or_else(|_| {
                let mut response = Response::new(Body::from(
                    json!({ "message": "Internal server error" }).to_string(),
                ));
                *response.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                response
            })
    }
}

/// Handle an execute-api WebSocket upgrade using the API Gateway v2 resources in `store`.
///
/// This entry point is intended to be called by `ApiGwHandler::handle_websocket`. It performs
/// `$connect` authorization and integration invocation before accepting the HTTP upgrade, then
/// owns the socket until disconnect while bridging management API posts through the store sender.
pub async fn handle_websocket(
    store: Arc<ApiGwStore>,
    registry: Weak<ServiceRegistry>,
    request: ServiceRequest,
    upgrade: WebSocketUpgrade,
    custom_domain: Option<String>,
) -> Response {
    let invoke_host = request
        .headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    let Some(api_id) = api_id_from_execute_host(&invoke_host).map(str::to_string) else {
        return UpgradeFailure::new(404, "Invalid execute-api host").into_response();
    };
    let Some(record) = store.v2(&request.account_id, &request.region, &api_id) else {
        return UpgradeFailure::new(404, format!("Invalid API identifier specified {api_id}"))
            .into_response();
    };

    let (stage, route_selection_expression, routes, integrations, authorizers) = {
        let guard = record.read().await;
        if custom_domain.is_none()
            && guard
                .api
                .get("disableExecuteApiEndpoint")
                .and_then(Value::as_bool)
                == Some(true)
        {
            return UpgradeFailure::new(403, "Forbidden").into_response();
        }
        let Some(stage) = stage_from_path(request.uri.path(), &guard.stages) else {
            return UpgradeFailure::new(404, "Invalid stage identifier specified").into_response();
        };
        let stage_value = &guard.stages[stage];
        let snapshot = match stage_value.get("deploymentId").and_then(Value::as_str) {
            Some(deployment_id) => match guard.deployment_snapshots.get(deployment_id) {
                Some(snapshot) => snapshot.clone(),
                None => {
                    return UpgradeFailure::new(500, "Deployment snapshot is unavailable")
                        .into_response()
                }
            },
            None => guard.snapshot(),
        };
        if snapshot.api.get("protocolType").and_then(Value::as_str) != Some("WEBSOCKET") {
            return UpgradeFailure::new(400, "API protocolType must be WEBSOCKET").into_response();
        }
        (
            stage.to_string(),
            snapshot
                .api
                .get("routeSelectionExpression")
                .and_then(Value::as_str)
                .unwrap_or("$request.body.action")
                .to_string(),
            snapshot.routes.values().cloned().collect::<Vec<_>>(),
            snapshot.integrations,
            snapshot.authorizers,
        )
    };

    let domain_name = custom_domain.unwrap_or(invoke_host);
    let Some(connect_route) = route_for_key(&routes, "$connect").cloned() else {
        return UpgradeFailure::new(404, "No route found for $connect").into_response();
    };
    let connection_id = Uuid::new_v4().simple().to_string();
    let source_ip = source_ip(&request.headers).to_string();
    let mut connect_event = build_websocket_event(&WebSocketEventInput {
        connection_id: &connection_id,
        route_key: "$connect",
        event_type: WebSocketEventType::Connect,
        api_id: &api_id,
        stage: &stage,
        domain_name: &domain_name,
        request_id: &request.request_id,
        account_id: &request.account_id,
        source_ip: &source_ip,
        body: None,
        is_binary: false,
    });

    let authorizer_context = match authorize_connect(
        &store,
        &registry,
        &request,
        &api_id,
        &stage,
        &connect_route,
        &authorizers,
        &connect_event,
    )
    .await
    {
        Ok(context) => context,
        Err(failure) => return failure.into_response(),
    };
    if let Some(context) = &authorizer_context {
        connect_event["requestContext"]["authorizer"] = context.clone();
    }

    let runtime = WebSocketRuntime {
        store,
        registry,
        account: request.account_id,
        region: request.region,
        api_id,
        stage,
        domain_name,
        source_ip,
        route_selection_expression,
        routes,
        integrations,
        authorizer_context,
    };
    match invoke_route(&runtime, &connect_route, connect_event).await {
        Ok(output) if !output.function_error => {
            if let Some(status) = integration_status(&output.body) {
                if !(200..300).contains(&status) {
                    return UpgradeFailure::new(status, "$connect integration rejected connection")
                        .into_response();
                }
            }
        }
        _ => {
            return UpgradeFailure::new(500, "$connect integration failed").into_response();
        }
    }

    upgrade
        .on_upgrade(move |socket| run_connection(socket, runtime, connection_id))
        .into_response()
}

async fn run_connection(mut socket: WebSocket, runtime: WebSocketRuntime, connection_id: String) {
    register_connection(
        &runtime.store,
        &ConnectionRegistration {
            account: &runtime.account,
            region: &runtime.region,
            connection_id: &connection_id,
            api_id: &runtime.api_id,
            stage: &runtime.stage,
            domain_name: &runtime.domain_name,
            source_ip: &runtime.source_ip,
        },
    )
    .await;
    let (sender, mut outbound) = mpsc::channel(OUTBOUND_CHANNEL_CAPACITY);
    runtime.store.register_connection_sender(
        &runtime.account,
        &runtime.region,
        &connection_id,
        sender,
    );

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > MAX_POST_PAYLOAD_BYTES {
                            break;
                        }
                        process_message(&runtime, &connection_id, text.as_bytes(), false).await;
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        if bytes.len() > MAX_POST_PAYLOAD_BYTES {
                            break;
                        }
                        process_message(&runtime, &connection_id, &bytes, true).await;
                    }
                    Some(Ok(Message::Ping(bytes))) => {
                        if !matches!(
                            timeout(Duration::from_secs(1), socket.send(Message::Pong(bytes))).await,
                            Ok(Ok(()))
                        ) {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                }
            }
            payload = outbound.recv() => {
                let Some(payload) = payload else { break };
                if !matches!(
                    timeout(Duration::from_secs(1), socket.send(Message::Binary(payload.into()))).await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
        }
    }

    if let Some(route) = route_for_key(&runtime.routes, "$disconnect") {
        let event = runtime.event(
            &connection_id,
            "$disconnect",
            WebSocketEventType::Disconnect,
            None,
            false,
        );
        let _ = invoke_route(&runtime, route, event).await;
    }
    runtime
        .store
        .remove_connection_sender(&runtime.account, &runtime.region, &connection_id);
    let _ = close_connection(
        &runtime.store,
        &runtime.account,
        &runtime.region,
        &connection_id,
    )
    .await;
}

async fn process_message(
    runtime: &WebSocketRuntime,
    connection_id: &str,
    body: &[u8],
    is_binary: bool,
) {
    let _ = touch_connection(
        &runtime.store,
        &runtime.account,
        &runtime.region,
        connection_id,
    )
    .await;
    let selected = resolve_route_selection(&runtime.route_selection_expression, body);
    let route = selected
        .as_deref()
        .and_then(|key| route_for_key(&runtime.routes, key))
        .or_else(|| route_for_key(&runtime.routes, "$default"));
    let Some(route) = route else { return };
    let route_key = route
        .get("routeKey")
        .and_then(Value::as_str)
        .unwrap_or("$default");
    let event = runtime.event(
        connection_id,
        route_key,
        WebSocketEventType::Message,
        Some(body),
        is_binary,
    );
    let _ = invoke_route(runtime, route, event).await;
}

impl WebSocketRuntime {
    fn event(
        &self,
        connection_id: &str,
        route_key: &str,
        event_type: WebSocketEventType,
        body: Option<&[u8]>,
        is_binary: bool,
    ) -> Value {
        let request_id = Uuid::new_v4().simple().to_string();
        let mut event = build_websocket_event(&WebSocketEventInput {
            connection_id,
            route_key,
            event_type,
            api_id: &self.api_id,
            stage: &self.stage,
            domain_name: &self.domain_name,
            request_id: &request_id,
            account_id: &self.account,
            source_ip: &self.source_ip,
            body,
            is_binary,
        });
        if let Some(context) = &self.authorizer_context {
            event["requestContext"]["authorizer"] = context.clone();
        }
        event
    }
}

#[allow(clippy::too_many_arguments)]
async fn authorize_connect(
    store: &ApiGwStore,
    registry: &Weak<ServiceRegistry>,
    request: &ServiceRequest,
    api_id: &str,
    stage: &str,
    route: &Value,
    authorizers: &BTreeMap<String, Value>,
    connect_event: &Value,
) -> Result<Option<Value>, UpgradeFailure> {
    let authorization_type = route
        .get("authorizationType")
        .and_then(Value::as_str)
        .unwrap_or("NONE");
    if authorization_type == "NONE" {
        return Ok(None);
    }
    if authorization_type != "CUSTOM" {
        return Err(UpgradeFailure::new(403, "Forbidden"));
    }
    let authorizer_id = route
        .get("authorizerId")
        .and_then(Value::as_str)
        .ok_or_else(|| UpgradeFailure::new(401, "Unauthorized"))?;
    let authorizer = authorizers
        .get(authorizer_id)
        .filter(|value| value.get("authorizerType").and_then(Value::as_str) == Some("REQUEST"))
        .ok_or_else(|| UpgradeFailure::new(401, "Unauthorized"))?;
    let identities = identity_values(authorizer, &request.headers, request.uri.query());
    if identities.is_empty() || identities.iter().any(String::is_empty) {
        return Err(UpgradeFailure::new(401, "Unauthorized"));
    }
    let route_arn = format!(
        "arn:aws:execute-api:{}:{}:{}/{}/$connect",
        request.region, request.account_id, api_id, stage
    );
    let ttl = authorizer
        .get("authorizerResultTtlInSeconds")
        .and_then(Value::as_u64)
        .unwrap_or(300);
    let cache_key = format!(
        "ws:{authorizer_id}:{route_arn}:{}",
        identities.join("\u{1f}")
    );
    if ttl > 0 {
        let shared = store.shared(&request.account_id, &request.region);
        let cached = {
            let mut guard = shared.write().await;
            let now = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
            guard.authorizer_cache.retain(|_, value| {
                value.get("expiresAt").and_then(Value::as_u64).unwrap_or(0) > now
            });
            guard
                .authorizer_cache
                .get(&cache_key)
                .and_then(|value| value.get("result"))
                .cloned()
        };
        if let Some(result) = cached {
            return websocket_authorizer_context(authorizer, &result, &route_arn);
        }
    }
    let event = json!({
        "type": "REQUEST",
        "methodArn": route_arn,
        "routeArn": route_arn,
        "identitySource": identities,
        "headers": headers_object(&request.headers),
        "queryStringParameters": query_object(request.uri.query()),
        "requestContext": connect_event.get("requestContext").cloned().unwrap_or(Value::Null),
    });
    let uri = authorizer
        .get("authorizerUri")
        .and_then(Value::as_str)
        .ok_or_else(|| UpgradeFailure::new(500, "Authorizer is not configured"))?;
    let output = invoke_lambda(
        registry,
        &request.account_id,
        &request.region,
        &request.request_id,
        uri,
        event,
        29_000,
    )
    .await
    .map_err(|_| UpgradeFailure::new(500, "Authorizer invocation failed"))?;
    if output.function_error {
        return Err(UpgradeFailure::new(500, "Authorizer invocation failed"));
    }
    let result: Value = serde_json::from_slice(&output.body)
        .map_err(|_| UpgradeFailure::new(500, "Invalid authorizer response"))?;
    let context = websocket_authorizer_context(authorizer, &result, &route_arn)?;
    if ttl > 0 {
        const MAX_AUTHORIZER_CACHE_ENTRIES: usize = 1024;
        let shared = store.shared(&request.account_id, &request.region);
        let mut guard = shared.write().await;
        while guard.authorizer_cache.len() >= MAX_AUTHORIZER_CACHE_ENTRIES {
            let Some(oldest) = guard.authorizer_cache.keys().next().cloned() else {
                break;
            };
            guard.authorizer_cache.remove(&oldest);
        }
        let now = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
        guard.authorizer_cache.insert(
            cache_key,
            json!({ "expiresAt": now.saturating_add(ttl), "result": result }),
        );
    }
    Ok(context)
}

fn websocket_authorizer_context(
    authorizer: &Value,
    result: &Value,
    route_arn: &str,
) -> Result<Option<Value>, UpgradeFailure> {
    let allowed = if authorizer
        .get("enableSimpleResponses")
        .and_then(Value::as_bool)
        == Some(true)
    {
        result.get("isAuthorized").and_then(Value::as_bool) == Some(true)
    } else {
        policy_allows(result, route_arn)
    };
    if !allowed {
        return Err(UpgradeFailure::new(403, "Forbidden"));
    }
    let mut context = result
        .get("context")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(principal_id) = result.get("principalId") {
        context.insert("principalId".into(), principal_id.clone());
    }
    Ok(Some(Value::Object(context)))
}

async fn invoke_route(
    runtime: &WebSocketRuntime,
    route: &Value,
    event: Value,
) -> Result<LambdaOutput, ()> {
    let target = route
        .get("target")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("integrations/"))
        .ok_or(())?;
    let integration = runtime.integrations.get(target).ok_or(())?;
    match integration
        .get("integrationType")
        .and_then(Value::as_str)
        .unwrap_or("")
    {
        "MOCK" => {
            return Ok(LambdaOutput {
                function_error: false,
                body: Bytes::from_static(b"{}"),
            });
        }
        "AWS_PROXY" => {}
        _ => return Err(()),
    }
    let uri = integration
        .get("integrationUri")
        .and_then(Value::as_str)
        .ok_or(())?;
    let timeout_millis = integration
        .get("timeoutInMillis")
        .and_then(Value::as_u64)
        .unwrap_or(29_000);
    invoke_lambda(
        &runtime.registry,
        &runtime.account,
        &runtime.region,
        &Uuid::new_v4().simple().to_string(),
        uri,
        event,
        timeout_millis,
    )
    .await
}

async fn invoke_lambda(
    registry: &Weak<ServiceRegistry>,
    _account: &str,
    region: &str,
    request_id: &str,
    integration_uri: &str,
    event: Value,
    timeout_millis: u64,
) -> Result<LambdaOutput, ()> {
    let registry = registry.upgrade().ok_or(())?;
    let dispatcher = registry.internal_dispatcher().ok_or(())?;
    let function = function_from_uri(integration_uri).ok_or(())?;
    let uri: Uri = format!("/2015-03-31/functions/{function}/invocations")
        .parse()
        .map_err(|_| ())?;
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential=locallycloud/19700101/{region}/lambda/aws4_request"
        ))
        .map_err(|_| ())?,
    );
    let response = timeout(
        Duration::from_millis(timeout_millis),
        dispatcher.dispatch(
            &Method::POST,
            &uri,
            &headers,
            Bytes::from(event.to_string()),
            request_id,
        ),
    )
    .await
    .map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    let function_error = response.headers().contains_key("x-amz-function-error");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(|_| ())?;
    Ok(LambdaOutput {
        function_error,
        body,
    })
}

fn api_id_from_execute_host(host: &str) -> Option<&str> {
    let host = host.split(':').next().unwrap_or(host);
    let lower = host.to_ascii_lowercase();
    let marker = lower.find(".execute-api.")?;
    let api_id = &host[..marker];
    (!api_id.is_empty()).then_some(api_id)
}

fn stage_from_path<'a>(path: &str, stages: &'a BTreeMap<String, Value>) -> Option<&'a str> {
    match path.split('/').find(|part| !part.is_empty()) {
        Some(stage) => stages
            .get_key_value(stage)
            .map(|(stage_name, _)| stage_name.as_str()),
        None => stages
            .get_key_value("$default")
            .map(|(stage_name, _)| stage_name.as_str()),
    }
}

fn route_for_key<'a>(routes: &'a [Value], key: &str) -> Option<&'a Value> {
    routes
        .iter()
        .find(|route| route.get("routeKey").and_then(Value::as_str) == Some(key))
}

fn source_ip(headers: &HeaderMap) -> &str {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .unwrap_or("")
}

fn headers_object(headers: &HeaderMap) -> Value {
    let mut object = Map::new();
    for (name, value) in headers {
        object.insert(
            name.as_str().to_string(),
            Value::String(String::from_utf8_lossy(value.as_bytes()).into_owned()),
        );
    }
    Value::Object(object)
}

fn query_object(query: Option<&str>) -> Value {
    let mut object = Map::new();
    for pair in query
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key);
        if !key.is_empty() {
            object.insert(key, Value::String(percent_decode(value)));
        }
    }
    if object.is_empty() {
        Value::Null
    } else {
        Value::Object(object)
    }
}

fn identity_values(authorizer: &Value, headers: &HeaderMap, query: Option<&str>) -> Vec<String> {
    let query = query_object(query);
    authorizer
        .get("identitySource")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|source| {
            source
                .strip_prefix("$request.header.")
                .and_then(|name| headers.get(name))
                .and_then(|value| value.to_str().ok())
                .or_else(|| {
                    source
                        .strip_prefix("$request.querystring.")
                        .and_then(|name| query.get(name))
                        .and_then(Value::as_str)
                })
                .unwrap_or("")
                .to_string()
        })
        .collect()
}

fn integration_status(body: &[u8]) -> Option<u16> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .get("statusCode")?
        .as_u64()
        .and_then(|status| u16::try_from(status).ok())
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

async fn register_connection(
    store: &ApiGwStore,
    registration: &ConnectionRegistration<'_>,
) -> Value {
    let timestamp = now_iso();
    let mut connection = json!({
        "connectionId": registration.connection_id,
        "apiId": registration.api_id,
        "stage": registration.stage,
        "domainName": registration.domain_name,
        "connectedAt": timestamp,
        "lastActiveAt": timestamp,
        "identity": { "sourceIp": registration.source_ip },
        "open": true,
    });
    connection[OUTBOUND_MESSAGES] = json!([]);
    store
        .shared(registration.account, registration.region)
        .write()
        .await
        .connections
        .insert(registration.connection_id.to_string(), connection.clone());
    connection
}

#[cfg(test)]
pub(crate) async fn register_test_connection(
    store: &ApiGwStore,
    account: &str,
    region: &str,
    connection_id: &str,
    api_id: &str,
    stage: &str,
) {
    register_connection(
        store,
        &ConnectionRegistration {
            account,
            region,
            connection_id,
            api_id,
            stage,
            domain_name: "test.execute-api.localhost",
            source_ip: "127.0.0.1",
        },
    )
    .await;
}

pub(crate) async fn touch_connection(
    store: &ApiGwStore,
    account: &str,
    region: &str,
    connection_id: &str,
) -> Result<(), ApiGwError> {
    let shared = store.shared(account, region);
    let mut guard = shared.write().await;
    let connection = guard
        .connections
        .get_mut(connection_id)
        .filter(|connection| is_open(connection))
        .ok_or_else(|| gone(connection_id))?;
    connection["lastActiveAt"] = json!(now_iso());
    Ok(())
}

pub(crate) async fn close_connection(
    store: &ApiGwStore,
    account: &str,
    region: &str,
    connection_id: &str,
) -> Result<(), ApiGwError> {
    let shared = store.shared(account, region);
    let mut guard = shared.write().await;
    if !guard.connections.get(connection_id).is_some_and(is_open) {
        return Err(gone(connection_id));
    }
    guard.connections.remove(connection_id);
    drop(guard);
    store.remove_connection_sender(account, region, connection_id);
    Ok(())
}

pub(crate) async fn post_to_connection(
    store: &ApiGwStore,
    account: &str,
    region: &str,
    connection_id: &str,
    payload: &[u8],
) -> Out {
    if payload.len() > MAX_POST_PAYLOAD_BYTES {
        return Err(ApiGwError::PayloadTooLarge(format!(
            "Payload exceeds the maximum allowed size of {MAX_POST_PAYLOAD_BYTES} bytes"
        )));
    }

    let shared = store.shared(account, region);
    let mut guard = shared.write().await;
    if !guard.connections.get(connection_id).is_some_and(is_open) {
        return Err(gone(connection_id));
    }
    if !store.send_to_connection(account, region, connection_id, payload.to_vec()) {
        guard.connections.remove(connection_id);
        return Err(gone(connection_id));
    }
    let connection = guard
        .connections
        .get_mut(connection_id)
        .ok_or_else(|| gone(connection_id))?;
    connection["lastActiveAt"] = json!(now_iso());
    if !connection
        .get(OUTBOUND_MESSAGES)
        .is_some_and(Value::is_array)
    {
        connection[OUTBOUND_MESSAGES] = json!([]);
    }
    let history = connection[OUTBOUND_MESSAGES]
        .as_array_mut()
        .ok_or_else(|| ApiGwError::Internal("Outbound message history is invalid".into()))?;
    if history.len() >= OUTBOUND_HISTORY_CAPACITY {
        history.remove(0);
    }
    history.push(json!({ "data": BASE64.encode(payload) }));
    Ok((200, json!({})))
}
pub(crate) async fn get_connection(
    store: &ApiGwStore,
    account: &str,
    region: &str,
    connection_id: &str,
) -> Out {
    let shared = store.shared(account, region);
    let guard = shared.read().await;
    let connection = guard
        .connections
        .get(connection_id)
        .filter(|connection| is_open(connection))
        .ok_or_else(|| gone(connection_id))?;
    Ok((
        200,
        json!({
            "connectedAt": connection.get("connectedAt").cloned().unwrap_or(Value::Null),
            "lastActiveAt": connection.get("lastActiveAt").cloned().unwrap_or(Value::Null),
            "identity": {
                "sourceIp": connection
                    .pointer("/identity/sourceIp")
                    .cloned()
                    .unwrap_or(Value::Null),
            },
        }),
    ))
}

pub(crate) async fn delete_connection(
    store: &ApiGwStore,
    account: &str,
    region: &str,
    connection_id: &str,
) -> Out {
    close_connection(store, account, region, connection_id).await?;
    Ok((204, json!({})))
}

pub(crate) fn build_websocket_event(input: &WebSocketEventInput<'_>) -> Value {
    let (body, is_base64_encoded) = match input.body {
        Some(body) if input.is_binary => (Value::String(BASE64.encode(body)), true),
        Some(body) => (
            Value::String(String::from_utf8_lossy(body).into_owned()),
            false,
        ),
        None => (Value::Null, false),
    };
    json!({
        "requestContext": {
            "accountId": input.account_id,
            "apiId": input.api_id,
            "connectionId": input.connection_id,
            "domainName": input.domain_name,
            "eventType": input.event_type.as_str(),
            "identity": { "sourceIp": input.source_ip },
            "messageDirection": "IN",
            "requestId": input.request_id,
            "requestTimeEpoch": now_epoch_millis(),
            "routeKey": input.route_key,
            "stage": input.stage,
        },
        "body": body,
        "isBase64Encoded": is_base64_encoded,
    })
}

pub(crate) fn resolve_route_selection(expression: &str, body: &[u8]) -> Option<String> {
    let path = expression.strip_prefix("$request.body.")?;
    if path.is_empty() {
        return None;
    }
    let mut value = serde_json::from_slice::<Value>(body).ok()?;
    for field in path.split('.') {
        if field.is_empty() {
            return None;
        }
        value = value.get(field)?.clone();
    }
    match value {
        Value::String(value) => Some(value),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "000000000000";
    const REGION: &str = "us-east-1";
    const CONNECTION: &str = "connection-1";

    async fn registered_store() -> ApiGwStore {
        let store = ApiGwStore::new();
        register_connection(
            &store,
            &ConnectionRegistration {
                account: ACCOUNT,
                region: REGION,
                connection_id: CONNECTION,
                api_id: "api-1",
                stage: "prod",
                domain_name: "api-1.execute-api.us-east-1.amazonaws.com",
                source_ip: "192.0.2.10",
            },
        )
        .await;
        store
    }

    fn assert_gone(result: Out) {
        assert!(matches!(result, Err(ApiGwError::Gone(_))));
    }
    #[tokio::test]
    async fn register_and_get_return_expected_metadata() {
        let store = registered_store().await;
        let (status, metadata) = get_connection(&store, ACCOUNT, REGION, CONNECTION)
            .await
            .unwrap();

        assert_eq!(status, 200);
        assert!(metadata["connectedAt"].as_str().is_some());
        assert_eq!(metadata["connectedAt"], metadata["lastActiveAt"]);
        assert_eq!(metadata["identity"]["sourceIp"], "192.0.2.10");
        assert_eq!(metadata.as_object().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn connection_lookup_is_account_and_region_scoped() {
        let store = registered_store().await;

        assert_gone(get_connection(&store, "other", REGION, CONNECTION).await);
        assert_gone(get_connection(&store, ACCOUNT, "eu-west-1", CONNECTION).await);
        assert_eq!(
            get_connection(&store, ACCOUNT, REGION, CONNECTION)
                .await
                .unwrap()
                .0,
            200
        );
    }

    #[tokio::test]
    async fn touch_updates_only_an_open_connection() {
        let store = registered_store().await;
        {
            let shared = store.shared(ACCOUNT, REGION);
            let mut guard = shared.write().await;
            guard.connections.get_mut(CONNECTION).unwrap()["lastActiveAt"] =
                json!("1970-01-01T00:00:00Z");
        }

        touch_connection(&store, ACCOUNT, REGION, CONNECTION)
            .await
            .unwrap();
        let (_, metadata) = get_connection(&store, ACCOUNT, REGION, CONNECTION)
            .await
            .unwrap();
        assert_ne!(metadata["lastActiveAt"], "1970-01-01T00:00:00Z");
        assert!(matches!(
            touch_connection(&store, ACCOUNT, REGION, "missing").await,
            Err(ApiGwError::Gone(_))
        ));
    }

    #[tokio::test]
    async fn post_accepts_the_128_kib_boundary_and_preserves_bytes() {
        let store = registered_store().await;
        let (sender, _receiver) = mpsc::channel(1);
        store.register_connection_sender(ACCOUNT, REGION, CONNECTION, sender);
        let payload = vec![0xff; MAX_POST_PAYLOAD_BYTES];

        let (status, body) = post_to_connection(&store, ACCOUNT, REGION, CONNECTION, &payload)
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, json!({}));

        let shared = store.shared(ACCOUNT, REGION);
        let guard = shared.read().await;
        let queued = &guard.connections[CONNECTION][OUTBOUND_MESSAGES][0]["data"];
        assert_eq!(BASE64.decode(queued.as_str().unwrap()).unwrap(), payload);
    }

    #[tokio::test]
    async fn oversized_post_is_rejected_without_queuing() {
        let store = registered_store().await;
        let result = post_to_connection(
            &store,
            ACCOUNT,
            REGION,
            CONNECTION,
            &vec![0; MAX_POST_PAYLOAD_BYTES + 1],
        )
        .await;

        assert!(matches!(result, Err(ApiGwError::PayloadTooLarge(_))));
        let shared = store.shared(ACCOUNT, REGION);
        let guard = shared.read().await;
        assert!(guard.connections[CONNECTION][OUTBOUND_MESSAGES]
            .as_array()
            .unwrap()
            .is_empty());
    }
    #[tokio::test]
    async fn delete_closes_and_removes_the_connection() {
        let store = registered_store().await;

        let (status, body) = delete_connection(&store, ACCOUNT, REGION, CONNECTION)
            .await
            .unwrap();
        assert_eq!(status, 204);
        assert_eq!(body, json!({}));
        assert!(!store
            .shared(ACCOUNT, REGION)
            .read()
            .await
            .connections
            .contains_key(CONNECTION));
        assert_gone(get_connection(&store, ACCOUNT, REGION, CONNECTION).await);
        assert_gone(delete_connection(&store, ACCOUNT, REGION, CONNECTION).await);
    }

    #[tokio::test]
    async fn every_management_operation_rejects_unknown_or_closed_connections() {
        let store = registered_store().await;
        {
            let shared = store.shared(ACCOUNT, REGION);
            shared
                .write()
                .await
                .connections
                .get_mut(CONNECTION)
                .unwrap()["open"] = json!(false);
        }

        assert_gone(post_to_connection(&store, ACCOUNT, REGION, CONNECTION, b"x").await);
        assert_gone(get_connection(&store, ACCOUNT, REGION, CONNECTION).await);
        assert_gone(delete_connection(&store, ACCOUNT, REGION, CONNECTION).await);
        assert_gone(post_to_connection(&store, ACCOUNT, REGION, "missing", b"x").await);
        assert_gone(get_connection(&store, ACCOUNT, REGION, "missing").await);
        assert_gone(delete_connection(&store, ACCOUNT, REGION, "missing").await);
    }

    fn event_input<'a>(
        event_type: WebSocketEventType,
        route_key: &'a str,
        body: Option<&'a [u8]>,
        is_binary: bool,
    ) -> WebSocketEventInput<'a> {
        WebSocketEventInput {
            connection_id: CONNECTION,
            route_key,
            event_type,
            api_id: "api-1",
            stage: "prod",
            domain_name: "api-1.execute-api.us-east-1.amazonaws.com",
            request_id: "request-1",
            account_id: ACCOUNT,
            source_ip: "192.0.2.10",
            body,
            is_binary,
        }
    }

    #[test]
    fn builds_connect_message_and_disconnect_event_contexts() {
        for (event_type, route_key, expected) in [
            (WebSocketEventType::Connect, "$connect", "CONNECT"),
            (WebSocketEventType::Message, "send", "MESSAGE"),
            (WebSocketEventType::Disconnect, "$disconnect", "DISCONNECT"),
        ] {
            let event = build_websocket_event(&event_input(event_type, route_key, None, false));
            let context = &event["requestContext"];
            assert_eq!(context["connectionId"], CONNECTION);
            assert_eq!(context["routeKey"], route_key);
            assert_eq!(context["eventType"], expected);
            assert_eq!(context["messageDirection"], "IN");
            assert_eq!(context["apiId"], "api-1");
            assert_eq!(context["stage"], "prod");
            assert_eq!(
                context["domainName"],
                "api-1.execute-api.us-east-1.amazonaws.com"
            );
            assert_eq!(context["identity"]["sourceIp"], "192.0.2.10");
            assert!(context["requestTimeEpoch"].as_i64().is_some());
            assert!(event["body"].is_null());
            assert_eq!(event["isBase64Encoded"], false);
        }
    }
    #[test]
    fn message_event_distinguishes_text_and_binary_frames() {
        let text = build_websocket_event(&event_input(
            WebSocketEventType::Message,
            "send",
            Some(b"hello"),
            false,
        ));
        assert_eq!(text["body"], "hello");
        assert_eq!(text["isBase64Encoded"], false);

        let binary_payload = [0xff, 0x00, 0x7f];
        let binary = build_websocket_event(&event_input(
            WebSocketEventType::Message,
            "send",
            Some(&binary_payload),
            true,
        ));
        assert_eq!(binary["body"], BASE64.encode(binary_payload));
        assert_eq!(binary["isBase64Encoded"], true);
    }

    #[test]
    fn route_selection_resolves_body_fields() {
        assert_eq!(
            resolve_route_selection("$request.body.action", br#"{"action":"send"}"#),
            Some("send".into())
        );
        assert_eq!(
            resolve_route_selection("$request.body.kind.code", br#"{"kind":{"code":7}}"#),
            Some("7".into())
        );
        assert_eq!(
            resolve_route_selection("$request.body.enabled", br#"{"enabled":true}"#),
            Some("true".into())
        );
    }

    #[test]
    fn route_selection_returns_none_for_unsupported_or_unresolvable_values() {
        for (expression, body) in [
            ("$request.header.action", br#"{"action":"send"}"#.as_slice()),
            ("$request.body.", br#"{"action":"send"}"#.as_slice()),
            ("$request.body.missing", br#"{"action":"send"}"#.as_slice()),
            ("$request.body.action", br#"{"action":{}}"#.as_slice()),
            ("$request.body.action", b"not-json".as_slice()),
        ] {
            assert_eq!(resolve_route_selection(expression, body), None);
        }
    }

    #[test]
    fn execute_host_and_stage_are_resolved_strictly() {
        assert_eq!(
            api_id_from_execute_host("abc123.execute-api.us-east-1.amazonaws.com:4566"),
            Some("abc123")
        );
        assert_eq!(api_id_from_execute_host("example.com"), None);

        let stages = BTreeMap::from([("prod".to_string(), json!({}))]);
        assert_eq!(stage_from_path("/prod", &stages), Some("prod"));
        assert_eq!(stage_from_path("/missing", &stages), None);
        assert_eq!(stage_from_path("/", &stages), None);
        let default_stage = BTreeMap::from([("$default".to_string(), json!({}))]);
        assert_eq!(stage_from_path("/", &default_stage), Some("$default"));
    }

    #[test]
    fn authorizer_policy_requires_allow_and_honors_deny() {
        assert!(policy_allows(
            &json!({
                "policyDocument": { "Statement": [{
                    "Effect": "Allow", "Action": "execute-api:Invoke", "Resource": "*"
                }] }
            }),
            "arn:aws:execute-api:us-east-1:000000000000:api/prod/$connect"
        ));
        assert!(!policy_allows(
            &json!({
                "policyDocument": { "Statement": [
                    { "Effect": "Allow", "Action": "execute-api:Invoke", "Resource": "*" },
                    { "Effect": "Deny", "Action": "execute-api:Invoke", "Resource": "*" }
                ] }
            }),
            "arn:aws:execute-api:us-east-1:000000000000:api/prod/$connect"
        ));
        assert!(!policy_allows(&json!({}), "arn:aws:execute-api:test"));
    }

    #[test]
    fn integration_status_is_read_only_from_structured_lambda_results() {
        assert_eq!(integration_status(br#"{"statusCode":204}"#), Some(204));
        assert_eq!(integration_status(br#"{"statusCode":"403"}"#), None);
        assert_eq!(integration_status(b"not-json"), None);
    }

    #[tokio::test]
    async fn post_delivers_the_original_binary_payload_to_registered_sender() {
        let store = registered_store().await;
        let (sender, mut receiver) = mpsc::channel(1);
        store.register_connection_sender(ACCOUNT, REGION, CONNECTION, sender);
        let payload = vec![0, 0xff, 7, 128];

        post_to_connection(&store, ACCOUNT, REGION, CONNECTION, &payload)
            .await
            .unwrap();

        assert_eq!(receiver.recv().await, Some(payload));
    }
}
