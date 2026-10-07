//! Axum HTTP server: binding, readiness and graceful shutdown.
//!
//! Binds the configured listen port (default 4566), processes requests on the tokio
//! runtime, reports readiness once the registry is initialized, and drains in-flight
//! requests within the configured grace period on shutdown — cancelling the remainder if
//! the grace period is exceeded. Every request is handed to the
//! [`InternalDispatcher`](crate::integration::InternalDispatcher), the single dispatch
//! path shared with cross-service calls. See Requirements 2, 3 and 23.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use crate::dashboard_context::{
    encode, query_read, read_target, rest_read, valid_region, DashboardContext,
};
use axum::body::Body;
use axum::extract::{
    connect_info::ConnectInfo, ws::WebSocketUpgrade, FromRequestParts, Path, Query, Request, State,
};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use http::StatusCode;

use crate::config::LocallyCloudConfig;
use crate::error_mapping::AwsError;
use crate::health::{health_response, Readiness};
use crate::integration::{render, InternalDispatcher};
use crate::observability::new_request_id;
use crate::proxy::{LegacyHealth, ProxyConfig};
use crate::registry::{AwsProtocol, ServiceRegistry};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("failed to bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("server error: {0}")]
    Serve(#[source] std::io::Error),
    #[error("invalid configured control-plane TLS identity: {0}")]
    Tls(#[source] std::io::Error),
}

#[derive(Clone)]
struct AppState {
    readiness: Readiness,
    dispatcher: Arc<InternalDispatcher>,
    registry: Arc<ServiceRegistry>,
    meter: Arc<crate::metering::Meter>,
    max_request_body_bytes: usize,
    dashboard: Arc<DashboardContext>,
    control_plane_tls_hostname: Option<String>,
}

pub struct LocallyCloudServer {
    config: Arc<LocallyCloudConfig>,
    registry: Arc<ServiceRegistry>,
    readiness: Readiness,
    tls_resolver: Option<Arc<dyn crate::tls::TlsIdentityResolver>>,
}

impl LocallyCloudServer {
    pub fn new(config: LocallyCloudConfig, registry: Arc<ServiceRegistry>) -> Self {
        LocallyCloudServer {
            config: Arc::new(config),
            registry,
            readiness: Readiness::new(),
            tls_resolver: None,
        }
    }

    pub fn with_tls_resolver(mut self, resolver: Arc<dyn crate::tls::TlsIdentityResolver>) -> Self {
        self.tls_resolver = Some(resolver);
        self
    }

    /// Bind, serve, and run until an OS termination signal, then shut down gracefully.
    pub async fn run(self) -> Result<(), ServerError> {
        self.run_with_startup(|| {}).await
    }

    /// Resume restored producers after the internal dispatcher is available.
    pub async fn run_with_startup(self, startup: impl FnOnce() + Send) -> Result<(), ServerError> {
        let tls_resolver: Option<Arc<dyn crate::tls::TlsIdentityResolver>> = match &self.config.tls
        {
            Some(config) => Some(Arc::new(
                crate::tls::ControlPlaneResolver::load(config, self.tls_resolver)
                    .await
                    .map_err(ServerError::Tls)?,
            )),
            None => self.tls_resolver,
        };
        let addr = self.config.listen_addr;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|source| ServerError::Bind { addr, source })?;

        // Registry is initialized by construction; report readiness (Req 2.7).
        self.readiness.mark_ready();
        tracing::info!(%addr, "locallycloud listening");

        let legacy_health = LegacyHealth::new(true);
        let _health_checker = legacy_health.clone().spawn_checker(
            self.config.legacy_backend_url.clone(),
            self.config.legacy_health_check_interval,
        );
        let meter = Arc::new(crate::metering::Meter::new());
        let dispatcher = Arc::new(
            InternalDispatcher::new_shared(
                &self.registry,
                ProxyConfig {
                    backend_url: self.config.legacy_backend_url.clone(),
                    upstream_timeout: self.config.upstream_timeout,
                },
                legacy_health,
                self.config.default_region.clone(),
                self.config.account_id.clone(),
            )
            .with_meter(meter.clone()),
        );
        self.registry.set_internal_dispatcher(dispatcher.clone());
        startup();
        let state = AppState {
            readiness: self.readiness.clone(),
            dispatcher,
            registry: self.registry.clone(),
            meter,
            max_request_body_bytes: self.config.max_request_body_bytes,
            control_plane_tls_hostname: self.config.tls.as_ref().map(|tls| tls.hostname.clone()),
            dashboard: Arc::new(
                DashboardContext::load(
                    addr,
                    self.config.account_id.clone(),
                    self.config.default_region.clone(),
                )
                .await,
            ),
        };
        let app = Router::new()
            .route("/_locallycloud/health", get(health_handler))
            .route("/_localstack/health", get(health_handler))
            .route("/_locallycloud/status", get(status_handler))
            .route("/_locallycloud/activity", post(activity_handler))
            .route("/_locallycloud/context", get(context_handler))
            .route(
                "/_locallycloud/explore/regions",
                post(explorer_regions_handler),
            )
            .route(
                "/_locallycloud/explore/read",
                axum::routing::post(explorer_read_handler),
            )
            .route("/_locallycloud/ui", get(ui_handler))
            .route("/_locallycloud/ui/", get(ui_handler))
            .route("/_locallycloud/ui/{*page}", get(ui_handler))
            .route("/_locallycloud/explore/s3", get(s3_explorer_handler))
            .route("/_locallycloud/dashboard.js", get(ui_script_handler))
            .route("/_locallycloud/dashboard.css", get(ui_style_handler))
            .route("/_locallycloud/brand/{asset}", get(ui_brand_handler))
            .route("/_locallycloud/dashboard-i18n.js", get(ui_i18n_handler))
            .route("/_locallycloud/icons.svg", get(ui_icons_handler))
            .fallback(any(dispatch_handler))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                tls_domain_handler,
            ))
            .with_state(state);

        let grace = self.config.shutdown_grace_period;

        let (signal_tx, signal_rx) = tokio::sync::oneshot::channel::<()>();
        let serve = axum::serve(
            crate::tls::DomainListener::new(listener, tls_resolver),
            app.into_make_service_with_connect_info::<crate::tls::ConnectionInfo>(),
        )
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            let _ = signal_tx.send(());
        });
        let serve_task = tokio::spawn(async move { serve.await });

        // Wait for the signal, then bound the drain by the grace period (Req 3.1–3.4).
        let _ = signal_rx.await;
        tracing::info!(
            ?grace,
            "shutdown signal received; draining in-flight requests"
        );
        match tokio::time::timeout(grace, serve_task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => return Err(ServerError::Serve(e)),
            Ok(Err(join_err)) => tracing::error!(error = %join_err, "serve task join error"),
            Err(_elapsed) => {
                tracing::warn!(
                    ?grace,
                    "grace period exceeded; cancelling remaining requests"
                );
            }
        }
        tracing::info!("shutdown complete");
        Ok(())
    }
}

async fn health_handler(State(state): State<AppState>) -> Response {
    let (status, body) = health_response(state.readiness.is_ready());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("static health response is always valid")
}

async fn status_handler(State(state): State<AppState>) -> Response {
    let metrics = state.meter.snapshot();
    let cost = crate::cost::estimate(&metrics);
    let body = crate::status::status_json(
        &state.registry,
        &metrics,
        &cost,
        state.readiness.is_ready(),
        env!("CARGO_PKG_VERSION"),
    );
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Body::from(body))
        .expect("status response is always valid")
}

#[derive(serde::Deserialize)]
struct S3Browse {
    bucket: Option<String>,
    prefix: Option<String>,
    token: Option<String>,
    #[serde(flatten)]
    context: BrowseContext,
}

impl S3Browse {
    fn uri(&self) -> Result<http::Uri, &'static str> {
        let Some(bucket) = &self.bucket else {
            return Ok(http::Uri::from_static("/"));
        };
        if bucket.is_empty()
            || bucket.len() > 63
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            return Err("invalid bucket name");
        }
        let mut path = format!("/{bucket}?list-type=2&delimiter=%2F&max-keys=100");
        for (key, value) in [
            ("prefix", &self.prefix),
            ("continuation-token", &self.token),
        ] {
            if let Some(value) = value {
                path.push_str(&format!("&{key}={}", encode(value)));
            }
        }
        path.parse().map_err(|_| "invalid S3 listing URI")
    }
}

// Browsers cannot set Host. Adapt only S3 listings to the normal AWS dispatcher;
// IAM, account/region scope and audit remain enforced by that shared path.
async fn s3_explorer_handler(
    State(state): State<AppState>,
    Query(query): Query<S3Browse>,
    incoming: http::HeaderMap,
) -> Response {
    if !local_dashboard_headers(&incoming) {
        return dashboard_error("dashboard reads require the local origin", 403);
    }
    let uri = match query.uri() {
        Ok(uri) => uri,
        Err(message) => {
            return render(
                AwsError::new("InvalidArgument", message, 400).render(AwsProtocol::RestXml),
            )
        }
    };
    let mut headers = http::HeaderMap::new();
    headers.insert("host", http::HeaderValue::from_static("s3.localhost"));
    headers.insert(
        "x-locallycloud-dashboard",
        http::HeaderValue::from_static("1"),
    );
    dashboard_read(
        &state,
        &query.context,
        &http::Method::GET,
        &uri,
        headers,
        bytes::Bytes::new(),
        "s3",
    )
    .await
}

#[derive(Default, serde::Deserialize)]
struct BrowseContext {
    region: Option<String>,
    profile: Option<String>,
}

async fn context_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let dashboard = state.dashboard.refreshed().await;
    Json(serde_json::json!({"accountId": state.dashboard.account_id,
        "defaultRegion": state.dashboard.default_region, "defaultProfile": "instance",
        "profiles": dashboard.profiles.iter().map(|p| serde_json::json!({"name": p.name, "region": p.region, "signed": p.credentials.is_some()})).collect::<Vec<_>>() }))
}

#[derive(serde::Deserialize)]
struct BrowseRead {
    #[serde(flatten)]
    context: BrowseContext,
    service: String,
    operation: Option<String>,
    path: Option<String>,
    #[serde(default)]
    body: serde_json::Value,
}

// Resolve the account through the same verified STS path as the header. The browser
// cannot request an arbitrary account's inventory by supplying an account id.
struct DashboardAccount {
    account: String,
    region: String,
    access_key: Option<String>,
}

async fn dashboard_account(
    state: &AppState,
    context: &BrowseContext,
) -> Result<DashboardAccount, Box<Response>> {
    let dashboard = state.dashboard.refreshed().await;
    let profile = dashboard
        .profile(context.profile.as_deref().unwrap_or("instance"))
        .ok_or_else(|| Box::new(dashboard_error("unknown local profile", 400)))?;
    let region = context.region.as_deref().unwrap_or(&profile.region);
    if !valid_region(region) {
        return Err(Box::new(dashboard_error("invalid region", 400)));
    }
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "content-type",
        http::HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert("host", http::HeaderValue::from_static("localhost"));
    let identity = dispatch_dashboard_profile(
        state,
        profile,
        region,
        &http::Method::POST,
        &http::Uri::from_static("/"),
        headers,
        bytes::Bytes::from_static(b"Action=GetCallerIdentity&Version=2011-06-15"),
        "sts",
    )
    .await;
    if !identity.status().is_success() {
        return Err(Box::new(identity));
    }
    let Ok(body) = axum::body::to_bytes(identity.into_body(), 64 * 1024).await else {
        return Err(Box::new(dashboard_error(
            "identity response unavailable",
            502,
        )));
    };
    // STS is the in-process producer of this fixed response; only its decimal Account
    // field is consumed, never arbitrary XML, resource values or client-supplied scope.
    let account = std::str::from_utf8(&body)
        .ok()
        .and_then(|s| s.split_once("<Account>"))
        .and_then(|(_, s)| s.split_once("</Account>"))
        .map(|(account, _)| account)
        .filter(|account| account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit()));
    let Some(account) = account else {
        return Err(Box::new(dashboard_error("invalid STS account", 502)));
    };
    Ok(DashboardAccount {
        account: account.to_owned(),
        region: region.to_owned(),
        access_key: profile.access_key.clone(),
    })
}

async fn explorer_regions_handler(
    State(state): State<AppState>,
    incoming: http::HeaderMap,
    Json(context): Json<BrowseContext>,
) -> Response {
    if !local_dashboard_headers(&incoming) {
        return dashboard_error("dashboard reads require the local origin", 403);
    }
    let verified = match dashboard_account(&state, &context).await {
        Ok(verified) => verified,
        Err(error) => return *error,
    };
    let account = &verified.account;
    match state.registry.resource_inventory(account).await {
        Ok(inventory) => {
            Json(serde_json::json!({"accountId": account, "regions": inventory.regions, "services": inventory.services})).into_response()
        }
        Err(message) => dashboard_error(message, 503),
    }
}

async fn explorer_read_handler(
    State(state): State<AppState>,
    incoming: http::HeaderMap,
    Json(read): Json<BrowseRead>,
) -> Response {
    if !local_dashboard_headers(&incoming) {
        return dashboard_error("dashboard reads require the local origin", 403);
    }
    let mut headers = http::HeaderMap::new();
    let (method, uri, body) = match read.service.as_str() {
        "sts" if read.operation.as_deref() == Some("GetCallerIdentity") => {
            headers.insert(
                "content-type",
                http::HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            (
                http::Method::POST,
                http::Uri::from_static("/"),
                bytes::Bytes::from_static(b"Action=GetCallerIdentity&Version=2011-06-15"),
            )
        }
        "lambda" => {
            let Some(path) = read.path.as_deref().filter(|path| lambda_read_path(path)) else {
                return dashboard_error("unsupported Lambda read", 400);
            };
            let Ok(uri) = format!("/2015-03-31/{path}").parse::<http::Uri>() else {
                return dashboard_error("invalid path", 400);
            };
            (http::Method::GET, uri, bytes::Bytes::new())
        }
        "sns" | "cloudformation" => {
            let body = match query_read(
                &read.service,
                read.operation.as_deref().unwrap_or(""),
                &read.body,
            ) {
                Ok(body) => body,
                Err(message) => return dashboard_error(message, 400),
            };
            headers.insert(
                "content-type",
                http::HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            (
                http::Method::POST,
                http::Uri::from_static("/"),
                bytes::Bytes::from(body),
            )
        }
        "apigateway" | "scheduler" | "pipes" => {
            let uri = match rest_read(&read.service, read.path.as_deref().unwrap_or("")) {
                Ok(uri) => uri,
                Err(message) => return dashboard_error(message, 400),
            };
            (http::Method::GET, uri, bytes::Bytes::new())
        }
        _ => {
            let Some((target, version)) =
                read_target(&read.service, read.operation.as_deref().unwrap_or(""))
            else {
                return dashboard_error("unsupported dashboard read", 400);
            };
            headers.insert(
                "content-type",
                format!("application/x-amz-json-{version}").parse().unwrap(),
            );
            headers.insert(
                "x-amz-target",
                format!("{target}.{}", read.operation.as_deref().unwrap())
                    .parse()
                    .unwrap(),
            );
            (
                http::Method::POST,
                http::Uri::from_static("/"),
                bytes::Bytes::from(read.body.to_string()),
            )
        }
    };
    headers.insert("host", http::HeaderValue::from_static("localhost"));
    dashboard_read(
        &state,
        &read.context,
        &method,
        &uri,
        headers,
        body,
        &read.service,
    )
    .await
}

// Profile signing is a local UI capability. Reject DNS rebinding and foreign origins;
// shared credentials are not loaded when the listener is bound beyond loopback.
fn local_dashboard_headers(headers: &http::HeaderMap) -> bool {
    let Some(host) = headers.get("host").and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let Ok(authority) = host.parse::<http::uri::Authority>() else {
        return false;
    };
    if !matches!(authority.host(), "localhost" | "127.0.0.1" | "[::1]") {
        return false;
    }
    headers.get("origin").is_none_or(|origin| {
        origin
            .to_str()
            .is_ok_and(|origin| origin == format!("http://{host}"))
    })
}

fn lambda_read_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or("");
    if path == "functions/" || path == "event-source-mappings/" {
        return true;
    }
    let parts: Vec<_> = path.split('/').collect();
    parts.len() == 3
        && parts[0] == "functions"
        && !parts[1].is_empty()
        && parts[2] == "configuration"
}

#[allow(clippy::too_many_arguments)]
async fn dashboard_read(
    state: &AppState,
    context: &BrowseContext,
    method: &http::Method,
    uri: &http::Uri,
    headers: http::HeaderMap,
    body: bytes::Bytes,
    service: &str,
) -> Response {
    let dashboard = state.dashboard.refreshed().await;
    let Some(profile) = dashboard.profile(context.profile.as_deref().unwrap_or("instance")) else {
        return dashboard_error("unknown local profile", 400);
    };
    let region = context.region.as_deref().unwrap_or(&profile.region);
    if !valid_region(region) {
        return dashboard_error("invalid region", 400);
    }
    dispatch_dashboard_profile(state, profile, region, method, uri, headers, body, service).await
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_dashboard_profile(
    state: &AppState,
    profile: &crate::dashboard_context::Profile,
    region: &str,
    method: &http::Method,
    uri: &http::Uri,
    mut headers: http::HeaderMap,
    body: bytes::Bytes,
    service: &str,
) -> Response {
    headers.insert(
        "x-locallycloud-dashboard",
        http::HeaderValue::from_static("1"),
    );
    if let (Some(access), Some(credentials)) = (&profile.access_key, &profile.credentials) {
        if crate::integration::sigv4::sign(
            method,
            uri,
            &mut headers,
            &body,
            region,
            service,
            access,
            credentials,
        )
        .is_none()
        {
            return dashboard_error("local profile could not sign the request", 400);
        }
    }
    state
        .dispatcher
        .dispatch_dashboard(method, uri, &headers, body, region, service)
        .await
}

fn dashboard_error(message: &str, status: u16) -> Response {
    render(AwsError::new("InvalidRequest", message, status).render(AwsProtocol::RestJson))
}

async fn ui_handler() -> Response {
    Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::from(crate::status::DASHBOARD_HTML))
        .expect("dashboard html is always valid")
}

async fn activity_handler(
    State(state): State<AppState>,
    incoming: http::HeaderMap,
    Json(context): Json<BrowseContext>,
) -> Response {
    if !local_dashboard_headers(&incoming) {
        return dashboard_error("dashboard reads require the local origin", 403);
    }
    let verified = match dashboard_account(&state, &context).await {
        Ok(verified) => verified,
        Err(error) => return *error,
    };
    if state
        .dispatcher
        .authorize(crate::integration::authorization::AuthorizationRequest {
            request_identity: crate::integration::RequestIdentity {
                account_id: verified.account.clone(),
                access_key_id: verified.access_key,
                arn: None,
            },
            delegated_identity: None,
            source_service: "dashboard".into(),
            action: "cloudtrail:LookupEvents".into(),
            resource: "*".into(),
            context: std::collections::BTreeMap::from([(
                "aws:requestedregion".into(),
                vec![verified.region.clone()],
            )]),
        })
        .is_err()
    {
        return render(
            AwsError::new(
                "AccessDeniedException",
                "not authorized to inspect activity",
                403,
            )
            .render(AwsProtocol::RestJson),
        );
    }
    Json(
        state
            .registry
            .activity
            .snapshot_scoped(&verified.account, &verified.region),
    )
    .into_response()
}

async fn ui_script_handler() -> Response {
    Response::builder()
        .status(200)
        .header("content-type", "text/javascript; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::from(crate::status::DASHBOARD_JS))
        .expect("dashboard script is always valid")
}

async fn ui_style_handler() -> Response {
    Response::builder()
        .header("content-type", "text/css; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::from(crate::status::DASHBOARD_CSS))
        .expect("embedded dashboard CSS response is always valid")
}

async fn ui_brand_handler(Path(asset): Path<String>) -> Response {
    let svg = match asset.as_str() {
        "icon.svg" => include_str!("../../../packaging/assets/locallycloud.svg"),
        "wordmark.svg" => include_str!("../../../packaging/assets/locallycloud-wordmark.svg"),
        "wordmark-light.svg" => {
            include_str!("../../../packaging/assets/locallycloud-wordmark-light.svg")
        }
        _ => return Response::builder().status(404).body(Body::empty()).unwrap(),
    };
    Response::builder()
        .header("content-type", "image/svg+xml")
        .header("cache-control", "no-store")
        .body(Body::from(svg))
        .expect("embedded brand asset response is always valid")
}

async fn ui_i18n_handler() -> Response {
    Response::builder()
        .header("content-type", "text/javascript; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::from(crate::status::DASHBOARD_I18N))
        .expect("dashboard translations response is always valid")
}

async fn ui_icons_handler(headers: http::HeaderMap) -> Response {
    use sha2::Digest;
    static ETAG: OnceLock<String> = OnceLock::new();
    let etag = ETAG.get_or_init(|| {
        format!(
            "\"{:x}\"",
            sha2::Sha256::digest(crate::status::SERVICE_ICONS_SVG)
        )
    });
    let unchanged = headers
        .get(http::header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|candidate| {
                let candidate = candidate.trim();
                candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
            })
        });
    Response::builder()
        .status(if unchanged { 304 } else { 200 })
        .header("content-type", "image/svg+xml")
        .header("cache-control", "public, no-cache")
        .header("etag", etag.as_str())
        .body(if unchanged {
            Body::empty()
        } else {
            Body::from(crate::status::SERVICE_ICONS_SVG)
        })
        .expect("embedded service sprite response is always valid")
}

fn dashboard_ui_request(method: &http::Method, uri: &http::Uri, headers: &http::HeaderMap) -> bool {
    let path = uri.path().trim_start_matches('/');
    let region = path.split('/').next().unwrap_or("");
    method == http::Method::GET
        && (valid_region(region) || matches!(region, "home" | "dashboard"))
        && headers
            .get("accept")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| h.contains("text/html"))
        && !headers.contains_key("authorization")
        && !headers.contains_key("x-amz-target")
        && !uri
            .query()
            .is_some_and(|q| q.to_ascii_lowercase().contains("x-amz-"))
        && !headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| h.contains(".s3."))
}

async fn tls_domain_handler(
    State(state): State<AppState>,
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    let server_name = req
        .extensions()
        .get::<ConnectInfo<crate::tls::ConnectionInfo>>()
        .and_then(|info| info.0.server_name.as_deref());
    let Some(server_name) = server_name else {
        return next.run(req).await;
    };
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let authority = host.parse::<http::uri::Authority>().ok();
    if !authority
        .as_ref()
        .is_some_and(|authority| authority.host().eq_ignore_ascii_case(server_name))
    {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    if state.control_plane_tls_hostname.as_deref() == Some(server_name) {
        // AWS control-plane TLS does not expose dashboard routes or reinterpret custom domains.
        if req.uri().path().starts_with("/_locallycloud")
            || req.uri().path().starts_with("/_localstack")
        {
            return StatusCode::NOT_FOUND.into_response();
        }
        return dispatch_handler(State(state), req).await;
    }
    let credential = req
        .uri()
        .query()
        .and_then(crate::integration::extract_x_amz_credential);
    let authorization = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if crate::integration::claims_sigv4_identity(authorization, credential.as_deref())
        && crate::router::extract_service_from_credential_scope(
            authorization,
            credential.as_deref(),
        )
        .is_none_or(|service| service.as_str() != "execute-api")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let registered = match state
        .registry
        .native_handler(&crate::registry::ServiceName::new("execute-api"))
    {
        Some(handler) => handler
            .public_invoke_region(&state.dashboard.account_id, host, "/")
            .await
            .is_some(),
        None => false,
    };
    if !registered {
        return StatusCode::NOT_FOUND.into_response();
    }
    // SNI authenticates a domain's data plane, never its dashboard or AWS control plane.
    dispatch_handler(State(state), req).await
}

async fn dispatch_handler(State(state): State<AppState>, req: Request) -> Response {
    let tls = req
        .extensions()
        .get::<ConnectInfo<crate::tls::ConnectionInfo>>()
        .is_some_and(|info| info.0.server_name.is_some());
    if !tls && dashboard_ui_request(req.method(), req.uri(), req.headers()) {
        return ui_handler().await;
    }
    let (mut parts, body) = req.into_parts();
    let peer = ConnectInfo::<crate::tls::ConnectionInfo>::from_request_parts(&mut parts, &state)
        .await
        .ok();
    if let Ok(upgrade) = WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        let request_id = new_request_id();
        return state
            .dispatcher
            .dispatch_websocket(
                &parts.method,
                &parts.uri,
                &parts.headers,
                upgrade,
                &request_id,
            )
            .await;
    }

    let body_bytes = match axum::body::to_bytes(body, state.max_request_body_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let err = AwsError::new(
                "RequestEntityTooLarge",
                "request body exceeds the configured maximum size",
                413,
            )
            .with_request_id(new_request_id());
            let response = render(err.render(AwsProtocol::RestJson));
            return if crate::error_mapping::cloudwatch_cbor_request(&parts.uri, &parts.headers) {
                crate::error_mapping::cloudwatch_cbor_error(response).await
            } else {
                response
            };
        }
    };
    let request_id = new_request_id();
    match peer {
        Some(ConnectInfo(addr)) => {
            state
                .dispatcher
                .dispatch_verified_connection(
                    &parts.method,
                    &parts.uri,
                    &parts.headers,
                    body_bytes,
                    &request_id,
                    addr.peer.ip(),
                    addr.server_name.is_some(),
                )
                .await
        }
        None => {
            state
                .dispatcher
                .dispatch(
                    &parts.method,
                    &parts.uri,
                    &parts.headers,
                    body_bytes,
                    &request_id,
                )
                .await
        }
    }
}

/// Resolve when an OS termination signal (SIGINT or, on unix, SIGTERM) is received.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[cfg(test)]
mod dashboard_tests {

    #[tokio::test]
    async fn service_sprite_is_cacheable_and_revalidates_by_content() {
        let response = super::ui_icons_handler(http::HeaderMap::new()).await;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-type"], "image/svg+xml");
        assert_eq!(response.headers()["cache-control"], "public, no-cache");
        let etag = response.headers()["etag"].to_str().unwrap().to_owned();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), crate::status::SERVICE_ICONS_SVG.as_bytes());
        for candidate in [
            etag.clone(),
            format!("W/{etag}"),
            format!("\"old\", {etag}"),
            "*".into(),
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert("if-none-match", candidate.parse().unwrap());
            let response = super::ui_icons_handler(headers).await;
            assert_eq!(response.status(), 304);
            assert!(axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .is_empty());
        }
        let mut headers = http::HeaderMap::new();
        headers.insert("if-none-match", "\"old\"".parse().unwrap());
        assert_eq!(super::ui_icons_handler(headers).await.status(), 200);
    }
    use super::{BrowseContext, S3Browse};

    #[test]
    fn regional_html_never_intercepts_signed_aws_requests() {
        let uri = "/us-east-1/dynamo/Orders".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("accept", "text/html".parse().unwrap());
        assert!(super::dashboard_ui_request(
            &http::Method::GET,
            &uri,
            &headers
        ));
        assert!(!super::dashboard_ui_request(
            &http::Method::POST,
            &uri,
            &headers
        ));
        for path in ["/home", "/home/key", "/dashboard/key"] {
            let path = path.parse().unwrap();
            assert!(super::dashboard_ui_request(
                &http::Method::GET,
                &path,
                &headers
            ));
            headers.insert("authorization", "AWS4-HMAC-SHA256 signed".parse().unwrap());
            assert!(!super::dashboard_ui_request(
                &http::Method::GET,
                &path,
                &headers
            ));
            headers.remove("authorization");
        }
        headers.insert("authorization", "AWS4-HMAC-SHA256 signed".parse().unwrap());
        assert!(!super::dashboard_ui_request(
            &http::Method::GET,
            &uri,
            &headers
        ));
        headers.remove("authorization");
        let signed = "/us-east-1/dynamo/Orders?X-Amz-Signature=abc"
            .parse()
            .unwrap();
        assert!(!super::dashboard_ui_request(
            &http::Method::GET,
            &signed,
            &headers
        ));
        assert!(!super::lambda_read_path("functions/demo/invocations"));
        headers.insert("host", "127.0.0.1:4566".parse().unwrap());
        assert!(super::local_dashboard_headers(&headers));
        headers.insert("origin", "https://untrusted.example".parse().unwrap());
        assert!(!super::local_dashboard_headers(&headers));
        headers.remove("origin");
        headers.insert("host", "untrusted.example:4566".parse().unwrap());
        assert!(!super::local_dashboard_headers(&headers));
    }

    #[test]
    fn s3_browser_only_builds_listings_and_escapes_opaque_prefixes() {
        let mut query = S3Browse {
            bucket: None,
            prefix: None,
            token: None,
            context: BrowseContext::default(),
        };
        assert_eq!(query.uri().unwrap().to_string(), "/");
        query.bucket = Some("orders-demo".into());
        query.prefix = Some("invoices/ñ &?".into());
        query.token = Some("a+/=".into());
        assert_eq!(query.uri().unwrap().to_string(), "/orders-demo?list-type=2&delimiter=%2F&max-keys=100&prefix=invoices%2F%C3%B1%20%26%3F&continuation-token=a%2B%2F%3D");
        query.bucket = Some("orders-demo/key?delete".into());
        assert!(query.uri().is_err());
    }
}
