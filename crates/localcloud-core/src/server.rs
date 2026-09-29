//! Axum HTTP server: binding, readiness and graceful shutdown.
//!
//! Binds the configured listen port (default 4566), processes requests on the tokio
//! runtime, reports readiness once the registry is initialized, and drains in-flight
//! requests within the configured grace period on shutdown — cancelling the remainder if
//! the grace period is exceeded. Every request is handed to the
//! [`InternalDispatcher`](crate::integration::InternalDispatcher), the single dispatch
//! path shared with cross-service calls. See Requirements 2, 3 and 23.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{
    connect_info::ConnectInfo, ws::WebSocketUpgrade, FromRequestParts, Request, State,
};
use axum::response::Response;
use axum::routing::{any, get};
use axum::Router;

use crate::config::LocalCloudConfig;
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
}

#[derive(Clone)]
struct AppState {
    readiness: Readiness,
    dispatcher: Arc<InternalDispatcher>,
    registry: Arc<ServiceRegistry>,
    meter: Arc<crate::metering::Meter>,
    max_request_body_bytes: usize,
}

pub struct LocalCloudServer {
    config: Arc<LocalCloudConfig>,
    registry: Arc<ServiceRegistry>,
    readiness: Readiness,
}

impl LocalCloudServer {
    pub fn new(config: LocalCloudConfig, registry: Arc<ServiceRegistry>) -> Self {
        LocalCloudServer {
            config: Arc::new(config),
            registry,
            readiness: Readiness::new(),
        }
    }

    /// Bind, serve, and run until an OS termination signal, then shut down gracefully.
    pub async fn run(self) -> Result<(), ServerError> {
        let addr = self.config.listen_addr;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|source| ServerError::Bind { addr, source })?;

        // Registry is initialized by construction; report readiness (Req 2.7).
        self.readiness.mark_ready();
        tracing::info!(%addr, "localcloud listening");

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
        let state = AppState {
            readiness: self.readiness.clone(),
            dispatcher,
            registry: self.registry.clone(),
            meter,
            max_request_body_bytes: self.config.max_request_body_bytes,
        };
        let app = Router::new()
            .route("/_localcloud/health", get(health_handler))
            .route("/_localstack/health", get(health_handler))
            .route("/_localcloud/status", get(status_handler))
            .route("/_localcloud/ui", get(ui_handler))
            .fallback(any(dispatch_handler))
            .with_state(state);

        let grace = self.config.shutdown_grace_period;

        let (signal_tx, signal_rx) = tokio::sync::oneshot::channel::<()>();
        let serve = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
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

async fn ui_handler() -> Response {
    Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::from(crate::status::DASHBOARD_HTML))
        .expect("dashboard html is always valid")
}

async fn dispatch_handler(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let peer = ConnectInfo::<SocketAddr>::from_request_parts(&mut parts, &state)
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
            return render(err.render(AwsProtocol::RestJson));
        }
    };
    let request_id = new_request_id();
    match peer {
        Some(ConnectInfo(addr)) => {
            state
                .dispatcher
                .dispatch_verified_peer(
                    &parts.method,
                    &parts.uri,
                    &parts.headers,
                    body_bytes,
                    &request_id,
                    addr.ip(),
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
