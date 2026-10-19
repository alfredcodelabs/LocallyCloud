//! Task-owned credential, native SDK and awslogs bridges. No host endpoint is exposed.
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use http::{Method, StatusCode};
use locallycloud_compute::runtime::{ComputeRuntime, TaskOutput};
use locallycloud_compute::youki::{YoukiRuntime, VPC_EGRESS_PORT};
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::integration::authorization::ServiceRoleCredentials;
use locallycloud_core::integration::correlation::CorrelationContext;
use locallycloud_core::integration::identity::CallerIdentity;
use locallycloud_core::integration::logs::{
    GroupRef, InternalLogSink, LogScope, ProducerContext, ProducerLogEvent, ProducerStreamSpec,
    StreamRef,
};
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{AwsProtocol, ServiceName, ServiceRegistry};
use locallycloud_core::router::{
    extract_region_from_credential_scope, extract_service_from_credential_scope, resolve,
    RouteDisposition, RouteInput,
};
use locallycloud_ec2::{Ec2Handler, TaskNetworkLease};
use locallycloud_ecs::TaskLaunch;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};
use uuid::Uuid;

pub const CREDENTIALS_PORT: u16 = 18081;
pub const AWS_GATEWAY_PORT: u16 = 18082;
const MAX_HTTP_BODY: usize = 4 * 1024 * 1024;
const MAX_LOG_BYTES: usize = 256 * 1024;
const MAX_LOG_EVENTS: usize = 128;
const MAX_EVENT_BYTES: usize = 4096;
const MAX_LOG_FAILURES: u8 = 8;

struct CredentialEntry {
    credentials: ServiceRoleCredentials,
    expires_at: i64,
}
struct GuestState {
    registry: Weak<ServiceRegistry>,
    ec2: Arc<Ec2Handler>,
    account: String,
    region: String,
    subnet_id: String,
    private_ip: Ipv4Addr,
    security_groups: Vec<String>,
    task_role: Option<String>,
    credentials: Mutex<Vec<CredentialEntry>>,
    refresh_gate: Semaphore,
    credential_path: String,
    credential_token: String,
}

pub struct PreparedGuest {
    state: Arc<GuestState>,
    task_id: String,
    logs: Option<PreparedLogs>,
}

struct PreparedLogs {
    sink: Arc<dyn InternalLogSink>,
    scope: LogScope,
    target: StreamRef,
    context: ProducerContext,
    network: Arc<GuestState>,
}

pub struct GuestEndpoints {
    servers: Vec<JoinHandle<()>>,
    logs: Option<JoinHandle<()>>,
    stop_logs: watch::Sender<bool>,
    dropped_log_bytes: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
}

impl PreparedGuest {
    /// Prepare before image execution. Issued task credentials never include execution credentials.
    pub async fn prepare(
        registry: Weak<ServiceRegistry>,
        ec2: Arc<Ec2Handler>,
        task: &TaskLaunch,
        network: &TaskNetworkLease,
    ) -> Result<Self, String> {
        if [CREDENTIALS_PORT, AWS_GATEWAY_PORT, VPC_EGRESS_PORT].contains(&task.port) {
            return Err("Application port conflicts with a reserved task networking port".into());
        }
        let state = Arc::new(GuestState {
            registry,
            ec2,
            account: task.account.clone(),
            region: task.region.clone(),
            subnet_id: network.subnet_id.clone(),
            private_ip: network.private_ip,
            security_groups: network.security_group_ids.clone(),
            task_role: task.task_role_arn.clone(),
            credentials: Mutex::new(Vec::new()),
            refresh_gate: Semaphore::new(1),
            credential_path: format!("/v2/credentials/{}", Uuid::new_v4()),
            credential_token: Uuid::new_v4().to_string(),
        });
        if state.task_role.is_some() {
            state.current_credentials().await?;
        }
        let logs = match &task.log_configuration {
            Some(configuration) => {
                if configuration.log_driver != "awslogs" {
                    return Err("Only awslogs is supported".into());
                }
                if !state.allows_service("logs") {
                    return Err(
                        "Task VPC endpoint or egress for CloudWatch Logs is unavailable".into(),
                    );
                }
                let role = task
                    .execution_role_arn
                    .as_ref()
                    .ok_or("awslogs requires an execution role")?;
                let group = configuration
                    .options
                    .get("awslogs-group")
                    .ok_or("awslogs-group is required")?;
                let region = configuration
                    .options
                    .get("awslogs-region")
                    .ok_or("awslogs-region is required")?;
                if region != &task.region {
                    return Err("Isolated awslogs requires the task region; cross-region egress is unavailable".into());
                }
                let prefix = configuration
                    .options
                    .get("awslogs-stream-prefix")
                    .ok_or("awslogs-stream-prefix is required")?;
                let registry = state
                    .registry
                    .upgrade()
                    .ok_or("Service registry is unavailable")?;
                let sink = registry
                    .log_sink(&ServiceName::new("logs"))
                    .ok_or("CloudWatch Logs is unavailable")?;
                let scope = LogScope::new(&task.account, region);
                let context = ProducerContext {
                    source_service: "ecs".into(),
                    identity: CallerIdentity::AssumedRole {
                        role_arn: role.clone(),
                        session_name: task.task_id.clone(),
                    },
                    correlation: CorrelationContext {
                        flow_id: Uuid::new_v4().to_string(),
                        span_id: Uuid::new_v4().to_string(),
                    },
                    loop_depth: 0,
                };
                let target = timeout(Duration::from_secs(5), async {
                    // CreateLogStream validates the existing group without requiring extra Describe permissions.
                    let group = GroupRef {
                        name: group.clone(),
                    };
                    sink.ensure_stream(
                        scope.clone(),
                        group,
                        ProducerStreamSpec {
                            name: format!("{prefix}/{}/{}", task.container_name, task.task_id),
                        },
                        context.clone(),
                    )
                    .await
                    .map_err(|error| error.to_string())
                })
                .await
                .map_err(|_| "CloudWatch Logs setup timed out")??;
                Some(PreparedLogs {
                    sink,
                    scope,
                    target,
                    context,
                    network: state.clone(),
                })
            }
            None => None,
        };
        Ok(Self {
            state,
            task_id: task.task_id.clone(),
            logs,
        })
    }

    pub fn ports(&self) -> Vec<u16> {
        let mut ports = vec![AWS_GATEWAY_PORT];
        if self.state.task_role.is_some() {
            ports.push(CREDENTIALS_PORT);
        }
        ports
    }

    /// Apply after image and request environment variables are merged.
    pub fn inject_env(&self, environment: &mut HashMap<String, String>) {
        environment.retain(|key, _| !key.starts_with("AWS_ENDPOINT_URL_"));
        for key in [
            "AWS_ACCESS_KEY",
            "AWS_SECRET_KEY",
            "AWS_ROLE_ARN",
            "AWS_ROLE_SESSION_NAME",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_SECURITY_TOKEN",
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CONFIG_FILE",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        ] {
            environment.remove(key);
        }
        environment.insert("AWS_SHARED_CREDENTIALS_FILE".into(), "/dev/null".into());
        environment.insert("AWS_CONFIG_FILE".into(), "/dev/null".into());
        environment.insert(
            "AWS_ENDPOINT_URL".into(),
            format!("http://127.0.0.1:{AWS_GATEWAY_PORT}"),
        );
        environment.insert("AWS_REGION".into(), self.state.region.clone());
        environment.insert("AWS_DEFAULT_REGION".into(), self.state.region.clone());
        environment.insert("AWS_EC2_METADATA_DISABLED".into(), "true".into());
        if self.state.task_role.is_some() {
            environment.insert(
                "AWS_CONTAINER_CREDENTIALS_FULL_URI".into(),
                format!(
                    "http://127.0.0.1:{CREDENTIALS_PORT}{}",
                    self.state.credential_path
                ),
            );
            environment.insert(
                "AWS_CONTAINER_AUTHORIZATION_TOKEN".into(),
                self.state.credential_token.clone(),
            );
        }
    }

    /// For an already gated guest. The image must not execute until this succeeds.
    pub async fn start(
        self,
        runtime: Arc<YoukiRuntime>,
        task_id: &str,
    ) -> Result<GuestEndpoints, String> {
        if task_id != self.task_id {
            return Err("Task metadata binding does not match its owner".into());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut listeners = Vec::new();
        for port in self.ports() {
            loop {
                match runtime.bind_isolated_tcp(task_id, port).await {
                    Ok(listener) => {
                        listeners.push(listener);
                        break;
                    }
                    Err(_) if Instant::now() < deadline => {
                        tokio::time::sleep(Duration::from_millis(20)).await
                    }
                    Err(_) => return Err("Task metadata namespace binding failed".into()),
                }
            }
        }
        self.start_on_listeners(runtime, listeners).await
    }

    /// Accept listeners bound by the host pre-exec gate inside this exact task namespace.
    pub async fn start_on_listeners(
        self,
        runtime: Arc<dyn ComputeRuntime>,
        listeners: Vec<TcpListener>,
    ) -> Result<GuestEndpoints, String> {
        let mut expected = self.ports();
        expected.sort_unstable();
        let mut actual = Vec::new();
        for listener in &listeners {
            let address = listener
                .local_addr()
                .map_err(|_| "Task metadata listener is unavailable")?;
            if address.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST) {
                return Err("Task metadata listener must bind namespace loopback".into());
            }
            actual.push(address.port());
        }
        actual.sort_unstable();
        if actual != expected {
            return Err("Task metadata listener set does not match the prepared owner".into());
        }
        let mut servers = Vec::new();
        let (stop_logs, stop) = watch::channel(false);
        let closed = Arc::new(AtomicBool::new(false));
        for listener in listeners {
            let credentials = listener
                .local_addr()
                .map_err(|_| "Task metadata listener is unavailable")?
                .port()
                == CREDENTIALS_PORT;
            let state = self.state.clone();
            let request_stop = stop.clone();
            let router = Router::new().fallback(any(move |request: Request| {
                let state = state.clone();
                let mut stop = request_stop.clone();
                async move {
                    if *stop.borrow() { return plain(StatusCode::SERVICE_UNAVAILABLE,"Task is stopping"); }
                    tokio::select! {
                        response = async { if credentials { state.credential_request(request).await } else { state.sdk_request(request).await } } => response,
                        _ = stop.changed() => plain(StatusCode::SERVICE_UNAVAILABLE,"Task is stopping"),
                    }
                }
            }));
            let mut server_stop = stop.clone();
            let connection_stop = closed.clone();
            servers.push(tokio::spawn(async move {
                let _ = axum::serve(LimitedListener::new(listener, 8, connection_stop), router)
                    .with_graceful_shutdown(async move {
                        let _ = server_stop.changed().await;
                    })
                    .await;
            }));
        }
        let dropped_log_bytes = Arc::new(AtomicU64::new(0));
        let logs = self.logs.map(|logs| {
            tokio::spawn(forward_logs(
                runtime,
                self.task_id,
                logs,
                stop,
                dropped_log_bytes.clone(),
            ))
        });
        Ok(GuestEndpoints {
            servers,
            logs,
            stop_logs,
            dropped_log_bytes,
            closed,
        })
    }
}

impl GuestEndpoints {
    pub fn dropped_log_bytes(&self) -> u64 {
        self.dropped_log_bytes.load(Ordering::Relaxed)
    }
    /// Call after compute termination and before release_task removes its captured output.
    pub async fn shutdown(&mut self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.stop_logs.send(true);
        if let Some(mut logs) = self.logs.take() {
            if timeout(Duration::from_secs(5), &mut logs).await.is_err() {
                logs.abort();
                let _ = logs.await;
            }
        }
        for mut server in self.servers.drain(..) {
            if timeout(Duration::from_secs(2), &mut server).await.is_err() {
                server.abort();
                let _ = server.await;
            }
        }
    }
}
impl Drop for GuestEndpoints {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.stop_logs.send(true);
        for server in &self.servers {
            server.abort();
        }
        if let Some(logs) = &self.logs {
            logs.abort();
        }
    }
}

impl GuestState {
    fn allows_service(&self, service: &str) -> bool {
        self.ec2.vpc_endpoint_access(
            &self.account,
            &self.region,
            &self.subnet_id,
            self.private_ip,
            &self.security_groups,
            service,
        )
    }
    async fn current_credentials(&self) -> Result<ServiceRoleCredentials, String> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if let Some(credentials) = self
            .credentials
            .lock()
            .map_err(|_| "Task credential state is unavailable")?
            .last()
            .filter(|entry| entry.expires_at > now + 300)
            .map(|entry| entry.credentials.clone())
        {
            return Ok(credentials);
        }
        let _refresh = self
            .refresh_gate
            .acquire()
            .await
            .map_err(|_| "Task credential refresh is unavailable")?;
        if let Some(credentials) = self
            .credentials
            .lock()
            .map_err(|_| "Task credential state is unavailable")?
            .last()
            .filter(|entry| entry.expires_at > now + 300)
            .map(|entry| entry.credentials.clone())
        {
            return Ok(credentials);
        }
        let role = self.task_role.clone().ok_or("Task has no task role")?;
        let registry = self
            .registry
            .upgrade()
            .ok_or("Service registry is unavailable")?;
        let evaluator = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .ok_or("Task role credential issuer is unavailable")?;
        let account = self.account.clone();
        let credentials = tokio::task::spawn_blocking(move || {
            evaluator.issue_service_role_credentials(&account, &role, "ecs-tasks.amazonaws.com")
        })
        .await
        .map_err(|_| "Task role credential issuance failed")?
        .map_err(|_| "Task role credentials were denied")?;
        let expires_at = OffsetDateTime::parse(&credentials.expiration, &Rfc3339)
            .map_err(|_| "Task role credential expiration is invalid")?
            .unix_timestamp();
        if expires_at <= now + 300 {
            return Err("Task role credentials expire too soon".into());
        }
        let mut entries = self
            .credentials
            .lock()
            .map_err(|_| "Task credential state is unavailable")?;
        entries.retain(|entry| entry.expires_at > now);
        if entries.len() >= 4 {
            return Err("Task credential rotation capacity reached".into());
        }
        entries.push(CredentialEntry {
            credentials: credentials.clone(),
            expires_at,
        });
        Ok(credentials)
    }

    async fn credential_request(&self, request: Request) -> Response {
        if request.method() != Method::GET
            || request.uri().path() != self.credential_path
            || request.uri().query().is_some()
            || request
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                != Some(self.credential_token.as_str())
        {
            return plain(StatusCode::NOT_FOUND, "Task credentials are unavailable");
        }
        match self.current_credentials().await {
            Ok(credentials) => {
                let payload = serde_json::json!({"RoleArn":self.task_role,"AccessKeyId":credentials.access_key_id,"SecretAccessKey":credentials.secret_access_key,"Token":credentials.session_token,"Expiration":credentials.expiration});
                let mut response = Response::new(Body::from(payload.to_string()));
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                );
                response.headers_mut().insert(
                    http::header::CACHE_CONTROL,
                    http::HeaderValue::from_static("no-store"),
                );
                response
            }
            Err(_) => plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "Task credentials are unavailable",
            ),
        }
    }

    async fn sdk_request(&self, request: Request) -> Response {
        let (parts, body) = request.into_parts();
        let protocol = AwsProtocol::RestJson;
        let error = |code: &str, message: &str, status: u16, protocol| {
            AwsError::new(code, message, status)
                .render(protocol)
                .into_response()
        };
        if parts.uri.scheme().is_some()
            || parts.uri.authority().is_some()
            || parts
                .headers
                .keys()
                .any(|name| name.as_str().starts_with("x-locallycloud-"))
        {
            return error(
                "AccessDeniedException",
                "Invalid guest request metadata",
                403,
                protocol,
            );
        }
        let Some(registry) = self.registry.upgrade() else {
            return error(
                "ServiceUnavailableException",
                "Service registry is unavailable",
                503,
                protocol,
            );
        };
        let authorization = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        let Some(service) = extract_service_from_credential_scope(authorization, None) else {
            return error(
                "AccessDeniedException",
                "Task SigV4 credentials are required",
                403,
                protocol,
            );
        };
        if extract_region_from_credential_scope(authorization, None).as_deref()
            != Some(self.region.as_str())
        {
            return error(
                "AccessDeniedException",
                "Task region does not match",
                403,
                protocol,
            );
        }
        let bytes = match timeout(Duration::from_secs(10), to_bytes(body, MAX_HTTP_BODY)).await {
            Ok(Ok(bytes)) => bytes,
            _ => {
                return error(
                    "RequestEntityTooLargeException",
                    "Guest request body limit exceeded",
                    413,
                    protocol,
                )
            }
        };
        let input = RouteInput {
            authorization,
            x_amz_credential: None,
            x_amz_target: parts
                .headers
                .get("x-amz-target")
                .and_then(|v| v.to_str().ok()),
            host: parts
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok()),
            path: parts.uri.path(),
            body: &bytes,
        };
        let decision = match resolve(&registry, &input) {
            Ok(decision) => decision,
            Err(_) => {
                return error(
                    "InvalidRequestException",
                    "Guest service could not be resolved",
                    400,
                    protocol,
                )
            }
        };
        let protocol = registry
            .lookup(&decision.service_name)
            .map(|entry| entry.metadata.protocol)
            .unwrap_or(protocol);
        if decision.service_name.as_str() != service.as_str()
            || (service.as_str() == "ssm"
                && !matches!(
                    input.x_amz_target,
                    Some("AmazonSSM.GetParameter" | "AmazonSSM.GetParameters")
                ))
        {
            return error(
                "AccessDeniedException",
                "Guest operation is outside the audited native IAM contract",
                403,
                protocol,
            );
        }
        if decision.disposition != RouteDisposition::HandledNatively {
            return error(
                "ServiceUnavailableException",
                "Guest gateway requires a native service",
                503,
                protocol,
            );
        }
        let key = authorization.and_then(RequestIdentity::access_key_from_authorization);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let owned = key.as_ref().is_some_and(|key| {
            self.credentials.lock().ok().is_some_and(|entries| {
                entries
                    .iter()
                    .any(|entry| entry.expires_at > now && entry.credentials.access_key_id == *key)
            })
        });
        let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
            return error(
                "AccessDeniedException",
                "Task credential verifier is unavailable",
                403,
                protocol,
            );
        };
        let account = self.account.clone();
        let region = self.region.clone();
        let method = parts.method.clone();
        let uri = parts.uri.clone();
        let headers = parts.headers.clone();
        let signing_service = service.as_str().to_owned();
        let verify_bytes = bytes.clone();
        let verified = if owned {
            tokio::task::spawn_blocking(move || {
                evaluator.verify_sigv4(
                    &account,
                    &method,
                    &uri,
                    &headers,
                    &verify_bytes,
                    &region,
                    &signing_service,
                )
            })
            .await
            .unwrap_or(false)
        } else {
            false
        };
        if !verified {
            return error(
                "InvalidSignatureException",
                "Task signature validation failed",
                403,
                protocol,
            );
        }
        if !self.allows_service(service.as_str()) {
            return error(
                "VpcEndpointUnavailableException",
                "VPC endpoint or task egress is unavailable",
                503,
                protocol,
            );
        }
        let Some(dispatcher) = registry.internal_dispatcher() else {
            return error(
                "ServiceUnavailableException",
                "Native dispatcher is unavailable",
                503,
                protocol,
            );
        };
        let dispatched = timeout(
            Duration::from_secs(15),
            dispatcher.dispatch_scoped(
                &parts.method,
                &parts.uri,
                &parts.headers,
                bytes,
                &Uuid::new_v4().to_string(),
                &self.account,
                &self.region,
            ),
        )
        .await;
        let response = match dispatched {
            Ok(response) => response,
            Err(_) => {
                return error(
                    "ServiceUnavailableException",
                    "Native guest request timed out",
                    503,
                    protocol,
                )
            }
        };
        let (parts, body) = response.into_parts();
        match timeout(Duration::from_secs(15), to_bytes(body, MAX_HTTP_BODY)).await {
            Ok(Ok(bytes)) => Response::from_parts(parts, Body::from(bytes)),
            _ => error(
                "ResponseTooLargeException",
                "Guest response limit exceeded",
                502,
                protocol,
            ),
        }
    }
}

fn plain(status: StatusCode, message: &'static str) -> Response {
    let mut response = Response::new(Body::from(message));
    *response.status_mut() = status;
    response
}

struct PendingLogs {
    events: Vec<ProducerLogEvent>,
    next_cursor: u64,
    failures: u8,
    retained_bytes: u64,
    dropped: Arc<AtomicU64>,
    task_id: String,
}
impl Drop for PendingLogs {
    fn drop(&mut self) {
        if self.retained_bytes > 0 {
            self.dropped
                .fetch_add(self.retained_bytes, Ordering::Relaxed);
            tracing::warn!(task_id=%self.task_id,dropped_bytes=self.retained_bytes,"ECS log batch was not acknowledged before bounded delivery ended");
        }
    }
}

fn pending_logs(output: TaskOutput, task_id: &str, dropped: Arc<AtomicU64>) -> PendingLogs {
    let timestamp_ms = i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .unwrap_or(i64::MAX);
    let mut events = Vec::new();
    let mut consumed = 0;
    while consumed < output.text.len() && consumed < MAX_LOG_BYTES && events.len() < MAX_LOG_EVENTS
    {
        let mut end = output
            .text
            .len()
            .min(consumed + MAX_EVENT_BYTES)
            .min(MAX_LOG_BYTES);
        while end > consumed && !output.text.is_char_boundary(end) {
            end -= 1;
        }
        if end == consumed {
            break;
        }
        let slice = &output.text[consumed..end];
        if let Some(newline) = slice.find('\n') {
            end = consumed + newline + 1;
        }
        events.push(ProducerLogEvent {
            timestamp_ms,
            message: output.text[consumed..end].to_owned(),
        });
        consumed = end;
    }
    let lost = output
        .dropped_bytes
        .saturating_add((output.text.len() - consumed) as u64);
    if lost > 0 {
        dropped.fetch_add(lost, Ordering::Relaxed);
        tracing::warn!(
            task_id,
            lost_output_bytes = lost,
            "ECS bounded log capture or batch limit discarded output"
        );
    }
    PendingLogs {
        events,
        next_cursor: output.next_cursor,
        failures: 0,
        retained_bytes: consumed as u64,
        dropped,
        task_id: task_id.into(),
    }
}

async fn forward_logs(
    runtime: Arc<dyn ComputeRuntime>,
    task_id: String,
    logs: PreparedLogs,
    mut stop: watch::Receiver<bool>,
    dropped: Arc<AtomicU64>,
) {
    let mut cursor = 0;
    let mut pending: Option<PendingLogs> = None;
    let mut closing = false;
    let mut read_failures: u32 = 0;
    let first_read_deadline = Instant::now() + Duration::from_secs(5);
    let mut has_read = false;
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=ticker.tick()=>{},
            changed=stop.changed(),if !closing=>{closing=changed.is_err() || *stop.borrow();},
        }
        if pending.is_none() {
            match timeout(
                Duration::from_secs(2),
                runtime.read_output(&task_id, cursor),
            )
            .await
            {
                Ok(Ok(output)) if !output.text.is_empty() || output.dropped_bytes > 0 => {
                    read_failures = 0;
                    has_read = true;
                    pending = Some(pending_logs(output, &task_id, dropped.clone()))
                }
                Ok(Ok(_)) if closing => break,
                Ok(Ok(_)) => {
                    read_failures = 0;
                    has_read = true;
                    continue;
                }
                _ => {
                    read_failures = read_failures.saturating_add(1);
                    if (has_read || Instant::now() >= first_read_deadline)
                        && (closing || read_failures.is_power_of_two())
                    {
                        tracing::warn!(
                            task_id,
                            read_failures,
                            final_read = closing,
                            "ECS captured logs could not be read"
                        );
                    }
                    if closing {
                        break;
                    }
                    continue;
                }
            }
        }
        let Some(batch) = pending.as_mut() else {
            continue;
        };
        if batch.events.is_empty() {
            cursor = batch.next_cursor;
            batch.retained_bytes = 0;
            pending = None;
            continue;
        }
        let result = if logs.network.allows_service("logs") {
            timeout(
                Duration::from_secs(3),
                logs.sink.append(
                    logs.scope.clone(),
                    logs.target.clone(),
                    batch.events.clone(),
                    logs.context.clone(),
                ),
            )
            .await
            .ok()
            .and_then(Result::ok)
        } else {
            None
        };
        if matches!(result,Some(ref outcome) if outcome.stored_events==batch.events.len()) {
            cursor = batch.next_cursor;
            batch.retained_bytes = 0;
            pending = None;
        } else {
            batch.failures = batch.failures.saturating_add(1);
            if batch.failures >= MAX_LOG_FAILURES || closing {
                cursor = batch.next_cursor;
                pending = None;
            }
        }
    }
}

/// Limit complete HTTP connections, including slow response consumers and keepalive.
struct LimitedListener {
    inner: TcpListener,
    slots: Arc<Semaphore>,
    closed: Arc<AtomicBool>,
}
impl LimitedListener {
    fn new(inner: TcpListener, slots: usize, closed: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            slots: Arc::new(Semaphore::new(slots)),
            closed,
        }
    }
}
struct LimitedStream {
    inner: TcpStream,
    _permit: OwnedSemaphorePermit,
    deadline: Pin<Box<tokio::time::Sleep>>,
    stop_tick: Pin<Box<tokio::time::Sleep>>,
    closed: Arc<AtomicBool>,
}
impl axum::serve::Listener for LimitedListener {
    type Io = LimitedStream;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = match self.inner.accept().await {
                Ok(value) => value,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
            };
            let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            return (
                LimitedStream {
                    inner: stream,
                    _permit: permit,
                    deadline: Box::pin(tokio::time::sleep(Duration::from_secs(30))),
                    stop_tick: Box::pin(tokio::time::sleep(Duration::from_secs(1))),
                    closed: self.closed.clone(),
                },
                address,
            );
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}
impl LimitedStream {
    fn closing(&mut self, context: &mut Context<'_>) -> bool {
        if self.closed.load(Ordering::Acquire)
            || std::future::Future::poll(self.deadline.as_mut(), context).is_ready()
        {
            return true;
        }
        if std::future::Future::poll(self.stop_tick.as_mut(), context).is_ready() {
            self.stop_tick
                .as_mut()
                .reset(Instant::now() + Duration::from_secs(1));
            let _ = std::future::Future::poll(self.stop_tick.as_mut(), context);
        }
        false
    }
}
impl AsyncRead for LimitedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.closing(context) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}
impl AsyncWrite for LimitedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.closing(context) {
            return Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
        }
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_core::handler::{NativeHandler, ServiceRequest};
    use locallycloud_core::integration::authorization::{
        AuthorizationError, AuthorizationEvaluator, AuthorizationRequest,
    };
    use locallycloud_core::registry::ServiceMetadata;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Handler;
    #[async_trait::async_trait]
    impl NativeHandler for Handler {
        async fn handle(&self, _: ServiceRequest) -> Response {
            Response::new(Body::empty())
        }
    }
    struct Issuer(AtomicUsize);
    impl AuthorizationEvaluator for Issuer {
        fn authorize(&self, _: AuthorizationRequest) -> Result<(), AuthorizationError> {
            Ok(())
        }
        fn issue_service_role_credentials(
            &self,
            account: &str,
            role: &str,
            principal: &str,
        ) -> Result<ServiceRoleCredentials, AuthorizationError> {
            assert_eq!(account, "000000000000");
            assert_eq!(role, "arn:aws:iam::000000000000:role/task");
            assert_eq!(principal, "ecs-tasks.amazonaws.com");
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(ServiceRoleCredentials {
                access_key_id: "ASIATASK".into(),
                secret_access_key: "task-secret".into(),
                session_token: "task-token".into(),
                expiration: (OffsetDateTime::now_utc() + time::Duration::hours(1))
                    .format(&Rfc3339)
                    .unwrap(),
            })
        }
        fn verify_sigv4(
            &self,
            _: &str,
            _: &Method,
            _: &http::Uri,
            _: &http::HeaderMap,
            _: &[u8],
            _: &str,
            _: &str,
        ) -> bool {
            true
        }
    }
    fn state() -> (Arc<ServiceRegistry>, Arc<GuestState>, Arc<Issuer>) {
        let registry = Arc::new(ServiceRegistry::new());
        let issuer = Arc::new(Issuer(AtomicUsize::new(0)));
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            Arc::new(Handler),
            issuer.clone(),
        );
        registry.register_native(
            ServiceName::new("dynamodb"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("DynamoDB_20120810")),
            Arc::new(Handler),
        );
        let state = Arc::new(GuestState {
            registry: Arc::downgrade(&registry),
            ec2: Arc::new(Ec2Handler::default()),
            account: "000000000000".into(),
            region: "us-east-1".into(),
            subnet_id: "subnet-test".into(),
            private_ip: "10.0.0.10".parse().unwrap(),
            security_groups: vec!["sg-task".into()],
            task_role: Some("arn:aws:iam::000000000000:role/task".into()),
            credentials: Mutex::new(Vec::new()),
            refresh_gate: Semaphore::new(1),
            credential_path: "/v2/credentials/task".into(),
            credential_token: "owned-token".into(),
        });
        (registry, state, issuer)
    }

    #[tokio::test]
    async fn task_credentials_are_cached_expiring_and_never_injected_as_static_keys() {
        let (_registry, state, issuer) = state();
        let (first, second) =
            tokio::join!(state.current_credentials(), state.current_credentials());
        assert_eq!(first.unwrap().access_key_id, second.unwrap().access_key_id);
        assert_eq!(issuer.0.load(Ordering::SeqCst), 1);
        let denied = state
            .credential_request(
                Request::builder()
                    .uri(&state.credential_path)
                    .header("authorization", "foreign-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);
        let response = state
            .credential_request(
                Request::builder()
                    .uri(&state.credential_path)
                    .header("authorization", "owned-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let payload: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(payload["AccessKeyId"], "ASIATASK");
        assert_eq!(payload["Token"], "task-token");
        assert!(
            OffsetDateTime::parse(payload["Expiration"].as_str().unwrap(), &Rfc3339).unwrap()
                > OffsetDateTime::now_utc()
        );
        let prepared = PreparedGuest {
            state,
            task_id: "task".into(),
            logs: None,
        };
        let mut env = HashMap::from([
            ("AWS_ACCESS_KEY_ID".into(), "admin".into()),
            ("AWS_SECRET_ACCESS_KEY".into(), "admin-secret".into()),
            (
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI".into(),
                "/other".into(),
            ),
            ("AWS_ENDPOINT_URL_DYNAMODB".into(), "http://host".into()),
            ("AWS_WEB_IDENTITY_TOKEN_FILE".into(), "/admin".into()),
        ]);
        prepared.inject_env(&mut env);
        assert!(!env.contains_key("AWS_ACCESS_KEY_ID"));
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!env.contains_key("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"));
        assert!(!env.contains_key("AWS_ENDPOINT_URL_DYNAMODB"));
        assert!(!env.contains_key("AWS_WEB_IDENTITY_TOKEN_FILE"));
        assert_eq!(env["AWS_SHARED_CREDENTIALS_FILE"], "/dev/null");
        assert_eq!(env["AWS_CONFIG_FILE"], "/dev/null");
        assert_eq!(
            env["AWS_CONTAINER_CREDENTIALS_FULL_URI"],
            "http://127.0.0.1:18081/v2/credentials/task"
        );
    }

    #[tokio::test]
    async fn sdk_gateway_rejects_foreign_keys_internal_headers_and_missing_vpc_access() {
        let (_registry, state, _issuer) = state();
        state.current_credentials().await.unwrap();
        fn request(key: &str, internal: bool) -> Request {
            let mut request=Request::builder().method("POST").uri("/").header("x-amz-target","DynamoDB_20120810.ListTables").header("authorization",format!("AWS4-HMAC-SHA256 Credential={key}/20261019/us-east-1/dynamodb/aws4_request, SignedHeaders=host, Signature=invalid"));
            if internal {
                request = request.header(
                    "x-locallycloud-caller-principal",
                    "arn:aws:iam::000000000000:role/admin/session",
                );
            }
            request.body(Body::from("{}")).unwrap()
        }
        let response = state.sdk_request(request("ASIAFOREIGN", false)).await;
        assert_eq!(response.status(), 403);
        assert!(
            String::from_utf8_lossy(&to_bytes(response.into_body(), 4096).await.unwrap())
                .contains("InvalidSignatureException")
        );
        let response = state.sdk_request(request("ASIATASK", true)).await;
        assert_eq!(response.status(), 403);
        // The verifier is mocked above: owned requests must still pass the real EC2 endpoint gate.
        let response = state.sdk_request(request("ASIATASK", false)).await;
        assert_eq!(response.status(), 503);
        assert!(
            String::from_utf8_lossy(&to_bytes(response.into_body(), 4096).await.unwrap())
                .contains("VpcEndpointUnavailableException")
        );
    }

    #[test]
    fn bounded_log_batch_reports_capture_excess_and_unacknowledged_delivery() {
        let dropped = Arc::new(AtomicU64::new(0));
        let output = TaskOutput {
            text: "π".repeat(MAX_LOG_BYTES),
            next_cursor: (MAX_LOG_BYTES * 2) as u64,
            dropped_bytes: 37,
        };
        let mut batch = pending_logs(output, "task", dropped.clone());
        assert!(batch.events.len() <= MAX_LOG_EVENTS);
        assert!(batch
            .events
            .iter()
            .all(|event| event.message.len() <= MAX_EVENT_BYTES));
        assert_eq!(
            batch
                .events
                .iter()
                .map(|event| event.message.len())
                .sum::<usize>(),
            MAX_LOG_BYTES
        );
        assert_eq!(dropped.load(Ordering::Relaxed), MAX_LOG_BYTES as u64 + 37);
        batch.retained_bytes = 0;
        drop(batch);
        assert_eq!(
            dropped.load(Ordering::Relaxed),
            MAX_LOG_BYTES as u64 + 37,
            "acknowledged bytes must not be reported lost"
        );
        let batch = pending_logs(
            TaskOutput {
                text: "unacknowledged\n".into(),
                next_cursor: 15,
                dropped_bytes: 0,
            },
            "task",
            dropped.clone(),
        );
        let retained = batch.retained_bytes;
        drop(batch);
        assert_eq!(
            dropped.load(Ordering::Relaxed),
            MAX_LOG_BYTES as u64 + 37 + retained
        );
    }

    #[tokio::test]
    async fn complete_connection_cap_and_shutdown_cover_idle_keepalive_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let closed = Arc::new(AtomicBool::new(false));
        let mut limited = LimitedListener::new(listener, 1, closed.clone());
        let mut first = TcpStream::connect(address).await.unwrap();
        let (mut owned, _) = axum::serve::Listener::accept(&mut limited).await;
        first.write_all(b"x").await.unwrap();
        let mut byte = [0u8; 1];
        owned.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"x");
        let second = TcpStream::connect(address).await.unwrap();
        assert!(timeout(
            Duration::from_millis(20),
            axum::serve::Listener::accept(&mut limited)
        )
        .await
        .is_err());
        drop(second);
        closed.store(true, Ordering::Release);
        assert_eq!(
            timeout(Duration::from_secs(2), owned.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
    fn encoded(text: &str) -> String {
        text.bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
                    (byte as char).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect()
    }
    async fn native(
        registry: &ServiceRegistry,
        service: &str,
        body: String,
        target: Option<&str>,
    ) -> String {
        let mut headers = http::HeaderMap::new();
        // Explicit trusted controller fixture; task requests never pass through this helper.
        headers.insert(
            "x-locallycloud-verified-internal-scope",
            http::HeaderValue::from_static("1"),
        );
        headers.insert(
            "x-locallycloud-caller-principal",
            http::HeaderValue::from_static("arn:aws:iam::000000000000:role/operator/setup"),
        );
        if let Some(target) = target {
            headers.insert("x-amz-target", target.parse().unwrap());
            headers.insert(
                "content-type",
                http::HeaderValue::from_static("application/x-amz-json-1.1"),
            );
        }
        let response = registry
            .native_handler(&ServiceName::new(service))
            .unwrap()
            .handle(ServiceRequest {
                method: Method::POST,
                uri: "/".parse().unwrap(),
                headers,
                body: body.into(),
                account_id: "000000000000".into(),
                region: "us-east-1".into(),
                request_id: Uuid::new_v4().to_string(),
            })
            .await;
        let status = response.status();
        let text = String::from_utf8(
            to_bytes(response.into_body(), MAX_HTTP_BODY)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(status.is_success(), "{service} status {status}: {text}");
        text
    }
    fn element(text: &str, name: &str) -> String {
        text.split(&format!("<{name}>"))
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned()
    }
    fn signed_request(credentials: &ServiceRoleCredentials, target: &str, body: &str) -> Request {
        use hmac::{Hmac, Mac};
        use sha2::{Digest, Sha256};
        fn mac(key: &[u8], value: &[u8]) -> Vec<u8> {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
            mac.update(value);
            mac.finalize().into_bytes().to_vec()
        }
        let service = if target.starts_with("Logs_") {
            "logs"
        } else if target.starts_with("AmazonSSM.") {
            "ssm"
        } else {
            "dynamodb"
        };
        let date = OffsetDateTime::now_utc()
            .format(
                &time::format_description::parse_borrowed::<3>(
                    "[year][month][day]T[hour][minute][second]Z",
                )
                .unwrap(),
            )
            .unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("host", http::HeaderValue::from_static("127.0.0.1:18082"));
        headers.insert(
            "content-type",
            http::HeaderValue::from_static(if service != "dynamodb" {
                "application/x-amz-json-1.1"
            } else {
                "application/x-amz-json-1.0"
            }),
        );
        headers.insert("x-amz-date", date.parse().unwrap());
        headers.insert("x-amz-target", target.parse().unwrap());
        headers.insert(
            "x-amz-security-token",
            credentials.session_token.parse().unwrap(),
        );
        let mut names = headers.keys().map(|name| name.as_str()).collect::<Vec<_>>();
        names.sort_unstable();
        let signed = names.join(";");
        let canonical_headers = names
            .iter()
            .map(|name| format!("{name}:{}\n", headers[*name].to_str().unwrap()))
            .collect::<String>();
        let canonical = format!(
            "POST\n/\n\n{canonical_headers}\n{signed}\n{:x}",
            Sha256::digest(body.as_bytes())
        );
        let scope = format!("{}/us-east-1/{service}/aws4_request", &date[..8]);
        let string = format!(
            "AWS4-HMAC-SHA256\n{date}\n{scope}\n{:x}",
            Sha256::digest(canonical.as_bytes())
        );
        let key = mac(
            format!("AWS4{}", credentials.secret_access_key).as_bytes(),
            &date.as_bytes()[..8],
        );
        let key = mac(&key, b"us-east-1");
        let key = mac(&key, service.as_bytes());
        let key = mac(&key, b"aws4_request");
        let signature = mac(&key, string.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        headers.insert("authorization",format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",credentials.access_key_id).parse().unwrap());
        let mut request = Request::new(Body::from(body.to_owned()));
        *request.method_mut() = Method::POST;
        *request.uri_mut() = "/".parse().unwrap();
        *request.headers_mut() = headers;
        request
    }
    async fn external(registry: &ServiceRegistry, request: Request) -> Response {
        let (parts, body) = request.into_parts();
        let body = to_bytes(body, MAX_HTTP_BODY).await.unwrap();
        registry
            .internal_dispatcher()
            .unwrap()
            .dispatch_verified_peer(
                &parts.method,
                &parts.uri,
                &parts.headers,
                body,
                &Uuid::new_v4().to_string(),
                Ipv4Addr::LOCALHOST.into(),
            )
            .await
    }
    struct OutputRuntime;
    #[async_trait::async_trait]
    impl ComputeRuntime for OutputRuntime {
        async fn start_task(
            &self,
            _: &str,
            _: &locallycloud_compute::runtime::TaskSpec,
        ) -> Result<
            locallycloud_compute::runtime::TaskHandle,
            locallycloud_compute::runtime::RuntimeError,
        > {
            unreachable!()
        }
        async fn stop_task(
            &self,
            _: &str,
        ) -> Result<
            locallycloud_compute::runtime::TaskHandle,
            locallycloud_compute::runtime::RuntimeError,
        > {
            unreachable!()
        }
        async fn get_output(
            &self,
            _: &str,
        ) -> Result<String, locallycloud_compute::runtime::RuntimeError> {
            Ok("cursor-output-fixture\n".into())
        }
        async fn read_output(
            &self,
            _: &str,
            cursor: u64,
        ) -> Result<TaskOutput, locallycloud_compute::runtime::RuntimeError> {
            let text = "cursor-output-fixture\n";
            Ok(TaskOutput {
                text: if cursor == 0 {
                    text.into()
                } else {
                    String::new()
                },
                next_cursor: text.len() as u64,
                dropped_bytes: 0,
            })
        }
    }

    #[tokio::test]
    async fn native_iam_signed_sdk_vpc_revoke_recovery_and_execution_role_logs() {
        let registry = Arc::new(ServiceRegistry::new());
        let iam_store = Arc::new(locallycloud_iam_sts::store::IamStore::new());
        let iam_sessions = Arc::new(locallycloud_iam_sts::sts::SessionStore::new());
        locallycloud_dynamodb::register(&registry);
        locallycloud_ssm::register(&registry);
        locallycloud_cloudwatch_logs::register(&registry).unwrap();
        let ec2 = locallycloud_ec2::register(&registry);
        registry.set_internal_dispatcher(Arc::new(
            locallycloud_core::integration::InternalDispatcher::new_shared(
                &registry,
                locallycloud_core::proxy::ProxyConfig {
                    backend_url: "http://127.0.0.1:1".into(),
                    upstream_timeout: Duration::from_secs(1),
                },
                locallycloud_core::proxy::LegacyHealth::new(false),
                "us-east-1".into(),
                "000000000000".into(),
            ),
        ));
        let trust = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}}"#;
        for role in ["task", "execution", "operator"] {
            let actions = match role {
                "task" => "dynamodb:*",
                "execution" => "logs:*",
                "operator" => "ec2:*",
                _ => unreachable!(),
            };
            let policy = serde_json::json!({"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":actions,"Resource":"*"}}).to_string();
            let create = locallycloud_iam_sts::query::QueryRequest::parse(
                format!(
                    "RoleName={role}&AssumeRolePolicyDocument={}",
                    encoded(trust)
                )
                .as_bytes(),
            );
            locallycloud_iam_sts::iam::create_role(&iam_store, "000000000000", &create).unwrap();
            let policy = locallycloud_iam_sts::query::QueryRequest::parse(
                format!(
                    "RoleName={role}&PolicyName=test&PolicyDocument={}",
                    encoded(&policy)
                )
                .as_bytes(),
            );
            locallycloud_iam_sts::iam::put_inline_policy(
                &iam_store,
                "000000000000",
                locallycloud_iam_sts::iam::Entity::Role,
                &policy,
            )
            .unwrap();
        }
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            iam_store.clone(),
            iam_sessions,
            locallycloud_iam_sts::enforcement::EnforcementMode::Strict,
        );
        assert!(registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .unwrap()
            .strict_sigv4_required());
        let vpc = element(
            &native(
                &registry,
                "ec2",
                "Action=CreateVpc&CidrBlock=10.0.0.0%2F16".into(),
                None,
            )
            .await,
            "vpcId",
        );
        native(
            &registry,
            "ec2",
            format!("Action=ModifyVpcAttribute&VpcId={vpc}&EnableDnsHostnames.Value=true"),
            None,
        )
        .await;
        let subnet = element(
            &native(
                &registry,
                "ec2",
                format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.0.1.0%2F24"),
                None,
            )
            .await,
            "subnetId",
        );
        let group = element(
            &native(
                &registry,
                "ec2",
                format!(
                    "Action=CreateSecurityGroup&VpcId={vpc}&GroupName=task&GroupDescription=task"
                ),
                None,
            )
            .await,
            "groupId",
        );
        let endpoint_group=element(&native(&registry,"ec2",format!("Action=CreateSecurityGroup&VpcId={vpc}&GroupName=endpoint&GroupDescription=endpoint"),None).await,"groupId");
        native(&registry,"ec2",format!("Action=AuthorizeSecurityGroupIngress&GroupId={endpoint_group}&IpProtocol=tcp&FromPort=443&ToPort=443&CidrIp=10.0.0.0%2F16"),None).await;
        native(&registry,"ec2",format!("Action=CreateVpcEndpoint&VpcId={vpc}&ServiceName=com.amazonaws.us-east-1.logs&VpcEndpointType=Interface&SubnetId.1={subnet}&SecurityGroupId.1={endpoint_group}&PrivateDnsEnabled=true"),None).await;
        let sink = registry.log_sink(&ServiceName::new("logs")).unwrap();
        sink.ensure_group(
            LogScope::new("000000000000", "us-east-1"),
            locallycloud_core::integration::logs::ProducerGroupSpec {
                name: "/ecs/native".into(),
            },
            ProducerContext {
                source_service: "ecs".into(),
                identity: CallerIdentity::AssumedRole {
                    role_arn: "arn:aws:iam::000000000000:role/execution".into(),
                    session_name: "setup".into(),
                },
                correlation: CorrelationContext {
                    flow_id: Uuid::new_v4().to_string(),
                    span_id: Uuid::new_v4().to_string(),
                },
                loop_depth: 0,
            },
        )
        .await
        .unwrap();
        let task_id = Uuid::new_v4().simple().to_string();
        let network = ec2
            .reserve_task_network(
                "000000000000",
                "us-east-1",
                &subnet,
                std::slice::from_ref(&group),
                &task_id,
            )
            .unwrap();
        let task = TaskLaunch {
            task_id: task_id.clone(),
            container_name: "worker".into(),
            image: "fixture".into(),
            command: Vec::new(),
            environment: HashMap::new(),
            memory_mb: 512,
            cpu: 256,
            subnets: vec![subnet.clone()],
            security_groups: vec![group.clone()],
            account: "000000000000".into(),
            region: "us-east-1".into(),
            port: 8080,
            task_role_arn: Some("arn:aws:iam::000000000000:role/task".into()),
            execution_role_arn: Some("arn:aws:iam::000000000000:role/execution".into()),
            log_configuration: Some(locallycloud_ecs::TaskLogConfiguration {
                log_driver: "awslogs".into(),
                options: std::collections::BTreeMap::from([
                    ("awslogs-group".into(), "/ecs/native".into()),
                    ("awslogs-region".into(), "us-east-1".into()),
                    ("awslogs-stream-prefix".into(), "prefix".into()),
                ]),
            }),
        };
        let mut prepared =
            PreparedGuest::prepare(Arc::downgrade(&registry), ec2.clone(), &task, &network)
                .await
                .unwrap();
        assert!(
            matches!(&prepared.logs.as_ref().unwrap().context.identity,CallerIdentity::AssumedRole {role_arn,..} if role_arn == "arn:aws:iam::000000000000:role/execution")
        );
        let credentials = prepared.state.current_credentials().await.unwrap();
        assert!(credentials.access_key_id.starts_with("ASIA"));
        let missing = prepared
            .state
            .sdk_request(signed_request(
                &credentials,
                "DynamoDB_20120810.ListTables",
                "{}",
            ))
            .await;
        assert_eq!(missing.status(), 503);
        let route = element(
            &native(
                &registry,
                "ec2",
                format!("Action=CreateRouteTable&VpcId={vpc}"),
                None,
            )
            .await,
            "routeTableId",
        );
        native(
            &registry,
            "ec2",
            format!("Action=AssociateRouteTable&RouteTableId={route}&SubnetId={subnet}"),
            None,
        )
        .await;
        native(&registry,"ec2",format!("Action=CreateVpcEndpoint&VpcId={vpc}&ServiceName=com.amazonaws.us-east-1.dynamodb&VpcEndpointType=Gateway&RouteTableId.1={route}&PrivateDnsEnabled=false"),None).await;
        let create = r#"{"TableName":"guest-table","AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],"KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],"BillingMode":"PAY_PER_REQUEST"}"#;
        let response = prepared
            .state
            .sdk_request(signed_request(
                &credentials,
                "DynamoDB_20120810.CreateTable",
                create,
            ))
            .await;
        let status = response.status();
        let body = to_bytes(response.into_body(), MAX_HTTP_BODY).await.unwrap();
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let response = prepared
            .state
            .sdk_request(signed_request(
                &credentials,
                "DynamoDB_20120810.ListTables",
                "{}",
            ))
            .await;
        assert_eq!(response.status(), 200);
        assert!(String::from_utf8_lossy(
            &to_bytes(response.into_body(), MAX_HTTP_BODY).await.unwrap()
        )
        .contains("guest-table"));
        let mut corrupted = credentials.clone();
        corrupted.secret_access_key = "wrong".into();
        assert_eq!(
            prepared
                .state
                .sdk_request(signed_request(
                    &corrupted,
                    "DynamoDB_20120810.ListTables",
                    "{}"
                ))
                .await
                .status(),
            403
        );
        let evaluator = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .unwrap();
        let foreign = evaluator
            .issue_service_role_credentials(
                "000000000000",
                "arn:aws:iam::000000000000:role/task",
                "ecs-tasks.amazonaws.com",
            )
            .unwrap();
        let foreign_request = signed_request(&foreign, "DynamoDB_20120810.ListTables", "{}");
        assert!(evaluator.verify_sigv4(
            "000000000000",
            foreign_request.method(),
            foreign_request.uri(),
            foreign_request.headers(),
            b"{}",
            "us-east-1",
            "dynamodb"
        ));
        assert_eq!(
            prepared.state.sdk_request(foreign_request).await.status(),
            403,
            "another task's genuine session must not gain this gateway"
        );
        let log_body=serde_json::json!({"logGroupName":"/ecs/native","logStreamName":format!("prefix/worker/{task_id}")}).to_string();
        let denied_logs = prepared
            .state
            .sdk_request(signed_request(
                &credentials,
                "Logs_20140328.GetLogEvents",
                &log_body,
            ))
            .await;
        let denied_status = denied_logs.status();
        let denied_body = to_bytes(denied_logs.into_body(), 4096).await.unwrap();
        assert!(
            denied_status.is_client_error(),
            "{denied_status}: {}",
            String::from_utf8_lossy(&denied_body)
        );
        assert!(
            String::from_utf8_lossy(&denied_body).contains("AccessDenied"),
            "Task role must not inherit execution role log permissions"
        );
        let execution = evaluator
            .issue_service_role_credentials(
                "000000000000",
                "arn:aws:iam::000000000000:role/execution",
                "ecs-tasks.amazonaws.com",
            )
            .unwrap();
        let denied_ddb = external(
            &registry,
            signed_request(&execution, "DynamoDB_20120810.ListTables", "{}"),
        )
        .await;
        assert!(denied_ddb.status().is_client_error());
        assert!(
            String::from_utf8_lossy(&to_bytes(denied_ddb.into_body(), 4096).await.unwrap())
                .contains("AccessDenied"),
            "Execution role must not inherit task role DynamoDB permissions"
        );
        native(&registry,"ec2",format!("Action=RevokeSecurityGroupEgress&GroupId={group}&IpPermissions.1.IpProtocol=-1&IpPermissions.1.FromPort=0&IpPermissions.1.ToPort=0&IpPermissions.1.IpRanges.1.CidrIp=0.0.0.0%2F0"),None).await;
        assert_eq!(
            prepared
                .state
                .sdk_request(signed_request(
                    &credentials,
                    "DynamoDB_20120810.ListTables",
                    "{}"
                ))
                .await
                .status(),
            503
        );
        native(&registry,"ec2",format!("Action=AuthorizeSecurityGroupEgress&GroupId={group}&IpPermissions.1.IpProtocol=-1&IpPermissions.1.FromPort=0&IpPermissions.1.ToPort=0&IpPermissions.1.IpRanges.1.CidrIp=0.0.0.0%2F0"),None).await;
        assert_eq!(
            prepared
                .state
                .sdk_request(signed_request(
                    &credentials,
                    "DynamoDB_20120810.ListTables",
                    "{}"
                ))
                .await
                .status(),
            200
        );
        let (stop, receiver) = watch::channel(false);
        let dropped = Arc::new(AtomicU64::new(0));
        let log_scope = prepared.logs.as_ref().unwrap().scope.clone();
        let log_target = prepared.logs.as_ref().unwrap().target.clone();
        let log_context = prepared.logs.as_ref().unwrap().context.clone();
        let worker = tokio::spawn(forward_logs(
            Arc::new(OutputRuntime),
            task_id.clone(),
            prepared.logs.take().unwrap(),
            receiver,
            dropped.clone(),
        ));
        timeout(Duration::from_secs(5),async {
            loop {
                let body=serde_json::json!({"logGroupName":"/ecs/native","logStreamName":format!("prefix/worker/{task_id}"),"startFromHead":true}).to_string();
                let response=external(&registry,signed_request(&execution,"Logs_20140328.GetLogEvents",&body)).await;
                assert_eq!(response.status(),200);
                let response=String::from_utf8(to_bytes(response.into_body(),MAX_HTTP_BODY).await.unwrap().to_vec()).unwrap();
                if response.contains("cursor-output-fixture") {break;}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.unwrap();
        stop.send(true).unwrap();
        timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        for (action, allowed) in [("logs:GetLogEvents", false), ("logs:*", true)] {
            let policy = serde_json::json!({"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":action,"Resource":"*"}}).to_string();
            let policy = locallycloud_iam_sts::query::QueryRequest::parse(
                format!(
                    "RoleName=execution&PolicyName=test&PolicyDocument={}",
                    encoded(&policy)
                )
                .as_bytes(),
            );
            locallycloud_iam_sts::iam::put_inline_policy(
                &iam_store,
                "000000000000",
                locallycloud_iam_sts::iam::Entity::Role,
                &policy,
            )
            .unwrap();
            let result = sink
                .append(
                    log_scope.clone(),
                    log_target.clone(),
                    vec![ProducerLogEvent {
                        timestamp_ms: (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
                            as i64,
                        message: "execution-policy-recovery".into(),
                    }],
                    log_context.clone(),
                )
                .await;
            if allowed {
                assert_eq!(result.unwrap().stored_events, 1);
            } else {
                assert!(
                    matches!(result, Err(locallycloud_core::integration::logs::SinkError::Rejected(message)) if message.contains("AccessDenied")),
                    "Revoked execution permissions must reject the native producer"
                );
            }
        }
        let streams_request =
            signed_request(&credentials, "DynamoDBStreams_20120810.ListStreams", "{}");
        assert!(evaluator.verify_sigv4(
            "000000000000",
            streams_request.method(),
            streams_request.uri(),
            streams_request.headers(),
            b"{}",
            "us-east-1",
            "dynamodb"
        ));
        let denied = prepared.state.sdk_request(streams_request).await;
        assert_eq!(
            denied.status(),
            403,
            "Unaudited aliases must not inherit DynamoDB endpoint authority"
        );
        assert!(
            String::from_utf8_lossy(&to_bytes(denied.into_body(), 4096).await.unwrap())
                .contains("audited native IAM contract")
        );
        native(&registry,"ec2",format!("Action=CreateVpcEndpoint&VpcId={vpc}&ServiceName=com.amazonaws.us-east-1.ssm&VpcEndpointType=Interface&SubnetId.1={subnet}&SecurityGroupId.1={endpoint_group}&PrivateDnsEnabled=true"),None).await;
        native(
            &registry,
            "ssm",
            r#"{"Name":"/guest/audited","Value":"unchanged","Type":"String"}"#.into(),
            Some("AmazonSSM.PutParameter"),
        )
        .await;
        let policy=serde_json::json!({"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["dynamodb:*","ssm:*"],"Resource":"*"}}).to_string();
        let policy = locallycloud_iam_sts::query::QueryRequest::parse(
            format!(
                "RoleName=task&PolicyName=test&PolicyDocument={}",
                encoded(&policy)
            )
            .as_bytes(),
        );
        locallycloud_iam_sts::iam::put_inline_policy(
            &iam_store,
            "000000000000",
            locallycloud_iam_sts::iam::Entity::Role,
            &policy,
        )
        .unwrap();
        for (target, body) in [
            (
                "AmazonSSM.PutParameter",
                r#"{"Name":"/guest/audited","Value":"forbidden","Type":"String","Overwrite":true}"#,
            ),
            ("AmazonSSM.DeleteParameter", r#"{"Name":"/guest/audited"}"#),
            ("AmazonSSM.DescribeParameters", "{}"),
            ("AmazonSSM.GetParametersByPath", r#"{"Path":"/guest"}"#),
            (
                "AmazonSSM.AddTagsToResource",
                r#"{"ResourceType":"Parameter","ResourceId":"/guest/audited","Tags":[{"Key":"denied","Value":"denied"}]}"#,
            ),
        ] {
            let request = signed_request(&credentials, target, body);
            assert!(evaluator.verify_sigv4(
                "000000000000",
                request.method(),
                request.uri(),
                request.headers(),
                body.as_bytes(),
                "us-east-1",
                "ssm"
            ));
            let denied = prepared.state.sdk_request(request).await;
            assert_eq!(
                denied.status(),
                403,
                "{target} must fail closed despite genuine session and ssm:* permission"
            );
            assert!(
                String::from_utf8_lossy(&to_bytes(denied.into_body(), 4096).await.unwrap())
                    .contains("audited native IAM contract")
            );
        }
        for (target, body) in [
            ("AmazonSSM.GetParameter", r#"{"Name":"/guest/audited"}"#),
            ("AmazonSSM.GetParameters", r#"{"Names":["/guest/audited"]}"#),
        ] {
            let response = prepared
                .state
                .sdk_request(signed_request(&credentials, target, body))
                .await;
            assert_eq!(
                response.status(),
                200,
                "{target} remains in the audited contract"
            );
            let body =
                String::from_utf8(to_bytes(response.into_body(), 4096).await.unwrap().to_vec())
                    .unwrap();
            assert!(body.contains("unchanged"));
            assert!(!body.contains("forbidden"));
        }
    }
}
