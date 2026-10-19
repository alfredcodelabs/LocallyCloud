use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::Mutex;
use uuid::Uuid;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use http::{HeaderMap, Method};
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::ServiceRoleAuthorizationRequest;
use locallycloud_core::integration::identity::{CallerIdentity, IdentityPropagator};
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{AwsProtocol, ServiceRegistry};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::TARGET_PREFIX;

const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const MAX_BODY: usize = 1024 * 1024;
#[path = "authorization.rs"]
mod authorization;
#[path = "persistence.rs"]
mod persistence;
use persistence::{PersistError, Persistence};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct Scope {
    account: String,
    region: String,
}
impl Scope {
    fn new(request: &ServiceRequest) -> Self {
        Self {
            account: request.account_id.clone(),
            region: request.region.clone(),
        }
    }
    fn cluster_arn(&self, name: &str) -> String {
        format!(
            "arn:aws:ecs:{}:{}:cluster/{name}",
            self.region, self.account
        )
    }
    fn task_arn(&self, family: &str, revision: usize) -> String {
        format!(
            "arn:aws:ecs:{}:{}:task-definition/{family}:{revision}",
            self.region, self.account
        )
    }
}

#[derive(Default)]
struct State {
    clusters: BTreeMap<(Scope, String), bool>,
    definitions: BTreeMap<(Scope, String), Vec<Value>>,
    tasks: BTreeMap<(Scope, String), TaskRecord>,
    task_tokens: BTreeMap<(Scope, String), (String, String)>,
    services: BTreeMap<(Scope, String, String), ServiceRecord>,
}

#[derive(Clone)]
pub struct TaskLaunch {
    pub task_id: String,
    pub container_name: String,
    pub image: String,
    pub command: Vec<String>,
    pub environment: HashMap<String, String>,
    pub memory_mb: u32,
    pub cpu: u32,
    pub subnets: Vec<String>,
    pub security_groups: Vec<String>,
    pub account: String,
    pub region: String,
    pub port: u16,
    pub task_role_arn: Option<String>,
    pub execution_role_arn: Option<String>,
    pub log_configuration: Option<TaskLogConfiguration>,
}

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskLogConfiguration {
    pub log_driver: String,
    pub options: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize, serde::Serialize)]
pub struct TaskNetworkInfo {
    pub eni_id: String,
    pub private_ip: std::net::Ipv4Addr,
    pub subnet_id: String,
}

#[async_trait]
pub trait TaskRuntime: Send + Sync {
    fn supports_execution_identity(&self) -> bool {
        false
    }
    fn supports_awslogs(&self) -> bool {
        false
    }
    async fn preflight(
        &self,
        image: &str,
        account: &str,
        region: &str,
        subnets: &[String],
        security_groups: &[String],
    ) -> Result<(), String>;
    async fn start(&self, task: &TaskLaunch) -> Result<TaskNetworkInfo, String>;
    async fn stop(&self, task_id: &str) -> Result<(), String>;
    async fn running(&self, task_id: &str) -> bool;
}

#[derive(Clone, Deserialize, serde::Serialize)]
struct TaskRecord {
    cluster: String,
    definition: String,
    container: String,
    status: String,
    network: Option<TaskNetworkInfo>,
    stopped_reason: Option<String>,
    #[serde(skip, default = "std::time::Instant::now")]
    started_at: std::time::Instant,
    #[serde(skip)]
    drain_until: Option<std::time::Instant>,
    #[serde(default)]
    service_name: Option<String>,
}

#[derive(Clone, Deserialize, serde::Serialize)]
struct ServiceRecord {
    cluster: String,
    name: String,
    definition: String,
    desired: usize,
    network: NetworkConfiguration,
    #[serde(skip)]
    tasks: Vec<String>,
    status: String,
    load_balancers: Vec<LoadBalancer>,
    health_grace_seconds: u32,
    #[serde(skip)]
    last_error: Option<String>,
}

pub(crate) struct EcsHandler {
    state: Arc<Mutex<State>>,
    runtime: Option<Arc<dyn TaskRuntime>>,
    reconcile_lock: Arc<tokio::sync::Mutex<()>>,
    dispatcher: Option<Arc<InternalDispatcher>>,
    registry: std::sync::Weak<ServiceRegistry>,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
    persistence: Option<Arc<Persistence>>,
    launch_lock: Arc<tokio::sync::Mutex<()>>,
}
impl EcsHandler {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::with_runtime(None)
    }
    pub(crate) fn with_runtime(runtime: Option<Arc<dyn TaskRuntime>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            runtime,
            reconcile_lock: Arc::new(tokio::sync::Mutex::new(())),
            dispatcher: None,
            registry: std::sync::Weak::new(),
            worker: Mutex::new(None),
            persistence: None,
            launch_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
    pub(crate) fn with_registry(
        runtime: Option<Arc<dyn TaskRuntime>>,
        registry: std::sync::Weak<ServiceRegistry>,
    ) -> Self {
        let mut handler = Self::with_runtime(runtime);
        handler.registry = registry;
        handler
    }
    pub(crate) fn with_dispatcher(
        runtime: Option<Arc<dyn TaskRuntime>>,
        dispatcher: Arc<InternalDispatcher>,
        registry: std::sync::Weak<ServiceRegistry>,
    ) -> Self {
        let mut handler = Self::with_registry(runtime, registry);
        handler.dispatcher = Some(dispatcher);
        handler
    }
    pub(crate) async fn with_state(
        runtime: Option<Arc<dyn TaskRuntime>>,
        registry: std::sync::Weak<ServiceRegistry>,
        database: Arc<locallycloud_state::StateDb>,
    ) -> Result<Self, PersistError> {
        let (store, state) = tokio::task::spawn_blocking(move || -> Result<_, PersistError> {
            let store = Arc::new(Persistence::new(
                database,
                locallycloud_state::StateCipher::from_env()?,
            )?);
            let state = store.restore()?;
            Ok((store, state))
        })
        .await??;
        let mut handler = Self::with_registry(runtime, registry);
        handler.state = Arc::new(Mutex::new(state));
        handler.persistence = Some(store);
        Ok(handler)
    }
    fn fork(&self) -> Self {
        Self {
            state: self.state.clone(),
            runtime: self.runtime.clone(),
            reconcile_lock: self.reconcile_lock.clone(),
            dispatcher: self.dispatcher.clone(),
            registry: self.registry.clone(),
            worker: Mutex::new(None),
            persistence: self.persistence.clone(),
            launch_lock: self.launch_lock.clone(),
        }
    }
    async fn persist(
        &self,
        scope: &Scope,
        kind: &str,
        name: &str,
        value: Option<Value>,
    ) -> Result<(), EcsError> {
        let Some(store) = self.persistence.clone() else {
            return Ok(());
        };
        let scope = scope.clone();
        let kind = kind.to_owned();
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || match value {
            Some(value) => store.save(&scope, &kind, &name, &value),
            None => store.delete(&scope, &kind, &name),
        })
        .await
        .map_err(|_| EcsError::Internal)?
        .map_err(|_| EcsError::Internal)
    }
    fn persist_sync(
        &self,
        scope: &Scope,
        kind: &str,
        name: &str,
        value: &Value,
    ) -> Result<(), EcsError> {
        if let Some(store) = &self.persistence {
            store
                .save(scope, kind, name, value)
                .map_err(|_| EcsError::Internal)?;
        }
        Ok(())
    }
    pub(crate) fn start_reconciler(&self) {
        let Ok(mut worker) = self.worker.lock() else {
            return;
        };
        if worker.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let handler = Self {
            state: self.state.clone(),
            runtime: self.runtime.clone(),
            reconcile_lock: self.reconcile_lock.clone(),
            dispatcher: self.dispatcher.clone(),
            registry: self.registry.clone(),
            worker: Mutex::new(None),
            persistence: self.persistence.clone(),
            launch_lock: self.launch_lock.clone(),
        };
        *worker = Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let _guard = handler.reconcile_lock.lock().await;
                let keys: Vec<_> = match handler.state.lock() {
                    Ok(state) => state.services.keys().cloned().collect(),
                    Err(_) => return,
                };
                if keys.is_empty() {
                    return;
                }
                for key in keys {
                    // An unsuccessful pass is retried; partial work remains recorded for cleanup.
                    if let Err(error) = handler.reconcile_service(&key).await {
                        if let Ok(mut state) = handler.state.lock() {
                            if let Some(service) = state.services.get_mut(&key) {
                                service.last_error = Some(AwsError::from(error).message);
                            }
                        }
                    }
                }
            }
        }));
    }
    async fn query(
        &self,
        scope: &Scope,
        service: &str,
        action: &str,
        fields: &[(&str, String)],
    ) -> Result<String, EcsError> {
        let dispatcher = self
            .dispatcher
            .clone()
            .or_else(|| {
                self.registry
                    .upgrade()
                    .and_then(|registry| registry.internal_dispatcher())
            })
            .ok_or_else(|| EcsError::Client("Service integration is unavailable".into()))?;
        let encode = |value: &str| {
            value
                .bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect::<String>()
        };
        let mut body = format!(
            "Action={action}&Version={}",
            if service == "ec2" {
                "2016-11-15"
            } else {
                "2015-12-01"
            }
        );
        for (name, value) in fields {
            body.push_str(&format!("&{name}={}", encode(value)));
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            "application/x-www-form-urlencoded"
                .parse()
                .map_err(|_| EcsError::Internal)?,
        );
        headers.insert(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=local/19700101/{}/{service}/aws4_request",
                scope.region
            )
            .parse()
            .map_err(|_| EcsError::Internal)?,
        );
        let mut identity = CallerIdentity::ServicePrincipal {
            service: "ecs".into(),
        };
        if let Some(evaluator) = self
            .registry
            .upgrade()
            .and_then(|registry| {
                registry
                    .authorization_evaluator(&locallycloud_core::registry::ServiceName::new("iam"))
            })
            .filter(|evaluator| evaluator.strict_sigv4_required())
        {
            let role_arn = format!(
                "arn:aws:iam::{}:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS",
                scope.account
            );
            let resource = if action.starts_with("Describe") {
                "*".into()
            } else {
                fields
                    .iter()
                    .find(|(name, _)| {
                        matches!(*name, "TargetGroupArn" | "TargetGroupArns.member.1")
                    })
                    .map(|(_, value)| value.clone())
                    .unwrap_or_else(|| "*".into())
            };
            evaluator
                .authorize_service_role_execution(ServiceRoleAuthorizationRequest {
                    source_arn: None,
                    caller: RequestIdentity {
                        account_id: scope.account.clone(),
                        access_key_id: None,
                        arn: None,
                    },
                    role_arn: role_arn.clone(),
                    service_principal: "ecs.amazonaws.com".into(),
                    action: format!("{service}:{action}"),
                    resource,
                })
                .map_err(|_| EcsError::AccessDenied)?;
            identity = CallerIdentity::AssumedRole {
                role_arn,
                session_name: "ecs-service".into(),
            };
        }
        IdentityPropagator::attach(&mut headers, &identity);
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dispatcher.dispatch_scoped(
                &Method::POST,
                &http::Uri::from_static("/"),
                &headers,
                bytes::Bytes::from(body),
                &Uuid::new_v4().to_string(),
                &scope.account,
                &scope.region,
            ),
        )
        .await
        .map_err(|_| EcsError::Client("Service integration timed out".into()))?;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), MAX_BODY)
            .await
            .map_err(|_| EcsError::Client("Invalid integration response".into()))?;
        if !status.is_success() {
            return Err(EcsError::Client(format!("{action} failed ({status})")));
        }
        String::from_utf8(body.to_vec()).map_err(|_| EcsError::Internal)
    }
    async fn target(
        &self,
        scope: &Scope,
        lb: &LoadBalancer,
        task: &TaskRecord,
        register: bool,
    ) -> Result<(), EcsError> {
        let network = task.network.as_ref().ok_or(EcsError::Internal)?;
        self.query(
            scope,
            "elasticloadbalancing",
            if register {
                "RegisterTargets"
            } else {
                "DeregisterTargets"
            },
            &[
                ("TargetGroupArn", lb.target_group_arn.clone()),
                ("Targets.member.1.Id", network.private_ip.to_string()),
                ("Targets.member.1.Port", lb.container_port.to_string()),
            ],
        )
        .await?;
        Ok(())
    }
    fn operation<'a>(&self, request: &'a ServiceRequest) -> Result<&'a str, EcsError> {
        if request.method != Method::POST
            || request.uri.path() != "/"
            || request.uri.query().is_some()
        {
            return Err(EcsError::UnknownOperation);
        }
        validate_content_type(&request.headers)?;
        if request.body.len() > MAX_BODY {
            return Err(EcsError::Client("Request body is too large".into()));
        }
        request
            .headers
            .get("x-amz-target")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix(TARGET_PREFIX))
            .and_then(|v| v.strip_prefix('.'))
            .ok_or(EcsError::UnknownOperation)
    }
    fn authorize_image_execution(
        &self,
        scope: &Scope,
        role: Option<&str>,
        image: &str,
    ) -> Result<(), EcsError> {
        let evaluator = self.registry.upgrade().and_then(|registry| {
            registry.authorization_evaluator(&locallycloud_core::registry::ServiceName::new("iam"))
        });
        let Some(role) = role else {
            return if evaluator
                .as_ref()
                .is_some_and(|evaluator| evaluator.strict_sigv4_required())
            {
                Err(EcsError::AccessDenied)
            } else {
                Ok(())
            };
        };
        let evaluator = evaluator.ok_or(EcsError::AccessDenied)?;
        let prefix = format!("{}.dkr.ecr.{}.amazonaws.com/", scope.account, scope.region);
        let repository = image
            .strip_prefix(&prefix)
            .and_then(|path| path.rsplit_once(':'))
            .filter(|(repository, tag)| {
                !repository.is_empty()
                    && !tag.is_empty()
                    && !repository.contains("..")
                    && !tag.contains('/')
            })
            .map(|(repository, _)| repository)
            .ok_or_else(|| {
                EcsError::Client(
                    "Execution-role image must use this account and region ECR repository".into(),
                )
            })?;
        let resource = format!(
            "arn:aws:ecr:{}:{}:repository/{repository}",
            scope.region, scope.account
        );
        for (action, resource) in [
            ("ecr:GetAuthorizationToken", "*"),
            ("ecr:BatchGetImage", resource.as_str()),
            ("ecr:GetDownloadUrlForLayer", resource.as_str()),
        ] {
            evaluator
                .authorize_service_role_execution(ServiceRoleAuthorizationRequest {
                    source_arn: None,
                    caller: RequestIdentity {
                        account_id: scope.account.clone(),
                        access_key_id: None,
                        arn: None,
                    },
                    role_arn: role.into(),
                    service_principal: "ecs-tasks.amazonaws.com".into(),
                    action: action.into(),
                    resource: resource.into(),
                })
                .map_err(|_| EcsError::AccessDenied)?;
        }
        Ok(())
    }
    fn authorize_roles<'a>(
        &self,
        request: &ServiceRequest,
        roles: impl Iterator<Item = &'a str>,
    ) -> Result<(), EcsError> {
        for role in roles {
            let prefix = format!("arn:aws:iam::{}:role/", request.account_id);
            if !role.starts_with(&prefix) || role.len() <= prefix.len() || role.len() > 2048 {
                return Err(EcsError::Client("Role must belong to this account".into()));
            }
            let evaluator = self
                .registry
                .upgrade()
                .and_then(|registry| {
                    registry.authorization_evaluator(
                        &locallycloud_core::registry::ServiceName::new("iam"),
                    )
                })
                .ok_or(EcsError::AccessDenied)?;
            evaluator
                .authorize_service_role_assignment(ServiceRoleAuthorizationRequest {
                    source_arn: None,
                    caller: RequestIdentity {
                        account_id: request.account_id.clone(),
                        access_key_id: request
                            .headers
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .and_then(RequestIdentity::access_key_from_authorization),
                        arn: None,
                    },
                    role_arn: role.into(),
                    service_principal: "ecs-tasks.amazonaws.com".into(),
                    action: "sts:AssumeRole".into(),
                    resource: role.into(),
                })
                .map_err(|_| EcsError::AccessDenied)?;
        }
        Ok(())
    }
    fn authorize_definition(
        &self,
        request: &ServiceRequest,
        identifier: &str,
    ) -> Result<String, EcsError> {
        let result = self.describe_task_definition(
            DescribeTaskDefinition {
                task_definition: identifier.into(),
                include: None,
            },
            &Scope::new(request),
        )?;
        let definition = &result["taskDefinition"];
        self.authorize_roles(
            request,
            [
                definition["taskRoleArn"].as_str(),
                definition["executionRoleArn"].as_str(),
            ]
            .into_iter()
            .flatten(),
        )?;
        definition["taskDefinitionArn"]
            .as_str()
            .map(str::to_owned)
            .ok_or(EcsError::Internal)
    }
    fn process(&self, request: &ServiceRequest) -> Result<Value, EcsError> {
        let target = self.operation(request)?;
        let scope = Scope::new(request);
        match target {
            "CreateCluster" => self.create_cluster(decode(&request.body)?, &scope),
            "DescribeClusters" => self.describe_clusters(decode(&request.body)?, &scope),
            "ListClusters" => self.list_clusters(decode(&request.body)?, &scope),
            "DeleteCluster" => self.delete_cluster(decode(&request.body)?, &scope),
            "RegisterTaskDefinition" => {
                let input: RegisterTaskDefinition = decode(&request.body)?;
                self.authorize_roles(
                    request,
                    [
                        input.task_role_arn.as_deref(),
                        input.execution_role_arn.as_deref(),
                    ]
                    .into_iter()
                    .flatten(),
                )?;
                self.register_task_definition(input, &scope)
            }
            "DeregisterTaskDefinition" => {
                self.deregister_task_definition(decode(&request.body)?, &scope)
            }
            "DescribeTaskDefinition" => {
                self.describe_task_definition(decode(&request.body)?, &scope)
            }
            _ => Err(EcsError::UnknownOperation),
        }
    }
    async fn process_async(&self, request: &ServiceRequest) -> Result<Value, EcsError> {
        let operation = self.operation(request)?;
        if !matches!(operation, "RunTask" | "CreateService") {
            self.authorize_operator(request, None)?;
        }
        match operation {
            "RunTask" => {
                let _guard = self.reconcile_lock.lock().await;
                let mut input: RunTask = decode(&request.body)?;
                input.resolved_definition =
                    Some(self.authorize_definition(request, &input.task_definition)?);
                self.authorize_operator(request, input.resolved_definition.as_deref())?;
                self.run_task(input, &Scope::new(request)).await
            }
            "DescribeTasks" => {
                self.describe_tasks(decode(&request.body)?, &Scope::new(request))
                    .await
            }
            "StopTask" => {
                let _guard = self.reconcile_lock.lock().await;
                self.stop_task(decode(&request.body)?, &Scope::new(request))
                    .await
            }
            "CreateService" => {
                let mut input: CreateService = decode(&request.body)?;
                input.task_definition =
                    self.authorize_definition(request, &input.task_definition)?;
                self.authorize_operator(request, Some(&input.task_definition))?;
                self.create_service(input, &Scope::new(request)).await
            }
            "DescribeServices" => {
                self.describe_services(decode(&request.body)?, &Scope::new(request))
                    .await
            }
            "UpdateService" => {
                self.update_service(decode(&request.body)?, &Scope::new(request))
                    .await
            }
            "DeleteService" => {
                self.delete_service(decode(&request.body)?, &Scope::new(request))
                    .await
            }
            "ListTasks" => self.list_tasks(decode(&request.body)?, &Scope::new(request)),
            _ => {
                if self.persistence.is_none() {
                    return self.process(request);
                }
                let _guard = self.reconcile_lock.lock().await;
                let handler = self.fork();
                let request = request.clone();
                tokio::task::spawn_blocking(move || handler.process(&request))
                    .await
                    .map_err(|_| EcsError::Internal)?
            }
        }
    }
    async fn run_task(&self, input: RunTask, scope: &Scope) -> Result<Value, EcsError> {
        let _launch_guard = self.launch_lock.lock().await;
        if input.launch_type.as_deref() != Some("FARGATE") || input.count.unwrap_or(1) != 1 {
            return Err(EcsError::Client(
                "Only one FARGATE task is supported".into(),
            ));
        }
        let network = input
            .network_configuration
            .and_then(|v| v.awsvpc_configuration)
            .ok_or_else(|| EcsError::Client("Fargate requires awsvpcConfiguration".into()))?;
        if network.subnets.len() != 1
            || network
                .assign_public_ip
                .as_deref()
                .is_some_and(|v| v != "DISABLED")
        {
            return Err(EcsError::Client("One private subnet is required".into()));
        }
        let cluster = cluster_name(scope, input.cluster.as_deref().unwrap_or("default"))?;
        let (family, revision) = task_identifier(
            scope,
            input
                .resolved_definition
                .as_deref()
                .unwrap_or(&input.task_definition),
        )?;
        let (definition, container) = {
            let state = self.state.lock().map_err(|_| EcsError::Internal)?;
            if state.clusters.get(&(scope.clone(), cluster.clone())) != Some(&true) {
                return Err(EcsError::ClusterNotFound(cluster));
            }
            let definitions = state
                .definitions
                .get(&(scope.clone(), family))
                .ok_or_else(|| EcsError::Client("Task definition was not found".into()))?;
            let definition = revision
                .and_then(|n| definitions.get(n.saturating_sub(1)))
                .or_else(|| {
                    if revision.is_none() {
                        definitions
                            .iter()
                            .rev()
                            .find(|definition| definition["status"] == "ACTIVE")
                    } else {
                        None
                    }
                })
                .ok_or_else(|| EcsError::Client("Task definition was not found".into()))?
                .clone();
            if definition["status"] != "ACTIVE" && !input.service_launch {
                return Err(EcsError::Client("Task definition is inactive".into()));
            }
            let containers = definition["containerDefinitions"]
                .as_array()
                .ok_or(EcsError::Internal)?;
            if containers.len() != 1 {
                return Err(EcsError::Client(
                    "Only one container per task is supported".into(),
                ));
            }
            (definition.clone(), containers[0].clone())
        };
        let token_fingerprint = format!(
            "{}|{}|{}|{}|{:?}",
            cluster,
            input.task_definition,
            network.subnets.join(","),
            network
                .security_groups
                .as_ref()
                .map(|v| v.join(","))
                .unwrap_or_default(),
            input.launch_type
        );
        if let Some(token) = input.client_token.as_deref() {
            let state = self.state.lock().map_err(|_| EcsError::Internal)?;
            if let Some((prior, arn)) = state.task_tokens.get(&(scope.clone(), token.to_owned())) {
                if prior != &token_fingerprint {
                    return Err(EcsError::Client(
                        "Client token reused with different parameters".into(),
                    ));
                }
                if let Some(record) = state.tasks.get(&(scope.clone(), arn.clone())) {
                    return Ok(json!({"tasks":[task_value(arn, scope, record)],"failures":[]}));
                }
            }
        }
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| EcsError::Client("Fargate runtime is unavailable".into()))?;
        let ports = container["portMappings"]
            .as_array()
            .ok_or_else(|| EcsError::Client("One TCP port mapping is required".into()))?;
        if ports.len() != 1
            || ports[0]["protocol"]
                .as_str()
                .is_some_and(|value| value != "tcp")
        {
            return Err(EcsError::Client("One TCP port mapping is required".into()));
        }
        let port = ports[0]["containerPort"]
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| EcsError::Client("Invalid container port".into()))?;
        let task_id = Uuid::new_v4().to_string();
        let image = container["image"]
            .as_str()
            .ok_or(EcsError::Internal)?
            .to_owned();
        let command = container["entryPoint"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(container["command"].as_array().into_iter().flatten())
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let environment = container["environment"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| {
                Some((
                    e["name"].as_str()?.to_owned(),
                    e["value"].as_str()?.to_owned(),
                ))
            })
            .collect();
        let task = TaskLaunch {
            task_id: task_id.clone(),
            container_name: container["name"]
                .as_str()
                .ok_or(EcsError::Internal)?
                .to_owned(),
            image,
            command,
            environment,
            memory_mb: definition["memory"]
                .as_str()
                .and_then(|v| v.parse().ok())
                .ok_or(EcsError::Internal)?,
            cpu: definition["cpu"]
                .as_str()
                .and_then(|v| v.parse().ok())
                .ok_or(EcsError::Internal)?,
            subnets: network.subnets,
            security_groups: network.security_groups.unwrap_or_default(),
            account: scope.account.clone(),
            region: scope.region.clone(),
            port,
            task_role_arn: definition["taskRoleArn"].as_str().map(str::to_owned),
            execution_role_arn: definition["executionRoleArn"].as_str().map(str::to_owned),
            log_configuration: container
                .get("logConfiguration")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| EcsError::Internal)?,
        };
        if (task.task_role_arn.is_some() || task.execution_role_arn.is_some())
            && !runtime.supports_execution_identity()
        {
            return Err(EcsError::Client(
                "Configured Fargate runtime does not support task execution identities".into(),
            ));
        }
        if task.log_configuration.is_some() && !runtime.supports_awslogs() {
            return Err(EcsError::Client(
                "Configured Fargate runtime does not support awslogs".into(),
            ));
        }
        self.authorize_image_execution(scope, task.execution_role_arn.as_deref(), &task.image)?;
        let arn = format!(
            "arn:aws:ecs:{}:{}:task/{}/{}",
            scope.region, scope.account, cluster, task_id
        );
        let mut record = TaskRecord {
            cluster: cluster.clone(),
            definition: definition["taskDefinitionArn"]
                .as_str()
                .ok_or(EcsError::Internal)?
                .to_owned(),
            container: container["name"]
                .as_str()
                .ok_or(EcsError::Internal)?
                .to_owned(),
            status: "PENDING".into(),
            network: None,
            stopped_reason: None,
            started_at: std::time::Instant::now(),
            drain_until: None,
            service_name: None,
        };
        if let Some(token) = input.client_token.as_deref() {
            let mut interrupted = record.clone();
            interrupted.status = "STOPPED".into();
            interrupted.stopped_reason = Some(
                "Task execution was interrupted by emulator restart; outcome is unknown".into(),
            );
            self.persist(
                scope,
                "3token",
                token,
                Some(json!([token_fingerprint, arn, interrupted])),
            )
            .await?;
        }
        {
            let mut state = self.state.lock().map_err(|_| EcsError::Internal)?;
            if state.clusters.get(&(scope.clone(), cluster.clone())) != Some(&true) {
                return Err(EcsError::ClusterNotFound(cluster));
            }
            if let Some(token) = input.client_token.as_deref() {
                if let Some((prior, prior_arn)) =
                    state.task_tokens.get(&(scope.clone(), token.to_owned()))
                {
                    if prior != &token_fingerprint {
                        return Err(EcsError::Client(
                            "Client token reused with different parameters".into(),
                        ));
                    }
                    if let Some(prior_task) = state.tasks.get(&(scope.clone(), prior_arn.clone())) {
                        return Ok(
                            json!({"tasks":[task_value(prior_arn, scope, prior_task)],"failures":[]}),
                        );
                    }
                }
                state.task_tokens.insert(
                    (scope.clone(), token.to_owned()),
                    (token_fingerprint, arn.clone()),
                );
            }
            state
                .tasks
                .insert((scope.clone(), arn.clone()), record.clone());
        }
        if let Err(error) =
            self.authorize_image_execution(scope, task.execution_role_arn.as_deref(), &task.image)
        {
            if let Some(record) = self
                .state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .tasks
                .get_mut(&(scope.clone(), arn.clone()))
            {
                record.status = "STOPPED".into();
                record.stopped_reason =
                    Some("Execution role does not authorize the image pull".into());
            }
            return Err(error);
        }
        let network_info = match runtime.start(&task).await {
            Ok(network_info) => network_info,
            Err(reason) => {
                let cleanup = runtime.stop(&task_id).await;
                record.status = if cleanup.is_ok() {
                    "STOPPED"
                } else {
                    "STOPPING"
                }
                .into();
                let reason = match cleanup {
                    Ok(()) => reason,
                    Err(error) => format!("{reason}; cleanup pending for {task_id}: {error}"),
                };
                record.stopped_reason = Some(reason.clone());
                self.state
                    .lock()
                    .map_err(|_| EcsError::Internal)?
                    .tasks
                    .insert((scope.clone(), arn.clone()), record.clone());
                return Ok(
                    json!({"tasks":[],"failures":[{"arn":arn,"reason":"RESOURCE:INIT_ERROR","detail":reason}]}),
                );
            }
        };
        record.network = Some(network_info);
        let mut state = self.state.lock().map_err(|_| EcsError::Internal)?;
        // StopTask may have requested teardown while the runtime was starting.
        if let Some(current) = state.tasks.get(&(scope.clone(), arn.clone())) {
            if matches!(current.status.as_str(), "STOPPING" | "STOPPED") {
                return Ok(json!({"tasks":[task_value(&arn, scope, current)],"failures":[]}));
            }
        }
        record.status = "RUNNING".into();
        state
            .tasks
            .insert((scope.clone(), arn.clone()), record.clone());
        Ok(json!({"tasks":[task_value(&arn, scope, &record)],"failures":[]}))
    }
    async fn describe_tasks(&self, input: DescribeTasks, scope: &Scope) -> Result<Value, EcsError> {
        if input.tasks.len() > 100 {
            return Err(EcsError::Client("Too many tasks".into()));
        }
        let cluster = cluster_name(scope, input.cluster.as_deref().unwrap_or("default"))?;
        let mut tasks = Vec::new();
        let mut failures = Vec::new();
        for id in input.tasks {
            let arn = if id.starts_with("arn:") {
                id.clone()
            } else {
                format!(
                    "arn:aws:ecs:{}:{}:task/{}/{}",
                    scope.region, scope.account, cluster, id
                )
            };
            let record = self
                .state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .tasks
                .get(&(scope.clone(), arn.clone()))
                .cloned();
            match record {
                Some(mut record) if record.cluster == cluster => {
                    if record.status == "RUNNING" {
                        // Reconciled below without holding the state lock.
                        let task_id = arn.rsplit('/').next().unwrap_or("");
                        let runtime = self.runtime.as_ref().ok_or(EcsError::Internal)?;
                        if !runtime.running(task_id).await {
                            // Readback must not mark cleanup complete; the reconciler owns teardown.
                            record.status = "STOPPED".into();
                            record.stopped_reason = Some("Essential container exited".into());
                        }
                    }
                    tasks.push(task_value(&arn, scope, &record));
                }
                _ => failures.push(json!({"arn":id,"reason":"MISSING"})),
            }
        }
        Ok(json!({"tasks":tasks,"failures":failures}))
    }
    async fn stop_task(&self, input: StopTask, scope: &Scope) -> Result<Value, EcsError> {
        let cluster = cluster_name(scope, input.cluster.as_deref().unwrap_or("default"))?;
        let arn = if input.task.starts_with("arn:") {
            input.task
        } else {
            format!(
                "arn:aws:ecs:{}:{}:task/{}/{}",
                scope.region, scope.account, cluster, input.task
            )
        };
        let record = self
            .state
            .lock()
            .map_err(|_| EcsError::Internal)?
            .tasks
            .get(&(scope.clone(), arn.clone()))
            .cloned()
            .filter(|r| r.cluster == cluster)
            .ok_or_else(|| EcsError::Client("Task was not found".into()))?;
        let associations: Vec<_> = self
            .state
            .lock()
            .map_err(|_| EcsError::Internal)?
            .services
            .iter()
            .filter(|((s, _, _), service)| s == scope && service.tasks.contains(&arn))
            .flat_map(|(_, service)| service.load_balancers.clone())
            .collect();
        let mut record = record;
        if input._reason.is_some() {
            record.stopped_reason = input._reason.clone();
        }
        if !associations.is_empty() && record.network.is_some() && record.status != "STOPPED" {
            if record.drain_until.is_none() {
                let mut delay = 0;
                for lb in &associations {
                    let attributes = self
                        .query(
                            scope,
                            "elasticloadbalancing",
                            "DescribeTargetGroupAttributes",
                            &[("TargetGroupArn", lb.target_group_arn.clone())],
                        )
                        .await?;
                    let seconds = attributes
                        .split_once("<Key>deregistration_delay.timeout_seconds</Key>")
                        .and_then(|(_, suffix)| xml_text(suffix, "Value"))
                        .and_then(|value| value.parse::<u64>().ok())
                        .filter(|value| *value <= 3600)
                        .ok_or_else(|| {
                            EcsError::Client("Invalid target deregistration delay".into())
                        })?;
                    delay = delay.max(seconds);
                    self.target(scope, lb, &record, false).await?;
                }
                record.status = "STOPPING".into();
                record.drain_until =
                    Some(std::time::Instant::now() + std::time::Duration::from_secs(delay));
                self.state
                    .lock()
                    .map_err(|_| EcsError::Internal)?
                    .tasks
                    .insert((scope.clone(), arn.clone()), record.clone());
            }
            if record
                .drain_until
                .is_some_and(|deadline| deadline > std::time::Instant::now())
            {
                return Ok(json!({"task":task_value(&arn,scope,&record)}));
            }
        }
        if record.status != "STOPPED" {
            let mut stopping = record.clone();
            stopping.status = "STOPPING".into();
            self.state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .tasks
                .insert((scope.clone(), arn.clone()), stopping.clone());
            let task_id = arn.rsplit('/').next().unwrap_or("");
            if let Err(error) = self
                .runtime
                .as_ref()
                .ok_or(EcsError::Internal)?
                .stop(task_id)
                .await
            {
                stopping.stopped_reason = Some(format!("Cleanup pending for {task_id}: {error}"));
                self.state
                    .lock()
                    .map_err(|_| EcsError::Internal)?
                    .tasks
                    .insert((scope.clone(), arn.clone()), stopping);
                return Err(EcsError::Client(error));
            }
        }
        record.status = "STOPPED".into();
        if input._reason.is_some() {
            record.stopped_reason = input._reason;
        }
        {
            let mut state = self.state.lock().map_err(|_| EcsError::Internal)?;
            state
                .tasks
                .insert((scope.clone(), arn.clone()), record.clone());
            for service in state.services.values_mut() {
                service.tasks.retain(|task| task != &arn);
            }
        }
        Ok(json!({"task":task_value(&arn, scope, &record)}))
    }
    async fn create_service(&self, input: CreateService, scope: &Scope) -> Result<Value, EcsError> {
        let _guard = self.reconcile_lock.lock().await;
        valid_name(&input.service_name)?;
        if input.launch_type.as_deref() != Some("FARGATE") || input.desired_count > 2 {
            return Err(EcsError::Client(
                "Only FARGATE desiredCount 0..2 is supported".into(),
            ));
        }
        let cluster = cluster_name(scope, input.cluster.as_deref().unwrap_or("default"))?;
        let network = input
            .network_configuration
            .ok_or_else(|| EcsError::Client("Network configuration is required".into()))?;
        if network
            .awsvpc_configuration
            .as_ref()
            .is_none_or(|v| v.subnets.len() != 1)
        {
            return Err(EcsError::Client("One private subnet is required".into()));
        }
        let (family, revision) = task_identifier(scope, &input.task_definition)?;
        let (image, pinned_definition, container_name, container_port, execution_role) = {
            let state = self.state.lock().map_err(|_| EcsError::Internal)?;
            let definitions = state
                .definitions
                .get(&(scope.clone(), family))
                .ok_or_else(|| EcsError::Client("Task definition was not found".into()))?;
            let definition = revision
                .and_then(|n| definitions.get(n.saturating_sub(1)))
                .or_else(|| {
                    if revision.is_none() {
                        definitions
                            .iter()
                            .rev()
                            .find(|definition| definition["status"] == "ACTIVE")
                    } else {
                        None
                    }
                })
                .ok_or_else(|| EcsError::Client("Task definition was not found".into()))?;
            if definition["status"] != "ACTIVE" {
                return Err(EcsError::Client("Task definition is inactive".into()));
            }
            let containers = definition["containerDefinitions"]
                .as_array()
                .ok_or(EcsError::Internal)?;
            if containers.len() != 1
                || containers[0]["portMappings"]
                    .as_array()
                    .is_none_or(|ports| ports.len() != 1)
            {
                return Err(EcsError::Client(
                    "Service requires one container and TCP port".into(),
                ));
            }
            (
                containers[0]["image"]
                    .as_str()
                    .ok_or(EcsError::Internal)?
                    .to_owned(),
                definition["taskDefinitionArn"]
                    .as_str()
                    .ok_or(EcsError::Internal)?
                    .to_owned(),
                containers[0]["name"]
                    .as_str()
                    .ok_or(EcsError::Internal)?
                    .to_owned(),
                containers[0]["portMappings"][0]["containerPort"]
                    .as_u64()
                    .ok_or(EcsError::Internal)?,
                definition["executionRoleArn"].as_str().map(str::to_owned),
            )
        };
        let awsvpc = network
            .awsvpc_configuration
            .as_ref()
            .ok_or(EcsError::Internal)?;
        let health_grace_seconds = input.health_check_grace_period_seconds.unwrap_or(0);
        if health_grace_seconds > 300 {
            return Err(EcsError::Client(
                "Local health grace is limited to 300 seconds".into(),
            ));
        }
        let load_balancers = input.load_balancers.unwrap_or_default();
        if load_balancers.len() > 1 {
            return Err(EcsError::Client(
                "Only one target group is supported".into(),
            ));
        }
        for lb in &load_balancers {
            if lb.container_name != container_name
                || u64::from(lb.container_port) != container_port
                || !lb.target_group_arn.starts_with(&format!(
                    "arn:aws:elasticloadbalancing:{}:{}:targetgroup/",
                    scope.region, scope.account
                ))
            {
                return Err(EcsError::Client(
                    "Target group, container and port must match this task and scope".into(),
                ));
            }
            let group = self
                .query(
                    scope,
                    "elasticloadbalancing",
                    "DescribeTargetGroups",
                    &[("TargetGroupArns.member.1", lb.target_group_arn.clone())],
                )
                .await?;
            if !group.contains("<TargetType>ip</TargetType>")
                || !group.contains("<Protocol>HTTP</Protocol>")
            {
                return Err(EcsError::Client(
                    "Service requires an HTTP IP target group".into(),
                ));
            }
            if !group.contains("<LoadBalancerArns><member>") {
                return Err(EcsError::InvalidParameter(
                    "Target group must be associated with a load balancer listener".into(),
                ));
            }
            let subnet = self
                .query(
                    scope,
                    "ec2",
                    "DescribeSubnets",
                    &[(
                        "SubnetId.1",
                        awsvpc.subnets.first().ok_or(EcsError::Internal)?.clone(),
                    )],
                )
                .await?;
            let vpc = xml_text(&group, "VpcId").ok_or(EcsError::Internal)?;
            if xml_text(&subnet, "vpcId") != Some(vpc) {
                return Err(EcsError::Client(
                    "Target group and subnet must share a VPC".into(),
                ));
            }
        }
        self.authorize_image_execution(scope, execution_role.as_deref(), &image)?;
        self.runtime
            .as_ref()
            .ok_or_else(|| EcsError::Client("Fargate runtime is unavailable".into()))?
            .preflight(
                &image,
                &scope.account,
                &scope.region,
                &awsvpc.subnets,
                awsvpc.security_groups.as_deref().unwrap_or(&[]),
            )
            .await
            .map_err(EcsError::Client)?;
        let key = (scope.clone(), cluster.clone(), input.service_name.clone());
        {
            let state = self.state.lock().map_err(|_| EcsError::Internal)?;
            if state.clusters.get(&(scope.clone(), cluster.clone())) != Some(&true) {
                return Err(EcsError::ClusterNotFound(cluster));
            }
            if state.services.len() >= 64 {
                return Err(EcsError::Client("Local service capacity reached".into()));
            }
            if state.services.contains_key(&key) {
                return Err(EcsError::Client("Service already exists".into()));
            }
        }
        let service = ServiceRecord {
            cluster: cluster.clone(),
            name: input.service_name,
            definition: pinned_definition,
            desired: input.desired_count as usize,
            network,
            tasks: Vec::new(),
            status: "PROVISIONING".into(),
            load_balancers,
            health_grace_seconds,
            last_error: None,
        };
        self.persist(
            scope,
            "2service",
            &format!("{}/{}", service.cluster, service.name),
            Some(serde_json::to_value(&service).map_err(|_| EcsError::Internal)?),
        )
        .await?;
        self.state
            .lock()
            .map_err(|_| EcsError::Internal)?
            .services
            .insert(key.clone(), service);
        let result = match self.reconcile_service(&key).await {
            Ok(()) => {
                let mut active = self
                    .state
                    .lock()
                    .map_err(|_| EcsError::Internal)?
                    .services
                    .get(&key)
                    .cloned()
                    .ok_or(EcsError::Internal)?;
                active.status = "ACTIVE".into();
                match self
                    .persist(
                        scope,
                        "2service",
                        &format!("{}/{}", active.cluster, active.name),
                        Some(serde_json::to_value(&active).map_err(|_| EcsError::Internal)?),
                    )
                    .await
                {
                    Ok(()) => {
                        self.state
                            .lock()
                            .map_err(|_| EcsError::Internal)?
                            .services
                            .insert(key.clone(), active);
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            let mut draining = self
                .state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .services
                .get(&key)
                .cloned()
                .ok_or(EcsError::Internal)?;
            draining.desired = 0;
            draining.status = "DRAINING".into();
            // PROVISIONING is already durable and restores as cleanup-only if this write fails.
            self.state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .services
                .insert(key.clone(), draining.clone());
            let _cleanup_intent = self
                .persist(
                    scope,
                    "2service",
                    &format!("{}/{}", draining.cluster, draining.name),
                    Some(serde_json::to_value(&draining).map_err(|_| EcsError::Internal)?),
                )
                .await;
            // Never let a failed state write prevent teardown of processes started by this request.
            let _cleanup = self.reconcile_service(&key).await;
            return Err(error);
        }
        let state = self.state.lock().map_err(|_| EcsError::Internal)?;
        Ok(
            json!({"service":service_value(scope, state.services.get(&key).ok_or(EcsError::Internal)?)}),
        )
    }
    async fn describe_services(
        &self,
        input: DescribeServices,
        scope: &Scope,
    ) -> Result<Value, EcsError> {
        let _guard = self.reconcile_lock.lock().await;
        if input.services.len() > 10 {
            return Err(EcsError::Client("Too many services".into()));
        }
        let cluster = cluster_name(scope, input.cluster.as_deref().unwrap_or("default"))?;
        let mut services = Vec::new();
        let mut failures = Vec::new();
        for id in input.services {
            let name = service_name(scope, &cluster, &id)?;
            let key = (scope.clone(), cluster.clone(), name);
            if self
                .state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .services
                .contains_key(&key)
            {
                let state = self.state.lock().map_err(|_| EcsError::Internal)?;
                if let Some(service) = state.services.get(&key) {
                    services.push(service_value(scope, service));
                }
            } else {
                failures.push(json!({"arn":id,"reason":"MISSING"}));
            }
        }
        Ok(json!({"services":services,"failures":failures}))
    }
    async fn update_service(&self, input: UpdateService, scope: &Scope) -> Result<Value, EcsError> {
        let _guard = self.reconcile_lock.lock().await;
        let cluster = cluster_name(scope, input.cluster.as_deref().unwrap_or("default"))?;
        let name = service_name(scope, &cluster, &input.service)?;
        let key = (scope.clone(), cluster, name);
        let desired = input
            .desired_count
            .ok_or_else(|| EcsError::Client("desiredCount is required".into()))?;
        if desired > 2 {
            return Err(EcsError::Client(
                "Only desiredCount 0..2 is supported".into(),
            ));
        }
        let mut service = self
            .state
            .lock()
            .map_err(|_| EcsError::Internal)?
            .services
            .get(&key)
            .cloned()
            .ok_or_else(|| EcsError::Client("Service was not found".into()))?;
        if service.status != "ACTIVE" {
            return Err(EcsError::Client("Service is draining".into()));
        }
        service.desired = desired as usize;
        self.persist(
            scope,
            "2service",
            &format!("{}/{}", service.cluster, service.name),
            Some(serde_json::to_value(&service).map_err(|_| EcsError::Internal)?),
        )
        .await?;
        self.state
            .lock()
            .map_err(|_| EcsError::Internal)?
            .services
            .insert(key.clone(), service);
        self.reconcile_service(&key).await?;
        let state = self.state.lock().map_err(|_| EcsError::Internal)?;
        Ok(
            json!({"service":service_value(scope, state.services.get(&key).ok_or(EcsError::Internal)?)}),
        )
    }
    async fn delete_service(&self, input: DeleteService, scope: &Scope) -> Result<Value, EcsError> {
        let _guard = self.reconcile_lock.lock().await;
        let cluster = cluster_name(scope, input.cluster.as_deref().unwrap_or("default"))?;
        let name = service_name(scope, &cluster, &input.service)?;
        let key = (scope.clone(), cluster.clone(), name);
        let service = self
            .state
            .lock()
            .map_err(|_| EcsError::Internal)?
            .services
            .get(&key)
            .cloned()
            .ok_or_else(|| EcsError::Client("Service was not found".into()))?;
        if !input.force.unwrap_or(false) && !service.tasks.is_empty() {
            return Err(EcsError::Client(
                "Service must be scaled to zero before deletion".into(),
            ));
        }
        let mut draining = service.clone();
        draining.desired = 0;
        draining.status = "DRAINING".into();
        self.persist(
            scope,
            "2service",
            &format!("{}/{}", service.cluster, service.name),
            Some(serde_json::to_value(&draining).map_err(|_| EcsError::Internal)?),
        )
        .await?;
        self.state
            .lock()
            .map_err(|_| EcsError::Internal)?
            .services
            .insert(key.clone(), draining);
        for arn in &service.tasks {
            self.stop_task(
                StopTask {
                    cluster: Some(cluster.clone()),
                    task: arn.clone(),
                    _reason: None,
                },
                scope,
            )
            .await?;
        }
        let pending = self
            .state
            .lock()
            .map_err(|_| EcsError::Internal)?
            .services
            .get(&key)
            .cloned()
            .ok_or(EcsError::Internal)?;
        if !pending.tasks.is_empty() {
            return Ok(json!({"service":service_value(scope,&pending)}));
        }
        self.persist(
            scope,
            "2service",
            &format!("{}/{}", service.cluster, service.name),
            None,
        )
        .await?;
        self.state
            .lock()
            .map_err(|_| EcsError::Internal)?
            .services
            .remove(&key);
        let mut deleted = service;
        deleted.desired = 0;
        deleted.tasks.clear();
        deleted.status = "INACTIVE".into();
        Ok(json!({"service":service_value(scope, &deleted)}))
    }
    fn list_tasks(&self, input: ListTasks, scope: &Scope) -> Result<Value, EcsError> {
        let desired =
            DesiredTaskStatus::parse(input.desired_status.as_deref().unwrap_or("RUNNING"))?;
        let cluster = cluster_name(scope, input.cluster.as_deref().unwrap_or("default"))?;
        let service = input
            .service_name
            .as_deref()
            .map(|id| service_name(scope, &cluster, id))
            .transpose()?;
        let state = self.state.lock().map_err(|_| EcsError::Internal)?;
        if let Some(service) = &service {
            let exists =
                state
                    .services
                    .contains_key(&(scope.clone(), cluster.clone(), service.clone()));
            let recorded = state.tasks.iter().any(|((task_scope, _), task)| {
                task_scope == scope
                    && task.cluster == cluster
                    && task.service_name.as_deref() == Some(service)
            });
            if !exists && !recorded {
                return Err(EcsError::Client(
                    "Service task ownership is unavailable".into(),
                ));
            }
        }
        let tasks: Vec<_> = state
            .tasks
            .iter()
            .filter(|((task_scope, _), task)| {
                task_scope == scope
                    && task.cluster == cluster
                    && desired.matches(&task.status)
                    && service
                        .as_deref()
                        .is_none_or(|service| task.service_name.as_deref() == Some(service))
            })
            .map(|((_, arn), _)| arn.clone())
            .collect();
        Ok(json!({"taskArns":tasks}))
    }
    async fn reconcile_service(&self, key: &(Scope, String, String)) -> Result<(), EcsError> {
        let (scope, cluster, _) = key;
        let service = self
            .state
            .lock()
            .map_err(|_| EcsError::Internal)?
            .services
            .get(key)
            .cloned()
            .ok_or(EcsError::Internal)?;
        let runtime = self.runtime.as_ref().ok_or(EcsError::Internal)?;
        let mut active = service.tasks.clone();
        for arn in service.tasks {
            let record = self
                .state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .tasks
                .get(&(scope.clone(), arn.clone()))
                .cloned()
                .ok_or(EcsError::Internal)?;
            if record.status == "STOPPING" {
                self.stop_task(
                    StopTask {
                        cluster: Some(cluster.clone()),
                        task: arn.clone(),
                        _reason: None,
                    },
                    scope,
                )
                .await?;
                if self
                    .state
                    .lock()
                    .map_err(|_| EcsError::Internal)?
                    .tasks
                    .get(&(scope.clone(), arn.clone()))
                    .is_some_and(|task| task.status == "STOPPED")
                {
                    active.retain(|task| task != &arn);
                }
                continue;
            }
            let mut unhealthy = false;
            if service.status == "ACTIVE"
                && record.started_at.elapsed().as_secs() >= u64::from(service.health_grace_seconds)
            {
                for lb in &service.load_balancers {
                    if let Some(network) = &record.network {
                        let health = self
                            .query(
                                scope,
                                "elasticloadbalancing",
                                "DescribeTargetHealth",
                                &[
                                    ("TargetGroupArn", lb.target_group_arn.clone()),
                                    ("Targets.member.1.Id", network.private_ip.to_string()),
                                    ("Targets.member.1.Port", lb.container_port.to_string()),
                                ],
                            )
                            .await?;
                        unhealthy |= xml_text(&health, "State") == Some("unhealthy");
                    }
                }
            }
            if unhealthy || !runtime.running(arn.rsplit('/').next().unwrap_or("")).await {
                self.stop_task(
                    StopTask {
                        cluster: Some(cluster.clone()),
                        task: arn.clone(),
                        _reason: Some(
                            if unhealthy {
                                "Task failed ELB health checks"
                            } else {
                                "Essential container exited"
                            }
                            .into(),
                        ),
                    },
                    scope,
                )
                .await?;
                if self
                    .state
                    .lock()
                    .map_err(|_| EcsError::Internal)?
                    .tasks
                    .get(&(scope.clone(), arn.clone()))
                    .is_some_and(|task| task.status == "STOPPED")
                {
                    active.retain(|task| task != &arn);
                }
            }
        }
        while active.len() > service.desired {
            let Some(arn) = active.last().cloned() else {
                break;
            };
            self.stop_task(
                StopTask {
                    cluster: Some(cluster.clone()),
                    task: arn.clone(),
                    _reason: None,
                },
                scope,
            )
            .await?;
            if self
                .state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .tasks
                .get(&(scope.clone(), arn.clone()))
                .is_some_and(|task| task.status == "STOPPED")
            {
                active.pop();
            } else {
                return Ok(());
            }
        }
        // Existing targets are retried too: a lost registration response cannot orphan a task.
        for arn in &active {
            let record = self
                .state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .tasks
                .get(&(scope.clone(), arn.clone()))
                .cloned()
                .ok_or(EcsError::Internal)?;
            if record.status == "RUNNING" {
                for lb in &service.load_balancers {
                    self.target(scope, lb, &record, true).await?;
                }
            }
        }
        while active.len() < service.desired {
            let result = self
                .run_task(
                    RunTask {
                        cluster: Some(cluster.clone()),
                        task_definition: service.definition.clone(),
                        launch_type: Some("FARGATE".into()),
                        count: Some(1),
                        client_token: None,
                        resolved_definition: None,
                        service_launch: true,
                        network_configuration: Some(service.network.clone()),
                    },
                    scope,
                )
                .await?;
            let Some(arn) = result["tasks"]
                .as_array()
                .and_then(|v| v.first())
                .and_then(|v| v["taskArn"].as_str())
            else {
                let failure = result["failures"]
                    .as_array()
                    .and_then(|failures| failures.first());
                let mut detail = failure
                    .and_then(|failure| failure["detail"].as_str())
                    .map(str::to_owned);
                if let Some(arn) = failure.and_then(|failure| failure["arn"].as_str()) {
                    let mut state = self.state.lock().map_err(|_| EcsError::Internal)?;
                    if let Some(record) = state.tasks.get_mut(&(scope.clone(), arn.to_owned())) {
                        record.service_name = Some(service.name.clone());
                        if record.stopped_reason.is_some() {
                            detail = record.stopped_reason.clone();
                        }
                        if record.status == "STOPPING" {
                            state
                                .services
                                .get_mut(key)
                                .ok_or(EcsError::Internal)?
                                .tasks
                                .push(arn.to_owned());
                        }
                    }
                }
                let detail: String = detail
                    .as_deref()
                    .unwrap_or("Runtime provided no failure details")
                    .chars()
                    .take(1024)
                    .collect();
                return Err(EcsError::Client(format!(
                    "Service task failed to start: {detail}"
                )));
            };
            self.state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .tasks
                .get_mut(&(scope.clone(), arn.to_owned()))
                .ok_or(EcsError::Internal)?
                .service_name = Some(service.name.clone());
            active.push(arn.to_owned());
            // Track ownership before registration; any failure leaves a retryable owned task.
            self.state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .services
                .get_mut(key)
                .ok_or(EcsError::Internal)?
                .tasks = active.clone();
            let record = self
                .state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .tasks
                .get(&(scope.clone(), arn.to_owned()))
                .cloned()
                .ok_or(EcsError::Internal)?;
            for lb in &service.load_balancers {
                if let Err(error) = self.target(scope, lb, &record, true).await {
                    // Retain the service ownership record if deregistration or stop fails.
                    self.stop_task(
                        StopTask {
                            cluster: Some(cluster.clone()),
                            task: arn.to_owned(),
                            _reason: Some("Target registration failed".into()),
                        },
                        scope,
                    )
                    .await?;
                    return Err(error);
                }
            }
        }
        if service.status == "DRAINING" && active.is_empty() {
            self.persist(
                scope,
                "2service",
                &format!("{}/{}", service.cluster, service.name),
                None,
            )
            .await?;
            self.state
                .lock()
                .map_err(|_| EcsError::Internal)?
                .services
                .remove(key);
        }
        Ok(())
    }
    fn create_cluster(&self, input: CreateCluster, scope: &Scope) -> Result<Value, EcsError> {
        let name = input.cluster_name.unwrap_or_else(|| "default".into());
        valid_name(&name)?;
        let mut state = self.state.lock().map_err(|_| EcsError::Internal)?;
        self.persist_sync(scope, "0cluster", &name, &json!(true))?;
        state.clusters.insert((scope.clone(), name.clone()), true);
        Ok(json!({"cluster": cluster_value(scope, &name, true)}))
    }
    fn list_clusters(&self, input: ListClusters, scope: &Scope) -> Result<Value, EcsError> {
        let maximum = input.max_results.unwrap_or(100);
        if !(1..=100).contains(&maximum) {
            return Err(EcsError::InvalidParameter(
                "maxResults must be between 1 and 100".into(),
            ));
        }
        let cursor = match input.next_token {
            Some(token) => {
                if !token.starts_with(&scope.cluster_arn("")) {
                    return Err(EcsError::InvalidParameter("Invalid nextToken".into()));
                }
                Some(
                    cluster_name(scope, &token)
                        .map_err(|_| EcsError::InvalidParameter("Invalid nextToken".into()))?,
                )
            }
            None => None,
        };
        let state = self.state.lock().map_err(|_| EcsError::Internal)?;
        let mut names = state
            .clusters
            .iter()
            .filter(|((entry_scope, name), active)| {
                entry_scope == scope
                    && **active
                    && cursor.as_ref().is_none_or(|cursor| name > cursor)
            })
            .map(|((_, name), _)| name);
        let page: Vec<_> = names
            .by_ref()
            .take(maximum as usize)
            .map(|name| scope.cluster_arn(name))
            .collect();
        let mut response = json!({"clusterArns": page});
        if names.next().is_some() {
            response["nextToken"] = json!(page.last().expect("nonempty page before continuation"));
        }
        Ok(response)
    }
    fn describe_clusters(&self, input: DescribeClusters, scope: &Scope) -> Result<Value, EcsError> {
        if input.include.as_ref().is_some_and(|include| {
            include.iter().any(|field| {
                !matches!(
                    field.as_str(),
                    "TAGS" | "CONFIGURATIONS" | "SETTINGS" | "STATISTICS" | "ATTACHMENTS"
                )
            })
        }) {
            return Err(EcsError::InvalidParameter(
                "Invalid cluster include field".into(),
            ));
        }
        let requested = input.clusters.unwrap_or_else(|| vec!["default".into()]);
        if requested.len() > 100 {
            return Err(EcsError::Client(
                "clusters can contain at most 100 entries".into(),
            ));
        }
        let state = self.state.lock().map_err(|_| EcsError::Internal)?;
        let mut clusters = Vec::new();
        let mut failures = Vec::new();
        for identifier in requested {
            let name = cluster_name(scope, &identifier)?;
            match state.clusters.get(&(scope.clone(), name.clone())) {
                Some(active) => {
                    let mut value = cluster_value(scope, &name, *active);
                    value["runningTasksCount"] = json!(state
                        .tasks
                        .iter()
                        .filter(|((task_scope, _), task)| task_scope == scope
                            && task.cluster == name
                            && task.status == "RUNNING")
                        .count());
                    value["pendingTasksCount"] = json!(state
                        .tasks
                        .iter()
                        .filter(|((task_scope, _), task)| task_scope == scope
                            && task.cluster == name
                            && task.status == "PENDING")
                        .count());
                    value["activeServicesCount"] = json!(state
                        .services
                        .keys()
                        .filter(|(service_scope, service_cluster, _)| service_scope == scope
                            && service_cluster == &name)
                        .count());
                    clusters.push(value);
                }
                None => failures.push(json!({"arn": identifier, "reason": "MISSING"})),
            }
        }
        Ok(json!({"clusters": clusters, "failures": failures}))
    }
    fn delete_cluster(&self, input: ClusterId, scope: &Scope) -> Result<Value, EcsError> {
        let name = cluster_name(scope, &input.cluster)?;
        let mut state = self.state.lock().map_err(|_| EcsError::Internal)?;
        let active = state
            .clusters
            .get(&(scope.clone(), name.clone()))
            .ok_or_else(|| EcsError::ClusterNotFound(name.clone()))?;
        if !*active {
            return Err(EcsError::ClusterNotFound(name));
        }
        if state
            .services
            .iter()
            .any(|((service_scope, service_cluster, _), _)| {
                service_scope == scope && service_cluster == &name
            })
        {
            return Err(EcsError::Client("Cluster contains services".into()));
        }
        if state.tasks.iter().any(|((task_scope, _), task)| {
            task_scope == scope && task.cluster == name && task.status != "STOPPED"
        }) {
            return Err(EcsError::Client("Cluster contains running tasks".into()));
        }
        self.persist_sync(scope, "0cluster", &name, &json!(false))?;
        *state
            .clusters
            .get_mut(&(scope.clone(), name.clone()))
            .expect("cluster checked") = false;
        Ok(json!({"cluster": cluster_value(scope, &name, false)}))
    }
    fn register_task_definition(
        &self,
        input: RegisterTaskDefinition,
        scope: &Scope,
    ) -> Result<Value, EcsError> {
        valid_name(&input.family)?;
        if input.requires_compatibilities.as_deref() != Some(&["FARGATE".to_owned()][..]) {
            return Err(EcsError::Client(
                "Only requiresCompatibilities=[FARGATE] is supported".into(),
            ));
        }
        if input.network_mode.as_deref() != Some("awsvpc") {
            return Err(EcsError::Client(
                "Fargate requires networkMode=awsvpc".into(),
            ));
        }
        let cpu = parse_cpu(&input.cpu)?;
        let memory = parse_memory(&input.memory)?;
        if !valid_fargate_size(cpu, memory) {
            return Err(EcsError::Client(
                "No Fargate configuration exists for given values".into(),
            ));
        }
        if input.container_definitions.is_empty() {
            return Err(EcsError::Client(
                "At least one container definition is required".into(),
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        for container in &input.container_definitions {
            valid_name(&container.name)?;
            if !names.insert(&container.name) || container.image.trim().is_empty() {
                return Err(EcsError::Client(
                    "Container names must be unique and images nonempty".into(),
                ));
            }
        }
        let has_roles = input.task_role_arn.is_some() || input.execution_role_arn.is_some();
        if has_roles
            && !self
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.supports_execution_identity())
        {
            return Err(EcsError::Client(
                "Configured Fargate runtime does not support task execution identities".into(),
            ));
        }
        for role in [
            input.task_role_arn.as_deref(),
            input.execution_role_arn.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let prefix = format!("arn:aws:iam::{}:role/", scope.account);
            if !role.starts_with(&prefix) || role.len() <= prefix.len() || role.len() > 2048 {
                return Err(EcsError::Client("Role must belong to this account".into()));
            }
        }
        for container in &input.container_definitions {
            if let Some(log) = &container.log_configuration {
                if !self
                    .runtime
                    .as_ref()
                    .is_some_and(|runtime| runtime.supports_awslogs())
                {
                    return Err(EcsError::Client(
                        "Configured Fargate runtime does not support awslogs".into(),
                    ));
                }
                if input.execution_role_arn.is_none()
                    || log.log_driver != "awslogs"
                    || log.options.len() != 3
                    || !["awslogs-group", "awslogs-region", "awslogs-stream-prefix"]
                        .iter()
                        .all(|key| {
                            log.options
                                .get(*key)
                                .is_some_and(|value| !value.is_empty() && value.len() <= 512)
                        })
                    || log.options.get("awslogs-region") != Some(&scope.region)
                {
                    return Err(EcsError::Client("awslogs requires an execution role and scoped group, region and stream prefix".into()));
                }
            }
        }
        let mut state = self.state.lock().map_err(|_| EcsError::Internal)?;
        let definitions = state
            .definitions
            .entry((scope.clone(), input.family.clone()))
            .or_default();
        let revision = definitions.len() + 1;
        let containers =
            serde_json::to_value(&input.container_definitions).map_err(|_| EcsError::Internal)?;
        let value = json!({
            "taskDefinitionArn": scope.task_arn(&input.family, revision),
            "family": input.family,
            "revision": revision,
            "status": "ACTIVE",
            "networkMode": "awsvpc",
            "requiresCompatibilities": ["FARGATE"],
            "compatibilities": ["FARGATE"],
            "cpu": cpu.to_string(),
            "memory": memory.to_string(),
            "containerDefinitions": containers,
            "volumes": [],
            "taskRoleArn": input.task_role_arn,
            "executionRoleArn": input.execution_role_arn
        });
        self.persist_sync(
            scope,
            "1definition",
            &format!("{}:{revision}", input.family),
            &value,
        )?;
        definitions.push(value.clone());
        Ok(json!({"taskDefinition": value}))
    }
    fn deregister_task_definition(
        &self,
        input: DeregisterTaskDefinition,
        scope: &Scope,
    ) -> Result<Value, EcsError> {
        let (family, revision) = task_identifier(scope, &input.task_definition)?;
        let revision = revision
            .ok_or_else(|| EcsError::Client("Deregistration requires a revision".into()))?;
        let mut state = self.state.lock().map_err(|_| EcsError::Internal)?;
        let definition = state
            .definitions
            .get_mut(&(scope.clone(), family.clone()))
            .and_then(|definitions| definitions.get_mut(revision.saturating_sub(1)))
            .ok_or_else(|| EcsError::Client("Task definition was not found".into()))?;
        let mut inactive = definition.clone();
        inactive["status"] = "INACTIVE".into();
        self.persist_sync(
            scope,
            "1definition",
            &format!("{family}:{revision}"),
            &inactive,
        )?;
        *definition = inactive.clone();
        Ok(json!({"taskDefinition":inactive}))
    }
    fn describe_task_definition(
        &self,
        input: DescribeTaskDefinition,
        scope: &Scope,
    ) -> Result<Value, EcsError> {
        if input
            .include
            .as_ref()
            .is_some_and(|values| values.iter().any(|value| value != "TAGS"))
        {
            return Err(EcsError::Client("Only include=TAGS is supported".into()));
        }
        let (family, revision) = task_identifier(scope, &input.task_definition)?;
        let state = self.state.lock().map_err(|_| EcsError::Internal)?;
        let definitions = state
            .definitions
            .get(&(scope.clone(), family.clone()))
            .ok_or_else(|| EcsError::Client("Unable to describe task definition".into()))?;
        let value = revision
            .and_then(|n| definitions.get(n.saturating_sub(1)))
            .or_else(|| {
                if revision.is_none() {
                    definitions
                        .iter()
                        .rev()
                        .find(|definition| definition["status"] == "ACTIVE")
                } else {
                    None
                }
            })
            .ok_or_else(|| EcsError::Client("Unable to describe task definition".into()))?;
        let mut response = json!({"taskDefinition": value});
        if input.include.is_some() {
            response["tags"] = json!([]);
        }
        Ok(response)
    }
}

fn task_value(arn: &str, scope: &Scope, record: &TaskRecord) -> Value {
    let attachments = record
        .network
        .as_ref()
        .map(|network| {
            json!([{"id": network.eni_id, "type": "ElasticNetworkInterface",
            "status": if record.status == "RUNNING" {"ATTACHED"} else {"DETACHED"},
            "details": [
                {"name": "subnetId", "value": network.subnet_id},
                {"name": "networkInterfaceId", "value": network.eni_id},
                {"name": "privateIPv4Address", "value": network.private_ip.to_string()}
            ]}])
        })
        .unwrap_or_else(|| json!([]));
    let mut value = json!({"taskArn":arn,"clusterArn":scope.cluster_arn(&record.cluster),
        "taskDefinitionArn":record.definition,"lastStatus":record.status,
        "desiredStatus":if matches!(record.status.as_str(), "RUNNING" | "PENDING") {"RUNNING"} else {"STOPPED"},
        "launchType":"FARGATE","platformVersion":"1.4.0",
        "containers":[{"name":record.container,"lastStatus":record.status}],
        "attachments":attachments,"attributes":[]});
    if let Some(reason) = &record.stopped_reason {
        value["stoppedReason"] = json!(reason);
    }
    value
}

impl Drop for EcsHandler {
    fn drop(&mut self) {
        if let Ok(worker) = self.worker.get_mut() {
            if let Some(worker) = worker.take() {
                worker.abort();
            }
        }
    }
}
fn xml_text<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    body.split_once(&format!("<{tag}>"))?
        .1
        .split_once(&format!("</{tag}>"))
        .map(|(value, _)| value)
}
fn service_name(scope: &Scope, cluster: &str, id: &str) -> Result<String, EcsError> {
    let prefix = format!(
        "arn:aws:ecs:{}:{}:service/{cluster}/",
        scope.region, scope.account
    );
    let name = id.strip_prefix(&prefix).unwrap_or(id);
    if name.starts_with("arn:") {
        return Err(EcsError::Client("Service was not found".into()));
    }
    valid_name(name)?;
    Ok(name.to_owned())
}
fn service_value(scope: &Scope, service: &ServiceRecord) -> Value {
    json!({"serviceArn":format!("arn:aws:ecs:{}:{}:service/{}/{}",scope.region,scope.account,service.cluster,service.name),
        "serviceName":service.name,"clusterArn":scope.cluster_arn(&service.cluster),"status":service.status,
        "desiredCount":service.desired,"runningCount":service.tasks.len(),"pendingCount":0,
        "taskDefinition":service.definition,"launchType":"FARGATE","platformVersion":"1.4.0",
        "loadBalancers":service.load_balancers,"healthCheckGracePeriodSeconds":service.health_grace_seconds,"deployments":[],"events":service.last_error.as_ref().map(|message| vec![json!({"id":"locallycloud-reconcile","message":message})]).unwrap_or_default(),"enableExecuteCommand":false})
}

fn cluster_value(scope: &Scope, name: &str, active: bool) -> Value {
    json!({"clusterArn": scope.cluster_arn(name), "clusterName": name,
        "status": if active {"ACTIVE"} else {"INACTIVE"},
        "registeredContainerInstancesCount": 0, "runningTasksCount": 0,
        "pendingTasksCount": 0, "activeServicesCount": 0,
        "statistics": [], "tags": [], "settings": [], "capacityProviders": [], "defaultCapacityProviderStrategy": []})
}
fn cluster_name(scope: &Scope, id: &str) -> Result<String, EcsError> {
    let name = id
        .strip_prefix(&format!(
            "arn:aws:ecs:{}:{}:cluster/",
            scope.region, scope.account
        ))
        .unwrap_or(id);
    valid_name(name)?;
    if name.starts_with("arn:") {
        return Err(EcsError::ClusterNotFound(id.into()));
    }
    Ok(name.into())
}
fn task_identifier(scope: &Scope, id: &str) -> Result<(String, Option<usize>), EcsError> {
    let base = id
        .strip_prefix(&format!(
            "arn:aws:ecs:{}:{}:task-definition/",
            scope.region, scope.account
        ))
        .unwrap_or(id);
    if base.starts_with("arn:") {
        return Err(EcsError::Client(
            "Unable to describe task definition".into(),
        ));
    }
    let (family, revision) = match base.rsplit_once(':') {
        Some((family, revision)) => (
            family,
            Some(
                revision
                    .parse::<usize>()
                    .map_err(|_| EcsError::Client("Invalid task definition revision".into()))?,
            ),
        ),
        None => (base, None),
    };
    valid_name(family)?;
    if revision == Some(0) {
        return Err(EcsError::Client("Invalid task definition revision".into()));
    }
    Ok((family.into(), revision))
}
fn valid_name(name: &str) -> Result<(), EcsError> {
    if name.is_empty()
        || name.len() > 255
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(EcsError::Client("Invalid ECS resource name".into()));
    }
    Ok(())
}
fn parse_cpu(value: &str) -> Result<u32, EcsError> {
    let normalized = value.trim().to_ascii_lowercase();
    if let Ok(units) = normalized.parse::<u32>() {
        return Ok(units);
    }
    let vcpu = normalized
        .strip_suffix("vcpu")
        .or_else(|| normalized.strip_suffix("vcpus"))
        .and_then(|n| n.trim().parse::<f64>().ok())
        .ok_or_else(|| EcsError::Client("Invalid cpu value".into()))?;
    let units = vcpu * 1024.0;
    if !units.is_finite() || units.fract() != 0.0 || units < 0.0 || units > u32::MAX as f64 {
        return Err(EcsError::Client("Invalid cpu value".into()));
    }
    Ok(units as u32)
}
fn parse_memory(value: &str) -> Result<u32, EcsError> {
    let normalized = value.trim().to_ascii_lowercase().replace(' ', "");
    if let Ok(mib) = normalized.parse::<u32>() {
        return Ok(mib);
    }
    let gb = normalized
        .strip_suffix("gb")
        .or_else(|| normalized.strip_suffix("gib"))
        .and_then(|n| n.parse::<u32>().ok())
        .ok_or_else(|| EcsError::Client("Invalid memory value".into()))?;
    gb.checked_mul(1024)
        .ok_or_else(|| EcsError::Client("Invalid memory value".into()))
}
fn valid_fargate_size(cpu: u32, mem: u32) -> bool {
    match cpu {
        256 => matches!(mem, 512 | 1024 | 2048),
        512 => (1024..=4096).contains(&mem) && mem.is_multiple_of(1024),
        1024 => (2048..=8192).contains(&mem) && mem.is_multiple_of(1024),
        2048 => (4096..=16384).contains(&mem) && mem.is_multiple_of(1024),
        4096 => (8192..=30720).contains(&mem) && mem.is_multiple_of(1024),
        8192 => (16384..=61440).contains(&mem) && mem.is_multiple_of(4096),
        16384 => (32768..=122880).contains(&mem) && mem.is_multiple_of(8192),
        _ => false,
    }
}
fn validate_content_type(headers: &HeaderMap) -> Result<(), EcsError> {
    let value = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if value
        .split(';')
        .next()
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(CONTENT_TYPE))
    {
        Ok(())
    } else {
        Err(EcsError::Serialization(
            "Content-Type must be application/x-amz-json-1.1".into(),
        ))
    }
}
fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, EcsError> {
    serde_json::from_slice(body)
        .map_err(|_| EcsError::Serialization("Invalid ECS request body".into()))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateCluster {
    cluster_name: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescribeClusters {
    clusters: Option<Vec<String>>,
    include: Option<Vec<String>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListClusters {
    max_results: Option<i64>,
    next_token: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClusterId {
    cluster: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegisterTaskDefinition {
    family: String,
    container_definitions: Vec<ContainerDefinition>,
    cpu: String,
    memory: String,
    network_mode: Option<String>,
    requires_compatibilities: Option<Vec<String>>,
    task_role_arn: Option<String>,
    execution_role_arn: Option<String>,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContainerDefinition {
    name: String,
    image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    essential: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_point: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<Vec<EnvironmentVariable>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port_mappings: Option<Vec<PortMapping>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_configuration: Option<TaskLogConfiguration>,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PortMapping {
    container_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnvironmentVariable {
    name: String,
    value: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescribeTaskDefinition {
    task_definition: String,
    include: Option<Vec<String>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeregisterTaskDefinition {
    task_definition: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RunTask {
    cluster: Option<String>,
    task_definition: String,
    launch_type: Option<String>,
    count: Option<u32>,
    client_token: Option<String>,
    network_configuration: Option<NetworkConfiguration>,
    #[serde(skip)]
    resolved_definition: Option<String>,
    #[serde(skip)]
    service_launch: bool,
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetworkConfiguration {
    awsvpc_configuration: Option<AwsvpcConfiguration>,
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AwsvpcConfiguration {
    subnets: Vec<String>,
    security_groups: Option<Vec<String>>,
    assign_public_ip: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescribeTasks {
    cluster: Option<String>,
    tasks: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StopTask {
    cluster: Option<String>,
    task: String,
    #[serde(rename = "reason")]
    _reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateService {
    cluster: Option<String>,
    service_name: String,
    task_definition: String,
    launch_type: Option<String>,
    desired_count: u32,
    network_configuration: Option<NetworkConfiguration>,
    load_balancers: Option<Vec<LoadBalancer>>,
    health_check_grace_period_seconds: Option<u32>,
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoadBalancer {
    target_group_arn: String,
    container_name: String,
    container_port: u16,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescribeServices {
    cluster: Option<String>,
    services: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateService {
    cluster: Option<String>,
    service: String,
    desired_count: Option<u32>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeleteService {
    cluster: Option<String>,
    service: String,
    force: Option<bool>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListTasks {
    cluster: Option<String>,
    service_name: Option<String>,
    desired_status: Option<String>,
}

#[derive(Clone, Copy)]
enum DesiredTaskStatus {
    Running,
    Stopped,
    Pending,
}
impl DesiredTaskStatus {
    fn parse(value: &str) -> Result<Self, EcsError> {
        match value {
            "RUNNING" => Ok(Self::Running),
            "STOPPED" => Ok(Self::Stopped),
            "PENDING" => Ok(Self::Pending),
            _ => Err(EcsError::InvalidParameter(
                "desiredStatus must be RUNNING, STOPPED or PENDING".into(),
            )),
        }
    }
    fn matches(self, status: &str) -> bool {
        match self {
            Self::Running => matches!(status, "RUNNING" | "PENDING"),
            Self::Stopped => matches!(status, "STOPPING" | "STOPPED"),
            Self::Pending => false,
        }
    }
}

#[derive(Debug)]
enum EcsError {
    AccessDenied,
    Serialization(String),
    Client(String),
    InvalidParameter(String),
    ClusterNotFound(String),
    UnknownOperation,
    Internal,
}
impl From<EcsError> for AwsError {
    fn from(value: EcsError) -> Self {
        match value {
            EcsError::AccessDenied => {
                AwsError::new("AccessDeniedException", "Request is not authorized", 400)
            }
            EcsError::Serialization(message) => {
                AwsError::new("SerializationException", message, 400)
            }
            EcsError::Client(message) => AwsError::new("ClientException", message, 400),
            EcsError::InvalidParameter(message) => {
                AwsError::new("InvalidParameterException", message, 400)
            }
            EcsError::ClusterNotFound(name) => AwsError::new(
                "ClusterNotFoundException",
                format!("Cluster {name} was not found"),
                400,
            ),
            EcsError::UnknownOperation => AwsError::new(
                "UnknownOperationException",
                "ECS operation is not supported",
                400,
            ),
            EcsError::Internal => AwsError::new("ServerException", "ECS state is unavailable", 500),
        }
    }
}
#[async_trait]
impl NativeHandler for EcsHandler {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        let s = self.state.lock().map_err(|_| "ECS inventory unavailable")?;
        let mut regions: Vec<_> = s
            .clusters
            .iter()
            .filter(|((k, _), active)| k.account == account && **active)
            .map(|((k, _), _)| k.region.clone())
            .collect();
        regions.extend(
            s.definitions
                .iter()
                .filter(|((k, _), v)| k.account == account && !v.is_empty())
                .map(|((k, _), _)| k.region.clone()),
        );
        regions.extend(
            s.services
                .iter()
                .filter(|((k, _, _), v)| k.account == account && v.status != "INACTIVE")
                .map(|((k, _, _), _)| k.region.clone()),
        );
        Ok(regions)
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let result = self.process_async(&request).await;
        if self
            .state
            .lock()
            .is_ok_and(|state| !state.services.is_empty())
        {
            self.start_reconciler();
        }
        match result {
            Ok(value) => Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
                .header("x-amzn-RequestId", &request.request_id)
                .body(Body::from(
                    serde_json::to_vec(&value).expect("ECS JSON response"),
                ))
                .expect("ECS response"),
            Err(error) => AwsError::from(error)
                .with_request_id(request.request_id)
                .render(AwsProtocol::Json11)
                .into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn request(op: &str, body: Value, account: &str, region: &str) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, CONTENT_TYPE.parse().unwrap());
        headers.insert(
            "x-amz-target",
            format!("{TARGET_PREFIX}.{op}").parse().unwrap(),
        );
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
            account_id: account.into(),
            region: region.into(),
            request_id: "test".into(),
        }
    }
    fn task(family: &str, cpu: &str, memory: &str) -> Value {
        json!({"family":family,"containerDefinitions":[{"name":"app","image":"example.com/app:1"}],
            "requiresCompatibilities":["FARGATE"],"networkMode":"awsvpc","cpu":cpu,"memory":memory})
    }
    struct FailedStartRuntime {
        cleanup_fails: std::sync::atomic::AtomicBool,
        starts: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl TaskRuntime for FailedStartRuntime {
        async fn preflight(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &[String],
            _: &[String],
        ) -> Result<(), String> {
            Ok(())
        }
        async fn start(&self, _: &TaskLaunch) -> Result<TaskNetworkInfo, String> {
            self.starts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err("OCI readiness failed".into())
        }
        async fn stop(&self, _: &str) -> Result<(), String> {
            if self.cleanup_fails.load(std::sync::atomic::Ordering::SeqCst) {
                Err("rootfs removal denied".into())
            } else {
                Ok(())
            }
        }
        async fn running(&self, _: &str) -> bool {
            false
        }
    }
    #[tokio::test]
    async fn failed_start_preserves_task_identity_reason_token_and_cleanup_retry() {
        let runtime = Arc::new(FailedStartRuntime {
            cleanup_fails: std::sync::atomic::AtomicBool::new(true),
            starts: std::sync::atomic::AtomicUsize::new(0),
        });
        let handler = EcsHandler::with_runtime(Some(runtime.clone()));
        let account = "111111111111";
        let region = "us-east-1";
        handler
            .process(&request(
                "CreateCluster",
                json!({"clusterName":"web"}),
                account,
                region,
            ))
            .ok()
            .unwrap();
        let mut definition = task("web", "256", "1024");
        definition["containerDefinitions"][0]["portMappings"] = json!([{"containerPort":8080}]);
        handler
            .process(&request(
                "RegisterTaskDefinition",
                definition,
                account,
                region,
            ))
            .ok()
            .unwrap();
        let input = json!({"cluster":"web", "taskDefinition":"web", "launchType":"FARGATE", "clientToken":"stable-failure", "networkConfiguration":{"awsvpcConfiguration":{"subnets":["subnet-test"]}}});
        let failed = handler
            .process_async(&request("RunTask", input.clone(), account, region))
            .await
            .ok()
            .unwrap();
        let arn = failed["failures"][0]["arn"].as_str().unwrap();
        assert!(arn.starts_with("arn:aws:ecs:us-east-1:111111111111:task/web/"));
        assert!(failed["failures"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("OCI readiness failed"));
        assert!(failed["failures"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("rootfs removal denied"));
        let repeated = handler
            .process_async(&request("RunTask", input, account, region))
            .await
            .ok()
            .unwrap();
        assert_eq!(repeated["tasks"][0]["taskArn"], arn);
        assert_eq!(repeated["tasks"][0]["lastStatus"], "STOPPING");
        assert!(repeated["tasks"][0]["stoppedReason"]
            .as_str()
            .unwrap()
            .contains("cleanup pending"));
        assert_eq!(runtime.starts.load(std::sync::atomic::Ordering::SeqCst), 1);
        let stop = request(
            "StopTask",
            json!({"cluster":"web", "task":arn}),
            account,
            region,
        );
        assert!(handler.process_async(&stop).await.is_err());
        runtime
            .cleanup_fails
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let stopped = handler.process_async(&stop).await.ok().unwrap();
        assert_eq!(stopped["task"]["lastStatus"], "STOPPED");
        let described = handler
            .process_async(&request(
                "DescribeTasks",
                json!({"cluster":"web","tasks":[arn]}),
                account,
                region,
            ))
            .await
            .ok()
            .unwrap();
        assert_eq!(described["tasks"][0]["lastStatus"], "STOPPED");
    }

    #[tokio::test]
    async fn list_clusters_paginates_active_scope_and_describe_accepts_provider_projection() {
        async fn call(
            handler: &EcsHandler,
            op: &str,
            payload: Value,
            account: &str,
            region: &str,
        ) -> (u16, Value) {
            let response = handler.handle(request(op, payload, account, region)).await;
            let status = response.status().as_u16();
            let body = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            (status, serde_json::from_slice(&body).unwrap())
        }
        let handler = EcsHandler::new();
        let account = "111111111111";
        let region = "us-east-1";
        for (name, owner, location) in [
            ("alpha", account, region),
            ("beta", account, region),
            ("deleted", account, region),
            ("foreign", "222222222222", region),
            ("west", account, "us-west-2"),
        ] {
            assert_eq!(
                call(
                    &handler,
                    "CreateCluster",
                    json!({"clusterName":name}),
                    owner,
                    location
                )
                .await
                .0,
                200
            );
        }
        assert_eq!(
            call(
                &handler,
                "DeleteCluster",
                json!({"cluster":"deleted"}),
                account,
                region
            )
            .await
            .0,
            200
        );
        let (status, first) = call(
            &handler,
            "ListClusters",
            json!({"maxResults":1}),
            account,
            region,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(
            first["clusterArns"],
            json!(["arn:aws:ecs:us-east-1:111111111111:cluster/alpha"])
        );
        let token = first["nextToken"].as_str().unwrap();
        let (status, second) = call(
            &handler,
            "ListClusters",
            json!({"maxResults":1,"nextToken":token}),
            account,
            region,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(
            second["clusterArns"],
            json!(["arn:aws:ecs:us-east-1:111111111111:cluster/beta"])
        );
        assert!(second.get("nextToken").is_none());
        for (owner, location) in [("222222222222", region), (account, "us-west-2")] {
            let (status, error) = call(
                &handler,
                "ListClusters",
                json!({"nextToken":token}),
                owner,
                location,
            )
            .await;
            assert_eq!(status, 400);
            assert!(error["__type"]
                .as_str()
                .unwrap()
                .ends_with("InvalidParameterException"));
        }
        for payload in [
            json!({"maxResults":0}),
            json!({"maxResults":101}),
            json!({"nextToken":"invalid"}),
        ] {
            assert_eq!(
                call(&handler, "ListClusters", payload, account, region)
                    .await
                    .0,
                400
            );
        }
        let (_, all) = call(&handler, "ListClusters", json!({}), account, region).await;
        assert_eq!(all["clusterArns"].as_array().unwrap().len(), 2);
        let (status, described) = call(
            &handler,
            "DescribeClusters",
            json!({"clusters":["beta"],"include":["TAGS","CONFIGURATIONS","SETTINGS"]}),
            account,
            region,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(described["clusters"][0]["status"], "ACTIVE");
        assert_eq!(
            call(
                &handler,
                "DescribeClusters",
                json!({"include":["UNKNOWN"]}),
                account,
                region
            )
            .await
            .0,
            400
        );
    }

    #[test]
    fn cluster_lifecycle_scope_and_failures() {
        let handler = EcsHandler::new();
        let a = "111111111111";
        let b = "222222222222";
        let created = handler
            .process(&request(
                "CreateCluster",
                json!({"clusterName":"app"}),
                a,
                "us-east-1",
            ))
            .ok()
            .unwrap();
        assert_eq!(created["cluster"]["status"], "ACTIVE");
        let other = handler
            .process(&request(
                "DescribeClusters",
                json!({"clusters":["app"]}),
                b,
                "us-east-1",
            ))
            .ok()
            .unwrap();
        assert_eq!(other["clusters"].as_array().unwrap().len(), 0);
        assert_eq!(other["failures"][0]["reason"], "MISSING");
        let deleted = handler
            .process(&request(
                "DeleteCluster",
                json!({"cluster":"app"}),
                a,
                "us-east-1",
            ))
            .ok()
            .unwrap();
        assert_eq!(deleted["cluster"]["status"], "INACTIVE");
        let after = handler
            .process(&request(
                "DescribeClusters",
                json!({"clusters":["app"]}),
                a,
                "us-east-1",
            ))
            .ok()
            .unwrap();
        assert_eq!(after["clusters"][0]["status"], "INACTIVE");
    }
    #[test]
    fn fargate_revision_validation_and_scope() {
        let handler = EcsHandler::new();
        let a = "111111111111";
        assert!(handler
            .process(&request(
                "RegisterTaskDefinition",
                task("web", "256", "1024"),
                a,
                "us-east-1"
            ))
            .is_ok());
        let mut wrong_network = task("web", "256", "1024");
        wrong_network["networkMode"] = "bridge".into();
        assert!(handler
            .process(&request(
                "RegisterTaskDefinition",
                wrong_network,
                a,
                "us-east-1"
            ))
            .is_err());
        assert!(handler
            .process(&request(
                "RegisterTaskDefinition",
                task("web", "256", "4096"),
                a,
                "us-east-1"
            ))
            .is_err());
        let second = handler
            .process(&request(
                "RegisterTaskDefinition",
                task("web", "1 vCPU", "2 GB"),
                a,
                "us-east-1",
            ))
            .ok()
            .unwrap();
        assert_eq!(second["taskDefinition"]["revision"], 2);
        let latest = handler
            .process(&request(
                "DescribeTaskDefinition",
                json!({"taskDefinition":"web"}),
                a,
                "us-east-1",
            ))
            .ok()
            .unwrap();
        assert_eq!(latest["taskDefinition"]["revision"], 2);
        let first = handler
            .process(&request(
                "DescribeTaskDefinition",
                json!({"taskDefinition":"web:1"}),
                a,
                "us-east-1",
            ))
            .ok()
            .unwrap();
        assert_eq!(first["taskDefinition"]["revision"], 1);
        assert!(handler
            .process(&request(
                "DescribeTaskDefinition",
                json!({"taskDefinition":"web:0"}),
                a,
                "us-east-1"
            ))
            .is_err());
        assert!(handler
            .process(&request(
                "DescribeTaskDefinition",
                json!({"taskDefinition":"web"}),
                a,
                "eu-west-1"
            ))
            .is_err());
    }
    #[tokio::test]
    async fn json11_wire_success_and_unsupported_error() {
        let handler = EcsHandler::new();
        let account = "111111111111";
        let response = handler
            .handle(request(
                "CreateCluster",
                json!({"clusterName":"web"}),
                account,
                "us-east-1",
            ))
            .await;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()[http::header::CONTENT_TYPE], CONTENT_TYPE);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["cluster"]["clusterArn"],
            "arn:aws:ecs:us-east-1:111111111111:cluster/web"
        );
        let rejected = handler
            .handle(request(
                "RunTask",
                json!({"cluster":"web"}),
                account,
                "us-east-1",
            ))
            .await;
        assert_eq!(rejected.status(), 400);
        let body = axum::body::to_bytes(rejected.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["__type"], "SerializationException");
    }

    #[test]
    fn execution_ops_and_unknown_fields_never_mutate() {
        let handler = EcsHandler::new();
        let a = "111111111111";
        assert!(handler
            .process(&request(
                "RunTask",
                json!({"taskDefinition":"web"}),
                a,
                "us-east-1"
            ))
            .is_err());
        assert!(handler
            .process(&request(
                "CreateService",
                json!({"serviceName":"web"}),
                a,
                "us-east-1"
            ))
            .is_err());
        let mut unsupported = task("web", "256", "1024");
        unsupported["taskRoleArn"] = "arn:aws:iam::111111111111:role/r".into();
        assert!(handler
            .process(&request(
                "RegisterTaskDefinition",
                unsupported,
                a,
                "us-east-1"
            ))
            .is_err());
        let first = handler
            .process(&request(
                "RegisterTaskDefinition",
                task("web", "256", "1024"),
                a,
                "us-east-1",
            ))
            .ok()
            .unwrap();
        assert_eq!(first["taskDefinition"]["revision"], 1);
    }
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;
