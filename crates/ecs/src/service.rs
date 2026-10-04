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
use locallycloud_core::registry::AwsProtocol;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::TARGET_PREFIX;

const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const MAX_BODY: usize = 1024 * 1024;

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
}

#[derive(Clone)]
pub struct TaskNetworkInfo {
    pub eni_id: String,
    pub private_ip: std::net::Ipv4Addr,
    pub subnet_id: String,
}

#[async_trait]
pub trait TaskRuntime: Send + Sync {
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

#[derive(Clone)]
struct TaskRecord {
    cluster: String,
    definition: String,
    container: String,
    status: String,
    network: Option<TaskNetworkInfo>,
    stopped_reason: Option<String>,
}

#[derive(Clone)]
struct ServiceRecord {
    cluster: String,
    name: String,
    definition: String,
    desired: usize,
    network: NetworkConfiguration,
    tasks: Vec<String>,
    status: String,
}

pub(crate) struct EcsHandler {
    state: Mutex<State>,
    runtime: Option<Arc<dyn TaskRuntime>>,
    reconcile_lock: tokio::sync::Mutex<()>,
}
impl EcsHandler {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::with_runtime(None)
    }
    pub(crate) fn with_runtime(runtime: Option<Arc<dyn TaskRuntime>>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            runtime,
            reconcile_lock: tokio::sync::Mutex::new(()),
        }
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
    fn process(&self, request: &ServiceRequest) -> Result<Value, EcsError> {
        let target = self.operation(request)?;
        let scope = Scope::new(request);
        match target {
            "CreateCluster" => self.create_cluster(decode(&request.body)?, &scope),
            "DescribeClusters" => self.describe_clusters(decode(&request.body)?, &scope),
            "DeleteCluster" => self.delete_cluster(decode(&request.body)?, &scope),
            "RegisterTaskDefinition" => {
                self.register_task_definition(decode(&request.body)?, &scope)
            }
            "DescribeTaskDefinition" => {
                self.describe_task_definition(decode(&request.body)?, &scope)
            }
            _ => Err(EcsError::UnknownOperation),
        }
    }
    async fn process_async(&self, request: &ServiceRequest) -> Result<Value, EcsError> {
        match self.operation(request)? {
            "RunTask" => {
                self.run_task(decode(&request.body)?, &Scope::new(request))
                    .await
            }
            "DescribeTasks" => {
                self.describe_tasks(decode(&request.body)?, &Scope::new(request))
                    .await
            }
            "StopTask" => {
                self.stop_task(decode(&request.body)?, &Scope::new(request))
                    .await
            }
            "CreateService" => {
                self.create_service(decode(&request.body)?, &Scope::new(request))
                    .await
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
            _ => self.process(request),
        }
    }
    async fn run_task(&self, input: RunTask, scope: &Scope) -> Result<Value, EcsError> {
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
        let (family, revision) = task_identifier(scope, &input.task_definition)?;
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
                        definitions.last()
                    } else {
                        None
                    }
                })
                .ok_or_else(|| EcsError::Client("Task definition was not found".into()))?
                .clone();
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
        };
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
        };
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
                        if !self
                            .runtime
                            .as_ref()
                            .expect("runtime exists for running task")
                            .running(task_id)
                            .await
                        {
                            record.status = "STOPPED".into();
                            self.state
                                .lock()
                                .map_err(|_| EcsError::Internal)?
                                .tasks
                                .insert((scope.clone(), arn.clone()), record.clone());
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
        let mut record = record;
        record.status = "STOPPED".into();
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
        let (image, pinned_definition) = {
            let state = self.state.lock().map_err(|_| EcsError::Internal)?;
            let definitions = state
                .definitions
                .get(&(scope.clone(), family))
                .ok_or_else(|| EcsError::Client("Task definition was not found".into()))?;
            let definition = revision
                .and_then(|n| definitions.get(n.saturating_sub(1)))
                .or_else(|| {
                    if revision.is_none() {
                        definitions.last()
                    } else {
                        None
                    }
                })
                .ok_or_else(|| EcsError::Client("Task definition was not found".into()))?;
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
            )
        };
        let awsvpc = network
            .awsvpc_configuration
            .as_ref()
            .ok_or(EcsError::Internal)?;
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
            let mut state = self.state.lock().map_err(|_| EcsError::Internal)?;
            if state.clusters.get(&(scope.clone(), cluster.clone())) != Some(&true) {
                return Err(EcsError::ClusterNotFound(cluster));
            }
            if state.services.contains_key(&key) {
                return Err(EcsError::Client("Service already exists".into()));
            }
            state.services.insert(
                key.clone(),
                ServiceRecord {
                    cluster: cluster.clone(),
                    name: input.service_name,
                    definition: pinned_definition,
                    desired: input.desired_count as usize,
                    network,
                    tasks: Vec::new(),
                    status: "ACTIVE".into(),
                },
            );
        }
        self.reconcile_service(&key).await?;
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
                self.reconcile_service(&key).await?;
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
        {
            let mut state = self.state.lock().map_err(|_| EcsError::Internal)?;
            let service = state
                .services
                .get_mut(&key)
                .ok_or_else(|| EcsError::Client("Service was not found".into()))?;
            service.desired = desired as usize;
        }
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
        let cluster = cluster_name(scope, input.cluster.as_deref().unwrap_or("default"))?;
        let state = self.state.lock().map_err(|_| EcsError::Internal)?;
        let tasks = if let Some(service_id) = input.service_name {
            let name = service_name(scope, &cluster, &service_id)?;
            state
                .services
                .get(&(scope.clone(), cluster, name))
                .map(|s| s.tasks.clone())
                .unwrap_or_default()
        } else {
            state
                .tasks
                .iter()
                .filter(|((task_scope, _), t)| {
                    task_scope == scope && t.cluster == cluster && t.status == "RUNNING"
                })
                .map(|((_, arn), _)| arn.clone())
                .collect()
        };
        Ok(json!({"taskArns":tasks}))
    }
    async fn reconcile_service(&self, key: &(Scope, String, String)) -> Result<(), EcsError> {
        let (scope, cluster, _) = key;
        let mut service = self
            .state
            .lock()
            .map_err(|_| EcsError::Internal)?
            .services
            .get(key)
            .cloned()
            .ok_or(EcsError::Internal)?;
        let mut active = Vec::new();
        for arn in service.tasks {
            let task_id = arn.rsplit('/').next().unwrap_or("");
            if self.runtime.as_ref().is_some_and(|_| !task_id.is_empty())
                && self
                    .runtime
                    .as_ref()
                    .expect("checked")
                    .running(task_id)
                    .await
            {
                active.push(arn);
            } else {
                self.stop_task(
                    StopTask {
                        cluster: Some(cluster.clone()),
                        task: arn,
                        _reason: None,
                    },
                    scope,
                )
                .await?;
            }
        }
        while active.len() > service.desired {
            let arn = active.pop().expect("active task exists");
            self.stop_task(
                StopTask {
                    cluster: Some(cluster.clone()),
                    task: arn,
                    _reason: None,
                },
                scope,
            )
            .await?;
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
                break;
            };
            active.push(arn.to_owned());
        }
        service.tasks = active;
        self.state
            .lock()
            .map_err(|_| EcsError::Internal)?
            .services
            .insert(key.clone(), service);
        Ok(())
    }
    fn create_cluster(&self, input: CreateCluster, scope: &Scope) -> Result<Value, EcsError> {
        let name = input.cluster_name.unwrap_or_else(|| "default".into());
        valid_name(&name)?;
        let mut state = self.state.lock().map_err(|_| EcsError::Internal)?;
        state.clusters.insert((scope.clone(), name.clone()), true);
        Ok(json!({"cluster": cluster_value(scope, &name, true)}))
    }
    fn describe_clusters(&self, input: DescribeClusters, scope: &Scope) -> Result<Value, EcsError> {
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
            "volumes": []
        });
        definitions.push(value.clone());
        Ok(json!({"taskDefinition": value}))
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
                    definitions.last()
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
        "deployments":[],"events":[],"enableExecuteCommand":false})
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
struct RunTask {
    cluster: Option<String>,
    task_definition: String,
    launch_type: Option<String>,
    count: Option<u32>,
    client_token: Option<String>,
    network_configuration: Option<NetworkConfiguration>,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetworkConfiguration {
    awsvpc_configuration: Option<AwsvpcConfiguration>,
}
#[derive(Clone, Deserialize)]
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
}

enum EcsError {
    Serialization(String),
    Client(String),
    ClusterNotFound(String),
    UnknownOperation,
    Internal,
}
impl From<EcsError> for AwsError {
    fn from(value: EcsError) -> Self {
        match value {
            EcsError::Serialization(message) => {
                AwsError::new("SerializationException", message, 400)
            }
            EcsError::Client(message) => AwsError::new("ClientException", message, 400),
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
        match self.process_async(&request).await {
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
