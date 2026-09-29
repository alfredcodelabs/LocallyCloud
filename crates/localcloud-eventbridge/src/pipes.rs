use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use axum::body::to_bytes;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use serde_json::{json, Value};
use tokio::task::JoinHandle;

use localcloud_core::integration::identity::{CallerIdentity, IdentityPropagator};
use localcloud_core::registry::ServiceRegistry;

use crate::arn::EbArn;
use crate::delivery::{self, DeliveryRequest};
use crate::error::PipesError;
use crate::http_client::HttpClient;
use crate::model::{Pipe, RetryPolicy};
use crate::pattern;
use crate::store::EbStore;
use crate::transform;

#[path = "pipe_persistence.rs"]
mod pipe_persistence;

pub struct PipesService {
    pub store: Arc<EbStore>,
    registry: Weak<ServiceRegistry>,
    http: Arc<dyn HttpClient>,
    workers: Mutex<HashMap<String, JoinHandle<()>>>,
}

impl PipesService {
    pub fn restore(&self) -> Result<(), String> {
        let Some(db) = self.store.state_db() else {
            return Ok(());
        };
        for (account, region, pipe) in pipe_persistence::load(&db)? {
            self.store.restore_pipe(account, region, pipe)?;
        }
        Ok(())
    }

    pub async fn resume_workers(&self) {
        for (account, region) in self.store.scope_keys() {
            let scope = self.store.scope(&account, &region).await;
            let pipes: Vec<_> = scope.read().await.pipes.values().cloned().collect();
            for pipe in pipes {
                self.reconcile(&account, &region, &pipe);
            }
        }
    }

    pub fn new(
        store: Arc<EbStore>,
        registry: Weak<ServiceRegistry>,
        http: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            store,
            registry,
            http,
            workers: Mutex::new(HashMap::new()),
        }
    }

    pub async fn dispatch(
        &self,
        operation: &str,
        path_value: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, PipesError> {
        self.reap_finished_workers();
        let result = match operation {
            "CreatePipe" => self.create(path_value, account, region, body).await,
            "DescribePipe" => self.describe(path_value, account, region).await,
            "UpdatePipe" => self.update(path_value, account, region, body).await,
            "DeletePipe" => self.delete(path_value, account, region).await,
            "ListPipes" => self.list(account, region, body).await,
            "StartPipe" => self.set_running(path_value, account, region, true).await,
            "StopPipe" => self.set_running(path_value, account, region, false).await,
            "TagResource" => self.tag(path_value, account, region, body).await,
            "UntagResource" => self.untag(path_value, account, region, body).await,
            "ListTagsForResource" => self.list_tags(path_value, account, region).await,
            _ => Err(PipesError::NotFound("route not found".into())),
        };
        self.reap_finished_workers();
        result
    }
}

impl Drop for PipesService {
    fn drop(&mut self) {
        if let Ok(mut workers) = self.workers.lock() {
            for (_, worker) in workers.drain() {
                worker.abort();
            }
        }
    }
}

fn required_name(value: Option<&str>) -> Result<&str, PipesError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| PipesError::Validation("Name is required".into()))
}
fn required<'a>(body: &'a Value, key: &str) -> Result<&'a str, PipesError> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| PipesError::Validation(format!("{key} is required")))
}
fn valid_pipe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
fn pipe_tags(body: &Value) -> BTreeMap<String, String> {
    let values = body.get("tags").or_else(|| body.get("Tags"));
    if let Some(map) = values.and_then(Value::as_object) {
        return map
            .iter()
            .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.into())))
            .collect();
    }
    values
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tag| {
            Some((
                tag.get("Key")?.as_str()?.into(),
                tag.get("Value")?.as_str()?.into(),
            ))
        })
        .collect()
}
fn validate_source(value: &str) -> Result<(), PipesError> {
    if value.contains(":sqs:")
        || value.contains(":dynamodb:") && value.contains("/stream/")
        || value.contains(":kinesis:") && value.contains(":stream/")
    {
        Ok(())
    } else {
        Err(PipesError::Validation(
            "Source must be an SQS queue, DynamoDB stream, or Kinesis stream ARN".into(),
        ))
    }
}

fn validate_target(value: &str) -> Result<(), PipesError> {
    if [":lambda:", ":sqs:", ":sns:", ":states:"]
        .iter()
        .any(|service| value.contains(service))
        || value.contains(":events:") && value.contains(":event-bus/")
    {
        Ok(())
    } else {
        Err(PipesError::Validation(
            "Target must be Lambda, SQS, SNS, Step Functions, or an EventBridge bus".into(),
        ))
    }
}

fn validate_enrichment(value: Option<&str>) -> Result<(), PipesError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.contains(":lambda:")
        || value.contains(":states:")
        || value.contains(":events:") && value.contains(":api-destination/")
    {
        Ok(())
    } else {
        Err(PipesError::Validation(
            "Enrichment must be Lambda, Step Functions, or an API destination".into(),
        ))
    }
}
fn filter_values(parameters: &Value) -> Vec<&Value> {
    let direct = parameters.get("FilterCriteria");
    let nested = parameters
        .as_object()
        .and_then(|map| map.values().find_map(|value| value.get("FilterCriteria")));
    direct
        .or(nested)
        .and_then(|criteria| criteria.get("Filters"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .collect()
}
fn validate_filters(parameters: &Value) -> Result<(), PipesError> {
    for filter in filter_values(parameters) {
        let raw = filter
            .get("Pattern")
            .and_then(Value::as_str)
            .ok_or_else(|| PipesError::Validation("Filter.Pattern is required".into()))?;
        let value: Value = serde_json::from_str(raw)
            .map_err(|_| PipesError::Validation("filter pattern must be valid JSON".into()))?;
        pattern::compile(&value).map_err(|error| PipesError::Validation(error.to_string()))?;
    }
    Ok(())
}

fn validate_source_parameters(source: &str, parameters: &Value) -> Result<(), PipesError> {
    let batch = find_number(parameters, "BatchSize");
    if source.contains(":sqs:") {
        if batch.is_some_and(|value| !(1..=10).contains(&value)) {
            return Err(PipesError::Validation(
                "SQS BatchSize must be between 1 and 10".into(),
            ));
        }
        return Ok(());
    }
    if batch.is_some_and(|value| !(1..=10_000).contains(&value)) {
        return Err(PipesError::Validation(
            "stream BatchSize must be between 1 and 10000".into(),
        ));
    }
    if let Some(position) = find_string(parameters, "StartingPosition") {
        let valid = if source.contains(":dynamodb:") {
            matches!(position, "TRIM_HORIZON" | "LATEST")
        } else {
            matches!(position, "TRIM_HORIZON" | "LATEST" | "AT_TIMESTAMP")
        };
        if !valid {
            return Err(PipesError::Validation(
                "invalid stream StartingPosition".into(),
            ));
        }
        if position == "AT_TIMESTAMP"
            && find_value(parameters, "StartingPositionTimestamp").is_none()
        {
            return Err(PipesError::Validation(
                "StartingPositionTimestamp is required for AT_TIMESTAMP".into(),
            ));
        }
    }
    Ok(())
}
impl PipesService {
    async fn create(
        &self,
        path_name: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, PipesError> {
        let name = required_name(path_name)?;
        if !valid_pipe_name(name) {
            return Err(PipesError::Validation("invalid pipe name".into()));
        }
        let source = required(body, "Source")?.to_string();
        validate_source(&source)?;
        let target = required(body, "Target")?.to_string();
        validate_target(&target)?;
        validate_enrichment(body.get("Enrichment").and_then(Value::as_str))?;
        let role_arn = required(body, "RoleArn")?.to_string();
        let source_parameters = body
            .get("SourceParameters")
            .cloned()
            .unwrap_or_else(|| json!({}));
        validate_filters(&source_parameters)?;
        validate_source_parameters(&source, &source_parameters)?;
        let desired = body
            .get("DesiredState")
            .and_then(Value::as_str)
            .unwrap_or("RUNNING");
        if !matches!(desired, "RUNNING" | "STOPPED") {
            return Err(PipesError::Validation("invalid DesiredState".into()));
        }
        let scope = self.store.scope(account, region).await;
        let mut state = scope.write().await;
        if state.pipes.contains_key(name) {
            return Err(PipesError::Conflict(format!("Pipe {name} already exists")));
        }
        let arn = EbArn::Pipe {
            region: region.into(),
            account: account.into(),
            name: name.into(),
        }
        .to_string();
        let pipe = Pipe {
            name: name.into(),
            arn: arn.clone(),
            description: body
                .get("Description")
                .and_then(Value::as_str)
                .map(str::to_string),
            source,
            source_parameters,
            enrichment: body
                .get("Enrichment")
                .and_then(Value::as_str)
                .map(str::to_string),
            enrichment_parameters: body
                .get("EnrichmentParameters")
                .cloned()
                .unwrap_or_else(|| json!({})),
            target,
            target_parameters: body
                .get("TargetParameters")
                .cloned()
                .unwrap_or_else(|| json!({})),
            role_arn,
            desired_state: desired.into(),
            current_state: "CREATING".into(),
            tags: pipe_tags(body),
            generation: 1,
            source_checkpoints: BTreeMap::new(),
        };
        pipe_persistence::save(self.store.state_db(), account, region, &pipe)
            .map_err(PipesError::Internal)?;
        state.pipes.insert(name.into(), pipe.clone());
        drop(state);
        self.reconcile(account, region, &pipe);
        Ok(json!({"Arn":arn,"Name":name,"DesiredState":desired,"CurrentState":pipe.current_state}))
    }
    async fn describe(
        &self,
        path_name: Option<&str>,
        account: &str,
        region: &str,
    ) -> Result<Value, PipesError> {
        let name = required_name(path_name)?;
        let scope = self.store.scope(account, region).await;
        let state = scope.read().await;
        let pipe = state
            .pipes
            .get(name)
            .ok_or_else(|| PipesError::NotFound(format!("Pipe {name} does not exist")))?;
        Ok(pipe_json(pipe))
    }
    async fn update(
        &self,
        path_name: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, PipesError> {
        let name = required_name(path_name)?;
        let scope = self.store.scope(account, region).await;
        let mut state = scope.write().await;
        let pipe = state
            .pipes
            .get_mut(name)
            .ok_or_else(|| PipesError::NotFound(format!("Pipe {name} does not exist")))?;
        if let Some(value) = body.get("SourceParameters") {
            validate_filters(value)?;
            validate_source_parameters(&pipe.source, value)?;
        }
        if let Some(value) = body.get("Target").and_then(Value::as_str) {
            validate_target(value)?;
        }
        if body.get("Enrichment").is_some() {
            validate_enrichment(body.get("Enrichment").and_then(Value::as_str))?;
        }
        if body
            .get("Target")
            .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
        {
            return Err(PipesError::Validation("Target must not be empty".into()));
        }
        if body
            .get("RoleArn")
            .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
        {
            return Err(PipesError::Validation("RoleArn must not be empty".into()));
        }
        if let Some(value) = body.get("DesiredState").and_then(Value::as_str) {
            if !matches!(value, "RUNNING" | "STOPPED") {
                return Err(PipesError::Validation("invalid DesiredState".into()));
            }
        }
        let mut pipe = pipe.clone();
        pipe.current_state = "UPDATING".into();
        if body.get("Description").is_some() {
            pipe.description = body
                .get("Description")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        if let Some(value) = body.get("SourceParameters") {
            pipe.source_parameters = value.clone();
            pipe.source_checkpoints.clear();
        }
        if body.get("Enrichment").is_some() {
            pipe.enrichment = body
                .get("Enrichment")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        if let Some(value) = body.get("EnrichmentParameters") {
            pipe.enrichment_parameters = value.clone();
        }
        if let Some(value) = body.get("Target").and_then(Value::as_str) {
            pipe.target = value.into();
        }
        if let Some(value) = body.get("TargetParameters") {
            pipe.target_parameters = value.clone();
        }
        if let Some(value) = body.get("RoleArn").and_then(Value::as_str) {
            pipe.role_arn = value.into();
        }
        if let Some(value) = body.get("DesiredState").and_then(Value::as_str) {
            pipe.desired_state = value.into();
        }
        pipe.generation += 1;
        pipe_persistence::save(self.store.state_db(), account, region, &pipe)
            .map_err(PipesError::Internal)?;
        let updated = pipe.clone();
        state.pipes.insert(name.into(), pipe);
        drop(state);
        self.reconcile(account, region, &updated);
        Ok(
            json!({"Arn":updated.arn,"Name":updated.name,"DesiredState":updated.desired_state,"CurrentState":updated.current_state}),
        )
    }
    async fn delete(
        &self,
        path_name: Option<&str>,
        account: &str,
        region: &str,
    ) -> Result<Value, PipesError> {
        let name = required_name(path_name)?;
        let scope = self.store.scope(account, region).await;
        let mut state = scope.write().await;
        let removed = state
            .pipes
            .get(name)
            .ok_or_else(|| PipesError::NotFound(format!("Pipe {name} does not exist")))?
            .clone();
        pipe_persistence::delete(self.store.state_db(), account, region, name)
            .map_err(PipesError::Internal)?;
        state.pipes.remove(name);
        drop(state);
        self.abort(&worker_key(account, region, name));
        Ok(
            json!({"Arn":removed.arn,"Name":name,"DesiredState":"STOPPED","CurrentState":"DELETING"}),
        )
    }
    async fn list(&self, account: &str, region: &str, body: &Value) -> Result<Value, PipesError> {
        let max_results = body
            .get("MaxResults")
            .and_then(Value::as_u64)
            .unwrap_or(100);
        if !(1..=100).contains(&max_results) {
            return Err(PipesError::Validation(
                "MaxResults must be between 1 and 100".into(),
            ));
        }
        let scope = self.store.scope(account, region).await;
        let state = scope.read().await;
        let prefix = body.get("NamePrefix").and_then(Value::as_str).unwrap_or("");
        let desired = body.get("DesiredState").and_then(Value::as_str);
        let current = body.get("CurrentState").and_then(Value::as_str);
        let source = body.get("SourcePrefix").and_then(Value::as_str);
        let target = body.get("TargetPrefix").and_then(Value::as_str);
        let next_token = body.get("NextToken").and_then(Value::as_str);
        let mut pipes: Vec<_> = state
            .pipes
            .values()
            .filter(|pipe| {
                pipe.name.starts_with(prefix)
                    && next_token.is_none_or(|token| pipe.name.as_str() > token)
                    && desired.is_none_or(|value| value == pipe.desired_state)
                    && current.is_none_or(|value| value == pipe.current_state)
                    && source.is_none_or(|value| pipe.source.starts_with(value))
                    && target.is_none_or(|value| pipe.target.starts_with(value))
            })
            .take(max_results as usize + 1)
            .map(pipe_summary)
            .collect();
        let next_token = if pipes.len() > max_results as usize {
            pipes.truncate(max_results as usize);
            pipes
                .last()
                .and_then(|pipe| pipe.get("Name"))
                .and_then(Value::as_str)
                .map(str::to_string)
        } else {
            None
        };
        let mut response = json!({"Pipes":pipes});
        if let Some(token) = next_token {
            response["NextToken"] = json!(token);
        }
        Ok(response)
    }
    async fn set_running(
        &self,
        path_name: Option<&str>,
        account: &str,
        region: &str,
        running: bool,
    ) -> Result<Value, PipesError> {
        let name = required_name(path_name)?;
        let scope = self.store.scope(account, region).await;
        let mut state = scope.write().await;
        let pipe = state
            .pipes
            .get_mut(name)
            .ok_or_else(|| PipesError::NotFound(format!("Pipe {name} does not exist")))?;
        let mut pipe = pipe.clone();
        pipe.desired_state = if running { "RUNNING" } else { "STOPPED" }.into();
        pipe.current_state = if running { "STARTING" } else { "STOPPING" }.into();
        pipe.generation += 1;
        pipe_persistence::save(self.store.state_db(), account, region, &pipe)
            .map_err(PipesError::Internal)?;
        let updated = pipe.clone();
        state.pipes.insert(name.into(), pipe);
        drop(state);
        self.reconcile(account, region, &updated);
        Ok(
            json!({"Arn":updated.arn,"Name":updated.name,"DesiredState":updated.desired_state,"CurrentState":updated.current_state}),
        )
    }
}
impl PipesService {
    async fn tag(
        &self,
        arn: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, PipesError> {
        let supplied = pipe_tags(body);
        self.mutate_tags(arn, account, region, |tags| tags.extend(supplied))
            .await?;
        Ok(json!({}))
    }
    async fn untag(
        &self,
        arn: Option<&str>,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Value, PipesError> {
        let keys: Vec<_> = body
            .get("TagKeys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        self.mutate_tags(arn, account, region, |tags| {
            tags.retain(|key, _| !keys.contains(key))
        })
        .await?;
        Ok(json!({}))
    }
    async fn list_tags(
        &self,
        arn: Option<&str>,
        account: &str,
        region: &str,
    ) -> Result<Value, PipesError> {
        let arn = required_name(arn)?;
        let parsed =
            EbArn::parse(arn).map_err(|_| PipesError::NotFound("pipe does not exist".into()))?;
        if parsed.account() != account || parsed.region() != region {
            return Err(PipesError::NotFound("pipe does not exist".into()));
        }
        let EbArn::Pipe { name, .. } = parsed else {
            return Err(PipesError::NotFound("pipe does not exist".into()));
        };
        let scope = self.store.scope(account, region).await;
        let state = scope.read().await;
        let pipe = state
            .pipes
            .get(&name)
            .ok_or_else(|| PipesError::NotFound("pipe does not exist".into()))?;
        Ok(json!({"tags":pipe.tags}))
    }
    async fn mutate_tags(
        &self,
        arn: Option<&str>,
        account: &str,
        region: &str,
        mutation: impl FnOnce(&mut BTreeMap<String, String>),
    ) -> Result<(), PipesError> {
        let arn = required_name(arn)?;
        let parsed =
            EbArn::parse(arn).map_err(|_| PipesError::NotFound("pipe does not exist".into()))?;
        if parsed.account() != account || parsed.region() != region {
            return Err(PipesError::NotFound("pipe does not exist".into()));
        }
        let EbArn::Pipe { name, .. } = parsed else {
            return Err(PipesError::NotFound("pipe does not exist".into()));
        };
        let scope = self.store.scope(account, region).await;
        let mut state = scope.write().await;
        let pipe = state
            .pipes
            .get_mut(&name)
            .ok_or_else(|| PipesError::NotFound("pipe does not exist".into()))?;
        let mut updated = pipe.clone();
        mutation(&mut updated.tags);
        pipe_persistence::save(self.store.state_db(), account, region, &updated)
            .map_err(PipesError::Internal)?;
        *pipe = updated;
        Ok(())
    }

    fn reconcile(&self, account: &str, region: &str, pipe: &Pipe) {
        let key = worker_key(account, region, &pipe.name);
        self.abort(&key);
        let store = self.store.clone();
        let account = account.to_string();
        let region = region.to_string();
        let item = pipe.clone();
        if item.desired_state != "RUNNING" {
            let worker = tokio::spawn(async move {
                tokio::task::yield_now().await;
                let scope = store.scope(&account, &region).await;
                let mut state = scope.write().await;
                let Some(stored) = state.pipes.get_mut(&item.name) else {
                    return;
                };
                if stored.generation == item.generation
                    && stored.desired_state == item.desired_state
                {
                    stored.current_state = "STOPPED".into();
                }
            });
            if let Ok(mut workers) = self.workers.lock() {
                workers.retain(|_, worker| !worker.is_finished());
                workers.insert(key, worker);
            }
            return;
        }

        let registry = self.registry.clone();
        let http = self.http.clone();
        let worker = tokio::spawn(async move {
            tokio::task::yield_now().await;
            let scope = store.scope(&account, &region).await;
            {
                let mut state = scope.write().await;
                let Some(stored) = state.pipes.get_mut(&item.name) else {
                    return;
                };
                if stored.generation != item.generation
                    || stored.desired_state != item.desired_state
                {
                    return;
                }
                stored.current_state = "RUNNING".into();
            }
            loop {
                let scope = store.scope(&account, &region).await;
                let current = { scope.read().await.pipes.get(&item.name).cloned() };
                let Some(current) = current.filter(|value| {
                    value.current_state == "RUNNING" && value.generation == item.generation
                }) else {
                    break;
                };
                let Some(registry) = registry.upgrade() else {
                    break;
                };
                let batch = match poll_source(&registry, &current, &region, &account).await {
                    Ok(batch) => batch,
                    Err(()) => {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        continue;
                    }
                };
                for record in &batch.records {
                    if !process_record(
                        &registry,
                        &store,
                        http.as_ref(),
                        &current,
                        record,
                        &region,
                        &account,
                    )
                    .await
                    {
                        break;
                    }
                    if let Some((shard, sequence)) = &record.stream_checkpoint {
                        let scope = store.scope(&account, &region).await;
                        let mut state = scope.write().await;
                        if let Some(stored) = state.pipes.get(&item.name) {
                            if stored.generation != item.generation {
                                break;
                            }
                            let mut updated = stored.clone();
                            updated
                                .source_checkpoints
                                .insert(shard.clone(), sequence.clone());
                            if let Err(error) = pipe_persistence::save(
                                store.state_db(),
                                &account,
                                &region,
                                &updated,
                            ) {
                                tracing::warn!(%error, pipe = %item.name, "pipe checkpoint commit failed");
                                break;
                            }
                            state.pipes.insert(item.name.clone(), updated);
                        } else {
                            break;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
        if let Ok(mut workers) = self.workers.lock() {
            workers.retain(|_, worker| !worker.is_finished());
            workers.insert(key, worker);
        }
    }
    fn abort(&self, key: &str) {
        if let Ok(mut workers) = self.workers.lock() {
            workers.retain(|_, worker| !worker.is_finished());
            if let Some(worker) = workers.remove(key) {
                worker.abort();
            }
        }
    }

    fn reap_finished_workers(&self) {
        if let Ok(mut workers) = self.workers.lock() {
            workers.retain(|_, worker| !worker.is_finished());
        }
    }
}

fn worker_key(account: &str, region: &str, name: &str) -> String {
    format!("{account}:{region}:{name}")
}
fn pipe_json(pipe: &Pipe) -> Value {
    let mut value = json!({"Name":pipe.name,"Arn":pipe.arn,"Source":pipe.source,"SourceParameters":pipe.source_parameters,"Enrichment":pipe.enrichment,"EnrichmentParameters":pipe.enrichment_parameters,"Target":pipe.target,"TargetParameters":pipe.target_parameters,"RoleArn":pipe.role_arn,"DesiredState":pipe.desired_state,"CurrentState":pipe.current_state});
    if let Some(description) = &pipe.description {
        value["Description"] = json!(description);
    }
    value
}
fn pipe_summary(pipe: &Pipe) -> Value {
    let mut value = json!({"Name":pipe.name,"Arn":pipe.arn,"Source":pipe.source,"Target":pipe.target,"DesiredState":pipe.desired_state,"CurrentState":pipe.current_state});
    if let Some(description) = &pipe.description {
        value["Description"] = json!(description);
    }
    value
}

#[derive(Clone)]
struct PolledRecord {
    payload: Value,
    receipt: Option<String>,
    stream_checkpoint: Option<(String, String)>,
}

struct PollBatch {
    records: Vec<PolledRecord>,
}

async fn poll_source(
    registry: &ServiceRegistry,
    pipe: &Pipe,
    region: &str,
    account: &str,
) -> Result<PollBatch, ()> {
    if pipe.source.contains(":sqs:") {
        let name = pipe.source.rsplit(':').next().ok_or(())?;
        let queue_region = pipe.source.split(':').nth(3).unwrap_or(region);
        let queue_account = pipe.source.split(':').nth(4).unwrap_or(account);
        let url = format!("https://sqs.{queue_region}.amazonaws.com/{queue_account}/{name}");
        let batch = find_number(&pipe.source_parameters, "BatchSize").unwrap_or(10);
        let response = dispatch_json(
            registry,
            pipe,
            account,
            "sqs",
            "AmazonSQS.ReceiveMessage",
            json!({"QueueUrl":url,"MaxNumberOfMessages":batch}),
            region,
        )
        .await?;
        let records = response
            .get("Messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|message| {
                let body = message
                    .get("Body")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let parsed = serde_json::from_str(body)
                    .unwrap_or_else(|_| Value::String(body.into()));
                PolledRecord {
                    payload: json!({"body":parsed,"messageId":message.get("MessageId"),"attributes":message.get("Attributes")}),
                    receipt: message
                        .get("ReceiptHandle")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    stream_checkpoint: None,
                }
            })
            .collect();
        return Ok(PollBatch { records });
    }

    let shards = discover_stream_shards(registry, pipe, region, account).await?;
    let (service, target) = if pipe.source.contains(":kinesis:") {
        ("kinesis", "Kinesis_20131202.GetRecords")
    } else {
        ("dynamodb", "DynamoDBStreams_20120810.GetRecords")
    };
    let mut records = Vec::new();
    for shard in shards {
        let cursor = create_stream_iterator(registry, pipe, region, account, &shard).await?;
        let response = dispatch_json(
            registry,
            pipe,
            account,
            service,
            target,
            json!({"ShardIterator":cursor,"Limit":find_number(&pipe.source_parameters,"BatchSize").unwrap_or(100)}),
            region,
        )
        .await?;
        for payload in response
            .get("Records")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .cloned()
        {
            let sequence = stream_sequence(pipe, &payload).ok_or(())?.to_string();
            records.push(PolledRecord {
                payload,
                receipt: None,
                stream_checkpoint: Some((shard.clone(), sequence)),
            });
        }
    }
    Ok(PollBatch { records })
}

async fn discover_stream_shards(
    registry: &ServiceRegistry,
    pipe: &Pipe,
    region: &str,
    account: &str,
) -> Result<Vec<String>, ()> {
    let kinesis = pipe.source.contains(":kinesis:");
    let (service, target) = if kinesis {
        ("kinesis", "Kinesis_20131202.DescribeStream")
    } else {
        ("dynamodb", "DynamoDBStreams_20120810.DescribeStream")
    };
    let mut shards = Vec::new();
    let mut exclusive_start: Option<String> = None;
    loop {
        let mut request = if kinesis {
            json!({"StreamName":kinesis_stream_name(&pipe.source).ok_or(())?})
        } else {
            json!({"StreamArn":pipe.source})
        };
        if let Some(shard) = &exclusive_start {
            request["ExclusiveStartShardId"] = json!(shard);
        }
        let description =
            dispatch_json(registry, pipe, account, service, target, request, region).await?;
        let page = stream_shard_ids(&description)?;
        let next = if kinesis {
            if description
                .pointer("/StreamDescription/HasMoreShards")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                Some(page.last().cloned().ok_or(())?)
            } else {
                None
            }
        } else {
            description
                .pointer("/StreamDescription/LastEvaluatedShardId")
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        shards.extend(page);
        let Some(next) = next else {
            break;
        };
        if exclusive_start.as_deref() == Some(&next) {
            return Err(());
        }
        exclusive_start = Some(next);
    }
    Ok(shards)
}

async fn create_stream_iterator(
    registry: &ServiceRegistry,
    pipe: &Pipe,
    region: &str,
    account: &str,
    shard_id: &str,
) -> Result<String, ()> {
    let kinesis = pipe.source.contains(":kinesis:");
    let (service, target) = if kinesis {
        ("kinesis", "Kinesis_20131202.GetShardIterator")
    } else {
        ("dynamodb", "DynamoDBStreams_20120810.GetShardIterator")
    };
    let mut request = if kinesis {
        json!({"StreamName":kinesis_stream_name(&pipe.source).ok_or(())?,"ShardId":shard_id})
    } else {
        json!({"StreamArn":pipe.source,"ShardId":shard_id})
    };
    if let Some(sequence) = pipe.source_checkpoints.get(shard_id) {
        request["ShardIteratorType"] = json!("AFTER_SEQUENCE_NUMBER");
        if kinesis {
            request["StartingSequenceNumber"] = json!(sequence);
        } else {
            request["SequenceNumber"] = json!(sequence);
        }
    } else {
        let position = find_string(&pipe.source_parameters, "StartingPosition").unwrap_or("LATEST");
        request["ShardIteratorType"] = json!(position);
        if position == "AT_TIMESTAMP" {
            request["Timestamp"] = find_value(&pipe.source_parameters, "StartingPositionTimestamp")
                .cloned()
                .ok_or(())?;
        }
    }
    dispatch_json(registry, pipe, account, service, target, request, region)
        .await?
        .get("ShardIterator")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or(())
}

fn kinesis_stream_name(arn: &str) -> Option<&str> {
    arn.splitn(6, ':')
        .nth(5)?
        .strip_prefix("stream/")
        .filter(|name| !name.is_empty() && !name.contains('/'))
}

fn stream_sequence<'a>(pipe: &Pipe, record: &'a Value) -> Option<&'a str> {
    if pipe.source.contains(":kinesis:") {
        record.get("SequenceNumber").and_then(Value::as_str)
    } else {
        record
            .pointer("/dynamodb/SequenceNumber")
            .and_then(Value::as_str)
    }
}

fn stream_shard_ids(description: &Value) -> Result<Vec<String>, ()> {
    description
        .pointer("/StreamDescription/Shards")
        .and_then(Value::as_array)
        .ok_or(())?
        .iter()
        .map(|shard| {
            shard
                .get("ShardId")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or(())
        })
        .collect()
}
async fn process_record(
    registry: &ServiceRegistry,
    store: &EbStore,
    http: &dyn HttpClient,
    pipe: &Pipe,
    record: &PolledRecord,
    region: &str,
    account: &str,
) -> bool {
    if !record_matches(pipe, &record.payload) {
        return match &record.receipt {
            Some(receipt) => delete_sqs_message(registry, pipe, receipt, region, account).await,
            None => true,
        };
    }
    let mut payload = record.payload.clone();
    if let Some(enrichment) = &pipe.enrichment {
        let enrichment_payload = find_string(&pipe.enrichment_parameters, "InputTemplate")
            .map(|template| apply_pipe_template(template, &payload))
            .unwrap_or_else(|| payload.to_string());
        let enriched = if let Ok(EbArn::ApiDestination {
            name,
            region: arn_region,
            account: arn_account,
        }) = EbArn::parse(enrichment)
        {
            if arn_region != region || arn_account != account {
                return handle_record_failure(registry, pipe, record, region, account).await;
            }
            let scope = store.scope(account, region).await;
            let configuration = {
                let state = scope.read().await;
                state.api_destinations.get(&name).and_then(|destination| {
                    state
                        .connections
                        .values()
                        .find(|connection| connection.arn == destination.connection_arn)
                        .map(|connection| (destination.clone(), connection.clone()))
                })
            };
            let Some((destination, connection)) = configuration else {
                return handle_record_failure(registry, pipe, record, region, account).await;
            };
            match crate::events::invoke_api_destination(
                http,
                &destination,
                &connection,
                &enrichment_payload,
            )
            .await
            {
                crate::events::ApiDelivery::Success(value) => value,
                _ => return handle_record_failure(registry, pipe, record, region, account).await,
            }
        } else {
            let Ok(value) = invoke_sync_enrichment(
                registry,
                pipe,
                enrichment,
                enrichment_payload,
                region,
                account,
            )
            .await
            else {
                return handle_record_failure(registry, pipe, record, region, account).await;
            };
            value
        };
        payload = enriched;
    }
    if let Some(template) = find_string(&pipe.target_parameters, "InputTemplate") {
        let transformed = apply_pipe_template(template, &payload);
        payload = serde_json::from_str(&transformed).unwrap_or(Value::String(transformed));
    }
    let request = DeliveryRequest {
        source_service: "pipes",
        arn: pipe.target.clone(),
        payload: match payload {
            Value::String(value) => value,
            other => other.to_string(),
        },
        role_arn: Some(pipe.role_arn.clone()),
        sqs_parameters: find_value(&pipe.target_parameters, "SqsQueueParameters").cloned(),
        target_parameters: Some(pipe.target_parameters.clone()),
        retry: RetryPolicy {
            maximum_attempts: find_number(&pipe.source_parameters, "MaximumRetryAttempts")
                .unwrap_or(0)
                .min(u64::from(u32::MAX)) as u32,
            maximum_age_seconds: find_number(&pipe.source_parameters, "MaximumRecordAgeInSeconds"),
        },
        dead_letter_arn: None,
        scheduled_at: None,
    };
    if delivery::deliver(registry, &request, region, account)
        .await
        .is_ok()
    {
        return match &record.receipt {
            Some(receipt) => delete_sqs_message(registry, pipe, receipt, region, account).await,
            None => true,
        };
    }
    handle_record_failure(registry, pipe, record, region, account).await
}

async fn invoke_sync_enrichment(
    registry: &ServiceRegistry,
    pipe: &Pipe,
    arn: &str,
    payload: String,
    region: &str,
    account: &str,
) -> Result<Value, ()> {
    let request = DeliveryRequest {
        source_service: "pipes",
        arn: arn.into(),
        payload,
        role_arn: Some(pipe.role_arn.clone()),
        sqs_parameters: None,
        target_parameters: Some(pipe.enrichment_parameters.clone()),
        retry: RetryPolicy {
            maximum_attempts: 0,
            maximum_age_seconds: None,
        },
        dead_letter_arn: None,
        scheduled_at: None,
    };
    delivery::deliver_sync(registry, &request, region, account)
        .await
        .map_err(|_| ())
}

async fn handle_record_failure(
    registry: &ServiceRegistry,
    pipe: &Pipe,
    record: &PolledRecord,
    region: &str,
    account: &str,
) -> bool {
    if record.receipt.is_some() {
        return false;
    }
    let Some(arn) = source_dlq_arn(&pipe.source_parameters) else {
        return false;
    };
    let dlq = DeliveryRequest {
        source_service: "pipes",
        arn: arn.into(),
        payload: record.payload.to_string(),
        role_arn: Some(pipe.role_arn.clone()),
        sqs_parameters: None,
        target_parameters: None,
        retry: RetryPolicy {
            maximum_attempts: 0,
            maximum_age_seconds: None,
        },
        dead_letter_arn: None,
        scheduled_at: None,
    };
    delivery::deliver(registry, &dlq, region, account)
        .await
        .is_ok()
}

async fn delete_sqs_message(
    registry: &ServiceRegistry,
    pipe: &Pipe,
    receipt: &str,
    region: &str,
    account: &str,
) -> bool {
    let name = pipe.source.rsplit(':').next().unwrap_or_default();
    let queue_region = pipe.source.split(':').nth(3).unwrap_or(region);
    let queue_account = pipe.source.split(':').nth(4).unwrap_or(account);
    let url = format!("https://sqs.{queue_region}.amazonaws.com/{queue_account}/{name}");
    dispatch_json(
        registry,
        pipe,
        account,
        "sqs",
        "AmazonSQS.DeleteMessage",
        json!({"QueueUrl":url,"ReceiptHandle":receipt}),
        region,
    )
    .await
    .is_ok()
}

fn source_dlq_arn(parameters: &Value) -> Option<&str> {
    find_value(parameters, "DeadLetterConfig")?
        .get("Arn")
        .and_then(Value::as_str)
}

fn record_matches(pipe: &Pipe, record: &Value) -> bool {
    let filters = filter_values(&pipe.source_parameters);
    filters.is_empty()
        || filters.into_iter().any(|filter| {
            filter
                .get("Pattern")
                .and_then(Value::as_str)
                .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                .and_then(|value| pattern::compile(&value).ok())
                .is_some_and(|compiled| pattern::matches(&compiled, record))
        })
}
fn apply_pipe_template(template: &str, payload: &Value) -> String {
    let mut output = template.to_string();
    while let Some(start) = output.find("<$") {
        let Some(relative_end) = output[start..].find('>') else {
            break;
        };
        let end = start + relative_end;
        let path = &output[start + 1..end];
        let value = transform::extract(payload, path);
        let replacement = match value {
            Value::String(value) => value,
            Value::Null => String::new(),
            other => other.to_string(),
        };
        output.replace_range(start..=end, &replacement);
    }
    output
}
fn find_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    if let Some(found) = value.get(key) {
        return Some(found);
    }
    value
        .as_object()?
        .values()
        .find_map(|child| find_value(child, key))
}
fn find_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    find_value(value, key).and_then(Value::as_str)
}
fn find_number(value: &Value, key: &str) -> Option<u64> {
    find_value(value, key).and_then(Value::as_u64)
}

async fn dispatch_json(
    registry: &ServiceRegistry,
    pipe: &Pipe,
    account: &str,
    service: &str,
    target: &str,
    body: Value,
    region: &str,
) -> Result<Value, ()> {
    let action = target.rsplit('.').next().ok_or(())?;
    let permission = format!("{service}:{action}");
    if !delivery::authorize_role_execution(
        registry,
        Some(&pipe.role_arn),
        "pipes",
        &permission,
        &pipe.source,
        account,
    ) {
        return Err(());
    }
    let dispatcher = registry.internal_dispatcher().ok_or(())?;
    let mut headers = HeaderMap::new();
    IdentityPropagator::attach(
        &mut headers,
        &CallerIdentity::AssumedRole {
            role_arn: pipe.role_arn.clone(),
            session_name: "eventbridge".into(),
        },
    );
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(target).map_err(|_| ())?,
    );
    headers.insert(
        "content-type",
        HeaderValue::from_static(if service == "kinesis" {
            "application/x-amz-json-1.1"
        } else {
            "application/x-amz-json-1.0"
        }),
    );
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential=localcloud/19700101/{region}/{service}/aws4_request"
        ))
        .map_err(|_| ())?,
    );
    let uri: Uri = "/".parse().map_err(|_| ())?;
    let response = dispatcher
        .dispatch_scoped(
            &Method::POST,
            &uri,
            &headers,
            Bytes::from(body.to_string()),
            &uuid::Uuid::new_v4().to_string(),
            account,
            region,
        )
        .await;
    if !response.status().is_success() {
        return Err(());
    }
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(|_| ())?;
    if bytes.is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_slice(&bytes).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::response::Response;
    use localcloud_core::handler::{NativeHandler, ServiceRequest};
    use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName};

    #[tokio::test]
    async fn pipe_config_tags_and_checkpoint_survive_restart() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let db =
            Arc::new(localcloud_state::StateDb::open(root.path().join("state.sqlite3")).unwrap());
        let account = "000000000000";
        let region = "us-east-1";
        let store = Arc::new(EbStore::with_state(db.clone()).unwrap());
        let service = PipesService::new(
            store.clone(),
            Weak::new(),
            Arc::new(crate::http_client::CurlHttpClient),
        );
        service.restore().unwrap();
        service
            .dispatch(
                "CreatePipe",
                Some("durable"),
                account,
                region,
                &json!({
                    "Source":"arn:aws:kinesis:us-east-1:000000000000:stream/source",
                    "Target":"arn:aws:sqs:us-east-1:000000000000:target",
                    "RoleArn":"arn:aws:iam::000000000000:role/pipe",
                    "DesiredState":"STOPPED",
                    "Tags":{"owner":"data"}
                }),
            )
            .await
            .unwrap();
        service
            .dispatch(
                "UpdatePipe",
                Some("durable"),
                account,
                region,
                &json!({"Target":"arn:aws:sqs:us-east-1:000000000000:updated"}),
            )
            .await
            .unwrap();
        let arn = "arn:aws:pipes:us-east-1:000000000000:pipe/durable";
        service
            .dispatch(
                "TagResource",
                Some(arn),
                account,
                region,
                &json!({"Tags":{"team":"etl"}}),
            )
            .await
            .unwrap();
        {
            let scope = store.scope(account, region).await;
            let mut state = scope.write().await;
            let mut pipe = state.pipes["durable"].clone();
            pipe.source_checkpoints
                .insert("shard-1".into(), "seq-42".into());
            pipe_persistence::save(store.state_db(), account, region, &pipe).unwrap();
            state.pipes.insert("durable".into(), pipe);
        }
        drop(service);
        drop(store);
        let reopened = Arc::new(EbStore::with_state(db).unwrap());
        let service = PipesService::new(
            reopened,
            Weak::new(),
            Arc::new(crate::http_client::CurlHttpClient),
        );
        service.restore().unwrap();
        let pipe = service
            .store
            .scope(account, region)
            .await
            .read()
            .await
            .pipes["durable"]
            .clone();
        assert_eq!(pipe.tags["owner"], "data");
        assert_eq!(pipe.tags["team"], "etl");
        assert_eq!(pipe.target, "arn:aws:sqs:us-east-1:000000000000:updated");
        assert_eq!(pipe.source_checkpoints["shard-1"], "seq-42");
        assert_eq!(pipe.desired_state, "STOPPED");
        service
            .dispatch("DeletePipe", Some("durable"), account, region, &json!({}))
            .await
            .unwrap();
        assert!(pipe_persistence::load(&service.store.state_db().unwrap())
            .unwrap()
            .is_empty());
    }

    fn json_response(status: u16, value: Value) -> Response {
        http::Response::builder()
            .status(status)
            .body(Body::from(value.to_string()))
            .unwrap()
    }

    struct SqsRecorder {
        message: Mutex<Option<Value>>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl SqsRecorder {
        fn with_message(message: Value) -> Self {
            Self {
                message: Mutex::new(Some(message)),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl NativeHandler for SqsRecorder {
        async fn handle(&self, request: ServiceRequest) -> Response {
            let target = request
                .headers
                .get("x-amz-target")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            self.calls
                .lock()
                .unwrap()
                .push((target.clone(), body.clone()));
            match target.as_str() {
                "AmazonSQS.ReceiveMessage" => {
                    let message = self.message.lock().unwrap().take();
                    json_response(
                        200,
                        message.map_or_else(
                            || json!({}),
                            |body| {
                                json!({"Messages":[{
                                    "Body":body.to_string(),
                                    "MessageId":"message-1",
                                    "ReceiptHandle":"receipt-1"
                                }]})
                            },
                        ),
                    )
                }
                "AmazonSQS.SendMessage" => json_response(200, json!({"MessageId":"recorded"})),
                "AmazonSQS.DeleteMessage" => json_response(200, json!({})),
                _ => json_response(400, json!({"message":"unexpected operation"})),
            }
        }
    }

    #[tokio::test]
    async fn dynamodb_pipeline_paginates_shards_and_recreates_iterators_from_checkpoints() {
        struct StreamRecorder {
            requests: Mutex<Vec<(String, Value)>>,
            checkpoint_iterators: tokio::sync::Semaphore,
        }

        impl Default for StreamRecorder {
            fn default() -> Self {
                Self {
                    requests: Mutex::default(),
                    checkpoint_iterators: tokio::sync::Semaphore::new(0),
                }
            }
        }

        #[async_trait::async_trait]
        impl NativeHandler for StreamRecorder {
            async fn handle(&self, request: ServiceRequest) -> Response {
                let target = request
                    .headers
                    .get("x-amz-target")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                self.requests
                    .lock()
                    .unwrap()
                    .push((target.clone(), body.clone()));
                let response = match target.as_str() {
                    "DynamoDBStreams_20120810.DescribeStream" => {
                        if body.get("ExclusiveStartShardId").is_none() {
                            json!({"StreamDescription":{
                                "Shards":[{"ShardId":"shard-000"}],
                                "LastEvaluatedShardId":"shard-000"
                            }})
                        } else {
                            assert_eq!(body["ExclusiveStartShardId"], "shard-000");
                            json!({"StreamDescription":{
                                "Shards":[{"ShardId":"shard-001"}]
                            }})
                        }
                    }
                    "DynamoDBStreams_20120810.GetShardIterator" => {
                        let shard = body["ShardId"].as_str().unwrap();
                        if body["ShardIteratorType"] == "AFTER_SEQUENCE_NUMBER" {
                            assert_eq!(body["SequenceNumber"], format!("sequence-{shard}"));
                            self.checkpoint_iterators.add_permits(1);
                            json!({"ShardIterator":format!("{shard}:after")})
                        } else {
                            assert_eq!(body["ShardIteratorType"], "TRIM_HORIZON");
                            json!({"ShardIterator":format!("{shard}:initial")})
                        }
                    }
                    "DynamoDBStreams_20120810.GetRecords" => {
                        let iterator = body["ShardIterator"].as_str().unwrap();
                        if let Some(shard) = iterator.strip_suffix(":initial") {
                            json!({"Records":[{
                                "eventID":shard,
                                "dynamodb":{"SequenceNumber":format!("sequence-{shard}")}
                            }]})
                        } else {
                            json!({"Records":[]})
                        }
                    }
                    _ => return json_response(400, json!({"message":"unexpected operation"})),
                };
                json_response(200, response)
            }
        }

        #[derive(Default)]
        struct TargetRecorder {
            messages: Mutex<Vec<Value>>,
        }

        #[async_trait::async_trait]
        impl NativeHandler for TargetRecorder {
            async fn handle(&self, request: ServiceRequest) -> Response {
                let body = serde_json::from_slice(&request.body).unwrap();
                self.messages.lock().unwrap().push(body);
                json_response(200, json!({"MessageId":"recorded"}))
            }
        }

        let registry = ServiceRegistry::with_known_services();
        let stream = Arc::new(StreamRecorder::default());
        let target = Arc::new(TargetRecorder::default());
        registry.register_native(
            ServiceName::new("streams.dynamodb"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("DynamoDBStreams_20120810")),
            stream.clone(),
        );
        registry.register_native(
            ServiceName::new("sqs"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("AmazonSQS")),
            target.clone(),
        );
        crate::register(&registry);
        let store = Arc::new(EbStore::new());
        let service = PipesService::new(
            store.clone(),
            Arc::downgrade(&registry),
            Arc::new(crate::http_client::CurlHttpClient),
        );
        service
            .dispatch(
                "CreatePipe",
                Some("stream"),
                "000000000000",
                "us-east-1",
                &json!({
                    "Source":"arn:aws:dynamodb:us-east-1:000000000000:table/t/stream/1",
                    "SourceParameters":{"DynamoDBStreamParameters":{"StartingPosition":"TRIM_HORIZON","BatchSize":10}},
                    "Target":"arn:aws:sqs:us-east-1:000000000000:out",
                    "RoleArn":"arn:aws:iam::000000000000:role/pipe"
                }),
            )
            .await
            .unwrap();

        let permits = tokio::time::timeout(
            Duration::from_secs(10),
            stream.checkpoint_iterators.acquire_many(2),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "worker should recreate both shard iterators from checkpoints; requests: {:?}",
                stream.requests.lock().unwrap()
            )
        })
        .expect("checkpoint semaphore should remain open");
        permits.forget();

        let scope = store.scope("000000000000", "us-east-1").await;
        let checkpoints = scope
            .read()
            .await
            .pipes
            .get("stream")
            .unwrap()
            .source_checkpoints
            .clone();
        assert_eq!(
            checkpoints,
            BTreeMap::from([
                ("shard-000".into(), "sequence-shard-000".into()),
                ("shard-001".into(), "sequence-shard-001".into()),
            ])
        );
        let messages = target.messages.lock().unwrap();
        assert_eq!(messages.len(), 2);
        assert!(messages.iter().any(|message| {
            message["MessageBody"]
                .as_str()
                .is_some_and(|body| body.contains("shard-000"))
        }));
        assert!(messages.iter().any(|message| {
            message["MessageBody"]
                .as_str()
                .is_some_and(|body| body.contains("shard-001"))
        }));
        let requests = stream.requests.lock().unwrap();
        assert!(requests.iter().any(|(target, body)| {
            target.ends_with("DescribeStream") && body["ExclusiveStartShardId"] == "shard-000"
        }));
    }

    #[tokio::test]
    async fn sqs_source_is_deleted_only_after_target_delivery() {
        let registry = ServiceRegistry::with_known_services();
        let sqs = Arc::new(SqsRecorder::with_message(json!({"kind":"ok"})));
        registry.register_native(
            ServiceName::new("sqs"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("AmazonSQS")),
            sqs.clone(),
        );
        crate::register(&registry);
        let service = PipesService::new(
            Arc::new(EbStore::new()),
            Arc::downgrade(&registry),
            Arc::new(crate::http_client::CurlHttpClient),
        );
        service
            .dispatch(
                "CreatePipe",
                Some("sqs-delete"),
                "000000000000",
                "us-east-1",
                &json!({
                    "Source":"arn:aws:sqs:us-east-1:000000000000:source",
                    "Target":"arn:aws:sqs:us-east-1:000000000000:target",
                    "RoleArn":"arn:aws:iam::000000000000:role/pipe"
                }),
            )
            .await
            .unwrap();

        for _ in 0..100 {
            if sqs
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|(target, _)| target == "AmazonSQS.DeleteMessage")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let calls = sqs.calls.lock().unwrap();
        let send = calls
            .iter()
            .position(|(target, _)| target == "AmazonSQS.SendMessage")
            .expect("target delivery");
        let delete = calls
            .iter()
            .position(|(target, _)| target == "AmazonSQS.DeleteMessage")
            .expect("source deletion");
        assert!(send < delete);
        assert_eq!(calls[delete].1["ReceiptHandle"], "receipt-1");
    }

    #[tokio::test]
    async fn filter_then_sync_enrichment_replaces_target_payload() {
        #[derive(Default)]
        struct LambdaRecorder {
            payloads: Mutex<Vec<Value>>,
            invocation_types: Mutex<Vec<String>>,
        }

        #[async_trait::async_trait]
        impl NativeHandler for LambdaRecorder {
            async fn handle(&self, request: ServiceRequest) -> Response {
                self.payloads
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(&request.body).unwrap());
                self.invocation_types.lock().unwrap().push(
                    request
                        .headers
                        .get("x-amz-invocation-type")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_string(),
                );
                json_response(200, json!({"enriched":true,"kind":"ok"}))
            }
        }

        let registry = ServiceRegistry::with_known_services();
        let sqs = Arc::new(SqsRecorder::with_message(json!({"kind":"ok"})));
        let lambda = Arc::new(LambdaRecorder::default());
        registry.register_native(
            ServiceName::new("sqs"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("AmazonSQS")),
            sqs.clone(),
        );
        registry.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            lambda.clone(),
        );
        crate::register(&registry);
        let service = PipesService::new(
            Arc::new(EbStore::new()),
            Arc::downgrade(&registry),
            Arc::new(crate::http_client::CurlHttpClient),
        );
        service
            .dispatch(
                "CreatePipe",
                Some("enriched"),
                "000000000000",
                "us-east-1",
                &json!({
                    "Source":"arn:aws:sqs:us-east-1:000000000000:source",
                    "SourceParameters":{"FilterCriteria":{"Filters":[{
                        "Pattern":"{\"body\":{\"kind\":[\"ok\"]}}"
                    }]}},
                    "Enrichment":"arn:aws:lambda:us-east-1:000000000000:function:enrich",
                    "EnrichmentParameters":{"InputTemplate":"{\"kind\":\"<$.body.kind>\"}"},
                    "Target":"arn:aws:sqs:us-east-1:000000000000:target",
                    "RoleArn":"arn:aws:iam::000000000000:role/pipe"
                }),
            )
            .await
            .unwrap();

        for _ in 0..100 {
            if sqs.calls.lock().unwrap().iter().any(|(target, body)| {
                target == "AmazonSQS.SendMessage"
                    && body["QueueUrl"]
                        .as_str()
                        .is_some_and(|url| url.ends_with("/target"))
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            lambda.payloads.lock().unwrap().as_slice(),
            &[json!({"kind":"ok"})]
        );
        assert_eq!(
            lambda.invocation_types.lock().unwrap().as_slice(),
            &["RequestResponse"]
        );
        let calls = sqs.calls.lock().unwrap();
        let sent = calls
            .iter()
            .find(|(target, body)| {
                target == "AmazonSQS.SendMessage"
                    && body["QueueUrl"]
                        .as_str()
                        .is_some_and(|url| url.ends_with("/target"))
            })
            .expect("enriched target delivery");
        assert_eq!(
            serde_json::from_str::<Value>(sent.1["MessageBody"].as_str().unwrap()).unwrap(),
            json!({"enriched":true,"kind":"ok"})
        );
    }

    #[tokio::test]
    async fn step_functions_enrichment_uses_start_sync_output() {
        #[derive(Default)]
        struct StatesRecorder {
            requests: Mutex<Vec<Value>>,
        }

        #[async_trait::async_trait]
        impl NativeHandler for StatesRecorder {
            async fn handle(&self, request: ServiceRequest) -> Response {
                assert_eq!(
                    request
                        .headers
                        .get("x-amz-target")
                        .and_then(|value| value.to_str().ok()),
                    Some("AWSStepFunctions.StartSyncExecution")
                );
                self.requests
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(&request.body).unwrap());
                json_response(
                    200,
                    json!({"status":"SUCCEEDED","output":"{\"from\":\"states\"}"}),
                )
            }
        }

        let registry = ServiceRegistry::with_known_services();
        let states = Arc::new(StatesRecorder::default());
        registry.register_native(
            ServiceName::new("states"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("AWSStepFunctions")),
            states.clone(),
        );
        crate::register(&registry);
        let arn = "arn:aws:states:us-east-1:000000000000:stateMachine:enrich";
        let pipe = Pipe {
            name: "states-enrichment".into(),
            arn: "arn:aws:pipes:us-east-1:000000000000:pipe/states-enrichment".into(),
            description: None,
            source: "arn:aws:sqs:us-east-1:000000000000:source".into(),
            source_parameters: json!({}),
            enrichment: Some(arn.into()),
            enrichment_parameters: json!({}),
            target: "arn:aws:sqs:us-east-1:000000000000:target".into(),
            target_parameters: json!({}),
            role_arn: "arn:aws:iam::000000000000:role/pipe".into(),
            desired_state: "RUNNING".into(),
            current_state: "RUNNING".into(),
            tags: BTreeMap::new(),
            generation: 1,
            source_checkpoints: BTreeMap::new(),
        };
        let output = invoke_sync_enrichment(
            &registry,
            &pipe,
            arn,
            "{\"kind\":\"ok\"}".into(),
            "us-east-1",
            "000000000000",
        )
        .await
        .unwrap();
        assert_eq!(output, json!({"from":"states"}));
        assert_eq!(states.requests.lock().unwrap()[0]["stateMachineArn"], arn);
        assert_eq!(
            states.requests.lock().unwrap()[0]["input"],
            "{\"kind\":\"ok\"}"
        );
    }

    #[tokio::test]
    async fn list_pipes_paginates_and_stopped_transition_is_owned_and_reaped() {
        let registry = ServiceRegistry::with_known_services();
        let service = PipesService::new(
            Arc::new(EbStore::new()),
            Arc::downgrade(&registry),
            Arc::new(crate::http_client::CurlHttpClient),
        );
        for name in ["a", "b", "c"] {
            service
                .dispatch(
                    "CreatePipe",
                    Some(name),
                    "000000000000",
                    "us-east-1",
                    &json!({
                        "Source":"arn:aws:sqs:us-east-1:000000000000:source",
                        "Target":"arn:aws:sqs:us-east-1:000000000000:target",
                        "RoleArn":"arn:aws:iam::000000000000:role/pipe",
                        "DesiredState":"STOPPED"
                    }),
                )
                .await
                .unwrap();
        }
        assert_eq!(service.workers.lock().unwrap().len(), 3);
        tokio::task::yield_now().await;
        let first = service
            .dispatch(
                "ListPipes",
                None,
                "000000000000",
                "us-east-1",
                &json!({"MaxResults":2}),
            )
            .await
            .unwrap();
        for _ in 0..100 {
            if service
                .workers
                .lock()
                .unwrap()
                .values()
                .all(JoinHandle::is_finished)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        service.reap_finished_workers();
        assert!(service.workers.lock().unwrap().is_empty());
        assert_eq!(first["Pipes"][0]["Name"], "a");
        assert_eq!(first["Pipes"][1]["Name"], "b");
        assert_eq!(first["NextToken"], "b");
        let second = service
            .dispatch(
                "ListPipes",
                None,
                "000000000000",
                "us-east-1",
                &json!({"MaxResults":2,"NextToken":first["NextToken"]}),
            )
            .await
            .unwrap();
        assert_eq!(second["Pipes"].as_array().unwrap().len(), 1);
        assert_eq!(second["Pipes"][0]["Name"], "c");
        assert!(second.get("NextToken").is_none());
    }

    #[test]
    fn validates_stream_starting_position_and_target_domain() {
        assert!(validate_source_parameters(
            "arn:aws:dynamodb:r:a:table/t/stream/1",
            &json!({"DynamoDBStreamParameters":{"StartingPosition":"AT_TIMESTAMP"}}),
        )
        .is_err());
        assert!(validate_source_parameters(
            "arn:aws:kinesis:r:a:stream/s",
            &json!({"KinesisStreamParameters":{"StartingPosition":"AT_TIMESTAMP"}}),
        )
        .is_err());
        assert!(validate_source_parameters(
            "arn:aws:kinesis:r:a:stream/s",
            &json!({"KinesisStreamParameters":{"StartingPosition":"AT_TIMESTAMP","StartingPositionTimestamp":1_700_000_000}}),
        )
        .is_ok());
        assert!(validate_target("arn:aws:logs:r:a:log-group:g").is_err());
        assert_eq!(
            kinesis_stream_name("arn:aws:kinesis:us-east-1:000000000000:stream/orders"),
            Some("orders")
        );
    }

    #[test]
    fn discovers_every_stream_shard() {
        let description = json!({
            "StreamDescription": {
                "Shards": [
                    {"ShardId": "shard-000"},
                    {"ShardId": "shard-001"}
                ]
            }
        });
        assert_eq!(
            stream_shard_ids(&description).unwrap(),
            vec!["shard-000", "shard-001"]
        );
    }

    #[test]
    fn template_and_filter_order_helpers() {
        let payload = json!({"body":{"kind":"ok"}});
        assert_eq!(
            apply_pipe_template("{\"kind\":\"<$.body.kind>\"}", &payload),
            "{\"kind\":\"ok\"}"
        );
        let mut pipe = Pipe {
            name: "p".into(),
            arn: "a".into(),
            description: None,
            source: "arn:aws:sqs:r:a:q".into(),
            source_parameters: json!({"FilterCriteria":{"Filters":[{"Pattern":"{\"body\":{\"kind\":[\"ok\"]}}"}]}}),
            enrichment: None,
            enrichment_parameters: json!({}),
            target: "t".into(),
            target_parameters: json!({}),
            role_arn: "r".into(),
            desired_state: "RUNNING".into(),
            current_state: "RUNNING".into(),
            tags: BTreeMap::new(),
            generation: 1,
            source_checkpoints: BTreeMap::new(),
        };
        assert!(record_matches(&pipe, &payload));
        pipe.source_parameters = json!({});
        assert!(record_matches(&pipe, &json!({"anything":true})));
    }
}
