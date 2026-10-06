use super::*;
use std::collections::{BTreeSet, VecDeque};
use tokio::task::JoinSet;

#[derive(Clone, Copy)]
struct Parameters {
    batch: usize,
    parallel: usize,
    retries: i64,
    age: i64,
    bisect: bool,
}

fn integer(
    parameters: &Value,
    key: &str,
    default: i64,
    min: i64,
    max: i64,
) -> Result<i64, PipesError> {
    let Some(value) = find_value(parameters, key) else {
        return Ok(default);
    };
    let value = value
        .as_i64()
        .ok_or_else(|| PipesError::Validation(format!("{key} must be an integer")))?;
    if !(min..=max).contains(&value) {
        return Err(PipesError::Validation(format!(
            "{key} must be between {min} and {max}"
        )));
    }
    Ok(value)
}
impl Parameters {
    fn parse(source: &str, parameters: &Value) -> Result<Self, PipesError> {
        let batch = integer(
            parameters,
            "BatchSize",
            100,
            1,
            if source.contains(":sqs:") { 10 } else { 10_000 },
        )? as usize;
        integer(parameters, "MaximumBatchingWindowInSeconds", 0, 0, 300)?;
        let parallel = integer(parameters, "ParallelizationFactor", 1, 1, 10)? as usize;
        let retries = integer(parameters, "MaximumRetryAttempts", -1, -1, 10_000)?;
        let age = integer(parameters, "MaximumRecordAgeInSeconds", -1, -1, 604_800)?;
        let bisect = match find_value(parameters, "OnPartialBatchItemFailure") {
            None => false,
            Some(Value::String(value)) if value == "AUTOMATIC_BISECT" => true,
            _ => {
                return Err(PipesError::Validation(
                    "OnPartialBatchItemFailure must be AUTOMATIC_BISECT".into(),
                ))
            }
        };
        Ok(Self {
            batch,
            parallel,
            retries,
            age,
            bisect,
        })
    }
}
pub(super) fn validate_parameters(source: &str, parameters: &Value) -> Result<(), PipesError> {
    if !parameters.is_object() {
        return Err(PipesError::Validation(
            "SourceParameters must be an object".into(),
        ));
    }
    let container = if source.contains(":kinesis:") {
        "KinesisStreamParameters"
    } else if source.contains(":dynamodb:") {
        "DynamoDBStreamParameters"
    } else {
        "SqsQueueParameters"
    };
    if parameters
        .get(container)
        .is_some_and(|value| !value.is_object())
    {
        return Err(PipesError::Validation(format!(
            "{container} must be an object"
        )));
    }
    if find_value(parameters, "StartingPosition").is_some_and(|value| !value.is_string()) {
        return Err(PipesError::Validation(
            "StartingPosition must be a string".into(),
        ));
    }
    if find_value(parameters, "StartingPositionTimestamp")
        .is_some_and(|value| value.as_f64().is_none_or(|value| value < 0.0))
    {
        return Err(PipesError::Validation(
            "StartingPositionTimestamp must be a non-negative timestamp".into(),
        ));
    }
    Parameters::parse(source, parameters).map(|_| ())
}
pub(super) fn validate_enrichment_batch(
    source: &str,
    parameters: &Value,
    enrichment: Option<&str>,
) -> Result<(), PipesError> {
    if (source.contains(":kinesis:") || source.contains(":dynamodb:"))
        && enrichment.is_some_and(|arn| arn.contains(":api-destination/"))
        && find_number(parameters, "BatchSize").is_some_and(|batch| batch > 1)
    {
        return Err(PipesError::Validation(
            "API destination enrichment does not support stream batching; BatchSize must be 1"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_target_parameters(parameters: &Value) -> Result<(), PipesError> {
    if !parameters.is_null() && !parameters.is_object() {
        return Err(PipesError::Validation(
            "TargetParameters must be an object".into(),
        ));
    }
    for key in [
        "StepFunctionStateMachineParameters",
        "LambdaFunctionParameters",
    ] {
        if parameters.get(key).is_some_and(|value| !value.is_object()) {
            return Err(PipesError::Validation(format!("{key} must be an object")));
        }
    }
    if let Some(value) = find_value(parameters, "InvocationType") {
        if !value
            .as_str()
            .is_some_and(|value| matches!(value, "REQUEST_RESPONSE" | "FIRE_AND_FORGET"))
        {
            return Err(PipesError::Validation(
                "InvocationType must be REQUEST_RESPONSE or FIRE_AND_FORGET".into(),
            ));
        }
    }
    Ok(())
}

pub(super) async fn run_round(
    registry: Arc<ServiceRegistry>,
    store: Arc<EbStore>,
    http: Arc<dyn HttpClient>,
    pipe: Pipe,
    region: String,
    account: String,
) {
    let Ok(shards) = discover_stream_shards(&registry, &pipe, &region, &account).await else {
        return;
    };
    // Each discovered shard owns one bounded PF worker; a poison shard cannot stall polling other shards.
    let mut workers = JoinSet::new();
    for index in 0..shards.len() {
        let (registry, store, http, region, account) = (
            registry.clone(),
            store.clone(),
            http.clone(),
            region.clone(),
            account.clone(),
        );
        let pipe = pipe.clone();
        workers.spawn(async move {
            loop {
                let scope = store.scope(&account, &region).await;
                let current = { scope.read().await.pipes.get(&pipe.name).cloned() };
                let Some(mut current) = current.filter(|current| {
                    current.generation == pipe.generation && current.desired_state == "RUNNING"
                }) else {
                    return;
                };
                current.source_cursor = index;
                if let Ok(batch) = poll_source(&registry, &current, &region, &account).await {
                    if !save_source_identity(
                        &store,
                        &current,
                        batch.source_creation_timestamp,
                        &account,
                        &region,
                    )
                    .await
                    {
                        return;
                    }
                    process_shard(
                        registry.clone(),
                        store.clone(),
                        http.clone(),
                        current,
                        batch.records,
                        region.clone(),
                        account.clone(),
                    )
                    .await;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
    }
    while workers.join_next().await.is_some() {}
}

async fn save_source_identity(
    store: &EbStore,
    pipe: &Pipe,
    timestamp: Option<f64>,
    account: &str,
    region: &str,
) -> bool {
    let scope = store.scope(account, region).await;
    let mut state = scope.write().await;
    let Some(current) = state.pipes.get(&pipe.name).filter(|current| {
        current.generation == pipe.generation && current.desired_state == "RUNNING"
    }) else {
        return false;
    };
    if current
        .source_creation_timestamp
        .is_some_and(|expected| Some(expected) != timestamp)
    {
        return false;
    }
    if current.source_creation_timestamp.is_some() {
        return true;
    }
    let mut updated = current.clone();
    updated.source_creation_timestamp = timestamp;
    if pipe_persistence::save(store.state_db(), account, region, &updated).is_err() {
        return false;
    }
    state.pipes.insert(pipe.name.clone(), updated);
    true
}

fn partition(record: &PolledRecord) -> String {
    record
        .payload
        .get("partitionKey")
        .map(Value::to_string)
        .or_else(|| {
            record
                .payload
                .pointer("/dynamodb/Keys")
                .map(Value::to_string)
        })
        .unwrap_or_else(|| "unknown".into())
}
fn attempt_key(record: &PolledRecord) -> String {
    record
        .stream_checkpoint
        .as_ref()
        .map(|(shard, sequence)| format!("{shard}:{sequence}"))
        .unwrap_or_default()
}
fn expired(record: &PolledRecord, maximum: i64) -> bool {
    let now = crate::model::source_start_timestamp();
    if record.source_expires_at.is_some_and(|expiry| now >= expiry) {
        return true;
    }
    if maximum < 0 {
        return false;
    }
    let timestamp = record
        .payload
        .get("approximateArrivalTimestamp")
        .or_else(|| {
            record
                .payload
                .pointer("/dynamodb/ApproximateCreationDateTime")
        })
        .and_then(Value::as_f64);
    timestamp.is_some_and(|timestamp| {
        crate::model::source_start_timestamp() - timestamp >= maximum as f64
    })
}

async fn process_shard(
    registry: Arc<ServiceRegistry>,
    store: Arc<EbStore>,
    http: Arc<dyn HttpClient>,
    pipe: Pipe,
    records: Vec<PolledRecord>,
    region: String,
    account: String,
) {
    let Ok(mut parameters) = Parameters::parse(&pipe.source, &pipe.source_parameters) else {
        return;
    };
    if pipe
        .enrichment
        .as_ref()
        .is_some_and(|arn| arn.contains(":api-destination/"))
    {
        parameters.batch = 1;
    }
    let mut pending: VecDeque<Vec<PolledRecord>> = records
        .chunks(parameters.batch)
        .map(<[PolledRecord]>::to_vec)
        .collect();
    while !pending.is_empty() {
        let mut keys = BTreeSet::new();
        let mut wave = Vec::new();
        while wave.len() < parameters.parallel {
            let Some(next) = pending.front() else { break };
            let next_keys: BTreeSet<_> = next.iter().map(partition).collect();
            if !keys.is_disjoint(&next_keys) {
                break;
            }
            keys.extend(next_keys);
            wave.push(pending.pop_front().unwrap());
        }
        let mut workers = JoinSet::new();
        let mut outcomes = vec![0; wave.len()];
        for (index, records) in wave.iter().cloned().enumerate() {
            let (registry, store, http, pipe, region, account) = (
                registry.clone(),
                store.clone(),
                http.clone(),
                pipe.clone(),
                region.clone(),
                account.clone(),
            );
            workers.spawn(async move {
                let completed = process_batch(
                    &registry,
                    &store,
                    http.as_ref(),
                    &pipe,
                    &records,
                    &region,
                    &account,
                )
                .await;
                (index, completed)
            });
        }
        while let Some(result) = workers.join_next().await {
            if let Ok((index, completed)) = result {
                outcomes[index] = completed
            }
        }
        // Later successes cannot leap over a failed earlier batch, even when they finish first.
        let mut prefix = Vec::new();
        let mut failed = false;
        for (records, completed) in wave.iter().zip(outcomes) {
            prefix.extend_from_slice(&records[..completed]);
            if completed != records.len() {
                failed = true;
                break;
            }
        }
        if !prefix.is_empty() && !checkpoint(&store, &pipe, &prefix, &account, &region).await {
            return;
        }
        if failed {
            return;
        }
    }
}

async fn checkpoint(
    store: &EbStore,
    pipe: &Pipe,
    records: &[PolledRecord],
    account: &str,
    region: &str,
) -> bool {
    let Some((shard, sequence)) = records
        .last()
        .and_then(|record| record.stream_checkpoint.as_ref())
    else {
        return false;
    };
    let scope = store.scope(account, region).await;
    let mut state = scope.write().await;
    let Some(current) = state.pipes.get(&pipe.name).filter(|current| {
        current.generation == pipe.generation && current.desired_state == "RUNNING"
    }) else {
        return false;
    };
    let mut updated = current.clone();
    updated
        .source_checkpoints
        .insert(shard.clone(), sequence.clone());
    for record in records {
        updated.source_retry_attempts.remove(&attempt_key(record));
        updated.source_completed.remove(&attempt_key(record));
    }
    if pipe_persistence::save(store.state_db(), account, region, &updated).is_err() {
        return false;
    }
    state.pipes.insert(pipe.name.clone(), updated);
    true
}

async fn reserve_attempt(
    store: &EbStore,
    pipe: &Pipe,
    records: &[PolledRecord],
    account: &str,
    region: &str,
    maximum: i64,
    increment: bool,
) -> Option<Vec<bool>> {
    let scope = store.scope(account, region).await;
    let mut state = scope.write().await;
    let current = state.pipes.get(&pipe.name).filter(|current| {
        current.generation == pipe.generation && current.desired_state == "RUNNING"
    })?;
    let mut updated = current.clone();
    let exhausted: Vec<_> = records
        .iter()
        .map(|record| {
            let count = updated
                .source_retry_attempts
                .entry(attempt_key(record))
                .or_default();
            // MaximumRetryAttempts excludes the original call; persisted before dispatch so crashes never reset the budget.
            if maximum >= 0 && u64::from(*count) > maximum as u64 {
                true
            } else {
                if increment {
                    *count = count.saturating_add(1);
                }
                false
            }
        })
        .collect();
    pipe_persistence::save(store.state_db(), account, region, &updated).ok()?;
    state.pipes.insert(pipe.name.clone(), updated);
    Some(exhausted)
}

async fn release_bisect_attempt(
    store: &EbStore,
    pipe: &Pipe,
    records: &[PolledRecord],
    account: &str,
    region: &str,
) -> bool {
    let scope = store.scope(account, region).await;
    let mut state = scope.write().await;
    let Some(current) = state.pipes.get(&pipe.name).filter(|current| {
        current.generation == pipe.generation && current.desired_state == "RUNNING"
    }) else {
        return false;
    };
    let mut updated = current.clone();
    for record in records {
        if let Some(attempts) = updated.source_retry_attempts.get_mut(&attempt_key(record)) {
            *attempts = attempts.saturating_sub(1);
        }
    }
    if pipe_persistence::save(store.state_db(), account, region, &updated).is_err() {
        return false;
    }
    state.pipes.insert(pipe.name.clone(), updated);
    true
}

async fn mark_completed(
    store: &EbStore,
    pipe: &Pipe,
    records: &[PolledRecord],
    account: &str,
    region: &str,
) -> bool {
    let scope = store.scope(account, region).await;
    let mut state = scope.write().await;
    let Some(current) = state.pipes.get(&pipe.name).filter(|current| {
        current.generation == pipe.generation && current.desired_state == "RUNNING"
    }) else {
        return false;
    };
    let mut updated = current.clone();
    updated
        .source_completed
        .extend(records.iter().map(attempt_key));
    if pipe_persistence::save(store.state_db(), account, region, &updated).is_err() {
        return false;
    }
    state.pipes.insert(pipe.name.clone(), updated);
    true
}
async fn already_completed(
    store: &EbStore,
    pipe: &Pipe,
    records: &[PolledRecord],
    account: &str,
    region: &str,
) -> Option<Vec<bool>> {
    let scope = store.scope(account, region).await;
    let state = scope.read().await;
    let current = state.pipes.get(&pipe.name).filter(|current| {
        current.generation == pipe.generation && current.desired_state == "RUNNING"
    })?;
    Some(
        records
            .iter()
            .map(|record| current.source_completed.contains(&attempt_key(record)))
            .collect(),
    )
}

#[derive(Clone, Copy)]
enum BatchFailure {
    Target,
    Payload { attempt_reserved: bool },
}

async fn process_batch(
    registry: &ServiceRegistry,
    store: &EbStore,
    http: &dyn HttpClient,
    pipe: &Pipe,
    records: &[PolledRecord],
    region: &str,
    account: &str,
) -> usize {
    let Ok(parameters) = Parameters::parse(&pipe.source, &pipe.source_parameters) else {
        return 0;
    };
    let mut work = VecDeque::from([records.to_vec()]);
    let mut completed = 0;
    while let Some(batch) = work.pop_front() {
        let Some(done) = already_completed(store, pipe, &batch, account, region).await else {
            return completed;
        };
        if done.iter().all(|done| *done) {
            completed += batch.len();
            continue;
        }
        if done.iter().any(|done| *done) {
            for record in batch.into_iter().rev() {
                work.push_front(vec![record]);
            }
            continue;
        }
        let Some(exhausted) = reserve_attempt(
            store,
            pipe,
            &batch,
            account,
            region,
            parameters.retries,
            false,
        )
        .await
        else {
            return completed;
        };
        if exhausted.iter().zip(&batch).any(|(exhausted, record)| {
            *exhausted && record_matches(pipe, &decoded(&record.payload))
        }) || batch.iter().any(|record| {
            record_matches(pipe, &decoded(&record.payload)) && expired(record, parameters.age)
        }) {
            // Mixed age/retry exhaustion is split before DLQ: never discard a younger record merely because its neighbor expired.
            if batch.len() > 1 {
                for record in batch.into_iter().rev() {
                    work.push_front(vec![record]);
                }
                continue;
            }
            if !discard(registry, pipe, &batch[0], region, account).await {
                return completed;
            }
            if !mark_completed(store, pipe, &batch, account, region).await {
                return completed;
            }
            completed += 1;
            continue;
        }
        let result = tokio::time::timeout(
            Duration::from_secs(300),
            invoke_batch(registry, store, http, pipe, &batch, region, account),
        )
        .await
        .unwrap_or(Err(BatchFailure::Target));
        match result {
            Ok(failures) if failures.is_empty() => {
                if !mark_completed(store, pipe, &batch, account, region).await {
                    return completed;
                }
                completed += batch.len();
            }
            Ok(failures) => {
                let failures: BTreeSet<_> = failures.into_iter().collect();
                let successful: Vec<_> = batch
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| !failures.contains(index))
                    .map(|(_, record)| record.clone())
                    .collect();
                if !successful.is_empty()
                    && !mark_completed(store, pipe, &successful, account, region).await
                {
                    return completed;
                }
                if parameters.bisect && batch.len() > 1 {
                    let failed: Vec<_> = batch
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| failures.contains(index))
                        .map(|(_, record)| record.clone())
                        .collect();
                    if !release_bisect_attempt(store, pipe, &failed, account, region).await {
                        return completed;
                    }
                    let middle = batch.len() / 2;
                    work.push_front(batch[middle..].to_vec());
                    work.push_front(batch[..middle].to_vec());
                } else {
                    // Completion markers preserve successful items while retries traverse the source positions in order.
                    work.push_front(batch);
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
            Err(failure)
                if batch.len() > 1
                    && (parameters.bisect || matches!(failure, BatchFailure::Payload { .. })) =>
            {
                // Splitting does not consume the normal retry budget, including a payload expanded by enrichment.
                let reserved = match failure {
                    BatchFailure::Target => true,
                    BatchFailure::Payload { attempt_reserved } => attempt_reserved,
                };
                if reserved && !release_bisect_attempt(store, pipe, &batch, account, region).await {
                    return completed;
                }
                let middle = batch.len() / 2;
                work.push_front(batch[middle..].to_vec());
                work.push_front(batch[..middle].to_vec());
            }
            Err(BatchFailure::Payload {
                attempt_reserved: false,
            }) => {
                // A rejected singleton still consumes an attempt, so finite retry budgets reach the configured DLQ.
                if reserve_attempt(
                    store,
                    pipe,
                    &batch,
                    account,
                    region,
                    parameters.retries,
                    true,
                )
                .await
                .is_none()
                {
                    return completed;
                }
                work.push_front(batch);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(_) => {
                work.push_front(batch);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    completed
}

async fn discard(
    registry: &ServiceRegistry,
    pipe: &Pipe,
    record: &PolledRecord,
    region: &str,
    account: &str,
) -> bool {
    if source_dlq_arn(&pipe.source_parameters).is_none() {
        return true;
    }
    handle_record_failure(registry, pipe, record, region, account).await
}

fn decoded(record: &Value) -> Value {
    use base64::Engine;
    let mut view = record.clone();
    if let Some(value) = record
        .get("data")
        .and_then(Value::as_str)
        .and_then(|value| base64::engine::general_purpose::STANDARD.decode(value).ok())
        .and_then(|value| serde_json::from_slice::<Value>(&value).ok())
    {
        view["data"] = value;
    }
    view
}
fn transformed(template: Option<&str>, value: Value) -> Value {
    template
        .map(|template| {
            let raw = apply_pipe_template(template, &decoded(&value));
            serde_json::from_str(&raw).unwrap_or(Value::String(raw))
        })
        .unwrap_or(value)
}

async fn invoke_batch(
    registry: &ServiceRegistry,
    store: &EbStore,
    http: &dyn HttpClient,
    pipe: &Pipe,
    records: &[PolledRecord],
    region: &str,
    account: &str,
) -> Result<Vec<usize>, BatchFailure> {
    let parameters = Parameters::parse(&pipe.source, &pipe.source_parameters)
        .map_err(|_| BatchFailure::Target)?;
    if (!pipe.target.contains(":states:") && !pipe.target.contains(":lambda:"))
        || pipe
            .enrichment
            .as_ref()
            .is_some_and(|arn| arn.contains(":api-destination/"))
    {
        for (index, record) in records.iter().enumerate() {
            reserve_attempt(
                store,
                pipe,
                std::slice::from_ref(record),
                account,
                region,
                parameters.retries,
                true,
            )
            .await
            .ok_or(BatchFailure::Target)?;
            if !process_record(registry, store, http, pipe, record, region, account).await {
                return Ok((index..records.len()).collect());
            }
        }
        return Ok(vec![]);
    }
    let selected: Vec<_> = records
        .iter()
        .enumerate()
        .filter(|(_, record)| record_matches(pipe, &decoded(&record.payload)))
        .collect();
    if selected.is_empty() {
        return Ok(vec![]);
    }
    let values: Vec<_> = selected
        .iter()
        .map(|(_, record)| {
            transformed(
                pipe.enrichment
                    .as_ref()
                    .and_then(|_| find_string(&pipe.enrichment_parameters, "InputTemplate")),
                record.payload.clone(),
            )
        })
        .collect();
    let mut payload = Value::Array(values);
    let limit = if pipe.target.contains(":states:") {
        262_144
    } else {
        6 * 1024 * 1024
    };
    let enrichment_limit = if pipe
        .enrichment
        .as_ref()
        .is_some_and(|arn| arn.contains(":states:"))
    {
        262_144
    } else {
        6 * 1024 * 1024
    };
    if pipe.enrichment.is_some() && payload.to_string().len() > enrichment_limit {
        return Err(BatchFailure::Payload {
            attempt_reserved: false,
        });
    }
    if pipe.enrichment.is_some() {
        reserve_attempt(
            store,
            pipe,
            records,
            account,
            region,
            parameters.retries,
            true,
        )
        .await
        .ok_or(BatchFailure::Target)?;
    }
    if let Some(enrichment) = &pipe.enrichment {
        payload = invoke_sync_enrichment(
            registry,
            pipe,
            enrichment,
            payload.to_string(),
            region,
            account,
        )
        .await
        .map_err(|_| BatchFailure::Target)?;
        if !payload.is_array() {
            return Err(BatchFailure::Target);
        }
    }
    let values = payload
        .as_array()
        .ok_or(BatchFailure::Target)?
        .iter()
        .cloned()
        .map(|value| transformed(find_string(&pipe.target_parameters, "InputTemplate"), value))
        .collect();
    payload = Value::Array(values);
    let payload = payload.to_string();
    if payload.len() > limit {
        return Err(BatchFailure::Payload {
            attempt_reserved: pipe.enrichment.is_some(),
        });
    }
    if pipe.enrichment.is_none() {
        reserve_attempt(
            store,
            pipe,
            records,
            account,
            region,
            parameters.retries,
            true,
        )
        .await
        .ok_or(BatchFailure::Target)?;
    }
    let request = DeliveryRequest {
        source_service: "pipes",
        source_arn: Some(pipe.arn.clone()),
        arn: pipe.target.clone(),
        payload,
        role_arn: Some(pipe.role_arn.clone()),
        sqs_parameters: None,
        target_parameters: Some(pipe.target_parameters.clone()),
        retry: RetryPolicy {
            maximum_attempts: 0,
            maximum_age_seconds: None,
        },
        dead_letter_arn: None,
        scheduled_at: None,
    };
    let synchronous = find_string(&pipe.target_parameters, "InvocationType")
        .unwrap_or("REQUEST_RESPONSE")
        == "REQUEST_RESPONSE";
    let output = if synchronous {
        tokio::time::timeout(
            Duration::from_secs(300),
            delivery::deliver_sync(registry, &request, region, account),
        )
        .await
        .map_err(|_| BatchFailure::Target)?
        .map_err(|_| BatchFailure::Target)?
    } else {
        delivery::deliver(registry, &request, region, account)
            .await
            .map_err(|_| BatchFailure::Target)?;
        Value::Null
    };
    partial_failures(&output, records).map_err(|_| BatchFailure::Target)
}

fn partial_failures(output: &Value, records: &[PolledRecord]) -> Result<Vec<usize>, bool> {
    let Some(failures) = output.get("batchItemFailures") else {
        return Ok(vec![]);
    };
    if failures.is_null() {
        return Ok(vec![]);
    }
    let Some(failures) = failures.as_array() else {
        return Err(false);
    };
    failures
        .iter()
        .map(|failure| {
            let identifier = failure
                .get("itemIdentifier")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or(false)?;
            records
                .iter()
                .position(|record| {
                    record.payload.get("eventID").and_then(Value::as_str) == Some(identifier)
                })
                .ok_or(false)
        })
        .collect()
}

#[cfg(test)]
#[path = "pipe_stream_tests.rs"]
mod tests;
