use super::*;
use axum::{body::Body, response::Response};
use locallycloud_core::{
    handler::{NativeHandler, ServiceRequest},
    registry::{AwsProtocol, ServiceMetadata, ServiceName},
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[tokio::test]
async fn unchanged_stream_identity_skips_writes_but_new_identity_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let db =
        Arc::new(locallycloud_state::StateDb::open(root.path().join("state.sqlite3")).unwrap());
    let store = Arc::new(EbStore::with_state(db.clone()).unwrap());
    let service = PipesService::new(
        store.clone(),
        Weak::new(),
        Arc::new(crate::http_client::CurlHttpClient),
    );
    service.restore().unwrap();
    let pipe = configure(&service, &store, json!({"StartingPosition":"TRIM_HORIZON"})).await;
    assert!(save_source_identity(&store, &pipe, Some(42.0), "000000000000", "us-east-1").await);
    db.connection()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_pipe_writes BEFORE INSERT ON events_pipes
             BEGIN SELECT RAISE(ABORT, 'test writes unavailable'); END;",
        )
        .unwrap();
    assert!(pipe_persistence::save(store.state_db(), "000000000000", "us-east-1", &pipe).is_err());
    assert!(save_source_identity(&store, &pipe, Some(42.0), "000000000000", "us-east-1").await);
    assert!(!save_source_identity(&store, &pipe, Some(43.0), "000000000000", "us-east-1").await);
    let scope = store.scope("000000000000", "us-east-1").await;
    let mut state = scope.write().await;
    let stored = state.pipes.get_mut(&pipe.name).unwrap();
    assert_eq!(stored.source_creation_timestamp, Some(42.0));
    stored.source_creation_timestamp = None;
    drop(state);
    assert!(!save_source_identity(&store, &pipe, Some(42.0), "000000000000", "us-east-1").await);
    assert_eq!(
        scope.read().await.pipes[&pipe.name].source_creation_timestamp,
        None
    );
}

#[derive(Default)]
struct Targets {
    active: AtomicUsize,
    peak: AtomicUsize,
    calls: Mutex<Vec<Vec<Value>>>,
    poison: AtomicBool,
    partial: AtomicBool,
    partial_bad: AtomicBool,
    dlq_fail: AtomicBool,
    dlq: Mutex<Vec<Value>>,
    partitions: Mutex<BTreeSet<String>>,
}
#[async_trait::async_trait]
impl NativeHandler for Targets {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let value: Value = serde_json::from_slice(&request.body).unwrap();
        let target = request.headers["x-amz-target"].to_str().unwrap();
        if target == "AmazonSQS.SendMessage" {
            if self.dlq_fail.load(Ordering::SeqCst) {
                return response(500, json!({"__type":"InternalError"}));
            }
            self.dlq
                .lock()
                .unwrap()
                .push(serde_json::from_str(value["MessageBody"].as_str().unwrap()).unwrap());
            return response(200, json!({"MessageId":"dlq"}));
        }
        assert_eq!(target, "AWSStepFunctions.StartSyncExecution");
        let records: Vec<Value> = serde_json::from_str(value["input"].as_str().unwrap()).unwrap();
        assert!(!records.is_empty());
        let keys: BTreeSet<_> = records
            .iter()
            .map(|value| value["partitionKey"].to_string())
            .collect();
        {
            let mut active = self.partitions.lock().unwrap();
            assert!(
                active.is_disjoint(&keys),
                "a partition must never overlap another invocation"
            );
            active.extend(keys.clone());
        }
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        self.calls.lock().unwrap().push(records.clone());
        tokio::time::sleep(Duration::from_millis(
            if records[0]["sequenceNumber"] == "1" {
                50
            } else {
                5
            },
        ))
        .await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.partitions
            .lock()
            .unwrap()
            .retain(|key| !keys.contains(key));
        if self.poison.load(Ordering::SeqCst)
            && records.iter().any(|value| value["sequenceNumber"] == "bad")
        {
            if self.partial_bad.load(Ordering::SeqCst) {
                let failures: Vec<_> = records
                    .iter()
                    .filter(|record| record["sequenceNumber"] == "bad")
                    .map(|record| json!({"itemIdentifier": record["eventID"]}))
                    .collect();
                return response(
                    200,
                    json!({"status":"SUCCEEDED","output":json!({"batchItemFailures":failures}).to_string()}),
                );
            }
            return response(200, json!({"status":"FAILED","error":"PoisonRecord"}));
        }
        let output = if self.partial.swap(false, Ordering::SeqCst) && records.len() > 1 {
            json!({"batchItemFailures":[{"itemIdentifier":records[1]["eventID"]}]})
        } else {
            json!({"batchItemFailures":[]})
        };
        response(
            200,
            json!({"status":"SUCCEEDED","output":output.to_string()}),
        )
    }
}
fn response(status: u16, value: Value) -> Response {
    Response::builder()
        .status(status)
        .body(Body::from(value.to_string()))
        .unwrap()
}
fn record(sequence: &str, key: &str) -> PolledRecord {
    PolledRecord {
        payload: json!({"eventID":format!("shard:{sequence}"), "sequenceNumber":sequence,
        "partitionKey":key,"data":"eyJ2YWx1ZSI6MX0=","approximateArrivalTimestamp":crate::model::source_start_timestamp(),
        "eventSource":"aws:kinesis"}),
        receipt: None,
        stream_checkpoint: Some(("shard".into(), sequence.into())),
        source_expires_at: None,
    }
}
async fn configure(service: &PipesService, store: &EbStore, source: Value) -> Pipe {
    let scope = store.scope("000000000000", "us-east-1").await;
    if scope.read().await.pipes.contains_key("batch") {
        service
            .dispatch(
                "DeletePipe",
                Some("batch"),
                "000000000000",
                "us-east-1",
                &json!({}),
            )
            .await
            .unwrap();
    }
    service.dispatch("CreatePipe",Some("batch"),"000000000000","us-east-1",&json!({
        "Source":"arn:aws:kinesis:us-east-1:000000000000:stream/source","SourceParameters":{"KinesisStreamParameters":source},
        "Target":"arn:aws:states:us-east-1:000000000000:stateMachine:target","RoleArn":"arn:aws:iam::000000000000:role/pipe",
        "DesiredState":"STOPPED"})).await.unwrap();
    let mut state = scope.write().await;
    let pipe = state.pipes.get_mut("batch").unwrap();
    pipe.desired_state = "RUNNING".into();
    pipe.current_state = "RUNNING".into();
    let pipe = pipe.clone();
    pipe_persistence::save(store.state_db(), "000000000000", "us-east-1", &pipe).unwrap();
    pipe
}

#[tokio::test]
async fn stream_batches_fence_concurrency_checkpoints_and_durable_failure_handoff() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let db =
        Arc::new(locallycloud_state::StateDb::open(root.path().join("state.sqlite3")).unwrap());
    let store = Arc::new(EbStore::with_state(db.clone()).unwrap());
    let registry = ServiceRegistry::with_known_services();
    let targets = Arc::new(Targets::default());
    for (service, prefix) in [("states", "AWSStepFunctions"), ("sqs", "AmazonSQS")] {
        registry.register_native(
            ServiceName::new(service),
            ServiceMetadata::new(AwsProtocol::Json10, Some(prefix)),
            targets.clone(),
        );
    }
    crate::register(&registry);
    let http = Arc::new(crate::http_client::CurlHttpClient);
    let service = PipesService::new(store.clone(), Weak::new(), http.clone());
    service.restore().unwrap();
    let pipe = configure(
        &service,
        &store,
        json!({"StartingPosition":"TRIM_HORIZON","BatchSize":1,"ParallelizationFactor":2}),
    )
    .await;
    process_shard(
        registry.clone(),
        store.clone(),
        http.clone(),
        pipe.clone(),
        vec![record("1", "a"), record("2", "b")],
        "us-east-1".into(),
        "000000000000".into(),
    )
    .await;
    assert_eq!(targets.peak.load(Ordering::SeqCst), 2);
    let scope = store.scope("000000000000", "us-east-1").await;
    assert_eq!(
        scope.read().await.pipes["batch"].source_checkpoints["shard"],
        "2"
    );
    assert!(scope.read().await.pipes["batch"]
        .source_retry_attempts
        .is_empty());
    targets.peak.store(0, Ordering::SeqCst);
    process_shard(
        registry.clone(),
        store.clone(),
        http.clone(),
        pipe.clone(),
        vec![record("3", "same"), record("4", "same")],
        "us-east-1".into(),
        "000000000000".into(),
    )
    .await;
    assert_eq!(targets.peak.load(Ordering::SeqCst), 1);

    let pipe=configure(&service,&store,json!({"StartingPosition":"TRIM_HORIZON","BatchSize":2,"MaximumRetryAttempts":0,
        "OnPartialBatchItemFailure":"AUTOMATIC_BISECT","DeadLetterConfig":{"Arn":"arn:aws:sqs:us-east-1:000000000000:dlq"}})).await;
    targets.poison.store(true, Ordering::SeqCst);
    targets.dlq_fail.store(true, Ordering::SeqCst);
    process_shard(
        registry.clone(),
        store.clone(),
        http.clone(),
        pipe.clone(),
        vec![record("good", "a"), record("bad", "b")],
        "us-east-1".into(),
        "000000000000".into(),
    )
    .await;
    assert_eq!(
        scope.read().await.pipes["batch"].source_checkpoints["shard"],
        "good"
    );
    assert_eq!(
        scope.read().await.pipes["batch"].source_retry_attempts["shard:bad"],
        1
    );
    // A later successful batch cannot make a failed predecessor disappear.
    let mut parallel = pipe.clone();
    parallel.source_parameters = json!({"KinesisStreamParameters":{"BatchSize":1,"ParallelizationFactor":2,"MaximumRetryAttempts":0,
        "DeadLetterConfig":{"Arn":"arn:aws:sqs:us-east-1:000000000000:dlq"}}});
    process_shard(
        registry.clone(),
        store.clone(),
        http.clone(),
        parallel,
        vec![record("bad", "b"), record("later", "c")],
        "us-east-1".into(),
        "000000000000".into(),
    )
    .await;
    assert_eq!(
        scope.read().await.pipes["batch"].source_checkpoints["shard"],
        "good"
    );
    let restored = Arc::new(EbStore::with_state(db).unwrap());
    let reopened = PipesService::new(restored.clone(), Weak::new(), http.clone());
    reopened.restore().unwrap();
    let recovered = restored
        .scope("000000000000", "us-east-1")
        .await
        .read()
        .await
        .pipes["batch"]
        .clone();
    assert_eq!(recovered.source_retry_attempts["shard:bad"], 1);
    targets.dlq_fail.store(false, Ordering::SeqCst);
    process_shard(
        registry.clone(),
        restored.clone(),
        http.clone(),
        recovered.clone(),
        vec![record("bad", "b")],
        "us-east-1".into(),
        "000000000000".into(),
    )
    .await;
    assert_eq!(targets.dlq.lock().unwrap().len(), 1);
    assert_eq!(
        restored
            .scope("000000000000", "us-east-1")
            .await
            .read()
            .await
            .pipes["batch"]
            .source_checkpoints["shard"],
        "bad"
    );
    let calls_before = targets.calls.lock().unwrap().len();
    process_shard(
        registry.clone(),
        restored.clone(),
        http.clone(),
        recovered.clone(),
        vec![record("later", "c")],
        "us-east-1".into(),
        "000000000000".into(),
    )
    .await;
    assert_eq!(
        targets.calls.lock().unwrap().len(),
        calls_before,
        "durably completed out-of-order work must not be invoked or falsely dead-lettered on restart"
    );
    assert_eq!(targets.dlq.lock().unwrap().len(), 1);
    let recovered_scope = restored.scope("000000000000", "us-east-1").await;
    recovered_scope
        .write()
        .await
        .pipes
        .get_mut("batch")
        .unwrap()
        .generation += 1;
    assert!(
        !checkpoint(
            &restored,
            &recovered,
            &[record("stale", "a")],
            "000000000000",
            "us-east-1"
        )
        .await
    );

    let pipe = configure(
        &service,
        &store,
        json!({"BatchSize":2,"MaximumRetryAttempts":1}),
    )
    .await;
    targets.poison.store(false, Ordering::SeqCst);
    targets.partial.store(true, Ordering::SeqCst);
    process_shard(
        registry.clone(),
        store.clone(),
        http.clone(),
        pipe,
        vec![record("p1", "a"), record("p2", "b")],
        "us-east-1".into(),
        "000000000000".into(),
    )
    .await;
    assert_eq!(
        scope.read().await.pipes["batch"].source_checkpoints["shard"],
        "p2"
    );

    // A reported first-item failure must never falsely dead-letter its already successful neighbor.
    targets.poison.store(true, Ordering::SeqCst);
    targets.partial_bad.store(true, Ordering::SeqCst);
    for bisect in [false, true] {
        let mut parameters = json!({"BatchSize":2,"MaximumRetryAttempts":0,"DeadLetterConfig":{"Arn":"arn:aws:sqs:us-east-1:000000000000:dlq"}});
        if bisect {
            parameters["OnPartialBatchItemFailure"] = json!("AUTOMATIC_BISECT");
        }
        let pipe = configure(&service, &store, parameters).await;
        let before_calls = targets.calls.lock().unwrap().len();
        let before_dlq = targets.dlq.lock().unwrap().len();
        tokio::time::timeout(
            Duration::from_secs(3),
            process_shard(
                registry.clone(),
                store.clone(),
                http.clone(),
                pipe,
                vec![record("bad", "a"), record("successful", "b")],
                "us-east-1".into(),
                "000000000000".into(),
            ),
        )
        .await
        .unwrap();
        {
            let calls = targets.calls.lock().unwrap();
            assert_eq!(calls.len() - before_calls, if bisect { 2 } else { 1 });
            if bisect {
                assert_eq!(calls.last().unwrap().len(), 1);
                assert_eq!(calls.last().unwrap()[0]["sequenceNumber"], "bad");
            }
            let dlq = targets.dlq.lock().unwrap();
            assert_eq!(dlq.len() - before_dlq, 1);
            assert_eq!(dlq.last().unwrap()["sequenceNumber"], "bad");
        }
        assert_eq!(
            scope.read().await.pipes["batch"].source_checkpoints["shard"],
            "successful"
        );
        assert!(scope.read().await.pipes["batch"]
            .source_completed
            .is_empty());
    }

    // An oversized singleton rejected before dispatch must still exhaust a finite retry budget.
    let pipe = configure(
        &service,
        &store,
        json!({"BatchSize":1,"MaximumRetryAttempts":0,
        "DeadLetterConfig":{"Arn":"arn:aws:sqs:us-east-1:000000000000:dlq"}}),
    )
    .await;
    let before_calls = targets.calls.lock().unwrap().len();
    let before_dlq = targets.dlq.lock().unwrap().len();
    let mut oversized = record("oversized", "a");
    oversized.payload["data"] = json!("x".repeat(300_000));
    tokio::time::timeout(
        Duration::from_secs(3),
        process_shard(
            registry,
            store.clone(),
            http,
            pipe,
            vec![oversized],
            "us-east-1".into(),
            "000000000000".into(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(targets.calls.lock().unwrap().len(), before_calls);
    assert_eq!(targets.dlq.lock().unwrap().len(), before_dlq + 1);
    assert_eq!(
        targets.dlq.lock().unwrap().last().unwrap()["sequenceNumber"],
        "oversized"
    );
    assert_eq!(
        scope.read().await.pipes["batch"].source_checkpoints["shard"],
        "oversized"
    );
}

#[test]
fn stream_parameter_and_transform_contracts() {
    for value in [
        json!({"MaximumRetryAttempts":-2}),
        json!({"MaximumRetryAttempts":10_001}),
        json!({"MaximumRecordAgeInSeconds":"-1"}),
        json!({"ParallelizationFactor":0}),
        json!({"ParallelizationFactor":11}),
        json!({"BatchSize":1.5}),
        json!({"MaximumBatchingWindowInSeconds":301}),
        json!({"OnPartialBatchItemFailure":"IGNORE"}),
    ] {
        assert!(validate_parameters("arn:aws:kinesis:::stream/s", &value).is_err());
    }
    let parsed = Parameters::parse("kinesis", &json!({})).unwrap();
    assert_eq!((parsed.retries, parsed.age, parsed.parallel), (-1, -1, 1));
    assert!(validate_target_parameters(
        &json!({"StepFunctionStateMachineParameters":{"InvocationType":"bad"}})
    )
    .is_err());
    let payload = json!({"data":{"message":"quote\" and <$.data>"}});
    let raw = apply_pipe_template(
        "{\"message\":\"<$.data.message>\",\"obj\":<$.data>}",
        &payload,
    );
    let value: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(value["message"], payload["data"]["message"]);
    assert_eq!(value["obj"], payload["data"]);
    assert_eq!(decoded(&record("1", "a").payload)["data"]["value"], 1);
    assert!(expired(&record("1", "a"), 0));
    assert!(validate_enrichment_batch(
        "arn:aws:kinesis:::stream/s",
        &json!({"KinesisStreamParameters":{"BatchSize":2}}),
        Some("arn:aws:events:::api-destination/api")
    )
    .is_err());
    assert!(validate_enrichment_batch(
        "arn:aws:kinesis:::stream/s",
        &json!({"KinesisStreamParameters":{"BatchSize":1}}),
        Some("arn:aws:events:::api-destination/api")
    )
    .is_ok());
    assert!(partial_failures(
        &json!({"batchItemFailures":[{"itemIdentifier":""}]}),
        &[record("1", "a")]
    )
    .is_err());
}
