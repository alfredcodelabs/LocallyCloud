//! Per-stream Iceberg buffering and retry clocks; legacy S3 keeps its bounded policy.
use super::*;

#[derive(Clone, Copy, Serialize, Deserialize)]
pub(super) struct IcebergDeliveryPolicy {
    pub size_mib: u32,
    pub interval_seconds: u32,
    pub retry_seconds: u32,
}

impl Default for IcebergDeliveryPolicy {
    fn default() -> Self {
        Self {
            size_mib: 5,
            interval_seconds: 300,
            retry_seconds: 300,
        }
    }
}

impl IcebergDeliveryPolicy {
    pub fn parse(
        hints: Option<&BufferingHints>,
        retry: Option<&RetryOptions>,
    ) -> Result<Self, FirehoseError> {
        let mut policy = Self::default();
        match hints.map(|h| (h.size_in_m_bs, h.interval_in_seconds)) {
            None | Some((None, None)) => {}
            Some((Some(size), Some(interval)))
                if (1..=128).contains(&size) && (0..=900).contains(&interval) =>
            {
                policy.size_mib = size as u32;
                policy.interval_seconds = interval as u32;
            }
            Some((Some(_), Some(_))) => {
                return Err(FirehoseError::InvalidArgument(
                    "Iceberg BufferingHints requires SizeInMBs=1-128 and IntervalInSeconds=0-900"
                        .into(),
                ))
            }
            _ => {
                return Err(FirehoseError::InvalidArgument(
                    "BufferingHints requires both SizeInMBs and IntervalInSeconds".into(),
                ))
            }
        }
        if let Some(seconds) = retry.and_then(|r| r.duration_in_seconds) {
            if !(0..=7200).contains(&seconds) {
                return Err(FirehoseError::InvalidArgument(
                    "Iceberg RetryOptions.DurationInSeconds must be 0-7200".into(),
                ));
            }
            policy.retry_seconds = seconds as u32;
        }
        Ok(policy)
    }
}

#[derive(Clone, Copy)]
pub(super) struct StartedAt {
    pub unix_ms: u64,
    monotonic: Instant,
}

impl StartedAt {
    pub fn now() -> Result<Self, FirehoseError> {
        Self::at(Instant::now())
    }

    pub fn at(monotonic: Instant) -> Result<Self, FirehoseError> {
        let observed = Instant::now();
        let unix_ms: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| FirehoseError::Internal)?
            .as_millis()
            .try_into()
            .map_err(|_| FirehoseError::Internal)?;
        let elapsed_ms: u64 = observed
            .saturating_duration_since(monotonic)
            .as_millis()
            .try_into()
            .map_err(|_| FirehoseError::Internal)?;
        let future_ms: u64 = monotonic
            .saturating_duration_since(observed)
            .as_millis()
            .try_into()
            .map_err(|_| FirehoseError::Internal)?;
        let unix_ms = unix_ms.saturating_sub(elapsed_ms).saturating_add(future_ms);
        Ok(Self { unix_ms, monotonic })
    }

    pub fn restore_deadline(unix_ms: u64) -> Instant {
        let now = Instant::now();
        let current_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        now + Duration::from_millis(
            u128::from(unix_ms)
                .saturating_sub(current_ms)
                .min(7_200_000) as u64,
        )
    }

    pub fn restore(unix_ms: u64) -> Self {
        let now = Instant::now();
        let current_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        // Only the longest supported retry window matters; bound corrupt/ancient timestamps.
        let elapsed = current_ms
            .saturating_sub(u128::from(unix_ms))
            .min(7_201_000) as u64;
        Self {
            unix_ms,
            monotonic: now - Duration::from_millis(elapsed),
        }
    }
}

impl DeliveryStream {
    pub(super) fn iceberg_policy(&self) -> Option<IcebergDeliveryPolicy> {
        self.destination
            .iceberg
            .as_ref()
            .map(|_| self.destination.iceberg_delivery.unwrap_or_default())
    }

    pub(super) fn delivery_delay(&self, now: Instant) -> Option<Duration> {
        if self.terminal_failure
            || self.in_flight.is_some()
            || (self.pending.is_empty() && self.retained.is_empty())
        {
            return None;
        }
        if let Some(due) = self.retry_at.filter(|due| *due > now) {
            return Some(due.duration_since(now));
        }
        if !self.retained.is_empty() {
            return Some(Duration::ZERO);
        }
        let policy = self.iceberg_policy();
        let size = policy.map_or(COALESCE_SIZE_BYTES, |p| p.size_mib as usize * 1024 * 1024);
        if self.buffered_bytes >= size
            || (policy.is_none()
                && (self.source.is_some() || self.pending.len() >= MAX_BUFFERED_RECORDS))
        {
            return Some(Duration::ZERO);
        }
        let interval = policy.map_or(LOCAL_COALESCE_DELAY, |p| {
            Duration::from_secs(u64::from(p.interval_seconds))
        });
        Some(self.pending_since.map_or(Duration::ZERO, |first| {
            (first.monotonic + interval).saturating_duration_since(now)
        }))
    }

    pub(super) fn retry_remaining(&self, now: Instant) -> Option<Duration> {
        let policy = self.iceberg_policy()?;
        let elapsed = self.retry_started.map_or(Duration::ZERO, |start| {
            now.saturating_duration_since(start.monotonic)
        });
        Some(Duration::from_secs(u64::from(policy.retry_seconds)).saturating_sub(elapsed))
    }

    pub(super) fn retry_expired(&self, now: Instant) -> bool {
        self.retry_started.is_some() && self.retry_remaining(now).is_some_and(|left| left.is_zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(now: Instant) -> DeliveryStream {
        DeliveryStream {
            source: None,
            generation: Uuid::new_v4(),
            created_at: 0.0,
            destination: DestinationConfig {
                role_arn: String::new(),
                s3_role_arn: String::new(),
                bucket_arn: String::new(),
                bucket: "lake".into(),
                prefix: String::new(),
                routing: None,
                s3_buffering_hints: None,
                iceberg: Some(iceberg::Target {
                    database: "lake".into(),
                    table: "events".into(),
                    bucket: "lake".into(),
                }),
                error_backup: None,
                logging: None,
                iceberg_delivery: Some(IcebergDeliveryPolicy {
                    size_mib: 1,
                    interval_seconds: 60,
                    retry_seconds: 300,
                }),
            },
            role_caller: None,
            pending: VecDeque::from([vec![1]]),
            retained: VecDeque::new(),
            buffered_bytes: 1,
            retry_token: None,
            in_flight: None,
            delivery_attempts: 0,
            retry_at: None,
            pending_since: Some(StartedAt::at(now).unwrap()),
            retry_started: None,
            terminal_failure: false,
            phase: DeliveryPhase::Primary,
            backup_attempts: 0,
            backed_up_records: 0,
            primary_failure: FailureCode::InternalError,
            encryption: None,
        }
    }

    #[test]
    fn completion_moves_full_backlog_without_copying_payload_bytes() {
        for outcome in [0, 1, 2] {
            let (handler, _handle) = FirehoseHandler::new(Weak::new());
            let scope = Scope {
                account_id: "000000000000".into(),
                region: "us-east-1".into(),
            };
            let key = StreamKey::new(&scope, "copies");
            let now = Instant::now();
            let mut original = stream(now);
            original.pending.clear();
            original.buffered_bytes = 0;
            original
                .destination
                .iceberg_delivery
                .as_mut()
                .unwrap()
                .interval_seconds = 0;
            handler
                .inner
                .append_pending(&key, &mut original, vec![vec![1; MAX_RECORD_BYTES]])
                .unwrap();
            handler
                .inner
                .lock_streams()
                .unwrap()
                .insert(key.clone(), original);
            let batch = handler.inner.take_batches().pop().unwrap();
            let token = batch.token;
            let batch_pointer = batch.records[0].as_ptr();
            let pending_pointers = {
                let mut streams = handler.inner.lock_streams().unwrap();
                let stream = streams.get_mut(&key).unwrap();
                let mut remaining = MAX_BUFFERED_BYTES - MAX_RECORD_BYTES;
                let mut records = Vec::new();
                while remaining > 0 {
                    let size = remaining.min(MAX_RECORD_BYTES);
                    records.push(vec![2; size]);
                    remaining -= size;
                }
                handler.inner.append_pending(&key, stream, records).unwrap();
                assert_eq!(buffered_usage(stream).1, MAX_BUFFERED_BYTES);
                stream
                    .pending
                    .iter()
                    .map(|record| record.as_ptr())
                    .collect::<Vec<_>>()
            };
            let request = serde_json::from_value(json!({
                "DeliveryStreamName":"copies", "Record":{"Data":"eyJpZCI6MX0="}
            }))
            .unwrap();
            assert!(matches!(
                handler.put_record(request, &scope),
                Err(FirehoseError::ServiceUnavailable(_))
            ));
            match outcome {
                0 => handler.inner.complete_batch(batch, true),
                1 => handler.inner.complete_batch(batch, false),
                _ => handler.inner.requeue_unauthorized_batch(batch),
            }
            let streams = handler.inner.lock_streams().unwrap();
            let stream = streams.get(&key).unwrap();
            let copied_pending_bytes: usize = stream
                .pending
                .iter()
                .zip(pending_pointers)
                .filter(|(record, before)| record.as_ptr() != *before)
                .map(|(record, _)| record.len())
                .sum();
            assert_eq!(copied_pending_bytes, 0);
            assert_eq!(
                stream.pending.len(),
                (MAX_BUFFERED_BYTES - MAX_RECORD_BYTES).div_ceil(MAX_RECORD_BYTES)
            );
            let expected = if outcome == 0 {
                MAX_BUFFERED_BYTES - MAX_RECORD_BYTES
            } else {
                MAX_BUFFERED_BYTES
            };
            assert_eq!(buffered_usage(stream).1, expected);
            if outcome != 0 {
                let retained = stream.retained.front().unwrap();
                let copied_batch_bytes = if retained.as_ptr() == batch_pointer {
                    0
                } else {
                    retained.len()
                };
                assert_eq!(copied_batch_bytes, 0);
                assert_eq!(stream.retry_token, Some(token));
            }
        }
    }

    #[test]
    fn persistence_failures_preserve_payload_ownership_usage_and_replay_token() {
        for outcome in [0, 1, 2] {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../.locallycloud-tmp/batch-apigw-firehose-ddb/firehose")
                .join(format!("rollback-{}", Uuid::new_v4()));
            let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
            let (handler, handle) =
                FirehoseHandler::with_state(Weak::new(), state.clone()).unwrap();
            let scope = Scope {
                account_id: "000000000000".into(),
                region: "us-east-1".into(),
            };
            let key = StreamKey::new(&scope, "rollback");
            let mut original = stream(Instant::now());
            original.pending.clear();
            original.buffered_bytes = 0;
            original
                .destination
                .iceberg_delivery
                .as_mut()
                .unwrap()
                .interval_seconds = 0;
            handler.inner.persist_create(&key, &original).unwrap();
            handler
                .inner
                .append_pending(&key, &mut original, vec![b"batch".to_vec()])
                .unwrap();
            handler
                .inner
                .lock_streams()
                .unwrap()
                .insert(key.clone(), original);
            let batch = handler.inner.take_batches().pop().unwrap();
            let token = batch.token;
            let batch_pointer = batch.records[0].as_ptr();
            let pending_pointer = {
                let mut streams = handler.inner.lock_streams().unwrap();
                let stream = streams.get_mut(&key).unwrap();
                handler
                    .inner
                    .append_pending(&key, stream, vec![b"pending".to_vec()])
                    .unwrap();
                stream.pending[0].as_ptr()
            };
            state.connection().unwrap().execute_batch("CREATE TRIGGER reject_completion BEFORE UPDATE ON firehose_streams BEGIN SELECT RAISE(ABORT,'injected completion failure'); END;").unwrap();
            match outcome {
                0 => handler.inner.complete_batch(batch, true),
                1 => handler.inner.complete_batch(batch, false),
                _ => handler.inner.requeue_unauthorized_batch(batch),
            }
            {
                let streams = handler.inner.lock_streams().unwrap();
                let stream = streams.get(&key).unwrap();
                assert_eq!(stream.pending[0].as_ptr(), pending_pointer);
                assert_eq!(stream.retained[0].as_ptr(), batch_pointer);
                assert_eq!(buffered_usage(stream), (2, b"batchpending".len()));
                assert_eq!(stream.delivery_attempts, 0);
                assert_eq!(stream.retry_token, Some(token));
            }
            state
                .connection()
                .unwrap()
                .execute_batch("DROP TRIGGER reject_completion;")
                .unwrap();
            let restored = persistence::load(&state).unwrap().remove(&key).unwrap();
            assert_eq!(buffered_usage(&restored), (2, b"batchpending".len()));
            assert_eq!(restored.retry_token, Some(token));
            handler
                .inner
                .lock_streams()
                .unwrap()
                .insert(key.clone(), restored);
            let retry = handler
                .inner
                .take_batches_at(Instant::now() + Duration::from_secs(1))
                .pop()
                .unwrap();
            assert_eq!(retry.token, token);
            handler.inner.complete_batch(retry, true);
            let restored = persistence::load(&state).unwrap().remove(&key).unwrap();
            assert_eq!(buffered_usage(&restored), (1, b"pending".len()));
            drop(handler);
            drop(handle);
            drop(state);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn retry_and_expiry_restore_buffers_when_config_persistence_fails() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _entered = runtime.enter();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.locallycloud-tmp/batch-apigw-firehose-ddb/firehose")
            .join(format!("retry-{}", Uuid::new_v4()));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let (handler, handle) = FirehoseHandler::with_state(Weak::new(), state.clone()).unwrap();
        let scope = Scope {
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let key = StreamKey::new(&scope, "retry");
        let mut original = stream(Instant::now());
        original.pending.clear();
        original.buffered_bytes = 0;
        original
            .destination
            .iceberg_delivery
            .as_mut()
            .unwrap()
            .interval_seconds = 0;
        handler.inner.persist_create(&key, &original).unwrap();
        handler
            .inner
            .append_pending(&key, &mut original, vec![b"retry".to_vec()])
            .unwrap();
        handler
            .inner
            .lock_streams()
            .unwrap()
            .insert(key.clone(), original);
        let batch = handler.inner.take_batches().pop().unwrap();
        let token = batch.token;
        let pointer = batch.records[0].as_ptr();
        handler.inner.complete_batch(batch, false);
        let now = Instant::now();
        {
            let mut streams = handler.inner.lock_streams().unwrap();
            let stream = streams.get_mut(&key).unwrap();
            stream.retry_at = None;
            stream.retry_started = Some(StartedAt::at(now - Duration::from_secs(301)).unwrap());
            handler.inner.persist_create(&key, stream).unwrap();
        }
        state.connection().unwrap().execute_batch("CREATE TRIGGER reject_retry BEFORE UPDATE ON firehose_streams BEGIN SELECT RAISE(ABORT,'injected retry failure'); END;").unwrap();
        assert!(handler.inner.take_batches_at(now).is_empty());
        {
            let mut streams = handler.inner.lock_streams().unwrap();
            let stream = streams.get_mut(&key).unwrap();
            assert_eq!(stream.retained[0].as_ptr(), pointer);
            assert_eq!(buffered_usage(stream), (1, b"retry".len()));
            assert!(!stream.terminal_failure);
            stream.terminal_failure = true;
        }
        let retry = || serde_json::from_value(json!({"DeliveryStreamName":"retry"})).unwrap();
        assert!(matches!(
            handler.retry_delivery_stream(retry(), &scope),
            Err(FirehoseError::Persistence)
        ));
        {
            let streams = handler.inner.lock_streams().unwrap();
            let stream = streams.get(&key).unwrap();
            assert!(stream.terminal_failure);
            assert_eq!(stream.retained[0].as_ptr(), pointer);
            assert_eq!(stream.retry_token, Some(token));
        }
        state
            .connection()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_retry;")
            .unwrap();
        assert!(handler.retry_delivery_stream(retry(), &scope).is_ok());
        let streams = handler.inner.lock_streams().unwrap();
        let stream = streams.get(&key).unwrap();
        assert!(!stream.terminal_failure);
        assert_eq!(stream.retained[0].as_ptr(), pointer);
        assert_eq!(buffered_usage(stream), (1, b"retry".len()));
        drop(streams);
        drop(handler);
        runtime.block_on(handle.shutdown());
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_before_first_worker_poll_joins_idle_worker() {
        let (handler, handle) = FirehoseHandler::new(Weak::new());
        handler.inner.ensure_worker().unwrap();
        let abort = handler
            .inner
            .worker
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .abort_handle();
        let stopped = tokio::time::timeout(Duration::from_secs(1), handle.shutdown()).await;
        if stopped.is_err() {
            abort.abort();
            tokio::task::yield_now().await;
        }
        assert!(
            stopped.is_ok(),
            "shutdown must wake and join an idle worker that has never polled"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sqlite_worker_checkpoints_keep_current_thread_live_after_caller_cancellation() {
        for source_page in [false, true] {
            let (root, state, handler, handle, key, generation, batch) =
                tokio::task::spawn_blocking(move || {
                    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../../.locallycloud-tmp/batch-apigw-firehose-ddb/firehose")
                        .join(format!("worker-writer-{}", Uuid::new_v4()));
                    let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
                    let (handler, handle) =
                        FirehoseHandler::with_state(Weak::new(), state.clone()).unwrap();
                    let scope = Scope {
                        account_id: "000000000000".into(),
                        region: "us-east-1".into(),
                    };
                    let key = StreamKey::new(&scope, "worker-writer");
                    let mut original = stream(Instant::now());
                    original.pending.clear();
                    original.buffered_bytes = 0;
                    original.destination.iceberg = None;
                    original.destination.iceberg_delivery = None;
                    if source_page {
                        original.source = Some(serde_json::from_value(json!({
                        "arn":"arn:aws:kinesis:us-east-1:000000000000:stream/source",
                        "name":"source", "role_arn":"arn:aws:iam::000000000000:role/firehose",
                        "ready":false, "failure":null, "creation_timestamp":null, "stopped":false
                    })).unwrap());
                    }
                    let generation = original.generation;
                    handler.inner.persist_create(&key, &original).unwrap();
                    if !source_page {
                        handler
                            .inner
                            .append_pending(&key, &mut original, vec![b"row".to_vec()])
                            .unwrap();
                    }
                    handler
                        .inner
                        .lock_streams()
                        .unwrap()
                        .insert(key.clone(), original);
                    let batch = if source_page {
                        None
                    } else {
                        Some(
                            handler
                                .inner
                                .take_batches_at(Instant::now() + Duration::from_secs(60))
                                .pop()
                                .unwrap(),
                        )
                    };
                    (root, state, handler, handle, key, generation, batch)
                })
                .await
                .unwrap();
            let expected_token = batch.as_ref().map(|batch| batch.token);
            let (ready_send, ready_receive) = tokio::sync::oneshot::channel();
            let (release_send, release_receive) = std::sync::mpsc::channel();
            let writer_state = state.clone();
            let writer = std::thread::spawn(move || {
                let mut connection = writer_state.connection().unwrap();
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .unwrap();
                ready_send.send(()).unwrap();
                // The watchdog turns an async-blocking regression into a test failure, not a hang.
                let _ = release_receive.recv_timeout(Duration::from_secs(3));
                transaction.commit().unwrap();
            });
            ready_receive.await.unwrap();
            let operation_inner = handler.inner.clone();
            let operation_key = key.clone();
            let operation = tokio::spawn(async move {
                match batch {
                    Some(batch) => operation_inner
                        .defer_unauthorized_batch(batch)
                        .await
                        .unwrap(),
                    None => operation_inner
                        .append_source_page(
                            operation_key,
                            generation,
                            1.0,
                            vec![("shard".into(), "1".into(), b"row".to_vec())],
                            1,
                        )
                        .await
                        .unwrap(),
                }
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if handler.inner.streams.try_lock().is_err() {
                        break;
                    }
                    assert!(
                        !operation.is_finished(),
                        "checkpoint finished before writer release"
                    );
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("checkpoint must enter its locked blocking transaction");
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(
                !operation.is_finished(),
                "runtime timer must advance while SQLite waits"
            );
            operation.abort();
            assert!(operation.await.unwrap_err().is_cancelled());
            let delay_inner = handler.inner.clone();
            let delay = tokio::spawn(async move { delay_inner.next_retry_delay().await.unwrap() });
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(
                !delay.is_finished(),
                "worker delay lookup must wait off the runtime thread"
            );
            let inventory_handler = FirehoseHandler {
                inner: handler.inner.clone(),
            };
            let account = key.scope.account_id.clone();
            let inventory =
                tokio::spawn(
                    async move { inventory_handler.resource_regions(&account).await.unwrap() },
                );
            let other_inventory_handler = FirehoseHandler {
                inner: handler.inner.clone(),
            };
            let other_inventory = tokio::spawn(async move {
                other_inventory_handler
                    .resource_regions("other-account")
                    .await
                    .unwrap()
            });
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(
                !inventory.is_finished(),
                "inventory must wait off the runtime thread"
            );
            assert!(
                !other_inventory.is_finished(),
                "foreign inventory must also wait off the runtime thread"
            );
            let reader_inner = handler.inner.clone();
            let reader_key = key.clone();
            let (reader_started, reader_ready) = tokio::sync::oneshot::channel();
            let reader = tokio::task::spawn_blocking(move || {
                reader_started.send(()).unwrap();
                let streams = reader_inner.lock_streams().unwrap();
                streams.get(&reader_key).unwrap().clone()
            });
            reader_ready.await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(
                !reader.is_finished(),
                "cancelled caller must not unlock the in-progress checkpoint"
            );
            release_send.send(()).unwrap();
            tokio::task::spawn_blocking(move || writer.join().unwrap())
                .await
                .unwrap();
            let memory = tokio::time::timeout(Duration::from_secs(5), reader)
                .await
                .unwrap()
                .unwrap();
            let _delay = tokio::time::timeout(Duration::from_secs(5), delay)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), inventory)
                    .await
                    .unwrap()
                    .unwrap(),
                vec![key.scope.region.clone()]
            );
            assert!(
                tokio::time::timeout(Duration::from_secs(5), other_inventory)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(buffered_usage(&memory), (1, b"row".len()));
            assert_eq!(memory.retry_token, expected_token);
            let restore_state = state.clone();
            let restore_key = key.clone();
            let restored = tokio::task::spawn_blocking(move || {
                persistence::load(&restore_state)
                    .unwrap()
                    .remove(&restore_key)
                    .unwrap()
            })
            .await
            .unwrap();
            assert_eq!(buffered_usage(&restored), buffered_usage(&memory));
            assert_eq!(restored.pending, memory.pending);
            assert_eq!(restored.retained, memory.retained);
            assert_eq!(restored.retry_token, expected_token);
            if source_page {
                assert_eq!(
                    restored.source.as_ref().unwrap().fetched_shards["shard"],
                    "1"
                );
                assert_eq!(restored.source.as_ref().unwrap().next_shard, 1);
                let inner = handler.inner.clone();
                let replacement_key = key.clone();
                let replacement_generation = tokio::task::spawn_blocking(move || {
                    let mut streams = inner.lock_streams().unwrap();
                    let mut replacement = streams.get(&replacement_key).unwrap().clone();
                    replacement.generation = Uuid::new_v4();
                    replacement.pending.clear();
                    replacement.buffered_bytes = 0;
                    replacement.pending_since = None;
                    let source = replacement.source.as_mut().unwrap();
                    source.fetched_shards.clear();
                    source.creation_timestamp = None;
                    source.next_shard = 0;
                    inner.persist_delete(&replacement_key).unwrap();
                    inner
                        .persist_create(&replacement_key, &replacement)
                        .unwrap();
                    let generation = replacement.generation;
                    streams.insert(replacement_key, replacement);
                    generation
                })
                .await
                .unwrap();
                handler
                    .inner
                    .append_source_page(
                        key.clone(),
                        generation,
                        2.0,
                        vec![("shard".into(), "stale".into(), b"stale".to_vec())],
                        2,
                    )
                    .await
                    .unwrap();
                let inner = handler.inner.clone();
                let stale_key = key.clone();
                let current = tokio::task::spawn_blocking(move || {
                    let streams = inner.lock_streams().unwrap();
                    streams.get(&stale_key).unwrap().clone()
                })
                .await
                .unwrap();
                assert_eq!(current.generation, replacement_generation);
                assert_eq!(buffered_usage(&current), (0, 0));
                assert!(current.source.as_ref().unwrap().fetched_shards.is_empty());
                assert_eq!(current.source.as_ref().unwrap().creation_timestamp, None);
            }
            drop(handler);
            drop(handle);
            drop(state);
            tokio::fs::remove_dir_all(root).await.unwrap();
        }
    }

    #[test]
    fn independent_stream_deadlines_size_and_retry_window() {
        let (handler, _) = FirehoseHandler::new(Weak::new());
        let scope = Scope {
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let slow_key = StreamKey::new(&scope, "slow");
        let fast_key = StreamKey::new(&scope, "fast");
        let now = Instant::now();
        let slow = stream(now);
        let mut fast = stream(now);
        fast.destination
            .iceberg_delivery
            .as_mut()
            .unwrap()
            .interval_seconds = 0;
        handler
            .inner
            .lock_streams()
            .unwrap()
            .extend([(slow_key.clone(), slow), (fast_key.clone(), fast)]);
        let batch = handler.inner.take_batches_at(now).pop().unwrap();
        assert_eq!(batch.key.name, "fast");
        handler.inner.complete_batch_at(batch, true, now);
        assert!(handler
            .inner
            .take_batches_at(now + Duration::from_secs(59))
            .is_empty());
        let first = handler
            .inner
            .take_batches_at(now + Duration::from_secs(60))
            .pop()
            .unwrap();
        assert_eq!(first.key.name, "slow");
        let token = first.token;
        handler
            .inner
            .complete_batch_at(first, false, now + Duration::from_secs(120));
        // More than six failed attempts remain eligible inside Iceberg's duration budget.
        for attempt in 1..8 {
            let due = now + Duration::from_secs(120 + attempt * 30);
            let batch = handler.inner.take_batches_at(due).pop().unwrap();
            assert_eq!(batch.token, token);
            handler.inner.complete_batch_at(batch, false, due);
        }
        assert!(!handler.inner.lock_streams().unwrap()[&slow_key].terminal_failure);
        assert!(!handler.inner.lock_streams().unwrap()[&slow_key]
            .retry_expired(now + Duration::from_secs(360)));
        assert!(handler
            .inner
            .take_batches_at(now + Duration::from_secs(420))
            .is_empty());
        let streams = handler.inner.lock_streams().unwrap();
        assert!(streams[&slow_key].terminal_failure);
        assert_eq!(streams[&slow_key].retained, [vec![1]]);
        drop(streams);

        let mut sized = stream(now);
        sized.pending = VecDeque::from([vec![1; 1024 * 1024 - 1]]);
        sized.buffered_bytes = 1024 * 1024 - 1;
        assert_eq!(sized.delivery_delay(now), Some(Duration::from_secs(60)));
        sized.pending.push_back(vec![2]);
        sized.buffered_bytes += 1;
        assert_eq!(sized.delivery_delay(now), Some(Duration::ZERO));
        assert_eq!(
            sized.delivery_delay(now + Duration::from_secs(60)),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn policy_validation_defaults_and_boundaries() {
        for hints in [
            None,
            Some(BufferingHints {
                size_in_m_bs: None,
                interval_in_seconds: None,
            }),
        ] {
            let p = IcebergDeliveryPolicy::parse(hints.as_ref(), None).unwrap();
            assert_eq!(
                (p.size_mib, p.interval_seconds, p.retry_seconds),
                (5, 300, 300)
            );
        }
        for (size, interval) in [(1, 0), (128, 900)] {
            let hints = BufferingHints {
                size_in_m_bs: Some(size),
                interval_in_seconds: Some(interval),
            };
            let policy = IcebergDeliveryPolicy::parse(
                Some(&hints),
                Some(&RetryOptions {
                    duration_in_seconds: Some(7200),
                }),
            )
            .unwrap();
            assert_eq!(policy.size_mib, u32::try_from(size).unwrap());
        }
        for (size, interval) in [
            (Some(1), None),
            (None, Some(0)),
            (Some(0), Some(1)),
            (Some(129), Some(1)),
            (Some(1), Some(-1)),
            (Some(1), Some(901)),
        ] {
            assert!(IcebergDeliveryPolicy::parse(
                Some(&BufferingHints {
                    size_in_m_bs: size,
                    interval_in_seconds: interval
                }),
                None
            )
            .is_err());
        }
        for seconds in [-1, 7201] {
            assert!(IcebergDeliveryPolicy::parse(
                None,
                Some(&RetryOptions {
                    duration_in_seconds: Some(seconds)
                })
            )
            .is_err());
        }
    }

    #[test]
    fn restart_preserves_pending_age_retry_budget_backoff_and_legacy_state() {
        let observed = StartedAt::now().unwrap();
        let delayed = StartedAt::at(observed.monotonic - Duration::from_secs(2)).unwrap();
        assert!(
            delayed
                .unix_ms
                .saturating_add(2000)
                .abs_diff(observed.unix_ms)
                <= 2
        );
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.kiro/localcloud-tmp/firehose-iceberg-tests")
            .join(format!("clock-{}", Uuid::new_v4()));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let (handler, handle) = FirehoseHandler::with_state(Weak::new(), state.clone()).unwrap();
        let scope = Scope {
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let key = StreamKey::new(&scope, "clock");
        let now = Instant::now();
        let mut original = stream(now);
        original.pending.clear();
        original.buffered_bytes = 0;
        original.pending_since = None;
        handler.inner.persist_create(&key, &original).unwrap();
        state.connection().unwrap().execute_batch("CREATE TRIGGER fail_clock_append BEFORE INSERT ON firehose_records BEGIN SELECT RAISE(FAIL,'injected'); END;").unwrap();
        assert!(handler
            .inner
            .append_pending(&key, &mut original, vec![b"rejected".to_vec()])
            .is_err());
        assert!(original.pending.is_empty());
        assert_eq!(buffered_usage(&original), (0, 0));
        assert!(original.pending_since.is_none());
        let rejected = persistence::load(&state).unwrap().remove(&key).unwrap();
        assert!(rejected.pending.is_empty());
        assert_eq!(buffered_usage(&rejected), (0, 0));
        assert!(rejected.pending_since.is_none());
        state
            .connection()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_clock_append;")
            .unwrap();
        handler
            .inner
            .append_pending(&key, &mut original, vec![b"row".to_vec()])
            .unwrap();
        let accepted = original.pending_since.unwrap();
        let accepted_ms = accepted.unix_ms;
        let loaded = persistence::load(&state).unwrap().remove(&key).unwrap();
        assert_eq!(loaded.pending_since.unwrap().unix_ms, accepted_ms);
        assert_eq!(loaded.pending, [b"row".to_vec()]);
        assert_eq!(buffered_usage(&loaded), (1, b"row".len()));
        assert_eq!(loaded.iceberg_policy().unwrap().interval_seconds, 60);
        assert_eq!(
            loaded.delivery_delay(loaded.pending_since.unwrap().monotonic),
            Some(Duration::from_secs(60))
        );
        handler
            .inner
            .lock_streams()
            .unwrap()
            .insert(key.clone(), original);
        let batch = handler
            .inner
            .take_batches_at(accepted.monotonic + Duration::from_secs(60))
            .pop()
            .unwrap();
        handler
            .inner
            .complete_batch_at(batch, false, accepted.monotonic + Duration::from_secs(60));
        let mut loaded = persistence::load(&state).unwrap().remove(&key).unwrap();
        assert!(loaded.retry_started.is_some());
        assert!(loaded.retry_at.is_some());
        assert!(loaded.retry_at.unwrap() > Instant::now());
        assert_eq!(loaded.retained, [b"row".to_vec()]);
        // A committed old first-attempt timestamp cannot acquire a new retry window on restore.
        loaded.retry_started.as_mut().unwrap().unix_ms = accepted_ms.saturating_sub(301_000);
        handler.inner.persist_create(&key, &loaded).unwrap();
        let loaded = persistence::load(&state).unwrap().remove(&key).unwrap();
        assert!(loaded.retry_expired(Instant::now()));
        // Old configurations deserialize with the documented defaults and a fresh conservative clock.
        {
            let connection = state.connection().unwrap();
            let text: String = connection
                .query_row("SELECT config FROM firehose_streams", [], |r| r.get(0))
                .unwrap();
            let mut saved: Value = serde_json::from_str(&text).unwrap();
            for name in [
                "pending_since_ms",
                "retry_started_ms",
                "retry_due_ms",
                "primary_failure",
            ] {
                saved.as_object_mut().unwrap().remove(name);
            }
            saved["destination"]
                .as_object_mut()
                .unwrap()
                .remove("iceberg_delivery");
            connection
                .execute("UPDATE firehose_streams SET config=?1", [saved.to_string()])
                .unwrap();
        }
        let legacy = persistence::load(&state).unwrap().remove(&key).unwrap();
        assert_eq!(legacy.iceberg_policy().unwrap().interval_seconds, 300);
        assert_eq!(legacy.primary_failure, FailureCode::InternalError);
        assert!(legacy.retry_remaining(Instant::now()).unwrap() > Duration::from_secs(298));
        let second = persistence::load(&state).unwrap().remove(&key).unwrap();
        assert_eq!(
            legacy.retry_started.unwrap().unix_ms,
            second.retry_started.unwrap().unix_ms
        );
        drop(handle);
        drop(handler);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn backup_phase_survives_restart_and_failed_ack_without_reentering_iceberg() {
        for failure in [
            FailureCode::NoSuchTable,
            FailureCode::GlueAccessDenied,
            FailureCode::S3AccessDenied,
        ] {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../.kiro/localcloud-tmp/firehose-iceberg-tests")
                .join(format!("backup-{}", Uuid::new_v4()));
            let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
            let (handler, handle) =
                FirehoseHandler::with_state(Weak::new(), state.clone()).unwrap();
            let scope = Scope {
                account_id: "000000000000".into(),
                region: "us-east-1".into(),
            };
            let key = StreamKey::new(&scope, "backup");
            let now = Instant::now();
            let mut original = stream(now);
            original.pending.clear();
            original.buffered_bytes = 0;
            original.pending_since = None;
            let policy = original.destination.iceberg_delivery.as_mut().unwrap();
            policy.interval_seconds = 0;
            policy.retry_seconds = 0;
            original.destination.error_backup = Some(failure::ErrorBackup {
                prefix: "errors/".into(),
                global_prefix: Some("errors/".into()),
                table_prefix: None,
                logging: None,
            });
            handler.inner.persist_create(&key, &original).unwrap();
            handler
                .inner
                .append_pending(&key, &mut original, vec![b"original".to_vec()])
                .unwrap();
            handler
                .inner
                .lock_streams()
                .unwrap()
                .insert(key.clone(), original);
            let primary = handler.inner.take_batches().pop().unwrap();
            let token = primary.token;
            assert_eq!(primary.phase, DeliveryPhase::Primary);
            handler
                .inner
                .complete_delivery_at(primary, Err(failure), Instant::now());
            let backup = handler.inner.take_batches().pop().unwrap();
            assert_eq!(backup.phase, DeliveryPhase::Backup);
            assert_eq!(backup.primary_failure, failure);
            assert_eq!(backup.token, token);
            // Crash after the backup side effect but before its acknowledgement is observed.
            let loaded = persistence::load(&state).unwrap().remove(&key).unwrap();
            assert_eq!(loaded.phase, DeliveryPhase::Backup);
            assert_eq!(loaded.backed_up_records, 0);
            assert_eq!(loaded.primary_failure, failure);
            handler
                .inner
                .lock_streams()
                .unwrap()
                .insert(key.clone(), loaded);
            let retry = handler.inner.take_batches().pop().unwrap();
            assert_eq!(retry.phase, DeliveryPhase::Backup);
            assert_eq!(retry.token, token);
            handler.inner.complete_batch(retry, false);
            for attempt in 1..MAX_DELIVERY_ATTEMPTS {
                let at = Instant::now() + Duration::from_secs(u64::from(attempt) * 30);
                let retry = handler.inner.take_batches_at(at).pop().unwrap();
                assert_eq!(retry.phase, DeliveryPhase::Backup);
                assert_eq!(retry.records, [b"original".to_vec()]);
                handler.inner.complete_batch_at(retry, false, at);
            }
            let loaded = persistence::load(&state).unwrap().remove(&key).unwrap();
            assert!(loaded.terminal_failure);
            assert_eq!(loaded.backup_attempts, MAX_DELIVERY_ATTEMPTS);
            assert_eq!(loaded.phase, DeliveryPhase::Backup);
            assert_eq!(loaded.retained, [b"original".to_vec()]);
            assert_eq!(loaded.backed_up_records, 0);
            assert_eq!(loaded.primary_failure, failure);
            let mut loaded = loaded;
            loaded.terminal_failure = false;
            loaded.retry_at = None;
            loaded.backup_attempts = 0;
            handler
                .inner
                .lock_streams()
                .unwrap()
                .insert(key.clone(), loaded);
            let retry = handler.inner.take_batches().pop().unwrap();
            assert_eq!(retry.phase, DeliveryPhase::Backup);
            handler.inner.complete_batch(retry, true);
            let loaded = persistence::load(&state).unwrap().remove(&key).unwrap();
            assert_eq!(loaded.phase, DeliveryPhase::Primary);
            assert_eq!(loaded.backed_up_records, 1);
            assert_eq!(loaded.primary_failure, FailureCode::InternalError);
            assert!(loaded.pending.is_empty() && loaded.retained.is_empty());
            drop(handle);
            drop(handler);
            drop(state);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
