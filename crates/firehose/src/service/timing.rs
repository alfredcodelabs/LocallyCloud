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
        if self.pending.iter().map(Vec::len).sum::<usize>() >= size
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
        assert_eq!(sized.delivery_delay(now), Some(Duration::from_secs(60)));
        sized.pending.push_back(vec![2]);
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
            .join("../../target/firehose-iceberg-tests")
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
        original.pending_since = None;
        handler.inner.persist_create(&key, &original).unwrap();
        state.connection().unwrap().execute_batch("CREATE TRIGGER fail_clock_append BEFORE INSERT ON firehose_records BEGIN SELECT RAISE(FAIL,'injected'); END;").unwrap();
        assert!(handler
            .inner
            .append_pending(&key, &mut original, vec![b"rejected".to_vec()])
            .is_err());
        assert!(original.pending.is_empty());
        assert!(original.pending_since.is_none());
        let rejected = persistence::load(&state).unwrap().remove(&key).unwrap();
        assert!(rejected.pending.is_empty());
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
                .join("../../target/firehose-iceberg-tests")
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
