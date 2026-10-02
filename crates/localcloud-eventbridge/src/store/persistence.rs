use super::*;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use std::collections::HashSet;
use std::sync::atomic::Ordering;

impl EbStore {
    pub fn with_state(state: Arc<StateDb>) -> Result<Self, String> {
        Self::with_state_and_crypto(state, ConnectionCrypto::from_env()?)
    }

    pub(super) fn with_state_and_crypto(
        state: Arc<StateDb>,
        crypto: Option<ConnectionCrypto>,
    ) -> Result<Self, String> {
        let connection = state.connection().map_err(|error| error.to_string())?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS events_buses (
                account TEXT NOT NULL, region TEXT NOT NULL, payload BLOB NOT NULL,
                PRIMARY KEY(account, region)
            );
            CREATE TABLE IF NOT EXISTS events_scheduler (
                account TEXT NOT NULL, region TEXT NOT NULL, payload BLOB NOT NULL,
                PRIMARY KEY(account, region)
            );
            CREATE TABLE IF NOT EXISTS events_connections (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL, sealed BLOB NOT NULL,
                PRIMARY KEY(account,region,name)
            );
            CREATE TABLE IF NOT EXISTS events_api_destinations (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL, payload BLOB NOT NULL,
                PRIMARY KEY(account,region,name)
            );
            CREATE TABLE IF NOT EXISTS events_firing_cursor (
                kind TEXT NOT NULL, arn TEXT NOT NULL, generation INTEGER NOT NULL,
                cursor_ns INTEGER NOT NULL, anchor_ns INTEGER NOT NULL, PRIMARY KEY(kind, arn)
            );
            CREATE TABLE IF NOT EXISTS events_pending_firing (
                kind TEXT NOT NULL, arn TEXT NOT NULL, due_ns INTEGER NOT NULL,
                payload BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                next_retry_ns INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'PENDING', terminal_reason TEXT,
                PRIMARY KEY(kind, arn, due_ns)
            );
            CREATE TABLE IF NOT EXISTS events_pending_fanout (
                id TEXT PRIMARY KEY, payload BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events_archives (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                payload BLOB NOT NULL, PRIMARY KEY(account,region,name)
            );
            CREATE TABLE IF NOT EXISTS events_archived_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                account TEXT NOT NULL, region TEXT NOT NULL, archive_name TEXT NOT NULL,
                time_ns INTEGER NOT NULL, payload BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_archived_events_lookup
                ON events_archived_events(account,region,archive_name,time_ns);
            CREATE TABLE IF NOT EXISTS events_replays (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                payload BLOB NOT NULL, cursor INTEGER NOT NULL,
                PRIMARY KEY(account,region,name)
            );
            CREATE TABLE IF NOT EXISTS events_replay_items (
                account TEXT NOT NULL, region TEXT NOT NULL, replay_name TEXT NOT NULL,
                ordinal INTEGER NOT NULL, payload BLOB NOT NULL,
                PRIMARY KEY(account,region,replay_name,ordinal)
            );",
            )
            .map_err(|error| error.to_string())?;
        let store = Self {
            persistence: Some(state),
            connection_crypto: crypto,
            ..Self::default()
        };
        let mut statement = connection
            .prepare("SELECT account, region, payload FROM events_buses")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        for row in rows {
            let (account, region, payload) = row.map_err(|error| error.to_string())?;
            let buses = serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
            let account_state = AccountState {
                buses,
                ..AccountState::default()
            };
            store
                .scopes
                .insert((account, region), Arc::new(RwLock::new(account_state)));
        }
        drop(statement);
        let mut statement = connection
            .prepare("SELECT account, region, payload FROM events_scheduler")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        for row in rows {
            let (account, region, payload) = row.map_err(|error| error.to_string())?;
            let (groups, schedules): (BTreeMap<String, ScheduleGroup>, Vec<Schedule>) =
                serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
            let scope = store
                .scopes
                .entry((account, region))
                .or_insert_with(|| Arc::new(RwLock::new(AccountState::default())))
                .clone();
            let mut guard = scope.try_write().map_err(|error| error.to_string())?;
            guard.schedule_groups = groups;
            guard.schedules = schedules
                .into_iter()
                .map(|schedule| ((schedule.group.clone(), schedule.name.clone()), schedule))
                .collect();
        }
        drop(statement);
        let mut statement = connection
            .prepare("SELECT account,region,name,sealed FROM events_connections")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        for row in rows {
            let (account, region, name, sealed) = row.map_err(|error| error.to_string())?;
            let crypto = store.connection_crypto.as_ref().ok_or(
                "LOCALCLOUD_KMS_MASTER_KEY is required for stored EventBridge Connections",
            )?;
            let item = crypto.open(&account, &region, &name, &sealed)?;
            let scope = store
                .scopes
                .entry((account, region))
                .or_insert_with(|| Arc::new(RwLock::new(AccountState::default())))
                .clone();
            scope
                .try_write()
                .map_err(|error| error.to_string())?
                .connections
                .insert(name, item);
        }
        drop(statement);
        let mut statement = connection
            .prepare("SELECT account,region,name,payload FROM events_api_destinations")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        for row in rows {
            let (account, region, name, payload) = row.map_err(|error| error.to_string())?;
            let item: ApiDestination =
                serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
            if item.name != name {
                return Err("API Destination name mismatch".into());
            }
            let scope = store
                .scopes
                .entry((account, region))
                .or_insert_with(|| Arc::new(RwLock::new(AccountState::default())))
                .clone();
            scope
                .try_write()
                .map_err(|error| error.to_string())?
                .api_destinations
                .insert(name, item);
        }
        drop(statement);
        let mut statement = connection
            .prepare("SELECT account,region,name,payload FROM events_archives")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        for row in rows {
            let (account, region, name, payload) = row.map_err(|error| error.to_string())?;
            let archive: Archive =
                serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
            if archive.name != name || !archive.events.is_empty() {
                return Err("invalid EventBridge archive metadata".into());
            }
            let scope = store
                .scopes
                .entry((account, region))
                .or_insert_with(|| Arc::new(RwLock::new(AccountState::default())))
                .clone();
            scope
                .try_write()
                .map_err(|error| error.to_string())?
                .archives
                .insert(name, archive);
        }
        drop(statement);
        let mut statement = connection
            .prepare("SELECT account,region,name,payload,cursor FROM events_replays")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        for row in rows {
            let (account, region, name, payload, cursor) =
                row.map_err(|error| error.to_string())?;
            let replay: Replay =
                serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
            if replay.name != name || cursor < 0 {
                return Err("invalid EventBridge replay metadata".into());
            }
            let scope = store
                .scopes
                .entry((account, region))
                .or_insert_with(|| Arc::new(RwLock::new(AccountState::default())))
                .clone();
            scope
                .try_write()
                .map_err(|error| error.to_string())?
                .replays
                .insert(name, replay);
        }
        drop(statement);
        let mut statement = connection
            .prepare("SELECT kind,payload FROM events_pending_firing")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|error| error.to_string())?;
        for row in rows {
            let (kind, payload) = row.map_err(|error| error.to_string())?;
            let value: Value =
                serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
            match kind.as_str() {
                "scheduler" => {
                    serde_json::from_value::<Schedule>(value).map_err(|error| error.to_string())?;
                }
                "rule" => {
                    serde_json::from_value::<Rule>(
                        value
                            .get("rule")
                            .cloned()
                            .ok_or("missing rule firing snapshot")?,
                    )
                    .map_err(|error| error.to_string())?;
                    if value.get("event").is_none() {
                        return Err("missing rule firing event".into());
                    }
                }
                _ => return Err(format!("unknown firing kind {kind}")),
            }
        }
        Ok(store)
    }

    pub(crate) fn state_db(&self) -> Option<Arc<StateDb>> {
        self.persistence.clone()
    }

    pub(crate) fn restore_pipe(
        &self,
        account: String,
        region: String,
        pipe: Pipe,
    ) -> Result<(), String> {
        let scope = self
            .scopes
            .entry((account, region))
            .or_insert_with(|| Arc::new(RwLock::new(AccountState::default())))
            .clone();
        let mut guard = scope.try_write().map_err(|error| error.to_string())?;
        guard.pipes.insert(pipe.name.clone(), pipe);
        Ok(())
    }

    pub(crate) fn scope_keys(&self) -> Vec<(String, String)> {
        self.bus_scope_keys()
    }

    pub async fn persist_scheduler(
        &self,
        account: &str,
        region: &str,
        now: OffsetDateTime,
    ) -> Result<(), String> {
        let Some(db) = &self.persistence else {
            return Ok(());
        };
        let _gate = self.persist_lock.lock().await;
        let scope = self.scope(account, region).await;
        let guard = scope.read().await;
        let payload = serde_json::to_vec(&(
            &guard.schedule_groups,
            guard.schedules.values().collect::<Vec<_>>(),
        ))
        .map_err(|error| error.to_string())?;
        let cursors: Vec<_> = guard
            .schedules
            .values()
            .filter(|item| item.state == "ENABLED")
            .map(|item| {
                let initial = if item.expression.starts_with("at(") {
                    now - time::Duration::nanoseconds(1)
                } else if item.start_date.is_some_and(|start| start > now) {
                    item.start_date.unwrap_or(now) - time::Duration::minutes(1)
                } else {
                    now
                };
                let anchor = item.start_date.unwrap_or(now);
                (
                    item.arn.clone(),
                    item.generation as i64,
                    initial.unix_timestamp_nanos() as i64,
                    anchor.unix_timestamp_nanos() as i64,
                )
            })
            .collect();
        let present: HashSet<_> = guard
            .schedules
            .values()
            .map(|item| item.arn.clone())
            .collect();
        drop(guard);
        let db = db.clone();
        let account = account.to_string();
        let region = region.to_string();
        let result =
            tokio::task::spawn_blocking(move || {
                let mut connection = db.connection().map_err(|error| error.to_string())?;
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|error| error.to_string())?;
                let old: Option<Vec<u8>> = transaction.query_row(
                    "SELECT payload FROM events_scheduler WHERE account=?1 AND region=?2",
                    params![account,region], |row| row.get(0)
                ).optional().map_err(|error| error.to_string())?;
                if let Some(old) = old {
                    let (_, schedules): (BTreeMap<String, ScheduleGroup>, Vec<Schedule>) =
                        serde_json::from_slice(&old).map_err(|error| error.to_string())?;
                    for schedule in schedules {
                        if !present.contains(&schedule.arn) {
                            let count = transaction.execute(
                                "UPDATE events_pending_firing SET status='CANCELLED',
                                 terminal_reason='configuration changed'
                                 WHERE kind='scheduler' AND arn=?1 AND status='PENDING'",
                                params![schedule.arn]
                            ).map_err(|error| error.to_string())?;
                            if count > 0 { tracing::warn!(arn=%schedule.arn,count,"Scheduler firings cancelled after configuration change"); }
                        }
                    }
                }
                transaction
                    .execute(
                        "INSERT INTO events_scheduler(account,region,payload) VALUES(?1,?2,?3)
                 ON CONFLICT(account,region) DO UPDATE SET payload=excluded.payload",
                        params![account, region, payload],
                    )
                    .map_err(|error| error.to_string())?;
                for (arn, generation, cursor, anchor) in cursors {
                    transaction.execute(
                    "INSERT INTO events_firing_cursor(kind,arn,generation,cursor_ns,anchor_ns)
                     VALUES('scheduler',?1,?2,?3,?4)
                     ON CONFLICT(kind,arn) DO UPDATE SET generation=excluded.generation,
                        cursor_ns=excluded.cursor_ns,anchor_ns=excluded.anchor_ns
                     WHERE events_firing_cursor.generation != excluded.generation",
                    params![arn,generation,cursor,anchor]
                ).map_err(|error| error.to_string())?;
                }
                transaction.commit().map_err(|error| error.to_string())
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result);
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    pub fn firing_cursor(
        &self,
        kind: &str,
        arn: &str,
        generation: u64,
        initial: i64,
        anchor: i64,
    ) -> Result<(i64, i64), String> {
        let Some(db) = &self.persistence else {
            return Ok((initial, anchor));
        };
        let connection = db.connection().map_err(|error| error.to_string())?;
        connection.execute(
            "INSERT INTO events_firing_cursor(kind,arn,generation,cursor_ns,anchor_ns) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(kind,arn) DO UPDATE SET generation=excluded.generation,cursor_ns=excluded.cursor_ns,anchor_ns=excluded.anchor_ns
             WHERE events_firing_cursor.generation != excluded.generation",
            params![kind, arn, generation as i64, initial, anchor]
        ).map_err(|error| error.to_string())?;
        connection
            .query_row(
                "SELECT cursor_ns,anchor_ns FROM events_firing_cursor WHERE kind=?1 AND arn=?2",
                params![kind, arn],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())
    }

    pub fn enqueue_firing(
        &self,
        kind: &str,
        arn: &str,
        generation: u64,
        due_ns: i64,
        payload: &Value,
    ) -> Result<(), String> {
        let Some(db) = &self.persistence else {
            return Ok(());
        };
        let mut connection = db.connection().map_err(|error| error.to_string())?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let payload = serde_json::to_vec(payload).map_err(|error| error.to_string())?;
        let updated = transaction.execute(
            "UPDATE events_firing_cursor SET cursor_ns=?4 WHERE kind=?1 AND arn=?2 AND generation=?3 AND cursor_ns<?4",
            params![kind,arn,generation as i64,due_ns]
        ).map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("stale scheduled firing".into());
        }
        transaction.execute(
            "INSERT OR IGNORE INTO events_pending_firing(kind,arn,due_ns,payload) VALUES(?1,?2,?3,?4)",
            params![kind,arn,due_ns,payload]
        ).map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn pending_firings(&self, kind: &str, arn: &str) -> Result<Vec<(i64, Value)>, String> {
        let Some(db) = &self.persistence else {
            return Ok(Vec::new());
        };
        let connection = db.connection().map_err(|error| error.to_string())?;
        let mut statement = connection.prepare(
            "SELECT due_ns,payload FROM events_pending_firing WHERE kind=?1 AND arn=?2 AND status='PENDING' ORDER BY due_ns"
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![kind, arn], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (due, payload) = row.map_err(|error| error.to_string())?;
            let value = serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
            Ok((due, value))
        })
        .collect()
    }

    pub fn firing_ready(
        &self,
        kind: &str,
        arn: &str,
        due_ns: i64,
        now_ns: i64,
    ) -> Result<bool, String> {
        let Some(db) = &self.persistence else {
            return Ok(true);
        };
        let connection = db.connection().map_err(|error| error.to_string())?;
        let next: i64 = connection.query_row(
            "SELECT next_retry_ns FROM events_pending_firing WHERE kind=?1 AND arn=?2 AND due_ns=?3",
            params![kind,arn,due_ns], |row| row.get(0)
        ).map_err(|error| error.to_string())?;
        Ok(next <= now_ns)
    }

    pub fn defer_firing(
        &self,
        kind: &str,
        arn: &str,
        due_ns: i64,
        now_ns: i64,
    ) -> Result<(), String> {
        let Some(db) = &self.persistence else {
            return Ok(());
        };
        let connection = db.connection().map_err(|error| error.to_string())?;
        let attempts: i64 = connection
            .query_row(
                "SELECT attempts FROM events_pending_firing WHERE kind=?1 AND arn=?2 AND due_ns=?3",
                params![kind, arn, due_ns],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let delay = (1_i64 << attempts.min(5)).min(30);
        connection
            .execute(
                "UPDATE events_pending_firing SET attempts=attempts+1,next_retry_ns=?4
             WHERE kind=?1 AND arn=?2 AND due_ns=?3",
                params![
                    kind,
                    arn,
                    due_ns,
                    now_ns.saturating_add(delay * 1_000_000_000)
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn terminal_firing(
        &self,
        kind: &str,
        arn: &str,
        due_ns: i64,
        reason: &str,
    ) -> Result<(), String> {
        let Some(db) = &self.persistence else {
            return Ok(());
        };
        db.connection()
            .map_err(|error| error.to_string())?
            .execute(
                "UPDATE events_pending_firing SET status='FAILED',terminal_reason=?4
                 WHERE kind=?1 AND arn=?2 AND due_ns=?3 AND status='PENDING'",
                params![kind, arn, due_ns, reason],
            )
            .map_err(|error| error.to_string())?;
        tracing::error!(kind, arn, due_ns, reason, "scheduled firing exhausted");
        Ok(())
    }

    pub fn firing_attempts(&self, kind: &str, arn: &str, due_ns: i64) -> Result<i64, String> {
        let Some(db) = &self.persistence else {
            return Ok(0);
        };
        db.connection()
            .map_err(|error| error.to_string())?
            .query_row(
                "SELECT attempts FROM events_pending_firing WHERE kind=?1 AND arn=?2 AND due_ns=?3",
                params![kind, arn, due_ns],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())
    }

    pub fn complete_firing(&self, kind: &str, arn: &str, due_ns: i64) -> Result<(), String> {
        let Some(db) = &self.persistence else {
            return Ok(());
        };
        db.connection()
            .map_err(|error| error.to_string())?
            .execute(
                "DELETE FROM events_pending_firing WHERE kind=?1 AND arn=?2 AND due_ns=?3",
                params![kind, arn, due_ns],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn pending_notify(&self) -> Arc<tokio::sync::Notify> {
        self.pending_notify.clone()
    }

    pub fn notify_pending(&self) {
        self.pending_notify.notify_one();
    }

    pub fn healthy(&self) -> bool {
        !self.poisoned.load(Ordering::Acquire)
    }

    pub fn bus_scope_keys(&self) -> Vec<(String, String)> {
        self.scopes
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub async fn persist_buses(&self, account: &str, region: &str) -> Result<(), String> {
        self.persist_buses_at(account, region, OffsetDateTime::now_utc())
            .await
    }

    pub async fn persist_buses_at(
        &self,
        account: &str,
        region: &str,
        now: OffsetDateTime,
    ) -> Result<(), String> {
        let Some(db) = &self.persistence else {
            return Ok(());
        };
        let _gate = self.persist_lock.lock().await;
        let scope = self.scope(account, region).await;
        let guard = scope.read().await;
        let payload = serde_json::to_vec(&guard.buses).map_err(|error| error.to_string())?;
        let mut connections = Vec::with_capacity(guard.connections.len());
        for item in guard.connections.values() {
            let crypto = self.connection_crypto.as_ref().ok_or_else(|| {
                self.poisoned.store(true, Ordering::Release);
                "LOCALCLOUD_KMS_MASTER_KEY is required for EventBridge Connections".to_string()
            })?;
            let sealed = crypto.seal(account, region, item).inspect_err(|_| {
                self.poisoned.store(true, Ordering::Release);
            })?;
            connections.push((item.name.clone(), sealed));
        }
        let destinations: Vec<_> = guard
            .api_destinations
            .values()
            .map(|item| serde_json::to_vec(item).map(|payload| (item.name.clone(), payload)))
            .collect::<Result<_, _>>()
            .map_err(|error| error.to_string())?;
        let rules: Vec<_> = guard
            .buses
            .values()
            .flat_map(|bus| bus.rules.values())
            .filter(|rule| rule.enabled() && rule.schedule_expression.is_some())
            .map(|rule| (rule.arn.clone(), rule.generation as i64))
            .collect();
        let present: HashSet<_> = guard
            .buses
            .values()
            .flat_map(|bus| bus.rules.values())
            .map(|rule| rule.arn.clone())
            .collect();
        drop(guard);
        let db = db.clone();
        let account = account.to_string();
        let region = region.to_string();
        let cursor = now.unix_timestamp_nanos() as i64;
        let result =
            tokio::task::spawn_blocking(move || {
                let mut connection = db.connection().map_err(|error| error.to_string())?;
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|error| error.to_string())?;
                let old: Option<Vec<u8>> = transaction.query_row(
                    "SELECT payload FROM events_buses WHERE account=?1 AND region=?2",
                    params![account,region], |row| row.get(0)
                ).optional().map_err(|error| error.to_string())?;
                if let Some(old) = old {
                    let buses: BTreeMap<String,EventBus> =
                        serde_json::from_slice(&old).map_err(|error| error.to_string())?;
                    for rule in buses.values().flat_map(|bus| bus.rules.values()) {
                        if rule.schedule_expression.is_some()
                            && !present.contains(&rule.arn) {
                            let count = transaction.execute(
                                "UPDATE events_pending_firing SET status='CANCELLED',
                                 terminal_reason='configuration changed'
                                 WHERE kind='rule' AND arn=?1 AND status='PENDING'",
                                params![rule.arn]
                            ).map_err(|error| error.to_string())?;
                            if count > 0 { tracing::warn!(arn=%rule.arn,count,"Rule firings cancelled after configuration change"); }
                        }
                    }
                }
                transaction
                    .execute(
                        "INSERT INTO events_buses(account,region,payload) VALUES(?1,?2,?3)
                 ON CONFLICT(account,region) DO UPDATE SET payload=excluded.payload",
                        params![account, region, payload],
                    )
                    .map_err(|error| error.to_string())?;
                for (arn, generation) in rules {
                    transaction.execute(
                    "INSERT INTO events_firing_cursor(kind,arn,generation,cursor_ns,anchor_ns)
                     VALUES('rule',?1,?2,?3,?3)
                     ON CONFLICT(kind,arn) DO UPDATE SET generation=excluded.generation,
                        cursor_ns=excluded.cursor_ns,anchor_ns=excluded.anchor_ns
                     WHERE events_firing_cursor.generation != excluded.generation",
                    params![arn,generation,cursor]
                ).map_err(|error| error.to_string())?;
                }
                transaction.execute("DELETE FROM events_connections WHERE account=?1 AND region=?2",
                    params![account,region]).map_err(|error| error.to_string())?;
                for (name,sealed) in connections {
                    transaction.execute(
                        "INSERT INTO events_connections(account,region,name,sealed) VALUES(?1,?2,?3,?4)",
                        params![account,region,name,sealed]
                    ).map_err(|error| error.to_string())?;
                }
                transaction.execute("DELETE FROM events_api_destinations WHERE account=?1 AND region=?2",
                    params![account,region]).map_err(|error| error.to_string())?;
                for (name,payload) in destinations {
                    transaction.execute(
                        "INSERT INTO events_api_destinations(account,region,name,payload) VALUES(?1,?2,?3,?4)",
                        params![account,region,name,payload]
                    ).map_err(|error| error.to_string())?;
                }
                transaction.commit().map_err(|error| error.to_string())
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result);
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    pub async fn enqueue_fanout(&self, fanout: PendingFanout) -> Result<(), String> {
        let Some(state) = &self.persistence else {
            return Ok(());
        };
        let state = state.clone();
        let id = fanout.id.clone();
        let payload = serde_json::to_vec(&fanout).map_err(|error| error.to_string())?;
        tokio::task::spawn_blocking(move || {
            state
                .connection()
                .map_err(|error| error.to_string())?
                .execute(
                    "INSERT INTO events_pending_fanout(id, payload) VALUES(?1, ?2)",
                    params![id, payload],
                )
                .map_err(|error| error.to_string())?;
            Ok::<(), String>(())
        })
        .await
        .map_err(|error| error.to_string())?
    }

    pub async fn complete_fanout(&self, id: &str) -> Result<(), String> {
        let Some(state) = &self.persistence else {
            return Ok(());
        };
        let state = state.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            state
                .connection()
                .map_err(|error| error.to_string())?
                .execute("DELETE FROM events_pending_fanout WHERE id=?1", params![id])
                .map_err(|error| error.to_string())?;
            Ok::<(), String>(())
        })
        .await
        .map_err(|error| error.to_string())?
    }

    pub async fn pending_fanouts(&self) -> Result<Vec<PendingFanout>, String> {
        let Some(state) = &self.persistence else {
            return Ok(Vec::new());
        };
        let state = state.clone();
        tokio::task::spawn_blocking(move || {
            let connection = state.connection().map_err(|error| error.to_string())?;
            let mut statement = connection
                .prepare("SELECT payload FROM events_pending_fanout ORDER BY rowid")
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|error| error.to_string())?;
            rows.map(|row| {
                let payload = row.map_err(|error| error.to_string())?;
                serde_json::from_slice(&payload).map_err(|error| error.to_string())
            })
            .collect()
        })
        .await
        .map_err(|error| error.to_string())?
    }
}
