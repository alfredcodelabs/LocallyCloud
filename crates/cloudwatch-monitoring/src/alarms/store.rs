use super::*;

impl Alarms {
    pub(crate) fn new(
        persistence: Option<Arc<persistence::Persistence>>,
    ) -> Result<Self, MonitoringError> {
        let mut state = State::default();
        if let Some(persistence) = &persistence {
            let db = persistence.db.connection().map_err(persistence::internal)?;
            db.execute_batch("CREATE TABLE IF NOT EXISTS monitoring_alarms(account TEXT NOT NULL,region TEXT NOT NULL,name TEXT NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(account,region,name));CREATE TABLE IF NOT EXISTS monitoring_alarm_outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,account TEXT NOT NULL,region TEXT NOT NULL,payload BLOB NOT NULL);CREATE TABLE IF NOT EXISTS monitoring_alarm_history(id INTEGER PRIMARY KEY AUTOINCREMENT,account TEXT NOT NULL,region TEXT NOT NULL,name TEXT NOT NULL,ts INTEGER NOT NULL,payload BLOB NOT NULL);CREATE INDEX IF NOT EXISTS monitoring_history_scope_time ON monitoring_alarm_history(account,region,ts,id);CREATE INDEX IF NOT EXISTS monitoring_history_expiry ON monitoring_alarm_history(ts);").map_err(persistence::internal)?;
            db.execute(
                "DELETE FROM monitoring_alarm_history WHERE ts<?1",
                [now_ms() - HISTORY_RETENTION_MS],
            )
            .map_err(persistence::internal)?;
            {
                let mut statement = db
                    .prepare("SELECT account,region,name,payload FROM monitoring_alarms")
                    .map_err(persistence::internal)?;
                let mut rows = statement.query([]).map_err(persistence::internal)?;
                while let Some(row) = rows.next().map_err(persistence::internal)? {
                    let account: String = row.get(0).map_err(persistence::internal)?;
                    let region: String = row.get(1).map_err(persistence::internal)?;
                    let name: String = row.get(2).map_err(persistence::internal)?;
                    let bytes: Vec<u8> = row.get(3).map_err(persistence::internal)?;
                    let data = persistence
                        .cipher
                        .open(&["monitoring-alarm", &account, &region, &name], &bytes)
                        .map_err(persistence::internal)?;
                    let record: Record =
                        serde_json::from_slice(&data).map_err(persistence::internal)?;
                    if record.config.alarm_name != name {
                        return Err(persistence::internal("alarm identity mismatch"));
                    }
                    state.records.insert(
                        (
                            ScopeKey {
                                account_id: account,
                                region,
                            },
                            name,
                        ),
                        record,
                    );
                }
            }
            {
                let mut statement = db
                    .prepare(
                        "SELECT id,account,region,payload FROM monitoring_alarm_outbox ORDER BY id",
                    )
                    .map_err(persistence::internal)?;
                let mut rows = statement.query([]).map_err(persistence::internal)?;
                while let Some(row) = rows.next().map_err(persistence::internal)? {
                    let id: i64 = row.get(0).map_err(persistence::internal)?;
                    let account: String = row.get(1).map_err(persistence::internal)?;
                    let region: String = row.get(2).map_err(persistence::internal)?;
                    let bytes: Vec<u8> = row.get(3).map_err(persistence::internal)?;
                    let data = persistence
                        .cipher
                        .open(
                            &[
                                "monitoring-alarm-action",
                                &account,
                                &region,
                                &id.to_string(),
                            ],
                            &bytes,
                        )
                        .map_err(persistence::internal)?;
                    let pending: Pending =
                        serde_json::from_slice(&data).map_err(persistence::internal)?;
                    if pending.id != id
                        || pending.scope.account_id != account
                        || pending.scope.region != region
                    {
                        return Err(persistence::internal("action identity mismatch"));
                    }
                    state.pending.insert(id, pending);
                }
            }
            {
                let mut statement=db.prepare("SELECT id,account,region,name,payload FROM monitoring_alarm_history ORDER BY id").map_err(persistence::internal)?;
                let mut rows = statement.query([]).map_err(persistence::internal)?;
                while let Some(row) = rows.next().map_err(persistence::internal)? {
                    let id: i64 = row.get(0).map_err(persistence::internal)?;
                    let account: String = row.get(1).map_err(persistence::internal)?;
                    let region: String = row.get(2).map_err(persistence::internal)?;
                    let name: String = row.get(3).map_err(persistence::internal)?;
                    let bytes: Vec<u8> = row.get(4).map_err(persistence::internal)?;
                    let data = persistence
                        .cipher
                        .open(
                            &[
                                "monitoring-alarm-history",
                                &account,
                                &region,
                                &name,
                                &id.to_string(),
                            ],
                            &bytes,
                        )
                        .map_err(persistence::internal)?;
                    let entry: Value =
                        serde_json::from_slice(&data).map_err(persistence::internal)?;
                    if entry["AlarmName"] != name {
                        return Err(persistence::internal("history identity mismatch"));
                    }
                    state.history.insert(
                        id,
                        HistoryEntry {
                            id,
                            scope: ScopeKey {
                                account_id: account,
                                region,
                            },
                            name,
                            entry,
                        },
                    );
                }
            }
        }
        let ephemeral_cipher = if persistence.is_none() {
            Some(locallycloud_state::StateCipher::ephemeral().map_err(persistence::internal)?)
        } else {
            None
        };
        let result = Self {
            state: Mutex::new(state),
            persistence,
            wake: tokio::sync::Notify::new(),
            ephemeral_cipher,
        };
        // Upgrade legacy per-alarm history exactly once, without losing deleted-alarm history thereafter.
        {
            let mut state = result.state.lock().map_err(|_| lock_error())?;
            let legacy: Vec<_> = state
                .records
                .iter()
                .filter(|(_, r)| !r.history.is_empty())
                .map(|((scope, name), r)| (scope.clone(), name.clone(), r.clone()))
                .collect();
            for (scope, name, record) in legacy {
                result.commit_batch(
                    &mut state,
                    &scope,
                    &[(name, Some(record))],
                    vec![],
                    None,
                    vec![],
                )?;
            }
        }
        Ok(result)
    }

    pub(super) fn commit(
        &self,
        state: &mut State,
        scope: &ScopeKey,
        name: &str,
        record: Option<&Record>,
        pending: Vec<Pending>,
    ) -> Result<(), MonitoringError> {
        self.commit_batch(
            state,
            scope,
            &[(name.into(), record.cloned())],
            pending,
            None,
            vec![],
        )
    }

    pub(super) fn commit_batch(
        &self,
        state: &mut State,
        scope: &ScopeKey,
        updates: &[(String, Option<Record>)],
        mut pending: Vec<Pending>,
        ack: Option<i64>,
        mut entries: Vec<(String, Value)>,
    ) -> Result<(), MonitoringError> {
        // Reject the entire transition before committing if its delivery cannot be retained.
        if state
            .pending
            .len()
            .saturating_add(pending.len())
            .saturating_sub(usize::from(ack.is_some()))
            > 10_000
        {
            return Err(MonitoringError::Internal(
                "Alarm action backlog is full; retry after delivery recovers".into(),
            ));
        }
        let cutoff = now_ms() - HISTORY_RETENTION_MS;
        for (name, record) in updates {
            if let Some(record) = record {
                entries.extend(
                    record
                        .history
                        .iter()
                        .cloned()
                        .map(|entry| (name.clone(), entry)),
                );
            }
        }
        entries.retain(|(_, entry)| history_timestamp(entry) >= cutoff);
        let mut saved_history = Vec::new();
        let mut next_action_id = state.next_id;
        let mut next_history_id = state.next_history_id;
        if let Some(persistence) = &self.persistence {
            let mut db = persistence.db.connection().map_err(persistence::internal)?;
            let tx = db.transaction().map_err(persistence::internal)?;
            for (name, record) in updates {
                if let Some(record) = record {
                    let mut metadata = record.clone();
                    metadata.history.clear();
                    let data = persistence
                        .cipher
                        .seal(
                            &["monitoring-alarm", &scope.account_id, &scope.region, name],
                            &serde_json::to_vec(&metadata).map_err(persistence::internal)?,
                        )
                        .map_err(persistence::internal)?;
                    tx.execute("INSERT INTO monitoring_alarms(account,region,name,payload)VALUES(?1,?2,?3,?4) ON CONFLICT(account,region,name)DO UPDATE SET payload=excluded.payload",params![scope.account_id,scope.region,name,data]).map_err(persistence::internal)?;
                } else {
                    tx.execute(
                        "DELETE FROM monitoring_alarms WHERE account=?1 AND region=?2 AND name=?3",
                        params![scope.account_id, scope.region, name],
                    )
                    .map_err(persistence::internal)?;
                }
            }
            for action in &mut pending {
                tx.execute(
                    "INSERT INTO monitoring_alarm_outbox(account,region,payload)VALUES(?1,?2,X'')",
                    params![scope.account_id, scope.region],
                )
                .map_err(persistence::internal)?;
                action.id = tx.last_insert_rowid();
                let data = persistence
                    .cipher
                    .seal(
                        &[
                            "monitoring-alarm-action",
                            &scope.account_id,
                            &scope.region,
                            &action.id.to_string(),
                        ],
                        &serde_json::to_vec(action).map_err(persistence::internal)?,
                    )
                    .map_err(persistence::internal)?;
                tx.execute(
                    "UPDATE monitoring_alarm_outbox SET payload=?1 WHERE id=?2",
                    params![data, action.id],
                )
                .map_err(persistence::internal)?;
            }
            for (name, entry) in entries {
                tx.execute("INSERT INTO monitoring_alarm_history(account,region,name,ts,payload)VALUES(?1,?2,?3,?4,X'')",params![scope.account_id,scope.region,name,history_timestamp(&entry)]).map_err(persistence::internal)?;
                let id = tx.last_insert_rowid();
                let data = persistence
                    .cipher
                    .seal(
                        &[
                            "monitoring-alarm-history",
                            &scope.account_id,
                            &scope.region,
                            &name,
                            &id.to_string(),
                        ],
                        &serde_json::to_vec(&entry).map_err(persistence::internal)?,
                    )
                    .map_err(persistence::internal)?;
                tx.execute(
                    "UPDATE monitoring_alarm_history SET payload=?1 WHERE id=?2",
                    params![data, id],
                )
                .map_err(persistence::internal)?;
                saved_history.push(HistoryEntry {
                    id,
                    scope: scope.clone(),
                    name,
                    entry,
                });
            }
            if let Some(id) = ack {
                tx.execute("DELETE FROM monitoring_alarm_outbox WHERE id=?1", [id])
                    .map_err(persistence::internal)?;
            }
            tx.execute("DELETE FROM monitoring_alarm_history WHERE ts<?1", [cutoff])
                .map_err(persistence::internal)?;
            tx.commit().map_err(persistence::internal)?;
        } else {
            for action in &mut pending {
                next_action_id = next_action_id
                    .checked_add(1)
                    .ok_or_else(|| persistence::internal("action ID exhausted"))?;
                action.id = next_action_id;
            }
            for (name, entry) in entries {
                next_history_id = next_history_id
                    .checked_add(1)
                    .ok_or_else(|| persistence::internal("history ID exhausted"))?;
                saved_history.push(HistoryEntry {
                    id: next_history_id,
                    scope: scope.clone(),
                    name,
                    entry,
                });
            }
        }
        // Publish only after all metadata, history and outbox rows commit together.
        for (name, record) in updates {
            if let Some(record) = record {
                let mut metadata = record.clone();
                metadata.history.clear();
                state
                    .records
                    .insert((scope.clone(), name.clone()), metadata);
            } else {
                state.records.remove(&(scope.clone(), name.clone()));
            }
        }
        for action in pending {
            state.pending.insert(action.id, action);
        }
        if let Some(id) = ack {
            state.pending.remove(&id);
        }
        state
            .history
            .retain(|_, h| history_timestamp(&h.entry) >= cutoff);
        for entry in saved_history {
            state.history.insert(entry.id, entry);
        }
        state.next_id = next_action_id;
        state.next_history_id = next_history_id;
        self.wake.notify_one();
        Ok(())
    }
}
