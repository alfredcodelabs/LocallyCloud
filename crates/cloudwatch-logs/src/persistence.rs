//! Incremental, authenticated rows in the shared state database.
use std::sync::{Arc, Mutex};

use locallycloud_state::{StateCipher, StateDb};
use rusqlite::{params, Connection};
use serde::{de::DeserializeOwned, Serialize};

use crate::error::LogsError;
use crate::insights::{InsightsQuery, QueryStatus};
use crate::model::*;
use crate::pattern::FilterPattern;
use crate::store::StoreState;

pub(crate) struct Persistence {
    connection: Mutex<Connection>,
    cipher: StateCipher,
}

pub(crate) enum Change {
    Put {
        kind: &'static str,
        scope: ScopeKey,
        group: String,
        stream: String,
        id: String,
        timestamp: i64,
        bytes: Vec<u8>,
    },
    Delete {
        kind: Option<&'static str>,
        scope: ScopeKey,
        group: String,
        stream: Option<String>,
        id: Option<String>,
    },
    Expire {
        key: GroupKey,
        cutoff: i64,
    },
}

pub(crate) fn row<T: Serialize>(
    kind: &'static str,
    key: &GroupKey,
    stream: &str,
    id: &str,
    timestamp: i64,
    value: &T,
) -> Result<Change, LogsError> {
    Ok(Change::Put {
        kind,
        scope: key.scope.clone(),
        group: key.name.clone(),
        stream: stream.into(),
        id: id.into(),
        timestamp,
        bytes: serde_json::to_vec(value).map_err(|_| unavailable())?,
    })
}

pub(crate) fn remove(
    kind: Option<&'static str>,
    key: &GroupKey,
    stream: Option<&str>,
    id: Option<&str>,
) -> Change {
    Change::Delete {
        kind,
        scope: key.scope.clone(),
        group: key.name.clone(),
        stream: stream.map(str::to_owned),
        id: id.map(str::to_owned),
    }
}

pub(crate) fn unavailable() -> LogsError {
    LogsError::ServiceUnavailable("CloudWatch Logs durable storage is unavailable".into())
}

impl Persistence {
    pub(crate) fn open(db: Arc<StateDb>, cipher: StateCipher) -> Result<Arc<Self>, LogsError> {
        let connection = db.connection().map_err(|_| unavailable())?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS cloudwatch_logs_rows (
            kind TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
            group_name TEXT NOT NULL, stream_name TEXT NOT NULL, id TEXT NOT NULL,
            timestamp_ms INTEGER NOT NULL, payload BLOB NOT NULL,
            PRIMARY KEY(kind,account,region,group_name,stream_name,id));
            CREATE INDEX IF NOT EXISTS cloudwatch_logs_scope_group ON cloudwatch_logs_rows(account,region,group_name,stream_name);
            CREATE INDEX IF NOT EXISTS cloudwatch_logs_events_time ON cloudwatch_logs_rows(account,region,group_name,timestamp_ms) WHERE kind='event';").map_err(|_| unavailable())?;
        Ok(Arc::new(Self {
            connection: Mutex::new(connection),
            cipher,
        }))
    }

    pub(crate) fn commit(&self, changes: Vec<Change>) -> Result<(), LogsError> {
        let mut connection = self.connection.lock().map_err(|_| unavailable())?;
        let tx = connection.transaction().map_err(|_| unavailable())?;
        for change in changes {
            match change {
                Change::Put {
                    kind,
                    scope,
                    group,
                    stream,
                    id,
                    timestamp,
                    bytes,
                } => {
                    let payload = self
                        .cipher
                        .seal(
                            &[
                                "cloudwatch-logs",
                                kind,
                                &scope.account_id,
                                &scope.region,
                                &group,
                                &stream,
                                &id,
                            ],
                            &bytes,
                        )
                        .map_err(|_| unavailable())?;
                    tx.execute("INSERT INTO cloudwatch_logs_rows VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(kind,account,region,group_name,stream_name,id) DO UPDATE SET timestamp_ms=excluded.timestamp_ms,payload=excluded.payload", params![kind,scope.account_id,scope.region,group,stream,id,timestamp,payload]).map_err(|_| unavailable())?;
                }
                Change::Delete {
                    kind,
                    scope,
                    group,
                    stream,
                    id,
                } => {
                    let mut sql="DELETE FROM cloudwatch_logs_rows WHERE account=? AND region=? AND group_name=?".to_owned();
                    let mut parameters: Vec<rusqlite::types::Value> =
                        vec![scope.account_id.into(), scope.region.into(), group.into()];
                    for (column, value) in [
                        ("kind", kind.map(str::to_owned)),
                        ("stream_name", stream),
                        ("id", id),
                    ] {
                        if let Some(value) = value {
                            sql.push_str(&format!(" AND {column}=?"));
                            parameters.push(value.into());
                        }
                    }
                    tx.execute(&sql, rusqlite::params_from_iter(parameters))
                        .map_err(|_| unavailable())?;
                }
                Change::Expire { key, cutoff } => {
                    tx.execute("DELETE FROM cloudwatch_logs_rows WHERE kind='event' AND account=?1 AND region=?2 AND group_name=?3 AND timestamp_ms<?4", params![key.scope.account_id,key.scope.region,key.name,cutoff]).map_err(|_| unavailable())?;
                }
            }
        }
        tx.commit().map_err(|_| unavailable())
    }

    pub(crate) fn load(&self) -> Result<StoreState, LogsError> {
        let mut state = StoreState::default();
        let connection = self.connection.lock().map_err(|_| unavailable())?;
        // Resources precede streams and events. The ordering also preserves event order.
        let mut statement = connection.prepare("SELECT kind,account,region,group_name,stream_name,id,payload FROM cloudwatch_logs_rows ORDER BY CASE kind WHEN 'group' THEN 0 WHEN 'stream' THEN 1 WHEN 'event' THEN 2 ELSE 3 END,timestamp_ms,id").map_err(|_| unavailable())?;
        let mut rows = statement.query([]).map_err(|_| unavailable())?;
        while let Some(r) = rows.next().map_err(|_| unavailable())? {
            let kind: String = r.get(0).map_err(|_| unavailable())?;
            let account: String = r.get(1).map_err(|_| unavailable())?;
            let region: String = r.get(2).map_err(|_| unavailable())?;
            let group: String = r.get(3).map_err(|_| unavailable())?;
            let stream: String = r.get(4).map_err(|_| unavailable())?;
            let id: String = r.get(5).map_err(|_| unavailable())?;
            if matches!(kind.as_str(), "cursor" | "cursor-event" | "secret") {
                continue;
            }
            let encrypted: Vec<u8> = r.get(6).map_err(|_| unavailable())?;
            let plaintext = self
                .cipher
                .open(
                    &[
                        "cloudwatch-logs",
                        &kind,
                        &account,
                        &region,
                        &group,
                        &stream,
                        &id,
                    ],
                    &encrypted,
                )
                .map_err(|_| unavailable())?;
            let key = GroupKey {
                scope: ScopeKey::new(&account, &region),
                name: group,
            };
            match kind.as_str() {
                "group" => {
                    let mut value: LogGroup = decode(&plaintext)?;
                    for filter in value.metric_filters.values_mut() {
                        filter.pattern = Arc::new(
                            FilterPattern::compile(Some(&filter.pattern_text))
                                .map_err(|_| unavailable())?,
                        );
                    }
                    for filter in value.subscription_filters.values_mut() {
                        filter.pattern = Arc::new(
                            FilterPattern::compile(Some(&filter.pattern_text))
                                .map_err(|_| unavailable())?,
                        );
                    }
                    state.groups.insert(key, value);
                }
                "stream" => {
                    state
                        .groups
                        .get_mut(&key)
                        .ok_or_else(unavailable)?
                        .streams
                        .insert(stream, decode(&plaintext)?);
                }
                "event" => {
                    let mut event: StoredEvent = decode(&plaintext)?;
                    event.offload();
                    state
                        .groups
                        .get_mut(&key)
                        .and_then(|g| g.streams.get_mut(&stream))
                        .ok_or_else(unavailable)?
                        .events
                        .push(event);
                }
                "metric" => {
                    let effect: PendingMetricEffect = decode(&plaintext)?;
                    state.metric_effects.insert(effect.id, effect);
                }
                "subscription" => {
                    let effect: PendingSubscriptionDelivery = decode(&plaintext)?;
                    state.subscription_deliveries.insert(effect.id, effect);
                }
                "default" => {
                    state.metric_default_minutes.insert(decode(&plaintext)?);
                }
                "query" => {
                    let mut query: InsightsQuery = decode(&plaintext)?;
                    if query.status.is_terminal() {
                        query.snapshot = Vec::new();
                    }
                    if query.status == QueryStatus::Running {
                        query.status = QueryStatus::Scheduled;
                    }
                    state
                        .queries
                        .insert((query.scope.clone(), query.id.clone()), query);
                }
                "ordinal" => {
                    state
                        .next_put_ordinals
                        .insert(key.scope, decode(&plaintext)?);
                }
                "counters" => {
                    let (revision, metric, subscription, query): (u64, u64, u64, u64) =
                        decode(&plaintext)?;
                    state.revision = revision;
                    state.next_metric_effect_id = metric;
                    state.next_subscription_delivery_id = subscription;
                    state.next_query_revision = query;
                }
                // Paginator records are managed by the paginator, not the log inventory.
                "cursor" | "secret" => {}
                _ => return Err(unavailable()),
            }
        }
        for group in state.groups.values_mut() {
            for stream in group.streams.values_mut() {
                stream.events.sort_by_key(|e| {
                    (
                        e.timestamp_ms,
                        e.ingestion_time_ms,
                        e.put_ordinal,
                        e.event_ordinal,
                    )
                });
            }
        }
        Ok(state)
    }

    pub(crate) fn records<T: DeserializeOwned>(
        &self,
        namespace: &str,
    ) -> Result<Vec<(String, T)>, LogsError> {
        let c = self.connection.lock().map_err(|_| unavailable())?;
        let mut s=c.prepare("SELECT id,payload FROM cloudwatch_logs_rows WHERE kind='cursor' AND account='' AND region='' AND group_name=?1 AND stream_name='' ORDER BY id").map_err(|_|unavailable())?;
        let mut rows = s.query([namespace]).map_err(|_| unavailable())?;
        let mut values = Vec::new();
        while let Some(r) = rows.next().map_err(|_| unavailable())? {
            let id: String = r.get(0).map_err(|_| unavailable())?;
            let bytes: Vec<u8> = r.get(1).map_err(|_| unavailable())?;
            let plain = self
                .cipher
                .open(
                    &["cloudwatch-logs", "cursor", "", "", namespace, "", &id],
                    &bytes,
                )
                .map_err(|_| unavailable())?;
            values.push((id, decode(&plain)?));
        }
        Ok(values)
    }

    pub(crate) fn event(
        &self,
        key: &GroupKey,
        stream: &str,
        id: &str,
    ) -> Result<StoredEvent, LogsError> {
        let c = self.connection.lock().map_err(|_| unavailable())?;
        let bytes: Vec<u8> = c.query_row("SELECT payload FROM cloudwatch_logs_rows WHERE kind='event' AND account=?1 AND region=?2 AND group_name=?3 AND stream_name=?4 AND id=?5", params![key.scope.account_id,key.scope.region,key.name,stream,id], |r| r.get(0)).map_err(|_| unavailable())?;
        let plain = self
            .cipher
            .open(
                &[
                    "cloudwatch-logs",
                    "event",
                    &key.scope.account_id,
                    &key.scope.region,
                    &key.name,
                    stream,
                    id,
                ],
                &bytes,
            )
            .map_err(|_| unavailable())?;
        decode(&plain)
    }

    pub(crate) fn cursor_ids(&self, namespace: &str) -> Result<Vec<String>, LogsError> {
        let c = self.connection.lock().map_err(|_| unavailable())?;
        let mut q = c.prepare("SELECT id FROM cloudwatch_logs_rows WHERE kind='cursor' AND account='' AND region='' AND group_name=?1 AND stream_name='' ORDER BY id").map_err(|_| unavailable())?;
        let rows = q
            .query_map([namespace], |r| r.get(0))
            .map_err(|_| unavailable())?;
        rows.collect::<Result<_, _>>().map_err(|_| unavailable())
    }

    pub(crate) fn cursor_record<T: DeserializeOwned>(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<T, LogsError> {
        let c = self.connection.lock().map_err(|_| unavailable())?;
        let bytes: Vec<u8> = c.query_row("SELECT payload FROM cloudwatch_logs_rows WHERE kind='cursor' AND account='' AND region='' AND group_name=?1 AND stream_name='' AND id=?2", params![namespace,id], |r| r.get(0)).map_err(|_| unavailable())?;
        let plain = self
            .cipher
            .open(
                &["cloudwatch-logs", "cursor", "", "", namespace, "", id],
                &bytes,
            )
            .map_err(|_| unavailable())?;
        decode(&plain)
    }

    pub(crate) fn cursor_event(
        &self,
        snapshot: &str,
        position: usize,
        expires: i64,
        event: &PagedEvent,
    ) -> Result<Change, LogsError> {
        row(
            "cursor-event",
            &GroupKey {
                scope: ScopeKey::new("", ""),
                name: "events".into(),
            },
            snapshot,
            &format!("{position:016}"),
            expires,
            event,
        )
    }

    pub(crate) fn remove_cursor_events(&self, snapshot: &str) -> Result<(), LogsError> {
        let c = self.connection.lock().map_err(|_| unavailable())?;
        c.execute("DELETE FROM cloudwatch_logs_rows WHERE kind='cursor-event' AND account='' AND region='' AND group_name='events' AND stream_name=?1", [snapshot]).map_err(|_| unavailable())?;
        Ok(())
    }

    pub(crate) fn cursor_page(
        &self,
        snapshot: &str,
        position: usize,
        backward: bool,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Vec<PagedEvent>, LogsError> {
        let c = self.connection.lock().map_err(|_| unavailable())?;
        let (comparison, order) = if backward {
            ("<", "DESC")
        } else {
            (">=", "ASC")
        };
        let sql = format!("SELECT id,payload FROM cloudwatch_logs_rows WHERE kind='cursor-event' AND account='' AND region='' AND group_name='events' AND stream_name=?1 AND id {comparison} ?2 ORDER BY id {order} LIMIT ?3");
        let mut q = c.prepare(&sql).map_err(|_| unavailable())?;
        let mut rows = q
            .query(params![snapshot, format!("{position:016}"), limit as i64])
            .map_err(|_| unavailable())?;
        let mut result = Vec::new();
        let mut used = 0usize;
        while let Some(r) = rows.next().map_err(|_| unavailable())? {
            let id: String = r.get(0).map_err(|_| unavailable())?;
            let bytes: Vec<u8> = r.get(1).map_err(|_| unavailable())?;
            let plain = self
                .cipher
                .open(
                    &[
                        "cloudwatch-logs",
                        "cursor-event",
                        "",
                        "",
                        "events",
                        snapshot,
                        &id,
                    ],
                    &bytes,
                )
                .map_err(|_| unavailable())?;
            let event: PagedEvent = decode(&plain)?;
            let charge = event.event.body_len().saturating_add(26);
            if used.saturating_add(charge) > max_bytes {
                break;
            }
            used += charge;
            result.push(event);
        }
        if backward {
            result.reverse();
        }
        Ok(result)
    }

    pub(crate) fn secret(
        &self,
        namespace: &str,
        proposed: [u8; 32],
    ) -> Result<[u8; 32], LogsError> {
        let namespace = format!("{namespace}:secret");
        let records: Vec<(String, [u8; 32])> = self.records(&namespace)?;
        if let Some((_, secret)) = records.into_iter().find(|(id, _)| id == "signing-secret") {
            return Ok(secret);
        }
        self.commit(vec![self.cursor(
            &namespace,
            "signing-secret",
            0,
            &proposed,
        )?])?;
        Ok(proposed)
    }

    pub(crate) fn cursor<T: Serialize>(
        &self,
        namespace: &str,
        id: &str,
        expires: i64,
        value: &T,
    ) -> Result<Change, LogsError> {
        row(
            "cursor",
            &GroupKey {
                scope: ScopeKey::new("", ""),
                name: namespace.into(),
            },
            "",
            id,
            expires,
            value,
        )
    }

    pub(crate) fn prune_cursors(&self, namespace: &str, now: i64) -> Result<(), LogsError> {
        let c = self.connection.lock().map_err(|_| unavailable())?;
        c.execute("DELETE FROM cloudwatch_logs_rows WHERE kind IN ('cursor','cursor-event') AND group_name=?1 AND id!='signing-secret' AND timestamp_ms<=?2",params![namespace,now]).map_err(|_|unavailable())?;
        Ok(())
    }
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, LogsError> {
    serde_json::from_slice(bytes).map_err(|_| unavailable())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pagination::{EventNextPageRequest, EventPaginator};
    use crate::protocol::MetricTransformation;
    use crate::store::LogsStore;
    use std::collections::BTreeMap;

    fn fixture() -> (std::path::PathBuf, Arc<StateDb>, LogsStore, GroupKey) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/logs-durable-tests")
            .join(uuid::Uuid::new_v4().to_string());
        let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let store = LogsStore::durable(db.clone(), StateCipher::with_key(&[29; 32])).unwrap();
        let key = GroupKey {
            scope: ScopeKey::new("000000000000", "us-east-1"),
            name: "orders".into(),
        };
        store
            .create_group(
                key.clone(),
                LogGroup {
                    name: key.name.clone(),
                    arn: "arn:aws:logs:us-east-1:000000000000:log-group:orders".into(),
                    creation_time_ms: 0,
                    retention_days: None,
                    class: LogClass::Standard,
                    tags: BTreeMap::new(),
                    streams: BTreeMap::new(),
                    metric_filters: BTreeMap::new(),
                    subscription_filters: BTreeMap::new(),
                    revision: 0,
                },
            )
            .unwrap();
        store
            .create_stream(
                &key,
                LogStream {
                    name: "worker".into(),
                    arn: "arn:aws:logs:us-east-1:000000000000:log-group:orders:log-stream:worker"
                        .into(),
                    creation_time_ms: 0,
                    events: vec![],
                    first_event_timestamp_ms: None,
                    last_event_timestamp_ms: None,
                    last_ingestion_time_ms: None,
                    stored_bytes: 0,
                    revision: 0,
                },
            )
            .unwrap();
        (root, db, store, key)
    }
    fn append(store: &LogsStore, key: &GroupKey, message: &str, now: i64) {
        store
            .put_events(
                key,
                "worker",
                vec![PendingLogEvent {
                    timestamp_ms: now,
                    event_ordinal: 0,
                    message: message.into(),
                }],
                now,
            )
            .unwrap();
    }
    fn add_filter(store: &LogsStore, key: &GroupKey) {
        store
            .put_metric_filter(
                key,
                MetricFilter {
                    name: "count".into(),
                    pattern_text: String::new(),
                    pattern: Arc::new(FilterPattern::compile(None).unwrap()),
                    transformation: MetricTransformation {
                        metric_name: "Orders".into(),
                        metric_namespace: "OrderApp".into(),
                        metric_value: "1".into(),
                        default_value: None,
                        dimensions: None,
                        unit: Some("Count".into()),
                    },
                    creation_time_ms: 0,
                    revision: 0,
                },
                100,
                5,
            )
            .unwrap();
    }

    #[test]
    fn restart_preserves_incremental_events_configs_and_retryable_effects() {
        let (root, db, store, key) = fixture();
        store.set_retention(&key, Some(7)).unwrap();
        store
            .tag_group(&key, BTreeMap::from([("stage".into(), "test".into())]))
            .unwrap();
        add_filter(&store, &key);
        store
            .put_subscription_filter(
                &key,
                SubscriptionFilter {
                    name: "deliver".into(),
                    pattern_text: String::new(),
                    pattern: Arc::new(FilterPattern::compile(None).unwrap()),
                    destination_arn: "arn:aws:lambda:us-east-1:000000000000:function:orders".into(),
                    function_name: "orders".into(),
                    distribution: "ByLogStream".into(),
                    creation_time_ms: 0,
                    revision: 0,
                },
                2,
                5,
            )
            .unwrap();
        append(&store, &key, "private order one", 1_700_000_000_000);
        let before: Vec<u8> = db
            .connection()
            .unwrap()
            .query_row(
                "SELECT payload FROM cloudwatch_logs_rows WHERE kind='event'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        append(&store, &key, "private order two", 1_700_000_000_001);
        let after:Vec<u8>=db.connection().unwrap().query_row("SELECT payload FROM cloudwatch_logs_rows WHERE kind='event' ORDER BY timestamp_ms LIMIT 1",[],|r|r.get(0)).unwrap();
        assert_eq!(
            before, after,
            "append must not rewrite earlier event ciphertext"
        );
        assert!(!before.windows(7).any(|w| w == b"private"));
        let ids: Vec<_> = store
            .pending_metric_effects(10)
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect();
        store.finish_metric_effects(&ids, false).unwrap();
        let query=crate::insights::start(&store,serde_json::from_value(serde_json::json!({"logGroupName":"orders","startTime":1_700_000_000,"endTime":1_700_000_001,"queryString":"fields @message"})).unwrap(),key.scope.clone(),1_700_000_000_002).unwrap();
        assert_eq!(
            store.claim_scheduled_query().unwrap().unwrap().id,
            query.query_id
        );
        drop(store);
        let store = LogsStore::durable(db.clone(), StateCipher::with_key(&[29; 32])).unwrap();
        let (_, groups) = store.describe_groups(&key.scope, None).unwrap();
        assert_eq!(groups[0].retention_days, Some(7));
        assert_eq!(groups[0].tags["stage"], "test");
        assert_eq!(groups[0].metric_filters.len(), 1);
        assert_eq!(groups[0].subscription_filters.len(), 1);
        assert_eq!(store.pending_subscription_deliveries(10).unwrap().len(), 2);
        let recovered = store.get_query(&key.scope, &query.query_id).unwrap();
        assert_eq!(recovered.status, QueryStatus::Scheduled);
        assert_eq!(recovered.snapshot.len(), 2);
        store.claim_scheduled_query().unwrap().unwrap();
        assert!(store
            .complete_query(
                &key.scope,
                &query.query_id,
                Vec::new(),
                Default::default(),
                1_700_000_000_003
            )
            .unwrap());
        assert_eq!(
            store
                .get_query(&key.scope, &query.query_id)
                .unwrap()
                .snapshot
                .capacity(),
            0
        );

        assert_eq!(
            store
                .visible_stream_events(&key, "worker", 1_700_000_000_002)
                .unwrap()
                .1
                .len(),
            2
        );
        assert_eq!(
            store
                .pending_metric_effects(10)
                .unwrap()
                .iter()
                .map(|e| e.id)
                .collect::<Vec<_>>(),
            ids
        );
        assert!(LogsStore::durable(db.clone(), StateCipher::with_key(&[30; 32])).is_err());
        store.finish_metric_effects(&ids, true).unwrap();
        store.delete_group(&key).unwrap();
        drop(store);
        let reopened = LogsStore::durable(db.clone(), StateCipher::with_key(&[29; 32])).unwrap();
        assert!(reopened
            .describe_groups(&key.scope, None)
            .unwrap()
            .1
            .is_empty());
        assert!(reopened.pending_metric_effects(10).unwrap().is_empty());
        assert_eq!(
            reopened
                .get_query(&key.scope, &query.query_id)
                .unwrap()
                .snapshot
                .capacity(),
            0
        );
        drop(reopened);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_append_rolls_back_visible_events_effects_and_ordinals() {
        let (root, db, store, key) = fixture();
        add_filter(&store, &key);
        append(&store, &key, "committed", 1_700_000_000_000);
        let connection = db.connection().unwrap();
        connection.execute_batch("CREATE TRIGGER logs_fail BEFORE INSERT ON cloudwatch_logs_rows WHEN NEW.kind='event' BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
        assert!(store
            .put_events(
                &key,
                "worker",
                vec![PendingLogEvent {
                    timestamp_ms: 1_700_000_000_001,
                    event_ordinal: 0,
                    message: "must roll back".into()
                }],
                1_700_000_000_001
            )
            .is_err());
        assert_eq!(
            store
                .visible_stream_events(&key, "worker", 1_700_000_000_002)
                .unwrap()
                .1
                .len(),
            1
        );
        assert_eq!(store.pending_metric_effects(10).unwrap().len(), 1);
        connection.execute_batch("DROP TRIGGER logs_fail").unwrap();
        append(&store, &key, "next committed", 1_700_000_000_002);
        let events = store
            .visible_stream_events(&key, "worker", 1_700_000_000_003)
            .unwrap()
            .1;
        assert_eq!(events[1].event.put_ordinal, events[0].event.put_ordinal + 1);
        drop(store);
        drop(connection);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn event_cursor_continues_its_snapshot_after_restart_and_new_append() {
        let (root, db, store, key) = fixture();
        append(&store, &key, "one", 1_700_000_000_000);
        append(&store, &key, "two", 1_700_000_000_001);
        let mut extra = store
            .describe_groups(&key.scope, None)
            .unwrap()
            .1
            .remove(0)
            .metadata_without_streams();
        extra.name = "a-empty".into();
        extra.arn = "arn:aws:logs:us-east-1:000000000000:log-group:a-empty".into();
        extra.revision = 0;
        store
            .create_group(
                GroupKey {
                    scope: key.scope.clone(),
                    name: extra.name.clone(),
                },
                extra,
            )
            .unwrap();
        let gp =
            crate::pagination::DescribePaginator::with_persistence(store.persistence()).unwrap();
        let (revision, groups) = store.describe_groups(&key.scope, None).unwrap();
        let group_token = gp
            .first_page(
                groups,
                key.scope.clone(),
                None,
                1,
                revision,
                1_700_000_000_002,
            )
            .unwrap()
            .next_token
            .unwrap();
        drop(gp);
        let p = EventPaginator::with_persistence(store.persistence()).unwrap();
        let (revision, events) = store
            .visible_stream_events(&key, "worker", 1_700_000_000_002)
            .unwrap();
        let first = p
            .first_page(
                events,
                key.scope.clone(),
                "request-key".into(),
                1,
                1024,
                revision,
                true,
                1_700_000_000_002,
            )
            .unwrap();
        let token = first.next_forward_token;
        // Persist exactly the pre-indexed format, retaining this real signed token's
        // manifest ID/revision/expiry and the existing durable signing secret.
        let persistence = store.persistence().unwrap();
        let id = persistence.cursor_ids("events").unwrap().remove(0);
        let mut legacy: serde_json::Value = persistence.cursor_record("events", &id).unwrap();
        let original = persistence.cursor_page(&id, 0, false, 10, 1024).unwrap();
        legacy.as_object_mut().unwrap().remove("disk_len");
        legacy["events"] = serde_json::to_value(original).unwrap();
        persistence
            .commit(vec![persistence
                .cursor(
                    "events",
                    &id,
                    legacy["expires_at_ms"].as_i64().unwrap(),
                    &legacy,
                )
                .unwrap()])
            .unwrap();
        persistence.remove_cursor_events(&id).unwrap();
        drop(persistence);
        drop(p);
        drop(store);
        let store = LogsStore::durable(db.clone(), StateCipher::with_key(&[29; 32])).unwrap();
        append(&store, &key, "three", 1_700_000_000_003);
        let p = EventPaginator::with_persistence(store.persistence()).unwrap();
        let next = p
            .next_page(EventNextPageRequest {
                token: &token,
                scope: &key.scope,
                request_key: "request-key",
                limit: 1,
                max_bytes: 1024,
                require_forward_head: false,
                start_from_head: true,
                now_ms: 1_700_000_000_004,
            })
            .unwrap();
        assert_eq!(next.events.len(), 1);
        assert_eq!(next.events[0].event.message, "two");
        assert!(!next.has_more);
        let gp =
            crate::pagination::DescribePaginator::with_persistence(store.persistence()).unwrap();
        let group_page = gp
            .next_page(&group_token, &key.scope, None, 1, 1_700_000_000_004)
            .unwrap();
        assert_eq!(group_page.groups[0].name, "orders");
        assert_eq!(
            group_page.groups[0]
                .streams
                .values()
                .map(|stream| stream.stored_bytes)
                .sum::<u64>(),
            6,
            "DescribeGroups cursor must preserve original storedBytes after restart"
        );
        drop(gp);

        let other = ScopeKey::new("111111111111", "us-east-1");
        assert!(p
            .next_page(EventNextPageRequest {
                token: &token,
                scope: &other,
                request_key: "request-key",
                limit: 1,
                max_bytes: 1024,
                require_forward_head: false,
                start_from_head: true,
                now_ms: 1_700_000_000_004
            })
            .is_err());
        drop(p);
        drop(store);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn durable_large_backlog_pages_keep_bodies_off_ram_and_preserve_deleted_snapshot() {
        let (root, db, store, key) = fixture();
        let now = 1_700_000_000_000;
        // Over the entire ephemeral cursor budget, created one bounded API batch at a time.
        let message = "x".repeat(1024 * 1024 - 100);
        for index in 0..66 {
            append(&store, &key, &message, now + index);
        }
        let (_, metadata) = store
            .visible_event_metadata(&key, None, None, now + 100)
            .unwrap();
        assert_eq!(metadata.len(), 66);
        assert!(metadata
            .iter()
            .all(|event| event.event.message.capacity() == 0));
        assert_eq!(
            metadata
                .iter()
                .map(|event| event.event.body_len())
                .sum::<usize>(),
            message.len() * 66
        );
        let p = EventPaginator::with_persistence(store.persistence()).unwrap();
        let request = || {
            serde_json::from_value(serde_json::json!({
                "logGroupName": "orders", "logStreamName": "worker", "startFromHead": true,
            }))
            .unwrap()
        };
        let first =
            crate::events::get(&store, &p, request(), key.scope.clone(), now + 100).unwrap();
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.events[0].message, message);
        let token = first.next_forward_token;
        let persistence = store.persistence().unwrap();
        let id = persistence.cursor_ids("events").unwrap().remove(0);
        let manifest: serde_json::Value = persistence.cursor_record("events", &id).unwrap();
        assert_eq!(manifest["disk_len"], 66);
        assert!(manifest.get("events").is_none());
        assert!(serde_json::to_vec(&manifest).unwrap().len() < 4096);
        drop(p);
        drop(store);
        let store = LogsStore::durable(db.clone(), StateCipher::with_key(&[29; 32])).unwrap();
        let (_, restored) = store
            .visible_event_metadata(&key, None, None, now + 100)
            .unwrap();
        assert!(restored
            .iter()
            .all(|event| event.event.message.capacity() == 0));
        store.delete_group(&key).unwrap();
        let p = EventPaginator::with_persistence(store.persistence()).unwrap();
        let mut next_request: crate::protocol::GetLogEventsRequest = request();
        next_request.next_token = Some(token.clone());
        let next =
            crate::events::get(&store, &p, next_request, key.scope.clone(), now + 101).unwrap();
        assert_eq!(next.events.len(), 1);
        assert_eq!(next.events[0].timestamp, now + 1);
        assert_eq!(next.events[0].message, message);
        let mut foreign_request: crate::protocol::GetLogEventsRequest = request();
        foreign_request.next_token = Some(token);
        assert!(crate::events::get(
            &store,
            &p,
            foreign_request,
            ScopeKey::new("111111111111", "us-east-1"),
            now + 101
        )
        .is_err());
        drop(p);
        drop(store);
        drop(persistence);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_appends_commit_distinct_events_and_survive_restart() {
        let (root, db, store, key) = fixture();
        let store = Arc::new(store);
        let handles: Vec<_> = (0..16)
            .map(|index| {
                let store = store.clone();
                let key = key.clone();
                std::thread::spawn(move || {
                    append(
                        &store,
                        &key,
                        &format!("order-{index}"),
                        1_700_000_000_000 + index,
                    )
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        drop(store);
        let reopened = LogsStore::durable(db.clone(), StateCipher::with_key(&[29; 32])).unwrap();
        let events = reopened
            .visible_stream_events(&key, "worker", 1_700_000_000_100)
            .unwrap()
            .1;
        assert_eq!(events.len(), 16);
        let ids: std::collections::BTreeSet<_> = events.iter().map(|e| &e.event.id).collect();
        assert_eq!(ids.len(), 16);
        let ordinals: std::collections::BTreeSet<_> =
            events.iter().map(|e| e.event.put_ordinal).collect();
        assert_eq!(ordinals.len(), 16);
        drop(reopened);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn durable_metric_effect_is_not_removed_until_receiver_commit_ack() {
        use locallycloud_core::integration::metrics::{EmitOutcome, MetricObservation, MetricSink};
        use locallycloud_core::registry::{
            AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry,
        };
        struct DelayedSink {
            started: tokio::sync::Notify,
            committed: tokio::sync::Notify,
        }
        #[async_trait::async_trait]
        impl MetricSink for DelayedSink {
            fn try_emit(&self, _observations: Vec<MetricObservation>) -> EmitOutcome {
                panic!("durable outbox must not accept channel enqueue as a commit");
            }
            async fn emit_durable(&self, observations: Vec<MetricObservation>) -> EmitOutcome {
                assert!(observations[0].correlation_id.starts_with("logs-effect:"));
                self.started.notify_one();
                self.committed.notified().await;
                EmitOutcome::Accepted
            }
        }
        let (root, db, store, key) = fixture();
        add_filter(&store, &key);
        append(&store, &key, "one", 1_700_000_000_000);
        let store = Arc::new(store);
        let registry = ServiceRegistry::with_known_services();
        let sink = Arc::new(DelayedSink {
            started: tokio::sync::Notify::new(),
            committed: tokio::sync::Notify::new(),
        });
        registry.register_native_with_metric_sink(
            ServiceName::new("monitoring"),
            ServiceMetadata::new(AwsProtocol::Json10, None),
            Arc::new(crate::service::LogsHandler::new(Arc::downgrade(&registry)).unwrap()),
            sink.clone(),
        );
        let worker = crate::metric_delivery::MetricDeliveryWorker::new(
            store.clone(),
            Arc::downgrade(&registry),
        );
        worker.wake();
        tokio::time::timeout(std::time::Duration::from_secs(2), sink.started.notified())
            .await
            .unwrap();
        assert_eq!(store.pending_metric_effects(10).unwrap().len(), 1);
        let count: i64 = db
            .connection()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM cloudwatch_logs_rows WHERE kind='metric'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        sink.committed.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !store.pending_metric_effects(10).unwrap().is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let count: i64 = db
            .connection()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM cloudwatch_logs_rows WHERE kind='metric'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        drop(worker);
        drop(registry);
        drop(sink);
        drop(store);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }
}
