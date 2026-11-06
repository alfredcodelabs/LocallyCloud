//! Durable MREC topology intents and independently retried outbox delivery.
use std::collections::{BTreeSet, HashSet};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::response::Response;
use locallycloud_core::handler::ServiceRequest;
use locallycloud_dynamodb::error::DdbError;
use locallycloud_state::{StateCipher, StateDb};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, watch, Notify};

use crate::dynamodb_engine::WorkerPool;

const PAGE: usize = 32;
const RPC_TIMEOUT: Duration = Duration::from_secs(15);
type Scope = (String, String);
type Key = (String, String);
type Reply = Result<(u16, Value), String>;

pub struct RelayNotifier {
    enabled: AtomicBool,
    dirty: Mutex<BTreeSet<Scope>>,
    overflow: AtomicBool,
    signal: Notify,
}

impl RelayNotifier {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(false),
            dirty: Mutex::new(BTreeSet::new()),
            overflow: AtomicBool::new(false),
            signal: Notify::new(),
        })
    }

    pub fn notify(&self, account: &str, region: &str) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        if let Ok(mut dirty) = self.dirty.lock() {
            if dirty.len() < 64 {
                dirty.insert((account.into(), region.into()));
            } else {
                self.overflow.store(true, Ordering::Release);
            }
        } else {
            self.overflow.store(true, Ordering::Release);
        }
        self.signal.notify_one();
    }

    fn activate(&self) {
        self.enabled.store(true, Ordering::Release);
        self.overflow.store(true, Ordering::Release);
        self.signal.notify_one();
    }

    fn take(&self) {
        if let Ok(mut dirty) = self.dirty.lock() {
            dirty.clear();
        }
        self.overflow.swap(false, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Global {
    account: String,
    name: String,
    id: String,
    regions: Vec<String>,
    phase: Phase,
    revision: i64,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Phase {
    Active,
    Creating {
        source: String,
        target: String,
        schema: Value,
        stage: CreateStage,
        cursor: i64,
    },
    Deleting {
        target: String,
        stage: DeleteStage,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum CreateStage {
    EnableSource,
    Reserved,
    Waiting,
    Configuring(usize),
    Copying,
    CatchingUp,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
enum DeleteStage {
    Freeze,
    DrainTarget,
    Survivors(usize),
    Detach,
    Delete,
    Finish,
}

#[derive(Clone)]
struct Metadata {
    state: Arc<StateDb>,
    cipher: Arc<StateCipher>,
}

impl Metadata {
    async fn open(state: Arc<StateDb>) -> io::Result<Self> {
        let cipher = Arc::new(StateCipher::from_env().map_err(io::Error::other)?);
        Self::with_cipher(state, cipher).await
    }

    async fn with_cipher(state: Arc<StateDb>, cipher: Arc<StateCipher>) -> io::Result<Self> {
        let db = state.clone();
        tokio::task::spawn_blocking(move || {
            db.connection().map_err(io::Error::other)?.execute_batch(
                "CREATE TABLE IF NOT EXISTS lc_dynamodb_global_tables(account TEXT NOT NULL,name TEXT NOT NULL,metadata BLOB NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(account,name));
                 CREATE TABLE IF NOT EXISTS lc_dynamodb_relay_cursors(account TEXT NOT NULL,source TEXT NOT NULL,target TEXT NOT NULL,position BLOB NOT NULL,PRIMARY KEY(account,source,target));
                 CREATE TABLE IF NOT EXISTS lc_dynamodb_relay_retry(account TEXT NOT NULL,source TEXT NOT NULL,target TEXT NOT NULL,state BLOB NOT NULL,PRIMARY KEY(account,source,target));"
            ).map_err(io::Error::other)
        }).await.map_err(io::Error::other)??;
        Ok(Self { state, cipher })
    }

    async fn get(&self, account: &str, name: &str) -> Result<Option<Global>, String> {
        let this = self.clone();
        let account = account.to_owned();
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || {
            let connection = this
                .state
                .connection()
                .map_err(|_| "replication metadata unavailable")?;
            let mut query = connection
                .prepare(
                    "SELECT metadata,revision FROM lc_dynamodb_global_tables WHERE account=?1 AND name=?2",
                )
                .map_err(|_| "replication metadata unavailable")?;
            let mut rows = query
                .query((&account, &name))
                .map_err(|_| "replication metadata unavailable")?;
            let Some(row) = rows
                .next()
                .map_err(|_| "replication metadata unavailable")?
            else {
                return Ok(None);
            };
            let bytes: Vec<u8> = row.get(0).map_err(|_| "replication metadata unavailable")?;
            let bytes = this
                .cipher
                .open(&["dynamodb-global-v1", &account, &name], &bytes)
                .map_err(|_| "replication metadata failed authentication")?;
            let global: Global =
                serde_json::from_slice(&bytes).map_err(|_| "replication metadata is invalid")?;
            if global.account != account
                || global.name != name
                || global.regions.is_empty()
                || global.regions.len() > 64
            {
                return Err("replication metadata scope is invalid".into());
            }
            let revision:i64=row.get(1).map_err(|_|"replication metadata revision is invalid")?;
            if global.revision<=0 || global.revision!=revision{return Err("replication metadata revision failed authentication".into());}
            Ok(Some(global))
        })
        .await
        .map_err(|_| "replication metadata task failed")?
    }

    async fn save(&self, global: &Global) -> Result<(), String> {
        let this = self.clone();
        let mut global = global.clone();
        tokio::task::spawn_blocking(move || {
            let previous=global.revision;
            if previous<0{return Err("invalid replication metadata revision".into());}
            global.revision=previous.checked_add(1).ok_or("replication metadata revision exhausted")?;
            let bytes=serde_json::to_vec(&global).map_err(|_|"could not encode replication metadata")?;
            if bytes.len()>256*1024 {return Err("replication metadata exceeds its bounded size".into());}
            let sealed=this.cipher.seal(&["dynamodb-global-v1",&global.account,&global.name],&bytes).map_err(|_|"could not encrypt replication metadata")?;
            let connection=this.state.connection().map_err(|_|"replication metadata unavailable")?;
            let changed=if previous==0 {
                connection.execute("INSERT OR IGNORE INTO lc_dynamodb_global_tables VALUES(?1,?2,?3,?4)",(&global.account,&global.name,sealed,global.revision))
            } else {
                connection.execute("UPDATE lc_dynamodb_global_tables SET metadata=?3,revision=?4 WHERE account=?1 AND name=?2 AND revision=?5",(&global.account,&global.name,sealed,global.revision,previous))
            }.map_err(|_|"could not persist replication intent")?;
            if changed!=1{return Err("replication metadata changed; retry the operation".into());}
            Ok(())
        }).await.map_err(|_|"replication metadata task failed")?
    }

    async fn remove(&self, global: &Global) -> Result<(), String> {
        let state = self.state.clone();
        let account = global.account.clone();
        let name = global.name.clone();
        let revision = global.revision;
        tokio::task::spawn_blocking(move || {
            let count=state.connection().map_err(|_|"replication metadata unavailable")?.execute(
                "DELETE FROM lc_dynamodb_global_tables WHERE account=?1 AND name=?2 AND revision=?3",(&account,&name,revision)).map_err(|_|"could not remove replication metadata")?;
            if count!=1{return Err("replication metadata changed; retry deletion".into());}
            Ok(())
        }).await.map_err(|_|"replication metadata task failed")?
    }

    async fn keys(&self, after: &Key) -> Result<Vec<Key>, String> {
        let state = self.state.clone();
        let after = after.clone();
        tokio::task::spawn_blocking(move || {
            let connection=state.connection().map_err(|_|"replication metadata unavailable")?;
            let mut statement=connection.prepare("SELECT account,name FROM lc_dynamodb_global_tables WHERE account>?1 OR(account=?1 AND name>?2) ORDER BY account,name LIMIT 32").map_err(|_|"replication metadata unavailable")?;
            let rows=statement.query_map((&after.0,&after.1),|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?))).map_err(|_|"replication metadata unavailable")?;
            rows.collect::<Result<Vec<_>,_>>().map_err(|_|"replication metadata unavailable".into())
        }).await.map_err(|_|"replication metadata task failed")?
    }

    async fn cursor(
        &self,
        account: &str,
        source: &str,
        target: &str,
        update: Option<i64>,
    ) -> Result<i64, String> {
        let this = self.clone();
        let account = account.to_owned();
        let source = source.to_owned();
        let target = target.to_owned();
        tokio::task::spawn_blocking(move || {
            let connection=this.state.connection().map_err(|_|"replication cursor unavailable")?;
            let context=["dynamodb-relay-cursor-v1",&account,&source,&target];
            if let Some(value)=update {
                let sealed=this.cipher.seal(&context,&value.to_be_bytes()).map_err(|_|"could not encrypt relay cursor")?;
                connection.execute("INSERT INTO lc_dynamodb_relay_cursors VALUES(?1,?2,?3,?4) ON CONFLICT(account,source,target) DO UPDATE SET position=excluded.position",(&account,&source,&target,sealed)).map_err(|_|"could not persist relay cursor")?;
                return Ok(value);
            }
            let mut statement=connection.prepare("SELECT position FROM lc_dynamodb_relay_cursors WHERE account=?1 AND source=?2 AND target=?3").map_err(|_|"replication cursor unavailable")?;
            let mut rows=statement.query((&account,&source,&target)).map_err(|_|"replication cursor unavailable")?;
            let Some(row)=rows.next().map_err(|_|"replication cursor unavailable")? else{return Ok(0);};
            let data:Vec<u8>=row.get(0).map_err(|_|"replication cursor unavailable")?;
            let bytes=this.cipher.open(&context,&data).map_err(|_|"relay cursor failed authentication")?;
            let bytes:[u8;8]=bytes.as_slice().try_into().map_err(|_|"relay cursor is invalid")?;
            Ok(i64::from_be_bytes(bytes).max(0))
        }).await.map_err(|_|"replication metadata task failed")?
    }

    async fn retry(
        &self,
        account: &str,
        source: &str,
        target: &str,
        outcome: Option<bool>,
    ) -> Result<bool, String> {
        let this = self.clone();
        let account = account.to_owned();
        let source = source.to_owned();
        let target = target.to_owned();
        tokio::task::spawn_blocking(move || {
            let connection=this.state.connection().map_err(|_|"relay retry metadata unavailable")?;
            let context=["dynamodb-relay-retry-v1",&account,&source,&target];
            if outcome==Some(true) {
                connection.execute("DELETE FROM lc_dynamodb_relay_retry WHERE account=?1 AND source=?2 AND target=?3",(&account,&source,&target)).map_err(|_|"relay retry metadata unavailable")?;
                return Ok(true);
            }
            let mut query=connection.prepare("SELECT state FROM lc_dynamodb_relay_retry WHERE account=?1 AND source=?2 AND target=?3").map_err(|_|"relay retry metadata unavailable")?;
            let mut rows=query.query((&account,&source,&target)).map_err(|_|"relay retry metadata unavailable")?;
            let mut failures=0_u8;let mut due=0_i64;
            if let Some(row)=rows.next().map_err(|_|"relay retry metadata unavailable")? {
                let data:Vec<u8>=row.get(0).map_err(|_|"relay retry metadata unavailable")?;
                let data=this.cipher.open(&context,&data).map_err(|_|"relay retry metadata failed authentication")?;
                (failures,due)=serde_json::from_slice(&data).map_err(|_|"invalid relay retry metadata")?;
            }
            drop(rows);drop(query);
            let now=time::OffsetDateTime::now_utc().unix_timestamp();
            if outcome==Some(false) {
                failures=failures.saturating_add(1).min(6);
                due=now+(1_i64 << failures.saturating_sub(1)).min(30);
                let data=serde_json::to_vec(&(failures,due)).map_err(|_|"could not encode retry metadata")?;
                let sealed=this.cipher.seal(&context,&data).map_err(|_|"could not encrypt retry metadata")?;
                connection.execute("INSERT INTO lc_dynamodb_relay_retry VALUES(?1,?2,?3,?4) ON CONFLICT(account,source,target) DO UPDATE SET state=excluded.state",(&account,&source,&target,sealed)).map_err(|_|"could not persist retry metadata")?;
                return Ok(false);
            }
            Ok(due<=now || due>now+30)
        }).await.map_err(|_|"relay retry metadata task failed")?
    }
}

struct Control {
    request: ServiceRequest,
    reply: oneshot::Sender<Response>,
}

pub struct Coordinator {
    pool: Arc<WorkerPool>,
    metadata: Metadata,
    notifier: Arc<RelayNotifier>,
    sender: mpsc::Sender<Control>,
    receiver: Mutex<Option<mpsc::Receiver<Control>>>,
    stop: watch::Sender<bool>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    started: AtomicBool,
}

impl Coordinator {
    pub async fn new(
        pool: Arc<WorkerPool>,
        state: Arc<StateDb>,
        notifier: Arc<RelayNotifier>,
    ) -> io::Result<Arc<Self>> {
        let metadata = Metadata::open(state).await?;
        if !metadata
            .keys(&(String::new(), String::new()))
            .await
            .map_err(io::Error::other)?
            .is_empty()
        {
            notifier.activate();
        }
        let (sender, receiver) = mpsc::channel(16);
        let (stop, _) = watch::channel(false);
        Ok(Arc::new(Self {
            pool,
            metadata,
            notifier,
            sender,
            receiver: Mutex::new(Some(receiver)),
            stop,
            tasks: Mutex::new(Vec::new()),
            started: AtomicBool::new(false),
        }))
    }

    pub fn resume(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let receiver = self.receiver.lock().ok().and_then(|mut r| r.take());
        let Some(receiver) = receiver else {
            return;
        };
        let control = self.clone();
        let relay = self.clone();
        let tasks = vec![
            tokio::spawn(async move { control.controls(receiver).await }),
            tokio::spawn(async move { relay.run().await }),
        ];
        if let Ok(mut handles) = self.tasks.lock() {
            handles.extend(tasks);
        }
    }

    pub async fn shutdown(&self) {
        let _ = self.stop.send(true);
        let tasks = match self.tasks.lock() {
            Ok(mut tasks) => std::mem::take(&mut *tasks),
            Err(_) => return,
        };
        for mut task in tasks {
            if tokio::time::timeout(Duration::from_secs(65), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
    }

    pub async fn handle(&self, request: ServiceRequest) -> Response {
        let op = operation(&request).unwrap_or_default();
        if matches!(
            op.as_str(),
            "CreateTable"
                | "DeleteTable"
                | "UpdateTable"
                | "UpdateTimeToLive"
                | "RestoreTableFromBackup"
        ) {
            if !self.started.load(Ordering::Acquire) {
                return failure(
                    "replication control plane is not ready",
                    &request.request_id,
                );
            }
            let id = request.request_id.clone();
            let (reply, response) = oneshot::channel();
            if self.sender.try_send(Control { request, reply }).is_err() {
                return DdbError::Throttling("replication control plane is busy".into())
                    .into_response(&id);
            }
            return response
                .await
                .unwrap_or_else(|_| failure("replication control plane stopped", &id));
        }
        let body = match serde_json::from_slice::<Value>(&request.body) {
            Ok(body) => body,
            Err(_) => {
                return DdbError::Validation("invalid request body".into())
                    .into_response(&request.request_id)
            }
        };
        if matches!(
            op.as_str(),
            "PutItem" | "UpdateItem" | "DeleteItem" | "BatchWriteItem" | "TransactWriteItems"
        ) {
            let names = match mutation_tables(&op, &body) {
                Ok(names) => names,
                Err(error) => return error.into_response(&request.request_id),
            };
            for name in names {
                match self.metadata.get(&request.account_id, &name).await {
                    Ok(Some(global)) if matches!(&global.phase,Phase::Creating{target,..}|Phase::Deleting{target,..} if target==&request.region) => {
                        return DdbError::ResourceInUse(
                            "replica is not writable while its lifecycle operation is in progress"
                                .into(),
                        )
                        .into_response(&request.request_id)
                    }
                    Ok(_) => {}
                    Err(error) => return failure(&error, &request.request_id),
                }
            }
        }
        let result = self
            .pool
            .query(
                &request.account_id,
                &request.region,
                op.clone(),
                body.clone(),
            )
            .await;
        let result = match result {
            Ok((status, mut output)) if status == 200 && op == "DescribeTable" => {
                if let Some(name) = table_name(&body) {
                    match self.metadata.get(&request.account_id, &name).await {
                        Ok(Some(global)) if global.regions.contains(&request.region) => {
                            overlay(&mut output, "Table", &global, &request.region)
                        }
                        Ok(Some(_)) => {}
                        Ok(None) => {}
                        Err(error) => return failure(&error, &request.request_id),
                    }
                }
                Ok((status, output))
            }
            other => other,
        };
        encode(result, &request.request_id)
    }

    async fn controls(self: Arc<Self>, mut receiver: mpsc::Receiver<Control>) {
        let mut stop = self.stop.subscribe();
        loop {
            let command =
                tokio::select! {biased;_=stop.changed()=>break, command=receiver.recv()=>command};
            let Some(command) = command else {
                break;
            };
            if command.reply.is_closed() {
                continue;
            }
            let response = self.control(&command.request).await;
            let _ = command.reply.send(response);
        }
    }

    async fn control(&self, request: &ServiceRequest) -> Response {
        let op = operation(request).unwrap_or_default();
        let mut body = match serde_json::from_slice::<Value>(&request.body) {
            Ok(body) => body,
            Err(_) => {
                return DdbError::Validation("invalid request body".into())
                    .into_response(&request.request_id)
            }
        };
        let name_field = if op == "RestoreTableFromBackup" {
            "TargetTableName"
        } else {
            "TableName"
        };
        let lookup = json!({"TableName":body.get(name_field)});
        let Some(name) = table_name(&lookup) else {
            return DdbError::Validation(format!("{name_field} is required"))
                .into_response(&request.request_id);
        };
        body["TableName"] = json!(name);
        let global = match self.metadata.get(&request.account_id, &name).await {
            Ok(global) => global,
            Err(error) => return failure(&error, &request.request_id),
        };
        let result = match op.as_str() {
            "CreateTable" | "RestoreTableFromBackup"
                if global
                    .as_ref()
                    .is_some_and(|g| g.regions.contains(&request.region)) =>
            {
                Err(DdbError::ResourceInUse(
                    "table is reserved by a global table operation".into(),
                ))
            }
            "UpdateTable" if body.get("ReplicaUpdates").is_some() => {
                self.begin_update(request, &name, &body, global).await
            }
            "DeleteTable"
                if global
                    .as_ref()
                    .is_some_and(|g| g.regions.contains(&request.region)) =>
            {
                self.begin_delete(request, &name, global).await
            }
            "UpdateTimeToLive"
                if global
                    .as_ref()
                    .is_some_and(|global| global.regions.contains(&request.region)) =>
            {
                Err(DdbError::Validation(
                    "TTL setting synchronization is not yet supported for ExtendDB global tables"
                        .into(),
                ))
            }
            "UpdateTable"
                if global
                    .as_ref()
                    .is_some_and(|global| global.regions.contains(&request.region)) =>
            {
                let global = match global {
                    Some(global) => global,
                    None => {
                        return failure("global table metadata disappeared", &request.request_id)
                    }
                };
                if !matches!(global.phase, Phase::Active) {
                    Err(DdbError::ResourceInUse(
                        "global table update is in progress".into(),
                    ))
                } else if body.as_object().is_none_or(|object| {
                    object.keys().any(|key| {
                        !matches!(key.as_str(), "TableName" | "DeletionProtectionEnabled")
                    })
                }) {
                    Err(DdbError::Validation("this schema or security update is not supported for ExtendDB global tables".into()))
                } else {
                    return encode(
                        self.pool
                            .query(&request.account_id, &request.region, op, body)
                            .await,
                        &request.request_id,
                    );
                }
            }
            _ => {
                return encode(
                    self.pool
                        .query(&request.account_id, &request.region, op, body)
                        .await,
                    &request.request_id,
                )
            }
        };
        match result {
            Ok(output) => encode(Ok((200, output)), &request.request_id),
            Err(error) => error.into_response(&request.request_id),
        }
    }

    async fn rpc(&self, account: &str, region: &str, op: &str, body: Value) -> Reply {
        tokio::time::timeout(
            RPC_TIMEOUT,
            self.pool.query(account, region, op.into(), body),
        )
        .await
        .map_err(|_| "replication peer request timed out".to_owned())?
    }

    async fn private(
        &self,
        global: &Global,
        region: &str,
        op: &str,
        body: Value,
    ) -> Result<Value, String> {
        let (status, body) = self.rpc(&global.account, region, op, body).await?;
        if status == 200 {
            Ok(body)
        } else {
            Err(format!(
                "replication control operation failed with status {status}"
            ))
        }
    }

    async fn begin_update(
        &self,
        request: &ServiceRequest,
        name: &str,
        body: &Value,
        global: Option<Global>,
    ) -> Result<Value, DdbError> {
        if body.as_object().is_none_or(|object| {
            object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "TableName" | "ReplicaUpdates" | "MultiRegionConsistency"
                )
            })
        }) {
            return Err(DdbError::Validation(
                "combined table and replica updates are not supported".into(),
            ));
        }
        if global
            .as_ref()
            .is_some_and(|global| !global.regions.contains(&request.region))
        {
            return Err(DdbError::ResourceInUse(
                "an unrelated regional table cannot be adopted into this global table".into(),
            ));
        }
        let updates = body
            .get("ReplicaUpdates")
            .and_then(Value::as_array)
            .filter(|updates| updates.len() == 1)
            .ok_or_else(|| DdbError::Validation("one replica update is required".into()))?;
        let update = updates
            .first()
            .and_then(Value::as_object)
            .filter(|u| u.len() == 1)
            .ok_or_else(|| DdbError::Validation("invalid replica update".into()))?;
        let (action, config) = update
            .iter()
            .next()
            .ok_or_else(|| DdbError::Validation("invalid replica update".into()))?;
        let target = config
            .get("RegionName")
            .and_then(Value::as_str)
            .filter(|r| valid_region(r))
            .ok_or_else(|| DdbError::Validation("valid replica RegionName is required".into()))?
            .to_owned();
        if config.as_object().is_none_or(|o| o.len() != 1)
            || body
                .get("MultiRegionConsistency")
                .and_then(Value::as_str)
                .is_some_and(|mode| mode != "EVENTUAL")
        {
            return Err(DdbError::Validation(
                "only RegionName and MREC replica updates are supported".into(),
            ));
        }
        let source_description = self
            .describe(&request.account_id, &request.region, name)
            .await?;
        if source_description
            .get("TableStatus")
            .and_then(Value::as_str)
            != Some("ACTIVE")
            || [
                "GlobalSecondaryIndexes",
                "LocalSecondaryIndexes",
                "VectorIndexes",
            ]
            .iter()
            .any(|field| {
                source_description
                    .get(*field)
                    .and_then(Value::as_array)
                    .is_some_and(|indexes| {
                        indexes.iter().any(|index| {
                            index
                                .get("IndexStatus")
                                .and_then(Value::as_str)
                                .is_some_and(|status| status != "ACTIVE")
                        })
                    })
            })
        {
            return Err(DdbError::ResourceInUse(
                "source table or index update is still in progress".into(),
            ));
        }
        let (ttl_status, ttl) = self
            .rpc(
                &request.account_id,
                &request.region,
                "DescribeTimeToLive",
                json!({"TableName":name}),
            )
            .await
            .map_err(DdbError::Internal)?;
        if ttl_status != 200 {
            return Err(DdbError::Internal(
                "could not verify the source TTL configuration".into(),
            ));
        }
        if ttl
            .get("TimeToLiveDescription")
            .and_then(|description| description.get("TimeToLiveStatus"))
            .and_then(Value::as_str)
            != Some("DISABLED")
        {
            return Err(DdbError::Validation("TTL-enabled sources require synchronized replica settings; this integration is not yet supported".into()));
        }
        let mut global = match global {
            Some(global) => global,
            None => Global {
                account: request.account_id.clone(),
                name: name.into(),
                id: uuid::Uuid::new_v4().to_string(),
                regions: vec![request.region.clone()],
                phase: Phase::Active,
                revision: 0,
                error: None,
            },
        };
        if !matches!(global.phase, Phase::Active) {
            return Err(DdbError::ResourceInUse(
                "a global table update is already in progress".into(),
            ));
        }
        match action.as_str() {
            "Create" => {
                if global.regions.contains(&target) {
                    return Err(DdbError::ResourceInUse("replica already exists".into()));
                }
                if global.regions.len() >= 64 {
                    return Err(DdbError::Throttling(
                        "replica membership capacity reached".into(),
                    ));
                }
                match self
                    .rpc(
                        &global.account,
                        &target,
                        "DescribeTable",
                        json!({"TableName":name}),
                    )
                    .await
                    .map_err(DdbError::Internal)?
                {
                    (200, _) => {
                        return Err(DdbError::ResourceInUse(
                            "an existing regional table cannot be adopted as a replica".into(),
                        ))
                    }
                    (400, body) if not_found(&body) => {}
                    _ => {
                        return Err(DdbError::Internal(
                            "could not verify that the replica destination is absent".into(),
                        ))
                    }
                }
                let schema = clone_schema(&source_description, name)?;
                global.regions.push(target.clone());
                global.regions.sort();
                global.phase = Phase::Creating {
                    source: request.region.clone(),
                    target,
                    schema,
                    stage: CreateStage::EnableSource,
                    cursor: 0,
                };
            }
            "Delete" => {
                if !global.regions.contains(&target) || global.regions.len() < 2 {
                    return Err(DdbError::Validation("replica does not exist".into()));
                }
                let description = self.describe(&global.account, &target, name).await?;
                if description
                    .get("DeletionProtectionEnabled")
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    return Err(DdbError::ResourceInUse(
                        "replica deletion protection is enabled".into(),
                    ));
                }
                global.phase = Phase::Deleting {
                    target,
                    stage: DeleteStage::Freeze,
                };
            }
            _ => {
                return Err(DdbError::Validation(
                    "replica update is not supported".into(),
                ))
            }
        }
        self.metadata
            .save(&global)
            .await
            .map_err(DdbError::Internal)?;
        self.notifier.activate();
        let mut output = json!({"TableDescription":source_description});
        overlay(&mut output, "TableDescription", &global, &request.region);
        Ok(output)
    }

    async fn begin_delete(
        &self,
        request: &ServiceRequest,
        name: &str,
        global: Option<Global>,
    ) -> Result<Value, DdbError> {
        let mut global = global
            .ok_or_else(|| DdbError::ResourceNotFound("global table does not exist".into()))?;
        let description = self
            .describe(&request.account_id, &request.region, name)
            .await?;
        match &global.phase {
            Phase::Active => {}
            Phase::Deleting { target, .. } if target == &request.region => {
                let mut out = json!({"TableDescription":description});
                overlay(&mut out, "TableDescription", &global, &request.region);
                return Ok(out);
            }
            _ => {
                return Err(DdbError::ResourceInUse(
                    "a global table update is already in progress".into(),
                ))
            }
        }
        if description
            .get("DeletionProtectionEnabled")
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Err(DdbError::ResourceInUse(
                "replica deletion protection is enabled".into(),
            ));
        }
        global.phase = Phase::Deleting {
            target: request.region.clone(),
            stage: DeleteStage::Freeze,
        };
        self.metadata
            .save(&global)
            .await
            .map_err(DdbError::Internal)?;
        self.notifier.activate();
        let mut out = json!({"TableDescription":description});
        overlay(&mut out, "TableDescription", &global, &request.region);
        Ok(out)
    }

    async fn describe(&self, account: &str, region: &str, name: &str) -> Result<Value, DdbError> {
        let (status, body) = self
            .rpc(account, region, "DescribeTable", json!({"TableName":name}))
            .await
            .map_err(DdbError::Internal)?;
        if status == 200 {
            body.get("Table")
                .cloned()
                .ok_or_else(|| DdbError::Internal("table description is missing".into()))
        } else if not_found(&body) {
            Err(DdbError::ResourceNotFound("table does not exist".into()))
        } else {
            Err(DdbError::Internal(
                "could not describe the replication table".into(),
            ))
        }
    }

    async fn run(self: Arc<Self>) {
        let mut stop = self.stop.subscribe();
        let mut retry = 1;
        loop {
            tokio::select! {biased;_=stop.changed()=>break,_=self.notifier.signal.notified()=>{}}
            self.notifier.take();
            if *stop.borrow() {
                break;
            }
            let outcome = self.sweep().await;
            if *stop.borrow() {
                break;
            }
            match outcome {
                Ok(true) => {
                    retry = 1;
                    self.notifier.signal.notify_one();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(false) => {
                    retry = 1;
                }
                Err(_) => {
                    tokio::select! {_=stop.changed()=>break,_=self.notifier.signal.notified()=>{},_=tokio::time::sleep(Duration::from_secs(retry))=>{}}
                    retry = (retry * 2).min(30);
                    self.notifier.signal.notify_one();
                }
            }
        }
    }

    async fn sweep(self: &Arc<Self>) -> Result<bool, String> {
        let mut after = (String::new(), String::new());
        let mut progress = false;
        let mut failed = false;
        loop {
            let keys = self.metadata.keys(&after).await?;
            if keys.is_empty() {
                break;
            }
            let mut jobs = tokio::task::JoinSet::new();
            let mut lanes = HashSet::new();
            for key in &keys {
                if *self.stop.borrow() {
                    return Ok(false);
                }
                let Some(global) = self.metadata.get(&key.0, &key.1).await? else {
                    continue;
                };
                if !matches!(global.phase, Phase::Active) {
                    while jobs.len() >= 4 {
                        if let Some(result) = jobs.join_next().await {
                            match result {
                                Ok(Ok(changed)) => progress |= changed,
                                _ => failed = true,
                            }
                        }
                    }
                    let this = self.clone();
                    let global = global.clone();
                    jobs.spawn(async move { this.advance(global).await });
                }
                for source in &global.regions {
                    for target in &global.regions {
                        if source == target
                            || !lanes.insert((
                                global.account.clone(),
                                source.clone(),
                                target.clone(),
                            ))
                        {
                            continue;
                        }
                        while jobs.len() >= 4 {
                            if let Some(result) = jobs.join_next().await {
                                match result {
                                    Ok(Ok(changed)) => progress |= changed,
                                    _ => failed = true,
                                }
                            }
                        }
                        let this = self.clone();
                        let account = global.account.clone();
                        let source = source.clone();
                        let target = target.clone();
                        jobs.spawn(async move { this.relay(&account, &source, &target).await });
                    }
                }
            }
            while let Some(result) = jobs.join_next().await {
                match result {
                    Ok(Ok(changed)) => progress |= changed,
                    _ => failed = true,
                }
            }
            if let Some(last) = keys.last() {
                after = last.clone();
            }
            if keys.len() < PAGE {
                break;
            }
        }
        // Keep activation sticky so an older empty scan cannot disable a new
        // topology's notifications. Failed lanes retain their own retry timers.
        if failed && !progress {
            Err("some replication work remains unavailable".into())
        } else {
            Ok(progress)
        }
    }

    async fn relay(&self, account: &str, source: &str, target: &str) -> Result<bool, String> {
        if !self.metadata.retry(account, source, target, None).await? {
            return Err("replication destination is waiting for its retry deadline".into());
        }
        let result = self.relay_page(account, source, target).await;
        self.metadata
            .retry(account, source, target, Some(result.is_ok()))
            .await?;
        result
    }

    async fn relay_page(&self, account: &str, source: &str, target: &str) -> Result<bool, String> {
        let after = self.metadata.cursor(account, source, target, None).await?;
        let (status, body) = self
            .rpc(
                account,
                source,
                "__locallycloud_global_pending",
                json!({"Target":target,"AfterSeq":after,"Limit":PAGE}),
            )
            .await?;
        if status != 200 {
            return Err("could not read replication outbox".into());
        }
        let rows = body.as_array().ok_or("invalid replication outbox page")?;
        let mut progress = false;
        let mut failed = false;
        let mut cursor = after;
        for row in rows {
            let seq = row
                .get("seq")
                .and_then(Value::as_i64)
                .filter(|seq| *seq > 0)
                .ok_or("invalid replication sequence")?;
            cursor = cursor.max(seq);
            let change = row.get("change").ok_or("replication change missing")?;
            let table = change
                .get("table_name")
                .and_then(Value::as_str)
                .ok_or("replication table missing")?;
            let Some(global) = self.metadata.get(account, table).await? else {
                failed = true;
                continue;
            };
            if row.get("target").and_then(Value::as_str) != Some(target)
                || change.get("account_id").and_then(Value::as_str) != Some(account)
                || change.get("global_id").and_then(Value::as_str) != Some(global.id.as_str())
                || !global.regions.iter().any(|r| r == source)
                || !global.regions.iter().any(|r| r == target)
            {
                failed = true;
                continue;
            }
            match self
                .rpc(
                    account,
                    target,
                    "__locallycloud_global_apply",
                    json!({"Change":change}),
                )
                .await
            {
                Ok((200, _)) => match self
                    .rpc(
                        account,
                        source,
                        "__locallycloud_global_ack",
                        json!({"Seq":seq,"Target":target}),
                    )
                    .await
                {
                    Ok((200, _)) => progress = true,
                    _ => failed = true,
                },
                _ => failed = true,
            }
        }
        self.metadata
            .cursor(
                account,
                source,
                target,
                Some(if rows.len() < PAGE { 0 } else { cursor }),
            )
            .await?;
        if failed {
            Err("unacknowledged replication changes will be retried".into())
        } else {
            Ok(progress || rows.len() == PAGE)
        }
    }

    async fn pending(&self, global: &Global, source: &str, target: &str) -> Result<bool, String> {
        let body = self
            .private(
                global,
                source,
                "__locallycloud_global_pending",
                json!({"Target":target,"Limit":1}),
            )
            .await?;
        Ok(!body
            .as_array()
            .ok_or("invalid pending response")?
            .is_empty())
    }

    async fn advance(&self, mut global: Global) -> Result<bool, String> {
        let phase_key = format!("phase:{}", global.id);
        if !self
            .metadata
            .retry(&global.account, &phase_key, &global.name, None)
            .await?
        {
            return Err("replica lifecycle is waiting for its retry deadline".into());
        }
        global.error = None;
        let result = self.advance_inner(global.clone()).await;
        self.metadata
            .retry(
                &global.account,
                &phase_key,
                &global.name,
                Some(result.is_ok()),
            )
            .await?;
        if result.is_err() {
            global.error =
                Some("Replica operation is retrying; pending writes remain durable".into());
            let _ = self.metadata.save(&global).await;
        }
        result
    }

    async fn advance_inner(&self, mut global: Global) -> Result<bool, String> {
        match global.phase.clone() {
            Phase::Active => return Ok(false),
            Phase::Creating {
                source,
                target,
                schema,
                stage,
                cursor,
            } => {
                let next = match stage {
                    CreateStage::EnableSource => {
                        let description = self
                            .describe(&global.account, &source, &global.name)
                            .await
                            .map_err(|error| error.to_string())?;
                        if description
                            .get("StreamSpecification")
                            .and_then(|spec| spec.get("StreamEnabled"))
                            .and_then(Value::as_bool)
                            != Some(true)
                        {
                            let specification = schema
                                .get("StreamSpecification")
                                .cloned()
                                .ok_or("replica stream specification is missing")?;
                            let (status,_)=self.rpc(&global.account,&source,"UpdateTable",json!({"TableName":global.name,"StreamSpecification":specification})).await?;
                            if status != 200 {
                                return Err("could not enable source stream capture".into());
                            }
                        }
                        CreateStage::Reserved
                    }
                    CreateStage::Reserved => {
                        self.private(
                            &global,
                            &target,
                            "__locallycloud_global_reserve",
                            json!({"TableName":global.name,"GlobalId":global.id}),
                        )
                        .await?;
                        let (status, body) = self
                            .rpc(
                                &global.account,
                                &target,
                                "DescribeTable",
                                json!({"TableName":global.name}),
                            )
                            .await?;
                        if status != 200 {
                            if status != 400 || !not_found(&body) {
                                return Err("could not recover reserved replica".into());
                            }
                            let (status, _) = self
                                .rpc(&global.account, &target, "CreateTable", schema.clone())
                                .await?;
                            if status != 200 {
                                return Err("could not create reserved replica".into());
                            }
                        }
                        CreateStage::Waiting
                    }
                    CreateStage::Waiting => {
                        let table = self
                            .describe(&global.account, &target, &global.name)
                            .await
                            .map_err(|e| e.to_string())?;
                        if table.get("TableStatus").and_then(Value::as_str) != Some("ACTIVE") {
                            return Err("reserved replica table is still creating".into());
                        }
                        CreateStage::Configuring(0)
                    }
                    CreateStage::Configuring(index) => {
                        let mut members = vec![target.clone()];
                        members.extend(global.regions.iter().filter(|r| **r != target).cloned());
                        if let Some(region) = members.get(index) {
                            self.private(&global,region,"__locallycloud_global_configure",json!({"TableName":global.name,"GlobalId":global.id,"Regions":global.regions})).await?;
                            CreateStage::Configuring(index + 1)
                        } else {
                            CreateStage::Copying
                        }
                    }
                    CreateStage::Copying => {
                        let page = self
                            .private(
                                &global,
                                &source,
                                "__locallycloud_global_snapshot",
                                json!({"TableName":global.name,"AfterRowId":cursor,"Limit":PAGE}),
                            )
                            .await?;
                        let changes = page
                            .get("changes")
                            .and_then(Value::as_array)
                            .ok_or("invalid replication snapshot")?;
                        for change in changes {
                            self.private(
                                &global,
                                &target,
                                "__locallycloud_global_apply",
                                json!({"Change":change}),
                            )
                            .await?;
                        }
                        let next_cursor = page
                            .get("next_rowid")
                            .and_then(Value::as_i64)
                            .ok_or("invalid snapshot cursor")?;
                        let done = page
                            .get("done")
                            .and_then(Value::as_bool)
                            .ok_or("invalid snapshot completion")?;
                        if !done && next_cursor <= cursor {
                            return Err("replication snapshot did not advance".into());
                        }
                        global.phase = Phase::Creating {
                            source,
                            target,
                            schema,
                            stage: if done {
                                CreateStage::CatchingUp
                            } else {
                                CreateStage::Copying
                            },
                            cursor: next_cursor,
                        };
                        self.metadata.save(&global).await?;
                        return Ok(true);
                    }
                    CreateStage::CatchingUp => {
                        for region in &global.regions {
                            if region != &target && self.pending(&global, region, &target).await? {
                                return Ok(false);
                            }
                        }
                        self.private(
                            &global,
                            &target,
                            "__locallycloud_global_activate",
                            json!({"TableName":global.name,"GlobalId":global.id}),
                        )
                        .await?;
                        global.phase = Phase::Active;
                        self.metadata.save(&global).await?;
                        return Ok(true);
                    }
                };
                global.phase = Phase::Creating {
                    source,
                    target,
                    schema,
                    stage: next,
                    cursor,
                };
            }
            Phase::Deleting { target, stage } => {
                let survivors: Vec<_> = global
                    .regions
                    .iter()
                    .filter(|r| **r != target)
                    .cloned()
                    .collect();
                let next = match stage {
                    DeleteStage::Freeze => {
                        self.private(
                            &global,
                            &target,
                            "__locallycloud_global_freeze",
                            json!({"TableName":global.name,"GlobalId":global.id}),
                        )
                        .await?;
                        DeleteStage::DrainTarget
                    }
                    DeleteStage::DrainTarget => {
                        for region in &survivors {
                            if self.pending(&global, &target, region).await? {
                                return Ok(false);
                            }
                        }
                        DeleteStage::Survivors(0)
                    }
                    DeleteStage::Survivors(index) => {
                        if let Some(region) = survivors.get(index) {
                            if self.pending(&global, region, &target).await? {
                                return Ok(false);
                            }
                            self.private(&global,region,"__locallycloud_global_configure",json!({"TableName":global.name,"GlobalId":global.id,"Regions":survivors})).await?;
                            DeleteStage::Survivors(index + 1)
                        } else {
                            DeleteStage::Detach
                        }
                    }
                    DeleteStage::Detach => {
                        self.private(
                            &global,
                            &target,
                            "__locallycloud_global_detach",
                            json!({"TableName":global.name}),
                        )
                        .await?;
                        DeleteStage::Delete
                    }
                    DeleteStage::Delete => {
                        let (status, body) = self
                            .rpc(
                                &global.account,
                                &target,
                                "DeleteTable",
                                json!({"TableName":global.name}),
                            )
                            .await?;
                        if status != 200 && !(status == 400 && not_found(&body)) {
                            return Err("could not delete retiring replica".into());
                        }
                        DeleteStage::Finish
                    }
                    DeleteStage::Finish => {
                        if survivors.len() < 2 {
                            for region in &survivors {
                                self.private(
                                    &global,
                                    region,
                                    "__locallycloud_global_detach",
                                    json!({"TableName":global.name}),
                                )
                                .await?;
                            }
                            self.metadata.remove(&global).await?;
                        } else {
                            global.regions = survivors;
                            global.phase = Phase::Active;
                            self.metadata.save(&global).await?;
                        }
                        return Ok(true);
                    }
                };
                global.phase = Phase::Deleting {
                    target,
                    stage: next,
                };
            }
        }
        self.metadata.save(&global).await?;
        Ok(true)
    }
}

fn operation(request: &ServiceRequest) -> Option<String> {
    request
        .headers
        .get("x-amz-target")?
        .to_str()
        .ok()?
        .split_once('.')
        .map(|(_, op)| op.to_owned())
}
fn table_name(body: &Value) -> Option<String> {
    let value = body.get("TableName")?.as_str()?;
    let name = if value.starts_with("arn:") {
        value.splitn(6, ':').nth(5)?.strip_prefix("table/")?
    } else {
        value
    };
    ((3..=255).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)))
    .then(|| name.to_owned())
}
fn mutation_tables(operation: &str, body: &Value) -> Result<BTreeSet<String>, DdbError> {
    let mut names = BTreeSet::new();
    match operation {
        "BatchWriteItem" => {
            if let Some(items) = body.get("RequestItems").and_then(Value::as_object) {
                if items.len() > 100 {
                    return Err(DdbError::Validation(
                        "too many tables in mutation request".into(),
                    ));
                }
                for name in items.keys() {
                    if let Some(name) = table_name(&json!({"TableName":name})) {
                        names.insert(name);
                    }
                }
            }
        }
        "TransactWriteItems" => {
            if let Some(items) = body.get("TransactItems").and_then(Value::as_array) {
                if items.len() > 100 {
                    return Err(DdbError::Validation("too many transaction actions".into()));
                }
                for item in items {
                    for action in ["Put", "Update", "Delete", "ConditionCheck"] {
                        if let Some(name) = item.get(action).and_then(table_name) {
                            names.insert(name);
                        }
                    }
                }
            }
        }
        _ => {
            if let Some(name) = table_name(body) {
                names.insert(name);
            }
        }
    }
    Ok(names)
}
fn valid_region(region: &str) -> bool {
    (3..=64).contains(&region.len())
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn not_found(body: &Value) -> bool {
    body.get("__type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.ends_with("ResourceNotFoundException"))
}
fn failure(message: &str, id: &str) -> Response {
    DdbError::Internal(message.into()).into_response(id)
}
fn encode(result: Reply, id: &str) -> Response {
    match result {
        Ok((status, body)) => Response::builder()
            .status(status)
            .header("content-type", "application/x-amz-json-1.0")
            .header("x-amzn-requestid", id)
            .body(Body::from(body.to_string()))
            .unwrap_or_else(|_| failure("could not encode DynamoDB response", id)),
        Err(error) => failure(&error, id),
    }
}
fn overlay(output: &mut Value, field: &str, global: &Global, region: &str) {
    let Some(table) = output.get_mut(field).and_then(Value::as_object_mut) else {
        return;
    };
    table.insert("GlobalTableVersion".into(), json!("2019.11.21"));
    table.insert("MultiRegionConsistency".into(), json!("EVENTUAL"));
    let replicas: Vec<_> = global
        .regions
        .iter()
        .filter(|r| r.as_str() != region)
        .map(|r| {
            let status = match &global.phase {
                Phase::Creating { target, .. } if target == r => "CREATING",
                Phase::Deleting { target, .. } if target == r => "DELETING",
                _ => "ACTIVE",
            };
            let mut replica = json!({"RegionName":r,"ReplicaStatus":status});
            if status != "ACTIVE" {
                if let Some(reason) = &global.error {
                    replica["ReplicaStatusDescription"] = json!(reason);
                }
            }
            replica
        })
        .collect();
    table.insert("Replicas".into(), json!(replicas));
    match &global.phase {
        Phase::Active => {}
        Phase::Deleting { target, .. } if target == region => {
            table.insert("TableStatus".into(), json!("DELETING"));
        }
        _ => {
            table.insert("TableStatus".into(), json!("UPDATING"));
        }
    }
}

fn clone_schema(description: &Value, name: &str) -> Result<Value, DdbError> {
    let mut body = json!({"TableName":name});
    for field in ["AttributeDefinitions", "KeySchema", "StreamSpecification"] {
        if let Some(value) = description.get(field) {
            body[field] = value.clone();
        }
    }
    let view = description
        .get("StreamSpecification")
        .and_then(|spec| spec.get("StreamViewType"))
        .and_then(Value::as_str)
        .unwrap_or("NEW_AND_OLD_IMAGES");
    body["StreamSpecification"] = json!({"StreamEnabled":true,"StreamViewType":view});
    let billing = description
        .get("BillingModeSummary")
        .and_then(|s| s.get("BillingMode"))
        .and_then(Value::as_str)
        .unwrap_or("PROVISIONED");
    body["BillingMode"] = json!(billing);
    if billing == "PROVISIONED" {
        let throughput = description
            .get("ProvisionedThroughput")
            .ok_or_else(|| DdbError::Validation("source throughput is unavailable".into()))?;
        body["ProvisionedThroughput"] = json!({"ReadCapacityUnits":throughput.get("ReadCapacityUnits"),"WriteCapacityUnits":throughput.get("WriteCapacityUnits")});
    }
    for field in ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"] {
        if let Some(indexes) = description
            .get(field)
            .and_then(Value::as_array)
            .filter(|i| !i.is_empty())
        {
            let mut cloned = Vec::new();
            for index in indexes {
                let mut projected = json!({"IndexName":index.get("IndexName"),"KeySchema":index.get("KeySchema"),"Projection":index.get("Projection")});
                if field == "GlobalSecondaryIndexes" && billing == "PROVISIONED" {
                    let throughput = index.get("ProvisionedThroughput").ok_or_else(|| {
                        DdbError::Validation("source index throughput is unavailable".into())
                    })?;
                    projected["ProvisionedThroughput"] = json!({"ReadCapacityUnits":throughput.get("ReadCapacityUnits"),"WriteCapacityUnits":throughput.get("WriteCapacityUnits")});
                }
                cloned.push(projected);
            }
            body[field] = json!(cloned);
        }
    }
    if let Some(indexes) = description
        .get("VectorIndexes")
        .and_then(Value::as_array)
        .filter(|indexes| !indexes.is_empty())
    {
        let mut cloned = Vec::new();
        for index in indexes {
            let mut projected = json!({});
            for field in [
                "IndexName",
                "VectorAttribute",
                "Dimensions",
                "DistanceFunction",
                "Projection",
                "SearchSchema",
            ] {
                if let Some(value) = index.get(field) {
                    projected[field] = value.clone();
                }
            }
            if [
                "IndexName",
                "VectorAttribute",
                "Dimensions",
                "DistanceFunction",
            ]
            .iter()
            .any(|field| projected.get(*field).is_none())
            {
                return Err(DdbError::Validation(
                    "source vector index definition is incomplete".into(),
                ));
            }
            cloned.push(projected);
        }
        body["VectorIndexes"] = json!(cloned);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global(name: &str) -> Global {
        Global {
            account: "000000000000".into(),
            name: name.into(),
            id: uuid::Uuid::new_v4().to_string(),
            regions: vec!["us-east-1".into(), "us-east-2".into()],
            phase: Phase::Creating {
                source: "us-east-1".into(),
                target: "us-east-2".into(),
                schema: json!({"privateSchemaMarker":"secret-schema-value"}),
                stage: CreateStage::Reserved,
                cursor: 0,
            },
            revision: 0,
            error: None,
        }
    }

    #[tokio::test]
    async fn metadata_intents_are_encrypted_scope_bound_and_compare_and_swap() {
        let root = std::env::temp_dir().join(format!(
            "dynamodb-replication-metadata-{}",
            uuid::Uuid::new_v4()
        ));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let metadata =
            Metadata::with_cipher(state.clone(), Arc::new(StateCipher::with_key(&[41; 32])))
                .await
                .unwrap();
        let first = global("ledger");
        metadata.save(&first).await.unwrap();
        assert!(metadata.save(&first).await.is_err());
        let mut current = metadata
            .get(&first.account, &first.name)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.revision, 1);
        current.phase = Phase::Active;
        metadata.save(&current).await.unwrap();
        assert!(metadata.remove(&current).await.is_err());
        let restored = metadata
            .get(&first.account, &first.name)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.revision, 2);
        assert!(matches!(restored.phase, Phase::Active));
        let connection = state.connection().unwrap();
        let ciphertext: Vec<u8> = connection
            .query_row(
                "SELECT metadata FROM lc_dynamodb_global_tables WHERE account=?1 AND name=?2",
                (&first.account, &first.name),
                |row| row.get(0),
            )
            .unwrap();
        assert!(!ciphertext
            .windows(b"secret-schema-value".len())
            .any(|window| window == b"secret-schema-value"));
        connection
            .execute(
                "INSERT INTO lc_dynamodb_global_tables VALUES(?1,'foreign',?2,2)",
                (&first.account, ciphertext),
            )
            .unwrap();
        assert!(metadata
            .get(&first.account, "foreign")
            .await
            .unwrap_err()
            .contains("authentication"));
        drop(connection);
        drop(metadata);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn relay_lane_cursors_and_retry_delays_survive_restart() {
        let root = std::env::temp_dir().join(format!(
            "dynamodb-replication-cursor-{}",
            uuid::Uuid::new_v4()
        ));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let cipher = Arc::new(StateCipher::with_key(&[42; 32]));
        let metadata = Metadata::with_cipher(state.clone(), cipher.clone())
            .await
            .unwrap();
        metadata
            .cursor("000000000000", "us-east-1", "us-east-2", Some(32))
            .await
            .unwrap();
        metadata
            .retry("000000000000", "us-east-1", "us-east-2", Some(false))
            .await
            .unwrap();
        drop(metadata);
        let restored = Metadata::with_cipher(state.clone(), cipher).await.unwrap();
        assert_eq!(
            restored
                .cursor("000000000000", "us-east-1", "us-east-2", None)
                .await
                .unwrap(),
            32
        );
        let retry_rows:i64=state.connection().unwrap().query_row("SELECT COUNT(*) FROM lc_dynamodb_relay_retry WHERE account='000000000000' AND source='us-east-1' AND target='us-east-2'",[],|row|row.get(0)).unwrap();
        assert_eq!(retry_rows, 1);
        assert!(restored
            .retry("000000000000", "us-east-1", "us-west-1", None)
            .await
            .unwrap());
        restored
            .retry("000000000000", "us-east-1", "us-east-2", Some(true))
            .await
            .unwrap();
        assert!(restored
            .retry("000000000000", "us-east-1", "us-east-2", None)
            .await
            .unwrap());
        drop(restored);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn notifier_is_lazy_coalesced_bounded_and_keeps_wakeup_permits() {
        let notifier = RelayNotifier::new();
        notifier.notify("000000000000", "us-east-1");
        assert!(notifier.dirty.lock().unwrap().is_empty());
        notifier.activate();
        for n in 0..80 {
            notifier.notify("000000000000", &format!("region-{n}"));
        }
        assert_eq!(notifier.dirty.lock().unwrap().len(), 64);
        assert!(notifier.overflow.load(Ordering::Acquire));
        tokio::time::timeout(Duration::from_secs(1), notifier.signal.notified())
            .await
            .unwrap();
        notifier.take();
        assert!(notifier.dirty.lock().unwrap().is_empty());
        assert!(!notifier.overflow.load(Ordering::Acquire));
    }

    #[test]
    fn replica_schema_preserves_views_gsi_lsi_and_vectors_without_status_fields() {
        let schema=clone_schema(&json!({"BillingModeSummary":{"BillingMode":"PAY_PER_REQUEST"},"KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],"StreamSpecification":{"StreamEnabled":false,"StreamViewType":"KEYS_ONLY"},"GlobalSecondaryIndexes":[{"IndexName":"by-value","KeySchema":[],"Projection":{"ProjectionType":"ALL"},"IndexStatus":"ACTIVE"}],"LocalSecondaryIndexes":[{"IndexName":"by-local","KeySchema":[],"Projection":{"ProjectionType":"ALL"},"IndexStatus":"ACTIVE"}],"VectorIndexes":[{"IndexName":"semantic","VectorAttribute":{"AttributeName":"embedding"},"Dimensions":3,"DistanceFunction":"COSINE","Projection":{"ProjectionType":"ALL"},"IndexStatus":"ACTIVE"}]}),"ledger").unwrap();
        assert_eq!(
            schema["StreamSpecification"],
            json!({"StreamEnabled":true,"StreamViewType":"KEYS_ONLY"})
        );
        for field in [
            "GlobalSecondaryIndexes",
            "LocalSecondaryIndexes",
            "VectorIndexes",
        ] {
            assert!(schema[field][0].get("IndexStatus").is_none());
        }
        assert_eq!(schema["VectorIndexes"][0]["Dimensions"], 3);
    }
}
