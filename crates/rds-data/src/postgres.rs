use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::response::Response;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::ServiceRegistry;
use serde_json::{json, Value};
use tokio::sync::{Mutex, OwnedMutexGuard, Semaphore};
use tokio::task::JoinHandle;
use tokio_postgres::{types::Type, Client, Config, NoTls, SimpleQueryMessage};
use uuid::Uuid;

use crate::config::{RdsDataConfig, RdsDataLimits};
use crate::error::RdsDataError;
use crate::model::{
    BatchRequest, BeginRequest, DecimalReturnType, ExecuteRequest, FinalizeRequest,
    FormatRecordsAs, LongReturnType,
};

#[derive(Clone, Debug)]
pub struct PgClusterEndpoint {
    pub port: u16,
    pub database: String,
    pub username: String,
    pub http_endpoint_enabled: bool,
    pub status: String,
}

#[async_trait]
pub trait ClusterResolver: Send + Sync {
    async fn resolve(
        &self,
        account: String,
        region: String,
        arn: String,
    ) -> Option<PgClusterEndpoint>;
}

#[async_trait]
impl<F, Fut> ClusterResolver for F
where
    F: Fn(String, String, String) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Option<PgClusterEndpoint>> + Send,
{
    async fn resolve(
        &self,
        account: String,
        region: String,
        arn: String,
    ) -> Option<PgClusterEndpoint> {
        self(account, region, arn).await
    }
}

struct Transaction {
    client: Arc<Client>,
    operation_lock: Arc<Mutex<()>>,
    closed: Arc<AtomicBool>,
    account: String,
    region: String,
    resource_arn: String,
    secret_arn: String,
    port: u16,
    created: Instant,
    last_activity: std::sync::Mutex<Instant>,
}

pub(crate) struct PgState {
    config: RdsDataConfig,
    transactions: Mutex<HashMap<String, Arc<Transaction>>>,
    reaper: Mutex<Option<JoinHandle<()>>>,
    shutdown: AtomicBool,
    requests: Arc<Semaphore>,
}

impl PgState {
    fn new(config: RdsDataConfig) -> Self {
        let max_requests = config.limits.max_blocking_operations;
        Self {
            config,
            transactions: Mutex::new(HashMap::new()),
            reaper: Mutex::new(None),
            shutdown: AtomicBool::new(false),
            requests: Arc::new(Semaphore::new(max_requests)),
        }
    }

    fn expired(&self, transaction: &Transaction, now: Instant) -> bool {
        now.duration_since(transaction.created) >= self.config.transaction_absolute_timeout
            || now.duration_since(*transaction.last_activity.lock().expect("activity lock"))
                >= self.config.transaction_idle_timeout
    }

    async fn ensure_reaper(self: &Arc<Self>) {
        let mut reaper = self.reaper.lock().await;
        if reaper.is_some() {
            return;
        }
        let state = self.clone();
        *reaper = Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if state.shutdown.load(Ordering::Acquire) {
                    break;
                }
                let candidates = {
                    let transactions = state.transactions.lock().await;
                    transactions
                        .iter()
                        .filter(|(_, transaction)| {
                            transaction.closed.load(Ordering::Acquire)
                                || state.expired(transaction, Instant::now())
                        })
                        .map(|(id, transaction)| (id.clone(), transaction.clone()))
                        .collect::<Vec<_>>()
                };
                for (id, transaction) in candidates {
                    let _operation = transaction.operation_lock.lock().await;
                    if !transaction.closed.load(Ordering::Acquire)
                        && !state.expired(&transaction, Instant::now())
                    {
                        continue;
                    }
                    transaction.closed.store(true, Ordering::Release);
                    state.transactions.lock().await.remove(&id);
                    let _ = transaction.client.simple_query("ROLLBACK").await;
                }
            }
        }));
    }

    pub(crate) async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        let _drained = self
            .requests
            .clone()
            .acquire_many_owned(self.config.limits.max_blocking_operations as u32)
            .await
            .ok();
        if let Some(reaper) = self.reaper.lock().await.take() {
            reaper.abort();
            let _ = reaper.await;
        }
        let transactions = std::mem::take(&mut *self.transactions.lock().await);
        for (_, transaction) in transactions {
            let _operation = transaction.operation_lock.lock().await;
            transaction.closed.store(true, Ordering::Release);
            let _ = transaction.client.simple_query("ROLLBACK").await;
        }
    }
}

pub(crate) struct PgHandler {
    registry: Arc<ServiceRegistry>,
    resolver: Option<Arc<dyn ClusterResolver>>,
    pub(crate) state: Arc<PgState>,
}

impl PgHandler {
    pub(crate) fn new(
        registry: Arc<ServiceRegistry>,
        resolver: Option<Arc<dyn ClusterResolver>>,
        config: RdsDataConfig,
    ) -> Self {
        Self {
            registry,
            resolver,
            state: Arc::new(PgState::new(config)),
        }
    }

    async fn endpoint(
        &self,
        req: &ServiceRequest,
        resource_arn: &str,
    ) -> Result<PgClusterEndpoint, RdsDataError> {
        let parts: Vec<_> = resource_arn.split(':').collect();
        if parts.len() != 7
            || parts[0] != "arn"
            || parts[1] != "aws"
            || parts[2] != "rds"
            || parts[3] != req.region
            || parts[4] != req.account_id
            || parts[5] != "cluster"
            || parts[6].is_empty()
        {
            return Err(RdsDataError::BadRequest(
                "resourceArn must name an Aurora DB cluster in this account and region",
            ));
        }
        let resolver = self.resolver.as_ref().ok_or(RdsDataError::Unavailable)?;
        let endpoint = resolver
            .resolve(
                req.account_id.clone(),
                req.region.clone(),
                resource_arn.to_owned(),
            )
            .await
            .ok_or(RdsDataError::Database("DB cluster is not available"))?;
        if endpoint.status != "available" || !endpoint.http_endpoint_enabled {
            return Err(RdsDataError::Database(
                "Data API is not enabled on an available DB cluster",
            ));
        }
        Ok(endpoint)
    }

    async fn secret(
        &self,
        req: &ServiceRequest,
        secret_arn: &str,
    ) -> Result<(String, String), RdsDataError> {
        let parts: Vec<_> = secret_arn.split(':').collect();
        if parts.len() != 7
            || parts[0] != "arn"
            || parts[1] != "aws"
            || parts[2] != "secretsmanager"
            || parts[3] != req.region
            || parts[4] != req.account_id
            || parts[5] != "secret"
            || parts[6].is_empty()
        {
            return Err(RdsDataError::BadRequest(
                "secretArn must name a secret in this account and region",
            ));
        }
        let dispatcher = self
            .registry
            .internal_dispatcher()
            .ok_or(RdsDataError::Unavailable)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_static("secretsmanager.GetSecretValue"),
        );
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-amz-json-1.1"),
        );
        let body = serde_json::to_vec(&json!({"SecretId": secret_arn}))
            .map_err(|_| RdsDataError::Internal)?;
        let response = dispatcher
            .dispatch_scoped(
                &Method::POST,
                &Uri::from_static("/"),
                &headers,
                Bytes::from(body),
                &req.request_id,
                &req.account_id,
                &req.region,
            )
            .await;
        if !response.status().is_success() {
            return Err(RdsDataError::Database("secret could not be resolved"));
        }
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .map_err(|_| RdsDataError::Unavailable)?;
        let value: Value = serde_json::from_slice(&body)
            .map_err(|_| RdsDataError::Database("secret is invalid"))?;
        let secret =
            value
                .get("SecretString")
                .and_then(Value::as_str)
                .ok_or(RdsDataError::Database(
                    "secret must contain PostgreSQL credentials",
                ))?;
        let credentials: Value = serde_json::from_str(secret)
            .map_err(|_| RdsDataError::Database("secret is invalid"))?;
        let username = credentials
            .get("username")
            .and_then(Value::as_str)
            .ok_or(RdsDataError::Database("secret has no username"))?;
        let password = credentials
            .get("password")
            .and_then(Value::as_str)
            .ok_or(RdsDataError::Database("secret has no password"))?;
        Ok((username.to_owned(), password.to_owned()))
    }

    async fn connect(
        &self,
        req: &ServiceRequest,
        resource_arn: &str,
        secret_arn: &str,
        database: Option<&str>,
    ) -> Result<(Arc<Client>, u16), RdsDataError> {
        let endpoint = self.endpoint(req, resource_arn).await?;
        let (username, password) = self.secret(req, secret_arn).await?;
        if username != endpoint.username {
            return Err(RdsDataError::Database(
                "secret credentials do not match DB cluster",
            ));
        }
        let mut config = Config::new();
        config
            .host("127.0.0.1")
            .port(endpoint.port)
            .user(&username)
            .password(&password)
            .dbname(database.unwrap_or(&endpoint.database));
        let (client, connection) = config
            .connect(NoTls)
            .await
            .map_err(|_| RdsDataError::Database("could not authenticate with DB cluster"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok((Arc::new(client), endpoint.port))
    }

    async fn transaction(
        &self,
        req: &ServiceRequest,
        resource_arn: &str,
        secret_arn: &str,
        id: &str,
        finalizing: bool,
    ) -> Result<(Arc<Client>, OwnedMutexGuard<()>), RdsDataError> {
        let transaction = {
            let transactions = self.state.transactions.lock().await;
            let transaction = transactions
                .get(id)
                .ok_or(RdsDataError::TransactionNotFound)?;
            if transaction.account != req.account_id
                || transaction.region != req.region
                || transaction.resource_arn != resource_arn
                || transaction.secret_arn != secret_arn
            {
                return Err(RdsDataError::TransactionNotFound);
            }
            transaction.clone()
        };
        let guard = transaction.operation_lock.clone().lock_owned().await;
        if transaction.closed.load(Ordering::Acquire)
            || self.state.expired(&transaction, Instant::now())
        {
            return Err(RdsDataError::TransactionNotFound);
        }
        if !self
            .endpoint(req, resource_arn)
            .await
            .is_ok_and(|endpoint| endpoint.port == transaction.port)
        {
            transaction.closed.store(true, Ordering::Release);
            self.state.transactions.lock().await.remove(id);
            let _ = transaction.client.simple_query("ROLLBACK").await;
            return Err(RdsDataError::TransactionNotFound);
        }
        if finalizing {
            transaction.closed.store(true, Ordering::Release);
        }
        *transaction.last_activity.lock().expect("activity lock") = Instant::now();
        Ok((transaction.client.clone(), guard))
    }

    async fn process(&self, req: &ServiceRequest) -> Result<Vec<u8>, RdsDataError> {
        let _admission = self
            .state
            .requests
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RdsDataError::Unavailable)?;
        if self.state.shutdown.load(Ordering::Acquire) {
            return Err(RdsDataError::Unavailable);
        }
        if req.body.len() > self.state.config.limits.request_bytes {
            return Err(RdsDataError::BadRequest("request exceeds 4 MiB limit"));
        }
        if req.uri.query().is_some() || req.headers.contains_key("x-amz-target") {
            return Err(RdsDataError::BadRequest(
                "RDS Data REST endpoint does not accept query or X-Amz-Target",
            ));
        }
        if req.method != Method::POST
            || req
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_none_or(|v| !v.starts_with("application/json"))
        {
            return Err(RdsDataError::BadRequest(
                "RDS Data operations require POST application/json",
            ));
        }
        match req.uri.path() {
            "/Execute" => {
                let input: ExecuteRequest = serde_json::from_slice(&req.body)
                    .map_err(|_| RdsDataError::BadRequest("invalid request"))?;
                if input.schema.is_some()
                    || input.continue_after_timeout
                    || input.format_records_as == Some(FormatRecordsAs::Json)
                    || input.result_set_options.long_return_type != LongReturnType::Long
                    || input.result_set_options.decimal_return_type
                        != DecimalReturnType::DoubleOrLong
                {
                    return Err(RdsDataError::Unsupported(
                        "requested Data API result option is unsupported",
                    ));
                }
                let (client, _operation) = if let Some(id) = input.transaction_id.as_deref() {
                    let (client, guard) = self
                        .transaction(req, &input.resource_arn, &input.secret_arn, id, false)
                        .await?;
                    (client, Some(guard))
                } else {
                    (
                        self.connect(
                            req,
                            &input.resource_arn,
                            &input.secret_arn,
                            input.database.as_deref(),
                        )
                        .await?
                        .0,
                        None,
                    )
                };
                execute_guarded(
                    &client,
                    &input.sql,
                    &input.parameters,
                    input.include_result_metadata,
                    &self.state.config.limits,
                    input.transaction_id.is_some(),
                )
                .await
            }
            "/BatchExecute" => {
                let input: BatchRequest = serde_json::from_slice(&req.body)
                    .map_err(|_| RdsDataError::BadRequest("invalid request"))?;
                if input.schema.is_some() {
                    return Err(RdsDataError::Unsupported("schema is unsupported"));
                }
                reject_transaction_control(&input.sql)?;
                let (client, _operation) = if let Some(id) = input.transaction_id.as_deref() {
                    let (client, guard) = self
                        .transaction(req, &input.resource_arn, &input.secret_arn, id, false)
                        .await?;
                    (client, Some(guard))
                } else {
                    (
                        self.connect(
                            req,
                            &input.resource_arn,
                            &input.secret_arn,
                            input.database.as_deref(),
                        )
                        .await?
                        .0,
                        None,
                    )
                };
                if input.parameter_sets.len() > self.state.config.limits.max_batch_sets {
                    return Err(RdsDataError::BadRequest("too many batch parameter sets"));
                }
                if input.parameter_sets.iter().all(Vec::is_empty) {
                    let statement = client.prepare(&input.sql).await.map_err(|_| {
                        RdsDataError::Database("SQL statement could not be prepared")
                    })?;
                    if !statement.columns().is_empty() {
                        return Err(RdsDataError::Unsupported(
                            "BatchExecuteStatement does not support result sets",
                        ));
                    }
                }
                let in_transaction = input.transaction_id.is_some();
                let start_sql = if in_transaction {
                    "SAVEPOINT lc_batch"
                } else {
                    "BEGIN"
                };
                let rollback_sql = if in_transaction {
                    "ROLLBACK TO SAVEPOINT lc_batch; RELEASE SAVEPOINT lc_batch"
                } else {
                    "ROLLBACK"
                };
                let commit_sql = if in_transaction {
                    "RELEASE SAVEPOINT lc_batch"
                } else {
                    "COMMIT"
                };
                client
                    .simple_query(start_sql)
                    .await
                    .map_err(|_| RdsDataError::Database("batch transaction could not start"))?;
                let mut updates = Vec::new();
                for parameters in &input.parameter_sets {
                    let result = if parameters.is_empty() {
                        execute(&client, &input.sql, false, &self.state.config.limits).await
                    } else {
                        crate::bound::execute(
                            &client,
                            &input.sql,
                            parameters,
                            false,
                            &self.state.config.limits,
                        )
                        .await
                    };
                    match result {
                        Ok(value) if value.get("records").is_some() => {
                            let _ = client.simple_query(rollback_sql).await;
                            return Err(RdsDataError::Unsupported(
                                "BatchExecuteStatement does not support result sets",
                            ));
                        }
                        Ok(_) => updates.push(json!({})),
                        Err(error) => {
                            let _ = client.simple_query(rollback_sql).await;
                            return Err(error);
                        }
                    }
                }
                client
                    .simple_query(commit_sql)
                    .await
                    .map_err(|_| RdsDataError::Database("batch transaction could not commit"))?;
                serde_json::to_vec(&json!({"updateResults": updates}))
                    .map_err(|_| RdsDataError::Internal)
            }
            "/BeginTransaction" => {
                let input: BeginRequest = serde_json::from_slice(&req.body)
                    .map_err(|_| RdsDataError::BadRequest("invalid request"))?;
                if input.schema.is_some() {
                    return Err(RdsDataError::Unsupported("schema is unsupported"));
                }
                let (client, port) = self
                    .connect(
                        req,
                        &input.resource_arn,
                        &input.secret_arn,
                        input.database.as_deref(),
                    )
                    .await?;
                client
                    .simple_query("BEGIN")
                    .await
                    .map_err(|_| RdsDataError::Database("transaction could not start"))?;
                let id = Uuid::new_v4().to_string();
                let mut transactions = self.state.transactions.lock().await;
                if transactions.len() >= self.state.config.limits.max_transactions {
                    let _ = client.simple_query("ROLLBACK").await;
                    return Err(RdsDataError::Unavailable);
                }
                transactions.insert(
                    id.clone(),
                    Arc::new(Transaction {
                        client,
                        operation_lock: Arc::new(Mutex::new(())),
                        closed: Arc::new(AtomicBool::new(false)),
                        account: req.account_id.clone(),
                        region: req.region.clone(),
                        resource_arn: input.resource_arn,
                        secret_arn: input.secret_arn,
                        port,
                        created: Instant::now(),
                        last_activity: std::sync::Mutex::new(Instant::now()),
                    }),
                );
                drop(transactions);
                self.state.ensure_reaper().await;
                serde_json::to_vec(&json!({"transactionId": id}))
                    .map_err(|_| RdsDataError::Internal)
            }
            "/CommitTransaction" | "/RollbackTransaction" => {
                let input: FinalizeRequest = serde_json::from_slice(&req.body)
                    .map_err(|_| RdsDataError::BadRequest("invalid request"))?;
                let (client, _operation) = self
                    .transaction(
                        req,
                        &input.resource_arn,
                        &input.secret_arn,
                        &input.transaction_id,
                        true,
                    )
                    .await?;
                self.state
                    .transactions
                    .lock()
                    .await
                    .remove(&input.transaction_id);
                let commit = req.uri.path() == "/CommitTransaction";
                client
                    .simple_query(if commit { "COMMIT" } else { "ROLLBACK" })
                    .await
                    .map_err(|_| RdsDataError::Database("transaction could not be finalized"))?;
                let status = if commit {
                    "Transaction Committed"
                } else {
                    "Transaction Rolled Back"
                };
                serde_json::to_vec(&json!({"transactionStatus": status}))
                    .map_err(|_| RdsDataError::Internal)
            }
            _ => Err(RdsDataError::BadRequest("unsupported RDS Data operation")),
        }
    }
}

fn reject_transaction_control(sql: &str) -> Result<(), RdsDataError> {
    let mut rest = sql.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix("--") {
            rest = after
                .split_once('\n')
                .map_or("", |(_, tail)| tail)
                .trim_start();
        } else if let Some(after) = rest.strip_prefix("/*") {
            rest = after
                .split_once("*/")
                .ok_or(RdsDataError::BadRequest("SQL comment is incomplete"))?
                .1
                .trim_start();
        } else {
            break;
        }
    }
    let keyword = rest
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    if matches!(
        keyword.as_str(),
        "BEGIN" | "START" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE" | "END" | "ABORT"
    ) {
        return Err(RdsDataError::Unsupported(
            "transaction control SQL is unsupported",
        ));
    }
    Ok(())
}

async fn execute_guarded(
    client: &Client,
    sql: &str,
    parameters: &[crate::model::SqlParameter],
    include_metadata: bool,
    limits: &RdsDataLimits,
    in_transaction: bool,
) -> Result<Vec<u8>, RdsDataError> {
    if sql.trim().is_empty() || sql.len() > 65_536 || sql.contains('\0') {
        return Err(RdsDataError::BadRequest("SQL statement is invalid"));
    }
    reject_transaction_control(sql)?;
    let start = if in_transaction {
        "SAVEPOINT lc_execute"
    } else {
        "BEGIN"
    };
    let rollback = if in_transaction {
        "ROLLBACK TO SAVEPOINT lc_execute; RELEASE SAVEPOINT lc_execute"
    } else {
        "ROLLBACK"
    };
    let commit = if in_transaction {
        "RELEASE SAVEPOINT lc_execute"
    } else {
        "COMMIT"
    };
    client
        .simple_query(start)
        .await
        .map_err(|_| RdsDataError::Database("statement transaction could not start"))?;
    let result = if parameters.is_empty() {
        execute(client, sql, include_metadata, limits).await
    } else {
        crate::bound::execute(client, sql, parameters, include_metadata, limits).await
    }
    .and_then(|value| serde_json::to_vec(&value).map_err(|_| RdsDataError::Internal))
    .and_then(|body| {
        if body.len() <= limits.response_bytes {
            Ok(body)
        } else {
            Err(RdsDataError::Database("result exceeds response limit"))
        }
    });
    match result {
        Ok(body) => {
            client
                .simple_query(commit)
                .await
                .map_err(|_| RdsDataError::Database("statement transaction could not commit"))?;
            Ok(body)
        }
        Err(error) => {
            let _ = client.simple_query(rollback).await;
            Err(error)
        }
    }
}

async fn execute(
    client: &Client,
    sql: &str,
    include_metadata: bool,
    limits: &RdsDataLimits,
) -> Result<Value, RdsDataError> {
    if sql.trim().is_empty() || sql.len() > 65_536 || sql.contains('\0') {
        return Err(RdsDataError::BadRequest("SQL statement is invalid"));
    }
    let statement = client
        .prepare(sql)
        .await
        .map_err(|_| RdsDataError::Database("SQL statement could not be prepared"))?;
    let columns = statement.columns();
    let messages = client
        .simple_query_raw(sql)
        .await
        .map_err(|_| RdsDataError::Database("SQL statement failed"))?;
    tokio::pin!(messages);
    let mut records = Vec::new();
    let mut updated = 0;
    let mut estimated_bytes = 0usize;
    while let Some(message) = messages
        .try_next()
        .await
        .map_err(|_| RdsDataError::Database("SQL statement failed"))?
    {
        match message {
            SimpleQueryMessage::Row(row) => {
                if records.len() >= limits.max_rows {
                    return Err(RdsDataError::Database("result exceeds row limit"));
                }
                estimated_bytes += row.columns().len() * 64;
                for i in 0..row.len() {
                    if row
                        .get(i)
                        .is_some_and(|value| value.len() > limits.max_field_bytes)
                    {
                        return Err(RdsDataError::Database("field exceeds size limit"));
                    }
                    estimated_bytes =
                        estimated_bytes.saturating_add(row.get(i).map_or(0, str::len));
                }
                if estimated_bytes > limits.response_bytes {
                    return Err(RdsDataError::Database("result exceeds response limit"));
                }
                let fields = (0..row.len())
                    .map(|i| match row.get(i) {
                        None => json!({"isNull": true}),
                        Some(value) => match columns.get(i).map(|column| column.type_()) {
                            Some(&Type::BOOL) => value
                                .parse::<bool>()
                                .map(|v| json!({"booleanValue": v}))
                                .unwrap_or_else(|_| json!({"stringValue": value})),
                            Some(&Type::INT2 | &Type::INT4 | &Type::INT8) => value
                                .parse::<i64>()
                                .map(|v| json!({"longValue": v}))
                                .unwrap_or_else(|_| json!({"stringValue": value})),
                            Some(&Type::FLOAT4 | &Type::FLOAT8) => value
                                .parse::<f64>()
                                .map(|v| json!({"doubleValue": v}))
                                .unwrap_or_else(|_| json!({"stringValue": value})),
                            _ => json!({"stringValue": value}),
                        },
                    })
                    .collect::<Vec<_>>();
                records.push(fields);
            }
            SimpleQueryMessage::CommandComplete(count) => updated = count,
            _ => {}
        }
    }
    if !columns.is_empty() {
        let mut result = json!({"records": records});
        if include_metadata {
            result["columnMetadata"] = Value::Array(columns.iter().map(|column| {
                json!({"name": column.name(), "label": column.name(), "typeName": column.type_().name()})
            }).collect());
        }
        Ok(result)
    } else {
        Ok(json!({"numberOfRecordsUpdated": updated}))
    }
}

#[async_trait]
impl NativeHandler for PgHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let id = request.request_id.clone();
        match self.process(&request).await {
            Ok(body) => http::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("x-amzn-RequestId", id)
                .body(Body::from(body))
                .expect("valid response"),
            Err(error) => error.into_response(id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(resource_arn: &str) -> ServiceRequest {
        ServiceRequest {
            method: Method::POST,
            uri: Uri::from_static("/Execute"),
            headers: HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            body: Bytes::from(
                serde_json::to_vec(&json!({
                    "resourceArn": resource_arn,
                    "secretArn": "arn:aws:secretsmanager:us-east-1:000000000000:secret:db-test",
                    "sql": "SELECT 1"
                }))
                .unwrap(),
            ),
            region: "us-east-1".to_owned(),
            account_id: "000000000000".to_owned(),
            request_id: "test".to_owned(),
        }
    }

    #[test]
    fn transaction_control_sql_is_rejected_after_comments() {
        assert!(reject_transaction_control("/* harmless */ COMMIT").is_err());
        assert!(reject_transaction_control("-- comment\nROLLBACK").is_err());
        assert!(reject_transaction_control("SELECT 'COMMIT'").is_ok());
    }

    #[tokio::test]
    async fn db_instance_arn_and_missing_cluster_resolver_fail_closed() {
        let registry = Arc::new(ServiceRegistry::new());
        let handler = PgHandler::new(registry, None, RdsDataConfig::default());
        let db = handler
            .handle(request("arn:aws:rds:us-east-1:000000000000:db:mydb"))
            .await;
        assert_eq!(db.status(), StatusCode::BAD_REQUEST);
        let cluster = handler
            .handle(request("arn:aws:rds:us-east-1:000000000000:cluster:mydb"))
            .await;
        assert_eq!(cluster.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
