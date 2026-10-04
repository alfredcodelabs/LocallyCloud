use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use apache_avro::{types::Value as AvroValue, Reader as AvroReader};
use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use http::{HeaderMap, HeaderValue, Method, Uri};
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::AuthorizationRequest;
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{AwsProtocol, ServiceName, ServiceRegistry};
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::Field as ParquetField;
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::state::Scope;

mod sql;
use sql::{
    apply_predicates, sum_result, Predicate, Projection, QueryResult, ResultColumn, SqlParser,
};

pub(crate) const TARGET_PREFIX: &str = "AmazonAthena";
const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const SCAN_LIMIT: u64 = 64 * 1024 * 1024;
const JSON_INPUT_FORMAT: &str = "org.apache.hadoop.mapred.TextInputFormat";
const JSON_SERDE: &str = "org.openx.data.jsonserde.JsonSerDe";

#[derive(Clone, Eq, Hash, PartialEq)]
struct QueryKey {
    scope: Scope,
    id: String,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct TokenKey {
    scope: Scope,
    token: String,
}

#[derive(Clone)]
struct TokenEntry {
    query_id: String,
    spec: QuerySpec,
}

#[derive(Clone, Eq, PartialEq)]
struct QuerySpec {
    query_string: String,
    context: Option<QueryExecutionContext>,
    result_configuration: ResultConfiguration,
    work_group: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueryState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl QueryState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Running => "RUNNING",
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }

    fn is_active(self) -> bool {
        matches!(self, Self::Queued | Self::Running)
    }
}

struct QueryRecord {
    id: String,
    spec: QuerySpec,
    effective_output_location: S3Location,
    state: QueryState,
    submission_time: f64,
    completion_time: Option<f64>,
    reason: Option<String>,
    scanned_bytes: u64,
    result: Option<QueryResult>,
    result_token: String,
    caller: Option<RequestIdentity>,
}

pub(crate) struct AthenaHandler {
    registry: Weak<ServiceRegistry>,
    queries: Arc<DashMap<QueryKey, Arc<Mutex<QueryRecord>>>>,
    tokens: Arc<DashMap<TokenKey, TokenEntry>>,
}

impl AthenaHandler {
    pub(crate) fn new(registry: Weak<ServiceRegistry>) -> Self {
        Self {
            registry,
            queries: Arc::new(DashMap::new()),
            tokens: Arc::new(DashMap::new()),
        }
    }

    fn process(&self, request: &ServiceRequest) -> Result<Value, AthenaError> {
        if request.method != Method::POST
            || request.uri.path() != "/"
            || request.uri.query().is_some()
        {
            return Err(AthenaError::InvalidRequest(
                "Athena only accepts POST requests at /".into(),
            ));
        }
        validate_content_type(&request.headers)?;
        let operation = target(&request.headers)?;
        let caller = self.authorize(request, operation)?;
        match operation {
            "StartQueryExecution" => {
                self.start_query_execution(decode(&request.body)?, request, caller)
            }
            "GetQueryExecution" => self.get_query_execution(decode(&request.body)?, request),
            "StopQueryExecution" => self.stop_query_execution(decode(&request.body)?, request),
            "GetQueryResults" => {
                self.get_query_results(decode(&request.body)?, request, caller.as_ref())
            }
            _ => Err(AthenaError::InvalidRequest(
                "The requested Athena operation is not supported".into(),
            )),
        }
    }

    fn authorize(
        &self,
        request: &ServiceRequest,
        operation: &str,
    ) -> Result<Option<RequestIdentity>, AthenaError> {
        let Some(registry) = self.registry.upgrade() else {
            return Err(AthenaError::Internal);
        };
        let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
            return Ok(None);
        };
        if !evaluator.strict_sigv4_required() {
            return Ok(None);
        }
        if request
            .headers
            .get("x-locallycloud-verified-external-sigv4")
            != Some(&HeaderValue::from_static("1"))
        {
            return Err(AthenaError::AccessDenied);
        }
        let access_key_id = request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(RequestIdentity::access_key_from_authorization)
            .ok_or(AthenaError::AccessDenied)?;
        let caller = RequestIdentity {
            account_id: request.account_id.clone(),
            access_key_id: Some(access_key_id),
            arn: None,
        };
        evaluator
            .authorize(AuthorizationRequest {
                request_identity: caller.clone(),
                delegated_identity: None,
                source_service: "athena".into(),
                action: format!("athena:{operation}"),
                resource: format!(
                    "arn:aws:athena:{}:{}:workgroup/primary",
                    request.region, request.account_id
                ),
                context: Default::default(),
            })
            .map_err(|_| AthenaError::AccessDenied)?;
        Ok(Some(caller))
    }

    fn start_query_execution(
        &self,
        input: StartQueryExecutionRequest,
        request: &ServiceRequest,
        caller: Option<RequestIdentity>,
    ) -> Result<Value, AthenaError> {
        validate_start(&input)?;
        let scope = Scope::new(&request.account_id, &request.region);
        let spec = QuerySpec {
            query_string: input.query_string,
            context: input.query_execution_context,
            result_configuration: input.result_configuration,
            work_group: input.work_group,
        };

        if let Some(token) = input.client_request_token {
            let token_key = TokenKey {
                scope: scope.clone(),
                token,
            };
            match self.tokens.entry(token_key) {
                Entry::Occupied(entry) => {
                    let prior = entry.get();
                    if prior.spec != spec {
                        return Err(AthenaError::InvalidRequest(
                            "ClientRequestToken was reused with different query parameters".into(),
                        ));
                    }
                    return Ok(json!({ "QueryExecutionId": prior.query_id }));
                }
                Entry::Vacant(entry) => {
                    let query_id = self.insert_query(scope, spec.clone(), caller.clone())?;
                    entry.insert(TokenEntry {
                        query_id: query_id.clone(),
                        spec,
                    });
                    return Ok(json!({ "QueryExecutionId": query_id }));
                }
            }
        }

        let query_id = self.insert_query(scope, spec, caller)?;
        Ok(json!({ "QueryExecutionId": query_id }))
    }

    fn insert_query(
        &self,
        scope: Scope,
        spec: QuerySpec,
        caller: Option<RequestIdentity>,
    ) -> Result<String, AthenaError> {
        let id = Uuid::new_v4().to_string();
        let output = parse_s3_location(&spec.result_configuration.output_location)
            .map_err(|_| AthenaError::Internal)?;
        let effective_output_location = S3Location {
            bucket: output.bucket,
            key: output_key(&output.key, &id),
        };
        let record = Arc::new(Mutex::new(QueryRecord {
            id: id.clone(),
            spec,
            effective_output_location,
            state: QueryState::Queued,
            submission_time: now_epoch()?,
            completion_time: None,
            reason: None,
            scanned_bytes: 0,
            result: None,
            result_token: Uuid::new_v4().to_string(),
            caller,
        }));
        self.queries.insert(
            QueryKey {
                scope: scope.clone(),
                id: id.clone(),
            },
            Arc::clone(&record),
        );
        let registry = self.registry.clone();
        tokio::spawn(async move {
            run_query(registry, scope, record).await;
        });
        Ok(id)
    }

    fn get_query_execution(
        &self,
        input: QueryExecutionRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AthenaError> {
        let record = self.query(
            &request.account_id,
            &request.region,
            &input.query_execution_id,
        )?;
        let record = record.lock().map_err(|_| AthenaError::Internal)?;
        let mut status = serde_json::Map::new();
        status.insert("State".into(), record.state.as_str().into());
        status.insert("SubmissionDateTime".into(), record.submission_time.into());
        if let Some(time) = record.completion_time {
            status.insert("CompletionDateTime".into(), time.into());
        }
        if let Some(reason) = &record.reason {
            status.insert("StateChangeReason".into(), reason.clone().into());
        }
        let context = serde_json::to_value(record.spec.context.clone().unwrap_or_default())
            .map_err(|_| AthenaError::Internal)?;
        let result_configuration = json!({
            "OutputLocation": record.effective_output_location.uri()
        });
        Ok(json!({
            "QueryExecution": {
                "QueryExecutionId": record.id,
                "Query": record.spec.query_string,
                "StatementType": "DML",
                "QueryExecutionContext": context,
                "ResultConfiguration": result_configuration,
                "Status": Value::Object(status),
                "Statistics": { "DataScannedInBytes": record.scanned_bytes },
                "WorkGroup": record.spec.work_group.as_deref().unwrap_or("primary")
            }
        }))
    }

    fn stop_query_execution(
        &self,
        input: QueryExecutionRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AthenaError> {
        let record = self.query(
            &request.account_id,
            &request.region,
            &input.query_execution_id,
        )?;
        let mut record = record.lock().map_err(|_| AthenaError::Internal)?;
        if record.state.is_active() {
            record.state = QueryState::Cancelled;
            record.completion_time = Some(now_epoch()?);
            record.reason = Some("Query was cancelled by StopQueryExecution".into());
        }
        Ok(json!({}))
    }

    fn get_query_results(
        &self,
        input: GetQueryResultsRequest,
        request: &ServiceRequest,
        caller: Option<&RequestIdentity>,
    ) -> Result<Value, AthenaError> {
        let max_results = input.max_results.unwrap_or(1000);
        if !(1..=1000).contains(&max_results) {
            return Err(AthenaError::InvalidRequest(
                "MaxResults must be between 1 and 1000".into(),
            ));
        }
        let record = self.query(
            &request.account_id,
            &request.region,
            &input.query_execution_id,
        )?;
        let record = record.lock().map_err(|_| AthenaError::Internal)?;
        if record.state != QueryState::Succeeded {
            return Err(AthenaError::InvalidRequest(
                "Query results are available only for SUCCEEDED queries".into(),
            ));
        }
        let output_arn = format!(
            "arn:aws:s3:::{}/{}",
            record.effective_output_location.bucket, record.effective_output_location.key
        );
        if !iam_allows(
            &self.registry,
            &Scope::new(&request.account_id, &request.region),
            caller,
            "s3:GetObject",
            &output_arn,
        ) {
            return Err(AthenaError::AccessDenied);
        }
        let result = record.result.as_ref().ok_or(AthenaError::Internal)?;
        let invalid_token =
            || AthenaError::InvalidRequest("NextToken is invalid for this query".into());
        let start = match input.next_token {
            None => 0,
            Some(token) if token == record.result_token => 1,
            Some(token) => token
                .strip_prefix(&format!("{}:", record.result_token))
                .and_then(|offset| offset.parse::<usize>().ok())
                .filter(|offset| *offset > 0 && *offset < result.rows.len())
                .ok_or_else(invalid_token)?,
        };
        let end = start
            .saturating_add(max_results as usize)
            .min(result.rows.len());
        let rows = result.rows[start..end]
            .iter()
            .map(|row| {
                json!({ "Data": row.iter().map(|value| match value {
                Some(value) => json!({ "VarCharValue": value }),
                None => json!({}),
            }).collect::<Vec<_>>() })
            })
            .collect::<Vec<_>>();
        let mut output = json!({
            "ResultSet": {
                "ResultSetMetadata": { "ColumnInfo": result.columns.iter().map(|column| json!({
                    "Name": column.name, "Label": column.name, "Type": column.kind, "Nullable": "UNKNOWN"
                })).collect::<Vec<_>>() },
                "Rows": rows
            },
            "UpdateCount": 0
        });
        if end < result.rows.len() {
            output["NextToken"] = format!("{}:{end}", record.result_token).into();
        }
        Ok(output)
    }

    fn query(
        &self,
        account_id: &str,
        region: &str,
        query_id: &str,
    ) -> Result<Arc<Mutex<QueryRecord>>, AthenaError> {
        self.queries
            .get(&QueryKey {
                scope: Scope::new(account_id, region),
                id: query_id.to_owned(),
            })
            .map(|record| Arc::clone(record.value()))
            .ok_or_else(|| AthenaError::InvalidRequest("QueryExecutionId was not found".into()))
    }
}

#[async_trait]
impl NativeHandler for AthenaHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        match self.process(&request) {
            Ok(value) => Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
                .header("x-amzn-RequestId", &request.request_id)
                .body(Body::from(value.to_string()))
                .expect("Athena JSON response is valid"),
            Err(error) => AwsError::from(error)
                .with_request_id(request.request_id)
                .render(AwsProtocol::Json11)
                .into_response(),
        }
    }
}

#[derive(Debug)]
enum AthenaError {
    InvalidRequest(String),
    AccessDenied,
    Internal,
}

impl From<AthenaError> for AwsError {
    fn from(error: AthenaError) -> Self {
        match error {
            AthenaError::InvalidRequest(message) => {
                AwsError::new("InvalidRequestException", message, 400)
            }
            AthenaError::AccessDenied => {
                AwsError::new("AccessDeniedException", "Access denied", 400)
            }
            AthenaError::Internal => AwsError::new(
                "InternalServerException",
                "Athena could not complete the request",
                500,
            ),
        }
    }
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct QueryExecutionContext {
    database: Option<String>,
    catalog: Option<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct ResultConfiguration {
    output_location: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct StartQueryExecutionRequest {
    query_string: String,
    client_request_token: Option<String>,
    query_execution_context: Option<QueryExecutionContext>,
    result_configuration: ResultConfiguration,
    work_group: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct QueryExecutionRequest {
    query_execution_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct GetQueryResultsRequest {
    query_execution_id: String,
    max_results: Option<i64>,
    next_token: Option<String>,
}

fn validate_start(input: &StartQueryExecutionRequest) -> Result<(), AthenaError> {
    if input
        .client_request_token
        .as_ref()
        .is_some_and(|token| token.is_empty())
    {
        return Err(AthenaError::InvalidRequest(
            "ClientRequestToken must not be empty".into(),
        ));
    }
    if input
        .work_group
        .as_deref()
        .is_some_and(|work_group| work_group != "primary")
    {
        return Err(AthenaError::InvalidRequest(
            "Only the primary work group is supported".into(),
        ));
    }
    if let Some(context) = &input.query_execution_context {
        if context
            .database
            .as_ref()
            .is_some_and(|name| name.is_empty())
        {
            return Err(AthenaError::InvalidRequest(
                "Database must not be empty".into(),
            ));
        }
        if context
            .catalog
            .as_deref()
            .is_some_and(|catalog| catalog != "AwsDataCatalog")
        {
            return Err(AthenaError::InvalidRequest(
                "Only the AwsDataCatalog catalog is supported".into(),
            ));
        }
    }
    parse_s3_location(&input.result_configuration.output_location).map_err(|reason| {
        AthenaError::InvalidRequest(format!("OutputLocation is invalid: {reason}"))
    })?;
    Ok(())
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), AthenaError> {
    let media_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if media_type.is_some_and(|value| value.eq_ignore_ascii_case(CONTENT_TYPE)) {
        Ok(())
    } else {
        Err(AthenaError::InvalidRequest(format!(
            "Content-Type must be {CONTENT_TYPE}"
        )))
    }
}

fn target(headers: &HeaderMap) -> Result<&str, AthenaError> {
    let target = headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AthenaError::InvalidRequest("X-Amz-Target is required".into()))?;
    target
        .strip_prefix("AmazonAthena.")
        .filter(|operation| !operation.is_empty() && !operation.contains('.'))
        .ok_or_else(|| AthenaError::InvalidRequest("X-Amz-Target is invalid".into()))
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, AthenaError> {
    serde_json::from_slice(body)
        .map_err(|_| AthenaError::InvalidRequest("Request body is invalid".into()))
}

fn now_epoch() -> Result<f64, AthenaError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .map_err(|_| AthenaError::Internal)
}

#[derive(Debug)]
enum WorkerFailure {
    Cancelled,
    Failed { reason: String, scanned: u64 },
}

impl WorkerFailure {
    fn failed(reason: impl Into<String>, scanned: u64) -> Self {
        Self::Failed {
            reason: reason.into(),
            scanned,
        }
    }
}

fn iam_allows(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    action: &str,
    resource: &str,
) -> bool {
    let Some(registry) = registry.upgrade() else {
        return false;
    };
    let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
        return caller.is_none();
    };
    if !evaluator.strict_sigv4_required() {
        return true;
    }
    let Some(caller) = caller.filter(|caller| caller.account_id == scope.account_id()) else {
        return false;
    };
    evaluator
        .authorize(AuthorizationRequest {
            request_identity: caller.clone(),
            delegated_identity: None,
            source_service: "athena".into(),
            action: action.into(),
            resource: resource.into(),
            context: Default::default(),
        })
        .is_ok()
}

fn require_iam(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    action: &str,
    resource: &str,
    scanned: u64,
) -> Result<(), WorkerFailure> {
    if iam_allows(registry, scope, caller, action, resource) {
        Ok(())
    } else {
        Err(WorkerFailure::failed(
            format!("Access denied for {action} on {resource}"),
            scanned,
        ))
    }
}

async fn run_query(registry: Weak<ServiceRegistry>, scope: Scope, record: Arc<Mutex<QueryRecord>>) {
    let (spec, effective_output_location, caller) = {
        let Ok(mut query) = record.lock() else {
            return;
        };
        if query.state != QueryState::Queued {
            return;
        }
        query.state = QueryState::Running;
        (
            query.spec.clone(),
            query.effective_output_location.clone(),
            query.caller.clone(),
        )
    };

    match execute_query(
        &registry,
        &scope,
        caller.as_ref(),
        &record,
        &spec,
        &effective_output_location,
    )
    .await
    {
        Ok(()) => {}
        Err(WorkerFailure::Failed { reason, scanned }) => {
            if let Ok(mut query) = record.lock() {
                if query.state == QueryState::Running {
                    query.state = QueryState::Failed;
                    query.completion_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .ok()
                        .map(|duration| duration.as_secs_f64());
                    query.reason = Some(reason);
                    query.scanned_bytes = scanned;
                }
            }
        }
        Err(WorkerFailure::Cancelled) => {}
    }
}

async fn execute_query(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    record: &Arc<Mutex<QueryRecord>>,
    spec: &QuerySpec,
    effective_output_location: &S3Location,
) -> Result<(), WorkerFailure> {
    let parsed = SqlParser::new(&spec.query_string).parse().map_err(|reason| {
        WorkerFailure::failed(
            format!("Unsupported SQL: {reason}; expected SELECT COUNT(*), SUM(column), or column[, column] FROM identifier[.identifier] [WHERE column operator literal [AND ...]] [;]"),
            0,
        )
    })?;
    let database = parsed
        .database
        .clone()
        .or_else(|| {
            spec.context
                .as_ref()
                .and_then(|context| context.database.clone())
        })
        .ok_or_else(|| {
            WorkerFailure::failed(
                "Query database is required in QueryExecutionContext or the FROM clause",
                0,
            )
        })?;
    let table = glue_table_snapshot(registry, scope, caller, &database, &parsed.table).await?;
    let (result, scanned) =
        if !parsed.predicates.is_empty() || matches!(parsed.projection, Projection::Sum { .. }) {
            if !is_iceberg_table(&table) {
                return Err(WorkerFailure::failed(
                    "Predicates require an Iceberg table",
                    0,
                ));
            }
            let mut names = match &parsed.projection {
                Projection::Columns(names) => names.clone(),
                Projection::Count(_) => Vec::new(),
                Projection::Sum { column, .. } => vec![column.clone()],
            };
            let projected = names.len();
            for predicate in &parsed.predicates {
                if !names.contains(&predicate.column) {
                    names.push(predicate.column.clone());
                }
            }
            let (mut result, scanned) = iceberg_rows(
                registry,
                scope,
                caller,
                record,
                &table,
                &names,
                &parsed.predicates,
            )
            .await?;
            apply_predicates(&mut result, &parsed.predicates)
                .map_err(|reason| WorkerFailure::failed(reason, scanned))?;
            match &parsed.projection {
                Projection::Sum { alias, .. } => (
                    sum_result(&result, alias)
                        .map_err(|reason| WorkerFailure::failed(reason, scanned))?,
                    scanned,
                ),
                Projection::Count(alias) => (
                    QueryResult::count(alias.clone(), result.rows.len().saturating_sub(1) as u64),
                    scanned,
                ),
                Projection::Columns(_) => {
                    result.columns.truncate(projected);
                    for row in &mut result.rows {
                        row.truncate(projected);
                    }
                    (result, scanned)
                }
            }
        } else {
            match parsed.projection {
                Projection::Count(alias) => {
                    let (count, scanned) = if is_iceberg_table(&table) {
                        iceberg_count(registry, scope, caller, record, &table).await?
                    } else {
                        jsonl_count(registry, scope, caller, record, &table).await?
                    };
                    (QueryResult::count(alias, count), scanned)
                }
                Projection::Columns(columns) if is_iceberg_table(&table) => {
                    iceberg_rows(registry, scope, caller, record, &table, &columns, &[]).await?
                }
                Projection::Sum { .. } => unreachable!("SUM takes the row reader path"),
                Projection::Columns(_) => {
                    return Err(WorkerFailure::failed(
                        "Column projection requires an Iceberg table",
                        0,
                    ))
                }
            }
        };
    ensure_running(record)?;
    let csv = result.csv();
    if csv.len() > MAX_RESULT_BYTES {
        return Err(WorkerFailure::failed(
            "Query exceeded the 64 MiB result limit",
            scanned,
        ));
    }
    put_object(
        registry,
        scope,
        caller,
        &effective_output_location.bucket,
        &effective_output_location.key,
        Bytes::from(csv.into_bytes()),
        scanned,
    )
    .await?;

    let cancelled = {
        let mut query = record
            .lock()
            .map_err(|_| WorkerFailure::failed("Athena query state is unavailable", scanned))?;
        match query.state {
            QueryState::Running => {
                query.state = QueryState::Succeeded;
                query.completion_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .map(|duration| duration.as_secs_f64());
                query.scanned_bytes = scanned;
                query.result = Some(result);
                false
            }
            QueryState::Cancelled => true,
            _ => return Err(WorkerFailure::Cancelled),
        }
    };
    if cancelled {
        let _ = delete_object(
            registry,
            scope,
            caller,
            &effective_output_location.bucket,
            &effective_output_location.key,
            scanned,
        )
        .await;
        return Err(WorkerFailure::Cancelled);
    }
    Ok(())
}

fn is_iceberg_table(table: &GlueTableOutput) -> bool {
    table
        .parameters
        .get("table_type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.eq_ignore_ascii_case("ICEBERG"))
}

async fn iceberg_count(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    record: &Arc<Mutex<QueryRecord>>,
    table: &GlueTableOutput,
) -> Result<(u64, u64), WorkerFailure> {
    let (_, body, scanned) = iceberg_manifest_list(registry, scope, caller, record, table).await?;
    Ok((
        if body.is_empty() {
            0
        } else {
            count_manifest_list(&body, scanned)?
        },
        scanned,
    ))
}

async fn iceberg_manifest_list(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    record: &Arc<Mutex<QueryRecord>>,
    table: &GlueTableOutput,
) -> Result<(Value, Bytes, u64), WorkerFailure> {
    // Iceberg's current snapshot is the only source of truth. Listing all objects
    // under the table prefix would count old snapshots and uncommitted writes.
    let metadata_uri = table
        .parameters
        .get("metadata_location")
        .and_then(Value::as_str)
        .ok_or_else(|| WorkerFailure::failed("Iceberg table is missing metadata_location", 0))?;
    let metadata_location = parse_s3_location(metadata_uri).map_err(|reason| {
        WorkerFailure::failed(format!("Iceberg metadata_location is invalid: {reason}"), 0)
    })?;
    if metadata_location.key.is_empty() {
        return Err(WorkerFailure::failed(
            "Iceberg metadata_location must name an object",
            0,
        ));
    }
    ensure_running(record)?;
    let metadata_body = get_object(
        registry,
        scope,
        caller,
        &metadata_location.bucket,
        &metadata_location.key,
        0,
    )
    .await?;
    let mut scanned = metadata_body.len() as u64;
    if scanned > SCAN_LIMIT {
        return Err(WorkerFailure::failed(
            "Query exceeded the 64 MiB scan limit",
            scanned,
        ));
    }
    update_scanned(record, scanned)?;
    let metadata: Value = serde_json::from_slice(&metadata_body)
        .map_err(|_| WorkerFailure::failed("Iceberg metadata JSON is invalid", scanned))?;
    if metadata.get("format-version").and_then(Value::as_u64) != Some(2) {
        return Err(WorkerFailure::failed(
            "Only Iceberg format version 2 is supported",
            scanned,
        ));
    }
    let Some(snapshot_id) = metadata.get("current-snapshot-id").and_then(Value::as_i64) else {
        if metadata
            .get("current-snapshot-id")
            .is_none_or(Value::is_null)
        {
            return Ok((metadata, Bytes::new(), scanned));
        }
        return Err(WorkerFailure::failed(
            "Iceberg current-snapshot-id is invalid",
            scanned,
        ));
    };
    if snapshot_id == -1 {
        return Ok((metadata, Bytes::new(), scanned));
    }
    if snapshot_id < 0 {
        return Err(WorkerFailure::failed(
            "Iceberg current-snapshot-id is invalid",
            scanned,
        ));
    }
    let snapshots = metadata
        .get("snapshots")
        .and_then(Value::as_array)
        .ok_or_else(|| WorkerFailure::failed("Iceberg snapshots are missing", scanned))?;
    let snapshot = snapshots
        .iter()
        .find(|snapshot| snapshot.get("snapshot-id").and_then(Value::as_i64) == Some(snapshot_id))
        .ok_or_else(|| WorkerFailure::failed("Iceberg current snapshot was not found", scanned))?;
    let manifest_uri = snapshot
        .get("manifest-list")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WorkerFailure::failed("Iceberg current snapshot has no manifest list", scanned)
        })?;
    let manifest_location = parse_s3_location(manifest_uri).map_err(|reason| {
        WorkerFailure::failed(
            format!("Iceberg manifest list location is invalid: {reason}"),
            scanned,
        )
    })?;
    if manifest_location.key.is_empty() {
        return Err(WorkerFailure::failed(
            "Iceberg manifest list must name an object",
            scanned,
        ));
    }
    ensure_running(record)?;
    let manifest_body = get_object(
        registry,
        scope,
        caller,
        &manifest_location.bucket,
        &manifest_location.key,
        scanned,
    )
    .await?;
    scanned = scanned
        .checked_add(manifest_body.len() as u64)
        .ok_or_else(|| WorkerFailure::failed("Athena scan byte count overflowed", scanned))?;
    if scanned > SCAN_LIMIT {
        return Err(WorkerFailure::failed(
            "Query exceeded the 64 MiB scan limit",
            scanned,
        ));
    }
    update_scanned(record, scanned)?;
    Ok((metadata, manifest_body, scanned))
}

const MAX_RESULT_ROWS: usize = 100_000;
const MAX_RESULT_BYTES: usize = 64 * 1024 * 1024;

async fn iceberg_rows(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    record: &Arc<Mutex<QueryRecord>>,
    table: &GlueTableOutput,
    names: &[String],
    predicates: &[Predicate],
) -> Result<(QueryResult, u64), WorkerFailure> {
    let (metadata, manifest_list, mut scanned) =
        iceberg_manifest_list(registry, scope, caller, record, table).await?;
    let columns = iceberg_columns(&metadata, names, scanned)?;
    let mut result = QueryResult {
        rows: vec![names.iter().cloned().map(Some).collect()],
        columns,
    };
    let mut result_bytes = names.iter().map(String::len).sum::<usize>();
    if manifest_list.is_empty() {
        return Ok((result, scanned));
    }
    let reader = AvroReader::new(&manifest_list[..])
        .map_err(|_| WorkerFailure::failed("Iceberg manifest list Avro is invalid", scanned))?;
    for item in reader {
        ensure_running(record)?;
        let item = item.map_err(|_| {
            WorkerFailure::failed("Iceberg manifest list record is invalid", scanned)
        })?;
        let content = avro_integer(avro_field(&item, "content", scanned)?, scanned)?;
        if content != 0 {
            return Err(WorkerFailure::failed(
                "Iceberg delete or unknown manifest is unsupported",
                scanned,
            ));
        }
        let path = avro_string(avro_field(&item, "manifest_path", scanned)?, scanned)?;
        let location = parse_s3_location(path)
            .map_err(|_| WorkerFailure::failed("Iceberg manifest path is invalid", scanned))?;
        if location.key.is_empty() {
            return Err(WorkerFailure::failed(
                "Iceberg manifest path is empty",
                scanned,
            ));
        }
        let body = get_object(
            registry,
            scope,
            caller,
            &location.bucket,
            &location.key,
            scanned,
        )
        .await?;
        scanned = add_scan(record, scanned, body.len())?;
        let manifest = AvroReader::new(&body[..])
            .map_err(|_| WorkerFailure::failed("Iceberg manifest Avro is invalid", scanned))?;
        let spec_id = avro_integer(avro_field(&item, "partition_spec_id", scanned)?, scanned)?;
        let partition = iceberg_partition(&metadata, spec_id, scanned)?;
        for entry in manifest {
            ensure_running(record)?;
            let entry = entry.map_err(|_| {
                WorkerFailure::failed("Iceberg manifest record is invalid", scanned)
            })?;
            let status = avro_integer(avro_field(&entry, "status", scanned)?, scanned)?;
            if status == 2 {
                continue;
            }
            if status != 0 && status != 1 {
                return Err(WorkerFailure::failed(
                    "Iceberg manifest status is invalid",
                    scanned,
                ));
            }
            let file = avro_field(&entry, "data_file", scanned)?;
            if avro_integer(avro_field(file, "content", scanned)?, scanned)? != 0 {
                return Err(WorkerFailure::failed(
                    "Iceberg delete files are unsupported",
                    scanned,
                ));
            }
            if avro_string(avro_field(file, "file_format", scanned)?, scanned)? != "PARQUET" {
                return Err(WorkerFailure::failed(
                    "Only Parquet Iceberg data files are supported",
                    scanned,
                ));
            }
            if let Some((partition_name, source_name)) = &partition {
                let tuple = avro_field(file, "partition", scanned)?;
                let day = avro_date(avro_field(tuple, partition_name, scanned)?, scanned)?;
                let date = i32::try_from(day)
                    .ok()
                    .and_then(|day| day.checked_add(2_440_588))
                    .and_then(|day| time::Date::from_julian_day(day).ok())
                    .ok_or_else(|| WorkerFailure::failed("Invalid date partition", scanned))?
                    .to_string();
                let mut partition_result = QueryResult {
                    columns: vec![ResultColumn {
                        name: source_name.clone(),
                        kind: "date",
                    }],
                    rows: vec![vec![Some(source_name.clone())], vec![Some(date)]],
                };
                let applicable = predicates
                    .iter()
                    .filter(|p| p.column == *source_name)
                    .map(|p| Predicate {
                        column: p.column.clone(),
                        operator: p.operator.clone(),
                        value: p.value.clone(),
                    })
                    .collect::<Vec<_>>();
                apply_predicates(&mut partition_result, &applicable)
                    .map_err(|reason| WorkerFailure::failed(reason, scanned))?;
                if partition_result.rows.len() == 1 {
                    continue;
                }
            }
            let path = avro_string(avro_field(file, "file_path", scanned)?, scanned)?;
            let location = parse_s3_location(path)
                .map_err(|_| WorkerFailure::failed("Iceberg data file path is invalid", scanned))?;
            if location.key.is_empty() {
                return Err(WorkerFailure::failed(
                    "Iceberg data file path is empty",
                    scanned,
                ));
            }
            let body = get_object(
                registry,
                scope,
                caller,
                &location.bucket,
                &location.key,
                scanned,
            )
            .await?;
            scanned = add_scan(record, scanned, body.len())?;
            let expected = result
                .columns
                .iter()
                .map(|column| column.kind)
                .collect::<Vec<_>>();
            let schema = metadata["schemas"]
                .as_array()
                .and_then(|schemas| {
                    schemas
                        .iter()
                        .find(|s| s["schema-id"] == metadata["current-schema-id"])
                })
                .and_then(|s| s["fields"].as_array())
                .ok_or_else(|| WorkerFailure::failed("Current schema missing", scanned))?;
            let definitions = names
                .iter()
                .map(|name| {
                    let field = schema
                        .iter()
                        .find(|f| f["name"] == *name)
                        .ok_or_else(|| WorkerFailure::failed("Projected field missing", scanned))?;
                    Ok((
                        field["id"]
                            .as_i64()
                            .and_then(|id| i32::try_from(id).ok())
                            .ok_or_else(|| WorkerFailure::failed("Field ID missing", scanned))?,
                        field["required"] == true,
                    ))
                })
                .collect::<Result<Vec<_>, WorkerFailure>>()?;
            let names = names.to_vec();
            let rows = tokio::task::spawn_blocking(move || {
                parquet_typed_rows(body, &names, &expected, Some(&definitions))
            })
            .await
            .map_err(|_| WorkerFailure::failed("Parquet reader task failed", scanned))?
            .map_err(|reason| WorkerFailure::failed(reason, scanned))?;
            result_bytes = result_bytes.saturating_add(
                rows.iter()
                    .flat_map(|row| row.iter())
                    .filter_map(|value| value.as_ref().map(String::len))
                    .sum::<usize>(),
            );
            if result_bytes > MAX_RESULT_BYTES {
                return Err(WorkerFailure::failed(
                    "Query exceeded the 64 MiB result limit",
                    scanned,
                ));
            }
            if result.rows.len().saturating_add(rows.len()) > MAX_RESULT_ROWS {
                return Err(WorkerFailure::failed(
                    "Query exceeded the 100000 row result limit",
                    scanned,
                ));
            }
            result.rows.extend(rows);
        }
    }
    Ok((result, scanned))
}

fn iceberg_partition(
    metadata: &Value,
    spec_id: i64,
    scanned: u64,
) -> Result<Option<(String, String)>, WorkerFailure> {
    let specs = metadata["partition-specs"]
        .as_array()
        .ok_or_else(|| WorkerFailure::failed("Iceberg partition specs missing", scanned))?;
    let spec = specs
        .iter()
        .find(|s| s["spec-id"].as_i64() == Some(spec_id))
        .ok_or_else(|| WorkerFailure::failed("Iceberg partition spec missing", scanned))?;
    let fields = spec["fields"]
        .as_array()
        .ok_or_else(|| WorkerFailure::failed("Iceberg partition fields missing", scanned))?;
    if fields.is_empty() {
        return Ok(None);
    }
    if fields.len() != 1 || fields[0]["transform"] != "identity" {
        return Err(WorkerFailure::failed(
            "Only one identity date partition is supported",
            scanned,
        ));
    }
    let source = metadata["schemas"]
        .as_array()
        .and_then(|schemas| {
            schemas
                .iter()
                .find(|s| s["schema-id"] == metadata["current-schema-id"])
        })
        .and_then(|schema| schema["fields"].as_array())
        .and_then(|fields_| fields_.iter().find(|f| f["id"] == fields[0]["source-id"]))
        .ok_or_else(|| WorkerFailure::failed("Partition source missing", scanned))?;
    if source["type"] != "date" || source["required"] != true {
        return Err(WorkerFailure::failed(
            "Partition source must be a required date",
            scanned,
        ));
    }
    Ok(Some((
        fields[0]["name"]
            .as_str()
            .ok_or_else(|| WorkerFailure::failed("Partition name missing", scanned))?
            .into(),
        source["name"]
            .as_str()
            .ok_or_else(|| WorkerFailure::failed("Partition source name missing", scanned))?
            .into(),
    )))
}

fn iceberg_columns(
    metadata: &Value,
    names: &[String],
    scanned: u64,
) -> Result<Vec<ResultColumn>, WorkerFailure> {
    if let Some(specs) = metadata["partition-specs"].as_array() {
        for spec in specs {
            iceberg_partition(metadata, spec["spec-id"].as_i64().unwrap_or(-1), scanned)?;
        }
    }
    let schema_id = metadata
        .get("current-schema-id")
        .and_then(Value::as_i64)
        .ok_or_else(|| WorkerFailure::failed("Iceberg current schema is missing", scanned))?;
    let schema = metadata
        .get("schemas")
        .and_then(Value::as_array)
        .and_then(|schemas| {
            schemas
                .iter()
                .find(|schema| schema.get("schema-id").and_then(Value::as_i64) == Some(schema_id))
        })
        .ok_or_else(|| WorkerFailure::failed("Iceberg current schema was not found", scanned))?;
    let fields = schema
        .get("fields")
        .and_then(Value::as_array)
        .ok_or_else(|| WorkerFailure::failed("Iceberg schema fields are missing", scanned))?;
    let mut columns = Vec::new();
    for name in names {
        if columns
            .iter()
            .any(|column: &ResultColumn| column.name == *name)
        {
            return Err(WorkerFailure::failed("Duplicate projected column", scanned));
        }
        let field = fields
            .iter()
            .find(|field| field.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| {
                WorkerFailure::failed(format!("Iceberg column {name} was not found"), scanned)
            })?;
        if field.get("initial-default").is_some_and(|v| !v.is_null())
            || field.get("write-default").is_some_and(|v| !v.is_null())
        {
            return Err(WorkerFailure::failed(
                "Iceberg field defaults are unsupported",
                scanned,
            ));
        }
        let kind = match field.get("type").and_then(Value::as_str) {
            Some("long") => "bigint",
            Some("string") => "varchar",
            Some("int") => "integer",
            Some("boolean") => "boolean",
            Some("date") => "date",
            Some("timestamp") => "timestamp",
            Some("timestamptz") => "timestamptz",
            Some("decimal(18,2)" | "decimal(18, 2)") => "decimal(18,2)",
            _ => {
                return Err(WorkerFailure::failed(
                    format!("Iceberg column {name} has unsupported type"),
                    scanned,
                ))
            }
        };
        columns.push(ResultColumn {
            name: name.clone(),
            kind,
        });
    }
    Ok(columns)
}

fn avro_string(value: &AvroValue, scanned: u64) -> Result<&str, WorkerFailure> {
    match value {
        AvroValue::String(value) => Ok(value),
        AvroValue::Union(_, value) => avro_string(value, scanned),
        _ => Err(WorkerFailure::failed(
            "Iceberg manifest string has invalid type",
            scanned,
        )),
    }
}

fn add_scan(
    record: &Arc<Mutex<QueryRecord>>,
    scanned: u64,
    added: usize,
) -> Result<u64, WorkerFailure> {
    let total = scanned
        .checked_add(added as u64)
        .ok_or_else(|| WorkerFailure::failed("Athena scan byte count overflowed", scanned))?;
    if total > SCAN_LIMIT {
        return Err(WorkerFailure::failed(
            "Query exceeded the 64 MiB scan limit",
            total,
        ));
    }
    update_scanned(record, total)?;
    Ok(total)
}

#[cfg(test)]
fn parquet_rows(
    body: Bytes,
    names: &[String],
    expected: &[&str],
) -> Result<Vec<Vec<Option<String>>>, String> {
    parquet_typed_rows(body, names, expected, None)
}

fn parquet_typed_rows(
    body: Bytes,
    names: &[String],
    expected: &[&str],
    definitions: Option<&[(i32, bool)]>,
) -> Result<Vec<Vec<Option<String>>>, String> {
    let reader =
        SerializedFileReader::new(body).map_err(|_| "Parquet data file is invalid".to_string())?;
    let physical_names = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            match definitions {
                Some(definitions) => {
                    let columns = reader.metadata().file_metadata().schema_descr().columns();
                    let matching = columns.iter().find(|c| {
                        c.self_type().get_basic_info().has_id()
                            && c.self_type().get_basic_info().id() == definitions[index].0
                    });
                    if let Some(column) = matching {
                        return Ok(Some(column.self_type().name().to_owned()));
                    }
                    if columns
                        .iter()
                        .any(|c| c.self_type().get_basic_info().has_id())
                    {
                        return if definitions[index].1 {
                            Err(format!(
                                "Required field ID {} missing",
                                definitions[index].0
                            ))
                        } else {
                            Ok(None)
                        };
                    }
                    // Legacy unambiguous files without IDs remain readable by name.
                    Ok(Some(name.clone()))
                }
                None => Ok(Some(name.clone())),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let iter = reader
        .get_row_iter(None)
        .map_err(|_| "Parquet rows are invalid".to_string())?;
    let mut rows = Vec::new();
    let mut output_bytes = 0usize;
    for row in iter {
        let row = row.map_err(|_| "Parquet row is invalid".to_string())?;
        let mut values = Vec::new();
        for (index, ((name, expected), physical_name)) in
            names.iter().zip(expected).zip(&physical_names).enumerate()
        {
            let Some(physical_name) = physical_name else {
                values.push(None);
                continue;
            };
            let (_, value) = row
                .get_column_iter()
                .find(|(column, _)| *column == physical_name)
                .ok_or_else(|| format!("Parquet column {name} was not found"))?;
            values.push(match (expected, value) {
                (_, ParquetField::Null) => {
                    if definitions.is_some_and(|definitions| definitions[index].1) {
                        return Err(format!("Required column {name} contains null"));
                    }
                    None
                }
                (&"bigint", ParquetField::Long(value)) => Some(value.to_string()),
                (&"varchar", ParquetField::Str(value)) => Some(value.clone()),
                (&"integer", ParquetField::Int(value)) => Some(value.to_string()),
                (&"boolean", ParquetField::Bool(value)) => Some(value.to_string()),
                (&"date", ParquetField::Date(value)) => Some(
                    time::Date::from_julian_day(
                        value.checked_add(2_440_588).ok_or("date out of range")?,
                    )
                    .map_err(|_| "date out of range")?
                    .to_string(),
                ),
                (&"timestamp" | &"timestamptz", ParquetField::TimestampMicros(value)) => Some(
                    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(*value) * 1000)
                        .map_err(|_| "timestamp out of range")?
                        .format(&time::format_description::well_known::Rfc3339)
                        .map_err(|_| "timestamp formatting failed")?,
                ),
                (&"decimal(18,2)", ParquetField::Decimal(value))
                    if value.scale() == 2 && value.precision() == 18 && value.data().len() == 8 =>
                {
                    let cents =
                        i64::from_be_bytes(value.data().try_into().map_err(|_| "invalid decimal")?);
                    Some(format!(
                        "{}{}.{:02}",
                        if cents < 0 { "-" } else { "" },
                        cents.unsigned_abs() / 100,
                        cents.unsigned_abs() % 100
                    ))
                }
                _ => return Err(format!("Parquet column {name} has unsupported value type")),
            });
        }
        output_bytes = output_bytes.saturating_add(
            values
                .iter()
                .filter_map(|value: &Option<String>| value.as_ref().map(String::len))
                .sum::<usize>(),
        );
        if output_bytes > MAX_RESULT_BYTES {
            return Err("Query exceeded the 64 MiB result limit".into());
        }
        rows.push(values);
        if rows.len() > MAX_RESULT_ROWS {
            return Err("Query exceeded the 100000 row result limit".into());
        }
    }
    Ok(rows)
}

fn count_manifest_list(body: &[u8], scanned: u64) -> Result<u64, WorkerFailure> {
    let reader = AvroReader::new(body)
        .map_err(|_| WorkerFailure::failed("Iceberg manifest list Avro is invalid", scanned))?;
    let mut count = 0u64;
    for item in reader {
        let item = item.map_err(|_| {
            WorkerFailure::failed("Iceberg manifest list record is invalid", scanned)
        })?;
        let content = avro_integer(avro_field(&item, "content", scanned)?, scanned)?;
        match content {
            0 => {}
            1 => {
                return Err(WorkerFailure::failed(
                    "Iceberg delete manifests require row-level merge-on-read support",
                    scanned,
                ))
            }
            _ => {
                return Err(WorkerFailure::failed(
                    "Iceberg manifest content is invalid",
                    scanned,
                ))
            }
        }
        let added = avro_nonnegative(avro_field(&item, "added_rows_count", scanned)?, scanned)?;
        let existing =
            avro_nonnegative(avro_field(&item, "existing_rows_count", scanned)?, scanned)?;
        let deleted = avro_nonnegative(avro_field(&item, "deleted_rows_count", scanned)?, scanned)?;
        // deleted_rows_count records files removed from the manifest; those
        // rows are already excluded from the current snapshot's live count.
        let _ = deleted;
        count = count
            .checked_add(added)
            .and_then(|value| value.checked_add(existing))
            .ok_or_else(|| WorkerFailure::failed("Iceberg row count overflowed", scanned))?;
    }
    Ok(count)
}

fn avro_field<'a>(
    record: &'a AvroValue,
    name: &str,
    scanned: u64,
) -> Result<&'a AvroValue, WorkerFailure> {
    match record {
        AvroValue::Record(fields) => fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
            .ok_or_else(|| {
                WorkerFailure::failed(format!("Iceberg manifest list is missing {name}"), scanned)
            }),
        _ => Err(WorkerFailure::failed(
            "Iceberg manifest list record is not a record",
            scanned,
        )),
    }
}

fn avro_date(value: &AvroValue, scanned: u64) -> Result<i64, WorkerFailure> {
    match value {
        AvroValue::Date(day) | AvroValue::Int(day) => Ok(i64::from(*day)),
        AvroValue::Union(_, value) => avro_date(value, scanned),
        _ => Err(WorkerFailure::failed(
            "Iceberg date partition has invalid type",
            scanned,
        )),
    }
}

fn avro_integer(value: &AvroValue, scanned: u64) -> Result<i64, WorkerFailure> {
    match value {
        AvroValue::Int(value) => Ok(i64::from(*value)),
        AvroValue::Long(value) => Ok(*value),
        _ => Err(WorkerFailure::failed(
            "Iceberg manifest list count has invalid type",
            scanned,
        )),
    }
}

fn avro_nonnegative(value: &AvroValue, scanned: u64) -> Result<u64, WorkerFailure> {
    u64::try_from(avro_integer(value, scanned)?)
        .map_err(|_| WorkerFailure::failed("Iceberg manifest list count is negative", scanned))
}

async fn jsonl_count(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    record: &Arc<Mutex<QueryRecord>>,
    table: &GlueTableOutput,
) -> Result<(u64, u64), WorkerFailure> {
    let location = table_location(table)?;
    let keys = list_objects(registry, scope, caller, &location).await?;
    let mut count = 0u64;
    let mut scanned = 0u64;
    for key in keys {
        ensure_running(record)?;
        if !key.starts_with(&location.key) {
            continue;
        }
        let body = get_object(registry, scope, caller, &location.bucket, &key, scanned).await?;
        scanned = scanned
            .checked_add(body.len() as u64)
            .ok_or_else(|| WorkerFailure::failed("Athena scan byte count overflowed", scanned))?;
        update_scanned(record, scanned)?;
        if scanned > SCAN_LIMIT {
            return Err(WorkerFailure::failed(
                "Query exceeded the 64 MiB scan limit",
                scanned,
            ));
        }
        for (index, line) in body.split(|byte| *byte == b'\n').enumerate() {
            let line = trim_ascii(line);
            if line.is_empty() {
                continue;
            }
            serde_json::from_slice::<Value>(line).map_err(|error| {
                WorkerFailure::failed(
                    format!(
                        "Object {key} contains invalid JSON on line {}: {error}",
                        index + 1
                    ),
                    scanned,
                )
            })?;
            count = count
                .checked_add(1)
                .ok_or_else(|| WorkerFailure::failed("COUNT(*) overflowed", scanned))?;
        }
    }
    Ok((count, scanned))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GlueGetDatabaseOutput {
    database: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GlueGetTableOutput {
    table: GlueTableOutput,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GlueTableOutput {
    storage_descriptor: Option<Value>,
    #[serde(default)]
    parameters: Value,
    #[serde(default)]
    partition_keys: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GlueGetPartitionsOutput {
    #[serde(default)]
    partitions: Vec<Value>,
    next_token: Option<String>,
}

async fn glue_table_snapshot(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    database: &str,
    table: &str,
) -> Result<GlueTableOutput, WorkerFailure> {
    let database_output: GlueGetDatabaseOutput = glue_json_request(
        registry,
        scope,
        caller,
        "GetDatabase",
        json!({ "CatalogId": scope.account_id(), "Name": database }),
    )
    .await?;
    if !database_output.database.is_object() {
        return Err(WorkerFailure::failed(
            "Glue GetDatabase returned malformed metadata",
            0,
        ));
    }

    let table_output: GlueGetTableOutput = glue_json_request(
        registry,
        scope,
        caller,
        "GetTable",
        json!({
            "CatalogId": scope.account_id(),
            "DatabaseName": database,
            "Name": table
        }),
    )
    .await?;
    if is_iceberg_table(&table_output.table) {
        return Ok(table_output.table);
    }
    if !table_output.table.partition_keys.is_empty() {
        return Err(WorkerFailure::failed(
            "Partitioned Glue tables are not supported by the COUNT JSONL milestone",
            0,
        ));
    }

    let mut next_token: Option<String> = None;
    loop {
        let mut request = json!({
            "CatalogId": scope.account_id(),
            "DatabaseName": database,
            "TableName": table,
            "MaxResults": 1000
        });
        if let Some(token) = next_token.as_ref() {
            request
                .as_object_mut()
                .expect("Glue request is an object")
                .insert("NextToken".into(), token.clone().into());
        }
        let output: GlueGetPartitionsOutput =
            glue_json_request(registry, scope, caller, "GetPartitions", request).await?;
        if !output.partitions.is_empty() {
            return Err(WorkerFailure::failed(
                "Glue partitions are not supported by the COUNT JSONL milestone",
                0,
            ));
        }
        match output.next_token {
            Some(token) if next_token.as_deref() == Some(&token) => {
                return Err(WorkerFailure::failed(
                    "Glue GetPartitions repeated its pagination token",
                    0,
                ));
            }
            Some(token) => next_token = Some(token),
            None => break,
        }
    }

    Ok(table_output.table)
}

fn table_location(table: &GlueTableOutput) -> Result<S3Location, WorkerFailure> {
    let descriptor = table
        .storage_descriptor
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| WorkerFailure::failed("Glue table is missing StorageDescriptor", 0))?;
    let input_format = descriptor
        .get("InputFormat")
        .and_then(Value::as_str)
        .ok_or_else(|| WorkerFailure::failed("Glue table is missing InputFormat", 0))?;
    if input_format != JSON_INPUT_FORMAT {
        return Err(WorkerFailure::failed(
            format!("Unsupported Glue InputFormat {input_format}"),
            0,
        ));
    }
    let serde = descriptor
        .get("SerdeInfo")
        .and_then(Value::as_object)
        .and_then(|value| value.get("SerializationLibrary"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WorkerFailure::failed("Glue table is missing SerdeInfo.SerializationLibrary", 0)
        })?;
    if serde != JSON_SERDE {
        return Err(WorkerFailure::failed(
            format!("Unsupported Glue serialization library {serde}"),
            0,
        ));
    }
    let location = descriptor
        .get("Location")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WorkerFailure::failed("Glue table is missing StorageDescriptor.Location", 0)
        })?;
    parse_s3_location(location).map_err(|reason| {
        WorkerFailure::failed(format!("Glue table Location is invalid: {reason}"), 0)
    })
}

fn ensure_running(record: &Arc<Mutex<QueryRecord>>) -> Result<(), WorkerFailure> {
    let query = record
        .lock()
        .map_err(|_| WorkerFailure::failed("Athena query state is unavailable", 0))?;
    if query.state == QueryState::Running {
        Ok(())
    } else {
        Err(WorkerFailure::Cancelled)
    }
}

fn update_scanned(record: &Arc<Mutex<QueryRecord>>, scanned: u64) -> Result<(), WorkerFailure> {
    let mut query = record
        .lock()
        .map_err(|_| WorkerFailure::failed("Athena query state is unavailable", scanned))?;
    if query.state != QueryState::Running {
        return Err(WorkerFailure::Cancelled);
    }
    query.scanned_bytes = scanned;
    Ok(())
}

#[derive(Clone)]
struct S3Location {
    bucket: String,
    key: String,
}

impl S3Location {
    fn uri(&self) -> String {
        format!("s3://{}/{}", self.bucket, self.key)
    }
}

fn parse_s3_location(value: &str) -> Result<S3Location, String> {
    let rest = value
        .strip_prefix("s3://")
        .ok_or_else(|| "location must start with s3://".to_string())?;
    let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
    if !valid_bucket_name(bucket) || key.contains(['?', '#']) {
        return Err("location must contain a valid bucket and key prefix".into());
    }
    Ok(S3Location {
        bucket: bucket.into(),
        key: key.into(),
    })
}

fn valid_bucket_name(name: &str) -> bool {
    let length = name.len();
    if !(3..=63).contains(&length)
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        return false;
    }
    let first = name.as_bytes()[0];
    let last = name.as_bytes()[length - 1];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit())
        || !(last.is_ascii_lowercase() || last.is_ascii_digit())
        || name.contains("..")
        || name.contains(".-")
        || name.contains("-.")
        || looks_like_ipv4(name)
        || ["xn--", "sthree-", "amzn-s3-demo-"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        || name.ends_with("-s3alias")
        || name.ends_with("--ol-s3")
    {
        return false;
    }
    true
}

fn looks_like_ipv4(name: &str) -> bool {
    let mut parts = name.split('.');
    (0..4).all(|_| parts.next().is_some_and(|part| part.parse::<u8>().is_ok()))
        && parts.next().is_none()
}

fn output_key(prefix: &str, query_id: &str) -> String {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        format!("{query_id}.csv")
    } else {
        format!("{prefix}/{query_id}.csv")
    }
}

async fn list_objects(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    location: &S3Location,
) -> Result<Vec<String>, WorkerFailure> {
    let mut keys = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut uri = format!(
            "/{}?list-type=2&prefix={}",
            percent_encode(&location.bucket, false),
            percent_encode(&location.key, false)
        );
        if let Some(token) = &token {
            uri.push_str("&continuation-token=");
            uri.push_str(&percent_encode(token, false));
        }
        let uri: Uri = uri
            .parse()
            .map_err(|_| WorkerFailure::failed("S3 list URI is invalid", 0))?;
        let response = s3_request(
            registry,
            scope,
            caller,
            "s3:ListBucket",
            format!("arn:aws:s3:::{}", location.bucket),
            Method::GET,
            uri,
            HeaderMap::new(),
            Bytes::new(),
        )
        .await?;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|_| WorkerFailure::failed("Failed to read S3 ListObjectsV2 response", 0))?;
        if !status.is_success() {
            return Err(WorkerFailure::failed(
                format!("S3 ListObjectsV2 failed with status {status}"),
                0,
            ));
        }
        let page = parse_list_objects(&body)?;
        keys.extend(
            page.keys
                .into_iter()
                .filter(|key| key.starts_with(&location.key)),
        );
        if !page.truncated {
            break;
        }
        let next = page.next_token.ok_or_else(|| {
            WorkerFailure::failed("S3 ListObjectsV2 omitted its continuation token", 0)
        })?;
        if token.as_deref() == Some(&next) {
            return Err(WorkerFailure::failed(
                "S3 ListObjectsV2 repeated its continuation token",
                0,
            ));
        }
        token = Some(next);
    }
    Ok(keys)
}

async fn get_object(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    bucket: &str,
    key: &str,
    scanned: u64,
) -> Result<Bytes, WorkerFailure> {
    let uri: Uri = format!(
        "/{}/{}",
        percent_encode(bucket, false),
        percent_encode(key, true)
    )
    .parse()
    .map_err(|_| WorkerFailure::failed("S3 object URI is invalid", scanned))?;
    let response = s3_request(
        registry,
        scope,
        caller,
        "s3:GetObject",
        format!("arn:aws:s3:::{bucket}/{key}"),
        Method::GET,
        uri,
        HeaderMap::new(),
        Bytes::new(),
    )
    .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(WorkerFailure::failed(
            format!("S3 GetObject for {key} failed with status {status}"),
            scanned,
        ));
    }
    let remaining = SCAN_LIMIT.saturating_sub(scanned);
    let limit = usize::try_from(remaining.saturating_add(1)).unwrap_or(usize::MAX);
    axum::body::to_bytes(response.into_body(), limit)
        .await
        .map_err(|_| WorkerFailure::failed("Query exceeded the 64 MiB scan limit", SCAN_LIMIT + 1))
}

async fn put_object(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    bucket: &str,
    key: &str,
    body: Bytes,
    scanned: u64,
) -> Result<(), WorkerFailure> {
    let uri: Uri = format!(
        "/{}/{}",
        percent_encode(bucket, false),
        percent_encode(key, true)
    )
    .parse()
    .map_err(|_| WorkerFailure::failed("S3 result URI is invalid", scanned))?;
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("text/csv"));
    let response = s3_request(
        registry,
        scope,
        caller,
        "s3:PutObject",
        format!("arn:aws:s3:::{bucket}/{key}"),
        Method::PUT,
        uri,
        headers,
        body,
    )
    .await?;
    if !response.status().is_success() {
        return Err(WorkerFailure::failed(
            format!(
                "S3 PutObject for the query result failed with status {}",
                response.status()
            ),
            scanned,
        ));
    }
    Ok(())
}

async fn delete_object(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    bucket: &str,
    key: &str,
    scanned: u64,
) -> Result<(), WorkerFailure> {
    let uri: Uri = format!(
        "/{}/{}",
        percent_encode(bucket, false),
        percent_encode(key, true)
    )
    .parse()
    .map_err(|_| WorkerFailure::failed("S3 result URI is invalid", scanned))?;
    let response = s3_request(
        registry,
        scope,
        caller,
        "s3:DeleteObject",
        format!("arn:aws:s3:::{bucket}/{key}"),
        Method::DELETE,
        uri,
        HeaderMap::new(),
        Bytes::new(),
    )
    .await?;
    if !response.status().is_success() {
        return Err(WorkerFailure::failed(
            format!(
                "S3 DeleteObject for the query result failed with status {}",
                response.status()
            ),
            scanned,
        ));
    }
    Ok(())
}

async fn glue_json_request<T: DeserializeOwned>(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    operation: &str,
    body: Value,
) -> Result<T, WorkerFailure> {
    let root = format!("arn:aws:glue:{}:{}:", scope.region(), scope.account_id());
    let database = body
        .get("DatabaseName")
        .or_else(|| body.get("Name"))
        .and_then(Value::as_str);
    let table = body
        .get("TableName")
        .or_else(|| body.get("Name"))
        .and_then(Value::as_str);
    require_iam(
        registry,
        scope,
        caller,
        &format!("glue:{operation}"),
        &format!("{root}catalog"),
        0,
    )?;
    match operation {
        "GetDatabase" => {
            let database = database
                .ok_or_else(|| WorkerFailure::failed("Glue database name is missing", 0))?;
            require_iam(
                registry,
                scope,
                caller,
                "glue:GetDatabase",
                &format!("{root}database/{database}"),
                0,
            )?;
        }
        "GetTable" | "GetPartitions" => {
            let database = database
                .ok_or_else(|| WorkerFailure::failed("Glue database name is missing", 0))?;
            let table =
                table.ok_or_else(|| WorkerFailure::failed("Glue table name is missing", 0))?;
            require_iam(
                registry,
                scope,
                caller,
                &format!("glue:{operation}"),
                &format!("{root}database/{database}"),
                0,
            )?;
            require_iam(
                registry,
                scope,
                caller,
                &format!("glue:{operation}"),
                &format!("{root}table/{database}/{table}"),
                0,
            )?;
        }
        _ => {}
    }
    let registry = registry
        .upgrade()
        .ok_or_else(|| WorkerFailure::failed("Service registry is unavailable", 0))?;
    let dispatcher = registry
        .internal_dispatcher()
        .ok_or_else(|| WorkerFailure::failed("Internal dispatcher is unavailable", 0))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-amz-json-1.1"),
    );
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("AWSGlue.{operation}"))
            .map_err(|_| WorkerFailure::failed("Glue operation target is invalid", 0))?,
    );
    headers.insert(
        "authorization",
        HeaderValue::from_static(
            "AWS4-HMAC-SHA256 Credential=locallycloud/19700101/us-east-1/glue/aws4_request",
        ),
    );
    let request_body = serde_json::to_vec(&body)
        .map(Bytes::from)
        .map_err(|_| WorkerFailure::failed("Failed to serialize Glue request", 0))?;
    let uri: Uri = "/"
        .parse()
        .map_err(|_| WorkerFailure::failed("Glue request URI is invalid", 0))?;
    let response = dispatcher
        .dispatch_scoped(
            &Method::POST,
            &uri,
            &headers,
            request_body,
            &Uuid::new_v4().to_string(),
            scope.account_id(),
            scope.region(),
        )
        .await;
    let status = response.status();
    let response_body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .map_err(|_| WorkerFailure::failed("Glue response exceeded the supported limit", 0))?;
    if !status.is_success() {
        return Err(WorkerFailure::failed(
            format!("Glue {operation} failed with status {status}"),
            0,
        ));
    }
    serde_json::from_slice(&response_body)
        .map_err(|_| WorkerFailure::failed(format!("Glue {operation} response is malformed"), 0))
}

#[allow(clippy::too_many_arguments)]
async fn s3_request(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&RequestIdentity>,
    action: &str,
    resource: String,
    method: Method,
    uri: Uri,
    mut headers: HeaderMap,
    body: Bytes,
) -> Result<Response, WorkerFailure> {
    require_iam(registry, scope, caller, action, &resource, 0)?;
    let registry = registry
        .upgrade()
        .ok_or_else(|| WorkerFailure::failed("Service registry is unavailable", 0))?;
    let dispatcher = registry
        .internal_dispatcher()
        .ok_or_else(|| WorkerFailure::failed("Internal dispatcher is unavailable", 0))?;
    headers.insert(
        "authorization",
        HeaderValue::from_static(
            "AWS4-HMAC-SHA256 Credential=locallycloud/19700101/us-east-1/s3/aws4_request",
        ),
    );
    let request_id = Uuid::new_v4().to_string();
    Ok(dispatcher
        .dispatch_scoped(
            &method,
            &uri,
            &headers,
            body,
            &request_id,
            scope.account_id(),
            scope.region(),
        )
        .await)
}

struct ListPage {
    keys: Vec<String>,
    truncated: bool,
    next_token: Option<String>,
}

fn parse_list_objects(body: &[u8]) -> Result<ListPage, WorkerFailure> {
    enum Field {
        Key,
        Truncated,
        NextToken,
    }

    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut field = None;
    let mut value = String::new();
    let mut keys = Vec::new();
    let mut truncated = false;
    let mut next_token = None;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) => {
                field = match element.local_name().as_ref() {
                    "Key" => Some(Field::Key),
                    "IsTruncated" => Some(Field::Truncated),
                    "NextContinuationToken" => Some(Field::NextToken),
                    _ => None,
                };
                if field.is_some() {
                    value.clear();
                }
            }
            Ok(Event::Text(text)) if field.is_some() => {
                value.push_str(
                    &quick_xml::escape::unescape(text.as_ref())
                        .map_err(|_| WorkerFailure::failed("S3 listing XML is malformed", 0))?,
                );
            }
            Ok(Event::End(element)) => {
                let closes = matches!(
                    (&field, element.local_name().as_ref()),
                    (Some(Field::Key), "Key")
                        | (Some(Field::Truncated), "IsTruncated")
                        | (Some(Field::NextToken), "NextContinuationToken")
                );
                if closes {
                    match field.take().expect("checked above") {
                        Field::Key => keys.push(value.clone()),
                        Field::Truncated => {
                            truncated = match value.as_str() {
                                "true" => true,
                                "false" => false,
                                _ => {
                                    return Err(WorkerFailure::failed(
                                        "S3 listing IsTruncated is invalid",
                                        0,
                                    ))
                                }
                            }
                        }
                        Field::NextToken => next_token = Some(value.clone()),
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(WorkerFailure::failed("S3 listing XML is malformed", 0)),
        }
        buffer.clear();
    }
    Ok(ListPage {
        keys,
        truncated,
        next_token,
    })
}

fn percent_encode(value: &str, preserve_slash: bool) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (preserve_slash && byte == b'/')
        {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use locallycloud_core::integration::InternalDispatcher;
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
    use locallycloud_core::registry::{ServiceMetadata, ServiceName};

    use super::*;
    use crate::glue::{GlueHandler, TARGET_PREFIX as GLUE_TARGET_PREFIX};
    use crate::state::AnalyticsState;

    const ACCOUNT_ID: &str = "000000000000";
    const REGION: &str = "us-east-1";

    #[test]
    fn missing_iam_evaluator_does_not_downgrade_authenticated_query() {
        let registry = ServiceRegistry::with_known_services();
        let scope = Scope::new(ACCOUNT_ID, REGION);
        let caller = RequestIdentity {
            account_id: ACCOUNT_ID.into(),
            access_key_id: Some("AKIATEST".into()),
            arn: None,
        };
        assert!(!iam_allows(
            &Arc::downgrade(&registry),
            &scope,
            Some(&caller),
            "s3:GetObject",
            "arn:aws:s3:::data/object"
        ));
        assert!(iam_allows(
            &Arc::downgrade(&registry),
            &scope,
            None,
            "s3:GetObject",
            "arn:aws:s3:::data/object"
        ));
    }

    struct GlueTraceEntry {
        operation: String,
        account_id: String,
        region: String,
        body: Value,
    }

    #[derive(Default)]
    struct GlueTrace {
        entries: Mutex<Vec<GlueTraceEntry>>,
    }

    struct TracedGlueHandler {
        inner: GlueHandler,
        trace: Arc<GlueTrace>,
    }

    #[async_trait]
    impl NativeHandler for TracedGlueHandler {
        async fn handle(&self, request: ServiceRequest) -> Response {
            let operation = request
                .headers
                .get("x-amz-target")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("AWSGlue."))
                .unwrap_or_default()
                .to_string();
            let body = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
            self.trace
                .entries
                .lock()
                .expect("Glue trace lock is available")
                .push(GlueTraceEntry {
                    operation,
                    account_id: request.account_id.clone(),
                    region: request.region.clone(),
                    body,
                });
            self.inner.handle(request).await
        }
    }

    fn analytics_registry() -> (Arc<ServiceRegistry>, Arc<GlueTrace>) {
        let registry = ServiceRegistry::with_known_services();
        let trace = Arc::new(GlueTrace::default());
        let handler: Arc<dyn NativeHandler> = Arc::new(TracedGlueHandler {
            inner: GlueHandler::new(Arc::new(AnalyticsState::new())),
            trace: Arc::clone(&trace),
        });
        registry.register_native(
            ServiceName::new("glue"),
            ServiceMetadata::new(AwsProtocol::Json11, Some(GLUE_TARGET_PREFIX)),
            handler,
        );
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(true),
            REGION.into(),
            ACCOUNT_ID.into(),
        )));
        (registry, trace)
    }

    async fn seed_glue_catalog(registry: &Arc<ServiceRegistry>, scope: &Scope) {
        let weak = Arc::downgrade(registry);
        let database: Result<Value, WorkerFailure> = glue_json_request(
            &weak,
            scope,
            None,
            "CreateDatabase",
            json!({
                "CatalogId": scope.account_id(),
                "DatabaseInput": { "Name": "analytics_db" }
            }),
        )
        .await;
        assert!(database.is_ok(), "public Glue CreateDatabase must succeed");

        let table: Result<Value, WorkerFailure> = glue_json_request(
            &weak,
            scope,
            None,
            "CreateTable",
            json!({
                "CatalogId": scope.account_id(),
                "DatabaseName": "analytics_db",
                "TableInput": {
                    "Name": "events",
                    "PartitionKeys": [],
                    "StorageDescriptor": {
                        "Location": "s3://analytics-data/events/",
                        "InputFormat": JSON_INPUT_FORMAT,
                        "SerdeInfo": { "SerializationLibrary": JSON_SERDE }
                    }
                }
            }),
        )
        .await;
        assert!(table.is_ok(), "public Glue CreateTable must succeed");
    }

    fn manifest_fixture(content: i32, added: i64, existing: i64, deleted: i64) -> Vec<u8> {
        use apache_avro::{Schema, Writer};
        let schema = Schema::parse_str(
            r#"{
            "type": "record", "name": "manifest_file", "fields": [
                {"name": "content", "type": "int"},
                {"name": "added_rows_count", "type": "long"},
                {"name": "existing_rows_count", "type": "long"},
                {"name": "deleted_rows_count", "type": "long"}
            ]
        }"#,
        )
        .expect("valid Avro fixture schema");
        let mut writer = Writer::new(&schema, Vec::new());
        writer
            .append(AvroValue::Record(vec![
                ("content".into(), AvroValue::Int(content)),
                ("added_rows_count".into(), AvroValue::Long(added)),
                ("existing_rows_count".into(), AvroValue::Long(existing)),
                ("deleted_rows_count".into(), AvroValue::Long(deleted)),
            ]))
            .expect("valid Avro fixture record");
        writer.into_inner().expect("valid Avro fixture output")
    }

    #[test]
    fn iceberg_manifest_counts_only_live_rows_and_rejects_deletes() {
        assert_eq!(
            count_manifest_list(&manifest_fixture(0, 3, 7, 11), 0).ok(),
            Some(10)
        );
        assert!(matches!(
            count_manifest_list(&manifest_fixture(1, 0, 0, 2), 0),
            Err(WorkerFailure::Failed { reason, .. }) if reason.contains("delete manifests")
        ));
        assert!(matches!(
            count_manifest_list(&manifest_fixture(-1, 0, 0, 0), 0),
            Err(WorkerFailure::Failed { reason, .. }) if reason.contains("content is invalid")
        ));
        assert!(matches!(
            count_manifest_list(&manifest_fixture(0, -1, 0, 0), 0),
            Err(WorkerFailure::Failed { reason, .. }) if reason.contains("negative")
        ));
        assert!(count_manifest_list(b"not-avro", 0).is_err());
    }

    #[test]
    fn iceberg_projection_reads_parquet_rows_and_rejects_unsupported_sql() {
        use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
        use parquet::file::properties::WriterProperties;
        use parquet::file::writer::SerializedFileWriter;
        use parquet::schema::parser::parse_message_type;

        let parsed = SqlParser::new("SELECT id, payload FROM analytics.events;")
            .parse()
            .unwrap();
        assert_eq!(parsed.database.as_deref(), Some("analytics"));
        assert_eq!(parsed.table, "events");
        assert!(
            matches!(parsed.projection, Projection::Columns(ref names) if names == &["id", "payload"])
        );
        assert!(SqlParser::new("SELECT id FROM events GROUP BY id")
            .parse()
            .is_err());

        let schema = Arc::new(
            parse_message_type(
                "message test { REQUIRED INT64 id; OPTIONAL BYTE_ARRAY payload (UTF8); }",
            )
            .unwrap(),
        );
        let props = Arc::new(WriterProperties::builder().build());
        let mut bytes = Vec::new();
        {
            let mut writer = SerializedFileWriter::new(&mut bytes, schema, props).unwrap();
            let mut group = writer.next_row_group().unwrap();
            let mut id = group.next_column().unwrap().unwrap();
            id.typed::<Int64Type>()
                .write_batch(&[1, 2], None, None)
                .unwrap();
            id.close().unwrap();
            let mut payload = group.next_column().unwrap().unwrap();
            payload
                .typed::<ByteArrayType>()
                .write_batch(&[ByteArray::from("first")], Some(&[1, 0]), None)
                .unwrap();
            payload.close().unwrap();
            group.close().unwrap();
            writer.close().unwrap();
        }
        let rows = parquet_rows(
            Bytes::from(bytes),
            &["id".into(), "payload".into()],
            &["bigint", "varchar"],
        )
        .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![Some("1".into()), Some("first".into())],
                vec![Some("2".into()), None]
            ]
        );
    }

    #[test]
    fn iceberg_result_pagination_preserves_null_cells() {
        let (registry, _) = analytics_registry();
        let handler = AthenaHandler::new(Arc::downgrade(&registry));
        let id = "page-query".to_string();
        handler.queries.insert(
            QueryKey {
                scope: Scope::new(ACCOUNT_ID, REGION),
                id: id.clone(),
            },
            Arc::new(Mutex::new(QueryRecord {
                id: id.clone(),
                spec: QuerySpec {
                    query_string: "SELECT id, payload FROM events".into(),
                    context: None,
                    result_configuration: ResultConfiguration {
                        output_location: "s3://analytics-data/results/".into(),
                    },
                    work_group: None,
                },
                effective_output_location: S3Location {
                    bucket: "analytics-data".into(),
                    key: "results/page-query.csv".into(),
                },
                state: QueryState::Succeeded,
                submission_time: 0.0,
                completion_time: Some(1.0),
                reason: None,
                scanned_bytes: 100,
                result: Some(QueryResult {
                    columns: vec![
                        ResultColumn {
                            name: "id".into(),
                            kind: "bigint",
                        },
                        ResultColumn {
                            name: "payload".into(),
                            kind: "varchar",
                        },
                    ],
                    rows: vec![
                        vec![Some("id".into()), Some("payload".into())],
                        vec![Some("1".into()), Some("first".into())],
                        vec![Some("2".into()), None],
                    ],
                }),
                result_token: "secret".into(),
                caller: None,
            })),
        );
        let request = ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            account_id: ACCOUNT_ID.into(),
            region: REGION.into(),
            request_id: "request".into(),
        };
        let first = handler
            .get_query_results(
                GetQueryResultsRequest {
                    query_execution_id: id.clone(),
                    max_results: Some(2),
                    next_token: None,
                },
                &request,
                None,
            )
            .unwrap();
        assert_eq!(first["ResultSet"]["Rows"].as_array().unwrap().len(), 2);
        let token = first["NextToken"].as_str().unwrap();
        let second = handler
            .get_query_results(
                GetQueryResultsRequest {
                    query_execution_id: id,
                    max_results: Some(2),
                    next_token: Some(token.into()),
                },
                &request,
                None,
            )
            .unwrap();
        assert_eq!(
            second["ResultSet"]["Rows"][0]["Data"],
            json!([{ "VarCharValue": "2" }, {}])
        );
        assert!(second.get("NextToken").is_none());
    }

    #[tokio::test]
    async fn iceberg_count_reads_current_snapshot_through_public_glue_and_s3() {
        let (registry, trace) = analytics_registry();
        locallycloud_s3::register(&registry);
        let scope = Scope::new(ACCOUNT_ID, REGION);
        let weak = Arc::downgrade(&registry);
        let create_bucket = s3_request(
            &weak,
            &scope,
            None,
            "s3:CreateBucket",
            "arn:aws:s3:::analytics-data".into(),
            Method::PUT,
            "/analytics-data".parse().unwrap(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("S3 CreateBucket dispatch");
        assert!(create_bucket.status().is_success());
        let metadata = json!({
            "format-version": 2,
            "current-snapshot-id": 77,
            "snapshots": [{
                "snapshot-id": 77,
                "manifest-list": "s3://analytics-data/iceberg/metadata/snap-77.avro"
            }]
        });
        put_object(
            &weak,
            &scope,
            None,
            "analytics-data",
            "iceberg/metadata/v1.metadata.json",
            Bytes::from(serde_json::to_vec(&metadata).unwrap()),
            0,
        )
        .await
        .unwrap_or_else(|_| panic!("S3 metadata put must succeed"));
        put_object(
            &weak,
            &scope,
            None,
            "analytics-data",
            "iceberg/metadata/snap-77.avro",
            Bytes::from(manifest_fixture(0, 3, 2, 4)),
            0,
        )
        .await
        .unwrap_or_else(|_| panic!("S3 manifest put must succeed"));
        seed_glue_catalog(&registry, &scope).await;
        let table: Result<Value, WorkerFailure> = glue_json_request(
            &weak,
            &scope,
            None,
            "CreateTable",
            json!({
                "DatabaseName": "analytics_db",
                "TableInput": {
                    "Name": "iceberg_events",
                    "Parameters": {
                        "table_type": "ICEBERG",
                        "metadata_location": "s3://analytics-data/iceberg/metadata/v1.metadata.json"
                    },
                    "StorageDescriptor": {"Location": "s3://analytics-data/iceberg/"}
                }
            }),
        )
        .await;
        assert!(
            table.is_ok(),
            "public Glue Iceberg CreateTable must succeed"
        );
        let record = Arc::new(Mutex::new(QueryRecord {
            id: "query-iceberg".into(),
            spec: QuerySpec {
                query_string: "SELECT COUNT(*) AS n FROM iceberg_events".into(),
                context: Some(QueryExecutionContext {
                    database: Some("analytics_db".into()),
                    catalog: None,
                }),
                result_configuration: ResultConfiguration {
                    output_location: "s3://analytics-data/results/".into(),
                },
                work_group: None,
            },
            effective_output_location: S3Location {
                bucket: "analytics-data".into(),
                key: "results/query-iceberg.csv".into(),
            },
            state: QueryState::Running,
            submission_time: 0.0,
            completion_time: None,
            reason: None,
            scanned_bytes: 0,
            result: None,
            result_token: "token".into(),
            caller: None,
        }));
        let (spec, output) = {
            let query = record.lock().unwrap();
            (query.spec.clone(), query.effective_output_location.clone())
        };
        execute_query(&weak, &scope, None, &record, &spec, &output)
            .await
            .unwrap_or_else(|_| panic!("Iceberg COUNT must succeed"));
        let result = get_object(
            &weak,
            &scope,
            None,
            "analytics-data",
            "results/query-iceberg.csv",
            0,
        )
        .await
        .expect("public S3 result");
        assert_eq!(&result[..], b"n\n5\n");
        assert_eq!(record.lock().unwrap().state, QueryState::Succeeded);
        let ops = trace
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|entry| entry.operation.clone())
            .collect::<Vec<_>>();
        assert!(ops.ends_with(&["GetDatabase".into(), "GetTable".into()]));
    }

    #[tokio::test]
    async fn glue_snapshot_uses_public_operations_and_preserves_scope() {
        let (registry, trace) = analytics_registry();
        let scope = Scope::new(ACCOUNT_ID, REGION);
        seed_glue_catalog(&registry, &scope).await;
        trace
            .entries
            .lock()
            .expect("Glue trace lock is available")
            .clear();

        let snapshot = glue_table_snapshot(
            &Arc::downgrade(&registry),
            &scope,
            None,
            "analytics_db",
            "events",
        )
        .await;
        let snapshot = match snapshot {
            Ok(snapshot) => snapshot,
            Err(_) => panic!("same-scope Glue metadata must be visible to Athena"),
        };
        let location = match table_location(&snapshot) {
            Ok(location) => location,
            Err(_) => panic!("public Glue metadata must contain a valid table location"),
        };
        assert_eq!(location.uri(), "s3://analytics-data/events/");

        {
            let entries = trace.entries.lock().expect("Glue trace lock is available");
            assert_eq!(
                entries
                    .iter()
                    .map(|entry| entry.operation.as_str())
                    .collect::<Vec<_>>(),
                ["GetDatabase", "GetTable", "GetPartitions"]
            );
            assert!(entries.iter().all(|entry| {
                entry.account_id == ACCOUNT_ID
                    && entry.region == REGION
                    && entry.body["CatalogId"] == ACCOUNT_ID
            }));
            assert_eq!(entries[2].body["MaxResults"], 1000);
        }

        trace
            .entries
            .lock()
            .expect("Glue trace lock is available")
            .clear();
        let other_region = Scope::new(ACCOUNT_ID, "eu-west-1");
        assert!(
            glue_table_snapshot(
                &Arc::downgrade(&registry),
                &other_region,
                None,
                "analytics_db",
                "events",
            )
            .await
            .is_err(),
            "Glue metadata must be isolated by region"
        );
        let entries = trace.entries.lock().expect("Glue trace lock is available");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].operation, "GetDatabase");
        assert_eq!(entries[0].account_id, ACCOUNT_ID);
        assert_eq!(entries[0].region, "eu-west-1");
    }
}
