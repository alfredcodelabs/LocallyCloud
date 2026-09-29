use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use uuid::Uuid;

use crate::error::LogsError;
use crate::groups::validate_group_name;
use crate::model::ScopeKey;
use crate::protocol::{
    DescribeQueriesRequest, DescribeQueriesResponse, GetQueryResultsRequest,
    GetQueryResultsResponse, QueryInfo, QueryStatistics, ResultField, StartQueryRequest,
    StartQueryResponse, StopQueryRequest, StopQueryResponse,
};
use crate::store::{LogsStore, NewQuery};

const MAX_QUERY_CHARS: usize = 10_000;
const MAX_QUERY_RESULTS: u32 = 100_000;
const DEFAULT_QUERY_RESULTS: u32 = 10_000;
const MAX_PAGE_ITEMS: u32 = 10_000;
const DEFAULT_DESCRIBE_ITEMS: u16 = 50;
const MAX_DESCRIBE_ITEMS: u16 = 100;
const MAX_SOURCE_GROUPS: usize = 50;
const RESULT_TOKEN_TTL_MS: i64 = 60 * 60 * 1_000;
const DESCRIBE_TOKEN_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
const MAX_TOKEN_BYTES: usize = 64 * 1_024;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueryStatus {
    Scheduled,
    Running,
    Complete,
    Failed,
    Cancelled,
    Timeout,
}

impl QueryStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "Scheduled",
            Self::Running => "Running",
            Self::Complete => "Complete",
            Self::Failed => "Failed",
            Self::Cancelled => "Cancelled",
            Self::Timeout => "Timeout",
        }
    }

    fn parse(value: &str) -> Result<Self, LogsError> {
        match value {
            "Scheduled" => Ok(Self::Scheduled),
            "Running" => Ok(Self::Running),
            "Complete" => Ok(Self::Complete),
            "Failed" => Ok(Self::Failed),
            "Cancelled" => Ok(Self::Cancelled),
            "Timeout" => Ok(Self::Timeout),
            _ => Err(LogsError::InvalidParameter("status is invalid".into())),
        }
    }

    pub(crate) fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Failed | Self::Cancelled | Self::Timeout
        )
    }
}

#[derive(Clone)]
pub(crate) struct QuerySnapshotEvent {
    pub group_name: String,
    pub stream_name: String,
    pub timestamp_ms: i64,
    pub put_ordinal: u64,
    pub event_ordinal: u32,
    pub message: String,
}

#[derive(Clone)]
pub(crate) struct InsightsQuery {
    pub id: String,
    pub scope: ScopeKey,
    pub group_names: Vec<String>,
    pub query_string: String,
    pub plan: QueryPlan,
    pub status: QueryStatus,
    pub creation_time_ms: i64,
    pub duration_ms: i64,
    pub result_limit: usize,
    pub snapshot: Vec<QuerySnapshotEvent>,
    pub rows: Vec<Vec<ResultField>>,
    pub statistics: QueryStatistics,
    pub revision: u64,
}

impl InsightsQuery {
    fn info(&self) -> QueryInfo {
        QueryInfo {
            query_language: "CWLI",
            query_id: self.id.clone(),
            query_string: self.query_string.clone(),
            status: self.status.as_str().into(),
            create_time: self.creation_time_ms,
            log_group_name: (self.group_names.len() == 1).then(|| self.group_names[0].clone()),
            query_duration: self.duration_ms,
            bytes_scanned: self.statistics.bytes_scanned,
        }
    }
}

#[derive(Clone)]
pub(crate) struct QueryPlan {
    commands: Vec<Command>,
}

#[derive(Clone)]
enum Command {
    Fields(Vec<String>),
    Display(Vec<String>),
    Filter(Expr),
    Sort {
        field: String,
        descending: bool,
    },
    Limit(usize),
    Stats {
        alias: String,
        group_fields: Vec<String>,
    },
}

#[derive(Clone)]
enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Compare(String, CompareOp, Scalar),
}

#[derive(Clone, Copy)]
enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone)]
enum Scalar {
    String(String),
    Number(f64),
    Bool(bool),
    Null,
}

#[derive(Clone)]
struct WorkingRow {
    fields: BTreeMap<String, Scalar>,
    projection: Option<Vec<String>>,
    order_key: (i64, u64, u32),
}

pub struct InsightsPaginator {
    secret: [u8; 32],
}

impl Default for InsightsPaginator {
    fn default() -> Self {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut secret = [0_u8; 32];
        secret[..16].copy_from_slice(first.as_bytes());
        secret[16..].copy_from_slice(second.as_bytes());
        Self { secret }
    }
}

pub fn start(
    store: &LogsStore,
    request: StartQueryRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<StartQueryResponse, LogsError> {
    if request.query_language.as_deref().unwrap_or("CWLI") != "CWLI" {
        return Err(LogsError::InvalidParameter(
            "only the CWLI query language is supported".into(),
        ));
    }
    if request.start_time < 0 || request.end_time < 0 || request.start_time > request.end_time {
        return Err(LogsError::InvalidParameter(
            "startTime and endTime must define a non-negative inclusive range".into(),
        ));
    }
    let start_ms = request.start_time.checked_mul(1_000).ok_or_else(|| {
        LogsError::InvalidParameter("startTime is outside the supported range".into())
    })?;
    let end_ms = request
        .end_time
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(999))
        .ok_or_else(|| {
            LogsError::InvalidParameter("endTime is outside the supported range".into())
        })?;
    let source_count = usize::from(request.log_group_name.is_some())
        + usize::from(request.log_group_names.is_some())
        + usize::from(request.log_group_identifiers.is_some());
    if source_count != 1 {
        return Err(LogsError::InvalidParameter(
            "exactly one log group source member is required".into(),
        ));
    }
    let mut group_names = if let Some(name) = request.log_group_name {
        vec![name]
    } else if let Some(names) = request.log_group_names {
        names
    } else {
        request
            .log_group_identifiers
            .expect("one source member was validated")
            .into_iter()
            .map(|identifier| resolve_group_identifier(&identifier, &scope))
            .collect::<Result<Vec<_>, _>>()?
    };
    if group_names.is_empty() || group_names.len() > MAX_SOURCE_GROUPS {
        return Err(LogsError::InvalidParameter(
            "between 1 and 50 log groups are required".into(),
        ));
    }
    let mut unique = BTreeSet::new();
    for name in &group_names {
        validate_group_name(name)?;
        if !unique.insert(name.clone()) {
            return Err(LogsError::InvalidParameter(
                "log group sources must be unique".into(),
            ));
        }
    }
    group_names.sort();
    let result_limit = request.limit.unwrap_or(DEFAULT_QUERY_RESULTS);
    if !(1..=MAX_QUERY_RESULTS).contains(&result_limit) {
        return Err(LogsError::InvalidParameter(
            "limit must be between 1 and 100000".into(),
        ));
    }
    let plan = compile_query(&request.query_string)?;
    let query_id = store.start_query(NewQuery {
        scope,
        group_names,
        query_string: request.query_string,
        plan,
        start_ms,
        end_ms,
        result_limit: result_limit as usize,
        now_ms,
    })?;
    Ok(StartQueryResponse { query_id })
}

pub fn get(
    store: &LogsStore,
    paginator: &InsightsPaginator,
    request: GetQueryResultsRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<GetQueryResultsResponse, LogsError> {
    validate_query_id(&request.query_id)?;
    let max_items = request.max_items.unwrap_or(MAX_PAGE_ITEMS);
    if !(1..=MAX_PAGE_ITEMS).contains(&max_items) {
        return Err(LogsError::InvalidParameter(
            "maxItems must be between 1 and 10000".into(),
        ));
    }
    let query = store.get_query(&scope, &request.query_id)?;
    let position = request
        .next_token
        .as_deref()
        .map(|token| {
            paginator.decode_result_token(
                token,
                &scope,
                &query.id,
                query.revision,
                max_items,
                now_ms,
            )
        })
        .transpose()?
        .unwrap_or(0);
    if !query.status.is_terminal() && position != 0 {
        return Err(LogsError::InvalidParameter("nextToken is invalid".into()));
    }
    if position > query.rows.len() {
        return Err(LogsError::InvalidParameter("nextToken is invalid".into()));
    }
    let end = position
        .saturating_add(max_items as usize)
        .min(query.rows.len());
    let results = if query.status == QueryStatus::Complete {
        query.rows[position..end].to_vec()
    } else {
        Vec::new()
    };
    let next_token = (query.status == QueryStatus::Complete && end < query.rows.len())
        .then(|| {
            paginator.encode_result_token(&scope, &query.id, query.revision, end, max_items, now_ms)
        })
        .transpose()?;
    Ok(GetQueryResultsResponse {
        query_language: "CWLI",
        results,
        statistics: query.statistics,
        status: query.status.as_str().into(),
        next_token,
    })
}

pub fn stop(
    store: &LogsStore,
    request: StopQueryRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<StopQueryResponse, LogsError> {
    validate_query_id(&request.query_id)?;
    Ok(StopQueryResponse {
        success: store.cancel_query(&scope, &request.query_id, now_ms)?,
    })
}

pub fn describe(
    store: &LogsStore,
    paginator: &InsightsPaginator,
    request: DescribeQueriesRequest,
    scope: ScopeKey,
    now_ms: i64,
) -> Result<DescribeQueriesResponse, LogsError> {
    if request.query_language.as_deref().unwrap_or("CWLI") != "CWLI" {
        return Err(LogsError::InvalidParameter(
            "only the CWLI query language is supported".into(),
        ));
    }
    if let Some(name) = request.log_group_name.as_deref() {
        validate_group_name(name)?;
    }
    let status = request
        .status
        .as_deref()
        .map(QueryStatus::parse)
        .transpose()?;
    let max_results = request.max_results.unwrap_or(DEFAULT_DESCRIBE_ITEMS);
    if !(1..=MAX_DESCRIBE_ITEMS).contains(&max_results) {
        return Err(LogsError::InvalidParameter(
            "maxResults must be between 1 and 100".into(),
        ));
    }
    let binding = DescribeBinding::new_scope(
        scope.clone(),
        request.log_group_name.clone(),
        request.status.clone(),
        max_results,
    );
    let all_queries = store.describe_queries(&scope)?;
    let by_id: HashMap<_, _> = all_queries
        .iter()
        .map(|query| (query.id.clone(), query))
        .collect();
    let (ids, start) = if let Some(token) = request.next_token.as_deref() {
        paginator.decode_describe_token(token, &binding, now_ms)?
    } else {
        let mut queries: Vec<_> = all_queries
            .iter()
            .filter(|query| {
                request.log_group_name.as_ref().is_none_or(|name| {
                    query
                        .group_names
                        .iter()
                        .any(|group_name| group_name == name)
                }) && status.is_none_or(|status| query.status == status)
            })
            .collect();
        queries.sort_by(|left, right| {
            right
                .creation_time_ms
                .cmp(&left.creation_time_ms)
                .then_with(|| right.id.cmp(&left.id))
        });
        (
            queries.into_iter().map(|query| query.id.clone()).collect(),
            0,
        )
    };
    if start > ids.len() {
        return Err(LogsError::InvalidParameter("nextToken is invalid".into()));
    }
    let end = start.saturating_add(max_results as usize).min(ids.len());
    let queries = ids[start..end]
        .iter()
        .map(|id| {
            by_id
                .get(id)
                .ok_or_else(|| LogsError::InvalidParameter("nextToken is invalid".into()))
                .map(|query| query.info())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let next_token = (end < ids.len())
        .then(|| paginator.encode_describe_token(&binding, ids, end, now_ms))
        .transpose()?;
    Ok(DescribeQueriesResponse {
        queries,
        next_token,
    })
}

pub(crate) async fn execute_query(
    store: &LogsStore,
    query: &InsightsQuery,
) -> Option<(Vec<Vec<ResultField>>, QueryStatistics)> {
    let mut rows = Vec::with_capacity(query.snapshot.len());
    for (index, event) in query.snapshot.iter().enumerate() {
        if index % 128 == 0 {
            if !store.query_is_running(&query.scope, &query.id).ok()? {
                return None;
            }
            tokio::task::yield_now().await;
        }
        rows.push(event_row(event));
    }
    for command in &query.plan.commands {
        match command {
            Command::Fields(fields) | Command::Display(fields) => {
                for row in &mut rows {
                    row.projection = Some(fields.clone());
                }
            }
            Command::Filter(expression) => {
                rows.retain(|row| expression.matches(&row.fields));
            }
            Command::Sort { field, descending } => {
                rows.sort_by(|left, right| {
                    let ordering =
                        compare_optional(left.fields.get(field), right.fields.get(field))
                            .then_with(|| left.order_key.cmp(&right.order_key));
                    if *descending {
                        ordering.reverse()
                    } else {
                        ordering
                    }
                });
            }
            Command::Limit(limit) => rows.truncate(*limit),
            Command::Stats {
                alias,
                group_fields,
            } => {
                rows = aggregate(rows, alias, group_fields);
            }
        }
        if !store.query_is_running(&query.scope, &query.id).ok()? {
            return None;
        }
    }
    rows.truncate(query.result_limit);
    let records_matched = rows.len() as f64;
    let results = rows.into_iter().map(output_row).collect();
    Some((
        results,
        QueryStatistics {
            records_matched,
            records_scanned: query.snapshot.len() as f64,
            bytes_scanned: query
                .snapshot
                .iter()
                .map(|event| event.message.len() as f64)
                .sum(),
            log_groups_scanned: query.group_names.len() as f64,
        },
    ))
}

fn compile_query(query: &str) -> Result<QueryPlan, LogsError> {
    if query.is_empty() || query.chars().count() > MAX_QUERY_CHARS {
        return Err(malformed("queryString is outside supported limits"));
    }
    if query.to_ascii_lowercase().contains("source ") {
        return Err(malformed("SOURCE is not supported"));
    }
    let mut commands = Vec::new();
    for segment in query.split('|') {
        let segment = segment.trim();
        if segment.is_empty() {
            return Err(malformed("query pipeline contains an empty command"));
        }
        let (name, rest) = segment
            .split_once(char::is_whitespace)
            .map(|(name, rest)| (name.to_ascii_lowercase(), rest.trim()))
            .unwrap_or_else(|| (segment.to_ascii_lowercase(), ""));
        let command = match name.as_str() {
            "fields" => Command::Fields(parse_field_list(rest)?),
            "display" => Command::Display(parse_field_list(rest)?),
            "filter" => Command::Filter(FilterParser::new(rest)?.parse()?),
            "sort" => parse_sort(rest)?,
            "limit" => Command::Limit(parse_limit(rest)?),
            "stats" => parse_stats(rest)?,
            _ => return Err(malformed("query command is not supported")),
        };
        commands.push(command);
    }
    if commands.is_empty() {
        return Err(malformed("queryString must contain a command"));
    }
    Ok(QueryPlan { commands })
}

fn parse_field_list(source: &str) -> Result<Vec<String>, LogsError> {
    let fields: Vec<_> = source
        .split(',')
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .map(str::to_owned)
        .collect();
    if fields.is_empty() || fields.len() > 100 || fields.iter().any(|field| !valid_field(field)) {
        return Err(malformed("field list is invalid"));
    }
    Ok(fields)
}

fn parse_sort(source: &str) -> Result<Command, LogsError> {
    let parts: Vec<_> = source.split_whitespace().collect();
    if parts.is_empty() || parts.len() > 2 || !valid_field(parts[0]) {
        return Err(malformed("sort command is invalid"));
    }
    let descending = match parts.get(1).copied().unwrap_or("asc") {
        value if value.eq_ignore_ascii_case("asc") => false,
        value if value.eq_ignore_ascii_case("desc") => true,
        _ => return Err(malformed("sort direction is invalid")),
    };
    Ok(Command::Sort {
        field: parts[0].into(),
        descending,
    })
}

fn parse_limit(source: &str) -> Result<usize, LogsError> {
    let value = source
        .parse::<u32>()
        .map_err(|_| malformed("limit command is invalid"))?;
    if !(1..=MAX_QUERY_RESULTS).contains(&value) {
        return Err(malformed("limit command is outside supported limits"));
    }
    Ok(value as usize)
}

fn parse_stats(source: &str) -> Result<Command, LogsError> {
    let lower = source.to_ascii_lowercase();
    if !lower.starts_with("count()") {
        return Err(malformed("only stats count() is supported"));
    }
    let mut rest = source[7..].trim();
    let mut alias = "count".to_owned();
    if rest.to_ascii_lowercase().starts_with("as ") {
        let after_as = rest[3..].trim();
        let split = after_as.find(char::is_whitespace).unwrap_or(after_as.len());
        alias = after_as[..split].to_owned();
        rest = after_as[split..].trim();
    }
    if !valid_field(&alias) {
        return Err(malformed("stats alias is invalid"));
    }
    let group_fields = if rest.is_empty() {
        Vec::new()
    } else if rest.to_ascii_lowercase().starts_with("by ") {
        parse_field_list(rest[3..].trim())?
    } else {
        return Err(malformed("stats command is invalid"));
    };
    Ok(Command::Stats {
        alias,
        group_fields,
    })
}

fn valid_field(field: &str) -> bool {
    !field.is_empty()
        && field.len() <= 256
        && field
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'_' | b'.' | b'-'))
}

fn event_row(event: &QuerySnapshotEvent) -> WorkingRow {
    let mut fields = BTreeMap::new();
    fields.insert(
        "@timestamp".into(),
        Scalar::Number(event.timestamp_ms as f64),
    );
    fields.insert("@message".into(), Scalar::String(event.message.clone()));
    fields.insert(
        "@logStream".into(),
        Scalar::String(event.stream_name.clone()),
    );
    fields.insert("@log".into(), Scalar::String(event.group_name.clone()));
    if let Ok(Value::Object(object)) = serde_json::from_str::<Value>(&event.message) {
        for (name, value) in object {
            if !name.starts_with('@') {
                if let Some(value) = json_scalar(value) {
                    fields.insert(name, value);
                }
            }
        }
    }
    WorkingRow {
        fields,
        projection: None,
        order_key: (event.timestamp_ms, event.put_ordinal, event.event_ordinal),
    }
}

fn json_scalar(value: Value) -> Option<Scalar> {
    match value {
        Value::String(value) => Some(Scalar::String(value)),
        Value::Number(value) => value.as_f64().map(Scalar::Number),
        Value::Bool(value) => Some(Scalar::Bool(value)),
        Value::Null => Some(Scalar::Null),
        _ => None,
    }
}

fn aggregate(rows: Vec<WorkingRow>, alias: &str, group_fields: &[String]) -> Vec<WorkingRow> {
    let mut groups: BTreeMap<Vec<String>, (usize, Vec<Option<Scalar>>)> = BTreeMap::new();
    for row in rows {
        let values: Vec<_> = group_fields
            .iter()
            .map(|field| row.fields.get(field).cloned())
            .collect();
        let key = values
            .iter()
            .map(|value| value.as_ref().map(Scalar::text).unwrap_or_default())
            .collect();
        let entry = groups.entry(key).or_insert((0, values));
        entry.0 += 1;
    }
    groups
        .into_values()
        .enumerate()
        .map(|(ordinal, (count, values))| {
            let mut fields = BTreeMap::new();
            for (name, value) in group_fields.iter().zip(values) {
                if let Some(value) = value {
                    fields.insert(name.clone(), value);
                }
            }
            fields.insert(alias.to_owned(), Scalar::Number(count as f64));
            let mut projection = group_fields.to_vec();
            projection.push(alias.to_owned());
            WorkingRow {
                fields,
                projection: Some(projection),
                order_key: (0, ordinal as u64, 0),
            }
        })
        .collect()
}

fn output_row(row: WorkingRow) -> Vec<ResultField> {
    let names = row
        .projection
        .unwrap_or_else(|| row.fields.keys().cloned().collect());
    names
        .into_iter()
        .filter_map(|field| {
            row.fields.get(&field).map(|value| ResultField {
                field,
                value: value.text(),
            })
        })
        .collect()
}

impl Scalar {
    fn text(&self) -> String {
        match self {
            Self::String(value) => value.clone(),
            Self::Number(value) if value.fract() == 0.0 => format!("{value:.0}"),
            Self::Number(value) => value.to_string(),
            Self::Bool(value) => value.to_string(),
            Self::Null => "null".into(),
        }
    }

    fn compare(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::String(left), Self::String(right)) => Some(left.cmp(right)),
            (Self::Number(left), Self::Number(right)) => left.partial_cmp(right),
            (Self::Bool(left), Self::Bool(right)) => Some(left.cmp(right)),
            (Self::Null, Self::Null) => Some(Ordering::Equal),
            _ => None,
        }
    }
}

impl Expr {
    fn matches(&self, fields: &BTreeMap<String, Scalar>) -> bool {
        match self {
            Self::And(left, right) => left.matches(fields) && right.matches(fields),
            Self::Or(left, right) => left.matches(fields) || right.matches(fields),
            Self::Compare(field, operator, expected) => fields
                .get(field)
                .and_then(|actual| actual.compare(expected))
                .is_some_and(|ordering| match operator {
                    CompareOp::Eq => ordering == Ordering::Equal,
                    CompareOp::Ne => ordering != Ordering::Equal,
                    CompareOp::Lt => ordering == Ordering::Less,
                    CompareOp::Le => ordering != Ordering::Greater,
                    CompareOp::Gt => ordering == Ordering::Greater,
                    CompareOp::Ge => ordering != Ordering::Less,
                }),
        }
    }
}

fn compare_optional(left: Option<&Scalar>, right: Option<&Scalar>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left
            .compare(right)
            .unwrap_or_else(|| left.text().cmp(&right.text())),
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => Ordering::Equal,
    }
}

#[derive(Clone)]
enum FilterToken {
    Field(String),
    Literal(Scalar),
    Operator(CompareOp),
    And,
    Or,
    LeftParen,
    RightParen,
}

struct FilterParser {
    tokens: Vec<FilterToken>,
    position: usize,
}

impl FilterParser {
    fn new(source: &str) -> Result<Self, LogsError> {
        Ok(Self {
            tokens: lex_filter(source)?,
            position: 0,
        })
    }

    fn parse(mut self) -> Result<Expr, LogsError> {
        let expression = self.parse_or()?;
        if self.position != self.tokens.len() {
            return Err(malformed("filter expression is invalid"));
        }
        Ok(expression)
    }

    fn parse_or(&mut self) -> Result<Expr, LogsError> {
        let mut expression = self.parse_and()?;
        while matches!(self.tokens.get(self.position), Some(FilterToken::Or)) {
            self.position += 1;
            expression = Expr::Or(Box::new(expression), Box::new(self.parse_and()?));
        }
        Ok(expression)
    }

    fn parse_and(&mut self) -> Result<Expr, LogsError> {
        let mut expression = self.parse_primary()?;
        while matches!(self.tokens.get(self.position), Some(FilterToken::And)) {
            self.position += 1;
            expression = Expr::And(Box::new(expression), Box::new(self.parse_primary()?));
        }
        Ok(expression)
    }

    fn parse_primary(&mut self) -> Result<Expr, LogsError> {
        if matches!(self.tokens.get(self.position), Some(FilterToken::LeftParen)) {
            self.position += 1;
            let expression = self.parse_or()?;
            if !matches!(
                self.tokens.get(self.position),
                Some(FilterToken::RightParen)
            ) {
                return Err(malformed("filter parentheses are unbalanced"));
            }
            self.position += 1;
            return Ok(expression);
        }
        let Some(FilterToken::Field(field)) = self.tokens.get(self.position).cloned() else {
            return Err(malformed("filter field is missing"));
        };
        self.position += 1;
        let Some(FilterToken::Operator(operator)) = self.tokens.get(self.position).cloned() else {
            return Err(malformed("filter operator is missing"));
        };
        self.position += 1;
        let Some(FilterToken::Literal(value)) = self.tokens.get(self.position).cloned() else {
            return Err(malformed("filter value is missing"));
        };
        self.position += 1;
        Ok(Expr::Compare(field, operator, value))
    }
}

fn lex_filter(source: &str) -> Result<Vec<FilterToken>, LogsError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if tokens.len() >= 256 {
            return Err(malformed("filter expression is too complex"));
        }
        match bytes[index] {
            b'(' => {
                tokens.push(FilterToken::LeftParen);
                index += 1;
            }
            b')' => {
                tokens.push(FilterToken::RightParen);
                index += 1;
            }
            b'=' => {
                tokens.push(FilterToken::Operator(CompareOp::Eq));
                index += 1;
            }
            b'!' if bytes.get(index + 1) == Some(&b'=') => {
                tokens.push(FilterToken::Operator(CompareOp::Ne));
                index += 2;
            }
            b'<' => {
                let inclusive = bytes.get(index + 1) == Some(&b'=');
                tokens.push(FilterToken::Operator(if inclusive {
                    CompareOp::Le
                } else {
                    CompareOp::Lt
                }));
                index += 1 + usize::from(inclusive);
            }
            b'>' => {
                let inclusive = bytes.get(index + 1) == Some(&b'=');
                tokens.push(FilterToken::Operator(if inclusive {
                    CompareOp::Ge
                } else {
                    CompareOp::Gt
                }));
                index += 1 + usize::from(inclusive);
            }
            b'"' | b'\'' => {
                let quote = bytes[index];
                let start = index + 1;
                index += 1;
                while index < bytes.len() && bytes[index] != quote {
                    if bytes[index] == b'\\' {
                        index += 1;
                    }
                    index += 1;
                }
                if index >= bytes.len() {
                    return Err(malformed("filter string is unterminated"));
                }
                let raw = &source[start..index];
                let value = if quote == b'"' {
                    serde_json::from_str::<String>(&source[start - 1..=index])
                        .map_err(|_| malformed("filter string is invalid"))?
                } else {
                    raw.replace("\\'", "'")
                };
                tokens.push(FilterToken::Literal(Scalar::String(value)));
                index += 1;
            }
            _ => {
                let start = index;
                while index < bytes.len()
                    && !bytes[index].is_ascii_whitespace()
                    && !matches!(bytes[index], b'(' | b')' | b'=' | b'!' | b'<' | b'>')
                {
                    index += 1;
                }
                if start == index {
                    return Err(malformed("filter expression is invalid"));
                }
                let word = &source[start..index];
                let lower = word.to_ascii_lowercase();
                let token = match lower.as_str() {
                    "and" => FilterToken::And,
                    "or" => FilterToken::Or,
                    "true" => FilterToken::Literal(Scalar::Bool(true)),
                    "false" => FilterToken::Literal(Scalar::Bool(false)),
                    "null" => FilterToken::Literal(Scalar::Null),
                    _ => match word.parse::<f64>() {
                        Ok(value) if value.is_finite() => {
                            FilterToken::Literal(Scalar::Number(value))
                        }
                        _ if valid_field(word) => FilterToken::Field(word.into()),
                        _ => return Err(malformed("filter token is invalid")),
                    },
                };
                tokens.push(token);
            }
        }
    }
    if tokens.is_empty() {
        return Err(malformed("filter expression is empty"));
    }
    Ok(tokens)
}

fn resolve_group_identifier(identifier: &str, scope: &ScopeKey) -> Result<String, LogsError> {
    if !identifier.starts_with("arn:") {
        return Ok(identifier.to_owned());
    }
    let prefix = format!(
        "arn:aws:logs:{}:{}:log-group:",
        scope.region, scope.account_id
    );
    identifier
        .strip_prefix(&prefix)
        .filter(|name| !name.is_empty() && !name.ends_with(":*"))
        .map(str::to_owned)
        .ok_or_else(|| {
            LogsError::InvalidParameter(
                "logGroupIdentifiers must be names or same-scope log group ARNs".into(),
            )
        })
}

fn validate_query_id(query_id: &str) -> Result<(), LogsError> {
    if (1..=128).contains(&query_id.len())
        && query_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Ok(())
    } else {
        Err(LogsError::InvalidParameter("queryId is invalid".into()))
    }
}

fn malformed(message: &str) -> LogsError {
    LogsError::MalformedQuery(message.into())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DescribeBinding {
    scope: ScopeKeyToken,
    group_name: Option<String>,
    status: Option<String>,
    max_results: u16,
}

impl From<ScopeKey> for ScopeKeyToken {
    fn from(scope: ScopeKey) -> Self {
        Self {
            account_id: scope.account_id,
            region: scope.region,
        }
    }
}

impl DescribeBinding {
    fn new_scope(
        scope: ScopeKey,
        group_name: Option<String>,
        status: Option<String>,
        max_results: u16,
    ) -> Self {
        Self {
            scope: scope.into(),
            group_name,
            status,
            max_results,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ScopeKeyToken {
    account_id: String,
    region: String,
}

#[derive(Serialize, Deserialize)]
struct ResultToken {
    version: u8,
    scope: ScopeKeyToken,
    query_id: String,
    revision: u64,
    position: usize,
    max_items: u32,
    expires_at_ms: i64,
}

#[derive(Serialize, Deserialize)]
struct DescribeToken {
    version: u8,
    binding: DescribeBinding,
    query_ids: Vec<String>,
    position: usize,
    expires_at_ms: i64,
}

impl InsightsPaginator {
    fn encode_result_token(
        &self,
        scope: &ScopeKey,
        query_id: &str,
        revision: u64,
        position: usize,
        max_items: u32,
        now_ms: i64,
    ) -> Result<String, LogsError> {
        self.encode(&ResultToken {
            version: 1,
            scope: ScopeKeyToken {
                account_id: scope.account_id.clone(),
                region: scope.region.clone(),
            },
            query_id: query_id.into(),
            revision,
            position,
            max_items,
            expires_at_ms: now_ms.saturating_add(RESULT_TOKEN_TTL_MS),
        })
    }

    fn decode_result_token(
        &self,
        token: &str,
        scope: &ScopeKey,
        query_id: &str,
        revision: u64,
        max_items: u32,
        now_ms: i64,
    ) -> Result<usize, LogsError> {
        let payload: ResultToken = self.decode(token)?;
        if payload.version != 1
            || payload.scope.account_id != scope.account_id
            || payload.scope.region != scope.region
            || payload.query_id != query_id
            || payload.revision != revision
            || payload.max_items != max_items
            || payload.expires_at_ms <= now_ms
        {
            return Err(LogsError::InvalidParameter("nextToken is invalid".into()));
        }
        Ok(payload.position)
    }

    fn encode_describe_token(
        &self,
        binding: &DescribeBinding,
        query_ids: Vec<String>,
        position: usize,
        now_ms: i64,
    ) -> Result<String, LogsError> {
        self.encode(&DescribeToken {
            version: 1,
            binding: binding.clone(),
            query_ids,
            position,
            expires_at_ms: now_ms.saturating_add(DESCRIBE_TOKEN_TTL_MS),
        })
    }

    fn decode_describe_token(
        &self,
        token: &str,
        binding: &DescribeBinding,
        now_ms: i64,
    ) -> Result<(Vec<String>, usize), LogsError> {
        let payload: DescribeToken = self.decode(token)?;
        if payload.version != 1
            || &payload.binding != binding
            || payload.expires_at_ms <= now_ms
            || payload.position > payload.query_ids.len()
        {
            return Err(LogsError::InvalidParameter("nextToken is invalid".into()));
        }
        Ok((payload.query_ids, payload.position))
    }

    fn encode<T: Serialize>(&self, value: &T) -> Result<String, LogsError> {
        let payload = serde_json::to_vec(value)
            .map_err(|_| LogsError::ServiceUnavailable("query token encoding failed".into()))?;
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| LogsError::ServiceUnavailable("query token encoding failed".into()))?;
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn decode<T: for<'de> Deserialize<'de>>(&self, token: &str) -> Result<T, LogsError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(LogsError::InvalidParameter("nextToken is invalid".into()));
        }
        let (payload, signature) = token
            .split_once('.')
            .ok_or_else(|| LogsError::InvalidParameter("nextToken is invalid".into()))?;
        if signature.contains('.') {
            return Err(LogsError::InvalidParameter("nextToken is invalid".into()));
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| LogsError::InvalidParameter("nextToken is invalid".into()))?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| LogsError::InvalidParameter("nextToken is invalid".into()))?;
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| LogsError::InvalidParameter("nextToken is invalid".into()))?;
        mac.update(&payload);
        mac.verify_slice(&signature)
            .map_err(|_| LogsError::InvalidParameter("nextToken is invalid".into()))?;
        serde_json::from_slice(&payload)
            .map_err(|_| LogsError::InvalidParameter("nextToken is invalid".into()))
    }
}
