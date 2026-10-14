//! `GetMetricData` for `MetricStat` queries.
//!
//! Metric math and Metrics Insights (`Expression`) are not supported and reject the whole
//! request with `InvalidParameterValue`, so callers never see a silently partial result.
//! Values are computed with the same period bucketing as `GetMetricStatistics`, except that
//! samples with different units are aggregated into one series when `Unit` is omitted (one
//! value per timestamp is all the response shape can carry).
use super::*;
use std::collections::BTreeSet;

const ACTION: &str = "GetMetricData";
const MAX_QUERIES: usize = 500;
const MAX_DATAPOINTS: usize = 100_800;
const MAX_ID_LEN: usize = 255;
const MAX_NAME_LEN: usize = 255;
const MAX_DIMENSION_VALUE_LEN: usize = 1_024;
const TOKEN_TTL_MS: i64 = 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanBy {
    TimestampDescending,
    TimestampAscending,
}

impl ScanBy {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "TimestampDescending" => Some(Self::TimestampDescending),
            "TimestampAscending" => Some(Self::TimestampAscending),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct MetricStatQuery {
    key: MetricKey,
    period_ms: i64,
    stat: Statistic,
    unit: Option<MetricUnit>,
}

#[derive(Debug)]
struct DataQuery {
    id: String,
    label: Option<String>,
    return_data: bool,
    metric_stat: MetricStatQuery,
}

/// Normalized request; its `Debug` form binds pagination tokens to the exact query.
#[derive(Debug)]
struct MetricDataRequest {
    queries: Vec<DataQuery>,
    start_ms: i64,
    end_ms: i64,
    scan_by: ScanBy,
    max_datapoints: usize,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Cursor {
    query: usize,
    after_ms: Option<i64>,
    expires: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusCode {
    Complete,
    PartialData,
}

impl StatusCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "Complete",
            Self::PartialData => "PartialData",
        }
    }
}

struct DataResult {
    id: String,
    data: Option<(String, Vec<(i64, f64)>)>,
    status: StatusCode,
}

pub(crate) struct MetricDataOutput {
    results: Vec<DataResult>,
    next_token: Option<String>,
}

fn invalid(message: impl Into<String>) -> MonitoringError {
    MonitoringError::InvalidParameter(message.into())
}

fn invalid_token() -> MonitoringError {
    MonitoringError::InvalidNextToken("The specified NextToken is invalid or expired".into())
}

fn optional_string<'a>(value: &'a Value, name: &str) -> Result<Option<&'a str>, MonitoringError> {
    match json_field(value, name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(invalid(format!("{name} must be a string"))),
    }
}

fn valid_id(id: &str) -> bool {
    let mut bytes = id.bytes();
    id.len() <= MAX_ID_LEN
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_period(period: u64) -> bool {
    period <= i32::MAX as u64
        && (matches!(period, 1 | 5 | 10 | 20 | 30) || period.is_multiple_of(60))
}

fn parse_metric_stat(value: &Value, member: &str) -> Result<MetricStatQuery, MonitoringError> {
    let metric = json_field(value, "Metric")
        .filter(|metric| metric.is_object())
        .ok_or_else(|| invalid(format!("{member}.MetricStat.Metric is required")))?;
    let namespace = json_string(metric, "Namespace")?;
    let metric_name = json_string(metric, "MetricName")?;
    if namespace.len() > MAX_NAME_LEN || metric_name.len() > MAX_NAME_LEN {
        return Err(invalid(format!(
            "{member}.MetricStat.Metric Namespace and MetricName must be at most 255 characters"
        )));
    }
    let dimensions = parse_json_dimensions(json_field(metric, "Dimensions"))?;
    if dimensions
        .iter()
        .any(|(name, value)| name.len() > MAX_NAME_LEN || value.len() > MAX_DIMENSION_VALUE_LEN)
    {
        return Err(invalid(format!(
            "{member}.MetricStat.Metric.Dimensions are outside supported limits"
        )));
    }
    let period = json_field(value, "Period")
        .and_then(Value::as_u64)
        .filter(|period| *period > 0)
        .ok_or_else(|| {
            invalid(format!(
                "{member}.MetricStat.Period must be a positive integer"
            ))
        })?;
    if !valid_period(period) {
        return Err(invalid(format!(
            "{member}.MetricStat.Period must be 1, 5, 10, 20, 30 or a multiple of 60"
        )));
    }
    let stat = json_field(value, "Stat")
        .and_then(Value::as_str)
        .and_then(Statistic::parse)
        .ok_or_else(|| {
            invalid(format!(
                "{member}.MetricStat.Stat must be SampleCount, Sum, Average, Minimum, Maximum or a percentile such as p99 or p99.9"
            ))
        })?;
    let unit = optional_string(value, "Unit")?
        .map(|unit| {
            MetricUnit::parse(unit)
                .ok_or_else(|| invalid(format!("{member}.MetricStat.Unit is not a valid unit")))
        })
        .transpose()?;
    Ok(MetricStatQuery {
        key: MetricKey {
            namespace: namespace.to_owned(),
            metric_name: metric_name.to_owned(),
            dimensions,
        },
        period_ms: period_millis(period)?,
        stat,
        unit,
    })
}

fn parse_query(
    value: &Value,
    index: usize,
    scope: &ScopeKey,
) -> Result<DataQuery, MonitoringError> {
    let member = format!("MetricDataQueries.member.{}", index + 1);
    if !value.is_object() {
        return Err(invalid(format!("{member} must be a structure")));
    }
    let id = optional_string(value, "Id")?
        .filter(|id| valid_id(id))
        .ok_or_else(|| {
            invalid(format!(
                "{member}.Id must match ^[a-z][a-zA-Z0-9_]*$ and be at most 255 characters"
            ))
        })?;
    if optional_string(value, "AccountId")?.is_some_and(|account| account != scope.account_id) {
        return Err(invalid(format!(
            "{member}.AccountId: cross-account GetMetricData is not supported by locallycloud"
        )));
    }
    let label = optional_string(value, "Label")?.map(str::to_owned);
    let return_data = match json_field(value, "ReturnData") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => return Err(invalid(format!("{member}.ReturnData must be a boolean"))),
    };
    if json_field(value, "Period").is_some_and(|period| {
        !period.is_null() && !period.as_u64().is_some_and(|period| period > 0)
    }) {
        return Err(invalid(format!(
            "{member}.Period must be a positive integer"
        )));
    }
    let metric_stat = json_field(value, "MetricStat")
        .filter(|stat| stat.is_object())
        .ok_or_else(|| invalid(format!("{member} must specify MetricStat")))?;
    Ok(DataQuery {
        id: id.to_owned(),
        label,
        return_data,
        metric_stat: parse_metric_stat(metric_stat, &member)?,
    })
}

fn parse_request(
    body: &Value,
    scope: &ScopeKey,
) -> Result<(MetricDataRequest, Option<String>), MonitoringError> {
    let queries = json_field(body, "MetricDataQueries")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("MetricDataQueries is required"))?;
    if queries.is_empty() || queries.len() > MAX_QUERIES {
        return Err(invalid(
            "MetricDataQueries must contain between 1 and 500 members",
        ));
    }
    if queries.iter().any(|query| {
        json_field(query, "Expression").is_some_and(|expression| !expression.is_null())
    }) {
        return Err(invalid(
            "MetricDataQueries Expression (metric math and Metrics Insights) is not supported by locallycloud; use MetricStat queries",
        ));
    }
    let queries = queries
        .iter()
        .enumerate()
        .map(|(index, query)| parse_query(query, index, scope))
        .collect::<Result<Vec<_>, _>>()?;
    let mut ids = BTreeSet::new();
    if !queries.iter().all(|query| ids.insert(query.id.as_str())) {
        return Err(invalid("MetricDataQueries Id values must be unique"));
    }
    let start_ms = parse_json_timestamp(json_required(body, "StartTime")?)?;
    let end_ms = parse_json_timestamp(json_required(body, "EndTime")?)?;
    if start_ms >= end_ms {
        return Err(invalid("StartTime must precede EndTime"));
    }
    let scan_by = optional_string(body, "ScanBy")?
        .map(|scan_by| {
            ScanBy::parse(scan_by)
                .ok_or_else(|| invalid("ScanBy must be TimestampDescending or TimestampAscending"))
        })
        .transpose()?
        .unwrap_or(ScanBy::TimestampDescending);
    let max_datapoints = match json_field(body, "MaxDatapoints") {
        None | Some(Value::Null) => MAX_DATAPOINTS,
        Some(value) => value
            .as_u64()
            .filter(|value| *value > 0)
            .map(|value| {
                usize::try_from(value)
                    .unwrap_or(MAX_DATAPOINTS)
                    .min(MAX_DATAPOINTS)
            })
            .ok_or_else(|| invalid("MaxDatapoints must be a positive integer"))?,
    };
    if json_field(body, "LabelOptions")
        .is_some_and(|options| !options.is_null() && !options.is_object())
    {
        return Err(invalid("LabelOptions must be a structure"));
    }
    let next_token = optional_string(body, "NextToken")?.map(str::to_owned);
    Ok((
        MetricDataRequest {
            queries,
            start_ms,
            end_ms,
            scan_by,
            max_datapoints,
        },
        next_token,
    ))
}

/// Translate Query-protocol members into the JSON request shape.
pub(crate) fn query_body(query: &QueryRequest) -> Result<Value, MonitoringError> {
    let mut body = serde_json::Map::new();
    for key in ["StartTime", "EndTime", "ScanBy", "NextToken"] {
        if let Some(value) = query.get(key) {
            body.insert(key.into(), json!(value));
        }
    }
    if let Some(value) = query.get("MaxDatapoints") {
        body.insert(
            "MaxDatapoints".into(),
            json!(parse_u64(value, "MaxDatapoints")?),
        );
    }
    let mut queries = Vec::new();
    for index in 1..=MAX_QUERIES + 1 {
        let member = format!("MetricDataQueries.member.{index}");
        if !query.has_prefix(&format!("{member}.")) {
            break;
        }
        if index > MAX_QUERIES {
            return Err(invalid(
                "MetricDataQueries must contain between 1 and 500 members",
            ));
        }
        let mut entry = serde_json::Map::new();
        for field in ["Id", "Label", "Expression", "AccountId"] {
            if let Some(value) = query.get(&format!("{member}.{field}")) {
                entry.insert(field.into(), json!(value));
            }
        }
        if let Some(value) = query.get(&format!("{member}.ReturnData")) {
            let flag = match value {
                "true" => true,
                "false" => false,
                _ => return Err(invalid(format!("{member}.ReturnData must be a boolean"))),
            };
            entry.insert("ReturnData".into(), json!(flag));
        }
        if let Some(value) = query.get(&format!("{member}.Period")) {
            entry.insert("Period".into(), json!(parse_u64(value, "Period")?));
        }
        let stat_prefix = format!("{member}.MetricStat");
        if query.has_prefix(&format!("{stat_prefix}.")) {
            let mut metric = serde_json::Map::new();
            for field in ["Namespace", "MetricName"] {
                if let Some(value) = query.get(&format!("{stat_prefix}.Metric.{field}")) {
                    metric.insert(field.into(), json!(value));
                }
            }
            let dimensions =
                parse_dimensions(query, &format!("{stat_prefix}.Metric.Dimensions.member"))?;
            metric.insert(
                "Dimensions".into(),
                Value::Array(
                    dimensions
                        .into_iter()
                        .map(|(name, value)| json!({ "Name": name, "Value": value }))
                        .collect(),
                ),
            );
            let mut stat = serde_json::Map::new();
            stat.insert("Metric".into(), Value::Object(metric));
            if let Some(value) = query.get(&format!("{stat_prefix}.Period")) {
                stat.insert("Period".into(), json!(parse_u64(value, "Period")?));
            }
            for field in ["Stat", "Unit"] {
                if let Some(value) = query.get(&format!("{stat_prefix}.{field}")) {
                    stat.insert(field.into(), json!(value));
                }
            }
            entry.insert("MetricStat".into(), Value::Object(stat));
        }
        queries.push(Value::Object(entry));
    }
    body.insert("MetricDataQueries".into(), Value::Array(queries));
    Ok(Value::Object(body))
}

impl MonitoringHandler {
    pub(crate) fn get_metric_data(
        &self,
        body: &Value,
        scope: &ScopeKey,
    ) -> Result<MetricDataOutput, MonitoringError> {
        let (request, token) = parse_request(body, scope)?;
        let binding = format!("{request:?}");
        let cursor = match token {
            None => Cursor {
                query: 0,
                after_ms: None,
                expires: now_ms().saturating_add(TOKEN_TTL_MS),
            },
            Some(token) => {
                let plaintext = self
                    .alarms
                    .open_token(ACTION, &binding, scope, &token)
                    .ok_or_else(invalid_token)?;
                let cursor: Cursor =
                    serde_json::from_slice(&plaintext).map_err(|_| invalid_token())?;
                if cursor.expires <= now_ms() || cursor.query >= request.queries.len() {
                    return Err(invalid_token());
                }
                cursor
            }
        };
        let mut budget = request.max_datapoints;
        let mut results = Vec::new();
        let mut next = None;
        let mut cache = BTreeMap::new();
        for (index, query) in request.queries.iter().enumerate().skip(cursor.query) {
            // AWS omits queries with `ReturnData` false from `MetricDataResults`.
            if query.return_data {
                let after_ms = (index == cursor.query).then_some(cursor.after_ms).flatten();
                let mut series = self.series(scope, &request, query, after_ms, &mut cache)?;
                let status = if series.len() > budget {
                    series.truncate(budget);
                    let resume = series.last().map(|(timestamp_ms, _)| *timestamp_ms);
                    next = Some((index, resume.or(after_ms)));
                    StatusCode::PartialData
                } else {
                    budget -= series.len();
                    StatusCode::Complete
                };
                let label = query
                    .label
                    .clone()
                    .unwrap_or_else(|| query.metric_stat.key.metric_name.clone());
                results.push(DataResult {
                    id: query.id.clone(),
                    data: Some((label, series)),
                    status,
                });
                if status == StatusCode::PartialData {
                    break;
                }
            }
            if budget == 0 && index + 1 < request.queries.len() {
                next = Some((index + 1, None));
                break;
            }
        }
        let next_token = next
            .map(|(query, after_ms)| {
                let cursor = Cursor {
                    query,
                    after_ms,
                    expires: cursor.expires,
                };
                let plaintext = serde_json::to_vec(&cursor).map_err(persistence::internal)?;
                self.alarms.seal_token(ACTION, &binding, scope, &plaintext)
            })
            .transpose()?;
        Ok(MetricDataOutput {
            results,
            next_token,
        })
    }

    /// One aggregated value per period, in `ScanBy` order, after the resume timestamp.
    fn series(
        &self,
        scope: &ScopeKey,
        request: &MetricDataRequest,
        query: &DataQuery,
        after_ms: Option<i64>,
        cache: &mut BTreeMap<String, Vec<(i64, f64)>>,
    ) -> Result<Vec<(i64, f64)>, MonitoringError> {
        let stat = &query.metric_stat;
        // Identical MetricStat queries in one request are aggregated once.
        let cache_key = format!("{stat:?}");
        if !cache.contains_key(&cache_key) {
            let points = self.domain.points(
                scope,
                &stat.key,
                request.start_ms,
                request.end_ms,
                stat.unit.map(MetricUnit::as_str),
            )?;
            let ascending = bucket_values(points, stat.period_ms, false)
                .into_iter()
                .filter_map(|((timestamp_ms, _), values)| {
                    stat.stat
                        .compute(&values)
                        .map(|value| (timestamp_ms, value))
                })
                .collect();
            cache.insert(cache_key.clone(), ascending);
        }
        let ascending = cache.get(&cache_key).map(Vec::as_slice).unwrap_or_default();
        let series: Vec<_> = match request.scan_by {
            ScanBy::TimestampAscending => ascending
                .iter()
                .copied()
                .filter(|(timestamp_ms, _)| after_ms.is_none_or(|after| *timestamp_ms > after))
                .collect(),
            ScanBy::TimestampDescending => ascending
                .iter()
                .rev()
                .copied()
                .filter(|(timestamp_ms, _)| after_ms.is_none_or(|after| *timestamp_ms < after))
                .collect(),
        };
        Ok(series)
    }
}

impl MetricDataOutput {
    pub(crate) fn to_json(&self) -> Value {
        let results: Vec<_> = self
            .results
            .iter()
            .map(|result| {
                let mut entry = serde_json::Map::new();
                entry.insert("Id".into(), json!(result.id));
                if let Some((label, series)) = &result.data {
                    entry.insert("Label".into(), json!(label));
                    entry.insert(
                        "Timestamps".into(),
                        Value::Array(
                            series
                                .iter()
                                .map(|(timestamp_ms, _)| json!(*timestamp_ms as f64 / 1_000.0))
                                .collect(),
                        ),
                    );
                    entry.insert(
                        "Values".into(),
                        Value::Array(series.iter().map(|(_, value)| json!(value)).collect()),
                    );
                }
                entry.insert("StatusCode".into(), json!(result.status.as_str()));
                Value::Object(entry)
            })
            .collect();
        let mut body = serde_json::Map::new();
        body.insert("MetricDataResults".into(), Value::Array(results));
        if let Some(token) = &self.next_token {
            body.insert("NextToken".into(), json!(token));
        }
        body.insert("Messages".into(), json!([]));
        Value::Object(body)
    }

    pub(crate) fn to_xml(&self) -> Result<String, MonitoringError> {
        let mut results = String::new();
        for result in &self.results {
            let mut member = text_element("Id", &result.id);
            if let Some((label, series)) = &result.data {
                member.push_str(&text_element("Label", label));
                let mut timestamps = String::new();
                let mut values = String::new();
                for (timestamp_ms, value) in series {
                    timestamps.push_str(&text_element("member", &format_timestamp(*timestamp_ms)?));
                    values.push_str(&text_element("member", &number_text(*value)));
                }
                member.push_str(&format!(
                    "<Timestamps>{timestamps}</Timestamps><Values>{values}</Values>"
                ));
            }
            member.push_str(&text_element("StatusCode", result.status.as_str()));
            results.push_str(&format!("<member>{member}</member>"));
        }
        let next_token = self
            .next_token
            .as_deref()
            .map(|token| text_element("NextToken", token))
            .unwrap_or_default();
        Ok(format!(
            "<MetricDataResults>{results}</MetricDataResults>{next_token}<Messages/>"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "000000000000";
    const REGION: &str = "us-east-1";
    const NAMESPACE: &str = "LocallyCloud/MetricData";

    fn scope() -> ScopeKey {
        ScopeKey {
            account_id: ACCOUNT.into(),
            region: REGION.into(),
        }
    }

    fn observation(
        metric: &str,
        timestamp_ms: i64,
        value: f64,
        unit: MetricUnit,
    ) -> MetricObservation {
        MetricObservation {
            account_id: ACCOUNT.into(),
            region: REGION.into(),
            namespace: NAMESPACE.into(),
            metric_name: metric.into(),
            dimensions: BTreeMap::from([("Service".into(), "orders".into())]),
            timestamp_ms,
            value,
            unit: Some(unit),
            storage_resolution: 60,
            origin: MetricOrigin::PublicPutMetricData,
            correlation_id: format!("{metric}-{timestamp_ms}-{value}"),
        }
    }

    /// Three one-minute buckets of `Latency` (several samples each) and `Errors`.
    fn handler() -> (MonitoringHandler, i64) {
        let base_ms = now_ms().div_euclid(60_000).saturating_sub(5) * 60_000;
        let domain = Arc::new(MonitoringDomain::default());
        let mut observations = Vec::new();
        for minute in 0..3_i64 {
            for sample in 0..4_i64 {
                observations.push(observation(
                    "Latency",
                    base_ms + minute * 60_000 + sample * 1_000,
                    (minute * 10 + sample) as f64 + 0.5,
                    MetricUnit::Milliseconds,
                ));
            }
            observations.push(observation(
                "Errors",
                base_ms + minute * 60_000,
                (minute + 1) as f64,
                MetricUnit::Count,
            ));
        }
        domain.commit(observations).unwrap();
        let handler = MonitoringHandler {
            registry: std::sync::Weak::new(),
            _worker: Arc::new(WorkerGuard(None)),
            domain,
            alarms: Arc::new(alarms::Alarms::new(None).unwrap()),
        };
        (handler, base_ms)
    }

    fn metric_query(id: &str, metric: &str, stat: &str) -> Value {
        json!({
            "Id": id,
            "MetricStat": {
                "Metric": {
                    "Namespace": NAMESPACE,
                    "MetricName": metric,
                    "Dimensions": [{ "Name": "Service", "Value": "orders" }]
                },
                "Period": 60,
                "Stat": stat
            }
        })
    }

    fn request(base_ms: i64, queries: Vec<Value>) -> Value {
        json!({
            "StartTime": base_ms as f64 / 1_000.0,
            "EndTime": (base_ms + 180_000) as f64 / 1_000.0,
            "MetricDataQueries": queries
        })
    }

    fn run(handler: &MonitoringHandler, body: &Value) -> Result<Value, MonitoringError> {
        handler
            .get_metric_data(body, &scope())
            .map(|output| output.to_json())
    }

    fn series(result: &Value) -> Vec<(i64, f64)> {
        let timestamps = result["Timestamps"].as_array().unwrap();
        let values = result["Values"].as_array().unwrap();
        assert_eq!(timestamps.len(), values.len());
        timestamps
            .iter()
            .zip(values)
            .map(|(timestamp, value)| {
                (
                    (timestamp.as_f64().unwrap() * 1_000.0).round() as i64,
                    value.as_f64().unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn values_match_get_metric_statistics_for_the_same_series() {
        let (handler, base_ms) = handler();
        let stats = ["Sum", "Average", "Minimum", "Maximum", "SampleCount"];
        let statistics = handler
            .get_metric_statistics_json(
                &json!({
                    "Namespace": NAMESPACE,
                    "MetricName": "Latency",
                    "Dimensions": [{ "Name": "Service", "Value": "orders" }],
                    "StartTime": base_ms as f64 / 1_000.0,
                    "EndTime": (base_ms + 180_000) as f64 / 1_000.0,
                    "Period": 60,
                    "Statistics": stats
                }),
                &scope(),
            )
            .unwrap();
        let queries = stats
            .iter()
            .map(|stat| metric_query(&stat.to_ascii_lowercase(), "Latency", stat))
            .collect();
        let data = run(&handler, &request(base_ms, queries)).unwrap();
        let results = data["MetricDataResults"].as_array().unwrap();
        assert_eq!(results.len(), stats.len());
        for (stat, result) in stats.iter().zip(results) {
            assert_eq!(result["StatusCode"], "Complete");
            assert_eq!(result["Label"], "Latency");
            let expected: Vec<_> = statistics["Datapoints"]
                .as_array()
                .unwrap()
                .iter()
                .map(|point| {
                    (
                        (point["Timestamp"].as_f64().unwrap() * 1_000.0).round() as i64,
                        point[*stat].as_f64().unwrap(),
                    )
                })
                .collect();
            assert_eq!(expected.len(), 3);
            assert_eq!(series(result), expected, "{stat}");
        }
        assert!(data.get("NextToken").is_none());
        assert_eq!(data["Messages"], json!([]));
    }

    #[test]
    fn percentiles_use_nearest_rank_over_stored_samples() {
        let (handler, base_ms) = handler();
        let queries = ["p50", "p75", "p99.9", "p0"]
            .iter()
            .enumerate()
            .map(|(index, stat)| metric_query(&format!("q{index}"), "Latency", stat))
            .collect();
        let data = run(&handler, &request(base_ms, queries)).unwrap();
        let first_minute = |index: usize| {
            series(&data["MetricDataResults"][index])
                .into_iter()
                .find(|(timestamp_ms, _)| *timestamp_ms == base_ms)
                .unwrap()
                .1
        };
        // Samples in the first minute: 0.5, 1.5, 2.5, 3.5.
        assert_eq!(first_minute(0), 1.5);
        assert_eq!(first_minute(1), 2.5);
        assert_eq!(first_minute(2), 3.5);
        assert_eq!(first_minute(3), 0.5);
    }

    #[test]
    fn scan_by_orders_timestamps() {
        let (handler, base_ms) = handler();
        let expected = vec![base_ms + 120_000, base_ms + 60_000, base_ms];
        let mut body = request(base_ms, vec![metric_query("m1", "Errors", "Sum")]);
        let timestamps = |data: &Value| {
            series(&data["MetricDataResults"][0])
                .into_iter()
                .map(|(timestamp_ms, _)| timestamp_ms)
                .collect::<Vec<_>>()
        };
        assert_eq!(timestamps(&run(&handler, &body).unwrap()), expected);
        body["ScanBy"] = json!("TimestampDescending");
        assert_eq!(timestamps(&run(&handler, &body).unwrap()), expected);
        body["ScanBy"] = json!("TimestampAscending");
        let ascending: Vec<_> = expected.iter().rev().copied().collect();
        assert_eq!(timestamps(&run(&handler, &body).unwrap()), ascending);
        body["ScanBy"] = json!("Newest");
        assert!(matches!(
            run(&handler, &body),
            Err(MonitoringError::InvalidParameter(_))
        ));
    }

    #[test]
    fn max_datapoints_paginates_with_opaque_bound_tokens() {
        let (handler, base_ms) = handler();
        let mut body = request(
            base_ms,
            vec![
                metric_query("errors", "Errors", "Sum"),
                metric_query("latency", "Latency", "Maximum"),
            ],
        );
        body["MaxDatapoints"] = json!(2);
        body["ScanBy"] = json!("TimestampAscending");
        let mut pages = Vec::new();
        loop {
            let page = run(&handler, &body).unwrap();
            let token = page
                .get("NextToken")
                .and_then(Value::as_str)
                .map(str::to_owned);
            pages.push(page);
            let Some(token) = token else {
                break;
            };
            body["NextToken"] = json!(token);
            assert!(pages.len() < 10, "pagination must terminate");
        }
        let summary: Vec<Vec<(String, String, usize)>> = pages
            .iter()
            .map(|page| {
                page["MetricDataResults"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|result| {
                        (
                            result["Id"].as_str().unwrap().to_owned(),
                            result["StatusCode"].as_str().unwrap().to_owned(),
                            result["Values"].as_array().unwrap().len(),
                        )
                    })
                    .collect()
            })
            .collect();
        let entry = |id: &str, status: &str, count| (id.to_owned(), status.to_owned(), count);
        assert_eq!(
            summary,
            vec![
                vec![entry("errors", "PartialData", 2)],
                vec![
                    entry("errors", "Complete", 1),
                    entry("latency", "PartialData", 1)
                ],
                vec![entry("latency", "Complete", 2)],
            ]
        );
        let mut merged = BTreeMap::<String, Vec<(i64, f64)>>::new();
        for page in &pages {
            for result in page["MetricDataResults"].as_array().unwrap() {
                merged
                    .entry(result["Id"].as_str().unwrap().to_owned())
                    .or_default()
                    .extend(series(result));
            }
        }
        assert_eq!(
            merged["errors"],
            vec![
                (base_ms, 1.0),
                (base_ms + 60_000, 2.0),
                (base_ms + 120_000, 3.0)
            ]
        );
        assert_eq!(merged["latency"].len(), 3);

        let token = pages[0]["NextToken"].as_str().unwrap().to_owned();
        let mut tampered = body.clone();
        let mut forged = token.clone().into_bytes();
        let last = forged.len() - 1;
        forged[last] = if forged[last] == b'0' { b'1' } else { b'0' };
        tampered["NextToken"] = json!(String::from_utf8(forged).unwrap());
        assert!(matches!(
            run(&handler, &tampered),
            Err(MonitoringError::InvalidNextToken(_))
        ));
        let mut rebound = body.clone();
        rebound["NextToken"] = json!(token);
        rebound["MaxDatapoints"] = json!(3);
        assert!(matches!(
            run(&handler, &rebound),
            Err(MonitoringError::InvalidNextToken(_))
        ));
        for garbage in ["", "zz", "abc", "not-a-token"] {
            let mut invalid = body.clone();
            invalid["NextToken"] = json!(garbage);
            assert!(matches!(
                run(&handler, &invalid),
                Err(MonitoringError::InvalidNextToken(_))
            ));
        }
        body["MaxDatapoints"] = json!(0);
        assert!(matches!(
            run(&handler, &body),
            Err(MonitoringError::InvalidParameter(_))
        ));
    }

    #[test]
    fn expressions_are_rejected_without_partial_success() {
        let (handler, base_ms) = handler();
        let body = request(
            base_ms,
            vec![
                metric_query("m1", "Errors", "Sum"),
                json!({ "Id": "e1", "Expression": "m1 * 2", "Label": "Doubled" }),
            ],
        );
        let Err(MonitoringError::InvalidParameter(message)) = run(&handler, &body) else {
            panic!("Expression must be rejected");
        };
        assert!(message.contains("Expression"));
        assert!(message.contains("not supported"));
    }

    #[test]
    fn invalid_queries_are_rejected() {
        let (handler, base_ms) = handler();
        let reject = |queries: Vec<Value>| {
            assert!(
                matches!(
                    run(&handler, &request(base_ms, queries.clone())),
                    Err(MonitoringError::InvalidParameter(_))
                ),
                "{queries:?}"
            );
        };
        for id in ["M1", "1m", "m-1", "", "_m"] {
            reject(vec![metric_query(id, "Errors", "Sum")]);
        }
        reject(vec![metric_query(
            &format!("m{}", "a".repeat(255)),
            "Errors",
            "Sum",
        )]);
        reject(vec![
            metric_query("m1", "Errors", "Sum"),
            metric_query("m1", "Latency", "Sum"),
        ]);
        reject(Vec::new());
        reject(
            (0..=MAX_QUERIES)
                .map(|index| metric_query(&format!("m{index}"), "Errors", "Sum"))
                .collect(),
        );
        for stat in ["Median", "p101", "tm99", "P90"] {
            reject(vec![metric_query("m1", "Errors", stat)]);
        }
        let mut period = metric_query("m1", "Errors", "Sum");
        period["MetricStat"]["Period"] = json!(61);
        reject(vec![period]);
        let mut unit = metric_query("m1", "Errors", "Sum");
        unit["MetricStat"]["Unit"] = json!("Furlongs");
        reject(vec![unit]);
        let mut account = metric_query("m1", "Errors", "Sum");
        account["AccountId"] = json!("111111111111");
        reject(vec![account]);
        reject(vec![json!({ "Id": "m1" })]);
        let mut reversed = request(base_ms, vec![metric_query("m1", "Errors", "Sum")]);
        reversed["EndTime"] = reversed["StartTime"].clone();
        assert!(matches!(
            run(&handler, &reversed),
            Err(MonitoringError::InvalidParameter(_))
        ));
        assert!(run(
            &handler,
            &request(
                base_ms,
                (0..MAX_QUERIES)
                    .map(|index| metric_query(&format!("m{index}"), "Errors", "Sum"))
                    .collect()
            )
        )
        .is_ok());
    }

    #[test]
    fn return_data_false_and_unit_filter() {
        let (handler, base_ms) = handler();
        let mut hidden = metric_query("hidden", "Errors", "Sum");
        hidden["ReturnData"] = json!(false);
        let mut mismatched = metric_query("seconds", "Latency", "Sum");
        mismatched["MetricStat"]["Unit"] = json!("Seconds");
        let mut matching = metric_query("millis", "Latency", "SampleCount");
        matching["MetricStat"]["Unit"] = json!("Milliseconds");
        matching["Label"] = json!("Custom label");
        let data = run(
            &handler,
            &request(base_ms, vec![hidden, mismatched, matching]),
        )
        .unwrap();
        // Queries with `ReturnData` false are not part of `MetricDataResults`.
        let results = &data["MetricDataResults"];
        assert_eq!(results.as_array().unwrap().len(), 2);
        assert!(results
            .as_array()
            .unwrap()
            .iter()
            .all(|result| result["Id"] != "hidden"));
        assert_eq!(results[0]["Values"], json!([]));
        assert_eq!(results[1]["Label"], "Custom label");
        assert_eq!(
            series(&results[1])
                .into_iter()
                .map(|(_, value)| value)
                .collect::<Vec<_>>(),
            vec![4.0, 4.0, 4.0]
        );
    }

    fn wire_request(body: Vec<u8>, json_target: bool) -> ServiceRequest {
        let mut headers = http::HeaderMap::new();
        if json_target {
            headers.insert(
                "x-amz-target",
                "GraniteServiceVersion20100801.GetMetricData"
                    .parse()
                    .unwrap(),
            );
            headers.insert(
                http::header::CONTENT_TYPE,
                "application/x-amz-json-1.0".parse().unwrap(),
            );
        } else {
            headers.insert(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded".parse().unwrap(),
            );
        }
        ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: body.into(),
            region: REGION.into(),
            account_id: ACCOUNT.into(),
            request_id: "metric-data".into(),
        }
    }

    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn query_xml_and_json_wire_shapes() {
        let (handler, base_ms) = handler();
        let start = format_timestamp(base_ms).unwrap();
        let end = format_timestamp(base_ms + 180_000).unwrap();
        let prefix = "MetricDataQueries.member.1";
        let stat = format!("{prefix}.MetricStat");
        let query = format!(
            "Action=GetMetricData&Version=2010-08-01&StartTime={start}&EndTime={end}&ScanBy=TimestampAscending\
             &{prefix}.Id=m1&{prefix}.Label=Errors%20%26%20more&{prefix}.ReturnData=true\
             &{stat}.Metric.Namespace={NAMESPACE}&{stat}.Metric.MetricName=Errors\
             &{stat}.Metric.Dimensions.member.1.Name=Service&{stat}.Metric.Dimensions.member.1.Value=orders\
             &{stat}.Period=60&{stat}.Stat=Sum&{stat}.Unit=Count"
        );
        let response = handler
            .handle(wire_request(query.into_bytes(), false))
            .await;
        assert_eq!(response.status(), 200);
        let xml = body_text(response).await;
        let timestamps = [base_ms, base_ms + 60_000, base_ms + 120_000]
            .iter()
            .map(|timestamp_ms| {
                format!(
                    "<member>{}</member>",
                    format_timestamp(*timestamp_ms).unwrap()
                )
            })
            .collect::<String>();
        assert_eq!(
            xml,
            format!(
                "<GetMetricDataResponse xmlns=\"{XMLNS}\"><GetMetricDataResult><MetricDataResults><member><Id>m1</Id>\
                 <Label>Errors &amp; more</Label><Timestamps>{timestamps}</Timestamps>\
                 <Values><member>1</member><member>2</member><member>3</member></Values>\
                 <StatusCode>Complete</StatusCode></member></MetricDataResults><Messages/></GetMetricDataResult>\
                 <ResponseMetadata><RequestId>metric-data</RequestId></ResponseMetadata></GetMetricDataResponse>"
            )
        );

        let expression = format!(
            "Action=GetMetricData&StartTime={start}&EndTime={end}&{prefix}.Id=e1&{prefix}.Expression=SELECT%201"
        );
        let response = handler
            .handle(wire_request(expression.into_bytes(), false))
            .await;
        assert_eq!(response.status(), 400);
        let xml = body_text(response).await;
        assert!(xml.contains("<Code>InvalidParameterValue</Code>"));
        assert!(xml.contains("not supported"));

        let json_body = json!({
            "StartTime": base_ms as f64 / 1_000.0,
            "EndTime": (base_ms + 180_000) as f64 / 1_000.0,
            "MaxDatapoints": 1,
            "MetricDataQueries": [metric_query("m1", "Errors", "Average")]
        });
        let response = handler
            .handle(wire_request(json_body.to_string().into_bytes(), true))
            .await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()[http::header::CONTENT_TYPE],
            "application/x-amz-json-1.0"
        );
        let value: Value = serde_json::from_str(&body_text(response).await).unwrap();
        assert_eq!(
            value["MetricDataResults"],
            json!([{
                "Id": "m1",
                "Label": "Errors",
                "Timestamps": [(base_ms + 120_000) as f64 / 1_000.0],
                "Values": [3.0],
                "StatusCode": "PartialData"
            }])
        );
        assert!(value["NextToken"]
            .as_str()
            .is_some_and(|token| !token.is_empty()));
        assert_eq!(value["Messages"], json!([]));

        let mut invalid = json_body.clone();
        invalid["MetricDataQueries"][0]["Id"] = json!("Bad-Id");
        let response = handler
            .handle(wire_request(invalid.to_string().into_bytes(), true))
            .await;
        assert_eq!(response.status(), 400);
        let error: Value = serde_json::from_str(&body_text(response).await).unwrap();
        assert_eq!(error["__type"], "InvalidParameterValue");

        let mut token = json_body;
        token["NextToken"] = json!("00");
        let response = handler
            .handle(wire_request(token.to_string().into_bytes(), true))
            .await;
        assert_eq!(response.status(), 400);
        let error: Value = serde_json::from_str(&body_text(response).await).unwrap();
        assert_eq!(error["__type"], "InvalidNextToken");
    }

    #[tokio::test]
    async fn cbor_timestamps_are_epoch_tagged() {
        let (handler, base_ms) = handler();
        let body = request(base_ms, vec![metric_query("m1", "Errors", "Sum")]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&body, &mut bytes).unwrap();
        let mut request = wire_request(bytes, false);
        request.uri = "/service/GraniteServiceVersion20100801/operation/GetMetricData"
            .parse()
            .unwrap();
        request.headers.insert(
            http::header::CONTENT_TYPE,
            "application/cbor".parse().unwrap(),
        );
        request
            .headers
            .insert("smithy-protocol", "rpc-v2-cbor".parse().unwrap());
        let response = handler.handle(request).await;
        assert_eq!(response.status(), 200);
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        let wire: ciborium::Value = ciborium::de::from_reader(bytes.as_ref()).unwrap();
        let decoded = rpc_cbor::to_json(wire.clone(), 0).unwrap();
        assert_eq!(
            decoded["MetricDataResults"][0]["Values"],
            json!([3.0, 2.0, 1.0])
        );
        let ciborium::Value::Map(entries) = wire else {
            panic!("output structure");
        };
        let results = entries
            .iter()
            .find(|(key, _)| *key == ciborium::Value::Text("MetricDataResults".into()))
            .map(|(_, value)| value.clone())
            .unwrap();
        let ciborium::Value::Array(results) = results else {
            panic!("results array");
        };
        let ciborium::Value::Map(result) = &results[0] else {
            panic!("result structure");
        };
        let timestamps = result
            .iter()
            .find(|(key, _)| *key == ciborium::Value::Text("Timestamps".into()))
            .map(|(_, value)| value.clone())
            .unwrap();
        let ciborium::Value::Array(timestamps) = timestamps else {
            panic!("timestamps array");
        };
        assert_eq!(timestamps.len(), 3);
        assert!(timestamps
            .iter()
            .all(|timestamp| matches!(timestamp, ciborium::Value::Tag(1, _))));
    }
}
