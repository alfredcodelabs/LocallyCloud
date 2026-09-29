//! Native CloudWatch Monitoring subset used by localcloud service integrations.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use localcloud_core::error_mapping::AwsError;
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::integration::metrics::{
    EmitOutcome, MetricObservation, MetricOrigin, MetricSink, MetricUnit,
};
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::mpsc;

const XMLNS: &str = "http://monitoring.amazonaws.com/doc/2010-08-01/";
const CHANNEL_CAPACITY: usize = 64;
const MAX_METRIC_DATA: usize = 1_000;
const MAX_DIMENSIONS: usize = 30;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ScopeKey {
    account_id: String,
    region: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MetricKey {
    namespace: String,
    metric_name: String,
    dimensions: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct MetricPoint {
    timestamp_ms: i64,
    value: f64,
    unit: Option<MetricUnit>,
    _storage_resolution: u16,
    _origin: MetricOrigin,
    _correlation_id: String,
}

#[derive(Default)]
struct MonitoringDomain {
    series: RwLock<BTreeMap<ScopeKey, BTreeMap<MetricKey, Vec<MetricPoint>>>>,
}

impl MonitoringDomain {
    fn commit(&self, observations: Vec<MetricObservation>) -> Result<(), MonitoringError> {
        if observations.is_empty() || observations.len() > MAX_METRIC_DATA {
            return Err(MonitoringError::InvalidParameter(
                "MetricData must contain between 1 and 1000 members".into(),
            ));
        }
        for observation in &observations {
            validate_observation(observation)?;
        }
        let mut series = self
            .series
            .write()
            .map_err(|_| MonitoringError::Internal("monitoring store lock poisoned".into()))?;
        for observation in observations {
            let scope = ScopeKey {
                account_id: observation.account_id,
                region: observation.region,
            };
            let key = MetricKey {
                namespace: observation.namespace,
                metric_name: observation.metric_name,
                dimensions: observation.dimensions,
            };
            let point = MetricPoint {
                timestamp_ms: observation.timestamp_ms,
                value: observation.value,
                unit: observation.unit,
                _storage_resolution: observation.storage_resolution,
                _origin: observation.origin,
                _correlation_id: observation.correlation_id,
            };
            let points = series.entry(scope).or_default().entry(key).or_default();
            points.push(point);
            points.sort_by_key(|point| point.timestamp_ms);
        }
        Ok(())
    }

    fn list(
        &self,
        scope: &ScopeKey,
        namespace: Option<&str>,
        metric_name: Option<&str>,
    ) -> Result<Vec<MetricKey>, MonitoringError> {
        let series = self
            .series
            .read()
            .map_err(|_| MonitoringError::Internal("monitoring store lock poisoned".into()))?;
        Ok(series
            .get(scope)
            .into_iter()
            .flat_map(|metrics| metrics.keys())
            .filter(|key| namespace.is_none_or(|value| key.namespace == value))
            .filter(|key| metric_name.is_none_or(|value| key.metric_name == value))
            .cloned()
            .collect())
    }

    fn points(
        &self,
        scope: &ScopeKey,
        key: &MetricKey,
        start_ms: i64,
        end_ms: i64,
        unit: Option<&str>,
    ) -> Result<Vec<MetricPoint>, MonitoringError> {
        let series = self
            .series
            .read()
            .map_err(|_| MonitoringError::Internal("monitoring store lock poisoned".into()))?;
        Ok(series
            .get(scope)
            .and_then(|metrics| metrics.get(key))
            .into_iter()
            .flatten()
            .filter(|point| point.timestamp_ms >= start_ms && point.timestamp_ms < end_ms)
            .filter(|point| {
                unit.is_none_or(|unit| point.unit.map(MetricUnit::as_str).unwrap_or("None") == unit)
            })
            .cloned()
            .collect())
    }
}

struct MonitoringMetricSink {
    sender: mpsc::Sender<Vec<MetricObservation>>,
}

impl MetricSink for MonitoringMetricSink {
    fn try_emit(&self, observations: Vec<MetricObservation>) -> EmitOutcome {
        if observations.is_empty()
            || observations
                .iter()
                .any(|observation| validate_observation(observation).is_err())
        {
            return EmitOutcome::Dropped;
        }
        match self.sender.try_send(observations) {
            Ok(()) => EmitOutcome::Accepted,
            Err(mpsc::error::TrySendError::Full(_)) => EmitOutcome::Full,
            Err(mpsc::error::TrySendError::Closed(_)) => EmitOutcome::Unavailable,
        }
    }
}

struct MonitoringHandler {
    domain: Arc<MonitoringDomain>,
}

enum WireResponse {
    Query { action: String, body: String },
    Json(Value),
}

#[async_trait]
impl NativeHandler for MonitoringHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let protocol = if request.headers.contains_key("x-amz-target") {
            AwsProtocol::Json10
        } else {
            AwsProtocol::Query
        };
        match self.process(&request, protocol) {
            Ok(WireResponse::Query { action, body }) => {
                success_response(&action, &body, &request.request_id)
            }
            Ok(WireResponse::Json(body)) => json_response(body, &request.request_id),
            Err(error) => error_response(error, &request.request_id, protocol),
        }
    }
}

impl MonitoringHandler {
    fn process(
        &self,
        request: &ServiceRequest,
        protocol: AwsProtocol,
    ) -> Result<WireResponse, MonitoringError> {
        if request.method != http::Method::POST
            || request.uri.path() != "/"
            || request.uri.query().is_some()
        {
            return Err(MonitoringError::InvalidAction(
                "CloudWatch Monitoring operations require POST /".into(),
            ));
        }
        let scope = ScopeKey {
            account_id: request.account_id.clone(),
            region: request.region.clone(),
        };
        if protocol == AwsProtocol::Json10 {
            return self.process_json(request, &scope).map(WireResponse::Json);
        }
        let query = QueryRequest::parse(&request.body);
        let action = query
            .get("Action")
            .ok_or_else(|| MonitoringError::InvalidAction("missing Action".into()))?
            .to_owned();
        let body = match action.as_str() {
            "PutMetricData" => {
                self.put_metric_data(&query, &scope, &request.request_id)?;
                String::new()
            }
            "ListMetrics" => self.list_metrics(&query, &scope)?,
            "GetMetricStatistics" => self.get_metric_statistics(&query, &scope)?,
            _ => {
                return Err(MonitoringError::InvalidAction(format!(
                    "unsupported CloudWatch action {action}"
                )))
            }
        };
        Ok(WireResponse::Query { action, body })
    }

    fn process_json(
        &self,
        request: &ServiceRequest,
        scope: &ScopeKey,
    ) -> Result<Value, MonitoringError> {
        let target = request
            .headers
            .get("x-amz-target")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| MonitoringError::InvalidAction("missing x-amz-target".into()))?;
        let action = target
            .rsplit_once('.')
            .map(|(_, action)| action)
            .ok_or_else(|| MonitoringError::InvalidAction("invalid x-amz-target".into()))?;
        let body: Value = serde_json::from_slice(&request.body)
            .map_err(|_| MonitoringError::InvalidParameter("request body must be JSON".into()))?;
        match action {
            "PutMetricData" => {
                self.put_metric_data_json(&body, scope, &request.request_id)?;
                Ok(json!({}))
            }
            "ListMetrics" => self.list_metrics_json(&body, scope),
            "GetMetricStatistics" => self.get_metric_statistics_json(&body, scope),
            _ => Err(MonitoringError::InvalidAction(format!(
                "unsupported CloudWatch action {action}"
            ))),
        }
    }

    fn put_metric_data_json(
        &self,
        body: &Value,
        scope: &ScopeKey,
        request_id: &str,
    ) -> Result<(), MonitoringError> {
        let namespace = json_string(body, "Namespace")?.to_owned();
        let data = json_field(body, "MetricData")
            .and_then(Value::as_array)
            .ok_or_else(|| MonitoringError::InvalidParameter("MetricData is required".into()))?;
        if data.is_empty() || data.len() > MAX_METRIC_DATA {
            return Err(MonitoringError::InvalidParameter(
                "MetricData must contain between 1 and 1000 members".into(),
            ));
        }
        let mut observations = Vec::with_capacity(data.len());
        for datum in data {
            let value = json_field(datum, "Value")
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite())
                .ok_or_else(|| MonitoringError::InvalidParameter("Value must be finite".into()))?;
            let timestamp_ms = json_field(datum, "Timestamp")
                .map(parse_json_timestamp)
                .transpose()?
                .unwrap_or_else(now_ms);
            let storage_resolution = json_field(datum, "StorageResolution")
                .and_then(Value::as_u64)
                .map(|value| {
                    u16::try_from(value).map_err(|_| {
                        MonitoringError::InvalidParameter(
                            "StorageResolution is outside supported range".into(),
                        )
                    })
                })
                .transpose()?
                .unwrap_or(60);
            observations.push(MetricObservation {
                account_id: scope.account_id.clone(),
                region: scope.region.clone(),
                namespace: namespace.clone(),
                metric_name: json_string(datum, "MetricName")?.to_owned(),
                dimensions: parse_json_dimensions(json_field(datum, "Dimensions"))?,
                timestamp_ms,
                value,
                unit: json_field(datum, "Unit")
                    .and_then(Value::as_str)
                    .map(|unit| {
                        MetricUnit::parse(unit).ok_or_else(|| {
                            MonitoringError::InvalidParameter(format!(
                                "unsupported metric unit {unit}"
                            ))
                        })
                    })
                    .transpose()?,
                storage_resolution,
                origin: MetricOrigin::PublicPutMetricData,
                correlation_id: request_id.to_owned(),
            });
        }
        self.domain.commit(observations)
    }

    fn list_metrics_json(&self, body: &Value, scope: &ScopeKey) -> Result<Value, MonitoringError> {
        let metrics = self.domain.list(
            scope,
            json_field(body, "Namespace").and_then(Value::as_str),
            json_field(body, "MetricName").and_then(Value::as_str),
        )?;
        let metrics: Vec<_> = metrics
            .into_iter()
            .map(|metric| {
                let dimensions: Vec<_> = metric
                    .dimensions
                    .into_iter()
                    .map(|(name, value)| json!({ "Name": name, "Value": value }))
                    .collect();
                json!({
                    "Namespace": metric.namespace,
                    "MetricName": metric.metric_name,
                    "Dimensions": dimensions,
                })
            })
            .collect();
        Ok(json!({ "Metrics": metrics }))
    }

    fn get_metric_statistics_json(
        &self,
        body: &Value,
        scope: &ScopeKey,
    ) -> Result<Value, MonitoringError> {
        let namespace = json_string(body, "Namespace")?.to_owned();
        let metric_name = json_string(body, "MetricName")?.to_owned();
        let start_ms = parse_json_timestamp(json_required(body, "StartTime")?)?;
        let end_ms = parse_json_timestamp(json_required(body, "EndTime")?)?;
        if start_ms >= end_ms {
            return Err(MonitoringError::InvalidParameter(
                "StartTime must precede EndTime".into(),
            ));
        }
        let period = json_field(body, "Period")
            .and_then(Value::as_u64)
            .filter(|period| *period > 0)
            .ok_or_else(|| MonitoringError::InvalidParameter("Period must be positive".into()))?;
        let statistics: Vec<String> = json_field(body, "Statistics")
            .and_then(Value::as_array)
            .ok_or_else(|| MonitoringError::InvalidParameter("Statistics is required".into()))?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let allowed = ["Sum", "SampleCount", "Minimum", "Maximum", "Average"];
        if statistics.is_empty()
            || statistics
                .iter()
                .any(|statistic| !allowed.contains(&statistic.as_str()))
        {
            return Err(MonitoringError::InvalidParameter(
                "Statistics contains an unsupported value".into(),
            ));
        }
        let key = MetricKey {
            namespace,
            metric_name: metric_name.clone(),
            dimensions: parse_json_dimensions(json_field(body, "Dimensions"))?,
        };
        let points = self.domain.points(
            scope,
            &key,
            start_ms,
            end_ms,
            json_field(body, "Unit").and_then(Value::as_str),
        )?;
        let period_ms = i64::try_from(period)
            .ok()
            .and_then(|period| period.checked_mul(1_000))
            .ok_or_else(|| MonitoringError::InvalidParameter("Period is too large".into()))?;
        let mut buckets: BTreeMap<(i64, String), Vec<MetricPoint>> = BTreeMap::new();
        for point in points {
            let bucket = point.timestamp_ms.div_euclid(period_ms) * period_ms;
            let unit = point
                .unit
                .map(MetricUnit::as_str)
                .unwrap_or("None")
                .to_owned();
            buckets.entry((bucket, unit)).or_default().push(point);
        }
        let mut datapoints = Vec::new();
        for ((timestamp_ms, _), points) in buckets.into_iter().rev() {
            let values: Vec<f64> = points.iter().map(|point| point.value).collect();
            let sum: f64 = values.iter().sum();
            let count = values.len() as f64;
            let minimum = values.iter().copied().fold(f64::INFINITY, f64::min);
            let maximum = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let unit = points
                .first()
                .and_then(|point| point.unit.map(MetricUnit::as_str))
                .unwrap_or("None");
            let mut datum = serde_json::Map::new();
            datum.insert("Timestamp".into(), json!(timestamp_ms as f64 / 1_000.0));
            datum.insert("Unit".into(), json!(unit));
            for statistic in &statistics {
                let value = match statistic.as_str() {
                    "Sum" => sum,
                    "SampleCount" => count,
                    "Minimum" => minimum,
                    "Maximum" => maximum,
                    "Average" => sum / count,
                    _ => unreachable!(),
                };
                datum.insert(statistic.clone(), json!(value));
            }
            datapoints.push(Value::Object(datum));
        }
        Ok(json!({ "Label": metric_name, "Datapoints": datapoints }))
    }

    fn put_metric_data(
        &self,
        query: &QueryRequest,
        scope: &ScopeKey,
        request_id: &str,
    ) -> Result<(), MonitoringError> {
        let namespace = required(query, "Namespace")?.to_owned();
        let mut observations = Vec::new();
        for index in 1..=MAX_METRIC_DATA {
            let prefix = format!("MetricData.member.{index}");
            let Some(metric_name) = query.get(&format!("{prefix}.MetricName")) else {
                break;
            };
            let value = parse_f64(required(query, &format!("{prefix}.Value"))?, "Value")?;
            let timestamp_ms = query
                .get(&format!("{prefix}.Timestamp"))
                .map(parse_timestamp)
                .transpose()?
                .unwrap_or_else(now_ms);
            let unit = query
                .get(&format!("{prefix}.Unit"))
                .map(|unit| {
                    MetricUnit::parse(unit).ok_or_else(|| {
                        MonitoringError::InvalidParameter(format!("unsupported metric unit {unit}"))
                    })
                })
                .transpose()?;
            let storage_resolution = query
                .get(&format!("{prefix}.StorageResolution"))
                .map(|value| parse_u16(value, "StorageResolution"))
                .transpose()?
                .unwrap_or(60);
            observations.push(MetricObservation {
                account_id: scope.account_id.clone(),
                region: scope.region.clone(),
                namespace: namespace.clone(),
                metric_name: metric_name.to_owned(),
                dimensions: parse_dimensions(query, &format!("{prefix}.Dimensions.member"))?,
                timestamp_ms,
                value,
                unit,
                storage_resolution,
                origin: MetricOrigin::PublicPutMetricData,
                correlation_id: request_id.to_owned(),
            });
        }
        if observations.is_empty() {
            return Err(MonitoringError::InvalidParameter(
                "MetricData must contain at least one member".into(),
            ));
        }
        if query
            .get(&format!(
                "MetricData.member.{}.MetricName",
                MAX_METRIC_DATA + 1
            ))
            .is_some()
        {
            return Err(MonitoringError::InvalidParameter(
                "MetricData exceeds the supported batch limit".into(),
            ));
        }
        self.domain.commit(observations)
    }

    fn list_metrics(
        &self,
        query: &QueryRequest,
        scope: &ScopeKey,
    ) -> Result<String, MonitoringError> {
        let metrics = self
            .domain
            .list(scope, query.get("Namespace"), query.get("MetricName"))?;
        let members = metrics.iter().map(metric_xml).collect::<Vec<_>>().join("");
        Ok(format!("<Metrics>{members}</Metrics>"))
    }

    fn get_metric_statistics(
        &self,
        query: &QueryRequest,
        scope: &ScopeKey,
    ) -> Result<String, MonitoringError> {
        let namespace = required(query, "Namespace")?.to_owned();
        let metric_name = required(query, "MetricName")?.to_owned();
        let start_ms = parse_timestamp(required(query, "StartTime")?)?;
        let end_ms = parse_timestamp(required(query, "EndTime")?)?;
        if start_ms >= end_ms {
            return Err(MonitoringError::InvalidParameter(
                "StartTime must precede EndTime".into(),
            ));
        }
        let period = parse_u64(required(query, "Period")?, "Period")?;
        if period == 0 {
            return Err(MonitoringError::InvalidParameter(
                "Period must be positive".into(),
            ));
        }
        let statistics = query.list("Statistics.member");
        if statistics.is_empty() {
            return Err(MonitoringError::InvalidParameter(
                "Statistics must contain at least one member".into(),
            ));
        }
        let allowed = ["Sum", "SampleCount", "Minimum", "Maximum", "Average"];
        if statistics
            .iter()
            .any(|statistic| !allowed.contains(&statistic.as_str()))
        {
            return Err(MonitoringError::InvalidParameter(
                "unsupported statistic".into(),
            ));
        }
        let key = MetricKey {
            namespace,
            metric_name: metric_name.clone(),
            dimensions: parse_dimensions(query, "Dimensions.member")?,
        };
        let points = self
            .domain
            .points(scope, &key, start_ms, end_ms, query.get("Unit"))?;
        let period_ms = i64::try_from(period)
            .ok()
            .and_then(|period| period.checked_mul(1_000))
            .ok_or_else(|| MonitoringError::InvalidParameter("Period is too large".into()))?;
        let mut buckets: BTreeMap<(i64, String), Vec<MetricPoint>> = BTreeMap::new();
        for point in points {
            let bucket = point.timestamp_ms.div_euclid(period_ms) * period_ms;
            let unit = point
                .unit
                .map(MetricUnit::as_str)
                .unwrap_or("None")
                .to_owned();
            buckets.entry((bucket, unit)).or_default().push(point);
        }
        let mut datapoints = String::new();
        for ((timestamp_ms, _), points) in buckets.into_iter().rev() {
            let values: Vec<f64> = points.iter().map(|point| point.value).collect();
            let sum: f64 = values.iter().sum();
            let count = values.len() as f64;
            let minimum = values.iter().copied().fold(f64::INFINITY, f64::min);
            let maximum = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let unit = points
                .first()
                .and_then(|point| point.unit.map(MetricUnit::as_str))
                .unwrap_or("None");
            let mut member = text_element("Timestamp", &format_timestamp(timestamp_ms)?);
            for statistic in &statistics {
                let value = match statistic.as_str() {
                    "Sum" => sum,
                    "SampleCount" => count,
                    "Minimum" => minimum,
                    "Maximum" => maximum,
                    "Average" => sum / count,
                    _ => unreachable!(),
                };
                member.push_str(&text_element(statistic, &number_text(value)));
            }
            member.push_str(&text_element("Unit", unit));
            datapoints.push_str(&format!("<member>{member}</member>"));
        }
        Ok(format!(
            "<Label>{}</Label><Datapoints>{datapoints}</Datapoints>",
            xml_escape(&metric_name)
        ))
    }
}

pub fn register(registry: &Arc<ServiceRegistry>) {
    let domain = Arc::new(MonitoringDomain::default());
    let (sender, mut receiver) = mpsc::channel::<Vec<MetricObservation>>(CHANNEL_CAPACITY);
    let worker_domain = domain.clone();
    tokio::spawn(async move {
        while let Some(observations) = receiver.recv().await {
            let _ = worker_domain.commit(observations);
        }
    });
    let handler: Arc<dyn NativeHandler> = Arc::new(MonitoringHandler { domain });
    let sink: Arc<dyn MetricSink> = Arc::new(MonitoringMetricSink { sender });
    let mut metadata =
        ServiceMetadata::new(AwsProtocol::Json10, Some("GraniteServiceVersion20100801"));
    metadata.known_actions = vec![
        "PutMetricData".into(),
        "ListMetrics".into(),
        "GetMetricStatistics".into(),
    ];
    registry.register_native_with_metric_sink(
        ServiceName::new("monitoring"),
        metadata,
        handler,
        sink,
    );
}

#[derive(Debug, thiserror::Error)]
enum MonitoringError {
    #[error("{0}")]
    InvalidAction(String),
    #[error("{0}")]
    InvalidParameter(String),
    #[error("{0}")]
    Internal(String),
}

fn error_response(error: MonitoringError, request_id: &str, protocol: AwsProtocol) -> Response {
    let (code, status) = match error {
        MonitoringError::InvalidAction(_) => ("InvalidAction", 400),
        MonitoringError::InvalidParameter(_) => ("InvalidParameterValue", 400),
        MonitoringError::Internal(_) => ("InternalServiceError", 500),
    };
    let mut error = AwsError::new(code, error.to_string(), status).with_request_id(request_id);
    if protocol == AwsProtocol::Query {
        error = error.with_xml_namespace(XMLNS);
    }
    error.render(protocol).into_response()
}

fn json_response(body: Value, request_id: &str) -> Response {
    Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "application/x-amz-json-1.0")
        .header("x-amzn-RequestId", request_id)
        .body(Body::from(body.to_string()))
        .expect("Monitoring JSON response is valid")
}

fn success_response(action: &str, body: &str, request_id: &str) -> Response {
    let result = if body.is_empty() {
        String::new()
    } else {
        format!("<{action}Result>{body}</{action}Result>")
    };
    let xml = format!(
        "<{action}Response xmlns=\"{XMLNS}\">{result}<ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata></{action}Response>",
        xml_escape(request_id)
    );
    Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "text/xml")
        .header("x-amzn-RequestId", request_id)
        .body(Body::from(xml))
        .expect("Monitoring XML response is valid")
}

fn json_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value.as_object().and_then(|object| {
        object.get(name).or_else(|| {
            let mut camel = name.to_owned();
            camel.get_mut(0..1)?.make_ascii_lowercase();
            object.get(&camel)
        })
    })
}

fn json_required<'a>(value: &'a Value, name: &str) -> Result<&'a Value, MonitoringError> {
    json_field(value, name)
        .ok_or_else(|| MonitoringError::InvalidParameter(format!("{name} is required")))
}

fn json_string<'a>(value: &'a Value, name: &str) -> Result<&'a str, MonitoringError> {
    json_required(value, name)?
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| MonitoringError::InvalidParameter(format!("{name} must be a string")))
}

fn parse_json_timestamp(value: &Value) -> Result<i64, MonitoringError> {
    if let Some(seconds) = value.as_f64() {
        let milliseconds = seconds * 1_000.0;
        if milliseconds.is_finite()
            && milliseconds >= i64::MIN as f64
            && milliseconds <= i64::MAX as f64
        {
            return Ok(milliseconds.round() as i64);
        }
    }
    value
        .as_str()
        .ok_or_else(|| MonitoringError::InvalidParameter("timestamp is invalid".into()))
        .and_then(parse_timestamp)
}

fn parse_json_dimensions(
    value: Option<&Value>,
) -> Result<BTreeMap<String, String>, MonitoringError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let dimensions = value
        .as_array()
        .ok_or_else(|| MonitoringError::InvalidParameter("Dimensions must be a list".into()))?;
    if dimensions.len() > MAX_DIMENSIONS {
        return Err(MonitoringError::InvalidParameter(
            "too many metric dimensions".into(),
        ));
    }
    let mut result = BTreeMap::new();
    for dimension in dimensions {
        let name = json_string(dimension, "Name")?;
        let value = json_string(dimension, "Value")?;
        if result.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(MonitoringError::InvalidParameter(
                "dimension names must be unique".into(),
            ));
        }
    }
    Ok(result)
}

fn validate_observation(observation: &MetricObservation) -> Result<(), MonitoringError> {
    if observation.account_id.is_empty()
        || observation.region.is_empty()
        || observation.namespace.is_empty()
        || observation.namespace.len() > 255
        || observation.metric_name.is_empty()
        || observation.metric_name.len() > 255
        || !observation.value.is_finite()
        || observation.dimensions.len() > MAX_DIMENSIONS
        || !matches!(observation.storage_resolution, 1 | 60)
    {
        return Err(MonitoringError::InvalidParameter(
            "metric observation is outside supported limits".into(),
        ));
    }
    if observation.dimensions.iter().any(|(name, value)| {
        name.is_empty() || name.len() > 255 || value.is_empty() || value.len() > 1_024
    }) {
        return Err(MonitoringError::InvalidParameter(
            "metric dimensions are outside supported limits".into(),
        ));
    }
    if observation.origin == MetricOrigin::PublicPutMetricData
        && observation.namespace.starts_with("AWS/")
    {
        return Err(MonitoringError::InvalidParameter(
            "public metrics cannot use a reserved AWS namespace".into(),
        ));
    }
    let current_time = now_ms();
    let oldest = current_time.saturating_sub(14 * 24 * 60 * 60 * 1_000);
    let newest = current_time.saturating_add(2 * 60 * 60 * 1_000);
    if observation.timestamp_ms < oldest || observation.timestamp_ms > newest {
        return Err(MonitoringError::InvalidParameter(
            "metric timestamp must be within the supported CloudWatch window".into(),
        ));
    }
    Ok(())
}

fn metric_xml(key: &MetricKey) -> String {
    let dimensions = key
        .dimensions
        .iter()
        .map(|(name, value)| {
            format!(
                "<member>{}{}</member>",
                text_element("Name", name),
                text_element("Value", value)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<member>{}{}<Dimensions>{dimensions}</Dimensions></member>",
        text_element("Namespace", &key.namespace),
        text_element("MetricName", &key.metric_name)
    )
}

fn parse_dimensions(
    query: &QueryRequest,
    prefix: &str,
) -> Result<BTreeMap<String, String>, MonitoringError> {
    let mut dimensions = BTreeMap::new();
    for index in 1..=MAX_DIMENSIONS {
        let name_key = format!("{prefix}.{index}.Name");
        let value_key = format!("{prefix}.{index}.Value");
        match (query.get(&name_key), query.get(&value_key)) {
            (None, None) => break,
            (Some(name), Some(value)) if !name.is_empty() && !value.is_empty() => {
                if dimensions
                    .insert(name.to_owned(), value.to_owned())
                    .is_some()
                {
                    return Err(MonitoringError::InvalidParameter(
                        "dimension names must be unique".into(),
                    ));
                }
            }
            _ => {
                return Err(MonitoringError::InvalidParameter(
                    "dimension name and value are both required".into(),
                ))
            }
        }
    }
    if query
        .get(&format!("{prefix}.{}.Name", MAX_DIMENSIONS + 1))
        .is_some()
    {
        return Err(MonitoringError::InvalidParameter(
            "too many metric dimensions".into(),
        ));
    }
    Ok(dimensions)
}

fn required<'a>(query: &'a QueryRequest, key: &str) -> Result<&'a str, MonitoringError> {
    query.get(key).ok_or_else(|| {
        MonitoringError::InvalidParameter(format!("required parameter {key} is missing"))
    })
}

fn parse_f64(value: &str, name: &str) -> Result<f64, MonitoringError> {
    value
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
        .ok_or_else(|| MonitoringError::InvalidParameter(format!("{name} must be a finite number")))
}

fn parse_u16(value: &str, name: &str) -> Result<u16, MonitoringError> {
    value
        .parse::<u16>()
        .map_err(|_| MonitoringError::InvalidParameter(format!("{name} must be an integer")))
}

fn parse_u64(value: &str, name: &str) -> Result<u64, MonitoringError> {
    value
        .parse::<u64>()
        .map_err(|_| MonitoringError::InvalidParameter(format!("{name} must be an integer")))
}

fn parse_timestamp(value: &str) -> Result<i64, MonitoringError> {
    let timestamp = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| MonitoringError::InvalidParameter("timestamp must be RFC3339".into()))?;
    i64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000).map_err(|_| {
        MonitoringError::InvalidParameter("timestamp is outside supported range".into())
    })
}

fn format_timestamp(timestamp_ms: i64) -> Result<String, MonitoringError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(timestamp_ms) * 1_000_000)
        .map_err(|_| {
            MonitoringError::Internal("stored timestamp is outside supported range".into())
        })?
        .format(&Rfc3339)
        .map_err(|_| MonitoringError::Internal("failed to format stored timestamp".into()))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn number_text(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        value.to_string()
    }
}

fn text_element(name: &str, value: &str) -> String {
    format!("<{name}>{}</{name}>", xml_escape(value))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Debug)]
struct QueryRequest {
    params: BTreeMap<String, String>,
}

impl QueryRequest {
    fn parse(body: &[u8]) -> Self {
        let text = String::from_utf8_lossy(body);
        let params = text
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                (form_decode(key), form_decode(value))
            })
            .collect();
        Self { params }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.params
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    fn list(&self, prefix: &str) -> Vec<String> {
        let mut values = Vec::new();
        for index in 1.. {
            let Some(value) = self.get(&format!("{prefix}.{index}")) else {
                break;
            };
            values.push(value.to_owned());
        }
        values
    }
}

fn form_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                    output.push((high << 4) | low);
                    index += 3;
                } else {
                    output.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ACCOUNT: &str = "000000000000";
    const TEST_REGION: &str = "us-east-1";
    const TEST_NAMESPACE: &str = "Localcloud/Monitoring/A16";
    const TEST_METRIC: &str = "UnitOrderMetric";

    fn a16_handler() -> (MonitoringHandler, ScopeKey, i64) {
        let base_ms = now_ms().div_euclid(60_000).saturating_sub(3) * 60_000;
        let domain = Arc::new(MonitoringDomain::default());
        let observations = [
            (base_ms + 10_000, 7.0, MetricUnit::Count),
            (base_ms + 20_000, 11.0, MetricUnit::Seconds),
            (base_ms + 70_000, 3.0, MetricUnit::Count),
        ]
        .into_iter()
        .map(|(timestamp_ms, value, unit)| MetricObservation {
            account_id: TEST_ACCOUNT.to_owned(),
            region: TEST_REGION.to_owned(),
            namespace: TEST_NAMESPACE.to_owned(),
            metric_name: TEST_METRIC.to_owned(),
            dimensions: BTreeMap::new(),
            timestamp_ms,
            value,
            unit: Some(unit),
            storage_resolution: 60,
            origin: MetricOrigin::PublicPutMetricData,
            correlation_id: "a16-test".to_owned(),
        })
        .collect();
        domain.commit(observations).expect("A16 fixtures are valid");
        (
            MonitoringHandler { domain },
            ScopeKey {
                account_id: TEST_ACCOUNT.to_owned(),
                region: TEST_REGION.to_owned(),
            },
            base_ms,
        )
    }

    #[test]
    fn statistics_units_output_json() {
        let (handler, scope, base_ms) = a16_handler();
        let response = handler
            .get_metric_statistics_json(
                &json!({
                    "Namespace": TEST_NAMESPACE,
                    "MetricName": TEST_METRIC,
                    "StartTime": base_ms as f64 / 1_000.0,
                    "EndTime": (base_ms + 120_000) as f64 / 1_000.0,
                    "Period": 60,
                    "Statistics": ["Sum", "SampleCount"]
                }),
                &scope,
            )
            .expect("JSON statistics should succeed");

        let datapoints = response["Datapoints"]
            .as_array()
            .expect("Datapoints must be an array");
        let timestamps = datapoints
            .iter()
            .map(|point| {
                (point["Timestamp"]
                    .as_f64()
                    .expect("Timestamp must be numeric")
                    * 1_000.0)
                    .round() as i64
            })
            .collect::<Vec<_>>();
        assert_eq!(timestamps, vec![base_ms + 60_000, base_ms, base_ms]);

        let observed = datapoints
            .iter()
            .map(|point| {
                let timestamp_ms = (point["Timestamp"].as_f64().unwrap() * 1_000.0).round() as i64;
                let unit = point["Unit"].as_str().unwrap().to_owned();
                let sum = point["Sum"].as_f64().unwrap();
                let count = point["SampleCount"].as_f64().unwrap();
                ((timestamp_ms, unit), (sum, count))
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(observed.len(), 3);
        assert_eq!(
            observed.get(&(base_ms, "Count".to_owned())),
            Some(&(7.0, 1.0))
        );
        assert_eq!(
            observed.get(&(base_ms, "Seconds".to_owned())),
            Some(&(11.0, 1.0))
        );
        assert_eq!(
            observed.get(&(base_ms + 60_000, "Count".to_owned())),
            Some(&(3.0, 1.0))
        );
    }

    #[test]
    fn statistics_units_output_query() {
        let (handler, scope, base_ms) = a16_handler();
        let query = QueryRequest::parse(
            format!(
                "Namespace={TEST_NAMESPACE}&MetricName={TEST_METRIC}&StartTime={}&EndTime={}&Period=60&Statistics.member.1=Sum&Statistics.member.2=SampleCount",
                format_timestamp(base_ms).unwrap(),
                format_timestamp(base_ms + 120_000).unwrap()
            )
            .as_bytes(),
        );
        let body = handler
            .get_metric_statistics(&query, &scope)
            .expect("Query statistics should succeed");

        let later_timestamp =
            text_element("Timestamp", &format_timestamp(base_ms + 60_000).unwrap());
        let earlier_timestamp = text_element("Timestamp", &format_timestamp(base_ms).unwrap());
        assert!(body.find(&later_timestamp).unwrap() < body.find(&earlier_timestamp).unwrap());
        assert_eq!(body.matches("<member>").count(), 3);
        assert!(body.contains(&format!(
            "<member>{}<Sum>7</Sum><SampleCount>1</SampleCount><Unit>Count</Unit></member>",
            earlier_timestamp
        )));
        assert!(body.contains(&format!(
            "<member>{}<Sum>11</Sum><SampleCount>1</SampleCount><Unit>Seconds</Unit></member>",
            earlier_timestamp
        )));
        assert!(body.contains(&format!(
            "<member>{}<Sum>3</Sum><SampleCount>1</SampleCount><Unit>Count</Unit></member>",
            later_timestamp
        )));
    }
}
