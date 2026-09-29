use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use http::Method;
use localcloud_core::error_mapping::AwsError;
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::integration::metrics::{
    EmitOutcome, MetricObservation, MetricOrigin, MetricSink,
};
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::mpsc;

use crate::domain::{
    deduplicate_statistics, DomainError, MetricDomain, Sample, Statistic,
};
use crate::query::{response_envelope, text_element, QueryRequest, XMLNS};

const CHANNEL_CAPACITY: usize = 64;
const ACTIONS: [&str; 3] = ["PutMetricData", "ListMetrics", "GetMetricStatistics"];

struct MonitoringHandler {
    domain: Arc<MetricDomain>,
}

struct MonitoringMetricSink {
    domain: Arc<MetricDomain>,
    sender: mpsc::Sender<Vec<MetricObservation>>,
}

impl MetricSink for MonitoringMetricSink {
    fn try_emit(&self, observations: Vec<MetricObservation>) -> EmitOutcome {
        if self.domain.validate_batch(&observations).is_err() {
            return EmitOutcome::Dropped;
        }
        match self.sender.try_send(observations) {
            Ok(()) => EmitOutcome::Accepted,
            Err(mpsc::error::TrySendError::Full(_)) => EmitOutcome::Full,
            Err(mpsc::error::TrySendError::Closed(_)) => EmitOutcome::Unavailable,
        }
    }
}

#[async_trait]
impl NativeHandler for MonitoringHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        match self.handle_request(&request) {
            Ok((action, body)) => xml_response(&response_envelope(
                &action,
                &body,
                &request.request_id,
            )),
            Err(error) => error.into_response(&request.request_id),
        }
    }
}

impl MonitoringHandler {
    fn handle_request(
        &self,
        request: &ServiceRequest,
    ) -> Result<(String, String), MonitoringError> {
        if request.method != Method::POST || request.uri.path() != "/" {
            return Err(MonitoringError::InvalidParameter(
                "CloudWatch Monitoring requires POST /".to_string(),
            ));
        }
        let valid_content_type = request
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .to_ascii_lowercase()
                    .starts_with("application/x-www-form-urlencoded")
            })
            .unwrap_or(false);
        if !valid_content_type {
            return Err(MonitoringError::InvalidParameter(
                "Content-Type must be application/x-www-form-urlencoded".to_string(),
            ));
        }

        let query = QueryRequest::parse(&request.body);
        let action = query
            .get("Action")
            .ok_or_else(|| MonitoringError::MissingParameter("Action".to_string()))?;
        let body = match action {
            "PutMetricData" => self.put_metric_data(request, &query)?,
            "ListMetrics" => self.list_metrics(request, &query),
            "GetMetricStatistics" => self.get_metric_statistics(request, &query)?,
            _ => return Err(MonitoringError::InvalidAction(action.to_string())),
        };
        Ok((action.to_string(), body))
    }

    fn put_metric_data(
        &self,
        request: &ServiceRequest,
        query: &QueryRequest,
    ) -> Result<String, MonitoringError> {
        let namespace = required(query, "Namespace")?;
        let indices = query.indices("MetricData.member.");
        if indices.is_empty() || indices.len() > 1000 {
            return Err(MonitoringError::InvalidParameter(
                "MetricData must contain between 1 and 1000 members".to_string(),
            ));
        }

        let mut observations = Vec::with_capacity(indices.len());
        for index in indices {
            let prefix = format!("MetricData.member.{index}");
            let metric_name = required(query, &format!("{prefix}.MetricName"))?;
            let value = parse_f64(required(query, &format!("{prefix}.Value"))?, "Value")?;
            let timestamp_ms = match query.get(&format!("{prefix}.Timestamp")) {
                Some(value) => parse_timestamp(value, "Timestamp")?,
                None => now_timestamp_ms()?,
            };
            let unit = query.get(&format!("{prefix}.Unit")).map(str::to_string);
            let storage_resolution = match query.get(&format!("{prefix}.StorageResolution")) {
                Some(value) => parse_u16(value, "StorageResolution")?,
                None => 60,
            };
            let dimensions = parse_dimensions(query, &format!("{prefix}.Dimensions.member."))?;
            observations.push(MetricObservation {
                account_id: request.account_id.clone(),
                region: request.region.clone(),
                namespace: namespace.to_string(),
                metric_name: metric_name.to_string(),
                dimensions,
                timestamp_ms,
                value,
                unit,
                storage_resolution,
                origin: MetricOrigin::PublicPutMetricData,
                correlation_id: request.request_id.clone(),
            });
        }
        self.domain.commit(observations)?;
        Ok(String::new())
    }

    fn list_metrics(&self, request: &ServiceRequest, query: &QueryRequest) -> String {
        let series = self.domain.list_series(
            &request.account_id,
            &request.region,
            query.get("Namespace"),
            query.get("MetricName"),
        );
        let mut metrics = String::from("<Metrics>");
        for key in series {
            metrics.push_str("<member>");
            metrics.push_str(&text_element("Namespace", &key.namespace));
            metrics.push_str(&text_element("MetricName", &key.metric_name));
            metrics.push_str("<Dimensions>");
            for (name, value) in key.dimensions {
                metrics.push_str("<member>");
                metrics.push_str(&text_element("Name", &name));
                metrics.push_str(&text_element("Value", &value));
                metrics.push_str("</member>");
            }
            metrics.push_str("</Dimensions></member>");
        }
        metrics.push_str("</Metrics>");
        metrics
    }

    fn get_metric_statistics(
        &self,
        request: &ServiceRequest,
        query: &QueryRequest,
    ) -> Result<String, MonitoringError> {
        let namespace = required(query, "Namespace")?;
        let metric_name = required(query, "MetricName")?;
        let start_ms = parse_timestamp(required(query, "StartTime")?, "StartTime")?;
        let end_ms = parse_timestamp(required(query, "EndTime")?, "EndTime")?;
        if start_ms >= end_ms {
            return Err(MonitoringError::InvalidParameter(
                "StartTime must be before EndTime".to_string(),
            ));
        }
        let period_seconds = parse_i64(required(query, "Period")?, "Period")?;
        if period_seconds <= 0 {
            return Err(MonitoringError::InvalidParameter(
                "Period must be greater than zero".to_string(),
            ));
        }
        let period_ms = period_seconds
            .checked_mul(1000)
            .ok_or_else(|| MonitoringError::InvalidParameter("Period is too large".to_string()))?;

        let statistic_indices = query.indices("Statistics.member.");
        if statistic_indices.is_empty() {
            return Err(MonitoringError::MissingParameter(
                "Statistics.member.1".to_string(),
            ));
        }
        let mut statistics = Vec::with_capacity(statistic_indices.len());
        for index in statistic_indices {
            let value = required(query, &format!("Statistics.member.{index}"))?;
            statistics.push(Statistic::parse(value).ok_or_else(|| {
                MonitoringError::InvalidParameter(format!("unsupported statistic {value}"))
            })?);
        }
        let statistics = deduplicate_statistics(statistics);
        let dimensions = parse_dimensions(query, "Dimensions.member.")?;
        let samples = self
            .domain
            .series(
                &request.account_id,
                &request.region,
                namespace,
                metric_name,
                &dimensions,
            )
            .map(|series| series.samples)
            .unwrap_or_default();
        let datapoints = aggregate(samples, start_ms, end_ms, period_ms);

        let mut body = text_element("Label", metric_name);
        body.push_str("<Datapoints>");
        for (timestamp_ms, aggregate) in datapoints {
            body.push_str("<member>");
            body.push_str(&text_element(
                "Timestamp",
                &format_timestamp(timestamp_ms)?,
            ));
            for statistic in &statistics {
                body.push_str(&text_element(
                    statistic.as_str(),
                    &aggregate.value(*statistic).to_string(),
                ));
            }
            body.push_str(&text_element(
                "Unit",
                aggregate.unit.as_deref().unwrap_or("None"),
            ));
            body.push_str("</member>");
        }
        body.push_str("</Datapoints>");
        Ok(body)
    }
}

#[derive(Debug)]
struct Aggregate {
    sum: f64,
    count: u64,
    minimum: f64,
    maximum: f64,
    unit: Option<String>,
}

impl Aggregate {
    fn new(sample: &Sample) -> Self {
        Self {
            sum: sample.value,
            count: 1,
            minimum: sample.value,
            maximum: sample.value,
            unit: sample.unit.clone(),
        }
    }

    fn add(&mut self, sample: &Sample) {
        self.sum += sample.value;
        self.count += 1;
        self.minimum = self.minimum.min(sample.value);
        self.maximum = self.maximum.max(sample.value);
    }

    fn value(&self, statistic: Statistic) -> f64 {
        match statistic {
            Statistic::Sum => self.sum,
            Statistic::SampleCount => self.count as f64,
            Statistic::Minimum => self.minimum,
            Statistic::Maximum => self.maximum,
            Statistic::Average => self.sum / self.count as f64,
        }
    }
}

fn aggregate(
    mut samples: Vec<Sample>,
    start_ms: i64,
    end_ms: i64,
    period_ms: i64,
) -> BTreeMap<i64, Aggregate> {
    samples.sort_by_key(|sample| sample.timestamp_ms);
    let mut buckets = BTreeMap::new();
    for sample in samples {
        if sample.timestamp_ms < start_ms || sample.timestamp_ms >= end_ms {
            continue;
        }
        let bucket = start_ms + ((sample.timestamp_ms - start_ms) / period_ms) * period_ms;
        buckets
            .entry(bucket)
            .and_modify(|aggregate: &mut Aggregate| aggregate.add(&sample))
            .or_insert_with(|| Aggregate::new(&sample));
    }
    buckets
}

fn parse_dimensions(
    query: &QueryRequest,
    prefix: &str,
) -> Result<BTreeMap<String, String>, MonitoringError> {
    let mut dimensions = BTreeMap::new();
    for index in query.indices(prefix) {
        let name = required(query, &format!("{prefix}{index}.Name"))?;
        let value = required(query, &format!("{prefix}{index}.Value"))?;
        if dimensions.insert(name.to_string(), value.to_string()).is_some() {
            return Err(MonitoringError::InvalidParameter(format!(
                "duplicate dimension {name}"
            )));
        }
    }
    Ok(dimensions)
}

fn required<'a>(query: &'a QueryRequest, key: &str) -> Result<&'a str, MonitoringError> {
    query
        .get(key)
        .ok_or_else(|| MonitoringError::MissingParameter(key.to_string()))
}

fn parse_f64(value: &str, field: &str) -> Result<f64, MonitoringError> {
    value
        .parse::<f64>()
        .ok()
        .filter(|parsed| parsed.is_finite())
        .ok_or_else(|| MonitoringError::InvalidParameter(format!("{field} must be finite")))
}

fn parse_i64(value: &str, field: &str) -> Result<i64, MonitoringError> {
    value.parse::<i64>().map_err(|_| {
        MonitoringError::InvalidParameter(format!("{field} must be a valid integer"))
    })
}

fn parse_u16(value: &str, field: &str) -> Result<u16, MonitoringError> {
    value.parse::<u16>().map_err(|_| {
        MonitoringError::InvalidParameter(format!("{field} must be a valid integer"))
    })
}

fn parse_timestamp(value: &str, field: &str) -> Result<i64, MonitoringError> {
    let timestamp = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        MonitoringError::InvalidParameter(format!("{field} must be an RFC3339 timestamp"))
    })?;
    timestamp_ms(timestamp)
}

fn now_timestamp_ms() -> Result<i64, MonitoringError> {
    timestamp_ms(OffsetDateTime::now_utc())
}

fn timestamp_ms(timestamp: OffsetDateTime) -> Result<i64, MonitoringError> {
    i64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| MonitoringError::InvalidParameter("timestamp is out of range".to_string()))
}

fn format_timestamp(timestamp_ms: i64) -> Result<String, MonitoringError> {
    let timestamp = OffsetDateTime::from_unix_timestamp_nanos(i128::from(timestamp_ms) * 1_000_000)
        .map_err(|_| MonitoringError::Internal("stored timestamp is out of range".to_string()))?;
    timestamp
        .format(&Rfc3339)
        .map_err(|error| MonitoringError::Internal(error.to_string()))
}

fn xml_response(body: &str) -> Response {
    http::Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "application/xml")
        .body(Body::from(body.to_string()))
        .expect("CloudWatch XML response is valid")
}

#[derive(Debug, Error)]
enum MonitoringError {
    #[error("missing required parameter {0}")]
    MissingParameter(String),
    #[error("{0}")]
    InvalidParameter(String),
    #[error("unknown action {0}")]
    InvalidAction(String),
    #[error("{0}")]
    Domain(#[from] DomainError),
    #[error("{0}")]
    Internal(String),
}

impl MonitoringError {
    fn into_response(self, request_id: &str) -> Response {
        let (code, status) = match &self {
            Self::MissingParameter(_) => ("MissingParameter", 400),
            Self::InvalidParameter(_) | Self::Domain(_) => ("InvalidParameterValue", 400),
            Self::InvalidAction(_) => ("InvalidAction", 400),
            Self::Internal(_) => ("InternalError", 500),
        };
        AwsError::new(code, self.to_string(), status)
            .with_request_id(request_id)
            .with_xml_namespace(XMLNS)
            .render(AwsProtocol::Query)
            .into_response()
    }
}

async fn persist_worker(
    domain: Arc<MetricDomain>,
    mut receiver: mpsc::Receiver<Vec<MetricObservation>>,
) {
    while let Some(observations) = receiver.recv().await {
        let _ = domain.commit(observations);
    }
}

pub fn register(registry: &Arc<ServiceRegistry>) {
    let domain = Arc::new(MetricDomain::default());
    let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
    tokio::spawn(persist_worker(domain.clone(), receiver));

    let handler: Arc<dyn NativeHandler> = Arc::new(MonitoringHandler {
        domain: domain.clone(),
    });
    let sink: Arc<dyn MetricSink> = Arc::new(MonitoringMetricSink { domain, sender });
    let mut metadata = ServiceMetadata::new(AwsProtocol::Query, None);
    metadata.known_actions = ACTIONS.iter().map(|action| (*action).to_string()).collect();
    registry.register_native_with_metric_sink(
        ServiceName::new("monitoring"),
        metadata,
        handler,
        sink,
    );
}
