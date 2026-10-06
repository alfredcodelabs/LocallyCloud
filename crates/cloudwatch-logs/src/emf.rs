//! CloudWatch embedded metric format (EMF) extraction for ingested log events.

use std::collections::BTreeMap;

use locallycloud_core::integration::metrics::{MetricObservation, MetricOrigin, MetricUnit};
use serde_json::{Map, Value};

use crate::model::{GroupKey, StoredEvent};

const MAX_METRICS_PER_DIRECTIVE: usize = 100;
const MAX_DIMENSIONS_PER_SET: usize = 30;
const MAX_VALUES_PER_METRIC: usize = 100;
const MAX_DATAPOINTS_PER_EVENT: usize = 10_000;
const MAX_NAME_LEN: usize = 255;
const MAX_DIMENSION_NAME_LEN: usize = 250;
const MAX_DIMENSION_VALUE_LEN: usize = 1_024;
const PAST_WINDOW_MS: i64 = 14 * 24 * 60 * 60 * 1_000;
const FUTURE_WINDOW_MS: i64 = 2 * 60 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EmfMetric {
    pub namespace: String,
    pub name: String,
    pub dimensions: BTreeMap<String, String>,
    pub values: Vec<f64>,
    pub unit: MetricUnit,
    pub storage_resolution: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EmfDocument {
    pub timestamp_ms: Option<i64>,
    pub metrics: Vec<EmfMetric>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmfError {
    NotEmf,
    Invalid(&'static str),
}

/// Resolves every EMF datapoint carried by `events`; invalid or non-EMF events yield nothing.
pub(crate) fn observations_for_events(
    group_key: &GroupKey,
    events: &[StoredEvent],
    now_ms: i64,
) -> Vec<MetricObservation> {
    events
        .iter()
        .flat_map(|event| observations_for_event(group_key, event, now_ms))
        .collect()
}

fn observations_for_event(
    group_key: &GroupKey,
    event: &StoredEvent,
    now_ms: i64,
) -> Vec<MetricObservation> {
    let Ok(document) = parse(&event.message) else {
        return Vec::new();
    };
    let timestamp_ms = document.timestamp_ms.unwrap_or(event.timestamp_ms);
    if timestamp_ms < now_ms.saturating_sub(PAST_WINDOW_MS)
        || timestamp_ms > now_ms.saturating_add(FUTURE_WINDOW_MS)
    {
        return Vec::new();
    }
    let mut observations = Vec::new();
    for metric in document.metrics {
        for value in metric.values {
            observations.push(MetricObservation {
                account_id: group_key.scope.account_id.clone(),
                region: group_key.scope.region.clone(),
                namespace: metric.namespace.clone(),
                metric_name: metric.name.clone(),
                dimensions: metric.dimensions.clone(),
                timestamp_ms,
                value,
                unit: Some(metric.unit),
                storage_resolution: metric.storage_resolution,
                origin: MetricOrigin::CloudWatchLogs,
                correlation_id: event.id.clone(),
            });
        }
    }
    observations
}

pub(crate) fn parse(message: &str) -> Result<EmfDocument, EmfError> {
    if !message.contains("\"_aws\"") {
        return Err(EmfError::NotEmf);
    }
    let Ok(Value::Object(root)) = serde_json::from_str::<Value>(message) else {
        return Err(EmfError::NotEmf);
    };
    let metadata = root
        .get("_aws")
        .ok_or(EmfError::NotEmf)?
        .as_object()
        .ok_or(EmfError::Invalid("_aws must be an object"))?;
    let timestamp_ms = metadata
        .get("Timestamp")
        .map(|timestamp| {
            timestamp
                .as_i64()
                .ok_or(EmfError::Invalid("Timestamp must be an integer"))
        })
        .transpose()?;
    let directives = metadata
        .get("CloudWatchMetrics")
        .and_then(Value::as_array)
        .ok_or(EmfError::Invalid("CloudWatchMetrics must be an array"))?;
    let mut metrics = Vec::new();
    let mut datapoints = 0_usize;
    for directive in directives {
        let directive = directive
            .as_object()
            .ok_or(EmfError::Invalid("MetricDirective must be an object"))?;
        let namespace = directive
            .get("Namespace")
            .and_then(Value::as_str)
            .filter(|namespace| valid_name(namespace, MAX_NAME_LEN))
            .ok_or(EmfError::Invalid("Namespace is invalid"))?;
        let dimension_sets = dimension_sets(directive.get("Dimensions"), &root)?;
        let definitions = directive
            .get("Metrics")
            .and_then(Value::as_array)
            .ok_or(EmfError::Invalid("Metrics must be an array"))?;
        if definitions.len() > MAX_METRICS_PER_DIRECTIVE {
            return Err(EmfError::Invalid("too many metrics in a directive"));
        }
        for definition in definitions {
            let definition = MetricDefinition::parse(definition)?;
            let values = metric_values(root.get(definition.name))?;
            for dimensions in &dimension_sets {
                datapoints = datapoints.saturating_add(values.len());
                if datapoints > MAX_DATAPOINTS_PER_EVENT {
                    return Err(EmfError::Invalid("too many datapoints in one event"));
                }
                metrics.push(EmfMetric {
                    namespace: namespace.to_owned(),
                    name: definition.name.to_owned(),
                    dimensions: dimensions.clone(),
                    values: values.clone(),
                    unit: definition.unit,
                    storage_resolution: definition.storage_resolution,
                });
            }
        }
    }
    Ok(EmfDocument {
        timestamp_ms,
        metrics,
    })
}

struct MetricDefinition<'a> {
    name: &'a str,
    unit: MetricUnit,
    storage_resolution: u16,
}

impl<'a> MetricDefinition<'a> {
    fn parse(definition: &'a Value) -> Result<Self, EmfError> {
        let definition = definition
            .as_object()
            .ok_or(EmfError::Invalid("MetricDefinition must be an object"))?;
        let name = definition
            .get("Name")
            .and_then(Value::as_str)
            .filter(|name| valid_name(name, MAX_NAME_LEN))
            .ok_or(EmfError::Invalid("metric Name is invalid"))?;
        let unit = match definition.get("Unit") {
            None => MetricUnit::None,
            Some(unit) => unit
                .as_str()
                .and_then(MetricUnit::parse)
                .ok_or(EmfError::Invalid("metric Unit is invalid"))?,
        };
        let storage_resolution = match definition.get("StorageResolution") {
            None => 60,
            Some(resolution) => match resolution.as_u64() {
                Some(1) => 1,
                Some(60) => 60,
                _ => return Err(EmfError::Invalid("StorageResolution must be 1 or 60")),
            },
        };
        Ok(Self {
            name,
            unit,
            storage_resolution,
        })
    }
}

fn dimension_sets(
    dimensions: Option<&Value>,
    root: &Map<String, Value>,
) -> Result<Vec<BTreeMap<String, String>>, EmfError> {
    let sets = match dimensions {
        None => return Ok(vec![BTreeMap::new()]),
        Some(sets) => sets
            .as_array()
            .ok_or(EmfError::Invalid("Dimensions must be an array"))?,
    };
    if sets.is_empty() {
        return Ok(vec![BTreeMap::new()]);
    }
    sets.iter()
        .map(|set| {
            let keys = set
                .as_array()
                .ok_or(EmfError::Invalid("DimensionSet must be an array"))?;
            if keys.len() > MAX_DIMENSIONS_PER_SET {
                return Err(EmfError::Invalid("too many dimensions in a DimensionSet"));
            }
            keys.iter()
                .map(|key| {
                    let key = key
                        .as_str()
                        .filter(|key| valid_name(key, MAX_DIMENSION_NAME_LEN))
                        .ok_or(EmfError::Invalid("dimension key is invalid"))?;
                    let value = root
                        .get(key)
                        .and_then(Value::as_str)
                        .filter(|value| valid_name(value, MAX_DIMENSION_VALUE_LEN))
                        .ok_or(EmfError::Invalid("dimension value is missing or invalid"))?;
                    Ok((key.to_owned(), value.to_owned()))
                })
                .collect()
        })
        .collect()
}

fn metric_values(target: Option<&Value>) -> Result<Vec<f64>, EmfError> {
    let finite = |value: &Value| value.as_f64().filter(|value| value.is_finite());
    match target {
        Some(Value::Array(values)) => {
            if values.len() > MAX_VALUES_PER_METRIC {
                return Err(EmfError::Invalid("too many values for a metric"));
            }
            values
                .iter()
                .map(|value| finite(value).ok_or(EmfError::Invalid("metric value is not numeric")))
                .collect()
        }
        Some(value) => finite(value)
            .map(|value| vec![value])
            .ok_or(EmfError::Invalid("metric value is not numeric")),
        None => Err(EmfError::Invalid("metric value is missing")),
    }
}

fn valid_name(value: &str, max_len: usize) -> bool {
    (1..=max_len).contains(&value.len()) && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScopeKey;
    use serde_json::json;

    const NOW_MS: i64 = 1_700_000_000_000;

    fn powertools_line() -> String {
        json!({
            "_aws": {
                "Timestamp": NOW_MS,
                "CloudWatchMetrics": [{
                    "Namespace": "ServerlessAirline",
                    "Dimensions": [["service"]],
                    "Metrics": [{ "Name": "SuccessfulBooking", "Unit": "Count" }]
                }]
            },
            "service": "booking",
            "SuccessfulBooking": [1.0]
        })
        .to_string()
    }

    fn invalid(message: Value) -> EmfError {
        parse(&message.to_string()).unwrap_err()
    }

    fn event(message: String, timestamp_ms: i64) -> StoredEvent {
        StoredEvent {
            id: "event-1".into(),
            timestamp_ms,
            ingestion_time_ms: NOW_MS,
            put_ordinal: 1,
            event_ordinal: 0,
            message,
            message_bytes: None,
        }
    }

    fn group_key() -> GroupKey {
        GroupKey {
            scope: ScopeKey::new("000000000000", "us-east-1"),
            name: "/aws/lambda/booking".into(),
        }
    }

    #[test]
    fn parses_powertools_document() {
        let document = parse(&powertools_line()).unwrap();
        assert_eq!(document.timestamp_ms, Some(NOW_MS));
        assert_eq!(
            document.metrics,
            vec![EmfMetric {
                namespace: "ServerlessAirline".into(),
                name: "SuccessfulBooking".into(),
                dimensions: BTreeMap::from([("service".into(), "booking".into())]),
                values: vec![1.0],
                unit: MetricUnit::Count,
                storage_resolution: 60,
            }]
        );
    }

    #[test]
    fn expands_directives_dimension_sets_and_value_arrays() {
        let message = json!({
            "_aws": {
                "Timestamp": NOW_MS,
                "CloudWatchMetrics": [
                    {
                        "Namespace": "App",
                        "Dimensions": [["service"], ["service", "region"], []],
                        "Metrics": [
                            { "Name": "Latency", "Unit": "Milliseconds", "StorageResolution": 1 },
                            { "Name": "Errors" }
                        ]
                    },
                    {
                        "Namespace": "Other",
                        "Dimensions": [["region"]],
                        "Metrics": [{ "Name": "Errors" }]
                    }
                ]
            },
            "service": "api",
            "region": "eu",
            "Latency": [10, 20.5, 30],
            "Errors": 2
        });
        let document = parse(&message.to_string()).unwrap();
        assert_eq!(document.metrics.len(), 7);
        let latency_sets: Vec<_> = document
            .metrics
            .iter()
            .filter(|metric| metric.name == "Latency")
            .map(|metric| metric.dimensions.len())
            .collect();
        assert_eq!(latency_sets, [1, 2, 0]);
        let latency = &document.metrics[0];
        assert_eq!(latency.values, [10.0, 20.5, 30.0]);
        assert_eq!(latency.unit, MetricUnit::Milliseconds);
        assert_eq!(latency.storage_resolution, 1);
        let errors = &document.metrics[3];
        assert_eq!(errors.values, [2.0]);
        assert_eq!(errors.unit, MetricUnit::None);
        assert_eq!(errors.storage_resolution, 60);
        let other = document.metrics.last().unwrap();
        assert_eq!(other.namespace, "Other");
        assert_eq!(
            other.dimensions,
            BTreeMap::from([("region".into(), "eu".into())])
        );

        let mut key = group_key();
        key.scope = ScopeKey::new("111111111111", "eu-west-1");
        let observations =
            observations_for_events(&key, &[event(message.to_string(), NOW_MS)], NOW_MS);
        assert_eq!(observations.len(), 3 * 3 + 3 + 1);
        assert!(observations.iter().all(|observation| {
            observation.account_id == "111111111111"
                && observation.region == "eu-west-1"
                && observation.origin == MetricOrigin::CloudWatchLogs
        }));
    }

    #[test]
    fn empty_or_absent_dimensions_publish_dimensionless_metrics() {
        for dimensions in [json!([[]]), json!([]), Value::Null] {
            let mut directive = json!({ "Namespace": "App", "Metrics": [{ "Name": "Hits" }] });
            if !dimensions.is_null() {
                directive["Dimensions"] = dimensions;
            }
            let message = json!({
                "_aws": { "Timestamp": NOW_MS, "CloudWatchMetrics": [directive] },
                "Hits": 1
            });
            let document = parse(&message.to_string()).unwrap();
            assert_eq!(document.metrics.len(), 1);
            assert!(document.metrics[0].dimensions.is_empty());
        }
    }

    #[test]
    fn missing_targets_invalidate_the_event() {
        let missing_value = json!({
            "_aws": { "Timestamp": NOW_MS, "CloudWatchMetrics": [{
                "Namespace": "App", "Dimensions": [[]], "Metrics": [{ "Name": "Hits" }]
            }]}
        });
        assert_eq!(
            invalid(missing_value),
            EmfError::Invalid("metric value is missing")
        );
        let missing_dimension = json!({
            "_aws": { "Timestamp": NOW_MS, "CloudWatchMetrics": [{
                "Namespace": "App", "Dimensions": [["service"]], "Metrics": [{ "Name": "Hits" }]
            }]},
            "Hits": 1
        });
        assert_eq!(
            invalid(missing_dimension),
            EmfError::Invalid("dimension value is missing or invalid")
        );
    }

    #[test]
    fn enforces_dimension_metric_and_value_limits() {
        let mut root = json!({ "Hits": 1 });
        let keys: Vec<String> = (0..31).map(|index| format!("d{index}")).collect();
        for key in &keys {
            root[key] = json!("v");
        }
        root["_aws"] = json!({ "Timestamp": NOW_MS, "CloudWatchMetrics": [{
            "Namespace": "App", "Dimensions": [keys], "Metrics": [{ "Name": "Hits" }]
        }]});
        assert_eq!(
            invalid(root.clone()),
            EmfError::Invalid("too many dimensions in a DimensionSet")
        );
        root["_aws"]["CloudWatchMetrics"][0]["Dimensions"] = json!([keys[..30]]);
        assert_eq!(parse(&root.to_string()).unwrap().metrics.len(), 1);

        let definitions: Vec<_> = (0..101).map(|_| json!({ "Name": "Hits" })).collect();
        root["_aws"]["CloudWatchMetrics"][0]["Metrics"] = json!(definitions);
        assert_eq!(
            invalid(root.clone()),
            EmfError::Invalid("too many metrics in a directive")
        );

        root["_aws"]["CloudWatchMetrics"][0]["Metrics"] = json!([{ "Name": "Hits" }]);
        root["Hits"] = json!(vec![1; 101]);
        assert_eq!(
            invalid(root.clone()),
            EmfError::Invalid("too many values for a metric")
        );
        root["Hits"] = json!(vec![1; 100]);
        assert_eq!(
            parse(&root.to_string()).unwrap().metrics[0].values.len(),
            100
        );
    }

    #[test]
    fn non_json_and_non_emf_messages_are_not_emf() {
        for message in [
            "plain text log line".to_owned(),
            "START RequestId: 1 Version: $LATEST".to_owned(),
            "{\"_aws\": ".to_owned(),
            "prefix {\"_aws\":{}}".to_owned(),
            "[\"_aws\"]".to_owned(),
            json!({ "level": "INFO", "message": "\"_aws\"" }).to_string(),
        ] {
            assert_eq!(parse(&message), Err(EmfError::NotEmf), "{message}");
        }
    }

    #[test]
    fn rejects_wrong_member_types() {
        let base = || {
            json!({
                "_aws": { "Timestamp": NOW_MS, "CloudWatchMetrics": [{
                    "Namespace": "App", "Dimensions": [["service"]],
                    "Metrics": [{ "Name": "Hits", "Unit": "Count" }]
                }]},
                "service": "api",
                "Hits": 1
            })
        };
        type Mutation = fn(&mut Value);
        let cases: Vec<(Mutation, &str)> = vec![
            (|doc| doc["_aws"] = json!("x"), "_aws must be an object"),
            (
                |doc| doc["_aws"]["Timestamp"] = json!("now"),
                "Timestamp must be an integer",
            ),
            (
                |doc| doc["_aws"]["Timestamp"] = json!(1.5),
                "Timestamp must be an integer",
            ),
            (
                |doc| doc["_aws"]["CloudWatchMetrics"] = json!({}),
                "CloudWatchMetrics must be an array",
            ),
            (
                |doc| doc["_aws"]["CloudWatchMetrics"][0]["Namespace"] = json!(7),
                "Namespace is invalid",
            ),
            (
                |doc| doc["_aws"]["CloudWatchMetrics"][0]["Namespace"] = json!(""),
                "Namespace is invalid",
            ),
            (
                |doc| doc["_aws"]["CloudWatchMetrics"][0]["Dimensions"] = json!(["service"]),
                "DimensionSet must be an array",
            ),
            (
                |doc| doc["_aws"]["CloudWatchMetrics"][0]["Dimensions"] = json!([[1]]),
                "dimension key is invalid",
            ),
            (
                |doc| doc["service"] = json!(5),
                "dimension value is missing or invalid",
            ),
            (
                |doc| doc["_aws"]["CloudWatchMetrics"][0]["Metrics"][0]["Unit"] = json!("Widgets"),
                "metric Unit is invalid",
            ),
            (
                |doc| {
                    doc["_aws"]["CloudWatchMetrics"][0]["Metrics"][0]["StorageResolution"] =
                        json!(30)
                },
                "StorageResolution must be 1 or 60",
            ),
            (
                |doc| doc["_aws"]["CloudWatchMetrics"][0]["Metrics"][0]["Name"] = json!(null),
                "metric Name is invalid",
            ),
            (
                |doc| doc["Hits"] = json!("1"),
                "metric value is not numeric",
            ),
            (
                |doc| doc["Hits"] = json!([1, "2"]),
                "metric value is not numeric",
            ),
            (
                |doc| doc["Hits"] = json!({ "v": 1 }),
                "metric value is not numeric",
            ),
        ];
        for (mutate, reason) in cases {
            let mut document = base();
            mutate(&mut document);
            assert_eq!(invalid(document), EmfError::Invalid(reason));
        }
        assert!(parse(&base().to_string()).is_ok());
    }

    #[test]
    fn timestamp_defaults_to_event_time_and_out_of_window_events_are_skipped() {
        let mut message: Value = serde_json::from_str(&powertools_line()).unwrap();
        message["_aws"].as_object_mut().unwrap().remove("Timestamp");
        let observations = observations_for_events(
            &group_key(),
            &[event(message.to_string(), NOW_MS - 5_000)],
            NOW_MS,
        );
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].timestamp_ms, NOW_MS - 5_000);
        assert_eq!(observations[0].unit, Some(MetricUnit::Count));

        for timestamp in [NOW_MS - PAST_WINDOW_MS - 1, NOW_MS + FUTURE_WINDOW_MS + 1] {
            message["_aws"]["Timestamp"] = json!(timestamp);
            assert!(observations_for_events(
                &group_key(),
                &[event(message.to_string(), NOW_MS)],
                NOW_MS
            )
            .is_empty());
        }
    }

    #[test]
    fn caps_total_datapoints_per_event() {
        let sets: Vec<_> = (0..101).map(|_| json!([])).collect();
        let message = json!({
            "_aws": { "Timestamp": NOW_MS, "CloudWatchMetrics": [{
                "Namespace": "App", "Dimensions": sets, "Metrics": [{ "Name": "Hits" }]
            }]},
            "Hits": vec![1; 100]
        });
        assert_eq!(
            invalid(message),
            EmfError::Invalid("too many datapoints in one event")
        );
    }
}
