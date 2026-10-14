//! CloudWatch embedded metric format (EMF) extraction for ingested log events.
//!
//! Follows "Specification: Embedded metric format" (CloudWatch User Guide):
//! `_aws.Timestamp`, `CloudWatchMetrics`, and each directive's `Namespace`, `Dimensions`
//! (at least one DimensionSet, which may itself be empty) and `Metrics` are required.
//! Invalid namespaces, DimensionSets and metric names only drop the metrics they govern;
//! structural violations drop every metric of the event. The log event itself is always kept.

use std::collections::{BTreeMap, BTreeSet};

use locallycloud_core::integration::metrics::{MetricObservation, MetricOrigin, MetricUnit};
use serde_json::{Map, Value};

use crate::model::{GroupKey, StoredEvent};

const MAX_METRIC_DEFINITIONS_PER_EVENT: usize = 100;
const MAX_DIMENSIONS_PER_SET: usize = 30;
const MAX_VALUES_PER_METRIC: usize = 100;
/// Local safety bound: the specification does not cap the number of DimensionSets.
const MAX_DATAPOINTS_PER_EVENT: usize = 10_000;
const MAX_NAME_LEN: usize = 255;
const MAX_DIMENSION_NAME_LEN: usize = 250;
const MAX_DIMENSION_VALUE_LEN: usize = 1_024;
/// 2^360, the largest magnitude a metric value may have.
const MAX_ABS_METRIC_VALUE: f64 = f64::from_bits(1_383 << 52);
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
    pub timestamp_ms: i64,
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
    let timestamp_ms = document.timestamp_ms;
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
        .ok_or(EmfError::Invalid("Timestamp is required"))?
        .as_i64()
        .ok_or(EmfError::Invalid("Timestamp must be an integer"))?;
    let directives = metadata
        .get("CloudWatchMetrics")
        .and_then(Value::as_array)
        .ok_or(EmfError::Invalid("CloudWatchMetrics must be an array"))?;
    let mut metrics = Vec::new();
    let mut definition_count = 0_usize;
    let mut datapoints = 0_usize;
    for directive in directives {
        let directive = directive
            .as_object()
            .ok_or(EmfError::Invalid("MetricDirective must be an object"))?;
        let namespace = directive
            .get("Namespace")
            .and_then(Value::as_str)
            .filter(|namespace| valid_text(namespace, MAX_NAME_LEN))
            // `AWS/` is reserved for vended metrics; Monitoring would refuse these anyway,
            // so drop the directive here instead of queueing undeliverable effects.
            .filter(|namespace| !namespace.starts_with("AWS/"));
        let dimension_sets = dimension_sets(directive.get("Dimensions"), &root)?;
        let definitions = directive
            .get("Metrics")
            .and_then(Value::as_array)
            .ok_or(EmfError::Invalid("Metrics must be an array"))?;
        definition_count = definition_count.saturating_add(definitions.len());
        if definition_count > MAX_METRIC_DEFINITIONS_PER_EVENT {
            return Err(EmfError::Invalid(
                "too many metric definitions in one event",
            ));
        }
        for definition in definitions {
            let definition = MetricDefinition::parse(definition)?;
            let Some(name) = definition.name else {
                continue;
            };
            let values = metric_values(root.get(name))?;
            let (Some(namespace), Some(values)) = (namespace, values) else {
                continue;
            };
            for dimensions in &dimension_sets {
                datapoints = datapoints.saturating_add(values.len());
                if datapoints > MAX_DATAPOINTS_PER_EVENT {
                    return Err(EmfError::Invalid("too many datapoints in one event"));
                }
                metrics.push(EmfMetric {
                    namespace: namespace.to_owned(),
                    name: name.to_owned(),
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
    /// `None` when the name is invalid: that metric is not published.
    name: Option<&'a str>,
    unit: MetricUnit,
    storage_resolution: u16,
}

impl<'a> MetricDefinition<'a> {
    fn parse(definition: &'a Value) -> Result<Self, EmfError> {
        let definition = definition
            .as_object()
            .ok_or(EmfError::Invalid("MetricDefinition must be an object"))?;
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
        let name = definition
            .get("Name")
            .and_then(Value::as_str)
            .filter(|name| valid_text(name, MAX_NAME_LEN));
        Ok(Self {
            name,
            unit,
            storage_resolution,
        })
    }
}

/// Resolves the directive's DimensionSets, dropping the ones that do not meet the
/// specification; a repeated key inside a DimensionSet invalidates the whole document.
fn dimension_sets(
    dimensions: Option<&Value>,
    root: &Map<String, Value>,
) -> Result<Vec<BTreeMap<String, String>>, EmfError> {
    let sets = dimensions
        .ok_or(EmfError::Invalid("Dimensions is required"))?
        .as_array()
        .ok_or(EmfError::Invalid("Dimensions must be an array"))?;
    if sets.is_empty() {
        return Err(EmfError::Invalid(
            "Dimensions must contain at least one DimensionSet",
        ));
    }
    let mut resolved = Vec::new();
    for set in sets {
        let Some(keys) = set.as_array() else {
            continue;
        };
        if has_duplicate_keys(keys) {
            return Err(EmfError::Invalid(
                "DimensionSet contains a duplicate dimension key",
            ));
        }
        if let Some(dimensions) = resolve_dimension_set(keys, root) {
            resolved.push(dimensions);
        }
    }
    Ok(resolved)
}

fn has_duplicate_keys(keys: &[Value]) -> bool {
    let mut seen = BTreeSet::new();
    keys.iter()
        .filter_map(Value::as_str)
        .any(|key| !seen.insert(key))
}

fn resolve_dimension_set(
    keys: &[Value],
    root: &Map<String, Value>,
) -> Option<BTreeMap<String, String>> {
    if keys.len() > MAX_DIMENSIONS_PER_SET {
        return None;
    }
    keys.iter()
        .map(|key| {
            let key = key.as_str().filter(|key| valid_dimension_key(key))?;
            let value = root
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| valid_text(value, MAX_DIMENSION_VALUE_LEN))?;
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Returns `None` when a value is outside ±2^360: that metric is not published.
fn metric_values(target: Option<&Value>) -> Result<Option<Vec<f64>>, EmfError> {
    let numeric = |value: &Value| {
        value
            .as_f64()
            .filter(|value| value.is_finite())
            .ok_or(EmfError::Invalid("metric value is not numeric"))
    };
    let values = match target {
        Some(Value::Array(values)) => {
            if values.len() > MAX_VALUES_PER_METRIC {
                return Err(EmfError::Invalid("too many values for a metric"));
            }
            values.iter().map(numeric).collect::<Result<Vec<_>, _>>()?
        }
        Some(value) => vec![numeric(value)?],
        None => return Err(EmfError::Invalid("metric value is missing")),
    };
    Ok(values
        .iter()
        .all(|value| value.abs() <= MAX_ABS_METRIC_VALUE)
        .then_some(values))
}

/// 1 to `max_len` printable ASCII characters, not only whitespace.
fn valid_text(value: &str, max_len: usize) -> bool {
    (1..=max_len).contains(&value.len())
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        && value.bytes().any(|byte| byte != b' ')
}

fn valid_dimension_key(key: &str) -> bool {
    valid_text(key, MAX_DIMENSION_NAME_LEN) && !key.starts_with(':')
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

    fn base() -> Value {
        json!({
            "_aws": { "Timestamp": NOW_MS, "CloudWatchMetrics": [{
                "Namespace": "App", "Dimensions": [["service"]],
                "Metrics": [{ "Name": "Hits", "Unit": "Count" }]
            }]},
            "service": "api",
            "Hits": 1
        })
    }

    fn invalid(message: Value) -> EmfError {
        parse(&message.to_string()).unwrap_err()
    }

    fn metrics(message: &Value) -> Vec<EmfMetric> {
        parse(&message.to_string()).unwrap().metrics
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
        assert_eq!(document.timestamp_ms, NOW_MS);
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
    fn missing_timestamp_yields_no_metrics() {
        let mut message: Value = serde_json::from_str(&powertools_line()).unwrap();
        message["_aws"].as_object_mut().unwrap().remove("Timestamp");
        assert_eq!(
            invalid(message.clone()),
            EmfError::Invalid("Timestamp is required")
        );
        assert!(observations_for_events(
            &group_key(),
            &[event(message.to_string(), NOW_MS)],
            NOW_MS
        )
        .is_empty());
    }

    #[test]
    fn timestamp_must_lie_within_14_days_past_and_2_hours_future() {
        let mut message: Value = serde_json::from_str(&powertools_line()).unwrap();
        let observe = |message: &Value| {
            // The event time never substitutes for `_aws.Timestamp`.
            observations_for_events(
                &group_key(),
                &[event(message.to_string(), NOW_MS - 5_000)],
                NOW_MS,
            )
        };
        for timestamp in [NOW_MS - PAST_WINDOW_MS, NOW_MS + FUTURE_WINDOW_MS] {
            message["_aws"]["Timestamp"] = json!(timestamp);
            let observations = observe(&message);
            assert_eq!(observations.len(), 1);
            assert_eq!(observations[0].timestamp_ms, timestamp);
            assert_eq!(observations[0].unit, Some(MetricUnit::Count));
        }
        for timestamp in [NOW_MS - PAST_WINDOW_MS - 1, NOW_MS + FUTURE_WINDOW_MS + 1] {
            message["_aws"]["Timestamp"] = json!(timestamp);
            assert!(observe(&message).is_empty());
        }
    }

    #[test]
    fn dimensions_member_is_required() {
        let mut message = base();
        message["_aws"]["CloudWatchMetrics"][0]
            .as_object_mut()
            .unwrap()
            .remove("Dimensions");
        assert_eq!(
            invalid(message),
            EmfError::Invalid("Dimensions is required")
        );
    }

    #[test]
    fn dimensions_must_contain_at_least_one_dimension_set() {
        let mut message = base();
        message["_aws"]["CloudWatchMetrics"][0]["Dimensions"] = json!([]);
        assert_eq!(
            invalid(message),
            EmfError::Invalid("Dimensions must contain at least one DimensionSet")
        );
    }

    #[test]
    fn empty_dimension_set_publishes_a_dimensionless_metric() {
        let mut message = base();
        message["_aws"]["CloudWatchMetrics"][0]["Dimensions"] = json!([[]]);
        let metrics = metrics(&message);
        assert_eq!(metrics.len(), 1);
        assert!(metrics[0].dimensions.is_empty());
    }

    #[test]
    fn duplicate_keys_within_a_dimension_set_invalidate_the_document() {
        for sets in [
            json!([["service", "service"]]),
            json!([["service"], ["region", "service", "region"]]),
        ] {
            let mut message = base();
            message["region"] = json!("eu");
            message["_aws"]["CloudWatchMetrics"][0]["Dimensions"] = sets;
            assert_eq!(
                invalid(message),
                EmfError::Invalid("DimensionSet contains a duplicate dimension key")
            );
        }
        let mut message = base();
        message["_aws"]["CloudWatchMetrics"][0]["Dimensions"] = json!([["service"], ["service"]]);
        assert_eq!(metrics(&message).len(), 2);
    }

    #[test]
    fn invalid_dimension_sets_are_skipped_without_affecting_the_others() {
        let too_many: Vec<String> = (0..31).map(|index| format!("d{index}")).collect();
        let cases: Vec<(Value, Value)> = vec![
            (json!(too_many), json!(null)),
            (json!("service"), json!(null)),
            (json!([1]), json!(null)),
            (json!([""]), json!(null)),
            (json!(["   "]), json!(null)),
            (json!([":colon"]), json!(null)),
            (json!(["k".repeat(251)]), json!(null)),
            (json!(["clé"]), json!(null)),
            (json!(["missing"]), json!(null)),
            (json!(["target"]), json!(5)),
            (json!(["target"]), json!("")),
            (json!(["target"]), json!("  ")),
            (json!(["target"]), json!("v".repeat(1_025))),
            (json!(["target"]), json!("tab\tvalue")),
            (json!(["target"]), json!("ünïcode")),
        ];
        for (set, target) in cases {
            let mut message = base();
            for key in &too_many {
                message[key] = json!("v");
            }
            message["clé"] = json!("v");
            message[":colon"] = json!("v");
            message["target"] = target;
            message["_aws"]["CloudWatchMetrics"][0]["Dimensions"] = json!([set, ["service"]]);
            let metrics = metrics(&message);
            assert_eq!(metrics.len(), 1, "{set}");
            assert_eq!(
                metrics[0].dimensions,
                BTreeMap::from([("service".into(), "api".into())])
            );
        }

        let mut message = base();
        for key in &too_many[..30] {
            message[key] = json!("v");
        }
        message["_aws"]["CloudWatchMetrics"][0]["Dimensions"] = json!([too_many[..30]]);
        assert_eq!(metrics(&message)[0].dimensions.len(), 30);
        message["k".repeat(250)] = json!("v".repeat(1_024));
        message["_aws"]["CloudWatchMetrics"][0]["Dimensions"] = json!([["k".repeat(250)]]);
        assert_eq!(metrics(&message).len(), 1);
    }

    #[test]
    fn invalid_namespace_drops_only_its_directive() {
        for namespace in [
            json!(7),
            json!(""),
            json!("   "),
            json!("n".repeat(256)),
            json!("Spaß"),
            json!(null),
            json!("AWS/Lambda"),
        ] {
            let mut message = base();
            let mut skipped = message["_aws"]["CloudWatchMetrics"][0].clone();
            skipped["Namespace"] = namespace;
            message["_aws"]["CloudWatchMetrics"]
                .as_array_mut()
                .unwrap()
                .insert(0, skipped);
            let metrics = metrics(&message);
            assert_eq!(metrics.len(), 1);
            assert_eq!(metrics[0].namespace, "App");
        }
        let mut message = base();
        message["_aws"]["CloudWatchMetrics"][0]["Namespace"] = json!("n".repeat(255));
        assert_eq!(metrics(&message).len(), 1);
    }

    #[test]
    fn invalid_metric_name_drops_only_that_metric() {
        for name in [
            json!(null),
            json!(3),
            json!(""),
            json!(" "),
            json!("m".repeat(256)),
        ] {
            let mut message = base();
            message["_aws"]["CloudWatchMetrics"][0]["Metrics"] =
                json!([{ "Name": name }, { "Name": "Hits" }]);
            let metrics = metrics(&message);
            assert_eq!(metrics.len(), 1);
            assert_eq!(metrics[0].name, "Hits");
        }
    }

    #[test]
    fn metric_values_beyond_two_to_the_360_drop_only_that_metric() {
        let limit = 2_f64.powi(360);
        assert_eq!(MAX_ABS_METRIC_VALUE, limit);
        let mut message = base();
        message["_aws"]["CloudWatchMetrics"][0]["Metrics"] =
            json!([{ "Name": "Huge" }, { "Name": "Hits" }]);
        for huge in [json!(limit * 2.0), json!([1, -limit * 2.0])] {
            message["Huge"] = huge;
            let metrics = metrics(&message);
            assert_eq!(metrics.len(), 1);
            assert_eq!(metrics[0].name, "Hits");
        }
        message["Huge"] = json!([limit, -limit]);
        assert_eq!(metrics(&message).len(), 2);
    }

    #[test]
    fn more_than_100_metric_definitions_per_event_drop_every_metric() {
        let mut message = base();
        let directive = message["_aws"]["CloudWatchMetrics"][0].clone();
        let mut directives = vec![directive.clone(), directive];
        directives[0]["Metrics"] = json!(vec![json!({ "Name": "Hits" }); 50]);
        directives[1]["Metrics"] = json!(vec![json!({ "Name": "Hits" }); 50]);
        message["_aws"]["CloudWatchMetrics"] = json!(directives);
        assert_eq!(metrics(&message).len(), 100);
        message["_aws"]["CloudWatchMetrics"][1]["Metrics"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "Name": "Hits" }));
        assert_eq!(
            invalid(message),
            EmfError::Invalid("too many metric definitions in one event")
        );
    }

    #[test]
    fn more_than_100_values_in_a_metric_array_drop_every_metric() {
        let mut message = base();
        message["Hits"] = json!(vec![1; 100]);
        assert_eq!(metrics(&message)[0].values.len(), 100);
        message["_aws"]["CloudWatchMetrics"][0]["Metrics"] =
            json!([{ "Name": "Hits" }, { "Name": "Other" }]);
        message["Other"] = json!(1);
        message["Hits"] = json!(vec![1; 101]);
        assert_eq!(
            invalid(message),
            EmfError::Invalid("too many values for a metric")
        );
    }

    #[test]
    fn missing_metric_target_invalidates_the_event() {
        let mut message = base();
        message.as_object_mut().unwrap().remove("Hits");
        assert_eq!(
            invalid(message),
            EmfError::Invalid("metric value is missing")
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
                |doc| doc["_aws"]["CloudWatchMetrics"][0] = json!([]),
                "MetricDirective must be an object",
            ),
            (
                |doc| doc["_aws"]["CloudWatchMetrics"][0]["Dimensions"] = json!({}),
                "Dimensions must be an array",
            ),
            (
                |doc| doc["_aws"]["CloudWatchMetrics"][0]["Metrics"] = json!({}),
                "Metrics must be an array",
            ),
            (
                |doc| doc["_aws"]["CloudWatchMetrics"][0]["Metrics"][0] = json!("Hits"),
                "MetricDefinition must be an object",
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
