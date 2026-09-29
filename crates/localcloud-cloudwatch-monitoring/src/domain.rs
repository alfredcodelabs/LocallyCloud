use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use localcloud_core::integration::metrics::MetricObservation;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("metric batch must contain between 1 and 1000 observations")]
    InvalidBatchSize,
    #[error("account id and region must not be empty")]
    InvalidScope,
    #[error("namespace and metric name must not be empty")]
    InvalidName,
    #[error("metric value must be finite")]
    InvalidValue,
    #[error("dimension names and values must not be empty")]
    InvalidDimension,
    #[error("unit must not be empty")]
    InvalidUnit,
    #[error("storage resolution must be 1 or 60")]
    InvalidStorageResolution,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SeriesKey {
    pub namespace: String,
    pub metric_name: String,
    pub dimensions: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Sample {
    pub timestamp_ms: i64,
    pub value: f64,
    pub unit: Option<String>,
    pub storage_resolution: u16,
}

#[derive(Debug, Clone)]
pub struct Series {
    pub key: SeriesKey,
    pub samples: Vec<Sample>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ScopeKey {
    account_id: String,
    region: String,
}

#[derive(Default)]
pub struct MetricDomain {
    scopes: RwLock<BTreeMap<ScopeKey, BTreeMap<SeriesKey, Vec<Sample>>>>,
}

impl MetricDomain {
    pub fn validate_batch(&self, observations: &[MetricObservation]) -> Result<(), DomainError> {
        if observations.is_empty() || observations.len() > 1000 {
            return Err(DomainError::InvalidBatchSize);
        }
        for observation in observations {
            if observation.account_id.trim().is_empty() || observation.region.trim().is_empty() {
                return Err(DomainError::InvalidScope);
            }
            if observation.namespace.trim().is_empty() || observation.metric_name.trim().is_empty() {
                return Err(DomainError::InvalidName);
            }
            if !observation.value.is_finite() {
                return Err(DomainError::InvalidValue);
            }
            if observation
                .dimensions
                .iter()
                .any(|(name, value)| name.trim().is_empty() || value.trim().is_empty())
            {
                return Err(DomainError::InvalidDimension);
            }
            if observation
                .unit
                .as_ref()
                .map(|unit| unit.trim().is_empty())
                .unwrap_or(false)
            {
                return Err(DomainError::InvalidUnit);
            }
            if observation.storage_resolution != 1 && observation.storage_resolution != 60 {
                return Err(DomainError::InvalidStorageResolution);
            }
        }
        Ok(())
    }

    pub fn commit(&self, observations: Vec<MetricObservation>) -> Result<(), DomainError> {
        self.validate_batch(&observations)?;
        let mut scopes = self.scopes.write().expect("metric store lock poisoned");
        for observation in observations {
            let scope = ScopeKey {
                account_id: observation.account_id,
                region: observation.region,
            };
            let series = SeriesKey {
                namespace: observation.namespace,
                metric_name: observation.metric_name,
                dimensions: observation.dimensions,
            };
            scopes
                .entry(scope)
                .or_default()
                .entry(series)
                .or_default()
                .push(Sample {
                    timestamp_ms: observation.timestamp_ms,
                    value: observation.value,
                    unit: observation.unit,
                    storage_resolution: observation.storage_resolution,
                });
        }
        Ok(())
    }

    pub fn list_series(
        &self,
        account_id: &str,
        region: &str,
        namespace: Option<&str>,
        metric_name: Option<&str>,
    ) -> Vec<SeriesKey> {
        let scopes = self.scopes.read().expect("metric store lock poisoned");
        let scope = ScopeKey {
            account_id: account_id.to_string(),
            region: region.to_string(),
        };
        scopes
            .get(&scope)
            .into_iter()
            .flat_map(|series| series.keys())
            .filter(|key| namespace.map(|value| key.namespace == value).unwrap_or(true))
            .filter(|key| {
                metric_name
                    .map(|value| key.metric_name == value)
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    pub fn series(
        &self,
        account_id: &str,
        region: &str,
        namespace: &str,
        metric_name: &str,
        dimensions: &BTreeMap<String, String>,
    ) -> Option<Series> {
        let scopes = self.scopes.read().expect("metric store lock poisoned");
        let scope = ScopeKey {
            account_id: account_id.to_string(),
            region: region.to_string(),
        };
        let key = SeriesKey {
            namespace: namespace.to_string(),
            metric_name: metric_name.to_string(),
            dimensions: dimensions.clone(),
        };
        scopes.get(&scope).and_then(|series| {
            series.get(&key).map(|samples| Series {
                key,
                samples: samples.clone(),
            })
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Statistic {
    Sum,
    SampleCount,
    Minimum,
    Maximum,
    Average,
}

impl Statistic {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "Sum" => Some(Self::Sum),
            "SampleCount" => Some(Self::SampleCount),
            "Minimum" => Some(Self::Minimum),
            "Maximum" => Some(Self::Maximum),
            "Average" => Some(Self::Average),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sum => "Sum",
            Self::SampleCount => "SampleCount",
            Self::Minimum => "Minimum",
            Self::Maximum => "Maximum",
            Self::Average => "Average",
        }
    }
}

pub fn deduplicate_statistics(statistics: Vec<Statistic>) -> Vec<Statistic> {
    let mut seen = BTreeSet::new();
    statistics
        .into_iter()
        .filter(|statistic| seen.insert(statistic.as_str()))
        .collect()
}
