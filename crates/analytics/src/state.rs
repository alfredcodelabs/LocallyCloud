use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct Scope {
    account_id: String,
    region: String,
}

impl Scope {
    pub(crate) fn new(account_id: &str, region: &str) -> Self {
        Self {
            account_id: account_id.to_owned(),
            region: region.to_owned(),
        }
    }

    pub(crate) fn account_id(&self) -> &str {
        &self.account_id
    }

    pub(crate) fn region(&self) -> &str {
        &self.region
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct DatabaseInput {
    #[serde(rename = "Name")]
    pub(crate) name: String,
    #[serde(flatten)]
    pub(crate) fields: BTreeMap<String, Value>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct TableInput {
    #[serde(rename = "Name")]
    pub(crate) name: String,
    #[serde(flatten)]
    pub(crate) fields: BTreeMap<String, Value>,
}

pub(crate) struct DatabaseRecord {
    pub(crate) input: DatabaseInput,
    pub(crate) create_time: f64,
    pub(crate) update_time: f64,
    pub(crate) tables: BTreeMap<String, TableRecord>,
}

pub(crate) struct TableRecord {
    pub(crate) input: TableInput,
    pub(crate) create_time: f64,
    pub(crate) update_time: f64,
    pub(crate) version_id: u64,
    pub(crate) partitions: Vec<Value>,
}

#[derive(Default)]
pub(crate) struct Catalog {
    pub(crate) databases: BTreeMap<String, DatabaseRecord>,
}

pub(crate) struct AnalyticsState {
    catalogs: DashMap<Scope, Arc<Mutex<Catalog>>>,
}

impl AnalyticsState {
    pub(crate) fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        let mut regions = Vec::new();
        for e in self
            .catalogs
            .iter()
            .filter(|e| e.key().account_id == account)
        {
            if !e
                .value()
                .lock()
                .map_err(|_| "Glue inventory unavailable")?
                .databases
                .is_empty()
            {
                regions.push(e.key().region.clone());
            }
        }
        Ok(regions)
    }

    pub(crate) fn new() -> Self {
        Self {
            catalogs: DashMap::new(),
        }
    }

    pub(crate) fn catalog(&self, scope: &Scope) -> Arc<Mutex<Catalog>> {
        self.catalogs
            .entry(scope.clone())
            .or_insert_with(|| Arc::new(Mutex::new(Catalog::default())))
            .clone()
    }
}
