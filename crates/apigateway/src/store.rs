//! Region/account-scoped API Gateway store. Control-plane resources are stored as the JSON
//! values AWS returns, keyed by id; v1 REST APIs and v2 APIs each hold their child resources.

use std::collections::BTreeMap;
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

#[path = "persistence.rs"]
mod persistence;
pub(crate) use persistence::Persistence;

/// Generate a 10-character lowercase-alphanumeric API Gateway id.
pub fn gen_id() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = String::with_capacity(10);
    for b in Uuid::new_v4().as_bytes().iter().take(10) {
        s.push(CHARS[(*b as usize) % CHARS.len()] as char);
    }
    s
}

/// Immutable v1 configuration captured by a deployment.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct RestDeploymentSnapshot {
    pub resources: BTreeMap<String, Value>,
    pub authorizers: BTreeMap<String, Value>,
    pub models: BTreeMap<String, Value>,
    pub request_validators: BTreeMap<String, Value>,
    pub gateway_responses: BTreeMap<String, Value>,
}

/// A v1 REST API and its child resources.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct RestApiRecord {
    pub api: Value,
    pub resources: BTreeMap<String, Value>,
    pub authorizers: BTreeMap<String, Value>,
    pub models: BTreeMap<String, Value>,
    pub request_validators: BTreeMap<String, Value>,
    pub deployments: BTreeMap<String, Value>,
    pub deployment_snapshots: BTreeMap<String, RestDeploymentSnapshot>,
    pub stages: BTreeMap<String, Value>,
    pub gateway_responses: BTreeMap<String, Value>,
}

impl RestApiRecord {
    pub fn snapshot(&self) -> RestDeploymentSnapshot {
        RestDeploymentSnapshot {
            resources: self.resources.clone(),
            authorizers: self.authorizers.clone(),
            models: self.models.clone(),
            request_validators: self.request_validators.clone(),
            gateway_responses: self.gateway_responses.clone(),
        }
    }
}

/// Immutable v2 configuration captured by a deployment.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ApiV2DeploymentSnapshot {
    pub api: Value,
    pub routes: BTreeMap<String, Value>,
    pub integrations: BTreeMap<String, Value>,
    pub authorizers: BTreeMap<String, Value>,
}

/// A v2 API (HTTP or WEBSOCKET) and its child resources.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ApiV2Record {
    pub api: Value,
    pub routes: BTreeMap<String, Value>,
    pub integrations: BTreeMap<String, Value>,
    pub authorizers: BTreeMap<String, Value>,
    pub deployments: BTreeMap<String, Value>,
    pub deployment_snapshots: BTreeMap<String, ApiV2DeploymentSnapshot>,
    pub stages: BTreeMap<String, Value>,
}

impl ApiV2Record {
    pub fn snapshot(&self) -> ApiV2DeploymentSnapshot {
        ApiV2DeploymentSnapshot {
            api: self.api.clone(),
            routes: self.routes.clone(),
            integrations: self.integrations.clone(),
            authorizers: self.authorizers.clone(),
        }
    }
}

/// Resources shared by the v1 and v2 control planes in one account and region.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SharedRecord {
    pub api_keys: BTreeMap<String, Value>,
    pub usage_plans: BTreeMap<String, Value>,
    pub domains: BTreeMap<String, Value>,
    /// Private REST custom domains, keyed by their AWS domainNameId.
    pub private_domains: BTreeMap<String, Value>,
    pub domain_access_associations: BTreeMap<String, Value>,
    #[serde(skip)]
    pub connections: BTreeMap<String, Value>,
    #[serde(skip)]
    pub authorizer_cache: BTreeMap<String, Value>,
}

type Key = (String, String, String);
type ScopeKey = (String, String);

#[derive(Default)]
pub struct ApiGwStore {
    rest: DashMap<Key, Arc<RwLock<RestApiRecord>>>,
    v2: DashMap<Key, Arc<RwLock<ApiV2Record>>>,
    shared: DashMap<ScopeKey, Arc<RwLock<SharedRecord>>>,
    connection_senders: DashMap<Key, mpsc::Sender<Vec<u8>>>,
}

fn key(account: &str, region: &str, id: &str) -> Key {
    (account.to_string(), region.to_string(), id.to_string())
}

impl ApiGwStore {
    pub(crate) async fn public_invoke_region(
        &self,
        account: &str,
        host: &str,
        api_id: Option<&str>,
    ) -> Option<String> {
        let mut matches = Vec::new();
        if let Some(id) = api_id {
            matches.extend(
                self.rest
                    .iter()
                    .map(|e| e.key().clone())
                    .chain(self.v2.iter().map(|e| e.key().clone()))
                    .filter(|key| key.0 == account && key.2 == id)
                    .map(|key| key.1),
            );
        } else {
            let scopes: Vec<_> = self
                .shared
                .iter()
                .filter(|e| e.key().0 == account)
                .map(|e| (e.key().1.clone(), e.value().clone()))
                .collect();
            for (region, scope) in scopes {
                let scope = scope.read().await;
                if scope
                    .domains
                    .keys()
                    .any(|name| name.eq_ignore_ascii_case(host))
                    || scope.private_domains.values().any(|domain| {
                        domain
                            .get("domainName")
                            .and_then(Value::as_str)
                            .is_some_and(|name| name.eq_ignore_ascii_case(host))
                    })
                {
                    matches.push(region);
                }
            }
        }
        matches.sort();
        matches.dedup();
        (matches.len() == 1).then(|| matches.remove(0))
    }

    pub(crate) async fn resource_regions(
        &self,
        account: &str,
    ) -> Result<Vec<String>, &'static str> {
        let mut regions: Vec<_> = self
            .rest
            .iter()
            .map(|e| e.key().clone())
            .chain(self.v2.iter().map(|e| e.key().clone()))
            .filter(|k| k.0 == account)
            .map(|k| k.1)
            .collect();
        let scopes: Vec<_> = self
            .shared
            .iter()
            .filter(|e| e.key().0 == account)
            .map(|e| (e.key().1.clone(), e.value().clone()))
            .collect();
        for (region, scope) in scopes {
            let s = scope.read().await;
            if !s.api_keys.is_empty()
                || !s.usage_plans.is_empty()
                || !s.domains.is_empty()
                || !s.private_domains.is_empty()
                || !s.domain_access_associations.is_empty()
            {
                regions.push(region);
            }
        }
        Ok(regions)
    }

    pub fn new() -> Self {
        Self::default()
    }

    // ---- v1 REST APIs ----
    pub fn insert_rest(
        &self,
        account: &str,
        region: &str,
        id: &str,
        rec: RestApiRecord,
    ) -> Arc<RwLock<RestApiRecord>> {
        let handle = Arc::new(RwLock::new(rec));
        self.rest.insert(key(account, region, id), handle.clone());
        handle
    }
    pub fn rest(
        &self,
        account: &str,
        region: &str,
        id: &str,
    ) -> Option<Arc<RwLock<RestApiRecord>>> {
        self.rest.get(&key(account, region, id)).map(|e| e.clone())
    }
    pub fn remove_rest(&self, account: &str, region: &str, id: &str) -> bool {
        self.rest.remove(&key(account, region, id)).is_some()
    }
    pub fn list_rest(&self, account: &str, region: &str) -> Vec<Arc<RwLock<RestApiRecord>>> {
        self.rest
            .iter()
            .filter(|e| e.key().0 == account && e.key().1 == region)
            .map(|e| e.value().clone())
            .collect()
    }

    // ---- v2 APIs ----
    pub fn insert_v2(
        &self,
        account: &str,
        region: &str,
        id: &str,
        rec: ApiV2Record,
    ) -> Arc<RwLock<ApiV2Record>> {
        let handle = Arc::new(RwLock::new(rec));
        self.v2.insert(key(account, region, id), handle.clone());
        handle
    }
    pub fn v2(&self, account: &str, region: &str, id: &str) -> Option<Arc<RwLock<ApiV2Record>>> {
        self.v2.get(&key(account, region, id)).map(|e| e.clone())
    }
    pub fn remove_v2(&self, account: &str, region: &str, id: &str) -> bool {
        self.v2.remove(&key(account, region, id)).is_some()
    }
    pub fn list_v2(&self, account: &str, region: &str) -> Vec<Arc<RwLock<ApiV2Record>>> {
        self.v2
            .iter()
            .filter(|e| e.key().0 == account && e.key().1 == region)
            .map(|e| e.value().clone())
            .collect()
    }

    /// Shared v1/v2 resources for an account and region.
    pub fn shared(&self, account: &str, region: &str) -> Arc<RwLock<SharedRecord>> {
        self.shared
            .entry((account.to_string(), region.to_string()))
            .or_insert_with(|| Arc::new(RwLock::new(SharedRecord::default())))
            .clone()
    }

    pub fn register_connection_sender(
        &self,
        account: &str,
        region: &str,
        connection_id: &str,
        sender: mpsc::Sender<Vec<u8>>,
    ) {
        self.connection_senders
            .insert(key(account, region, connection_id), sender);
    }

    pub fn send_to_connection(
        &self,
        account: &str,
        region: &str,
        connection_id: &str,
        payload: Vec<u8>,
    ) -> bool {
        let connection_key = key(account, region, connection_id);
        let Some(sender) = self.connection_senders.get(&connection_key) else {
            return false;
        };
        let sent = sender.try_send(payload).is_ok();
        drop(sender);
        if !sent {
            self.connection_senders.remove(&connection_key);
        }
        sent
    }

    pub fn remove_connection_sender(&self, account: &str, region: &str, connection_id: &str) {
        self.connection_senders
            .remove(&key(account, region, connection_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_ten_chars_alphanumeric() {
        let id = gen_id();
        assert_eq!(id.len(), 10);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn rest_insert_get_remove() {
        let store = ApiGwStore::new();
        store.insert_rest("0", "us-east-1", "abc", RestApiRecord::default());
        assert!(store.rest("0", "us-east-1", "abc").is_some());
        assert!(store.remove_rest("0", "us-east-1", "abc"));
        assert!(store.rest("0", "us-east-1", "abc").is_none());
    }
}
