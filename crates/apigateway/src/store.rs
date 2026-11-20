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
    /// Required in persisted deployments: old snapshots cannot reconstruct their policy.
    pub policy: Value,
    pub endpoint_configuration: Value,
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
    pub deployment_snapshots: BTreeMap<String, Arc<RestDeploymentSnapshot>>,
    pub stages: BTreeMap<String, Value>,
    pub gateway_responses: BTreeMap<String, Value>,
}

impl RestApiRecord {
    pub fn snapshot(&self) -> Arc<RestDeploymentSnapshot> {
        Arc::new(RestDeploymentSnapshot {
            policy: self.api.get("policy").cloned().unwrap_or(Value::Null),
            endpoint_configuration: self
                .api
                .get("endpointConfiguration")
                .cloned()
                .unwrap_or(Value::Null),
            resources: self.resources.clone(),
            authorizers: self.authorizers.clone(),
            models: self.models.clone(),
            request_validators: self.request_validators.clone(),
            gateway_responses: self.gateway_responses.clone(),
        })
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
    pub deployment_snapshots: BTreeMap<String, Arc<ApiV2DeploymentSnapshot>>,
    pub stages: BTreeMap<String, Value>,
}

impl ApiV2Record {
    pub fn snapshot(&self) -> Arc<ApiV2DeploymentSnapshot> {
        Arc::new(ApiV2DeploymentSnapshot {
            api: self.api.clone(),
            routes: self.routes.clone(),
            integrations: self.integrations.clone(),
            authorizers: self.authorizers.clone(),
        })
    }
}

/// Resources shared by the v1 and v2 control planes in one account and region.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SharedRecord {
    #[serde(default)]
    pub account_settings: Option<Value>,
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
    pub(crate) config: crate::config::ApiGatewayConfig,
    rest: DashMap<Key, Arc<RwLock<RestApiRecord>>>,
    v2: DashMap<Key, Arc<RwLock<ApiV2Record>>>,
    shared: DashMap<ScopeKey, Arc<RwLock<SharedRecord>>>,
    connection_senders: DashMap<Key, mpsc::Sender<Vec<u8>>>,
}

fn key(account: &str, region: &str, id: &str) -> Key {
    (account.to_string(), region.to_string(), id.to_string())
}

pub(crate) fn cached_authorizer(cache: &BTreeMap<String, Value>, key: &str) -> Option<Value> {
    let value = cache.get(key)?;
    (value.get("expiresAt")?.as_u64()? > cache_now_secs())
        .then(|| value.get("result").cloned())
        .flatten()
}

pub(crate) fn cache_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
                || s.account_settings.is_some()
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

    pub(crate) fn with_config(config: crate::config::ApiGatewayConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub(crate) async fn cached_authorizer(
        &self,
        account: &str,
        region: &str,
        key: &str,
    ) -> Option<Value> {
        let shared = self.shared(account, region);
        let guard = shared.read().await;
        cached_authorizer(&guard.authorizer_cache, key)
    }

    pub(crate) async fn cache_authorizer(
        &self,
        account: &str,
        region: &str,
        key: String,
        value: Value,
    ) {
        let shared = self.shared(account, region);
        let mut guard = shared.write().await;
        let now = cache_now_secs();
        guard
            .authorizer_cache
            .retain(|_, value| value.get("expiresAt").and_then(Value::as_u64).unwrap_or(0) > now);
        while guard.authorizer_cache.len() >= self.config.authorizer_cache_capacity {
            let Some(oldest) = guard.authorizer_cache.keys().next().cloned() else {
                break;
            };
            guard.authorizer_cache.remove(&oldest);
        }
        guard.authorizer_cache.insert(key, value);
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
#[path = "store/deployment_tests.rs"]
mod deployment_tests;

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

#[cfg(test)]
mod operational_config_tests {
    use super::*;

    #[tokio::test]
    async fn configured_authorizer_cache_is_bounded_per_scope() {
        let config = crate::ApiGatewayConfig {
            authorizer_cache_capacity: 1,
            ..Default::default()
        };
        let store = ApiGwStore::with_config(config).unwrap();
        store
            .cache_authorizer(
                "account",
                "east",
                "first".into(),
                serde_json::json!({"result":1}),
            )
            .await;
        store
            .cache_authorizer(
                "account",
                "west",
                "other".into(),
                serde_json::json!({"result":3}),
            )
            .await;
        store
            .cache_authorizer(
                "account",
                "east",
                "second".into(),
                serde_json::json!({"result":2}),
            )
            .await;
        let east = store.shared("account", "east");
        let east = east.read().await;
        assert_eq!(east.authorizer_cache.len(), 1);
        assert_eq!(east.authorizer_cache["second"]["result"], 2);
        drop(east);
        assert!(store
            .shared("account", "west")
            .read()
            .await
            .authorizer_cache
            .contains_key("other"));
    }

    #[tokio::test]
    async fn cache_lookup_checks_only_its_key_without_removing_other_entries() {
        let store = ApiGwStore::new();
        let shared = store.shared("account", "east");
        {
            let mut guard = shared.write().await;
            guard.authorizer_cache.insert(
                "valid".into(),
                serde_json::json!({"expiresAt":u64::MAX,"result":{"principalId":"owned"}}),
            );
            guard.authorizer_cache.insert(
                "expired".into(),
                serde_json::json!({"expiresAt":0,"result":"old"}),
            );
            guard
                .authorizer_cache
                .insert("malformed".into(), serde_json::json!({"result":"old"}));
        }
        assert_eq!(
            store.cached_authorizer("account", "east", "valid").await,
            Some(serde_json::json!({"principalId":"owned"}))
        );
        assert!(store
            .cached_authorizer("account", "east", "expired")
            .await
            .is_none());
        assert!(store
            .cached_authorizer("account", "east", "malformed")
            .await
            .is_none());
        assert!(store
            .cached_authorizer("account", "east", "missing")
            .await
            .is_none());
        let guard = shared.read().await;
        assert_eq!(guard.authorizer_cache.len(), 3);
        assert!(guard.authorizer_cache.contains_key("expired"));
        assert!(guard.authorizer_cache.contains_key("malformed"));
    }

    #[tokio::test]
    async fn cache_insert_prunes_expired_entries_before_evicting_live_entries_in_its_scope() {
        let store = ApiGwStore::with_config(crate::ApiGatewayConfig {
            authorizer_cache_capacity: 2,
            ..Default::default()
        })
        .unwrap();
        for (account, region) in [("account", "east"), ("account", "west"), ("other", "east")] {
            let shared = store.shared(account, region);
            let mut guard = shared.write().await;
            guard.authorizer_cache.insert(
                "a-live".into(),
                serde_json::json!({"expiresAt":u64::MAX,"result":"live"}),
            );
            guard.authorizer_cache.insert(
                "z-expired".into(),
                serde_json::json!({"expiresAt":0,"result":"old"}),
            );
        }
        store
            .cache_authorizer(
                "account",
                "east",
                "new".into(),
                serde_json::json!({"expiresAt":u64::MAX,"result":"new"}),
            )
            .await;
        assert_eq!(
            store.cached_authorizer("account", "east", "a-live").await,
            Some(serde_json::json!("live"))
        );
        assert_eq!(
            store.cached_authorizer("account", "east", "new").await,
            Some(serde_json::json!("new"))
        );
        let east = store.shared("account", "east");
        let east = east.read().await;
        assert_eq!(east.authorizer_cache.len(), 2);
        assert!(!east.authorizer_cache.contains_key("z-expired"));
        drop(east);
        for (account, region) in [("account", "west"), ("other", "east")] {
            let shared = store.shared(account, region);
            let guard = shared.read().await;
            assert!(guard.authorizer_cache.contains_key("z-expired"));
            assert!(!guard.authorizer_cache.contains_key("new"));
        }
        assert!(store
            .cached_authorizer("account", "west", "new")
            .await
            .is_none());
        assert!(store
            .cached_authorizer("other", "east", "new")
            .await
            .is_none());
    }

    #[tokio::test]
    #[ignore = "Synthetic before/after authorizer-cache hit scaling benchmark"]
    async fn authorizer_cache_hit_scaling_benchmark() {
        const HITS: u32 = 1000;
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        for entries in [100, 1000, 10_000] {
            let store = ApiGwStore::with_config(crate::ApiGatewayConfig {
                authorizer_cache_capacity: entries,
                ..Default::default()
            })
            .unwrap();
            let shared = store.shared("benchmark", "region");
            let target = format!("key-{:05}", entries - 1);
            {
                let mut guard = shared.write().await;
                for index in 0..entries {
                    guard.authorizer_cache.insert(format!("key-{index:05}"), serde_json::json!({"expiresAt":u64::MAX,"result":{"principalId":"synthetic"}}));
                }
            }
            let mut old_samples = Vec::new();
            let mut new_samples = Vec::new();
            for _ in 0..3 {
                let start = std::time::Instant::now();
                for _ in 0..HITS {
                    let scoped = store.shared("benchmark", "region");
                    let mut guard = scoped.write().await;
                    let now = cache_now_secs();
                    guard.authorizer_cache.retain(|_, value| {
                        value.get("expiresAt").and_then(Value::as_u64).unwrap_or(0) > now
                    });
                    let result = cached_authorizer(&guard.authorizer_cache, &target);
                    std::hint::black_box(result);
                }
                old_samples.push(start.elapsed());
                let start = std::time::Instant::now();
                for _ in 0..HITS {
                    std::hint::black_box(
                        store
                            .cached_authorizer("benchmark", "region", &target)
                            .await,
                    );
                }
                new_samples.push(start.elapsed());
            }
            old_samples.sort();
            new_samples.sort();
            eprintln!("authorizer-cache build={profile} entries={entries} hits={HITS} samples=3 median_before_ns_per_hit={} median_after_ns_per_hit={}", old_samples[1].as_nanos() / u128::from(HITS), new_samples[1].as_nanos() / u128::from(HITS));
            assert_eq!(shared.read().await.authorizer_cache.len(), entries);
        }
    }

    #[test]
    fn invalid_config_is_rejected_before_store_construction() {
        assert!(ApiGwStore::with_config(crate::ApiGatewayConfig {
            websocket_outbound_channel_capacity: 0,
            ..Default::default()
        })
        .is_err());
    }
}
