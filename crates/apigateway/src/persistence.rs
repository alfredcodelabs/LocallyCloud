//! Small scoped control-plane snapshots; live connections and caches are not serialized.
use super::*;
use locallycloud_state::StateDb;
use rusqlite::params;

#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct ScopeSnapshot {
    rest: Vec<(String, RestApiRecord)>,
    v2: Vec<(String, ApiV2Record)>,
    shared: SharedRecord,
}

pub(crate) struct Persistence {
    state: Arc<StateDb>,
    cipher: locallycloud_state::StateCipher,
}
impl Persistence {
    pub(crate) fn new(
        state: Arc<StateDb>,
        cipher: locallycloud_state::StateCipher,
    ) -> Result<Self, String> {
        state.connection().map_err(|e| e.to_string())?.execute_batch(
            "CREATE TABLE IF NOT EXISTS apigateway_scopes(account TEXT NOT NULL,region TEXT NOT NULL,version INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(account,region));",
        ).map_err(|e| e.to_string())?;
        Ok(Self { state, cipher })
    }
    pub(crate) fn restore(&self, store: &ApiGwStore) -> Result<(), String> {
        let connection = self.state.connection().map_err(|e| e.to_string())?;
        let mut statement = connection
            .prepare("SELECT account,region,version,payload FROM apigateway_scopes")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (account, region, version, payload) = row.map_err(|e| e.to_string())?;
            if version != 1 {
                return Err("unsupported API Gateway state schema".into());
            }
            let clear = self
                .cipher
                .open(&["apigateway", &account, &region], &payload)
                .map_err(|e| e.to_string())?;
            let snapshot: ScopeSnapshot =
                serde_json::from_slice(&clear).map_err(|e| e.to_string())?;
            store.install_scope(&account, &region, snapshot);
        }
        Ok(())
    }
    pub(crate) fn save(
        &self,
        account: &str,
        region: &str,
        snapshot: &ScopeSnapshot,
    ) -> Result<(), String> {
        let clear = serde_json::to_vec(snapshot).map_err(|e| e.to_string())?;
        let payload = self
            .cipher
            .seal(&["apigateway", account, region], &clear)
            .map_err(|e| e.to_string())?;
        self.state.connection().map_err(|e| e.to_string())?.execute(
            "INSERT INTO apigateway_scopes(account,region,version,payload) VALUES(?1,?2,1,?3) ON CONFLICT(account,region) DO UPDATE SET version=excluded.version,payload=excluded.payload",
            params![account,region,payload],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }
}

impl ApiGwStore {
    pub(crate) async fn snapshot_scope(&self, account: &str, region: &str) -> ScopeSnapshot {
        let rest: Vec<_> = self
            .rest
            .iter()
            .filter(|e| e.key().0 == account && e.key().1 == region)
            .map(|e| (e.key().2.clone(), e.value().clone()))
            .collect();
        let v2: Vec<_> = self
            .v2
            .iter()
            .filter(|e| e.key().0 == account && e.key().1 == region)
            .map(|e| (e.key().2.clone(), e.value().clone()))
            .collect();
        let mut snapshot = ScopeSnapshot::default();
        for (id, record) in rest {
            snapshot.rest.push((id, record.read().await.clone()));
        }
        for (id, record) in v2 {
            snapshot.v2.push((id, record.read().await.clone()));
        }
        if let Some(record) = self
            .shared
            .get(&(account.into(), region.into()))
            .map(|e| e.value().clone())
        {
            let record = record.read().await;
            snapshot.shared = SharedRecord {
                api_keys: record.api_keys.clone(),
                usage_plans: record.usage_plans.clone(),
                domains: record.domains.clone(),
                private_domains: record.private_domains.clone(),
                domain_access_associations: record.domain_access_associations.clone(),
                connections: BTreeMap::new(),
                authorizer_cache: BTreeMap::new(),
            };
        }
        snapshot
    }
    pub(crate) fn install_scope(&self, account: &str, region: &str, snapshot: ScopeSnapshot) {
        self.rest
            .retain(|key, _| key.0 != account || key.1 != region);
        self.v2.retain(|key, _| key.0 != account || key.1 != region);
        for (id, record) in snapshot.rest {
            self.rest
                .insert(key(account, region, &id), Arc::new(RwLock::new(record)));
        }
        for (id, record) in snapshot.v2 {
            self.v2
                .insert(key(account, region, &id), Arc::new(RwLock::new(record)));
        }
        self.shared.insert(
            (account.into(), region.into()),
            Arc::new(RwLock::new(snapshot.shared)),
        );
    }
    pub(crate) async fn publish_scope(
        &self,
        account: &str,
        region: &str,
        mut snapshot: ScopeSnapshot,
        commit: impl FnOnce(&ScopeSnapshot) -> Result<(), String>,
    ) -> Result<(), String> {
        // Retain live WebSocket state; only the configuration belongs to the staged store.
        let shared = self
            .shared
            .get(&(account.into(), region.into()))
            .map(|e| e.value().clone());
        let mut guard = match &shared {
            Some(record) => Some(record.write().await),
            None => None,
        };
        // Acquire runtime locks before commit; publication below has no cancellation point.
        commit(&snapshot)?;
        if let Some(record) = guard.as_mut() {
            let mut configuration = std::mem::take(&mut snapshot.shared);
            configuration.connections = std::mem::take(&mut record.connections);
            configuration.authorizer_cache = std::mem::take(&mut record.authorizer_cache);
            **record = configuration;
        }
        // Replace existing API records atomically; retain-then-insert would expose a
        // transient 404 to concurrent invocations during an ordinary configuration update.
        let rest_ids: std::collections::BTreeSet<_> =
            snapshot.rest.iter().map(|(id, _)| id.clone()).collect();
        let v2_ids: std::collections::BTreeSet<_> =
            snapshot.v2.iter().map(|(id, _)| id.clone()).collect();
        self.rest
            .retain(|key, _| key.0 != account || key.1 != region || rest_ids.contains(&key.2));
        self.v2
            .retain(|key, _| key.0 != account || key.1 != region || v2_ids.contains(&key.2));
        for (id, record) in snapshot.rest {
            self.rest
                .insert(key(account, region, &id), Arc::new(RwLock::new(record)));
        }
        for (id, record) in snapshot.v2 {
            self.v2
                .insert(key(account, region, &id), Arc::new(RwLock::new(record)));
        }
        if shared.is_none() {
            self.shared.insert(
                (account.into(), region.into()),
                Arc::new(RwLock::new(snapshot.shared)),
            );
        }
        Ok(())
    }
}

impl ApiGwStore {
    pub(crate) async fn restore_domain_bindings(
        &self,
        bindings: &crate::domains::DomainBindings,
    ) -> Result<(), crate::error::ApiGwError> {
        let scopes: Vec<_> = self
            .shared
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        for ((account, region), record) in scopes {
            let record = record.read().await;
            for (name, domain) in &record.domains {
                let config = domain
                    .get("domainNameConfigurations")
                    .and_then(Value::as_array)
                    .and_then(|v| v.first());
                let (arn, target) = if let Some(config) = config {
                    (
                        config.get("certificateArn").and_then(Value::as_str),
                        config.get("apiGatewayDomainName").and_then(Value::as_str),
                    )
                } else {
                    (
                        domain.get("regionalCertificateArn").and_then(Value::as_str),
                        domain.get("regionalDomainName").and_then(Value::as_str),
                    )
                };
                let arn = arn.ok_or_else(|| {
                    crate::error::ApiGwError::Internal(
                        "Persisted custom domain has no regional certificate".into(),
                    )
                })?;
                let binding = bindings.prepare(&account, &region, name, arn, target)?;
                bindings.publish(binding)?;
            }
        }
        Ok(())
    }
}
