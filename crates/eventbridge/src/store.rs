use locallycloud_state::StateDb;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use dashmap::DashMap;
use time::OffsetDateTime;
use tokio::sync::RwLock;

use crate::arn::EbArn;
use crate::model::{
    ApiDestination, Archive, Connection, EventBus, Pipe, Replay, Rule, Schedule, ScheduleGroup,
};

mod archive_persistence;
mod crypto;
mod persistence;
#[cfg(test)]
mod restart_tests;

use crypto::ConnectionCrypto;

type ScopeKey = (String, String);

#[derive(Default)]
pub struct AccountState {
    pub buses: BTreeMap<String, EventBus>,
    pub archives: BTreeMap<String, Archive>,
    pub replays: BTreeMap<String, Replay>,
    pub connections: BTreeMap<String, Connection>,
    pub api_destinations: BTreeMap<String, ApiDestination>,
    pub schedule_groups: BTreeMap<String, ScheduleGroup>,
    pub schedules: BTreeMap<(String, String), Schedule>,
    pub pipes: BTreeMap<String, Pipe>,
}

#[derive(Default)]
pub struct EbStore {
    scopes: DashMap<ScopeKey, Arc<RwLock<AccountState>>>,
    persistence: Option<Arc<StateDb>>,
    connection_crypto: Option<ConnectionCrypto>,
    persist_lock: tokio::sync::Mutex<()>,
    pub(crate) scheduler_gate: tokio::sync::RwLock<()>,
    poisoned: AtomicBool,
    pending_notify: Arc<tokio::sync::Notify>,
}

impl EbStore {
    pub(crate) async fn resource_regions(
        &self,
        account: &str,
        service: &str,
    ) -> Result<Vec<String>, &'static str> {
        if !self.healthy() {
            return Err("EventBridge inventory unavailable");
        }
        let scopes: Vec<_> = self
            .scopes
            .iter()
            .filter(|e| e.key().0 == account)
            .map(|e| (e.key().1.clone(), e.value().clone()))
            .collect();
        let mut regions = Vec::new();
        for (region, scope) in scopes {
            let s = scope.read().await;
            let bus = s.buses.values().any(|b| {
                b.name != "default"
                    || !b.rules.is_empty()
                    || b.policy.is_some()
                    || b.kms_key_identifier.is_some()
                    || b.dead_letter_config.is_some()
                    || b.log_config.is_some()
                    || b.description.is_some()
                    || !b.tags.is_empty()
            });
            let present = match service {
                "events" => {
                    bus || !s.archives.is_empty()
                        || !s.replays.is_empty()
                        || !s.connections.is_empty()
                        || !s.api_destinations.is_empty()
                }
                "scheduler" => {
                    !s.schedules.is_empty()
                        || s.schedule_groups
                            .values()
                            .any(|g| g.name != "default" || !g.tags.is_empty())
                }
                "pipes" => !s.pipes.is_empty(),
                _ => false,
            };
            if present {
                regions.push(region);
            }
        }
        Ok(regions)
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub async fn scope(&self, account: &str, region: &str) -> Arc<RwLock<AccountState>> {
        let key = (account.to_string(), region.to_string());
        let state = self
            .scopes
            .entry(key)
            .or_insert_with(|| Arc::new(RwLock::new(AccountState::default())))
            .clone();
        {
            let mut guard = state.write().await;
            if !guard.buses.contains_key("default") {
                guard.buses.insert(
                    "default".into(),
                    EventBus {
                        name: "default".into(),
                        arn: EbArn::EventBus {
                            region: region.into(),
                            account: account.into(),
                            name: "default".into(),
                        }
                        .to_string(),
                        description: None,
                        event_source_name: None,
                        policy: None,
                        kms_key_identifier: None,
                        dead_letter_config: None,
                        log_config: None,
                        rules: BTreeMap::new(),
                        tags: BTreeMap::new(),
                    },
                );
            }
            if !guard.schedule_groups.contains_key("default") {
                let now = OffsetDateTime::now_utc();
                guard.schedule_groups.insert(
                    "default".into(),
                    ScheduleGroup {
                        name: "default".into(),
                        arn: EbArn::ScheduleGroup {
                            region: region.into(),
                            account: account.into(),
                            name: "default".into(),
                        }
                        .to_string(),
                        created_at: now,
                        modified_at: now,
                        tags: BTreeMap::new(),
                    },
                );
            }
        }
        state
    }

    pub fn scope_if_present(
        &self,
        account: &str,
        region: &str,
    ) -> Option<Arc<RwLock<AccountState>>> {
        self.scopes
            .get(&(account.to_string(), region.to_string()))
            .map(|entry| entry.clone())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PendingFanout {
    pub id: String,
    pub account: String,
    pub region: String,
    pub event: Value,
    pub rules: Vec<Rule>,
}
