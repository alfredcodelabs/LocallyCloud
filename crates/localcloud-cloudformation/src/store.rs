//! In-memory stack store, keyed by stack name within an account+region scope.

use std::sync::Arc;

use dashmap::DashMap;

use crate::model::Stack;
use crate::proto::Query;

/// Concurrent store of stacks keyed by `"{account}:{region}:{stack_name}"`.
#[derive(Default)]
pub struct CfnStore {
    stacks: DashMap<String, Stack>,
    change_sets: DashMap<String, ChangeSet>,
}

#[derive(Clone)]
pub struct ChangeSetChange {
    pub logical_id: String,
    pub resource_type: String,
    pub action: &'static str,
    pub physical_id: Option<String>,
}

#[derive(Clone)]
pub struct ChangeSet {
    pub id: String,
    pub name: String,
    pub stack_name: String,
    pub stack_id: String,
    pub change_type: String,
    pub status: String,
    pub reason: Option<String>,
    pub executed: bool,
    pub request: Query,
    pub changes: Vec<ChangeSetChange>,
}

impl CfnStore {
    pub fn new() -> Arc<Self> {
        Arc::new(CfnStore {
            stacks: DashMap::new(),
            change_sets: DashMap::new(),
        })
    }

    fn key(account: &str, region: &str, name: &str) -> String {
        format!("{account}:{region}:{name}")
    }

    pub fn get(&self, account: &str, region: &str, name: &str) -> Option<Stack> {
        self.stacks
            .get(&Self::key(account, region, name))
            .map(|s| s.clone())
    }

    /// Look up a stack by name or by full stack id.
    pub fn find(&self, account: &str, region: &str, name_or_id: &str) -> Option<Stack> {
        if let Some(s) = self.get(account, region, name_or_id) {
            return Some(s);
        }
        let prefix = format!("{account}:{region}:");
        self.stacks
            .iter()
            .find(|e| e.key().starts_with(&prefix) && e.value().stack_id == name_or_id)
            .map(|e| e.value().clone())
    }

    pub fn put(&self, account: &str, region: &str, stack: Stack) {
        self.stacks
            .insert(Self::key(account, region, &stack.stack_name), stack);
    }

    pub fn remove(&self, account: &str, region: &str, name: &str) -> Option<Stack> {
        self.stacks
            .remove(&Self::key(account, region, name))
            .map(|(_, s)| s)
    }

    pub fn list(&self, account: &str, region: &str) -> Vec<Stack> {
        let prefix = format!("{account}:{region}:");
        self.stacks
            .iter()
            .filter(|e| e.key().starts_with(&prefix))
            .map(|e| e.value().clone())
            .collect()
    }
    pub fn insert_change_set(&self, account: &str, region: &str, change: ChangeSet) -> bool {
        use dashmap::mapref::entry::Entry;
        let key = Self::key(
            account,
            region,
            &format!("{}:{}", change.stack_name, change.name),
        );
        match self.change_sets.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(change);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    pub fn claim_change_set(&self, account: &str, region: &str, change: &ChangeSet) -> bool {
        let key = Self::key(
            account,
            region,
            &format!("{}:{}", change.stack_name, change.name),
        );
        if let Some(mut entry) = self.change_sets.get_mut(&key) {
            if entry.status == "CREATE_COMPLETE" && !entry.executed {
                entry.executed = true;
                return true;
            }
        }
        false
    }

    pub fn find_change_set(
        &self,
        account: &str,
        region: &str,
        stack: &str,
        name: &str,
    ) -> Option<ChangeSet> {
        self.change_sets
            .iter()
            .find(|entry| {
                entry.key().starts_with(&format!("{account}:{region}:"))
                    && (entry.value().name == name || entry.value().id == name)
                    && (stack.is_empty()
                        || entry.value().stack_name == stack
                        || entry.value().stack_id == stack)
            })
            .map(|entry| entry.value().clone())
    }

    pub fn remove_change_set(&self, account: &str, region: &str, change: &ChangeSet) {
        self.change_sets.remove(&Self::key(
            account,
            region,
            &format!("{}:{}", change.stack_name, change.name),
        ));
    }
    pub fn review_change_set(&self, account: &str, region: &str, stack: &str) -> Option<ChangeSet> {
        self.change_sets
            .iter()
            .find(|entry| {
                entry.key().starts_with(&format!("{account}:{region}:"))
                    && entry.value().change_type == "CREATE"
                    && !entry.value().executed
                    && (entry.value().stack_name == stack || entry.value().stack_id == stack)
            })
            .map(|entry| entry.value().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_set_is_claimed_once_under_contention() {
        let store = CfnStore::new();
        let change = ChangeSet {
            id: "id".into(),
            name: "change".into(),
            stack_name: "stack".into(),
            stack_id: "stack-id".into(),
            change_type: "CREATE".into(),
            status: "CREATE_COMPLETE".into(),
            reason: None,
            executed: false,
            request: Query {
                params: Default::default(),
            },
            changes: Vec::new(),
        };
        assert!(store.insert_change_set("account", "region", change.clone()));
        let workers = (0..8)
            .map(|_| {
                let store = store.clone();
                let change = change.clone();
                std::thread::spawn(move || store.claim_change_set("account", "region", &change))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|claimed| *claimed)
                .count(),
            1
        );
        assert!(store
            .find_change_set("other-account", "region", "stack", "change")
            .is_none());
    }
}
