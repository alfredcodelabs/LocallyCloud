//! In-memory stack store, keyed by stack name within an account+region scope.

use std::sync::Arc;

use dashmap::DashMap;

use crate::model::Stack;

/// Concurrent store of stacks keyed by `"{account}:{region}:{stack_name}"`.
#[derive(Default)]
pub struct CfnStore {
    stacks: DashMap<String, Stack>,
}

impl CfnStore {
    pub fn new() -> Arc<Self> {
        Arc::new(CfnStore {
            stacks: DashMap::new(),
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
        self.stacks
            .iter()
            .find(|e| e.value().stack_id == name_or_id)
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
}
