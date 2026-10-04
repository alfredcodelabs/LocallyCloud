//! Concurrency-safe IAM state store.
//!
//! Resources are keyed by `(account, name)` (IAM is partition-global, so region is not part
//! of the key). Creation is atomic create-if-absent via the `DashMap` entry API: two
//! same-name creates yield at most one resource, the loser observing the conflict.

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

use crate::model::{IamGroup, IamPolicy, IamRole, IamUser, InstanceProfile};

type Key = (String, String);

fn key(account: &str, name: &str) -> Key {
    (account.to_string(), name.to_string())
}

/// The IAM resource store. All maps are concurrent; values are cloned on read.
#[derive(Default)]
pub struct IamStore {
    users: DashMap<Key, IamUser>,
    groups: DashMap<Key, IamGroup>,
    roles: DashMap<Key, IamRole>,
    policies: DashMap<Key, IamPolicy>,
    instance_profiles: DashMap<Key, InstanceProfile>,
}

/// Outcome of an atomic create-if-absent.
pub enum Created<T> {
    Inserted(T),
    AlreadyExists,
}

impl IamStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has_resources(&self, account: &str) -> bool {
        self.users.iter().any(|e| e.key().0 == account)
            || self.groups.iter().any(|e| e.key().0 == account)
            || self.roles.iter().any(|e| e.key().0 == account)
            || self.policies.iter().any(|e| e.key().0 == account)
            || self.instance_profiles.iter().any(|e| e.key().0 == account)
    }

    // ---- users ----------------------------------------------------------------
    pub fn create_user(&self, account: &str, user: IamUser) -> Created<IamUser> {
        match self.users.entry(key(account, &user.user_name)) {
            Entry::Occupied(_) => Created::AlreadyExists,
            Entry::Vacant(slot) => {
                let stored = user.clone();
                slot.insert(user);
                Created::Inserted(stored)
            }
        }
    }
    pub fn get_user(&self, account: &str, name: &str) -> Option<IamUser> {
        self.users.get(&key(account, name)).map(|u| u.clone())
    }
    pub fn remove_user(&self, account: &str, name: &str) -> Option<IamUser> {
        self.users.remove(&key(account, name)).map(|(_, v)| v)
    }
    pub fn list_users(&self, account: &str) -> Vec<IamUser> {
        self.users
            .iter()
            .filter(|e| e.key().0 == account)
            .map(|e| e.value().clone())
            .collect()
    }
    /// Apply a mutation to a stored user; returns `false` when absent.
    pub fn update_user<F: FnOnce(&mut IamUser)>(&self, account: &str, name: &str, f: F) -> bool {
        match self.users.get_mut(&key(account, name)) {
            Some(mut u) => {
                f(&mut u);
                true
            }
            None => false,
        }
    }

    // ---- groups ---------------------------------------------------------------
    pub fn create_group(&self, account: &str, group: IamGroup) -> Created<IamGroup> {
        match self.groups.entry(key(account, &group.group_name)) {
            Entry::Occupied(_) => Created::AlreadyExists,
            Entry::Vacant(slot) => {
                let stored = group.clone();
                slot.insert(group);
                Created::Inserted(stored)
            }
        }
    }
    pub fn get_group(&self, account: &str, name: &str) -> Option<IamGroup> {
        self.groups.get(&key(account, name)).map(|g| g.clone())
    }
    pub fn remove_group(&self, account: &str, name: &str) -> Option<IamGroup> {
        self.groups.remove(&key(account, name)).map(|(_, v)| v)
    }
    pub fn list_groups(&self, account: &str) -> Vec<IamGroup> {
        self.groups
            .iter()
            .filter(|e| e.key().0 == account)
            .map(|e| e.value().clone())
            .collect()
    }
    pub fn update_group<F: FnOnce(&mut IamGroup)>(&self, account: &str, name: &str, f: F) -> bool {
        match self.groups.get_mut(&key(account, name)) {
            Some(mut g) => {
                f(&mut g);
                true
            }
            None => false,
        }
    }

    // ---- roles ----------------------------------------------------------------
    pub fn create_role(&self, account: &str, role: IamRole) -> Created<IamRole> {
        match self.roles.entry(key(account, &role.role_name)) {
            Entry::Occupied(_) => Created::AlreadyExists,
            Entry::Vacant(slot) => {
                let stored = role.clone();
                slot.insert(role);
                Created::Inserted(stored)
            }
        }
    }
    pub fn get_role(&self, account: &str, name: &str) -> Option<IamRole> {
        self.roles.get(&key(account, name)).map(|r| r.clone())
    }
    pub fn remove_role(&self, account: &str, name: &str) -> Option<IamRole> {
        self.roles.remove(&key(account, name)).map(|(_, v)| v)
    }
    pub fn list_roles(&self, account: &str) -> Vec<IamRole> {
        self.roles
            .iter()
            .filter(|e| e.key().0 == account)
            .map(|e| e.value().clone())
            .collect()
    }
    pub fn update_role<F: FnOnce(&mut IamRole)>(&self, account: &str, name: &str, f: F) -> bool {
        match self.roles.get_mut(&key(account, name)) {
            Some(mut r) => {
                f(&mut r);
                true
            }
            None => false,
        }
    }

    // ---- policies (keyed by ARN within the account) ---------------------------
    pub fn insert_policy(&self, account: &str, policy: IamPolicy) -> Created<IamPolicy> {
        match self.policies.entry(key(account, &policy.arn)) {
            Entry::Occupied(_) => Created::AlreadyExists,
            Entry::Vacant(slot) => {
                let stored = policy.clone();
                slot.insert(policy);
                Created::Inserted(stored)
            }
        }
    }
    /// Insert a policy unconditionally (used to seed the AWS-managed catalog idempotently).
    pub fn seed_policy(&self, account: &str, policy: IamPolicy) {
        self.policies
            .entry(key(account, &policy.arn))
            .or_insert(policy);
    }
    pub fn get_policy(&self, account: &str, arn: &str) -> Option<IamPolicy> {
        self.policies.get(&key(account, arn)).map(|p| p.clone())
    }
    pub fn remove_policy(&self, account: &str, arn: &str) -> Option<IamPolicy> {
        self.policies.remove(&key(account, arn)).map(|(_, v)| v)
    }
    pub fn list_policies(&self, account: &str) -> Vec<IamPolicy> {
        self.policies
            .iter()
            .filter(|e| e.key().0 == account)
            .map(|e| e.value().clone())
            .collect()
    }
    pub fn update_policy<F: FnOnce(&mut IamPolicy)>(&self, account: &str, arn: &str, f: F) -> bool {
        match self.policies.get_mut(&key(account, arn)) {
            Some(mut p) => {
                f(&mut p);
                true
            }
            None => false,
        }
    }

    // ---- instance profiles ----------------------------------------------------
    pub fn create_instance_profile(
        &self,
        account: &str,
        profile: InstanceProfile,
    ) -> Created<InstanceProfile> {
        match self.instance_profiles.entry(key(account, &profile.name)) {
            Entry::Occupied(_) => Created::AlreadyExists,
            Entry::Vacant(slot) => {
                let stored = profile.clone();
                slot.insert(profile);
                Created::Inserted(stored)
            }
        }
    }
    pub fn get_instance_profile(&self, account: &str, name: &str) -> Option<InstanceProfile> {
        self.instance_profiles
            .get(&key(account, name))
            .map(|p| p.clone())
    }
    pub fn remove_instance_profile(&self, account: &str, name: &str) -> Option<InstanceProfile> {
        self.instance_profiles
            .remove(&key(account, name))
            .map(|(_, v)| v)
    }
    pub fn list_instance_profiles(&self, account: &str) -> Vec<InstanceProfile> {
        self.instance_profiles
            .iter()
            .filter(|e| e.key().0 == account)
            .map(|e| e.value().clone())
            .collect()
    }
    pub fn update_instance_profile<F: FnOnce(&mut InstanceProfile)>(
        &self,
        account: &str,
        name: &str,
        f: F,
    ) -> bool {
        match self.instance_profiles.get_mut(&key(account, name)) {
            Some(mut p) => {
                f(&mut p);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn user(name: &str) -> IamUser {
        IamUser {
            user_name: name.to_string(),
            user_id: "AIDAX".to_string(),
            arn: format!("arn:aws:iam::1:user/{name}"),
            path: "/".to_string(),
            create_date: "now".to_string(),
            tags: BTreeMap::new(),
            attached_policies: Vec::new(),
            inline_policies: BTreeMap::new(),
            groups: Vec::new(),
            permission_boundary: None,
            access_keys: Vec::new(),
        }
    }

    #[test]
    fn create_is_idempotent_per_name() {
        let store = IamStore::new();
        assert!(matches!(
            store.create_user("1", user("a")),
            Created::Inserted(_)
        ));
        assert!(matches!(
            store.create_user("1", user("a")),
            Created::AlreadyExists
        ));
    }

    #[test]
    fn scoped_by_account() {
        let store = IamStore::new();
        store.create_user("1", user("a"));
        assert!(store.get_user("1", "a").is_some());
        assert!(store.get_user("2", "a").is_none());
        assert_eq!(store.list_users("2").len(), 0);
    }

    #[test]
    fn update_missing_returns_false() {
        let store = IamStore::new();
        assert!(!store.update_user("1", "ghost", |_| {}));
    }
}
