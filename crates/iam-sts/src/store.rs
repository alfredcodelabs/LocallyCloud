//! Committed IAM state and isolated mutation staging.
use crate::error::IamStsError;
use crate::model::{IamGroup, IamPolicy, IamRole, IamUser, InstanceProfile};
use crate::persistence::IamPersistence;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, RwLock};

type Key = (String, String);
fn key(account: &str, name: &str) -> Key {
    (account.to_string(), name.to_string())
}

#[derive(Clone, Default)]
pub(crate) struct IamRecords {
    pub bootstrap_initialized: BTreeSet<String>,
    pub users: BTreeMap<Key, IamUser>,
    pub groups: BTreeMap<Key, IamGroup>,
    pub roles: BTreeMap<Key, IamRole>,
    pub policies: BTreeMap<Key, IamPolicy>,
    pub instance_profiles: BTreeMap<Key, InstanceProfile>,
}
#[derive(Default)]
pub struct IamStore {
    records: RwLock<IamRecords>,
    mutation: Mutex<()>,
    persistence: Option<Arc<IamPersistence>>,
}
pub enum Created<T> {
    Inserted(T),
    AlreadyExists,
}
impl IamStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn durable(persistence: Arc<IamPersistence>) -> Result<Self, IamStsError> {
        Ok(Self {
            records: RwLock::new(persistence.load_resources()?),
            mutation: Mutex::new(()),
            persistence: Some(persistence),
        })
    }
    pub(crate) fn transact<T>(
        &self,
        operation: impl FnOnce(&IamStore) -> Result<T, IamStsError>,
    ) -> Result<T, IamStsError> {
        let _mutation = self.mutation.lock().unwrap();
        // ponytail: clone control-plane metadata; stage per entity if IAM scale warrants it.
        let before = self.records.read().unwrap().clone();
        let staged = Self {
            records: RwLock::new(before.clone()),
            ..Self::default()
        };
        let result = operation(&staged)?;
        let after = staged.records.into_inner().unwrap();
        if let Some(persistence) = &self.persistence {
            persistence.commit_resources(&before, &after)?;
        }
        *self.records.write().unwrap() = after;
        Ok(result)
    }
    pub(crate) fn bootstrap_initialized(&self, account: &str) -> bool {
        self.records
            .read()
            .unwrap()
            .bootstrap_initialized
            .contains(account)
    }
    pub(crate) fn mark_bootstrap_initialized(&self, account: &str) {
        self.records
            .write()
            .unwrap()
            .bootstrap_initialized
            .insert(account.into());
    }
    pub fn has_resources(&self, account: &str) -> bool {
        let records = self.records.read().unwrap();
        records
            .users
            .keys()
            .chain(records.groups.keys())
            .chain(records.roles.keys())
            .chain(records.policies.keys())
            .chain(records.instance_profiles.keys())
            .any(|key| key.0 == account)
    }
    pub fn create_user(&self, account: &str, resource: IamUser) -> Created<IamUser> {
        let mut records = self.records.write().unwrap();
        match records.users.entry(key(account, &resource.user_name)) {
            std::collections::btree_map::Entry::Occupied(_) => Created::AlreadyExists,
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(resource.clone());
                Created::Inserted(resource)
            }
        }
    }
    pub fn get_user(&self, account: &str, name: &str) -> Option<IamUser> {
        self.records
            .read()
            .unwrap()
            .users
            .get(&key(account, name))
            .cloned()
    }
    pub fn remove_user(&self, account: &str, name: &str) -> Option<IamUser> {
        self.records
            .write()
            .unwrap()
            .users
            .remove(&key(account, name))
    }
    pub fn list_users(&self, account: &str) -> Vec<IamUser> {
        self.records
            .read()
            .unwrap()
            .users
            .iter()
            .filter(|(key, _)| key.0 == account)
            .map(|(_, value)| value.clone())
            .collect()
    }
    pub fn update_user<F: FnOnce(&mut IamUser)>(&self, account: &str, name: &str, f: F) -> bool {
        if let Some(resource) = self
            .records
            .write()
            .unwrap()
            .users
            .get_mut(&key(account, name))
        {
            f(resource);
            true
        } else {
            false
        }
    }
    pub fn create_group(&self, account: &str, resource: IamGroup) -> Created<IamGroup> {
        let mut records = self.records.write().unwrap();
        match records.groups.entry(key(account, &resource.group_name)) {
            std::collections::btree_map::Entry::Occupied(_) => Created::AlreadyExists,
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(resource.clone());
                Created::Inserted(resource)
            }
        }
    }
    pub fn get_group(&self, account: &str, name: &str) -> Option<IamGroup> {
        self.records
            .read()
            .unwrap()
            .groups
            .get(&key(account, name))
            .cloned()
    }
    pub fn remove_group(&self, account: &str, name: &str) -> Option<IamGroup> {
        self.records
            .write()
            .unwrap()
            .groups
            .remove(&key(account, name))
    }
    pub fn list_groups(&self, account: &str) -> Vec<IamGroup> {
        self.records
            .read()
            .unwrap()
            .groups
            .iter()
            .filter(|(key, _)| key.0 == account)
            .map(|(_, value)| value.clone())
            .collect()
    }
    pub fn update_group<F: FnOnce(&mut IamGroup)>(&self, account: &str, name: &str, f: F) -> bool {
        if let Some(resource) = self
            .records
            .write()
            .unwrap()
            .groups
            .get_mut(&key(account, name))
        {
            f(resource);
            true
        } else {
            false
        }
    }
    pub fn create_role(&self, account: &str, resource: IamRole) -> Created<IamRole> {
        let mut records = self.records.write().unwrap();
        match records.roles.entry(key(account, &resource.role_name)) {
            std::collections::btree_map::Entry::Occupied(_) => Created::AlreadyExists,
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(resource.clone());
                Created::Inserted(resource)
            }
        }
    }
    pub fn get_role(&self, account: &str, name: &str) -> Option<IamRole> {
        self.records
            .read()
            .unwrap()
            .roles
            .get(&key(account, name))
            .cloned()
    }
    pub fn remove_role(&self, account: &str, name: &str) -> Option<IamRole> {
        self.records
            .write()
            .unwrap()
            .roles
            .remove(&key(account, name))
    }
    pub fn list_roles(&self, account: &str) -> Vec<IamRole> {
        self.records
            .read()
            .unwrap()
            .roles
            .iter()
            .filter(|(key, _)| key.0 == account)
            .map(|(_, value)| value.clone())
            .collect()
    }
    pub fn update_role<F: FnOnce(&mut IamRole)>(&self, account: &str, name: &str, f: F) -> bool {
        if let Some(resource) = self
            .records
            .write()
            .unwrap()
            .roles
            .get_mut(&key(account, name))
        {
            f(resource);
            true
        } else {
            false
        }
    }
    pub fn insert_policy(&self, account: &str, resource: IamPolicy) -> Created<IamPolicy> {
        let mut records = self.records.write().unwrap();
        match records.policies.entry(key(account, &resource.arn)) {
            std::collections::btree_map::Entry::Occupied(_) => Created::AlreadyExists,
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(resource.clone());
                Created::Inserted(resource)
            }
        }
    }
    pub fn get_policy(&self, account: &str, name: &str) -> Option<IamPolicy> {
        self.records
            .read()
            .unwrap()
            .policies
            .get(&key(account, name))
            .cloned()
    }
    pub fn remove_policy(&self, account: &str, name: &str) -> Option<IamPolicy> {
        self.records
            .write()
            .unwrap()
            .policies
            .remove(&key(account, name))
    }
    pub fn list_policies(&self, account: &str) -> Vec<IamPolicy> {
        self.records
            .read()
            .unwrap()
            .policies
            .iter()
            .filter(|(key, _)| key.0 == account)
            .map(|(_, value)| value.clone())
            .collect()
    }
    pub fn update_policy<F: FnOnce(&mut IamPolicy)>(
        &self,
        account: &str,
        name: &str,
        f: F,
    ) -> bool {
        if let Some(resource) = self
            .records
            .write()
            .unwrap()
            .policies
            .get_mut(&key(account, name))
        {
            f(resource);
            true
        } else {
            false
        }
    }
    pub fn create_instance_profile(
        &self,
        account: &str,
        resource: InstanceProfile,
    ) -> Created<InstanceProfile> {
        let mut records = self.records.write().unwrap();
        match records
            .instance_profiles
            .entry(key(account, &resource.name))
        {
            std::collections::btree_map::Entry::Occupied(_) => Created::AlreadyExists,
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(resource.clone());
                Created::Inserted(resource)
            }
        }
    }
    pub fn get_instance_profile(&self, account: &str, name: &str) -> Option<InstanceProfile> {
        self.records
            .read()
            .unwrap()
            .instance_profiles
            .get(&key(account, name))
            .cloned()
    }
    pub fn remove_instance_profile(&self, account: &str, name: &str) -> Option<InstanceProfile> {
        self.records
            .write()
            .unwrap()
            .instance_profiles
            .remove(&key(account, name))
    }
    pub fn list_instance_profiles(&self, account: &str) -> Vec<InstanceProfile> {
        self.records
            .read()
            .unwrap()
            .instance_profiles
            .iter()
            .filter(|(key, _)| key.0 == account)
            .map(|(_, value)| value.clone())
            .collect()
    }
    pub fn update_instance_profile<F: FnOnce(&mut InstanceProfile)>(
        &self,
        account: &str,
        name: &str,
        f: F,
    ) -> bool {
        if let Some(resource) = self
            .records
            .write()
            .unwrap()
            .instance_profiles
            .get_mut(&key(account, name))
        {
            f(resource);
            true
        } else {
            false
        }
    }
    pub fn seed_policy(&self, account: &str, policy: IamPolicy) {
        self.records
            .write()
            .unwrap()
            .policies
            .entry(key(account, &policy.arn))
            .or_insert(policy);
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
