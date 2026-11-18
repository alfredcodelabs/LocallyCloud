//! Committed IAM state and isolated mutation staging.
use crate::error::IamStsError;
use crate::model::{IamGroup, IamPolicy, IamRole, IamUser, InstanceProfile};
use crate::persistence::IamPersistence;
use crate::transaction::ResourceScope;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, RwLock};

/// Explicit account-root provisioning is process configuration, never an IAM user or DB entity.
#[derive(Clone)]
pub(crate) struct AccountRoot {
    pub account: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}
impl AccountRoot {
    pub fn arn(&self) -> String {
        format!("arn:aws:iam::{}:root", self.account)
    }
}

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
impl IamRecords {
    fn select(&self, scope: &ResourceScope) -> Self {
        fn selected<T: Clone>(map: &BTreeMap<Key, T>, keys: &BTreeSet<Key>) -> BTreeMap<Key, T> {
            keys.iter()
                .filter_map(|key| map.get(key).map(|value| (key.clone(), value.clone())))
                .collect()
        }
        Self {
            bootstrap_initialized: BTreeSet::new(),
            users: selected(&self.users, &scope.users),
            groups: selected(&self.groups, &scope.groups),
            roles: selected(&self.roles, &scope.roles),
            policies: selected(&self.policies, &scope.policies),
            instance_profiles: selected(&self.instance_profiles, &scope.instance_profiles),
        }
    }
    fn within(&self, scope: &ResourceScope) -> bool {
        self.bootstrap_initialized.is_empty()
            && self.users.keys().all(|key| scope.users.contains(key))
            && self.groups.keys().all(|key| scope.groups.contains(key))
            && self.roles.keys().all(|key| scope.roles.contains(key))
            && self.policies.keys().all(|key| scope.policies.contains(key))
            && self
                .instance_profiles
                .keys()
                .all(|key| scope.instance_profiles.contains(key))
    }
    fn publish(&mut self, scope: ResourceScope, after: Self) {
        fn publish<T>(map: &mut BTreeMap<Key, T>, keys: BTreeSet<Key>, after: BTreeMap<Key, T>) {
            for key in keys {
                map.remove(&key);
            }
            map.extend(after);
        }
        publish(&mut self.users, scope.users, after.users);
        publish(&mut self.groups, scope.groups, after.groups);
        publish(&mut self.roles, scope.roles, after.roles);
        publish(&mut self.policies, scope.policies, after.policies);
        publish(
            &mut self.instance_profiles,
            scope.instance_profiles,
            after.instance_profiles,
        );
    }
}
#[derive(Default)]
pub struct IamStore {
    records: RwLock<IamRecords>,
    root: RwLock<Option<AccountRoot>>,
    mutation: Mutex<()>,
    persistence: Option<Arc<IamPersistence>>,
}
#[cfg(test)]
pub(crate) enum TagTarget {
    User(String),
    Role(String),
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
            root: RwLock::new(None),
            mutation: Mutex::new(()),
            persistence: Some(persistence),
        })
    }
    pub(crate) fn transact<T>(
        &self,
        operation: impl FnOnce(&IamStore) -> Result<T, IamStsError>,
    ) -> Result<T, IamStsError> {
        let _mutation = self.mutation.lock().unwrap();
        // Stage one copy; the mutation gate keeps the committed comparison stable.
        let staged = Self {
            records: RwLock::new(self.records.read().unwrap().clone()),
            root: RwLock::new(self.root.read().unwrap().clone()),
            ..Self::default()
        };
        let result = operation(&staged)?;
        let after = staged.records.into_inner().unwrap();
        if let Some(persistence) = &self.persistence {
            persistence.commit_resources(&self.records.read().unwrap(), &after)?;
        }
        *self.records.write().unwrap() = after;
        Ok(result)
    }
    pub(crate) fn transact_resources<T>(
        &self,
        scope: ResourceScope,
        operation: impl FnOnce(&IamStore) -> Result<T, IamStsError>,
    ) -> Result<T, IamStsError> {
        let _mutation = self.mutation.lock().unwrap();
        let before = self.records.read().unwrap().select(&scope);
        let staged = Self {
            records: RwLock::new(before.clone()),
            ..Self::default()
        };
        let result = operation(&staged)?;
        let root_untouched = staged.root.read().unwrap().is_none();
        let after = staged.records.into_inner().unwrap();
        if !root_untouched || !after.within(&scope) {
            return Err(crate::persistence::state_error(
                "IAM transaction escaped its resource scope",
            ));
        }
        if let Some(persistence) = &self.persistence {
            persistence.commit_resources(&before, &after)?;
        }
        self.records.write().unwrap().publish(scope, after);
        Ok(result)
    }

    #[cfg(test)]
    pub(crate) fn transact_tags<T>(
        &self,
        account: &str,
        target: TagTarget,
        operation: impl FnOnce(&IamStore) -> Result<T, IamStsError>,
    ) -> Result<T, IamStsError> {
        let mut scope = ResourceScope::default();
        match &target {
            TagTarget::User(name) => {
                scope.users.insert(key(account, name));
            }
            TagTarget::Role(name) => {
                scope.roles.insert(key(account, name));
            }
        }
        self.transact_resources(scope, |staged| {
            let result = operation(staged)?;
            let present = match &target {
                TagTarget::User(name) => staged.get_user(account, name).is_some(),
                TagTarget::Role(name) => staged.get_role(account, name).is_some(),
            };
            if !present {
                return Err(crate::persistence::state_error(
                    "IAM tag target was removed",
                ));
            }
            Ok(result)
        })
    }

    pub(crate) fn provision_root(&self, root: AccountRoot) -> Result<(), ()> {
        if self.records.read().unwrap().users.values().any(|user| {
            user.access_keys
                .iter()
                .any(|key| key.access_key_id == root.access_key_id)
        }) {
            return Err(());
        }
        *self.root.write().unwrap() = Some(root);
        Ok(())
    }
    pub(crate) fn root_for_key(&self, account: &str, key: &str) -> Option<AccountRoot> {
        self.root
            .read()
            .unwrap()
            .as_ref()
            .filter(|root| root.account == account && root.access_key_id == key)
            .cloned()
    }
    pub(crate) fn root_for_account(&self, account: &str) -> Option<AccountRoot> {
        self.root
            .read()
            .unwrap()
            .as_ref()
            .filter(|root| root.account == account)
            .cloned()
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
    /// Resolve credential ownership across accounts without returning signing material.
    /// Preserve duplicates so the caller rejects collisions even within one account.
    pub(crate) fn active_key_accounts(&self, access_key_id: &str) -> Vec<String> {
        self.records
            .read()
            .unwrap()
            .users
            .iter()
            .flat_map(|((account, _), user)| {
                user.access_keys
                    .iter()
                    .filter(move |key| key.access_key_id == access_key_id && key.status == "Active")
                    .map(move |_| account.clone())
            })
            .collect()
    }

    pub(crate) fn root_account_for_key(&self, access_key_id: &str) -> Option<String> {
        self.root
            .read()
            .unwrap()
            .as_ref()
            .filter(|root| root.access_key_id == access_key_id)
            .map(|root| root.account.clone())
    }

    pub(crate) fn user_for_key(&self, account: &str, access_key: &str) -> Option<IamUser> {
        self.records
            .read()
            .unwrap()
            .users
            .range(key(account, "")..)
            .take_while(|((owner, _), _)| owner == account)
            .find(|(_, user)| {
                user.access_keys
                    .iter()
                    .any(|key| key.access_key_id == access_key && key.status == "Active")
            })
            .map(|(_, user)| user.clone())
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
    pub(crate) fn read_tags<T>(
        &self,
        account: &str,
        kind: crate::tag_pagination::TagKind,
        name: &str,
        read: impl FnOnce(&str, &BTreeMap<String, String>) -> Result<T, IamStsError>,
    ) -> Result<T, IamStsError> {
        use crate::tag_pagination::TagKind;
        let records = self.records.read().unwrap();
        let entity_key = key(account, name);
        let missing = || IamStsError::NoSuchEntity("IAM tag resource not found".into());
        let (arn, tags) = match kind {
            TagKind::User => {
                let user = records.users.get(&entity_key).ok_or_else(missing)?;
                (&user.arn, &user.tags)
            }
            TagKind::Role => {
                let role = records.roles.get(&entity_key).ok_or_else(missing)?;
                (&role.arn, &role.tags)
            }
            TagKind::Policy => {
                let policy = records
                    .policies
                    .get(&entity_key)
                    .or_else(|| records.policies.get(&key("aws", name)))
                    .ok_or_else(missing)?;
                if policy.is_aws_managed {
                    return Err(IamStsError::InvalidInput(
                        "ListPolicyTags supports customer managed policies only".into(),
                    ));
                }
                (&policy.arn, &policy.tags)
            }
            TagKind::InstanceProfile => {
                let profile = records
                    .instance_profiles
                    .get(&entity_key)
                    .ok_or_else(missing)?;
                (&profile.arn, &profile.tags)
            }
        };
        read(arn, tags)
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
    fn role(name: &str) -> IamRole {
        IamRole {
            role_name: name.into(),
            role_id: "AROATEST".into(),
            arn: format!("arn:aws:iam::1:role/{name}"),
            path: "/".into(),
            create_date: "now".into(),
            assume_role_policy_document: "{}".into(),
            description: None,
            max_session_duration: 3600,
            tags: BTreeMap::new(),
            attached_policies: Vec::new(),
            inline_policies: BTreeMap::new(),
            permission_boundary: None,
        }
    }

    #[test]
    fn tag_staging_is_scoped_and_rejects_errors_or_escaping_deltas() {
        let store = IamStore::new();
        store.create_user("1", user("target"));
        store.create_user("2", user("target"));
        store.create_user("1", user("other"));
        store.create_role("1", role("worker"));
        store.mark_bootstrap_initialized("1");
        store
            .provision_root(AccountRoot {
                account: "1".into(),
                access_key_id: "fixture".into(),
                secret_access_key: "fictional".into(),
            })
            .unwrap();
        let query = crate::query::QueryRequest::parse(
            b"UserName=target&Tags.member.1.Key=k&Tags.member.1.Value=v",
        );
        let result = store.transact_tags("1", TagTarget::User("target".into()), |staged| {
            assert_eq!(staged.records.read().unwrap().users.len(), 1);
            assert!(staged.get_role("1", "worker").is_none());
            assert!(staged.get_user("2", "target").is_none());
            assert!(!staged.bootstrap_initialized("1"));
            crate::iam::tag_user(staged, "1", &query)?;
            Err::<(), _>(IamStsError::ValidationError("fixture rejection".into()))
        });
        assert!(matches!(result, Err(IamStsError::ValidationError(_))));
        assert!(store.get_user("1", "target").unwrap().tags.is_empty());
        for escape in 0..5 {
            let result = store.transact_tags("1", TagTarget::User("target".into()), |staged| {
                crate::iam::tag_user(staged, "1", &query)?;
                match escape {
                    0 => {
                        staged.create_user("1", user("extra"));
                    }
                    1 => staged.mark_bootstrap_initialized("1"),
                    2 => {
                        staged.remove_user("1", "target");
                    }
                    3 => {
                        staged
                            .provision_root(AccountRoot {
                                account: "1".into(),
                                access_key_id: "other".into(),
                                secret_access_key: "fictional".into(),
                            })
                            .unwrap();
                    }
                    _ => {
                        staged.create_role("1", role("extra"));
                    }
                }
                Ok(())
            });
            assert!(matches!(result, Err(IamStsError::InternalFailure(_))));
            assert!(store.get_user("1", "target").unwrap().tags.is_empty());
        }
        store
            .transact_tags("1", TagTarget::User("target".into()), |staged| {
                crate::iam::tag_user(staged, "1", &query)
            })
            .unwrap();
        assert_eq!(store.get_user("1", "target").unwrap().tags["k"], "v");
        assert!(store.get_user("2", "target").unwrap().tags.is_empty());
        assert!(store.get_user("1", "other").unwrap().tags.is_empty());
        assert!(store.get_user("1", "extra").is_none());
        assert!(store.get_role("1", "extra").is_none());
        assert!(store.bootstrap_initialized("1"));
        assert_eq!(
            store.root_for_account("1").unwrap().access_key_id,
            "fixture"
        );
        let missing = crate::query::QueryRequest::parse(
            b"UserName=missing&Tags.member.1.Key=k&Tags.member.1.Value=v",
        );
        assert!(matches!(
            store.transact_tags("1", TagTarget::User("missing".into()), |staged| {
                crate::iam::tag_user(staged, "1", &missing)
            }),
            Err(IamStsError::NoSuchEntity(_))
        ));
    }

    #[test]
    fn tag_transactions_and_full_transactions_share_one_mutation_gate() {
        let store = Arc::new(IamStore::new());
        store.create_user("1", user("target"));
        store.create_user("1", user("other"));
        store.create_role("1", role("worker"));
        let barrier = Arc::new(std::sync::Barrier::new(3));
        std::thread::scope(|threads| {
            for (kind, field) in [
                (0, "UserName=target"),
                (1, "RoleName=worker"),
                (2, "UserName=other"),
            ] {
                let store = store.clone();
                let barrier = barrier.clone();
                threads.spawn(move || {
                    barrier.wait();
                    for index in 0..25 {
                        let query = crate::query::QueryRequest::parse(
                            format!("{field}&Tags.member.1.Key=k{index}&Tags.member.1.Value=v")
                                .as_bytes(),
                        );
                        match kind {
                            0 => store.transact_tags(
                                "1",
                                TagTarget::User("target".into()),
                                |staged| crate::iam::tag_user(staged, "1", &query),
                            ),
                            1 => store.transact_tags(
                                "1",
                                TagTarget::Role("worker".into()),
                                |staged| crate::iam::tag_role(staged, "1", &query),
                            ),
                            _ => store.transact(|staged| crate::iam::tag_user(staged, "1", &query)),
                        }
                        .unwrap();
                    }
                });
            }
        });
        assert_eq!(store.get_user("1", "target").unwrap().tags.len(), 25);
        assert_eq!(store.get_user("1", "other").unwrap().tags.len(), 25);
        assert_eq!(store.get_role("1", "worker").unwrap().tags.len(), 25);
    }

    #[test]
    fn durable_tag_transactions_preserve_unrelated_rows_and_rollback_before_publish() {
        use locallycloud_state::{StateCipher, StateDb};
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        fn rows(db: &StateDb) -> BTreeMap<(String, String, String), Vec<u8>> {
            let connection = db.connection().unwrap();
            let mut query = connection
                .prepare("SELECT account,kind,name,payload FROM iam_resources")
                .unwrap();
            let rows = query
                .query_map([], |row| {
                    Ok(((row.get(0)?, row.get(1)?, row.get(2)?), row.get(3)?))
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            rows
        }
        let directory = Directory(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../compatibility-tests/.work/iam-vpc-fixes")
                .join(format!("iam-scoped-tags-{}", uuid::Uuid::new_v4())),
        );
        let db = Arc::new(StateDb::open(directory.0.join("state.db")).unwrap());
        let persistence = Arc::new(
            IamPersistence::with_cipher(db.clone(), StateCipher::with_key(&[7; 32])).unwrap(),
        );
        let store = IamStore::durable(persistence.clone()).unwrap();
        store
            .transact(|staged| {
                staged.create_user("1", user("target"));
                staged.create_user("2", user("target"));
                staged.create_role("1", role("worker"));
                staged.mark_bootstrap_initialized("1");
                crate::iam::create_group(
                    staged,
                    "1",
                    &crate::query::QueryRequest::parse(b"GroupName=untouched"),
                )?;
                Ok(())
            })
            .unwrap();
        let before = rows(&db);
        db.connection().unwrap().execute_batch("CREATE TRIGGER reject_tag BEFORE UPDATE ON iam_resources BEGIN SELECT RAISE(ABORT,'fixture write failure'); END;").unwrap();
        for (kind, name, field) in [
            ("user", "target", "UserName"),
            ("role", "worker", "RoleName"),
        ] {
            let query = crate::query::QueryRequest::parse(
                format!("{field}={name}&Tags.member.1.Key=k&Tags.member.1.Value=v").as_bytes(),
            );
            let result = match kind {
                "user" => store.transact_tags("1", TagTarget::User(name.into()), |staged| {
                    crate::iam::tag_user(staged, "1", &query)
                }),
                _ => store.transact_tags("1", TagTarget::Role(name.into()), |staged| {
                    crate::iam::tag_role(staged, "1", &query)
                }),
            };
            assert!(matches!(result, Err(IamStsError::InternalFailure(_))));
        }
        assert_eq!(rows(&db), before);
        assert!(store.get_user("1", "target").unwrap().tags.is_empty());
        assert!(store.get_role("1", "worker").unwrap().tags.is_empty());
        db.connection()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_tag")
            .unwrap();
        for (kind, name, field) in [
            ("user", "target", "UserName"),
            ("role", "worker", "RoleName"),
        ] {
            let tag = crate::query::QueryRequest::parse(
                format!("{field}={name}&Tags.member.1.Key=k&Tags.member.1.Value=v").as_bytes(),
            );
            match kind {
                "user" => store.transact_tags("1", TagTarget::User(name.into()), |staged| {
                    crate::iam::tag_user(staged, "1", &tag)
                }),
                _ => store.transact_tags("1", TagTarget::Role(name.into()), |staged| {
                    crate::iam::tag_role(staged, "1", &tag)
                }),
            }
            .unwrap();
        }
        let after = rows(&db);
        assert_eq!(after.len(), before.len());
        for (key, payload) in &before {
            if key.0 != "1" || !matches!(key.1.as_str(), "user" | "role") {
                assert_eq!(after.get(key), Some(payload));
            }
        }
        let restored = IamStore::durable(persistence.clone()).unwrap();
        assert_eq!(restored.get_user("1", "target").unwrap().tags["k"], "v");
        assert_eq!(restored.get_role("1", "worker").unwrap().tags["k"], "v");
        assert!(restored.bootstrap_initialized("1"));
        for (kind, name, field) in [
            ("user", "target", "UserName"),
            ("role", "worker", "RoleName"),
        ] {
            let untag = crate::query::QueryRequest::parse(
                format!("{field}={name}&TagKeys.member.1=k").as_bytes(),
            );
            match kind {
                "user" => store.transact_tags("1", TagTarget::User(name.into()), |staged| {
                    crate::iam::untag_user(staged, "1", &untag)
                }),
                _ => store.transact_tags("1", TagTarget::Role(name.into()), |staged| {
                    crate::iam::untag_role(staged, "1", &untag)
                }),
            }
            .unwrap();
        }
        let restored = IamStore::durable(persistence).unwrap();
        assert!(restored.get_user("1", "target").unwrap().tags.is_empty());
        assert!(restored.get_role("1", "worker").unwrap().tags.is_empty());
        assert!(restored.get_group("1", "untouched").is_some());
        assert!(restored.get_user("2", "target").unwrap().tags.is_empty());
    }
}
