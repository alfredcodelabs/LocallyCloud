use crate::persistence::KmsPersistence;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use localcloud_state::StateDb;
use std::sync::Arc;

use crate::error::KmsError;
use crate::model::{AliasRecord, KeyListEntry, KeyRecord, Scope};

#[derive(Eq, Hash, PartialEq)]
struct StoreKey {
    scope: Scope,
    key_id: String,
}

impl StoreKey {
    fn new(scope: &Scope, key_id: &str) -> Self {
        Self {
            scope: scope.clone(),
            key_id: key_id.to_owned(),
        }
    }
}

#[derive(Eq, Hash, PartialEq)]
struct DefaultKey {
    scope: Scope,
    service: String,
}

impl DefaultKey {
    fn new(scope: &Scope, service: &str) -> Self {
        Self {
            scope: scope.clone(),
            service: service.to_owned(),
        }
    }
}

#[derive(Eq, Hash, PartialEq)]
struct AliasKey {
    scope: Scope,
    alias_name: String,
}

impl AliasKey {
    fn new(scope: &Scope, alias_name: &str) -> Self {
        Self {
            scope: scope.clone(),
            alias_name: alias_name.to_owned(),
        }
    }
}

pub(crate) struct KmsStore {
    persistence: KmsPersistence,
    keys: DashMap<StoreKey, KeyRecord>,
    defaults: DashMap<DefaultKey, String>,
    aliases: DashMap<AliasKey, AliasRecord>,
}

impl KmsStore {
    pub(crate) fn new(db: Arc<StateDb>) -> Result<Self, KmsError> {
        let persistence = KmsPersistence::new(db)?;
        let store = Self {
            persistence,
            keys: DashMap::new(),
            defaults: DashMap::new(),
            aliases: DashMap::new(),
        };
        for (scope, record) in store.persistence.load_keys()? {
            store
                .keys
                .insert(StoreKey::new(&scope, &record.key_id), record);
        }
        for (scope, alias) in store.persistence.load_aliases()? {
            if !store
                .keys
                .contains_key(&StoreKey::new(&scope, &alias.target_key_id))
            {
                return Err(KmsError::Internal);
            }
            store
                .aliases
                .insert(AliasKey::new(&scope, &alias.alias_name), alias);
        }
        for (scope, service, key_id) in store.persistence.load_defaults()? {
            if !store.keys.contains_key(&StoreKey::new(&scope, &key_id))
                || store
                    .alias_target(&scope, &format!("alias/aws/{service}"))
                    .as_deref()
                    != Some(&key_id)
            {
                return Err(KmsError::Internal);
            }
            store
                .defaults
                .insert(DefaultKey::new(&scope, &service), key_id);
        }
        Ok(store)
    }

    pub(crate) fn insert(&self, scope: &Scope, record: KeyRecord) -> Result<bool, KmsError> {
        let key = StoreKey::new(scope, &record.key_id);
        match self.keys.entry(key) {
            Entry::Vacant(entry) => {
                self.persistence.save_key(scope, &record)?;
                entry.insert(record);
                Ok(true)
            }
            Entry::Occupied(_) => Ok(false),
        }
    }

    pub(crate) fn service_default_key(
        &self,
        scope: &Scope,
        service: &str,
        create: impl FnOnce() -> Result<KeyRecord, KmsError>,
    ) -> Result<String, KmsError> {
        match self.defaults.entry(DefaultKey::new(scope, service)) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let record = create()?;
                let key_id = record.key_id.clone();
                let alias = AliasRecord {
                    alias_name: format!("alias/aws/{service}"),
                    target_key_id: key_id.clone(),
                    creation_date: record.creation_date,
                    last_updated_date: record.creation_date,
                };
                self.persistence
                    .save_default(scope, service, &record, &alias)?;
                self.keys.insert(StoreKey::new(scope, &key_id), record);
                self.aliases
                    .insert(AliasKey::new(scope, &alias.alias_name), alias);
                entry.insert(key_id.clone());
                Ok(key_id)
            }
        }
    }

    pub(crate) fn with_key<R>(
        &self,
        scope: &Scope,
        key_id: &str,
        operation: impl FnOnce(&KeyRecord) -> R,
    ) -> Option<R> {
        let key = self.keys.get(&StoreKey::new(scope, key_id))?;
        Some(operation(&key))
    }

    pub(crate) fn with_key_mut<R>(
        &self,
        scope: &Scope,
        key_id: &str,
        operation: impl FnOnce(&mut KeyRecord) -> Result<R, KmsError>,
    ) -> Result<Option<R>, KmsError> {
        let Some(mut key) = self.keys.get_mut(&StoreKey::new(scope, key_id)) else {
            return Ok(None);
        };
        let mut staged = key.clone();
        let value = operation(&mut staged)?;
        self.persistence.save_key(scope, &staged)?;
        *key = staged;
        Ok(Some(value))
    }

    pub(crate) fn list(&self, scope: &Scope) -> Vec<KeyListEntry> {
        let mut keys: Vec<KeyListEntry> = self
            .keys
            .iter()
            .filter(|entry| entry.key().scope == *scope)
            .map(|entry| KeyListEntry {
                key_id: entry.value().key_id.clone(),
                key_arn: scope.key_arn(&entry.value().key_id),
            })
            .collect();
        keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        keys
    }

    pub(crate) fn insert_alias(
        &self,
        scope: &Scope,
        record: AliasRecord,
    ) -> Result<bool, KmsError> {
        match self.aliases.entry(AliasKey::new(scope, &record.alias_name)) {
            Entry::Vacant(entry) => {
                self.persistence.save_alias(scope, &record)?;
                entry.insert(record);
                Ok(true)
            }
            Entry::Occupied(_) => Ok(false),
        }
    }

    pub(crate) fn alias_target(&self, scope: &Scope, alias_name: &str) -> Option<String> {
        self.aliases
            .get(&AliasKey::new(scope, alias_name))
            .map(|record| record.target_key_id.clone())
    }

    pub(crate) fn update_alias(
        &self,
        scope: &Scope,
        alias_name: &str,
        target_key_id: String,
        last_updated_date: f64,
    ) -> Result<bool, KmsError> {
        let Some(mut record) = self.aliases.get_mut(&AliasKey::new(scope, alias_name)) else {
            return Ok(false);
        };
        let mut staged = record.clone();
        staged.target_key_id = target_key_id;
        staged.last_updated_date = last_updated_date;
        self.persistence.save_alias(scope, &staged)?;
        *record = staged;
        Ok(true)
    }

    pub(crate) fn remove_alias(&self, scope: &Scope, alias_name: &str) -> Result<bool, KmsError> {
        let key = AliasKey::new(scope, alias_name);
        match self.aliases.entry(key) {
            Entry::Occupied(entry) => {
                self.persistence.delete_alias(scope, alias_name)?;
                entry.remove();
                Ok(true)
            }
            Entry::Vacant(_) => Ok(false),
        }
    }

    pub(crate) fn list_aliases(&self, scope: &Scope) -> Vec<AliasRecord> {
        let mut aliases: Vec<AliasRecord> = self
            .aliases
            .iter()
            .filter(|entry| entry.key().scope == *scope)
            .map(|entry| entry.value().clone())
            .collect();
        aliases.sort_by(|left, right| left.alias_name.cmp(&right.alias_name));
        aliases
    }
}
