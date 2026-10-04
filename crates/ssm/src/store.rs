use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use locallycloud_state::StateDb;
use rusqlite::params;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

use crate::error::SsmError;
use crate::model::{
    ParameterMetadataSnapshot, ParameterRecord, ParameterSnapshot, ParameterValue,
    ParameterValueSnapshot, Scope,
};

#[derive(Eq, Hash, PartialEq)]
struct StoreKey {
    scope: Scope,
    name: String,
}

impl StoreKey {
    fn new(scope: &Scope, name: &str) -> Self {
        Self {
            scope: scope.clone(),
            name: name.to_owned(),
        }
    }
}

pub(crate) struct ParameterStore {
    parameters: DashMap<StoreKey, ParameterRecord>,
    state: Option<Arc<StateDb>>,
    save_lock: Mutex<()>,
}

impl ParameterStore {
    pub(crate) fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        Ok(self
            .parameters
            .iter()
            .filter(|e| e.key().scope.account_id == account)
            .map(|e| e.key().scope.region.clone())
            .collect())
    }

    pub(crate) fn new() -> Self {
        Self {
            parameters: DashMap::new(),
            state: None,
            save_lock: Mutex::new(()),
        }
    }

    pub(crate) fn with_state(state: Arc<StateDb>) -> Result<Self, SsmError> {
        let store = Self {
            state: Some(state),
            ..Self::new()
        };
        store.load()?;
        Ok(store)
    }

    pub(crate) fn save(&self) -> Result<(), SsmError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        // ponytail: full parameters snapshot per write; use per-record upserts if write volume grows.
        let _serial = self.save_lock.lock().map_err(|_| SsmError::Internal)?;
        let mut records = Vec::new();
        for entry in self.parameters.iter() {
            let json = serde_json::to_vec(entry.value()).map_err(|_| SsmError::Internal)?;
            records.push((
                entry.key().scope.account_id.clone(),
                entry.key().scope.region.clone(),
                entry.key().name.clone(),
                json,
            ));
        }
        let mut db = state.connection().map_err(|_| SsmError::Internal)?;
        let tx = db.transaction().map_err(|_| SsmError::Internal)?;
        tx.execute("DELETE FROM ssm_parameters", [])
            .map_err(|_| SsmError::Internal)?;
        {
            let mut insert = tx.prepare("INSERT INTO ssm_parameters(account_id,region,name,record) VALUES (?1,?2,?3,?4)").map_err(|_| SsmError::Internal)?;
            for (account, region, name, json) in records {
                insert
                    .execute(params![account, region, name, json])
                    .map_err(|_| SsmError::Internal)?;
            }
        }
        tx.commit().map_err(|_| SsmError::Internal)
    }

    fn load(&self) -> Result<(), SsmError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        let db = state.connection().map_err(|_| SsmError::Internal)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS ssm_parameters (account_id TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY(account_id,region,name))").map_err(|_| SsmError::Internal)?;
        let mut query = db
            .prepare("SELECT account_id,region,name,record FROM ssm_parameters")
            .map_err(|_| SsmError::Internal)?;
        let rows = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|_| SsmError::Internal)?;
        for row in rows {
            let (account, region, name, json) = row.map_err(|_| SsmError::Internal)?;
            let record: ParameterRecord =
                serde_json::from_slice(&json).map_err(|_| SsmError::Internal)?;
            if record.name != name {
                return Err(SsmError::Internal);
            }
            self.parameters
                .insert(StoreKey::new(&Scope::new(&account, &region), &name), record);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn put(
        &self,
        scope: &Scope,
        name: String,
        value: ParameterValue,
        description: Option<String>,
        overwrite: bool,
        initial_tags: Option<BTreeMap<String, String>>,
        now: f64,
    ) -> Result<u64, SsmError> {
        let key = StoreKey::new(scope, &name);
        match self.parameters.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(ParameterRecord {
                    name,
                    description,
                    value,
                    version: 1,
                    last_modified_date: now,
                    tags: initial_tags.unwrap_or_default(),
                });
                Ok(1)
            }
            Entry::Occupied(mut entry) => {
                if !overwrite {
                    return Err(SsmError::ParameterAlreadyExists);
                }
                if initial_tags.is_some() {
                    return Err(SsmError::Validation);
                }
                let next_version = entry
                    .get()
                    .version
                    .checked_add(1)
                    .ok_or(SsmError::Internal)?;
                let record = entry.get_mut();
                record.value = value;
                record.description = description;
                record.version = next_version;
                record.last_modified_date = now;
                Ok(next_version)
            }
        }
    }

    pub(crate) fn get(&self, scope: &Scope, name: &str) -> Result<ParameterSnapshot, SsmError> {
        let record = self
            .parameters
            .get(&StoreKey::new(scope, name))
            .ok_or(SsmError::ParameterNotFound)?;
        Ok(ParameterSnapshot {
            name: record.name.clone(),
            value: match &record.value {
                ParameterValue::Plain(value) => {
                    ParameterValueSnapshot::Plain(value.expose().to_owned())
                }
                ParameterValue::Encrypted {
                    ciphertext,
                    key_arn,
                    ..
                } => ParameterValueSnapshot::Encrypted {
                    ciphertext: ciphertext.clone(),
                    key_arn: key_arn.clone(),
                },
            },
            version: record.version,
            last_modified_date: record.last_modified_date,
        })
    }

    pub(crate) fn describe(
        &self,
        scope: &Scope,
        exact_name: Option<&str>,
    ) -> Vec<ParameterMetadataSnapshot> {
        let mut parameters: Vec<_> = self
            .parameters
            .iter()
            .filter(|entry| {
                entry.key().scope == *scope
                    && exact_name.is_none_or(|name| entry.key().name == name)
            })
            .map(|entry| ParameterMetadataSnapshot {
                name: entry.name.clone(),
                description: entry.description.clone(),
                parameter_type: entry.value.parameter_type(),
                key_id: entry.value.key_id().map(str::to_owned),
                version: entry.version,
                last_modified_date: entry.last_modified_date,
            })
            .collect();
        parameters.sort_by(|left, right| left.name.cmp(&right.name));
        parameters
    }

    pub(crate) fn delete(&self, scope: &Scope, name: &str) -> Result<(), SsmError> {
        self.parameters
            .remove(&StoreKey::new(scope, name))
            .map(|_| ())
            .ok_or(SsmError::ParameterNotFound)
    }

    pub(crate) fn add_tags(
        &self,
        scope: &Scope,
        name: &str,
        additions: BTreeMap<String, String>,
    ) -> Result<(), SsmError> {
        let mut record = self
            .parameters
            .get_mut(&StoreKey::new(scope, name))
            .ok_or(SsmError::InvalidResourceId)?;
        let mut replacement = record.tags.clone();
        replacement.extend(additions);
        if replacement.len() > 50 {
            return Err(SsmError::Validation);
        }
        record.tags = replacement;
        Ok(())
    }

    pub(crate) fn remove_tags(
        &self,
        scope: &Scope,
        name: &str,
        keys: &[String],
    ) -> Result<(), SsmError> {
        let mut record = self
            .parameters
            .get_mut(&StoreKey::new(scope, name))
            .ok_or(SsmError::InvalidResourceId)?;
        for key in keys {
            record.tags.remove(key);
        }
        Ok(())
    }

    pub(crate) fn list_tags(
        &self,
        scope: &Scope,
        name: &str,
    ) -> Result<Vec<(String, String)>, SsmError> {
        let record = self
            .parameters
            .get(&StoreKey::new(scope, name))
            .ok_or(SsmError::InvalidResourceId)?;
        Ok(record
            .tags
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_string_ciphertext_survives_restart() {
        let path = std::env::temp_dir()
            .join(format!("locallycloud-ssm-{}", uuid::Uuid::new_v4()))
            .join("state.sqlite3");
        let state = Arc::new(StateDb::open(path).unwrap());
        let scope = Scope::new("000000000000", "us-east-1");
        let store = ParameterStore::with_state(state.clone()).unwrap();
        store
            .put(
                &scope,
                "/etl/password".into(),
                ParameterValue::Encrypted {
                    ciphertext: vec![0x81, 0x82, 0x83],
                    key_arn: "arn:aws:kms:us-east-1:000000000000:key/test".into(),
                    key_id: "alias/aws/ssm".into(),
                },
                None,
                false,
                None,
                1.0,
            )
            .unwrap();
        store.save().unwrap();
        drop(store);
        let restarted = ParameterStore::with_state(state).unwrap();
        match restarted.get(&scope, "/etl/password").unwrap().value {
            ParameterValueSnapshot::Encrypted {
                ciphertext,
                key_arn,
            } => {
                assert_eq!(ciphertext, vec![0x81, 0x82, 0x83]);
                assert_eq!(key_arn, "arn:aws:kms:us-east-1:000000000000:key/test");
            }
            ParameterValueSnapshot::Plain(_) => panic!("SecureString lost its ciphertext"),
        }
    }
}
