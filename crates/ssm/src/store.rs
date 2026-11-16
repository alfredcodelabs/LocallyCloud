use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use locallycloud_state::StateDb;
use rusqlite::params;

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
    mutation: Mutex<()>,
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
            mutation: Mutex::new(()),
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

    fn persist(&self, key: &StoreKey, record: Option<&ParameterRecord>) -> Result<(), SsmError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        let mut db = state.connection().map_err(|_| SsmError::Persistence)?;
        let tx = db.transaction().map_err(|_| SsmError::Persistence)?;
        match record {
            Some(record) => {
                let json = serde_json::to_vec(record).map_err(|_| SsmError::Persistence)?;
                tx.execute("INSERT INTO ssm_parameters(account_id,region,name,record) VALUES (?1,?2,?3,?4) ON CONFLICT(account_id,region,name) DO UPDATE SET record=excluded.record",
                    params![key.scope.account_id, key.scope.region, key.name, json]).map_err(|_| SsmError::Persistence)?;
            }
            None => {
                tx.execute(
                    "DELETE FROM ssm_parameters WHERE account_id=?1 AND region=?2 AND name=?3",
                    params![key.scope.account_id, key.scope.region, key.name],
                )
                .map_err(|_| SsmError::Persistence)?;
            }
        }
        tx.commit().map_err(|_| SsmError::Persistence)
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
        let _serial = self.mutation.lock().map_err(|_| SsmError::Internal)?;
        let key = StoreKey::new(scope, &name);
        let existing = self.parameters.get(&key).map(|record| record.clone());
        let record = match existing {
            None => ParameterRecord {
                name,
                description,
                value,
                version: 1,
                last_modified_date: now,
                tags: initial_tags.unwrap_or_default(),
            },
            Some(mut record) => {
                if !overwrite {
                    return Err(SsmError::ParameterAlreadyExists);
                }
                if initial_tags.is_some() {
                    return Err(SsmError::Validation);
                }
                record.version = record.version.checked_add(1).ok_or(SsmError::Internal)?;
                record.value = value;
                record.description = description;
                record.last_modified_date = now;
                record
            }
        };
        let version = record.version;
        self.persist(&key, Some(&record))?;
        self.parameters.insert(key, record);
        Ok(version)
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
        let _serial = self.mutation.lock().map_err(|_| SsmError::Internal)?;
        let key = StoreKey::new(scope, name);
        if !self.parameters.contains_key(&key) {
            return Err(SsmError::ParameterNotFound);
        }
        self.persist(&key, None)?;
        self.parameters.remove(&key);
        Ok(())
    }

    pub(crate) fn add_tags(
        &self,
        scope: &Scope,
        name: &str,
        additions: BTreeMap<String, String>,
    ) -> Result<(), SsmError> {
        let _serial = self.mutation.lock().map_err(|_| SsmError::Internal)?;
        let mut candidate = self
            .parameters
            .get(&StoreKey::new(scope, name))
            .ok_or(SsmError::InvalidResourceId)?
            .clone();
        let mut replacement = candidate.tags.clone();
        replacement.extend(additions);
        if replacement.len() > 50 {
            return Err(SsmError::Validation);
        }
        candidate.tags = replacement;
        self.persist(&StoreKey::new(scope, name), Some(&candidate))?;
        self.parameters
            .insert(StoreKey::new(scope, name), candidate);
        Ok(())
    }

    pub(crate) fn remove_tags(
        &self,
        scope: &Scope,
        name: &str,
        keys: &[String],
    ) -> Result<(), SsmError> {
        let _serial = self.mutation.lock().map_err(|_| SsmError::Internal)?;
        let mut candidate = self
            .parameters
            .get(&StoreKey::new(scope, name))
            .ok_or(SsmError::InvalidResourceId)?
            .clone();
        for key in keys {
            candidate.tags.remove(key);
        }
        self.persist(&StoreKey::new(scope, name), Some(&candidate))?;
        self.parameters
            .insert(StoreKey::new(scope, name), candidate);
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

    #[tokio::test]
    async fn sqlite_wait_does_not_block_reads_of_committed_parameters() {
        let path = std::env::temp_dir()
            .join(format!("ssm-read-{}", uuid::Uuid::new_v4()))
            .join("state.sqlite3");
        let state = Arc::new(StateDb::open(path).unwrap());
        let store = Arc::new(ParameterStore::with_state(state.clone()).unwrap());
        let scope = Scope::new("000000000000", "us-east-1");
        store
            .put(
                &scope,
                "/config".into(),
                ParameterValue::Plain(crate::model::SecretString::new("old".into())),
                None,
                false,
                None,
                1.0,
            )
            .unwrap();
        let blocker = state.connection().unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let writing = store.clone();
        let writing_scope = scope.clone();
        let writer = tokio::task::spawn_blocking(move || {
            writing.put(
                &writing_scope,
                "/config".into(),
                ParameterValue::Plain(crate::model::SecretString::new("new".into())),
                None,
                true,
                None,
                2.0,
            )
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while store.mutation.try_lock().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let reading = store.clone();
        let reading_scope = scope.clone();
        let reader = tokio::task::spawn_blocking(move || reading.get(&reading_scope, "/config"));
        let snapshot = tokio::time::timeout(std::time::Duration::from_secs(2), reader)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.version, 1);
        blocker.execute_batch("ROLLBACK").unwrap();
        assert_eq!(writer.await.unwrap().unwrap(), 2);
        assert_eq!(store.get(&scope, "/config").unwrap().version, 2);
    }

    #[test]
    fn writes_touch_one_entity_and_failed_commits_do_not_publish() {
        let path = std::env::temp_dir()
            .join(format!("ssm-delta-{}", uuid::Uuid::new_v4()))
            .join("state.sqlite3");
        let state = Arc::new(StateDb::open(path).unwrap());
        let store = ParameterStore::with_state(state.clone()).unwrap();
        let scope = Scope::new("000000000000", "us-east-1");
        let foreign = Scope::new("111111111111", "us-east-1");
        let put = |scope: &Scope, value: &str| {
            store.put(
                scope,
                "/config".into(),
                ParameterValue::Plain(crate::model::SecretString::new(value.into())),
                None,
                true,
                None,
                1.0,
            )
        };
        put(&scope, "first").unwrap();
        put(&foreign, "unrelated").unwrap();
        state.connection().unwrap().execute_batch("CREATE TRIGGER protect_other_update BEFORE UPDATE ON ssm_parameters WHEN OLD.account_id='111111111111' BEGIN SELECT RAISE(ABORT,'unrelated update'); END;
            CREATE TRIGGER protect_other_delete BEFORE DELETE ON ssm_parameters WHEN OLD.account_id='111111111111' BEGIN SELECT RAISE(ABORT,'unrelated delete'); END;").unwrap();
        assert_eq!(put(&scope, "second").unwrap(), 2);
        store
            .add_tags(
                &scope,
                "/config",
                BTreeMap::from([("team".into(), "data".into())]),
            )
            .unwrap();
        state.connection().unwrap().execute_batch("CREATE TRIGGER fail_write BEFORE UPDATE ON ssm_parameters WHEN OLD.account_id='000000000000' BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
        assert!(put(&scope, "failed").is_err());
        assert!(store
            .remove_tags(&scope, "/config", &["team".into()])
            .is_err());
        assert_eq!(store.get(&scope, "/config").unwrap().version, 2);
        assert_eq!(store.list_tags(&scope, "/config").unwrap().len(), 1);
        state
            .connection()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_write;")
            .unwrap();
        store.delete(&scope, "/config").unwrap();
        drop(store);
        let restored = ParameterStore::with_state(state).unwrap();
        assert!(matches!(
            restored.get(&scope, "/config"),
            Err(SsmError::ParameterNotFound)
        ));
        assert_eq!(restored.get(&foreign, "/config").unwrap().version, 1);
    }

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
