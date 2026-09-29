use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use localcloud_state::StateDb;
use rusqlite::params;
use uuid::Uuid;

use crate::error::SecretsError;
use crate::model::{Scope, SecretRecord};

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

#[derive(Clone, Eq, Hash, PartialEq)]
struct PageBinding {
    scope: Scope,
    operation: String,
    query: String,
    max_results: usize,
}

struct FrozenPage {
    binding: PageBinding,
    ids: Vec<String>,
    next_token: Option<String>,
}

pub(crate) struct PageResult {
    pub(crate) ids: Vec<String>,
    pub(crate) next_token: Option<String>,
}

pub(crate) struct SecretStore {
    secrets: DashMap<StoreKey, Arc<Mutex<Option<SecretRecord>>>>,
    pages: DashMap<String, FrozenPage>,
    state: Option<Arc<StateDb>>,
    save_lock: Mutex<()>,
}

impl SecretStore {
    pub(crate) fn new() -> Self {
        Self {
            secrets: DashMap::new(),
            pages: DashMap::new(),
            state: None,
            save_lock: Mutex::new(()),
        }
    }

    pub(crate) fn with_state(state: Arc<StateDb>) -> Result<Self, SecretsError> {
        let store = Self {
            state: Some(state),
            ..Self::new()
        };
        store.reload()?;
        Ok(store)
    }

    pub(crate) fn save(&self) -> Result<(), SecretsError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        // ponytail: full secrets snapshot per write; use per-record upserts if write volume grows.
        let _serial = self.save_lock.lock().map_err(|_| SecretsError::Internal)?;
        let mut records = Vec::new();
        for entry in self.secrets.iter() {
            if let Some(record) = entry
                .value()
                .lock()
                .map_err(|_| SecretsError::Internal)?
                .as_ref()
            {
                let json = serde_json::to_vec(record).map_err(|_| SecretsError::Internal)?;
                records.push((
                    entry.key().scope.account_id.clone(),
                    entry.key().scope.region.clone(),
                    entry.key().name.clone(),
                    json,
                ));
            }
        }
        let mut db = state.connection().map_err(|_| SecretsError::Internal)?;
        let tx = db.transaction().map_err(|_| SecretsError::Internal)?;
        tx.execute("DELETE FROM sm_secrets", [])
            .map_err(|_| SecretsError::Internal)?;
        {
            let mut insert = tx
                .prepare(
                    "INSERT INTO sm_secrets(account_id,region,name,record) VALUES (?1,?2,?3,?4)",
                )
                .map_err(|_| SecretsError::Internal)?;
            for (account, region, name, json) in records {
                insert
                    .execute(params![account, region, name, json])
                    .map_err(|_| SecretsError::Internal)?;
            }
        }
        tx.commit().map_err(|_| SecretsError::Internal)
    }

    pub(crate) fn reload(&self) -> Result<(), SecretsError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        let db = state.connection().map_err(|_| SecretsError::Internal)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS sm_secrets (account_id TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY(account_id,region,name))").map_err(|_| SecretsError::Internal)?;
        let mut query = db
            .prepare("SELECT account_id,region,name,record FROM sm_secrets")
            .map_err(|_| SecretsError::Internal)?;
        let records = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|_| SecretsError::Internal)?;
        let mut loaded = Vec::new();
        for row in records {
            let (account, region, name, json) = row.map_err(|_| SecretsError::Internal)?;
            let mut record: SecretRecord =
                serde_json::from_slice(&json).map_err(|_| SecretsError::Internal)?;
            if let Some(rotation) = record.rotation.as_mut() {
                if let Some(occurrence) = rotation.occurrence.as_mut() {
                    occurrence.in_flight = false;
                }
            }
            if record.name != name
                || !record
                    .arn
                    .starts_with(&Scope::new(&account, &region).arn_prefix())
            {
                return Err(SecretsError::Internal);
            }
            loaded.push((
                StoreKey::new(&Scope::new(&account, &region), &name),
                Arc::new(Mutex::new(Some(record))),
            ));
        }
        self.secrets.clear();
        for (key, record) in loaded {
            self.secrets.insert(key, record);
        }
        self.pages.clear();
        Ok(())
    }

    pub(crate) fn slot_for_name(
        &self,
        scope: &Scope,
        name: &str,
    ) -> Arc<Mutex<Option<SecretRecord>>> {
        self.secrets
            .entry(StoreKey::new(scope, name))
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone()
    }

    pub(crate) fn resolve(
        &self,
        scope: &Scope,
        secret_id: &str,
    ) -> Result<Arc<Mutex<Option<SecretRecord>>>, SecretsError> {
        if secret_id.starts_with("arn:") {
            let parts: Vec<&str> = secret_id.splitn(7, ':').collect();
            if parts.len() != 7
                || parts[0] != "arn"
                || parts[1] != "aws"
                || parts[2] != "secretsmanager"
                || parts[5] != "secret"
                || parts[6].is_empty()
            {
                return Err(SecretsError::InvalidParameter);
            }
            if !secret_id.starts_with(&scope.arn_prefix()) {
                return Err(SecretsError::ResourceNotFound);
            }
            for entry in self.secrets.iter() {
                if entry.key().scope != *scope {
                    continue;
                }
                let slot = entry.value().clone();
                let matches = slot
                    .lock()
                    .map_err(|_| SecretsError::Internal)?
                    .as_ref()
                    .is_some_and(|record| record.arn == secret_id);
                if matches {
                    return Ok(slot);
                }
            }
            return Err(SecretsError::ResourceNotFound);
        }
        if secret_id.is_empty() || secret_id.contains(':') {
            return Err(SecretsError::InvalidParameter);
        }
        let slot = self.slot_for_name(scope, secret_id);
        let exists = slot.lock().map_err(|_| SecretsError::Internal)?.is_some();
        if exists {
            Ok(slot)
        } else {
            Err(SecretsError::ResourceNotFound)
        }
    }

    pub(crate) fn list_names(&self, scope: &Scope, include_deleted: bool) -> Vec<String> {
        let mut names = Vec::new();
        for entry in self.secrets.iter() {
            if entry.key().scope != *scope {
                continue;
            }
            if let Ok(record) = entry.value().lock() {
                if record
                    .as_ref()
                    .is_some_and(|record| include_deleted || record.deleted_date.is_none())
                {
                    names.push(entry.key().name.clone());
                }
            }
        }
        names.sort();
        names
    }

    pub(crate) fn paginate(
        &self,
        scope: &Scope,
        operation: &str,
        query: String,
        ids: Vec<String>,
        max_results: usize,
        next_token: Option<&str>,
    ) -> Result<PageResult, SecretsError> {
        let binding = PageBinding {
            scope: scope.clone(),
            operation: operation.to_owned(),
            query,
            max_results,
        };
        if let Some(token) = next_token {
            let page = self
                .pages
                .get(token)
                .ok_or(SecretsError::InvalidNextToken)?;
            if page.binding != binding {
                return Err(SecretsError::InvalidNextToken);
            }
            return Ok(PageResult {
                ids: page.ids.clone(),
                next_token: page.next_token.clone(),
            });
        }

        let split = ids.len().min(max_results);
        let first = ids[..split].to_vec();
        let remaining = &ids[split..];
        let mut next = None;
        let chunks: Vec<Vec<String>> = remaining
            .chunks(max_results)
            .map(|chunk| chunk.to_vec())
            .collect();
        for chunk in chunks.into_iter().rev() {
            let token = Uuid::new_v4().to_string();
            self.pages.insert(
                token.clone(),
                FrozenPage {
                    binding: binding.clone(),
                    ids: chunk,
                    next_token: next,
                },
            );
            next = Some(token);
        }
        Ok(PageResult {
            ids: first,
            next_token: next,
        })
    }

    pub(crate) fn records_for_names(
        &self,
        scope: &Scope,
        names: &[String],
    ) -> Result<Vec<BTreeMap<String, serde_json::Value>>, SecretsError> {
        let mut records = Vec::new();
        for name in names {
            let slot = self.slot_for_name(scope, name);
            let guard = slot.lock().map_err(|_| SecretsError::Internal)?;
            let Some(record) = guard.as_ref() else {
                continue;
            };
            let mut value = BTreeMap::new();
            value.insert("ARN".to_owned(), record.arn.clone().into());
            value.insert("Name".to_owned(), record.name.clone().into());
            value.insert("CreatedDate".to_owned(), record.created_date.into());
            value.insert(
                "LastChangedDate".to_owned(),
                record.last_changed_date.into(),
            );
            if let Some(description) = &record.description {
                value.insert("Description".to_owned(), description.clone().into());
            }
            if let Some(kms_key_id) = &record.kms_key_id {
                value.insert("KmsKeyId".to_owned(), kms_key_id.clone().into());
            }
            if let Some(deleted_date) = record.deleted_date {
                value.insert("DeletedDate".to_owned(), deleted_date.into());
            }
            let tags = record
                .tags
                .iter()
                .map(|(key, value)| serde_json::json!({"Key": key, "Value": value}))
                .collect();
            value.insert("Tags".to_owned(), serde_json::Value::Array(tags));
            records.push(value);
        }
        Ok(records)
    }
}
