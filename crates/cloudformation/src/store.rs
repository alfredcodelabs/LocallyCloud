//! Scoped ownership metadata, with optional incremental encrypted persistence.

use std::sync::{Arc, Mutex};

use crate::error::CfnError;
use crate::persistence::{now, Persistence, RETENTION_SECONDS};
use locallycloud_state::{StateCipher, StateDb};

use dashmap::DashMap;

use crate::model::Stack;
use crate::proto::Query;

/// Concurrent store of stacks keyed by `"{account}:{region}:{stack_name}"`.
pub struct CfnStore {
    stacks: DashMap<String, Stack>,
    change_sets: DashMap<String, ChangeSet>,
    deleted: DashMap<String, (i64, Stack)>,
    persistence: Option<Persistence>,
    mutation: Mutex<()>,
    operations: Mutex<std::collections::BTreeSet<String>>,
    operation_limit: Arc<tokio::sync::Semaphore>,
}

impl Default for CfnStore {
    fn default() -> Self {
        Self {
            stacks: DashMap::new(),
            change_sets: DashMap::new(),
            deleted: DashMap::new(),
            persistence: None,
            mutation: Mutex::new(()),
            operations: Mutex::new(Default::default()),
            operation_limit: Arc::new(tokio::sync::Semaphore::new(4)),
        }
    }
}

pub(crate) struct OperationGuard {
    store: Arc<CfnStore>,
    key: String,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl Drop for OperationGuard {
    fn drop(&mut self) {
        if let Ok(mut operations) = self.store.operations.lock() {
            operations.remove(&self.key);
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ChangeSetChange {
    pub logical_id: String,
    pub resource_type: String,
    pub action: String,
    pub physical_id: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
    pub(crate) fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        Ok(self
            .stacks
            .iter()
            .filter(|e| e.value().status != crate::model::StackStatus::DeleteComplete)
            .filter_map(|e| {
                let (owner, tail) = e.key().split_once(':')?;
                let (region, _) = tail.split_once(':')?;
                (owner == account).then(|| region.to_owned())
            })
            .collect())
    }

    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn with_state(db: &StateDb) -> Result<Arc<Self>, CfnError> {
        let cipher = StateCipher::from_env().map_err(|_| CfnError::Internal)?;
        Self::with_cipher(db, cipher)
    }

    pub(crate) fn with_cipher(db: &StateDb, cipher: StateCipher) -> Result<Arc<Self>, CfnError> {
        let persistence = Persistence::new(db, cipher)?;
        let store = Self {
            persistence: Some(persistence),
            ..Self::default()
        };
        store
            .persistence
            .as_ref()
            .unwrap()
            .load(|kind, key, deleted_at, plaintext| {
                match kind {
                    "stack" => {
                        store.stacks.insert(
                            key,
                            serde_json::from_slice(plaintext).map_err(|_| CfnError::Internal)?,
                        );
                    }
                    "change" => {
                        store.change_sets.insert(
                            key,
                            serde_json::from_slice(plaintext).map_err(|_| CfnError::Internal)?,
                        );
                    }
                    "deleted" => {
                        let record: (i64, Stack) =
                            serde_json::from_slice(plaintext).map_err(|_| CfnError::Internal)?;
                        if Some(record.0) != deleted_at {
                            return Err(CfnError::Internal);
                        }
                        store.deleted.insert(key, record);
                    }
                    _ => return Err(CfnError::Internal),
                }
                Ok(())
            })?;
        let interrupted = store
            .stacks
            .iter()
            .filter(|entry| {
                matches!(
                    entry.status,
                    crate::model::StackStatus::CreateInProgress
                        | crate::model::StackStatus::UpdateInProgress
                        | crate::model::StackStatus::DeleteInProgress
                )
            })
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect::<Vec<_>>();
        for (key, mut stack) in interrupted {
            stack.status = match stack.status {
                crate::model::StackStatus::CreateInProgress => {
                    crate::model::StackStatus::CreateFailed
                }
                crate::model::StackStatus::UpdateInProgress => {
                    crate::model::StackStatus::UpdateFailed
                }
                _ => crate::model::StackStatus::DeleteFailed,
            };
            stack.events.push(crate::model::StackEvent { event_id: uuid::Uuid::new_v4().to_string(), logical_id: stack.stack_name.clone(), resource_type: "AWS::CloudFormation::Stack".into(), status: stack.status.as_str().into(), reason: Some("LocallyCloud stopped during this operation; only recorded resource ownership is available".into()), timestamp: time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).map_err(|_| CfnError::Internal)? });
            store
                .persistence
                .as_ref()
                .unwrap()
                .put("stack", &key, &stack)?;
            store.stacks.insert(key, stack);
        }
        store.expire_deleted();
        Ok(Arc::new(store))
    }

    pub(crate) fn operation(
        self: &Arc<Self>,
        account: &str,
        region: &str,
        name: &str,
    ) -> Result<OperationGuard, CfnError> {
        let key = Self::key(account, region, name);
        let mut operations = self.operations.lock().map_err(|_| CfnError::Internal)?;
        if operations.contains(&key) {
            return Err(CfnError::Validation(format!(
                "Stack [{name}] has an operation in progress"
            )));
        }
        let permit = self
            .operation_limit
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                CfnError::LimitExceeded("The concurrent stack operation limit was exceeded".into())
            })?;
        operations.insert(key.clone());
        Ok(OperationGuard {
            store: self.clone(),
            key,
            _permit: permit,
        })
    }

    pub(crate) fn admit(
        &self,
        account: &str,
        region: &str,
        stack: Stack,
        change: Option<&ChangeSet>,
    ) -> Result<(), CfnError> {
        let _guard = self.mutation.lock().map_err(|_| CfnError::Internal)?;
        let stack_key = Self::key(account, region, &stack.stack_name);
        let claim = if let Some(change) = change {
            let key = Self::key(
                account,
                region,
                &format!("{}:{}", change.stack_name, change.name),
            );
            let mut current = self
                .change_sets
                .get(&key)
                .map(|entry| entry.clone())
                .ok_or_else(|| CfnError::Validation("ChangeSet does not exist".into()))?;
            if current.id != change.id || current.executed || current.status != "CREATE_COMPLETE" {
                return Err(CfnError::Validation(format!(
                    "ChangeSet [{}] is not executable",
                    change.name
                )));
            }
            current.executed = true;
            Some((key, current))
        } else {
            None
        };
        if let Some(persistence) = &self.persistence {
            persistence.admit(
                &stack_key,
                &stack,
                claim.as_ref().map(|(key, change)| (key.as_str(), change)),
            )?;
        }
        self.stacks.insert(stack_key, stack);
        if let Some((key, change)) = claim {
            self.change_sets.insert(key, change);
        }
        Ok(())
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
            .or_else(|| {
                self.expire_deleted();
                self.deleted
                    .get(&Self::key(account, region, name_or_id))
                    .map(|entry| entry.value().1.clone())
            })
    }

    pub fn put(&self, account: &str, region: &str, stack: Stack) -> Result<(), CfnError> {
        let _guard = self.mutation.lock().map_err(|_| CfnError::Internal)?;
        let key = Self::key(account, region, &stack.stack_name);
        if let Some(persistence) = &self.persistence {
            persistence.put("stack", &key, &stack)?;
        }
        self.stacks.insert(key, stack);
        Ok(())
    }

    fn expire_deleted(&self) {
        self.deleted
            .retain(|_, (deleted_at, _)| *deleted_at > now() - RETENTION_SECONDS);
    }

    pub fn archive(&self, account: &str, region: &str, stack: Stack) -> Result<(), CfnError> {
        let _guard = self.mutation.lock().map_err(|_| CfnError::Internal)?;
        let active_key = Self::key(account, region, &stack.stack_name);
        let archive_key = Self::key(account, region, &stack.stack_id);
        let prefix = format!("{account}:{region}:");
        let changes = self
            .change_sets
            .iter()
            .filter(|e| e.key().starts_with(&prefix) && e.stack_id == stack.stack_id)
            .map(|e| e.key().clone())
            .collect::<Vec<_>>();
        let deleted_at = now();
        if let Some(persistence) = &self.persistence {
            persistence.archive(&active_key, &archive_key, &stack, deleted_at, &changes)?;
        }
        self.stacks.remove(&active_key);
        for key in changes {
            self.change_sets.remove(&key);
        }
        self.expire_deleted();
        self.deleted.insert(archive_key, (deleted_at, stack));
        Ok(())
    }

    pub fn list_with_deleted(&self, account: &str, region: &str) -> Vec<Stack> {
        self.expire_deleted();
        let mut stacks = self.list(account, region);
        let prefix = format!("{account}:{region}:");
        stacks.extend(
            self.deleted
                .iter()
                .filter(|entry| entry.key().starts_with(&prefix))
                .map(|entry| entry.value().1.clone()),
        );
        stacks
    }

    pub fn list(&self, account: &str, region: &str) -> Vec<Stack> {
        let prefix = format!("{account}:{region}:");
        self.stacks
            .iter()
            .filter(|e| e.key().starts_with(&prefix))
            .map(|e| e.value().clone())
            .collect()
    }
    pub fn insert_change_set(
        &self,
        account: &str,
        region: &str,
        change: ChangeSet,
    ) -> Result<bool, CfnError> {
        let _guard = self.mutation.lock().map_err(|_| CfnError::Internal)?;
        let key = Self::key(
            account,
            region,
            &format!("{}:{}", change.stack_name, change.name),
        );
        if self.change_sets.contains_key(&key) {
            return Ok(false);
        }
        if let Some(persistence) = &self.persistence {
            persistence.put("change", &key, &change)?;
        }
        self.change_sets.insert(key, change);
        Ok(true)
    }

    pub fn claim_change_set(
        &self,
        account: &str,
        region: &str,
        change: &ChangeSet,
    ) -> Result<bool, CfnError> {
        let _guard = self.mutation.lock().map_err(|_| CfnError::Internal)?;
        let key = Self::key(
            account,
            region,
            &format!("{}:{}", change.stack_name, change.name),
        );
        let Some(mut next) = self.change_sets.get(&key).map(|entry| entry.clone()) else {
            return Ok(false);
        };
        if next.status != "CREATE_COMPLETE" || next.executed {
            return Ok(false);
        }
        next.executed = true;
        if let Some(persistence) = &self.persistence {
            persistence.put("change", &key, &next)?;
        }
        self.change_sets.insert(key, next);
        Ok(true)
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

    pub fn remove_change_set(
        &self,
        account: &str,
        region: &str,
        change: &ChangeSet,
    ) -> Result<(), CfnError> {
        let _guard = self.mutation.lock().map_err(|_| CfnError::Internal)?;
        let key = Self::key(
            account,
            region,
            &format!("{}:{}", change.stack_name, change.name),
        );
        if let Some(persistence) = &self.persistence {
            persistence.remove_change(&key)?;
        }
        self.change_sets.remove(&key);
        Ok(())
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
    fn durable_ownership_restart_isolation_claim_archive_and_failed_commit() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/cfn-durable-tests")
            .join(uuid::Uuid::new_v4().to_string());
        let db = StateDb::open(root.join("state.sqlite3")).unwrap();
        let reopen = || CfnStore::with_cipher(&db, StateCipher::with_key(&[31; 32])).unwrap();
        let store = reopen();
        let stack = Stack {
            stack_id: "arn:stack:original".into(),
            stack_name: "orders".into(),
            status: crate::model::StackStatus::CreateComplete,
            template_body: "private-template-NoEcho-token".into(),
            parameters: [("Password".into(), "secret-password".into())].into(),
            resources: vec![crate::model::StackResource {
                logical_id: "Queue".into(),
                physical_id: "queue-url".into(),
                resource_type: "AWS::SQS::Queue".into(),
                status: "CREATE_COMPLETE".into(),
                attributes: [("Arn".into(), "queue-arn".into())].into(),
                pending_cleanup: vec![crate::model::ReplacementCleanup {
                    physical_id: "old-resource".into(),
                    properties: serde_json::json!({"secret":"value"}),
                }],
            }],
            outputs: vec![crate::model::Output {
                key: "Queue".into(),
                value: "queue-url".into(),
                export_name: Some("OrdersQueue".into()),
            }],
            events: vec![crate::model::StackEvent {
                event_id: "event".into(),
                logical_id: "Queue".into(),
                resource_type: "AWS::SQS::Queue".into(),
                status: "CREATE_COMPLETE".into(),
                reason: None,
                timestamp: "2026-10-06T00:00:00Z".into(),
            }],
            tags: vec![("application".into(), "orders".into())],
            creation_time: "2026-10-06T00:00:00Z".into(),
            last_updated_time: None,
        };
        store.put("owner", "us-east-1", stack.clone()).unwrap();
        let mut other = stack.clone();
        other.stack_id = "arn:stack:other".into();
        store.put("owner", "us-west-2", other).unwrap();
        let sql = db.connection().unwrap();
        let ciphertext: Vec<u8> = sql
            .query_row(
                "SELECT payload FROM cfn_metadata_v1 WHERE scope_key='owner:us-west-2:orders'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let change = ChangeSet {
            id: "change-id".into(),
            name: "update".into(),
            stack_name: "orders".into(),
            stack_id: stack.stack_id.clone(),
            change_type: "UPDATE".into(),
            status: "CREATE_COMPLETE".into(),
            reason: None,
            executed: false,
            request: Query {
                params: [("TemplateBody".into(), "private-change-template".into())].into(),
            },
            changes: vec![ChangeSetChange {
                logical_id: "Queue".into(),
                resource_type: "AWS::SQS::Queue".into(),
                action: "Modify".into(),
                physical_id: Some("queue-url".into()),
            }],
        };
        store
            .insert_change_set("owner", "us-east-1", change.clone())
            .unwrap();
        assert!(store
            .claim_change_set("owner", "us-east-1", &change)
            .unwrap());
        let mut admission = change.clone();
        admission.id = "admission-id".into();
        admission.name = "admission".into();
        store
            .insert_change_set("owner", "us-east-1", admission.clone())
            .unwrap();
        let mut progress = stack.clone();
        progress.status = crate::model::StackStatus::UpdateInProgress;
        sql.execute_batch("CREATE TRIGGER cfn_reject_claim BEFORE UPDATE ON cfn_metadata_v1 WHEN NEW.kind='change' BEGIN SELECT RAISE(ABORT,'forced failure'); END;").unwrap();
        assert!(store
            .admit("owner", "us-east-1", progress.clone(), Some(&admission))
            .is_err());
        assert_eq!(
            store.get("owner", "us-east-1", "orders").unwrap().status,
            crate::model::StackStatus::CreateComplete
        );
        assert!(
            !store
                .find_change_set("owner", "us-east-1", "orders", "admission")
                .unwrap()
                .executed
        );
        let restored = reopen();
        assert_eq!(
            restored.get("owner", "us-east-1", "orders").unwrap().status,
            crate::model::StackStatus::CreateComplete
        );
        assert!(
            !restored
                .find_change_set("owner", "us-east-1", "orders", "admission")
                .unwrap()
                .executed
        );
        drop(restored);
        sql.execute_batch("DROP TRIGGER cfn_reject_claim;").unwrap();
        store
            .admit("owner", "us-east-1", progress, Some(&admission))
            .unwrap();
        drop(store);
        let store = reopen();
        let interrupted = store.get("owner", "us-east-1", "orders").unwrap();
        assert_eq!(interrupted.status, crate::model::StackStatus::UpdateFailed);
        assert_eq!(interrupted.resources[0].physical_id, "queue-url");
        assert!(interrupted
            .events
            .last()
            .unwrap()
            .reason
            .as_ref()
            .unwrap()
            .contains("only recorded resource ownership"));
        assert!(
            store
                .find_change_set("owner", "us-east-1", "orders", "admission")
                .unwrap()
                .executed
        );
        store.put("owner", "us-east-1", stack.clone()).unwrap();
        drop(store);
        assert!(CfnStore::with_cipher(&db, StateCipher::with_key(&[32; 32])).is_err());
        let store = reopen();
        let restored = store.find("owner", "us-east-1", "orders").unwrap();
        assert_eq!(
            serde_json::to_value(&restored).unwrap(),
            serde_json::to_value(&stack).unwrap()
        );
        assert!(store.find("other", "us-east-1", "orders").is_none());
        assert!(store.find("owner", "eu-west-1", "orders").is_none());
        assert!(!store
            .claim_change_set("owner", "us-east-1", &change)
            .unwrap());
        assert_eq!(
            store
                .find_change_set("owner", "us-east-1", "orders", "change-id")
                .unwrap()
                .changes[0]
                .action,
            "Modify"
        );
        sql.execute_batch("CREATE TRIGGER cfn_reject_update BEFORE UPDATE ON cfn_metadata_v1 BEGIN SELECT RAISE(ABORT,'forced failure'); END;").unwrap();
        let mut updated = stack.clone();
        updated.template_body = "changed".into();
        assert_eq!(
            store.put("owner", "us-east-1", updated).unwrap_err(),
            CfnError::Internal
        );
        assert_eq!(
            store
                .get("owner", "us-east-1", "orders")
                .unwrap()
                .template_body,
            stack.template_body
        );
        sql.execute_batch("DROP TRIGGER cfn_reject_update; CREATE TRIGGER cfn_reject_archive BEFORE INSERT ON cfn_metadata_v1 WHEN NEW.kind='deleted' BEGIN SELECT RAISE(ABORT,'forced failure'); END;").unwrap();
        assert!(store.archive("owner", "us-east-1", stack.clone()).is_err());
        assert!(store.get("owner", "us-east-1", "orders").is_some());
        assert!(reopen().get("owner", "us-east-1", "orders").is_some());
        assert!(reopen()
            .find_change_set("owner", "us-east-1", "orders", "update")
            .is_some());
        sql.execute_batch("DROP TRIGGER cfn_reject_archive;")
            .unwrap();
        let mut deleted = stack.clone();
        deleted.status = crate::model::StackStatus::DeleteComplete;
        store
            .archive("owner", "us-east-1", deleted.clone())
            .unwrap();
        drop(store);
        let store = reopen();
        assert!(store.get("owner", "us-east-1", "orders").is_none());
        assert_eq!(
            store
                .find("owner", "us-east-1", &stack.stack_id)
                .unwrap()
                .status,
            crate::model::StackStatus::DeleteComplete
        );
        assert!(store
            .find_change_set("owner", "us-east-1", "orders", "update")
            .is_none());
        let unchanged: Vec<u8> = sql
            .query_row(
                "SELECT payload FROM cfn_metadata_v1 WHERE scope_key='owner:us-west-2:orders'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            ciphertext, unchanged,
            "unrelated rows must not be rewritten"
        );
        let all_payloads: Vec<Vec<u8>> = sql
            .prepare("SELECT payload FROM cfn_metadata_v1")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for payload in all_payloads {
            assert!(!payload.windows(15).any(|part| part == b"secret-password"));
        }
        // A real older archive has its authenticated timestamp preserved through restart.
        let expired_at = now() - RETENTION_SECONDS - 1;
        store
            .persistence
            .as_ref()
            .unwrap()
            .archive(
                "owner:us-east-1:orders",
                "owner:us-east-1:arn:stack:original",
                &deleted,
                expired_at,
                &[],
            )
            .unwrap();
        drop(store);
        assert!(reopen()
            .find("owner", "us-east-1", &stack.stack_id)
            .is_none());
        assert_eq!(
            sql.query_row(
                "SELECT COUNT(*) FROM cfn_metadata_v1 WHERE kind='deleted'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        drop(sql);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deleted_history_is_scoped_expires_and_does_not_occupy_the_name() {
        let store = CfnStore::new();
        let mut stack = Stack {
            stack_id: "arn:stack:old".into(),
            stack_name: "stack".into(),
            status: crate::model::StackStatus::DeleteComplete,
            template_body: "{\"Resources\":{}}".into(),
            parameters: Default::default(),
            resources: Vec::new(),
            outputs: Vec::new(),
            events: Vec::new(),
            tags: Vec::new(),
            creation_time: String::new(),
            last_updated_time: None,
        };
        store.archive("account", "region", stack.clone()).unwrap();
        assert!(store.find("account", "region", "stack").is_none());
        assert!(store.find("other", "region", "arn:stack:old").is_none());
        assert!(store.find("account", "other", "arn:stack:old").is_none());
        assert!(store.find("account", "region", "arn:stack:old").is_some());
        stack.stack_id = "arn:stack:new".into();
        stack.status = crate::model::StackStatus::CreateComplete;
        store.put("account", "region", stack).unwrap();
        assert_eq!(
            store.find("account", "region", "stack").unwrap().stack_id,
            "arn:stack:new"
        );
        assert_eq!(store.list_with_deleted("account", "region").len(), 2);
        store
            .deleted
            .get_mut(&CfnStore::key("account", "region", "arn:stack:old"))
            .unwrap()
            .0 = now() - 91 * 24 * 60 * 60;
        assert!(store.find("account", "region", "arn:stack:old").is_none());
        assert_eq!(store.list_with_deleted("account", "region").len(), 1);
    }

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
        assert!(store
            .insert_change_set("account", "region", change.clone())
            .unwrap());
        let workers = (0..8)
            .map(|_| {
                let store = store.clone();
                let change = change.clone();
                std::thread::spawn(move || {
                    store
                        .claim_change_set("account", "region", &change)
                        .unwrap()
                })
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
