//! Durable control-plane entities; runtime processes and network leases are never stored.
use crate::{
    error::LambdaError,
    model::{FunctionKey, FunctionStore, LayerKey, LayerStore},
};
use locallycloud_state::{StateCipher, StateDb};
use rusqlite::params;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use zeroize::Zeroizing;

pub(crate) struct LambdaPersistence {
    db: Arc<StateDb>,
    cipher: StateCipher,
}
pub(crate) fn state_error(_: impl std::fmt::Display) -> LambdaError {
    LambdaError::InternalError("Lambda state could not be committed or loaded; check the state database and original master key".into())
}
impl LambdaPersistence {
    pub fn new(db: Arc<StateDb>) -> Result<Self, LambdaError> {
        Self::with_cipher(db, StateCipher::from_env().map_err(state_error)?)
    }
    pub(crate) fn with_cipher(db: Arc<StateDb>, cipher: StateCipher) -> Result<Self, LambdaError> {
        db.connection().map_err(state_error)?.execute_batch("CREATE TABLE IF NOT EXISTS lambda_entities(account TEXT NOT NULL,region TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(account,region,kind,name));").map_err(state_error)?;
        Ok(Self { db, cipher })
    }
    pub fn restore(
        self: &Arc<Self>,
        store: &FunctionStore,
        layers: &LayerStore,
    ) -> Result<(), LambdaError> {
        let connection = self.db.connection().map_err(state_error)?;
        let mut query = connection
            .prepare("SELECT account,region,kind,name,payload FROM lambda_entities")
            .map_err(state_error)?;
        let rows = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })
            .map_err(state_error)?;
        let functions = FunctionStore::new();
        let staged_layers = LayerStore::new();
        for row in rows {
            let (account, region, kind, name, payload) = row.map_err(state_error)?;
            let plain = self
                .cipher
                .open(&["lambda", &account, &region, &kind, &name], &payload)
                .map_err(state_error)?;
            match kind.as_str() {
                "function" => {
                    functions.records.insert(
                        FunctionKey {
                            account_id: account,
                            region,
                            name,
                        },
                        decode(&plain)?,
                    );
                }
                "layer" => {
                    staged_layers.records.insert(
                        LayerKey {
                            account_id: account,
                            region,
                            name,
                        },
                        decode(&plain)?,
                    );
                }
                _ => return Err(state_error("unknown Lambda entity kind")),
            }
        }
        for entry in functions.records {
            store.records.insert(entry.0, entry.1);
        }
        for entry in staged_layers.records {
            layers.records.insert(entry.0, entry.1);
        }
        *store.persistence.lock().unwrap() = Some(self.clone());
        Ok(())
    }
    fn save<T: Serialize>(
        &self,
        account: &str,
        region: &str,
        kind: &str,
        name: &str,
        record: &T,
    ) -> Result<(), LambdaError> {
        let plain = Zeroizing::new(serde_json::to_vec(record).map_err(state_error)?);
        let payload = self
            .cipher
            .seal(&["lambda", account, region, kind, name], &plain)
            .map_err(state_error)?;
        self.db.connection().map_err(state_error)?.execute("INSERT INTO lambda_entities(account,region,kind,name,payload) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(account,region,kind,name) DO UPDATE SET payload=excluded.payload",params![account,region,kind,name,payload]).map_err(state_error)?;
        Ok(())
    }
    pub fn commit_function(
        &self,
        original: &FunctionStore,
        staged: &FunctionStore,
        account: &str,
        region: &str,
        name: &str,
    ) -> Result<(), LambdaError> {
        let key = FunctionKey {
            account_id: account.into(),
            region: region.into(),
            name: name.into(),
        };
        if let Some(record) = staged.records.get(&key) {
            self.save(account, region, "function", name, record.value())?;
            original.records.insert(key, record.clone());
        } else {
            return Err(state_error("staged function unexpectedly missing"));
        }
        Ok(())
    }
    pub fn commit_layer(
        &self,
        original: &LayerStore,
        staged: &LayerStore,
        account: &str,
        region: &str,
        name: &str,
    ) -> Result<(), LambdaError> {
        let key = LayerKey {
            account_id: account.into(),
            region: region.into(),
            name: name.into(),
        };
        if let Some(record) = staged.records.get(&key) {
            self.save(account, region, "layer", name, record.value())?;
            original.records.insert(key, record.clone());
        } else {
            return Err(state_error("staged layer unexpectedly missing"));
        }
        Ok(())
    }
    pub fn delete_function(
        &self,
        account: &str,
        region: &str,
        name: &str,
    ) -> Result<(), LambdaError> {
        self.db.connection().map_err(state_error)?.execute("DELETE FROM lambda_entities WHERE account=?1 AND region=?2 AND kind='function' AND name=?3",params![account,region,name]).map_err(state_error)?;
        Ok(())
    }
}
fn decode<T: DeserializeOwned>(plain: &[u8]) -> Result<T, LambdaError> {
    serde_json::from_slice(plain).map_err(state_error)
}

impl FunctionStore {
    pub(crate) fn stage_one(&self, account: &str, region: &str, name: &str) -> Self {
        let staged = Self::new();
        let key = FunctionKey {
            account_id: account.into(),
            region: region.into(),
            name: name.into(),
        };
        if let Some(record) = self.records.get(&key) {
            staged.records.insert(key, record.clone());
        }
        staged
    }
}
impl LayerStore {
    pub(crate) fn stage_one(&self, account: &str, region: &str, name: &str) -> Self {
        let staged = Self::new();
        let key = LayerKey {
            account_id: account.into(),
            region: region.into(),
            name: name.into(),
        };
        if let Some(record) = self.records.get(&key) {
            staged.records.insert(key, record.clone());
        }
        staged
    }
}

pub(crate) mod archive {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}
pub(crate) mod optional_archive {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_some(&STANDARD.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| STANDARD.decode(text).map_err(serde::de::Error::custom))
            .transpose()
    }
}
