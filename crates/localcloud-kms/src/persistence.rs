use std::sync::Arc;

use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM, NONCE_LEN};
use base64::{engine::general_purpose::STANDARD, Engine};
use localcloud_state::StateDb;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::KmsError;
use crate::model::{AliasRecord, KeyManager, KeyRecord, KeyState, Scope, SecretMaterial};
use crate::policy::KeyPolicy;

pub(crate) struct KmsPersistence {
    db: Arc<StateDb>,
    master: SecretMaterial,
}

#[derive(Serialize, Deserialize)]
struct SavedKey {
    key_id: String,
    description: String,
    creation_date: f64,
    state: String,
    deletion_date: Option<f64>,
    pending_window_days: Option<u32>,
    manager: String,
    owner_service: Option<String>,
    policy: String,
    explicit_policy: bool,
    material_version: u32,
    sealed_material: Vec<u8>,
}

impl KmsPersistence {
    pub(crate) fn new(db: Arc<StateDb>) -> Result<Self, KmsError> {
        let encoded = Zeroizing::new(
            std::env::var("LOCALCLOUD_KMS_MASTER_KEY").map_err(|_| KmsError::Internal)?,
        );
        let mut decoded = Zeroizing::new(
            STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| KmsError::Internal)?,
        );
        let master: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| KmsError::Internal)?;
        decoded.zeroize();
        Self::with_master(db, SecretMaterial::new(master))
    }

    fn with_master(db: Arc<StateDb>, master: SecretMaterial) -> Result<Self, KmsError> {
        let store = Self { db, master };
        store.connection()?.execute_batch(
            "CREATE TABLE IF NOT EXISTS kms_keys (account TEXT NOT NULL, region TEXT NOT NULL, key_id TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY(account,region,key_id));
             CREATE TABLE IF NOT EXISTS kms_aliases (account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL, target TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL, PRIMARY KEY(account,region,name));
             CREATE TABLE IF NOT EXISTS kms_defaults (account TEXT NOT NULL, region TEXT NOT NULL, service TEXT NOT NULL, key_id TEXT NOT NULL, PRIMARY KEY(account,region,service));"
        ).map_err(|_| KmsError::Internal)?;
        // Decrypt all existing keys at startup so a wrong master key fails before requests are served.
        store.load_keys()?;
        Ok(store)
    }

    fn connection(&self) -> Result<Connection, KmsError> {
        self.db.connection().map_err(|_| KmsError::Internal)
    }

    pub(crate) fn load_keys(&self) -> Result<Vec<(Scope, KeyRecord)>, KmsError> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare("SELECT account,region,key_id,record FROM kms_keys")
            .map_err(|_| KmsError::Internal)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|_| KmsError::Internal)?;
        rows.map(|row| {
            let (account, region, stored_id, bytes) = row.map_err(|_| KmsError::Internal)?;
            let scope = Scope::new(&account, &region);
            let saved: SavedKey = serde_json::from_slice(&bytes).map_err(|_| KmsError::Internal)?;
            if saved.key_id != stored_id {
                return Err(KmsError::Internal);
            }
            let material = self.open_material(&scope, &saved.key_id, &saved.sealed_material)?;
            let state = match saved.state.as_str() {
                "Enabled" => KeyState::Enabled,
                "PendingDeletion" => KeyState::PendingDeletion {
                    deletion_date: saved.deletion_date.ok_or(KmsError::Internal)?,
                    pending_window_days: saved.pending_window_days.ok_or(KmsError::Internal)?,
                },
                _ => return Err(KmsError::Internal),
            };
            let manager = match saved.manager.as_str() {
                "Customer" => KeyManager::Customer,
                "Aws" => KeyManager::Aws,
                _ => return Err(KmsError::Internal),
            };
            let policy = KeyPolicy::parse(saved.policy).map_err(|_| KmsError::Internal)?;
            Ok((
                scope,
                KeyRecord {
                    key_id: saved.key_id,
                    description: saved.description,
                    creation_date: saved.creation_date,
                    state,
                    manager,
                    owner_service: saved.owner_service,
                    policy,
                    explicit_policy: saved.explicit_policy,
                    material_version: saved.material_version,
                    material,
                },
            ))
        })
        .collect()
    }

    pub(crate) fn load_aliases(&self) -> Result<Vec<(Scope, AliasRecord)>, KmsError> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare("SELECT account,region,name,target,created,updated FROM kms_aliases")
            .map_err(|_| KmsError::Internal)?;
        let result = stmt
            .query_map([], |row| {
                Ok((
                    Scope::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?),
                    AliasRecord {
                        alias_name: row.get(2)?,
                        target_key_id: row.get(3)?,
                        creation_date: row.get(4)?,
                        last_updated_date: row.get(5)?,
                    },
                ))
            })
            .map_err(|_| KmsError::Internal)?
            .map(|row| row.map_err(|_| KmsError::Internal))
            .collect();
        result
    }

    pub(crate) fn load_defaults(&self) -> Result<Vec<(Scope, String, String)>, KmsError> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare("SELECT account,region,service,key_id FROM kms_defaults")
            .map_err(|_| KmsError::Internal)?;
        let result = stmt
            .query_map([], |row| {
                Ok((
                    Scope::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?),
                    row.get(2)?,
                    row.get(3)?,
                ))
            })
            .map_err(|_| KmsError::Internal)?
            .map(|row| row.map_err(|_| KmsError::Internal))
            .collect();
        result
    }

    pub(crate) fn save_key(&self, scope: &Scope, key: &KeyRecord) -> Result<(), KmsError> {
        self.save_key_on(&self.connection()?, scope, key)
    }
    pub(crate) fn save_alias(&self, scope: &Scope, alias: &AliasRecord) -> Result<(), KmsError> {
        save_alias(&self.connection()?, scope, alias)
    }
    pub(crate) fn delete_alias(&self, scope: &Scope, name: &str) -> Result<(), KmsError> {
        self.connection()?
            .execute(
                "DELETE FROM kms_aliases WHERE account=?1 AND region=?2 AND name=?3",
                params![scope.account_id, scope.region, name],
            )
            .map_err(|_| KmsError::Internal)?;
        Ok(())
    }
    pub(crate) fn save_default(
        &self,
        scope: &Scope,
        service: &str,
        key: &KeyRecord,
        alias: &AliasRecord,
    ) -> Result<(), KmsError> {
        let mut conn = self.connection()?;
        let tx = conn.transaction().map_err(|_| KmsError::Internal)?;
        self.save_key_on(&tx, scope, key)?;
        save_alias(&tx, scope, alias)?;
        tx.execute(
            "INSERT INTO kms_defaults(account,region,service,key_id) VALUES (?1,?2,?3,?4)",
            params![scope.account_id, scope.region, service, key.key_id],
        )
        .map_err(|_| KmsError::Internal)?;
        tx.commit().map_err(|_| KmsError::Internal)
    }

    fn save_key_on(
        &self,
        conn: &Connection,
        scope: &Scope,
        key: &KeyRecord,
    ) -> Result<(), KmsError> {
        let (state, deletion_date, pending_window_days) = match key.state {
            KeyState::Enabled => ("Enabled", None, None),
            KeyState::PendingDeletion {
                deletion_date,
                pending_window_days,
            } => (
                "PendingDeletion",
                Some(deletion_date),
                Some(pending_window_days),
            ),
        };
        let saved = SavedKey {
            key_id: key.key_id.clone(),
            description: key.description.clone(),
            creation_date: key.creation_date,
            state: state.into(),
            deletion_date,
            pending_window_days,
            manager: (match key.manager {
                KeyManager::Customer => "Customer",
                KeyManager::Aws => "Aws",
            })
            .into(),
            owner_service: key.owner_service.clone(),
            policy: key.policy.raw().into(),
            explicit_policy: key.explicit_policy,
            material_version: key.material_version,
            sealed_material: self.seal_material(scope, &key.key_id, &key.material)?,
        };
        let bytes = serde_json::to_vec(&saved).map_err(|_| KmsError::Internal)?;
        conn.execute("INSERT INTO kms_keys(account,region,key_id,record) VALUES (?1,?2,?3,?4) ON CONFLICT(account,region,key_id) DO UPDATE SET record=excluded.record", params![scope.account_id, scope.region, key.key_id, bytes]).map_err(|_| KmsError::Internal)?;
        Ok(())
    }

    fn seal_material(
        &self,
        scope: &Scope,
        key_id: &str,
        material: &SecretMaterial,
    ) -> Result<Vec<u8>, KmsError> {
        let key = RandomizedNonceKey::new(&AES_256_GCM, self.master.expose())
            .map_err(|_| KmsError::Internal)?;
        let mut data = Zeroizing::new(material.expose().to_vec());
        let nonce = key
            .seal_in_place_append_tag(Aad::from(material_aad(scope, key_id)), &mut *data)
            .map_err(|_| KmsError::Internal)?;
        let mut sealed = nonce.as_ref().to_vec();
        sealed.extend_from_slice(&data);
        Ok(sealed)
    }

    fn open_material(
        &self,
        scope: &Scope,
        key_id: &str,
        sealed: &[u8],
    ) -> Result<SecretMaterial, KmsError> {
        if sealed.len() != NONCE_LEN + 32 + 16 {
            return Err(KmsError::Internal);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&sealed[..NONCE_LEN]);
        let key = RandomizedNonceKey::new(&AES_256_GCM, self.master.expose())
            .map_err(|_| KmsError::Internal)?;
        let mut data = Zeroizing::new(sealed[NONCE_LEN..].to_vec());
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(material_aad(scope, key_id)),
                &mut data,
            )
            .map_err(|_| KmsError::Internal)?;
        let material: [u8; 32] = plain.try_into().map_err(|_| KmsError::Internal)?;
        Ok(SecretMaterial::new(material))
    }
}

fn material_aad(scope: &Scope, key_id: &str) -> Vec<u8> {
    let mut aad = b"localcloud-kms-store-v1".to_vec();
    for part in [&scope.account_id, &scope.region, key_id] {
        aad.extend_from_slice(&(part.len() as u32).to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    aad
}
fn save_alias(conn: &Connection, scope: &Scope, alias: &AliasRecord) -> Result<(), KmsError> {
    conn.execute("INSERT INTO kms_aliases(account,region,name,target,created,updated) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(account,region,name) DO UPDATE SET target=excluded.target,updated=excluded.updated", params![scope.account_id, scope.region, alias.alias_name, alias.target_key_id, alias.creation_date, alias.last_updated_date]).map_err(|_| KmsError::Internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn encrypted_material_survives_restart_and_rejects_wrong_master() {
        let path = std::env::temp_dir()
            .join(format!("localcloud-kms-{}", Uuid::new_v4()))
            .join("state.sqlite3");
        let db = Arc::new(StateDb::open(path).expect("state"));
        let scope = Scope::new("000000000000", "us-east-1");
        let record = KeyRecord {
            key_id: Uuid::new_v4().to_string(),
            description: "persistent".into(),
            creation_date: 1.0,
            state: KeyState::Enabled,
            manager: KeyManager::Customer,
            owner_service: None,
            policy: KeyPolicy::default_for(&scope.account_id),
            explicit_policy: false,
            material_version: 1,
            material: SecretMaterial::new([0x5a; 32]),
        };
        let first = KmsPersistence::with_master(db.clone(), SecretMaterial::new([0x11; 32]))
            .expect("create");
        first.save_key(&scope, &record).expect("commit");
        drop(first);
        let reopened = KmsPersistence::with_master(db.clone(), SecretMaterial::new([0x11; 32]))
            .expect("reopen");
        let keys = reopened.load_keys().expect("recover");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].1.material.expose(), &[0x5a; 32]);
        let bytes: Vec<u8> = db
            .connection()
            .expect("db")
            .query_row("SELECT record FROM kms_keys", [], |row| row.get(0))
            .expect("saved");
        assert!(!bytes.windows(32).any(|chunk| chunk == [0x5a; 32]));
        assert!(KmsPersistence::with_master(db.clone(), SecretMaterial::new([0x22; 32])).is_err());
        db.connection()
            .unwrap()
            .execute("UPDATE kms_keys SET key_id='moved'", [])
            .unwrap();
        assert!(KmsPersistence::with_master(db, SecretMaterial::new([0x11; 32])).is_err());
    }
}
