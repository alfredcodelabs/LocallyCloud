//! Incremental encrypted ECR records; callers serialize mutations with registry locks.
use std::sync::Arc;

use locallycloud_state::{StateCipher, StateDb};
use rusqlite::{params, OptionalExtension};

use crate::registry_v2::{Blob, RepoKey, DOCKER_MANIFEST, MAX_BLOB, MAX_MANIFEST, OCI_MANIFEST};
use crate::{EcrHandler, Repository};

pub type EcrStateError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) struct Persistence {
    pub(crate) database: Arc<StateDb>,
    cipher: StateCipher,
}

fn invalid() -> EcrStateError {
    std::io::Error::other("invalid persisted ECR state").into()
}

impl Persistence {
    pub(crate) fn new(database: Arc<StateDb>, cipher: StateCipher) -> Result<Self, EcrStateError> {
        database.connection()?.execute_batch(
            "CREATE TABLE IF NOT EXISTS ecr_records (
                account TEXT NOT NULL, region TEXT NOT NULL, repository TEXT NOT NULL,
                kind TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL,
                payload BLOB NOT NULL, PRIMARY KEY(account,region,repository,kind,id)
            );",
        )?;
        Ok(Self { database, cipher })
    }

    fn seal(
        &self,
        key: &RepoKey,
        kind: &str,
        id: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, EcrStateError> {
        Ok(self.cipher.seal(
            &["ecr", &key.account, &key.region, &key.name, kind, id],
            value,
        )?)
    }

    fn open(
        &self,
        key: &RepoKey,
        kind: &str,
        id: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, EcrStateError> {
        Ok(self
            .cipher
            .open(
                &["ecr", &key.account, &key.region, &key.name, kind, id],
                value,
            )?
            .to_vec())
    }

    pub(crate) fn create_repository(
        &self,
        key: &RepoKey,
        value: &[u8],
    ) -> Result<(), EcrStateError> {
        let payload = self.seal(key, "repository", "", value)?;
        self.database.connection()?.execute("INSERT INTO ecr_records(account,region,repository,kind,id,version,payload) VALUES (?1,?2,?3,'repository','',1,?4)",params![key.account,key.region,key.name,payload])?;
        Ok(())
    }

    pub(crate) fn delete_repository(&self, key: &RepoKey) -> Result<(), EcrStateError> {
        self.database.connection()?.execute(
            "DELETE FROM ecr_records WHERE account=?1 AND region=?2 AND repository=?3",
            params![key.account, key.region, key.name],
        )?;
        Ok(())
    }

    pub(crate) fn save_blob(
        &self,
        key: &RepoKey,
        digest: &str,
        bytes: &[u8],
    ) -> Result<(), EcrStateError> {
        if bytes.len() > MAX_BLOB || crate::registry_v2::sha256(bytes) != digest {
            return Err(invalid());
        }
        let payload = self.seal(key, "blob", digest, bytes)?;
        let index = self.seal(
            key,
            "blob-index",
            digest,
            &serde_json::to_vec(&bytes.len())?,
        )?;
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction()?;
        for (kind, value) in [("blob", payload), ("blob-index", index)] {
            transaction.execute("INSERT INTO ecr_records(account,region,repository,kind,id,version,payload) VALUES (?1,?2,?3,?4,?5,1,?6) ON CONFLICT(account,region,repository,kind,id) DO UPDATE SET payload=excluded.payload",params![key.account,key.region,key.name,kind,digest,value])?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn load_blob(
        &self,
        key: &RepoKey,
        digest: &str,
        size: usize,
    ) -> Result<bytes::Bytes, EcrStateError> {
        if size > MAX_BLOB || !crate::registry_v2::valid_digest(digest) {
            return Err(invalid());
        }
        let payload: Vec<u8> = self.database.connection()?.query_row("SELECT payload FROM ecr_records WHERE account=?1 AND region=?2 AND repository=?3 AND kind='blob' AND id=?4 AND version=1 AND length(payload)<=?5",params![key.account,key.region,key.name,digest,i64::try_from(MAX_BLOB+64)?],|row| row.get(0))?;
        let clear = self.open(key, "blob", digest, &payload)?;
        if clear.len() != size || crate::registry_v2::sha256(&clear) != digest {
            return Err(invalid());
        }
        Ok(bytes::Bytes::from(clear))
    }

    pub(crate) fn save_manifest(
        &self,
        key: &RepoKey,
        digest: &str,
        body: &[u8],
        tag: Option<&str>,
    ) -> Result<(), EcrStateError> {
        let manifest = self.seal(key, "manifest", digest, body)?;
        let tag_payload = tag
            .map(|tag| self.seal(key, "tag", tag, digest.as_bytes()))
            .transpose()?;
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute("INSERT INTO ecr_records(account,region,repository,kind,id,version,payload) VALUES (?1,?2,?3,'manifest',?4,1,?5) ON CONFLICT(account,region,repository,kind,id) DO UPDATE SET payload=excluded.payload",params![key.account,key.region,key.name,digest,manifest])?;
        if let (Some(tag), Some(payload)) = (tag, tag_payload) {
            transaction.execute("INSERT INTO ecr_records(account,region,repository,kind,id,version,payload) VALUES (?1,?2,?3,'tag',?4,1,?5) ON CONFLICT(account,region,repository,kind,id) DO UPDATE SET payload=excluded.payload",params![key.account,key.region,key.name,tag,payload])?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn restore(&self, handler: &EcrHandler) -> Result<(), EcrStateError> {
        let connection = self.database.connection()?;
        // Read metadata one entity at a time; never SELECT encrypted blob payloads at startup.
        let unknown: Option<u8> = connection.query_row("SELECT 1 FROM ecr_records WHERE kind NOT IN ('repository','blob-index','blob','manifest','tag') LIMIT 1", [], |row| row.get(0)).optional()?;
        if unknown.is_some() {
            return Err(invalid());
        }
        // Separate scans avoid sorting/materializing every encrypted manifest payload.
        for restore_kind in ["repository", "blob-index", "manifest", "tag"] {
            let mut statement = connection.prepare("SELECT account,region,repository,kind,id,version,CASE WHEN length(payload)<=?1 THEN payload ELSE NULL END FROM ecr_records WHERE kind=?2")?;
            let mut rows =
                statement.query(params![i64::try_from(MAX_MANIFEST + 64)?, restore_kind])?;
            while let Some(row) = rows.next()? {
                let key = RepoKey {
                    account: row.get(0)?,
                    region: row.get(1)?,
                    name: row.get(2)?,
                };
                let kind: String = row.get(3)?;
                let id: String = row.get(4)?;
                let version: u32 = row.get(5)?;
                let payload: Vec<u8> = row.get(6)?;
                if version != 1
                    || crate::validate_repository_name(&key.name).is_err()
                    || payload.len() > MAX_MANIFEST + 64
                {
                    return Err(invalid());
                }
                let clear = self.open(&key, &kind, &id, &payload)?;
                match kind.as_str() {
                    "repository" => {
                        let repo: Repository = serde_json::from_slice(&clear)?;
                        if !id.is_empty()
                            || repo.name != key.name
                            || !repo.created_at.is_finite()
                            || repo.created_at < 0.0
                            || !matches!(
                                repo.image_tag_mutability.as_str(),
                                "MUTABLE" | "IMMUTABLE"
                            )
                            || repo.encryption_type != "AES256"
                            || repo.kms_key.is_some()
                        {
                            return Err(invalid());
                        }
                        if !handler.registry_v2.provision_restored_repository(
                            &key,
                            repo.image_tag_mutability == "IMMUTABLE",
                        ) {
                            return Err(invalid());
                        }
                        handler
                            .repos
                            .insert(EcrHandler::key(&key.account, &key.region, &key.name), repo);
                    }
                    "blob-index" => {
                        if !crate::registry_v2::valid_digest(&id) {
                            return Err(invalid());
                        }
                        let size: usize = serde_json::from_slice(&clear)?;
                        if size > MAX_BLOB {
                            return Err(invalid());
                        }
                        let exists:Option<i64>=connection.query_row("SELECT length(payload) FROM ecr_records WHERE account=?1 AND region=?2 AND repository=?3 AND kind='blob' AND id=?4 AND version=1",params![key.account,key.region,key.name,id],|row|row.get(0)).optional()?;
                        if exists != Some(i64::try_from(size + 29)?) {
                            return Err(invalid());
                        }
                        handler
                            .registry_v2
                            .restore_blob(&key, id, Blob::durable(size))?;
                    }
                    "manifest" => {
                        if clear.len() > MAX_MANIFEST || crate::registry_v2::sha256(&clear) != id {
                            return Err(invalid());
                        }
                        let value: serde_json::Value = serde_json::from_slice(&clear)?;
                        let media = match value["mediaType"].as_str() {
                            Some(OCI_MANIFEST) => OCI_MANIFEST,
                            Some(DOCKER_MANIFEST) => DOCKER_MANIFEST,
                            _ => return Err(invalid()),
                        };
                        handler.registry_v2.restore_manifest(
                            &key,
                            id,
                            bytes::Bytes::from(clear),
                            media,
                        )?;
                    }
                    "tag" => {
                        let digest = String::from_utf8(clear)?;
                        if !crate::registry_v2::valid_reference(&id)
                            || id.starts_with("sha256:")
                            || !crate::registry_v2::valid_digest(&digest)
                        {
                            return Err(invalid());
                        }
                        handler.registry_v2.restore_tag(&key, id, digest)?;
                    }
                    _ => return Err(invalid()),
                }
            }
        }
        Ok(())
    }
}
