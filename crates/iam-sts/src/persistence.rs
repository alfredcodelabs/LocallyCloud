//! Encrypted rows for IAM resources and unexpired STS sessions.
use crate::{error::IamStsError, store::IamRecords, sts::Session};
use locallycloud_state::{StateCipher, StateDb};
use rusqlite::{params, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::Zeroizing;

type RowKey = (String, String, String);
type Rows = BTreeMap<RowKey, Zeroizing<Vec<u8>>>;

pub(crate) struct IamPersistence {
    db: Arc<StateDb>,
    cipher: StateCipher,
}

pub(crate) fn state_error(_: impl std::fmt::Display) -> IamStsError {
    IamStsError::InternalFailure("IAM state could not be committed or loaded; check the state database and original master key".into())
}

impl IamPersistence {
    pub fn new(db: Arc<StateDb>) -> Result<Self, IamStsError> {
        Self::with_cipher(db, StateCipher::from_env().map_err(state_error)?)
    }
    pub(crate) fn with_cipher(db: Arc<StateDb>, cipher: StateCipher) -> Result<Self, IamStsError> {
        db.connection().map_err(state_error)?.execute_batch(
            "CREATE TABLE IF NOT EXISTS iam_resources (account TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(account,kind,name));
             CREATE TABLE IF NOT EXISTS iam_sessions (account TEXT NOT NULL, id TEXT PRIMARY KEY, expires INTEGER NOT NULL, payload BLOB NOT NULL);"
        ).map_err(state_error)?;
        Ok(Self { db, cipher })
    }
    pub fn load_resources(&self) -> Result<IamRecords, IamStsError> {
        let connection = self.db.connection().map_err(state_error)?;
        let mut query = connection
            .prepare("SELECT account,kind,name,payload FROM iam_resources")
            .map_err(state_error)?;
        let rows = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(state_error)?;
        let mut resources = IamRecords::default();
        for row in rows {
            let (account, kind, name, payload) = row.map_err(state_error)?;
            let plain = self
                .cipher
                .open(&["iam", &account, "global", &kind, &name], &payload)
                .map_err(state_error)?;
            let key = (account.clone(), name.clone());
            match kind.as_str() {
                "bootstrap" => {
                    if name != "initialized" || !decode::<bool>(&plain)? {
                        return Err(state_error("invalid bootstrap marker"));
                    }
                    resources.bootstrap_initialized.insert(account);
                }
                "user" => {
                    resources.users.insert(key, decode(&plain)?);
                }
                "group" => {
                    resources.groups.insert(key, decode(&plain)?);
                }
                "role" => {
                    resources.roles.insert(key, decode(&plain)?);
                }
                "policy" => {
                    resources.policies.insert(key, decode(&plain)?);
                }
                "instance-profile" => {
                    resources.instance_profiles.insert(key, decode(&plain)?);
                }
                _ => return Err(state_error("unknown resource kind")),
            }
        }
        Ok(resources)
    }
    pub fn commit_resources(
        &self,
        before: &IamRecords,
        after: &IamRecords,
    ) -> Result<(), IamStsError> {
        let before = rows(before)?;
        let after = rows(after)?;
        let mut connection = self.db.connection().map_err(state_error)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(state_error)?;
        for ((account, kind, name), plain) in &after {
            if before.get(&(account.clone(), kind.clone(), name.clone())) == Some(plain) {
                continue;
            }
            let payload = self
                .cipher
                .seal(&["iam", account, "global", kind, name], plain)
                .map_err(state_error)?;
            tx.execute("INSERT INTO iam_resources(account,kind,name,payload) VALUES(?1,?2,?3,?4) ON CONFLICT(account,kind,name) DO UPDATE SET payload=excluded.payload",params![account,kind,name,payload]).map_err(state_error)?;
        }
        for (account, kind, name) in before.keys().filter(|key| !after.contains_key(*key)) {
            tx.execute(
                "DELETE FROM iam_resources WHERE account=?1 AND kind=?2 AND name=?3",
                params![account, kind, name],
            )
            .map_err(state_error)?;
        }
        tx.commit().map_err(state_error)
    }
    pub fn save_session(&self, id: &str, session: &Session) -> Result<(), IamStsError> {
        let plain = Zeroizing::new(serde_json::to_vec(session).map_err(state_error)?);
        let payload = self
            .cipher
            .seal(&["sts", &session.account, "global", "session", id], &plain)
            .map_err(state_error)?;
        self.db
            .connection()
            .map_err(state_error)?
            .execute(
                "INSERT INTO iam_sessions(account,id,expires,payload) VALUES(?1,?2,?3,?4)",
                params![
                    session.account,
                    id,
                    session.expires_at.unix_timestamp(),
                    payload
                ],
            )
            .map_err(state_error)?;
        Ok(())
    }
    pub fn load_sessions(&self) -> Result<Vec<(String, Session)>, IamStsError> {
        let connection = self.db.connection().map_err(state_error)?;
        let mut query = connection
            .prepare("SELECT account,id,payload FROM iam_sessions")
            .map_err(state_error)?;
        let rows = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(state_error)?;
        let mut sessions = Vec::new();
        for row in rows {
            let (account, id, payload) = row.map_err(state_error)?;
            let plain = self
                .cipher
                .open(&["sts", &account, "global", "session", &id], &payload)
                .map_err(state_error)?;
            let session: Session = decode(&plain)?;
            if session.account != account {
                return Err(state_error("session scope mismatch"));
            }
            if session.expires_at > time::OffsetDateTime::now_utc() {
                sessions.push((id, session));
            } else {
                connection
                    .execute("DELETE FROM iam_sessions WHERE id=?1", params![id])
                    .map_err(state_error)?;
            }
        }
        Ok(sessions)
    }
    pub fn remove_session(&self, id: &str) -> Result<(), IamStsError> {
        self.db
            .connection()
            .map_err(state_error)?
            .execute("DELETE FROM iam_sessions WHERE id=?1", params![id])
            .map_err(state_error)?;
        Ok(())
    }
}
fn decode<T: DeserializeOwned>(plain: &[u8]) -> Result<T, IamStsError> {
    serde_json::from_slice(plain).map_err(state_error)
}
fn rows(records: &IamRecords) -> Result<Rows, IamStsError> {
    fn add<T: Serialize>(
        rows: &mut Rows,
        kind: &str,
        resources: &BTreeMap<(String, String), T>,
    ) -> Result<(), IamStsError> {
        for ((account, name), resource) in resources {
            rows.insert(
                (account.clone(), kind.to_owned(), name.clone()),
                Zeroizing::new(serde_json::to_vec(resource).map_err(state_error)?),
            );
        }
        Ok(())
    }
    let mut rows = Rows::new();
    for account in &records.bootstrap_initialized {
        rows.insert(
            (account.clone(), "bootstrap".into(), "initialized".into()),
            Zeroizing::new(serde_json::to_vec(&true).map_err(state_error)?),
        );
    }
    add(&mut rows, "user", &records.users)?;
    add(&mut rows, "group", &records.groups)?;
    add(&mut rows, "role", &records.roles)?;
    add(&mut rows, "policy", &records.policies)?;
    add(&mut rows, "instance-profile", &records.instance_profiles)?;
    Ok(rows)
}
