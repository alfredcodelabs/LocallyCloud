//! Encrypted rows for IAM resources and unexpired STS sessions.
use crate::{error::IamStsError, store::IamRecords, sts::Session};
use locallycloud_state::{StateCipher, StateDb};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
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

/// Authenticate the shared master key against existing IAM envelopes without initializing
/// or modifying state. `false` means this source contains no IAM key evidence.
/// The offline caller must retain the runtime lock until its administrative change commits.
pub fn authenticate_state_key(path: &Path, cipher: &StateCipher) -> Result<bool, IamStsError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(state_error)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(state_error)?;
    connection
        .execute_batch("BEGIN DEFERRED")
        .map_err(state_error)?;
    let present = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='iam_resources')",
        [], |row| row.get::<_, bool>(0),
    ).map_err(state_error)?;
    if !present {
        return Ok(false);
    }
    let mut query = connection
        .prepare(
            "SELECT CASE WHEN length(CAST(account AS BLOB)) BETWEEN 1 AND 64 THEN account END,
                CASE WHEN length(CAST(kind AS BLOB)) BETWEEN 1 AND 32 THEN kind END,
                CASE WHEN length(CAST(name AS BLOB)) BETWEEN 1 AND 2048 THEN name END,
                CASE WHEN length(CAST(payload AS BLOB)) BETWEEN 1 AND 8388608 THEN payload END
         FROM iam_resources ORDER BY account,kind,name",
        )
        .map_err(state_error)?;
    let mut rows = query.query([]).map_err(state_error)?;
    let mut authenticated = false;
    while let Some(row) = rows.next().map_err(state_error)? {
        let account: String = row.get(0).map_err(state_error)?;
        let kind: String = row.get(1).map_err(state_error)?;
        let name: String = row.get(2).map_err(state_error)?;
        let payload: Vec<u8> = row.get(3).map_err(state_error)?;
        if [&account, &kind, &name]
            .iter()
            .any(|field| field.contains('\0'))
            || !matches!(
                kind.as_str(),
                "bootstrap" | "user" | "group" | "role" | "policy" | "instance-profile"
            )
        {
            return Err(state_error("invalid IAM record scope"));
        }
        let _plain = cipher
            .open(&["iam", &account, "global", &kind, &name], &payload)
            .map_err(state_error)?;
        authenticated = true;
    }
    Ok(authenticated)
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

#[cfg(test)]
mod key_authentication_tests {
    use super::*;

    struct Fixture {
        root: std::path::PathBuf,
        state: Arc<StateDb>,
    }
    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("iam-readonly-key-{}", uuid::Uuid::new_v4()));
            let state = Arc::new(StateDb::open(root.join("state.db")).unwrap());
            Self { root, state }
        }
        fn schema(&self) {
            IamPersistence::with_cipher(self.state.clone(), StateCipher::with_key(&[7; 32]))
                .unwrap();
        }
        fn record(&self, account: &str, name: &str, key: u8) {
            let payload = StateCipher::with_key(&[key; 32])
                .seal(&["iam", account, "global", "bootstrap", name], b"true")
                .unwrap();
            self.state.connection().unwrap().execute("INSERT INTO iam_resources(account,kind,name,payload) VALUES(?1,'bootstrap',?2,?3)",params![account,name,payload]).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn missing_and_empty_sources_have_no_key_evidence_and_are_never_initialized() {
        let fixture = Fixture::new();
        let missing = fixture.root.join("missing.db");
        let cipher = StateCipher::with_key(&[7; 32]);
        assert!(authenticate_state_key(&missing, &cipher).is_err());
        assert!(!missing.exists());
        let before = std::fs::read(fixture.state.path()).unwrap();
        assert!(!authenticate_state_key(fixture.state.path(), &cipher).unwrap());
        assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
        fixture.schema();
        let before = std::fs::read(fixture.state.path()).unwrap();
        assert!(!authenticate_state_key(fixture.state.path(), &cipher).unwrap());
        assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
    }

    #[test]
    fn correct_key_authenticates_every_row_and_wrong_key_never_mutates_source() {
        let fixture = Fixture::new();
        fixture.schema();
        fixture.record("000000000000", "initialized", 7);
        fixture.record("aws", "another", 7);
        let before = std::fs::read(fixture.state.path()).unwrap();
        assert!(
            authenticate_state_key(fixture.state.path(), &StateCipher::with_key(&[7; 32])).unwrap()
        );
        let wrong = authenticate_state_key(fixture.state.path(), &StateCipher::with_key(&[8; 32]))
            .unwrap_err();
        assert_eq!(wrong, state_error("ignored sensitive detail"));
        assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
        fixture.record("zzz", "last-key-mismatch", 8);
        assert!(
            authenticate_state_key(fixture.state.path(), &StateCipher::with_key(&[7; 32])).is_err()
        );
    }

    #[test]
    fn malformed_scopes_oversized_payloads_and_corruption_are_rejected_generically() {
        let fixture = Fixture::new();
        fixture.schema();
        let cipher = StateCipher::with_key(&[7; 32]);
        for (field, value) in [
            ("account", "x".repeat(65)),
            ("kind", "x".repeat(33)),
            ("name", "x".repeat(2049)),
            ("kind", "future".into()),
            ("name", "bad\0name".into()),
        ] {
            fixture
                .state
                .connection()
                .unwrap()
                .execute("DELETE FROM iam_resources", [])
                .unwrap();
            fixture.record("000000000000", "initialized", 7);
            let sql = match field {
                "account" => "UPDATE iam_resources SET account=?1",
                "kind" => "UPDATE iam_resources SET kind=?1",
                _ => "UPDATE iam_resources SET name=?1",
            };
            fixture
                .state
                .connection()
                .unwrap()
                .execute(sql, [value])
                .unwrap();
            let before = std::fs::read(fixture.state.path()).unwrap();
            assert_eq!(
                authenticate_state_key(fixture.state.path(), &cipher).unwrap_err(),
                state_error("hidden")
            );
            assert_eq!(std::fs::read(fixture.state.path()).unwrap(), before);
        }
        fixture
            .state
            .connection()
            .unwrap()
            .execute("DELETE FROM iam_resources", [])
            .unwrap();
        fixture.record("000000000000", "initialized", 7);
        fixture
            .state
            .connection()
            .unwrap()
            .execute("UPDATE iam_resources SET payload=x'010203'", [])
            .unwrap();
        assert_eq!(
            authenticate_state_key(fixture.state.path(), &cipher).unwrap_err(),
            state_error("hidden")
        );
        fixture
            .state
            .connection()
            .unwrap()
            .execute("UPDATE iam_resources SET payload=zeroblob(8388609)", [])
            .unwrap();
        assert_eq!(
            authenticate_state_key(fixture.state.path(), &cipher).unwrap_err(),
            state_error("hidden")
        );
    }
}
