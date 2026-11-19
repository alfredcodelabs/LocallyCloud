use super::*;
use locallycloud_state::{StateCipher, StateDb};
use rusqlite::params;
use serde::{de::DeserializeOwned, Serialize};

pub(super) struct Persistence {
    db: Arc<StateDb>,
    cipher: StateCipher,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedExecution {
    arn: String,
    id: String,
    token: Option<String>,
    execution: Execution,
}

impl Persistence {
    pub fn new(db: Arc<StateDb>) -> Result<Self, String> {
        Self::with_cipher(db, StateCipher::from_env().map_err(|e| e.to_string())?)
    }
    pub(super) fn with_cipher(db: Arc<StateDb>, cipher: StateCipher) -> Result<Self, String> {
        db.connection().map_err(|e| e.to_string())?.execute_batch("CREATE TABLE IF NOT EXISTS region_switch_entities(account TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(account,kind,id))").map_err(|e|e.to_string())?;
        Ok(Self { db, cipher })
    }
    fn save<T: Serialize>(
        &self,
        account: &str,
        kind: &str,
        id: &str,
        value: &T,
    ) -> Result<(), Error> {
        let value = serde_json::to_vec(value).map_err(|_| Error::internal())?;
        let payload = self
            .cipher
            .seal(&["arc-region-switch", account, kind, id], &value)
            .map_err(|_| Error::internal())?;
        self.db.connection().map_err(|_|Error::internal())?.execute("INSERT INTO region_switch_entities(account,kind,id,payload) VALUES(?1,?2,?3,?4) ON CONFLICT(account,kind,id) DO UPDATE SET payload=excluded.payload",params![account,kind,id,payload]).map_err(|_|Error::internal())?;
        Ok(())
    }
    pub fn plan(&self, plan: &Plan) -> Result<(), Error> {
        self.save(
            &plan.account,
            "plan",
            plan.value["arn"].as_str().ok_or_else(Error::internal)?,
            plan,
        )
    }
    pub fn execution(
        &self,
        account: &str,
        arn: &str,
        id: &str,
        token: Option<String>,
        execution: Execution,
    ) -> Result<(), Error> {
        self.save(
            account,
            "execution",
            &format!("{arn}|{id}"),
            &SavedExecution {
                arn: arn.into(),
                id: id.into(),
                token,
                execution,
            },
        )
    }
    pub fn restore(&self) -> Result<State, String> {
        fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
            serde_json::from_slice(bytes).map_err(|e| e.to_string())
        }
        let connection = self.db.connection().map_err(|e| e.to_string())?;
        let mut stmt = connection
            .prepare("SELECT account,kind,id,payload FROM region_switch_entities ORDER BY kind,id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut state = State::default();
        for row in rows {
            let (account, kind, id, payload) = row.map_err(|e| e.to_string())?;
            let bytes = self
                .cipher
                .open(&["arc-region-switch", &account, &kind, &id], &payload)
                .map_err(|e| e.to_string())?;
            match kind.as_str() {
                "plan" => {
                    let plan: Plan = decode(&bytes)?;
                    if plan.account != account || plan.value["arn"] != id {
                        return Err("Invalid Region Switch plan state".into());
                    }
                    state.plans.insert(id, plan);
                }
                "execution" => {
                    let saved: SavedExecution = decode(&bytes)?;
                    if id != format!("{}|{}", saved.arn, saved.id) {
                        return Err("Invalid Region Switch execution state".into());
                    }
                    if let Some(token) = saved.token {
                        state
                            .tokens
                            .insert((saved.arn.clone(), token), saved.id.clone());
                    }
                    state
                        .executions
                        .insert((saved.arn, saved.id), saved.execution);
                }
                _ => return Err("Invalid Region Switch entity kind".into()),
            }
        }
        Ok(state)
    }
}
