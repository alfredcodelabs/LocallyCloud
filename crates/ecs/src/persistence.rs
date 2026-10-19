//! Per-entity encrypted control-plane state. No host process or socket is restored.
use super::*;
use locallycloud_state::{StateCipher, StateDb};
use rusqlite::params;

pub(super) type PersistError = Box<dyn std::error::Error + Send + Sync>;
pub(super) struct Persistence {
    database: Arc<StateDb>,
    cipher: StateCipher,
}
impl Persistence {
    pub(super) fn new(database: Arc<StateDb>, cipher: StateCipher) -> Result<Self, PersistError> {
        database.connection()?.execute_batch("CREATE TABLE IF NOT EXISTS ecs_control(account TEXT NOT NULL, region TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL, version INTEGER NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(account,region,kind,name));")?;
        Ok(Self { database, cipher })
    }
    pub(super) fn save(
        &self,
        scope: &Scope,
        kind: &str,
        name: &str,
        value: &Value,
    ) -> Result<(), PersistError> {
        let clear = serde_json::to_vec(value)?;
        if clear.len() > MAX_BODY {
            return Err(std::io::Error::other("ECS persisted entity is too large").into());
        }
        let payload = self
            .cipher
            .seal(&["ecs", &scope.account, &scope.region, kind, name], &clear)?;
        self.database.connection()?.execute("INSERT INTO ecs_control(account,region,kind,name,version,payload) VALUES(?1,?2,?3,?4,1,?5) ON CONFLICT(account,region,kind,name) DO UPDATE SET payload=excluded.payload", params![scope.account,scope.region,kind,name,payload])?;
        Ok(())
    }
    pub(super) fn delete(&self, scope: &Scope, kind: &str, name: &str) -> Result<(), PersistError> {
        self.database.connection()?.execute(
            "DELETE FROM ecs_control WHERE account=?1 AND region=?2 AND kind=?3 AND name=?4",
            params![scope.account, scope.region, kind, name],
        )?;
        Ok(())
    }
    pub(super) fn restore(&self) -> Result<State, PersistError> {
        let connection = self.database.connection()?;
        let mut statement = connection.prepare("SELECT account,region,kind,name,version,payload FROM ecs_control ORDER BY kind,length(name),name")?;
        let mut rows = statement.query([])?;
        let mut state = State::default();
        while let Some(row) = rows.next()? {
            let scope = Scope {
                account: row.get(0)?,
                region: row.get(1)?,
            };
            let kind: String = row.get(2)?;
            let name: String = row.get(3)?;
            if row.get::<_, i64>(4)? != 1 {
                return Err(std::io::Error::other("unsupported ECS state version").into());
            }
            let payload: Vec<u8> = row.get(5)?;
            let clear = self.cipher.open(
                &["ecs", &scope.account, &scope.region, &kind, &name],
                &payload,
            )?;
            if clear.len() > MAX_BODY {
                return Err(std::io::Error::other("ECS persisted entity is too large").into());
            }
            match kind.as_str() {
                "0cluster" => {
                    valid_name(&name)
                        .map_err(|_| std::io::Error::other("invalid ECS cluster state"))?;
                    state
                        .clusters
                        .insert((scope, name), serde_json::from_slice(&clear)?);
                }
                "1definition" => {
                    let value: Value = serde_json::from_slice(&clear)?;
                    let family = value["family"]
                        .as_str()
                        .ok_or_else(|| std::io::Error::other("invalid ECS task definition state"))?
                        .to_owned();
                    let definitions = state
                        .definitions
                        .entry((scope.clone(), family.clone()))
                        .or_default();
                    let revision = definitions.len() + 1;
                    if value["taskDefinitionArn"] != scope.task_arn(&family, revision)
                        || name != format!("{family}:{revision}")
                        || value["revision"] != revision
                    {
                        return Err(std::io::Error::other("invalid ECS definition revision").into());
                    }
                    definitions.push(value);
                }
                "2service" => {
                    let mut service: ServiceRecord = serde_json::from_slice(&clear)?;
                    if service.status == "PROVISIONING" {
                        service.status = "DRAINING".into();
                        service.desired = 0;
                    }
                    if !matches!(service.status.as_str(), "ACTIVE" | "DRAINING") {
                        return Err(std::io::Error::other("invalid ECS service status").into());
                    }
                    if state.services.len() >= 64
                        || name != format!("{}/{}", service.cluster, service.name)
                        || service.desired > 2
                        || !service.tasks.is_empty()
                        || !state
                            .clusters
                            .contains_key(&(scope.clone(), service.cluster.clone()))
                    {
                        return Err(std::io::Error::other("invalid ECS service state").into());
                    }
                    state.services.insert(
                        (scope, service.cluster.clone(), service.name.clone()),
                        service,
                    );
                }
                "3token" => {
                    let (fingerprint, arn, record): (String, String, TaskRecord) =
                        serde_json::from_slice(&clear)?;
                    if record.status != "STOPPED"
                        || record.network.is_some()
                        || !arn.starts_with(&format!(
                            "arn:aws:ecs:{}:{}:task/",
                            scope.region, scope.account
                        ))
                    {
                        return Err(
                            std::io::Error::other("invalid interrupted ECS task state").into()
                        );
                    }
                    state.tasks.insert((scope.clone(), arn.clone()), record);
                    state.task_tokens.insert((scope, name), (fingerprint, arn));
                }
                _ => return Err(std::io::Error::other("unsupported ECS entity kind").into()),
            }
        }
        Ok(state)
    }
}
