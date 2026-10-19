//! Per-resource encrypted ALB configuration. All methods run on a blocking worker.
use crate::*;
use locallycloud_state::{StateCipher, StateDb};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub type PersistError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Serialize, Deserialize)]
pub(crate) struct SavedGroup {
    pub arn: String,
    pub name: String,
    pub vpc_id: String,
    pub port: u16,
    pub target_type: String,
    pub health: HealthSettings,
    pub delay: u64,
    pub targets: Vec<(Ipv4Addr, u16)>,
}
impl SavedGroup {
    pub fn from_group(group: &TargetGroup) -> Self {
        Self {
            arn: group.arn.clone(),
            name: group.name.clone(),
            vpc_id: group.vpc_id.clone(),
            port: group.port,
            target_type: group.target_type.clone(),
            health: group.health.clone(),
            delay: group.deregistration_delay,
            targets: group
                .targets
                .values()
                .filter(|t| t.draining_until.is_none())
                .map(|t| (t.ip, t.port))
                .collect(),
        }
    }
}
#[derive(Serialize, Deserialize)]
pub(crate) struct SavedListener {
    pub arn: String,
    pub port: u16,
    pub target_group_arn: String,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct SavedAlb {
    pub arn: String,
    pub name: String,
    pub subnets: Vec<String>,
    pub groups: Vec<String>,
    pub bind_ip: Ipv4Addr,
    pub listeners: Vec<SavedListener>,
}
impl SavedAlb {
    pub fn from_alb(alb: &LoadBalancer) -> Self {
        Self {
            arn: alb.arn.clone(),
            name: alb.name.clone(),
            subnets: alb
                .network
                .subnets
                .iter()
                .map(|(id, _)| id.clone())
                .collect(),
            groups: alb.network.security_groups.clone(),
            bind_ip: alb.endpoint.bind_ip,
            listeners: alb
                .listeners
                .values()
                .map(|l| SavedListener {
                    arn: l.arn.clone(),
                    port: l.port,
                    target_group_arn: l.target_group_arn.clone(),
                })
                .collect(),
        }
    }
}

pub(crate) struct Persistence {
    db: Arc<StateDb>,
    cipher: StateCipher,
}
impl Persistence {
    pub fn new(db: Arc<StateDb>, cipher: StateCipher) -> Result<Self, PersistError> {
        db.connection()?.execute_batch("CREATE TABLE IF NOT EXISTS elbv2_resources(account TEXT NOT NULL,region TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,version INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(account,region,kind,name));")?;
        Ok(Self { db, cipher })
    }
    pub fn save<T: Serialize>(
        &self,
        scope: &Scope,
        kind: &str,
        name: &str,
        value: &T,
    ) -> Result<(), Error> {
        let bytes = serde_json::to_vec(value).map_err(|_| Error::internal())?;
        if bytes.len() > 256 * 1024 {
            return Err(Error::invalid(
                "Local ALB resource configuration limit exceeded",
            ));
        }
        let payload = self
            .cipher
            .seal(&["elbv2", &scope.0, &scope.1, kind, name], &bytes)
            .map_err(|_| Error::internal())?;
        self.db.connection().map_err(|_|Error::internal())?.execute("INSERT INTO elbv2_resources(account,region,kind,name,version,payload) VALUES (?1,?2,?3,?4,1,?5) ON CONFLICT(account,region,kind,name) DO UPDATE SET payload=excluded.payload",params![scope.0,scope.1,kind,name,payload]).map_err(|_|Error::internal())?;
        Ok(())
    }
    pub fn delete(&self, scope: &Scope, kind: &str, name: &str) -> Result<(), Error> {
        self.db.connection().map_err(|_|Error::internal())?.execute("DELETE FROM elbv2_resources WHERE account=?1 AND region=?2 AND kind=?3 AND name=?4",params![scope.0,scope.1,kind,name]).map_err(|_|Error::internal())?;
        Ok(())
    }
    pub fn restore(&self, handler: &Elbv2Handler) -> Result<(), PersistError> {
        let connection = self.db.connection()?;
        for kind in ["group", "alb"] {
            let mut query = connection.prepare("SELECT account,region,name,version,payload,length(payload) FROM elbv2_resources WHERE kind=?1 ORDER BY account,region,name")?;
            let mut rows = query.query([kind])?;
            while let Some(row) = rows.next()? {
                let scope = (row.get::<_, String>(0)?, row.get::<_, String>(1)?);
                let name: String = row.get(2)?;
                if row.get::<_, i64>(3)? != 1 || row.get::<_, i64>(5)? > 256 * 1024 + 64 {
                    return Err("invalid ALB state record".into());
                }
                let bytes: Vec<u8> = row.get(4)?;
                let clear = self
                    .cipher
                    .open(&["elbv2", &scope.0, &scope.1, kind, &name], &bytes)?;
                match kind {
                    "group" => {
                        handler.restore_group(&scope, &name, serde_json::from_slice(&clear)?)?
                    }
                    "alb" => handler.restore_alb(&scope, &name, serde_json::from_slice(&clear)?)?,
                    _ => return Err("invalid ALB state kind".into()),
                }
            }
        }
        Ok(())
    }
}
