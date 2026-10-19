//! Incremental EC2 topology. Persist proposed entities while the scope mutex is held.
use super::*;
use rusqlite::params;

pub type Ec2StateError = Box<dyn std::error::Error + Send + Sync>;
const MAX_RECORD: usize = 8 * 1024 * 1024;

pub(super) struct Change {
    kind: &'static str,
    id: String,
    payload: Option<Vec<u8>>,
}
impl Change {
    pub(super) fn put(
        kind: &'static str,
        id: &str,
        value: &impl serde::Serialize,
    ) -> Result<Self, Ec2Error> {
        let payload = serde_json::to_vec(value).map_err(|_| unavailable())?;
        if payload.len() > MAX_RECORD {
            return Err(Ec2Error::new(
                "ResourceLimitExceeded",
                "EC2 topology entity exceeds local persistence limit",
            ));
        }
        Ok(Self {
            kind,
            id: id.into(),
            payload: Some(payload),
        })
    }
    pub(super) fn delete(kind: &'static str, id: &str) -> Self {
        Self {
            kind,
            id: id.into(),
            payload: None,
        }
    }
}

pub(super) struct Persistence {
    database: Arc<StateDb>,
    cipher: StateCipher,
}
fn unavailable() -> Ec2Error {
    Ec2Error::new(
        "InternalError",
        "EC2 persistence unavailable; topology was not changed",
    )
}
fn invalid() -> Ec2StateError {
    std::io::Error::other("invalid persisted EC2 topology").into()
}
impl Persistence {
    pub(super) fn new(database: Arc<StateDb>, cipher: StateCipher) -> Result<Self, Ec2StateError> {
        database.connection()?.execute_batch("CREATE TABLE IF NOT EXISTS ec2_records(account TEXT NOT NULL,region TEXT NOT NULL,kind TEXT NOT NULL,id TEXT NOT NULL,version INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(account,region,kind,id));")?;
        Ok(Self { database, cipher })
    }
    fn save(&self, key: &(String, String), changes: &[Change]) -> Result<(), Ec2StateError> {
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction()?;
        for change in changes {
            match &change.payload {
                Some(clear) => {
                    let payload = self
                        .cipher
                        .seal(&["ec2", &key.0, &key.1, change.kind, &change.id], clear)?;
                    transaction.execute("INSERT INTO ec2_records(account,region,kind,id,version,payload) VALUES (?1,?2,?3,?4,1,?5) ON CONFLICT(account,region,kind,id) DO UPDATE SET payload=excluded.payload",params![key.0,key.1,change.kind,change.id,payload])?;
                }
                None => {
                    transaction.execute("DELETE FROM ec2_records WHERE account=?1 AND region=?2 AND kind=?3 AND id=?4",params![key.0,key.1,change.kind,change.id])?;
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }
    pub(super) fn restore(&self, handler: &Ec2Handler) -> Result<(), Ec2StateError> {
        let connection = self.database.connection()?;
        let mut statement=connection.prepare("SELECT account,region,kind,id,version,CASE WHEN length(payload)<=?1 THEN payload ELSE NULL END FROM ec2_records")?;
        let mut rows = statement.query([i64::try_from(MAX_RECORD + 64)?])?;
        let mut state = handler.scopes.lock().map_err(|_| invalid())?;
        while let Some(row) = rows.next()? {
            let account: String = row.get(0)?;
            let region: String = row.get(1)?;
            let kind: String = row.get(2)?;
            let id: String = row.get(3)?;
            let version: u32 = row.get(4)?;
            let payload: Vec<u8> = row.get(5)?;
            if version != 1 || id.is_empty() {
                return Err(invalid());
            }
            let clear = self
                .cipher
                .open(&["ec2", &account, &region, &kind, &id], &payload)?;
            let scope = state.entry((account, region)).or_default();
            macro_rules! restore {
                ($ty:ty,$field:ident) => {{
                    let value: $ty = serde_json::from_slice(&clear)?;
                    if value.id != id {
                        return Err(invalid());
                    }
                    scope.$field.insert(id, value);
                }};
            }
            match kind.as_str() {
                "vpc" => {
                    let value: Vpc = serde_json::from_slice(&clear)?;
                    if value.id != id {
                        return Err(invalid());
                    }
                    scope.vpcs.insert(id, Arc::new(value));
                }
                "dns" => {
                    scope.vpc_dns.insert(id, serde_json::from_slice(&clear)?);
                }
                "subnet" => restore!(Subnet, subnets),
                "sg" => restore!(SecurityGroup, security_groups),
                "eni" => restore!(NetworkInterface, network_interfaces),
                "route-table" => restore!(RouteTable, route_tables),
                "igw" => restore!(InternetGateway, internet_gateways),
                "eip" => {
                    let value: ElasticIp = serde_json::from_slice(&clear)?;
                    if value.allocation_id != id {
                        return Err(invalid());
                    }
                    scope.elastic_ips.insert(id, value);
                }
                "nat" => restore!(NatGateway, nat_gateways),
                "endpoint" => restore!(VpcEndpoint, vpc_endpoints),
                "eni-token" => {
                    scope.eni_tokens.insert(id, serde_json::from_slice(&clear)?);
                }
                "route-token" => {
                    scope
                        .route_table_tokens
                        .insert(id, serde_json::from_slice(&clear)?);
                }
                "nat-token" => {
                    scope
                        .nat_gateway_tokens
                        .insert(id, serde_json::from_slice(&clear)?);
                }
                "endpoint-token" => {
                    scope
                        .vpc_endpoint_tokens
                        .insert(id, serde_json::from_slice(&clear)?);
                }
                "instance-token" => {
                    scope
                        .instance_tokens
                        .insert(id, serde_json::from_slice(&clear)?);
                }
                "instance" => {
                    let mut value: Instance = serde_json::from_slice(&clear)?;
                    if value.spec.instance_id != id {
                        return Err(invalid());
                    }
                    if value.state != InstanceState::Terminated {
                        value.state = InstanceState::Stopped;
                    }
                    value.endpoint = None;
                    scope.instances.insert(id, value);
                }
                _ => return Err(invalid()),
            }
        }
        // No runtime ENI/socket/PID is restored. Dependencies come from current topology.
        for scope in state.values() {
            if scope.subnets.values().any(|value|!scope.vpcs.contains_key(&value.vpc_id))
                || scope.security_groups.values().any(|value|!scope.vpcs.contains_key(&value.vpc_id))
                || scope.route_tables.values().any(|value|!scope.vpcs.contains_key(&value.vpc_id))
                || scope.network_interfaces.values().any(|eni| !scope.subnets.get(&eni.subnet_id).is_some_and(|subnet|subnet.vpc_id==eni.vpc_id) || eni.group_ids.iter().any(|id|!scope.security_groups.get(id).is_some_and(|group|group.vpc_id==eni.vpc_id)))
                || scope.security_groups.values().any(|group|group.ingress.iter().chain(&group.egress).any(|rule|matches!(&rule.peer,RulePeer::Group(id) if !scope.security_groups.get(id).is_some_and(|peer|peer.vpc_id==group.vpc_id)))) {return Err(invalid());}
        }
        Ok(())
    }
}
impl Ec2Handler {
    pub(super) fn persist(
        &self,
        key: &(String, String),
        changes: &[Change],
    ) -> Result<(), Ec2Error> {
        if let Some(persistence) = &self.persistence {
            persistence.save(key, changes).map_err(|_| unavailable())?;
        }
        Ok(())
    }
}

pub async fn register_with_state_and_instance_runtime(
    registry: &Arc<ServiceRegistry>,
    database: Arc<StateDb>,
    runtime: Arc<dyn InstanceRuntime>,
) -> Result<Arc<Ec2Handler>, Ec2StateError> {
    let registry_weak = Arc::downgrade(registry);
    let handler = tokio::task::spawn_blocking(move || {
        let persistence = Arc::new(Persistence::new(database, StateCipher::from_env()?)?);
        let mut handler = Ec2Handler::with_instance_runtime(runtime);
        handler.persistence = Some(persistence.clone());
        handler.registry = Some(registry_weak);
        persistence.restore(&handler)?;
        Ok::<_, Ec2StateError>(Arc::new(handler))
    })
    .await
    .map_err(|error| -> Ec2StateError { Box::new(error) })??;
    Ok(register_handler(registry, handler))
}
