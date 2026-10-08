use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_ec2::{Ec2Handler, TaskNetworkLease};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::sync::Mutex;

use crate::runtime::{self, PostgresRuntime};

const XMLNS: &str = "http://rds.amazonaws.com/doc/2014-10-31/";
type Key = (String, String, String);

struct PasswordFile(PathBuf);
impl Drop for PasswordFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Instance {
    id: String,
    account: String,
    region: String,
    username: String,
    db_name: String,
    class: String,
    storage: u32,
    port: u16,
    status: String,
    error: Option<String>,
    #[serde(default)]
    replica_source: Option<String>,
    #[serde(default)]
    cluster_id: Option<String>,
    #[serde(default)]
    vpc: Option<VpcAttachment>,
    #[serde(default)]
    socket_token: String,
    #[serde(default)]
    dbi_resource_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct VpcAttachment {
    subnet_group: String,
    subnet_id: String,
    security_group_ids: Vec<String>,
    private_ip: Ipv4Addr,
    client_port: u16,
}

#[derive(Clone, Serialize, Deserialize)]
struct DbSubnetGroup {
    name: String,
    description: String,
    account: String,
    region: String,
    vpc_id: String,
    subnets: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct RdsInstanceEndpoint {
    pub account: String,
    pub region: String,
    pub id: String,
    pub db_name: String,
    pub username: String,
    pub socket_dir: PathBuf,
    pub port: u16,
}

#[derive(Clone, Serialize, Deserialize)]
struct Cluster {
    id: String,
    account: String,
    region: String,
    username: String,
    db_name: String,
    writer_id: Option<String>,
    #[serde(default)]
    last_writer_port: Option<u16>,
    http_endpoint_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct RdsClusterEndpoint {
    pub socket_dir: PathBuf,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub http_endpoint_enabled: bool,
    pub status: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Snapshot {
    id: String,
    source: Instance,
    status: String,
    #[serde(default)]
    error: Option<String>,
}

pub struct RdsHandler {
    root: PathBuf,
    instances: Arc<Mutex<HashMap<Key, Instance>>>,
    snapshots: Arc<Mutex<HashMap<Key, Snapshot>>>,
    clusters: Arc<Mutex<HashMap<Key, Cluster>>>,
    subnet_groups: Mutex<HashMap<Key, DbSubnetGroup>>,
    network_leases: Arc<Mutex<HashMap<Key, TaskNetworkLease>>>,
    ec2: RwLock<Option<Arc<Ec2Handler>>>,
    jobs: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl RdsHandler {
    pub async fn instance_by_arn(&self, arn: &str) -> Option<RdsInstanceEndpoint> {
        let (prefix, id) = arn.rsplit_once(":db:")?;
        let mut parts = prefix.split(':');
        if parts.next()? != "arn" || parts.next()? != "aws" || parts.next()? != "rds" {
            return None;
        }
        let region = parts.next()?;
        let account = parts.next()?;
        if parts.next().is_some() || id.is_empty() {
            return None;
        }
        let instance = self
            .instances
            .lock()
            .await
            .get(&(account.to_owned(), region.to_owned(), id.to_owned()))?
            .clone();
        if instance.status != "available" || instance.replica_source.is_some() {
            return None;
        }
        Some(RdsInstanceEndpoint {
            account: instance.account.clone(),
            region: instance.region.clone(),
            id: instance.id.clone(),
            db_name: instance.db_name.clone(),
            username: instance.username.clone(),
            socket_dir: socket_dir(&instance),
            port: instance.port,
        })
    }

    pub fn new(root: PathBuf) -> Self {
        let mut instances = HashMap::new();
        let mut snapshots = HashMap::new();
        let mut clusters = HashMap::new();
        if let Ok(accounts) = std::fs::read_dir(&root) {
            for account in accounts.flatten() {
                if let Ok(regions) = std::fs::read_dir(account.path()) {
                    for region in regions.flatten() {
                        if let Ok(entries) = std::fs::read_dir(region.path().join("instances")) {
                            for entry in entries.flatten() {
                                let metadata = entry.path().join("meta.json");
                                if let Ok(bytes) = std::fs::read(metadata) {
                                    if let Ok(mut instance) =
                                        serde_json::from_slice::<Instance>(&bytes)
                                    {
                                        if instance.cluster_id.is_some()
                                            && !entry.path().join("data").exists()
                                        {
                                            instance.status = "failed".to_owned();
                                            instance.error = Some("Aurora writer data is retained by cluster or missing".to_owned());
                                            if let Ok(serialized) = serde_json::to_vec(&instance) {
                                                let _ = std::fs::write(
                                                    entry.path().join("meta.json"),
                                                    serialized,
                                                );
                                            }
                                        } else if instance.status == "available"
                                            || instance.status == "backing-up"
                                        {
                                            instance.status = "restarting".to_owned();
                                        } else if instance.status == "creating"
                                            || instance.status == "restoring"
                                            || instance.status == "modifying"
                                            || instance.status == "deleting"
                                        {
                                            let _ =
                                                std::fs::remove_file(entry.path().join("password"));
                                            instance.status = "failed".to_owned();
                                            instance.error = Some(
                                                "Operation interrupted by server restart"
                                                    .to_owned(),
                                            );
                                            if let Ok(serialized) = serde_json::to_vec(&instance) {
                                                let _ = std::fs::write(
                                                    entry.path().join("meta.json"),
                                                    serialized,
                                                );
                                            }
                                        }
                                        if !valid_socket_token(&instance.socket_token)
                                            || instance.dbi_resource_id.is_empty()
                                        {
                                            if !valid_socket_token(&instance.socket_token) {
                                                instance.socket_token = new_socket_token();
                                            }
                                            if instance.dbi_resource_id.is_empty() {
                                                instance.dbi_resource_id = new_dbi_resource_id();
                                            }
                                            if let Ok(serialized) = serde_json::to_vec(&instance) {
                                                let _ = std::fs::write(
                                                    entry.path().join("meta.json"),
                                                    serialized,
                                                );
                                            }
                                        }
                                        instances.insert(
                                            (
                                                instance.account.clone(),
                                                instance.region.clone(),
                                                instance.id.clone(),
                                            ),
                                            instance,
                                        );
                                    }
                                }
                            }
                        }
                        if let Ok(entries) = std::fs::read_dir(region.path().join("clusters")) {
                            for entry in entries.flatten() {
                                if let Ok(bytes) = std::fs::read(entry.path().join("cluster.json"))
                                {
                                    if let Ok(cluster) = serde_json::from_slice::<Cluster>(&bytes) {
                                        clusters.insert(
                                            (
                                                cluster.account.clone(),
                                                cluster.region.clone(),
                                                cluster.id.clone(),
                                            ),
                                            cluster,
                                        );
                                    }
                                }
                            }
                        }
                        if let Ok(entries) = std::fs::read_dir(region.path().join("snapshots")) {
                            for entry in entries.flatten() {
                                if let Ok(bytes) = std::fs::read(entry.path().join("snapshot.json"))
                                {
                                    if let Ok(mut snapshot) =
                                        serde_json::from_slice::<Snapshot>(&bytes)
                                    {
                                        if snapshot.status == "creating" {
                                            snapshot.status = "failed".to_owned();
                                            snapshot.error = Some(
                                                "Snapshot interrupted by server restart".to_owned(),
                                            );
                                            if let Ok(serialized) = serde_json::to_vec(&snapshot) {
                                                let _ = std::fs::write(
                                                    entry.path().join("snapshot.json"),
                                                    serialized,
                                                );
                                            }
                                            if let Ok(partials) = std::fs::read_dir(entry.path()) {
                                                for partial in partials.flatten() {
                                                    if partial
                                                        .file_name()
                                                        .to_string_lossy()
                                                        .starts_with("data.tmp-")
                                                    {
                                                        let _ =
                                                            std::fs::remove_dir_all(partial.path());
                                                    }
                                                }
                                            }
                                        }
                                        snapshots.insert(
                                            (
                                                snapshot.source.account.clone(),
                                                snapshot.source.region.clone(),
                                                snapshot.id.clone(),
                                            ),
                                            snapshot,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        for cluster in clusters.values_mut() {
            if let Some(writer_id) = &cluster.writer_id {
                let writer = instances.get(&(
                    cluster.account.clone(),
                    cluster.region.clone(),
                    writer_id.clone(),
                ));
                let cluster_dir = root
                    .join(&cluster.account)
                    .join(&cluster.region)
                    .join("clusters")
                    .join(&cluster.id);
                if writer.is_some_and(|writer| {
                    writer.status == "restarting" || writer.status == "available"
                }) {
                    let _ = std::fs::remove_file(cluster_dir.join("master-password"));
                } else if writer.is_none() {
                    cluster.writer_id = None;
                    if let Ok(bytes) = serde_json::to_vec(cluster) {
                        let temp = cluster_dir.join("cluster.json.tmp");
                        if std::fs::write(&temp, bytes).is_ok() {
                            let _ = std::fs::rename(temp, cluster_dir.join("cluster.json"));
                        }
                    }
                }
            }
        }
        let subnet_groups = load_subnet_groups(&root);
        Self {
            root,
            instances: Arc::new(Mutex::new(instances)),
            snapshots: Arc::new(Mutex::new(snapshots)),
            clusters: Arc::new(Mutex::new(clusters)),
            subnet_groups: Mutex::new(subnet_groups),
            network_leases: Arc::new(Mutex::new(HashMap::new())),
            ec2: RwLock::new(None),
            jobs: Mutex::new(Vec::new()),
        }
    }

    pub async fn attach_ec2(&self, ec2: Arc<Ec2Handler>) {
        *self.ec2.write().expect("RDS EC2 lock") = Some(ec2.clone());
        let instances: Vec<_> = self.instances.lock().await.values().cloned().collect();
        for mut instance in instances {
            let Some(vpc) = instance.vpc.as_mut() else {
                continue;
            };
            let Some(lease) = ec2.reserve_task_network(
                &instance.account,
                &instance.region,
                &vpc.subnet_id,
                &vpc.security_group_ids,
                &instance.id,
            ) else {
                continue;
            };
            vpc.private_ip = lease.private_ip;
            let _ = lease.set_dns_name(&rds_hostname(&instance));
            let key = (
                instance.account.clone(),
                instance.region.clone(),
                instance.id.clone(),
            );
            if persist(&self.directory(&instance), &instance).await.is_ok() {
                self.instances.lock().await.insert(key.clone(), instance);
                self.network_leases.lock().await.insert(key, lease);
            }
        }
    }

    fn ec2(&self) -> Result<Arc<Ec2Handler>, Error> {
        self.ec2
            .read()
            .expect("RDS EC2 lock")
            .clone()
            .ok_or_else(|| Error::internal("EC2 VPC service unavailable"))
    }

    async fn create_subnet_group(
        &self,
        req: &ServiceRequest,
        input: &Input,
    ) -> Result<String, Error> {
        let name = input.required("DBSubnetGroupName")?;
        validate_id(name)?;
        let description = input.required("DBSubnetGroupDescription")?;
        let subnet_ids = input.rds_members("SubnetIds", "SubnetIdentifier");
        if subnet_ids.len() < 2 {
            return Err(Error::invalid(
                "DB subnet group requires subnets in at least two Availability Zones",
            ));
        }
        let ec2 = self.ec2()?;
        let mut vpc_id = None;
        let mut subnets = Vec::new();
        for subnet_id in subnet_ids {
            let (subnet_vpc, zone, _) = ec2
                .subnet_description(&req.account_id, &req.region, &subnet_id)
                .ok_or_else(|| {
                    Error::new(
                        "DBSubnetGroupDoesNotCoverEnoughAZs",
                        "Subnet not found",
                        400,
                    )
                })?;
            if vpc_id.as_ref().is_some_and(|id| id != &subnet_vpc)
                || subnets.iter().any(|(id, _)| id == &subnet_id)
            {
                return Err(Error::invalid(
                    "DB subnet group subnets must be unique and in one VPC",
                ));
            }
            vpc_id = Some(subnet_vpc);
            subnets.push((subnet_id, zone));
        }
        if subnets
            .iter()
            .map(|(_, zone)| zone)
            .collect::<std::collections::HashSet<_>>()
            .len()
            < 2
        {
            return Err(Error::new(
                "DBSubnetGroupDoesNotCoverEnoughAZs",
                "DB subnet group requires two Availability Zones",
                400,
            ));
        }
        let group = DbSubnetGroup {
            name: name.to_owned(),
            description: description.to_owned(),
            account: req.account_id.clone(),
            region: req.region.clone(),
            vpc_id: vpc_id.expect("nonempty subnets"),
            subnets,
        };
        let key = (req.account_id.clone(), req.region.clone(), name.to_owned());
        let mut groups = self.subnet_groups.lock().await;
        if groups.contains_key(&key) {
            return Err(Error::new(
                "DBSubnetGroupAlreadyExists",
                "DB subnet group already exists",
                400,
            ));
        }
        persist_subnet_group(&self.root, &group)
            .await
            .map_err(Error::internal)?;
        let xml = subnet_group_xml(&group);
        groups.insert(key, group);
        Ok(format!("<DBSubnetGroup>{xml}</DBSubnetGroup>"))
    }

    async fn describe_subnet_groups(
        &self,
        req: &ServiceRequest,
        input: &Input,
    ) -> Result<String, Error> {
        let wanted = input.get("DBSubnetGroupName");
        let groups = self.subnet_groups.lock().await;
        let selected: Vec<_> = groups
            .values()
            .filter(|group| {
                group.account == req.account_id
                    && group.region == req.region
                    && wanted.is_none_or(|name| name == group.name)
            })
            .collect();
        if selected.is_empty() && wanted.is_some() {
            return Err(Error::new(
                "DBSubnetGroupNotFoundFault",
                "DB subnet group not found",
                404,
            ));
        }
        let mut xml = String::from("<DBSubnetGroups>");
        for group in selected {
            xml.push_str(&format!(
                "<DBSubnetGroup>{}</DBSubnetGroup>",
                subnet_group_xml(group)
            ));
        }
        xml.push_str("</DBSubnetGroups>");
        Ok(xml)
    }

    async fn delete_subnet_group(
        &self,
        req: &ServiceRequest,
        input: &Input,
    ) -> Result<String, Error> {
        let name = input.required("DBSubnetGroupName")?;
        let key = (req.account_id.clone(), req.region.clone(), name.to_owned());
        if self.instances.lock().await.values().any(|instance| {
            instance.account == req.account_id
                && instance.region == req.region
                && instance
                    .vpc
                    .as_ref()
                    .is_some_and(|vpc| vpc.subnet_group == name)
        }) {
            return Err(Error::new(
                "InvalidDBSubnetGroupStateFault",
                "DB subnet group is in use",
                400,
            ));
        }
        let mut groups = self.subnet_groups.lock().await;
        let group = groups.get(&key).ok_or_else(|| {
            Error::new(
                "DBSubnetGroupNotFoundFault",
                "DB subnet group not found",
                404,
            )
        })?;
        tokio::fs::remove_file(subnet_group_path(&self.root, group))
            .await
            .map_err(|error| Error::internal(error.to_string()))?;
        groups.remove(&key);
        Ok(String::new())
    }

    async fn list_tags(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let arn = input.required("ResourceName")?;
        let prefix = format!("arn:aws:rds:{}:{}:", req.region, req.account_id);
        let resource = arn.strip_prefix(&prefix).ok_or_else(|| {
            Error::invalid("ResourceName must be an RDS ARN in the request account and Region")
        })?;
        if let Some(name) = resource.strip_prefix("subgrp:") {
            let key = (req.account_id.clone(), req.region.clone(), name.to_owned());
            if !self.subnet_groups.lock().await.contains_key(&key) {
                return Err(Error::new(
                    "DBSubnetGroupNotFoundFault",
                    "DB subnet group not found",
                    404,
                ));
            }
        } else if let Some(name) = resource.strip_prefix("db:") {
            let key = (req.account_id.clone(), req.region.clone(), name.to_owned());
            if !self.instances.lock().await.contains_key(&key) {
                return Err(Error::new(
                    "DBInstanceNotFound",
                    "DB instance not found",
                    404,
                ));
            }
        } else {
            return Err(Error::invalid(
                "ResourceName must identify a DB instance or DB subnet group",
            ));
        }
        Ok("<TagList/>".to_owned())
    }

    fn directory(&self, instance: &Instance) -> PathBuf {
        self.root
            .join(&instance.account)
            .join(&instance.region)
            .join("instances")
            .join(&instance.id)
    }

    fn cluster_directory(&self, cluster: &Cluster) -> PathBuf {
        self.root
            .join(&cluster.account)
            .join(&cluster.region)
            .join("clusters")
            .join(&cluster.id)
    }

    pub async fn resolve_cluster(
        &self,
        account: &str,
        region: &str,
        resource_arn: &str,
    ) -> Option<RdsClusterEndpoint> {
        let id = resource_arn.strip_prefix(&format!("arn:aws:rds:{region}:{account}:cluster:"))?;
        let key = (account.to_owned(), region.to_owned(), id.to_owned());
        let cluster = self.clusters.lock().await.get(&key).cloned()?;
        let writer_id = cluster.writer_id?;
        let writer_key = (account.to_owned(), region.to_owned(), writer_id);
        let writer = self.refresh_instance(&writer_key, false).await?;
        let status = writer.status.clone();
        Some(RdsClusterEndpoint {
            socket_dir: socket_dir(&writer),
            port: writer.port,
            database: cluster.db_name,
            username: cluster.username,
            http_endpoint_enabled: cluster.http_endpoint_enabled,
            status,
        })
    }

    fn snapshot_directory(&self, snapshot: &Snapshot) -> PathBuf {
        self.root
            .join(&snapshot.source.account)
            .join(&snapshot.source.region)
            .join("snapshots")
            .join(&snapshot.id)
    }

    async fn create_cluster(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let id = input.required("DBClusterIdentifier")?;
        validate_id(id)?;
        if input.required("Engine")? != "aurora-postgresql" {
            return Err(Error::invalid(
                "Only Engine=aurora-postgresql is supported for DB clusters",
            ));
        }
        for field in [
            "DBSubnetGroupName",
            "VpcSecurityGroupIds.member.1",
            "KmsKeyId",
            "GlobalClusterIdentifier",
            "ReplicationSourceIdentifier",
            "ServerlessV2ScalingConfiguration.MinCapacity",
            "EngineVersion",
            "ManageMasterUserPassword",
        ] {
            if input.get(field).is_some() {
                return Err(Error::invalid(format!("{field} is unsupported")));
            }
        }
        if input.get("StorageEncrypted") == Some("true") {
            return Err(Error::invalid("StorageEncrypted is unsupported"));
        }
        validate_scope(&req.account_id, &req.region)?;
        let username = input.required("MasterUsername")?;
        validate_user(username)?;
        let password = input.required("MasterUserPassword")?;
        if password.is_empty() || password.contains(['\n', '\r']) {
            return Err(Error::invalid("Invalid MasterUserPassword"));
        }
        let db_name = input.get("DatabaseName").unwrap_or("postgres");
        validate_user(db_name)?;
        let cluster = Cluster {
            id: id.to_owned(),
            account: req.account_id.clone(),
            region: req.region.clone(),
            username: username.to_owned(),
            db_name: db_name.to_owned(),
            writer_id: None,
            last_writer_port: None,
            http_endpoint_enabled: input.get("EnableHttpEndpoint") == Some("true"),
        };
        let key = (
            cluster.account.clone(),
            cluster.region.clone(),
            cluster.id.clone(),
        );
        let directory = self.cluster_directory(&cluster);
        let mut clusters = self.clusters.lock().await;
        if clusters.contains_key(&key) {
            return Err(Error::new(
                "DBClusterAlreadyExistsFault",
                "DB cluster already exists",
                400,
            ));
        }
        tokio::fs::create_dir_all(&directory)
            .await
            .map_err(|e| Error::internal(e.to_string()))?;
        let secret_path = directory.join("master-password");
        use tokio::io::AsyncWriteExt;
        let written = async {
            let mut secret = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&secret_path)
                .await
                .map_err(|e| e.to_string())?;
            secret
                .write_all(password.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            persist_cluster(&directory, &cluster).await
        }
        .await;
        if let Err(error) = written {
            let _ = tokio::fs::remove_dir_all(&directory).await;
            return Err(Error::internal(error));
        }
        let response = format!("<DBCluster>{}</DBCluster>", cluster_xml(&cluster, None));
        clusters.insert(key, cluster);
        Ok(response)
    }

    async fn delete_cluster(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let id = input.required("DBClusterIdentifier")?;
        let key = (req.account_id.clone(), req.region.clone(), id.to_owned());
        let mut clusters = self.clusters.lock().await;
        let cluster = clusters
            .get(&key)
            .cloned()
            .ok_or_else(|| Error::new("DBClusterNotFoundFault", "DB cluster not found", 404))?;
        let member_exists = self.instances.lock().await.values().any(|instance| {
            instance.account == req.account_id
                && instance.region == req.region
                && instance.cluster_id.as_deref() == Some(id)
        });
        if member_exists {
            return Err(Error::new(
                "InvalidDBClusterStateFault",
                "Delete DB instances first",
                400,
            ));
        }
        tokio::fs::remove_dir_all(self.cluster_directory(&cluster))
            .await
            .map_err(|e| Error::internal(e.to_string()))?;
        clusters.remove(&key);
        Ok(format!(
            "<DBCluster>{}</DBCluster>",
            cluster_xml(&cluster, None)
        ))
    }

    async fn describe_clusters(
        &self,
        req: &ServiceRequest,
        input: &Input,
    ) -> Result<String, Error> {
        let wanted = input.get("DBClusterIdentifier");
        let clusters: Vec<Cluster> = self
            .clusters
            .lock()
            .await
            .values()
            .filter(|cluster| {
                cluster.account == req.account_id
                    && cluster.region == req.region
                    && wanted.is_none_or(|id| id == cluster.id)
            })
            .cloned()
            .collect();
        if wanted.is_some() && clusters.is_empty() {
            return Err(Error::new(
                "DBClusterNotFoundFault",
                "DB cluster not found",
                404,
            ));
        }
        let instances = self.instances.lock().await;
        let mut xml = String::from("<DBClusters>");
        for cluster in clusters {
            let writer = cluster.writer_id.as_ref().and_then(|id| {
                instances.get(&(cluster.account.clone(), cluster.region.clone(), id.clone()))
            });
            xml.push_str("<DBCluster>");
            xml.push_str(&cluster_xml(&cluster, writer));
            xml.push_str("</DBCluster>");
        }
        xml.push_str("</DBClusters>");
        Ok(xml)
    }

    async fn create_aurora_writer(
        &self,
        req: &ServiceRequest,
        input: &Input,
    ) -> Result<String, Error> {
        let id = input.required("DBInstanceIdentifier")?;
        validate_id(id)?;
        let cluster_id = input.required("DBClusterIdentifier")?;
        validate_id(cluster_id)?;
        for field in [
            "MasterUsername",
            "MasterUserPassword",
            "DBName",
            "AllocatedStorage",
            "DBSubnetGroupName",
            "VpcSecurityGroupIds.member.1",
            "KmsKeyId",
        ] {
            if input.get(field).is_some() {
                return Err(Error::invalid(format!(
                    "{field} is unsupported for an Aurora instance"
                )));
            }
        }
        let class = match input
            .get("DBInstanceClass")
            .filter(|value| !value.is_empty())
        {
            None => {
                return Err(Error::new(
                    "MissingParameter",
                    "Missing DBInstanceClass",
                    400,
                ))
            }
            Some("db.t3.medium") => "db.t3.medium",
            Some("db.t3.micro") => {
                return Err(Error::invalid(
                    "DBInstanceClass=db.t3.micro is not compatible with Engine=aurora-postgresql",
                ));
            }
            Some(_) => {
                return Err(Error::invalid(
                    "Local implementation supports only DBInstanceClass=db.t3.medium for Aurora PostgreSQL",
                ));
            }
        };
        validate_scope(&req.account_id, &req.region)?;
        let cluster_key = (
            req.account_id.clone(),
            req.region.clone(),
            cluster_id.to_owned(),
        );
        let key = (req.account_id.clone(), req.region.clone(), id.to_owned());
        let runtime = runtime::resolve_from_env()
            .await
            .map_err(|error| Error::internal(error.to_string()))?;
        let mut clusters = self.clusters.lock().await;
        let cluster = clusters
            .get_mut(&cluster_key)
            .ok_or_else(|| Error::new("DBClusterNotFoundFault", "DB cluster not found", 404))?;
        if cluster.writer_id.is_some() {
            return Err(Error::new(
                "InvalidDBClusterStateFault",
                "DB cluster already has a writer",
                400,
            ));
        }
        let cluster_dir = self.cluster_directory(cluster);
        let mut port = free_port().await.map_err(Error::internal)?;
        for _ in 0..8 {
            if Some(port) != cluster.last_writer_port {
                break;
            }
            port = free_port().await.map_err(Error::internal)?;
        }
        if Some(port) == cluster.last_writer_port {
            return Err(Error::internal(
                "Unable to allocate a new Aurora writer port".to_owned(),
            ));
        }
        let retained_data = tokio::fs::try_exists(cluster_dir.join("data"))
            .await
            .map_err(|error| Error::internal(error.to_string()))?;
        let password = if retained_data {
            None
        } else {
            Some(
                tokio::fs::read_to_string(cluster_dir.join("master-password"))
                    .await
                    .map_err(|error| Error::internal(error.to_string()))?,
            )
        };
        let instance = Instance {
            id: id.to_owned(),
            account: req.account_id.clone(),
            region: req.region.clone(),
            username: cluster.username.clone(),
            db_name: cluster.db_name.clone(),
            class: class.to_owned(),
            storage: 20,
            port,
            status: "creating".to_owned(),
            error: None,
            replica_source: None,
            cluster_id: Some(cluster_id.to_owned()),
            vpc: None,
            socket_token: new_socket_token(),
            dbi_resource_id: new_dbi_resource_id(),
        };
        let directory = self.directory(&instance);
        {
            let mut state = self.instances.lock().await;
            if state.contains_key(&key) {
                return Err(Error::new(
                    "DBInstanceAlreadyExists",
                    "DB instance already exists",
                    400,
                ));
            }
            state.insert(key.clone(), instance.clone());
        }
        let prepared = async {
            tokio::fs::create_dir_all(&directory)
                .await
                .map_err(|e| e.to_string())?;
            persist(&directory, &instance).await
        }
        .await;
        if let Err(error) = prepared {
            self.instances.lock().await.remove(&key);
            let _ = tokio::fs::remove_dir_all(&directory).await;
            return Err(Error::internal(error));
        }
        cluster.writer_id = Some(id.to_owned());
        let previous_port = cluster.last_writer_port;
        cluster.last_writer_port = Some(port);
        if let Err(error) = persist_cluster(&cluster_dir, cluster).await {
            cluster.writer_id = None;
            cluster.last_writer_port = previous_port;
            self.instances.lock().await.remove(&key);
            let _ = tokio::fs::remove_dir_all(&directory).await;
            return Err(Error::internal(error));
        }
        drop(clusters);
        let response = format!("<DBInstance>{}</DBInstance>", instance_xml(&instance));
        let state = self.instances.clone();
        let mut jobs = self.jobs.lock().await;
        jobs.retain(|job| !job.is_finished());
        jobs.push(tokio::spawn(async move {
            let result = if retained_data {
                reopen_cluster_writer(&runtime, &cluster_dir, &directory, &instance).await
            } else {
                provision(
                    &runtime,
                    &directory,
                    &instance,
                    password.as_deref().expect("first writer password"),
                )
                .await
            };
            let mut completed = instance;
            match result {
                Ok(()) => {
                    completed.status = "available".to_owned();
                    if let Err(reason) = persist(&directory, &completed).await {
                        stop_instance(&runtime, &directory).await;
                        completed.status = "failed".to_owned();
                        completed.error =
                            Some(format!("Unable to persist instance metadata: {reason}"));
                        let _ = persist(&directory, &completed).await;
                    } else {
                        let _ = tokio::fs::remove_file(cluster_dir.join("master-password")).await;
                    }
                }
                Err(reason) => {
                    stop_instance(&runtime, &directory).await;
                    completed.status = "failed".to_owned();
                    completed.error = Some(reason);
                    let _ = persist(&directory, &completed).await;
                }
            }
            state.lock().await.insert(key, completed);
        }));
        Ok(response)
    }

    async fn create(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let id = input.required("DBInstanceIdentifier")?;
        validate_id(id)?;
        let engine = input.required("Engine")?;
        if engine == "aurora-postgresql" {
            return self.create_aurora_writer(req, input).await;
        }
        if engine != "postgres" {
            return Err(Error::invalid("Only Engine=postgres is supported"));
        }
        for field in ["KmsKeyId", "DBClusterIdentifier"] {
            if input.get(field).is_some() {
                return Err(Error::invalid(format!("{field} is unsupported")));
            }
        }
        if input.get("StorageEncrypted") == Some("true")
            || input.get("EnableIAMDatabaseAuthentication") == Some("true")
            || input.get("MultiAZ") == Some("true")
        {
            return Err(Error::invalid(
                "Encryption, IAM database authentication and MultiAZ are unsupported",
            ));
        }
        let username = input.required("MasterUsername")?;
        validate_user(username)?;
        let password = input.required("MasterUserPassword")?;
        if password.contains(['\n', '\r']) {
            return Err(Error::invalid("MasterUserPassword contains a newline"));
        }
        if password.is_empty() {
            return Err(Error::invalid("MasterUserPassword is empty"));
        }
        let db_name = input.get("DBName").unwrap_or("postgres");
        validate_user(db_name)?;
        let class = input.get("DBInstanceClass").unwrap_or("db.t3.micro");
        if class != "db.t3.micro" {
            return Err(Error::invalid("Only db.t3.micro is supported"));
        }
        let storage = input
            .get("AllocatedStorage")
            .unwrap_or("20")
            .parse::<u32>()
            .map_err(|_| Error::invalid("AllocatedStorage must be an integer"))?;
        if !(20..=100).contains(&storage) {
            return Err(Error::invalid("AllocatedStorage must be 20..100 GiB"));
        }
        if input.get("PubliclyAccessible") == Some("true") {
            return Err(Error::invalid(
                "PubliclyAccessible=true is unsupported for private RDS",
            ));
        }
        let client_port = input
            .get("Port")
            .unwrap_or("5432")
            .parse::<u16>()
            .map_err(|_| Error::invalid("Port must be 1..65535"))?;
        if client_port == 0 {
            return Err(Error::invalid("Port must be 1..65535"));
        }
        let mut lease = None;
        let mut vpc = None;
        if let Some(group_name) = input.get("DBSubnetGroupName") {
            let group_key = (
                req.account_id.clone(),
                req.region.clone(),
                group_name.to_owned(),
            );
            let group = self
                .subnet_groups
                .lock()
                .await
                .get(&group_key)
                .cloned()
                .ok_or_else(|| {
                    Error::new(
                        "DBSubnetGroupNotFoundFault",
                        "DB subnet group not found",
                        404,
                    )
                })?;
            let ec2 = self.ec2()?;
            let security_group_ids = input.rds_members("VpcSecurityGroupIds", "VpcSecurityGroupId");
            let security_group_ids = if security_group_ids.is_empty() {
                vec![ec2
                    .default_security_group_id(&req.account_id, &req.region, &group.vpc_id)
                    .ok_or_else(|| Error::invalid("Default VPC security group is unavailable"))?]
            } else {
                security_group_ids
            };
            if security_group_ids.iter().any(|id| {
                ec2.security_group_vpc_id(&req.account_id, &req.region, id)
                    .as_deref()
                    != Some(&group.vpc_id)
            }) {
                return Err(Error::invalid(
                    "VpcSecurityGroupIds must belong to the DB subnet group VPC",
                ));
            }
            let subnet_id = group.subnets[0].0.clone();
            let reserved = ec2
                .reserve_task_network(
                    &req.account_id,
                    &req.region,
                    &subnet_id,
                    &security_group_ids,
                    id,
                )
                .ok_or_else(|| {
                    Error::new(
                        "InvalidVPCNetworkStateFault",
                        "Unable to reserve private RDS network interface",
                        400,
                    )
                })?;
            vpc = Some(VpcAttachment {
                subnet_group: group_name.to_owned(),
                subnet_id,
                security_group_ids,
                private_ip: reserved.private_ip,
                client_port,
            });
            lease = Some(reserved);
        } else if !input
            .rds_members("VpcSecurityGroupIds", "VpcSecurityGroupId")
            .is_empty()
        {
            return Err(Error::invalid(
                "VpcSecurityGroupIds requires DBSubnetGroupName",
            ));
        }
        let runtime = runtime::resolve_from_env()
            .await
            .map_err(|error| Error::internal(error.to_string()))?;
        validate_scope(&req.account_id, &req.region)?;
        let key = (req.account_id.clone(), req.region.clone(), id.to_owned());
        let port = free_port().await.map_err(Error::internal)?;
        let instance = Instance {
            id: id.to_owned(),
            account: req.account_id.clone(),
            region: req.region.clone(),
            username: username.to_owned(),
            db_name: db_name.to_owned(),
            class: class.to_owned(),
            storage,
            port,
            status: "creating".to_owned(),
            error: None,
            replica_source: None,
            cluster_id: None,
            vpc,
            socket_token: new_socket_token(),
            dbi_resource_id: new_dbi_resource_id(),
        };
        {
            let mut state = self.instances.lock().await;
            if state.contains_key(&key) {
                return Err(Error::new(
                    "DBInstanceAlreadyExists",
                    "DB instance already exists",
                    400,
                ));
            }
            state.insert(key.clone(), instance.clone());
        }
        let directory = self.directory(&instance);
        if let Err(error) = tokio::fs::create_dir_all(&directory).await {
            self.instances.lock().await.remove(&key);
            return Err(Error::internal(error.to_string()));
        }
        if let Err(reason) = persist(&directory, &instance).await {
            self.instances.lock().await.remove(&key);
            let _ = tokio::fs::remove_dir_all(&directory).await;
            return Err(Error::internal(reason));
        }
        if let Some(lease) = lease {
            if !lease.set_dns_name(&rds_hostname(&instance)) {
                self.instances.lock().await.remove(&key);
                let _ = tokio::fs::remove_dir_all(&directory).await;
                return Err(Error::internal("Unable to register RDS private DNS"));
            }
            self.network_leases.lock().await.insert(key.clone(), lease);
        }
        let network_leases = self.network_leases.clone();
        let state = self.instances.clone();
        let response = format!("<DBInstance>{}</DBInstance>", instance_xml(&instance));
        let password = password.to_owned();
        let mut jobs = self.jobs.lock().await;
        jobs.retain(|job| !job.is_finished());
        jobs.push(tokio::spawn(async move {
            let result = provision(&runtime, &directory, &instance, &password).await;
            let mut completed = instance;
            match result {
                Ok(()) => {
                    let published = if let Some(vpc) = &completed.vpc {
                        let backend = SocketAddr::from(([127, 0, 0, 1], completed.port));
                        network_leases
                            .lock()
                            .await
                            .get(&key)
                            .is_some_and(|lease| lease.set_endpoint(vpc.client_port, backend))
                    } else {
                        true
                    };
                    if !published {
                        stop_instance(&runtime, &directory).await;
                        completed.status = "failed".to_owned();
                        completed.error = Some("Unable to publish private RDS endpoint".to_owned());
                        let _ = persist(&directory, &completed).await;
                    } else {
                        completed.status = "available".to_owned();
                        if let Err(reason) = persist(&directory, &completed).await {
                            stop_instance(&runtime, &directory).await;
                            completed.status = "failed".to_owned();
                            completed.error =
                                Some(format!("Unable to persist instance metadata: {reason}"));
                            let _ = persist(&directory, &completed).await;
                        }
                    }
                }
                Err(reason) => {
                    stop_instance(&runtime, &directory).await;
                    completed.status = "failed".to_owned();
                    completed.error = Some(reason);
                    let _ = persist(&directory, &completed).await;
                }
            }
            if completed.status == "failed" {
                network_leases.lock().await.remove(&key);
            }
            state.lock().await.insert(key, completed);
        }));
        Ok(response)
    }

    async fn create_replica(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let id = input.required("DBInstanceIdentifier")?;
        let source_id = input.required("SourceDBInstanceIdentifier")?;
        validate_id(id)?;
        validate_id(source_id)?;
        if id == source_id {
            return Err(Error::invalid("A replica cannot be its own source"));
        }
        for field in [
            "DBClusterIdentifier",
            "SourceDBClusterIdentifier",
            "KmsKeyId",
            "DBSubnetGroupName",
            "VpcSecurityGroupIds.member.1",
            "AvailabilityZone",
        ] {
            if input.get(field).is_some() {
                return Err(Error::invalid(format!("{field} is unsupported")));
            }
        }
        validate_scope(&req.account_id, &req.region)?;
        let source_key = (
            req.account_id.clone(),
            req.region.clone(),
            source_id.to_owned(),
        );
        let key = (req.account_id.clone(), req.region.clone(), id.to_owned());
        let runtime = runtime::resolve_from_env()
            .await
            .map_err(|error| Error::internal(error.to_string()))?;
        let port = free_port().await.map_err(Error::internal)?;
        let (instance, source) = {
            let mut state = self.instances.lock().await;
            let source = state.get(&source_key).cloned().ok_or_else(|| {
                Error::new("DBInstanceNotFound", "Source DB instance not found", 404)
            })?;
            if source.cluster_id.is_some() || source.vpc.is_some() {
                return Err(Error::invalid(
                    "VPC and Aurora read replicas require dedicated network provisioning",
                ));
            }
            if source.status != "available" || source.replica_source.is_some() {
                return Err(Error::new(
                    "InvalidDBInstanceState",
                    "Source must be an available writer",
                    400,
                ));
            }
            let mut replica = source.clone();
            replica.id = id.to_owned();
            replica.port = port;
            replica.socket_token = new_socket_token();
            replica.dbi_resource_id = new_dbi_resource_id();
            replica.status = "creating".to_owned();
            replica.error = None;
            replica.replica_source = Some(source_id.to_owned());
            if state.contains_key(&key) {
                return Err(Error::new(
                    "DBInstanceAlreadyExists",
                    "DB instance already exists",
                    400,
                ));
            }
            state.insert(key.clone(), replica.clone());
            (replica, source.clone())
        };
        let directory = self.directory(&instance);
        if let Err(error) = tokio::fs::create_dir_all(&directory).await {
            self.instances.lock().await.remove(&key);
            return Err(Error::internal(error.to_string()));
        }
        if let Err(reason) = persist(&directory, &instance).await {
            self.instances.lock().await.remove(&key);
            let _ = tokio::fs::remove_dir_all(&directory).await;
            return Err(Error::internal(reason));
        }
        let state = self.instances.clone();
        let response = format!("<DBInstance>{}</DBInstance>", instance_xml(&instance));
        let mut jobs = self.jobs.lock().await;
        jobs.retain(|job| !job.is_finished());
        jobs.push(tokio::spawn(async move {
            let result = provision_replica(&runtime, &source, &directory, &instance).await;
            let mut completed = instance;
            match result {
                Ok(()) => {
                    completed.status = "available".to_owned();
                    if let Err(reason) = persist(&directory, &completed).await {
                        stop_instance(&runtime, &directory).await;
                        completed.status = "failed".to_owned();
                        completed.error =
                            Some(format!("Unable to persist replica metadata: {reason}"));
                        let _ = persist(&directory, &completed).await;
                    }
                }
                Err(reason) => {
                    stop_instance(&runtime, &directory).await;
                    completed.status = "failed".to_owned();
                    completed.error = Some(reason);
                    let _ = persist(&directory, &completed).await;
                }
            }
            state.lock().await.insert(key, completed);
        }));
        Ok(response)
    }

    async fn promote_replica(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let id = input.required("DBInstanceIdentifier")?;
        let key = (req.account_id.clone(), req.region.clone(), id.to_owned());
        let mut instance = self
            .instances
            .lock()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| Error::new("DBInstanceNotFound", "DB instance not found", 404))?;
        if instance.status != "available" || instance.replica_source.is_none() {
            return Err(Error::new(
                "InvalidDBInstanceState",
                "DB instance is not an available read replica",
                400,
            ));
        }
        let runtime = runtime::resolve_from_env()
            .await
            .map_err(|error| Error::internal(error.to_string()))?;
        let directory = self.directory(&instance);
        let data = directory.join("data");
        command(
            &runtime,
            "pg_ctl",
            &["-D", &data.to_string_lossy(), "promote", "-w"],
        )
        .await
        .map_err(Error::internal)?;
        let recovery = sql_query(
            &runtime,
            &instance,
            "SELECT pg_is_in_recovery()",
            &directory,
        )
        .await
        .map_err(Error::internal)?;
        if recovery.trim() != "f" {
            return Err(Error::internal(
                "PostgreSQL standby is still in recovery".to_owned(),
            ));
        }
        instance.replica_source = None;
        persist(&directory, &instance)
            .await
            .map_err(Error::internal)?;
        self.instances.lock().await.insert(key, instance.clone());
        Ok(format!(
            "<DBInstance>{}</DBInstance>",
            instance_xml(&instance)
        ))
    }

    async fn refresh_instance(&self, key: &Key, probe_available: bool) -> Option<Instance> {
        let mut state = self.instances.lock().await;
        let instance = state.get_mut(key)?;
        if instance.status != "restarting" && !(probe_available && instance.status == "available") {
            return Some(instance.clone());
        }
        let directory = self.directory(instance);
        let result = match runtime::resolve_from_env().await {
            Ok(runtime) if instance.status == "restarting" => {
                start_and_probe(&runtime, &directory, instance, None)
                    .await
                    .map(|_| runtime)
            }
            Ok(runtime) => Ok(runtime),
            Err(error) => Err(error.to_string()),
        };
        let result = match result {
            Ok(runtime) => probe(&runtime, &directory, instance).await,
            Err(error) => Err(error),
        };
        instance.status = if result.is_ok() {
            "available"
        } else {
            "failed"
        }
        .to_owned();
        instance.error = result.err();
        if let Some(vpc) = &instance.vpc {
            if instance.status == "available" {
                let backend = SocketAddr::from(([127, 0, 0, 1], instance.port));
                let published = self
                    .network_leases
                    .lock()
                    .await
                    .get(key)
                    .is_some_and(|lease| lease.set_endpoint(vpc.client_port, backend));
                if !published {
                    instance.status = "failed".to_owned();
                    instance.error =
                        Some("Private RDS network interface is unavailable".to_owned());
                }
            }
            if instance.status == "failed" {
                self.network_leases.lock().await.remove(key);
            }
        }
        if let Err(error) = persist(&directory, instance).await {
            instance.status = "failed".to_owned();
            instance.error = Some(format!("Unable to persist DB instance status: {error}"));
        }
        Some(instance.clone())
    }

    async fn describe(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let wanted = input.get("DBInstanceIdentifier");
        let resource_ids = match input
            .get("Filters.Filter.1.Name")
            .or_else(|| input.get("Filters.member.1.Name"))
        {
            Some("dbi-resource-id") => {
                let mut values = input.members("Filters.Filter.1.Values.Value.");
                if values.is_empty() {
                    values = input.members("Filters.Filter.1.Values.member.");
                }
                if values.is_empty() {
                    values = input.members("Filters.Filter.1.Value.");
                }
                Some(values)
            }
            Some(_) => return Err(Error::invalid("Unsupported DB instance filter")),
            None => None,
        };
        let instances: Vec<Instance> = self
            .instances
            .lock()
            .await
            .values()
            .filter(|instance| {
                instance.account == req.account_id
                    && instance.region == req.region
                    && wanted.is_none_or(|id| {
                        id == instance.id
                            || id == instance.dbi_resource_id
                            || id
                                == format!(
                                    "arn:aws:rds:{}:{}:db:{}",
                                    instance.region, instance.account, instance.id
                                )
                    })
                    && resource_ids
                        .as_ref()
                        .is_none_or(|ids| ids.contains(&instance.dbi_resource_id))
            })
            .cloned()
            .collect();
        if wanted.is_some() && instances.is_empty() {
            return Err(Error::new(
                "DBInstanceNotFound",
                "DB instance not found",
                404,
            ));
        }
        let mut rendered = String::from("<DBInstances>");
        for instance in instances {
            let key = (
                instance.account.clone(),
                instance.region.clone(),
                instance.id.clone(),
            );
            let instance = self.refresh_instance(&key, true).await.unwrap_or(instance);
            rendered.push_str("<DBInstance>");
            rendered.push_str(&instance_xml(&instance));
            rendered.push_str("</DBInstance>");
        }
        rendered.push_str("</DBInstances>");
        Ok(rendered)
    }

    async fn delete(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let id = input.required("DBInstanceIdentifier")?;
        let key = (req.account_id.clone(), req.region.clone(), id.to_owned());
        if input.get("SkipFinalSnapshot") != Some("true") {
            return Err(Error::invalid("SkipFinalSnapshot=true is required"));
        }
        let instance = {
            let mut state = self.instances.lock().await;
            if state.values().any(|replica| {
                replica.account == req.account_id
                    && replica.region == req.region
                    && replica.replica_source.as_deref() == Some(id)
                    && replica.status != "failed"
            }) {
                return Err(Error::new(
                    "InvalidDBInstanceState",
                    "Promote or delete read replicas before deleting their source",
                    400,
                ));
            }
            let current = state
                .get_mut(&key)
                .ok_or_else(|| Error::new("DBInstanceNotFound", "DB instance not found", 404))?;
            if current.status != "available" && current.status != "failed" {
                return Err(Error::new(
                    "InvalidDBInstanceState",
                    "DB instance is busy",
                    400,
                ));
            }
            let original = current.clone();
            current.status = "deleting".to_owned();
            original
        };
        let runtime = match runtime::resolve_from_env().await {
            Ok(runtime) => runtime,
            Err(error) => {
                self.instances.lock().await.insert(key.clone(), instance);
                return Err(Error::internal(error.to_string()));
            }
        };
        let directory = self.directory(&instance);
        let data = directory.join("data");
        if command(
            &runtime,
            "pg_ctl",
            &["-D", &data.to_string_lossy(), "status"],
        )
        .await
        .is_ok()
        {
            if let Err(reason) = command(
                &runtime,
                "pg_ctl",
                &[
                    "-D",
                    &data.to_string_lossy(),
                    "stop",
                    "-m",
                    "immediate",
                    "-w",
                ],
            )
            .await
            {
                let mut failed = instance.clone();
                failed.status = "failed".to_owned();
                failed.error = Some(format!("Unable to stop PostgreSQL: {reason}"));
                self.instances.lock().await.insert(key.clone(), failed);
                return Err(Error::internal(reason));
            }
        }
        if let Some(cluster_id) = &instance.cluster_id {
            let result: Result<(), String> = async {
                let cluster_key = (
                    instance.account.clone(),
                    instance.region.clone(),
                    cluster_id.clone(),
                );
                let mut clusters = self.clusters.lock().await;
                let cluster = clusters
                    .get_mut(&cluster_key)
                    .ok_or_else(|| "Aurora cluster metadata is missing".to_owned())?;
                let cluster_dir = self.cluster_directory(cluster);
                let retained = cluster_dir.join("data");
                let secret_exists = tokio::fs::try_exists(cluster_dir.join("master-password"))
                    .await
                    .map_err(|error| error.to_string())?;
                let data_exists = tokio::fs::try_exists(&data)
                    .await
                    .map_err(|error| error.to_string())?;
                let retained_exists = tokio::fs::try_exists(&retained)
                    .await
                    .map_err(|error| error.to_string())?;
                if !secret_exists {
                    if data_exists && retained_exists {
                        return Err("Aurora cluster already has retained data".to_owned());
                    }
                    if data_exists {
                        tokio::fs::rename(&data, &retained)
                            .await
                            .map_err(|error| error.to_string())?;
                    } else if !retained_exists {
                        return Err("Aurora writer data is missing".to_owned());
                    }
                }
                tokio::fs::remove_dir_all(&directory)
                    .await
                    .map_err(|error| error.to_string())?;
                cluster.writer_id = None;
                persist_cluster(&cluster_dir, cluster).await?;
                Ok(())
            }
            .await;
            if let Err(error) = result {
                let mut failed = instance.clone();
                failed.status = "failed".to_owned();
                failed.error = Some(format!("Unable to retain Aurora cluster data: {error}"));
                self.instances.lock().await.insert(key.clone(), failed);
                return Err(Error::internal(error));
            }
            self.instances.lock().await.remove(&key);
            let _ = cleanup_socket_dir(&instance).await;
            return Ok(format!(
                "<DBInstance>{}</DBInstance>",
                instance_xml(&Instance {
                    status: "deleting".to_owned(),
                    ..instance
                })
            ));
        }
        if let Err(error) = tokio::fs::remove_dir_all(&directory).await {
            let mut failed = instance.clone();
            failed.status = "failed".to_owned();
            failed.error = Some(format!("Unable to remove DB instance directory: {error}"));
            self.instances.lock().await.insert(key.clone(), failed);
            return Err(Error::internal(error.to_string()));
        }
        self.instances.lock().await.remove(&key);
        self.network_leases.lock().await.remove(&key);
        let _ = cleanup_socket_dir(&instance).await;
        Ok(format!(
            "<DBInstance>{}</DBInstance>",
            instance_xml(&Instance {
                status: "deleting".to_owned(),
                ..instance
            })
        ))
    }

    async fn create_snapshot(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let id = input.required("DBSnapshotIdentifier")?;
        validate_id(id)?;
        let source_id = input.required("DBInstanceIdentifier")?;
        validate_id(source_id)?;
        let source_key = (
            req.account_id.clone(),
            req.region.clone(),
            source_id.to_owned(),
        );
        let snapshot_key = (req.account_id.clone(), req.region.clone(), id.to_owned());
        let runtime = runtime::resolve_from_env()
            .await
            .map_err(|error| Error::internal(error.to_string()))?;
        let source = {
            let mut instances = self.instances.lock().await;
            let instance = instances
                .get_mut(&source_key)
                .ok_or_else(|| Error::new("DBInstanceNotFound", "DB instance not found", 404))?;
            if instance.cluster_id.is_some() {
                return Err(Error::invalid("Use a DB cluster snapshot for Aurora"));
            }
            if instance.status != "available" {
                return Err(Error::new(
                    "InvalidDBInstanceState",
                    "DB instance is not available",
                    400,
                ));
            }
            let source = instance.clone();
            instance.status = "backing-up".to_owned();
            source
        };
        let snapshot = Snapshot {
            id: id.to_owned(),
            source: source.clone(),
            status: "creating".to_owned(),
            error: None,
        };
        {
            let mut snapshots = self.snapshots.lock().await;
            if snapshots.contains_key(&snapshot_key) {
                self.instances
                    .lock()
                    .await
                    .insert(source_key.clone(), source);
                return Err(Error::new(
                    "DBSnapshotAlreadyExists",
                    "DB snapshot already exists",
                    400,
                ));
            }
            snapshots.insert(snapshot_key.clone(), snapshot.clone());
        }
        let source_dir = self.directory(&source);
        let target_dir = self.snapshot_directory(&snapshot);
        let prepared = async {
            tokio::fs::create_dir_all(&target_dir)
                .await
                .map_err(|error| error.to_string())?;
            tokio::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o700))
                .await
                .map_err(|error| error.to_string())?;
            persist_snapshot(&target_dir, &snapshot).await?;
            let mut backing_up = source.clone();
            backing_up.status = "backing-up".to_owned();
            persist(&source_dir, &backing_up).await?;
            Ok::<(), String>(())
        }
        .await;
        if let Err(reason) = prepared {
            self.snapshots.lock().await.remove(&snapshot_key);
            self.instances.lock().await.insert(source_key, source);
            let _ = tokio::fs::remove_dir_all(&target_dir).await;
            return Err(Error::internal(reason));
        }
        let response = format!("<DBSnapshot>{}</DBSnapshot>", snapshot_xml(&snapshot));
        let instances = self.instances.clone();
        let snapshots = self.snapshots.clone();
        let mut jobs = self.jobs.lock().await;
        jobs.retain(|job| !job.is_finished());
        jobs.push(tokio::spawn(async move {
            let result = backup_snapshot(&runtime, &source, &source_dir, &target_dir).await;
            let mut completed = snapshot;
            match result {
                Ok(()) => {
                    completed.status = "available".to_owned();
                    if let Err(reason) = persist_snapshot(&target_dir, &completed).await {
                        completed.status = "failed".to_owned();
                        completed.error =
                            Some(format!("Unable to persist snapshot metadata: {reason}"));
                        let _ = tokio::fs::remove_dir_all(target_dir.join("data")).await;
                        let _ = persist_snapshot(&target_dir, &completed).await;
                    }
                }
                Err(reason) => {
                    completed.status = "failed".to_owned();
                    completed.error = Some(reason);
                    let _ = persist_snapshot(&target_dir, &completed).await;
                }
            }
            snapshots.lock().await.insert(snapshot_key, completed);
            let mut source_status = source;
            source_status.status = if probe(&runtime, &source_dir, &source_status).await.is_ok() {
                "available"
            } else {
                "failed"
            }
            .to_owned();
            let _ = persist(&source_dir, &source_status).await;
            instances.lock().await.insert(source_key, source_status);
        }));
        Ok(response)
    }

    async fn describe_snapshots(
        &self,
        req: &ServiceRequest,
        input: &Input,
    ) -> Result<String, Error> {
        let wanted = input.get("DBSnapshotIdentifier");
        let source = input.get("DBInstanceIdentifier");
        let mut snapshots: Vec<Snapshot> = self
            .snapshots
            .lock()
            .await
            .values()
            .filter(|snapshot| {
                snapshot.source.account == req.account_id
                    && snapshot.source.region == req.region
                    && wanted.is_none_or(|id| id == snapshot.id)
                    && source.is_none_or(|id| id == snapshot.source.id)
            })
            .cloned()
            .collect();
        if wanted.is_some() && snapshots.is_empty() {
            return Err(Error::new(
                "DBSnapshotNotFound",
                "DB snapshot not found",
                404,
            ));
        }
        snapshots.sort_by(|a, b| a.id.cmp(&b.id));
        let mut xml = String::from("<DBSnapshots>");
        for snapshot in snapshots {
            xml.push_str("<DBSnapshot>");
            xml.push_str(&snapshot_xml(&snapshot));
            xml.push_str("</DBSnapshot>");
        }
        xml.push_str("</DBSnapshots>");
        Ok(xml)
    }

    async fn delete_snapshot(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let id = input.required("DBSnapshotIdentifier")?;
        let key = (req.account_id.clone(), req.region.clone(), id.to_owned());
        let snapshot = {
            let mut snapshots = self.snapshots.lock().await;
            let current = snapshots
                .get_mut(&key)
                .ok_or_else(|| Error::new("DBSnapshotNotFound", "DB snapshot not found", 404))?;
            if current.status != "available" && current.status != "failed" {
                return Err(Error::new(
                    "InvalidDBSnapshotState",
                    "DB snapshot is busy",
                    400,
                ));
            }
            let snapshot = current.clone();
            current.status = "deleting".to_owned();
            snapshot
        };
        if let Err(error) = tokio::fs::remove_dir_all(self.snapshot_directory(&snapshot)).await {
            self.snapshots.lock().await.insert(key, snapshot);
            return Err(Error::internal(error.to_string()));
        }
        self.snapshots.lock().await.remove(&key);
        Ok(format!(
            "<DBSnapshot>{}</DBSnapshot>",
            snapshot_xml(&snapshot)
        ))
    }

    async fn restore_snapshot(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let id = input.required("DBInstanceIdentifier")?;
        validate_id(id)?;
        let snapshot_id = input.required("DBSnapshotIdentifier")?;
        let snapshot_key = (
            req.account_id.clone(),
            req.region.clone(),
            snapshot_id.to_owned(),
        );
        let snapshot = self
            .snapshots
            .lock()
            .await
            .get(&snapshot_key)
            .cloned()
            .ok_or_else(|| Error::new("DBSnapshotNotFound", "DB snapshot not found", 404))?;
        if snapshot.status != "available" {
            return Err(Error::new(
                "InvalidDBSnapshotState",
                "DB snapshot is not available",
                400,
            ));
        }
        if snapshot.source.vpc.is_some() {
            return Err(Error::invalid(
                "Restoring a VPC DB snapshot requires private network provisioning",
            ));
        }
        for field in [
            "DBSubnetGroupName",
            "VpcSecurityGroupIds.member.1",
            "KmsKeyId",
        ] {
            if input.get(field).is_some() {
                return Err(Error::invalid(format!("{field} is unsupported")));
            }
        }
        let class = input
            .get("DBInstanceClass")
            .unwrap_or(&snapshot.source.class);
        if class != "db.t3.micro" {
            return Err(Error::invalid("Only db.t3.micro is supported"));
        }
        let runtime = runtime::resolve_from_env()
            .await
            .map_err(|error| Error::internal(error.to_string()))?;
        let key = (req.account_id.clone(), req.region.clone(), id.to_owned());
        let mut instance = snapshot.source.clone();
        instance.id = id.to_owned();
        instance.class = class.to_owned();
        instance.socket_token = new_socket_token();
        instance.dbi_resource_id = new_dbi_resource_id();
        instance.port = free_port().await.map_err(Error::internal)?;
        instance.status = "restoring".to_owned();
        instance.error = None;
        {
            let mut instances = self.instances.lock().await;
            if instances.contains_key(&key) {
                return Err(Error::new(
                    "DBInstanceAlreadyExists",
                    "DB instance already exists",
                    400,
                ));
            }
            instances.insert(key.clone(), instance.clone());
        }
        {
            let mut snapshots = self.snapshots.lock().await;
            let Some(current) = snapshots.get_mut(&snapshot_key) else {
                self.instances.lock().await.remove(&key);
                return Err(Error::new(
                    "DBSnapshotNotFound",
                    "DB snapshot not found",
                    404,
                ));
            };
            if current.status != "available" {
                self.instances.lock().await.remove(&key);
                return Err(Error::new(
                    "InvalidDBSnapshotState",
                    "DB snapshot is busy",
                    400,
                ));
            }
            current.status = "restoring".to_owned();
        }
        let directory = self.directory(&instance);
        let prepared = async {
            tokio::fs::create_dir_all(&directory)
                .await
                .map_err(|error| error.to_string())?;
            persist(&directory, &instance).await
        }
        .await;
        if let Err(reason) = prepared {
            self.instances.lock().await.remove(&key);
            if let Some(current) = self.snapshots.lock().await.get_mut(&snapshot_key) {
                current.status = "available".to_owned();
            }
            let _ = tokio::fs::remove_dir_all(&directory).await;
            return Err(Error::internal(reason));
        }
        let response = format!("<DBInstance>{}</DBInstance>", instance_xml(&instance));
        let instances = self.instances.clone();
        let snapshots = self.snapshots.clone();
        let snapshot_dir = self.snapshot_directory(&snapshot);
        let mut jobs = self.jobs.lock().await;
        jobs.retain(|job| !job.is_finished());
        jobs.push(tokio::spawn(async move {
            let result = restore(&runtime, &snapshot_dir, &directory, &instance).await;
            let mut completed = instance;
            match result {
                Ok(()) => {
                    completed.status = "available".to_owned();
                    if let Err(reason) = persist(&directory, &completed).await {
                        stop_instance(&runtime, &directory).await;
                        let _ = tokio::fs::remove_dir_all(directory.join("data")).await;
                        completed.status = "failed".to_owned();
                        completed.error =
                            Some(format!("Unable to persist restored instance: {reason}"));
                        let _ = persist(&directory, &completed).await;
                    }
                }
                Err(reason) => {
                    stop_instance(&runtime, &directory).await;
                    let _ = tokio::fs::remove_dir_all(directory.join("data")).await;
                    let _ = cleanup_socket_dir(&completed).await;
                    completed.status = "failed".to_owned();
                    completed.error = Some(reason);
                    let _ = persist(&directory, &completed).await;
                }
            }
            instances.lock().await.insert(key, completed);
            if let Some(current) = snapshots.lock().await.get_mut(&snapshot_key) {
                current.status = "available".to_owned();
            }
        }));
        Ok(response)
    }

    async fn modify(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let id = input.required("DBInstanceIdentifier")?;
        let key = (req.account_id.clone(), req.region.clone(), id.to_owned());
        let original = self
            .instances
            .lock()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| Error::new("DBInstanceNotFound", "DB instance not found", 404))?;
        if original.cluster_id.is_some() {
            return Err(Error::invalid("ModifyDBInstance for Aurora is unsupported"));
        }
        if original.status != "available" {
            return Err(Error::new(
                "InvalidDBInstanceState",
                "DB instance is not available",
                400,
            ));
        }
        if input.get("ApplyImmediately") != Some("true") {
            return Err(Error::invalid("ApplyImmediately=true is required"));
        }
        for field in [
            "DBSubnetGroupName",
            "VpcSecurityGroupIds.member.1",
            "KmsKeyId",
            "MasterUserPassword",
            "EngineVersion",
        ] {
            if input.get(field).is_some() {
                return Err(Error::invalid(format!("{field} is unsupported")));
            }
        }
        let mut updated = original.clone();
        if let Some(class) = input.get("DBInstanceClass") {
            if class != "db.t3.micro" {
                return Err(Error::invalid("Only db.t3.micro is supported"));
            }
            updated.class = class.to_owned();
        }
        if let Some(value) = input.get("AllocatedStorage") {
            let storage = value
                .parse::<u32>()
                .map_err(|_| Error::invalid("AllocatedStorage must be an integer"))?;
            if !(20..=100).contains(&storage) || storage < original.storage {
                return Err(Error::invalid(
                    "AllocatedStorage must be 20..100 GiB and cannot decrease",
                ));
            }
            updated.storage = storage;
        }
        if updated.class == original.class && updated.storage == original.storage {
            return Err(Error::invalid("No supported modification requested"));
        }
        {
            let mut state = self.instances.lock().await;
            let current = state
                .get_mut(&key)
                .ok_or_else(|| Error::new("DBInstanceNotFound", "DB instance not found", 404))?;
            if current.status != "available"
                || current.class != original.class
                || current.storage != original.storage
            {
                return Err(Error::new(
                    "InvalidDBInstanceState",
                    "DB instance changed during modification",
                    400,
                ));
            }
            current.status = "modifying".to_owned();
        }
        let directory = self.directory(&updated);
        if let Err(reason) = persist(&directory, &updated).await {
            self.instances.lock().await.insert(key, original);
            return Err(Error::internal(reason));
        }
        self.instances.lock().await.insert(key, updated.clone());
        Ok(format!(
            "<DBInstance>{}</DBInstance>",
            instance_xml(&updated)
        ))
    }

    pub async fn shutdown(&self) {
        let jobs = std::mem::take(&mut *self.jobs.lock().await);
        for job in &jobs {
            job.abort();
        }
        for job in jobs {
            let _ = job.await;
        }

        let instances: Vec<Instance> = {
            let mut state = self.instances.lock().await;
            state
                .values_mut()
                .map(|instance| {
                    if instance.status == "creating" || instance.status == "restoring" {
                        instance.status = "failed".to_owned();
                        instance.error =
                            Some("Operation interrupted by server shutdown".to_owned());
                    } else if instance.status == "backing-up" {
                        instance.status = "available".to_owned();
                    }
                    instance.clone()
                })
                .collect()
        };
        for instance in &instances {
            let _ = tokio::fs::remove_file(self.directory(instance).join("password")).await;
        }
        if let Ok(runtime) = runtime::resolve_from_env().await {
            for instance in &instances {
                let data = self.directory(instance).join("data");
                let _ = command(
                    &runtime,
                    "pg_ctl",
                    &["-D", &data.to_string_lossy(), "stop", "-m", "fast", "-w"],
                )
                .await;
            }
        }
        for instance in &instances {
            let _ = cleanup_socket_dir(instance).await;
            let _ = persist(&self.directory(instance), instance).await;
        }
        self.network_leases.lock().await.clear();
        let snapshots: Vec<Snapshot> = {
            let mut state = self.snapshots.lock().await;
            state
                .values_mut()
                .map(|snapshot| {
                    if snapshot.status == "creating" {
                        snapshot.status = "failed".to_owned();
                        snapshot.error = Some("Snapshot interrupted by server shutdown".to_owned());
                    } else if snapshot.status == "restoring" {
                        snapshot.status = "available".to_owned();
                    }
                    snapshot.clone()
                })
                .collect()
        };
        for snapshot in &snapshots {
            let directory = self.snapshot_directory(snapshot);
            if snapshot.status == "failed" {
                if let Ok(mut entries) = tokio::fs::read_dir(&directory).await {
                    while let Ok(Some(entry)) = entries.next_entry().await {
                        if entry.file_name().to_string_lossy().starts_with("data.tmp-") {
                            let _ = tokio::fs::remove_dir_all(entry.path()).await;
                        }
                    }
                }
            }
            let _ = persist_snapshot(&directory, snapshot).await;
        }
    }
}

#[async_trait]
impl NativeHandler for RdsHandler {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        let mut regions = Vec::new();
        let instances = self
            .instances
            .lock()
            .await
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let snapshots = self
            .snapshots
            .lock()
            .await
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let clusters = self
            .clusters
            .lock()
            .await
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let subnet_groups = self
            .subnet_groups
            .lock()
            .await
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for map in [instances, snapshots, clusters, subnet_groups] {
            regions.extend(map.into_iter().filter(|k| k.0 == account).map(|k| k.1));
        }
        Ok(regions)
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let input = Input::parse(&request);
        let action = input.get("Action").unwrap_or("Unknown");
        let result = match action {
            "CreateDBCluster" => self.create_cluster(&request, &input).await,
            "DescribeDBClusters" => self.describe_clusters(&request, &input).await,
            "DeleteDBCluster" => self.delete_cluster(&request, &input).await,
            "ListTagsForResource" => self.list_tags(&request, &input).await,
            "CreateDBSubnetGroup" => self.create_subnet_group(&request, &input).await,
            "DescribeDBSubnetGroups" => self.describe_subnet_groups(&request, &input).await,
            "DeleteDBSubnetGroup" => self.delete_subnet_group(&request, &input).await,
            "CreateDBInstance" => self.create(&request, &input).await,
            "DescribeDBInstances" => self.describe(&request, &input).await,
            "CreateDBInstanceReadReplica" => self.create_replica(&request, &input).await,
            "PromoteReadReplica" => self.promote_replica(&request, &input).await,
            "DeleteDBInstance" => self.delete(&request, &input).await,
            "ModifyDBInstance" => self.modify(&request, &input).await,
            "CreateDBSnapshot" => self.create_snapshot(&request, &input).await,
            "DescribeDBSnapshots" => self.describe_snapshots(&request, &input).await,
            "DeleteDBSnapshot" => self.delete_snapshot(&request, &input).await,
            "RestoreDBInstanceFromDBSnapshot" => self.restore_snapshot(&request, &input).await,
            _ => Err(Error::new(
                "InvalidAction",
                "Operation is not implemented",
                400,
            )),
        };
        match result {
            Ok(inner) => {
                let body = format!("<{action}Response xmlns=\"{XMLNS}\"><{action}Result>{inner}</{action}Result><ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata></{action}Response>", escape(&request.request_id));
                Response::builder()
                    .status(200)
                    .header("content-type", "text/xml")
                    .body(Body::from(body))
                    .expect("valid RDS response")
            }
            Err(error) => error.response(&request.request_id),
        }
    }
}

pub fn register(
    registry: &ServiceRegistry,
) -> Result<Arc<RdsHandler>, locallycloud_state::StateError> {
    let root = match std::env::var_os("LOCALLYCLOUD_RDS_DATA_DIR").filter(|value| !value.is_empty())
    {
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(locallycloud_state::StateError::InvalidPath(
                    "LOCALLYCLOUD_RDS_DATA_DIR",
                ));
            }
            path
        }
        None => locallycloud_state::StateDb::data_dir()?.join("rds"),
    };
    locallycloud_state::StateDb::private_dir(&root)?;
    let handler = Arc::new(RdsHandler::new(root));
    let mut metadata = ServiceMetadata::new(AwsProtocol::Query, None);
    metadata.known_actions = [
        "CreateDBCluster",
        "DescribeDBClusters",
        "DeleteDBCluster",
        "ListTagsForResource",
        "CreateDBSubnetGroup",
        "DescribeDBSubnetGroups",
        "DeleteDBSubnetGroup",
        "CreateDBInstance",
        "DescribeDBInstances",
        "CreateDBInstanceReadReplica",
        "PromoteReadReplica",
        "DeleteDBInstance",
        "ModifyDBInstance",
        "CreateDBSnapshot",
        "DescribeDBSnapshots",
        "DeleteDBSnapshot",
        "RestoreDBInstanceFromDBSnapshot",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    registry.register_native(ServiceName::new("rds"), metadata, handler.clone());
    Ok(handler)
}

async fn backup_snapshot(
    runtime: &PostgresRuntime,
    source: &Instance,
    source_dir: &Path,
    target_dir: &Path,
) -> Result<(), String> {
    probe(runtime, source_dir, source).await?;
    let temporary = target_dir.join(format!("data.tmp-{}", uuid::Uuid::new_v4()));
    let mut cmd = Command::new(runtime.bin_dir.join("pg_basebackup"));
    cmd.args([
        "-h",
        &socket_dir(source).to_string_lossy(),
        "-p",
        &source.port.to_string(),
        "-U",
        &source.username,
        "-D",
        &temporary.to_string_lossy(),
        "-X",
        "stream",
        "--checkpoint=fast",
    ]);
    if let Err(reason) = execute(cmd).await {
        let _ = tokio::fs::remove_dir_all(&temporary).await;
        return Err(reason);
    }
    tokio::fs::rename(&temporary, target_dir.join("data"))
        .await
        .map_err(|error| error.to_string())
}

async fn persist_snapshot(directory: &Path, snapshot: &Snapshot) -> Result<(), String> {
    let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
    let temp = directory.join("snapshot.json.tmp");
    tokio::fs::write(&temp, bytes)
        .await
        .map_err(|error| error.to_string())?;
    tokio::fs::rename(temp, directory.join("snapshot.json"))
        .await
        .map_err(|error| error.to_string())
}

async fn restore(
    runtime: &PostgresRuntime,
    snapshot: &Path,
    directory: &Path,
    instance: &Instance,
) -> Result<(), String> {
    tokio::fs::create_dir_all(directory)
        .await
        .map_err(|error| error.to_string())?;
    let socket = prepare_socket_dir(instance).await?;
    copy_tree(&snapshot.join("data"), &directory.join("data")).await?;
    let settings = format!(
        "\nlisten_addresses = '127.0.0.1'\nport = {}\nunix_socket_directories = '{}'\n",
        instance.port,
        socket.to_string_lossy().replace('\'', "''")
    );
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(directory.join("data/postgresql.conf"))
        .await
        .map_err(|error| error.to_string())?;
    file.write_all(settings.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    start_and_probe(runtime, directory, instance, None).await?;
    probe(runtime, directory, instance).await
}

async fn copy_tree(source: &Path, target: &Path) -> Result<(), String> {
    let mut pending = vec![(source.to_path_buf(), target.to_path_buf())];
    while let Some((from, to)) = pending.pop() {
        let metadata = tokio::fs::symlink_metadata(&from)
            .await
            .map_err(|error| error.to_string())?;
        if !metadata.is_dir() {
            return Err("Snapshot data contains a non-directory root".to_owned());
        }
        tokio::fs::create_dir_all(&to)
            .await
            .map_err(|error| error.to_string())?;
        tokio::fs::set_permissions(&to, metadata.permissions())
            .await
            .map_err(|error| error.to_string())?;
        let mut entries = tokio::fs::read_dir(&from)
            .await
            .map_err(|error| error.to_string())?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| error.to_string())?
        {
            let source_path = entry.path();
            let target_path = to.join(entry.file_name());
            let metadata = tokio::fs::symlink_metadata(&source_path)
                .await
                .map_err(|error| error.to_string())?;
            if metadata.is_dir() {
                pending.push((source_path, target_path));
            } else if metadata.is_file() {
                tokio::fs::copy(&source_path, &target_path)
                    .await
                    .map_err(|error| error.to_string())?;
                tokio::fs::set_permissions(&target_path, metadata.permissions())
                    .await
                    .map_err(|error| error.to_string())?;
            } else {
                return Err("Snapshot data contains a symlink or unsupported entry".to_owned());
            }
        }
    }
    Ok(())
}

fn snapshot_xml(snapshot: &Snapshot) -> String {
    format!("<DBSnapshotIdentifier>{}</DBSnapshotIdentifier><DBInstanceIdentifier>{}</DBInstanceIdentifier><Status>{}</Status><Engine>postgres</Engine><AllocatedStorage>{}</AllocatedStorage><SnapshotType>manual</SnapshotType><Port>{}</Port>", escape(&snapshot.id), escape(&snapshot.source.id), escape(&snapshot.status), snapshot.source.storage, snapshot.source.port)
}

async fn reopen_cluster_writer(
    runtime: &PostgresRuntime,
    cluster_dir: &Path,
    directory: &Path,
    instance: &Instance,
) -> Result<(), String> {
    let socket = prepare_socket_dir(instance).await?;
    tokio::fs::rename(cluster_dir.join("data"), directory.join("data"))
        .await
        .map_err(|error| error.to_string())?;
    let settings = format!(
        "\nlisten_addresses = '127.0.0.1'\nport = {}\nunix_socket_directories = '{}'\n",
        instance.port,
        socket.to_string_lossy().replace('\'', "''")
    );
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(directory.join("data/postgresql.conf"))
        .await
        .map_err(|error| error.to_string())?;
    file.write_all(settings.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    start_and_probe(runtime, directory, instance, None).await?;
    probe(runtime, directory, instance).await
}

async fn provision(
    runtime: &PostgresRuntime,
    directory: &Path,
    instance: &Instance,
    password: &str,
) -> Result<(), String> {
    tokio::fs::create_dir_all(directory)
        .await
        .map_err(|error| error.to_string())?;
    let data = directory.join("data");
    let socket_dir = prepare_socket_dir(instance).await?;
    let pwfile = directory.join("password");
    let password_file_guard = PasswordFile(pwfile.clone());
    use tokio::io::AsyncWriteExt;
    let mut secret_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pwfile)
        .await
        .map_err(|error| error.to_string())?;
    secret_file
        .write_all(format!("{password}\n").as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    drop(secret_file);
    let result = command(
        runtime,
        "initdb",
        &[
            "-D",
            &data.to_string_lossy(),
            "-U",
            &instance.username,
            "--auth-host=scram-sha-256",
            "--auth-local=trust",
            "--pwfile",
            &pwfile.to_string_lossy(),
        ],
    )
    .await;
    drop(password_file_guard);
    result?;
    let config = data.join("postgresql.conf");
    let socket_path = socket_dir.to_string_lossy().replace('\'', "''");
    let settings = format!(
        "\nlisten_addresses = '127.0.0.1'\nport = {}\nunix_socket_directories = '{}'\n",
        instance.port, socket_path
    );
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(config)
        .await
        .map_err(|error| error.to_string())?;
    file.write_all(settings.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    start_and_probe(runtime, directory, instance, Some(password)).await?;
    if instance.db_name != "postgres" {
        let sql = format!(
            "CREATE DATABASE \"{}\"",
            instance.db_name.replace('"', "\"\"")
        );
        sql_command(
            runtime,
            instance,
            "postgres",
            Some(password),
            &sql,
            directory,
        )
        .await?;
        sql_command(
            runtime,
            instance,
            &instance.db_name,
            Some(password),
            "SELECT 1",
            directory,
        )
        .await?;
    }
    Ok(())
}

async fn provision_replica(
    runtime: &PostgresRuntime,
    source: &Instance,
    directory: &Path,
    instance: &Instance,
) -> Result<(), String> {
    let socket = prepare_socket_dir(instance).await?;
    let data = directory.join("data");
    let mut cmd = Command::new(runtime.bin_dir.join("pg_basebackup"));
    cmd.args([
        "-h",
        &socket_dir(source).to_string_lossy(),
        "-p",
        &source.port.to_string(),
        "-U",
        &instance.username,
        "-D",
        &data.to_string_lossy(),
        "-X",
        "stream",
        "-R",
        "--checkpoint=fast",
    ]);
    execute(cmd).await?;
    let config = data.join("postgresql.conf");
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(config)
        .await
        .map_err(|error| error.to_string())?;
    file.write_all(
        format!(
            "\nport = {}\nunix_socket_directories = '{}'\n",
            instance.port,
            socket.to_string_lossy().replace('\'', "''")
        )
        .as_bytes(),
    )
    .await
    .map_err(|error| error.to_string())?;
    start_and_probe(runtime, directory, instance, None).await?;
    let recovery = sql_query(runtime, instance, "SELECT pg_is_in_recovery()", directory).await?;
    if recovery.trim() != "t" {
        return Err("PostgreSQL replica did not enter recovery mode".to_owned());
    }
    Ok(())
}

async fn sql_query(
    runtime: &PostgresRuntime,
    instance: &Instance,
    sql: &str,
    _directory: &Path,
) -> Result<String, String> {
    let mut cmd = Command::new(runtime.bin_dir.join("psql"));
    cmd.args([
        "-X",
        "-A",
        "-t",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        &socket_dir(instance).to_string_lossy(),
        "-p",
        &instance.port.to_string(),
        "-U",
        &instance.username,
        "-d",
        "postgres",
        "-c",
        sql,
    ]);
    execute(cmd).await
}

async fn start_and_probe(
    runtime: &PostgresRuntime,
    directory: &Path,
    instance: &Instance,
    password: Option<&str>,
) -> Result<(), String> {
    prepare_socket_dir(instance).await?;
    let data = directory.join("data");
    let data_arg = data.to_string_lossy();
    if command(runtime, "pg_ctl", &["-D", &data_arg, "status"])
        .await
        .is_err()
    {
        command(
            runtime,
            "pg_ctl",
            &[
                "-D",
                &data_arg,
                "-l",
                &directory.join("postgres.log").to_string_lossy(),
                "start",
                "-w",
                "-t",
                "30",
            ],
        )
        .await?;
    }
    sql_command(
        runtime, instance, "postgres", password, "SELECT 1", directory,
    )
    .await
}

async fn probe(
    runtime: &PostgresRuntime,
    directory: &Path,
    instance: &Instance,
) -> Result<(), String> {
    let data = directory.join("data");
    command(
        runtime,
        "pg_ctl",
        &["-D", &data.to_string_lossy(), "status"],
    )
    .await?;
    sql_command(
        runtime,
        instance,
        &instance.db_name,
        None,
        "SELECT 1",
        directory,
    )
    .await
}

async fn stop_instance(runtime: &PostgresRuntime, directory: &Path) {
    let data = directory.join("data");
    let _ = command(
        runtime,
        "pg_ctl",
        &[
            "-D",
            &data.to_string_lossy(),
            "stop",
            "-m",
            "immediate",
            "-w",
        ],
    )
    .await;
}

async fn sql_command(
    runtime: &PostgresRuntime,
    instance: &Instance,
    db: &str,
    password: Option<&str>,
    sql: &str,
    _directory: &Path,
) -> Result<(), String> {
    let port = instance.port.to_string();
    let socket = socket_dir(instance);
    let host = if password.is_some() {
        "127.0.0.1"
    } else {
        socket
            .to_str()
            .ok_or_else(|| "Invalid socket path".to_owned())?
    };
    let mut cmd = Command::new(runtime.bin_dir.join("psql"));
    cmd.args([
        "-X",
        "-A",
        "-t",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        host,
        "-p",
        &port,
        "-U",
        &instance.username,
        "-d",
        db,
        "-c",
        sql,
    ]);
    if let Some(secret) = password {
        cmd.env("PGPASSWORD", secret);
    }
    execute(cmd).await.map(|_| ())
}

async fn command(runtime: &PostgresRuntime, tool: &str, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(runtime.bin_dir.join(tool));
    cmd.args(args);
    execute(cmd).await
}

async fn execute(mut cmd: Command) -> Result<String, String> {
    let output = tokio::time::timeout(Duration::from_secs(60), cmd.kill_on_drop(true).output())
        .await
        .map_err(|_| "PostgreSQL command timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn persist(directory: &Path, instance: &Instance) -> Result<(), String> {
    let bytes = serde_json::to_vec(instance).map_err(|error| error.to_string())?;
    let temp = directory.join("meta.json.tmp");
    tokio::fs::write(&temp, bytes)
        .await
        .map_err(|error| error.to_string())?;
    tokio::fs::rename(temp, directory.join("meta.json"))
        .await
        .map_err(|error| error.to_string())
}

async fn free_port() -> Result<u16, String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|error| error.to_string())
}

async fn persist_cluster(directory: &Path, cluster: &Cluster) -> Result<(), String> {
    let bytes = serde_json::to_vec(cluster).map_err(|e| e.to_string())?;
    let temp = directory.join("cluster.json.tmp");
    tokio::fs::write(&temp, bytes)
        .await
        .map_err(|e| e.to_string())?;
    tokio::fs::rename(temp, directory.join("cluster.json"))
        .await
        .map_err(|e| e.to_string())
}

fn cluster_xml(cluster: &Cluster, writer: Option<&Instance>) -> String {
    let available = writer.is_some_and(|instance| instance.status == "available");
    let status = if available {
        "available"
    } else if writer.is_some_and(|instance| instance.status == "failed") {
        "failed"
    } else {
        "creating"
    };
    let mut xml = format!(
        "<DBClusterIdentifier>{}</DBClusterIdentifier><DBClusterArn>arn:aws:rds:{}:{}:cluster:{}</DBClusterArn><Engine>aurora-postgresql</Engine><Status>{}</Status><MasterUsername>{}</MasterUsername><DatabaseName>{}</DatabaseName><Port>{}</Port><HttpEndpointEnabled>{}</HttpEndpointEnabled>",
        escape(&cluster.id), escape(&cluster.region), escape(&cluster.account),
        escape(&cluster.id), status, escape(&cluster.username), escape(&cluster.db_name),
        writer.map_or(5432, |instance| instance.port), cluster.http_endpoint_enabled
    );
    if let Some(writer) = writer {
        xml.push_str(&format!("<DBClusterMembers><DBClusterMember><DBInstanceIdentifier>{}</DBInstanceIdentifier><IsClusterWriter>true</IsClusterWriter></DBClusterMember></DBClusterMembers>", escape(&writer.id)));
        if available {
            xml.push_str(
                "<Endpoint>127.0.0.1</Endpoint><ReaderEndpoint>127.0.0.1</ReaderEndpoint>",
            );
        }
    }
    xml
}

fn new_dbi_resource_id() -> String {
    format!(
        "db-{}",
        uuid::Uuid::new_v4().simple().to_string()[..26].to_ascii_uppercase()
    )
}

fn new_socket_token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn valid_socket_token(token: &str) -> bool {
    token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn socket_dir(instance: &Instance) -> PathBuf {
    PathBuf::from(format!("/tmp/lc-rds-{}", instance.socket_token))
}

async fn prepare_socket_dir(instance: &Instance) -> Result<PathBuf, String> {
    if !valid_socket_token(&instance.socket_token) {
        return Err("Invalid RDS socket token".to_owned());
    }
    let path = socket_dir(instance);
    match tokio::fs::DirBuilder::new().mode(0o700).create(&path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.to_string()),
    }
    let metadata = tokio::fs::symlink_metadata(&path)
        .await
        .map_err(|error| error.to_string())?;
    let owner = tokio::fs::metadata("/proc/self")
        .await
        .map_err(|error| error.to_string())?
        .uid();
    if !metadata.file_type().is_dir() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
        return Err("RDS socket directory is not private to this user".to_owned());
    }
    Ok(path)
}

async fn cleanup_socket_dir(instance: &Instance) -> Result<(), String> {
    if !valid_socket_token(&instance.socket_token) {
        return Err("Invalid RDS socket token".to_owned());
    }
    let path = socket_dir(instance);
    let owner = tokio::fs::metadata("/proc/self")
        .await
        .map_err(|error| error.to_string())?
        .uid();
    match tokio::fs::symlink_metadata(&path).await {
        Ok(metadata)
            if metadata.file_type().is_dir()
                && metadata.uid() == owner
                && metadata.mode() & 0o077 == 0 =>
        {
            tokio::fs::remove_dir_all(path)
                .await
                .map_err(|error| error.to_string())
        }
        Ok(_) => Err("RDS socket directory is not private".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn rds_hostname(instance: &Instance) -> String {
    format!("{}.{}.rds.amazonaws.com", instance.id, instance.region)
}

fn subnet_group_path(root: &Path, group: &DbSubnetGroup) -> PathBuf {
    root.join(&group.account)
        .join(&group.region)
        .join("subnet-groups")
        .join(format!("{}.json", group.name))
}

async fn persist_subnet_group(root: &Path, group: &DbSubnetGroup) -> Result<(), String> {
    let path = subnet_group_path(root, group);
    tokio::fs::create_dir_all(path.parent().expect("subnet group parent"))
        .await
        .map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec(group).map_err(|error| error.to_string())?;
    let temp = path.with_extension("json.tmp");
    tokio::fs::write(&temp, bytes)
        .await
        .map_err(|error| error.to_string())?;
    tokio::fs::rename(temp, path)
        .await
        .map_err(|error| error.to_string())
}

fn load_subnet_groups(root: &Path) -> HashMap<Key, DbSubnetGroup> {
    let mut groups = HashMap::new();
    if let Ok(accounts) = std::fs::read_dir(root) {
        for account in accounts.flatten() {
            if let Ok(regions) = std::fs::read_dir(account.path()) {
                for region in regions.flatten() {
                    if let Ok(entries) = std::fs::read_dir(region.path().join("subnet-groups")) {
                        for entry in entries.flatten() {
                            if let Ok(bytes) = std::fs::read(entry.path()) {
                                if let Ok(group) = serde_json::from_slice::<DbSubnetGroup>(&bytes) {
                                    groups.insert(
                                        (
                                            group.account.clone(),
                                            group.region.clone(),
                                            group.name.clone(),
                                        ),
                                        group,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    groups
}

fn subnet_group_xml(group: &DbSubnetGroup) -> String {
    let mut xml = format!(
        "<DBSubnetGroupName>{}</DBSubnetGroupName><DBSubnetGroupDescription>{}</DBSubnetGroupDescription><SubnetGroupStatus>Complete</SubnetGroupStatus><VpcId>{}</VpcId><DBSubnetGroupArn>arn:aws:rds:{}:{}:subgrp:{}</DBSubnetGroupArn><SupportedNetworkTypes><member>IPV4</member></SupportedNetworkTypes><Subnets>",
        escape(&group.name), escape(&group.description), escape(&group.vpc_id),
        escape(&group.region), escape(&group.account), escape(&group.name)
    );
    for (id, zone) in &group.subnets {
        xml.push_str(&format!("<Subnet><SubnetIdentifier>{}</SubnetIdentifier><SubnetAvailabilityZone><Name>{}</Name></SubnetAvailabilityZone><SubnetStatus>Active</SubnetStatus></Subnet>", escape(id), escape(zone)));
    }
    xml.push_str("</Subnets>");
    xml
}

fn instance_xml(instance: &Instance) -> String {
    let visible_status = if instance.status == "restarting" {
        "creating"
    } else {
        &instance.status
    };
    let engine = if instance.cluster_id.is_some() {
        "aurora-postgresql"
    } else {
        "postgres"
    };
    let visible_port = instance
        .vpc
        .as_ref()
        .map_or(instance.port, |vpc| vpc.client_port);
    let mut xml = format!("<DBInstanceIdentifier>{}</DBInstanceIdentifier><DBInstanceClass>{}</DBInstanceClass><Engine>{}</Engine><DBInstanceStatus>{}</DBInstanceStatus><MasterUsername>{}</MasterUsername><AllocatedStorage>{}</AllocatedStorage><DBName>{}</DBName><Port>{}</Port>", escape(&instance.id), escape(&instance.class), engine, escape(visible_status), escape(&instance.username), instance.storage, escape(&instance.db_name), visible_port);
    if let Some(vpc) = &instance.vpc {
        xml.push_str(&format!("<DBSubnetGroup><DBSubnetGroupName>{}</DBSubnetGroupName><SubnetGroupStatus>Complete</SubnetGroupStatus></DBSubnetGroup><VpcSecurityGroups>", escape(&vpc.subnet_group)));
        for id in &vpc.security_group_ids {
            xml.push_str(&format!("<VpcSecurityGroupMembership><VpcSecurityGroupId>{}</VpcSecurityGroupId><Status>active</Status></VpcSecurityGroupMembership>", escape(id)));
        }
        xml.push_str("</VpcSecurityGroups><PubliclyAccessible>false</PubliclyAccessible>");
    }
    if let Some(cluster_id) = &instance.cluster_id {
        xml.push_str(&format!(
            "<DBClusterIdentifier>{}</DBClusterIdentifier>",
            escape(cluster_id)
        ));
    }
    if instance.status == "available" || instance.status == "backing-up" {
        xml.push_str(&format!(
            "<Endpoint><Address>{}</Address><Port>{}</Port></Endpoint>",
            if instance.vpc.is_some() {
                rds_hostname(instance)
            } else {
                "127.0.0.1".to_owned()
            },
            visible_port
        ));
    }
    xml.push_str(&format!(
        "<DbiResourceId>{}</DbiResourceId>",
        escape(&instance.dbi_resource_id)
    ));
    xml.push_str(&format!(
        "<DBInstanceArn>arn:aws:rds:{}:{}:db:{}</DBInstanceArn>",
        escape(&instance.region),
        escape(&instance.account),
        escape(&instance.id)
    ));
    if let Some(source) = &instance.replica_source {
        xml.push_str(&format!(
            "<ReadReplicaSourceDBInstanceIdentifier>{}</ReadReplicaSourceDBInstanceIdentifier>",
            escape(source)
        ));
    }
    xml
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn validate_scope(account: &str, region: &str) -> Result<(), Error> {
    let safe = |value: &str| {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    if safe(account) && safe(region) {
        Ok(())
    } else {
        Err(Error::invalid("Invalid account or region"))
    }
}

fn validate_id(value: &str) -> Result<(), Error> {
    if (1..=63).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Ok(())
    } else {
        Err(Error::invalid("Invalid DBInstanceIdentifier"))
    }
}

fn validate_user(value: &str) -> Result<(), Error> {
    if (1..=63).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        Ok(())
    } else {
        Err(Error::invalid("Invalid PostgreSQL identifier"))
    }
}

struct Input(BTreeMap<String, Vec<String>>);
impl Input {
    fn parse(req: &ServiceRequest) -> Self {
        let mut fields = BTreeMap::<String, Vec<String>>::new();
        for (name, value) in form_urlencoded::parse(req.uri.query().unwrap_or("").as_bytes())
            .chain(form_urlencoded::parse(&req.body))
        {
            fields
                .entry(name.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        Self(fields)
    }
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.first().map(String::as_str)
    }
    fn members(&self, prefix: &str) -> Vec<String> {
        let mut members: Vec<_> = self
            .0
            .iter()
            .filter_map(|(key, values)| {
                let index = key.strip_prefix(prefix)?.parse::<usize>().ok()?;
                if index == 0 {
                    return None;
                }
                Some((index, values.first()?.clone()))
            })
            .collect();
        members.sort_by_key(|(index, _)| *index);
        members.into_iter().map(|(_, value)| value).collect()
    }
    fn rds_members(&self, name: &str, member: &str) -> Vec<String> {
        let named = self.members(&format!("{name}.{member}."));
        if named.is_empty() {
            self.members(&format!("{name}.member."))
        } else {
            named
        }
    }
    fn required(&self, key: &str) -> Result<&str, Error> {
        self.get(key)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::invalid(format!("Missing {key}")))
    }
}

#[derive(Debug)]
struct Error {
    code: &'static str,
    message: String,
    status: u16,
}
impl Error {
    fn new(code: &'static str, message: impl Into<String>, status: u16) -> Self {
        Self {
            code,
            message: message.into(),
            status,
        }
    }
    fn invalid(message: impl Into<String>) -> Self {
        Self::new("InvalidParameterCombination", message, 400)
    }
    fn internal(message: impl Into<String>) -> Self {
        Self::new("InternalFailure", message, 500)
    }
    fn response(self, request_id: &str) -> Response {
        AwsError::new(self.code, self.message, self.status)
            .with_request_id(request_id.to_owned())
            .with_xml_namespace(XMLNS)
            .render(AwsProtocol::Query)
            .into_response()
    }
}

#[cfg(test)]
mod aurora_class_tests {
    use super::*;
    use axum::body::to_bytes;

    fn request(class: &str) -> ServiceRequest {
        ServiceRequest {
            method: axum::http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: Default::default(),
            body: format!(
                "Action=CreateDBInstance&DBInstanceIdentifier=class-writer&DBClusterIdentifier=missing-cluster&Engine=aurora-postgresql{class}"
            ).into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
            request_id: "aurora-class-contract".into(),
        }
    }

    #[tokio::test]
    async fn rejected_aurora_classes_return_query_errors_without_resources() {
        let root =
            std::env::temp_dir().join(format!("locallycloud-rds-class-{}", uuid::Uuid::new_v4()));
        let handler = RdsHandler::new(root.clone());
        for (class, code, message) in [
            ("", "MissingParameter", "Missing DBInstanceClass"),
            (
                "&DBInstanceClass=",
                "MissingParameter",
                "Missing DBInstanceClass",
            ),
            (
                "&DBInstanceClass=db.t3.micro",
                "InvalidParameterCombination",
                "not compatible with Engine=aurora-postgresql",
            ),
            (
                "&DBInstanceClass=db.r6g.large",
                "InvalidParameterCombination",
                "Local implementation supports only",
            ),
        ] {
            let response = handler.handle(request(class)).await;
            assert_eq!(response.status(), 400);
            assert!(response.headers()["content-type"]
                .to_str()
                .unwrap()
                .contains("xml"));
            let body = String::from_utf8(
                to_bytes(response.into_body(), 16 * 1024)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
            assert!(body.contains(message), "{body}");
            assert!(body.contains("aurora-class-contract"), "{body}");
            assert!(handler.instances.lock().await.is_empty());
            assert!(handler.clusters.lock().await.is_empty());
            assert!(!tokio::fs::try_exists(&root).await.unwrap());
        }
    }

    #[tokio::test]
    async fn medium_aurora_class_reaches_cluster_lookup_when_runtime_is_available() {
        if runtime::resolve_from_env().await.is_err() {
            return;
        }
        let root =
            std::env::temp_dir().join(format!("locallycloud-rds-medium-{}", uuid::Uuid::new_v4()));
        let handler = RdsHandler::new(root.clone());
        let response = handler
            .handle(request("&DBInstanceClass=db.t3.medium"))
            .await;
        assert_eq!(response.status(), 404);
        let body = String::from_utf8(
            to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            body.contains("<Code>DBClusterNotFoundFault</Code>"),
            "{body}"
        );
        assert!(handler.instances.lock().await.is_empty());
        assert!(!tokio::fs::try_exists(&root).await.unwrap());
    }
}

#[cfg(test)]
mod replica_tests {
    use super::*;
    use axum::body::Bytes;
    use axum::http::{HeaderMap, Method, Uri};

    fn input(fields: &[(&str, &str)]) -> Input {
        Input(
            fields
                .iter()
                .map(|(key, value)| (key.to_string(), vec![value.to_string()]))
                .collect(),
        )
    }

    async fn ready(handler: &RdsHandler, id: &str) -> Instance {
        for _ in 0..100 {
            if let Some(instance) = handler
                .instances
                .lock()
                .await
                .get(&(
                    "000000000000".to_owned(),
                    "us-east-1".to_owned(),
                    id.to_owned(),
                ))
                .cloned()
            {
                if instance.status == "available" {
                    return instance;
                }
                assert_ne!(instance.status, "failed", "{:?}", instance.error);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("instance {id} did not become available");
    }

    #[tokio::test]
    async fn aurora_restart_recreates_private_socket_and_preserves_rows() {
        let Ok(runtime) = runtime::resolve_from_env().await else {
            return;
        };
        let root =
            std::env::temp_dir().join(format!("locallycloud-rds-restart-{}", uuid::Uuid::new_v4()));
        let handler = RdsHandler::new(root.clone());
        let req = ServiceRequest {
            method: Method::POST,
            uri: Uri::from_static("/"),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            region: "us-east-1".to_owned(),
            account_id: "000000000000".to_owned(),
            request_id: "restart".to_owned(),
        };
        handler
            .create_cluster(
                &req,
                &input(&[
                    ("DBClusterIdentifier", "restart-cluster"),
                    ("Engine", "aurora-postgresql"),
                    ("MasterUsername", "releaseuser"),
                    ("MasterUserPassword", "ReleaseFixture9!"),
                    ("EnableHttpEndpoint", "true"),
                ]),
            )
            .await
            .unwrap();
        handler
            .create(
                &req,
                &input(&[
                    ("DBInstanceIdentifier", "restart-writer"),
                    ("DBClusterIdentifier", "restart-cluster"),
                    ("Engine", "aurora-postgresql"),
                    ("DBInstanceClass", "db.t3.medium"),
                ]),
            )
            .await
            .unwrap();
        let writer = ready(&handler, "restart-writer").await;
        sql_command(
            &runtime,
            &writer,
            "postgres",
            None,
            "CREATE TABLE restart_probe (value integer); INSERT INTO restart_probe VALUES (42)",
            &handler.directory(&writer),
        )
        .await
        .unwrap();
        handler.shutdown().await;
        assert!(!tokio::fs::try_exists(socket_dir(&writer)).await.unwrap());
        drop(handler);

        let restored = RdsHandler::new(root.clone());
        let endpoint = restored
            .resolve_cluster(
                &req.account_id,
                &req.region,
                "arn:aws:rds:us-east-1:000000000000:cluster:restart-cluster",
            )
            .await
            .unwrap();
        let restored_writer = restored
            .instances
            .lock()
            .await
            .get(&(
                req.account_id.clone(),
                req.region.clone(),
                "restart-writer".to_owned(),
            ))
            .cloned()
            .unwrap();
        let rows = sql_query(
            &runtime,
            &restored_writer,
            "SELECT value FROM restart_probe",
            &restored.directory(&restored_writer),
        )
        .await;
        restored.shutdown().await;
        tokio::fs::remove_dir_all(root).await.unwrap();
        assert_eq!(endpoint.status, "available");
        assert!(endpoint.http_endpoint_enabled);
        assert_eq!(endpoint.socket_dir, socket_dir(&writer));
        assert_eq!(restored_writer.class, "db.t3.medium");
        assert_eq!(rows.unwrap().trim(), "42");
    }

    #[tokio::test]
    async fn streaming_replica_is_read_only_until_promoted() {
        let Ok(runtime) = runtime::resolve_from_env().await else {
            return;
        };
        let root = std::env::temp_dir().join(format!(
            "lcr-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        let handler = RdsHandler::new(root.clone());
        let req = ServiceRequest {
            method: Method::POST,
            uri: Uri::from_static("/"),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            region: "us-east-1".to_owned(),
            account_id: "000000000000".to_owned(),
            request_id: "test".to_owned(),
        };
        handler
            .create(
                &req,
                &input(&[
                    ("DBInstanceIdentifier", "source"),
                    ("Engine", "postgres"),
                    ("MasterUsername", "localuser"),
                    ("MasterUserPassword", "localpassword"),
                ]),
            )
            .await
            .unwrap();
        let source = ready(&handler, "source").await;
        let source_dir = handler.directory(&source);
        sql_command(
            &runtime,
            &source,
            "postgres",
            None,
            "CREATE TABLE replica_probe (value integer); INSERT INTO replica_probe VALUES (42)",
            &source_dir,
        )
        .await
        .unwrap();

        handler
            .create_replica(
                &req,
                &input(&[
                    ("DBInstanceIdentifier", "replica"),
                    ("SourceDBInstanceIdentifier", "source"),
                ]),
            )
            .await
            .unwrap();
        let replica = ready(&handler, "replica").await;
        let replica_dir = handler.directory(&replica);
        assert_eq!(
            sql_query(
                &runtime,
                &replica,
                "SELECT value FROM replica_probe",
                &replica_dir
            )
            .await
            .unwrap()
            .trim(),
            "42"
        );
        assert!(sql_command(
            &runtime,
            &replica,
            "postgres",
            None,
            "INSERT INTO replica_probe VALUES (43)",
            &replica_dir
        )
        .await
        .is_err());
        assert!(handler
            .instance_by_arn("arn:aws:rds:us-east-1:000000000000:db:replica")
            .await
            .is_none());
        handler
            .promote_replica(&req, &input(&[("DBInstanceIdentifier", "replica")]))
            .await
            .unwrap();
        sql_command(
            &runtime,
            &replica,
            "postgres",
            None,
            "INSERT INTO replica_probe VALUES (43)",
            &replica_dir,
        )
        .await
        .unwrap();
        assert_eq!(
            sql_query(
                &runtime,
                &replica,
                "SELECT count(*) FROM replica_probe",
                &replica_dir
            )
            .await
            .unwrap()
            .trim(),
            "2"
        );
        assert!(handler
            .instance_by_arn("arn:aws:rds:us-east-1:000000000000:db:replica")
            .await
            .is_some());
        handler.shutdown().await;
        let _ = tokio::fs::remove_dir_all(root).await;
    }
}

#[cfg(test)]
mod vpc_tests {
    use super::*;
    use axum::body::{to_bytes, Bytes};
    use axum::http::{HeaderMap, Method, Uri};

    fn request(body: String) -> ServiceRequest {
        ServiceRequest {
            method: Method::POST,
            uri: Uri::from_static("/"),
            headers: HeaderMap::new(),
            body: Bytes::from(body),
            region: "us-east-1".to_owned(),
            account_id: "000000000000".to_owned(),
            request_id: "test".to_owned(),
        }
    }

    async fn call_ec2(ec2: &Ec2Handler, body: String) -> String {
        let response = ec2.handle(request(body)).await;
        assert_eq!(response.status(), 200);
        String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    fn xml_value<'a>(xml: &'a str, name: &str) -> &'a str {
        xml.split_once(&format!("<{name}>"))
            .unwrap()
            .1
            .split_once(&format!("</{name}>"))
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn deep_state_path_uses_private_short_socket_and_stable_resource_id() {
        let root = std::env::temp_dir()
            .join(format!("lcr-deep-{}", uuid::Uuid::new_v4()))
            .join("x".repeat(90))
            .join("y".repeat(90));
        let handler = RdsHandler::new(root.clone());
        let instance = Instance {
            id: "orders-db".to_owned(),
            account: "000000000000".to_owned(),
            region: "us-east-1".to_owned(),
            username: "orders".to_owned(),
            db_name: "orders".to_owned(),
            class: "db.t3.micro".to_owned(),
            storage: 20,
            port: 5432,
            status: "creating".to_owned(),
            error: None,
            replica_source: None,
            cluster_id: None,
            vpc: None,
            socket_token: new_socket_token(),
            dbi_resource_id: new_dbi_resource_id(),
        };
        let socket = prepare_socket_dir(&instance).await.unwrap();
        assert!(socket.as_os_str().len() < 80);
        let listener =
            std::os::unix::net::UnixListener::bind(socket.join(".s.PGSQL.65535")).unwrap();
        drop(listener);
        let key = (
            instance.account.clone(),
            instance.region.clone(),
            instance.id.clone(),
        );
        handler.instances.lock().await.insert(key, instance.clone());
        let arn = "arn%3Aaws%3Ards%3Aus-east-1%3A000000000000%3Adb%3Aorders-db";
        let response = handler
            .handle(request(format!(
                "Action=DescribeDBInstances&DBInstanceIdentifier={arn}"
            )))
            .await;
        assert_eq!(response.status(), 200);
        let body = String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains(&format!(
            "<DbiResourceId>{}</DbiResourceId>",
            instance.dbi_resource_id
        )));
        let response = handler.handle(request(format!("Action=DescribeDBInstances&Filters.Filter.1.Name=dbi-resource-id&Filters.Filter.1.Values.Value.1={}", instance.dbi_resource_id))).await;
        assert_eq!(response.status(), 200);
        let body = String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("<DBInstanceIdentifier>orders-db</DBInstanceIdentifier>"));
        let response = handler.handle(request("Action=DescribeDBInstances&Filters.Filter.1.Name=dbi-resource-id&Filters.Filter.1.Values.Value.1=db-NOTFOUND".to_owned())).await;
        let body = String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!body.contains("<DBInstanceIdentifier>"));
        cleanup_socket_dir(&instance).await.unwrap();
    }

    #[tokio::test]
    async fn subnet_group_roundtrip_and_az_validation() {
        let root = std::env::temp_dir().join(format!("lcr-vpc-{}", uuid::Uuid::new_v4()));
        let ec2 = Arc::new(Ec2Handler::default());
        let vpc_xml = call_ec2(&ec2, "Action=CreateVpc&CidrBlock=10.42.0.0%2F16".to_owned()).await;
        let vpc = xml_value(&vpc_xml, "vpcId");
        let subnet_a = call_ec2(&ec2, format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.42.1.0%2F24&AvailabilityZone=us-east-1a")).await;
        let subnet_b = call_ec2(&ec2, format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.42.2.0%2F24&AvailabilityZone=us-east-1b")).await;
        let a = xml_value(&subnet_a, "subnetId");
        let b = xml_value(&subnet_b, "subnetId");
        let handler = RdsHandler::new(root.clone());
        handler.attach_ec2(ec2.clone()).await;
        let invalid = handler.handle(request(format!("Action=CreateDBSubnetGroup&DBSubnetGroupName=orders&DBSubnetGroupDescription=orders&SubnetIds.member.1={a}"))).await;
        assert_eq!(invalid.status(), 400);
        let created = handler.handle(request(format!("Action=CreateDBSubnetGroup&DBSubnetGroupName=orders&DBSubnetGroupDescription=orders&SubnetIds.SubnetIdentifier.1={a}&SubnetIds.SubnetIdentifier.2={b}"))).await;
        assert_eq!(created.status(), 200);
        let body = String::from_utf8(
            to_bytes(created.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains(&format!("<VpcId>{vpc}</VpcId>")));
        assert!(body.contains("<SubnetGroupStatus>Complete</SubnetGroupStatus>"));
        let arn = "arn:aws:rds:us-east-1:000000000000:subgrp:orders";
        let tags = handler
            .handle(request(format!(
                "Action=ListTagsForResource&ResourceName={arn}"
            )))
            .await;
        assert_eq!(tags.status(), 200);
        let body = String::from_utf8(
            to_bytes(tags.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("<TagList/>") && body.contains("<ListTagsForResourceResult>"));
        let foreign = handler.handle(request("Action=ListTagsForResource&ResourceName=arn:aws:rds:us-west-2:000000000000:subgrp:orders".to_owned())).await;
        assert_eq!(foreign.status(), 400);
        let restarted = RdsHandler::new(root.clone());
        let described = restarted
            .handle(request(
                "Action=DescribeDBSubnetGroups&DBSubnetGroupName=orders".to_owned(),
            ))
            .await;
        assert_eq!(described.status(), 200);
        let deleted = restarted
            .handle(request(
                "Action=DeleteDBSubnetGroup&DBSubnetGroupName=orders".to_owned(),
            ))
            .await;
        assert_eq!(deleted.status(), 200);
        restarted.attach_ec2(ec2).await;
        let legacy = restarted.handle(request(format!(
            "Action=CreateDBSubnetGroup&DBSubnetGroupName=orders&DBSubnetGroupDescription=orders&SubnetIds.member.1={a}&SubnetIds.member.2={b}"
        ))).await;
        assert_eq!(legacy.status(), 200);
        let _ = tokio::fs::remove_dir_all(root).await;
    }
}

#[cfg(test)]
mod inventory_tests {
    use super::*;
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    #[tokio::test]
    async fn inventory_waiting_on_snapshots_does_not_block_cluster_deletion() {
        let root = std::env::temp_dir().join(format!(
            "locallycloud-rds-inventory-{}",
            uuid::Uuid::new_v4()
        ));
        let handler = RdsHandler::new(root.clone());
        let request = ServiceRequest {
            method: axum::http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: Default::default(),
            body: "Action=CreateDBCluster&DBClusterIdentifier=inventory-cluster&Engine=aurora-postgresql&MasterUsername=admin&MasterUserPassword=test-password".into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
            request_id: "inventory-regression".into(),
        };
        let input = Input::parse(&request);
        handler.create_cluster(&request, &input).await.unwrap();
        let snapshots = handler.snapshots.lock().await;
        let inventory = handler.resource_regions(&request.account_id);
        tokio::pin!(inventory);
        poll_fn(|cx| {
            assert!(inventory.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let deleted = tokio::time::timeout(
            Duration::from_secs(2),
            handler.delete_cluster(&request, &input),
        )
        .await;
        drop(snapshots);
        assert!(deleted.expect("inventory held an unrelated lock").is_ok());
        assert!(inventory.await.unwrap().is_empty());
        tokio::fs::remove_dir_all(root).await.unwrap();
    }
}
