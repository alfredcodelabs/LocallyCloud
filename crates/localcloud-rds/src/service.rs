use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use localcloud_core::error_mapping::AwsError;
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
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
            socket_dir: self.directory(&instance).join("socket"),
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
        Self {
            root,
            instances: Arc::new(Mutex::new(instances)),
            snapshots: Arc::new(Mutex::new(snapshots)),
            clusters: Arc::new(Mutex::new(clusters)),
            jobs: Mutex::new(Vec::new()),
        }
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
            socket_dir: self.directory(&writer).join("socket"),
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
        let class = input.get("DBInstanceClass").unwrap_or("db.t3.micro");
        if class != "db.t3.micro" {
            return Err(Error::invalid("Only db.t3.micro is supported"));
        }
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
        for field in [
            "DBSubnetGroupName",
            "VpcSecurityGroupIds.member.1",
            "KmsKeyId",
            "DBClusterIdentifier",
        ] {
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
                    completed.status = "available".to_owned();
                    if let Err(reason) = persist(&directory, &completed).await {
                        stop_instance(&runtime, &directory).await;
                        completed.status = "failed".to_owned();
                        completed.error =
                            Some(format!("Unable to persist instance metadata: {reason}"));
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
            if source.cluster_id.is_some() {
                return Err(Error::invalid(
                    "Aurora cluster members cannot use CreateDBInstanceReadReplica",
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
        let source_dir = self.directory(&source);
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
            let result =
                provision_replica(&runtime, &source_dir, source.port, &directory, &instance).await;
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
        if let Err(error) = persist(&directory, instance).await {
            instance.status = "failed".to_owned();
            instance.error = Some(format!("Unable to persist DB instance status: {error}"));
        }
        Some(instance.clone())
    }

    async fn describe(&self, req: &ServiceRequest, input: &Input) -> Result<String, Error> {
        let wanted = input.get("DBInstanceIdentifier");
        let instances: Vec<Instance> = self
            .instances
            .lock()
            .await
            .values()
            .filter(|instance| {
                instance.account == req.account_id
                    && instance.region == req.region
                    && wanted.is_none_or(|id| id == instance.id)
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
                    let _ = tokio::fs::remove_dir_all(directory.join("socket")).await;
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
            let _ = persist(&self.directory(instance), instance).await;
        }
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
    async fn handle(&self, request: ServiceRequest) -> Response {
        let input = Input::parse(&request);
        let action = input.get("Action").unwrap_or("Unknown");
        let result = match action {
            "CreateDBCluster" => self.create_cluster(&request, &input).await,
            "DescribeDBClusters" => self.describe_clusters(&request, &input).await,
            "DeleteDBCluster" => self.delete_cluster(&request, &input).await,
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
) -> Result<Arc<RdsHandler>, localcloud_state::StateError> {
    let root = match std::env::var_os("LOCALCLOUD_RDS_DATA_DIR").filter(|value| !value.is_empty()) {
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(localcloud_state::StateError::InvalidPath(
                    "LOCALCLOUD_RDS_DATA_DIR",
                ));
            }
            path
        }
        None => localcloud_state::StateDb::data_dir()?.join("rds"),
    };
    localcloud_state::StateDb::private_dir(&root)?;
    let handler = Arc::new(RdsHandler::new(root));
    let mut metadata = ServiceMetadata::new(AwsProtocol::Query, None);
    metadata.known_actions = [
        "CreateDBCluster",
        "DescribeDBClusters",
        "DeleteDBCluster",
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
        &source_dir.join("socket").to_string_lossy(),
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
    let socket = directory.join("socket");
    tokio::fs::create_dir_all(&socket)
        .await
        .map_err(|error| error.to_string())?;
    tokio::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|error| error.to_string())?;
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
    let socket = directory.join("socket");
    tokio::fs::create_dir_all(&socket)
        .await
        .map_err(|error| error.to_string())?;
    tokio::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|error| error.to_string())?;
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
    let socket_dir = directory.join("socket");
    tokio::fs::create_dir_all(&socket_dir)
        .await
        .map_err(|error| error.to_string())?;
    tokio::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|error| error.to_string())?;
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
    source_dir: &Path,
    source_port: u16,
    directory: &Path,
    instance: &Instance,
) -> Result<(), String> {
    let socket = directory.join("socket");
    tokio::fs::create_dir_all(&socket)
        .await
        .map_err(|error| error.to_string())?;
    tokio::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|error| error.to_string())?;
    let data = directory.join("data");
    let mut cmd = Command::new(runtime.bin_dir.join("pg_basebackup"));
    cmd.args([
        "-h",
        &source_dir.join("socket").to_string_lossy(),
        "-p",
        &source_port.to_string(),
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
    directory: &Path,
) -> Result<String, String> {
    let mut cmd = Command::new(runtime.bin_dir.join("psql"));
    cmd.args([
        "-X",
        "-A",
        "-t",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        &directory.join("socket").to_string_lossy(),
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
    directory: &Path,
) -> Result<(), String> {
    let port = instance.port.to_string();
    let socket = directory.join("socket");
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
    let mut xml = format!("<DBInstanceIdentifier>{}</DBInstanceIdentifier><DBInstanceClass>{}</DBInstanceClass><Engine>{}</Engine><DBInstanceStatus>{}</DBInstanceStatus><MasterUsername>{}</MasterUsername><AllocatedStorage>{}</AllocatedStorage><DBName>{}</DBName><Port>{}</Port>", escape(&instance.id), escape(&instance.class), engine, escape(visible_status), escape(&instance.username), instance.storage, escape(&instance.db_name), instance.port);
    if let Some(cluster_id) = &instance.cluster_id {
        xml.push_str(&format!(
            "<DBClusterIdentifier>{}</DBClusterIdentifier>",
            escape(cluster_id)
        ));
    }
    if instance.status == "available" || instance.status == "backing-up" {
        xml.push_str(&format!(
            "<Endpoint><Address>127.0.0.1</Address><Port>{}</Port></Endpoint>",
            instance.port
        ));
    }
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
