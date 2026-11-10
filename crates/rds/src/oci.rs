//! PostgreSQL tools and durable guests backed by explicitly installed runtime packs.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

use locallycloud_compute::runtime::{
    ComputeRuntime, RuntimeError, TaskMount, TaskSpec, TaskState, TaskUser,
};
use locallycloud_compute::runtime_pack::{read_guest_file, RuntimePack, RuntimePacks};
use locallycloud_compute::youki::YoukiRuntime;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_postgres::{NoTls, SimpleQueryMessage};

use super::{Instance, PostgresRuntime};

const RUNTIME: &str = "postgres16";
const MEMORY_MB: u32 = 512;

#[derive(Clone)]
pub(super) enum Runtime {
    Host(PostgresRuntime),
    Oci(Arc<Engine>),
}
impl Runtime {
    pub fn command(&self, tool: &str) -> Command {
        Command {
            runtime: self.clone(),
            tool: tool.into(),
            args: Vec::new(),
            password: None,
        }
    }
    pub async fn quiesce(&self, directory: &Path) -> Result<(), String> {
        match self {
            Self::Host(_) => Ok(()),
            Self::Oci(engine) => engine.recover(Some(directory)).await,
        }
    }
    pub async fn prepare(&self) -> Result<(), String> {
        match self {
            Self::Host(_) => Ok(()),
            Self::Oci(engine) => {
                engine.available().await?;
                engine.source().await.map(drop)
            }
        }
    }
}
pub(super) struct Command {
    runtime: Runtime,
    tool: String,
    args: Vec<String>,
    password: Option<String>,
}
impl Command {
    pub fn args(&mut self, args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> &mut Self {
        self.args.extend(
            args.into_iter()
                .map(|s| s.as_ref().to_string_lossy().into_owned()),
        );
        self
    }
    pub fn env(&mut self, key: &str, value: &str) -> &mut Self {
        if key == "PGPASSWORD" {
            self.password = Some(value.into());
        }
        self
    }
    pub async fn output(self) -> Result<Output, String> {
        match self.runtime {
            Runtime::Host(runtime) => {
                let binary = runtime
                    .tool(&self.tool)
                    .ok_or("unsupported PostgreSQL tool")?;
                let mut command = tokio::process::Command::new(binary);
                command.args(self.args).kill_on_drop(true);
                if let Some(password) = self.password {
                    command.env("PGPASSWORD", password);
                }
                tokio::time::timeout(Duration::from_secs(60), command.output())
                    .await
                    .map_err(|_| "PostgreSQL command timed out".to_owned())?
                    .map_err(|e| e.to_string())
            }
            Runtime::Oci(engine) => {
                engine
                    .run(&self.tool, &self.args, self.password.as_deref())
                    .await
            }
        }
    }
}

struct Guest {
    lease: TaskLease,
    _source: Option<Arc<RuntimePack>>,
    proxy: JoinHandle<()>,
}
struct Slot {
    gate: Arc<Semaphore>,
    guest: Mutex<Option<Guest>>,
}
pub(super) struct Engine {
    root: PathBuf,
    root_lease: Arc<std::fs::File>,
    recovered: tokio::sync::OnceCell<()>,
    packs: Arc<RuntimePacks>,
    runtime: tokio::sync::OnceCell<Arc<YoukiRuntime>>,
    slots: Mutex<HashMap<PathBuf, Arc<Slot>>>,
}
impl Engine {
    pub fn new(root: PathBuf, root_lease: Arc<std::fs::File>) -> Self {
        let directory = std::env::var_os("LOCALLYCLOUD_RUNTIME_PACKS_DIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("LOCALLYCLOUD_WORK_DIR")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| locallycloud_compute::private_dir::work_dir("lambda"))
                    .join("runtime-packs")
            });
        Self {
            root,
            root_lease,
            recovered: tokio::sync::OnceCell::new(),
            packs: Arc::new(RuntimePacks::new(directory)),
            runtime: tokio::sync::OnceCell::new(),
            slots: Mutex::new(HashMap::new()),
        }
    }
    pub async fn ensure_recovered(&self) -> Result<(), String> {
        self.recovered
            .get_or_try_init(|| async { self.recover(None).await })
            .await
            .map(|_| ())
    }
    pub async fn available(&self) -> Result<(), String> {
        self.compute().await.map(drop)
    }
    async fn compute(&self) -> Result<Arc<YoukiRuntime>, String> {
        self.runtime
            .get_or_try_init(|| async {
                tokio::task::spawn_blocking(YoukiRuntime::discover)
                    .await
                    .map_err(|error| error.to_string())?
                    .map(Arc::new)
                    .ok_or_else(|| {
                        "Rootless OCI runtime unavailable; install crun or youki to use RDS"
                            .to_owned()
                    })
            })
            .await
            .cloned()
    }
    fn architecture() -> Result<&'static str, String> {
        match std::env::consts::ARCH {
            "x86_64" => Ok("x86_64"),
            "aarch64" => Ok("arm64"),
            _ => Err("unsupported RDS runtime architecture".into()),
        }
    }
    async fn intent(
        &self,
        id: &str,
        resource: &Path,
        image: Arc<RuntimePack>,
    ) -> Result<TaskLease, String> {
        let directory = self.root.join(".oci-tasks");
        tokio::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)
            .await
            .map_err(|e| e.to_string())?;
        let path = directory.join(format!("{id}.json"));
        let record = Intent {
            schema: 1,
            id: id.into(),
            resource: resource.to_path_buf(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .await
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes).await.map_err(|e| e.to_string())?;
        file.sync_all().await.map_err(|e| e.to_string())?;
        tokio::fs::File::open(&directory)
            .await
            .map_err(|e| e.to_string())?
            .sync_all()
            .await
            .map_err(|e| e.to_string())?;
        Ok(TaskLease {
            runtime: self.compute().await?,
            path,
            id: id.into(),
            image,
            root_lease: self.root_lease.clone(),
            armed: true,
        })
    }
    pub async fn recover(&self, resource: Option<&Path>) -> Result<(), String> {
        let mut entries = match tokio::fs::read_dir(self.root.join(".oci-tasks")).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Some(resource) = resource {
                    self.slots
                        .lock()
                        .map_err(|_| "RDS guest inventory unavailable")?
                        .remove(resource);
                }
                return Ok(());
            }
            Err(error) => return Err(error.to_string()),
        };
        let mut count = 0;
        while let Some(entry) = entries.next_entry().await.map_err(|e| e.to_string())? {
            count += 1;
            if count > 4096 {
                return Err("RDS task recovery exceeds limit; data retained".into());
            }
            let metadata = entry.metadata().await.map_err(|e| e.to_string())?;
            if !metadata.is_file() || metadata.len() > 16384 {
                return Err("RDS task journal invalid; data retained".into());
            }
            let record: Intent = serde_json::from_slice(
                &tokio::fs::read(entry.path())
                    .await
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|_| "RDS task journal invalid")?;
            if resource.is_some_and(|resource| resource != record.resource) {
                continue;
            }
            let valid = record.id.strip_prefix("rds-").is_some_and(|suffix| {
                super::valid_socket_token(suffix)
                    || suffix
                        .strip_prefix("tool-")
                        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
            });
            if record.schema != 1
                || !valid
                || entry.file_name().to_str() != Some(format!("{}.json", record.id).as_str())
                || !record.resource.starts_with(&self.root)
            {
                return Err("RDS task journal scope invalid; data retained".into());
            }
            let runtime = self.compute().await?;
            Self::dispose(&runtime, &record.id).await?;
            let slots: Vec<_> = self
                .slots
                .lock()
                .map_err(|_| "RDS guest inventory unavailable")?
                .values()
                .cloned()
                .collect();
            for slot in slots {
                let guest = {
                    let mut guest = slot
                        .guest
                        .lock()
                        .map_err(|_| "RDS guest lock unavailable")?;
                    if guest
                        .as_ref()
                        .is_some_and(|guest| guest.lease.id == record.id)
                    {
                        guest.take()
                    } else {
                        None
                    }
                };
                if let Some(mut guest) = guest {
                    guest.proxy.abort();
                    let _ = guest.proxy.await;
                    guest.lease.armed = false;
                }
            }
            remove_intent(&entry.path()).await?;
        }
        if let Some(resource) = resource {
            self.slots
                .lock()
                .map_err(|_| "RDS guest inventory unavailable")?
                .remove(resource);
        }
        Ok(())
    }
    async fn source(&self) -> Result<Arc<RuntimePack>, String> {
        self.packs.load(RUNTIME,Self::architecture()?).await.map_err(|_|"PostgreSQL runtime pack unavailable or invalid; run locallycloud runtime install postgres16".into())
    }
    fn slot(&self, directory: &Path) -> Result<Arc<Slot>, String> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| "RDS guest inventory unavailable")?;
        Ok(slots
            .entry(directory.to_owned())
            .or_insert_with(|| {
                Arc::new(Slot {
                    gate: Arc::new(Semaphore::new(1)),
                    guest: Mutex::new(None),
                })
            })
            .clone())
    }
    async fn directory(&self, data: &str) -> Result<PathBuf, String> {
        let path = Path::new(data);
        if path.file_name().and_then(|v| v.to_str()) != Some("data") {
            return Err("invalid RDS data directory".into());
        }
        let parent = path.parent().ok_or("missing RDS instance directory")?;
        let root = tokio::fs::canonicalize(&self.root)
            .await
            .map_err(|e| e.to_string())?;
        let canonical = tokio::fs::canonicalize(&parent)
            .await
            .map_err(|e| e.to_string())?;
        if !canonical.starts_with(&root) || canonical == root || canonical != parent {
            return Err("RDS data path is outside its owned directory".into());
        }
        Ok(canonical)
    }
    async fn instance(directory: &Path) -> Result<Instance, String> {
        let bytes = tokio::fs::read(directory.join("meta.json"))
            .await
            .map_err(|_| "RDS instance metadata unavailable")?;
        if bytes.len() > 65536 {
            return Err("RDS instance metadata exceeds limit".into());
        }
        serde_json::from_slice(&bytes).map_err(|_| "RDS instance metadata invalid".into())
    }
    async fn image(
        &self,
        directory: &Path,
    ) -> Result<(Arc<RuntimePack>, Option<Arc<RuntimePack>>), String> {
        let snapshot = directory.join("oci-image");
        if tokio::fs::try_exists(snapshot.join("manifest.json"))
            .await
            .map_err(|e| e.to_string())?
        {
            let arch = Self::architecture()?;
            let root_lease = self.root_lease.clone();
            return tokio::task::spawn_blocking(move || {
                let _root_lease = root_lease;
                RuntimePack::load_snapshot(&snapshot, RUNTIME, arch)
                    .map(|image| (Arc::new(image), None))
                    .map_err(|_| {
                        "RDS owned runtime image invalid; preserve the instance for recovery"
                            .to_owned()
                    })
            })
            .await
            .map_err(|e| e.to_string())?;
        }
        if tokio::fs::try_exists(&snapshot)
            .await
            .map_err(|e| e.to_string())?
        {
            return Err(
                "RDS runtime preparation was interrupted; preserve the instance for recovery"
                    .into(),
            );
        }
        let source = self.source().await?;
        let copying = source.clone();
        let arch = Self::architecture()?;
        let root_lease = self.root_lease.clone();
        let image = tokio::task::spawn_blocking(move || {
            let _root_lease = root_lease;
            copying.snapshot(&snapshot).map_err(|e| e.to_string())?;
            RuntimePack::load_snapshot(&snapshot, RUNTIME, arch)
                .map(Arc::new)
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())??;
        Ok((image, Some(source)))
    }
    async fn spec(
        image: &RuntimePack,
        rootfs: PathBuf,
        command: Vec<String>,
        mounts: Vec<TaskMount>,
    ) -> Result<TaskSpec, String> {
        let root = rootfs.clone();
        let user = tokio::task::spawn_blocking(move || {
            let passwd = String::from_utf8(
                read_guest_file(&root, Path::new("/etc/passwd"), 65536)
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let fields: Vec<_> = passwd
                .lines()
                .find(|line| line.starts_with("postgres:"))
                .ok_or("runtime image lacks PostgreSQL user")?
                .split(':')
                .collect();
            let uid = fields
                .get(2)
                .ok_or("invalid runtime user")?
                .parse()
                .map_err(|_| "invalid runtime UID")?;
            let gid = fields
                .get(3)
                .ok_or("invalid runtime group")?
                .parse()
                .map_err(|_| "invalid runtime GID")?;
            Ok::<_, String>(TaskUser { uid, gid })
        })
        .await
        .map_err(|e| e.to_string())??;
        Ok(TaskSpec {
            mounts,
            user: Some(user),
            name: "rds-postgresql".into(),
            image: rootfs.display().to_string(),
            command,
            env: image
                .environment
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            memory_mb: MEMORY_MB,
            vcpu_count: 1,
        })
    }
    async fn dispose(runtime: &YoukiRuntime, id: &str) -> Result<(), String> {
        match runtime.stop_task(id).await {
            Ok(_) | Err(RuntimeError::TaskAlreadyCompleted { .. }) => {}
            Err(RuntimeError::TaskNotFound { .. }) => {
                if !runtime
                    .reconcile_orphaned_task(id)
                    .await
                    .map_err(|e| e.to_string())?
                {
                    return Err("RDS orphaned task could not be reconciled".into());
                }
            }
            Err(error) => return Err(error.to_string()),
        }
        runtime.release_task(id).await.map_err(|e| e.to_string())
    }
    async fn finite(
        &self,
        image: Arc<RuntimePack>,
        rootfs: PathBuf,
        tool: &str,
        args: Vec<String>,
        mounts: Vec<TaskMount>,
    ) -> Result<Output, String> {
        let runtime = self.compute().await?;
        let id = format!("rds-tool-{}", uuid::Uuid::new_v4());
        let mut command = vec![format!("/usr/lib/postgresql/16/bin/{tool}")];
        command.extend(args);
        let spec = Self::spec(&image, rootfs.clone(), command, mounts).await?;
        let resource = if rootfs
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("backup-guest-"))
        {
            rootfs
                .parent()
                .ok_or("backup root has no owner")?
                .to_path_buf()
        } else {
            rootfs
                .parent()
                .and_then(Path::parent)
                .ok_or("runtime root has no owner")?
                .to_path_buf()
        };
        let mut lease = self.intent(&id, &resource, image.clone()).await?;
        let result = async {
            runtime
                .start_task_isolated(&id, &spec)
                .await
                .map_err(|e| e.to_string())?;
            tokio::time::timeout(Duration::from_secs(60), async {
                loop {
                    match runtime.task_state(&id).await.map_err(|e| e.to_string())? {
                        TaskState::Running => tokio::time::sleep(Duration::from_millis(25)).await,
                        TaskState::Completed => return Ok(true),
                        _ => return Ok(false),
                    }
                }
            })
            .await
            .map_err(|_| "RDS tool timed out".to_owned())?
        }
        .await;
        let text = runtime.get_output(&id).await.unwrap_or_default();
        lease.finish().await?;
        result.map(|success| output(if success { 0 } else { 1 }, text))
    }
    async fn run(
        &self,
        tool: &str,
        args: &[String],
        password: Option<&str>,
    ) -> Result<Output, String> {
        match tool {
            "psql" => Self::query(args, password).await.map(|s| output(0, s)),
            "initdb" => {
                let directory = self.directory(required(args, "-D")?).await?;
                let slot = self.slot(&directory)?;
                let _permit = slot
                    .gate
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| "RDS instance closed")?;
                let (image, _source) = self.image(&directory).await?;
                let data = directory.join("data");
                tokio::fs::create_dir_all(&data)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut rewritten = args.to_vec();
                replace(&mut rewritten, "-D", "/data")?;
                replace(&mut rewritten, "--pwfile", "/password")?;
                let mounts = vec![
                    mount(data, "/data", false),
                    mount(directory.join("password"), "/password", true),
                ];
                self.finite(
                    image,
                    directory.join("oci-image/rootfs"),
                    "initdb",
                    rewritten,
                    mounts,
                )
                .await
            }
            "pg_ctl" => {
                let directory = self.directory(required(args, "-D")?).await?;
                let slot = self.slot(&directory)?;
                let _permit = slot
                    .gate
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| "RDS instance closed")?;
                let action = args
                    .iter()
                    .find(|s| matches!(s.as_str(), "start" | "stop" | "status" | "promote"))
                    .ok_or("unsupported PostgreSQL lifecycle operation")?;
                match action.as_str() {
                    "start" => self
                        .start(&directory, &slot)
                        .await
                        .map(|_| output(0, String::new())),
                    "stop" => self
                        .stop(&directory, &slot)
                        .await
                        .map(|_| output(0, String::new())),
                    "status" => {
                        let id = task_id(&Self::instance(&directory).await?)?;
                        let runtime = self.compute().await?;
                        let known = slot
                            .guest
                            .lock()
                            .map_err(|_| "RDS guest lock unavailable")?
                            .is_some();
                        if known {
                            return runtime
                                .task_state(&id)
                                .await
                                .map(|state| {
                                    output(
                                        if state == TaskState::Running { 0 } else { 3 },
                                        String::new(),
                                    )
                                })
                                .map_err(|e| e.to_string());
                        }
                        if !runtime
                            .reconcile_orphaned_task(&id)
                            .await
                            .map_err(|e| e.to_string())?
                        {
                            return Err("RDS orphan cleanup is not confirmed".into());
                        }
                        Ok(output(3, String::new()))
                    }
                    "promote" => {
                        let instance = Self::instance(&directory).await?;
                        let query = vec![
                            "-h".into(),
                            super::socket_dir(&instance).display().to_string(),
                            "-p".into(),
                            instance.port.to_string(),
                            "-U".into(),
                            instance.username,
                            "-d".into(),
                            "postgres".into(),
                            "-c".into(),
                            "SELECT pg_promote(true, 30)".into(),
                        ];
                        Self::query(&query, None).await.map(|s| output(0, s))
                    }
                    _ => Err("unsupported PostgreSQL lifecycle operation".into()),
                }
            }
            "pg_basebackup" => self.backup(args).await,
            _ => Err("unsupported PostgreSQL OCI tool".into()),
        }
    }
    async fn query(args: &[String], password: Option<&str>) -> Result<String, String> {
        let mut config = tokio_postgres::Config::new();
        config
            .host(required(args, "-h")?)
            .port(
                required(args, "-p")?
                    .parse()
                    .map_err(|_| "invalid PostgreSQL port")?,
            )
            .user(required(args, "-U")?)
            .dbname(required(args, "-d")?)
            .connect_timeout(Duration::from_secs(5));
        if let Some(password) = password {
            config.password(password);
        }
        let (client, connection) = config
            .connect(NoTls)
            .await
            .map_err(|e| format!("PostgreSQL connection failed: {e}"))?;
        let connection = tokio::spawn(connection);
        let result = tokio::time::timeout(
            Duration::from_secs(60),
            client.simple_query(required(args, "-c")?),
        )
        .await
        .map_err(|_| "PostgreSQL query timed out".to_owned())
        .and_then(|result| result.map_err(|e| format!("PostgreSQL query failed: {e}")));
        drop(client);
        connection.abort();
        let _ = connection.await;
        result.map(|messages| {
            messages
                .iter()
                .filter_map(|message| match message {
                    SimpleQueryMessage::Row(row) => Some(
                        (0..row.len())
                            .map(|i| row.get(i).unwrap_or(""))
                            .collect::<Vec<_>>()
                            .join("|"),
                    ),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
    }
    async fn start(&self, directory: &Path, slot: &Slot) -> Result<(), String> {
        if slot
            .guest
            .lock()
            .map_err(|_| "RDS guest lock unavailable")?
            .is_some()
        {
            return Err("RDS guest already owned".into());
        }
        let instance = Self::instance(directory).await?;
        let id = task_id(&instance)?;
        let runtime = self.compute().await?;
        if !runtime
            .reconcile_orphaned_task(&id)
            .await
            .map_err(|e| e.to_string())?
        {
            return Err("RDS previous guest termination is not confirmed".into());
        }
        let (image, source) = self.image(directory).await?;
        let version = tokio::fs::read_to_string(directory.join("data/PG_VERSION"))
            .await
            .map_err(|_| "PostgreSQL data version unavailable")?;
        if version.trim() != "16" {
            return Err("RDS OCI currently requires PostgreSQL16 data; preserve this instance for migration".into());
        }
        let socket = super::prepare_socket_dir(&instance).await?;
        let mut mounts = vec![
            mount(directory.join("data"), "/data", false),
            mount(socket, "/socket", false),
        ];
        if instance.replica_source.is_some() {
            if let Ok(source) = tokio::fs::read_to_string(directory.join("replica-socket")).await {
                let source = PathBuf::from(source);
                validate_socket(&source)?;
                mounts.push(mount(source, "/source-socket", true));
            }
        }
        let spec = Self::spec(
            &image,
            directory.join("oci-image/rootfs"),
            vec![
                "/usr/lib/postgresql/16/bin/postgres".into(),
                "-D".into(),
                "/data".into(),
                "-p".into(),
                instance.port.to_string(),
                "-c".into(),
                "listen_addresses=127.0.0.1".into(),
                "-c".into(),
                "unix_socket_directories=/socket".into(),
            ],
            mounts,
        )
        .await?;
        let listener = TcpListener::bind(("127.0.0.1", instance.port))
            .await
            .map_err(|_| "RDS endpoint port is unavailable")?;
        let mut lease = self.intent(&id, directory, image.clone()).await?;
        let result = async {
            runtime
                .start_isolated_service(&id, &spec, instance.port, Duration::from_secs(30))
                .await
                .map_err(|e| e.to_string())?;
            let mut config = tokio_postgres::Config::new();
            config
                .host(super::socket_dir(&instance).display().to_string())
                .port(instance.port)
                .user(&instance.username)
                .dbname("postgres");
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    match config.connect(NoTls).await {
                        Ok((client, connection)) => {
                            let connection = tokio::spawn(connection);
                            client
                                .simple_query("SELECT 1")
                                .await
                                .map_err(|e| e.to_string())?;
                            drop(client);
                            let _ = connection.await;
                            return Ok::<_, String>(());
                        }
                        Err(error)
                            if error
                                .as_db_error()
                                .is_some_and(|db| db.code().code() == "57P03")
                                || std::error::Error::source(&error)
                                    .and_then(|source| source.downcast_ref::<std::io::Error>())
                                    .is_some_and(|error| {
                                        matches!(
                                            error.kind(),
                                            std::io::ErrorKind::NotFound
                                                | std::io::ErrorKind::ConnectionRefused
                                                | std::io::ErrorKind::ConnectionReset
                                        )
                                    }) =>
                        {
                            tokio::time::sleep(Duration::from_millis(25)).await
                        }
                        Err(error) => return Err(format!("RDS SQL readiness failed: {error}")),
                    }
                }
            })
            .await
            .map_err(|_| "RDS SQL readiness timed out".to_owned())?
        }
        .await;
        if let Err(error) = result {
            lease.finish().await?;
            return Err(error);
        }
        let forward_runtime = runtime.clone();
        let forward_id = id.clone();
        let port = instance.port;
        let proxy = tokio::spawn(async move {
            let admission = Arc::new(Semaphore::new(128));
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>match accepted{Ok((mut client,_))=>{let Ok(permit)=admission.clone().try_acquire_owned() else {continue;};let runtime=forward_runtime.clone();let id=forward_id.clone();connections.spawn(async move{let _permit=permit;if let Ok(mut backend)=runtime.connect_isolated_tcp(&id,port,Duration::from_secs(5)).await{let _=tokio::io::copy_bidirectional(&mut client,&mut backend).await;}});},Err(_)=>break},
                    _=connections.join_next(),if !connections.is_empty()=>{}
                }
            }
        });
        *slot
            .guest
            .lock()
            .map_err(|_| "RDS guest lock unavailable")? = Some(Guest {
            lease,
            _source: source,
            proxy,
        });
        Ok(())
    }
    async fn stop(&self, directory: &Path, slot: &Slot) -> Result<(), String> {
        let runtime = self.compute().await?;
        let instance = Self::instance(directory).await?;
        let id = task_id(&instance)?;
        let known = slot
            .guest
            .lock()
            .map_err(|_| "RDS guest lock unavailable")?
            .is_some();
        if !known {
            if !runtime
                .reconcile_orphaned_task(&id)
                .await
                .map_err(|e| e.to_string())?
            {
                return Err("RDS orphan cleanup is not confirmed".into());
            }
            return Ok(());
        }
        runtime
            .interrupt_task(&id)
            .await
            .map_err(|e| e.to_string())?;
        tokio::time::timeout(Duration::from_secs(30), async {
            while runtime.task_state(&id).await.map_err(|e| e.to_string())? == TaskState::Running {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Ok::<_, String>(())
        })
        .await
        .map_err(|_| "RDS PostgreSQL shutdown timed out; data retained".to_owned())??;
        runtime.release_task(&id).await.map_err(|e| e.to_string())?;
        let guest = slot
            .guest
            .lock()
            .map_err(|_| "RDS guest lock unavailable")?
            .take();
        if let Some(mut guest) = guest {
            guest.proxy.abort();
            let _ = guest.proxy.await;
            guest.lease.finish().await?;
        }
        Ok(())
    }
    async fn backup(&self, args: &[String]) -> Result<Output, String> {
        let target = PathBuf::from(required(args, "-D")?);
        let parent = target
            .parent()
            .ok_or("invalid RDS backup target")?
            .to_path_buf();
        let canonical = tokio::fs::canonicalize(&parent)
            .await
            .map_err(|e| e.to_string())?;
        let root = tokio::fs::canonicalize(&self.root)
            .await
            .map_err(|e| e.to_string())?;
        if !canonical.starts_with(&root) || canonical != parent {
            return Err("RDS backup target escapes owned data".into());
        }
        let socket = PathBuf::from(required(args, "-h")?);
        validate_socket(&socket)?;
        tokio::fs::DirBuilder::new()
            .mode(0o700)
            .create(&target)
            .await
            .map_err(|e| e.to_string())?;
        let source_id = socket
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("lc-rds-"))
            .map(|token| format!("rds-{token}"))
            .ok_or("invalid RDS source socket")?;
        let slots: Vec<_> = self
            .slots
            .lock()
            .map_err(|_| "RDS guest inventory unavailable")?
            .values()
            .cloned()
            .collect();
        let mut source = None;
        for slot in slots {
            let guest = slot
                .guest
                .lock()
                .map_err(|_| "RDS guest lock unavailable")?;
            if let Some(guest) = guest.as_ref().filter(|guest| guest.lease.id == source_id) {
                source = Some(guest.lease.image.clone());
                break;
            }
        }
        let source = match source {
            Some(image) => image,
            None => self.source().await?,
        };
        let temporary = parent.join(format!("backup-guest-{}", uuid::Uuid::new_v4()));
        let creating = temporary.clone();
        let installing = source.clone();
        let root_lease = self.root_lease.clone();
        tokio::task::spawn_blocking(move || {
            let _root_lease = root_lease;
            installing.install(&creating)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
        let mut rewritten = args.to_vec();
        replace(&mut rewritten, "-D", "/backup")?;
        replace(&mut rewritten, "-h", "/source-socket")?;
        let result = self
            .finite(
                source,
                temporary.clone(),
                "pg_basebackup",
                rewritten,
                vec![
                    mount(target, "/backup", false),
                    mount(socket.clone(), "/source-socket", true),
                ],
            )
            .await;
        if result.is_ok() {
            tokio::fs::remove_dir_all(&temporary)
                .await
                .map_err(|e| e.to_string())?;
        }
        if args.iter().any(|arg| arg == "-R")
            && result.as_ref().is_ok_and(|out| out.status.success())
        {
            tokio::fs::write(
                parent.join("replica-socket"),
                socket.as_os_str().as_encoded_bytes(),
            )
            .await
            .map_err(|e| e.to_string())?;
        }
        result
    }
}
fn required<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .ok_or_else(|| format!("missing PostgreSQL {flag} argument"))
}
fn replace(args: &mut [String], flag: &str, value: &str) -> Result<(), String> {
    let i = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or_else(|| format!("missing PostgreSQL {flag} argument"))?;
    let target = args
        .get_mut(i + 1)
        .ok_or("missing PostgreSQL argument value")?;
    *target = value.into();
    Ok(())
}
fn task_id(instance: &Instance) -> Result<String, String> {
    if !super::valid_socket_token(&instance.socket_token) {
        return Err("invalid RDS task identity".into());
    }
    Ok(format!("rds-{}", instance.socket_token))
}
fn mount(source: PathBuf, destination: &str, read_only: bool) -> TaskMount {
    TaskMount {
        source,
        destination: PathBuf::from(destination),
        read_only,
    }
}
fn validate_socket(path: &Path) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("lc-rds-"));
    if path.parent() != Some(Path::new("/tmp")) || !name.is_some_and(super::valid_socket_token) {
        return Err("invalid RDS source socket".into());
    }
    Ok(())
}
fn output(code: i32, text: String) -> Output {
    let success = code == 0;
    Output {
        status: ExitStatus::from_raw(code << 8),
        stdout: if success {
            text.as_bytes().to_vec()
        } else {
            Vec::new()
        },
        stderr: if success {
            Vec::new()
        } else {
            text.into_bytes()
        },
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: u32,
    id: String,
    resource: PathBuf,
}
struct TaskLease {
    runtime: Arc<YoukiRuntime>,
    path: PathBuf,
    id: String,
    image: Arc<RuntimePack>,
    root_lease: Arc<std::fs::File>,
    armed: bool,
}
impl TaskLease {
    async fn finish(&mut self) -> Result<(), String> {
        Engine::dispose(&self.runtime, &self.id).await?;
        remove_intent(&self.path).await?;
        self.armed = false;
        Ok(())
    }
}
impl Drop for TaskLease {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let runtime = self.runtime.clone();
        let path = self.path.clone();
        let id = self.id.clone();
        let image = self.image.clone();
        let root_lease = self.root_lease.clone();
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        handle.spawn(async move {
            let _image = image;
            let _root_lease = root_lease;
            if Engine::dispose(&runtime, &id).await.is_ok() {
                let _ = remove_intent(&path).await;
            }
        });
    }
}
pub(super) fn pending(root: &Path) -> bool {
    match std::fs::read_dir(root.join(".oci-tasks")) {
        Ok(mut entries) => entries.next().is_some(),
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

async fn remove_intent(path: &Path) -> Result<(), String> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let parent = path.parent().ok_or("invalid RDS intent path")?;
    tokio::fs::File::open(parent)
        .await
        .map_err(|e| e.to_string())?
        .sync_all()
        .await
        .map_err(|e| e.to_string())
}
