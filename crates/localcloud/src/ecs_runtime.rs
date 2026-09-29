//! Narrow ECR-backed OCI Fargate runtime with bounded OCI/Docker tar layers.
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};

use flate2::read::GzDecoder;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use localcloud_compute::runtime::{ComputeRuntime, RuntimeError, TaskSpec, TaskState};
use localcloud_compute::youki::YoukiRuntime;
use localcloud_ecs::{TaskLaunch, TaskNetworkInfo, TaskRuntime};
use serde_json::Value;
use tokio::io;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub struct EcsOciRuntime {
    ecr: Arc<localcloud_ecr::EcrHandler>,
    ec2: Arc<localcloud_ec2::Ec2Handler>,
    runtime: Mutex<Option<Arc<YoukiRuntime>>>,
    roots: Mutex<HashMap<String, TaskResources>>,
}

struct TaskResources {
    root: PathBuf,
    network: localcloud_ec2::TaskNetworkLease,
    proxy: JoinHandle<()>,
}
impl EcsOciRuntime {
    pub fn new(ecr: Arc<localcloud_ecr::EcrHandler>, ec2: Arc<localcloud_ec2::Ec2Handler>) -> Self {
        Self {
            ecr,
            ec2,
            runtime: Mutex::new(None),
            roots: Mutex::new(HashMap::new()),
        }
    }
    pub async fn shutdown(&self) {
        let ids = match self.roots.lock() {
            Ok(roots) => roots.keys().cloned().collect::<Vec<_>>(),
            Err(_) => return,
        };
        for id in ids {
            if let Err(error) = self.stop(&id).await {
                tracing::warn!(task_id = %id, error = %error, "ECS task shutdown failed");
            }
        }
    }
    fn runtime(&self) -> Result<Arc<YoukiRuntime>, String> {
        let mut guard = self
            .runtime
            .lock()
            .map_err(|_| "ECS runtime lock unavailable")?;
        if guard.is_none() {
            *guard = Some(Arc::new(
                YoukiRuntime::discover().ok_or("crun or youki is required")?,
            ));
        }
        Ok(guard.as_ref().expect("runtime initialized").clone())
    }
}

#[async_trait::async_trait]
impl TaskRuntime for EcsOciRuntime {
    async fn preflight(
        &self,
        image: &str,
        account: &str,
        region: &str,
        subnets: &[String],
        security_groups: &[String],
    ) -> Result<(), String> {
        let subnet = subnets.first().ok_or("One subnet is required")?;
        self.ec2
            .network_selection(account, region, subnet, security_groups)
            .ok_or("Subnet or security group is unavailable")?;
        let (repo, reference) = parse_ecr_image(image, account, region)?;
        self.ecr
            .image_blobs(account, region, repo, reference)
            .ok_or("ECR image was not found or has unsupported layer media type")?;
        Ok(())
    }
    async fn start(&self, task: &TaskLaunch) -> Result<TaskNetworkInfo, String> {
        self.ec2
            .network_selection(
                &task.account,
                &task.region,
                &task.subnets[0],
                &task.security_groups,
            )
            .ok_or("Subnet or security group is unavailable")?;
        let (repo, reference) = parse_ecr_image(&task.image, &task.account, &task.region)?;
        let (config, layers) = self
            .ecr
            .image_blobs(&task.account, &task.region, repo, reference)
            .ok_or("ECR image was not found or has unsupported layer media type")?;
        let task_id = task.task_id.clone();
        let work = localcloud_compute::private_dir::work_dir("ecs");
        localcloud_compute::private_dir::ensure(&work).map_err(|error| error.to_string())?;
        let root = work.join(&task_id);
        let root_for_build = root.clone();
        let config = config.to_vec();
        let layers = layers
            .into_iter()
            .map(|(blob, compressed)| (blob.to_vec(), compressed))
            .collect::<Vec<_>>();
        let image_defaults =
            tokio::task::spawn_blocking(move || materialize(&root_for_build, &config, &layers))
                .await
                .map_err(|e| e.to_string())??;
        let command = if task.command.is_empty() {
            image_defaults.0
        } else {
            task.command.clone()
        };
        if command.is_empty() {
            let _ = fs::remove_dir_all(&root);
            return Err("Image has no command".into());
        }
        let mut env = image_defaults.1;
        env.extend(task.environment.clone());
        let network = match self.ec2.reserve_task_network(
            &task.account,
            &task.region,
            &task.subnets[0],
            &task.security_groups,
            &task_id,
        ) {
            Some(network) => network,
            None => {
                let _ = fs::remove_dir_all(&root);
                return Err("Unable to reserve task network interface".into());
            }
        };
        let spec = TaskSpec {
            name: task_id.clone(),
            image: root.display().to_string(),
            command,
            env,
            memory_mb: task.memory_mb,
            vcpu_count: (task.cpu / 1024).max(1),
        };
        let runtime = match self.runtime() {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = fs::remove_dir_all(&root);
                return Err(error);
            }
        };
        if let Err(error) = runtime
            .start_isolated_service(&task_id, &spec, task.port, Duration::from_secs(5))
            .await
        {
            let _ = fs::remove_dir_all(&root);
            return Err(error.to_string());
        }
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                let _ = runtime.stop_task(&task_id).await;
                let _ = fs::remove_dir_all(&root);
                return Err(error.to_string());
            }
        };
        let endpoint = match listener.local_addr() {
            Ok(endpoint) => endpoint,
            Err(error) => {
                let _ = runtime.stop_task(&task_id).await;
                let _ = fs::remove_dir_all(&root);
                return Err(error.to_string());
            }
        };
        if !network.set_endpoint(task.port, endpoint) {
            let _ = runtime.stop_task(&task_id).await;
            let _ = fs::remove_dir_all(&root);
            return Err("Unable to publish task endpoint".into());
        }
        let proxy = tokio::spawn(serve_task_proxy(
            listener,
            TaskProxyContext {
                ec2: self.ec2.clone(),
                runtime,
                account: task.account.clone(),
                region: task.region.clone(),
                task_id: task_id.clone(),
                group_ids: task.security_groups.clone(),
                guest_port: task.port,
            },
        ));
        let info = TaskNetworkInfo {
            eni_id: network.eni_id.clone(),
            private_ip: network.private_ip,
            subnet_id: network.subnet_id.clone(),
        };
        self.roots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                task_id,
                TaskResources {
                    root,
                    network,
                    proxy,
                },
            );
        Ok(info)
    }
    async fn stop(&self, task_id: &str) -> Result<(), String> {
        let runtime = self.runtime()?;
        match runtime.stop_task(task_id).await {
            Ok(_)
            | Err(RuntimeError::TaskAlreadyCompleted { .. })
            | Err(RuntimeError::TaskNotFound { .. }) => {}
            Err(error) => return Err(error.to_string()),
        }
        let resources = {
            self.roots
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(task_id)
        };
        if let Some(resources) = resources {
            resources.proxy.abort();
            drop(resources.network);
            tokio::fs::remove_dir_all(resources.root)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
    async fn running(&self, task_id: &str) -> bool {
        let running = match self.runtime() {
            Ok(runtime) => matches!(runtime.task_state(task_id).await, Ok(TaskState::Running)),
            Err(_) => false,
        };
        if !running {
            let _ = self.stop(task_id).await;
        }
        running
    }
}

struct TaskProxyContext {
    ec2: Arc<localcloud_ec2::Ec2Handler>,
    runtime: Arc<YoukiRuntime>,
    account: String,
    region: String,
    task_id: String,
    group_ids: Vec<String>,
    guest_port: u16,
}

async fn serve_task_proxy(listener: TcpListener, context: TaskProxyContext) {
    let TaskProxyContext {
        ec2,
        runtime,
        account,
        region,
        task_id,
        group_ids,
        guest_port,
    } = context;
    loop {
        let Ok((mut inbound, peer)) = listener.accept().await else {
            break;
        };
        let std::net::IpAddr::V4(source) = peer.ip() else {
            continue;
        };
        if !ec2.security_groups_allow_ingress(&account, &region, &group_ids, source, guest_port) {
            continue;
        }
        let runtime = runtime.clone();
        let task_id = task_id.clone();
        tokio::spawn(async move {
            if let Ok(mut outbound) = runtime
                .connect_isolated_tcp(&task_id, guest_port, Duration::from_secs(2))
                .await
            {
                let _ = io::copy_bidirectional(&mut inbound, &mut outbound).await;
            }
        });
    }
}

fn parse_ecr_image<'a>(
    image: &'a str,
    account: &str,
    region: &str,
) -> Result<(&'a str, &'a str), String> {
    let prefix = format!("{account}.dkr.ecr.{region}.amazonaws.com/");
    let path = image
        .strip_prefix(&prefix)
        .ok_or("Image must be in the task account and region ECR registry")?;
    let (repo, reference) = path.rsplit_once(':').ok_or("ECR image tag is required")?;
    if repo.is_empty() || reference.is_empty() || repo.contains("..") || reference.contains('/') {
        return Err("Invalid ECR image reference".into());
    }
    Ok((repo, reference))
}

fn materialize(
    root: &Path,
    config: &[u8],
    layers: &[(Vec<u8>, bool)],
) -> Result<(Vec<String>, HashMap<String, String>), String> {
    let image: Value = serde_json::from_slice(config).map_err(|_| "Invalid OCI image config")?;
    let config = image.get("config").ok_or("OCI image config is missing")?;
    let mut command = Vec::new();
    for key in ["Entrypoint", "Cmd"] {
        if let Some(items) = config.get(key).and_then(Value::as_array) {
            for item in items {
                command.push(item.as_str().ok_or("Invalid image command")?.to_owned());
            }
        }
    }
    let mut env = HashMap::new();
    if let Some(items) = config.get("Env").and_then(Value::as_array) {
        for item in items {
            let item = item.as_str().ok_or("Invalid image environment")?;
            let (key, value) = item.split_once('=').ok_or("Invalid image environment")?;
            env.insert(key.to_owned(), value.to_owned());
        }
    }
    if layers.len() > MAX_LAYERS {
        return Err("Too many OCI layers".into());
    }
    if root.exists() {
        return Err("Task rootfs already exists".into());
    }
    fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let mut total_unpacked = 0usize;
    let result = layers.iter().try_for_each(|(layer, compressed)| {
        if *compressed {
            let mut decoder = GzDecoder::new(layer.as_slice());
            let mut unpacked = Vec::new();
            decoder
                .by_ref()
                .take(MAX_UNPACKED_LAYER_BYTES as u64 + 1)
                .read_to_end(&mut unpacked)
                .map_err(|_| "Invalid gzip OCI layer")?;
            if unpacked.len() > MAX_UNPACKED_LAYER_BYTES {
                return Err("Layer too large".into());
            }
            total_unpacked = total_unpacked
                .checked_add(unpacked.len())
                .ok_or("Image too large")?;
            if total_unpacked > MAX_UNPACKED_IMAGE_BYTES {
                return Err("Image too large".into());
            }
            extract_layer(root, &unpacked)
        } else {
            total_unpacked = total_unpacked
                .checked_add(layer.len())
                .ok_or("Image too large")?;
            if total_unpacked > MAX_UNPACKED_IMAGE_BYTES {
                return Err("Image too large".into());
            }
            extract_layer(root, layer)
        }
    });
    if let Err(error) = result {
        let _ = fs::remove_dir_all(root);
        return Err(error);
    }
    Ok((command, env))
}

const MAX_LAYERS: usize = 32;
const MAX_UNPACKED_LAYER_BYTES: usize = 128 * 1024 * 1024;
const MAX_UNPACKED_IMAGE_BYTES: usize = 256 * 1024 * 1024;

fn extract_layer(root: &Path, layer: &[u8]) -> Result<(), String> {
    if layer.len() > MAX_UNPACKED_LAYER_BYTES {
        return Err("Layer too large".into());
    }
    let mut offset = 0usize;
    let mut total = 0usize;
    while offset
        .checked_add(512)
        .is_some_and(|end| end <= layer.len())
    {
        let header = &layer[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            return Ok(());
        }
        let name = std::str::from_utf8(&header[..100])
            .map_err(|_| "Invalid tar path")?
            .split('\0')
            .next()
            .unwrap_or("");
        let prefix = std::str::from_utf8(&header[345..500])
            .map_err(|_| "Invalid tar prefix")?
            .split('\0')
            .next()
            .unwrap_or("");
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let relative = Path::new(&path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            || path.contains(".wh.")
        {
            return Err("Unsafe OCI layer path".into());
        }
        let size_text = std::str::from_utf8(&header[124..136])
            .map_err(|_| "Invalid tar size")?
            .trim_matches('\0')
            .trim();
        let size = usize::from_str_radix(size_text, 8).map_err(|_| "Invalid tar size")?;
        total = total.checked_add(size).ok_or("Layer too large")?;
        if total > MAX_UNPACKED_LAYER_BYTES {
            return Err("Layer too large".into());
        }
        let data_start = offset + 512;
        let data_end = data_start.checked_add(size).ok_or("Layer too large")?;
        if data_end > layer.len() {
            return Err("Truncated OCI layer".into());
        }
        let target = root.join(relative);
        let file_type = header[156];
        match file_type {
            b'5' => fs::create_dir_all(&target).map_err(|e| e.to_string())?,
            b'0' | 0 => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                let mut file = File::create(&target).map_err(|e| e.to_string())?;
                file.write_all(&layer[data_start..data_end])
                    .map_err(|e| e.to_string())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = std::str::from_utf8(&header[100..108])
                        .map_err(|_| "Invalid tar mode")?
                        .trim_matches('\0')
                        .trim();
                    let mode =
                        u32::from_str_radix(mode, 8).map_err(|_| "Invalid tar mode")? & 0o777;
                    fs::set_permissions(&target, fs::Permissions::from_mode(mode))
                        .map_err(|e| e.to_string())?;
                }
            }
            _ => return Err("OCI layer contains unsupported entry type".into()),
        }
        offset = data_start
            .checked_add(size.div_ceil(512) * 512)
            .ok_or("Layer too large")?;
    }
    Err("Truncated OCI layer".into())
}
