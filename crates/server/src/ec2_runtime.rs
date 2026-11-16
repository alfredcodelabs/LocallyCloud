//! Narrow EC2 adapter for a local OCI HTTP image.

use serde::{Deserialize, Deserializer};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use locallycloud_compute::runtime::{ComputeRuntime, RuntimeError, TaskSpec, TaskState};
use locallycloud_compute::youki::YoukiRuntime;
use locallycloud_ec2::{InstanceRuntime, InstanceSpec};
use tokio::net::TcpStream;

fn configured_path<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PathBuf>, D::Error> {
    PathBuf::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ec2RuntimeConfig {
    #[serde(deserialize_with = "configured_path")]
    pub image_rootfs: Option<PathBuf>,
    pub startup_timeout_secs: u64,
    pub connect_timeout_secs: u64,
}

impl Default for Ec2RuntimeConfig {
    fn default() -> Self {
        Self {
            image_rootfs: None,
            startup_timeout_secs: 5,
            connect_timeout_secs: 2,
        }
    }
}

impl Ec2RuntimeConfig {
    pub fn resolve_with(
        mut self,
        get: &dyn Fn(&str) -> Option<OsString>,
        current_dir: &Path,
    ) -> Result<Self, String> {
        if let Some(path) = get("LOCALLYCLOUD_EC2_IMAGE_ROOTFS") {
            self.image_rootfs = Some(path.into());
        }
        for (name, target) in [
            (
                "LOCALLYCLOUD_EC2_STARTUP_TIMEOUT_SECS",
                &mut self.startup_timeout_secs,
            ),
            (
                "LOCALLYCLOUD_EC2_CONNECT_TIMEOUT_SECS",
                &mut self.connect_timeout_secs,
            ),
        ] {
            if let Some(value) = get(name) {
                *target = value
                    .to_str()
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| format!("{name} must be an integer"))?;
            }
        }
        for (name, value) in [
            ("startup_timeout_secs", self.startup_timeout_secs),
            ("connect_timeout_secs", self.connect_timeout_secs),
        ] {
            if !(1..=300).contains(&value) {
                return Err(format!("ec2.{name} must be between 1 and 300"));
            }
        }
        if let Some(path) = &mut self.image_rootfs {
            if path.as_os_str().is_empty() {
                return Err("ec2.image_rootfs must not be empty".into());
            }
            if path.is_relative() {
                *path = current_dir.join(&*path);
            }
        }
        Ok(self)
    }
}

#[derive(Default)]
pub struct Ec2OciRuntime {
    runtime: Mutex<Option<Arc<YoukiRuntime>>>,
    config: Ec2RuntimeConfig,
}

impl Ec2OciRuntime {
    pub fn new(config: Ec2RuntimeConfig) -> Self {
        Self {
            runtime: Mutex::new(None),
            config,
        }
    }
    fn runtime(&self) -> Result<Arc<YoukiRuntime>, String> {
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| "EC2 runtime state is unavailable".to_owned())?;
        if runtime.is_none() {
            *runtime = Some(Arc::new(YoukiRuntime::discover().ok_or_else(|| {
                "crun or youki is required for EC2 instances".to_owned()
            })?));
        }
        Ok(runtime.as_ref().expect("runtime initialized").clone())
    }
}

#[async_trait::async_trait]
impl InstanceRuntime for Ec2OciRuntime {
    async fn start_instance(&self, spec: &InstanceSpec) -> Result<(), String> {
        if spec.image_id != "ami-locallycloud-http"
            || spec.instance_type != "t3.micro"
            || spec.guest_port != 8080
        {
            return Err("Only ami-locallycloud-http on t3.micro port 8080 is supported".into());
        }
        let configured = self.config.image_rootfs.as_ref().ok_or_else(|| {
            "Configure ec2.image_rootfs or LOCALLYCLOUD_EC2_IMAGE_ROOTFS to run EC2 instances"
                .to_owned()
        })?;
        let rootfs = tokio::fs::canonicalize(configured)
            .await
            .map_err(|_| "EC2 image rootfs is unavailable".to_owned())?;
        if !tokio::fs::metadata(&rootfs)
            .await
            .map_err(|_| "EC2 image rootfs is unavailable".to_owned())?
            .is_dir()
        {
            return Err("EC2 image rootfs must be a directory".into());
        }
        let runtime = self.runtime()?;
        let task = TaskSpec {
            mounts: Vec::new(),
            user: None,
            name: spec.instance_id.clone(),
            image: rootfs.display().to_string(),
            command: vec!["/bin/httpd".into(), spec.guest_port.to_string()],
            env: Default::default(),
            memory_mb: 1024,
            vcpu_count: 2,
        };
        runtime
            .start_isolated_service(
                &spec.instance_id,
                &task,
                spec.guest_port,
                Duration::from_secs(self.config.startup_timeout_secs),
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn connect_instance(
        &self,
        instance_id: &str,
        guest_port: u16,
    ) -> Result<TcpStream, String> {
        self.runtime()?
            .connect_isolated_tcp(
                instance_id,
                guest_port,
                Duration::from_secs(self.config.connect_timeout_secs),
            )
            .await
            .map_err(|error| error.to_string())
    }

    async fn stop_instance(&self, instance_id: &str) -> Result<(), String> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| "EC2 runtime state is unavailable".to_owned())?
            .clone();
        let Some(runtime) = runtime else {
            return Ok(());
        };
        match runtime.stop_task(instance_id).await {
            Ok(_)
            | Err(RuntimeError::TaskNotFound { .. })
            | Err(RuntimeError::TaskAlreadyCompleted { .. }) => runtime
                .release_task(instance_id)
                .await
                .map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn instance_running(&self, instance_id: &str) -> bool {
        let Ok(runtime) = self.runtime() else {
            return false;
        };
        matches!(
            runtime.task_state(instance_id).await,
            Ok(TaskState::Running)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn absent_or_missing_rootfs_fails_only_when_an_instance_is_started() {
        let spec = InstanceSpec {
            instance_id: "i-owned-test".into(),
            image_id: "ami-locallycloud-http".into(),
            instance_type: "t3.micro".into(),
            vpc_id: "vpc-owned".into(),
            subnet_id: "subnet-owned".into(),
            private_ip: std::net::Ipv4Addr::new(10, 0, 0, 1),
            security_group_ids: Vec::new(),
            guest_port: 8080,
        };
        let runtime = Ec2OciRuntime::new(Ec2RuntimeConfig::default());
        let error = runtime.start_instance(&spec).await.unwrap_err();
        assert!(error.contains("ec2.image_rootfs"));
        let config = Ec2RuntimeConfig {
            image_rootfs: Some(
                std::env::temp_dir()
                    .join(uuid::Uuid::new_v4().to_string())
                    .join("missing-rootfs"),
            ),
            ..Default::default()
        };
        let error = Ec2OciRuntime::new(config)
            .start_instance(&spec)
            .await
            .unwrap_err();
        assert_eq!(error, "EC2 image rootfs is unavailable");
    }
}
