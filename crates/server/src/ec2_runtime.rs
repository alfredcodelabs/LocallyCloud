//! Narrow EC2 adapter for a local OCI HTTP image.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use locallycloud_compute::runtime::{ComputeRuntime, RuntimeError, TaskSpec, TaskState};
use locallycloud_compute::youki::YoukiRuntime;
use locallycloud_ec2::{InstanceRuntime, InstanceSpec};
use tokio::net::TcpStream;

#[derive(Default)]
pub struct Ec2OciRuntime {
    runtime: Mutex<Option<Arc<YoukiRuntime>>>,
}

impl Ec2OciRuntime {
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
        let rootfs = std::env::var_os("LOCALLYCLOUD_EC2_IMAGE_ROOTFS")
            .map(PathBuf::from)
            .ok_or_else(|| "LOCALLYCLOUD_EC2_IMAGE_ROOTFS is required".to_owned())?
            .canonicalize()
            .map_err(|error| format!("EC2 image rootfs is unavailable: {error}"))?;
        if !rootfs.is_dir() {
            return Err("EC2 image rootfs must be a directory".into());
        }
        let runtime = self.runtime()?;
        let task = TaskSpec {
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
                Duration::from_secs(5),
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
            .connect_isolated_tcp(instance_id, guest_port, Duration::from_secs(2))
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
            | Err(RuntimeError::TaskAlreadyCompleted { .. }) => Ok(()),
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
