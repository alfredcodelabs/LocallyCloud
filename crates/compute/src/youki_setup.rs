//! Native OCI createContainer rendezvous. User code cannot execute until setup is acknowledged.
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(test)]
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::runtime::RuntimeError;
use crate::youki::YoukiRuntime;

const MAX_STATE: usize = 16 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(45);
pub(crate) const SETUP_TIMEOUT: Duration = Duration::from_secs(20);

/// Install guest-owned SDK, credentials and network listeners before the image executes.
#[async_trait]
pub trait IsolatedGuestSetup: Send + Sync {
    async fn prepare(&self, runtime: Arc<YoukiRuntime>, task_id: &str) -> Result<(), RuntimeError>;
}

pub(crate) struct NamespaceFiles {
    pub(crate) bundle: PathBuf,
    user: std::fs::File,
    network: std::fs::File,
}
impl NamespaceFiles {
    pub(crate) fn duplicate(&self) -> Result<(std::fs::File, std::fs::File), RuntimeError> {
        Ok((
            self.user.try_clone().map_err(failed)?,
            self.network.try_clone().map_err(failed)?,
        ))
    }
}

pub(crate) struct NamespaceLease {
    map: Arc<dashmap::DashMap<String, Arc<NamespaceFiles>>>,
    task_id: String,
    files: Arc<NamespaceFiles>,
}
impl NamespaceLease {
    pub(crate) fn install(
        map: Arc<dashmap::DashMap<String, Arc<NamespaceFiles>>>,
        task_id: &str,
        files: Arc<NamespaceFiles>,
    ) -> Self {
        map.insert(task_id.into(), files.clone());
        Self {
            map,
            task_id: task_id.into(),
            files,
        }
    }
}
impl Drop for NamespaceLease {
    fn drop(&mut self) {
        self.map
            .remove_if(&self.task_id, |_, files| Arc::ptr_eq(files, &self.files));
    }
}

pub(crate) struct SetupGate {
    listener: UnixListener,
    pub(crate) address: String,
    pub(crate) helper: String,
}
impl SetupGate {
    pub(crate) async fn new() -> Result<Self, RuntimeError> {
        tokio::task::spawn_blocking(|| {
            // The createContainer hook already inhabits the guest netns, so an
            // abstract Unix address would resolve in a different socket namespace.
            let uid = unsafe { libc::geteuid() };
            let parent = PathBuf::from(format!("/run/user/{uid}"));
            let metadata = std::fs::symlink_metadata(&parent).map_err(failed)?;
            if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
                return Err(failed(
                    "rootless user runtime directory must be owned and private",
                ));
            }
            let address = parent.join(format!("lcsetup-{}", uuid::Uuid::new_v4().simple()));
            let listener = std::os::unix::net::UnixListener::bind(&address).map_err(failed)?;
            std::fs::set_permissions(&address, std::fs::Permissions::from_mode(0o600))
                .map_err(failed)?;
            listener.set_nonblocking(true).map_err(failed)?;
            let address = address
                .to_str()
                .ok_or_else(|| failed("setup socket path must be UTF-8"))?
                .to_owned();
            let helper = std::env::current_exe()
                .map_err(failed)?
                .into_os_string()
                .into_string()
                .map_err(|_| failed("OCI setup helper path must be UTF-8"))?;
            Ok((listener, address, helper))
        })
        .await
        .map_err(failed)?
        .and_then(|(listener, address, helper)| {
            Ok(Self {
                listener: UnixListener::from_std(listener).map_err(failed)?,
                address,
                helper,
            })
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        let address = format!("lcsetup-test-{}", uuid::Uuid::new_v4().simple());
        let socket_address =
            std::os::unix::net::SocketAddr::from_abstract_name(address.as_bytes()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind_addr(&socket_address).unwrap();
        listener.set_nonblocking(true).unwrap();
        Self {
            listener: UnixListener::from_std(listener).unwrap(),
            address,
            helper: "/owned/locallycloud".to_owned(),
        }
    }

    pub(crate) fn hook(&self) -> Value {
        serde_json::json!({
            "path":self.helper,
            "args":[self.helper,"--internal-oci-setup-gate",self.address],
            "timeout":50,
        })
    }

    pub(crate) async fn accept(
        &self,
        task_id: &str,
        bundle: &Path,
        runtime_pid: &std::sync::atomic::AtomicU32,
    ) -> Result<SetupConnection, RuntimeError> {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(10), self.listener.accept())
            .await
            .map_err(failed)?
            .map_err(failed)?;
        let runtime_pid = runtime_pid.load(std::sync::atomic::Ordering::Acquire);
        let credentials = stream.peer_cred().map_err(failed)?;
        // SAFETY: geteuid has no preconditions and reads the current process credential.
        let expected_uid = unsafe { libc::geteuid() };
        let peer_pid = credentials
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or_else(|| failed("OCI setup peer has no PID"))?;
        let init_pid = process_parent(peer_pid).await?;
        if runtime_pid == 0
            || credentials.uid() != expected_uid
            || init_pid <= 1
            || !descends_from(init_pid, runtime_pid).await?
        {
            return Err(failed(
                "OCI setup peer is not the supervised runtime's init hook",
            ));
        }
        let user = receive_namespace(&stream).await?;
        let network = receive_namespace(&stream).await?;
        let mut length = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut length))
            .await
            .map_err(failed)?
            .map_err(failed)?;
        let length = usize::try_from(u32::from_be_bytes(length)).map_err(failed)?;
        if length > MAX_STATE {
            return Err(failed("OCI setup state exceeds limit"));
        }
        let mut raw = vec![0; length];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut raw))
            .await
            .map_err(failed)?
            .map_err(failed)?;
        validate_state(&raw, task_id, bundle)?;
        let owned_bundle = bundle.to_owned();
        let namespaces =
            tokio::task::spawn_blocking(move || validate_namespaces(user, network, owned_bundle))
                .await
                .map_err(failed)??;
        if process_parent(peer_pid).await? != init_pid
            || !descends_from(init_pid, runtime_pid).await?
        {
            return Err(failed("OCI setup process ownership changed"));
        }
        Ok(SetupConnection {
            stream,
            init_pid,
            namespaces: Arc::new(namespaces),
        })
    }
}

pub(crate) struct SetupConnection {
    stream: UnixStream,
    pub(crate) init_pid: u32,
    pub(crate) namespaces: Arc<NamespaceFiles>,
}
impl SetupConnection {
    pub(crate) async fn acknowledge(mut self) -> Result<(), RuntimeError> {
        tokio::time::timeout(Duration::from_secs(2), self.stream.write_all(b"1"))
            .await
            .map_err(failed)?
            .map_err(failed)
    }
}

fn validate_state(raw: &[u8], task_id: &str, bundle: &Path) -> Result<u32, RuntimeError> {
    if raw.len() > MAX_STATE {
        return Err(failed("OCI setup state exceeds limit"));
    }
    let state: Value = serde_json::from_slice(raw).map_err(failed)?;
    let expected_bundle = bundle
        .to_str()
        .ok_or_else(|| failed("OCI setup bundle path must be UTF-8"))?;
    if state["id"].as_str() != Some(task_id)
        || state["bundle"].as_str() != Some(expected_bundle)
        || !matches!(state["status"].as_str(), Some("creating" | "created"))
    {
        return Err(failed("OCI setup state does not match the owned task"));
    }
    // crun reports PID 0 inside a freshly created PID namespace. The host init
    // identity is attested independently from SO_PEERCRED and its parent chain.
    state["pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or_else(|| failed("OCI setup state has no valid namespace PID"))
}

async fn process_parent(pid: u32) -> Result<u32, RuntimeError> {
    let file = tokio::fs::File::open(format!("/proc/{pid}/status"))
        .await
        .map_err(|error| failed(format!("reading owned process parent: {error}")))?;
    let mut raw = Vec::new();
    file.take((MAX_STATE + 1) as u64)
        .read_to_end(&mut raw)
        .await
        .map_err(failed)?;
    if raw.len() > MAX_STATE {
        return Err(failed("OCI setup process status exceeds limit"));
    }
    let status = std::str::from_utf8(&raw).map_err(failed)?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|value| value.trim().parse().ok())
        .ok_or_else(|| failed("OCI setup process has no parent PID"))
}

async fn descends_from(mut pid: u32, parent: u32) -> Result<bool, RuntimeError> {
    for _ in 0..32 {
        if pid == parent {
            return Ok(true);
        }
        if pid <= 1 {
            return Ok(false);
        }
        pid = process_parent(pid).await?;
    }
    Ok(false)
}

fn validate_namespaces(
    user: std::fs::File,
    network: std::fs::File,
    bundle: PathBuf,
) -> Result<NamespaceFiles, RuntimeError> {
    const NS_GET_USERNS: libc::c_ulong = 0xb701;
    const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
    const NS_GET_OWNER_UID: libc::c_ulong = 0xb704;
    for (file, expected, host) in [
        (&user, libc::CLONE_NEWUSER, "/proc/self/ns/user"),
        (&network, libc::CLONE_NEWNET, "/proc/self/ns/net"),
    ] {
        // SAFETY: ioctl inspects the borrowed descriptor without pointer arguments.
        if unsafe { libc::ioctl(file.as_raw_fd(), NS_GET_NSTYPE) } != expected {
            return Err(failed("setup descriptor has the wrong namespace type"));
        }
        let current = std::fs::metadata(host).map_err(failed)?;
        let target = file.metadata().map_err(failed)?;
        if (current.dev(), current.ino()) == (target.dev(), target.ino()) {
            return Err(failed(
                "OCI setup requires isolated user and network namespaces",
            ));
        }
    }
    // SAFETY: NS_GET_USERNS returns a new owned descriptor, or a negative errno.
    let owner_fd = unsafe { libc::ioctl(network.as_raw_fd(), NS_GET_USERNS) };
    if owner_fd < 0 {
        return Err(failed(format!(
            "inspecting network namespace owner: {}",
            std::io::Error::last_os_error()
        )));
    }
    let owner = unsafe { std::fs::File::from_raw_fd(owner_fd) };
    let actual = owner.metadata().map_err(failed)?;
    let expected = user.metadata().map_err(failed)?;
    if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) {
        return Err(failed(
            "network namespace belongs to another user namespace",
        ));
    }
    let mut uid: libc::uid_t = 0;
    // SAFETY: uid points to valid output storage for NS_GET_OWNER_UID.
    if unsafe { libc::ioctl(user.as_raw_fd(), NS_GET_OWNER_UID, &mut uid) } != 0 {
        return Err(failed(format!(
            "inspecting user namespace owner: {}",
            std::io::Error::last_os_error()
        )));
    }
    if uid != unsafe { libc::geteuid() } {
        return Err(failed("user namespace belongs to another host user"));
    }
    Ok(NamespaceFiles {
        user,
        network,
        bundle,
    })
}

pub fn is_setup_address(address: &str) -> bool {
    socket_path(address).is_ok()
}

fn socket_path(address: &str) -> Result<PathBuf, RuntimeError> {
    let path = PathBuf::from(address);
    let name = path
        .file_name()
        .and_then(|part| part.to_str())
        .unwrap_or_default();
    let suffix = name.strip_prefix("lcsetup-").unwrap_or_default();
    // Inside the hook geteuid is namespaced; constrain the numeric host-UID path,
    // then authenticate the connecting host credential at the listener.
    let parent = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if address.len() >= 108
        || suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || parent.is_empty()
        || !parent.bytes().all(|byte| byte.is_ascii_digit())
        || path.parent().and_then(Path::parent) != Some(Path::new("/run/user"))
    {
        return Err(failed("invalid OCI setup socket path"));
    }
    Ok(path)
}

async fn receive_namespace(stream: &UnixStream) -> Result<std::fs::File, RuntimeError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            stream.readable().await.map_err(failed)?;
            match stream.try_io(tokio::io::Interest::READABLE, || {
                crate::netns_socket::receive_descriptor(stream.as_raw_fd())
            }) {
                Ok(fd) => return Ok(std::fs::File::from(fd)),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(error) => {
                    return Err(failed(format!(
                        "receiving setup namespace descriptor: {error}"
                    )))
                }
            }
        }
    })
    .await
    .map_err(failed)?
}

/// Hidden native OCI hook. Sends only its own namespace descriptors and bounded state.
pub async fn run_oci_setup_hook(address: &str) -> Result<(), RuntimeError> {
    let address = socket_path(address)?;
    tokio::time::timeout(HELPER_TIMEOUT, async move {
        let mut raw = Vec::new();
        tokio::io::stdin()
            .take((MAX_STATE + 1) as u64)
            .read_to_end(&mut raw)
            .await
            .map_err(failed)?;
        if raw.len() > MAX_STATE {
            return Err(failed("OCI setup state exceeds limit"));
        }
        let (user, network) = tokio::task::spawn_blocking(|| {
            Ok::<_, RuntimeError>((
                std::fs::File::open("/proc/self/ns/user").map_err(failed)?,
                std::fs::File::open("/proc/self/ns/net").map_err(failed)?,
            ))
        })
        .await
        .map_err(failed)??;
        let mut stream = UnixStream::connect(address).await.map_err(failed)?;
        for file in [user, network] {
            loop {
                stream.writable().await.map_err(failed)?;
                match stream.try_io(tokio::io::Interest::WRITABLE, || {
                    crate::netns_socket::send_descriptor(stream.as_raw_fd(), file.as_raw_fd())
                }) {
                    Ok(()) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(failed(error)),
                }
            }
        }
        stream
            .write_all(&(raw.len() as u32).to_be_bytes())
            .await
            .map_err(failed)?;
        stream.write_all(&raw).await.map_err(failed)?;
        let mut ack = [0u8; 1];
        stream.read_exact(&mut ack).await.map_err(failed)?;
        if ack != *b"1" {
            return Err(failed("OCI setup was not acknowledged"));
        }
        Ok(())
    })
    .await
    .map_err(failed)?
}

impl Drop for SetupGate {
    fn drop(&mut self) {
        #[cfg(test)]
        if !Path::new(&self.address).is_absolute() {
            return;
        }
        let path = PathBuf::from(&self.address);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || {
                let _ = std::fs::remove_file(path);
            });
        } else {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn failed(reason: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::ExecutionFailed {
        reason: format!("OCI pre-exec guest setup: {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn setup_gate_rejects_same_uid_client_outside_runtime() {
        let gate = SetupGate::for_test();
        let address =
            std::os::unix::net::SocketAddr::from_abstract_name(gate.address.as_bytes()).unwrap();
        let _client = tokio::task::spawn_blocking(move || {
            std::os::unix::net::UnixStream::connect_addr(&address)
        })
        .await
        .unwrap()
        .unwrap();
        let supervised = std::sync::atomic::AtomicU32::new(std::process::id());
        assert!(gate
            .accept("owned", Path::new("/owned/bundle"), &supervised)
            .await
            .is_err());
    }

    #[test]
    fn setup_rejects_host_namespaces_and_regular_file_descriptors() {
        for path in ["/proc/self/ns/user", "/dev/null"] {
            let result = validate_namespaces(
                std::fs::File::open(path).unwrap(),
                std::fs::File::open("/proc/self/ns/net").unwrap(),
                PathBuf::from("/owned/bundle"),
            );
            assert!(result.is_err());
        }
    }

    #[test]
    fn setup_state_and_address_reject_unowned_input() {
        let bundle = Path::new("/owned/bundle");
        let valid =
            serde_json::json!({"id":"owned","bundle":"/owned/bundle","status":"created","pid":123});
        assert_eq!(
            validate_state(valid.to_string().as_bytes(), "owned", bundle).unwrap(),
            123
        );
        let mut namespaced = valid.clone();
        namespaced["pid"] = serde_json::json!(0);
        assert_eq!(
            validate_state(namespaced.to_string().as_bytes(), "owned", bundle).unwrap(),
            0
        );
        for (field, value) in [
            ("id", serde_json::json!("other")),
            ("bundle", serde_json::json!("/other")),
            ("status", serde_json::json!("running")),
            ("pid", serde_json::json!(u64::MAX)),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(validate_state(invalid.to_string().as_bytes(), "owned", bundle).is_err());
        }
        assert!(validate_state(&vec![b'x'; MAX_STATE + 1], "owned", bundle).is_err());
        assert!(socket_path("/run/user/1000/lcsetup-0123456789abcdef0123456789abcdef").is_ok());
        for address in [
            "/tmp/socket",
            "locallycloud-setup-",
            "locallycloud-setup-0123456789abcdef0123456789abcdeF",
        ] {
            assert!(socket_path(address).is_err());
        }
    }
}
