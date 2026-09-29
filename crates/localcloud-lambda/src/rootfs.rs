//! Guest rootfs construction for a function's execution environment.
//!
//! Composes a self-contained rootfs directory the [`ComputeRuntime`](localcloud_compute)
//! consumes: the function code at [`LAMBDA_TASK_ROOT`](crate::exec_env::LAMBDA_TASK_ROOT), a
//! writable `/tmp`, the standard mountpoint directories crun/Firecracker expect, and layer
//! contents merged under `/opt` in listed order (Requirements 15.6, 15.7, 20.1–20.7). A
//! custom-runtime (`provided.*`) function runs its own `bootstrap`; a managed runtime runs
//! the platform Runtime Interface Client shipped by its base layer.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::error::LambdaError;

/// Absolute guest path where layers are merged.
pub const OPT_DIR: &str = "/opt";
/// The custom-runtime bootstrap path inside the task root.
pub const BOOTSTRAP_PATH: &str = "/var/task/bootstrap";
/// The platform Runtime Interface Client for managed runtimes.
pub const MANAGED_RIC: &str = "/var/runtime/bootstrap";

const NODE_RIC: &str = r#"#!/usr/bin/node
const api = `http://${process.env.AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime`;
const [moduleName, exportName] = process.env._HANDLER.split(/\.(?=[^.]+$)/);
let handler;
let invocationLogs = null;

function captureWrites(stream) {
  const write = stream.write.bind(stream);
  stream.write = (chunk, encoding, callback) => {
    if (invocationLogs !== null) {
      invocationLogs.push(Buffer.isBuffer(chunk) ? chunk.toString(typeof encoding === 'string' ? encoding : 'utf8') : String(chunk));
    }
    return write(chunk, encoding, callback);
  };
}

captureWrites(process.stdout);
captureWrites(process.stderr);

async function loadHandler() {
  if (handler) return handler;
  const module = await import(`file:///var/task/${moduleName}.js`);
  handler = module[exportName] ?? module.default?.[exportName];
  if (typeof handler !== 'function') throw new Error(`Handler '${process.env._HANDLER}' is not a function`);
  return handler;
}

function errorPayload(error) {
  return JSON.stringify({
    errorType: error?.name ?? 'Error',
    errorMessage: error?.message ?? String(error),
    stackTrace: String(error?.stack ?? '').split('\n').slice(1),
  });
}

async function post(path, body, headers = {}) {
  const response = await fetch(`${api}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body,
  });
  if (!response.ok) throw new Error(`Runtime API ${path} failed with ${response.status}`);
}

while (true) {
  const next = await fetch(`${api}/invocation/next`);
  if (next.status === 204) break;
  if (!next.ok) throw new Error(`Runtime API next failed with ${next.status}`);
  const requestId = next.headers.get('lambda-runtime-aws-request-id');
  const invokedFunctionArn = next.headers.get('lambda-runtime-invoked-function-arn');
  const deadlineMs = Number(next.headers.get('lambda-runtime-deadline-ms'));
  invocationLogs = [];
  let outcomePath;
  let outcomeBody;
  let outcomeHeaders = {};
  try {
    const event = JSON.parse(await next.text());
    const fn = await loadHandler();
    const context = {
      awsRequestId: requestId,
      invokedFunctionArn,
      getRemainingTimeInMillis: () => Math.max(0, deadlineMs - Date.now()),
    };
    outcomePath = `/invocation/${requestId}/response`;
    outcomeBody = JSON.stringify((await fn(event, context)) ?? null);
  } catch (error) {
    outcomePath = `/invocation/${requestId}/error`;
    outcomeBody = errorPayload(error);
    outcomeHeaders = { 'lambda-runtime-function-error-type': 'Handled' };
  }

  try {
    await post(`/invocation/${requestId}/logs`, JSON.stringify(invocationLogs));
  } catch (error) {
    outcomePath = `/invocation/${requestId}/error`;
    outcomeBody = errorPayload(new Error(`Runtime log delivery failed: ${error.message}`));
    outcomeHeaders = { 'lambda-runtime-function-error-type': 'Unhandled' };
  }
  invocationLogs = null;
  await post(outcomePath, outcomeBody, outcomeHeaders);
}
"#;

const PYTHON_RIC: &str = r#"#!__PYTHON__
import importlib
import io
import json
import os
import sys
import time
import traceback
import urllib.error
import urllib.request

sys.path[:0] = ["/var/task", "/opt/python"]
API = "http://{}/2018-06-01/runtime".format(os.environ["AWS_LAMBDA_RUNTIME_API"])
module_name, function_name = os.environ["_HANDLER"].rsplit(".", 1)
handler = None

class LambdaContext:
    def __init__(self, request_id, invoked_function_arn, deadline_ms):
        self.aws_request_id = request_id
        self.invoked_function_arn = invoked_function_arn
        self._deadline_ms = deadline_ms

    def get_remaining_time_in_millis(self):
        return max(0, self._deadline_ms - int(time.time() * 1000))

def post(path, payload, error_type=None):
    headers = {"content-type": "application/json"}
    if error_type:
        headers["lambda-runtime-function-error-type"] = error_type
    request = urllib.request.Request(
        API + path,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request):
        pass

while True:
    try:
        response = urllib.request.urlopen(API + "/invocation/next")
    except urllib.error.HTTPError as error:
        if error.code == 204:
            break
        raise
    with response:
        request_id = response.headers["lambda-runtime-aws-request-id"]
        invoked_function_arn = response.headers["lambda-runtime-invoked-function-arn"]
        deadline_ms = int(response.headers["lambda-runtime-deadline-ms"])
        body = response.read()

    captured = io.StringIO()
    stdout = sys.stdout
    stderr = sys.stderr
    sys.stdout = captured
    sys.stderr = captured
    error_type = None
    try:
        if handler is None:
            handler = getattr(importlib.import_module(module_name), function_name)
        event = json.loads(body)
        context = LambdaContext(request_id, invoked_function_arn, deadline_ms)
        outcome_path = "/invocation/{}/response".format(request_id)
        outcome_payload = handler(event, context)
        json.dumps(outcome_payload)
    except Exception as error:
        outcome_path = "/invocation/{}/error".format(request_id)
        outcome_payload = {
            "errorType": type(error).__name__,
            "errorMessage": str(error),
            "stackTrace": traceback.format_exception(error),
        }
        error_type = "Handled"
    finally:
        sys.stdout = stdout
        sys.stderr = stderr

    try:
        post(
            "/invocation/{}/logs".format(request_id),
            captured.getvalue().splitlines(keepends=True),
        )
    except Exception as error:
        outcome_path = "/invocation/{}/error".format(request_id)
        outcome_payload = {
            "errorType": "RuntimeLogDeliveryError",
            "errorMessage": "Runtime log delivery failed: {}".format(error),
            "stackTrace": traceback.format_exception(error),
        }
        error_type = "Unhandled"
    post(outcome_path, outcome_payload, error_type)
"#;

/// A prepared guest rootfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rootfs {
    /// Absolute path to the rootfs directory (the guest's `/`).
    pub path: PathBuf,
    /// The process argv to launch inside the guest.
    pub entrypoint: Vec<String>,
    /// Full file names of external extensions found under `/opt/extensions`.
    pub extension_names: Vec<String>,
}

/// The standard empty directories a rootfs needs (mountpoints + layout).
const SKELETON: &[&str] = &[
    "proc",
    "dev",
    "sys",
    "tmp",
    "opt",
    "var/task",
    "var/runtime",
    "bin",
    "usr",
    "etc",
    "lib",
];

/// Build a rootfs at `dest` from the extracted `code_dir` and ordered `layer_dirs`.
///
/// The code is placed at `/var/task`; layers are merged under `/opt` (later layers overlay
/// earlier ones); `/tmp` is world-writable. A custom-runtime `bootstrap` is made executable.
pub fn build_rootfs(
    dest: &Path,
    runtime: Option<&str>,
    code_dir: &Path,
    layer_dirs: &[PathBuf],
) -> Result<Rootfs, LambdaError> {
    // Start clean.
    let _ = fs::remove_dir_all(dest);
    for dir in SKELETON {
        fs::create_dir_all(dest.join(dir)).map_err(io("create rootfs skeleton"))?;
    }
    make_writable(&dest.join("tmp"));

    // Code → /var/task.
    copy_tree(code_dir, &dest.join("var/task")).map_err(io("copy function code"))?;

    // Layers → /opt (in listed order).
    for layer in layer_dirs {
        copy_tree(layer, &dest.join("opt")).map_err(io("merge layer"))?;
    }

    let runtime_entrypoint = entrypoint(runtime);
    let extension_names = discover_extensions(dest)?;
    let entrypoint = if extension_names.is_empty() {
        runtime_entrypoint.clone()
    } else {
        install_extension_supervisor(dest)?;
        let mut command = vec![
            "/bin/bash".to_string(),
            "/var/runtime/extension-supervisor".to_string(),
        ];
        command.extend(runtime_entrypoint);
        command
    };
    // Ensure a custom-runtime bootstrap is executable. Managed runtimes are installed by the
    // production executor because in-process compute backends do not need host runtime files.
    if is_custom(runtime) {
        let bootstrap = dest.join("var/task/bootstrap");
        if !bootstrap.exists() {
            return Err(LambdaError::InvalidParameterValue(
                "custom runtime package is missing an executable `bootstrap`".into(),
            ));
        }
        make_executable(&bootstrap);
    }

    Ok(Rootfs {
        path: dest.to_path_buf(),
        entrypoint,
        extension_names,
    })
}

const EXTENSION_SUPERVISOR: &str = r#"#!/bin/bash
set -u
extension_pids=()
runtime_pid=""
stopping=0

terminate_children() {
    stopping=1
    if [[ -n "$runtime_pid" ]]; then kill -TERM "$runtime_pid" 2>/dev/null || true; fi
    for pid in "${extension_pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
}
trap terminate_children TERM INT

report_unexpected_exit() {
    local api="${AWS_LAMBDA_RUNTIME_API:-}"
    local authority="${api%%/*}"
    local prefix="${api#*/}"
    local host="${authority%:*}"
    local port="${authority##*:}"
    [[ "$api" == */* && "$host" != "$port" ]] || return 0
    if exec 3<>"/dev/tcp/$host/$port"; then
        printf 'POST /%s/2018-06-01/runtime/init/error HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' "$prefix" "$authority" >&3
        exec 3>&-
        exec 3<&-
    fi
}

for extension in /opt/extensions/*; do
    "$extension" &
    extension_pids+=("$!")
done
"$@" &
runtime_pid="$!"
children=("$runtime_pid" "${extension_pids[@]}")
while (( ${#children[@]} )); do
    finished=""
    wait -n -p finished "${children[@]}"
    status="$?"
    if [[ -z "$finished" ]]; then
        (( stopping )) && break
        continue
    fi
    remaining=()
    for pid in "${children[@]}"; do
        [[ "$pid" == "$finished" ]] || remaining+=("$pid")
    done
    children=("${remaining[@]}")
    if [[ ! -e /tmp/.localcloud-extension-shutdown && "$stopping" == 0 ]]; then
        report_unexpected_exit
        terminate_children
        break
    fi
done
for pid in "${children[@]}"; do wait "$pid" 2>/dev/null || true; done
exit 0
"#;

fn discover_extensions(dest: &Path) -> Result<Vec<String>, LambdaError> {
    let dir = dest.join("opt/extensions");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(&dir).map_err(io("read extension directory"))? {
        let entry = entry.map_err(io("read extension directory entry"))?;
        let metadata = entry
            .metadata()
            .map_err(io("inspect extension executable"))?;
        if !metadata.is_file() {
            return Err(LambdaError::InvalidParameterValue(
                "every /opt/extensions entry must be an executable file".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(LambdaError::InvalidParameterValue(format!(
                    "extension {} is not executable",
                    entry.file_name().to_string_lossy()
                )));
            }
        }
        names.push(entry.file_name().into_string().map_err(|_| {
            LambdaError::InvalidParameterValue("extension file name is not UTF-8".into())
        })?);
    }
    names.sort();
    if names.len() > 10 {
        return Err(LambdaError::InvalidParameterValue(
            "a function can have at most 10 external extensions".into(),
        ));
    }
    Ok(names)
}

fn install_extension_supervisor(dest: &Path) -> Result<(), LambdaError> {
    let shell = find_host_executable("bash")
        .ok_or_else(|| LambdaError::NotImplemented("Lambda extensions require host bash".into()))?;
    copy_host_file(&shell, &dest.join("bin/bash"))?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("bash", dest.join("bin/sh")).map_err(io("link extension shell"))?;
    copy_dynamic_dependencies(&shell, dest, &mut Default::default())?;
    let path = dest.join("var/runtime/extension-supervisor");
    fs::write(&path, EXTENSION_SUPERVISOR).map_err(io("write extension supervisor"))?;
    make_executable(&path);
    Ok(())
}

/// The launch argv for a runtime: the custom `bootstrap` or the managed RIC.
pub fn entrypoint(runtime: Option<&str>) -> Vec<String> {
    if is_custom(runtime) {
        vec![BOOTSTRAP_PATH.to_string()]
    } else {
        vec![MANAGED_RIC.to_string()]
    }
}

/// Whether the runtime is a custom (`provided.*`) runtime that ships its own bootstrap.
pub fn is_custom(runtime: Option<&str>) -> bool {
    matches!(runtime, Some(r) if r.starts_with("provided"))
}

fn io(ctx: &'static str) -> impl Fn(std::io::Error) -> LambdaError {
    move |e| LambdaError::InternalError(format!("{ctx}: {e}"))
}

pub(crate) fn install_managed_runtime(
    dest: &Path,
    runtime: Option<&str>,
) -> Result<(), LambdaError> {
    match runtime {
        Some(runtime) if runtime.starts_with("nodejs") => install_node_runtime(dest),
        Some(runtime) if runtime.starts_with("python") => install_python_runtime(dest, runtime),
        Some(runtime) if runtime.starts_with("provided") => Ok(()),
        Some(runtime) => Err(LambdaError::NotImplemented(format!(
            "managed runtime {runtime} is not installed on this host"
        ))),
        None => Err(LambdaError::InvalidParameterValue(
            "managed Zip functions require a runtime".into(),
        )),
    }
}

/// Install a managed runtime, sharing Python's host standard library between rootfses.
/// `cache_root` must be a private, persistent directory. Hardlinks are used when possible;
/// copying is used when the filesystems differ.
pub(crate) fn install_managed_runtime_with_cache(
    dest: &Path,
    runtime: Option<&str>,
    cache_root: &Path,
) -> Result<(), LambdaError> {
    match runtime {
        Some(runtime) if runtime.starts_with("python") => {
            install_python_runtime_with_cache(dest, runtime, cache_root)
        }
        _ => install_managed_runtime(dest, runtime),
    }
}

fn install_node_runtime(dest: &Path) -> Result<(), LambdaError> {
    let node = find_host_executable("node").ok_or_else(|| {
        LambdaError::NotImplemented(
            "Node.js runtime requires a `node` executable on the host".into(),
        )
    })?;
    copy_host_file(&node, &dest.join("usr/bin/node"))?;
    copy_dynamic_dependencies(&node, dest, &mut Default::default())?;

    let bootstrap = dest.join(MANAGED_RIC.trim_start_matches('/'));
    fs::write(&bootstrap, NODE_RIC).map_err(io("write Node.js Runtime Interface Client"))?;
    make_executable(&bootstrap);
    Ok(())
}

fn install_python_runtime(dest: &Path, runtime: &str) -> Result<(), LambdaError> {
    install_python_runtime_inner(dest, runtime, None)
}

fn install_python_runtime_with_cache(
    dest: &Path,
    runtime: &str,
    cache_root: &Path,
) -> Result<(), LambdaError> {
    install_python_runtime_inner(dest, runtime, Some(cache_root))
}

fn install_python_runtime_inner(
    dest: &Path,
    runtime: &str,
    cache_root: Option<&Path>,
) -> Result<(), LambdaError> {
    let version = runtime
        .strip_prefix("python")
        .expect("Python runtime prefix");
    let executable_name = format!("python{version}");
    let python = find_host_executable(&executable_name).ok_or_else(|| {
        LambdaError::NotImplemented(format!(
            "{runtime} requires a `{executable_name}` executable on the host"
        ))
    })?;

    let output = Command::new(&python)
        .args([
            "-c",
            "import sysconfig; print(sysconfig.get_path('stdlib')); print(sysconfig.get_config_var('DESTSHARED') or '')",
        ])
        .output()
        .map_err(io("inspect Python runtime layout"))?;
    if !output.status.success() {
        return Err(LambdaError::InternalError(format!(
            "inspect Python runtime layout: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let stdlib = PathBuf::from(lines.next().unwrap_or_default());
    let extensions = PathBuf::from(lines.next().unwrap_or_default());
    if !stdlib.is_absolute() || !stdlib.is_dir() {
        return Err(LambdaError::InternalError(format!(
            "{runtime} reported an invalid standard-library path: {}",
            stdlib.display()
        )));
    }

    let python_dest = dest.join(
        python
            .strip_prefix("/")
            .expect("absolute Python executable path"),
    );
    copy_host_file(&python, &python_dest)?;
    let stdlib_dest = dest.join(stdlib.strip_prefix("/").expect("absolute stdlib path"));
    fs::create_dir_all(&stdlib_dest).map_err(io("create Python standard-library directory"))?;
    if let Some(cache_root) = cache_root {
        install_cached_stdlib(&stdlib, &stdlib_dest, runtime, &python, cache_root)?;
    } else {
        copy_tree(&stdlib, &stdlib_dest).map_err(io("copy Python standard library"))?;
    }

    let mut copied = std::collections::HashSet::new();
    copy_dynamic_dependencies(&python, dest, &mut copied)?;
    if extensions.is_dir() {
        let mut shared_objects = Vec::new();
        collect_shared_objects(&extensions, &mut shared_objects)
            .map_err(io("inspect Python extension modules"))?;
        for extension in shared_objects {
            // Python installations can ship optional modules whose native libraries are
            // absent on the host (for example _tkinter without Tk). The interpreter and
            // modules with complete dependencies must remain usable.
            match copy_dynamic_dependencies(&extension, dest, &mut copied) {
                Ok(()) => {}
                Err(LambdaError::NotImplemented(message))
                    if message.starts_with("managed runtime dependency is unavailable:") =>
                {
                    tracing::debug!(module = %extension.display(), %message, "skip unavailable optional Python extension dependency");
                }
                Err(error) => return Err(error),
            }
        }
    }

    let interpreter = python.to_str().ok_or_else(|| {
        LambdaError::InternalError("Python executable path is not valid UTF-8".into())
    })?;
    let bootstrap = dest.join(MANAGED_RIC.trim_start_matches('/'));
    fs::write(
        &bootstrap,
        PYTHON_RIC.replacen("__PYTHON__", interpreter, 1),
    )
    .map_err(io("write Python Runtime Interface Client"))?;
    make_executable(&bootstrap);
    Ok(())
}

/// A process-wide filesystem lock protects cache publication across concurrent cold starts.
struct CacheLock(fs::File);

impl CacheLock {
    fn acquire(cache_root: &Path) -> Result<Self, LambdaError> {
        use std::os::fd::AsRawFd;
        fs::create_dir_all(cache_root).map_err(io("create Python runtime cache"))?;
        if fs::symlink_metadata(cache_root)
            .map_err(io("inspect Python runtime cache"))?
            .file_type()
            .is_symlink()
        {
            return Err(LambdaError::InternalError(
                "Python runtime cache must not be a symlink".into(),
            ));
        }
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        fs::set_permissions(cache_root, fs::Permissions::from_mode(0o700))
            .map_err(io("secure Python runtime cache"))?;
        let file = fs::OpenOptions::new()
            .custom_flags(libc::O_NOFOLLOW)
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(cache_root.join(".lock"))
            .map_err(io("open Python runtime cache lock"))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(LambdaError::InternalError(format!(
                "lock Python runtime cache: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self(file))
    }
}

impl Drop for CacheLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn source_fingerprint(source: &Path, runtime: &str, python: &Path) -> std::io::Result<String> {
    use std::os::unix::fs::MetadataExt;
    fn visit(path: &Path, relative: &Path, hasher: &mut Sha256) -> std::io::Result<()> {
        let link_meta = fs::symlink_metadata(path)?;
        let meta = fs::metadata(path)?;
        // Some host packages add symlinks to optional data outside stdlib. We do not
        // traverse directory symlinks into arbitrary host trees.
        if link_meta.file_type().is_symlink() && meta.is_dir() {
            return Ok(());
        }
        hasher.update(relative.as_os_str().as_encoded_bytes());
        hasher.update(meta.dev().to_le_bytes());
        hasher.update(meta.ino().to_le_bytes());
        hasher.update(meta.len().to_le_bytes());
        hasher.update(meta.mtime().to_le_bytes());
        hasher.update(meta.mtime_nsec().to_le_bytes());
        hasher.update(meta.ctime().to_le_bytes());
        hasher.update(meta.ctime_nsec().to_le_bytes());
        if meta.is_dir() {
            let mut entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                visit(&entry.path(), &relative.join(entry.file_name()), hasher)?;
            }
        }
        Ok(())
    }
    let mut hasher = Sha256::new();
    hasher.update(b"localcloud-python-stdlib-v1");
    hasher.update(runtime.as_bytes());
    hasher.update(source.as_os_str().as_encoded_bytes());
    hasher.update(python.as_os_str().as_encoded_bytes());
    visit(python, Path::new("python-executable"), &mut hasher)?;
    visit(source, Path::new("stdlib"), &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn install_cached_stdlib(
    source: &Path,
    dest: &Path,
    runtime: &str,
    python: &Path,
    cache_root: &Path,
) -> Result<(), LambdaError> {
    let _lock = CacheLock::acquire(cache_root)?;
    let fingerprint = source_fingerprint(source, runtime, python)
        .map_err(io("fingerprint Python standard library"))?;
    let cache = cache_root.join(format!("{runtime}-{fingerprint}"));
    if cache.exists() {
        if fs::symlink_metadata(&cache)
            .map_err(io("inspect Python runtime cache entry"))?
            .file_type()
            .is_symlink()
        {
            return Err(LambdaError::InternalError(
                "Python runtime cache entry must not be a symlink".into(),
            ));
        }
        if !cache.join(".complete").is_file() {
            fs::remove_dir_all(&cache).map_err(io("remove incomplete Python runtime cache"))?;
        }
    }
    if !cache.exists() {
        let stage = cache_root.join(format!(".stage-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&stage).map_err(io("stage Python runtime cache"))?;
        let result = (|| {
            let data = stage.join("stdlib");
            fs::create_dir(&data).map_err(io("create cached Python standard library"))?;
            copy_stdlib_tree(source, &data).map_err(io("cache Python standard library"))?;
            let after = source_fingerprint(source, runtime, python)
                .map_err(io("recheck Python standard library"))?;
            if after != fingerprint {
                return Err(LambdaError::InternalError(
                    "Python standard library changed while caching".into(),
                ));
            }
            freeze_cached_tree(&data).map_err(io("freeze Python runtime cache"))?;
            fs::write(stage.join(".complete"), fingerprint.as_bytes())
                .map_err(io("complete Python runtime cache"))?;
            fs::rename(&stage, &cache).map_err(io("publish Python runtime cache"))
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&stage);
        }
        result?;
    }
    let marker = cache.join(".complete");
    if fs::symlink_metadata(&marker)
        .map_err(io("inspect Python runtime cache marker"))?
        .file_type()
        .is_symlink()
        || fs::read_to_string(&marker).map_err(io("read Python runtime cache marker"))?
            != fingerprint
    {
        return Err(LambdaError::InternalError(
            "Python runtime cache marker is invalid".into(),
        ));
    }
    link_cached_tree(&cache.join("stdlib"), dest)
        .map_err(io("install cached Python standard library"))
}

/// Materialize files without importing symlink targets outside the standard library.
fn copy_stdlib_tree(source: &Path, dest: &Path) -> std::io::Result<()> {
    let root = fs::canonicalize(source)?;
    fn visit(source: &Path, dest: &Path, root: &Path) -> std::io::Result<()> {
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let target = dest.join(entry.file_name());
            if kind.is_dir() {
                fs::create_dir(&target)?;
                visit(&entry.path(), &target, root)?;
            } else if kind.is_file() {
                fs::copy(entry.path(), target)?;
            } else if kind.is_symlink() {
                // Host Python packages may contain optional links to system directories.
                // Only internal file links are safe to copy into an isolated guest.
                let Ok(resolved) = fs::canonicalize(entry.path()) else {
                    continue;
                };
                if resolved.starts_with(root) && resolved.is_file() {
                    fs::copy(resolved, target)?;
                }
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Python standard library contains an unsupported file",
                ));
            }
        }
        Ok(())
    }
    visit(source, dest, &root)
}

#[cfg(unix)]
fn freeze_cached_tree(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            freeze_cached_tree(&entry.path())?;
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o555))?;
        } else if kind.is_file() {
            let meta = entry.metadata()?;
            let mode = if meta.permissions().mode() & 0o111 != 0 {
                0o555
            } else {
                0o444
            };
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode))?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cached standard library contains a link or special file",
            ));
        }
    }
    Ok(())
}

fn link_cached_tree(source: &Path, dest: &Path) -> std::io::Result<()> {
    if !fs::symlink_metadata(source)?.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "cached standard library is not a directory",
        ));
    }
    fs::create_dir_all(dest)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = dest.join(entry.file_name());
        if kind.is_dir() {
            link_cached_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            // A different filesystem (or one without hardlink support) falls back to copying.
            if fs::hard_link(entry.path(), &target).is_err() {
                fs::copy(entry.path(), &target)?;
            }
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cached standard library contains a link or special file",
            ));
        }
    }
    Ok(())
}

fn find_host_executable(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/usr/local/bin"]
        .into_iter()
        .map(Path::new)
        .map(|dir| dir.join(name))
        .chain(
            std::env::var_os("PATH")
                .into_iter()
                .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
                .map(|dir| dir.join(name)),
        )
        .find(|path| path.is_file())
        .and_then(|path| fs::canonicalize(path).ok())
}

fn dynamic_loader() -> Option<PathBuf> {
    if let Ok(maps) = fs::read_to_string("/proc/self/maps") {
        for path in maps
            .lines()
            .filter_map(|line| line.split_whitespace().last())
            .map(Path::new)
        {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if path.is_absolute()
                && path.is_file()
                && (name.contains("ld-linux") || name.starts_with("ld-musl"))
            {
                return Some(path.to_path_buf());
            }
        }
    }
    [
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/ld-linux-aarch64.so.1",
        "/lib/ld-musl-x86_64.so.1",
        "/lib/ld-musl-aarch64.so.1",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
}

fn copy_dynamic_dependencies(
    source: &Path,
    dest: &Path,
    copied: &mut std::collections::HashSet<PathBuf>,
) -> Result<(), LambdaError> {
    let loader = dynamic_loader().ok_or_else(|| {
        LambdaError::NotImplemented(
            "managed runtimes require a discoverable host dynamic loader".into(),
        )
    })?;
    // `/proc/self/maps` commonly reports the canonical `/usr/lib/...` loader while an ELF's
    // PT_INTERP requests its compatibility path (for example `/lib64/...`). Preserve both.
    for candidate in [
        loader.as_path(),
        Path::new("/lib64/ld-linux-x86-64.so.2"),
        Path::new("/lib/ld-linux-aarch64.so.1"),
        Path::new("/lib/ld-musl-x86_64.so.1"),
        Path::new("/lib/ld-musl-aarch64.so.1"),
    ] {
        if candidate.is_file() && copied.insert(candidate.to_path_buf()) {
            copy_host_file(
                candidate,
                &dest.join(candidate.strip_prefix("/").expect("absolute loader path")),
            )?;
        }
    }
    let output = Command::new(&loader)
        .arg("--list")
        .arg(source)
        .output()
        .map_err(io("inspect managed runtime shared libraries"))?;
    if !output.status.success() {
        return Err(LambdaError::InternalError(format!(
            "inspect managed runtime shared libraries for {}: {}",
            source.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.contains("=> not found") {
            return Err(LambdaError::NotImplemented(format!(
                "managed runtime dependency is unavailable: {}",
                line.trim()
            )));
        }
        let resolved = line.split_once("=>").map_or(line, |(_, resolved)| resolved);
        let candidate = resolved.split_whitespace().next().unwrap_or("");
        let library = Path::new(candidate);
        if library.is_absolute() && library.exists() && copied.insert(library.to_path_buf()) {
            copy_host_file(
                library,
                &dest.join(library.strip_prefix("/").expect("absolute library path")),
            )?;
        }
    }
    Ok(())
}

fn collect_shared_objects(path: &Path, output: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            collect_shared_objects(&entry.path(), output)?;
        } else if entry.file_name().to_string_lossy().contains(".so") {
            output.push(entry.path());
        }
    }
    Ok(())
}

fn copy_host_file(source: &Path, destination: &Path) -> Result<(), LambdaError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(io("create managed runtime directory"))?;
    }
    fs::copy(source, destination)
        .map(|_| ())
        .map_err(io("copy managed runtime file"))
}

/// Recursively copy the contents of `src` into `dst` (which must exist), overlaying files.
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if file_type.is_dir() {
            fs::create_dir_all(&target)?;
            copy_tree(&entry.path(), &target)?;
        } else {
            // `fs::copy` preserves the source permission bits (including the exec bit).
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn make_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o1777));
}

#[cfg(not(unix))]
fn make_writable(_path: &Path) {}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(perms.mode() | 0o111);
        let _ = fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp() -> PathBuf {
        std::env::temp_dir().join(format!("lc-rootfs-{}", uuid::Uuid::new_v4()))
    }

    fn write_file(path: &Path, contents: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut f = fs::File::create(path).unwrap();
        f.write_all(contents).unwrap();
    }

    #[cfg(unix)]
    fn make_cache_removable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                make_cache_removable(&entry.unwrap().path());
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn cached_stdlib_shares_files_and_invalidates_changed_source() {
        use std::os::unix::fs::MetadataExt;
        let base = temp();
        let source = base.join("host/python");
        let python = base.join("host/bin/python3.14");
        let cache = base.join("cache");
        let first = base.join("first");
        let second = base.join("second");
        let third = base.join("third");
        write_file(&source.join("pkg/module.py"), b"version = 1\n");
        write_file(&python, b"python executable");
        write_file(&base.join("private.txt"), b"must not enter guest");
        std::os::unix::fs::symlink(base.join("private.txt"), source.join("external.txt")).unwrap();
        std::os::unix::fs::symlink("pkg/module.py", source.join("internal.py")).unwrap();
        std::os::unix::fs::symlink(base.join("host"), source.join("external-dir")).unwrap();

        install_cached_stdlib(&source, &first, "python3.14", &python, &cache).unwrap();
        assert!(!first.join("external.txt").exists());
        assert!(!first.join("external-dir").exists());
        assert_eq!(
            fs::read(first.join("internal.py")).unwrap(),
            b"version = 1\n"
        );
        install_cached_stdlib(&source, &second, "python3.14", &python, &cache).unwrap();
        let source_file = first.join("pkg/module.py");
        let second_file = second.join("pkg/module.py");
        assert_eq!(
            fs::metadata(&source_file).unwrap().ino(),
            fs::metadata(&second_file).unwrap().ino()
        );

        // A source revision gets a new immutable cache entry; old rootfses retain their data.
        write_file(&source.join("pkg/module.py"), b"version = 2\n");
        install_cached_stdlib(&source, &third, "python3.14", &python, &cache).unwrap();
        let third_file = third.join("pkg/module.py");
        assert_ne!(
            fs::metadata(&source_file).unwrap().ino(),
            fs::metadata(&third_file).unwrap().ino()
        );
        assert_eq!(fs::read(source_file).unwrap(), b"version = 1\n");
        assert_eq!(fs::read(third_file).unwrap(), b"version = 2\n");
        make_cache_removable(&cache);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn concurrent_cache_publication_produces_complete_entries() {
        let base = temp();
        let source = base.join("host/python");
        let python = base.join("host/bin/python3.14");
        let cache = base.join("cache");
        write_file(&source.join("pkg/module.py"), b"stable");
        write_file(&python, b"python executable");
        std::thread::scope(|scope| {
            for index in 0..4 {
                let dest = base.join(format!("rootfs-{index}"));
                let source = source.clone();
                let python = python.clone();
                let cache = cache.clone();
                scope.spawn(move || {
                    install_cached_stdlib(&source, &dest, "python3.14", &python, &cache).unwrap();
                    assert_eq!(fs::read(dest.join("pkg/module.py")).unwrap(), b"stable");
                });
            }
        });
        let entries = fs::read_dir(&cache)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("python3.14-")
            })
            .count();
        assert_eq!(entries, 1);
        make_cache_removable(&cache);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn builds_custom_runtime_rootfs_with_layers() {
        let base = temp();
        let code = base.join("code");
        write_file(&code.join("bootstrap"), b"#!/bin/sh\n");
        write_file(&code.join("handler.sh"), b"echo hi\n");
        let layer = base.join("layer");
        write_file(&layer.join("lib/helper.sh"), b"x\n");
        let dest = base.join("rootfs");

        let rootfs = build_rootfs(&dest, Some("provided.al2023"), &code, &[layer]).unwrap();
        assert_eq!(rootfs.entrypoint, vec!["/var/task/bootstrap".to_string()]);
        assert!(dest.join("var/task/bootstrap").exists());
        assert!(dest.join("var/task/handler.sh").exists());
        assert!(dest.join("opt/lib/helper.sh").exists());
        assert!(dest.join("tmp").exists());
        assert!(dest.join("proc").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dest.join("var/task/bootstrap"))
                .unwrap()
                .permissions()
                .mode();
            assert!(mode & 0o111 != 0, "bootstrap is executable");
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn extension_layer_uses_supervisor_and_preserves_runtime_command() {
        if find_host_executable("bash").is_none() {
            return;
        }
        let base = temp();
        let code = base.join("code");
        write_file(&code.join("bootstrap"), b"#!/bin/sh\n");
        let layer = base.join("layer");
        for name in ["zeta", "alpha"] {
            let path = layer.join("extensions").join(name);
            write_file(&path, b"#!/bin/sh\nexit 0\n");
            make_executable(&path);
        }
        let dest = base.join("rootfs");
        let rootfs = build_rootfs(&dest, Some("provided.al2023"), &code, &[layer]).unwrap();
        assert_eq!(rootfs.extension_names, vec!["alpha", "zeta"]);
        assert_eq!(
            rootfs.entrypoint,
            vec![
                "/bin/bash",
                "/var/runtime/extension-supervisor",
                "/var/task/bootstrap"
            ]
        );
        assert!(dest.join("bin/bash").is_file());
        assert!(dest.join("var/runtime/extension-supervisor").is_file());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn non_executable_extension_fails_rootfs_build() {
        let base = temp();
        let code = base.join("code");
        write_file(&code.join("bootstrap"), b"#!/bin/sh\n");
        let layer = base.join("layer");
        write_file(&layer.join("extensions/not-executable"), b"data");
        let dest = base.join("rootfs");
        let result = build_rootfs(&dest, Some("provided.al2023"), &code, &[layer]);
        assert!(matches!(result, Err(LambdaError::InvalidParameterValue(_))));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn managed_runtime_uses_platform_ric() {
        let base = temp();
        let code = base.join("code");
        write_file(
            &code.join("index.js"),
            b"exports.handler = async () => ({});\n",
        );
        let dest = base.join("rootfs");
        let rootfs = build_rootfs(&dest, Some("nodejs22.x"), &code, &[]).unwrap();
        assert_eq!(
            rootfs.entrypoint,
            vec!["/var/runtime/bootstrap".to_string()]
        );
        assert!(dest.join("var/task/index.js").exists());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn installed_node_runtime_preserves_elf_loader_compatibility_path() {
        if find_host_executable("node").is_none() {
            return;
        }
        let base = temp();
        fs::create_dir_all(base.join("var/runtime")).unwrap();
        install_node_runtime(&base).unwrap();
        assert!(base.join("usr/bin/node").is_file());
        for loader in [
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/ld-linux-aarch64.so.1",
            "/lib/ld-musl-x86_64.so.1",
            "/lib/ld-musl-aarch64.so.1",
        ] {
            if Path::new(loader).is_file() {
                assert!(base.join(loader.trim_start_matches('/')).is_file());
            }
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn custom_runtime_without_bootstrap_is_rejected() {
        let base = temp();
        let code = base.join("code");
        write_file(&code.join("main"), b"x\n");
        let dest = base.join("rootfs");
        let err = build_rootfs(&dest, Some("provided.al2"), &code, &[]).unwrap_err();
        assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
        let _ = fs::remove_dir_all(&base);
    }
}
