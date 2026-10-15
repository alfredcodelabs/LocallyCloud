//! Guest rootfs construction for a function's execution environment.
//!
//! Composes a self-contained rootfs directory the [`ComputeRuntime`](locallycloud_compute)
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
'use strict';
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const util = require('node:util');

const api = `http://${process.env.AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime`;
// Captured before user code loads: tracers (aws-xray-sdk `captureHTTPsGlobal`, Powertools
// Tracer) replace the `http.request` property and instrument `fetch`, so Runtime API calls
// through the saved reference never appear in, or attach to, user traces.
const runtimeRequest = http.request;
const runtimeAgent = new http.Agent({ keepAlive: true });
const taskRoot = path.resolve(process.env.LAMBDA_TASK_ROOT || '/var/task');
const handlerName = process.env._HANDLER ?? '';
let invocationLogs = null;
let logBytes = 0;
let droppedLogBytes = 0;
const logLimit = 128 * 1024;

function captureWrites(stream) {
  const write = stream.write.bind(stream);
  stream.write = (chunk, encoding, callback) => {
    if (invocationLogs !== null) {
      const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), typeof encoding === 'string' ? encoding : 'utf8');
      const size = invocationLogs.length < 4096 ? Math.min(data.length, logLimit - logBytes) : 0;
      if (size > 0) invocationLogs.push(data.subarray(0, size).toString('utf8'));
      logBytes += size;
      droppedLogBytes += data.length - size;
    }
    return write(chunk, encoding, callback);
  };
}

captureWrites(process.stdout);
captureWrites(process.stderr);

// The AWS client's text log format (LogPatch): the global console methods write
// `<ISO time>\t<request id>\t<LEVEL>\t<message>` to stdout, `console.log` as INFO; the request
// id is `undefined` until the first invocation and then the latest one. Loggers with their own
// `Console` on `process.stdout` (Powertools) bypass the patch and stay raw.
let currentRequestId;
for (const [method, level] of Object.entries({
  trace: 'TRACE', debug: 'DEBUG', info: 'INFO', warn: 'WARN', error: 'ERROR', fatal: 'FATAL',
})) {
  console[method] = (message, ...params) => {
    process.stdout.write(`${new Date().toISOString()}\t${currentRequestId}\t${level}\t${util.format(message, ...params)}\n`);
  };
}
console.log = console.info;

function startCapture() {
  invocationLogs = [];
  logBytes = 0;
  droppedLogBytes = 0;
}

function endCapture() {
  const logs = invocationLogs ?? [];
  if (droppedLogBytes > 0) logs.push(`\n[locallycloud: ${droppedLogBytes} log bytes dropped because the capture limit was exceeded]\n`);
  invocationLogs = null;
  return logs;
}

class RuntimeError extends Error {
  constructor(name, message) {
    super(message);
    Object.defineProperty(this, 'name', { value: name });
    Error.captureStackTrace(this, RuntimeError);
  }
}

// `.js` is ESM when the nearest package.json has `"type": "module"`; the lookup stops at a
// `node_modules` directory, as in the AWS client.
function folderHasTypeModule(folder) {
  if (folder.endsWith('/node_modules')) return false;
  const manifest = path.join(folder, 'package.json');
  if (fs.existsSync(manifest)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(manifest, 'utf8'));
      if (pkg) return pkg.type === 'module';
    } catch {
      return false;
    }
  }
  if (folder === path.dirname(folder)) return false;
  return folderHasTypeModule(path.dirname(folder));
}

function tryRequire(file) {
  return fs.existsSync(file) ? require(file) : undefined;
}

async function tryImport(file) {
  return fs.existsSync(file) ? await import(pathToFileURL(file).href) : undefined;
}

// The AWS client's lookup (`UserFunction.js`): the extensionless path (a file or a directory
// index), `.js` per package.json `type`, `.mjs`, `.cjs`, then Node resolution from the task
// root and module root (`node_modules` packages).
async function loadModule(moduleRoot, moduleName) {
  const lambdaStylePath = path.resolve(taskRoot, moduleRoot, moduleName);
  const extensionless = tryRequire(lambdaStylePath);
  if (extensionless) return extensionless;
  const jsPath = `${lambdaStylePath}.js`;
  const typeModule = fs.existsSync(jsPath) && folderHasTypeModule(path.dirname(jsPath));
  if (!typeModule) {
    const loaded = tryRequire(jsPath);
    if (loaded) return loaded;
  }
  const loaded = (typeModule && (await tryImport(jsPath)))
    || (await tryImport(`${lambdaStylePath}.mjs`))
    || tryRequire(`${lambdaStylePath}.cjs`);
  if (loaded) return loaded;
  return require(require.resolve(moduleName, { paths: [taskRoot, path.resolve(taskRoot, moduleRoot)] }));
}

async function loadHandler() {
  // As the AWS client: only `..` is rejected, so absolute (`/opt/...`) and `./` module roots
  // work. The basename splits on its first '.' into the module name and a dotted property
  // path (`src/app.handlers.main` -> module root `src/`, module `app`, `handlers.main`).
  if (handlerName.includes('..') || handlerName.includes('\0')) {
    throw new RuntimeError('Runtime.MalformedHandlerName', `'${handlerName}' is not a valid handler name. Use absolute paths when specifying root directories in handler names.`);
  }
  const moduleAndHandler = path.basename(handlerName);
  const moduleRoot = handlerName.substring(0, handlerName.indexOf(moduleAndHandler));
  const match = moduleAndHandler.match(/^([^.]*)\.(.*)$/);
  if (!match) {
    throw new RuntimeError('Runtime.MalformedHandlerName', 'Bad handler');
  }
  const [, moduleName, handlerPath] = match;
  let loaded;
  try {
    loaded = await loadModule(moduleRoot, moduleName);
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new RuntimeError('Runtime.UserCodeSyntaxError', `${error.name}: ${error.message}`);
    }
    if (error?.code === 'MODULE_NOT_FOUND' || error?.code === 'ERR_MODULE_NOT_FOUND') {
      throw new RuntimeError('Runtime.ImportModuleError', `Error: ${error.message}`);
    }
    throw error;
  }
  const handler = handlerPath.split('.').reduce((value, key) => value?.[key], loaded);
  if (!handler) {
    throw new RuntimeError('Runtime.HandlerNotFound', `${handlerName} is undefined or not exported`);
  }
  if (typeof handler !== 'function') {
    throw new RuntimeError('Runtime.HandlerNotFound', `${handlerName} is not a function`);
  }
  return handler;
}

function errorPayload(error) {
  return JSON.stringify({
    errorType: error?.name ?? 'Error',
    errorMessage: error?.message ?? String(error),
    stackTrace: String(error?.stack ?? '').split('\n').slice(1),
  });
}

function logError(requestId, label, error) {
  const record = JSON.stringify({
    errorType: error?.name ?? 'Error',
    errorMessage: error?.message ?? String(error),
    stack: String(error?.stack ?? '').split('\n'),
  });
  process.stderr.write(`${new Date().toISOString()}\t${requestId}\tERROR\t${label} \t${record}\n`);
}

function runtimeCall(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const request = runtimeRequest(`${api}${path}`, { method, headers, agent: runtimeAgent }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('error', reject);
      response.on('end', () => resolve({
        status: response.statusCode,
        ok: response.statusCode >= 200 && response.statusCode < 300,
        headers: response.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    request.on('error', reject);
    request.end(body);
  });
}

async function post(path, body, headers = {}) {
  const response = await runtimeCall('POST', path, body, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
    ...headers,
  });
  if (!response.ok) throw new Error(`Runtime API ${path} failed with ${response.status}`);
}

// Init: load the handler before the first `next`; on failure report `/init/error` and exit.
async function initialize() {
  startCapture();
  let handler;
  let initFailed = false;
  let initError;
  try {
    handler = await loadHandler();
  } catch (error) {
    initFailed = true;
    initError = error;
    logError('undefined', 'Uncaught Exception', error);
  }
  try {
    await post('/init/logs', JSON.stringify(endCapture()));
  } catch {
    // Init output is best effort; the runtime still reports its Init outcome.
  }
  if (initFailed) {
    const errorType = String(initError?.name ?? '').replace(/[^A-Za-z0-9.]/g, '') || 'Runtime.Unknown';
    await post('/init/error', errorPayload(initError), { 'lambda-runtime-function-error-type': errorType });
    process.exit(1);
  }
  return handler;
}

async function invoke(handler, next) {
  const requestId = next.headers['lambda-runtime-aws-request-id'];
  const invokedFunctionArn = next.headers['lambda-runtime-invoked-function-arn'];
  const deadlineMs = Number(next.headers['lambda-runtime-deadline-ms']);
  const traceId = next.headers['lambda-runtime-trace-id'];
  currentRequestId = requestId;
  if (traceId) {
    process.env._X_AMZN_TRACE_ID = traceId;
  } else {
    delete process.env._X_AMZN_TRACE_ID;
  }
  startCapture();
  let outcomePath;
  let outcomeBody;
  let outcomeHeaders = {};
  try {
    const event = JSON.parse(next.body);
    const context = {
      callbackWaitsForEmptyEventLoop: true,
      functionName: process.env.AWS_LAMBDA_FUNCTION_NAME,
      functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION,
      memoryLimitInMB: process.env.AWS_LAMBDA_FUNCTION_MEMORY_SIZE,
      logGroupName: process.env.AWS_LAMBDA_LOG_GROUP_NAME,
      logStreamName: process.env.AWS_LAMBDA_LOG_STREAM_NAME,
      awsRequestId: requestId,
      invokedFunctionArn,
      getRemainingTimeInMillis: () => Math.max(0, deadlineMs - Date.now()),
    };
    outcomePath = `/invocation/${requestId}/response`;
    outcomeBody = JSON.stringify((await handler(event, context)) ?? null);
  } catch (error) {
    // As the AWS client: no error-type header; Lambda reports it `Unhandled` and keeps the
    // environment.
    outcomePath = `/invocation/${requestId}/error`;
    outcomeBody = errorPayload(error);
    logError(requestId, 'Invoke Error', error);
  }

  const logs = endCapture();
  try {
    await post(`/invocation/${requestId}/logs`, JSON.stringify(logs));
  } catch (error) {
    // A runtime fault: the private header resets the environment.
    outcomePath = `/invocation/${requestId}/error`;
    outcomeBody = errorPayload(new Error(`Runtime log delivery failed: ${error.message}`));
    outcomeHeaders = { 'locallycloud-runtime-fault': '1' };
  }
  await post(outcomePath, outcomeBody, outcomeHeaders);
}

async function main() {
  const handler = await initialize();
  while (true) {
    const next = await runtimeCall('GET', '/invocation/next');
    if (next.status === 204) break;
    if (!next.ok) throw new Error(`Runtime API next failed with ${next.status}`);
    await invoke(handler, next);
  }
}

main().catch((error) => {
  process.stderr.write(`${String(error?.stack ?? error)}\n`);
  process.exit(1);
});
"#;

const PYTHON_RIC: &str = r#"#!__PYTHON__
import importlib
import json
import os
import sys
import time
import traceback
import urllib.error
import urllib.request

# Lambda's import precedence: function code, layers, then the runtime-provided SDK.
PYTHON_DIR = "python{}.{}".format(*sys.version_info[:2])
sys.path[:0] = [
    os.environ.get("LAMBDA_TASK_ROOT", "/var/task"),
    "/opt/python/lib/{}/site-packages".format(PYTHON_DIR),
    "/opt/python",
    "/var/lang/lib/{}/site-packages".format(PYTHON_DIR),
]
API = "http://{}/2018-06-01/runtime".format(os.environ["AWS_LAMBDA_RUNTIME_API"])
invocation_logs = None
log_bytes = 0
dropped_log_bytes = 0
LOG_LIMIT = 128 * 1024

class InvocationTee:
    """A persistent stdout/stderr that also records output of the active invocation.

    Handler modules (and logging handlers they configure) may keep a reference to the stream
    they saw at import time, so the stream object itself must never be swapped.
    """

    def __init__(self, stream):
        self._stream = stream

    @property
    def encoding(self):
        return self._stream.encoding

    def write(self, data):
        global log_bytes, dropped_log_bytes
        written = self._stream.write(data)
        # Read the global once: another thread may end the invocation concurrently.
        logs = invocation_logs
        if logs is not None:
            # Concurrent writers can overshoot the limit; a negative slice would keep text.
            remaining = max(0, LOG_LIMIT - log_bytes)
            # Bound the encoding allocation too, even for one very large write.
            retained = data[:remaining].encode("utf-8")[:remaining].decode("utf-8", errors="ignore") if len(logs) < 4096 else ""
            size = len(retained.encode("utf-8"))
            if retained:
                logs.append(retained)
            log_bytes += size
            dropped_log_bytes += len(data) - len(retained)
        return written

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def flush(self):
        self._stream.flush()

    def isatty(self):
        return self._stream.isatty()

    def fileno(self):
        return self._stream.fileno()

    def __getattr__(self, name):
        return getattr(self._stream, name)

sys.stdout = InvocationTee(sys.stdout)
sys.stderr = InvocationTee(sys.stderr)

class CognitoIdentity:
    def __init__(self):
        self.cognito_identity_id = None
        self.cognito_identity_pool_id = None

class LambdaContext:
    def __init__(self, request_id, invoked_function_arn, deadline_ms):
        self.aws_request_id = request_id
        self.invoked_function_arn = invoked_function_arn
        self.function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        self.function_version = os.environ.get("AWS_LAMBDA_FUNCTION_VERSION")
        self.memory_limit_in_mb = os.environ.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE")
        self.log_group_name = os.environ.get("AWS_LAMBDA_LOG_GROUP_NAME")
        self.log_stream_name = os.environ.get("AWS_LAMBDA_LOG_STREAM_NAME")
        self.identity = CognitoIdentity()
        self.client_context = None
        self._deadline_ms = deadline_ms

    def get_remaining_time_in_millis(self):
        return max(0, self._deadline_ms - int(time.time() * 1000))

class FaultException(Exception):
    """A runtime fault reported with a Lambda error type instead of a Python class name."""

    def __init__(self, error_type, message):
        super().__init__(message)
        self.error_type = error_type

def load_handler(handler_name):
    try:
        module_name, function_name = handler_name.rsplit(".", 1)
    except ValueError as error:
        raise FaultException("Runtime.MalformedHandlerName", "Bad handler '{}': {}".format(handler_name, error)) from None
    segments = module_name.split("/")
    if module_name.startswith("/") or "\\" in module_name or "\0" in module_name or any(segment in ("", ".", "..") for segment in segments):
        raise FaultException("Runtime.MalformedHandlerName", "Bad handler '{}'".format(handler_name))
    try:
        module = importlib.import_module(module_name.replace("/", "."))
    except ImportError as error:
        raise FaultException("Runtime.ImportModuleError", "Unable to import module '{}': {}".format(module_name, error)) from None
    except SyntaxError as error:
        raise FaultException("Runtime.UserCodeSyntaxError", "Syntax error in module '{}': {}".format(module_name, error)) from None
    try:
        return getattr(module, function_name)
    except AttributeError:
        # The Lambda Python runtime completes Init and fails each invocation instead.
        message = "Handler '{}' missing on module '{}'".format(function_name, module_name)

        def missing_handler(event, context):
            raise FaultException("Runtime.HandlerNotFound", message)

        return missing_handler

def error_payload(error):
    if isinstance(error, FaultException):
        return {"errorType": error.error_type, "errorMessage": str(error), "stackTrace": []}
    return {
        "errorType": type(error).__name__,
        "errorMessage": str(error),
        "stackTrace": traceback.format_exception(error),
    }

def log_error(payload, error):
    frames = [] if isinstance(error, FaultException) else traceback.format_tb(error.__traceback__)
    lines = ["[ERROR] {}: {}".format(payload["errorType"], payload["errorMessage"]), "Traceback (most recent call last):"]
    lines.extend(frame.rstrip("\n") for frame in frames)
    sys.stdout.write("\n".join(lines) + "\n")

def start_capture():
    global invocation_logs, log_bytes, dropped_log_bytes
    invocation_logs = []
    log_bytes = 0
    dropped_log_bytes = 0

def end_capture():
    global invocation_logs
    logs = invocation_logs
    if dropped_log_bytes:
        logs.append("\n[locallycloud: {} log characters dropped because the capture limit was exceeded]\n".format(dropped_log_bytes))
    captured = "".join(logs)
    invocation_logs = None
    sys.stdout.flush()
    sys.stderr.flush()
    return captured

def post(path, payload, error_type=None, runtime_fault=False):
    headers = {"content-type": "application/json"}
    if error_type:
        error_type = "".join(c for c in error_type if c.isascii() and (c.isalnum() or c == "."))
        headers["lambda-runtime-function-error-type"] = error_type or "Runtime.Unknown"
    if runtime_fault:
        # Private header: the runtime itself failed, so the environment is reset.
        headers["locallycloud-runtime-fault"] = "1"
    request = urllib.request.Request(
        API + path,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request):
        pass

# Init: import the handler before the first `next`; on failure report `/init/error` and exit.
start_capture()
handler = None
init_error = None
try:
    handler = load_handler(os.environ.get("_HANDLER", ""))
except Exception as error:
    init_error = error_payload(error)
    log_error(init_error, error)
init_output = end_capture()
try:
    post("/init/logs", [init_output])
except Exception:
    pass
if init_error is not None:
    post("/init/error", init_error, init_error["errorType"])
    sys.exit(1)

while True:
    with urllib.request.urlopen(API + "/invocation/next") as response:
        if response.status == 204:
            break
        request_id = response.headers["lambda-runtime-aws-request-id"]
        invoked_function_arn = response.headers["lambda-runtime-invoked-function-arn"]
        deadline_ms = int(response.headers["lambda-runtime-deadline-ms"])
        trace_id = response.headers.get("lambda-runtime-trace-id")
        body = response.read()

    if trace_id:
        os.environ["_X_AMZN_TRACE_ID"] = trace_id
    else:
        os.environ.pop("_X_AMZN_TRACE_ID", None)
    start_capture()
    runtime_fault = False
    try:
        event = json.loads(body)
        context = LambdaContext(request_id, invoked_function_arn, deadline_ms)
        outcome_path = "/invocation/{}/response".format(request_id)
        outcome_payload = handler(event, context)
        json.dumps(outcome_payload)
    except Exception as error:
        outcome_path = "/invocation/{}/error".format(request_id)
        # As the AWS client: no error-type header; Lambda reports it `Unhandled` and keeps
        # the environment.
        outcome_payload = error_payload(error)
        log_error(outcome_payload, error)
    finally:
        captured = end_capture()

    try:
        post(
            "/invocation/{}/logs".format(request_id),
            [captured],
        )
    except Exception as error:
        outcome_path = "/invocation/{}/error".format(request_id)
        outcome_payload = {
            "errorType": "RuntimeLogDeliveryError",
            "errorMessage": "Runtime log delivery failed: {}".format(error),
            "stackTrace": traceback.format_exception(error),
        }
        runtime_fault = True
    post(outcome_path, outcome_payload, runtime_fault=runtime_fault)
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

# Tell the host which process class exited ("runtime" or "extension"). The exiting process
# posts its own error first; reading the status line keeps this report before guest exit.
report_unexpected_exit() {
    local exited="$1"
    local api="${AWS_LAMBDA_RUNTIME_API:-}"
    local authority="${api%%/*}"
    local prefix="${api#*/}"
    local host="${authority%:*}"
    local port="${authority##*:}"
    [[ "$api" == */* && "$host" != "$port" ]] || return 0
    if exec 3<>"/dev/tcp/$host/$port"; then
        printf 'POST /%s/locallycloud/supervisor/exit HTTP/1.1\r\nHost: %s\r\nLocallycloud-Exited: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' "$prefix" "$authority" "$exited" >&3
        IFS= read -r -t 2 _ <&3 || true
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
    if [[ ! -e /tmp/.locallycloud-extension-shutdown && "$stopping" == 0 ]]; then
        exited=extension
        [[ "$finished" == "$runtime_pid" ]] && exited=runtime
        report_unexpected_exit "$exited"
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

/// Install the minimal guest tools needed to wait for a VPC network proxy before
/// starting a runtime. This also covers custom runtimes with no bundled shell.
pub(crate) fn install_vpc_wait_tools(dest: &Path) -> Result<(), LambdaError> {
    if !dest.join("bin/bash").exists() {
        let bash = find_host_executable("bash")
            .ok_or_else(|| LambdaError::NotImplemented("VPC Lambda requires host bash".into()))?;
        copy_host_file(&bash, &dest.join("bin/bash"))?;
        copy_dynamic_dependencies(&bash, dest, &mut Default::default())?;
    }
    if !dest.join("bin/sh").exists() {
        #[cfg(unix)]
        std::os::unix::fs::symlink("bash", dest.join("bin/sh"))
            .map_err(io("link VPC wait shell"))?;
    }
    let sleep = find_host_executable("sleep")
        .ok_or_else(|| LambdaError::NotImplemented("VPC Lambda requires host sleep".into()))?;
    copy_host_file(&sleep, &dest.join("bin/sleep"))?;
    copy_dynamic_dependencies(&sleep, dest, &mut Default::default())?;
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
/// copying is used when the filesystems differ. The installation (host interpreter
/// inspection, tree fingerprints, cache lock, copies) runs on the blocking thread pool.
pub(crate) async fn install_managed_runtime_with_cache(
    dest: &Path,
    runtime: Option<&str>,
    cache_root: &Path,
) -> Result<(), LambdaError> {
    let (dest, runtime, cache_root) = (
        dest.to_path_buf(),
        runtime.map(str::to_owned),
        cache_root.to_path_buf(),
    );
    tokio::task::spawn_blocking(move || {
        install_managed_runtime_with_cache_blocking(&dest, runtime.as_deref(), &cache_root)
    })
    .await
    .map_err(|error| LambdaError::InternalError(format!("install managed runtime: {error}")))?
}

fn install_managed_runtime_with_cache_blocking(
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

fn missing_node_message() -> String {
    "Node.js runtimes require the `node` executable on the host. Install it from your \
     distribution: Arch Linux `sudo pacman -S nodejs`, Debian/Ubuntu `sudo apt install nodejs`."
        .into()
}

/// The `python3.X` package is only in the apt archive of the release that ships it.
fn missing_python_message(runtime: &str, executable: &str) -> String {
    let apt_release = match executable {
        "python3.12" => Some("Ubuntu 24.04"),
        "python3.13" => Some("Debian 13"),
        "python3.14" => Some("Ubuntu 26.04"),
        _ => None,
    };
    let apt = apt_release
        .map(|release| format!("; {release} `sudo apt install {executable}`"))
        .unwrap_or_default();
    format!(
        "{runtime} requires the `{executable}` executable on the host. Install it from your \
         distribution: Arch Linux `sudo pacman -S python` (Arch's current Python version \
         only){apt}; otherwise install {executable} from your distribution."
    )
}

/// Lambda's Node.js runtimes also include the AWS SDK for JavaScript v3 in
/// `/var/lang/lib/node_modules`; no supported distribution packages it, so it is not provided
/// and functions must bundle `@aws-sdk/*` (npm is never invoked at runtime).
fn install_node_runtime(dest: &Path) -> Result<(), LambdaError> {
    let node = find_host_executable("node")
        .ok_or_else(|| LambdaError::NotImplemented(missing_node_message()))?;
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
        LambdaError::NotImplemented(missing_python_message(runtime, &executable_name))
    })?;

    let output = Command::new(&python)
        .args([
            "-c",
            "import sysconfig; print(sysconfig.get_path('stdlib')); print(sysconfig.get_config_var('DESTSHARED') or ''); print(sysconfig.get_path('purelib')); print(sysconfig.get_path('platlib'))",
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
    // Some distributions (Arch) keep the system site-packages inside the stdlib directory.
    // Host packages are not part of the runtime; only the SDK is installed, separately.
    let site_dirs: Vec<PathBuf> = lines
        .map(PathBuf::from)
        .filter(|dir| dir.starts_with(&stdlib) && *dir != stdlib)
        .collect();

    let python_dest = dest.join(
        python
            .strip_prefix("/")
            .expect("absolute Python executable path"),
    );
    copy_host_file(&python, &python_dest)?;
    let stdlib_dest = dest.join(stdlib.strip_prefix("/").expect("absolute stdlib path"));
    fs::create_dir_all(&stdlib_dest).map_err(io("create Python standard-library directory"))?;
    if let Some(cache_root) = cache_root {
        install_cached_stdlib(
            &stdlib,
            &stdlib_dest,
            runtime,
            &python,
            &site_dirs,
            cache_root,
        )?;
    } else {
        copy_stdlib_tree(&stdlib, &stdlib_dest, &site_dirs)
            .map_err(io("copy Python standard library"))?;
    }
    let sdk = match cache_root {
        Some(cache_root) => discover_python_sdk_cached(&python, runtime, cache_root, &[]),
        None => discover_python_sdk(&python, &[]),
    };
    install_python_sdk(dest, runtime, &sdk, cache_root);

    let mut copied = std::collections::HashSet::new();
    copy_dynamic_dependencies(&python, dest, &mut copied)?;
    install_python_compat_libraries(dest, &mut copied)?;
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

/// Hash host metadata of a tree, skipping `exclude` and directory symlinks.
fn fingerprint_tree(
    path: &Path,
    relative: &Path,
    exclude: &[PathBuf],
    hasher: &mut Sha256,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if exclude.iter().any(|excluded| excluded == path) {
        return Ok(());
    }
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
            fingerprint_tree(
                &entry.path(),
                &relative.join(entry.file_name()),
                exclude,
                hasher,
            )?;
        }
    }
    Ok(())
}

fn source_fingerprint(
    source: &Path,
    runtime: &str,
    python: &Path,
    exclude: &[PathBuf],
) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"locallycloud-python-stdlib-v1");
    hasher.update(runtime.as_bytes());
    hasher.update(source.as_os_str().as_encoded_bytes());
    hasher.update(python.as_os_str().as_encoded_bytes());
    fingerprint_tree(python, Path::new("python-executable"), &[], &mut hasher)?;
    fingerprint_tree(source, Path::new("stdlib"), exclude, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn install_cached_stdlib(
    source: &Path,
    dest: &Path,
    runtime: &str,
    python: &Path,
    exclude: &[PathBuf],
    cache_root: &Path,
) -> Result<(), LambdaError> {
    let fingerprint = || source_fingerprint(source, runtime, python, exclude);
    install_cached_tree(
        cache_root,
        runtime,
        "stdlib",
        "Python standard library",
        fingerprint,
        fingerprint,
        |data| copy_stdlib_tree(source, data, exclude),
        dest,
    )
}

/// Publish `populate`'s output once per fingerprint as an immutable, read-only cache entry
/// `<cache_root>/<prefix>-<fingerprint>/<data>` and hardlink it into `dest`. `fingerprint`
/// may be memoized; `recheck` must hash the source again to detect changes while caching.
/// Publishing a new entry prunes older `<prefix>-<fingerprint>` entries: rootfses hold
/// hardlinks or copies of their files, never references to the entry itself.
#[allow(clippy::too_many_arguments)]
fn install_cached_tree(
    cache_root: &Path,
    prefix: &str,
    data_name: &str,
    what: &str,
    fingerprint: impl FnOnce() -> std::io::Result<String>,
    recheck: impl Fn() -> std::io::Result<String>,
    populate: impl Fn(&Path) -> std::io::Result<()>,
    dest: &Path,
) -> Result<(), LambdaError> {
    let failed = |action: &str| {
        let context = format!("{action} {what}");
        move |error: std::io::Error| LambdaError::InternalError(format!("{context}: {error}"))
    };
    let _lock = CacheLock::acquire(cache_root)?;
    let expected = fingerprint().map_err(failed("fingerprint"))?;
    let cache = cache_root.join(format!("{prefix}-{expected}"));
    if cache.exists() {
        if fs::symlink_metadata(&cache)
            .map_err(failed("inspect runtime cache entry of"))?
            .file_type()
            .is_symlink()
        {
            return Err(LambdaError::InternalError(format!(
                "{what} runtime cache entry must not be a symlink"
            )));
        }
        if !cache.join(".complete").is_file() {
            remove_cached_tree(&cache).map_err(failed("remove incomplete runtime cache of"))?;
        }
    }
    if !cache.exists() {
        let stage = cache_root.join(format!(".stage-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&stage).map_err(failed("stage runtime cache of"))?;
        let result = (|| {
            let data = stage.join(data_name);
            fs::create_dir(&data).map_err(failed("create cached"))?;
            populate(&data).map_err(failed("cache"))?;
            if recheck().map_err(failed("recheck"))? != expected {
                return Err(LambdaError::InternalError(format!(
                    "{what} changed while caching"
                )));
            }
            freeze_cached_tree(&data).map_err(failed("freeze runtime cache of"))?;
            fs::write(stage.join(".complete"), expected.as_bytes())
                .map_err(failed("complete runtime cache of"))?;
            fs::rename(&stage, &cache).map_err(failed("publish runtime cache of"))
        })();
        if result.is_err() {
            let _ = remove_cached_tree(&stage);
        }
        result?;
        prune_cached_trees(cache_root, prefix, &cache, what);
    }
    let marker = cache.join(".complete");
    if fs::symlink_metadata(&marker)
        .map_err(failed("inspect runtime cache marker of"))?
        .file_type()
        .is_symlink()
        || fs::read_to_string(&marker).map_err(failed("read runtime cache marker of"))? != expected
    {
        return Err(LambdaError::InternalError(format!(
            "{what} runtime cache marker is invalid"
        )));
    }
    link_cached_tree(&cache.join(data_name), dest).map_err(failed("install cached"))
}

/// Remove `<prefix>-<fingerprint>` entries superseded by `current`. Must hold the cache lock.
/// Only exact SHA-256 suffixes match, so `python3.13` never prunes `python3.13-sdk-*`.
fn prune_cached_trees(cache_root: &Path, prefix: &str, current: &Path, what: &str) {
    let entries = match fs::read_dir(cache_root) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(%error, "list {what} runtime cache for pruning");
            return;
        }
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        let superseded = name
            .to_str()
            .and_then(|name| name.strip_prefix(prefix))
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|hash| {
                hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            });
        let path = entry.path();
        if !superseded || path == current {
            continue;
        }
        if let Err(error) = remove_cached_tree(&path) {
            tracing::warn!(entry = %path.display(), %error, "prune stale {what} runtime cache");
        }
    }
}

/// Remove a (possibly frozen) cache tree: frozen directories are made writable first.
fn remove_cached_tree(path: &Path) -> std::io::Result<()> {
    fn thaw(path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if fs::symlink_metadata(path)?.is_dir() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            for entry in fs::read_dir(path)? {
                thaw(&entry?.path())?;
            }
        }
        Ok(())
    }
    thaw(path)?;
    fs::remove_dir_all(path)
}

/// Copy a file keeping its mtime, so host `__pycache__` bytecode stays valid in the guest.
fn copy_file(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::copy(source, target)?;
    let modified = fs::metadata(source)?.modified()?;
    // Setting explicit timestamps needs ownership, not write permission.
    fs::File::open(target)?.set_modified(modified)
}

/// Materialize files without importing symlink targets outside the copied tree. Paths in
/// `exclude` (host site-packages nested in the stdlib directory) are not copied.
fn copy_stdlib_tree(source: &Path, dest: &Path, exclude: &[PathBuf]) -> std::io::Result<()> {
    let root = fs::canonicalize(source)?;
    fn visit(source: &Path, dest: &Path, root: &Path, exclude: &[PathBuf]) -> std::io::Result<()> {
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            if exclude.iter().any(|excluded| *excluded == entry.path()) {
                continue;
            }
            let kind = entry.file_type()?;
            let target = dest.join(entry.file_name());
            if kind.is_dir() {
                fs::create_dir(&target)?;
                visit(&entry.path(), &target, root, exclude)?;
            } else if kind.is_file() {
                copy_file(&entry.path(), &target)?;
            } else if kind.is_symlink() {
                // Host Python packages may contain optional links to system directories.
                // Only internal file links are safe to copy into an isolated guest.
                let Ok(resolved) = fs::canonicalize(entry.path()) else {
                    continue;
                };
                if resolved.starts_with(root) && resolved.is_file() {
                    copy_file(&resolved, &target)?;
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
    visit(source, dest, &root, exclude)
}

/// Pure-Python packages of the host's distribution AWS SDK for Python (boto3) and its
/// dependencies, discovered by the runtime's own host interpreter.
#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
struct PythonSdk {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    packages: Vec<PythonSdkPackage>,
    /// Why the SDK is not provided (not installed, compiled extensions, ...).
    #[serde(default)]
    skipped: Option<String>,
    /// Existing directories of the interpreter's `sys.path`: installing, removing, or
    /// upgrading a distribution changes one of them.
    #[serde(default)]
    search_path: Vec<PathBuf>,
    /// Memoized [`python_sdk_fingerprint`]; never reported by the discovery script.
    #[serde(default)]
    fingerprint: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct PythonSdkPackage {
    /// Importable top-level name (`botocore`, `six`, ...).
    name: String,
    /// Package directory or single-module `.py` file in the host site directory.
    path: PathBuf,
}

/// Walks `boto3`'s installed requirements (extras excluded) and prints every importable
/// top-level package as JSON. `sys.argv[1:]` are extra search paths (tests only).
const PYTHON_SDK_DISCOVERY: &str = r#"
import importlib.machinery, importlib.metadata, importlib.util, json, os, re, sys
sys.path[:0] = sys.argv[1:]
SEARCH_PATH = [path for path in sys.path if os.path.isabs(path) and os.path.isdir(path)]
COMPILED = tuple(importlib.machinery.EXTENSION_SUFFIXES) + (".so",)
STDLIB = set(getattr(sys, "stdlib_module_names", ()))

def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()

def skip(reason):
    print(json.dumps({"skipped": reason, "search_path": SEARCH_PATH}))
    sys.exit(0)

def distribution(name):
    try:
        return importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return None

def top_levels(dist, name):
    text = dist.read_text("top_level.txt")
    if text:
        return set(text.split())
    names = set()
    for file in dist.files or []:
        head = file.parts[0] if file.parts else ""
        head = head[:-3] if head.endswith(".py") else head
        if head.isidentifier() and head != "__pycache__":
            names.add(head)
    if names:
        return names
    guess = norm(name).replace("-", "_")
    return {guess[len("python_"):] if guess.startswith("python_") else guess}

root = distribution("boto3")
if root is None:
    skip("boto3 is not installed")
pending, seen, packages = [("boto3", False)], set(), {}
while pending:
    name, conditional = pending.pop()
    if norm(name) in seen:
        continue
    dist = distribution(name)
    if dist is None:
        if conditional:
            continue
        skip("{} (required by boto3) is not installed".format(name))
    seen.add(norm(name))
    for requirement in dist.requires or []:
        spec, _, marker = requirement.partition(";")
        if "extra" in marker:
            continue
        match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
        if match:
            pending.append((match.group(1), bool(marker.strip())))
    for top in sorted(top_levels(dist, name)):
        if top in STDLIB or top in packages:
            continue
        found = importlib.util.find_spec(top)
        if found is None or found.origin is None:
            skip("{} (from {}) is not importable".format(top, name))
        if found.origin.endswith(COMPILED):
            skip("{} (from {}) is a compiled extension".format(top, name))
        if found.submodule_search_locations is None:
            if not found.origin.endswith(".py"):
                skip("{} (from {}) is not a Python source module".format(top, name))
            packages[top] = found.origin
            continue
        locations = list(found.submodule_search_locations)
        if len(locations) != 1:
            skip("{} (from {}) is a namespace package".format(top, name))
        for directory, _, files in os.walk(locations[0]):
            if any(file.endswith(COMPILED) for file in files):
                skip("{} (from {}) contains compiled extensions".format(top, name))
        packages[top] = locations[0]
print(json.dumps({
    "version": root.version,
    "packages": [{"name": name, "path": path} for name, path in sorted(packages.items())],
    "search_path": SEARCH_PATH,
}))
"#;

/// Ask the host interpreter (isolated: no `PYTHONPATH`, no user site) for its distribution
/// boto3. Any failure means "no SDK": it is an optional host package.
fn discover_python_sdk(python: &Path, extra_paths: &[&Path]) -> PythonSdk {
    let skipped = |reason: String| PythonSdk {
        skipped: Some(reason),
        ..Default::default()
    };
    let output = match Command::new(python)
        .args(["-I", "-c", PYTHON_SDK_DISCOVERY])
        .args(extra_paths)
        .current_dir("/")
        .output()
    {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            return skipped(format!(
                "SDK discovery failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
        Err(error) => return skipped(format!("SDK discovery failed: {error}")),
    };
    let mut sdk: PythonSdk = match serde_json::from_slice(&output.stdout) {
        Ok(sdk) => sdk,
        Err(error) => return skipped(format!("SDK discovery returned invalid output: {error}")),
    };
    for package in &mut sdk.packages {
        let valid_name = package
            .name
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && package
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        let Ok(path) = fs::canonicalize(&package.path) else {
            return skipped(format!("{} is not readable", package.path.display()));
        };
        let expected = if path.is_dir() {
            package.name.clone()
        } else {
            format!("{}.py", package.name)
        };
        if !valid_name || path.file_name() != Some(std::ffi::OsStr::new(&expected)) {
            return skipped(format!(
                "unexpected SDK package {} at {}",
                package.name,
                path.display()
            ));
        }
        package.path = path;
    }
    if sdk.skipped.is_none() && sdk.packages.is_empty() {
        return skipped("boto3 has no importable packages".into());
    }
    sdk
}

fn python_sdk_fingerprint(runtime: &str, sdk: &PythonSdk) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"locallycloud-python-sdk-v1");
    hasher.update(runtime.as_bytes());
    for package in &sdk.packages {
        hasher.update([0]);
        hasher.update(package.name.as_bytes());
        hasher.update([0]);
        hasher.update(package.path.as_os_str().as_encoded_bytes());
        fingerprint_tree(&package.path, Path::new(&package.name), &[], &mut hasher)?;
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Host metadata of a path that changes when entries are added, removed, or replaced in it.
#[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct PathStamp {
    path: PathBuf,
    dev: u64,
    ino: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

/// The interpreter, its search path, and the SDK packages: distribution package managers
/// and pip replace files by renaming, so an SDK change touches one of these.
fn python_sdk_stamps(python: &Path, sdk: &PythonSdk) -> std::io::Result<Vec<PathStamp>> {
    use std::os::unix::fs::MetadataExt;
    std::iter::once(python)
        .chain(sdk.search_path.iter().map(PathBuf::as_path))
        .chain(sdk.packages.iter().map(|package| package.path.as_path()))
        .map(|path| {
            let meta = fs::metadata(path)?;
            Ok(PathStamp {
                path: path.to_path_buf(),
                dev: meta.dev(),
                ino: meta.ino(),
                mtime: (meta.mtime(), meta.mtime_nsec()),
                ctime: (meta.ctime(), meta.ctime_nsec()),
            })
        })
        .collect()
}

#[derive(serde::Deserialize, serde::Serialize)]
struct PythonSdkMemo {
    python: PathBuf,
    stamps: Vec<PathStamp>,
    sdk: PythonSdk,
}

fn python_sdk_memo_path(cache_root: &Path, runtime: &str) -> PathBuf {
    cache_root.join(format!(".{runtime}-sdk-discovery.json"))
}

/// [`discover_python_sdk`] plus its fingerprint, memoized in `cache_root` while the stamps
/// of [`python_sdk_stamps`] are unchanged, so warm cache hits run no interpreter and do not
/// walk the SDK tree.
fn discover_python_sdk_cached(
    python: &Path,
    runtime: &str,
    cache_root: &Path,
    extra_paths: &[&Path],
) -> PythonSdk {
    let memo_path = python_sdk_memo_path(cache_root, runtime);
    let memo = fs::read(&memo_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<PythonSdkMemo>(&bytes).ok())
        .filter(|memo| {
            memo.python == python
                && python_sdk_stamps(python, &memo.sdk).is_ok_and(|stamps| stamps == memo.stamps)
        });
    if let Some(memo) = memo {
        return memo.sdk;
    }
    let mut sdk = discover_python_sdk(python, extra_paths);
    // Failed discoveries carry no search path; they are retried on the next cold start.
    if sdk.search_path.is_empty() {
        return sdk;
    }
    let Ok(stamps) = python_sdk_stamps(python, &sdk) else {
        return sdk;
    };
    if sdk.skipped.is_none() {
        match python_sdk_fingerprint(runtime, &sdk) {
            Ok(fingerprint) => sdk.fingerprint = Some(fingerprint),
            Err(_) => return sdk,
        }
    }
    // Do not memoize a result that may have raced with a package upgrade.
    if !python_sdk_stamps(python, &sdk).is_ok_and(|after| after == stamps) {
        return sdk;
    }
    let memo = PythonSdkMemo {
        python: python.to_path_buf(),
        stamps,
        sdk,
    };
    if cache_root.is_dir() {
        let staged = cache_root.join(format!(".{runtime}-sdk-discovery.{}", uuid::Uuid::new_v4()));
        let written = serde_json::to_vec(&memo)
            .map_err(std::io::Error::other)
            .and_then(|bytes| fs::write(&staged, bytes))
            .and_then(|()| fs::rename(&staged, &memo_path));
        if let Err(error) = written {
            tracing::debug!(%error, "memoize Python SDK discovery");
            let _ = fs::remove_file(&staged);
        }
    }
    memo.sdk
}

fn copy_python_sdk(sdk: &PythonSdk, dest: &Path) -> std::io::Result<()> {
    for package in &sdk.packages {
        if package.path.is_dir() {
            let target = dest.join(&package.name);
            fs::create_dir(&target)?;
            copy_stdlib_tree(&package.path, &target, &[])?;
        } else {
            copy_file(&package.path, &dest.join(format!("{}.py", package.name)))?;
        }
    }
    Ok(())
}

fn missing_python_sdk_message(runtime: &str, reason: &str) -> String {
    format!(
        "{runtime}: the AWS SDK for Python (boto3) that Lambda includes in its Python runtimes \
         is not provided ({reason}); functions that import boto3 must package it. To provide \
         it from your distribution: Arch Linux `sudo pacman -S python-boto3`, Debian/Ubuntu \
         `sudo apt install python3-boto3`."
    )
}

/// Install the host SDK where Lambda keeps it (`/var/lang/lib/pythonX.Y/site-packages`).
/// The SDK is optional: when it is absent or cannot be installed, the runtime still works.
fn install_python_sdk(dest: &Path, runtime: &str, sdk: &PythonSdk, cache_root: Option<&Path>) {
    static NOTICE: std::sync::Once = std::sync::Once::new();
    if let Some(reason) = &sdk.skipped {
        let message = missing_python_sdk_message(runtime, reason);
        let mut first = false;
        NOTICE.call_once(|| first = true);
        if first {
            tracing::info!("{message}");
        } else {
            tracing::debug!("{message}");
        }
        return;
    }
    let site = dest.join(format!("var/lang/lib/{runtime}/site-packages"));
    // Install into a sibling and rename it into place, so a partial SDK never reaches
    // `sys.path`.
    let stage = site.with_file_name(format!(".site-packages.stage-{}", uuid::Uuid::new_v4()));
    let installed = match cache_root {
        Some(cache_root) => install_cached_tree(
            cache_root,
            &format!("{runtime}-sdk"),
            "site-packages",
            "Python runtime SDK",
            || match &sdk.fingerprint {
                Some(fingerprint) => Ok(fingerprint.clone()),
                None => python_sdk_fingerprint(runtime, sdk),
            },
            || python_sdk_fingerprint(runtime, sdk),
            |data| copy_python_sdk(sdk, data),
            &stage,
        ),
        None => fs::create_dir_all(&stage)
            .and_then(|()| copy_python_sdk(sdk, &stage))
            .map_err(io("copy Python runtime SDK")),
    };
    let result = installed
        .and_then(|()| fs::rename(&stage, &site).map_err(io("install Python runtime SDK")));
    match result {
        Ok(()) => {
            tracing::debug!(runtime, version = ?sdk.version, "installed host AWS SDK for Python")
        }
        Err(error) => {
            tracing::warn!(runtime, %error, "skip host AWS SDK for Python");
            if fs::symlink_metadata(&stage).is_ok() {
                if let Err(error) = remove_cached_tree(&stage) {
                    tracing::warn!(runtime, stage = %stage.display(), %error, "remove partial host AWS SDK for Python");
                }
            }
            // A memoized discovery may be stale (for example, a fingerprint of an SDK that
            // changed while caching); rediscover on the next cold start.
            if let Some(cache_root) = cache_root {
                let _ = fs::remove_file(python_sdk_memo_path(cache_root, runtime));
            }
        }
    }
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
                copy_file(&entry.path(), &target)?;
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

/// The host Python may compile libraries into the interpreter, while binary wheels
/// still link these standard Lambda runtime libraries dynamically.
fn install_python_compat_libraries(
    dest: &Path,
    copied: &mut std::collections::HashSet<PathBuf>,
) -> Result<(), LambdaError> {
    for name in ["libz.so.1", "libresolv.so.2"] {
        let library = [
            "/usr/lib",
            "/usr/lib64",
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "/lib/aarch64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
        ]
        .into_iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
        .ok_or_else(|| {
            LambdaError::NotImplemented(format!("Python binary wheels require host {name}"))
        })?;
        copy_host_file(
            &library,
            &dest.join(library.strip_prefix("/").expect("absolute library path")),
        )?;
        copy_dynamic_dependencies(&library, dest, copied)?;
    }
    Ok(())
}

pub(crate) fn find_host_executable(name: &str) -> Option<PathBuf> {
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
        let detail = String::from_utf8_lossy(&output.stderr);
        if detail.contains("cannot open shared object file") {
            return Err(LambdaError::NotImplemented(format!(
                "managed runtime dependency is unavailable: {}",
                detail.trim()
            )));
        }
        return Err(LambdaError::InternalError(format!(
            "inspect managed runtime shared libraries for {}: {}",
            source.display(),
            detail.trim()
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
    use crate::runtime_api::{FunctionErrorType, Outcome};
    use std::io::Write;

    fn temp() -> PathBuf {
        std::env::temp_dir().join(format!("lc-rootfs-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn python_compat_libraries_include_wheel_runtime_dependencies() {
        let dest = temp();
        fs::create_dir_all(&dest).unwrap();
        install_python_compat_libraries(&dest, &mut Default::default()).unwrap();
        for name in ["libz.so.1", "libresolv.so.2"] {
            assert!([
                "usr/lib",
                "usr/lib64",
                "lib/x86_64-linux-gnu",
                "usr/lib/x86_64-linux-gnu",
                "lib/aarch64-linux-gnu",
                "usr/lib/aarch64-linux-gnu",
            ]
            .iter()
            .any(|dir| dest.join(dir).join(name).is_file()));
        }
        fs::remove_dir_all(dest).unwrap();
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

        write_file(
            &source.join("site-packages/host_only.py"),
            b"host package\n",
        );
        let exclude = [source.join("site-packages")];
        install_cached_stdlib(&source, &first, "python3.14", &python, &exclude, &cache).unwrap();
        assert!(!first.join("site-packages").exists());
        assert!(!first.join("external.txt").exists());
        assert!(!first.join("external-dir").exists());
        assert_eq!(
            fs::read(first.join("internal.py")).unwrap(),
            b"version = 1\n"
        );
        // Host package updates under the excluded site-packages do not rebuild the stdlib.
        write_file(
            &source.join("site-packages/host_only.py"),
            b"host package v2\n",
        );
        install_cached_stdlib(&source, &second, "python3.14", &python, &exclude, &cache).unwrap();
        let source_file = first.join("pkg/module.py");
        let second_file = second.join("pkg/module.py");
        assert_eq!(
            fs::metadata(&source_file).unwrap().ino(),
            fs::metadata(&second_file).unwrap().ino()
        );

        // A source revision gets a new immutable cache entry; old rootfses retain their data.
        // Change length so metadata differs even within one filesystem timestamp tick.
        write_file(&source.join("pkg/module.py"), b"version = 22\n");
        install_cached_stdlib(&source, &third, "python3.14", &python, &exclude, &cache).unwrap();
        let third_file = third.join("pkg/module.py");
        assert_ne!(
            fs::metadata(&source_file).unwrap().ino(),
            fs::metadata(&third_file).unwrap().ino()
        );
        assert_eq!(fs::read(source_file).unwrap(), b"version = 1\n");
        assert_eq!(fs::read(third_file).unwrap(), b"version = 22\n");
        make_cache_removable(&cache);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn publishing_a_cache_entry_prunes_only_superseded_entries_of_its_prefix() {
        let base = temp();
        let source = base.join("host/python");
        let python = base.join("host/bin/python3.14");
        let cache = base.join("cache");
        write_file(&source.join("pkg/module.py"), b"version = 1\n");
        write_file(&python, b"python executable");
        install_cached_stdlib(
            &source,
            &base.join("first"),
            "python3.14",
            &python,
            &[],
            &cache,
        )
        .unwrap();
        // Entries of other prefixes and non-fingerprint names share the directory.
        let hash = "0".repeat(64);
        let kept = [
            format!("python3.14-sdk-{hash}"),
            format!("python3.13-{hash}"),
            "python3.14-notes".to_string(),
            ".python3.14-sdk-discovery.json".to_string(),
        ];
        for name in &kept {
            write_file(&cache.join(name).join("data"), b"x");
        }
        let stdlib_entries = || {
            fs::read_dir(&cache)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with("python3.14-") && !kept.contains(name))
                .collect::<Vec<_>>()
        };
        let old = stdlib_entries();
        assert_eq!(old.len(), 1, "{old:?}");

        write_file(&source.join("pkg/module.py"), b"version = 22\n");
        let second = base.join("second");
        install_cached_stdlib(&source, &second, "python3.14", &python, &[], &cache).unwrap();
        let current = stdlib_entries();
        assert_eq!(current.len(), 1, "{current:?}");
        assert_ne!(current, old);
        for name in &kept {
            assert!(cache.join(name).join("data").is_file(), "{name} is kept");
        }
        // Existing rootfses keep their hardlinked files after their entry is pruned.
        assert_eq!(
            fs::read(base.join("first/pkg/module.py")).unwrap(),
            b"version = 1\n"
        );
        assert_eq!(
            fs::read(second.join("pkg/module.py")).unwrap(),
            b"version = 22\n"
        );
        remove_cached_tree(&base).unwrap();
    }

    /// An SDK whose second package cannot be copied, after the first one was.
    fn partially_copyable_sdk(base: &Path) -> PythonSdk {
        let host = base.join("host-site");
        write_file(&host.join("boto3/__init__.py"), b"");
        PythonSdk {
            packages: vec![
                PythonSdkPackage {
                    name: "boto3".into(),
                    path: host.join("boto3"),
                },
                PythonSdkPackage {
                    name: "botocore".into(),
                    path: host.join("missing"),
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn failed_python_sdk_copy_leaves_no_partial_site_packages() {
        let base = temp();
        let sdk = partially_copyable_sdk(&base);
        let rootfs = base.join("rootfs");
        install_python_sdk(&rootfs, "python3.14", &sdk, None);
        let lib = rootfs.join("var/lang/lib/python3.14");
        assert!(!sdk_site(&rootfs, "python3.14").exists());
        assert_eq!(fs::read_dir(&lib).unwrap().count(), 0, "stage is removed");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn failed_cached_python_sdk_copy_leaves_no_partial_site_packages_and_drops_memo() {
        let base = temp();
        let cache = base.join("cache");
        let mut sdk = partially_copyable_sdk(&base);
        // A memoized fingerprint lets publication reach the failing copy.
        sdk.fingerprint = Some("f".repeat(64));
        let memo = python_sdk_memo_path(&cache, "python3.14");
        write_file(&memo, b"{}");
        let rootfs = base.join("rootfs");
        install_python_sdk(&rootfs, "python3.14", &sdk, Some(&cache));
        assert!(!sdk_site(&rootfs, "python3.14").exists());
        assert!(!rootfs.join("var/lang").exists());
        assert!(!memo.exists());
        let leftovers: Vec<_> = fs::read_dir(&cache)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != ".lock")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        remove_cached_tree(&base).unwrap();
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
                    install_cached_stdlib(&source, &dest, "python3.14", &python, &[], &cache)
                        .unwrap();
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

    /// The host `python3` and its Lambda runtime name (`python3.X`).
    fn host_python() -> Option<(PathBuf, String)> {
        let python = find_host_executable("python3")?;
        let output = Command::new(&python)
            .args([
                "-c",
                "import sys; print('python%d.%d' % sys.version_info[:2])",
            ])
            .output()
            .ok()?;
        let runtime = String::from_utf8(output.stdout).ok()?.trim().to_string();
        Some((python, runtime))
    }

    fn write_dist(site: &Path, name: &str, requires: &[&str], top_level: Option<&str>) {
        let info = site.join(format!("{name}-1.0.dist-info"));
        let mut metadata = format!("Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n");
        for requirement in requires {
            metadata.push_str(&format!("Requires-Dist: {requirement}\n"));
        }
        write_file(&info.join("METADATA"), metadata.as_bytes());
        if let Some(top_level) = top_level {
            write_file(&info.join("top_level.txt"), top_level.as_bytes());
        }
    }

    /// A tiny distribution-style site directory: boto3 -> botocore -> jmespath, six.
    fn fake_sdk_site(site: &Path) {
        write_file(
            &site.join("boto3/__init__.py"),
            b"SOURCE = 'sdk'\n__version__ = '1.0'\nimport botocore\n",
        );
        write_dist(
            site,
            "boto3",
            &[
                "botocore",
                "awscrt; extra == \"crt\"",
                "locallycloud-absent-backport; python_version < \"3.0\"",
            ],
            Some("boto3\n"),
        );
        // botocore lists its files in RECORD (no top_level.txt).
        write_file(&site.join("botocore/__init__.py"), b"SOURCE = 'sdk'\n");
        write_dist(site, "botocore", &["jmespath (<2)", "six"], None);
        write_file(
            &site.join("botocore-1.0.dist-info/RECORD"),
            b"botocore/__init__.py,,\nbotocore-1.0.dist-info/METADATA,,\n../../bin/tool,,\n",
        );
        // jmespath has neither: its import name is derived from the distribution name.
        write_file(&site.join("jmespath/__init__.py"), b"SOURCE = 'sdk'\n");
        write_dist(site, "jmespath", &[], None);
        write_file(&site.join("six.py"), b"SOURCE = 'sdk'\n");
        write_dist(site, "six", &[], Some("six\n"));
        // Installed but not required by boto3: never copied.
        write_file(&site.join("unrelated/__init__.py"), b"");
        write_dist(site, "unrelated", &[], Some("unrelated\n"));
    }

    fn sdk_site(rootfs: &Path, runtime: &str) -> PathBuf {
        rootfs.join(format!("var/lang/lib/{runtime}/site-packages"))
    }

    #[test]
    fn python_sdk_discovery_follows_requirements_and_skips_compiled_packages() {
        let Some((python, _)) = host_python() else {
            return;
        };
        let base = temp();
        let site = base.join("site-packages");
        fake_sdk_site(&site);
        let sdk = discover_python_sdk(&python, &[&site]);
        assert_eq!(sdk.skipped, None);
        assert_eq!(sdk.version.as_deref(), Some("1.0"));
        let site = fs::canonicalize(&site).unwrap();
        let found: Vec<_> = sdk
            .packages
            .iter()
            .map(|package| (package.name.as_str(), package.path.clone()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("boto3", site.join("boto3")),
                ("botocore", site.join("botocore")),
                ("jmespath", site.join("jmespath")),
                ("six", site.join("six.py")),
            ]
        );

        write_file(&site.join("botocore/_speedups.so"), b"\x7fELF");
        let sdk = discover_python_sdk(&python, &[&site]);
        let reason = sdk.skipped.expect("compiled package is reported");
        assert!(
            reason.contains("botocore") && reason.contains("compiled"),
            "{reason}"
        );
        assert!(sdk.packages.is_empty());

        let broken = base.join("broken");
        write_file(&broken.join("boto3/__init__.py"), b"");
        write_dist(&broken, "boto3", &["locallycloud-missing-dependency"], None);
        let reason = discover_python_sdk(&python, &[&broken]).skipped.unwrap();
        assert!(
            reason.contains("locallycloud-missing-dependency"),
            "{reason}"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn python_sdk_discovery_is_memoized_until_the_sdk_changes() {
        let Some((python, runtime)) = host_python() else {
            return;
        };
        let base = temp();
        let site = base.join("site-packages");
        let cache = base.join("cache");
        fake_sdk_site(&site);
        fs::create_dir_all(&cache).unwrap();
        let first = discover_python_sdk_cached(&python, &runtime, &cache, &[&site]);
        assert_eq!(first.skipped, None);
        assert_eq!(
            first.fingerprint,
            Some(python_sdk_fingerprint(&runtime, &first).unwrap())
        );
        // Mark the memo: a hit returns it without running the interpreter again.
        let memo_path = python_sdk_memo_path(&cache, &runtime);
        let mut memo: serde_json::Value =
            serde_json::from_slice(&fs::read(&memo_path).unwrap()).unwrap();
        memo["sdk"]["version"] = "memoized".into();
        fs::write(&memo_path, serde_json::to_vec(&memo).unwrap()).unwrap();
        let hit = discover_python_sdk_cached(&python, &runtime, &cache, &[&site]);
        assert_eq!(hit.version.as_deref(), Some("memoized"));
        assert_eq!(hit.fingerprint, first.fingerprint);

        // Upgrading a distribution renames its metadata directory in the site directory.
        fs::rename(
            site.join("botocore-1.0.dist-info"),
            site.join("botocore-1.1.dist-info"),
        )
        .unwrap();
        let rediscovered = discover_python_sdk_cached(&python, &runtime, &cache, &[&site]);
        assert_eq!(rediscovered.version.as_deref(), Some("1.0"));

        // Changes inside a package directory invalidate it too.
        write_file(&site.join("botocore/new_module.py"), b"");
        let changed = discover_python_sdk_cached(&python, &runtime, &cache, &[&site]);
        assert_ne!(changed.fingerprint, rediscovered.fingerprint);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn missing_python_sdk_is_optional_and_names_distribution_packages() {
        let base = temp();
        let sdk = PythonSdk {
            skipped: Some("boto3 is not installed".into()),
            ..Default::default()
        };
        install_python_sdk(&base, "python3.14", &sdk, Some(&base.join("cache")));
        install_python_sdk(&base, "python3.14", &sdk, None);
        assert!(!base.join("var/lang").exists());
        let message = missing_python_sdk_message("python3.14", "boto3 is not installed");
        assert!(message.contains("sudo pacman -S python-boto3"), "{message}");
        assert!(
            message.contains("sudo apt install python3-boto3"),
            "{message}"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn cached_python_sdk_is_read_only_shared_and_rebuilt_when_the_sdk_changes() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let Some((python, runtime)) = host_python() else {
            return;
        };
        let base = temp();
        let site = base.join("host-site");
        let cache = base.join("cache");
        fake_sdk_site(&site);
        let sdk = discover_python_sdk(&python, &[&site]);
        let (first, second, third) = (base.join("first"), base.join("second"), base.join("third"));
        install_python_sdk(&first, &runtime, &sdk, Some(&cache));
        install_python_sdk(&second, &runtime, &sdk, Some(&cache));

        let installed = sdk_site(&first, &runtime);
        for file in [
            "boto3/__init__.py",
            "botocore/__init__.py",
            "jmespath/__init__.py",
            "six.py",
        ] {
            let mode = fs::metadata(installed.join(file))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o444, "{file} is read-only");
        }
        assert!(!installed.join("unrelated").exists());
        assert!(!installed.join("boto3-1.0.dist-info").exists());
        let entry = fs::read_dir(&cache)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains("-sdk-")
            })
            .unwrap();
        let data_mode = fs::metadata(entry.join("site-packages/boto3"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(data_mode & 0o777, 0o555);
        let ino = |root: &Path| {
            fs::metadata(sdk_site(root, &runtime).join("botocore/__init__.py"))
                .unwrap()
                .ino()
        };
        assert_eq!(ino(&first), ino(&second));

        // An SDK update produces a new entry; existing rootfses keep their files.
        let before = python_sdk_fingerprint(&runtime, &sdk).unwrap();
        write_file(
            &site.join("botocore/__init__.py"),
            b"SOURCE = 'sdk-updated'\n",
        );
        let updated = discover_python_sdk(&python, &[&site]);
        install_python_sdk(&third, &runtime, &updated, Some(&cache));
        assert_ne!(ino(&first), ino(&third));
        assert_eq!(
            fs::read(sdk_site(&third, &runtime).join("botocore/__init__.py")).unwrap(),
            b"SOURCE = 'sdk-updated'\n"
        );
        assert_eq!(
            fs::read(sdk_site(&first, &runtime).join("botocore/__init__.py")).unwrap(),
            b"SOURCE = 'sdk'\n"
        );
        assert_ne!(before, python_sdk_fingerprint(&runtime, &updated).unwrap());
        // The superseded entry is pruned; only the current SDK entry remains.
        let sdk_entries: Vec<_> = fs::read_dir(&cache)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(&format!("{runtime}-sdk-")))
            .collect();
        assert_eq!(sdk_entries.len(), 1, "{sdk_entries:?}");
        assert!(sdk_entries[0].ends_with(&python_sdk_fingerprint(&runtime, &updated).unwrap()));
        // Cleanup restores write permission on frozen entries.
        remove_cached_tree(&cache).unwrap();
        assert!(!cache.exists());
        let _ = fs::remove_dir_all(&base);
    }

    /// Point the RIC's absolute Lambda paths into a host directory.
    fn rooted_python_ric(python: &Path, rootfs: &Path) -> String {
        let root = rootfs.to_str().unwrap();
        PYTHON_RIC
            .replacen("__PYTHON__", python.to_str().unwrap(), 1)
            .replace("\"/opt/python", &format!("\"{root}/opt/python"))
            .replace("\"/var/lang/lib/", &format!("\"{root}/var/lang/lib/"))
    }

    const PYTHON_SDK_HANDLER: &str = r#"import boto3, botocore, jmespath, six, sys

def handler(event, context):
    return {
        "boto3": boto3.SOURCE,
        "boto3_file": boto3.__file__,
        "botocore": botocore.SOURCE,
        "jmespath": jmespath.SOURCE,
        "six": six.SOURCE,
        "path": sys.path[:4],
    }
"#;

    #[tokio::test]
    async fn python_ric_prefers_function_code_and_layers_over_runtime_sdk() {
        let Some((python, runtime)) = host_python() else {
            return;
        };
        let base = temp();
        let site = base.join("host-site");
        fake_sdk_site(&site);
        let rootfs = base.join("rootfs");
        let sdk = discover_python_sdk(&python, &[&site]);
        install_python_sdk(&rootfs, &runtime, &sdk, Some(&base.join("cache")));
        let task = rootfs.join("var/task");
        write_file(&task.join("app.py"), PYTHON_SDK_HANDLER.as_bytes());
        write_file(&task.join("jmespath/__init__.py"), b"SOURCE = 'task'\n");
        write_file(
            &rootfs.join("opt/python/botocore/__init__.py"),
            b"SOURCE = 'layer'\n",
        );
        write_file(
            &rootfs.join(format!("opt/python/lib/{runtime}/site-packages/six.py")),
            b"SOURCE = 'layer-site'\n",
        );
        let script = rootfs.join("var/runtime/bootstrap");
        write_file(&script, rooted_python_ric(&python, &rootfs).as_bytes());

        let (outcomes, ..) = run_ric_events(&python, &script, "app.handler", &task, &["{}"]).await;
        let Outcome::Success(body) = &outcomes[0] else {
            panic!("expected success, got {:?}", outcomes[0]);
        };
        let body: serde_json::Value = serde_json::from_slice(body).unwrap();
        let root = rootfs.to_str().unwrap();
        assert_eq!(body["boto3"], "sdk");
        assert!(body["boto3_file"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{root}/var/lang/lib/{runtime}/site-packages/")));
        assert_eq!(body["botocore"], "layer");
        assert_eq!(body["jmespath"], "task");
        assert_eq!(body["six"], "layer-site");
        assert_eq!(
            body["path"],
            serde_json::json!([
                task.to_str().unwrap(),
                format!("{root}/opt/python/lib/{runtime}/site-packages"),
                format!("{root}/opt/python"),
                format!("{root}/var/lang/lib/{runtime}/site-packages"),
            ])
        );
        make_cache_removable(&base.join("cache"));
        let _ = fs::remove_dir_all(&base);
    }

    /// Runs only when the host has its distribution boto3 (Arch `python-boto3`,
    /// Debian/Ubuntu `python3-boto3`).
    #[tokio::test]
    async fn python_ric_imports_host_distribution_boto3_when_installed() {
        let Some((python, runtime)) = host_python() else {
            return;
        };
        let sdk = discover_python_sdk(&python, &[]);
        if let Some(reason) = &sdk.skipped {
            eprintln!("skipping: host AWS SDK for Python is not usable: {reason}");
            return;
        }
        let base = temp();
        let rootfs = base.join("rootfs");
        install_python_sdk(&rootfs, &runtime, &sdk, Some(&base.join("cache")));
        let task = rootfs.join("var/task");
        write_file(
            &task.join("app.py"),
            br#"import boto3, botocore

def handler(event, context):
    client = boto3.client("s3", region_name="us-east-1", endpoint_url="http://127.0.0.1:9",
                          aws_access_key_id="test", aws_secret_access_key="test")
    return {"version": boto3.__version__, "file": boto3.__file__,
            "botocore": botocore.__file__, "service": client.meta.service_model.service_name}
"#,
        );
        let script = rootfs.join("var/runtime/bootstrap");
        write_file(&script, rooted_python_ric(&python, &rootfs).as_bytes());
        let (outcomes, ..) = run_ric_events(&python, &script, "app.handler", &task, &["{}"]).await;
        let Outcome::Success(body) = &outcomes[0] else {
            panic!("expected success, got {:?}", outcomes[0]);
        };
        let body: serde_json::Value = serde_json::from_slice(body).unwrap();
        let site = sdk_site(&rootfs, &runtime);
        assert_eq!(body["version"].as_str(), sdk.version.as_deref());
        assert_eq!(body["service"], "s3");
        for key in ["file", "botocore"] {
            assert!(
                body[key]
                    .as_str()
                    .unwrap()
                    .starts_with(site.to_str().unwrap()),
                "{body}"
            );
        }
        make_cache_removable(&base.join("cache"));
        let _ = fs::remove_dir_all(&base);
    }

    /// The runtime builds from the host interpreter whether or not boto3 is installed, and
    /// never copies the whole host site-packages.
    #[test]
    fn host_python_runtime_builds_without_host_site_packages() {
        let Some((python, runtime)) = host_python() else {
            return;
        };
        let base = temp();
        let rootfs = base.join("rootfs");
        fs::create_dir_all(rootfs.join("var/runtime")).unwrap();
        install_python_runtime_with_cache(&rootfs, &runtime, &base.join("cache")).unwrap();
        assert!(rootfs.join("var/runtime/bootstrap").is_file());
        let output = Command::new(&python)
            .args([
                "-c",
                "import sysconfig; print(sysconfig.get_path('purelib'))",
            ])
            .output()
            .unwrap();
        let purelib = String::from_utf8(output.stdout).unwrap();
        let purelib = Path::new(purelib.trim());
        assert!(!rootfs.join(purelib.strip_prefix("/").unwrap()).exists());
        let sdk = discover_python_sdk(&python, &[]);
        assert_eq!(
            sdk_site(&rootfs, &runtime).join("boto3").is_dir(),
            sdk.skipped.is_none()
        );
        make_cache_removable(&base.join("cache"));
        let _ = fs::remove_dir_all(&base);
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

    const RIC_KEY: &str = "ric-env";
    const RIC_ARN: &str = "arn:aws:lambda:us-east-1:000000000000:function:fn";
    const RIC_TRACES: [&str; 3] = [
        "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=0",
        "Root=1-5759e989-0123456789abcdef01234567;Parent=0123456789abcdef;Sampled=0",
        "Root=1-5759e98a-fedcba9876543210fedcba98;Parent=fedcba9876543210;Sampled=0",
    ];

    const PYTHON_HANDLER: &str = r#"import logging
import os
import sys

import_time_stdout = sys.stdout
structured = logging.getLogger("structured")
structured.addHandler(logging.StreamHandler(sys.stdout))
structured.setLevel(logging.INFO)
structured.propagate = False
logging.basicConfig(level=logging.INFO, format="%(message)s")

def handler(event, context):
    n = event["n"]
    import_time_stdout.write("import-time stream {}\n".format(n))
    structured.info("structured logger %d", n)
    logging.getLogger().info("root logger %d", n)
    print("print {}".format(n))
    if n == 3:
        raise ValueError("boom {}".format(n))
    return {
        "function_name": context.function_name,
        "function_version": context.function_version,
        "memory_limit_in_mb": context.memory_limit_in_mb,
        "invoked_function_arn": context.invoked_function_arn,
        "aws_request_id": context.aws_request_id,
        "log_group_name": context.log_group_name,
        "log_stream_name": context.log_stream_name,
        "cognito_identity_id": context.identity.cognito_identity_id,
        "client_context": context.client_context,
        "remaining_positive": context.get_remaining_time_in_millis() > 0,
        "trace": os.environ.get("_X_AMZN_TRACE_ID"),
        "encoding": sys.stdout.encoding,
        "isatty": sys.stdout.isatty(),
        "fileno": sys.stdout.fileno(),
    }
"#;

    const NODE_HANDLER: &str = r#"const importTimeStdout = process.stdout;
exports.handler = async (event, context) => {
  importTimeStdout.write(`import-time stream ${event.n}\n`);
  console.log(`console ${event.n}`);
  if (event.n === 3) throw new Error(`boom ${event.n}`);
  return {
    functionName: context.functionName,
    functionVersion: context.functionVersion,
    memoryLimitInMB: context.memoryLimitInMB,
    logGroupName: context.logGroupName,
    logStreamName: context.logStreamName,
    callbackWaitsForEmptyEventLoop: context.callbackWaitsForEmptyEventLoop,
    awsRequestId: context.awsRequestId,
    invokedFunctionArn: context.invokedFunctionArn,
    remainingPositive: context.getRemainingTimeInMillis() > 0,
    trace: process.env._X_AMZN_TRACE_ID ?? null,
  };
};
"#;

    struct RicRun {
        responses: Vec<serde_json::Value>,
        request_ids: Vec<String>,
        logs: Vec<String>,
        error: Outcome,
        /// Time from process spawn until the runtime first polled `/invocation/next`.
        init: std::time::Duration,
        init_logs: String,
    }

    /// A Runtime API server plus a host RIC process registered as one environment.
    async fn spawn_ric(
        interpreter: &Path,
        script: &Path,
        handler: &str,
        task: &Path,
    ) -> (
        std::sync::Arc<crate::runtime_api::InvocationBroker>,
        std::process::Child,
    ) {
        use crate::runtime_api::InvocationBroker;
        use std::sync::Arc;

        let broker = Arc::new(InvocationBroker::new());
        broker
            .discover_expected_extensions(RIC_KEY, vec![], "fn", "$LATEST", handler)
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = crate::runtime_api_server::router(broker.clone());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let child = Command::new(interpreter)
            .arg(script)
            .env_clear()
            .env("AWS_LAMBDA_RUNTIME_API", format!("{addr}/e/{RIC_KEY}"))
            .env("_HANDLER", handler)
            .env("LAMBDA_TASK_ROOT", task)
            .env("AWS_LAMBDA_FUNCTION_NAME", "fn")
            .env("AWS_LAMBDA_FUNCTION_VERSION", "$LATEST")
            .env("AWS_LAMBDA_FUNCTION_MEMORY_SIZE", "256")
            .env("AWS_LAMBDA_LOG_GROUP_NAME", "/aws/lambda/fn")
            .env("AWS_LAMBDA_LOG_STREAM_NAME", "2024/01/01/[$LATEST]abc")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        (broker, child)
    }

    /// Wait for a RIC process to exit, killing it after `limit`.
    async fn wait_exit(
        child: &mut std::process::Child,
        limit: std::time::Duration,
    ) -> std::process::ExitStatus {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("runtime did not exit");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Run a Runtime Interface Client on the host against a real Runtime API server: Init,
    /// then two successful (cold, then warm) invocations followed by a handler error.
    async fn run_ric(interpreter: &Path, script: &Path, handler: &str, task: &Path) -> RicRun {
        use std::time::Duration;

        let spawned = tokio::time::Instant::now();
        let (broker, mut child) = spawn_ric(interpreter, script, handler, task).await;
        broker
            .wait_init_ready(RIC_KEY, spawned + Duration::from_secs(30))
            .await
            .expect("runtime finished Init");
        let init = spawned.elapsed();
        let init_logs = broker.take_init_logs(RIC_KEY).unwrap_or_default().concat();

        let mut outcomes = Vec::new();
        let mut request_ids = Vec::new();
        let mut logs = Vec::new();
        for (index, trace) in RIC_TRACES.iter().enumerate() {
            let payload = format!("{{\"n\":{}}}", index + 1).into_bytes();
            let (request_id, rx) =
                broker.submit_traced(RIC_KEY, payload, RIC_ARN, 30_000, trace.to_string());
            let outcome = tokio::time::timeout(Duration::from_secs(30), rx)
                .await
                .expect("runtime responded")
                .unwrap();
            logs.push(broker.take_logs(&request_id).unwrap_or_default().concat());
            outcomes.push(outcome);
            request_ids.push(request_id);
        }
        broker.stop(RIC_KEY);
        let status = wait_exit(&mut child, Duration::from_secs(5)).await;
        assert!(
            status.success(),
            "runtime must exit cleanly after HTTP 204: {status}"
        );

        let error = outcomes.pop().unwrap();
        let responses = outcomes
            .into_iter()
            .map(|outcome| match outcome {
                Outcome::Success(body) => serde_json::from_slice(&body).unwrap(),
                other => panic!("expected success, got {other:?}"),
            })
            .collect();
        RicRun {
            responses,
            request_ids,
            logs,
            error,
            init,
            init_logs,
        }
    }

    /// Run a RIC whose Init must fail: it reports `/init/error`, never polls `next`, exits.
    async fn run_ric_init_failure(
        interpreter: &Path,
        script: &Path,
        handler: &str,
        task: &Path,
    ) -> (crate::runtime_api::InitError, serde_json::Value, String) {
        let (broker, mut child) = spawn_ric(interpreter, script, handler, task).await;
        let status = wait_exit(&mut child, std::time::Duration::from_secs(30)).await;
        assert!(!status.success(), "runtime must exit after an Init error");
        let error = broker
            .take_init_error(RIC_KEY)
            .expect("runtime reported /init/error");
        let payload = serde_json::from_slice(&error.payload).unwrap();
        let logs = broker.take_init_logs(RIC_KEY).unwrap_or_default().concat();
        assert!(broker.init_failed(RIC_KEY));
        (error, payload, logs)
    }

    fn assert_reported_error(outcome: &Outcome, message: &str) {
        match outcome {
            Outcome::Error {
                error_type,
                payload,
            } => {
                assert_eq!(*error_type, FunctionErrorType::Reported);
                let body: serde_json::Value = serde_json::from_slice(payload).unwrap();
                assert_eq!(body["errorMessage"], message);
            }
            other => panic!("expected reported error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn python_ric_provides_aws_context_trace_and_warm_log_capture() {
        let Some(python) = find_host_executable("python3") else {
            return;
        };
        let base = temp();
        let task = base.join("task");
        write_file(&task.join("app.py"), PYTHON_HANDLER.as_bytes());
        let script = base.join("bootstrap");
        let ric = PYTHON_RIC.replacen("__PYTHON__", python.to_str().unwrap(), 1);
        write_file(&script, ric.as_bytes());

        let run = run_ric(&python, &script, "app.handler", &task).await;
        for (index, response) in run.responses.iter().enumerate() {
            assert_eq!(response["function_name"], "fn");
            assert_eq!(response["function_version"], "$LATEST");
            assert_eq!(response["memory_limit_in_mb"], "256");
            assert_eq!(response["invoked_function_arn"], RIC_ARN);
            assert_eq!(response["aws_request_id"], run.request_ids[index]);
            assert_eq!(response["log_group_name"], "/aws/lambda/fn");
            assert_eq!(response["log_stream_name"], "2024/01/01/[$LATEST]abc");
            assert_eq!(response["cognito_identity_id"], serde_json::Value::Null);
            assert_eq!(response["client_context"], serde_json::Value::Null);
            assert_eq!(response["remaining_positive"], true);
            assert_eq!(response["trace"], RIC_TRACES[index]);
            assert_eq!(response["isatty"], false);
            assert!(response["encoding"].is_string());
            assert!(response["fileno"].as_i64().unwrap() >= 0);
        }
        for (index, logs) in run.logs.iter().enumerate() {
            let n = index + 1;
            for line in [
                format!("import-time stream {n}\n"),
                format!("structured logger {n}\n"),
                format!("root logger {n}\n"),
                format!("print {n}\n"),
            ] {
                assert!(
                    logs.contains(&line),
                    "invocation {n} missing {line:?}: {logs:?}"
                );
            }
            assert!(!logs.contains(&format!("print {}", n + 1)), "{logs:?}");
        }
        assert_reported_error(&run.error, "boom 3");
        let _ = fs::remove_dir_all(&base);
    }

    const PYTHON_THREADED_HANDLER: &str = r#"import sys
import threading
import time

errors = []
stop = threading.Event()
worker = None

def chatter():
    while not stop.is_set():
        try:
            print("background")
            sys.stdout.write("background write\n")
        except BaseException as error:
            errors.append(repr(error))
            return
        time.sleep(0.001)

def handler(event, context):
    global worker
    n = event["n"]
    if worker is None:
        worker = threading.Thread(target=chatter, daemon=True)
        worker.start()
    print("main {}".format(n))
    # Keep writing from the background thread while this invocation ends.
    time.sleep(0.05)
    if n == 3:
        stop.set()
        worker.join(5)
        raise ValueError("boom 3" if not errors else repr(errors))
    return {"errors": list(errors)}
"#;

    #[tokio::test]
    async fn python_ric_tolerates_background_thread_stdout() {
        let Some(python) = find_host_executable("python3") else {
            return;
        };
        let base = temp();
        let task = base.join("task");
        write_file(&task.join("app.py"), PYTHON_THREADED_HANDLER.as_bytes());
        let script = base.join("bootstrap");
        let ric = PYTHON_RIC.replacen("__PYTHON__", python.to_str().unwrap(), 1);
        write_file(&script, ric.as_bytes());

        let run = run_ric(&python, &script, "app.handler", &task).await;
        for response in &run.responses {
            assert_eq!(response["errors"], serde_json::json!([]));
        }
        for (index, logs) in run.logs.iter().enumerate() {
            let line = format!("main {}\n", index + 1);
            assert!(
                logs.contains(&line),
                "invocation {} missing {line:?}",
                index + 1
            );
        }
        assert_reported_error(&run.error, "boom 3");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn missing_interpreter_errors_name_executable_and_distribution_packages() {
        let node = missing_node_message();
        assert!(node.contains("`node`"));
        assert!(node.contains("sudo pacman -S nodejs"));
        assert!(node.contains("sudo apt install nodejs"));

        for (version, release) in [
            ("python3.12", "Ubuntu 24.04"),
            ("python3.13", "Debian 13"),
            ("python3.14", "Ubuntu 26.04"),
        ] {
            let message = missing_python_message(version, version);
            assert!(message.contains(&format!("`{version}` executable")));
            assert!(message.contains("sudo pacman -S python"));
            assert!(message.contains(&format!("{release} `sudo apt install {version}`")));
            assert!(message.contains(&format!("install {version} from your distribution")));
            assert!(!message.contains('/'), "no paths: {message}");
        }
        let unpackaged = missing_python_message("python3.11", "python3.11");
        assert!(!unpackaged.contains("apt install"));
        assert!(unpackaged.contains("install python3.11 from your distribution"));

        let error = install_managed_runtime(&temp(), Some("python3.99")).unwrap_err();
        assert!(
            matches!(&error, LambdaError::NotImplemented(message)
                if message == &missing_python_message("python3.99", "python3.99")),
            "{error}"
        );
    }

    #[tokio::test]
    async fn node_ric_provides_aws_context_trace_and_warm_log_capture() {
        let Some(node) = find_host_executable("node") else {
            return;
        };
        let base = temp();
        let task = base.join("task");
        write_file(&task.join("app.js"), NODE_HANDLER.as_bytes());
        let script = base.join("bootstrap");
        write_file(&script, NODE_RIC.as_bytes());

        let run = run_ric(&node, &script, "app.handler", &task).await;
        assert_node_run(&run);
        let error_log = &run.logs[2];
        assert!(
            error_log.contains(&format!(
                "\t{}\tERROR\tInvoke Error \t{{",
                run.request_ids[2]
            )),
            "{error_log:?}"
        );
        assert!(
            error_log.contains(r#""errorMessage":"boom 3""#),
            "{error_log:?}"
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// Instruments `http`/`https` and `fetch` at import time, like aws-xray-sdk
    /// `captureHTTPsGlobal` and the Powertools Tracer, recording every call to `calls.log`.
    /// A first-invocation self-check proves the recorders observe user calls.
    const NODE_INSTRUMENTING_HANDLER: &str = r#"const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const log = path.join(process.env.LAMBDA_TASK_ROOT, 'calls.log');
const record = (kind, target) => fs.appendFileSync(log, `${kind} ${target}\n`);
const describe = (target) => typeof target === 'string' ? target
  : target instanceof URL ? target.href
  : `${target?.hostname ?? target?.host}:${target?.port}${target?.path ?? ''}`;
for (const [name, module] of [['http', http], ['https', https]]) {
  for (const method of ['request', 'get']) {
    const original = module[method];
    module[method] = (...args) => { record(`${name}.${method}`, describe(args[0])); return original(...args); };
  }
}
const originalFetch = globalThis.fetch;
globalThis.fetch = (...args) => { record('fetch', describe(args[0])); return originalFetch(...args); };

async function selfCheck() {
  const server = http.createServer((req, res) => res.end('ok'));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/self-check`;
  await new Promise((resolve, reject) => {
    http.get(url, (res) => { res.resume(); res.on('end', resolve); }).on('error', reject);
  });
  await (await fetch(url)).text();
  server.close();
  server.closeAllConnections();
}

exports.handler = async (event) => {
  if (event.n === 1) await selfCheck();
  if (event.n === 3) throw new Error(`boom ${event.n}`);
  return { n: event.n };
};
"#;

    #[tokio::test]
    async fn node_ric_runtime_api_calls_bypass_user_http_instrumentation() {
        assert!(!NODE_RIC.contains("fetch(") && !NODE_RIC.contains("undici"));
        let Some(node) = find_host_executable("node") else {
            return;
        };
        let base = temp();
        let task = base.join("task");
        write_file(&task.join("app.js"), NODE_INSTRUMENTING_HANDLER.as_bytes());
        let script = base.join("bootstrap");
        write_file(&script, NODE_RIC.as_bytes());

        let run = run_ric(&node, &script, "app.handler", &task).await;
        assert_eq!(
            run.responses,
            vec![serde_json::json!({"n": 1}), serde_json::json!({"n": 2})]
        );
        assert_reported_error(&run.error, "boom 3");
        // Only the handler's own self-check calls were observed: Init logs, every `next`
        // (including the final 204), `logs`, `response` and `error` bypassed the patches.
        let calls = fs::read_to_string(task.join("calls.log")).unwrap();
        let calls: Vec<&str> = calls.lines().collect();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(
            calls[0].starts_with("http.get http://127.0.0.1:"),
            "{calls:?}"
        );
        assert!(calls[1].starts_with("fetch http://127.0.0.1:"), "{calls:?}");
        assert!(
            calls.iter().all(|call| call.ends_with("/self-check")),
            "{calls:?}"
        );
        let _ = fs::remove_dir_all(&base);
    }

    fn assert_node_run(run: &RicRun) {
        for (index, response) in run.responses.iter().enumerate() {
            assert_eq!(response["functionName"], "fn");
            assert_eq!(response["functionVersion"], "$LATEST");
            assert_eq!(response["memoryLimitInMB"], "256");
            assert_eq!(response["logGroupName"], "/aws/lambda/fn");
            assert_eq!(response["logStreamName"], "2024/01/01/[$LATEST]abc");
            assert_eq!(response["callbackWaitsForEmptyEventLoop"], true);
            assert_eq!(response["awsRequestId"], run.request_ids[index]);
            assert_eq!(response["invokedFunctionArn"], RIC_ARN);
            assert_eq!(response["remainingPositive"], true);
            assert_eq!(response["trace"], RIC_TRACES[index]);
        }
        for (index, logs) in run.logs.iter().enumerate() {
            let n = index + 1;
            for line in [
                format!("import-time stream {n}\n"),
                format!("console {n}\n"),
            ] {
                assert!(
                    logs.contains(&line),
                    "invocation {n} missing {line:?}: {logs:?}"
                );
            }
        }
        assert_reported_error(&run.error, "boom 3");
    }

    const NODE_SLOW_IMPORT: &str = "await new Promise((resolve) => setTimeout(resolve, 300));\n\
        console.log('init output');\n";

    /// Every AWS module layout resolves, and Init (here a 300 ms top-level await) completes
    /// before the first `next`.
    #[tokio::test]
    async fn node_ric_resolves_module_layouts_during_init() {
        let Some(node) = find_host_executable("node") else {
            return;
        };
        let esm = NODE_HANDLER.replace("exports.handler =", "export const handler =");
        let esm_slow = format!("{NODE_SLOW_IMPORT}{esm}");
        let nested_handler =
            format!("{NODE_HANDLER}\nexports.handlers = {{ main: exports.handler }};\n");
        let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
            ("app.handler", vec![("app.js", NODE_HANDLER)]),
            (
                "app.handler",
                vec![
                    ("app.js", esm.as_str()),
                    ("package.json", r#"{"type":"module"}"#),
                ],
            ),
            ("index.handler", vec![("index.mjs", esm_slow.as_str())]),
            ("app.handler", vec![("app.cjs", NODE_HANDLER)]),
            // The module name ends at the first dot; the rest is a property path.
            (
                "src/index.handlers.main",
                vec![("src/index.js", nested_handler.as_str())],
            ),
            // `.js` wins over `.mjs` and `.cjs`, as in the AWS lookup order.
            (
                "app.handler",
                vec![
                    ("app.js", NODE_HANDLER),
                    ("app.mjs", "throw new Error('wrong file');"),
                    ("app.cjs", "throw new Error('wrong file');"),
                ],
            ),
            (
                "src/nested/app.handler",
                vec![
                    ("src/nested/app.js", esm.as_str()),
                    ("src/package.json", r#"{"type":"module"}"#),
                    ("package.json", r#"{"type":"commonjs"}"#),
                ],
            ),
            ("./src/app.handler", vec![("src/app.js", NODE_HANDLER)]),
            // The extensionless path loads a directory's `index.js`.
            ("lib.handler", vec![("lib/index.js", NODE_HANDLER)]),
            // Node resolution finds a `node_modules` package through its `main`.
            (
                "pkg.handler",
                vec![
                    ("node_modules/pkg/package.json", r#"{"main":"main.js"}"#),
                    ("node_modules/pkg/main.js", NODE_HANDLER),
                ],
            ),
        ];
        for (handler, files) in cases {
            let base = temp();
            let task = base.join("task");
            for (name, contents) in &files {
                write_file(&task.join(name), contents.as_bytes());
            }
            let script = base.join("bootstrap");
            write_file(&script, NODE_RIC.as_bytes());
            let run = run_ric(&node, &script, handler, &task).await;
            assert_node_run(&run);
            if files[0].0 == "index.mjs" {
                assert!(
                    run.init >= std::time::Duration::from_millis(300),
                    "{:?}",
                    run.init
                );
                assert!(
                    run.init_logs.ends_with("\tundefined\tINFO\tinit output\n"),
                    "{:?}",
                    run.init_logs
                );
                assert_eq!(run.init_logs.lines().count(), 1, "{:?}", run.init_logs);
                assert!(!run.logs[0].contains("init output"), "{:?}", run.logs[0]);
            }
            let _ = fs::remove_dir_all(&base);
        }
    }

    /// An absolute module root (a layer under `/opt`) resolves outside the task root, and the
    /// package.json `type` lookup stops at `node_modules`, as in the AWS client.
    #[tokio::test]
    async fn node_ric_resolves_absolute_module_root() {
        let Some(node) = find_host_executable("node") else {
            return;
        };
        let base = temp();
        let task = base.join("task");
        fs::create_dir_all(&task).unwrap();
        let package = base.join("opt/nodejs/node_modules/x");
        write_file(&package.join("handler.js"), NODE_HANDLER.as_bytes());
        // Above `node_modules`: must not turn the CommonJS handler into ESM.
        write_file(
            &base.join("opt/nodejs/package.json"),
            br#"{"type":"module"}"#,
        );
        let script = base.join("bootstrap");
        write_file(&script, NODE_RIC.as_bytes());
        let handler = format!("{}/handler.handler", package.display());
        let run = run_ric(&node, &script, &handler, &task).await;
        assert_node_run(&run);
        let _ = fs::remove_dir_all(&base);
    }

    /// Run the extension supervisor on the host with one extension and a runtime (shell
    /// scripts) against a real Runtime API, and return the classified Init failure once the
    /// supervisor has exited.
    async fn run_supervisor(
        bash: &Path,
        runtime: &str,
        extension: &str,
    ) -> crate::runtime_api::InitError {
        use crate::runtime_api::InvocationBroker;
        use std::sync::Arc;

        let base = temp();
        let extensions = base.join("extensions");
        for (path, body) in [
            (extensions.join("ext"), extension),
            (base.join("runtime"), runtime),
        ] {
            write_file(&path, format!("#!{}\n{body}\n", bash.display()).as_bytes());
            make_executable(&path);
        }
        let supervisor = base.join("supervisor");
        let script = EXTENSION_SUPERVISOR
            .replace("/opt/extensions", extensions.to_str().unwrap())
            .replace(
                "/tmp/.locallycloud-extension-shutdown",
                base.join("shutdown").to_str().unwrap(),
            );
        write_file(&supervisor, script.as_bytes());

        let broker = Arc::new(InvocationBroker::new());
        broker
            .discover_expected_extensions(RIC_KEY, vec!["ext".into()], "fn", "$LATEST", "h")
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = crate::runtime_api_server::router(broker.clone());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut child = Command::new(bash)
            .arg(&supervisor)
            .arg(base.join("runtime"))
            .env("AWS_LAMBDA_RUNTIME_API", format!("{addr}/e/{RIC_KEY}"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // The supervisor reads the report's response before it terminates the others.
        let status = wait_exit(&mut child, std::time::Duration::from_secs(10)).await;
        assert!(status.success(), "{status}");
        assert!(broker.init_failed(RIC_KEY));
        let _ = fs::remove_dir_all(&base);
        broker
            .take_init_error(RIC_KEY)
            .expect("supervisor reported the exit")
    }

    #[tokio::test]
    async fn extension_supervisor_reports_which_process_exited() {
        let Some(bash) = find_host_executable("bash") else {
            return;
        };
        let crashed = run_supervisor(&bash, "exec sleep 30", "exit 3").await;
        assert_eq!(crashed.error_type, "Extension.Crash");
        let crashed = run_supervisor(&bash, "exit 1", "exec sleep 30").await;
        assert_eq!(crashed.error_type, "Runtime.ExitError");
        let payload: serde_json::Value = serde_json::from_slice(&crashed.payload).unwrap();
        assert_eq!(payload["errorType"], "Runtime.ExitError");
    }

    #[tokio::test]
    async fn node_ric_reports_typed_init_errors() {
        let Some(node) = find_host_executable("node") else {
            return;
        };
        const NESTED_EXPORTS: &str = "exports.handlers = { main: async () => 'ok' };\n";
        let cases = [
            (
                "missing.handler",
                vec![("app.js", NODE_HANDLER)],
                "Runtime.ImportModuleError",
                "Error: Cannot find module 'missing'",
            ),
            (
                "app.nothing",
                vec![("app.js", NODE_HANDLER)],
                "Runtime.HandlerNotFound",
                "app.nothing is undefined or not exported",
            ),
            (
                "app.handlers.missing",
                vec![("app.js", NESTED_EXPORTS)],
                "Runtime.HandlerNotFound",
                "app.handlers.missing is undefined or not exported",
            ),
            (
                "app.handlers",
                vec![("app.js", NESTED_EXPORTS)],
                "Runtime.HandlerNotFound",
                "app.handlers is not a function",
            ),
            // `app.v2.handler` is module `app`, not `app.v2`.
            (
                "app.v2.handler",
                vec![("app.v2.js", NODE_HANDLER)],
                "Runtime.ImportModuleError",
                "Error: Cannot find module 'app'",
            ),
            (
                "nodot",
                vec![("app.js", NODE_HANDLER)],
                "Runtime.MalformedHandlerName",
                "Bad handler",
            ),
            (
                "app.handler",
                vec![("app.mjs", "export const handler = ;")],
                "Runtime.UserCodeSyntaxError",
                "SyntaxError: ",
            ),
            // Any `..` is rejected with the AWS message, even when it would stay inside.
            (
                "../escape.handler",
                vec![("app.js", NODE_HANDLER)],
                "Runtime.MalformedHandlerName",
                "'../escape.handler' is not a valid handler name. Use absolute paths when specifying root directories in handler names.",
            ),
            (
                "src/../app.handler",
                vec![("app.js", NODE_HANDLER)],
                "Runtime.MalformedHandlerName",
                "is not a valid handler name",
            ),
        ];
        for (handler, files, error_type, message) in cases {
            let base = temp();
            let task = base.join("task");
            for (name, contents) in &files {
                write_file(&task.join(name), contents.as_bytes());
            }
            let script = base.join("bootstrap");
            write_file(&script, NODE_RIC.as_bytes());
            let (error, payload, logs) = run_ric_init_failure(&node, &script, handler, &task).await;
            assert_eq!(error.error_type, error_type, "{handler}");
            assert_eq!(payload["errorType"], error_type, "{handler}");
            assert!(
                payload["errorMessage"].as_str().unwrap().contains(message),
                "{handler}: {payload}"
            );
            assert!(payload["stackTrace"].is_array());
            assert!(
                logs.contains("\tundefined\tERROR\tUncaught Exception \t{"),
                "{handler}: {logs:?}"
            );
            assert!(logs.contains(error_type), "{handler}: {logs:?}");
            let _ = fs::remove_dir_all(&base);
        }
    }

    #[tokio::test]
    async fn python_ric_imports_during_init_and_reports_typed_errors() {
        let Some(python) = find_host_executable("python3") else {
            return;
        };
        let ric = PYTHON_RIC.replacen("__PYTHON__", python.to_str().unwrap(), 1);

        // Init (a 300 ms import) completes before the first `next`; nested paths resolve.
        let base = temp();
        let task = base.join("task");
        let slow = format!("import time\ntime.sleep(0.3)\nprint('init output')\n{PYTHON_HANDLER}");
        write_file(&task.join("src/app.py"), slow.as_bytes());
        let script = base.join("bootstrap");
        write_file(&script, ric.as_bytes());
        let run = run_ric(&python, &script, "src/app.handler", &task).await;
        assert!(
            run.init >= std::time::Duration::from_millis(300),
            "{:?}",
            run.init
        );
        assert_eq!(run.init_logs, "init output\n");
        assert_eq!(run.responses[0]["function_name"], "fn");
        assert!(!run.logs[0].contains("init output"));
        assert!(
            run.logs[2]
                .contains("[ERROR] ValueError: boom 3\nTraceback (most recent call last):\n"),
            "{:?}",
            run.logs[2]
        );
        let _ = fs::remove_dir_all(&base);

        for (handler, error_type, message) in [
            (
                "missing.handler",
                "Runtime.ImportModuleError",
                "Unable to import module 'missing': No module named 'missing'",
            ),
            (
                "broken.handler",
                "Runtime.UserCodeSyntaxError",
                "Syntax error in module 'broken'",
            ),
            (
                "nodot",
                "Runtime.MalformedHandlerName",
                "Bad handler 'nodot'",
            ),
            (
                "../app.handler",
                "Runtime.MalformedHandlerName",
                "Bad handler '../app.handler'",
            ),
        ] {
            let base = temp();
            let task = base.join("task");
            write_file(&task.join("app.py"), PYTHON_HANDLER.as_bytes());
            write_file(&task.join("broken.py"), b"def handler(:\n");
            let script = base.join("bootstrap");
            write_file(&script, ric.as_bytes());
            let (error, payload, logs) =
                run_ric_init_failure(&python, &script, handler, &task).await;
            assert_eq!(error.error_type, error_type, "{handler}");
            assert_eq!(payload["errorType"], error_type, "{handler}");
            assert!(
                payload["errorMessage"]
                    .as_str()
                    .unwrap()
                    .starts_with(message),
                "{handler}: {payload}"
            );
            assert!(
                logs.starts_with(&format!("[ERROR] {error_type}: {message}")),
                "{handler}: {logs:?}"
            );
            let _ = fs::remove_dir_all(&base);
        }
    }

    /// A missing handler attribute does not fail Python Init: every invocation fails with
    /// `Runtime.HandlerNotFound`, as the Lambda Python runtime does.
    #[tokio::test]
    async fn python_ric_missing_handler_fails_each_invocation() {
        let Some(python) = find_host_executable("python3") else {
            return;
        };
        let base = temp();
        let task = base.join("task");
        write_file(&task.join("app.py"), PYTHON_HANDLER.as_bytes());
        let script = base.join("bootstrap");
        let ric = PYTHON_RIC.replacen("__PYTHON__", python.to_str().unwrap(), 1);
        write_file(&script, ric.as_bytes());
        let spawned = tokio::time::Instant::now();
        let (broker, mut child) = spawn_ric(&python, &script, "app.missing", &task).await;
        broker
            .wait_init_ready(RIC_KEY, spawned + std::time::Duration::from_secs(30))
            .await
            .unwrap();
        let (request_id, rx) = broker.submit(RIC_KEY, b"{}".to_vec(), RIC_ARN, 30_000);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(30), rx)
            .await
            .unwrap()
            .unwrap();
        let Outcome::Error { payload, .. } = outcome else {
            panic!("expected function error, got {outcome:?}");
        };
        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["errorType"], "Runtime.HandlerNotFound");
        assert_eq!(
            payload["errorMessage"],
            "Handler 'missing' missing on module 'app'"
        );
        let logs = broker.take_logs(&request_id).unwrap().concat();
        assert!(
            logs.starts_with(
                "[ERROR] Runtime.HandlerNotFound: Handler 'missing' missing on module 'app'\n"
            ),
            "{logs:?}"
        );
        broker.stop(RIC_KEY);
        assert!(wait_exit(&mut child, std::time::Duration::from_secs(5))
            .await
            .success());
        let _ = fs::remove_dir_all(&base);
    }

    /// Start a RIC, finish Init, and run one invocation per payload in the same process.
    /// Returns the outcomes, request ids, per-invocation logs and Init output; the runtime
    /// must still be running (and exit cleanly on 204) after the last invocation.
    async fn run_ric_events(
        interpreter: &Path,
        script: &Path,
        handler: &str,
        task: &Path,
        events: &[&str],
    ) -> (Vec<Outcome>, Vec<String>, Vec<String>, String) {
        use std::time::Duration;

        let spawned = tokio::time::Instant::now();
        let (broker, mut child) = spawn_ric(interpreter, script, handler, task).await;
        broker
            .wait_init_ready(RIC_KEY, spawned + Duration::from_secs(30))
            .await
            .expect("runtime finished Init");
        let init_logs = broker.take_init_logs(RIC_KEY).unwrap_or_default().concat();
        let (mut outcomes, mut request_ids, mut logs) = (Vec::new(), Vec::new(), Vec::new());
        for event in events {
            let (request_id, rx) =
                broker.submit(RIC_KEY, event.as_bytes().to_vec(), RIC_ARN, 30_000);
            let outcome = tokio::time::timeout(Duration::from_secs(30), rx)
                .await
                .expect("runtime responded")
                .unwrap();
            assert!(child.try_wait().unwrap().is_none(), "runtime exited");
            logs.push(broker.take_logs(&request_id).unwrap_or_default().concat());
            outcomes.push(outcome);
            request_ids.push(request_id);
        }
        broker.stop(RIC_KEY);
        assert!(wait_exit(&mut child, Duration::from_secs(5))
            .await
            .success());
        (outcomes, request_ids, logs, init_logs)
    }

    /// A handler that raises on every call is reported without a fault, and the runtime
    /// keeps its module state across invocations (no new Init).
    #[tokio::test]
    async fn rics_keep_module_state_after_handler_errors() {
        let mut runtimes = Vec::new();
        if let Some(python) = find_host_executable("python3") {
            let ric = PYTHON_RIC.replacen("__PYTHON__", python.to_str().unwrap(), 1);
            let code = "calls = 0\n\ndef handler(event, context):\n    global calls\n    calls += 1\n    raise ValueError(\"call {}\".format(calls))\n";
            runtimes.push((python, ric, "app.py", code));
        }
        if let Some(node) = find_host_executable("node") {
            let code = "let calls = 0;\nexports.handler = async () => { calls += 1; throw new Error(`call ${calls}`); };\n";
            runtimes.push((node, NODE_RIC.to_owned(), "app.js", code));
        }
        for (interpreter, ric, file, code) in runtimes {
            let base = temp();
            let task = base.join("task");
            write_file(&task.join(file), code.as_bytes());
            let script = base.join("bootstrap");
            write_file(&script, ric.as_bytes());
            let (outcomes, _, _, _) =
                run_ric_events(&interpreter, &script, "app.handler", &task, &["{}"; 3]).await;
            for (index, outcome) in outcomes.iter().enumerate() {
                assert_reported_error(outcome, &format!("call {}", index + 1));
            }
            let _ = fs::remove_dir_all(&base);
        }
    }

    const NODE_CONSOLE_HANDLER: &str = r#"const { Console } = require('node:console');
// Powertools Logger and Metrics print through their own Console on process.stdout.
const powertools = new Console({ stdout: process.stdout, stderr: process.stderr });
console.log('init', 1);
exports.handler = async (event) => {
  console.log('log %d', 7, { a: 1 });
  console.info('info');
  console.warn('warn');
  console.error('error');
  console.debug('debug');
  console.trace('trace');
  console.fatal('fatal');
  console.log('multi\nline');
  powertools.log(JSON.stringify({ level: 'INFO', message: 'powertools' }));
  process.stdout.write('raw stdout\n');
  if (event.fail) throw new Error('boom');
  return 'ok';
};
"#;

    /// `console.*` lines carry the AWS text prefix with the current request id; Powertools'
    /// own `Console` and direct stream writes stay raw.
    #[tokio::test]
    async fn node_ric_prefixes_console_like_aws() {
        let Some(node) = find_host_executable("node") else {
            return;
        };
        let base = temp();
        let task = base.join("task");
        write_file(&task.join("app.js"), NODE_CONSOLE_HANDLER.as_bytes());
        let script = base.join("bootstrap");
        write_file(&script, NODE_RIC.as_bytes());
        let (outcomes, request_ids, logs, init_logs) = run_ric_events(
            &node,
            &script,
            "app.handler",
            &task,
            &["{}", r#"{"fail":true}"#],
        )
        .await;
        assert_eq!(outcomes[0], Outcome::Success(br#""ok""#.to_vec()));
        assert_reported_error(&outcomes[1], "boom");

        let prefixed = |line: &str| -> Option<(String, String, String)> {
            let mut fields = line.splitn(4, '\t');
            let time = fields.next()?;
            // `2024-01-01T00:00:00.000Z`
            let is_time = time.len() == 24 && time.ends_with('Z') && time.as_bytes()[10] == b'T';
            is_time.then_some(())?;
            Some((
                fields.next()?.to_owned(),
                fields.next()?.to_owned(),
                fields.next()?.to_owned(),
            ))
        };
        assert_eq!(
            prefixed(init_logs.trim_end()),
            Some(("undefined".into(), "INFO".into(), "init 1".into())),
            "{init_logs:?}"
        );
        for (logs, request_id) in logs.iter().zip(&request_ids) {
            let lines: Vec<&str> = logs.lines().collect();
            let expected = [
                ("INFO", "log 7 { a: 1 }"),
                ("INFO", "info"),
                ("WARN", "warn"),
                ("ERROR", "error"),
                ("DEBUG", "debug"),
                ("TRACE", "trace"),
                ("FATAL", "fatal"),
                ("INFO", "multi"),
            ];
            for (line, (level, message)) in lines.iter().zip(expected) {
                assert_eq!(
                    prefixed(line),
                    Some((request_id.clone(), level.into(), message.into())),
                    "{logs:?}"
                );
            }
            assert_eq!(lines[8], "line", "{logs:?}");
            assert_eq!(
                lines[9], r#"{"level":"INFO","message":"powertools"}"#,
                "{logs:?}"
            );
            assert_eq!(lines[10], "raw stdout", "{logs:?}");
        }
        assert!(
            logs[1].contains(&format!("\t{}\tERROR\tInvoke Error \t{{", request_ids[1])),
            "{:?}",
            logs[1]
        );
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
