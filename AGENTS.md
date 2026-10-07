# locallycloud — Agent & Architecture Guide

locallycloud is a native-Linux, high-fidelity local AWS emulator (LocalStack-style), written
in Rust. It is a **standalone product**: a single binary that serves the AWS wire protocols on
one port and runs compute in lightweight isolation — no JVM, no Docker daemon.

**Linux desktop first.** The primary user is a developer on their own Linux workstation,
running the emulator as their regular user (never `sudo`), next to a browser, an IDE, and other
apps. Design for that machine: XDG paths, a systemd user session, a desktop launcher for the
dashboard, low idle CPU/RAM, and nothing that needs root at runtime. Servers, CI runners, and
VMs must keep working, but they are secondary targets.

## Overview

- **Language:** Rust (edition 2021, MSRV `rust-version = "1.95.0"` in `Cargo.toml`), async on
  `tokio`.
- **Front door:** HTTP on port **4566** (Axum).
- **Routing:** a single front door resolves the target AWS service from the request and
  dispatches to a **native in-process handler**. Services not yet implemented natively can be
  forwarded to a **configurable external fallback backend** (default `http://localhost:4567`);
  this is optional and name-independent.
- **Compute isolation:** **Firecracker** microVMs (`/dev/kvm`) primary — the same isolation
  model AWS uses for Lambda — with a **daemonless OCI** fallback (`youki`/`crun`) when KVM is
  unavailable. **No Docker daemon, no `bollard`.**
- **Goal:** maximum fidelity to real AWS wire behavior (strict SDK/CLI (de)serialization),
  millisecond starts, low memory.

## Workspace layout

Directories are named after the service; package names carry the `locallycloud-` prefix
(`crates/s3` → `locallycloud-s3`). The binary package is `locallycloud`, in `crates/server`.

```
Cargo.toml                 # [workspace], version and MSRV shared by every crate
crates/
├── server/                # binary `locallycloud`: wiring, runtime selection, startup
├── core/                  # server, router, proxy, registry, error_mapping, config, endpoint,
│                          # observability, dashboard (`/_locallycloud/ui`)
├── state/                 # SQLite state database and encryption shared by services
├── compute/               # ComputeRuntime trait + Firecracker + OCI (youki/crun) + selector
└── <service>/             # one crate per AWS service: lambda, s3, dynamodb, sqs, sns, iam-sts,
                           # eventbridge, stepfunctions, apigateway, cloudformation, kinesis, …
packaging/                 # Debian (`debian/build-deb.sh`), Arch (`arch/PKGBUILD`), desktop assets
scripts/                   # version and packaging helpers
```

`crates/core/src/registry.rs` is the source of truth for known service names and protocols;
`crates/server/src/main.rs` shows which services register natively.

Specs live in `.kiro/specs/`; start with `core` and `integration`. Specs describe intended
behavior; only registered native handlers prove implemented behavior.

## First principles

1. Fidelity to real AWS wire behavior comes first (strict SDK/CLI error deserialization).
2. Reuse existing locallycloud patterns; do not introduce custom endpoint shapes.
3. Keep changes narrow, testable, and async.
4. **Cross-service realism is the #1 differentiator:** service-to-service calls (e.g. Step
   Functions → Lambda → S3/SQS/EventBridge) re-enter the same Router + Service Registry via
   internal dispatch, so they resolve identically to external client calls.

## Hard constraints

- **No Docker / Docker daemon / `bollard`** anywhere.
- **No unsynchronized global mutable state** — use `Arc<RwLock<T>>` or `dashmap`.
- All I/O, hypervisor calls, and proxy forwarding are `async` on `tokio`; never call blocking
  `std::fs`, `std::process`, or `std::thread::sleep` inside async code.
- Never hold a lock guard (including `dashmap` references) across an `.await`.
- AWS errors must match the protocol-correct shape (XML for REST-XML/Query, JSON 1.0/1.1 for
  JSON-RPC, REST-JSON for Lambda/API Gateway), with the right HTTP status and headers.
- Never log SigV4 signatures, secret keys, or security tokens.

## Security baseline

Everything arriving on port 4566 is untrusted, even on localhost: other local processes,
containers, and browser pages (via DNS rebinding) can reach it.

- No `unwrap`/`expect`/unchecked indexing on client-controlled data; return the AWS error.
- Validate resource names and object keys before turning them into filesystem paths
  (reject `..`, absolute paths, encoded separators, NUL bytes).
- When extracting Lambda code or layer archives, reject entries with `..` or absolute paths,
  do not follow symlinks, and cap total uncompressed size and entry count.
- Bound request bodies, field sizes, page sizes (to AWS maximums), and nesting depth of JSON/XML.
  Do not recurse without a depth limit over client-supplied structures.
- Never build process arguments through a shell; pass arguments to `Command` individually.
- Verify checksums of lazily downloaded compute artifacts before executing them.
- Default bind is `127.0.0.1`; binding to other interfaces must be explicit configuration.

## AWS protocol map

| Protocol     | Services                                                 | Routing key                 | Error shape               |
| ------------ | -------------------------------------------------------- | --------------------------- | ------------------------- |
| Query        | SNS, IAM, STS, CloudFormation, EC2, ELBv2, RDS           | `Action` + credential scope | XML                       |
| JSON 1.0/1.1 | DynamoDB, SQS, Kinesis, Step Functions, SSM, EventBridge, KMS, Logs, CloudWatch, Cognito | `X-Amz-Target` | JSON `__type` |
| REST JSON    | Lambda, API Gateway                                      | path + method               | JSON + `x-amzn-errortype` |
| REST XML     | S3, Route 53, CloudFront                                 | host/path                   | XML                       |

The table shows examples; `registry.rs` has the full list. The primary routing key is always the
**SigV4 credential scope**; protocol-specific sources (`X-Amz-Target`, host/path, `Action`) are
fallbacks.

## Compute engine

Compute is abstracted behind an async trait in `crates/compute/src/runtime.rs` (excerpt; the
real trait also covers isolated networking, task state, cursor-based output, and orphan
reconciliation):

```rust
#[async_trait::async_trait]
pub trait ComputeRuntime: Send + Sync {
    async fn start_task(&self, task_id: &str, spec: &TaskSpec) -> Result<TaskHandle, RuntimeError>;
    async fn stop_task(&self, task_id: &str) -> Result<TaskHandle, RuntimeError>;
    async fn get_output(&self, task_id: &str) -> Result<String, RuntimeError>;
}
```

- **`FirecrackerRuntime`** (primary): talks to the Firecracker control socket and uses
  `/dev/kvm` to launch microVMs; snapshot/restore for fast warm starts.
- **`YoukiRuntime`** (fallback): daemonless OCI runtime (`youki`/`crun`) when `/dev/kvm` is
  unavailable. No Docker, no `bollard`.
- **`RuntimeSelector`** picks automatically by KVM availability, with a config override.

### Runtime footprint (host-provided, optional)

The emulator is a **single binary with no eager runtime dependencies**: the server starts and
serves every in-process service without any compute backend. Only code-executing services
(Lambda, ECS, EC2) and RDS need host tools, and nothing is downloaded at runtime.

- **Host tools come from the distribution:** `crun`/`youki` from `PATH`
  (`YoukiRuntime::discover`), language executables (`python3.x`, `node`) for ZIP Lambdas, and
  PostgreSQL 16+ binaries for RDS (`LOCALLYCLOUD_PG_BIN_DIR`, then `PATH`, then the newest
  `/usr/lib/postgresql/<major>/bin`). They are optional package
  dependencies (`Suggests`/`optdepends`), never hard ones. A missing tool must surface a typed,
  actionable AWS error on first use, not a startup failure.
- **Caches are derived from the host:** Lambda builds per-runtime root filesystems under
  `${XDG_CACHE_HOME:-$HOME/.cache}/locallycloud/lambda/runtime-cache/` from the host interpreter.
  Cached trees are read-only (`0o555`/`0o444`); any code that removes or rebuilds them must
  restore write permission first, or the user cannot delete the cache.
- **Only the selected backend is used:** `/dev/kvm` accessible → Firecracker; otherwise OCI.
  Never both.

## Configuration

### Service registration and availability

The `ServiceRegistry` is seeded with known AWS service names in the `Proxied` disposition.
During startup, each implemented service crate registers its handler and flips only its own
entries to `Native`. A known routing name therefore does **not** imply a native implementation;
check `/_locallycloud/status` or `crates/server/src/main.rs`. Proxied requests require the
optional external fallback backend (`LOCALLYCLOUD_LEGACY_BACKEND_URL`, default
`http://localhost:4567`); they are not handled by this repository itself.

Implemented native handlers are cheap at idle, so the binary registers the available native
services by default. Per-service background work (SQS visibility timers, EventBridge scheduler,
retries) must start lazily on first relevant use, never at registration, so idle services consume
no background CPU.

### Persistence

State survives restarts by default in one SQLite database (`LOCALLYCLOUD_STATE_DB`, default
`${XDG_DATA_HOME:-$HOME/.local/share}/locallycloud/state.sqlite3`), encrypted with
`LOCALLYCLOUD_KMS_MASTER_KEY`. A service that keeps resources must register with
`register_with_state` and restore them on startup; an in-memory-only service is a bug unless it
is documented as such. Persist incrementally (per changed entity), never by re-serializing a
whole store per request, and restore without building intermediate copies of the full dataset:
restart time and RAM must stay flat as users accumulate data. A state database opened with a
different master key must fail fast with an actionable error.

### Environment variables

Name-independent: native `LOCALLYCLOUD_*`, plus `LOCALSTACK_*` compatibility aliases
and the standard `AWS_ENDPOINT_URL` / `AWS_REGION`. Every setting falls back to a documented
default independently. Common values:

- `LOCALLYCLOUD_KMS_MASTER_KEY` — **required**, base64 of 32 bytes; no default.
- `LOCALLYCLOUD_STATE_DB` (see Persistence)
- `LOCALLYCLOUD_HOST` / `LOCALLYCLOUD_PORT` (`127.0.0.1:4566`)
- `LOCALLYCLOUD_ACCOUNT_ID` (`000000000000`)
- `LOCALLYCLOUD_DEFAULT_REGION` (`us-east-1`)
- `LOCALLYCLOUD_RUNTIME` (`auto|firecracker|youki`)
- `LOCALLYCLOUD_IAM_ENFORCEMENT` (permissive by default; `strict` to test policies)
- `LOCALLYCLOUD_WORK_DIR` for Lambda work files (relative paths resolve from the process
  working directory); default `${XDG_CACHE_HOME:-$HOME/.cache}/locallycloud/lambda`.

The README configuration table is the user-facing reference; keep it in sync when adding a
variable. Choose a disk-backed work directory; an explicitly configured tmpfs still consumes RAM
(on desktops `/tmp` is often tmpfs). OCI execution requires a rootless systemd user session with
a user D-Bus (`dbus-user-session` on Debian) and delegated cgroup v2 memory control; guest swap
is disabled.

## Build & run

```
cargo build --workspace
LOCALLYCLOUD_KMS_MASTER_KEY="$(openssl rand -base64 32)" cargo run -p locallycloud   # :4566
```

Validate against the running server with `aws --profile locallycloud <service> <cmd>` or
`aws --endpoint-url http://127.0.0.1:4566 <service> <cmd>` with `test`/`test` credentials.
Respect an existing `AWS_PROFILE`. Profile setup for humans is in the README.

When testing, use a throwaway `LOCALLYCLOUD_STATE_DB` and `XDG_CACHE_HOME` on disk; never point a
test at the user's real state in `~/.local/share/locallycloud`.

## Platforms and packaging

Linux only, `x86_64` and `aarch64`/`arm64`. **Developed Arch-native first; supported on Debian
derivatives through one `.deb` per architecture installed with `apt`.** macOS and Windows without
WSL are served through a Linux VM with a loopback port forward. `docs/PLATFORMS.md` is the
user-facing source of truth for support levels; keep it in sync with this section.

| | Arch Linux | Debian family (one `.deb`) |
| --- | --- | --- |
| Role | Native development platform; where features are built and tested first | Supported install target for `apt` users |
| Version policy | **Always latest**: rolling repos, current Rust and libraries | Lowered to the oldest supported LTS so plain `apt` resolves every dependency |
| Supported | current Arch (`x86_64`; `aarch64` on Arch Linux ARM, best effort) | Debian stable (13) and the current Ubuntu LTS releases (24.04, 26.04), plus derivatives built on them (Mint, Pop!_OS, elementary, …) and **WSL 2** distributions based on them |
| Recipe | `packaging/arch/PKGBUILD` (`makepkg`) | `packaging/debian/build-deb.sh`, built natively per architecture in Debian 13 (`amd64`, `arm64`), never on Arch |
| Rust | repo `rust`/`cargo` | `rustup` pinned to `rust-version` |
| SQLite | repo `sqlite>=3.53.4` (dynamic) | 3.53.4 from sqlite.org, SHA-256 verified, **linked statically** |
| Runtime deps | `glibc`, `gcc-libs`, `sqlite` | `libc6 (>= <computed>)`, `libgcc-s1` |
| Recommends | — | `dbus-user-session` (installed by default by `apt`) |
| Optional | `optdepends`: `crun`, `postgresql`, `xdg-utils` | `Suggests`: `crun`, `postgresql`, `xdg-utils` |

Rules:

- Build and test on Arch with current versions, but every change must also work on the oldest
  supported LTS. Do not raise a minimum version above it: when a newer library is unavoidable,
  vendor and link it statically in the `.deb` (as with SQLite) instead of requiring backports,
  PPAs, or a newer release.
- **glibc baseline: 2.39** on both architectures (Ubuntu 24.04, the oldest supported LTS and a common WSL default).
  `build-deb.sh` computes `Depends: libc6 (>= X)` from the binary's versioned symbols and fails if
  X exceeds the baseline (`LOCALLYCLOUD_GLIBC_BASELINE`). Never hardcode the libc version, and
  raise the baseline only when the oldest supported LTS changes.
- The `.deb` binary is built in a Debian container, never copied from an Arch build: an Arch
  binary links against a newer glibc and will not run on the LTS releases.
- Host tools are optional and resolved at runtime (see Runtime footprint); support the versions
  the LTS releases ship and prefer the newest one each platform offers (e.g. Node.js 20 and
  PostgreSQL 17 on Debian 13, PostgreSQL 16 on Ubuntu 24.04, the current PostgreSQL on Arch;
  Python 3.12 on Ubuntu 24.04, 3.13 on Debian 13). Do not assume the newest versions Arch has.
- Rootless OCI (Lambda, ECS, EC2) needs a systemd user session with a user D-Bus. The `.deb`
  recommends `dbus-user-session`; on WSL 2, systemd must be enabled (`[boot] systemd=true` in
  `/etc/wsl.conf`). Without a user bus, fail with an actionable error and release the guest's
  memory reservation.
- Packages install only package-owned files under `/usr` (binary, `.desktop` launcher, icons,
  license/docs). Running the emulator never requires root; state and caches live in the user's
  XDG directories and survive uninstall.
- Versions derive from `Cargo.toml` through `scripts/package-version.sh`; see
  `packaging/VERSIONING.md` before changing versions, tags, or package revisions.
- CI (`debian-install`) installs each `.deb` with `apt` on Debian 13, Ubuntu 24.04, and Ubuntu
  26.04 for both architectures and starts the server; releases wait for it. Containers do not
  cover Lambda/OCI: before a release, also run the battery on a VM or WSL. Arch is covered by the
  development machine and CI.
- Do not add architecture-specific code without the other architecture's equivalent. Lambda
  `provided.*` binaries must match the host architecture; ZIP interpreters are portable.

## Definition of done

Before considering a change complete, all of these must pass:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

While iterating, run only the affected crate: `cargo test -p locallycloud-<service>`.

This is a desktop: the full workspace build/test compiles dozens of crates in parallel and can
exhaust RAM and swap while the user is working. Limit jobs (`-j 4`) or run it in a capped user
scope, e.g. `systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 -- cargo test -j 4
--workspace --locked`. Tests must not depend on fixed ports or shared paths: bind to port `0`
and use per-test temporary directories, so parallel runs do not collide.

## Adding a native service

1. Identify the AWS protocol and routing key.
2. Implement a `NativeHandler` in its crate, mirroring an existing native service.
3. Register it in the `ServiceRegistry` (`Proxied` → `Native`); no router change needed.
4. Map domain errors to the protocol-correct AWS error shape via `locallycloud-core`'s
   `error_mapping`; do not duplicate mapping per service.
5. Route cross-service calls through the integration layer, not a bespoke path.
6. Add tests; prefer AWS SDK / CLI based validation over hand-crafted HTTP.

## Scope

The product goal is a **complete serverless architecture** on one endpoint: Lambda, API Gateway,
DynamoDB, S3, SQS, SNS, EventBridge (+ Scheduler, Pipes, Schemas), Step Functions, IAM/STS, KMS,
SSM, Secrets Manager, CloudWatch Logs/Metrics, X-Ray, Kinesis, Firehose, Cognito User Pools and
CloudFormation/SAM, plus the networking, container, data, and recovery services already in
`crates/`. Prefer depth and fidelity in these services over adding new ones; breadth that does not
serve that architecture is not a goal.

Each service has a requirements-first spec under `.kiro/specs/`. A service remains `Proxied`
until its concrete native handler is implemented and registered; the presence of a spec or
routing name never implies runtime support.

## Testing

- Unit tests next to the code; integration tests under each crate's `tests/`.
- Test anything affecting request parsing, response shape, error handling, routing, endpoint
  resolution, or service enablement.
- Prefer SDK/CLI-based validation (`aws` CLI v2 against the running server).

## Code style

- Write all repository documentation in English. Exception: agent skills under
  `.agents/skills/` may be written in Spanish.
- Constructor injection / explicit wiring; avoid hidden globals.
- Prefer self-explanatory code over comments; always use braces in conditionals.
- Parse client strings into enums at the boundary; match on enums internally.
- Follow existing locallycloud patterns; copy before inventing.
- Conventional commits (`feat:`, `fix:`, `perf:`, `docs:`, `chore:`). Keep changes focused.

## Agent skills

Project skills live in `.agents/skills/`:

- `conditional-dispatch` — when writing or reviewing dispatch, mappings, validations, state
  transitions, or growing `if`/`else` chains.
- `whitebox-review` — for code reviews, security audits, and before closing relevant changes
  in `crates/`.
- `blackbox-validation` — to validate behavior from outside (CLI/SDK/HTTP) before closing a
  change that affects routes, contracts, state, or integrations.
- `dashboard-ui` — to change or review the embedded dashboard (`/_locallycloud/ui`).
- `local-agent` — to delegate a bounded task to a local OpenCode worker and audit its result.
