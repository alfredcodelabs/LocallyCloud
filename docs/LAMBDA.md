# Lambda runtimes

[← README](../README.md) · [Setup](SETUP.md) · [Services](SERVICES.md) · [Threat modeling](THREAT_MODELING.md) · [Platforms](PLATFORMS.md) · [Throttling](THROTTLING.md) · [FAQ](FAQ.md) · [Agent context](AGENT_CONTEXT.md)

## Install only what you use

Lambda execution needs an isolated compute backend; see
[host requirements](SETUP.md#optional-runtime-dependencies). Runtime management
runs as your regular user and needs no running server, state database or KMS key.
Install Python 3 to prepare or check packs; function invocation uses the
interpreter inside the pack, not a host Node.js or Python installation.

```sh
locallycloud runtime install nodejs22.x
locallycloud runtime list
locallycloud runtime check-updates
locallycloud runtime update nodejs22.x
locallycloud runtime rollback nodejs22.x
locallycloud runtime remove nodejs22.x
```

`install` downloads one official AWS image for the host architecture and verifies
its digests and file inventory. Installed runtimes are reused; startup and
invocation never download them. A missing or invalid pack fails invocation with
an actionable error.

`check-updates` reads upstream metadata without downloading layers or activating
a version. `update` verifies a candidate before switching versions; `rollback`
selects the previous installed version. Existing environments keep their version
until released. `remove` refuses to delete a pack in use. Install/update keep a
shared layer cache and retain versions needed for rollback or active environments.

Use `--json` for automation, `--directory PATH` to select another store, or
`--digest sha256:<64 lowercase hex digits>` to pin an install/update. See
`locallycloud runtime --help` for all options. The server must use the same store
through `LOCALLYCLOUD_RUNTIME_PACKS_DIR`; the default is
`<Lambda work directory>/runtime-packs`.

## Function packages and SDKs

| Function | Runtime preparation | Application package |
| --- | --- | --- |
| Node.js | `locallycloud runtime install nodejs22.x` | Handler and application dependencies; the official pack includes its AWS SDK v3. |
| Python | `locallycloud runtime install python3.13` | Handler and application dependencies; the official pack includes boto3. |
| Go | `locallycloud runtime install provided.al2023` | Linux executable named `bootstrap`, built with `aws-lambda-go`; SDK dependencies are compiled into it. |

The table lists the workflows that have been tested. Packs can also be installed for
the other supported runtimes: `nodejs20.x`, `nodejs22.x`, `nodejs24.x`,
`python3.11` to `python3.14`, `ruby3.3`, `ruby3.4`, `ruby4.0`, `dotnet8`,
`dotnet10`, `provided.al2` and `provided.al2023`. Java and deprecated runtimes such as `go1.x` are not supported.

Choose the runtime declared by your function. Native extensions and custom
executables must match the host CPU; setting Lambda's architecture does not
emulate another CPU. Deploy code and layers through the usual Lambda APIs.

Guests receive a private Runtime API and an executor-scoped HTTPS callback CA;
host certificate trust is unchanged. Custom CA paths must be absolute guest
paths. The isolated non-VPC path exposes the local AWS endpoint, not general
outbound Internet access.

## Memory budget

Each function keeps its own `MemorySize`. Independently,
`LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB` defaults to **4096 MiB shared across all
Lambda environments in the process**, including active and warm environments.
It allocates no RAM at startup and does not give each function 4096 MiB.

Admission counts each environment's configured memory plus 32 MiB of estimated
host overhead, rather than measured usage. Idle warm environments are evicted
when needed; if capacity still does not fit, invocation returns
`TooManyRequestsException`. Invalid or zero budgets disable invocation with a
diagnostic. This budget does not cap total server RSS, ECS or EC2 memory.

Keep room for the server and other desktop applications. Compute work files
should use disk-backed storage; tmpfs also consumes RAM. See
[throttling diagnostics](THROTTLING.md#diagnosis) for host-capacity metrics.
