# Setup and configuration

[← README](../README.md) · [Services](SERVICES.md) · [Lambda](LAMBDA.md) · [Threat modeling](THREAT_MODELING.md) · [Platforms](PLATFORMS.md) · [Throttling](THROTTLING.md) · [FAQ](FAQ.md)

Start with the [quick start](../README.md#quick-start). Use this reference for
installation choices, host dependencies and settings.

[🚀 Installation](#installation) · [⚙️ Runtime](#optional-runtime-dependencies) · [🔌 AWS profile](#local-aws-profile) · [🛠️ Configuration](#configuration) · [🧹 Uninstallation](#uninstallation)

## Installation

System packages use the distribution's package manager. Installing or removing them requires administrator privileges because they place files under `/usr`. **Running LocallyCloud and using its API do not require `sudo`.** Run the emulator as your regular user.

### From source

From the repository root, with these dependencies installed:

- Rust 1.95.0 or later, including Cargo.
- SQLite 3.54.1 or later, including development headers and the library.
- A C/C++ build toolchain, CMake, and pkg-config for native dependencies.
- OpenSSL CLI for the key-generation example below.
- AWS CLI v2 for the usage examples, or an AWS SDK for your application.

```sh
cargo build --release --locked -p locallycloud
```

The executable is `target/release/locallycloud`. Continue with [Quick start](../README.md#quick-start).

### Debian and Ubuntu package (`.deb`)

Choose `amd64` or `arm64` from [GitHub Releases](https://github.com/alfredcodelabs/LocallyCloud/releases);
`dpkg --print-architecture` shows your architecture. Check the [supported distributions
and glibc baseline](PLATFORMS.md#support-levels). Install the downloaded file:

```sh
sudo apt install ./locallycloud_0.1.2-1_amd64.deb
```

The package bundles SQLite and resolves system dependencies through `apt`. Rust is
not required. For compute, check the [optional runtime requirements](#optional-runtime-dependencies).

### Arch Linux package

When a tagged release is available, download its `.pkg.tar.zst` for Arch Linux `x86_64`:

```sh
sudo pacman -U ./locallycloud-0.1.2-1-x86_64.pkg.tar.zst
```

Arch uses SQLite from its repositories. For Arch Linux ARM, build with `makepkg`
in `packaging/arch`; see [support levels](PLATFORMS.md#support-levels).

Packages are published through [GitHub Releases](https://github.com/alfredcodelabs/LocallyCloud/releases)
after CI passes. If a tag shows only **Source code** archives, it has no installers.
The [AUR recipe](../packaging/aur/PKGBUILD) and [APT repository tooling](../packaging/apt/README.md)
are prepared; those channels are not published yet.

### AppImage (without installation)

Choose the AppImage matching `uname -m`: `x86_64` or `aarch64`. When available,
download it from [GitHub Releases](https://github.com/alfredcodelabs/LocallyCloud/releases).
It contains the same server and bundled SQLite as the `.deb`. Check the
[Linux and glibc requirements](PLATFORMS.md#support-levels); the host also needs
libgcc-s1 (`gcc-libs` on Arch).

Replace the example filename with your download:

```sh
chmod +x ./locallycloud-VERSION-x86_64.AppImage
./locallycloud-VERSION-x86_64.AppImage --version
```

Follow [Quick start](../README.md#quick-start) to configure your master key and
start the server, using the AppImage path in place of `locallycloud`.
If FUSE is unavailable, prefix the command with `APPIMAGE_EXTRACT_AND_RUN=1`.
State and caches use the same XDG directories as system packages. Compute still
needs the [optional host tools and runtime packs](#optional-runtime-dependencies).

### User-only installation without sudo

For an LLM agent or a user without administrator access, install the executable under your home directory. From a source checkout with the build dependencies already available:

```sh
cargo build --release --locked -p locallycloud
install -Dm755 target/release/locallycloud "$HOME/.local/bin/locallycloud"
export PATH="$HOME/.local/bin:$PATH"
```

Alternatively, on a supported Debian or Ubuntu host with the required system libraries already installed, extract the downloaded `.deb` for that host's architecture without registering a system package:

```sh
mkdir -p "$HOME/.local/opt/locallycloud" "$HOME/.local/bin"
dpkg-deb --extract ./locallycloud_0.1.2-1_amd64.deb "$HOME/.local/opt/locallycloud"
ln -s "$HOME/.local/opt/locallycloud/usr/bin/locallycloud" "$HOME/.local/bin/locallycloud"
export PATH="$HOME/.local/bin:$PATH"
```

Use your downloaded filename. Extraction does not resolve dependencies, install
desktop integration or register the program with a package manager. Keep
`~/.local/bin` in your `PATH`. Preparing optional host tools and OCI permissions
may still require administrator access; see [runtime requirements](#optional-runtime-dependencies).

## Optional runtime dependencies

The server can start without a compute runtime. Install these dependencies only for the workflows that need them. The `.deb` recommends `dbus-user-session`; check that it is installed before using OCI compute, since APT may skip recommendations.

| Workflow | Requirement |
| --- | --- |
| Invoke Lambda, run ECS/Fargate tasks, or run EC2 instances | `crun` or `youki` available in `PATH`, a systemd user session with a user D-Bus (`dbus-user-session` on Debian and Ubuntu), and delegated cgroup v2 memory control on a compatible Linux host. |
| Run ECS/Fargate tasks | The OCI prerequisites above, delegated cgroup v2 CPU control, `ip` and `nft` in `PATH` (`iproute2` and `nftables` packages), and kernel netfilter redirect support (`nft_redir`). Task networking is configured inside owned guest namespaces; run the emulator as your ordinary user. |
| Run Lambda code | A matching [official runtime pack](LAMBDA.md). Python 3 is needed only to install, check or update packs. |
| Route Firehose Iceberg records with `MetadataExtraction` | `jq` available in `PATH`. |
| Run broader Athena SQL on Iceberg tables | [DuckDB CLI and matching official extensions](#duckdb). |
| Run EC2 instances | The OCI prerequisites above and `LOCALLYCLOUD_EC2_IMAGE_ROOTFS` pointing to the image's root filesystem. |
| Run RDS PostgreSQL or Aurora PostgreSQL, including RDS Data API access | The OCI prerequisites above and an explicitly installed PostgreSQL pack: `locallycloud runtime install postgres18`. PostgreSQL 16, 17 and 18 are supported; the default is 18. No host PostgreSQL installation is required. |
| Open the dashboard from the applications menu | `xdg-utils`. Opening the URL directly in a browser does not require it. |

On Debian and Ubuntu, install only the host tools you need with `sudo apt install crun dbus-user-session` or `sudo apt install xdg-utils`; add `python3` for runtime preparation or `jq` for metadata extraction. On Arch, the equivalent packages are `crun`, `dbus`, `xdg-utils`, `python` and `jq`. Runtime packs are downloaded only by explicit `locallycloud runtime install/update` commands. To use a host PostgreSQL toolchain instead of OCI, set `LOCALLYCLOUD_PG_BIN_DIR` to its `bin` directory; all five tools (`initdb`, `pg_ctl`, `postgres`, `psql`, `pg_basebackup`) must have matching versions, 16 or later.

### DuckDB

Install the DuckDB CLI and prepare its official extensions (1.5.4 was validated):

```sh
duckdb -no-init -c "INSTALL avro; INSTALL iceberg; SELECT install_path FROM duckdb_extensions() WHERE extension_name IN ('avro', 'iceberg');"
export LOCALLYCLOUD_DUCKDB_BIN="$(command -v duckdb)"
```

Set `LOCALLYCLOUD_DUCKDB_EXTENSIONS_DIR` to the directory containing the two
reported files. Extensions must match the CLI version and platform; recheck them
when updating DuckDB. Startup and queries never download extensions.
See [SQL limits](SERVICES.md#athena-and-duckdb) and [directory defaults](#configuration).

### Official Lambda runtime packs

Install only the runtimes your functions use with `locallycloud runtime install
nodejs22.x`. See [Lambda runtimes](LAMBDA.md) for prerequisites, updates, rollback
and the shared memory budget. No runtimes are downloaded at server startup or
invocation.

For session setup, see [WSL 2](PLATFORMS.md#wsl-2) and
[D-Bus troubleshooting](FAQ.md#why-does-lambda-report-d-bus-errors-on-debian).

## Local AWS profile

The quick-start configuration commands write the following entries. You can also add them manually, preserving your other profiles.

In `~/.aws/config`:

```ini
[profile locallycloud]
region = us-east-1
endpoint_url = https://aws.localhost:4566
ca_bundle = /absolute/path/to/state.sqlite3.ca.pem
```

In `~/.aws/credentials`:

```ini
[locallycloud]
aws_access_key_id = test
aws_secret_access_key = test
```

The section names differ: `[profile locallycloud]` in `config`, `[locallycloud]`
in `credentials`. These are local test credentials.

Select the profile for a request:

```sh
aws --profile locallycloud sts get-caller-identity
aws --profile locallycloud s3 ls
```

To select it for the current terminal:

```sh
export AWS_PROFILE=locallycloud
```

With `AWS_PROFILE` set, neither `--profile` nor `--endpoint-url` is needed. Alternatively, configure these same entries under `[default]` in both files to use them when no named profile is selected. This changes the default destination of AWS CLI requests in that configuration.

The saved endpoint applies to all AWS CLI services unless a higher-priority endpoint override is configured. Existing `AWS_ENDPOINT_URL` or service-specific endpoint variables can override it; `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true` disables configured endpoints. When using `AWS_PROFILE` without `--profile`, environment credentials can also take precedence over saved credentials. Use a dedicated terminal with those overrides cleared for profile-based local development.

See the AWS documentation for [configured endpoints](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-endpoints.html) and [configuration and credentials files](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).

### SDK host prefixes

If `StartSyncExecution` produces `sync-127.0.0.1`, disable host-prefix injection:

- AWS CLI v2 / Boto3: `disable_host_prefix_injection = true` in the local AWS profile.
- JavaScript SDK v3: `disableHostPrefix: true` in the client constructor.

See [AWS options for other SDKs](https://docs.aws.amazon.com/sdkref/latest/guide/feature-host-prefix.html).

## Configuration

Startup resolves settings once, in this order: built-in defaults, an optional JSON
file, then environment variables. Existing priorities between native variables,
compatibility aliases and AWS variables remain unchanged. Services receive the
resolved settings; changing the file requires a restart.

The default file is `${XDG_CONFIG_HOME:-$HOME/.config}/locallycloud/config.json`.
Set `LOCALLYCLOUD_CONFIG_FILE` to an absolute path to select another file. A missing
default file is allowed; an explicitly selected missing file is an error. Files
must be regular JSON files of at most 64 KiB. Unknown fields, explicit `null`, wrong
types and invalid effective values fail startup. Omitted fields inherit defaults.
Keep encryption keys and credentials in their existing secret inputs; the JSON
file does not accept them.

```json
{
  "common": {
    "region": "us-east-1",
    "port": 4566
  },
  "iam": {
    "enforcement": "strict"
  },
  "apigateway": {
    "authorizer_cache_capacity": 1024
  },
  "state": {
    "path": "/home/alice/.local/share/locallycloud/state.sqlite3"
  }
}
```

The configuration file supports the following fields. Other settings continue to
use the environment variables below.

| Section | Fields |
| --- | --- |
| `common` | `host`, `port`, `region`, `account_id`, `allow_http`, `ui_enabled`, `upstream_timeout_secs`, `max_request_body_bytes` |
| `iam` | `enforcement`: `strict` or `permissive`; an invalid environment value is also an error |
| `apigateway` | `authorizer_cache_capacity` (default 1024, range 1–65536), `websocket_outbound_channel_capacity` (32, range 1–256), `websocket_outbound_history_capacity` (64, range 1–1024) |
| `apigateway` | `http_client_cache_capacity` (default 16, range 1–256), `http_max_idle_per_host` (1, range 1–16), `http_idle_timeout_secs` (30, range 1–300) |
| `apigateway` | `http_local_origins`: exact HTTP(S) origins allowed to reach host/private backends and JWT issuers (OIDC discovery and JWKS); default `[]` |
| `logging` | `filter` (default `info`), `format` (`auto`, `pretty`, `json`), `color` (`auto`, `always`, `never`) |
| `lambda` | `max_warm_total` (default 16, range 0–1024), `max_warm_per_key` (10, range 1–1024), `warm_idle_timeout_secs` (300, range 1–3600), `memory_budget_mb` (4096, range 1–4294967295), `work_dir`, `runtime_packs_dir` |
| `ec2` | `image_rootfs` (optional path), `startup_timeout_secs` (default 5), `connect_timeout_secs` (2); both timeouts accept 1–300 seconds |
| `cloudformation` | `operation_capacity`: concurrent stack operations (default 4, range 1–64); the same stack remains mutually exclusive |
| `s3` | `notification_queue_capacity` (default 1024, range 1–16384), `notification_retry_interval_ms` (1000, range 100–60000) |
| `sqs` | `endpoint_strategy`: `path` (default) or `aws` |
| `dynamodb` | `engine`: `native` (default) or `extenddb`; `simulate_write_limits` (default false, native only); `kms_timeout_secs` (3, range 1–300; encrypted-table KMS broker) |
| `eventbridge` | `retry_time_scale` (default 1, range 0.000001–1), `pending_retry_poll_interval_ms` (25, range 1–10000), `http_connect_timeout_secs` (5, range 1–300), `http_request_timeout_secs` (30, range 1–300), `http_response_body_limit_bytes` (10485760, range 1–10485760), `http_local_origins` (exact HTTPS origins allowed to reach host/private destinations; default `[]`), `http_client_cache_capacity` (16, range 1–256) |
| `stepfunctions` | `execution_poll_interval_ms` (default 10, range 1–10000), `athena_poll_interval_ms` (50, range 1–10000), `athena_cancel_timeout_secs` (5, range 1–300) |
| `sns` | `http_local_origins` (exact HTTP(S) origins permitted for local subscribers; default `[]`), `http_client_cache_capacity` (16, range 1–256), `http_timeout_secs` (5, range 1–300), `outbox_retry_initial_secs` (1, range 1–300), `outbox_retry_max_secs` (30, range 1–3600; at least the initial delay) |
| `kinesis` | `max_buffered_bytes` (67108864, range 1–1073741824, in-memory backend only), `simulate_write_limits` (false) |
| `firehose` | `source_poll_interval_ms` (1000, range 1–60000), `s3_dispatch_timeout_secs` (10, range 1–300), `max_retry_delay_secs` (30, range 1–3600) |
| `cognito` | `mailbox_dir` (optional absolute path to the local confirmation mailbox; disabled when omitted) |
| `logs` | `delivery_retry_interval_ms` (5000, range 1–60000), `retention_reclaim_delay_ms` (100, range 1–60000) |
| `state` | `path`: absolute SQLite path, shared by the server and offline S3/DynamoDB migrations |
| `ses` | Delivery provider, local verification simulation and worker/queue budgets; see [SES configuration](#ses-configuration) |

Logging writes to stderr, leaving stdout available for CLI output. `auto` selects
readable context labels such as `[ApiGateway]` in an interactive terminal and JSON
when stderr is redirected. Automatic color requires a terminal and respects a
nonempty `NO_COLOR`; JSON never includes ANSI color codes. Invalid explicit logging
settings stop startup with a redacted diagnostic. Failures use common service,
request ID and cause-code fields; expected request rejections are logged at debug
level. There is no per-service logger or additional logging worker.

Lambda and EC2 paths may be relative to the process working directory and are
resolved at startup. Missing compute tools, packs or an unconfigured EC2 image
still allow the in-process services to run; execution returns an actionable error
when needed. IAM bootstrap/root credentials remain environment-only secret inputs,
resolved once and injected separately from the JSON settings. The same resolved
credentials are used by the offline S3 migration.

EventBridge's HTTP response budget is local resource protection, not an AWS quota.
OAuth and Pipes enrichment read bounded bodies. Classic rules consume only the
response status, so a successful target is not retried merely because its ignored
response body is large. The API destination's AWS deadline remains separate from
these local client settings. Step Functions polling options do not alter ASL state
timeouts, history limits or callback token validity.

S3 permissive presigning captures source selection at startup, but does not cache
profile credentials. It opens the selected `AWS_SHARED_CREDENTIALS_FILE` (or the
selected profile in `~/.aws/credentials`) for each resolution using asynchronous
I/O. Only regular files up to 1 MiB are read. A replaced profile is visible to the
next resolution; an operation already in progress may finish using its earlier
read. Atomic file replacement avoids partially written profiles. Unavailable or
invalid profiles do not retain an earlier secret.

The existing development precedence remains: explicit S3 environment secret,
matching AWS environment key pair, matching selected profile, then the `test` and
`locallycloud` development fallback. Profile deletion therefore does not revoke
those fallback identities. S3 and permissive CloudFormation callbacks share the
same source configuration; an explicitly selected callback access key does not
automatically change identity when a profile changes. Strict S3 requests and strict
CloudFormation callbacks continue using live IAM credentials, expiry and revocation.
No SSO, credential process or external network provider is executed by this reader.
Secrets remain outside JSON configuration and diagnostics.

SNS HTTP(S) subscribers use the same destination policy through
`sns.http_local_origins`. Local test servers need an explicit origin; redirects
are not followed, and metadata and the emulator listener remain blocked. Failed
confirmation delivery leaves the subscription pending and emits a safe diagnostic.
The confirmation URL uses the startup-resolved endpoint.

Kinesis's byte budget applies to its in-memory backend; persisted records use the
SQLite backend. Write-limit simulation keeps the existing supported quota subset.
Cognito's optional mailbox must be an absolute private directory; confirmation
files use mode 0600 and the directory uses 0700. Never put confirmation codes,
passwords or credentials in the configuration file. These settings require restart.

HTTP integrations can reach public destinations. Host addresses, loopback, private
networks and shared address space require an exact origin in `http_local_origins`,
for example `["http://127.0.0.1:8080", "https://api.internal:8443"]`. Origins include
scheme, hostname and effective port; paths, credentials, fragments, queries and
wildcards are not accepted. DNS aliases require their own entry. Metadata and
credential endpoints, link-local and non-destination ranges, known IPv6 transition
mechanisms and LocallyCloud's own listener remain blocked even with an allowlist entry.

EventBridge API destinations and their OAuth endpoints apply the same rules through
`eventbridge.http_local_origins`; only HTTPS is accepted. A denied destination,
including an OAuth authorization endpoint, is a terminal failure: delivery stops,
the configured dead-letter queue is attempted, and the server logs
`cause_code=destination_denied` without the URL. Classic rules honor a
`Retry-After` header in seconds on retried statuses (401, 407, 409, 429, 5xx),
waiting for the longer of it and the retry policy backoff; a negative value stops
retrying. HTTP-date values are ignored.

The connector checks the addresses returned by DNS for each new connection; mixed
allowed/forbidden answers fail closed. It preserves Host/SNI and certificate checks,
ignores environment proxies, and returns redirects without following them. Internal
`x-locallycloud-*` headers are removed before forwarding. Configuration is resolved
at startup and requires a restart to change.

Host-address checks follow current kernel address ownership, including interfaces
added after startup. Unusual host networking such as nonlocal bind can conservatively
reject a destination. This is an application-level destination policy, not a network
sandbox for custom NAT64 prefixes, NAT reflection or routing rules.

API Gateway capacities bound local buffers and caches; they do not change AWS wire
limits. They allocate entries on demand. The SQLite engine, encryption, locking and
transaction durability remain in the shared state layer.


| Variable | Purpose | Default |
| --- | --- | --- |
| `RUST_LOG` | Overrides `logging.filter` using tracing filter directives; maximum 1024 bytes | `info` |
| `LOCALLYCLOUD_LOG_FORMAT` | Overrides `logging.format`: `auto`, `pretty`, or `json` | `auto` |
| `LOCALLYCLOUD_LOG_COLOR` | Overrides `logging.color`: `auto`, `always`, or `never`; applies to readable output | `auto` |
| `LOCALLYCLOUD_CLOUDFORMATION_OPERATION_CAPACITY` | Maximum admitted stack operations, independently of per-stack exclusion; 1–64 | `4` |
| `LOCALLYCLOUD_EC2_STARTUP_TIMEOUT_SECS` | Deadline for starting the local OCI HTTP instance; 1–300 seconds | `5` |
| `LOCALLYCLOUD_EC2_CONNECT_TIMEOUT_SECS` | Deadline for connecting to an instance's local service; 1–300 seconds | `2` |
| `LOCALLYCLOUD_LAMBDA_MAX_WARM_PER_KEY` | Maximum warm environments per execution key; 1–1024 | `10` |
| `LOCALLYCLOUD_LAMBDA_WARM_IDLE_TIMEOUT_SECS` | Retention of an idle warm environment; 1–3600 seconds | `300` |
| `LOCALLYCLOUD_S3_NOTIFICATION_QUEUE_CAPACITY` | Pending in-memory S3 notification slots; 1–16384 | `1024` |
| `LOCALLYCLOUD_S3_NOTIFICATION_RETRY_INTERVAL_MS` | Local durable-notification retry polling; 100–60000 ms | `1000` |
| `LOCALLYCLOUD_DYNAMODB_KMS_TIMEOUT_SECS` | Encrypted-table broker KMS request deadline; 1–300 seconds | `3` |
| `LOCALLYCLOUD_EVENTBRIDGE_PENDING_RETRY_POLL_INTERVAL_MS` | Local pending-retry polling; 1–10000 ms | `25` |
| `LOCALLYCLOUD_EVENTBRIDGE_HTTP_CONNECT_TIMEOUT_SECS` | HTTP connection deadline; 1–300 seconds | `5` |
| `LOCALLYCLOUD_EVENTBRIDGE_HTTP_REQUEST_TIMEOUT_SECS` | HTTP client request deadline; 1–300 seconds | `30` |
| `LOCALLYCLOUD_EVENTBRIDGE_HTTP_RESPONSE_BODY_LIMIT_BYTES` | Local budget for required HTTP response bodies, not an AWS quota; 1–10485760 | `10485760` |
| `LOCALLYCLOUD_EVENTBRIDGE_HTTP_LOCAL_ORIGINS` | JSON array overriding `eventbridge.http_local_origins`, including `[]` to clear the file value | `[]` |
| `LOCALLYCLOUD_EVENTBRIDGE_HTTP_CLIENT_CACHE_CAPACITY` | Per-origin HTTP clients kept for API destinations and OAuth endpoints; 1–256 | `16` |
| `LOCALLYCLOUD_STEPFUNCTIONS_EXECUTION_POLL_INTERVAL_MS` | Local execution polling; 1–10000 ms | `10` |
| `LOCALLYCLOUD_STEPFUNCTIONS_ATHENA_POLL_INTERVAL_MS` | Local Athena synchronization polling; 1–10000 ms | `50` |
| `LOCALLYCLOUD_STEPFUNCTIONS_ATHENA_CANCEL_TIMEOUT_SECS` | Best-effort Athena cancellation deadline; 1–300 seconds | `5` |
| `LOCALLYCLOUD_CONFIG_FILE` | Absolute path to the startup JSON file | XDG configuration path above |
| `LOCALLYCLOUD_HOST` | Server listen address | `127.0.0.1` |
| `LOCALLYCLOUD_PORT` | Endpoint port | `4566` |
| `LOCALLYCLOUD_DEFAULT_REGION` | Local region | `us-east-1` |
| `LOCALLYCLOUD_ACCOUNT_ID` | Account used in responses and ARNs | `000000000000` |
| `LOCALLYCLOUD_STATE_DB` | SQLite state file | `~/.local/share/locallycloud/state.sqlite3`, or under `XDG_DATA_HOME` when set |
| `LOCALLYCLOUD_KMS_MASTER_KEY` | Base64-encoded 32-byte master key | Required; no default |
| `LOCALLYCLOUD_IAM_ENFORCEMENT` | IAM mode; `strict` evaluates policies | Permissive |
| `LOCALLYCLOUD_APIGATEWAY_HTTP_CLIENT_CACHE_CAPACITY` | Maximum cached HTTP integration clients, one per origin; 1–256 | `16` |
| `LOCALLYCLOUD_APIGATEWAY_HTTP_MAX_IDLE_PER_HOST` | Maximum idle HTTP integration connections per origin; 1–16 | `1` |
| `LOCALLYCLOUD_APIGATEWAY_HTTP_IDLE_TIMEOUT_SECS` | HTTP integration idle connection retention in seconds; 1–300 | `30` |
| `LOCALLYCLOUD_HTTP_INTEGRATION_LOCAL_ORIGINS` | JSON array overriding `apigateway.http_local_origins`, including `[]` to clear the file value | `[]` |
| `LOCALLYCLOUD_APIGATEWAY_AUTHORIZER_CACHE_CAPACITY` | Maximum authorizer cache entries per account/region; 1–65536 | `1024` |
| `LOCALLYCLOUD_APIGATEWAY_WEBSOCKET_OUTBOUND_CHANNEL_CAPACITY` | Per-connection outbound channel capacity; 1–256 | `32` |
| `LOCALLYCLOUD_APIGATEWAY_WEBSOCKET_OUTBOUND_HISTORY_CAPACITY` | Retained outbound messages per connection; 1–1024 | `64` |
| `LOCALLYCLOUD_WORK_DIR` | Lambda work files | `${XDG_CACHE_HOME:-$HOME/.cache}/locallycloud/lambda` |
| `LOCALLYCLOUD_RUNTIME_PACKS_DIR` | Installed Lambda and PostgreSQL runtime packs; relative paths resolve from the server working directory | `<Lambda work directory>/runtime-packs` |
| `LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB` | Shared Lambda environment budget in MiB; see [memory accounting](LAMBDA.md#memory-budget) | `4096` |
| `LOCALLYCLOUD_LAMBDA_ACCOUNT_CONCURRENCY` | Independent Lambda execution quota for each account/region; integer from 1 to 2147483647 | `1000` |
| `LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE` | Classic EventBridge rules: multiply retry delays and maximum event age by this factor; finite number from 0.000001 to 1 | `1` (real time) |
| `LOCALLYCLOUD_SQS_ENDPOINT_STRATEGY` | Shape of returned SQS queue URLs: `path` (`https://aws.localhost:4566/<account>/<queue>`, on the endpoint advertised to Lambda as `AWS_ENDPOINT_URL`, so SDKs that call the queue URL host stay local) or `aws` (`https://sqs.<region>.amazonaws.com/<account>/<queue>`). Both forms are accepted as input | `path` |
| `LOCALLYCLOUD_S3_ACCESS_KEY_ID`, `LOCALLYCLOUD_S3_SECRET_ACCESS_KEY` | Optional permissive presign secret and matching key; callback key defaults to `locallycloud`. These are environment-only inputs | Unset |
| `AWS_PROFILE`, `AWS_SHARED_CREDENTIALS_FILE` | Permissive S3 presign profile selection; selected file contents are read live without caching | `default`, `$HOME/.aws/credentials` |
| `LOCALLYCLOUD_SQS_ESM_MAX_POLLERS` | Local ceiling for SQS event source mapping workers; integer from 2 to 1000, independent of Lambda reserved concurrency | `10` |
| `LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS` | Native-engine write-capacity simulation: `1`/`true` or `0`/`false`; invalid values fail startup. Reads and hot partitions are not modeled | Disabled |
| `LOCALLYCLOUD_SNS_HTTP_LOCAL_ORIGINS` | JSON array overriding `sns.http_local_origins` | `[]` |
| `LOCALLYCLOUD_SNS_HTTP_CLIENT_CACHE_CAPACITY` | Cached HTTP origins; 1–256 | `16` |
| `LOCALLYCLOUD_SNS_HTTP_TIMEOUT_SECS` | Subscriber connection/request deadline; 1–300 seconds | `5` |
| `LOCALLYCLOUD_SNS_OUTBOX_RETRY_INITIAL_SECS` | Initial publication retry delay; 1–300 seconds | `1` |
| `LOCALLYCLOUD_SNS_OUTBOX_RETRY_MAX_SECS` | Maximum retry delay; 1–3600 seconds, at least the initial delay | `30` |
| `LOCALLYCLOUD_FIREHOSE_SOURCE_POLL_INTERVAL_MS` | Kinesis source poll interval; 1–60000 milliseconds | `1000` |
| `LOCALLYCLOUD_FIREHOSE_S3_DISPATCH_TIMEOUT_SECS` | Internal S3 dispatch deadline; 1–300 seconds | `10` |
| `LOCALLYCLOUD_FIREHOSE_MAX_RETRY_DELAY_SECS` | Maximum delivery retry delay; 1–3600 seconds | `30` |
| `LOCALLYCLOUD_LOGS_DELIVERY_RETRY_INTERVAL_MS` | Pending metric/subscription retry interval; 1–60000 milliseconds | `5000` |
| `LOCALLYCLOUD_LOGS_RETENTION_RECLAIM_DELAY_MS` | Retention reclaim delay; 1–60000 milliseconds | `100` |
| `LOCALLYCLOUD_KINESIS_SIMULATE_WRITE_LIMITS` | Simulate the supported provisioned write limits: `1`/`true` or `0`/`false`; invalid explicit values fail startup | Disabled |
| `LOCALLYCLOUD_LAMBDA_MIN_UNRESERVED_CONCURRENCY` | Minimum slots left unreserved when assigning function RC; integer from 0 to the account quota. Set explicitly for quotas below 100 | `100` |
| `LOCALLYCLOUD_PG_BIN_DIR` | Explicit host PostgreSQL toolchain override for RDS, instead of OCI runtime packs | Unset; use an installed PostgreSQL runtime pack |
| `LOCALLYCLOUD_COGNITO_MAILBOX_DIR` | Absolute private directory that receives Cognito confirmation codes | Disabled |
| `LOCALLYCLOUD_UI` | Dashboard: `on` or `off`. `off` returns 404 for the dashboard and its read endpoints, which sign reads with your local AWS profiles; health and status stay available | `on` |
| `LOCALLYCLOUD_ENDPOINT_URL` | Endpoint that Lambda, ECS and EC2 guests use to call back into the emulator. `AWS_ENDPOINT_URL` takes priority when set | Derived from the listen address; a wildcard bind becomes `127.0.0.1` |
| `LOCALLYCLOUD_LEGACY_BACKEND_URL` | Optional external backend for services without a native handler | `http://localhost:4567` |
| `LOCALLYCLOUD_MAX_REQUEST_BODY_BYTES` | Maximum request body size in bytes | `134217728` (128 MiB) |
| `LOCALLYCLOUD_SHUTDOWN_GRACE_PERIOD_SECS` | Seconds to finish in-flight requests on shutdown | `5` |
| `LOCALLYCLOUD_TLS_HOSTNAME`, `LOCALLYCLOUD_TLS_CERT_PATH`, `LOCALLYCLOUD_TLS_KEY_PATH` | Override automatic HTTPS with a DNS hostname, PEM certificate and PKCS#8 key. Set all three or none | Automatic local CA and `aws.localhost` certificate |
| `LOCALLYCLOUD_ALLOW_HTTP` | Also accept plaintext HTTP. Explicit compatibility mode; IAM observes it as insecure transport | `false` |
| `LOCALLYCLOUD_ROUTE53_DNS_BIND` | Address for the Route 53 DNS server, for example `127.0.0.1:5353`. An invalid or busy address stops startup | Disabled |
| `LOCALLYCLOUD_RDS_DATA_DIR` | Absolute directory for local RDS databases | `${XDG_DATA_HOME:-$HOME/.local/share}/locallycloud/rds` |
| `LOCALLYCLOUD_EC2_IMAGE_ROOTFS` | Root filesystem directory for the `ami-locallycloud-http` image; required to run EC2 instances | None |
| `LOCALLYCLOUD_DUCKDB_BIN` | DuckDB executable; see [preparation](#duckdb) | Disabled |
| `LOCALLYCLOUD_DUCKDB_EXTENSIONS_DIR` | Directory directly containing matching `avro.duckdb_extension` and `iceberg.duckdb_extension` files | `${XDG_CACHE_HOME:-$HOME/.cache}/locallycloud/analytics/duckdb/extensions` |
| `LOCALLYCLOUD_DUCKDB_WORK_DIR` | Private temporary query snapshots and results; use disk-backed storage | `${XDG_CACHE_HOME:-$HOME/.cache}/locallycloud/analytics/duckdb/queries` |
| `LOCALLYCLOUD_LAMBDA_MAX_WARM_TOTAL` | Maximum warm Lambda environments across all functions; integer from 0 to 1024 | `16` |
| `LOCALLYCLOUD_KINESIS_MAX_BUFFERED_BYTES` | Record byte budget for the in-memory backend only; 1–1073741824 bytes | `67108864` (64 MiB) |
| `LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID`, `LOCALLYCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY` | Administrator credentials for strict IAM; see [strict IAM credentials](#strict-iam-credentials) | None |
| `LOCALLYCLOUD_ROOT_ACCESS_KEY_ID`, `LOCALLYCLOUD_ROOT_SECRET_ACCESS_KEY` | Root user credentials for the configured account | None |

### Strict IAM credentials

With `LOCALLYCLOUD_IAM_ENFORCEMENT=strict`, the `test`/`test` credentials are
denied, so the server needs an initial administrator. Set both bootstrap variables
before the first strict startup:

- The access key ID has 20 characters: `AKIA` followed by uppercase letters and digits.
- The secret access key has exactly 40 characters from `A-Z`, `a-z`, `0-9`, `+` and `/`.

LocallyCloud creates the IAM user `locallycloud-bootstrap` with an inline
`Action: "*"` policy once per account and keeps it in the state database. Use
those keys in a separate AWS profile to create the users and roles you want to
test. In strict mode, missing or malformed bootstrap credentials stop startup;
error messages never include the values.

The root variables follow the same format, provision the account's root user,
and must not reuse the bootstrap access key ID. Both are optional in permissive
mode.

For scaled concurrency and retry experiments, see the [throttling guide](THROTTLING.md).

### HTTPS for AWS clients

HTTPS is enabled by default at `https://aws.localhost:4566`. The server creates a
local CA automatically and stores its private key encrypted in the state database.
The public CA is exported alongside the database as `<state-db>.ca.pem`; startup
logs print its path. The CA survives restarts with the same database and master key.
No system trust store or `/etc/hosts` file is modified.

Configure the endpoint and trust file once for your local SDK or CLI profile:

```sh
export AWS_ENDPOINT_URL=https://aws.localhost:4566
export AWS_CA_BUNDLE="${LOCALLYCLOUD_STATE_DB:-${XDG_DATA_HOME:-$HOME/.local/share}/locallycloud/state.sqlite3}.ca.pem"
# Node.js uses its TLS trust setting:
export NODE_EXTRA_CA_CERTS="$AWS_CA_BUNDLE"
aws sts get-caller-identity
```

Other clients must load that CA through their TLS trust configuration. Browsers
need the CA imported into their own trust store before opening the HTTPS dashboard.
Keep the default public trust anchors when adding it; never disable certificate
verification. A custom `LOCALLYCLOUD_STATE_DB` changes the exported CA path.

The endpoint certificate covers `aws.localhost`, one subdomain label (for example
`bucket.aws.localhost`) and `sync-aws.localhost`. These support normal SDK endpoint
prefixes without service-specific endpoint overrides. Guests receive a private CA,
the canonical endpoint and local DNS automatically. Their CA private key stays in
the host process. VPC route, endpoint and security-group checks still apply.
Guests reserve the canonical endpoint port; choose a different ECS application port.

On the host, check `getent hosts aws.localhost bucket.aws.localhost sync-aws.localhost`
if DNS fails. Some Linux resolvers already map `.localhost` to loopback; others need
local resolver configuration. `/etc/hosts` supports exact names, not wildcards, so
it is unsuitable for arbitrary S3 bucket names. Guest DNS is handled internally.

Set `LOCALLYCLOUD_ALLOW_HTTP=true` only for HTTP compatibility. It adds HTTP on
the same port; a policy denying `aws:SecureTransport=false` still rejects those
requests. By default, HTTP connections are closed rather than redirected, preserving
SigV4 and the real transport semantics. The advertised endpoint stays HTTPS unless
an HTTP endpoint override is explicitly supplied in compatibility mode.

To provide your own identity, set `LOCALLYCLOUD_TLS_HOSTNAME`,
`LOCALLYCLOUD_TLS_CERT_PATH` and `LOCALLYCLOUD_TLS_KEY_PATH` together. Use a PEM
certificate matching that hostname and a PKCS#8 PEM private key. SDKs that add host
prefixes need matching certificate names and DNS resolution as well.

When starting isolated tests, remove inherited `AWS_ENDPOINT_URL` and
service-specific endpoint overrides so calls cannot reach another instance.

## Uninstallation

Stop LocallyCloud first with `Ctrl+C` in its terminal, or stop the user service or process supervisor you configured. Allow its runtime tasks and local PostgreSQL processes to stop before removing their files.

### Remove the installed program

For a Debian system package:

```sh
sudo apt remove locallycloud
```

For an Arch system package:

```sh
sudo pacman -R locallycloud
```

The package manager removes package-owned files: the binary, desktop launcher, icons, and documentation or license files. Do not remove these files manually from `/usr`. Dependencies you installed separately, such as PostgreSQL or `crun`, remain available to other applications.

For either user-only installation above:

```sh
rm -f -- "$HOME/.local/bin/locallycloud"
```

If you used Debian package extraction, also remove its extraction directory:

```sh
rm -rf -- "$HOME/.local/opt/locallycloud"
```

For a source checkout, the executable and build artifacts remain under `target/`. Run `cargo clean` from that checkout if you want to remove them; keeping the source repository is optional.

### Optional removal of user data

Uninstalling the program preserves resources, keys, and client settings in your home directory. No manual data deletion is required for a normal uninstall. To reset everything, review these locations after stopping the emulator:

| Location | Contents and cleanup |
| --- | --- |
| `${XDG_DATA_HOME:-$HOME/.local/share}/locallycloud/` | Default persistent state, including `state.sqlite3`, local RDS databases, and RDS Data API files. Delete only if you want to discard those resources. |
| `${XDG_CACHE_HOME:-$HOME/.cache}/locallycloud/` | Installed runtime packs (by default under `lambda/runtime-packs/`), Lambda code/root filesystems, compute bundles and analytics caches. Removing packs requires reinstalling them before execution. Stop LocallyCloud before removing this directory. |
| `${TMPDIR:-/tmp}/locallycloud-lambda-<uid>/` | Legacy/fallback Lambda work directory. Inspect leftovers after stopping LocallyCloud. `<uid>` is the output of `id -u`. |
| `${TMPDIR:-/tmp}/locallycloud-oci-<uid>/` and `locallycloud-ecs-<uid>/` | Legacy/fallback compute work directories. Remove only after their tasks have stopped. |
| `/tmp/lc-rds-<token>/` | PostgreSQL socket directories for local RDS instances. Inspect ownership and the corresponding stopped instance before removing a leftover directory; do not delete other instances' directories. |
| `~/.config/locallycloud/kms.key`, if created using the website's example | Your saved KMS master key. This is user-created, not installed by the package. Retain it if you plan to reuse encrypted state. Remove only the dedicated key file or directory you created. |
| `~/.aws/config` and `~/.aws/credentials` | Remove only `[profile locallycloud]` and `[locallycloud]`, respectively, if you no longer need that profile. Keep your other AWS profiles. |


Lambda runtime caches contain read-only trees. Before deleting a stopped instance's
cache, restore write permission on its directories only, for example
`find /path/to/that/cache -type d -exec chmod u+w {} +`. Do not recursively change
file permissions: runtime files may share hard links with installed packs. For custom `LOCALLYCLOUD_STATE_DB`, `LOCALLYCLOUD_RDS_DATA_DIR` or
`LOCALLYCLOUD_WORK_DIR`, inspect the configured locations separately. A custom SQLite
file may also have `-wal` and `-shm` sidecars. An EC2 root filesystem supplied through
`LOCALLYCLOUD_EC2_IMAGE_ROOTFS` belongs to you.

Remove only dedicated LocallyCloud files and profile entries. Keep shared host tools,
other AWS profiles, and any master key needed to reuse encrypted state.

## SES configuration

The native [SES sending milestone](SES.md) uses the same startup configuration and
secret-input rules described above. Its section in the existing JSON file is:

```json
{
  "ses": {
    "provider": "capture",
    "auto_verify_identities": false
  }
}
```

| JSON field | Environment override | Default and supported values |
| --- | --- | --- |
| `ses.provider` | `LOCALLYCLOUD_SES_PROVIDER` | `capture`; `resend` enables delivery through the managed provider's HTTPS API |
| `ses.auto_verify_identities` | `LOCALLYCLOUD_SES_AUTO_VERIFY_IDENTITIES` | `false`; explicitly set `true` to simulate verification completion for new create/verify calls in local development |
| `ses.request_timeout_secs` | `LOCALLYCLOUD_SES_REQUEST_TIMEOUT_SECS` | `30`; 1–300 seconds |
| `ses.max_concurrency` | `LOCALLYCLOUD_SES_MAX_CONCURRENCY` | `2`; 1–16 active delivery workers |
| `ses.max_pending_messages` | `LOCALLYCLOUD_SES_MAX_PENDING_MESSAGES` | `1000`; 1–100000 messages awaiting delivery or resolution |
| `ses.max_pending_bytes` | `LOCALLYCLOUD_SES_MAX_PENDING_BYTES` | `67108864`; 1024–1073741824 encrypted pending bytes |
| Not accepted in JSON | `LOCALLYCLOUD_SES_PROVIDER_API_KEY` | Unset; required when selecting `resend`, supplied as a secret environment input |

An invalid or empty explicit override fails startup. Resend without a key does not
fall back to capture. `api_key` and `credential_ref` are not supported JSON fields;
credential references and UI key entry await the shared administrative secret store.
Changes take effect after restart. Capture mode sends no real email.
