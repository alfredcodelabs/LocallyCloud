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
- SQLite 3.53.4 or later, including development headers and the library.
- A C/C++ build toolchain, CMake, and pkg-config for native dependencies.
- OpenSSL CLI for the key-generation example below.
- AWS CLI v2 for the usage examples, or an AWS SDK for your application.

```sh
cargo build --release --locked -p locallycloud
```

The executable is `target/release/locallycloud`. Continue with [Quick start](../README.md#quick-start).

### Debian and Ubuntu package (`.deb`)

The `.deb` supports Debian 13, Ubuntu 24.04 LTS and 26.04 LTS, distributions based on them (such as Linux Mint or Pop!_OS), and WSL 2 distributions based on them. Releases provide one package per architecture: `amd64` for Intel and AMD processors, and `arm64` for ARM processors. The package requires glibc 2.39 or later; older releases such as Ubuntu 22.04 are not supported, and `apt` refuses to install the package there. When a tagged release is available, download the `.deb` for your architecture (`dpkg --print-architecture` shows it). From the download directory:

```sh
sudo apt install ./locallycloud_0.1.0-1_amd64.deb
```

Use the filename for the version and architecture you downloaded. The package includes SQLite and installs its required system libraries through `apt`; Rust and a separate SQLite installation are not needed. It recommends `dbus-user-session`, but APT can leave recommendations uninstalled. Install it explicitly when using OCI compute. The installed command is `locallycloud`.

### Arch Linux package

When a tagged release is available, download its `.pkg.tar.zst` for Arch Linux `x86_64`:

```sh
sudo pacman -U ./locallycloud-0.1.0-1-x86_64.pkg.tar.zst
```

Use the filename for the version you downloaded. The package requires SQLite 3.53.4 or later from the Arch repositories. The installed command is `locallycloud`. On Arch Linux ARM (`aarch64`), build the package from a source checkout with `makepkg` in `packaging/arch`; that platform is supported on a best-effort basis.

GitHub Actions builds both package formats. The [AUR recipe](../packaging/aur/PKGBUILD) and [signed APT repository tooling](../packaging/apt/README.md) are prepared, but those distribution channels are not yet published. Download packages from [GitHub Releases](https://github.com/alfredcodelabs/LocallyCloud/releases). See the [packaging and release guide](../packaging/VERSIONING.md).

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
dpkg-deb --extract ./locallycloud_0.1.0-1_amd64.deb "$HOME/.local/opt/locallycloud"
ln -s "$HOME/.local/opt/locallycloud/usr/bin/locallycloud" "$HOME/.local/bin/locallycloud"
export PATH="$HOME/.local/bin:$PATH"
```

Use the filename for your downloaded release and choose one installation method. Extraction does not resolve dependencies or install desktop integration. This user-only installation is not managed by `apt` or `pacman`. Add `~/.local/bin` to your shell's `PATH` if it is not already there.

An agent can then start `locallycloud`, set up the `locallycloud` AWS profile, and use AWS CLI, SDKs, or HTTP requests under the same user. Host preparation for optional features may still need administrator access: installing dependencies or enabling rootless user namespaces and cgroup delegation. Rootless OCI execution depends on the host's kernel and security configuration; access to port 4566 itself does not require root.

## Optional runtime dependencies

The server can start without a compute runtime. Install these dependencies only for the workflows that need them. The `.deb` recommends `dbus-user-session`; check that it is installed before using OCI compute, since APT may skip recommendations.

| Workflow | Requirement |
| --- | --- |
| Invoke Lambda, run ECS/Fargate tasks, or run EC2 instances | `crun` or `youki` available in `PATH`, a systemd user session with a user D-Bus (`dbus-user-session` on Debian and Ubuntu), and delegated cgroup v2 memory control on a compatible Linux host. |
| Run ECS/Fargate tasks | The OCI prerequisites above, delegated cgroup v2 CPU control, `ip` and `nft` in `PATH` (`iproute2` and `nftables` packages), and kernel netfilter redirect support (`nft_redir`). Task networking is configured inside owned guest namespaces; run the emulator as your ordinary user. |
| Run Lambda code | A matching [official runtime pack](LAMBDA.md). Python 3 is needed only to install, check or update packs. |
| Route Firehose Iceberg records with `MetadataExtraction` | `jq` available in `PATH`. |
| Run broader Athena SQL on Iceberg tables | DuckDB, with `LOCALLYCLOUD_DUCKDB_BIN` set to its executable. Without it, Athena uses a built-in reader for a smaller SQL subset. |
| Run EC2 instances | The OCI prerequisites above and `LOCALLYCLOUD_EC2_IMAGE_ROOTFS` pointing to the image's root filesystem. |
| Run RDS PostgreSQL or Aurora PostgreSQL, including RDS Data API access | The OCI prerequisites above and an explicitly installed PostgreSQL pack: `locallycloud runtime install postgres18`. PostgreSQL 16, 17 and 18 are supported; the default is 18. No host PostgreSQL installation is required. |
| Open the dashboard from the applications menu | `xdg-utils`. Opening the URL directly in a browser does not require it. |

On Debian and Ubuntu, install only the host tools you need with `sudo apt install crun dbus-user-session` or `sudo apt install xdg-utils`; add `python3` for runtime preparation or `jq` for metadata extraction. On Arch, the equivalent packages are `crun`, `dbus`, `xdg-utils`, `python` and `jq`. Runtime packs are downloaded only by explicit `locallycloud runtime install/update` commands. To use a host PostgreSQL toolchain instead of OCI, set `LOCALLYCLOUD_PG_BIN_DIR` to its `bin` directory; all five tools (`initdb`, `pg_ctl`, `postgres`, `psql`, `pg_basebackup`) must have matching versions, 16 or later.

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
endpoint_url = http://127.0.0.1:4566
```

In `~/.aws/credentials`:

```ini
[locallycloud]
aws_access_key_id = test
aws_secret_access_key = test
```

The `config` file uses `[profile locallycloud]`; the `credentials` file uses `[locallycloud]`. These are local test credentials. The profile name is independent of the emulator's current binary name.

Select the profile for a request:

```sh
aws --profile locallycloud sts get-caller-identity
aws --profile locallycloud s3 ls
```

To make it the default for the current terminal:

```sh
export AWS_PROFILE=locallycloud
aws sts get-caller-identity
aws s3 ls
```

With `AWS_PROFILE` set, neither `--profile` nor `--endpoint-url` is needed. Alternatively, configure these same entries under `[default]` in both files to use them when no named profile is selected. This changes the default destination of AWS CLI requests in that configuration.

The saved endpoint applies to all AWS CLI services unless a higher-priority endpoint override is configured. Existing `AWS_ENDPOINT_URL` or service-specific endpoint variables can override it; `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true` disables configured endpoints. When using `AWS_PROFILE` without `--profile`, environment credentials can also take precedence over saved credentials. Use a dedicated terminal with those overrides cleared for profile-based local development.

See the AWS documentation for [configured endpoints](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-endpoints.html) and [configuration and credentials files](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `LOCALLYCLOUD_HOST` | Server listen address | `127.0.0.1` |
| `LOCALLYCLOUD_PORT` | Endpoint port | `4566` |
| `LOCALLYCLOUD_DEFAULT_REGION` | Local region | `us-east-1` |
| `LOCALLYCLOUD_ACCOUNT_ID` | Account used in responses and ARNs | `000000000000` |
| `LOCALLYCLOUD_STATE_DB` | SQLite state file | `~/.local/share/locallycloud/state.sqlite3`, or under `XDG_DATA_HOME` when set |
| `LOCALLYCLOUD_KMS_MASTER_KEY` | Base64-encoded 32-byte master key | Required; no default |
| `LOCALLYCLOUD_IAM_ENFORCEMENT` | IAM mode; `strict` evaluates policies | Permissive |
| `LOCALLYCLOUD_WORK_DIR` | Lambda work files | `${XDG_CACHE_HOME:-$HOME/.cache}/locallycloud/lambda` |
| `LOCALLYCLOUD_RUNTIME_PACKS_DIR` | Installed Lambda and PostgreSQL runtime packs; relative paths resolve from the server working directory | `<Lambda work directory>/runtime-packs` |
| `LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB` | Shared Lambda environment budget in MiB; see [memory accounting](LAMBDA.md#memory-budget) | `4096` |
| `LOCALLYCLOUD_LAMBDA_ACCOUNT_CONCURRENCY` | Independent Lambda execution quota for each account/region; integer from 1 to 2147483647 | `1000` |
| `LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE` | Classic EventBridge rules: multiply retry delays and maximum event age by this factor; finite number from 0.000001 to 1 | `1` (real time) |
| `LOCALLYCLOUD_SQS_ENDPOINT_STRATEGY` | Shape of returned SQS queue URLs: `path` (`http://127.0.0.1:4566/<account>/<queue>`, on the endpoint advertised to Lambda as `AWS_ENDPOINT_URL`, so SDKs that call the queue URL host stay local) or `aws` (`https://sqs.<region>.amazonaws.com/<account>/<queue>`). Both forms are accepted as input | `path` |
| `LOCALLYCLOUD_SQS_ESM_MAX_POLLERS` | Local ceiling for SQS event source mapping workers; integer from 2 to 1000, independent of Lambda reserved concurrency | `10` |
| `LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS` | Set exactly `1` to simulate controlled table write limits; reads and hot partitions are not modeled | Disabled |
| `LOCALLYCLOUD_KINESIS_SIMULATE_WRITE_LIMITS` | Set exactly `1` to simulate provisioned shard write limits | Disabled |
| `LOCALLYCLOUD_LAMBDA_MIN_UNRESERVED_CONCURRENCY` | Minimum slots left unreserved when assigning function RC; integer from 0 to the account quota. Set explicitly for quotas below 100 | `100` |
| `LOCALLYCLOUD_PG_BIN_DIR` | Explicit host PostgreSQL toolchain override for RDS, instead of OCI runtime packs | Unset; use an installed PostgreSQL runtime pack |
| `LOCALLYCLOUD_COGNITO_MAILBOX_DIR` | Directory that receives Cognito confirmation codes | Disabled |
| `LOCALLYCLOUD_UI` | Dashboard: `on` or `off`. `off` returns 404 for the dashboard and its read endpoints, which sign reads with your local AWS profiles; health and status stay available | `on` |
| `LOCALLYCLOUD_ENDPOINT_URL` | Endpoint that Lambda, ECS and EC2 guests use to call back into the emulator. `AWS_ENDPOINT_URL` takes priority when set | Derived from the listen address; a wildcard bind becomes `127.0.0.1` |
| `LOCALLYCLOUD_LEGACY_BACKEND_URL` | Optional external backend for services without a native handler | `http://localhost:4567` |
| `LOCALLYCLOUD_MAX_REQUEST_BODY_BYTES` | Maximum request body size in bytes | `134217728` (128 MiB) |
| `LOCALLYCLOUD_SHUTDOWN_GRACE_PERIOD_SECS` | Seconds to finish in-flight requests on shutdown | `5` |
| `LOCALLYCLOUD_TLS_HOSTNAME`, `LOCALLYCLOUD_TLS_CERT_PATH`, `LOCALLYCLOUD_TLS_KEY_PATH` | Serve HTTPS for this DNS hostname on the same port, with a PEM certificate and PKCS#8 key. Set all three or none | Disabled |
| `LOCALLYCLOUD_ROUTE53_DNS_BIND` | Address for the Route 53 DNS server, for example `127.0.0.1:5353`. An invalid or busy address stops startup | Disabled |
| `LOCALLYCLOUD_RDS_DATA_DIR` | Absolute directory for local RDS databases | `${XDG_DATA_HOME:-$HOME/.local/share}/locallycloud/rds` |
| `LOCALLYCLOUD_EC2_IMAGE_ROOTFS` | Root filesystem directory for the `ami-locallycloud-http` image; required to run EC2 instances | None |
| `LOCALLYCLOUD_DUCKDB_BIN` | DuckDB executable for Athena queries on Iceberg tables; without it, a built-in reader handles a smaller SQL subset | Disabled |
| `LOCALLYCLOUD_LAMBDA_MAX_WARM_TOTAL` | Maximum warm Lambda environments across all functions; integer from 0 to 1024 | `16` |
| `LOCALLYCLOUD_KINESIS_MAX_BUFFERED_BYTES` | Maximum bytes of records Kinesis keeps in memory | `67108864` (64 MiB) |
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
| `${XDG_CACHE_HOME:-$HOME/.cache}/locallycloud/` | PostgreSQL and language runtime caches; Lambda code/root filesystems and compute bundles under `lambda/`, `oci/` and `ecs/`. Stop LocallyCloud before removing this cache. |
| `${TMPDIR:-/tmp}/locallycloud-lambda-<uid>/` | Legacy/fallback Lambda work directory. Inspect leftovers after stopping LocallyCloud. `<uid>` is the output of `id -u`. |
| `${TMPDIR:-/tmp}/locallycloud-oci-<uid>/` and `locallycloud-ecs-<uid>/` | Legacy/fallback compute work directories. Remove only after their tasks have stopped. |
| `/tmp/lc-rds-<token>/` | PostgreSQL socket directories for local RDS instances. Inspect ownership and the corresponding stopped instance before removing a leftover directory; do not delete other instances' directories. |
| `~/.config/locallycloud/kms.key`, if created using the website's example | Your saved KMS master key. This is user-created, not installed by the package. Retain it if you plan to reuse encrypted state. Remove only the dedicated key file or directory you created. |
| `~/.aws/config` and `~/.aws/credentials` | Remove only `[profile locallycloud]` and `[locallycloud]`, respectively, if you no longer need that profile. Keep your other AWS profiles. |


Lambda runtime caches contain read-only trees. If you choose to delete a stopped
instance's cache, restore write permission first with `chmod -R u+w` on that specific
cache directory. For custom `LOCALLYCLOUD_STATE_DB`, `LOCALLYCLOUD_RDS_DATA_DIR` or
`LOCALLYCLOUD_WORK_DIR`, inspect the configured locations separately. A custom SQLite
file may also have `-wal` and `-shm` sidecars. An EC2 root filesystem supplied through
`LOCALLYCLOUD_EC2_IMAGE_ROOTFS` belongs to you.

Remove only dedicated LocallyCloud files and profile entries. Keep shared host tools,
other AWS profiles, and any master key needed to reuse encrypted state.
