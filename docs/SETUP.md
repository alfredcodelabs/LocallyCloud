# Setup and configuration

[← README](../README.md) · [Services](SERVICES.md) · [Platforms](PLATFORMS.md) · [Throttling](THROTTLING.md) · [FAQ](FAQ.md) · [Agent context](AGENT_CONTEXT.md)

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
sudo apt install ./locallycloud_0.1.0.beta.3-1_amd64.deb
```

Use the filename for the version and architecture you downloaded. The package includes SQLite and installs its required system libraries through `apt`, plus the recommended `dbus-user-session`; Rust and a separate SQLite installation are not needed. The installed command is `locallycloud`.

### Arch Linux package

When a tagged release is available, download its `.pkg.tar.zst` for Arch Linux `x86_64`:

```sh
sudo pacman -U ./locallycloud-0.1.0beta.3-1-x86_64.pkg.tar.zst
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
dpkg-deb --extract ./locallycloud_0.1.0.beta.3-1_amd64.deb "$HOME/.local/opt/locallycloud"
ln -s "$HOME/.local/opt/locallycloud/usr/bin/locallycloud" "$HOME/.local/bin/locallycloud"
export PATH="$HOME/.local/bin:$PATH"
```

Use the filename for your downloaded release and choose one installation method. Extraction does not resolve dependencies or install desktop integration. This user-only installation is not managed by `apt` or `pacman`. Add `~/.local/bin` to your shell's `PATH` if it is not already there.

An agent can then start `locallycloud`, set up the `locallycloud` AWS profile, and use AWS CLI, SDKs, or HTTP requests under the same user. Host preparation for optional features may still need administrator access: installing dependencies, enabling rootless user namespaces, or granting access to `/dev/kvm`. Rootless OCI execution depends on the host's kernel and security configuration; access to port 4566 itself does not require root.

## Optional runtime dependencies

The server can start without a compute runtime. Install these dependencies only for the workflows that need them; Linux packages do not install them automatically, except that `apt` installs the `.deb`'s recommended `dbus-user-session`.

| Workflow | Requirement |
| --- | --- |
| Invoke Lambda, run ECS/Fargate tasks, or run EC2 instances | `crun` or `youki` available in `PATH`, a systemd user session with a user D-Bus (`dbus-user-session` on Debian and Ubuntu), and delegated cgroup v2 memory control on a compatible Linux host. Custom-runtime binaries (`provided.al2023`) must match the host architecture. |
| Run ECS/Fargate tasks | The OCI prerequisites above, delegated cgroup v2 CPU control, `ip` and `nft` in `PATH` (`iproute2` and `nftables` packages), and kernel netfilter redirect support (`nft_redir`). Task networking is configured inside owned guest namespaces; run the emulator as your ordinary user. |
| Run ZIP-based Node.js or Python Lambda functions | An OCI runtime above and the matching language executable: `node` or, for example, `python3.13`. Debian 13's `nodejs` is Node 20; choose a version compatible with the declared function runtime. |
| Use the runtime-included AWS SDK (`import boto3`) in Python functions without packaging it | The distribution's boto3 for that interpreter: `python3-boto3` (Debian and Ubuntu) or `python-boto3` (Arch). LocallyCloud copies boto3 and its pure-Python dependencies into the runtime; packaged copies in the function or its layers take precedence. Without it, functions must package boto3. Node.js runtimes do not include the AWS SDK for JavaScript v3 locally, so bundle `@aws-sdk/*` with the function. |
| Run RDS PostgreSQL or Aurora PostgreSQL, including RDS Data API access | PostgreSQL 16 or later; use the newest version your distribution provides. `initdb`, `pg_ctl`, `postgres`, `psql`, and `pg_basebackup` must have matching versions. LocallyCloud starts its own databases. |
| Open the dashboard from the applications menu | `xdg-utils`. Opening the URL directly in a browser does not require it. |

On Debian and Ubuntu, install the components you need with `sudo apt install crun dbus-user-session`, `sudo apt install postgresql`, `sudo apt install python3-boto3`, or `sudo apt install xdg-utils`; on Arch, use `sudo pacman -S crun postgresql python-boto3 xdg-utils`. RDS finds PostgreSQL on `PATH` (Arch) or the newest version under `/usr/lib/postgresql/<version>/bin` (Debian and Ubuntu). Set `LOCALLYCLOUD_PG_BIN_DIR` only to use a different installation.


OCI execution requires a working systemd user D-Bus session and cgroup delegation.
On WSL 2, enable systemd first. See [platform setup](PLATFORMS.md#wsl-2) and
[Debian runtime troubleshooting](FAQ.md#why-does-lambda-report-d-bus-errors-and-then-toomanyrequestsexception-on-debian).

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
| `LOCALLYCLOUD_RUNTIME` | Compute runtime: `auto`, `firecracker`, or `youki` (OCI) | `auto` |
| `LOCALLYCLOUD_WORK_DIR` | Lambda work files | `${XDG_CACHE_HOME:-$HOME/.cache}/locallycloud/lambda` |
| `LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB` | Memory budget for Lambda environments | `1024` |
| `LOCALLYCLOUD_LAMBDA_ACCOUNT_CONCURRENCY` | Independent Lambda execution quota for each account/region; integer from 1 to 2147483647 | `1000` |
| `LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE` | Classic EventBridge rules: multiply retry delays and maximum event age by this factor; finite number from 0.000001 to 1 | `1` (real time) |
| `LOCALLYCLOUD_SQS_ENDPOINT_STRATEGY` | Shape of returned SQS queue URLs: `path` (`http://127.0.0.1:4566/<account>/<queue>`, on the endpoint advertised to Lambda as `AWS_ENDPOINT_URL`, so SDKs that call the queue URL host stay local) or `aws` (`https://sqs.<region>.amazonaws.com/<account>/<queue>`). Both forms are accepted as input | `path` |
| `LOCALLYCLOUD_SQS_ESM_MAX_POLLERS` | Local ceiling for SQS event source mapping workers; integer from 2 to 1000, independent of Lambda reserved concurrency | `10` |
| `LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS` | Set exactly `1` to simulate controlled table write limits; reads and hot partitions are not modeled | Disabled |
| `LOCALLYCLOUD_KINESIS_SIMULATE_WRITE_LIMITS` | Set exactly `1` to simulate provisioned shard write limits | Disabled |
| `LOCALLYCLOUD_LAMBDA_MIN_UNRESERVED_CONCURRENCY` | Minimum slots left unreserved when assigning function RC; integer from 0 to the account quota. Set explicitly for quotas below 100 | `100` |
| `LOCALLYCLOUD_PG_BIN_DIR` | PostgreSQL binaries for RDS | Found on `PATH`, then the newest under `/usr/lib/postgresql` |
| `LOCALLYCLOUD_COGNITO_MAILBOX_DIR` | Directory that receives Cognito confirmation codes | Disabled |
| `LOCALLYCLOUD_UI` | Dashboard: `on` or `off`. `off` returns 404 for the dashboard and its read endpoints, which sign reads with your local AWS profiles; health and status stay available | `on` |

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
| `${XDG_CACHE_HOME:-$HOME/.cache}/locallycloud/` | PostgreSQL and language runtime caches; Lambda code/root filesystems and compute bundles under `lambda/`, `oci/`, `ecs/`, and `firecracker/`. Stop LocallyCloud before removing this cache. |
| `${TMPDIR:-/tmp}/locallycloud-lambda-<uid>/` | Legacy/fallback Lambda work directory. Inspect leftovers after stopping LocallyCloud. `<uid>` is the output of `id -u`. |
| `${TMPDIR:-/tmp}/locallycloud-oci-<uid>/`, `locallycloud-ecs-<uid>/`, and `locallycloud-firecracker-<uid>/` | Legacy/fallback compute work directories. Remove only after their tasks have stopped. |
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
