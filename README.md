# LocallyCloud

A local AWS service emulator for Linux. Develop and test serverless applications, event pipelines, and data workflows through a single AWS-compatible endpoint, using your AWS CLI or SDK clients.

LocallyCloud runs as a Rust binary without a Docker daemon. **It is currently a beta for local development and testing.** Services implement subsets of AWS operations; validate your application on AWS before deploying it.

Need help? Read the [frequently asked questions](docs/FAQ.md) for profiles, compatibility, runtime requirements, and troubleshooting. [Supported platforms](docs/PLATFORMS.md) lists the Linux distributions, architectures, and WSL 2 support, and explains how to use LocallyCloud from macOS or Windows through a Linux virtual machine.

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

The executable is `target/release/locallycloud`. Continue with [Quick start](#quick-start).

### Debian and Ubuntu package (`.deb`)

The `.deb` supports Debian 13, Ubuntu 24.04 LTS and 26.04 LTS, distributions based on them (such as Linux Mint or Pop!_OS), and WSL 2 distributions based on them. Releases provide one package per architecture: `amd64` for Intel and AMD processors, and `arm64` for ARM processors. The package requires glibc 2.39 or later; older releases such as Ubuntu 22.04 are not supported, and `apt` refuses to install the package there. When a tagged release is available, download the `.deb` for your architecture (`dpkg --print-architecture` shows it). From the download directory:

```sh
sudo apt install ./locallycloud_0.1.0~beta.1-1_amd64.deb
```

Use the filename for the version and architecture you downloaded. The package includes SQLite and installs its required system libraries through `apt`, plus the recommended `dbus-user-session`; Rust and a separate SQLite installation are not needed. The installed command is `locallycloud`.

### Arch Linux package

When a tagged release is available, download its `.pkg.tar.zst` for Arch Linux `x86_64`:

```sh
sudo pacman -U ./locallycloud-0.1.0beta.1-1-x86_64.pkg.tar.zst
```

Use the filename for the version you downloaded. The package requires SQLite 3.53.4 or later from the Arch repositories. The installed command is `locallycloud`. On Arch Linux ARM (`aarch64`), build the package from a source checkout with `makepkg` in `packaging/arch`; that platform is supported on a best-effort basis.

GitHub Actions builds both package formats. AUR and an APT repository are planned; a portable package format has not been chosen yet. See the [packaging and release guide](packaging/VERSIONING.md).

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
dpkg-deb --extract ./locallycloud_0.1.0~beta.1-1_amd64.deb "$HOME/.local/opt/locallycloud"
ln -s "$HOME/.local/opt/locallycloud/usr/bin/locallycloud" "$HOME/.local/bin/locallycloud"
export PATH="$HOME/.local/bin:$PATH"
```

Use the filename for your downloaded release and choose one installation method. Extraction does not resolve dependencies or install desktop integration. This user-only installation is not managed by `apt` or `pacman`. Add `~/.local/bin` to your shell's `PATH` if it is not already there.

An agent can then start `locallycloud`, set up the `locallycloud` AWS profile, and use AWS CLI, SDKs, or HTTP requests under the same user. Host preparation for optional features may still need administrator access: installing dependencies, enabling rootless user namespaces, or granting access to `/dev/kvm`. Rootless OCI execution depends on the host's kernel and security configuration; access to port 4566 itself does not require root.

## Quick start

### 1. Configure a master key and start the server

Generate a base64-encoded 32-byte KMS master key **once, before the first startup**:

```sh
export LOCALLYCLOUD_KMS_MASTER_KEY="$(openssl rand -base64 32)"
```

Keep this key securely and reuse it for the same state directory after restarting. An unencoded 32-character string is not valid; changing the key prevents reading data encrypted with the previous key.

For a source build, run from the repository root:

```sh
./target/release/locallycloud
```

For an installed Debian, Arch, or user-only executable, run `locallycloud` instead. The state directory must be private to the user running the process.

### 2. Check the server

In another terminal:

```sh
curl -fsS http://127.0.0.1:4566/_locallycloud/health
```

The default AWS endpoint is `http://127.0.0.1:4566`. Open the dashboard at [http://127.0.0.1:4566/_locallycloud/ui](http://127.0.0.1:4566/_locallycloud/ui), or inspect registered services at `http://127.0.0.1:4566/_locallycloud/status`.

### 3. Configure the AWS profile once

In that second terminal, save local test credentials, the region, and the endpoint in a named AWS CLI v2 profile:

```sh
aws configure set aws_access_key_id test --profile locallycloud
aws configure set aws_secret_access_key test --profile locallycloud
aws configure set region us-east-1 --profile locallycloud
aws configure set endpoint_url http://127.0.0.1:4566 --profile locallycloud
aws --profile locallycloud sts get-caller-identity
```

AWS CLI reads the endpoint and port from the profile. Subsequent requests only need `--profile locallycloud`; you do not need to repeat `--endpoint-url`, credentials, or the region. See [Local AWS profile](#local-aws-profile) for the equivalent config files and how to make this the default profile.

### 4. Create a bucket and store an object

Using the profile configured above:

```sh
printf 'hello\n' > /tmp/locallycloud-demo.txt
aws --profile locallycloud s3api create-bucket \
  --bucket locallycloud-demo
aws --profile locallycloud s3api put-object \
  --bucket locallycloud-demo --key greeting.txt --body /tmp/locallycloud-demo.txt
aws --profile locallycloud s3api get-object \
  --bucket locallycloud-demo --key greeting.txt /tmp/locallycloud-download.txt
cat /tmp/locallycloud-download.txt
```

The downloaded file should contain `hello`.

## Available services

Service registration does not imply full AWS coverage. Supported operations and cross-service behavior vary by service.

| Area | Services and APIs |
| --- | --- |
| Storage and messaging | S3, DynamoDB, DynamoDB Streams, SQS, SNS |
| Compute and containers | Lambda, EC2/VPC, ECS/Fargate, ECR |
| Networking and delivery | API Gateway REST and v2, Elastic Load Balancing v2, Route 53, CloudFront |
| Events and workflows | EventBridge Events, Scheduler, Pipes, and Schemas; Step Functions |
| Streaming and data | Kinesis Data Streams, Data Firehose, Glue, Athena, RDS, RDS Data API |
| Identity and security | IAM, STS, KMS, Systems Manager, Secrets Manager, Cognito User Pools, Certificate Manager, WAF v2 |
| Infrastructure and observability | CloudFormation, CloudWatch Logs and Metrics, CloudTrail, X-Ray |
| Recovery | ARC configuration and routing controls, manual Region Switch |

Example workflows include S3 → Lambda → SQS, EventBridge → Step Functions → DynamoDB, and Kinesis → Firehose → S3. DynamoDB Global Tables MREC supports eventual replication; ARC can manually change a local Route 53 DNS target.

## Optional runtime dependencies

The server can start without a compute runtime. Install these dependencies only for the workflows that need them; Linux packages do not install them automatically, except that `apt` installs the `.deb`'s recommended `dbus-user-session`.

| Workflow | Requirement |
| --- | --- |
| Invoke Lambda, run ECS/Fargate tasks, or run EC2 instances | `crun` or `youki` available in `PATH`, a systemd user session with a user D-Bus (`dbus-user-session` on Debian and Ubuntu), and delegated cgroup v2 memory control on a compatible Linux host. Custom-runtime binaries (`provided.al2023`) must match the host architecture. |
| Run ZIP-based Node.js or Python Lambda functions | An OCI runtime above and the matching language executable: `node` or, for example, `python3.13`. Debian 13's `nodejs` is Node 20; choose a version compatible with the declared function runtime. |
| Run RDS PostgreSQL or Aurora PostgreSQL, including RDS Data API access | PostgreSQL 16 or later; use the newest version your distribution provides. `initdb`, `pg_ctl`, `postgres`, `psql`, and `pg_basebackup` must have matching versions. LocallyCloud starts its own databases. |
| Open the dashboard from the applications menu | `xdg-utils`. Opening the URL directly in a browser does not require it. |

On Debian and Ubuntu, install the components you need with `sudo apt install crun dbus-user-session`, `sudo apt install postgresql`, or `sudo apt install xdg-utils`; on Arch, use `sudo pacman -S crun postgresql xdg-utils`. RDS finds PostgreSQL on `PATH` (Arch) or the newest version under `/usr/lib/postgresql/<version>/bin` (Debian and Ubuntu). Set `LOCALLYCLOUD_PG_BIN_DIR` only to use a different installation.

### Debian OCI execution

The `.deb` recommends `dbus-user-session`, so `apt` installs it by default; installations that skip recommended packages, minimal images, and cloud images may still lack it. Install it with `crun`, then log out and log back in, or reboot, to establish the systemd user D-Bus session. On WSL 2, enable systemd first: add `[boot]` and `systemd=true` to `/etc/wsl.conf`, then run `wsl --shutdown` from Windows and reopen the distribution. Run LocallyCloud as your ordinary user; only package installation requires administrator privileges. You can inspect the user bus with `systemctl --user status dbus`.

The host must also delegate cgroup v2 memory control to the user session. Installing D-Bus alone does not provide that delegation. The current runtime uses systemd cgroups; switching to `cgroupfs` is not an automatic fallback and still requires permission to manage cgroups.

A known beta issue was reproduced with Debian 13 and `crun` 1.21: when a guest fails to start because D-Bus is unavailable, its memory reservation can remain allocated, and later Lambda invocations return `TooManyRequestsException`. With the default 1,024 MiB budget and a 128 MiB function, this starts after about six failed invocations. Resolve the session prerequisites, then restart LocallyCloud with the same state database and KMS master key. Increasing the memory budget does not fix this issue. See [Debian Lambda troubleshooting](docs/FAQ.md#why-does-lambda-report-d-bus-errors-and-then-toomanyrequestsexception-on-debian).

## Tool compatibility

Use LocallyCloud's endpoint with existing AWS tools. Compatibility is limited to tested workflows, not every feature of each tool.

| Tool | Tested scope |
| --- | --- |
| AWS CLI and SDKs | AWS wire protocols for implemented operations. |
| Terraform with the AWS provider | AWS provider 6.x: `apply`, `plan` with no changes, restart, and `destroy` for S3 buckets, SQS queues, SNS topics, DynamoDB tables, IAM roles, Lambda functions, KMS keys, SSM parameters, Secrets Manager secrets, CloudWatch log groups, EventBridge rules, HTTP APIs, Kinesis streams, and ECS clusters, plus specific integration workflows. |
| Serverless Framework with `serverless-localstack` | Specific integration workflows pointing at the local endpoint. |
| AWS SAM CLI 1.166.2 | `sam deploy` for HTTP API → Lambda ZIP → DynamoDB SimpleTable, including creation, deployment without changes, updates, and cleanup. |

The SAM workflow supports explicit or implicit roles and HTTP APIs, S3-packaged `CodeUri`, and HttpApi events. Unsupported SAM properties and resource types are rejected.

Supported `Globals.Function` settings include runtime, handler, memory, timeout, environment and VPC configuration. Local properties override scalar defaults, maps merge and global list entries precede local entries. Nonempty `Globals.HttpApi` settings are not supported.

Some `LOCALSTACK_*` configuration aliases and `/_localstack/health` are accepted. Other LocalStack plugins may require APIs that LocallyCloud does not implement.

IAM defaults to permissive mode. To test permissions, enable `LOCALLYCLOUD_IAM_ENFORCEMENT=strict` with bootstrap credentials. Lambda receives a temporary session for its role. DynamoDB evaluates direct actions and each affected table in supported batch, transaction, and PartiQL operations. The workflow with and without `dynamodb:PutItem` permission has been tested; this does not establish compatibility with all AWS policies.

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
| `LOCALLYCLOUD_PG_BIN_DIR` | PostgreSQL binaries for RDS | Found on `PATH`, then the newest under `/usr/lib/postgresql` |
| `LOCALLYCLOUD_COGNITO_MAILBOX_DIR` | Directory that receives Cognito confirmation codes | Disabled |

Requests reach one endpoint and are routed to the corresponding native service handler. Requests for services without a native handler may be forwarded to the configured external fallback backend. Check `/_locallycloud/status` to distinguish native services from proxied services.

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

For the default data, cache, and temporary compute locations, an optional full reset is:

The Lambda runtime cache contains read-only directories, so restore write permission before removing the cache; otherwise `rm -rf` leaves files behind with `Permission denied`.

```sh
# Destructive: run only after stopping LocallyCloud and reviewing these paths.
rm -rf -- "${XDG_DATA_HOME:-$HOME/.local/share}/locallycloud"
chmod -R u+w -- "${XDG_CACHE_HOME:-$HOME/.cache}/locallycloud"
rm -rf -- "${XDG_CACHE_HOME:-$HOME/.cache}/locallycloud"
rm -rf -- "${TMPDIR:-/tmp}/locallycloud-lambda-$(id -u)" \
  "${TMPDIR:-/tmp}/locallycloud-oci-$(id -u)" \
  "${TMPDIR:-/tmp}/locallycloud-ecs-$(id -u)" \
  "${TMPDIR:-/tmp}/locallycloud-firecracker-$(id -u)"
```

If you customized `LOCALLYCLOUD_STATE_DB`, `LOCALLYCLOUD_RDS_DATA_DIR`, or `LOCALLYCLOUD_WORK_DIR`, inspect those locations separately. RDS Data API state is stored under `rds-data` next to the configured state database; RDS databases use their own configured directory. For a custom SQLite file, include its `-wal` and `-shm` sidecars if present, without deleting unrelated files in the parent directory. An EC2 root filesystem supplied through `LOCALLYCLOUD_EC2_IMAGE_ROOTFS` belongs to you and is not removed by uninstalling.

Remove any user service, shell startup entries, or saved master-key file you created specifically for LocallyCloud. Clear session variables if needed:

```sh
unset AWS_PROFILE LOCALLYCLOUD_KMS_MASTER_KEY
```

Do not delete `~/.aws`, your PostgreSQL installation, or shared runtime directories as part of this cleanup. Package-manager removal or Debian `purge` does not erase these user data locations.

## Beta limitations

- Operations and resource types are partial. Check both the response and the local effect for the workflows your application depends on.
- Persistence varies by service. Preserve the state directory and KMS master key; verify restart behavior for your workflow. Cognito, EC2/VPC, ECS, ECR, Elastic Load Balancing, Route 53, CloudFront, WAF v2, CloudTrail, X-Ray, Glue, Athena, ARC, and Region Switch resources do not yet survive a restart. See [Will my resources survive a restart?](docs/FAQ.md#will-my-resources-survive-a-restart)
- On some virtual machines, such as CI runners, startup can take seconds instead of milliseconds while the cryptography library gathers entropy.
- Regional failover requires starting a plan manually. Automatic failure detection and recovery without data loss are not implemented.
- Local load testing can help find application bottlenecks, but results reflect your machine, not AWS quotas, scale, or performance.
- Use test data. This beta does not provide AWS security, availability, or durability guarantees and should not store sensitive data.

## Development and releases

From the repository root:

```sh
cargo fmt --all -- --check
cargo test --locked -p locallycloud-core -p locallycloud-state --lib
bash scripts/check-package-version.sh
```

These are the core checks used by CI; they do not cover every service integration. The external test directory is not required to build or run the emulator. Repository documentation is written in English.

The product version lives in `Cargo.toml`. Debian and Arch derive their package versions from it, and pushing a matching Git tag publishes release artifacts after CI passes. See [Versioning and packages](packaging/VERSIONING.md) for the release procedure and [Brand assets](packaging/assets/README.md) for logo exports.

## Project and license

LocallyCloud is a [Zento Studio Labs](https://zentostudio.com) project.

Released under the [Apache License 2.0](LICENSE.md).

Copyright © 2026 Alfred Rodriguez G.
