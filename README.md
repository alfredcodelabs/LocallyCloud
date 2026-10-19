# LocallyCloud

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="packaging/assets/locallycloud-wordmark-light.svg">
  <img src="packaging/assets/locallycloud-wordmark.svg" alt="LocallyCloud" width="358" height="62">
</picture>

**Local AWS workflows. One endpoint. No Docker daemon.**

Develop and test serverless applications, event pipelines and data workflows on
Linux using your AWS CLI or SDK clients.

[Quick start](#quick-start) · [Services](docs/SERVICES.md) · [Documentation](#documentation)

> [!NOTE]
> Beta for local development and testing. Services implement subsets of AWS
> operations; validate your application on AWS before deploying it.

## Installation

Download a package from [GitHub Releases](https://github.com/alfredcodelabs/LocallyCloud/releases)
for your architecture, then install it with your package manager:

```sh
# Debian 13 / Ubuntu 24.04 or 26.04 (example: amd64)
sudo apt install ./locallycloud_0.1.0.beta.3-1_amd64.deb

# Arch Linux (example: x86_64)
sudo pacman -U ./locallycloud-0.1.0beta.3-1-x86_64.pkg.tar.zst
```

Use the filename you downloaded. **Run LocallyCloud as your regular user, without
`sudo`.** See [supported platforms](docs/PLATFORMS.md) and
[installation options](docs/SETUP.md#installation), including user-only installation.

To build from source, install Rust 1.95.0+, SQLite 3.53.4+, a C/C++ toolchain,
CMake and pkg-config, then run:

```sh
cargo build --release --locked -p locallycloud
```

The executable is `target/release/locallycloud`.

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

AWS CLI reads the endpoint and port from the profile. Subsequent requests only need `--profile locallycloud`; you do not need to repeat `--endpoint-url`, credentials, or the region. See [Local AWS profile](docs/SETUP.md#local-aws-profile) for the equivalent config files and how to make this the default profile.

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

One local endpoint for your AWS workflows.

| ⚡ Compute | 📦 Storage & data | 🔀 Events & workflows |
| --- | --- | --- |
| Lambda · ECS/Fargate · EC2 | S3 · DynamoDB · RDS | SQS · SNS · EventBridge |
| ECR | Kinesis · Firehose | Step Functions |

**[Explore all services and compatibility →](docs/SERVICES.md)**

## Configuration

The default endpoint is `http://127.0.0.1:4566`; the default region is `us-east-1`.
State is encrypted with the required `LOCALLYCLOUD_KMS_MASTER_KEY`. Keep the same
key and state directory when restarting.

The server starts without a compute backend. Executing Lambda, ECS or EC2 requires
host runtime tools; RDS requires PostgreSQL. See [runtime dependencies](docs/SETUP.md#optional-runtime-dependencies)
and the [environment variable reference](docs/SETUP.md#configuration).

## Documentation

- [Setup and configuration](docs/SETUP.md): installation, AWS profiles, variables and uninstallation.
- [Available services](docs/SERVICES.md): compatibility, persistence and principal limits.
- [FAQ](docs/FAQ.md): usage and troubleshooting.
- [Supported platforms](docs/PLATFORMS.md): Linux distributions, architectures, WSL 2 and VMs.
- [Throttling](docs/THROTTLING.md): workstation-scale load and backpressure tests.

## Development and releases

Validate changes from the repository root, limiting parallel builds on a desktop:

```sh
cargo fmt --all --check
cargo clippy -j 4 --workspace --all-targets --locked -- -D warnings
cargo test -j 4 --workspace --locked
```

See [versioning and packages](packaging/VERSIONING.md) for releases,
[brand assets](packaging/assets/README.md) for logo exports and
[agent context](docs/AGENT_CONTEXT.md) for optional persistent project context.

## Project and license

LocallyCloud is a [Zento Studio Labs](https://zentostudio.com) project.
Released under the [Apache License 2.0](LICENSE.md).

Copyright © 2026 Alfred Rodriguez G.
