# Frequently asked questions

Practical answers for using LocallyCloud during the beta. Start with the [installation and quick-start guide](../README.md#installation) if this is your first visit.

- [Getting started](#getting-started)
- [AWS profiles and connections](#aws-profiles-and-connections)
- [Compatibility and services](#compatibility-and-services)
- [Troubleshooting](#troubleshooting)
- [Feedback and releases](#feedback-and-releases)

## Getting started

### What can I use LocallyCloud for?

Develop and test AWS application workflows locally, including serverless functions, events, messaging, storage, and data integrations. For example, you can test S3 → Lambda → SQS or EventBridge → Step Functions → DynamoDB without creating those resources on AWS.

### Which operating systems are supported?

LocallyCloud runs on Linux. It is developed on Arch Linux `x86_64` and packaged as a `.deb` for Debian 13, Ubuntu 24.04 LTS and 26.04 LTS, and distributions based on them, on `amd64` and `arm64`. WSL 2 on Windows works with the same `.deb`. Native Windows and macOS are not supported; run LocallyCloud in a Linux virtual machine and forward its port to `127.0.0.1:4566` on the host. [Supported platforms](PLATFORMS.md) describes the support levels, the glibc 2.39 requirement, WSL 2 setup, and the virtual-machine setup.

### Do I need Docker?

No Docker daemon is required to run LocallyCloud. The server runs as a Rust binary. Workflows that execute isolated compute, such as Lambda invocations, require `crun` or `youki`; ordinary service requests do not require that runtime. See [Optional runtime dependencies](../README.md#optional-runtime-dependencies).

### Do I need Rust or SQLite when installing a package?

Rust is needed to build from source, not to run an installed package. The Debian package includes SQLite in the binary. The Arch package uses SQLite from the system repositories and requires version 3.53.4 or later. A source build also requires SQLite 3.53.4 or later, its development files, and a native build toolchain.

### Can an LLM agent use LocallyCloud without administrator privileges?

Yes. Run the emulator as a regular user and use the `locallycloud` AWS profile from the agent's CLI or SDK client. Installing a system package with `apt` or `pacman` requires administrator privileges; [user-only installation](../README.md#user-only-installation-without-sudo) puts the executable in your home directory instead. Dependencies and optional host features must already be available or prepared separately.

### How do I uninstall it, and are my resources deleted?

Stop the emulator, then remove the system package with `sudo apt remove locallycloud` or `sudo pacman -R locallycloud`. For a user-only installation, remove its executable and any dedicated extraction directory. User state, the master key, and AWS profiles are preserved unless you delete them explicitly. The [uninstallation guide](../README.md#uninstallation) lists the exact default and custom data locations and optional cleanup steps.

### Where is the dashboard?

With the server running at its default address, open [http://127.0.0.1:4566/_locallycloud/ui](http://127.0.0.1:4566/_locallycloud/ui). The application-menu launcher opens this URL; it does not start the server.

Select an account/profile and region to inspect resources. The active-service filter uses existing resources. Read-only explorers include DynamoDB items, S3 objects, Lambda, Step Functions, SQS, CloudWatch Logs, EventBridge buses/rules/targets, SNS topics/subscriptions, API Gateway APIs and CloudFormation stacks/resources/events. Lists offer continuation when another page exists; configured log and resource links help investigate errors. Resource status alone does not confirm an entire application workflow succeeded.

In strict IAM mode, recent activity diagnostics also require `cloudtrail:LookupEvents` on `*`. A denied diagnostic view does not mean the emulator is offline; resource explorers still use their own service permissions.

### How do I encrypt objects created by an older version?

New S3 object bodies and uploaded parts use encrypted storage. Older objects remain readable in permissive mode and are identified as `legacy-plaintext` in the `x-locallycloud-storage-format` response header until migrated. Stop the server, retain its original `LOCALLYCLOUD_KMS_MASTER_KEY`, and run `locallycloud migrate-s3-encryption` with the same state configuration. Restart after the command succeeds. Rerunning resumes remaining buckets; keep your original master key to reopen encrypted data. Customer KMS policies still apply to migration. Migrate legacy SSE-KMS objects before reading them with strict IAM or a delegated service role.

## AWS profiles and connections

### What URL do I use to invoke API Gateway?

Open the API in the dashboard and use the local link beside its stage. REST APIs use `http://127.0.0.1:4566/restapis/<api-id>/<stage>/_user_request_/<path>`; HTTP APIs use `http://127.0.0.1:4566/execute-api/<api-id>/<stage>/<path>`, including the literal `$default` stage. Existing API IDs resolve within the instance account and their owning region. AWS-shaped `ApiEndpoint` metadata is not a local connection address.

REGIONAL REST and HTTP custom domains use ACM certificates, TLS SNI and their base-path/API mappings. Import a valid RSA certificate and its unencrypted PKCS#8 private key into ACM in the API region, then create the domain and mapping through the AWS CLI, CloudFormation or supported SAM `HttpApi.Domain` configuration. HTTP and HTTPS share the configured port (default `4566`); invoke `https://api.example.test:4566/shop/orders`. For a local self-signed certificate, configure client trust, for example `curl --cacert certificate.pem https://api.example.test:4566/shop/orders`; do not disable certificate validation. Imported certificates and their private keys are stored encrypted in the state database and survive a restart with the same master key. Associated certificates cannot be deleted until their domains are removed.

Create a Route 53 Alias A/AAAA record using the domain’s regional target and hosted-zone ID. To serve these records locally, start with `LOCALLYCLOUD_ROUTE53_DNS_BIND=127.0.0.1:1053` and configure your operating-system resolver to send only your development domain to that DNS endpoint. LocallyCloud does not change system DNS or certificate trust. A temporary `curl --resolve api.example.test:4566:127.0.0.1 --cacert certificate.pem https://api.example.test:4566/shop/orders` checks HTTPS but bypasses DNS. Use distinct custom domain names across accounts and regions; duplicate bindings on the single listener are rejected. EDGE endpoints, automatic ACM issuance, certificate chains, mutual TLS and wildcard custom domains are not implemented. API authorizers and private-domain restrictions still apply; private custom domains do not provide this TLS data plane.

### Do I need to include the endpoint and port in every command?

No. Save them once in the `locallycloud` AWS CLI v2 profile. In `~/.aws/config`:

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

Then use only the profile selector:

```sh
aws --profile locallycloud sts get-caller-identity
aws --profile locallycloud s3 ls
```

The profile stores the endpoint, including its port, and the region. Keep your other profiles when adding these entries. See [Local AWS profile](../README.md#local-aws-profile) for setup commands and configuration precedence.

### Can I make LocallyCloud the default for my terminal?

Yes:

```sh
export AWS_PROFILE=locallycloud
aws s3 ls
```

With this profile selected, you do not need `--profile` or `--endpoint-url`. You can also use `[default]` in both AWS files for commands that do not select a named profile. That changes the default destination of requests using that configuration; a named profile keeps local and other environments easy to select separately.

### Do I need real AWS credentials?

The quick start uses local `test` credentials with the default permissive IAM mode. Real AWS credentials are not needed for that setup. Strict IAM testing uses locally configured bootstrap credentials and roles; see [Tool compatibility](../README.md#tool-compatibility).

### Why does a command ignore the profile endpoint?

Check for an explicit `--endpoint-url`, an `AWS_ENDPOINT_URL` or service-specific endpoint variable, and service-specific endpoints in AWS config. Higher-priority endpoint settings can override the profile's global endpoint. `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true` disables configured endpoints. Use a dedicated terminal with those overrides cleared when testing the profile.

AWS documents [endpoint configuration and precedence](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-endpoints.html). Selecting a profile configures the client; it does not start LocallyCloud or change the server's listening port.

## Compatibility and services

### Is LocallyCloud compatible with my AWS SDK or LocalStack setup?

AWS CLI and SDK clients can target the local endpoint for implemented AWS operations. Some `LOCALSTACK_*` configuration aliases and the `/_localstack/health` route are accepted. Plugins that depend on additional LocalStack-specific APIs may need changes. Compatibility depends on the operations your application uses; a local result should still be validated on AWS.

### Can I use Terraform, Serverless Framework, or AWS SAM?

Terraform with AWS provider 6.x has been tested with `apply`, a `plan` with no changes, a server restart, and `destroy` for common serverless resources (S3, SQS, SNS, DynamoDB, IAM roles, Lambda, KMS, SSM, Secrets Manager, CloudWatch Logs, EventBridge, HTTP APIs, Kinesis) and ECS clusters. Serverless Framework workflows with `serverless-localstack` have also been tested. SAM CLI 1.166.2 has been tested with `sam deploy` for HTTP API → Lambda ZIP → DynamoDB SimpleTable, including creation, updates, deployment without changes, and cleanup. This is workflow-level compatibility, not complete support for every feature. See the [compatibility table](../README.md#tool-compatibility).

### Are all AWS operations supported for listed services?

No. Services implement subsets of AWS behavior. Review the [service overview](../README.md#available-services) and verify the operations your application needs. Inspect registered services with:

```sh
curl -fsS http://127.0.0.1:4566/_locallycloud/status
```

The status distinguishes native handlers from proxied services. A proxied service depends on the configured external fallback backend; its name appearing in the registry does not mean LocallyCloud implements it natively.

### How do I sign up and sign in Cognito users locally?

LocallyCloud does not send email or SMS. To receive confirmation codes, start the emulator with `LOCALLYCLOUD_COGNITO_MAILBOX_DIR` set to an absolute directory owned by your user with mode `0700`; each code is written there as a JSON file. Supported flows:

- `SignUp` → `ConfirmSignUp` with the code from the mailbox (or `AdminConfirmSignUp`) → `InitiateAuth` with `USER_PASSWORD_AUTH`.
- `AdminCreateUser` with a temporary password and `MessageAction=SUPPRESS` → `AdminInitiateAuth` with `ADMIN_USER_PASSWORD_AUTH` → `AdminRespondToAuthChallenge` for `NEW_PASSWORD_REQUIRED`. With `InitiateAuth`, answer with `RespondToAuthChallenge`.

Current limitations: `AdminCreateUser` without `MessageAction=SUPPRESS` is rejected, `ListUserPoolClients` requires `--max-results`, SRP authentication is not implemented, and user pools do not survive a restart.

### Can I test multi-region recovery or load?

DynamoDB Global Tables MREC supports eventual replication. Local ARC, Region Switch, and Route 53 support implemented manual recovery workflows. Automatic failure detection and recovery without data loss are not implemented. Load testing can expose application bottlenecks, but results reflect your host rather than AWS quotas, scale, or performance.

## Troubleshooting

### The server does not start. What should I check first?

Read the startup error and check these requirements:

- `LOCALLYCLOUD_KMS_MASTER_KEY` contains a base64-encoded 32-byte key.
- The state directory is owned by the current user, has private permissions, and is not a symlink.
- The linked SQLite version is 3.53.4 or later.
- The configured listen address and port are available.

If you set `LOCALLYCLOUD_STATE_DB`, use an absolute path to a SQLite file, not a directory. Startup errors should identify which requirement failed. Follow the [quick start](../README.md#quick-start) before adding optional integrations.

### Why does KMS fail after a restart?

Encrypted state requires the same master key used to create it. An environment variable does not survive closing a terminal unless you load it again. Restore your original `LOCALLYCLOUD_KMS_MASTER_KEY`; generating a replacement does not recover data encrypted with the previous key. Keep the key outside the repository and reuse it with the same state directory.

### The server runs, but Lambda, ECS, or EC2 execution fails. Why?

The control plane can start without an isolated compute runtime. Check that `crun` or `youki` is available in `PATH` and supported by your Linux host. OCI execution also requires a systemd user session with a user D-Bus and delegated cgroup v2 memory control; it applies the configured guest memory limit without using host swap. ZIP-based Node.js or Python Lambda functions require the executable for the declared language runtime. See [Optional runtime dependencies](../README.md#optional-runtime-dependencies).

### Why does Lambda report D-Bus errors and then TooManyRequestsException on Debian?

Minimal Debian installations may lack the user D-Bus session needed by the current OCI runtime. Install the optional dependencies:

```sh
sudo apt install crun dbus-user-session
```

Log out and log back in, or reboot, and verify the user session with `systemctl --user status dbus`. The host must also delegate cgroup v2 memory control to that session. Start LocallyCloud without `sudo`. The `.deb` recommends `dbus-user-session`, so `apt` installs it by default; it is missing if recommended packages were skipped or the system was installed from a minimal or cloud image. `crun` is never installed automatically. On WSL 2, systemd must also be enabled; see [Supported platforms](PLATFORMS.md#wsl-2).

On Debian 13 with `crun` 1.21, a failed guest launch can retain its local memory reservation. Repeated attempts then report `TooManyRequestsException` with a memory-budget error even though no guest is running; with the default budget this starts after about six failures. This is a known beta issue, not proof that a running Lambda consumed all available RAM. After resolving the session requirements, restart LocallyCloud with the same state database and `LOCALLYCLOUD_KMS_MASTER_KEY`; do not delete the state or generate a replacement key. Raising the budget only postpones the failure. See [Debian OCI execution](../README.md#debian-oci-execution).

### RDS cannot start a PostgreSQL database. What is missing?

Install PostgreSQL 16 or later from your distribution, preferably the newest version it provides: `sudo apt install postgresql` on Debian and Ubuntu, or `sudo pacman -S postgresql` on Arch. `initdb`, `pg_ctl`, `postgres`, `psql`, and `pg_basebackup` must belong to the same version. LocallyCloud finds them on `PATH` or, on Debian and Ubuntu, under `/usr/lib/postgresql/<version>/bin`, choosing the newest supported version. To use another installation, set `LOCALLYCLOUD_PG_BIN_DIR` to its `bin` directory before starting LocallyCloud.

LocallyCloud starts its own local databases. RDS Data API workflows that access those databases need the same PostgreSQL setup.

### Will my resources survive a restart?

Persistence varies by service and operation. Preserve the state directory and the KMS master key, and test restart behavior for your specific workflow. This beta is intended for test data.

These survive a restart with the same database and master key:

- S3 buckets and objects, DynamoDB tables and items, SQS queues and messages, SNS topics and subscriptions.
- EventBridge buses, rules, Scheduler, Pipes, and Schemas; Step Functions definitions and history.
- Lambda code, configuration, versions, layers, and event source mappings.
- IAM identities and valid STS sessions, KMS keys, SSM parameters, Secrets Manager secrets.
- CloudWatch Logs, CloudWatch metric alarms, Kinesis streams, Firehose delivery streams.
- API Gateway configuration and custom domains, imported ACM certificates and keys.
- CloudFormation stacks, change sets, and deleted-stack history.
- RDS instances, clusters, and snapshots, stored with their PostgreSQL data directories.

Interrupted Step Functions executions become `ABORTED`; they are not automatically replayed. Cognito user pools, EC2/VPC, ECS, ECR, Elastic Load Balancing, Route 53, CloudFront, WAF v2, CloudTrail, X-Ray, Glue, Athena, ARC, and Region Switch resources are still process-local. Recreate or reconcile them after a restart before using resources that depend on them; for example, `terraform plan` proposes to recreate an ECS cluster after a restart.

S3 metadata from earlier versions is migrated automatically on startup. Earlier binaries cannot read the upgraded state. This metadata upgrade is separate from the explicit migration of legacy plaintext object bodies.

### How can I tell whether the server is reachable?

```sh
curl -fsS http://127.0.0.1:4566/_locallycloud/health
aws --profile locallycloud sts get-caller-identity
```

If you configured a different address or port, update both the health-check URL and the AWS profile endpoint. A successful health check confirms HTTP reachability; the STS request also checks the client profile and AWS request path.

### How is Lambda memory usage limited?

The guest limit follows the function's `MemorySize`. The local Lambda environment budget defaults to 1,024 MiB and includes each active or warm guest's configured memory plus 32 MiB of estimated host overhead. Set `LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB` before startup to adjust it; invalid or zero values disable invocation with a startup diagnostic. When no environment fits, Lambda returns `TooManyRequestsException`. This budget accounts for Lambda environments, not total server RSS, stored resources, EC2 or ECS.

Compute output is bounded and read incrementally. Logs exceeding a capture limit include an explicit dropped-output notice. Work files default to the per-user cache; use `LOCALLYCLOUD_WORK_DIR` to select another location. Putting work files on tmpfs consumes RAM.

### Does deleting a stack remove its logs and runtime files?

Managed log groups follow their `DeletionPolicy`; retained groups are preserved. As in AWS, deleting a Lambda does not automatically delete its independently created default log group. CloudFormation reports an existing associated group when it remains outside stack management. Deleted stack history is available by stack ID in the dashboard, including retained resources and cleanup reasons. Cleanup failures keep resource identity and expose `DELETE_FAILED` for retry. Managed log groups are removed after their producers finish cleanup. Step Functions deletion waits for active execution workers; a stack cleanup timeout remains visible for retry. Deleted-stack history is stored in the state database and survives a restart.

Runtime cleanup confirms termination before releasing buffers, connections, root filesystems and bundles. Shared language/PostgreSQL runtime caches remain reusable; they are not stack-owned resources.

## Feedback and releases

### Where do I report a bug or request an operation?

Open an issue in this repository. Include:

- The LocallyCloud release tag or source commit, your Linux distribution and version, and the architecture (`uname -m`), including whether it runs in WSL 2 or a virtual machine.
- The CLI, SDK, or deployment-tool version you used.
- The service and operation, plus a small reproducible command or example.
- Expected behavior, actual behavior, and relevant error output.
- Any required runtime, PostgreSQL, or configuration details.

Use test data and remove credentials, tokens, signatures, master keys, and sensitive payloads from reports. For an unsupported operation, describe the workflow it would enable.

### Where do packages come from, and how are versions named?

The GitHub Actions workflow builds `.deb` packages for `amd64` and `arm64` and an Arch package for `x86_64`, installs each `.deb` with `apt` on Debian 13, Ubuntu 24.04, and Ubuntu 26.04, and publishes the packages with `SHA256SUMS` when a matching Git tag passes those checks. Alpha, beta, and rc tags publish prereleases. AUR and an APT repository need separate publication setup; they are not automatically populated by the workflow.

For example, `v0.1.0-beta.1` is a beta tag and `v0.1.0` has no prerelease suffix. See [Versioning and packages](../packaging/VERSIONING.md) for package formats, checksums, and release steps. Beta releases should be found through the releases list or their specific tag, rather than `/releases/latest`.

### Where can I find the license?

The project's license is [Apache License 2.0](../LICENSE.md).
