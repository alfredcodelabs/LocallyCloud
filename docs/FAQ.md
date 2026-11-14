# Frequently asked questions

[← README](../README.md) · [Setup](SETUP.md) · [Services](SERVICES.md) · [Lambda](LAMBDA.md) · [Threat modeling](THREAT_MODELING.md) · [Platforms](PLATFORMS.md) · [Throttling](THROTTLING.md)

Practical answers for using LocallyCloud. Start with the [installation and quick-start guide](../README.md#installation) if this is your first visit.

[🚀 Getting started](#getting-started) · [🔌 Profiles](#aws-profiles-and-connections) · [📦 Compatibility](#compatibility-and-services) · [🔧 Troubleshooting](#troubleshooting) · [💬 Feedback](#feedback-and-releases)

## Getting started

### What can I use LocallyCloud for?

Develop and test AWS application workflows locally, including serverless functions, events, messaging, storage, and data integrations. For example, you can test S3 → Lambda → SQS or EventBridge → Step Functions → DynamoDB without creating those resources on AWS.

### Which operating systems are supported?

Linux, including supported WSL 2 distributions. On macOS or Windows without WSL,
use a Linux VM. See the [platform and architecture matrix](PLATFORMS.md#support-levels).

### Do I need Docker?

No Docker daemon is required to run LocallyCloud. The server runs as a Rust binary. Workflows that execute isolated compute, such as Lambda invocations, require `crun` or `youki`; ordinary service requests do not require that runtime. See [Optional runtime dependencies](SETUP.md#optional-runtime-dependencies).

### Do I need Rust or SQLite when installing a package?

Packages do not need Rust. The `.deb` bundles SQLite; Arch uses the system library.
See [source-build requirements](SETUP.md#from-source) if you compile it yourself.

### Can an LLM agent use LocallyCloud without administrator privileges?

Yes. Run the emulator as a regular user and use the `locallycloud` AWS profile from the agent's CLI or SDK client. Installing a system package with `apt` or `pacman` requires administrator privileges; [user-only installation](SETUP.md#user-only-installation-without-sudo) puts the executable in your home directory instead. Dependencies and optional host features must already be available or prepared separately.

### How do I uninstall it, and are my resources deleted?

[Remove the program with its installation method](SETUP.md#uninstallation).
State, master keys and AWS profiles remain until you explicitly remove them.

### Where is the dashboard?

Open [the dashboard](http://127.0.0.1:4566/_locallycloud/ui) after starting the server.
The application-menu launcher opens it but does not start the server.

Select an account/profile and region to browse resources and logs. Resource status
alone does not prove that an application workflow succeeded. In strict IAM mode,
recent activity also needs `cloudtrail:LookupEvents` on `*`; denial of that view
does not mean the server is offline.

### Can I threat-model my stack?

Yes. Open **Threat modeling** in the dashboard and choose a CloudFormation stack.
The diagram, flows and missing controls come from its deployed configuration, and
the review follows the four OWASP threat modeling questions. Decisions are saved as
a local JSON file. See [Threat modeling](THREAT_MODELING.md).

### How do I encrypt objects created by an older version?

New S3 object bodies and uploaded parts use encrypted storage. Older objects remain readable in permissive mode and are identified as `legacy-plaintext` in the `x-locallycloud-storage-format` response header until migrated. Stop the server, retain its original `LOCALLYCLOUD_KMS_MASTER_KEY`, and run `locallycloud migrate-s3-encryption` with the same state configuration. Restart after the command succeeds. Rerunning resumes remaining buckets; keep your original master key to reopen encrypted data. Customer KMS policies still apply to migration. Migrate legacy SSE-KMS objects before reading them with strict IAM or a delegated service role.

## AWS profiles and connections

### What URL do I use to invoke API Gateway?

Open the API in the dashboard and copy its stage link. See [local API endpoints
and custom domains](SERVICES.md#api-gateway-endpoints-and-custom-domains) for URL
formats, HTTPS and DNS setup.

### Do I need to include the endpoint and port in every command?

No. Save the endpoint, region and test credentials in the `locallycloud` AWS
profile, then use `aws --profile locallycloud <service> <command>`. See
[profile setup and precedence](SETUP.md#local-aws-profile).

### Can I make LocallyCloud the default for my terminal?

Run `export AWS_PROFILE=locallycloud`. Requests then use the saved endpoint and
credentials without `--profile`. See [profile setup](SETUP.md#local-aws-profile).

### Do I need real AWS credentials?

The quick start uses local `test` credentials with the default permissive IAM mode. Real AWS credentials are not needed for that setup. Strict IAM testing uses locally configured bootstrap credentials and roles; see [Tool compatibility](SERVICES.md#tool-compatibility).

### Why does a command ignore the profile endpoint?

An explicit endpoint, environment variable or service-specific setting may override
it. Check [profile precedence](SETUP.md#local-aws-profile). Selecting a profile
configures the client; it does not start the server or change its listening port.

## Compatibility and services

### Is LocallyCloud compatible with my AWS SDK or LocalStack setup?

AWS CLI and SDK clients can use the local endpoint for implemented operations.
See [compatibility scope](SERVICES.md#tool-compatibility) for LocalStack aliases
and plugin limitations.

### Can I use Terraform, Serverless Framework, or AWS SAM?

Yes, for specific tested workflows. See the [tool compatibility table](SERVICES.md#tool-compatibility)
for scope and versions; support is not complete for every tool feature.

### Are all AWS operations supported for listed services?

No. Services implement subsets of AWS behavior. Review the [service overview](SERVICES.md) and verify the operations your application needs. Inspect registered services with:

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

Compute dependencies are optional at startup but required when executing code.
Check the [host requirements](SETUP.md#optional-runtime-dependencies), including
OCI's systemd user session, D-Bus and cgroup delegation. ECS also needs the listed
networking tools. Lambda requires its [official runtime pack](LAMBDA.md);
installing a host interpreter does not replace it.

### Why does Lambda report D-Bus errors on Debian?

Minimal Debian installations may lack the user D-Bus session needed by the current OCI runtime. Install the optional dependencies:

```sh
sudo apt install crun dbus-user-session
```

Log out and back in, then check `systemctl --user status dbus`. Run LocallyCloud
without `sudo` in a session with delegated cgroup v2 memory control. APT may skip
recommended packages, so install them explicitly. For WSL, [enable systemd](PLATFORMS.md#wsl-2).

### Why does an API Gateway mapping return 500 before invoking its backend?

Check the server's mapping diagnostic: it identifies the request/response phase
and a parse, evaluation or unsupported-construct error. Bodies and interpolated
error details are not logged. Compare the template with the
[supported VTL subset](SERVICES.md#api-gateway-mapping-templates).

If mapping reaches Step Functions but execution fails, inspect the generated
workflow input. Templates that insert `$input.body` directly as JSON must handle
an empty request body; LocallyCloud does not replace it with `{}`.

### RDS cannot start a PostgreSQL database. What is missing?

Install its pack with `locallycloud runtime install postgres18` and check the
[OCI requirements and optional host-toolchain override](SETUP.md#optional-runtime-dependencies).
RDS Data API uses the same runtime and databases.

### Will my resources survive a restart?

Persistence varies by service and operation. Preserve the state directory and the KMS master key, and test restart behavior for your specific workflow. LocallyCloud is intended for test data.

These survive a restart with the same database and master key:

- S3 buckets and objects, DynamoDB tables and items, SQS queues and messages, SNS topics and subscriptions.
- EventBridge buses, rules, Scheduler, Pipes, and Schemas; Step Functions definitions and history.
- Lambda code, configuration, versions, layers, and event source mappings.
- IAM identities and valid STS sessions, KMS keys, SSM parameters, Secrets Manager secrets.
- CloudWatch Logs, CloudWatch metric alarms, Kinesis streams, Firehose delivery streams.
- API Gateway configuration and custom domains, imported ACM certificates and keys.
- CloudFormation stacks, change sets, and deleted-stack history.
- RDS instances, clusters, and snapshots, stored with their PostgreSQL data directories.
- Glue catalog databases and tables.
- ECR repositories and stored images, EC2/VPC topology, ECS clusters/task definitions/services, and ALB configuration.

Interrupted Step Functions executions become `ABORTED`; they are not automatically replayed. ECS desired services reconcile with new processes and rebuilt network leases; interrupted standalone tasks are not replayed. EC2 instances that were not terminated restore as stopped, retaining their configured primary ENI and private IP. Use `StartInstances` with one instance ID per request to start them explicitly; `StopInstances` is not implemented. ALB listeners and target health are rebuilt.

Cognito user pools, Route 53, CloudFront, WAF v2, CloudTrail, X-Ray, Athena, ARC, and Region Switch resources are still process-local. Recreate or reconcile them after a restart before using resources that depend on them.

S3 metadata from earlier versions is migrated automatically on startup. Earlier binaries cannot read the upgraded state. This metadata upgrade is separate from the explicit migration of legacy plaintext object bodies.

### How can I tell whether the server is reachable?

```sh
curl -fsS http://127.0.0.1:4566/_locallycloud/health
aws --profile locallycloud sts get-caller-identity
```

If you configured a different address or port, update both the health-check URL and the AWS profile endpoint. A successful health check confirms HTTP reachability; the STS request also checks the client profile and AWS request path.

### How is Lambda memory usage limited?

Each function has its own guest limit; environments share a separate host budget.
See [memory accounting](LAMBDA.md#memory-budget).

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

Tagged releases publish packages to [GitHub Releases](https://github.com/alfredcodelabs/LocallyCloud/releases)
after the build and installation checks pass. Alpha/beta/rc tags are prereleases;
AUR and APT publication are separate. See [versioning and release checks](../packaging/VERSIONING.md).

### Where can I find the license?

The project's license is [Apache License 2.0](../LICENSE.md).
