# Available services

[← README](../README.md) · [Setup](SETUP.md) · [Platforms](PLATFORMS.md) · [Throttling](THROTTLING.md) · [FAQ](FAQ.md) · [Agent context](AGENT_CONTEXT.md)

[📦 Service catalog](#available-services) · [🔌 Compatibility](#tool-compatibility) · [⚡ Compute limits](#compute-and-networking-limits) · [💾 Persistence](#persistence-and-beta-limits)

> [!NOTE]
> Services implement subsets of AWS operations. Check `/_locallycloud/status` for
> native handlers and proxied services; proxied requests need an external backend.

| Area | Services and APIs |
| --- | --- |
| 📦 Storage and messaging | S3, DynamoDB, DynamoDB Streams, SQS, SNS |
| ⚡ Compute and containers | Lambda, EC2/VPC, ECS/Fargate, ECR |
| 🌐 Networking and delivery | API Gateway REST and v2, Elastic Load Balancing v2, Route 53, CloudFront |
| 🔀 Events and workflows | EventBridge Events, Scheduler, Pipes, and Schemas; Step Functions |
| 🌊 Streaming and data | Kinesis Data Streams, Data Firehose, Glue, Athena, RDS, RDS Data API |
| 🔐 Identity and security | IAM, STS, KMS, Systems Manager, Secrets Manager, Cognito User Pools, Certificate Manager, WAF v2 |
| 🔎 Infrastructure and observability | CloudFormation, CloudWatch Logs and Metrics, CloudTrail, X-Ray |
| 🔄 Recovery | ARC configuration and routing controls, manual Region Switch |

Example workflows include S3 → Lambda → SQS, EventBridge → Step Functions → DynamoDB, and Kinesis → Firehose → S3. DynamoDB Global Tables MREC supports eventual replication; ARC can manually change a local Route 53 DNS target.

## Tool compatibility

Use LocallyCloud's endpoint with existing AWS tools. Compatibility is limited to tested workflows, not every feature of each tool.

| Tool | Tested scope |
| --- | --- |
| AWS CLI and SDKs | AWS wire protocols for implemented operations. |
| Terraform with the AWS provider | AWS provider 6.x: `apply`, `plan` with no changes, restart, and `destroy` for S3 buckets, SQS queues, SNS topics, DynamoDB tables, IAM roles, Lambda functions, KMS keys, SSM parameters, Secrets Manager secrets, CloudWatch log groups, EventBridge rules, HTTP APIs, Kinesis streams, and ECS clusters, plus specific integration workflows. |
| Serverless Framework with `serverless-localstack` | Specific integration workflows pointing at the local endpoint. |
| AWS SAM CLI 1.166.2 | `sam deploy` for HTTP API → Lambda ZIP → DynamoDB SimpleTable, including creation, deployment without changes, updates, and cleanup. |

CloudFormation also supports the bounded ECS service → internal HTTP ALB lifecycle, including desired-count updates and recovery after restart. This does not establish Terraform ECS service compatibility.

The SAM workflow supports explicit/implicit roles, S3-packaged `CodeUri`, HttpApi
events and supported `Globals.Function` defaults. Unsupported properties and resource
types are rejected; nonempty `Globals.HttpApi` settings are not supported.

Some `LOCALSTACK_*` configuration aliases and `/_localstack/health` are accepted. Other LocalStack plugins may require APIs that LocallyCloud does not implement.

IAM defaults to permissive mode. To test permissions, enable `LOCALLYCLOUD_IAM_ENFORCEMENT=strict` with bootstrap credentials. Lambda receives a temporary session for its role. DynamoDB evaluates direct actions and each affected table in supported batch, transaction, and PartiQL operations. The workflow with and without `dynamodb:PutItem` permission has been tested; this does not establish compatibility with all AWS policies.

## Compute and networking limits

The ECS/Fargate reference supports one container and one TCP application port per
task, IPv4 `awsvpc`, service desired count 0–2, and an internal HTTP ALB with IP
targets. Target registration, health checks, replacement and draining are integrated.
HTTPS listeners, host/path rules, multi-container tasks, IPv6 and UDP application
traffic are outside that reference. Validate additional consumer requirements separately.

## Persistence and beta limits

Keep the state directory and KMS master key across restarts. Glue catalog entries,
ECR images, EC2/VPC topology, ECS configuration and ALB configuration are persisted.
Desired ECS services reconcile with fresh processes; EC2 instances restore as stopped
and require explicit `StartInstances` (one ID per request). `StopInstances` is not
implemented. Live sockets and health state are rebuilt.

Persistence varies elsewhere; see the [restart reference](FAQ.md#will-my-resources-survive-a-restart).
Regional failover is manual. Local load results reflect your workstation rather than
AWS scale, quotas or performance. See [throttling and backpressure](THROTTLING.md)
for supported simulations and gaps. Use test data; the beta provides no AWS security,
availability or durability guarantees.
