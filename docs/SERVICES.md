# Available services

[← README](../README.md) · [Setup](SETUP.md) · [Lambda](LAMBDA.md) · [Threat modeling](THREAT_MODELING.md) · [Platforms](PLATFORMS.md) · [Throttling](THROTTLING.md) · [FAQ](FAQ.md)

[📦 Service catalog](#available-services) · [🔌 Compatibility](#tool-compatibility) · [⚡ Compute limits](#compute-and-networking-limits) · [💾 Persistence](#persistence-and-limits)

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

Strict IAM supports `ForAnyValue`/`ForAllValues` for supported operators and
`kms:ResourceAliases` in native integrations. Unsupported operators are rejected.

### CloudFormation

Supports Lambda `Architectures`, [logging](LAMBDA.md#logging), Lambda-backed custom
resources, rollback, live resource progress and paginated `ListChangeSets`.
Install custom-resource runtimes before deployment; missing callbacks wait until
`ServiceTimeout`.

`Code.ZipFile` accepts Node.js/Python source in `index.js`/`index.py`, with an
`index.<export>` handler. Source and ZIP are each limited to 4 MiB;
`cfn-response` is not bundled. Historical change-set execution status is inferred
from the current stack state.

### Athena and DuckDB

The built-in reader supports single-table SELECTs. DuckDB adds bounded joins,
subqueries, `IN`, `GROUP BY`, `HAVING` and `ORDER BY` over authorized Glue Iceberg
snapshots. CTEs, UNION, table functions and non-SELECT statements are unsupported;
functions and result types are restricted. Queries are limited to one statement
and 256 KiB, with bounded scans, results and execution time.

See [DuckDB preparation](SETUP.md#duckdb).

### API Gateway mapping templates

REST API integrations support a bounded VTL subset: `#set`, `#if`/`#elseif`/`#else`,
`#foreach`, line comments, references, double-quoted interpolation, comparisons,
boolean operators, `+`, `-` and `%`.

String methods: `isEmpty`, `toLowerCase`, `startsWith`, `split`, `length`,
`substring` and `replaceAll`. Map/list methods: `isEmpty`, `size`, `get`, `keySet`,
`containsKey` and `remove`, as appropriate to the value type. Utilities include
escaping, URL/base64 encoding, JSON parsing and `$util.qr`.

Templates are limited to 300 KiB; rendered output, concatenation and string
method results to 1 MiB, with bounded nesting and work. Unknown constructs fail
with HTTP 500 and log the mapping phase and error category. This is not a full Velocity/Java implementation: regex features
such as lookaround/backreferences are rejected, and assigned collections are
copied rather than shared aliases. Direct/nested variable `remove` mutations
are supported. A regression test covers request and response mapping to a Step
Functions EXPRESS workflow with application templates; validate the rest of your
application separately.

## Compute and networking limits

The ECS/Fargate reference supports one container and one TCP application port per
task, IPv4 `awsvpc`, service desired count 0–2, and an internal HTTP ALB with IP
targets. Target registration, health checks, replacement and draining are integrated.
HTTPS listeners, host/path rules, multi-container tasks, IPv6 and UDP application
traffic are outside that reference. Validate additional consumer requirements separately.

## Persistence and limits

Keep the state directory and KMS master key across restarts. Glue catalog entries,
ECR images, EC2/VPC topology, ECS configuration and ALB configuration are persisted.
Desired ECS services reconcile with fresh processes; EC2 instances restore as stopped
and require explicit `StartInstances` (one ID per request). `StopInstances` is not
implemented. Live sockets and health state are rebuilt.

Persistence varies elsewhere; see the [restart reference](FAQ.md#will-my-resources-survive-a-restart).
Regional failover is manual. Local load results reflect your workstation rather than
AWS scale, quotas or performance. See [throttling and backpressure](THROTTLING.md)
for supported simulations and gaps. Use test data; LocallyCloud provides no AWS security,
availability or durability guarantees.
