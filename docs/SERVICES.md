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

STS `AssumeRole` checks the role's trust policy, caller permissions and conditions,
including `ExternalId`, before issuing credentials. Session duration respects the
role limit and the one-hour role-chaining limit. Inline session policies are supported;
managed session policy ARNs, session tags, source identity and MFA verification are
not implemented and are rejected. OIDC/SAML assertions are not verified; strict mode
denies their credential-issuing operations. Organizations SCPs are not evaluated.
MFA presence is absent for long-term keys and false for verified temporary sessions;
unverified MFA assertions are rejected. Time conditions use the evaluation clock,
including `aws:CurrentTime` and `aws:EpochTime`, rather than client-provided values.

Native IAM operations authorize the target ARN, including its path. Supported
conditions use the target's tags, requested tags, policy ARN and permissions
boundary. Creating tagged users, roles, policies or instance profiles also requires
the corresponding `Tag*` permission. Adding a role to an instance profile requires
`iam:PassRole` to EC2. Boundaries supplied when creating users or roles persist and
limit their permissions. Instance profile tags also persist across restarts.
IAM tag listings support `MaxItems` and `Marker` and return existing tags as stored.
Tag quota and character validation remain incomplete; Unicode tag-key case handling
is not fully validated.

Omitting `UserName` in `GetUser` or access-key operations requires verified,
long-term IAM user credentials. Supply `UserName` when using an assumed role or
delegated credentials. Root access-key administration is unsupported.

SSM and Step Functions evaluate supported resource and request tag conditions,
including `aws:TagKeys`. SSM also supports `ssm:resourceTag`; Step Functions execution
authorization uses the current state-machine tags. Creating a tagged state machine
or activity additionally requires `states:TagResource`.

In strict mode, Lambda and SQS compose supported identity and resource policies;
service-principal delivery requires a matching resource grant. KMS key policies must
grant the caller or delegate to IAM. An identity policy alone does not override an
explicit key policy that excludes the caller.
Lambda resource policies are scoped to the function, version or alias ARN; existing
unqualified policies are preserved. Cross-account Lambda references, deleting an
individual version and unsupported permission restrictions return explicit errors.
They do not fall back to the unqualified function or silently widen a grant.
Tags apply to an unqualified function ARN. Qualified tag mutations return an
invalid-parameter error; listing tags through a version or alias ARN is unsupported.

### EventBridge and ECR authorization

In strict mode, EventBridge applies supported event-bus policies to `PutEvents`.
Caller-published sources beginning with `aws.` fail per entry; the verified native
S3 producer can publish its own bucket events. `PutPartnerEvents` is explicitly
unsupported in strict mode because partner event-source ownership is not modeled.
Use a full supported policy document for `PutPermission`; its abbreviated
`Condition` form is unsupported rather than ignored. Cross-account event-bus
routing remains unsupported.

API destinations do not follow redirects, including OAuth token endpoint redirects.
Destination requests time out after five seconds. Delivery retries `401`, `407`,
`409`, `429` and `5xx`; other `3xx` and `4xx` responses are terminal.

ECR registry tokens retain their issuing identity. Registry operations recheck
repository permissions, identity denies, boundaries and session limits. Repository
policy APIs support the shared policy evaluator. As a conservative limitation, a
token is denied once its issuing STS session expires or its credential can no
longer be resolved, even before the token's advertised twelve-hour expiration.
Aborting a registry upload has no mapped IAM operation and is unsupported in strict
mode. These limits prevent a token from bypassing permissions.

### CloudFormation

Supports Lambda `Architectures`, [logging](LAMBDA.md#logging), Lambda-backed custom
resources, rollback, live resource progress and paginated `ListChangeSets`.
Install custom-resource runtimes before deployment; missing callbacks wait until
`ServiceTimeout`.

IAM role creation forwards `PermissionsBoundary` and `Tags` in the same authorized
`CreateRole` call. Updating either property on an existing role is currently rejected.

A stack's `RoleARN` is persisted and used for creation, updates and deletion.
Assigning a role requires `iam:PassRole` and trust for `cloudformation.amazonaws.com`.
An operator allowed to manage an existing stack can reuse its assigned role without
PassRole; scope stack-management permissions accordingly. Change sets retain the
validated role assignment. Legacy change sets require assignment validation before
activating a role that earlier versions ignored.

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

### API Gateway endpoints and custom domains

Use the dashboard's stage link, or these local URL formats:

| API | URL |
| --- | --- |
| REST | `https://aws.localhost:4566/restapis/<api-id>/<stage>/_user_request_/<path>` |
| HTTP | `https://aws.localhost:4566/execute-api/<api-id>/<stage>/<path>`; use literal `$default` for the default stage |

API IDs resolve in the instance account and owning region. AWS-shaped `ApiEndpoint`
metadata is not a local connection address.
HTTP proxy integrations preserve the backend's status, headers and body, including
redirect responses; API Gateway does not fetch the redirect target. HTTP integrations
generate `Content-Length` from the final outbound body, including mapped REST payloads.
REST HTTP integrations omit the caller's `Authorization` header when it carries a
SigV4 signature or the REST method uses `AWS_IAM`; other authorization schemes
remain available to the configured backend. This rule does not change HTTP API
or Lambda integration headers. REST `AWS_IAM` invocation itself remains unsupported.
In strict IAM mode, REST API resource policies restrict invocation using the
policy captured by the stage's deployment. Deploy again after editing a policy.
Methods with `NONE` authorization require an explicit resource-policy allow when
a policy is present; IAM credentials do not authenticate these methods. Explicit
resource-policy denies run before Lambda authorizers. Supported policy conditions
use verified peer IP and TLS metadata, not forwarding headers. Unsupported policy
features are rejected. REST deployments saved before policy snapshots were added
must be recreated; their original policy cannot be reconstructed.

For REGIONAL REST or HTTP custom domains:

1. Import a valid RSA certificate and its unencrypted PKCS#8 private key into ACM
   in the API's region.
2. Create the domain and base-path/API mapping through the CLI, CloudFormation or
   supported SAM `HttpApi.Domain` configuration. HTTPS uses the configured port;
   plain HTTP requires `LOCALLYCLOUD_ALLOW_HTTP=true`.
3. Create a Route 53 Alias A/AAAA record using the domain's regional target and hosted-zone ID.
   Set `LOCALLYCLOUD_ROUTE53_DNS_BIND=127.0.0.1:1053` and configure your OS resolver
   to send only the development domain to that endpoint.

For a self-signed certificate, use `--cacert`; keep certificate verification enabled.
To test HTTPS while bypassing DNS:

```sh
curl --resolve api.example.test:4566:127.0.0.1 --cacert certificate.pem https://api.example.test:4566/shop/orders
```

LocallyCloud does not change OS DNS or certificate trust. ACM imports persist
encrypted with the state key; detach domains before deleting their certificates.
Use distinct domain names across accounts and regions. EDGE endpoints, automatic
ACM issuance, certificate chains, mutual TLS and wildcard domains are unsupported.
Authorizers and private-domain restrictions still apply; private custom domains
have no TLS data plane.

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

Native IPv4 VPC topology, subnet and security group tags, route tables, NAT gateways
and endpoint configuration survive restarts. The default security group's self rule
can be revoked. Security group permission batches are validated before one atomic
write. Gateway endpoints support S3 and DynamoDB; Interface endpoints support SSM,
Secrets Manager, Logs, STS, SQS and KMS. Interface access uses the existing subnet and
security group model, without dedicated endpoint ENIs. NACLs, VPC peering and IPv6 are
not implemented. Validate the actual guest traffic required by your application.

The ECS/Fargate reference supports one container and one TCP application port per
task, IPv4 `awsvpc`, service desired count 0–2, and an internal HTTP ALB with IP
targets. Target registration, health checks, replacement and draining are integrated.
`RunTask` accepts one private subnet and one task per request.
HTTPS listeners, host/path rules, multi-container tasks, IPv6 and UDP application
traffic are outside that reference. Validate additional consumer requirements separately.

## Persistence and limits

Keep the state directory and KMS master key across restarts. The [restart reference](FAQ.md#will-my-resources-survive-a-restart)
lists persisted resources, process-local services and workload recovery behavior.
Regional failover is manual. Local load results reflect your workstation rather than
AWS scale, quotas or performance. See [throttling and backpressure](THROTTLING.md)
for supported simulations and gaps. Use test data; LocallyCloud provides no AWS security,
availability or durability guarantees.
