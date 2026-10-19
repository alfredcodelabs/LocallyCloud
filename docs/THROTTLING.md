# Throttling

[← README](../README.md) · [Setup](SETUP.md) · [Services](SERVICES.md) · [Platforms](PLATFORMS.md) · [FAQ](FAQ.md) · [Agent context](AGENT_CONTEXT.md)

Compare burst handling at workstation scale. Each service has independent limits;
there is no shared throttle across Lambda, DynamoDB and Kinesis.

[📊 Coverage](#coverage) · [🛠️ Configuration](#configuration) · [🔎 Diagnosis](#diagnosis) · [🧪 Before/after](#beforeafter-validation) · [📚 References](#aws-references)

## Coverage

| Service | Implemented | Not modeled / pending review |
| --- | --- | --- |
| Lambda | Account/region quota, function RC, unreserved pool and persistent reservations. All invocation paths share admission. | Scaling/request rates and the complete asynchronous retry window. |
| Step Functions | Standard/Express metrics, active count, ASL Retry/Catch and Standard open-execution quota. | Transition/API token buckets and `ExecutionThrottled`. |
| EventBridge classic | Async delivery, 185 retries/24-hour age, jittered backoff, time scaling and target DLQs. | Failures inside an accepted workflow are not retried. Restart may repeat the retry budget within the original age window. |
| SQS → Lambda | Adaptive pollers, rejection backoff, concurrency caps, partial acknowledgements and redrive. | Exact AWS scaling ramp and provisioned polling mode. |
| DynamoDB | Optional one-second table write windows, batch unprocessed entries and transaction cancellation. Limits use provisioned capacity or modeled warm throughput. | Read/GSI enforcement, hot partitions, burst/adaptive capacity, account quotas and throttling metrics. |
| Kinesis | Optional shard write windows and per-entry batch failures. | Read throttling, on-demand throughput and complete throttling observability. |

Coverage applies to native handlers. Proxied services depend on the external backend.
API Gateway, SNS, S3 and other services still need throughput review. Scheduler and Pipes
have separate retry policies.

## Configuration

| Variable | Default | Controls |
| --- | --- | --- |
| `LOCALLYCLOUD_LAMBDA_ACCOUNT_CONCURRENCY` | `1000` | Execution quota per account/region. |
| `LOCALLYCLOUD_LAMBDA_MIN_UNRESERVED_CONCURRENCY` | `100` | Minimum capacity left by function reservations. |
| `LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB` | `1024` | Host budget for Lambda environments. |
| `LOCALLYCLOUD_SQS_ESM_MAX_POLLERS` | `10` | Local worker ceiling per SQS mapping, independent of RC. |
| `LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE` | `1` | Multiplier for classic EventBridge retry delays and event age. |
| `LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS` | Disabled | Set `1` to enforce controlled table write limits. |
| `LOCALLYCLOUD_KINESIS_SIMULATE_WRITE_LIMITS` | Disabled | Set `1` to enforce modeled shard write limits. |

Example: quota `10` with minimum unreserved `2` permits eight reserved slots. Defaults
are independent; quotas below 100 require an explicit smaller minimum. Incompatible saved
reservations prevent startup without mutation. Inspect limits with `lambda get-account-settings`.

Time scale `0.01` makes one retry second last 10 ms and reduces event age proportionally.
See the [configuration reference](SETUP.md#configuration) for accepted ranges.

> [!TIP]
> Use disposable state and disk-backed caches; `/tmp` may be tmpfs. Budget roughly
> simultaneous environments × (`MemorySize` + 32 MiB), plus warm environments and
> room for other applications. Increasing a quota allocates no RAM.

## Diagnosis

| Signal | Meaning |
| --- | --- |
| `AWS/Lambda Throttles` | Concurrency admission rejections. |
| `AWS/Lambda ConcurrentExecutions` | Function/account execution peak; use `Maximum`. |
| `AWS/Lambda UnreservedConcurrentExecutions` | Active executions in the shared pool, distinct from available quota in `GetAccountSettings`. |
| `LocallyCloud/Lambda HostCapacityExceeded` | Host memory budget rejection; resize the experiment. |
| `AWS/States` | `ExecutionsStarted`, `ExecutionsSucceeded`, `ExecutionsFailed`, `ExecutionsTimedOut`, `ExecutionsAborted`: use `Sum` with `StateMachineArn`. `ExecutionTime` is in milliseconds. |
| `LocallyCloud/States ActiveExecutions` | Exact local active count, sampled each second; use `Maximum`. |
| Queue/DLQ state and unique outputs | Delivery attempts, backlog, completion and loss. Inspect `ApproximateReceiveCount` when testing redrive. |

Metrics are best effort. Lambda flushes minute aggregates every 60 seconds; wait before
reading short-run results. `ExecutionsStarted` emits 1 at start and 0 at completion, so
`SampleCount` is not the execution count. A Lambda rejection can fail a workflow without
producing Step Functions `ExecutionThrottled`, which measures state-transition throttling.

## Before/after validation

1. Select one bottleneck; keep host capacity above demand.
2. Hold inputs, payload size, burst size, parallelism and SDK retry settings constant.
3. Measure the unregulated burst: rejections, attempts, unique outputs and DLQ contents.
4. Add bounded intake without raising destination limits. Drain downstream work, wait for
   metrics, and compare completion and elapsed time.

For database/stream limits, include operations per invocation and payload size; concurrency
is not a writes-per-second budget. An API ACK or zero throttles does not establish completion.

Provision execution roles and queue permissions. Set visibility above execution time with
retry margin. Make outputs idempotent. Multiple mappings and other callers share the same
function RC; a mapping maximum does not reserve that capacity exclusively.

### Observed local result

Rootless execution, 20 events, RC 2, batch size 1 and equal host budgets. The lab used
`maxReceiveCount=1` for prompt DLQ observation, not as a production recommendation.

| Result | No mapping maximum | `MaximumConcurrency=2` |
| --- | ---: | ---: |
| Unique outputs | 11 | 20 |
| Lambda throttles | 10 | 0 |
| DLQ messages | 9 | 0 |
| Peak concurrency | 2 | 2 |
| Host-capacity rejections | 0 | 0 |

Separate checks validated Standard/Express metrics and idempotent starts. An HTTPS target
returning 503 received seven EventBridge attempts before scaled age expiry and DLQ handoff.
These counts describe the tested scenario; they are not universal expectations.

Further service checks must cover account/region isolation, partial failures, restarts,
recovery when capacity returns, and absence of partial writes on rejected requests.

## AWS references

- [Step Functions metrics](https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html)
- [DynamoDB throttling diagnosis](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/troubleshooting-throttling-diagnostics.html)
- [Kinesis provisioned shard limits](https://docs.aws.amazon.com/kinesis/latest/APIReference/API_CreateStream.html)
