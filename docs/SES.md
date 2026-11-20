# SES email capture and provider delivery

SES is a partial native service on the normal LocallyCloud endpoint. Applications
use the AWS SDK/CLI; a server-owned provider configuration selects encrypted local
capture or delivery through Resend's HTTPS API. No SMTP server is required.

## Supported contract

| API | Implemented operations |
| --- | --- |
| SES v2, REST JSON | `CreateEmailIdentity`, `GetEmailIdentity`, `DeleteEmailIdentity`, `ListEmailIdentities`, `SendEmail` with Simple content |
| SES classic, Query XML | `VerifyEmailIdentity`, `VerifyEmailAddress`, `DeleteIdentity`, `ListIdentities`, `SendEmail` |

Simple sending preserves the requested From, To, Cc, Bcc, Reply-To, subject and
text/HTML content. Text is UTF-8 or US-ASCII. Requests are capped at a local defensive
10 MiB ceiling, with at most 50 recipients. Account/region isolation and strict IAM
apply to native requests. Domain-verified senders authorize against that domain's
SES identity ARN. Continuation tokens are authenticated and bound to scope,
operation and filter.

New identities start `PENDING` by default, with stable DKIM tokens for domains, and
sending requires a verified identity. Real AWS email-link and DNS/DKIM verification
completion are not implemented. For isolated development, explicitly set
`ses.auto_verify_identities` to `true` before creating/verifying identities. This
simulates completion for those calls; it does not silently promote existing pending
identities. Resend still requires its own verified sending domain. Creating an SES
identity does not verify a domain at the provider.

Raw MIME, attachments, templates, custom headers, sending authorization ARNs,
configuration sets, tags on sends, quotas/account management, bulk sending and
provider delivery/bounce/complaint events are not implemented. Unsupported sending
options are rejected before accepting the message. This milestone is not full AWS
SES parity. Configuration UI, credential-vault entry and a captured-message UI remain
future work.

## Configure delivery

Use the shared [SES configuration reference](SETUP.md#ses-configuration). Settings
resolve at startup using defaults, the `ses` section in the existing config file,
then environment overrides. Credentials are separate environment inputs; JSON
cannot contain the API key. File changes require a restart.

Capture is the default and makes no provider requests. Messages are stored as
individually authenticated encrypted records in the shared SQLite database. There
is no AWS API for reading the captured message body, and no administrative inbox UI
in this milestone. Metadata and bodies survive restart with the same master key.

For managed delivery, select `resend` and supply
`LOCALLYCLOUD_SES_PROVIDER_API_KEY` through the process's secret environment. The
adapter calls the fixed `https://api.resend.com/emails` endpoint. It uses the shared
async HTTP destination policy, TLS verification, disabled proxies/redirects and a
bounded response body. Validation and opening configuration do not send email.

For a local capture example, merge this section into the existing startup JSON
file and restart LocallyCloud with the same master key. This explicitly enables
verification simulation for newly created identities:

```json
{
  "ses": {
    "provider": "capture",
    "auto_verify_identities": true
  }
}
```

Use the dedicated [local AWS profile](SETUP.md#local-aws-profile):

```sh
aws --profile locallycloud sesv2 create-email-identity \
  --email-identity sender@example.com

aws --profile locallycloud sesv2 send-email \
  --from-email-address sender@example.com \
  --destination '{"ToAddresses":["recipient@example.net"]}' \
  --content '{"Simple":{"Subject":{"Data":"Local SES"},"Body":{"Text":{"Data":"Hello"}}}}'
```

With Resend enabled, choose actual addresses authorized by your provider. Running
the send command requests a real email; creating an identity alone does not.

## CloudFormation and Cognito

CloudFormation supports `AWS::SES::EmailIdentity` with `EmailIdentity` and `Tags`.
`Ref` returns the identity name; domain identities expose the three DKIM token
name/value attribute pairs. These records do not perform DNS verification.

Cognito user pools can send sign-up confirmation email through native SES with
`EmailConfiguration.EmailSendingAccount` set to `DEVELOPER`. Set `SourceArn` to
an SES identity in the pool's account and region, and `From` to an address covered
by that identity. SES verification and sending permissions still apply. A failed
SES acceptance releases the reserved username without publishing the user;
successful acceptance does not guarantee provider delivery. Other Cognito email
flows and sending-authorization contracts are outside this milestone.

## Acceptance, retries and restart

A successful send returns an SES message ID after its encrypted message/outbox
record commits. It acknowledges local acceptance, not receipt in the recipient's
inbox. A provider acceptance records a separate provider ID. It does not fabricate
an AWS delivery event. Provider errors are classified internally rather than
returned as AWS IAM denials after the send was acknowledged.

Workers start only for pending deliveries and exit when the queue is empty. SQLite
work runs on blocking workers. Cancelling the HTTP client does not interrupt an
accepted commit or strand its delivery notification. Leased attempts can resume
after their deadline on restart, retaining the same payload and idempotency key.

Resend retries keep the same `Idempotency-Key` and payload. Retryable connection,
response-read, throttling and server failures use bounded retries; numeric
`Retry-After` values are honored. The adapter stops automatic replay after eight
attempts or 23 hours from acceptance, within Resend's documented 24-hour idempotency
window. Exhausted/ambiguous deliveries are retained as `uncertain`; provider
rejections are `failed`.

Pending count/byte budgets are global to the instance and include blocked and
uncertain deliveries. Completed captures and accepted-provider records remain on
disk; this milestone has no automatic content retention cleanup. There is no full
in-memory copy of message history.

Jobs retain an opaque credential binding. A changed provider key blocks pending
jobs instead of delivering them through another account. New messages use the new
configuration. Blocked-job administration is pending; do not rotate a provider key
with outstanding jobs expecting automatic rebinding. Previously captured messages
never become real deliveries when switching to Resend.

Provider tests use local HTTP fixtures and synthetic credentials. Real Resend
sending requires user-supplied credentials and an explicitly requested recipient;
no real provider email is required for the local test suite.

References: [SES v2 SendEmail](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendEmail.html),
[Resend Send Email](https://resend.com/docs/api-reference/emails/send-email),
[Resend idempotency](https://resend.com/docs/dashboard/emails/idempotency-keys).
