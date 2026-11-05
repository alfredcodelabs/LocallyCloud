# Threat modeling

[← README](../README.md) · [Setup](SETUP.md) · [Services](SERVICES.md) · [Lambda](LAMBDA.md) · [Platforms](PLATFORMS.md) · [Throttling](THROTTLING.md) · [FAQ](FAQ.md) · [Agent context](AGENT_CONTEXT.md)

**Threat models that start from what you deployed, not from a blank canvas.**

Most threat models are drawn by hand, go stale after the next deploy, and never get
reopened. LocallyCloud builds the diagram from your CloudFormation stack, flags
missing controls from its configuration, and tells you exactly which decisions a
change re-opens. You keep the judgment; the tool does the bookkeeping.

- **Zero drawing.** Resources, flows and trust gaps come from the deployed stack.
- **Evidence, not guesses.** Every gap cites the template property it comes from,
  or states that the template does not declare the control.
- **Re-review only what changed.** A per-resource configuration digest re-opens
  decisions on changed resources and leaves the rest of your review intact.
- **OWASP all the way.** The four threat modeling questions, STRIDE, the OWASP Risk
  Rating Methodology, and references to ASVS 5.0, Top 10:2025 and API Top 10:2023.
- **Agents that propose, people that decide.** An MCP companion lets an AI agent
  fill in the review quickly; every proposal waits for your approval.
- **Works with Threat Dragon.** Open OWASP Threat Dragon v2 models and export
  reviews back to them.
- **Local and private.** Runs inside the emulator on your machine. No account, no
  upload, no telemetry.

[⚖️ Comparison](#how-it-compares) · [🧭 Workflow](#workflow) · [🔎 Evidence](#what-the-view-reads) · [📚 Catalog](#threat-catalog) · [💾 Saving](#saving-and-refreshing) · [🤖 Agents](#agent-companion-mcp) · [⚠️ Limits](#limits)

## How it compares

Established tools are excellent at what they target. LocallyCloud's tool targets a
narrower job: keeping a threat model in sync with serverless infrastructure you
are developing locally.

| | Microsoft Threat Modeling Tool | OWASP Threat Dragon | IriusRisk | LocallyCloud |
| --- | --- | --- | --- | --- |
| Where it runs | Windows desktop | Web or desktop | Commercial platform (SaaS or self-hosted) | Built into the local emulator, Linux |
| Where the diagram comes from | Drawn by hand | Drawn by hand | Questionnaires, drawing or infrastructure-as-code import | Read from the deployed stack |
| Configuration evidence | — | — | From imported definitions | Declared facts with their property paths |
| After a change | Update the diagram by hand | Update the diagram by hand | Re-import and review | Refresh; only changed resources re-open |
| Cost | Free | Free, open source | Paid | Free, included |

Comparison based on each project's public documentation as of November 2026:
[Microsoft Threat Modeling Tool](https://learn.microsoft.com/azure/security/develop/threat-modeling-tool),
[OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) and
[IriusRisk](https://www.iriusrisk.com/). Check them for current features.

Choose IriusRisk for organization-wide governance and large threat libraries,
Microsoft's tool for Windows-centric DFD templates, and Threat Dragon for
open-source diagrams of any system. Use LocallyCloud when the system is an AWS
serverless stack you deploy to the emulator and want the model to follow the code.

## Workflow

Open the dashboard at `http://127.0.0.1:4566/_locallycloud/ui`, choose
**Threat modeling**, then a stack. The review follows the four
[OWASP threat modeling](https://owasp.org/www-community/Threat_Modeling) questions;
each step shows only what answers it, with a count of what is still pending.

| Step | What you do |
| --- | --- |
| 1. What are we working on? | Answer context questions (purpose, actors, data, tenants, access, trust boundaries), assign components to trust zones and confirm unresolved flows. |
| 2. What can go wrong? | Review catalog threats per element and the STRIDE prompts. Control gaps come from declared configuration; everything else needs a reviewer. |
| 3. What are we going to do about it? | Record findings and decide each one: open, mitigated, accepted or not applicable. |
| 4. Did we do a good enough job? | Use the coverage panel: unanswered questions, unzoned components, unrecorded gaps, open or orphaned findings, and decisions to review again. Each item links to its element. |

Questions are a dependency graph: later questions appear only when earlier answers
make them relevant (for example, tenant isolation only for multi-tenant systems).
`unknown` is always a valid answer and stays pending. A justified `not-applicable`
closes the questions that depend on it.

## What the view reads

The server builds the topology from the stack's deployed resources and processed
template, using read-only calls. The browser receives resource identities, flows
and classifications; property values and policy documents stay on the server.

| Evidence | Meaning |
| --- | --- |
| Configured flow | A destination read from deployed configuration (event mappings, rule targets, notifications, state machine tasks, API integrations). Not observed delivery. |
| Dependency | A `Ref`/`GetAtt`/`DependsOn` relation; provisioning order, not a data flow. Hidden by default. |
| Unresolved reference | A destination that is external, ambiguous, dynamic or unsupported, listed with its reason instead of guessed. |
| Declared fact | A classified setting from the template, such as `encryption-at-rest = kms` or `tls-only = not-declared`, with its property path. Values, policy documents and environment values are not exported; secrets in environment variables are detected by variable name only. |
| Configuration digest | A SHA-256 of each resource's type, physical ID and properties, with environment values excluded. Used to re-open only decisions on changed resources. |

## Threat catalog

The catalog is data with stable IDs, so findings and agent proposals can only cite
known entries.

- **Threats** (`LC-*`) follow STRIDE, apply to resource types or flows, and reference
  CWE, CAPEC, OWASP Top 10:2025 and API Security Top 10:2023 by ID.
- **Controls** (`LC-CTL-*`) reference ASVS 5.0 chapters and declare which facts meet
  or contradict them.
- **Risk** uses the [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology):
  eight likelihood and four technical impact factors (0–9). Severity is computed,
  never chosen, for catalog findings.

Each applicable threat and element gets a state:

| State | Rule |
| --- | --- |
| Control gap | The template contradicts the control or does not declare it, for example a bucket without a TLS-only bucket policy (`tls-only = not-declared`). |
| To review | No fact covers the control, or a fact cannot be evaluated (`unknown`). Some controls (input validation, object-level authorization, idempotency) are never visible in configuration. |
| Controls declared | Every control is shown by a fact. Declared is not verified. |

Current answers adjust risk factors through catalog rules: regulated data raises
confidentiality impact, public access raises opportunity, a flow inside one trust
zone lowers it. Answers awaiting review do not count. Each card lists the rules
applied and the catalog severity. The assessment is recomputed from the model on
every change and never stored; recorded findings are the reviewer's decisions.

A mitigated decision needs a mitigation, an owner and validation evidence. Other
closed decisions need a rationale.

## Saving and refreshing

Reviews are local files. Use **Save review JSON** to keep decisions; nothing is
stored on the server. **Open review JSON** restores a saved review (versions 1 and
2) up to 8 MiB, 512 nodes, 2048 edges, 512 findings, 32 trust zones, 32 saved
views and 32 facts per resource.

**Refresh from server** reloads the topology and keeps decisions for the same
account, region and stack. Decisions are re-opened only on resources whose
configuration digest changed, their flows, and the whole system when resources or
flows appear or disappear. A review saved without digests re-opens everything.

Saved views restrict the diagram to selected resources with their own layout; they
share answers and findings with the full review. **Export SVG** writes the current
diagram.

### OWASP Threat Dragon

**Export Threat Dragon** writes a [Threat Dragon](https://owasp.org/www-project-threat-dragon/)
v2 model that opens in Threat Dragon 2.x: components become actors, processes and
stores, configured and proposed flows become data flows, trust zones become trust
boundary boxes, and recorded findings become threats with their status, severity
and mitigation. Answers, facts, digests, evidence states and system-level findings
stay in the review JSON, and dependencies are not data flows, so they are not
exported. The dashboard lists what was left out.

**Open review JSON** also accepts a Threat Dragon v2 model and turns it into a
design review: every element is a proposed component or flow, each diagram becomes
a saved view, and boxes become trust zones for the components inside them. STRIDE
threats become findings that await review; closed threats without a mitigation or
description are reopened. Threats of other methodologies, curved boundaries and
flows without two connected components are skipped and listed.

## Agent companion (MCP)

An optional stdio MCP server lets an agent read a saved review and write proposals.
It cannot change the review: a person opens each proposal in the dashboard, checks
its diff and accepts it.

From the repository root:

```sh
npm ci --prefix tools/architecture-review-mcp
install -d -m 0700 ~/reviews/orders     # private workspace
# save review JSON from the dashboard as ~/reviews/orders/review.json
node tools/architecture-review-mcp/server.mjs --workspace "$HOME/reviews/orders"
```

The workspace must be an absolute path without symlinks, owned by you with mode
`0700`. Proposals are written to its `proposals/` directory. Register the command
in your agent's MCP configuration; Node.js 22 or later is required.

| Tool | Purpose |
| --- | --- |
| `read_review_context` | Scope, revision, digest and graph identities, paged and filterable by type or saved view. |
| `assess_catalog` | Catalog threats per element with state, control facts, adjusted risk and applied rules. |
| `list_pending_questions` | Pending questions per target, or one target's questions and answers. |
| `read_evidence` | Declared facts, unresolved references and recorded evidence for one target. |
| `propose_answer` | A proposed answer for a question; requires the current digest. |
| `propose_model_change` | A proposed design-only component or flow. |

Agents never compute severity, close findings or verify controls. A proposal made
against an older revision or digest is rejected. Labels, notes and evidence are
treated as untrusted data.

## Limits

- Facts come from the processed template, not from reading each service. Changes
  made outside CloudFormation (drift) are not visible.
- Digests exclude stack parameter values, so a parameter-only change does not
  re-open decisions. Resources outside the template have no digest; their presence
  re-opens all decisions.
- Some flows are not extracted yet: Lambda calls made from function code, S3
  notifications to EventBridge, API Gateway integrations with Step Functions, rules
  on the default or an external event bus, and Step Functions tasks beyond Lambda,
  DynamoDB, SQS and EventBridge. They appear as unresolved references or are absent.
- "Not declared" means absent from the template, not absent from the deployment.
  Known false gaps: settings applied after deployment outside the template (for
  example access logs that the Serverless Framework sets with `UpdateStage`), queues
  that are themselves dead-letter queues, and IAM actions that only accept
  `Resource: "*"` (log delivery and X-Ray). Record a finding with that rationale.
- The catalog covers serverless resource types and STRIDE. A control without a
  matching fact always stays "to review".
