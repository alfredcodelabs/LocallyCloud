# Agent context

Graphify is an optional development tool for navigating code, specifications and
decisions across sessions. It is independent of the emulator and runs locally.
The repository pins Graphify 0.9.90; each checkout keeps its own environment,
graph and caches under `target/agent-context/`. Nothing is shared through SQL.

## Setup and navigation

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/). Setup downloads the
pinned package and dependencies; ordinary indexing and queries make no model calls.
The installation includes Graphify's Terraform parser for infrastructure fixtures.

```sh
scripts/agent-context setup
scripts/agent-context update
scripts/agent-context status
scripts/agent-context query 'Lambda concurrency admission' --budget 2000
scripts/agent-context explain ConcurrencyLimiter
```

The wrapper uses an absolute workspace path and one extraction worker. Queries
automatically update changed structural inputs. `.graphifyignore` includes
`crates/`, documentation, `.kiro/specs/` and scripts while excluding build outputs,
credentials and state. It overrides the Git exclusion of specifications without
changing `.gitignore`. Do not put secrets in the included documents.

## Decisions and AWS contracts

Structural extraction locates files and symbols. Semantic extraction preserves
concepts, rationale, status and citations. It uses the coding agent's model and
consumes model context; it is not automatic or free of model cost.

At task start, check status. Unindexed documents are listed in
`target/agent-context/graphify-out/pending-documents.json`; select the documents
relevant to the task rather than processing the full corpus every session.

```sh
scripts/agent-context prepare docs/THROTTLING.md .kiro/specs/lambda/design.md
```

This prints a request path, source list and the installed extraction specification.
The project [Graphify skill](../.agents/skills/graphify/SKILL.md) describes producing
the fragment. Then import it with:

```sh
scripts/agent-context import /absolute/path/to/request.json /absolute/path/to/fragment.json
```

Import rejects changed sources, missing documents, conflicting node IDs, unknown
edge endpoints and missing provenance. It replaces only those documents' semantic
contributions. Queries refuse stale indexed semantics until they are refreshed.
Unindexed documents remain a coverage gap, reported on every query.
Freshness records the source and extraction-prompt hashes actually published in the
graph. Finding a cached fragment from another branch does not make that graph fresh.

Validate changes to the integration with `python3 scripts/tests/test-agent-context`.

For AWS contracts, first consult the current official page. If retaining a local
snapshot under `docs/`, include `source_url` and `captured_at` in YAML frontmatter
and preserve them during extraction. A link alone does not ingest its target.
Fetching an updated snapshot and extracting it are separate operations; no
scheduled fetcher or external API credentials are configured.

Keep generated graphs and caches local. Review durable decisions in maintained
documentation. Distinguish intended behavior, implementation and observed test
evidence; historical failures must not become current conclusions. Static graph
edges do not prove runtime dispatch or AWS fidelity. Verify the relevant source
before making changes. Use English for context and queries.
