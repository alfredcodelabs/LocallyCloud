import * as Catalog from "./catalog.js";
import * as Review from "./engine.js";
export const STATES = ["gap", "review", "declared"];

export const CONTROL_STATES = ["met", "unmet", "unknown"];
const INACTIVE = new Set([
  "NOT_RECORDED",
  "CONDITIONAL_NOT_RECORDED",
  "DELETE_COMPLETE",
]);
function control(id, node) {
  const facts = (Catalog.control(id).evidence || []).flatMap((e) => {
    const fact = node?.facts?.find((f) => f.id === e.fact);
    if (!fact) {
      return [];
    }
    return [
      {
        id: fact.id,
        value: fact.value,
        evidence: fact.evidence,
        state: e.met.includes(fact.value)
          ? "met"
          : e.unmet.includes(fact.value)
            ? "unmet"
            : "unknown",
      },
    ];
  });
  const state = facts.some((f) => f.state === "unmet")
    ? "unmet"
    : facts.length && facts.every((f) => f.state === "met")
      ? "met"
      : "unknown";
  return { id, state, facts };
}

function state(controls) {
  if (controls.some((c) => c.state === "unmet")) {
    return "gap";
  }
  return controls.every((c) => c.state === "met") ? "declared" : "review";
}

export function assess(model) {
  const nodes = new Map(model.nodes.map((n) => [n.id, n]));
  const elements = [
    ...model.nodes
      .filter((n) => !INACTIVE.has(n.status))
      .map((n) => ({ target: "n:" + n.id, type: n.type, node: n })),
    ...model.edges
      .filter((e) => e.kind !== "dependency")
      .map((e) => ({ target: "e:" + e.id, flow: true, node: nodes.get(e.to) })),
  ];
  const recorded = new Map(
    model.threats
      .filter((t) => t.catalogId)
      .map((t) => [t.catalogId + "|" + t.target, t]),
  );
  const items = [];
  for (const id of Catalog.threatIds()) {
    const threat = Catalog.threat(id),
      rating = Catalog.rate(threat.risk);
    for (const element of elements) {
      if (
        element.flow
          ? threat.appliesTo.flow !== true
          : !threat.appliesTo.node?.includes(element.type)
      ) {
        continue;
      }
      const controls = threat.controls.map((c) => control(c, element.node));
      const finding = recorded.get(id + "|" + element.target);
      items.push({
        catalogId: id,
        target: element.target,
        category: threat.category,
        severity: rating.severity,
        state: state(controls),
        controls,
        finding: finding
          ? {
              id: finding.id,
              status: finding.status,
              needsReview: finding.needsReview,
            }
          : null,
      });
    }
  }
  const rank = (s) => Catalog.SEVERITIES.length - Catalog.SEVERITIES.indexOf(s);
  return items.sort(
    (a, b) =>
      STATES.indexOf(a.state) - STATES.indexOf(b.state) ||
      rank(a.severity) - rank(b.severity) ||
      a.catalogId.localeCompare(b.catalogId),
  );
}

export function summary(items) {
  const groups = new Map();
  for (const item of items) {
    const group = groups.get(item.catalogId) || {
      catalogId: item.catalogId,
      category: item.category,
      severity: item.severity,
      total: 0,
      recorded: 0,
      gap: 0,
      review: 0,
      declared: 0,
      items: [],
    };
    group.total++;
    group[item.state]++;
    group.recorded += Number(!!item.finding);
    group.items.push(item);
    groups.set(item.catalogId, group);
  }
  return [...groups.values()];
}
export function draft(item, language) {
  const threat = Catalog.threat(item.catalogId);
  const evidence = item.controls.flatMap((c) =>
    c.facts.map((f) => `${c.id}: ${f.id}=${f.value} (${f.evidence})`),
  );
  return {
    methodology: threat.methodology,
    catalogId: threat.id,
    risk: structuredClone(threat.risk),
    category: threat.category,
    target: item.target,
    title: Catalog.label(threat, language),
    mitigation: item.controls
      .map((c) => Catalog.label(Catalog.control(c.id), language))
      .join("\n"),
    note: evidence.join("\n"),
  };
}

/** The four OWASP threat modeling questions, with the review stages each one asks. */
export const PHASES = [
  { id: "scope", stages: [0, 1, 2] },
  { id: "threats", stages: [3] },
  { id: "responses", stages: [] },
  { id: "validation", stages: [4] },
];
const QUESTION_CHECKS = ["scope-questions", "risk-questions", "evidence-questions"];

function phaseOf(stage) {
  return PHASES.find((p) => p.stages.includes(stage)).id;
}

/** What the review still lacks, per OWASP question, with the targets to visit. */
export function coverage(model) {
  const present = new Set([
    "system",
    ...model.nodes.map((n) => "n:" + n.id),
    ...model.edges.map((e) => "e:" + e.id),
  ]);
  const unique = (targets) => [...new Set(targets)];
  const pending = Review.pending(model);
  const questions = (phase) =>
    unique(pending.filter((q) => phaseOf(q.stage) === phase).map((q) => q.target));
  const items = assess(model);
  // Components are the nodes the review asks about; configuration glue needs no zone.
  const components = model.nodes.filter(
    (n) => n.status !== "INFERRED" && Review.questions(model, "n:" + n.id).length > 0,
  );
  const checks = [
    { id: QUESTION_CHECKS[0], phase: "scope", targets: questions("scope") },
    { id: "unresolved", phase: "scope", targets: unique(model.unresolved.map((u) => "n:" + u.target)) },
    { id: "unzoned", phase: "scope", targets: components.filter((n) => !n.zone).map((n) => "n:" + n.id) },
    { id: QUESTION_CHECKS[1], phase: "threats", targets: questions("threats") },
    {
      id: "unrecorded-gaps",
      phase: "threats",
      targets: unique(items.filter((i) => i.state === "gap" && !i.finding).map((i) => i.target)),
    },
    {
      id: "open-findings",
      phase: "responses",
      targets: unique(model.threats.filter((t) => t.status === "open").map((t) => t.target)),
    },
    { id: QUESTION_CHECKS[2], phase: "validation", targets: questions("validation") },
    {
      id: "needs-review",
      phase: "validation",
      targets: unique([
        ...model.review.answers.filter((a) => a.needsReview).map((a) => a.target),
        ...model.threats.filter((t) => t.needsReview).map((t) => t.target),
      ]),
    },
    {
      id: "orphaned-findings",
      phase: "validation",
      targets: unique(model.threats.filter((t) => !present.has(t.target)).map((t) => t.target)),
    },
  ].map((c) => ({ ...c, count: c.targets.length }));
  return { checks, ready: checks.every((c) => c.count === 0) };
}
