import * as Catalog from "./catalog.js";
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
