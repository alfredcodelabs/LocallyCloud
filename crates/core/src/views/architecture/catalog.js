import data from "./catalog.json" with { type: "json" };

const LEVELS = ["low", "medium", "high"];

const SEVERITY = [
  ["note", "low", "medium"],
  ["low", "medium", "high"],
  ["medium", "high", "critical"],
];

function fail(message) {
  throw new Error(message);
}
function index(items, kind) {
  const map = new Map();
  for (const item of items) {
    if (typeof item.id !== "string" || !item.id || map.has(item.id)) {
      fail(`Missing or duplicate catalog ${kind} ID`);
    }
    map.set(item.id, item);
  }
  return map;
}
function factors(input, names, label) {
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).some((k) => !names.includes(k))
  ) {
    fail(`Unsupported ${label} factors`);
  }
  return Object.fromEntries(
    names.map((name) => {
      const value = input[name];
      if (!Number.isInteger(value) || value < 0 || value > 9) {
        fail(`Risk factor ${name} must be an integer from 0 to 9`);
      }
      return [name, value];
    }),
  );
}

export function risk(input) {
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).some((k) => !["likelihood", "impact"].includes(k))
  ) {
    fail("Unsupported risk rating");
  }
  return {
    likelihood: factors(input.likelihood, data.risk.likelihood, "likelihood"),
    impact: factors(input.impact, data.risk.impact, "impact"),
  };
}
function level(score) {
  return score < 3 ? 0 : score < 6 ? 1 : 2;
}
function mean(values) {
  return values.reduce((sum, v) => sum + v, 0) / values.length;
}
export function rate(input) {
  const factorsOf = risk(input);
  const likelihood = mean(Object.values(factorsOf.likelihood)),
    impact = mean(Object.values(factorsOf.impact));
  return {
    likelihood,
    impact,
    likelihoodLevel: LEVELS[level(likelihood)],
    impactLevel: LEVELS[level(impact)],
    severity: SEVERITY[level(impact)][level(likelihood)],
  };
}

const methodologies = index(data.methodologies, "methodology");
const controls = index(data.controls, "control");
const threats = index(data.threats, "threat");
const FACT = /^[a-z][a-z-]{0,63}$/;
for (const c of controls.values()) {
  for (const e of c.evidence || []) {
    const values = [...e.met, ...e.unmet];
    if (
      !FACT.test(e.fact) ||
      !e.met.length ||
      values.some((v) => !FACT.test(v)) ||
      new Set(values).size !== values.length
    ) {
      fail(`Control ${c.id} has invalid fact evidence`);
    }
  }
}
for (const t of threats.values()) {
  if (!methodologies.get(t.methodology)?.categories.includes(t.category)) {
    fail(`Catalog threat ${t.id} has an unknown methodology or category`);
  }
  if (!t.controls.length || t.controls.some((id) => !controls.has(id))) {
    fail(`Catalog threat ${t.id} references an unknown control`);
  }
  if (
    !t.title?.en ||
    !(t.appliesTo?.flow === true || t.appliesTo?.node?.length)
  ) {
    fail(`Catalog threat ${t.id} needs a title and an element type`);
  }
  rate(t.risk);
}
const typeSets = new Map(Object.entries(data.typeSets));
const rules = index(data.riskRules, "risk rule");
const categories = new Set(
  [...methodologies.values()].flatMap((m) => m.categories),
);
for (const r of rules.values()) {
  const changes = [r.raise, r.lower].filter(Boolean);
  if (
    !r.title?.en ||
    !changes.length ||
    (r.categories || []).some((c) => !categories.has(c))
  ) {
    fail(`Risk rule ${r.id} needs a title, a change and known categories`);
  }
  for (const change of changes) {
    for (const [group, values] of Object.entries(change)) {
      const names = data.risk[group];
      if (!names) {
        fail(`Risk rule ${r.id} changes an unknown factor group`);
      }
      factors({ ...Object.fromEntries(names.map((n) => [n, 0])), ...values }, names, group);
    }
  }
}

export const VERSION = data.version;
export const SEVERITIES = ["note", "low", "medium", "high", "critical"];
export const methodology = (id) => methodologies.get(id);
export const methodologyIds = () => [...methodologies.keys()];
export const control = (id) => controls.get(id);
export const threat = (id) => threats.get(id);
export const threatIds = () => [...threats.keys()];
/** Localized catalog text, falling back to English. */
export const label = (entry, language) =>
  entry?.title?.[language] || entry?.title?.en || "";
/** Review questions as data: a DAG through `after` and `when` (validated by the engine). */
export const questions = () => data.questions;
export const typeSet = (name) => typeSets.get(name);
export const riskRules = () => [...rules.values()];
export const riskRule = (id) => rules.get(id);
