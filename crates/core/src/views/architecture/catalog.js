/* Threat catalog lookups and OWASP Risk Rating. The catalog is data (catalog.json): methodologies,
   controls and threats with stable IDs, so findings and agent proposals can only cite known entries. */
import data from './catalog.json' with { type: 'json' };

const LEVELS = ['low', 'medium', 'high'];
// OWASP Risk Rating overall severity, indexed [impact level][likelihood level].
const SEVERITY = [['note', 'low', 'medium'], ['low', 'medium', 'high'], ['medium', 'high', 'critical']];

function fail(message) { throw new Error(message); }
function index(items, kind) {
  const map = new Map();
  for (const item of items) {
    if (typeof item.id !== 'string' || !item.id || map.has(item.id)) { fail(`Missing or duplicate catalog ${kind} ID`); }
    map.set(item.id, item);
  }
  return map;
}
function factors(input, names, label) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(k => !names.includes(k))) { fail(`Unsupported ${label} factors`); }
  return Object.fromEntries(names.map(name => {
    const value = input[name];
    if (!Number.isInteger(value) || value < 0 || value > 9) { fail(`Risk factor ${name} must be an integer from 0 to 9`); }
    return [name, value];
  }));
}

/** OWASP Risk Rating factors (each 0–9): likelihood (threat agent + vulnerability) and technical impact. */
export function risk(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(k => !['likelihood', 'impact'].includes(k))) { fail('Unsupported risk rating'); }
  return { likelihood: factors(input.likelihood, data.risk.likelihood, 'likelihood'), impact: factors(input.impact, data.risk.impact, 'impact') };
}
function level(score) { return score < 3 ? 0 : score < 6 ? 1 : 2; }
function mean(values) { return values.reduce((sum, v) => sum + v, 0) / values.length; }
export function rate(input) {
  const factorsOf = risk(input);
  const likelihood = mean(Object.values(factorsOf.likelihood)), impact = mean(Object.values(factorsOf.impact));
  return { likelihood, impact, likelihoodLevel: LEVELS[level(likelihood)], impactLevel: LEVELS[level(impact)], severity: SEVERITY[level(impact)][level(likelihood)] };
}

const methodologies = index(data.methodologies, 'methodology');
const controls = index(data.controls, 'control');
const threats = index(data.threats, 'threat');
for (const t of threats.values()) {
  if (!methodologies.get(t.methodology)?.categories.includes(t.category)) { fail(`Catalog threat ${t.id} has an unknown methodology or category`); }
  if (!t.controls.length || t.controls.some(id => !controls.has(id))) { fail(`Catalog threat ${t.id} references an unknown control`); }
  if (!t.title?.en || !(t.appliesTo?.flow === true || t.appliesTo?.node?.length)) { fail(`Catalog threat ${t.id} needs a title and an element type`); }
  rate(t.risk);
}

export const VERSION = data.version;
export const SEVERITIES = ['note', 'low', 'medium', 'high', 'critical'];
export const methodology = (id) => methodologies.get(id);
export const methodologyIds = () => [...methodologies.keys()];
export const control = (id) => controls.get(id);
export const threat = (id) => threats.get(id);
export const threatIds = () => [...threats.keys()];
/** Localized catalog text, falling back to English. */
export const label = (entry, language) => entry?.title?.[language] || entry?.title?.en || '';
