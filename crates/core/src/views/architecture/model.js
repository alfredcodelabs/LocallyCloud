/* Review model: validation, saved-review import (v1/v2), refresh merge and saved views.
   Pure functions shared by the dashboard page and the MCP companion. The topology itself is
   built by the server; every document handled here is untrusted and bounded. */
import * as Review from './engine.js';
import * as Catalog from './catalog.js';

export const LIMIT = Object.freeze({ bytes: 8 * 1024 * 1024, nodes: 512, edges: 2048, threats: 512, zones: 32, views: 32, facts: 32 });
export const STRIDE = Catalog.methodology('STRIDE').categories;
export const KINDS = ['dependency', 'configured', 'proposed'];
export const STATUSES = ['open', 'mitigated', 'accepted', 'not-applicable'];
export const SEVERITIES = ['unrated', ...Catalog.SEVERITIES];
const DOCUMENTS = ['review', 'snapshot', 'template'];
const SOURCES = ['demo', 'template', 'snapshot', 'design'];
const ORIGINS = ['human', 'agent-reviewed', 'captured', 'declared'];

function fail(message) { throw new Error(message); }
function text(value, max = 256) { return typeof value === 'string' ? value.slice(0, max) : ''; }
function array(value, max) {
  if (!Array.isArray(value) || value.length > max) { fail(`Expected an array with at most ${max} entries`); }
  return value;
}
function records(value, max) {
  const items = array(value, max);
  if (items.some(item => !item || typeof item !== 'object' || Array.isArray(item))) { fail('Expected an array of objects'); }
  return items;
}
function bounded(input) {
  const pending = [[input, 0]]; let count = 0;
  while (pending.length) {
    const [v, depth] = pending.pop();
    if (++count > 50000 || depth > 32) { fail('Model exceeds the structure/depth limit'); }
    if (v && typeof v === 'object') {
      for (const child of Object.values(v)) { pending.push([child, depth + 1]); }
    }
  }
  return input;
}
export function parse(raw) {
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).length > LIMIT.bytes) { fail('File exceeds 8 MiB'); }
  return bounded(JSON.parse(raw));
}
function unique(items, kind) {
  const ids = new Set();
  for (const item of items) {
    if (!item.id || ids.has(item.id)) { fail(`Missing or duplicate ${kind} ID`); }
    ids.add(item.id);
  }
  return ids;
}
const HASH = /^sha256:[0-9a-f]{64}$/;
/** Declared configuration facts: enum values with the property path they came from. */
function facts(value) {
  const items = records(value || [], LIMIT.facts).map(f => ({ id: text(f.id, 64), value: text(f.value, 64), evidence: text(f.evidence, 1000) }));
  if (items.some(f => !f.id || !f.value)) { fail('A configuration fact needs an id and a value'); }
  return items.length ? { facts: items } : {};
}
function finite(value, fallback) { return Number.isFinite(value) ? Math.max(0, Math.min(100000, value)) : fallback; }

export function validate(input) {
  bounded(input);
  if (new TextEncoder().encode(JSON.stringify(input)).length > LIMIT.bytes) { fail('Model exceeds 8 MiB'); }
  if (![1, 2].includes(input?.version)) { fail('Unsupported model version (expected 1 or 2)'); }
  if (input.version === 2 && !input.review) { fail('Missing review workflow'); }
  if (input.documentType != null && !DOCUMENTS.includes(input.documentType)) { fail('Unsupported document type'); }
  const zones = records(input.zones, LIMIT.zones).map(z => ({ id: text(z.id), name: text(z.name) }));
  const zoneIds = unique(zones, 'zone');
  const nodes = records(input.nodes, LIMIT.nodes).map((n, i) => ({
    id: text(n.id), name: text(n.name), type: text(n.type), status: text(n.status), physicalId: text(n.physicalId, 1024),
    origin: ORIGINS.includes(n.origin) ? n.origin : n.status === 'PROPOSED' ? 'human' : input.source === 'snapshot' ? 'captured' : 'declared',
    zone: zoneIds.has(n.zone) ? n.zone : '', x: finite(n.x, 60 + (i % 4) * 250), y: finite(n.y, 100 + Math.floor(i / 4) * 160),
    ...facts(n.facts), ...(typeof n.configHash === 'string' && HASH.test(n.configHash) ? { configHash: n.configHash } : {}),
  }));
  const nodeIds = unique(nodes, 'node');
  const edges = records(input.edges, LIMIT.edges).map(e => {
    if (!KINDS.includes(e.kind) || !nodeIds.has(e.from) || !nodeIds.has(e.to)) { fail('Invalid edge kind or endpoint'); }
    return { id: text(e.id), from: text(e.from), to: text(e.to), kind: e.kind, label: text(e.label), evidence: text(e.evidence, 1000) };
  });
  unique(edges, 'edge');
  const threats = records(input.threats || [], LIMIT.threats).map(t => {
    const methodology = t.methodology ?? 'STRIDE', entry = t.catalogId == null ? null : Catalog.threat(t.catalogId);
    if (!Catalog.methodology(methodology)?.categories.includes(t.category) || !STATUSES.includes(t.status)) { fail('Invalid methodology category or review status'); }
    if (t.catalogId != null && (entry?.methodology !== methodology || entry.category !== t.category)) { fail('Unknown catalog threat or mismatched category'); }
    const risk = t.risk == null ? null : Catalog.risk(t.risk);
    const finding = {
      id: text(t.id), target: text(t.target, 1024), title: text(t.title), methodology, category: t.category, status: t.status,
      severity: risk ? Catalog.rate(risk).severity : SEVERITIES.includes(t.severity) ? t.severity : 'unrated',
      ...(entry ? { catalogId: entry.id } : {}), ...(risk ? { risk } : {}),
      mitigation: text(t.mitigation, 5000), note: text(t.note, 5000), needsReview: t.needsReview === true || input.version === 1,
      owner: text(t.owner), evidence: text(t.evidence, 5000),
      verification: input.version === 2 && t.verification === 'recorded' && !!text(t.evidence, 5000) ? 'recorded' : 'pending',
    };
    if (!finding.title || !finding.target || (finding.status !== 'open' && !(finding.mitigation.trim() || finding.note.trim()))) {
      fail('A threat needs a title and target; closed decisions need a mitigation or rationale');
    }
    return finding;
  });
  unique(threats, 'threat');
  const views = records(input.views || [], LIMIT.views).map(v => ({
    id: text(v.id), name: text(v.name),
    nodeIds: [...new Set(array(v.nodeIds, LIMIT.nodes).map(id => text(id)))],
    layout: records(v.layout || [], LIMIT.nodes).map(n => ({ id: text(n.id), x: finite(n.x, 60), y: finite(n.y, 100) })),
  }));
  unique(views, 'view');
  for (const v of views) { unique(v.layout, 'view layout'); if (!v.name || !v.nodeIds.length) { fail('A view needs a name and resource selection'); } }
  return {
    version: 2, documentType: DOCUMENTS.includes(input.documentType) ? input.documentType : 'review', id: text(input.id, 1024) || 'local-design', title: text(input.title) || 'Architecture review',
    source: SOURCES.includes(input.source) ? input.source : 'design',
    scope: { account: text(input.scope?.account), region: text(input.scope?.region), stack: text(input.scope?.stack, 1024), capturedAt: text(input.scope?.capturedAt) },
    zones, nodes, edges, threats, views,
    unresolved: records(input.unresolved || [], LIMIT.edges).map(u => ({ target: text(u.target), property: text(u.property), reason: text(u.reason) })),
    review: input.version === 1 ? { ...Review.fresh(), legacy: input.documentType === 'review' || threats.length > 0 } : Review.validate(input.review),
  };
}

/** A saved review (v1 or v2) or a server topology snapshot. Raw templates are not accepted. */
export function importModel(input) {
  if (input?.version == null) { fail('Expected a saved review or a LocallyCloud topology (version 1 or 2)'); }
  return validate(input);
}

export function sameScope(previous, next) {
  return previous.id === next.id && previous.scope.account === next.scope.account
    && previous.scope.region === next.scope.region && previous.scope.stack === next.scope.stack;
}

/** Apply a refreshed topology to a review. Decisions survive only for the same account, region and stack. */
export function merge(previous, next) {
  if (next.documentType === 'template' || !sameScope(previous, next)) { return next; }
  const old = new Map(previous.nodes.map(n => [n.id, n]));
  next.zones = previous.zones;
  next.views = structuredClone(previous.views || []);
  next.nodes = next.nodes.map(n => old.has(n.id) ? { ...n, x: old.get(n.id).x, y: old.get(n.id).y, zone: old.get(n.id).zone } : n);
  const presentNodes = new Set(next.nodes.map(n => n.id));
  for (const node of previous.nodes) {
    if (node.status === 'PROPOSED' && !presentNodes.has(node.id)) { next.nodes.push(structuredClone(node)); presentNodes.add(node.id); }
  }
  const edges = new Map(next.edges.map(e => [e.id, e]));
  for (const edge of previous.edges) {
    if (edge.kind === 'proposed' && presentNodes.has(edge.from) && presentNodes.has(edge.to)) { edges.set(edge.id, edge); }
  }
  next.edges = [...edges.values()];
  next.threats = structuredClone(previous.threats);
  next.review = structuredClone(previous.review || Review.fresh());
  return validate(Review.invalidate({ ...next, version: 2 }, changedTargets(previous, next)));
}

/** Targets whose decisions a refresh re-opens, or null for all of them. A capture without
    configuration digests cannot show what stayed the same, so it re-opens everything. Otherwise a
    node is unchanged when both captures carry the same digest; flows follow their endpoints, and
    the system follows any resource or flow that appears or disappears. */
function changedTargets(previous, next) {
  const captured = next.nodes.filter(n => n.status !== 'PROPOSED');
  // Inferred review assumptions (such as the HTTP client) have no configuration to digest.
  if (captured.some(n => n.status !== 'INFERRED' && !n.configHash)) { return null; }
  const before = new Map(previous.nodes.map(n => [n.id, n])), after = new Map(captured.map(n => [n.id, n]));
  const changed = new Set([...before.keys()].filter(id => !after.has(id) && before.get(id).status !== 'PROPOSED'));
  for (const [id, n] of after) {
    if (!before.has(id) || before.get(id).configHash !== n.configHash) { changed.add(id); }
  }
  const edgesBefore = new Set(previous.edges.map(e => e.id)), edgesAfter = new Set(next.edges.map(e => e.id));
  const targets = new Set([...changed].map(id => 'n:' + id));
  let topologyChanged = changed.size > 0 && [...changed].some(id => !before.has(id) || !after.has(id));
  for (const e of [...previous.edges, ...next.edges]) {
    const moved = edgesBefore.has(e.id) !== edgesAfter.has(e.id);
    if (moved) { topologyChanged = true; }
    if (moved || changed.has(e.from) || changed.has(e.to)) { targets.add('e:' + e.id); }
  }
  if (topologyChanged) { targets.add('system'); }
  return targets;
}

export function prompts(model, target) {
  return Review.questions(model, target).filter(q => !q.notApplicable).map(q => ({
    id: q.id, category: q.category, title: q.title, note: [q.explain, q.blockedReason].filter(Boolean).join(' '),
  }));
}

/** The model restricted to a saved view, with that view's layout. Answers and findings stay shared. */
export function view(model, id) {
  if (!id) { return model; }
  const selected = model.views.find(v => v.id === id);
  if (!selected) { fail('Unknown saved view'); }
  const ids = new Set(selected.nodeIds), layout = new Map(selected.layout.map(n => [n.id, n]));
  return { ...model,
    nodes: model.nodes.filter(n => ids.has(n.id)).map(n => ({ ...n, ...(layout.has(n.id) ? { x: layout.get(n.id).x, y: layout.get(n.id).y } : {}) })),
    edges: model.edges.filter(e => ids.has(e.from) && ids.has(e.to)),
    unresolved: model.unresolved.filter(u => ids.has(u.target)),
  };
}
