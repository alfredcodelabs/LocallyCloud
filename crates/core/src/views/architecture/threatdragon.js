/* OWASP Threat Dragon v2 interchange. Export writes the diagram, trust zones and recorded findings;
   import turns a Threat Dragon model into a design-only review whose decisions await review. Both
   directions are lossy by design: the review JSON stays the complete format. Imported documents are
   untrusted and bounded. */
import * as M from './model.js';
import * as Review from './engine.js';

export const VERSION = '2.3.0';
const NODE = Object.freeze({ width: 200, height: 105 });
const MAX = Object.freeze({ diagrams: 32, cells: 4096, threats: M.LIMIT.threats });
const STATUS_OUT = { open: 'Open', mitigated: 'Mitigated', accepted: 'Accepted', 'not-applicable': 'NotApplicable' };
const STATUS_IN = {
  open: 'open', mitigated: 'mitigated', avoided: 'mitigated', eliminated: 'mitigated',
  accepted: 'accepted', transferred: 'accepted', notapplicable: 'not-applicable', na: 'not-applicable',
};
const SEVERITY_OUT = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', note: 'Low', unrated: 'TBD' };
const SEVERITY_IN = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
const SHAPE_IN = { actor: 'External actor', process: 'Process', store: 'Data store' };
const STORE = /^(Data store|AWS::\w+::(Bucket|Table|GlobalTable|Queue|Stream|DeliveryStream|DBInstance|DBCluster|Secret|Parameter|LogGroup|Repository))$/;

function fail(message) { throw new Error(message); }
function text(value, max = 256) { return typeof value === 'string' ? value.slice(0, max) : ''; }
function list(value, max, what) {
  if (value == null) { return []; }
  if (!Array.isArray(value) || value.length > max) { fail(`Threat Dragon ${what} must be an array with at most ${max} entries`); }
  return value.filter(item => item && typeof item === 'object' && !Array.isArray(item));
}
const shapeOf = type => type === 'External actor' ? 'actor' : STORE.test(type) ? 'store' : 'process';
const count = (tally, key) => { tally[key] = (tally[key] || 0) + 1; };

/** A Threat Dragon v2 document, recognized by its summary/detail envelope and string version. */
export function isThreatDragon(input) {
  return typeof input?.version === 'string' && /^2\./.test(input.version) && !!input.summary && !!input.detail;
}

function threatOut(finding, number) {
  const mitigation = [finding.mitigation, finding.owner && `Owner: ${finding.owner}`, finding.evidence && `Validation evidence: ${finding.evidence}`]
    .filter(Boolean).join('\n\n');
  const description = [finding.note, finding.catalogId && `LocallyCloud catalog: ${finding.catalogId}`].filter(Boolean).join('\n\n');
  return {
    id: finding.id, title: finding.title, type: finding.category, modelType: 'STRIDE', status: STATUS_OUT[finding.status],
    severity: SEVERITY_OUT[finding.severity] || 'TBD', description, mitigation, number, score: '',
  };
}

/** The review as a Threat Dragon v2 model, plus what the format cannot carry. Deterministic. */
export function toThreatDragon(model) {
  const omitted = {};
  const findings = new Map();
  let number = 0;
  for (const finding of model.threats) {
    if (finding.methodology !== 'STRIDE' || finding.target === 'system') { count(omitted, finding.target === 'system' ? 'systemFindings' : 'findings'); continue; }
    findings.set(finding.target, [...(findings.get(finding.target) || []), threatOut(finding, ++number)]);
  }
  const threatsOf = target => findings.get(target) || [];
  const open = threats => threats.some(t => t.status === 'Open');
  let z = 1;
  const cells = [];
  for (const zone of model.zones) {
    const members = model.nodes.filter(n => n.zone === zone.id);
    if (!members.length) { continue; }
    const x = Math.max(0, Math.min(...members.map(n => n.x)) - 20), y = Math.max(0, Math.min(...members.map(n => n.y)) - 45);
    const right = Math.max(...members.map(n => n.x + NODE.width)) + 20, bottom = Math.max(...members.map(n => n.y + NODE.height)) + 20;
    cells.push({
      id: 'z:' + zone.id, shape: 'trust-boundary-box', zIndex: -50, position: { x, y }, size: { width: right - x, height: bottom - y },
      attrs: { label: { text: zone.name } },
      data: { type: 'tm.BoundaryBox', name: zone.name, description: '', isTrustBoundary: true, hasOpenThreats: false },
    });
  }
  for (const node of model.nodes) {
    const shape = shapeOf(node.type), threats = threatsOf('n:' + node.id);
    cells.push({
      id: 'n:' + node.id, shape, zIndex: z++, position: { x: node.x, y: node.y }, size: { ...NODE },
      attrs: { text: { text: node.name } },
      data: {
        type: { actor: 'tm.Actor', process: 'tm.Process', store: 'tm.Store' }[shape], name: node.name,
        description: [node.type, node.physicalId].filter(Boolean).join('\n'),
        isTrustBoundary: false, outOfScope: false, reasonOutOfScope: '', hasOpenThreats: open(threats), threats,
      },
    });
  }
  for (const edge of model.edges) {
    if (edge.kind === 'dependency') { count(omitted, 'dependencies'); continue; }
    const threats = threatsOf('e:' + edge.id);
    cells.push({
      id: 'e:' + edge.id, shape: 'flow', zIndex: z++, source: { cell: 'n:' + edge.from }, target: { cell: 'n:' + edge.to }, vertices: [],
      labels: [{ attrs: { labelText: { text: edge.label } }, position: 0.5 }],
      data: {
        type: 'tm.Flow', name: edge.label, description: edge.evidence, isTrustBoundary: false, outOfScope: false, reasonOutOfScope: '',
        hasOpenThreats: open(threats), isBidirectional: false, isEncrypted: false, isPublicNetwork: false, protocol: '', threats,
      },
    });
  }
  for (const target of findings.keys()) {
    if (!model.nodes.some(n => 'n:' + n.id === target) && !model.edges.some(e => e.kind !== 'dependency' && 'e:' + e.id === target)) {
      omitted.findings = (omitted.findings || 0) + findings.get(target).length;
    }
  }
  const document = {
    version: VERSION,
    summary: { title: model.title, owner: '', description: [model.scope.account, model.scope.region, model.scope.stack].filter(Boolean).join(' · '), id: 0 },
    detail: {
      contributors: [], reviewer: '', diagramTop: 1, threatTop: number,
      diagrams: [{ id: 0, title: model.title, description: '', diagramType: 'STRIDE', placeholder: '', thumbnail: './public/content/images/thumbnail.stride.jpg', version: VERSION, cells }],
    },
  };
  return { document, omitted };
}

function findingIn(threat, target, index, skipped) {
  const category = M.STRIDE.find(c => c.toLowerCase() === text(threat.type).toLowerCase());
  if (!category) { count(skipped, 'threats'); return null; }
  let status = STATUS_IN[text(threat.status, 32).toLowerCase()] || 'open';
  const mitigation = text(threat.mitigation, 5000), note = text(threat.description, 5000);
  if (status !== 'open' && !(mitigation.trim() || note.trim())) { count(skipped, 'reopened'); status = 'open'; }
  return {
    id: text(threat.id, 200) || `${target}:${index}`, target, title: text(threat.title) || category, methodology: 'STRIDE', category, status,
    severity: SEVERITY_IN[text(threat.severity, 32).toLowerCase()] || 'unrated', mitigation, note, needsReview: true,
  };
}

/** A Threat Dragon v2 model as a design-only review. Every imported decision needs review. */
export function fromThreatDragon(input) {
  if (!isThreatDragon(input)) { fail('Expected a Threat Dragon v2 model'); }
  const diagrams = list(input.detail.diagrams, MAX.diagrams, 'diagrams');
  if (diagrams.reduce((sum, d) => sum + (Array.isArray(d.cells) ? d.cells.length : 0), 0) > MAX.cells) { fail(`Threat Dragon model exceeds ${MAX.cells} cells`); }
  const skipped = {};
  const nodes = [], edges = [], zones = [], threats = [], views = [];
  let offset = 0;
  for (const [index, diagram] of diagrams.entries()) {
    const cells = list(diagram.cells, MAX.cells, 'cells');
    const placed = [];
    for (const cell of cells) {
      const id = text(cell.id), type = SHAPE_IN[cell.shape];
      if (!type) { continue; }
      const x = Number(cell.position?.x), y = Number(cell.position?.y);
      const at = { x: Number.isFinite(x) ? x : 60, y: Number.isFinite(y) ? y : 100 };
      if (cell.data?.outOfScope === true) { count(skipped, 'outOfScope'); }
      placed.push({ id, ...at });
      nodes.push({ id, name: text(cell.data?.name) || text(cell.attrs?.text?.text) || type, type, status: 'PROPOSED', origin: 'human', physicalId: '', zone: '', x: at.x, y: at.y + offset });
      list(cell.data?.threats, MAX.threats, 'threats').forEach((t, i) => { const f = findingIn(t, 'n:' + id, i, skipped); if (f) { threats.push(f); } });
    }
    const ids = new Set(placed.map(n => n.id));
    for (const cell of cells) {
      if (cell.shape === 'flow') {
        const from = text(cell.source?.cell), to = text(cell.target?.cell), id = text(cell.id);
        if (!ids.has(from) || !ids.has(to) || from === to) {
          count(skipped, 'flows');
          list(cell.data?.threats, MAX.threats, 'threats').forEach(() => count(skipped, 'threats'));
          continue;
        }
        const label = text(cell.data?.name) || text(cell.labels?.[0]?.attrs?.labelText?.text);
        edges.push({ id, from, to, kind: 'proposed', label, evidence: 'Imported from Threat Dragon; deployment and delivery unverified' });
        list(cell.data?.threats, MAX.threats, 'threats').forEach((t, i) => { const f = findingIn(t, 'e:' + id, i, skipped); if (f) { threats.push(f); } });
      } else if (cell.shape === 'trust-boundary-box') {
        const x = Number(cell.position?.x), y = Number(cell.position?.y), w = Number(cell.size?.width), h = Number(cell.size?.height);
        if (![x, y, w, h].every(Number.isFinite)) { count(skipped, 'boundaries'); continue; }
        const zone = { id: text(cell.id), name: text(cell.data?.name) || text(cell.attrs?.label?.text) || 'Trust boundary', area: w * h };
        const inside = placed.filter(n => n.x >= x && n.y >= y && n.x + NODE.width / 2 <= x + w && n.y + NODE.height / 2 <= y + h);
        for (const member of inside) {
          const node = nodes.find(n => n.id === member.id), current = zones.find(z => z.id === node.zone);
          if (!current || zone.area < current.area) { node.zone = zone.id; }
        }
        zones.push(zone);
      } else if (!SHAPE_IN[cell.shape]) {
        count(skipped, cell.shape === 'trust-boundary-curve' ? 'boundaries' : 'cells');
      }
    }
    if (diagrams.length > 1 && placed.length) {
      views.push({ id: 'td:' + index, name: text(diagram.title) || `Diagram ${index + 1}`, nodeIds: placed.map(n => n.id), layout: placed });
    }
    offset = Math.max(offset, ...nodes.map(n => n.y)) + 200;
  }
  const used = new Set(nodes.map(n => n.zone));
  const model = M.validate({
    version: 2, documentType: 'review', source: 'design', id: 'threat-dragon:' + (text(input.summary.title, 200) || 'model'),
    title: text(input.summary.title) || 'Threat model', scope: {},
    zones: zones.filter(z => used.has(z.id)).map(({ id, name }) => ({ id, name })), nodes, edges, threats, views, unresolved: [],
    review: Review.fresh(),
  });
  return { model, skipped };
}
