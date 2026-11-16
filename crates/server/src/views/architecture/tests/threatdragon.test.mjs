import test from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../model.js';
import * as TD from '../threatdragon.js';
import { snapshot } from './fixture.mjs';

function review() {
  const base = M.validate(snapshot());
  base.zones = [{ id: 'app', name: 'Application' }];
  base.nodes.find(n => n.id === 'Queue').zone = 'app';
  base.nodes.find(n => n.id === 'Worker').zone = 'app';
  base.threats = [
    { id: 'f1', target: 'n:Queue', title: 'Messages stored unencrypted', methodology: 'STRIDE', category: 'Information disclosure', status: 'mitigated', severity: 'high', mitigation: 'Use SSE-KMS', owner: 'team', evidence: 'template', note: '' },
    { id: 'f2', target: 'e:configured:Queue:Worker:event mapping', title: 'Poison messages', methodology: 'STRIDE', category: 'Denial of service', status: 'open', severity: 'unrated', mitigation: '', note: 'Needs a DLQ' },
    { id: 'f3', target: 'system', title: 'No audit trail', methodology: 'STRIDE', category: 'Repudiation', status: 'open', severity: 'medium', mitigation: '', note: '' },
  ];
  return M.validate({ ...base, version: 2 });
}

const cell = (doc, id) => doc.detail.diagrams[0].cells.find(c => c.id === id);

test('export writes shapes, zones, data flows and recorded findings in Threat Dragon v2 shape', () => {
  const { document, omitted } = TD.toThreatDragon(review());
  assert.equal(document.version, TD.VERSION);
  assert.equal(document.detail.diagrams[0].diagramType, 'STRIDE');
  assert.equal(cell(document, 'n:Queue').shape, 'store');
  assert.equal(cell(document, 'n:Worker').shape, 'process');
  const queue = cell(document, 'n:Queue').data;
  assert.equal(queue.type, 'tm.Store');
  assert.equal(queue.hasOpenThreats, false);
  assert.deepEqual(queue.threats.map(t => [t.status, t.severity, t.type]), [['Mitigated', 'High', 'Information disclosure']]);
  assert.match(queue.threats[0].mitigation, /Owner: team/);
  const flow = cell(document, 'e:configured:Queue:Worker:event mapping');
  assert.deepEqual([flow.shape, flow.source.cell, flow.target.cell], ['flow', 'n:Queue', 'n:Worker']);
  assert.equal(flow.data.threats[0].severity, 'TBD');
  assert.equal(flow.data.hasOpenThreats, true);
  const zone = cell(document, 'z:app');
  assert.equal(zone.shape, 'trust-boundary-box');
  assert.ok(zone.size.width >= 200 && zone.size.height >= 105);
  assert.equal(document.detail.diagrams[0].cells.filter(c => c.shape === 'flow').length, 2);
  assert.deepEqual(omitted, { systemFindings: 1, dependencies: 3 });
  assert.equal(document.detail.threatTop, 2);
});

test('export is deterministic', () => {
  assert.equal(JSON.stringify(TD.toThreatDragon(review())), JSON.stringify(TD.toThreatDragon(review())));
});

test('round trip keeps components, flows, zones and findings, with every decision awaiting review', () => {
  const { model, skipped } = TD.fromThreatDragon(TD.toThreatDragon(review()).document);
  assert.deepEqual(skipped, {});
  assert.equal(model.source, 'design');
  assert.equal(model.nodes.find(n => n.id === 'n:Queue').type, 'Data store');
  assert.ok(model.nodes.every(n => n.status === 'PROPOSED' && n.origin === 'human'));
  assert.equal(model.nodes.find(n => n.id === 'n:Queue').zone, 'z:app');
  assert.equal(model.nodes.find(n => n.id === 'n:Table').zone, '');
  assert.equal(model.edges.length, 2);
  assert.ok(model.edges.every(e => e.kind === 'proposed'));
  assert.deepEqual(model.threats.map(t => [t.status, t.severity, t.needsReview]).sort(), [['mitigated', 'high', true], ['open', 'unrated', true]]);
});

const td = cells => ({ version: '2.2.0', summary: { title: 'Shop' }, detail: { contributors: [], reviewer: '', diagramTop: 1, threatTop: 0, diagrams: [{ id: 0, title: 'Main', diagramType: 'STRIDE', thumbnail: '', version: '2.2.0', cells }] } });
const node = (id, shape, x, y, threats = []) => ({ id, shape, zIndex: 1, position: { x, y }, size: { width: 160, height: 80 }, data: { type: 'tm.Process', name: id, hasOpenThreats: false, threats } });

test('import maps Threat Dragon statuses and severities and reports what it cannot carry', () => {
  const threats = [
    { title: 'A', type: 'Spoofing', status: 'Transferred', severity: 'Critical', description: 'd', mitigation: '' },
    { title: 'B', type: 'tampering', status: 'NotApplicable', severity: 'TBD', description: '', mitigation: '' },
    { title: 'C', type: 'Linkability', status: 'Open', severity: 'Low', description: '', mitigation: '' },
  ];
  const { model, skipped } = TD.fromThreatDragon(td([
    node('web', 'process', 300, 100, threats), node('user', 'actor', 0, 100), node('db', 'store', 600, 100),
    { id: 'f1', shape: 'flow', source: { cell: 'user' }, target: { cell: 'web' }, data: { type: 'tm.Flow', name: 'HTTPS', threats: [] } },
    { id: 'f2', shape: 'flow', source: { x: 1, y: 1 }, target: { cell: 'db' }, data: { type: 'tm.Flow', name: 'loose' } },
    { id: 'b1', shape: 'trust-boundary-box', position: { x: 250, y: 50 }, size: { width: 700, height: 300 }, data: { name: 'Backend' } },
    { id: 'b2', shape: 'trust-boundary-box', position: { x: 550, y: 50 }, size: { width: 300, height: 200 }, data: { name: 'Data' } },
    { id: 'c1', shape: 'trust-boundary-curve', source: { x: 0, y: 0 }, target: { x: 9, y: 9 } },
    { id: 't1', shape: 'td-text-block', data: { type: 'tm.Text' } },
  ]));
  assert.deepEqual(model.nodes.map(n => [n.id, n.type, n.zone]), [['web', 'Process', 'b1'], ['user', 'External actor', ''], ['db', 'Data store', 'b2']]);
  assert.deepEqual(model.edges.map(e => [e.from, e.to, e.label]), [['user', 'web', 'HTTPS']]);
  assert.deepEqual(model.threats.map(t => [t.category, t.status, t.severity]), [['Spoofing', 'accepted', 'critical'], ['Tampering', 'open', 'unrated']]);
  assert.deepEqual(skipped, { threats: 1, reopened: 1, flows: 1, boundaries: 1, cells: 1 });
});

test('several diagrams become saved views with their own layout', () => {
  const doc = td([node('a', 'process', 10, 10)]);
  doc.detail.diagrams.push({ ...doc.detail.diagrams[0], id: 1, title: 'Second', cells: [node('b', 'store', 10, 10)] });
  const { model } = TD.fromThreatDragon(doc);
  assert.deepEqual(model.views.map(v => [v.name, v.nodeIds]), [['Main', ['a']], ['Second', ['b']]]);
  assert.ok(model.nodes.find(n => n.id === 'b').y > model.nodes.find(n => n.id === 'a').y);
  assert.deepEqual(M.view(model, 'td:1').nodes.map(n => [n.x, n.y]), [[10, 10]]);
});

test('import rejects other documents and unbounded input', () => {
  assert.equal(TD.isThreatDragon(snapshot()), false);
  assert.throws(() => TD.fromThreatDragon({ version: 2 }), /Threat Dragon v2/);
  const many = td([]);
  many.detail.diagrams = Array.from({ length: 33 }, () => many.detail.diagrams[0]);
  assert.throws(() => TD.fromThreatDragon(many), /at most 32/);
  assert.throws(() => TD.fromThreatDragon(td(Array.from({ length: 4097 }, (_, i) => node('n' + i, 'process', 0, 0)))), /4096 cells/);
  assert.throws(() => TD.fromThreatDragon(td([node('x', 'process', 0, 0), node('x', 'store', 0, 0)])), /duplicate node/);
});
