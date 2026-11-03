import test from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../model.js';
import { demo, snapshot } from './fixture.mjs';

test('server snapshots validate unchanged in identity and evidence', () => {
  const s = M.validate(snapshot());
  assert.equal(s.version, 2);
  assert.equal(s.documentType, 'snapshot');
  assert.equal(s.nodes.length, 6);
  assert.equal(s.nodes.find(n => n.id === 'Worker').physicalId, 'worker-physical');
  assert(s.nodes.every(n => n.origin === 'captured' && n.zone === ''));
  assert(s.edges.some(e => e.from === 'Queue' && e.to === 'Worker' && e.kind === 'configured'));
  assert.deepEqual(M.validate(s), s);
});

test('a raw CloudFormation template is not an importable document', () => {
  assert.throws(() => M.importModel({ Resources: { Queue: { Type: 'AWS::SQS::Queue' } } }), /saved review/);
});

test('refresh of the same stack preserves decisions and marks them for re-review', () => {
  const review = M.validate(snapshot());
  review.zones = [{ id: 'private', name: 'Reviewer boundary' }]; review.nodes[0].zone = 'private'; review.nodes[0].x = 475;
  review.threats = [{ id: 't1', target: 'n:Queue', title: 'Replay review', category: 'Tampering', status: 'mitigated', severity: 'medium', mitigation: 'Idempotency tested', note: '', needsReview: false }];
  const validReview = M.validate(review);
  const refreshed = M.merge(validReview, M.validate(snapshot({ only: ['Worker'] })));
  assert.equal(refreshed.threats[0].target, 'n:Queue');
  assert(refreshed.threats[0].needsReview);
  assert.equal(refreshed.zones[0].name, 'Reviewer boundary');
  const kept = M.merge(validReview, M.validate(snapshot()));
  assert.equal(kept.nodes.find(n => n.id === 'Queue').x, 475);
  assert.equal(kept.nodes.find(n => n.id === 'Queue').zone, 'private');
  assert.equal(M.merge(validReview, M.validate(snapshot({ region: 'us-east-2' }))).threats.length, 0, 'other scope starts fresh');
  const restored = M.validate({ ...validReview, documentType: 'review' });
  assert.deepEqual(M.importModel(M.parse(JSON.stringify(restored))), restored);
});

test('template-typed saved documents never inherit decisions', () => {
  const declared = { ...snapshot(), documentType: 'template', source: 'template', id: 'template:1', scope: {} };
  const review = M.validate(declared);
  review.threats = [{ id: 't1', target: 'n:Queue', title: 'x', category: 'Tampering', status: 'open', severity: 'low', mitigation: '', note: '', needsReview: false }];
  assert.equal(M.merge(M.validate(review), M.validate(declared)).threats.length, 0);
});

test('design merge keeps proposed elements', () => {
  const design = demo();
  assert.equal(M.merge(structuredClone(design), structuredClone(design)).edges.length, design.edges.length);
});

test('schema limits and rejections', () => {
  const review = M.validate(snapshot());
  const threat = { id: 't1', target: 'n:Queue', title: 'Replay', category: 'Tampering', status: 'mitigated', severity: 'medium', mitigation: '', note: '' };
  assert.throws(() => M.validate({ ...review, threats: [threat] }), /rationale/);
  assert.throws(() => M.validate({ ...review, version: 9 }), /version/);
  assert.throws(() => M.validate({ ...review, documentType: 'script' }), /document type/);
  assert.throws(() => M.validate({ ...review, edges: [{ id: 'bad', from: 'Queue', to: 'missing', kind: 'configured' }] }), /endpoint/);
  assert.throws(() => M.validate({ ...review, nodes: Array.from({ length: 513 }, (_, i) => ({ id: String(i) })) }), /512/);
  assert.throws(() => M.validate({ ...review, nodes: [review.nodes[0], review.nodes[0]] }), /duplicate/);
  assert.throws(() => M.validate({ ...review, nodes: [null] }), /objects/);
  let deep = {}; for (let i = 0; i < 34; i++) { deep = { nested: deep }; }
  assert.throws(() => M.validate({ ...review, title: deep }), /depth/);
  assert.throws(() => M.parse(JSON.stringify(deep)), /depth/);
  assert.throws(() => M.parse(' '.repeat(M.LIMIT.bytes + 1)), /8 MiB/);
  assert.throws(() => M.parse('[' + '0,'.repeat(50001) + '0]'), /structure/);
});

test('hostile labels are kept as data and long fields are truncated', () => {
  const malicious = demo(); malicious.nodes[0].name = '<img src=x onerror=alert(1)>';
  assert.equal(M.validate(malicious).nodes[0].name, malicious.nodes[0].name);
  const long = demo(); long.nodes[0].name = 'x'.repeat(5000); long.title = 'y'.repeat(5000);
  const v = M.validate(long);
  assert.equal(v.nodes[0].name.length, 256); assert.equal(v.title.length, 256);
});

test('STRIDE prompts for components and flows', () => {
  assert(M.prompts(demo(), 'n:queue').some(p => p.category === 'Denial of service'));
  assert(M.prompts(demo(), 'e:demo-0').some(p => p.category === 'Spoofing'));
});

test('saved views filter the graph, keep separate layouts and share the review', () => {
  const withViews = snapshot();
  withViews.views = [{ id: 'ledger', name: 'Ledger', nodeIds: ['Worker', 'Table'], layout: [{ id: 'Worker', x: 900, y: 800 }] }, { id: 'delivery', name: 'Delivery', nodeIds: ['Worker', 'Queue'], layout: [{ id: 'Worker', x: 25, y: 50 }] }];
  const validViews = M.validate(withViews), ledger = M.view(validViews, 'ledger'), delivery = M.view(validViews, 'delivery');
  assert.equal(ledger.review, delivery.review); assert.equal(ledger.id, 'stack-1'); assert.deepEqual(ledger.scope, validViews.scope);
  assert.equal(ledger.nodes.find(n => n.id === 'Worker').x, 900);
  assert.equal(delivery.nodes.find(n => n.id === 'Worker').x, 25);
  assert.notEqual(validViews.nodes.find(n => n.id === 'Worker').x, 900);
  assert(ledger.edges.every(e => ledger.nodes.some(n => n.id === e.from) && ledger.nodes.some(n => n.id === e.to)));
  assert.equal(delivery.unresolved.length, 0);
  assert.equal(M.view(validViews, ''), validViews);
  assert.throws(() => M.view(validViews, 'missing'), /Unknown/);
  assert.deepEqual(M.merge(validViews, M.validate(snapshot())).views, validViews.views);
  assert.throws(() => M.validate({ ...snapshot(), views: [{ id: 'empty', name: 'Empty', nodeIds: [] }] }), /selection/);
  assert.throws(() => M.validate({ ...snapshot(), views: Array.from({ length: 33 }, (_, i) => ({ id: 'v' + i, name: 'v', nodeIds: ['Queue'] })) }), /32/);
});
