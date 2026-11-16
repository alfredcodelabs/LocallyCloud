import test from 'node:test';
import assert from 'node:assert/strict';
import * as A from '../assessment.js';
import * as C from '../catalog.js';
import * as M from '../model.js';
import * as R from '../engine.js';
import { I18N } from '../i18n.js';
import { snapshot } from './fixture.mjs';

const fact = (id, value) => ({ id, value, evidence: `X.Properties.${id} (template)` });
function model() {
  const base = snapshot({ only: ['Queue', 'Worker', 'Mapping'] });
  base.nodes.push(
    { id: 'Ledger', name: 'Ledger', type: 'AWS::S3::Bucket', status: 'CREATE_COMPLETE', physicalId: 'ledger', facts: [fact('tls-only', 'enforced'), fact('public-access-block', 'enabled'), fact('resource-policy', 'restricted'), fact('versioning', 'enabled')] },
    { id: 'Open', name: 'Open', type: 'AWS::S3::Bucket', status: 'CREATE_COMPLETE', physicalId: 'open', facts: [fact('tls-only', 'not-declared'), fact('resource-policy', 'public')] },
    { id: 'Gone', name: 'Gone', type: 'AWS::S3::Bucket', status: 'DELETE_COMPLETE', physicalId: '' });
  base.nodes.find(n => n.id === 'Queue').facts = [fact('tls-only', 'enforced')];
  base.nodes.find(n => n.id === 'Worker').facts = [fact('role-privilege', 'unknown'), fact('reserved-concurrency', 'limited')];
  return M.validate(base);
}
const item = (items, id, target) => items.find(i => i.catalogId === id && i.target === target);

test('declared facts decide whether a catalog threat has a control gap, is declared or needs review', () => {
  const items = A.assess(model());
  assert.equal(item(items, 'LC-S3-I-002', 'n:Ledger').state, 'declared');
  assert.equal(item(items, 'LC-S3-I-002', 'n:Open').state, 'gap');
  assert.equal(item(items, 'LC-S3-I-001', 'n:Ledger').state, 'declared');
  assert.equal(item(items, 'LC-S3-I-001', 'n:Open').state, 'gap', 'a public policy is a gap even without a public access block fact');
  assert.equal(item(items, 'LC-LAMBDA-E-001', 'n:Worker').state, 'review', 'an unknown role stays to review');
  assert.equal(item(items, 'LC-LAMBDA-D-001', 'n:Worker').state, 'declared');
  assert.equal(item(items, 'LC-S3-T-002', 'n:Ledger').state, 'review', 'controls no fact can show are never declared');
  const control = item(items, 'LC-S3-I-002', 'n:Ledger').controls[0];
  assert.deepEqual(control.facts.map(f => [f.id, f.value, f.state]), [['tls-only', 'enforced', 'met']]);
  assert(!items.some(i => i.target === 'n:Gone'), 'deleted resources are not assessed');
  assert.deepEqual(items.slice(0, 2).map(i => i.state), ['gap', 'gap'], 'gaps come first');
});

test('flows read controls from the receiver and dependencies are not flows', () => {
  const items = A.assess(model());
  const flow = item(items, 'LC-FLOW-I-001', 'e:configured:Queue:Worker:event mapping');
  assert.equal(flow.state, 'review', 'the receiving function has no TLS fact');
  assert(!items.some(i => i.target.startsWith('e:dependency:')));
});

test('a recorded draft keeps the catalog identity, computed severity and evidence', () => {
  const current = model(), entry = item(A.assess(current), 'LC-S3-I-002', 'n:Open');
  const draft = A.draft(entry, 'es');
  assert.equal(draft.title, C.label(C.threat('LC-S3-I-002'), 'es'));
  assert.match(draft.note, /tls-only=not-declared/);
  const finding = { ...draft, id: 'f1', status: 'open', severity: 'note', owner: '', evidence: '', verification: 'pending', needsReview: false };
  const next = M.validate(R.finding({ ...current, threats: [finding] }, 'f1'));
  assert.equal(next.threats[0].severity, C.rate(C.threat('LC-S3-I-002').risk).severity);
  const linked = item(A.assess(next), 'LC-S3-I-002', 'n:Open');
  assert.deepEqual(linked.finding, { id: 'f1', status: 'open', needsReview: false });
  const group = A.summary(A.assess(next)).find(g => g.catalogId === 'LC-S3-I-002');
  assert.deepEqual([group.total, group.gap, group.declared, group.recorded], [2, 1, 1, 1]);
});

test('every fact and value a control cites has a label in each language', () => {
  for (const id of C.threatIds().flatMap(t => C.threat(t).controls)) {
    for (const e of C.control(id).evidence || []) {
      for (const language of ['en', 'es', 'pt']) {
        assert(I18N[language]['arFact_' + e.fact], `${language} arFact_${e.fact}`);
        for (const value of [...e.met, ...e.unmet]) { assert(I18N[language]['arFactValue_' + value], `${language} arFactValue_${value}`); }
      }
    }
  }
});
