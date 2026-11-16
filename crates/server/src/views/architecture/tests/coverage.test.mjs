import test from 'node:test';
import assert from 'node:assert/strict';
import * as A from '../assessment.js';
import * as M from '../model.js';
import * as R from '../engine.js';
import { snapshot } from './fixture.mjs';

const fact = (id, value) => ({ id, value, evidence: `X.Properties.${id} (template)` });
const check = (result, id) => result.checks.find(c => c.id === id);
function model() {
  const base = snapshot({ only: ['Queue', 'Worker', 'Mapping'] });
  base.nodes.find(n => n.id === 'Queue').facts = [fact('dead-letter', 'not-declared')];
  return M.validate(base);
}

test('phases follow the four OWASP threat modeling questions and cover every review stage once', () => {
  assert.deepEqual(A.PHASES.map(p => p.id), ['scope', 'threats', 'responses', 'validation']);
  assert.deepEqual(A.PHASES.flatMap(p => p.stages).sort(), R.STAGES.map((_, i) => i));
});

test('coverage lists what is still missing, each item tied to its phase and targets', () => {
  let current = model();
  let result = A.coverage(current);
  assert.equal(result.ready, false);
  for (const c of result.checks) { assert(A.PHASES.some(p => p.id === c.phase), c.id); assert.equal(c.count, c.targets.length, c.id); }
  assert.deepEqual(check(result, 'unrecorded-gaps').targets, ['n:Queue']);
  assert.deepEqual(check(result, 'unzoned').targets.sort(), ['n:Queue', 'n:Worker']);
  assert.deepEqual(check(result, 'unresolved').targets, []);
  assert(check(result, 'scope-questions').targets.includes('system'));
  assert.equal(check(result, 'open-findings').count, 0);

  const gap = A.assess(current).find(i => i.state === 'gap');
  current = M.validate(R.finding({ ...current, threats: [{ ...A.draft(gap, 'en'), id: 'f1', status: 'open', severity: 'note', owner: '', evidence: '', verification: 'pending', needsReview: false }] }, 'f1'));
  result = A.coverage(current);
  assert.equal(check(result, 'unrecorded-gaps').count, 0, 'a recorded gap is no longer missing');
  assert.deepEqual(check(result, 'open-findings').targets, ['n:Queue']);

  current = R.invalidate(current);
  assert.deepEqual(check(A.coverage(current), 'needs-review').targets.includes('n:Queue'), true);
});

test('a removed target leaves its finding orphaned until a reviewer decides', () => {
  const current = model();
  const gap = A.assess(current).find(i => i.state === 'gap');
  const recorded = M.validate(R.finding({ ...current, threats: [{ ...A.draft(gap, 'en'), id: 'f1', status: 'open', severity: 'note', owner: '', evidence: '', verification: 'pending', needsReview: false }] }, 'f1'));
  const refreshed = M.merge(recorded, M.validate(snapshot({ only: ['Worker'] })));
  assert.deepEqual(check(A.coverage(refreshed), 'orphaned-findings').targets, ['n:Queue']);
});

test('every phase and coverage check has a label in each language', async () => {
  const { I18N } = await import('../i18n.js');
  const ids = A.coverage(model()).checks.map(c => c.id);
  for (const language of ['en', 'es', 'pt']) {
    for (const p of A.PHASES) { assert(I18N[language]['arPhase_' + p.id], `${language} ${p.id}`); assert(I18N[language]['arPhaseNote_' + p.id], `${language} note ${p.id}`); }
    for (const id of ids) { assert(I18N[language]['arCheck_' + id], `${language} ${id}`); }
  }
});
