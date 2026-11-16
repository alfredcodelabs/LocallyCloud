import test from 'node:test';
import assert from 'node:assert/strict';
import * as A from '../assessment.js';
import * as M from '../model.js';
import * as R from '../engine.js';
import { snapshot } from './fixture.mjs';

const base = () => structuredClone(R.catalog);
const question = (id, extra = {}) => ({ id, stage: 0, scope: 'system', category: 'Spoofing', choices: ['yes', 'no'], after: [], title: id, explain: '', ...extra });

test('the question graph is data: references, scopes, choices and cycles are checked', () => {
  R.checkQuestions(base());
  assert.throws(() => R.checkQuestions([question('a', { after: [{ question: 'b', on: 'system' }] }), question('b', { after: [{ question: 'a', on: 'system' }] })]), /cycle/);
  assert.throws(() => R.checkQuestions([question('a', { when: { answer: 'b', on: 'system', is: ['yes'] } }), question('b', { when: { answer: 'a', on: 'system', is: ['yes'] } })]), /cycle/);
  assert.throws(() => R.checkQuestions([question('a', { after: [{ question: 'missing', on: 'system' }] })]), /unknown question/);
  assert.throws(() => R.checkQuestions([question('a'), question('b', { when: { answer: 'a', on: 'system', is: ['maybe'] } })]), /choice/);
  assert.throws(() => R.checkQuestions([question('a', { scope: 'flow' }), question('b', { scope: 'node', types: 'components', after: [{ question: 'a', on: 'target' }] })]), /scope/);
  assert.throws(() => R.checkQuestions([question('a', { scope: 'node', types: 'unknown-set' })]), /types/);
  assert.throws(() => R.checkQuestions([question('a', { choices: ['unknown'] })]), /choices/);
  assert.throws(() => R.checkQuestions([question('a'), question('a')]), /duplicate/);
  let deep = { answer: 'a', on: 'system', is: ['yes'] };
  for (let i = 0; i < 12; i++) { deep = { not: deep }; }
  assert.throws(() => R.checkQuestions([question('a'), question('b', { when: deep })]), /nested/);
});

test('visibility combines answers, facts and component types', () => {
  const definitions = [question('a'), question('b', { scope: 'node', types: 'components', when: { all: [{ answer: 'a', on: 'system', is: ['yes'] }, { fact: 'dead-letter', is: ['not-declared'] }] } })];
  R.checkQuestions(definitions);
  const model = M.validate(snapshot({ only: ['Queue'] }));
  model.nodes[0].facts = [{ id: 'dead-letter', value: 'not-declared', evidence: 'x' }];
  model.review.answers.push({ question: 'data', target: 'system', value: 'regulated', note: 'n', evidence: '', origin: 'human', needsReview: false });
  const when = definitions[1].when;
  assert.equal(R.matches(model, 'n:Queue', { fact: 'dead-letter', is: ['not-declared'] }), true);
  assert.equal(R.matches(model, 'n:Queue', when), false, 'answer a is missing');
  assert.equal(R.matches(model, 'n:Queue', { any: [{ answer: 'data', on: 'system', is: ['regulated'] }, when] }), true);
  model.review.answers[0].needsReview = true;
  assert.equal(R.matches(model, 'n:Queue', { answer: 'data', on: 'system', is: ['regulated'] }), true);
  assert.equal(R.matches(model, 'n:Queue', { answer: 'data', on: 'system', is: ['regulated'] }, true), false, 'current-only ignores answers awaiting review');
});

function answered(model, answers) {
  for (const [question, target, value] of answers) { model.review.answers.push({ question, target, value, note: 'reviewer', evidence: '', origin: 'human', needsReview: false }); }
  return M.validate(model);
}
const item = (items, id, target) => items.find(i => i.catalogId === id && i.target === target);

test('current answers adjust catalog risk deterministically, with a trace of the rules applied', () => {
  const plain = M.validate(snapshot({ only: ['Queue', 'Worker', 'Mapping'] }));
  const before = item(A.assess(plain), 'LC-SQS-I-001', 'n:Queue');
  assert.deepEqual([before.severity, before.baseSeverity, before.rules], ['low', 'low', []]);

  const reviewed = answered(structuredClone(plain), [['data', 'system', 'regulated'], ['access', 'n:Queue', 'public']]);
  const after = item(A.assess(reviewed), 'LC-SQS-I-001', 'n:Queue');
  assert.deepEqual(after.rules, ['LC-RULE-DATA-SENSITIVE', 'LC-RULE-DATA-REGULATED', 'LC-RULE-PUBLIC-ACCESS']);
  assert.equal(after.risk.impact.confidentiality, 9);
  assert.equal(after.risk.likelihood.opportunity, 9);
  assert.equal(after.baseSeverity, 'low');
  assert.notEqual(after.severity, 'low');
  assert.deepEqual(A.assess(reviewed), A.assess(structuredClone(reviewed)), 'same inputs, same assessment');
  assert.equal(A.draft(after, 'en').risk.impact.confidentiality, 9, 'a recorded finding keeps the adjusted factors');
  assert.deepEqual(item(A.assess(reviewed), 'LC-LAMBDA-D-001', 'n:Worker').rules, [], 'category-scoped rules leave other categories alone');

  const flow = 'e:configured:Queue:Worker:event mapping';
  const inside = answered(structuredClone(plain), [['boundary', flow, 'same-trust']]);
  const lowered = item(A.assess(inside), 'LC-FLOW-T-001', flow);
  assert.deepEqual(lowered.rules, ['LC-RULE-SAME-TRUST']);
  assert.equal(lowered.risk.likelihood.opportunity, 3);

  const stale = R.invalidate(reviewed);
  assert.deepEqual(item(A.assess(stale), 'LC-SQS-I-001', 'n:Queue').rules, [], 'answers awaiting review do not change risk');
});

test('the group severity is the highest of its items', () => {
  const reviewed = answered(M.validate(snapshot({ only: ['Queue', 'Worker', 'Mapping'] })), [['access', 'n:Queue', 'public']]);
  const items = A.assess(reviewed).filter(i => i.catalogId === 'LC-FLOW-T-001' || i.catalogId === 'LC-SQS-I-001');
  for (const group of A.summary(items)) {
    assert.equal(group.severity, group.items.map(i => i.severity).sort((a, b) => ['note', 'low', 'medium', 'high', 'critical'].indexOf(b) - ['note', 'low', 'medium', 'high', 'critical'].indexOf(a))[0]);
  }
});

test('every risk rule is localized', async () => {
  const C = await import('../catalog.js');
  for (const rule of C.riskRules()) {
    for (const language of ['en', 'es', 'pt']) { assert(rule.title[language], `${rule.id} ${language}`); }
  }
});
