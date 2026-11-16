import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../catalog.js';
import * as M from '../model.js';
import * as R from '../engine.js';
import { snapshot } from './fixture.mjs';

const flat = (likelihood, impact) => ({
  likelihood: Object.fromEntries(['skill', 'motive', 'opportunity', 'size', 'discovery', 'exploit', 'awareness', 'detection'].map(k => [k, likelihood])),
  impact: Object.fromEntries(['confidentiality', 'integrity', 'availability', 'accountability'].map(k => [k, impact])),
});

test('catalog entries are unique, localized and reference known controls and categories', () => {
  assert(C.threatIds().length >= 20);
  for (const id of C.threatIds()) {
    const t = C.threat(id);
    assert(C.methodology(t.methodology).categories.includes(t.category), id);
    assert(t.controls.every(c => C.control(c)), id);
    for (const language of ['en', 'es', 'pt']) { assert(t.title[language], `${id} ${language}`); }
    for (const ref of t.refs.owasp || []) { assert.match(ref, /^(A(0[1-9]|10):2025|API([1-9]|10):2023)$/, id); }
    for (const ref of t.refs.cwe || []) { assert.match(ref, /^CWE-\d+$/, id); }
    for (const ref of t.refs.capec || []) { assert.match(ref, /^CAPEC-\d+$/, id); }
  }
  for (const id of C.threatIds().flatMap(id => C.threat(id).controls)) {
    for (const ref of C.control(id).refs.asvs || []) { assert.match(ref, /^V([1-9]|1[0-7])$/, id); }
  }
});

test('review questions use catalog categories', () => {
  assert(R.catalog.every(q => M.STRIDE.includes(q.category)));
  assert.deepEqual(C.methodologyIds(), ['STRIDE']);
});

test('OWASP risk rating maps likelihood and impact to severity', () => {
  assert.equal(C.rate(flat(1, 1)).severity, 'note');
  assert.equal(C.rate(flat(7, 1)).severity, 'medium');
  assert.equal(C.rate(flat(4, 4)).severity, 'medium');
  assert.equal(C.rate(flat(1, 7)).severity, 'medium');
  assert.equal(C.rate(flat(7, 7)).severity, 'critical');
  const boundary = C.rate(flat(3, 6));
  assert.equal(boundary.likelihoodLevel, 'medium'); assert.equal(boundary.impactLevel, 'high'); assert.equal(boundary.severity, 'high');
  assert.throws(() => C.rate(flat(10, 1)), /0 to 9/);
  assert.throws(() => C.rate({ ...flat(1, 1), extra: {} }), /risk rating/);
  assert.throws(() => C.rate({ likelihood: { skill: 1 }, impact: flat(1, 1).impact }), /skill|motive/);
});

test('catalog findings compute severity and reject unknown or mismatched entries', () => {
  const review = M.validate(snapshot());
  const finding = { id: 't1', target: 'n:Queue', title: 'Plain text', category: 'Information disclosure', status: 'open', severity: 'low', mitigation: '', note: '' };
  const rated = M.validate({ ...review, threats: [{ ...finding, catalogId: 'LC-SQS-I-001', risk: flat(7, 7) }] }).threats[0];
  assert.equal(rated.severity, 'critical'); assert.equal(rated.methodology, 'STRIDE'); assert.equal(rated.catalogId, 'LC-SQS-I-001');
  const manual = M.validate({ ...review, threats: [finding] }).threats[0];
  assert.equal(manual.severity, 'low'); assert(!('catalogId' in manual) && !('risk' in manual));
  assert.throws(() => M.validate({ ...review, threats: [{ ...finding, catalogId: 'LC-INVENTED-001' }] }), /catalog/);
  assert.throws(() => M.validate({ ...review, threats: [{ ...finding, catalogId: 'LC-SQS-D-001' }] }), /catalog/);
  assert.throws(() => M.validate({ ...review, threats: [{ ...finding, methodology: 'DREAD' }] }), /methodology/);
  const saved = M.validate({ ...review, threats: [{ ...finding, catalogId: 'LC-SQS-I-001', risk: flat(2, 5) }] });
  assert.deepEqual(M.importModel(M.parse(JSON.stringify(saved))), saved);
});
