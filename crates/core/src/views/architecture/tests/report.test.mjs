import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../catalog.js';
import * as M from '../model.js';
import * as Report from '../report.js';
import { I18N } from '../i18n.js';
import { snapshot } from './fixture.mjs';

const fact = (id, value, evidence = `X.Properties.${id} (template)`) => ({ id, value, evidence });
function model() {
  const base = snapshot({ only: ['Queue', 'Worker', 'Mapping'] });
  base.nodes.push(
    { id: 'Ledger', name: 'Ledger', type: 'AWS::S3::Bucket', status: 'CREATE_COMPLETE', physicalId: 'ledger', facts: [fact('tls-only', 'enforced'), fact('public-access-block', 'enabled'), fact('resource-policy', 'restricted'), fact('versioning', 'enabled')] },
    { id: 'Open', name: 'Open', type: 'AWS::S3::Bucket', status: 'CREATE_COMPLETE', physicalId: 'open', facts: [fact('tls-only', 'not-declared', 'Open|Policy <b> (template)'), fact('resource-policy', 'public')] },
    { id: 'Gone', name: 'Gone', type: 'AWS::S3::Bucket', status: 'DELETE_COMPLETE', physicalId: '' });
  base.nodes.find(n => n.id === 'Queue').facts = [fact('tls-only', 'enforced')];
  base.nodes.find(n => n.id === 'Worker').facts = [fact('role-privilege', 'unknown'), fact('reserved-concurrency', 'limited')];
  return M.validate(base);
}
const rank = (s) => [...C.SEVERITIES].reverse().indexOf(s);

test('the report lists only control gaps, ranked by severity, with the unmet evidence', () => {
  const report = Report.build(model(), 'en');
  assert.equal(report.format, Report.FORMAT);
  assert.equal(report.basis, 'declared-configuration');
  assert(report.findings.length > 0);
  assert(report.findings.every(f => f.element.name !== 'Ledger'), 'a resource with every control declared has no finding');
  assert(report.findings.every(f => f.element.name !== 'Gone'), 'deleted resources are not reported');
  for (let i = 1; i < report.findings.length; i++) {
    assert(rank(report.findings[i - 1].severity) <= rank(report.findings[i].severity), 'most severe first');
  }
  const tls = report.findings.find(f => f.rule === 'LC-S3-I-002' && f.element.name === 'Open');
  assert.deepEqual(tls.evidence.map(e => [e.fact, e.value]), [['tls-only', 'not-declared']]);
  assert(tls.recommendation.length > 0 && tls.recommendation.every(r => r.text));
  assert.equal(tls.decision, null);
  const total = Object.values(report.summary.findings).reduce((a, b) => a + b, 0);
  assert.equal(total, report.findings.length);
});

test('controls without a visible setting are grouped with their reason, not reported as findings', () => {
  const report = Report.build(model(), 'en');
  assert(report.unverified.length > 0);
  assert(report.unverified.every(u => ['no-fact', 'cannot-evaluate'].includes(u.reason) && u.elements > 0));
  const reasons = new Set(report.unverified.map(u => u.reason));
  assert(reasons.has('cannot-evaluate'), 'an unknown role privilege cannot be evaluated');
  assert(reasons.has('no-fact'));
});

test('the report covers the whole stack whatever saved view is open', () => {
  const m = model();
  m.views = [{ id: 'v', name: 'Only queue', nodeIds: ['Queue'], layout: [] }];
  const whole = Report.build(m, 'en');
  assert(whole.findings.some(f => f.element.name === 'Open'));
});

test('markdown keeps every table row intact and carries no raw HTML', () => {
  const report = Report.build(model(), 'es');
  const t = (key, vars = {}) => (I18N.es[key] ?? key).replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? '');
  const text = Report.markdown(report, { t, severity: s => I18N.es['arSeverity_' + s], category: c => c, status: s => s });
  assert(text.startsWith('# Reporte de seguridad: '));
  assert(!text.includes('<b>'), 'evidence is escaped');
  assert(text.includes('Open\\|Policy &lt;b&gt;'));
  for (const line of text.split('\n').filter(l => l.startsWith('|'))) {
    assert(line.endsWith(' |'), line);
  }
});

test('every report text exists in every language', () => {
  const keys = Object.keys(I18N.en).filter(k => k.startsWith('arReport'));
  assert(keys.length > 10);
  for (const language of Object.keys(I18N)) {
    for (const key of [...keys, 'arPhaseNote_report']) {
      assert(I18N[language][key], `${language}.${key}`);
    }
  }
});
