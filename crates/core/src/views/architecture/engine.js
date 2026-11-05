/* Deterministic review workflow shared by the dashboard page and the optional MCP companion.
   Pure functions: no DOM, no network, no storage. Every input is untrusted and bounded. */
import * as Catalog from './catalog.js';

export const CATALOG = 1;
export const STAGES = ['Context', 'Access and data', 'Trust boundaries', 'Risks', 'Decisions'];
const UNKNOWN = ['unknown', 'not-applicable'];
const SCOPES = ['system', 'node', 'flow'];
const INACTIVE = ['NOT_RECORDED', 'CONDITIONAL_NOT_RECORDED', 'DELETE_COMPLETE'];
const PREDICATE_DEPTH = 8;
/** Question definitions from the catalog: a DAG through `after` (blocking) and `when` (visibility). */
export const catalog = Catalog.questions().map(q => ({ ...q, after: q.after || [] }));
const definitions = new Map(catalog.map(q => [q.id, q]));
function fail(message) { throw new Error(message); }
function object(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !keys.includes(k))) { fail('Unsupported object or field'); }
}
function string(value, max, required = false) {
  if (typeof value !== 'string' || value.length > max || (required && !value.trim())) { fail('Invalid or oversized text field'); }
  return value.trim();
}
/** Validate a visibility predicate against `lookup` (question ID → definition). `scope` is the
    owner's scope, or null for target-neutral rules. */
export function validatePredicate(p, scope, lookup = definitions, depth = 0) {
  const keys = p && typeof p === 'object' && !Array.isArray(p) ? Object.keys(p) : [];
  if (depth > PREDICATE_DEPTH || !keys.length) { fail('Invalid or too deeply nested predicate'); }
  if (keys.length === 1 && ['all', 'any'].includes(keys[0])) {
    if (!Array.isArray(p[keys[0]]) || !p[keys[0]].length) { fail('Predicate lists need entries'); }
    p[keys[0]].forEach(item => validatePredicate(item, scope, lookup, depth + 1));
    return;
  }
  if (keys.length === 1 && keys[0] === 'not') { validatePredicate(p.not, scope, lookup, depth + 1); return; }
  const values = Array.isArray(p.is) && p.is.length && p.is.every(v => typeof v === 'string');
  if ('answer' in p) {
    object(p, ['answer', 'on', 'is']);
    const q = lookup.get(p.answer);
    const compatible = p.on === 'system' ? q?.scope === 'system' : p.on === 'target' && (scope === null || q?.scope === scope);
    if (!q || !compatible || !values || p.is.some(v => !q.choices.includes(v))) { fail(`Predicate on ${p.answer} has an unknown question, scope or choice`); }
    return;
  }
  object(p, ['fact', 'is']);
  if (typeof p.fact !== 'string' || !values || (scope !== null && scope !== 'node')) { fail('Fact predicates need a fact, values and a node'); }
}
/** Answers a question depends on, as [on, question] pairs: its `after` list and its `when` predicate. */
function dependencies(q) {
  const found = q.after.map(d => [d.on, d.question]), pending = q.when ? [q.when] : [];
  while (pending.length) {
    const p = pending.pop();
    if (p.answer) { found.push([p.on, p.answer]); }
    pending.push(...(p.all || []), ...(p.any || []), ...(p.not ? [p.not] : []));
  }
  return found;
}
/** Validate question definitions: fields, references, scopes and an acyclic dependency graph. */
export function checkQuestions(list) {
  const lookup = new Map();
  for (const q of list) {
    if (typeof q.id !== 'string' || !q.id || lookup.has(q.id)) { fail('Missing or duplicate question ID'); }
    lookup.set(q.id, q);
  }
  for (const q of list) {
    if (!Number.isInteger(q.stage) || !STAGES[q.stage] || !SCOPES.includes(q.scope) || !Catalog.methodology('STRIDE').categories.includes(q.category)) { fail(`Question ${q.id} has an invalid stage, scope or category`); }
    if ((q.scope === 'node') !== !!Catalog.typeSet(q.types) || !Array.isArray(q.after) || !q.choices?.length || q.choices.some(c => UNKNOWN.includes(c))) { fail(`Question ${q.id} has invalid types, prerequisites or choices`); }
    for (const d of q.after) { validatePredicate({ answer: d.question, on: d.on, is: lookup.get(d.question)?.choices || [] }, q.scope, lookup); }
    if (q.when) { validatePredicate(q.when, q.scope, lookup); }
  }
  // The graph must stay acyclic so prerequisites always resolve.
  const state = new Map();
  const visit = (id) => {
    if (state.get(id) === 'done') { return; }
    if (state.get(id) === 'open') { fail(`Question graph has a cycle through ${id}`); }
    state.set(id, 'open');
    dependencies(lookup.get(id)).forEach(([, question]) => visit(question));
    state.set(id, 'done');
  };
  list.forEach(q => visit(q.id));
}
checkQuestions(catalog);
export function fresh() { return { catalogVersion: CATALOG, revision: 0, legacy: false, answers: [] }; }
export function validate(input) {
  if (input == null) { return fresh(); }
  object(input, ['catalogVersion', 'revision', 'legacy', 'answers']);
  if (input.catalogVersion !== CATALOG || !Number.isSafeInteger(input.revision) || input.revision < 0 || !Array.isArray(input.answers) || input.answers.length > 4096) { fail('Unsupported review catalog, revision or answer count'); }
  const seen = new Set();
  const answers = input.answers.map(a => {
    object(a, ['question', 'target', 'value', 'note', 'evidence', 'origin', 'needsReview']);
    const q = definitions.get(a.question);
    if (!q || ![...q.choices, ...UNKNOWN].includes(a.value) || !['human', 'agent-reviewed', 'imported'].includes(a.origin) || typeof a.needsReview !== 'boolean') { fail('Invalid answer or provenance'); }
    const target = string(a.target, 1024, true), key = target + '|' + q.id;
    if (seen.has(key)) { fail('Duplicate answer'); } seen.add(key);
    const note = string(a.note, 5000), evidence = string(a.evidence, 5000);
    if (a.value !== 'unknown' && !note) { fail('Answers need context or a not-applicable rationale'); }
    return { question: q.id, target, value: a.value, note, evidence, origin: a.origin, needsReview: a.needsReview };
  });
  return { catalogVersion: CATALOG, revision: input.revision, legacy: input.legacy === true, answers };
}
export function targetExists(model, target) {
  return target === 'system' || model.nodes.some(n => 'n:' + n.id === target) || model.edges.some(e => 'e:' + e.id === target);
}
export function answer(model, target, question) { return model.review.answers.find(a => a.target === target && a.question === question); }
function resolved(a) { return a && !a.needsReview && !UNKNOWN.includes(a.value); }
function usablePrerequisite(a) { return a && !UNKNOWN.includes(a.value); }
const at = (on, target) => on === 'system' ? 'system' : target;
/** Evaluate a predicate for `target`. With `current`, answers awaiting review do not count. */
export function matches(model, target, p, current = false) {
  if (p.all) { return p.all.every(item => matches(model, target, item, current)); }
  if (p.any) { return p.any.some(item => matches(model, target, item, current)); }
  if (p.not) { return !matches(model, target, p.not, current); }
  if (p.answer) {
    const a = answer(model, at(p.on, target), p.answer);
    return usablePrerequisite(a) && (!current || !a.needsReview) && p.is.includes(a.value);
  }
  const fact = model.nodes.find(n => 'n:' + n.id === target)?.facts?.find(f => f.id === p.fact);
  return !!fact && p.is.includes(fact.value);
}
function prerequisites(target, definition) {
  const found = new Set(), pending = [[target, definition]];
  while (pending.length) {
    const [scope, q] = pending.pop();
    for (const [on, id] of dependencies(q)) {
      const nextTarget = at(on, scope), key = nextTarget + '|' + id;
      if (!found.has(key)) { found.add(key); pending.push([nextTarget, definitions.get(id)]); }
    }
  }
  return found;
}
export function questions(model, target = 'system') {
  if (!targetExists(model, target)) { return []; }
  const node = model.nodes.find(n => 'n:' + n.id === target), edge = model.edges.find(e => 'e:' + e.id === target);
  if (node && INACTIVE.includes(node.status)) { return []; }
  const scope = node ? 'node' : edge ? (edge.kind === 'dependency' ? null : 'flow') : 'system';
  return catalog.filter(q => q.scope === scope && (!node || Catalog.typeSet(q.types).includes(node.type)) && (!q.when || matches(model, target, q.when))).map(q => {
    const inherited = [...prerequisites(target, q)].find(key => {
      const separator = key.lastIndexOf('|');
      const a = answer(model, key.slice(0, separator), key.slice(separator + 1));
      return a?.value === 'not-applicable' && !a.needsReview && !!a.note.trim();
    });
    const notApplicable = !!inherited;
    const priors = q.after.map(d => answer(model, at(d.on, target), d.question));
    const waiting = q.after.find((d, i) => !usablePrerequisite(priors[i]));
    const blocked = notApplicable || !!waiting;
    const blockedReason = notApplicable ? `Not applicable: prerequisite ${inherited} has a current justified N/A. Change that answer to reopen this question.` : waiting ? 'Answer ' + waiting.question + ' first; unknown answers remain pending.' : '';
    return { ...q, choices: [...q.choices, ...UNKNOWN], target, notApplicable, prerequisiteNeedsReview: priors.some(a => a?.needsReview === true), blocked, blockedReason, waitingOn: waiting?.question || '', answer: answer(model, target, q.id) || null };
  });
}
export function pending(model) {
  const targets = ['system', ...model.nodes.map(n => 'n:' + n.id), ...model.edges.filter(e => e.kind !== 'dependency').map(e => 'e:' + e.id)];
  return targets.flatMap(t => questions(model, t)).filter(q => !q.notApplicable && !resolved(q.answer) && !(q.answer?.value === 'not-applicable' && !q.answer.needsReview));
}
export function finding(model, id) {
  const next = structuredClone(model), item = next.threats.find(t => t.id === id);
  if (!item || !targetExists(next, item.target)) { fail('Finding target must exist'); }
  if (item.status !== 'open' && !(item.note?.trim() || item.mitigation?.trim())) { fail('Closed decisions need a rationale'); }
  if (item.status === 'mitigated' && (!item.owner?.trim() || !item.evidence?.trim() || !item.mitigation?.trim())) { fail('Mitigated decisions need mitigation, owner and validation evidence'); }
  item.verification = item.evidence?.trim() ? 'recorded' : 'pending';
  next.review.revision++;
  if (!Number.isSafeInteger(next.review.revision)) { fail('Review revision exhausted'); }
  return next;
}
/** Re-open decisions for review: all of them, or only those on `targets` ('system', 'n:…', 'e:…'). */
export function invalidate(model, targets = null) {
  const next = structuredClone(model);
  next.review = validate(next.review);
  if (next.review.revision >= Number.MAX_SAFE_INTEGER) { fail('Review revision exhausted'); }
  next.review.revision++;
  const affected = (target) => !targets || targets.has(target);
  next.review.answers.forEach(a => { if (affected(a.target)) { a.needsReview = true; } });
  next.threats.forEach(t => { if (affected(t.target)) { t.needsReview = true; } });
  return next;
}
function answerCommand(model, input, origin) {
  object(input, ['type', 'target', 'question', 'value', 'note', 'evidence']);
  if (input.type !== 'answer' || !['human', 'agent-reviewed'].includes(origin)) { fail('Unsupported review command or authority'); }
  const next = structuredClone(model); next.review = validate(next.review);
  const q = questions(next, input.target).find(q => q.id === input.question);
  if (!q || q.blocked) { fail(q?.blockedReason || 'Question is not applicable to this target'); }
  const a = { question: q.id, target: q.target, value: input.value, note: input.note, evidence: input.evidence, origin, needsReview: false };
  validate({ ...fresh(), answers: [a] });
  if (next.review.revision >= Number.MAX_SAFE_INTEGER) { fail('Review revision exhausted'); }
  next.review.revision++;
  // Conservative invalidation: changing a prior answer can change the whole threat context.
  const old = answer(next, q.target, q.id);
  if (old && (old.value !== a.value || old.note !== a.note || old.evidence !== a.evidence)) {
    const parents = prerequisites(q.target, q);
    next.review.answers.forEach(item => { if (!parents.has(item.target + '|' + item.question)) { item.needsReview = true; } });
    next.threats.forEach(t => { t.needsReview = true; });
  }
  next.review.answers = next.review.answers.filter(item => item.target !== q.target || item.question !== q.id);
  next.review.answers.push(a); next.review = validate(next.review);
  return next;
}
function designCommand(model, input, origin) {
  const node = input.type === 'add-node';
  object(input, node ? ['type', 'id', 'name', 'kind'] : ['type', 'id', 'from', 'to', 'label']);
  if (typeof input.id !== 'string' || !/^[a-f0-9-]{36}$/.test(input.id)) { fail('Design changes require a UUID'); }
  if (model.nodes.some(n => n.id === input.id) || model.edges.some(e => e.id === input.id)) { fail('Duplicate design ID'); }
  const next = structuredClone(model);
  if (node) {
    if (next.nodes.length >= 512 || !['External actor', 'Process', 'Data store'].includes(input.kind)) { fail('Invalid proposed component kind or node limit'); }
    next.nodes.push({ id: input.id, name: string(input.name, 160, true), type: input.kind, status: 'PROPOSED', origin, physicalId: '', zone: '', x: 60, y: Math.max(0, ...next.nodes.map(n => n.y)) + 170 });
  } else {
    if (next.edges.length >= 2048 || input.from === input.to || !next.nodes.some(n => n.id === input.from) || !next.nodes.some(n => n.id === input.to)) { fail('Invalid proposed flow endpoints or edge limit'); }
    next.edges.push({ id: input.id, from: input.from, to: input.to, kind: 'proposed', label: string(input.label, 160, true), evidence: `${origin} proposed flow; deployment and delivery unverified` });
  }
  const affected = new Set();
  if (node && input.kind === 'External actor') { affected.add('system'); }
  if (!node) {
    affected.add('n:' + input.from); affected.add('n:' + input.to);
    for (const edge of next.edges) {
      if ([input.from, input.to].some(id => edge.from === id || edge.to === id)) { affected.add('e:' + edge.id); }
    }
    if (next.nodes.some(n => [input.from, input.to].includes(n.id) && n.type === 'External actor')) { affected.add('system'); }
  }
  next.review.revision++;
  if (!Number.isSafeInteger(next.review.revision)) { fail('Review revision exhausted'); }
  next.review.answers.forEach(a => {
    if ((a.target === 'system' && affected.has('system') && a.question === 'actors') || (a.target !== 'system' && affected.has(a.target))) { a.needsReview = true; }
  });
  next.threats.forEach(t => { if (affected.has(t.target)) { t.needsReview = true; } });
  return next;
}
const commands = new Map([['answer', answerCommand], ['add-node', designCommand], ['add-flow', designCommand]]);
export function command(model, input, origin = 'human') {
  if (!input || !commands.has(input.type) || !['human', 'agent-reviewed'].includes(origin)) { fail('Unsupported review command or authority'); }
  return commands.get(input.type)(model, input, origin);
}
function canonical(value) {
  if (Array.isArray(value)) { return value.map(canonical); }
  if (value && typeof value === 'object') { return Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])])); }
  return value;
}
export async function digest(model) {
  const value = structuredClone(model);
  // Layout changes are not security decisions and do not stale agent proposals.
  value.nodes.forEach(n => { delete n.x; delete n.y; });
  value.documentType = 'review';
  const bytes = new TextEncoder().encode(JSON.stringify(canonical(value)));
  return Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes)), n => n.toString(16).padStart(2, '0')).join('');
}
export async function proposal(model, input) {
  command(model, input, 'agent-reviewed'); // Validate without committing any result.
  return { documentType: 'review-proposal', version: 1, catalogVersion: CATALOG, baseRevision: model.review.revision, baseDigest: await digest(model), command: structuredClone(input) };
}
export async function checkProposal(model, p) {
  object(p, ['documentType', 'version', 'catalogVersion', 'baseRevision', 'baseDigest', 'command']);
  if (p.documentType !== 'review-proposal' || p.version !== 1 || p.catalogVersion !== CATALOG || p.baseRevision !== model.review.revision || p.baseDigest !== await digest(model)) { fail('Stale proposal or wrong model, catalog or version'); }
  return command(model, p.command, 'agent-reviewed');
}
