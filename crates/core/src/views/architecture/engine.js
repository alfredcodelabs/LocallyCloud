/* Deterministic review workflow shared by the dashboard page and the optional MCP companion.
   Pure functions: no DOM, no network, no storage. Every input is untrusted and bounded. */
export const CATALOG = 1;
export const STAGES = ['Context', 'Access and data', 'Trust boundaries', 'Risks', 'Decisions'];
const UNKNOWN = ['unknown', 'not-applicable'];
const COMPONENTS = new Set([
  'External actor', 'Process', 'Data store',
  'AWS::Lambda::Function', 'AWS::StepFunctions::StateMachine', 'AWS::SQS::Queue',
  'AWS::SNS::Topic', 'AWS::Events::EventBus', 'AWS::Events::Rule',
  'AWS::DynamoDB::Table', 'AWS::DynamoDB::GlobalTable', 'AWS::S3::Bucket',
  'AWS::ApiGateway::RestApi', 'AWS::ApiGatewayV2::Api',
  'AWS::Kinesis::Stream', 'AWS::KinesisFirehose::DeliveryStream',
]);
const ASYNC_COMPONENTS = new Set([
  'AWS::Lambda::Function', 'AWS::StepFunctions::StateMachine', 'AWS::SQS::Queue',
  'AWS::SNS::Topic', 'AWS::Events::Rule', 'AWS::Kinesis::Stream',
  'AWS::KinesisFirehose::DeliveryStream',
]);
export const catalog = [
  { id: 'purpose', stage: 0, title: 'What does this system do, and what must it protect?', kind: 'system', category: 'Tampering', choices: ['documented'], explain: 'Describe the business outcome and the impact of misuse.' },
  { id: 'actors', stage: 0, title: 'Who uses or supplies data to this system?', kind: 'system', category: 'Spoofing', choices: ['internal', 'customers', 'third-parties', 'public'], explain: 'Include operators and external systems, not only application users.', requires: 'purpose' },
  { id: 'data', stage: 1, title: 'What is the highest sensitivity of the data?', kind: 'system', category: 'Information disclosure', choices: ['public', 'internal', 'sensitive', 'regulated'], explain: 'Record what data is involved; do not paste actual personal data or secrets.', requires: 'actors' },
  { id: 'tenants', stage: 1, title: 'Does the system separate different customers or tenants?', kind: 'system', category: 'Elevation of privilege', choices: ['single', 'multiple'], explain: 'A shared AWS account does not establish tenant isolation.', requires: 'actors' },
  { id: 'isolation', stage: 1, title: 'How is access between tenants prevented?', kind: 'system', category: 'Elevation of privilege', choices: ['documented'], explain: 'Describe the enforcement point and tests, not just a tenant ID field.', branch: ['tenants', 'multiple'] },
  { id: 'access', stage: 1, title: 'Which identities may access this component?', kind: 'node', category: 'Elevation of privilege', choices: ['service-only', 'users', 'third-parties', 'public'], explain: 'Capture intended access. This importer does not evaluate IAM.', requires: 'actors' },
  { id: 'privilege', stage: 1, title: 'Are this component’s permissions limited to its task?', kind: 'node', category: 'Elevation of privilege', choices: ['declared', 'not-established'], explain: 'Name the permissions and scope to review. A declaration is not a verified control.', localRequires: 'access' },
  { id: 'boundary', stage: 2, title: 'Does this flow cross a trust boundary?', kind: 'flow', category: 'Spoofing', choices: ['crossing', 'same-trust'], explain: 'Compare identity, owner, tenant, exposure and isolation. Zone colors alone are not proof.', requires: 'actors' },
  { id: 'identity', stage: 2, title: 'How is the sender authenticated at this boundary?', kind: 'flow', category: 'Spoofing', choices: ['documented', 'not-established'], explain: 'Identify the receiving enforcement point and identity.', localBranch: ['boundary', 'crossing'] },
  { id: 'payload', stage: 3, title: 'How are untrusted payloads and replayed messages handled?', kind: 'flow', category: 'Tampering', choices: ['documented', 'not-established'], explain: 'Describe validation, size limits and replay protection.', localRequires: 'boundary' },
  { id: 'retries', stage: 3, title: 'Are retries, duplicates, failures and dead-letter handling bounded?', kind: 'async-node', category: 'Denial of service', choices: ['documented', 'not-established'], explain: 'Record retry budgets, idempotency and DLQ tests.', localRequires: 'access' },
  { id: 'audit', stage: 4, title: 'What evidence would demonstrate the intended controls?', kind: 'system', category: 'Repudiation', choices: ['documented'], explain: 'List tests, captures and owners. This answer does not verify those controls.', requires: 'data' },
];
const definitions = new Map(catalog.map(q => [q.id, q]));
function fail(message) { throw new Error(message); }
function object(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !keys.includes(k))) { fail('Unsupported object or field'); }
}
function string(value, max, required = false) {
  if (typeof value !== 'string' || value.length > max || (required && !value.trim())) { fail('Invalid or oversized text field'); }
  return value.trim();
}
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
function prerequisites(target, definition) {
  const found = new Set(), pending = [[target, definition]];
  while (pending.length) {
    const [scope, q] = pending.pop();
    for (const [nextTarget, id] of [['system', q.requires], [scope, q.localRequires], ['system', q.branch?.[0]], [scope, q.localBranch?.[0]]]) {
      const key = nextTarget + '|' + id;
      if (id && !found.has(key)) { found.add(key); pending.push([nextTarget, definitions.get(id)]); }
    }
  }
  return found;
}
export function questions(model, target = 'system') {
  if (!targetExists(model, target)) { return []; }
  const node = model.nodes.find(n => 'n:' + n.id === target), edge = model.edges.find(e => 'e:' + e.id === target);
  if (node && (!COMPONENTS.has(node.type) || ['NOT_RECORDED', 'CONDITIONAL_NOT_RECORDED', 'DELETE_COMPLETE'].includes(node.status))) { return []; }
  const kinds = new Set(['system']);
  if (node) { kinds.clear(); kinds.add('node'); if (ASYNC_COMPONENTS.has(node.type)) { kinds.add('async-node'); } }
  if (edge) { kinds.clear(); if (edge.kind !== 'dependency') { kinds.add('flow'); } }
  return catalog.filter(q => kinds.has(q.kind)).filter(q => {
    const branch = q.branch || q.localBranch;
    return !branch || (usablePrerequisite(answer(model, q.branch ? 'system' : target, branch[0])) && answer(model, q.branch ? 'system' : target, branch[0]).value === branch[1]);
  }).map(q => {
    const prerequisite = q.requires || q.localRequires;
    const inherited = [...prerequisites(target, q)].find(key => {
      const separator = key.lastIndexOf('|');
      const a = answer(model, key.slice(0, separator), key.slice(separator + 1));
      return a?.value === 'not-applicable' && !a.needsReview && !!a.note.trim();
    });
    const notApplicable = !!inherited;
    const prior = prerequisite ? answer(model, q.requires ? 'system' : target, prerequisite) : null;
    const blocked = notApplicable || (prerequisite && !usablePrerequisite(prior));
    const blockedReason = notApplicable ? `Not applicable: prerequisite ${inherited} has a current justified N/A. Change that answer to reopen this question.` : blocked ? 'Answer ' + prerequisite + ' first; unknown answers remain pending.' : '';
    return { ...q, choices: [...q.choices, ...UNKNOWN], target, notApplicable, prerequisiteNeedsReview: prior?.needsReview === true, blocked: !!blocked, blockedReason, answer: answer(model, target, q.id) || null };
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
export function invalidate(model) {
  const next = structuredClone(model);
  next.review = validate(next.review);
  if (next.review.revision >= Number.MAX_SAFE_INTEGER) { fail('Review revision exhausted'); }
  next.review.revision++;
  next.review.answers.forEach(a => { a.needsReview = true; });
  next.threats.forEach(t => { t.needsReview = true; });
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
