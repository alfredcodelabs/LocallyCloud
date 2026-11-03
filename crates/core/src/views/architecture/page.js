/* Architecture review page for the embedded dashboard, loaded on demand by dashboard.js.
   Security: model data reaches the DOM only through textContent and attributes, never HTML.
   Every file the user opens and every server response is untrusted, size-bounded and validated. */
import * as M from './model.js';
import * as R from './engine.js';
import { I18N } from './i18n.js';

const TOPOLOGY_URL = '/_locallycloud/views/architecture/topology';
const ICONS_URL = '/_locallycloud/icons.svg';
const SVG_NS = 'http://www.w3.org/2000/svg';
const PROPOSAL_BYTES = 65536;
const STACK_PAGES = 20;
const DESIGN_KINDS = ['External actor', 'Process', 'Data store'];
const ICONS = new Set(['acm', 'apigateway', 'athena', 'cloudformation', 'cloudfront', 'cloudtrail', 'cognito-idp', 'dynamodb', 'ec2', 'ecr', 'ecs',
  'elasticloadbalancing', 'events', 'firehose', 'glue', 'iam', 'kinesis', 'kms', 'lambda', 'logs', 'rds', 'route53', 's3', 'secretsmanager', 'sns',
  'sqs', 'ssm', 'states', 'wafv2', 'xray']);
const ICON_ALIASES = new Map([['apigatewayv2', 'apigateway'], ['cognito', 'cognito-idp'], ['kinesisfirehose', 'firehose'], ['stepfunctions', 'states'],
  ['elasticloadbalancingv2', 'elasticloadbalancing'], ['cloudwatch', 'logs'], ['scheduler', 'events'], ['pipes', 'events'], ['eventschemas', 'events']]);

function serviceIcon(type) {
  const service = type.split('::')[1]?.toLowerCase() || '';
  const id = ICON_ALIASES.get(service) || service;
  return ICONS.has(id) ? id : null;
}
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) { continue; }
    if (k === 'text') { e.textContent = v; } else if (k.startsWith('on')) { e[k] = v; } else { e.setAttribute(k === 'cls' ? 'class' : k, v === true ? '' : v); }
  }
  for (const c of kids.flat()) { if (c != null && c !== false) { e.append(c); } }
  return e;
}
function svg(tag, attrs = {}, text) {
  const e = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) { e.setAttribute(k, v); }
  if (text != null) { e.textContent = text; }
  return e;
}
function options(select, items, value) {
  select.replaceChildren(...items.map(([id, name]) => h('option', { value: id, text: name })));
  if (value != null) { select.value = value; }
}
const short = (value, limit = 24) => value.length > limit ? value.slice(0, limit - 1) + '…' : value;
const field = (label, control) => h('label', { cls: 'ar-field' }, h('span', { text: label }), control);

/**
 * Mount the page into `root`.
 * ctx: { t, lang, call, api, profile, region, stack, signal, contextual, homePath }
 * View strings come from ./i18n.js; any other key falls back to the dashboard catalog via ctx.t.
 * Returns { unmount, confirmLeave, relocalize }.
 */
export function mount(root, ctx) {
  root.classList.add('ar');
  const controller = new AbortController();
  const signal = AbortSignal.any([controller.signal, ctx.signal]);
  const timers = new Set(), urls = new Set();
  const unmounted = () => signal.aborted;
  const t = (key, vars = {}) => {
    const own = I18N[ctx.lang()]?.[key] ?? I18N.en[key];
    return own == null ? ctx.t(key, vars) : own.replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? '');
  };
  const tx = (key, fallback, vars) => { const value = t(key, vars); return value === key ? fallback : value; };
  const qTitle = (q) => tx('arQ_' + q.id, q.title);
  const qExplain = (q) => tx('arQx_' + q.id, q.explain);
  const choiceLabel = (v) => tx('arC_' + v, v.replaceAll('-', ' '));
  const strideLabel = (c) => tx('arS' + M.STRIDE.indexOf(c), c);
  const stageLabel = (i) => tx('arStage' + i, R.STAGES[i]);
  const kindLabel = (k) => tx('arKind_' + k, k);
  const designLabel = (k) => tx('arDesign' + DESIGN_KINDS.indexOf(k), k);
  const statusLabel = (s) => tx('arStatus_' + s, s);
  const severityLabel = (s) => tx('arSeverity_' + s, s);
  const originLabel = (o) => tx('arOrigin_' + o, o);
  const stackHref = (name) => ctx.contextual(ctx.homePath() + 'architecture/' + encodeURIComponent(name));

  const unload = (event) => { if (dirty) { event.preventDefault(); } };
  window.addEventListener('beforeunload', unload);
  function unmount() {
    controller.abort();
    window.removeEventListener('beforeunload', unload);
    timers.forEach(clearTimeout); timers.clear();
    urls.forEach((url) => URL.revokeObjectURL(url)); urls.clear();
    root.replaceChildren(); root.classList.remove('ar');
  }

  if (!ctx.stack) {
    const page = picker();
    return { unmount, confirmLeave: () => true, relocalize: () => { root.replaceChildren(); page(); } };
  }

  /* ---------- Stack picker: one allowed read, cloudformation DescribeStacks ---------- */
  function picker() {
    let stacks = null, failure = null, truncated = false;
    const draw = () => {
      const body = failure ? h('p', { cls: 'notice', role: 'alert', text: failure })
        : !stacks ? h('p', { cls: 'dim', role: 'status', text: t('loading') })
          : !stacks.length ? h('p', { cls: 'dim', text: t('arNoStacks') })
            : h('div', { cls: 'table' }, h('table', null,
              h('thead', null, h('tr', null, h('th', { scope: 'col', text: t('name') }), h('th', { scope: 'col', text: t('status') }))),
              h('tbody', null, stacks.map((s) => h('tr', null, h('td', null, h('a', { href: stackHref(s.StackName), text: s.StackName })), h('td', { text: s.StackStatus || '' }))))));
      root.replaceChildren(
        h('h2', { cls: 'title', text: t('arTitle') }),
        h('p', { cls: 'meta', text: t('arIntro') }),
        h('p', { cls: 'dim', text: t('arEvidenceNote') }),
        h('section', { cls: 'panel' }, h('div', { cls: 'phead' }, h('h2', { text: t('arChooseStack') })), body,
          truncated ? h('p', { cls: 'dim', text: t('arStacksTruncated') }) : null));
    };
    draw();
    (async () => {
      const all = []; let token;
      for (let page = 0; page < STACK_PAGES; page++) {
        const reply = await ctx.api('cloudformation', 'DescribeStacks', token ? { NextToken: token } : {});
        const items = reply.Stacks;
        all.push(...(Array.isArray(items) ? items : items ? [items] : []).filter((s) => s && typeof s.StackName === 'string'));
        const next = typeof reply.NextToken === 'string' && reply.NextToken ? reply.NextToken : undefined;
        if (!next || next === token) { break; }
        token = next;
        if (page === STACK_PAGES - 1) { truncated = true; }
      }
      stacks = all.sort((a, b) => a.StackName.localeCompare(b.StackName));
    })().catch((error) => { failure = error.auth ? t('authErr') : t('apiErr', { err: error.message }); })
      .finally(() => { if (!unmounted()) { draw(); } });
    return draw;
  }

  /* ---------- Review editor ---------- */
  let model = null, selected = '', editing = null, scale = 1, drag = null, activeView = '';
  let dirty = false, questionIndex = 0, proposal = null, loading = false, loadError = '';
  const $ = (id) => root.querySelector('#ar-' + id);
  const diagram = () => M.view(model, activeView);
  function changed() { dirty = true; proposal = null; }
  function topologyChanged() { model = R.invalidate(model); changed(); }
  function announce(message, error = false) {
    const notice = $('notice'); if (!notice) { return; }
    notice.textContent = message; notice.classList.toggle('ar-error', error); notice.setAttribute('role', error ? 'alert' : 'status');
  }
  const fail = (error) => announce(t('arError', { err: error.message || String(error) }), true);
  function hasDecisions(m) { return !!m && (m.review.answers.length > 0 || m.threats.length > 0 || m.zones.length > 0 || m.views.length > 0); }
  function targets() { const graph = diagram(); return [...graph.nodes.map((n) => ['n:' + n.id, n.name]), ...graph.edges.map((e) => ['e:' + e.id, `${e.from} → ${e.to} (${kindLabel(e.kind)})`])]; }
  function labelTarget(target) {
    const node = model.nodes.find((n) => 'n:' + n.id === target), edge = model.edges.find((e) => 'e:' + e.id === target);
    return node?.name || (edge ? `${edge.from} → ${edge.to} (${kindLabel(edge.kind)})` : t('arRemovedElement', { target }));
  }
  const evidenceLabel = (f) => t(f.verification === 'recorded' ? 'arEvidenceRecorded' : 'arEvidencePending');
  function questionName(id) { return tx('arQ_' + id, R.catalog.find((q) => q.id === id)?.title || id); }
  function prerequisiteName(key) {
    const split = key.lastIndexOf('|'), target = key.slice(0, split), id = key.slice(split + 1);
    return split < 0 ? questionName(key) : target === 'system' ? questionName(id) : `${questionName(id)} (${labelTarget(target)})`;
  }
  function blockedText(q) {
    if (q.notApplicable) { return t('arBlockedNA', { prerequisite: prerequisiteName(q.blockedReason.match(/prerequisite (\S+) has/)?.[1] || '') }); }
    return q.blocked ? t('arBlocked', { prerequisite: questionName(q.requires || q.localRequires || '') }) : '';
  }

  async function fetchTopology() {
    const reply = await ctx.call(TOPOLOGY_URL, {
      method: 'POST', signal, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile: ctx.profile, region: ctx.region, stack: ctx.stack }),
    });
    return M.validate(reply);
  }
  function topologyError(error) {
    if (error.status === 404 && !error.type) { return t('arUnavailable'); }
    if (error.type === 'ResourceNotFoundException') { return t('arStackNotFound', { stack: ctx.stack }); }
    if (error.auth) { return t('arDenied'); }
    return t('apiErr', { err: error.message || String(error) });
  }
  async function refresh(initial) {
    if (loading) { return; }
    loading = true; loadError = ''; if (!initial) { announce(t('arRefreshing')); } render();
    try {
      const next = await fetchTopology();
      if (unmounted()) { return; }
      if (model && hasDecisions(model) && !M.sameScope(model, next) && !confirm(t('arRefreshOtherScope'))) { announce(t('arRefreshCancelled')); return; }
      const previous = model;
      model = previous ? M.merge(previous, next) : next;
      dirty = dirty || hasDecisions(previous); proposal = null;
      if (!model.nodes.some((n) => 'n:' + n.id === selected) && !model.edges.some((e) => 'e:' + e.id === selected)) { selected = model.nodes[0] ? 'n:' + model.nodes[0].id : ''; }
      announce(t(previous ? (hasDecisions(previous) && M.sameScope(previous, next) ? 'arRefreshedKept' : 'arRefreshed') : 'arLoaded'));
    } catch (error) {
      if (unmounted()) { return; }
      loadError = topologyError(error);
      announce(loadError, true);
    } finally { loading = false; if (!unmounted()) { render(); } }
  }

  function build() {
    const stride = M.STRIDE.map((c) => [c, strideLabel(c)]);
    root.replaceChildren(
      h('div', { cls: 'phead ar-head' },
        h('div', { cls: 'ar-heading' }, h('h2', { cls: 'title', id: 'ar-title' }), h('p', { cls: 'meta', id: 'ar-scope' })),
        h('div', { cls: 'ar-actions' },
          h('button', { type: 'button', id: 'ar-refresh', text: t('arRefreshServer'), onclick: () => { if (!dirty || confirm(t('arConfirmRefresh'))) { refresh(false); } } }),
          h('label', { cls: 'ar-file' }, h('span', { text: t('arOpenJson') }), h('input', { id: 'ar-import', type: 'file', accept: 'application/json,.json', onchange: openReview })),
          h('button', { type: 'button', id: 'ar-save', text: t('arSaveJson'), onclick: saveReview }),
          h('button', { type: 'button', id: 'ar-export-svg', text: t('arExportSvg'), onclick: exportSvg }),
          h('a', { href: ctx.contextual(ctx.homePath() + 'architecture/'), text: t('arOtherStack') }))),
      h('p', { id: 'ar-notice', cls: 'ar-notice', role: 'status', 'aria-live': 'polite' }),
      h('p', { cls: 'dim ar-evidence', text: t('arEvidenceNote') }),
      h('p', { cls: 'dim', id: 'ar-counts' }),
      h('details', { cls: 'ar-box' }, h('summary', { text: t('arUnresolved') }), h('p', { cls: 'dim', text: t('arUnresolvedNote') }), h('ul', { id: 'ar-unresolved-list' })),
      h('div', { cls: 'ar-workspace', id: 'ar-workspace' },
        h('section', { cls: 'ar-diagram', 'aria-label': t('arCanvas') },
          h('div', { cls: 'ar-toolbar' },
            field(t('arSavedView'), h('select', { id: 'ar-saved-view', onchange: (e) => { activeView = e.target.value; selected = targets()[0]?.[0] || ''; questionIndex = 0; render(); } })),
            field(t('arFind'), h('input', { id: 'ar-search', type: 'search', placeholder: t('arFindPlaceholder'), oninput: renderGraph })),
            h('label', { cls: 'check' }, h('input', { id: 'ar-dependencies', type: 'checkbox', onchange: renderGraph }), h('span', { text: t('arDependencies') })),
            h('span', { cls: 'ar-zoom' },
              h('button', { type: 'button', 'aria-label': t('arZoomOut'), text: '−', onclick: () => { scale = Math.max(0.25, scale - 0.25); renderGraph(); } }),
              h('button', { type: 'button', 'aria-label': t('arZoomIn'), text: '+', onclick: () => { scale = Math.min(2.5, scale + 0.25); renderGraph(); } }),
              h('button', { type: 'button', text: t('arFit'), onclick: () => { scale = Math.max(0.25, Math.min(1, $('viewport').clientWidth / extent().width)); renderGraph(); $('viewport').scrollTo(0, 0); } }))),
          h('p', { cls: 'ar-legend' }, ['arLegendConfigured', 'arLegendProposed', 'arLegendDependency', 'arLegendZones'].map((k) => h('span', { text: t(k) }))),
          h('div', { id: 'ar-viewport', cls: 'ar-viewport', tabindex: '0', 'aria-label': t('arViewport') },
            svg('svg', { id: 'ar-canvas', preserveAspectRatio: 'xMinYMin meet', role: 'group', 'aria-label': t('arCanvasLabel') })),
          h('div', { cls: 'ar-below' },
            h('p', { cls: 'dim', text: t('arCanvasNote') }),
            h('details', { cls: 'ar-box' }, h('summary', { text: t('arSaveView') }), h('p', { cls: 'dim', text: t('arSaveViewNote') }),
              h('form', { id: 'ar-view-form', cls: 'ar-form', onsubmit: saveView },
                field(t('arViewName'), h('input', { id: 'ar-view-name', maxlength: '160', required: true })),
                field(t('arViewPrefix'), h('input', { id: 'ar-view-prefix', maxlength: '256' })),
                field(t('arViewResources'), h('select', { id: 'ar-view-resources', multiple: true, size: '5' })),
                h('button', { type: 'submit', text: t('arSaveViewButton') })),
              h('button', { type: 'button', id: 'ar-delete-view', disabled: true, text: t('arDeleteView'), onclick: deleteView })),
            h('details', { cls: 'ar-box' }, h('summary', { text: t('arAddFlow') }),
              h('form', { id: 'ar-flow-form', cls: 'ar-form ar-inline', onsubmit: addFlow },
                field(t('arFrom'), h('select', { id: 'ar-flow-from' })), field(t('arTo'), h('select', { id: 'ar-flow-to' })),
                field(t('arFlowLabel'), h('input', { id: 'ar-flow-label', maxlength: '160', required: true })),
                h('button', { type: 'submit', text: t('arAddFlowButton') }))),
            h('details', { cls: 'ar-box' }, h('summary', { text: t('arAddComponent') }),
              h('form', { id: 'ar-node-form', cls: 'ar-form ar-inline', onsubmit: addNode },
                field(t('name'), h('input', { id: 'ar-node-name', maxlength: '160', required: true })),
                field(t('arComponentKind'), h('select', { id: 'ar-node-type' }, DESIGN_KINDS.map((k) => h('option', { value: k, text: designLabel(k) })))),
                h('button', { type: 'submit', text: t('arAddComponentButton') }))))),
        h('aside', { id: 'ar-inspector', cls: 'ar-inspector', tabindex: '-1', 'aria-label': t('arInspector') },
          h('section', { cls: 'ar-guided', 'aria-label': t('arGuided') },
            h('h3', { text: t('arGuided') }), h('p', { id: 'ar-save-state', cls: 'dim', role: 'status' }),
            field(t('arReviewScope'), h('select', { id: 'ar-review-scope', onchange: () => { questionIndex = 0; renderReview(); } },
              h('option', { value: 'system', text: t('arWholeSystem') }), h('option', { value: 'element', text: t('arSelectedElement') }))),
            h('nav', { id: 'ar-review-steps', cls: 'ar-steps', 'aria-label': t('arSteps') }),
            h('p', { id: 'ar-review-progress', cls: 'dim', 'aria-live': 'polite' }),
            h('div', { id: 'ar-review-question' }),
            h('div', { cls: 'ar-actions' },
              h('button', { type: 'button', id: 'ar-previous-question', text: t('arPrevious'), onclick: () => { questionIndex--; renderReview(); $('question-heading')?.focus(); } }),
              h('button', { type: 'button', id: 'ar-next-question', text: t('arNext'), onclick: () => { questionIndex++; renderReview(); $('question-heading')?.focus(); } })),
            h('details', { cls: 'ar-box' }, h('summary', { text: t('arProposal') }),
              h('label', { cls: 'ar-file' }, h('span', { text: t('arOpenProposal') }), h('input', { id: 'ar-proposal-import', type: 'file', accept: 'application/json,.json', onchange: openProposal })),
              h('p', { id: 'ar-proposal-diff', cls: 'ar-pre' }),
              h('div', { cls: 'ar-actions' },
                h('button', { type: 'button', id: 'ar-proposal-accept', disabled: true, text: t('arAcceptProposal'), onclick: acceptProposal }),
                h('button', { type: 'button', id: 'ar-proposal-reject', disabled: true, text: t('arDiscardProposal'), onclick: () => { proposal = null; renderReview(); } })))),
          field(t('arInspect'), h('select', { id: 'ar-target', onchange: (e) => choose(e.target.value) })),
          h('h3', { id: 'ar-element-name', cls: 'ar-wrap' }), h('p', { id: 'ar-element-info', cls: 'ar-pre ar-mono' }),
          h('div', { id: 'ar-zone-editor' },
            field(t('arZone'), h('select', { id: 'ar-zone', onchange: setZone })),
            h('form', { id: 'ar-zone-form', cls: 'ar-form ar-inline', onsubmit: addZone },
              field(t('arNewZone'), h('input', { id: 'ar-zone-name', maxlength: '160', required: true, placeholder: t('arNewZonePlaceholder') })),
              h('button', { type: 'submit', text: t('arAddZone') }))),
          h('section', null, h('h3', null, t('arPrompts') + ' ', h('span', { cls: 'badge', text: t('arNotFindings') })), h('div', { id: 'ar-prompts' })),
          h('section', null, h('h3', { text: t('arThreats') }), h('div', { id: 'ar-threat-list' }),
            h('button', { type: 'button', text: t('arAddThreat'), onclick: () => openThreat() })),
          h('form', { id: 'ar-threat-form', cls: 'ar-form ar-threat-form', hidden: true, onsubmit: saveThreat },
            h('h3', { id: 'ar-form-title' }),
            field(t('arThreatTitle'), h('input', { id: 'ar-threat-title', maxlength: '256', required: true })),
            field(t('arCategory'), h('select', { id: 'ar-category' }, stride.map(([v, l]) => h('option', { value: v, text: l })))),
            h('div', { cls: 'ar-pair' },
              field(t('arSeverity'), h('select', { id: 'ar-severity' }, M.SEVERITIES.map((s) => h('option', { value: s, text: severityLabel(s) })))),
              field(t('status'), h('select', { id: 'ar-decision' }, M.STATUSES.map((s) => h('option', { value: s, text: statusLabel(s) }))))),
            field(t('arMitigation'), h('textarea', { id: 'ar-mitigation', maxlength: '5000', rows: '3' })),
            field(t('arOwner'), h('input', { id: 'ar-owner', maxlength: '256' })),
            field(t('arValidationEvidence'), h('textarea', { id: 'ar-finding-evidence', maxlength: '5000', rows: '2' })),
            field(t('arRationale'), h('textarea', { id: 'ar-note', maxlength: '5000', rows: '3' })),
            h('p', { cls: 'dim', text: t('arDecisionRules') }),
            h('div', { cls: 'ar-actions' }, h('button', { type: 'submit', text: t('arSaveDecision') }),
              h('button', { type: 'button', text: t('arCancel'), onclick: () => { $('threat-form').hidden = true; editing = null; } }))))),
      h('section', { cls: 'panel ar-register-panel', id: 'ar-register-panel' }, h('div', { cls: 'phead' }, h('h2', { text: t('arRegister') })),
        h('p', { cls: 'dim', text: t('arRegisterNote') }),
        h('div', { cls: 'table' }, h('table', { cls: 'ar-register' },
          h('thead', null, h('tr', null, ['arThreat', 'arElement', 'arCategory', 'arDecision', 'arFreshness'].map((k) => h('th', { scope: 'col', text: t(k) })))),
          h('tbody', { id: 'ar-register' })))),
    );
    const canvas = $('canvas');
    canvas.onpointerdown = (event) => {
      if (event.button !== 0) { return; }
      const group = event.target.closest('[data-node]'); if (!group) { return; }
      const node = diagram().nodes.find((n) => n.id === group.dataset.node), p = new DOMPoint(event.clientX, event.clientY).matrixTransform(canvas.getScreenCTM().inverse());
      if (!node) { return; }
      drag = { node, dx: p.x - node.x, dy: p.y - node.y }; canvas.setPointerCapture(event.pointerId);
    };
    canvas.onpointermove = (event) => {
      if (!drag) { return; }
      const p = new DOMPoint(event.clientX, event.clientY).matrixTransform(canvas.getScreenCTM().inverse());
      drag.node.x = Math.max(25, Math.min(10000, p.x - drag.dx)); drag.node.y = Math.max(50, Math.min(10000, p.y - drag.dy));
      if (activeView) {
        const current = model.views.find((v) => v.id === activeView), position = current.layout.find((n) => n.id === drag.node.id);
        if (position) { position.x = drag.node.x; position.y = drag.node.y; } else { current.layout.push({ id: drag.node.id, x: drag.node.x, y: drag.node.y }); }
      } else {
        const node = model.nodes.find((n) => n.id === drag.node.id); node.x = drag.node.x; node.y = drag.node.y;
      }
      renderGraph();
      dirty = true; $('save-state').textContent = t('arUnsavedLayout');
    };
    canvas.onpointerup = (event) => { if (drag) { drag = null; canvas.releasePointerCapture(event.pointerId); } };
    canvas.onpointercancel = () => { drag = null; };
  }

  function extent() {
    const graph = diagram();
    return { width: Math.max(1080, ...graph.nodes.map((n) => n.x + 245)), height: Math.max(540, ...graph.nodes.map((n) => n.y + 150)) };
  }
  function renderGraph() {
    const graph = diagram(), canvas = $('canvas'), { width, height } = extent();
    canvas.setAttribute('viewBox', `0 0 ${width} ${height}`);
    canvas.style.width = `${scale * width}px`; canvas.style.height = `${scale * height}px`;
    const defs = svg('defs'), marker = svg('marker', { id: 'ar-arrow', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse' });
    marker.append(svg('path', { d: 'M 0 0 L 10 5 L 0 10', fill: 'none', stroke: 'context-stroke', 'stroke-width': 1.5 })); defs.append(marker);
    canvas.replaceChildren(defs);
    for (const zone of model.zones) {
      const nodes = graph.nodes.filter((n) => n.zone === zone.id); if (!nodes.length) { continue; }
      const x = Math.max(0, Math.min(...nodes.map((n) => n.x)) - 20), y = Math.max(0, Math.min(...nodes.map((n) => n.y)) - 45);
      const right = Math.max(...nodes.map((n) => n.x + 200)) + 20, bottom = Math.max(...nodes.map((n) => n.y + 105)) + 20;
      canvas.append(svg('rect', { x, y, width: right - x, height: bottom - y, rx: 8, class: 'ar-zone-box' }), svg('text', { x: x + 10, y: y + 20, class: 'ar-zone-label' }, short(zone.name, 60)));
    }
    const nodesById = new Map(graph.nodes.map((n) => [n.id, n]));
    const showDependencies = $('dependencies').checked;
    for (const edge of graph.edges) {
      if (edge.kind === 'dependency' && !showDependencies) { continue; }
      const from = nodesById.get(edge.from), to = nodesById.get(edge.to);
      const vertical = Math.abs(to.y - from.y) > Math.abs(to.x - from.x);
      const forward = vertical ? to.y > from.y : to.x > from.x;
      const x1 = vertical ? from.x + 100 : from.x + (forward ? 204 : -4), y1 = vertical ? from.y + (forward ? 109 : -4) : from.y + 52;
      const x2 = vertical ? to.x + 100 : to.x + (forward ? -4 : 204), y2 = vertical ? to.y + (forward ? -4 : 109) : to.y + 52;
      let d = vertical ? `M${x1} ${y1} V${(y1 + y2) / 2} H${x2} V${y2}` : `M${x1} ${y1} H${(x1 + x2) / 2} V${y2} H${x2}`;
      let labelX = vertical ? x1 + 12 : (x1 + x2) / 2, labelY = vertical ? (y1 + y2) / 2 : Math.min(y1, y2) - 66;
      const blockers = graph.nodes.filter((n) => n.id !== from.id && n.id !== to.id && n.x < Math.max(x1, x2) && n.x + 200 > Math.min(x1, x2) && n.y < Math.max(y1, y2) + 1 && n.y + 105 > Math.min(y1, y2) - 1);
      if (!vertical && blockers.length) {
        // One upper corridor; a general obstacle router is deferred for dense diagrams.
        const corridor = Math.max(20, Math.min(from.y, to.y, ...blockers.map((n) => n.y)) - 35);
        const exit1 = x1 + (forward ? 12 : -12), exit2 = x2 + (forward ? -12 : 12);
        d = `M${x1} ${y1} H${exit1} V${corridor} H${exit2} V${y2} H${x2}`;
        labelX = (exit1 + exit2) / 2; labelY = corridor - 10;
      }
      const target = 'e:' + edge.id;
      const g = svg('g', { class: `ar-edge ${edge.kind}${selected === target ? ' selected' : ''}`, 'data-edge': edge.id, role: 'button', tabindex: 0, 'aria-label': labelTarget(target) });
      const boundary = R.answer(model, target, 'boundary');
      const boundaryLabel = boundary?.value === 'crossing' ? ' · ' + t(boundary.needsReview ? 'arBoundaryReview' : 'arBoundary') : '';
      g.append(svg('path', { d, 'marker-end': 'url(#ar-arrow)' }), svg('path', { d, class: 'hit' }), svg('text', { x: labelX, y: labelY, 'text-anchor': vertical ? 'start' : 'middle' }, edge.label + boundaryLabel));
      g.addEventListener('click', () => choose(target)); g.addEventListener('keydown', (event) => activate(event, target)); canvas.append(g);
    }
    const query = $('search').value.toLowerCase();
    for (const node of graph.nodes) {
      const target = 'n:' + node.id, dim = query && !`${node.name} ${node.type}`.toLowerCase().includes(query);
      const g = svg('g', { transform: `translate(${node.x} ${node.y})`, class: `ar-node${selected === target ? ' selected' : ''}${dim ? ' dim' : ''}`, 'data-node': node.id, role: 'button', tabindex: 0, 'aria-label': `${node.name}, ${node.type}, ${node.status}` });
      const icon = serviceIcon(node.type);
      g.append(svg('rect', { width: 200, height: 105, rx: 6 }));
      if (icon) { g.append(svg('use', { href: `${ICONS_URL}#${icon}`, x: 14, y: 18, width: 14, height: 14, 'aria-hidden': 'true' })); }
      g.append(svg('text', { x: icon ? 36 : 14, y: 30, class: 'mark' }, node.type.split('::')[1] || node.type), svg('text', { x: 14, y: 58 }, short(node.name)),
        svg('text', { x: 14, y: 77, class: 'type' }, short(node.type, 30)), svg('text', { x: 14, y: 94, class: 'status' }, short(node.status, 29)), svg('title', {}, `${node.name}\n${node.type}\n${node.status}`));
      g.addEventListener('click', () => choose(target)); g.addEventListener('keydown', (event) => activate(event, target)); canvas.append(g);
    }
  }
  function activate(event, target) { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); choose(target); $('target').focus(); } }
  function choose(target) {
    if (activeView && !targets().some(([id]) => id === target)) { activeView = ''; }
    selected = target; questionIndex = 0; editing = null; $('threat-form').hidden = true; render();
  }
  function openThreat(finding = null, prompt = null) {
    editing = finding?.id || null; $('threat-form').hidden = false;
    $('form-title').textContent = t(finding ? 'arEditThreat' : 'arNewThreat');
    $('threat-title').value = finding?.title || prompt?.title || '';
    $('category').value = finding?.category || prompt?.category || M.STRIDE[0];
    $('decision').value = finding?.status || 'open'; $('severity').value = finding?.severity || 'unrated';
    $('mitigation').value = finding?.mitigation || ''; $('note').value = finding?.note || prompt?.note || '';
    $('owner').value = finding?.owner || ''; $('finding-evidence').value = finding?.evidence || '';
    $('threat-title').focus();
  }
  function renderInspector() {
    const node = model.nodes.find((n) => 'n:' + n.id === selected), edge = model.edges.find((e) => 'e:' + e.id === selected);
    options($('target'), targets(), selected); $('element-name').textContent = selected ? labelTarget(selected) : '';
    $('element-info').textContent = node ? `${node.type}\n${node.status}\n${t('arOrigin')}: ${originLabel(node.origin)}\n${node.id}${node.physicalId ? '\n' + node.physicalId : ''}`
      : edge ? `${kindLabel(edge.kind)}\n${edge.evidence}` : selected ? t('arAbsentElement') : '';
    $('zone-editor').hidden = !node;
    options($('zone'), [['', t('arUnassigned')], ...model.zones.map((z) => [z.id, z.name])], node?.zone || '');
    $('prompts').replaceChildren(...M.prompts(model, selected).map((p) => {
      const prompt = { category: p.category, title: tx('arQ_' + p.id, p.title), note: tx('arQx_' + p.id, p.note) };
      return h('div', { cls: 'ar-card' }, h('strong', { text: strideLabel(p.category) }), h('p', { text: prompt.title }),
        h('button', { type: 'button', text: t('arReviewQuestion'), onclick: () => openThreat(null, prompt) }));
    }));
    const findings = model.threats.filter((f) => f.target === selected);
    $('threat-list').replaceChildren(...(findings.length ? findings.map((f) => h('div', { cls: 'ar-card' }, h('strong', { text: f.title }),
      h('p', { text: [severityLabel(f.severity), statusLabel(f.status), evidenceLabel(f), f.needsReview ? t('arNeedsReview') : ''].filter(Boolean).join(' · ') }),
      h('button', { type: 'button', text: t('arEditDecision'), onclick: () => openThreat(f) }))) : [h('p', { cls: 'dim', text: t('arNoFindings') })]));
  }
  function sourceLabel() {
    return t(model.source === 'snapshot' ? 'arSourceSnapshot' : model.source === 'demo' ? 'arSourceDemo' : 'arSourceDesign');
  }
  function render() {
    if (unmounted()) { return; }
    $('refresh').disabled = loading;
    $('save').disabled = !model; $('export-svg').disabled = !model;
    $('workspace').hidden = !model; $('register-panel').hidden = !model;
    if (!model) {
      $('title').textContent = ctx.stack; $('scope').textContent = loading ? t('loading') : loadError;
      $('counts').textContent = ''; $('unresolved-list').replaceChildren();
      return;
    }
    if (!model.views.some((v) => v.id === activeView)) { activeView = ''; }
    const graph = diagram();
    if (activeView && !targets().some(([id]) => id === selected)) { selected = targets()[0]?.[0] || ''; }
    options($('saved-view'), [['', t('arWholeStack')], ...model.views.map((v) => [v.id, v.name])], activeView);
    $('delete-view').disabled = !activeView;
    const resources = $('view-resources');
    if ([...resources.options].map((o) => o.value).join('|') !== model.nodes.map((n) => n.id).join('|')) { options(resources, model.nodes.map((n) => [n.id, n.name])); }
    $('title').textContent = model.title;
    $('scope').textContent = [sourceLabel(), model.scope.account, model.scope.region, model.scope.capturedAt].filter(Boolean).join(' · ');
    $('counts').textContent = t('arCounts', { shown: graph.nodes.length, total: model.nodes.length, edges: graph.edges.length, unresolved: graph.unresolved.length, open: model.threats.filter((f) => f.status === 'open').length });
    $('unresolved-list').replaceChildren(...graph.unresolved.map((u) => h('li', { text: `${u.target} · ${u.property}: ${u.reason}` })));
    options($('flow-from'), model.nodes.map((n) => [n.id, n.name]), $('flow-from').value); options($('flow-to'), model.nodes.map((n) => [n.id, n.name]), $('flow-to').value);
    const present = new Set([...model.nodes.map((n) => 'n:' + n.id), ...model.edges.map((e) => 'e:' + e.id)]);
    $('register').replaceChildren(...model.threats.map((f) => h('tr', null,
      h('td', null, h('button', { type: 'button', cls: 'link', text: f.title, onclick: () => { choose(f.target); openThreat(f); $('inspector').scrollIntoView({ block: 'nearest' }); } })),
      h('td', { text: labelTarget(f.target) }), h('td', { text: strideLabel(f.category) }),
      h('td', { text: `${statusLabel(f.status)} / ${severityLabel(f.severity)} · ${evidenceLabel(f)}` }),
      h('td', { text: t(!present.has(f.target) ? 'arTargetRemoved' : f.needsReview ? 'arNeedsReview' : 'arRecorded') }))));
    if (!model.threats.length) { $('register').append(h('tr', null, h('td', { colspan: '5', cls: 'dim', text: t('arNoRegister') }))); }
    renderGraph(); renderInspector(); renderReview();
  }
  function reviewQuestions() { return R.questions(model, $('review-scope').value === 'system' ? 'system' : selected); }
  function renderReview() {
    $('save-state').textContent = t(dirty ? 'arUnsaved' : 'arExplicitSave');
    const list = reviewQuestions(); questionIndex = Math.max(0, Math.min(questionIndex, list.length - 1));
    const current = list[questionIndex], box = $('review-question'); box.replaceChildren();
    const graph = diagram();
    $('review-steps').replaceChildren(...R.STAGES.map((_, stage) => {
      const destination = ['system', selected, ...graph.nodes.map((n) => 'n:' + n.id), ...graph.edges.map((e) => 'e:' + e.id)].find((target) => R.questions(graph, target).some((q) => q.stage === stage));
      return h('button', { type: 'button', 'aria-current': current?.stage === stage ? 'step' : 'false', disabled: !destination, text: `${stage + 1}. ${stageLabel(stage)}`, onclick: () => {
        if (!list.some((q) => q.stage === stage)) {
          $('review-scope').value = destination === 'system' ? 'system' : 'element';
          if (destination !== 'system') { selected = destination; }
        }
        questionIndex = reviewQuestions().findIndex((q) => q.stage === stage); render(); $('question-heading')?.focus();
      } });
    }));
    const confirmed = list.filter((q) => !q.notApplicable && q.answer && !q.answer.needsReview && q.answer.value !== 'unknown').length;
    const inherited = list.filter((q) => q.notApplicable).length;
    const unknown = list.filter((q) => !q.notApplicable && q.answer?.value === 'unknown').length;
    $('review-progress').textContent = t(activeView ? 'arProgressView' : 'arProgress', { confirmed, applicable: list.length - inherited, inherited, unknown, pending: R.pending(graph).length });
    if (model.review.legacy) { box.append(h('p', { cls: 'dim', text: t('arLegacy') })); }
    if (!current) { box.append(h('p', { cls: 'dim', text: t('arNoQuestions') })); }
    if (current) {
      box.append(h('h4', { id: 'ar-question-heading', tabindex: '-1', text: `${questionIndex + 1}. ${qTitle(current)}` }), h('p', { cls: 'dim', text: qExplain(current) }),
        h('p', { cls: 'dim', text: t('arRule', { category: strideLabel(current.category), id: current.id, version: R.CATALOG }) }));
      if (current.blocked) { box.append(h('p', { role: 'status', text: blockedText(current) })); }
      if (current.prerequisiteNeedsReview && !current.blocked) { box.append(h('p', { role: 'status', text: t('arPrerequisiteReview') })); }
      if (current.answer) {
        const state = current.answer.needsReview ? 'arAnswerReview' : current.answer.value === 'unknown' ? 'arAnswerUnknown' : 'arAnswerRecorded';
        box.append(h('p', { cls: 'dim', text: `${t('arOrigin')}: ${originLabel(current.answer.origin)} · ${t(state)}` }));
      }
      const choice = h('select', { id: 'ar-answer-value', required: true });
      options(choice, [['', t('arChooseAnswer')], ...current.choices.map((v) => [v, choiceLabel(v)])], current.answer?.value || '');
      const note = h('textarea', { id: 'ar-answer-note', rows: '3', maxlength: '5000' }); note.value = current.answer?.note || '';
      const evidence = h('textarea', { id: 'ar-answer-evidence', rows: '2', maxlength: '5000' }); evidence.value = current.answer?.evidence || '';
      box.append(h('form', { cls: 'ar-form ar-answer', onsubmit: (event) => {
        event.preventDefault();
        try {
          model = M.validate(R.command(model, { type: 'answer', question: current.id, target: current.target, value: choice.value, note: note.value.trim(), evidence: evidence.value.trim() }));
          changed(); render(); announce(t('arAnswerSaved'));
        } catch (error) { fail(error); }
      } }, field(t('arAnswer'), choice), field(t('arAnswerNote'), note), field(t('arAnswerEvidence'), evidence),
      h('button', { type: 'submit', disabled: current.blocked, text: t('arConfirmAnswer') })));
      box.append(h('button', { type: 'button', disabled: selected === '' || current.target === 'system', text: t('arCandidate'), onclick: () => openThreat(null, {
        title: qTitle(current), category: current.category, note: t('arCandidateNote', { id: current.id, note: current.answer?.note || t('arNoSupport') }),
      }) }));
    }
    $('previous-question').disabled = questionIndex <= 0;
    $('next-question').disabled = questionIndex >= list.length - 1;
    $('proposal-accept').disabled = !proposal; $('proposal-reject').disabled = !proposal;
    if (!proposal) { $('proposal-diff').textContent = t('arProposalNote'); }
  }

  async function readFile(input, limit, tooLarge) {
    const file = input.files[0]; input.value = '';
    if (!file) { return null; }
    if (file.size > limit) { throw new Error(t(tooLarge)); }
    return file.text();
  }
  async function openProposal(event) {
    try {
      const raw = await readFile(event.target, PROPOSAL_BYTES, 'arProposalTooLarge'); if (raw == null || !model) { return; }
      const p = M.parse(raw), baseline = model;
      await R.checkProposal(baseline, p);
      if (baseline !== model) { throw new Error(t('arModelChanged')); }
      proposal = p; renderReview();
      const old = p.command.type === 'answer' ? R.answer(model, p.command.target, p.command.question) : null;
      $('proposal-diff').textContent = [t('arUntrustedProposal'), p.command.type === 'answer' ? `${p.command.target} / ${p.command.question}` : t('arProposedDesign'),
        `${t('arBefore')}: ${old ? JSON.stringify(old) : t(p.command.type === 'answer' ? 'arUnanswered' : 'arElementAbsent')}`,
        `${t('arAfter')}: ${JSON.stringify(p.command)}`, t('arProposalConfirmNote')].join('\n');
    } catch (error) { proposal = null; renderReview(); fail(error); }
  }
  async function acceptProposal() {
    const pending = proposal; if (!pending) { return; }
    proposal = null; renderReview();
    try {
      const baseline = model, candidate = await R.checkProposal(baseline, pending);
      if (baseline !== model) { throw new Error(t('arModelChanged')); }
      model = M.validate(candidate); changed(); render(); announce(t('arProposalAccepted'));
    } catch (error) { proposal = null; renderReview(); fail(error); }
  }
  function download(name, value, mime) {
    const url = URL.createObjectURL(new Blob([value], { type: mime })); urls.add(url);
    const a = h('a', { href: url, download: name, hidden: true }); root.append(a); a.click(); a.remove();
    const timer = setTimeout(() => { URL.revokeObjectURL(url); urls.delete(url); timers.delete(timer); }, 1000); timers.add(timer);
  }
  function fileName(extension) {
    const base = (model.title || 'architecture-review').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'architecture-review';
    return `${base}.architecture-review.${extension}`;
  }
  async function openReview(event) {
    try {
      const raw = await readFile(event.target, M.LIMIT.bytes, 'arFileTooLarge'); if (raw == null) { return; }
      if (dirty && !confirm(t('arConfirmReplace'))) { return; }
      const next = M.importModel(M.parse(raw));
      const merged = next.documentType === 'snapshot' && model;
      model = merged ? M.merge(model, next) : next;
      selected = model.nodes.length ? 'n:' + model.nodes[0].id : ''; editing = null; $('threat-form').hidden = true;
      dirty = next.documentType !== 'review'; proposal = null; questionIndex = 0; activeView = ''; loadError = '';
      render();
      const stack = ctx.stack, scope = model.scope.stack;
      const mismatch = scope && scope !== stack && !scope.includes(`:stack/${stack}/`);
      announce(t(mismatch ? 'arOpenedOtherStack' : 'arOpened'), mismatch);
    } catch (error) { fail(error); }
  }
  function saveReview() {
    try {
      download(fileName('json'), JSON.stringify(M.validate({ ...model, documentType: 'review' }), null, 2), 'application/json');
      dirty = false; renderReview(); announce(t('arSaved'));
    } catch (error) { fail(error); }
  }
  async function exportSvg() {
    try {
      const copy = $('canvas').cloneNode(true); copy.removeAttribute('style'); copy.removeAttribute('id');
      copy.setAttribute('xmlns', SVG_NS);
      const used = new Set([...copy.querySelectorAll('use')].map((u) => u.getAttribute('href').split('#')[1]));
      if (used.size) {
        // The sprite is a trusted, embedded server asset; model input is never parsed as markup.
        const sprite = new DOMParser().parseFromString(await (await fetch(ICONS_URL, { signal })).text(), 'image/svg+xml');
        const defs = copy.querySelector('defs');
        for (const id of used) {
          const symbol = [...sprite.querySelectorAll('symbol')].find((s) => s.id === id);
          if (symbol) { defs.append(document.importNode(symbol, true)); }
        }
        copy.querySelectorAll('use').forEach((u) => u.setAttribute('href', '#' + u.getAttribute('href').split('#')[1]));
      }
      const palette = getComputedStyle(root);
      const colors = ['bg', 'surface', 'text', 'muted', 'line', 'accent'].map((key) => `--${key}:${palette.getPropertyValue('--' + key).trim()}`).join(';');
      const style = svg('style');
      style.textContent = `svg{background:var(--bg);${colors}}.ar-node>rect{fill:var(--surface);stroke:var(--line)}.ar-node text,.ar-edge text{fill:var(--text);font:12px sans-serif}.type,.status,.ar-zone-label{font:10px sans-serif;fill:var(--muted)}.mark{fill:var(--accent);font:bold 10px sans-serif}.ar-edge path{fill:none;stroke:var(--accent);stroke-width:2}.ar-edge .hit{display:none}.ar-edge.proposed path{stroke-dasharray:7 5}.ar-edge.dependency path{stroke:var(--muted);stroke-dasharray:2 6}.ar-zone-box{fill:var(--bg);fill-opacity:.65;stroke:var(--line);stroke-dasharray:6 5}`;
      copy.prepend(style, svg('title', {}, t('arSvgTitle', { title: model.title, source: sourceLabel() })));
      if (unmounted()) { return; }
      download(fileName('svg'), new XMLSerializer().serializeToString(copy), 'image/svg+xml');
    } catch (error) { if (!unmounted()) { fail(error); } }
  }
  function saveView(event) {
    event.preventDefault();
    try {
      if (model.views.length >= M.LIMIT.views) { throw new Error(t('arViewLimit')); }
      const name = $('view-name').value.trim(), prefix = $('view-prefix').value.trim();
      const manual = new Set([...$('view-resources').selectedOptions].map((o) => o.value));
      const nodes = model.nodes.filter((n) => manual.has(n.id) || (prefix && n.id.startsWith(prefix)));
      if (!name || !nodes.length) { throw new Error(t('arViewInvalid')); }
      const id = crypto.randomUUID(), next = structuredClone(model);
      next.views.push({ id, name, nodeIds: nodes.map((n) => n.id), layout: nodes.map((n) => ({ id: n.id, x: n.x, y: n.y })) });
      model = M.validate(next); activeView = id; selected = 'n:' + nodes[0].id; changed(); render();
      announce(t('arViewSaved'));
    } catch (error) { fail(error); }
  }
  function deleteView() { model.views = model.views.filter((v) => v.id !== activeView); activeView = ''; changed(); render(); }
  function setZone(event) {
    const node = model.nodes.find((n) => 'n:' + n.id === selected);
    if (node) { node.zone = event.target.value; topologyChanged(); render(); announce(t('arZoneChanged')); }
  }
  function addZone(event) {
    event.preventDefault();
    if (model.zones.length >= M.LIMIT.zones) { announce(t('arZoneLimit'), true); return; }
    const name = $('zone-name').value.trim(), node = model.nodes.find((n) => 'n:' + n.id === selected);
    if (!name || !node) { return; }
    const id = crypto.randomUUID(); model.zones.push({ id, name }); node.zone = id; $('zone-name').value = ''; topologyChanged(); render();
  }
  function addFlow(event) {
    event.preventDefault();
    const from = $('flow-from').value, to = $('flow-to').value, label = $('flow-label').value.trim();
    if (!from || !to || from === to || !label || model.edges.length >= M.LIMIT.edges) { announce(t('arFlowInvalid'), true); return; }
    try {
      const id = crypto.randomUUID(); model = M.validate(R.command(model, { type: 'add-flow', id, from, to, label })); changed(); $('flow-label').value = ''; choose('e:' + id); announce(t('arFlowAdded'));
    } catch (error) { fail(error); }
  }
  function addNode(event) {
    event.preventDefault();
    const name = $('node-name').value.trim();
    if (!name || model.nodes.length >= M.LIMIT.nodes) { announce(t('arComponentInvalid'), true); return; }
    try {
      const id = crypto.randomUUID(); model = M.validate(R.command(model, { type: 'add-node', id, name, kind: $('node-type').value })); changed(); $('node-name').value = ''; choose('n:' + id); announce(t('arComponentAdded'));
    } catch (error) { fail(error); }
  }
  function saveThreat(event) {
    event.preventDefault();
    try {
      if (!editing && model.threats.length >= M.LIMIT.threats) { throw new Error(t('arThreatLimit')); }
      const threat = { id: editing || crypto.randomUUID(), target: selected, title: $('threat-title').value.trim(), category: $('category').value, severity: $('severity').value, status: $('decision').value,
        mitigation: $('mitigation').value.trim(), note: $('note').value.trim(), owner: $('owner').value.trim(), evidence: $('finding-evidence').value.trim(), verification: 'pending', needsReview: false };
      const next = { ...model, threats: [...model.threats.filter((f) => f.id !== editing), threat] };
      model = M.validate(R.finding(next, threat.id)); changed(); $('threat-form').hidden = true; editing = null; render(); $('inspector').scrollTop = 0; announce(t('arDecisionSaved'));
    } catch (error) { fail(error); }
  }

  build(); render(); refresh(true);
  return {
    unmount,
    confirmLeave: () => !dirty || confirm(t('arLeaveUnsaved')),
    relocalize: () => { const notice = $('notice')?.textContent || ''; build(); render(); if (notice) { announce(notice); } },
  };
}
