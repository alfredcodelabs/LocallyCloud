    const STATUS_URL = "/_locallycloud/status";
    const POLL_MS = 3000;

    const $ = (id) => document.getElementById(id);
    const store = {
      get: (k, d) => { try { return localStorage.getItem("lc." + k) ?? d; } catch { return d; } },
      set: (k, v) => { try { localStorage.setItem("lc." + k, v); } catch {} },
    };
    const browserLang = (navigator.language || "en").slice(0, 2);
    const state = {
      lang: [store.get("lang"), browserLang].find((l) => I18N[l]) || "en",
      sort: store.get("serviceSort", "name"),
      hideIdle: store.get("activeServicesOnly", "1") === "1",
      query: "",
      doc: null,
      activity: null, activityError: "",
      context: null, identity: null, identityError: "", inventory: null, inventoryError: "", region: "", profile: "", readController: new AbortController(),
      
      errorsOnly: false,
      lastOk: 0,
      health: "offline",
      error: "",
      svc: "",
    };
    const rowsByName = new Map();

    const t = (key, vars = {}) =>
      (I18N[state.lang][key] ?? I18N.en[key] ?? key).replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? "");
    const fmtInt = (n) => new Intl.NumberFormat(state.lang).format(n ?? 0);
    function fmtUsd(v) {
      v = v ?? 0;
      if (v === 0) return "$0";
      if (v < 0.001) return "< $0.001";
      return "~" + new Intl.NumberFormat(state.lang, {
        style: "currency", currency: "USD", minimumFractionDigits: 2, maximumFractionDigits: 3,
      }).format(v);
    }
    const fmtNum = (n) => new Intl.NumberFormat(state.lang, { maximumFractionDigits: 1 }).format(n);
    const fmtUnit = (n, unit) => new Intl.NumberFormat(state.lang, { style: "unit", unit, maximumFractionDigits: 1 }).format(n);
    const fmtMs = (n) => (n < 1000 ? fmtUnit(n, "millisecond") : fmtUnit(n / 1000, "second"));
    const fmtSec = (n) => fmtUnit(+n, "second");
    function fmtBytes(b) {
      const u = ["byte", "kilobyte", "megabyte", "gigabyte"];
      let i = 0; b = +b || 0;
      while (b >= 1024 && i < 3) { b /= 1024; i++; }
      return fmtUnit(b, u[i]);
    }
    // Accepts epoch seconds or ms (number or numeric string) and ISO strings.
    function toDate(v) {
      if (v == null || v === "") return null;
      if (typeof v === "string" && !/^\d+(\.\d+)?$/.test(v)) return new Date(v.replace(/(\.\d{3})\d+/, "$1"));
      v = +v;
      return new Date(v < 1e11 ? v * 1000 : v);
    }
    const fmtDate = (v) => { const d = toDate(v); return d ? new Intl.DateTimeFormat(state.lang, { dateStyle: "medium", timeStyle: "short" }).format(d) : "–"; };
    function fmtClock(ms) {
      const d = new Date(ms), opt = { hour: "2-digit", minute: "2-digit", second: "2-digit", fractionalSecondDigits: 3, hour12: false };
      if (d.toDateString() !== new Date().toDateString()) Object.assign(opt, { month: "short", day: "numeric" });
      return new Intl.DateTimeFormat(state.lang, opt).format(d);
    }

    // Tiny DOM builder: strings become text nodes, never HTML.
    function h(tag, props, ...kids) {
      const e = document.createElement(tag);
      for (const [k, v] of Object.entries(props || {})) {
        if (v == null || v === false) continue;
        if (k === "text") e.textContent = v;
        else if (k.startsWith("on")) e[k] = v;
        else e.setAttribute(k === "cls" ? "class" : k, v === true ? "" : v);
      }
      for (const c of kids.flat()) if (c != null && c !== false) e.append(c);
      return e;
    }
    const svg = (tag, attrs) => {
      const e = document.createElementNS("http://www.w3.org/2000/svg", tag);
      for (const k in attrs) e.setAttribute(k, attrs[k]);
      return e;
    };
    const enc = encodeURIComponent;
    const link = (href, text) => h("a", { href, text });
    const slug = (svc) => svc === "dynamodb" ? "dynamo" : svc;
    const homePath = () => "/" + state.region + "/";
    const servicePath = (svc, id = "") => homePath() + slug(svc) + (id ? "/" + enc(id) : "");
    const contextual = (path) => path + (path.includes("?") ? "&" : "?") + "profile=" + enc(state.profile);
    const R = {
      fn: (n) => contextual(servicePath("lambda", n)), grp: (n) => contextual(servicePath("logs", n)),
      q: (n) => contextual(servicePath("sqs", n)),
      sm: (arn) => {
        const match = String(arn).match(/^arn:[^:]+:states:[^:]+:[^:]+:(stateMachine|execution):(.+)$/);
        if (!match) return contextual(servicePath("states", arn));
        if (match[1] === "execution") {
          const [machine, ...execution] = match[2].split(":");
          return contextual(servicePath("states", machine) + "/executions/" + enc(execution.join(":")));
        }
        return contextual(servicePath("states", match[2]));
      },
    };
    function syncContextLinks() {
      document.querySelector(".brand a").href = contextual(homePath());
      $("nav-overview").href = contextual(homePath());
      $("nav-billing").href = contextual(homePath() + "billing/");
    }
    function updateOptions(select, options) {
      if (select.options.length !== options.length || options.some((option, i) => {
        const current = select.options[i];
        return current.value !== option.value || current.textContent !== option.textContent || current.disabled !== option.disabled;
      })) select.replaceChildren(...options);
    }
    function contextControls() {
      if (!state.context) return;
      updateOptions($("profile"), state.context.profiles.map((p) => h("option", {
        value: p.name, text: p.name === "instance" ? t("instanceProfile") : p.name,
      })));
      $("profile").value = state.profile;
      const regions = state.inventory && state.identity && state.inventory.accountId === state.identity.Account ? state.inventory.regions : [];
      const options = regions.map((region) => h("option", { value: region, text: region }));
      if (!regions.includes(state.region)) options.unshift(h("option", {
        value: "", text: t(regions.length ? "regionHasNoResources" : "noResourceRegions"), disabled: true,
      }));
      updateOptions($("region"), options);
      $("region").value = regions.includes(state.region) ? state.region : "";
      $("region").disabled = !regions.length;
      syncContextLinks(); renderIdentity();
    }
    const readContext = () => ({ region: state.region, profile: state.profile });
    async function refreshRegions() {
      const controller = state.readController;
      try {
        const inventory = await call("/_locallycloud/explore/regions", {
          method: "POST", body: JSON.stringify(readContext()), signal: controller.signal,
          headers: { "Content-Type": "application/json" },
        });
        if (controller.signal.aborted) return;
        if (inventory.accountId !== state.identity?.Account) throw new Error("Inventory account mismatch");
        state.inventory = inventory;
        state.inventoryError = "";
        contextControls();
      } catch (e) {
        if (controller.signal.aborted) return;
        state.inventoryError = e.message || String(e);
      }
      renderHeader();
      renderRows();
    }

    async function refreshActivity() {
      if (!state.identity) return;
      const controller = state.readController;
      try {
        const activity = await call("/_locallycloud/activity", {
          method: "POST", body: JSON.stringify(readContext()), signal: controller.signal,
          headers: { "Content-Type": "application/json" },
        });
        if (controller.signal.aborted) return;
        state.activity = activity; state.activityError = "";
      } catch (error) {
        if (controller.signal.aborted) return;
        state.activity = null;
        state.activityError = error.auth ? t("activityDenied") : t("activityUnavailable", { err: error.message || String(error) });
      }
      renderActivity(); renderRows(); renderSvcMeta();
    }

    function renderIdentity() {
      const identity = state.identity;
      const resource = identity?.Arn?.split(":").slice(5).join(":") || "";
      const assumed = resource.startsWith("assumed-role/");
      const kind = resource === "root" ? "iamRoot" : assumed ? "iamRole" : resource.startsWith("user/") ? "iamUser" : "callerIdentity";
      const name = resource === "root" ? "root" : resource.replace(/^(?:user|assumed-role)\//, "");
      $("identity-label").textContent = identity ? name + " @ " + identity.Account : t(state.identityError ? "identityUnavailable" : "identityLoading");
      $("identity-account").textContent = identity?.Account || "–";
      $("identity-kind").textContent = t(identity ? kind : "callerIdentity");
      $("identity-name").textContent = identity ? name : "–";
      $("identity-arn").textContent = identity?.Arn || "–";
      $("identity-id").textContent = identity?.UserId || "–";
      const signed = state.context?.profiles.find((p) => p.name === state.profile)?.signed;
      $("identity-note").textContent = identity ? t(signed ? "stsIdentity" : "unsignedIdentity") : "";
      $("identity-error").hidden = !state.identityError;
      $("identity-error").textContent = state.identityError;
    }
    const SERVICE_NAMES = { dynamodb: "DynamoDB", s3: "S3", lambda: "Lambda", logs: "CloudWatch Logs", monitoring: "CloudWatch Metrics", states: "Step Functions", sqs: "SQS", sns: "SNS", events: "EventBridge", eventbridge: "EventBridge", apigateway: "API Gateway", cloudformation: "CloudFormation" };
    const serviceName = (slug) => SERVICE_NAMES[slug] || slug;
    function serviceLabel(slug) {
      const icon = state.doc?.services?.find((service) => service.name === slug)?.icon;
      if (!icon) return [serviceName(slug)];
      const image = svg("svg", { width: 24, height: 24, "aria-hidden": "true", focusable: "false" });
      image.append(svg("use", { href: icon }));
      return [image, serviceName(slug)];
    }
    const arnName = (arn) => String(arn || "").split(/[:/]/).pop();
    const badge = (text, kind) => h("span", { cls: "badge" + (kind ? " b-" + kind : ""), text });

    // ---- AWS API (same origin, unsigned, read-only operations only) ----
    function xmlValue(node) {
      const children = [...node.children];
      if (!children.length) return node.textContent;
      if (children.every((child) => child.localName === "member")) return children.map(xmlValue);
      if (children.every((child) => child.localName === "entry")) return Object.fromEntries(children.map((child) => [
        child.querySelector("key")?.textContent, child.querySelector("value")?.textContent,
      ]));
      return Object.fromEntries(children.map((child) => [child.localName, xmlValue(child)]));
    }
    async function call(url, init) {
      const res = await fetch(url, { cache: "no-store", ...init, headers: { ...init?.headers, "x-locallycloud-dashboard": "1" } });
      const text = await res.text();
      let body = {};
      try { body = text ? JSON.parse(text) : {}; } catch {
        const xml = new DOMParser().parseFromString(text, "application/xml");
        if (!xml.querySelector("parsererror")) {
          const result = [...xml.documentElement.children].find((node) => node.localName.endsWith("Result"));
          body = result ? xmlValue(result) : { code: xml.querySelector("Code")?.textContent, message: xml.querySelector("Message")?.textContent };
        }
      }
      if (!res.ok) {
        const type = (res.headers.get("x-amzn-errortype") || body.__type || body.code || "").split(":")[0].split("#").pop();
        const err = new Error(body.message || body.Message || type || "HTTP " + res.status);
        err.type = type;
        err.auth = res.status === 403 || /AccessDenied|Unrecognized|InvalidClientToken|MissingAuth|Signature|NotAuthorized|ExpiredToken/.test(type);
        throw err;
      }
      return body;
    }
    const read = (request) => call("/_locallycloud/explore/read", {
      method: "POST", body: JSON.stringify({ ...readContext(), ...request }),
      signal: state.readController.signal, headers: { "Content-Type": "application/json" },
    });
    const api = (service, operation, body = {}) => read({ service, operation, body });
    const lambda = (path) => read({ service: "lambda", path });
    const errBox = (e) => h("p", { cls: "notice", role: "alert", text: e.auth ? t("authErr") : t("apiErr", { err: e.message }) });
    const msg = (key, vars) => h("p", { cls: "dim", text: t(key, vars) });

    // Section with title whose body is filled asynchronously by `load` (returns nodes).
    function panel(title, load, extra) {
      const body = h("div", null, h("p", { cls: "dim", role: "status", text: t("loading") }));
      Promise.resolve().then(load).then((n) => body.replaceChildren(...[n].flat()), (e) => body.replaceChildren(errBox(e)));
      return h("section", { cls: "panel" }, h("div", { cls: "phead" }, h("h2", { text: title }), extra), body);
    }
    function table(cols, rows, emptyKey = "empty") {
      if (!rows.length) return msg(emptyKey);
      const tb = h("tbody");
      const el = h("div", { cls: "table" }, h("table", null,
        h("thead", null, h("tr", null, cols.map((c) => { const [k, cls] = c.split("|"); return h("th", { scope: "col", cls, text: t(k) }); }))), tb));
      el.add = (rs) => rs.forEach((r) => tb.append(h("tr", null, r.map((v, i) => h("td", { cls: cols[i].split("|")[1] }, v ?? "–")))));
      el.add(rows);
      return el;
    }
    const kv = (pairs) => h("dl", { cls: "kv" }, pairs.filter((p) => p[1] != null && p[1] !== "")
      .map(([k, v]) => h("div", null, h("dt", { text: t(k) }), h("dd", null, v))));

    // ---- Charts: one GetMetricStatistics call per metric, last 60 min at 1 min ----
    const charts = [];
    function chart(title, ns, metric, dims, stats, fmt = fmtNum) {
      const fig = h("figure", { cls: "chart" });
      const load = async () => {
        const end = Math.floor(Date.now() / 1000), start = end - 3600;
        const q = stats.includes("Average") ? [...stats, "SampleCount"] : stats;
        const r = await api("monitoring", "GetMetricStatistics", {
          Namespace: ns, MetricName: metric, Dimensions: dims, StartTime: start, EndTime: end, Period: 60, Statistics: q,
        });
        const pts = (r.Datapoints || []).toSorted((a, b) => a.Timestamp - b.Timestamp);
        const W = 300, H = 56, x = (ts) => ((ts - start) / 3600) * W;
        const sum = (k) => pts.reduce((s, p) => s + (p[k] || 0), 0);
        const summary = stats.map((s) => {
          const v = s === "Sum" ? sum("Sum") : s === "Maximum" ? Math.max(...pts.map((p) => p.Maximum))
            : pts.reduce((a, p) => a + p.Average * (p.SampleCount || 1), 0) / (sum("SampleCount") || pts.length);
          return (stats.length > 1 ? t(s === "Average" ? "avg" : "max") + " " : "") + fmt(v);
        }).join(" · ");
        const cap = h("figcaption", { text: title });
        if (!pts.length) return fig.replaceChildren(cap, h("b", { text: "–" }), h("div", { cls: "empty", text: t("noData") }));
        const top = Math.max(...pts.flatMap((p) => stats.map((s) => p[s] || 0))) || 1;
        const y = (v) => H - (v / top) * (H - 4);
        const g = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": title + ": " + summary });
        g.append(svg("path", { d: `M0 ${H}H${W}`, class: "base", "vector-effect": "non-scaling-stroke" }));
        stats.forEach((s, i) => {
          if (s === "Sum") {
            for (const p of pts) {
              const r = svg("rect", { x: x(p.Timestamp), y: y(p.Sum), width: W / 60 - 1, height: H - y(p.Sum), class: "bar" });
              const tt = svg("title", {}); tt.textContent = fmtClock(p.Timestamp * 1000).slice(0, 5) + " · " + fmt(p.Sum);
              r.append(tt); g.append(r);
            }
          } else {
            // Contiguous minutes form lines; isolated minutes are drawn as visible dots.
            let d = "", dots = "";
            pts.forEach((p, k) => {
              const xy = x(p.Timestamp).toFixed(1) + " " + y(p[s]).toFixed(1);
              const near = (q) => q && Math.abs(q.Timestamp - p.Timestamp) <= 90;
              const prevNear = near(pts[k - 1]);
              if (!prevNear && !near(pts[k + 1])) { dots += "M" + xy + "h0.01"; } else { d += (prevNear ? "L" : "M") + xy; }
            });
            for (const [path, cls] of [[d, "l" + i], [dots, "dot l" + i]]) {
              if (path) { g.append(svg("path", { d: path, class: cls, "vector-effect": "non-scaling-stroke" })); }
            }
          }
        });
        const rtf = new Intl.RelativeTimeFormat(state.lang, { numeric: "auto", style: "short" });
        fig.replaceChildren(cap, h("b", { text: summary }), g,
          h("div", { cls: "axis", "aria-hidden": "true" }, h("span", { text: rtf.format(-60, "minute") }), h("span", { text: rtf.format(0, "second") })));
      };
      fig.load = () => load().catch((e) => fig.replaceChildren(h("figcaption", { text: title }), errBox(e)));
      fig.load();
      charts.push(fig);
      return fig;
    }
    const chartGrid = (title, list) => h("section", { cls: "panel" }, h("div", { cls: "phead" }, h("h2", { text: title }), h("span", { cls: "dim", text: t("chartRange") })), h("div", { cls: "charts" }, list));

    // ---- Log viewer (FilterLogEvents) with Powertools JSON parsing ----
    const LVL = { TRACE: 5, DEBUG: 10, INFO: 20, WARN: 30, ERROR: 40, CRITICAL: 50, FATAL: 50 };
    const LVL_KIND = { WARN: "warn", ERROR: "bad", CRITICAL: "bad", FATAL: "bad", INFO: "acc" };
    const prefs = { q: "", range: store.get("range", "3600000"), level: store.get("level", "0"), hideEmf: store.get("hideEmf") === "1", live: store.get("live") === "1" };
    function parseEvent(ev) {
      const m = String(ev.message || "").replace(/\n$/, "");
      const o = { ev, raw: m, msg: m };
      const sys = m.match(/^(START|END|REPORT) RequestId: ([\w-]+)/);
      if (sys) return Object.assign(o, { sys: sys[1], rid: sys[2], msg: m.replace(/\t/g, "  ") });
      if (m[0] === "{") {
        try {
          const j = (o.json = JSON.parse(m));
          if (j._aws) {
            o.emf = true;
            o.msg = t("emf", { m: (j._aws.CloudWatchMetrics || []).flatMap((c) => c.Metrics || []).map((x) => x.Name).join(", ") });
            return o;
          }
          const mm = j.message ?? j.msg;
          o.msg = typeof mm === "string" ? mm : mm === undefined ? m : JSON.stringify(mm);
          o.level = String(j.level ?? j.levelname ?? "").toUpperCase();
          const rid = j.function_request_id ?? j.requestId ?? j.request_id;
          if (rid != null && rid !== "") o.rid = String(rid);
          o.cold = j.cold_start === true;
        } catch {}
      }
      if (!o.json) {
        const p = m.match(/(?:^\[|\t)(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL)(?:\]|\t)/);
        if (p) o.level = p[1];
        const r = m.match(/\t([0-9a-f]{8}-[0-9a-f-]{27})\t/);
        if (r) o.rid = r[1];
      }
      if (o.level === "WARNING") o.level = "WARN";
      return o;
    }
    function logViewer(group) {
      const MAX = 500, seen = new Set();
      let last = 0, total = 0, busy = false;
      const tb = h("tbody"), status = h("p", { cls: "dim", role: "status", "aria-live": "polite" });
      const q = h("input", { type: "search", id: "lv-q", autocomplete: "off", placeholder: t("filter"), value: prefs.q });
      const sel = (id, val, opts) => { const s = h("select", { id }, opts.map(([v, l]) => h("option", { value: v, text: l }))); s.value = val; return s; };
      const range = sel("lv-range", prefs.range, [["900000", t("r15m")], ["3600000", t("r1h")], ["86400000", t("r24h")]]);
      const level = sel("lv-level", prefs.level, [["0", t("allLevels")], ...["DEBUG", "INFO", "WARN", "ERROR"].map((l) => [String(LVL[l]), "≥ " + l])]);
      const emf = h("input", { type: "checkbox", id: "lv-emf", checked: prefs.hideEmf });
      const live = h("input", { type: "checkbox", id: "lv-live", checked: prefs.live });
      const visible = (o) => !(o.emf && prefs.hideEmf) && !(+prefs.level && !(LVL[o.level] >= +prefs.level));
      function row(o) {
        const btn = h("button", { type: "button", cls: "exp", "aria-expanded": "false", "aria-label": t("details"), text: "▸" });
        const tr = h("tr", { cls: o.sys ? "sys" + (o.sys === "REPORT" ? " inv" : "") : o.emf ? "emf" : null },
          h("td", null, btn, fmtClock(o.ev.timestamp)),
          h("td", null, o.level ? badge(o.level, LVL_KIND[o.level]) : ""),
          h("td", { cls: "msg" },
            o.rid && !o.sys ? h("button", { type: "button", cls: "chip", text: o.rid.slice(0, 8), title: t("byReq", { id: o.rid }), "aria-label": t("byReq", { id: o.rid }),
              onclick: () => { q.value = o.rid; reload(); } }) : null,
            o.cold ? h("span", { cls: "tag", text: "❄ " + t("cold") }) : null, o.msg));
        tr.o = o;
        tr.hidden = !visible(o);
        btn.onclick = () => {
          const open = btn.getAttribute("aria-expanded") === "true";
          btn.setAttribute("aria-expanded", String(!open));
          btn.textContent = open ? "▸" : "▾";
          if (open) tr.nextSibling?.remove();
          else tr.after(h("tr", { cls: "detail" }, h("td", { colspan: "3" },
            h("pre", { text: (o.json ? JSON.stringify(o.json, null, 2) : o.raw) + "\n\n" + o.ev.logStreamName }))));
        };
        return tr;
      }
      const applyFilters = () => tb.querySelectorAll("tr").forEach((tr) => {
        if (tr.o) { tr.hidden = !visible(tr.o); if (tr.nextSibling && !tr.nextSibling.o) tr.nextSibling.hidden = tr.hidden; }
      });
      async function fetchSince(startTime) {
        const out = [];
        let token;
        for (let i = 0; i < 10; i++) {
          const r = await api("logs", "FilterLogEvents", { logGroupName: group, startTime, filterPattern: prefs.q || undefined, limit: 1000, nextToken: token });
          out.push(...(r.events || []));
          token = r.nextToken;
          if (!token) break;
        }
        return out.filter((e) => !seen.has(e.eventId) && seen.add(e.eventId));
      }
      const setStatus = () => {
        const n = [...tb.children].filter((r) => r.o).length;
        status.textContent = !n ? t("noLogs") : n < total ? t("latestOf", { n: fmtInt(n), total: fmtInt(total) }) : t("nEvents", { n: fmtInt(n) });
      };
      function add(events, prepend) {
        total += events.length;
        for (const e of events) { last = Math.max(last, e.timestamp); const tr = row(parseEvent(e)); prepend ? tb.prepend(tr) : tb.append(tr); }
        let rows = [...tb.children];
        while (rows.filter((r) => r.o).length > MAX) { const r = rows.pop(); r.remove(); }
      }
      async function reload() {
        prefs.q = q.value.trim();
        seen.clear(); total = 0; last = 0;
        tb.replaceChildren();
        status.textContent = t("loading");
        try {
          const ev = await fetchSince(Date.now() - +prefs.range);
          add(ev.slice(-MAX).reverse(), false);
          total = ev.length;
          setStatus();
        } catch (e) {
          status.textContent = e.type === "ResourceNotFoundException" ? t("noGroup") : e.auth ? t("authErr") : t("apiErr", { err: e.message });
        }
      }
      async function tick() {
        if (!prefs.live || busy) return;
        if (document.hidden) { status.textContent = t("livePaused"); return; }
        busy = true;
        try { const ev = await fetchSince(last || Date.now() - +prefs.range); if (ev.length) add(ev, true); setStatus(); } catch {}
        busy = false;
      }
      let deb;
      q.oninput = () => { clearTimeout(deb); deb = setTimeout(reload, 500); };
      range.onchange = () => { prefs.range = range.value; store.set("range", prefs.range); reload(); };
      level.onchange = () => { prefs.level = level.value; store.set("level", prefs.level); applyFilters(); };
      emf.onchange = () => { prefs.hideEmf = emf.checked; store.set("hideEmf", emf.checked ? "1" : "0"); applyFilters(); };
      live.onchange = () => { prefs.live = live.checked; store.set("live", live.checked ? "1" : "0"); tick(); };
      every(3000, tick);
      reload();
      return h("section", { cls: "panel" },
        h("div", { cls: "phead" }, h("h2", { text: t("logs") }), link(R.grp(group), group)),
        h("form", { cls: "toolbar", role: "search", onsubmit: (e) => { e.preventDefault(); clearTimeout(deb); reload(); } },
          h("label", { cls: "sr", for: "lv-q", text: t("filter") }), q,
          h("label", { cls: "sr", for: "lv-range", text: t("range") }), range,
          h("label", { cls: "sr", for: "lv-level", text: t("level") }), level,
          h("label", { cls: "check" }, emf, h("span", { text: t("hideEmf") })),
          h("label", { cls: "check live" }, live, h("span", { text: "● " + t("live") }))),
        status,
        h("div", { cls: "table" }, h("table", { cls: "logs" },
          h("thead", null, h("tr", null, h("th", { scope: "col", cls: "c-t", text: t("time") }), h("th", { scope: "col", cls: "c-l", text: t("level") }), h("th", { scope: "col", text: t("message") }))),
          tb)));
    }

    // ---- Pages ----
    const esmTable = (list, byFn) => table([byFn ? "function" : "source", "state", "batch|num"], list.map((m) => [
      byFn ? link(R.fn(arnName(m.FunctionArn)), arnName(m.FunctionArn))
        : m.EventSourceArn?.startsWith("arn:aws:sqs:") ? link(R.q(arnName(m.EventSourceArn)), arnName(m.EventSourceArn)) : m.EventSourceArn,
      m.State, fmtInt(m.BatchSize)]));
    function paginatedPanel(title, fetchPage, key, tokenOut, columns, renderRows) {
      return panel(title, async () => {
        const view = h("div"), controls = h("p", { cls: "more" });
        let list;
        const seen = new Set();
        let token, busy = false;
        async function load() {
          if (busy) return;
          busy = true;
          controls.replaceChildren(msg("loading"));
          try {
            const result = await fetchPage(token);
            const next = result[tokenOut];
            if (next && seen.has(next)) throw new Error(t("repeatedPageToken"));
            const rows = await renderRows(Array.isArray(result[key]) ? result[key] : []);
            if (list?.add) list.add(rows);
            else { list = table(columns, rows); view.replaceChildren(list, controls); }
            token = next;
            if (token) seen.add(token);
            controls.replaceChildren(...(token ? [h("button", {
              type: "button", cls: "link", text: t("loadMore"), onclick: load,
            })] : []));
          } catch (e) { controls.replaceChildren(errBox(e)); }
          finally { busy = false; }
        }
        view.append(controls);
        await load();
        return view;
      });
    }
    async function s3List(bucket, prefix = "", token) {
      const query = new URLSearchParams(readContext());
      if (bucket) query.set("bucket", bucket);
      if (prefix) query.set("prefix", prefix);
      if (token) query.set("token", token);
      const r = await fetch("/_locallycloud/explore/s3?" + query, { cache: "no-store", signal: state.readController.signal, headers: { "x-locallycloud-dashboard": "1" } });
      const xml = new DOMParser().parseFromString(await r.text(), "application/xml");
      if (xml.querySelector("parsererror")) throw new Error("Invalid S3 XML response");
      if (!r.ok) {
        const error = new Error(xml.querySelector("Message")?.textContent || "HTTP " + r.status);
        error.auth = r.status === 403; throw error;
      }
      return xml;
    }
    const xmlText = (node, tag) => node.querySelector(tag)?.textContent || "";
    const bucketLink = (bucket, prefix = "") => contextual(servicePath("s3", bucket) + (prefix ? "/" + enc(prefix) : ""));
    function bucketPage(id) {
      const slash = id.indexOf("/"), bucket = slash < 0 ? id : id.slice(0, slash), prefix = slash < 0 ? "" : id.slice(slash + 1);
      const body = h("div"); let token;
      async function load(more = false) {
        if (!more) { token = undefined; body.replaceChildren(msg("loading")); }
        try {
          const xml = await s3List(bucket, prefix, token);
          const rows = [...xml.querySelectorAll("CommonPrefixes")].map((n) => {
            const path = xmlText(n, "Prefix"); return [link(bucketLink(bucket, path), path.slice(prefix.length)), t("folder"), "–", "–"];
          });
          for (const n of xml.querySelectorAll("Contents")) {
            const key = xmlText(n, "Key");
            rows.push([key.slice(prefix.length), t("object"), fmtBytes(xmlText(n, "Size")), fmtDate(xmlText(n, "LastModified"))]);
          }
          if (more && body.firstChild?.add) body.firstChild.add(rows); else body.replaceChildren(table(["name", "type", "size|num", "lastModified"], rows));
          body.querySelector(".more")?.remove();
          token = xmlText(xml, "NextContinuationToken");
          if (token) body.append(h("p", { cls: "more" }, h("button", { type: "button", cls: "link", text: t("loadMore"), onclick: () => load(true) })));
        } catch (e) { body.replaceChildren(errBox(e)); }
      }
      load();
      const parent = prefix.replace(/\/$/, "").split("/").slice(0, -1).join("/");
      return h("section", { cls: "panel" }, h("div", { cls: "phead" }, h("h2", { text: t("folders") }),
        prefix ? link(bucketLink(bucket, parent ? parent + "/" : ""), t("parent")) : link(contextual(servicePath("s3")), t("buckets")),
        h("button", { type: "button", cls: "link", text: t("refresh"), onclick: () => load() })), body);
    }
    function itemBrowser(name) {
      const body = h("div"); let token, items = [];
      const json = h("pre", { cls: "item" });
      const dialog = h("dialog", { cls: "item-dialog", closedby: "any", "aria-label": t("rawItem") },
        h("div", { cls: "phead" }, h("h2", { text: t("rawItem") }),
          h("form", { method: "dialog" }, h("button", { type: "submit", text: t("close") }))), json);
      const value = (a) => {
        if (a.M) return Object.fromEntries(Object.entries(a.M).map(([key, v]) => [key, value(v)]));
        if (a.L) return a.L.map(value);
        return a.S ?? a.N ?? a.B ?? a.SS ?? a.NS ?? a.BS ?? a.BOOL ?? null;
      };
      function itemTable() {
        if (!items.length) return msg("empty");
        const columns = [...new Set(items.flatMap((item) => Object.keys(item)))].sort();
        const head = h("thead", null, h("tr", null,
          columns.map((key) => h("th", { scope: "col", text: key })), h("th", { scope: "col", text: "JSON" })));
        const rows = items.map((item) => {
          const cells = columns.map((key) => {
            const a = item[key];
            if (!a) return h("td", { text: "–" });
            const v = value(a), text = a.NULL ? "NULL" : typeof v === "object" ? JSON.stringify(v) : String(v);
            return h("td", null, h("code", { cls: "item-value", title: text, text }), " ", badge(Object.keys(a)[0]));
          });
          cells.push(h("td", null, h("button", { type: "button", cls: "link", text: "JSON", "aria-label": t("rawItem"),
            onclick: () => { json.textContent = JSON.stringify(item, null, 2); dialog.showModal(); } })));
          return h("tr", null, cells);
        });
        return h("div", { cls: "table" }, h("table", null, head, h("tbody", null, rows)));
      }
      async function load(more = false) {
        if (!more) { token = undefined; items = []; body.replaceChildren(msg("loading")); }
        try {
          const result = await api("dynamodb", "Scan", { TableName: name, ConsistentRead: true, Limit: 50, ExclusiveStartKey: token });
          items.push(...result.Items || []); body.replaceChildren(itemTable());
          token = result.LastEvaluatedKey;
          if (token && Object.keys(token).length) body.append(h("p", { cls: "more" }, h("button", { type: "button", cls: "link", text: t("loadMore"), onclick: () => load(true) })));
        } catch (e) { body.replaceChildren(errBox(e)); }
      }
      load();
      return h("section", { cls: "panel" }, h("div", { cls: "phead" }, h("h2", { text: t("items") }),
        h("button", { type: "button", cls: "link", text: t("refresh"), onclick: () => load() })), msg("itemScope"), body, dialog);
    }

    const restRead = (service, path) => read({ service, path });
    const jsonDetails = (value) => h("details", null, h("summary", { text: "JSON" }), h("pre", { cls: "item", text: JSON.stringify(value, null, 2) }));
    const resourceHref = (service, id) => contextual(servicePath(service, id));
    function resourceLink(arn) {
      const destination = String(arn || "").match(/\/functions\/(arn:aws:lambda:[^/]+)\/invocations$/);
      if (destination) {
        const linked = resourceLink(destination[1]);
        if (linked instanceof Node) { linked.textContent = arn; return linked; }
      }
      const parts = String(arn || "").split(":");
      if (parts[0] !== "arn" || parts[4] !== state.identity?.Account || parts[3] !== state.region) return arn;
      const service = parts[2], id = parts.slice(5).join(":");
      if (service === "lambda" && id.startsWith("function:")) return link(R.fn(id.slice(9)), arn);
      if (service === "states" && /^(stateMachine|execution):/.test(id)) return link(R.sm(arn), arn);
      if (service === "sqs") return link(R.q(id), arn);
      if (service === "sns") return link(resourceHref("sns", id), arn);
      if (service === "logs" && id.startsWith("log-group:")) return link(R.grp(id.slice(10).replace(/:\*$/, "")), arn);
      return arn;
    }
    function stackResourceLink(resource) {
      const service = {
        "AWS::DynamoDB::Table": "dynamodb", "AWS::S3::Bucket": "s3", "AWS::Lambda::Function": "lambda",
        "AWS::Logs::LogGroup": "logs", "AWS::Events::EventBus": "events",
      }[resource.ResourceType];
      if (service) return link(resourceHref(service, resource.PhysicalResourceId), resource.PhysicalResourceId);
      if (resource.ResourceType === "AWS::SQS::Queue") return link(R.q(arnName(resource.PhysicalResourceId)), resource.PhysicalResourceId);
      return resourceLink(resource.PhysicalResourceId);
    }
    function eventBusPage(id) {
      const split = location.pathname.lastIndexOf("/rules/");
      const bus = split < 0 ? id : decodeURIComponent(location.pathname.slice(0, split).split("/").pop());
      const name = split < 0 ? null : decodeURIComponent(location.pathname.slice(split + 7));
      const body = { EventBusName: bus, ...(name ? { Name: name } : {}) };
      if (name) return [
        panel(t("config"), async () => jsonDetails(await api("events", "DescribeRule", body))),
        paginatedPanel(t("targets"), (token) => api("events", "ListTargetsByRule", { EventBusName: bus, Rule: name, NextToken: token }),
          "Targets", "NextToken", ["name", "resource", "config"], (targets) => targets.map((target) => [target.Id, resourceLink(target.Arn), jsonDetails(target)])),
      ];
      return [panel(t("config"), async () => jsonDetails(await api("events", "DescribeEventBus", body))),
        paginatedPanel(t("rules"), (token) => api("events", "ListRules", { EventBusName: bus, NextToken: token }),
          "Rules", "NextToken", ["name", "state", "config"], (rules) => rules.map((rule) => [
            link(contextual(servicePath("events", bus) + "/rules/" + enc(rule.Name)), rule.Name), rule.State, jsonDetails(rule)]))];
    }
    function apiGatewayPage(id) {
      const [kind, apiId, ...tail] = id.split("/");
      if (!apiId || !["rest", "v2"].includes(kind)) return msg("noMatch");
      const root = kind === "rest" ? "/restapis/" + enc(apiId) : "/v2/apis/" + enc(apiId);
      if (tail.length) {
        const path = root + "/" + tail.map(enc).join("/");
        return panel(t("config"), async () => {
          const data = await restRead("apigateway", path);
          const uri = data.integrationUri || data.uri;
          return [uri ? kv([["resource", resourceLink(uri)]]) : null, jsonDetails(data)].filter(Boolean);
        });
      }
      const lists = kind === "rest" ? [["resources", "resources"], ["stages", "stages"]]
        : [["routes", "routes"], ["integrations", "integrations"], ["stages", "stages"]];
      return [panel(t("config"), async () => jsonDetails(await restRead("apigateway", root))),
        ...lists.map(([title, suffix]) => paginatedPanel(t(title), async (token) => {
          const data = await restRead("apigateway", root + "/" + suffix + (token ? "?" + (kind === "rest" ? "position=" : "nextToken=") + enc(token) : ""));
          return { items: data.items || data.item || [], token: data.nextToken || data.position };
        }, "items", "token", ["name", "config"], (items) => items.map((item) => {
          const name = item.id || item.routeId || item.integrationId || item.stageName || item.path;
          const href = suffix === "resources" ? null : resourceHref("apigateway", id + "/" + suffix + "/" + name);
          const label = item.routeKey || item.stageName || item.path || name;
          const config = h("div", null, jsonDetails(item));
          const integration = item.integrationUri || item.uri;
          if (integration) config.prepend(resourceLink(integration));
          if (suffix === "stages") {
            const stage = item.stageName === "$default" ? "$default" : enc(item.stageName);
            const invoke = kind === "rest" ? `/restapis/${enc(apiId)}/${enc(item.stageName)}/_user_request_/`
              : `/execute-api/${enc(apiId)}/${stage}/`;
            config.append(h("p", null, link(invoke, new URL(invoke, location.origin).href)));
          }
          const logArn = item.accessLogSettings?.destinationArn;
          if (logArn) config.prepend(resourceLink(logArn));
          if (suffix === "resources") for (const method of Object.keys(item.resourceMethods || {})) config.append(h("p", null,
            link(resourceHref("apigateway", id + "/resources/" + item.id + "/methods/" + method), method), " · ",
            link(resourceHref("apigateway", id + "/resources/" + item.id + "/methods/" + method + "/integration"), t("integrations"))));
          return [href ? link(href, label) : label, config];
        })))];
    }

    const PAGES = {
      events: [
        () => paginatedPanel(t("eventBuses"), (token) => api("events", "ListEventBuses", { NextToken: token }),
          "EventBuses", "NextToken", ["name", "ARN"], (buses) => buses.map((bus) => [link(resourceHref("events", bus.Name), bus.Name), bus.Arn])), eventBusPage,
      ],
      scheduler: [
        () => paginatedPanel(t("schedules"), (token) => restRead("scheduler", "/schedules" + (token ? "?NextToken=" + enc(token) : "")),
          "Schedules", "NextToken", ["name", "state", "resource"], (schedules) => schedules.map((schedule) => [
            link(resourceHref("scheduler", (schedule.GroupName || "default") + "/" + schedule.Name), schedule.Name), schedule.State, resourceLink(schedule.Target?.Arn)])),
        (id) => panel(t("config"), async () => {
          const split = id.indexOf("/"), group = split < 0 ? "default" : id.slice(0, split), name = split < 0 ? id : id.slice(split + 1);
          const data = await restRead("scheduler", "/schedules/" + enc(name) + "?groupName=" + enc(group));
          return [kv([["resource", resourceLink(data.Target?.Arn)]]), jsonDetails(data)];
        }),
      ],
      pipes: [
        () => paginatedPanel(t("pipes"), (token) => restRead("pipes", "/v1/pipes" + (token ? "?NextToken=" + enc(token) : "")),
          "Pipes", "NextToken", ["name", "state", "resource"], (pipes) => pipes.map((pipe) => [link(resourceHref("pipes", pipe.Name), pipe.Name), pipe.CurrentState, resourceLink(pipe.Target)])),
        (name) => panel(t("config"), async () => {
          const data = await restRead("pipes", "/v1/pipes/" + enc(name));
          return [kv([["source", resourceLink(data.Source)], ["resource", resourceLink(data.Target)]]), jsonDetails(data)];
        }),
      ],
      sns: [
        () => paginatedPanel(t("topics"), (token) => api("sns", "ListTopics", { NextToken: token }), "Topics", "NextToken", ["name", "ARN"],
          (topics) => topics.map((topic) => [link(resourceHref("sns", arnName(topic.TopicArn)), arnName(topic.TopicArn)), topic.TopicArn])),
        (id) => {
          const split = id.indexOf("/subscriptions/"), name = split < 0 ? id : id.slice(0, split);
          const topicArn = `arn:aws:sns:${state.region}:${state.identity.Account}:${name}`;
          if (split >= 0) return panel(t("config"), async () => kv(Object.entries((await api("sns", "GetSubscriptionAttributes", {
            SubscriptionArn: topicArn + ":" + id.slice(split + 15),
          })).Attributes || {})));
          return [panel(t("config"), async () => kv(Object.entries((await api("sns", "GetTopicAttributes", { TopicArn: topicArn })).Attributes || {}))),
            paginatedPanel(t("subscriptions"), (token) => api("sns", "ListSubscriptionsByTopic", { TopicArn: topicArn, NextToken: token }),
              "Subscriptions", "NextToken", ["protocol", "resource", "ARN"], (subscriptions) => subscriptions.map((sub) => [
                sub.Protocol, resourceLink(sub.Endpoint), sub.SubscriptionArn?.startsWith(topicArn + ":")
                  ? link(contextual(servicePath("sns", name) + "/subscriptions/" + enc(sub.SubscriptionArn.slice(topicArn.length + 1))), sub.SubscriptionArn) : sub.SubscriptionArn]))];
        },
      ],
      apigateway: [
        () => [
          paginatedPanel(t("restApis"), async (token) => {
            const data = await restRead("apigateway", "/restapis" + (token ? "?position=" + enc(token) : ""));
            return { items: data.item || [], position: data.position };
          }, "items", "position", ["name", "type"], (apis) => apis.map((api) => [link(resourceHref("apigateway", "rest/" + api.id), api.name || api.id), "REST"])),
          paginatedPanel(t("httpApis"), (token) => restRead("apigateway", "/v2/apis" + (token ? "?nextToken=" + enc(token) : "")),
            "items", "nextToken", ["name", "type"], (apis) => apis.map((api) => [link(resourceHref("apigateway", "v2/" + api.apiId), api.name || api.apiId), api.protocolType])),
        ], apiGatewayPage,
      ],
      cloudformation: [
        () => paginatedPanel(t("stacks"), (token) => api("cloudformation", "DescribeStacks", { NextToken: token }),
          "Stacks", "NextToken", ["name", "status", "created"], (stacks) => stacks.map((stack) => [link(resourceHref("cloudformation", stack.StackName), stack.StackName), stack.StackStatus, fmtDate(stack.CreationTime)])),
        (name) => [panel(t("config"), async () => {
          const stack = (await api("cloudformation", "DescribeStacks", { StackName: name })).Stacks?.[0];
          return [kv([["status", stack?.StackStatus], ["ARN", stack?.StackId], ["error", stack?.StackStatusReason]]),
            table(["name", "value"], (stack?.Outputs || []).map((output) => [output.OutputKey, output.OutputValue]))];
        }),
        panel(t("resources"), async () => table(["name", "type", "status", "resource"],
          ((await api("cloudformation", "DescribeStackResources", { StackName: name })).StackResources || []).map((resource) => [resource.LogicalResourceId, resource.ResourceType, resource.ResourceStatus, stackResourceLink(resource)]))),
        paginatedPanel(t("stackEvents"), (token) => api("cloudformation", "DescribeStackEvents", { StackName: name, NextToken: token }),
          "StackEvents", "NextToken", ["time", "name", "status", "error"], (events) => events.map((event) => [fmtDate(event.Timestamp), event.LogicalResourceId, event.ResourceStatus, event.ResourceStatusReason])),
        ],
      ],
      s3: [
        () => panel(t("buckets"), async () => {
          const xml = await s3List();
          return table(["name", "created"], [...xml.querySelectorAll("Buckets > Bucket")].map((b) => [
            link(bucketLink(xmlText(b, "Name")), xmlText(b, "Name")), fmtDate(xmlText(b, "CreationDate"))]));
        }), bucketPage,
      ],
      dynamodb: [
        () => paginatedPanel(t("tables"),
          (token) => api("dynamodb", "ListTables", { ExclusiveStartTableName: token }),
          "TableNames", "LastEvaluatedTableName", ["name"],
          (names) => names.map((name) => [link(contextual(servicePath("dynamodb", name)), name)])),
        (name) => [panel(t("config"), async () => {
          const { Table: d } = await api("dynamodb", "DescribeTable", { TableName: name });
          return kv([["status", d.TableStatus], ["ARN", d.TableArn], ["itemCount", fmtInt(d.ItemCount)],
            ["keys", (d.KeySchema || []).map((k) => k.AttributeName + " (" + k.KeyType + ")").join(", ")],
            ["attributes", (d.AttributeDefinitions || []).map((a) => a.AttributeName + ": " + a.AttributeType).join(", ")]]);
        }), itemBrowser(name)],
      ],
      lambda: [
        () => paginatedPanel(t("functions"),
          (token) => lambda("functions/" + (token ? "?Marker=" + enc(token) : "")),
          "Functions", "NextMarker", ["name", "runtime", "memory|num", "lastModified"],
          (functions) => functions.map((f) => [link(R.fn(f.FunctionName), f.FunctionName),
            f.Runtime || f.PackageType, fmtUnit(f.MemorySize, "megabyte"), fmtDate(f.LastModified)])),
        (fn) => [
          panel(t("config"), async () => {
            const c = await lambda("functions/" + enc(fn) + "/configuration");
            const envN = Object.keys(c.Environment?.Variables || {}).length;
            return kv([["runtime", c.Runtime], ["handler", c.Handler], ["memory", fmtUnit(c.MemorySize, "megabyte")],
              ["timeout", fmtSec(c.Timeout)], ["arch", (c.Architectures || []).join(", ")], ["codeSize", fmtBytes(c.CodeSize)],
              ["state", c.State], ["lastModified", fmtDate(c.LastModified)], ["env", envN ? t("envHidden", { n: envN }) : null],
              ["role", c.Role]]);
          }),
          chartGrid(t("metrics"), [
            chart(t("invocations"), "AWS/Lambda", "Invocations", [{ Name: "FunctionName", Value: fn }], ["Sum"]),
            chart(t("errors"), "AWS/Lambda", "Errors", [{ Name: "FunctionName", Value: fn }], ["Sum"]),
            chart(t("duration"), "AWS/Lambda", "Duration", [{ Name: "FunctionName", Value: fn }], ["Average", "Maximum"], fmtMs)]),
          panel(t("esm"), async () => esmTable((await lambda("event-source-mappings/?FunctionName=" + enc(fn))).EventSourceMappings || [])),
          panel(t("logs"), async () => {
            const config = await lambda("functions/" + enc(fn) + "/configuration");
            return logViewer(config.LoggingConfig?.LogGroup || "/aws/lambda/" + fn);
          }),
        ],
      ],
      logs: [
        () => {
          const body = h("div");
          const input = h("input", { type: "search", id: "lg-p", autocomplete: "off", placeholder: t("prefix"), value: prefs.prefix || "" });
          function load() {
            body.replaceChildren(paginatedPanel(t("logGroups"), (token) => api("logs", "DescribeLogGroups", {
              logGroupNamePrefix: prefs.prefix || undefined, nextToken: token, limit: 50,
            }), "logGroups", "nextToken", ["name", "stored|num", "retention", "created"], (groups) => groups.map((g) => [
              link(R.grp(g.logGroupName), g.logGroupName), fmtBytes(g.storedBytes),
              g.retentionInDays ? t("days", { n: g.retentionInDays }) : t("never"), fmtDate(g.creationTime)])));
          }
          load();
          return h("div", null,
            h("form", { cls: "toolbar", role: "search", onsubmit: (e) => { e.preventDefault(); prefs.prefix = input.value.trim(); load(); } },
              h("label", { cls: "sr", for: "lg-p", text: t("prefix") }), input), body);
        },
        (g) => [
          paginatedPanel(t("streams"), (token) => api("logs", "DescribeLogStreams", {
            logGroupName: g, orderBy: "LastEventTime", descending: true, limit: 50, nextToken: token,
          }), "logStreams", "nextToken", ["name", "lastEvent"], (streams) => streams.map((stream) => [stream.logStreamName, fmtDate(stream.lastEventTimestamp)])),
          logViewer(g),
        ],
      ],
      states: [
        () => paginatedPanel(t("stateMachines"),
          (token) => api("states", "ListStateMachines", { nextToken: token }),
          "stateMachines", "nextToken", ["name", "type", "created"],
          (machines) => machines.map((m) => [link(R.sm(m.stateMachineArn), m.name), m.type, fmtDate(m.creationDate)])),
        (arn) => arn.includes(":execution:") ? executionPage(arn) : [
          panel(t("config"), async () => {
            const d = await api("states", "DescribeStateMachine", { stateMachineArn: arn });
            const lg = (d.loggingConfiguration?.destinations || []).map((x) => x.cloudWatchLogsLogGroup?.logGroupArn).find(Boolean);
            const lgName = lg && lg.split(":log-group:")[1]?.replace(/:\*$/, "");
            return kv([["type", d.type], ["status", d.status], ["created", fmtDate(d.creationDate)], ["role", d.roleArn],
              ["logGroup", lgName ? h("span", null, link(R.grp(lgName), lgName), " · " + d.loggingConfiguration.level) : null]]);
          }),
          paginatedPanel(t("executions"), (token) => api("states", "ListExecutions", {
            stateMachineArn: arn, maxResults: 50, nextToken: token,
          }), "executions", "nextToken", ["name", "status", "started", "duration|num"], (executions) => executions.map((execution) => [
            link(R.sm(execution.executionArn), execution.name), badge(execution.status, { SUCCEEDED: "ok", RUNNING: "acc", FAILED: "bad", TIMED_OUT: "bad", ABORTED: "warn" }[execution.status]),
            fmtDate(execution.startDate), execution.stopDate ? fmtMs(toDate(execution.stopDate) - toDate(execution.startDate)) : "–"])),
        ],
      ],
      sqs: [
        () => paginatedPanel(t("queues"), (token) => api("sqs", "ListQueues", { MaxResults: 50, NextToken: token }),
          "QueueUrls", "NextToken", ["name", "available|num", "inFlight|num"], async (urls) => Promise.all(urls.map(async (url) => {
            const name = link(R.q(arnName(url)), arnName(url));
            try {
              const { Attributes: attributes = {} } = await api("sqs", "GetQueueAttributes", { QueueUrl: url,
                AttributeNames: ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"] });
              return [name, fmtInt(+attributes.ApproximateNumberOfMessages), fmtInt(+attributes.ApproximateNumberOfMessagesNotVisible)];
            } catch (e) { return [name, errBox(e), "–"]; }
          }))),
        (name) => {
          const dims = [{ Name: "QueueName", Value: name }];
          const info = (async () => {
            const { QueueUrl } = await api("sqs", "GetQueueUrl", { QueueName: name });
            const a = (await api("sqs", "GetQueueAttributes", { QueueUrl, AttributeNames: ["All"] })).Attributes || {};
            return { QueueUrl, a };
          })();
          return [
            panel(t("config"), async () => {
              const { a } = await info;
              const n = (k) => (a[k] == null ? null : fmtInt(+a[k]));
              return kv([["available", n("ApproximateNumberOfMessages")], ["inFlight", n("ApproximateNumberOfMessagesNotVisible")],
                ["delayed", n("ApproximateNumberOfMessagesDelayed")], ["visTimeout", a.VisibilityTimeout && fmtSec(a.VisibilityTimeout)],
                ["msgRetention", a.MessageRetentionPeriod && fmtUnit(a.MessageRetentionPeriod / 86400, "day")],
                ["maxSize", a.MaximumMessageSize && fmtBytes(a.MaximumMessageSize)], ["delay", a.DelaySeconds && fmtSec(a.DelaySeconds)],
                ["wait", a.ReceiveMessageWaitTimeSeconds && fmtSec(a.ReceiveMessageWaitTimeSeconds)],
                ["fifo", t(a.FifoQueue === "true" ? "yes" : "no")], ["created", fmtDate(a.CreatedTimestamp)], ["ARN", a.QueueArn]]);
            }),
            panel(t("redrive"), async () => {
              const { QueueUrl, a } = await info;
              const out = [];
              if (a.RedrivePolicy) {
                const p = JSON.parse(a.RedrivePolicy), dlq = arnName(p.deadLetterTargetArn);
                out.push(["dlqTarget", link(R.q(dlq), dlq)], ["maxReceive", fmtInt(+p.maxReceiveCount)]);
              }
              const src = (await api("sqs", "ListDeadLetterSourceQueues", { QueueUrl }).catch(() => ({}))).queueUrls || [];
              if (src.length) out.push(["dlqFor", h("span", null, src.map((u, i) => [i ? ", " : "", link(R.q(arnName(u)), arnName(u))]))]);
              return out.length ? kv(out) : msg("noRedrive");
            }),
            chartGrid(t("metrics"), [
              chart(t("sent"), "AWS/SQS", "NumberOfMessagesSent", dims, ["Sum"]),
              chart(t("received"), "AWS/SQS", "NumberOfMessagesReceived", dims, ["Sum"]),
              chart(t("deleted"), "AWS/SQS", "NumberOfMessagesDeleted", dims, ["Sum"]),
              chart(t("visibleMax"), "AWS/SQS", "ApproximateNumberOfMessagesVisible", dims, ["Maximum"]),
              chart(t("oldest"), "AWS/SQS", "ApproximateAgeOfOldestMessage", dims, ["Maximum"], fmtSec)]),
            panel(t("consumers"), async () => {
              const { a } = await info;
              return esmTable((await lambda("event-source-mappings/?EventSourceArn=" + enc(a.QueueArn))).EventSourceMappings || [], true);
            }),
          ];
        },
      ],
    };

    PAGES.apigatewayv2 = PAGES.apigateway;
    PAGES["execute-api"] = PAGES.apigateway;

    const GLOBAL_SERVICES = new Set(["iam", "sts", "route53", "cloudfront"]);
    const observedRecords = () => (state.activity?.records || []).filter((record) =>
      record.accountId === state.identity?.Account && (record.region === state.region || GLOBAL_SERVICES.has(record.service)));
    const hasError = (record) => record.httpStatus >= 400 || !!record.errorCode;
    function activityResource(record) {
      let resource = record.resource;
      if (!resource) return link(contextual(servicePath(record.service)), t("inspect"));
      if (record.service === "lambda") {
        try { resource = decodeURIComponent(resource); } catch {}
        return link(R.fn(resource), resource);
      }
      if (record.service === "states") return link(R.sm(resource), arnName(resource));
      if (record.service === "sqs") return link(R.q(arnName(resource)), arnName(resource));
      if (record.service === "logs") return link(R.grp(resource), resource);
      if (record.service === "dynamodb") return link(contextual(servicePath("dynamodb", resource)), resource);
      return resource;
    }
    let activityViewKey = "";
    function renderActivity() {
      const body = $("service-activity");
      if (!body) return;
      const records = observedRecords().filter((record) => record.service === state.svc);
      const key = [records[0]?.requestId, state.svc, state.errorsOnly, state.lang, state.activityError].join("|");
      if (key === activityViewKey) return;
      activityViewKey = key;
      if (state.activityError) { body.replaceChildren(h("p", { cls: "notice", role: "alert", text: state.activityError })); return; }
      const visible = records.filter((record) => !state.errorsOnly || hasError(record)).slice(0, 50);
      body.replaceChildren(table(["time", "operation", "resource", "result", "duration", "requestId"], visible.map((record) => [
        fmtClock(record.completedAt), record.operation, activityResource(record),
        badge(record.errorCode || t(hasError(record) ? "httpError" : "httpAccepted", { status: record.httpStatus }), hasError(record) ? "bad" : "ok"),
        fmtMs(record.durationMs), h("code", { title: record.requestId + " · " + record.region + " · " + record.accountId, text: record.requestId.slice(0, 8) }),
      ])), ...(state.activity?.evicted ? [msg("evictedActivity", { n: fmtInt(state.activity.evicted) })] : []));
    }
    function serviceDiagnostics() {
      activityViewKey = "";
      return h("details", { cls: "panel" }, h("summary", { text: t("serviceActivity") }),
        msg("serviceScope"), h("label", { cls: "check" }, h("input", { type: "checkbox", checked: state.errorsOnly,
          onchange: (e) => { state.errorsOnly = e.target.checked; renderActivity(); } }), t("errorsOnly")),
        h("div", { id: "service-activity" }));
    }
    function executionPage(arn) {
      return panel(t("executionHistory"), async () => {
        const d = await api("states", "DescribeExecution", { executionArn: arn });
        const history = await api("states", "GetExecutionHistory", { executionArn: arn, includeExecutionData: false, maxResults: 100 });
        const machine = await api("states", "DescribeStateMachine", { stateMachineArn: d.stateMachineArn });
        const lg = machine.loggingConfiguration?.destinations?.[0]?.cloudWatchLogsLogGroup?.logGroupArn?.split(":log-group:")[1]?.replace(/:\*$/, "");
        return [kv([["status", badge(d.status, d.status === "SUCCEEDED" ? "ok" : d.status === "RUNNING" ? "acc" : "bad")],
          ["errorCode", d.error], ["ARN", arn]]),
          h("p", null, link(R.sm(d.stateMachineArn), t("stateMachine")), " · ", lg ? link(R.grp(lg), t("logs")) : t("logsNotConfigured")),
          table(["time", "historyType", "state", "errorCode"], (history.events || []).map((event) => {
            const details = Object.entries(event).find(([key]) => key.endsWith("EventDetails"))?.[1] || {};
            return [fmtDate(event.timestamp), event.type, details.name, details.error];
          })), ...(history.nextToken ? [msg("historyLimited")] : [])];
      });
    }

    function renderBilling() {
      const services = state.doc?.services || [];
      $("billing-services").replaceChildren(msg("billingScope"),
        services.length ? table(["service", "requests|num", "cost|num"], services.filter((service) => service.requests > 0)
          .sort((a, b) => b.estimatedUsd - a.estimatedUsd)
          .map((service) => [link(contextual(servicePath(service.name)), service.name), fmtInt(service.requests), fmtUsd(service.estimatedUsd)]))
          : h("p", { cls: "dim", text: t(state.doc ? "empty" : "loading") }),
      );
    }

    // Dashboard paths are separate from AWS API routes; old hash bookmarks still work.
    let timers = [];
    function every(ms, fn) { timers.push(setInterval(fn, ms)); }
    async function route() {
      timers.forEach(clearInterval); timers = []; charts.length = 0;
      const legacy = (location.hash === "#app" ? "" : location.hash.replace(/^#\/?/, ""));
      state.readController.abort(); state.readController = new AbortController();
      let path = location.pathname.replace(/^\/(?:dashboard|home|_locallycloud\/ui)\/?/, "");
      const regional = location.pathname.match(/^\/([a-z][a-z0-9-]*-\d+)\/(.*)$/);
      state.profile = new URLSearchParams(location.search).get("profile") || state.profile || state.context?.defaultProfile || "instance";
      state.region = regional?.[1] || state.region || state.context?.defaultRegion || "us-east-1";
      if (regional) path = regional[2];
      state.identity = null; state.identityError = ""; state.inventoryError = "";
      state.activity = null; state.activityError = "";
      contextControls();
      $("detail").replaceChildren(msg("loading"));
      $("ov").hidden = true; $("billing").hidden = true; $("detail").hidden = false;
      const controller = state.readController;
      try {
        const identity = await read({ service: "sts", operation: "GetCallerIdentity" });
        if (controller.signal.aborted) return;
        if (!/^\d{12}$/.test(identity.Account || "") || !identity.Arn || !identity.UserId) throw new Error("Invalid STS identity response");
        state.identity = identity; renderIdentity();
        await Promise.all([refreshRegions(), refreshActivity()]);
        if (controller.signal.aborted) return;
      } catch (e) {
        if (controller.signal.aborted) return;
        state.identityError = e.auth ? t("authErr") : t("apiErr", { err: e.message });
        renderIdentity(); $("detail").replaceChildren(errBox(e)); $("crumbs").hidden = true;
        return;
      }
      const parts = (legacy || path).replace(/\/$/, "").split("/");
      if (parts[0] === "svc") parts.shift();
      const billing = parts[0] === "billing";
      const selected = !billing && parts[0] ? decodeURIComponent(parts[0]) : "";
      const svc = selected === "dynamo" ? "dynamodb" : selected;
      let id = svc && parts.length > 1 ? decodeURIComponent(parts.slice(1).join("/")) : "";
      if (svc === "states" && id && !id.startsWith("arn:")) {
        const [machine, execution] = id.split("/executions/");
        id = `arn:aws:states:${state.region}:${state.identity.Account}:${execution ? "execution" : "stateMachine"}:${machine}${execution ? ":" + execution : ""}`;
      }
      if (!regional && id.startsWith("arn:")) {
        const arnRegion = id.split(":")[3];
        if (arnRegion) state.region = arnRegion;
      }
      store.set("region", state.region); store.set("profile", state.profile);
      contextControls(); activityViewKey = "";
      // Canonicalize old dashboard/hash bookmarks without losing full resource identifiers.
      if (!regional || legacy) {
        const routeId = svc === "states" && id ? R.sm(id) : contextual(servicePath(svc, id));
        history.replaceState(null, "", billing ? contextual(homePath() + "billing/") : svc ? routeId : contextual(homePath()));
      }
      state.svc = svc;
      $("ov").hidden = !!svc || billing;
      $("billing").hidden = !billing;
      $("detail").hidden = !svc;
      $("crumbs").hidden = !svc;
      if (!svc && !billing) $("nav-overview").setAttribute("aria-current", "page");
      else $("nav-overview").removeAttribute("aria-current");
      if (billing) $("nav-billing").setAttribute("aria-current", "page");
      else $("nav-billing").removeAttribute("aria-current");
      if (billing) {
        $("detail").replaceChildren();
        document.title = t("billing") + " · LocallyCloud";
        renderBilling();
        return;
      }
      if (!svc) {
        $("detail").replaceChildren(); document.title = "LocallyCloud";
        renderRows(); return;
      }
      const crumbs = [[t("overview"), contextual(homePath())], [serviceName(svc), contextual(servicePath(svc))]];
      if (id) crumbs.push([svc === "states" ? arnName(id) : id]);
      crumbs[crumbs.length - 1][1] = null;
      $("crumbs").firstElementChild.replaceChildren(...crumbs.map(([txt, href]) =>
        h("li", null, href ? link(href, txt) : h("span", { "aria-current": "page", text: txt }))));
      document.title = crumbs.at(-1)[0] + " · LocallyCloud";
      const page = PAGES[svc];
      $("detail").replaceChildren(
        h("div", { cls: "phead" }, h("h2", { cls: "title", text: crumbs.at(-1)[0] }), h("button", { type: "button", cls: "link", text: t("refresh"), onclick: route })), h("p", { cls: "meta", id: "svcmeta" }),
        ...[page ? (id ? page[1](id) : page[0]()) : msg("noExplorer")].flat(), serviceDiagnostics());
      if (charts.length) every(60000, () => !document.hidden && charts.forEach((c) => c.load()));
      renderSvcMeta(); renderActivity(); renderRows();
      window.scrollTo(0, 0);
    }
    function renderSvcMeta() {
      const el = $("svcmeta"), s = state.doc?.services?.find((x) => x.name === state.svc);
      if (!el || !s) return;
      const records = observedRecords().filter((record) => record.service === state.svc);
      el.textContent = [GLOBAL_SERVICES.has(state.svc) ? t("globalScope", { account: state.identity.Account }) : state.region + " · " + state.identity.Account, t(s.disposition), s.protocol,
        ...(state.activityError ? [t("activityUnavailableShort")] : [fmtInt(records.length) + " " + t("totalRequests"), fmtInt(records.filter(hasError).length) + " " + t("apiErrors")])].join(" · ");
    }

    function applyLanguage() {
      document.documentElement.lang = state.lang;
      $("lang").value = state.lang;
      document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
      document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => { el.placeholder = t(el.dataset.i18nPlaceholder); });
      document.querySelectorAll("[data-i18n-label]").forEach((el) => { el.setAttribute("aria-label", t(el.dataset.i18nLabel)); });
      contextControls(); renderHeader();
      renderRows();
      activityViewKey = "";
      renderActivity();
    }

    function renderHeader() {
      const st = $("status");
      st.className = "status " + state.health;
      st.textContent = t(state.health);
      document.body.classList.toggle("stale", state.health === "offline" && !!state.doc);
      const notice = $("notice");
      notice.hidden = !state.error && !state.inventoryError;
      notice.textContent = state.error ? t("unreachable", { err: state.error }) : state.inventoryError ? t("inventoryUnavailable", { err: state.inventoryError }) : "";
      renderAgo();
      const doc = state.doc;
      if (!doc) return;
      $("version").textContent = doc.version ? "v" + doc.version : "";
      $("cost").textContent = fmtUsd(doc.estimatedCostUsd);
      if (!$("billing").hidden) renderBilling();
      renderSvcMeta();
    }

    function renderAgo() {
      if (!state.lastOk) { $("ago").textContent = ""; return; }
      const secs = Math.round((Date.now() - state.lastOk) / 1000);
      const rtf = new Intl.RelativeTimeFormat(state.lang, { numeric: "auto", style: "short" });
      $("ago").textContent = secs < 60 ? rtf.format(-secs, "second") : rtf.format(-Math.round(secs / 60), "minute");
    }

    function makeRow() {
      const tr = document.createElement("tr");
      tr.innerHTML = '<td class="svc"><a></a></td><td></td><td class="num"></td><td class="num"></td>';
      return tr;
    }

    function renderRows() {
      const counts = new Map();
      for (const record of observedRecords()) {
        const count = counts.get(record.service) || { requests: 0, errors: 0 };
        count.requests++; if (hasError(record)) count.errors++;
        counts.set(record.service, count);
      }
      const inventory = state.inventory && state.identity && state.inventory.accountId === state.identity.Account ? state.inventory.services : {};
      const active = (name) => inventory?.[name]?.global || inventory?.[name]?.regions?.includes(state.region);
      const services = (state.doc?.services ?? []).filter((service) => service.disposition === "Native").map((service) => ({ ...service, ...(counts.get(service.name) || { requests: 0, errors: 0 }) }));
      $("service-count").textContent = state.doc ? t("serviceCount", {
        active: fmtInt(services.filter((s) => active(s.name)).length), total: fmtInt(services.length),
      }) : "";
      const q = state.query.trim().toLowerCase();
      const matched = services.filter((s) => !q || (s.name + " " + serviceName(s.name)).toLowerCase().includes(q));
      const visible = matched.filter((s) => !state.hideIdle || active(s.name));
      visible.sort((a, b) =>
        state.sort === "requests" && b.requests !== a.requests
          ? (b.requests ?? 0) - (a.requests ?? 0)
          : a.name.localeCompare(b.name));

      const tbody = $("rows");
      const seen = new Set();
      for (const s of visible) {
        let tr = rowsByName.get(s.name);
        if (!tr) { tr = makeRow(); rowsByName.set(s.name, tr); }
        const [name, status, reqs, errors] = tr.children;
        if (name.firstChild.dataset.icon !== (s.icon || "")) {
          name.firstChild.replaceChildren(...serviceLabel(s.name));
          name.firstChild.dataset.icon = s.icon || "";
        }
        name.firstChild.href = contextual(servicePath(s.name));
        reqs.textContent = state.activityError ? "–" : fmtInt(s.requests);
        errors.textContent = state.activityError ? "–" : fmtInt(s.errors);
        errors.className = "num " + (!state.activityError && s.errors ? "b-bad" : "dim");
        status.replaceChildren(state.activityError ? badge(t("activityUnavailableShort"), "")
          : badge(t(s.errors ? "recentErrors" : s.requests ? "noErrors" : "noActivity"), s.errors ? "bad" : s.requests ? "ok" : ""));
        tr.classList.toggle("idle", !active(s.name));
        tbody.appendChild(tr); // moves existing node into sorted position
        seen.add(s.name);
      }
      for (const [name, tr] of rowsByName) {
        if (!seen.has(name)) { tr.remove(); rowsByName.delete(name); }
      }

      const more = $("more");
      const hidden = matched.length - visible.length;
      const cell = more.firstElementChild;
      cell.textContent = "";
      if (!state.doc) {
        more.hidden = true;
      } else if (hidden > 0) {
        more.hidden = false;
        cell.append(t("idleHidden", { n: hidden }) + " · ");
        const btn = document.createElement("button");
        btn.className = "link";
        btn.type = "button";
        btn.textContent = t("show");
        btn.onclick = () => setHideIdle(false);
        cell.append(btn);
      } else if (visible.length === 0) {
        more.hidden = false;
        cell.textContent = t("noMatch");
      } else {
        more.hidden = true;
      }
    }

    function setHideIdle(v) {
      state.hideIdle = v;
      $("hideIdle").checked = v;
      store.set("activeServicesOnly", v ? "1" : "0");
      renderRows();
    }

    let timer = null;
    async function poll() {
      try {
        state.doc = await call(STATUS_URL);
        if (state.identity) await Promise.all([refreshRegions(), refreshActivity()]);
        state.lastOk = Date.now();
        state.health = state.doc.ready ? "ready" : "starting";
        state.error = "";
      } catch (e) {
        state.health = "offline";
        state.error = e.message || String(e);
      }
      contextControls(); renderHeader();
      renderRows();
      renderActivity();
    }
    function start() { if (!timer) { poll(); timer = setInterval(poll, POLL_MS); } }
    function stop() { clearInterval(timer); timer = null; }

    $("lang").onchange = (e) => { state.lang = e.target.value; store.set("lang", state.lang); applyLanguage(); route(); };
    $("sort").value = state.sort;
    $("sort").onchange = (e) => { state.sort = e.target.value; store.set("serviceSort", state.sort); renderRows(); };
    $("hideIdle").checked = state.hideIdle;
    $("hideIdle").onchange = (e) => setHideIdle(e.target.checked);
    $("search").oninput = (e) => { state.query = e.target.value; renderRows(); renderActivity(); };
    document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
    document.addEventListener("click", (e) => {
      const a = e.target.closest("a");
      if (!a || a.hash === "#app" || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || a.origin !== location.origin || !/^\/(?:[a-z][a-z0-9-]*-\d+|dashboard)\//.test(a.pathname)) return;
      e.preventDefault(); history.pushState(null, "", a.href); route();
    });
    window.addEventListener("popstate", route);
    window.addEventListener("hashchange", () => { if (location.hash !== "#app") route(); });
    setInterval(renderAgo, 1000);

    function switchContext() {
      $("identity-panel").hidePopover();
      const profile = state.context.profiles.find((p) => p.name === $("profile").value);
      state.profile = profile.name;
      state.region = $("region").value || state.region;
      history.pushState(null, "", contextual(state.svc ? servicePath(state.svc) : homePath()));
      route();
    }
    $("region").onchange = switchContext;
    $("profile").onchange = () => {
      switchContext();
    };
    (async () => {
      try {
        state.context = await call("/_locallycloud/context");
        state.region = store.get("region", state.context.defaultRegion);
        const preferred = store.get("profile", state.context.defaultProfile);
        state.profile = state.context.profiles.some((p) => p.name === preferred) ? preferred : state.context.defaultProfile;
        applyLanguage(); await route(); start();
      } catch (e) { state.error = e.message; renderHeader(); }
    })();
