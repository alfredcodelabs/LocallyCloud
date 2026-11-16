/* Security report: the catalog assessment of a whole stack as findings ranked by severity.
   It reads the same facts and catalog as the threat model and adds no rules of its own. */
import * as A from "./assessment.js";
import * as Catalog from "./catalog.js";

export const FORMAT = "locallycloud-security-report";
export const VERSION = 1;
const RANKED = [...Catalog.SEVERITIES].reverse();

function element(model, target) {
  const id = target.slice(2);
  if (target.startsWith("n:")) {
    const node = model.nodes.find((n) => n.id === id);
    return { target, name: node?.name || id, type: node?.type || "" };
  }
  const edge = model.edges.find((e) => e.id === id);
  return {
    target,
    name: edge ? `${edge.from} → ${edge.to}` : id,
    type: edge ? `flow (${edge.kind})` : "flow",
  };
}

function finding(model, item, language) {
  const threat = Catalog.threat(item.catalogId);
  const unmet = item.controls.filter((c) => c.state === "unmet");
  return {
    severity: item.severity,
    rule: item.catalogId,
    title: Catalog.label(threat, language),
    category: item.category,
    element: element(model, item.target),
    evidence: unmet.flatMap((c) =>
      c.facts
        .filter((f) => f.state === "unmet")
        .map((f) => ({ control: c.id, fact: f.id, value: f.value, source: f.evidence })),
    ),
    recommendation: unmet.map((c) => ({
      control: c.id,
      text: Catalog.label(Catalog.control(c.id), language),
    })),
    decision: item.finding?.status || null,
  };
}

/** Controls that no declared fact could show, with how many elements depend on them. */
function unverified(items, language) {
  const counts = new Map();
  for (const item of items.filter((i) => i.state === "review")) {
    for (const c of item.controls.filter((c) => c.state === "unknown")) {
      const entry = counts.get(c.id) || {
        control: c.id,
        text: Catalog.label(Catalog.control(c.id), language),
        reason: c.facts.length ? "cannot-evaluate" : "no-fact",
        targets: new Set(),
      };
      entry.targets.add(item.target);
      counts.set(c.id, entry);
    }
  }
  return [...counts.values()]
    .map(({ targets, ...entry }) => ({ ...entry, elements: targets.size }))
    .sort((a, b) => b.elements - a.elements || a.control.localeCompare(b.control));
}

/** The report for every element of `model`, independent of saved views and of the diagram. */
export function build(model, language = "en") {
  const items = A.assess(model);
  const gaps = items.filter((i) => i.state === "gap");
  const findings = gaps
    .map((i) => finding(model, i, language))
    .sort(
      (a, b) =>
        RANKED.indexOf(a.severity) - RANKED.indexOf(b.severity) ||
        a.rule.localeCompare(b.rule) ||
        a.element.name.localeCompare(b.element.name),
    );
  const bySeverity = Object.fromEntries(
    RANKED.map((s) => [s, findings.filter((f) => f.severity === s).length]),
  );
  return {
    format: FORMAT,
    version: VERSION,
    catalog: Catalog.VERSION,
    stack: model.title,
    scope: {
      account: model.scope?.account || "",
      region: model.scope?.region || "",
      capturedAt: model.scope?.capturedAt || "",
    },
    basis: "declared-configuration",
    summary: {
      findings: bySeverity,
      toReview: items.filter((i) => i.state === "review").length,
      declared: items.filter((i) => i.state === "declared").length,
    },
    findings,
    unverified: unverified(items, language),
  };
}

/** Markdown cell text: no table breaks, no raw HTML, no line breaks. */
function cell(value) {
  return String(value ?? "")
    .replace(/\\/g, "\\\\")
    .replace(/\|/g, "\\|")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/[\r\n]+/g, " ");
}

function row(values) {
  return `| ${values.map(cell).join(" | ")} |`;
}

/** Markdown rendering; `t(key, vars)` and the label functions localize headings and values. */
export function markdown(report, { t, severity, category, status }) {
  const lines = [
    `# ${cell(t("arReportTitle"))}: ${cell(report.stack)}`,
    "",
    cell(
      [report.scope.account, report.scope.region, report.scope.capturedAt]
        .filter(Boolean)
        .join(" · "),
    ),
    "",
    `> ${cell(t("arReportBasis"))}`,
    "",
    `## ${cell(t("arReportSummary"))}`,
    "",
    row([t("arReportSeverity"), t("arReportFindings")]),
    row(["---", "---:"]),
    ...Object.entries(report.summary.findings).map(([s, n]) => row([severity(s), n])),
    "",
    cell(
      t("arReportOthers", {
        review: report.summary.toReview,
        declared: report.summary.declared,
      }),
    ),
    "",
    `## ${cell(t("arReportFindings"))}`,
    "",
  ];
  if (report.findings.length) {
    lines.push(
      row([
        t("arReportSeverity"),
        t("arReportRule"),
        t("arReportCategory"),
        t("arReportElement"),
        t("arReportEvidence"),
        t("arReportFix"),
        t("arReportDecision"),
      ]),
      row(["---", "---", "---", "---", "---", "---", "---"]),
      ...report.findings.map((f) =>
        row([
          severity(f.severity),
          `${f.rule} ${f.title}`,
          category(f.category),
          `${f.element.name} (${f.element.type})`,
          f.evidence.map((e) => `${e.fact}=${e.value} (${e.source})`).join("; "),
          f.recommendation.map((r) => r.text).join("; "),
          f.decision ? status(f.decision) : "—",
        ]),
      ),
    );
  } else {
    lines.push(cell(t("arReportNone")));
  }
  lines.push("", `## ${cell(t("arReportUnverified"))}`, "", cell(t("arReportUnverifiedNote")), "");
  if (report.unverified.length) {
    lines.push(
      row([t("arReportControl"), t("arReportReason"), t("arReportCount")]),
      row(["---", "---", "---:"]),
      ...report.unverified.map((u) =>
        row([`${u.control} ${u.text}`, t("arReportReason_" + u.reason), u.elements]),
      ),
    );
  } else {
    lines.push(cell(t("arReportNone")));
  }
  return lines.join("\n") + "\n";
}
