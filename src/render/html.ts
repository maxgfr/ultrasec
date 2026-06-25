import type { Dossier } from "../store.js";
import { SEVERITIES, type Finding, type Narrative, type Remediation, type Severity } from "../types.js";
import { byStr } from "../util.js";
import { AI_DISCLAIMER, hasNarrativeContent, remediationMap } from "../narrative.js";

// A single self-contained index.html — embedded CSS, no external assets, no JS
// required. The cross-file path renders as offline boxes-and-arrows so it works
// without a network (Mermaid source still lives in the Markdown report).

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

const SEV_COLOR: Record<Severity, string> = {
  critical: "#b91c1c",
  high: "#c2410c",
  medium: "#b45309",
  low: "#15803d",
  info: "#64748b",
};

function sevRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

function badge(text: string, color: string): string {
  return `<span class="badge" style="background:${color}">${esc(text)}</span>`;
}

function pathHtml(f: Finding): string {
  if (!f.path?.length) return f.sink ? `<code>${esc(f.sink.file)}:${f.sink.line}</code>` : "—";
  const nodes = f.path
    .map((p, i) => {
      const tag = i === 0 ? "source" : i === f.path!.length - 1 ? "sink" : "hop";
      const sym = p.symbol ? `<div class="sym">${esc(p.symbol)}()</div>` : "";
      return `<div class="node ${tag}"><div class="loc">${esc(p.file)}:${p.line}</div>${sym}<div class="why">${esc(p.why)}</div></div>`;
    })
    .join('<div class="arrow">→</div>');
  return `<div class="flow">${nodes}</div>`;
}

function riskHtml(f: Finding): string {
  const out: string[] = [];
  if (typeof f.risk === "number") out.push(badge(`risk ${f.risk}`, f.risk >= 95 ? "#7f1d1d" : f.risk >= 70 ? "#b91c1c" : f.risk >= 40 ? "#b45309" : "#475569"));
  if (typeof f.epss === "number") out.push(`<span class="kv">EPSS ${(f.epss * 100).toFixed(1)}%</span>`);
  if (f.kev) out.push(badge(`CISA KEV${f.kevDateAdded ? ` ${f.kevDateAdded}` : ""}`, "#7f1d1d"));
  if (f.verified) out.push(badge("verified secret", "#7f1d1d"));
  return out.length ? `<div class="risk">${out.join(" ")}</div>` : "";
}

function sourcesHtml(f: Finding): string {
  const s = f.sources && f.sources.length ? f.sources : f.tool !== "ultrasec" ? [f.tool] : [];
  if (s.length > 1) return `· agreed by ${esc(s.join(", "))}`;
  return f.tool !== "ultrasec" ? `· via ${esc(f.tool)}` : "";
}

function fixHtml(r?: Remediation): string {
  if (!r) return "";
  const patch = r.patch ? `<pre class="ai-patch">${esc(r.patch)}</pre>` : "";
  return `\n    <div class="ai-fix"><strong>Suggested fix (AI):</strong> ${esc(r.fix)}${r.owner ? ` · owner ${esc(r.owner)}` : ""}${patch}</div>`;
}

function findingHtml(f: Finding, rem?: Remediation): string {
  const refs = (f.references ?? [])
    .slice(0, 5)
    .map((r) => `<a href="${esc(r)}" rel="noreferrer noopener">${esc(r.replace(/^https?:\/\//, ""))}</a>`)
    .join(" · ");
  return `
  <section class="finding" id="${esc(f.id)}">
    <h3>${badge(f.severity.toUpperCase(), SEV_COLOR[f.severity])} ${esc(f.title)}</h3>
    <div class="meta">
      <code>${esc(f.id)}</code>
      ${f.cwe ? `· ${esc(f.cwe)}` : ""} · ${esc(f.category)}
      · status ${badge(f.status, f.status === "confirmed" ? "#b91c1c" : f.status === "needs-human" ? "#b45309" : f.status === "dismissed" ? "#64748b" : "#475569")}
      · confidence ${esc(f.confidence)}
      ${f.verdict ? `· verdict ${esc(f.verdict)}` : ""}
      ${sourcesHtml(f)}
    </div>
    ${riskHtml(f)}
    ${pathHtml(f)}
    <p class="msg">${esc(f.message)}</p>
    ${f.exploitPath ? `<p class="exploit"><strong>Exploit path:</strong> ${esc(f.exploitPath)}</p>` : ""}${fixHtml(rem)}
    ${refs ? `<p class="refs">${refs}</p>` : ""}
  </section>`;
}

function aiSectionHtml(title: string, items: string): string {
  return `\n  <section class="ai-narrative"><h2>${esc(title)} <span class="ai-tag">AI</span></h2><p class="ai-note">${esc(AI_DISCLAIMER)}</p>${items}</section>`;
}

function execSummaryHtml(n?: Narrative): string {
  if (!n?.executiveSummary) return "";
  return aiSectionHtml("Executive summary", `<p>${esc(n.executiveSummary)}</p>`);
}

function positivePatternsHtml(n?: Narrative): string {
  if (!n?.positivePatterns) return "";
  return aiSectionHtml("What the codebase does well", `<p>${esc(n.positivePatterns)}</p>`);
}

function hardeningNotesHtml(n?: Narrative): string {
  if (!n?.hardeningNotes?.length) return "";
  const items = `<p class="ai-note">Defense-in-depth suggestions — not findings; excluded from the severity counts.</p><ul>${n.hardeningNotes
    .map((h) => `<li>${esc(h)}</li>`)
    .join("")}</ul>`;
  return aiSectionHtml("Hardening notes", items);
}

function chainsHtml(n?: Narrative): string {
  if (!n?.attackChains?.length) return "";
  const items = n.attackChains
    .map((c) => `<div class="ai-block"><h3>${esc(c.title)}</h3><div class="meta">${c.findingIds.map((id) => `<code>${esc(id)}</code>`).join(" → ")}</div><p>${esc(c.narrative)}</p></div>`)
    .join("");
  return aiSectionHtml("Attack chains", items);
}

function rootCausesHtml(n?: Narrative): string {
  if (!n?.rootCauses?.length) return "";
  const items = n.rootCauses
    .map((g) => `<div class="ai-block"><h3>${esc(g.cause)}</h3><div class="meta">${g.findingIds.map((id) => `<code>${esc(id)}</code>`).join(", ")}</div><p>${esc(g.note)}</p></div>`)
    .join("");
  return aiSectionHtml("Root-cause groups", items);
}

// Injected only when --narrative carries content, so a no-narrative render stays
// byte-identical (the rules are appended after the last base rule, before </style>).
function aiCss(narrative?: Narrative): string {
  if (!hasNarrativeContent(narrative)) return "";
  return `\n  .ai-narrative { border:1px solid #6d28d9; background:#faf5ff; border-radius:10px; padding:10px 16px; margin:14px 0; }
  @media (prefers-color-scheme: dark){ .ai-narrative{ background:#1e1b2e; border-color:#7c3aed; } .ai-fix{ background:#1e1b2e; } }
  .ai-tag { background:#6d28d9; color:#fff; font-size:11px; padding:1px 6px; border-radius:8px; vertical-align:middle; }
  .ai-note { color:#6b7280; font-size:12px; font-style:italic; margin:2px 0 8px; }
  .ai-fix { border-left:3px solid #6d28d9; background:#faf5ff; padding:6px 10px; border-radius:4px; margin:8px 0; }
  .ai-patch { background:#0b0f17; color:#e5e7eb; padding:8px; border-radius:6px; overflow:auto; font-size:12px; }
  .ai-block { margin:8px 0; }`;
}

export function renderHtml(d: Dossier, narrative?: Narrative): string {
  const c = d.manifest.counts.bySeverity;
  const fs = d.findings
    .slice()
    .sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1) || sevRank(a.severity) - sevRank(b.severity) || byStr(a.id, b.id));
  const shown = fs.filter((f) => f.status !== "dismissed");
  const dismissed = fs.filter((f) => f.status === "dismissed");
  const rem = remediationMap(narrative);

  const counts = SEVERITIES.map((s) => `${badge(`${s} ${c[s]}`, SEV_COLOR[s])}`).join(" ");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ultrasec — security audit</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 980px; margin: 0 auto; padding: 24px; color: #111; background: #fff; }
  @media (prefers-color-scheme: dark) { body { color: #e5e7eb; background: #0b0f17; } a { color: #93c5fd; } code { background: #1f2937; } .node { background: #111827; border-color:#374151; } .finding{border-color:#1f2937;} }
  h1 { font-size: 24px; margin: 0 0 4px; }
  .sub { color: #6b7280; margin-bottom: 16px; }
  .badge { display:inline-block; color:#fff; padding:1px 8px; border-radius:10px; font-size:12px; font-weight:600; }
  code { background:#f3f4f6; padding:1px 5px; border-radius:4px; font-size:13px; }
  .finding { border:1px solid #e5e7eb; border-radius:10px; padding:14px 16px; margin:14px 0; }
  .finding h3 { margin:0 0 6px; font-size:17px; }
  .meta { color:#6b7280; font-size:13px; margin-bottom:10px; }
  .flow { display:flex; flex-wrap:wrap; align-items:stretch; gap:6px; margin:10px 0; }
  .node { background:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; padding:6px 10px; min-width:120px; }
  .node.source { border-color:#b45309; } .node.sink { border-color:#b91c1c; }
  .node .loc { font-family: ui-monospace, monospace; font-size:12px; font-weight:600; }
  .node .sym { font-family: ui-monospace, monospace; font-size:11px; color:#6b7280; }
  .node .why { font-size:11px; color:#6b7280; margin-top:2px; max-width:220px; }
  .arrow { align-self:center; color:#9ca3af; font-size:18px; }
  .msg { margin:8px 0; }
  .exploit { background:#fef2f2; border-left:3px solid #b91c1c; padding:6px 10px; border-radius:4px; }
  @media (prefers-color-scheme: dark){ .exploit{ background:#1f1315; } }
  .refs { font-size:12px; color:#6b7280; word-break:break-all; }
  .risk { margin:6px 0 4px; display:flex; flex-wrap:wrap; gap:6px; align-items:center; }
  .kv { font-size:12px; font-weight:600; color:#6b7280; }
  details { margin-top:18px; }${aiCss(narrative)}
</style></head>
<body>
  <h1>Security audit</h1>
  <div class="sub">repo <code>${esc(d.manifest.repo)}</code> · ultrasec ${esc(d.manifest.version)} · tools: ${esc(d.manifest.toolsRun.join(", ") || "none")}</div>
  <div>${counts}</div>${execSummaryHtml(narrative)}${positivePatternsHtml(narrative)}
  ${shown.length ? shown.map((f) => findingHtml(f, rem.get(f.id))).join("\n") : "<p>No actionable findings.</p>"}
  ${dismissed.length ? `<details><summary>${dismissed.length} dismissed candidate(s)</summary>${dismissed.map((f) => findingHtml(f, rem.get(f.id))).join("\n")}</details>` : ""}${chainsHtml(narrative)}${rootCausesHtml(narrative)}${hardeningNotesHtml(narrative)}
</body></html>
`;
}
