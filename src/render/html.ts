import type { Dossier } from "../store.js";
import { SEVERITIES, type Finding, type Severity } from "../types.js";
import { byStr } from "../util.js";

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

function findingHtml(f: Finding): string {
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
      ${f.tool !== "ultrasec" ? `· via ${esc(f.tool)}` : ""}
    </div>
    ${pathHtml(f)}
    <p class="msg">${esc(f.message)}</p>
    ${f.exploitPath ? `<p class="exploit"><strong>Exploit path:</strong> ${esc(f.exploitPath)}</p>` : ""}
    ${refs ? `<p class="refs">${refs}</p>` : ""}
  </section>`;
}

export function renderHtml(d: Dossier): string {
  const c = d.manifest.counts.bySeverity;
  const fs = d.findings
    .slice()
    .sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || byStr(a.id, b.id));
  const shown = fs.filter((f) => f.status !== "dismissed");
  const dismissed = fs.filter((f) => f.status === "dismissed");

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
  details { margin-top:18px; }
</style></head>
<body>
  <h1>Security audit</h1>
  <div class="sub">repo <code>${esc(d.manifest.repo)}</code> · ultrasec ${esc(d.manifest.version)} · tools: ${esc(d.manifest.toolsRun.join(", ") || "none")}</div>
  <div>${counts}</div>
  ${shown.length ? shown.map(findingHtml).join("\n") : "<p>No actionable findings.</p>"}
  ${dismissed.length ? `<details><summary>${dismissed.length} dismissed candidate(s)</summary>${dismissed.map(findingHtml).join("\n")}</details>` : ""}
</body></html>
`;
}
