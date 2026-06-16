import type { Dossier } from "../store.js";
import { SEVERITIES, type Finding, type Severity } from "../types.js";
import { pathMermaid } from "./mermaid.js";
import { byStr } from "../util.js";

// The tiered Markdown report: SUMMARY (TL;DR), REPORT (confirmed + needs-human,
// actionable), FULL (everything incl. dismissed, with the reasoning trail).

const BADGE: Record<Severity, string> = {
  critical: "🟥 CRITICAL",
  high: "🟧 HIGH",
  medium: "🟨 MEDIUM",
  low: "🟩 LOW",
  info: "⬜ INFO",
};

function sevRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

function sortFindings(fs: Finding[]): Finding[] {
  return fs.slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || byStr(a.id, b.id));
}

function pathLine(f: Finding): string {
  if (f.path?.length) return f.path.map((p) => `\`${p.file}:${p.line}\``).join(" → ");
  if (f.sink) return `\`${f.sink.file}:${f.sink.line}\``;
  return "—";
}

function header(d: Dossier): string {
  const c = d.manifest.counts.bySeverity;
  return [
    `repo \`${d.manifest.repo}\` · ultrasec ${d.manifest.version}`,
    `findings: **${d.manifest.counts.findings}** — ${SEVERITIES.map((s) => `${BADGE[s]} ${c[s]}`).join(" · ")}`,
    `tools: ${d.manifest.toolsRun.join(", ") || "none (graph + taint only)"}`,
  ].join("  \n");
}

function statusTag(f: Finding): string {
  const v = f.verdict ? ` · verdict ${f.verdict}` : "";
  return `status **${f.status}**${v} · confidence ${f.confidence}`;
}

export function renderSummary(d: Dossier): string {
  const fs = sortFindings(d.findings);
  const confirmed = fs.filter((f) => f.status === "confirmed");
  const needs = fs.filter((f) => f.status === "needs-human");
  const L: string[] = [`# Security audit — summary`, "", header(d), ""];
  if (!confirmed.length && !needs.length) {
    L.push(d.findings.length ? `No confirmed issues. ${d.findings.length} candidate(s) — see REPORT.md.` : `No findings.`);
    return L.join("\n") + "\n";
  }
  if (confirmed.length) {
    L.push(`## Confirmed (${confirmed.length})`);
    for (const f of confirmed) L.push(`- ${BADGE[f.severity]} **${f.title}** — ${pathLine(f)} (${f.cwe ?? f.category})`);
    L.push("");
  }
  if (needs.length) {
    L.push(`## Needs human review (${needs.length})`);
    for (const f of needs) L.push(`- ${BADGE[f.severity]} ${f.title} — ${pathLine(f)} (${f.cwe ?? f.category})`);
  }
  return L.join("\n") + "\n";
}

function renderFinding(f: Finding, opts: { mermaid?: boolean } = {}): string {
  const L: string[] = [];
  L.push(`### ${BADGE[f.severity]} ${f.title}`);
  L.push("");
  L.push(`\`${f.id}\` · ${f.cwe ? `[${f.cwe}](${(f.references ?? [])[0] ?? `https://cwe.mitre.org/`}) · ` : ""}${f.category} · ${statusTag(f)}${f.tool !== "ultrasec" ? ` · via ${f.tool}` : ""}`);
  L.push("");
  L.push(`**Path:** ${pathLine(f)}`);
  L.push("");
  L.push(f.message);
  if (f.exploitPath) {
    L.push("");
    L.push(`**Exploit path:** ${f.exploitPath}`);
  }
  if (opts.mermaid) {
    const mm = pathMermaid(f);
    if (mm) {
      L.push("");
      L.push("```mermaid");
      L.push(mm);
      L.push("```");
    }
  }
  if (f.references?.length) {
    L.push("");
    L.push(`References: ${f.references.slice(0, 5).map((r) => `<${r}>`).join(" · ")}`);
  }
  return L.join("\n");
}

export function renderReport(d: Dossier): string {
  const fs = sortFindings(d.findings).filter((f) => f.status === "confirmed" || f.status === "needs-human" || f.status === "open");
  const L: string[] = [`# Security audit — report`, "", header(d), ""];
  if (!fs.length) {
    L.push(`No actionable findings. (See FULL.md for dismissed candidates.)`);
    return L.join("\n") + "\n";
  }
  L.push(`Confirmed and to-review findings, most severe first. Dismissed candidates are in FULL.md.`);
  L.push("");
  for (const f of fs) {
    L.push(renderFinding(f, { mermaid: true }));
    L.push("");
    L.push("---");
    L.push("");
  }
  return L.join("\n") + "\n";
}

export function renderFull(d: Dossier): string {
  const fs = sortFindings(d.findings);
  const L: string[] = [`# Security audit — full`, "", header(d), ""];
  const groups: [string, Finding[]][] = [
    ["Confirmed", fs.filter((f) => f.status === "confirmed")],
    ["Needs human review", fs.filter((f) => f.status === "needs-human")],
    ["Unadjudicated candidates", fs.filter((f) => f.status === "open")],
    ["Dismissed", fs.filter((f) => f.status === "dismissed")],
  ];
  for (const [name, list] of groups) {
    if (!list.length) continue;
    L.push(`## ${name} (${list.length})`);
    L.push("");
    for (const f of list) {
      L.push(renderFinding(f, { mermaid: name !== "Dismissed" }));
      L.push("");
    }
  }
  L.push(`---`);
  L.push(`Engine: ultrasec ${d.manifest.version}. ${d.manifest.generatedNote}`);
  return L.join("\n") + "\n";
}
