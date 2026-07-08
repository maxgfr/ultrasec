import { locationsLine, type Dossier } from "../store.js";
import { SEVERITIES, type Finding, type Narrative, type Remediation, type Severity } from "../types.js";
import { pathMermaid } from "./mermaid.js";
import { byStr } from "../util.js";
import { executiveSummaryMd, positivePatternsMd, suggestedFixMd, attackChainsMd, rootCausesMd, hardeningNotesMd, remediationMap } from "../narrative.js";

// The tiered Markdown report: SUMMARY (TL;DR) and REPORT — the complete audit,
// every finding grouped by status (incl. dismissed), with the reasoning trail.

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

// Primary sort key is the composite risk score (EPSS/KEV-aware); severity then
// id break ties and order pre-enrichment dossiers sensibly.
function sortFindings(fs: Finding[]): Finding[] {
  return fs.slice().sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1) || sevRank(a.severity) - sevRank(b.severity) || byStr(a.id, b.id));
}

/** Risk / EPSS / KEV / verified annotations, when present. */
function riskTag(f: Finding): string {
  const parts: string[] = [];
  if (typeof f.risk === "number") parts.push(`risk ${f.risk}`);
  if (typeof f.epss === "number") parts.push(`EPSS ${(f.epss * 100).toFixed(1)}%`);
  if (f.kev) parts.push(`🚨 CISA KEV${f.kevDateAdded ? ` (${f.kevDateAdded})` : ""}`);
  if (f.verified) parts.push(`✅ verified secret`);
  return parts.join(" · ");
}

/** Deterministic blame/owner provenance, when present (opt-in `--blame`). */
function provTag(f: Finding): string {
  const p = f.provenance;
  if (!p) return "";
  const who = [p.author, p.date].filter(Boolean).join(" · ");
  return [who, p.commit ? `@${p.commit}` : "", p.owner ? `owner ${p.owner}` : ""].filter(Boolean).join(" · ");
}

/** "agreed by a, b" when multiple scanners corroborate; else "via <tool>". */
function sourcesTag(f: Finding): string {
  const s = f.sources && f.sources.length ? f.sources : f.tool !== "ultrasec" ? [f.tool] : [];
  if (s.length > 1) return `agreed by ${s.join(", ")}`;
  return f.tool !== "ultrasec" ? `via ${f.tool}` : "";
}

function pathLine(f: Finding): string {
  if (f.path?.length) return f.path.map((p) => `\`${p.file}:${p.line}\``).join(" → ");
  if (f.sink) return `\`${f.sink.file}:${f.sink.line}\``;
  return "—";
}

function header(d: Dossier): string {
  const c = d.manifest.counts.bySeverity;
  const kev = d.findings.filter((f) => f.kev).length;
  const ranked = d.findings.some((f) => typeof f.risk === "number");
  const lines = [
    `repo \`${d.manifest.repo}\` · ultrasec ${d.manifest.version}`,
    `findings: **${d.manifest.counts.findings}** — ${SEVERITIES.map((s) => `${BADGE[s]} ${c[s]}`).join(" · ")}${kev ? ` · 🚨 ${kev} in CISA KEV` : ""}`,
    `tools: ${d.manifest.toolsRun.join(", ") || "none (graph + taint only)"}`,
  ];
  if (ranked) lines.push(`_ranked by composite risk (severity ⊕ EPSS ⊕ KEV)_`);
  return lines.join("  \n");
}

function statusTag(f: Finding): string {
  const v = f.verdict ? ` · verdict ${f.verdict}` : "";
  return `status **${f.status}**${v} · confidence ${f.confidence}`;
}

export function renderSummary(d: Dossier, narrative?: Narrative): string {
  const fs = sortFindings(d.findings);
  const confirmed = fs.filter((f) => f.status === "confirmed");
  const needs = fs.filter((f) => f.status === "needs-human");
  const L: string[] = [`# Security audit — summary`, "", header(d), "", ...executiveSummaryMd(narrative), ...positivePatternsMd(narrative)];
  if (!confirmed.length && !needs.length) {
    L.push(d.findings.length ? `No confirmed issues. ${d.findings.length} candidate(s) — see REPORT.md.` : `No findings.`);
    return L.join("\n") + "\n";
  }
  const tail = (f: Finding) => {
    const rt = riskTag(f);
    return ` (${f.cwe ?? f.category})${rt ? ` · ${rt}` : ""}`;
  };
  if (confirmed.length) {
    L.push(`## Confirmed (${confirmed.length})`);
    for (const f of confirmed) L.push(`- ${BADGE[f.severity]} **${f.title}** — ${pathLine(f)}${tail(f)}`);
    L.push("");
  }
  if (needs.length) {
    L.push(`## Needs human review (${needs.length})`);
    for (const f of needs) L.push(`- ${BADGE[f.severity]} ${f.title} — ${pathLine(f)}${tail(f)}`);
  }
  return L.join("\n") + "\n";
}

function renderFinding(f: Finding, opts: { mermaid?: boolean; remediation?: Remediation } = {}): string {
  const L: string[] = [];
  L.push(`### ${BADGE[f.severity]} ${f.title}`);
  L.push("");
  const src = sourcesTag(f);
  L.push(
    `\`${f.id}\` · ${f.cwe ? `[${f.cwe}](${(f.references ?? [])[0] ?? `https://cwe.mitre.org/`}) · ` : ""}${f.category} · ${statusTag(f)}${src ? ` · ${src}` : ""}`,
  );
  const rt = riskTag(f);
  if (rt) {
    L.push("");
    L.push(`**Risk:** ${rt}`);
  }
  L.push("");
  L.push(`**Path:** ${pathLine(f)}`);
  if (f.locations?.length) {
    L.push("");
    L.push(`**Affects:** ${locationsLine(f.locations)}`);
  }
  const pv = provTag(f);
  if (pv) {
    L.push("");
    L.push(`**Provenance:** ${pv}`);
  }
  L.push("");
  L.push(f.message);
  if (f.exploitPath) {
    L.push("");
    L.push(`**Exploit path:** ${f.exploitPath}`);
  }
  // AI-authored suggested fix (presence-gated): only when a remediation for this
  // finding was provided via --narrative; absent ⇒ no change to today's output.
  L.push(...suggestedFixMd(opts.remediation));
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
    L.push(
      `References: ${f.references
        .slice(0, 5)
        .map((r) => `<${r}>`)
        .join(" · ")}`,
    );
  }
  return L.join("\n");
}

export function renderReport(d: Dossier, narrative?: Narrative): string {
  const fs = sortFindings(d.findings);
  const rem = remediationMap(narrative);
  const L: string[] = [`# Security audit — report`, "", header(d), "", ...executiveSummaryMd(narrative), ...positivePatternsMd(narrative)];
  const groups: [string, Finding[]][] = [
    ["Confirmed", fs.filter((f) => f.status === "confirmed")],
    ["Needs human review", fs.filter((f) => f.status === "needs-human")],
    ["Unadjudicated candidates", fs.filter((f) => f.status === "open")],
    ["Dismissed", fs.filter((f) => f.status === "dismissed")],
  ];
  if (!groups.some(([, list]) => list.length)) {
    L.push(`No findings.`);
    return L.join("\n") + "\n";
  }
  for (const [name, list] of groups) {
    if (!list.length) continue;
    L.push(`## ${name} (${list.length})`);
    L.push("");
    for (const f of list) {
      L.push(renderFinding(f, { mermaid: name !== "Dismissed", remediation: rem.get(f.id) }));
      L.push("");
    }
  }
  L.push(...attackChainsMd(narrative), ...rootCausesMd(narrative), ...hardeningNotesMd(narrative));
  L.push(`---`);
  L.push(`Engine: ultrasec ${d.manifest.version}. ${d.manifest.generatedNote}`);
  return L.join("\n") + "\n";
}
