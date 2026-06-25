import type { Dossier } from "./store.js";
import type { Finding, Narrative, Remediation } from "./types.js";
import { byStr } from "./util.js";

// AI-authored report narrative (Phase 3). The engine emits a worklist of the
// confirmed/needs-human findings + a Narrative scaffold; the agent authors
// NARRATIVE.json (executive summary, per-finding fixes, attack chains, root-cause
// groups); `render --narrative` folds it in as clearly-marked, ADDITIVE sections.
// It never changes a finding's status/severity/set. `mergeNarrative` enforces
// grounding: any section citing an unknown or non-confirmed finding id is dropped.

export const AI_DISCLAIMER = "AI-authored — verify against the cited findings before acting.";

export interface NarrativeFindingRef {
  id: string;
  severity: string;
  title: string;
  category: string;
  cwe?: string;
  at: string;
  status: string;
  owner?: string;
}

export function citedAt(f: Finding): string {
  if (f.path?.length) return f.path.map((p) => `${p.file}:${p.line}`).join(" → ");
  if (f.sink) return `${f.sink.file}:${f.sink.line}`;
  if (f.source) return `${f.source.file}:${f.source.line}`;
  return "—";
}

/** Build the narrative worklist: the reportable findings + a fill-in scaffold. */
export function buildNarrativeWorklist(dossier: Dossier): { findings: NarrativeFindingRef[]; scaffold: Narrative } {
  const reportable = dossier.findings
    .filter((f) => f.status === "confirmed" || f.status === "needs-human")
    .slice()
    .sort((a, b) => byStr(a.id, b.id));
  const findings: NarrativeFindingRef[] = reportable.map((f) => ({
    id: f.id,
    severity: f.severity,
    title: f.title,
    category: f.category,
    ...(f.cwe ? { cwe: f.cwe } : {}),
    at: citedAt(f),
    status: f.status,
    ...(f.provenance?.owner ? { owner: f.provenance.owner } : {}),
  }));
  // Remediations are for CONFIRMED issues only (the merge will drop the rest).
  const scaffold: Narrative = {
    executiveSummary: "",
    positivePatterns: "",
    remediations: reportable
      .filter((f) => f.status === "confirmed")
      .map((f) => ({ id: f.id, fix: "", ...(f.provenance?.owner ? { owner: f.provenance.owner } : {}) })),
    attackChains: [],
    rootCauses: [],
    hardeningNotes: [],
  };
  return { findings, scaffold };
}

export function renderNarrativeWorklistMd(wl: { findings: NarrativeFindingRef[]; scaffold: Narrative }, context?: string): string {
  const L: string[] = [];
  L.push(`# ultrasec report-narrative worklist (${wl.findings.length})`);
  L.push("");
  L.push(`Author **NARRATIVE.json** (a Narrative object), then fold it into the report with`);
  L.push(`\`ultrasec render --narrative NARRATIVE.json --run <run>\`. Fields (all optional, all additive):`);
  L.push(`- \`executiveSummary\`: a few sentences for non-experts atop the report.`);
  L.push(`- \`positivePatterns\`: what the codebase does **well** (solid auth, parameterized queries…) — calibrates trust in the findings and helps prioritise. Free prose, advisory.`);
  L.push(`- \`remediations\`: \`{id, fix, patch?, owner?}\` — a concrete fix per **confirmed** finding.`);
  L.push(`- \`attackChains\`: \`{title, findingIds[], narrative}\` — how findings combine into an exploit.`);
  L.push(`- \`rootCauses\`: \`{cause, findingIds[], note}\` — group findings by shared underlying cause.`);
  L.push(`- \`hardeningNotes\`: \`string[]\` — defense-in-depth suggestions that are **not** findings (the attack is already prevented elsewhere). Advisory; excluded from the severity counts.`);
  L.push("");
  L.push(`> Grounding is strict for finding-citing sections: any \`remediations\`/\`attackChains\`/\`rootCauses\``);
  L.push(`> entry citing an **unknown or non-confirmed** finding id is dropped on merge. \`executiveSummary\`,`);
  L.push(`> \`positivePatterns\`, and \`hardeningNotes\` are advisory prose that cite no finding ids. Narrative`);
  L.push(`> prose **never** changes a finding's status, severity, or set.`);
  L.push("");
  if (context) {
    L.push(`## Project context`);
    L.push(`_From \`CONTEXT.md\`._`);
    L.push("");
    L.push(context);
    L.push("");
  }
  L.push(`## Reportable findings (cite these ids)`);
  L.push("");
  for (const f of wl.findings) {
    L.push(`- \`${f.id}\` — [${f.severity}] ${f.title} (${f.cwe ?? f.category}) · status ${f.status} · at ${f.at}${f.owner ? ` · owner ${f.owner}` : ""}`);
  }
  L.push("");
  L.push(`## Scaffold (starting point for NARRATIVE.json)`);
  L.push("```json");
  L.push(JSON.stringify(wl.scaffold, null, 2));
  L.push("```");
  return L.join("\n") + "\n";
}

/** Parse a NARRATIVE.json body into a Narrative, dropping malformed entries. Tolerant. */
export function parseNarrative(raw: string): Narrative {
  const d = JSON.parse(raw) as any;
  const n: Narrative = {};
  if (typeof d?.executiveSummary === "string") n.executiveSummary = d.executiveSummary;
  if (typeof d?.positivePatterns === "string") n.positivePatterns = d.positivePatterns;
  if (Array.isArray(d?.hardeningNotes)) {
    const hn = d.hardeningNotes.filter((x: any) => typeof x === "string" && x.trim()).map((x: string) => x.trim());
    if (hn.length) n.hardeningNotes = hn;
  }
  if (Array.isArray(d?.remediations)) {
    const rem: Remediation[] = d.remediations
      .filter((r: any) => r && typeof r.id === "string" && typeof r.fix === "string")
      .map((r: any) => ({ id: r.id, fix: r.fix, ...(typeof r.patch === "string" ? { patch: r.patch } : {}), ...(typeof r.owner === "string" ? { owner: r.owner } : {}) }));
    if (rem.length) n.remediations = rem;
  }
  if (Array.isArray(d?.attackChains)) {
    const ch = d.attackChains
      .filter((c: any) => c && typeof c.title === "string" && Array.isArray(c.findingIds) && typeof c.narrative === "string")
      .map((c: any) => ({ title: c.title, findingIds: c.findingIds.filter((x: any) => typeof x === "string"), narrative: c.narrative }));
    if (ch.length) n.attackChains = ch;
  }
  if (Array.isArray(d?.rootCauses)) {
    const rc = d.rootCauses
      .filter((g: any) => g && typeof g.cause === "string" && Array.isArray(g.findingIds) && typeof g.note === "string")
      .map((g: any) => ({ cause: g.cause, findingIds: g.findingIds.filter((x: any) => typeof x === "string"), note: g.note }));
    if (rc.length) n.rootCauses = rc;
  }
  return n;
}

/**
 * Enforce grounding: keep only narrative sections whose cited finding ids are all
 * CONFIRMED in the dossier. A remediation for an unknown/non-confirmed id is
 * dropped; an attack chain or root-cause group citing any non-confirmed id is
 * dropped. The executive summary (free prose, no structural citation) is kept.
 */
export function mergeNarrative(n: Narrative, dossier: Dossier): Narrative {
  const confirmed = new Set(dossier.findings.filter((f) => f.status === "confirmed").map((f) => f.id));
  const out: Narrative = {};
  if (n.executiveSummary && n.executiveSummary.trim()) out.executiveSummary = n.executiveSummary.trim();
  // Advisory prose — no finding-id citation, so no grounding gate (like the executive summary).
  if (n.positivePatterns && n.positivePatterns.trim()) out.positivePatterns = n.positivePatterns.trim();
  if (n.hardeningNotes?.length) out.hardeningNotes = n.hardeningNotes;
  const rem = (n.remediations ?? []).filter((r) => confirmed.has(r.id));
  if (rem.length) out.remediations = rem;
  const chains = (n.attackChains ?? []).filter((c) => c.findingIds.length > 0 && c.findingIds.every((id) => confirmed.has(id)));
  if (chains.length) out.attackChains = chains;
  const rc = (n.rootCauses ?? []).filter((g) => g.findingIds.length > 0 && g.findingIds.every((id) => confirmed.has(id)));
  if (rc.length) out.rootCauses = rc;
  return out;
}

export function hasNarrativeContent(n?: Narrative): boolean {
  return !!n && !!(n.executiveSummary || n.positivePatterns || n.remediations?.length || n.attackChains?.length || n.rootCauses?.length || n.hardeningNotes?.length);
}

export function remediationMap(n?: Narrative): Map<string, Remediation> {
  const m = new Map<string, Remediation>();
  for (const r of n?.remediations ?? []) m.set(r.id, r);
  return m;
}

// ── Markdown fragments (shared by render/report.ts) ──────────────────────────
export function executiveSummaryMd(n?: Narrative): string[] {
  if (!n?.executiveSummary) return [];
  return [`## Executive summary (AI-authored)`, `_${AI_DISCLAIMER}_`, "", n.executiveSummary, ""];
}

export function positivePatternsMd(n?: Narrative): string[] {
  if (!n?.positivePatterns) return [];
  return [`## What the codebase does well (AI-authored)`, `_${AI_DISCLAIMER}_`, "", n.positivePatterns, ""];
}

export function suggestedFixMd(r: Remediation | undefined): string[] {
  if (!r) return [];
  const L = ["", `**Suggested fix (AI):** ${r.fix}${r.owner ? ` · owner ${r.owner}` : ""}`];
  if (r.patch) L.push("", "```diff", r.patch, "```");
  return L;
}

export function attackChainsMd(n?: Narrative): string[] {
  if (!n?.attackChains?.length) return [];
  const L = [`## Attack chains (AI-authored)`, `_${AI_DISCLAIMER}_`, ""];
  for (const c of n.attackChains) {
    L.push(`### ${c.title}`);
    L.push(`- findings: ${c.findingIds.map((id) => `\`${id}\``).join(" → ")}`);
    L.push("");
    L.push(c.narrative);
    L.push("");
  }
  return L;
}

export function rootCausesMd(n?: Narrative): string[] {
  if (!n?.rootCauses?.length) return [];
  const L = [`## Root-cause groups (AI-authored)`, `_${AI_DISCLAIMER}_`, ""];
  for (const g of n.rootCauses) {
    L.push(`### ${g.cause}`);
    L.push(`- findings: ${g.findingIds.map((id) => `\`${id}\``).join(", ")}`);
    L.push("");
    L.push(g.note);
    L.push("");
  }
  return L;
}

export function hardeningNotesMd(n?: Narrative): string[] {
  if (!n?.hardeningNotes?.length) return [];
  const L = [
    `## Hardening notes (AI-authored)`,
    `_${AI_DISCLAIMER}_`,
    "",
    `_Defense-in-depth suggestions — **not** findings (the attack is already prevented elsewhere); excluded from the severity counts._`,
    "",
  ];
  for (const note of n.hardeningNotes) L.push(`- ${note}`);
  L.push("");
  return L;
}
