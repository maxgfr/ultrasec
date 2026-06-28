import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Dossier } from "./store.js";
import type { Finding, Narrative, RootCauseGroup } from "./types.js";
import { byStr } from "./util.js";
import { AI_DISCLAIMER, citedAt, hasNarrativeContent, mergeNarrative, parseNarrative, remediationMap } from "./narrative.js";

// Remediation-planning stage (Phase 4). Emit-only, mirroring `narrative`: the engine
// turns the audited dossier into a remediation-PRD DRAFT (IMPLEMENT.md) + a structured
// worklist (IMPLEMENT.todo.json). Confirmed findings become fix work items; needs-human
// findings become investigation items; a grounded NARRATIVE.json (suggested fixes,
// patches, root causes) is folded in when present. It NEVER changes a finding's
// status/severity/set and persists nothing to the dossier — the draft is fed to the
// local `to-prd` skill to author the PRD, or handed to an implementer/AI.

export interface ImplementItem {
  id: string;
  title: string;
  severity: string;
  category: string;
  cwe?: string;
  at: string; // citedAt(f) — the grounded [file:line]
  status: string; // "confirmed" | "needs-human"
  kind: "fix" | "investigate";
  fix?: string; // folded from a narrative remediation
  patch?: string; // folded from a narrative remediation
  owner?: string; // narrative remediation owner, else provenance owner
}

export interface ImplementWorklist {
  fixes: ImplementItem[];
  investigations: ImplementItem[];
  rootCauses: RootCauseGroup[];
  dismissed: number;
}

/**
 * Load + ground NARRATIVE.json (or an explicit `file`) against the dossier, using the
 * SAME confirmed-only `mergeNarrative` gate render/powered use. Returns undefined when
 * the file is absent/empty/malformed, so `implement` degrades to stub fixes. Lives here
 * (not in narrative.ts) so the pure narrative module stays fs-free.
 */
export function loadNarrative(run: string, dossier: Dossier, file?: string): Narrative | undefined {
  const p = file ?? join(run, "NARRATIVE.json");
  if (!existsSync(p)) return undefined;
  try {
    const merged = mergeNarrative(parseNarrative(readFileSync(p, "utf8")), dossier);
    return hasNarrativeContent(merged) ? merged : undefined;
  } catch {
    return undefined; // no usable narrative — render plain
  }
}

/**
 * Deterministically group confirmed findings by (category, cwe) when the narrative
 * supplies no rootCauses. Members are id-sorted; groups are sorted by their first
 * member id. A JSON-encoded (category, cwe) key keeps pairs from colliding.
 */
function deriveRootCauses(confirmed: Finding[]): RootCauseGroup[] {
  const groups = new Map<string, { cause: string; findingIds: string[] }>();
  for (const f of confirmed) {
    const key = JSON.stringify([f.category, f.cwe ?? ""]);
    const cause = f.cwe ? `${f.cwe} (${f.category})` : f.category;
    const g = groups.get(key) ?? { cause, findingIds: [] };
    g.findingIds.push(f.id);
    groups.set(key, g);
  }
  return [...groups.values()]
    .map((g) => ({
      cause: g.cause,
      findingIds: g.findingIds.slice().sort(byStr),
      note: `${g.findingIds.length} confirmed finding(s) share this category/CWE — fix once at the root.`,
    }))
    .sort((a, b) => byStr(a.findingIds[0]!, b.findingIds[0]!));
}

/**
 * Build the remediation worklist: confirmed findings → fix items (folding any grounded
 * narrative remediation by id), needs-human → investigation items, plus root-cause
 * groups (from the narrative when present, else derived) and the dismissed count.
 * Open + dismissed findings are excluded from the item lists (mirrors the narrative
 * worklist); dismissed is surfaced only as a count for the "Out of scope" section.
 */
export function buildImplementWorklist(dossier: Dossier, narrative?: Narrative): ImplementWorklist {
  const rem = remediationMap(narrative);

  const confirmed = dossier.findings
    .filter((f) => f.status === "confirmed")
    .slice()
    .sort((a, b) => byStr(a.id, b.id));
  const needsHuman = dossier.findings
    .filter((f) => f.status === "needs-human")
    .slice()
    .sort((a, b) => byStr(a.id, b.id));
  const dismissed = dossier.findings.filter((f) => f.status === "dismissed").length;

  const fixes: ImplementItem[] = confirmed.map((f) => {
    const r = rem.get(f.id);
    return {
      id: f.id,
      title: f.title,
      severity: f.severity,
      category: f.category,
      ...(f.cwe ? { cwe: f.cwe } : {}),
      at: citedAt(f),
      status: f.status,
      kind: "fix" as const,
      ...(r?.fix ? { fix: r.fix } : {}),
      ...(r?.patch ? { patch: r.patch } : {}),
      ...(r?.owner ? { owner: r.owner } : f.provenance?.owner ? { owner: f.provenance.owner } : {}),
    };
  });

  const investigations: ImplementItem[] = needsHuman.map((f) => ({
    id: f.id,
    title: f.title,
    severity: f.severity,
    category: f.category,
    ...(f.cwe ? { cwe: f.cwe } : {}),
    at: citedAt(f),
    status: f.status,
    kind: "investigate" as const,
    ...(f.provenance?.owner ? { owner: f.provenance.owner } : {}),
  }));

  const rootCauses = narrative?.rootCauses?.length ? narrative.rootCauses : deriveRootCauses(confirmed);

  return { fixes, investigations, rootCauses, dismissed };
}

const TODO_DIRECTIVE =
  "<!-- ultrasec IMPLEMENT draft — feed this file to the `to-prd` skill to author the remediation PRD, or hand it to an implementer/AI. Every item is grounded in a confirmed [file:line]. -->";

function severityBreakdown(items: ImplementItem[]): string {
  const counts: Record<string, number> = {};
  for (const i of items) counts[i.severity] = (counts[i.severity] ?? 0) + 1;
  return ["critical", "high", "medium", "low", "info"]
    .filter((s) => counts[s])
    .map((s) => `${counts[s]} ${s}`)
    .join(", ");
}

/**
 * Render the remediation-PRD draft. Headings mirror the `to-prd` template (Problem
 * statement / Solution / User stories / Out of scope) so the draft drops cleanly into
 * that skill. Each confirmed finding becomes a numbered work item grounded in its
 * [file:line], with an acceptance-criteria scaffold and any suggested fix/patch/owner.
 */
export function renderImplementMd(wl: ImplementWorklist, context?: string): string {
  const L: string[] = [];
  L.push(TODO_DIRECTIVE);
  L.push(`# Remediation PRD draft — ${wl.fixes.length} fix${wl.fixes.length === 1 ? "" : "es"}, ${wl.investigations.length} to investigate`);
  L.push(`_${AI_DISCLAIMER}_`);
  L.push("");
  L.push(`> Deterministic draft from the ultrasec dossier. Feed it to the **\`to-prd\`** skill to`);
  L.push(`> author the remediation PRD, or hand it to an implementer/AI. It never changes a`);
  L.push(`> finding's status, severity, or set — every work item cites a confirmed \`[file:line]\`.`);
  L.push("");

  if (context) {
    L.push(`## Project context`);
    L.push(`_From \`CONTEXT.md\`._`);
    L.push("");
    L.push(context);
    L.push("");
  }

  // ── Problem statement ──────────────────────────────────────────────────────
  L.push(`## Problem statement`);
  L.push("");
  if (wl.fixes.length) {
    L.push(`The audit confirmed **${wl.fixes.length}** exploitable finding(s) (${severityBreakdown(wl.fixes)}) that must be remediated.`);
  } else {
    L.push(`No confirmed findings to remediate yet — run \`verify --apply\` first.`);
  }
  if (wl.investigations.length) {
    L.push("");
    L.push(
      `A further **${wl.investigations.length}** finding(s) (${severityBreakdown(wl.investigations)}) are uncertain and need human investigation before a fix can be scoped.`,
    );
  }
  L.push("");

  // ── Solution (grouped by root cause) ───────────────────────────────────────
  L.push(`## Solution`);
  L.push("");
  if (wl.rootCauses.length) {
    L.push(`Fix at the root cause where possible:`);
    L.push("");
    for (const g of wl.rootCauses) {
      L.push(`### Root cause: ${g.cause}`);
      L.push(`- findings: ${g.findingIds.map((id) => `\`${id}\``).join(", ")}`);
      L.push(`- ${g.note}`);
      L.push("");
    }
  } else {
    L.push(`Address each confirmed finding individually (no shared root cause).`);
    L.push("");
  }

  // ── User stories / work items (one per confirmed finding) ──────────────────
  L.push(`## User stories / work items`);
  L.push("");
  if (!wl.fixes.length) {
    L.push(`_None — nothing confirmed yet._`);
    L.push("");
  }
  let n = 0;
  for (const f of wl.fixes) {
    n++;
    L.push(
      `${n}. **Fix \`${f.title}\`** at \`${f.at}\` so it is no longer exploitable. _([${f.severity}] ${f.cwe ?? f.category} · \`${f.id}\`${f.owner ? ` · owner ${f.owner}` : ""})_`,
    );
    if (f.fix) L.push(`   - Suggested fix (AI): ${f.fix}`);
    if (f.patch) {
      L.push(`   - Suggested patch:`);
      L.push("     ```diff");
      for (const line of f.patch.split("\n")) L.push(`     ${line}`);
      L.push("     ```");
    }
    L.push(`   - Acceptance criteria:`);
    L.push(`     - [ ] The cited line \`${f.at}\` is no longer exploitable for this finding.`);
    L.push(`     - [ ] A regression test reproduces the issue before the fix and passes after it.`);
  }
  L.push("");

  // ── Investigation items (needs-human) ──────────────────────────────────────
  if (wl.investigations.length) {
    L.push(`## Investigation items (needs-human — resolve before scoping a fix)`);
    L.push("");
    let m = 0;
    for (const f of wl.investigations) {
      m++;
      L.push(
        `${m}. Investigate \`${f.title}\` at \`${f.at}\` _([${f.severity}] ${f.cwe ?? f.category} · \`${f.id}\`${f.owner ? ` · owner ${f.owner}` : ""})_ — confirm whether it is exploitable, then route to fix or dismiss.`,
      );
    }
    L.push("");
  }

  // ── Out of scope ───────────────────────────────────────────────────────────
  L.push(`## Out of scope`);
  L.push(wl.dismissed ? `- ${wl.dismissed} finding(s) were dismissed during the audit — not in scope for this work.` : `- Nothing dismissed.`);
  L.push("");

  return L.join("\n") + "\n";
}
