import type { Dossier } from "./store.js";
import type { Finding, Status } from "./types.js";
import { isHigh } from "./verify.js";
import { byStr } from "./util.js";
import { proposedFor, renderProposalSummary, type ProposedAdjudication } from "./noise.js";
import { parseIdVerdictRows, type ParseResult } from "./apply-parse.js";
import { compareWithinStatus } from "./rank.js";
import { groupFamilies } from "./family.js";

// The cheap quick-dismiss fast-lane (Phase 4). A compact, code-free worklist of
// every OPEN candidate so the agent can clear obvious noise in one pass BEFORE the
// expensive per-finding dossier/verify work. Deliberately one-directional and
// conservative: `noise` only dismisses low/medium/info; on a high/critical finding
// a `noise` verdict is IGNORED (it stays open for full adversarial verification) —
// the same "never quick-drop a serious finding" discipline as the verify gate.

export const TRIAGE_VERDICTS = ["noise", "keep"] as const;
export type TriageVerdict = (typeof TRIAGE_VERDICTS)[number];

export interface TriageItem {
  id: string;
  severity: string;
  category: string;
  title: string;
  /** Cited "file:line" — NO code excerpt (triage is a glance, not a read). */
  at: string;
  /** Filled by the agent. */
  verdict: TriageVerdict | null;
  /** Machine-proposed ground for a noise-by-construction finding. A suggestion
   *  to accept or refuse — never a filled-in verdict. */
  proposed?: ProposedAdjudication;
}

export interface TriageInput {
  id: string;
  verdict: TriageVerdict;
}

function citedAt(f: Finding): string {
  if (f.sink) return `${f.sink.file}:${f.sink.line}`;
  const last = f.path?.[f.path.length - 1];
  if (last) return `${last.file}:${last.line}`;
  if (f.source) return `${f.source.file}:${f.source.line}`;
  return "—";
}

export function buildTriageWorklist(dossier: Dossier): TriageItem[] {
  return (
    dossier.findings
      .filter((f) => f.status === "open")
      .slice()
      // Ranked, not alphabetical. The worklist is read top-down and abandoned when
      // attention runs out, so the order decides what actually gets triaged — and
      // sorting by content hash put that decision in the hands of a hash.
      .sort(compareWithinStatus)
      .map((f) => {
        const item: TriageItem = { id: f.id, severity: f.severity, category: f.category, title: f.title, at: citedAt(f), verdict: null };
        const proposed = proposedFor(f);
        if (proposed) item.proposed = proposed;
        return item;
      })
  );
}

export function renderTriageMd(items: TriageItem[], context?: string): string {
  const L: string[] = [];
  L.push(`# ultrasec triage worklist (${items.length})`);
  L.push("");
  L.push(`A fast, code-free first pass over OPEN candidates. For each, set a \`verdict\`:`);
  L.push(`\`noise\` (obvious false positive, not worth a full read) or \`keep\` (worth verifying).`);
  L.push(`Save as TRIAGE.json (array of {id, verdict}) and run \`ultrasec triage --apply TRIAGE.json\`.`);
  L.push("");
  L.push(`> Conservative: \`noise\` dismisses only **low/medium/info**. On a **high/critical**`);
  L.push(`> finding a \`noise\` verdict is **ignored** — it stays open for full \`verify\`. Anything`);
  L.push(`> you're unsure about → \`keep\`.`);
  L.push("");
  if (context) {
    L.push(`## Project context`);
    L.push(`_From \`CONTEXT.md\`._`);
    L.push("");
    L.push(context);
    L.push("");
  }
  L.push(...renderProposalSummary(items));
  L.push(...groupedWorklist(items));
  L.push("");
  return L.join("\n") + "\n";
}

/**
 * The worklist, with repeated candidates gathered under one heading.
 *
 * On the first large audit this list was 1342 bullets to decide one at a time,
 * of which 604 were four repeated scanner titles and the top two titles alone
 * were 279 rows. The auditor ended up grouping it by hand in `jq` before they
 * could start.
 *
 * GROUPING SAVES READING, NEVER A VERDICT — the same rule `noise.ts` states for
 * its proposal summary, and the reason every member id is still printed. A
 * group that fanned out would let one decision rewrite findings the apply file
 * never named; TRIAGE.json is still an array of `{id, verdict}` and
 * `TRIAGE.todo.json` still carries one row per finding. What collapses is the
 * prose around them.
 */
function groupedWorklist(items: readonly TriageItem[]): string[] {
  // `groupFamilies` keys on a Finding's location; a TriageItem carries the same
  // facts under different names, so map it across rather than duplicating the
  // grouping rule here.
  const asFinding = new Map<string, TriageItem>(items.map((it) => [it.id, it]));
  const shims: Finding[] = items.map((it) => ({
    id: it.id,
    category: it.category as Finding["category"],
    title: it.title,
    severity: it.severity as Finding["severity"],
    confidence: "low",
    message: "",
    tool: "ultrasec",
    status: "open",
    sink: { file: it.at.replace(/:\d+$/, ""), line: Number(/:(\d+)$/.exec(it.at)?.[1] ?? 1) },
  }));

  const { families, singles } = groupFamilies(shims);
  const line = (it: TriageItem) => `- \`${it.id}\` — [${it.severity}] ${it.category}: ${it.title} · at \`${it.at}\``;

  const L: string[] = [];
  for (const fam of families) {
    const lead = asFinding.get(fam.lead.id)!;
    L.push(`### ${lead.title} ×${fam.members.length} — under \`${fam.root}\``);
    L.push(`_One judgment, ${fam.members.length} rows. A verdict must still name each id you mean._`);
    L.push("");
    for (const m of fam.members) L.push(line(asFinding.get(m.id)!));
    L.push("");
  }
  if (singles.length) {
    if (families.length) {
      L.push(`### The rest (${singles.length})`);
      L.push("");
    }
    for (const s of singles) L.push(line(asFinding.get(s.id)!));
  }
  return L;
}

export interface ApplyTriageResult {
  findings: Finding[];
  applied: number;
  dismissed: number;
  /** High/critical findings whose `noise` verdict was IGNORED — kept open for verify. */
  kept: { id: string; severity: string }[];
}

/** Fold triage verdicts back in. Only acts on OPEN findings; idempotent. */
export function applyTriage(dossier: Dossier, inputs: TriageInput[]): ApplyTriageResult {
  const byId = new Map<string, TriageInput>();
  for (const v of inputs) byId.set(v.id, v); // last-wins on dupes

  let applied = 0,
    dismissed = 0;
  const kept: ApplyTriageResult["kept"] = [];

  const findings = dossier.findings.map((f) => {
    const v = byId.get(f.id);
    if (!v || f.status !== "open") return f; // out of scope / no verdict → untouched
    applied++;
    if (v.verdict === "noise") {
      if (isHigh(f.severity)) {
        // too severe to quick-dismiss — ignore the verdict, keep it open for verify.
        kept.push({ id: f.id, severity: f.severity });
        return f;
      }
      dismissed++;
      return { ...f, status: "dismissed" as Status, message: `${f.message}\n\nTriage: dismissed as noise.` };
    }
    return f; // "keep" → unchanged (stays open for full verify)
  });

  return { findings, applied, dismissed, kept };
}

/**
 * Parse a TRIAGE.json body: a JSON array or {triage:[...]}. Individual malformed rows
 * are skipped, but — like `parseVerdicts`/`parseRevalidations` — an unrecognized shape
 * or an all-unusable batch THROWS rather than folding zero rows and reporting success.
 * A silent no-op reads exactly like a completed triage pass, which is the one thing an
 * audit tool must never do.
 */
export function parseTriage(raw: string): ParseResult<TriageInput> {
  return parseIdVerdictRows(raw, {
    wrapperKeys: ["triage"],
    label: "triage",
    verdicts: TRIAGE_VERDICTS,
    build: (v, verdict) => ({ id: v.id as string, verdict: verdict as TriageVerdict }),
  });
}
