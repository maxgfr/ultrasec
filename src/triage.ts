import type { Dossier } from "./store.js";
import type { Finding, Status } from "./types.js";
import { isHigh } from "./verify.js";
import { byStr } from "./util.js";

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
  return dossier.findings
    .filter((f) => f.status === "open")
    .slice()
    .sort((a, b) => byStr(a.id, b.id))
    .map((f) => ({ id: f.id, severity: f.severity, category: f.category, title: f.title, at: citedAt(f), verdict: null }));
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
  for (const it of items) {
    L.push(`- \`${it.id}\` — [${it.severity}] ${it.category}: ${it.title} · at \`${it.at}\``);
  }
  L.push("");
  return L.join("\n") + "\n";
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

/** Parse a TRIAGE.json body: a JSON array or {triage:[...]}, tolerant. */
export function parseTriage(raw: string): TriageInput[] {
  const data = JSON.parse(raw) as unknown;
  const arr = Array.isArray(data) ? data : Array.isArray((data as any)?.triage) ? (data as any).triage : [];
  return (arr as any[])
    .filter((v) => v && typeof v.id === "string" && (TRIAGE_VERDICTS as readonly string[]).includes(v.verdict))
    .map((v) => ({ id: v.id as string, verdict: v.verdict as TriageVerdict }));
}
