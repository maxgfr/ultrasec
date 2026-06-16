import type { Dossier } from "./store.js";
import type { Finding, Status, Verdict } from "./types.js";
import { byStr } from "./util.js";

// The adversarial verification gate. The engine emits a claim↔evidence worklist;
// the AI (skeptic subagents) adjudicates each finding by reading the dossier's
// real code, then `--apply` folds the verdicts back in. The policy is
// deliberately CONSERVATIVE: aggressive auto-suppression discards real bugs
// (research shows ~22%), so a high/critical finding is only dismissed on an
// explicit `refuted`; anything merely `unsupported`/uncertain becomes
// `needs-human` rather than disappearing.

export interface VerifyItem {
  id: string;
  severity: string;
  cwe?: string;
  title: string;
  category: string;
  /** What must hold for this to be a real, exploitable issue. */
  claim: string;
  /** Files the adjudicator should open. */
  files: string[];
  /** Filled by the adjudicator. */
  verdict: Verdict | null;
  note: string;
  exploitPath?: string;
}

export interface VerdictInput {
  id: string;
  verdict: Verdict;
  note?: string;
  exploitPath?: string;
}

/** Findings still needing adjudication (open or previously needs-human). */
function pending(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.status === "open" || f.status === "needs-human");
}

export function buildWorklist(dossier: Dossier): VerifyItem[] {
  return pending(dossier.findings)
    .slice()
    .sort((a, b) => byStr(a.id, b.id))
    .map((f) => {
      const files = new Set<string>();
      for (const p of f.path ?? []) files.add(`${p.file}:${p.line}`);
      if (f.sink) files.add(`${f.sink.file}:${f.sink.line}`);
      if (f.source) files.add(`${f.source.file}:${f.source.line}`);
      return {
        id: f.id,
        severity: f.severity,
        cwe: f.cwe,
        title: f.title,
        category: f.category,
        claim: f.message,
        files: [...files],
        verdict: null,
        note: "",
      };
    });
}

/** Round-robin slice `i` of `n` over the stable worklist order (balanced shards). */
export function shard<T>(items: T[], n: number, i: number): T[] {
  return items.filter((_, idx) => idx % n === i);
}

export function renderWorklistMd(items: VerifyItem[]): string {
  const L: string[] = [];
  L.push(`# ultrasec verification worklist (${items.length})`);
  L.push("");
  L.push(`For each item: open the cited code (\`ultrasec dossier <id>\`), decide whether`);
  L.push(`the flow is **real and exploitable**, and set a verdict:`);
  L.push(`\`supported\` · \`partial\` · \`unsupported\` · \`refuted\` (+ a short note, and an`);
  L.push(`\`exploitPath\` when supported). Save as verdicts.json (array of`);
  L.push(`{id, verdict, note, exploitPath}) and run \`ultrasec verify --apply verdicts.json\`.`);
  L.push("");
  L.push(`> Be skeptical, but do NOT dismiss a high/critical finding unless you can`);
  L.push(`> positively **refute** it. Uncertain ⇒ leave it for a human.`);
  L.push("");
  for (const it of items) {
    L.push(`## ${it.id} — [${it.severity}] ${it.title}`);
    if (it.cwe) L.push(`- ${it.cwe} · ${it.category}`);
    L.push(`- files: ${it.files.map((f) => `\`${f}\``).join(", ")}`);
    L.push(`- claim: ${it.claim}`);
    L.push("");
  }
  return L.join("\n") + "\n";
}

export interface ApplyResult {
  findings: Finding[];
  applied: number;
  confirmed: number;
  dismissed: number;
  needsHuman: number;
  /** Conservative overrides: unsupported/partial high-severity kept for a human. */
  keptForHuman: { id: string; verdict: Verdict; severity: string }[];
}

function isHigh(sev: string): boolean {
  return sev === "critical" || sev === "high";
}

/** Map a verdict onto a finding status under the conservative policy. */
function nextStatus(verdict: Verdict, severity: string): Status {
  switch (verdict) {
    case "supported":
      return "confirmed";
    case "refuted":
      return "dismissed"; // an explicit contradiction — safe to drop
    case "unsupported":
      return isHigh(severity) ? "needs-human" : "dismissed";
    case "partial":
      return "needs-human";
  }
}

export function applyVerdicts(dossier: Dossier, verdicts: VerdictInput[]): ApplyResult {
  const byId = new Map<string, VerdictInput>();
  for (const v of verdicts) byId.set(v.id, v); // last-wins on dupes

  let confirmed = 0,
    dismissed = 0,
    needsHuman = 0,
    applied = 0;
  const keptForHuman: ApplyResult["keptForHuman"] = [];

  const findings = dossier.findings.map((f) => {
    const v = byId.get(f.id);
    if (!v) return f;
    applied++;
    const status = nextStatus(v.verdict, f.severity);
    if (v.verdict === "unsupported" && isHigh(f.severity)) keptForHuman.push({ id: f.id, verdict: v.verdict, severity: f.severity });
    if (status === "confirmed") confirmed++;
    else if (status === "dismissed") dismissed++;
    else needsHuman++;
    const next: Finding = {
      ...f,
      status,
      verdict: v.verdict,
      confidence: v.verdict === "supported" ? "high" : v.verdict === "partial" ? "medium" : f.confidence,
    };
    if (v.exploitPath) next.exploitPath = v.exploitPath;
    if (v.note) next.message = `${f.message}\n\nVerdict (${v.verdict}): ${v.note}`;
    return next;
  });

  return { findings, applied, confirmed, dismissed, needsHuman, keptForHuman };
}

/** Parse a verdicts file body: a JSON array, or {verdicts:[...]}, tolerant. */
export function parseVerdicts(raw: string): VerdictInput[] {
  const data = JSON.parse(raw) as unknown;
  const arr = Array.isArray(data) ? data : Array.isArray((data as any)?.verdicts) ? (data as any).verdicts : [];
  return (arr as any[])
    .filter((v) => v && typeof v.id === "string" && typeof v.verdict === "string")
    .map((v) => ({ id: v.id, verdict: v.verdict, note: v.note, exploitPath: v.exploitPath }));
}
