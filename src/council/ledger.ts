import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Lang, Phase } from "./brief.js";
import type { CouncilTodo } from "./consolidate.js";
import { addUsage, emptyUsage, type Failure, type Usage } from "./events.js";

// `<run>/council/COUNCIL.json` — what the council did, what it cost, and what
// the orchestrator decided. Engine-written only. The report's engines/cost
// annex reads `totals` and `reviewers[].usage`; the decisions block is how a
// rejected candidate stays listed (with its reason) after the fact, rather than
// vanishing the moment it was not ingested.
//
// Every council artifact lives under `<run>/council/`: the snapshot, the
// briefs, each reviewer's logs, the worklist and this ledger. The one write
// outside it is `--apply`, which folds accepted candidates into findings.json
// through the same citation gate as `investigate --apply`.

export const COUNCIL_DIR = "council";
export const LEDGER = "COUNCIL.json";
export const TODO = "COUNCIL.todo.json";
export const BRIEF_MD = "COUNCIL.md";

export type ReviewerStatus = "ok" | "no-report" | "budget" | "timeout" | "quota" | "credit" | "transient" | "failed" | "not-installed";

export interface Attempt {
  /** The reviewer entry (preset or config) the attempt ran. */
  cli: string;
  model: string;
  /** True when this attempt resumed the reviewer's session for one closing turn. */
  resume: boolean;
  status: ReviewerStatus;
  exit: number | null;
  durationMs: number;
  usage: Usage;
  failure?: Failure;
}

export interface ReviewerRecord {
  name: string;
  phase: Phase;
  /** The reviewer entry (preset or config). Re-resolved on `--resume`, never executed from here. */
  cli: string;
  model: string;
  focus?: string;
  status: ReviewerStatus;
  session?: string;
  /** A reset time the provider announced, verbatim — `council --resume` prints it. */
  resetAt?: string;
  attempts: Attempt[];
  usage: Usage;
  /** Run-relative path of the redacted report, when one was produced. */
  report?: string;
}

export interface Decision {
  candidate: string;
  title: string;
  sources: string[];
  findingId?: string;
  reason?: string;
  /** Who refused it: the orchestrator's verdict, or the citation gate. */
  by?: "orchestrator" | "citation-gate";
}

export interface Ledger {
  schema: 1;
  repo: string;
  commit: string;
  lang: Lang;
  reviewers: ReviewerRecord[];
  totals: Usage;
  decisions: { accepted: Decision[]; rejected: Decision[] };
}

export const councilDir = (run: string): string => join(run, COUNCIL_DIR);
export const snapshotDir = (run: string): string => join(run, COUNCIL_DIR, "snapshot");
export const reviewerDir = (run: string, phase: Phase, name: string): string => join(run, COUNCIL_DIR, phase, name);

export function loadLedger(run: string): Ledger | undefined {
  const p = join(councilDir(run), LEDGER);
  if (!existsSync(p)) return undefined;
  const l = JSON.parse(readFileSync(p, "utf8")) as Ledger;
  l.decisions ??= { accepted: [], rejected: [] };
  return l;
}

export function newLedger(repo: string, commit: string, lang: Lang): Ledger {
  return { schema: 1, repo, commit, lang, reviewers: [], totals: emptyUsage(false), decisions: { accepted: [], rejected: [] } };
}

/** Replace (or add) the record for `name` in `phase`. */
export function upsertReviewer(l: Ledger, r: ReviewerRecord): void {
  const i = l.reviewers.findIndex((x) => x.name === r.name && x.phase === r.phase);
  if (i >= 0) l.reviewers[i] = r;
  else l.reviewers.push(r);
}

export function saveLedger(run: string, l: Ledger): void {
  mkdirSync(councilDir(run), { recursive: true });
  l.totals = l.reviewers.reduce((acc, r) => addUsage(acc, r.usage), emptyUsage(false));
  l.reviewers.sort((a, b) => (a.phase === b.phase ? (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) : a.phase === "blind" ? -1 : 1));
  writeFileSync(join(councilDir(run), LEDGER), JSON.stringify(l, null, 2));
}

export function usageLine(u: Usage): string {
  if (!u.exposed) return "usage not exposed";
  const tok = u.input + u.output + u.reasoning;
  return `${tok.toLocaleString("en-US")} tokens (in ${u.input} · out ${u.output} · reasoning ${u.reasoning} · cache r/w ${u.cacheRead}/${u.cacheWrite}) · $${u.cost.toFixed(4)}`;
}

/** COUNCIL.md — the orchestrator's reading list. Grouping is for reading; every decision is still per candidate id. */
export function renderCouncilMd(run: string, l: Ledger, todo: CouncilTodo): string {
  const L: string[] = [];
  L.push(`# Council — second opinion from other models`, "");
  L.push(`Snapshot of \`${l.commit.slice(0, 12)}\` (tracked files only). Every claim below is UNVERIFIED: open each cited line`);
  L.push(`yourself, reproduce what can be reproduced, then record a decision per candidate and fold it with`);
  L.push(`\`ultrasec council --run ${run} --apply <decisions.json>\`. Corroboration orders the reading; it decides nothing.`, "");

  L.push(`## Reviewers`, "", `| reviewer | phase | entry:model | status | usage | report |`, `|---|---|---|---|---|---|`);
  for (const r of l.reviewers) {
    const via =
      r.attempts.length > 1
        ? ` (${r.attempts.length} attempts: ${r.attempts.map((a) => `${a.resume ? "resume " : ""}${a.model || a.cli}→${a.status}`).join(", ")})`
        : "";
    L.push(
      `| ${r.name} | ${r.phase} | ${r.cli}:${r.model || "(default)"} | ${r.status}${r.resetAt ? ` — resets ${r.resetAt}` : ""}${via} | ${usageLine(r.usage)} | ${r.report ? `\`${r.report}\`` : "—"} |`,
    );
  }
  L.push("", `Total: ${usageLine(l.totals)}${l.reviewers.some((r) => !r.usage.exposed) ? " (some reviewers do not expose usage)" : ""}`, "");

  L.push(`## Candidates (${todo.candidates.length})`, "");
  if (!todo.candidates.length) L.push("_None — every claim either mapped onto an existing finding or carried nothing to verify._", "");
  for (const c of todo.candidates) {
    L.push(`### \`${c.id}\` — ${c.title}`);
    L.push(`- severity: ${c.severity ?? "unstated"} · ${c.cwe ?? "no CWE"} (${c.family}) · sources: ${c.sources.join(", ")} (${c.corroboration})`);
    for (const x of c.citations)
      L.push(`- ${x.citation === "ok" ? "✓" : "✗"} \`${x.at}\`${x.raw ? ` (written \`${x.raw}\`)` : ""}${x.reason ? ` — ${x.reason}` : ""}`);
    if (c.scenario) L.push(`- scenario: ${c.scenario}`);
    for (const f of c.flags) L.push(`- ⚠ ${f}`);
    for (const r of c.claims) L.push(`- ${r.reviewer}/${r.phase} \`${r.ref}\`: ${r.title}${r.severity ? ` (${r.severity})` : ""}`);
    L.push("");
  }

  if (todo.corroborations.length) {
    L.push(`## Corroborations of findings the run already holds (${todo.corroborations.length})`, "");
    for (const c of todo.corroborations) L.push(`- \`${c.findingId}\` (${c.status}) ${c.title} — ${c.sources.join(", ")} via ${c.via}`);
    L.push("");
  }

  if (todo.contested.length) {
    L.push(`## Contested (${todo.contested.length}) — a worklist, never applied`, "");
    L.push(`Re-open each contested finding with \`ultrasec dossier <id> --run ${run}\` and re-verify it if the proof holds.`, "");
    for (const c of todo.contested) {
      L.push(`### \`${c.id}\` (${c.known}) — ${c.reviewer}: ${c.claim}`);
      for (const x of c.citations) L.push(`- ${x.citation === "ok" ? "✓" : "✗"} \`${x.at}\`${x.reason ? ` — ${x.reason}` : ""}`);
      L.push("");
    }
  }

  if (l.decisions.accepted.length || l.decisions.rejected.length) {
    L.push(`## Decisions so far`, "");
    for (const d of l.decisions.accepted) L.push(`- ✓ \`${d.candidate}\` → \`${d.findingId ?? "folded"}\` ${d.title}`);
    for (const d of l.decisions.rejected) L.push(`- ✗ \`${d.candidate}\` ${d.title} — ${d.reason ?? ""}${d.by === "citation-gate" ? " (citation gate)" : ""}`);
    L.push("");
  }
  return `${L.join("\n")}\n`;
}
