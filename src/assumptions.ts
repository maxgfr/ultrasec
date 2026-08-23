import { join } from "node:path";
import type { RepoScan } from "./scan.js";
import { localDefNames } from "./scan.js";
import { readText } from "./walk.js";
import { langForFile } from "./lang.js";
import { findSinks, findSources } from "./catalog.js";
import { isTestPath } from "./vendor/codeindex-engine.mjs";
import { byStr } from "./util.js";
import { coerceRows, type DroppedRow, type ParseResult } from "./apply-parse.js";

// The assumption map. Read the code function by function and record two things:
// what each one GUARANTEES (with the lines that establish it) and what it
// ASSUMES without anything enforcing it.
//
// The second list is the point. A function that trusts its caller to have
// checked ownership, and a caller that trusts the function to check it, is a
// vulnerability that exists in NEITHER function's code — which is exactly why
// taint enumeration cannot see it and why file-by-file review keeps missing it.
// An assumption marked `nothing-found` is the highest-value lead an audit
// produces, because it names a place where the code is relying on something
// nobody wrote down.
//
// Deliberately verdict-free: no severity, no finding, no citation gate on the
// notes. This stage builds UNDERSTANDING, and forcing a severity out of it too
// early is how a reviewer talks themselves out of an uncomfortable observation.

/** How the engine ranked a unit — evidence for the reader, not a verdict. */
export interface UnitSignals {
  /** Untrusted-input reads inside this file. */
  sources: number;
  /** Dangerous operations inside this file. */
  sinks: number;
}

export interface AssumptionItem {
  /** `file:line` of the function, or the file when the extractor found no symbols. */
  at: string;
  file: string;
  /** Function name, when known. Anonymous handlers legitimately have none. */
  symbol?: string;
  signals: UnitSignals;
  /** Why the engine put this unit in front of you. */
  why: string;
  // ── Filled by the agent ────────────────────────────────────────────────
  /** What this function establishes, each with the line that establishes it. */
  guarantees: { claim: string; file: string; line: number }[];
  /**
   * What it depends on and does NOT verify. `enforcedAt` names the line that
   * enforces it; the literal string "nothing-found" means you looked and there
   * is no such line. Those are the leads.
   */
  assumptions: { claim: string; enforcedAt: string }[];
  /** What it calls, and what it expects each callee to have done. */
  calls: { callee: string; expectedBehavior: string }[];
  /** Things you could not resolve. Listed, never guessed. */
  openQuestions: string[];
}

const MAX_UNITS = 120;

/**
 * Build the worklist, ordered by how much untrusted data a file handles.
 *
 * The unit is the FILE plus its symbols rather than every symbol in the repo: a
 * per-symbol worklist on a real codebase runs to thousands of entries, and an
 * audit that reads all of them reads none of them carefully.
 */
export function buildAssumptionWorklist(scan: RepoScan): AssumptionItem[] {
  const items: AssumptionItem[] = [];

  for (const f of scan.files) {
    const lang = langForFile(f.rel);
    if (!lang) continue;
    const text = readText(join(scan.repo, f.rel));
    const sources = findSources(lang, text).length;
    const sinks = findSinks(lang, f.calls, undefined, f.imports, localDefNames(f.symbols)).length;
    if (!sources && !sinks) continue; // nothing untrusted and nothing dangerous

    const why =
      sources && sinks ? "reads untrusted input AND performs a dangerous operation" : sources ? "reads untrusted input" : "performs a dangerous operation";

    // One entry per named symbol, so the agent records per-function facts; a file
    // whose functions are anonymous (an Express router) gets one file-level entry
    // rather than nothing.
    const named = f.symbols.filter((s) => s.name).slice(0, 12);
    if (named.length) {
      for (const s of named) {
        items.push({
          at: `${f.rel}:${s.line}`,
          file: f.rel,
          symbol: s.name,
          signals: { sources, sinks },
          why,
          guarantees: [],
          assumptions: [],
          calls: [],
          openQuestions: [],
        });
      }
    } else {
      items.push({ at: f.rel, file: f.rel, signals: { sources, sinks }, why, guarantees: [], assumptions: [], calls: [], openQuestions: [] });
    }
  }

  // Shipped code first, test harness last.
  //
  // Ranking on source+sink density alone puts jest files near the top: a test
  // reads fixtures (sources) and calls the very operation it exercises (sinks),
  // so it scores exactly like the code it covers. On the audited repo that spent
  // 29 of 120 units — a quarter of the agent's budget — recording what a mocked
  // `sendEvent` guarantees, which is nothing anyone ships.
  //
  // Sorted last rather than dropped: `taint` excludes test paths because a test
  // is not an ENTRY POINT and a wrong answer there is a false positive, but an
  // assumption is understanding, and a repo with room left in the budget loses
  // nothing by reading its harness. A test-only repo still gets a worklist.
  const testLast = (i: AssumptionItem): number => (isTestPath(i.file) ? 1 : 0);
  return items
    .sort((a, b) => testLast(a) - testLast(b) || b.signals.sources + b.signals.sinks - (a.signals.sources + a.signals.sinks) || byStr(a.at, b.at))
    .slice(0, MAX_UNITS);
}

export function renderAssumptionsMd(items: AssumptionItem[], context?: string): string {
  const L: string[] = [];
  L.push(`# ultrasec assumption map (${items.length} unit${items.length === 1 ? "" : "s"})`);
  L.push("");
  L.push(`Read each unit and record what it **guarantees** and what it **assumes**. Build`);
  L.push(`understanding, not verdicts: no severity here, and no finding — forcing a rating out`);
  L.push(`of an observation this early is how an uncomfortable one gets talked away.`);
  L.push("");
  L.push(`For each unit:`);
  L.push("");
  L.push(`- **guarantees** — what holds when it returns, each with the line that establishes it.`);
  L.push(`  If nothing establishes it, it is not a guarantee; it is an assumption.`);
  L.push(`- **assumptions** — what it depends on and does not verify. Set \`enforcedAt\` to the`);
  L.push(`  \`file:line\` that enforces it, or to the literal **\`nothing-found\`** when you looked`);
  L.push(`  and there is none.`);
  L.push(`- **calls** — what it calls and what it expects each callee to have already done.`);
  L.push(`- **openQuestions** — what you could not resolve. List it; do not guess it.`);
  L.push("");
  L.push(`> **\`nothing-found\` is the output.** A function that trusts its caller to have checked`);
  L.push(`> ownership, called by a caller that trusts the function to check it, is a vulnerability`);
  L.push(`> present in NEITHER function's code. That is why taint enumeration cannot see it and`);
  L.push(`> why reading file by file keeps missing it. \`--apply\` turns every \`nothing-found\` into`);
  L.push(`> a prioritized \`investigate\` lead.`);
  L.push("");
  if (context) {
    L.push(`## Project context`);
    L.push(`_From \`CONTEXT.md\` — the trust model these assumptions are measured against._`);
    L.push("");
    L.push(context);
    L.push("");
  }
  for (const it of items) {
    L.push(`## \`${it.at}\`${it.symbol ? ` — ${it.symbol}()` : ""}`);
    L.push(`- ${it.why} (${it.signals.sources} source(s), ${it.signals.sinks} sink(s) in this file)`);
    L.push("");
  }
  return L.join("\n") + "\n";
}

export interface AssumptionResult {
  at: string;
  guarantees?: { claim: string; file: string; line: number }[];
  assumptions?: { claim: string; enforcedAt: string }[];
  calls?: { callee: string; expectedBehavior: string }[];
  openQuestions?: string[];
}

export const NOTHING_FOUND = "nothing-found";

export function parseAssumptionResults(raw: string): ParseResult<AssumptionResult> {
  const arr = coerceRows(JSON.parse(raw) as unknown, ["assumptions", "units"], "assumption results");
  const rows: AssumptionResult[] = [];
  const dropped: DroppedRow[] = [];
  for (const [index, entry] of (arr as unknown[]).entries()) {
    const v = entry as Record<string, unknown>;
    if (!v || typeof v !== "object") {
      dropped.push({ index, reason: "not an object" });
      continue;
    }
    if (typeof v.at !== "string" || !v.at) {
      dropped.push({ index, reason: "missing `at` (which unit is this a record of?)" });
      continue;
    }
    rows.push({
      at: v.at,
      guarantees: Array.isArray(v.guarantees) ? (v.guarantees as AssumptionResult["guarantees"]) : undefined,
      assumptions: Array.isArray(v.assumptions) ? (v.assumptions as AssumptionResult["assumptions"]) : undefined,
      calls: Array.isArray(v.calls) ? (v.calls as AssumptionResult["calls"]) : undefined,
      openQuestions: Array.isArray(v.openQuestions) ? (v.openQuestions as string[]) : undefined,
    });
  }
  if (rows.length === 0 && (arr as unknown[]).length > 0) {
    throw new Error(`assumption results: all ${(arr as unknown[]).length} row(s) were unusable — nothing folded (fail-closed)`);
  }
  return { rows, dropped };
}

/** Every unenforced assumption, in worklist order — the hunting queue. */
export function unenforced(results: AssumptionResult[]): { at: string; claim: string }[] {
  const out: { at: string; claim: string }[] = [];
  for (const r of results) {
    for (const a of r.assumptions ?? []) {
      if (a.enforcedAt?.trim().toLowerCase() === NOTHING_FOUND) out.push({ at: r.at, claim: a.claim });
    }
  }
  return out;
}

/**
 * Render the map. Unenforced assumptions come FIRST and are what the reader is
 * meant to leave with; the per-unit records are the working notes behind them.
 */
export function renderAssumptionMap(results: AssumptionResult[]): string {
  const leads = unenforced(results);
  const L: string[] = [`# Assumption map`, ""];
  L.push(`${results.length} unit(s) recorded · **${leads.length} unenforced assumption(s)**.`);
  L.push("");
  L.push(`> An unenforced assumption is not a vulnerability. It is the place to look for one:`);
  L.push(`> the code is relying on something nobody wrote down.`);
  L.push("");
  if (leads.length) {
    L.push(`## Trusted but never enforced (${leads.length})`);
    L.push("");
    for (const l of leads) L.push(`- \`${l.at}\` — ${l.claim}`);
    L.push("");
  }
  const questions = results.flatMap((r) => (r.openQuestions ?? []).map((q) => ({ at: r.at, q })));
  if (questions.length) {
    L.push(`## Open questions (${questions.length})`);
    L.push("");
    for (const q of questions) L.push(`- \`${q.at}\` — ${q.q}`);
    L.push("");
  }
  L.push(`## Per-unit records`);
  L.push("");
  for (const r of results) {
    L.push(`### \`${r.at}\``);
    if (r.guarantees?.length) {
      L.push(`**Guarantees**`);
      for (const g of r.guarantees) L.push(`- ${g.claim} — \`${g.file}:${g.line}\``);
    }
    if (r.assumptions?.length) {
      L.push(`**Assumes**`);
      for (const a of r.assumptions) L.push(`- ${a.claim} — ${a.enforcedAt === NOTHING_FOUND ? "**nothing found**" : `enforced at \`${a.enforcedAt}\``}`);
    }
    if (r.calls?.length) {
      L.push(`**Calls**`);
      for (const c of r.calls) L.push(`- \`${c.callee}\` — expects: ${c.expectedBehavior}`);
    }
    L.push("");
  }
  return L.join("\n") + "\n";
}

/** The file `investigate` picks leads up from, when this stage has run. */
export const LEADS_FILE = "ASSUMPTIONS.leads.json";

/** Leads that belong to a region, matched by path prefix. */
export function leadsForRegion(leads: { at: string; claim: string }[], region: string, files: string[]): string[] {
  const inRegion = (at: string) => at.startsWith(`${region}/`) || files.some((f) => at.startsWith(f));
  return leads.filter((l) => inRegion(l.at)).map((l) => `${l.at}: ${l.claim}`);
}
