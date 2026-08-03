import { mkdirSync, writeFileSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { countBySeverity, writeDossier, type Dossier } from "./store.js";
import type { Finding } from "./types.js";
import type { DroppedRow, ParseResult } from "./apply-parse.js";

// The shared stage harness. Every new AI stage (context/triage/investigate/
// revalidate/narrative) follows the proven `verify` shape: the engine EMITS a
// `<STEM>.todo.json` worklist + a `<STEM>.md` human brief into the run dir → the
// agent (or, in powered mode, an external CLI) fills it → `<cmd> --apply` folds it
// back in. These helpers generalize the apply-file resolution + persist loop that
// `commands/verify.ts` pioneered, so no stage re-derives it (or drifts from it).

export interface StageFiles {
  /** JSON worklist the agent fills, e.g. "VERIFY.todo.json". */
  todo: string;
  /** Human-readable brief, e.g. "VERIFY.md". */
  md: string;
}

/** Conventional worklist file names for a stage stem ("VERIFY" → VERIFY.todo.json / VERIFY.md). */
export function stageFiles(stem: string): StageFiles {
  return { todo: `${stem}.todo.json`, md: `${stem}.md` };
}

/** Write a stage's worklist: the JSON todo + the human Markdown. Returns the todo path. */
export function emitWorklist(run: string, files: StageFiles, items: unknown, md: string): string {
  mkdirSync(run, { recursive: true });
  const todoPath = join(run, files.todo);
  writeFileSync(todoPath, JSON.stringify(items, null, 2));
  writeFileSync(join(run, files.md), md);
  return todoPath;
}

/**
 * Resolve an `--apply` argument to a list of files (generalizes verify's
 * `collectVerdictFiles`):
 *   - a comma list "a,b,c" → each path, trimmed + resolved;
 *   - a directory → every entry whose name matches `dirRegex`, joined to it,
 *     SORTED (readdir order is filesystem-dependent; the fold must be
 *     deterministic) — and FAIL-CLOSED: a directory yielding no match throws
 *     instead of silently folding nothing;
 *   - else a single file.
 */
export function collectApplyFiles(applyPath: string, dirRegex: RegExp): string[] {
  if (applyPath.includes(",")) return applyPath.split(",").map((s) => resolve(s.trim()));
  const abs = resolve(applyPath);
  let isDir = false;
  try {
    isDir = statSync(abs).isDirectory();
  } catch {
    /* fall through to single-file (caller surfaces the read error) */
  }
  if (isDir) {
    const matches = readdirSync(abs)
      .filter((n) => dirRegex.test(n))
      .sort()
      .map((n) => join(abs, n));
    if (matches.length === 0) throw new Error(`${abs}: no apply file matching ${dirRegex} in this directory — nothing to fold (fail-closed)`);
    return matches;
  }
  return [abs];
}

/**
 * Read + parse every apply file, concatenating the parsed rows AND the rows each
 * parser refused. Throws an Error whose message is prefixed with the offending
 * `<path>: ` on a read/parse failure, so the caller can surface exactly which file
 * failed.
 *
 * The `dropped` rows travel with the result so no caller can accidentally fold a
 * partially-parsed file and report success — see `apply-parse.ts` for why that
 * mattered enough to change every signature.
 *
 * `applyPath` of `-` reads stdin instead, so verdicts can be piped in.
 */
export function readApply<T>(applyPath: string, dirRegex: RegExp, parse: (raw: string) => ParseResult<T>): ParseResult<T> {
  if (applyPath === "-") {
    let raw: string;
    try {
      raw = readFileSync(0, "utf8");
    } catch (e) {
      throw new Error(`<stdin>: ${(e as Error).message}`);
    }
    try {
      return parse(raw);
    } catch (e) {
      throw new Error(`<stdin>: ${(e as Error).message}`);
    }
  }

  const files = collectApplyFiles(applyPath, dirRegex);
  const rows: T[] = [];
  const dropped: DroppedRow[] = [];
  for (const f of files) {
    let parsed: ParseResult<T>;
    try {
      parsed = parse(readFileSync(f, "utf8"));
    } catch (e) {
      throw new Error(`${f}: ${(e as Error).message}`);
    }
    rows.push(...parsed.rows);
    // Only qualify by file when the fold spans several — a single-file apply
    // reads better without the path repeated on every line.
    dropped.push(...parsed.dropped.map((d) => (files.length > 1 ? { ...d, file: f } : d)));
  }
  return { rows, dropped };
}

/**
 * Persist an updated finding set into a run dir, recomputing the manifest counts
 * and reusing the existing graph. The single place every adjudicating stage writes
 * through, so the dossier triple stays consistent (counts always reflect findings).
 */
export function persistFindings(run: string, dossier: Dossier, findings: Finding[]): void {
  const manifest = { ...dossier.manifest, counts: { findings: findings.length, bySeverity: countBySeverity(findings) } };
  writeDossier(run, { manifest, findings, graph: dossier.graph });
}
