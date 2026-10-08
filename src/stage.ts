import { mkdirSync, writeFileSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { countBySeverity, writeDossier, type Dossier } from "./store.js";
import type { Finding } from "./types.js";
import type { DroppedRow, NormalizedRow, ParseResult } from "./apply-parse.js";
import { flagBool, type ParsedArgs } from "./util.js";

// The shared stage harness. Every new AI stage (context/triage/investigate/
// revalidate/narrative) follows the proven `verify` shape: the engine EMITS a
// `<STEM>.todo.json` worklist into the run dir → the agent (or, in powered mode,
// an external CLI) fills it → `<cmd> --apply` folds it back in. These helpers
// generalize the apply-file resolution + persist loop that `commands/verify.ts`
// pioneered, so no stage re-derives it (or drifts from it).
//
// ── Why the Markdown brief is opt-in ───────────────────────────────────────
//
// Every worklist used to be written twice: the JSON an agent fills and a `.md`
// "brief" restating it for a human. On a 1,245-candidate run the twins were
// 264 KB + 158 KB for REVALIDATE alone, and the agents read BOTH — the brief to
// understand the task, the JSON to fill it — paying for every item twice. The
// instructions a brief carried are fixed text: they live in the references
// (schemas.md) and are printed once by the emitting command. So the JSON is the
// worklist, and the brief is written only when a human asks for it: `--md`, or
// `ULTRASEC_MD=1` for a whole session.

export interface StageFiles {
  /** JSON worklist the agent fills, e.g. "VERIFY.todo.json". */
  todo: string;
  /** Human-readable brief, e.g. "VERIFY.md" — written only on request. */
  md: string;
}

/** Conventional worklist file names for a stage stem ("VERIFY" → VERIFY.todo.json / VERIFY.md). */
export function stageFiles(stem: string): StageFiles {
  return { todo: `${stem}.todo.json`, md: `${stem}.md` };
}

/** Whether the human `.md` twin of a worklist is wanted: `--md`, or ULTRASEC_MD=1. */
export function wantsMdTwin(args?: ParsedArgs): boolean {
  return (args !== undefined && flagBool(args, "md")) || process.env.ULTRASEC_MD === "1";
}

/**
 * Write a stage's worklist: the JSON todo, plus the human Markdown brief when
 * `md` is on (default: `ULTRASEC_MD=1`). The brief is passed as a thunk so a
 * run that does not want it does not pay to render it. Returns the todo path.
 */
export function emitWorklist(run: string, files: StageFiles, items: unknown, md: string | (() => string), opts: { md?: boolean } = {}): string {
  mkdirSync(run, { recursive: true });
  const todoPath = join(run, files.todo);
  writeFileSync(todoPath, JSON.stringify(items, null, 2));
  if (opts.md ?? wantsMdTwin()) writeFileSync(join(run, files.md), typeof md === "function" ? md() : md);
  return todoPath;
}

/**
 * The line an emitting command prints where it used to point at the brief: the
 * JSON is the worklist, the format is in the references, the brief is opt-in.
 */
export function worklistNote(files: StageFiles, wroteMd: boolean): string {
  return wroteMd
    ? `  brief: ${files.md} (human copy of ${files.todo})`
    : `  fill ${files.todo} directly — field-by-field format in references/schemas.md (\`--md\` also writes ${files.md})`;
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
  const normalized: NormalizedRow[] = [];
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
    // Carry the rewrites too, or a multi-file fold reports what it refused and
    // stays silent about what it changed.
    normalized.push(...(parsed.normalized ?? []));
  }
  return { rows, dropped, ...(normalized.length ? { normalized } : {}) };
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
