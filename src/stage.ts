import { mkdirSync, writeFileSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { countBySeverity, writeDossier, type Dossier } from "./store.js";
import type { Finding } from "./types.js";

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
 *   - a directory → every entry whose name matches `dirRegex`, joined to it;
 *   - else a single file.
 */
export function collectApplyFiles(applyPath: string, dirRegex: RegExp): string[] {
  if (applyPath.includes(",")) return applyPath.split(",").map((s) => resolve(s.trim()));
  const abs = resolve(applyPath);
  try {
    if (statSync(abs).isDirectory()) {
      return readdirSync(abs)
        .filter((n) => dirRegex.test(n))
        .map((n) => join(abs, n));
    }
  } catch {
    /* fall through to single-file */
  }
  return [abs];
}

/**
 * Read + parse every apply file, concatenating the parsed arrays. Throws an Error
 * whose message is prefixed with the offending `<path>: ` on a read/parse failure,
 * so the caller can surface exactly which file failed.
 */
export function readApply<T>(applyPath: string, dirRegex: RegExp, parse: (raw: string) => T[]): T[] {
  const out: T[] = [];
  for (const f of collectApplyFiles(applyPath, dirRegex)) {
    try {
      out.push(...parse(readFileSync(f, "utf8")));
    } catch (e) {
      throw new Error(`${f}: ${(e as Error).message}`);
    }
  }
  return out;
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
