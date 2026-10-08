import { existsSync } from "node:fs";
import { join } from "node:path";

// Where each artifact of a run directory lives — the one place that decides it.
//
// ── Why there is a `.work/` folder ─────────────────────────────────────────
//
// A mid-size monorepo audit (1,245 candidates) left more than thirty files and
// two sub-folders at the top of its run directory: a 2.7 MB `graph.json`, the
// scan cache, the orchestration scripts, the journal, the pack suggestions and
// every worklist twice over. The deliverable was one file among them, and the
// agent driving the audit opened several of the others "to get oriented" —
// paying for megabytes nobody needed to read.
//
// So the run keeps at its top only what a person or an agent is meant to open
// (findings.json, manifest.json, CONTEXT.md, NARRATIVE.json, the worklists while
// an audit is in progress, and the report), and everything the engine keeps for
// ITSELF goes under `.work/`. A dot-folder, so a directory listing — the first
// thing an agent does — does not even show it.
//
// ── Migration ──────────────────────────────────────────────────────────────
//
// Runs written before this layout keep `graph.json`, `cache/`, `JOURNAL.md`,
// `PACK-SUGGESTIONS.json` and `orchestration/` at the top. Writers always use
// the new place; readers go through `readPath`, which falls back to the old one
// when the new one is absent, so an existing run keeps loading without a
// migration step and the next write moves nothing it did not have to.

/** The internal-state folder under a run directory. */
export const WORK_DIR = ".work";

/** Absolute path of the internal-state folder of `run`. */
export function workDir(run: string): string {
  return join(run, WORK_DIR);
}

/** Where an internal artifact is WRITTEN: always under `.work/`. */
export function workPath(run: string, ...parts: string[]): string {
  return join(run, WORK_DIR, ...parts);
}

/**
 * Where an internal artifact is READ from: `.work/<parts>` when present, else
 * the pre-`.work` top-level location when THAT is present (an older run), else
 * the new location — so a "not found" error names where it should have been.
 */
export function readPath(run: string, ...parts: string[]): string {
  const current = workPath(run, ...parts);
  if (existsSync(current)) return current;
  const legacy = join(run, ...parts);
  return existsSync(legacy) ? legacy : current;
}

/**
 * What a finished run keeps at its top level after `clean` (and after `audit`
 * without `--keep-work`): the report, the dossier it was rendered from, and the
 * two documents a human or an agent authored. Everything else is regenerable.
 */
export const KEPT_FILES: readonly string[] = ["REPORT.md", "REPORT.html", "findings.json", "manifest.json", "CONTEXT.md", "NARRATIVE.json"];

/**
 * Rendered outputs of the previous report layout. `clean` never deletes a
 * report someone already produced: an older run's SUMMARY.md / index.html /
 * top-level JOURNAL.md were the deliverables under the contract it was written
 * with, so they are preserved rather than silently removed.
 */
export const LEGACY_DELIVERABLES: readonly string[] = ["SUMMARY.md", "index.html", "JOURNAL.md"];
