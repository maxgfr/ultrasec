import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { readText } from "./walk.js";
import { scanRepo as engineScanRepo, type FileRecord } from "./vendor/codeindex-engine.mjs";

// Jupyter notebooks — the code an audit cannot see because it is not stored as
// code.
//
// A `.ipynb` is JSON. No extension set in this engine claimed it, no language
// mapped it, and no external scanner reads it either: bandit has had B307
// (`eval`) since forever and simply cannot open the format. So on a repository
// with eight notebooks, the audit's file count said eight files were tracked and
// the findings said nothing was in them — the two statements a security tool must
// never both make.
//
// It cost a real finding. `analysis/notebooks/search_stats.ipynb` runs
// `df['action_eventname'].apply(eval)` over rows pulled from Matomo, whose event
// names any visitor to the public site can set. A human found it by reading. The
// engine had walked straight past the file.
//
// ── The shadow, and why it is line-aligned ─────────────────────────────────
//
// Everything downstream of `scan` speaks `[file:line]`, and `check` REJECTS a
// citation whose line does not resolve in the file. So a notebook's code is
// rewritten as a Python file with EXACTLY the same number of lines as the raw
// JSON, where line N holds the code if line N of the JSON carries a source
// string, and is blank otherwise.
//
// That one property is what makes the whole thing cheap: every pass after this
// one — taint, orphan sinks, the guard matrix, the graph — sees an ordinary
// Python file, and every citation it emits points at the real byte offset in the
// real notebook, where a reader will find the code and the gate will find a line.
//
// Positions come from searching the raw text for each source string's CANONICAL
// JSON encoding, with the structure itself taken from `JSON.parse`. A notebook
// whose writer escaped differently (`é` for a literal `é`) simply fails the
// search, and that line is counted as unaligned rather than guessed at.

/** Jupyter's own autosave copies. A checkpoint is a stale duplicate of the
 *  notebook beside it: scanning both doubles every finding in the tree, which is
 *  precisely the vendored-artifact noise a real audit spent its triage budget
 *  on. Skipped, and counted, so the number is visible rather than assumed. */
const CHECKPOINT_DIR = /(^|\/)\.ipynb_checkpoints\//;

/** IPython line magics (`%matplotlib inline`, `%%time`) and shell escapes
 *  (`!pip install …`). Neither is Python, and feeding them to a Python parser
 *  produces syntax noise, not findings. Blanked — the LINE still exists, so
 *  nothing after it shifts. */
const NOT_PYTHON = /^\s*[%!]/;

export interface NotebookShadow {
  /** Python text with the same line count as the raw notebook. */
  text: string;
  /** Lines of real code the shadow carries. */
  codeLines: number;
  /** Source lines whose position could not be located in the raw text, or whose
   *  cell stored `source` as one string rather than a list of lines. Reported,
   *  never silently dropped. */
  unaligned: number;
  /** Magic / shell lines blanked out. */
  blanked: number;
}

interface RawCell {
  cell_type?: unknown;
  source?: unknown;
}

/**
 * Rewrite one notebook as a line-aligned Python shadow.
 *
 * Returns `undefined` when the text is not a notebook this can read at all (not
 * JSON, or no `cells` array) — the caller counts that rather than failing the
 * scan, because an unreadable notebook is one file's worth of coverage, not a
 * reason to abandon a repository.
 */
export function notebookShadow(raw: string): NotebookShadow | undefined {
  let doc: { cells?: unknown };
  try {
    doc = JSON.parse(raw) as { cells?: unknown };
  } catch {
    return undefined;
  }
  if (!doc || !Array.isArray(doc.cells)) return undefined;

  const total = raw.split("\n").length;
  const out: string[] = new Array(total).fill("");
  let codeLines = 0;
  let unaligned = 0;
  let blanked = 0;

  // A forward-only cursor: source strings appear in the raw text in the same
  // order the parser reports them, so each search starts where the last match
  // ended. That keeps two identical lines in two different cells from both
  // resolving to the first one's position.
  let cursor = 0;
  const lineOf = (index: number): number => raw.slice(0, index).split("\n").length;

  for (const cell of doc.cells as RawCell[]) {
    if (cell?.cell_type !== "code") continue;
    const source = cell.source;
    // nbformat allows `source` to be a list of lines OR one string, and real
    // notebooks carry both — six cells of the notebook that motivated this file
    // are one-line strings. A ONE-line string is exactly as alignable as a list
    // element: the whole cell sits on one raw line, which is the line to cite.
    // A MULTI-line string is not, because every one of its lines shares that
    // single raw line; those are counted, because half a cell placed on the
    // wrong lines is worse than a number that says what was missed.
    let pieces: unknown[];
    if (typeof source === "string") {
      if (source.split("\n").filter((l, i, a) => l !== "" || i < a.length - 1).length > 1) {
        unaligned += source.split("\n").length;
        continue;
      }
      pieces = [source];
    } else if (Array.isArray(source)) {
      pieces = source;
    } else continue;

    for (const piece of pieces) {
      if (typeof piece !== "string") continue;
      const at = raw.indexOf(JSON.stringify(piece), cursor);
      if (at < 0) {
        unaligned++;
        continue;
      }
      cursor = at + 1;
      const line = lineOf(at);
      if (line > total) {
        unaligned++;
        continue;
      }
      const code = piece.replace(/\r?\n$/, "");
      if (NOT_PYTHON.test(code)) {
        blanked++;
        continue;
      }
      if (!code.trim()) continue;
      out[line - 1] = code;
      codeLines++;
    }
  }

  return { text: out.join("\n"), codeLines, unaligned, blanked };
}

/** What the manifest records about this pass, so a run that scanned no notebook
 *  and a run that could not scan one are never the same statement. */
export interface NotebookStats {
  /** `.ipynb` files the walk enumerated, checkpoints excluded. */
  found: number;
  /** Notebooks whose code was extracted and handed to the extractor. */
  scanned: number;
  /** Jupyter checkpoint copies skipped as duplicates. */
  checkpoints: number;
  /** Source lines that could not be aligned to a raw line — never cited. */
  unaligned: number;
  /** Why nothing was scanned, when nothing was. */
  note?: string;
}

export interface NotebookScan {
  /** Engine records for the shadow `.py` files — `rel` is still the SHADOW's
   *  path, so the caller's existing record→FileScan mapper recognises it as
   *  Python. `origin` says which notebook each one came from. */
  records: FileRecord[];
  /** shadow rel (`<notebook>.ipynb.py`) → the notebook's own repo-relative path. */
  origin: Map<string, string>;
  stats: NotebookStats;
}

/**
 * Extract every notebook in `rels` through the ordinary extractor.
 *
 * The shadows go to a temp directory and are scanned with the SAME engine every
 * other file goes through, so a notebook gets real symbols, imports and call
 * sites rather than a second-class regex pass. The directory is removed before
 * this returns, whatever happens.
 *
 * Records come back carrying the SHADOW path on purpose: the caller owns the
 * one record→FileScan mapping in this codebase, and handing it a `.py` rel lets
 * it recognise the language without a second copy of that logic living here. It
 * swaps in the notebook's real path afterwards, from `origin`.
 *
 * A filesystem that refuses the write (a read-only checkout, a full disk) costs
 * the notebooks and nothing else: the scan continues, and `stats.note` says what
 * was lost. That is the one behaviour worth insisting on — a security tool that
 * dies on an unwritable temp dir teaches people to run it with the pass off.
 */
export function scanNotebooks(repo: string, rels: readonly string[]): NotebookScan {
  const checkpoints = rels.filter((r) => CHECKPOINT_DIR.test(r)).length;
  const targets = rels.filter((r) => !CHECKPOINT_DIR.test(r));
  const empty = (note?: string): NotebookScan => ({
    records: [],
    origin: new Map(),
    stats: { found: targets.length, scanned: 0, checkpoints, unaligned: 0, ...(note ? { note } : {}) },
  });
  if (!targets.length) return empty();

  let dir: string | undefined;
  try {
    dir = mkdtempSync(join(tmpdir(), "ultrasec-nb-"));
  } catch (e) {
    return empty(`notebook code was not scanned: could not create a temp directory (${(e as Error).message})`);
  }

  try {
    // shadow rel (`<notebook>.py`) → the notebook's own rel, for the rewrite back.
    const origin = new Map<string, string>();
    let unaligned = 0;
    let unreadable = 0;

    for (const rel of targets) {
      const shadow = notebookShadow(readText(join(repo, rel)));
      if (!shadow) {
        unreadable++;
        continue;
      }
      unaligned += shadow.unaligned;
      // A notebook of nothing but markdown and magics has no code to scan. Still
      // counted as scanned — we looked, and there was nothing there.
      const shadowRel = `${rel}.py`;
      const abs = join(dir, shadowRel);
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, shadow.text);
      origin.set(shadowRel, rel);
    }

    const stats: NotebookStats = {
      found: targets.length,
      scanned: origin.size,
      checkpoints,
      unaligned,
      ...(unreadable ? { note: `${unreadable} notebook(s) were not valid nbformat JSON and were not scanned` } : {}),
    };
    if (!origin.size) return { records: [], origin, stats };

    const engine = engineScanRepo(dir, {});
    return { records: engine.files.filter((f) => origin.has(f.rel)), origin, stats };
  } catch (e) {
    return empty(`notebook code was not scanned: ${(e as Error).message}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
