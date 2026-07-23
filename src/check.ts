import { existsSync, openSync, readSync, closeSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import type { Dossier } from "./store.js";
import { SEVERITIES, type CodeLoc, type Finding, type Severity } from "./types.js";

// The exit gate. Grounding (default): every cited [file:line] must resolve in the
// repo — a hallucinated or stale location fails the audit (the same
// anti-hallucination contract as ultraindex/ultrasearch `check`). Semantic
// (--semantic): also require the audit to be fully adjudicated (no `open`
// candidate left) and every `confirmed` finding to still resolve.

export interface Dangling {
  id: string;
  file: string;
  line: number;
  reason: string;
}

export interface CheckResult {
  ok: boolean;
  dangling: Dangling[];
  open: number;
  confirmed: number;
  dismissed: number;
  needsHuman: number;
  gated: number; // findings considered after --min-severity
  messages: string[];
}

// A location is "external" if it resolves outside the repo (an absolute path
// from a dependency scanner, or a `../` escape). Such refs aren't graded for
// grounding — and crucially we never READ them (path-traversal guard). Exported
// so `investigate` can reject AI-invented citations BEFORE folding them in, with
// the EXACT same resolution as the grounding gate (no drift between the two).
export function insideRepo(repo: string, file: string): boolean {
  const base = resolve(repo);
  const abs = resolve(base, file);
  return abs === base || abs.startsWith(base + sep);
}

// Fixed-size binary chunk used to stream-count newlines — bounds memory to
// O(chunk) regardless of file size, unlike `readFileSync(file, "utf8")` which
// materializes the WHOLE decoded file as one JS string and throws past
// Node's max string length (~512MB-1GB). A `logs --budget thorough` run can
// produce a 10M-line file well past that ceiling.
const LINE_COUNT_CHUNK_BYTES = 1 << 20; // 1 MiB

/**
 * Count `\n` bytes across a whole open file descriptor via fixed-size binary
 * reads, never decoding or holding more than one chunk in memory at a time.
 * `\n` (0x0A) can never appear as part of a multi-byte UTF-8 sequence — every
 * continuation/lead byte is >= 0x80 — so scanning raw bytes for it is exactly
 * equivalent to counting `\n` in the decoded string, for any valid UTF-8
 * content. `chunkBytes` is overridable (default `LINE_COUNT_CHUNK_BYTES`) so
 * tests can force a tiny chunk size and prove counting is correct regardless
 * of where a `\n` (or a run of them) falls relative to a chunk boundary.
 * Exported for direct unit testing without a multi-GB fixture.
 */
export function countNewlines(fd: number, chunkBytes: number = LINE_COUNT_CHUNK_BYTES): number {
  const buf = Buffer.alloc(chunkBytes);
  let newlines = 0;
  for (;;) {
    const n = readSync(fd, buf, 0, chunkBytes, null);
    if (n === 0) break;
    for (let i = 0; i < n; i++) if (buf[i] === 0x0a) newlines++;
  }
  return newlines;
}

export type LineCountOutcome =
  | { status: "ok"; lines: number }
  | { status: "missing" } // outside the repo, or doesn't exist
  | { status: "unreadable"; error: string }; // exists but couldn't be read (huge file, a directory, permissions…)

/**
 * `lineCountDetailed` mirrors `"".split(/\r?\n/).length`'s semantics — N
 * newlines means N+1 "lines" (an unterminated trailing partial line still
 * counts as one more line, same as `String.split`; an empty file has 0
 * newlines and counts as 1 "line", matching `"".split(/\r?\n/).length === 1`)
 * — WITHOUT ever materializing the file as one JS string. Distinguishes a
 * missing citation from an unreadable one (a real file the process simply
 * couldn't read) — the two used to collapse into the same misleading "file
 * not found" note.
 */
export function lineCountDetailed(repo: string, file: string): LineCountOutcome {
  if (!insideRepo(repo, file)) return { status: "missing" };
  const abs = join(repo, file);
  if (!existsSync(abs)) return { status: "missing" };
  let fd: number;
  try {
    fd = openSync(abs, "r");
  } catch (e) {
    return { status: "unreadable", error: (e as Error).message };
  }
  try {
    return { status: "ok", lines: countNewlines(fd) + 1 };
  } catch (e) {
    return { status: "unreadable", error: (e as Error).message };
  } finally {
    closeSync(fd);
  }
}

/** Back-compat convenience wrapper — `null` on ANY failure (missing OR
 *  unreadable), same contract callers relied on before this file streamed
 *  its counting. Prefer `lineCountDetailed` where the caller should tell the
 *  two apart (see `check()` below). */
export function lineCount(repo: string, file: string): number | null {
  const outcome = lineCountDetailed(repo, file);
  return outcome.status === "ok" ? outcome.lines : null;
}

function locsOf(f: Finding): CodeLoc[] {
  const locs: CodeLoc[] = [];
  if (f.source) locs.push(f.source);
  if (f.sink) locs.push(f.sink);
  for (const p of f.path ?? []) locs.push(p);
  // Per-instance dep locations are citations too — grade them the same way.
  // A missing line means a whole-file citation (normalized to line 0 below).
  for (const e of f.locations ?? []) locs.push({ file: e.file, line: e.line ?? 0 });
  return locs;
}

export interface CheckOptions {
  repo?: string;
  semantic?: boolean;
  minSeverity?: Severity;
}

function atLeast(sev: Severity, floor: Severity): boolean {
  return SEVERITIES.indexOf(sev) <= SEVERITIES.indexOf(floor); // 0=critical … 4=info
}

export function check(dossier: Dossier, opts: CheckOptions = {}): CheckResult {
  const repo = opts.repo ?? dossier.manifest.repo;
  const floor = opts.minSeverity;
  const findings = floor ? dossier.findings.filter((f) => atLeast(f.severity, floor)) : dossier.findings;

  const dangling: Dangling[] = [];
  const lineCache = new Map<string, LineCountOutcome>();
  const linesOf = (file: string): LineCountOutcome => {
    if (!lineCache.has(file)) lineCache.set(file, lineCountDetailed(repo, file));
    return lineCache.get(file)!;
  };

  for (const f of findings) {
    // Dismissed findings need not resolve (the code may have been the false lead).
    if (f.status === "dismissed") continue;
    for (const loc of locsOf(f)) {
      // External references (absolute dependency paths, etc.) aren't repo
      // citations — don't grade or read them.
      if (!insideRepo(repo, loc.file)) continue;
      const lc = linesOf(loc.file);
      if (lc.status === "missing") dangling.push({ id: f.id, file: loc.file, line: loc.line, reason: "file not found" });
      // Distinct from "not found": the citation resolves to a real path the
      // process couldn't read (huge past Node's string limit, a directory,
      // permissions…) — reporting it as "not found" would send someone
      // looking for a file that's actually right there.
      else if (lc.status === "unreadable") dangling.push({ id: f.id, file: loc.file, line: loc.line, reason: `file unreadable (${lc.error})` });
      // Line 0 = an explicit whole-file citation (IaC/config checks like checkov
      // normalize to it) — the file must exist, but there is no line to range-check.
      else if (loc.line === 0) continue;
      else if (loc.line < 1 || loc.line > lc.lines)
        dangling.push({ id: f.id, file: loc.file, line: loc.line, reason: `line out of range (file has ${lc.lines} lines)` });
    }
  }

  const open = findings.filter((f) => f.status === "open").length;
  const confirmed = findings.filter((f) => f.status === "confirmed").length;
  const dismissed = findings.filter((f) => f.status === "dismissed").length;
  const needsHuman = findings.filter((f) => f.status === "needs-human").length;
  // Fail-closed: a finding is "adjudicated" only in a recognized terminal status.
  // Anything else — the literal `open`, a MISSING status, or a foreign/unknown
  // value (version skew, a tampered/corrupted dossier) — carries no real verdict
  // and must trip the semantic gate. Keying only off `=== "open"` would wave a
  // status-less or unknown-status finding through as "adjudicated" (fail-open).
  const ADJUDICATED = new Set<string>(["confirmed", "dismissed", "needs-human"]);
  const unadjudicated = findings.filter((f) => !ADJUDICATED.has(f.status as string)).length;

  const messages: string[] = [];
  let ok = true;

  if (dangling.length) {
    ok = false;
    messages.push(`${dangling.length} dangling citation(s) — a cited [file:line] does not resolve (hallucinated or stale).`);
  }
  if (opts.semantic) {
    if (unadjudicated > 0) {
      ok = false;
      messages.push(`${unadjudicated} candidate(s) still unadjudicated — run \`ultrasec verify\` and \`--apply\` verdicts before the gate can pass.`);
    }
    if (needsHuman > 0) messages.push(`${needsHuman} finding(s) flagged needs-human — review required (not auto-failing).`);
  }
  if (ok)
    messages.push(`grounding OK${opts.semantic ? " · audit adjudicated" : ""} — ${confirmed} confirmed, ${dismissed} dismissed, ${needsHuman} needs-human.`);

  return { ok, dangling, open, confirmed, dismissed, needsHuman, gated: findings.length, messages };
}
