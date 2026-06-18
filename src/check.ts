import { existsSync, readFileSync } from "node:fs";
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

export function lineCount(repo: string, file: string): number | null {
  if (!insideRepo(repo, file)) return null;
  const abs = join(repo, file);
  if (!existsSync(abs)) return null;
  try {
    return readFileSync(abs, "utf8").split(/\r?\n/).length;
  } catch {
    return null;
  }
}

function locsOf(f: Finding): CodeLoc[] {
  const locs: CodeLoc[] = [];
  if (f.source) locs.push(f.source);
  if (f.sink) locs.push(f.sink);
  for (const p of f.path ?? []) locs.push(p);
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
  const lineCache = new Map<string, number | null>();
  const linesOf = (file: string): number | null => {
    if (!lineCache.has(file)) lineCache.set(file, lineCount(repo, file));
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
      if (lc === null) dangling.push({ id: f.id, file: loc.file, line: loc.line, reason: "file not found" });
      else if (loc.line < 1 || loc.line > lc) dangling.push({ id: f.id, file: loc.file, line: loc.line, reason: `line out of range (file has ${lc} lines)` });
    }
  }

  const open = findings.filter((f) => f.status === "open").length;
  const confirmed = findings.filter((f) => f.status === "confirmed").length;
  const dismissed = findings.filter((f) => f.status === "dismissed").length;
  const needsHuman = findings.filter((f) => f.status === "needs-human").length;

  const messages: string[] = [];
  let ok = true;

  if (dangling.length) {
    ok = false;
    messages.push(`${dangling.length} dangling citation(s) — a cited [file:line] does not resolve (hallucinated or stale).`);
  }
  if (opts.semantic) {
    if (open > 0) {
      ok = false;
      messages.push(`${open} candidate(s) still unadjudicated — run \`ultrasec verify\` and \`--apply\` verdicts before the gate can pass.`);
    }
    if (needsHuman > 0) messages.push(`${needsHuman} finding(s) flagged needs-human — review required (not auto-failing).`);
  }
  if (ok) messages.push(`grounding OK${opts.semantic ? " · audit adjudicated" : ""} — ${confirmed} confirmed, ${dismissed} dismissed, ${needsHuman} needs-human.`);

  return { ok, dangling, open, confirmed, dismissed, needsHuman, gated: findings.length, messages };
}
