import { createReadStream, statSync } from "node:fs";
import { createInterface } from "node:readline";
import { relative, sep } from "node:path";
import { makeToolFinding } from "../tools/normalize.js";
import type { Finding, Severity } from "../types.js";
import { detectFormat, parseLine, type LogFormat, type ParsedEvent } from "./detect.js";
import { ATTACK_SIGNATURES, ESCALATION_FAMILIES, FAMILY_CWE, SCANNER_UAS, type AttackSignature } from "./patterns.js";
import { redact } from "./secrets.js";

// The streaming engine behind `ultrasec logs`. Reads each file with
// createReadStream + readline (bounded memory — never reads a whole log into
// RAM), runs the deterministic signature/scanner-UA detectors per line, and
// returns Findings + run stats + a truncation trail that is never silent.
//
// Extensibility note (for the follow-up task): every line's work funnels
// through `processEvent()` below with one `RunState` threaded through the
// whole run. Behavioral aggregation (brute-force/burst detection) and syslog
// slot in there — a per-IP accumulator alongside `ipCounter`, a new branch in
// `parseLine`'s format switch — without restructuring this loop.

export interface AnalyzeOptions {
  budget: "quick" | "standard" | "thorough";
  /** Force a format for every input file instead of auto-detecting per file. */
  format?: LogFormat;
  /** Override the budget preset's total-lines-per-run cap. */
  maxLines?: number;
  redact: boolean;
  /** Every finding's `sink.file` is stored relative to this directory. */
  base: string;
}

export interface LogStats {
  files: { path: string; lines: number; format: LogFormat }[];
  topIps: { ip: string; count: number }[];
  topPaths: { path: string; count: number }[];
  statusCounts: Record<string, number>;
  firstTs?: string;
  lastTs?: string;
  totalLines: number;
}

export interface AnalyzeResult {
  findings: Finding[];
  stats: LogStats;
  /** Human-readable coverage notes — budget stops, per-line and per-family
   *  caps. Never empty silently: every cap that engaged is reported here. */
  truncation: string[];
}

// Total LINES across the whole run (all files combined), not per file.
const BUDGETS: Record<AnalyzeOptions["budget"], number> = {
  quick: 200_000,
  standard: 2_000_000,
  thorough: 10_000_000,
};

const MAX_LINE_LEN = 8_192; // per-line length cap, applied before matching
const FAMILY_CAP = 50; // kept findings per attack-signature family, per RUN
const MAX_DISTINCT = 100_000; // distinct IPs/paths tracked before "(other)"
const EVIDENCE_MAX = 200; // evidence text cap in a finding's message
const TOP_N = 10;

function decodeOnce(path: string | undefined): string | undefined {
  if (!path) return undefined;
  try {
    return decodeURIComponent(path);
  } catch {
    return undefined; // malformed %xx — match on the raw path/line instead
  }
}

/** low→medium→high, one notch. Already-high/critical findings are left alone
 *  (the family's baseline severities never start above "high" today, so this
 *  never needs to reach "critical" — see patterns.ts). */
function escalateOnce(sev: Severity): Severity {
  if (sev === "low") return "medium";
  if (sev === "medium") return "high";
  return sev;
}

function truncateEvidence(s: string): string {
  return s.length > EVIDENCE_MAX ? s.slice(0, EVIDENCE_MAX) : s;
}

/** First-seen-bounded counter: tracks at most `cap` distinct keys; anything
 *  beyond that folds into a synthetic "(other)" bucket rather than growing
 *  unbounded memory on a run with millions of distinct IPs/paths. */
class BoundedCounter {
  private readonly counts = new Map<string, number>();
  constructor(private readonly cap: number) {}
  add(key: string): void {
    const cur = this.counts.get(key);
    if (cur !== undefined) {
      this.counts.set(key, cur + 1);
      return;
    }
    if (this.counts.size < this.cap) this.counts.set(key, 1);
    else this.counts.set("(other)", (this.counts.get("(other)") ?? 0) + 1);
  }
  top(n: number): { key: string; count: number }[] {
    return [...this.counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([key, count]) => ({ key, count }));
  }
}

/** Mutable state threaded through the whole run (every file). */
interface RunState {
  findings: Finding[];
  seenSignatureHits: Set<string>; // dedup key: `${file}::${line}::${sigId}`
  seenScannerUas: Set<string>; // dedup key: `${file}::${uaName}`
  familyCounts: Map<string, number>;
  familyOverflow: Map<string, number>;
  ipCounter: BoundedCounter;
  pathCounter: BoundedCounter;
  statusCounts: Record<string, number>;
  firstTs?: string;
  lastTs?: string;
  totalLines: number;
  files: LogStats["files"];
  truncation: string[];
  budgetRemaining: number;
}

function newState(maxLines: number): RunState {
  return {
    findings: [],
    seenSignatureHits: new Set(),
    seenScannerUas: new Set(),
    familyCounts: new Map(),
    familyOverflow: new Map(),
    ipCounter: new BoundedCounter(MAX_DISTINCT),
    pathCounter: new BoundedCounter(MAX_DISTINCT),
    statusCounts: {},
    totalLines: 0,
    files: [],
    truncation: [],
    budgetRemaining: maxLines,
  };
}

function addSignatureFinding(state: RunState, sig: AttackSignature, relPath: string, lineNo: number, ev: ParsedEvent, redactOn: boolean): void {
  const dedupKey = `${relPath}::${lineNo}::${sig.id}`;
  if (state.seenSignatureHits.has(dedupKey)) return;
  state.seenSignatureHits.add(dedupKey);

  // Rank-then-cap, streaming-safe: "rank" is first-seen order (deterministic
  // across runs of the same input) rather than a post-hoc severity sort, which
  // would require buffering every hit before capping — the opposite of the
  // bounded-memory streaming this engine promises.
  const kept = state.familyCounts.get(sig.family) ?? 0;
  if (kept >= FAMILY_CAP) {
    state.familyOverflow.set(sig.family, (state.familyOverflow.get(sig.family) ?? 0) + 1);
    return;
  }
  state.familyCounts.set(sig.family, kept + 1);

  let severity = sig.severity;
  let escalated = false;
  if (ESCALATION_FAMILIES.includes(sig.family) && typeof ev.status === "number" && ev.status >= 200 && ev.status < 300) {
    severity = escalateOnce(severity);
    escalated = true;
  }

  const evidenceSrc = redactOn ? redact(ev.raw).redacted : ev.raw;
  const evidence = truncateEvidence(evidenceSrc);
  const message = `${sig.title}: ${evidence}${escalated ? " (succeeded — 2xx)" : ""}`;

  const f = makeToolFinding({
    tool: "ultrasec",
    category: "logs",
    ident: `${sig.id}:${relPath}:${lineNo}`,
    title: sig.title,
    severity,
    message,
    file: relPath,
    line: lineNo,
    cwe: FAMILY_CWE[sig.family],
    confidence: "low",
  });
  if (f.sink) f.sink.kind = sig.family;
  state.findings.push(f);
}

function addScannerUaFinding(state: RunState, uaName: string, relPath: string, lineNo: number, uaRaw: string, redactOn: boolean): void {
  const key = `${relPath}::${uaName}`;
  if (state.seenScannerUas.has(key)) return; // one finding per (file, UA name) — first line seen
  state.seenScannerUas.add(key);

  const evidenceSrc = redactOn ? redact(uaRaw).redacted : uaRaw;
  const evidence = truncateEvidence(evidenceSrc);
  const f = makeToolFinding({
    tool: "ultrasec",
    category: "logs",
    ident: `scanner-ua:${uaName}:${relPath}`,
    title: `Scanner user-agent detected: ${uaName}`,
    severity: "low",
    message: `Known scanner/attack-tool user-agent (${uaName}): ${evidence}`,
    file: relPath,
    line: lineNo,
    confidence: "low",
  });
  if (f.sink) f.sink.kind = "scanner-ua";
  state.findings.push(f);
}

// One line's worth of work: update run stats, then every per-line detector.
function processEvent(state: RunState, relPath: string, lineNo: number, ev: ParsedEvent, opts: AnalyzeOptions): void {
  state.totalLines++;
  if (ev.ts) {
    if (state.firstTs === undefined) state.firstTs = ev.ts;
    state.lastTs = ev.ts;
  }
  if (ev.ip) state.ipCounter.add(ev.ip);
  if (ev.path) state.pathCounter.add(ev.path);
  if (typeof ev.status === "number") {
    const k = String(ev.status);
    state.statusCounts[k] = (state.statusCounts[k] ?? 0) + 1;
  }

  const decodedPath = decodeOnce(ev.path);
  const targets = [ev.path, decodedPath, ev.ua, ev.raw].filter((t): t is string => typeof t === "string");
  for (const sig of ATTACK_SIGNATURES) {
    if (targets.some((t) => sig.re.test(t))) addSignatureFinding(state, sig, relPath, lineNo, ev, opts.redact);
  }

  if (ev.ua) {
    for (const scanner of SCANNER_UAS) {
      if (scanner.re.test(ev.ua)) {
        addScannerUaFinding(state, scanner.name, relPath, lineNo, ev.ua, opts.redact);
        break; // one scanner match recorded per line is enough signal
      }
    }
  }
}

/** Best-effort "~M" total-line estimate for a budget-stopped file, from bytes
 *  read so far vs. the file's on-disk size — never re-reads the file. */
function estimateTotalLines(sizeBytes: number, bytesRead: number, linesRead: number): number {
  if (linesRead <= 0 || bytesRead <= 0) return linesRead;
  const avgBytesPerLine = bytesRead / linesRead;
  return avgBytesPerLine > 0 ? Math.max(linesRead, Math.round(sizeBytes / avgBytesPerLine)) : linesRead;
}

async function analyzeFile(absPath: string, relPath: string, opts: AnalyzeOptions, state: RunState): Promise<void> {
  let sizeBytes = 0;
  try {
    sizeBytes = statSync(absPath).size;
  } catch {
    /* best-effort — only feeds the "~M" truncation estimate */
  }

  const stream = createReadStream(absPath, { encoding: "utf8" });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });

  let fmt: LogFormat | undefined = opts.format;
  const sample: string[] = []; // non-blank lines collected for format voting
  const pending: { lineNo: number; raw: string }[] = []; // buffered until format is known
  let lineNo = 0;
  let bytesRead = 0;
  let longLines = 0;
  let stoppedAtBudget = false;

  const runOne = (n: number, raw: string): void => {
    bytesRead += Buffer.byteLength(raw, "utf8") + 1;
    let line = raw;
    if (line.length > MAX_LINE_LEN) {
      line = line.slice(0, MAX_LINE_LEN);
      longLines++;
    }
    processEvent(state, relPath, n, parseLine(fmt!, line), opts);
  };

  for await (const raw of rl) {
    if (state.budgetRemaining <= 0) {
      stoppedAtBudget = true;
      break;
    }
    lineNo++;
    state.budgetRemaining--;

    if (fmt === undefined) {
      pending.push({ lineNo, raw });
      if (raw.trim().length > 0) sample.push(raw);
      if (sample.length < 50) continue;
      fmt = detectFormat(sample);
      for (const p of pending) runOne(p.lineNo, p.raw);
      pending.length = 0;
      continue;
    }
    runOne(lineNo, raw);
  }

  if (fmt === undefined) {
    // EOF (or an early budget stop) before a 50-line sample — detect off
    // whatever we saw rather than leaving the buffered lines unprocessed.
    fmt = detectFormat(sample);
    for (const p of pending) runOne(p.lineNo, p.raw);
  }

  rl.close();
  stream.destroy();

  if (longLines > 0) {
    state.truncation.push(`${relPath}: ${longLines} line(s) exceeded ${MAX_LINE_LEN} chars — truncated before matching`);
  }
  if (stoppedAtBudget) {
    state.truncation.push(`${relPath}: stopped at line ${lineNo} of ~${estimateTotalLines(sizeBytes, bytesRead, lineNo)}`);
  }
  state.files.push({ path: relPath, lines: lineNo, format: fmt });
}

export async function analyzeLogs(paths: string[], opts: AnalyzeOptions): Promise<AnalyzeResult> {
  const maxLines = opts.maxLines ?? BUDGETS[opts.budget];
  const state = newState(maxLines);

  for (const absPath of paths) {
    const relPath = relative(opts.base, absPath).split(sep).join("/");
    if (state.budgetRemaining <= 0) {
      state.truncation.push(`${relPath}: not read — the ${maxLines.toLocaleString("en-US")}-line run budget was already exhausted`);
      continue;
    }
    await analyzeFile(absPath, relPath, opts, state);
  }

  for (const [family, overflow] of state.familyOverflow) {
    if (overflow > 0) state.truncation.push(`family ${family}: ${overflow} further hit(s) not emitted (per-family cap ${FAMILY_CAP})`);
  }

  const stats: LogStats = {
    files: state.files,
    topIps: state.ipCounter.top(TOP_N).map(({ key, count }) => ({ ip: key, count })),
    topPaths: state.pathCounter.top(TOP_N).map(({ key, count }) => ({ path: key, count })),
    statusCounts: state.statusCounts,
    ...(state.firstTs !== undefined ? { firstTs: state.firstTs } : {}),
    ...(state.lastTs !== undefined ? { lastTs: state.lastTs } : {}),
    totalLines: state.totalLines,
  };

  return { findings: state.findings, stats, truncation: state.truncation };
}
