import { createReadStream, statSync } from "node:fs";
import { createInterface } from "node:readline";
import { relative, sep } from "node:path";
import { makeToolFinding } from "../tools/normalize.js";
import { shortHash } from "../util.js";
import type { Finding, Severity } from "../types.js";
import { detectFormat, parseLine, type LogFormat, type ParsedEvent } from "./detect.js";
import { ATTACK_SIGNATURES, ESCALATION_FAMILIES, FAMILY_CWE, PROBE_PATH_RE, SCANNER_UAS, classifyAuthEvent, type AttackSignature } from "./patterns.js";
import { PII_PATTERNS, SECRET_PATTERNS, redact, truncateEvidence } from "./secrets.js";

// The streaming engine behind `ultrasec logs`. Reads each file with
// createReadStream + readline (bounded memory — never reads a whole log into
// RAM), runs the deterministic detectors per line, and returns Findings + run
// stats + a truncation trail that is never silent. Three detector layers share
// one `RunState` threaded through the whole run (every file, one pass):
//   1. per-line signature/scanner-UA detection (Task 6 — unchanged below);
//   2. per-line secret/PII-leak detection (this task — `processSecrets`);
//   3. per-IP behavioral aggregation: brute-force/compromise, request bursts,
//      scan/recon→hit (this task — `processBehavior`, bounded IP state).

export interface AnalyzeOptions {
  budget: "quick" | "standard" | "thorough";
  /** Force a format for every input file instead of auto-detecting per file. */
  format?: LogFormat;
  /** Override the budget preset's total-lines-per-run cap. */
  maxLines?: number;
  redact: boolean;
  /** Every finding's `sink.file` is stored relative to this directory. */
  base: string;
  /** Sliding-window size (seconds) for the behavioral detectors. Default 60
   *  (`DEFAULT_WINDOW_SECONDS`) when omitted. */
  windowSec?: number;
}

export interface LogStats {
  files: { path: string; lines: number; format: LogFormat }[];
  topIps: { ip: string; count: number }[];
  topPaths: { path: string; count: number }[];
  statusCounts: Record<string, number>;
  firstTs?: string;
  lastTs?: string;
  totalLines: number;
  /** Total auth-fail EVENTS across the run (line-level count, every IP, not
   *  gated by the brute-force threshold — a raw signal for context). */
  authFailures: number;
  /** Auth-success events that occurred for an IP which had at least one prior
   *  auth-fail event this run — a broader, sub-threshold cousin of the
   *  "possible credential compromise" finding (which requires a full
   *  qualifying brute-force run first). */
  authSuccessAfterFailure: number;
  /** Distinct IPs behaviorally tracked this run (capped at MAX_TRACKED_IPS). */
  distinctIpsSeen: number;
  /** True when more distinct IPs arrived than MAX_TRACKED_IPS could track —
   *  `distinctIpsSeen` is then a floor, not an exact count (see BoundedIpStates). */
  distinctIpsOverflowed: boolean;
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
const TOP_N = 10;

// ── Behavioral aggregation (per-IP state, second detector layer) ────────────

// Bounded per-IP behavioral state — protects memory against a log forged with
// millions of distinct source IPs. Each tracked IP costs real memory (three
// sliding-window queues), unlike the simple BoundedCounter above, so the cap
// is enforced with its own eviction (see BoundedIpStates): IPs beyond it keep
// their per-line signature/UA findings but skip brute-force/burst/recon
// aggregation, and the run notes the overflow once.
const MAX_TRACKED_IPS = 100_000;

// >=20 failed-auth events from one IP inside the window: comfortably above the
// couple of mistyped-password retries a normal user produces, low enough to
// still catch a slow/low-and-slow credential-stuffing run.
const BRUTE_FORCE_FAIL_THRESHOLD = 20;

// Default sliding-window size in seconds for every behavioral detector unless
// `--window` overrides it — long enough to catch a scripted burst, short
// enough that unrelated traffic hours apart is never pooled together.
export const DEFAULT_WINDOW_SECONDS = 60;

// Fallback window (in LINES, not seconds) for a source whose timestamp can't
// be turned into an unambiguous epoch (classic BSD syslog's "Mon DD HH:MM:SS"
// carries no year — see `parseTsEpochMs`). 500 lines approximates a couple of
// minutes of traffic on a moderately busy log without silently disabling the
// detector on ts-less formats; every finding built off it says so.
const LINE_PROXY_WINDOW = 500;

// MORE THAN 300 requests from one IP inside the window: well above a single
// real browsing session or a legitimate poller, low enough to catch a
// scripted sweep before it finishes the window.
const REQUEST_BURST_THRESHOLD = 300;

// >=15 4xx (401/403/404) responses from one IP inside the window: enough
// distinct failed probes to read as directory/endpoint enumeration or
// credential/authorization probing, not a couple of natural not-founds.
const ERROR_SPIKE_THRESHOLD = 15;
const ERROR_SPIKE_STATUSES = new Set([401, 403, 404]);

// ── Secret/PII leak findings ─────────────────────────────────────────────────

// Kept secret/PII-leak findings per log FILE (not per run, unlike FAMILY_CAP) —
// a single flooded file shouldn't crowd out every other file's leaks in the
// same run.
const SECRET_FILE_CAP = 25;

// A single email in a log line is routine (a support ticket, an account email
// in an app log) — not worth a finding by itself. Five or more DISTINCT emails
// in one file reads as an actual bulk PII leak (a dumped user table, a
// mail-merge that hit the log) rather than one-off appearances.
const EMAIL_BULK_THRESHOLD = 5;

// Bounds the per-file distinct-email tracking set (hashed, never the raw
// address — see `trackDistinctEmails`) against a pathological file with
// millions of unique addresses; the heuristic only ever needs to know
// "have we crossed 5", never the true cardinality.
const EMAIL_HASH_CAP = 10_000;

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

const NGINX_BRACKET_TS_RE = /^(\d{1,2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$/;
const ISO_TZ_TS_RE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/i;
const MONTH_INDEX: Record<string, number> = {
  Jan: 0,
  Feb: 1,
  Mar: 2,
  Apr: 3,
  May: 4,
  Jun: 5,
  Jul: 6,
  Aug: 7,
  Sep: 8,
  Oct: 9,
  Nov: 10,
  Dec: 11,
};

/**
 * Turn a `ParsedEvent.ts` string into epoch milliseconds — ONLY when it
 * carries a full, self-describing, unambiguous instant (an explicit year AND
 * an explicit UTC offset/`Z`). Two shapes qualify:
 *  - the nginx/common access-log bracket date (`10/Oct/2023:13:55:01 +0000`) —
 *    built via `Date.UTC` + the literal offset, never the runtime's local tz;
 *  - ISO-8601 with an explicit `Z`/offset (`2024-01-02T10:00:00Z`) — `Date.parse`
 *    is deterministic for these (unlike a bare, offset-less ISO string, which
 *    per spec parses in the RUNNING MACHINE's local tz — never trusted here,
 *    that would make the same log window differently on two machines).
 * Anything else — notably classic BSD syslog's "Mon DD HH:MM:SS" (no year) —
 * returns `undefined` rather than fabricate a year/timezone that was never on
 * the wire; callers fall back to `LINE_PROXY_WINDOW`.
 */
function parseTsEpochMs(ts: string | undefined): number | undefined {
  if (!ts) return undefined;
  const nginx = NGINX_BRACKET_TS_RE.exec(ts);
  if (nginx) {
    const [, day, mon, year, hh, mm, ss, tz] = nginx;
    const month = MONTH_INDEX[mon!];
    if (month === undefined) return undefined;
    const base = Date.UTC(Number(year), month, Number(day), Number(hh), Number(mm), Number(ss));
    const sign = tz![0] === "-" ? 1 : -1; // "+HHMM" is east of UTC — subtract to normalize.
    const offsetMin = Number(tz!.slice(1, 3)) * 60 + Number(tz!.slice(3, 5));
    return base + sign * offsetMin * 60_000;
  }
  if (ISO_TZ_TS_RE.test(ts)) {
    const parsed = Date.parse(ts);
    return Number.isNaN(parsed) ? undefined : parsed;
  }
  return undefined;
}

/** One occurrence fed into a `SlidingWindowTracker` — carries enough to both
 *  drive window eviction (`idx`/`tsMs`) and cite the event as evidence
 *  (`relPath`/`lineNo`). */
interface WindowMark {
  /** Run-wide monotonic event index (`RunState.totalLines` at the time),
   *  the line-count proxy's "clock" when no timestamp is available. */
  idx: number;
  tsMs?: number;
  relPath: string;
  lineNo: number;
}

/**
 * Bounded sliding-window occurrence counter for one IP's one detector
 * (auth-fail / request / 4xx). The windowing MODE is decided once, from the
 * first mark fed in — time-based when it carries a parseable epoch, else the
 * line-count proxy — and stays fixed for the tracker's life, so a run never
 * silently switches window semantics mid-series for the same IP. Memory is
 * bounded two ways: the queue only ever holds marks inside the current
 * window (evicted on every `add`), and every caller in `processBehavior`
 * stops feeding a tracker once its threshold has fired (see `analyze.ts`) —
 * so pre-fire the queue never exceeds the detector's own threshold either.
 */
class SlidingWindowTracker {
  private readonly marks: WindowMark[] = [];
  private mode: "time" | "line-proxy" | undefined;
  constructor(
    private readonly windowSeconds: number,
    private readonly lineProxySize: number,
  ) {}

  add(mark: WindowMark): { count: number; oldest: WindowMark; usedLineProxy: boolean } {
    if (this.mode === undefined) this.mode = mark.tsMs !== undefined ? "time" : "line-proxy";
    this.marks.push(mark);
    if (this.mode === "time" && mark.tsMs !== undefined) {
      const cutoff = mark.tsMs - this.windowSeconds * 1000;
      while (this.marks.length > 1 && (this.marks[0]!.tsMs ?? mark.tsMs) < cutoff) this.marks.shift();
    } else {
      const cutoff = mark.idx - this.lineProxySize;
      while (this.marks.length > 1 && this.marks[0]!.idx < cutoff) this.marks.shift();
    }
    return { count: this.marks.length, oldest: this.marks[0]!, usedLineProxy: this.mode === "line-proxy" };
  }

  /** Drop every held mark — called once a detector has fired (one finding per
   *  (IP, detector) per run) so a hot IP's queue doesn't keep growing for the
   *  rest of the run for no further benefit. */
  clear(): void {
    this.marks.length = 0;
  }
}

function windowDescription(usedLineProxy: boolean, windowSeconds: number): string {
  return usedLineProxy
    ? `the last ${LINE_PROXY_WINDOW.toLocaleString("en-US")} lines (no parseable timestamp on this source — falling back to a line-count proxy window)`
    : `a ${windowSeconds}s window`;
}

/** Per-IP behavioral state — one of these per tracked IP (bounded by
 *  BoundedIpStates), covering all three behavioral detector pairs. */
interface IpBehaviorState {
  authFail: SlidingWindowTracker;
  bruteForceFired: boolean;
  sawAnyAuthFail: boolean;
  /** Sticky once a brute-force run has qualified (independent of whether the
   *  window/tracker keeps growing) — this is what gates the credential-
   *  compromise finding on a LATER success, even after `authFail` is cleared. */
  hadQualifyingAuthRun: boolean;
  qualifyingAuthMark?: WindowMark;
  compromiseFired: boolean;

  request: SlidingWindowTracker;
  burstFired: boolean;

  error4xx: SlidingWindowTracker;
  spikeFired: boolean;
  hadQualifyingErrorRun: boolean;
  reconHitFired: boolean;
}

function newIpBehaviorState(windowSeconds: number): IpBehaviorState {
  return {
    authFail: new SlidingWindowTracker(windowSeconds, LINE_PROXY_WINDOW),
    bruteForceFired: false,
    sawAnyAuthFail: false,
    hadQualifyingAuthRun: false,
    compromiseFired: false,
    request: new SlidingWindowTracker(windowSeconds, LINE_PROXY_WINDOW),
    burstFired: false,
    error4xx: new SlidingWindowTracker(windowSeconds, LINE_PROXY_WINDOW),
    spikeFired: false,
    hadQualifyingErrorRun: false,
    reconHitFired: false,
  };
}

/**
 * First-seen-bounded map from IP → behavioral state. Unlike `BoundedCounter`
 * (a single number per key), each entry here costs real memory (three
 * sliding-window queues), so a log forged with millions of distinct source
 * IPs is capped at `MAX_TRACKED_IPS` tracked entries; IPs beyond the cap are
 * simply not behaviorally aggregated (their line-level signature/scanner-UA/
 * secret findings still fire normally) — the run notes the overflow once.
 */
class BoundedIpStates {
  private readonly map = new Map<string, IpBehaviorState>();
  overflowed = false;
  constructor(
    private readonly cap: number,
    private readonly windowSeconds: number,
  ) {}
  get(ip: string): IpBehaviorState | undefined {
    const existing = this.map.get(ip);
    if (existing) return existing;
    if (this.map.size >= this.cap) {
      this.overflowed = true;
      return undefined;
    }
    const fresh = newIpBehaviorState(this.windowSeconds);
    this.map.set(ip, fresh);
    return fresh;
  }
  get trackedCount(): number {
    return this.map.size;
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
  // ── behavioral aggregation ─────────────────────────────────────────────
  ipStates: BoundedIpStates;
  authFailures: number;
  authSuccessAfterFailure: number;
  windowSeconds: number;
  // ── secret/PII leak findings ───────────────────────────────────────────
  secretCountByFile: Map<string, number>;
  secretOverflowByFile: Map<string, number>;
  emailHashesByFile: Map<string, Set<string>>;
}

function newState(maxLines: number, windowSeconds: number): RunState {
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
    ipStates: new BoundedIpStates(MAX_TRACKED_IPS, windowSeconds),
    authFailures: 0,
    authSuccessAfterFailure: 0,
    windowSeconds,
    secretCountByFile: new Map(),
    secretOverflowByFile: new Map(),
    emailHashesByFile: new Map(),
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

// ── secret/PII leak findings ─────────────────────────────────────────────────

const SECRET_KIND_SET = new Set(SECRET_PATTERNS.map((p) => p.kind)); // vs PII_PATTERNS — decides severity below
const EMAIL_PATTERN = PII_PATTERNS.find((p) => p.kind === "email")!.re;

function addLeakFinding(state: RunState, kind: string, relPath: string, lineNo: number, evidence: string): void {
  const cur = state.secretCountByFile.get(relPath) ?? 0;
  if (cur >= SECRET_FILE_CAP) {
    state.secretOverflowByFile.set(relPath, (state.secretOverflowByFile.get(relPath) ?? 0) + 1);
    return;
  }
  state.secretCountByFile.set(relPath, cur + 1);

  const severity: Severity = SECRET_KIND_SET.has(kind) ? "high" : "medium";
  const f = makeToolFinding({
    tool: "ultrasec",
    category: "logs",
    ident: `${SECRET_LEAK_KIND_PREFIX}${kind}:${relPath}:${lineNo}`,
    title: `Secret/PII leak in log — ${kind}`,
    severity,
    message: `A ${kind} value appears in the clear in this log line: ${evidence}`,
    file: relPath,
    line: lineNo,
    cwe: "CWE-532",
    confidence: "low",
  });
  if (f.sink) f.sink.kind = `${SECRET_LEAK_KIND_PREFIX}${kind}`;
  state.findings.push(f);
}

/** Distinct emails seen so far in ONE file, as SHA-256-derived hashes — never
 *  the raw address, even transiently (this run-scoped set outlives any one
 *  line/finding, so nothing PII-shaped should sit in it). Bounded by
 *  EMAIL_HASH_CAP; returns the (possibly capped) distinct count so far. */
function trackDistinctEmails(state: RunState, relPath: string, raw: string): number {
  let set = state.emailHashesByFile.get(relPath);
  if (!set) {
    set = new Set();
    state.emailHashesByFile.set(relPath, set);
  }
  // `String.match` resets a global regex's `lastIndex` to 0 before it runs (per
  // spec, same guarantee `redact()` documents), so reusing this shared RegExp
  // across every line in the run is safe.
  const matches = raw.match(EMAIL_PATTERN) ?? [];
  for (const email of matches) {
    if (set.size >= EMAIL_HASH_CAP) break;
    set.add(shortHash(email.toLowerCase()));
  }
  return set.size;
}

/**
 * Per-line secret/PII-leak detection. One `redact()` call gives both the
 * sanitized evidence text AND the set of kinds hit on this line — no second
 * pass needed. `email` is bulk-gated (see EMAIL_BULK_THRESHOLD): a ONE-PASS
 * streaming approximation, since this engine never buffers a file to look
 * ahead — lines seen before a file's distinct-email count crosses the
 * threshold are not retroactively flagged, only the line that crosses it and
 * everything after. Every other kind (secrets + Luhn-gated credit-card) fires
 * on first sight, capped at SECRET_FILE_CAP per file.
 */
function processSecrets(state: RunState, relPath: string, lineNo: number, ev: ParsedEvent, opts: AnalyzeOptions): void {
  const { redacted, hits } = redact(ev.raw);
  if (!hits.length) return;

  const evidenceSrc = opts.redact ? redacted : ev.raw;
  const evidence = truncateEvidence(evidenceSrc);

  // De-dup by kind on this line — a line with 3 emails still yields one
  // "email" leak finding for that line, not three.
  const kindsOnLine = new Set(hits.map((h) => h.kind));
  for (const kind of kindsOnLine) {
    if (kind === "email") {
      const distinctCount = trackDistinctEmails(state, relPath, ev.raw);
      if (distinctCount < EMAIL_BULK_THRESHOLD) continue; // one-off — not a bulk leak (yet)
    }
    addLeakFinding(state, kind, relPath, lineNo, evidence);
  }
}

// ── behavioral aggregation (per-IP, second detector layer) ──────────────────

export const KIND_BRUTE_FORCE = "brute-force";
export const KIND_CREDENTIAL_COMPROMISE = "credential-compromise";
export const KIND_REQUEST_BURST = "request-burst";
export const KIND_SCAN_BEHAVIOR = "scan-behavior";
export const KIND_RECON_HIT = "recon-hit";
/** Prefix every secret/PII-leak finding's `sink.kind` carries — `log-secret-<kind>`. */
export const SECRET_LEAK_KIND_PREFIX = "log-secret-";

function addBehaviorFinding(
  state: RunState,
  a: { kind: string; title: string; severity: Severity; message: string; relPath: string; lineNo: number; ip: string },
): void {
  const f = makeToolFinding({
    tool: "ultrasec",
    category: "logs",
    ident: `${a.kind}:${a.ip}:${a.relPath}`,
    title: a.title,
    severity: a.severity,
    message: a.message,
    file: a.relPath,
    line: a.lineNo,
    confidence: "low",
  });
  if (f.sink) f.sink.kind = a.kind;
  state.findings.push(f);
}

/**
 * Per-IP behavioral aggregation: brute-force auth attempts (+ a possible
 * credential-compromise follow-on), request bursts, and scan/recon→hit. One
 * finding per (IP, detector) per run — every tracker below stops accepting
 * new marks once its detector has fired (see SlidingWindowTracker's doc),
 * which is what keeps this "keep the strongest [i.e. first-qualifying]"
 * rather than re-firing on every subsequent qualifying window.
 */
function processBehavior(state: RunState, relPath: string, lineNo: number, ev: ParsedEvent, windowSeconds: number): void {
  if (!ev.ip) return;
  const mark: WindowMark = { idx: state.totalLines, tsMs: parseTsEpochMs(ev.ts), relPath, lineNo };
  const ipState = state.ipStates.get(ev.ip);
  const authKind = classifyAuthEvent(ev.raw);
  if (authKind === "auth-fail") state.authFailures++;

  // Request burst — every line carrying an ip counts.
  if (ipState && !ipState.burstFired) {
    const { count, oldest, usedLineProxy } = ipState.request.add(mark);
    if (count > REQUEST_BURST_THRESHOLD) {
      ipState.burstFired = true;
      ipState.request.clear();
      addBehaviorFinding(state, {
        kind: KIND_REQUEST_BURST,
        title: "Request burst",
        severity: "low",
        message: `Request burst: ${count} requests from ${ev.ip} within ${windowDescription(usedLineProxy, windowSeconds)} (starting at ${oldest.relPath}:${oldest.lineNo}) — possible recon/DoS indicator.`,
        relPath: oldest.relPath,
        lineNo: oldest.lineNo,
        ip: ev.ip,
      });
    }
  }

  // Error spike (401/403/404 scanning) — feeds recon→hit below via hadQualifyingErrorRun.
  if (ipState && !ipState.spikeFired && typeof ev.status === "number" && ERROR_SPIKE_STATUSES.has(ev.status)) {
    const { count, oldest, usedLineProxy } = ipState.error4xx.add(mark);
    if (count >= ERROR_SPIKE_THRESHOLD) {
      ipState.spikeFired = true;
      ipState.hadQualifyingErrorRun = true;
      ipState.error4xx.clear();
      addBehaviorFinding(state, {
        kind: KIND_SCAN_BEHAVIOR,
        title: "Scanning behavior",
        severity: "low",
        message: `Scanning behavior: ${count} 401/403/404 responses from ${ev.ip} within ${windowDescription(usedLineProxy, windowSeconds)} (starting at ${oldest.relPath}:${oldest.lineNo}).`,
        relPath: oldest.relPath,
        lineNo: oldest.lineNo,
        ip: ev.ip,
      });
    }
  }

  // Recon → hit: a 2xx on a probe-path AFTER this ip already qualified as scanning.
  if (ipState && ipState.hadQualifyingErrorRun && !ipState.reconHitFired && typeof ev.status === "number" && ev.status >= 200 && ev.status < 300) {
    const decoded = decodeOnce(ev.path);
    const probeTargets = [ev.path, decoded].filter((t): t is string => typeof t === "string");
    if (probeTargets.some((t) => PROBE_PATH_RE.test(t))) {
      ipState.reconHitFired = true;
      addBehaviorFinding(state, {
        kind: KIND_RECON_HIT,
        title: "Recon followed by hit",
        severity: "medium",
        message: `Recon followed by hit: ${ev.ip} scanned for sensitive paths, then got a 2xx on a sensitive path at ${relPath}:${lineNo} — confirm what was disclosed.`,
        relPath,
        lineNo,
        ip: ev.ip,
      });
    }
  }

  // Brute-force + possible credential compromise.
  if (authKind === "auth-fail" && ipState) {
    ipState.sawAnyAuthFail = true;
    if (!ipState.bruteForceFired) {
      const { count, oldest, usedLineProxy } = ipState.authFail.add(mark);
      if (count >= BRUTE_FORCE_FAIL_THRESHOLD) {
        ipState.bruteForceFired = true;
        ipState.hadQualifyingAuthRun = true;
        ipState.qualifyingAuthMark = oldest;
        ipState.authFail.clear();
        addBehaviorFinding(state, {
          kind: KIND_BRUTE_FORCE,
          title: "Brute-force authentication attempts",
          severity: "medium",
          message: `Brute-force pattern: ${count} failed auth attempts from ${ev.ip} within ${windowDescription(usedLineProxy, windowSeconds)} (starting at ${oldest.relPath}:${oldest.lineNo}).`,
          relPath: oldest.relPath,
          lineNo: oldest.lineNo,
          ip: ev.ip,
        });
      }
    }
  } else if (authKind === "auth-success" && ipState) {
    if (ipState.sawAnyAuthFail) state.authSuccessAfterFailure++;
    if (ipState.hadQualifyingAuthRun && !ipState.compromiseFired) {
      ipState.compromiseFired = true;
      const q = ipState.qualifyingAuthMark!;
      addBehaviorFinding(state, {
        kind: KIND_CREDENTIAL_COMPROMISE,
        title: "Possible credential compromise",
        severity: "high",
        message: `Possible credential compromise: ${ev.ip} had a qualifying brute-force run starting at ${q.relPath}:${q.lineNo}, followed by a successful authentication at ${relPath}:${lineNo}. needs-human: confirm this wasn't the legitimate user succeeding after mistyping a password before treating it as a compromise.`,
        relPath: q.relPath,
        lineNo: q.lineNo,
        ip: ev.ip,
      });
    }
  }
}

// One line's worth of work: update run stats, then every per-line detector.
function processEvent(state: RunState, relPath: string, lineNo: number, ev: ParsedEvent, opts: AnalyzeOptions): void {
  state.totalLines++;
  if (ev.ts) {
    if (state.firstTs === undefined) state.firstTs = ev.ts;
    state.lastTs = ev.ts;
  }
  if (ev.ip) state.ipCounter.add(ev.ip);
  // topPaths lands verbatim in LOGSTATS.json and --json stdout, so a raw
  // query-string secret counted here would republish exactly what the
  // secret/PII detector redacts everywhere else (CWE-532). When redaction is
  // on, count the REDACTED form of the path — a deliberate choice: two
  // distinct secrets on an otherwise-identical path template collapse into
  // one counted key, but that's strictly better than leaking either one, and
  // it keeps "same path, same bucket" for the common case (no secret on the
  // path at all, where redact() is a no-op).
  if (ev.path) state.pathCounter.add(opts.redact ? redact(ev.path).redacted : ev.path);
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

  processSecrets(state, relPath, lineNo, ev, opts);
  processBehavior(state, relPath, lineNo, ev, state.windowSeconds);
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
  const secretOverflow = state.secretOverflowByFile.get(relPath);
  if (secretOverflow) {
    state.truncation.push(`${relPath}: ${secretOverflow} further secret/PII leak hit(s) not emitted (per-file cap ${SECRET_FILE_CAP})`);
  }
  state.files.push({ path: relPath, lines: lineNo, format: fmt });
}

export async function analyzeLogs(paths: string[], opts: AnalyzeOptions): Promise<AnalyzeResult> {
  const maxLines = opts.maxLines ?? BUDGETS[opts.budget];
  const windowSeconds = opts.windowSec ?? DEFAULT_WINDOW_SECONDS;
  const state = newState(maxLines, windowSeconds);

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
  if (state.ipStates.overflowed) {
    state.truncation.push(
      `behavioral aggregation: distinct-IP cap (${MAX_TRACKED_IPS.toLocaleString("en-US")}) reached — brute-force/burst/recon detection was skipped for IPs beyond the cap`,
    );
  }

  const stats: LogStats = {
    files: state.files,
    topIps: state.ipCounter.top(TOP_N).map(({ key, count }) => ({ ip: key, count })),
    topPaths: state.pathCounter.top(TOP_N).map(({ key, count }) => ({ path: key, count })),
    statusCounts: state.statusCounts,
    ...(state.firstTs !== undefined ? { firstTs: state.firstTs } : {}),
    ...(state.lastTs !== undefined ? { lastTs: state.lastTs } : {}),
    totalLines: state.totalLines,
    authFailures: state.authFailures,
    authSuccessAfterFailure: state.authSuccessAfterFailure,
    distinctIpsSeen: state.ipStates.trackedCount,
    distinctIpsOverflowed: state.ipStates.overflowed,
  };

  return { findings: state.findings, stats, truncation: state.truncation };
}
