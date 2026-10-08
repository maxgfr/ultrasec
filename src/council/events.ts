import { finalTextFrom, type ReviewerSpec } from "./reviewers.js";
import { COVERAGE_HEADING } from "./locale.js";

// Reading what a reviewer CLI printed: its report, its session, what it cost,
// and — above all — WHY it stopped when it stopped without a report.
//
// The distinction matters because each cause has a different cure. A run cut
// by our own budget or timeout is resumed on the SAME model for one closing
// turn: the context is already paid for and the report costs cents. A quota or
// credit stop cannot be resumed on the same model until the quota resets, so it
// goes to the `--fallback` list. A transient error (a gateway 504, a reset
// connection) is neither: the next fallback simply gets a turn. On the audit
// this was built from, one reviewer was cut at its cap holding nothing but
// progress notes, and the whole run would have been lost without the one-turn
// resume.
//
// Everything CLI-specific — where the session id, the usage and the text sit in
// an event, which phrases a provider uses for its stops — comes from the
// reviewer's spec (`reviewers.ts`). What is here is generic.

export type FailureKind = "quota" | "credit" | "transient" | "error";

export interface Failure {
  kind: FailureKind;
  message: string;
  /** A reset time the provider announced, verbatim (`2026-10-09 01:52:02`). */
  resetAt?: string;
}

export interface Usage {
  /** False when the CLI does not print usage at all. */
  exposed: boolean;
  input: number;
  output: number;
  reasoning: number;
  cacheRead: number;
  cacheWrite: number;
  /** USD, as the CLI reported it. */
  cost: number;
  steps: number;
}

export interface Digest {
  session?: string;
  usage: Usage;
  /** The reviewer's final answer — the report. */
  text: string;
  failure?: Failure;
  toolCalls: number;
}

export function emptyUsage(exposed: boolean): Usage {
  return { exposed, input: 0, output: 0, reasoning: 0, cacheRead: 0, cacheWrite: 0, cost: 0, steps: 0 };
}

export function addUsage(a: Usage, b: Usage): Usage {
  return {
    exposed: a.exposed || b.exposed,
    input: a.input + b.input,
    output: a.output + b.output,
    reasoning: a.reasoning + b.reasoning,
    cacheRead: a.cacheRead + b.cacheRead,
    cacheWrite: a.cacheWrite + b.cacheWrite,
    cost: Math.round((a.cost + b.cost) * 1e6) / 1e6,
    steps: a.steps + b.steps,
  };
}

// ── Stop detection ─────────────────────────────────────────────────────────

/**
 * Generic phrasings of provider stops. `[ _-]` separators so a snake_case
 * error code (`insufficient_quota`) reads like its prose. Credit is checked
 * before quota: "insufficient quota" is money, not a rate, and a credit stop is
 * not cured by waiting.
 */
const CREDIT =
  /insufficient[ _-](?:credits?|balance|funds|quota)|out[ _-]of[ _-]credits?|\b(?:low|no)[ _-]credits?\b|credits?[ _-](?:exhausted|depleted)|balance[ _-](?:exhausted|too[ _-]low)|payment[ _-]required/i;
const QUOTA = /usage[ _-]limit|rate[ _-]?limit|quota|too[ _-]many[ _-]requests|limit (?:will )?resets?\b/i;
const TRANSIENT =
  /time[ _-]?d?[ _-]?out|gateway|service[ _-]unavailable|temporarily[ _-]unavailable|overloaded|ECONNRESET|ETIMEDOUT|ECONNREFUSED|EAI_AGAIN|socket hang up/i;
/** HTTP statuses — read only in a STRUCTURED error (an error event, a failed exit), never in prose. */
const CODES: readonly [FailureKind, RegExp][] = [
  ["credit", /\b402\b/],
  ["quota", /\b429\b/],
  ["transient", /\b(?:50[234]|529)\b/],
];
/**
 * What is worth stopping a run for in an UNSTRUCTURED stream (a text CLI's
 * stderr, which can echo the transcript): explicit stop phrases only. A review
 * of a login form talks about rate limits; a quoted `429` is a line number.
 */
const STOP_PHRASES =
  /usage[ _-]limit[ _-](?:reached|exceeded)|quota[ _-](?:exceeded|reached|exhausted)|limit will reset|insufficient[ _-](?:credits?|balance|funds|quota)|out[ _-]of[ _-]credits?|payment[ _-]required/i;
/** A date-time anywhere in a stop message: the reset the provider announced. */
const DATE_TIME = /\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b/;

export interface Detector {
  credit: RegExp[];
  quota: RegExp[];
  transient: RegExp[];
}

const compile = (ps: readonly string[] | undefined): RegExp[] => (ps ?? []).map((p) => new RegExp(p, "i"));

/** A reviewer's own phrasings, checked before the generic ones. */
export function detectorFor(spec: Pick<ReviewerSpec, "creditPatterns" | "quotaPatterns" | "transientPatterns"> | undefined): Detector {
  return { credit: compile(spec?.creditPatterns), quota: compile(spec?.quotaPatterns), transient: compile(spec?.transientPatterns) };
}

/**
 * Classify an error text. `structured` is true when the text is known to be an
 * error (an error event, the output of a failed exit) — only then do bare HTTP
 * statuses count.
 */
export function classifyFailure(message: string, detector: Detector = detectorFor(undefined), structured = true): Failure {
  const m = message.slice(0, 2000);
  const tiers: [FailureKind, RegExp[]][] = [
    ["credit", detector.credit],
    ["quota", detector.quota],
    ["transient", detector.transient],
    ["credit", [CREDIT]],
    ["quota", [QUOTA]],
    ["transient", [TRANSIENT]],
    ...(structured ? CODES.map(([k, re]): [FailureKind, RegExp[]] => [k, [re]]) : []),
  ];
  const kind = tiers.find(([, res]) => res.some((re) => re.test(m)))?.[0] ?? "error";
  const resetAt = kind === "quota" || kind === "credit" ? m.match(DATE_TIME)?.[0] : undefined;
  return { kind, message: m.replace(/\s+/g, " ").trim().slice(0, 300), ...(resetAt ? { resetAt } : {}) };
}

/** Is this unstructured line a provider stop? Generic phrases, or the reviewer's own patterns. */
function isStopLine(line: string, d: Detector): boolean {
  return STOP_PHRASES.test(line) || [...d.credit, ...d.quota].some((re) => re.test(line));
}

// ── JSON paths ─────────────────────────────────────────────────────────────

/** Read a dotted path (`part.tokens.cache.read`) from a parsed JSON value. */
export function getPath(obj: unknown, path: string | undefined): unknown {
  if (!path) return undefined;
  let cur: unknown = obj;
  for (const key of path.split(".")) {
    if (!cur || typeof cur !== "object" || !Object.hasOwn(cur, key)) return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}

const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

function parseLine(line: string): Record<string, unknown> | undefined {
  try {
    const v = JSON.parse(line) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
  } catch {
    return undefined; // a stray log line is not an event
  }
}

/** The error an event carries, as text, if any. */
function eventError(spec: ReviewerSpec, ev: Record<string, unknown>): string | undefined {
  const p = spec.eventPaths ?? {};
  const payload = (p.errors ?? []).map((path) => getPath(ev, path)).find((v) => v !== undefined && v !== null && v !== false);
  if (p.errorType && getPath(ev, p.type ?? "type") === p.errorType) return JSON.stringify(payload ?? ev);
  return payload !== undefined ? JSON.stringify(payload) : undefined;
}

const sessionOf = (spec: ReviewerSpec, ev: unknown): string | undefined =>
  (spec.sessionIdPath ?? []).map((p) => str(getPath(ev, p))).find((s): s is string => !!s);

function readUsage(spec: ReviewerSpec, ev: unknown, into: Usage): void {
  const u = spec.usagePaths ?? {};
  into.input += num(getPath(ev, u.input));
  into.output += num(getPath(ev, u.output));
  into.reasoning += num(getPath(ev, u.reasoning));
  into.cacheRead += num(getPath(ev, u.cacheRead));
  into.cacheWrite += num(getPath(ev, u.cacheWrite));
  into.cost = Math.round((into.cost + num(getPath(ev, u.cost))) * 1e6) / 1e6;
  into.steps += u.steps ? num(getPath(ev, u.steps)) : 1;
}

/**
 * Inspect one output line as it arrives: what the watcher needs to decide to
 * stop. JSON-event CLIs are read on stdout (their error and step events); text
 * CLIs only on stderr — their stdout is the report, and a report quoting "429"
 * must not be mistaken for a rate limit.
 */
export function watchLine(spec: ReviewerSpec, stream: "stdout" | "stderr", line: string): { cost?: number; failure?: Failure } {
  const d = detectorFor(spec);
  if (spec.events === "jsonl-steps" || spec.events === "jsonl") {
    if (stream !== "stdout") return {};
    const ev = parseLine(line);
    if (!ev) return {};
    const err = eventError(spec, ev);
    if (err) return { failure: classifyFailure(err, d) };
    const p = spec.eventPaths ?? {};
    if (spec.events === "jsonl-steps" && p.stepType && getPath(ev, p.type ?? "type") === p.stepType) return { cost: num(getPath(ev, spec.usagePaths?.cost)) };
    return {};
  }
  if (stream === "stderr" && isStopLine(line, d)) return { failure: classifyFailure(line, d, false) };
  return {};
}

/**
 * Digest a `jsonl-steps` stream. The report is the text of the LAST message
 * that produced text: text parts of earlier messages are the agent narrating
 * its exploration ("let me read the router…"), and concatenating them buried
 * the report on every real run.
 */
function digestSteps(spec: ReviewerSpec, raw: string): Digest {
  const p = spec.eventPaths ?? {};
  const typeOf = (ev: unknown): unknown => getPath(ev, p.type ?? "type");
  const usage = emptyUsage(true);
  let session: string | undefined;
  let failure: Failure | undefined;
  let toolCalls = 0;
  const textByMessage = new Map<string, string[]>();
  let lastTextMessage: string | undefined;
  const d = detectorFor(spec);

  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    const ev = parseLine(line);
    if (!ev) continue;
    session ??= sessionOf(spec, ev);
    const err = eventError(spec, ev);
    if (err) failure = classifyFailure(err, d);
    const type = typeOf(ev);
    if (p.stepType && type === p.stepType) readUsage(spec, ev, usage);
    else if (p.toolType && type === p.toolType) toolCalls++;
    else if (p.textType && type === p.textType) {
      const text = str(getPath(ev, p.text));
      if (!text) continue;
      const msg = str(getPath(ev, p.messageId)) ?? "_";
      const arr = textByMessage.get(msg) ?? textByMessage.set(msg, []).get(msg)!;
      arr.push(text);
      lastTextMessage = msg;
    }
  }
  const text = lastTextMessage ? (textByMessage.get(lastTextMessage) ?? []).join("\n") : "";
  // A run that went on to produce its report after a transient error did not fail.
  const failed = failure && !isContractShaped(text) ? failure : undefined;
  return { ...(session ? { session } : {}), usage, text, ...(failed ? { failure: failed } : {}), toolCalls };
}

/** Digest a `jsonl` CLI: one result object, the last JSON line on stdout. */
function digestResult(spec: ReviewerSpec, raw: string): Digest {
  const usage = emptyUsage(true);
  const p = spec.eventPaths ?? {};
  for (const line of raw.trim().split("\n").reverse()) {
    const obj = parseLine(line);
    if (!obj) continue;
    readUsage(spec, obj, usage);
    const text = str(getPath(obj, p.text)) ?? "";
    const session = sessionOf(spec, obj);
    const failure = getPath(obj, p.errorFlag) === true ? classifyFailure(text || JSON.stringify(obj), detectorFor(spec)) : undefined;
    return { ...(session ? { session } : {}), usage, text: failure ? "" : text, ...(failure ? { failure } : {}), toolCalls: 0 };
  }
  return { usage, text: "", toolCalls: 0 };
}

/**
 * Digest one invocation. `fileText` is what the CLI wrote to `{outFile}`, for
 * a reviewer whose report is read from a file.
 */
export function digest(spec: ReviewerSpec, stdout: string, stderr: string, exitCode: number | null, fileText?: string): Digest {
  const d = detectorFor(spec);
  const exposed = !!spec.usagePaths && Object.keys(spec.usagePaths).length > 0;
  let out: Digest;
  if (spec.events === "jsonl-steps") out = digestSteps(spec, stdout);
  else if (spec.events === "jsonl") out = digestResult(spec, stdout);
  else out = { usage: emptyUsage(false), text: "", toolCalls: 0 };
  out.usage.exposed = exposed;

  const from = finalTextFrom(spec);
  if (from === "stdout") out.text = stdout.trim();
  else if (from === "file") out.text = (fileText ?? "").trim();

  if (!out.failure) {
    if (exitCode !== 0 && !isContractShaped(out.text)) out.failure = classifyFailure(stderr || (spec.events === "text" ? stdout : "") || `exit ${exitCode}`, d);
    else if (exitCode === 0 && !isContractShaped(out.text) && isStopLine(stderr, d)) out.failure = classifyFailure(stderr, d, false);
  }
  return out;
}

/**
 * Does this text look like the report the brief asked for — at least one
 * `### <ID> — <title>` block, or a coverage section (in any locale)? A clean
 * "nothing found" report still has the coverage section, so it counts;
 * progress notes do not.
 */
export function isContractShaped(text: string): boolean {
  return /^###\s+\S+/m.test(text) || COVERAGE_HEADING.test(text);
}
