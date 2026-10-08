import type { EventFormat } from "./adapters.js";

// Reading what a reviewer CLI printed: its report, its session, what it cost,
// and — above all — WHY it stopped when it stopped without a report.
//
// The distinction matters because each cause has a different cure. A run cut
// by our own budget or timeout is resumed on the SAME model for one closing
// turn: the context is already paid for and the report costs cents. A quota or
// credit stop cannot be resumed on the same model until the quota resets, so it
// goes to the `--fallback` list. A 504 from a free model's upstream is neither:
// the next fallback simply gets a turn. On the audit this was built from, one
// reviewer was cut at its cap holding nothing but progress notes, and the
// whole run would have been lost without the one-turn resume.

export type FailureKind = "quota" | "credit" | "upstream" | "error";

export interface Failure {
  kind: FailureKind;
  message: string;
  /** When the provider said the quota resets, verbatim (`2026-10-09 01:52:02`). */
  resetAt?: string;
}

export interface Usage {
  /** False when the CLI does not print usage at all (vibe, codex). */
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

// Order matters: kilo's credit exhaustion is spelled `usage_limit_exceeded`,
// which the quota pattern would otherwise claim — and a credit stop is not cured
// by waiting.
const CREDIT = /usage_limit_exceeded|low credit|insufficient (?:credit|balance|funds)|out of credits?|payment required|\b402\b/i;
const QUOTA = /usage limit reached|limit will reset|rate[ _-]?limit|quota|too many requests|\b1308\b|\b429\b/i;
const UPSTREAM = /upstream idle timeout|gateway time-?out|bad gateway|service unavailable|overloaded|\b50[234]\b/i;
const RESET_AT = /reset (?:at|on)\s+(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)/i;

/** Classify an error text. Every string here came from a real run. */
export function classifyFailure(message: string): Failure {
  const m = message.slice(0, 2000);
  const resetAt = m.match(RESET_AT)?.[1];
  const kind: FailureKind = CREDIT.test(m) ? "credit" : QUOTA.test(m) ? "quota" : UPSTREAM.test(m) ? "upstream" : "error";
  return { kind, message: m.replace(/\s+/g, " ").trim().slice(0, 300), ...(resetAt ? { resetAt } : {}) };
}

const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

/** The error carried by one opencode/kilo event line, if any, as text. */
function eventError(ev: Record<string, unknown>): string | undefined {
  if (ev.type === "error") return JSON.stringify(ev.error ?? ev.part ?? ev);
  const part = ev.part as Record<string, unknown> | undefined;
  if (part?.error) return JSON.stringify(part.error);
  return undefined;
}

/** Provider stops spelled out in prose — the only stderr lines of a text CLI
 *  worth stopping a run for. Deliberately narrower than QUOTA: a bare `429` on a
 *  report line is a line number, not a rate limit. */
const PROSE_STOP = /usage limit reached|limit will reset|usage_limit_exceeded|low credit|insufficient (?:credit|balance|funds)/i;

/**
 * Inspect one output line as it arrives: what the watcher needs to decide to
 * stop. Event CLIs are read on stdout (their error events); text CLIs only on
 * stderr — their stdout is the report, and a report quoting "429" must not be
 * mistaken for a rate limit.
 */
export function watchLine(format: EventFormat, stream: "stdout" | "stderr", line: string): { cost?: number; failure?: Failure } {
  if (format === "opencode-json") {
    if (stream !== "stdout") return {};
    let ev: Record<string, unknown>;
    try {
      ev = JSON.parse(line) as Record<string, unknown>;
    } catch {
      return {};
    }
    const err = eventError(ev);
    if (err) return { failure: classifyFailure(err) };
    if (ev.type === "step_finish") return { cost: num((ev.part as Record<string, unknown> | undefined)?.cost) };
    return {};
  }
  if (stream === "stderr" && PROSE_STOP.test(line)) return { failure: classifyFailure(line) };
  return {};
}

/**
 * Digest an opencode/kilo `--format json` stream: one JSON event per line, with
 * `type` among step_start / step_finish / text / tool_use / error.
 *
 * The report is the text of the LAST message that produced text. Text parts of
 * earlier messages are the agent narrating its exploration ("let me read the
 * router…"), and concatenating them buried the report on every real run.
 */
export function digestOpencode(raw: string): Digest {
  const usage = emptyUsage(true);
  let session: string | undefined;
  let failure: Failure | undefined;
  let toolCalls = 0;
  const textByMessage = new Map<string, string[]>();
  let lastTextMessage: string | undefined;

  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    let ev: Record<string, unknown>;
    try {
      ev = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue; // a stray log line is not an event
    }
    const part = (ev.part ?? {}) as Record<string, unknown>;
    session ??= str(ev.sessionID) ?? str(part.sessionID);
    const err = eventError(ev);
    if (err) failure = classifyFailure(err);
    switch (ev.type) {
      case "step_finish": {
        const t = (part.tokens ?? {}) as Record<string, unknown>;
        const cache = (t.cache ?? {}) as Record<string, unknown>;
        usage.input += num(t.input);
        usage.output += num(t.output);
        usage.reasoning += num(t.reasoning);
        usage.cacheRead += num(cache.read);
        usage.cacheWrite += num(cache.write);
        usage.cost = Math.round((usage.cost + num(part.cost)) * 1e6) / 1e6;
        usage.steps++;
        break;
      }
      case "text": {
        const text = str(part.text);
        if (!text) break;
        const msg = str(part.messageID) ?? "_";
        const arr = textByMessage.get(msg) ?? textByMessage.set(msg, []).get(msg)!;
        arr.push(text);
        lastTextMessage = msg;
        break;
      }
      case "tool_use":
        toolCalls++;
        break;
    }
  }
  const text = lastTextMessage ? (textByMessage.get(lastTextMessage) ?? []).join("\n") : "";
  // A run that went on to produce its report after a transient error did not fail.
  const failed = failure && !isContractShaped(text) ? failure : undefined;
  return { ...(session ? { session } : {}), usage, text, ...(failed ? { failure: failed } : {}), toolCalls };
}

/** Digest `claude -p --output-format json`: one result object, last on stdout. */
export function digestClaude(raw: string): Digest {
  const usage = emptyUsage(true);
  const lines = raw.trim().split("\n").reverse();
  for (const line of lines) {
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    const u = (obj.usage ?? {}) as Record<string, unknown>;
    usage.input = num(u.input_tokens);
    usage.output = num(u.output_tokens);
    usage.cacheRead = num(u.cache_read_input_tokens);
    usage.cacheWrite = num(u.cache_creation_input_tokens);
    usage.cost = num(obj.total_cost_usd);
    usage.steps = num(obj.num_turns);
    const text = str(obj.result) ?? "";
    const session = str(obj.session_id);
    const failure = obj.is_error === true ? classifyFailure(text || String(obj.subtype ?? "error")) : undefined;
    return { ...(session ? { session } : {}), usage, text: failure ? "" : text, ...(failure ? { failure } : {}), toolCalls: 0 };
  }
  return { usage, text: "", toolCalls: 0 };
}

/** Digest a text CLI: stdout IS the report; usage is not exposed. */
export function digestText(stdout: string, stderr: string, exitCode: number | null): Digest {
  const failure =
    exitCode !== 0
      ? classifyFailure(stderr || stdout || `exit ${exitCode}`)
      : !isContractShaped(stdout) && PROSE_STOP.test(stderr)
        ? classifyFailure(stderr)
        : undefined;
  return { usage: emptyUsage(false), text: stdout.trim(), ...(failure ? { failure } : {}), toolCalls: 0 };
}

export function digest(format: EventFormat, stdout: string, stderr: string, exitCode: number | null): Digest {
  if (format === "opencode-json") {
    const d = digestOpencode(stdout);
    if (!d.failure && exitCode !== 0 && !isContractShaped(d.text)) d.failure = classifyFailure(stderr || `exit ${exitCode}`);
    return d;
  }
  if (format === "claude-json") {
    const d = digestClaude(stdout);
    if (!d.failure && exitCode !== 0 && !d.text) d.failure = classifyFailure(stderr || `exit ${exitCode}`);
    return d;
  }
  return digestText(stdout, stderr, exitCode);
}

/**
 * Does this text look like the report the brief asked for — at least one
 * `### <ID> — <title>` block, or a coverage section? A clean "nothing found"
 * report still has the coverage section, so it counts; progress notes do not.
 */
export function isContractShaped(text: string): boolean {
  return /^###\s+\S+/m.test(text) || /^##\s+(?:C\.\s*)?(?:Coverage|Couverture)\b/im.test(text);
}
