import { AsyncLocalStorage } from "node:async_hooks";
import { createHash } from "node:crypto";
import { statSync } from "node:fs";

// ── Tiny zero-dependency arg parser ──────────────────────────────────────────
// Supports: positionals, `--flag value`, `--flag=value`, boolean `--flag`, and
// single-dash short flags (`-h`, `-v`, bundled `-hv`).
// A long flag is boolean when it is in BOOLEAN_FLAGS, or is immediately followed
// by another flag token / nothing. Listing a value-less flag in BOOLEAN_FLAGS is
// what stops it from greedily swallowing a following positional — e.g. so
// `dossier --json <id>` keeps `<id>` as a positional instead of `--json`'s value.
/** A single flag occurrence; repeated flags accumulate into an array. */
export type FlagValue = string | boolean | (string | boolean)[];

export interface ParsedArgs {
  /** Positional arguments, in order (the first is usually the sub-command). */
  _: string[];
  /** Named flags. Boolean flags are `true`; valued flags are strings; a flag
   *  passed more than once becomes an array of its occurrences. */
  flags: Record<string, FlagValue>;
}

/**
 * Value-less (boolean) flags: they set `true` and NEVER consume the next token,
 * so a positional after them isn't swallowed (the `dossier --json <id>` class of
 * bug). MUST stay in sync with every flag read via `flagBool()`.
 */
export const BOOLEAN_FLAGS: ReadonlySet<string> = new Set([
  "help",
  "version",
  "json",
  "quiet",
  "offline",
  "no-enrich",
  "no-tools",
  "docker",
  "dry-run",
  "upgrade",
  "blame",
  "provenance",
  "sinks",
  "log-hygiene",
  "merge",
  "resume",
  "powered",
  "no-scan",
  "gitignore",
  "semantic",
  "keep-output",
  "all",
  "eco",
  "list",
  "no-redact",
  "strict",
  "no-context",
  "compact",
  "include-tests",
  "include-vendored",
  "re-verdict",
  "no-journal",
  "no-env-sources",
  "strict-scope",
  "write",
  "sigma",
  // `mcp` only.
  "allow-remote",
  "allow-write",
  // `probe` only.
  "i-own-this",
  "allow-private",
  "deep",
  "graphql",
]);

/** Single-dash short-flag aliases, as documented in the CLI's GLOBAL help. Each
 *  maps to the long flag it stands for; an unknown letter becomes its own boolean. */
const SHORT_FLAGS: Record<string, string> = { h: "help", v: "version" };

export function parseArgs(argv: string[]): ParsedArgs {
  const _: string[] = [];
  // Null-prototype so a flag literally named like an Object.prototype member
  // ("--constructor", "--toString") can't return an inherited value on lookup.
  const flags: Record<string, FlagValue> = Object.create(null);
  // Repeated flags accumulate (e.g. `--scope a --scope b`) instead of last-wins,
  // so a multi-value flag is never silently narrowed.
  const set = (key: string, val: string | boolean): void => {
    if (Object.hasOwn(flags, key)) {
      const cur = flags[key]!;
      if (Array.isArray(cur)) cur.push(val);
      else flags[key] = [cur, val];
    } else {
      flags[key] = val;
    }
  };
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i]!;
    if (tok.startsWith("--")) {
      const body = tok.slice(2);
      const eq = body.indexOf("=");
      if (eq >= 0) {
        set(body.slice(0, eq), body.slice(eq + 1));
        continue;
      }
      const next = argv[i + 1];
      if (!BOOLEAN_FLAGS.has(body) && next !== undefined && !next.startsWith("--")) {
        set(body, next);
        i++;
      } else {
        set(body, true);
      }
    } else if (/^-[A-Za-z]+$/.test(tok)) {
      // Single-dash short flag(s), e.g. `-h`, `-v`, bundled `-hv`. Always boolean;
      // each letter resolves to its long-name alias when known, else to itself.
      for (const ch of tok.slice(1)) set(SHORT_FLAGS[ch] ?? ch, true);
    } else {
      _.push(tok);
    }
  }
  return { _, flags };
}

/** Read a flag as a string, or `undefined` if absent / boolean-only. For a repeated
 *  flag, the LAST string occurrence wins (conventional single-value semantics). */
export function flagStr(args: ParsedArgs, name: string): string | undefined {
  const v = args.flags[name];
  if (Array.isArray(v)) {
    for (let i = v.length - 1; i >= 0; i--) if (typeof v[i] === "string") return v[i] as string;
    return undefined;
  }
  return typeof v === "string" ? v : undefined;
}

/** Read a flag as a boolean (presence, or `--flag=true`). */
export function flagBool(args: ParsedArgs, name: string): boolean {
  const v = args.flags[name];
  if (Array.isArray(v)) return v.some((x) => x === true || x === "true");
  return v === true || v === "true";
}

/** Read a flag as a trimmed string list — merges every occurrence of the flag AND
 *  the comma-separated form (so `--scope a --scope b` and `--scope a,b` both work). */
export function listFlag(args: ParsedArgs, name: string): string[] | undefined {
  const v = args.flags[name];
  if (v === undefined) return undefined;
  const raw = Array.isArray(v) ? v : [v];
  const parts = raw
    .flatMap((x) => (typeof x === "string" ? x.split(",") : []))
    .map((s) => s.trim())
    .filter(Boolean);
  return parts.length ? parts : undefined;
}

/** Read a flag as a finite number (or `undefined` if absent / unparseable). */
export function numFlag(args: ParsedArgs, name: string): number | undefined {
  const v = flagStr(args, name);
  if (v === undefined) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

/** Prototype-safe lookup on a string-keyed record: returns the value only if it is
 *  an OWN property, so a key equal to an Object.prototype member ("constructor",
 *  "toString", "valueOf", …) can never return an inherited function. */
export function own<T>(obj: Record<string, T> | null | undefined, key: string): T | undefined {
  return obj != null && Object.hasOwn(obj, key) ? obj[key] : undefined;
}

/**
 * Is this path a directory we can actually walk? The single definition of
 * "scannable repo", shared by every command that takes `--repo`, so a
 * mistyped path fails identically everywhere instead of walking zero files
 * and reporting a clean audit.
 */
export function isScannableDir(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false; // missing, or a permission error we can't walk through
  }
}

/** Short, stable content hash for deriving idempotent ids. */
export function shortHash(input: string, len = 12): string {
  return createHash("sha256").update(input).digest("hex").slice(0, len);
}

/** Deterministic string compare (locale-independent), for stable ordering. */
export function byStr(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

// ── Finding message stage notes ──────────────────────────────────────────────
// `verify --apply` and `revalidate --apply` each append a trailing block to a
// finding's `message`. Both used to append unconditionally, so re-applying the
// same file grew the message every time — on a real audit run every one of 265
// findings carried a duplicated block, one carried four, and that is what
// inflated REPORT.md to 413 KB. An apply must be idempotent: folding the same
// verdicts twice has to leave the dossier byte-identical.

/** Stage labels allowed to append a trailing note block to a finding message. */
const STAGE_LABELS = ["Verdict", "Revalidation"] as const;
const STAGE_SPLIT = new RegExp(`\\n\\n(?=(?:${STAGE_LABELS.join("|")}) \\()`);

/**
 * Append `stage`'s note to a finding message, REPLACING that stage's previous
 * note rather than stacking a second copy.
 *
 * Other stages' blocks are preserved: a revalidation note must survive a
 * re-verify, and a verdict note must survive a re-revalidation. Within one
 * stage it is last-wins, which is what makes a repeated `--apply` a no-op.
 */
export function withStageNote(message: string, stage: (typeof STAGE_LABELS)[number], label: string, note?: string): string {
  // parts[0] is the text before the first stage block; every later part IS one.
  const parts = message.split(STAGE_SPLIT);
  const kept = parts.filter((part, i) => i === 0 || !part.startsWith(`${stage} (`));
  return `${kept.join("\n\n")}\n\n${stage} (${label})${note ? `: ${note}` : ""}`;
}

/**
 * The stage blocks a message carries — the ADJUDICATION, separated from the
 * engine's own prose.
 *
 * `withStageNote` appends "Verdict (refuted): <the auditor's argument>" to a
 * finding's message, so the reasoning that decides an audit lives inside a field
 * that also holds boilerplate. Anything that compacts a finding for display has
 * to be able to tell the two apart, or it drops the half that took the work: a
 * 1041-finding refuted tier held **384 distinct arguments**, and a table showing
 * only the named ground hid every one of them.
 *
 * Returns "" when the finding was never adjudicated.
 */
export function stageNotes(message: string | undefined | null): string {
  const parts = String(message ?? "").split(STAGE_SPLIT);
  return parts.slice(1).join(" · ").trim();
}

// ── Output sink ──────────────────────────────────────────────────────────────
// The commands print their results. That is right for a CLI and fatal for the
// MCP server, whose stdout carries JSON-RPC frames and nothing else — a single
// stray line there corrupts the stream for the rest of the session.
//
// So the sink is injectable, scoped with AsyncLocalStorage rather than a module
// variable. That distinction is the whole point: a command is async, so two
// tool calls interleave, and a global sink would land one command's output in
// the other's buffer. ALS follows the async context instead, so each capture
// collects exactly its own call.
//
// With no store — every CLI invocation — this is the same direct write it
// always was.
interface OutputSink {
  out: string[];
  err: string[];
  /** Also write through to the real streams (`--report` archives, never diverts). */
  tee?: boolean;
}

const outputSink = new AsyncLocalStorage<OutputSink>();

export function eprintln(msg: string): void {
  const sink = outputSink.getStore();
  if (sink) {
    sink.err.push(msg);
    if (!sink.tee) return;
  }
  process.stderr.write(msg + "\n");
}

export function println(msg: string): void {
  const sink = outputSink.getStore();
  if (sink) {
    sink.out.push(msg);
    if (!sink.tee) return;
  }
  process.stdout.write(msg + "\n");
}

export interface Captured<T> {
  result: T;
  stdout: string;
  stderr: string;
}

// Run `fn` with everything it prints collected instead of written. Used by the
// MCP server to turn a command's printed result into a tool result.
export async function captureOutput<T>(fn: () => T | Promise<T>): Promise<Captured<T>> {
  const sink: OutputSink = { out: [], err: [] };
  const result = await outputSink.run(sink, async () => await fn());
  return { result, stdout: sink.out.join("\n"), stderr: sink.err.join("\n") };
}

// Same collection, but the streams still receive everything — the shape
// `--report` and JOURNAL.md need, where the archive is ADDITIVE and a user
// watching the terminal must see exactly what they saw before.
export async function teeOutput<T>(fn: () => T | Promise<T>): Promise<Captured<T>> {
  const sink: OutputSink = { out: [], err: [], tee: true };
  const result = await outputSink.run(sink, async () => await fn());
  return { result, stdout: sink.out.join("\n"), stderr: sink.err.join("\n") };
}
