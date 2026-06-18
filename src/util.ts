import { createHash } from "node:crypto";

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
  "offline",
  "no-enrich",
  "no-tools",
  "docker",
  "dry-run",
  "blame",
  "provenance",
  "sinks",
  "merge",
  "resume",
  "powered",
  "no-scan",
  "gitignore",
  "semantic",
  "keep-output",
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
    if (Object.prototype.hasOwnProperty.call(flags, key)) {
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
  const parts = raw.flatMap((x) => (typeof x === "string" ? x.split(",") : [])).map((s) => s.trim()).filter(Boolean);
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
  return obj != null && Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

/** Short, stable content hash for deriving idempotent ids. */
export function shortHash(input: string, len = 12): string {
  return createHash("sha256").update(input).digest("hex").slice(0, len);
}

/** Deterministic string compare (locale-independent), for stable ordering. */
export function byStr(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function eprintln(msg: string): void {
  process.stderr.write(msg + "\n");
}

export function println(msg: string): void {
  process.stdout.write(msg + "\n");
}
