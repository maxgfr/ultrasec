import { createHash } from "node:crypto";

// ── Tiny zero-dependency arg parser ──────────────────────────────────────────
// Supports: positionals, `--flag value`, `--flag=value`, and boolean `--flag`.
// A flag immediately followed by another `--token` (or nothing) is boolean.
export interface ParsedArgs {
  /** Positional arguments, in order (the first is usually the sub-command). */
  _: string[];
  /** Named flags. Boolean flags are `true`; valued flags are strings. */
  flags: Record<string, string | boolean>;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const _: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i]!;
    if (tok.startsWith("--")) {
      const body = tok.slice(2);
      const eq = body.indexOf("=");
      if (eq >= 0) {
        flags[body.slice(0, eq)] = body.slice(eq + 1);
        continue;
      }
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[body] = next;
        i++;
      } else {
        flags[body] = true;
      }
    } else {
      _.push(tok);
    }
  }
  return { _, flags };
}

/** Read a flag as a string, or `undefined` if absent / boolean-only. */
export function flagStr(args: ParsedArgs, name: string): string | undefined {
  const v = args.flags[name];
  return typeof v === "string" ? v : undefined;
}

/** Read a flag as a boolean (presence, or `--flag=true`). */
export function flagBool(args: ParsedArgs, name: string): boolean {
  const v = args.flags[name];
  return v === true || v === "true";
}

/** Read a comma-separated flag as a trimmed string list (or `undefined` if absent). */
export function listFlag(args: ParsedArgs, name: string): string[] | undefined {
  const v = flagStr(args, name);
  if (!v) return undefined;
  const parts = v.split(",").map((s) => s.trim()).filter(Boolean);
  return parts.length ? parts : undefined;
}

/** Read a flag as a finite number (or `undefined` if absent / unparseable). */
export function numFlag(args: ParsedArgs, name: string): number | undefined {
  const v = flagStr(args, name);
  if (v === undefined) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
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
