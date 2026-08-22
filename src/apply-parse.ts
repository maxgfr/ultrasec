// Shared shape for every `--apply` parser (verdicts / triage / discoveries /
// revalidations).
//
// The rule these types exist to enforce: a malformed row is NEVER discarded in
// silence. Before this module each parser dropped bad rows with a bare
// `continue`/`filter` and only threw when EVERY row was invalid — so a single
// typo'd `verdict` or `category` made a finding vanish with no diagnostic, in a
// tool whose whole contract is fail-closed adjudication. A dropped `supported`
// verdict silently removed a CONFIRMED vulnerability from the final report.
//
// Parsers now return every row they refused, with the field and the value that
// caused it, and the commands surface those alongside the ingest counters.

import { CATEGORIES, SEVERITIES, normalizeCategory, type Category, type Severity } from "./types.js";

/** One row the parser refused, and why. */
export interface DroppedRow {
  /** 0-based position in the source array — how the author finds the row. */
  index: number;
  /** Names the offending field and echoes the value received. */
  reason: string;
  /** Source path, set when `--apply` folded more than one file. */
  file?: string;
}

/** One row the parser kept, but had to rewrite to a canonical value. */
export interface NormalizedRow {
  /** 0-based position in the source array. */
  index: number;
  /** Names the field, the value received, and what it became. */
  note: string;
}

/** What every `--apply` parser returns: what it kept, what it refused, and what
 *  it had to rewrite. A silent rewrite is its own kind of data loss, so a fold
 *  is reported next to the drops rather than absorbed. */
export interface ParseResult<T> {
  rows: T[];
  dropped: DroppedRow[];
  normalized?: NormalizedRow[];
}

/**
 * Render a received value compactly for a rejection message. Strings are quoted
 * so `"3"` is visibly not `3`; objects collapse to their type rather than dumping
 * a payload into the terminal.
 */
export function describeValue(v: unknown): string {
  if (v === undefined) return "missing";
  if (v === null) return "null";
  if (typeof v === "string") return JSON.stringify(v.length > 40 ? `${v.slice(0, 40)}…` : v);
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return `array(${v.length})`;
  return typeof v;
}

/** Reason for a value outside a closed vocabulary. */
export function notInVocabulary(field: string, value: unknown, allowed: readonly string[]): string {
  return `${field} ${describeValue(value)} is not one of ${allowed.join("|")}`;
}

/** Reason for a field of the wrong type (or absent). */
export function badField(field: string, value: unknown, expected: string): string {
  return `${field} ${describeValue(value)} — expected ${expected}`;
}

/**
 * Coerce an apply payload to its row array, accepting a bare array or any of the
 * documented wrapper keys. Throws (fail-closed) on anything else.
 */
export function coerceRows(data: unknown, wrapperKeys: readonly string[], label: string): unknown[] {
  if (Array.isArray(data)) return data;
  for (const key of wrapperKeys) {
    const nested = (data as Record<string, unknown> | null | undefined)?.[key];
    if (Array.isArray(nested)) return nested;
  }
  const shapes = [`a JSON array`, ...wrapperKeys.map((k) => `{"${k}":[...]}`)].join(" or ");
  throw new Error(`unrecognized ${label} shape — expected ${shapes} (fail-closed)`);
}

/**
 * Fail-closed guard: a non-empty payload that yielded nothing usable is an error,
 * not an empty fold. The message lists every rejection so the author can fix the
 * file in one pass instead of bisecting it.
 */
export function requireUsable<T>(result: ParseResult<T>, sourceLength: number, requirement: string): ParseResult<T> {
  if (sourceLength > 0 && result.rows.length === 0) {
    const detail = result.dropped.map((d) => `row ${d.index}: ${d.reason}`).join("; ");
    throw new Error(`${sourceLength} row(s), none usable — each needs ${requirement} (fail-closed)${detail ? ` — ${detail}` : ""}`);
  }
  return result;
}

/** Human-readable lines for the folded rows — reported, never silent. */
export function formatNormalized(normalized: readonly NormalizedRow[]): string[] {
  return normalized.map((n) => `  ↷ row ${n.index}: ${n.note}`);
}

/** Human-readable lines for the dropped rows, in the style of the existing `✗ rejected` output. */
export function formatDropped(dropped: readonly DroppedRow[]): string[] {
  return dropped.map((d) => `  ✗ dropped ${d.file ? `${d.file} ` : ""}row ${d.index}: ${d.reason}`);
}

/**
 * Print the refused rows and return the stage's exit code. Shared by all four
 * `--apply` commands so a malformed row reads identically whichever stage saw it.
 *
 * `--strict` exits 1 on any drop: a partial fold is a silent coverage loss, and CI
 * should be able to refuse it even though the valid rows were applied.
 */
export function surfaceDropped(dropped: readonly DroppedRow[], strict: boolean, emit: (line: string) => void): number {
  for (const line of formatDropped(dropped)) emit(line);
  if (strict && dropped.length > 0) {
    emit(`  --strict: ${dropped.length} malformed row(s) refused — failing so the loss isn't absorbed silently.`);
    return 1;
  }
  return 0;
}

/**
 * The `{id, verdict}` payload shared by verify, triage and revalidate. They differ
 * only in their wrapper keys, their verdict vocabulary and the extra fields they
 * carry, so the validation loop lives here once — the same reason `stage.ts` owns
 * the apply-file resolution.
 */
export function parseIdVerdictRows<V extends string, T>(
  raw: string,
  opts: {
    wrapperKeys: readonly string[];
    label: string;
    verdicts: readonly V[];
    /** Called only for rows that passed validation. */
    build: (row: Record<string, unknown>, verdict: V) => T;
  },
): ParseResult<T> {
  const arr = coerceRows(JSON.parse(raw) as unknown, opts.wrapperKeys, opts.label);
  const rows: T[] = [];
  const dropped: DroppedRow[] = [];

  for (const [index, row] of arr.entries()) {
    if (!row || typeof row !== "object") {
      dropped.push({ index, reason: badField("row", row, "an object") });
      continue;
    }
    const r = row as Record<string, unknown>;
    const bad: string[] = [];
    if (typeof r.id !== "string") bad.push(badField("id", r.id, "a string"));
    if (!(opts.verdicts as readonly string[]).includes(r.verdict as string)) bad.push(notInVocabulary("verdict", r.verdict, opts.verdicts));
    if (bad.length) {
      dropped.push({ index, reason: bad.join(", ") });
      continue;
    }
    rows.push(opts.build(r, r.verdict as V));
  }

  return requireUsable({ rows, dropped }, arr.length, `a string "id" and a "verdict" among ${opts.verdicts.join("|")}`);
}

// ── The Discovery row ───────────────────────────────────────────────────────
//
// One agent-authored finding, as `investigate --apply` and `variants --apply`
// both submit it.
//
// This validation lived inline in `investigate.ts`, and `variants.ts` had none
// at all: it cast `v.variants as Discovery[]` — a TYPE assertion, erased at
// runtime — and handed the result straight to `ingestDiscoveries`. On the first
// real audit that meant `variants --apply` threw on a row with no `title`, then
// ingested eleven rows carrying `category: null, severity: null`, which
// corrupted the manifest's severity histogram and finally made `render` throw.
// The fail-closed promise held on one stage and not on its neighbour.
//
// So the row validator lives HERE, beside the other shared apply primitives,
// and both stages call it. A third stage that ingests discoveries gets it right
// for free instead of getting it wrong in a new way.

/** One agent-authored finding, with its vocabulary fields already canonical. */
export interface DiscoveryRow {
  title: string;
  category: Category;
  /** The class name the author wrote, when it was folded onto `category`.
   *  Preserved so the report can say "stored-xss" where storage says "taint". */
  vulnClass?: string;
  severity: Severity;
  cwe?: string;
  message: string;
  file: string;
  line: number;
  path?: { file: string; line: number; why: string }[];
}

/** Kept (`row`, plus a `note` when a value was rewritten), or refused (`reason`). */
export interface DiscoveryRowResult {
  row?: DiscoveryRow;
  reason?: string;
  note?: string;
}

/** What a Discovery row must carry — the `requireUsable` requirement string. */
export const DISCOVERY_REQUIREMENT = `title/message/file (strings), line ≥ 0, a category among ${CATEGORIES.join(
  "|",
)} (aliases accepted) and a severity among ${SEVERITIES.join("|")}`;

/**
 * Validate one Discovery row.
 *
 * Every offending field is reported at once: fixing a discovery one error per
 * run is exactly the friction that made silent drops tolerable in the first
 * place.
 */
export function parseDiscoveryRow(raw: unknown): DiscoveryRowResult {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { reason: badField("row", raw, "an object") };
  const d = raw as Record<string, unknown>;

  const bad: string[] = [];
  for (const field of ["title", "message", "file"] as const) {
    if (typeof d[field] !== "string" || !(d[field] as string).length) bad.push(badField(field, d[field], "a non-empty string"));
  }
  // `line: 0` is the documented whole-file citation (schemas.md) that config/IaC
  // findings normalize to, and `check` already special-cases it. Rejecting it
  // here refused a legitimate shape the format defines.
  if (!Number.isInteger(d.line) || (d.line as number) < 0) bad.push(badField("line", d.line, "an integer ≥ 0 (0 = the whole file)"));
  const cat = normalizeCategory(d.category as string);
  if (!cat) bad.push(`${notInVocabulary("category", d.category, CATEGORIES)} (nor a known alias — see CATEGORY_ALIASES)`);
  if (!(SEVERITIES as readonly string[]).includes(d.severity as string)) bad.push(notInVocabulary("severity", d.severity, SEVERITIES));
  if (bad.length) return { reason: bad.join(", ") };

  const path = Array.isArray(d.path)
    ? (d.path as unknown[])
        .filter((p) => {
          const s = p as { file?: unknown; line?: unknown } | null;
          return !!s && typeof s === "object" && typeof s.file === "string" && Number.isInteger(s.line) && (s.line as number) >= 1;
        })
        .map((p) => {
          const s = p as { file: string; line: number; why?: unknown };
          return { file: s.file, line: s.line, why: typeof s.why === "string" ? s.why : "" };
        })
    : undefined;

  return {
    row: {
      title: d.title as string,
      category: cat!.category,
      ...(cat!.folded ? { vulnClass: String(d.category) } : {}),
      severity: d.severity as Severity,
      ...(typeof d.cwe === "string" ? { cwe: d.cwe } : {}),
      message: d.message as string,
      file: d.file as string,
      line: d.line as number,
      ...(path && path.length ? { path } : {}),
    },
    ...(cat!.folded ? { note: `category ${describeValue(d.category)} folded to "${cat!.category}"` } : {}),
  };
}
