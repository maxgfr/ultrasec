import { shortHash } from "../util.js";
import type { Category, Confidence, Finding, Severity } from "../types.js";

// Helpers shared by every tool adapter: map a tool's severity vocabulary onto
// ultrasec's, and assemble a normalized Finding with a stable, content-derived id
// (so re-runs and merges are idempotent).

// Null-prototype: a tool-supplied severity string could equal an Object.prototype
// member ("constructor"…), which on a plain object would return an inherited
// function and defeat the `?? fallback` below — leaking a non-Severity value.
const SEVERITY_ALIASES: Record<string, Severity> = Object.assign(Object.create(null) as Record<string, Severity>, {
  critical: "critical",
  high: "high",
  error: "high",
  moderate: "medium",
  medium: "medium",
  warning: "medium",
  low: "low",
  minor: "low",
  note: "low",
  // deepsec's non-security bug tiers — alias explicitly so they don't silently
  // collapse to the fallback (HIGH_BUG = a high-priority bug; BUG = an ordinary one).
  high_bug: "high",
  bug: "low",
  info: "info",
  informational: "info",
  unknown: "info",
  none: "info",
});

export function normalizeSeverity(raw: string | undefined | null, fallback: Severity = "medium"): Severity {
  if (!raw) return fallback;
  return SEVERITY_ALIASES[String(raw).trim().toLowerCase()] ?? fallback;
}

export interface ToolFindingInput {
  tool: string;
  category: Category;
  /** Tool-native id (CVE / rule id / advisory id). */
  ident: string;
  title: string;
  severity: Severity;
  message: string;
  file?: string;
  line?: number;
  cwe?: string;
  references?: string[];
  /** Default confidence for tool findings is "medium" — a real scanner flagged it. */
  confidence?: Confidence;
  // ── Optional dependency identity (dep adapters) — powers dedup + EPSS/KEV ─────
  /** Every advisory id for this vuln (primary + aliases). The CVE is auto-picked. */
  aliases?: string[];
  /** Affected package name. */
  pkg?: string;
  /** Installed/affected version. */
  version?: string;
  /** Secret adapters: whether the credential was actively validated as live. */
  verified?: boolean;
}

/** Pull the canonical CVE id out of a set of advisory ids, if any. */
export function pickCve(ids: (string | undefined | null)[]): string | undefined {
  for (const id of ids) {
    const m = /^CVE-\d{4}-\d{4,}$/i.exec(String(id ?? "").trim());
    if (m) return m[0].toUpperCase();
  }
  return undefined;
}

/** Every distinct CVE id mentioned anywhere in the given strings/arrays. */
export function cvesIn(...inputs: unknown[]): string[] {
  const text = inputs
    .flat(Infinity)
    .map((x) => (typeof x === "string" ? x : ""))
    .join(" ");
  const out = new Set<string>();
  const re = /CVE-\d{4}-\d{4,}/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) out.add(m[0].toUpperCase());
  return [...out];
}

export function makeToolFinding(i: ToolFindingInput): Finding {
  // The version is part of the identity for dep findings: the same advisory at
  // the same lockfile is one finding PER installed version pre-correlation (the
  // correlator then merges them into one with `locations[]`). Version-less
  // findings (sast/secret/config) keep their historical hash input — no id churn.
  const id = shortHash(`${i.tool}:${i.ident}:${i.file ?? ""}:${i.line ?? ""}${i.version ? `:${i.version}` : ""}`);
  const f: Finding = {
    id,
    category: i.category,
    title: i.title || i.ident,
    severity: i.severity,
    confidence: i.confidence ?? "medium",
    message: i.message,
    tool: i.tool,
    sources: [i.tool],
    status: "open",
  };
  if (i.cwe) f.cwe = i.cwe;
  if (i.references && i.references.length) f.references = i.references;
  // Dependency identity: gather all advisory ids, pick the CVE as the join key.
  const aliases = [i.ident, ...(i.aliases ?? [])].filter((x): x is string => Boolean(x));
  const uniqAliases = [...new Set(aliases)];
  if (i.aliases !== undefined || /^(CVE|GHSA|RUSTSEC|GO|PYSEC|OSV)-/i.test(i.ident)) {
    if (uniqAliases.length) f.aliases = uniqAliases;
    const cve = pickCve(uniqAliases);
    if (cve) f.cve = cve;
  }
  if (i.pkg) f.pkg = i.pkg;
  if (i.version) f.version = i.version;
  if (i.verified !== undefined) f.verified = i.verified;
  if (i.file) {
    const loc = { file: i.file, line: i.line ?? 1 };
    f.sink = loc; // for SAST/secret/config the flagged location is the "sink"
  }
  return f;
}

/**
 * Parse a stream of concatenated top-level JSON values (whitespace/newline
 * separated, NOT wrapped in an array) — govulncheck's `-json` output shape.
 * Skips malformed fragments rather than throwing.
 */
export function parseJsonStream(raw: string): unknown[] {
  const out: unknown[] = [];
  let depth = 0;
  let inStr = false;
  let esc = false;
  let start = -1;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]!;
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      continue;
    }
    if (ch === "{" || ch === "[") {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === "}" || ch === "]") {
      depth--;
      if (depth === 0 && start >= 0) {
        try {
          out.push(JSON.parse(raw.slice(start, i + 1)));
        } catch {
          /* skip malformed fragment */
        }
        start = -1;
      }
    }
  }
  return out;
}

/** Pull the first CWE-NNN out of an arbitrary string or array. */
export function firstCwe(input: unknown): string | undefined {
  const text = Array.isArray(input) ? input.join(" ") : typeof input === "string" ? input : "";
  const m = /CWE[-_ ]?(\d+)/i.exec(text);
  return m ? `CWE-${m[1]}` : undefined;
}
