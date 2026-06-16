import { shortHash } from "../util.js";
import type { Category, Confidence, Finding, Severity } from "../types.js";

// Helpers shared by every tool adapter: map a tool's severity vocabulary onto
// ultrasec's, and assemble a normalized Finding with a stable, content-derived id
// (so re-runs and merges are idempotent).

const SEVERITY_ALIASES: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  error: "high",
  moderate: "medium",
  medium: "medium",
  warning: "medium",
  low: "low",
  minor: "low",
  note: "low",
  info: "info",
  informational: "info",
  unknown: "info",
  none: "info",
};

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
}

export function makeToolFinding(i: ToolFindingInput): Finding {
  const id = shortHash(`${i.tool}:${i.ident}:${i.file ?? ""}:${i.line ?? ""}`);
  const f: Finding = {
    id,
    category: i.category,
    title: i.title || i.ident,
    severity: i.severity,
    confidence: i.confidence ?? "medium",
    message: i.message,
    tool: i.tool,
    status: "open",
  };
  if (i.cwe) f.cwe = i.cwe;
  if (i.references && i.references.length) f.references = i.references;
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
