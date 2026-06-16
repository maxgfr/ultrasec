// Single source of truth for the version the bundle reports. `sync-version.mjs`
// rewrites this string at release time (kept in lockstep with package.json and
// SKILL.md). SCHEMA_VERSION bumps when the on-disk audit-dossier format changes.
export const VERSION = "1.1.0";
export const SCHEMA_VERSION = 1;

// ── Severity / confidence ──────────────────────────────────────────────────
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ["high", "medium", "low"] as const;
export type Confidence = (typeof CONFIDENCES)[number];

// ── Findings ────────────────────────────────────────────────────────────────
// How a finding was surfaced. `taint` = a cross-file source→sink data-flow the
// engine enumerated for the AI to adjudicate; the rest map to external tools or
// non-taint reasoning the AI performs (authz/business-logic, weak crypto, …).
export const CATEGORIES = [
  "taint",
  "sast",
  "dep",
  "secret",
  "config",
  "authz",
  "crypto",
  "other",
] as const;
export type Category = (typeof CATEGORIES)[number];

// Lifecycle of a finding through the conservative verify gate. A candidate is
// `open` until adjudicated; a true positive becomes `confirmed`; a proven false
// positive is `dismissed`; anything uncertain (esp. high-severity) stays
// `needs-human` — never silently dropped (the research shows aggressive
// auto-suppression discards ~22% of real bugs).
export const STATUSES = ["open", "confirmed", "needs-human", "dismissed"] as const;
export type Status = (typeof STATUSES)[number];

// Adversarial-verification verdict for one (finding ↔ evidence) pair, mirroring
// the ultrasearch/ultraindex semantic gate vocabulary.
export const VERDICTS = ["supported", "partial", "unsupported", "refuted"] as const;
export type Verdict = (typeof VERDICTS)[number];

export interface CodeLoc {
  /** Repo-relative POSIX path. */
  file: string;
  /** 1-based line. */
  line: number;
  /** 1-based column, when known. */
  col?: number;
  /** Enclosing symbol (function/method), when known. */
  symbol?: string;
}

/** One hop of a cross-file source→sink chain — the heart of the link analysis. */
export interface PathStep extends CodeLoc {
  /** Why taint is believed to propagate through this hop. */
  why: string;
}

export interface Finding {
  /** Stable id, content-derived (so re-scans and merges are idempotent). */
  id: string;
  category: Category;
  /** e.g. "CWE-89". */
  cwe?: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** Where untrusted data enters (taint findings). */
  source?: CodeLoc & { kind?: string };
  /** The dangerous operation reached (taint findings). */
  sink?: CodeLoc & { kind?: string };
  /** The cross-file/function chain from source to sink. */
  path?: PathStep[];
  message: string;
  /** Producer: "ultrasec" for engine-enumerated, else the external tool name. */
  tool: string;
  /** CWE / advisory / docs URLs. */
  references?: string[];
  /** Adversarial-verification outcome, once adjudicated. */
  verdict?: Verdict;
  /** Concrete trigger path / proof-of-exploit sketch, once reasoned. */
  exploitPath?: string;
  status: Status;
}

// ── Audit dossier (on-disk run folder) ───────────────────────────────────────
export interface Manifest {
  version: string;
  schemaVersion: number;
  repo: string;
  generatedNote: string; // human note; deliberately not a timestamp (reproducible)
  languages: string[];
  toolsRun: string[];
  counts: { findings: number; bySeverity: Record<Severity, number> };
}
