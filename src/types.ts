// Single source of truth for the version the bundle reports. `sync-version.mjs`
// rewrites this string at release time (kept in lockstep with package.json and
// SKILL.md). SCHEMA_VERSION bumps when the on-disk audit-dossier format changes.
export const VERSION = "1.5.0";
// 2: graph.json gained `callersBySymbol` (reverse call-index); manifest gained
// optional `truncation`/`scopes` (large-repo scaling). Older dossiers omit them.
// 3: findings gained optional `provenance` (git-blame author/commit/date +
// CODEOWNERS owner), populated only under `scan --blame`. Older dossiers omit it.
export const SCHEMA_VERSION = 3;

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

/**
 * Deterministic committer/ownership provenance for a finding's primary line —
 * a triage signal ("introduced last week by X, owned by team Y"), populated only
 * under `scan --blame`. Every field is derived from git history / CODEOWNERS, so
 * the dossier stays reproducible (the date is the commit's AUTHOR-date, never
 * wall-clock "now"). Evidence only — it NEVER gates a verdict (ultrasec must not
 * cull findings by age the way a pure-LLM scanner might).
 */
export interface Provenance {
  /** Last author to touch the line (git blame). */
  author?: string;
  /** Short commit sha of that change. */
  commit?: string;
  /** Author-date, ISO yyyy-mm-dd — deterministic from history. */
  date?: string;
  /** CODEOWNERS owner(s) for the file, joined when several. */
  owner?: string;
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
  /**
   * Every tool that independently reported this finding (incl. `tool`), sorted
   * and de-duplicated. Length > 1 means corroboration — a confidence prior for
   * the verify gate ("N scanners agree"). Set by the cross-tool correlator.
   */
  sources?: string[];
  /** CWE / advisory / docs URLs. */
  references?: string[];
  // ── Dependency identity (dep findings) — used for cross-tool dedup + scoring ─
  /** Canonical CVE id when known (e.g. "CVE-2021-23337"); the EPSS/KEV join key. */
  cve?: string;
  /** Every advisory id for this vuln (primary + aliases: CVE / GHSA / RUSTSEC / GO-…). */
  aliases?: string[];
  /** Affected package name (e.g. "lodash"). */
  pkg?: string;
  /** Installed/affected version. */
  version?: string;
  // ── Enrichment (deterministic, post-scan) ───────────────────────────────────
  /** EPSS exploitation-probability in [0,1] (FIRST.org), when the CVE is scored. */
  epss?: number;
  /** True when the CVE is in CISA's Known Exploited Vulnerabilities catalog. */
  kev?: boolean;
  /** Date the CVE was added to CISA KEV (ISO yyyy-mm-dd), when applicable. */
  kevDateAdded?: string;
  /** Composite risk 0–100 (severity ⊕ EPSS ⊕ KEV) — the primary sort key. */
  risk?: number;
  /** Secret findings: whether a scanner actively validated the credential is live. */
  verified?: boolean;
  /** Adversarial-verification outcome, once adjudicated. */
  verdict?: Verdict;
  /** Concrete trigger path / proof-of-exploit sketch, once reasoned. */
  exploitPath?: string;
  /** Deterministic git-blame / CODEOWNERS provenance (opt-in `--blame`). Evidence only. */
  provenance?: Provenance;
  /** Commit that fixed/moved the cited line, set by `revalidate --apply` on a
   *  `fixed` verdict (Phase 2). Optional — older dossiers omit it (back-compat). */
  fixedIn?: string;
  status: Status;
}

// ── Project-context primer (Phase 1) ─────────────────────────────────────────
// A deterministic scaffold of the project's trust model the agent turns into a
// prose CONTEXT.md. ADDITIVE EVIDENCE ONLY — it never gates a verdict.
export interface ContextScaffold {
  frameworks: string[];
  entryPoints: { file: string; line: number; kind: string }[];
  authMiddleware: { file: string; line: number; hint: string }[];
  sanitizers: { file: string; line: number; kind: string }[];
  trustBoundaries: string[];
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
  /** Coverage truncation — surfaced so a capped run is never mistaken for a full one. */
  truncation?: {
    /** Taint candidates dropped by `--max-candidates` (0 = none dropped). */
    candidates: number;
    /** Total taint candidates enumerated before the cap. */
    total: number;
    /** True when the file walk hit `--max-files` (some files were not scanned). */
    files?: boolean;
  };
  /** Every scope/diff that has contributed to this (possibly merged) run. */
  scopes?: string[];
}
