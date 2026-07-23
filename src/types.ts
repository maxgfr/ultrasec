// Single source of truth for the version the bundle reports. `sync-version.mjs`
// rewrites this string at release time (kept in lockstep with package.json and
// SKILL.md). SCHEMA_VERSION bumps when the on-disk audit-dossier format changes.
export const VERSION = "1.10.3";
// 2: graph.json gained `callersBySymbol` (reverse call-index); manifest gained
// optional `truncation`/`scopes` (large-repo scaling). Older dossiers omit them.
// 3: findings gained optional `provenance` (git-blame author/commit/date +
// CODEOWNERS owner), populated only under `scan --blame`. Older dossiers omit it.
// 4: findings gained optional `priorAnalysis` (upstream-agent reasoning ingested
// as a SIGNAL, e.g. from deepsec) + `fixedIn` (commit a `revalidate` fix folded
// in). Both additive + optional — older dossiers omit them (back-compat).
// 5: dep findings gained optional `locations` (per-version/per-lockfile instances
// of a cross-version-merged advisory); manifest gained optional `toolStatus`
// (per-tool ran/empty/skipped/failed). Additive + optional (back-compat).
// 6: manifest gained optional `sbom` (CycloneDX deliverable); additive, back-compat.
export const SCHEMA_VERSION = 6;

// ── Severity / confidence ──────────────────────────────────────────────────
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ["high", "medium", "low"] as const;
export type Confidence = (typeof CONFIDENCES)[number];

// ── Findings ────────────────────────────────────────────────────────────────
// How a finding was surfaced. `taint` = a cross-file source→sink data-flow the
// engine enumerated for the AI to adjudicate; the rest map to external tools or
// non-taint reasoning the AI performs (authz/business-logic, weak crypto, …).
export const CATEGORIES = ["taint", "sast", "dep", "secret", "config", "authz", "crypto", "logs", "other"] as const;
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

/**
 * Reasoning from an UPSTREAM agent scanner (e.g. deepsec) ingested as a SIGNAL —
 * NEVER auto-applied. ultrasec's conservative verify gate remains the only thing
 * that changes a finding's status; this is background for the adjudicator, surfaced
 * (clearly labelled) in the dossier + verify worklist but never a verdict.
 */
export interface PriorAnalysis {
  /** Producing tool, e.g. "deepsec". */
  tool: string;
  reasoning?: string;
  mitigationsChecked?: string[];
  /** e.g. "true-positive" | "fixed" | … — a hint, NOT an ultrasec status. */
  revalidationVerdict?: string;
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
  /**
   * Per-instance evidence of a cross-version-merged dep advisory: every
   * lockfile location (and installed version) the advisory was reported at.
   * Grounding-gated like any citation (file must resolve). Set by the
   * correlator only when the cluster spans more than one distinct instance.
   */
  locations?: { file: string; line?: number; version?: string }[];
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
  /** Upstream-agent reasoning (e.g. deepsec) ingested as a SIGNAL — never a verdict. */
  priorAnalysis?: PriorAnalysis;
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

// ── AI-authored report narrative (Phase 3) ───────────────────────────────────
// Additive, clearly-marked report sections the agent authors and `render
// --narrative` folds in. NEVER changes a finding's status/severity/set — it's
// prose layered on top of the deterministic report; sections citing unknown or
// non-confirmed finding ids are dropped on merge (grounding stays strict).
export interface Remediation {
  id: string;
  fix: string;
  patch?: string;
  owner?: string;
}
export interface AttackChain {
  title: string;
  findingIds: string[];
  narrative: string;
}
export interface RootCauseGroup {
  cause: string;
  findingIds: string[];
  note: string;
}
export interface Narrative {
  executiveSummary?: string;
  /** What the codebase does well — calibrates trust in the findings. Free prose, advisory (cites no finding ids). */
  positivePatterns?: string;
  remediations?: Remediation[];
  attackChains?: AttackChain[];
  rootCauses?: RootCauseGroup[];
  /** Defense-in-depth suggestions that are explicitly NOT findings — advisory, excluded from severity counts and never grounding-gated. */
  hardeningNotes?: string[];
}

// ── Audit dossier (on-disk run folder) ───────────────────────────────────────
export interface Manifest {
  version: string;
  schemaVersion: number;
  repo: string;
  generatedNote: string; // human note; deliberately not a timestamp (reproducible)
  languages: string[];
  toolsRun: string[];
  /** Per-tool outcome — distinguishes "ran, 0 findings" from "skipped (no target)"
   *  from "failed". Additive/optional; older dossiers and `--tools none` omit it. */
  toolStatus?: { name: string; status: "ran" | "empty" | "skipped" | "failed"; findings?: number; note?: string }[];
  counts: { findings: number; bySeverity: Record<Severity, number> };
  /** Coverage truncation — surfaced so a capped run is never mistaken for a full one. */
  truncation?: {
    /** Taint candidates dropped by `--max-candidates` (0 = none dropped). */
    candidates: number;
    /** Total taint candidates enumerated before the cap. */
    total: number;
    /** True when the file walk hit `--max-files` (some files were not scanned). */
    files?: boolean;
    /** Command-specific replacement for the default "Coverage capped" advice
     *  sentence (which names scan-only flags: `--max-candidates`/`--scope`).
     *  Set by commands — e.g. `logs`, whose family caps aren't reachable via
     *  those flags — whose remediation differs from a taint-candidate cap.
     *  Absent ⇒ `store.ts` renders the default scan advice, byte-identical to
     *  before this field existed. */
    hint?: string;
  };
  /** Every scope/diff that has contributed to this (possibly merged) run. */
  scopes?: string[];
  /** Basename of the CycloneDX SBOM generated this run (`src/tools/sbom.ts`), a
   *  dossier deliverable in its own right and the input grype/package-checker
   *  prefer over re-walking the tree. Additive/optional; older dossiers and
   *  hosts without `syft` omit it. */
  sbom?: string;
}
