// Single source of truth for the version the bundle reports. `sync-version.mjs`
// rewrites this string at release time (kept in lockstep with package.json and
// SKILL.md). SCHEMA_VERSION bumps when the on-disk audit-dossier format changes.
export const VERSION = "1.22.0";
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
// 7: taint findings gained optional `sourceScope` (is the source in the same
// function as the frame it closed?) and `dataflow` (does the bound value still
// reach the entry line?) — ranking signals, not filters, so older dossiers rank
// exactly as before; plus optional `brocard`, the named ground for a refutation.
// All three additive + optional (back-compat).
export const SCHEMA_VERSION = 7;

// ── Severity / confidence ──────────────────────────────────────────────────
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ["high", "medium", "low"] as const;
export type Confidence = (typeof CONFIDENCES)[number];

// ── Findings ────────────────────────────────────────────────────────────────
// How a finding was surfaced. `taint` = a cross-file source→sink data-flow the
// engine enumerated for the AI to adjudicate; the rest map to external tools or
// non-taint reasoning the AI performs (authz/business-logic, weak crypto, …).
// "privacy" covers how personal data is handled rather than how it is protected:
// a transfer to a third-party processor, a control named "anonymisation" that
// only pseudonymises, a constant public salt, an absent retention policy. Those
// are findings an auditor must be able to file as such — filing them under
// "logs" or "secret", as the vocabulary previously forced, distorts the report.
export const CATEGORIES = ["taint", "sast", "dep", "secret", "config", "authz", "crypto", "logs", "privacy", "other"] as const;
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

/**
 * The named grounds on which a candidate may be refuted — adapted from William
 * Woodruff's brocards for vulnerability triage.
 *
 * "Only dismiss what you can positively refute" is the right rule and, on its
 * own, an unfalsifiable one: it never says what a refutation may consist of. A
 * brocard does. Each is a test a reviewer can disagree with, which is the whole
 * point — a dismissal that names one is auditable, a dismissal that names none
 * is an abandonment wearing a verdict's clothes.
 */
export const BROCARDS = [
  "no-threat-model",
  "exploit-from-the-heavens",
  "outside-usage",
  "standard-behavior",
  "documented-behavior",
  "cure-worse-than-disease",
  "report-not-dispositive",
] as const;
export type Brocard = (typeof BROCARDS)[number];

/** One-line gloss per brocard, rendered next to a dismissal in the report. */
export const BROCARD_SUMMARY: Record<Brocard, string> = {
  "no-threat-model": "no coherent attacker: the claim cannot complete “an attacker with X can Y to obtain Z”",
  "exploit-from-the-heavens": "the capability required already equals or exceeds what the exploit grants",
  "outside-usage": "the path is not reached in any real deployment",
  "standard-behavior": "the behaviour is the specification working as written",
  "documented-behavior": "the behaviour is documented, security implications included",
  "cure-worse-than-disease": "remediation would cause more harm than the issue does",
  "report-not-dispositive": "the report's authority (a CVE id, a scanner's severity) is not evidence either way",
};

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

// ── Intra-procedural signals (schema 7) ─────────────────────────────────────
// Both sharpen a summary-based candidate WITHOUT filtering it. The BFS answers
// "can control reach this sink from a file that reads untrusted input?"; these
// answer "and does the value plausibly travel with it?". Reachability is not
// taint: keep the two vocabularies apart in anything user-facing.

/**
 * Where a taint source sits relative to the frame it closed.
 * `symbol` same enclosing function · `module` file scope (middleware, top-level
 * registration — legitimate) · `file` a DIFFERENT function of the same file,
 * i.e. co-location and nothing else.
 */
export const SOURCE_SCOPES = ["symbol", "module", "file"] as const;
export type SourceScope = (typeof SOURCE_SCOPES)[number];

/** Whether a def-use walk could still see the source's bound value at the entry
 *  line. Absent (undefined) means undecidable, never "no". */
export const DATAFLOWS = ["linked", "unlinked"] as const;
export type Dataflow = (typeof DATAFLOWS)[number];

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
  /**
   * Where the source sits relative to the frame it closed: `symbol` (same
   * function), `module` (file scope), `file` (a DIFFERENT function of the same
   * file — co-location only). Ranking signal for taint candidates; absent on
   * non-taint findings and on dossiers written before schema 7.
   */
  sourceScope?: SourceScope;
  /**
   * Whether an intra-procedural def-use walk could still see the source's bound
   * value at the frame's entry line. Absent means the shape was outside what a
   * line-based walk decides — NOT that the value fails to arrive.
   */
  dataflow?: Dataflow;
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
  /**
   * The named ground for a `refuted` verdict. Optional, and deliberately not
   * enforced: a dismissal without one still applies (the conservative policy
   * already refuses to auto-dismiss high/critical on anything short of an
   * explicit refutation), but `check --semantic` reports it so a reviewer can
   * see which dismissals were argued and which were merely asserted.
   */
  brocard?: Brocard;
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
  /** Which extraction tier produced this run's symbols and call sites. Same
   *  contract as `truncation` above: a degraded run must never pass for a full
   *  one. `ast: false` means tree-sitter was unavailable and the regex
   *  extractors ran instead — measured on a 69-file TypeScript repo, that is 27
   *  taint candidates instead of 66, with every cross-file command-injection
   *  candidate missing. Additive/optional; dossiers written before this field
   *  existed omit it. */
  extraction?: { tier: "adjacent" | "env" | "cache" | "none"; ast: boolean };
  /** Basename of the CycloneDX SBOM generated this run (`src/tools/sbom.ts`), a
   *  dossier deliverable in its own right and the input grype/package-checker
   *  prefer over re-walking the tree. Additive/optional; older dossiers and
   *  hosts without `syft` omit it. */
  sbom?: string;
}
