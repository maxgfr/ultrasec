// Single source of truth for the version the bundle reports. `sync-version.mjs`
// rewrites this string at release time (kept in lockstep with package.json and
// SKILL.md). SCHEMA_VERSION bumps when the on-disk audit-dossier format changes.
export const VERSION = "1.40.2";
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
// 8: manifest gained optional `passes` (which opt-in scan passes actually ran)
// and `downgraded` (findings de-prioritized as noise-by-construction, with the
// reason and count, so a suppressed class is never silent).
// Additive + optional — older dossiers omit it, and a consumer that can't tell
// "flag not passed" from "flag passed, zero results" falls back to the old
// advice, byte-identical to before.
// 9: findings gained optional `flow` (the assigned value at an assignment sink
// plus the bindings the def-use walk followed — evidence for the adjudicator,
// never acted on by the engine), optional `atCommit` (the commit a history-scanned citation
// belongs to, so the gate resolves it against that tree rather than HEAD) and
// optional `noise` — the noise-by-construction class a
// finding was DEMOTED under (never dismissed): ciphertext-by-design, a taint
// path confined to the test harness, a vendored build artifact. Additive +
// optional; it is re-derived by every scan rather than authored, and it carries
// a suggested refutation ground into the triage/verify worklists.
export const SCHEMA_VERSION = 9;

// ── Severity / confidence ──────────────────────────────────────────────────
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ["high", "medium", "low"] as const;
export type Confidence = (typeof CONFIDENCES)[number];

/**
 * How close the finding is to code that actually runs — the axis severity alone
 * cannot express.
 *
 * The first real audit ranked 182 orphan sinks (a dangerous callee the taint
 * pass could NOT connect to any source) and a handful of build-only CVEs at
 * `critical`, and every one of the 182 was refuted. Severity says how bad it
 * would be; this says whether anything shows it is on a live path.
 *
 * - `runtime`   — on a path the shipped artifact executes (a runtime dependency,
 *                 a source→sink flow the engine linked end to end).
 * - `toolchain` — reachable only through build/test tooling (a devDependency
 *                 chain, a fixture harness). Real, but not attacker-facing in
 *                 the deployed artifact.
 * - `unproven`  — nothing established either way. An orphan sink is the type
 *                 case: worth a look, never a headline.
 *
 * Evidence, not a verdict: it damps the composite `risk` and floors the
 * displayed severity, and an auditor can still confirm an `unproven` finding by
 * finding the path the engine missed.
 */
export const REACHABILITIES = ["runtime", "toolchain", "unproven"] as const;
export type Reachability = (typeof REACHABILITIES)[number];

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

/**
 * Vulnerability-class names an auditor reaches for, folded onto the closed
 * `CATEGORIES` vocabulary above.
 *
 * `category` records HOW a finding was surfaced. An auditor filing a discovery
 * names WHAT the bug is — "xss", "ssrf", "idor", "disclosure" — and every one of
 * those was refused. On the first real audit that cost 11 of 12 manual findings:
 * `investigate` is the documented route for exactly the classes the engine
 * cannot enumerate (sanitizer bypasses, business logic, privacy), and the door
 * it offers them is a vocabulary that does not contain their names. The command
 * exited 0 while dropping them.
 *
 * A closed vocabulary is still right for storage — `category` keys dedup
 * (`dedupKey`), correlation and ASVS coverage scoring, so it cannot be free
 * text. The fix is to accept the names at the door and fold them, reporting what
 * each one became rather than refusing the row.
 *
 * Mappings follow how the ENGINE files the same shape: everything that is
 * "untrusted input reaches a dangerous operation" is `taint`, because that is
 * what the catalog's own sink kinds produce. Classes that assert no data-flow
 * (`dos`, `disclosure`, `robustness`) go to `other` rather than borrowing a
 * flow they have not shown.
 */
export const CATEGORY_ALIASES: Readonly<Record<string, Category>> = {
  // Untrusted input reaching a dangerous operation — the engine's `taint` shape.
  xss: "taint",
  "dom-xss": "taint",
  "stored-xss": "taint",
  "reflected-xss": "taint",
  ssrf: "taint",
  sqli: "taint",
  "sql-injection": "taint",
  "nosql-injection": "taint",
  injection: "taint",
  "command-injection": "taint",
  "code-injection": "taint",
  rce: "taint",
  "path-traversal": "taint",
  "directory-traversal": "taint",
  lfi: "taint",
  rfi: "taint",
  ssti: "taint",
  xxe: "taint",
  "prototype-pollution": "taint",
  "open-redirect": "taint",
  "header-injection": "taint",
  "crlf-injection": "taint",
  "response-splitting": "taint",
  "input-validation": "taint",
  validation: "taint",
  deserialization: "taint",
  "insecure-deserialization": "taint",
  "mass-assignment": "taint",
  "ldap-injection": "taint",
  "xpath-injection": "taint",
  "csv-injection": "taint",
  "prompt-injection": "taint",
  redos: "taint",
  // Missing or wrong authorization.
  idor: "authz",
  "access-control": "authz",
  "broken-access-control": "authz",
  authorization: "authz",
  authentication: "authz",
  authn: "authz",
  "privilege-escalation": "authz",
  csrf: "authz",
  // Cryptography.
  "weak-crypto": "crypto",
  cryptography: "crypto",
  tls: "crypto",
  // Credentials.
  credentials: "secret",
  "hardcoded-secret": "secret",
  "credential-leak": "secret",
  // Deployment / hardening / third-party code.
  misconfiguration: "config",
  hardening: "config",
  "security-headers": "config",
  cors: "config",
  csp: "config",
  iac: "config",
  dependency: "dep",
  "vulnerable-dependency": "dep",
  cve: "dep",
  advisory: "dep",
  "supply-chain": "dep",
  logging: "logs",
  "log-injection": "logs",
  // Personal data.
  gdpr: "privacy",
  rgpd: "privacy",
  pii: "privacy",
  "data-protection": "privacy",
  tracking: "privacy",
  consent: "privacy",
  // Real classes with no data-flow claim and no better home.
  dos: "other",
  "denial-of-service": "other",
  "resource-exhaustion": "other",
  disclosure: "other",
  "information-disclosure": "other",
  "info-leak": "other",
  "error-handling": "other",
  robustness: "other",
  abuse: "other",
  "rate-limit": "other",
  "rate-limiting": "other",
  "business-logic": "other",
  race: "other",
  "race-condition": "other",
};

/**
 * Resolve a submitted category to a member of `CATEGORIES`, or `undefined` when
 * nothing sensible maps. Case- and separator-insensitive, so `"SQL Injection"`,
 * `"sql_injection"` and `"sql-injection"` all land the same way.
 *
 * Returns the canonical value AND whether it was folded, because a silent
 * rewrite is its own kind of data loss — the caller reports every fold.
 */
export function normalizeCategory(value: unknown): { category: Category; folded: boolean } | undefined {
  if (typeof value !== "string") return undefined;
  const key = value
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, "-");
  if ((CATEGORIES as readonly string[]).includes(key)) return { category: key as Category, folded: key !== value };
  const alias = Object.hasOwn(CATEGORY_ALIASES, key) ? CATEGORY_ALIASES[key] : undefined;
  return alias ? { category: alias, folded: true } : undefined;
}

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
/**
 * Noise-by-construction classes: shapes where the match is REAL but the code it
 * sits in cannot carry the risk the finding describes.
 *
 * Kept here with the other closed vocabularies because `Finding.noise` is part
 * of the on-disk schema; the rules that decide membership live in `noise.ts`.
 */
export const NOISE_CLASSES = ["encrypted-at-rest", "test-only-path", "vendored-artifact", "pattern-declaration", "resource-identifier"] as const;
export type NoiseClass = (typeof NOISE_CLASSES)[number];

/**
 * The named ground a dismissal on each basis stands on — all of them existing
 * BROCARDS, never new ones.
 *
 * A class name says how the machine recognised the shape; a brocard says why the
 * dismissal is sound. Adding "test-only" as a ground would conflate the two and
 * quietly grow the vocabulary of things an auditor may assert without argument.
 * This table is the argument, and a reviewer disagrees with a row in it.
 */
export const NOISE_GROUND: Readonly<Record<NoiseClass, Brocard>> = {
  // Ciphertext in a ciphertext file is the format working as written.
  "encrypted-at-rest": "standard-behavior",
  // "The path is not reached in any real deployment" — a test harness is not a
  // deployment. This is `outside-usage` almost verbatim.
  "test-only-path": "outside-usage",
  // A byte-identical copy of a published upstream release: no attacker can
  // complete "with X I can Y to obtain Z" against a blob everyone already has.
  "vendored-artifact": "no-threat-model",
  // A line that DESCRIBES a dangerous pattern is data, not an operation: no
  // attacker completes "with X I can Y to obtain Z" against a documentation
  // string. Security tools, WAF signature sets and lint-rule packs all trip
  // their own rules this way.
  "pattern-declaration": "no-threat-model",
  // The value names a DOCUMENT, not a way in. Possessing a spreadsheet id is not
  // possessing access to it — the sharing setting is, and that is not in the
  // repo. `exploit-from-the-heavens` would be wrong (it is not that the
  // attacker needs too much); the claim simply has no attacker story as written.
  "resource-identifier": "no-threat-model",
};

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
  /**
   * What the engine knows about whether the tainted value actually ARRIVES at
   * the sink — laid out for the adjudicator instead of acted on.
   *
   * Enumeration closes a path on "a source at or above the sink line in the same
   * file", which is co-location. Tightening that mechanically would trade recall
   * on DOM XSS, the class where real bugs live, to remove noise. So the engine
   * states what it saw — the value assigned at an assignment sink, and the names
   * the def-use walk was following — and the reader decides. That is the
   * division of labour this tool is built on: the engine enumerates and
   * evidences, the reasoning is not its job.
   */
  flow?: {
    /** For an assignment sink, the text of the assigned value. */
    assigned?: string;
    /** The bindings the def-use walk tracked from the source. */
    tainted?: string[];
  };
  /**
   * The commit the cited location belongs to, when the finding came from a scan
   * of git HISTORY rather than of the working tree.
   *
   * gitleaks `detect` reads every commit, which is the coverage that catches a
   * credential added and later deleted — and it means the cited `file:line` need
   * not exist at HEAD at all. Without this the citation gate read those as
   * dangling ("hallucinated or stale") and FAILED, on any repo that ever deleted
   * a file: 20 of them on the first real audit, none of them invented.
   *
   * Engine-set only, from the scanner's own output. Never author-set, so it
   * cannot be used to walk a made-up citation past the gate — and the gate does
   * not skip the check, it resolves it against THIS commit instead.
   */
  atCommit?: string;
  /**
   * The noise-by-construction class this finding was DEMOTED under — never
   * dismissed. Set by the scan's de-noising pass, not authored, and re-derived
   * on every scan, so it needs no merge preservation.
   *
   * It carries a suggested refutation ground (`NOISE_GROUND`) into the triage
   * and verify worklists, which is what lets forty identical test-harness
   * candidates cost one argued adjudication instead of forty restatements.
   */
  noise?: NoiseClass;
  /**
   * Whether anything places this finding on a path that runs — see
   * `REACHABILITIES`. Engine-derived evidence, never authored: absent simply
   * means the run did not establish it.
   */
  reachability?: Reachability;
  /**
   * The vulnerability class the AUTHOR named, when it differs from the storage
   * `category` it was folded onto.
   *
   * `category` records how a finding was surfaced, and it must stay a closed
   * vocabulary because dedup, correlation and ASVS scoring key on it. An auditor
   * filing a discovery names what the bug IS — "stored-xss", "idor", "ssrf" —
   * and `CATEGORY_ALIASES` folds that onto `taint`/`authz`/`other` so it can be
   * stored. Which worked, and then threw the answer away: on one real audit all
   * twelve semantic findings — three of them high-severity XSS — read as `sast`
   * in the report, and the class an auditor had actually determined appeared
   * nowhere.
   *
   * Set only on the fold, so a finding whose category was already canonical
   * carries nothing and the field stays absent from every engine-produced row.
   */
  vulnClass?: string;
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
  /** Jupyter notebooks: how many the walk found, how many were extracted, and
   *  what could not be aligned. Present only when the tree HAS notebooks — a
   *  repo with none stays silent, a repo whose notebooks could not be read says
   *  so, and those two cases produce identical findings lists otherwise. */
  notebooks?: { found: number; scanned: number; checkpoints: number; unaligned: number; note?: string };
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
  /** Which opt-in passes this run actually performed. The counts alone cannot
   *  say it: a run with `--log-hygiene` that found nothing and a run without the
   *  flag both produce zero logging findings, and the coverage advice used to
   *  tell the first user to enable an option they had already enabled.
   *  Additive/optional — dossiers written before this field existed omit it, and
   *  `undefined` means "unknown", never "off". */
  passes?: {
    /** `scan --sinks` (orphan-sink recall). */
    sinks?: boolean;
    /** `scan --log-hygiene` (CWE-117 taint sinks + the CWE-532 line pass). */
    logHygiene?: boolean;
    /** `scan --blame` (git provenance on every finding). */
    blame?: boolean;
    /** `scan --include-tests` (test-path candidates kept at full severity). */
    includeTests?: boolean;
    /**
     * `ultrasec guards` (the entry-point × guard matrix) ran against this run.
     *
     * It is what lets `coverage` stop describing CWE-306 and CWE-862 as
     * "judgment — not enumerated". Missing authorization has no line to
     * taint-trace, so before the matrix nothing in the engine could reach it,
     * and the honest coverage answer was that nobody had looked. Once the matrix
     * has run, every request handler HAS been enumerated and the remaining
     * question is which of them the auditor adjudicated.
     */
    guards?: boolean;
    /**
     * `ultrasec guards --lens throttle` (the entry-point × rate-limit matrix).
     *
     * The same absence question, asked of throttling instead of authorization,
     * and it unlocks the same kind of coverage claim: "missing rate limiting"
     * stops being a line in an advice string nobody can act on and becomes an
     * enumerated set of handlers with a marker or without one.
     */
    throttle?: boolean;
  };
  /** Findings de-prioritized as noise BY CONSTRUCTION, with the reason and how
   *  many. The engine's rule is that nothing disappears quietly: a class that
   *  cannot be a real finding (a secret inside a file that is ciphertext by
   *  design) is pushed down the report, and the run still says how many and why.
   *  Additive/optional — absent when nothing was downgraded. */
  downgraded?: { reason: string; count: number }[];
  /** Basename of the CycloneDX SBOM generated this run (`src/tools/sbom.ts`), a
   *  dossier deliverable in its own right and the input grype/package-checker
   *  prefer over re-walking the tree. Additive/optional; older dossiers and
   *  hosts without `syft` omit it. */
  sbom?: string;
  /**
   * What the dependency-reachability pass established, and from which files.
   *
   * `sources` is the accountability half: a `toolchain` mark damps a finding's
   * risk, so a reader has to be able to tell "no build-only advisories" from
   * "no lockfile that records dev-ness". npm lockfiles classify transitives;
   * `package.json` alone classifies direct devDependencies only.
   */
  reachability?: { toolchain: number; sources: string[] };
}
