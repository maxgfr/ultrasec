import { join } from "node:path";
import { encryptedShapeOf } from "./secrets.js";
import { readText } from "./walk.js";
import { isTestPath } from "./vendor/codeindex-engine.mjs";
import { NOISE_CLASSES, NOISE_GROUND, type Brocard, type Confidence, type Finding, type NoiseClass, type Severity } from "./types.js";

// ── Noise by construction ────────────────────────────────────────────────────
//
// Some findings are real matches on code that cannot carry the risk the finding
// describes: ciphertext in a file whose whole point is ciphertext, a taint path
// that never leaves the test harness, an entropy hit inside a vendored tool
// bundle. They are not false positives in the scanner's sense — the pattern is
// genuinely there — so refuting each one individually is honest work that
// produces the same sentence forty times.
//
// Measured on the first real-world audit: 46 of 62 taint candidates had every
// node inside `__tests__`/`*.e2e.ts` (37 of them the same `query()` sink), and
// 37 of 37 gitleaks findings were noise of one of these shapes.
//
// Three rules govern this pass, and each one is load-bearing:
//
// 1. DEMOTE, NEVER DROP. The finding stays, at a lower severity, with the
//    reason named in its message, and the count lands in `manifest.downgraded`.
//    Dropping would leave the run unable to say how many were suppressed, which
//    is the coverage dishonesty this engine argues against everywhere else.
//
// 2. NEVER AUTO-ADJUDICATE. Nothing here sets `status`, `verdict` or `brocard`.
//    Demotion's job is not to hide a finding — it is to state its severity
//    honestly, which is what moves it into the tier where `triage` is permitted
//    to clear it in one pass (`applyTriage` refuses `noise` on high/critical).
//    The verdict still has to be authored.
//
// 3. THE POSITION IS THE ARGUMENT. `NOISE_GROUND` maps each class onto an
//    existing brocard, so a reviewer disagrees with a row in that table rather
//    than with a new unfalsifiable ground.
//
// This pass runs AFTER `correlate`, on whole findings — deliberately outside the
// enumeration pipeline that `tests/golden-findings.test.ts` freezes. Filtering
// inside the catalog would delete the candidate instead, leaving nothing for the
// manifest to account for.

/** Tool bundles and third-party trees committed as build artifacts. */
const VENDORED_DIR = /(^|\/)(\.yarn\/(releases|plugins)|vendor|vendored|third_party|third-party|node_modules)\//i;
const MINIFIED = /\.min\.(js|mjs|cjs|css)$/i;

interface NoiseRule {
  id: NoiseClass;
  /** Severity floor. Never raises a finding — `worstOf` keeps the lower of the two. */
  severity: Severity;
  confidence: Confidence;
  /** Names what was checked, appended to the finding's message. */
  why: (f: Finding, repo: string) => string;
  matches: (f: Finding, repo: string) => boolean;
}

/** Every repo-relative location a finding cites. */
function locationsOf(f: Finding): string[] {
  const out: string[] = [];
  if (f.source?.file) out.push(f.source.file);
  if (f.sink?.file) out.push(f.sink.file);
  for (const p of f.path ?? []) if (p.file) out.push(p.file);
  return out;
}

const RULES: NoiseRule[] = [
  {
    id: "encrypted-at-rest",
    severity: "info",
    confidence: "low",
    why: (f, repo) => {
      const shape = f.sink?.file ? shapeOf(repo, f.sink.file) : undefined;
      return `de-prioritized: ${f.sink?.file} is a ${shape?.label ?? "ciphertext-by-design file"}, where ciphertext is the point of the file. Check that the ENCRYPTION KEY is not also committed, and that this really is the format it claims.`;
    },
    // Secret findings only: a SAST hit inside a SealedSecret is a different claim.
    matches: (f, repo) => f.category === "secret" && !!f.sink?.file && !!shapeOf(repo, f.sink.file),
  },
  {
    id: "test-only-path",
    severity: "low",
    confidence: "low",
    why: () =>
      `de-prioritized: every cited location is a test path, so the flow does not exist in the shipped artifact. Confirm the harness is not itself the product (fixtures served in production, a test route mounted by the app) before dismissing.`,
    // Deliberately scoped to the enumerated classes. A hardcoded credential in a
    // test file is a classic real leak — CI tokens live there — so `secret` and
    // `config` findings are NOT demoted for sitting in a test.
    matches: (f) => {
      if (f.category !== "taint" && f.category !== "sast") return false;
      const locs = locationsOf(f);
      return locs.length > 0 && locs.every((l) => isTestPath(l));
    },
  },
  {
    id: "vendored-artifact",
    severity: "info",
    confidence: "low",
    why: (f) =>
      `de-prioritized: ${f.sink?.file ?? f.source?.file} is a vendored or minified build artifact, not this repo's source. Fix it upstream or re-vendor; editing it here is overwritten by the next install.`,
    matches: (f) => {
      // A dependency advisory is keyed on the PACKAGE, not on a file — its
      // location, when it has one, is the lockfile that proves the version.
      if (f.category === "dep") return false;
      const at = f.sink?.file ?? f.source?.file;
      return !!at && (VENDORED_DIR.test(at) || MINIFIED.test(at));
    },
  },
];

/** Cached `encryptedShapeOf` — it reads the file to test the content marker. */
const shapeCache = new Map<string, ReturnType<typeof encryptedShapeOf>>();
function shapeOf(repo: string, rel: string): ReturnType<typeof encryptedShapeOf> {
  const key = `${repo}\u0000${rel}`;
  if (!shapeCache.has(key)) {
    let shape: ReturnType<typeof encryptedShapeOf>;
    try {
      shape = encryptedShapeOf(rel, readText(join(repo, rel)));
    } catch {
      shape = undefined; // unreadable — treat as ordinary, never as suppressed
    }
    shapeCache.set(key, shape);
  }
  return shapeCache.get(key);
}

/**
 * A machine-PROPOSED adjudication. Never applied, and deliberately not written
 * into the item's `verdict` field: a pre-filled verdict would make
 * `cp TRIAGE.todo.json TRIAGE.json` a passing adjudication, which is the
 * rubber-stamp this whole gate exists to prevent.
 *
 * What it removes is not the decision — it is having to reinvent the same
 * reasoning forty times. The agent still authors the verdict.
 */
export interface ProposedAdjudication {
  /** The noise class the engine recognised. */
  class: NoiseClass;
  /** The ground a dismissal on that basis would stand on (an existing brocard). */
  ground: Brocard;
  /** What was actually checked, so the proposal can be refused on its merits. */
  why: string;
}

/** The proposal for a finding, if the engine classified it. */
export function proposedFor(f: Finding): ProposedAdjudication | undefined {
  if (!f.noise) return undefined;
  return { class: f.noise, ground: NOISE_GROUND[f.noise], why: PROPOSAL_WHY[f.noise] };
}

/** One line per class, phrased as the claim a reviewer would have to refute. */
const PROPOSAL_WHY: Readonly<Record<NoiseClass, string>> = {
  "encrypted-at-rest": "the file is ciphertext by design — the blob is not the secret; check the KEY is not committed too",
  "test-only-path": "every node of the path is a test path — it does not exist in the shipped artifact",
  "vendored-artifact": "a vendored or minified upstream build artifact, byte-identical to a published release",
};

export interface DemoteOptions {
  /** Keep test-path candidates at full severity (`scan --include-tests`) — for
   *  auditing the test suite itself, which is a real thing to want. */
  includeTests?: boolean;
}

/** The class a finding belongs to, if any. First match wins, in RULES order. */
export function classifyNoise(f: Finding, repo: string, opts: DemoteOptions = {}): NoiseClass | undefined {
  // A scanner that VERIFIED the credential against its provider has evidence no
  // file format can override: a live credential is live, wherever it sits.
  if (f.verified) return undefined;
  for (const rule of RULES) {
    if (rule.id === "test-only-path" && opts.includeTests) continue;
    if (rule.matches(f, repo)) return rule.id;
  }
  return undefined;
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
/** The LOWER of two severities — a floor never promotes a finding. */
function floorOf(current: Severity, floor: Severity): Severity {
  return SEVERITY_ORDER.indexOf(current) >= SEVERITY_ORDER.indexOf(floor) ? current : floor;
}

/**
 * De-prioritize noise-by-construction findings and report what was demoted.
 *
 * Returns the manifest's `downgraded` shape directly — one row per class, so a
 * suppressed class is always something the run can account for by name.
 */
export function demoteNoise(
  findings: Finding[],
  repo: string,
  opts: DemoteOptions = {},
): { findings: Finding[]; downgraded: { reason: string; count: number }[] } {
  const counts = new Map<NoiseClass, number>();
  const byId = new Map(RULES.map((r) => [r.id, r]));

  const out = findings.map((f) => {
    const cls = classifyNoise(f, repo, opts);
    if (!cls) return f;
    const rule = byId.get(cls)!;
    counts.set(cls, (counts.get(cls) ?? 0) + 1);
    return {
      ...f,
      severity: floorOf(f.severity, rule.severity),
      confidence: rule.confidence,
      noise: cls,
      message: `${f.message} — ${rule.why(f, repo)}`,
    };
  });

  // Stable order (RULES order), and only classes that actually fired.
  const downgraded = NOISE_CLASSES.filter((c) => counts.has(c)).map((c) => ({ reason: c, count: counts.get(c)! }));
  return { findings: out, downgraded };
}
