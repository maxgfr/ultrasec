import { join } from "node:path";
import { encryptedShapeOf } from "./secrets.js";
import { readText } from "./walk.js";
import { fileContentAtCommit, lineContentAtCommit } from "./git.js";
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
/**
 * A path that is not this repo's source.
 *
 * Deliberately the same vocabulary as the walker's `DEFAULT_IGNORE_DIRS`, plus
 * the package-manager and Python trees that only ever appear in a scanner's
 * output. It used to list five directories where the walker skipped seventeen,
 * so the two disagreed about what "vendored" means — and `.venv/` and `.next/`,
 * which between them accounted for 541 findings on one audit, fell in the gap.
 *
 * This is the belt to the prune matcher's braces. `buildPruneMatcher` now drops
 * these paths from scanner output before they ever become findings; a finding
 * that still arrives with such a path (an `--include-vendored` run, a scanner
 * reporting a location the matcher could not parse) is demoted rather than
 * ranked.
 *
 * `.ipynb_checkpoints/` joins the list for the same reason `.next/` did: it is
 * Jupyter's autosave, a stale copy of the notebook beside it, and every finding
 * in it is a second copy of one in real source. The notebook pass skips it
 * outright; this catches whatever reaches a finding by another route (a secret
 * scanner reading the raw file, an `--include-vendored` run).
 */
const VENDORED_DIR =
  /(^|\/)(\.yarn\/(releases|plugins)|vendor|vendored|third_party|third-party|node_modules|\.pnpm|bower_components|site-packages|\.venv|venv|__pycache__|\.tox|\.ipynb_checkpoints|dist|build|out|target|coverage|\.next|\.nuxt|\.svelte-kit|\.turbo|\.gradle)\//i;
const MINIFIED = /\.min\.(js|mjs|cjs|css)$/i;

/** Classes `test-only-path` may demote. `secret` is deliberately absent (see the rule). */
const TEST_DEMOTABLE: ReadonlySet<Finding["category"]> = new Set(["taint", "sast", "crypto", "authz", "config"]);

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
      const shape = f.sink?.file ? shapeOf(repo, f.sink.file, f.atCommit) : undefined;
      return `de-prioritized: ${f.sink?.file} is a ${shape?.label ?? "ciphertext-by-design file"}, where ciphertext is the point of the file. Check that the ENCRYPTION KEY is not also committed, and that this really is the format it claims.`;
    },
    // Keyed on the CLAIM, not on which tool made it.
    //
    // This used to read `f.category === "secret"`, on the reasoning that a SAST
    // hit inside a SealedSecret is a different claim. The reasoning is right;
    // the test was not. `category` records HOW a finding was surfaced, so the
    // same "there is a credential on this line" claim arrives as `secret` from
    // gitleaks and as `sast` from semgrep's own secret rules — and on a real
    // audit 7 semgrep CWE-798 hits on `*.sealed-secret.yaml` therefore stayed
    // at HIGH while the 34 gitleaks hits on the same files were demoted. Same
    // files, same claim, opposite treatment, and the seven were counted as
    // unread candidates in the report.
    //
    // CWE-798 (use of hard-coded credentials) is what makes it a secret claim.
    // A SAST finding on a sealed-secret file that claims something ELSE — a
    // malformed manifest, a bad apiVersion — carries a different CWE and is
    // still left at full severity, which is what the original note meant.
    matches: (f, repo) => (f.category === "secret" || f.cwe?.toUpperCase() === "CWE-798") && !!f.sink?.file && !!shapeOf(repo, f.sink.file, f.atCommit),
  },
  {
    id: "test-only-path",
    severity: "low",
    confidence: "low",
    why: () =>
      `de-prioritized: every cited location is a test path, so the flow does not exist in the shipped artifact. Confirm the harness is not itself the product (fixtures served in production, a test route mounted by the app) before dismissing.`,
    // Deliberately scoped to the enumerated classes. A hardcoded credential in a
    // test file is a classic real leak — CI tokens live there — so `secret`
    // findings are NOT demoted for sitting in a test (`committed-password-hash`
    // must stay loud). `crypto`, `authz` and `config` claims, on the other hand,
    // describe a flow the test harness performs — a `jwt-alg-none` assertion
    // string, a `verify: false` in a fixture client, a weak hash in a helper —
    // and on the self-audit three of the six "critical"s were exactly that.
    matches: (f) => {
      if (!TEST_DEMOTABLE.has(f.category)) return false;
      const locs = locationsOf(f);
      return locs.length > 0 && locs.every((l) => isTestPath(l));
    },
  },
  {
    // The flagged value is a RESOURCE identifier, not a credential.
    //
    // `const SPREADSHEET_KEY = "1a2b…"` is a Google Sheets document id. gitleaks
    // rates it a "Generic API Key" on entropy — helped along by the word KEY in
    // the name — but holding a document id is not holding access to the
    // document: the sharing setting is, and that is not in the repo. Seven of
    // the 37 false positives on the first real audit were exactly this.
    //
    // The claim here is narrow and checkable: the NAME says what the value is.
    // It is deliberately NOT the claim "this document is public", which nothing
    // in the repo can establish — so the message asks for that check rather than
    // making it, and the finding is demoted to `low`, not `info`.
    id: "resource-identifier",
    severity: "low",
    confidence: "low",
    why: (f) =>
      `de-prioritized: ${f.sink?.file}:${f.sink?.line} assigns a resource/document identifier, not a credential — possessing the id is not possessing access. CHECK the document's sharing setting and whether its contents are sensitive; that is not knowable from this repo.`,
    matches: (f, repo) => {
      if (f.category !== "secret" || !f.sink?.file) return false;
      const line = lineAt(repo, f.sink.file, f.sink.line, f.atCommit);
      if (!line) return false;
      // Both must hold: a name that says "document", and a value that is not a
      // recognisable credential. A real key in a badly-named variable still fires.
      return RESOURCE_NAME.test(line) && !CREDENTIAL_SHAPE.test(line);
    },
  },
  {
    // The cited line DECLARES a dangerous pattern rather than performing one.
    //
    // Found by auditing ultrasec with ultrasec: `src/authtokens.ts` holds the
    // rules that detect `alg: none` and `wantAssertionsSigned: false`, and the
    // `note:` fields quoting those strings matched the rules describing them —
    // two CRITICALs on a file whose entire job is to name that bug.
    //
    // Not specific to security tools. WAF signature sets, custom lint rules,
    // payload corpora and security documentation all carry the pattern they
    // warn about, and the line-regex auditors cannot tell a string from a
    // statement.
    id: "pattern-declaration",
    severity: "info",
    confidence: "low",
    why: (f) =>
      `de-prioritized: ${f.sink?.file}:${f.sink?.line} declares a pattern rather than performing the operation — it is a rule/metadata field, a bare regex literal, or a comment. Confirm the value is not ALSO applied somewhere — a rule file that configures the running system is both.`,
    matches: (f, repo) => {
      // Dep advisories key on the package; taint paths are multi-node and this
      // asks about ONE cited line.
      if (f.category === "dep" || !f.sink?.file) return false;
      const line = lineAt(repo, f.sink.file, f.sink.line, f.atCommit);
      return !!line && (PATTERN_METADATA.test(line) || BARE_REGEX_LINE.test(line) || WHOLE_LINE_COMMENT.test(line));
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

/**
 * A property whose NAME says the value is rule metadata, holding a quoted string
 * or a regex. Anchored at the start of the line, so only the line's first
 * property counts — `note: "…"` is metadata; `algorithms: ["none"]` is config.
 */
const PATTERN_METADATA =
  /^\s*(?:re|regex|regexp|pattern|patterns|rule|rules|note|title|description|detail|remediation|example|examples|hint|advice|summary|docs?)\s*:\s*(?:\/|["'`])/;

/**
 * An identifier whose NAME says the value addresses a document or a resource.
 * `KEY` alone is not enough — that is the word that made gitleaks fire.
 */
const RESOURCE_NAME =
  /\b(?:SPREADSHEET|SHEET|WORKSHEET|DOC|DOCUMENT|FOLDER|DRIVE|DATASET|CALENDAR|PROJECT|BUCKET|WORKSPACE|CHANNEL|TENANT|ORG|GROUP)[_-]?(?:KEY|ID|GID|UUID|SLUG)\b/i;

/**
 * Shapes that ARE credentials whatever the variable is called — a private key
 * block, a JWT, or a provider-prefixed token. Their presence overrides the name.
 */
const CREDENTIAL_SHAPE =
  /-----BEGIN|\beyJ[A-Za-z0-9_-]{10,}|\bAKIA[0-9A-Z]{12,}|\b(?:sk|rk)-[A-Za-z0-9]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bxox[baprs]-|\bAIza[0-9A-Za-z_-]{30,}/;

/**
 * A whole-line comment. Commented-out code is not executed and an explanatory
 * comment is not an operation, so a detector matching one has matched prose.
 * Anchored at the line start, so a statement with a trailing comment is
 * untouched.
 */
const WHOLE_LINE_COMMENT = /^\s*(?:\/\/|#|\*|<!--)/;

/** A line that is nothing but a regex literal — how rule arrays are written. */
const BARE_REGEX_LINE = /^\s*\/(?:[^/\\\n]|\\.)+\/[gimsuy]*\s*,?\s*$/;

/**
 * One line of a repo file, or `undefined` if it cannot be read.
 *
 * A finding from a scan of git HISTORY cites a file that may not exist at HEAD,
 * so `atCommit` is read from that commit instead. Without this the two
 * line-reading classes below silently never fire on history findings — which is
 * exactly the population they exist for: a scanner reads every commit, and the
 * secrets worth classifying are usually the ones someone already deleted.
 */
const lineCache = new Map<string, string[] | undefined>();
function lineAt(repo: string, rel: string, line: number, commit?: string): string | undefined {
  if (commit) return lineContentAtCommit(repo, commit, rel, line) ?? undefined;
  const key = `${repo}\u0000${rel}`;
  if (!lineCache.has(key)) {
    try {
      lineCache.set(key, readText(join(repo, rel)).split(/\r?\n/));
    } catch {
      lineCache.set(key, undefined); // unreadable — treat as ordinary code
    }
  }
  return lineCache.get(key)?.[line - 1];
}

/** Cached `encryptedShapeOf` — it reads the file to test the content marker. */
const shapeCache = new Map<string, ReturnType<typeof encryptedShapeOf>>();
function shapeOf(repo: string, rel: string, commit?: string): ReturnType<typeof encryptedShapeOf> {
  const key = `${repo}\u0000${commit ?? ""}\u0000${rel}`;
  if (!shapeCache.has(key)) {
    let content: string | undefined;
    // A history-scanned finding cites a file that may be gone from HEAD, so read
    // it from the commit the scanner named.
    if (commit) content = fileContentAtCommit(repo, commit, rel) ?? undefined;
    if (content === undefined) {
      try {
        content = readText(join(repo, rel));
      } catch {
        content = undefined;
      }
    }
    // Unreadable either way: `encryptedShapeOf` matches the path suffix BEFORE
    // it looks at content, so an empty read still recognises
    // `*.sealed-secret.yaml`. The filename is a claim the file makes about
    // itself, and refusing to classify a deleted file that plainly says what it
    // is would leave the entire deleted-secrets population unclassified — the
    // very population a history scan exists to surface.
    shapeCache.set(key, encryptedShapeOf(rel, content ?? ""));
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

/**
 * The proposed classes across a worklist, named ONCE each with their ground and
 * their members — the only grouping this design does.
 *
 * Grouping saves no verdict (`check --semantic` counts per finding) and must not
 * try to: a group that fans out would let one row rewrite findings the apply file
 * never named. What it saves is READING. A brief carrying 46 identical
 * "every node of this path is a test path" lines buries the handful of items
 * that need thought; naming the class once and listing its members does not.
 *
 * Returns `[]` when nothing was classified, so the block is presence-gated and a
 * run without demotions renders byte-identically to before.
 */
export function proposalSummary(
  items: readonly { id: string; proposed?: ProposedAdjudication }[],
): { class: NoiseClass; ground: Brocard; why: string; ids: string[] }[] {
  const byClass = new Map<NoiseClass, { class: NoiseClass; ground: Brocard; why: string; ids: string[] }>();
  for (const it of items) {
    if (!it.proposed) continue;
    const row = byClass.get(it.proposed.class) ?? { class: it.proposed.class, ground: it.proposed.ground, why: it.proposed.why, ids: [] };
    row.ids.push(it.id);
    byClass.set(it.proposed.class, row);
  }
  // Stable order: the vocabulary's own.
  return NOISE_CLASSES.filter((c) => byClass.has(c)).map((c) => byClass.get(c)!);
}

/** Markdown lines for `proposalSummary`, or `[]` when nothing was classified. */
export function renderProposalSummary(items: readonly { id: string; proposed?: ProposedAdjudication }[]): string[] {
  const rows = proposalSummary(items);
  if (!rows.length) return [];
  const L: string[] = [`## Proposed noise classes (${rows.length})`, ""];
  L.push(`_The engine classified these as noise BY CONSTRUCTION and DEMOTED them — it did not`);
  L.push(`adjudicate them. Each row is a suggestion with a named ground: accept it per item, or`);
  L.push(`refuse it. Read the caveat — a demotion you cannot interrogate is a silent filter._`);
  L.push("");
  for (const r of rows) {
    L.push(`- **${r.class}** (${r.ids.length}) → ground \`${r.ground}\` — ${r.why}`);
    const shown = r.ids.slice(0, SUMMARY_IDS);
    L.push(`  - ${shown.map((i) => `\`${i}\``).join(", ")}${r.ids.length > shown.length ? `, … and ${r.ids.length - shown.length} more` : ""}`);
  }
  L.push("");
  return L;
}

/** Enough ids to recognise the family without reprinting the worklist. */
const SUMMARY_IDS = 8;

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
  "pattern-declaration": "the cited line declares the pattern (rule metadata or a bare regex) rather than performing the operation",
  "resource-identifier": "the value addresses a document, it is not a credential — but confirm the document's sharing setting, which this repo cannot tell you",
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
    // Already classified: count it, change nothing. Demotion appends to
    // `message`, so a second pass over the same finding would grow the sentence
    // every time — the same non-idempotence `stageNotes` exists to prevent for
    // verdicts. Counting it keeps the manifest's `downgraded` an honest tally of
    // the WHOLE dossier rather than of whichever findings this pass happened to
    // produce, which is what a `--merge` run needs.
    if (f.noise) {
      counts.set(f.noise, (counts.get(f.noise) ?? 0) + 1);
      return f;
    }
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
