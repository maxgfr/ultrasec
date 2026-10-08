import { lineCount } from "../check.js";
import type { Severity } from "../types.js";
import type { Phase } from "./brief.js";
import { ADVISORY, FIX_FIELD, HISTORY, SCENARIO_FIELD, SECTION_WORDS, SEVERITY_FIELD, SEVERITY_WORDS } from "./locale.js";
import { placeholderArtefacts, redactReviewerText } from "./redact.js";
import { BRIEF_PREFIX } from "./snapshot.js";

// Turning a reviewer's Markdown into claims the orchestrator can check.
//
// Deterministic and fail-closed on the one thing that matters: a citation is
// `ok` only when the file exists in the snapshot and the line is in range. A
// claim is never accepted here — this module only says what each reviewer
// SAID and whether its `path:line` points at real text. On the audit this was
// built from, four confident external claims were false; every one of them
// still had to be read by hand, and a claim whose citation does not resolve is
// the cheapest one to discard.

export type CitationState = "ok" | "unresolved";

export interface Citation {
  /** As written by the reviewer. */
  raw: string;
  /** Snapshot-relative path, after resolution. */
  file: string;
  line: number;
  endLine?: number;
  citation: CitationState;
  reason?: string;
  /** Set when a bare basename was resolved to the one file carrying it. */
  resolvedFrom?: string;
}

export type ClaimSection = "finding" | "new" | "contest";

export interface Claim {
  reviewer: string;
  phase: Phase;
  section: ClaimSection;
  /** The reviewer's own id (`R3`), or — on a contested finding — its id. */
  ref: string;
  title: string;
  severity?: Severity;
  cwe?: string;
  citations: Citation[];
  scenario?: string;
  fix?: string;
  /** The block, secrets redacted, truncated. */
  excerpt: string;
  /** Secret-masking placeholders the block leans on (see redact.ts). */
  artefacts: string[];
  /** Facts the reviewer could not have known on a snapshot — engine-verifiable. */
  verify: string[];
  cves: string[];
}

/** The tree a citation is resolved against: the snapshot, i.e. HEAD. */
export interface TreeIndex {
  root: string;
  files: ReadonlySet<string>;
  byBase: ReadonlyMap<string, string[]>;
}

export function indexTree(root: string, files: readonly string[]): TreeIndex {
  const byBase = new Map<string, string[]>();
  for (const f of files) {
    const base = f.slice(f.lastIndexOf("/") + 1);
    const arr = byBase.get(base) ?? byBase.set(base, []).get(base)!;
    arr.push(f);
  }
  return { root, files: new Set(files), byBase };
}

export function parseSeverity(text: string): Severity | undefined {
  const field = text.match(SEVERITY_FIELD)?.[1];
  const word = (s: string | undefined): Severity | undefined => {
    if (!s) return undefined;
    const m = s.toLowerCase().match(/\p{L}+/u);
    return m && Object.hasOwn(SEVERITY_WORDS, m[0]) ? SEVERITY_WORDS[m[0]] : undefined;
  };
  return word(field) ?? word(text.match(BRACKETED_SEVERITY)?.[1]);
}

/** `[high]`, `(critical)` — a severity word in brackets, in any locale. */
const BRACKETED_SEVERITY = new RegExp(`[[(](${Object.keys(SEVERITY_WORDS).join("|")})[\\])]`, "iu");

/** Bare files a citation may name without an extension. */
const NO_EXT = new Set(["Dockerfile", "Makefile", "Procfile", "Gemfile", "Rakefile", "Jenkinsfile", "Vagrantfile", "Caddyfile", "Brewfile", "Containerfile"]);
/** Host suffixes: `db.internal:5432` is an address, not a file. */
const HOST_SUFFIX = /\.(?:com|net|org|io|dev|local|localhost|internal|cloud|fr|eu|co|ai|svc|cluster|example|test)$/i;

/** Could this token be a file path (rather than a host, an IP, a version)? */
export function looksLikeFile(token: string): boolean {
  const base = token.slice(token.lastIndexOf("/") + 1);
  if (!base) return false;
  if (/^\d+(?:\.\d+){1,3}$/.test(base)) return false; // 0.0.0.0, 1.2.3
  if (!token.includes("/") && HOST_SUFFIX.test(base)) return false;
  return /\.[A-Za-z][A-Za-z0-9]*$/.test(base) || NO_EXT.has(base) || /^\.[\w.-]+$/.test(base);
}

// `path:line`, `path:start-end`, `path:line:col`, backticked or bare. The
// lookbehind refuses a start inside a word or right after `/`, `@` or `.`, so
// `https://host:443` and `user@host:22` never begin a match mid-token.
const CITE = /(?<![\w./@-])((?:[\w@.+-]+\/)*[\w@.+-]+):(\d+)(?:[-–](\d+))?/g;
const CITE_GH = /(?<![\w./@-])((?:[\w@.+-]+\/)*[\w@.+-]+)#L(\d+)(?:-L?(\d+))?/g;

/** Every `path:line` mention in a block, in order, de-duplicated by raw text. */
export function extractCitations(text: string): { raw: string; file: string; line: number; endLine?: number }[] {
  const out: { raw: string; file: string; line: number; endLine?: number }[] = [];
  const seen = new Set<string>();
  for (const re of [CITE, CITE_GH]) {
    for (const m of text.matchAll(re)) {
      const file = m[1]!;
      if (!looksLikeFile(file)) continue;
      const line = Number(m[2]);
      const end = m[3] ? Number(m[3]) : undefined;
      const raw = m[0];
      if (seen.has(raw)) continue;
      seen.add(raw);
      out.push({ raw, file, line, ...(end !== undefined && end > line ? { endLine: end } : {}) });
    }
  }
  return out;
}

/** Resolve one mention against the snapshot. */
export function resolveCitation(
  idx: TreeIndex,
  c: { raw: string; file: string; line: number; endLine?: number },
  lines: (f: string) => number | null,
): Citation {
  let file = c.file.replace(/^\.\//, "");
  const rootPrefix = `${idx.root.replace(/\/+$/, "")}/`;
  if (file.startsWith(rootPrefix)) file = file.slice(rootPrefix.length);
  else if (file.startsWith("/") && idx.files.has(file.slice(1))) file = file.slice(1);
  const base = { raw: c.raw, line: c.line, ...(c.endLine ? { endLine: c.endLine } : {}) };
  const bad = (reason: string): Citation => ({ ...base, file, citation: "unresolved", reason });

  if (file.startsWith(BRIEF_PREFIX)) return bad("cites the council brief, not the code");
  let resolvedFrom: string | undefined;
  if (!idx.files.has(file)) {
    if (file.includes("/")) return bad("file not found in the snapshot");
    // A bare basename resolves ONLY when one file carries it — guessing between
    // two `index.ts` would turn a vague claim into a precise false one.
    const hits = idx.byBase.get(file) ?? [];
    if (hits.length !== 1) return bad(hits.length ? `ambiguous basename (${hits.length} files)` : "file not found in the snapshot");
    resolvedFrom = file;
    file = hits[0]!;
  }
  const lc = lines(file);
  if (lc === null) return bad("file not readable");
  const last = c.endLine ?? c.line;
  if (c.line < 0 || c.line > lc || last > lc) return { ...bad(`line out of range (file has ${lc} lines)`), ...(resolvedFrom ? { resolvedFrom } : {}) };
  return { ...base, file, citation: "ok", ...(resolvedFrom ? { resolvedFrom } : {}) };
}

function verifyNotes(text: string): string[] {
  const notes: string[] = [];
  if (ADVISORY.test(text)) notes.push("advisory/version status asserted without an advisory database — check the run's own dependency-scanner results");
  if (HISTORY.test(text)) notes.push("history asserted on a snapshot with no git history — check with `revalidate` / git log");
  return notes;
}

const MAX_EXCERPT = 1500;

/** The kind of claims a `##` section holds: its letter (A/B/C, language-neutral) or a heading word of any locale. */
function sectionOf(heading: string, phase: Phase): ClaimSection | "skip" {
  const h = heading.toLowerCase();
  const has = (words: readonly string[]): boolean => words.some((w) => h.includes(w));
  if (/^##\s+a[.)]\s/.test(h) || has(SECTION_WORDS.contested)) return "contest";
  if (/^##\s+b[.)]\s/.test(h) || has(SECTION_WORDS.newFindings)) return "new";
  if (/^##\s+c[.)]\s/.test(h) || has(SECTION_WORDS.noClaims)) return "skip";
  return phase === "devil" ? "new" : "finding";
}

function splitHeading(raw: string, n: number): { ref: string; title: string } {
  const text = raw.replace(/^#{3,4}\s+/, "").trim();
  const m = text.match(/^(.+?)\s+[—–-]\s+(.+)$/) ?? text.match(/^([^:]{1,40}):\s+(.+)$/);
  const clean = (s: string) => s.replace(/[*`[\]]/g, "").trim();
  if (m) return { ref: clean(m[1]!), title: clean(m[2]!) };
  return { ref: `#${n}`, title: clean(text) };
}

/**
 * Parse one reviewer report into claims. `###`/`####` blocks are claims; the
 * `##` section they sit under says what kind (a devil's-advocate report has
 * `A.` contested findings, `B.` new findings, `C.` coverage, headed in any
 * locale of `locale.ts`). Coverage and to-verify sections carry no claims.
 * `placeholders` adds masking-placeholder shapes to the defaults.
 */
export function parseReport(md: string, who: { reviewer: string; phase: Phase }, idx: TreeIndex, opts: { placeholders?: readonly RegExp[] } = {}): Claim[] {
  const ph = opts.placeholders ?? [];
  const lineCache = new Map<string, number | null>();
  const lines = (f: string): number | null => {
    if (!lineCache.has(f)) lineCache.set(f, lineCount(idx.root, f));
    return lineCache.get(f)!;
  };
  const claims: Claim[] = [];
  let section: ClaimSection | "skip" = who.phase === "devil" ? "new" : "finding";
  let block: string[] | undefined;
  let n = 0;

  const flush = (): void => {
    if (!block || section === "skip") {
      block = undefined;
      return;
    }
    const raw = block.join("\n");
    const { ref, title } = splitHeading(block[0]!, ++n);
    const severity = parseSeverity(raw);
    const cwe = raw.match(/\bCWE[-‐–\s]?(\d{1,4})\b/i)?.[1];
    const scenario = raw.match(SCENARIO_FIELD)?.[1]?.trim();
    const fix = raw.match(FIX_FIELD)?.[1]?.trim();
    const excerpt = redactReviewerText(raw, ph);
    claims.push({
      reviewer: who.reviewer,
      phase: who.phase,
      section,
      ref: redactReviewerText(ref, ph),
      title: redactReviewerText(title, ph),
      ...(severity ? { severity } : {}),
      ...(cwe ? { cwe: `CWE-${Number(cwe)}` } : {}),
      citations: extractCitations(raw).map((c) => resolveCitation(idx, c, lines)),
      ...(scenario ? { scenario: redactReviewerText(scenario, ph).slice(0, 400) } : {}),
      ...(fix ? { fix: redactReviewerText(fix, ph).slice(0, 400) } : {}),
      excerpt: excerpt.length > MAX_EXCERPT ? `${excerpt.slice(0, MAX_EXCERPT)}…` : excerpt,
      // On the RAW block: a placeholder is an artefact whether or not our own
      // redaction would have masked what surrounds it.
      artefacts: placeholderArtefacts(raw, ph),
      verify: verifyNotes(raw),
      cves: [...new Set([...raw.matchAll(/\bCVE-\d{4}-\d{3,}\b/gi)].map((m) => m[0].toUpperCase()))],
    });
    block = undefined;
  };

  let fence = false;
  for (const line of md.split("\n")) {
    if (/^\s*```/.test(line)) fence = !fence;
    if (!fence && /^##\s/.test(line)) {
      flush();
      section = sectionOf(line, who.phase);
      continue;
    }
    if (!fence && /^#{3,4}\s+\S/.test(line)) {
      flush();
      block = [line];
      continue;
    }
    block?.push(line);
  }
  flush();
  return claims;
}
