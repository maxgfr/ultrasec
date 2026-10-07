import type { Category, Severity } from "../types.js";

// The weakness-class model, as types.
//
// Three layers, and only the first is meant to be stable:
//
//   1. a CLASS (registry.ts) — what must be true for code to be safe, defined
//      once and independently of any framework: an invariant, what a valid
//      guard looks like, examples in several languages, a severity rubric;
//   2. a PACK (packs/*.ts) — the idioms one ecosystem or framework writes that
//      class with, as data: the line that is unsafe, the line that guards it,
//      the version range the data was validated against (`testedWith`);
//   3. the HUNT (src/investigate.ts) — for a class × framework no pack covers,
//      the invariant and examples are handed to the auditor, who finds the
//      repository's own idioms and returns them as pack suggestions.
//
// A pack is a recall floor that can gate CI; it is not a claim of complete
// coverage. Adding a framework is adding data and fixtures — the engine
// (engine.ts) never learns a framework's name.

/** The ecosystems a pack can target. `*` is the language-agnostic pack. */
export const ECOSYSTEMS = ["node", "python", "java", "go", "ruby", "php"] as const;
export type Ecosystem = (typeof ECOSYSTEMS)[number];

export const CLASS_IDS = [
  "timing-unsafe-secret-compare",
  "csv-formula-injection",
  "client-ip-first-xff",
  "unbounded-public-export",
  "security-headers-absent",
  "session-cookie-chunks-on-logout",
  "env-bool-coercion",
] as const;
export type ClassId = (typeof CLASS_IDS)[number];

export interface ClassExample {
  /** An ultrasec language id (`javascript`, `python`, …). */
  language: string;
  vulnerable: string;
  fixed: string;
}

/** One weakness class — the part that does not age with a framework release. */
export interface WeaknessClass {
  id: ClassId;
  title: string;
  cwe: string;
  severity: Severity;
  category: Category;
  /** What must hold for the code to be safe, stated as source → sink → guard. */
  invariant: string;
  /** What a guard that actually establishes the invariant looks like. */
  guard: string;
  /** How to move the base severity up or down for a concrete instance. */
  rubric: string;
  /** Default finding text when a pack rule carries no note of its own. */
  note: string;
  examples: ClassExample[];
}

/**
 * A shape a rule reports under. Legacy shapes (`webconfig` / `authtokens`)
 * keep the ident, title and message the original detectors produced, so a
 * finding's content-derived id survives the move onto the class engine;
 * `class` is the shape of every idiom added since.
 */
export interface EmitShape {
  family: "webconfig" | "authtokens" | "class";
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  category: Category;
  note: string;
}

interface RuleBase {
  /** Unique within its pack. */
  id: string;
  /** ultrasec language ids (`src/lang.ts`) the rule reads. */
  languages: string[];
  /** Only files whose repo-relative path matches. */
  files?: RegExp;
  /** Legacy shape to report under, as `family/id` (e.g. `webconfig/csv-formula`). */
  emit?: string;
  /** Idiom-specific explanation; the class note is used when absent. */
  note?: string;
  /**
   * Fire only inside a package whose manifest declares this framework
   * (`src/frameworks.ts`). For postures whose anchor alone is weak evidence —
   * a `Flask(__name__)` in a throwaway script is not a deployed app.
   */
  requiresFramework?: string;
}

/** A code line that is unsafe on its own. */
export interface LineRule extends RuleBase {
  kind: "line";
  /** Tested on the line's CODE (comment stripped, strings kept). */
  match: RegExp;
  /** A guard on the same line clears it (tested on the code). */
  unless?: RegExp;
  /** Another code line within `before` lines above (or the line itself) must match. */
  context?: { re: RegExp; before: number };
  /** The file's raw text must match (e.g. "this file reads the environment"). */
  fileGate?: RegExp;
}

/** A file that produces something (a CSV, a logout) without ever guarding it. */
export interface FileRule extends RuleBase {
  kind: "file";
  /** The raw file must match all of these. */
  gate: RegExp[];
  /** The code line(s) the finding is cited on. */
  anchor: RegExp;
  /** Which anchor line to cite. */
  pick: "first" | "last";
  /** Guard: the file's code (comments stripped) matching this clears the file. */
  unless?: RegExp;
}

/** One way of starting a query, and what makes it bounded. */
export interface QueryIdiom {
  /** Where the statement starts (no `g` flag needed — the engine adds it). */
  start: RegExp;
  /** The statement must also contain this to be a query at all. */
  requires?: RegExp;
  /** The statement is bounded (paged, capped, streamed) when it contains this. */
  bounded: RegExp;
}

/** A query with no row limit inside a route that serves a public export. */
export interface RouteQueryRule extends RuleBase {
  kind: "route-query";
  /** The file is a route module by path… */
  routeFile?: RegExp;
  /** …whose path names an export… */
  exportPath: RegExp;
  /** …or the file declares a route whose path/name (capture group 1) names one. */
  routeDecl?: RegExp;
  queries: QueryIdiom[];
  /**
   * Where a statement ends. `js-legacy`: the first `;` or blank line (what the
   * original Next.js detector read). `balanced`: a `;` or a newline at paren
   * depth 0 that is not followed by a `.`-chained continuation.
   */
  statement: "js-legacy" | "balanced";
}

/**
 * A protection that is ABSENT. An absence has no line, so the finding is
 * grounded on the one line that does exist — where the protection would be
 * registered (the app constructor, the settings list, the config object).
 */
export interface AbsentRule extends RuleBase {
  kind: "absent";
  /** The code line to cite (first match in the file). */
  anchor: RegExp;
  /** Anchor only in files whose raw text also matches this. */
  fileGate?: RegExp;
  /** Cite line 1 when the file has no anchor line (a config with no object literal). */
  fallbackLine1?: boolean;
  /** Present in the anchor file's code → no finding. */
  presentInFile?: RegExp;
  /**
   * Present in any file of the app's own tree → no finding; a sibling app's
   * does not count. `scope: "anchor-dir"` is the anchor's directory subtree,
   * `package` the detected framework's package. `files`/`languages` narrow
   * which files are read for it.
   */
  presentInTree?: { re: RegExp; scope: "anchor-dir" | "package"; files?: RegExp; languages?: string[] };
}

/** Where a framework was detected — all the engine needs to gate and scope rules. */
export interface FrameworkScope {
  id: string;
  /** Repo-relative package directory (`""` = the repo root). */
  dir: string;
}

export type Rule = LineRule | FileRule | RouteQueryRule | AbsentRule;

/** What a pack says about one class: its idioms, or why the class does not apply. */
export type ClassCoverage = { rules: Rule[] } | { notApplicable: string };

export interface Pack {
  /** Unique pack id (`node`, `express`, `django`, …). */
  id: string;
  /** `*` for the language-agnostic pack. */
  ecosystem: Ecosystem | "*";
  /** Framework id from `src/frameworks.ts`; absent for an ecosystem-wide pack. */
  framework?: string;
  /**
   * Framework versions the rules were validated against by fixtures, as
   * space-separated comparators with `||` alternatives (`>=4 <6`). A detected
   * version outside it is DEGRADED coverage — reported and hunted, never
   * silently trusted.
   */
  testedWith?: string;
  /** Documentation the defaults encoded here were checked against. */
  sources?: string[];
  classes: Partial<Record<ClassId, ClassCoverage>>;
}
