import { readFileSync, readdirSync, lstatSync, statSync, realpathSync, type Dirent } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { byStr } from "./util.js";
import { isIgnored as engineIsIgnored, parseGitignore as engineParseGitignore, type IgnoreRule as EngineIgnoreRule } from "./vendor/codeindex-engine.mjs";

// Directories never worth scanning for a security audit (vendored code, build
// output, VCS internals). Kept conservative + deterministic.
const DEFAULT_IGNORE_DIRS = new Set([
  ".git",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "out",
  "target",
  ".next",
  ".nuxt",
  "coverage",
  ".venv",
  "venv",
  "__pycache__",
  ".gradle",
  ".idea",
  ".vscode",
  ".ultrasec",
]);

const MAX_FILE_BYTES = 1_500_000; // skip huge/minified blobs

export interface WalkedFile {
  /** Repo-relative POSIX path. */
  rel: string;
  /** Absolute path. */
  abs: string;
  bytes: number;
}

export interface WalkOptions {
  ignoreDirs?: Set<string>;
  maxBytes?: number;
  /** Limit the walk to these subdir/glob roots (the load-bearing scale knob — prunes
   *  out-of-scope directory trees during recursion so a huge repo is never fully walked). */
  scope?: string[];
  /** Keep only files whose repo-relative path matches one of these globs. */
  include?: string[];
  /** Drop files (and prune directory trees) whose path matches one of these globs. */
  exclude?: string[];
  /** Stop after this many files (sets `truncated`). Guards against unbounded walks. */
  maxFiles?: number;
  /** Also honour the repo-root `.gitignore` (opt-in; common patterns only). */
  gitignore?: boolean;
}

export interface WalkResult {
  files: WalkedFile[];
  /** True when `maxFiles` cut the walk short — some files were not enumerated. */
  truncated: boolean;
  /** Number of in-scope files pushed (== files.length; the visible total). */
  totalSeen: number;
}

// ── Zero-dependency glob matching ────────────────────────────────────────────
// Supports `*` (any run within a path segment), `**` (across segments), `?` (one
// non-slash char), and a trailing `/` (match the dir and everything under it).
// Anchored to the repo-relative POSIX path. `**/x` matches `x` at any depth
// (including the root), mirroring .gitignore / Semgrep conventions.
export function globToRe(pattern: string): RegExp {
  let p = pattern.replace(/^\.\//, "").replace(/\/+$/g, (m) => (m ? "/" : "")); // collapse trailing slashes to one
  let dirMatch = false;
  if (p.endsWith("/")) {
    dirMatch = true;
    p = p.slice(0, -1);
  }
  let re = "";
  let i = 0;
  while (i < p.length) {
    if (p.startsWith("**/", i)) {
      re += "(?:.*/)?";
      i += 3;
      continue;
    }
    if (p.startsWith("**", i)) {
      re += ".*";
      i += 2;
      continue;
    }
    const ch = p[i]!;
    if (ch === "*") {
      re += "[^/]*";
      i++;
    } else if (ch === "?") {
      re += "[^/]";
      i++;
    } else if (ch === "[") {
      // POSIX-style character class ([abc], [!a-z]) — translate, don't escape.
      let j = i + 1;
      const neg = p[j] === "!" || p[j] === "^";
      if (neg) j++;
      if (p[j] === "]") j++; // a ']' right after '[' (or '[!') is a literal member
      while (j < p.length && p[j] !== "]") {
        if (p[j] === "\\") j++; // honour an escaped char so an escaped ']' isn't the terminator
        j++;
      }
      if (j >= p.length) {
        re += "\\["; // no closing ']' → a literal '['
        i++;
      } else {
        // De-escape members, then escape only what a regex class needs (\ and ]).
        const cls = p
          .slice(neg ? i + 2 : i + 1, j)
          .replace(/\\(.)/g, "$1")
          .replace(/[\\\]]/g, "\\$&");
        re += neg ? `[^/${cls}]` : `[${cls}]`; // negated class still never matches '/'
        i = j + 1;
      }
    } else {
      re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
      i++;
    }
  }
  const body = dirMatch ? re + "(?:/.*)?" : re;
  // Total by construction: a malformed class (e.g. a reversed range [z-a]) must
  // never crash a scan — fall back to matching the pattern literally, like git
  // gracefully ignoring an invalid pattern.
  try {
    return new RegExp("^" + body + "$");
  } catch {
    return new RegExp("^" + pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$");
  }
}

/** How deep to look for nested `.gitignore` files. Generous — a monorepo keeps
 *  one per package — but bounded, so a pathological tree cannot stall a scan. */
const GITIGNORE_MAX_DEPTH = 8;

/** Options for `buildPruneMatcher` — the prune half of the walk options, which
 *  is all that is meaningful for a path the walker never produced. */
export interface PruneOptions {
  gitignore?: boolean;
  exclude?: string[];
}

/**
 * One predicate for "the walk would have pruned this path", reusable by anything
 * that produces repo-relative paths of its own — above all the external
 * scanners, which get the raw repo bind-mounted and have never seen `--gitignore`.
 *
 * Built from the VENDORED ENGINE's `parseGitignore`/`isIgnored`, not from the
 * local pair in this file, and deliberately so: the engine honours nested
 * `.gitignore` files while the local `walkWithMeta` reads only the root's. A
 * filter that disagreed with the walker about what is ignored would replace one
 * inconsistency with a subtler one.
 *
 * Returns `undefined` when nothing would be pruned, so callers can skip the work
 * entirely and stay byte-identical to the un-pruned path.
 */
export function buildPruneMatcher(root: string, opts: PruneOptions): ((rel: string) => boolean) | undefined {
  const excludeRes = opts.exclude?.length ? opts.exclude.map(globToRe) : undefined;
  const rules: EngineIgnoreRule[] = [];
  if (opts.gitignore) {
    const visit = (dir: string, baseRel: string, depth: number): void => {
      if (depth > GITIGNORE_MAX_DEPTH) return;
      let entries: Dirent[];
      try {
        entries = readdirSync(dir, { withFileTypes: true });
      } catch {
        return; // unreadable directory: not a reason to fail the audit
      }
      if (entries.some((e) => e.isFile() && e.name === ".gitignore")) {
        try {
          rules.push(...engineParseGitignore(readFileSync(join(dir, ".gitignore"), "utf8"), baseRel));
        } catch {
          /* unreadable .gitignore — the rest still applies */
        }
      }
      for (const e of entries) {
        if (!e.isDirectory() || DEFAULT_IGNORE_DIRS.has(e.name)) continue;
        visit(join(dir, e.name), baseRel ? `${baseRel}/${e.name}` : e.name, depth + 1);
      }
    };
    visit(root, "", 0);
  }
  if (!excludeRes && !rules.length) return undefined;
  return (rel: string): boolean => {
    if (excludeRes?.some((re) => re.test(rel))) return true;
    if (!rules.length) return false;
    // git ignores everything UNDER an ignored directory, and a `data/` rule
    // matches the directory, not the files in it. The walker gets this for free
    // by testing each directory as it descends and never entering an ignored
    // one; a path-only matcher has to walk the ancestors itself. Ancestors are
    // tested first because git will not let a negation re-include a file whose
    // parent directory is excluded.
    let at = -1;
    while ((at = rel.indexOf("/", at + 1)) !== -1) {
      if (engineIsIgnored(rules, rel.slice(0, at), true)) return true;
    }
    return engineIsIgnored(rules, rel, false);
  };
}

/**
 * Expand brace alternation — `a/{x,y}.ts` → `["a/x.ts", "a/y.ts"]` — into the
 * plain globs `globToRe` understands. Nested braces expand recursively; an
 * unbalanced brace is left alone and matched literally, as before.
 *
 * Deliberately NOT folded into `globToRe`: `--include`/`--exclude` have shipped
 * with `{}` as literal characters, and quietly changing what a user's existing
 * pattern matches is not this function's job. Callers that want alternation opt
 * in by expanding first.
 */
export function expandBraces(pattern: string): string[] {
  const open = pattern.indexOf("{");
  if (open === -1) return [pattern];
  let depth = 0;
  let close = -1;
  for (let i = open; i < pattern.length; i++) {
    if (pattern[i] === "{") depth++;
    else if (pattern[i] === "}" && --depth === 0) {
      close = i;
      break;
    }
  }
  if (close === -1) return [pattern]; // unbalanced — literal, as before
  const head = pattern.slice(0, open);
  const tail = pattern.slice(close + 1);
  const parts: string[] = [];
  let level = 0;
  let start = open + 1;
  for (let i = open + 1; i < close; i++) {
    const ch = pattern[i];
    if (ch === "{") level++;
    else if (ch === "}") level--;
    else if (ch === "," && level === 0) {
      parts.push(pattern.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(pattern.slice(start, close));
  return parts.flatMap((alt) => expandBraces(head + alt + tail));
}

interface ScopeEntry {
  /** Plain dir/file prefix (no wildcards), e.g. "src/api" — used for dir pruning. */
  base: string;
  /** Compiled matcher when the scope contains a wildcard, else undefined. */
  re?: RegExp;
  raw: string;
}

/** Literal directory prefix of a glob (everything before the first wildcard, cut to
 *  the last slash) — the deepest directory guaranteed to be on the path. */
function literalBase(s: string): string {
  const clean = s.replace(/^\.\//, "").replace(/\/+$/, "");
  const wi = clean.search(/[*?]/);
  if (wi === -1) return clean;
  const lit = clean.slice(0, wi);
  const slash = lit.lastIndexOf("/");
  return slash === -1 ? "" : lit.slice(0, slash);
}

function toScopeEntries(scopes: string[]): ScopeEntry[] {
  return scopes.map((raw) => {
    const clean = raw.replace(/^\.\//, "").replace(/\/+$/, "");
    const hasWild = /[*?]/.test(clean);
    return { raw: clean, base: literalBase(clean), re: hasWild ? globToRe(clean) : undefined };
  });
}

/** Can a directory possibly contain something in scope? (Permissive — file-level
 *  matching is the precise filter; this only prunes clearly-unrelated trees.) */
function dirInScope(relDir: string, scopes: ScopeEntry[]): boolean {
  if (relDir === "") return true; // repo root
  for (const sc of scopes) {
    const base = sc.base;
    if (base === "") return true; // e.g. "**/*.js" — cannot prune by directory
    if (relDir === base) return true;
    if (relDir.startsWith(base + "/")) return true; // already inside the scope
    if (base.startsWith(relDir + "/")) return true; // on the way down to the scope
  }
  return false;
}

function fileInScope(rel: string, scopes: ScopeEntry[]): boolean {
  for (const sc of scopes) {
    if (sc.re) {
      if (sc.re.test(rel)) return true;
    } else if (rel === sc.raw || rel.startsWith(sc.raw + "/")) {
      return true;
    }
  }
  return false;
}

/** One `.gitignore` rule, in source order. `negated` marks a `!`-re-include. */
export interface GitignoreRule {
  glob: string;
  negated: boolean;
}

/** Best-effort parse of a repo-root `.gitignore` into an ORDERED rule list (git's
 *  last-match-wins). Common patterns only: comments, anchored (`/x`) vs any-depth,
 *  directory-only (trailing `/`), `!`-negations, and a leading `\` escape for a
 *  literal `#`/`!`. Order is preserved so a later exclude can re-override an earlier
 *  `!`-negation, matching `git check-ignore`. */
export function parseGitignore(content: string): GitignoreRule[] {
  const rules: GitignoreRule[] = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const negated = line.startsWith("!");
    let body = negated ? line.slice(1) : line;
    if (body.startsWith("\\")) body = body.slice(1); // unescape a literal leading '#'/'!'
    const rooted = body.startsWith("/");
    let pat = rooted ? body.slice(1) : body;
    const dirOnly = pat.endsWith("/");
    if (dirOnly) pat = pat.replace(/\/+$/, "");
    if (!pat) continue;
    const anchored = rooted || pat.includes("/");
    const g = anchored ? pat : "**/" + pat;
    // Match the path + (for a dir) its contents. Only a NON-dir-only pattern also
    // matches a bare file of that name (`build/` must not exclude a file `build`).
    rules.push({ glob: g + "/", negated });
    if (!dirOnly) rules.push({ glob: g, negated });
  }
  return rules;
}

/** Recursively list files under `root`, skipping ignored dirs. Deterministic. */
export function walk(root: string, opts: WalkOptions = {}): WalkedFile[] {
  return walkWithMeta(root, opts).files;
}

/** How deep below the repo root a manifest is still considered part of it. Two
 *  levels covers the shapes that actually occur (`web/`, `packages/api/`) without
 *  wandering into vendored trees. */
const MANIFEST_MAX_DEPTH = 3;

/**
 * Every directory under `root` (root included) holding one of `names`, nearest
 * first, then alphabetically — the discovery the package-manager audits need.
 *
 * Checking only the repo root, as they used to, silently skips every monorepo:
 * on a repo with `web/pnpm-lock.yaml` and `api/poetry.lock`, `pnpm audit` was
 * reported as "no pnpm-lock.yaml" while the vendored package-checker — which
 * does walk the tree — found both and reported 49 advisories. A coverage hole
 * that reads as a clean result is worse than a loud failure.
 *
 * Bounded and dependency-aware: `DEFAULT_IGNORE_DIRS` keeps it out of
 * node_modules and friends, so a nested dependency's own lockfile is never
 * mistaken for a workspace.
 */
export function findManifestDirs(root: string, names: readonly string[], maxDepth = MANIFEST_MAX_DEPTH): string[] {
  const found: { dir: string; depth: number }[] = [];
  const visit = (dir: string, depth: number): void => {
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // unreadable directory: not a reason to fail the audit
    }
    if (entries.some((e) => e.isFile() && names.includes(e.name))) found.push({ dir, depth });
    if (depth >= maxDepth) return;
    for (const e of entries) {
      if (!e.isDirectory() || e.name.startsWith(".") || DEFAULT_IGNORE_DIRS.has(e.name)) continue;
      visit(join(dir, e.name), depth + 1);
    }
  };
  visit(root, 0);
  return found.sort((a, b) => a.depth - b.depth || byStr(a.dir, b.dir)).map((f) => f.dir);
}

/** As `walk`, but also reports whether `maxFiles` truncated the result. */
export function walkWithMeta(root: string, opts: WalkOptions = {}): WalkResult {
  const ignore = opts.ignoreDirs ?? DEFAULT_IGNORE_DIRS;
  const maxBytes = opts.maxBytes ?? MAX_FILE_BYTES;
  const maxFiles = opts.maxFiles ?? Infinity;
  const scopes = opts.scope && opts.scope.length ? toScopeEntries(opts.scope) : undefined;
  const includeRes = opts.include && opts.include.length ? opts.include.map(globToRe) : undefined;

  // User --exclude: a flat exclude set (no negation). gitignore: an ORDERED rule
  // list evaluated last-match-wins so a later exclude can override an earlier `!`.
  const userExcludeRes = opts.exclude && opts.exclude.length ? opts.exclude.map(globToRe) : undefined;
  const giRules: { re: RegExp; negated: boolean }[] = [];
  if (opts.gitignore) {
    try {
      for (const r of parseGitignore(readFileSync(join(root, ".gitignore"), "utf8"))) giRules.push({ re: globToRe(r.glob), negated: r.negated });
    } catch {
      /* no .gitignore — fine */
    }
  }
  const isExcluded = (rel: string): boolean => {
    if (userExcludeRes && userExcludeRes.some((re) => re.test(rel))) return true;
    let ex = false;
    for (const r of giRules) if (r.re.test(rel)) ex = !r.negated; // last match wins
    return ex;
  };

  // Resolve `root` once for symlink-containment checks (reject targets that escape).
  let rootReal: string;
  try {
    rootReal = realpathSync(root);
  } catch {
    rootReal = resolve(root);
  }

  const out: WalkedFile[] = [];
  let truncated = false;

  const visit = (dir: string): void => {
    if (truncated) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries.sort(byStr)) {
      if (truncated) return;
      const abs = join(dir, name);
      let st: ReturnType<typeof lstatSync>;
      try {
        st = lstatSync(abs); // classify WITHOUT following — see symlink handling below
      } catch {
        continue;
      }
      if (st.isSymbolicLink()) {
        // git tracks symlinked FILES, so scan a symlink that resolves to a regular
        // file INSIDE the repo; but never recurse a symlinked DIRECTORY (it could
        // point at an ancestor → loop) and never follow one that escapes the repo.
        try {
          const real = realpathSync(abs);
          if (real !== rootReal && !real.startsWith(rootReal + sep)) continue; // escapes repo
          const target = statSync(abs); // follow
          if (target.isDirectory()) continue; // avoid symlink-dir loops
          st = target; // a real file inside the repo → treat it as a file
        } catch {
          continue; // dangling/broken symlink
        }
      }
      const rel = relative(root, abs).split(sep).join("/");
      if (st.isDirectory()) {
        if (ignore.has(name)) continue;
        if (scopes && !dirInScope(rel, scopes)) continue;
        if (isExcluded(rel)) continue;
        visit(abs);
      } else if (st.isFile()) {
        if (st.size > maxBytes) continue;
        if (scopes && !fileInScope(rel, scopes)) continue;
        if (includeRes && !includeRes.some((re) => re.test(rel))) continue;
        if (isExcluded(rel)) continue;
        if (out.length >= maxFiles) {
          truncated = true;
          return;
        }
        out.push({ rel, abs, bytes: st.size });
      }
    }
  };

  visit(root);
  const files = out.sort((a, b) => byStr(a.rel, b.rel));
  return { files, truncated, totalSeen: files.length };
}

export function readText(abs: string): string {
  try {
    return readFileSync(abs, "utf8");
  } catch {
    return "";
  }
}
