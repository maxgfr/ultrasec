import { readFileSync, readdirSync, lstatSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { byStr } from "./util.js";

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
    const ch = p[i++]!;
    if (ch === "*") re += "[^/]*";
    else if (ch === "?") re += "[^/]";
    else re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  const body = dirMatch ? re + "(?:/.*)?" : re;
  return new RegExp("^" + body + "$");
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

export interface GitignoreGlobs {
  /** Patterns that exclude paths. */
  excludes: string[];
  /** `!`-negation patterns that RE-INCLUDE paths a broader exclude would drop. */
  reincludes: string[];
}

/** Best-effort parse of a repo-root `.gitignore` into our glob vocabulary. Common
 *  patterns only: comments, anchored (`/x`) vs any-depth, directory-only (trailing
 *  `/`), and `!`-negations (honoured as re-includes so we don't UNDER-scan files
 *  git would actually see). */
export function gitignoreToGlobs(content: string): GitignoreGlobs {
  const excludes: string[] = [];
  const reincludes: string[] = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const negated = line.startsWith("!");
    let body = negated ? line.slice(1) : line;
    const rooted = body.startsWith("/");
    let pat = rooted ? body.slice(1) : body;
    const dirOnly = pat.endsWith("/");
    if (dirOnly) pat = pat.replace(/\/+$/, "");
    if (!pat) continue;
    const anchored = rooted || pat.includes("/");
    const g = anchored ? pat : "**/" + pat;
    const sink = negated ? reincludes : excludes;
    // Always match the path + (for a dir) its contents. Only a NON-dir-only pattern
    // also matches a bare file of that name — a `build/` entry must not exclude a
    // file literally named `build` elsewhere.
    sink.push(g + "/");
    if (!dirOnly) sink.push(g);
  }
  return { excludes, reincludes };
}

/** Recursively list files under `root`, skipping ignored dirs. Deterministic. */
export function walk(root: string, opts: WalkOptions = {}): WalkedFile[] {
  return walkWithMeta(root, opts).files;
}

/** As `walk`, but also reports whether `maxFiles` truncated the result. */
export function walkWithMeta(root: string, opts: WalkOptions = {}): WalkResult {
  const ignore = opts.ignoreDirs ?? DEFAULT_IGNORE_DIRS;
  const maxBytes = opts.maxBytes ?? MAX_FILE_BYTES;
  const maxFiles = opts.maxFiles ?? Infinity;
  const scopes = opts.scope && opts.scope.length ? toScopeEntries(opts.scope) : undefined;
  const includeRes = opts.include && opts.include.length ? opts.include.map(globToRe) : undefined;

  const excludeGlobs = [...(opts.exclude ?? [])];
  const reincludeGlobs: string[] = [];
  if (opts.gitignore) {
    try {
      const gi = gitignoreToGlobs(readFileSync(join(root, ".gitignore"), "utf8"));
      excludeGlobs.push(...gi.excludes);
      reincludeGlobs.push(...gi.reincludes);
    } catch {
      /* no .gitignore — fine */
    }
  }
  const excludeRes = excludeGlobs.length ? excludeGlobs.map(globToRe) : undefined;
  const reincludeRes = reincludeGlobs.length ? reincludeGlobs.map(globToRe) : undefined;
  // Excluded UNLESS a gitignore `!`-negation re-includes it (git's last-match-wins).
  const isExcluded = (rel: string): boolean =>
    !!excludeRes && excludeRes.some((re) => re.test(rel)) && !(reincludeRes && reincludeRes.some((re) => re.test(rel)));

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
      let st;
      try {
        // lstat (not stat): never follow symlinks — a directory symlink to an
        // ancestor would otherwise loop and multiply the file set. Matches git.
        st = lstatSync(abs);
      } catch {
        continue;
      }
      if (st.isSymbolicLink()) continue;
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
