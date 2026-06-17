import { readFileSync, readdirSync, statSync } from "node:fs";
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

/** Best-effort parse of a repo-root `.gitignore` into exclude globs our matcher
 *  understands. Negations (`!…`) are skipped (conservative — never un-excludes). */
export function gitignoreToGlobs(content: string): string[] {
  const globs: string[] = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;
    const rooted = line.startsWith("/");
    let pat = rooted ? line.slice(1) : line;
    const dirOnly = pat.endsWith("/");
    if (dirOnly) pat = pat.replace(/\/+$/, "");
    if (!pat) continue;
    const anchored = rooted || pat.includes("/");
    const g = anchored ? pat : "**/" + pat;
    // A gitignore entry matches the path itself and (for dirs) everything under it.
    globs.push(g + "/");
    globs.push(g);
  }
  return globs;
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
  if (opts.gitignore) {
    try {
      excludeGlobs.push(...gitignoreToGlobs(readFileSync(join(root, ".gitignore"), "utf8")));
    } catch {
      /* no .gitignore — fine */
    }
  }
  const excludeRes = excludeGlobs.length ? excludeGlobs.map(globToRe) : undefined;

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
        st = statSync(abs);
      } catch {
        continue;
      }
      const rel = relative(root, abs).split(sep).join("/");
      if (st.isDirectory()) {
        if (ignore.has(name)) continue;
        if (scopes && !dirInScope(rel, scopes)) continue;
        if (excludeRes && excludeRes.some((re) => re.test(rel))) continue;
        visit(abs);
      } else if (st.isFile()) {
        if (st.size > maxBytes) continue;
        if (scopes && !fileInScope(rel, scopes)) continue;
        if (includeRes && !includeRes.some((re) => re.test(rel))) continue;
        if (excludeRes && excludeRes.some((re) => re.test(rel))) continue;
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
