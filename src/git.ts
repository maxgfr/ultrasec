import { execFileSync } from "node:child_process";

// Minimal, zero-dependency git access for `--diff`/`--since`. Everything runs via
// `execFileSync` with an argv array (NEVER a shell), and the ref is passed as a
// positional argument, not interpolated — so an attacker-controlled branch/ref
// name can't inject a command (cf. the 2026 Codex branch-name injection).

function git(repo: string, args: string[]): string | null {
  try {
    return execFileSync("git", ["-C", repo, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch {
    return null;
  }
}

/** True when `repo` is inside a git work tree. */
export function isGitRepo(repo: string): boolean {
  return git(repo, ["rev-parse", "--is-inside-work-tree"])?.trim() === "true";
}

/**
 * Repo-relative POSIX paths changed since `ref` (committed diff + untracked files),
 * excluding deletions. Returns `null` when git is unavailable or the ref doesn't
 * resolve — callers surface a clear error rather than silently full-scanning.
 */
export function changedFiles(repo: string, ref: string): string[] | null {
  if (!isGitRepo(repo)) return null;
  // Validate the ref resolves before using it (clear error, no surprises).
  if (git(repo, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]) === null) return null;

  const out = new Set<string>();
  const diff = git(repo, ["diff", "--name-only", "--diff-filter=d", `${ref}...HEAD`]);
  if (diff === null) return null;
  for (const line of diff.split(/\r?\n/)) if (line.trim()) out.add(line.trim());

  // Also include working-tree changes vs the ref and untracked-but-present files,
  // so an in-progress audit sees what's actually on disk.
  const worktree = git(repo, ["diff", "--name-only", "--diff-filter=d", ref]);
  if (worktree) for (const line of worktree.split(/\r?\n/)) if (line.trim()) out.add(line.trim());
  const untracked = git(repo, ["ls-files", "--others", "--exclude-standard"]);
  if (untracked) for (const line of untracked.split(/\r?\n/)) if (line.trim()) out.add(line.trim());

  return [...out].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

// ── Blame (provenance) ───────────────────────────────────────────────────────
export interface BlameInfo {
  /** Last author to touch the line. */
  author?: string;
  /** Short commit sha (first 10 chars). */
  commit?: string;
  /** Author-date as ISO yyyy-mm-dd — deterministic from history (NOT wall-clock). */
  date?: string;
}

/**
 * Parse one entry of `git blame --porcelain` output into a {@link BlameInfo}.
 * Pure (no I/O), so it is unit-testable without a repo. Returns `null` when the
 * input isn't porcelain (the first line must be `<40-hex-sha> <orig> <final> …`).
 * The date is derived from `author-time` (epoch seconds, UTC) — a stable git
 * fact, so two runs over the same history yield the same date.
 */
export function parseBlamePorcelain(raw: string): BlameInfo | null {
  if (!raw) return null;
  const lines = raw.split(/\r?\n/);
  const m = /^([0-9a-f]{40})\b/.exec((lines[0] ?? "").trim());
  if (!m) return null;
  const info: BlameInfo = { commit: m[1]!.slice(0, 10) };
  for (const line of lines) {
    if (line.startsWith("author ")) info.author = line.slice(7).trim();
    else if (line.startsWith("author-time ")) {
      const t = Number(line.slice(12).trim());
      if (Number.isFinite(t)) info.date = new Date(t * 1000).toISOString().slice(0, 10);
    }
  }
  return info;
}

/**
 * Blame a single line. `file` is repo-relative and passed positionally after
 * `--` (never interpolated — same injection-hardening as the diff path). Returns
 * `null` when git is unavailable, the path doesn't resolve, or the line is
 * invalid — callers degrade to no provenance rather than failing.
 */
export function blameLine(repo: string, file: string, line: number): BlameInfo | null {
  if (!Number.isInteger(line) || line < 1) return null;
  const out = git(repo, ["blame", "-L", `${line},${line}`, "--porcelain", "--", file]);
  return out === null ? null : parseBlamePorcelain(out);
}

// ── Revalidation facts (Phase 2 — git-history FP cut) ────────────────────────
// Compact, offline-tolerant git facts about a finding's cited location, so the
// agent can decide whether a previously-confirmed issue is still-valid / fixed /
// false-positive / uncertain WITHOUT re-reading the whole repo. Every helper goes
// through the hardened argv `git()` path and degrades to a benign value (false /
// null) when git is unavailable, so the engine's network-free contract holds.

// Bound git-history work so a pathological file can't stall a run.
const LOG_CAP = 50;
const HUGE_FILE_LINES = 20000;

// A subdir `--repo` (e.g. one package of a monorepo) resolves the file paths here
// relative to that subdir, but a `HEAD:<path>` rev-expression is resolved relative
// to the worktree ROOT — so `HEAD:src/a.js` misses `<root>/pkg/src/a.js`. Prepend
// the worktree prefix (`git rev-parse --show-prefix`, e.g. "pkg/") so cat-file/show
// see the real object path. Empty for a repo AT the worktree root (unchanged
// behaviour) and empty when git is unavailable (helpers then degrade to false/null
// exactly as before). Pathspecs (`-- <file>`) and `-L a,b:<file>` are already
// cwd-relative under `git -C <repo>`, so they must NOT be prefixed. Memoized per
// repo — the prefix is stable for the lifetime of a run.
const prefixCache = new Map<string, string>();
function worktreePrefix(repo: string): string {
  const cached = prefixCache.get(repo);
  if (cached !== undefined) return cached;
  const p = git(repo, ["rev-parse", "--show-prefix"])?.trim() ?? "";
  prefixCache.set(repo, p);
  return p;
}

/** True when `file` exists in the committed tree at HEAD. (`HEAD:<file>` is a single
 *  argv rev-expression, never a shell string — same injection-hardening as blame.) */
export function fileExistsAtHead(repo: string, file: string): boolean {
  return git(repo, ["cat-file", "-e", `HEAD:${worktreePrefix(repo)}${file}`]) !== null;
}

/** The content of `file` line `line` at HEAD, or `null` if the file/line is gone. */
export function lineContentAtHead(repo: string, file: string, line: number): string | null {
  if (!Number.isInteger(line) || line < 1) return null;
  const blob = git(repo, ["show", `HEAD:${worktreePrefix(repo)}${file}`]);
  if (blob === null) return null;
  const lines = blob.split(/\r?\n/);
  return line <= lines.length ? lines[line - 1]! : null;
}

/**
 * Short shas of commits that touched `file` after `sinceRef` (exclusive), newest
 * first, capped at {@link LOG_CAP}. `null` when git is unavailable or `sinceRef`
 * doesn't resolve — so a missing provenance ref yields "unknown", not "zero".
 */
export function logSince(repo: string, file: string, sinceRef: string): string[] | null {
  if (git(repo, ["rev-parse", "--verify", "--quiet", `${sinceRef}^{commit}`]) === null) return null;
  const out = git(repo, ["log", `--max-count=${LOG_CAP}`, "--format=%h", `${sinceRef}..HEAD`, "--", file]);
  if (out === null) return null;
  return out
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export interface LineChange {
  commit: string;
  author?: string;
  date?: string;
}

/**
 * Parse the header line of `git log -L … --format=%h%x00%an%x00%ad` output (NUL-
 * separated) into a {@link LineChange}. Pure (no I/O). Returns `null` when no
 * NUL-delimited header is present (empty history / unsupported output).
 */
export function parseLineLog(raw: string): LineChange | null {
  const header = raw.split(/\r?\n/).find((l) => l.includes("\u0000"));
  if (!header) return null;
  const [commit, author, date] = header.split("\u0000");
  if (!commit || !commit.trim()) return null;
  return { commit: commit.trim(), author: author?.trim() || undefined, date: date?.trim() || undefined };
}

/**
 * The most recent commit that changed `file` line `line` (via `git log -L`),
 * or `null`. Guards against pathological cost: skips files larger than
 * {@link HUGE_FILE_LINES} lines or a line past EOF, degrading to `null`.
 */
export function lineLastChanged(repo: string, file: string, line: number): LineChange | null {
  if (!Number.isInteger(line) || line < 1) return null;
  const blob = git(repo, ["show", `HEAD:${worktreePrefix(repo)}${file}`]);
  if (blob === null) return null;
  const total = blob.split(/\r?\n/).length;
  if (line > total || total > HUGE_FILE_LINES) return null;
  // `-L a,b:<file>` is cwd-relative under `git -C <repo>` (unlike the rev-expression
  // above), so the subdir-relative path is already correct — do NOT prefix it.
  const out = git(repo, ["log", "-n", "1", "--format=%h%x00%an%x00%ad", "--date=short", "-L", `${line},${line}:${file}`]);
  return out === null ? null : parseLineLog(out);
}

/**
 * Find the path a now-deleted `oldPath` was renamed to, by scanning rename events
 * in `git log --name-status` output (lines like `R100\told\tnew`). Pure. Returns
 * the first new path whose old name matches, or `null`.
 */
export function parseRenameStatus(raw: string, oldPath: string): string | null {
  for (const l of raw.split(/\r?\n/)) {
    const m = /^R\d*\t([^\t]+)\t([^\t]+)$/.exec(l);
    if (m && m[1] === oldPath) return m[2]!;
  }
  return null;
}

/**
 * Best-effort: if `file` no longer exists at HEAD, the path it was most likely
 * renamed to. Bounded (scans the last {@link LOG_CAP}×4 rename events). `null`
 * when the file still exists, git is unavailable, or no rename is found.
 */
export function fileRenamedTo(repo: string, file: string): string | null {
  if (fileExistsAtHead(repo, file)) return null;
  const out = git(repo, ["log", "--all", "-M", "--diff-filter=R", "--name-status", "--format=", `--max-count=${LOG_CAP * 4}`]);
  if (out === null) return null;
  return parseRenameStatus(out, file);
}
