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
