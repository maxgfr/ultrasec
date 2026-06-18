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
