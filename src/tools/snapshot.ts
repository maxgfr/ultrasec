import { execFileSync } from "node:child_process";
import { constants, copyFileSync, lstatSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

// A copy of the files a commit would contain, for a scanner that walks a
// directory and has no notion of `.gitignore`.
//
// `gitleaks detect --no-git` (and `gitleaks dir`) read EVERYTHING under the path
// they are given. On a real monorepo that was 17 GB — node_modules, build output,
// sibling worktrees — and the scan was killed after ten minutes, while the
// tracked files alone scanned in 3.3 s. Pointing the tool at a staged copy is the
// only exclusion every gitleaks version honours.
//
// The set is `git ls-files --cached --others --exclude-standard`: what is
// tracked, plus untracked files git would NOT ignore. The second half matters —
// an untracked `.env` that no `.gitignore` covers is one `git add .` away from
// the history, and is exactly what a secret scanner should see. Files are taken
// from the working tree, so an uncommitted edit to a tracked file is scanned as
// it stands. Copies are reflinks where the filesystem supports them
// (APFS, btrfs, XFS), so staging costs metadata, not bytes.

export interface StagedTarget {
  /** The directory the tool scans instead of the repository. */
  dir: string;
  /** How many files were staged. */
  files: number;
  /** Remove the staged copy. Safe to call more than once. */
  dispose(): void;
  /** The coverage this target gives up — reported as the tool's degraded note. */
  degraded?: string;
}

/** Tracked and unignored files of `repo`, repo-relative; null when it is not a git checkout. */
export function trackedFiles(repo: string): string[] | null {
  let raw: string;
  try {
    raw = execFileSync("git", ["-C", repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
      encoding: "utf8",
      maxBuffer: 512 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 120_000,
    });
  } catch {
    return null;
  }
  return [...new Set(raw.split("\0").filter(Boolean))];
}

/**
 * Stage a copy of `repo`'s tracked and unignored files in a fresh temporary
 * directory. Returns null when `repo` is not a git checkout — the caller then
 * scans the directory as it is, which is the only option left.
 *
 * Symlinks, submodules and paths deleted from the working tree are skipped: a
 * link can point outside the repository, and a submodule is another repository.
 */
export function stageTrackedFiles(repo: string, degraded?: string): StagedTarget | null {
  const files = trackedFiles(repo);
  if (!files) return null;
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-snapshot-"));
  let staged = 0;
  try {
    for (const rel of files) {
      const src = join(repo, rel);
      let regular = false;
      try {
        regular = lstatSync(src).isFile();
      } catch {
        continue; // deleted in the working tree
      }
      if (!regular) continue;
      const dst = join(dir, rel);
      mkdirSync(dirname(dst), { recursive: true });
      copyFileSync(src, dst, constants.COPYFILE_FICLONE);
      staged++;
    }
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    throw e;
  }
  return {
    dir,
    files: staged,
    dispose: () => rmSync(dir, { recursive: true, force: true }),
    ...(degraded ? { degraded } : {}),
  };
}
