import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative, sep } from "node:path";
import { headCommit } from "../git.js";

// What an external reviewer is allowed to see, and what it is started with.
//
// A snapshot, never the working tree. `git archive HEAD | tar -x` is the
// committed tree and nothing else: no untracked `.env`, no token file a
// developer dropped next to the code, no `node_modules`, and nothing the
// reviewer could write back into the repository. Line numbers are HEAD's, so
// every citation it makes resolves against the same text the orchestrator
// verifies. (`tools/snapshot.ts` stages tracked AND unignored untracked files —
// right for a secret scanner, whose job is to see that `.env`; wrong here,
// where the reviewer must not.)
//
// The price is stated in the brief: no git history, no advisory database. On the
// audit this came from, reviewers asserted CVE status ("<package> <version> is
// the fixed version") and history facts from memory, and were wrong.

/** Brief files live at the snapshot root under this prefix, and are never a citation target. */
export const BRIEF_PREFIX = "_COUNCIL_BRIEF";

export interface Snapshot {
  dir: string;
  commit: string;
}

/**
 * Extract `commit` (default HEAD) of `repo` into `dir`, replacing whatever was
 * there. Two argv-only calls through a temp tarball beside `dir` — no shell
 * pipe, so no path is ever interpreted by a shell.
 */
export function createSnapshot(repo: string, dir: string, commit?: string): Snapshot {
  const sha = commit ?? headCommit(repo);
  if (!sha) throw new Error(`${repo} is not a git checkout with a commit — council reviews a snapshot of HEAD, and there is none`);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const tar = `${dir}.tar`;
  try {
    execFileSync("git", ["-C", repo, "archive", "--format=tar", "-o", tar, sha], { stdio: ["ignore", "ignore", "pipe"], timeout: 300_000 });
    execFileSync("tar", ["-xf", tar, "-C", dir], { stdio: ["ignore", "ignore", "pipe"], timeout: 300_000 });
  } finally {
    rmSync(tar, { force: true });
  }
  return { dir, commit: sha };
}

/** Reuse `dir` when it is a snapshot of `commit`; otherwise (re)create it. */
export function ensureSnapshot(repo: string, dir: string, recordedCommit: string | undefined, commit?: string): Snapshot {
  const want = commit ?? headCommit(repo) ?? undefined;
  if (want && recordedCommit === want && existsSync(dir)) return { dir, commit: want };
  return createSnapshot(repo, dir, want);
}

/** Every regular file in the snapshot, POSIX-relative, minus the briefs. */
export function snapshotFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    let entries: import("node:fs").Dirent[];
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) {
        const rel = relative(dir, p).split(sep).join("/");
        if (!rel.startsWith(BRIEF_PREFIX)) out.push(rel);
      }
    }
  };
  walk(dir);
  return out.sort();
}

/**
 * The environment a reviewer CLI starts with: HOME (where its own login lives),
 * PATH, a dumb terminal — and nothing else.
 *
 * Agent allow-lists commonly include `printenv`, and the shell that launches an
 * audit holds GitHub, cloud and registry tokens. Inheriting `process.env` hands
 * all of them to a model that was just told to read untrusted code. This is
 * `env -i HOME=… PATH=… TERM=dumb`, without needing `env`.
 */
export function councilEnv(extra: Record<string, string> = {}, base: NodeJS.ProcessEnv = process.env): Record<string, string> {
  return {
    HOME: base.HOME ?? homedir(),
    PATH: base.PATH ?? "/usr/bin:/bin",
    TERM: "dumb",
    ...extra,
  };
}
