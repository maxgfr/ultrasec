import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding } from "./normalize.js";
import { detect } from "./registry.js";
import { stageTrackedFiles } from "./snapshot.js";

// gitleaks → hardcoded secrets. Output is a top-level JSON ARRAY (no wrapper),
// PascalCase keys, no severity (assign high) and no CWE (CWE-798). `--redact`
// keeps the raw secret out of the dossier.
//
// What is scanned, by default: a SNAPSHOT of the files a commit would contain
// (tracked + untracked-unignored, see `snapshot.ts`), never the raw directory.
// The raw directory is node_modules, build output and sibling worktrees — 17 GB
// on a real monorepo, killed after ten minutes — and the full history is the
// other half of that failure: `detect` over every commit hit the 300 s timeout on
// the same repo. Both were reported as a failed scan, i.e. no secret coverage at
// all, where the tracked files alone take seconds.
//
// The history is still where a deleted-but-committed credential lives, so it is
// one flag away (`scan --secrets-history`). Without it the tool status says, as
// degraded coverage, that history was not scanned; with it, a history pass that
// times out falls back to the snapshot and says that instead of failing.
//
// gitleaks 8.19 split `detect` into `git` (history) and `dir` (a directory);
// `detect` survives as a deprecated alias, so older installs keep working.

/** First gitleaks release with the `git` / `dir` subcommands. */
const SUBCOMMANDS_SINCE: readonly [number, number] = [8, 19];

/** True when `version` (any string carrying `major.minor`) predates `git`/`dir`. Unknown ⇒ modern. */
export function gitleaksIsLegacy(version: string | undefined): boolean {
  const m = /(\d+)\.(\d+)/.exec(version ?? "");
  if (!m) return false;
  const [major, minor] = [Number(m[1]), Number(m[2])];
  return major < SUBCOMMANDS_SINCE[0] || (major === SUBCOMMANDS_SINCE[0] && minor < SUBCOMMANDS_SINCE[1]);
}

const COMMON = ["--report-format", "json", "--report-path", "-", "--no-banner", "--redact", "--exit-code", "0"];

/** The argv for one gitleaks pass: the history of a git checkout, or a directory as it stands. */
export function gitleaksArgv(target: string, opts: { history: boolean; legacy: boolean }): string[] {
  if (opts.legacy) return ["detect", "--source", target, ...COMMON, ...(opts.history ? [] : ["--no-git"])];
  return [opts.history ? "git" : "dir", target, ...COMMON];
}

export const HISTORY_NOT_SCANNED = "git history not scanned (tracked-file snapshot only) — pass `scan --secrets-history` to scan every commit";

export const gitleaks: ToolAdapter = {
  name: "gitleaks",
  cacheable: true,
  category: "secret",
  dockerImage: "ghcr.io/gitleaks/gitleaks:latest",
  historyFallback: true,
  // `--report-path -` is gitleaks' documented stdout sink (json to a file otherwise);
  // `--exit-code 0` so "leaks found" (normally exit 1) isn't treated as a tool failure.
  argv: (target, ctx) => {
    // History needs a checkout to read. Docker mounts the repo at /work, which is
    // not a host path we can probe, so there the request is taken at its word.
    const onHost = existsSync(target);
    const hasGit = !onHost || existsSync(join(target, ".git"));
    // The docker image tracks `latest`, so only a native install can be legacy.
    const legacy = onHost && gitleaksIsLegacy(detect("gitleaks").version);
    return gitleaksArgv(target, { history: !!ctx?.history && hasGit, legacy });
  },
  // Default pass: the tracked-file snapshot. A history pass reads the repository
  // itself (`git log` needs `.git`), so it is not staged.
  stage: (repo, ctx) => (ctx.history ? null : stageTrackedFiles(repo, HISTORY_NOT_SCANNED)),
  parse(raw): Finding[] {
    const arr = JSON.parse(raw || "[]") as any;
    if (!Array.isArray(arr)) return [];
    return arr.map((f: any) =>
      makeToolFinding({
        tool: "gitleaks",
        category: "secret",
        ident: `${f.RuleID}:${f.File}:${f.StartLine}`,
        title: f.Description || f.RuleID,
        severity: "high",
        // A history hit needs different ADVICE from a working-tree one: deleting
        // the file does not remove the credential from the history, so if it was
        // ever real it has to be rotated, not just removed.
        message: `Hardcoded secret (${f.Description || f.RuleID}) at ${f.File}:${f.StartLine}${
          f.Commit
            ? ` — found in git HISTORY at commit ${String(f.Commit).slice(0, 8)}. If the file no longer exists at HEAD the credential is still in the history: rotate it, deleting the file does not revoke it.`
            : ""
        }`,
        file: f.File,
        line: f.StartLine,
        cwe: "CWE-798",
        // A history pass reads every commit, so the cited file may not exist at
        // HEAD. Keeping the sha is what lets the citation gate resolve the
        // location against the tree it actually belongs to instead of calling it
        // hallucinated. Absent on a directory (snapshot) pass.
        ...(typeof f.Commit === "string" && f.Commit ? { atCommit: f.Commit } : {}),
      }),
    );
  },
};
