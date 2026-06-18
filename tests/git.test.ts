import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isGitRepo, changedFiles } from "../src/git.js";

function gitAvailable(): boolean {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const HAS_GIT = gitAvailable();

describe.skipIf(!HAS_GIT)("git changedFiles", () => {
  let repo: string;
  const git = (args: string[]) => execFileSync("git", ["-C", repo, ...args], { stdio: "ignore" });

  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), "ultrasec-git-"));
    git(["init", "-q"]);
    git(["config", "user.email", "t@t.t"]);
    git(["config", "user.name", "t"]);
    mkdirSync(join(repo, "src"), { recursive: true });
    writeFileSync(join(repo, "src", "a.js"), "export function a(){}\n");
    writeFileSync(join(repo, "src", "b.js"), "export function b(){}\n");
    git(["add", "-A"]);
    git(["commit", "-q", "-m", "init"]);
    // change one tracked file + add one untracked file
    writeFileSync(join(repo, "src", "a.js"), "export function a(){ return 1; }\n");
    writeFileSync(join(repo, "src", "c.js"), "export function c(){}\n");
  });
  afterAll(() => rmSync(repo, { recursive: true, force: true }));

  it("detects a git work tree", () => {
    expect(isGitRepo(repo)).toBe(true);
  });

  it("returns changed + untracked files (repo-relative POSIX), excluding unchanged", () => {
    const changed = changedFiles(repo, "HEAD");
    expect(changed).not.toBeNull();
    expect(changed!).toContain("src/a.js"); // modified
    expect(changed!).toContain("src/c.js"); // untracked
    expect(changed!).not.toContain("src/b.js"); // unchanged
  });

  it("returns null for a non-repo path", () => {
    const notRepo = mkdtempSync(join(tmpdir(), "ultrasec-notgit-"));
    expect(isGitRepo(notRepo)).toBe(false);
    expect(changedFiles(notRepo, "HEAD")).toBeNull();
    rmSync(notRepo, { recursive: true, force: true });
  });

  it("returns null for an unresolvable ref", () => {
    expect(changedFiles(repo, "no-such-ref-xyz")).toBeNull();
  });
});
