import { afterEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gitleaks } from "../src/tools/gitleaks.js";
import * as gl from "../src/tools/gitleaks.js";
import * as snapshot from "../src/tools/snapshot.js";
import { runAdapter, toolStatus, type ToolAdapter } from "../src/tools/run.js";
import { toolStatusLines } from "../src/store.js";

// gitleaks on a real monorepo: `detect` over the full history hit the 300 s
// timeout, and `--no-git` over the working tree walked 17 GB of node_modules and
// was killed after ten minutes. Both read as "gitleaks failed" — no secret
// coverage at all — while a snapshot of the tracked files scanned in 3.3 s.

const dirs: string[] = [];
const tmp = (p: string) => {
  const d = mkdtempSync(join(tmpdir(), p));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function gitRepo(): string {
  const repo = tmp("ultrasec-gl-");
  const git = (...a: string[]) => execFileSync("git", ["-C", repo, ...a], { stdio: "ignore" });
  git("init", "-q");
  writeFileSync(join(repo, ".gitignore"), "node_modules/\nbuild/\n");
  writeFileSync(join(repo, "tracked.js"), "export const a = 1;\n");
  mkdirSync(join(repo, "node_modules", "dep"), { recursive: true });
  writeFileSync(join(repo, "node_modules", "dep", "index.js"), "huge\n");
  mkdirSync(join(repo, "build"));
  writeFileSync(join(repo, "build", "out.js"), "built\n");
  git("add", ".gitignore", "tracked.js");
  git("-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false", "commit", "-qm", "init");
  // Untracked but NOT ignored: one `git add .` away from the history.
  writeFileSync(join(repo, ".env"), "TOKEN=x\n");
  return repo;
}

describe("gitleaks argv", () => {
  it("uses `dir` for a directory pass and `git` for history on gitleaks >= 8.19", () => {
    expect(gl.gitleaksArgv("/t", { history: false, legacy: false }).slice(0, 2)).toEqual(["dir", "/t"]);
    expect(gl.gitleaksArgv("/t", { history: true, legacy: false }).slice(0, 2)).toEqual(["git", "/t"]);
  });

  it("keeps `detect` (with --no-git for a directory pass) on older releases", () => {
    expect(gl.gitleaksArgv("/t", { history: false, legacy: true })).toContain("--no-git");
    expect(gl.gitleaksArgv("/t", { history: true, legacy: true })).not.toContain("--no-git");
    expect(gl.gitleaksArgv("/t", { history: true, legacy: true }).slice(0, 3)).toEqual(["detect", "--source", "/t"]);
  });

  it("reads the version gate from `gitleaks --version` output", () => {
    expect(gl.gitleaksIsLegacy("gitleaks version 8.30.1")).toBe(false);
    expect(gl.gitleaksIsLegacy("8.19.0")).toBe(false);
    expect(gl.gitleaksIsLegacy("v8.18.4")).toBe(true);
    expect(gl.gitleaksIsLegacy(undefined)).toBe(false);
  });

  it("does not walk history unless asked to", () => {
    const repo = gitRepo();
    expect(gitleaks.argv(repo, {})).not.toContain("git");
    expect(gitleaks.argv(repo, { history: true })).toContain(repo);
  });
});

describe("tracked-file snapshot", () => {
  it("stages tracked and unignored files only — never node_modules or build output", () => {
    const repo = gitRepo();
    const s = snapshot.stageTrackedFiles(repo, "history not scanned");
    expect(s).not.toBeNull();
    try {
      const top = readdirSync(s!.dir).sort();
      expect(top).toEqual([".env", ".gitignore", "tracked.js"]);
      expect(s!.degraded).toBe("history not scanned");
    } finally {
      s!.dispose();
    }
    expect(existsSync(s!.dir)).toBe(false);
  });

  it("returns null outside a git checkout", () => {
    expect(snapshot.stageTrackedFiles(tmp("ultrasec-nogit-"))).toBeNull();
  });

  it("gitleaks stages the snapshot by default and reports history as degraded coverage", () => {
    const repo = gitRepo();
    const s = gitleaks.stage!(repo, {});
    expect(s?.degraded).toMatch(/history not scanned/);
    s?.dispose();
    expect(gitleaks.stage!(repo, { history: true })).toBeNull();
  });
});

// A node one-liner stands in for the scanner: it lists the directory it was
// pointed at, so the test sees exactly what the tool would have walked.
const lister = (extra: Partial<ToolAdapter> = {}): ToolAdapter => ({
  name: "fake-lister",
  category: "secret",
  command: () => [process.execPath],
  argv: (target) => [
    "-e",
    `const fs=require("fs");const out=[];(function w(d,p){for(const e of fs.readdirSync(d,{withFileTypes:true})){const r=p?p+"/"+e.name:e.name;if(e.isDirectory())w(d+"/"+e.name,r);else out.push({File:${JSON.stringify("")}+process.argv[1]+"/"+r})}})(process.argv[1],"");console.log(JSON.stringify(out))`,
    target,
  ],
  parse: (raw) =>
    (JSON.parse(raw) as { File: string }[]).map((f) => ({
      id: f.File,
      category: "secret",
      title: "x",
      severity: "high",
      confidence: "low",
      message: "x",
      tool: "fake-lister",
      status: "open",
      sink: { file: f.File, line: 1 },
    })),
  stage: (repo) => snapshot.stageTrackedFiles(repo, "history not scanned"),
  ...extra,
});

describe("runner staging", () => {
  it("scans the staged copy, cites repo-relative paths and surfaces the degraded note", async () => {
    const repo = gitRepo();
    const r = await runAdapter(lister(), repo);
    expect(r.ok).toBe(true);
    const files = r.findings.map((f) => f.sink!.file).sort();
    expect(files).toEqual([".env", ".gitignore", "tracked.js"]);
    expect(r.degraded).toBe("history not scanned");
    const [status] = toolStatus([r]);
    expect(status!.degraded).toBe("history not scanned");
    expect(toolStatusLines([status!])[0]).toMatch(/degraded: history not scanned/);
  });

  it("a timed-out history pass falls back to the snapshot instead of failing", async () => {
    const repo = gitRepo();
    const slowHistory = lister({
      historyFallback: true,
      stage: (r, ctx) => (ctx.history ? null : snapshot.stageTrackedFiles(r, "history not scanned")),
      argv: (target, ctx) => (ctx?.history ? ["-e", "setTimeout(() => {}, 20000)"] : lister().argv(target)),
    });
    const r = await runAdapter(slowHistory, repo, false, { history: true, timeoutMs: 500 });
    expect(r.ok).toBe(true);
    expect(r.findings.map((f) => f.sink!.file)).toContain("tracked.js");
    expect(r.findings.map((f) => f.sink!.file)).not.toContain("node_modules/dep/index.js");
    expect(r.degraded).toMatch(/history scan abandoned \(timed out/);
  }, 15000);
});
