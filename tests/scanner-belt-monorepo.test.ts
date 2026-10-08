import { afterEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkov } from "../src/tools/checkov.js";
import { exportUvLock, pipAudit } from "../src/tools/pip-audit.js";
import { runAdapter, type ToolAdapter } from "../src/tools/run.js";

// Two scanners lost all coverage on a JS monorepo with a Python sub-project
// (`analysis/uv.lock`, 1.2 GB of node_modules, a 750 MB `.next`): checkov timed
// out walking build output, and pip-audit skipped with "no requirements.txt"
// although the repo pinned 70 vulnerable Python packages in a uv lockfile.

const dirs: string[] = [];
const tmp = (p: string) => {
  const d = mkdtempSync(join(tmpdir(), p));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("checkov scans the tracked-file snapshot", () => {
  it("never walks ignored build output or node_modules", () => {
    const repo = tmp("ultrasec-checkov-");
    const git = (...a: string[]) => execFileSync("git", ["-C", repo, ...a], { stdio: "ignore" });
    git("init", "-q");
    writeFileSync(join(repo, ".gitignore"), "node_modules/\n.next/\n");
    writeFileSync(join(repo, "Dockerfile"), "FROM node:20\n");
    mkdirSync(join(repo, ".next", "cache"), { recursive: true });
    writeFileSync(join(repo, ".next", "cache", "blob"), "x\n");
    mkdirSync(join(repo, "node_modules", "dep"), { recursive: true });
    writeFileSync(join(repo, "node_modules", "dep", "Dockerfile"), "FROM scratch\n");
    git("add", ".");
    const s = checkov.stage!(repo, {});
    expect(s).not.toBeNull();
    try {
      expect(readdirSync(s!.dir).sort()).toEqual([".gitignore", "Dockerfile"]);
    } finally {
      s!.dispose();
    }
  });
});

describe("pip-audit finds Python manifests below the root", () => {
  function monorepo(): string {
    const repo = tmp("ultrasec-pip-");
    writeFileSync(join(repo, "package.json"), "{}\n");
    mkdirSync(join(repo, "analysis"));
    writeFileSync(join(repo, "analysis", "uv.lock"), "version = 1\n");
    mkdirSync(join(repo, "tools"));
    writeFileSync(join(repo, "tools", "requirements.txt"), "requests==2.25.0\n");
    mkdirSync(join(repo, "node_modules", "x"), { recursive: true });
    writeFileSync(join(repo, "node_modules", "x", "requirements.txt"), "vendored==1\n");
    return repo;
  }

  it("runs on a uv.lock or requirements.txt in a workspace, and skips with a note otherwise", () => {
    const repo = monorepo();
    expect(pipAudit.applicable!(repo)).toBeNull();
    expect(pipAudit.workspaces!(repo).sort()).toEqual([join(repo, "analysis"), join(repo, "tools")]);
    expect(pipAudit.applicable!(tmp("ultrasec-pip-empty-"))).toBe("no requirements.txt or uv.lock (checked the root and its subdirectories)");
  });

  it("cites the workspace manifest, repo-relative", () => {
    const repo = monorepo();
    const raw = JSON.stringify({
      dependencies: [{ name: "pillow", version: "12.2.0", vulns: [{ id: "PYSEC-1", aliases: ["CVE-2026-1"], fix_versions: ["12.3.0"] }] }],
    });
    expect(pipAudit.parse(raw, repo, { workspace: "analysis" })[0]?.sink).toEqual({ file: "analysis/uv.lock", line: 1 });
    expect(pipAudit.parse(raw, repo, { workspace: "tools" })[0]?.sink).toEqual({ file: "tools/requirements.txt", line: 1 });
  });

  it("audits a requirements.txt as it is, and fails a uv workspace loudly when uv is missing", () => {
    const repo = monorepo();
    const argv = pipAudit.argv(repo);
    expect(pipAudit.workspaceArgv!(join(repo, "tools"), argv)).toEqual({ argv });
    const path = process.env.PATH;
    process.env.PATH = tmp("ultrasec-empty-path-");
    try {
      expect(exportUvLock(join(repo, "analysis"))).toMatch(/`uv` is not installed/);
      expect(pipAudit.workspaceArgv!(join(repo, "analysis"), argv)).toMatch(/`uv` is not installed/);
    } finally {
      process.env.PATH = path;
    }
  });
});

describe("per-workspace argv", () => {
  it("runs each workspace with its own argv, disposes it, and records a refusal as a failure", async () => {
    const root = tmp("ultrasec-ws-argv-");
    const ok = join(root, "ok");
    const no = join(root, "no");
    mkdirSync(ok);
    mkdirSync(no);
    const disposed: string[] = [];
    const adapter: ToolAdapter = {
      name: "fixture-ws-argv",
      category: "dep",
      argv: () => ["shared"],
      // Echo the argv back as the report, so the test sees what each run received.
      command: () => [process.execPath, "-e", "process.stdout.write(JSON.stringify(process.argv.slice(1)))"],
      workspaces: () => [ok, no],
      workspaceArgv: (dir) => (dir === no ? "cannot prepare" : { argv: ["own"], dispose: () => disposed.push(dir) }),
      parse: (raw) => (JSON.parse(raw) as string[]).map((a) => ({ id: a }) as never),
    };
    const result = await runAdapter(adapter, root);
    expect(result.findings).toEqual([{ id: "own" }]);
    expect(disposed).toEqual([ok]);
    expect(result.workspaceCoverage).toEqual({ total: 2, completed: 1 });
    expect(result.note).toContain("failed no: cannot prepare");
  });
});
