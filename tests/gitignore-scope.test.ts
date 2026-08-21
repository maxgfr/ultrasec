import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildPruneMatcher } from "../src/walk.js";
import { prunePaths, relativizeFindings, toolStatus, type ToolRunResult } from "../src/tools/run.js";
import { auditSecrets } from "../src/secrets.js";
import type { Finding } from "../src/types.js";

// Issue #10 (defect 4). `--gitignore` pruned the taint graph and nothing else:
// the always-on auditors call `walk(repo)` with no options, and the external
// scanners get the raw repo bind-mounted (`docker run -v <repo>:/work`). A scan
// that pruned 1.1 GB of vendored data from its own walk still shipped 51
// findings out of it.

function repoWith(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-ignore-"));
  for (const [rel, body] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, body);
  }
  return dir;
}

const at = (file: string): Finding => ({
  id: `id-${file}`,
  category: "secret",
  title: "t",
  severity: "high",
  confidence: "medium",
  message: "m",
  tool: "gitleaks",
  sink: { file, line: 1 },
  status: "open",
});

describe("buildPruneMatcher", () => {
  it("is undefined when nothing would be pruned — the un-pruned path stays identical", () => {
    const repo = repoWith({ "a.js": "x\n" });
    expect(buildPruneMatcher(repo, {})).toBeUndefined();
    expect(buildPruneMatcher(repo, { gitignore: true })).toBeUndefined();
  });

  it("honours the root .gitignore", () => {
    const repo = repoWith({ ".gitignore": "dist/\n*.log\n", "a.js": "x\n" });
    const prune = buildPruneMatcher(repo, { gitignore: true })!;
    expect(prune("dist/bundle.js")).toBe(true);
    expect(prune("server.log")).toBe(true);
    expect(prune("src/a.js")).toBe(false);
  });

  it("honours NESTED .gitignore files, like the walker does", () => {
    // The local walkWithMeta reads only the root's; the engine reads all of
    // them. A filter that disagreed with the walker would swap one
    // inconsistency for a subtler one.
    const repo = repoWith({
      ".gitignore": "node_modules/\n",
      "targets/ingester/.gitignore": "data/\n",
      "targets/frontend/.gitignore": ".next/\n",
      "targets/ingester/index.js": "x\n",
    });
    const prune = buildPruneMatcher(repo, { gitignore: true })!;
    expect(prune("targets/ingester/data/vendored.json")).toBe(true);
    expect(prune("targets/frontend/.next/static/chunk.js")).toBe(true);
    expect(prune("targets/ingester/index.js")).toBe(false);
  });

  it("honours a negation, last match winning", () => {
    const repo = repoWith({ ".gitignore": "*.log\n!keep.log\n", "a.js": "x\n" });
    const prune = buildPruneMatcher(repo, { gitignore: true })!;
    expect(prune("debug.log")).toBe(true);
    expect(prune("keep.log")).toBe(false);
  });

  it("applies --exclude globs with or without --gitignore", () => {
    const repo = repoWith({ "a.js": "x\n" });
    const prune = buildPruneMatcher(repo, { exclude: ["**/*.min.js"] })!;
    expect(prune("public/app.min.js")).toBe(true);
    expect(prune("public/app.js")).toBe(false);
  });
});

describe("prunePaths — the single choke point for tool findings", () => {
  const prune = (rel: string) => rel.startsWith("dist/");

  it("drops a finding whose cited location was pruned", () => {
    const { findings, dropped } = prunePaths([at("dist/bundle.js"), at("src/a.js")], prune);
    expect(dropped).toBe(1);
    expect(findings.map((f) => f.sink!.file)).toEqual(["src/a.js"]);
  });

  it("NEVER drops a finding with no cited location", () => {
    // A dependency advisory keyed on a package rather than a file has no path to
    // test. Losing a CVE to a path filter would be worse than the bug being fixed.
    const dep: Finding = { ...at("x"), category: "dep", cve: "CVE-2021-23337", sink: undefined };
    const { findings, dropped } = prunePaths([dep], prune);
    expect(dropped).toBe(0);
    expect(findings).toHaveLength(1);
  });

  it("judges on the source when there is no sink", () => {
    const f: Finding = { ...at("x"), sink: undefined, source: { file: "dist/gen.js", line: 2 } };
    expect(prunePaths([f], prune).dropped).toBe(1);
  });

  it("reports the post-filter count to toolStatus, not the pre-filter one", () => {
    const { findings, dropped } = prunePaths([at("dist/a.js"), at("dist/b.js"), at("src/c.js")], prune);
    const result: ToolRunResult = {
      name: "gitleaks",
      ran: true,
      ok: true,
      findings,
      note: `${findings.length} finding(s) · ${dropped} pruned (ignored paths)`,
    };
    const [status] = toolStatus([result]);
    expect(status!.findings).toBe(1);
    expect(status!.note).toMatch(/2 pruned/);
  });

  it("runs after relativization, so docker's /work paths are already stripped", () => {
    const raw: Finding = { ...at("/work/dist/bundle.js") };
    const rel = relativizeFindings([raw], "/work");
    expect(rel[0]!.sink!.file).toBe("dist/bundle.js");
    expect(prunePaths(rel, prune).dropped).toBe(1);
  });
});

describe("the always-on auditors honour the same prune", () => {
  it("skips a gitignored file that would otherwise yield a finding", () => {
    const leak = 'url = "postgresql://svc:R4bb1tHutch99@db.internal:5432/app"\n';
    const repo = repoWith({ ".gitignore": "generated/\n", "config.toml": leak, "generated/config.toml": leak });

    const unpruned = auditSecrets(repo)
      .map((f) => f.sink!.file)
      .sort();
    expect(unpruned).toEqual(["config.toml", "generated/config.toml"]);

    const prune = buildPruneMatcher(repo, { gitignore: true })!;
    const pruned = auditSecrets(repo, prune).map((f) => f.sink!.file);
    expect(pruned).toEqual(["config.toml"]);
  });
});
