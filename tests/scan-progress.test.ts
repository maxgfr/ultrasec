import { describe, it, expect } from "vitest";
import { execFile } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { orchestrate, type ToolAdapter, type ToolProgress } from "../src/tools/run.js";

// Issue #10 (defect 6). A thorough scan printed nothing from start to finish —
// 22 minutes of silence, with `docker ps` the only way to tell "running" from
// "hung", because one adapter was walking git history. Adapters run serially, so
// naming the one currently blocking is the whole signal.

const BUNDLE = join(import.meta.dirname, "..", "scripts", "ultrasec.mjs");
const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

function run(args: string[]): Promise<{ stdout: string; stderr: string }> {
  return new Promise((res) => {
    execFile(process.execPath, [BUNDLE, ...args], { encoding: "utf8" }, (_e, stdout, stderr) => res({ stdout: stdout ?? "", stderr: stderr ?? "" }));
  });
}

const out = () => mkdtempSync(join(tmpdir(), "ultrasec-progress-"));

describe("orchestrate reports each adapter starting and finishing", () => {
  const fake = (name: string): ToolAdapter => ({
    name,
    category: "sast",
    argv: () => ["--version"],
    parse: () => [],
    applicable: () => "not applicable in this test",
  });

  it("emits a start event and a completion event per adapter, in order", () => {
    const seen: ToolProgress[] = [];
    orchestrate([fake("alpha"), fake("beta")], FIXTURE, { onProgress: (e) => seen.push(e) });

    expect(seen.map((e) => `${e.tool}:${e.result ? "done" : "start"}`)).toEqual(["alpha:start", "alpha:done", "beta:start", "beta:done"]);
  });

  it("carries position, result and elapsed time on completion", () => {
    const seen: ToolProgress[] = [];
    orchestrate([fake("alpha"), fake("beta")], FIXTURE, { onProgress: (e) => seen.push(e) });

    const done = seen.filter((e) => e.result);
    expect(done.map((e) => `${e.index}/${e.total}`)).toEqual(["1/2", "2/2"]);
    for (const e of done) {
      expect(e.result!.note).toBeTruthy();
      expect(typeof e.ms).toBe("number");
    }
  });

  it("is optional — omitting it changes nothing", () => {
    expect(() => orchestrate([fake("alpha")], FIXTURE, {})).not.toThrow();
  });
});

describe("scan progress stream", () => {
  it("reports stages and per-scanner progress on stderr, by default", async () => {
    const { stderr } = await run(["scan", "--repo", FIXTURE, "--out", out(), "--offline"]);
    expect(stderr).toMatch(/ultrasec · walking /);
    expect(stderr).toMatch(/building the link-graph/);
    expect(stderr).toMatch(/enumerating source→sink taint paths/);
    expect(stderr).toMatch(/writing the dossier/);
    // Per-scanner, positioned, so the tool that is blocking is always named.
    expect(stderr).toMatch(/\[\d+\/\d+\] gitleaks/);
  });

  it("keeps stdout byte-identical whether progress is on or off", async () => {
    const a = await run(["scan", "--repo", FIXTURE, "--out", out(), "--offline", "--json"]);
    const b = await run(["scan", "--repo", FIXTURE, "--out", out(), "--offline", "--json", "--quiet"]);
    // The run directory differs per invocation; everything else must match.
    const strip = (s: string) => s.replace(/"out": "[^"]*"/, '"out": "<dir>"');
    expect(strip(a.stdout)).toBe(strip(b.stdout));
  });

  it("--quiet mutes the progress stream entirely", async () => {
    const { stderr } = await run(["scan", "--repo", FIXTURE, "--out", out(), "--offline", "--quiet"]);
    expect(stderr).not.toMatch(/ultrasec · /);
  });
});
