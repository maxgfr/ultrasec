import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildFileResolver, type ResolutionGap } from "../src/resolve.js";
import { runScan } from "../src/commands/scan.js";
import { parseArgs } from "../src/util.js";
import type { RepoScan } from "../src/scan.js";

// A resolve context the vendored engine cannot build must cost the files it
// choked on, not the scan. On a Phoenix repo the engine's Elixir module index
// read `symbols` off every `.ex` record — records this adapter builds from
// `rel`/`ext` alone — and `TypeError: f.symbols is not iterable` ended the run
// before one finding was written.

function phoenixRepo(): string {
  const repo = mkdtempSync(join(tmpdir(), "ultrasec-resolve-guard-"));
  mkdirSync(join(repo, "lib", "app_web"), { recursive: true });
  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "mix.exs"), 'defmodule App.MixProject do\n  defp deps do\n    [{:phoenix, "~> 1.7.14"}]\n  end\nend\n');
  writeFileSync(
    join(repo, "lib", "app_web", "export_controller.ex"),
    'defmodule AppWeb.ExportController do\n  def index(conn, params) do\n    json(conn, %{q: params["q"]})\n  end\nend\n',
  );
  writeFileSync(join(repo, "src", "a.js"), 'const b = require("./b");\nmodule.exports = b;\n');
  writeFileSync(join(repo, "src", "b.js"), "module.exports = 1;\n");
  return repo;
}

const fileScan = (rel: string, lang: string) => ({ rel, lang, symbols: [], imports: [], calls: [] });

describe("buildFileResolver — a context the engine cannot build", () => {
  it("leaves the offending extension out, keeps resolving the rest, and records the gap", () => {
    const repo = phoenixRepo();
    const scan: RepoScan = {
      repo,
      files: [fileScan("lib/app_web/export_controller.ex", "elixir"), fileScan("src/a.js", "javascript"), fileScan("src/b.js", "javascript")],
    };
    const gaps: ResolutionGap[] = [];
    const resolve = buildFileResolver(scan, [], gaps);
    expect(resolve("src/a.js", "./b")).toBe("src/b.js");
    expect(gaps).toHaveLength(1);
    expect(gaps[0]).toMatchObject({ ext: ".ex", files: 1 });
    expect(gaps[0]!.reason).toMatch(/symbols/);
  });

  it("records nothing when the context builds", () => {
    const repo = phoenixRepo();
    const gaps: ResolutionGap[] = [];
    buildFileResolver({ repo, files: [fileScan("src/a.js", "javascript"), fileScan("src/b.js", "javascript")] }, [], gaps);
    expect(gaps).toEqual([]);
  });
});

describe("scan — an Elixir repo", () => {
  it("completes, and says in the manifest which files import resolution left out", async () => {
    const repo = phoenixRepo();
    const out = mkdtempSync(join(tmpdir(), "ultrasec-resolve-guard-out-"));
    const code = await runScan(parseArgs(["scan", "--repo", repo, "--out", out, "--no-enrich", "--no-tools", "--offline", "--quiet"]));
    expect(code).toBe(0);
    const manifest = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8")) as { resolutionGaps?: ResolutionGap[] };
    expect(manifest.resolutionGaps).toEqual([expect.objectContaining({ ext: ".ex", files: 1 }), expect.objectContaining({ ext: ".exs", files: 1 })]);
  });
});
