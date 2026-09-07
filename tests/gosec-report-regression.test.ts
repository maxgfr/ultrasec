import { describe, expect, it } from "vitest";
import { gosec } from "../src/tools/gosec.js";
import { orchestrate, runAdapter, toolStatus, type ToolResultCache } from "../src/tools/run.js";
import { tmpdir } from "node:os";
import { join } from "node:path";

function partialAdapter() {
  const raw = JSON.stringify({
    "Golang errors": { broken: [{ error: "undefined: Missing" }] },
    Issues: [{ severity: "HIGH", confidence: "HIGH", rule_id: "G404", details: "Weak random generator", file: join(tmpdir(), "good.go"), line: "3" }],
  });
  return { ...gosec, applicable: () => null, command: () => [process.execPath], argv: () => ["-e", `process.stdout.write(${JSON.stringify(raw)})`] };
}

describe("gosec scan coverage", () => {
  it.each(["", "   ", "{}", "null", "[]", "not JSON"])("rejects a missing or malformed report: %j", (raw) => {
    expect(() => gosec.parse(raw, "/repo")).toThrow();
  });

  it("rejects package-loading errors instead of reporting a clean scan", () => {
    const raw = JSON.stringify({
      "Golang errors": { ".": [{ line: 0, column: 0, error: "go command required, not found" }] },
      Issues: [],
      Stats: { files: 0, lines: 0, nosec: 0, found: 0 },
    });
    expect(() => gosec.parse(raw, "/repo")).toThrow(/go command required, not found/);
  });

  it("accepts a valid clean report", () => {
    expect(gosec.parse(JSON.stringify({ "Golang errors": {}, Issues: [], Stats: { files: 1, lines: 8, nosec: 0, found: 0 } }), "/repo")).toEqual([]);
  });

  it("does not silence gosec diagnostics", () => {
    expect(gosec.argv("/repo")).not.toContain("-quiet");
  });

  it("retains real issues from partially analyzed packages without declaring success or caching the failure", async () => {
    const cache: ToolResultCache = { entries: new Map(), treeDigest: "fixture" };
    const result = await runAdapter(partialAdapter(), tmpdir(), false, { cache });
    expect(result.ok).toBe(false);
    expect(result.ran).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.sink?.file).toBe("good.go");
    expect(result.note).toContain("undefined: Missing");
    expect(toolStatus([result])[0]?.status).toBe("failed");
    expect(cache.entries.size).toBe(0);
  });

  it("applies the same ignored-path pruning to partial findings", async () => {
    const result = await runAdapter(partialAdapter(), tmpdir(), false, { pruned: (file) => file === "good.go" });
    expect(result.ok).toBe(false);
    expect(result.findings).toEqual([]);
    expect(result.note).toContain("1 pruned");
  });

  it("keeps partial evidence in the orchestrated dossier, not the successfully run tool list", async () => {
    const result = await orchestrate([partialAdapter()], tmpdir());
    expect(result.findings).toHaveLength(1);
    expect(result.toolsRun).toEqual([]);
    expect(result.results[0]?.ok).toBe(false);
  });

  it("retains partial findings from an incomplete workspace without marking it covered", async () => {
    const result = await runAdapter({ ...partialAdapter(), workspaces: () => [tmpdir()] }, tmpdir());
    expect(result.findings).toHaveLength(1);
    expect(result.ok).toBe(false);
    expect(result.workspaceCoverage).toEqual({ total: 1, completed: 0 });
  });
});
