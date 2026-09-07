import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runAdapter, toolStatus, type ToolAdapter } from "../src/tools/run.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("workspace execution completeness", () => {
  it.each([false, true])("records actual subprocess coverage without discarding successful results (failure=%s)", async (fail) => {
    const root = mkdtempSync(join(tmpdir(), "ultrasec-workspace-completion-"));
    dirs.push(root);
    const workspaces = [join(root, "good"), join(root, "bad")];
    workspaces.forEach((p) => mkdirSync(p));
    const adapter: ToolAdapter = {
      name: "fixture-workspace-tool",
      category: "sast",
      argv: () => [],
      command: () => [process.execPath, "-e", `if (${fail} && process.cwd().endsWith('bad')) process.exit(2); process.stdout.write('[]');`],
      workspaces: () => workspaces,
      parse: (raw) => JSON.parse(raw),
    };
    const result = await runAdapter(adapter, root);
    // The legacy optional path remains tolerant of partial workspace failures.
    expect(result.ok).toBe(true);
    expect(result.ran).toBe(true);
    expect(result.workspaceCoverage).toEqual({ total: 2, completed: fail ? 1 : 2 });
    expect(toolStatus([result])[0]?.workspaceCoverage).toEqual(result.workspaceCoverage);
  });
});
