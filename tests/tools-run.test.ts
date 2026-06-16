import { describe, it, expect } from "vitest";
import { orchestrate, runAdapter, type ToolAdapter } from "../src/tools/run.js";

const fake: ToolAdapter = {
  name: "definitely-not-a-real-binary-xyz",
  category: "sast",
  argv: () => ["--json"],
  parse: () => [],
};

describe("orchestrate (graceful degradation)", () => {
  it("skips uninstalled tools without throwing", () => {
    const r = orchestrate([fake], "/tmp");
    expect(r.findings).toEqual([]);
    expect(r.toolsRun).toEqual([]);
    expect(r.results[0]!.ran).toBe(false);
    expect(r.results[0]!.note).toBe("not installed");
  });

  it("runAdapter reports a missing binary as not-run", () => {
    const r = runAdapter(fake, "/tmp");
    expect(r.ran).toBe(false);
    expect(r.ok).toBe(false);
  });

  it("only runs selected tools when `which` is given", () => {
    const r = orchestrate([fake], "/tmp", ["some-other-tool"]);
    expect(r.results).toHaveLength(0); // fake not selected
  });
});
