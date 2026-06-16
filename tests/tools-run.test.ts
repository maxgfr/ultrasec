import { describe, it, expect } from "vitest";
import { orchestrate, runAdapter, unmountFindings, type ToolAdapter } from "../src/tools/run.js";
import type { Finding } from "../src/types.js";

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
    const r = orchestrate([fake], "/tmp", { which: ["some-other-tool"] });
    expect(r.results).toHaveLength(0); // fake not selected
  });

  it("in docker mode, skips adapters that have no official image", () => {
    const r = orchestrate([fake], "/tmp", { useDocker: true }); // fake has no dockerImage
    expect(r.results).toHaveLength(0);
    expect(r.findings).toEqual([]);
  });
});

describe("unmountFindings (docker /work → repo-relative)", () => {
  it("strips the /work mount prefix from every location", () => {
    const f: Finding = {
      id: "x", category: "dep", title: "t", severity: "high", confidence: "medium", message: "m", tool: "osv-scanner", status: "open",
      source: { file: "/work/a.js", line: 1 },
      sink: { file: "/work/pkg/b.js", line: 2 },
      path: [{ file: "/work/a.js", line: 1, why: "s" }, { file: "rel/c.js", line: 3, why: "k" }],
    };
    const [g] = unmountFindings([f]);
    expect(g!.source!.file).toBe("a.js");
    expect(g!.sink!.file).toBe("pkg/b.js");
    expect(g!.path![0]!.file).toBe("a.js");
    expect(g!.path![1]!.file).toBe("rel/c.js"); // already relative, untouched
  });
});
