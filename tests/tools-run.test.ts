import { describe, it, expect } from "vitest";
import { orchestrate, runAdapter, relativizeFindings, toolStatus, type ToolAdapter, type ToolRunResult } from "../src/tools/run.js";
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

describe("toolStatus (per-tool ran/empty/skipped/failed)", () => {
  const R = (o: Partial<ToolRunResult> & { name: string }): ToolRunResult => ({ ran: false, ok: false, findings: [], note: "", ...o });
  it("distinguishes ran-with-findings, ran-but-empty, skipped and failed", () => {
    const results: ToolRunResult[] = [
      R({ name: "trivy", ran: true, ok: true, findings: [{} as Finding, {} as Finding], note: "2 finding(s)" }),
      R({ name: "gitleaks", ran: true, ok: true, findings: [], note: "0 finding(s)" }),
      R({ name: "osv-scanner", ran: false, ok: false, note: "no target files" }),
      R({ name: "semgrep", ran: true, ok: false, note: "run failed: boom" }),
    ];
    expect(toolStatus(results)).toEqual([
      { name: "trivy", status: "ran", findings: 2, note: "2 finding(s)" },
      { name: "gitleaks", status: "empty", findings: 0, note: "0 finding(s)" },
      { name: "osv-scanner", status: "skipped", note: "no target files" },
      { name: "semgrep", status: "failed", note: "run failed: boom" },
    ]);
  });
});

describe("relativizeFindings (→ repo-relative, native or docker)", () => {
  const f: Finding = {
    id: "x",
    category: "dep",
    title: "t",
    severity: "high",
    confidence: "medium",
    message: "m",
    tool: "osv-scanner",
    status: "open",
    source: { file: "/work/a.js", line: 1 },
    sink: { file: "/work/pkg/b.js", line: 2 },
    path: [
      { file: "/work/a.js", line: 1, why: "s" },
      { file: "rel/c.js", line: 3, why: "k" },
    ],
  };
  it("strips the /work mount prefix (docker mode)", () => {
    const [g] = relativizeFindings([f], "/work");
    expect(g!.source!.file).toBe("a.js");
    expect(g!.sink!.file).toBe("pkg/b.js");
    expect(g!.path![0]!.file).toBe("a.js");
    expect(g!.path![1]!.file).toBe("rel/c.js"); // already relative, untouched
  });
  it("strips an absolute repo dir (native mode) and leaves external paths", () => {
    const nf: Finding = { ...f, sink: { file: "/home/me/proj/src/x.js", line: 9 }, source: undefined, path: undefined };
    expect(relativizeFindings([nf], "/home/me/proj")[0]!.sink!.file).toBe("src/x.js");
    const ext: Finding = { ...f, sink: { file: "/root/go/pkg/dep.go", line: 1 }, source: undefined, path: undefined };
    expect(relativizeFindings([ext], "/home/me/proj")[0]!.sink!.file).toBe("/root/go/pkg/dep.go"); // outside repo, untouched
  });
});
