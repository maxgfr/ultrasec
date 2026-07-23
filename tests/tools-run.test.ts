import { describe, it, expect } from "vitest";
import { orchestrate, runAdapter, relativizeFindings, toolStatus, type ToolAdapter, type ToolRunResult, type RunContext } from "../src/tools/run.js";
import type { Finding } from "../src/types.js";

// A node -e one-liner stands in for a real scanner binary: cross-platform, no
// bash/shell dependency, and it lets `command()`-override adapters be exercised
// end to end (spawn → parse) without relying on any PATH tool being installed.
const nodeEcho: ToolAdapter = {
  name: "fake-node-tool",
  category: "sast",
  command: () => [process.execPath],
  argv: () => ["-e", "console.log('[]')"],
  parse: (raw) => JSON.parse(raw),
};

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

describe("ToolAdapter.command (executable override)", () => {
  it("runs via the overridden executable instead of a PATH probe on adapter.name", () => {
    const r = runAdapter(nodeEcho, "/tmp");
    expect(r.ran).toBe(true);
    expect(r.ok).toBe(true);
    expect(r.findings).toEqual([]);
    expect(r.note).toBe("0 finding(s)");
  });

  it("command() returning null is a graceful 'not installed' skip", () => {
    const adapter: ToolAdapter = { ...nodeEcho, name: "fake-unsupported-host", command: () => null };
    const r = runAdapter(adapter, "/tmp");
    expect(r.ran).toBe(false);
    expect(r.ok).toBe(false);
    expect(r.note).toBe("not installed");
  });
});

describe("ToolAdapter.applicable (repo-content gate)", () => {
  it("a string result skips the run and surfaces as the note, without touching argv", () => {
    let argvCalled = false;
    const adapter: ToolAdapter = {
      ...nodeEcho,
      name: "fake-gated-tool",
      applicable: () => "no package-lock.json",
      argv: () => {
        argvCalled = true;
        return ["-e", "console.log('[]')"];
      },
    };
    const r = runAdapter(adapter, "/tmp");
    expect(r.ran).toBe(false);
    expect(r.note).toBe("no package-lock.json");
    expect(argvCalled).toBe(false);
    expect(toolStatus([r])).toEqual([{ name: "fake-gated-tool", status: "skipped", note: "no package-lock.json" }]);
  });

  it("null applicable() lets the run proceed", () => {
    const adapter: ToolAdapter = { ...nodeEcho, name: "fake-applicable-ok", applicable: () => null };
    const r = runAdapter(adapter, "/tmp");
    expect(r.ran).toBe(true);
    expect(r.ok).toBe(true);
  });
});

describe("ToolAdapter.network + RunContext.offline", () => {
  it("network:true is skipped under --offline with a dedicated note, and runs otherwise", () => {
    const adapter: ToolAdapter = { ...nodeEcho, name: "fake-network-tool", network: true };
    const offlineResult = orchestrate([adapter], "/tmp", { offline: true }).results[0]!;
    expect(offlineResult.ran).toBe(false);
    expect(offlineResult.note).toBe("offline (network required)");

    const onlineResult = orchestrate([adapter], "/tmp", { offline: false }).results[0]!;
    expect(onlineResult.ran).toBe(true);
    expect(onlineResult.ok).toBe(true);
  });

  it("a network predicate is re-evaluated on every run, not cached", () => {
    let needsNetwork = true;
    const adapter: ToolAdapter = { ...nodeEcho, name: "fake-flip-network-tool", network: () => needsNetwork };

    const first = runAdapter(adapter, "/tmp", false, { offline: true });
    expect(first.ran).toBe(false);
    expect(first.note).toBe("offline (network required)");

    needsNetwork = false;
    const second = runAdapter(adapter, "/tmp", false, { offline: true });
    expect(second.ran).toBe(true);
    expect(second.ok).toBe(true);
  });

  it("an adapter without network runs under --offline unaffected", () => {
    const r = orchestrate([nodeEcho], "/tmp", { offline: true }).results[0]!;
    expect(r.ran).toBe(true);
    expect(r.ok).toBe(true);
  });
});

describe("RunContext propagation", () => {
  it("passes offline/sbom through to argv()", () => {
    let received: RunContext | undefined;
    const adapter: ToolAdapter = {
      ...nodeEcho,
      name: "fake-ctx-tool",
      argv: (_target, ctx) => {
        received = ctx;
        return ["-e", "console.log('[]')"];
      },
    };
    orchestrate([adapter], "/tmp", { offline: false, sbom: "/abs/path/sbom.json" });
    expect(received).toEqual({ offline: false, sbom: "/abs/path/sbom.json" });
  });
});

describe("docker mode + command-override adapters", () => {
  it("still excludes command-override adapters that have no dockerImage", () => {
    const r = orchestrate([nodeEcho], "/tmp", { useDocker: true });
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
