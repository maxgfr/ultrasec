import { describe, it, expect, vi } from "vitest";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  orchestrate,
  runAdapter,
  relativizeFindings,
  toolStatus,
  CACHED_NOTE,
  type ToolAdapter,
  type ToolRunResult,
  type ToolResultCache,
  type RunContext,
} from "../src/tools/run.js";
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
  it("skips uninstalled tools without throwing", async () => {
    const r = await orchestrate([fake], "/tmp");
    expect(r.findings).toEqual([]);
    expect(r.toolsRun).toEqual([]);
    expect(r.results[0]!.ran).toBe(false);
    expect(r.results[0]!.note).toBe("not installed");
  });

  it("runAdapter reports a missing binary as not-run", async () => {
    const r = await runAdapter(fake, "/tmp");
    expect(r.ran).toBe(false);
    expect(r.ok).toBe(false);
  });

  it("only runs selected tools when `which` is given", async () => {
    const r = await orchestrate([fake], "/tmp", { which: ["some-other-tool"] });
    expect(r.results).toHaveLength(0); // fake not selected
  });

  it("in docker mode, skips adapters that have no official image", async () => {
    const r = await orchestrate([fake], "/tmp", { useDocker: true }); // fake has no dockerImage
    expect(r.results).toHaveLength(0);
    expect(r.findings).toEqual([]);
  });
});

describe("ToolAdapter.command (executable override)", () => {
  it("runs via the overridden executable instead of a PATH probe on adapter.name", async () => {
    const r = await runAdapter(nodeEcho, "/tmp");
    expect(r.ran).toBe(true);
    expect(r.ok).toBe(true);
    expect(r.findings).toEqual([]);
    expect(r.note).toBe("0 finding(s)");
  });

  it("command() returning null is a graceful 'not installed' skip", async () => {
    const adapter: ToolAdapter = { ...nodeEcho, name: "fake-unsupported-host", command: () => null };
    const r = await runAdapter(adapter, "/tmp");
    expect(r.ran).toBe(false);
    expect(r.ok).toBe(false);
    expect(r.note).toBe("not installed");
  });
});

describe("ToolAdapter.applicable (repo-content gate)", () => {
  it("a string result skips the run and surfaces as the note, without touching argv", async () => {
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
    const r = await runAdapter(adapter, "/tmp");
    expect(r.ran).toBe(false);
    expect(r.note).toBe("no package-lock.json");
    expect(argvCalled).toBe(false);
    expect(toolStatus([r])).toEqual([{ name: "fake-gated-tool", status: "skipped", note: "no package-lock.json" }]);
  });

  it("null applicable() lets the run proceed", async () => {
    const adapter: ToolAdapter = { ...nodeEcho, name: "fake-applicable-ok", applicable: () => null };
    const r = await runAdapter(adapter, "/tmp");
    expect(r.ran).toBe(true);
    expect(r.ok).toBe(true);
  });
});

describe("ToolAdapter.network + RunContext.offline", () => {
  it("network:true is skipped under --offline with a dedicated note, and runs otherwise", async () => {
    const adapter: ToolAdapter = { ...nodeEcho, name: "fake-network-tool", network: true };
    const offlineResult = (await orchestrate([adapter], "/tmp", { offline: true })).results[0]!;
    expect(offlineResult.ran).toBe(false);
    expect(offlineResult.note).toBe("offline (network required)");

    const onlineResult = (await orchestrate([adapter], "/tmp", { offline: false })).results[0]!;
    expect(onlineResult.ran).toBe(true);
    expect(onlineResult.ok).toBe(true);
  });

  it("a network predicate is re-evaluated on every run, not cached", async () => {
    let needsNetwork = true;
    const adapter: ToolAdapter = { ...nodeEcho, name: "fake-flip-network-tool", network: () => needsNetwork };

    const first = await runAdapter(adapter, "/tmp", false, { offline: true });
    expect(first.ran).toBe(false);
    expect(first.note).toBe("offline (network required)");

    needsNetwork = false;
    const second = await runAdapter(adapter, "/tmp", false, { offline: true });
    expect(second.ran).toBe(true);
    expect(second.ok).toBe(true);
  });

  it("an adapter without network runs under --offline unaffected", async () => {
    const r = (await orchestrate([nodeEcho], "/tmp", { offline: true })).results[0]!;
    expect(r.ran).toBe(true);
    expect(r.ok).toBe(true);
  });
});

describe("RunContext propagation", () => {
  it("passes offline/sbom through to argv()", async () => {
    let received: RunContext | undefined;
    const adapter: ToolAdapter = {
      ...nodeEcho,
      name: "fake-ctx-tool",
      argv: (_target, ctx) => {
        received = ctx;
        return ["-e", "console.log('[]')"];
      },
    };
    await orchestrate([adapter], "/tmp", { offline: false, sbom: "/abs/path/sbom.json" });
    expect(received).toEqual({ offline: false, sbom: "/abs/path/sbom.json" });
  });
});

describe("docker mode + command-override adapters", () => {
  it("still excludes command-override adapters that have no dockerImage", async () => {
    const r = await orchestrate([nodeEcho], "/tmp", { useDocker: true });
    expect(r.results).toHaveLength(0);
    expect(r.findings).toEqual([]);
  });
});

describe("docker mode → always pulls the rolling `latest` tag fresh", () => {
  it("runDocker's argv forces `--pull always` so a stale cached `latest` is never silently reused", async () => {
    vi.resetModules();
    let seenCommand: string | undefined;
    let seenArgs: string[] | undefined;
    vi.doMock("node:child_process", async (importOriginal) => {
      const original = await importOriginal<typeof import("node:child_process")>();
      return {
        ...original,
        execFile: (command: string, args: string[], _opts: unknown, cb: (e: null, out: string, err: string) => void) => {
          seenCommand = command;
          seenArgs = args;
          cb(null, "[]", "");
        },
      };
    });
    try {
      const fresh = await import("../src/tools/run.js");
      const dockerAdapter: import("../src/tools/run.js").ToolAdapter = {
        name: "fake-docker-tool",
        category: "sast",
        dockerImage: "example.org/fake-tool:latest",
        argv: () => ["--json"],
        parse: () => [],
      };
      const r = await fresh.runAdapter(dockerAdapter, "/repo", true);
      expect(r.ran).toBe(true);
      expect(seenCommand).toBe("docker");
      expect(seenArgs).toBeDefined();
      // `--pull always` must be present so a cached `latest` never wins silently.
      const pullIdx = seenArgs!.indexOf("--pull");
      expect(pullIdx).toBeGreaterThan(-1);
      expect(seenArgs![pullIdx + 1]).toBe("always");
      // And the run actually targets the adapter's rolling-tag image.
      expect(seenArgs).toContain("example.org/fake-tool:latest");
    } finally {
      vi.doUnmock("node:child_process");
      vi.resetModules();
    }
  });
});

describe("result cache (`cacheable` adapters under --resume)", () => {
  /** A fake scanner that records every spawn in `marker`, so a replay is provable. */
  const spawnCounting = (name: string, marker: string, cacheable = true): ToolAdapter => ({
    name,
    category: "sast",
    cacheable,
    command: () => [process.execPath],
    argv: () => [
      "-e",
      `require("node:fs").appendFileSync(${JSON.stringify(marker)}, "x"); console.log('[{"id":"z","category":"sast","title":"t","severity":"low","confidence":"low","message":"m","tool":"fake","status":"open"}]')`,
    ],
    parse: (raw) => JSON.parse(raw),
  });
  const spawns = (marker: string) => (existsSync(marker) ? readFileSync(marker, "utf8").length : 0);
  const cacheFor = (over: Partial<ToolResultCache> = {}): ToolResultCache => ({ entries: new Map(), treeDigest: "digest-1", head: "abc", salt: "s", ...over });

  it("replays the second run from the cache: same note plus the cached marker, one spawn", async () => {
    const marker = join(mkdtempSync(join(tmpdir(), "ultrasec-toolcache-")), "spawns");
    const adapter = spawnCounting("fake-cacheable-tool", marker);
    const cache = cacheFor();
    const first = (await orchestrate([adapter], "/tmp", { cache })).results[0]!;
    expect(first.ok).toBe(true);
    expect(first.findings).toHaveLength(1);
    expect(first.note).toBe("1 finding(s)");
    expect(spawns(marker)).toBe(1);

    const second = (await orchestrate([adapter], "/tmp", { cache })).results[0]!;
    expect(second.ok).toBe(true);
    expect(second.findings).toEqual(first.findings);
    expect(second.note).toBe(`1 finding(s) · ${CACHED_NOTE}`);
    expect(spawns(marker)).toBe(1); // no second spawn
    expect(toolStatus([second])[0]!.note).toContain("cached");
  });

  it("re-runs when the tree digest, HEAD or the argv changed", async () => {
    const marker = join(mkdtempSync(join(tmpdir(), "ultrasec-toolcache-")), "spawns");
    const adapter = spawnCounting("fake-cacheable-tool", marker);
    const entries = new Map();
    await orchestrate([adapter], "/tmp", { cache: cacheFor({ entries }) });
    await orchestrate([adapter], "/tmp", { cache: cacheFor({ entries, treeDigest: "digest-2" }) });
    expect(spawns(marker)).toBe(2);
    await orchestrate([adapter], "/tmp", { cache: cacheFor({ entries, treeDigest: "digest-2", head: "def" }) });
    expect(spawns(marker)).toBe(3);
    const other = { ...adapter, argv: () => [...adapter.argv("/tmp"), "extra-positional"] };
    await orchestrate([other], "/tmp", { cache: cacheFor({ entries, treeDigest: "digest-2", head: "def" }) });
    expect(spawns(marker)).toBe(4);
  });

  it("never replays an adapter that does not claim `cacheable`, and never without a cache", async () => {
    const marker = join(mkdtempSync(join(tmpdir(), "ultrasec-toolcache-")), "spawns");
    const adapter = spawnCounting("fake-uncacheable-tool", marker, false);
    const cache = cacheFor();
    await orchestrate([adapter], "/tmp", { cache });
    await orchestrate([adapter], "/tmp", { cache });
    expect(spawns(marker)).toBe(2);
    expect(cache.entries.size).toBe(0);
    const cacheable = spawnCounting("fake-cacheable-tool", marker);
    await orchestrate([cacheable], "/tmp");
    await orchestrate([cacheable], "/tmp");
    expect(spawns(marker)).toBe(4);
  });
});

describe("orchestrate — concurrency pool", () => {
  const sleeper = (name: string, ms: number): ToolAdapter => ({
    name,
    category: "sast",
    command: () => [process.execPath],
    argv: () => ["-e", `setTimeout(() => console.log('[]'), ${ms})`],
    parse: (raw) => JSON.parse(raw),
  });

  it("keeps `results` in adapter order whatever order the processes finish in", async () => {
    const adapters = [sleeper("slow", 300), sleeper("fast", 10), sleeper("mid", 100)];
    const seen: string[] = [];
    const r = await orchestrate(adapters, "/tmp", { concurrency: 3, onProgress: (e) => e.result && seen.push(e.tool) });
    expect(r.results.map((x) => x.name)).toEqual(["slow", "fast", "mid"]);
    expect(seen).toEqual(["fast", "mid", "slow"]); // completion order — the pool really ran them together
    expect(r.toolsRun).toEqual(["slow", "fast", "mid"]);
  });

  it("concurrency 1 is the old serial run", async () => {
    const seen: string[] = [];
    await orchestrate([sleeper("a", 50), sleeper("b", 10)], "/tmp", {
      concurrency: 1,
      onProgress: (e) => seen.push(`${e.tool}:${e.result ? "done" : "start"}`),
    });
    expect(seen).toEqual(["a:start", "a:done", "b:start", "b:done"]);
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
