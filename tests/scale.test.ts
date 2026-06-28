import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";

// Generates a synthetic repo with the exact shape that blew up the OLD taint walk:
// one shared exported sink (`runQuery` → db.query) called from thousands of files,
// each carrying an http source. The pre-WS1 code rescanned ALL files per BFS frame
// (O(F²)); the reverse call-index makes it ~O(edges). We don't microbenchmark —
// we assert it completes comfortably and that truncation is reported, not silent.
const N = 2500;

describe("scale: shared-sink fan-out (O(edges) guard)", () => {
  let repo: string;
  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), "ultrasec-scale-"));
    mkdirSync(join(repo, "src"), { recursive: true });
    writeFileSync(
      join(repo, "src", "sink.js"),
      `function runQuery(x) {\n  return globalThis.db.query("SELECT * WHERE id=" + x);\n}\nmodule.exports = { runQuery };\n`,
    );
    for (let i = 0; i < N; i++) {
      writeFileSync(
        join(repo, "src", `h${i}.js`),
        `const { runQuery } = require("./sink");\nfunction h${i}(req) {\n  const x = req.query.q;\n  return runQuery(x);\n}\nmodule.exports = { h${i} };\n`,
      );
    }
  });
  afterAll(() => rmSync(repo, { recursive: true, force: true }));

  it("enumerates ~N cross-file candidates quickly and reports truncation", () => {
    const t0 = Date.now();
    const scan = scanRepo(repo);
    const graph = buildGraph(scan);
    // The reverse index for the shared sink symbol holds every caller.
    expect((graph.callersBySymbol?.["runQuery"] ?? []).length).toBe(N);

    const r = enumerateTaint(scan, graph); // default cap 1000
    const elapsed = Date.now() - t0;

    expect(r.total).toBeGreaterThanOrEqual(N); // one candidate per caller's source
    expect(r.findings.length).toBe(1000); // capped at the default
    expect(r.truncated).toBe(r.total - 1000); // remainder reported, never silent
    // Every kept candidate is the cross-file SQL flow into the shared sink.
    expect(r.findings.every((f) => f.cwe === "CWE-89")).toBe(true);
    // Comfortable wall-clock — the old O(F²) walk would be ~N× slower here.
    expect(elapsed).toBeLessThan(20_000);
  }, 60_000);

  it("a raised cap keeps them all with zero truncation", () => {
    const scan = scanRepo(repo);
    const r = enumerateTaint(scan, buildGraph(scan), { maxCandidates: N + 100 });
    expect(r.truncated).toBe(0);
    expect(r.findings.length).toBe(r.total);
  }, 60_000);
});
