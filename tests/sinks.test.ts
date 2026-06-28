import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";
import { enumerateSinkCandidates } from "../src/sinks.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

describe("enumerateSinkCandidates (orphan-sink recall)", () => {
  const scan = scanRepo(FIXTURE);
  const graph = buildGraph(scan);
  const taint = enumerateTaint(scan, graph).findings;

  it("emits a dangerous sink with no source-reachable taint path as a low-confidence sast candidate", () => {
    const { findings } = enumerateSinkCandidates(scan, taint);
    // db.js:11 is getUserSafe's parameterized query() — a real SQL sink the
    // source-gated taint BFS never connects to a source, so it yields zero taint
    // findings today. The orphan-sink layer must surface it for adjudication.
    const orphan = findings.find((f) => f.sink!.file === "src/db.js" && f.sink!.line === 11);
    expect(orphan, "expected an orphan sink candidate at db.js:11").toBeTruthy();
    expect(orphan!.category).toBe("sast");
    expect(orphan!.confidence).toBe("low");
    expect(orphan!.status).toBe("open");
    expect(orphan!.tool).toBe("ultrasec");
    expect(orphan!.cwe).toBe("CWE-89");
    expect(orphan!.sink!.kind).toBe("sql");
    // it is a sink-only candidate — no proven source→sink path
    expect(orphan!.path).toBeUndefined();
    expect(orphan!.source).toBeUndefined();
  });

  it("does NOT re-emit a sink already covered by a taint finding", () => {
    const { findings } = enumerateSinkCandidates(scan, taint);
    for (const t of taint) {
      const dup = findings.find((f) => f.sink!.file === t.sink!.file && f.sink!.line === t.sink!.line && f.sink!.kind === t.sink!.kind);
      expect(dup, `orphan layer duplicated a covered taint sink ${t.sink!.file}:${t.sink!.line}`).toBeFalsy();
    }
  });

  it("rank-then-caps and reports truncation (never silent)", () => {
    const full = enumerateSinkCandidates(scan, []);
    expect(full.total).toBe(full.findings.length);
    expect(full.total).toBeGreaterThanOrEqual(2);
    const capped = enumerateSinkCandidates(scan, [], { maxCandidates: 1 });
    expect(capped.findings.length).toBe(1);
    expect(capped.total).toBe(full.total);
    expect(capped.truncated).toBe(full.total - 1);
  });

  it("produces ids disjoint from taint ids and is idempotent", () => {
    const first = enumerateSinkCandidates(scan, taint).findings;
    const taintIds = new Set(taint.map((f) => f.id));
    expect(first.every((f) => !taintIds.has(f.id))).toBe(true);
    const second = enumerateSinkCandidates(scan, taint).findings;
    expect(second.map((f) => f.id)).toEqual(first.map((f) => f.id));
  });
});
