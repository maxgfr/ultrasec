import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { buildAttackSurface } from "../src/map.js";
import { buildInvestigateWorklist, ingestDiscoveries, parseDiscoveries, type Discovery } from "../src/investigate.js";
import type { Dossier } from "../src/store.js";
import type { Finding } from "../src/types.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

function dossier(findings: Finding[]): Dossier {
  const scan = scanRepo(FIXTURE);
  return {
    manifest: {
      version: "0.0.0",
      schemaVersion: 4,
      repo: FIXTURE,
      generatedNote: "",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    },
    findings,
    graph: buildGraph(scan),
  };
}

describe("buildInvestigateWorklist — region grouping with neighbours", () => {
  it("groups by attack-surface region and surfaces graph neighbours", () => {
    const scan = scanRepo(FIXTURE);
    const regions = buildInvestigateWorklist(buildAttackSurface(scan), buildGraph(scan));
    const src = regions.find((r) => r.region === "src");
    expect(src).toBeDefined();
    expect(src!.files.some((f) => f === "src/server.js")).toBe(true);
    // server.js imports db.js + report.js → those are 1-hop neighbours
    expect(src!.neighbors.length).toBeGreaterThan(0);
    expect(src!.files).not.toContain(undefined);
  });
});

describe("ingestDiscoveries", () => {
  const existing: Finding = {
    id: "exist1",
    category: "taint",
    cwe: "CWE-89",
    title: "SQLi",
    severity: "high",
    confidence: "high",
    message: "known",
    tool: "ultrasec",
    sources: ["ultrasec"],
    status: "confirmed",
    sink: { file: "src/db.js", line: 6 },
  };

  const newDisc: Discovery = {
    title: "Missing authorization on getUser",
    category: "authz",
    severity: "high",
    cwe: "CWE-862",
    message: "No auth guard before the DB read.",
    file: "src/server.js",
    line: 9,
  };

  it("ingests a new, in-range discovery as an open ultrasec-ai finding", () => {
    const res = ingestDiscoveries(dossier([existing]), [newDisc], FIXTURE);
    expect(res.ingested).toBe(1);
    expect(res.rejected).toHaveLength(0);
    const added = res.findings.find((f) => f.title === newDisc.title)!;
    expect(added.tool).toBe("ultrasec-ai");
    expect(added.status).toBe("open");
    expect(added.sources).toContain("ultrasec-ai");
    expect(added.sink).toEqual({ file: "src/server.js", line: 9 });
  });

  it("folds a discovery at an existing finding's location into its sources (no duplicate)", () => {
    const dupe: Discovery = { title: "SQLi", category: "taint", severity: "high", cwe: "CWE-89", message: "same spot", file: "src/db.js", line: 6 };
    const res = ingestDiscoveries(dossier([existing]), [dupe], FIXTURE);
    expect(res.ingested).toBe(0);
    expect(res.folded).toBe(1);
    expect(res.findings).toHaveLength(1); // no new finding
    expect(res.findings[0]!.sources).toEqual(["ultrasec", "ultrasec-ai"]);
  });

  it("rejects an out-of-range / nonexistent citation before folding", () => {
    const bad: Discovery = { title: "ghost", category: "sast", severity: "high", message: "m", file: "src/db.js", line: 99999 };
    const ghostFile: Discovery = { title: "ghost2", category: "sast", severity: "high", message: "m", file: "src/nope.js", line: 1 };
    const res = ingestDiscoveries(dossier([existing]), [bad, ghostFile], FIXTURE);
    expect(res.ingested).toBe(0);
    expect(res.rejected).toHaveLength(2);
    expect(res.rejected[0]!.reason).toMatch(/out of range/);
    expect(res.rejected[1]!.reason).toMatch(/not found/);
  });

  it("also validates path-step citations", () => {
    const badPath: Discovery = {
      title: "multi-hop",
      category: "taint",
      severity: "high",
      message: "m",
      file: "src/server.js",
      line: 9,
      path: [
        { file: "src/server.js", line: 9, why: "source" },
        { file: "src/db.js", line: 99999, why: "sink out of range" },
      ],
    };
    const res = ingestDiscoveries(dossier([existing]), [badPath], FIXTURE);
    expect(res.ingested).toBe(0);
    expect(res.rejected).toHaveLength(1);
  });

  it("produces stable ids across re-ingest (idempotent)", () => {
    const a = ingestDiscoveries(dossier([existing]), [newDisc], FIXTURE);
    const b = ingestDiscoveries(dossier([existing]), [newDisc], FIXTURE);
    const idA = a.findings.find((f) => f.title === newDisc.title)!.id;
    const idB = b.findings.find((f) => f.title === newDisc.title)!.id;
    expect(idA).toBe(idB);
  });
});

describe("parseDiscoveries", () => {
  it("keeps valid discoveries, drops ones with bad category/severity/missing fields", () => {
    const raw = JSON.stringify([
      { title: "ok", category: "authz", severity: "high", message: "m", file: "a.js", line: 3 },
      { title: "bad-cat", category: "nope", severity: "high", message: "m", file: "a.js", line: 3 },
      { title: "bad-sev", category: "authz", severity: "extreme", message: "m", file: "a.js", line: 3 },
      { title: "no-line", category: "authz", severity: "high", message: "m", file: "a.js" },
    ]);
    const out = parseDiscoveries(raw);
    expect(out.map((d) => d.title)).toEqual(["ok"]);
  });

  it("accepts a {discoveries:[]} wrapper and normalizes path steps", () => {
    const raw = JSON.stringify({
      discoveries: [{ title: "t", category: "taint", severity: "high", message: "m", file: "a.js", line: 1, path: [{ file: "a.js", line: 1 }] }],
    });
    const out = parseDiscoveries(raw);
    expect(out).toHaveLength(1);
    expect(out[0]!.path![0]).toEqual({ file: "a.js", line: 1, why: "" });
  });
});
