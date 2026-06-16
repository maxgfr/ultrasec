import { describe, it, expect } from "vitest";
import type { Dossier } from "../src/store.js";
import type { Finding, Severity } from "../src/types.js";
import { buildWorklist, shard, applyVerdicts, parseVerdicts } from "../src/verify.js";

function finding(id: string, severity: Severity, status: Finding["status"] = "open"): Finding {
  return {
    id,
    category: "taint",
    cwe: "CWE-89",
    title: `finding ${id}`,
    severity,
    confidence: "low",
    message: "candidate",
    tool: "ultrasec",
    status,
    sink: { file: "src/db.js", line: 6 },
    path: [
      { file: "src/server.js", line: 10, why: "source" },
      { file: "src/db.js", line: 6, why: "sink" },
    ],
  };
}

function dossier(findings: Finding[]): Dossier {
  return {
    manifest: {
      version: "0.0.0",
      schemaVersion: 1,
      repo: "/repo",
      generatedNote: "",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    },
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

describe("buildWorklist", () => {
  it("includes open + needs-human, excludes confirmed/dismissed", () => {
    const d = dossier([finding("a", "high"), finding("b", "high", "confirmed"), finding("c", "high", "needs-human"), finding("d", "high", "dismissed")]);
    expect(buildWorklist(d).map((i) => i.id)).toEqual(["a", "c"]);
  });
});

describe("shard", () => {
  it("round-robins into disjoint balanced slices covering everything", () => {
    const items = [1, 2, 3, 4, 5];
    const s0 = shard(items, 2, 0);
    const s1 = shard(items, 2, 1);
    expect(s0).toEqual([1, 3, 5]);
    expect(s1).toEqual([2, 4]);
    expect([...s0, ...s1].sort()).toEqual(items);
  });
});

describe("applyVerdicts — conservative policy", () => {
  it("supported → confirmed (confidence raised)", () => {
    const r = applyVerdicts(dossier([finding("a", "high")]), [{ id: "a", verdict: "supported", exploitPath: "POST /x" }]);
    expect(r.findings[0]!.status).toBe("confirmed");
    expect(r.findings[0]!.confidence).toBe("high");
    expect(r.findings[0]!.exploitPath).toBe("POST /x");
    expect(r.confirmed).toBe(1);
  });

  it("refuted → dismissed (explicit contradiction is safe to drop)", () => {
    const r = applyVerdicts(dossier([finding("a", "critical")]), [{ id: "a", verdict: "refuted" }]);
    expect(r.findings[0]!.status).toBe("dismissed");
  });

  it("unsupported on a HIGH finding → needs-human, NOT dismissed", () => {
    const r = applyVerdicts(dossier([finding("a", "high")]), [{ id: "a", verdict: "unsupported" }]);
    expect(r.findings[0]!.status).toBe("needs-human");
    expect(r.keptForHuman).toHaveLength(1);
  });

  it("unsupported on a LOW finding → dismissed", () => {
    const r = applyVerdicts(dossier([finding("a", "low")]), [{ id: "a", verdict: "unsupported" }]);
    expect(r.findings[0]!.status).toBe("dismissed");
  });

  it("partial → needs-human", () => {
    const r = applyVerdicts(dossier([finding("a", "medium")]), [{ id: "a", verdict: "partial" }]);
    expect(r.findings[0]!.status).toBe("needs-human");
  });
});

describe("parseVerdicts", () => {
  it("accepts a bare array and a {verdicts:[]} wrapper, dropping malformed", () => {
    expect(parseVerdicts('[{"id":"a","verdict":"supported"},{"bad":1}]')).toEqual([{ id: "a", verdict: "supported", note: undefined, exploitPath: undefined }]);
    expect(parseVerdicts('{"verdicts":[{"id":"b","verdict":"refuted"}]}')[0]!.id).toBe("b");
  });
});
