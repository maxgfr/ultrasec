import { describe, it, expect } from "vitest";
import { join } from "node:path";
import type { Dossier } from "../src/store.js";
import type { Finding } from "../src/types.js";
import { check } from "../src/check.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

function dossier(findings: Finding[]): Dossier {
  return {
    manifest: {
      version: "0.0.0",
      schemaVersion: 1,
      repo: FIXTURE,
      generatedNote: "",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    },
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

function f(id: string, file: string, line: number, status: Finding["status"] = "confirmed"): Finding {
  return { id, category: "taint", title: id, severity: "high", confidence: "high", message: "m", tool: "ultrasec", status, sink: { file, line } };
}

describe("check — grounding", () => {
  it("passes when every cited [file:line] resolves", () => {
    const r = check(dossier([f("a", "src/db.js", 6)]));
    expect(r.ok).toBe(true);
    expect(r.dangling).toHaveLength(0);
  });

  it("fails on a nonexistent file", () => {
    const r = check(dossier([f("a", "src/ghost.js", 1)]));
    expect(r.ok).toBe(false);
    expect(r.dangling[0]!.reason).toBe("file not found");
  });

  it("fails on an out-of-range line (hallucinated location)", () => {
    const r = check(dossier([f("a", "src/db.js", 99999)]));
    expect(r.ok).toBe(false);
    expect(r.dangling[0]!.reason).toMatch(/out of range/);
  });

  it("ignores dismissed findings (the lead may have been false)", () => {
    const r = check(dossier([f("a", "src/ghost.js", 1, "dismissed")]));
    expect(r.ok).toBe(true);
  });
});

describe("check — semantic", () => {
  it("fails if a candidate is still unadjudicated", () => {
    const r = check(dossier([f("a", "src/db.js", 6, "open")]), { semantic: true });
    expect(r.ok).toBe(false);
    expect(r.messages.join(" ")).toMatch(/unadjudicated/);
  });

  it("passes once everything is adjudicated and grounded", () => {
    const r = check(dossier([f("a", "src/db.js", 6, "confirmed"), f("b", "src/report.js", 5, "dismissed")]), { semantic: true });
    expect(r.ok).toBe(true);
  });
});
