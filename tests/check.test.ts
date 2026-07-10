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

describe("check — file-scoped (line 0) citations", () => {
  // Eval P1.4: checkov/IaC config findings normalize to line 0 (a whole-file
  // finding). The gate used to reject line < 1, so a fresh --docker scan failed
  // its own mandatory gate. A line-0 citation now means "this file" — only file
  // existence is checked, not a line range.
  it("passes a line-0 citation when the file exists", () => {
    const r = check(dossier([f("a", "src/db.js", 0)]));
    expect(r.ok).toBe(true);
    expect(r.dangling).toHaveLength(0);
  });

  it("still fails a line-0 citation when the file does not exist", () => {
    const r = check(dossier([f("a", "src/ghost.js", 0)]));
    expect(r.ok).toBe(false);
    expect(r.dangling[0]!.reason).toBe("file not found");
  });

  it("still rejects a negative line and an out-of-range line", () => {
    expect(check(dossier([f("a", "src/db.js", -1)])).ok).toBe(false);
    expect(check(dossier([f("a", "src/db.js", 99999)])).ok).toBe(false);
  });

  it("grounds dep locations[] — file must resolve, line 0/absent is whole-file", () => {
    const dep: Finding = {
      id: "d",
      category: "dep",
      title: "adv",
      severity: "high",
      confidence: "medium",
      message: "m",
      tool: "osv-scanner",
      status: "confirmed",
      sink: { file: "package.json", line: 1 },
      locations: [
        { file: "package.json", line: 0, version: "1.0.0" },
        { file: "app/package.json", version: "2.0.0" },
      ],
    };
    // app/package.json doesn't exist in the fixture → that instance is a dangling citation.
    const r = check(dossier([dep]));
    expect(r.ok).toBe(false);
    expect(r.dangling.some((d) => d.file === "app/package.json")).toBe(true);
    expect(r.dangling.some((d) => d.file === "package.json")).toBe(false);
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

  // Gate integrity (fail-closed): the semantic gate must treat ANY non-adjudicated
  // status as unadjudicated — not only the literal "open". A finding whose status
  // is unknown/foreign (version skew, a tampered/corrupted findings.json, an
  // externally-authored dossier) carries no real verdict, yet an equality-on-"open"
  // check would wave it through ("audit adjudicated"). That is the stale-ledger
  // fail-open class: the gate must detect unadjudicated claims, not just refuted ones.
  it("fails on an unknown/foreign status (not just literal open)", () => {
    const r = check(dossier([f("a", "src/db.js", 6, "reviewed" as Finding["status"])]), { semantic: true });
    expect(r.ok).toBe(false);
    expect(r.messages.join(" ")).toMatch(/unadjudicated/);
  });

  it("fails when a finding carries no status field at all", () => {
    const bare = {
      id: "a",
      category: "taint",
      title: "a",
      severity: "high",
      confidence: "high",
      message: "m",
      tool: "ultrasec",
      sink: { file: "src/db.js", line: 6 },
    } as unknown as Finding;
    const r = check(dossier([bare]), { semantic: true });
    expect(r.ok).toBe(false);
    expect(r.messages.join(" ")).toMatch(/unadjudicated/);
  });
});
