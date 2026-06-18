import { describe, it, expect } from "vitest";
import type { Dossier } from "../src/store.js";
import type { Finding, Severity } from "../src/types.js";
import { buildTriageWorklist, applyTriage, parseTriage } from "../src/triage.js";

function f(id: string, severity: Severity, status: Finding["status"] = "open"): Finding {
  return { id, category: "sast", title: `finding ${id}`, severity, confidence: "low", message: "candidate", tool: "semgrep", status, sink: { file: "src/x.js", line: 3 } };
}

function dossier(findings: Finding[]): Dossier {
  return {
    manifest: {
      version: "0.0.0",
      schemaVersion: 4,
      repo: "/repo",
      generatedNote: "",
      languages: [],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    },
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

describe("buildTriageWorklist", () => {
  it("includes only OPEN candidates and carries no code field", () => {
    const items = buildTriageWorklist(dossier([f("a", "high"), f("b", "low", "confirmed"), f("c", "medium")]));
    expect(items.map((i) => i.id).sort()).toEqual(["a", "c"]);
    for (const it of items) {
      expect(it.at).toBe("src/x.js:3");
      expect(it).not.toHaveProperty("excerpt");
      expect(it).not.toHaveProperty("code");
      expect(it.verdict).toBeNull();
    }
  });
});

describe("applyTriage — conservative quick-dismiss", () => {
  it("noise dismisses a low/medium/info finding", () => {
    const r = applyTriage(dossier([f("a", "low"), f("b", "info"), f("c", "medium")]), [
      { id: "a", verdict: "noise" },
      { id: "b", verdict: "noise" },
      { id: "c", verdict: "noise" },
    ]);
    expect(r.findings.every((x) => x.status === "dismissed")).toBe(true);
    expect(r.dismissed).toBe(3);
    expect(r.kept).toHaveLength(0);
  });

  it("noise is IGNORED on high/critical — finding stays open, recorded in kept", () => {
    const r = applyTriage(dossier([f("a", "high"), f("b", "critical")]), [
      { id: "a", verdict: "noise" },
      { id: "b", verdict: "noise" },
    ]);
    expect(r.findings.every((x) => x.status === "open")).toBe(true);
    expect(r.dismissed).toBe(0);
    expect(r.kept.map((k) => k.id).sort()).toEqual(["a", "b"]);
  });

  it("keep leaves a finding open (unchanged) for full verify", () => {
    const r = applyTriage(dossier([f("a", "medium")]), [{ id: "a", verdict: "keep" }]);
    expect(r.findings[0]!.status).toBe("open");
    expect(r.dismissed).toBe(0);
  });

  it("only acts on open findings (ignores already-adjudicated ones)", () => {
    const r = applyTriage(dossier([f("a", "low", "confirmed")]), [{ id: "a", verdict: "noise" }]);
    expect(r.findings[0]!.status).toBe("confirmed");
    expect(r.applied).toBe(0);
  });

  it("is idempotent on re-apply", () => {
    const d = dossier([f("a", "low"), f("hi", "high")]);
    const once = applyTriage(d, [{ id: "a", verdict: "noise" }, { id: "hi", verdict: "noise" }]);
    const twice = applyTriage({ ...d, findings: once.findings }, [{ id: "a", verdict: "noise" }, { id: "hi", verdict: "noise" }]);
    expect(twice.findings).toEqual(once.findings); // stable: low dismissed once, high stays open
    expect(twice.dismissed).toBe(0); // 'a' already dismissed, not re-counted
  });
});

describe("parseTriage", () => {
  it("accepts a bare array and a {triage:[]} wrapper, dropping unknown verdicts", () => {
    expect(parseTriage('[{"id":"a","verdict":"noise"},{"id":"b","verdict":"bogus"},{"verdict":"keep"}]')).toEqual([{ id: "a", verdict: "noise" }]);
    expect(parseTriage('{"triage":[{"id":"c","verdict":"keep"}]}')[0]!.id).toBe("c");
  });
});
