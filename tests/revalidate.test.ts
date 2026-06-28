import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Dossier } from "../src/store.js";
import type { Finding, Severity } from "../src/types.js";
import { buildRevalidateWorklist, applyRevalidations, parseRevalidations, revalFactsFromWorklist } from "../src/revalidate.js";

function finding(id: string, severity: Severity, status: Finding["status"]): Finding {
  return {
    id,
    category: "taint",
    title: `finding ${id}`,
    severity,
    confidence: "high",
    message: "candidate",
    tool: "ultrasec",
    status,
    sink: { file: "src/db.js", line: 6 },
  };
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

describe("buildRevalidateWorklist — scope", () => {
  it("includes only confirmed + needs-human; git facts degrade offline", () => {
    const d = dossier([
      finding("conf", "high", "confirmed"),
      finding("nh", "high", "needs-human"),
      finding("open", "high", "open"),
      finding("dism", "high", "dismissed"),
    ]);
    // a non-git temp dir → every git helper returns false/null gracefully
    const items = buildRevalidateWorklist(d, mkdtempSync(join(tmpdir(), "ultrasec-reval-")));
    expect(items.map((i) => i.id).sort()).toEqual(["conf", "nh"]);
    expect(items.every((i) => i.fileExists === false && i.currentLine === null)).toBe(true);
    expect(items.every((i) => i.at === "src/db.js:6" && i.verdict === null)).toBe(true);
  });
});

describe("applyRevalidations — conservative policy", () => {
  it("still-valid keeps the finding unchanged", () => {
    const r = applyRevalidations(dossier([finding("a", "high", "confirmed")]), [{ id: "a", verdict: "still-valid" }]);
    expect(r.findings[0]!.status).toBe("confirmed");
    expect(r.stillValid).toBe(1);
    expect(r.flagged).toHaveLength(0);
  });

  it("fixed → dismissed and records fixedIn (agent-supplied wins)", () => {
    const r = applyRevalidations(dossier([finding("a", "high", "confirmed")]), [{ id: "a", verdict: "fixed", fixedIn: "deadbeef" }]);
    expect(r.findings[0]!.status).toBe("dismissed");
    expect(r.findings[0]!.fixedIn).toBe("deadbeef");
    expect(r.findings[0]!.message).toContain("fixed in deadbeef");
    expect(r.fixed).toBe(1);
  });

  it("fixed → infers fixedIn from lineLastChanged when the agent omits it", () => {
    const r = applyRevalidations(dossier([finding("a", "high", "confirmed")]), [{ id: "a", verdict: "fixed" }], { fixedInById: new Map([["a", "abc1234"]]) });
    expect(r.findings[0]!.fixedIn).toBe("abc1234");
  });

  it("high-severity false-positive → needs-human (escalated, never auto-dismissed)", () => {
    const r = applyRevalidations(dossier([finding("a", "critical", "confirmed")]), [{ id: "a", verdict: "false-positive" }]);
    expect(r.findings[0]!.status).toBe("needs-human");
    expect(r.needsHuman).toBe(1);
    expect(r.flagged.some((f) => f.id === "a")).toBe(true);
  });

  it("low-severity false-positive → dismissed", () => {
    const r = applyRevalidations(dossier([finding("a", "low", "confirmed")]), [{ id: "a", verdict: "false-positive" }]);
    expect(r.findings[0]!.status).toBe("dismissed");
    expect(r.dismissed).toBe(1);
  });

  it("uncertain → needs-human", () => {
    const r = applyRevalidations(dossier([finding("a", "medium", "confirmed")]), [{ id: "a", verdict: "uncertain" }]);
    expect(r.findings[0]!.status).toBe("needs-human");
  });

  it("ignores verdicts for out-of-scope (open/dismissed) findings", () => {
    const r = applyRevalidations(dossier([finding("a", "high", "open")]), [{ id: "a", verdict: "fixed" }]);
    expect(r.findings[0]!.status).toBe("open"); // untouched
    expect(r.applied).toBe(0);
  });

  it("drift guard: still-valid on a gone location is KEPT but flagged", () => {
    const r = applyRevalidations(dossier([finding("a", "high", "confirmed")]), [{ id: "a", verdict: "still-valid" }], { unresolved: new Set(["a"]) });
    expect(r.findings[0]!.status).toBe("confirmed"); // kept
    expect(r.findings[0]!.message).toMatch(/drifted\/removed/);
    expect(r.flagged.some((f) => f.id === "a")).toBe(true);
  });
});

describe("revalFactsFromWorklist", () => {
  it("derives the unresolved set + inferred fixing commits", () => {
    const facts = revalFactsFromWorklist([
      {
        id: "gone",
        severity: "high",
        title: "t",
        at: "x:1",
        fileExists: false,
        currentLine: null,
        commitsSinceFinding: null,
        lineLastChanged: null,
        renamedTo: null,
        verdict: null,
        note: "",
      },
      {
        id: "live",
        severity: "high",
        title: "t",
        at: "y:2",
        fileExists: true,
        currentLine: "code",
        commitsSinceFinding: 1,
        lineLastChanged: { commit: "abc1234" },
        renamedTo: null,
        verdict: null,
        note: "",
      },
    ]);
    expect([...facts.unresolved!]).toEqual(["gone"]);
    expect(facts.fixedInById!.get("live")).toBe("abc1234");
  });
});

describe("parseRevalidations", () => {
  it("accepts a bare array and a {revalidations:[]} wrapper, dropping malformed/unknown verdicts", () => {
    expect(parseRevalidations('[{"id":"a","verdict":"fixed","fixedIn":"sha1"},{"id":"b","verdict":"bogus"},{"noid":1}]')).toEqual([
      { id: "a", verdict: "fixed", fixedIn: "sha1", note: undefined },
    ]);
    expect(parseRevalidations('{"revalidations":[{"id":"c","verdict":"still-valid"}]}')[0]!.id).toBe("c");
  });
});
