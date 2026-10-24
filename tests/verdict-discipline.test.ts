import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { applyVerdicts, parseVerdicts } from "../src/verify.js";
import { check } from "../src/check.js";
import { preserveAdjudication, type Dossier } from "../src/store.js";
import type { Finding, Severity } from "../src/types.js";

// A verdict a reviewer can disagree with has three parts besides the label: a
// confirmation says who does what to whom (`exploitPath`), a needs-human says
// which fact is still missing (`note`), and the severity never exceeds the
// impact demonstrated. All three are reported, never gate-failing.

const REPO = join(import.meta.dirname, "fixtures", "vuln-express");

function finding(id: string, severity: Severity): Finding {
  return {
    id,
    category: "taint",
    cwe: "CWE-89",
    title: "SQLi",
    severity,
    confidence: "low",
    message: "m",
    tool: "ultrasec",
    status: "open",
    sink: { file: "src/db.js", line: 6 },
  };
}

function dossier(findings: Finding[]): Dossier {
  return {
    manifest: {
      version: "0",
      schemaVersion: 7,
      repo: REPO,
      generatedNote: "",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 } },
    },
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

describe("a confirmation carries its attacker scenario", () => {
  it("lists supported rows without an exploitPath", () => {
    const res = applyVerdicts(dossier([finding("a", "high"), finding("b", "high")]), [
      { id: "a", verdict: "supported" },
      { id: "b", verdict: "supported", exploitPath: "anon · ?id=1 OR 1=1 · every row" },
    ]);
    expect(res.noScenario).toEqual(["a"]);
  });

  it("check --semantic reports a confirmed finding with no scenario, without failing", () => {
    const d = dossier([{ ...finding("a", "high"), status: "confirmed", verdict: "supported" }]);
    const res = check(d, { repo: REPO, semantic: true });
    expect(res.unscenarioedConfirmations).toEqual(["a"]);
    expect(res.messages.join(" ")).toMatch(/no attacker scenario/);
    expect(res.ok).toBe(true);
  });
});

describe("a needs-human names the missing fact", () => {
  it("check --semantic reports a needs-human whose verdict carries no note", () => {
    const res = applyVerdicts(dossier([finding("a", "high"), finding("b", "high")]), [
      { id: "a", verdict: "partial" },
      { id: "b", verdict: "partial", note: "depends on whether the proxy strips X-Forwarded-For" },
    ]);
    const out = check({ ...dossier(res.findings) }, { repo: REPO, semantic: true });
    expect(out.unexplainedNeedsHuman).toEqual(["a"]);
    expect(out.messages.join(" ")).toMatch(/name no missing fact/);
    expect(out.ok).toBe(true);
  });
});

describe("severity never exceeds the demonstrated impact", () => {
  it("lowers the severity on a confirmation", () => {
    const res = applyVerdicts(dossier([finding("a", "high")]), [{ id: "a", verdict: "supported", exploitPath: "x", severity: "medium" }]);
    expect(res.findings[0]!.severity).toBe("medium");
    expect(res.findings[0]!.demonstratedSeverity).toBe("medium");
    expect(res.lowered).toEqual([{ id: "a", from: "high", to: "medium" }]);
  });

  it("never raises it", () => {
    const res = applyVerdicts(dossier([finding("a", "medium")]), [{ id: "a", verdict: "supported", exploitPath: "x", severity: "critical" }]);
    expect(res.findings[0]!.severity).toBe("medium");
    expect(res.lowered).toEqual([]);
  });

  it("ignores it on anything but a confirmation — an uncertain high stays in front of a human", () => {
    const res = applyVerdicts(dossier([finding("a", "high")]), [{ id: "a", verdict: "unsupported", severity: "low" }]);
    expect(res.findings[0]!.status).toBe("needs-human");
    expect(res.findings[0]!.severity).toBe("high");
  });

  it("drops an unknown severity instead of failing the fold", () => {
    const parsed = parseVerdicts(JSON.stringify([{ id: "a", verdict: "supported", severity: "severe" }]));
    expect(parsed.rows).toHaveLength(1);
    expect(parsed.rows[0]!.severity).toBeUndefined();
  });

  it("survives scan --merge as a ceiling", () => {
    const old: Finding = { ...finding("a", "medium"), status: "confirmed", verdict: "supported", demonstratedSeverity: "medium" };
    expect(preserveAdjudication(finding("a", "high"), old).severity).toBe("medium");
    // The engine rating it lower still wins.
    expect(preserveAdjudication(finding("a", "low"), old).severity).toBe("low");
  });
});
