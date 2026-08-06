import { describe, it, expect } from "vitest";
import { applyVerdicts, parseVerdicts } from "../src/verify.js";
import { check } from "../src/check.js";
import type { Dossier } from "../src/store.js";
import { BROCARDS, BROCARD_SUMMARY, type Finding, type Severity } from "../src/types.js";
import { join } from "node:path";

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

describe("brocards — a dismissal names its ground", () => {
  it("records the ground on a refutation", () => {
    const res = applyVerdicts(dossier([finding("a", "high")]), [{ id: "a", verdict: "refuted", brocard: "outside-usage" }]);
    expect(res.findings[0]!.status).toBe("dismissed");
    expect(res.findings[0]!.brocard).toBe("outside-usage");
  });

  it("ignores a ground on any verdict that is not a refutation", () => {
    // A ground explains why something ISN'T a bug. Attaching one to `supported`
    // would put a refutation's vocabulary on a confirmation.
    const res = applyVerdicts(dossier([finding("a", "high")]), [{ id: "a", verdict: "supported", brocard: "outside-usage" }]);
    expect(res.findings[0]!.status).toBe("confirmed");
    expect(res.findings[0]!.brocard).toBeUndefined();
  });

  it("drops an unrecognized ground instead of failing the whole fold", () => {
    // A typo must cost the annotation, not the batch: the verdicts around it are
    // real work and the missing-ground report will surface the omission anyway.
    const parsed = parseVerdicts(JSON.stringify([{ id: "a", verdict: "refuted", brocard: "made-up-ground" }]));
    expect(parsed.rows).toHaveLength(1);
    expect(parsed.rows[0]!.brocard).toBeUndefined();
  });

  it("accepts every documented ground", () => {
    for (const b of BROCARDS) {
      const parsed = parseVerdicts(JSON.stringify([{ id: "a", verdict: "refuted", brocard: b }]));
      expect(parsed.rows[0]!.brocard, `${b} must round-trip`).toBe(b);
    }
  });

  it("has a one-line gloss for every ground (the report renders it)", () => {
    for (const b of BROCARDS) expect(BROCARD_SUMMARY[b]?.length ?? 0).toBeGreaterThan(10);
  });
});

describe("check --semantic reports unargued dismissals", () => {
  it("lists a high dismissal that names no ground", () => {
    const d = dossier([{ ...finding("a", "high"), status: "dismissed", verdict: "refuted" }]);
    const res = check(d, { repo: REPO, semantic: true });
    expect(res.unarguedDismissals).toEqual(["a"]);
    expect(res.messages.join(" ")).toMatch(/name no ground/);
  });

  it("stays silent once the ground is named", () => {
    const d = dossier([{ ...finding("a", "high"), status: "dismissed", verdict: "refuted", brocard: "standard-behavior" }]);
    expect(check(d, { repo: REPO, semantic: true }).unarguedDismissals).toEqual([]);
  });

  it("does not fail the gate — it reports", () => {
    // A hard gate here would teach adjudicators to pick a ground to get green,
    // which is the opposite of the point.
    const d = dossier([{ ...finding("a", "high"), status: "dismissed", verdict: "refuted" }]);
    expect(check(d, { repo: REPO, semantic: true }).ok).toBe(true);
  });

  it("only asks for a ground on high/critical", () => {
    const d = dossier([{ ...finding("a", "medium"), status: "dismissed", verdict: "refuted" }]);
    expect(check(d, { repo: REPO, semantic: true }).unarguedDismissals).toEqual([]);
  });
});
