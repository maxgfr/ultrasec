import { describe, it, expect } from "vitest";
import { buildCoverage, renderCoverageMd, ASVS } from "../src/coverage.js";
import type { Dossier } from "../src/store.js";
import type { Finding } from "../src/types.js";

const dossier = (findings: Finding[]): Dossier => ({
  manifest: {
    version: "0",
    schemaVersion: 7,
    repo: "/tmp/x",
    generatedNote: "",
    languages: ["javascript"],
    toolsRun: [],
    counts: { findings: findings.length, bySeverity: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 } },
  },
  findings,
  graph: { files: [], edges: [], symbolDefs: {} },
});

const f = (over: Partial<Finding>): Finding => ({
  id: "x",
  category: "taint",
  title: "t",
  severity: "high",
  confidence: "low",
  message: "m",
  tool: "ultrasec",
  status: "open",
  ...over,
});

describe("coverage matrix", () => {
  it("accounts for EVERY category in exactly one state", () => {
    // The whole point: nothing may be quietly skipped. A category with no bucket
    // is a category the report never mentions.
    const rows = buildCoverage(dossier([]));
    expect(rows).toHaveLength(ASVS.length);
    expect(rows.every((r) => ["engine", "examined", "unexamined"].includes(r.state))).toBe(true);
  });

  it("reports an empty audit as NOT EXAMINED, never as clean", () => {
    const rows = buildCoverage(dossier([]));
    expect(rows.every((r) => r.state === "unexamined")).toBe(true);
    expect(renderCoverageMd(rows)).toMatch(/is not\s+a clean bill of health/);
  });

  it("marks a category examined once a finding lands in it", () => {
    const rows = buildCoverage(dossier([f({ sink: { file: "a.js", line: 1, kind: "sql" } })]), ["sql"]);
    expect(rows.find((r) => r.id === "V5")!.state).toBe("examined");
  });

  it("counts a class the engine walked but this repo never exercised as enumerated, not as a gap", () => {
    // The pass ran; it simply found nothing. That is different from never looking.
    const rows = buildCoverage(dossier([f({ sink: { file: "a.js", line: 1, kind: "sql" } })]), ["sql", "ssrf"]);
    expect(rows.find((r) => r.id === "V13")!.state).toBe("engine");
  });

  it("names the judgment categories so 'not applicable' has to be argued", () => {
    const md = renderCoverageMd(buildCoverage(dossier([])));
    expect(md).toMatch(/Answer these explicitly/);
    expect(md).toMatch(/without a\s+reason is how coverage silently shrinks/);
    expect(md).toMatch(/Access control/);
    expect(md).toMatch(/Business logic/);
  });

  it("does not claim coverage of classes a source audit cannot speak to", () => {
    // Listing all 14 ASVS chapters would be exactly the coverage theatre this
    // file exists to avoid.
    expect(ASVS.map((c) => c.id)).not.toContain("V10");
  });
});
