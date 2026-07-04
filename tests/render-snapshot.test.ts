import { describe, it, expect } from "vitest";
import type { Dossier } from "../src/store.js";
import type { Finding } from "../src/types.js";
import { renderSummary, renderReport } from "../src/render/report.js";
import { renderHtml } from "../src/render/html.js";

// Back-compat guard for the Phase 3 narrative-aware render: with NO narrative arg
// the output must stay byte-identical. The snapshot is captured against the
// pre-narrative render and must keep matching after the change.

const findings: Finding[] = [
  {
    id: "conf1",
    category: "taint",
    cwe: "CWE-89",
    title: "SQL injection in user lookup",
    severity: "high",
    confidence: "high",
    message: "Tainted req.query.id reaches a raw SQL query.",
    tool: "ultrasec",
    status: "confirmed",
    verdict: "supported",
    exploitPath: "GET /user?id=1 OR 1=1",
    risk: 72,
    references: ["https://cwe.mitre.org/data/definitions/89.html"],
    provenance: { author: "Alice", date: "2026-01-02", commit: "abc1234", owner: "@team-api" },
    source: { file: "src/server.js", line: 10 },
    sink: { file: "src/db.js", line: 6 },
    path: [
      { file: "src/server.js", line: 10, why: "source: req.query.id" },
      { file: "src/db.js", line: 6, why: "sink: string-concat SQL" },
    ],
  },
  {
    id: "nh1",
    category: "authz",
    title: "Possible missing authorization on /admin",
    severity: "critical",
    confidence: "medium",
    message: "Admin route may lack an auth guard.",
    tool: "deepsec",
    sources: ["deepsec"],
    status: "needs-human",
    sink: { file: "src/admin.js", line: 3 },
  },
  {
    id: "open1",
    category: "sast",
    cwe: "CWE-79",
    title: "Reflected XSS candidate",
    severity: "medium",
    confidence: "low",
    message: "Unescaped value written to response.",
    tool: "semgrep",
    sources: ["opengrep", "semgrep"],
    status: "open",
    sink: { file: "src/view.js", line: 20 },
  },
  {
    id: "dism1",
    category: "taint",
    title: "Dismissed false lead",
    severity: "low",
    confidence: "low",
    message: "Looked tainted, proven safe.",
    tool: "ultrasec",
    status: "dismissed",
    verdict: "refuted",
    sink: { file: "src/safe.js", line: 1 },
  },
];

const dossier: Dossier = {
  manifest: {
    version: "9.9.9",
    schemaVersion: 4,
    repo: "/repo",
    generatedNote: "deterministic note.",
    languages: ["javascript"],
    toolsRun: ["semgrep", "deepsec"],
    counts: { findings: findings.length, bySeverity: { critical: 1, high: 1, medium: 1, low: 1, info: 0 } },
  },
  findings,
  graph: { files: [], edges: [], symbolDefs: {} },
};

describe("render — byte-identical with NO narrative (Phase 3 guard)", () => {
  it("renderSummary", () => expect(renderSummary(dossier)).toMatchSnapshot());
  it("renderReport", () => expect(renderReport(dossier)).toMatchSnapshot());
  it("renderHtml", () => expect(renderHtml(dossier)).toMatchSnapshot());

  it("explicit undefined narrative == omitted arg", () => {
    expect(renderSummary(dossier, undefined)).toBe(renderSummary(dossier));
    expect(renderReport(dossier, undefined)).toBe(renderReport(dossier));
    expect(renderHtml(dossier, undefined)).toBe(renderHtml(dossier));
  });
});
