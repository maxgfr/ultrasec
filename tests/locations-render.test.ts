import { describe, it, expect } from "vitest";
import { renderDossierMd, type Dossier } from "../src/store.js";
import { renderReport } from "../src/render/report.js";
import type { Finding } from "../src/types.js";

// A cross-version-merged dep advisory carries its per-instance evidence in
// `locations[]` (WP2). Both human renderers must surface it — and stay
// byte-identical when the field is absent (snapshot back-compat).

function depFinding(extra: Partial<Finding> = {}): Finding {
  return {
    id: "dep1",
    category: "dep",
    title: "qs vulnerable to Prototype Poisoning",
    severity: "high",
    confidence: "medium",
    message: "qs@6.5.2: prototype poisoning (fixed in 6.5.3)",
    tool: "osv-scanner",
    sources: ["osv-scanner"],
    status: "open",
    cve: "CVE-2022-24999",
    pkg: "qs",
    version: "6.5.2",
    sink: { file: "package-lock.json", line: 1 },
    ...extra,
  };
}

function dossier(f: Finding): Dossier {
  return {
    manifest: {
      version: "0.0.0-test",
      schemaVersion: 5,
      repo: "/tmp/repo",
      generatedNote: "test",
      languages: ["javascript"],
      toolsRun: ["osv-scanner"],
      counts: { findings: 1, bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } },
    },
    findings: [f],
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

const LOCS = [
  { file: "package-lock.json", line: 1, version: "0.6.6" },
  { file: "app/package-lock.json", line: 1, version: "6.5.2" },
];

describe("locations[] rendering", () => {
  it("DOSSIER.md lists every merged instance on an 'affects' line", () => {
    const md = renderDossierMd(dossier(depFinding({ locations: LOCS })));
    expect(md).toContain("affects: v0.6.6 `package-lock.json:1` · v6.5.2 `app/package-lock.json:1`");
  });

  it("DOSSIER.md has no 'affects' line when locations is absent", () => {
    expect(renderDossierMd(dossier(depFinding()))).not.toContain("affects:");
  });

  it("REPORT.md lists every merged instance on an 'Affects' line", () => {
    const md = renderReport(dossier(depFinding({ locations: LOCS })));
    expect(md).toContain("**Affects:** v0.6.6 `package-lock.json:1` · v6.5.2 `app/package-lock.json:1`");
  });

  it("REPORT.md has no 'Affects' line when locations is absent", () => {
    expect(renderReport(dossier(depFinding()))).not.toContain("**Affects:**");
  });
});
