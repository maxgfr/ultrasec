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

  // An advisory merged across versions cites ONE lockfile line and affects
  // several. REPORT.md must show every instance whichever tier the finding lands
  // in. What carries them changed — a confirmed advisory is now rolled into the
  // per-package table with the rest of the dependency half, instead of getting a
  // prose write-up between two code findings — but the contract did not: the
  // per-version evidence is still printed in full, and losing it while compacting
  // would make the report wrong.
  it("REPORT.md lists every merged instance for a CONFIRMED advisory", () => {
    const md = renderReport(dossier(depFinding({ locations: LOCS, status: "confirmed" })));
    expect(md).toContain("v0.6.6 `package-lock.json:1` · v6.5.2 `app/package-lock.json:1`");
  });

  it("keeps a confirmed advisory out of the code write-ups, in its own section", () => {
    const md = renderReport(dossier(depFinding({ locations: LOCS, status: "confirmed" })));
    // The defect this prevents: composite risk weights EPSS, so a lockfile CVE
    // opened the Confirmed section ahead of every source-code finding.
    expect(md).toContain("### Dependency advisories — 1 confirmed");
  });

  it("REPORT.md keeps every merged instance in the compact tier too", () => {
    const md = renderReport(dossier(depFinding({ locations: LOCS })));
    expect(md).toContain("v0.6.6 `package-lock.json:1` · v6.5.2 `app/package-lock.json:1`");
  });

  it("REPORT.md has no 'Affects' line when locations is absent", () => {
    expect(renderReport(dossier(depFinding({ status: "confirmed" })))).not.toContain("**Affects:**");
  });
});
