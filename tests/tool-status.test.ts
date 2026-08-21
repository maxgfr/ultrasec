import { describe, it, expect } from "vitest";
import { renderDossierMd, mergeDossier, type Dossier } from "../src/store.js";
import { renderReport } from "../src/render/report.js";
import type { Manifest } from "../src/types.js";

// Eval P2.7: per-tool ran/empty/skipped/failed status is persisted in the
// manifest and rendered, so a report distinguishes "osv ran, found nothing" from
// "osv skipped (no lockfile)". Rendering is presence-gated: absent → byte-identical.

function manifest(extra: Partial<Manifest> = {}): Manifest {
  return {
    version: "0",
    schemaVersion: 5,
    repo: "/tmp/repo",
    generatedNote: "note",
    languages: ["javascript"],
    toolsRun: ["trivy"],
    counts: { findings: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    ...extra,
  };
}
function dossier(m: Manifest): Dossier {
  return { manifest: m, findings: [], graph: { files: [], edges: [], symbolDefs: {} } };
}

const STATUS = [
  { name: "trivy", status: "ran" as const, findings: 3 },
  { name: "osv-scanner", status: "skipped" as const, note: "no target files" },
  { name: "gitleaks", status: "empty" as const, findings: 0 },
];

describe("tool status rendering", () => {
  it("DOSSIER.md lists each tool's outcome when toolStatus is present", () => {
    const md = renderDossierMd(dossier(manifest({ toolStatus: STATUS })));
    expect(md).toContain("trivy: ran (3)");
    expect(md).toContain("osv-scanner: skipped — no target files");
    expect(md).toContain("gitleaks: empty");
  });

  it("DOSSIER.md is unchanged when toolStatus is absent", () => {
    expect(renderDossierMd(dossier(manifest()))).not.toContain("skipped");
  });

  // REPORT.md SUMMARIZES where DOSSIER.md enumerates. Printing all 21 adapters
  // verbatim put a wall of "skipped — not installed" at the top of the report
  // with the FAILED scanners buried inside it — and a failed scanner is a hole
  // in the coverage table, which is the one outcome a reader must not miss.
  it("REPORT.md summarizes tool outcomes when present and says nothing otherwise", () => {
    const md = renderReport(dossier(manifest({ toolStatus: STATUS })));
    expect(md).toContain("2 ran");
    expect(md).toContain("1 skipped");
    expect(renderReport(dossier(manifest()))).not.toContain("scanners:");
  });

  it("REPORT.md names a FAILED scanner and calls it a coverage hole", () => {
    const md = renderReport(dossier(manifest({ toolStatus: [...STATUS, { name: "checkov", status: "failed" as const, note: "docker ETIMEDOUT" }] })));
    expect(md).toContain("1 FAILED");
    expect(md).toContain("checkov");
    expect(md).toContain("coverage hole");
  });
});

describe("mergeDossier — toolStatus union", () => {
  it("unions by tool name, next wins on conflict, and a scoped pass without status keeps prev's", () => {
    const prev = dossier(
      manifest({
        toolStatus: [
          { name: "trivy", status: "empty", findings: 0 },
          { name: "osv-scanner", status: "skipped" },
        ],
      }),
    );
    const next = dossier(manifest({ scopes: ["src/"], toolStatus: [{ name: "trivy", status: "ran", findings: 5 }] }));
    const merged = mergeDossier(prev, next);
    const byName = Object.fromEntries((merged.manifest.toolStatus ?? []).map((s) => [s.name, s]));
    expect(byName.trivy).toMatchObject({ status: "ran", findings: 5 }); // next wins
    expect(byName["osv-scanner"]).toMatchObject({ status: "skipped" }); // prev preserved
  });

  it("carries prev's status when next has none", () => {
    const prev = dossier(manifest({ toolStatus: [{ name: "trivy", status: "ran", findings: 2 }] }));
    const next = dossier(manifest({ scopes: ["src/"] })); // scoped pass, tools skipped → no status
    expect(mergeDossier(prev, next).manifest.toolStatus).toEqual([{ name: "trivy", status: "ran", findings: 2 }]);
  });
});
