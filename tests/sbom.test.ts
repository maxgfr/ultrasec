import { describe, it, expect } from "vitest";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateSbom } from "../src/tools/sbom.js";
import { mergeDossier, renderDossierMd, type Dossier } from "../src/store.js";
import type { Manifest } from "../src/types.js";

// Eval-style manifest/dossier builders, mirroring tests/tool-status.test.ts.
function manifest(extra: Partial<Manifest> = {}): Manifest {
  return {
    version: "0",
    schemaVersion: 6,
    repo: "/tmp/repo",
    generatedNote: "note",
    languages: ["javascript"],
    toolsRun: [],
    counts: { findings: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    ...extra,
  };
}
function dossier(m: Manifest): Dossier {
  return { manifest: m, findings: [], graph: { files: [], edges: [], symbolDefs: {} } };
}

describe("generateSbom (syft producer)", () => {
  it("gracefully reports absence when syft cannot be resolved on PATH — no file written, never throws", () => {
    const dir = mkdtempSync(join(tmpdir(), "ultrasec-sbom-"));
    const prevPath = process.env.PATH;
    // Empty PATH: neither `syft` nor the `which`/`where` fallback probe can resolve
    // — deterministic "not installed", regardless of what happens to be on the
    // host running this test (never invoke a real syft in tests).
    process.env.PATH = "";
    let result: ReturnType<typeof generateSbom>;
    try {
      expect(() => {
        result = generateSbom("/some/repo", dir);
      }).not.toThrow();
    } finally {
      process.env.PATH = prevPath;
    }
    expect(result!).toEqual({ note: "syft not installed — no SBOM" });
    expect(existsSync(join(dir, "sbom.cdx.json"))).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("mergeDossier — sbom carry", () => {
  it("carries prev's sbom forward when next lacks one (e.g. a scoped pass that skipped tools)", () => {
    const prev = dossier(manifest({ sbom: "sbom.cdx.json" }));
    const next = dossier(manifest({ scopes: ["src/"] }));
    expect(mergeDossier(prev, next).manifest.sbom).toBe("sbom.cdx.json");
  });

  it("next wins when both are set", () => {
    const prev = dossier(manifest({ sbom: "old-sbom.cdx.json" }));
    const next = dossier(manifest({ sbom: "sbom.cdx.json" }));
    expect(mergeDossier(prev, next).manifest.sbom).toBe("sbom.cdx.json");
  });

  it("stays absent when neither has one", () => {
    const prev = dossier(manifest());
    const next = dossier(manifest());
    expect(mergeDossier(prev, next).manifest.sbom).toBeUndefined();
  });
});

describe("DOSSIER.md — SBOM deliverable line", () => {
  it("renders the SBOM line when manifest.sbom is present", () => {
    const md = renderDossierMd(dossier(manifest({ sbom: "sbom.cdx.json" })));
    expect(md).toContain("- SBOM: `sbom.cdx.json` (CycloneDX)");
  });

  it("omits the SBOM line when manifest.sbom is absent", () => {
    expect(renderDossierMd(dossier(manifest()))).not.toContain("SBOM:");
  });
});
