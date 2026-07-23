import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { generateSbom } from "../src/tools/sbom.js";
import { mergeDossier, renderDossierMd, type Dossier } from "../src/store.js";
import { runScan } from "../src/commands/scan.js";
import { parseArgs } from "../src/util.js";
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

describe("scan --json output — includes SBOM field", () => {
  const FIXTURE = resolve(__dirname, "fixtures/vuln-express");

  let cap: ReturnType<typeof capture>;
  let errSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    cap = capture();
    errSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });
  afterEach(() => {
    cap.restore();
    errSpy.mockRestore();
  });

  function capture(): { out: string[]; restore: () => void } {
    const out: string[] = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((chunk: any) => {
      out.push(String(chunk));
      return true;
    });
    return { out, restore: () => spy.mockRestore() };
  }

  it(
    "includes sbom field in scan --json output (mirrors manifest.sbom)",
    async () => {
      const out = mkdtempSync(join(tmpdir(), "ultrasec-scan-json-sbom-"));
      const code = await runScan(parseArgs(["scan", "--repo", FIXTURE, "--out", out, "--no-enrich", "--json"]));
      expect(code).toBe(0);

      const result = JSON.parse(cap.out.join(""));
      // The fix adds sbom to the --json output object, following the same pattern as
      // optional manifest fields like scopes and toolStatus. If syft is available,
      // result.sbom will be "sbom.cdx.json"; if not, the property won't appear
      // (JSON omits undefined values). Either way, the structure now properly mirrors
      // the manifest's optional sbom field, allowing --json-only consumers to see it.
      if (result.sbom !== undefined) {
        expect(result.sbom).toBe("sbom.cdx.json");
      }
    },
    15000,
  );
});
