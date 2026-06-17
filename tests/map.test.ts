import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildAttackSurface, renderMapMd } from "../src/map.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

describe("buildAttackSurface", () => {
  const scan = scanRepo(FIXTURE);
  const surface = buildAttackSurface(scan);

  it("finds the HTTP entry point in server.js", () => {
    const http = surface.entryPoints.find((g) => g.kind === "http");
    expect(http, "expected an http entry group").toBeTruthy();
    expect(http!.samples.some((e) => e.file === "src/server.js")).toBe(true);
  });

  it("groups the SQL and command sinks by class", () => {
    const kinds = surface.sinks.map((s) => s.kind);
    expect(kinds).toContain("sql");
    expect(kinds).toContain("command");
    const cmd = surface.sinks.find((s) => s.kind === "command")!;
    expect(cmd.cwe).toBe("CWE-78");
    expect(cmd.severity).toBe("critical");
  });

  it("totals and per-language counts are populated", () => {
    expect(surface.totals.sinks).toBeGreaterThanOrEqual(2);
    expect(surface.totals.sources).toBeGreaterThanOrEqual(1);
    expect(surface.byLanguage.some((l) => l.lang === "javascript")).toBe(true);
  });

  it("suggests targets ranked by attack-surface density and marks covered ones", () => {
    expect(surface.suggestedTargets.length).toBeGreaterThanOrEqual(1);
    expect(surface.suggestedTargets[0]!.scope).toBe("src");
    const withCovered = buildAttackSurface(scan, ["src"]);
    expect(withCovered.suggestedTargets.find((t) => t.scope === "src")!.covered).toBe(true);
  });

  it("is deterministic across runs", () => {
    expect(buildAttackSurface(scan)).toEqual(buildAttackSurface(scan));
  });

  it("renders a Markdown map mentioning the next target", () => {
    const md = renderMapMd(scan.repo, surface);
    expect(md).toContain("attack-surface map");
    expect(md).toContain("Next:");
  });
});
