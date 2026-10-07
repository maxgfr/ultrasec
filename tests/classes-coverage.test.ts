import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classCoverage, huntId, needsHunt, renderClassCoverageMd, withHuntProgress, PACK_SUGGESTIONS_FILE } from "../src/classes/coverage.js";
import type { DetectedFramework } from "../src/frameworks.js";

// The class × framework matrix is a coverage CLAIM, so its failure modes are
// the ones that matter: a pack trusted outside the range it was validated on,
// a framework with no pack reported as covered, a non-applicable class
// reported as a gap.

const fw = (id: string, ecosystem: DetectedFramework["ecosystem"], version: string, dir = ""): DetectedFramework => ({
  id,
  title: id,
  ecosystem,
  dir,
  version,
  versionSource: "lockfile",
  evidence: `${dir ? `${dir}/` : ""}package.json:1`,
});
const cell = (cells: ReturnType<typeof classCoverage>, c: string, f: string) => cells.find((x) => x.class === c && x.framework === f)!;

describe("classCoverage", () => {
  it("covers every class deterministically for a framework inside its pack's testedWith", () => {
    const cells = classCoverage([fw("nextjs", "node", "16.3.3", "packages/app")]);
    expect(cells).toHaveLength(7);
    for (const c of cells) {
      expect(c.state, c.class).toBe("deterministic");
      expect(c.degraded, c.class).toBeUndefined();
      expect(needsHunt(c)).toBe(false);
    }
    expect(cell(cells, "security-headers-absent", "nextjs").packs).toEqual(["nextjs"]);
    // The first-hop idiom reads the same in every language: the common pack carries it.
    expect(cell(cells, "client-ip-first-xff", "nextjs").packs).toEqual(["common"]);
  });

  it("degrades — and hunts — the framework-pack cells of a version outside testedWith", () => {
    const cells = classCoverage([fw("nextjs", "node", "17.0.0")]);
    expect(cell(cells, "security-headers-absent", "nextjs").degraded).toBe("nextjs 17.0.0 is outside nextjs testedWith >=12 <17");
    expect(needsHunt(cell(cells, "unbounded-public-export", "nextjs"))).toBe(true);
    // A language idiom does not depend on the framework's version.
    expect(cell(cells, "timing-unsafe-secret-compare", "nextjs").degraded).toBeUndefined();
  });

  it("marks a framework with no pack as degraded where language idioms ran, and not covered elsewhere", () => {
    const cells = classCoverage([fw("sinatra", "ruby", "4.0.0")]);
    expect(cell(cells, "timing-unsafe-secret-compare", "sinatra")).toMatchObject({
      state: "deterministic",
      packs: ["ruby"],
      degraded: "no sinatra pack — only the ruby language idioms ran",
    });
    expect(cell(cells, "security-headers-absent", "sinatra")).toMatchObject({ state: "not-covered", degraded: "no sinatra pack" });
    expect(cell(cells, "session-cookie-chunks-on-logout", "sinatra")).toMatchObject({ state: "not-applicable" });
  });

  it("says why a class does not apply, and never hunts it", () => {
    const c = cell(classCoverage([fw("django", "python", "5.0")]), "session-cookie-chunks-on-logout", "django");
    expect(c.state).toBe("not-applicable");
    expect(c.reason).toMatch(/server-side/);
    expect(needsHunt(c)).toBe(false);
  });

  it("names a hunt per cell and package", () => {
    expect(huntId({ class: "csv-formula-injection", framework: "koa", dir: "apps/api" })).toBe("hunt:csv-formula-injection:koa@apps/api");
    expect(huntId({ class: "csv-formula-injection", framework: "koa", dir: "" })).toBe("hunt:csv-formula-injection:koa");
  });
});

describe("withHuntProgress", () => {
  it("moves a hunted cell to ai-hunt once emitted and to ai-hunted once applied", () => {
    const cells = classCoverage([fw("koa", "node", "2.15.0")]);
    const exportCell = cell(cells, "unbounded-public-export", "koa");
    const headersCell = cell(cells, "security-headers-absent", "koa");
    expect(exportCell.state).toBe("not-covered");
    const run = mkdtempSync(join(tmpdir(), "ultrasec-classes-"));
    writeFileSync(join(run, "INVESTIGATE.todo.json"), JSON.stringify([{ region: huntId(exportCell), hunt: { id: huntId(exportCell) } }]));
    expect(cell(withHuntProgress(cells, run), "unbounded-public-export", "koa").state).toBe("ai-hunt");
    writeFileSync(join(run, PACK_SUGGESTIONS_FILE), JSON.stringify({ hunted: [huntId(exportCell)], suggestions: [] }));
    expect(cell(withHuntProgress(cells, run), "unbounded-public-export", "koa").state).toBe("ai-hunted");
    // A cell the pack settles is never overlaid.
    expect(cell(withHuntProgress(cells, run), "security-headers-absent", "koa").state).toBe(headersCell.state);
  });

  it("renders the matrix with its degraded cells called out", () => {
    const md = renderClassCoverageMd(classCoverage([fw("nextjs", "node", "17.0.0", "web"), fw("django", "python", "5.0.1", "api")]));
    expect(md).toContain("### Weakness classes × frameworks");
    expect(md).toContain("| class | nextjs 17.0.0 (`web`) | django 5.0.1 (`api`) |");
    expect(md).toMatch(/\| security-headers-absent \| ✅ pack ⚠ \| ✅ pack \|/);
    expect(md).toContain("outside nextjs testedWith");
  });
});
