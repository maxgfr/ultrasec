import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classCoverage, huntId, matrixStack, needsHunt, renderClassCoverageMd, withHuntProgress, PACK_SUGGESTIONS_FILE } from "../src/classes/coverage.js";
import { CLASS_IDS, type Pack } from "../src/classes/types.js";
import type { DetectedFramework } from "../src/frameworks.js";

// The class × framework matrix is a coverage CLAIM, so its failure modes are
// the ones that matter: a pack trusted outside the range it was validated on,
// a framework with no pack reported as covered, a non-applicable class
// reported as a gap.

const fw = (id: string, ecosystem: DetectedFramework["ecosystem"], version: string, dir = "", extra: Partial<DetectedFramework> = {}): DetectedFramework => ({
  id,
  title: id,
  ecosystem,
  dir,
  version,
  versionSource: "lockfile",
  evidence: `${dir ? `${dir}/` : ""}package.json:1`,
  ...extra,
});
const lib = (id: string, version: string, dir = "") => fw(id, "node", version, dir, { kind: "library" });
const cell = (cells: ReturnType<typeof classCoverage>, c: string, f: string) => cells.find((x) => x.class === c && x.framework === f)!;

describe("classCoverage", () => {
  it("covers every class deterministically for a framework inside its pack's testedWith", () => {
    const cells = classCoverage([fw("nextjs", "node", "16.3.3", "packages/app"), lib("next-auth", "4.24.13", "packages/app")]);
    expect(cells).toHaveLength(CLASS_IDS.length);
    // What the Next.js pack declares hunted is hunted; everything else is a pack's claim.
    const declaredHunt = ["proxy-headers-trusted", "request-body-unbounded", "debug-mode-enabled"];
    for (const c of cells) {
      if (declaredHunt.includes(c.class)) {
        expect(needsHunt(c), c.class).toBe(true);
        continue;
      }
      expect(c.state, c.class).toBe("deterministic");
      expect(c.degraded, c.class).toBeUndefined();
      expect(needsHunt(c)).toBe(false);
    }
    // A language idiom does not outrank the framework's own "hunt this".
    expect(cell(cells, "debug-mode-enabled", "nextjs")).toMatchObject({ state: "deterministic", packs: ["node"] });
    expect(cell(cells, "debug-mode-enabled", "nextjs").degraded).toMatch(/next dev/);
    expect(cell(cells, "security-headers-absent", "nextjs").packs).toEqual(["nextjs"]);
    // The first-hop idiom reads the same in every language: the common pack carries it.
    expect(cell(cells, "client-ip-first-xff", "nextjs").packs).toEqual(["common"]);
  });

  it("degrades — and hunts — the WHOLE column of a version outside testedWith", () => {
    const cells = classCoverage([fw("nextjs", "node", "17.0.0"), lib("next-auth", "4.24.13")]);
    expect(cell(cells, "security-headers-absent", "nextjs").degraded).toBe("nextjs 17.0.0 is outside nextjs testedWith >=12 <17");
    expect(needsHunt(cell(cells, "unbounded-public-export", "nextjs"))).toBe(true);
    // A language idiom is no better tested on a release nobody ran it against:
    // the framework may now hand the code its input another way.
    for (const c of cells) {
      expect(c.degraded, c.class).toContain("outside nextjs testedWith");
      expect(needsHunt(c), c.class).toBe(true);
    }
  });

  it("hunts every class of a framework that has no pack in an ecosystem that has none", () => {
    const cells = classCoverage([fw("phoenix", "elixir", "1.7.14")]);
    expect(cells).toHaveLength(CLASS_IDS.length);
    for (const c of cells) {
      expect(c, c.class).toMatchObject({ state: "not-covered", degraded: "no phoenix pack" });
      expect(needsHunt(c)).toBe(true);
    }
  });

  it("counts a language pack only where it reads the framework's language", () => {
    // Ktor is JVM, written in Kotlin: the java pack's JVM idioms read it.
    const ktor = classCoverage([fw("ktor", "java", "2.3.12", "", { languages: ["kotlin"] })]);
    expect(cell(ktor, "timing-unsafe-secret-compare", "ktor")).toMatchObject({
      state: "deterministic",
      degraded: "no ktor pack — only the java language idioms ran",
    });
    // Fresh runs JavaScript on Deno: the Node pack's JavaScript idioms read it.
    const fresh = classCoverage([fw("fresh", "deno", "1.6.8")]);
    expect(cell(fresh, "csv-formula-injection", "fresh")).toMatchObject({ state: "deterministic", packs: ["node"] });
    // ASP.NET Core is C#: only the language-agnostic first-hop idiom reads it.
    const dotnet = classCoverage([fw("aspnetcore", "dotnet", "8.0")]);
    expect(cell(dotnet, "client-ip-first-xff", "aspnetcore")).toMatchObject({ state: "deterministic", packs: ["common"] });
    expect(cell(dotnet, "csv-formula-injection", "aspnetcore").state).toBe("not-covered");
  });

  it("checks a library pack against the LIBRARY's version, in the package that declares it", () => {
    const inRange = classCoverage([fw("nextjs", "node", "16.3.3", "web"), lib("next-auth", "4.24.13", "web")]);
    expect(cell(inRange, "session-cookie-chunks-on-logout", "nextjs")).toMatchObject({ state: "deterministic", packs: ["next-auth"] });
    expect(cell(inRange, "session-cookie-chunks-on-logout", "nextjs").degraded).toBeUndefined();

    const outOfRange = classCoverage([fw("nextjs", "node", "16.3.3", "web"), lib("next-auth", "6.0.0", "web")]);
    const c = cell(outOfRange, "session-cookie-chunks-on-logout", "nextjs");
    expect(c).toMatchObject({ state: "deterministic", degraded: "next-auth 6.0.0 is outside next-auth testedWith >=4 <6" });
    expect(needsHunt(c)).toBe(true);
    // Only the cells the library decided are its claim.
    expect(cell(outOfRange, "security-headers-absent", "nextjs").degraded).toBeUndefined();

    // Declared in another app of the monorepo: not this column's library.
    const elsewhere = classCoverage([fw("nextjs", "node", "16.3.3", "apps/web"), lib("next-auth", "4.24.13", "apps/admin")]);
    expect(cell(elsewhere, "session-cookie-chunks-on-logout", "nextjs").state).toBe("not-covered");
  });

  it("reads a pack's hunt declaration as the reason a cell is hunted", () => {
    const pack: Pack = {
      id: "acme",
      ecosystem: "node",
      framework: "acme",
      testedWith: ">=1 <2",
      classes: { "csv-formula-injection": { hunt: "acme streams CSV through its own writer" } },
    };
    const c = cell(classCoverage([fw("acme", "node", "1.2.0")], [pack]), "csv-formula-injection", "acme");
    expect(c).toMatchObject({ state: "not-covered", degraded: "acme streams CSV through its own writer" });
  });

  it("hunts every class of an inferred framework", () => {
    const unknown = fw("unknown", "node", "", "services/edge", { kind: "inferred", title: "unknown web framework", evidence: "services/edge/server.js:3" });
    delete unknown.version;
    const cells = classCoverage([unknown]);
    expect(cells).toHaveLength(CLASS_IDS.length);
    for (const c of cells) expect(needsHunt(c) || c.state === "not-applicable", c.class).toBe(true);
    expect(cell(cells, "security-headers-absent", "unknown").degraded).toBe("unknown web framework — no pack can know it");
    expect(huntId(cell(cells, "security-headers-absent", "unknown"))).toBe("hunt:security-headers-absent:unknown@services/edge");
  });

  it("keeps libraries out of the columns, and only the ones a pack is written against", () => {
    const stack = matrixStack([fw("nextjs", "node", "16.3.3"), lib("next-auth", "4.24.13"), lib("react", "19.0.0")]);
    expect(stack.map((f) => f.id)).toEqual(["nextjs", "next-auth"]);
    expect(new Set(classCoverage(stack).map((c) => c.framework))).toEqual(new Set(["nextjs"]));
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
