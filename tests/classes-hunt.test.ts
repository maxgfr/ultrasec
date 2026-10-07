import { describe, it, expect, vi } from "vitest";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildClassHunts, parseHuntResults, recordHuntResults } from "../src/classes/hunt.js";
import { classCoverage, huntId, withHuntProgress, PACK_SUGGESTIONS_FILE } from "../src/classes/coverage.js";
import { parseDiscoveries } from "../src/investigate.js";
import { runInvestigate } from "../src/commands/investigate.js";
import { writeDossier } from "../src/store.js";
import { parseArgs } from "../src/util.js";
import type { DetectedFramework } from "../src/frameworks.js";

// The AI half of the weakness classes: a hunt for every class × framework no
// pack settles, and nothing for the ones a pack does — then the idioms the
// auditor recognized, citation-checked into PACK-SUGGESTIONS.json, never
// applied.

const fw = (id: string, ecosystem: DetectedFramework["ecosystem"], version: string, dir = ""): DetectedFramework => ({
  id,
  title: id,
  ecosystem,
  dir,
  version,
  versionSource: "lockfile",
  evidence: `${dir ? `${dir}/` : ""}package.json:3`,
});
const manifestFor = (...frameworks: DetectedFramework[]) => ({ frameworks, weaknessClasses: classCoverage(frameworks) });

describe("buildClassHunts", () => {
  it("emits nothing when every class is covered deterministically (a Next.js app inside testedWith)", () => {
    const nextAuth: DetectedFramework = { ...fw("next-auth", "node", "4.24.13", "packages/app"), kind: "library" };
    expect(buildClassHunts(manifestFor(fw("nextjs", "node", "16.3.3", "packages/app"), nextAuth))).toEqual([]);
  });

  it("hunts only the cells a partial pack leaves uncovered", () => {
    const hunts = buildClassHunts(manifestFor(fw("koa", "node", "2.15.0")));
    // The session-chunk idiom is NextAuth's: with no NextAuth declared, that cell is hunted too.
    expect(hunts.map((h) => h.region)).toEqual(["hunt:unbounded-public-export:koa", "hunt:session-cookie-chunks-on-logout:koa"]);
    const h = hunts[0]!;
    expect(h.files).toEqual(["package.json"]);
    expect(h.hunt).toMatchObject({ class: "unbounded-public-export", framework: "koa", version: "2.15.0", reason: "pack koa has no idiom for this class" });
    expect(h.hunt!.examples[0]!.language).toBe("javascript");
    expect(h.prompt).toContain("INVARIANT:");
    expect(h.prompt).toContain('"hunt": "hunt:unbounded-public-export:koa"');
  });

  it("hunts every cell of a version outside testedWith, naming the floor that already ran", () => {
    const hunts = buildClassHunts(manifestFor(fw("nextjs", "node", "17.0.0", "web")));
    expect(hunts).toHaveLength(7);
    const headers = hunts.find((h) => h.region === "hunt:security-headers-absent:nextjs@web")!;
    expect(headers.hunt!.packsApplied).toEqual(["nextjs"]);
    expect(headers.hunt!.reason).toBe("nextjs 17.0.0 is outside nextjs testedWith >=12 <17");
    expect(hunts.find((h) => h.region === "hunt:timing-unsafe-secret-compare:nextjs@web")!.hunt!.packsApplied).toEqual(["node"]);
  });

  it("never hunts a class declared not applicable", () => {
    expect(buildClassHunts(manifestFor(fw("sinatra", "ruby", "4.0.0"))).some((h) => h.region.includes("session-cookie"))).toBe(false);
  });
});

describe("parseHuntResults", () => {
  it("reads idioms, hunted ids and the hunt ids discoveries carry", () => {
    const r = parseHuntResults(
      JSON.stringify({
        discoveries: [{ title: "t", hunt: "hunt:csv-formula-injection:koa" }],
        idioms: [
          {
            hunt: "hunt:csv-formula-injection:koa",
            class: "csv-formula-injection",
            framework: "koa",
            kind: "unsafe",
            pattern: "ctx.body = toCsv(rows)",
            file: "a.js",
            line: 2,
          },
          { class: "nope", framework: "koa", kind: "unsafe", pattern: "x", file: "a.js", line: 1 },
          { class: "csv-formula-injection", framework: "koa", kind: "guard", pattern: "x", regex: "(", file: "a.js", line: 1 },
        ],
        hunted: ["hunt:env-bool-coercion:koa", "not-a-hunt"],
      }),
    );
    expect(r.idioms).toHaveLength(1);
    expect(r.dropped.map((d) => d.index)).toEqual([1, 2]);
    expect(r.dropped[1]!.reason).toContain("does not compile");
    expect([...new Set(r.hunted)].sort()).toEqual(["hunt:csv-formula-injection:koa", "hunt:env-bool-coercion:koa"]);
  });

  it("leaves a bare Discovery[] payload exactly as it was", () => {
    expect(parseHuntResults(JSON.stringify([{ title: "t" }]))).toEqual({ idioms: [], hunted: [], dropped: [] });
  });

  it("lets an apply carry only hunt results", () => {
    expect(parseDiscoveries(JSON.stringify({ hunted: ["hunt:csv-formula-injection:koa"] })).rows).toEqual([]);
    expect(() => parseDiscoveries(JSON.stringify({ something: [] }))).toThrow(/fail-closed/);
  });
});

describe("recordHuntResults", () => {
  it("writes cited idioms to PACK-SUGGESTIONS.json, rejects invented lines, and merges later applies", () => {
    const repo = mkdtempSync(join(tmpdir(), "ultrasec-hunt-repo-"));
    writeFileSync(join(repo, "export.js"), 'const rows = await Order.query();\nctx.body = rows.map((r) => [r.a, r.b].join(","));\n');
    const run = mkdtempSync(join(tmpdir(), "ultrasec-hunt-run-"));
    const manifest = { frameworks: [fw("koa", "node", "2.15.0")] };
    const idiom = {
      class: "csv-formula-injection" as const,
      framework: "koa",
      kind: "unsafe" as const,
      pattern: 'ctx.body = rows.map(…).join(",")',
      file: "export.js",
      line: 2,
    };
    const first = recordHuntResults(
      run,
      repo,
      manifest,
      [{ idioms: [idiom, { ...idiom, line: 99 }], hunted: ["hunt:csv-formula-injection:koa"], dropped: [] }],
      ["nextjs"],
    );
    expect(first.accepted).toBe(1);
    expect(first.rejected[0]!.reason).toMatch(/line out of range/);
    const file = JSON.parse(readFileSync(join(run, PACK_SUGGESTIONS_FILE), "utf8"));
    expect(file.schema).toBe(1);
    expect(file.note).toMatch(/NEVER applies/);
    expect(file.suggestions[0]).toMatchObject({ pack: "new pack: koa", seenOn: "koa 2.15.0", evidence: 'ctx.body = rows.map((r) => [r.a, r.b].join(","));' });
    const again = recordHuntResults(run, repo, manifest, [{ idioms: [idiom], hunted: ["hunt:env-bool-coercion:koa"], dropped: [] }], ["nextjs"]);
    expect(again.accepted).toBe(0);
    const merged = JSON.parse(readFileSync(join(run, PACK_SUGGESTIONS_FILE), "utf8"));
    expect(merged.suggestions).toHaveLength(1);
    expect(merged.hunted).toEqual(["hunt:csv-formula-injection:koa", "hunt:env-bool-coercion:koa"]);
  });
});

describe("investigate — weakness-class hunts end to end", () => {
  function capture(fn: () => number): { code: number; out: string } {
    const chunks: string[] = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => {
      chunks.push(String(c));
      return true;
    });
    try {
      return { code: fn(), out: chunks.join("") };
    } finally {
      spy.mockRestore();
    }
  }

  it("emits the hunts beside the regions, ingests their results, and the matrix records them", () => {
    const repo = mkdtempSync(join(tmpdir(), "ultrasec-hunt-e2e-"));
    mkdirSync(join(repo, "src"));
    writeFileSync(join(repo, "package.json"), '{\n  "dependencies": {\n    "koa": "^2.15.0"\n  }\n}\n');
    writeFileSync(join(repo, "src", "export.js"), 'router.get("/export/orders", async (ctx) => {\n  ctx.body = await Order.findAll();\n});\n');
    const run = mkdtempSync(join(tmpdir(), "ultrasec-hunt-e2e-run-"));
    const koa = { ...fw("koa", "node", "2.15.0"), evidence: "package.json:3" };
    writeDossier(run, {
      manifest: {
        version: "0",
        schemaVersion: 10,
        repo,
        generatedNote: "",
        languages: ["javascript"],
        toolsRun: [],
        counts: { findings: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
        frameworks: [koa],
        weaknessClasses: classCoverage([koa]),
      },
      findings: [],
      graph: { files: [], edges: [], symbolDefs: {} },
    });

    const emit = capture(() => runInvestigate(parseArgs(["--run", run, "--repo", repo])));
    expect(emit.code).toBe(0);
    expect(emit.out).toContain("2 weakness-class hunt");
    const todo = JSON.parse(readFileSync(join(run, "INVESTIGATE.todo.json"), "utf8")) as { region: string; hunt?: { id: string } }[];
    const id = huntId({ class: "unbounded-public-export", framework: "koa", dir: "" });
    expect(todo.filter((r) => r.hunt).map((r) => r.region)).toEqual([id, huntId({ class: "session-cookie-chunks-on-logout", framework: "koa", dir: "" })]);
    expect(readFileSync(join(run, "INVESTIGATE.md"), "utf8")).toContain("## Weakness-class hunts");
    expect(withHuntProgress(classCoverage([koa]), run).find((c) => c.class === "unbounded-public-export")!.state).toBe("ai-hunt");

    writeFileSync(
      join(run, "INVESTIGATE.json"),
      JSON.stringify({
        discoveries: [
          {
            title: "Public export loads every order",
            category: "other",
            severity: "medium",
            cwe: "CWE-770",
            message: "Anyone can GET /export/orders and materialize the whole table.",
            file: "src/export.js",
            line: 2,
            hunt: id,
          },
        ],
        idioms: [
          {
            hunt: id,
            class: "unbounded-public-export",
            framework: "koa",
            kind: "unsafe",
            pattern: "ctx.body = await Model.findAll()",
            file: "src/export.js",
            line: 2,
          },
        ],
      }),
    );
    const applied = capture(() => runInvestigate(parseArgs(["--run", run, "--repo", repo, "--apply", join(run, "INVESTIGATE.json"), "--strict"])));
    expect(applied.code).toBe(0);
    expect(applied.out).toContain("ingested 1 new");
    expect(applied.out).toContain("pack suggestions: 1 new idiom(s) · 1 hunt(s) recorded");
    expect(withHuntProgress(classCoverage([koa]), run).find((c) => c.class === "unbounded-public-export")!.state).toBe("ai-hunted");
  });
});
