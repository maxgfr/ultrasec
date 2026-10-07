import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { auditWeaknessClasses } from "../src/classes/engine.js";
import { PACKS } from "../src/classes/packs/index.js";
import { CLASS_IDS, type ClassId } from "../src/classes/types.js";
import { FRAMEWORKS, detectFrameworks, satisfies, webFrameworks } from "../src/frameworks.js";

// The recall matrix: weakness class × ecosystem (and × framework where the
// idiom is the framework's). Every cell is a SYNTHETIC vulnerable/fixed pair
// under tests/fixtures/classes; this test fails when a vulnerable variant is
// not detected (a pack lost recall) or a fixed variant is (a pack lost its
// guard). It is also the contract a new pack signs: add the cell here, with
// both variants, or the completeness check below refuses the pack.

const FIXTURE = join(import.meta.dirname, "fixtures", "classes");
type Cell = { vuln: string[]; fixed: string[] };
const expectations = JSON.parse(readFileSync(join(FIXTURE, "expectations.json"), "utf8")) as Record<ClassId, Record<string, Cell>>;

/** The first lot: the frameworks every class must be decided for. */
const FIRST_LOT = ["nextjs", "express", "nestjs", "fastify", "django", "flask", "fastapi", "spring", "net-http", "gin", "rails", "laravel"];
const ecosystemOf = (cell: string): string => FRAMEWORKS.find((f) => f.id === cell)?.ecosystem ?? cell;
/** Ecosystems with a language pack: the ones a class must be decided for. An
 *  ecosystem with none (Elixir, Rust, .NET, Deno) is detected and hunted. */
const PACKED_ECOSYSTEMS = [...new Set(PACKS.filter((p) => !p.framework && p.ecosystem !== "*").map((p) => p.ecosystem))];

const frameworks = webFrameworks(detectFrameworks(FIXTURE));
const { hits } = auditWeaknessClasses(FIXTURE, undefined, undefined, frameworks);
const filesOf = (c: ClassId): Set<string> => new Set(hits.filter((h) => h.classId === c).map((h) => h.file));

describe("weakness classes — recall matrix (synthetic vulnerable/fixed pairs)", () => {
  for (const c of CLASS_IDS) {
    for (const [cell, pair] of Object.entries(expectations[c] ?? {})) {
      it(`${c} × ${cell}: detected in the vulnerable variant`, () => {
        for (const f of pair.vuln) expect(filesOf(c).has(f), `${c} not detected in ${f}`).toBe(true);
      });
      it(`${c} × ${cell}: silent on the fixed variant`, () => {
        for (const f of pair.fixed) expect(filesOf(c).has(f), `${c} reported on the fixed ${f}`).toBe(false);
      });
    }
  }

  it("reports nothing at all in any fixed variant", () => {
    expect(hits.filter((h) => /^[a-z]+-fixed\//.test(h.file)).map((h) => `${h.classId} ${h.file}:${h.line} (${h.packId}/${h.ruleId})`)).toEqual([]);
  });

  it("reports in a vulnerable variant only what its cell expects", () => {
    const stray = hits.filter((h) => !Object.values(expectations[h.classId] ?? {}).some((p) => p.vuln.includes(h.file)));
    expect(stray.map((h) => `${h.classId} ${h.file}:${h.line} (${h.packId}/${h.ruleId})`)).toEqual([]);
  });
});

describe("weakness classes — the matrix is complete for the first lot", () => {
  const frameworkLevel = (c: ClassId) => !PACKS.some((p) => !p.framework && p.classes[c] && "rules" in p.classes[c]!);

  for (const c of CLASS_IDS) {
    it(`${c}: every ecosystem is either covered by a fixture cell or declared not applicable`, () => {
      const cells = Object.keys(expectations[c] ?? {});
      for (const eco of PACKED_ECOSYSTEMS) {
        const covered = cells.some((cell) => ecosystemOf(cell) === eco);
        const declaredNa = PACKS.some((p) => p.ecosystem === eco && p.classes[c] && "notApplicable" in p.classes[c]!);
        expect(covered || declaredNa, `${c} × ${eco}: no fixture cell and no notApplicable declaration`).toBe(true);
        if (declaredNa) expect(covered, `${c} × ${eco}: declared not applicable AND has a cell`).toBe(false);
      }
      if (frameworkLevel(c)) for (const fw of FIRST_LOT) expect(cells, `${c} is framework-level: ${fw} needs its own cell`).toContain(fw);
    });
  }

  it("every framework in the fixtures is detected inside its pack's testedWith", () => {
    for (const f of frameworks) {
      const pack = PACKS.find((p) => p.framework === f.id);
      expect(pack, `no pack for ${f.id}`).toBeTruthy();
      expect(f.version, `${f.id} in ${f.dir}: no version`).toBeTruthy();
      expect(satisfies(f.version!, pack!.testedWith!), `${f.id} ${f.version} outside ${pack!.testedWith}`).toBe(true);
    }
    expect(new Set(frameworks.map((f) => f.id))).toEqual(new Set(FIRST_LOT));
  });
});
