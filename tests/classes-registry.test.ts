import { describe, it, expect } from "vitest";
import { CLASSES, CLASS_LIST } from "../src/classes/registry.js";
import { PACKS } from "../src/classes/packs/index.js";
import { boundRules, shapeFor } from "../src/classes/engine.js";
import { CLASS_IDS, CONFIG_FORMATS } from "../src/classes/types.js";
import { LANGS } from "../src/lang.js";
import { catalogIdioms } from "../src/catalog.js";
import { STACK } from "../src/stack.js";

// The class registry and the packs are DATA the engine trusts blindly. These
// checks are what keep a typo in a pack from becoming a rule that never fires
// (an unknown language) or a crash at scan time (an unknown legacy shape).

const LANG_IDS = new Set(LANGS.map((l) => l.id));
const RULE_LANGS = new Set([...LANG_IDS, ...Object.values(CONFIG_FORMATS)]);

describe("weakness-class registry", () => {
  it("defines every class id once, with an invariant, a guard and examples", () => {
    expect(CLASS_LIST.map((c) => c.id).sort()).toEqual([...CLASS_IDS].sort());
    for (const c of CLASS_LIST) {
      expect(c.cwe, c.id).toMatch(/^CWE-\d+$/);
      expect(c.invariant.length, c.id).toBeGreaterThan(40);
      expect(c.guard.length, c.id).toBeGreaterThan(20);
      expect(c.examples.length, c.id).toBeGreaterThan(0);
      for (const e of c.examples) expect(LANG_IDS.has(e.language), `${c.id} example language ${e.language}`).toBe(true);
    }
  });
});

describe("idiom packs", () => {
  it("have unique ids, and a framework pack names its tested version range", () => {
    const ids = PACKS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const p of PACKS) if (p.framework) expect(p.testedWith, p.id).toMatch(/^[<>=]/);
  });

  it("only reference known classes, known languages and resolvable shapes", () => {
    for (const b of boundRules()) {
      expect(CLASSES[b.classId], `${b.pack.id}/${b.rule.id}`).toBeTruthy();
      for (const l of b.rule.languages) expect(RULE_LANGS.has(l), `${b.pack.id}/${b.rule.id} language ${l}`).toBe(true);
      expect(() => shapeFor(b.classId, b.rule), `${b.pack.id}/${b.rule.id}`).not.toThrow();
      if (b.rule.kind === "call")
        for (const emit of [...(b.rule.bare ?? []), ...(b.rule.flags ?? []).map((f) => f.emit)])
          expect(() => shapeFor(b.classId, b.rule, emit), `${b.pack.id}/${b.rule.id} ${emit}`).not.toThrow();
    }
  });

  it("rule ids are unique within a pack", () => {
    for (const p of PACKS) {
      const ids = boundRules([p]).map((b) => `${b.classId}/${b.rule.id}`);
      expect(new Set(ids).size, p.id).toBe(ids.length);
    }
  });
});

describe("taint-catalog framework labels", () => {
  const idioms = catalogIdioms();

  it("name a stack row and a version range", () => {
    const ids = new Set(STACK.map((e) => e.id));
    for (const i of idioms) {
      expect(ids.has(i.framework), `${i.title}: unknown stack id ${i.framework}`).toBe(true);
      expect(i.testedWith, i.title).toMatch(/^[<>=]/);
    }
  });

  it("cover the framework rows the catalog used to carry unlabelled", () => {
    const has = (framework: string, title: RegExp, kind: string) => idioms.some((i) => i.framework === framework && i.kind === kind && title.test(i.title));
    expect(has("trpc", /procedure input/, "source")).toBe(true);
    expect(has("trpc", /callback/, "refutation")).toBe(true);
    expect(has("nextjs", /Next\.js \/ fetch/, "source")).toBe(true);
    expect(has("nextjs", /App-Router/, "route")).toBe(true);
    expect(has("nextjs", /Server Action/, "route")).toBe(true);
    expect(has("hono", /Hono/, "source")).toBe(true);
    expect(has("spring", /Spring request/, "source")).toBe(true);
    expect(has("phoenix", /Phoenix/, "source")).toBe(true);
  });
});
