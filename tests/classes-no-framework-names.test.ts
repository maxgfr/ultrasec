import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { STACK } from "../src/stack.js";

// The class layer's contract: the engine, the matrix and the hunt never learn
// a framework's name. Idioms are pack data (src/classes/packs), stacks are
// table rows (src/stack.ts); a framework spelled in these three files is an
// idiom hard-coded where no `testedWith` can degrade it and no hunt can
// replace it. Comments may cite frameworks as examples; code may not.

const GUARDED = ["src/classes/engine.ts", "src/classes/coverage.ts", "src/classes/hunt.ts"];

/** Code only: comments removed, string and regex contents kept (an idiom hides there). */
function codeOf(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .split("\n")
    .map((l) => l.replace(/(^|[^:"'`\\])\/\/.*$/, "$1"))
    .join("\n");
}

const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

/** Every name a stack row is known by: id, title, label, dependency names. Short
 *  ids that are ordinary words in code (`next`, `echo`, `plug`) are checked
 *  through their title and packages instead. */
const ORDINARY = new Set([
  "next",
  "echo",
  "plug",
  "fresh",
  "warp",
  "tide",
  "fiber",
  "slim",
  "rocket",
  "sails",
  "bottle",
  "chi",
  "oak",
  "jwt",
  "react",
  "vue",
  "svelte",
  "graphql",
  "knex",
  "unknown",
]);
const NAMES = [
  ...new Set(
    STACK.flatMap((e) => [e.id, e.title, ...(e.label ? [e.label] : []), ...Object.values(e.deps).flat()])
      .map((n) => n.replace(/\*$/, ""))
      .filter((n) => n.length >= 3 && !ORDINARY.has(n.toLowerCase())),
  ),
];

describe("no framework is hard-coded in the class engine, the matrix or the hunt", () => {
  for (const file of GUARDED) {
    it(file, () => {
      const code = codeOf(readFileSync(join(import.meta.dirname, "..", file), "utf8"));
      const found = NAMES.filter((n) => new RegExp(`(?<![\\w@.-])${esc(n)}(?![\\w-])`, "i").test(code));
      expect(found).toEqual([]);
    });
  }

  it("checks a meaningful vocabulary", () => {
    for (const n of ["Next.js", "django", "laravel/framework", "github.com/gin-gonic/gin", "phoenix", "next-auth", "@trpc/server"]) expect(NAMES).toContain(n);
  });
});
