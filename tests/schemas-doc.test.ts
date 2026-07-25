import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseVerdicts } from "../src/verify.js";
import { parseTriage } from "../src/triage.js";
import { parseRevalidations } from "../src/revalidate.js";
import { parseDiscoveries } from "../src/investigate.js";
import { parseNarrative } from "../src/narrative.js";
import { SEVERITIES, CONFIDENCES, CATEGORIES, STATUSES, VERDICTS, type Finding } from "../src/types.js";

// references/schemas.md is the only place an agent can learn the exact shape of every
// worklist it has to write. A documented example that `--apply` would reject is worse
// than no example, so every JSON block in that file is run through the REAL parser
// here — the docs cannot drift from what the engine accepts.
const SCHEMAS = join(import.meta.dirname, "..", "skills", "ultrasec", "references", "schemas.md");
const doc = readFileSync(SCHEMAS, "utf8");

/** Every fenced ```json block, in document order. */
const blocks: string[] = [...doc.matchAll(/```json\n([\s\S]*?)```/g)].map((m) => m[1] ?? "");

/** The first block that parses to something matching `pick`. */
function blockWhere(pick: (v: unknown) => boolean): string {
  const hit = blocks.find((b) => {
    try {
      return pick(JSON.parse(b));
    } catch {
      return false;
    }
  });
  if (!hit) throw new Error("no matching JSON block in references/schemas.md");
  return hit;
}

const isArrayOfObjectsWith =
  (key: string) =>
  (v: unknown): boolean =>
    Array.isArray(v) && v.length > 0 && v.every((r) => typeof r === "object" && r !== null && key in (r as object));

describe("references/schemas.md examples are valid JSON", () => {
  it("has blocks, and every one parses", () => {
    expect(blocks.length).toBeGreaterThanOrEqual(8);
    for (const [i, b] of blocks.entries()) {
      expect(() => JSON.parse(b), `JSON block #${i + 1} in schemas.md does not parse`).not.toThrow();
    }
  });
});

describe("references/schemas.md examples round-trip through the real --apply parsers", () => {
  it("the verdict example is accepted by parseVerdicts", () => {
    const rows = parseVerdicts(
      blockWhere((v) => isArrayOfObjectsWith("verdict")(v) && (v as { verdict: string }[]).some((r) => (VERDICTS as readonly string[]).includes(r.verdict))),
    );
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) {
      expect(typeof r.id).toBe("string");
      expect(VERDICTS as readonly string[]).toContain(r.verdict);
    }
    // The documented example must show the exploitPath a `supported` verdict requires.
    expect(rows.some((r) => r.verdict === "supported" && (r.exploitPath ?? "").length > 0)).toBe(true);
  });

  it("the triage example is accepted by parseTriage", () => {
    const rows = parseTriage(
      blockWhere((v) => isArrayOfObjectsWith("verdict")(v) && (v as { verdict: string }[]).every((r) => r.verdict === "noise" || r.verdict === "keep")),
    );
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) expect(["noise", "keep"]).toContain(r.verdict);
  });

  it("the revalidation example is accepted by parseRevalidations", () => {
    const rows = parseRevalidations(
      blockWhere(
        (v) =>
          isArrayOfObjectsWith("verdict")(v) &&
          (v as { verdict: string }[]).some((r) => ["still-valid", "fixed", "false-positive", "uncertain"].includes(r.verdict)),
      ),
    );
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) expect(["still-valid", "fixed", "false-positive", "uncertain"]).toContain(r.verdict);
  });

  it("the Discovery example is accepted by parseDiscoveries", () => {
    const rows = parseDiscoveries(blockWhere(isArrayOfObjectsWith("message")));
    expect(rows.length).toBeGreaterThan(0);
    for (const d of rows) {
      expect(CATEGORIES as readonly string[]).toContain(d.category);
      expect(SEVERITIES as readonly string[]).toContain(d.severity);
      expect(typeof d.file).toBe("string");
      expect(d.line).toBeGreaterThan(0);
      for (const p of d.path ?? []) expect(p.why.length, "every path step needs a why").toBeGreaterThan(0);
    }
  });

  it("the Narrative example is accepted by parseNarrative, with every section populated", () => {
    const n = parseNarrative(blockWhere((v) => typeof v === "object" && v !== null && "executiveSummary" in (v as object)));
    // The two fields the docs push hardest are exactly the ones an example tends to omit.
    expect(n.positivePatterns?.length, "the example must demonstrate positivePatterns").toBeGreaterThan(0);
    expect(n.hardeningNotes?.length, "the example must demonstrate hardeningNotes").toBeGreaterThan(0);
    expect(n.remediations?.length).toBeGreaterThan(0);
    expect(n.attackChains?.length).toBeGreaterThan(0);
    expect(n.rootCauses?.length).toBeGreaterThan(0);
  });

  it("the Finding example uses only real enum values", () => {
    const f = JSON.parse(blockWhere((v) => typeof v === "object" && v !== null && "status" in (v as object) && "cwe" in (v as object))) as Finding;
    expect(CATEGORIES as readonly string[]).toContain(f.category);
    expect(SEVERITIES as readonly string[]).toContain(f.severity);
    expect(CONFIDENCES as readonly string[]).toContain(f.confidence);
    expect(STATUSES as readonly string[]).toContain(f.status);
    if (f.verdict) expect(VERDICTS as readonly string[]).toContain(f.verdict);
    for (const p of f.path ?? []) expect(typeof p.why).toBe("string");
  });
});

describe("references/schemas.md documents the vocabularies it claims to", () => {
  it("lists every enum value the engine defines", () => {
    for (const v of [...SEVERITIES, ...CONFIDENCES, ...CATEGORIES, ...STATUSES, ...VERDICTS]) {
      expect(doc.includes(`\`${v}\``), `schemas.md never mentions the value \`${v}\``).toBe(true);
    }
  });
});
