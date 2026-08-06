import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { buildVariantWorklist, renderVariantsMd, parseVariantResults, renderRegressionRules } from "../src/variants.js";
import type { Dossier } from "../src/store.js";
import type { Finding, Status } from "../src/types.js";

const REPO = join(import.meta.dirname, "fixtures", "vuln-express");

function f(id: string, status: Status, over: Partial<Finding> = {}): Finding {
  return {
    id,
    category: "taint",
    cwe: "CWE-89",
    title: "SQL injection: untrusted input reaches query()",
    severity: "high",
    confidence: "high",
    message: "m",
    tool: "ultrasec",
    status,
    sink: { file: "src/db.js", line: 6, kind: "sql" },
    ...over,
  };
}

const dossier = (findings: Finding[]): Dossier => ({
  manifest: {
    version: "0",
    schemaVersion: 7,
    repo: REPO,
    generatedNote: "",
    languages: ["javascript"],
    toolsRun: [],
    counts: { findings: findings.length, bySeverity: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 } },
  },
  findings,
  graph: { files: [], edges: [], symbolDefs: {} },
});

describe("buildVariantWorklist", () => {
  it("seeds only from CONFIRMED findings", () => {
    // Hunting variants of an unproved candidate multiplies a guess; the whole
    // value of the stage is that the root cause is already established.
    const d = dossier([f("a", "confirmed"), f("b", "open"), f("c", "needs-human"), f("d", "dismissed")]);
    expect(buildVariantWorklist(d).map((i) => i.seedId)).toEqual(["a"]);
  });

  it("lists a same-operation neighbour as the strongest axis", () => {
    const d = dossier([f("a", "confirmed"), f("b", "open", { sink: { file: "src/other.js", line: 12, kind: "sql" } })]);
    const n = buildVariantWorklist(d)[0]!.neighbours;
    expect(n).toContainEqual(expect.objectContaining({ file: "src/other.js", line: 12, axis: "same-sink-callee" }));
  });

  it("never lists the seed's own location as its neighbour", () => {
    const d = dossier([f("a", "confirmed"), f("b", "open")]); // same sink file:line
    expect(buildVariantWorklist(d)[0]!.neighbours.every((n) => !(n.file === "src/db.js" && n.line === 6))).toBe(true);
  });

  it("falls back to same-cwe when nothing shares the operation or file", () => {
    const d = dossier([
      f("a", "confirmed"),
      f("b", "open", { title: "SQL injection: untrusted input reaches execute()", sink: { file: "src/z.js", line: 3, kind: "sql" } }),
    ]);
    expect(buildVariantWorklist(d)[0]!.neighbours[0]!.axis).toBe("same-cwe");
  });

  it("says plainly there is nothing to hunt when no finding is confirmed", () => {
    const md = renderVariantsMd(buildVariantWorklist(dossier([f("a", "open")])));
    expect(md).toMatch(/variants are hunted from proved bugs, not candidates/);
  });

  it("brief demands an exact match before any generalization", () => {
    const md = renderVariantsMd(buildVariantWorklist(dossier([f("a", "confirmed")])));
    expect(md).toMatch(/EXACT match first/);
    expect(md).toMatch(/zero results means the bug is misunderstood/);
    expect(md).toMatch(/one dimension at a time/);
    expect(md).toMatch(/Proximity is not a finding/);
  });
});

describe("parseVariantResults", () => {
  it("drops a row with no seedId rather than guessing which hunt it belongs to", () => {
    const p = parseVariantResults(JSON.stringify([{ variants: [] }, { seedId: "a", variants: [] }]));
    expect(p.rows).toHaveLength(1);
    expect(p.dropped[0]!.reason).toMatch(/seedId/);
  });

  it("fails closed when every row is unusable", () => {
    expect(() => parseVariantResults(JSON.stringify([{ nope: 1 }]))).toThrow(/nothing folded/);
  });

  it("accepts the {variants:[…]} wrapper the fan-out contracts return", () => {
    const p = parseVariantResults(JSON.stringify({ variants: [{ seedId: "a", variants: [] }] }));
    expect(p.rows).toHaveLength(1);
  });
});

describe("renderRegressionRules", () => {
  it("emits nothing when the auditor wrote no rule", () => {
    expect(renderRegressionRules([{ seedId: "a", variants: [] }])).toBe("");
  });

  it("emits one indented rule per seed under a single `rules:` key", () => {
    const yaml = renderRegressionRules([{ seedId: "a", rootCause: "wrapper never took params", variants: [], regressionRule: "- id: x\n  severity: ERROR" }]);
    expect(yaml).toMatch(/^rules:$/m);
    expect(yaml).toMatch(/^ {2}- id: x$/m);
    expect(yaml).toMatch(/# seed a — wrapper never took params/);
  });
});
