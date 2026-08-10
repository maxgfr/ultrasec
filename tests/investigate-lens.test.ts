import { describe, it, expect } from "vitest";
import { LENSES, buildInvestigateWorklist } from "../src/investigate.js";
import type { AttackSurface } from "../src/map.js";
import type { Graph } from "../src/graph.js";

// The access-control lens is the low-code half of the access-control workstream:
// it does not enumerate anything (taint cannot), it re-frames the SAME regions as
// an IDOR/BOLA/BFLA hunt. Guard the lens vocabulary and that its text actually
// reaches the region prompts.

const surface: AttackSurface = {
  totals: { files: 1, sources: 1, sinks: 1, truncated: false },
  entryPoints: [{ kind: "http", count: 1, samples: [{ file: "src/routes.js", line: 3, kind: "http", title: "req.params" }] }],
  sinks: [{ kind: "sql", cwe: "CWE-89", severity: "high", count: 1, samples: [{ file: "src/routes.js", line: 9, callee: "query" }] }],
  byLanguage: [{ lang: "javascript", files: 1, sources: 1, sinks: 1 }],
  byTopDir: [{ dir: "src", files: 1, sources: 1, sinks: 1, score: 5 }],
  suggestedTargets: [{ scope: "src", sinks: 1, sources: 1, score: 5, covered: false, reason: "sink density" }],
};
const graph: Graph = { files: ["src/routes.js"], edges: [], symbolDefs: {} };

describe("access-control lens", () => {
  it("registers access-control and its idor alias", () => {
    expect(Object.keys(LENSES)).toEqual(expect.arrayContaining(["access-control", "idor", "sharp-edges", "crypto", "privacy"]));
    // The alias must be the SAME text, so the two can never drift.
    expect(LENSES.idor).toBe(LENSES["access-control"]);
  });

  it("names IDOR/BOLA/BFLA and points at its reference", () => {
    const t = LENSES["access-control"]!;
    expect(t).toMatch(/IDOR\/BOLA/);
    expect(t).toMatch(/BFLA/);
    expect(t).toMatch(/references\/access-control\.md/);
  });

  it("folds the lens text into the region prompt when requested", () => {
    const withLens = buildInvestigateWorklist(surface, graph, [], "access-control");
    expect(withLens[0]!.prompt).toMatch(/LENS — access-control/);
    expect(withLens[0]!.prompt).toMatch(/owner_id\/tenant_id/);
    // Without a lens the base prompt carries no LENS section.
    const noLens = buildInvestigateWorklist(surface, graph, []);
    expect(noLens[0]!.prompt).not.toMatch(/LENS —/);
  });
});
