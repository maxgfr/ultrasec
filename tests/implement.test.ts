import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Dossier } from "../src/store.js";
import type { Finding, Narrative } from "../src/types.js";
import { buildImplementWorklist, loadNarrative, renderImplementMd } from "../src/implement.js";

function f(
  id: string,
  status: Finding["status"],
  opts: { severity?: Finding["severity"]; category?: Finding["category"]; cwe?: string; owner?: string } = {},
): Finding {
  return {
    id,
    category: opts.category ?? "taint",
    title: `finding ${id}`,
    severity: opts.severity ?? "high",
    confidence: "high",
    message: "m",
    tool: "ultrasec",
    status,
    sink: { file: "src/db.js", line: 6 },
    ...(opts.cwe ? { cwe: opts.cwe } : {}),
    ...(opts.owner ? { provenance: { owner: opts.owner } } : {}),
  };
}

function dossier(findings: Finding[]): Dossier {
  return {
    manifest: {
      version: "0.0.0",
      schemaVersion: 4,
      repo: "/repo",
      generatedNote: "",
      languages: [],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    },
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

describe("buildImplementWorklist — classification", () => {
  it("confirmed → fix, needs-human → investigate; open/dismissed excluded from items", () => {
    const wl = buildImplementWorklist(dossier([f("c1", "confirmed"), f("nh1", "needs-human"), f("o1", "open"), f("d1", "dismissed")]));
    expect(wl.fixes.map((i) => i.id)).toEqual(["c1"]);
    expect(wl.fixes.every((i) => i.kind === "fix")).toBe(true);
    expect(wl.investigations.map((i) => i.id)).toEqual(["nh1"]);
    expect(wl.investigations.every((i) => i.kind === "investigate")).toBe(true);
    expect(wl.dismissed).toBe(1); // counted, not listed
  });

  it("is deterministic: items are id-sorted regardless of input order", () => {
    const wl = buildImplementWorklist(dossier([f("c3", "confirmed"), f("c1", "confirmed"), f("c2", "confirmed")]));
    expect(wl.fixes.map((i) => i.id)).toEqual(["c1", "c2", "c3"]);
  });

  it("empty dossier yields empty lists and renders without throwing", () => {
    const wl = buildImplementWorklist(dossier([]));
    expect(wl).toEqual({ fixes: [], investigations: [], rootCauses: [], dismissed: 0 });
    expect(() => renderImplementMd(wl)).not.toThrow();
    expect(renderImplementMd(wl)).toContain("## Problem statement");
  });
});

describe("buildImplementWorklist — narrative fold", () => {
  it("folds fix/patch/owner from a narrative remediation by id; unknown ids are ignored", () => {
    const d = dossier([f("c1", "confirmed")]);
    const narrative: Narrative = {
      remediations: [
        { id: "c1", fix: "Use parameterized queries", patch: "- bad\n+ good", owner: "@api" },
        { id: "ghost", fix: "n/a" }, // no matching finding → never emitted
      ],
    };
    const wl = buildImplementWorklist(d, narrative);
    expect(wl.fixes).toHaveLength(1);
    const c1 = wl.fixes[0]!;
    expect(c1.fix).toBe("Use parameterized queries");
    expect(c1.patch).toBe("- bad\n+ good");
    expect(c1.owner).toBe("@api");
  });

  it("owner precedence: narrative remediation owner wins over provenance owner", () => {
    const d = dossier([f("c1", "confirmed", { owner: "@team" })]);
    expect(buildImplementWorklist(d).fixes[0]!.owner).toBe("@team"); // provenance fallback
    const narrative: Narrative = { remediations: [{ id: "c1", fix: "f", owner: "@api" }] };
    expect(buildImplementWorklist(d, narrative).fixes[0]!.owner).toBe("@api"); // narrative wins
  });

  it("an empty-string fix stub does not pollute the item", () => {
    const d = dossier([f("c1", "confirmed")]);
    const narrative: Narrative = { remediations: [{ id: "c1", fix: "" }] };
    expect(buildImplementWorklist(d, narrative).fixes[0]!.fix).toBeUndefined();
  });
});

describe("buildImplementWorklist — root causes", () => {
  it("uses narrative.rootCauses verbatim when present", () => {
    const d = dossier([f("c1", "confirmed")]);
    const narrative: Narrative = { rootCauses: [{ cause: "string concat", findingIds: ["c1"], note: "n" }] };
    expect(buildImplementWorklist(d, narrative).rootCauses).toEqual([{ cause: "string concat", findingIds: ["c1"], note: "n" }]);
  });

  it("derives groups by (category, cwe) over confirmed findings when no narrative", () => {
    const d = dossier([f("c1", "confirmed", { cwe: "CWE-89" }), f("c2", "confirmed", { cwe: "CWE-89" }), f("c3", "confirmed", { cwe: "CWE-79" })]);
    const rc = buildImplementWorklist(d).rootCauses;
    expect(rc).toHaveLength(2);
    const g89 = rc.find((g) => g.cause.includes("CWE-89"))!;
    expect(g89.findingIds).toEqual(["c1", "c2"]); // shared cause grouped, id-sorted
    const g79 = rc.find((g) => g.cause.includes("CWE-79"))!;
    expect(g79.findingIds).toEqual(["c3"]);
    expect(rc.map((g) => g.findingIds[0])).toEqual(["c1", "c3"]); // groups sorted by first member
  });
});

describe("renderImplementMd — remediation-PRD draft", () => {
  const d = dossier([f("c1", "confirmed"), f("nh1", "needs-human"), f("d1", "dismissed")]);
  const narrative: Narrative = { remediations: [{ id: "c1", fix: "Use parameterized queries", patch: "- bad\n+ good" }] };
  const md = renderImplementMd(buildImplementWorklist(d, narrative));

  it("has the to-prd-shaped section headings", () => {
    for (const h of ["## Problem statement", "## Solution", "## User stories / work items", "## Investigation items", "## Out of scope"]) {
      expect(md).toContain(h);
    }
  });

  it("carries the to-prd handoff directive and the AI disclaimer", () => {
    expect(md).toContain("to-prd");
    expect(md).toContain("verify against the cited findings"); // AI_DISCLAIMER
  });

  it("grounds every confirmed work item in its [file:line] with an acceptance scaffold", () => {
    expect(md).toContain("`src/db.js:6`");
    expect(md).toContain("no longer exploitable");
    expect(md).toContain("regression test");
  });

  it("inlines a suggested fix + a fenced diff patch when the narrative supplies them", () => {
    expect(md).toContain("Use parameterized queries");
    expect(md).toContain("```diff");
  });

  it("counts dismissed candidates under Out of scope", () => {
    expect(md).toContain("1 finding(s) were dismissed");
  });
});

describe("loadNarrative", () => {
  it("grounds NARRATIVE.json against the dossier (confirmed-only) and returns undefined when absent", () => {
    const dir = mkdtempSync(join(tmpdir(), "ultrasec-impl-"));
    const d = dossier([f("c1", "confirmed"), f("nh1", "needs-human")]);
    writeFileSync(
      join(dir, "NARRATIVE.json"),
      JSON.stringify({
        remediations: [
          { id: "c1", fix: "x" },
          { id: "nh1", fix: "y" },
        ],
      }),
    );
    const n = loadNarrative(dir, d);
    expect(n?.remediations?.map((r) => r.id)).toEqual(["c1"]); // non-confirmed nh1 dropped by grounding
    expect(loadNarrative(join(dir, "absent"), d)).toBeUndefined();
  });
});
