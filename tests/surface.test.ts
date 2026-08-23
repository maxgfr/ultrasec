import { describe, it, expect } from "vitest";
import { CATEGORIES, type Category, type Finding, type Severity } from "../src/types.js";
import { bySurface, surfaceOf, SURFACE_TITLE, SURFACES, unadjudicatedCode } from "../src/surface.js";

function f(over: Partial<Finding> = {}): Finding {
  return {
    id: over.id ?? "abc123",
    category: "taint",
    title: "t",
    severity: "high",
    confidence: "medium",
    message: "m",
    tool: "ultrasec",
    status: "open",
    ...over,
  } as Finding;
}

describe("surfaceOf", () => {
  it("routes every category in the closed vocabulary", () => {
    // The report has three sections and no fallback bin. A category with no
    // home would silently render nowhere, so assert the mapping is total.
    for (const category of CATEGORIES) {
      expect(SURFACES).toContain(surfaceOf(f({ category })));
    }
  });

  it("separates installed code from written code", () => {
    expect(surfaceOf(f({ category: "dep" }))).toBe("deps");
    expect(surfaceOf(f({ category: "taint" }))).toBe("code");
    expect(surfaceOf(f({ category: "sast" }))).toBe("code");
    expect(surfaceOf(f({ category: "authz" }))).toBe("code");
  });

  it("gives secrets and IaC their own surface", () => {
    // In the repo, so not a vendor problem; but read as a diff, not a flow.
    expect(surfaceOf(f({ category: "secret" }))).toBe("supply");
    expect(surfaceOf(f({ category: "config" }))).toBe("supply");
  });

  it("reads an unknown category as code rather than hiding it in the dep fold", () => {
    expect(surfaceOf(f({ category: "not-a-category" as Category }))).toBe("code");
  });

  it("names every surface", () => {
    for (const s of SURFACES) expect(SURFACE_TITLE[s]).toBeTruthy();
  });
});

describe("bySurface", () => {
  it("partitions without losing or duplicating a finding", () => {
    const all = [f({ id: "a", category: "taint" }), f({ id: "b", category: "dep" }), f({ id: "c", category: "secret" }), f({ id: "d", category: "sast" })];
    const g = bySurface(all);
    expect(g.code.map((x) => x.id)).toEqual(["a", "d"]);
    expect(g.supply.map((x) => x.id)).toEqual(["c"]);
    expect(g.deps.map((x) => x.id)).toEqual(["b"]);
    expect(g.code.length + g.supply.length + g.deps.length).toBe(all.length);
  });

  it("returns all three keys even when empty", () => {
    const g = bySurface([]);
    expect(Object.keys(g).sort()).toEqual(["code", "deps", "supply"]);
  });
});

describe("unadjudicatedCode", () => {
  const open = (category: Category, severity: Severity, id: string) => f({ id, category, severity, status: "open" });

  it("counts unread HIGH and CRITICAL source-code candidates", () => {
    const got = unadjudicatedCode([open("taint", "critical", "a"), open("sast", "high", "b"), open("authz", "high", "c")]);
    expect(got.map((x) => x.id).sort()).toEqual(["a", "b", "c"]);
  });

  it("ignores open dependency advisories — a ranked list is a legitimate resting place", () => {
    expect(unadjudicatedCode([open("dep", "critical", "cve")])).toEqual([]);
  });

  it("ignores anything already decided", () => {
    for (const status of ["confirmed", "needs-human", "dismissed"] as const) {
      expect(unadjudicatedCode([f({ category: "taint", severity: "critical", status })])).toEqual([]);
    }
  });

  it("ignores medium and below — those are what triage is for", () => {
    for (const severity of ["medium", "low", "info"] as const) {
      expect(unadjudicatedCode([open("taint", severity, "x")])).toEqual([]);
    }
  });

  it("counts an unread secret or IaC finding — those are the repo's own too", () => {
    expect(
      unadjudicatedCode([open("secret", "high", "s"), open("config", "high", "c")])
        .map((x) => x.id)
        .sort(),
    ).toEqual(["c", "s"]);
  });
});
