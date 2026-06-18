import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { parseArgs } from "../src/util.js";
import { runGraph } from "../src/commands/graph.js";
import { normalizeSeverity } from "../src/tools/normalize.js";
import { cvssBaseScore, deriveSeverity } from "../src/tools/cvss.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

// Regression suite for the prototype-key bug class (a symbol/severity/metric/flag
// value colliding with an Object.prototype member like "constructor"/"toString").

describe("graph command — prototype-named symbol", () => {
  it("treats `constructor` as an unknown symbol (exit 2), not a bogus success", () => {
    const code = runGraph(parseArgs(["graph", "constructor", "--repo", FIXTURE]));
    expect(code).toBe(2);
  });
  it("still resolves a real symbol", () => {
    const code = runGraph(parseArgs(["graph", "getUser", "--repo", FIXTURE]));
    expect(code).toBe(0);
  });
});

describe("normalizeSeverity — prototype-named severity", () => {
  it("falls back instead of leaking an inherited function", () => {
    expect(normalizeSeverity("constructor")).toBe("medium");
    expect(normalizeSeverity("toString", "low")).toBe("low");
    expect(normalizeSeverity("high")).toBe("high"); // sanity
  });
});

describe("cvssBaseScore — prototype-named metric value", () => {
  it("returns null (invalid) for a vector whose metric is a prototype member", () => {
    expect(cvssBaseScore("CVSS:3.1/AV:constructor/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeNull();
    // and deriveSeverity then uses its fallback, not a NaN-driven downgrade to info
    expect(deriveSeverity("CVSS:3.1/AV:constructor/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe("medium");
    // a valid vector still scores
    expect(cvssBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeGreaterThan(9);
  });
});
