import { describe, it, expect } from "vitest";
import { riskScore, deploymentFacts } from "../src/tools/scoring.js";
import { SEVERITIES } from "../src/types.js";

describe("risk score v2 — deployment facts re-weight, absence changes nothing", () => {
  it("is bit-identical to the old formula when CONTEXT.md says nothing", () => {
    // The only safe way to add a factor to a ranking people already trust: a run
    // without the new inputs must produce the exact score it produced before.
    for (const severity of SEVERITIES) {
      for (const epss of [undefined, 0, 0.13, 1]) {
        const expected = Math.round(100 * (0.6 * { critical: 1.0, high: 0.8, medium: 0.5, low: 0.25, info: 0.1 }[severity] + 0.4 * (epss ?? 0)));
        expect(riskScore({ severity, epss })).toBe(expected);
      }
    }
  });

  it("keeps the KEV floor whatever the deployment says", () => {
    expect(riskScore({ severity: "low", kev: true, exposure: "build-time", criticality: "peripheral" })).toBe(95);
  });

  it("ranks an internet-facing crown jewel above an identical build-time peripheral", () => {
    const a = riskScore({ severity: "high", epss: 0.2, exposure: "internet-facing", criticality: "crown-jewel" });
    const b = riskScore({ severity: "high", epss: 0.2, exposure: "build-time", criticality: "peripheral" });
    expect(a).toBeGreaterThan(b);
  });

  it("treats a half-filled CONTEXT neutrally rather than demoting everything", () => {
    // Recording only exposure must not silently push every finding down as if
    // criticality had been declared 'peripheral'.
    const onlyExposure = riskScore({ severity: "high", epss: 0.2, exposure: "internet-facing" });
    const both = riskScore({ severity: "high", epss: 0.2, exposure: "internet-facing", criticality: "standard" });
    expect(onlyExposure).toBe(both);
  });

  it("stays inside 0–100", () => {
    expect(riskScore({ severity: "critical", epss: 1, exposure: "internet-facing", criticality: "crown-jewel" })).toBeLessThanOrEqual(100);
    expect(riskScore({ severity: "info", epss: 0, exposure: "build-time", criticality: "peripheral" })).toBeGreaterThanOrEqual(0);
  });
});

describe("deploymentFacts", () => {
  it("reads the documented line shape", () => {
    expect(deploymentFacts("Exposure: internet-facing\nCriticality: crown-jewel")).toEqual({ exposure: "internet-facing", criticality: "crown-jewel" });
  });

  it("reads it through markdown list and bold decoration", () => {
    expect(deploymentFacts("- **Exposure**: `internal`\n- **Criticality**: `peripheral`")).toEqual({ exposure: "internal", criticality: "peripheral" });
  });

  it("ignores a value outside the vocabulary rather than inventing a weight", () => {
    expect(deploymentFacts("Exposure: somewhat-public")).toEqual({});
  });

  it("returns nothing for an absent CONTEXT.md", () => {
    expect(deploymentFacts(undefined)).toEqual({});
    expect(deploymentFacts("A prose context with no such line.")).toEqual({});
  });
});
