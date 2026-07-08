import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { riskScore } from "../src/tools/scoring.js";
import type { Severity } from "../src/types.js";

// Eval P2.6: the composite risk ordering was asserted "sane" but never MEASURED
// against a reference triage. This pins it with a Spearman rank correlation
// against a labelled KEV->EPSS->CVSS reference (tests/fixtures/calibration/),
// plus the load-bearing invariants (KEV always top-tier; a high-EPSS medium can
// outrank a low-EPSS high; EPSS is monotonic at fixed severity).

interface Entry {
  cve: string;
  severity: Severity;
  cvss: number;
  epss: number;
  kev: boolean;
  referenceRank: number;
}

const REF: { entries: Entry[] } = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures", "calibration", "reference-triage.json"), "utf8"));

/** Fractional (tie-averaged) ranks of the values, 1 = smallest. */
function rankAverage(values: number[]): number[] {
  const idx = values.map((v, i) => ({ v, i })).sort((a, b) => a.v - b.v);
  const ranks = new Array(values.length).fill(0);
  let i = 0;
  while (i < idx.length) {
    let j = i;
    while (j + 1 < idx.length && idx[j + 1]!.v === idx[i]!.v) j++;
    const avg = (i + j) / 2 + 1; // 1-based average rank across the tie group
    for (let k = i; k <= j; k++) ranks[idx[k]!.i] = avg;
    i = j + 1;
  }
  return ranks;
}

/** Spearman rank correlation between two equal-length numeric series. */
function spearman(a: number[], b: number[]): number {
  const ra = rankAverage(a);
  const rb = rankAverage(b);
  const n = a.length;
  const mean = (n + 1) / 2;
  let num = 0;
  let da = 0;
  let db = 0;
  for (let i = 0; i < n; i++) {
    const x = ra[i]! - mean;
    const y = rb[i]! - mean;
    num += x * y;
    da += x * x;
    db += y * y;
  }
  return num / Math.sqrt(da * db);
}

describe("risk calibration", () => {
  const entries = REF.entries;
  const risk = entries.map((e) => riskScore({ severity: e.severity, epss: e.epss, kev: e.kev }));
  // Higher priority = lower rank number, so correlate risk against NEGATED referenceRank.
  const refPriority = entries.map((e) => -e.referenceRank);

  it("risk ordering tracks the reference triage (Spearman >= 0.95)", () => {
    const rho = spearman(risk, refPriority);
    // Measured 0.989 on this corpus; the tight floor trips on a weight regression
    // (e.g. dropping EPSS's influence) while tolerating rounding.
    expect(rho).toBeGreaterThanOrEqual(0.95);
  });

  it("every KEV finding lands in the top tier (risk >= 95)", () => {
    for (const e of entries.filter((e) => e.kev)) {
      expect(riskScore({ severity: e.severity, epss: e.epss, kev: e.kev }), e.cve).toBeGreaterThanOrEqual(95);
    }
    // and KEV items are among the very highest-risk entries overall
    const top = [...risk].sort((a, b) => b - a).slice(0, entries.filter((e) => e.kev).length);
    expect(Math.min(...top)).toBeGreaterThanOrEqual(95);
  });

  it("a high-EPSS medium outranks a low-EPSS high", () => {
    expect(riskScore({ severity: "medium", epss: 0.97 })).toBeGreaterThan(riskScore({ severity: "high", epss: 0.01 }));
  });

  it("risk is monotonic in EPSS at fixed severity", () => {
    const highs = entries.filter((e) => e.severity === "high" && !e.kev).sort((a, b) => a.epss - b.epss);
    for (let i = 1; i < highs.length; i++) {
      expect(riskScore(highs[i]!)).toBeGreaterThanOrEqual(riskScore(highs[i - 1]!));
    }
  });
});
