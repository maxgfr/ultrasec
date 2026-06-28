import { describe, it, expect } from "vitest";
import { riskScore, parseEpssCsv, parseKev, applyEnrichment, type Feeds } from "../src/tools/scoring.js";
import { makeToolFinding } from "../src/tools/normalize.js";

describe("riskScore", () => {
  it("blends severity and EPSS, KEV floors at 95", () => {
    expect(riskScore({ severity: "critical" })).toBe(60); // 0.6*1.0
    expect(riskScore({ severity: "high" })).toBe(48);
    expect(riskScore({ severity: "low" })).toBe(15);
    expect(riskScore({ severity: "high", epss: 0.9 })).toBe(84); // 0.48 + 0.36
    expect(riskScore({ severity: "low", kev: true })).toBe(95); // KEV overrides
    expect(riskScore({ severity: "critical", epss: 1, kev: true })).toBe(100);
  });
  it("a high-EPSS high outranks a severity-only critical", () => {
    expect(riskScore({ severity: "high", epss: 0.9 })).toBeGreaterThan(riskScore({ severity: "critical" }));
  });
});

describe("parseEpssCsv", () => {
  const csv = `#model_version:v2025\ncve,epss,percentile\nCVE-2021-23337,0.00445,0.732\nCVE-2020-8203,0.01,0.9\nbad-row`;
  it("parses rows, skips comments/header/garbage, uppercases the key", () => {
    const m = parseEpssCsv(csv);
    expect(m.size).toBe(2);
    expect(m.get("CVE-2021-23337")!.epss).toBeCloseTo(0.00445);
    expect(m.get("CVE-2020-8203")!.percentile).toBeCloseTo(0.9);
  });
});

describe("parseKev", () => {
  it("indexes cveID → dateAdded, tolerates junk", () => {
    const m = parseKev(JSON.stringify({ vulnerabilities: [{ cveID: "CVE-2021-23337", dateAdded: "2022-05-25" }] }));
    expect(m.has("CVE-2021-23337")).toBe(true);
    expect(m.get("CVE-2021-23337")).toBe("2022-05-25");
    expect(parseKev("not json").size).toBe(0);
    expect(parseKev("{}").size).toBe(0);
  });
});

describe("applyEnrichment", () => {
  const feeds: Feeds = {
    epss: new Map([["CVE-2021-23337", { epss: 0.9 }]]),
    kev: new Map([["CVE-2021-23337", "2022-05-25"]]),
  };
  it("attaches epss/kev/risk to a CVE finding and risk-only to others", () => {
    const dep = makeToolFinding({
      tool: "trivy",
      category: "dep",
      ident: "CVE-2021-23337",
      title: "x",
      severity: "high",
      message: "m",
      pkg: "lodash",
      version: "1",
    });
    const sast = makeToolFinding({ tool: "semgrep", category: "sast", ident: "r:1", title: "y", severity: "medium", message: "m", file: "a.py", line: 1 });
    const [d, s] = applyEnrichment([dep, sast], feeds);
    expect(d!.epss).toBeCloseTo(0.9);
    expect(d!.kev).toBe(true);
    expect(d!.kevDateAdded).toBe("2022-05-25");
    expect(d!.risk).toBe(95); // KEV floor
    expect(s!.epss).toBeUndefined();
    expect(s!.kev).toBeUndefined();
    expect(s!.risk).toBe(30); // 0.6*0.5 severity-only
  });
});
