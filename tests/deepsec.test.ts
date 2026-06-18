import { describe, it, expect } from "vitest";
import { importDeepsec } from "../src/tools/deepsec.js";
import { normalizeSeverity } from "../src/tools/normalize.js";

// A minimal ExportedFinding[] as produced by `deepsec export --format json`.
const sample = JSON.stringify([
  {
    title: "SQL injection in user lookup",
    description: "User input concatenated into a raw query. CWE-89.",
    severity: "HIGH",
    labels: ["security", "cwe-89"],
    metadata: {
      projectId: "p1",
      filePath: "src/db/users.ts",
      lineNumbers: [42, 43],
      severity: "HIGH",
      vulnSlug: "sql-injection",
      confidence: "high",
      discoveredAt: "2026-01-01",
      runId: "r1",
      revalidation: { verdict: "true-positive", reasoning: "reaches the DB unsanitized" },
      githubUrl: "https://github.com/x/y/blob/main/src/db/users.ts#L42",
      owners: {},
    },
  },
  {
    title: "Broken access control on admin route",
    description: "Missing authorization check.",
    severity: "MEDIUM",
    labels: [],
    metadata: {
      projectId: "p1",
      filePath: "src/routes/admin.ts",
      lineNumbers: [10],
      severity: "MEDIUM",
      vulnSlug: "missing-access-control",
      confidence: "medium",
      discoveredAt: "2026-01-01",
      runId: "r1",
      owners: {},
    },
  },
]);

describe("importDeepsec", () => {
  const f = importDeepsec(sample);

  it("maps each ExportedFinding to a deepsec-sourced, open Finding", () => {
    expect(f).toHaveLength(2);
    expect(f.every((x) => x.tool === "deepsec")).toBe(true);
    expect(f.every((x) => x.sources?.includes("deepsec"))).toBe(true);
    expect(f.every((x) => x.status === "open")).toBe(true);
  });

  it("sets the sink location from filePath + first line number", () => {
    const sqli = f.find((x) => x.title.includes("SQL injection"))!;
    expect(sqli.sink).toEqual({ file: "src/db/users.ts", line: 42 });
  });

  it("normalizes severity and confidence", () => {
    const sqli = f.find((x) => x.title.includes("SQL injection"))!;
    expect(sqli.severity).toBe("high");
    expect(sqli.confidence).toBe("high");
  });

  it("derives category from the vulnSlug and NEVER maps to 'taint'", () => {
    const sqli = f.find((x) => x.title.includes("SQL injection"))!;
    const authz = f.find((x) => x.title.includes("access control"))!;
    expect(sqli.category).toBe("sast");
    expect(authz.category).toBe("authz");
    expect(f.every((x) => x.category !== "taint")).toBe(true);
  });

  it("pulls a CWE from the description/labels when present", () => {
    const sqli = f.find((x) => x.title.includes("SQL injection"))!;
    expect(sqli.cwe).toBe("CWE-89");
  });

  it("keeps the githubUrl reference and folds the revalidation reasoning into the message", () => {
    const sqli = f.find((x) => x.title.includes("SQL injection"))!;
    expect(sqli.references).toContain("https://github.com/x/y/blob/main/src/db/users.ts#L42");
    expect(sqli.message.toLowerCase()).toContain("revalidation");
  });

  it("ids are stable/idempotent across re-imports", () => {
    expect(importDeepsec(sample).map((x) => x.id)).toEqual(f.map((x) => x.id));
  });

  it("tolerates empty / malformed input without throwing", () => {
    expect(importDeepsec("")).toEqual([]);
    expect(importDeepsec("not json")).toEqual([]);
    expect(importDeepsec("{}")).toEqual([]); // not an array
    expect(importDeepsec("[1, null, {}]")).toEqual([]); // entries without metadata are skipped
  });
});

describe("normalizeSeverity (deepsec non-security tiers)", () => {
  it("aliases HIGH_BUG and BUG so they don't silently collapse to the fallback", () => {
    expect(normalizeSeverity("HIGH_BUG")).toBe("high");
    expect(normalizeSeverity("BUG")).toBe("low");
  });
});
