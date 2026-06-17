import { describe, it, expect } from "vitest";
import { parseSarif } from "../src/tools/sarif.js";

const sarif = JSON.stringify({
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "demo",
          rules: [
            {
              id: "RULE-A",
              properties: { tags: ["security", "external/cwe/cwe-78"], "security-severity": "8.8" },
              helpUri: "https://example.com/RULE-A",
              shortDescription: { text: "Command injection" },
            },
          ],
        },
      },
      results: [
        {
          ruleId: "RULE-A",
          message: { text: "untrusted input to exec" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "src/x.py" }, region: { startLine: 5 } } }],
        },
        {
          ruleId: "RULE-B",
          level: "warning",
          message: { text: "weak hash" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "src/y.py" }, region: { startLine: 9 } } }],
        },
      ],
    },
  ],
});

describe("parseSarif", () => {
  const f = parseSarif(sarif, { tool: "demo", category: "sast", defaultCwe: "CWE-1" });
  it("derives severity from security-severity and CWE from rule tags", () => {
    const a = f.find((x) => x.title === "RULE-A")!;
    expect(a.severity).toBe("high"); // 8.8 → high
    expect(a.cwe).toBe("CWE-78");
    expect(a.category).toBe("sast");
    expect(a.tool).toBe("demo");
    expect(a.sink).toEqual({ file: "src/x.py", line: 5 });
    expect(a.references).toContain("https://example.com/RULE-A");
  });
  it("falls back to SARIF level and the default CWE", () => {
    const b = f.find((x) => x.title === "RULE-B")!;
    expect(b.severity).toBe("medium"); // warning
    expect(b.cwe).toBe("CWE-1"); // default
  });
  it("tolerates empty / malformed input", () => {
    expect(parseSarif("", { tool: "x", category: "sast" })).toEqual([]);
    expect(parseSarif("{}", { tool: "x", category: "sast" })).toEqual([]);
    expect(parseSarif("not json", { tool: "x", category: "sast" })).toEqual([]);
  });
});
