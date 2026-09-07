import { describe, expect, it } from "vitest";
import { gosec } from "../src/tools/gosec.js";

describe("gosec scan coverage", () => {
  it.each(["", "   ", "{}", "null", "[]", "not JSON"])("rejects a missing or malformed report: %j", (raw) => {
    expect(() => gosec.parse(raw, "/repo")).toThrow();
  });

  it("rejects package-loading errors instead of reporting a clean scan", () => {
    const raw = JSON.stringify({
      "Golang errors": { ".": [{ line: 0, column: 0, error: "go command required, not found" }] },
      Issues: [],
      Stats: { files: 0, lines: 0, nosec: 0, found: 0 },
    });
    expect(() => gosec.parse(raw, "/repo")).toThrow(/go command required, not found/);
  });

  it("accepts a valid clean report", () => {
    expect(gosec.parse(JSON.stringify({ "Golang errors": {}, Issues: [], Stats: { files: 1, lines: 8, nosec: 0, found: 0 } }), "/repo")).toEqual([]);
  });

  it("does not silence gosec diagnostics", () => {
    expect(gosec.argv("/repo")).not.toContain("-quiet");
  });
});
