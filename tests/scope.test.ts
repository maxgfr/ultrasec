import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

describe("scanRepo scoping", () => {
  it("scope limits the scan to a subdirectory", () => {
    const scan = scanRepo(FIXTURE, { scope: ["src"] });
    expect(scan.files.length).toBeGreaterThan(0);
    expect(scan.files.every((f) => f.rel.startsWith("src/"))).toBe(true);
  });

  it("an exact file path as scope matches just that file (the --diff mechanism)", () => {
    const scan = scanRepo(FIXTURE, { scope: ["src/db.js"] });
    expect(scan.files.map((f) => f.rel)).toEqual(["src/db.js"]);
  });

  it("exclude drops matching files", () => {
    const scan = scanRepo(FIXTURE, { exclude: ["**/report.js"] });
    const rels = scan.files.map((f) => f.rel);
    expect(rels).not.toContain("src/report.js");
    expect(rels).toContain("src/db.js");
  });

  it("max-files truncation is reported on the scan", () => {
    const scan = scanRepo(FIXTURE, { maxFiles: 1 });
    expect(scan.truncated).toBe(true);
    expect(scan.files.length).toBeLessThanOrEqual(1);
  });
});
