import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildAssumptionWorklist } from "../src/assumptions.js";
import { worklistJson } from "../src/stage.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

describe("buildAssumptionWorklist — one unit per file, its symbols listed", () => {
  const items = buildAssumptionWorklist(scanRepo(FIXTURE));

  it("lists each file once, with `name:line` symbols, the signals and the reason written once", () => {
    expect(items.length).toBeGreaterThan(0);
    expect(new Set(items.map((i) => i.file)).size).toBe(items.length);
    for (const it of items) {
      expect(it.at).toBe(it.file);
      for (const u of it.symbols ?? []) expect(u).toMatch(/^[^:]+:\d+$/);
    }
  });

  it("writes no empty answer arrays to the file", () => {
    const raw = worklistJson(items);
    expect(raw).not.toContain('"guarantees":[]');
    expect(raw).not.toContain('"openQuestions":[]');
  });
});
