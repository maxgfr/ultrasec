import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildAttackSurface, isTestHarness, renderMapMd } from "../src/map.js";

// On a Next.js monorepo the map's "sql ×434" was almost entirely Testing Library
// `ui.x.query()` calls, `jest.setup.js` and e2e specs led the entry-point list,
// and a test-only directory could outrank the app as a suggested target. A test
// harness is not the shipped artifact: it stays counted (and marked) but ranks
// last and never decides which target to scan first.

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "ultrasec-map-harness-"));
  mkdirSync(join(dir, "app"), { recursive: true });
  mkdirSync(join(dir, "tests"), { recursive: true });
  writeFileSync(
    join(dir, "app", "server.js"),
    [
      'const express = require("express");',
      'const db = require("./db");',
      "const app = express();",
      'app.get("/u", (req, res) => db.query("SELECT * FROM u WHERE id=" + req.query.id));',
      "",
    ].join("\n"),
  );
  const many = Array.from({ length: 12 }, (_, i) => `test("t${i}", () => db.query(req.query.x${i}));`).join("\n");
  writeFileSync(join(dir, "tests", "server.test.js"), `const db = require("../app/db");\nconst req = { query: {} };\n${many}\n`);
  writeFileSync(join(dir, "jest.setup.js"), "window.localStorage.setItem('a', location.search);\n");
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("isTestHarness", () => {
  it("covers test files and test-runner config/setup files", () => {
    for (const p of [
      "src/__tests__/a.test.ts",
      "jest.setup.js",
      "packages/fe/jest.config.cjs",
      "playwright.rgaa.config.ts",
      "vitest.config.ts",
      "src/e2e/x.e2e.ts",
    ]) {
      expect(isTestHarness(p), p).toBe(true);
    }
    for (const p of ["src/server.js", "app/api/route.ts", "src/setup.ts", "next.config.mjs"]) expect(isTestHarness(p), p).toBe(false);
  });
});

describe("map keeps the test harness counted but out of the lead", () => {
  it("never suggests a test-only directory ahead of shipped code", () => {
    const s = buildAttackSurface(scanRepo(dir));
    expect(s.suggestedTargets[0]!.scope).toBe("app");
  });

  it("samples shipped files first and reports how many hits are in tests", () => {
    const s = buildAttackSurface(scanRepo(dir));
    const sql = s.sinks.find((k) => k.kind === "sql")!;
    expect(sql.samples[0]!.file).toBe("app/server.js");
    expect(sql.testCount).toBe(12);
    expect(sql.count).toBe(13);
  });

  it("says so in the Markdown", () => {
    const md = renderMapMd(dir, buildAttackSurface(scanRepo(dir)));
    expect(md).toMatch(/×13 \(12 in test files\)/);
  });
});
