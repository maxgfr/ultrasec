import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";

// A test file is not an attack surface: nobody sends it a request.
//
// Indexing `__tests__/service.test.ts` as an entry point produced **46 of 63**
// taint candidates on one real audit (73 %), zero confirmed — including 37
// SQL-injection candidates in a repo with no SQL database, 22 of them from a
// single `.test.tsx`. `noise.ts` demoted them, but only AFTER they were
// enumerated, ranked, capped, written into the worklist and adjudicated.

function repoWith(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-testsurface-"));
  for (const [rel, body] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, body);
  }
  return dir;
}

const REPO = {
  // Same shape twice: once in the shipped app, once in the harness.
  "src/handler.js": `const db = require("./db");
export function handler(req, res) {
  res.end(db.query("SELECT * FROM t WHERE id = " + req.query.id));
}
`,
  "src/db.js": `export function query(sql) {\n  return runRaw(sql);\n}\n`,
  "src/__tests__/handler.test.js": `const db = require("../db");
test("it queries", () => {
  const req = { query: { id: "1" } };
  db.query("SELECT * FROM t WHERE id = " + req.query.id);
});
`,
};

const candidates = (includeTests: boolean) => {
  const scan = scanRepo(repoWith(REPO));
  return enumerateTaint(scan, buildGraph(scan), { maxDepth: 8, maxCandidates: 1000, includeTests }).findings;
};

describe("the test harness is not an entry point", () => {
  it("does not root a taint path in a test file", () => {
    const sources = candidates(false).map((f) => f.source?.file ?? "");
    expect(sources.some((s) => s.includes("__tests__"))).toBe(false);
  });

  it("still finds the same flow in the shipped code", () => {
    const shipped = candidates(false).filter((f) => f.source?.file === "src/handler.js");
    expect(shipped.length).toBeGreaterThan(0);
  });

  it("--include-tests restores the harness as surface, for auditing the harness", () => {
    const withTests = candidates(true).map((f) => f.source?.file ?? "");
    expect(withTests.some((s) => s.includes("__tests__"))).toBe(true);
  });
});
