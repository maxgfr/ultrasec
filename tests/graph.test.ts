import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph, reverseDependents, mergeGraphs, type Graph } from "../src/graph.js";
import { neighbors } from "../src/neighbors.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

describe("scanRepo", () => {
  const scan = scanRepo(FIXTURE);

  it("scans the JS source files (ignores package.json)", () => {
    const rels = scan.files.map((f) => f.rel).sort();
    expect(rels).toEqual(["src/db.js", "src/report.js", "src/server.js", "src/sqlite.js"]);
  });

  it("extracts exported function symbols", () => {
    const db = scan.files.find((f) => f.rel === "src/db.js")!;
    const names = db.symbols.map((s) => s.name).sort();
    expect(names).toContain("getUser");
    expect(names).toContain("getUserSafe");
  });

  it("extracts import specifiers", () => {
    const server = scan.files.find((f) => f.rel === "src/server.js")!;
    const specs = server.imports.map((i) => i.spec);
    expect(specs).toContain("./db");
    expect(specs).toContain("./report");
    expect(specs).toContain("express");
  });

  it("extracts call sites including the SQL sink call", () => {
    const db = scan.files.find((f) => f.rel === "src/db.js")!;
    const callees = db.calls.map((c) => c.callee);
    expect(callees).toContain("query"); // sqlite.query(sql)
  });
});

describe("buildGraph", () => {
  const graph = buildGraph(scanRepo(FIXTURE));

  it("creates resolved import edges across files", () => {
    const e = graph.edges.find(
      (x) => x.from === "src/server.js" && x.to === "src/db.js" && x.kind === "import",
    );
    expect(e).toBeTruthy();
  });

  it("does not resolve external modules to repo files", () => {
    const toExternal = graph.edges.filter((x) => x.to === "express");
    expect(toExternal.length).toBe(0); // external imports are not file edges
  });

  it("creates a cross-file call edge (server.getUser -> db.js)", () => {
    const e = graph.edges.find(
      (x) => x.from === "src/server.js" && x.to === "src/db.js" && x.kind === "call",
    );
    expect(e).toBeTruthy();
    expect(e!.toSymbol).toBe("getUser");
  });

  it("indexes unique exported symbol definitions", () => {
    expect(graph.symbolDefs["getUser"]).toEqual(["src/db.js"]);
  });

  it("builds a reverse call-index (callersBySymbol)", () => {
    const callers = graph.callersBySymbol?.["getUser"];
    expect(callers, "expected getUser to have recorded callers").toBeTruthy();
    expect(callers!.some((c) => c.file === "src/server.js")).toBe(true);
    // sorted by (file, line) for deterministic BFS order
    const sorted = callers!.slice().sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
    expect(callers).toEqual(sorted);
  });
});

describe("mergeGraphs (prototype-key safety)", () => {
  // Symbol names can collide with Object.prototype members — these must be treated
  // as data, not return inherited functions. Regression for the merge crash on a
  // `toString`/`constructor` callee.
  const mk = (over: Partial<Graph>): Graph => ({ files: [], edges: [], symbolDefs: {}, callersBySymbol: {}, ...over });

  it("merges graphs whose symbol names are Object.prototype members", () => {
    const a = mk({
      files: ["a.js"],
      symbolDefs: { toString: ["a.js"], constructor: ["a.js"] },
      callersBySymbol: { toString: [{ file: "a.js", line: 1 }], constructor: [{ file: "a.js", line: 2 }] },
    });
    const b = mk({
      files: ["b.js"],
      symbolDefs: { toString: ["b.js"] },
      callersBySymbol: { toString: [{ file: "b.js", line: 3 }] },
    });
    let merged!: Graph;
    expect(() => (merged = mergeGraphs(a, b))).not.toThrow();
    expect(merged.symbolDefs["toString"]).toEqual(["a.js", "b.js"]);
    expect(merged.callersBySymbol!["toString"]!.map((r) => r.file)).toEqual(["a.js", "b.js"]);
    expect(Array.isArray(merged.callersBySymbol!["constructor"])).toBe(true);
  });
});

describe("reverseDependents", () => {
  const graph = buildGraph(scanRepo(FIXTURE));

  it("includes the seed and files that call into it", () => {
    const deps = reverseDependents(graph, ["src/db.js"], 3);
    expect(deps).toContain("src/db.js"); // seed included
    expect(deps).toContain("src/server.js"); // server imports/calls db
  });
});

describe("neighbors", () => {
  const graph = buildGraph(scanRepo(FIXTURE));

  it("finds inbound and outbound links of db.js", () => {
    const r = neighbors(graph, "src/db.js", 1);
    const nodes = r.links.map((l) => l.node);
    expect(nodes).toContain("src/server.js"); // inbound (server imports/calls db)
    expect(nodes).toContain("src/sqlite.js"); // outbound (db imports/calls sqlite)
  });
});
