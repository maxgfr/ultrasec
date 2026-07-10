import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { join } from "node:path";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { scanRepo } from "../src/scan.js";
import { buildGraph, reverseDependents, mergeGraphs, type Graph } from "../src/graph.js";
import { neighbors } from "../src/neighbors.js";
import { runGraph } from "../src/commands/graph.js";
import { parseArgs } from "../src/util.js";

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
    const e = graph.edges.find((x) => x.from === "src/server.js" && x.to === "src/db.js" && x.kind === "import");
    expect(e).toBeTruthy();
  });

  it("does not resolve external modules to repo files", () => {
    const toExternal = graph.edges.filter((x) => x.to === "express");
    expect(toExternal.length).toBe(0); // external imports are not file edges
  });

  it("creates a cross-file call edge (server.getUser -> db.js)", () => {
    const e = graph.edges.find((x) => x.from === "src/server.js" && x.to === "src/db.js" && x.kind === "call");
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

describe("runGraph — exit codes", () => {
  // Regression lock (eval P2.8 said these exit 0 — they exit 2 as of v1.8.0 and
  // must stay that way so a script can detect the error).
  const stderr = () => vi.spyOn(process.stderr, "write").mockImplementation(() => true);

  it("exits 2 when the <file|symbol> argument is missing", () => {
    const spy = stderr();
    expect(runGraph(parseArgs(["graph", "--repo", FIXTURE]))).toBe(2);
    spy.mockRestore();
  });

  it("exits 2 for a target that is neither a file node nor a known symbol", () => {
    const spy = stderr();
    expect(runGraph(parseArgs(["graph", "totally-unknown-thing", "--repo", FIXTURE]))).toBe(2);
    spy.mockRestore();
  });

  it("exits 0 for a resolvable file node", () => {
    const out = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    expect(runGraph(parseArgs(["graph", "src/db.js", "--repo", FIXTURE]))).toBe(0);
    out.mockRestore();
  });
});

// Regression for B2: `graph <file|symbol> --run <run>` must resolve the node from
// the RUN's graph (like every sibling command: dossier/paths/triage/verify), not
// silently ignore --run and re-scan the CWD (which then prints a misleading "not a
// file node nor a known exported symbol" error even though the run's graph.json
// lists the node).
describe("runGraph — --run resolves from the run's dossier (B2)", () => {
  let runDir: string;

  beforeAll(() => {
    runDir = mkdtempSync(join(tmpdir(), "ultrasec-graphrun-"));
    const graph = buildGraph(scanRepo(FIXTURE));
    // Minimal dossier on disk: graph command only consumes graph.json.
    writeFileSync(join(runDir, "graph.json"), JSON.stringify(graph));
    writeFileSync(join(runDir, "findings.json"), "[]");
    writeFileSync(join(runDir, "manifest.json"), JSON.stringify({ repo: FIXTURE }));
  });
  afterAll(() => rmSync(runDir, { recursive: true, force: true }));

  it("resolves a file node listed in the run's graph.json (not the CWD)", () => {
    const out = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const code = runGraph(parseArgs(["graph", "src/db.js", "--run", runDir]));
    out.mockRestore();
    err.mockRestore();
    expect(code).toBe(0);
  });

  it("resolves an exported symbol from the run's graph.json", () => {
    const out = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const code = runGraph(parseArgs(["graph", "getUser", "--run", runDir]));
    out.mockRestore();
    err.mockRestore();
    expect(code).toBe(0);
  });

  it("errors cleanly (exit 2) when --run points at a directory with no dossier", () => {
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const empty = mkdtempSync(join(tmpdir(), "ultrasec-emptyrun-"));
    const code = runGraph(parseArgs(["graph", "src/db.js", "--run", empty]));
    err.mockRestore();
    rmSync(empty, { recursive: true, force: true });
    expect(code).toBe(2);
  });
});
