import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";
import { findSinks, findSources } from "../src/catalog.js";
import { langForFile } from "../src/lang.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

describe("catalog", () => {
  it("recognizes the SQL and command sinks in the fixture", () => {
    const db = langForFile("db.js")!;
    const sinks = findSinks(db, [{ callee: "query", receiver: "sqlite", line: 6 }]);
    expect(sinks.some((s) => s.kind === "sql")).toBe(true);
  });

  it("recognizes req.query as an HTTP source", () => {
    const js = langForFile("server.js")!;
    const src = findSources(js, "const id = req.query.id;");
    expect(src.some((s) => s.kind === "http")).toBe(true);
  });
});

describe("enumerateTaint (cross-file)", () => {
  const scan = scanRepo(FIXTURE);
  const graph = buildGraph(scan);
  const { findings } = enumerateTaint(scan, graph);

  it("finds a cross-file SQL injection: server.js req.query -> db.js query()", () => {
    const sqli = findings.find((f) => f.cwe === "CWE-89");
    expect(sqli, "expected a CWE-89 finding").toBeTruthy();
    expect(sqli!.source!.file).toBe("src/server.js");
    expect(sqli!.sink!.file).toBe("src/db.js");
    expect(sqli!.path!.length).toBeGreaterThanOrEqual(3); // source -> call hop -> sink
    // the path crosses files
    const files = new Set(sqli!.path!.map((p) => p.file));
    expect(files.size).toBeGreaterThanOrEqual(2);
  });

  it("finds a cross-file command injection: server.js req.query -> report.js execSync", () => {
    const cmd = findings.find((f) => f.cwe === "CWE-78");
    expect(cmd, "expected a CWE-78 finding").toBeTruthy();
    expect(cmd!.sink!.file).toBe("src/report.js");
    expect(cmd!.source!.file).toBe("src/server.js");
  });

  it("does NOT flag getUserSafe (no source reaches it)", () => {
    // the parameterized query is on db.js line 11; no candidate path should end there
    expect(findings.some((f) => f.sink!.file === "src/db.js" && f.sink!.line === 11)).toBe(false);
  });

  it("does not invent a sink at a function-definition line (sqlite.js:2)", () => {
    // `function query(...)` must not be treated as a query() call/sink.
    expect(findings.some((f) => f.sink!.file === "src/sqlite.js")).toBe(false);
    const sqli = findings.find((f) => f.cwe === "CWE-89")!;
    expect(sqli.sink!.line).toBe(6); // the real concatenated query in getUser
  });

  it("candidate findings start as open, low-confidence taint findings", () => {
    for (const f of findings) {
      expect(f.category).toBe("taint");
      expect(f.status).toBe("open");
      expect(f.tool).toBe("ultrasec");
    }
  });
});

describe("enumerateTaint (budget-aware ranking + no silent caps)", () => {
  const scan = scanRepo(FIXTURE);
  const graph = buildGraph(scan);

  it("reports total and zero truncation under the default cap", () => {
    const r = enumerateTaint(scan, graph);
    expect(r.truncated).toBe(0);
    expect(r.total).toBe(r.findings.length);
    expect(r.total).toBeGreaterThanOrEqual(2);
  });

  it("rank-then-cap keeps the highest-ranked candidate and reports the remainder", () => {
    const full = enumerateTaint(scan, graph);
    const capped = enumerateTaint(scan, graph, { maxCandidates: 1 });
    expect(capped.findings.length).toBe(1);
    expect(capped.total).toBe(full.total);
    expect(capped.truncated).toBe(full.total - 1);
    // critical command-injection outranks the high SQLi → it survives the cap
    expect(capped.findings[0]!.severity).toBe("critical");
    expect(capped.findings[0]!.cwe).toBe("CWE-78");
  });

  it("maxDepth=0 yields no cross-file candidates (depth gate is honoured)", () => {
    const r = enumerateTaint(scan, graph, { maxDepth: 0 });
    // with no backward hops, a sink can only close on a source in its own file
    expect(r.findings.every((f) => new Set(f.path!.map((p) => p.file)).size === 1)).toBe(true);
  });
});
