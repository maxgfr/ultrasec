import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";
import { buildUnitMap } from "../src/dataflow.js";
import type { Finding } from "../src/types.js";

// The BFS closes a path when it finds a source at-or-above the frame's entry
// line IN THE SAME FILE. That is positional, not structural: two unrelated
// handlers of one router used to produce a candidate indistinguishable from a
// real flow. `sourceScope` records which of the two it is.
//
// The router fixture is the load-bearing case: measured on the project's own
// fixtures an Express file extracts ZERO symbols (every handler is an anonymous
// arrow), so a symbol-name comparison cannot separate these and the unit map has
// to carry it.

const FIXTURE = join(import.meta.dirname, "fixtures", "scope");

function run(opts = {}): Finding[] {
  const scan = scanRepo(FIXTURE);
  return enumerateTaint(scan, buildGraph(scan), { maxCandidates: 10000, ...opts }).findings;
}

const cmdIn = (findings: Finding[], file: string, line: number) =>
  findings.filter((f) => f.sink?.kind === "command" && f.sink.file === file && f.sink.line === line);

describe("source scoping — same file is not the same function", () => {
  const findings = run();

  it("scopes a source and sink sharing one arrow handler as `symbol`", () => {
    // /ping: `req.query.host` and `execSync` are both inside the same closure.
    const real = cmdIn(findings, "src/router.js", 23);
    expect(real.length, "the genuine command-injection flow must be enumerated").toBeGreaterThan(0);
    expect(real.every((f) => f.sourceScope === "symbol")).toBe(true);
  });

  it("scopes a source in a DIFFERENT handler of the same file as `file`", () => {
    // /status runs a constant command; the only sources above it live in /greet.
    const colocated = cmdIn(findings, "src/router.js", 16);
    expect(colocated.length, "co-located pair is still enumerated by default (recall first)").toBeGreaterThan(0);
    expect(colocated.every((f) => f.sourceScope === "file")).toBe(true);
  });

  it("separates Python functions the same way", () => {
    const fixed = cmdIn(findings, "src/helper.py", 11);
    const user = cmdIn(findings, "src/helper.py", 16);
    expect(fixed.every((f) => f.sourceScope === "file")).toBe(true);
    expect(user.length).toBeGreaterThan(0);
    expect(user.every((f) => f.sourceScope === "symbol")).toBe(true);
  });

  it("ranks a same-function flow above a merely co-located one", () => {
    const cmd = findings.filter((f) => f.sink?.kind === "command" && f.sink.file === "src/router.js");
    const scopes = cmd.map((f) => f.sourceScope);
    expect(scopes.indexOf("symbol")).toBeLessThan(scopes.lastIndexOf("file"));
  });

  it("--strict-scope drops only the co-located pairs, never the real flow", () => {
    const strict = run({ strictScope: true });
    expect(strict.some((f) => f.sourceScope === "file")).toBe(false);
    expect(cmdIn(strict, "src/router.js", 23).length).toBeGreaterThan(0);
    expect(cmdIn(strict, "src/helper.py", 16).length).toBeGreaterThan(0);
    expect(strict.length).toBeLessThan(findings.length);
  });
});

describe("buildUnitMap", () => {
  it("attributes an anonymous arrow body to the arrow, not the file", () => {
    const src = ['app.get("/x", (req, res) => {', "  const a = req.query.a;", "  res.send(a);", "});", 'const top = "outside";'];
    const u = buildUnitMap(src, "javascript");
    expect(u.ok).toBe(true);
    expect(u.at(2)).toBe(1);
    expect(u.at(3)).toBe(1);
    expect(u.at(5)).toBe(0); // file scope
  });

  it("does not treat an if-block as a unit boundary", () => {
    const src = ["function f() {", "  const a = req.query.a;", "  if (a) {", "    exec(a);", "  }", "}"];
    const u = buildUnitMap(src, "javascript");
    expect(u.at(2)).toBe(u.at(4)); // same function despite the nested block
  });

  it("treats two methods of one class as separate units", () => {
    const src = ["class C {", "  a() {", "    const x = req.query.x;", "  }", "  b() {", "    exec('ls');", "  }", "}"];
    const u = buildUnitMap(src, "javascript");
    expect(u.at(3)).not.toBe(u.at(6));
  });

  it("refuses to guess when braces inside strings desynchronize the count", () => {
    // The closing brace is real; the one in the string must not be counted.
    const src = ["function f() {", '  const t = "}{";', "}"];
    const u = buildUnitMap(src, "javascript");
    expect(u.ok).toBe(true);
    expect(u.at(2)).toBe(1);
  });

  it("reports `ok: false` rather than a wrong map on an unbalanced file", () => {
    const u = buildUnitMap(["function f() {", "  x();"], "javascript");
    expect(u.ok).toBe(false);
  });

  it("has no block model for shell, and says so", () => {
    expect(buildUnitMap(["a=1"], "shell").ok).toBe(false);
  });
});
