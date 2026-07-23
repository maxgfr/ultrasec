import { describe, it, expect } from "vitest";
import { resolveImport } from "../src/resolve.js";
import { neighbors } from "../src/neighbors.js";
import type { Graph } from "../src/graph.js";
import { findSources, findSanitizers } from "../src/catalog.js";
import { langForFile } from "../src/lang.js";
import { parseVerdicts } from "../src/verify.js";
import { check } from "../src/check.js";
import type { Dossier } from "../src/store.js";
import type { Finding } from "../src/types.js";

// Regression tests for the 11 bugs found by the adversarial self-review.

describe("resolve: '..' escaping the repo stays unresolvable (not collapsed)", () => {
  it("does not resolve an over-deep ../ to an in-repo file", () => {
    const files = new Set(["x.js", "a/b.js"]);
    expect(resolveImport("a/b.js", "../../../../x", files)).toBeUndefined();
    expect(resolveImport("a/b.js", "../x", files)).toBe("x.js"); // legit one still works
  });
});

describe("neighbors: inbound edge uses the CALLER symbol (fromSymbol)", () => {
  it("attributes an in-link to the calling function", () => {
    const g: Graph = {
      files: ["a.js", "b.js"],
      edges: [{ from: "b.js", to: "a.js", kind: "call", weight: 1, fromSymbol: "caller", toSymbol: "callee" }],
      symbolDefs: {},
    };
    const inLink = neighbors(g, "a.js", 1).links.find((l) => l.direction === "in")!;
    expect(inLink.symbol).toBe("caller");
  });
});

describe("catalog: HTTP source regex no longer matches a `.request` property chain", () => {
  const js = langForFile("x.js")!;
  it("ignores obj.request.query but still catches req.query", () => {
    expect(findSources(js, "const q = localStorage.request.query;").length).toBe(0);
    expect(findSources(js, "const id = req.query.id;").some((s) => s.kind === "http")).toBe(true);
  });
});

describe("catalog: .split() is no longer treated as command sanitization", () => {
  const js = langForFile("x.js")!;
  it("does not hint argv-array for a bare .split()", () => {
    expect(findSanitizers(js, "execSync('x ' + name.split(',')[0])", "command")).toEqual([]);
    expect(findSanitizers(js, "execFile('ls', args)", "command")).not.toEqual([]); // real one still hints
  });
});

describe("verify: invalid verdict values are rejected", () => {
  it("keeps only the four valid verdicts", () => {
    const v = parseVerdicts('[{"id":"a","verdict":"INVALID"},{"id":"b","verdict":"supported"}]');
    expect(v).toHaveLength(1);
    expect(v[0]!.id).toBe("b");
  });
});

describe("check: a path escaping the repo is skipped, never read or false-flagged", () => {
  function dossier(file: string): Dossier {
    const f: Finding = {
      id: "a",
      category: "taint",
      title: "t",
      severity: "high",
      confidence: "high",
      message: "m",
      tool: "ultrasec",
      status: "confirmed",
      sink: { file, line: 1 },
    };
    return {
      manifest: {
        version: "0",
        schemaVersion: 1,
        repo: "/tmp",
        generatedNote: "",
        languages: [],
        toolsRun: [],
        counts: { findings: 1, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
      },
      findings: [f],
      graph: { files: [], edges: [], symbolDefs: {} },
    };
  }
  it("does not flag an out-of-repo absolute/escape path as dangling", () => {
    expect(check(dossier("../../../../../../etc/passwd")).dangling).toHaveLength(0);
    expect(check(dossier("/etc/passwd")).dangling).toHaveLength(0);
  });
});
