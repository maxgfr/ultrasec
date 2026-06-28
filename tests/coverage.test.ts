import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";
import { findSinks } from "../src/catalog.js";
import { langForFile } from "../src/lang.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-extra");

describe("WS6 broadened catalog", () => {
  const js = langForFile("app.js")!;

  it("recognises a receiver-gated NoSQL sink (db.find)", () => {
    const hits = findSinks(js, [{ callee: "find", receiver: "db", line: 1 }]);
    expect(hits.some((h) => h.kind === "nosql" && h.cwe === "CWE-943")).toBe(true);
  });

  it("does NOT flag Array.prototype.find (different receiver)", () => {
    const hits = findSinks(js, [{ callee: "find", receiver: "arr", line: 1 }]);
    expect(hits.some((h) => h.kind === "nosql")).toBe(false);
  });

  it("recognises prototype pollution (_.merge) but not a plain merge()", () => {
    expect(findSinks(js, [{ callee: "merge", receiver: "_", line: 1 }]).some((h) => h.kind === "proto")).toBe(true);
    expect(findSinks(js, [{ callee: "merge", receiver: "cfg", line: 1 }]).some((h) => h.kind === "proto")).toBe(false);
  });

  it("recognises XXE and SSTI sinks", () => {
    expect(findSinks(js, [{ callee: "parseFromString", line: 1 }]).some((h) => h.kind === "xxe")).toBe(true);
    expect(findSinks(js, [{ callee: "from_string", line: 1 }]).some((h) => h.kind === "ssti")).toBe(true);
  });

  it("enumerates NoSQL + prototype-pollution candidates end-to-end", () => {
    const scan = scanRepo(FIXTURE);
    const { findings } = enumerateTaint(scan, buildGraph(scan));
    expect(
      findings.some((f) => f.cwe === "CWE-943"),
      "expected a NoSQL candidate",
    ).toBe(true);
    expect(
      findings.some((f) => f.cwe === "CWE-1321"),
      "expected a prototype-pollution candidate",
    ).toBe(true);
  });
});
