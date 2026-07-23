import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LANGS, langForFile } from "../src/lang.js";
import { scanRepo, recordToFileScan } from "../src/scan.js";
import type { FileRecord } from "../src/vendor/codeindex-engine.mjs";

describe("lang registry breadth", () => {
  it("covers ~15 language groups", () => {
    expect(LANGS.length).toBeGreaterThanOrEqual(15);
  });

  it("maps common extensions to ultrasec language ids", () => {
    expect(langForFile("a/b.py")?.id).toBe("python");
    expect(langForFile("a/b.go")?.id).toBe("go");
    // .ts/.tsx collapse to the ultrasec "javascript" id (the engine calls them
    // "typescript" — the catalogs gate on the ultrasec id, so this must not leak).
    expect(langForFile("a/b.tsx")?.id).toBe("javascript");
    expect(langForFile("a/b.ts")?.id).toBe("javascript");
    expect(langForFile("a/b.rs")?.id).toBe("rust");
    expect(langForFile("a/b.rb")?.id).toBe("ruby");
    expect(langForFile("a/b.php")?.id).toBe("php");
    expect(langForFile("a/b.cpp")?.id).toBe("c_cpp");
    expect(langForFile("a/README.md")).toBeUndefined();
  });
});

// ── The engine → FileScan adapter (the load-bearing seam) ────────────────────
describe("recordToFileScan: engine FileRecord → ultrasec FileScan", () => {
  const base: FileRecord = {
    rel: "src/a.ts",
    ext: ".ts",
    size: 0,
    lines: 10,
    hash: "h",
    kind: "code",
    lang: "typescript", // engine label…
    headings: [],
    symbols: [
      { name: "handle", kind: "function", file: "src/a.ts", line: 2, endLine: 5, exported: true, lang: "typescript" },
      { name: "_priv", kind: "method", file: "src/a.ts", line: 6, exported: false, lang: "typescript" },
    ],
    refs: [
      { kind: "import", spec: "./util" },
      { kind: "doc-link", spec: "../README.md" }, // must be filtered out
    ],
    calls: [
      { name: "query", line: 4, receiver: "db" },
      { name: "trim", line: 7 }, // no receiver
    ],
  };

  it("uses the ultrasec language id, not the engine's", () => {
    expect(recordToFileScan(base)!.lang).toBe("javascript"); // …not "typescript"
  });

  it("maps calls name→callee, keeping receiver and line", () => {
    const { calls } = recordToFileScan(base)!;
    expect(calls).toEqual([
      { callee: "query", receiver: "db", line: 4 },
      { callee: "trim", receiver: undefined, line: 7 },
    ]);
  });

  it("passes symbol endLine through faithfully (undefined stays undefined)", () => {
    const { symbols } = recordToFileScan(base)!;
    expect(symbols[0]).toEqual({ name: "handle", kind: "function", line: 2, endLine: 5, exported: true });
    expect(symbols[1]!.endLine).toBeUndefined();
  });

  it("carries the engine's richer symbol kinds through unchanged", () => {
    expect(recordToFileScan(base)!.symbols[1]!.kind).toBe("method");
  });

  it("keeps only import refs, and only their specifier (no line)", () => {
    const { imports } = recordToFileScan(base)!;
    expect(imports).toEqual([{ spec: "./util" }]);
    expect(imports[0]).not.toHaveProperty("line");
  });

  it("drops a record whose extension ultrasec does not reason about", () => {
    expect(recordToFileScan({ ...base, rel: "a/README.md", ext: ".md" })).toBeUndefined();
  });
});

// ── End-to-end: a real scan exercises the engine + adapter together ───────────
describe("scanRepo adapter (real engine extraction)", () => {
  let repo: string;
  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), "ultrasec-adapter-"));
    mkdirSync(join(repo, "src"), { recursive: true });
    writeFileSync(
      join(repo, "src", "a.ts"),
      ['import { helper } from "./util";', "export function handle(req) {", "  const x = req.query.q;", '  return db.query("SELECT " + x);', "}"].join("\n"),
    );
    writeFileSync(join(repo, "src", "svc.py"), ["import os", "def run(name):", "    return os.system(name)"].join("\n"));
  });
  afterAll(() => rmSync(repo, { recursive: true, force: true }));

  it("labels a .ts file javascript and a .py file python", () => {
    const scan = scanRepo(repo);
    expect(scan.files.find((f) => f.rel === "src/a.ts")!.lang).toBe("javascript");
    expect(scan.files.find((f) => f.rel === "src/svc.py")!.lang).toBe("python");
  });

  it("extracts the db.query call with its receiver and line", () => {
    const scan = scanRepo(repo);
    const q = scan.files.find((f) => f.rel === "src/a.ts")!.calls.find((c) => c.callee === "query")!;
    expect(q.receiver).toBe("db");
    expect(q.line).toBe(4);
  });

  it("extracts os.system in python with its receiver", () => {
    const scan = scanRepo(repo);
    const sys = scan.files.find((f) => f.rel === "src/svc.py")!.calls.find((c) => c.callee === "system")!;
    expect(sys.receiver).toBe("os");
  });

  it("surfaces imports as specifier-only", () => {
    const scan = scanRepo(repo);
    const imps = scan.files.find((f) => f.rel === "src/a.ts")!.imports;
    expect(imps.map((i) => i.spec)).toContain("./util");
    for (const i of imps) expect(Object.keys(i)).toEqual(["spec"]);
  });

  it("exposes the raw engine scan on the RepoScan (non-serialized input for downstream)", () => {
    const scan = scanRepo(repo);
    expect(scan.engine).toBeDefined();
    expect(scan.engine!.files.length).toBeGreaterThanOrEqual(2);
  });
});
