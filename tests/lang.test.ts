import { describe, it, expect } from "vitest";
import { LANGS, langForFile, extract } from "../src/lang.js";

describe("lang registry breadth", () => {
  it("covers ~15 language groups", () => {
    expect(LANGS.length).toBeGreaterThanOrEqual(15);
  });

  it("maps common extensions to languages", () => {
    expect(langForFile("a/b.py")?.id).toBe("python");
    expect(langForFile("a/b.go")?.id).toBe("go");
    expect(langForFile("a/b.tsx")?.id).toBe("javascript");
    expect(langForFile("a/b.rs")?.id).toBe("rust");
    expect(langForFile("a/b.rb")?.id).toBe("ruby");
    expect(langForFile("a/b.php")?.id).toBe("php");
    expect(langForFile("a/README.md")).toBeUndefined();
  });
});

describe("extract (python)", () => {
  const py = langForFile("x.py")!;
  const { symbols, imports, calls } = extract(
    py,
    [
      "import os",
      "from flask import request",
      "def handle(req):",
      "    name = request.args.get('n')",
      "    return os.system('echo ' + name)",
      "def _private():",
      "    pass",
    ].join("\n"),
  );

  it("finds defs and marks underscore-private as not exported", () => {
    const handle = symbols.find((s) => s.name === "handle")!;
    expect(handle.exported).toBe(true);
    expect(symbols.find((s) => s.name === "_private")!.exported).toBe(false);
  });

  it("finds imports", () => {
    expect(imports.map((i) => i.spec)).toEqual(expect.arrayContaining(["os", "flask"]));
  });

  it("finds the os.system sink call with its receiver", () => {
    const sys = calls.find((c) => c.callee === "system")!;
    expect(sys.receiver).toBe("os");
  });
});

describe("def lines are not mistaken for calls", () => {
  it("does not extract a call from `function query(...)`", () => {
    const js = langForFile("x.js")!;
    const { calls, symbols } = extract(js, "function query(sql, params) {\n  return db.run(sql);\n}");
    expect(symbols.some((s) => s.name === "query")).toBe(true);
    expect(calls.some((c) => c.callee === "query" && !c.receiver)).toBe(false);
    expect(calls.some((c) => c.callee === "run")).toBe(true); // real call kept
  });

  it("does not extract a call from python `def handle(req):`", () => {
    const py = langForFile("x.py")!;
    const { calls } = extract(py, "def handle(req):\n    return run(req)");
    expect(calls.some((c) => c.callee === "handle")).toBe(false);
    expect(calls.some((c) => c.callee === "run")).toBe(true);
  });
});

describe("extract (js) export rule — precomputed CJS export region", () => {
  const js = langForFile("x.js")!;

  it("marks ESM-exported and CJS-exported symbols, leaving private ones unexported", () => {
    const { symbols } = extract(
      js,
      [
        "export function pub(a) { return a; }",
        "function helper() {}",
        "function shipped() {}",
        "function alsoShipped() {}",
        "module.exports = { shipped, alsoShipped };",
        "function viaExports() {}",
        "exports.viaExports = viaExports;",
      ].join("\n"),
    );
    const exp = (n: string) => symbols.find((s) => s.name === n)?.exported;
    expect(exp("pub")).toBe(true); // ESM export on the def line
    expect(exp("shipped")).toBe(true); // module.exports = { shipped }
    expect(exp("alsoShipped")).toBe(true);
    expect(exp("viaExports")).toBe(true); // exports.viaExports =
    expect(exp("helper")).toBe(false); // never exported
  });

  it("does not export a name that only appears before the exports marker on a line", () => {
    // The old whole-file regex required the name to appear AFTER `exports` on the
    // same line; the precomputed region preserves that exact semantic.
    const { symbols } = extract(js, ["function before() {}", "before(); // exports happen elsewhere", "module.exports = {};"].join("\n"));
    expect(symbols.find((s) => s.name === "before")?.exported).toBe(false);
  });
});

describe("extract — pathologically long (minified) lines are skipped", () => {
  const js = langForFile("x.js")!;
  it("ignores defs/calls on a >2000-char line without hanging", () => {
    const longLine = `var x = "${"a".repeat(5000)}"; function buried() {} db.query(buried);`;
    const src = ["function realDef() {}", longLine, "realDef();"].join("\n");
    const { symbols, calls } = extract(js, src);
    expect(symbols.some((s) => s.name === "realDef")).toBe(true);
    expect(symbols.some((s) => s.name === "buried")).toBe(false); // on the skipped line
    expect(calls.some((c) => c.callee === "query")).toBe(false); // on the skipped line
  });
});

describe("extract (go) export rule = capitalized", () => {
  const go = langForFile("x.go")!;
  const { symbols } = extract(go, ["func Handler(w, r) {", "}", "func helper() {", "}"].join("\n"));
  it("marks Capitalized funcs exported, lowercase unexported", () => {
    expect(symbols.find((s) => s.name === "Handler")!.exported).toBe(true);
    expect(symbols.find((s) => s.name === "helper")!.exported).toBe(false);
  });
});
