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

describe("extract (go) export rule = capitalized", () => {
  const go = langForFile("x.go")!;
  const { symbols } = extract(go, ["func Handler(w, r) {", "}", "func helper() {", "}"].join("\n"));
  it("marks Capitalized funcs exported, lowercase unexported", () => {
    expect(symbols.find((s) => s.name === "Handler")!.exported).toBe(true);
    expect(symbols.find((s) => s.name === "helper")!.exported).toBe(false);
  });
});
