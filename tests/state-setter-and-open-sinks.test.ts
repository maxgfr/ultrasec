import { describe, it, expect } from "vitest";
import { findSinks } from "../src/catalog.js";
import { langForFile } from "../src/lang.js";

// Two generic callees claimed far more than their sink. On a Next.js app with
// zustand stores, `set(produce((state) => …))` — the store setter — produced 200
// high-severity "prototype pollution" candidates; `modal.open()` and a hook's
// `open(Trigger.EXIT_INTENT)` were filed as path traversal. The fix gates each
// callee on the evidence that it is the dangerous API: a deep-path setter library
// for `set`, the filesystem module for JavaScript's `open`.

const js = langForFile("x.js")!;
const py = langForFile("x.py")!;
const kinds = (hits: ReturnType<typeof findSinks>) => hits.map((h) => h.kind);

describe("set() is prototype pollution only when it is a deep-path setter", () => {
  it("ignores the zustand/immer store setter", () => {
    const imports = [{ spec: "zustand" }, { spec: "immer" }];
    expect(kinds(findSinks(js, [{ callee: "set", receiver: undefined, line: 1 }], undefined, imports))).not.toContain("proto");
  });

  it("still fires on lodash / set-value / dot-prop setters", () => {
    for (const spec of ["lodash", "lodash.set", "lodash-es", "set-value", "dot-prop", "object-path"]) {
      expect(kinds(findSinks(js, [{ callee: "set", receiver: undefined, line: 1 }], undefined, [{ spec }])), spec).toContain("proto");
    }
    expect(kinds(findSinks(js, [{ callee: "set", receiver: "_", line: 1 }], undefined, [{ spec: "lodash" }]))).toContain("proto");
    expect(kinds(findSinks(js, [{ callee: "setWith", receiver: "_", line: 1 }], undefined, [{ spec: "lodash" }]))).toContain("proto");
  });

  it("keeps firing when imports were not extracted (regex tier)", () => {
    expect(kinds(findSinks(js, [{ callee: "set", receiver: "_", line: 1 }], undefined, []))).toContain("proto");
  });

  it("leaves the deep-merge callees as they were", () => {
    const imports = [{ spec: "zustand" }];
    expect(kinds(findSinks(js, [{ callee: "merge", receiver: "_", line: 1 }], undefined, imports))).toContain("proto");
    expect(kinds(findSinks(js, [{ callee: "defaultsDeep", receiver: undefined, line: 1 }], undefined, imports))).toContain("proto");
  });
});

describe("JavaScript open() is a path sink only on the filesystem module", () => {
  it("ignores a modal / hook open()", () => {
    const imports = [{ spec: "react" }, { spec: "@codegouvfr/react-dsfr/Modal" }];
    expect(kinds(findSinks(js, [{ callee: "open", receiver: "modal13Matieres", line: 1 }], undefined, imports))).not.toContain("path");
    expect(kinds(findSinks(js, [{ callee: "open", receiver: undefined, line: 1 }], undefined, imports))).not.toContain("path");
  });

  it("still fires on fs.open / fs/promises open", () => {
    expect(kinds(findSinks(js, [{ callee: "open", receiver: "fs", line: 1 }], undefined, [{ spec: "fs" }]))).toContain("path");
    expect(kinds(findSinks(js, [{ callee: "open", receiver: undefined, line: 1 }], undefined, [{ spec: "node:fs/promises" }]))).toContain("path");
    expect(kinds(findSinks(js, [{ callee: "open", receiver: "fsp", line: 1 }], undefined, [{ spec: "fs-extra" }]))).toContain("path");
  });

  it("keeps window.open on the open-redirect rule", () => {
    expect(kinds(findSinks(js, [{ callee: "open", receiver: "window", line: 1 }], undefined, [{ spec: "react" }]))).toContain("redirect");
  });

  it("leaves Python's builtin open() a path sink", () => {
    expect(kinds(findSinks(py, [{ callee: "open", receiver: undefined, line: 1 }], undefined, [{ spec: "os" }]))).toContain("path");
  });

  it("keeps the other JavaScript path callees untouched", () => {
    expect(kinds(findSinks(js, [{ callee: "readFileSync", receiver: "fs", line: 1 }], undefined, [{ spec: "react" }]))).toContain("path");
  });
});
