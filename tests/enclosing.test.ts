import { describe, it, expect } from "vitest";
import { enclosingSymbolName } from "../src/scan.js";
import type { Sym } from "../src/lang.js";

// The shared enclosing-symbol helper (src/scan.ts) attributes a line to the
// symbol whose extent encloses it, with semantics BYTE-IDENTICAL to the engine's
// `enclosingAmong` (src/callers.ts, used by buildRawCallerIndex). This unifies
// the sink/source seed attribution in taint.ts/sinks.ts with the raw caller
// index's hop attribution, so the taint BFS's visited key `${file}#${symbol}`
// stays in one namespace. Cases: endLine present / absent / nested / out-of-extent.

const sym = (name: string, line: number, endLine?: number, kind = "function"): Sym => ({ name, kind, line, endLine, exported: true });

describe("enclosingSymbolName", () => {
  it("returns the symbol whose extent (line..endLine) covers the line", () => {
    const symbols = [sym("foo", 1, 10), sym("bar", 12, 20)];
    expect(enclosingSymbolName(symbols, 5)).toBe("foo");
    expect(enclosingSymbolName(symbols, 15)).toBe("bar");
  });

  it("returns undefined when the line is past a symbol's endLine and no other extent covers it (out-of-extent)", () => {
    const symbols = [sym("foo", 1, 10)];
    // line 15 is after foo's extent — foo does NOT enclose it, so no attribution.
    expect(enclosingSymbolName(symbols, 15)).toBeUndefined();
  });

  it("falls back to the nearest preceding definition when endLine is unknown", () => {
    const symbols = [sym("a", 1, undefined), sym("b", 10, undefined)];
    expect(enclosingSymbolName(symbols, 5)).toBe("a"); // nearest preceding
    expect(enclosingSymbolName(symbols, 12)).toBe("b");
    expect(enclosingSymbolName(symbols, 0)).toBeUndefined(); // before any def
  });

  it("picks the innermost symbol for nested extents", () => {
    const symbols = [sym("outer", 1, 30), sym("inner", 10, 20)];
    expect(enclosingSymbolName(symbols, 15)).toBe("inner"); // inside inner
    expect(enclosingSymbolName(symbols, 25)).toBe("outer"); // inside outer only
    expect(enclosingSymbolName(symbols, 5)).toBe("outer"); // before inner opens
  });

  it("prefers the tighter extent on a same-line tie (innermost wins)", () => {
    // Two symbols opening on the same line: the one with the smaller extent is
    // the innermost and must win.
    const symbols = [sym("wide", 5, 40), sym("tight", 5, 12)];
    expect(enclosingSymbolName(symbols, 8)).toBe("tight");
  });

  it("skips reference-kind symbols (reexport / reexport-all / default)", () => {
    const symbols = [sym("real", 1, 20, "function"), sym("Reexported", 5, undefined, "reexport")];
    // At line 6 the nearest preceding by raw line is the reexport, but reference
    // kinds are not definitions and must be skipped — real (extent 1..20) wins.
    expect(enclosingSymbolName(symbols, 6)).toBe("real");
  });

  it("returns undefined for an empty symbol list", () => {
    expect(enclosingSymbolName([], 5)).toBeUndefined();
  });
});
