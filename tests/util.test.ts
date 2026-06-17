import { describe, it, expect } from "vitest";
import { parseArgs, flagStr, flagBool, listFlag, own, shortHash, byStr } from "../src/util.js";

describe("parseArgs", () => {
  it("collects positionals", () => {
    expect(parseArgs(["scan", "x", "y"])._).toEqual(["scan", "x", "y"]);
  });

  it("parses --flag value", () => {
    const a = parseArgs(["scan", "--repo", "/tmp/x"]);
    expect(a._).toEqual(["scan"]);
    expect(flagStr(a, "repo")).toBe("/tmp/x");
  });

  it("parses --flag=value", () => {
    expect(flagStr(parseArgs(["--out=/tmp/o"]), "out")).toBe("/tmp/o");
  });

  it("treats a flag with no value as boolean", () => {
    const a = parseArgs(["tools", "--json"]);
    expect(flagBool(a, "json")).toBe(true);
    expect(flagStr(a, "json")).toBeUndefined();
  });

  it("treats a flag followed by another flag as boolean", () => {
    const a = parseArgs(["--json", "--out", "/x"]);
    expect(flagBool(a, "json")).toBe(true);
    expect(flagStr(a, "out")).toBe("/x");
  });

  it("flagBool accepts explicit =true", () => {
    expect(flagBool(parseArgs(["--semantic=true"]), "semantic")).toBe(true);
  });

  it("accumulates a repeated flag instead of last-wins (listFlag merges)", () => {
    const a = parseArgs(["scan", "--scope", "a", "--scope", "b", "--scope", "c,d"]);
    expect(listFlag(a, "scope")).toEqual(["a", "b", "c", "d"]);
    expect(flagStr(a, "scope")).toBe("c,d"); // single-value consumers get the last
  });

  it("is prototype-safe: a flag named like a prototype member is not inherited", () => {
    const a = parseArgs(["scan"]);
    expect(flagStr(a, "constructor")).toBeUndefined();
    expect(flagBool(a, "toString")).toBe(false);
    expect(listFlag(a, "hasOwnProperty")).toBeUndefined();
  });
});

describe("own", () => {
  it("returns own values but never inherited prototype members", () => {
    const m = { high: 0.8 } as Record<string, number>;
    expect(own(m, "high")).toBe(0.8);
    expect(own(m, "missing")).toBeUndefined();
    expect(own(m, "constructor")).toBeUndefined(); // would be a function on a raw lookup
    expect(own(m, "toString")).toBeUndefined();
    expect(own(undefined, "x")).toBeUndefined();
  });
});

describe("shortHash", () => {
  it("is deterministic and length-bounded", () => {
    expect(shortHash("abc")).toBe(shortHash("abc"));
    expect(shortHash("abc")).toHaveLength(12);
    expect(shortHash("abc", 8)).toHaveLength(8);
  });

  it("differs for different input", () => {
    expect(shortHash("a")).not.toBe(shortHash("b"));
  });
});

describe("byStr", () => {
  it("orders deterministically", () => {
    expect(["c", "a", "b"].sort(byStr)).toEqual(["a", "b", "c"]);
  });
});
