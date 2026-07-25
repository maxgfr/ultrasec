import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { parseArgs, flagStr, flagBool, listFlag, own, shortHash, byStr, BOOLEAN_FLAGS } from "../src/util.js";

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

  // Regression: a value-less (boolean) flag must NOT swallow the following
  // positional — `dossier --json <id>` once parsed as { json: "<id>" } and lost
  // the id, yielding a spurious "need a <finding-id>".
  it("a boolean flag does not consume the following positional", () => {
    const a = parseArgs(["dossier", "--json", "abc123", "--run", "/r"]);
    expect(flagBool(a, "json")).toBe(true);
    expect(flagStr(a, "json")).toBeUndefined();
    expect(a._).toEqual(["dossier", "abc123"]); // the id survives as a positional
    expect(flagStr(a, "run")).toBe("/r"); // value flags still consume their value
  });

  it("a value flag still consumes its value (boolean registry is flag-scoped)", () => {
    expect(flagStr(parseArgs(["graph", "--repo", "/x", "--json"]), "repo")).toBe("/x");
    expect(flagBool(parseArgs(["graph", "--repo", "/x", "--json"]), "json")).toBe(true);
  });

  // Regression: `-h`/`-v` are documented short aliases. They were silently dropped
  // (treated as positionals), so `clean -h` skipped help and DESTRUCTIVELY ran clean.
  it("recognizes -h / -v short flags as their long aliases", () => {
    expect(flagBool(parseArgs(["clean", "-h"]), "help")).toBe(true);
    expect(parseArgs(["clean", "-h"])._).toEqual(["clean"]); // -h is a flag, not a positional → main() shows help before dispatch
    expect(flagBool(parseArgs(["-v"]), "version")).toBe(true);
  });

  it("bundles single-dash short flags (-hv → help + version)", () => {
    const a = parseArgs(["-hv"]);
    expect(flagBool(a, "help")).toBe(true);
    expect(flagBool(a, "version")).toBe(true);
  });

  it("does not treat a lone dash or a negative number as a short flag", () => {
    expect(parseArgs(["scan", "-"])._).toEqual(["scan", "-"]);
    expect(parseArgs(["x", "-1"])._).toEqual(["x", "-1"]);
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

// BOOLEAN_FLAGS declares, in a comment, that it "MUST stay in sync with every
// flag read via flagBool()". Nothing enforced that, and `no-redact` drifted out
// of the set: `logs --no-redact <dir>` swallowed the path and exited 2 (only the
// flags-last form worked). This test is that contract, executable.
describe("BOOLEAN_FLAGS covers every flagBool() call site", () => {
  const SRC = join(import.meta.dirname, "..", "src");

  const tsFiles = (dir: string): string[] =>
    readdirSync(dir).flatMap((e) => {
      const p = join(dir, e);
      if (statSync(p).isDirectory()) return e === "vendor" ? [] : tsFiles(p);
      return p.endsWith(".ts") && !p.endsWith(".d.ts") ? [p] : [];
    });

  it("has no flagBool key missing from the set", () => {
    const missing = new Map<string, string>();
    for (const file of tsFiles(SRC)) {
      for (const m of readFileSync(file, "utf8").matchAll(/flagBool\(\s*\w+\s*,\s*["']([^"']+)["']/g)) {
        const flag = m[1] ?? "";
        if (!BOOLEAN_FLAGS.has(flag)) missing.set(flag, file);
      }
    }
    expect(
      [...missing].map(([flag, file]) => `--${flag} (${file})`),
      "a flagBool() flag outside BOOLEAN_FLAGS greedily swallows the next positional",
    ).toEqual([]);
  });

  it("keeps --no-redact from swallowing the log path", () => {
    const a = parseArgs(["logs", "--no-redact", "./var/log"]);
    expect(a._).toEqual(["logs", "./var/log"]);
    expect(flagBool(a, "no-redact")).toBe(true);
  });
});
