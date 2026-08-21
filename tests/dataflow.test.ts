import { describe, it, expect } from "vitest";
import { sanitizersAlongPath, traceDefUse, traceDefUseDetail, boundNames } from "../src/dataflow.js";
import type { PathStep } from "../src/types.js";

const step = (file: string, line: number): PathStep => ({ file, line, why: "" });

describe("sanitizersAlongPath", () => {
  // Looking only at the sink line — as this used to — misses the ordinary shape
  // of defensive code: sanitize on one line, use on the next. That silence reads
  // as "nothing protects this flow", the wrong prior to hand an adjudicator.
  const lines: Record<string, string[]> = {
    "a.js": [
      "function handler(req, res) {", // 1
      "  const raw = req.query.q;", // 2
      "  const safe = escapeHtml(raw);", // 3
      "  render(safe);", // 4
      "}", // 5
    ],
    "b.js": [
      "function render(v) {", // 1
      "  res.send(v);", // 2
      "}", // 3
    ],
  };
  const lineAt = (f: string, l: number) => lines[f]?.[l - 1] ?? "";

  it("finds a sanitizer written a line above the sink", () => {
    const hits = sanitizersAlongPath([step("a.js", 2), step("a.js", 4)], "xss", lineAt);
    expect(hits.map((h) => h.line)).toContain(3);
    expect(hits[0]!.note).toMatch(/escaping/);
  });

  it("finds a sanitizer at an intermediate hop in another file", () => {
    const hits = sanitizersAlongPath([step("a.js", 2), step("a.js", 3), step("b.js", 2)], "xss", lineAt);
    expect(hits.some((h) => h.file === "a.js" && h.line === 3)).toBe(true);
  });

  it("reports nothing when the path is genuinely unguarded", () => {
    const bare = { "c.js": ["exec(cmd);"] };
    expect(sanitizersAlongPath([step("c.js", 1)], "command", (_f, l) => bare["c.js"]![l - 1] ?? "")).toEqual([]);
  });

  it("only reports sanitizers matching the sink kind (plus generic validation)", () => {
    const hits = sanitizersAlongPath([step("a.js", 3)], "sql", lineAt);
    expect(hits.some((h) => /escaping/.test(h.note))).toBe(false);
  });
});

describe("traceDefUse", () => {
  it("links a value carried through renames to the sink", () => {
    const src = ["const raw = req.query.q;", "const mid = raw;", "const out = mid + '';", "exec(out);"];
    expect(traceDefUse(src, 1, "req.query", 4)).toBe("linked");
  });

  it("marks a source whose binding never reaches the sink as unlinked", () => {
    const src = ["const raw = req.query.q;", "log(raw);", "exec('uptime');"];
    expect(traceDefUse(src, 1, "req.query", 3)).toBe("unlinked");
  });

  it("treats a source used on the sink line itself as linked", () => {
    expect(traceDefUse(["exec(req.query.cmd);"], 1, "req.query", 1)).toBe("linked");
  });

  it("returns undefined — not `unlinked` — when the source is used inline elsewhere", () => {
    // Nothing is bound, so the walk has no name to follow. Undecidable must not
    // be reported as decided: `unlinked` has to mean "looked and did not find it".
    const src = ["send(req.query.q);", "exec(other);"];
    expect(traceDefUse(src, 1, "req.query", 2)).toBeUndefined();
  });

  it("handles destructuring bindings", () => {
    const src = ["const { id, name } = req.body;", "query('SELECT ' + id);"];
    expect(traceDefUse(src, 1, "req.body", 2)).toBe("linked");
  });

  it("skips a type token when a language declares one", () => {
    const src = ['String uid = req.getParameter("id");', "stmt.execute(uid);"];
    expect(traceDefUse(src, 1, "req.getParameter", 2)).toBe("linked");
  });
});

describe("boundNames", () => {
  it("takes the last identifier of a plain binding, skipping the type", () => {
    expect(boundNames("String uid")).toEqual(["uid"]);
    expect(boundNames("  const x")).toEqual(["x"]);
  });

  it("takes every identifier of a destructuring pattern", () => {
    expect(boundNames("const { id, name }")).toEqual(["id", "name"]);
  });

  it("reduces a member assignment to its property, which later mentions contain", () => {
    expect(boundNames("this.userId")).toEqual(["userId"]);
  });
});

describe("traceDefUseDetail — the names, not just the verdict", () => {
  // The verdict says "the bound value is not mentioned at the sink". The names
  // say WHICH value should have arrived, which is what turns a hint into
  // something an adjudicator can check against the code in front of them.
  it("returns the bindings the walk followed", () => {
    const src = ["const id = req.query.id;", "const q = id;", "db.query(q);"];
    const d = traceDefUseDetail(src, 1, "req.query", 3);
    expect(d.verdict).toBe("linked");
    expect(d.tainted).toEqual(["id", "q"]);
  });

  it("reports the names even when nothing reaches the sink", () => {
    const src = ["const id = req.query.id;", "db.query(other);"];
    const d = traceDefUseDetail(src, 1, "req.query", 2);
    expect(d.verdict).toBe("unlinked");
    expect(d.tainted).toEqual(["id"]);
  });

  it("agrees with traceDefUse, which now delegates to it", () => {
    const src = ["const id = req.query.id;", "const q = id;", "db.query(q);"];
    expect(traceDefUse(src, 1, "req.query", 3)).toBe(traceDefUseDetail(src, 1, "req.query", 3).verdict);
  });
});
