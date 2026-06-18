import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { walk, walkWithMeta, globToRe, parseGitignore } from "../src/walk.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

describe("globToRe", () => {
  it("`src/**` matches files under src only", () => {
    const re = globToRe("src/**");
    expect(re.test("src/a.js")).toBe(true);
    expect(re.test("src/x/y.js")).toBe(true);
    expect(re.test("lib/a.js")).toBe(false);
  });

  it("`**/*.js` matches a .js at any depth incl. root", () => {
    const re = globToRe("**/*.js");
    expect(re.test("a.js")).toBe(true);
    expect(re.test("x/y/a.js")).toBe(true);
    expect(re.test("a.ts")).toBe(false);
  });

  it("`*.js` is anchored to the root segment", () => {
    const re = globToRe("*.js");
    expect(re.test("a.js")).toBe(true);
    expect(re.test("src/a.js")).toBe(false);
  });

  it("trailing slash matches the dir and everything under it", () => {
    const re = globToRe("dist/");
    expect(re.test("dist")).toBe(true);
    expect(re.test("dist/bundle.js")).toBe(true);
    expect(re.test("distant/x")).toBe(false);
  });

  it("`?` matches a single non-slash char", () => {
    const re = globToRe("a?.js");
    expect(re.test("ab.js")).toBe(true);
    expect(re.test("a/.js")).toBe(false);
  });

  it("supports [...] character classes (incl. negation), not literal escaping", () => {
    const cls = globToRe("**/*.[oa]");
    expect(cls.test("x.o")).toBe(true);
    expect(cls.test("x.a")).toBe(true);
    expect(cls.test("x.c")).toBe(false);
    const neg = globToRe("file[!0-9].js");
    expect(neg.test("filea.js")).toBe(true);
    expect(neg.test("file1.js")).toBe(false);
  });

  it("is TOTAL: a malformed class (reversed range) never throws", () => {
    expect(() => globToRe("[z-a].js")).not.toThrow();
    expect(() => globToRe("[9-0]*")).not.toThrow();
    expect(() => globToRe("[")).not.toThrow();
    // a valid pattern after the bad one still compiles normally
    expect(globToRe("**/*.js").test("a/b.js")).toBe(true);
  });

  it("handles an escaped ] as a class member, not the terminator", () => {
    const re = globToRe("[a\\]b].js");
    expect(re.test("a.js")).toBe(true);
    expect(re.test("].js")).toBe(true);
    expect(re.test("b.js")).toBe(true);
    expect(re.test("c.js")).toBe(false);
  });
});

describe("walk (defaults, backward-compatible)", () => {
  it("lists every file (no language filter)", () => {
    const rels = walk(FIXTURE).map((f) => f.rel);
    expect(rels).toEqual([
      "package.json",
      "src/db.js",
      "src/report.js",
      "src/server.js",
      "src/sqlite.js",
    ]);
  });

  it("is deterministic across runs", () => {
    expect(walk(FIXTURE).map((f) => f.rel)).toEqual(walk(FIXTURE).map((f) => f.rel));
  });
});

describe("walk (scope / include / exclude)", () => {
  it("scope prunes to a subdirectory", () => {
    const rels = walk(FIXTURE, { scope: ["src"] }).map((f) => f.rel);
    expect(rels.every((r) => r.startsWith("src/"))).toBe(true);
    expect(rels).not.toContain("package.json");
  });

  it("include keeps only matching globs", () => {
    const rels = walk(FIXTURE, { include: ["**/*.js"] }).map((f) => f.rel);
    expect(rels).not.toContain("package.json");
    expect(rels).toContain("src/db.js");
  });

  it("exclude drops matching files", () => {
    const rels = walk(FIXTURE, { exclude: ["**/report.js"] }).map((f) => f.rel);
    expect(rels).not.toContain("src/report.js");
    expect(rels).toContain("src/db.js");
  });
});

describe("walk (maxFiles truncation)", () => {
  it("stops at maxFiles and reports truncated", () => {
    const r = walkWithMeta(FIXTURE, { maxFiles: 2 });
    expect(r.files.length).toBe(2);
    expect(r.truncated).toBe(true);
    expect(r.totalSeen).toBe(2);
  });

  it("does not flag truncation when under the cap", () => {
    const r = walkWithMeta(FIXTURE, { maxFiles: 1000 });
    expect(r.truncated).toBe(false);
  });
});

describe("gitignore", () => {
  const tmp = mkdtempSync(join(tmpdir(), "ultrasec-walk-"));
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  it("parses ordered rules: dir-only stays dir-only, negations carry a flag", () => {
    const rules = parseGitignore("# comment\nsecret.txt\nbuildlogs/\n!keep.js\n");
    const globs = rules.map((r) => r.glob);
    expect(globs).toContain("**/secret.txt"); // file → bare form
    expect(globs).toContain("**/buildlogs/"); // dir-only → dir form
    expect(globs).not.toContain("**/buildlogs"); // …but NOT the bare-file form
    expect(rules.some((r) => r.glob.includes("keep.js") && r.negated)).toBe(true); // negation captured, not dropped
  });

  it("honours last-match-wins: a later exclude re-overrides an earlier negation", () => {
    const t = mkdtempSync(join(tmpdir(), "ultrasec-order-"));
    writeFileSync(join(t, "keep.log"), "x");
    writeFileSync(join(t, ".gitignore"), "!keep.log\n*.log\n"); // exclude AFTER negation → keep.log ignored
    expect(walk(t, { gitignore: true }).map((f) => f.rel)).not.toContain("keep.log");
    rmSync(t, { recursive: true, force: true });
  });

  it("unescapes a leading backslash (\\#literal ignores a file named #literal)", () => {
    const rules = parseGitignore("\\#literal\n");
    expect(rules.some((r) => r.glob === "**/#literal")).toBe(true);
  });

  it("a malformed gitignore rule does not abort the rules after it", () => {
    const t = mkdtempSync(join(tmpdir(), "ultrasec-gibad-"));
    writeFileSync(join(t, "a.js"), "x");
    writeFileSync(join(t, "keep.js"), "x");
    writeFileSync(join(t, ".gitignore"), "[z-a].x\na.js\n"); // bad rule THEN a real one
    const rels = walk(t, { gitignore: true }).map((f) => f.rel);
    expect(rels).not.toContain("a.js"); // the rule after the malformed one still applies
    expect(rels).toContain("keep.js");
    rmSync(t, { recursive: true, force: true });
  });

  it("honours the root .gitignore when opted in", () => {
    mkdirSync(join(tmp, "logs"), { recursive: true });
    writeFileSync(join(tmp, "keep.js"), "ok");
    writeFileSync(join(tmp, "ignored.log"), "x");
    writeFileSync(join(tmp, "logs", "a.txt"), "x");
    writeFileSync(join(tmp, ".gitignore"), "*.log\nlogs/\n");
    const rels = walk(tmp, { gitignore: true }).map((f) => f.rel).filter((r) => r !== ".gitignore");
    expect(rels).toContain("keep.js");
    expect(rels).not.toContain("ignored.log");
    expect(rels.some((r) => r.startsWith("logs/"))).toBe(false);
  });

  it("re-includes a negated path that a broader pattern excluded", () => {
    const t2 = mkdtempSync(join(tmpdir(), "ultrasec-gineg-"));
    writeFileSync(join(t2, "a.log"), "x");
    writeFileSync(join(t2, "keep.log"), "x");
    writeFileSync(join(t2, ".gitignore"), "*.log\n!keep.log\n");
    const rels = walk(t2, { gitignore: true }).map((f) => f.rel);
    expect(rels).not.toContain("a.log"); // excluded by *.log
    expect(rels).toContain("keep.log"); // re-included by !keep.log
    rmSync(t2, { recursive: true, force: true });
  });
});

describe("walk (symlink safety)", () => {
  it("skips a directory-symlink loop but still scans a symlinked FILE in-repo", () => {
    const t = mkdtempSync(join(tmpdir(), "ultrasec-sym-"));
    mkdirSync(join(t, "src"), { recursive: true });
    writeFileSync(join(t, "real.js"), "x");
    writeFileSync(join(t, "src", "f.js"), "x");
    try {
      symlinkSync(t, join(t, "src", "loop"), "dir"); // dir symlink → ancestor (would loop)
      symlinkSync("../real.js", join(t, "src", "linked.js")); // file symlink → in-repo file
    } catch {
      rmSync(t, { recursive: true, force: true });
      return; // symlinks unsupported on this FS — nothing to assert
    }
    const rels = walk(t).map((f) => f.rel);
    expect(rels).toContain("src/f.js");
    expect(rels).toContain("src/linked.js"); // symlinked file IS scanned (git tracks it)
    expect(rels.some((r) => r.includes("loop"))).toBe(false); // dir symlink NOT traversed
    rmSync(t, { recursive: true, force: true });
  });

  it("does not follow a symlink that escapes the repo root", () => {
    const outside = mkdtempSync(join(tmpdir(), "ultrasec-outside-"));
    writeFileSync(join(outside, "secret.js"), "x");
    const t = mkdtempSync(join(tmpdir(), "ultrasec-escape-"));
    try {
      symlinkSync(join(outside, "secret.js"), join(t, "escape.js"));
    } catch {
      rmSync(t, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
      return;
    }
    const rels = walk(t).map((f) => f.rel);
    expect(rels).not.toContain("escape.js"); // escaping symlink rejected
    rmSync(t, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  });
});
