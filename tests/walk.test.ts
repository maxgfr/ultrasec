import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { walk, walkWithMeta, globToRe, gitignoreToGlobs } from "../src/walk.js";

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

  it("converts common patterns, keeps dir-only as dir-only, and captures negations", () => {
    const { excludes, reincludes } = gitignoreToGlobs("# comment\nsecret.txt\nbuildlogs/\n!keep.js\n");
    expect(excludes).toContain("**/secret.txt"); // file → bare form
    expect(excludes).toContain("**/buildlogs/"); // dir-only → dir form
    expect(excludes).not.toContain("**/buildlogs"); // …but NOT the bare-file form
    expect(reincludes.some((g) => g.includes("keep.js"))).toBe(true); // negation honoured, not dropped
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
  it("does not follow symlinks (no cycle, no duplication)", () => {
    const t = mkdtempSync(join(tmpdir(), "ultrasec-sym-"));
    mkdirSync(join(t, "real"), { recursive: true });
    writeFileSync(join(t, "real", "f.js"), "x");
    // a directory symlink pointing back at the repo root would loop if followed
    try {
      symlinkSync(t, join(t, "real", "loop"), "dir");
    } catch {
      rmSync(t, { recursive: true, force: true });
      return; // symlinks unsupported on this FS — nothing to assert
    }
    const rels = walk(t).map((f) => f.rel);
    expect(rels).toContain("real/f.js");
    expect(rels.some((r) => r.includes("loop"))).toBe(false); // symlink not traversed
    rmSync(t, { recursive: true, force: true });
  });
});
