import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseBlamePorcelain, blameLine } from "../src/git.js";
import { parseCodeowners, ownerFor, addProvenance } from "../src/provenance.js";
import type { Finding } from "../src/types.js";

function gitAvailable(): boolean {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
const HAS_GIT = gitAvailable();

describe("parseBlamePorcelain", () => {
  const sample = [
    "0123456789abcdef0123456789abcdef01234567 1 1 1",
    "author Jane Doe",
    "author-mail <jane@example.com>",
    "author-time 1700000000",
    "author-tz +0000",
    "committer Someone Else",
    "committer-time 1700000001",
    "summary add x",
    "filename src/x.js",
    "\tconst x = 1;",
  ].join("\n");

  it("extracts the author, a short commit, and a deterministic ISO author-date", () => {
    const p = parseBlamePorcelain(sample)!;
    expect(p.author).toBe("Jane Doe"); // not the committer
    expect(p.commit).toBe("0123456789");
    expect(p.date).toBe("2023-11-14"); // 1700000000s UTC — from history, not wall-clock
  });

  it("returns null on empty / non-porcelain input (never throws)", () => {
    expect(parseBlamePorcelain("")).toBeNull();
    expect(parseBlamePorcelain("not porcelain at all")).toBeNull();
  });
});

describe("CODEOWNERS matching", () => {
  const rules = parseCodeowners(["# owners", "*            @default", "*.js         @js-team", "/src/api/    @api-team @sec"].join("\n"));

  it("last matching rule wins (CODEOWNERS semantics)", () => {
    expect(ownerFor(rules, "src/api/users.js")).toEqual(["@api-team", "@sec"]);
  });
  it("matches an unanchored glob at any depth", () => {
    expect(ownerFor(rules, "lib/deep/util.js")).toEqual(["@js-team"]);
  });
  it("falls back to the catch-all", () => {
    expect(ownerFor(rules, "README.md")).toEqual(["@default"]);
  });
  it("returns undefined when nothing matches", () => {
    expect(ownerFor(parseCodeowners("/only/here @x"), "elsewhere/file.ts")).toBeUndefined();
  });
});

describe.skipIf(!HAS_GIT)("blameLine + addProvenance (integration)", () => {
  let repo: string;
  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), "ultrasec-prov-"));
    const env = { ...process.env, GIT_AUTHOR_DATE: "@1700000000 +0000", GIT_COMMITTER_DATE: "@1700000000 +0000" };
    const g = (args: string[]) => execFileSync("git", ["-C", repo, ...args], { stdio: "ignore", env });
    g(["init", "-q"]);
    g(["config", "user.email", "jane@example.com"]);
    g(["config", "user.name", "Jane Doe"]);
    mkdirSync(join(repo, "src"), { recursive: true });
    writeFileSync(join(repo, "src", "x.js"), "const a = 1;\nconst b = 2;\n");
    writeFileSync(join(repo, "CODEOWNERS"), "*.js @team\n");
    g(["add", "-A"]);
    g(["commit", "-q", "-m", "init"]);
  });
  afterAll(() => rmSync(repo, { recursive: true, force: true }));

  it("blameLine returns the committing author and a deterministic date", () => {
    const b = blameLine(repo, "src/x.js", 1)!;
    expect(b.author).toBe("Jane Doe");
    expect(b.date).toBe("2023-11-14");
    expect(b.commit).toMatch(/^[0-9a-f]{10}$/);
  });

  it("addProvenance attaches author + owner to a finding's primary location", () => {
    const f: Finding = {
      id: "x",
      category: "sast",
      title: "t",
      severity: "low",
      confidence: "low",
      message: "m",
      tool: "ultrasec",
      sink: { file: "src/x.js", line: 1 },
      status: "open",
    };
    const [out] = addProvenance([f], repo, { blame: true });
    expect(out!.provenance!.author).toBe("Jane Doe");
    expect(out!.provenance!.owner).toBe("@team");
  });

  it("degrades gracefully when blame fails AND no CODEOWNERS rule matches", () => {
    const f: Finding = {
      id: "y",
      category: "sast",
      title: "t",
      severity: "low",
      confidence: "low",
      message: "m",
      tool: "ultrasec",
      // .py matches no rule (CODEOWNERS only owns *.js) and the path doesn't resolve
      sink: { file: "does/not/exist.py", line: 1 },
      status: "open",
    };
    const [out] = addProvenance([f], repo, { blame: true });
    expect(out!.provenance).toBeUndefined();
  });

  it("attaches CODEOWNERS owner by path pattern even when blame is unavailable", () => {
    const f: Finding = {
      id: "z",
      category: "sast",
      title: "t",
      severity: "low",
      confidence: "low",
      message: "m",
      tool: "ultrasec",
      sink: { file: "src/never-committed.js", line: 1 },
      status: "open",
    };
    const [out] = addProvenance([f], repo, { blame: true });
    expect(out!.provenance!.owner).toBe("@team"); // owned by pattern *.js
    expect(out!.provenance!.author).toBeUndefined(); // but no blame (file not committed)
  });
});
