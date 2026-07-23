import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { join } from "node:path";
import { mkdtempSync, writeFileSync, rmSync, openSync, closeSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import type { Dossier } from "../src/store.js";
import type { Finding } from "../src/types.js";
import { check, countNewlines, lineCountDetailed, lineCount } from "../src/check.js";

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");

function dossier(findings: Finding[]): Dossier {
  return {
    manifest: {
      version: "0.0.0",
      schemaVersion: 1,
      repo: FIXTURE,
      generatedNote: "",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    },
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

function f(id: string, file: string, line: number, status: Finding["status"] = "confirmed"): Finding {
  return { id, category: "taint", title: id, severity: "high", confidence: "high", message: "m", tool: "ultrasec", status, sink: { file, line } };
}

describe("check — grounding", () => {
  it("passes when every cited [file:line] resolves", () => {
    const r = check(dossier([f("a", "src/db.js", 6)]));
    expect(r.ok).toBe(true);
    expect(r.dangling).toHaveLength(0);
  });

  it("fails on a nonexistent file", () => {
    const r = check(dossier([f("a", "src/ghost.js", 1)]));
    expect(r.ok).toBe(false);
    expect(r.dangling[0]!.reason).toBe("file not found");
  });

  it("fails on an out-of-range line (hallucinated location)", () => {
    const r = check(dossier([f("a", "src/db.js", 99999)]));
    expect(r.ok).toBe(false);
    expect(r.dangling[0]!.reason).toMatch(/out of range/);
  });

  it("ignores dismissed findings (the lead may have been false)", () => {
    const r = check(dossier([f("a", "src/ghost.js", 1, "dismissed")]));
    expect(r.ok).toBe(true);
  });
});

describe("check — file-scoped (line 0) citations", () => {
  // Eval P1.4: checkov/IaC config findings normalize to line 0 (a whole-file
  // finding). The gate used to reject line < 1, so a fresh --docker scan failed
  // its own mandatory gate. A line-0 citation now means "this file" — only file
  // existence is checked, not a line range.
  it("passes a line-0 citation when the file exists", () => {
    const r = check(dossier([f("a", "src/db.js", 0)]));
    expect(r.ok).toBe(true);
    expect(r.dangling).toHaveLength(0);
  });

  it("still fails a line-0 citation when the file does not exist", () => {
    const r = check(dossier([f("a", "src/ghost.js", 0)]));
    expect(r.ok).toBe(false);
    expect(r.dangling[0]!.reason).toBe("file not found");
  });

  it("still rejects a negative line and an out-of-range line", () => {
    expect(check(dossier([f("a", "src/db.js", -1)])).ok).toBe(false);
    expect(check(dossier([f("a", "src/db.js", 99999)])).ok).toBe(false);
  });

  it("grounds dep locations[] — file must resolve, line 0/absent is whole-file", () => {
    const dep: Finding = {
      id: "d",
      category: "dep",
      title: "adv",
      severity: "high",
      confidence: "medium",
      message: "m",
      tool: "osv-scanner",
      status: "confirmed",
      sink: { file: "package.json", line: 1 },
      locations: [
        { file: "package.json", line: 0, version: "1.0.0" },
        { file: "app/package.json", version: "2.0.0" },
      ],
    };
    // app/package.json doesn't exist in the fixture → that instance is a dangling citation.
    const r = check(dossier([dep]));
    expect(r.ok).toBe(false);
    expect(r.dangling.some((d) => d.file === "app/package.json")).toBe(true);
    expect(r.dangling.some((d) => d.file === "package.json")).toBe(false);
  });
});

describe("check — semantic", () => {
  it("fails if a candidate is still unadjudicated", () => {
    const r = check(dossier([f("a", "src/db.js", 6, "open")]), { semantic: true });
    expect(r.ok).toBe(false);
    expect(r.messages.join(" ")).toMatch(/unadjudicated/);
  });

  it("passes once everything is adjudicated and grounded", () => {
    const r = check(dossier([f("a", "src/db.js", 6, "confirmed"), f("b", "src/report.js", 5, "dismissed")]), { semantic: true });
    expect(r.ok).toBe(true);
  });

  // Gate integrity (fail-closed): the semantic gate must treat ANY non-adjudicated
  // status as unadjudicated — not only the literal "open". A finding whose status
  // is unknown/foreign (version skew, a tampered/corrupted findings.json, an
  // externally-authored dossier) carries no real verdict, yet an equality-on-"open"
  // check would wave it through ("audit adjudicated"). That is the stale-ledger
  // fail-open class: the gate must detect unadjudicated claims, not just refuted ones.
  it("fails on an unknown/foreign status (not just literal open)", () => {
    const r = check(dossier([f("a", "src/db.js", 6, "reviewed" as Finding["status"])]), { semantic: true });
    expect(r.ok).toBe(false);
    expect(r.messages.join(" ")).toMatch(/unadjudicated/);
  });

  it("fails when a finding carries no status field at all", () => {
    const bare = {
      id: "a",
      category: "taint",
      title: "a",
      severity: "high",
      confidence: "high",
      message: "m",
      tool: "ultrasec",
      sink: { file: "src/db.js", line: 6 },
    } as unknown as Finding;
    const r = check(dossier([bare]), { semantic: true });
    expect(r.ok).toBe(false);
    expect(r.messages.join(" ")).toMatch(/unadjudicated/);
  });
});

// IMPORTANT 3: lineCount() used to readFileSync(file, "utf8") — a huge file
// (e.g. `logs --budget thorough`'s 10M-line ceiling) can exceed Node's max
// string length, throwing, and the catch collapsed that into a misleading
// "file not found" note. The counting is now a small, directly unit-testable
// function (`countNewlines`) driven by fixed-size binary reads — no 1GB
// fixture required to exercise it.
describe("check — lineCount streaming (IMPORTANT 3)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ultrasec-check-linecount-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  function fdOf(path: string): number {
    return openSync(path, "r");
  }

  describe("countNewlines — chunk-boundary correctness", () => {
    it("counts 0 newlines in an empty buffer source", () => {
      const file = join(dir, "empty.txt");
      writeFileSync(file, "");
      const fd = fdOf(file);
      try {
        expect(countNewlines(fd)).toBe(0);
      } finally {
        closeSync(fd);
      }
    });

    it("counts newlines correctly with the default (large) chunk size", () => {
      const file = join(dir, "normal.txt");
      writeFileSync(file, "a\nb\nc\n");
      const fd = fdOf(file);
      try {
        expect(countNewlines(fd)).toBe(3);
      } finally {
        closeSync(fd);
      }
    });

    it("counts newlines correctly when a \\n falls EXACTLY on a chunk boundary (chunkBytes forced tiny)", () => {
      // "ab\ncd\n" with chunkBytes=3: chunks are "ab\n" | "cd\n" — the first
      // \n is the LAST byte of chunk 1, the second is the last byte of chunk 2.
      const file = join(dir, "boundary-exact.txt");
      writeFileSync(file, "ab\ncd\n");
      const fd = fdOf(file);
      try {
        expect(countNewlines(fd, 3)).toBe(2);
      } finally {
        closeSync(fd);
      }
    });

    it("counts newlines correctly when reading one byte at a time (chunkBytes=1, the worst case)", () => {
      const content = "line1\nline2\nline3\nline4\n";
      const file = join(dir, "byte-at-a-time.txt");
      writeFileSync(file, content);
      const fd = fdOf(file);
      try {
        expect(countNewlines(fd, 1)).toBe(4);
      } finally {
        closeSync(fd);
      }
    });

    it("agrees with String.split(/\\r?\\n/).length - 1 across chunk sizes for a run of consecutive newlines", () => {
      // A run of blank lines straddling a small chunk boundary — every \n in
      // "a\n\n\n\nb" must still be counted once each regardless of chunkBytes.
      const content = "a\n\n\n\nb";
      const expected = content.split(/\r?\n/).length - 1; // 4
      const file = join(dir, "run.txt");
      writeFileSync(file, content);
      for (const chunkBytes of [1, 2, 3, 1024]) {
        const fd = fdOf(file);
        try {
          expect(countNewlines(fd, chunkBytes)).toBe(expected);
        } finally {
          closeSync(fd);
        }
      }
    });
  });

  describe("lineCountDetailed — status discrimination", () => {
    it("status: ok, matching the old split(/\\r?\\n/).length semantics for a normal file", () => {
      const file = join(dir, "normal.log");
      writeFileSync(file, "one\ntwo\nthree\n");
      const outcome = lineCountDetailed(dir, "normal.log");
      expect(outcome).toEqual({ status: "ok", lines: 4 }); // split(...).length === 4 (trailing "")
    });

    it('status: ok with lines: 1 for an empty file (matches "".split(/\\r?\\n/).length === 1)', () => {
      writeFileSync(join(dir, "empty.log"), "");
      const outcome = lineCountDetailed(dir, "empty.log");
      expect(outcome).toEqual({ status: "ok", lines: 1 });
    });

    it("status: missing for a file that does not exist", () => {
      const outcome = lineCountDetailed(dir, "does-not-exist.log");
      expect(outcome).toEqual({ status: "missing" });
    });

    it("status: missing for a path that escapes the repo (path-traversal guard)", () => {
      const outcome = lineCountDetailed(dir, "../../../../../../etc/passwd");
      expect(outcome).toEqual({ status: "missing" });
    });

    // Reproduces "exists but can't be read as a file" WITHOUT a multi-GB
    // fixture: opening a directory succeeds, but reading it throws EISDIR —
    // the same "real path, unreadable content" shape a too-large file hits.
    it("status: unreadable (not missing) for a path that exists but can't be read as a file", () => {
      const subdir = join(dir, "a-directory");
      writeFileSync(join(dir, ".keep"), ""); // ensure dir isn't empty (irrelevant, just realism)
      mkdirSync(subdir);
      const outcome = lineCountDetailed(dir, "a-directory");
      expect(outcome.status).toBe("unreadable");
      if (outcome.status === "unreadable") expect(outcome.error.length).toBeGreaterThan(0);
    });

    it("lineCount() back-compat wrapper: null on missing AND on unreadable (can't tell them apart, by design)", () => {
      mkdirSync(join(dir, "another-dir"));
      expect(lineCount(dir, "nope.log")).toBeNull();
      expect(lineCount(dir, "another-dir")).toBeNull();
      writeFileSync(join(dir, "ok.log"), "x\ny\n");
      expect(lineCount(dir, "ok.log")).toBe(3);
    });
  });

  describe("check() — dangling reason distinguishes unreadable from not found", () => {
    it("reports 'file not found' for a genuinely missing citation", () => {
      const missingDossier = dossier([f("a", "src/totally-ghost.js", 1)]);
      const r = check(missingDossier);
      expect(r.ok).toBe(false);
      expect(r.dangling[0]!.reason).toBe("file not found");
    });

    it("reports a distinct 'file unreadable' reason (not 'file not found') for a citation that resolves but can't be read", () => {
      const repoDir = mkdtempSync(join(tmpdir(), "ultrasec-check-unreadable-repo-"));
      mkdirSync(join(repoDir, "src"));
      mkdirSync(join(repoDir, "src", "weird-dir")); // a directory cited as if it were a file
      const unreadableDossier: Dossier = {
        manifest: {
          version: "0.0.0",
          schemaVersion: 1,
          repo: repoDir,
          generatedNote: "",
          languages: ["javascript"],
          counts: { findings: 1, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
          toolsRun: [],
        },
        findings: [f("a", "src/weird-dir", 1)],
        graph: { files: [], edges: [], symbolDefs: {} },
      };
      const r = check(unreadableDossier);
      expect(r.ok).toBe(false);
      expect(r.dangling[0]!.reason).not.toBe("file not found");
      expect(r.dangling[0]!.reason).toMatch(/unreadable/);
      rmSync(repoDir, { recursive: true, force: true });
    });
  });
});
