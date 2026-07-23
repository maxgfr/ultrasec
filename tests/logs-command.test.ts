import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { runLogs, computeBase, expandInputs } from "../src/commands/logs.js";
import { loadDossier } from "../src/store.js";
import { check } from "../src/check.js";
import { parseArgs } from "../src/util.js";

const FIXTURES_DIR = join(import.meta.dirname, "fixtures", "logs");

function silence(): () => void {
  const o = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  const e = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  return () => {
    o.mockRestore();
    e.mockRestore();
  };
}

describe("runLogs — end to end", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ultrasec-logs-cmd-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("writes a standard, grounded dossier + LOGSTATS.json from the fixtures dir", async () => {
    const out = join(dir, "run");
    const restore = silence();
    const code = await runLogs(parseArgs(["logs", FIXTURES_DIR, "--out", out]));
    restore();
    expect(code).toBe(0);

    for (const f of ["manifest.json", "findings.json", "graph.json", "DOSSIER.md", "LOGSTATS.json"]) {
      expect(existsSync(join(out, f)), `${f} missing`).toBe(true);
    }

    const dossier = loadDossier(out);
    expect(dossier.findings.length).toBeGreaterThan(0);
    expect(dossier.findings.every((f) => f.category === "logs")).toBe(true);
    expect(dossier.findings.every((f) => f.tool === "ultrasec")).toBe(true);
    expect(dossier.findings.every((f) => f.status === "open")).toBe(true);
    expect(dossier.findings.every((f) => f.confidence === "low")).toBe(true);

    // Grounding: every cited [file:line] must resolve under manifest.repo — the
    // SAME machinery `ultrasec check` runs.
    const res = check(dossier);
    expect(res.dangling).toEqual([]);
    expect(res.ok).toBe(true);

    const stats = JSON.parse(readFileSync(join(out, "LOGSTATS.json"), "utf8"));
    expect(Array.isArray(stats.topIps)).toBe(true);
    expect(stats.topIps.length).toBeGreaterThan(0);
    expect(typeof stats.statusCounts).toBe("object");
    expect(Object.keys(stats.statusCounts).length).toBeGreaterThan(0);
    expect(stats.files.length).toBe(2);
  });

  it("--json prints a machine-readable summary", async () => {
    const out = join(dir, "run");
    let printed = "";
    const o = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => {
      printed += String(c);
      return true;
    });
    const code = await runLogs(parseArgs(["logs", FIXTURES_DIR, "--out", out, "--json"]));
    o.mockRestore();
    expect(code).toBe(0);
    const parsed = JSON.parse(printed);
    expect(parsed.out).toBe(out);
    expect(typeof parsed.findings).toBe("number");
    expect(Array.isArray(parsed.stats.topIps)).toBe(true);
  });

  it("--no-redact keeps raw evidence in the written dossier", async () => {
    const out = join(dir, "run");
    const restore = silence();
    const code = await runLogs(parseArgs(["logs", FIXTURES_DIR, "--out", out, "--no-redact"]));
    restore();
    expect(code).toBe(0);
    const raw = readFileSync(join(out, "findings.json"), "utf8");
    expect(raw).toContain("hunter2secret");
  });

  it("rejects empty input with a clear error and exit 2", async () => {
    const empty = join(dir, "empty");
    mkdirSync(empty, { recursive: true });
    const restore = silence();
    const code = await runLogs(parseArgs(["logs", empty, "--out", join(dir, "run")]));
    restore();
    expect(code).toBe(2);
  });

  it("errors on an unknown --budget value", async () => {
    const restore = silence();
    const code = await runLogs(parseArgs(["logs", FIXTURES_DIR, "--out", join(dir, "run"), "--budget", "bogus"]));
    restore();
    expect(code).toBe(2);
  });

  it("errors when given a path that does not exist", async () => {
    const restore = silence();
    const code = await runLogs(parseArgs(["logs", join(dir, "nope.log"), "--out", join(dir, "run")]));
    restore();
    expect(code).toBe(2);
  });
});

describe("expandInputs", () => {
  it("expands a directory to its *.log/*.jsonl files, non-recursively, sorted", () => {
    const files = expandInputs([FIXTURES_DIR]);
    expect(files).toEqual([join(FIXTURES_DIR, "app.jsonl"), join(FIXTURES_DIR, "nginx-combined.log")]);
  });

  it("passes an explicit file through unchanged", () => {
    const file = join(FIXTURES_DIR, "app.jsonl");
    expect(expandInputs([file])).toEqual([file]);
  });
});

describe("computeBase", () => {
  it("prefers cwd when it is an ancestor of every input file", () => {
    const cwd = resolve(process.cwd());
    const files = [join(FIXTURES_DIR, "app.jsonl"), join(FIXTURES_DIR, "nginx-combined.log")];
    expect(computeBase(files)).toBe(cwd);
  });

  it("falls back to the strict common ancestor when files live outside cwd", () => {
    const dir = mkdtempSync(join(tmpdir(), "ultrasec-logs-base-"));
    try {
      const sub1 = join(dir, "a");
      const sub2 = join(dir, "b");
      mkdirSync(sub1, { recursive: true });
      mkdirSync(sub2, { recursive: true });
      const f1 = join(sub1, "x.log");
      const f2 = join(sub2, "y.log");
      writeFileSync(f1, "x\n");
      writeFileSync(f2, "y\n");
      expect(computeBase([f1, f2])).toBe(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
