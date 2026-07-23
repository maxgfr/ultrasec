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
    expect(stats.files.length).toBe(3);
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

  it("errors on a non-positive --window value", async () => {
    const restore = silence();
    const code = await runLogs(parseArgs(["logs", FIXTURES_DIR, "--out", join(dir, "run"), "--window", "0"]));
    restore();
    expect(code).toBe(2);
  });

  it("auth.log alone produces grounded brute-force + credential-compromise findings, with a 'behavior' stdout summary", async () => {
    const out = join(dir, "run");
    let printed = "";
    const o = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => {
      printed += String(c);
      return true;
    });
    const code = await runLogs(parseArgs(["logs", join(FIXTURES_DIR, "auth.log"), "--out", out]));
    o.mockRestore();
    expect(code).toBe(0);

    const dossier = loadDossier(out);
    expect(dossier.findings.some((f) => f.sink?.kind === "brute-force")).toBe(true);
    expect(dossier.findings.some((f) => f.sink?.kind === "credential-compromise")).toBe(true);

    const res = check(dossier);
    expect(res.dangling).toEqual([]);
    expect(res.ok).toBe(true);

    expect(printed).toContain("behavior: brute-force IPs: 1");
  });

  it("--window threads through to the aggregator (a wide window flips a below-default-window case to firing)", async () => {
    const spacedDir = mkdtempSync(join(tmpdir(), "ultrasec-logs-window-cmd-"));
    try {
      const file = join(spacedDir, "spaced.jsonl");
      const lines: string[] = [];
      for (let i = 0; i < 20; i++) {
        const ts = new Date(Date.UTC(2024, 0, 1, 0, 0, i * 5)).toISOString();
        lines.push(JSON.stringify({ timestamp: ts, message: "login failed for user bob", ip: "203.0.113.230" }));
      }
      writeFileSync(file, lines.join("\n") + "\n");

      const outDefault = join(spacedDir, "run-default");
      const restore1 = silence();
      const code1 = await runLogs(parseArgs(["logs", file, "--out", outDefault]));
      restore1();
      expect(code1).toBe(0);
      expect(loadDossier(outDefault).findings.some((f) => f.sink?.kind === "brute-force")).toBe(false);

      const outWide = join(spacedDir, "run-wide");
      const restore2 = silence();
      const code2 = await runLogs(parseArgs(["logs", file, "--out", outWide, "--window", "120"]));
      restore2();
      expect(code2).toBe(0);
      expect(loadDossier(outWide).findings.some((f) => f.sink?.kind === "brute-force")).toBe(true);
    } finally {
      rmSync(spacedDir, { recursive: true, force: true });
    }
  });

  it("errors when given a path that does not exist", async () => {
    const restore = silence();
    const code = await runLogs(parseArgs(["logs", join(dir, "nope.log"), "--out", join(dir, "run")]));
    restore();
    expect(code).toBe(2);
  });

  it("errors on an unknown --format value, listing valid values, instead of silently degrading to raw parsing", async () => {
    let printed = "";
    const o = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const e = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => {
      printed += String(c);
      return true;
    });
    const code = await runLogs(parseArgs(["logs", FIXTURES_DIR, "--out", join(dir, "run"), "--format", "bogus"]));
    o.mockRestore();
    e.mockRestore();
    expect(code).toBe(2);
    expect(printed).toContain("bogus");
    // The error must list the valid values (mirrors import.ts's --format validation).
    expect(printed).toContain("nginx-combined");
    expect(printed).toContain("auto");
    expect(existsSync(join(dir, "run", "manifest.json"))).toBe(false);
  });

  it("--format auto behaves like omitting --format (per-file auto-detection)", async () => {
    const out = join(dir, "run");
    const restore = silence();
    const code = await runLogs(parseArgs(["logs", FIXTURES_DIR, "--out", out, "--format", "auto"]));
    restore();
    expect(code).toBe(0);
    const dossier = loadDossier(out);
    expect(dossier.findings.length).toBeGreaterThan(0);
  });

  it("accepts every real LogFormat value for --format", async () => {
    for (const fmt of ["nginx-combined", "common", "json-lines", "syslog", "generic", "raw"]) {
      const out = join(dir, `run-${fmt}`);
      const restore = silence();
      const code = await runLogs(parseArgs(["logs", FIXTURES_DIR, "--out", out, "--format", fmt]));
      restore();
      expect(code, `--format ${fmt} should exit 0`).toBe(0);
    }
  });

  it("logs dossier truncation banner uses logs-appropriate wording, not scan-only flags", async () => {
    const floodDir = mkdtempSync(join(tmpdir(), "ultrasec-logs-trunc-"));
    try {
      const file = join(floodDir, "flood.log");
      const lines: string[] = [];
      for (let i = 0; i < 80; i++) {
        lines.push(
          `203.0.113.${(i % 200) + 1} - - [10/Oct/2023:15:00:${String(i % 60).padStart(2, "0")} +0000] "GET /search?q=1' OR '${i}'='${i} HTTP/1.1" 200 100 "-" "Mozilla/5.0"`,
        );
      }
      writeFileSync(file, lines.join("\n") + "\n");

      const out = join(floodDir, "run");
      const restore = silence();
      const code = await runLogs(parseArgs(["logs", file, "--out", out]));
      restore();
      expect(code).toBe(0);

      const md = readFileSync(join(out, "DOSSIER.md"), "utf8");
      expect(md).toContain("Coverage capped");
      expect(md).toContain("--max-lines");
      expect(md).not.toContain("--max-candidates");
      expect(md).not.toContain("--scope");
    } finally {
      rmSync(floodDir, { recursive: true, force: true });
    }
  });
});

describe("expandInputs", () => {
  it("expands a directory to its *.log/*.jsonl files, non-recursively, sorted", () => {
    const files = expandInputs([FIXTURES_DIR]);
    expect(files).toEqual([join(FIXTURES_DIR, "app.jsonl"), join(FIXTURES_DIR, "auth.log"), join(FIXTURES_DIR, "nginx-combined.log")]);
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
