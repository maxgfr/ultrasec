import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeDossier, type Dossier } from "../src/store.js";
import { appendJournal, writeReport, JOURNAL_FILE, type Transcript } from "../src/transcript.js";
import type { Finding } from "../src/types.js";

// `--report` and JOURNAL.md exist because, before them, every intermediate stage's
// output lived only in the operator's scrollback: `render` writes artifacts, but
// only at the END of the chain. The counters that say what an audit actually
// covered — verdicts folded, rows refused, tools skipped — were unrecoverable.
//
// Both are ADDITIVE. The load-bearing assertion in this file is that stdout is
// byte-identical with and without them.

const REPO = join(import.meta.dirname, "fixtures", "vuln-express");
const BUNDLE = join(import.meta.dirname, "..", "scripts", "ultrasec.mjs");

const TRANSCRIPT: Transcript = {
  command: "ultrasec verify --run .ultrasec",
  stdout: "applied 2 verdict(s): 1 confirmed · 1 dismissed\n  ✗ dropped row 3: verdict missing",
  stderr: "",
  code: 0,
  at: "2026-01-02T03:04:05.000Z",
};

function seedRun(): string {
  const run = mkdtempSync(join(tmpdir(), "ultrasec-report-"));
  const f: Finding = {
    id: "f1",
    category: "taint",
    cwe: "CWE-89",
    title: "SQLi",
    severity: "high",
    confidence: "high",
    message: "m",
    tool: "ultrasec",
    status: "open",
    sink: { file: "src/db.js", line: 6 },
  };
  const d: Dossier = {
    manifest: {
      version: "0",
      schemaVersion: 5,
      repo: REPO,
      generatedNote: "",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: 1, bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } },
    },
    findings: [f],
    graph: { files: [], edges: [], symbolDefs: {} },
  };
  writeDossier(run, d);
  return run;
}

function cli(args: string[], input?: string): { code: number; out: string } {
  try {
    return { code: 0, out: execFileSync(process.execPath, [BUNDLE, ...args], { encoding: "utf8", input }) };
  } catch (e: any) {
    return { code: e.status as number, out: String(e.stdout ?? "") + String(e.stderr ?? "") };
  }
}

describe("writeReport picks its format from the extension", () => {
  it("writes markdown with the output fenced", () => {
    const p = join(mkdtempSync(join(tmpdir(), "ultrasec-fmt-")), "r.md");
    writeReport(p, TRANSCRIPT);
    const body = readFileSync(p, "utf8");
    expect(body).toContain("# ultrasec verify --run .ultrasec");
    expect(body).toContain("2026-01-02T03:04:05.000Z · exit 0");
    expect(body).toContain("```");
    expect(body).toContain("applied 2 verdict(s)");
  });

  it("writes self-contained HTML — no external stylesheet to go missing", () => {
    const p = join(mkdtempSync(join(tmpdir(), "ultrasec-fmt-")), "r.html");
    writeReport(p, TRANSCRIPT);
    const body = readFileSync(p, "utf8");
    expect(body).toMatch(/^<!doctype html>/);
    expect(body).toContain("<style>");
    expect(body).not.toMatch(/<link[^>]+stylesheet/);
    expect(body).not.toMatch(/<script/);
  });

  it("escapes the transcript into HTML rather than letting it become markup", () => {
    const p = join(mkdtempSync(join(tmpdir(), "ultrasec-fmt-")), "r.html");
    writeReport(p, { ...TRANSCRIPT, stdout: `<img src=x onerror="alert(1)">` });
    const body = readFileSync(p, "utf8");
    expect(body).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    expect(body).not.toContain("<img src=x");
  });

  it("writes the transcript verbatim as JSON", () => {
    const p = join(mkdtempSync(join(tmpdir(), "ultrasec-fmt-")), "r.json");
    writeReport(p, TRANSCRIPT);
    expect(JSON.parse(readFileSync(p, "utf8"))).toEqual(TRANSCRIPT);
  });

  it("throws on an unknown extension instead of writing a mislabelled file", () => {
    const p = join(mkdtempSync(join(tmpdir(), "ultrasec-fmt-")), "r.pdf");
    expect(() => writeReport(p, TRANSCRIPT)).toThrow(/unsupported --report extension "pdf"/);
    expect(existsSync(p)).toBe(false);
  });
});

describe("JOURNAL.md accumulates across commands", () => {
  it("creates the file with a header, then appends one entry per command", () => {
    const run = mkdtempSync(join(tmpdir(), "ultrasec-journal-"));
    appendJournal(run, TRANSCRIPT);
    appendJournal(run, { ...TRANSCRIPT, command: "ultrasec check --semantic", stdout: "grounding OK", at: "2026-01-02T03:09:00.000Z" });

    const body = readFileSync(join(run, JOURNAL_FILE), "utf8");
    expect(body.match(/^# ultrasec run journal$/gm)).toHaveLength(1); // header written once
    expect(body).toContain("`ultrasec verify --run .ultrasec`");
    expect(body).toContain("`ultrasec check --semantic`");
    // The entry must carry the lost-coverage signal, not just the headline.
    expect(body).toContain("✗ dropped row 3: verdict missing");
    expect(body.indexOf("verify")).toBeLessThan(body.indexOf("check --semantic")); // append order
  });
});

describe("archiving is additive — stdout never changes", () => {
  it.runIf(existsSync(BUNDLE))("produces identical stdout with and without --report", () => {
    const bare = seedRun();
    const withReport = seedRun();
    const payload = JSON.stringify([{ id: "f1", verdict: "refuted" }]);
    writeFileSync(join(bare, "verdicts.json"), payload);
    writeFileSync(join(withReport, "verdicts.json"), payload);
    const reportPath = join(withReport, "out.md");

    const a = cli(["verify", "--run", bare, "--apply", join(bare, "verdicts.json"), "--no-journal"]);
    const b = cli(["verify", "--run", withReport, "--apply", join(withReport, "verdicts.json"), "--no-journal", "--report", reportPath]);

    // Only the run path differs between the two invocations.
    expect(b.out.replace(withReport, "RUN")).toBe(a.out.replace(bare, "RUN"));
    expect(readFileSync(reportPath, "utf8")).toContain("applied 1 verdict");
  });

  it.runIf(existsSync(BUNDLE))("rejects a bad --report extension BEFORE running the command", () => {
    const run = seedRun();
    writeFileSync(join(run, "verdicts.json"), JSON.stringify([{ id: "f1", verdict: "refuted" }]));

    const { code, out } = cli(["verify", "--run", run, "--apply", join(run, "verdicts.json"), "--report", join(run, "out.pdf")]);

    expect(code).toBe(2);
    expect(out).toMatch(/unsupported --report extension "pdf"/);
    // The command must not have run: the dossier is untouched, no journal written.
    expect(existsSync(join(run, JOURNAL_FILE))).toBe(false);
  });

  it.runIf(existsSync(BUNDLE))("journals a run automatically, and --no-journal opts out", () => {
    const run = seedRun();
    writeFileSync(join(run, "verdicts.json"), JSON.stringify([{ id: "f1", verdict: "refuted" }]));

    cli(["verify", "--run", run, "--apply", join(run, "verdicts.json")]);
    expect(readFileSync(join(run, JOURNAL_FILE), "utf8")).toContain("applied 1 verdict");

    const quiet = seedRun();
    writeFileSync(join(quiet, "verdicts.json"), JSON.stringify([{ id: "f1", verdict: "refuted" }]));
    cli(["verify", "--run", quiet, "--apply", join(quiet, "verdicts.json"), "--no-journal"]);
    expect(existsSync(join(quiet, JOURNAL_FILE))).toBe(false);
  });
});

// The read-only commands must stay read-only. `check` is the CI gate documented
// as writing nothing, and the orchestration contracts let fan-out subagents run
// `dossier`/`graph`/`paths` precisely because they don't write — several of them
// appending to one JOURNAL.md would break the one-writer rule the whole fan-out
// design rests on.
describe("read-only commands never journal", () => {
  for (const cmd of ["check", "paths"]) {
    it.runIf(existsSync(BUNDLE))(`${cmd} leaves the run directory without a JOURNAL.md`, () => {
      const run = seedRun();
      cli([cmd, "--run", run]);
      expect(existsSync(join(run, JOURNAL_FILE)), `${cmd} wrote a journal entry`).toBe(false);
    });
  }

  it.runIf(existsSync(BUNDLE))("but --report still works for them — it writes where you pointed", () => {
    const run = seedRun();
    const report = join(run, "paths.md");
    cli(["paths", "--run", run, "--report", report]);
    expect(existsSync(report)).toBe(true);
    expect(existsSync(join(run, JOURNAL_FILE))).toBe(false);
  });

  it.runIf(existsSync(BUNDLE))("a writing command still journals", () => {
    const run = seedRun();
    writeFileSync(join(run, "verdicts.json"), JSON.stringify([{ id: "f1", verdict: "refuted" }]));
    cli(["verify", "--run", run, "--apply", join(run, "verdicts.json")]);
    expect(existsSync(join(run, JOURNAL_FILE))).toBe(true);
  });
});
